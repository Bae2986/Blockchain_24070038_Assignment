import hashlib, time

# (a) Avalanche effect
print("=== AVALANCHE EFFECT ===")
h1 = hashlib.sha256(b"Blockchain 2026").hexdigest()
h2 = hashlib.sha256(b"blockchain 2026").hexdigest()
print("Input: Blockchain 2026 ->", h1)
print("Input: blockchain 2026 ->", h2)
print("Different? ->", h1 != h2)

# (b) Toy PoW
print("\n=== TOY PROOF-OF-WORK ===")
def mine(data: bytes, k: int):
    target = "0" * k
    nonce, t0 = 0, time.time()
    while True:
        h = hashlib.sha256(data + str(nonce).encode()).hexdigest()
        if h.startswith(target):
            return nonce, time.time() - t0
        nonce += 1

for k in range(1, 7):
    nonce, dt = mine(b"block#1|txroot=abc|", k)
    print(f"k={k}  nonce={nonce:>9}  time={dt:.4f}s")

"""
Lab 03 - Merkle Tree implementation
Hoàn thành 3 TODO: merkle_root, merkle_proof, verify_proof
"""
import hashlib


def sha256(data: bytes) -> bytes:
    """Return 32-byte SHA-256 digest."""
    return hashlib.sha256(data).digest()


def hash_leaf(data) -> bytes:
    """Hash a leaf. Accepts str or bytes."""
    if isinstance(data, str):
        data = data.encode()
    return sha256(data)


def hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash the concatenation of two child hashes."""
    return sha256(left + right)


# ============================================================
# TODO 1: merkle_root(leaves)
# ============================================================
def merkle_root(leaves):
    """
    Build the Merkle tree bottom-up.
    Duplicate the last node when a level has odd length (Bitcoin rule).
    Returns the Merkle root as 32-byte digest.
    """
    if not leaves:
        return None

    # Chuẩn hóa leaves thành các hash 32-byte
    nodes = []
    for leaf in leaves:
        if isinstance(leaf, bytes) and len(leaf) == 32:
            nodes.append(leaf)
        else:
            nodes.append(hash_leaf(leaf))

    # Lặp lên cho tới khi còn 1 nút (root)
    while len(nodes) > 1:
        # Nếu lẻ -> nhân đôi nút cuối (quy tắc Bitcoin)
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1])

        new_level = []
        for i in range(0, len(nodes), 2):
            new_level.append(hash_pair(nodes[i], nodes[i + 1]))
        nodes = new_level

    return nodes[0]


# ============================================================
# TODO 2: merkle_proof(leaves, index)
# ============================================================
def merkle_proof(leaves, index):
    """
    Return list of (sibling_hash, is_left) pairs from leaf to root.
    is_left = True  -> sibling nằm bên TRÁI leaf hiện tại
    is_left = False -> sibling nằm bên PHẢI leaf hiện tại
    """
    if not leaves:
        return []

    # Chuẩn hóa leaves
    nodes = []
    for leaf in leaves:
        if isinstance(leaf, bytes) and len(leaf) == 32:
            nodes.append(leaf)
        else:
            nodes.append(hash_leaf(leaf))

    proof = []
    current_index = index

    while len(nodes) > 1:
        # Nhân đôi nút cuối nếu lẻ (để khớp với merkle_root)
        if len(nodes) % 2 != 0:
            nodes.append(nodes[-1])

        # Xác định sibling
        if current_index % 2 == 0:
            sibling_index = current_index + 1
            is_left = False  # sibling nằm bên phải
        else:
            sibling_index = current_index - 1
            is_left = True   # sibling nằm bên trái

        proof.append((nodes[sibling_index], is_left))

        # Xây tầng tiếp theo
        new_level = []
        for i in range(0, len(nodes), 2):
            new_level.append(hash_pair(nodes[i], nodes[i + 1]))
        nodes = new_level
        current_index = current_index // 2

    return proof


# ============================================================
# TODO 3: verify_proof(leaf_hash, proof, root)
# ============================================================
def verify_proof(leaf_hash: bytes, proof, root: bytes) -> bool:
    """
    Recompute upward from leaf to root using the proof, then compare.
    """
    current = leaf_hash

    for sibling_hash, is_left in proof:
        if is_left:
            # sibling bên trái -> H(sibling || current)
            current = hash_pair(sibling_hash, current)
        else:
            # sibling bên phải -> H(current || sibling)
            current = hash_pair(current, sibling_hash)

    return current == root


# ============================================================
# SELF-TEST — in ra các dòng CHECK ... OK
# ============================================================
def run_checks():
    # Test 1: single leaf
    leaves1 = ["Tx1"]
    root1 = merkle_root(leaves1)
    proof1 = merkle_proof(leaves1, 0)
    ok1 = verify_proof(hash_leaf("Tx1"), proof1, root1)
    print("CHECK 1 (1 leaf):", "OK" if ok1 else "FAILED")

    # Test 2: 2 leaves
    leaves2 = ["Tx1", "Tx2"]
    root2 = merkle_root(leaves2)
    proof2a = merkle_proof(leaves2, 0)
    proof2b = merkle_proof(leaves2, 1)
    ok2 = (verify_proof(hash_leaf("Tx1"), proof2a, root2) and
           verify_proof(hash_leaf("Tx2"), proof2b, root2))
    print("CHECK 2 (2 leaves):", "OK" if ok2 else "FAILED")

    # Test 3: 3 leaves (odd -> test duplicate rule)
    leaves3 = ["Tx1", "Tx2", "Tx3"]
    root3 = merkle_root(leaves3)
    proof3 = merkle_proof(leaves3, 2)
    ok3 = verify_proof(hash_leaf("Tx3"), proof3, root3)
    print("CHECK 3 (3 leaves, odd):", "OK" if ok3 else "FAILED")

    # Test 4: 8 leaves, proof for Tx5
    txs8 = ["Tx1", "Tx2", "Tx3", "Tx4", "Tx5", "Tx6", "Tx7", "Tx8"]
    root8 = merkle_root(txs8)
    proof8 = merkle_proof(txs8, 4)  # Tx5
    ok8 = verify_proof(hash_leaf("Tx5"), proof8, root8)
    print("CHECK 4 (8 leaves, Tx5):", "OK" if ok8 else "FAILED")
    print("         Proof length:", len(proof8), "(should be log2(8) = 3)")

    # Test 5: tampered proof must fail
    bad_leaf = hash_leaf("Tx5_TAMPERED")
    ok5 = not verify_proof(bad_leaf, proof8, root8)
    print("CHECK 5 (tamper -> reject):", "OK" if ok5 else "FAILED")

    # Test 6: 1024 leaves -> proof length = 10
    txs1024 = [f"Tx{i}" for i in range(1024)]
    root1024 = merkle_root(txs1024)
    proof1024 = merkle_proof(txs1024, 500)
    ok6 = verify_proof(hash_leaf("Tx500"), proof1024, root1024)
    print("CHECK 6 (1024 leaves):", "OK" if ok6 else "FAILED")
    print("         Proof length:", len(proof1024), "(should be log2(1024) = 10)")


if __name__ == "__main__":
    run_checks()


    from eth_account import Account
from eth_account.messages import encode_defunct

# Tạo account ngẫu nhiên (KHÔNG dùng cho tiền thật)
acct = Account.create()
print("Address:", acct.address)

# --- Ký lần 1 ---
msg = encode_defunct(text="I attended Session 3 / Toi da hoc Buoi 3")
sig1 = Account.sign_message(msg, acct.key)
print("\n--- Signature lần 1 ---")
print("r =", hex(sig1.r))
print("s =", hex(sig1.s))
print("v =", sig1.v)

# --- Ký lần 2 CÙNG message ---
sig2 = Account.sign_message(msg, acct.key)
print("\n--- Signature lần 2 (cùng message) ---")
print("r =", hex(sig2.r))
print("s =", hex(sig2.s))
print("v =", sig2.v)
print("Giống hệt nhau?", (sig1.r == sig2.r and sig1.s == sig2.s and sig1.v == sig2.v))

# --- Recover địa chỉ từ chữ ký ---
who = Account.recover_message(msg, signature=sig1.signature)
print("\n--- Recover ---")
print("Recovered :", who)
print("Original  :", acct.address)
print("Match?    :", who == acct.address)

# --- Sửa 1 ký tự trong message ---
bad_msg = encode_defunct(text="I attended Session 3 / Toi da hoc Buoi 4")
bad_who = Account.recover_message(bad_msg, signature=sig1.signature)
print("\n--- Tampered message ---")
print("Tampered recover:", bad_who)
print("Match original? :", bad_who == acct.address)
print("=> Chứng minh toàn vẹn: sửa message -> địa chỉ khôi phục KHÁC")