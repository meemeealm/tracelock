"""RFC 6962 tests. The brute-force reference below is written independently of
tracelock.merkle, straight from the RFC definition of MTH."""
import hashlib

import pytest

from tracelock.merkle import (
    EMPTY_ROOT, MerkleTree, leaf_hash, node_hash, verify_consistency, verify_inclusion,
)


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def brute_mth(data: list[bytes]) -> bytes:
    """MTH(D[n]) from RFC 6962 section 2.1, recomputed from raw data."""
    n = len(data)
    if n == 0:
        return sha(b"")
    if n == 1:
        return sha(b"\x00" + data[0])
    k = 1
    while k * 2 < n:  # largest power of two strictly less than n
        k *= 2
    return sha(b"\x01" + brute_mth(data[:k]) + brute_mth(data[k:]))


def make(n: int) -> tuple[MerkleTree, list[bytes]]:
    data = [f"leaf-{i}".encode() for i in range(n)]
    t = MerkleTree()
    for d in data:
        t.append(d)
    return t, data


def test_empty_tree():
    t = MerkleTree()
    assert t.size == 0 and t.root() == EMPTY_ROOT == sha(b"")


def test_domain_separation():
    assert leaf_hash(b"x") == sha(b"\x00x")
    assert node_hash(b"L" * 32, b"R" * 32) == sha(b"\x01" + b"L" * 32 + b"R" * 32)
    assert leaf_hash(b"") != EMPTY_ROOT


def test_hand_computed_roots_sizes_1_to_8():
    d = [bytes([i]) for i in range(8)]
    l = [leaf_hash(x) for x in d]
    h = node_hash
    expected = {
        1: l[0],
        2: h(l[0], l[1]),
        3: h(h(l[0], l[1]), l[2]),
        4: h(h(l[0], l[1]), h(l[2], l[3])),
        5: h(h(h(l[0], l[1]), h(l[2], l[3])), l[4]),
        6: h(h(h(l[0], l[1]), h(l[2], l[3])), h(l[4], l[5])),
        7: h(h(h(l[0], l[1]), h(l[2], l[3])), h(h(l[4], l[5]), l[6])),
        8: h(h(h(l[0], l[1]), h(l[2], l[3])), h(h(l[4], l[5]), h(l[6], l[7]))),
    }
    t = MerkleTree()
    for n in range(1, 9):
        t.append(d[n - 1])
        assert t.root() == expected[n], f"incremental root, size {n}"
        assert t.root_at(n) == expected[n], f"recursive root, size {n}"
        assert brute_mth(d[:n]) == expected[n]


def test_certificate_transparency_reference_roots():
    # Roots of the 8-leaf tree used by the Google CT reference implementation.
    leaves = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
              b"\x50\x51\x52\x53\x54\x55\x56\x57", bytes(range(0x60, 0x70))]
    roots = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ]
    t = MerkleTree()
    for leaf, root in zip(leaves, roots):
        t.append(leaf)
        assert t.root().hex() == root


def test_incremental_root_matches_brute_force_up_to_100():
    t = MerkleTree()
    data = []
    for i in range(100):
        data.append(f"e{i}".encode())
        t.append(data[-1])
        assert t.root() == brute_mth(data)
    for size in range(1, 101):  # historical roots too
        assert t.root_at(size) == brute_mth(data[:size])


def test_rebuild_from_leaf_hashes_gives_same_root():
    t, data = make(37)
    t2 = MerkleTree(leaf_hash(d) for d in data)
    assert t2.root() == t.root() and t2.size == 37


def test_known_inclusion_proofs_size_8():
    t, data = make(8)
    l = [leaf_hash(d) for d in data]
    h = node_hash
    assert t.inclusion_proof(0) == [l[1], h(l[2], l[3]), h(h(l[4], l[5]), h(l[6], l[7]))]
    assert t.inclusion_proof(5) == [l[4], h(l[6], l[7]), h(h(l[0], l[1]), h(l[2], l[3]))]


def test_known_consistency_proofs():
    t, data = make(8)
    l = [leaf_hash(d) for d in data]
    h = node_hash
    assert t.consistency_proof(1, 2) == [l[1]]
    t3, _ = make(3)
    assert t3.consistency_proof(2, 3) == [l[2]]
    # RFC 6962 SUBPROOF(3, D[8]) = [l2, l3, H(l0,l1), H(H(l4,l5),H(l6,l7))]
    assert t.consistency_proof(3, 8) == [l[2], l[3], h(l[0], l[1]), h(h(l[4], l[5]), h(l[6], l[7]))]
    assert t.consistency_proof(4, 8) == [h(h(l[4], l[5]), h(l[6], l[7]))]
    assert t.consistency_proof(5, 5) == [] and t.consistency_proof(0, 8) == []


def test_inclusion_all_indices_all_sizes_up_to_32():
    t, data = make(32)
    for size in range(1, 33):
        root = brute_mth(data[:size])
        for i in range(size):
            proof = t.inclusion_proof(i, size)
            assert verify_inclusion(leaf_hash(data[i]), i, size, proof, root), (i, size)


def test_inclusion_negative_cases():
    t, data = make(13)
    root = brute_mth(data)
    proof = t.inclusion_proof(6)
    lh = leaf_hash(data[6])
    assert verify_inclusion(lh, 6, 13, proof, root)
    assert not verify_inclusion(lh, 7, 13, proof, root)  # wrong index
    assert not verify_inclusion(leaf_hash(b"other"), 6, 13, proof, root)  # wrong leaf
    assert not verify_inclusion(lh, 6, 13, proof, sha(b"bad root"))
    assert not verify_inclusion(lh, 6, 8, proof, root)  # wrong size (proof shape differs)
    assert not verify_inclusion(lh, 6, 20, proof, root)
    assert not verify_inclusion(lh, 6, 13, proof[:-1], root)  # truncated
    assert not verify_inclusion(lh, 6, 13, proof + [proof[0]], root)  # extended
    assert not verify_inclusion(lh, 13, 13, proof, root)  # index out of range
    assert not verify_inclusion(lh, 0, 0, [], root)
    for j in range(len(proof)):  # flip one bit in each proof element
        bad = list(proof)
        bad[j] = bytes([bad[j][0] ^ 1]) + bad[j][1:]
        assert not verify_inclusion(lh, 6, 13, bad, root)


def test_root_does_not_commit_to_size_so_sth_must_bind_both():
    # Sizes 12 and 13 give index 6 a proof of identical shape, so the proof checks
    # out for either size. This is inherent to RFC 6962; it is why an STH signs
    # (tree_size, root_hash) together and verifiers must take both from the STH.
    t, data = make(13)
    proof = t.inclusion_proof(6, 13)
    assert verify_inclusion(leaf_hash(data[6]), 6, 12, proof, brute_mth(data))


def test_consistency_all_pairs_up_to_32():
    t, data = make(32)
    for new in range(0, 33):
        new_root = brute_mth(data[:new])
        for old in range(0, new + 1):
            proof = t.consistency_proof(old, new)
            old_root = brute_mth(data[:old])
            assert verify_consistency(old, new, old_root, new_root, proof), (old, new)


def test_consistency_negative_cases_all_pairs_up_to_32():
    t, data = make(32)
    for new in range(2, 33):
        new_root = brute_mth(data[:new])
        for old in range(1, new):
            old_root = brute_mth(data[:old])
            proof = t.consistency_proof(old, new)
            assert proof, (old, new)
            assert not verify_consistency(old, new, sha(b"x"), new_root, proof)
            assert not verify_consistency(old, new, old_root, sha(b"x"), proof)
            assert not verify_consistency(old, new, old_root, new_root, proof[:-1])
            assert not verify_consistency(old, new, old_root, new_root, proof + [proof[-1]])
            assert not verify_consistency(old, new, old_root, new_root, [])
            for j in range(len(proof)):
                bad = list(proof)
                bad[j] = bytes([bad[j][0] ^ 1]) + bad[j][1:]
                assert not verify_consistency(old, new, old_root, new_root, bad), (old, new, j)


def test_consistency_detects_rewritten_history():
    t, data = make(10)
    # An attacker rewrites leaf 2 and rebuilds a 10-leaf tree.
    forged = list(data)
    forged[2] = b"forged"
    t2 = MerkleTree()
    for d in forged:
        t2.append(d)
    old_root = t.root_at(6)  # witnessed earlier
    proof = t2.consistency_proof(6, 10)
    assert not verify_consistency(6, 10, old_root, t2.root(), proof)


def test_range_errors():
    t, _ = make(5)
    for bad in (lambda: t.inclusion_proof(5), lambda: t.inclusion_proof(0, 6),
                lambda: t.consistency_proof(3, 6), lambda: t.consistency_proof(4, 3),
                lambda: t.root_at(6), lambda: t.append_leaf_hash(b"short")):
        with pytest.raises(ValueError):
            bad()


def test_consistency_degenerate_sizes():
    assert verify_consistency(0, 0, EMPTY_ROOT, EMPTY_ROOT, [])
    assert verify_consistency(0, 5, EMPTY_ROOT, sha(b"anything"), [])
    assert not verify_consistency(0, 5, sha(b"nonempty"), sha(b"r"), [])
    assert not verify_consistency(5, 3, sha(b"a"), sha(b"b"), [])
    assert not verify_consistency(3, 3, sha(b"a"), sha(b"b"), [])
