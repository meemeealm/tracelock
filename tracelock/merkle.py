"""RFC 6962 Merkle tree (Certificate Transparency style).

    leaf hash = SHA256(0x00 || data)
    node hash = SHA256(0x01 || left || right)
    MTH({})   = SHA256("")

Proof *generation* follows RFC 6962 section 2.1.1 (PATH) and 2.1.2 (SUBPROOF)
literally. Proof *verification* uses the iterative algorithms of RFC 9162
section 2.1.3.2 / 2.1.4.2, which accept exactly the RFC 6962 proofs.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

HASH_LEN = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (requires n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def _is_pow2(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


class MerkleTree:
    """Append-only RFC 6962 tree over leaf hashes.

    ``root()`` is O(log n) via a frontier of perfect subtrees. Historical
    roots and proofs are computed recursively; hashes of perfect subtrees are
    cached because leaves never change once appended.
    """

    def __init__(self, leaf_hashes: Iterable[bytes] = ()) -> None:
        self._leaves: list[bytes] = []
        self._frontier: list[tuple[int, bytes]] = []  # (subtree size, hash)
        self._perfect: dict[tuple[int, int], bytes] = {}
        for h in leaf_hashes:
            self.append_leaf_hash(h)

    @property
    def size(self) -> int:
        return len(self._leaves)

    def append(self, data: bytes) -> int:
        """Hash ``data`` as a leaf and append it. Returns the leaf index."""
        return self.append_leaf_hash(leaf_hash(data))

    def append_leaf_hash(self, h: bytes) -> int:
        if len(h) != HASH_LEN:
            raise ValueError("leaf hash must be 32 bytes")
        index = len(self._leaves)
        self._leaves.append(h)
        # Binary-counter style merge of equal-sized perfect subtrees.
        size, node = 1, h
        while self._frontier and self._frontier[-1][0] == size:
            _, left = self._frontier.pop()
            node = node_hash(left, node)
            size *= 2
        self._frontier.append((size, node))
        return index

    def leaf_hash_at(self, index: int) -> bytes:
        return self._leaves[index]

    def root(self) -> bytes:
        """Root of the current tree."""
        if not self._frontier:
            return EMPTY_ROOT
        r = self._frontier[-1][1]
        for _, h in reversed(self._frontier[:-1]):
            r = node_hash(h, r)
        return r

    def root_at(self, size: int) -> bytes:
        """Root of the tree as it was when it had ``size`` leaves."""
        self._check_size(size)
        return EMPTY_ROOT if size == 0 else self._mth(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """Audit path for leaf ``index`` in the tree of ``size`` leaves (leaf-to-root)."""
        size = self.size if size is None else size
        self._check_size(size)
        if not 0 <= index < size:
            raise ValueError("index out of range for tree size")
        return self._path(index, 0, size)

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        """Proof that the tree of ``old_size`` leaves is a prefix of ``new_size``."""
        new_size = self.size if new_size is None else new_size
        self._check_size(new_size)
        if not 0 <= old_size <= new_size:
            raise ValueError("require 0 <= old_size <= new_size")
        if old_size in (0, new_size):
            return []
        return self._subproof(old_size, 0, new_size, True)

    # -- internals ---------------------------------------------------------

    def _check_size(self, size: int) -> None:
        if not 0 <= size <= self.size:
            raise ValueError(f"tree size {size} out of range (current size {self.size})")

    def _mth(self, lo: int, hi: int) -> bytes:
        """MTH(D[lo:hi]) per RFC 6962 (hi > lo)."""
        n = hi - lo
        if n == 1:
            return self._leaves[lo]
        perfect = _is_pow2(n)
        if perfect and (lo, hi) in self._perfect:
            return self._perfect[(lo, hi)]
        k = _split(n)
        r = node_hash(self._mth(lo, lo + k), self._mth(lo + k, hi))
        if perfect:
            self._perfect[(lo, hi)] = r
        return r

    def _path(self, m: int, lo: int, hi: int) -> list[bytes]:
        """PATH(m, D[lo:hi]) where m is relative to lo."""
        n = hi - lo
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return self._path(m, lo, lo + k) + [self._mth(lo + k, hi)]
        return self._path(m - k, lo + k, hi) + [self._mth(lo, lo + k)]

    def _subproof(self, m: int, lo: int, hi: int, b: bool) -> list[bytes]:
        """SUBPROOF(m, D[lo:hi], b) per RFC 6962 section 2.1.2."""
        n = hi - lo
        if m == n:
            return [] if b else [self._mth(lo, hi)]
        k = _split(n)
        if m <= k:
            return self._subproof(m, lo, lo + k, b) + [self._mth(lo + k, hi)]
        return self._subproof(m - k, lo + k, hi, False) + [self._mth(lo, lo + k)]


def verify_inclusion(
    leaf_hash_: bytes, index: int, size: int, proof: list[bytes], root: bytes
) -> bool:
    """Check that ``leaf_hash_`` is leaf ``index`` of the tree (size, root)."""
    if size <= 0 or not 0 <= index < size:
        return False
    fn, sn = index, size - 1
    r = leaf_hash_
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]
) -> bool:
    """Check that tree (old_size, old_root) is a prefix of (new_size, new_root)."""
    if old_size < 0 or new_size < old_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        # The empty tree is a prefix of everything; nothing to prove.
        return not proof and old_root == EMPTY_ROOT
    if not proof:
        return False
    path = list(proof)
    if _is_pow2(old_size):
        path.insert(0, old_root)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0
