"""Merkle tree over record hashes — checkpointing and inclusion proofs.

The sovereignty property in code: an inclusion proof shows that ONE
decision belongs to an anchored checkpoint without revealing any other
decision in the ledger.
"""

from __future__ import annotations

import hashlib

GENESIS = "0" * 64


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pair(left: str, right: str) -> str:
    return _h(bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaves: list[str]) -> str:
    """Root over hex leaf hashes. Odd node promotes."""
    if not leaves:
        return GENESIS
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_pair(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def inclusion_proof(leaves: list[str], index: int) -> list[tuple[str, str]]:
    """Audit path for leaves[index]: list of (sibling_hash, side)."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    proof = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(_pair(level[i], level[i + 1]))
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        sibling = idx ^ 1  # neighbour in the pair
        if sibling < len(level) and sibling != idx:
            side = "left" if sibling < idx else "right"
            proof.append((level[sibling], side))
        idx //= 2
        level = nxt
    return proof


def verify_inclusion(leaf: str, proof: list[tuple[str, str]], root: str) -> bool:
    """Re-derive the root from a single leaf and its audit path."""
    acc = leaf
    for sibling, side in proof:
        acc = _pair(sibling, acc) if side == "left" else _pair(acc, sibling)
    return acc == root
