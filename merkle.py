"""Merkle checkpoint and inclusion-proof helpers for record digests."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

GENESIS = "0" * 64
PROOF_SCHEMA = "provenance-layer/inclusion-proof/v2"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_NODE_DOMAIN = b"provenance-layer/merkle-node/v2\x00"


def _validate_digest(value: str, label: str) -> None:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError(f"{label} must be a 32-byte lowercase hexadecimal digest")


def _pair(left: str, right: str) -> str:
    _validate_digest(left, "left digest")
    _validate_digest(right, "right digest")
    return hashlib.sha256(_NODE_DOMAIN + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Return the root. An unpaired odd node is promoted unchanged."""

    for index, leaf in enumerate(leaves):
        _validate_digest(leaf, f"leaf {index}")
    if not leaves:
        return GENESIS
    level = list(leaves)
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level) - 1, 2):
            next_level.append(_pair(level[index], level[index + 1]))
        if len(level) % 2:
            next_level.append(level[-1])
        level = next_level
    return level[0]


def inclusion_proof(leaves: list[str], index: int) -> dict[str, Any]:
    """Return an index- and tree-size-aware proof for leaves[index]."""

    if type(index) is not int:
        raise TypeError("leaf index must be an integer")
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    for leaf_index, leaf in enumerate(leaves):
        _validate_digest(leaf, f"leaf {leaf_index}")

    path: list[dict[str, str]] = []
    level = list(leaves)
    cursor = index
    while len(level) > 1:
        sibling = cursor ^ 1
        if sibling < len(level):
            path.append(
                {
                    "hash": level[sibling],
                    "side": "left" if sibling < cursor else "right",
                }
            )
        next_level: list[str] = []
        for pair_index in range(0, len(level) - 1, 2):
            next_level.append(_pair(level[pair_index], level[pair_index + 1]))
        if len(level) % 2:
            next_level.append(level[-1])
        cursor //= 2
        level = next_level

    return {
        "schema": PROOF_SCHEMA,
        "leaf_index": index,
        "tree_size": len(leaves),
        "path": path,
    }


def verify_inclusion(leaf: str, proof: dict[str, Any], root: str) -> bool:
    """Verify a proof while validating its index/size path shape."""

    try:
        _validate_digest(leaf, "leaf")
        _validate_digest(root, "root")
        if not isinstance(proof, dict) or proof.get("schema") != PROOF_SCHEMA:
            return False
        index = proof.get("leaf_index")
        tree_size = proof.get("tree_size")
        path = proof.get("path")
        if type(index) is not int or type(tree_size) is not int:
            return False
        if tree_size < 1 or not 0 <= index < tree_size or not isinstance(path, list):
            return False

        accumulator = leaf
        cursor = index
        level_size = tree_size
        path_index = 0
        while level_size > 1:
            sibling = cursor ^ 1
            if sibling < level_size:
                if path_index >= len(path) or not isinstance(path[path_index], dict):
                    return False
                step = path[path_index]
                sibling_hash = step.get("hash")
                side = step.get("side")
                _validate_digest(sibling_hash, "proof sibling")
                expected_side = "left" if sibling < cursor else "right"
                if side != expected_side:
                    return False
                accumulator = (
                    _pair(sibling_hash, accumulator)
                    if side == "left"
                    else _pair(accumulator, sibling_hash)
                )
                path_index += 1
            cursor //= 2
            level_size = (level_size + 1) // 2

        return path_index == len(path) and hmac.compare_digest(accumulator, root)
    except (TypeError, ValueError):
        return False
