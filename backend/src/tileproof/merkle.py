"""Binary Merkle tree with domain separation and inclusion proofs.

- leaf hash  = SHA-256(0x00 || domain || index (u32 BE) || salt || payload)
- node hash  = SHA-256(0x01 || left || right)
- odd node at a level is promoted unchanged (no duplication, avoids the
  CVE-2012-2459 ambiguity). The number of leaves is fixed by the manifest
  (width, height, tile size), so promotion is unambiguous.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(domain: bytes, index: int, salt: bytes, payload: bytes) -> bytes:
    return sha256(LEAF_PREFIX + domain + index.to_bytes(4, "big") + salt + payload)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


@dataclass(frozen=True)
class ProofStep:
    sibling: bytes
    sibling_is_left: bool


class MerkleTree:
    """Merkle tree built from precomputed leaf hashes."""

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("Merkle tree needs at least one leaf")
        self.levels: list[list[bytes]] = [list(leaves)]
        level = self.levels[0]
        while len(level) > 1:
            nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
            if len(level) % 2:
                nxt.append(level[-1])  # promote odd node
            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> bytes:
        return self.levels[-1][0]

    @property
    def leaves(self) -> list[bytes]:
        return self.levels[0]

    def proof(self, index: int) -> list[ProofStep]:
        steps: list[ProofStep] = []
        for level in self.levels[:-1]:
            sib = index ^ 1
            if sib < len(level):
                steps.append(ProofStep(level[sib], sibling_is_left=sib < index))
            # else: promoted node, no step at this level
            index //= 2
        return steps


def verify_proof(leaf: bytes, index: int, n_leaves: int, proof: list[ProofStep], root: bytes) -> bool:
    """Verify an inclusion proof; n_leaves is needed to know where nodes were promoted."""
    h, size, steps = leaf, n_leaves, iter(proof)
    while size > 1:
        sib = index ^ 1
        if sib < size:
            step = next(steps, None)
            if step is None or step.sibling_is_left != (sib < index):
                return False
            h = node_hash(step.sibling, h) if step.sibling_is_left else node_hash(h, step.sibling)
        index //= 2
        size = (size + 1) // 2
    return next(steps, None) is None and h == root
