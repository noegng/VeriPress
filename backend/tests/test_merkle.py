import hashlib

import pytest

from tileproof.merkle import MerkleTree, ProofStep, leaf_hash, node_hash, verify_proof


def leaves(n: int) -> list[bytes]:
    return [leaf_hash(b"TEST", i, b"", f"tile-{i}".encode()) for i in range(n)]


def test_root_of_two_leaves_is_domain_separated_node_hash():
    a, b = leaves(2)
    expected = hashlib.sha256(b"\x01" + a + b).digest()
    assert MerkleTree([a, b]).root == expected


def test_odd_leaf_is_promoted_not_duplicated():
    a, b, c = leaves(3)
    expected = hashlib.sha256(b"\x01" + hashlib.sha256(b"\x01" + a + b).digest() + c).digest()
    assert MerkleTree([a, b, c]).root == expected


@pytest.mark.parametrize("n", [1, 2, 3, 5, 7, 8, 13, 300])
def test_every_leaf_has_a_valid_inclusion_proof(n):
    ls = leaves(n)
    tree = MerkleTree(ls)
    for i in range(n):
        assert verify_proof(ls[i], i, n, tree.proof(i), tree.root)


def test_proof_rejects_wrong_index():
    ls = leaves(7)
    tree = MerkleTree(ls)
    assert not verify_proof(ls[2], 3, 7, tree.proof(2), tree.root)


def test_proof_rejects_tampered_leaf():
    ls = leaves(7)
    tree = MerkleTree(ls)
    assert not verify_proof(leaves(8)[7], 2, 7, tree.proof(2), tree.root)


def test_proof_rejects_truncated_or_extended_proof():
    ls = leaves(8)
    tree = MerkleTree(ls)
    proof = tree.proof(5)
    assert not verify_proof(ls[5], 5, 8, proof[:-1], tree.root)
    assert not verify_proof(ls[5], 5, 8, proof + [ProofStep(b"\x00" * 32, False)], tree.root)


def test_leaf_and_node_hashes_cannot_collide():
    a, b = leaves(2)
    # an internal node presented as a leaf payload must not verify as that node
    assert leaf_hash(b"", 0, b"", a + b) != node_hash(a, b)


def test_empty_tree_is_rejected():
    with pytest.raises(ValueError):
        MerkleTree([])
