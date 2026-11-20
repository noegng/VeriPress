"""Aggregated anchoring (decisions.md Q8): N signed records, one XRPL transaction. OWNER: Dev A.

`BatchingLedger(base, store)` is a Ledger for *signing*: anchor / anchor_anonymous /
anchor_passkey only queue the record (what its memo would have carried) and return a
provisional anchor (validated=False, tx_hash = the manifest digest, used as entry id).
`flush()` anchors the Merkle root of the queued records with `base.anchor_batch(root, n)` and
writes each record's receipt {batch_tx, index, leaf, proof} to the store.

Verification (pipeline._fetch_anchor) rebuilds a per-photo anchor from a receipt: the leaf is
recomputed from the receipt's fields, its inclusion is checked against the root read on chain
(with the leaf count from the chain), and the usual signature / proof checks then apply. The
receipt is untrusted like the rest of the store; anyone may anchor a batch root, but cannot
put a valid device signature / ZK proof / passkey assertion in it.
"""

from __future__ import annotations

import time

from .contentaddr import canonical_json
from .ledger import Anchor, Ledger
from .merkle import MerkleTree, ProofStep, leaf_hash, verify_proof
from .store import Store

BATCH_DOMAIN = b"VPB1"
FIELDS = ("d", "s", "k", "a", "r", "h")  # digest, signature, pubkey, anonymous, registry root, bundle hash


def leaf_payload(fields: dict, index: int) -> bytes:
    return leaf_hash(BATCH_DOMAIN, index, b"", canonical_json({k: fields.get(k, "") for k in FIELDS}))


def _anchor_from_fields(tx_hash: str, f: dict, timestamp: int, explorer: str, validated: bool) -> Anchor:
    return Anchor(tx_hash, str(f.get("d", "")), str(f.get("s", "")), str(f.get("k", "")), timestamp, explorer,
                  validated=validated, anonymous=bool(f.get("a")), registry_root=str(f.get("r", "")),
                  bundle_hash=str(f.get("h", "")))


def resolve_receipt(receipt: dict, ledger: Ledger) -> tuple[Anchor | None, dict | None, str]:
    """(per-photo anchor, batch info, error). Queued records give a provisional anchor whose
    time is *now* (the stored time is untrusted: it must not move revocation checks back)."""
    leaf = receipt.get("leaf") or receipt.get("queued")
    if not isinstance(leaf, dict):
        return None, None, "Malformed batch receipt"
    if "queued" in receipt:
        return _anchor_from_fields(str(leaf.get("d", "")).upper(), leaf, int(time.time()), "", False), None, ""
    batch = ledger.fetch_anchor(str(receipt.get("batch_tx", "")))
    if batch is None or batch.batch_size <= 0:
        return None, None, f"Batch transaction {receipt.get('batch_tx')} not found on the ledger"
    try:
        index = int(receipt["index"])
        steps = [ProofStep(bytes.fromhex(p["sibling"]), bool(p["left"])) for p in receipt.get("proof", [])]
        ok = 0 <= index < batch.batch_size and verify_proof(
            leaf_payload(leaf, index), index, batch.batch_size, steps, bytes.fromhex(batch.digest))
    except (KeyError, TypeError, ValueError):
        ok = False
    if not ok:
        return None, None, "Batch inclusion proof does not match the anchored batch root"
    info = {"tx_hash": batch.tx_hash, "index": index, "size": batch.batch_size}
    return _anchor_from_fields(batch.tx_hash, leaf, batch.timestamp, batch.explorer_url, batch.validated), info, ""


class BatchingLedger:
    def __init__(self, base: Ledger, store: Store) -> None:
        self.base, self.store = base, store
        self.queue: list[tuple[str, dict]] = []

    def __getattr__(self, name):  # reads (fetch_anchor, credential_type, …) go to the real ledger
        return getattr(self.base, name)

    def _queue(self, fields: dict) -> Anchor:
        entry_id = fields["d"].upper()
        self.queue.append((entry_id, fields))
        self.store.put_receipt(entry_id, {"queued": fields})
        return _anchor_from_fields(entry_id, fields, int(time.time()), "", False)

    def anchor(self, digest: str, signature: str, pubkey: str, wait: bool = True) -> Anchor:
        return self._queue({"d": digest, "s": signature, "k": pubkey, "a": 0, "r": "", "h": ""})

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        return self._queue({"d": digest, "s": "", "k": "", "a": 1, "r": registry_root, "h": bundle_hash})

    def anchor_passkey(self, digest: str, pubkey: str, bundle_hash: str, wait: bool = True) -> Anchor:
        return self._queue({"d": digest, "s": "", "k": pubkey, "a": 0, "r": "", "h": bundle_hash})

    def flush(self, wait: bool = True) -> str | None:
        """Anchor the queued records in one transaction; returns its hash (None if empty)."""
        if not self.queue:
            return None
        records, self.queue = self.queue, []
        tree = MerkleTree([leaf_payload(f, i) for i, (_, f) in enumerate(records)])
        batch = self.base.anchor_batch(tree.root.hex(), len(records), wait=wait)
        for i, (entry_id, fields) in enumerate(records):
            proof = [{"sibling": s.sibling.hex(), "left": s.sibling_is_left} for s in tree.proof(i)]
            self.store.put_receipt(entry_id, {"batch_tx": batch.tx_hash, "index": i, "leaf": fields, "proof": proof})
        return batch.tx_hash
