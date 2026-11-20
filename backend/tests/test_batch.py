"""Aggregated anchoring (decisions.md Q8): N signed records, one XRPL transaction.

Each record is signed exactly as before; only anchoring is queued. flush() anchors the Merkle
root of the records; each record gets a receipt (batch tx, index, inclusion proof) from which
the verifier rebuilds a per-photo anchor — then the usual checks apply unchanged.
"""

import io
import json

import numpy as np
import pytest
from conftest import photo_like
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress.batching import BatchingLedger
from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, sign_image, verify_image
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture
def setup(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
    (d / "device.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key}))
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    base = FakeLedger()
    base.issue(w.public_key, CredentialType.CAPTURE_DEVICE)
    store = Store(tmp_path / "store")
    return base, BatchingLedger(base, store), store


def sign_three(batch, store):
    return [sign_image(photo_like(seed=s), "device", batch, store) for s in range(3)]


def test_three_photos_one_transaction(setup):
    base, batch, store = setup
    signed = sign_three(batch, store)
    assert len(base.anchors) == 0
    report, _ = verify_image(png_to_rgb(signed[0][1]), base, store, entry_id=signed[0][0].entry_id)
    assert report.pending  # queued, not anchored yet
    tx = batch.flush()
    assert len(base.anchors) == 1 and tx in base.anchors
    for i, (res, png) in enumerate(signed):
        report, _ = verify_image(png_to_rgb(png), base, store, entry_id=res.entry_id)
        assert report.verdict == FinalVerdict.REAL, report.reason
        assert not report.pending
        assert report.anchor.tx_hash == tx
        assert report.batch == {"tx_hash": tx, "index": i, "size": 3}
        assert report.to_json()["batch"] == report.batch


def test_batched_photo_found_without_id(setup):
    base, batch, store = setup
    signed = sign_three(batch, store)
    batch.flush()
    report, _ = verify_image(png_to_rgb(signed[1][1]), base, store)  # phash lookup
    assert report.entry_id == signed[1][0].entry_id and report.verdict == FinalVerdict.REAL


def test_forged_inclusion_proof_is_unknown(setup):
    base, batch, store = setup
    signed = sign_three(batch, store)
    batch.flush()
    rid = signed[0][0].entry_id
    receipt = store.get_receipt(rid)
    receipt["proof"][0]["sibling"] = "00" * 32
    store.put_receipt(rid, receipt)
    report, _ = verify_image(png_to_rgb(signed[0][1]), base, store, entry_id=rid)
    assert report.verdict == FinalVerdict.UNKNOWN and "batch" in report.reason.lower()


def test_leaf_fields_swapped_in_the_receipt_are_unknown(setup):
    """The receipt is untrusted: swapping in another record's signature breaks the inclusion."""
    base, batch, store = setup
    signed = sign_three(batch, store)
    batch.flush()
    a, b = signed[0][0].entry_id, signed[1][0].entry_id
    ra, rb = store.get_receipt(a), store.get_receipt(b)
    ra["leaf"]["s"] = rb["leaf"]["s"]
    store.put_receipt(a, ra)
    report, _ = verify_image(png_to_rgb(signed[0][1]), base, store, entry_id=a)
    assert report.verdict == FinalVerdict.UNKNOWN


def test_attacker_batch_root_cannot_vouch_for_a_forged_record(setup, tmp_path):
    """Anyone can anchor a batch root; without the device's signature over the digest it is worthless."""
    from veripress.batching import leaf_payload

    base, batch, store = setup
    signed = sign_three(batch, store)
    batch.flush()
    rid = signed[0][0].entry_id
    receipt = store.get_receipt(rid)
    receipt["leaf"]["s"] = "00" * 64  # forged signature, re-anchored in the attacker's own batch
    from veripress.merkle import MerkleTree

    tree = MerkleTree([leaf_payload(receipt["leaf"], 0)])
    tx = base.anchor_batch(tree.root.hex(), 1)
    store.put_receipt(rid, {"batch_tx": tx.tx_hash, "index": 0, "leaf": receipt["leaf"], "proof": []})
    report, _ = verify_image(png_to_rgb(signed[0][1]), base, store, entry_id=rid)
    assert report.verdict == FinalVerdict.UNKNOWN and not report.signature_ok


def test_a_batch_tx_is_not_a_photo_anchor(setup):
    base, batch, store = setup
    sign_three(batch, store)
    tx = batch.flush()
    assert verify_image(photo_like(seed=0), base, store, entry_id=tx)[0].verdict == FinalVerdict.UNKNOWN


def test_empty_flush_sends_nothing(setup):
    base, batch, _ = setup
    assert batch.flush() is None and len(base.anchors) == 0


def test_queued_record_is_checked_against_revocation_now(setup):
    """A queued receipt's time is untrusted: revocation must not be dodged by backdating it."""
    base, batch, store = setup
    res, png = sign_image(photo_like(seed=0), "device", batch, store)
    receipt = store.get_receipt(res.entry_id)
    device = res.manifest.signer
    base.revoke(device, at=1)  # revoked long ago… after a forged queued "time" of 0
    receipt["queued"]["t"] = 0
    store.put_receipt(res.entry_id, receipt)
    report, _ = verify_image(png_to_rgb(png), base, store, entry_id=res.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN


def test_develop_chain_through_a_batched_negative(setup):
    from conftest import jpeg

    base, batch, store = setup
    raw, raw_png = sign_image(photo_like(seed=0), "device", batch, store)
    batch.flush()
    dev, dev_png = sign_image(jpeg(png_to_rgb(raw_png), 90), "device", batch, store,
                              parent=raw.entry_id, op="develop")
    batch.flush()
    report, _ = verify_image(png_to_rgb(dev_png), base, store, entry_id=dev.entry_id)
    assert report.verdict == FinalVerdict.REAL, report.reason
    assert [h["verified"] for h in report.history] == [True, True]
