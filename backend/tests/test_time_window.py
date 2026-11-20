"""Capture time window [T0, T1] (Apple Reference Image's T0/T1, decisions after the track slides).

T0: the signed manifest embeds the latest validated XRPL ledger (index + hash) at signing time;
    a ledger hash cannot be guessed in advance, so the image was signed after that ledger closed.
T1: the anchor's ledger close time.
"""

import io
import json

import numpy as np
import pytest
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

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
    ledger = FakeLedger()
    ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE)
    return ledger, Store(tmp_path / "store")


def test_signed_photo_has_a_verifiable_time_window(photo, setup):
    ledger, store = setup
    index, ledger_hash, closed = ledger.latest_validated()
    signed, png = sign_image(photo, "device", ledger, store)
    assert signed.manifest.t0 == {"ledger_index": index, "ledger_hash": ledger_hash}
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    anchor = ledger.fetch_anchor(signed.entry_id)
    assert report.time_window == {"not_before": closed, "not_after": anchor.timestamp,
                                  "ledger_index": index, "t0_ok": True}
    assert report.to_json()["time_window"] == report.time_window


def test_unknown_ledger_hash_does_not_give_a_lower_bound(photo, setup, monkeypatch):
    """A signer cannot claim an earlier/later T0 with a made-up hash: it simply does not verify."""
    ledger, store = setup
    monkeypatch.setattr(ledger, "latest_validated", lambda: (999_999, "AB" * 32, 1_700_000_000))
    signed, png = sign_image(photo, "device", ledger, store)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.time_window["t0_ok"] is False and report.time_window["not_before"] is None
    assert report.verdict == FinalVerdict.REAL  # the photo itself is still authentic


def test_ledger_without_t0_support_still_signs(photo, setup, monkeypatch):
    ledger, store = setup

    def unsupported():
        raise NotImplementedError

    monkeypatch.setattr(ledger, "latest_validated", unsupported)
    signed, png = sign_image(photo, "device", ledger, store)
    assert signed.manifest.t0 is None
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.time_window["not_before"] is None and report.time_window["not_after"] is not None
