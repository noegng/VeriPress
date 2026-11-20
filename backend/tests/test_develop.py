"""Digital negative -> reference JPEG (Apple Reference Image phase 1 / phase 2, decentralised).

The device signs the RAW development (op "capture"), then signs the JPEG it developed from it
(op "develop", parent = RAW anchor). The JPEG is REAL only if the same device signed both and
the chain verifies; otherwise it is a mere signed edit.
"""

import io
import json

import numpy as np
import pytest
from conftest import jpeg, rescale
from PIL import Image, ImageEnhance
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, sign_image, verify_image
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


def develop(rgb: np.ndarray) -> np.ndarray:
    """A camera-like development: contrast + saturation, downscale, JPEG."""
    img = ImageEnhance.Color(ImageEnhance.Contrast(Image.fromarray(rgb)).enhance(1.25)).enhance(1.2)
    return jpeg(rescale(np.asarray(img), 0.75), 92)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    ledger = FakeLedger()
    for name in ("device", "ai"):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        (d / f"{name}.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key}))
        ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE if name == "device" else CredentialType.AI_GENERATOR)
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    return ledger, Store(tmp_path / "store")


def test_jpeg_developed_from_a_signed_raw_is_real(photo, setup):
    ledger, store = setup
    raw, raw_png = sign_image(photo, "device", ledger, store)  # the digital negative
    dev, dev_png = sign_image(develop(png_to_rgb(raw_png)), "device", ledger, store, parent=raw.entry_id, op="develop")
    assert dev.manifest.op == "develop" and dev.manifest.parent == raw.entry_id
    report, _ = verify_image(png_to_rgb(dev_png), ledger, store, entry_id=dev.entry_id)
    assert report.verdict == FinalVerdict.REAL, report.reason
    assert "developed from the signed raw" in report.reason.lower()
    assert [h["op"] for h in report.history] == ["develop", "capture"]


def test_developed_jpeg_shared_on_whatsapp_is_still_real(photo, setup):
    ledger, store = setup
    raw, raw_png = sign_image(photo, "device", ledger, store)
    dev, dev_png = sign_image(develop(png_to_rgb(raw_png)), "device", ledger, store, parent=raw.entry_id, op="develop")
    report, _ = verify_image(jpeg(rescale(png_to_rgb(dev_png), 0.6), 65), ledger, store)
    assert report.entry_id == dev.entry_id and report.verdict == FinalVerdict.REAL


def test_developing_another_device_s_raw_is_refused(photo, setup):
    ledger, store = setup
    raw, raw_png = sign_image(photo, "ai", ledger, store)  # signed by another key
    with pytest.raises(ValueError, match="same device"):
        sign_image(develop(png_to_rgb(raw_png)), "device", ledger, store, parent=raw.entry_id, op="develop")


def test_develop_needs_a_parent(photo, setup):
    ledger, store = setup
    with pytest.raises(ValueError, match="parent"):
        sign_image(photo, "device", ledger, store, op="develop")


def test_develop_whose_negative_cannot_be_verified_is_only_an_edit(photo, setup):
    ledger, store = setup
    raw, raw_png = sign_image(photo, "device", ledger, store)
    dev, dev_png = sign_image(develop(png_to_rgb(raw_png)), "device", ledger, store, parent=raw.entry_id, op="develop")
    del ledger.anchors[raw.entry_id]  # the negative's anchor is gone
    report, _ = verify_image(png_to_rgb(dev_png), ledger, store, entry_id=dev.entry_id)
    assert report.verdict == FinalVerdict.EDITED and "could not be verified" in report.reason
