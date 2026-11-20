"""C2PA manifest in the published image, pointing to the XRPL anchor (decisions.md Q10, Q20)."""

import io
import json

import numpy as np
import pytest
from conftest import jpeg, rescale
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress import c2pa_embed
from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, sign_image, verify_image
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture
def setup(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    ledger = FakeLedger()
    for name, ctype in (("device", CredentialType.CAPTURE_DEVICE), ("ai", CredentialType.AI_GENERATOR)):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        (d / f"{name}.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key}))
        ledger.issue(w.public_key, ctype)
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    return ledger, Store(tmp_path / "store")


def test_published_image_carries_a_c2pa_manifest_pointing_to_the_anchor(photo, setup):
    ledger, store = setup
    signed, png = sign_image(photo, "device", ledger, store)
    info = c2pa_embed.read(png)
    assert info["tx_hash"] == signed.entry_id
    assert info["manifest_digest"] == signed.manifest.digest()
    assert info["source_type"].endswith("/digitalCapture")
    assert info["state"] == "Valid" and info["signer_trusted"] is False  # test certificate, said honestly
    assert store.image_path(signed.entry_id).read_bytes() == png  # the downloadable file is the C2PA one
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL and "identical" in report.reason  # pixels untouched


def test_ai_images_are_declared_as_generated(photo, setup):
    ledger, store = setup
    _, png = sign_image(photo, "ai", ledger, store)
    assert c2pa_embed.read(png)["source_type"].endswith("/trainedAlgorithmicMedia")


def test_c2pa_dies_after_whatsapp_but_veripress_still_verifies(photo, setup):
    """The pitch moment (decisions.md Q20)."""
    ledger, store = setup
    signed, png = sign_image(photo, "device", ledger, store)
    shared = jpeg(rescale(png_to_rgb(png), 0.5), 70)
    buf = io.BytesIO()
    Image.fromarray(shared).save(buf, "JPEG")
    assert c2pa_embed.read(buf.getvalue()) is None
    report, _ = verify_image(shared, ledger, store)
    assert report.verdict == FinalVerdict.REAL


def test_pixel_edit_breaks_the_c2pa_hard_binding(photo, setup):
    ledger, store = setup
    _, png = sign_image(photo, "device", ledger, store)
    raw = bytearray(png)
    idat = raw.find(b"IDAT")
    raw[idat + 40] ^= 0xFF  # flip one byte of compressed pixel data, keep the C2PA chunk
    info = c2pa_embed.read(bytes(raw))
    assert info is not None and info["state"] != "Valid"


def test_c2pa_can_be_switched_off(photo, setup, monkeypatch):
    ledger, store = setup
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    _, png = sign_image(photo, "device", ledger, store)
    assert c2pa_embed.read(png) is None
