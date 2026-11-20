import io
import json

import numpy as np
import pytest
from conftest import jpeg, rescale
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from tileproof.ledger import CredentialType, FakeLedger
from tileproof.pipeline import FinalVerdict, redact_image, sign_image, verify_image
from tileproof.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture
def keys(tmp_path, monkeypatch):
    """Demo keys in the format written by Dev B's setup script (docs/interfaces.md)."""
    d = tmp_path / "keys"
    d.mkdir()
    out = {}
    for name in ("device", "ai"):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        data = {"seed": w.seed, "address": w.classic_address, "public_key": w.public_key, "private_key": w.private_key}
        (d / f"{name}.json").write_text(json.dumps(data))
        out[name] = w.public_key
    monkeypatch.setenv("TILEPROOF_KEYS", str(d))
    return out


@pytest.fixture
def ledger(keys):
    lg = FakeLedger()
    lg.issue(keys["device"], CredentialType.CAPTURE_DEVICE)
    lg.issue(keys["ai"], CredentialType.AI_GENERATOR)
    return lg


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


def test_device_signed_untouched_image_is_real(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    report, heatmap = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL
    assert report.credential == CredentialType.CAPTURE_DEVICE
    assert report.signature_ok
    assert heatmap is not None


def test_edited_image_is_edited_with_heatmap(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    edited = png_to_rgb(png).copy()
    edited[100:200, 100:200] = (255, 0, 255)
    report, heatmap = verify_image(jpeg(edited, 85), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    assert report.tiles.counts()["changed"] > 0
    assert heatmap is not None


def test_ai_generator_signed_image_is_ai(photo, ledger, store):
    signed, png = sign_image(photo, "ai", ledger, store)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.AI
    assert report.credential == CredentialType.AI_GENERATOR


def test_revoked_credential_is_unknown(photo, ledger, store, keys):
    signed, png = sign_image(photo, "device", ledger, store)
    ledger.revoke(keys["device"])
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert report.credential is None
    assert "credential" in report.reason.lower()


def test_forged_signature_is_unknown(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    a = ledger.anchors[signed.entry_id]
    bad = "00" * 64
    ledger.anchors[signed.entry_id] = type(a)(a.tx_hash, a.digest, bad, a.pubkey, a.timestamp, a.explorer_url)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert not report.signature_ok
    assert "signature" in report.reason.lower()


def test_manifest_swapped_in_store_is_unknown(photo, ledger, store):
    """The off-chain store is untrusted: its manifest must match the anchored digest."""
    from conftest import photo_like

    signed, png = sign_image(photo, "device", ledger, store)
    other, _ = sign_image(photo_like(seed=3), "device", ledger, store)
    entry, forged = store.get(signed.entry_id), store.get(other.entry_id)
    entry.manifest, entry.disclosure = forged.manifest, forged.disclosure
    store.put(entry)
    report, _ = verify_image(photo_like(seed=3), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "manifest" in report.reason.lower()


def test_tampered_disclosure_is_unknown(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    entry = store.get(signed.entry_id)
    entry.disclosure.tiles[3].f[0] += 1
    store.put(entry)
    report, heatmap = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "disclosure" in report.reason.lower()
    assert heatmap is None


def test_unknown_image_is_unknown_without_heatmap(photo, ledger, store):
    from conftest import photo_like

    sign_image(photo, "device", ledger, store)
    report, heatmap = verify_image(photo_like(seed=7), ledger, store)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert report.found_by is None and report.anchor is None and report.tiles is None
    assert heatmap is None


def test_unknown_entry_id_is_unknown(photo, ledger, store):
    report, heatmap = verify_image(photo, ledger, store, entry_id="DEADBEEF")
    assert report.verdict == FinalVerdict.UNKNOWN
    assert heatmap is None


def test_anchor_missing_on_ledger_is_unknown(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    del ledger.anchors[signed.entry_id]
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "anchor" in report.reason.lower()


def test_whatsapp_like_copy_is_found_by_phash_and_real(photo, ledger, store, monkeypatch):
    """Metadata stripped, downscaled, recompressed, no id, no watermark: perceptual hash fallback."""
    monkeypatch.setenv("TILEPROOF_WATERMARK", "0")
    sign_image(photo, "device", ledger, store)
    shared = jpeg(rescale(photo, 0.5), 70)
    report, _ = verify_image(shared, ledger, store)
    assert report.found_by == "phash"
    assert report.verdict == FinalVerdict.REAL
    assert report.tiles.verdict.value == "recompressed"


def test_phash_picks_the_right_image_among_several(ledger, store):
    from conftest import photo_like

    ids = {s: sign_image(photo_like(seed=s), "device", ledger, store)[0].entry_id for s in range(5)}
    report, _ = verify_image(jpeg(photo_like(seed=3), 75), ledger, store)
    assert report.entry_id == ids[3]


def test_report_json_matches_api_contract(photo, ledger, store):
    """Shape fixed in docs/interfaces.md, consumed by Dev B's page."""
    signed, png = sign_image(photo, "device", ledger, store)
    report, heatmap = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    j = report.to_json(heatmap)
    json.dumps(j)  # serialisable
    assert set(j) == {"verdict", "reason", "found_by", "entry_id", "anchor", "credential",
                      "signature_ok", "tiles", "heatmap_png_b64"}
    assert j["verdict"] == "real" and j["credential"] == "CAPTURE_DEVICE" and j["found_by"] == "tx_hash"
    assert set(j["anchor"]) == {"tx_hash", "timestamp", "explorer_url", "signer"}
    assert j["anchor"]["signer"] == signed.manifest.signer
    assert set(j["tiles"]) == {"verdict", "grid", "counts", "statuses", "distances"}
    assert j["tiles"]["grid"] == {"cols": 20, "rows": 15, "tile": 32}
    assert len(j["tiles"]["statuses"]) == 300 and j["tiles"]["statuses"][0] == "exact"
    assert j["heatmap_png_b64"].startswith("iVBOR")


def test_unknown_report_json_has_nulls(photo, ledger, store):
    report, heatmap = verify_image(photo, ledger, store)
    j = report.to_json(heatmap)
    assert j["verdict"] == "unknown" and j["found_by"] is None
    assert j["anchor"] is None and j["tiles"] is None and j["heatmap_png_b64"] is None


def test_sign_result_json_matches_api_contract(photo, ledger, store):
    signed, _ = sign_image(photo, "device", ledger, store)
    j = signed.to_json()
    json.dumps(j)
    assert set(j) == {"entry_id", "tx_hash", "explorer_url", "digest", "signer", "grid", "roots", "image_url"}
    assert j["image_url"] == f"/api/files/{signed.entry_id}.png"
    assert j["digest"] == signed.manifest.digest()
    assert set(j["roots"]) == {"exact", "robust"}


def test_redacted_copy_stays_real_with_hidden_tiles(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(64, 64, 160, 128)], store)
    assert rid == f"{signed.entry_id}-r1"
    red = png_to_rgb(red_png)
    assert (red[64:128, 64:160] == 0).all()
    report, _ = verify_image(red, ledger, store, entry_id=rid)
    assert report.verdict == FinalVerdict.REAL
    assert report.tiles.counts()["redacted"] == 3 * 2
    assert report.anchor.tx_hash == signed.entry_id  # same anchor as the original


def test_redacted_copy_is_found_by_phash(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(0, 0, 320, 240)], store)
    report, _ = verify_image(jpeg(png_to_rgb(red_png), 80), ledger, store)
    assert report.entry_id == rid and report.verdict == FinalVerdict.REAL


def test_whatsapp_like_copy_is_found_by_watermark_and_real(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    shared = jpeg(rescale(png_to_rgb(png), 0.5), 60)
    report, _ = verify_image(shared, ledger, store)
    assert report.found_by == "watermark"
    assert report.entry_id == signed.entry_id
    assert report.verdict == FinalVerdict.REAL


def test_watermark_copied_onto_another_image_is_detected(photo, ledger, store):
    from conftest import photo_like
    from tileproof.watermark import embed

    signed, _ = sign_image(photo, "device", ledger, store)
    fake = embed(photo_like(seed=11), bytes.fromhex(signed.manifest.wm_id))
    report, _ = verify_image(jpeg(fake, 85), ledger, store)
    assert report.found_by == "watermark"
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "watermark" in report.reason.lower()
