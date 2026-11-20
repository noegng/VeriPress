"""Adversarial review (docs/security-review.md § "Adversarial review"): each test is an attack that
used to pass, plus guards against false positives of its fix."""

import io
import json

import numpy as np
import pytest
from conftest import jpeg, photo_like, rescale
from PIL import Image, ImageDraw, ImageFilter
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress import features as F
from veripress.commitment import TileStatus, commit, redact, verify
from veripress.ledger import CredentialType, FakeLedger
from veripress.perceptual import phash
from veripress.pipeline import FinalVerdict, redact_image, sign_image, verify_image
from veripress.store import Entry, Store
from veripress.tiling import grid_for


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture
def keys(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    out = {}
    for name in ("device", "ai"):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        data = {"seed": w.seed, "address": w.classic_address, "public_key": w.public_key, "private_key": w.private_key}
        (d / f"{name}.json").write_text(json.dumps(data))
        out[name] = w.public_key
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    return out


@pytest.fixture
def ledger(keys):
    lg = FakeLedger()
    lg.issue(keys["device"], CredentialType.CAPTURE_DEVICE, at=0)
    lg.issue(keys["ai"], CredentialType.AI_GENERATOR, at=0)
    return lg


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


@pytest.fixture
def no_watermark(monkeypatch):
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")


BOX = (192, 160, 320, 288)  # 4x4 tiles of 32 px in the 640x480 test photo


def recolour_same_luma(rgb: np.ndarray, box=BOX) -> np.ndarray:
    """Complementary colours, same luminance (red car -> cyan car)."""
    x0, y0, x1, y1 = box
    ycc = np.asarray(Image.fromarray(rgb[y0:y1, x0:x1]).convert("YCbCr")).copy()
    ycc[..., 1] = 255 - ycc[..., 1]
    ycc[..., 2] = 255 - ycc[..., 2]
    out = rgb.copy()
    out[y0:y1, x0:x1] = np.asarray(Image.fromarray(ycc, "YCbCr").convert("RGB"))
    return out


def blur(rgb: np.ndarray, radius: float, box=BOX) -> np.ndarray:
    im = Image.fromarray(rgb)
    im.paste(im.crop(box).filter(ImageFilter.GaussianBlur(radius)), box[:2])
    return np.asarray(im)


# ---------------------------------------------------------------- 7. colour and detail features


def test_colour_change_with_the_same_luminance_is_edited(photo, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    report, _ = verify_image(jpeg(recolour_same_luma(png_to_rgb(png)), 85), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    grid = signed.manifest.grid
    changed = {i for i, s in enumerate(report.tiles.statuses) if s == TileStatus.CHANGED}
    assert changed and changed <= set(grid.tiles_in_box(*BOX))


def test_blurred_region_is_edited_even_after_recompression(photo, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    report, _ = verify_image(jpeg(blur(png_to_rgb(png), 5), 85), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.EDITED


@pytest.mark.parametrize("seed", range(4))
def test_benign_shared_copies_still_verify_with_colour_and_detail_features(ledger, store, no_watermark, seed):
    img = photo_like(seed=seed)
    signed, png = sign_image(img, "device", ledger, store)
    for shared in (jpeg(rescale(png_to_rgb(png), 0.5), 60), jpeg(png_to_rgb(png), 72), jpeg(img, 80)):
        report, _ = verify_image(shared, ledger, store, entry_id=signed.entry_id)
        assert report.verdict == FinalVerdict.REAL, report.reason


def test_new_records_commit_colour_and_detail_features(photo):
    manifest, disclosure = commit(photo, b"\0" * 32)
    assert manifest.feature == F.SPEC
    assert F.SPEC["chroma"] > 0 and F.SPEC["n"] > 10
    assert len(disclosure.tiles[0].f) == F.vector_length(F.SPEC)


def test_records_signed_with_the_first_feature_set_still_verify(photo):
    """Photos anchored before this change (luma only, 10 coefficients) keep verifying."""
    manifest, disclosure = commit(photo, b"\0" * 32, spec=F.SPEC_V1)
    assert manifest.feature == F.SPEC_V1 and len(disclosure.tiles[0].f) == 10
    assert verify(jpeg(photo, 80), manifest, disclosure).verdict.value == "recompressed"


def test_unknown_feature_parameters_are_refused(photo):
    manifest, disclosure = commit(photo, b"\0" * 32)
    manifest.feature = {**F.SPEC, "n": 99}
    with pytest.raises(ValueError):
        verify(photo, manifest, disclosure)


# ---------------------------------------------------------------- 4. local edit in a lossless copy


def test_subtle_local_edit_in_a_lossless_copy_is_edited(photo, ledger, store, no_watermark):
    """Most tiles still byte-identical: the copy is lossless, so a merely 'close' tile was edited."""
    signed, png = sign_image(photo, "device", ledger, store)
    report, _ = verify_image(blur(png_to_rgb(png), 1.5), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    assert report.tiles.counts()["robust"] == 0


def test_jpeg_of_an_image_with_flat_areas_is_not_mistaken_for_a_lossless_edit(ledger, store, no_watermark):
    """Flat tiles can survive JPEG byte for byte: they must not make a JPEG look lossless."""
    img = photo_like(seed=5)
    img[:, :400] = 255  # blown-out sky over most of the picture
    signed, png = sign_image(img, "device", ledger, store)
    report, _ = verify_image(jpeg(png_to_rgb(png), 90), ledger, store, entry_id=signed.entry_id)
    assert report.tiles.counts()["exact"] > 0
    assert report.verdict == FinalVerdict.REAL, report.reason


# ---------------------------------------------------------------- 1. image that does not match its record


def test_unrelated_image_checked_against_an_entry_id_is_unknown(photo, ledger, store, no_watermark):
    signed, _ = sign_image(photo, "device", ledger, store)
    report, _ = verify_image(photo_like(seed=9), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "does not match" in report.reason


# ---------------------------------------------------------------- 5. lookup poisoning


def test_fake_redacted_variant_in_the_store_does_not_hide_the_genuine_record(photo, ledger, store):
    """Built from public data only: the signed manifest + a fully redacted disclosure, with the
    perceptual hash of the copy being shared, so the lookup ranks it first."""
    signed, png = sign_image(photo, "device", ledger, store)
    shared = jpeg(png_to_rgb(png), 80)
    e = store.get(signed.entry_id)
    _, fake = redact(png_to_rgb(png), e.manifest, e.disclosure, set(range(e.manifest.grid.count)))
    store.put(Entry(f"{signed.entry_id}-r7", signed.entry_id, e.manifest, fake, phash(shared)))
    report, _ = verify_image(shared, ledger, store)
    assert report.verdict == FinalVerdict.REAL
    assert report.entry_id == signed.entry_id


def test_forged_perceptual_hash_on_another_record_does_not_hide_the_genuine_record(ledger, store, no_watermark):
    a, _ = sign_image(photo_like(seed=1), "device", ledger, store)
    b, _ = sign_image(photo_like(seed=2), "device", ledger, store)
    shared = jpeg(photo_like(seed=1), 80)
    p = store.root / b.entry_id / "entry.json"
    d = json.loads(p.read_text())
    d["phash"] = f"{phash(shared):016x}"  # the store is untrusted: anyone can list a record anywhere
    p.write_text(json.dumps(d))
    report, _ = verify_image(shared, ledger, store)
    assert report.verdict == FinalVerdict.REAL
    assert report.entry_id == a.entry_id


# ---------------------------------------------------------------- 3. post-quantum downgrade by omission


def test_ed25519_only_manifest_for_a_device_with_an_attested_pq_key_is_unknown(photo, keys, ledger, store, no_watermark):
    """After Q-day a forger may hold the Ed25519 key only: it must not get 'real' by simply not
    declaring the ML-DSA-87 key the registry attests."""
    ledger.issue(keys["device"], CredentialType.CAPTURE_DEVICE, pq_hash="ab" * 32, at=0)
    signed, png = sign_image(photo, "device", ledger, store)  # this device has no ML-DSA key file
    assert signed.manifest.pq_pubkey_sha256 is None
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "post-quantum" in report.reason.lower()


def test_photo_anchored_before_the_pq_key_was_attested_stays_real(photo, keys, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    later = ledger.fetch_anchor(signed.entry_id).timestamp + 60
    ledger.issue(keys["device"], CredentialType.CAPTURE_DEVICE, pq_hash="ab" * 32, at=later)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL


# ---------------------------------------------------------------- 6. content under a redaction


def test_text_written_inside_a_redacted_area_is_changed(photo, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(96, 96, 288, 224)], store)
    im = Image.fromarray(png_to_rgb(red_png))
    d = ImageDraw.Draw(im)
    for y in range(100, 220, 12):
        d.text((100, y), "SECRET MESSAGE 0123456789", fill=(40, 40, 40))
    report, _ = verify_image(np.asarray(im), ledger, store, entry_id=rid)
    assert report.verdict == FinalVerdict.EDITED
    assert report.tiles.counts()["changed"] > 0


@pytest.mark.parametrize("quality,scale", [(85, 1.0), (72, 0.5), (60, 0.6)])
def test_redacted_copy_shared_as_jpeg_keeps_its_redacted_tiles(photo, ledger, store, no_watermark, quality, scale):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(96, 96, 288, 224)], store)
    shared = jpeg(rescale(png_to_rgb(red_png), scale) if scale != 1.0 else png_to_rgb(red_png), quality)
    report, _ = verify_image(shared, ledger, store, entry_id=rid)
    # The hidden tiles still pass as redacted. (At these sizes, 16-20 px per tile once shared, a
    # neighbour of the black box may drift past the tolerance: that predates this check.)
    assert report.tiles.counts()["redacted"] == len(grid_for(photo, 32).tiles_in_box(96, 96, 288, 224))
