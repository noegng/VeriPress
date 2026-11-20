"""ZK B — selective disclosure of capture time and place (docs/decisions.md Q16-Q17)."""

import io
import json
from datetime import datetime, timezone

import numpy as np
import pytest
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from tileproof import metadata
from tileproof.ledger import CredentialType, FakeLedger
from tileproof.pipeline import sign_image, verify_image
from tileproof.store import Store


def exif_bytes(dt="2026:11:20 13:36:58", offset="+01:00", lat=(41.0, 6.0, 30.48), lat_ref="N",
               lon=(16.0, 52.0, 12.0), lon_ref="E") -> bytes:
    ex = Image.Exif()
    ifd = ex.get_ifd(0x8769)
    ifd[0x9003] = dt
    if offset:
        ifd[0x9011] = offset
    if lat:
        gps = ex.get_ifd(0x8825)
        gps.update({1: lat_ref, 2: lat, 3: lon_ref, 4: lon})
    return ex.tobytes()


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


# ---------------------------------------------------------------- reading EXIF


def test_capture_time_and_place_are_read_from_exif():
    cap = metadata.read_capture(exif_bytes())
    assert cap.time == int(datetime(2026, 11, 20, 12, 36, 58, tzinfo=timezone.utc).timestamp())  # +01:00
    assert cap.lat_e6 == 41108467 and cap.lon_e6 == 16870000
    assert cap.utc_offset_min == 60


def test_southern_and_western_hemispheres_are_negative():
    cap = metadata.read_capture(exif_bytes(lat=(33.0, 52.0, 0.0), lat_ref="S", lon=(151.0, 12.0, 36.0), lon_ref="W"))
    assert cap.lat_e6 == -33866667 and cap.lon_e6 == -151210000


@pytest.mark.parametrize("raw", [None, b"", exif_bytes(lat=None)])
def test_no_time_or_no_gps_means_no_capture_metadata(raw):
    assert metadata.read_capture(raw) is None


def test_day_and_area_claims_contain_the_capture_without_being_exact():
    cap = metadata.read_capture(exif_bytes())
    day, area = metadata.claims(cap)
    assert day.t_min <= cap.time <= day.t_max and day.t_max - day.t_min == 86399
    assert day.label == "20 Nov 2026"  # local day (UTC+1)
    assert area.lat_min_e6 <= cap.lat_e6 <= area.lat_max_e6 and area.lon_min_e6 <= cap.lon_e6 <= area.lon_max_e6
    assert 80_000 <= area.lat_max_e6 - area.lat_min_e6 <= 120_000  # ~10 km
    assert area.label == "≈ 41.11°N 16.87°E (10 km)"


# ---------------------------------------------------------------- pipeline


@pytest.fixture
def setup(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
    (d / "device.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key}))
    monkeypatch.setenv("TILEPROOF_KEYS", str(d))
    monkeypatch.setenv("TILEPROOF_WATERMARK", "0")
    ledger = FakeLedger()
    ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE)
    return ledger, Store(tmp_path / "store")


def test_signed_photo_proves_its_day_and_area_but_hides_time_and_gps(photo, setup):
    ledger, store = setup
    signed, png = sign_image(photo, "device", ledger, store, exif=exif_bytes())
    assert signed.manifest.meta_commitment
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    claims = {c["kind"]: c for c in report.meta_claims}
    assert claims["day"] == {"kind": "day", "label": "20 Nov 2026", "proof_ok": True}
    assert claims["area"] == {"kind": "area", "label": "≈ 41.11°N 16.87°E (10 km)", "proof_ok": True}
    public = json.dumps(report.to_json()) + (store.root / signed.entry_id / "entry.json").read_text() \
        + (store.root / signed.entry_id / "meta.json").read_text()
    cap = metadata.read_capture(exif_bytes())
    for secret in (str(cap.lat_e6), str(cap.lon_e6), str(cap.time)):  # exact position / second never published
        assert secret not in public


def test_photo_without_exif_has_no_claims(photo, setup):
    ledger, store = setup
    signed, png = sign_image(photo, "device", ledger, store)
    assert signed.manifest.meta_commitment is None
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.meta_claims == []


def test_forged_claim_is_shown_as_unproven(photo, setup):
    """The stored claims are untrusted: labels come from the verified public inputs only."""
    ledger, store = setup
    signed, png = sign_image(photo, "device", ledger, store, exif=exif_bytes())
    path = store.root / signed.entry_id / "meta.json"
    claims = json.loads(path.read_text())
    for i in (1, 2):  # pretend the photo was taken a year earlier (same shape: still a "day")
        claims[0]["public"][i] = str(int(claims[0]["public"][i]) - 86400 * 365)
    path.write_text(json.dumps(claims))
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    day = next(c for c in report.meta_claims if c["kind"] == "day")
    assert day["label"] == "20 Nov 2025" and day["proof_ok"] is False  # shown, but as unproven


def test_claims_copied_from_another_photo_do_not_verify(photo, setup):
    from conftest import photo_like

    ledger, store = setup
    a, png_a = sign_image(photo, "device", ledger, store, exif=exif_bytes())
    b, _ = sign_image(photo_like(seed=8), "device", ledger, store, exif=exif_bytes(dt="2025:01:01 10:00:00"))
    (store.root / a.entry_id / "meta.json").write_text((store.root / b.entry_id / "meta.json").read_text())
    report, _ = verify_image(png_to_rgb(png_a), ledger, store, entry_id=a.entry_id)
    assert report.meta_claims and all(c["proof_ok"] is False for c in report.meta_claims)
