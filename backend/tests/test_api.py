"""API smoke tests — OWNER: Dev B.  Offline: FakeLedger, watermark off, throwaway keys + store.

The env is set inside a module fixture and restored afterwards: pytest imports every test
module before running any, so module-level env changes would leak into Dev A's tests.
"""

import importlib
import io
import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image


def _write_demo_keys(folder: Path) -> None:
    from xrpl.constants import CryptoAlgorithm
    from xrpl.core.keypairs import derive_keypair
    from xrpl.wallet import Wallet

    folder.mkdir(parents=True, exist_ok=True)
    for name in ("device", "ai"):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        pub, priv = derive_keypair(w.seed, algorithm=CryptoAlgorithm.ED25519)
        data = {"seed": w.seed, "address": w.address, "public_key": pub, "private_key": priv}
        (folder / f"{name}.json").write_text(json.dumps(data))


@pytest.fixture(scope="module", autouse=True)
def client(tmp_path_factory):
    from fastapi.testclient import TestClient

    tmp = tmp_path_factory.mktemp("api")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("TILEPROOF_KEYS", str(tmp / "keys-elsewhere"))  # not backend/keys: review item 2
        mp.setenv("TILEPROOF_STORE", str(tmp / "store"))
        mp.setenv("TILEPROOF_WATERMARK", "0")
        mp.setenv("TILEPROOF_LEDGER", "fake")
        _write_demo_keys(tmp / "keys-elsewhere")
        import tileproof.api

        api = importlib.reload(tileproof.api)  # the app reads its config at import time
        global _client
        _client = TestClient(api.app)
        yield _client


_client = None


def png(rgb: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(rgb).save(buf, "PNG")
    return buf.getvalue()


def post_verify(data: bytes, name: str = "x.png", **form):
    return _client.post("/api/verify", files={"image": (name, data, "image/png")}, data=form)


@pytest.fixture(scope="module")
def signed(client):
    from conftest import photo_like

    r = client.post("/api/sign", files={"image": ("a.png", png(photo_like()), "image/png")}, data={"signer": "device"})
    assert r.status_code == 200, r.text
    body = r.json()
    return body, client.get(body["image_url"]).content


def test_page_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json()["ledger"] == "FakeLedger"


def test_sign_then_verify_is_real_with_keys_outside_backend(signed):
    _, published = signed
    assert post_verify(published).json()["verdict"] == "real"


def test_lower_case_ids_are_normalised(client, signed):
    body, published = signed
    tx = body["tx_hash"]
    assert post_verify(published, entry_id=tx.lower()).json()["found_by"] == "tx_hash"
    r = client.post(
        "/api/redact",
        files={"image": ("x.png", published, "image/png")},
        data={"entry_id": tx.lower(), "boxes": "[[0,0,64,64]]"},
    )
    assert r.status_code == 200, r.text
    new_id = r.json()["entry_id"]
    assert new_id.startswith(tx) and new_id.endswith("-r1")
    redacted = client.get(r.json()["image_url"].lower())
    assert redacted.status_code == 200
    rep = post_verify(redacted.content, entry_id=new_id.lower()).json()
    assert rep["verdict"] == "real" and rep["tiles"]["counts"]["redacted"] > 0


@pytest.mark.parametrize("bad", ["zz", "../../keys/device", "AB-r1"])
def test_bad_entry_ids_are_rejected(bad):
    assert post_verify(png(np.zeros((64, 64, 3), np.uint8)), entry_id=bad).status_code == 422


def test_files_route_does_not_escape_the_store(client):
    assert client.get("/api/files/..%2F..%2Fkeys%2Fdevice.png").status_code == 404


def test_unreadable_upload_is_400():
    assert post_verify(b"not an image", name="x.jpg").status_code == 400


def test_pixel_limit_is_checked_after_decoding():
    assert post_verify(png(np.zeros((7000, 6000, 3), np.uint8))).status_code == 413


def test_preview_scales_16_bit_instead_of_clipping(client):
    g16 = np.linspace(0, 65535, 128 * 128).reshape(128, 128).astype(np.uint16)
    buf = io.BytesIO()
    Image.fromarray(g16).save(buf, "TIFF")
    r = client.post("/api/preview", files={"image": ("g.tiff", buf.getvalue(), "image/tiff")})
    assert r.status_code == 200 and r.headers["content-type"] == "image/jpeg"
    out = np.asarray(Image.open(io.BytesIO(r.content)))
    assert out.shape[:2] == (128, 128) and (out == 255).mean() < 0.05
