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
        data = {"seed": w.seed, "address": w.address, "public_key": pub, "private_key": priv,
                "mldsa": _mldsa_key()}  # as setup_testnet.py writes them (hybrid post-quantum)
        (folder / f"{name}.json").write_text(json.dumps(data))


def _mldsa_key() -> dict:
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    k = mldsa.MLDSA87PrivateKey.generate()
    return {"public_key": k.public_key().public_bytes_raw().hex(),
            "private_pem": k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()}


@pytest.fixture(scope="module", autouse=True)
def client(tmp_path_factory):
    from fastapi.testclient import TestClient

    tmp = tmp_path_factory.mktemp("api")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("VERIPRESS_KEYS", str(tmp / "keys-elsewhere"))  # not backend/keys: review item 2
        mp.setenv("VERIPRESS_STORE", str(tmp / "store"))
        mp.setenv("VERIPRESS_WATERMARK", "0")
        mp.setenv("VERIPRESS_LEDGER", "fake")
        _write_demo_keys(tmp / "keys-elsewhere")
        import veripress.api

        api = importlib.reload(veripress.api)  # the app reads its config at import time
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
    rep = post_verify(published).json()
    assert rep["verdict"] == "real"
    # offline ledger attests the ML-DSA-87 key of keys/device.json, like the registry on XRPL
    assert rep["post_quantum"] == {"alg": "ML-DSA-87", "signature_ok": True, "attested": True}


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


def test_sign_with_unknown_parent_is_422(client):
    r = client.post(
        "/api/sign",
        files={"image": ("a.png", png(np.full((64, 64, 3), 128, np.uint8)), "image/png")},
        data={"signer": "device", "parent": "AB" * 32},
    )
    assert r.status_code == 422 and "unknown parent" in r.json()["detail"]


def test_sign_with_known_parent_builds_history(client, signed):
    from conftest import photo_like

    body, _ = signed
    edit = photo_like(seed=5)
    r = client.post(
        "/api/sign",
        files={"image": ("e.png", png(edit), "image/png")},
        data={"signer": "device", "parent": body["tx_hash"].lower()},
    )
    assert r.status_code == 200, r.text
    rep = post_verify(client.get(r.json()["image_url"]).content).json()
    assert [h["op"] for h in rep["history"]] == ["edit", "capture"]


def test_anonymous_signing_is_refused_for_the_ai_key(client):
    r = client.post(
        "/api/sign",
        files={"image": ("a.png", png(np.full((64, 64, 3), 90, np.uint8)), "image/png")},
        data={"signer": "ai", "anonymous": "1"},
    )
    assert r.status_code == 422


def _zk_ready() -> bool:
    from veripress import zk

    return (zk.zk_dir() / "node_modules").exists()


@pytest.mark.skipif(not _zk_ready(), reason="zk deps missing: cd zk && npm ci")
def test_anonymous_sign_and_verify_offline(client):
    """Registry built like setup_testnet.py does (device + fakes), root published in the
    FakeLedger: the anonymous photo verifies as real with a valid ZK proof, without signer key."""
    import os

    from conftest import photo_like

    from veripress import zk

    keys = Path(os.environ["VERIPRESS_KEYS"])
    dev = json.loads((keys / "device.json").read_text())
    dev["bjj"] = zk.keygen()
    (keys / "device.json").write_text(json.dumps(dev))
    pks = [zk.keygen()["pk"] for _ in range(3)] + [dev["bjj"]["pk"]]
    (keys / "registry_devices.json").write_text(json.dumps({"pks": pks}))
    import veripress.api as api

    api.app.state.ledger.publish_registry_root(zk.root(pks), at=0)

    r = client.post(
        "/api/sign",
        files={"image": ("a.png", png(photo_like(seed=8)), "image/png")},
        data={"signer": "device", "anonymous": "1"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["anonymous"] is True and body["signer"] == "" and body["registry_root"]
    rep = post_verify(client.get(body["image_url"]).content).json()
    assert rep["verdict"] == "real" and rep["anonymous"] is True
    assert rep["zk"]["proof_ok"] and rep["zk"]["root_valid_at_anchor"]
    assert rep["anchor"]["signer"] == ""


def _jpeg_with_capture_exif(rgb: np.ndarray) -> bytes:
    """JPEG carrying DateTimeOriginal + offset + GPS (Bari), like a phone photo."""
    ex = Image.Exif()
    ifd = ex.get_ifd(0x8769)
    ifd[0x9003], ifd[0x9011] = "2026:11:20 13:36:58", "+01:00"
    ex.get_ifd(0x8825).update({1: "N", 2: (41.0, 6.0, 30.48), 3: "E", 4: (16.0, 52.0, 12.0)})
    buf = io.BytesIO()
    Image.fromarray(rgb).save(buf, "JPEG", quality=95, exif=ex.tobytes())
    return buf.getvalue()


@pytest.mark.skipif(not _zk_ready(), reason="zk deps missing: cd zk && npm ci")
def test_exif_of_the_upload_gives_proven_day_and_area_claims(client):
    """ZK B through the API: the uploaded file's EXIF reaches sign_image, the published PNG
    has no EXIF, and verification shows day + area claims proven in zero knowledge."""
    from conftest import photo_like

    r = client.post(
        "/api/sign",
        files={"image": ("phone.jpg", _jpeg_with_capture_exif(photo_like(seed=12)), "image/jpeg")},
        data={"signer": "device"},
    )
    assert r.status_code == 200, r.text
    published = client.get(r.json()["image_url"]).content
    assert not Image.open(io.BytesIO(published)).getexif()  # GPS never leaves in the image
    claims = post_verify(published).json()["meta_claims"]
    assert sorted(c["kind"] for c in claims) == ["area", "day"]
    assert all(c["proof_ok"] for c in claims)
    assert "20 Nov 2026" in next(c["label"] for c in claims if c["kind"] == "day")


def test_public_link_page_and_json(client, signed):
    """/v/<id>: server-rendered page whose social preview tags already hold the verdict and an
    absolute thumbnail URL; /api/entry/<id>: the verification JSON of the stored image."""
    import html as htmllib
    import re

    body, _ = signed
    tx = body["tx_hash"]
    j = client.get(f"/api/entry/{tx.lower()}").json()
    assert j["verdict"] == "real" and j["entry_id"] == tx

    r = client.get(f"/v/{tx.lower()}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    page = r.text
    meta = dict(re.findall(r'<meta property="(og:[a-z]+)" content="([^"]*)"', page))
    assert "Real" in htmllib.unescape(meta["og:title"])
    assert meta["og:image"] == f"http://testserver/api/files/{tx}.png"
    assert meta["og:url"] == f"http://testserver/v/{tx}"
    assert "__" not in "".join(meta.values())  # every template marker was filled
    embedded = re.search(r'<script id="report" type="application/json">(.*?)</script>', page, re.S).group(1)
    assert json.loads(embedded)["verdict"] == "real"


def test_public_link_unknown_or_bad_ids(client):
    assert client.get(f"/v/{'AB' * 32}").status_code == 404
    assert client.get(f"/api/entry/{'AB' * 32}").status_code == 404
    assert client.get("/v/not-hex").status_code == 404
    assert client.get("/api/entry/not-hex").status_code == 422


def test_public_page_escapes_a_hostile_report(client, monkeypatch):
    """A reason containing markup must neither close the embedded JSON <script> nor break out
    of the meta attributes."""
    import veripress.api as api

    evil = '"><script>alert(1)</script>'

    class Report:
        def to_json(self, heatmap=None):
            return {"verdict": "edited", "reason": evil, "anchor": None, "meta_claims": []}

    monkeypatch.setattr(api.pipeline, "verify_stored", lambda *a: (Report(), None))
    page = client.get(f"/v/{'CD' * 32}").text
    assert "<script>alert(1)</script>" not in page
    assert "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;" in page  # meta description, escaped
    assert "\\u003cscript>alert(1)\\u003c/script>" in page  # embedded JSON, cannot close the tag


def test_fast_anchoring_flag_and_anchor_status(client, signed):
    """wait=0 reaches the pipeline (the FakeLedger validates at once, so pending stays False);
    /api/anchor/<tx> gives the light status the page polls."""
    from conftest import photo_like

    r = client.post(
        "/api/sign",
        files={"image": ("a.png", png(photo_like(seed=14)), "image/png")},
        data={"signer": "device", "wait": "0"},
    )
    assert r.status_code == 200 and r.json()["pending"] is False
    tx = r.json()["tx_hash"]
    s = client.get(f"/api/anchor/{tx.lower()}").json()
    assert s["tx_hash"] == tx and s["validated"] is True
    assert client.get(f"/api/anchor/{'AB' * 32}").status_code == 404
    assert client.get("/api/anchor/xyz").status_code == 422


# --- passkey (phase 2 task 6) ----------------------------------------------------------------

def _spki_b64url(private_key) -> str:
    import base64

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    der = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(der).rstrip(b"=").decode()


def test_passkey_registration_is_localhost_only(client):
    from cryptography.hazmat.primitives.asymmetric import ec

    body = {"credential_id": "AAEC", "public_key": _spki_b64url(ec.generate_private_key(ec.SECP256R1()))}
    assert client.post("/api/passkey/register", json=body).status_code == 403  # TestClient is not 127.0.0.1


def test_passkey_registration_stores_the_sec1_key_and_its_hash(client, monkeypatch):
    import hashlib

    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    import veripress.api as api

    monkeypatch.setattr(api, "LOCAL_CLIENTS", api.LOCAL_CLIENTS | {"testclient"})
    key = ec.generate_private_key(ec.SECP256R1())
    r = client.post("/api/passkey/register", json={"credential_id": "AAEC", "public_key": _spki_b64url(key)})
    assert r.status_code == 200, r.text
    sec1 = key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert r.json()["sha256"] == hashlib.sha256(sec1).hexdigest()
    status = client.get("/api/passkey").json()
    assert status["registered"] and status["credential_id"] == "AAEC" and status["attested"] is False

    wrong = _spki_b64url(ed25519.Ed25519PrivateKey.generate())
    assert client.post("/api/passkey/register", json={"credential_id": "AAEC", "public_key": wrong}).status_code == 422
    assert client.post("/api/passkey/register", json={"credential_id": "AAEC", "public_key": "!!"}).status_code == 422


def test_passkey_signing_routes_until_and_once_the_pipeline_supports_it(client, signed, monkeypatch):
    import veripress.api as api

    for name in ("prepare_passkey_sign", "complete_passkey_sign"):
        monkeypatch.delattr(api.pipeline, name, raising=False)
    img = {"image": ("a.png", png(np.full((64, 64, 3), 70, np.uint8)), "image/png")}
    assert client.post("/api/sign/passkey/prepare", files=img).status_code == 503
    assert client.post("/api/sign/passkey/complete", json={"prep_id": "x", "assertion": {}}).status_code == 503

    # plumbing with a stand-in pipeline: what the page sends reaches it, errors map to HTTP codes
    seen = {}

    def prepare(rgb, store, parent=None, exif=None, ledger=None):
        seen["prepare"] = (rgb.shape, parent, ledger is api.app.state.ledger)  # ledger: T0 + parent check
        return {"prep_id": "P1", "challenge": "ab" * 32}

    def complete(prep_id, assertion, ledger, store, wait=True):
        seen["wait"] = wait
        if prep_id != "P1":
            raise KeyError(prep_id)
        if assertion.get("signature") != "good":
            raise ValueError("assertion does not verify")
        manifest = api.app.state.store.get(signed[0]["entry_id"]).manifest
        manifest.passkey = "04" + "11" * 64  # stand-in result of a passkey signature
        return api.pipeline.SignResult(signed[0]["entry_id"], ledger.fetch_anchor(signed[0]["tx_hash"]), manifest), b""

    monkeypatch.setattr(api.pipeline, "prepare_passkey_sign", prepare, raising=False)
    monkeypatch.setattr(api.pipeline, "complete_passkey_sign", complete, raising=False)
    assert client.post("/api/sign/passkey/prepare", files=img).json() == {"prep_id": "P1", "challenge": "ab" * 32}
    assert seen["prepare"] == ((64, 64, 3), None, True)
    assert client.post("/api/sign/passkey/complete", json={"prep_id": "nope", "assertion": {}}).status_code == 404
    assert client.post("/api/sign/passkey/complete", json={"prep_id": "P1", "assertion": {"signature": "bad"}}).status_code == 422
    ok = client.post("/api/sign/passkey/complete", json={"prep_id": "P1", "assertion": {"signature": "good"}, "wait": 0})
    assert ok.status_code == 200 and ok.json()["passkey"] is True
    assert seen["wait"] is True  # offline FakeLedger: always validated, even when the page asks wait=0
    assert ok.json()["pending"] is False


def test_wait_flag_parsing(client):
    import veripress.api as api

    assert api.wait_for_validation(None) and api.wait_for_validation("1")
    # Not monkeypatch: pytest 9 reads the old value statically, misses Starlette's State
    # storage, and would *delete* app.state.ledger on undo.
    saved = api.app.state.ledger
    api.app.state.ledger = object()  # any on-chain ledger
    try:
        assert not api.wait_for_validation("0") and not api.wait_for_validation(0) and not api.wait_for_validation(False)
        assert api.wait_for_validation(None) and api.wait_for_validation(True)
    finally:
        api.app.state.ledger = saved


def test_develop_from_a_signed_raw_is_real_with_history(client, signed):
    from conftest import photo_like

    body, _ = signed  # stands for the signed RAW negative (same device key)
    r = client.post(
        "/api/sign",
        files={"image": ("d.png", png(photo_like(seed=9)), "image/png")},
        data={"signer": "device", "parent": body["tx_hash"], "op": "develop"},
    )
    assert r.status_code == 200, r.text
    rep = post_verify(client.get(r.json()["image_url"]).content).json()
    assert rep["verdict"] == "real"
    assert [h["op"] for h in rep["history"]] == ["develop", "capture"]


@pytest.mark.parametrize("form", [{"op": "edit"}, {"op": "develop"}])
def test_develop_needs_op_develop_and_a_parent(client, form):
    # op other than develop -> 422 here; develop without parent -> 422 from the pipeline
    r = client.post("/api/sign", files={"image": ("d.png", png(np.full((64, 64, 3), 90, np.uint8)), "image/png")},
                    data={"signer": "device", **form})
    assert r.status_code == 422


def test_c2pa_manifest_is_reported_as_information(signed):
    body, published = signed
    rep = post_verify(published).json()
    c = rep["c2pa"]
    assert c is not None and c["tx_hash"] == body["tx_hash"] and c["matches_anchor"] is True
    assert c["signer_trusted"] is False  # local test CA, not on the C2PA trust list
    assert rep["verdict"] == "real"
    # Re-encoded (what a messaging app does): the manifest is gone, the provenance is not.
    rgb = np.asarray(Image.open(io.BytesIO(published)).convert("RGB"))
    stripped = post_verify(png(rgb)).json()
    assert stripped["c2pa"] is None and stripped["verdict"] == "real"


def test_forged_c2pa_manifest_does_not_change_the_verdict(client):
    from veripress import c2pa_embed

    # Anyone can sign a C2PA manifest that points to any anchor (security-review.md).
    forged = c2pa_embed.embed(png(np.full((64, 64, 3), 33, np.uint8)), "CD" * 32, "ee" * 32, "capture",
                              "https://testnet.xrpl.org/transactions/" + "CD" * 32)
    rep = post_verify(forged).json()
    assert rep["verdict"] == "unknown"
    assert rep["c2pa"]["tx_hash"] == "CD" * 32 and rep["c2pa"]["matches_anchor"] is False


def test_batch_of_three_photos_one_transaction(client):
    from conftest import photo_like

    files = [("images", (f"p{i}.png", png(photo_like(seed=20 + i)), "image/png")) for i in range(3)]
    files.append(("images", ("broken.jpg", b"not an image", "image/jpeg")))
    r = client.post("/api/sign/batch", files=files, data={"signer": "device", "wait": "0"})
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["size"] == 3 and res["pending"] is False  # offline ledger validates at once
    assert [("entry_id" in e) for e in res["entries"]] == [True, True, True, False]
    assert res["entries"][3]["name"] == "broken.jpg" and res["entries"][3]["error"]
    for i, e in enumerate(res["entries"][:3]):
        rep = post_verify(client.get(e["image_url"]).content).json()
        assert rep["verdict"] == "real", rep["reason"]
        assert rep["batch"] == {"tx_hash": res["tx_hash"], "index": i, "size": 3}
        assert rep["anchor"]["tx_hash"] == res["tx_hash"]


def test_batch_limits(client):
    one = ("images", ("a.png", png(np.full((64, 64, 3), 50, np.uint8)), "image/png"))
    assert client.post("/api/sign/batch", files=[one] * 9, data={"signer": "device"}).status_code == 422
    # nothing signable (the AI key is never in the anonymous registry) -> 422, no transaction
    r = client.post("/api/sign/batch", files=[one], data={"signer": "ai", "anonymous": "1"})
    assert r.status_code == 422
