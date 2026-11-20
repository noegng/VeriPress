"""HTTP API — OWNER: Dev B.  Routes and JSON shapes: docs/interfaces.md.

    uv run uvicorn veripress.api:app --reload            # VERIPRESS_LEDGER=fake (default)
    VERIPRESS_LEDGER=xrpl uv run uvicorn veripress.api:app --host 0.0.0.0

Calls only `pipeline.*`. Pipeline work (≈2 s CPU) and XRPL anchoring (waits for validation)
are blocking, so they run in the threadpool to keep the event loop responsive.
"""

from __future__ import annotations

import base64
import hashlib
import html
import io
import json
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, Response
from PIL import Image

from . import metadata, pipeline, watermark, zk
from .ledger import CredentialType, FakeLedger, Ledger, XrplLedger
from .signing import keys_dir
from .store import Store
from .tiling import load_upload

log = logging.getLogger("uvicorn.error")  # configured by uvicorn; our own logger would print nothing
WARM = {"state": "off"}  # off | loading | ready | failed — shown by /api/health and the page
BACKEND = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD = 100 * 1024 * 1024  # camera RAW (CR3, ProRAW DNG…) is often 25-80 MB
MAX_PIXELS = 40_000_000
TX_HASH = r"[0-9A-Fa-f]{16,64}"
ENTRY_ID = re.compile(rf"^({TX_HASH})(-r\d+)?$")
PARENT = re.compile(rf"^{TX_HASH}$")
# signing.py resolves keys relative to the CWD; pin it so uvicorn works from any directory.
os.environ.setdefault("VERIPRESS_KEYS", str(BACKEND / "keys"))


def norm_entry_id(raw: str | None) -> str | None:
    """Tx hashes are stored upper-case: a pasted lower-case hash must still match on a
    case-sensitive (Linux) filesystem. Only the hex part is upper-cased ("-r1" kept)."""
    raw = (raw or "").strip()
    if not raw:
        return None
    m = ENTRY_ID.match(raw)
    if not m:
        raise HTTPException(422, "entry_id / tx_hash must be hex (optionally with -r<n>)")
    return m.group(1).upper() + (m.group(2) or "")


def make_ledger() -> Ledger:
    kind = os.environ.get("VERIPRESS_LEDGER", "fake")
    if kind == "xrpl":
        return XrplLedger()
    if kind != "fake":
        raise RuntimeError(f"VERIPRESS_LEDGER must be fake|xrpl, got {kind!r}")
    ledger = FakeLedger()
    # Offline demo: trust the demo keys like the real registry would. Same folder as signing.py.
    pk_file = keys_dir() / "passkey.json"
    passkey = json.loads(pk_file.read_text()) if pk_file.exists() else {}
    for name, ctype in (("device", CredentialType.CAPTURE_DEVICE), ("ai", CredentialType.AI_GENERATOR)):
        p = keys_dir() / f"{name}.json"
        if p.exists():
            # The device credential carries the attested passkey, as setup_testnet.py --passkey does.
            attested = name == "device" and passkey.get("attested")
            ledger.issue(json.loads(p.read_text())["public_key"], ctype,
                         passkey_hash=passkey["sha256"] if attested else None)
    # ...and publish the anonymous registry root, as setup_testnet.py does on XRPL.
    reg = keys_dir() / "registry_devices.json"
    if reg.exists():
        try:
            ledger.publish_registry_root(zk.root(json.loads(reg.read_text())["pks"]), at=0)
        except zk.ZkError as e:  # Node / zk deps missing: named signing still works offline
            log.warning("VeriPress: anonymous registry not loaded (%s)", e)
    return ledger


def _warm_up() -> None:
    WARM["state"] = "loading"
    log.info("VeriPress: loading TrustMark watermark models (first run downloads them, ~3 min)…")
    t0 = time.monotonic()
    try:
        watermark.warm_up()
        WARM["state"] = "ready"
        log.info("VeriPress: watermark models ready in %.0f s", time.monotonic() - t0)
    except Exception:  # noqa: BLE001 — the API still works, sign/verify will retry the load
        WARM["state"] = "failed"
        log.exception("VeriPress: watermark warm-up failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # TrustMark downloads its models on first use (~3 min): start now, in the background,
    # so the page is served immediately.
    if watermark.enabled():
        threading.Thread(target=_warm_up, daemon=True).start()
    yield


app = FastAPI(title="VeriPress", lifespan=lifespan)
app.state.ledger = make_ledger()
app.state.store = Store(os.environ.get("VERIPRESS_STORE", BACKEND / "store"))


async def read_image(upload: UploadFile) -> np.ndarray:
    return (await read_upload(upload))[1]


async def read_upload(upload: UploadFile) -> tuple[bytes, np.ndarray]:
    """(raw bytes, decoded sRGB pixels). The raw bytes are needed to sign: they carry the EXIF
    capture time + GPS that ZK B commits to (the decoded pixels have no metadata)."""
    data = await upload.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "image too large (max 100 MB)")
    # load_upload (Dev A): JPEG/PNG/HEIC/TIFF 16-bit, EXIF + ICC -> sRGB, camera RAW via LibRaw.
    # Not Image.open first: Pillow reads a RAW as its small embedded preview. RAW development
    # is CPU-heavy, hence the threadpool. A RAW's size is only known once developed.
    try:
        rgb = await run_in_threadpool(load_upload, data, upload.filename)
    except ValueError as e:
        raise HTTPException(400, f"not a readable image: {e}") from e
    if rgb.shape[0] * rgb.shape[1] > MAX_PIXELS:
        raise HTTPException(413, "image too large (max 40 MP)")
    return data, rgb


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {
        "ok": True,
        "ledger": type(app.state.ledger).__name__,
        "watermark": watermark.enabled(),
        "watermark_ready": WARM["state"],
    }


@app.post("/api/preview")
async def preview(image: UploadFile = File(...)) -> Response:
    """Browser-displayable JPEG of an upload the browser cannot render itself (camera RAW,
    HEIC on Chrome). Full resolution, so redaction boxes drawn on it map 1:1 to pixels."""
    rgb = await read_image(image)

    def encode() -> bytes:
        buf = io.BytesIO()
        Image.fromarray(rgb).save(buf, "JPEG", quality=88)
        return buf.getvalue()

    return Response(await run_in_threadpool(encode), media_type="image/jpeg")


@app.get("/api/files/{name}")
def files(name: str) -> FileResponse:
    if not name.endswith(".png") or not ENTRY_ID.match(name.removesuffix(".png")):
        raise HTTPException(404)
    entry_id = norm_entry_id(name.removesuffix(".png"))
    path = app.state.store.image_path(entry_id)
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(path, media_type="image/png", filename=f"veripress-{entry_id[:12]}.png")


async def _verify_stored(entry_id: str) -> dict:
    try:
        report, heatmap = await run_in_threadpool(
            pipeline.verify_stored, entry_id, app.state.ledger, app.state.store
        )
    except KeyError as e:
        raise HTTPException(404, "unknown entry") from e
    return report.to_json(heatmap)


@app.get("/api/anchor/{tx_hash}")
async def anchor_status(tx_hash: str) -> dict:
    """Light status of an anchor (fast anchoring: the page polls it until validated, instead of
    re-running a full image verification)."""
    tx = tx_hash.strip().upper()
    if not PARENT.match(tx):
        raise HTTPException(422, "tx hash must be hex")
    a = await run_in_threadpool(app.state.ledger.fetch_anchor, tx)
    if a is None:
        raise HTTPException(404, "anchor not found")
    return {"tx_hash": a.tx_hash, "validated": a.validated, "timestamp": a.timestamp, "explorer_url": a.explorer_url}


@app.get("/api/entry/{entry_id}")
async def entry(entry_id: str) -> dict:
    """/api/verify's JSON, computed on the published image kept in the store."""
    return await _verify_stored(norm_entry_id(entry_id))


SHARE_TITLES = {
    "real": "🟢 Real — provenance verified on XRPL",
    "edited": "🟠 Edited since it was signed",
    "ai": "🔵 AI-generated (declared and signed)",
    "unknown": "⚪ No verifiable provenance",
}


def _share_text(r: dict) -> tuple[str, str]:
    """(title, description) of the social preview, from the verification report."""
    title = SHARE_TITLES.get(r["verdict"], SHARE_TITLES["unknown"])
    if r["verdict"] == "real" and r.get("anonymous"):
        title = "🟢 Real — accredited device (anonymous), verified on XRPL"
    parts = [r.get("reason") or ""]
    parts += [c["label"] for c in r.get("meta_claims") or [] if c.get("proof_ok")]
    if r.get("anchor"):
        when = datetime.fromtimestamp(r["anchor"]["timestamp"], timezone.utc).strftime("%d %b %Y %H:%M UTC")
        parts.append(f"anchored {when}")
    return title, " · ".join(p for p in parts if p)


@app.get("/v/{entry_id}", response_class=HTMLResponse)
async def public_view(entry_id: str, request: Request) -> HTMLResponse:
    """Public, read-only verification page. Rendered on the server: social-network crawlers do
    not run JavaScript, so the Open Graph / Twitter tags must already hold the verdict and the
    thumbnail. The report is embedded once, so a visit costs a single verification."""
    if not ENTRY_ID.match(entry_id):
        raise HTTPException(404)
    entry_id = norm_entry_id(entry_id)
    r = await _verify_stored(entry_id)
    title, description = _share_text(r)
    image_path = f"/api/files/{entry_id}.png"
    base = str(request.base_url).rstrip("/")
    # JSON inside <script>: escape "<" so no value can close the tag ("</script>").
    report_json = json.dumps(r, separators=(",", ":")).replace("<", "\\u003c")
    page = (STATIC / "view.html").read_text()
    for marker, value in (
        ("__TITLE__", html.escape(title)),
        ("__DESCRIPTION__", html.escape(description)),
        ("__IMAGE_URL__", html.escape(base + image_path)),
        ("__PAGE_URL__", html.escape(f"{base}/v/{entry_id}")),
        ("__IMAGE_PATH__", html.escape(image_path)),
        ("__REPORT_JSON__", report_json),
    ):
        page = page.replace(marker, value)
    return HTMLResponse(page)


@app.post("/api/sign")
async def sign(
    image: UploadFile = File(...),
    signer: str = Form("device"),
    parent: str | None = Form(None),
    anonymous: str | None = Form(None),
    wait: str | None = Form(None),
):
    if signer not in ("device", "ai"):
        raise HTTPException(422, "signer must be device|ai")
    parent = (parent or "").strip().upper() or None
    if parent and not PARENT.match(parent):
        raise HTTPException(422, "parent must be a tx hash")
    anon = (anonymous or "").strip().lower() in ("1", "true", "on")
    # wait=0: fast anchoring, answer at submission (pending until validated). Default: wait.
    # The offline FakeLedger has no consensus to wait for (and nothing would ever validate a
    # pending tx in the backup demo), so it always anchors as validated.
    wait_validated = (wait or "").strip() != "0" or isinstance(app.state.ledger, FakeLedger)
    data, rgb = await read_upload(image)
    # ZK B: capture time + GPS from the file's EXIF are committed in the signed manifest and
    # only proven as "day" / "~10 km area" claims. The published PNG carries no EXIF.
    exif = await run_in_threadpool(metadata.exif_from_upload, data)
    try:
        result, _png = await run_in_threadpool(
            lambda: pipeline.sign_image(
                rgb, signer, app.state.ledger, app.state.store, parent,
                anonymous=anon, exif=exif, wait=wait_validated,
            )
        )
    except FileNotFoundError as e:  # keys/ missing
        raise HTTPException(503, f"signing key missing — run scripts/setup_testnet.py ({e.filename})") from e
    except ValueError as e:  # pipeline: unknown parent, AI key or device not in the anonymous registry…
        raise HTTPException(422, str(e)) from e
    except zk.ZkError as e:  # Node / zk deps missing (a RuntimeError, so caught before the next clause)
        raise HTTPException(503, f"zero-knowledge prover unavailable — run `cd zk && npm ci` ({e})") from e
    except RuntimeError as e:  # anchor tx rejected
        raise HTTPException(502, str(e)) from e
    body = result.to_json()
    # Phase 2 /api/sign fields (interfaces.md); the pipeline's own values win once it sets them.
    body.setdefault("anonymous", result.anchor.anonymous)
    body.setdefault("pending", not result.anchor.validated)
    body.setdefault("meta_claims", [])
    if result.anchor.anonymous:
        body.setdefault("registry_root", result.anchor.registry_root)
    return body


@app.post("/api/verify")
async def verify(image: UploadFile = File(...), entry_id: str | None = Form(None)):
    entry_id = norm_entry_id(entry_id)
    rgb = await read_image(image)
    report, heatmap = await run_in_threadpool(
        pipeline.verify_image, rgb, app.state.ledger, app.state.store, entry_id
    )
    return report.to_json(heatmap)


# --- Passkey (phase 2 task 6, decisions.md Q21-Q23) ------------------------------------------
# Registration only stores a CANDIDATE key, from this machine only: the server listens on
# 0.0.0.0 for the phone, and anyone on the room's Wi-Fi must not bind their own passkey to the
# accredited device. The registry then attests it explicitly: setup_testnet.py --passkey.

LOCAL_CLIENTS = {"127.0.0.1", "::1"}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _passkey_file() -> Path:
    return keys_dir() / "passkey.json"


def _device_pubkey() -> str | None:
    p = keys_dir() / "device.json"
    return json.loads(p.read_text())["public_key"] if p.exists() else None


@app.post("/api/passkey/register")
async def passkey_register(request: Request) -> dict:
    """Body {credential_id, public_key}: base64url credential id and SPKI DER public key, as
    returned by navigator.credentials.create() / getPublicKey(). Saves the P-256 key in SEC1
    uncompressed form (contract) and its sha256, to be attested by the registry."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

    if request.client is None or request.client.host not in LOCAL_CLIENTS:
        raise HTTPException(403, "passkey registration is only allowed from the demo laptop (localhost)")
    try:
        body = await request.json()
        cred_id = str(body["credential_id"])
        key = load_der_public_key(_b64url_decode(str(body["public_key"])))
        _b64url_decode(cred_id)
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(422, f"bad passkey registration: {e}") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise HTTPException(422, "passkey must be ECDSA P-256 (COSE alg -7)")
    sec1 = key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    sha = hashlib.sha256(sec1).hexdigest()
    path = _passkey_file()
    path.write_text(json.dumps({"credential_id": cred_id, "public_key": sec1.hex(), "sha256": sha,
                                "spki": _b64url(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))}, indent=2))
    path.chmod(0o600)
    return {"sha256": sha, "next": "uv run python scripts/setup_testnet.py --passkey  (registry attests it)"}


@app.get("/api/passkey")
async def passkey_status() -> dict:
    """What the page needs to offer 'Sign with passkey': the credential id to request, the
    public key to send with the assertion, and whether the registry attests it."""
    path = _passkey_file()
    if not path.exists():
        return {"registered": False, "attested": False}
    data = json.loads(path.read_text())
    device = _device_pubkey()
    attested = bool(device) and await run_in_threadpool(app.state.ledger.credential_passkey, device) == data["sha256"]
    return {"registered": True, "attested": attested, "credential_id": data["credential_id"],
            "public_key": data["spki"], "sha256": data["sha256"]}


def _pipeline_fn(name: str):
    fn = getattr(pipeline, name, None)
    if fn is None:  # Dev A's server-side WebAuthn verification not merged yet
        raise HTTPException(503, f"passkey signing not available yet (pipeline.{name})")
    return fn


@app.post("/api/sign/passkey/prepare")
async def passkey_prepare(image: UploadFile = File(...), parent: str | None = Form(None)) -> dict:
    prepare = _pipeline_fn("prepare_passkey_sign")
    parent = (parent or "").strip().upper() or None
    if parent and not PARENT.match(parent):
        raise HTTPException(422, "parent must be a tx hash")
    data, rgb = await read_upload(image)
    exif = await run_in_threadpool(metadata.exif_from_upload, data)
    try:
        return await run_in_threadpool(lambda: prepare(rgb, app.state.store, parent, exif=exif))
    except ValueError as e:
        raise HTTPException(422, str(e)) from e


@app.post("/api/sign/passkey/complete")
async def passkey_complete(request: Request) -> dict:
    complete = _pipeline_fn("complete_passkey_sign")
    try:
        body = await request.json()
        prep_id, assertion = str(body["prep_id"]), dict(body["assertion"])
    except (ValueError, KeyError, TypeError) as e:
        raise HTTPException(422, "body must be {prep_id, assertion}") from e
    try:
        result, _png = await run_in_threadpool(complete, prep_id, assertion, app.state.ledger, app.state.store)
    except KeyError as e:
        raise HTTPException(404, "unknown or expired prep_id") from e
    except ValueError as e:  # assertion does not verify / passkey not attested…
        raise HTTPException(422, str(e)) from e
    except RuntimeError as e:  # anchor tx rejected
        raise HTTPException(502, str(e)) from e
    body = result.to_json()
    body.setdefault("anonymous", False)
    body.setdefault("pending", not result.anchor.validated)
    body.setdefault("meta_claims", [])
    body.setdefault("passkey", True)
    return body


@app.post("/api/redact")
async def redact(image: UploadFile = File(...), entry_id: str = Form(...), boxes: str = Form(...)):
    entry_id = norm_entry_id(entry_id)
    if entry_id is None:
        raise HTTPException(422, "entry_id is required")
    try:
        parsed = [tuple(int(v) for v in b) for b in json.loads(boxes)]
        if not parsed or len(parsed) > 64 or any(len(b) != 4 for b in parsed):
            raise ValueError
    except (ValueError, TypeError) as e:
        raise HTTPException(422, "boxes must be JSON [[x0,y0,x1,y1], …]") from e
    rgb = await read_image(image)
    try:
        new_id, _png = await run_in_threadpool(pipeline.redact_image, rgb, entry_id, parsed, app.state.store)
    except KeyError as e:
        raise HTTPException(404, "unknown entry") from e
    return {"entry_id": new_id, "image_url": f"/api/files/{new_id}.png"}
