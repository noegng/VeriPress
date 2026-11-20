"""HTTP API — OWNER: Dev B.  Routes and JSON shapes: docs/interfaces.md.

    uv run uvicorn tileproof.api:app --reload            # TILEPROOF_LEDGER=fake (default)
    TILEPROOF_LEDGER=xrpl uv run uvicorn tileproof.api:app --host 0.0.0.0

Calls only `pipeline.*`. Pipeline work (≈2 s CPU) and XRPL anchoring (waits for validation)
are blocking, so they run in the threadpool to keep the event loop responsive.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response
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
os.environ.setdefault("TILEPROOF_KEYS", str(BACKEND / "keys"))


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
    kind = os.environ.get("TILEPROOF_LEDGER", "fake")
    if kind == "xrpl":
        return XrplLedger()
    if kind != "fake":
        raise RuntimeError(f"TILEPROOF_LEDGER must be fake|xrpl, got {kind!r}")
    ledger = FakeLedger()
    # Offline demo: trust the demo keys like the real registry would. Same folder as signing.py.
    for name, ctype in (("device", CredentialType.CAPTURE_DEVICE), ("ai", CredentialType.AI_GENERATOR)):
        p = keys_dir() / f"{name}.json"
        if p.exists():
            ledger.issue(json.loads(p.read_text())["public_key"], ctype)
    # ...and publish the anonymous registry root, as setup_testnet.py does on XRPL.
    reg = keys_dir() / "registry_devices.json"
    if reg.exists():
        try:
            ledger.publish_registry_root(zk.root(json.loads(reg.read_text())["pks"]), at=0)
        except zk.ZkError as e:  # Node / zk deps missing: named signing still works offline
            log.warning("TileProof: anonymous registry not loaded (%s)", e)
    return ledger


def _warm_up() -> None:
    WARM["state"] = "loading"
    log.info("TileProof: loading TrustMark watermark models (first run downloads them, ~3 min)…")
    t0 = time.monotonic()
    try:
        watermark.warm_up()
        WARM["state"] = "ready"
        log.info("TileProof: watermark models ready in %.0f s", time.monotonic() - t0)
    except Exception:  # noqa: BLE001 — the API still works, sign/verify will retry the load
        WARM["state"] = "failed"
        log.exception("TileProof: watermark warm-up failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # TrustMark downloads its models on first use (~3 min): start now, in the background,
    # so the page is served immediately.
    if watermark.enabled():
        threading.Thread(target=_warm_up, daemon=True).start()
    yield


app = FastAPI(title="TileProof", lifespan=lifespan)
app.state.ledger = make_ledger()
app.state.store = Store(os.environ.get("TILEPROOF_STORE", BACKEND / "store"))


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
    return FileResponse(path, media_type="image/png", filename=f"tileproof-{entry_id[:12]}.png")


@app.post("/api/sign")
async def sign(
    image: UploadFile = File(...),
    signer: str = Form("device"),
    parent: str | None = Form(None),
    anonymous: str | None = Form(None),
):
    if signer not in ("device", "ai"):
        raise HTTPException(422, "signer must be device|ai")
    parent = (parent or "").strip().upper() or None
    if parent and not PARENT.match(parent):
        raise HTTPException(422, "parent must be a tx hash")
    anon = (anonymous or "").strip().lower() in ("1", "true", "on")
    data, rgb = await read_upload(image)
    # ZK B: capture time + GPS from the file's EXIF are committed in the signed manifest and
    # only proven as "day" / "~10 km area" claims. The published PNG carries no EXIF.
    exif = await run_in_threadpool(metadata.exif_from_upload, data)
    try:
        result, _png = await run_in_threadpool(
            lambda: pipeline.sign_image(
                rgb, signer, app.state.ledger, app.state.store, parent, anonymous=anon, exif=exif
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
