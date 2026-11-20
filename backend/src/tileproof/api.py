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
from contextlib import asynccontextmanager
from pathlib import Path

import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from PIL import Image, ImageOps, UnidentifiedImageError

from . import pipeline, watermark
from .ledger import CredentialType, FakeLedger, Ledger, XrplLedger
from .store import Store

try:  # iPhone photos are HEIC
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:  # pragma: no cover
    pass

log = logging.getLogger("tileproof.api")
BACKEND = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD = 25 * 1024 * 1024
MAX_PIXELS = 40_000_000
TX_HASH = r"[0-9A-Fa-f]{16,64}"
ENTRY_ID = re.compile(rf"^{TX_HASH}(-r\d+)?$")
PARENT = re.compile(rf"^{TX_HASH}$")
# signing.py resolves keys relative to the CWD; pin it so uvicorn works from any directory.
os.environ.setdefault("TILEPROOF_KEYS", str(BACKEND / "keys"))


def make_ledger() -> Ledger:
    kind = os.environ.get("TILEPROOF_LEDGER", "fake")
    if kind == "xrpl":
        return XrplLedger()
    if kind != "fake":
        raise RuntimeError(f"TILEPROOF_LEDGER must be fake|xrpl, got {kind!r}")
    ledger = FakeLedger()
    # Offline demo: trust the demo keys like the real registry would.
    for name, ctype in (("device", CredentialType.CAPTURE_DEVICE), ("ai", CredentialType.AI_GENERATOR)):
        p = BACKEND / "keys" / f"{name}.json"
        if p.exists():
            ledger.issue(json.loads(p.read_text())["public_key"], ctype)
    return ledger


def _warm_up() -> None:
    try:
        watermark.warm_up()
        log.info("watermark models ready")
    except Exception:  # noqa: BLE001 — the API still works, sign/verify will retry the load
        log.exception("watermark warm-up failed")


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
    data = await upload.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "image too large (max 25 MB)")
    try:
        img = Image.open(io.BytesIO(data))
        if img.width * img.height > MAX_PIXELS:
            raise HTTPException(413, "image too large (max 40 MP)")
        # Phones store photos rotated + an EXIF flag; apply it so pixels match what users see.
        img = ImageOps.exif_transpose(img)
        return np.asarray(img.convert("RGB"))
    except (UnidentifiedImageError, OSError, ValueError) as e:
        raise HTTPException(400, f"not a readable image: {e}") from e


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "ledger": type(app.state.ledger).__name__, "watermark": watermark.enabled()}


@app.get("/api/files/{name}")
def files(name: str) -> FileResponse:
    entry_id = name.removesuffix(".png")
    if not name.endswith(".png") or not ENTRY_ID.match(entry_id):
        raise HTTPException(404)
    path = app.state.store.image_path(entry_id)
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(path, media_type="image/png", filename=f"tileproof-{entry_id[:12]}.png")


@app.post("/api/sign")
async def sign(image: UploadFile = File(...), signer: str = Form("device"), parent: str | None = Form(None)):
    if signer not in ("device", "ai"):
        raise HTTPException(422, "signer must be device|ai")
    parent = (parent or "").strip().upper() or None
    if parent and not PARENT.match(parent):
        raise HTTPException(422, "parent must be a tx hash")
    rgb = await read_image(image)
    try:
        result, _png = await run_in_threadpool(
            pipeline.sign_image, rgb, signer, app.state.ledger, app.state.store, parent
        )
    except FileNotFoundError as e:  # keys/ missing
        raise HTTPException(503, f"signing key missing — run scripts/setup_testnet.py ({e.filename})") from e
    except RuntimeError as e:  # anchor tx rejected
        raise HTTPException(502, str(e)) from e
    return result.to_json()


@app.post("/api/verify")
async def verify(image: UploadFile = File(...), entry_id: str | None = Form(None)):
    entry_id = (entry_id or "").strip() or None
    if entry_id and not ENTRY_ID.match(entry_id):
        raise HTTPException(422, "entry_id / tx_hash must be hex")
    rgb = await read_image(image)
    report, heatmap = await run_in_threadpool(
        pipeline.verify_image, rgb, app.state.ledger, app.state.store, entry_id
    )
    return report.to_json(heatmap)


@app.post("/api/redact")
async def redact(image: UploadFile = File(...), entry_id: str = Form(...), boxes: str = Form(...)):
    if not ENTRY_ID.match(entry_id):
        raise HTTPException(422, "entry_id must be hex")
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
