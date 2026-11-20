"""HTTP API — OWNER: Dev B.  Routes and JSON shapes: docs/interfaces.md.

    uv run uvicorn tileproof.api:app --reload            # TILEPROOF_LEDGER=fake (default)
    TILEPROOF_LEDGER=xrpl uv run uvicorn tileproof.api:app

Calls only `pipeline.*`. While Dev A's pipeline raises NotImplementedError, the routes
answer with the example JSON of interfaces.md (header `X-Tileproof-Mock: 1`), so the page
can be built in parallel. `?mock=real|edited|ai|unknown` picks the mocked verdict.
"""

from __future__ import annotations

import base64
import io
import json
import os
import re
from pathlib import Path

import numpy as np
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from PIL import Image, ImageOps, UnidentifiedImageError

from . import pipeline
from .ledger import CredentialType, FakeLedger, Ledger, XrplLedger
from .store import Store

BACKEND = Path(__file__).resolve().parents[2]
STATIC = Path(__file__).resolve().parent / "static"
MAX_UPLOAD = 25 * 1024 * 1024
MAX_PIXELS = 40_000_000
ENTRY_ID = re.compile(r"^[0-9A-Fa-f]{16,64}(-r\d+)?$")


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


app = FastAPI(title="TileProof")
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
    except (UnidentifiedImageError, OSError) as e:
        raise HTTPException(400, f"not a readable image: {e}") from e


def mocked(body: dict) -> JSONResponse:
    return JSONResponse(body, headers={"X-Tileproof-Mock": "1"})


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "ledger": type(app.state.ledger).__name__}


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
async def sign(image: UploadFile = File(...), signer: str = Form("device")):
    if signer not in ("device", "ai"):
        raise HTTPException(422, "signer must be device|ai")
    rgb = await read_image(image)
    try:
        result, _png = pipeline.sign_image(rgb, signer, app.state.ledger, app.state.store)
        return result.to_json()
    except NotImplementedError:
        return mocked(mock_sign(rgb, signer))


@app.post("/api/verify")
async def verify(request: Request, image: UploadFile = File(...), entry_id: str | None = Form(None)):
    entry_id = (entry_id or "").strip() or None
    if entry_id and not ENTRY_ID.match(entry_id):
        raise HTTPException(422, "entry_id / tx_hash must be hex")
    rgb = await read_image(image)
    try:
        report, heatmap = pipeline.verify_image(rgb, app.state.ledger, app.state.store, entry_id)
        return report.to_json(heatmap)
    except NotImplementedError:
        return mocked(mock_verify(rgb, request.query_params.get("mock", "edited")))


@app.post("/api/redact")
async def redact(image: UploadFile = File(...), entry_id: str = Form(...), boxes: str = Form(...)):
    if not ENTRY_ID.match(entry_id):
        raise HTTPException(422, "entry_id must be hex")
    try:
        parsed = [tuple(int(v) for v in b) for b in json.loads(boxes)]
        if not parsed or any(len(b) != 4 for b in parsed):
            raise ValueError
    except (ValueError, TypeError) as e:
        raise HTTPException(422, "boxes must be JSON [[x0,y0,x1,y1], …]") from e
    rgb = await read_image(image)
    try:
        new_id, _png = pipeline.redact_image(rgb, entry_id, parsed, app.state.store)
        return {"entry_id": new_id, "image_url": f"/api/files/{new_id}.png"}
    except NotImplementedError:
        new_id = f"{entry_id}-r1"
        return mocked({"entry_id": new_id, "image_url": f"/api/files/{new_id}.png"})


# --- mocks (removed at the sync once pipeline.py is ready) -------------------------------

MOCK_TX = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90"
MOCK_PUB = "ED" + "12" * 32


def _grid(rgb: np.ndarray) -> dict:
    h, w = rgb.shape[:2]
    return {"cols": -(-w // 32), "rows": -(-h // 32), "tile": 32}


def mock_sign(rgb: np.ndarray, signer: str) -> dict:
    return {
        "entry_id": MOCK_TX,
        "tx_hash": MOCK_TX,
        "explorer_url": f"https://testnet.xrpl.org/transactions/{MOCK_TX}",
        "digest": "9f" * 32,
        "signer": MOCK_PUB,
        "grid": _grid(rgb),
        "roots": {"exact": "ab" * 32, "robust": "cd" * 32},
        "image_url": f"/api/files/{MOCK_TX}.png",
    }


def mock_verify(rgb: np.ndarray, verdict: str) -> dict:
    if verdict == "unknown":
        return {
            "verdict": "unknown", "reason": "No provenance found (no tx_hash, watermark or perceptual match)",
            "found_by": None, "entry_id": None, "anchor": None, "credential": None,
            "signature_ok": False, "tiles": None, "heatmap_png_b64": None,
        }
    grid = _grid(rgb)
    cols, rows = grid["cols"], grid["rows"]
    statuses = ["exact"] * (cols * rows)
    if verdict == "edited":  # a changed block in the middle, a few recompressed tiles around it
        for r in range(rows // 3, rows // 3 + max(1, rows // 4)):
            for c in range(cols // 3, cols // 3 + max(1, cols // 4)):
                statuses[r * cols + c] = "changed"
        for i in range(0, len(statuses), 7):
            if statuses[i] == "exact":
                statuses[i] = "robust"
    dist = {"exact": 0.0, "robust": 1.2, "changed": 37.5, "redacted": 0.0}
    counts = {k: statuses.count(k) for k in ("exact", "robust", "changed", "redacted")}
    credential = "AI_GENERATOR" if verdict == "ai" else "CAPTURE_DEVICE"
    reasons = {
        "real": f"Signed by a CAPTURE_DEVICE credential; {counts['exact']}/{len(statuses)} tiles match",
        "ai": f"Signed by an AI_GENERATOR credential; {counts['exact']}/{len(statuses)} tiles match",
        "edited": f"{counts['changed']}/{len(statuses)} tiles changed since signature",
    }
    return {
        "verdict": verdict,
        "reason": reasons.get(verdict, reasons["edited"]),
        "found_by": "phash",
        "entry_id": MOCK_TX,
        "anchor": {
            "tx_hash": MOCK_TX, "timestamp": 1795000000,
            "explorer_url": f"https://testnet.xrpl.org/transactions/{MOCK_TX}", "signer": MOCK_PUB,
        },
        "credential": credential,
        "signature_ok": True,
        "tiles": {
            "verdict": "edited" if verdict == "edited" else "intact",
            "grid": grid, "counts": counts, "statuses": statuses,
            "distances": [dist[s] for s in statuses],
        },
        "heatmap_png_b64": _mock_heatmap(statuses, cols, rows) if verdict == "edited" else None,
    }


def _mock_heatmap(statuses: list[str], cols: int, rows: int) -> str:
    colors = {"exact": (0, 0, 0, 0), "robust": (250, 200, 0, 90), "changed": (232, 89, 12, 180), "redacted": (0, 0, 0, 255)}
    img = Image.new("RGBA", (cols, rows))
    img.putdata([colors[s] for s in statuses])
    buf = io.BytesIO()
    img.resize((cols * 32, rows * 32), Image.Resampling.NEAREST).save(buf, "PNG")
    return base64.b64encode(buf.getvalue()).decode()
