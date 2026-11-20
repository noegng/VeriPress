"""Sign / verify pipeline — OWNER: Dev A.  The signatures and JSON shapes below are the
contract with Dev B's API (see docs/interfaces.md): change only via a dedicated commit on main.

Final verdict rules (implemented test-first by Dev A):
  no entry found (no tx_hash, no watermark, no phash match)        -> UNKNOWN
  anchor missing on ledger / digest mismatch / bad signature       -> UNKNOWN (reason says why)
  disclosure does not match the signed roots                       -> UNKNOWN
  tiles: EDITED                                                    -> EDITED (heatmap)
  tiles: INTACT|RECOMPRESSED + credential CAPTURE_DEVICE           -> REAL
  tiles: INTACT|RECOMPRESSED + credential AI_GENERATOR             -> AI
  tiles: INTACT|RECOMPRESSED + no valid credential (or revoked)    -> UNKNOWN
"""

from __future__ import annotations

import base64
import io
import os
from dataclasses import dataclass
from enum import Enum
from typing import Literal

import numpy as np
from PIL import Image

from .tiling import Grid
from .commitment import Manifest, Verdict, VerifyResult, commit, heatmap, redact, verify
from .perceptual import phash
from .ledger import Anchor, CredentialType, Ledger
from .signing import load_key, verify_signature
from .store import Entry, Store

Signer = Literal["device", "ai"]  # demo keys in keys/device.json, keys/ai.json (written by Dev B's setup script)
FoundBy = Literal["tx_hash", "watermark", "phash"]


class FinalVerdict(str, Enum):
    REAL = "real"
    EDITED = "edited"
    AI = "ai"
    UNKNOWN = "unknown"


@dataclass
class SignResult:
    entry_id: str
    anchor: Anchor
    manifest: Manifest

    def to_json(self) -> dict:
        """Shape: docs/interfaces.md "POST /api/sign"."""
        g = self.manifest.grid
        return {
            "entry_id": self.entry_id,
            "tx_hash": self.anchor.tx_hash,
            "explorer_url": self.anchor.explorer_url,
            "digest": self.manifest.digest(),
            "signer": self.manifest.signer,
            "grid": {"cols": g.cols, "rows": g.rows, "tile": g.tile},
            "roots": {"exact": self.manifest.exact_root, "robust": self.manifest.robust_root},
            "image_url": f"/api/files/{self.entry_id}.png",
        }


@dataclass
class Report:
    verdict: FinalVerdict
    reason: str
    found_by: FoundBy | None
    entry_id: str | None
    anchor: Anchor | None
    credential: CredentialType | None
    signature_ok: bool
    tiles: VerifyResult | None
    grid: Grid | None = None

    def to_json(self, heatmap_png: bytes | None = None) -> dict:
        """Shape: docs/interfaces.md "POST /api/verify"."""
        a, t, g = self.anchor, self.tiles, self.grid
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "found_by": self.found_by,
            "entry_id": self.entry_id,
            "anchor": None if a is None else {
                "tx_hash": a.tx_hash, "timestamp": a.timestamp,
                "explorer_url": a.explorer_url, "signer": a.pubkey,
            },
            "credential": self.credential.value if self.credential else None,
            "signature_ok": self.signature_ok,
            "tiles": None if t is None or g is None else {
                "verdict": t.verdict.value,
                "grid": {"cols": g.cols, "rows": g.rows, "tile": g.tile},
                "counts": t.counts(),
                "statuses": [s.value for s in t.statuses],
                "distances": [round(d, 2) for d in t.distances],
            },
            "heatmap_png_b64": base64.b64encode(heatmap_png).decode() if heatmap_png else None,
        }


def _png(img: np.ndarray | Image.Image) -> bytes:
    buf = io.BytesIO()
    (img if isinstance(img, Image.Image) else Image.fromarray(img)).save(buf, "PNG")
    return buf.getvalue()


def sign_image(rgb: np.ndarray, signer: Signer, ledger: Ledger, store: Store) -> tuple[SignResult, bytes]:
    """Commit, sign, anchor, store. Returns the result and the PNG to publish."""
    key = load_key(signer)
    manifest, disclosure = commit(rgb, os.urandom(32))
    manifest.signer = key.public_key
    manifest.op = "ai_generate" if signer == "ai" else "capture"
    digest = manifest.digest()
    anchor = ledger.anchor(digest, key.sign(digest), key.public_key)
    png = _png(rgb)
    store.put(Entry(anchor.tx_hash, anchor.tx_hash, manifest, disclosure, phash(rgb)), png)
    return SignResult(anchor.tx_hash, anchor, manifest), png


def verify_image(
    rgb: np.ndarray, ledger: Ledger, store: Store, entry_id: str | None = None
) -> tuple[Report, bytes | None]:
    """Find the entry (entry_id > watermark > phash), check anchor/signature/credential/tiles.
    Returns the report and the heatmap PNG (None when no entry was found)."""
    found_by: FoundBy | None = None
    if entry_id:
        entry, found_by = store.get(entry_id), "tx_hash"
    else:
        entry = store.nearest(phash(rgb))
        found_by = "phash" if entry else None
    if entry is None:
        reason = f"No provenance record for id {entry_id}" if entry_id else "No provenance found for this image"
        return Report(FinalVerdict.UNKNOWN, reason, None, None, None, None, False, None), None
    manifest = entry.manifest
    anchor = ledger.fetch_anchor(entry.tx_hash)
    if anchor is None:
        reason = f"Anchor transaction {entry.tx_hash} not found on the ledger"
        return Report(FinalVerdict.UNKNOWN, reason, found_by, entry.id, None, None, False, None), None
    sig_ok = verify_signature(anchor.digest, anchor.signature, anchor.pubkey)
    credential = ledger.credential_type(anchor.pubkey, anchor.timestamp)
    tiles = verify(rgb, manifest, entry.disclosure)
    reason = ""
    if anchor.digest != manifest.digest() or anchor.pubkey != manifest.signer:
        verdict = FinalVerdict.UNKNOWN
        reason = "Stored manifest does not match the anchored digest"
    elif not sig_ok:
        verdict = FinalVerdict.UNKNOWN
        reason = "Anchored signature does not verify against the signer key"
    elif tiles.verdict == Verdict.INVALID_DISCLOSURE:
        verdict = FinalVerdict.UNKNOWN
        reason = "Tile disclosure does not match the signed Merkle roots"
    elif tiles.verdict == Verdict.EDITED:
        verdict = FinalVerdict.EDITED
    elif credential == CredentialType.AI_GENERATOR:
        verdict = FinalVerdict.AI
    elif credential == CredentialType.CAPTURE_DEVICE:
        verdict = FinalVerdict.REAL
    else:
        verdict = FinalVerdict.UNKNOWN
        reason = "Signer has no valid credential (never issued or revoked)"
    report = Report(verdict, reason, found_by, entry.id, anchor, credential, sig_ok, tiles, manifest.grid)
    hm = _png(heatmap(rgb, manifest, tiles)) if tiles.statuses else None
    return report, hm


def redact_image(
    rgb: np.ndarray, entry_id: str, boxes: list[tuple[int, int, int, int]], store: Store
) -> tuple[str, bytes]:
    """Black out boxes, store a redacted variant entry. Returns (new_entry_id, png)."""
    entry = store.get(entry_id)
    if entry is None:
        raise KeyError(entry_id)
    grid = entry.manifest.grid
    tiles = {i for box in boxes for i in grid.tiles_in_box(*box)}
    out, disclosure = redact(rgb, entry.manifest, entry.disclosure, tiles)
    n = 1
    while store.get(f"{entry.tx_hash}-r{n}") is not None:
        n += 1
    new_id = f"{entry.tx_hash}-r{n}"
    png = _png(out)
    store.put(Entry(new_id, entry.tx_hash, entry.manifest, disclosure, phash(out)), png)
    return new_id, png
