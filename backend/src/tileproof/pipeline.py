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

from dataclasses import dataclass
from enum import Enum
from typing import Literal

import numpy as np

from .commitment import Manifest, VerifyResult
from .ledger import Anchor, CredentialType, Ledger
from .store import Store

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
        raise NotImplementedError  # shape: docs/interfaces.md "POST /api/sign"


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

    def to_json(self, heatmap_png: bytes | None = None) -> dict:
        raise NotImplementedError  # shape: docs/interfaces.md "POST /api/verify"


def sign_image(rgb: np.ndarray, signer: Signer, ledger: Ledger, store: Store) -> tuple[SignResult, bytes]:
    """Commit, sign, anchor, store. Returns the result and the PNG to publish."""
    raise NotImplementedError


def verify_image(
    rgb: np.ndarray, ledger: Ledger, store: Store, entry_id: str | None = None
) -> tuple[Report, bytes | None]:
    """Find the entry (entry_id > watermark > phash), check anchor/signature/credential/tiles.
    Returns the report and the heatmap PNG (None when no entry was found)."""
    raise NotImplementedError


def redact_image(
    rgb: np.ndarray, entry_id: str, boxes: list[tuple[int, int, int, int]], store: Store
) -> tuple[str, bytes]:
    """Black out boxes, store a redacted variant entry. Returns (new_entry_id, png)."""
    raise NotImplementedError
