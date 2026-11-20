"""Off-chain store — OWNER: Dev A.  Shared interface: change only via a dedicated commit on main.

The disclosure (salts + features per tile) is too big for an XRPL memo, so it lives here.
In production: IPFS or hosted by the owner. Layout on disk:

  store/<entry_id>/entry.json   {"id", "tx_hash", "manifest", "disclosure", "phash"}
  store/<entry_id>/image.png    the published image (watermarked once TrustMark lands)

entry_id == tx_hash for an original; "<tx_hash>-r<n>" for a redacted variant
(same manifest/anchor, redacted disclosure).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .commitment import Disclosure, Manifest


@dataclass
class Entry:
    id: str
    tx_hash: str
    manifest: Manifest
    disclosure: Disclosure
    phash: int  # 64-bit perceptual hash of the published image


class Store:
    def __init__(self, root: str | Path = "store") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, entry: Entry, image_png: bytes | None = None) -> None:
        d = self.root / entry.id
        d.mkdir(parents=True, exist_ok=True)
        data = {
            "id": entry.id,
            "tx_hash": entry.tx_hash,
            "manifest": entry.manifest.__dict__,
            "disclosure": entry.disclosure.to_dict(),
            "phash": f"{entry.phash:016x}",
        }
        (d / "entry.json").write_text(json.dumps(data, separators=(",", ":")))
        if image_png is not None:
            (d / "image.png").write_bytes(image_png)

    def get(self, entry_id: str) -> Entry | None:
        p = self.root / entry_id / "entry.json"
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        return Entry(
            id=d["id"],
            tx_hash=d["tx_hash"],
            manifest=Manifest.from_dict(d["manifest"]),
            disclosure=Disclosure.from_dict(d["disclosure"]),
            phash=int(d["phash"], 16),
        )

    def image_path(self, entry_id: str) -> Path:
        return self.root / entry_id / "image.png"

    def find_by_watermark(self, wm_id: str, phash: int) -> Entry | None:
        """Entries whose manifest carries this watermark id (original + redacted variants):
        return the one closest to `phash`."""
        best: tuple[int, str] | None = None
        for p in self.root.glob("*/entry.json"):
            d = json.loads(p.read_text())
            if d["manifest"].get("wm_id") == wm_id:
                dist = (phash ^ int(d["phash"], 16)).bit_count()
                if best is None or dist < best[0]:
                    best = (dist, d["id"])
        return self.get(best[1]) if best else None

    def nearest(self, phash: int, max_distance: int = 10) -> Entry | None:
        """Closest entry by Hamming distance on the perceptual hash, if within max_distance."""
        best: tuple[int, str] | None = None
        for p in self.root.glob("*/entry.json"):
            other = int(json.loads(p.read_text())["phash"], 16)
            dist = (phash ^ other).bit_count()
            if dist <= max_distance and (best is None or dist < best[0]):
                best = (dist, p.parent.name)
        return self.get(best[1]) if best else None
