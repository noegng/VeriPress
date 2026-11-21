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
import re
from dataclasses import dataclass
from pathlib import Path

from .commitment import Disclosure, Manifest


ENTRY_ID = re.compile(r"^[0-9A-Fa-f]{16,64}(-r\d+)?$")  # tx hash, or tx hash + redaction variant


def valid_id(entry_id: str) -> bool:
    """Entry ids also come from signed manifests (parent): never let one escape the store."""
    return isinstance(entry_id, str) and bool(ENTRY_ID.match(entry_id))


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
        if not valid_id(entry_id):
            return None
        p = self.root / entry_id / "entry.json"
        return self._read_entry(p) if p.exists() else None

    # The store is untrusted (anyone can add a record): reading it is total. A malformed record
    # (bad JSON, missing field, wrong type, id that is not its folder's) is skipped, never fatal
    # (security audit 21/11, F2: one bad file used to break every id-less verification).
    @staticmethod
    def _load(path: Path):
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError, TypeError):
            return None

    @classmethod
    def _read_entry(cls, path: Path) -> Entry | None:
        d = cls._load(path)
        try:
            if d["id"] != path.parent.name:
                return None
            return Entry(
                id=d["id"],
                tx_hash=d["tx_hash"],
                manifest=Manifest.from_dict(d["manifest"]),
                disclosure=Disclosure.from_dict(d["disclosure"]),
                phash=int(d["phash"], 16),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None

    def _index(self) -> list[tuple[str, str | None, int]]:
        """(folder, watermark id, perceptual hash) of every readable record."""
        out = []
        for p in self.root.glob("*/entry.json"):
            d = self._load(p)
            try:
                wm = d["manifest"].get("wm_id")
                out.append((p.parent.name, wm if isinstance(wm, str) else None, int(d["phash"], 16)))
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
        return out

    def put_bundle(self, entry_id: str, bundle: dict) -> None:
        """Proof bundle of an anonymous / passkey signature (its sha256 is anchored)."""
        (self.root / entry_id / "bundle.json").write_text(json.dumps(bundle, sort_keys=True, separators=(",", ":")))

    def get_bundle(self, entry_id: str) -> dict | None:
        if not valid_id(entry_id):
            return None
        p = self.root / entry_id / "bundle.json"
        d = self._load(p) if p.exists() else None
        return d if isinstance(d, dict) else None

    def put_meta(self, entry_id: str, claims: list[dict]) -> None:
        """ZK proofs of capture-metadata claims (untrusted: checked against the signed commitment)."""
        (self.root / entry_id / "meta.json").write_text(json.dumps(claims, separators=(",", ":")))

    def get_meta(self, entry_id: str) -> list[dict]:
        if not valid_id(entry_id):
            return []
        p = self.root / entry_id / "meta.json"
        data = self._load(p) if p.exists() else []
        return data if isinstance(data, list) else []

    def put_pq(self, entry_id: str, pq: dict) -> None:
        """Hybrid post-quantum signature {alg, public_key, signature} (too big for a 1 kB memo)."""
        if valid_id(entry_id):
            (self.root / entry_id / "pq.json").write_text(json.dumps(pq, separators=(",", ":")))

    def get_pq(self, entry_id: str) -> dict | None:
        p = self.root / entry_id / "pq.json" if valid_id(entry_id) else None
        data = self._load(p) if p is not None and p.exists() else None
        return data if isinstance(data, dict) else None

    def put_receipt(self, entry_id: str, receipt: dict) -> None:
        """Aggregated anchoring: {batch_tx, index, leaf, proof} or {queued: leaf} (untrusted)."""
        if valid_id(entry_id):
            (self.root / entry_id).mkdir(parents=True, exist_ok=True)
            (self.root / entry_id / "receipt.json").write_text(json.dumps(receipt, separators=(",", ":")))

    def get_receipt(self, entry_id: str) -> dict | None:
        p = self.root / entry_id / "receipt.json" if valid_id(entry_id) else None
        if p is None or not p.exists():
            return None
        data = self._load(p)
        return data if isinstance(data, dict) else None

    def image_path(self, entry_id: str) -> Path:
        if not valid_id(entry_id):
            return self.root / "_invalid_id_" / "image.png"  # never exists
        return self.root / entry_id / "image.png"

    def find_by_watermark(self, wm_id: str, phash: int) -> Entry | None:
        """Entries whose manifest carries this watermark id (original + redacted variants):
        return the one closest to `phash`."""
        found = self.find_all_by_watermark(wm_id, phash)
        return found[0] if found else None

    def find_all_by_watermark(self, wm_id: str, phash: int) -> list[Entry]:
        """Every entry whose manifest carries this watermark id, closest perceptual hash first.
        The store is untrusted: anyone may add a variant, so callers verify each candidate."""
        found = [((phash ^ ph).bit_count(), "-r" in i, i) for i, wm, ph in self._index() if wm == wm_id]
        return [e for _, _, i in sorted(found) if (e := self.get(i)) is not None]

    def nearest_all(self, phash: int, max_distance: int = 10) -> list[Entry]:
        """Every entry within max_distance of the perceptual hash, closest first (untrusted)."""
        found = [((phash ^ ph).bit_count(), "-r" in i, i) for i, _, ph in self._index()]
        return [e for d, _, i in sorted(found) if d <= max_distance and (e := self.get(i)) is not None]

    def nearest(self, phash: int, max_distance: int = 10) -> Entry | None:
        """Closest entry by Hamming distance on the perceptual hash, if within max_distance."""
        found = self.nearest_all(phash, max_distance)
        return found[0] if found else None
