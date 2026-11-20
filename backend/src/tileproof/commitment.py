"""Commit an image (two Merkle trees over tiles), redact tiles, verify an image.

Public, signed & anchored:   Manifest   (dims, tile size, feature params, both roots)
Distributed with the image:  Disclosure (per tile: salt + committed features + exact leaf,
                                         or, for redacted tiles, only the two leaf hashes)

Leaves are salted per tile (salt_i = HMAC(seed, i)) so a redacted tile's leaf
hashes reveal nothing about its content, even for low-entropy tiles.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from enum import Enum

import numpy as np
from PIL import Image

from . import features as F
from .merkle import MerkleTree, leaf_hash, sha256
from .tiling import DEFAULT_TILE, Grid, grid_for, resize_to, tile_pixels

EXACT_DOMAIN = b"TPX1"
ROBUST_DOMAIN = b"TPR1"
VERSION = 1


# ---------------------------------------------------------------- data model


@dataclass
class Manifest:
    width: int
    height: int
    tile: int
    exact_root: str
    robust_root: str
    feature: dict = field(
        default_factory=lambda: {"pool": F.POOL, "n": F.N_COEFFS, "step": F.STEP}
    )
    signer: str = ""  # XRPL ed25519 public key ("ED…") of the signing device / generator
    op: str = "capture"  # capture | ai_generate | edit
    parent: str | None = None  # tx hash of the version this one was edited from
    wm_id: str = ""  # hex 64-bit watermark lookup id embedded in the pixels ("" = none)
    v: int = VERSION

    @property
    def grid(self) -> Grid:
        return Grid(self.width, self.height, self.tile)

    def canonical(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        """Hash that gets signed and anchored on XRPL."""
        return sha256(self.canonical()).hex()

    @classmethod
    def from_dict(cls, d: dict) -> "Manifest":
        return cls(**d)


@dataclass
class TileDisclosure:
    i: int
    x: str  # exact leaf hash
    salt: str | None = None  # revealed tiles
    f: list[int] | None = None  # revealed tiles: committed features
    r: str | None = None  # redacted tiles: robust leaf hash

    @property
    def redacted(self) -> bool:
        return self.salt is None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Disclosure:
    tiles: list[TileDisclosure]
    v: int = VERSION

    def to_dict(self) -> dict:
        return {"v": self.v, "tiles": [t.to_dict() for t in self.tiles]}

    @classmethod
    def from_dict(cls, d: dict) -> "Disclosure":
        return cls(tiles=[TileDisclosure(**t) for t in d["tiles"]], v=d.get("v", VERSION))


# ---------------------------------------------------------------- helpers


def tile_salt(seed: bytes, index: int) -> bytes:
    return hmac.new(seed, b"tile" + index.to_bytes(4, "big"), hashlib.sha256).digest()[:16]


def _exact_leaf(rgb: np.ndarray, grid: Grid, i: int, salt: bytes) -> bytes:
    return leaf_hash(EXACT_DOMAIN, i, salt, tile_pixels(rgb, grid, i).tobytes())


def _robust_leaf(vec, i: int, salt: bytes) -> bytes:
    return leaf_hash(ROBUST_DOMAIN, i, salt, F.feature_bytes(vec))


# ---------------------------------------------------------------- commit / redact


def commit(rgb: np.ndarray, seed: bytes, tile: int = DEFAULT_TILE) -> tuple[Manifest, Disclosure]:
    grid = grid_for(rgb, tile)
    feats = F.quantized_features(rgb, grid)
    salts = [tile_salt(seed, i) for i in range(grid.count)]
    exact = [_exact_leaf(rgb, grid, i, salts[i]) for i in range(grid.count)]
    robust = [_robust_leaf(feats[i], i, salts[i]) for i in range(grid.count)]
    manifest = Manifest(
        width=grid.width,
        height=grid.height,
        tile=tile,
        exact_root=MerkleTree(exact).root.hex(),
        robust_root=MerkleTree(robust).root.hex(),
    )
    disclosure = Disclosure(
        tiles=[
            TileDisclosure(i=i, x=exact[i].hex(), salt=salts[i].hex(), f=feats[i].tolist())
            for i in range(grid.count)
        ]
    )
    return manifest, disclosure


def redact(
    rgb: np.ndarray, manifest: Manifest, disclosure: Disclosure, tiles: set[int]
) -> tuple[np.ndarray, Disclosure]:
    """Black out `tiles` in the image and strip their salt/features from the disclosure."""
    grid = manifest.grid
    out = rgb.copy()
    new_tiles = []
    for t in disclosure.tiles:
        if t.i in tiles and not t.redacted:
            x0, y0, x1, y1 = grid.bounds(t.i)
            out[y0:y1, x0:x1] = 0
            r = _robust_leaf(np.array(t.f), t.i, bytes.fromhex(t.salt)).hex()
            new_tiles.append(TileDisclosure(i=t.i, x=t.x, r=r))
        else:
            new_tiles.append(t)
    return out, Disclosure(tiles=new_tiles)


# ---------------------------------------------------------------- verify


class TileStatus(str, Enum):
    EXACT = "exact"  # byte-identical pixels
    ROBUST = "robust"  # pixels differ but content matches (recompression, rescale)
    CHANGED = "changed"  # content edited
    REDACTED = "redacted"  # hidden by the owner, authenticated by hash only


class Verdict(str, Enum):
    INTACT = "intact"
    RECOMPRESSED = "recompressed"
    EDITED = "edited"
    INVALID_DISCLOSURE = "invalid_disclosure"


@dataclass
class VerifyResult:
    verdict: Verdict
    statuses: list[TileStatus]
    distances: list[float]
    exact_root_ok: bool
    robust_root_ok: bool

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in TileStatus}
        for s in self.statuses:
            out[s.value] += 1
        return out


def verify(rgb: np.ndarray, manifest: Manifest, disclosure: Disclosure) -> VerifyResult:
    grid = manifest.grid
    if manifest.feature != {"pool": F.POOL, "n": F.N_COEFFS, "step": F.STEP}:
        raise ValueError(f"unsupported feature params {manifest.feature}")
    tiles = sorted(disclosure.tiles, key=lambda t: t.i)
    if [t.i for t in tiles] != list(range(grid.count)):
        return VerifyResult(Verdict.INVALID_DISCLOSURE, [], [], False, False)

    # 1. Authenticate the disclosure itself against the signed roots.
    exact_leaves = [bytes.fromhex(t.x) for t in tiles]
    robust_leaves = [
        bytes.fromhex(t.r) if t.redacted else _robust_leaf(np.array(t.f), t.i, bytes.fromhex(t.salt))
        for t in tiles
    ]
    exact_ok = MerkleTree(exact_leaves).root.hex() == manifest.exact_root
    robust_ok = MerkleTree(robust_leaves).root.hex() == manifest.robust_root
    if not (exact_ok and robust_ok):
        return VerifyResult(Verdict.INVALID_DISCLOSURE, [], [], exact_ok, robust_ok)

    # 2. Compare the received image tile by tile.
    rgb = resize_to(rgb, grid.width, grid.height)
    raw = F.raw_features(rgb, grid)
    statuses: list[TileStatus] = []
    distances: list[float] = []
    for t in tiles:
        if t.redacted:
            statuses.append(TileStatus.REDACTED)
            distances.append(0.0)
            continue
        dist = float(F.tile_distance(raw[t.i : t.i + 1], np.array([t.f]))[0])
        distances.append(dist)
        if _exact_leaf(rgb, grid, t.i, bytes.fromhex(t.salt)).hex() == t.x:
            statuses.append(TileStatus.EXACT)
        elif dist <= F.TOLERANCE:
            statuses.append(TileStatus.ROBUST)
        else:
            statuses.append(TileStatus.CHANGED)

    if TileStatus.CHANGED in statuses:
        verdict = Verdict.EDITED
    elif TileStatus.ROBUST in statuses:
        verdict = Verdict.RECOMPRESSED
    else:
        verdict = Verdict.INTACT
    return VerifyResult(verdict, statuses, distances, exact_ok, robust_ok)


# ---------------------------------------------------------------- visualisation


_COLORS = {
    TileStatus.EXACT: (0, 200, 80, 60),
    TileStatus.ROBUST: (120, 220, 60, 90),
    TileStatus.CHANGED: (230, 30, 30, 150),
    TileStatus.REDACTED: (0, 0, 0, 230),
}


def heatmap(rgb: np.ndarray, manifest: Manifest, result: VerifyResult) -> Image.Image:
    """Overlay tile statuses on the (resized) received image."""
    grid = manifest.grid
    base = Image.fromarray(resize_to(rgb, grid.width, grid.height)).convert("RGBA")
    overlay = np.zeros((grid.height, grid.width, 4), dtype=np.uint8)
    for i, s in enumerate(result.statuses):
        x0, y0, x1, y1 = grid.bounds(i)
        overlay[y0:y1, x0:x1] = _COLORS[s]
        overlay[y0, x0:x1] = overlay[y0:y1, x0] = (255, 255, 255, 40)  # grid lines
    return Image.alpha_composite(base, Image.fromarray(overlay, "RGBA")).convert("RGB")
