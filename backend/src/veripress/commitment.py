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
from .tiling import Grid, auto_tile, grid_for, resize_to, tile_pixels

EXACT_DOMAIN = b"VPX1"
ROBUST_DOMAIN = b"VPR1"
VERSION = 1
REDACTED_MAX_MEAN = 16  # a redacted tile is black; JPEG keeps it far below these bounds
REDACTED_MAX_P95 = 48


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
    anonymous: bool = False  # signed with a zero-knowledge device attestation (signer = "")
    meta_commitment: str | None = None  # Poseidon commitment to EXIF time + GPS (ZK B)
    passkey: str | None = None  # P-256 public key (SEC1 hex) when signed with a passkey
    pq_pubkey_sha256: str | None = None  # sha256 of the attested ML-DSA-87 key (hybrid post-quantum)
    disclosure_cid: str = ""  # CIDv1 (raw, sha2-256) of the canonical disclosure JSON
    t0: dict | None = None  # {"ledger_index", "ledger_hash"}: latest validated XRPL ledger at signing
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
    g: list[int] | None = None  # revealed tiles: features of the unwatermarked original, if any
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


def _robust_leaf(vec, i: int, salt: bytes, alt=None) -> bytes:
    """Robust leaf over the committed features, plus those of the unwatermarked original when
    the published image carries a watermark (both versions are authentic captures)."""
    payload = F.feature_bytes(vec) + (F.feature_bytes(alt) if alt is not None else b"")
    return leaf_hash(ROBUST_DOMAIN, i, salt, payload)


def _alt(t: "TileDisclosure"):
    return None if t.g is None else np.array(t.g)


# ---------------------------------------------------------------- commit / redact


def commit(
    rgb: np.ndarray, seed: bytes, tile: int | None = None, original: np.ndarray | None = None
) -> tuple[Manifest, Disclosure]:
    """`original`: the same picture before watermarking, so that it (and its shared copies)
    also verifies; the exact tree covers `rgb` only."""
    tile = tile or auto_tile(rgb.shape[1], rgb.shape[0])
    grid = grid_for(rgb, tile)
    feats = F.quantized_features(rgb, grid)
    salts = [tile_salt(seed, i) for i in range(grid.count)]
    exact = [_exact_leaf(rgb, grid, i, salts[i]) for i in range(grid.count)]
    if original is not None and original.shape != rgb.shape:
        raise ValueError("original must have the same size as the watermarked image")
    alts = F.quantized_features(original, grid) if original is not None else [None] * grid.count
    robust = [_robust_leaf(feats[i], i, salts[i], alts[i]) for i in range(grid.count)]
    manifest = Manifest(
        width=grid.width,
        height=grid.height,
        tile=tile,
        exact_root=MerkleTree(exact).root.hex(),
        robust_root=MerkleTree(robust).root.hex(),
    )
    disclosure = Disclosure(
        tiles=[
            TileDisclosure(
                i=i, x=exact[i].hex(), salt=salts[i].hex(), f=feats[i].tolist(),
                g=None if alts[i] is None else alts[i].tolist(),
            )
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
            r = _robust_leaf(np.array(t.f), t.i, bytes.fromhex(t.salt), _alt(t)).hex()
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
    original_tiles: int = 0  # tiles closer to the unwatermarked original than to the published image

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
        bytes.fromhex(t.r) if t.redacted else _robust_leaf(np.array(t.f), t.i, bytes.fromhex(t.salt), _alt(t))
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
    original_tiles = 0
    distances: list[float] = []
    for t in tiles:
        if t.redacted:
            # Authenticated by hash only: the received pixels must really be blacked out,
            # otherwise anything could be pasted under a "redacted" label.
            px = tile_pixels(rgb, grid, t.i)
            hidden = px.mean() <= REDACTED_MAX_MEAN and np.percentile(px, 95) <= REDACTED_MAX_P95
            statuses.append(TileStatus.REDACTED if hidden else TileStatus.CHANGED)
            distances.append(0.0 if hidden else float("inf"))
            continue
        dist = float(F.tile_distance(raw[t.i : t.i + 1], np.array([t.f]))[0])
        if t.g is not None:  # closer to the unwatermarked original?
            dist_g = float(F.tile_distance(raw[t.i : t.i + 1], np.array([t.g]))[0])
            closer_to_original = dist_g < dist
            dist = min(dist, dist_g)
        else:
            closer_to_original = False
        distances.append(dist)
        if _exact_leaf(rgb, grid, t.i, bytes.fromhex(t.salt)).hex() == t.x:
            statuses.append(TileStatus.EXACT)
        elif dist <= F.TOLERANCE:
            statuses.append(TileStatus.ROBUST)
            original_tiles += closer_to_original
        else:
            statuses.append(TileStatus.CHANGED)

    if TileStatus.CHANGED in statuses:
        verdict = Verdict.EDITED
    elif TileStatus.ROBUST in statuses:
        verdict = Verdict.RECOMPRESSED
    else:
        verdict = Verdict.INTACT
    return VerifyResult(verdict, statuses, distances, exact_ok, robust_ok, original_tiles)


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
    base = Image.fromarray(np.clip(resize_to(rgb, grid.width, grid.height), 0, 255).astype(np.uint8)).convert("RGBA")
    overlay = np.zeros((grid.height, grid.width, 4), dtype=np.uint8)
    for i, s in enumerate(result.statuses):
        x0, y0, x1, y1 = grid.bounds(i)
        overlay[y0:y1, x0:x1] = _COLORS[s]
        overlay[y0, x0:x1] = overlay[y0:y1, x0] = (255, 255, 255, 40)  # grid lines
    return Image.alpha_composite(base, Image.fromarray(overlay, "RGBA")).convert("RGB")
