"""Robust per-tile features: survive JPEG recompression / mild rescaling,
change when the tile's content is edited.

Per tile and channel: average-pool to 8x8 -> orthonormal 2D DCT-II -> first coefficients in
zigzag order (DC included) -> divide by STEP and round.

  luminance : the first `n` coefficients. 0-9 = shape and brightness; 10..n-1 = finer detail
              (erased by blurring), weighted DETAIL_WEIGHT;
  Cb, Cr    : the first `chroma` coefficients each, weighted CHROMA_WEIGHT (colour: a recolouring
              that keeps the luminance changed nothing in the first feature set).

The parameters are part of the signed manifest (`feature`), so records signed with the first
feature set (SPEC_V1: luminance only, 10 coefficients) keep verifying.

The quantized vector is committed in the robust Merkle tree. A verifier does NOT compare hashes
(quantization boundaries would make benign recompression flip a leaf); it compares the received
tile's feature vector with the committed one using a distance tolerance. The Merkle root only
authenticates the committed reference vectors.
"""

from __future__ import annotations

import numpy as np

from .tiling import Grid

POOL = 8
STEP = 4.0
SPEC_V1 = {"pool": POOL, "n": 10, "step": STEP}  # 20/11: luminance only
SPEC = {"pool": POOL, "n": 15, "step": STEP, "chroma": 3}  # adversarial review: + detail + colour
SUPPORTED = (SPEC, SPEC_V1)

TOLERANCE = 4.5  # max weighted |delta| (in STEPs) for a tile to count as unchanged.
# Calibrated 20/11 on 6 real 3-5k camera photos (Wikimedia Commons) shared WhatsApp-like
# (1600 px q72 and 1280 px q55) with tiles = long side / 40: benign max 2.96, copy-move
# forgeries of 2 tiles detected 100%, of half a tile 78%. Then on 4 iPhone HEIC photos
# (Display P3) really sent through WhatsApp: needs ICC->sRGB + unclipped resampling + DC_WEIGHT,
# after which benign max = 2.01. `veripress.cli calibrate` re-runs it.
# SPEC (adversarial review). Same 4 iPhone photos (real WhatsApp + 1600q72 + 1280q55): detail
# coefficients 10-14 move at most 1.97 steps benignly, 7.5 under a Gaussian blur of radius 5 over
# a region (3.2 at radius 3: not caught); Cb/Cr move at most 2.66 benignly, 52 to 89 under a
# recolouring that keeps the luminance. Harder benign cases set the weights: thin dark lines
# downscaled 2x move detail by 5.3 steps (x0.75 = 4.0), and JPEG chroma subsampling after a
# strong downscale moves Cb/Cr by up to 12 steps on saturated synthetic edges (x0.25 = 3.1).

DC_WEIGHT = 0.5  # mean brightness drifts more than structure under resampling/clipping
DETAIL_WEIGHT = 0.75  # finer luminance detail: erased by blurring, aliased by thin periodic lines
CHROMA_WEIGHT = 0.25  # JPEG halves the colour resolution: wide benign drift, huge under recolouring
_DETAIL_FROM = 10

_LUMA = np.array([0.299, 0.587, 0.114])
_CB = np.array([-0.168736, -0.331264, 0.5])
_CR = np.array([0.5, -0.418688, -0.081312])


def _dct_matrix(n: int) -> np.ndarray:
    k = np.arange(n)[:, None]
    i = np.arange(n)[None, :]
    m = np.cos(np.pi * (2 * i + 1) * k / (2 * n)) * np.sqrt(2.0 / n)
    m[0] /= np.sqrt(2.0)
    return m


_D = _dct_matrix(POOL)


def _zigzag(n: int) -> list[tuple[int, int]]:
    order = sorted(
        ((r, c) for r in range(n) for c in range(n)),
        key=lambda rc: (rc[0] + rc[1], rc[0] if (rc[0] + rc[1]) % 2 else rc[1]),
    )
    return order


_ZZ = np.array(_zigzag(POOL))


def check_spec(feature: dict) -> dict:
    """The feature parameters of a manifest, if this verifier supports them (else ValueError)."""
    for spec in SUPPORTED:
        if feature == spec:
            return spec
    raise ValueError(f"unsupported feature params {feature}")


def vector_length(spec: dict) -> int:
    return spec["n"] + 2 * spec.get("chroma", 0)


def _weights(spec: dict) -> np.ndarray:
    luma = [DC_WEIGHT] + [1.0] * (min(spec["n"], _DETAIL_FROM) - 1) + [DETAIL_WEIGHT] * max(spec["n"] - _DETAIL_FROM, 0)
    chroma = [CHROMA_WEIGHT] * (2 * spec.get("chroma", 0))
    return np.array(luma + chroma, dtype=np.float32)


def _pooled(channel: np.ndarray, grid: Grid) -> np.ndarray:
    """Each tile's real pixels (no padding) area-averaged into POOL x POOL cells, (n, POOL, POOL).
    Uses a summed-area table so tiles of any size (merged edge tiles) are handled exactly."""
    sat = np.zeros((channel.shape[0] + 1, channel.shape[1] + 1))
    sat[1:, 1:] = channel.cumsum(0).cumsum(1)
    b = np.array([grid.bounds(i) for i in range(grid.count)])  # (n, 4): x0 y0 x1 y1
    k = np.arange(POOL + 1) / POOL
    xe = np.rint(b[:, 0:1] + k * (b[:, 2:3] - b[:, 0:1])).astype(int)  # (n, POOL+1)
    ye = np.rint(b[:, 1:2] + k * (b[:, 3:4] - b[:, 1:2])).astype(int)
    xe[:, 1:] = np.maximum(xe[:, 1:], xe[:, :-1] + 1)  # >= 1 px per cell (tiny tiles)
    ye[:, 1:] = np.maximum(ye[:, 1:], ye[:, :-1] + 1)
    xe, ye = np.minimum(xe, channel.shape[1]), np.minimum(ye, channel.shape[0])
    s = sat[ye[:, :, None], xe[:, None, :]]  # (n, POOL+1, POOL+1)
    box = s[:, 1:, 1:] - s[:, :-1, 1:] - s[:, 1:, :-1] + s[:, :-1, :-1]
    area = np.maximum(np.diff(ye)[:, :, None] * np.diff(xe)[:, None, :], 1)
    return box / area


def _coeffs(channel: np.ndarray, grid: Grid, n: int) -> np.ndarray:
    c = _D @ _pooled(channel, grid) @ _D.T
    zz = _ZZ[:n]
    return c[:, zz[:, 0], zz[:, 1]]


def raw_features(rgb: np.ndarray, grid: Grid, spec: dict = SPEC) -> np.ndarray:
    """Unquantized feature vectors, shape (count, vector_length(spec)), in units of STEP."""
    a = rgb.astype(np.float64)
    parts = [_coeffs(a @ _LUMA, grid, spec["n"])]
    if spec.get("chroma"):
        parts += [_coeffs(a @ _CB + 128, grid, spec["chroma"]), _coeffs(a @ _CR + 128, grid, spec["chroma"])]
    return np.concatenate(parts, axis=1) / spec["step"]


def quantized_features(rgb: np.ndarray, grid: Grid, spec: dict = SPEC) -> np.ndarray:
    """Committed feature vectors (int16)."""
    return np.rint(raw_features(rgb, grid, spec)).astype(np.int16)


def feature_bytes(vec: np.ndarray) -> bytes:
    return np.asarray(vec, dtype=">i2").tobytes()


def tile_distance(received_raw: np.ndarray, committed: np.ndarray, spec: dict = SPEC) -> np.ndarray:
    """Per-tile weighted L-infinity distance (in quantization steps): DC down-weighted, fine
    luminance detail up-weighted."""
    d = np.abs(received_raw - committed.astype(np.float32)) * _weights(spec)
    return d.max(axis=1)


def is_textured(committed: np.ndarray, spec: dict = SPEC) -> bool:
    """A tile with visible luminance structure (any AC coefficient of at least one step). Flat
    tiles (sky, blown-out areas) can survive a JPEG byte for byte; textured ones cannot."""
    return bool(np.abs(np.asarray(committed)[1 : spec["n"]]).max(initial=0) >= 1)
