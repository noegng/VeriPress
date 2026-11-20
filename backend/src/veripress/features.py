"""Robust per-tile features: survive JPEG recompression / mild rescaling,
change when the tile's content is edited.

Per tile: luminance -> average-pool to 8x8 -> orthonormal 2D DCT-II ->
first N coefficients in zigzag order (DC included) -> divide by STEP and round.

The quantized vector is committed in the robust Merkle tree. A verifier does
NOT compare hashes (quantization boundaries would make benign recompression
flip a leaf); it compares the received tile's feature vector with the
committed one using a distance tolerance. The Merkle root only authenticates
the committed reference vectors.
"""

from __future__ import annotations

import numpy as np

from .tiling import Grid

POOL = 8
N_COEFFS = 10
STEP = 4.0
TOLERANCE = 4.5  # max |delta| (in STEPs) for a tile to count as unchanged.
# Calibrated 20/11 on 6 real 3-5k camera photos (Wikimedia Commons) shared WhatsApp-like
# (1600 px q72 and 1280 px q55) with tiles = long side / 40: benign max 2.96, copy-move
# forgeries of 2 tiles detected 100%, of half a tile 78%. Then on 4 iPhone HEIC photos
# (Display P3) really sent through WhatsApp: needs ICC->sRGB + unclipped resampling + DC_WEIGHT,
# after which benign max = 2.01. `veripress.cli calibrate` re-runs it.


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


_ZZ = np.array(_zigzag(POOL)[:N_COEFFS])


def _pooled(rgb: np.ndarray, grid: Grid) -> np.ndarray:
    """Each tile's real pixels (no padding) area-averaged into POOL x POOL cells, (n, POOL, POOL).
    Uses a summed-area table so tiles of any size (merged edge tiles) are handled exactly."""
    luma = rgb.astype(np.float64) @ np.array([0.299, 0.587, 0.114])
    sat = np.zeros((luma.shape[0] + 1, luma.shape[1] + 1))
    sat[1:, 1:] = luma.cumsum(0).cumsum(1)
    b = np.array([grid.bounds(i) for i in range(grid.count)])  # (n, 4): x0 y0 x1 y1
    k = np.arange(POOL + 1) / POOL
    xe = np.rint(b[:, 0:1] + k * (b[:, 2:3] - b[:, 0:1])).astype(int)  # (n, POOL+1)
    ye = np.rint(b[:, 1:2] + k * (b[:, 3:4] - b[:, 1:2])).astype(int)
    xe[:, 1:] = np.maximum(xe[:, 1:], xe[:, :-1] + 1)  # >= 1 px per cell (tiny tiles)
    ye[:, 1:] = np.maximum(ye[:, 1:], ye[:, :-1] + 1)
    xe, ye = np.minimum(xe, luma.shape[1]), np.minimum(ye, luma.shape[0])
    s = sat[ye[:, :, None], xe[:, None, :]]  # (n, POOL+1, POOL+1)
    box = s[:, 1:, 1:] - s[:, :-1, 1:] - s[:, 1:, :-1] + s[:, :-1, :-1]
    area = np.maximum(np.diff(ye)[:, :, None] * np.diff(xe)[:, None, :], 1)
    return box / area


def raw_features(rgb: np.ndarray, grid: Grid) -> np.ndarray:
    """Unquantized feature vectors, shape (count, N_COEFFS), in units of STEP."""
    pooled = _pooled(rgb, grid)
    coeffs = _D @ pooled @ _D.T
    return coeffs[:, _ZZ[:, 0], _ZZ[:, 1]] / STEP


def quantized_features(rgb: np.ndarray, grid: Grid) -> np.ndarray:
    """Committed feature vectors (int16)."""
    return np.rint(raw_features(rgb, grid)).astype(np.int16)


def feature_bytes(vec: np.ndarray) -> bytes:
    return np.asarray(vec, dtype=">i2").tobytes()


DC_WEIGHT = 0.5  # mean brightness drifts more than structure under resampling/clipping


def tile_distance(received_raw: np.ndarray, committed: np.ndarray) -> np.ndarray:
    """Per-tile weighted L-infinity distance (in quantization steps), DC down-weighted."""
    d = np.abs(received_raw - committed.astype(np.float32))
    d[:, 0] *= DC_WEIGHT
    return d.max(axis=1)
