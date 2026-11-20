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

from .tiling import Grid, padded_tiles

POOL = 8
N_COEFFS = 10
STEP = 4.0
TOLERANCE = 4.5  # max |delta| (in STEPs) for a tile to count as unchanged.
# Calibrated on synthetic photos: benign JPEG q50-90 + 0.5x rescale stay <= 3.8,
# content edits on a fully covered tile mostly score 5-150. Re-tune on real photos.


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


def raw_features(rgb: np.ndarray, grid: Grid) -> np.ndarray:
    """Unquantized feature vectors, shape (count, N_COEFFS), in units of STEP."""
    tiles = padded_tiles(rgb, grid).astype(np.float32)
    luma = tiles @ np.array([0.299, 0.587, 0.114], dtype=np.float32)  # (n, t, t)
    f = grid.tile // POOL
    pooled = luma.reshape(-1, POOL, f, POOL, f).mean(axis=(2, 4))  # (n, 8, 8)
    coeffs = _D @ pooled @ _D.T
    return coeffs[:, _ZZ[:, 0], _ZZ[:, 1]] / STEP


def quantized_features(rgb: np.ndarray, grid: Grid) -> np.ndarray:
    """Committed feature vectors (int16)."""
    return np.rint(raw_features(rgb, grid)).astype(np.int16)


def feature_bytes(vec: np.ndarray) -> bytes:
    return np.asarray(vec, dtype=">i2").tobytes()


def tile_distance(received_raw: np.ndarray, committed: np.ndarray) -> np.ndarray:
    """Per-tile L-infinity distance (in quantization steps)."""
    return np.abs(received_raw - committed.astype(np.float32)).max(axis=1)
