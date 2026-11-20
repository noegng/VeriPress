"""64-bit perceptual hash of a whole image (lookup only, never authentication). OWNER: Dev A.

Grayscale -> 32x32 -> 2D DCT -> top-left 8x8 low frequencies -> bit = coeff > median.
Survives recompression, rescaling and metadata stripping; used to find the store entry
of an image shared without its id (and as fallback when the watermark is unreadable).
"""

from __future__ import annotations

import numpy as np
from PIL import Image

from .features import _dct_matrix

_D32 = _dct_matrix(32)


def phash(rgb: np.ndarray) -> int:
    gray = Image.fromarray(rgb).convert("L").resize((32, 32), Image.Resampling.LANCZOS)
    coeffs = _D32 @ np.asarray(gray, dtype=np.float64) @ _D32.T
    low = coeffs[:8, :8].flatten()
    bits = low > np.median(low[1:])  # median without DC, which dominates
    return int("".join("1" if b else "0" for b in bits), 2)
