"""Invisible watermark carrying a 64-bit lookup id (Adobe TrustMark). OWNER: Dev A.

The id is random, chosen at signing time and committed in the manifest (`wm_id`), so the
image is watermarked BEFORE its tiles are committed: the anchored roots cover the
watermarked pixels. The watermark is only a lookup pointer; authentication still comes
from the anchored signature + Merkle roots, which also catch a watermark copied onto
another image.

Payload: 4-bit version + 64-bit id = 68 bits = TrustMark BCH_4 capacity.
Models are downloaded on first use (call `warm_up()` before a demo).
"""

from __future__ import annotations

import os
from functools import lru_cache

import numpy as np
from PIL import Image

_VERSION_BITS = "0001"


def enabled() -> bool:
    return os.environ.get("VERIPRESS_WATERMARK", "1") != "0"


@lru_cache(maxsize=1)
def _tm():
    from trustmark import TrustMark  # heavy import (torch), keep lazy

    return TrustMark(verbose=False, model_type="Q", encoding_type=TrustMark.Encoding.BCH_4)


def warm_up() -> None:
    _tm()


def embed(rgb: np.ndarray, wm_id: bytes) -> np.ndarray:
    if len(wm_id) != 8:
        raise ValueError("wm_id must be 8 bytes")
    bits = _VERSION_BITS + format(int.from_bytes(wm_id, "big"), "064b")
    out = _tm().encode(Image.fromarray(rgb), bits, MODE="binary")
    return np.asarray(out.convert("RGB"), dtype=np.uint8)


def extract(rgb: np.ndarray) -> bytes | None:
    bits, present, _ = _tm().decode(Image.fromarray(rgb), MODE="binary")
    if not present or len(bits) != 68 or not bits.startswith(_VERSION_BITS):
        return None
    return int(bits[4:], 2).to_bytes(8, "big")
