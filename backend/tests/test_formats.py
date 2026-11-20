"""Image formats a professional photographer may submit (load_rgb is the single entry point)."""

import numpy as np
import pytest
from PIL import Image

from tileproof.tiling import load_rgb

GRADIENT16 = np.linspace(0, 65535, 64 * 64).reshape(64, 64).astype(np.uint16)


@pytest.mark.parametrize("ext", ["png", "tiff"])
def test_16_bit_grayscale_is_scaled_not_clipped(tmp_path, ext):
    path = tmp_path / f"gray16.{ext}"
    Image.fromarray(GRADIENT16).save(path)
    rgb = load_rgb(path)
    assert rgb.shape == (64, 64, 3) and rgb.dtype == np.uint8
    expected = np.rint(GRADIENT16 / 257).astype(np.uint8)
    assert np.abs(rgb[..., 0].astype(int) - expected).max() <= 1
    assert (rgb[..., 0] == 255).mean() < 0.01  # was 99.6 % white before the fix


def test_float_image_in_0_1_range_is_scaled(tmp_path):
    f = (GRADIENT16 / 65535).astype(np.float32)
    rgb = load_rgb(Image.fromarray(f, "F"))
    assert abs(int(rgb[32, 32, 0]) - int(round(f[32, 32] * 255))) <= 1


def _write_rgb48_tiff(path, px):
    """Minimal uncompressed 48-bit RGB TIFF, as Lightroom/Capture One export in 16-bit."""
    import struct

    h, w, _ = px.shape
    data = px.astype("<u2").tobytes()
    entries = [(256, 3, 1, w), (257, 3, 1, h), (258, 3, 3, None), (259, 3, 1, 1), (262, 3, 1, 2),
               (273, 4, 1, None), (277, 3, 1, 3), (278, 3, 1, h), (279, 4, 1, len(data)), (284, 3, 1, 1)]
    bps_off = 8 + 2 + len(entries) * 12 + 4
    data_off = bps_off + 6
    out = bytearray(b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", len(entries)))
    for tag, typ, cnt, val in entries:
        val = {258: bps_off, 273: data_off}.get(tag, val)
        packed = struct.pack("<HH", val, 0) if typ == 3 and cnt == 1 else struct.pack("<I", val)
        out += struct.pack("<HHI", tag, typ, cnt) + packed
    out += struct.pack("<I", 0) + struct.pack("<HHH", 16, 16, 16) + data
    path.write_bytes(bytes(out))


def test_48_bit_rgb_tiff_is_scaled(tmp_path):
    px = np.linspace(0, 65535, 32 * 48 * 3).reshape(32, 48, 3).astype(np.uint16)
    _write_rgb48_tiff(tmp_path / "rgb16.tiff", px)
    rgb = load_rgb(tmp_path / "rgb16.tiff")
    assert np.abs(rgb.astype(int) - np.rint(px / 257)).max() <= 1
