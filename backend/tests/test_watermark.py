import numpy as np
from conftest import jpeg, photo_like, rescale

from veripress.watermark import embed, extract

WM = bytes.fromhex("0123456789abcdef")


def test_watermark_survives_whatsapp_like_sharing(photo):
    marked = embed(photo, WM)
    assert marked.shape == photo.shape
    assert extract(jpeg(rescale(marked, 0.5), 60)) == WM


def test_watermark_is_invisible_enough(photo):
    marked = embed(photo, WM).astype(float)
    psnr = 10 * np.log10(255**2 / np.mean((marked - photo) ** 2))
    assert psnr > 38


def test_clean_image_has_no_watermark():
    assert extract(photo_like(seed=9)) is None
