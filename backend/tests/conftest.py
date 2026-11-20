import io

import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFilter


def photo_like(w: int = 640, h: int = 480, seed: int = 0) -> np.ndarray:
    """Synthetic 'photo': gradients, blurred shapes, sharp edges, sensor noise."""
    rng = np.random.default_rng(seed)
    yy, xx = np.mgrid[0:h, 0:w]
    base = np.stack(
        [120 + 80 * np.sin(xx / 90), 100 + 60 * np.cos(yy / 70), 140 + 50 * np.sin((xx + yy) / 120)],
        axis=-1,
    )
    img = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))
    d = ImageDraw.Draw(img)
    for _ in range(40):
        x, y = rng.integers(0, w), rng.integers(0, h)
        r = int(rng.integers(10, 80))
        color = tuple(int(c) for c in rng.integers(0, 256, 3))
        (d.ellipse if rng.random() < 0.5 else d.rectangle)((x - r, y - r, x + r, y + r), fill=color)
    img = img.filter(ImageFilter.GaussianBlur(1.2))
    d = ImageDraw.Draw(img)
    for _ in range(15):  # sharp details
        x, y = rng.integers(0, w), rng.integers(0, h)
        d.line((x, y, x + rng.integers(-60, 60), y + rng.integers(-60, 60)), fill=(20, 20, 20), width=2)
    arr = np.asarray(img).astype(np.int16) + rng.normal(0, 3, (h, w, 3)).astype(np.int16)
    return np.clip(arr, 0, 255).astype(np.uint8)


def jpeg(rgb: np.ndarray, quality: int) -> np.ndarray:
    buf = io.BytesIO()
    Image.fromarray(rgb).save(buf, "JPEG", quality=quality)
    return np.asarray(Image.open(buf).convert("RGB"))


def rescale(rgb: np.ndarray, factor: float) -> np.ndarray:
    h, w = rgb.shape[:2]
    return np.asarray(
        Image.fromarray(rgb).resize((int(w * factor), int(h * factor)), Image.Resampling.BILINEAR)
    )


@pytest.fixture
def photo() -> np.ndarray:
    return photo_like()
