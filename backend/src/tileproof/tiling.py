"""Image loading and tiling."""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image, ImageCms, ImageOps

try:  # iPhone photos are HEIC by default
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:  # pragma: no cover
    pass

DEFAULT_TILE = 32  # floor
TILES_ACROSS = 40  # calibrated on real 4K photos shared at 1280-1600 px: a tile must keep ~40 px


def auto_tile(width: int, height: int) -> int:
    """Tile size ~ long side / 40, multiple of 8, at least DEFAULT_TILE."""
    return max(DEFAULT_TILE, 8 * round(max(width, height) / TILES_ACROSS / 8))


_SRGB = ImageCms.createProfile("sRGB")


def _to_8bit(img: Image.Image) -> Image.Image:
    """High bit depth single-channel modes (16-bit TIFF/PNG exports, float) scaled to 8 bits.
    Pillow's own convert() clips them at 255 instead of scaling."""
    if img.mode.startswith("I;16") or img.mode == "I":
        a = np.asarray(img).astype(np.float64)
        scale = 257.0 if a.max() > 255 else 1.0  # "I" may also hold plain 8-bit values
        return Image.fromarray(np.clip(np.rint(a / scale), 0, 255).astype(np.uint8), "L")
    if img.mode == "F":
        a = np.asarray(img).astype(np.float64)
        a = a * 255.0 if a.max() <= 1.0 else a  # normalised [0, 1] or already 0-255
        return Image.fromarray(np.clip(np.rint(a), 0, 255).astype(np.uint8), "L")
    return img


RAW_EXTENSIONS = {".cr2", ".cr3", ".nef", ".nrw", ".arw", ".srf", ".sr2", ".raf", ".rw2", ".orf", ".pef", ".dng", ".3fr", ".iiq", ".x3f"}


def _load_raw(source: Path | bytes) -> np.ndarray:
    """Develop a camera RAW deterministically (LibRaw): camera white balance, sRGB, 8 bits,
    orientation applied. DNG goes here too: Pillow would only read its embedded preview."""
    import rawpy

    with rawpy.imread(io.BytesIO(source) if isinstance(source, bytes) else str(source)) as raw:
        return raw.postprocess(use_camera_wb=True, output_bps=8, output_color=rawpy.ColorSpace.sRGB).copy()


def load_upload(data: bytes, filename: str | None = None) -> np.ndarray:
    """Load uploaded bytes (API entry point). Many RAW formats are TIFF containers that Pillow
    would open as their small embedded preview, so RAW is tried first unless the name says
    it is a regular image. Raises ValueError if nothing can read it."""
    suffix = Path(filename).suffix.lower() if filename else ""
    if suffix in RAW_EXTENSIONS or suffix not in Image.registered_extensions():
        try:
            return _load_raw(data)
        except Exception:  # not a RAW (rawpy raises LibRawFileUnsupportedError & co)
            pass
    try:
        return load_rgb(Image.open(io.BytesIO(data)))
    except Exception as e:
        raise ValueError(f"unreadable image ({filename or 'upload'}): {e}") from e


def load_rgb(source: str | Path | Image.Image) -> np.ndarray:
    """Load an image as an HxWx3 uint8 sRGB array, applying EXIF orientation and the ICC profile.

    iPhone photos are Display P3 while shared copies (WhatsApp...) are untagged sRGB: reading
    both as raw numbers shifts every tile (real-photo calibration finding)."""
    if not isinstance(source, Image.Image) and Path(source).suffix.lower() in RAW_EXTENSIONS:
        return _load_raw(Path(source))
    img = source if isinstance(source, Image.Image) else Image.open(source)
    icc = img.info.get("icc_profile")
    img = _to_8bit(ImageOps.exif_transpose(img)).convert("RGB")
    if icc:
        try:
            src = ImageCms.ImageCmsProfile(io.BytesIO(icc))
            if "srgb" not in ImageCms.getProfileDescription(src).lower():
                img = ImageCms.profileToProfile(img, src, _SRGB, outputMode="RGB")
        except (ImageCms.PyCMSError, OSError):
            pass  # unreadable profile: keep the raw values
    return np.asarray(img, dtype=np.uint8)


def resize_to(rgb: np.ndarray, width: int, height: int) -> np.ndarray:
    """Bring a received image back to the committed size (e.g. after a platform downscale)."""
    if rgb.shape[1] == width and rgb.shape[0] == height:
        return rgb
    # Resample in float, per channel: Lanczos ringing must not be clipped at 0/255, clipping
    # shifts the mean of tiles with thin dark lines on a bright background. Returns float32.
    chans = [
        np.asarray(Image.fromarray(rgb[..., c].astype(np.float32), "F").resize((width, height), Image.Resampling.LANCZOS))
        for c in range(3)
    ]
    return np.stack(chans, axis=-1)


@dataclass(frozen=True)
class Grid:
    width: int
    height: int
    tile: int

    # A remainder thinner than a quarter tile is merged into the last tile: slivers of a few
    # pixels are dominated by resampling artefacts at the image border (calibration finding).

    @staticmethod
    def _count(size: int, tile: int) -> int:
        n, rem = -(-size // tile), size % tile
        return n - 1 if n > 1 and 0 < rem < tile / 4 else n

    @property
    def cols(self) -> int:
        return self._count(self.width, self.tile)

    @property
    def rows(self) -> int:
        return self._count(self.height, self.tile)

    @property
    def count(self) -> int:
        return self.rows * self.cols

    def position(self, index: int) -> tuple[int, int]:
        """(row, col) of a tile index (row-major)."""
        return divmod(index, self.cols)

    def bounds(self, index: int) -> tuple[int, int, int, int]:
        """(x0, y0, x1, y1) pixel box of a tile; the last row/column runs to the image edge."""
        r, c = self.position(index)
        x0, y0 = c * self.tile, r * self.tile
        x1 = self.width if c == self.cols - 1 else x0 + self.tile
        y1 = self.height if r == self.rows - 1 else y0 + self.tile
        return x0, y0, x1, y1

    def tiles_in_box(self, x0: int, y0: int, x1: int, y1: int) -> list[int]:
        """Indices of all tiles intersecting a pixel box."""
        c0, r0 = max(x0, 0) // self.tile, max(y0, 0) // self.tile
        c1 = min((min(x1, self.width) - 1) // self.tile, self.cols - 1)
        r1 = min((min(y1, self.height) - 1) // self.tile, self.rows - 1)
        c0, r0 = min(c0, self.cols - 1), min(r0, self.rows - 1)
        return [r * self.cols + c for r in range(r0, r1 + 1) for c in range(c0, c1 + 1)]


def grid_for(rgb: np.ndarray, tile: int = DEFAULT_TILE) -> Grid:
    return Grid(width=rgb.shape[1], height=rgb.shape[0], tile=tile)


def tile_pixels(rgb: np.ndarray, grid: Grid, index: int) -> np.ndarray:
    """Raw (unpadded) pixels of a tile."""
    x0, y0, x1, y1 = grid.bounds(index)
    return rgb[y0:y1, x0:x1]


def padded_tiles(rgb: np.ndarray, grid: Grid) -> np.ndarray:
    """All tiles as an array (count, tile, tile, 3), edge tiles padded by edge replication."""
    t = grid.tile
    ph, pw = grid.rows * t - grid.height, grid.cols * t - grid.width
    padded = np.pad(rgb, ((0, ph), (0, pw), (0, 0)), mode="edge")
    return (
        padded.reshape(grid.rows, t, grid.cols, t, 3)
        .swapaxes(1, 2)
        .reshape(grid.count, t, t, 3)
    )
