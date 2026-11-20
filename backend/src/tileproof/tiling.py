"""Image loading and tiling."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps

DEFAULT_TILE = 32  # floor
TILES_ACROSS = 40  # calibrated on real 4K photos shared at 1280-1600 px: a tile must keep ~40 px


def auto_tile(width: int, height: int) -> int:
    """Tile size ~ long side / 40, multiple of 8, at least DEFAULT_TILE."""
    return max(DEFAULT_TILE, 8 * round(max(width, height) / TILES_ACROSS / 8))


def load_rgb(source: str | Path | Image.Image) -> np.ndarray:
    """Load an image as an HxWx3 uint8 array, applying EXIF orientation."""
    img = source if isinstance(source, Image.Image) else Image.open(source)
    img = ImageOps.exif_transpose(img)
    return np.asarray(img.convert("RGB"), dtype=np.uint8)


def resize_to(rgb: np.ndarray, width: int, height: int) -> np.ndarray:
    """Bring a received image back to the committed size (e.g. after a platform downscale)."""
    if rgb.shape[1] == width and rgb.shape[0] == height:
        return rgb
    return np.asarray(Image.fromarray(rgb).resize((width, height), Image.Resampling.LANCZOS))


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
