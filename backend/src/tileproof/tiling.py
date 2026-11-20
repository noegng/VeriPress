"""Image loading and tiling."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps

DEFAULT_TILE = 32


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

    @property
    def cols(self) -> int:
        return -(-self.width // self.tile)

    @property
    def rows(self) -> int:
        return -(-self.height // self.tile)

    @property
    def count(self) -> int:
        return self.rows * self.cols

    def position(self, index: int) -> tuple[int, int]:
        """(row, col) of a tile index (row-major)."""
        return divmod(index, self.cols)

    def bounds(self, index: int) -> tuple[int, int, int, int]:
        """(x0, y0, x1, y1) pixel box of a tile, clipped to the image."""
        r, c = self.position(index)
        x0, y0 = c * self.tile, r * self.tile
        return x0, y0, min(x0 + self.tile, self.width), min(y0 + self.tile, self.height)

    def tiles_in_box(self, x0: int, y0: int, x1: int, y1: int) -> list[int]:
        """Indices of all tiles intersecting a pixel box."""
        c0, r0 = max(x0, 0) // self.tile, max(y0, 0) // self.tile
        c1, r1 = (min(x1, self.width) - 1) // self.tile, (min(y1, self.height) - 1) // self.tile
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
