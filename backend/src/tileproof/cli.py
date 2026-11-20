"""tileproof CLI.

  tileproof commit IMAGE -o OUT_DIR            -> OUT_DIR/{manifest,disclosure}.json + seed.bin (secret)
  tileproof verify IMAGE MANIFEST DISCLOSURE [--heatmap out.png]
  tileproof redact IMAGE MANIFEST DISCLOSURE --box x0,y0,x1,y1 [--box ...] -o OUT_DIR
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PIL import Image

from .commitment import Disclosure, Manifest, commit, heatmap, redact, verify
from .tiling import DEFAULT_TILE, load_rgb


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, separators=(",", ":")))


def _read(manifest: str, disclosure: str) -> tuple[Manifest, Disclosure]:
    return (
        Manifest.from_dict(json.loads(Path(manifest).read_text())),
        Disclosure.from_dict(json.loads(Path(disclosure).read_text())),
    )


def cmd_commit(a: argparse.Namespace) -> int:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    seed = os.urandom(32)
    (out / "seed.bin").write_bytes(seed)
    manifest, disclosure = commit(load_rgb(a.image), seed, a.tile)
    _write_json(out / "manifest.json", manifest.__dict__)
    _write_json(out / "disclosure.json", disclosure.to_dict())
    print(f"tiles        {manifest.grid.count} ({manifest.grid.cols}x{manifest.grid.rows} of {a.tile}px)")
    print(f"exact_root   {manifest.exact_root}")
    print(f"robust_root  {manifest.robust_root}")
    print(f"manifest     {manifest.digest()}  <- sign & anchor this")
    print(f"written to   {out}/  (keep seed.bin secret)")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    manifest, disclosure = _read(a.manifest, a.disclosure)
    rgb = load_rgb(a.image)
    res = verify(rgb, manifest, disclosure)
    print(f"manifest   {manifest.digest()}")
    print(f"verdict    {res.verdict.value}")
    print(f"roots ok   exact={res.exact_root_ok} robust={res.robust_root_ok}")
    if res.statuses:
        print("tiles     ", " ".join(f"{k}={v}" for k, v in res.counts().items()))
        if a.heatmap:
            heatmap(rgb, manifest, res).save(a.heatmap)
            print(f"heatmap    {a.heatmap}")
    return 0 if res.verdict.value in ("intact", "recompressed") else 1


def cmd_redact(a: argparse.Namespace) -> int:
    manifest, disclosure = _read(a.manifest, a.disclosure)
    rgb = load_rgb(a.image)
    tiles: set[int] = set()
    for box in a.box:
        x0, y0, x1, y1 = (int(v) for v in box.split(","))
        tiles |= set(manifest.grid.tiles_in_box(x0, y0, x1, y1))
    out_img, out_disc = redact(rgb, manifest, disclosure, tiles)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    Image.fromarray(out_img).save(out / "redacted.png")
    _write_json(out / "disclosure.json", out_disc.to_dict())
    print(f"redacted {len(tiles)} tiles -> {out}/redacted.png + disclosure.json")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tileproof")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("commit", help="build tile Merkle trees for an image")
    c.add_argument("image")
    c.add_argument("-o", "--out", required=True)
    c.add_argument("--tile", type=int, default=DEFAULT_TILE)
    c.set_defaults(fn=cmd_commit)

    v = sub.add_parser("verify", help="verify an image against a manifest + disclosure")
    v.add_argument("image")
    v.add_argument("manifest")
    v.add_argument("disclosure")
    v.add_argument("--heatmap")
    v.set_defaults(fn=cmd_verify)

    r = sub.add_parser("redact", help="black out regions while keeping the rest verifiable")
    r.add_argument("image")
    r.add_argument("manifest")
    r.add_argument("disclosure")
    r.add_argument("--box", action="append", required=True, help="x0,y0,x1,y1 (repeatable)")
    r.add_argument("-o", "--out", required=True)
    r.set_defaults(fn=cmd_redact)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
