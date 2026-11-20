"""tileproof CLI.

  tileproof commit IMAGE -o OUT_DIR            -> OUT_DIR/{manifest,disclosure}.json + seed.bin (secret)
  tileproof verify IMAGE MANIFEST DISCLOSURE [--heatmap out.png]
  tileproof redact IMAGE MANIFEST DISCLOSURE --box x0,y0,x1,y1 [--box ...] -o OUT_DIR
  tileproof demo IMAGE [--ai AI_IMAGE] -o OUT_DIR -> the demo scenarios offline (FakeLedger), incl. anonymous signing
  tileproof calibrate ORIG_DIR SHARED_DIR -o OUT.json
                                               -> robust-tile / phash margins on real shared copies
                                                  (same file stem in both dirs, e.g. IMG_1.jpg / IMG_1.jpeg)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from PIL import Image

from .commitment import Disclosure, Manifest, commit, heatmap, redact, verify
from .tiling import load_rgb


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
    print(f"tiles        {manifest.grid.count} ({manifest.grid.cols}x{manifest.grid.rows} of {manifest.tile}px)")
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


def _jpeg(rgb, quality: int, scale: float = 1.0):
    import io

    import numpy as np

    img = Image.fromarray(rgb)
    if scale != 1.0:
        img = img.resize((int(img.width * scale), int(img.height * scale)), Image.Resampling.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=quality)
    return np.asarray(Image.open(buf).convert("RGB"))


def cmd_demo(a: argparse.Namespace) -> int:
    """Play the pitch scenarios end to end with an in-memory ledger (backup demo)."""
    import io

    import numpy as np
    from xrpl.constants import CryptoAlgorithm
    from xrpl.wallet import Wallet

    from .ledger import CredentialType, FakeLedger
    from .pipeline import redact_image, sign_image, verify_image
    from .signing import load_key
    from .store import Store
    from .watermark import embed

    out = Path(a.out)
    keys = out / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for name in ("device", "ai"):
        if not (keys / f"{name}.json").exists():
            w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
            _write_json(keys / f"{name}.json", {"public_key": w.public_key, "private_key": w.private_key})
    os.environ["TILEPROOF_KEYS"] = str(keys)
    ledger, store = FakeLedger(), Store(out / "store")
    ledger.issue(load_key("device").public_key, CredentialType.CAPTURE_DEVICE)
    ledger.issue(load_key("ai").public_key, CredentialType.AI_GENERATOR)
    # Anonymous registry (ZK A): the device + 20 fictitious members, root "published" at t=0.
    from . import zk

    dev = json.loads((keys / "device.json").read_text())
    if "bjj" not in dev:
        dev["bjj"] = zk.keygen()
        _write_json(keys / "device.json", dev)
    reg = keys / "registry_devices.json"
    if not reg.exists():
        pks = [zk.keygen()["pk"] for _ in range(20)]
        pks.insert(7, dev["bjj"]["pk"])
        _write_json(reg, {"pks": pks})
    ledger.publish_registry_root(zk.root(json.loads(reg.read_text())["pks"]), at=0)

    def rgb_of(png: bytes):
        return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))

    summary: dict[str, dict] = {}

    def check(name: str, rgb) -> None:
        Image.fromarray(rgb).save(out / f"{name}.png")
        report, hm = verify_image(rgb, ledger, store)
        if hm:
            (out / f"{name}.heatmap.png").write_bytes(hm)
        j = report.to_json()
        summary[name] = {k: j[k] for k in ("verdict", "reason", "found_by", "credential", "anonymous")}
        summary[name]["tiles"] = j["tiles"]["counts"] if j["tiles"] else None
        print(f"{name:20} {j['verdict']:8} via {str(j['found_by']):9} {j['reason']}")

    src = load_rgb(a.image)
    h, w = src.shape[:2]
    original, png = sign_image(src, "device", ledger, store)
    signed = rgb_of(png)
    check("1_capture", signed)

    edited = signed.copy()
    edited[h * 3 // 8 : h * 5 // 8, w * 3 // 8 : w * 5 // 8] = (255, 0, 255)
    check("2_edited", _jpeg(edited, 90))

    check("3_whatsapp", _jpeg(signed, 60, scale=min(1.0, 1600 / max(h, w), 0.5)))

    _, red_png = redact_image(signed, original.entry_id, [(w // 8, h // 8, w * 3 // 8, h * 3 // 8)], store)
    check("4_redacted", rgb_of(red_png))

    wm_id = bytes.fromhex(original.manifest.wm_id)
    check("5_copied_watermark", _jpeg(embed(np.ascontiguousarray(np.rot90(src, 2)), wm_id), 85))

    ai_src = load_rgb(a.ai) if a.ai else np.ascontiguousarray(src[:, ::-1])
    _, ai_png = sign_image(ai_src, "ai", ledger, store)
    check("6_ai", rgb_of(ai_png))

    anon_src = np.ascontiguousarray(src[::-1])  # another picture, signed without revealing the device
    _, anon_png = sign_image(anon_src, "device", ledger, store, anonymous=True)
    check("7_anonymous", rgb_of(anon_png))

    _write_json(out / "summary.json", summary)
    print(f"written to {out}/")
    return 0


def cmd_calibrate(a: argparse.Namespace) -> int:
    from . import features as F
    from .commitment import TileStatus
    from .perceptual import phash

    def images(d: str) -> list[Path]:
        return sorted(p for p in Path(d).iterdir() if p.is_file() and not p.name.startswith("."))

    shared = {p.stem: p for p in images(a.shared)}
    pairs: dict[str, dict] = {}
    missing: list[str] = []
    for orig in images(a.originals):
        if orig.stem not in shared:
            missing.append(orig.stem)
            continue
        src, recv = load_rgb(orig), load_rgb(shared[orig.stem])
        manifest, disclosure = commit(src, os.urandom(32))
        res = verify(recv, manifest, disclosure)
        pairs[orig.stem] = {
            "size": [src.shape[1], src.shape[0]],
            "received_size": [recv.shape[1], recv.shape[0]],
            "changed_tiles": sum(s == TileStatus.CHANGED for s in res.statuses),
            "tiles": len(res.statuses),
            "max_tile_distance": round(max(res.distances), 2),
            "p99_tile_distance": round(sorted(res.distances)[int(0.99 * (len(res.distances) - 1))], 2),
            "phash_distance": (phash(src) ^ phash(recv)).bit_count(),
        }
        print(f"{orig.stem:20} changed={pairs[orig.stem]['changed_tiles']:5} "
              f"max={pairs[orig.stem]['max_tile_distance']:6} phash={pairs[orig.stem]['phash_distance']}")
    report = {
        "tolerance": F.TOLERANCE,
        "pairs": pairs,
        "missing": missing,
        "all_pass": bool(pairs) and all(p["changed_tiles"] == 0 and p["phash_distance"] <= 10 for p in pairs.values()),
    }
    _write_json(Path(a.out), report)
    if missing:
        print(f"no shared copy for: {', '.join(missing)}")
    print(f"all_pass={report['all_pass']} (tolerance {F.TOLERANCE}) -> {a.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tileproof")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("commit", help="build tile Merkle trees for an image")
    c.add_argument("image")
    c.add_argument("-o", "--out", required=True)
    c.add_argument("--tile", type=int, default=None, help="default: ~long side / 40")
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

    dm = sub.add_parser("demo", help="play the six demo scenarios offline")
    dm.add_argument("image")
    dm.add_argument("--ai", help="AI-generated image for scenario 6 (default: mirrored photo)")
    dm.add_argument("-o", "--out", required=True)
    dm.set_defaults(fn=cmd_demo)

    cb = sub.add_parser("calibrate", help="measure tile/phash margins on real shared copies")
    cb.add_argument("originals")
    cb.add_argument("shared")
    cb.add_argument("-o", "--out", required=True)
    cb.set_defaults(fn=cmd_calibrate)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
