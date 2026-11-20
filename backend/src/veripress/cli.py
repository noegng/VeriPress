"""veripress CLI.

  veripress commit IMAGE -o OUT_DIR            -> OUT_DIR/{manifest,disclosure}.json + seed.bin (secret)
  veripress verify IMAGE MANIFEST DISCLOSURE [--heatmap out.png]
  veripress redact IMAGE MANIFEST DISCLOSURE --box x0,y0,x1,y1 [--box ...] -o OUT_DIR
  veripress demo-batch IMG... -o OUT_DIR       -> N photos anchored in one transaction
  veripress demo-raw RAW -o OUT_DIR            -> digital negative -> signed reference JPEG
  veripress demo IMAGE [--ai AI_IMAGE] -o OUT_DIR -> the demo scenarios offline (FakeLedger), incl. anonymous signing
  veripress calibrate ORIG_DIR SHARED_DIR -o OUT.json
                                               -> robust-tile / phash margins on real shared copies
                                                  (copies matched to originals by content: any file names)
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


def _demo_ledger(out: Path):
    """Offline demo world: fresh device/ai keys in out/keys, credentials on a FakeLedger."""
    from xrpl.constants import CryptoAlgorithm
    from xrpl.wallet import Wallet

    from .ledger import CredentialType, FakeLedger
    from .signing import load_key
    from .store import Store

    keys = out / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    for name in ("device", "ai"):
        if not (keys / f"{name}.json").exists():
            w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
            _write_json(keys / f"{name}.json", {"public_key": w.public_key, "private_key": w.private_key})
    os.environ["VERIPRESS_KEYS"] = str(keys)
    ledger, store = FakeLedger(), Store(out / "store")
    ledger.issue(load_key("device").public_key, CredentialType.CAPTURE_DEVICE)
    ledger.issue(load_key("ai").public_key, CredentialType.AI_GENERATOR)
    return ledger, store


def cmd_export_disclosure(a: argparse.Namespace) -> int:
    from .contentaddr import canonical_json, cid_v1_raw
    from .store import Store

    entry = Store(a.store).get(a.entry_id)
    if entry is None:
        print(f"unknown entry {a.entry_id}", file=sys.stderr)
        return 1
    data = canonical_json(entry.disclosure.to_dict())
    cid = cid_v1_raw(data)
    if entry.manifest.disclosure_cid and cid != entry.manifest.disclosure_cid:
        print(f"warning: stored disclosure {cid} differs from the signed one {entry.manifest.disclosure_cid}"
              " (redacted variant?)", file=sys.stderr)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{cid}.json").write_bytes(data)
    print(f"{out / (cid + '.json')}  ({len(data)} bytes)")
    return 0


def cmd_demo_batch(a: argparse.Namespace) -> int:
    """Aggregated anchoring: sign N photos, anchor them in ONE transaction, verify each."""
    import io

    import numpy as np

    from .batching import BatchingLedger
    from .pipeline import sign_image, verify_image

    out = Path(a.out)
    ledger, store = _demo_ledger(out)
    batch = BatchingLedger(ledger, store)
    signed = [sign_image(load_rgb(p), "device", batch, store) for p in a.images]
    before = len(ledger.anchors)
    tx = batch.flush()
    photos = []
    for path, (res, png) in zip(a.images, signed):
        report, _ = verify_image(np.asarray(Image.open(io.BytesIO(png)).convert("RGB")), ledger, store,
                                 entry_id=res.entry_id)
        photos.append({"file": Path(path).name, "verdict": report.verdict.value, "batch": report.batch})
        print(f"{Path(path).name:28} {report.verdict.value:8} batch #{report.batch['index']} of {report.batch['size']}")
    summary = {"batch_tx": tx, "size": len(signed), "transactions": len(ledger.anchors) - before, "photos": photos}
    _write_json(out / "summary.json", summary)
    print(f"{len(signed)} photos -> {summary['transactions']} transaction ({tx})")
    return 0


def cmd_demo_raw(a: argparse.Namespace) -> int:
    """Digital negative -> reference JPEG (Apple Reference Image phases 1 and 2, on XRPL)."""
    import io

    import numpy as np
    from PIL import ImageEnhance

    from .pipeline import sign_image, verify_image

    out = Path(a.out)
    ledger, store = _demo_ledger(out)
    summary: dict[str, dict] = {}

    def check(name: str, rgb, ext: str = "png") -> None:
        Image.fromarray(rgb).save(out / f"{name}.{ext}", quality=92)
        report, _ = verify_image(rgb, ledger, store)
        j = report.to_json()
        summary[name] = {"verdict": j["verdict"], "reason": j["reason"], "found_by": j["found_by"],
                         "history": [h["op"] for h in j["history"]]}
        print(f"{name:18} {j['verdict']:8} via {str(j['found_by']):9} {j['reason']}")

    def rgb_of(png: bytes):
        return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))

    # Phase 1: the device signs its RAW development (LibRaw for camera RAW / DNG).
    negative = load_rgb(a.image)
    raw, raw_png = sign_image(negative, "device", ledger, store)
    check("1_raw_negative", rgb_of(raw_png))

    # Phase 2: the device develops a JPEG from it and signs it as a development of the negative.
    img = Image.fromarray(rgb_of(raw_png))
    img = ImageEnhance.Color(ImageEnhance.Contrast(img).enhance(1.2)).enhance(1.15)
    img.thumbnail((2400, 2400))
    jpeg_rgb = _jpeg(np.asarray(img), 92)
    dev, dev_png = sign_image(jpeg_rgb, "device", ledger, store, parent=raw.entry_id, op="develop")
    dev_rgb = rgb_of(dev_png)
    check("2_reference_jpeg", dev_rgb, "jpg")

    h, w = dev_rgb.shape[:2]
    check("3_jpeg_whatsapp", _jpeg(dev_rgb, 70, scale=min(1.0, 1600 / max(h, w))), "jpg")
    retouched = dev_rgb.copy()
    retouched[h * 3 // 8 : h * 5 // 8, w * 3 // 8 : w * 5 // 8] = (255, 0, 255)
    check("4_jpeg_retouched", _jpeg(retouched, 90), "jpg")

    _write_json(out / "summary.json", summary)
    print(f"written to {out}/")
    return 0


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
    ledger, store = _demo_ledger(out)
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
        summary[name] = {k: j[k] for k in ("verdict", "reason", "found_by", "credential", "anonymous", "meta_claims")}
        summary[name]["tiles"] = j["tiles"]["counts"] if j["tiles"] else None
        print(f"{name:20} {j['verdict']:8} via {str(j['found_by']):9} {j['reason']}")
        for c in j["meta_claims"]:
            print(f"{'':20} {'✅' if c['proof_ok'] else '❌'} proven {c['kind']}: {c['label']}")

    src = load_rgb(a.image)
    h, w = src.shape[:2]
    from .metadata import exif_from_upload

    exif = exif_from_upload(Path(a.image).read_bytes())  # capture day + area proven in ZK (step 8)
    original, png = sign_image(src, "device", ledger, store, exif=exif)
    signed = rgb_of(png)
    check("1_capture", signed)

    edited = signed.copy()
    edited[h * 3 // 8 : h * 5 // 8, w * 3 // 8 : w * 5 // 8] = (255, 0, 255)
    check("2_edited", _jpeg(edited, 90))

    check("3_whatsapp", _jpeg(signed, 60, scale=min(1.0, 1600 / max(h, w), 0.5)))

    _, red_png = redact_image(signed, original.entry_id, [(w // 8, h // 8, w * 3 // 8, h * 3 // 8)], store)
    check("4_redacted", rgb_of(red_png))

    if original.manifest.wm_id:
        wm_id = bytes.fromhex(original.manifest.wm_id)
        check("5_copied_watermark", _jpeg(embed(np.ascontiguousarray(np.rot90(src, 2)), wm_id), 85))
    else:  # no watermark to copy (backup demo without the TrustMark models)
        summary["5_copied_watermark"] = {"skipped": "watermark disabled (VERIPRESS_WATERMARK=0)"}
        print(f"{'5_copied_watermark':20} skipped  (watermark disabled)")

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

    def load_all(d: str) -> dict[str, tuple]:
        out = {}
        for p in images(d):
            try:
                rgb = load_rgb(p)
            except Exception:  # noqa: BLE001 — not an image: ignored
                continue
            out[p.name] = (p, rgb, phash(rgb))
        return out

    # Pair by content, not by name: WhatsApp renames what it exports (and order is easy to mix up).
    originals, shared = load_all(a.originals), load_all(a.shared)
    candidates = sorted(
        ((o[2] ^ c[2]).bit_count(), on, cn)
        for on, o in originals.items() for cn, c in shared.items()
    )
    match: dict[str, str] = {}
    for dist, on, cn in candidates:
        if dist <= 10 and on not in match and cn not in match.values():
            match[on] = cn

    pairs: dict[str, dict] = {}
    for on in sorted(match):
        (opath, src, oph), (cpath, recv, cph) = originals[on], shared[match[on]]
        manifest, disclosure = commit(src, os.urandom(32))
        res = verify(recv, manifest, disclosure)
        pairs[opath.stem] = {
            "shared": cpath.name,
            "size": [src.shape[1], src.shape[0]],
            "received_size": [recv.shape[1], recv.shape[0]],
            "changed_tiles": sum(s == TileStatus.CHANGED for s in res.statuses),
            "tiles": len(res.statuses),
            "max_tile_distance": round(max(res.distances), 2),
            "p99_tile_distance": round(sorted(res.distances)[int(0.99 * (len(res.distances) - 1))], 2),
            "phash_distance": (oph ^ cph).bit_count(),
        }
        print(f"{opath.stem:20} <- {cpath.name:32} changed={pairs[opath.stem]['changed_tiles']:5} "
              f"max={pairs[opath.stem]['max_tile_distance']:6} phash={pairs[opath.stem]['phash_distance']}")
    missing = sorted(originals[on][0].stem for on in originals if on not in match)
    unmatched = sorted(cn for cn in shared if cn not in match.values())
    report = {
        "tolerance": F.TOLERANCE,
        "pairs": pairs,
        "missing": missing,
        "unmatched": unmatched,
        "all_pass": bool(pairs) and not missing and not unmatched
        and all(p["changed_tiles"] == 0 for p in pairs.values()),
    }
    _write_json(Path(a.out), report)
    if missing:
        print(f"no shared copy for: {', '.join(missing)}")
    if unmatched:
        print(f"shared files matching no original: {', '.join(unmatched)}")
    print(f"all_pass={report['all_pass']} (tolerance {F.TOLERANCE}) -> {a.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="veripress")
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

    ex = sub.add_parser("export-disclosure", help="write an entry's disclosure as <CID>.json, for mirroring")
    ex.add_argument("entry_id")
    ex.add_argument("--store", default="store")
    ex.add_argument("-o", "--out", required=True)
    ex.set_defaults(fn=cmd_export_disclosure)

    db = sub.add_parser("demo-batch", help="sign N photos, anchor them in one transaction")
    db.add_argument("images", nargs="+")
    db.add_argument("-o", "--out", required=True)
    db.set_defaults(fn=cmd_demo_batch)

    dr = sub.add_parser("demo-raw", help="RAW negative -> signed reference JPEG (Apple Reference Image, on XRPL)")
    dr.add_argument("image", help="camera RAW / DNG (or any image)")
    dr.add_argument("-o", "--out", required=True)
    dr.set_defaults(fn=cmd_demo_raw)

    cb = sub.add_parser("calibrate", help="measure tile/phash margins on real shared copies")
    cb.add_argument("originals")
    cb.add_argument("shared")
    cb.add_argument("-o", "--out", required=True)
    cb.set_defaults(fn=cmd_calibrate)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
