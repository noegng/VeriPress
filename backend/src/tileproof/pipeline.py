"""Sign / verify pipeline — OWNER: Dev A.  The signatures and JSON shapes below are the
contract with Dev B's API (see docs/interfaces.md): change only via a dedicated commit on main.

Final verdict rules, first match wins (implemented test-first, tests/test_pipeline.py):
  no entry found (no id, no watermark, no phash match)              -> UNKNOWN
  anchor missing on the ledger                                      -> UNKNOWN
  stored manifest != anchored digest/signer                         -> UNKNOWN
  bad signature                                                     -> UNKNOWN
  disclosure does not match the signed roots                        -> UNKNOWN
  found by watermark and > half of the tiles changed                -> UNKNOWN (copied watermark)
  tiles: EDITED (a redacted tile that is not black counts as changed) -> EDITED (heatmap)
  > MAX_REDACTED_SHARE of the tiles redacted                        -> UNKNOWN (proves too little)
  op == "edit" + any valid credential                               -> EDITED (signed edit; the
                                                                       reason flags an unverifiable chain)
  credential AI_GENERATOR                                           -> AI
  credential CAPTURE_DEVICE                                         -> REAL
  no valid credential (never issued or revoked, even after signing) -> UNKNOWN
A tile matches if it is close to the published (watermarked) image OR to the unwatermarked
original: both are committed at signing. sign_image refuses a `parent` that is not anchored.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import numpy as np
from PIL import Image

from .tiling import Grid
from .commitment import Manifest, Verdict, VerifyResult, commit, heatmap, redact, verify
from .perceptual import phash
from .ledger import Anchor, CredentialType, Ledger
from . import watermark, zk
from .signing import keys_dir, load_key, verify_signature
from .store import Entry, Store

Signer = Literal["device", "ai"]  # demo keys in keys/device.json, keys/ai.json (written by Dev B's setup script)
FoundBy = Literal["tx_hash", "watermark", "phash"]


MAX_REDACTED_SHARE = 0.5  # above this, a redacted copy proves too little to be called real


class FinalVerdict(str, Enum):
    REAL = "real"
    EDITED = "edited"
    AI = "ai"
    UNKNOWN = "unknown"


@dataclass
class SignResult:
    entry_id: str
    anchor: Anchor
    manifest: Manifest

    def to_json(self) -> dict:
        """Shape: docs/interfaces.md "POST /api/sign"."""
        g = self.manifest.grid
        return {
            "entry_id": self.entry_id,
            "tx_hash": self.anchor.tx_hash,
            "explorer_url": self.anchor.explorer_url,
            "digest": self.manifest.digest(),
            "signer": self.manifest.signer,
            "grid": {"cols": g.cols, "rows": g.rows, "tile": g.tile},
            "roots": {"exact": self.manifest.exact_root, "robust": self.manifest.robust_root},
            "image_url": f"/api/files/{self.entry_id}.png",
        }


@dataclass
class Report:
    verdict: FinalVerdict
    reason: str
    found_by: FoundBy | None
    entry_id: str | None
    anchor: Anchor | None
    credential: CredentialType | None
    signature_ok: bool
    tiles: VerifyResult | None
    grid: Grid | None = None
    history: list[dict] = field(default_factory=list)  # newest first: {tx_hash, op, timestamp, verified}
    # Phase 2 (docs/interfaces.md § Phase 2)
    anonymous: bool = False
    zk: dict | None = None  # {"proof_ok", "registry_root", "root_valid_at_anchor"} in anonymous mode
    credential_revoked_at: int | None = None
    passkey: bool = False
    meta_claims: list[dict] = field(default_factory=list)
    pending: bool = False

    def to_json(self, heatmap_png: bytes | None = None) -> dict:
        """Shape: docs/interfaces.md "POST /api/verify"."""
        a, t, g = self.anchor, self.tiles, self.grid
        return {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "found_by": self.found_by,
            "entry_id": self.entry_id,
            "anchor": None if a is None else {
                "tx_hash": a.tx_hash, "timestamp": a.timestamp,
                "explorer_url": a.explorer_url, "signer": a.pubkey,
            },
            "credential": self.credential.value if self.credential else None,
            "signature_ok": self.signature_ok,
            "tiles": None if t is None or g is None else {
                "verdict": t.verdict.value,
                "grid": {"cols": g.cols, "rows": g.rows, "tile": g.tile},
                "counts": t.counts(),
                "statuses": [s.value for s in t.statuses],
                "distances": [round(d, 2) for d in t.distances],
            },
            "history": self.history,
            "anonymous": self.anonymous,
            "zk": self.zk,
            "credential_revoked_at": self.credential_revoked_at,
            "passkey": self.passkey,
            "meta_claims": self.meta_claims,
            "pending": self.pending,
            "heatmap_png_b64": base64.b64encode(heatmap_png).decode() if heatmap_png else None,
        }


def _png(img: np.ndarray | Image.Image) -> bytes:
    buf = io.BytesIO()
    (img if isinstance(img, Image.Image) else Image.fromarray(img)).save(buf, "PNG")
    return buf.getvalue()


def _bundle_hash(bundle: dict) -> str:
    return hashlib.sha256(json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _anonymous_registry(signer: Signer) -> tuple[dict, list[list[str]], int]:
    """(device Baby Jubjub key, registry public keys, index of the device in the registry)."""
    if signer != "device":
        raise ValueError("anonymous signing is only for capture devices")
    bjj = json.loads((keys_dir() / f"{signer}.json").read_text()).get("bjj")
    reg = keys_dir() / "registry_devices.json"
    if not bjj or not reg.exists():
        raise ValueError("anonymous signing needs keys/device.json['bjj'] and keys/registry_devices.json")
    pks = json.loads(reg.read_text())["pks"]
    try:
        return bjj, pks, [list(map(str, p)) for p in pks].index(list(map(str, bjj["pk"])))
    except ValueError as e:
        raise ValueError("this device is not in the anonymous registry") from e


def sign_image(
    rgb: np.ndarray, signer: Signer, ledger: Ledger, store: Store, parent: str | None = None,
    anonymous: bool = False,
) -> tuple[SignResult, bytes]:
    """Commit, sign, anchor, store. Returns the result and the PNG to publish.
    `parent`: tx hash of the signed version this image was edited from (version chain).
    `anonymous`: prove membership of the device registry in zero knowledge instead of
    publishing the device key and signature (decisions.md Q2-Q4)."""
    if parent is not None and (store.get(parent) is None or ledger.fetch_anchor(parent) is None):
        raise ValueError(f"unknown parent {parent}: not anchored or not in the store")
    if anonymous:
        bjj, pks, index = _anonymous_registry(signer)
    key = load_key(signer)
    wm_id, original = b"", None
    if watermark.enabled():
        wm_id, original = os.urandom(8), rgb
        rgb = watermark.embed(rgb, wm_id)  # exact tree covers the watermarked pixels
    # robust tree covers both versions: the gallery original must verify too
    manifest, disclosure = commit(rgb, os.urandom(32), original=original)
    manifest.wm_id = wm_id.hex()
    manifest.signer = "" if anonymous else key.public_key
    manifest.anonymous = anonymous
    manifest.op = "ai_generate" if signer == "ai" else ("edit" if parent else "capture")
    manifest.parent = parent
    digest = manifest.digest()
    bundle = None
    if anonymous:
        bundle = zk.prove_device(bjj["sk"], pks, index, digest)
        anchor = ledger.anchor_anonymous(digest, bundle["public"][0], _bundle_hash(bundle))
    else:
        anchor = ledger.anchor(digest, key.sign(digest), key.public_key)
    png = _png(rgb)
    store.put(Entry(anchor.tx_hash, anchor.tx_hash, manifest, disclosure, phash(rgb)), png)
    if bundle is not None:
        store.put_bundle(anchor.tx_hash, bundle)
    return SignResult(anchor.tx_hash, anchor, manifest), png


def _check_anonymous(anchor: Anchor, manifest: Manifest, bundle: dict | None, ledger: Ledger) -> dict:
    """Zero-knowledge device attestation: the proof must be the anchored one, cover this exact
    manifest digest, verify, and use the registry root in force at anchor time."""
    proof_ok = (
        bundle is not None
        and _bundle_hash(bundle) == anchor.bundle_hash
        and list(bundle.get("public", [])) == [anchor.registry_root, *zk.split_digest(manifest.digest())]
        and zk.verify_device(bundle["proof"], bundle["public"])
    )
    root_ok = proof_ok and ledger.registry_root_at(anchor.timestamp) == anchor.registry_root
    return {"proof_ok": bool(proof_ok), "registry_root": anchor.registry_root, "root_valid_at_anchor": bool(root_ok)}


def verify_image(
    rgb: np.ndarray, ledger: Ledger, store: Store, entry_id: str | None = None
) -> tuple[Report, bytes | None]:
    """Find the entry (entry_id > watermark > phash), check anchor/signature/credential/tiles.
    Returns the report and the heatmap PNG (None when no entry was found)."""
    found_by: FoundBy | None = None
    if entry_id:
        entry, found_by = store.get(entry_id), "tx_hash"
    else:
        entry, ph = None, phash(rgb)
        wm = watermark.extract(rgb) if watermark.enabled() else None
        if wm is not None:
            entry = store.find_by_watermark(wm.hex(), ph)
            found_by = "watermark" if entry else None
        if entry is None:
            entry = store.nearest(ph)
            found_by = "phash" if entry else None
    if entry is None:
        reason = f"No provenance record for id {entry_id}" if entry_id else "No provenance found for this image"
        return Report(FinalVerdict.UNKNOWN, reason, None, None, None, None, False, None), None
    manifest = entry.manifest
    anchor = ledger.fetch_anchor(entry.tx_hash)
    if anchor is None:
        reason = f"Anchor transaction {entry.tx_hash} not found on the ledger"
        return Report(FinalVerdict.UNKNOWN, reason, found_by, entry.id, None, None, False, None), None
    zk_check = None
    if anchor.anonymous:
        zk_check = _check_anonymous(anchor, manifest, store.get_bundle(entry.tx_hash), ledger)
        sig_ok = zk_check["proof_ok"]
        credential = CredentialType.CAPTURE_DEVICE if zk_check["root_valid_at_anchor"] else None
    else:
        sig_ok = verify_signature(anchor.digest, anchor.signature, anchor.pubkey)
        credential = ledger.credential_type(anchor.pubkey, anchor.timestamp)
    tiles = verify(rgb, manifest, entry.disclosure)
    reason = ""
    if (
        anchor.digest != manifest.digest()
        or anchor.pubkey != manifest.signer
        or anchor.anonymous != manifest.anonymous
    ):
        verdict = FinalVerdict.UNKNOWN
        reason = "Stored manifest does not match the anchored digest"
    elif anchor.anonymous and not sig_ok:
        verdict = FinalVerdict.UNKNOWN
        reason = "Zero-knowledge device proof is invalid or does not cover this manifest"
    elif anchor.anonymous and credential is None:
        verdict = FinalVerdict.UNKNOWN
        reason = "Device registry root used by the proof was not in force at anchor time"
    elif not sig_ok:
        verdict = FinalVerdict.UNKNOWN
        reason = "Anchored signature does not verify against the signer key"
    elif tiles.verdict == Verdict.INVALID_DISCLOSURE:
        verdict = FinalVerdict.UNKNOWN
        reason = "Tile disclosure does not match the signed Merkle roots"
    elif found_by == "watermark" and tiles.counts()["changed"] > len(tiles.statuses) // 2:
        verdict = FinalVerdict.UNKNOWN
        reason = "Watermark points to a record whose content does not match this image (copied watermark?)"
    elif tiles.verdict == Verdict.EDITED:
        verdict = FinalVerdict.EDITED
        c = tiles.counts()
        reason = f"{c['changed']}/{len(tiles.statuses)} tiles changed since signing"
    elif tiles.counts()["redacted"] > len(tiles.statuses) * MAX_REDACTED_SHARE:
        verdict = FinalVerdict.UNKNOWN
        reason = "Too much of the image is redacted to vouch for its content"
    elif manifest.op == "edit" and credential is not None:
        verdict = FinalVerdict.EDITED
        reason = f"Signed edit of {manifest.parent} by a {credential.value} credential"
        history = _history(entry.tx_hash, ledger, store)
        if not all(h["verified"] for h in history):
            reason += "; the original version could not be verified"
    elif credential in (CredentialType.AI_GENERATOR, CredentialType.CAPTURE_DEVICE):
        verdict = FinalVerdict.AI if credential == CredentialType.AI_GENERATOR else FinalVerdict.REAL
        c, n = tiles.counts(), len(tiles.statuses)
        if tiles.verdict == Verdict.INTACT:
            how = "identical"
        elif tiles.original_tiles * 2 >= n - c["redacted"]:
            how = "match the original capture (unwatermarked)"
        else:
            how = "match after recompression"
        who = (
            f"Signed anonymously by an accredited {credential.value} (zero-knowledge proof)"
            if anchor.anonymous else f"Signed by a {credential.value} credential"
        )
        reason = f"{who}; {n - c['redacted']}/{n} tiles {how}"
        if c["redacted"]:
            reason += f", {c['redacted']} redacted"
    else:
        verdict = FinalVerdict.UNKNOWN
        reason = "Signer has no valid credential (never issued or revoked)"
    history = _history(entry.tx_hash, ledger, store)
    report = Report(
        verdict, reason, found_by, entry.id, anchor, credential, sig_ok, tiles, manifest.grid, history,
        anonymous=anchor.anonymous, zk=zk_check,
    )
    hm = _png(heatmap(rgb, manifest, tiles)) if tiles.statuses else None
    return report, hm


def _history(tx_hash: str | None, ledger: Ledger, store: Store, max_depth: int = 20) -> list[dict]:
    """Walk the `parent` chain; each step checks the stored manifest against its anchor."""
    out: list[dict] = []
    while tx_hash and len(out) < max_depth:
        entry, anchor = store.get(tx_hash), ledger.fetch_anchor(tx_hash)
        if entry is None or anchor is None:
            out.append({"tx_hash": tx_hash, "op": None, "timestamp": None, "verified": False})
            break
        m = entry.manifest
        ok = anchor.digest == m.digest() and verify_signature(anchor.digest, anchor.signature, anchor.pubkey)
        out.append({"tx_hash": tx_hash, "op": m.op, "timestamp": anchor.timestamp, "verified": ok})
        tx_hash = m.parent if ok else None
    return out


def redact_image(
    rgb: np.ndarray, entry_id: str, boxes: list[tuple[int, int, int, int]], store: Store
) -> tuple[str, bytes]:
    """Black out boxes, store a redacted variant entry. Returns (new_entry_id, png)."""
    entry = store.get(entry_id)
    if entry is None:
        raise KeyError(entry_id)
    grid = entry.manifest.grid
    tiles = {i for box in boxes for i in grid.tiles_in_box(*box)}
    out, disclosure = redact(rgb, entry.manifest, entry.disclosure, tiles)
    n = 1
    while store.get(f"{entry.tx_hash}-r{n}") is not None:
        n += 1
    new_id = f"{entry.tx_hash}-r{n}"
    png = _png(out)
    store.put(Entry(new_id, entry.tx_hash, entry.manifest, disclosure, phash(out)), png)
    return new_id, png
