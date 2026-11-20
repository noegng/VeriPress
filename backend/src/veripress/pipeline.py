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
import secrets
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import numpy as np
from PIL import Image

from .tiling import Grid
from .commitment import Disclosure, Manifest, Verdict, VerifyResult, commit, heatmap, redact, verify
from .perceptual import phash
from .ledger import Anchor, CredentialType, Ledger
from . import c2pa_embed, metadata, watermark, zk
from .batching import resolve_receipt
from .contentaddr import canonical_json, cid_v1_raw
from .signing import PQ_ALG, keys_dir, load_key, load_pq_key, verify_pq, verify_signature, verify_webauthn
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
    meta_claims: list[dict] = field(default_factory=list)

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
            # phase 2 (interfaces.md § Phase 2)
            "anonymous": self.manifest.anonymous,
            "passkey": self.manifest.passkey is not None,
            "pending": not self.anchor.validated,
            "meta_claims": self.meta_claims,
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
    time_window: dict | None = None  # {"not_before", "not_after", "ledger_index", "t0_ok"}
    disclosure_cid: str | None = None
    batch: dict | None = None  # aggregated anchoring: {"tx_hash", "index", "size"}
    post_quantum: dict | None = None  # {"alg", "signature_ok", "attested"} when the manifest is hybrid

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
            "time_window": self.time_window,
            "disclosure_cid": self.disclosure_cid,
            "batch": self.batch,
            "post_quantum": self.post_quantum,
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


@dataclass
class _Prepared:
    """A committed, not yet anchored manifest (waits for its signature / proof)."""
    rgb: np.ndarray  # published pixels (watermarked)
    manifest: Manifest
    disclosure: Disclosure
    capture: metadata.Capture | None
    salt: str | None
    created: float = field(default_factory=time.monotonic)
    pq: dict | None = None  # {"alg", "public_key", "signature"} hybrid post-quantum signature


def _prepare(
    rgb: np.ndarray, op: str, signer_pubkey: str, ledger: Ledger | None, store: Store,
    parent: str | None = None, exif: bytes | None = None, anonymous: bool = False, passkey: str | None = None,
    pq_pubkey_sha256: str | None = None,
) -> _Prepared:
    if parent is not None and (store.get(parent) is None or (
            ledger is not None and _fetch_anchor(parent, ledger, store)[0] is None)):
        raise ValueError(f"unknown parent {parent}: not anchored or not in the store")
    wm_id, original = b"", None
    if watermark.enabled():
        wm_id, original = os.urandom(8), rgb
        rgb = watermark.embed(rgb, wm_id)  # exact tree covers the watermarked pixels
    # robust tree covers both versions: the gallery original must verify too
    manifest, disclosure = commit(rgb, os.urandom(32), original=original)
    manifest.wm_id = wm_id.hex()
    manifest.disclosure_cid = cid_v1_raw(canonical_json(disclosure.to_dict()))  # mirrors can be checked
    manifest.signer = "" if anonymous else signer_pubkey
    manifest.anonymous = anonymous
    manifest.passkey = passkey
    manifest.pq_pubkey_sha256 = None if anonymous else pq_pubkey_sha256  # the key would identify the device
    manifest.op = op if op in ("ai_generate", "develop") else ("edit" if parent else "capture")
    manifest.parent = parent
    manifest.t0 = _latest_ledger(ledger)
    capture = metadata.read_capture(exif)
    salt = os.urandom(31).hex() if capture else None  # never stored: only the claims are published
    if capture:
        manifest.meta_commitment = zk.commit_meta(capture.time, capture.lat_e6, capture.lon_e6, salt)
    return _Prepared(rgb, manifest, disclosure, capture, salt)


def _publish(prep: _Prepared, anchor: Anchor, store: Store, bundle: dict | None = None) -> tuple[SignResult, bytes]:
    manifest, digest = prep.manifest, prep.manifest.digest()
    png = _png(prep.rgb)
    if c2pa_embed.enabled():  # Content Credentials pointing to the anchor (metadata only, same pixels)
        png = c2pa_embed.embed(png, anchor.tx_hash, digest, manifest.op, anchor.explorer_url)
    store.put(Entry(anchor.tx_hash, anchor.tx_hash, manifest, prep.disclosure, phash(prep.rgb)), png)
    if bundle is not None:
        store.put_bundle(anchor.tx_hash, bundle)
    if prep.pq is not None:
        store.put_pq(anchor.tx_hash, prep.pq)
    claims = []
    if prep.capture:
        cap = prep.capture
        made = metadata.claims(cap)
        store.put_meta(anchor.tx_hash, [
            {"kind": c.kind, **zk.prove_meta(cap.time, cap.lat_e6, cap.lon_e6, prep.salt, c.bounds())} for c in made
        ])
        claims = [{"kind": c.kind, "label": c.label, "proof_ok": True} for c in made]
    return SignResult(anchor.tx_hash, anchor, manifest, claims), png


def _pq_material(signer: str, device_pubkey: str, ledger: Ledger | None):
    """(ML-DSA-87 key, public hex, sha256) if this signer has one AND the registry attests it,
    else None: until attested we sign classic Ed25519 only (no unverifiable hybrid)."""
    try:
        loaded = load_pq_key(signer)
    except (OSError, ValueError, KeyError):
        loaded = None
    if loaded is None or ledger is None:
        return None
    key, pub_hex = loaded
    sha = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()
    try:
        attested = ledger.credential_pq(device_pubkey) == sha
    except Exception:  # noqa: BLE001 — not implemented on this ledger yet / network
        attested = False
    return (key, pub_hex, sha) if attested else None


def _pq_sign(prep: _Prepared, pq) -> None:
    if pq is not None:
        key, pub_hex, _ = pq
        sig = key.sign(bytes.fromhex(prep.manifest.digest())).hex()
        prep.pq = {"alg": PQ_ALG, "public_key": pub_hex, "signature": sig}


def sign_image(
    rgb: np.ndarray, signer: Signer, ledger: Ledger, store: Store, parent: str | None = None,
    anonymous: bool = False, wait: bool = True, exif: bytes | None = None, op: str | None = None,
) -> tuple[SignResult, bytes]:
    """Commit, sign, anchor, store. Returns the result and the PNG to publish.
    `parent`: tx hash of the signed version this image was edited from (version chain).
    `anonymous`: prove membership of the device registry in zero knowledge instead of
    publishing the device key and signature (decisions.md Q2-Q4).
    `exif`: raw EXIF of the uploaded file; with a capture time + GPS, the manifest commits to
    them and day / ~10 km area claims are proven in zero knowledge (decisions.md Q16-Q17).
    `op="develop"`: this image is the device's own development of its signed RAW `parent`
    (digital negative -> reference JPEG): same device key required."""
    if op not in (None, "develop"):
        raise ValueError(f"unsupported op {op!r}")
    if anonymous:
        bjj, pks, index = _anonymous_registry(signer)
    key = load_key(signer)
    if op == "develop":
        neg = store.get(parent) if parent else None
        if neg is None:
            raise ValueError("develop needs the parent: the signed RAW (digital negative) it was developed from")
        if anonymous or neg.manifest.anonymous or neg.manifest.signer != key.public_key:
            raise ValueError("develop must be signed by the same device that signed the RAW negative")
    pq = None if anonymous else _pq_material(signer, key.public_key, ledger)
    prep = _prepare(rgb, op or ("ai_generate" if signer == "ai" else "capture"), key.public_key, ledger, store,
                    parent=parent, exif=exif, anonymous=anonymous, pq_pubkey_sha256=pq[2] if pq else None)
    _pq_sign(prep, pq)
    digest = prep.manifest.digest()
    bundle = None
    if anonymous:
        bundle = zk.prove_device(bjj["sk"], pks, index, digest)
        anchor = ledger.anchor_anonymous(digest, bundle["public"][0], _bundle_hash(bundle), wait=wait)
    else:
        anchor = ledger.anchor(digest, key.sign(digest), key.public_key, wait=wait)
    return _publish(prep, anchor, store, bundle)


# ---------------------------------------------------------------- passkey (WebAuthn) signing

PASSKEY_PREP_TTL_S = 600
_PREPS: dict[str, _Prepared] = {}
_PREPS_LOCK = threading.Lock()


def _passkey_registration() -> dict:
    p = keys_dir() / "passkey.json"
    if not p.exists():
        raise ValueError("no passkey registered (keys/passkey.json): use 'Set up passkey' first")
    return json.loads(p.read_text())


def prepare_passkey_sign(
    rgb: np.ndarray, store: Store, parent: str | None = None, exif: bytes | None = None, ledger: Ledger | None = None,
) -> dict:
    """Step 1: commit the image for the device whose passkey is registered; the manifest digest
    is the WebAuthn challenge. Pass `ledger` to get the T0 lower bound and check `parent`."""
    reg = _passkey_registration()
    device = load_key("device").public_key
    pq = _pq_material("device", device, ledger)
    prep = _prepare(rgb, "capture", device, ledger, store, parent=parent, exif=exif,
                    passkey=str(reg["public_key"]).lower(), pq_pubkey_sha256=pq[2] if pq else None)
    _pq_sign(prep, pq)
    prep_id = secrets.token_urlsafe(18)
    now = time.monotonic()
    with _PREPS_LOCK:
        for k in [k for k, v in _PREPS.items() if now - v.created > PASSKEY_PREP_TTL_S]:
            del _PREPS[k]
        _PREPS[prep_id] = prep
    return {"prep_id": prep_id, "challenge": prep.manifest.digest()}


def complete_passkey_sign(
    prep_id: str, assertion: dict, ledger: Ledger, store: Store, wait: bool = True,
) -> tuple[SignResult, bytes]:
    """Step 2: verify the WebAuthn assertion over the digest, check the registry attests this
    passkey for the device, anchor, publish. KeyError: unknown / expired / used prep_id;
    ValueError: invalid assertion or passkey not attested."""
    with _PREPS_LOCK:
        prep = _PREPS.pop(prep_id)  # single use, even if the assertion turns out invalid
    if time.monotonic() - prep.created > PASSKEY_PREP_TTL_S:
        raise KeyError(prep_id)
    manifest, digest = prep.manifest, prep.manifest.digest()
    if str(assertion.get("credential_id", "")) != str(_passkey_registration().get("credential_id", "")):
        raise ValueError("assertion made with another credential than the registered passkey")
    verify_webauthn(assertion, digest, manifest.passkey)
    if ledger.credential_passkey(manifest.signer) != _sha256_hex(manifest.passkey):
        raise ValueError("this passkey is not attested by the registry for the device (setup_testnet.py --passkey)")
    bundle = {k: assertion[k] for k in ("credential_id", "authenticator_data", "client_data_json", "signature", "public_key")}
    anchor = ledger.anchor_passkey(digest, manifest.signer, _bundle_hash(bundle), wait=wait)
    return _publish(prep, anchor, store, bundle)


def _sha256_hex(hex_bytes: str | None) -> str:
    try:
        return hashlib.sha256(bytes.fromhex(hex_bytes or "")).hexdigest()
    except ValueError:
        return ""


def _check_passkey(anchor: Anchor, manifest: Manifest, bundle: dict | None, ledger: Ledger) -> tuple[bool, bool]:
    """(assertion valid for this digest and the anchored bundle, passkey attested by the registry)."""
    if bundle is None or _bundle_hash(bundle) != anchor.bundle_hash or not manifest.passkey:
        return False, False
    try:
        verify_webauthn(bundle, manifest.digest(), manifest.passkey)
        ok = True
    except ValueError:
        ok = False
    try:
        attested = ledger.credential_passkey(anchor.pubkey) == _sha256_hex(manifest.passkey)
    except Exception:  # noqa: BLE001
        attested = False
    return ok, attested


CLOCK_SKEW_S = 3600  # camera clocks drift: a capture day may start up to 1 h after the anchor


def _meta_claims(manifest: Manifest, stored: list[dict], anchored_at: int) -> list[dict]:
    """Verified capture-metadata claims. Each proof must be bound to the commitment in the
    signed manifest; labels come from its public inputs, never from stored text. EXIF is input
    to the signer, so a claim must also be possible: no capture day after the anchor (T1)."""
    out = []
    for c in stored if manifest.meta_commitment else []:
        public = c.get("public") if isinstance(c, dict) else None
        if not isinstance(public, list) or len(public) != 7:
            continue
        try:
            kind, label = metadata.describe(public)
        except (TypeError, ValueError):
            continue
        ok = str(public[0]) == manifest.meta_commitment and zk.verify_meta(c.get("proof", {}), public)
        claim = {"kind": kind, "label": label, "proof_ok": bool(ok)}
        if kind == "day" and int(public[1]) > anchored_at + CLOCK_SKEW_S:
            claim.update(proof_ok=False, note="capture day after the anchor time: impossible")
        out.append(claim)
    return out


def _latest_ledger(ledger: Ledger | None) -> dict | None:
    """T0: latest validated ledger at signing time (None if the ledger cannot tell)."""
    if ledger is None:
        return None
    try:
        index, ledger_hash, _ = ledger.latest_validated()
    except Exception:  # noqa: BLE001 — not implemented / network: sign without a lower bound
        return None
    return {"ledger_index": int(index), "ledger_hash": str(ledger_hash).upper()}


def _time_window(manifest: Manifest, anchor: Anchor, ledger: Ledger) -> dict:
    """[T0, T1]: signed after ledger T0 closed (its hash was in the signed manifest), anchored at T1."""
    not_before, index = None, None
    if manifest.t0:
        index = manifest.t0.get("ledger_index")
        try:
            not_before = ledger.ledger_close_time(int(index), str(manifest.t0.get("ledger_hash", "")))
        except Exception:  # noqa: BLE001
            not_before = None
    return {"not_before": not_before, "not_after": anchor.timestamp, "ledger_index": index,
            "t0_ok": not_before is not None}


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
    Returns the report and the heatmap PNG (None when no entry was found).

    The store is untrusted, and anyone can list records in it (a fake "redacted variant" of a real
    photo, a real record under a forged perceptual hash): without an explicit id, every candidate
    found by the watermark or the perceptual hash is verified, and the best-supported one wins.
    Each verdict only ever claims what the chain proves about that record, so picking the best is
    sound; it just stops a planted record from hiding the genuine one."""
    if entry_id:
        candidates = [(store.get(entry_id), "tx_hash")]
    else:
        ph = phash(rgb)
        wm = watermark.extract(rgb) if watermark.enabled() else None
        candidates = [(e, "watermark") for e in (store.find_all_by_watermark(wm.hex(), ph) if wm else [])]
        seen = {e.id for e, _ in candidates}
        candidates += [(e, "phash") for e in store.nearest_all(ph) if e.id not in seen]
        candidates = candidates[:MAX_CANDIDATES]
    candidates = [(e, f) for e, f in candidates if e is not None]
    if not candidates:
        reason = f"No provenance record for id {entry_id}" if entry_id else "No provenance found for this image"
        return Report(FinalVerdict.UNKNOWN, reason, None, None, None, None, False, None), None
    best = max((_verify_entry(rgb, e, f, ledger, store) for e, f in candidates), key=_support)
    report, manifest = best
    hm = _png(heatmap(rgb, manifest, report.tiles)) if report.tiles is not None and report.tiles.statuses else None
    return report, hm


MAX_CANDIDATES = 8


def _support(result: tuple["Report", Manifest | None]) -> tuple:
    """How well a candidate record supports the image: verdict first, then fewer changed tiles."""
    r = result[0]
    rank = {FinalVerdict.REAL: 2, FinalVerdict.AI: 2, FinalVerdict.EDITED: 1}.get(r.verdict, 0)
    c = r.tiles.counts() if r.tiles is not None and r.tiles.statuses else {"changed": 10**9, "redacted": 10**9}
    return rank, -c["changed"], -c["redacted"]


def _verify_entry(rgb: np.ndarray, entry: Entry, found_by: FoundBy, ledger: Ledger, store: Store
                  ) -> tuple["Report", Manifest | None]:
    """Verify the image against one record. Returns the report and the record's manifest."""
    manifest = entry.manifest
    anchor, batch_info, err = _fetch_anchor(entry.tx_hash, ledger, store)
    if anchor is None:
        return Report(FinalVerdict.UNKNOWN, err, found_by, entry.id, None, None, False, None), None
    auth = _authenticate(anchor, manifest, entry.tx_hash, ledger, store)
    sig_ok, credential, zk_check = auth["sig_ok"], auth["credential"], auth["zk"]
    is_passkey, passkey_attested = auth["passkey"], auth["passkey_attested"]
    # Non-retroactive revocation: the credential was valid at anchor time but has been revoked since.
    revoked_at = None
    if not anchor.anonymous and credential is not None:
        revoked_at = ledger.credential_revoked_at(anchor.pubkey)
        if revoked_at is not None and revoked_at <= anchor.timestamp:
            revoked_at = None
    tiles = verify(rgb, manifest, entry.disclosure)
    reason = ""
    if not auth["manifest_matches"]:
        verdict = FinalVerdict.UNKNOWN
        reason = "Stored manifest does not match the anchored digest"
    elif anchor.anonymous and not sig_ok:
        verdict = FinalVerdict.UNKNOWN
        reason = "Zero-knowledge device proof is invalid or does not cover this manifest"
    elif anchor.anonymous and credential is None:
        verdict = FinalVerdict.UNKNOWN
        reason = "Device registry root used by the proof was not in force at anchor time"
    elif is_passkey and not sig_ok:
        verdict = FinalVerdict.UNKNOWN
        reason = "Passkey (WebAuthn) assertion is invalid or does not cover this manifest"
    elif is_passkey and not passkey_attested:
        verdict = FinalVerdict.UNKNOWN
        reason = "Passkey is not the one the registry attests for this device"
    elif not sig_ok:
        verdict = FinalVerdict.UNKNOWN
        reason = "Anchored signature does not verify against the signer key"
    elif auth["pq"] and auth["pq"].get("missing"):
        verdict = FinalVerdict.UNKNOWN
        reason = ("No post-quantum (ML-DSA-87) signature, although the registry attested one for this "
                  "device when it was anchored (downgrade to Ed25519 only)")
    elif auth["pq"] and not auth["pq"]["signature_ok"]:
        verdict = FinalVerdict.UNKNOWN
        reason = "Post-quantum (ML-DSA-87) signature declared by the manifest is missing or invalid"
    elif auth["pq"] and not auth["pq"]["attested"]:
        verdict = FinalVerdict.UNKNOWN
        reason = "Post-quantum (ML-DSA-87) key is not the one the registry attests for this device"
    elif tiles.verdict == Verdict.INVALID_DISCLOSURE:
        verdict = FinalVerdict.UNKNOWN
        reason = "Tile disclosure does not match the signed Merkle roots"
    elif tiles.counts()["changed"] > len(tiles.statuses) // 2:
        # Not "edited": an unrelated picture checked against a record (planted link, forged
        # perceptual hash, copied watermark) is not a retouch of that record's photo.
        verdict = FinalVerdict.UNKNOWN
        reason = ("Watermark points to a record whose content does not match this image (copied watermark?)"
                  if found_by == "watermark" else
                  "This image does not match the record it was checked against (most tiles differ)")
    elif tiles.verdict == Verdict.EDITED:
        verdict = FinalVerdict.EDITED
        c = tiles.counts()
        reason = f"{c['changed']}/{len(tiles.statuses)} tiles changed since signing"
    elif tiles.counts()["redacted"] > len(tiles.statuses) * MAX_REDACTED_SHARE:
        verdict = FinalVerdict.UNKNOWN
        reason = "Too much of the image is redacted to vouch for its content"
    elif manifest.op == "develop" and credential is not None:
        history = _history(entry.tx_hash, ledger, store)
        neg = store.get(manifest.parent) if manifest.parent else None
        chain_ok = (
            all(h["verified"] for h in history) and len(history) >= 2 and history[1]["op"] == "capture"
            and neg is not None and not manifest.anonymous and not neg.manifest.anonymous
            and bool(manifest.signer) and neg.manifest.signer == manifest.signer  # "same device" provable
        )
        if chain_ok:
            verdict = FinalVerdict.AI if credential == CredentialType.AI_GENERATOR else FinalVerdict.REAL
            reason = (f"Developed from the signed RAW negative {manifest.parent} by the same "
                      f"{credential.value}; {len(tiles.statuses)} tiles match the published development")
        elif manifest.anonymous or (neg is not None and neg.manifest.anonymous):
            verdict = FinalVerdict.EDITED
            reason = (f"Signed development of {manifest.parent}; anonymous signatures cannot prove "
                      "it was developed by the device that captured it")
        else:
            verdict = FinalVerdict.EDITED
            reason = f"Signed development of {manifest.parent}; the original version could not be verified"
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
            if anchor.anonymous
            else f"Signed with a hardware passkey attested for a {credential.value} credential"
            if is_passkey else f"Signed by a {credential.value} credential"
        )
        if auth["pq"]:
            who += " — hybrid post-quantum signature (Ed25519 + ML-DSA-87)"
        reason = f"{who}; {n - c['redacted']}/{n} tiles {how}"
        if c["redacted"]:
            reason += f", {c['redacted']} redacted"
        if revoked_at is not None:
            reason += f"; device revoked since {_utc(revoked_at)}, after this photo was anchored"
    else:
        verdict = FinalVerdict.UNKNOWN
        reason = "Signer has no valid credential (never issued or revoked)"
    if not anchor.validated:
        reason = f"Anchor pending validation on the ledger (provisional verdict); {reason}"
    history = _history(entry.tx_hash, ledger, store)
    report = Report(
        verdict, reason, found_by, entry.id, anchor, credential, sig_ok, tiles, manifest.grid, history,
        anonymous=anchor.anonymous, zk=zk_check, credential_revoked_at=revoked_at,
        pending=not anchor.validated,
        time_window=_time_window(manifest, anchor, ledger),
        disclosure_cid=manifest.disclosure_cid or None,
        batch=batch_info,
        post_quantum=auth["pq"],
        passkey=is_passkey,
        # Claims describe the signed capture: only shown when the verdict ties this image to it.
        meta_claims=[] if verdict == FinalVerdict.UNKNOWN
        else _meta_claims(manifest, store.get_meta(entry.tx_hash), anchor.timestamp),
    )
    return report, manifest


def verify_stored(entry_id: str, ledger: Ledger, store: Store) -> tuple[Report, bytes | None]:
    """Verify the published image kept in the store for `entry_id` (public link /v/<tx>).
    Raises KeyError for an unknown entry."""
    path = store.image_path(entry_id)
    if store.get(entry_id) is None or not path.exists():
        raise KeyError(entry_id)
    rgb = np.asarray(Image.open(path).convert("RGB"))
    return verify_image(rgb, ledger, store, entry_id=entry_id)


def _utc(ts: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _fetch_anchor(entry_id: str, ledger: Ledger, store: Store) -> tuple[Anchor | None, dict | None, str]:
    """Per-photo anchor of an entry: its own tx, or rebuilt from a batch receipt (aggregated
    anchoring). A batch tx itself is not a photo anchor. -> (anchor, batch info, error)."""
    receipt = store.get_receipt(entry_id)
    if receipt is not None:
        return resolve_receipt(receipt, ledger)
    a = ledger.fetch_anchor(entry_id)
    if a is not None and a.batch_size:
        return None, None, f"{entry_id} is a batch anchor, not the anchor of a photo"
    return a, None, "" if a is not None else f"Anchor transaction {entry_id} not found on the ledger"


def _authenticate(anchor: Anchor, manifest: Manifest, tx_hash: str, ledger: Ledger, store: Store) -> dict:
    """Who vouches for this anchored manifest, per signing mode (named Ed25519, anonymous ZK,
    passkey WebAuthn). Used for the record itself AND every step of its version chain."""
    out = {"sig_ok": False, "credential": None, "zk": None, "passkey": False, "passkey_attested": None,
           "manifest_matches": anchor.digest == manifest.digest() and anchor.pubkey == manifest.signer
           and anchor.anonymous == manifest.anonymous}
    if anchor.anonymous:
        z = _check_anonymous(anchor, manifest, store.get_bundle(tx_hash), ledger)
        out.update(zk=z, sig_ok=z["proof_ok"],
                   credential=CredentialType.CAPTURE_DEVICE if z["root_valid_at_anchor"] else None)
    elif anchor.bundle_hash and not anchor.signature:  # passkey (WebAuthn)
        ok, attested = _check_passkey(anchor, manifest, store.get_bundle(tx_hash), ledger)
        out.update(sig_ok=ok, passkey=True, passkey_attested=attested,
                   credential=ledger.credential_type(anchor.pubkey, anchor.timestamp))
    else:
        out.update(sig_ok=verify_signature(anchor.digest, anchor.signature, anchor.pubkey),
                   credential=ledger.credential_type(anchor.pubkey, anchor.timestamp))
    out["pq"] = None
    if not manifest.pq_pubkey_sha256 and not anchor.anonymous:
        # The device had an attested ML-DSA-87 key when this was anchored, yet the manifest does
        # not use it: an Ed25519-only forgery (e.g. after Q-day) must not pass (no downgrade).
        try:
            attested_then = ledger.credential_pq(anchor.pubkey, at_time=anchor.timestamp)
        except Exception:  # noqa: BLE001 — not implemented / network: as before, no requirement
            attested_then = None
        if attested_then:
            out["pq"] = {"alg": PQ_ALG, "signature_ok": False, "attested": True, "missing": True}
    elif manifest.pq_pubkey_sha256:  # declared in the signed manifest: mandatory (no downgrade)
        pqb = store.get_pq(tx_hash) or {}
        pub = str(pqb.get("public_key", ""))
        sig_pq = (pqb.get("alg") == PQ_ALG and _sha256_hex(pub) == manifest.pq_pubkey_sha256
                  and verify_pq(anchor.digest, str(pqb.get("signature", "")), pub))
        try:
            attested = ledger.credential_pq(anchor.pubkey, at_time=anchor.timestamp) == manifest.pq_pubkey_sha256
        except Exception:  # noqa: BLE001
            attested = False
        out["pq"] = {"alg": PQ_ALG, "signature_ok": bool(sig_pq), "attested": bool(attested)}
    out["verified"] = bool(
        (out["pq"] is None or (out["pq"]["signature_ok"] and out["pq"]["attested"]))
        and out["manifest_matches"] and out["sig_ok"]
        and (not anchor.anonymous or out["credential"] is not None)  # root in force at anchor time
        and (not out["passkey"] or out["passkey_attested"])
    )
    return out


def _history(tx_hash: str | None, ledger: Ledger, store: Store, max_depth: int = 20) -> list[dict]:
    """Walk the `parent` chain; each step is authenticated like the record itself."""
    out: list[dict] = []
    while tx_hash and len(out) < max_depth:
        entry, anchor = store.get(tx_hash), _fetch_anchor(tx_hash, ledger, store)[0]
        if entry is None or anchor is None:
            out.append({"tx_hash": tx_hash, "op": None, "timestamp": None, "verified": False})
            break
        m = entry.manifest
        ok = _authenticate(anchor, m, tx_hash, ledger, store)["verified"]
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
