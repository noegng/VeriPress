# Interfaces: Python modules, HTTP API, data formats

Reference for the formats used between modules, on the ledger and over HTTP. The design behind them is in [`architecture.md`](architecture.md).

Team rule: any change to this file, to `ledger.py`, to `store.py` or to the signatures in `pipeline.py` goes through a dedicated commit in a pull request, announced to the other developer.

## Python modules

| Module | Role |
|---|---|
| `tiling.py` | `load_upload(data, filename) -> ndarray`: **entry point for uploaded files**. JPEG, PNG, HEIC, WebP, AVIF, TIFF (16-bit too), camera RAW via LibRaw; EXIF orientation; ICC → sRGB. Raises `ValueError` if unreadable. Never call `Image.open` first: Pillow reads a RAW as its small embedded preview |
| `commitment.py` | `commit`, `redact`, `verify`; `Manifest`, `Disclosure` |
| `pipeline.py` | `sign_image`, `prepare_passkey_sign`, `complete_passkey_sign`, `verify_image`, `verify_stored`, `redact_image`; `SignResult.to_json`, `Report.to_json` |
| `ledger.py` | `Ledger` (protocol), `FakeLedger` (in memory), `XrplLedger` (Testnet) |
| `batching.py` | `BatchingLedger(base, store)`: queue anchors, `flush()` = one transaction |
| `store.py` | Off-chain records (layout in `architecture.md` § 8); `find_all_by_watermark(wm_id, phash)`, `nearest_all(phash)` (candidates, closest first) |
| `watermark.py` | TrustMark `embed`, `extract`, `warm_up()` (load the models at API start-up). `VERIPRESS_WATERMARK=0` disables it |
| `signing.py` | Ed25519 keys, `verify_webauthn`, ML-DSA-87 (`load_pq_key`, `verify_pq`) |
| `zk.py` | Wrapper around `node zk/cli.mjs` |
| `metadata.py` | EXIF → capture time + GPS, day / area claims |
| `c2pa_embed.py` | `embed` (C2PA manifest in the PNG), `read` (from file bytes). `VERIPRESS_C2PA=0` disables it |
| `api.py` | FastAPI app; calls only `pipeline.*` |

```python
sign_image(rgb, signer, ledger, store, parent=None, anonymous=False, wait=True, exif=None, op=None)
    -> (SignResult, png_bytes)
    # signer: "device" | "ai"; exif: raw EXIF of the uploaded file (time + GPS)
    # op="develop": requires parent = the signed RAW, same named device
prepare_passkey_sign(rgb, store, parent=None, exif=None, ledger=None) -> {"prep_id", "challenge"}
complete_passkey_sign(prep_id, assertion, ledger, store, wait=True) -> (SignResult, png_bytes)
    # assertion = {"credential_id", "authenticator_data", "client_data_json", "signature", "public_key"} (base64url)
verify_image(rgb, ledger, store, entry_id=None) -> (Report, heatmap_png | None)
verify_stored(entry_id, ledger, store) -> (Report, heatmap_png | None)   # public link /v/<id>
redact_image(rgb, entry_id, boxes, store) -> (new_entry_id, png_bytes)
```

Exceptions: `ValueError` = invalid request (HTTP 422); `KeyError` = unknown entry (HTTP 404).

### Ledger protocol

```python
@dataclass(frozen=True)
class Anchor:
    tx_hash: str
    digest: str            # batch anchor: the Merkle root
    signature: str         # "" for anonymous, passkey and batch anchors
    pubkey: str            # "" for anonymous and batch anchors
    timestamp: int         # close time of the ledger (T1); submission time while not validated
    explorer_url: str
    validated: bool = True     # False until validated (fast anchoring)
    anonymous: bool = False
    registry_root: str = ""    # anonymous: root used by the proof
    bundle_hash: str = ""      # anonymous / passkey: SHA-256 of the stored proof bundle
    cid: str = ""              # unused: the CID lives in the signed manifest (disclosure_cid)
    batch_size: int = 0        # batch anchor: number of leaves

class Ledger(Protocol):
    def anchor(self, digest, signature, pubkey, wait=True) -> Anchor: ...
    def anchor_anonymous(self, digest, registry_root, bundle_hash, wait=True) -> Anchor: ...
    def anchor_passkey(self, digest, pubkey, bundle_hash, wait=True) -> Anchor: ...
    def anchor_batch(self, root, count, wait=True) -> Anchor: ...
    def fetch_anchor(self, tx_hash) -> Anchor | None: ...        # also returns unvalidated txs
    def credential_type(self, pubkey, at_time=None) -> CredentialType | None: ...  # valid at that instant
                                                                 # (the pipeline always passes the anchor time)
    def credential_revoked_at(self, pubkey) -> int | None: ...   # unix time of the CredentialDelete
    def credential_passkey(self, pubkey) -> str | None: ...      # SHA-256 hex of the attested P-256 key
    def credential_pq(self, pubkey, at_time=None) -> str | None: ...  # SHA-256 hex of the ML-DSA-87 key attested at that instant
    def registry_root_at(self, at_time) -> str | None: ...       # anonymous registry root in force
    def latest_validated(self) -> tuple[int, str, int]: ...      # (index, hash, close_time): T0
    def ledger_close_time(self, ledger_index, ledger_hash) -> int | None: ...  # None if the hash does not match
```

`VERIPRESS_LEDGER=fake|xrpl` (default `fake`) selects the ledger in `api.py`.

## On-ledger formats (XRPL Testnet)

Conventions: `pubkey` = XRPL Ed25519 public key, `"ED"` + 64 hex. `digest` = hex SHA-256 of the canonical manifest. `signature` = hex Ed25519 signature over `bytes.fromhex(digest)`.

| Transaction | From → to | MemoType | MemoData (compact JSON) |
|---|---|---|---|
| Named anchor | `Payment` 1 drop, anchoring account → registry | `veripress/v1` | `{"d": digest, "s": signature, "k": pubkey}` |
| Anonymous anchor | same | `veripress/v1` | `{"d", "a": 1, "r": registry_root, "h": bundle_hash}` |
| Passkey anchor | same | `veripress/v1` | `{"d", "k": device pubkey, "w": bundle_hash}` |
| Batch anchor | same | `veripress/v1` | `{"b": merkle_root, "n": count}` |
| Registry root | `AccountSet`, registry → itself | `veripress/registry-root/v1` | `{"root", "depth": 10, "n": device_count}` |

Credentials: issued by the registry (`CredentialCreate`), accepted by the subject (`CredentialAccept`), `CredentialType` = hex of `CAPTURE_DEVICE` or `AI_GENERATOR`, revoked with `CredentialDelete`. The `URI` attests extra keys: `passkey=<base64url SHA-256>;mldsa87=<base64url SHA-256>` (103 bytes; the older `passkey:sha256:<hex>` form is still read). XRPL cannot edit a URI, so changing an attested key means deleting and re-creating the Credential. Attestations are read from the registry's history, so a revocation does not erase them.

Batch leaf: `leaf_hash("VPB1", index, "", canonical JSON {d, s, k, a, r, h})`, i.e. what an individual memo would have carried.

## Keys (written by `backend/scripts/setup_testnet.py`, never committed)

```
keys/registry.json          {"seed", "address"}       Credential issuer, receives the anchors
keys/anchor.json            {"seed", "address"}       pays the anchoring transactions
keys/device.json            {"seed", "address", "public_key", "private_key",   CAPTURE_DEVICE
                             "bjj": {"sk", "pk"},                              Baby Jubjub (ZK)
                             "mldsa": {"public_key", "private_pem"}}           ML-DSA-87
keys/ai.json                same                                               AI_GENERATOR
keys/registry_devices.json  {"pks": [[x, y], …]}      anonymous registry, in tree order
keys/passkey.json           {"credential_id", "public_key"}   registered WebAuthn passkey
```

Script options: `--fresh` (new accounts), `--revoke device|ai`, `--reissue device|ai` (both republish the registry root), `--passkey` (attest `keys/passkey.json`).

## ZK tool (`zk/cli.mjs`)

`node zk/cli.mjs <command>`: JSON on stdin → JSON on stdout (exit code ≠ 0 and a message on stderr on error). Big integers are decimal strings.

| Command | Input | Output |
|---|---|---|
| `keygen` | `{}` | `{"sk": "<32-byte hex>", "pk": ["x", "y"]}` (Baby Jubjub) |
| `root` | `{"pks": [["x","y"], …], "depth": 10}` | `{"root"}` (Poseidon tree, leaf = `Poseidon(x, y)`, empty leaves = 0) |
| `prove-device` | `{"sk", "pks", "index", "digest": "<64 hex>", "depth": 10}` | `{"proof", "public": ["root", "digest_hi", "digest_lo"]}` |
| `verify-device` | `{"proof", "public"}` | `{"ok": bool}` |
| `commit-meta` | `{"time", "lat_e6", "lon_e6", "salt": "<31-byte hex>"}` | `{"commitment"}` = `Poseidon(time, lat_e6 + 90e6, lon_e6 + 180e6, salt)` |
| `prove-meta` | `{"time", "lat_e6", "lon_e6", "salt", "t_min", "t_max", "lat_min_e6", "lat_max_e6", "lon_min_e6", "lon_max_e6"}` | `{"proof", "public": ["commitment", "t_min", "t_max", "lat_min", "lat_max", "lon_min", "lon_max"]}` |
| `verify-meta` | `{"proof", "public"}` | `{"ok": bool}` |

## HTTP API (`api.py`)

| Route | Purpose |
|---|---|
| `GET /` | The web page (Examine / Certify tabs) |
| `GET /api/health` | `{ok, ledger, watermark, watermark_ready}` |
| `POST /api/preview` | Browser-displayable JPEG of an upload the browser cannot render (RAW, HEIC on Chrome) |
| `GET /api/files/{entry_id}.png` | The published image |
| `POST /api/sign` | Sign one image |
| `POST /api/sign/batch` | Sign 1–8 images, one anchoring transaction |
| `POST /api/sign/passkey/prepare`, `…/complete` | Two-step passkey signing |
| `POST /api/passkey/register`, `GET /api/passkey` | Register a passkey candidate (localhost only) / read it |
| `POST /api/verify` | Verify an uploaded image |
| `POST /api/lookup` | Certified records an upload may derive from (watermark, then perceptual hash), no verification: `{candidates: [{entry_id, tx_hash, found_by, op, anonymous, signer, timestamp, image_url}]}`. The page offers the first one as the parent of a new version |
| `POST /api/redact` | Create a redacted variant |
| `GET /api/anchor/{tx_hash}` | Anchor status `{tx_hash, validated, timestamp, explorer_url}` (polled after fast anchoring) |
| `GET /api/entry/{entry_id}` | `/api/verify` JSON computed on the stored image |
| `GET /api/proof/{entry_id}` | Public material for the in-browser proof replay: `{tx_hash, manifest, disclosure}` (`manifest` = the canonical bytes whose SHA-256 is the anchored digest) |
| `GET /api/demo`, `GET /api/demo/{name}` | The pitch specimens prepared by `cli prepare-demo` (`demo/signed/`, closed list) |
| `GET /v/{entry_id}` | Public read-only verification page, with social preview tags |

### `POST /api/sign`

Multipart: `image`, `signer` = `device` | `ai`, optional `parent` (tx hash → `op = edit`), `op = develop` (with `parent`), `anonymous = "1"`, `wait = "0"` (fast anchoring). The API passes the raw EXIF of the upload to `sign_image`.

```json
{
  "entry_id": "A1B2…",
  "tx_hash": "A1B2…",
  "explorer_url": "https://testnet.xrpl.org/transactions/A1B2…",
  "digest": "9f…",
  "signer": "ED12…",
  "grid": {"cols": 39, "rows": 29, "tile": 104},
  "roots": {"exact": "…", "robust": "…"},
  "image_url": "/api/files/A1B2….png",
  "anonymous": false,
  "passkey": false,
  "pending": false,
  "meta_claims": [{"kind": "day", "label": "20 Nov 2026", "proof_ok": true}]
}
```

`POST /api/sign/passkey/prepare` (multipart `image`, `parent?`) → `{"prep_id", "challenge"}`. The challenge is the manifest digest; a `prep_id` is single-use and expires after 10 minutes. `POST /api/sign/passkey/complete` (JSON `{"prep_id", "assertion"}`) → same shape as `/api/sign`. Accepted WebAuthn origins: `VERIPRESS_WEBAUTHN_HOSTS` (default `localhost,127.0.0.1`); user presence **and** user verification are required.

`POST /api/sign/batch` (multipart: `images` ×1–8, `signer`, `anonymous?`, `wait?`) → `{"tx_hash", "explorer_url", "size", "pending", "entries": [{"name", "entry_id", "image_url"} | {"name", "error"}]}`. An unreadable file is reported in `entries` without blocking the others; 422 if none could be signed.

### `POST /api/verify`

Multipart: `image`, optional `entry_id`.

```json
{
  "verdict": "real | edited | ai | unknown",
  "reason": "Signed by a CAPTURE_DEVICE credential; 1131/1131 tiles match after recompression",
  "found_by": "tx_hash | watermark | phash | null",
  "entry_id": "A1B2…",
  "anchor": {"tx_hash": "…", "timestamp": 1795000000, "explorer_url": "…", "signer": "ED12…"},
  "credential": "CAPTURE_DEVICE | AI_GENERATOR | null",
  "signature_ok": true,
  "tiles": {
    "verdict": "intact | recompressed | edited | invalid_disclosure",
    "grid": {"cols": 39, "rows": 29, "tile": 104},
    "counts": {"exact": 0, "robust": 1131, "changed": 0, "redacted": 0},
    "statuses": ["robust", "…"],
    "distances": [1.2, "…"]
  },
  "history": [
    {"tx_hash": "C3D4…", "op": "edit", "timestamp": 1795000100, "verified": true},
    {"tx_hash": "A1B2…", "op": "capture", "timestamp": 1795000000, "verified": true}
  ],
  "anonymous": false,
  "zk": null,
  "credential_revoked_at": null,
  "passkey": false,
  "meta_claims": [
    {"kind": "day",  "label": "20 Nov 2026", "proof_ok": true},
    {"kind": "area", "label": "≈ 41.12°N 16.87°E (10 km)", "proof_ok": true}
  ],
  "pending": false,
  "time_window": {"not_before": 1794999980, "not_after": 1795000000, "ledger_index": 123456, "t0_ok": true},
  "disclosure_cid": "bafkrei…",
  "batch": null,
  "post_quantum": {"alg": "ML-DSA-87", "signature_ok": true, "attested": true},
  "c2pa": null,
  "heatmap_png_b64": "iVBORw0…"
}
```

- Nothing found: `verdict = "unknown"`, `found_by`, `anchor`, `tiles`, `heatmap_png_b64` are `null`, `history = []`.
- `statuses` and `distances` are in row-major order (index = `row × cols + col`); `distances` are in quantisation steps (tolerance 4.5).
- `history`: version chain, newest first.
- `zk` (anonymous mode only): `{"proof_ok", "registry_root", "root_valid_at_anchor"}`; `anchor.signer` is then `""`.
- `credential_revoked_at`: set when the device was revoked **after** the anchor; the verdict stays `real`.
- `pending: true`: provisional verdict; `reason` starts with "Anchor pending validation".
- `meta_claims`: `[]` without a metadata commitment, or when the verdict is `unknown`. The area label is the box centre rounded to 0.01° (no reverse geocoding). A day claim that starts after the anchor gets `"proof_ok": false` and `"note": "capture day after the anchor time: impossible"`.
- `time_window`: `[T0, T1]`; `null` when nothing is found.
- `batch`: `{"tx_hash", "index", "size"}` for an aggregated anchor.
- `post_quantum`: `null` unless the manifest declares an ML-DSA key, or the registry attested one for the device at anchor time while the manifest does not use it: then `{"alg", "signature_ok": false, "attested": true, "missing": true}` and the verdict is `unknown` (downgrade).
- `c2pa`: read from the uploaded **bytes**, never the pixels. `null` (no manifest, e.g. after WhatsApp) or `{"tx_hash", "manifest_digest", "explorer", "source_type", "state", "signer_trusted", "matches_anchor"}`. Information only: the verdict never depends on it.

### `POST /api/redact`

Multipart: `image`, `entry_id`, `boxes` = JSON `[[x0, y0, x1, y1], …]` → `{"entry_id": "A1B2…-r1", "image_url": "/api/files/A1B2…-r1.png"}`.

### Display

| `verdict` | Badge |
|---|---|
| `real` | 🟢 Real |
| `edited` | 🟠 Edited + heatmap (or signed edit: show `history`) |
| `ai` | 🔵 AI-generated |
| `unknown` | ⚪ Unknown (≠ fake) + `reason` |

## Command line (`uv run python -m veripress.cli …`, from `backend/`)

| Command | Purpose |
|---|---|
| `commit`, `verify`, `redact` | Low-level tile commitment, without the ledger |
| `demo photo.jpg -o out/` | The demo scenarios offline (`FakeLedger`) |
| `prepare-demo --raw file.CR3` | Re-sign every pitch asset on the real ledger, into the API store, and write `demo/signed/RUNBOOK.md` |
| `demo-batch photos… -o out/` | N photos, one anchoring transaction |
| `demo-raw file.CR3 -o out/` | RAW negative → signed reference JPEG |
| `export-disclosure <entry_id> -o mirror/` | Write the disclosure as `<CID>.json` for a mirror |
| `calibrate` | Measure tile and pHash margins on real shared copies |
