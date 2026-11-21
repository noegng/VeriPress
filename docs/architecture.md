# Architecture

How VeriPress signs an image, anchors it on the XRP Ledger, and later verifies a copy of it, tile by tile. Every number and format below is the one in the code (`backend/src/veripress/`). Field-level formats are in [`interfaces.md`](interfaces.md); the reasons behind each choice are in [`decisions.md`](decisions.md).

## Overview

```
                         SIGN                                         VERIFY
 image ──▶ load & normalise ──▶ watermark (TrustMark, 64-bit id)      received image (any copy)
                │                     │                                   │
                │                     ▼                                   ▼
                │            split into tiles                      find the record:
                │         ┌───────────┴───────────┐                entry id ▸ watermark ▸ pHash
                │    exact tree              robust tree                  │
                │  (raw pixel bytes)   (DCT features, both versions)      ▼
                │         └───────────┬───────────┘               fetch the XRPL anchor,
                ▼                     ▼                           check signer + Credential
       EXIF time + GPS ──▶  Manifest (dims, roots, wm_id,         at anchor time
       (Poseidon commitment)  op, parent, T0, …)                          │
                                      │ SHA-256 = digest                  ▼
                 sign: Ed25519 │ ZK proof │ passkey (+ ML-DSA-87)  authenticate the disclosure
                                      ▼                           against the signed roots
                     XRPL Testnet: Payment 1 drop + Memo                  │
                     {digest, signature or proof hash, key}               ▼
                                      │                           compare every tile:
                                      ▼                           exact ▸ robust ▸ changed
                     store: manifest, disclosure, image,                  │
                     proofs (content-addressed, untrusted)                ▼
                                                                   verdict + heatmap
```

| Component | Where | Role |
|---|---|---|
| Web page | `static/index.html`, `static/view.html`, shared `static/site.css` + `site.js` | Examine / certify tabs; tiles, drift and Merkle tree drawn on the photo; in-browser proof replay (WebCrypto + a public XRPL node); redaction; passkey; public link page |
| API | `api.py` (FastAPI) | HTTP routes; calls only `pipeline.*` |
| Pipeline | `pipeline.py` | Sign, verify, redact; final verdict rules |
| Commitment | `commitment.py`, `merkle.py`, `features.py`, `tiling.py` | Tiles, two Merkle trees, tile comparison |
| Lookup | `watermark.py` (TrustMark), `perceptual.py` (pHash) | Find the record of an image shared without its id |
| Ledger | `ledger.py` (`XrplLedger`, `FakeLedger`), `batching.py` | Anchors, Credentials, registry root, time window |
| Signatures | `signing.py`, `zk.py` + `zk/` (circom), `metadata.py` | Ed25519, WebAuthn, ML-DSA-87, Groth16 proofs |
| Store | `store.py`, `contentaddr.py` | Off-chain records, addressed by CID |
| C2PA | `c2pa_embed.py` | Standard Content Credentials in the published PNG |

## 1. Loading and normalising the image

Two copies of the same photo must give the same pixels, whatever format they arrive in. `tiling.load_upload` / `load_rgb`:

- reads JPEG, PNG, HEIC, WebP, AVIF, TIFF and camera RAW files (CR2, CR3, NEF, ARW, RAF, RW2, ORF, DNG…). RAW files are developed deterministically with LibRaw (camera white balance, sRGB, 8 bits);
- applies the EXIF orientation;
- converts any embedded ICC profile to sRGB. iPhones save in Display P3, while WhatsApp sends back untagged sRGB: without this step every tile shifted;
- scales 16-bit and float images to 8 bits (Pillow would clip them).

Result: an `H×W×3` array of 8-bit sRGB pixels. Everything below works on this array, never on file bytes.

## 2. Tiles

- Tile size = long side / 40, rounded to a multiple of 8, at least 32 px (`auto_tile`). A 4032×3024 photo gets 104 px tiles: 39 × 29 = 1,131 tiles. The size is calibrated so that a tile still has ~40 px after a platform downscales the image to 1,280–1,600 px.
- Row-major order: index = `row × cols + col`.
- An edge strip thinner than a quarter tile is merged into the last row or column: thin slivers are dominated by resampling artefacts.

## 3. Two Merkle trees

Both trees use the same hashing scheme (`merkle.py`):

```
leaf = SHA-256(0x00 ‖ domain ‖ index (u32 BE) ‖ salt_i ‖ payload)
node = SHA-256(0x01 ‖ left ‖ right)
```

- The `0x00` / `0x01` prefixes separate leaves from inner nodes (second-preimage protection).
- The tile index in the leaf prevents reordering tiles.
- An odd node is promoted unchanged, never duplicated (avoids the CVE-2012-2459 ambiguity). The leaf count is fixed by the signed width, height and tile size.
- **Salts:** `salt_i = HMAC-SHA256(seed, "tile" ‖ i)[:16]`, with a fresh random 32-byte seed per image. The seed is discarded; each tile's salt is published with that tile. A redacted tile's salt is withheld, so its leaf hashes reveal nothing, even for a flat, low-entropy tile.

### Exact tree (domain `VPX1`)

Payload = the tile's raw RGB bytes (no padding). One changed bit in a tile changes its leaf: the tree proves the pixels are untouched.

"Exact" means the **decoded pixels** are identical, not the file. An image whose metadata was stripped, or that was re-encoded losslessly (PNG → PNG), is still exact. The exact tree covers the published (watermarked) pixels only.

### Robust tree (domain `VPR1`)

Payload = quantised low-frequency features of the tile (`features.py`). For each channel:

1. area-average the tile's real pixels into 8×8 cells (summed-area table, so merged edge tiles of any size are handled exactly);
2. orthonormal 2-D DCT-II;
3. keep the first coefficients in zig-zag order (DC included);
4. divide by a step of 4 and round to `int16`.

Channels and coefficients (21 values per tile):

| Channel | Coefficients | What they catch |
|---|---|---|
| Luminance (`0.299 R + 0.587 G + 0.114 B`) | 0–9 | Shapes and brightness |
| Luminance | 10–14 | Finer detail (erased by blurring) |
| Cb, Cr (colour) | 0–2 each | A recolouring that keeps the luminance |

The feature parameters are in the signed manifest. Records signed before the adversarial review used luminance coefficients 0–9 only, and still verify with those parameters.

When the image is watermarked, the leaf also commits the features of the **unwatermarked original** (`f ‖ g`), so the robust tree vouches for both versions (see § 6).

The features themselves (`f`, `g`) are published in the disclosure. The verifier does **not** compare robust hashes: quantisation boundaries would make a benign recompression flip a leaf. It authenticates the published vectors with the root, then compares distances (§ 9).

## 4. Manifest and digest

The manifest is what gets signed. It is serialised as canonical JSON (sorted keys, no spaces), and `digest = SHA-256(canonical manifest)`.

| Field | Meaning |
|---|---|
| `width`, `height`, `tile` | Grid (fixes the number of leaves) |
| `exact_root`, `robust_root` | Roots of the two trees |
| `feature` | `{"pool": 8, "n": 15, "step": 4, "chroma": 3}`: feature parameters, checked by the verifier (first records: `{"pool": 8, "n": 10, "step": 4}`) |
| `signer` | XRPL Ed25519 public key of the device or AI generator (`""` when anonymous) |
| `op` | `capture`, `ai_generate`, `edit` (has a `parent`) or `develop` (RAW → JPEG) |
| `parent` | Anchor tx hash of the version this one derives from (version chain) |
| `wm_id` | 64-bit watermark id, hex (`""` if no watermark) |
| `anonymous` | `true` when signed with a zero-knowledge device proof |
| `meta_commitment` | Poseidon commitment to EXIF capture time + GPS, or `null` |
| `passkey` | P-256 public key (SEC1 hex) when signed with a passkey |
| `pq_pubkey_sha256` | SHA-256 of the attested ML-DSA-87 key (hybrid post-quantum signature) |
| `disclosure_cid` | IPFS CIDv1 of the disclosure |
| `t0` | `{ledger_index, ledger_hash}` of the latest validated XRPL ledger at signing |
| `v` | Format version (1) |

The **disclosure** travels separately because it is too big for the ledger. Per tile: `{i, x, salt, f, g}` (exact leaf, salt, features of the published image, features of the original), or `{i, x, r}` for a redacted tile (the two leaf hashes, nothing else).

## 5. Signing modes

The digest is signed in one of three ways. Each mode binds its proof to the digest, so an anchor cannot be replayed on another manifest.

| Mode | What the anchor memo carries | What the verifier checks |
|---|---|---|
| **Named** (default) | `{d: digest, s: Ed25519 signature, k: device key}` | The signature, and the key's XRPL Credential at anchor time |
| **Anonymous** (ZK) | `{d, a: 1, r: registry root, h: SHA-256(proof bundle)}` | Groth16 proof that *some* key of the device registry signed `d`; the root was in force at anchor time |
| **Passkey** (WebAuthn) | `{d, k: device key, w: SHA-256(assertion bundle)}` | P-256 assertion over `challenge = digest`; the registry attests this passkey for the device |

Named and passkey signatures get an extra **hybrid post-quantum signature** (ML-DSA-87, FIPS 204) when the registry attests the device's ML-DSA key (§ 10).

The XRPL account key *is* the device key: the device's Ed25519 public key derives its XRPL address, which is the subject of its Credential.

## 6. Watermark: finding the record after metadata stripping

- Model: Adobe **TrustMark** (variant Q, BCH_4 error correction), payload 68 bits = 4-bit version + 64-bit id.
- The id is **random**, chosen at signing and written in the signed manifest (`wm_id`). The image is watermarked **before** its tiles are committed, so the exact root covers the watermarked pixels.
- The watermark is only a **pointer**. It never decides the verdict: the signature and the Merkle roots do.
- **Copied watermark:** a watermark pasted onto another picture leads to a record whose tiles do not match. When more than half the tiles changed, the verdict is ⚪ *Unknown* ("copied watermark?"), not 🟠: the picture is not a retouch of that record's photo. The same rule applies however the record was found (explicit id, perceptual hash).
- **The unwatermarked original also verifies.** Watermarking moves some features by up to ~20 quantisation steps, so the gallery original used to come out 🟠. The robust leaf now commits both versions (`f` and `g`), and a tile matches if it is close to either. We rejected the alternative, re-watermarking at verification, because it would put a neural network inside the verdict (adversarial inputs, dependence on a model version). The original never verifies as *exact*, since its pixels are not the watermarked ones; the reason says it "matches the original capture (unwatermarked)".
- Fallback when no watermark is readable: a 64-bit perceptual hash of the whole image (32×32 grey → DCT → top-left 8×8 → bit = coefficient > median), nearest record within a Hamming distance of 10. Used only to find a record, never to authenticate. In production this needs an off-chain index: XRPL has no similarity search.

Lookup at verification: an explicit entry id is used alone. Otherwise every record carrying the watermark id, then every record within the pHash distance, is a **candidate** (up to 8), and each one is fully verified; the best-supported verdict wins (real / AI, then edited, then fewer changed tiles). The store is untrusted and anyone can list a record in it: a planted "redacted variant" of a real photo, or a real record re-listed under a forged pHash, used to be picked first and hide the genuine record. Picking the best is sound because each verdict only claims what the chain proves about that record.

## 7. XRPL usage (Testnet)

| Need | XRPL feature | Detail |
|---|---|---|
| Anchor a manifest | `Payment` of 1 drop, anchoring account → registry account | One Memo, `MemoType = "veripress/v1"`, `MemoData` = compact JSON (formats in § 5) |
| Trusted devices and AI generators | `CredentialCreate` (registry) + `CredentialAccept` (subject) | `CredentialType` = `CAPTURE_DEVICE` or `AI_GENERATOR` |
| Revocation | `CredentialDelete` | Not retroactive: validity is checked **at anchor time**, read from the registry's history |
| Attest a passkey / ML-DSA key | Credential `URI` | `passkey=<b64url SHA-256>;mldsa87=<b64url SHA-256>` (fits the 128-byte limit) |
| Anonymous registry | `AccountSet` (no flag change) from the registry to itself | Memo `veripress/registry-root/v1` `{root, depth, n}`; the root in force at T is the last one published before T |
| Time window | Ledger hash and close time | T0 in the manifest, T1 = close time of the anchor's ledger (§ 11) |
| Aggregated anchoring | One `Payment` per batch | Memo `{b: Merkle root, n: count}` (§ 13) |

Only transactions from the right account count: Credentials must be created by the registry and accepted by their subject, registry roots must be sent by the registry itself, and only validated `tesSUCCESS` transactions are read. Anyone can send a memo to the registry; it is worthless unless it carries a valid signature or proof.

Testnet was chosen over Devnet for stability; Credentials are active there. The `Batch` amendment is not on Testnet, hence our own Merkle aggregation. `scripts/setup_testnet.py` recreates the whole state (accounts, Credentials, anonymous registry, attestations) after a Testnet reset.

## 8. Off-chain store

`store/<entry_id>/` (in production: IPFS or hosted by the owner):

| File | Content |
|---|---|
| `entry.json` | `{id, tx_hash, manifest, disclosure, phash}` |
| `image.png` | The published (watermarked) image, with its C2PA manifest |
| `bundle.json` | ZK proof or WebAuthn assertion (its SHA-256 is anchored) |
| `meta.json` | ZK proofs of the capture-metadata claims |
| `pq.json` | ML-DSA-87 signature (4.6 KB: too big for a 1 KB memo) |
| `receipt.json` | Inclusion proof in an aggregated anchor |

`entry_id` = anchor tx hash, or `<tx_hash>-r<n>` for a redacted variant (same manifest and anchor, redacted disclosure). Ids are checked against a regex, so a `parent` in a manifest cannot point outside the store.

**The store is untrusted.** Each piece is checked against the chain: the manifest must hash to the anchored digest, the disclosure must rebuild the signed roots, proof bundles must hash to the anchored value, receipts must prove inclusion in the anchored batch root. The disclosure's IPFS CID (`disclosure_cid`, CIDv1 raw sha2-256) is in the signed manifest, so any mirror can serve it.

The unwatermarked original is **not** kept: only its features (`g`) are.

## 9. Verifying a received image

`pipeline.verify_image`:

1. **Find the record** (§ 6).
2. **Fetch the anchor** from XRPL, or rebuild it from a batch receipt.
3. **Authenticate** according to the signing mode (§ 5): the ML-DSA signature too if the manifest declares one, and the Credential at anchor time.
4. **Authenticate the disclosure**: rebuild both trees from the published leaves and features; the roots must equal the signed ones.
5. **Compare tiles.** Bring the image back to the signed size (Lanczos in floating point, without clipping, so thin dark lines on a bright background do not shift a tile's mean). Then for each tile:
   - **exact**: its recomputed exact leaf equals the committed one;
   - **robust**: distance ≤ 4.5 steps. The distance is the largest weighted gap over the coefficients, in quantisation steps. Weights: 0.5 on the luminance DC (mean brightness drifts more than structure under resampling), 0.75 on the detail coefficients (thin periodic lines alias when downscaled), 0.25 on colour (JPEG halves the colour resolution; a recolouring still moves it by 50+ steps). It is the smaller of the distances to the watermarked and to the original features;
   - **redacted**: authenticated by hash only. The received pixels must really be black (mean ≤ 16, 95th percentile ≤ 48), otherwise anything could be pasted under a "redacted" label;
   - **changed**: otherwise.
6. **Lossless copies.** If at least half of the *textured* tiles (any luminance AC coefficient ≥ 1 step) are still byte-identical, the copy is lossless and has no recompression noise to forgive. Then every *robust* tile is counted as **changed** (a subtle recolouring or light blur), and a redacted tile must be truly black (99th percentile ≤ 8). Flat tiles are left out of the count because they can survive a JPEG byte for byte.
7. **Tile verdict:** `edited` if any tile changed, else `recompressed` if any tile is only robust, else `intact`.
8. **Final verdict**: rules below, first match wins.

| Condition | Verdict |
|---|---|
| No record found | ⚪ Unknown |
| Anchor missing on the ledger | ⚪ Unknown |
| Stored manifest ≠ anchored digest or signer | ⚪ Unknown |
| Signature, ZK proof or passkey assertion invalid; passkey not attested; registry root not in force | ⚪ Unknown |
| ML-DSA-87 declared but missing, invalid or not attested; or not declared although the registry attested an ML-DSA key at anchor time (no downgrade) | ⚪ Unknown |
| Disclosure does not match the signed roots | ⚪ Unknown |
| More than half the tiles changed | ⚪ Unknown (not this record's photo; "copied watermark?" when found by watermark) |
| Some tiles changed | 🟠 Edited, with heatmap |
| More than 50 % of the tiles redacted | ⚪ Unknown (proves too little) |
| `op = develop`, chain verified, same named device | 🟢 Real (else 🟠) |
| `op = edit` with a valid Credential | 🟠 Edited (signed edit, version history shown) |
| Credential `AI_GENERATOR` | 🔵 AI-generated |
| Credential `CAPTURE_DEVICE` | 🟢 Real |
| No valid Credential at anchor time | ⚪ Unknown |

If the device was revoked **after** the anchor, the verdict stays 🟢 and the reason adds "device revoked since …". If the anchor is not validated yet, the verdict is flagged `pending`.

The `parent` chain is walked (up to 20 steps), and every step is authenticated like the record itself, whatever its signing mode.

### Calibration

Measured on real photos, then frozen in `features.py`:

- 6 camera photos of 3–5k px (Wikimedia Commons) shared WhatsApp-like (1,600 px q72 and 1,280 px q55): largest benign distance 2.96 for a tolerance of 4.5. A copy-move of 2 tiles is detected 100 % of the time, of half a tile 78 %.
- 4 iPhone HEIC photos (Display P3) really sent through WhatsApp: largest benign distance 2.01 after ICC conversion, unclipped resampling and DC weighting. The original, the signed version, and WhatsApp copies of both all verify 🟢. A half-tile edit is still detected 97 % of the time.
- Colour and detail features (adversarial review), same 4 iPhone photos (real WhatsApp copies, plus simulated 1,600 px q72 and 1,280 px q55, signed and original, found without id): all 16 copies 🟢, largest weighted distance 3.97. Detected after JPEG: a recolouring of 4×4 tiles that keeps the luminance; a Gaussian blur of radius ≥ 5 px over a region. In a lossless copy, any of these edits is detected.
- Not detected after JPEG: a blur of radius ≤ 4 px, or the blurring of a detail as small as a licence plate (100×30 px). Once a platform downscales a 12 MP photo to 1,280 px, such details are already gone from the authentic copies too, so no tolerance can tell them apart.
- `uv run python -m veripress.cli calibrate` re-runs the measurement.

Performance on a 12 MP photo: signing ~2 s, verification ~2 s (plus ~2 s per ZK proof).

## 10. Hybrid post-quantum signature

- Each device and the AI generator also hold an **ML-DSA-87** key (FIPS 204, native in `cryptography` ≥ 44).
- The registry attests the key's SHA-256 in the Credential `URI`. Only an attested key is used; until then, signing is Ed25519 only.
- The manifest then carries `pq_pubkey_sha256`, and the ML-DSA signature over the digest is stored in `pq.json`.
- A manifest that declares the key **requires** a valid ML-DSA signature and an attested key, otherwise ⚪: deleting the file cannot downgrade the record.
- A manifest that does **not** declare it is ⚪ too if the registry attested an ML-DSA key for this device at anchor time: otherwise a forger holding only the Ed25519 key (after Q-day) could simply leave the field out. Attestations are read as they were at anchor time, so photos anchored before the key was attested keep verifying.
- Never in anonymous mode: the key would identify the device.
- Still not post-quantum: Groth16 proofs on BN254 (their soundness; anonymity is perfect zero-knowledge and holds), P-256 passkeys, the C2PA ES256 signature, XRPL account signatures. After "Q-day", the XRPL timeline still prevents back-dating a forged signature.

## 11. Time window [T0, T1]

Like Apple's Reference Image T0 / T1 tokens, but decentralised:

- **T0**: at signing, the manifest includes the hash of the latest validated XRPL ledger. A ledger hash cannot be predicted before that ledger closes, so the image was signed **after** T0.
- **T1**: close time of the ledger that contains the anchor.

The verifier re-reads the ledger at T0's index and checks its hash (wrong hash, future or unvalidated ledger → no lower bound). The page shows "signed between 14:02:31 and 14:02:52 UTC".

## 12. Zero-knowledge proofs

Circom 2 circuits, Groth16 on BN254, `snarkjs` + `circomlib`, driven by `zk/cli.mjs` (JSON in, JSON out) and wrapped by `zk.py`.

### Anonymous device attestation (`device.circom`, 14,578 constraints)

- Besides its Ed25519 key, each device has a **Baby Jubjub** key (EdDSA-Poseidon, efficient inside a circuit).
- The registry publishes on XRPL the root of a **Poseidon Merkle tree** (depth 10, 1,024 slots) of accredited keys. Leaf = `Poseidon(x, y)`. The demo registry holds the real device plus ~20 fictitious ones: anonymity grows with the number of devices.
- The proof states: "I know a key in the tree with this root, and it signed this digest". Public inputs: `[root, digest_hi, digest_lo]` (the SHA-256 digest split into two 128-bit halves).
- No nullifier is needed: the signature checked in the circuit covers the digest, so a proof cannot be reused for another manifest.
- Revocation = publish a new root without the device. A proof is accepted only if its root **was in force at anchor time**, so revocation is not retroactive here either.
- Proof ~2 s, verification ~0.6 s, bundle 906 bytes (its SHA-256 is anchored).

### Selective metadata disclosure (`meta.circom`, 1,295 constraints)

- At signing, EXIF `DateTimeOriginal` (+ time zone) and GPS are committed in the signed manifest: `meta_commitment = Poseidon(time, lat×10⁶ + 90×10⁶, lon×10⁶ + 180×10⁶, salt)`. The salt is secret and never stored.
- Two claims are proven and published: "taken on day D" (local day, 24 h interval) and "within a ~10 km box around …" (centre rounded to 0.01°). The exact time and position are never published.
- At verification each proof must be bound to the commitment in the signed manifest, and labels are recomputed from the verified public inputs, never read from stored text. Claims are hidden when the verdict is ⚪.
- EXIF is input to the signer, so the proofs show what the signed EXIF says, not that it is true. One impossibility is caught: a capture day that starts after the anchor (T1, with 1 h of clock skew) is shown as unproven.

### Trusted setup

Phase 1 comes from the public *Perpetual Powers of Tau* ceremony (PSE, 80 contributions); phase 2 is a single local contribution, enough for a demo. In production: a multi-party phase 2, or a proof system without a per-circuit setup (PLONK, Halo2).

## 13. Other features

- **Verifiable redaction.** The owner blacks out boxes; the covered tiles keep only their two leaf hashes in a new disclosure (`<tx>-r<n>`), under the same signed manifest and anchor. The verifier authenticates hidden tiles by hash, checks they are really black, and verifies the rest normally. Salts prevent brute-forcing hidden tiles.
- **Version chain.** Signing with `parent` = a previous anchor makes `op = edit`; the verifier shows the history back to the original capture.
- **RAW negative → reference JPEG** (`op = develop`), modelled on Apple Reference Image: the device signs its RAW, then its own JPEG development with the RAW as parent. 🟢 only if the chain verifies and both are signed by the same named device key.
- **Fast anchoring.** `/api/sign` with `wait=0` answers on submission; the verdict carries `pending` until the transaction is validated, and the page polls `/api/anchor/<tx>`.
- **Aggregated anchoring.** `BatchingLedger` queues N records (what each memo would have carried), then anchors their Merkle root in **one** transaction (leaf domain `VPB1`). Each photo keeps a receipt `{batch_tx, index, leaf, proof}`. Anyone can anchor a root, but cannot put a valid device signature or proof in it.
- **C2PA.** The published PNG carries a standard C2PA manifest (`c2pa.actions` + an `org.veripress.anchor` assertion with the tx hash and digest), signed by a local **test** certificate. It sits in the metadata, not the pixels, so the trees are unaffected. WhatsApp strips it: that is the gap VeriPress closes. At verification it is read from the uploaded bytes and shown as **information only**: anyone can forge a C2PA manifest pointing to any anchor, so the verdict never depends on it.
- **Public link** `/v/<entry_id>`: a read-only page that verifies the stored image, with social preview tags.

## 14. Stack

- **Backend:** Python, FastAPI, NumPy, Pillow (+ `pillow-heif`), `rawpy` (LibRaw), `trustmark` (PyTorch), `xrpl-py`, `cryptography` (Ed25519, P-256, ML-DSA-87), `c2pa-python`.
- **ZK:** circom 2, `snarkjs`, `circomlib` (Node ≥ 20). Compiled circuits and verification keys are committed: the backend runs without circom.
- **Front end:** a single HTML page served by FastAPI (vanilla JS, canvas, WebAuthn).
- **Network:** XRPL Testnet.
- **Tests:** 288 automated tests (`cd backend && uv run python -m pytest`), including dedicated security tests; the XRPL tests run against Testnet with `VERIPRESS_NET=1`.
