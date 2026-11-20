# Architecture

## Overview

```
 ┌──────────────┐   sign (WebAuthn)   ┌──────────────┐   anchor tx    ┌──────────────┐
 │ Capture app  │ ──────────────────▶ │   Backend    │ ─────────────▶ │ XRPL Devnet  │
 │ (browser/TS) │   tiles + Merkle    │  (Python)    │   watermark    │ Credentials  │
 └──────────────┘                     └──────────────┘                │ Anchors      │
        ▲                                    ▲                        └──────────────┘
        │                                    │                               ▲
 ┌──────────────┐   upload image      ┌──────────────┐   read anchor        │
 │  Verifier UI │ ──────────────────▶ │  Verify API  │ ─────────────────────┘
 │ heatmap/tree │ ◀────────────────── │              │
 └──────────────┘   verdict + map     └──────────────┘
```

## 1. Tiling & Merkle trees

- Decode image to RGBA, split into **32×32 tiles** (edge tiles padded), row-major order.
- **Exact tree** — leaf = `SHA-256(0x00 || tile_index || raw_RGB_bytes)`.
- **Robust tree** — leaf = `SHA-256(0x00 || tile_index || robust_feature(tile))` where `robust_feature`:
  - convert to luminance, downscale tile to 8×8, 2D DCT, keep low-frequency coefficients (e.g. top-left 3×3 minus DC or including DC), coarse quantization;
  - stored alongside: the raw feature vector, so the verifier can compare with a **distance threshold** (not just hash equality) for localization after recompression.
- Internal node = `SHA-256(0x01 || left || right)` (domain separation against second-preimage attacks).
- Leaf index included to prevent tile reordering.

> Tuning knob: tile size and quantization step trade robustness (survive JPEG) vs sensitivity (detect small edits). To calibrate on a sample set during the hackathon.

## 2. Capture & signing

- Manifest (canonical JSON / CBOR):
  ```json
  {
    "v": 1,
    "width": 4032, "height": 3024, "tile": 32,
    "exact_root": "…", "robust_root": "…",
    "meta_commitment": "SHA-256(salt || EXIF/GPS/time)",
    "parent": null,            // anchor tx hash of parent version, if an edit
    "op": "capture",           // capture | crop | resize | redact | ai_generate | edit
    "signer": "<public key>"
  }
  ```
- Signature: **WebAuthn** assertion with `challenge = SHA-256(manifest)` (hardware-backed passkey). Fallback: Ed25519 software key for the demo.
- Metadata (GPS, timestamp, device) is **committed, not published** — revealed selectively by the owner.

## 3. XRPL usage (Devnet)

| Need | XRPL feature |
|---|---|
| Trusted devices / AI generators | `CredentialCreate` / `CredentialAccept` from a registry account (types: `CAPTURE_DEVICE`, `AI_GENERATOR`) |
| Revocation | `CredentialDelete` — verifier compares anchor time vs revocation |
| Anchor | Payment (1 drop to self/registry) with `Memos`: manifest hash, roots, signature; or one NFToken/MPT per image (URI → manifest) |
| Edit history | Each new anchor references `parent` anchor tx hash → version chain back to the genesis capture |
| Scaling (stretch) | Aggregate N manifests into one Merkle root per tx, or `Batch` |

Amendments checked live on 2026-11-20 via `feature` RPC: Credentials, PermissionedDomains, MPT, Batch, TokenEscrow active on Mainnet/Testnet/Devnet; Confidential MPT, Vault, Lending, Sponsor, DynamicMPT active on **Devnet only**. Library: `xrpl.js` 5.3.0 / `xrpl-py`.

## 4. Watermark (durable binding)

- Embed a short ID (e.g. 64–100 bits derived from the anchor tx hash) with **TrustMark** (Adobe, open source, Python).
- Verifier: extract ID → fetch anchor → recompute robust tree on the received image → compare.
- **Anti-copy**: a watermark pasted onto another image points to an anchor whose robust tree does not match → flagged.
- Fallback lookup when no watermark: perceptual hash of the whole image → off-chain indexer of anchors (honest limit: XRPL has no similarity search).

## 5. Verifiable redaction

- Owner publishes the image with some tiles blacked out, plus for each **revealed** tile its leaf data, and for each **hidden** tile only its leaf hash.
- Verifier recomputes the exact root from revealed tiles + hidden hashes → matches signed root → revealed tiles authenticated, hidden tiles never disclosed.
- Leaves salted per tile (`SHA-256(salt_i || …)`) so hidden tiles can't be brute-forced (e.g. low-entropy flat areas).

## 6. Verifier

1. Read watermark → anchor (or perceptual lookup).
2. Fetch manifest + signature, check signer's XRPL Credential (type, validity at anchor time).
3. Exact root match → 🟢. Else robust tile comparison → heatmap → 🟠. Signer is `AI_GENERATOR` → 🔵. Nothing found → ⚪.
4. Walk the `parent` chain to show the edit history.
5. **Merkle-tree-to-image view**: tile overlay (green intact / red changed / black redacted) + clickable tree up to the anchored root.

## Stack

- **Frontend**: TypeScript, Vite, canvas for tiling, WebCrypto + WebAuthn, `xrpl.js`.
- **Backend**: Python (FastAPI), `trustmark`, `xrpl-py`, Pillow/NumPy for DCT features.
- **Network**: XRPL Devnet (`wss://s.devnet.rippletest.net:51233`) — with a one-command setup script to recreate state if Devnet resets.
