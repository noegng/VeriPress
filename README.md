# VeriPress

> Prove where an image comes from — and show exactly which parts changed — even after it has been compressed and shared on social media.

Built for **IXH26 – Italian XRPL Hackathon** (Bari, 20–21 Nov 2026), **Track 1: Advanced cryptography for blockchain**.

---

## The problem

- AI-generated and edited images are now indistinguishable from real photos.
- The current industry standard (**C2PA / Content Credentials**) stores provenance in file metadata — which social networks routinely **strip**.
- Its trust model (trust lists, manifest repositories) is **centralized**.
- Signatures over the whole file break on the first recompression, and say nothing about *what* changed.

## Our solution

1. **Sign** — the image is signed by a device key accredited on XRPL: a named Ed25519 key, a hardware passkey (WebAuthn, Touch ID), or **anonymously** with a zero-knowledge proof that *some* accredited device signed it. An **XRPL Credential** certifies that the device (or a declared AI generator) is trusted; it can be revoked, without affecting photos anchored before. Optional hybrid post-quantum signature (ML-DSA-87).
2. **Split into tiles** — the image is cut into tiles (~1/40 of the long side, at least 32 px), hashed into two salted Merkle trees:
   - an **exact** tree (raw pixel bytes) → proves the pixels are untouched;
   - a **robust** tree (quantized low-frequency DCT features per tile) → survives JPEG recompression and resizing, breaks on content edits.
3. **Anchor on XRPL** — the hash of the signed manifest (both roots, watermark id, metadata commitment, ledger time T0…) goes into an XRPL Testnet transaction: public timestamp, decentralized manifest registry. Many photos can share one transaction.
4. **Watermark** — an invisible watermark (Adobe TrustMark) in the pixels carries a random 64-bit lookup id committed in the signed manifest, so provenance survives metadata stripping. The robust tree binds the watermark to the content, so copying it onto another image is detected. It is only a pointer: the verdict comes from the signature and the Merkle roots, and the unwatermarked original verifies too.
5. **Prove facts, not data** — zero-knowledge proofs show "taken on 20 Nov 2026" and "within ~10 km of …" without publishing the exact time or GPS position.

## Verdicts

| Verdict | Meaning |
|---|---|
| 🟢 **Real** | Signed by a credentialed capture device, content unchanged (even after recompression) |
| 🟠 **Edited** | Heatmap shows exactly which tiles changed, or a signed edit of a known original |
| 🔵 **AI-generated** | Signed by a credentialed AI generator |
| ⚪ **Unknown** | No valid provenance found (≠ fake) |

**Verifiable redaction:** black out a face; hidden tiles stay authenticated by hash only, and the rest of the image still verifies against the original signature.

## Demo scenario

1. Sign a photo → anchored on XRPL → 🟢
2. Edit it → 🟠 red heatmap on the edited tiles
3. Send it through WhatsApp (recompressed, metadata and C2PA stripped) → provenance recovered via the watermark, 🟢
4. Redact a region → hidden tiles shown black, the rest verified
5. Copy the watermark onto a fake image → mismatch detected, ⚪
6. Image from a credentialed AI generator → 🔵
7. Anonymous signing (zero-knowledge) → 🟢 "accredited device, anonymous"
8. Proven claims: capture day and ~10 km area
9. RAW negative → signed reference JPEG → 🟢
10. Revoke the device → photos anchored before stay 🟢

## Why it's different

| | C2PA / existing tools | VeriPress |
|---|---|---|
| Survives metadata stripping | Only via centralized lookup | Watermark → XRPL anchor |
| Shows *where* the image changed | No | Tile-level heatmap |
| Survives recompression | No (hard hash) | Robust tile tree |
| Redaction (e.g. blur faces) | No (pixel level) | Verifiable via Merkle proofs |
| Trust registry | Centralized trust list | XRPL Credentials (revocable, auditable, not retroactive) |
| Signer privacy | Signer identity in the manifest | Optional zero-knowledge device attestation |
| Capture metadata | Published or removed | Committed; coarse claims proven in zero knowledge |

Designed to **complement** C2PA, not replace it: the published PNG also carries a standard C2PA manifest pointing to the XRPL anchor.

## Run it

```bash
cd zk && npm ci                                   # once (ZK tool)
cd backend
uv run python -m pytest                           # 288 tests
uv run python -m veripress.cli demo photo.jpg -o out/   # demo scenarios, offline
uv run python scripts/setup_testnet.py            # keys, XRPL Testnet accounts, Credentials, registry
VERIPRESS_LEDGER=xrpl uv run uvicorn veripress.api:app  # → http://localhost:8000
```

Without `VERIPRESS_LEDGER`, the API runs on an in-memory ledger that trusts the keys in `backend/keys/`. The first watermark use downloads the TrustMark models (~3 min).

## Honest limits

- We prove **origin**, not "not AI". No proof = unknown, not fake.
- The **analog hole**: photographing a screen with a trusted device still yields a "real" signature.
- Perceptual features are attackable → used for **lookup and localization only**, never as the authentication itself.
- After JPEG, 🟢 vouches for each tile's shapes, colours and coarse texture, not for every fine detail: blurring something as small as a licence plate still passes once the image is shared (in a lossless copy, it is detected). See [`docs/security-review.md`](docs/security-review.md#adversarial-review-night-of-2021-nov).
- Device keys can be extracted; mitigated (not solved) by hardware-backed passkeys + credential revocation. In the demo, the "device" key is a software key on the server.
- The Groth16 trusted setup uses a single local phase-2 contribution (demo only).

## Docs

- [`docs/architecture.md`](docs/architecture.md) — how it works: tiles, Merkle trees, signatures, XRPL, ZK, verification
- [`docs/interfaces.md`](docs/interfaces.md) — modules, HTTP API, on-ledger and data formats
- [`docs/security-review.md`](docs/security-review.md) — threat model, what holds, known limits
- [`docs/decisions.md`](docs/decisions.md) — design decisions and why
- [`docs/research.md`](docs/research.md) — prior art, limits, sources
- [`docs/plan.md`](docs/plan.md) — status, demo, pitch outline, future work
- [`zk/README.md`](zk/README.md) — zero-knowledge circuits
- [`docs/fr/`](docs/fr/) — simplified guide in French (team)

## Team

2 developers - 1 idea

## AI usage

AI tools were used to build this project, as allowed by the track rules with full transparency: see [`AI-USAGE.md`](AI-USAGE.md).
