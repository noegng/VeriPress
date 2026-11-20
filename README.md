# TileProof

> Prove where an image comes from — and show exactly which parts changed — even after it has been compressed and shared on social media.

Built for **IXH26 – Italian XRPL Hackathon** (Bari, 20–21 Nov 2026), **Track 1: Advanced cryptography for blockchain**.

_Working name — rename freely._

---

## The problem

- AI-generated and edited images are now indistinguishable from real photos.
- The current industry standard (**C2PA / Content Credentials**) stores provenance in file metadata — which social networks routinely **strip**.
- Its trust model (trust lists, manifest repositories) is **centralized**.
- Signatures over the whole file break on the first recompression, and say nothing about *what* changed.

## Our solution

1. **Sign at capture** — the phone signs the photo with a hardware-backed key (WebAuthn / passkey). An **XRPL Credential** certifies that the device (or a declared AI generator) is trusted; it can be revoked.
2. **Split into tiles** — the image is cut into 32×32 tiles, hashed into two Merkle trees:
   - an **exact** tree (raw pixel bytes) → proves the image is bit-for-bit untouched;
   - a **robust** tree (quantized low-frequency features per tile) → survives JPEG recompression, breaks on content edits.
3. **Anchor on XRPL** — Merkle roots + signature + commitment to metadata are recorded in an XRPL transaction: public timestamp, decentralized manifest registry.
4. **Watermark** — an invisible watermark in the pixels carries the XRPL anchor ID, so provenance survives metadata stripping. The robust tree binds the watermark to the content, so copying it onto another image is detected.

## Verdicts

| Verdict | Meaning |
|---|---|
| 🟢 **Real** | Signed by a credentialed capture device, content unchanged |
| 🟠 **Edited** | Heatmap shows exactly which tiles changed |
| 🔵 **AI-generated** | Signed by a credentialed AI generator |
| ⚪ **Unknown** | No provenance found (≠ fake) |

**Bonus — verifiable redaction:** blur a face, reveal only the other tiles with their Merkle proofs; the rest of the image stays verifiable against the original signature.

## Demo scenario

1. Take a photo → signed + anchored on XRPL → 🟢
2. Edit it in an editor → 🟠 red heatmap on edited tiles
3. Send it through WhatsApp (recompressed, metadata stripped) → provenance recovered via watermark, tiles still 🟢
4. Blur a face → redacted tiles shown black, rest verified
5. Copy the watermark onto a fake image → mismatch detected
6. Image from a credentialed AI generator → 🔵

## Why it's different

| | C2PA / existing tools | TileProof |
|---|---|---|
| Survives metadata stripping | Only via centralized lookup | Watermark → XRPL anchor |
| Shows *where* the image changed | No | Tile-level heatmap |
| Survives recompression | No (hard hash) | Robust tile tree |
| Redaction (e.g. blur faces) | No (pixel level) | Verifiable via Merkle proofs |
| Trust registry | Centralized trust list | XRPL Credentials (revocable, auditable) |

Designed to **complement** C2PA, not replace it.

## Honest limits

- We prove **origin**, not "not AI". No proof = unknown, not fake.
- The **analog hole**: photographing a screen with a trusted device still yields a "real" signature.
- Perceptual features are attackable → used for **lookup and localization only**, never as the authentication itself.
- Device keys can be extracted; mitigated (not solved) by hardware-backed passkeys + credential revocation.

## Docs

- [`docs/architecture.md`](docs/architecture.md) — components, data formats, XRPL usage
- [`docs/research.md`](docs/research.md) — prior art, limits, sources
- [`docs/plan.md`](docs/plan.md) — hackathon plan, roles, pitch outline

## Team

3 people — 2 developers, 1 business/pitch.
