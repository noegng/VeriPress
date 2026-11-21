# Plan and status

**IXH26, Track 1 (Advanced cryptography for blockchain).** Feature freeze Sat 21 Nov 10:00 · submission 12:00 · pitches 12:30.

## Team

| Who | Focus |
|---|---|
| Dev A | Trust and verification: tiling, Merkle trees, robust features, pipeline and verdicts, watermark, ZK circuits, metadata proofs, C2PA, passkey verification, post-quantum signature, batching |
| Dev B | Registry and interface: XRPL Testnet (`XrplLedger`, setup script), FastAPI API, web page and visualisations, public link, passkey page |
| Business / pitch | Problem sizing, business model ([`business-model_fr.md`](business-model_fr.md)), slides, jury Q&A, submission |

How the two developers worked in parallel without conflicts: [`team-rules.md`](team-rules.md) (internal, in French).

## What is implemented

Everything below runs end to end on **XRPL Testnet** and is covered by automated tests (288).

| Feature | Status |
|---|---|
| Adaptive tiles, exact + robust Merkle trees, salted leaves | ✅ |
| Robust tree calibrated on real iPhone photos sent through WhatsApp | ✅ |
| Signing and anchoring (Payment + Memo), Credentials `CAPTURE_DEVICE` / `AI_GENERATOR` | ✅ |
| Verdicts 🟢 🟠 🔵 ⚪ with tile heatmap and Merkle tree ↔ image view | ✅ |
| TrustMark watermark (64-bit id), copied-watermark detection, pHash fallback | ✅ |
| Unwatermarked original also verifies (dual commitment) | ✅ |
| Verifiable redaction | ✅ |
| Version chain (`parent`), RAW negative → reference JPEG (`develop`) | ✅ |
| Formats: HEIC, 16-bit TIFF/PNG, camera RAW (LibRaw), ICC → sRGB | ✅ |
| ZK anonymous device attestation (Groth16, Poseidon registry on XRPL) | ✅ |
| Non-retroactive revocation (named and anonymous) | ✅ |
| ZK capture metadata: "taken on day D", "within ~10 km of …" | ✅ |
| Passkey (WebAuthn P-256, Touch ID), attested by the registry | ✅ (demo on the laptop) |
| Hybrid post-quantum signature Ed25519 + ML-DSA-87 | ✅ |
| Time window [T0, T1] from XRPL ledger hashes | ✅ |
| Fast anchoring (`pending`), public link `/v/<tx>` with social previews | ✅ |
| Content-addressed disclosures (IPFS CID in the signed manifest) | ✅ (served by our API, no real pinning) |
| Aggregated anchoring (N photos, 1 transaction) | ✅ |
| C2PA manifest in the published PNG, read back at verification | ✅ (test certificate, information only) |

## Demo scenario

Assets are re-signed on Testnet with `uv run python -m veripress.cli prepare-demo --raw <file.CR3>`, which writes the live run sheet to `demo/signed/RUNBOOK.md`.

1. Signed photo → 🟢
2. Retouched copy → 🟠 with the heatmap on the edited tiles
3. Copy sent through WhatsApp (recompressed, metadata stripped, C2PA gone) → found by the watermark, 🟢
4. Redacted copy → hidden tiles shown black, the rest 🟢
5. Watermark copied onto another picture → ⚪ "copied watermark?"
6. AI-generated image signed by the `AI_GENERATOR` → 🔵
7. Anonymous signing (zero-knowledge) → 🟢 "accredited device (anonymous)"
8. Proven claims: "taken on 20 Nov 2026", "within ~10 km of the capture place (Bari)", without revealing the exact time or GPS
9. RAW negative → reference JPEG → 🟢
10. Device revoked after anchoring → the earlier photo stays 🟢 "revoked since …"
11. Batch: several photos, one transaction

## Pitch outline (≈ 3–5 min)

Final deck and spoken script (3 min, demo 1 min 15): [`VeriPress-pitch.pptx`](VeriPress-pitch.pptx), [`pitch-script.md`](pitch-script.md).

1. Hook: a real, an edited and an AI image: "which one is real?"
2. Problem: provenance dies when metadata is stripped; trust is centralised; a hash breaks on recompression.
3. Solution in four steps: sign, tile, anchor on XRPL, watermark.
4. Live demo.
5. Comparison with C2PA.
6. Honest limits and future work.
7. Close.

## Future work

- A camera sensor that signs the RAW itself (today: server key or laptop passkey).
- ZK proof that a published image is a crop / resize / JPEG of a signed original (VerITAS, ZK-JPEG style).
- Passkey + anonymous mode (P-256 inside the circuit); proofs generated in the browser.
- On-demand metadata claims (requires authenticating the owner).
- Multi-party trusted setup, or PLONK / Halo2.
- Real IPFS pinning; C2PA certificate from the C2PA trust list; VeriPress data as a C2PA assertion standard.
- Attestations read at anchor time everywhere (`at_time`), own XRPL node or cross-checked nodes.
