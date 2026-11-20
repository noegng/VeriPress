# Research: prior art, limits, positioning

## Prior art

| Approach | Who | Notes |
|---|---|---|
| Sign at capture + anchor on-chain | **Numbers Protocol** (Capture app, IPFS + chain, co-author of ERC-7053), **Starling Lab** (Stanford/USC, Reuters Capitol riot archive) | The base idea "hash the photo on a blockchain" is not new |
| Signed metadata + edit chain | **C2PA / Content Credentials** (Adobe, Microsoft, camera makers, AI labs) | Industry standard; manifest embedded in the file |
| Recover provenance after stripping | C2PA **soft binding**: watermark (Adobe **TrustMark**) or fingerprint → lookup in a manifest repository | Repository typically centralized (Content Credentials Cloud); spec acknowledges collision attacks on soft bindings |
| ZK proofs of allowed edits | PhotoProof (2016), ZK-IMG (2022), **VerITAS** (Datta, Chen, Boneh, 2024), HyperVerITAS & ZK-JPEG (2026), zkIPV | Strong but heavy (minutes per image); JPEG robustness only recently addressed |
| Perceptual hashing | pHash, PDQ, PhotoDNA, NeuralHash, ISCC (ISO 24138) | Known collision & evasion attacks |

**Takeaway:** "hash + blockchain" alone scores low on innovation. Our differentiation is in the implementation:

1. Tile-level **semi-fragile Merkle tree** → localization of edits that survives recompression.
2. **Verifiable redaction** at pixel/tile level (redactable-signature style).
3. **XRPL as decentralized manifest repository**, bound to content via watermark + robust tree (anti watermark-copy).
4. **Decentralized device/AI-generator PKI** with XRPL Credentials (revocable, not retroactively).
5. **Zero-knowledge proofs** on top of it: anonymous device attestation (the photo comes from *an* accredited device, not which one) and selective disclosure of capture time and place.
6. **Hardware-backed signing in the browser** (WebAuthn passkey) — no native app; hybrid post-quantum signature (ML-DSA-87).

## Limits (prepare answers for the jury)

1. **Analog hole** — re-photographing a screen. Unsolved by any provenance system; mitigations: depth sensors, liveness, out of scope.
2. **Absence of proof ≠ AI** — we prove origin, we don't detect AI.
3. **Recompression** breaks exact hashes → robust tree; trade-off between robustness and sensitivity (threshold tuning).
4. **Perceptual features are attackable** → used for lookup/localization only, never as the authenticator; the signature over the exact root is the authenticator.
5. **Watermark copy** → bound to robust tree in the anchor.
6. **Key extraction** → hardware keys + credential revocation; still a trust assumption on the device registry. In the demo the "device" key is a software key on the server (or a laptop passkey).
7. **Privacy** → only commitments on-chain; anonymous mode hides which device signed; capture time and GPS proven as coarse claims (day, ~10 km) in zero knowledge; salted leaves.
8. **Scale / cost** → done: many manifests per transaction (Merkle root of the batch), since the Batch amendment is not on Testnet.
9. **Lookup without watermark** → needs an off-chain indexer (XRPL has no similarity search).
10. **Trusted setup** of the Groth16 circuits → single local phase-2 contribution for the demo; multi-party ceremony or PLONK / Halo2 in production.

Full threat model and review: [`security-review.md`](security-review.md).

## Future work

- ZK proof that a published image is a crop/resize/JPEG of a signed original (VerITAS / ZK-JPEG style).
- Fuller C2PA interop: we already embed a C2PA manifest pointing to the XRPL anchor (test certificate); next is a trust-list certificate and a standard VeriPress assertion.
- Confidential MPT / commitments for private ownership of provenance records.
- Sensor-level signing of the RAW (as in Apple Reference Image), instead of a server key or passkey.

## Sources

- C2PA Soft Binding API — https://c2pa.org/specifications/specifications/2.2/softbinding/Decoupled.html
- Adobe CAI Soft Binding / TrustMark — https://developer.adobe.com/cai-soft-binding-api
- Durable Content Credentials — https://softwareseni.com/durable-content-credentials-how-provenance-survives-metadata-stripping
- C2PA limits — https://www.softwareseni.com/how-c2pa-content-credentials-work-and-what-their-limits-are/
- Media Integrity and Authentication (2026) — https://www.alphaxiv.org/abs/2602.18681
- Numbers Protocol — https://techcrunch.com/2021/01/12/numbers-protocols-blockchain-camera-capture-app-safeguards-the-integrity-of-photos/
- Starling Lab — https://venturebeat.com/business/project-starling-uses-technology-to-preserve-authenticity-of-capitol-riot-images
- ZK-IMG — https://arxiv.org/pdf/2211.04775
- VerITAS — https://eprint.iacr.org/2024/1066
- ePrint 2026/641 — https://eprint.iacr.org/2026/641
- ePrint 2026/2039 — https://eprint.iacr.org/2026/2039
- zkIPV — https://dspace.isical.ac.in/items/5b20029b-e700-43b7-b6e9-6f1d69fca871
- Learning to Break Deep Perceptual Hashing — https://github.com/ml-research/Learning-to-Break-Deep-Perceptual-Hashing
- Deep hashing not robust — https://cpg.doc.ic.ac.uk/blog/deephash-not-robust-to-detection-avoidance
- USENIX Security 2025 (Zhang et al.) — https://www.usenix.org/system/files/usenixsecurity25-zhang-yushu.pdf
- XRPL 3.3.0 release — https://xrpl.org/blog/2026/xrpld-3.3.0
