# Hackathon plan

**Deadline:** final submission **Sat 21 Nov, 12:00** — pitches 12:30.

## Roles

| Who | Focus |
|---|---|
| Dev 1 | Backend: Merkle trees, robust features, XRPL anchoring & Credentials, TrustMark |
| Dev 2 | Frontend: capture (WebAuthn), verifier UI, heatmap + tree view, demo flow |
| Business/pitch | Mentor questions, problem sizing, pitch & slides, jury Q&A prep, submission form |

## Milestones

| When | Goal |
|---|---|
| Fri evening | Repo + docs ✅ · tiling + exact/robust Merkle trees · XRPL Devnet setup script (registry, credentials) |
| Fri night | Anchor + verify end-to-end (🟢 / 🟠 heatmap) · robust tree calibrated on JPEG recompression |
| Sat early morning | Watermark (TrustMark) · redaction · AI-generator credential · WebAuthn (fallback Ed25519) |
| Sat 10:00 | **Feature freeze** — record backup demo video, rehearse pitch |
| Sat 12:00 | Submit |

## Priority (cut from the bottom if late)

1. Merkle tiles + XRPL anchor + verifier heatmap (**must**)
2. Robust tree surviving recompression (**must**)
3. XRPL Credentials for devices / AI generator (**must**)
4. Watermark lookup + anti-copy
5. Verifiable redaction
6. WebAuthn hardware signing
7. Aggregated anchoring / Batch

## Pitch outline (≈3–5 min)

1. Hook: a real vs edited vs AI image — "which one is real?"
2. Problem: provenance dies when metadata is stripped; trust is centralized.
3. Solution: TileProof in 4 steps.
4. **Live demo** (capture → edit → WhatsApp → redact → watermark copy → AI).
5. Why it's different (comparison table vs C2PA).
6. Honest limits + future work (ZK edits).
7. Ask / close.

## Open questions for mentors

- Is Devnet stable for the demo tomorrow? Any reset planned?
- Track 1 details from the slides: required dataset/format/constraints?
- Pitch length, Q&A, submission format (repo / video / slides)?
