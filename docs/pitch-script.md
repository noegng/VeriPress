# Pitch script

Spoken script for the jury pitch (8 slides): **3 min**, then **2 min of questions**. Slides: [`VeriPress-pitch.pptx`](VeriPress-pitch.pptx). The same text is in each slide's speaker notes.

Every point shown on a slide is spoken once, in the order it appears. The script is written for about **160 words per minute**. Words in *[square brackets]* are optional: drop them if a rehearsal runs long.

| # | Slide | From | To | Length | Words |
|---|---|---|---|---|---|
| 1 | VeriPress | 0:00 | 0:12 | 12 s | ~31 |
| 2 | Where provenance breaks | 0:12 | 0:23 | 11 s | ~30 |
| 3 | Who does what, and when | 0:23 | 0:36 | 13 s | ~35 |
| 4 | Signing and certifying a photo | 0:36 | 0:57 | 21 s | ~57 |
| 5 | Verifying a photo, without the original | 0:57 | 1:18 | 21 s | ~58 |
| 6 | The cryptography | 1:18 | 1:35 | 17 s | ~49 |
| 7 | **Live demo** | 1:35 | 2:50 | **1 min 15** | — |
| 8 | No single point of trust | 2:50 | 3:00 | 10 s | ~24 |

## Before going on stage

- The API runs on Testnet, started from `backend/`: `VERIPRESS_LEDGER=xrpl uv run uvicorn veripress.api:app --host 0.0.0.0`.
- The page is open at **http://localhost:8000**, in the browser that holds the Touch ID passkey, in **presentation mode** (press **P**).
- The demo files from `cli prepare-demo` are at hand (`demo/signed/RUNBOOK.md`): the photo to sign, its WhatsApp copy, the retouched copy, the AI image.
- One person speaks, the other drives the demo and the slides.

---

## 1 · VeriPress (0:00 – 0:12)

On screen: the app's masthead and home question, *Is this photo what it claims to be?*, the five-line lede, and the certificate of one real record anchored on Testnet (transaction, signers, SHA-256 digest, both Merkle roots, tiles, T0) with the app's **Real** seal.

> Hi, we're VeriPress. Is this photo what it claims to be? We answer with cryptography: Merkle-committed tiles, a hybrid post-quantum signature, an XRPL anchor. This certificate is real, and survives WhatsApp.

## 2 · Where provenance breaks (0:12 – 0:23)

On screen: the question, then three cards: metadata stripped, file hashes break, trust is central.

> Real, edited or AI? Once shared, nobody can tell.
> WhatsApp strips EXIF and C2PA.
> Recompression breaks any file signature.
> And trust is central: Apple's Reference Image hangs on Apple's servers.

## 3 · Who does what, and when (0:23 – 0:36)

On screen: the swimlane. Rows are actors (registry, device, ledger, store, anyone), columns are phases (setup, sign & anchor, verify). Sweep the rows, then the two phases.

> Your Apple diagram, on XRPL.
> Our registry gives each device a Credential. The device signs and anchors on the ledger, the disclosure goes to an untrusted store, and anyone verifies.
> Two phases. Let's zoom in.

## 4 · Signing and certifying a photo (0:36 – 0:57)

On screen: seven numbered steps; for each, the computation (blue, monospace) and what it proves. Point at the step numbers as you go.

> **Signing,** seven steps.
> Read the last ledger hash: T0. Embed a random 64-bit watermark id.
> Cut 32-pixel tiles, commit them in two salted Merkle trees: exact over RGB, robust over DCT coefficients.
> Hash the canonical manifest, sign it with Ed25519 **and** ML-DSA-87.
> Anchor it in an XRPL Payment Memo, closed at T1.
> Publish the disclosure by CID.

## 5 · Verifying a photo, without the original (0:57 – 1:18)

On screen: seven numbered steps, ending on the four verdicts in their colours.

> **Verifying** needs no original.
> Decode the watermark, find the record.
> The anchored digest must match the stored manifest: the store can't lie.
> Check both signatures, and the Credential **at T1**.
> Authenticate the published features against the robust root, then compare each tile: within 4.5 steps, a match; beyond, it lights up.
> First rule that fires: Real, Edited, AI or Unknown.

## 6 · The cryptography (1:18 – 1:35)

On screen: four annexes: commitments, signatures, zero-knowledge, XRPL trust layer. Annexes A, B and D were just walked through; spend the time on what is new.

> Under the hood: domain-separated leaves, HMAC salts, so redacted tiles leak nothing.
> The ML-DSA key hash sits in the Credential: the post-quantum half can't be stripped.
> And zero knowledge, Groth16 on BN254: anonymous signing in a Poseidon registry, and "taken on day D, within 10 km" without revealing GPS.

## 7 · Live demo (1:35 – 2:50, 1 min 15)

On screen: the four steps and their expected verdicts. Switch to the browser on *"Let's see it live."*

| Time | Action | Say |
|---|---|---|
| 0:00 – 0:20 | **Certify a photo**: drop it, sign and anchor on XRPL. | "This is a real XRPL Testnet transaction… **Certified**, with its seal." |
| 0:20 – 0:40 | **Examine a photo**: the copy that went through WhatsApp. | "Same photo after WhatsApp: no metadata, recompressed. VeriPress finds it through the invisible watermark: **still real**." |
| 0:40 – 0:55 | The retouched copy. | "Here we changed one detail. **Edited**, and the heatmap shows exactly which tiles." |
| 0:55 – 1:10 | The AI image. | "And an image from our declared AI generator: honestly labelled **AI-generated**, by its own signer." |
| 1:10 – 1:15 | Back to the slides. | "So, why a ledger?" |

If Testnet is slow, verify the pre-signed images instead of signing live. Only if ahead of time: anonymous ZK signing, or a revoked device whose earlier photo stays Real.

## 8 · No single point of trust (2:50 – 3:00)

On screen: Apple's three limits, each with our answer, then our limit and the closing line.

> Your three objections, answered: trust lives on XRPL, any device and verifier work, revocation looks forward. We prove origin, not truth. Thank you. Questions?

---

## Questions (2 min): ready answers

| Question | Answer |
|---|---|
| Robust features can be attacked? | Yes. They are used for **lookup and localisation only**. Authentication is the signature plus the Merkle roots. The verifier never compares robust hashes: it authenticates the published features with the root, then compares distances per tile. |
| What if someone copies the watermark onto another picture? | The tiles don't match that record, so the verdict is **Unknown, "copied watermark?"**, not Real. |
| Is it post-quantum? | The manifest signature is hybrid (ML-DSA-87). Not yet post-quantum: Groth16 soundness on BN254, P-256 passkeys, XRPL account signatures. The ledger timeline still prevents back-dating a forged signature. |
| Trusted setup? | Phase 1 from the public Perpetual Powers of Tau (80 contributions). Phase 2 is a single local contribution, demo only. Production: a multi-party phase 2, or PLONK / Halo2. |
| Can a ZK proof be replayed? | No. The EdDSA signature checked in the circuit covers the digest, so no nullifier is needed. Proof ~2 s, bundle 906 bytes. |
| Merkle tree pitfalls? | 0x00 / 0x01 prefixes for leaves and nodes, the tile index inside the leaf, and an odd node promoted, never duplicated (CVE-2012-2459). |
| Fine details after JPEG? | After JPEG, Real vouches for each tile's shapes and colours, not every fine detail. A lossless copy catches everything. |
| The device key? | In the demo the device key is a software key on the server; the passkey on the laptop is hardware-backed. In production the camera sensor signs the RAW. |
| Analog hole? | A trusted camera filming a screen still signs. We prove origin, not truth. |
| Many photos? | One transaction anchors a Merkle root of N records; each photo keeps its receipt. |
| C2PA? | The published PNG carries a standard C2PA manifest pointing to the anchor. It is shown as information only, because anyone can forge one. |
