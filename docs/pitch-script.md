# Pitch script

Spoken script for the jury pitch: **3 min**, then **2 min of questions**. Slides: [`VeriPress-pitch.pptx`](VeriPress-pitch.pptx). The same text is in each slide's speaker notes.

Every point shown on a slide is spoken once, in the order it appears. The script is written for about **160 words per minute**. Words in *[square brackets]* are optional: drop them if a rehearsal runs long.

| # | Slide | From | To | Length | Words |
|---|---|---|---|---|---|
| 1 | VeriPress | 0:00 | 0:06 | 6 s | ~17 |
| 2 | Where provenance breaks | 0:06 | 0:22 | 16 s | ~43 |
| 3 | Who does what, and when | 0:22 | 0:53 | 31 s | ~82 |
| 4 | The cryptography | 0:53 | 1:33 | 40 s | ~107 |
| 5 | **Live demo** | 1:33 | 2:48 | **1 min 15** | — |
| 6 | No single point of trust | 2:48 | 3:00 | 12 s | ~32 |

## Before going on stage

- The API runs on Testnet, started from `backend/`: `VERIPRESS_LEDGER=xrpl uv run uvicorn veripress.api:app --host 0.0.0.0`.
- The page is open at **http://localhost:8000**, in the browser that holds the Touch ID passkey, in **presentation mode** (press **P**).
- The demo files from `cli prepare-demo` are at hand (`demo/signed/RUNBOOK.md`): the photo to sign, its WhatsApp copy, the retouched copy, the AI image.
- One person speaks, the other drives the demo and the slides.

---

## 1 · VeriPress (0:00 – 0:06)

On screen: the tagline, the three steps *Sign · Share · Verify*, the tiled photo stamped *Real · anchored on XRPL*.

> Hi, we're VeriPress: sign a photo, share it anywhere, and anyone can still verify it on XRPL.

## 2 · Where provenance breaks (0:06 – 0:22)

On screen: the question, then three cards: metadata stripped, file hashes break, trust is central.

> Real, edited or AI? Once shared, nobody can tell.
> **One:** WhatsApp strips the EXIF and the C2PA manifest.
> **Two:** recompression breaks any signature over the file, which can't say what changed.
> **Three:** trust is central: Apple's Reference Image hangs on Apple's CAs and servers.

## 3 · Who does what, and when (0:22 – 0:53)

On screen: the swimlane. Rows are actors (registry, device, ledger, store, anyone), columns are phases (setup, sign & anchor, share & verify). Point at each box as you name it.

> Your Apple diagram, on XRPL.
> **Setup:** our registry issues each device a Credential with its key hashes; the device accepts it.
> **Phase one:** the device takes the last ledger hash as T0, watermarks, builds Merkle roots, signs with ML-DSA too, and anchors the digest in a Payment Memo, closed at T1. The disclosure goes to an untrusted store, by CID.
> **Phase two:** anyone reads the watermark, looks up the record, checks validity at T1, gets a per-tile verdict.
> Revocation is never retroactive.

## 4 · The cryptography (0:53 – 1:33)

On screen: four cards: commitments, signatures, zero-knowledge, XRPL trust layer.

> Under the hood.
> **Commitments:** two salted Merkle trees per image. Exact, over raw RGB bytes: untouched pixels. Robust, over 21 quantised DCT coefficients per tile: survives JPEG, pinpoints edits. HMAC salts: redacted tiles leak nothing.
> **Signatures:** Ed25519, the device's XRPL key, plus ML-DSA-87 *[, FIPS 204,]* attested in the Credential so it can't be stripped. Or a Touch ID passkey.
> **Zero knowledge,** Groth16 on BN254: anonymous signing as a member of a Poseidon registry rooted on XRPL, and claims like "taken on day D, within 10 km", without revealing time or GPS *[: 14,578 and 1,295 constraints]*.
> **XRPL:** Credentials replace the CA and CRL, validity is read at anchor time, and T0, T1 bound the signing.

## 5 · Live demo (1:33 – 2:48, 1 min 15)

On screen: the four steps and their expected verdicts. Switch to the browser on *"Let's see it live."*

| Time | Action | Say |
|---|---|---|
| 0:00 – 0:20 | **Sign** tab: drop the photo, *Sign & anchor on XRPL*. | "This is a real XRPL Testnet transaction… **Real**. Here's the chain of evidence: accredited device, post-quantum signature, signed between these two ledger times." |
| 0:20 – 0:40 | **Verify** tab: the copy that went through WhatsApp. | "Same photo after WhatsApp: no metadata, recompressed. VeriPress finds it through the invisible watermark: **still real**." |
| 0:40 – 0:55 | The retouched copy. | "Here we changed one detail. **Edited**, and the heatmap shows exactly which tiles." |
| 0:55 – 1:10 | The AI image. | "And an image from our declared AI generator: honestly labelled **AI-generated**, by its own signer." |
| 1:10 – 1:15 | Back to the slides. | "So, why a ledger?" |

If Testnet is slow, verify the pre-signed images instead of signing live. Only if ahead of time: anonymous ZK signing, or a revoked device whose earlier photo stays Real.

## 6 · No single point of trust (2:48 – 3:00)

On screen: Apple's three limits, each with our answer, then the closing strip.

> Your three objections, answered: trust lives on XRPL, any device and verifier work, revocation looks forward. About 290 tests, end to end on Testnet. We prove origin, not truth. Thank you. Questions?

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
