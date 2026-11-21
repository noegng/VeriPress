# Design decisions

Record of the team's design sessions (structured question-and-answer sessions with Claude Code, see [`../AI-USAGE.md`](../AI-USAGE.md)). For each question: what was decided, why when useful, and what came of it. Formats are in [`interfaces.md`](interfaces.md); the resulting design is in [`architecture.md`](architecture.md).

---

## Session 1: demo scope (Fri 20 Nov, morning)

| # | Question | Decision | Outcome |
|---|---|---|---|
| 1 | Demo steps to keep | 1 photo 🟢, 2 edit 🟠 + heatmap, 3 WhatsApp, 6 AI image 🔵; 4 redaction if time allows; 5 (copied watermark) depends on the watermark | All six steps done |
| 2 | TrustMark watermark | Do it if possible, with a perceptual-hash fallback | Done, with the fallback |
| 3 | Signing at capture | Software Ed25519 first, real passkey later if time allows | Passkey done (session 2, Q21–Q23) |
| 4 | XRPL network | **Testnet**: more stable than Devnet, Credentials active | Kept |
| 5 | Anchor format | Payment of 1 drop + Memo `veripress/v1` | Kept, extended for the anonymous, passkey and batch modes |
| 6 | Front end | A single page served by FastAPI; Merkle tree ↔ image views as an option | Done, views included |
| 7 | WhatsApp during the demo | Image prepared in advance, plus a backup video: the venue network is unreliable | Kept |
| 8 | Where to use test-driven development | Only on Merkle trees / redaction proofs and the final verdict rules | Kept; ~300 tests in the end |
| 9 | Work split | Dev A: trust and verification (signature, pipeline, verdict, store, watermark). Dev B: registry and interface (XRPL, API, page, visualisations) | Kept |
| 10 | Contracts before coding | `ledger.py` with a `FakeLedger`, and `interfaces.md`, written before splitting up | Kept |
| 11 | Git | Branches `dev-a/*` / `dev-b/*`, each developer writes only to their own files | Kept; pull requests from Friday afternoon |
| 12 | Where the disclosure lives | Local `store/` indexed by tx hash (production: IPFS or hosted by the owner) | Kept, plus content addressing (Q9) |
| 13 | Finding an image without a watermark | 64-bit perceptual hash, nearest neighbour | Kept |
| 14 | Order of options | Watermark → redaction in the page → tree ↔ image view → passkey → version chain | All done |
| 15 | AI image | Generated in advance, signed by a key holding the `AI_GENERATOR` Credential | Done |
| 16 | Version chain (`parent`) | Optional, last | Done |

### Decisions taken along the way

| Topic | Decision |
|---|---|
| Calibration | On real iPhone photos sent through WhatsApp: adaptive tile size (~1/40 of the long side, replacing the fixed 32 px), ICC → sRGB conversion, resampling without clipping, weight 0.5 on the DC coefficient |
| Professional formats | 16-bit scaled to 8 bits, RAW via LibRaw (`rawpy`), `load_upload` as the API entry point. JPEG XL left out |
| Unwatermarked original | **Dual commitment**: each robust leaf commits the watermarked version **and** the original; a tile matches if it is close to either. Chosen over re-watermarking at verification, which would have put a neural network in the verdict (adversarial inputs, version dependence) |
| Watermark id | Random 64-bit id chosen at signing and committed in the manifest (the first plan derived it from the tx hash, which is only known after anchoring, while the watermark must be in the pixels before committing) |
| Architecture review | A two-axis code review (standards, spec) rather than a large refactoring pass |

---

## Session 2: phase 2 (Fri 20 Nov, afternoon)

### Round 1: scope and order

| # | Question | Decision | Outcome |
|---|---|---|---|
| Q1 | Order (whatever is not done at the 10:00 freeze becomes future work) | 1 ZK anonymous attestation · 2 non-retroactive revocation · 3 public link `/v/<tx>` · 4 ZK metadata · 5 fast anchoring · 6 C2PA · 7 passkey · 8 content-addressed storage · 9 aggregated anchoring | All nine done |
| Q2 | Keys for ZK | Each device also gets a **Baby Jubjub** key (EdDSA-Poseidon, circuit-friendly). The registry publishes on XRPL the root of a Poseidon Merkle tree of accredited keys. The Ed25519 key keeps the named mode | Done |
| Q3 | Anonymous mode | The anchor carries neither the device key nor its signature, only the digest, the registry root and the hash of the proof. Verdict 🟢 "accredited device (anonymous)". Chosen at signing ("Sign anonymously" box) | Done |
| Q4 | Valid root | A proof is accepted if its root **was in force at anchor time**. Revoking = publishing a new root, so revocation is not retroactive in anonymous mode either | Done |
| Q5 | Non-retroactive revocation (named mode) | Revocation date read from the `CredentialDelete` in the registry history. Photo anchored before: 🟢 + "device revoked since …"; after: ⚪ | Done |
| Q6 | Where proofs are generated | Server side (Node + snarkjs called from Python); in the browser as an option | Server side |
| Q7 | ZK toolchain | circom (built with cargo), snarkjs + circomlib in `zk/`; compiled circuit and verification key committed; Hermez/PSE powers of tau (production: multi-party phase 2) | Done |
| Q8 | Aggregated anchoring | Without the Batch amendment (not on Testnet): Merkle tree of N records, anchor the root, each photo keeps its inclusion proof | Done |
| Q9 | Decentralised storage | Disclosures are already self-authenticating. Compute an IPFS CID, put it in the signed manifest, serve the file from our API, no real pinning | Done (CID in the manifest rather than the memo) |
| Q10 | C2PA | C2PA manifest (`c2pa-python`) with a test certificate, said honestly | Done |
| Q11 | Fast anchoring | `/api/sign` answers on submission; the page shows "pending"; the verdict carries a `pending` flag | Done |
| Q12 | Split | Dev A: ZK, metadata, C2PA, pending status in the pipeline, server-side WebAuthn check. Dev B: revocation, public link, fast anchoring, registry roots, passkey page and routes. CID and batching: whoever is free first | Done (CID and batching by Dev A on the pipeline side, Dev B on the ledger side) |

### Round 2: ZK, metadata, contract, demo

| # | Question | Decision |
|---|---|---|
| Q13 | Nullifier | **None**: the manifest digest is a public input and the signature checked in the circuit covers it, so a proof cannot be replayed. The SHA-256 digest is split into two 128-bit halves |
| Q14 | Registry size | Depth 10 (1,024 devices); demo registry filled with ~20 fictitious devices. To say: anonymity grows with the number of devices |
| Q15 | `zk/` tool | Dev A delivers `keygen`, `root`, `prove`, `verify` (+ metadata). Dev B uses them in the setup script and publishes the root (memo `veripress/registry-root/v1`); `XrplLedger.registry_root_at(time)` |
| Q16 | Metadata commitment | At signing: EXIF `DateTimeOriginal` + GPS → `meta_commitment = Poseidon(unix time, lat×10⁶, lon×10⁶, salt)` in the signed manifest. Secret salt. No EXIF = no commitment |
| Q17 | Proven claims | Generated at signing: "taken on day D" (24 h) and "within a ~10 km area around …". Never the exact time or GPS. On-demand proofs = future work (would require authenticating the owner) |
| Q18 | JSON contract | `/api/verify`: `anonymous`, `zk`, `meta_claims`, `pending`, `credential_revoked_at`. `/api/sign`: `anonymous`. First phase-2 pull request, before the code |
| Q19 | Demo | New steps: anonymous signing, then the day and area claims |
| Q20 | C2PA and format | C2PA manifest in the metadata of the published PNG, not in the pixels, so the trees do not change. Pitch moment: "C2PA disappears after WhatsApp, VeriPress still finds the provenance" |

### Round 3: passkey and organisation

| # | Question | Decision |
|---|---|---|
| Q21 | Linking the passkey to the XRPL account | The registry **attests the passkey**: SHA-256 of the P-256 public key in the `URI` of the `CAPTURE_DEVICE` Credential. The server verifies the WebAuthn assertion (ECDSA P-256, `cryptography`). The URI format later moved from hex to base64url so it could also hold the ML-DSA key within XRPL's 128-byte limit |
| Q22 | HTTPS for the demo | Passkey shown **on the laptop** (localhost + Touch ID). HTTPS tunnel for the phone only if time remains |
| Q23 | Passkey + anonymous | Incompatible (a passkey cannot produce a Baby Jubjub key): passkey = named mode only. P-256 circuits = future work |
| Q24 | Public link `/v/<tx>` | Read-only page: published image, verdict, proven claims, explorer link, social preview tags |
| Q25 | Organisation | One pull request per feature, merged by its author once green, and announced. Sync points ~19:00, ~23:00, ~03:00, 08:00; freeze at 10:00 |

---

## Added after the Track 1 slides (Fri evening)

Inspired by Apple's *Reference Image* design, but anchored on a public ledger:

| Topic | Decision |
|---|---|
| Time window [T0, T1] | The manifest commits to the hash of the latest validated XRPL ledger (T0: signed after); the anchor's ledger close time is T1 |
| RAW negative → reference JPEG | `op = develop`: the device signs its RAW, then its own JPEG development with the RAW as parent; 🟢 only if both are signed by the same named device |
| Hybrid post-quantum signature | Ed25519 + **ML-DSA-87** (FIPS 204), key attested by the registry in the Credential URI; once declared in a manifest, the ML-DSA signature is mandatory (no downgrade); never in anonymous mode |
| Security review | One review per side (signature / pipeline, then XRPL / API), see [`security-review.md`](security-review.md) |
| Adversarial review (night of 20–21 Nov) | Attack our own system for real, then fix what passes, test first: colour and detail in the robust features (parameters in the signed manifest, first records still verify), lossless-copy rule, every candidate record verified, ML-DSA required when attested at anchor time, impossible capture dates rejected, stricter redaction in lossless copies. Detail: [`security-review.md`](security-review.md#adversarial-review-night-of-2021-nov) |
