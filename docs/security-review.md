# Security review

Three reviews were run before the feature freeze (Fri 20 Nov): one on the signature and verification side (Dev A, ~19:00), one on the XRPL and API side (Dev B, ~21:00), then an adversarial review that ran real attacks against the system (night of 20–21 Nov, § "Adversarial review"). This document merges them. Mechanisms are described in [`architecture.md`](architecture.md).

## Threat model

- The attacker controls the files they submit for verification, the **off-chain store**, and their own XRPL transactions: anyone can send a memo to the registry account.
- The attacker does **not** control the key of an accredited device, its attested passkey, or the registry account.
- The attacker may also be **a malicious accredited device** that bypasses our client.

## What holds (covered by tests)

### Signature and verification

| Property | Mechanism | Tests |
|---|---|---|
| A forged anchor is worthless | Each mode requires its proof, bound to the anchored digest: Ed25519 signature, Groth16 proof (digest as a public input), WebAuthn assertion (challenge = digest) | `test_pipeline`, `test_zk_anonymous`, `test_passkey` |
| The store is not trusted | Manifest = anchored digest; disclosure = signed Merkle roots; proof bundles = anchored hash | `test_*tampered*`, `test_manifest_swapped…` |
| No proof replay | ZK proof and assertion bound to the digest; proof bundle hashed in the anchor | `test_valid_proof_reanchored…`, `test_tampered_assertion_bundle…` |
| Non-retroactive revocation | Credential date (named mode) or registry root in force at anchor time (anonymous mode) | `test_device_revoked_*`, `test_revocation_after_anchoring…` |
| Honest redaction | A "redacted" tile must really be black; more than 50 % redacted → ⚪ | `test_fully_redacted_record…` |
| Passkey | Key = the one in the manifest and attested by the registry; challenge, type, origin, rpIdHash, user presence + verification, credential id | `test_invalid_assertions_are_refused` (5 cases) |
| Metadata claims | Proof bound to the commitment in the signed manifest; label recomputed from the public inputs; hidden when ⚪ | `test_zk_metadata` |
| Post-quantum | A manifest that declares an ML-DSA key requires its signature and attestation: deletion, tampering, key substitution and withdrawn attestation all fail | `test_post_quantum` |
| Copied watermark | Record found by watermark with more than half the tiles changed → ⚪ | `test_pipeline` |

### XRPL and API

No exploitable vulnerability found.

| Property | Mechanism | Tests |
|---|---|---|
| Registry root cannot be forged | Only `AccountSet` transactions **sent by the registry account** count; a `registry-root` memo from anyone else is ignored | `test_ledger_registry` |
| Credentials cannot be forged | `CredentialCreate` must come from the registry, `CredentialAccept` from the subject (after a Create); only validated `tesSUCCESS` transactions count | `test_ledger_revocation` |
| Attested keys (passkey, ML-DSA-87) | Read from the registry's `CredentialCreate` in force, in the history; a revocation does not erase the attestation (validity is judged by `credential_type(pk, t)`) | `test_ledger_pq` |
| T0 cannot be forged | `ledger_close_time` re-reads the validated ledger at that index and compares its hash; wrong hash, future or unvalidated ledger → none | `test_ledger_time_window`, Testnet |
| A batch root alone is worthless | Non-integer or ≤ 0 counts are ignored. A root anchored by a third party attests nothing: each receipt must contain a valid signature, ZK proof or passkey assertion | `test_ledger_batch`, `test_batch` |
| Unvalidated anchor | Timestamped at submission or now, never at an attacker-chosen date, so revocation is evaluated at the present time; verdict flagged `pending` | `test_fast_anchoring_flag_and_anchor_status` |
| Safe submission | No automatic resubmission (risk of double anchoring); sequence number under a lock | Testnet |
| Public page | JSON report in `<script>` with `<` escaped; Open Graph tags through `html.escape`; `innerHTML` only via `esc()` / `Number()`; `entry_id` checked by regex; C2PA shown as information only | `test_public_page_escapes_a_hostile_report`, `test_forged_c2pa_manifest_does_not_change_the_verdict` |
| Passkey registration | Localhost only (TCP peer; uvicorn trusts `X-Forwarded-For` only from 127.0.0.1). The route only writes a **candidate**: the operator attests it (`--passkey`) | `test_passkey_registration_is_localhost_only` |

## Findings fixed during the review

1. **The version chain only verified Ed25519 signatures** (medium). A parent signed anonymously or with a passkey was always "unverified", so a RAW signed with Touch ID and then developed to JPEG wrongly came out 🟠. → A single per-mode `_authenticate` function now serves the verdict **and** every step of the chain.
2. **Anonymous `develop`** (medium, revealed by fix 1). In anonymous mode both signers are `""`, so "same device" was true by construction: an accredited device bypassing our client could present someone else's anonymous RAW as its negative. → `develop` requires a named signer on both sides, at signing and at verification.
3. **Entry ids not validated in the store** (low). The `parent` of a signed manifest could point outside the store (`../`), read-only. → `store.valid_id`: only `hash` or `hash-rN`.

## Adversarial review (night of 20–21 Nov)

We attacked our own system with about twenty concrete forgeries, on a real 12 MP iPhone photo and on test images. No attack forged a signature, a proof or an anchor. Seven got a misleading verdict; all are fixed, each with a regression test in `tests/test_adversarial.py` (and `test_zk_metadata.py` for A8).

| # | Attack | Before | After | Fix |
|---|---|---|---|---|
| A1 | Recolour a region (red → cyan) keeping its luminance | 🟢 Real | 🟠 Edited | Robust features now include colour (Cb, Cr) |
| A2 | Blur a region (radius ≥ 5 px), then share as JPEG | 🟢 Real | 🟠 Edited | Robust features now include finer luminance detail (coefficients 10–14) |
| A2' | Subtle local edit (light blur, recolouring) in a lossless copy (PNG) | 🟢 Real | 🟠 Edited | If most textured tiles are byte-identical, the copy is lossless: a merely "close" tile is an edit |
| A5 | Check an unrelated picture against a real record's id (planted link) | 🟠 "edited version of a real photo" | ⚪ Unknown | "More than half the tiles changed → not this record's photo" applies however the record was found |
| A6 | Plant in the store, from public data only, a fake fully-redacted variant of a real photo (or re-list another real record) under the perceptual hash of the copy being shared | the **genuine** photo came out ⚪ or 🟠 | 🟢 Real | Every candidate record is verified; the best-supported one wins |
| A7 | Post-quantum downgrade: sign Ed25519 only, without declaring the ML-DSA-87 key the registry attests for the device | 🟢 Real | ⚪ Unknown | If the registry attested an ML-DSA key at anchor time, the ML-DSA signature is required; attestations are read at anchor time |
| A8 | Forged EXIF: capture date in 2031 for a photo anchored in 2026 | "taken on 1 Jun 2031" proven | shown as unproven | A capture day starting after the anchor (T1, 1 h of skew) is impossible |
| A9 | Dark grey text written inside a redacted (black) area of a lossless copy | 🟢 Real | 🟠 Edited | In a lossless copy, a redacted tile must be truly black |

Attacks that already failed: swapping red and blue, adding text (even 16 px), shifting a region by 6 px, filling a region with grey, tampering with the store without public data, replaying an anchor memo in another transaction (only gives a later timestamp). The `device.circom` circuit was re-read: `enabled = 1`, both digest halves range-checked to 128 bits, the key must be in the tree. The phase-2 entropy of the ZK setup came from `/dev/urandom` and was not stored.

Calibration after the fix: on the 4 iPhone photos (signed and original, real and simulated WhatsApp copies, found without id), no false edit; largest weighted distance 3.97 for a tolerance of 4.5. Records signed with the first feature set keep verifying with it (the parameters are in the signed manifest).

## External audit (21 Nov): `security-audit-fixes.md`

Five attacks were reported against the verdict logic; each now has a regression test that fails before the fix and passes after (`test_adversarial.py` § 8, `test_api.py`).

| ID | Attack | Before | After | Fix |
|---|---|---|---|---|
| F1 | Plant 8 records with the genuine pHash, sorted before it | ⚪ Unknown (genuine never checked) | 🟢 Real | No truncation of the candidates before verification; verification stops only at a perfect record |
| F2 | Drop one malformed `entry.json` in the store | HTTP 500 on every verification without id, and on `/api/lookup` | Record skipped | Total store parser (bad JSON, missing field, id ≠ folder); a candidate that cannot be read is unknown; the API answers 503, never a bare 500 |
| F3 | Capture anchored before its key was accredited, then "developed" after accreditation | 🟢 Real through the RAW chain | Not real | A version is verified only if its key was accredited at its anchor time, in every mode |
| F4 | +1 on every pixel switches off the pixel-based "lossless copy" guess, then a light blur | 🟢 Real | Not real | Strict mode comes from the **codec** of the uploaded file (PNG/TIFF/BMP… at the signed size), passed by the API; the pixel guess remains for tests and the CLI |
| F5 | Visible dark content painted under a redaction (+1) | 🟢 Real | 🟠 Edited | Same as F4: in a lossless file, redacted tiles must be truly black |
| F6 | Passkey attestation read in its latest state | Re-attesting could validate an older manifest or invalidate older photos | Read at anchor time | `credential_passkey(pubkey, at_time)` |

Strict mode and the unwatermarked original: a lossless copy of the original capture is not byte-identical to the signed (watermarked) pixels, but reproduces the committed original features to within their rounding (≤ 0.5 step measured on the pitch photo, against ≥ 0.73 for +1 or a light blur). When most tiles that have a distinct original version are reproduced that closely, strict mode keeps them; otherwise it is exact. The pitch photo's original exported as PNG stays 🟢.

Not done (decision for the team): an API rate limit / time budget, now that every candidate is verified (F1); in production the store must not be writable by anyone.

## Known limits, accepted and stated to the jury

- **Fine details after recompression.** A 🟢 after JPEG vouches for the content at the scale of a tile (~1/40 of the image), its colours and its coarse texture, not for every detail: a blur of radius ≤ 4 px, or blurring something as small as a licence plate, still passes once the image is shared as JPEG. After a platform downscales a 12 MP photo to 1,280 px, those details are gone from authentic copies too. In a lossless file (PNG, TIFF… at the signed size, decided from the codec, not from the pixels), any such edit is detected.
- **Faint content under a redaction in a lossy copy.** JPEG block noise on a black area reaches the level of faint dark-grey text, so in a lossy copy only the coarse "black" bounds apply. In a lossless file the area must be truly black.
- **EXIF is input.** The ZK claims prove what the signed EXIF says (only impossible future dates are caught). In production the camera writes and signs it.
- **No retroactive revocation.** Revocation never reaches back, by design. If a device key is stolen at time T and revoked later, photos forged in between stay 🟢. A "compromised since T" revocation (a dated CredentialDelete) is future work.
- **Registry account history.** Anchors are payments to the registry account, and anyone can send it transactions: verification downloads its whole history (cached a few seconds), so cost grows with every photo, and ~11 XRP of spam (1 million payments) would slow every verification. Production: a separate account to receive the anchors, `DepositAuth` on the registry, an indexer.
- **Single registry key.** Whoever holds the registry account can accredit any device. Production: an XRPL multi-signature `SignerList` on the registry.

- **C2PA** manifests can be forged by anyone to point to any anchor (our certificate is a test one). The page presents C2PA as **information**, never as proof; the verdict comes from VeriPress.
- **Demo device = the server.** `/api/sign` signs with the device's software key for anyone who reaches the server. On the venue Wi-Fi anyone could produce a 🟢 photo. In production the key lives in the camera sensor, or is the device's passkey. During the demo: do not show the server address, or bind to `127.0.0.1` when the phone is not needed.
- **Physical origin.** Signing happens on the server (software key) or with a passkey on the laptop; a sensor that signs the RAW itself, as Apple does, is future work. The **analog hole** (photographing a screen) affects every signature-based approach.
- **`device` circuit**: no domain separation between a leaf hash (`Poseidon(Ax, Ay)`) and an inner node hash. Not exploitable: the depth is fixed at 10 and the key must be a curve point. Planned hardening: `Poseidon(3)` with a domain tag.
- **Trusted setup**: public phase 1 (PSE, 80 contributions), single local phase-2 contribution. Production: multi-party ceremony, or PLONK / Halo2.
- **WebAuthn signature counter** not tracked (clone detection); synced Apple passkeys return 0 anyway. Verifiers must list the signing origins in `VERIPRESS_WEBAUTHN_HOSTS`.
- **Passkey attestation**: now read at anchor time, like the ML-DSA one (audit F6).
- **Public tunnel**: requests would then come from 127.0.0.1, so passkey registration would no longer be restricted to the machine. Do not open a tunnel while registering or attesting a passkey.
- **Trusted public Testnet node**, without state proofs: a malicious node could lie. Production: own node, or several nodes cross-checked.
- **Demo keys in clear** in `keys/` (`chmod 600`, never committed). Production: HSM or secure enclave.
- **Post-quantum coverage**: the manifest signature is hybrid Ed25519 + ML-DSA-87. Still classical: Groth16 soundness on BN254 (anonymity, being perfect zero-knowledge, holds), P-256 passkeys (browsers have no post-quantum passkeys yet), the C2PA ES256 signature, XRPL account signatures. After "Q-day", the XRPL timeline still prevents back-dating a forged signature.
- **Perceptual features are attackable**: they only localise changes and find records. Authentication always comes from the signature over the roots. An image crafted so that every tile stays within tolerance of the signed features would pass as 🟢 after recompression: the colour and detail features make this harder, not impossible.
