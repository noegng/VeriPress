# Security review

Two reviews were run before the feature freeze (Fri 20 Nov): one on the signature and verification side (Dev A, ~19:00), one on the XRPL and API side (Dev B, ~21:00). This document merges them. Mechanisms are described in [`architecture.md`](architecture.md).

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

## Known limits, accepted and stated to the jury

- **C2PA** manifests can be forged by anyone to point to any anchor (our certificate is a test one). The page presents C2PA as **information**, never as proof; the verdict comes from VeriPress.
- **Demo device = the server.** `/api/sign` signs with the device's software key for anyone who reaches the server. On the venue Wi-Fi anyone could produce a 🟢 photo. In production the key lives in the camera sensor, or is the device's passkey. During the demo: do not show the server address, or bind to `127.0.0.1` when the phone is not needed.
- **Physical origin.** Signing happens on the server (software key) or with a passkey on the laptop; a sensor that signs the RAW itself, as Apple does, is future work. The **analog hole** (photographing a screen) affects every signature-based approach.
- **`device` circuit**: no domain separation between a leaf hash (`Poseidon(Ax, Ay)`) and an inner node hash. Not exploitable: the depth is fixed at 10 and the key must be a curve point. Planned hardening: `Poseidon(3)` with a domain tag.
- **Trusted setup**: public phase 1 (PSE, 80 contributions), single local phase-2 contribution. Production: multi-party ceremony, or PLONK / Halo2.
- **WebAuthn signature counter** not tracked (clone detection); synced Apple passkeys return 0 anyway. Verifiers must list the signing origins in `VERIPRESS_WEBAUTHN_HOSTS`.
- **Attestation read from the latest `CredentialCreate`** when no time is given: attesting a new passkey or ML-DSA key would invalidate older photos signed with the previous one. Passing `at_time = anchor.timestamp` removes this limit (proposed in PR #41).
- **Public tunnel**: requests would then come from 127.0.0.1, so passkey registration would no longer be restricted to the machine. Do not open a tunnel while registering or attesting a passkey.
- **Trusted public Testnet node**, without state proofs: a malicious node could lie. Production: own node, or several nodes cross-checked.
- **Demo keys in clear** in `keys/` (`chmod 600`, never committed). Production: HSM or secure enclave.
- **Post-quantum coverage**: the manifest signature is hybrid Ed25519 + ML-DSA-87. Still classical: Groth16 soundness on BN254 (anonymity, being perfect zero-knowledge, holds), P-256 passkeys (browsers have no post-quantum passkeys yet), the C2PA ES256 signature, XRPL account signatures. After "Q-day", the XRPL timeline still prevents back-dating a forged signature.
- **Perceptual features are attackable**: they only localise changes and find records. Authentication always comes from the signature over the roots.
