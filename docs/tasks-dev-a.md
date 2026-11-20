# Tâches Dev A — confiance et vérification

Lire d'abord [`team-rules.md`](team-rules.md) et [`interfaces.md`](interfaces.md). Branches `dev-a/*`.

## Doit marcher (avant la synchro de 03:00)

1. **Tests du cœur existant** (TDD, `tests/test_merkle.py`, `tests/test_commitment.py`) : preuves de Merkle (nombre de feuilles impair, mauvais index), `commit` puis `verify` intact, JPEG q50–90 et redimensionnement ×0.5 → `recompressed`, retouche d'une zone → tuiles `changed` au bon endroit, masquage → `redacted` et racines toujours valides. Les fixtures sont dans `conftest.py`.
2. **`signing.py`** : charger `keys/{device,ai}.json`, `sign(digest) -> sig hex`, `verify(digest, sig, pubkey) -> bool` (Ed25519, `cryptography`). Ajouter `signer` (pubkey) et `op` au `Manifest`, ainsi qu'une clé de test générée dans les tests.
3. **`pipeline.py`** (TDD sur les règles de verdict du docstring, avec `FakeLedger` + `Store(tmp_path)`) :
   - `sign_image` : commit → digest → signature → `ledger.anchor` → `store.put` (entry_id = tx_hash, phash).
   - `verify_image` : recherche par `entry_id` > filigrane > phash (`store.nearest`) → vérifie l'ancrage, le digest, la signature, le Credential, puis les tuiles → `Report` + heatmap.
   - phash 64 bits de l'image entière (DCT 32×32 → 8×8 basses fréquences > médiane).
   - `SignResult.to_json` et `Report.to_json` exactement au format de `interfaces.md`.
4. **Calibrage réel** : passer 3 à 5 vraies photos de téléphone par WhatsApp, vérifier que les tuiles restent `robust` et que le phash les retrouve. Ajuster `TOLERANCE` et `max_distance` si besoin. Garder ces images pour la démo (`demo/`, non commité si lourd).
5. **Image IA** : préparer une image générée et la signer avec `signer="ai"`.

## Options (dans l'ordre)

6. **Filigrane TrustMark** (`watermark.py`) : `embed(rgb, entry_id) -> rgb`, `extract(rgb) -> entry_id | None`. L'identifiant tient en ~64 bits : utiliser les 16 premiers hex du tx_hash et faire la recherche par préfixe dans le store. Sur `main`, faire `uv add trustmark` dans un commit dédié. Brancher le module dans `sign_image` (image publiée tatouée, **commit fait sur l'image tatouée**) et dans `verify_image`. Tester la survie à WhatsApp.
   → **Étape 5** : filigrane recopié sur une autre image → `robust` ne correspond pas → `edited` ou `unknown` avec la raison « watermark does not match content ».
7. `redact_image` (le cœur `redact` existe déjà) pour l'étape 4 côté page.
8. Vraie passkey WebAuthn (si Dev B n'est pas dessus).
9. Chaîne de versions : champ `parent` dans le manifeste, `verify_image` remonte la chaîne.

## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
