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
8. ~~Vraie passkey WebAuthn~~ → décidé le 20/11 : laissée à Dev B (P-256 ≠ clés XRPL, il faut lier la passkey au compte XRPL de l'appareil).
9. Chaîne de versions : champ `parent` dans le manifeste, `verify_image` remonte la chaîne.

## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
- **20/11 — engagement double** (trouvé à la revue de l'API) : l'original non tatoué d'une photo signée sortait 🟠, car l'écart dû au filigrane atteint 20 pas dans certaines tuiles. Corrigé : la feuille robuste engage les descripteurs de la version tatouée **et** de l'original (`TileDisclosure.g`), et une tuile est conforme si elle est proche de l'une ou de l'autre. Aucun réseau de neurones n'intervient dans le verdict. Sur les 4 photos réelles : original, copie WhatsApp de l'original, version signée et version signée passée par WhatsApp → 🟢. Une retouche d'une demi-tuile reste détectée à 97 %.
- **20/11 soir — fait** : tâches 1, 2, 3, 6 (filigrane + étape 5), 7 (masquage), 9 (chaîne de versions), plus `tileproof.cli demo` (les 6 scénarios hors ligne). 50 tests au vert. 12 MP : signature ~2 s, vérification ~2 s.
- **20/11 — calibrage (tâche 4)** : sur 6 vraies photos 3-5k (Wikimedia Commons) partagées façon WhatsApp (1600 px q72 et 1280 px q55), tuiles de 32 px → jusqu'à 7 % de faux « changed ». Cause : bandes de bord fines + remplissage. Corrigé : taille de tuile = grand côté / 40 (≥ 32), descripteurs sans remplissage, bandes < ¼ de tuile fusionnées. Résultat : 0 faux positif (max 2,96 pour une tolérance de 4,5), copier-coller de 2 tuiles détecté à 100 %, d'une demi-tuile à 78 %.
- **Image IA (tâche 5)** : `demo/ai/sd_pod_plane_cc0.jpg` (Stable Diffusion, CC0, Wikimedia Commons). Signée `ai` → 🔵, y compris après partage WhatsApp. `demo --ai IMAGE` l'utilise pour le scénario 6.
- **20/11 — vraies photos iPhone passées par WhatsApp** (`demo/originals` HEIC, `demo/whatsapp`) : au départ jusqu'à 303 tuiles en faux « changed ». Deux causes : l'iPhone enregistre en Display P3 alors que WhatsApp renvoie du sRGB sans profil, et la rambarde fine sur un mur blanc fait dépasser le rééchantillonnage (le dépassement est tronqué à 255). Corrigé : conversion ICC → sRGB au chargement, rééchantillonnage Lanczos en flottant sans troncature, poids 0,5 sur le coefficient DC. Résultat : `calibrate` → `all_pass=True`, max 2,01 ; les 4 copies WhatsApp réelles donnent 🟢 ; démo complète OK avec `demo/ai/Gemini_…jpeg`.
- **Note démo** : WhatsApp « HD » garde 4032×3024. Pour l'étape 3 en direct, partager l'image **signée** (tatouée) téléchargée depuis la page, pas l'original. `/security-review` fait. Passkey → Dev B.
- **Lancer** : `cd backend && uv run python -m pytest` · `uv run python -m tileproof.cli demo photo.jpg -o out/`. Le premier usage du filigrane télécharge les modèles TrustMark (~3 min) : appeler `watermark.warm_up()` au démarrage de l'API.
