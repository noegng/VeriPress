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

6. **Filigrane TrustMark** (`watermark.py`) : `embed(rgb, wm_id) -> rgb`, `extract(rgb) -> wm_id | None`. *(Fait autrement : `wm_id` aléatoire de 64 bits engagé dans le manifeste, car l'image est tatouée avant l'ancrage.)* Sur `main`, faire `uv add trustmark` dans un commit dédié. Brancher le module dans `sign_image` (image publiée tatouée, **commit fait sur l'image tatouée**) et dans `verify_image`. Tester la survie à WhatsApp.
   → **Étape 5** : filigrane recopié sur une autre image → `robust` ne correspond pas → `edited` ou `unknown` avec la raison « watermark does not match content ».
7. `redact_image` (le cœur `redact` existe déjà) pour l'étape 4 côté page.
8. ~~Vraie passkey WebAuthn~~ → décidé le 20/11 : laissée à Dev B (P-256 ≠ clés XRPL, il faut lier la passkey au compte XRPL de l'appareil).
9. Chaîne de versions : champ `parent` dans le manifeste, `verify_image` remonte la chaîne.

## Phase 2 (contrat : `interfaces.md` § Phase 2 ; décisions : `decisions.md`)

1. **ZK A** : `zk/` (circuit circom `device.circom` = EdDSA-Poseidon + inclusion Merkle de profondeur 10, entrées publiques `root`, `digest_hi`, `digest_lo`), `setup.sh` (powers of tau Hermez + zkey), `cli.mjs` (`keygen`, `root`, `prove-device`, `verify-device`), wrapper `veripress/zk.py`. Pipeline : `sign_image(anonymous=True)` → paquet de preuve dans le store, `anchor_anonymous` ; verdict : preuve valide + `registry_root_at(anchor time) == racine` → 🟢 anonyme. TDD sur les règles de verdict (preuve fausse, racine périmée, digest échangé). `FakeLedger` : `anchor_anonymous`, `registry_root_at`.
2. **Révocation non rétroactive** (côté pipeline) : passer `anchor.timestamp` à `credential_type`, et renseigner `credential_revoked_at` dans le rapport.
3. **`verify_stored`** pour le lien public.
4. **ZK B** : `metadata.py` (EXIF `DateTimeOriginal` + GPS → entiers ; jour et zone de 10 km), circuit `meta.circom` (Poseidon + comparaisons d'intervalles), `commit-meta` / `prove-meta` / `verify-meta`, `meta_commitment` dans le manifeste, `meta_claims` dans le rapport.
5. **`pending`** (ancrage rapide) : verdict provisoire si `anchor.validated` est faux.
6. **C2PA** : `c2pa_embed.py`, manifeste dans le PNG publié (assertion personnalisée avec tx hash et digest), certificat de test généré dans `keys/` (non commité).
7. **WebAuthn côté serveur** : `prepare_passkey_sign` / `complete_passkey_sign`, vérification ECDSA P-256 de l'assertion (`authenticatorData ‖ sha256(clientDataJSON)`, challenge = digest), comparaison avec `credential_passkey`.
8. **CID** / 9. **ancrage groupé** : si libre.

## Retours de Dev B (20/11, soir)

Constatés sur `main` à `b581731` (après #22 et #23) : `uv run python -m pytest` → 144 passent, 6 ignorés, **1 échec intermittent** (point 1). Les numéros de ligne correspondent à ce commit.

1. **Test instable `test_revoked_credential_is_unknown`** (prioritaire, `tests/test_pipeline.py:74`).
   - **Symptôme :** il échoue environ 1 fois sur 3 depuis #23. Reproduit : 3 lancements de `pytest tests/test_pipeline.py -k revoked_credential_is_unknown` donnent 1 échec, avec `REAL` au lieu de `UNKNOWN`.
   - **Cause :** `sign_image` signe le manifeste C2PA *après* l'ancrage (`pipeline.py:194`). Le `ledger.revoke(keys["device"])` du test tombe donc souvent dans la seconde qui suit `anchor.timestamp`. Or, avec la révocation non rétroactive, `FakeLedger.credential_type` ne rejette que si `at_time >= revoked`. La photo, ancrée avant la révocation, sort alors 🟢, ce qui est le comportement voulu.
   - **Diagnostic :** le code est correct ; c'est le test qui suppose que la signature et la révocation tombent dans la même seconde.
   - **Correctif proposé :** dater la révocation explicitement, par exemple `ledger.revoke(keys["device"], at=ledger.anchors[signed.entry_id].timestamp)` (révoquée dès l'ancrage → ⚪). C'est le seul `revoke(...)` sans `at=` dans `tests/`.
2. **Passkey : ce qu'attend l'API** (#20, déjà fusionné ; c'est le dernier maillon avant la démo Touch ID).
   - **Statut actuel :** `/api/sign/passkey/prepare` et `/complete` répondent 503 tant que `pipeline.prepare_passkey_sign` et `pipeline.complete_passkey_sign` n'existent pas (`api.py:380`, `_pipeline_fn`). Le contrat est dans `interfaces.md` l. 168-170. Les précisions ci-dessous viennent du code de la page et de l'API.
   - **Appels :**
     - `prepare(rgb, store, parent, exif=exif)` → `{"prep_id", "challenge": digest_hex}`.
     - `complete(prep_id, assertion, ledger, store)` → `(SignResult, png)`, sans argument `wait` : c'est donc la valeur par défaut du pipeline qui s'applique.
   - **Erreurs converties par l'API :** `KeyError` → 404 (prep_id inconnu ou expiré), `ValueError` → 422 (assertion invalide, passkey non attestée, parent inconnu), `RuntimeError` → 502 (transaction rejetée).
   - **`assertion` envoyé par la page :**
     - `credential_id`, `authenticator_data`, `client_data_json` et `signature` sont en base64url **sans padding** ;
     - `signature` est la signature ECDSA au format **DER** renvoyé par WebAuthn, que `cryptography` accepte telle quelle ;
     - **attention, `public_key` est la clé SPKI DER en base64url, pas le SEC1 hex.** Pour la comparer à `ledger.credential_passkey(clé_ed25519_appareil)`, la convertir en SEC1 non compressé puis en calculer le sha256, comme dans `api.py:357` : `load_der_public_key(...).public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)`. Le `credential_id` doit correspondre à celui de `keys/passkey.json`.
   - **À vérifier dans `complete` :**
     - message signé = `authenticator_data ‖ sha256(client_data_json)` ;
     - dans `client_data_json` : `type == "webauthn.get"`, et `challenge` égal au base64url sans padding de `bytes.fromhex(digest)` ;
     - drapeau UV présent : bit `0x04` de l'octet 32 d'`authenticator_data`, puisque la page demande `userVerification: "required"` ;
     - ne pas figer l'origine (`http://localhost:<port>`).
   - **Ancrage :** `ledger.anchor_passkey(digest, clé_ed25519_appareil, bundle_hash, wait)`.
     - `k` est la clé Ed25519 de l'appareil (`keys/device.json`), celle dont le Credential porte l'URI `passkey:sha256:…`.
     - `bundle_hash` est le sha256 du paquet (assertion et clé), stocké avec `store.put_bundle`.
     - En vérification, `report.passkey` contient la clé SEC1 hex (`interfaces.md` l. 129).
   - **Pour tester sans navigateur :** générer une clé P-256 avec `cryptography`, puis fabriquer à la main `authenticator_data` (rpIdHash 32 o ‖ flags `0x05` ‖ compteur 4 o) et `client_data_json`. `keys/passkey.json` contient aujourd'hui une clé **de test** déjà attestée sur Testnet ; elle sera remplacée par la vraie passkey Touch ID.
   - **Limite connue (côté Dev B) :** `credential_passkey` lit l'URI *actuelle* du Credential. Si on atteste une autre passkey plus tard, les anciennes photos signées par passkey ne se vérifieraient plus. C'est sans effet pour la démo.
3. **C2PA invisible à la vérification** (suggestion pour la démo, à trancher).
   - **Constat :** le manifeste est écrit (`pipeline.py:194`) mais jamais relu. `verify_image` reçoit des pixels et ne peut donc pas le lire.
   - **Conséquence :** le moment du pitch prévu en Q20 (« C2PA disparaît après WhatsApp, VeriPress retrouve la provenance ») demande aujourd'hui un lecteur C2PA externe.
   - **Proposition de Dev B, sans toucher au pipeline :** dans `/api/verify`, appeler `c2pa_embed.read(data)` sur les octets bruts envoyés, puis ajouter un champ `c2pa` à la réponse (`null`, ou le dict de `read` plus `matches_anchor: tx_hash == report.tx_hash`). La page afficherait alors :
     - « Manifeste C2PA présent → même ancre XRPL (certificat de test) » ;
     - ou « Manifeste C2PA absent (supprimé au partage) — provenance retrouvée par le filigrane ».
   - **À décider par Dev A :** OK pour le faire dans `api.py`, ou préférence pour un champ dans `VerifyReport` ? C'est une extension du contrat JSON de `/api/verify`, qui sera annoncée dans la PR.
4. **`cli demo` plante quand `VERIPRESS_WATERMARK=0`** (mineur, utile pour une démo de secours sans les modèles TrustMark).
   - **Cause :** sans filigrane, `manifest.wm_id == ""`. Le scénario 5 (`cli.py:171-172`) appelle quand même `watermark.embed(..., bytes.fromhex(""))`, ce qui lève `ValueError: wm_id must be 8 bytes`.
   - **Effet sur les tests :** `test_cli_demo` échoue si la variable est exportée dans le shell.
   - **Correctif proposé :** sauter le scénario 5 (ou le marquer « skipped ») quand `not watermark.enabled()`.
5. **Pour la démo** (info, aucune action demandée).
   - Les PNG signés avant #23 ne portent pas de manifeste C2PA. Après le gel, **re-signer les photos de démo sur le `main` final**, puis refaire la copie WhatsApp à partir du nouveau PNG signé.
   - Si Testnet est remis à zéro, relancer d'abord `setup_testnet.py`.


**→ Réponses de Dev A (20/11 ~18 h, PR « Retours de Dev B »)**
1. Corrigé : le test date la révocation à la seconde de l'ancrage (`revoke(..., at=anchor.timestamp)`). Avant : 3 échecs sur 6 lancements ; après : 8 réussites sur 8. C'était le seul `revoke()` sans date.
2. Déjà livré dans la PR #25 (`prepare/complete_passkey_sign`) : clé SPKI comparée en SEC1, challenge = `bytes.fromhex(digest)`, UP + UV, origine non figée (hôtes `VERIPRESS_WEBAUTHN_HOSTS`), message = `authData ‖ sha256(cdj)`, `anchor_passkey`. **Ajout** : le `credential_id` doit être celui de `keys/passkey.json`. Précision : dans `/api/verify`, `passkey` est un **booléen** (interfaces.md l. 192) ; la clé SEC1 hex de la l. 129 est le champ du *manifeste*. **Pour toi** : passer `ledger=app.state.ledger` à `prepare` (T0 + parent).
3. En attente de la décision de Noé (voir la PR).
4. Corrigé : sans filigrane, le scénario 5 est marqué `{"skipped": …}` et la démo va au bout (le scénario 3 est retrouvé par phash). Test `test_demo_runs_without_the_watermark_models`.
5. Noté.
## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
- **20/11 — ZK B fait** : circuit `meta.circom` (1 295 contraintes : engagement Poseidon de la date + du GPS, appartenance à des intervalles), commandes `commit-meta`, `prove-meta` et `verify-meta`, `metadata.py` (EXIF → `Capture`, affirmations jour / zone de 10 km, libellés recalculés à partir des entrées publiques vérifiées), `sign_image(exif=…)`, `meta_claims` dans le rapport. Sur IMG_4110 : « 20 Nov 2026 » et « ≈ Bari (10 km) » prouvés, ni l'heure ni le GPS exacts publiés. Aussi fait : révocation datée dans le rapport, `pending`, `verify_stored` (PR #10). **Dev B** : passer `exif=metadata.exif_from_upload(data)` dans `/api/sign`, afficher `meta_claims`.
- **20/11 — ZK A fait** : `zk/` (circuit `device.circom` de 14 578 contraintes, `cli.mjs`, `setup.sh` avec le powers of tau PSE), `veripress/zk.py`, signature anonyme (`sign_image(anonymous=True)`) et vérification (preuve = celle ancrée, couvre ce digest, racine en vigueur à l'ancrage). `FakeLedger` : `anchor_anonymous`, `registry_root_at`, `publish_registry_root`, révocation datée. Scénario 7 dans `cli demo`. 7 tests dans `test_zk_anonymous.py`. Preuve ~2 s, vérification ~0,6 s, paquet de 906 octets. **Reste côté Dev B** pour Testnet : `XrplLedger.anchor_anonymous` / `registry_root_at` et le registre dans `setup_testnet.py`.
- **20/11 — engagement double** (trouvé à la revue de l'API) : l'original non tatoué d'une photo signée sortait 🟠, car l'écart dû au filigrane atteint 20 pas dans certaines tuiles. Corrigé : la feuille robuste engage les descripteurs de la version tatouée **et** de l'original (`TileDisclosure.g`), et une tuile est conforme si elle est proche de l'une ou de l'autre. Aucun réseau de neurones n'intervient dans le verdict. Sur les 4 photos réelles : original, copie WhatsApp de l'original, version signée et version signée passée par WhatsApp → 🟢. Une retouche d'une demi-tuile reste détectée à 97 %.
- **20/11 soir — fait** : tâches 1, 2, 3, 6 (filigrane + étape 5), 7 (masquage), 9 (chaîne de versions), plus `veripress.cli demo` (les 6 scénarios hors ligne). 50 tests au vert. 12 MP : signature ~2 s, vérification ~2 s.
- **20/11 — calibrage (tâche 4)** : sur 6 vraies photos 3-5k (Wikimedia Commons) partagées façon WhatsApp (1600 px q72 et 1280 px q55), tuiles de 32 px → jusqu'à 7 % de faux « changed ». Cause : bandes de bord fines + remplissage. Corrigé : taille de tuile = grand côté / 40 (≥ 32), descripteurs sans remplissage, bandes < ¼ de tuile fusionnées. Résultat : 0 faux positif (max 2,96 pour une tolérance de 4,5), copier-coller de 2 tuiles détecté à 100 %, d'une demi-tuile à 78 %.
- **Image IA (tâche 5)** : `demo/ai/sd_pod_plane_cc0.jpg` (Stable Diffusion, CC0, Wikimedia Commons). Signée `ai` → 🔵, y compris après partage WhatsApp. `demo --ai IMAGE` l'utilise pour le scénario 6.
- **20/11 — vraies photos iPhone passées par WhatsApp** (`demo/originals` HEIC, `demo/whatsapp`) : au départ jusqu'à 303 tuiles en faux « changed ». Deux causes : l'iPhone enregistre en Display P3 alors que WhatsApp renvoie du sRGB sans profil, et la rambarde fine sur un mur blanc fait dépasser le rééchantillonnage (le dépassement est tronqué à 255). Corrigé : conversion ICC → sRGB au chargement, rééchantillonnage Lanczos en flottant sans troncature, poids 0,5 sur le coefficient DC. Résultat : `calibrate` → `all_pass=True`, max 2,01 ; les 4 copies WhatsApp réelles donnent 🟢 ; démo complète OK avec `demo/ai/Gemini_…jpeg`.
- **Note démo** : WhatsApp « HD » garde 4032×3024. Pour l'étape 3 en direct, partager l'image **signée** (tatouée) téléchargée depuis la page, pas l'original. `/security-review` fait. Passkey → Dev B.
- **Lancer** : `cd backend && uv run python -m pytest` · `uv run python -m veripress.cli demo photo.jpg -o out/`. Le premier usage du filigrane télécharge les modèles TrustMark (~3 min) : appeler `watermark.warm_up()` au démarrage de l'API.
