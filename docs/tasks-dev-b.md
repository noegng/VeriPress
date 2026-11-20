# Tâches Dev B — registre et interface

Lire d'abord [`team-rules.md`](team-rules.md) et [`interfaces.md`](interfaces.md). Branches `dev-b/*`.
Le cœur crypto (`commitment.py`, `pipeline.py`) appartient à Dev A : ne pas y toucher.

## Doit marcher (avant la synchro de 03:00)

1. **`scripts/setup_testnet.py`** (xrpl-py, `wss://s.altnet.rippletest.net:51233`), relançable en une commande si Testnet est remis à zéro :
   - comptes financés par le faucet : `registry`, `anchor`, `device` (ed25519), `ai` (ed25519) → `keys/*.json` (format dans `interfaces.md`) ;
   - `CredentialCreate` du registre vers `device` (`CAPTURE_DEVICE`) et vers `ai` (`AI_GENERATOR`), puis `CredentialAccept` par chaque sujet ;
   - option `--revoke device` (`CredentialDelete`) pour montrer la révocation.
2. **`XrplLedger`** dans `ledger.py` : `anchor` (Payment 1 drop `anchor` → `registry`, Memo `tileproof/v1`, attendre la validation), `fetch_anchor` (lire la tx, décoder le Memo, horodatage = close time du ledger converti en unix), `credential_type` (`ledger_entry` Credential subject/issuer/type, accepté = flag `lsfAccepted`). Test de fumée `tests/test_ledger_xrpl.py`, ignoré sans réseau.
3. **`api.py`** (FastAPI) : routes de `interfaces.md`, `TILEPROOF_LEDGER=fake|xrpl`, `Store("store")`. Tant que `pipeline.py` n'est pas prêt, renvoyer les JSON d'exemple. Lancement : `uv run uvicorn tileproof.api:app --reload`.
4. **`static/index.html`** (HTML/JS sans framework, une seule page) :
   - onglet **Signer** : envoi d'image (marche aussi depuis un téléphone : `<input type=file accept=image/* capture>`), choix device/ai → lien vers l'explorateur + bouton de téléchargement de l'image publiée ;
   - onglet **Vérifier** : envoi d'image (+ champ tx_hash facultatif) → gros badge 🟢/🟠/🔵/⚪, `reason`, heatmap, lien vers l'explorateur, compteurs de tuiles.
5. Vérifier que la page s'affiche bien sur mobile (projeter le téléphone pendant la démo).

## Options (dans l'ordre)

6. **Masquage dans la page** (étape 4) : tracer des rectangles sur l'image → `POST /api/redact` → télécharger, puis revérifier → tuiles noires authentifiées.
7. **Visualisation arbre ↔ image** : à partir de `tiles.statuses` + `grid`, afficher l'arbre de Merkle (feuilles = tuiles colorées, nœuds remontant jusqu'à la racine ancrée). Survoler une tuile met en évidence son chemin de preuve. Faire d'abord un `prototype` avec 2 ou 3 variantes.
8. Vraie passkey WebAuthn côté navigateur (si Dev A n'est pas dessus).

## Retours de la revue Dev A (20/11)

Le reste est conforme : propriété des fichiers, routes et JSON de `interfaces.md`, validation des identifiants, limites de taille, échappement dans la page, clés en `chmod 600`. Signature et vérification testées dans le navigateur, sans erreur JS.

1. **RAW via l'API** (prioritaire) : `read_image` fait `Image.open` puis `load_rgb`. Résultat : un CR3 est refusé (400 « cannot identify image file »), et un DNG n'est lu que par sa vignette (864 px au lieu de 4032). Remplacer par `tiling.load_upload(data, upload.filename)` (voir `interfaces.md`). Garder la limite de 40 MP, mais la vérifier sur `rgb.shape` après chargement, car un RAW ne donne pas sa taille avant d'être développé. `load_upload` lève `ValueError` si le fichier est illisible : continuer à le transformer en 400. Dans `index.html`, élargir `accept="image/*"` en `accept="image/*,.dng,.cr2,.cr3,.nef,.arw,.raf,.rw2,.orf"` : certains sélecteurs de fichiers grisent les RAW.
2. **Mode hors ligne** : `make_ledger()` émet les Credentials du `FakeLedger` depuis `BACKEND / "keys"` en dur, alors que `signing.py` lit `TILEPROOF_KEYS`. Si cette variable pointe ailleurs, tout sort ⚪ « Signer has no valid credential » (reproduit dans le navigateur). Lire le même dossier : `signing.keys_dir()`.
3. **Mineur** : mettre en majuscules `entry_id` (`/api/verify`, `/api/redact`), comme c'est déjà fait pour `parent`. Les tx hash sont en majuscules dans le store : un hash collé en minuscules marche sur macOS (système de fichiers insensible à la casse) mais échouera sur un serveur Linux. Pour une variante `-r1`, ne mettre en majuscules que la partie hex.

**→ Fait (Dev B, 20/11 nuit)** : les 3 points, couverts par `tests/test_api.py` (hors ligne : clés jetables dans un autre dossier, ids en minuscules, 16 bits, 40 MP après décodage). En plus : limite d'upload passée de 25 à **100 Mo** (un CR3 / DNG ProRAW dépasse souvent 25 Mo), `accept` inclut aussi `.heic,.heif`, et nouvelle route `POST /api/preview` (JPEG pleine résolution) utilisée par la page quand le navigateur ne sait pas afficher le fichier (RAW, HEIC sous Chrome, TIFF). **Pas testé avec un vrai RAW** (aucun fichier sous la main) : à vérifier avec les CR3/DNG de la revue.

À noter, aucune action demandée : Dev A corrige un faux 🟠 quand on vérifie l'**original non tatoué** d'une photo signée (l'écart dû au filigrane dépasse la tolérance dans certaines tuiles). Le contrat ne change pas.

## Retours de la revue de code (20/11, nuit)

Les points 1 à 3 ci-dessus sont confirmés corrigés (merci !). Nouveaux points :

4. **Piège pour l'étape 3 de la démo** (prioritaire) : après une signature, `txInput` est pré-rempli avec le tx_hash (l. ~270). La vérification suivante passe donc par `found_by = tx_hash` au lieu du filigrane, ce qui casse le message « retrouvée malgré WhatsApp ». Ne pas pré-remplir, ou vider le champ quand on change d'image.
5. **`/api/sign` avec un `parent` inconnu** : `pipeline.sign_image` lève maintenant `ValueError("unknown parent …")`. À transformer en 422, sinon l'API répond 500.
6. **Historique** : une entrée non vérifiée a `timestamp: null`, ce qui s'affiche « 01/01/1970 ». Afficher « — » à la place (l. ~321).
7. **Libellés** : « Signed and anchored on XRPL Testnet » (l. ~99) et les liens de l'historique restent figés sur Testnet, même avec le ledger factice. Mineur.

**→ Fait (Dev B)** : (4) plus de pré-remplissage du tx_hash après signature, et le champ est vidé quand on choisit une nouvelle image à vérifier ; (5) `ValueError` du pipeline → 422, tests `test_sign_with_unknown_parent_is_422` et `…_known_parent_builds_history` ; (6) `timestamp: null` → « — » (dates de l'ancre et de l'historique) ; (7) libellé du bouton Signer et liens de l'explorateur selon `/api/health` (hors ligne : hash sans lien). Vérifié dans le navigateur, signature réelle sur Testnet comprise.

## Phase 2 (contrat : `interfaces.md` § Phase 2 ; décisions : `decisions.md`)

Fusion **par PR** désormais (`team-rules.md` §3).

1. **Registre anonyme** : `setup_testnet.py` crée une clé Baby Jubjub par appareil (`node zk/cli.mjs keygen`, dès que Dev A l'a livré), ajoute ~20 appareils fictifs, écrit `keys/registry_devices.json`, calcule la racine (`zk root`) et la publie (Memo `tileproof/registry-root/v1`). `--revoke device` publie aussi une nouvelle racine sans lui. `XrplLedger.registry_root_at(t)` et `anchor_anonymous`.
2. **Révocation non rétroactive** : `credential_type(pubkey, at_time)` honore `at_time` (date du `CredentialCreate` / `CredentialDelete` dans l'historique du compte registre), et `credential_revoked_at`.
3. **Lien public** `/v/<entry_id>` : page en lecture seule (image, verdict, affirmations, explorateur), balises Open Graph / Twitter avec la miniature ; route `GET /api/entry/{id}` → `pipeline.verify_stored`.
4. **Interface ZK** : case « Signer anonymement », affichage « appareil accrédité (anonyme) » sans clé de signataire, affirmations jour et zone (`meta_claims`).
5. **Ancrage rapide** : `anchor(..., wait=False)` (soumission sans attente), `fetch_anchor` renvoie aussi les tx non validées (`validated=False`), page « en attente » qui se rafraîchit.
6. **Passkey** : routes `/api/sign/passkey/prepare|complete`, `navigator.credentials.create/get` dans la page (localhost, Touch ID), `--passkey` dans le script de mise en place pour mettre `passkey:sha256:<hex>` dans l'`URI` du Credential, `credential_passkey`.
7. **CID** / 8. **ancrage groupé** : si libre.

## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
- **Ven. soir — marche :** `setup_testnet.py` (comptes + Credentials + `--revoke`/`--reissue`, testé sur Testnet), `XrplLedger` (test de fumée OK), `api.py` (toutes les routes, réponses simulées tant que `pipeline.py` lève `NotImplementedError`, en-tête `X-Tileproof-Mock`), `static/index.html` (Signer/Vérifier, heatmap, vérifié à 390 px).
- **Ven. nuit — marche :** mocks retirés, API branchée sur le vrai pipeline (threadpool, `parent`, préchargement TrustMark, `load_upload`), options 6 (masquage) et 7 (arbre ↔ image), historique des versions, retours de la revue Dev A.
- **Reste :** répétition complète en `TILEPROOF_LEDGER=xrpl` avec filigrane (pas encore faite de bout en bout) ; test avec de vrais RAW ; option 8 passkey = décision d'équipe (P-256 ≠ ed25519, touche le format d'ancrage).
- **Lancer :** `cd backend && uv run python scripts/setup_testnet.py` (une fois) puis `TILEPROOF_LEDGER=xrpl uv run uvicorn tileproof.api:app --host 0.0.0.0` → http://localhost:8000 (hors ligne : sans `TILEPROOF_LEDGER`). Smoke XRPL : `TILEPROOF_NET=1 uv run python -m pytest tests/test_ledger_xrpl.py`.
