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

## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
- **Ven. soir — marche :** `setup_testnet.py` (comptes + Credentials + `--revoke`/`--reissue`, testé sur Testnet), `XrplLedger` (test de fumée OK), `api.py` (toutes les routes, réponses simulées tant que `pipeline.py` lève `NotImplementedError`, en-tête `X-Tileproof-Mock`), `static/index.html` (Signer/Vérifier, heatmap, vérifié à 390 px).
- **Ven. nuit — marche :** mocks retirés, API branchée sur le vrai pipeline (threadpool, `parent`, préchargement TrustMark, `load_upload`), options 6 (masquage) et 7 (arbre ↔ image), historique des versions, retours de la revue Dev A.
- **Reste :** répétition complète en `TILEPROOF_LEDGER=xrpl` avec filigrane (pas encore faite de bout en bout) ; test avec de vrais RAW ; option 8 passkey = décision d'équipe (P-256 ≠ ed25519, touche le format d'ancrage).
- **Lancer :** `cd backend && uv run python scripts/setup_testnet.py` (une fois) puis `TILEPROOF_LEDGER=xrpl uv run uvicorn tileproof.api:app --host 0.0.0.0` → http://localhost:8000 (hors ligne : sans `TILEPROOF_LEDGER`). Smoke XRPL : `TILEPROOF_NET=1 uv run python -m pytest tests/test_ledger_xrpl.py`.
