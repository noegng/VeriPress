# Tâches Dev B — registre et interface

Lire d'abord [`team-rules.md`](team-rules.md) et [`interfaces.md`](interfaces.md). Branches `dev-b/*`.
Le cœur crypto (`commitment.py`, `pipeline.py`) appartient à Dev A : ne pas y toucher.

## Doit marcher (avant la synchro de 03:00)

1. **`scripts/setup_testnet.py`** (xrpl-py, `wss://s.altnet.rippletest.net:51233`), relançable en une commande si Testnet est remis à zéro :
   - comptes financés par le faucet : `registry`, `anchor`, `device` (ed25519), `ai` (ed25519) → `keys/*.json` (format dans `interfaces.md`) ;
   - `CredentialCreate` du registre vers `device` (`CAPTURE_DEVICE`) et vers `ai` (`AI_GENERATOR`), puis `CredentialAccept` par chaque sujet ;
   - option `--revoke device` (`CredentialDelete`) pour montrer la révocation.
2. **`XrplLedger`** dans `ledger.py` : `anchor` (Payment 1 drop `anchor` → `registry`, Memo `veripress/v1`, attendre la validation), `fetch_anchor` (lire la tx, décoder le Memo, horodatage = close time du ledger converti en unix), `credential_type` (`ledger_entry` Credential subject/issuer/type, accepté = flag `lsfAccepted`). Test de fumée `tests/test_ledger_xrpl.py`, ignoré sans réseau.
3. **`api.py`** (FastAPI) : routes de `interfaces.md`, `VERIPRESS_LEDGER=fake|xrpl`, `Store("store")`. Tant que `pipeline.py` n'est pas prêt, renvoyer les JSON d'exemple. Lancement : `uv run uvicorn veripress.api:app --reload`.
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
2. **Mode hors ligne** : `make_ledger()` émet les Credentials du `FakeLedger` depuis `BACKEND / "keys"` en dur, alors que `signing.py` lit `VERIPRESS_KEYS`. Si cette variable pointe ailleurs, tout sort ⚪ « Signer has no valid credential » (reproduit dans le navigateur). Lire le même dossier : `signing.keys_dir()`.
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

1. **Registre anonyme** : `setup_testnet.py` crée une clé Baby Jubjub par appareil (`node zk/cli.mjs keygen`, dès que Dev A l'a livré), ajoute ~20 appareils fictifs, écrit `keys/registry_devices.json`, calcule la racine (`zk root`) et la publie (Memo `veripress/registry-root/v1`). `--revoke device` publie aussi une nouvelle racine sans lui. `XrplLedger.registry_root_at(t)` et `anchor_anonymous`.
2. **Révocation non rétroactive** : `credential_type(pubkey, at_time)` honore `at_time` (date du `CredentialCreate` / `CredentialDelete` dans l'historique du compte registre), et `credential_revoked_at`.
3. **Lien public** `/v/<entry_id>` : page en lecture seule (image, verdict, affirmations, explorateur), balises Open Graph / Twitter avec la miniature ; route `GET /api/entry/{id}` → `pipeline.verify_stored`.
4. **Interface ZK** : case « Signer anonymement », affichage « appareil accrédité (anonyme) » sans clé de signataire, affirmations jour et zone (`meta_claims`).
5. **Ancrage rapide** : `anchor(..., wait=False)` (soumission sans attente), `fetch_anchor` renvoie aussi les tx non validées (`validated=False`), page « en attente » qui se rafraîchit.
6. **Passkey** : routes `/api/sign/passkey/prepare|complete`, `navigator.credentials.create/get` dans la page (localhost, Touch ID), `--passkey` dans le script de mise en place pour mettre `passkey:sha256:<hex>` dans l'`URI` du Credential, `credential_passkey`.
7. **CID** / 8. **ancrage groupé** : si libre.

## Renommage VeriPress (20/11, 16h)

Le projet s'appelle maintenant **VeriPress**, et les identifiants techniques sont renommés (PR de Dev A) :
- paquet `tileproof` → `veripress` (`uv run uvicorn veripress.api:app`, `python -m veripress.cli`) ;
- variables `TILEPROOF_*` → `VERIPRESS_*` (`VERIPRESS_LEDGER`, `VERIPRESS_KEYS`, `VERIPRESS_STORE`, `VERIPRESS_WATERMARK`, `VERIPRESS_NET`…) ;
- Memos `veripress/v1` et `veripress/registry-root/v1` ;
- étiquettes de domaine Merkle `VPX1` / `VPR1`.

Les anciens ancrages Testnet et les anciens `store/` ne se vérifient plus : il faut re-signer les photos de démo. Dev A a déjà relancé `setup_testnet.py` (racine du registre republiée sous le nouveau Memo). **Ta branche `dev-b/anonymous-ui`** : fais `git merge origin/main` dedans (git suit le déplacement `src/tileproof` → `src/veripress`), puis renomme dans ton code les éventuels `tileproof` restants.

## Fenêtre de temps T0 / T1 (Dev A, 20/11 ~17 h)

Contrat dans `interfaces.md` § « Fenêtre de temps ». À faire : `XrplLedger.latest_validated()` (requête `ledger`, `ledger_index="validated"` → index, hash, close time) et `ledger_close_time(index, hash)` (requête `ledger` à cet index ; renvoyer `None` si le hash diffère ou si le ledger n'est pas validé). Puis afficher `time_window` dans la page et sur `/v/<id>`. Tant que ce n'est pas fait, la signature se fait sans T0, et `t0_ok` vaut false.

## Passkey côté serveur (Dev A, 20/11 ~17 h 30)

`prepare_passkey_sign` / `complete_passkey_sign` sont fusionnés : tes routes fonctionnent pour de vrai. Deux choses de ton côté :
1. Dans `/api/sign/passkey/prepare`, passer **`ledger=app.state.ledger`** à `prepare(...)`. Sans lui, pas de borne T0 et pas de vérification de l'ancrage du `parent`.
2. J'ai modifié une ligne de `tests/test_api.py::test_passkey_signing_routes_…` : la réponse factice porte maintenant une passkey, car `SignResult.to_json()` renvoie la vraie valeur de `passkey` (+ `anonymous`, `pending`, `meta_claims`). Tes `setdefault` dans l'API peuvent être retirés.

Origines WebAuthn acceptées : `VERIPRESS_WEBAUTHN_HOSTS` (défaut `localhost,127.0.0.1`, http accepté seulement pour ces deux hôtes). La vérification exige UP **et** UV (Touch ID). Un `prep_id` sert une seule fois et expire après 10 min.

## Réponse à tes notes pour Dev A (20/11 ~18 h)

Tout est dans `tasks-dev-a.md` § « Retours de Dev B » (PR #26). Pour le **point 3** : **OK pour le faire dans `api.py`**. Lis le C2PA sur les octets bruts avec `c2pa_embed.read(data)` et ajoute `c2pa` (`null` ou `{…read…, "matches_anchor": bool}`) à la réponse de `/api/verify`. Annonce l'extension du contrat dans ta PR et dans `interfaces.md`.

## Revue de sécurité Dev A (20/11 ~19 h) — pour toi

Compte rendu : `docs/security-review.md`. Pour la page : le champ `c2pa` de `/api/verify` doit rester une **information** (« manifeste C2PA présent, certificat non reconnu »), jamais un ✓ de provenance. N'importe qui peut fabriquer un manifeste qui pointe vers n'importe quel ancrage.

## Ancrage groupé (Dev A, 20/11 ~19 h 30)

Contrat dans `interfaces.md` § « Ancrage groupé ». À faire dans `XrplLedger` :
- `anchor_batch(root, count, wait)` : Payment avec le Memo `veripress/v1` `{"b": root, "n": count}` ;
- `fetch_anchor` : reconnaître ce Memo et renvoyer `Anchor(digest=root, batch_size=n, signature="", pubkey="")`.

Option côté page : un mode « lot » (plusieurs fichiers, puis « Anchor batch »), et afficher `batch` (« ancrée dans le lot <tx>, n° i sur N »).

## Revue de ta PR #32 (Dev A, 20/11 ~18 h 15)

T0 côté XRPL : conforme, et vérifié sur Testnet (bon hash → heure de clôture ; hash faux ou ledger futur → `None`). Un accroc : en résolvant le conflit avec la PR #31 (commit `c2a63a7`), **le stub `XrplLedger.anchor_batch` a été supprimé**. Le protocole, `FakeLedger` et `Anchor.batch_size` sont intacts, mais un `BatchingLedger.flush()` sur Testnet lève maintenant une `AttributeError` au lieu d'un message clair. → Implémente directement `anchor_batch` (§ « Ancrage groupé » plus haut), ou remets le stub en attendant.

## Signature hybride post-quantique (Dev A, 20/11 ~18 h 45)

Contrat : `interfaces.md` § « Signature hybride post-quantique ». À faire de ton côté :
1. `setup_testnet.py` : générer une clé ML-DSA-87 par appareil (`keys/device.json["mldsa"]`, idem pour `ai`), puis l'attester dans l'`URI` du Credential (`mldsa87:sha256:<hex>`, séparé par `;` de `passkey:sha256:…`). Attention : `--passkey` et la réémission ne doivent pas effacer l'autre partie de l'URI.
2. `XrplLedger.credential_pq(pubkey)` : lire cette partie de l'URI. Et `_passkey_from_uri` doit tolérer le `;`.
3. Page et `/v/<id>` : afficher `post_quantum` (« 🔐 hybrid post-quantum: Ed25519 + ML-DSA-87 ✓ »).

Tant que ce n'est pas fait, on signe en Ed25519 seul : rien ne casse.

## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
- **Ven. ~13 h — phase 1 :** script Testnet, `XrplLedger`, API (branchée sur le vrai pipeline), page (signer / vérifier, heatmap, masquage, arbre ↔ image, historique, lien public), retours de revue 1–7. Répétition complète en `xrpl` + filigrane : les 6 étapes passent.
- **Ven. ~16 h 30 — phase 2, tout fusionné :** contrat Ledger (#7, #19 `anchor_passkey`), révocation non rétroactive (#9), registre anonyme côté XRPL + script (#11), signature anonyme dans l'API et la page (#13), EXIF → affirmations ZK B (#14), lien public `/v/<id>` + aperçus sociaux (#15), ancrage rapide (#18), passkey côté Dev B (#20). Chaque fonction vérifiée sur Testnet dans le navigateur.
- **Reste :** passkey de bout en bout dès que `prepare/complete_passkey_sign` (Dev A) est fusionné (enregistrer la vraie passkey Touch ID, puis `--passkey`) ; `/security-review` XRPL avant le gel ; test avec de vrais RAW ; options 7–8 (CID, ancrage groupé) si le temps le permet. `keys/passkey.json` contient pour l'instant une clé P-256 **de test** (attestée) : la remplacer par la vraie.
- **Ven. ~21 h — toutes les tâches Dev B fusionnées :** fenêtre T0/T1 côté XRPL + affichage (#32) ; passkey branchée sur le ledger (T0, parent, ancrage rapide) et `op=develop` (#33) ; ancrage groupé `anchor_batch` (#35) ; C2PA (information), CID, lot dans la vérification et signature groupée dans l'API et la page (#37) ; post-quantique : clés ML-DSA-87 attestées dans l'URI (format base64url, car l'hex ne tenait pas), `credential_pq` lu dans l'historique pour que la révocation reste non rétroactive (#41) ; revue de sécurité XRPL (`security-review.md`). Tout est vérifié sur Testnet : passkey de bout en bout (clé de test), lot de 3 photos dans 1 transaction, photo hybride encore 🟢 après `--revoke`.
- **Reste (humain, au gel) :** enregistrer la **vraie** passkey Touch ID (bouton « Set up » sur localhost, puis `setup_testnet.py --passkey`) : `keys/passkey.json` contient une clé P-256 de test attestée ; relancer `cli prepare-demo` pour signer les images du pitch en hybride ; `AI-USAGE.md` : confirmé et complété par Dev B (sam. 21 nov.).
- **Lancer :** `cd zk && npm ci` (une fois) ; `cd backend && uv run python scripts/setup_testnet.py` (relançable : comptes, Credentials, registre anonyme) puis `VERIPRESS_LEDGER=xrpl uv run uvicorn veripress.api:app --host 0.0.0.0` → http://localhost:8000 (hors ligne : sans `VERIPRESS_LEDGER`). Démo : `--revoke device` / `--reissue device` ; passkey : bouton « Set up » sur localhost puis `setup_testnet.py --passkey`. Tests réseau : `VERIPRESS_NET=1 uv run python -m pytest tests/test_ledger_xrpl.py`.
