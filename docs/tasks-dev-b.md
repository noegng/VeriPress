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

## Journal de passage de relais
<!-- 3 lignes : ce qui marche / ce qui reste / comment lancer -->
- **Ven. soir — marche :** `setup_testnet.py` (comptes + Credentials + `--revoke`/`--reissue`, testé sur Testnet), `XrplLedger` (test de fumée OK), `api.py` (toutes les routes, réponses simulées tant que `pipeline.py` lève `NotImplementedError`, en-tête `X-Tileproof-Mock`), `static/index.html` (Signer/Vérifier, heatmap, vérifié à 390 px).
- **Reste :** retirer les mocks à la synchro quand `pipeline.py` est prêt ; passer la démo en `TILEPROOF_LEDGER=xrpl` ; options 6 (masquage) et 7 (arbre ↔ image).
- **Lancer :** `cd backend && uv run python scripts/setup_testnet.py` (une fois) puis `uv run uvicorn tileproof.api:app --reload --host 0.0.0.0` → http://localhost:8000 (`?mock=real|edited|ai|unknown` pour forcer un verdict simulé). Smoke XRPL : `TILEPROOF_NET=1 uv run python -m pytest tests/test_ledger_xrpl.py`.
