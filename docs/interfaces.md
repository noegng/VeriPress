# Interfaces (contrat Dev A ↔ Dev B)

Toute modification de ce fichier, de `ledger.py`, `store.py` ou des signatures de `pipeline.py` passe par **un commit dédié sur `main`, annoncé à l'autre dev**.

## Python

| Module | Propriétaire | Rôle |
|---|---|---|
| `tileproof/ledger.py` | Dev B | `Ledger` (protocole), `FakeLedger` (mémoire), `XrplLedger` (Testnet) |
| `tileproof/store.py` | Dev A | stockage hors chaîne : manifeste + divulgation + image publiée + phash ; `find_by_watermark(wm_id, phash)` |
| `tileproof/watermark.py` | Dev A | TrustMark : `embed`, `extract`, `warm_up()` (charge les modèles ; à appeler au démarrage de l'API). `TILEPROOF_WATERMARK=0` le désactive |
| `tileproof/pipeline.py` | Dev A | `sign_image`, `verify_image`, `redact_image`, `Report.to_json` |
| `tileproof/api.py` | Dev B | FastAPI, appelle uniquement `pipeline.*` |

Le manifeste signé contient `signer`, `op` (`capture` | `ai_generate`) et `wm_id` (hex 64 bits du filigrane, choisi à la signature : l'image est tatouée **avant** l'engagement).

Le choix du ledger se fait par la variable d'env. `TILEPROOF_LEDGER=fake|xrpl` (défaut `fake`), lue dans `api.py`.

## Fichiers générés par le script de mise en place (Dev B)

`backend/scripts/setup_testnet.py` crée les comptes (faucet Testnet), émet et fait accepter les Credentials, puis écrit :

```
backend/keys/registry.json   {"seed","address"}                      émetteur des Credentials, destinataire des ancrages
backend/keys/anchor.json     {"seed","address"}                      paie les tx d'ancrage
backend/keys/device.json     {"seed","address","public_key","private_key"}   CAPTURE_DEVICE, ed25519
backend/keys/ai.json         idem                                     AI_GENERATOR, ed25519
```

`private_key` / `public_key` sont au format xrpl-py (`"ED"` + 64 hex). Pour signer :
`Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key[2:]))`.
Le dossier `keys/` n'est **jamais commité**.

## HTTP (servi par `api.py`)

### `GET /` → `static/index.html` (deux onglets : Signer / Vérifier)

### `GET /api/files/{entry_id}.png` → image publiée (à télécharger puis partager)

### `POST /api/sign`  (multipart : `image`, `signer` = `device` | `ai`, optionnel `parent` = tx_hash de la version d'origine → `op = "edit"`)

```json
{
  "entry_id": "A1B2…",
  "tx_hash": "A1B2…",
  "explorer_url": "https://testnet.xrpl.org/transactions/A1B2…",
  "digest": "9f…",
  "signer": "ED12…",
  "grid": {"cols": 20, "rows": 15, "tile": 32},
  "roots": {"exact": "…", "robust": "…"},
  "image_url": "/api/files/A1B2….png"
}
```

### `POST /api/verify`  (multipart : `image`, optionnel `entry_id`)

```json
{
  "verdict": "real | edited | ai | unknown",
  "reason": "Signed by a CAPTURE_DEVICE credential; 300/300 tiles match",
  "found_by": "tx_hash | watermark | phash | null",
  "entry_id": "A1B2…",
  "anchor": {"tx_hash": "…", "timestamp": 1795000000, "explorer_url": "…", "signer": "ED12…"},
  "credential": "CAPTURE_DEVICE | AI_GENERATOR | null",
  "signature_ok": true,
  "tiles": {
    "verdict": "intact | recompressed | edited | invalid_disclosure",
    "grid": {"cols": 20, "rows": 15, "tile": 32},
    "counts": {"exact": 280, "robust": 12, "changed": 8, "redacted": 0},
    "statuses": ["exact", "robust", "changed", "redacted", "…"],
    "distances": [0.0, 1.2, 37.5, "…"]
  },
  "history": [
    {"tx_hash": "C3D4…", "op": "edit", "timestamp": 1795000100, "verified": true},
    {"tx_hash": "A1B2…", "op": "capture", "timestamp": 1795000000, "verified": true}
  ],
  "heatmap_png_b64": "iVBORw0…"
}
```

Quand rien n'est trouvé : `verdict = "unknown"`, `found_by = null`, `anchor`, `tiles`, `heatmap_png_b64` à `null` et `history = []`.
`history` : chaîne des versions, de la plus récente à l'origine (option « chaîne de versions »).
`statuses` est en ordre ligne par ligne (index = `row * cols + col`), utilisable tel quel pour la visualisation arbre ↔ image.

### `POST /api/redact`  (multipart : `image`, `entry_id`, `boxes` = JSON `[[x0,y0,x1,y1], …]`)  — option

```json
{"entry_id": "A1B2…-r1", "image_url": "/api/files/A1B2…-r1.png"}
```

### Affichage du verdict

| verdict | badge |
|---|---|
| `real` | 🟢 Real |
| `edited` | 🟠 Edited + heatmap (ou modification signée : afficher `history`) |
| `ai` | 🔵 AI-generated |
| `unknown` | ⚪ Unknown (≠ fake) + `reason` |
