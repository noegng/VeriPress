# Interfaces (contrat Dev A ↔ Dev B)

Toute modification de ce fichier, de `ledger.py`, `store.py` ou des signatures de `pipeline.py` passe par **un commit dédié (dans une PR vers `main`), annoncé à l'autre dev**.

## Python

| Module | Propriétaire | Rôle |
|---|---|---|
| `veripress/ledger.py` | Dev B | `Ledger` (protocole), `FakeLedger` (mémoire), `XrplLedger` (Testnet) |
| `veripress/store.py` | Dev A | stockage hors chaîne : manifeste + divulgation + image publiée + phash ; `find_by_watermark(wm_id, phash)` |
| `veripress/watermark.py` | Dev A | TrustMark : `embed`, `extract`, `warm_up()` (charge les modèles ; à appeler au démarrage de l'API). `VERIPRESS_WATERMARK=0` le désactive |
| `veripress/tiling.py` | Dev A | `load_upload(data: bytes, filename: str \| None) -> np.ndarray` : **point d'entrée pour les fichiers envoyés à l'API**. Gère JPEG/PNG/HEIC/WebP/AVIF/TIFF (y compris 16 bits), conversion ICC → sRGB, orientation EXIF, et les RAW d'appareils photo (CR2/CR3/NEF/ARW/RAF/RW2/ORF/DNG…, via LibRaw). Lève `ValueError` si illisible. Ne pas passer par `Image.open` avant : Pillow lit un RAW comme sa petite vignette d'aperçu |
| `veripress/pipeline.py` | Dev A | `sign_image`, `verify_image`, `redact_image`, `Report.to_json` |
| `veripress/api.py` | Dev B | FastAPI, appelle uniquement `pipeline.*` |

Le manifeste signé contient `signer`, `op` (`capture` | `ai_generate`) et `wm_id` (hex 64 bits du filigrane, choisi à la signature : l'image est tatouée **avant** l'engagement).

Le choix du ledger se fait par la variable d'env. `VERIPRESS_LEDGER=fake|xrpl` (défaut `fake`), lue dans `api.py`.

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

---

# Phase 2 (décisions : [`decisions.md`](decisions.md), séance 2)

Tout ce qui suit est **additif** : les champs et routes de la phase 1 ne changent pas.

## Outil ZK `zk/` (Dev A)

Node ≥ 20, circuits circom 2 (Groth16, BN254), `snarkjs` + `circomlib`. Une seule entrée : `node zk/cli.mjs <commande>`, **JSON sur stdin → JSON sur stdout** (code ≠ 0 en cas d'erreur, message sur stderr). Wrapper Python : `veripress/zk.py` (Dev A). Les grands entiers sont des **chaînes décimales**.

| Commande | Entrée | Sortie |
|---|---|---|
| `keygen` | `{}` | `{"sk": "<hex 32 o>", "pk": ["x", "y"]}` (Baby Jubjub) |
| `root` | `{"pks": [["x","y"], …], "depth": 10}` | `{"root": "…"}` (arbre Poseidon, feuille = `Poseidon(x, y)`, feuilles vides = 0) |
| `prove-device` | `{"sk", "pks", "index", "digest": "<hex 64>", "depth": 10}` | `{"proof": {…}, "public": ["root", "digest_hi", "digest_lo"]}` |
| `verify-device` | `{"proof", "public"}` | `{"ok": true}` |
| `commit-meta` | `{"time": unix, "lat_e6": int, "lon_e6": int, "salt": "<hex 31 o>"}` | `{"commitment": "…"}` (`Poseidon(time, lat_e6 + 90e6, lon_e6 + 180e6, salt)`) |
| `prove-meta` | `{"time", "lat_e6", "lon_e6", "salt", "t_min", "t_max", "lat_min_e6", "lat_max_e6", "lon_min_e6", "lon_max_e6"}` | `{"proof", "public": ["commitment", "t_min", "t_max", "lat_min", "lat_max", "lon_min", "lon_max"]}` |
| `verify-meta` | `{"proof", "public"}` | `{"ok": true}` |

Fichiers commités : `zk/circuits/*.circom`, `zk/build/*.wasm`, `*_final.zkey`, `*_vkey.json`. Le fichier « powers of tau » se télécharge via `zk/setup.sh` et n'est pas commité.

## Manifeste signé — nouveaux champs (Dev A)

| Champ | Valeur |
|---|---|
| `anonymous` | `true` en mode anonyme ; alors `signer = ""` |
| `meta_commitment` | `"…"` (décimal) ou `null` si la photo n'a pas d'EXIF date + GPS |
| `passkey` | clé publique P-256 SEC1 non compressée (hex) si signé par passkey, sinon `null` |

## Ledger — ajouts (Dev B, `FakeLedger` mis à jour par Dev A pour les tests)

```python
@dataclass(frozen=True)
class Anchor:              # champs ajoutés, avec valeur par défaut
    ...
    validated: bool = True          # False tant que la tx n'est pas validée (ancrage rapide)
    anonymous: bool = False
    registry_root: str = ""         # mode anonyme : racine utilisée par la preuve
    bundle_hash: str = ""           # mode anonyme / passkey : sha256 hex du paquet de preuve stocké dans store/
    cid: str = ""                   # option : CID IPFS de la divulgation

class Ledger(Protocol):
    def anchor(self, digest, signature, pubkey, wait: bool = True) -> Anchor: ...
    def anchor_anonymous(self, digest, registry_root, bundle_hash, wait: bool = True) -> Anchor: ...
    def anchor_passkey(self, digest, pubkey, bundle_hash, wait: bool = True) -> Anchor: ...  # ajouté (Dev B) : memo {d, k, w}, Anchor.signature = ""
    def fetch_anchor(self, tx_hash) -> Anchor | None: ...           # renvoie aussi les tx non validées (validated=False)
    def credential_type(self, pubkey, at_time=None) -> CredentialType | None:
        """at_time OBLIGATOIRE maintenant : Credential valide à cet instant (émis avant, pas encore supprimé)."""
    def credential_revoked_at(self, pubkey) -> int | None: ...       # date unix du CredentialDelete, sinon None
    def credential_passkey(self, pubkey) -> str | None: ...           # sha256 hex de la clé P-256 attestée dans l'URI du Credential
    def registry_root_at(self, at_time: int) -> str | None: ...       # racine du registre anonyme en vigueur à cet instant
```

Memos XRPL :
- ancrage anonyme : MemoType `veripress/v1`, MemoData `{"d": digest, "a": 1, "r": registry_root, "h": bundle_hash}` ;
- ancrage passkey : `{"d", "k": pubkey Ed25519 de l'appareil, "w": bundle_hash}` (sans `s`) ;
- racine du registre : émise par le compte registre vers lui-même, MemoType `veripress/registry-root/v1`, MemoData `{"root": "…", "depth": 10, "n": nb_appareils}`. La racine en vigueur à l'instant T est la dernière publiée avant T.
- Credential `CAPTURE_DEVICE` avec passkey : `URI` = hex de `"passkey:sha256:<hex>"`.

Fichiers de clés (script de Dev B) : `keys/device.json` et `keys/ai.json` gagnent `"bjj": {"sk", "pk"}` (via `zk keygen`) ; `keys/registry_devices.json` = `{"pks": [[x, y], …]}`, dans l'ordre de l'arbre (appareils réels + ~20 fictifs).

## Pipeline — ajouts (Dev A)

```python
sign_image(rgb, signer, ledger, store, parent=None, anonymous=False, wait=True, exif=None) -> (SignResult, png)
    # exif : octets EXIF bruts du fichier envoyé (pour date + GPS) ; anonymous et passkey s'excluent
prepare_passkey_sign(rgb, store, parent=None, exif=None) -> {"prep_id", "challenge": digest_hex}
complete_passkey_sign(prep_id, assertion: dict, ledger, store) -> (SignResult, png)
    # assertion = {"credential_id", "authenticator_data", "client_data_json", "signature", "public_key"} (base64url)
verify_stored(entry_id, ledger, store) -> (Report, heatmap)   # pour /v/<tx> : vérifie l'image publiée stockée
```

Exceptions : `ValueError` = requête invalide (→ 422 dans l'API) ; `KeyError` = entrée inconnue (→ 404).

## HTTP — ajouts

`POST /api/sign` : nouveaux champs `anonymous` (`"1"`/absent) et `wait` (`"0"` = ancrage rapide). L'API passe à `sign_image` l'EXIF brut du fichier envoyé : `exif=metadata.exif_from_upload(data)` (Dev A ; `None` pour un RAW ou sans EXIF). Réponse : nouveaux champs `"anonymous": bool`, `"pending": bool`, `"meta_claims": [...]` (même format que ci-dessous).

`POST /api/sign/passkey/prepare` (multipart `image`, `parent?`) → `{"prep_id", "challenge"}` ; `POST /api/sign/passkey/complete` (JSON `{"prep_id", "assertion"}`) → comme `/api/sign`.

`GET /v/{entry_id}` → page publique (Dev B) ; `GET /api/entry/{entry_id}` → JSON de `/api/verify` calculé sur l'image stockée (`verify_stored`).

`POST /api/verify` — clés ajoutées à la réponse :

```json
{
  "pending": false,
  "anonymous": true,
  "zk": {"proof_ok": true, "registry_root": "1234…", "root_valid_at_anchor": true},
  "credential_revoked_at": null,
  "passkey": false,
  "meta_claims": [
    {"kind": "day",  "label": "20 Nov 2026",            "proof_ok": true},
    {"kind": "area", "label": "≈ 41.12°N 16.87°E (10 km)", "proof_ok": true}
  ]
}
```

- `zk` vaut `null` en mode nominatif ; `meta_claims` vaut `[]` sans engagement de métadonnées.
- `credential_revoked_at` (unix) : renseigné si l'appareil a été révoqué **après** l'ancrage. Le verdict reste `real`, la page affiche « appareil révoqué depuis le … ».
- `pending: true` : le verdict est provisoire, et `reason` commence par « Anchor pending validation ».
- En mode anonyme, `anchor.signer` vaut `""`.
- Le libellé de zone donne le centre de la boîte arrondi à 0,01° (sans géocodage inverse) ; un nom de ville est une option côté page.

## Fenêtre de temps [T0, T1] (ajout après les slides de la piste 1)

Comme les jetons T0 / T1 d'Apple Reference Image, mais décentralisé :
- **T0** : au moment de signer, le manifeste signé contient `t0 = {"ledger_index", "ledger_hash"}`, le dernier ledger XRPL validé. Un hash de ledger est imprévisible avant la clôture de ce ledger, donc l'image a été signée **après** T0.
- **T1** : l'heure de clôture du ledger de l'ancrage.

Ledger (Dev B pour `XrplLedger` ; `FakeLedger` déjà fait par Dev A) :
```python
def latest_validated(self) -> tuple[int, str, int]: ...                       # (index, hash, close_time unix)
def ledger_close_time(self, ledger_index: int, ledger_hash: str) -> int | None: ...  # None si le hash ne correspond pas
```
Si `latest_validated` lève une exception (non implémenté, réseau), on signe sans T0.

`/api/verify` : nouvelle clé `"time_window": {"not_before": unix | null, "not_after": unix, "ledger_index": int | null, "t0_ok": bool}` (`null` quand rien n'est trouvé). Affichage proposé : « signée entre 14:02:31 et 14:02:52 UTC », avec le lien vers le ledger T0.

## Négatif RAW → JPEG de référence (`op = "develop"`)

Calqué sur Apple Reference Image (phase 1 : négatif numérique signé ; phase 2 : JPEG de référence), mais ancré sur XRPL :
- `sign_image(rgb_jpeg, "device", …, parent=<tx du RAW>, op="develop")`. Refusé (`ValueError`) sans `parent`, ou si le RAW n'a pas été signé par **la même clé d'appareil**, ou en mode anonyme ;
- vérification : `verdict = real`, motif « Developed from the signed RAW negative <tx> by the same CAPTURE_DEVICE … », `history = [develop, capture]`, si la chaîne vérifie et que les deux signataires sont identiques ; sinon `edited` (« Signed development … could not be verified ») ;
- démo : `uv run python -m veripress.cli demo-raw fichier.CR3 -o out/`.

Option pour Dev B : un champ `op=develop` (avec `parent`) dans `/api/sign`, à passer à `sign_image(op=…)`.
