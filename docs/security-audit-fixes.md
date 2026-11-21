# Audit de sécurité VeriPress — spécification des correctifs

**Date :** 21 novembre 2026
**Périmètre :** cœur cryptographique et logique de verdict (`backend/src/veripress/`)
**Base :** `283 passed, 9 skipped` avant correctifs. Les cinq attaques ci-dessous ne sont couvertes par aucun test existant.
**But de ce document :** donner à un agent de développement une spec exécutable, finding par finding, avec la cause, l'attaque, la preuve, le correctif et le test de régression.

> **Règle d'or :** chaque finding doit avoir un test qui **échoue avant** le correctif et **passe après**. Ne pas "corriger" en assouplissant un invariant de sécurité (voir §7).

---

## 0. Mode d'emploi

```bash
cd backend
uv run python -m pytest -q                 # doit rester à 283 passed, 9 skipped (+ nouveaux tests)
```

Ordre conseillé (du moins risqué au plus invasif) :

1. **F2** — parseur de store total (rapide, aucun changement d'API publique).
2. **F1** — suppression de la troncature des candidats (petit diff).
3. **F3** — credential à l'instant de l'ancre dans la chaîne de versions (petit diff + test).
4. **F4/F5** — mode `lossless` explicite (traverse `commitment` → `pipeline` → `api`).
5. **F6** — hardening passkey `at_time` (optionnel).

Après chaque tâche : lancer la suite complète, puis mettre à jour `docs/security-review.md` et `docs/architecture.md` (voir §8).

---

## 1. Résumé

| ID | Sévérité | Type | Fichiers principaux | Effet avant correctif |
|----|----------|------|---------------------|------------------------|
| F1 | **Élevée** | Disponibilité de la provenance | `pipeline.py`, `store.py` | 8 enregistrements plantés → la vraie photo devient ⚪ *Unknown* |
| F2 | **Élevée** | Déni de service | `store.py`, `api.py` | 1 fichier malformé → HTTP 500 sur `/api/verify` et `/api/lookup` |
| F3 | **Moyenne** | Chaîne de confiance | `pipeline.py` | Une capture antérieure à l'accréditation devient 🟢 *Real* via `develop` |
| F4 | **Élevée** | Intégrité du contenu | `commitment.py`, `pipeline.py`, `api.py` | +1 invisible désactive le garde "lossless" : flou subtil → 🟢 |
| F5 | **Moyenne-élevée** | Intégrité du contenu | `commitment.py` | Contenu forgé visible sous une rédaction → 🟢 avec "redacted" |
| F6 | Faible | Cohérence temporelle | `pipeline.py`, `ledger.py` | Attestation passkey lue au présent, pas à l'ancre |

---

## 2. F1 — Saturation de `MAX_CANDIDATES` : suppression de la provenance

### Cause

`backend/src/veripress/pipeline.py:447-469`

```python
        candidates = [(e, "watermark") for e in (store.find_all_by_watermark(wm.hex(), ph) if wm else [])]
        seen = {e.id for e, _ in candidates}
        candidates += [(e, "phash") for e in store.nearest_all(ph) if e.id not in seen]
        candidates = candidates[:MAX_CANDIDATES]      # <-- troncature AVANT vérification
    ...
    best = max((_verify_entry(rgb, e, f, ledger, store) for e, f in candidates), key=_support)
MAX_CANDIDATES = 8
```

Le store est non fiable et public par conception (`docs/architecture.md` § "Lookup at verification"). Un attaquant copie `manifest.wm_id` et `phash` de l'enregistrement genuin (tous deux publics), crée 8 enregistrements avec des ids qui trient avant le vrai hash (`0000000000000000`, `0000000000000001`, …), et le genuin devient le **9ᵉ candidat : il n'est jamais vérifié**.

Cela contredit l'affirmation de `docs/architecture.md` : « every candidate … is fully verified; the best-supported one wins … a planted record used to hide the genuine one ». Le plafond rend le correctif A6 contournable.

### Attaque (PoC)

```python
signed, png = sign_image(photo, "device", ledger, store)
shared = jpeg(png_to_rgb(png), 80)                 # la copie partagée
e = store.get(signed.entry_id)
for k in range(8):
    store.put(Entry(f"{k:016X}", f"{0xDEAD0000+k:064X}", e.manifest, e.disclosure, phash(shared)))
report, _ = verify_image(shared, ledger, store)
# AVANT : UNKNOWN ("Anchor transaction 0000… not found") ; le genuin est candidat #9
# APRÈS : REAL, entry_id == signed.entry_id
```

### Correctif

**Supprimer la troncature avant vérification.** Vérifier tous les candidats ; `max` choisit déjà le meilleur. Ne **pas** dédupliquer par `tx_hash` : `Entry.tx_hash` vient du store non fiable, un attaquant peut le mettre égal à celui du genuin et faire disparaître ce dernier.

```python
        candidates = [(e, "watermark") for e in (store.find_all_by_watermark(wm.hex(), ph) if wm else [])]
        seen = {e.id for e, _ in candidates}
        candidates += [(e, "phash") for e in store.nearest_all(ph) if e.id not in seen]
        # PAS de candidates[:MAX_CANDIDATES] : un attaquant qui peut écrire dans le store
        # pourrait planter MAX_CANDIDATES enregistrements triés avant le genuin et le cacher
        # (audit F1). On vérifie tout ; le coût est borné par le store, à limiter côté API.
```

Option de performance (sans changer la correction) : évaluer les candidats dans l'ordre (watermark d'abord, puis distance pHash croissante) et **s'arrêter dès qu'un verdict `REAL`/`AI` est trouvé** — c'est le rang maximal, aucun enregistrement planté ne peut l'atteindre sans signature/ancre valide. Cela n'empêche pas un flood *avant* le genuin, mais évite de tout vérifier dans le cas normal.

Supprimer `MAX_CANDIDATES` ou le renommer `MAX_DISPLAYED_CANDIDATES` s'il sert à l'affichage. Ajouter une limite de débit / un budget temps **au niveau API** (pas une troncature silencieuse).

### Test de régression

Dans `backend/tests/test_adversarial.py` (section « lookup poisoning ») :

```python
def test_eight_planted_records_do_not_hide_the_genuine_one(photo, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    shared = jpeg(png_to_rgb(png), 80)
    e = store.get(signed.entry_id)
    for k in range(8):
        store.put(Entry(f"{k:016X}", f"{0xDEAD0000 + k:064X}", e.manifest, e.disclosure, phash(shared)))
    report, _ = verify_image(shared, ledger, store)
    assert report.verdict == FinalVerdict.REAL
    assert report.entry_id == signed.entry_id
```

Variante watermark (optionnelle) : mettre `e.manifest.wm_id = "ab" * 8`, replacer l'entrée, et `monkeypatch.setattr(pipeline.watermark, "extract", lambda rgb: bytes.fromhex("ab" * 8))`, `monkeypatch.setattr(pipeline.watermark, "enabled", lambda: True)`. Les 8 plantés héritent du `wm_id` et trient avant.

### Definition of Done

- [ ] Plus de `candidates[:MAX_CANDIDATES]` avant `_verify_entry`.
- [ ] Le test ci-dessus passe (avant : `UNKNOWN`).
- [ ] `docs/architecture.md` : l'affirmation « every candidate is verified » redevient vraie ; mentionner la limite de coût et le rate limit API.

---

## 3. F2 — Un enregistrement malformé casse toutes les vérifications sans id

### Cause

`backend/src/veripress/store.py:144-160` :

```python
    def find_all_by_watermark(self, wm_id, phash):
        for p in self.root.glob("*/entry.json"):
            d = json.loads(p.read_text())
            if d["manifest"].get("wm_id") == wm_id:
                found.append(((phash ^ int(d["phash"], 16)).bit_count(), "-r" in d["id"], d["id"]))
        ...

    def nearest_all(self, phash, max_distance=10):
        for p in self.root.glob("*/entry.json"):
            dist = (phash ^ int(json.loads(p.read_text())["phash"], 16)).bit_count()
        ...
```

Un JSON invalide, ou un objet sans `phash`/`manifest`, lève `JSONDecodeError`/`KeyError`. `verify_image` propage, et `api.py:416-423` n'a aucun `try/except` :

```python
@app.post("/api/verify")
async def verify(image: UploadFile = File(...), entry_id: str | None = Form(None)):
    ...
    report, heatmap = await run_in_threadpool(
        pipeline.verify_image, rgb, app.state.ledger, app.state.store, entry_id
    )
```

→ **HTTP 500 pour toute image sans `entry_id`**, et idem `/api/lookup` (`lookup_records` → `nearest_all`). Un seul fichier suffit.

### Preuve (API)

```python
c = TestClient(api.app, raise_server_exceptions=False)
# store vide
assert c.post("/api/verify", files={"image": ("x.png", png(), "image/png")}).status_code == 200
# l'attaquant dépose un enregistrement sans "phash"
(STORE / "0000000000000000").mkdir(parents=True)
(STORE / "0000000000000000" / "entry.json").write_text('{"id": "0000000000000000"}')
# AVANT : 500 ; APRÈS : 200, verdict "unknown"
assert c.post("/api/verify", files={"image": ("x.png", png(), "image/png")}).status_code == 200
assert c.post("/api/lookup", files={"image": ("x.png", png(), "image/png")}).status_code == 200
```

### Correctif

**Rendre le parseur total.** Centraliser la lecture d'une entrée et ignorer (journaliser) les enregistrements invalides.

Dans `store.py` :

```python
    @staticmethod
    def _read_entry(path: Path) -> "Entry | None":
        try:
            d = json.loads(path.read_text())
            return Entry(
                id=d["id"],
                tx_hash=d["tx_hash"],
                manifest=Manifest.from_dict(d["manifest"]),
                disclosure=Disclosure.from_dict(d["disclosure"]),
                phash=int(d["phash"], 16),
            )
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def get(self, entry_id: str) -> "Entry | None":
        if not valid_id(entry_id):
            return None
        p = self.root / entry_id / "entry.json"
        return self._read_entry(p) if p.exists() else None

    def find_all_by_watermark(self, wm_id: str, phash: int) -> list["Entry"]:
        found = []
        for p in self.root.glob("*/entry.json"):
            try:
                d = json.loads(p.read_text())
                if d["manifest"].get("wm_id") != wm_id:
                    continue
                dist = (phash ^ int(d["phash"], 16)).bit_count()
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                continue
            found.append((dist, "-r" in str(d.get("id", "")), p.parent.name))
        return [e for _, _, i in sorted(found) if (e := self.get(i)) is not None]

    def nearest_all(self, phash: int, max_distance: int = 10) -> list["Entry"]:
        found = []
        for p in self.root.glob("*/entry.json"):
            try:
                dist = (phash ^ int(json.loads(p.read_text())["phash"], 16)).bit_count()
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if dist <= max_distance:
                found.append((dist, "-r" in p.parent.name, p.parent.name))
        return [e for _, _, i in sorted(found) if (e := self.get(i)) is not None]
```

Appliquer le même traitement à `find_by_watermark`, `nearest`, `get_bundle`, `get_meta`, `get_pq`, `get_receipt` (ces trois derniers attrapent déjà `ValueError` ; ajouter `TypeError`/`OSError`). Un `bundle.json` malformé lève aujourd'hui dans `_check_anonymous`/`_check_passkey` (`json.loads` non protégé) : le protéger aussi.

**Défense en profondeur dans `pipeline.verify_image`** : entourer la découverte des candidats d'un `try/except Exception` et retourner `UNKNOWN` avec une raison, jamais laisser remonter une exception de données non fiables. Et dans `api.py`, ne jamais répondre 500 sur une erreur de store :

```python
    try:
        report, heatmap = await run_in_threadpool(
            pipeline.verify_image, rgb, app.state.ledger, app.state.store, entry_id
        )
    except Exception as e:  # noqa: BLE001 — store non fiable
        log.exception("VeriPress: verification failed")
        raise HTTPException(503, "verification temporarily unavailable") from e
```

Le vrai correctif reste le parseur total ; le wrapper évite les 500 sur les erreurs imprévues.

### Test de régression

```python
def test_a_malformed_store_record_does_not_break_id_less_verification(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    bad = store.root / "0000000000000000"
    bad.mkdir(parents=True, exist_ok=True)
    (bad / "entry.json").write_text('{"id": "0000000000000000"}')
    report, _ = verify_image(png_to_rgb(png), ledger, store)   # ne doit pas lever
    assert report.verdict == FinalVerdict.REAL
    assert report.entry_id == signed.entry_id
```

Et un test API (dans `test_api.py`) : déposer le fichier malformé dans `app.state.store.root`, puis `POST /api/verify` et `POST /api/lookup` → `200`, pas `500`.

### Definition of Done

- [ ] Aucun `json.loads` non protégé sur un fichier du store.
- [ ] `/api/verify` et `/api/lookup` répondent 200 (verdict `unknown` ou résultat normal) avec un store malformé.
- [ ] Le test ci-dessus passe.

---

## 4. F3 — `develop` officialise une capture antérieure à l'accréditation

### Cause

`backend/src/veripress/pipeline.py:703-710` :

```python
    out["verified"] = bool(
        (out["pq"] is None or (out["pq"]["signature_ok"] and out["pq"]["attested"]))
        and out["manifest_matches"] and out["sig_ok"]
        and (not anchor.anonymous or out["credential"] is not None)  # <-- seulement anonyme
        and (not out["passkey"] or out["passkey_attested"])
    )
```

Pour une signature **nommée** (Ed25519) ou **passkey**, `verified` ne vérifie pas que la clé avait un credential **à l'instant de l'ancre**. `_history` (`pipeline.py:712-724`) marque donc `verified=True` une capture ancrée avant l'émission du credential. La branche `develop` (`pipeline.py:570-588`) voit `all(h["verified"])` et son propre credential valide → **REAL**, alors que la capture seule est **UNKNOWN** (« Signer has no valid credential »).

### Preuve

```python
# capture ancrée à T=1000, aucun credential à cette date
rc, _ = verify_image(cap_png, ledger, store, entry_id=cap.entry_id)   # UNKNOWN
ledger.issue(device_pubkey, CredentialType.CAPTURE_DEVICE, at=2000)    # accrédité plus tard
dev, dev_png = sign_image(cap_rgb, "device", ledger, store, parent=cap.entry_id, op="develop")
rd, _ = verify_image(dev_png, ledger, store, entry_id=dev.entry_id)    # AVANT : REAL
# history flags : [True, True]  (la capture est "verified" sur la seule signature)
```

### Correctif

Exiger un credential à l'instant de l'ancre **pour tous les modes** :

```python
    out["verified"] = bool(
        (out["pq"] is None or (out["pq"]["signature_ok"] and out["pq"]["attested"]))
        and out["manifest_matches"] and out["sig_ok"]
        and out["credential"] is not None          # <-- tous les modes
        and (not out["passkey"] or out["passkey_attested"])
    )
```

C'est sûr : `credential` vaut déjà `CAPTURE_DEVICE` en anonyme si la racine était en vigueur à l'ancre, et `ledger.credential_type(pubkey, anchor.timestamp)` en nommé/passkey. La révocation non rétroactive reste correcte : un credential valide à l'ancre mais révoqué depuis donne toujours `credential != None` (l'intervalle couvre l'ancre).

Pour un message d'erreur plus clair, ajouter `credential` au dict de `_history` et l'utiliser dans la branche `develop` :

```python
        out.append({"tx_hash": tx_hash, "op": m.op, "timestamp": anchor.timestamp,
                    "verified": ok, "credential": auth["credential"]})
        ...
        chain_ok = (
            all(h["verified"] for h in history) and len(history) >= 2
            and history[1]["op"] == "capture" and history[1]["credential"] is not None
            ...
        )
```

### Test de régression

```python
import time
from dataclasses import replace
from veripress.ledger import CredentialType, FakeLedger

def test_develop_of_a_capture_anchored_before_accreditation_is_an_edit(photo, keys, tmp_path, no_watermark):
    class TimedLedger(FakeLedger):
        """Même sémantique que XrplLedger.credential_type(at_time) : intervalles de validité."""
        def __init__(self):
            super().__init__(); self.issued = {}
        def issue(self, pk, ctype, passkey_hash=None, pq_hash=None, at=None):
            super().issue(pk, ctype, passkey_hash, pq_hash, at)
            self.issued[pk] = int(time.time()) if at is None else at
        def credential_type(self, pk, at_time=None):
            if at_time is not None:
                since = self.issued.get(pk)
                if since is None or at_time < since:
                    return None
            return super().credential_type(pk, at_time)

    ledger = TimedLedger()
    store = Store(tmp_path / "store")
    cap, cap_png = sign_image(photo, "device", ledger, store)          # avant tout credential
    ledger.anchors[cap.entry_id] = replace(ledger.anchors[cap.entry_id], timestamp=1000)
    rc, _ = verify_image(png_to_rgb(cap_png), ledger, store, entry_id=cap.entry_id)
    assert rc.verdict == FinalVerdict.UNKNOWN

    ledger.issue(keys["device"], CredentialType.CAPTURE_DEVICE, at=2000)  # accrédité plus tard
    dev, dev_png = sign_image(png_to_rgb(cap_png), "device", ledger, store,
                              parent=cap.entry_id, op="develop")
    rd, _ = verify_image(png_to_rgb(dev_png), ledger, store, entry_id=dev.entry_id)
    assert rd.verdict == FinalVerdict.EDITED   # avant le correctif : REAL
```

Vérifier aussi que `test_develop.py` (credential émis avant le signing) reste vert.

### Definition of Done

- [ ] `verified` exige `credential is not None` pour tous les modes.
- [ ] Le test ci-dessus passe (avant : `REAL`).
- [ ] `docs/security-review.md` : documenter le cas « capture avant accréditation + develop après ».

---

## 5. F4 — Le garde "copie lossless" est contrôlé par l'attaquant (+1 invisible)

### Cause

`backend/src/veripress/commitment.py:271-281` :

```python
    textured = [k for k, t in enumerate(tiles) if not t.redacted and F.is_textured(t.f, spec)]
    exact_textured = sum(statuses[k] == TileStatus.EXACT for k in textured)
    if textured and exact_textured >= LOSSLESS_EXACT_SHARE * len(textured):
        for k, s in enumerate(statuses):
            if s == TileStatus.ROBUST:
                statuses[k] = TileStatus.CHANGED
            elif s == TileStatus.REDACTED and np.percentile(...) > REDACTED_MAX_LOSSLESS_P99:
                statuses[k], distances[k] = TileStatus.CHANGED, float("inf")
```

`EXACT` = feuille exacte = pixels **byte-identiques**. Il suffit de modifier **un pixel par tuile** (+1), ou tous les pixels de +1 : c'est invisible, le PNG reste lossless, mais plus aucune tuile n'est `EXACT`. Le garde s'éteint et une retouche subtile redevient `ROBUST` → **REAL**.

### Preuve

```
blur pristine        -> EDITED   exact=284 robust=  0 changed=16
blur +1px/tile       -> REAL     exact=  0 robust=300 changed= 0
blur +1 all          -> REAL     exact=  0 robust=300 changed= 0
```

`+1px/tile` = **300 pixels sur 921 600 (0,03 %)**. C'est une régression des correctifs A2'/A9 et cela contredit `docs/security-review.md` : « In a lossless copy (PNG), any such edit is detected. »

### Correctif

Le caractère "lossless" doit être une propriété **du fichier reçu** (codec), pas de la comparaison pixel. Le vérificateur reçoit les octets dans l'API ; on les propage.

**1. `commitment.verify`** — ajouter `lossless: bool | None = None` :

```python
def verify(rgb: np.ndarray, manifest: Manifest, disclosure: Disclosure,
           lossless: bool | None = None) -> VerifyResult:
    ...
    strict = lossless
    if strict is None:   # rétro-compat : tests/CLI sans info de codec
        strict = bool(textured) and exact_textured >= LOSSLESS_EXACT_SHARE * len(textured)
    if strict:
        for k, s in enumerate(statuses):
            if s == TileStatus.ROBUST:
                statuses[k] = TileStatus.CHANGED
            elif s == TileStatus.REDACTED and np.percentile(tile_pixels(rgb, grid, tiles[k].i), 99) > REDACTED_MAX_LOSSLESS_P99:
                statuses[k], distances[k] = TileStatus.CHANGED, float("inf")
        original_tiles = 0
```

**2. `pipeline`** — propager le paramètre :

```python
def verify_image(rgb, ledger, store, entry_id=None, heatmap_png=True, lossless=None):
    ...
    best = max((_verify_entry(rgb, e, f, ledger, store, lossless) for e, f in candidates), key=_support)

def _verify_entry(rgb, entry, found_by, ledger, store, lossless=None):
    ...
    tiles = verify(rgb, manifest, entry.disclosure, lossless=lossless)
```

`verify_stored` (l'image publiée est le PNG signé) : `lossless=True`.

**3. `api.py`** — détecter le codec et le passer :

```python
LOSSLESS_FORMATS = {"PNG", "TIFF", "BMP", "GIF", "ICO"}

def lossless_codec(data: bytes) -> bool:
    try:
        img = Image.open(io.BytesIO(data))
        if img.format == "WEBP":
            return bool(img.info.get("lossless"))
        return img.format in LOSSLESS_FORMATS
    except Exception:  # noqa: BLE001 — illisible : laisser le défaut
        return False

@app.post("/api/verify")
async def verify(image: UploadFile = File(...), entry_id: str | None = Form(None)):
    ...
    report, heatmap = await run_in_threadpool(
        pipeline.verify_image, rgb, app.state.ledger, app.state.store, entry_id, want,
        lossless_codec(data),
    )
```

**4. CLI** (optionnel mais recommandé) : passer `lossless=path.suffix.lower() in {".png", ".tif", ".tiff", ".bmp"}` aux appels `verify_image` de `cli.py:182/287/312/384`.

**Conséquence assumée :** un PNG issu d'un JPEG (re-save lossless d'une image déjà lossy) sera traité en strict et pourra afficher des tuiles changées. C'est acceptable : ce n'est pas une copie lossless de l'image signée. Si gênant, ajouter un détecteur de bruit JPEG (blockiness 8×8) et ne forcer le strict que si le fichier est lossless **et** sans artefacts JPEG.

### Test de régression

```python
def shift(rgb, d):
    return np.clip(rgb.astype(np.int16) + d, 0, 255).astype(np.uint8)

def test_plus_one_does_not_disable_the_lossless_guard(photo, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    blurred = blur(png_to_rgb(png), 0.8)                 # helper existant de test_adversarial.py
    # sans lossless explicite : le garde tombe (comportement actuel)
    assert verify_image(shift(blurred, 1), ledger, store, entry_id=signed.entry_id)[0].verdict == FinalVerdict.REAL
    # avec lossless=True (ce que fait l'API pour un PNG) : la retouche est détectée
    report, _ = verify_image(shift(blurred, 1), ledger, store, entry_id=signed.entry_id, lossless=True)
    assert report.verdict == FinalVerdict.EDITED
```

Test API : uploader un PNG +1 avec un flou → `verdict == "edited"` (l'API passe `lossless=True`).

### Definition of Done

- [ ] `commitment.verify` accepte `lossless`.
- [ ] `verify_image`/`_verify_entry`/`verify_stored` propagent `lossless` ; `verify_stored` force `True`.
- [ ] L'API détecte le codec et passe `lossless=True` pour PNG/TIFF/BMP.
- [ ] Le test ci-dessus passe (avant : `REAL`).
- [ ] `docs/security-review.md` : la phrase « In a lossless copy (PNG), any such edit is detected » devient vraie **au niveau du codec**, pas de l'identité pixel.

---

## 6. F5 — Contenu forgé visible sous une rédaction, accepté comme "redacted"

### Cause

`backend/src/veripress/commitment.py:247-253` et `275-281` :

```python
            hidden = px.mean() <= REDACTED_MAX_MEAN and np.percentile(px, 95) <= REDACTED_MAX_P95
            ...
            elif s == TileStatus.REDACTED and np.percentile(...) > REDACTED_MAX_LOSSLESS_P99:
```

Le contrôle strict `p99 <= 8` n'est appliqué qu'en mode lossless. Avec F4 (ou sur un JPEG), une tuile rédigée ne doit satisfaire que `mean <= 16` et `p95 <= 48`. Un attaquant remplit jusqu'à **46,7 %** de l'image (≤ 50 % de tuiles rédigées autorisées, `MAX_REDACTED_SHARE = 0.5`) avec du contenu **visible** gris foncé sur noir, ajoute +1, et obtient :

```
half the image redacted, then filled with visible dark content -> REAL
tiles: changed=0 redacted=140 / 300
```

C'est A9 généralisé à près de la moitié de l'image.

### Correctif

F4 corrige déjà le cas lossless (le `p99 <= 8` s'applique dès que `lossless=True`). Pour F5 :

1. **Appliquer F4** (le strict dès qu'on sait que le fichier est lossless).
2. **Resserrer la borne** : exiger une zone quasi uniforme, pas seulement sombre en moyenne. Exemple :

```python
REDACTED_MAX_STD = 6  # une zone rédigée est quasi uniforme, pas un dégradé/text
...
hidden = (
    px.mean() <= REDACTED_MAX_MEAN
    and np.percentile(px, 95) <= REDACTED_MAX_P95
    and float(px.std()) <= REDACTED_MAX_STD
)
```

Calibrer `REDACTED_MAX_STD` sur les tests JPEG existants (`test_redacted_copy_shared_as_jpeg_keeps_its_redacted_tiles`) pour ne pas créer de faux `CHANGED` sur le bruit JPEG d'une zone noire. Si le bruit JPEG dépasse la borne, appliquer `REDACTED_MAX_STD` uniquement en mode `lossless=True` et garder mean/p95 en lossy.

3. **Test** : reprendre le PoC F5 (rédaction de 7 lignes de tuiles, remplissage gris foncé + texte, +1) et exiger `EDITED` avec `lossless=True`.

### Test de régression

```python
def test_visible_dark_content_under_a_redaction_is_edited(photo, ledger, store, no_watermark):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(0, 0, 640, 224)], store)
    im = Image.fromarray(png_to_rgb(red_png)); d = ImageDraw.Draw(im)
    d.rectangle((40, 40, 600, 200), fill=(8, 8, 8))
    d.text((60, 60), "This text was never in the signed photo", fill=(40, 40, 40))
    for x in range(60, 580, 24):
        d.line((x, 100, x + 12, 160), fill=(36, 36, 36), width=2)
    forged = shift(np.asarray(im), 1)
    report, _ = verify_image(forged, ledger, store, entry_id=rid, lossless=True)
    assert report.verdict == FinalVerdict.EDITED
    assert report.tiles.counts()["changed"] > 0
```

### Definition of Done

- [ ] En mode `lossless=True`, une tuile rédigée avec du contenu visible (texte/formes) est `CHANGED`.
- [ ] Les tests JPEG de rédaction restent verts (pas de faux positif sur le bruit JPEG).
- [ ] `docs/security-review.md` : la limite « In a lossless copy the area must be truly black » est vraie.

---

## 7. F6 (hardening, optionnel) — Attestation passkey lue au présent

`backend/src/veripress/pipeline.py:362-377` :

```python
        attested = ledger.credential_passkey(anchor.pubkey) == _sha256_hex(manifest.passkey)
```

`credential_passkey` n'a pas de `at_time` : c'est la **dernière** attestation qui est comparée, pas celle en vigueur à l'ancre. Ce n'est pas une forge (le registre contrôle l'attestation), mais cela crée des incohérences temporelles (un manifeste ancien accepté avec une passkey attestée plus tard, ou qui échoue après une ré-attestation).

Correctif : ajouter `at_time: int | None = None` à `Ledger.credential_passkey`, l'implémenter dans `FakeLedger` (mémoriser l'instant d'attestation) et `XrplLedger` (déjà `_credential_uri(..., at_time)`), et appeler `ledger.credential_passkey(anchor.pubkey, at_time=anchor.timestamp)`. Test : attester une passkey après l'ancre → la vérification de l'ancien manifeste ne doit pas l'accepter.

---

## 8. Invariants à ne **pas** casser

- **Ne pas** transformer les features robustes en hash d'image complet : la tolérance 21 coefficients DCT est le compromis assumé (survit à JPEG/resize). La limite « détails fins » reste documentée.
- **Ne pas** forcer le mode strict sur les JPEG : cela produirait des faux `EDITED` sur toutes les copies WhatsApp. Le mode strict est pour les codecs **sans perte**.
- **Ne pas** supprimer la rédaction ni augmenter `MAX_REDACTED_SHARE` : le seuil 50 % est un choix produit.
- **Ne pas** dédupliquer les candidats par `tx_hash` (non fiable). Si dédup, uniquement par identité de fichier (`id`) et sans jamais écarter un candidat valide.
- **Ne pas** toucher à la vérification Ed25519 / WebAuthn / ML-DSA / ZK : elle est saine (aucune forge trouvée).
- Le point EdDSA `(0,1)` dans `device.circom` n'est pas exploitable (le registre ne le contient pas et la feuille est liée à `Poseidon(Ax,Ay)`). Une vérification défensive « A ≠ identité » est possible mais non prioritaire.

---

## 9. Mise à jour de la documentation

- `docs/security-review.md` :
  - Ajouter une section « Audit 21/11 » avec F1–F5, le statut « corrigé » et les tests.
  - Corriger la limite : « In a lossless copy (PNG), any such edit is detected » → préciser **détection basée sur le codec**, et que le +1 pixel ne désactive plus le garde.
  - Ajouter F1/F2 comme limites de **disponibilité** (store non fiable) avec le rate limit API en production.
- `docs/architecture.md` :
  - § « Lookup at verification » : « every candidate is verified » reste vrai ; retirer/justifier le plafond de 8 (affichage seulement).
  - § « Off-chain store » : mentionner que les enregistrements malformés sont ignorés, pas fatals.
  - § « Verdict » : le mode strict dépend du codec du fichier reçu, pas de l'identité des pixels.

---

## 10. Checklist finale

- [ ] F1 : plus de troncature avant vérification ; test `8 plantés + genuin → REAL`.
- [ ] F2 : parseur de store total ; `/api/verify` et `/api/lookup` ne renvoient plus 500 sur un fichier malformé ; test API.
- [ ] F3 : `verified` exige un credential à l'ancre pour tous les modes ; test capture-avant-accréditation → `EDITED`.
- [ ] F4 : `lossless` propagé depuis l'API (codec) ; test `+1 + flou → EDITED`.
- [ ] F5 : contenu visible sous rédaction → `EDITED` en lossless ; tests JPEG verts.
- [ ] F6 (optionnel) : `credential_passkey(at_time)`.
- [ ] `uv run python -m pytest -q` : tous les tests passent (283 + nouveaux).
- [ ] Aucun fichier du projet modifié en dehors du code, des tests et de la doc.
- [ ] Les PoC de l'audit (scripts `final_poc.py`, `api_poc.py`, `onepix.py`) ou leurs équivalents pytest échouent avant, passent après.

---

## 11. Annexe — commandes de reproduction

Les scripts de l'audit (hors dépôt) :

```bash
cd backend
PYTHONPATH=src uv run python /private/var/folders/dg/7h26w0w92ndcb3fmhq_px37r0000gn/T/opencode/veripress-poc/final_poc.py
PYTHONPATH=src uv run python /private/var/folders/dg/7h26w0w92ndcb3fmhq_px37r0000gn/T/opencode/veripress-poc/api_poc.py
PYTHONPATH=src uv run python /private/var/folders/dg/7h26w0w92ndcb3fmhq_px37r0000gn/T/opencode/veripress-poc/onepix.py
```

Si le dossier temporaire a été nettoyé, les tests de régression des §2–§6 sont autosuffisants et remplacent les scripts.
