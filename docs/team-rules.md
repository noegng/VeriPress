# Règles d'équipe — à lire par chaque agent avant de coder

Hackathon IXH26. **Gel des fonctionnalités : sam. 21 nov. 10:00. Rendu : 12:00. Pitch : 12:30.**
Deux devs, deux agents Claude, en parallèle. Le but de ces règles est de ne jamais se marcher dessus.

## 1. Qui fait quoi

- **Dev A, « confiance et vérification »** : signature, pipeline, verdict final, store, filigrane. Tâches : [`tasks-dev-a.md`](tasks-dev-a.md)
- **Dev B, « registre et interface »** : XRPL Testnet, API FastAPI, page web, visualisations. Tâches : [`tasks-dev-b.md`](tasks-dev-b.md)

## 2. Propriété des fichiers

Un agent **ne modifie que les fichiers de son dev**. S'il a besoin d'un changement chez l'autre, il le signale à son humain au lieu de le faire.

| Dev A | Dev B | Partagés (commit dédié sur `main`, annoncé) |
|---|---|---|
| `backend/src/tileproof/commitment.py` | `backend/src/tileproof/ledger.py` (corps de `XrplLedger`) | `docs/interfaces.md` |
| `backend/src/tileproof/signing.py` | `backend/src/tileproof/api.py` | signatures publiques de `ledger.py`, `store.py`, `pipeline.py` |
| `backend/src/tileproof/pipeline.py` (corps) | `backend/src/tileproof/static/**` | `backend/pyproject.toml` + `uv.lock` |
| `backend/src/tileproof/store.py` (corps) | `backend/scripts/**` | `README.md`, `docs/plan.md`, `CLAUDE.md`, ce fichier |
| `backend/src/tileproof/watermark.py` | `backend/tests/test_ledger*.py`, `test_api*.py` | `backend/tests/conftest.py` (ajouts seulement) |
| `backend/src/tileproof/cli.py`, `features.py`, `tiling.py`, `merkle.py` | | |
| `backend/tests/` (sauf les fichiers de B) | | |
| **Phase 2 :** `zk/**`, `backend/src/tileproof/zk.py`, `metadata.py`, `c2pa_embed.py`, WebAuthn dans `signing.py` | **Phase 2 :** `/v/<tx>` (page + route), routes passkey, ancrage rapide et `credential_*`/`registry_root_at` dans `XrplLedger`, publication des racines dans `scripts/` | `FakeLedger` : Dev A le complète pour ses tests, Dev B le garde aligné sur `XrplLedger` |

## 3. Git

- Branches courtes : `dev-a/<sujet>`, `dev-b/<sujet>`. Jamais de `push --force` sur `main`.
- **Fusion dans `main` par PR GitHub** (depuis le 20/11 au soir), y compris les changements de contrat partagé : un commit dédié dans la PR, annoncé dans sa description.
- **Dépendances** : dans un commit à part (sur `main` ou dans sa propre PR) (`uv add …` puis commit de `pyproject.toml` + `uv.lock`), pour éviter les conflits de lockfile. Déjà ajoutées : fastapi, uvicorn, python-multipart, xrpl-py, cryptography. TrustMark sera ajouté par Dev A le moment venu.
- **Points de synchro** (fusion dans `main`, chacun fait un rebase sur `main` avant) : **~23:00, ~03:00, 08:00, 10:00 (gel)**. Entre deux synchros, on peut fusionner plus souvent si c'est vert.
- Avant de fusionner : `cd backend && uv run python -m pytest` doit passer.
- Jamais de commit de `backend/keys/`, `backend/store/`, de seeds ou de `.env`.

## 4. Travailler sans attendre l'autre

- Dev A développe et teste avec `FakeLedger` (aucun réseau).
- Dev B développe la page contre les JSON d'exemple de `docs/interfaces.md` tant que `pipeline.py` lève `NotImplementedError` (réponse simulée dans `api.py`, retirée à la synchro).
- Variable `TILEPROOF_LEDGER=fake|xrpl` : on passe sur `xrpl` seulement quand `XrplLedger` est prêt.

## 5. Méthode (plugin mattpocock-skills, mode hackathon)

- Question de conception ou d'interface → skill `prototype` (jetable, plusieurs variantes).
- Bloqué plus de 20 min sur un bug → skill `diagnosing-bugs`.
- **TDD (skill `tdd`) uniquement** sur : arbres de Merkle et preuves de masquage, et règles du verdict final (`pipeline.py`). Le reste se vérifie à la main ou avec un test de fumée.
- À ne pas utiliser : `/implement` en TDD partout, `/to-spec`, `/to-tickets`, `/triage`, `/wayfinder`, `/improve-codebase-architecture`, `/setup-matt-pocock-skills`.
- Avant le gel : `/security-review` sur la partie XRPL et signature.
- Fin de session ou passage de relais : ajouter 3 lignes en bas de sa fiche de tâches (ce qui marche, ce qui reste, comment lancer).

## 6. Périmètre de la démo

Doit marcher : (1) photo signée → 🟢, (2) retouche → 🟠 + heatmap, (3) image passée par WhatsApp (préparée à l'avance) → provenance retrouvée, tuiles 🟢, (6) image IA → 🔵.
Options, dans l'ordre : filigrane TrustMark (+ étape 5 : copie détectée) · masquage dans la page (étape 4) · visualisation arbre ↔ image · vraie passkey WebAuthn · chaîne de versions (`parent`).
Réseau : **XRPL Testnet**. Ancrage : Payment 1 drop + Memo. Signature : Ed25519 logiciel.
