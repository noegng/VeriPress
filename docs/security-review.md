# Revue de sécurité — phase 2 (Dev A, ven. 20/11 ~19 h)

Périmètre : verdict final, signature nominative / anonyme (ZK) / passkey (WebAuthn), chaîne de versions et `develop`, métadonnées prouvées, T0, C2PA, store. La partie XRPL (`XrplLedger`, script) est revue par Dev B.

## Modèle de menace retenu

- L'attaquant contrôle les fichiers qu'il fait vérifier, le **store** hors chaîne et ses propres transactions XRPL : n'importe qui peut envoyer un Memo au compte registre.
- Il **ne** contrôle **ni** la clé d'un appareil accrédité, **ni** la passkey attestée, **ni** le compte registre.
- Il peut aussi être **un appareil accrédité malveillant** qui contourne notre client.

## Ce qui tient (vérifié par des tests)

| Propriété | Mécanisme | Tests |
|---|---|---|
| Un ancrage forgé ne vaut rien | Chaque mode exige sa preuve liée au digest ancré : Ed25519, Groth16 (digest en entrée publique), assertion WebAuthn (challenge = digest) | `test_pipeline`, `test_zk_anonymous`, `test_passkey` |
| Le store n'est pas digne de confiance | Manifeste == digest ancré ; divulgation == racines de Merkle ; preuves == hash ancré | `test_*tampered*`, `test_manifest_swapped…` |
| Pas de rejeu de preuve | Preuve ZK et assertion liées au digest ; paquet de preuve haché dans l'ancrage | `test_valid_proof_reanchored…`, `test_tampered_assertion_bundle…` |
| Révocation non rétroactive | Date du Credential (nominatif) ou racine en vigueur à l'ancrage (anonyme) | `test_device_revoked_*`, `test_revocation_after_anchoring…` |
| Masquage honnête | Une tuile « masquée » doit vraiment être noire ; au-delà de 50 % masqué -> ⚪ | `test_fully_redacted_record…` |
| Passkey | Clé = celle du manifeste et attestée par le registre ; challenge, type, origine, rpIdHash, UP + UV, credential_id | `test_invalid_assertions_are_refused` (5 cas) |
| Métadonnées | Preuve liée à l'engagement du manifeste signé ; libellé recalculé depuis les entrées publiques ; masquée si ⚪ | `test_zk_metadata` |

## Constats de cette revue (corrigés dans la PR « Revue de sécurité »)

1. **`_history` ne savait vérifier que les signatures Ed25519** (bug, gravité moyenne). Un parent signé anonymement ou par passkey était toujours « non vérifié » : un RAW signé par Touch ID puis développé en JPEG tombait à tort en 🟠. → Une seule fonction `_authenticate`, propre à chaque mode, sert au verdict **et** à chaque étape de la chaîne.
2. **`develop` anonyme** (gravité moyenne, révélée par le correctif 1). En anonyme, les deux signataires valent `""`, donc « même appareil » était vrai par construction. Un appareil accrédité qui contourne notre client aurait pu présenter le RAW anonyme d'un autre comme son négatif. → `develop` exige un signataire nominatif des deux côtés, à la vérification comme à la signature, avec un motif explicite.
3. **Identifiants d'entrée non validés dans le store** (faible). Le `parent` d'un manifeste signé pouvait viser un chemin hors du store (`../`), en lecture seule. → `store.valid_id` : uniquement `hash` ou `hash-rN`.

## Points connus, non corrigés (assumés et dits au jury)

- **C2PA** : un manifeste C2PA peut être fabriqué par n'importe qui pour pointer vers n'importe quel ancrage (certificat non reconnu). → Dans la page : à présenter comme une **information**, jamais comme une preuve (le verdict vient de VeriPress).
- **Circuit `device`** : pas de séparation de domaine entre le hash d'une feuille (`Poseidon(Ax, Ay)`) et celui d'un nœud de l'arbre. Non exploitable : profondeur fixe à 10, et la clé doit être un point de la courbe. Durcissement prévu : `Poseidon(3)` avec une étiquette de domaine.
- **Cérémonie de confiance** : phase 1 publique (PSE, 80 contributions) ; phase 2 = une seule contribution locale. En production : cérémonie multi-parties, ou PLONK / Halo2.
- **WebAuthn** : compteur de signature non suivi (détection de clonage). Les passkeys Apple synchronisées renvoient de toute façon 0. Côté vérificateur, `VERIPRESS_WEBAUTHN_HOSTS` doit lister les origines de signature.
- **Attestation de la passkey** relue dans l'état *actuel* du Credential : réattester une autre passkey invalide les anciennes photos signées par passkey (`tasks-dev-b.md`).
- **Origine physique** : la signature se fait encore côté serveur (clé logicielle) ou par passkey sur le portable ; un capteur qui signe le RAW, comme chez Apple, reste du travail futur. Le trou analogique (photographier un écran) est inhérent à toute approche par signature.
- **Post-quantique (mis à jour 20/11 ~18 h 45)** : la signature du manifeste est désormais **hybride Ed25519 + ML-DSA-87** (FIPS 204), clé attestée par le registre et signature obligatoire dès qu'elle est déclarée (`test_post_quantum.py` : suppression, falsification, substitution de clé, attestation retirée). Restent non post-quantiques : les preuves Groth16 sur BN254 (leur **validité** ; l'anonymat, en zero-knowledge parfait, tient), la passkey P-256 (les navigateurs n'ont pas encore de passkeys post-quantiques), la signature C2PA (ES256) et les signatures de comptes XRPL. Une fois le « Q-day » arrivé, la chronologie XRPL empêche toujours d'antidater une fausse signature.

## Partie XRPL (Dev B, ven. 20/11 ~21 h)

Périmètre : `XrplLedger` (ancrages, lecture des Memos, Credentials, registre anonyme, T0, lots, attestations dans l'URI), `scripts/setup_testnet.py`, et les routes de l'API : enregistrement de la passkey, `/v/<id>`, `/api/anchor`, `/api/sign/batch`, `c2pa` dans `/api/verify`. Même modèle de menace que ci-dessus : n'importe qui peut envoyer des transactions et des Memos au compte registre. **Aucune vulnérabilité exploitable trouvée.**

| Propriété | Mécanisme | Tests |
|---|---|---|
| Racine du registre non falsifiable | Seuls les `AccountSet` **envoyés par le compte registre** (`Account == registry`) comptent. Un Memo `registry-root` envoyé par un tiers est ignoré | `test_ledger_registry` |
| Credentials non falsifiables | `CredentialCreate` doit venir du registre, `CredentialAccept` du sujet (après un Create) ; un Create d'un autre compte est ignoré ; seules les transactions validées et `tesSUCCESS` comptent | `test_ledger_revocation` |
| Clés attestées (passkey, ML-DSA-87) | Lues dans le `CredentialCreate` **du registre** en vigueur (historique) ; un Create d'un autre compte est ignoré ; une révocation n'efface pas l'attestation (c'est `credential_type(pk, t)` qui juge la validité) | `test_ledger_pq` |
| T0 non falsifiable | `ledger_close_time` redemande le ledger validé à cet index et compare son hash. Faux hash, ledger futur ou non validé : `None`. Seuls les ledgers validés sont mis en cache | `test_ledger_time_window`, Testnet |
| Racine de lot sans valeur seule | `n` non entier ou ≤ 0 : ignoré. Une racine ancrée par un tiers n'atteste rien : chaque reçu doit contenir une signature, une preuve ZK ou une passkey valides (`batching.py`) | `test_ledger_batch`, `test_batch` |
| Ancrage non validé | Horodaté à la soumission ou au présent, jamais à une date fournie par l'attaquant : la révocation est donc évaluée au présent ; verdict « pending » | `test_fast_anchoring_flag_and_anchor_status` |
| Soumissions sûres | Aucune nouvelle tentative de soumission (risque de double ancrage) ; numéro de séquence sous verrou | Testnet (deux ancrages à la suite) |
| Page publique | Rapport JSON dans `<script>` avec `<` échappé ; balises OG passées par `html.escape` ; `innerHTML` seulement via `esc()` / `Number()` ; `entry_id` validé par regex ; C2PA affiché comme information, sans effet sur le verdict | `test_public_page_escapes_a_hostile_report`, `test_forged_c2pa_manifest_does_not_change_the_verdict` |
| Enregistrement de la passkey | Réservé à localhost (pair TCP ; uvicorn n'accepte `X-Forwarded-For` que d'un pair 127.0.0.1). La route n'écrit qu'une **candidate** : seul l'opérateur l'atteste (`--passkey`) | `test_passkey_registration_is_localhost_only` |

### Points connus, non corrigés (assumés et dits au jury)

- **L'« appareil » de la démo, c'est le serveur.** `/api/sign` et `/api/sign/batch` signent avec la clé logicielle de l'appareil pour quiconque joint le serveur (lancé sur `0.0.0.0` pour le téléphone). Sur le Wi-Fi de la salle, n'importe qui pourrait donc produire une photo 🟢 « appareil accrédité ». En production, la clé vit dans le capteur, ou c'est la passkey de l'appareil. Pendant la démo, ne pas afficher l'adresse IP du serveur, ou le lancer sur `127.0.0.1` si le téléphone n'est pas nécessaire.
- **Tunnel public** (par exemple pour les aperçus sociaux) : les requêtes arriveraient alors de 127.0.0.1, et l'enregistrement de la passkey ne serait plus réservé à la machine. Ne pas ouvrir de tunnel pendant l'enregistrement ou l'attestation d'une passkey.
- **Lecture par un nœud public Testnet de confiance**, sans preuve d'état : un nœud malveillant pourrait mentir. En production : son propre nœud, ou plusieurs nœuds recoupés.
- **Attestation lue dans le dernier `CredentialCreate`** quand `at_time` n'est pas fourni : réattester une autre passkey ou une autre clé ML-DSA invalide les anciennes photos. Le pipeline peut passer `at_time=anchor.timestamp` pour lever cette limite (proposé à Dev A, #41). Ce point remplace « relue dans l'état *actuel* » ci-dessus : depuis #41, une révocation ne l'efface plus.
- **Clés de démo en clair dans `keys/`** (`chmod 600`, jamais commitées). En production : HSM ou enclave sécurisée.
