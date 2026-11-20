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
- **Post-quantique** : Ed25519, ECDSA P-256 et BN254 ne résistent pas à un ordinateur quantique. Apple utilise ML-DSA-87 + RSA-3072 en hybride : c'est la piste pour le manifeste.
