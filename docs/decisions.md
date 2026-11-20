# Décisions d'équipe (récapitulatif des séances de grilling)

Pour chaque question : la décision retenue et, si utile, pourquoi. Les détails techniques et les formats sont dans [`interfaces.md`](interfaces.md), la répartition dans [`team-rules.md`](team-rules.md) et les fiches de tâches.

---

## Séance 1 — périmètre de la démo (ven. 20/11, début de journée)

| # | Question | Décision |
|---|---|---|
| 1 | Étapes de démo à garder | 1 photo 🟢, 2 retouche 🟠 + carte, 3 WhatsApp, 6 image IA 🔵 ; 4 masquage si le temps le permet ; 5 (copie du filigrane) dépend du filigrane. **Résultat : les 6 étapes sont faites.** |
| 2 | Filigrane TrustMark | À faire si possible (« la solution la plus pro possible »), avec repli sur un hachage perceptuel. **Fait.** |
| 3 | Signature à la capture | Ed25519 logiciel d'abord, vraie passkey plus tard si le temps le permet. |
| 4 | Réseau XRPL | **Testnet** (plus stable que Devnet, Credentials actifs). |
| 5 | Format de l'ancrage | Payment de 1 drop + Memo (`veripress/v1`). |
| 6 | Frontend | Une page servie par FastAPI d'abord ; visualisations (arbre de Merkle ↔ image) en option. **Faites.** |
| 7 | WhatsApp pendant la démo | Image préparée à l'avance, et vidéo de secours. Le réseau de la salle n'est pas fiable. |
| 8 | Où faire du TDD | Seulement : arbres de Merkle / preuves de masquage et règles du verdict final. |
| 9 | Répartition | Dev A (Noé) : confiance et vérification (signature, pipeline, verdict, store, filigrane). Dev B : registre et interface (XRPL, API, page, visualisations). |
| 10 | Contrats avant de coder | `ledger.py` (avec un `FakeLedger`) + `docs/interfaces.md`, écrits avant de se séparer. |
| 11 | Git | Branches `dev-a/*` / `dev-b/*`, chacun n'écrit que dans ses fichiers, points de synchro. Les règles sont écrites pour les agents dans `team-rules.md`. |
| 12 | Où vit la divulgation | `store/` local indexé par tx hash (en production : IPFS ou hébergée par le propriétaire). |
| 13 | Retrouver une image sans filigrane | Hachage perceptuel 64 bits, recherche du plus proche voisin. |
| 14 | Ordre des options | Filigrane → masquage dans la page → visualisation arbre ↔ image → passkey → chaîne de versions. |
| 15 | Image IA | Image générée à l'avance, signée par une clé qui porte le Credential `AI_GENERATOR`. |
| 16 | Chaîne de versions (`parent`) | En option, en dernier. **Faite.** |

### Décisions prises ensuite, au fil du travail

| Sujet | Décision |
|---|---|
| Commits | Pas de mention « Claude » en co-auteur. |
| Passkey | Confiée à Dev B (phase 1), reprise dans la phase 2 (Q21–Q23). |
| Calibrage | Sur de vraies photos iPhone passées par WhatsApp : taille de tuile adaptative (~1/40 du grand côté), conversion ICC → sRGB, rééchantillonnage sans troncature, poids 0,5 sur le coefficient DC. |
| Formats pros | 16 bits ramené sur 8 bits, RAW via LibRaw (`rawpy`), `load_upload` comme point d'entrée de l'API. JPEG XL laissé de côté. |
| Original non tatoué | **Engagement double** : chaque feuille robuste engage la version tatouée **et** l'original, et une tuile est conforme si elle est proche de l'une ou de l'autre. Préféré au re-tatouage à la vérification, qui aurait introduit un réseau de neurones dans le verdict (risque d'attaque adversariale, dépendance à une version). |
| Fusion dans `main` | **Par PR GitHub**, à partir du 20/11 après-midi. |
| Revue d'architecture | `/improve-codebase-architecture` non utilisé (coûteux, et déconseillé en hackathon) ; à la place, une revue de code sur deux axes (standards et spec). |

---

## Séance 2 — phase 2 (ven. 20/11, après-midi)

### Tour 1 — périmètre et ordre

| # | Question | Décision |
|---|---|---|
| Q1 | Ordre (ce qui n'est pas fini à 10:00 passe en « travail futur ») | 1 ZK A (attestation anonyme) · 2 révocation non rétroactive · 3 lien public `/v/<tx>` · 4 ZK B (métadonnées) · 5 ancrage rapide · 6 C2PA · 7 passkey · 8 stockage par adresse de contenu · 9 ancrage groupé. |
| Q2 | Clés pour le ZK | Chaque appareil a en plus une **clé Baby Jubjub** (EdDSA-Poseidon, compatible circuits). Le registre publie sur XRPL la racine d'un arbre de Merkle Poseidon des clés accréditées. La clé Ed25519 garde le mode nominatif. |
| Q3 | Mode anonyme | L'ancrage ne contient ni la clé ni la signature de l'appareil, mais le digest, la racine du registre et la preuve (son hash, voir Q13 et interfaces.md). Verdict 🟢 « appareil accrédité (anonyme) ». Choix au moment de signer (case « Signer anonymement »). |
| Q4 | Racine valide | Une preuve est acceptée si sa racine **était en vigueur au moment de l'ancrage**. Révoquer = publier une nouvelle racine, ce qui rend la révocation non rétroactive en mode anonyme. |
| Q5 | Révocation non rétroactive (nominatif) | Date de révocation lue dans le `CredentialDelete` de l'historique du registre. Photo ancrée avant : 🟢 + « appareil révoqué depuis le … » ; après : ⚪. Dev B, dans `XrplLedger` (`at_time`). |
| Q6 | Où générer les preuves | Côté serveur (Node + snarkjs appelés depuis Python) ; dans le navigateur en option. |
| Q7 | Chaîne d'outils ZK | `circom` compilé avec `cargo` ; `snarkjs` + `circomlib` dans `zk/` ; circuit compilé et clé de vérification commités ; cérémonie avec le fichier « powers of tau » de Hermez (dans le pitch : en production, phase 2 multi-parties). |
| Q8 | Ancrage groupé | Sans l'amendement Batch (absent de Testnet) : arbre de Merkle de N manifestes, on ancre la racine, chaque photo garde sa preuve d'inclusion. En dernier. |
| Q9 | Stockage décentralisé | Les divulgations sont déjà auto-authentifiées. On calcule un CID IPFS mis dans le Memo et on sert le fichier par notre API, sans épinglage réel. |
| Q10 | C2PA | Manifeste C2PA (`c2pa-python`) avec un certificat de test, en le disant honnêtement. |
| Q11 | Ancrage rapide | `/api/sign` répond dès la soumission ; la page affiche « en attente » ; le verdict porte un drapeau `pending`. |
| Q12 | Répartition | **Dev A** : ZK A, ZK B, engagement des métadonnées, C2PA, statut « en attente » dans le pipeline (+ vérification WebAuthn côté serveur, voir Q21). **Dev B** : révocation non rétroactive, lien public, ancrage rapide, publication des racines du registre, passkey (page et routes), interface. CID et ancrage groupé : le premier libre. |

### Tour 2 — détails ZK, métadonnées, contrat, démo

| # | Question | Décision |
|---|---|---|
| Q13 | Nullifier | **Pas de nullifier** : le digest du manifeste est une entrée publique, et la signature vérifiée dans le circuit porte dessus, donc pas de rejeu. Le digest SHA-256 est découpé en deux moitiés de 128 bits. |
| Q14 | Taille du registre | Profondeur 10 (1 024 appareils) ; registre de démo rempli avec ~20 appareils fictifs. À dire : l'anonymat croît avec le nombre d'appareils. |
| Q15 | Outil `zk/` | Dev A livre `keygen`, `root`, `prove`, `verify` (+ métadonnées). Dev B s'en sert dans le script de mise en place et publie la racine (Memo `veripress/registry-root/v1`). `XrplLedger.registry_root_at(time)`. |
| Q16 | Engagement des métadonnées | À la signature : EXIF `DateTimeOriginal` + GPS → `meta_commitment = Poseidon(heure unix, lat×10⁶, lon×10⁶, sel)` dans le manifeste signé. Sel secret. Pas d'EXIF = pas d'engagement. |
| Q17 | Affirmations prouvées | Générées à la signature : « prise le jour J » (24 h) et « dans une zone de ~10 km autour de *ville* ». Jamais l'heure ni le GPS exacts. Preuves à la demande = travail futur (il faudrait authentifier le propriétaire). |
| Q18 | Contrat JSON | `/api/verify` : `anonymous`, `zk`, `meta_claims`, `pending` (+ `credential_revoked_at`). `/api/sign` : champ `anonymous`. Première PR de la phase 2, avant le code. |
| Q19 | Démo | Nouvelles étapes 7 (signature anonyme) et 8 (affirmations jour et zone), entre l'IA et la révocation. |
| Q20 | C2PA et format | Manifeste C2PA dans les métadonnées du PNG publié, hors pixels, donc les arbres ne changent pas. Moment du pitch : « C2PA disparaît après WhatsApp, VeriPress retrouve la provenance ». |

### Tour 3 — passkey et organisation

| # | Question | Décision |
|---|---|---|
| Q21 | Relier la passkey au compte XRPL | Le registre **atteste la passkey** : hash de la clé publique P-256 dans le champ `URI` du Credential `CAPTURE_DEVICE`. Le serveur vérifie l'assertion WebAuthn (ECDSA P-256, `cryptography`). |
| Q22 | HTTPS pour la démo | Passkey démontrée **sur le portable** (localhost + Touch ID). Tunnel HTTPS pour le téléphone seulement s'il reste du temps. |
| Q23 | Passkey + anonyme | Incompatibles (la passkey ne peut pas produire de clé Baby Jubjub) : passkey = mode nominatif uniquement. Circuits P-256 = travail futur. |
| Q24 | Lien public `/v/<tx>` | Page en lecture seule : image publiée, verdict, affirmations prouvées, lien vers l'explorateur, balises d'aperçu pour les réseaux sociaux. |
| Q25 | Organisation | PR 1 (Dev A) = contrat de la phase 2 + plan et fiches. Puis une PR par fonctionnalité, fusionnée par son auteur une fois au vert, et annoncée. Synchro ~19:00, ~23:00, ~03:00, 08:00 ; gel à 10:00. |
