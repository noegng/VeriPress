# VeriPress expliqué simplement

Guide interne, pour comprendre tout le processus de bout en bout sans lire le code. Les docs détaillées pour le jury sont en anglais : [`architecture.md`](../architecture.md) (comment ça marche), [`interfaces.md`](../interfaces.md) (formats et API), [`security-review.md`](../security-review.md) (sécurité).

---

## 1. L'idée en 30 secondes

On veut pouvoir dire, devant n'importe quelle copie d'une image :

- **d'où elle vient** (tel appareil accrédité, ou tel générateur d'IA déclaré) ;
- **si elle a été modifiée, et où** (une carte des zones changées) ;
- et que ça marche **même après WhatsApp**, qui recompresse l'image et efface toutes ses métadonnées.

Pour ça :

1. au moment de la signature, on découpe l'image en tuiles et on calcule une empreinte de chaque tuile ;
2. on résume toutes ces empreintes en deux petites valeurs (les racines de deux arbres de Merkle), qu'on signe ;
3. on écrit cette signature sur la blockchain XRPL : c'est public, daté, et personne ne peut la modifier après coup ;
4. on cache dans les pixels un filigrane invisible qui sert d'**adresse** pour retrouver la fiche de l'image ;
5. à la vérification, on retrouve la fiche, on vérifie la signature, puis on compare l'image reçue **tuile par tuile**.

---

## 2. Les cinq notions à connaître

| Notion | En une phrase |
|---|---|
| **Hash** (SHA-256) | Une empreinte de 32 octets. Le moindre bit changé dans l'entrée donne une empreinte complètement différente, et on ne peut pas revenir en arrière. |
| **Arbre de Merkle** | On hache chaque tuile (les « feuilles »), puis on hache les paires de hashs, puis les paires de paires… jusqu'à un seul hash, la **racine**. Changer une seule tuile change la racine. Et on peut prouver qu'une tuile fait partie de l'arbre sans montrer les autres. |
| **Signature** | Avec sa clé privée, l'appareil signe un message. Tout le monde peut vérifier avec la clé publique que c'est bien lui, et que le message n'a pas changé. |
| **XRPL** | Une blockchain publique. On y écrit une petite note (un *Memo*) dans une transaction de 1 drop (0,000001 XRP). Elle est datée, publique et ne peut plus être modifiée. |
| **Credential XRPL** | Une attestation inscrite sur XRPL : « le compte du registre certifie que cette clé est un appareil photo de confiance » (`CAPTURE_DEVICE`) ou « un générateur d'IA déclaré » (`AI_GENERATOR`). Elle peut être supprimée (révocation). |

---

## 3. La signature, étape par étape

Ce qui se passe quand on clique sur « Signer » (`pipeline.sign_image`).

### 3.1 Lire l'image proprement

Avant tout, on transforme le fichier en un simple tableau de pixels RGB 8 bits, toujours de la même façon (`tiling.load_upload`) :

- on applique la rotation EXIF (photo prise en portrait) ;
- on convertit les couleurs en sRGB. **Pourquoi :** l'iPhone enregistre en Display P3, alors que WhatsApp renvoie du sRGB. Sans conversion, toutes les tuiles semblaient modifiées ;
- on accepte JPEG, PNG, HEIC, TIFF 16 bits et les RAW d'appareils photo (développés avec LibRaw).

À partir d'ici, on ne travaille **que sur les pixels**, jamais sur les octets du fichier.

### 3.2 Poser le filigrane

On tire au hasard un **identifiant de 64 bits** (`wm_id`) et on le cache dans les pixels avec TrustMark (le filigrane invisible d'Adobe, un réseau de neurones). Ce filigrane est conçu pour résister à la recompression.

On le pose **avant** de calculer les empreintes, donc les empreintes portent sur l'image tatouée : c'est elle qu'on publie.

### 3.3 Découper en tuiles

Taille d'une tuile ≈ grand côté / 40, au moins 32 px. Exemple : une photo iPhone de 4032×3024 donne des tuiles de 104 px, soit 39 colonnes × 29 lignes = **1 131 tuiles**.

**Pourquoi 1/40 :** après WhatsApp, la photo fait ~1 600 px de large. Chaque tuile garde alors ~40 px, assez pour rester reconnaissable. Avec des tuiles fixes de 32 px, on avait des faux « modifié ».

### 3.4 Deux empreintes par tuile, donc deux arbres

Pour chaque tuile, on calcule deux empreintes, avec un **sel** (16 octets aléatoires propres à la tuile) :

| Arbre | Ce qu'on hache | Ce qu'il prouve |
|---|---|---|
| **Exact** | Les octets bruts des pixels de la tuile | Que les pixels sont **identiques au bit près** |
| **Robuste** | Un **résumé** de la tuile, réduite à 8×8 puis transformée DCT (comme JPEG) : 15 coefficients de luminosité (formes, puis détails fins) et 3 par canal de couleur (Cb, Cr), arrondis | Que le **contenu** est le même (formes, couleurs, texture grossière), même après recompression ou redimensionnement |

Les deux arbres donnent deux racines : `exact_root` et `robust_root`.

**Pourquoi un sel :** quand on masque une tuile (un visage, par exemple), on ne publie que son hash. Sans sel, quelqu'un pourrait essayer toutes les tuiles possibles d'une zone unie (un mur blanc, par exemple) et retrouver le contenu caché.

**L'original non tatoué :** le résumé robuste de chaque tuile contient aussi celui de la version **sans filigrane** (champ `g`). Comme ça, la photo restée dans la galerie du téléphone se vérifie aussi. Le filigrane décale certains coefficients de ~20 pas, assez pour qu'elle ressorte 🟠 sinon. On ne garde **pas** les pixels de l'original, seulement ce résumé.

### 3.5 Le manifeste

Le **manifeste** est une petite fiche JSON qui résume tout :

- dimensions et taille de tuile ;
- les deux racines ;
- la clé publique du signataire ;
- `op` : `capture`, `ai_generate`, `edit` ou `develop` ;
- `parent` : la version d'origine, pour une retouche ;
- l'identifiant du filigrane ;
- l'engagement sur la date et le GPS (voir § 6.4) ;
- T0, le dernier ledger XRPL au moment de signer (voir § 6.7) ;
- le CID de la divulgation, etc.

On en calcule le hash, le **digest**. C'est **ce digest qu'on signe**, et lui seul.

À côté, la **divulgation** (*disclosure*) contient pour chaque tuile son sel, son hash exact et son résumé robuste. Elle est trop grosse pour la blockchain, donc elle va dans le store.

### 3.6 Signer le digest (3 modes)

| Mode | Comment | Ce qu'on voit sur XRPL |
|---|---|---|
| **Nominatif** (par défaut) | Clé Ed25519 de l'appareil | digest + signature + clé publique de l'appareil |
| **Anonyme** | Preuve à divulgation nulle de connaissance (ZK) : « un des appareils du registre a signé ce digest » | digest + racine du registre + hash de la preuve. **Pas** la clé de l'appareil |
| **Passkey** | Touch ID du portable (WebAuthn) : le digest sert de « challenge » | digest + clé de l'appareil + hash de l'assertion |

En plus, si le registre a attesté une clé post-quantique ML-DSA-87 pour cet appareil, on ajoute une **deuxième signature** avec elle (voir § 6.6).

### 3.7 Ancrer sur XRPL

Une transaction **Payment de 1 drop** du compte d'ancrage vers le compte registre, avec un Memo `veripress/v1` qui contient par exemple `{"d": digest, "s": signature, "k": clé}`. Le hash de cette transaction devient l'**identifiant de l'image** (`entry_id`).

C'est ça qui rend tout infalsifiable : une fois le digest sur XRPL, on ne peut plus changer ni le manifeste, ni les racines, ni la date.

### 3.8 Ranger dans le store

Le dossier `backend/store/<tx_hash>/` contient :

| Fichier | Contenu |
|---|---|
| `entry.json` | manifeste + divulgation + pHash de l'image |
| `image.png` | l'image **publiée** (tatouée), avec un manifeste C2PA dans ses métadonnées |
| `bundle.json` | preuve ZK ou assertion passkey, selon le mode |
| `meta.json` | preuves ZK de la date et de la zone |
| `pq.json` | signature ML-DSA-87 (4,6 Ko, trop grosse pour un Memo) |
| `receipt.json` | reçu, si l'image fait partie d'un ancrage groupé |

**Point clé : on ne fait pas confiance au store.** Tout ce qu'il contient est revérifié contre XRPL à chaque vérification (voir § 4.3). En production, il pourrait être sur IPFS ou chez n'importe qui.

---

## 4. La vérification, étape par étape

Ce qui se passe quand on dépose une image dans « Vérifier » (`pipeline.verify_image`).

### 4.1 Retrouver la fiche

1. si on donne l'identifiant (`entry_id`), on n'utilise que celle-là ;
2. sinon on prend comme **candidates** toutes les fiches qui ont l'identifiant du **filigrane** (`wm_id`), puis toutes celles dont le **pHash** est proche. Le pHash est une empreinte « perceptuelle » de 64 bits, qui change peu quand l'image est recompressée.

On vérifie **chaque** candidate jusqu'au bout (étapes suivantes), et on garde le meilleur verdict. **Pourquoi :** n'importe qui peut ajouter une fiche dans le store. Avant, une fausse « variante masquée » d'une vraie photo, fabriquée avec des données publiques, passait en premier et faisait sortir la vraie photo en ⚪.

Le filigrane et le pHash ne servent **qu'à retrouver** les fiches. Ils ne prouvent rien. La preuve vient des étapes suivantes.

### 4.2 Vérifier l'ancrage et la signature

- On lit la transaction sur XRPL.
- Selon le mode, on vérifie la signature Ed25519, la preuve ZK ou l'assertion passkey. La signature ML-DSA est exigée si le manifeste en annonce une, **ou** si le registre avait attesté une clé ML-DSA pour cet appareil au moment de l'ancrage.
- On vérifie que l'appareil avait un **Credential valide au moment de l'ancrage**. S'il a été révoqué *après*, la photo reste 🟢, avec la mention « révoqué depuis le … ».

### 4.3 Vérifier que le store n'a pas menti

- Le hash du manifeste stocké doit être égal au digest écrit sur XRPL.
- Avec la divulgation, on reconstruit les deux arbres. Leurs racines doivent être égales à celles du manifeste.

Si quelqu'un a modifié le store, ça ne passe pas : ⚪.

### 4.4 Comparer tuile par tuile

On remet l'image reçue à la taille d'origine (WhatsApp l'a réduite), puis pour chaque tuile :

| Statut | Test | Couleur sur la carte |
|---|---|---|
| **exact** | le hash des pixels est identique à celui signé | vert |
| **robust** | le résumé est proche : écart pondéré ≤ 4,5 pas (de la version tatouée **ou** de l'original). Poids : 0,5 sur la luminosité moyenne, 0,75 sur les détails, 0,25 sur la couleur | vert |
| **changed** | écart > 4,5 pas : le contenu a changé | rouge |
| **redacted** | tuile masquée par le propriétaire : vérifiée par son hash, et elle doit vraiment être noire | noir |

**Exemple concret :** la photo signée, envoyée par WhatsApp, arrive en 1600×1200 JPEG. On la remet en 4032×3024. Aucune tuile n'est « exact » (les pixels ont bougé), mais les 1 131 sont « robust » (écart max mesuré : ~2). Résultat : 🟢 « 1131/1131 tiles match after recompression ».

**Pourquoi 4,5 :** calibré sur de vraies photos passées par WhatsApp. La pire tuile non retouchée est à ~4, et une retouche de 2 tuiles est détectée à 100 %.

**Pourquoi la couleur et les détails :** avant la revue adversariale, le résumé ne regardait que la luminosité grossière. Inverser les couleurs d'une zone (rouge → cyan) ou la flouter donnait 🟢. Maintenant c'est 🟠, même après JPEG (pour un flou de rayon ≥ 5 px).

**Copie sans perte (PNG) :** si au moins la moitié des tuiles texturées sont encore « exact », la copie n'a pas été recompressée. Il n'y a donc aucun bruit à pardonner : une tuile seulement « robust » a été retouchée, elle passe en **changed**. Une tuile masquée doit alors être vraiment noire. Les tuiles unies (ciel blanc) ne comptent pas, car elles peuvent sortir d'un JPEG intactes.

**« Exact » veut dire pixels identiques, pas fichier identique :** une image dont on a juste retiré les métadonnées reste « exact ». En revanche, l'original non tatoué ne peut jamais être « exact » (ses pixels ne sont pas ceux qui ont été signés) : il ressort « robust », avec la mention « match the original capture (unwatermarked) ».

### 4.5 Le verdict

On applique les règles dans l'ordre, et la première qui s'applique gagne :

1. rien trouvé, ancrage absent, signature ou preuve invalide, store incohérent → ⚪ **Unknown** ;
2. plus de la moitié des tuiles ont changé → ⚪ : ce n'est pas la photo de cette fiche (« filigrane copié ? » si on l'a trouvée par le filigrane). Ce n'est pas 🟠, sinon un lien piégé ferait passer n'importe quelle image pour « une retouche d'une vraie photo » ;
3. des tuiles ont changé → 🟠 **Edited**, avec la carte ;
4. plus de 50 % de l'image masquée → ⚪ (ça ne prouve plus grand-chose) ;
5. retouche signée (`op = edit`) → 🟠, avec l'historique des versions ;
6. signée par un `AI_GENERATOR` → 🔵 **AI** ;
7. signée par un `CAPTURE_DEVICE` → 🟢 **Real** ;
8. pas de Credential valide au moment de l'ancrage → ⚪.

⚪ veut dire « on ne peut rien prouver », **pas** « c'est un faux ».

---

## 5. Ce qui est prouvé, et ce qui n'est qu'un indice

| Élément | Rôle | Peut décider du verdict ? |
|---|---|---|
| Signature / preuve ZK / passkey + Credential sur XRPL | Qui a signé, et s'il était accrédité | **Oui** |
| Racines de Merkle signées | Quelles tuiles sont intactes | **Oui** |
| Filigrane | Adresse pour retrouver la fiche | Non (sauf pour détecter un filigrane copié) |
| pHash | Adresse de secours | Non |
| Manifeste C2PA | Information affichée avec ℹ️ | **Non** : n'importe qui peut en fabriquer un |
| Store | Stockage | Non : tout est revérifié contre XRPL |

---

## 6. Les briques en plus

### 6.1 Masquage vérifiable

On noircit une zone (un visage, par exemple). Les tuiles touchées ne gardent que leurs hashs, sans le sel ni le résumé. Ça crée une variante `<tx>-r1` qui garde **le même manifeste et le même ancrage**. Le reste de l'image se vérifie toujours, et les tuiles cachées sont prouvées par leur hash, sans être révélées.

### 6.2 Chaîne de versions

On signe une retouche en donnant `parent` = la transaction de l'original. Le vérificateur remonte la chaîne et affiche l'historique (retouche → capture). Chaque étape est vérifiée comme la photo elle-même.

### 6.3 RAW → JPEG (`develop`)

L'appareil signe son RAW (le « négatif »), puis le JPEG qu'il en tire, avec le RAW comme parent. C'est 🟢 seulement si les deux sont signés par **le même appareil nommé**. Inspiré d'Apple Reference Image.

### 6.4 Date et lieu prouvés sans les révéler (ZK)

À la signature, on lit l'heure et le GPS dans l'EXIF, et on n'écrit dans le manifeste qu'un **engagement** : `Poseidon(heure, lat, lon, sel secret)`, qui ne révèle rien. Puis on génère deux preuves ZK :

- « prise le 20 nov. 2026 » ;
- « dans une zone de ~10 km autour de … ».

Le vérificateur voit ces deux affirmations, prouvées, mais jamais l'heure exacte ni la position exacte.

### 6.5 Signature anonyme (ZK)

Chaque appareil a aussi une clé « Baby Jubjub » (adaptée aux circuits ZK). Le registre publie sur XRPL la **racine d'un arbre de Merkle** de toutes les clés accréditées (le vrai appareil + ~20 fictifs pour la démo). L'appareil prouve « ma clé est dans cet arbre et j'ai signé ce digest », sans dire laquelle.

- Révoquer = publier une nouvelle racine sans l'appareil.
- Une preuve n'est acceptée que si sa racine **était en vigueur au moment de l'ancrage** : la révocation n'est pas rétroactive.
- Preuve en ~2 s, vérification en ~0,6 s.

### 6.6 Passkey et post-quantique

- **Passkey** : la signature vient de Touch ID (puce sécurisée du Mac). Le registre a écrit le hash de cette passkey dans le Credential de l'appareil, donc on sait que c'est la bonne. Pas compatible avec le mode anonyme.
- **Post-quantique** : en plus d'Ed25519, on signe avec **ML-DSA-87** (norme FIPS 204, résistante aux ordinateurs quantiques). Le registre atteste aussi cette clé. Si le manifeste annonce une signature ML-DSA, elle devient **obligatoire** : supprimer `pq.json` donne ⚪, pas un 🟢 dégradé. Et si le registre avait attesté une clé ML-DSA pour l'appareil au moment de l'ancrage, un manifeste signé en Ed25519 seul donne ⚪ : sinon, après l'arrivée des ordinateurs quantiques, un faussaire n'aurait qu'à ne pas annoncer la clé.

### 6.7 Fenêtre de temps [T0, T1]

- **T0** : au moment de signer, on met dans le manifeste le hash du dernier ledger XRPL. Ce hash était imprévisible avant, donc l'image a forcément été signée **après** T0.
- **T1** : l'heure de la transaction d'ancrage.

La page affiche « signée entre 14:02:31 et 14:02:52 UTC ».

### 6.8 Ancrage rapide et ancrage groupé

- **Rapide** (`wait=0`) : on répond dès l'envoi de la transaction, sans attendre sa validation (quelques secondes). Le verdict est marqué « en attente » jusqu'à la validation.
- **Groupé** : N photos signées, **une seule** transaction, qui contient la racine d'un arbre de Merkle des N ancrages. Chaque photo garde sa preuve d'appartenance (`receipt.json`).

### 6.9 CID et C2PA

- **CID** : l'adresse IPFS de la divulgation est dans le manifeste signé. N'importe quel miroir peut donc servir la divulgation, et on vérifie que c'est la bonne.
- **C2PA** : le PNG publié contient aussi un manifeste C2PA standard (le format d'Adobe, Microsoft, etc.) qui pointe vers l'ancrage XRPL. WhatsApp l'efface : c'est justement le problème que VeriPress résout. On l'affiche pour information, avec un certificat de **test**.

---

## 7. Limites à connaître (et à dire au jury)

- **On prouve l'origine, pas « ce n'est pas de l'IA ».** Pas de preuve = ⚪, pas « faux ».
- **Trou analogique** : photographier un écran avec un appareil accrédité donne une vraie signature.
- **Dans la démo, l'« appareil », c'est le serveur** (clé logicielle) ou la passkey du portable. En production, la clé serait dans le capteur de l'appareil photo.
- **Les résumés robustes sont attaquables** (on peut fabriquer une image différente avec des résumés proches). C'est pour ça qu'ils ne servent qu'à localiser les changements, jamais d'authentification à eux seuls.
- **Après JPEG, 🟢 ne garantit pas les détails fins** : un flou de rayon ≤ 4 px, ou le flou d'un détail de la taille d'une plaque d'immatriculation, passe encore. Une fois la photo réduite à 1 280 px par WhatsApp, ces détails ont aussi disparu des copies authentiques, donc on ne peut pas les distinguer. Sur une copie sans perte (PNG), tout est détecté.
- **L'EXIF est une entrée** : les preuves de date et de lieu prouvent ce que dit l'EXIF signé, pas que c'est vrai. On rejette seulement une date impossible (jour de prise de vue postérieur à l'ancrage).
- **Pas de révocation rétroactive** : si la clé d'un appareil est volée, les photos forgées avant la révocation restent 🟢.
- **Cérémonie ZK** : une seule contribution locale pour la phase 2. Suffisant pour une démo, pas pour la production.
- **Le pHash a besoin d'un index hors chaîne** : XRPL ne sait pas chercher « l'image la plus ressemblante ».
- Le reste est dans [`security-review.md`](../security-review.md).

---

## 8. Où est quoi dans le code

Tout est dans `backend/src/veripress/` :

| Fichier | Ce qu'il fait |
|---|---|
| `tiling.py` | Lecture des fichiers, normalisation, découpe en tuiles |
| `features.py` | Résumé robuste d'une tuile (DCT) et distance entre deux résumés |
| `merkle.py` | Arbres de Merkle et preuves |
| `commitment.py` | Manifeste, divulgation, `commit` / `verify` / `redact` tuile par tuile |
| `watermark.py` | Filigrane TrustMark |
| `perceptual.py` | pHash |
| `signing.py` | Clés Ed25519, vérification passkey, ML-DSA-87 |
| `zk.py` + `zk/` | Preuves ZK (circuits circom, outil Node) |
| `metadata.py` | EXIF → date et GPS → affirmations |
| `ledger.py` | XRPL : ancrages, Credentials, racine du registre, T0 |
| `batching.py` | Ancrage groupé |
| `store.py` | Le store |
| `c2pa_embed.py` | Manifeste C2PA |
| `pipeline.py` | **Le chef d'orchestre** : `sign_image`, `verify_image`, règles du verdict |
| `api.py` | Les routes HTTP |
| `static/` | La page web |
| `cli.py` | Commandes : `demo`, `prepare-demo`, `calibrate`… |

Script XRPL : `backend/scripts/setup_testnet.py` (crée les comptes, les Credentials et le registre anonyme ; `--revoke device` pour la démo de révocation).

---

## 9. Lancer

```bash
cd zk && npm ci                                         # une fois
cd backend
uv run python -m pytest                                 # les tests
uv run python scripts/setup_testnet.py                  # clés + comptes Testnet (relançable)
VERIPRESS_LEDGER=xrpl uv run uvicorn veripress.api:app  # http://localhost:8000
uv run python -m veripress.cli demo photo.jpg -o out/   # démo hors ligne
```

Sans `VERIPRESS_LEDGER=xrpl`, l'API tourne avec un faux ledger en mémoire. Le premier usage du filigrane télécharge les modèles TrustMark (~3 min).

---

## 10. Glossaire

| Terme | Sens |
|---|---|
| **Ancrage** (*anchor*) | La transaction XRPL qui contient le digest |
| **Credential** | Attestation XRPL « cette clé est un appareil de confiance / un générateur d'IA » |
| **DCT** | Transformée en cosinus discrète : décompose une image en fréquences, comme JPEG. Les basses fréquences (formes, luminosité) résistent à la compression |
| **Digest** | Hash du manifeste : ce qu'on signe et qu'on ancre |
| **Divulgation** (*disclosure*) | Pour chaque tuile : sel, hash exact, résumé robuste. Permet de reconstruire les arbres |
| **Groth16** | Le type de preuve ZK qu'on utilise : petite (~1 Ko) et rapide à vérifier |
| **Manifeste** | La fiche signée : dimensions, racines, signataire, filigrane, etc. |
| **pHash** | Empreinte « perceptuelle » de toute l'image : deux images qui se ressemblent ont des pHash proches |
| **Poseidon** | Fonction de hachage adaptée aux circuits ZK (SHA-256 y serait beaucoup trop lent) |
| **Registre** | Le compte XRPL qui émet les Credentials et publie la racine des appareils anonymes |
| **Sel** | Valeur aléatoire ajoutée avant de hacher, pour qu'on ne puisse pas deviner le contenu à partir du hash |
| **Store** | Le stockage hors chaîne (dossier `store/`), non fiable par principe |
| **Tuile** | Un carré de l'image (~1/40 du grand côté) |
| **ZK** (*zero-knowledge*) | Preuve à divulgation nulle de connaissance : prouver qu'une chose est vraie sans révéler le secret qui la rend vraie |
