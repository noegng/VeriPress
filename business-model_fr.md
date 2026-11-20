# VeriPress : business model, avantage XRPL, défense devant le jury

*Document de réflexion, IXH26 Bari, piste 1. Version du 20 nov. 2026, avant le pitch du 21 nov. à 12:30.*

> **Règle de lecture.** Les chiffres suivis de [n] renvoient à la section Sources. Les chiffres marqués **(hyp.)** sont nos hypothèses de travail : rien ne les source, il faudra les valider auprès de vrais clients. Ce qui est **fait** veut dire implémenté, testé et montré en démo sur XRPL Testnet. Ce qui est **futur** n'existe pas encore.

---

## 0. En une phrase

VeriPress prouve **d'où vient une image** et montre **quelles zones ont changé**, même après une recompression WhatsApp. La confiance (appareils accrédités, révocations, horodatage) vit sur un registre public, XRPL, plutôt que chez un seul fournisseur.

---

## 1. Business model

### 1.1 Pourquoi maintenant : la réglementation crée la demande

| Texte | Ce qu'il impose | Date | Effet pour nous |
|---|---|---|---|
| **AI Act UE, art. 50(2)** | Les fournisseurs d'IA générative doivent marquer leurs sorties dans un format **lisible par machine** et détectable | Prévu au 2 août 2026. L'accord en trilogue sur le *Digital Omnibus* (7 mai 2026) le reporte au **2 déc. 2026** pour les systèmes déjà sur le marché. La portée exacte et le statut d'adoption de ce report restent à vérifier dans le JO [5][6][7] | Marché « conformité » pour les générateurs : Credential `AI_GENERATOR`, filigrane et ancrage. Le code de bonnes pratiques de l'AI Office est encore en cours [6] |
| **AI Act, art. 50(4)** | Les déployeurs doivent signaler les deepfakes | Applicable depuis le **2 août 2026** [5][6] | Les plateformes et les médias doivent savoir trier le vrai, le retouché et l'IA |
| **DSA, art. 34-35** (très grandes plateformes) | Atténuation des risques systémiques. Les lignes directrices « élections » de 2024 recommandent d'étiqueter les deepfakes ; une révision qui citerait l'art. 50 est attendue avant les élections de 2027 (c'est une prévision d'un cabinet) [8] | En vigueur | Les plateformes doivent détecter et **préserver** les marques de provenance |
| **Loi italienne 132/2025 sur l'IA** | Nouveau délit, art. **612-quater** du code pénal : diffuser un deepfake trompeur, 1 à 5 ans de prison [9][10] | En vigueur depuis oct. 2025 | En Italie, la justice va avoir besoin de preuves d'authenticité utilisables |
| **Californie SB 942 / AB 853** | Transparence IA en vigueur en août 2026. Au **1er janv. 2028**, les appareils de capture vendus en Californie devront proposer d'intégrer une provenance « authentique » [11][12] | 2026-2028 | Marché des **fabricants** : la signature à la capture devient une obligation produit. Une loi SB 1000 de 2026 pourrait changer ce cadre (non vérifié [12]) |
| **Fraude à l'assurance** | Allianz UK a stoppé 32 400 fraudes en 2025 (≈ 174 M£), dont des dégâts ajoutés par IA sur des photos de voitures [13]. Selon Verisk, 99 % des assureurs ont déjà vu des pièces de sinistre manipulées par IA [14] | Maintenant | C'est le problème le plus chiffrable, et le retour sur investissement y est le plus direct |

### 1.2 Clients cibles : qui a le problème, qui paie

| Segment | Douleur | Ce qu'il achète | Volonté de payer |
|---|---|---|---|
| **Assureurs, experts sinistres** | Photos de sinistre truquées ou réutilisées | SDK ou page de capture signée dans le parcours de déclaration, API de vérification, carte des zones modifiées | **Forte**, le gain se mesure en fraude évitée. Le marché existe déjà : Truepic est branché dans Verisk ClaimSearch [14] |
| **Agences photo, rédactions** | Prouver qu'une photo est authentique après sa diffusion sur les réseaux ; protéger les sources | Signature à la capture pour les photographes, page publique `/v/<tx>`, mode anonyme, masquage vérifiable des visages | Moyenne : budgets serrés, mais l'enjeu de réputation est fort |
| **Générateurs d'IA** | Respecter l'art. 50(2) | Credential `AI_GENERATOR`, filigrane et ancrage groupé (un « tampon IA » vérifiable) | Moyenne à forte, mais ils ont déjà C2PA et SynthID. Nous sommes un complément |
| **Plateformes, réseaux sociaux** | DSA : préserver et afficher la provenance | API de vérification en volume ; lecture du filigrane après suppression des métadonnées | Forte, mais cycle de vente très long |
| **Justice, avocats, huissiers, forces de l'ordre** | Recevabilité et chaîne de conservation des preuves photo | Certificat de vérification horodaté, fenêtre de temps [T0, T1] | Moyenne. Il faudra une reconnaissance juridique (expertise) |
| **Fabricants d'appareils, éditeurs d'apps photo** | Californie 2028, différenciation produit | Licence SDK, émission de Credentials pour leurs appareils | Forte à terme, mais ventes difficiles d'accès pour une jeune équipe |
| **ONG, journalisme d'investigation** | Documenter sans exposer les sources | Mode anonyme (ZK), métadonnées divulguées sélectivement | Faible. Modèle gratuit ou financé par des subventions |

### 1.3 Trois modèles possibles

**A. SaaS et API par vérification ou par signature (B2B vertical).**
Abonnement mensuel plus un prix à l'unité, par exemple ≈ 0,01 à 0,05 € par photo signée et ancrée et une fraction de centime par vérification **(hyp.)**.
- \+ Revenus rapides, on vend un résultat (fraude évitée), le coût on-chain est quasi nul (voir 1.4).
- − On redevient un acteur central si le vérificateur est fermé : c'est précisément ce qu'on reproche à Apple.

**B. Licence SDK pour fabricants et éditeurs d'apps, avec frais d'accréditation.**
Prix par appareil ou par utilisateur actif, plus un forfait annuel par émetteur de Credentials **(hyp.)**.
- \+ Gros volumes, effet réseau, alignement sur l'échéance californienne de 2028.
- − Cycles de vente de 12 à 24 mois, il faut une signature au niveau du capteur (futur), et la concurrence de C2PA, déjà intégré chez Google Pixel 10 [15].

**C. Registre neutre « confiance en service » (modèle fondation ou consortium).**
Le vérificateur est open source et gratuit. Les émetteurs (fabricants, agences, générateurs IA) paient une cotisation pour être reconnus, et l'ancrage groupé est refacturé.
- \+ C'est le plus cohérent avec la promesse « pas de point de défaillance unique », et le plus défendable devant un jury crypto.
- − Il faut une gouvernance et une masse critique d'émetteurs. Peu de revenus au départ.

**Recommandation : un modèle *open-core*, A d'abord, C à terme.**
1. Le **vérificateur et le format de preuve sont ouverts** et gratuits. La vérification doit rester possible sans nous, sinon on reproduit le défaut de « censure rétroactive ».
2. On gagne de l'argent sur la **capture et la signature en service** (SDK web/mobile, API d'ancrage groupé, tableau de bord), en commençant par **un seul secteur, l'assurance sinistres**, où le retour sur investissement se chiffre.
3. Quand plusieurs émetteurs existent (assureurs, agences, un fabricant), on bascule la gouvernance du registre vers un **consortium** (comptes émetteurs multisignature) : c'est le modèle C. La licence SDK pour fabricants (modèle B) devient une option vers 2027-2028.

### 1.4 Coûts d'ancrage sur XRPL (ordres de grandeur)

Paramètres sourcés :
- Frais d'une transaction de référence : **10 drops** = 0,00001 XRP, plus élevés seulement si le réseau est chargé [1].
- Réserve de base d'un compte : **1 XRP**. Réserve par objet possédé, y compris un Credential : **0,2 XRP** depuis décembre 2024. Ces valeurs se votent et se lisent dans `server_info` [2][3].
- Le Credential est d'abord couvert par la réserve de l'émetteur, puis par celle du **sujet** une fois accepté [4].
- Memo : **1 Ko** au maximum [16]. Clôture d'un ledger : **≈ 3 à 5 s** [17].
- Cours du XRP : autour de **1 USD** à la mi-novembre 2026 (plus bas à 0,89 USD le 15 nov.) [18]. On prend 1 XRP ≈ 1 USD pour les ordres de grandeur.

| Scénario | Calcul | Coût |
|---|---|---|
| 1 photo, ancrage individuel (Payment de 1 drop + Memo) | 10 drops de frais + 1 drop transféré | ≈ **0,00001 USD** |
| 1 million de photos en ancrage individuel | 1 M × 11 drops = 11 XRP | ≈ **11 USD**, mais 1 M de transactions qui encombrent le ledger |
| **Ancrage groupé, implémenté** : 1 transaction par ledger, quel que soit N | ≈ 21 600 tx/jour × 10 drops = 0,216 XRP/jour | ≈ **80 USD par an, quel que soit le volume**. Chaque photo garde sa preuve d'inclusion de Merkle (en log₂ N) |
| Compte opérateur ou registre | 1 XRP de réserve | ≈ 1 USD |
| **Appareil en mode nominatif** (un compte par appareil, sujet de son Credential) | 1 + 0,2 XRP bloqués | ≈ **1,2 USD par appareil**. 10 000 photographes : ≈ 12 k USD bloqués (acceptable). 100 M de téléphones : impossible |
| **Appareil en mode anonyme (ZK)** | Une racine de registre Poseidon publiée par Memo à chaque mise à jour | **0 réserve par appareil** |

**Conclusion.** Le coût de la transaction ne pose aucun problème, surtout avec l'ancrage groupé. Le vrai poste qui grossit avec le nombre d'appareils, c'est la **réserve par compte appareil**. À grande échelle, il faut passer au registre de Merkle (ZK), ou à une hiérarchie : un Credential par fabricant ou par modèle, et des certificats d'appareil signés hors chaîne par la clé de ce fabricant. Les vrais coûts d'exploitation sont **hors chaîne** : serveurs, filigrane TrustMark, génération des preuves ZK (temps par preuve **à mesurer**), stockage et épinglage IPFS des divulgations.

> Note : l'ancrage groupé ne dépend pas de l'amendement `Batch` (des transactions `Batch` paieraient encore des frais pour chaque transaction interne). On ancre une seule racine pour N photos.

### 1.5 Mise sur le marché

1. **Pilote (mois 1 à 6)** : un assureur ou un réseau d'experts sinistres italien, idéalement régional et lié à l'écosystème du hackathon. Périmètre : sinistres auto et habitation, photos prises par l'assuré via notre page de capture (passkey), vérification côté gestionnaire avec la carte des zones modifiées. Indicateur : part des dossiers où la carte signale une retouche, et temps gagné par l'expert **(hyp.)**.
2. **Second pilote** : une agence de presse ou une rédaction italienne, avec la page publique `/v/<tx>` et le mode anonyme pour les sources sensibles. C'est notre vitrine pour la crédibilité.
3. **Partenariats** : laboratoires de cryptographie et associations (De Componendis Cifris), écosystème XRPL (subventions, accélérateurs), participation aux groupes de travail C2PA pour faire reconnaître un « ancrage XRPL » comme assertion.
4. **Plus tard** : générateurs d'IA européens soumis à l'art. 50(2), puis fabricants (Californie 2028).

---

## 2. Pourquoi XRPL, et pas « une blockchain » quelconque

### 2.1 Ce que XRPL nous donne nativement

| Besoin du protocole | Fonction XRPL | Ce que ça nous évite |
|---|---|---|
| Accréditer des appareils et des générateurs IA | **Credentials** (`CredentialCreate`/`Accept`/`Delete`, XLS-70) [4] | Écrire, auditer et maintenir un contrat d'identité. Le Credential est un objet du ledger avec un émetteur, un sujet et un type |
| Révocation publique et datée | `CredentialDelete` est inscrit dans l'historique public, avec la date du ledger | Un serveur OCSP ou une liste de révocation centrale. La **non-rétroactivité** se calcule en comparant la date d'ancrage et la date de révocation |
| Horodatage | Clôture en ≈ 3-5 s, **finalité déterministe** (pas de réorganisation) [17] | Attendre des confirmations probabilistes |
| Lier le manifeste à la transaction | **Memos** (1 Ko) [16] | Un contrat de stockage |
| Ancrer pour presque rien | 10 drops par transaction [1] | Des frais de gaz variables |
| Gouvernance de l'émetteur | Multisignature native (`SignerList`), clé de rotation (`RegularKey`). C'est **futur côté configuration**, natif côté protocole | Un contrat multisig à auditer |
| Fenêtre [T0, T1] | Le hash du dernier ledger validé est imprévisible avant sa clôture (T0), la transaction d'ancrage donne T1 | Un serveur d'horodatage de confiance (RFC 3161) |
| Neutralité | Registre public avec des validateurs indépendants | La dépendance à un vendeur (le « cloud privé d'attestation » d'Apple) |

### 2.2 Comparaison honnête

| | **XRPL** | Ethereum L1 | L2 Ethereum (ex. Base) | Solana | **Centralisé (C2PA + trust list)** |
|---|---|---|---|---|---|
| Identité et révocation | **Native** (Credentials) | Par contrat (ex. Ethereum Attestation Service) | Par contrat | Par programme | Autorités de certification + trust list C2PA [15] |
| Coût d'un ancrage | ≈ 0,00001 USD [1] | Élevé et variable | ≈ 0,002 à 0,10 USD selon les sources [19] | Faible : 5 000 lamports par signature (non vérifié pour 2026) | ≈ 0 |
| Finalité | ≈ 3-5 s, déterministe | ≈ 13 min pour la finalité économique (connaissance générale, non sourcé) | Confirmation douce en secondes ; finalité réelle quand le lot est posté et finalisé sur L1 | Rapide | Immédiate, mais c'est la parole du serveur |
| Code à auditer | Aucun contrat | Contrat | Contrat, plus la confiance dans le séquenceur | Programme | Aucun |
| Neutralité, pas de censure rétroactive | Bonne | Très bonne | Séquenceur souvent centralisé | Bonne | **Faible** : si le service ou la CA disparaît, les preuves aussi |
| Écosystème « provenance » | Faible | Fort (ERC-7053 de Numbers Protocol) | Moyen | Moyen | **Très fort** (Adobe, Google, fabricants) |

**Ce qu'on dit au jury.** XRPL n'est pas le seul choix possible. C'est le plus **économe** : identité, révocation et horodatage sont natifs, sans smart contract à auditer, avec une finalité de quelques secondes et des frais négligeables. Ethereum a l'écosystème, C2PA a l'industrie. **On ne remplace pas C2PA** : on lui ajoute une couche de confiance décentralisée et des preuves qui survivent au partage. On écrit déjà un manifeste C2PA (fait).

### 2.3 Ce que XRPL ne fait pas, et comment on le contourne

| Limite | Contournement |
|---|---|
| Pas de recherche par similarité | Le filigrane TrustMark porte un identifiant de 64 bits ; en secours, un hachage perceptuel dans un index hors chaîne (fait). L'index se reconstruit depuis la chaîne |
| Pas de stockage de fichiers (Memo de 1 Ko) | On n'ancre que des hashes et des racines. Les divulgations sont adressées par CID IPFS (fait) et s'auto-vérifient, donc n'importe quel miroir peut les servir |
| Pas de vérificateur ZK sur la chaîne (pas de contrats généraux sur le mainnet) | La preuve Groth16 se vérifie côté vérificateur, et son hash est ancré. C'est suffisant : la chaîne sert de registre, pas de juge |
| Tout est public par défaut | Engagements salés, mode anonyme ZK, divulgation sélective des métadonnées (fait) |
| Tous les nœuds ne gardent pas tout l'historique | Il existe des nœuds d'historique complet (Clio, XRPL Foundation). Futur : un paquet de preuve exportable, et un ancrage redondant optionnel ailleurs (ex. OpenTimestamps) |
| Signatures pas post-quantiques | Voir la question 9 |
| Testnet est réinitialisé périodiquement | Un script recrée l'état de démo ; la production se ferait sur le mainnet |

---

## 3. Défendre le projet devant le jury

### 3.1 Les trois messages clés

1. **La preuve survit au vrai partage et dit *où* l'image a changé.** Après WhatsApp, C2PA a disparu, VeriPress retrouve la provenance et affiche la carte des tuiles modifiées. Calibré sur de vraies photos d'iPhone.
2. **Une confiance publique, révocable mais jamais rétroactive.** Les Credentials XRPL corrigent les trois défauts reprochés à Apple Reference Image : point de défaillance unique, enfermement dans une plateforme, censure rétroactive.
3. **La vie privée garantie par la cryptographie.** « Un appareil accrédité a signé, le 20 novembre, à environ 10 km de Bari », sans dire quel appareil ni où exactement (Groth16).

### 3.2 Questions et objections probables

| # | Question | Réponse courte et honnête |
|---|---|---|
| 1 | **Pourquoi une blockchain ?** | Il nous faut un registre que personne ne peut réécrire ni éteindre, pour trois choses : qui est accrédité, quand une révocation a eu lieu, quand une photo a été ancrée. Avec une base de données, on dépend de celui qui la contrôle : c'est le défaut d'Apple. Sur la chaîne, on ne met que des hashes. |
| 2 | **Une clé logicielle n'est pas une origine physique.** | Exact. La démo utilise une clé Ed25519 et une passkey Secure Enclave (P-256) attestée par le registre. La passkey prouve que la clé est dans du matériel, pas que le capteur a pris la photo. Le protocole ne dépend pas du type d'appareil : un capteur qui signe le RAW (comme chez Apple) n'est qu'un type de clé de plus à accréditer. C'est le travail avec les fabricants (futur). |
| 3 | **Le trou analogique (photographier un écran).** | Aucune approche par signature ne le résout, Apple non plus. On le limite : la fenêtre [T0, T1] borne le moment, et les métadonnées prouvées (date, zone) rendent la mise en scène plus coûteuse. Futur : signaux de profondeur ou LiDAR signés. On prouve une **origine**, pas la vérité de la scène. |
| 4 | **Et si la clé est volée ?** | On révoque le Credential (`CredentialDelete`), de façon publique et datée. Les photos ancrées après sont rejetées, celles d'avant restent valides avec la mention « appareil révoqué depuis le … ». Limite : un voleur peut signer entre le vol et la révocation. Futur : distinguer une révocation « retrait » d'une révocation « compromission », qui permettrait de déclarer une date de compromission antérieure. |
| 5 | **Pourquoi pas simplement C2PA ?** | On est compatibles (manifeste C2PA écrit, fait). Mais C2PA vit dans les métadonnées, que les réseaux suppriment, sa signature casse à la première recompression, elle ne dit pas *où* l'image a changé, et sa trust list est centralisée. On apporte le filigrane relié à l'ancrage, l'arbre robuste avec sa carte, le masquage vérifiable et un registre public. |
| 6 | **Et la vie privée des photographes ?** | En mode nominatif, l'appareil est public. D'où le mode **anonyme** (preuve d'appartenance au registre sans dire quel appareil), les métadonnées **engagées et salées**, et la divulgation sélective. L'anonymat grandit avec la taille du registre (démo : profondeur 10, ≈ 20 appareils fictifs, à dire). |
| 7 | **Coût et passage à l'échelle ?** | Avec l'ancrage groupé (fait), une transaction couvre N photos : ≈ 80 USD par an au rythme d'une transaction par ledger, quel que soit le volume. Le vrai coût qui grossit, c'est la réserve de 1,2 XRP par appareil en mode nominatif, d'où le registre de Merkle (anonyme) ou des Credentials par fabricant pour le grand public. |
| 8 | **Et la cérémonie de confiance ZK ?** | Phase 1 : Powers of Tau publics, à plusieurs contributeurs. Phase 2 : une seule contribution locale, ce qui convient à une démo, pas à la production. En production : cérémonie à plusieurs participants, ou passage à PLONK/Halo2 (setup universel ou sans setup). Une fausse preuve ne permet d'ailleurs que de se faire passer pour « un appareil accrédité anonyme », pas de forger une signature nominative. |
| 9 | **Post-quantique ?** | Nos arbres de Merkle (SHA-256) sont à base de hash, donc déjà robustes. Les signatures (Ed25519, P-256, BN254) ne le sont pas. Le manifeste est hors chaîne et seul son hash est ancré, donc on peut ajouter une signature hybride **ML-DSA + Ed25519** comme Apple sans dépasser le Memo de 1 Ko (futur). Et grâce à l'ancrage, une photo horodatée avant l'arrivée d'ordinateurs quantiques garde une preuve d'antériorité. |
| 10 | **Et si Testnet ou XRPL tombe ?** | Testnet : script de recréation et vidéo de secours. XRPL : si le réseau s'arrête, on ne peut plus ancrer, mais les ancrages passés restent dans l'historique, que des nœuds indépendants conservent. Futur : paquet de preuve autonome et ancrage redondant. Une base de données centrale, elle, disparaît avec son opérateur. |
| 11 | **En quoi c'est mieux qu'Apple ?** | Apple signe mieux, au niveau du capteur et en post-quantique, et on le reconnaît. On corrige les trois défauts cités dans les slides : (1) plusieurs émetteurs plutôt qu'une CA unique, et une compromission ne touche qu'eux, à partir de sa date ; (2) n'importe quel appareil (WebAuthn, Ed25519), avec un vérificateur ouvert ; (3) révocation non rétroactive, et une vérification qui ne dépend pas de nos serveurs. Et en plus : survie au partage, carte des modifications, anonymat. |
| 12 | **Qui contrôle le compte registre ? N'est-ce pas un nouveau point unique ?** | Dans la démo, oui : un seul émetteur. En cible : **plusieurs émetteurs** (fabricants, agences, consortium), chacun en multisignature XRPL, et le vérificateur choisit sa politique d'émetteurs reconnus, comme une trust list mais publique et avec son historique. |
| 13 | **Le filigrane peut être copié ou retiré.** | Copié : détecté, car l'arbre robuste ancré ne correspond pas à l'image (fait, démo). Retiré : on retombe sur le hachage perceptuel, sinon « inconnu ». Le filigrane n'est qu'un **pointeur** : le verdict vient de la signature et des racines de Merkle. |
| 14 | **Qui paie, et est-ce que ça existe déjà ?** | Truepic vend déjà de la capture certifiée aux assureurs via Verisk [14] : le besoin et le budget existent. Notre différence : une preuve qui reste vérifiable sans nous, et la carte des modifications. |

### 3.3 Trame de pitch en 4 minutes

| Temps | Contenu | Critère du jury visé |
|---|---|---|
| 0:00-0:25 | **Accroche** : trois images, « laquelle est vraie ? ». Puis : « Après WhatsApp, même la bonne a perdu sa preuve. » | Pitch, impact |
| 0:25-0:55 | **Problème** : C2PA meurt au partage. Apple Reference Image a trois défauts (point unique, enfermement, censure rétroactive). Réglementation : AI Act art. 50 au 2 décembre, deepfakes punis en Italie. | Impact, vision |
| 0:55-1:25 | **Solution en 4 étapes** : signer à la capture, tuiles et deux arbres de Merkle, ancrage et Credentials XRPL, filigrane | Vision crypto |
| 1:25-2:45 | **Démo en direct** (vidéo de secours prête) : photo 🟢 → retouche 🟠 avec la carte → WhatsApp, provenance retrouvée → révocation non rétroactive → signature anonyme et « 20 nov., ≈ Bari » → (si le temps le permet) filigrane copié détecté | Exécution, interaction avec la blockchain |
| 2:45-3:15 | **Pourquoi XRPL** : Credentials natifs, ≈ 4 s, 10 drops, ancrage groupé ≈ 80 USD/an pour un volume illimité. Plus de 190 tests | Efficacité, proximité d'un vrai déploiement |
| 3:15-3:40 | **Business** : open-core, premier pilote avec un assureur, puis la presse, puis les générateurs d'IA | Impact |
| 3:40-4:00 | **Limites assumées et suite** : trou analogique, capteur signé avec les fabricants, post-quantique hybride. Phrase de fin : « La photo peut voyager partout ; sa preuve voyage avec elle. » | Pitch, défense |

Conseil : répéter la démo au chronomètre, et préparer **3 slides de réserve** pour les questions (coûts XRPL, schéma ZK, tableau comparatif).

---

## 4. Risques, limites et feuille de route

### 4.1 Risques et limites à assumer

- **Pas encore d'origine physique** : pas de signature au niveau du capteur. Il faut un partenariat fabricant, et c'est la plus grosse marche.
- **Trou analogique** : une limite de toute approche par signature.
- **Robustesse perceptuelle** : les attributs robustes sont attaquables, donc on ne s'en sert que pour la localisation et la recherche, jamais comme authentification. Le compromis entre robustesse et sensibilité est calibré sur WhatsApp et iPhone ; il reste d'autres plateformes et formats à calibrer (JPEG XL, HEIC, recadrages).
- **ZK** : cérémonie de phase 2 à refaire, circuit à durcir (séparation de domaine), pas d'anonymat avec une passkey (circuits P-256 futurs), petit registre donc anonymat faible.
- **Passkey** : attestation relue dans l'état *actuel* du Credential (réattester invalide les anciennes photos), compteur de clonage non suivi.
- **C2PA** : notre manifeste utilise un certificat de test. Il est présenté comme une information, jamais comme une preuve.
- **Disponibilité** : dépendance aux nœuds d'historique complet ; index hors chaîne à rendre reconstructible et répliqué.
- **Marché** : C2PA a l'industrie derrière lui, et Truepic est déjà chez les assureurs. Il faut un angle précis (survie au partage, preuve vérifiable sans fournisseur).
- **Juridique** : la recevabilité comme preuve et le statut RGPD des métadonnées (même engagées) sont à valider avec des juristes. La réglementation bouge encore (Omnibus, SB 1000).
- **Crypto-actif** : la réserve en XRP dépend du cours, et le vote des validateurs peut la modifier [2][20].

### 4.2 Feuille de route (6 à 12 mois après le hackathon)

| Horizon | Objectifs |
|---|---|
| **M0-M2** | Mainnet ; multisignature de l'émetteur ; paquet de preuve autonome exportable ; vérificateur open source autonome (CLI et navigateur) ; mesures de performance (temps de preuve ZK, filigrane) ; audit interne du circuit et cérémonie phase 2 multi-parties |
| **M2-M6** | **Pilote assurance** (SDK web de capture avec passkey, tableau de bord gestionnaire) ; app mobile native avec attestation matérielle (Android Key Attestation, Apple App Attest) ; calibrage sur Instagram, Telegram et X ; plusieurs émetteurs |
| **M6-M9** | Pilote presse (page publique, mode anonyme) ; signature hybride post-quantique du manifeste (ML-DSA) ; preuves de métadonnées à la demande, authentifiées par le propriétaire ; circuits P-256 pour une passkey anonyme |
| **M9-M12** | Offre de conformité art. 50(2) pour générateurs d'IA ; proposition d'assertion « ancrage XRPL » dans C2PA ; discussions avec un fabricant (Californie 2028) ; recherche : preuves ZK de transformations autorisées (recadrage, redimensionnement) dans l'esprit de VerITAS |

---

## Sources

1. XRPL, *Transaction Cost* (coût de référence de 10 drops, montée en charge) : https://xrpl.org/docs/concepts/transactions/transaction-cost
2. XRPL, *Reserves* (réserve de base et réserve par objet, lecture via `server_info`) : https://xrpl.org/docs/concepts/accounts/reserves
3. The Block, *XRP Ledger developers lower base reserve for accounts to 1 XRP* (déc. 2024) : https://www.theblock.co/post/329247/xrp-ledger-base-reserve ; XRPL blog, *Lower reserves are in effect* : https://xrpl.org/blog/2024/lower-reserves-are-in-effect
4. XRPL, *Credential* (entrée du ledger, réserve émetteur puis sujet) : https://xrpl.org/docs/references/protocol/ledger-data/ledger-entry-types/credential ; *CredentialAccept* : https://xrpl.org/docs/references/protocol/transactions/types/credentialaccept ; XLS-70 : https://xls.xrpl.org/xls/XLS-0070-credentials.html
5. Cloud Security Alliance, *EU AI Act Article 50: Transparency Obligations Take Effect* (juil. 2026) : https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-article-50-transparency-20260729/ ; note sur l'échéance du filigrane (sept. 2026) : https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/09/CSA_research_note_eu_ai_act_article50_watermarking_deadline_20260921-csa-styled.pdf
6. Simmons & Simmons, *Provisional agreement reached on AI Omnibus package* : https://www.simmons-simmons.com/en/publications/cmoveo6ke00icuxskpgueb0od/ai-omnibus-update ; Sidley, *EU AI Act transparency obligations: preparing for compliance by 2 August 2026* : https://datamatters.sidley.com/2026/06/24/eu-ai-act-transparency-obligations-preparing-for-compliance-by-2-august-2026/
7. CMS, *Digital omnibus on AI: adjusted timelines and transitional provisions* : https://cms.law/en/gbr/publication/digital-omnibus-on-ai-adjusted-timelines-and-transitional-provisions-explained
8. DLA Piper, *Commission guidelines on systemic risks to electoral processes* (2024) : https://www.dlapiper.com/en/insights/blogs/mse-today/2024/commission-guidelines-on-systematic-risks-electoral-processes ; Willkie, *Election integrity under the DSA* (nov. 2026) : https://www.willkie.com/publications/2026/11/election-integrity-under-the-digital-services-act-dsa-six-takeaways-for-platforms
9. DLA Piper, *Diritto Intelligente n° 14* (loi 132/2025) : https://www.dlapiper.com/en/insights/publications/diritto-intelligente/2025/diritto-intelligente-issue-n-14
10. Baker Botts, *Italy's AI law* : https://ourtake.bakerbotts.com/post/102lr7n/italys-ai-law-a-national-framework-bounded-by-the-eu-ai-act ; IRIS Merlin : https://merlin.obs.coe.int/article/10424
11. Orrick, *California delays its AI Transparency Act* : https://infobytes.orrick.com/2025-10-17/california-delays-its-ai-transparency-act-and-passes-new-content-laws/ ; Morgan Lewis (août 2026) : https://www.morganlewis.com/de/pubs/2026/08/new-california-ai-disclosure-rules-become-operative
12. MoFo, *California Revamps AI Transparency Requirements* (mention de SB 1000, non vérifiée) : https://www.mofo.com/resources/insights/261001-california-revamps-ai-transparency-requirements
13. Allianz UK, *Posting car photos fuels fraud* (juin 2026) : https://www.allianz.co.uk/news-and-insight/news/posting-car-photos-fuels-fraud.html
14. Verisk, *Truepic brings verified visual evidence to Verisk's ClaimSearch workflow* (sept. 2026) : https://www.verisk.com/company/newsroom/truepic-brings-verified-visual-evidence-to-verisks-claimsearch-workflow/
15. Google Security Blog, *Pixel & Android: trusted images with C2PA Content Credentials* (sept. 2025) : https://security.googleblog.com/2025/09/pixel-android-trusted-images-c2pa-content-credentials.html ; *C2PA adoption in 2026* : https://softwareseni.com/c2pa-adoption-in-2026-hardware-platforms-and-verification-reality
16. XRPL, *Transaction Common Fields* (Memos ≤ 1 Ko) : https://xrpl.org/transaction-common-fields.html
17. CryptoSlate, rythme de clôture de 3 à 5 s et record de ledger : https://cryptoslate.com/xrpl-proved-it-can-handle-over-3000-transactions-but-the-traffic-was-entirely-synthetic/
18. TradingNews, *XRP holds $0.967 after $0.894 two-year low* (nov. 2026) : https://www.tradingnews.com/news/xrp-holds-0-967-after-0-894-two-year-low-reclaiming-1-00-opens-a-1-105-usd-target
19. Base docs, *Fees* : https://docs.base.org/chain/fees ; Spark, *The L2 fee war* : https://www.spark.money/research/ethereum-l2-rollup-fee-war-dynamics
20. XRPL, *Fee Voting* : https://xrpl.org/fee-voting.html

Sources internes au dépôt : `README.md`, `docs/decisions.md`, `docs/interfaces.md`, `docs/security-review.md`, `docs/research.md` (état de l'art : Numbers Protocol, Starling Lab, VerITAS, ZK-IMG). Les éléments sur Apple Reference Image et les critères du jury viennent des slides des organisateurs, que nous n'avons pas vérifiés de façon indépendante.

**Non sourcé** : tous les prix de vente **(hyp.)**, les 5 000 lamports de Solana, la finalité d'Ethereum (≈ 13 min), les durées de génération des preuves ZK (à mesurer).
