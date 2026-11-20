# TileProof ZK

Circuits circom 2 (Groth16, BN254) et CLI Node. Contrat : `docs/interfaces.md` § Phase 2. Décisions : `docs/decisions.md` (Q2–Q4, Q13–Q14).

| Circuit | Prouve | Contraintes |
|---|---|---|
| `device.circom` | « un appareil du registre (arbre Poseidon de profondeur 10) a signé ce digest de manifeste », sans dire lequel | 14 578 |

```bash
cd zk && npm install            # snarkjs, circomlib, circomlibjs
bash setup.sh                   # circom → wasm, cérémonie phase 2, clé de vérification
echo '{}' | node cli.mjs keygen
```

Pré-requis : Node ≥ 20, et `circom` uniquement pour recompiler (`cargo install --git https://github.com/iden3/circom circom`). Les fichiers `build/*.wasm`, `build/*_final.zkey` et `build/*_vkey.json` sont commités : le backend fonctionne sans circom.

**Confiance.** La phase 1 vient de la cérémonie publique *Perpetual Powers of Tau* (PSE, 80 contributions). La phase 2, propre au circuit, est une seule contribution locale : suffisant pour une démo. En production, il faut une cérémonie multi-parties, ou un système de preuve sans cérémonie propre au circuit (PLONK, Halo2).
