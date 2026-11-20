# VeriPress ZK

Circom 2 circuits (Groth16, BN254) and a Node command-line tool. Command formats: [`docs/interfaces.md`](../docs/interfaces.md#zk-tool-zkclimjs). Design: [`docs/architecture.md`](../docs/architecture.md#12-zero-knowledge-proofs). Decisions: [`docs/decisions.md`](../docs/decisions.md) (Q2–Q4, Q13–Q17).

| Circuit | Proves | Constraints |
|---|---|---|
| `device.circom` | "a device of the registry (Poseidon Merkle tree, depth 10) signed this manifest digest", without revealing which one | 14,578 |
| `meta.circom` | "the committed capture time and GPS position lie in these intervals" (day, ~10 km box), without revealing them | 1,295 |

```bash
cd zk && npm ci                 # snarkjs, circomlib, circomlibjs
bash setup.sh                   # circom → wasm, phase-2 ceremony, verification keys (only to rebuild)
echo '{}' | node cli.mjs keygen
```

Requirements: Node ≥ 20, and `circom` only to recompile (`cargo install --git https://github.com/iden3/circom circom`). `build/*.wasm`, `build/*_final.zkey` and `build/*_vkey.json` are committed: the backend works without circom. The backend calls this tool through `backend/src/veripress/zk.py`.

**Trust.** Phase 1 comes from the public *Perpetual Powers of Tau* ceremony (PSE, 80 contributions). Phase 2, specific to each circuit, is a single local contribution: enough for a demo. In production: a multi-party ceremony, or a proof system without a per-circuit setup (PLONK, Halo2).

**Known hardening.** `device.circom` does not domain-separate leaf hashes (`Poseidon(x, y)`) from inner-node hashes. Not exploitable (fixed depth, the key must be a curve point); the fix is `Poseidon(3)` with a domain tag.
