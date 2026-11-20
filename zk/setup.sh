#!/usr/bin/env bash
# TileProof ZK setup: compile circuits, phase-2 trusted setup on top of the public
# "powers of tau" (PSE perpetual ceremony, phase 1, 2^14), export verification keys.
#
# Phase 2 here is a single local contribution: fine for a hackathon demo. In production it
# must be a multi-party ceremony (decisions.md Q7).
#   bash zk/setup.sh            # from the repo root, or `npm run setup` inside zk/
set -euo pipefail
cd "$(dirname "$0")"
PTAU=build/pot14.ptau
# Perpetual Powers of Tau (PSE / Ethereum Foundation), 80 contributions, truncated to 2^14.
PTAU_URL=https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_14.ptau
mkdir -p build
[ -d node_modules ] || npm install --silent
[ -f "$PTAU" ] || curl -fsSL "$PTAU_URL" -o "$PTAU"

for c in ${CIRCUITS:-device}; do
  circom "circuits/$c.circom" --r1cs --wasm -o build >/dev/null
  cp "build/${c}_js/${c}.wasm" "build/$c.wasm"
  npx snarkjs groth16 setup "build/$c.r1cs" "$PTAU" "build/${c}_0000.zkey" >/dev/null
  npx snarkjs zkey contribute "build/${c}_0000.zkey" "build/${c}_final.zkey" \
      --name="tileproof-hackathon" -e="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')" >/dev/null
  npx snarkjs zkey export verificationkey "build/${c}_final.zkey" "build/${c}_vkey.json" >/dev/null
  echo "$c: build/$c.wasm build/${c}_final.zkey build/${c}_vkey.json"
done
