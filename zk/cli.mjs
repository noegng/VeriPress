#!/usr/bin/env node
// VeriPress ZK CLI — contract in docs/interfaces.md § Phase 2. JSON on stdin -> JSON on stdout.
// Big integers are decimal strings. Exit code != 0 and a message on stderr on error.
//
//   echo '{}' | node zk/cli.mjs keygen
//   echo '{"pks": [["x","y"]], "depth": 10}' | node zk/cli.mjs root
//   echo '{"sk","pks","index","digest","depth"}' | node zk/cli.mjs prove-device
//   echo '{"proof","public"}' | node zk/cli.mjs verify-device
//   echo '{"time","lat_e6","lon_e6","salt"}' | node zk/cli.mjs commit-meta
//   echo '{…, "t_min","t_max","lat_min_e6","lat_max_e6","lon_min_e6","lon_max_e6"}' | node zk/cli.mjs prove-meta
//   echo '{"proof","public"}' | node zk/cli.mjs verify-meta

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildEddsa, buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const BUILD = join(HERE, "build");
const DEFAULT_DEPTH = 10;

const readStdin = () => new Promise((resolve) => {
  let data = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (c) => (data += c));
  process.stdin.on("end", () => resolve(data.trim() ? JSON.parse(data) : {}));
});

let _poseidon, _eddsa;
async function crypto() {
  _poseidon ??= await buildPoseidon();
  _eddsa ??= await buildEddsa();
  return { poseidon: _poseidon, eddsa: _eddsa, F: _poseidon.F };
}

const hexToBuf = (h) => Buffer.from(h, "hex");

function splitDigest(digest) {
  if (!/^[0-9a-fA-F]{64}$/.test(digest)) throw new Error("digest must be 64 hex chars");
  return [BigInt("0x" + digest.slice(0, 32)), BigInt("0x" + digest.slice(32))];
}

// Poseidon Merkle tree over Poseidon(x, y) leaves, empty leaves = 0. Returns all levels.
function buildTree({ poseidon, F }, pks, depth) {
  if (pks.length > 2 ** depth) throw new Error(`registry holds at most ${2 ** depth} keys`);
  let level = Array.from({ length: 2 ** depth }, (_, i) =>
    i < pks.length ? F.toObject(poseidon([BigInt(pks[i][0]), BigInt(pks[i][1])])) : 0n);
  const levels = [level];
  for (let d = 0; d < depth; d++) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(F.toObject(poseidon([level[i], level[i + 1]])));
    levels.push(next);
    level = next;
  }
  return levels;
}

const commands = {
  async keygen() {
    const { eddsa, F } = await crypto();
    const sk = randomBytes(32);
    const pk = eddsa.prv2pub(sk);
    return { sk: sk.toString("hex"), pk: [F.toObject(pk[0]).toString(), F.toObject(pk[1]).toString()] };
  },

  async root({ pks, depth = DEFAULT_DEPTH }) {
    const levels = buildTree(await crypto(), pks, depth);
    return { root: levels[depth][0].toString() };
  },

  async "prove-device"({ sk, pks, index, digest, depth = DEFAULT_DEPTH }) {
    const c = await crypto();
    const { eddsa, poseidon, F } = c;
    const prv = hexToBuf(sk);
    const pk = eddsa.prv2pub(prv);
    const [Ax, Ay] = [F.toObject(pk[0]), F.toObject(pk[1])];
    if (String(Ax) !== String(pks[index][0]) || String(Ay) !== String(pks[index][1]))
      throw new Error("sk does not match pks[index]");
    const [hi, lo] = splitDigest(digest);
    const sig = eddsa.signPoseidon(prv, poseidon([hi, lo]));
    const levels = buildTree(c, pks, depth);
    const path_elements = [], path_index = [];
    let i = index;
    for (let d = 0; d < depth; d++) {
      path_elements.push(levels[d][i ^ 1].toString());
      path_index.push(String(i & 1));
      i >>= 1;
    }
    const input = {
      root: levels[depth][0].toString(), digest_hi: hi.toString(), digest_lo: lo.toString(),
      Ax: Ax.toString(), Ay: Ay.toString(),
      R8x: F.toObject(sig.R8[0]).toString(), R8y: F.toObject(sig.R8[1]).toString(), S: sig.S.toString(),
      path_elements, path_index,
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input, join(BUILD, "device.wasm"), join(BUILD, "device_final.zkey"));
    return { proof, public: publicSignals };
  },

  async "verify-device"({ proof, public: pub }) {
    return { ok: await verifyWith("device", proof, pub) };
  },

  // ---- ZK B: capture time + GPS (meta.circom) ----

  async "commit-meta"(m) {
    const { poseidon, F } = await crypto();
    const [t, la, lo, salt] = metaPrivate(m);
    return { commitment: F.toObject(poseidon([t, la, lo, salt])).toString() };
  },

  async "prove-meta"(m) {
    const { poseidon, F } = await crypto();
    const [time, lat_s, lon_s, salt] = metaPrivate(m);
    const input = {
      commitment: F.toObject(poseidon([time, lat_s, lon_s, salt])).toString(),
      t_min: String(m.t_min), t_max: String(m.t_max),
      lat_min: String(shiftLat(m.lat_min_e6)), lat_max: String(shiftLat(m.lat_max_e6)),
      lon_min: String(shiftLon(m.lon_min_e6)), lon_max: String(shiftLon(m.lon_max_e6)),
      time: String(time), lat_s: String(lat_s), lon_s: String(lon_s), salt: String(salt),
    };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input, join(BUILD, "meta.wasm"), join(BUILD, "meta_final.zkey"));
    return { proof, public: publicSignals };
  },

  async "verify-meta"({ proof, public: pub }) {
    return { ok: await verifyWith("meta", proof, pub) };
  },
};

const shiftLat = (e6) => BigInt(e6) + 90_000_000n;
const shiftLon = (e6) => BigInt(e6) + 180_000_000n;

function metaPrivate({ time, lat_e6, lon_e6, salt }) {
  if (!/^[0-9a-fA-F]{62}$/.test(salt)) throw new Error("salt must be 31 bytes hex");
  return [BigInt(time), shiftLat(lat_e6), shiftLon(lon_e6), BigInt("0x" + salt)];
}

async function verifyWith(circuit, proof, pub) {
  const vkey = JSON.parse(readFileSync(join(BUILD, `${circuit}_vkey.json`), "utf8"));
  try { return await snarkjs.groth16.verify(vkey, pub, proof); } catch { return false; }
}

const cmd = process.argv[2];
if (!commands[cmd]) {
  process.stderr.write(`usage: node zk/cli.mjs <${Object.keys(commands).join("|")}>  (JSON on stdin)\n`);
  process.exit(2);
}
try {
  const out = await commands[cmd](await readStdin());
  process.stdout.write(JSON.stringify(out) + "\n");
  process.exit(0); // snarkjs keeps worker threads alive
} catch (e) {
  process.stderr.write(`${cmd}: ${e.message}\n`);
  process.exit(1);
}
