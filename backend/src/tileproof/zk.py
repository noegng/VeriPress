"""Python wrapper of the `zk/` Node CLI (Groth16 / circom). OWNER: Dev A.

Contract: docs/interfaces.md § Phase 2. Each call spawns `node zk/cli.mjs <cmd>` with JSON on
stdin; big integers are decimal strings. Proving a device attestation takes ~2 s.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

DEPTH = 10  # registry tree depth: up to 1024 devices (decisions.md Q14)


class ZkError(RuntimeError):
    pass


def zk_dir() -> Path:
    return Path(os.environ.get("TILEPROOF_ZK_DIR") or Path(__file__).resolve().parents[3] / "zk")


def _run(cmd: str, payload: dict, timeout: float = 120) -> dict:
    try:
        proc = subprocess.run(
            ["node", str(zk_dir() / "cli.mjs"), cmd],
            input=json.dumps(payload), capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise ZkError(f"zk {cmd}: {e}") from e
    if proc.returncode != 0:
        raise ZkError(proc.stderr.strip() or f"zk {cmd} failed ({proc.returncode})")
    return json.loads(proc.stdout)


def split_digest(digest: str) -> tuple[str, str]:
    """SHA-256 hex -> (high 128 bits, low 128 bits) as decimal strings (circuit public inputs)."""
    return str(int(digest[:32], 16)), str(int(digest[32:], 16))


def keygen() -> dict:
    """{"sk": hex, "pk": [x, y]} — a Baby Jubjub key (keys/<device>.json["bjj"])."""
    return _run("keygen", {})


def root(pks: list[list[str]], depth: int = DEPTH) -> str:
    return _run("root", {"pks": pks, "depth": depth})["root"]


def prove_device(sk: str, pks: list[list[str]], index: int, digest: str, depth: int = DEPTH) -> dict:
    """{"proof": {...}, "public": [root, digest_hi, digest_lo]}"""
    return _run("prove-device", {"sk": sk, "pks": pks, "index": index, "digest": digest, "depth": depth})


def verify_device(proof: dict, public: list[str]) -> bool:
    try:
        return bool(_run("verify-device", {"proof": proof, "public": public})["ok"])
    except ZkError:
        return False
