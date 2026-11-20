"""Ed25519 signing with XRPL-format keys (see docs/interfaces.md). OWNER: Dev A.

Keys live in $TILEPROOF_KEYS (default ./keys), written by scripts/setup_testnet.py:
  keys/<name>.json  {"seed", "address", "public_key": "ED…", "private_key": "ED…"}
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def keys_dir() -> Path:
    return Path(os.environ.get("TILEPROOF_KEYS", "keys"))


@dataclass(frozen=True)
class SignerKey:
    public_key: str  # "ED" + 64 hex, XRPL format
    private_key: str

    def sign(self, digest: str) -> str:
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(self.private_key[2:]))
        return sk.sign(bytes.fromhex(digest)).hex()


def load_key(name: str) -> SignerKey:
    data = json.loads((keys_dir() / f"{name}.json").read_text())
    return SignerKey(public_key=data["public_key"].upper(), private_key=data["private_key"])


def verify_signature(digest: str, signature: str, public_key: str) -> bool:
    try:
        if not public_key.upper().startswith("ED") or len(public_key) != 66:
            return False
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key[2:]))
        pk.verify(bytes.fromhex(signature), bytes.fromhex(digest))
        return True
    except (InvalidSignature, ValueError):
        return False
