"""Ed25519 signing with XRPL-format keys (see docs/interfaces.md). OWNER: Dev A.

Keys live in $VERIPRESS_KEYS (default ./keys), written by scripts/setup_testnet.py:
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
    return Path(os.environ.get("VERIPRESS_KEYS", "keys"))


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


# ---------------------------------------------------------------- WebAuthn (passkey, P-256)

def _b64u_decode(s: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def webauthn_hosts() -> set[str]:
    """Hosts allowed as WebAuthn origin / relying party (VERIPRESS_WEBAUTHN_HOSTS, comma-separated)."""
    return {h.strip() for h in os.environ.get("VERIPRESS_WEBAUTHN_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()}


def verify_webauthn(assertion: dict, digest: str, passkey_sec1_hex: str) -> None:
    """Check a WebAuthn assertion over the manifest digest. Raises ValueError with the reason.

    - the assertion's key is the passkey committed in the manifest;
    - clientDataJSON: type "webauthn.get", challenge = the digest bytes, origin on an allowed host
      (https, or http only for localhost / 127.0.0.1);
    - authenticatorData: rpIdHash = sha256(origin host), user present AND verified (Touch ID);
    - ECDSA P-256 / SHA-256 signature over authenticatorData || sha256(clientDataJSON).
    """
    import hashlib
    from urllib.parse import urlparse

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    try:
        key = serialization.load_der_public_key(_b64u_decode(assertion["public_key"]))
        auth = _b64u_decode(assertion["authenticator_data"])
        cdj = _b64u_decode(assertion["client_data_json"])
        sig = _b64u_decode(assertion["signature"])
        client = json.loads(cdj)
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"malformed WebAuthn assertion: {e}") from e
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("passkey must be ECDSA P-256")
    sec1 = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    if sec1.hex() != (passkey_sec1_hex or "").lower():
        raise ValueError("assertion made with another passkey than the one in the manifest")
    if client.get("type") != "webauthn.get":
        raise ValueError("clientData type is not webauthn.get")
    if _b64u_decode(str(client.get("challenge", ""))) != bytes.fromhex(digest):
        raise ValueError("WebAuthn challenge is not this manifest digest")
    origin = urlparse(str(client.get("origin", "")))
    host = origin.hostname or ""
    if host not in webauthn_hosts() or not (
        origin.scheme == "https" or (origin.scheme == "http" and host in ("localhost", "127.0.0.1"))
    ):
        raise ValueError(f"WebAuthn origin not allowed: {client.get('origin')}")
    if len(auth) < 37 or auth[:32] != hashlib.sha256(host.encode()).digest():
        raise ValueError("authenticatorData rpIdHash does not match the origin")
    if not (auth[32] & 0x01 and auth[32] & 0x04):
        raise ValueError("user presence and user verification (biometrics / PIN) are required")
    try:
        key.verify(sig, auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as e:
        raise ValueError("WebAuthn signature does not verify") from e


# ---------------------------------------------------------------- post-quantum (ML-DSA-87, FIPS 204)

PQ_ALG = "ML-DSA-87"


def load_pq_key(name: str):
    """(ML-DSA-87 private key, raw public key hex) from keys/<name>.json["mldsa"], or None."""
    from cryptography.hazmat.primitives import serialization

    data = json.loads((keys_dir() / f"{name}.json").read_text()).get("mldsa")
    if not data:
        return None
    return serialization.load_pem_private_key(data["private_pem"].encode(), None), str(data["public_key"]).lower()


def verify_pq(digest: str, signature_hex: str, public_key_hex: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric import mldsa

    try:
        pub = mldsa.MLDSA87PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), bytes.fromhex(digest))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
