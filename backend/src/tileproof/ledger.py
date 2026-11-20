"""XRPL contract — OWNER: Dev B.  Shared interface: change only via a dedicated commit on main.

Everything the rest of the code needs from the ledger goes through `Ledger`.
`FakeLedger` is an in-memory implementation so Dev A can build and test the
pipeline without network; Dev B implements `XrplLedger` (Testnet).

Conventions (fixed):
- `pubkey`   : XRPL ed25519 public key, hex upper, "ED" + 64 hex (66 chars).
               The signer key IS an XRPL account key: its address is
               `xrpl.core.keypairs.derive_classic_address(pubkey)`, and that address is
               the Subject of its Credential.
- `digest`   : hex SHA-256 of the canonical manifest (`Manifest.digest()`).
- `signature`: hex Ed25519 signature (64 bytes) over `bytes.fromhex(digest)`.
- Anchor tx  : Payment of 1 drop from the anchoring service account to the registry account,
               one Memo: MemoType = hex("tileproof/v1"),
               MemoData = hex(JSON {"d": digest, "s": signature, "k": pubkey}).
- Credential : issued by the registry account, CredentialType = hex of the enum value
               ("CAPTURE_DEVICE" / "AI_GENERATOR"), accepted by the subject.
               Revoked = CredentialDelete -> `credential_type` returns None.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class CredentialType(str, Enum):
    CAPTURE_DEVICE = "CAPTURE_DEVICE"
    AI_GENERATOR = "AI_GENERATOR"


@dataclass(frozen=True)
class Anchor:
    tx_hash: str
    digest: str
    signature: str
    pubkey: str
    timestamp: int  # unix seconds (ledger close time)
    explorer_url: str


class Ledger(Protocol):
    def anchor(self, digest: str, signature: str, pubkey: str) -> Anchor:
        """Submit the anchor tx, wait for validation, return it."""
        ...

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        """Read back an anchor tx. None if not found / not a tileproof memo."""
        ...

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        """Valid (accepted, not expired, not deleted) credential of the key's account.
        `at_time` may be ignored for the hackathon (current state only)."""
        ...


class FakeLedger:
    """In-memory ledger for tests and offline dev."""

    def __init__(self) -> None:
        self.anchors: dict[str, Anchor] = {}
        self.credentials: dict[str, CredentialType] = {}

    def issue(self, pubkey: str, ctype: CredentialType) -> None:
        self.credentials[pubkey] = ctype

    def revoke(self, pubkey: str) -> None:
        self.credentials.pop(pubkey, None)

    def anchor(self, digest: str, signature: str, pubkey: str) -> Anchor:
        tx_hash = hashlib.sha256(f"{digest}{signature}{len(self.anchors)}".encode()).hexdigest().upper()
        a = Anchor(tx_hash, digest, signature, pubkey, int(time.time()), f"fake://tx/{tx_hash}")
        self.anchors[tx_hash] = a
        return a

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        return self.anchors.get(tx_hash)

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        return self.credentials.get(pubkey)


class XrplLedger:
    """Real implementation on XRPL Testnet — TODO Dev B.

    Reads config from env / keys/ (see docs/interfaces.md): node URL, anchoring service
    wallet, registry address. Explorer: https://testnet.xrpl.org/transactions/<hash>
    """

    def anchor(self, digest: str, signature: str, pubkey: str) -> Anchor:
        raise NotImplementedError

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        raise NotImplementedError

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        raise NotImplementedError
