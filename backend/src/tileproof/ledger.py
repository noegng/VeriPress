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
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
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
    # Phase 2 (docs/interfaces.md § Phase 2)
    validated: bool = True  # False while the tx is not yet in a validated ledger (fast anchoring)
    anonymous: bool = False
    registry_root: str = ""  # anonymous mode: registry root the proof was made against
    bundle_hash: str = ""  # anonymous / passkey: sha256 hex of the proof bundle kept in the store
    cid: str = ""  # option: content id of the disclosure


class Ledger(Protocol):
    def anchor(self, digest: str, signature: str, pubkey: str, wait: bool = True) -> Anchor:
        """Submit the anchor tx; wait=True waits for validation, False returns on submit."""
        ...

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        """Anonymous anchor: no device key nor signature on chain, only the proof's root and hash."""
        ...

    def registry_root_at(self, at_time: int) -> str | None:
        """Anonymous device registry root in force at `at_time` (last one published before it)."""
        ...

    def credential_revoked_at(self, pubkey: str) -> int | None:
        """Unix time of the CredentialDelete of this key's credential, if any."""
        ...

    def credential_passkey(self, pubkey: str) -> str | None:
        """sha256 hex of the P-256 passkey attested in the credential URI, if any."""
        ...

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        """Read back an anchor tx. None if not found / not a tileproof memo."""
        ...

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        """Credential of the key's account valid at `at_time` (issued before it, not deleted
        before it; non-retroactive revocation, decisions.md Q5). None = now."""
        ...


class FakeLedger:
    """In-memory ledger for tests and offline dev."""

    def __init__(self) -> None:
        self.anchors: dict[str, Anchor] = {}
        self.credentials: dict[str, CredentialType] = {}
        self.revoked_at: dict[str, int] = {}
        self.passkeys: dict[str, str] = {}
        self.registry_roots: list[tuple[int, str]] = []  # (published at, root), in order

    def issue(self, pubkey: str, ctype: CredentialType, passkey_hash: str | None = None) -> None:
        self.credentials[pubkey] = ctype
        self.revoked_at.pop(pubkey, None)
        if passkey_hash:
            self.passkeys[pubkey] = passkey_hash

    def revoke(self, pubkey: str, at: int | None = None) -> None:
        if pubkey in self.credentials:
            self.revoked_at[pubkey] = int(time.time()) if at is None else at

    def publish_registry_root(self, root: str, at: int | None = None) -> None:
        self.registry_roots.append((int(time.time()) if at is None else at, root))
        self.registry_roots.sort()

    def _store(self, a: Anchor) -> Anchor:
        self.anchors[a.tx_hash] = a
        return a

    def _tx_hash(self, *parts: str) -> str:
        return hashlib.sha256(("".join(parts) + str(len(self.anchors))).encode()).hexdigest().upper()

    def anchor(self, digest: str, signature: str, pubkey: str, wait: bool = True) -> Anchor:
        h = self._tx_hash(digest, signature)
        return self._store(Anchor(h, digest, signature, pubkey, int(time.time()), f"fake://tx/{h}"))

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        h = self._tx_hash(digest, bundle_hash)
        return self._store(Anchor(h, digest, "", "", int(time.time()), f"fake://tx/{h}", anonymous=True,
                                  registry_root=registry_root, bundle_hash=bundle_hash))

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        return self.anchors.get(tx_hash)

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        revoked = self.revoked_at.get(pubkey)
        if revoked is not None and (at_time is None or at_time >= revoked):
            return None
        return self.credentials.get(pubkey)

    def credential_revoked_at(self, pubkey: str) -> int | None:
        return self.revoked_at.get(pubkey)

    def credential_passkey(self, pubkey: str) -> str | None:
        return self.passkeys.get(pubkey)

    def registry_root_at(self, at_time: int) -> str | None:
        roots = [r for t, r in self.registry_roots if t <= at_time]
        return roots[-1] if roots else None


MEMO_TYPE = "tileproof/v1"
LSF_ACCEPTED = 0x00010000
DEFAULT_NODE = "https://s.altnet.rippletest.net:51234"
EXPLORER = "https://testnet.xrpl.org/transactions/"


class XrplLedger:
    """Real implementation on XRPL Testnet.

    Config: env TILEPROOF_XRPL_URL (default Testnet JSON-RPC), TILEPROOF_KEYS (default
    backend/keys). Needs keys/anchor.json (payer) and keys/registry.json (issuer + destination),
    written by scripts/setup_testnet.py.
    """

    def __init__(self, node_url: str | None = None, keys_dir: str | Path | None = None) -> None:
        from xrpl.clients import JsonRpcClient
        from xrpl.wallet import Wallet

        keys = Path(keys_dir or os.environ.get("TILEPROOF_KEYS") or Path(__file__).resolve().parents[2] / "keys")
        self.client = JsonRpcClient(node_url or os.environ.get("TILEPROOF_XRPL_URL") or DEFAULT_NODE)
        self.registry = json.loads((keys / "registry.json").read_text())["address"]
        self.wallet = Wallet.from_seed(json.loads((keys / "anchor.json").read_text())["seed"])

    def anchor(self, digest: str, signature: str, pubkey: str, wait: bool = True) -> Anchor:
        # TODO Dev B (phase 2): wait=False -> submit without waiting (fast anchoring)
        from xrpl.models.transactions import Memo, Payment
        from xrpl.transaction import submit_and_wait
        from xrpl.utils import str_to_hex

        data = json.dumps({"d": digest, "s": signature, "k": pubkey}, separators=(",", ":"))
        tx = Payment(
            account=self.wallet.address,
            destination=self.registry,
            amount="1",
            memos=[Memo(memo_type=str_to_hex(MEMO_TYPE), memo_data=str_to_hex(data))],
        )
        resp = submit_and_wait(tx, self.client, self.wallet)
        code = resp.result.get("meta", {}).get("TransactionResult")
        if code != "tesSUCCESS":
            raise RuntimeError(f"anchor tx failed: {code}")
        tx_hash = resp.result["hash"]
        return Anchor(tx_hash, digest, signature, pubkey, _close_time(resp.result), EXPLORER + tx_hash)

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        from xrpl.models.requests import Tx
        from xrpl.utils import hex_to_str

        resp = self.client.request(Tx(transaction=tx_hash))
        if not resp.is_successful() or not resp.result.get("validated"):
            return None
        r = resp.result
        tx = r.get("tx_json", r)  # API v2 nests fields under tx_json
        if (
            tx.get("TransactionType") != "Payment"
            or tx.get("Destination") != self.registry
            or r.get("meta", {}).get("TransactionResult") != "tesSUCCESS"
        ):
            return None
        for m in tx.get("Memos", []):
            memo = m.get("Memo", {})
            try:
                if hex_to_str(memo.get("MemoType", "")) != MEMO_TYPE:
                    continue
                data = json.loads(hex_to_str(memo["MemoData"]))
                hash_ = r.get("hash", tx_hash).upper()
                return Anchor(hash_, data["d"], data["s"], data["k"], _close_time(r), EXPLORER + hash_)
            except (KeyError, ValueError, UnicodeDecodeError):
                continue
        return None

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        from xrpl.core.keypairs import derive_classic_address
        from xrpl.models.requests import LedgerEntry
        from xrpl.models.requests.ledger_entry import Credential
        from xrpl.utils import posix_to_ripple_time, str_to_hex

        try:
            subject = derive_classic_address(pubkey)
        except Exception:
            return None
        now = posix_to_ripple_time(int(time.time()))
        for ctype in CredentialType:
            resp = self.client.request(
                LedgerEntry(
                    credential=Credential(subject=subject, issuer=self.registry, credential_type=str_to_hex(ctype.value)),
                    ledger_index="validated",
                )
            )
            if not resp.is_successful():
                continue
            node = resp.result["node"]
            expired = "Expiration" in node and node["Expiration"] <= now
            if node.get("Flags", 0) & LSF_ACCEPTED and not expired:
                return ctype
        return None


    # ---- Phase 2 — TODO Dev B (docs/interfaces.md § Phase 2) ----

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        raise NotImplementedError("Dev B, phase 2: anonymous anchor memo")

    def registry_root_at(self, at_time: int) -> str | None:
        raise NotImplementedError("Dev B, phase 2: registry roots published by the registry account")

    def credential_revoked_at(self, pubkey: str) -> int | None:
        raise NotImplementedError("Dev B, phase 2: CredentialDelete date")

    def credential_passkey(self, pubkey: str) -> str | None:
        raise NotImplementedError("Dev B, phase 2: passkey hash in the credential URI")


def _close_time(result: dict) -> int:
    """Ledger close time (unix seconds) from a tx / submit_and_wait result."""
    from xrpl.utils import ripple_time_to_posix

    tx = result.get("tx_json", result)
    if "date" in tx:
        return ripple_time_to_posix(tx["date"])
    if "close_time_iso" in result:
        return int(datetime.fromisoformat(result["close_time_iso"].replace("Z", "+00:00")).timestamp())
    return int(time.time())
