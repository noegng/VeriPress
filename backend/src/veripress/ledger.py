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
               one Memo: MemoType = hex("veripress/v1"),
               MemoData = hex(JSON {"d": digest, "s": signature, "k": pubkey}).
- Credential : issued by the registry account, CredentialType = hex of the enum value
               ("CAPTURE_DEVICE" / "AI_GENERATOR"), accepted by the subject.
               Revoked = CredentialDelete -> `credential_type` returns None.

Phase 2 (details and memo formats: docs/interfaces.md § Phase 2):
- anonymous anchor : MemoData {"d": digest, "a": 1, "r": registry_root, "h": bundle_hash}
- passkey anchor   : MemoData {"d": digest, "k": device ed25519 pubkey, "w": bundle_hash}
- registry root    : registry -> registry, MemoType "veripress/registry-root/v1",
                     MemoData {"root", "depth", "n"}; the root in force at T = last published before T.
- revocation is NOT retroactive: `credential_type(pk, at_time)` answers for the instant `at_time`.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, replace
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
    timestamp: int  # unix seconds (ledger close time; submission time while not validated)
    explorer_url: str
    # Phase 2 (defaults keep phase-1 code working)
    validated: bool = True  # False while the tx is not validated yet (fast anchoring)
    anonymous: bool = False
    registry_root: str = ""  # anonymous mode: registry root used by the proof
    bundle_hash: str = ""  # anonymous / passkey: sha256 hex of the proof bundle kept in store/
    cid: str = ""  # option: IPFS CID of the disclosure
    batch_size: int = 0  # > 0: a batch anchor (digest = Merkle root of `batch_size` records)


class Ledger(Protocol):
    def anchor(self, digest: str, signature: str, pubkey: str, wait: bool = True) -> Anchor:
        """Submit the anchor tx. wait=True: return once validated; wait=False: return right
        after submission with validated=False (fast anchoring)."""
        ...

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        """Anonymous anchor: no device key nor signature on chain, only the digest, the registry
        root the ZK proof was made against and the hash of the stored proof bundle."""
        ...

    def anchor_passkey(self, digest: str, pubkey: str, bundle_hash: str, wait: bool = True) -> Anchor:
        """Passkey anchor: memo {"d", "k": device Ed25519 pubkey, "w": bundle_hash}, no "s".
        The P-256 WebAuthn assertion over the digest is in the stored bundle; the device's
        Credential URI attests the passkey (credential_passkey). Anchor.signature = ""."""
        ...

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        """Read back an anchor tx (also when not validated yet: validated=False).
        None if not found / not a veripress memo."""
        ...

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        """Credential of the key's account valid AT `at_time` (accepted before, not deleted yet,
        not expired then). Pass the anchor time: revocation is not retroactive.
        at_time=None = current state."""
        ...

    def credential_revoked_at(self, pubkey: str) -> int | None:
        """Unix time of the CredentialDelete that ended the key's credential, if it is
        currently revoked; None if it is valid now or was never issued."""
        ...

    def credential_passkey(self, pubkey: str) -> str | None:
        """sha256 hex of the P-256 passkey public key attested in the URI of the key's
        CAPTURE_DEVICE credential ("passkey:sha256:<hex>"), or None."""
        ...

    def registry_root_at(self, at_time: int) -> str | None:
        """Root of the anonymous device registry in force at `at_time` (last one published
        by the registry before that instant), or None."""
        ...

    def anchor_batch(self, root: str, count: int, wait: bool = True) -> Anchor:
        """Aggregated anchoring: one tx for the Merkle root of `count` records (memo {"b", "n"})."""
        ...

    def latest_validated(self) -> tuple[int, str, int]:
        """(ledger_index, ledger_hash, close_time unix) of the latest validated ledger — T0 lower
        bound: a ledger hash cannot be known before that ledger closes."""
        ...

    def ledger_close_time(self, ledger_index: int, ledger_hash: str) -> int | None:
        """Close time of validated ledger `ledger_index` if its hash is `ledger_hash`, else None."""
        ...


class FakeLedger:
    """In-memory ledger for tests and offline dev."""

    def __init__(self) -> None:
        self.anchors: dict[str, Anchor] = {}
        self.credentials: dict[str, CredentialType] = {}
        self.revoked_at: dict[str, int] = {}
        self.passkeys: dict[str, str] = {}
        self.registry_roots: list[tuple[int, str]] = []  # (published at, root), in order
        self.ledgers: dict[int, tuple[str, int]] = {}  # index -> (hash, close time)

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
        return self._store(Anchor(h, digest, signature, pubkey, int(time.time()), f"fake://tx/{h}", validated=wait))

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        h = self._tx_hash(digest, bundle_hash)
        return self._store(Anchor(h, digest, "", "", int(time.time()), f"fake://tx/{h}", validated=wait,
                                  anonymous=True, registry_root=registry_root, bundle_hash=bundle_hash))

    def anchor_passkey(self, digest: str, pubkey: str, bundle_hash: str, wait: bool = True) -> Anchor:
        # Kept aligned with XrplLedger.anchor_passkey by Dev B (team-rules: FakeLedger alignment).
        h = self._tx_hash(digest, bundle_hash)
        return self._store(Anchor(h, digest, "", pubkey, int(time.time()), f"fake://tx/{h}", validated=wait,
                                  bundle_hash=bundle_hash))

    def anchor_batch(self, root: str, count: int, wait: bool = True) -> Anchor:
        h = self._tx_hash(root, str(count))
        return self._store(Anchor(h, root, "", "", int(time.time()), f"fake://tx/{h}", validated=wait,
                                  batch_size=count))

    def validate(self, tx_hash: str) -> None:
        """Tests: the submitted tx makes it into a validated ledger."""
        from dataclasses import replace

        self.anchors[tx_hash] = replace(self.anchors[tx_hash], validated=True)

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

    def _ledger(self) -> tuple[int, str, int]:
        """Fake ledger sequence: one ledger per anchor, starting at 1000."""
        index = 1000 + len(self.anchors)
        if index not in self.ledgers:
            h = hashlib.sha256(f"fake-ledger-{index}".encode()).hexdigest().upper()
            self.ledgers[index] = (h, int(time.time()))
        return index, *self.ledgers[index]

    def latest_validated(self) -> tuple[int, str, int]:
        return self._ledger()

    def ledger_close_time(self, ledger_index: int, ledger_hash: str) -> int | None:
        h, t = self.ledgers.get(ledger_index, (None, None))
        return t if h is not None and h == ledger_hash.upper() else None


MEMO_TYPE = "veripress/v1"
REGISTRY_ROOT_MEMO_TYPE = "veripress/registry-root/v1"
LSF_ACCEPTED = 0x00010000
DEFAULT_NODE = "https://s.altnet.rippletest.net:51234"
EXPLORER = "https://testnet.xrpl.org/transactions/"


class XrplLedger:
    """Real implementation on XRPL Testnet.

    Config: env VERIPRESS_XRPL_URL (default Testnet JSON-RPC), VERIPRESS_KEYS (default
    backend/keys). Needs keys/anchor.json (payer) and keys/registry.json (issuer + destination),
    written by scripts/setup_testnet.py.
    """

    def __init__(self, node_url: str | None = None, keys_dir: str | Path | None = None) -> None:
        from xrpl.clients import JsonRpcClient
        from xrpl.wallet import Wallet

        keys = Path(keys_dir or os.environ.get("VERIPRESS_KEYS") or Path(__file__).resolve().parents[2] / "keys")
        self.client = JsonRpcClient(node_url or os.environ.get("VERIPRESS_XRPL_URL") or DEFAULT_NODE)
        self.registry = json.loads((keys / "registry.json").read_text())["address"]
        self.wallet = Wallet.from_seed(json.loads((keys / "anchor.json").read_text())["seed"])
        self._history_cache: dict[str, tuple[float, list[dict]]] = {}
        self._pending: dict[str, tuple[float, Anchor]] = {}  # fast anchors not validated yet
        self._submit_lock = threading.Lock()
        self._last_sequence: int | None = None
        self._fee: tuple[float, str] | None = None  # (fetched at, drops)

    def _request(self, req):
        """Read-only request with one retry: the public Testnet node sometimes drops a
        connection (ConnectTimeout seen during tests). Never used for submissions, where a
        retry could anchor twice."""
        try:
            return self.client.request(req)
        except Exception:  # noqa: BLE001 — httpx / websockets transport errors
            time.sleep(0.5)
            return self.client.request(req)

    def _history(self, address: str) -> list[dict]:
        """Validated account history, oldest first. Cached HISTORY_TTL seconds: enough to
        share one download between the calls of a single verification, short enough for a
        revocation made during the demo to show up at once."""
        from xrpl.models.requests import AccountTx

        hit = self._history_cache.get(address)
        if hit and time.monotonic() - hit[0] < HISTORY_TTL:
            return hit[1]
        entries: list[dict] = []
        marker = None
        while True:
            resp = self._request(AccountTx(account=address, forward=True, limit=200, marker=marker))
            if not resp.is_successful():
                if resp.result.get("error") == "actNotFound":  # never funded: no history
                    break
                raise RuntimeError(f"XRPL account history unavailable: {resp.result.get('error')}")
            entries += resp.result.get("transactions", [])
            marker = resp.result.get("marker")
            if not marker:
                break
        self._history_cache[address] = (time.monotonic(), entries)
        return entries

    def _submit_anchor(self, data: dict, wait: bool = True) -> tuple[str, int, bool]:
        """Payment of 1 drop anchoring service -> registry carrying one veripress/v1 memo.
        Returns (tx hash, time, validated). wait=True: ledger close time once validated.
        wait=False (fast anchoring): returns right after submission (submission time,
        validated=False) if the node provisionally accepted it."""
        from xrpl.models.transactions import Memo, Payment
        from xrpl.transaction import autofill, sign, submit, submit_and_wait
        from xrpl.utils import str_to_hex

        tx = Payment(
            account=self.wallet.address,
            destination=self.registry,
            amount="1",
            memos=[Memo(memo_type=str_to_hex(MEMO_TYPE), memo_data=str_to_hex(_compact(data)))],
        )
        # One submission at a time, with a locally tracked Sequence: two quick signatures must
        # not both get the sequence the (load-balanced) node reports, or the second fails.
        # Sequence and fee are filled from local state when known: each lookup on the public
        # node costs ~1 s (xrpl-py's JSON-RPC client opens a new TLS connection per request).
        with self._submit_lock:
            known = {}
            if self._last_sequence is not None:
                known["sequence"] = self._last_sequence + 1
            if self._fee and time.monotonic() - self._fee[0] < FEE_TTL:
                known["fee"] = self._fee[1]
            if known:
                tx = Payment.from_dict({**tx.to_dict(), **known})
            try:
                tx = autofill(tx, self.client)  # only what is still missing (LastLedgerSequence…)
                self._fee = (time.monotonic(), tx.fee) if "fee" not in known else self._fee
                signed = sign(tx, self.wallet)
                if wait:
                    resp = submit_and_wait(signed, self.client)
                    code = resp.result.get("meta", {}).get("TransactionResult")
                    if code != "tesSUCCESS":
                        raise RuntimeError(f"anchor tx failed: {code}")
                    self._last_sequence = signed.sequence
                    return resp.result["hash"], _close_time(resp.result), True
                resp = submit(signed, self.client)
                result = resp.result.get("engine_result", "")
                # tes = applied to the open ledger; ter = queued / retried by the node. Anything
                # else (tec fee claimed, tef / tem / tel) will not anchor: fail now.
                if not (result == "tesSUCCESS" or result.startswith("ter")):
                    raise RuntimeError(f"anchor tx rejected: {result} {resp.result.get('engine_result_message', '')}")
                self._last_sequence = signed.sequence
                return signed.get_hash(), int(time.time()), False
            except Exception:
                # Resynchronise sequence and fee from the network on the next submission.
                self._last_sequence, self._fee = None, None
                raise

    def _remember(self, a: Anchor) -> Anchor:
        """Fast anchors are kept locally until validated: right after submission the public
        node pool may not know the tx yet, and verifying it must say 'pending', not 'unknown'."""
        if not a.validated:
            self._pending[a.tx_hash] = (time.monotonic(), a)
        return a

    def anchor(self, digest: str, signature: str, pubkey: str, wait: bool = True) -> Anchor:
        tx_hash, ts, ok = self._submit_anchor({"d": digest, "s": signature, "k": pubkey}, wait)
        return self._remember(Anchor(tx_hash, digest, signature, pubkey, ts, EXPLORER + tx_hash, validated=ok))

    def anchor_anonymous(self, digest: str, registry_root: str, bundle_hash: str, wait: bool = True) -> Anchor:
        """No device key nor signature on chain: the ZK proof (kept off-chain, its sha256 in
        "h") shows that SOME device of the registry root "r" signed the digest."""
        tx_hash, ts, ok = self._submit_anchor({"d": digest, "a": 1, "r": registry_root, "h": bundle_hash}, wait)
        return self._remember(Anchor(tx_hash, digest, "", "", ts, EXPLORER + tx_hash, validated=ok,
                                     anonymous=True, registry_root=registry_root, bundle_hash=bundle_hash))

    def anchor_passkey(self, digest: str, pubkey: str, bundle_hash: str, wait: bool = True) -> Anchor:
        tx_hash, ts, ok = self._submit_anchor({"d": digest, "k": pubkey, "w": bundle_hash}, wait)
        return self._remember(Anchor(tx_hash, digest, "", pubkey, ts, EXPLORER + tx_hash, validated=ok,
                                     bundle_hash=bundle_hash))

    def fetch_anchor(self, tx_hash: str) -> Anchor | None:
        from xrpl.models.requests import Tx

        tx_hash = tx_hash.upper()
        resp = self._request(Tx(transaction=tx_hash))
        if not resp.is_successful():  # txnNotFound: maybe submitted a moment ago
            hit = self._pending.get(tx_hash)
            if hit and time.monotonic() - hit[0] < PENDING_TTL:
                return hit[1]
            self._pending.pop(tx_hash, None)
            return None
        r = resp.result
        tx = r.get("tx_json", r)  # API v2 nests fields under tx_json
        validated = bool(r.get("validated"))
        if (
            tx.get("TransactionType") != "Payment"
            or tx.get("Destination") != self.registry
            or (validated and r.get("meta", {}).get("TransactionResult") != "tesSUCCESS")
        ):
            self._pending.pop(tx_hash, None)
            return None
        data = _memo_json(tx, MEMO_TYPE)
        if data is None:
            return None
        if validated:
            self._pending.pop(tx_hash, None)
            return _anchor_from_memo(data, r.get("hash", tx_hash).upper(), _close_time(r))
        hit = self._pending.get(tx_hash)
        submitted = hit[1].timestamp if hit else int(time.time())
        a = _anchor_from_memo(data, r.get("hash", tx_hash).upper(), submitted)
        return None if a is None else replace(a, validated=False)

    def registry_root_at(self, at_time: int) -> str | None:
        """Last root the registry published (AccountSet + veripress/registry-root/v1 memo)
        at or before `at_time`: a proof is accepted only against the root in force when the
        photo was anchored, so revoking a device (new root without it) is not retroactive."""
        root = None
        for e in self._history(self.registry):  # oldest first
            tx = e.get("tx_json") or e.get("tx") or {}
            if (
                not e.get("validated", False)
                or e.get("meta", {}).get("TransactionResult") != "tesSUCCESS"
                or tx.get("Account") != self.registry
            ):
                continue
            data = _memo_json(tx, REGISTRY_ROOT_MEMO_TYPE)
            if not data or "root" not in data:
                continue
            if _close_time(e) > at_time:
                break
            root = str(data["root"])
        return root

    def credential_type(self, pubkey: str, at_time: int | None = None) -> CredentialType | None:
        from xrpl.core.keypairs import derive_classic_address
        from xrpl.models.requests import LedgerEntry
        from xrpl.models.requests.ledger_entry import Credential
        from xrpl.utils import posix_to_ripple_time, str_to_hex

        try:
            subject = derive_classic_address(pubkey)
        except Exception:
            return None
        if at_time is not None:
            # Non-retroactive: was the credential valid at that instant? (account history)
            for ctype, intervals in self._intervals(subject).items():
                if any(_valid_at(iv, at_time) for iv in intervals):
                    return ctype
            return None
        now = posix_to_ripple_time(int(time.time()))
        for ctype in CredentialType:
            resp = self._request(
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

    def _intervals(self, subject: str) -> dict[CredentialType, list[Interval]]:
        """Validity intervals of each credential type issued by the registry to `subject`.
        Read from the SUBJECT's history: the Credential object sits in both the issuer's and
        the subject's owner directories, so every Create/Accept/Delete shows up there too,
        without the hundreds of anchor payments that pile up on the registry account."""
        from xrpl.utils import str_to_hex

        entries = self._history(subject)
        return {
            ctype: _credential_intervals(entries, subject, self.registry, str_to_hex(ctype.value))
            for ctype in CredentialType
        }

    def credential_revoked_at(self, pubkey: str) -> int | None:
        from xrpl.core.keypairs import derive_classic_address

        try:
            subject = derive_classic_address(pubkey)
        except Exception:
            return None
        return _revoked_at(self._intervals(subject).values(), int(time.time()))

    # --- Phase 2: implemented by a later Dev B feature PR (task 6 in tasks-dev-b.md) ---

    def credential_passkey(self, pubkey: str) -> str | None:
        """Passkey hash the registry attested in the URI of the device's CAPTURE_DEVICE
        credential (current state: an assertion is checked against the device as it is now)."""
        from xrpl.core.keypairs import derive_classic_address
        from xrpl.models.requests import LedgerEntry
        from xrpl.models.requests.ledger_entry import Credential
        from xrpl.utils import str_to_hex

        try:
            subject = derive_classic_address(pubkey)
        except Exception:
            return None
        resp = self._request(
            LedgerEntry(
                credential=Credential(
                    subject=subject, issuer=self.registry,
                    credential_type=str_to_hex(CredentialType.CAPTURE_DEVICE.value),
                ),
                ledger_index="validated",
            )
        )
        if not resp.is_successful():
            return None
        node = resp.result["node"]
        if not node.get("Flags", 0) & LSF_ACCEPTED:
            return None
        return _passkey_from_uri(node.get("URI", ""))


PASSKEY_URI_PREFIX = "passkey:sha256:"


def passkey_uri(passkey_sha256: str) -> str:
    """Credential URI attesting a passkey (docs/interfaces.md)."""
    return PASSKEY_URI_PREFIX + passkey_sha256.lower()


def _passkey_from_uri(uri_hex: str) -> str | None:
    from xrpl.utils import hex_to_str

    try:
        uri = hex_to_str(uri_hex)
    except (ValueError, UnicodeDecodeError):
        return None
    if not uri.startswith(PASSKEY_URI_PREFIX):
        return None
    h = uri[len(PASSKEY_URI_PREFIX):].lower()
    return h if len(h) == 64 and all(c in "0123456789abcdef" for c in h) else None


def _compact(data: dict) -> str:
    return json.dumps(data, separators=(",", ":"))


def _memo_json(tx: dict, memo_type: str) -> dict | None:
    """JSON payload of the first memo of `memo_type` in a tx, or None."""
    from xrpl.utils import hex_to_str

    for m in tx.get("Memos", []):
        memo = m.get("Memo", {})
        try:
            if hex_to_str(memo.get("MemoType", "")) != memo_type:
                continue
            data = json.loads(hex_to_str(memo["MemoData"]))
        except (KeyError, ValueError, UnicodeDecodeError):
            continue
        if isinstance(data, dict):
            return data
    return None


def _anchor_from_memo(data: dict, tx_hash: str, timestamp: int) -> Anchor | None:
    """The three veripress/v1 memo shapes (docs/interfaces.md):
    named {"d","s","k"} · anonymous {"d","a":1,"r","h"} · passkey {"d","k","w"}."""
    url = EXPLORER + tx_hash
    try:
        digest = str(data["d"])
        if data.get("a") == 1:
            return Anchor(tx_hash, digest, "", "", timestamp, url, anonymous=True,
                          registry_root=str(data["r"]), bundle_hash=str(data["h"]))
        if "w" in data:
            return Anchor(tx_hash, digest, "", str(data["k"]), timestamp, url, bundle_hash=str(data["w"]))
        return Anchor(tx_hash, digest, str(data["s"]), str(data["k"]), timestamp, url)
    except KeyError:
        return None


HISTORY_TTL = 3.0  # seconds
PENDING_TTL = 120.0  # seconds a fast anchor is trusted locally while the network does not know it yet
FEE_TTL = 60.0  # seconds a fetched network fee is reused

# (start, end, expiration): valid on [start, end) and before expiration; end/expiration None = open.
Interval = tuple[int, int | None, int | None]


def _credential_intervals(entries: list[dict], subject: str, issuer: str, ctype_hex: str) -> list[Interval]:
    """Validity intervals of one credential (subject, issuer, type) from a chronological account
    history (account_tx entries, API v1 or v2). A credential counts from its CredentialAccept
    (an unaccepted credential is not valid) until its CredentialDelete; a later
    CredentialCreate + CredentialAccept opens a new interval. Only validated, successful txs."""
    from xrpl.utils import ripple_time_to_posix

    out: list[Interval] = []
    created = False
    start: int | None = None
    expiration: int | None = None
    for e in entries:
        tx = e.get("tx_json") or e.get("tx") or {}
        if not e.get("validated", False) or e.get("meta", {}).get("TransactionResult") != "tesSUCCESS":
            continue
        if str(tx.get("CredentialType", "")).upper() != ctype_hex.upper():
            continue
        kind, account = tx.get("TransactionType"), tx.get("Account")
        if kind == "CredentialCreate" and account == issuer and tx.get("Subject") == subject:
            created = True
            expiration = ripple_time_to_posix(tx["Expiration"]) if "Expiration" in tx else None
        elif kind == "CredentialAccept" and account == subject and tx.get("Issuer") == issuer and created:
            start = _close_time(e)
        elif kind == "CredentialDelete" and tx.get("Subject", account) == subject and tx.get("Issuer", account) == issuer:
            # Either side may delete; Subject / Issuer default to the sending account.
            if start is not None:
                out.append((start, _close_time(e), expiration))
            created, start, expiration = False, None, None
    if start is not None:
        out.append((start, None, expiration))
    return out


def _valid_at(interval: Interval, t: int) -> bool:
    start, end, expiration = interval
    return start <= t and (end is None or t < end) and (expiration is None or t < expiration)


def _revoked_at(intervals_by_type, now: int) -> int | None:
    """Time of the CredentialDelete that ended the most recent credential, if no credential is
    valid now. An expired (but not deleted) credential is not a revocation: None."""
    latest = [ivs[-1] for ivs in intervals_by_type if ivs]
    if not latest or any(_valid_at(iv, now) for iv in latest):
        return None
    ends = [iv[1] for iv in latest if iv[1] is not None]
    return max(ends) if ends else None

    # --- Aggregated anchoring — TODO Dev B (memo {"b": root, "n": count}; fetch_anchor -> batch_size) ---

    def anchor_batch(self, root: str, count: int, wait: bool = True) -> Anchor:
        raise NotImplementedError("Dev B: Payment memo {\"b\": root, \"n\": count}")

    # --- T0 lower bound (after the track slides) — TODO Dev B ---

    def latest_validated(self) -> tuple[int, str, int]:
        raise NotImplementedError("Dev B: `ledger` request, ledger_index='validated'")

    def ledger_close_time(self, ledger_index: int, ledger_hash: str) -> int | None:
        raise NotImplementedError("Dev B: `ledger` request at ledger_index, compare ledger_hash")


def _close_time(result: dict) -> int:
    """Ledger close time (unix seconds) from a tx / submit_and_wait result."""
    from xrpl.utils import ripple_time_to_posix

    tx = result.get("tx_json", result)
    if "date" in tx:
        return ripple_time_to_posix(tx["date"])
    if "close_time_iso" in result:
        return int(datetime.fromisoformat(result["close_time_iso"].replace("Z", "+00:00")).timestamp())
    return int(time.time())
