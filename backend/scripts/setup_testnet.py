"""XRPL Testnet setup — OWNER: Dev B.

Creates (via the Testnet faucet) the demo accounts, issues and accepts the Credentials,
writes keys/*.json (format: docs/interfaces.md), and maintains the anonymous device registry
(phase 2): a Baby Jubjub key per device, ~20 fictitious devices, keys/registry_devices.json,
and its Poseidon root published on XRPL. Safe to re-run after a Testnet reset.

    uv run python scripts/setup_testnet.py              # create everything (skips existing keys)
    uv run python scripts/setup_testnet.py --fresh      # ignore existing keys, new accounts
    uv run python scripts/setup_testnet.py --revoke device   # CredentialDelete + new registry root without it
    uv run python scripts/setup_testnet.py --reissue device  # re-issue + new registry root with it
    uv run python scripts/setup_testnet.py --passkey         # registry attests keys/passkey.json (Touch ID)

The registry follows the credentials: the real device is in the tree iff its CAPTURE_DEVICE
credential is accepted, so --revoke / --reissue republish the right root by themselves.
Needs Node >= 20 and `cd zk && npm ci` for the ZK part.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.core.keypairs import derive_keypair
from xrpl.models.requests import AccountInfo, LedgerEntry
from xrpl.models.requests.ledger_entry import Credential
from xrpl.models.transactions import AccountSet, CredentialAccept, CredentialCreate, CredentialDelete, Memo
from xrpl.transaction import submit_and_wait
from xrpl.utils import str_to_hex
from xrpl.wallet import Wallet, generate_faucet_wallet

from veripress import zk
from veripress.ledger import REGISTRY_ROOT_MEMO_TYPE, XrplLedger, passkey_uri

NODE_URL = "https://s.altnet.rippletest.net:51234"
KEYS = Path(__file__).resolve().parent.parent / "keys"
SUBJECTS = {"device": "CAPTURE_DEVICE", "ai": "AI_GENERATOR"}
LSF_ACCEPTED = 0x00010000
N_FAKE_DEVICES = 20  # anonymity set of the demo registry (decisions.md Q14)


def log(msg: str) -> None:
    print(msg, flush=True)


def account_exists(client: JsonRpcClient, address: str) -> bool:
    return client.request(AccountInfo(account=address, ledger_index="validated")).is_successful()


def load_or_create(client: JsonRpcClient, name: str, algo: CryptoAlgorithm, fresh: bool) -> Wallet:
    path = KEYS / f"{name}.json"
    if path.exists() and not fresh:
        data = json.loads(path.read_text())
        wallet = Wallet.from_seed(data["seed"], algorithm=algo)
        if account_exists(client, wallet.address):
            log(f"  {name:8} {wallet.address}  (existing)")
            return wallet
        log(f"  {name:8} {wallet.address} not on ledger (Testnet reset?) -> new account")
    wallet = generate_faucet_wallet(client, Wallet.create(algorithm=algo))
    data = {"seed": wallet.seed, "address": wallet.address}
    if algo is CryptoAlgorithm.ED25519:
        pub, priv = derive_keypair(wallet.seed, algorithm=algo)
        data |= {"public_key": pub, "private_key": priv}
    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)
    log(f"  {name:8} {wallet.address}  (funded by faucet)")
    return wallet


def credential_state(client: JsonRpcClient, subject: str, issuer: str, ctype: str) -> str:
    """'missing' | 'pending' | 'accepted'"""
    resp = client.request(
        LedgerEntry(
            credential=Credential(subject=subject, issuer=issuer, credential_type=str_to_hex(ctype)),
            ledger_index="validated",
        )
    )
    if not resp.is_successful():
        return "missing"
    return "accepted" if resp.result["node"].get("Flags", 0) & LSF_ACCEPTED else "pending"


def submit(client: JsonRpcClient, tx, wallet: Wallet, label: str) -> None:
    resp = submit_and_wait(tx, client, wallet)
    code = resp.result["meta"]["TransactionResult"]
    log(f"    {label}: {code}  https://testnet.xrpl.org/transactions/{resp.result['hash']}")
    if code != "tesSUCCESS":
        sys.exit(f"{label} failed: {code}")


def device_passkey_uri(ctype: str) -> str | None:
    """URI of the device credential: the attested passkey survives --revoke / --reissue."""
    path = KEYS / "passkey.json"
    if ctype != SUBJECTS["device"] or not path.exists():
        return None
    data = json.loads(path.read_text())
    return passkey_uri(data["sha256"]) if data.get("attested") else None


def issue(client: JsonRpcClient, registry: Wallet, subject: Wallet, ctype: str) -> None:
    state = credential_state(client, subject.address, registry.address, ctype)
    if state == "missing":
        uri = device_passkey_uri(ctype)
        tx = CredentialCreate(
            account=registry.address, subject=subject.address, credential_type=str_to_hex(ctype),
            uri=str_to_hex(uri) if uri else None,
        )
        submit(client, tx, registry, f"CredentialCreate {ctype}" + (" (passkey attested)" if uri else ""))
        state = "pending"
    if state == "pending":
        tx = CredentialAccept(account=subject.address, issuer=registry.address, credential_type=str_to_hex(ctype))
        submit(client, tx, subject, f"CredentialAccept {ctype}")
    else:
        log(f"    {ctype}: already accepted")


def load(name: str, algo: CryptoAlgorithm) -> Wallet:
    return Wallet.from_seed(json.loads((KEYS / f"{name}.json").read_text())["seed"], algorithm=algo)


# --- anonymous device registry (phase 2, decisions.md Q2-Q4, Q14-Q15) ------------------------

def write_secret(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2))
    path.chmod(0o600)


def ensure_bjj(name: str) -> list[str]:
    """Baby Jubjub key of a subject (keys/<name>.json["bjj"]), created once. The AI key gets
    one too (contract), but only CAPTURE_DEVICE keys ever enter the registry."""
    path = KEYS / f"{name}.json"
    data = json.loads(path.read_text())
    if "bjj" not in data:
        data["bjj"] = zk.keygen()
        write_secret(path, data)
        log(f"  {name:8} Baby Jubjub key created")
    return [str(c) for c in data["bjj"]["pk"]]


def fake_devices() -> list[list[str]]:
    """Public keys of the fictitious devices (their secret keys are thrown away)."""
    path = KEYS / "registry_fakes.json"
    if path.exists():
        return json.loads(path.read_text())["pks"]
    pks = [[str(c) for c in zk.keygen()["pk"]] for _ in range(N_FAKE_DEVICES)]
    write_secret(path, {"pks": pks})
    log(f"  {N_FAKE_DEVICES} fictitious devices created")
    return pks


def publish_registry_root(client: JsonRpcClient, registry: Wallet, root: str, n: int) -> None:
    """AccountSet (no flag changed) carrying the memo: XRPL rejects a Payment to oneself, and
    a no-op AccountSet is the usual way for an account to write a note on its own history."""
    data = json.dumps({"root": root, "depth": zk.DEPTH, "n": n}, separators=(",", ":"))
    tx = AccountSet(
        account=registry.address,
        memos=[Memo(memo_type=str_to_hex(REGISTRY_ROOT_MEMO_TYPE), memo_data=str_to_hex(data))],
    )
    submit(client, tx, registry, f"registry root ({n} devices)")


def sync_registry(client: JsonRpcClient, registry: Wallet) -> None:
    """Rebuild keys/registry_devices.json from the credentials and publish its root if it is
    not the one currently in force. The real device sits at a fixed pseudo-random position."""
    import time

    device_pk = ensure_bjj("device")
    ensure_bjj("ai")
    pks = list(fake_devices())
    device = load("device", CryptoAlgorithm.ED25519)
    member = credential_state(client, device.address, registry.address, SUBJECTS["device"]) == "accepted"
    if member:
        pos = int(hashlib.sha256("".join(device_pk).encode()).hexdigest(), 16) % (len(pks) + 1)
        pks.insert(pos, device_pk)
    write_secret(KEYS / "registry_devices.json", {"pks": pks})
    root = zk.root(pks)
    current = XrplLedger(node_url=NODE_URL, keys_dir=KEYS).registry_root_at(int(time.time()) + 60)
    log(f"  registry: {len(pks)} devices, real device {'IN' if member else 'OUT'}, root {root[:16]}…")
    if current == root:
        log("  root already in force on XRPL")
    else:
        publish_registry_root(client, registry, root, len(pks))


def attest_passkey(client: JsonRpcClient) -> None:
    """The registry attests the device's passkey (decisions.md Q21): re-issue the device's
    CAPTURE_DEVICE credential with URI "passkey:sha256:<hex>". XRPL cannot edit a credential's
    URI, so it is deleted and re-created; photos anchored before keep verifying (revocation is
    not retroactive). keys/passkey.json is written by the page (localhost only)."""
    path = KEYS / "passkey.json"
    if not path.exists():
        sys.exit("no keys/passkey.json: register the passkey first (page, on localhost)")
    data = json.loads(path.read_text())
    registry = load("registry", CryptoAlgorithm.SECP256K1)
    device = load("device", CryptoAlgorithm.ED25519)
    ctype = SUBJECTS["device"]
    device_pk = json.loads((KEYS / "device.json").read_text())["public_key"]
    current = XrplLedger(node_url=NODE_URL, keys_dir=KEYS).credential_passkey(device_pk)
    log(f"Passkey sha256 {data['sha256'][:16]}…")
    if current == data["sha256"]:
        log("  already attested in the device credential")
    else:
        if credential_state(client, device.address, registry.address, ctype) != "missing":
            tx = CredentialDelete(account=registry.address, subject=device.address, credential_type=str_to_hex(ctype))
            submit(client, tx, registry, f"CredentialDelete {ctype} (to re-issue with the passkey)")
        write_secret(path, {**data, "attested": True})
        issue(client, registry, device, ctype)
    write_secret(path, {**data, "attested": True})
    log("Anonymous registry:")
    sync_registry(client, registry)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fresh", action="store_true", help="create new accounts even if keys/ exists")
    p.add_argument("--revoke", choices=SUBJECTS, help="delete the credential of this subject")
    p.add_argument("--reissue", choices=SUBJECTS, help="re-issue the credential of this subject")
    p.add_argument("--passkey", action="store_true",
                   help="attest the passkey saved in keys/passkey.json in the device credential URI")
    args = p.parse_args()

    KEYS.mkdir(exist_ok=True)
    client = JsonRpcClient(NODE_URL)

    if args.passkey:
        attest_passkey(client)
        return

    if args.revoke or args.reissue:
        registry = load("registry", CryptoAlgorithm.SECP256K1)
        name = args.revoke or args.reissue
        subject = load(name, CryptoAlgorithm.ED25519)
        ctype = SUBJECTS[name]
        if args.reissue:
            issue(client, registry, subject, ctype)
        elif credential_state(client, subject.address, registry.address, ctype) == "missing":
            log(f"{ctype} of {name} already absent")
        else:
            tx = CredentialDelete(account=registry.address, subject=subject.address, credential_type=str_to_hex(ctype))
            submit(client, tx, registry, f"CredentialDelete {ctype}")
        if name == "device":
            log("Anonymous registry:")
            sync_registry(client, registry)
        return

    log("Accounts:")
    registry = load_or_create(client, "registry", CryptoAlgorithm.SECP256K1, args.fresh)
    load_or_create(client, "anchor", CryptoAlgorithm.SECP256K1, args.fresh)
    subjects = {n: load_or_create(client, n, CryptoAlgorithm.ED25519, args.fresh) for n in SUBJECTS}

    log("Credentials:")
    for name, ctype in SUBJECTS.items():
        issue(client, registry, subjects[name], ctype)
    log("Anonymous registry:")
    if args.fresh:
        (KEYS / "registry_fakes.json").unlink(missing_ok=True)
    sync_registry(client, registry)
    log(f"Done. Keys in {KEYS}")


if __name__ == "__main__":
    main()
