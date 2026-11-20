"""XRPL Testnet setup — OWNER: Dev B.

Creates (via the Testnet faucet) the demo accounts, issues and accepts the Credentials,
and writes keys/*.json (format: docs/interfaces.md). Safe to re-run after a Testnet reset.

    uv run python scripts/setup_testnet.py              # create everything (skips existing keys)
    uv run python scripts/setup_testnet.py --fresh      # ignore existing keys, new accounts
    uv run python scripts/setup_testnet.py --revoke device   # CredentialDelete (demo revocation)
    uv run python scripts/setup_testnet.py --reissue device  # re-issue after a revocation
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from xrpl.clients import JsonRpcClient
from xrpl.constants import CryptoAlgorithm
from xrpl.core.keypairs import derive_keypair
from xrpl.models.requests import AccountInfo, LedgerEntry
from xrpl.models.requests.ledger_entry import Credential
from xrpl.models.transactions import CredentialAccept, CredentialCreate, CredentialDelete
from xrpl.transaction import submit_and_wait
from xrpl.utils import str_to_hex
from xrpl.wallet import Wallet, generate_faucet_wallet

NODE_URL = "https://s.altnet.rippletest.net:51234"
KEYS = Path(__file__).resolve().parent.parent / "keys"
SUBJECTS = {"device": "CAPTURE_DEVICE", "ai": "AI_GENERATOR"}
LSF_ACCEPTED = 0x00010000


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


def issue(client: JsonRpcClient, registry: Wallet, subject: Wallet, ctype: str) -> None:
    state = credential_state(client, subject.address, registry.address, ctype)
    if state == "missing":
        tx = CredentialCreate(account=registry.address, subject=subject.address, credential_type=str_to_hex(ctype))
        submit(client, tx, registry, f"CredentialCreate {ctype}")
        state = "pending"
    if state == "pending":
        tx = CredentialAccept(account=subject.address, issuer=registry.address, credential_type=str_to_hex(ctype))
        submit(client, tx, subject, f"CredentialAccept {ctype}")
    else:
        log(f"    {ctype}: already accepted")


def load(name: str, algo: CryptoAlgorithm) -> Wallet:
    return Wallet.from_seed(json.loads((KEYS / f"{name}.json").read_text())["seed"], algorithm=algo)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--fresh", action="store_true", help="create new accounts even if keys/ exists")
    p.add_argument("--revoke", choices=SUBJECTS, help="delete the credential of this subject")
    p.add_argument("--reissue", choices=SUBJECTS, help="re-issue the credential of this subject")
    args = p.parse_args()

    KEYS.mkdir(exist_ok=True)
    client = JsonRpcClient(NODE_URL)

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
        return

    log("Accounts:")
    registry = load_or_create(client, "registry", CryptoAlgorithm.SECP256K1, args.fresh)
    load_or_create(client, "anchor", CryptoAlgorithm.SECP256K1, args.fresh)
    subjects = {n: load_or_create(client, n, CryptoAlgorithm.ED25519, args.fresh) for n in SUBJECTS}

    log("Credentials:")
    for name, ctype in SUBJECTS.items():
        issue(client, registry, subjects[name], ctype)
    log(f"Done. Keys in {KEYS}")


if __name__ == "__main__":
    main()
