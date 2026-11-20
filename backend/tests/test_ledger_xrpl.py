"""Smoke test for XrplLedger on Testnet — OWNER: Dev B.

Skipped unless keys/ exists (run scripts/setup_testnet.py) and TILEPROOF_NET=1.
    TILEPROOF_NET=1 uv run python -m pytest tests/test_ledger_xrpl.py -s
"""

import json
import os
from pathlib import Path

import pytest

from tileproof.ledger import CredentialType, XrplLedger

KEYS = Path(__file__).resolve().parent.parent / "keys"
pytestmark = pytest.mark.skipif(
    os.environ.get("TILEPROOF_NET") != "1" or not (KEYS / "anchor.json").exists(),
    reason="network smoke test: set TILEPROOF_NET=1 and run scripts/setup_testnet.py",
)


def test_anchor_roundtrip_and_credentials():
    ledger = XrplLedger(keys_dir=KEYS)
    device = json.loads((KEYS / "device.json").read_text())["public_key"]
    ai = json.loads((KEYS / "ai.json").read_text())["public_key"]

    digest, sig = "ab" * 32, "cd" * 64
    a = ledger.anchor(digest, sig, device)
    print("\nanchor:", a.explorer_url)
    assert a.timestamp > 1_700_000_000

    b = ledger.fetch_anchor(a.tx_hash)
    assert b is not None
    assert (b.digest, b.signature, b.pubkey, b.tx_hash) == (digest, sig, device, a.tx_hash)

    assert ledger.fetch_anchor("00" * 32) is None
    assert ledger.credential_type(device) is CredentialType.CAPTURE_DEVICE
    assert ledger.credential_type(ai) is CredentialType.AI_GENERATOR
    assert ledger.credential_type("ED" + "11" * 32) is None


def test_non_retroactive_revocation_on_real_history():
    """The demo device was revoked and re-issued during the tests: every gap in its history
    must read as 'no credential' at that instant, every interval as CAPTURE_DEVICE."""
    from xrpl.core.keypairs import derive_classic_address

    ledger = XrplLedger(keys_dir=KEYS)
    device = json.loads((KEYS / "device.json").read_text())["public_key"]
    intervals = ledger._intervals(derive_classic_address(device))[CredentialType.CAPTURE_DEVICE]
    assert intervals, "device has no CAPTURE_DEVICE history: run scripts/setup_testnet.py"
    for start, end, _ in intervals:
        assert ledger.credential_type(device, start) is CredentialType.CAPTURE_DEVICE
        if end is not None:
            assert ledger.credential_type(device, end - 1) is CredentialType.CAPTURE_DEVICE
            assert ledger.credential_type(device, end) is None  # revoked from that instant
    assert ledger.credential_type(device, intervals[0][0] - 1) is None  # before the first accept
    # current state and history agree
    now_valid = ledger.credential_type(device) is CredentialType.CAPTURE_DEVICE
    assert (ledger.credential_revoked_at(device) is None) == now_valid
    print(f"\n{len(intervals)} validity interval(s):", intervals)
