"""Smoke test for XrplLedger on Testnet — OWNER: Dev B.

Skipped unless keys/ exists (run scripts/setup_testnet.py) and VERIPRESS_NET=1.
    VERIPRESS_NET=1 uv run python -m pytest tests/test_ledger_xrpl.py -s
"""

import json
import os
from pathlib import Path

import pytest

from veripress.ledger import CredentialType, XrplLedger

KEYS = Path(__file__).resolve().parent.parent / "keys"
pytestmark = pytest.mark.skipif(
    os.environ.get("VERIPRESS_NET") != "1" or not (KEYS / "anchor.json").exists(),
    reason="network smoke test: set VERIPRESS_NET=1 and run scripts/setup_testnet.py",
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


def test_registry_root_in_force_matches_local_registry():
    """The root published by scripts/setup_testnet.py is the Poseidon root of
    keys/registry_devices.json: anonymous proofs made from that file verify against it."""
    import time

    from veripress import zk

    reg = KEYS / "registry_devices.json"
    if not reg.exists():
        pytest.skip("anonymous registry not set up: run scripts/setup_testnet.py")
    ledger = XrplLedger(keys_dir=KEYS)
    pks = json.loads(reg.read_text())["pks"]
    assert ledger.registry_root_at(int(time.time()) + 60) == zk.root(pks)


def test_fast_anchoring_two_in_a_row():
    """wait=False returns at submission (validated=False); two quick anchors must not collide on
    the account Sequence; both read back as pending at once, then as validated."""
    import time

    ledger = XrplLedger(keys_dir=KEYS)
    device = json.loads((KEYS / "device.json").read_text())["public_key"]
    t0 = time.monotonic()
    a = ledger.anchor("ee" * 32, "ff" * 64, device, wait=False)
    b = ledger.anchor("dd" * 32, "ff" * 64, device, wait=False)
    print(f"\ntwo fast anchors submitted in {time.monotonic() - t0:.1f}s:", a.tx_hash[:12], b.tx_hash[:12])
    assert not a.validated and not b.validated and a.tx_hash != b.tx_hash
    first = ledger.fetch_anchor(a.tx_hash)
    assert first is not None and first.digest == "ee" * 32  # never 'unknown' right after submission
    for _ in range(30):
        fa, fb = ledger.fetch_anchor(a.tx_hash), ledger.fetch_anchor(b.tx_hash)
        if fa and fb and fa.validated and fb.validated:
            break
        time.sleep(1)
    assert fa.validated and fb.validated
    print(f"both validated after {time.monotonic() - t0:.1f}s")


def test_time_window_t0_before_t1():
    """T0 = latest validated ledger before anchoring: a fresh ledger (fresh client, no cache)
    confirms its close time from (index, hash), refuses a forged hash, and T0 <= T1."""
    ledger = XrplLedger(keys_dir=KEYS)
    index, ledger_hash, close = ledger.latest_validated()
    device = json.loads((KEYS / "device.json").read_text())["public_key"]
    anchor = ledger.anchor("cc" * 32, "ff" * 64, device, wait=True)
    fresh = XrplLedger(keys_dir=KEYS)
    assert fresh.ledger_close_time(index, ledger_hash) == close
    assert fresh.ledger_close_time(index, "00" * 32) is None
    assert close <= anchor.timestamp
    print(f"\nT0 ledger {index} closed {close}, anchored {anchor.timestamp} ({anchor.timestamp - close}s window)")


def test_batch_of_three_records_in_one_transaction(tmp_path):
    """BatchingLedger over the real ledger: three records (named, named, anonymous) queued,
    one Payment with memo {"b", "n": 3}; every receipt proves its leaf against the root read
    back from XRPL."""
    from veripress.batching import BatchingLedger, resolve_receipt
    from veripress.store import Store

    base = XrplLedger(keys_dir=KEYS)
    store = Store(tmp_path / "store")
    device = json.loads((KEYS / "device.json").read_text())["public_key"]
    batching = BatchingLedger(base, store)
    batching.anchor("a1" * 32, "ff" * 64, device)
    batching.anchor("b2" * 32, "ff" * 64, device)
    batching.anchor_anonymous("c3" * 32, "1234", "22" * 32)
    tx = batching.flush(wait=True)
    batch = base.fetch_anchor(tx)
    assert batch is not None and batch.batch_size == 3 and batch.validated
    for i, digest in enumerate(("A1" * 32, "B2" * 32, "C3" * 32)):
        anchor, info, err = resolve_receipt(store.get_receipt(digest), base)
        assert err == "" and info == {"tx_hash": tx, "index": i, "size": 3}
        assert anchor.digest.upper() == digest and anchor.timestamp == batch.timestamp
    print(f"\nbatch of 3 anchored in {tx}")
