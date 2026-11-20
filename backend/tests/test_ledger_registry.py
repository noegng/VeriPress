"""Anonymous registry, ledger side (phase 2 task 1) — OWNER: Dev B.  Offline: memo parsing and
registry_root_at on a synthetic registry history (account_tx API v2 shape)."""

import json

import pytest
from xrpl.utils import posix_to_ripple_time, str_to_hex

from veripress.ledger import (
    MEMO_TYPE,
    REGISTRY_ROOT_MEMO_TYPE,
    XrplLedger,
    _anchor_from_memo,
    _memo_json,
)

REG = "rRegistryXXXXXXXXXXXXXXXXXXXXXXXX"
T0 = 1_795_000_000


def memo(memo_type, data):
    payload = data if isinstance(data, str) else json.dumps(data)
    return {"Memo": {"MemoType": str_to_hex(memo_type), "MemoData": str_to_hex(payload)}}


def entry(t, memos, *, kind="AccountSet", account=REG, ok=True, validated=True):
    return {
        "tx_json": {"TransactionType": kind, "Account": account, "date": posix_to_ripple_time(t), "Memos": memos},
        "meta": {"TransactionResult": "tesSUCCESS" if ok else "tecNO_PERMISSION"},
        "validated": validated,
    }


def root_entry(t, root, **kw):
    return entry(t, [memo(REGISTRY_ROOT_MEMO_TYPE, {"root": root, "depth": 10, "n": 22})], **kw)


# --- memo parsing --------------------------------------------------------------------------

def test_memo_json_picks_the_right_type_and_skips_garbage():
    tx = {"Memos": [memo("other/v1", {"x": 1}), memo(MEMO_TYPE, "not json"), memo(MEMO_TYPE, {"d": "ab"})]}
    assert _memo_json(tx, MEMO_TYPE) == {"d": "ab"}
    assert _memo_json(tx, REGISTRY_ROOT_MEMO_TYPE) is None
    assert _memo_json({}, MEMO_TYPE) is None


def test_three_anchor_shapes():
    named = _anchor_from_memo({"d": "aa", "s": "bb", "k": "ED11"}, "H", T0)
    assert (named.signature, named.pubkey, named.anonymous) == ("bb", "ED11", False)

    anon = _anchor_from_memo({"d": "aa", "a": 1, "r": "123", "h": "cc"}, "H", T0)
    assert anon.anonymous and (anon.signature, anon.pubkey) == ("", "")
    assert (anon.registry_root, anon.bundle_hash) == ("123", "cc")

    pk = _anchor_from_memo({"d": "aa", "k": "ED11", "w": "dd"}, "H", T0)
    assert (pk.signature, pk.pubkey, pk.bundle_hash, pk.anonymous) == ("", "ED11", "dd", False)

    assert _anchor_from_memo({"d": "aa", "k": "ED11"}, "H", T0) is None  # neither s nor w
    assert _anchor_from_memo({"s": "bb", "k": "ED11"}, "H", T0) is None  # no digest


# --- registry_root_at ----------------------------------------------------------------------

@pytest.fixture
def ledger(monkeypatch):
    lg = XrplLedger.__new__(XrplLedger)
    lg.registry = REG
    lg._history_cache = {}
    history = [
        entry(T0 - 50, [memo(MEMO_TYPE, {"d": "x", "s": "y", "k": "z"})], kind="Payment", account="rAnchor"),
        root_entry(T0, "ROOT1"),
        root_entry(T0 + 50, "FORGED", account="rSomeoneElse"),  # not from the registry
        root_entry(T0 + 60, "FAILED", ok=False),
        root_entry(T0 + 70, "PENDING", validated=False),
        root_entry(T0 + 100, "ROOT2"),  # e.g. after revoking a device
    ]
    monkeypatch.setattr(lg, "_history", lambda address: history if address == REG else [])
    return lg


def test_root_in_force_at_anchor_time(ledger):
    assert ledger.registry_root_at(T0 - 1) is None  # nothing published yet
    assert ledger.registry_root_at(T0) == "ROOT1"
    assert ledger.registry_root_at(T0 + 99) == "ROOT1"  # forged / failed / pending ignored
    assert ledger.registry_root_at(T0 + 100) == "ROOT2"
    assert ledger.registry_root_at(T0 + 10**6) == "ROOT2"
