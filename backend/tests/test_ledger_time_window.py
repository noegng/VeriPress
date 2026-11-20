"""T0 lower bound, ledger side (interfaces.md § Fenêtre de temps) — OWNER: Dev B.
Offline: XrplLedger.latest_validated / ledger_close_time against canned `ledger` responses
(API v2 shape, as returned by the Testnet public node)."""

import pytest
from xrpl.utils import posix_to_ripple_time

from veripress.ledger import XrplLedger

T = 1_795_000_000
H_OLD = "4370a4bcd7a9d110f99e709582412f95f5b6112fa84f12223eb6b14d8609add3"
H_NEW = "99955FEC7AAA731E06F05557186BC736CB9F7479CEBD38CE8E237AF6AD34AC00"


class Resp:
    def __init__(self, result, ok=True):
        self.result, self._ok = result, ok

    def is_successful(self):
        return self._ok


def ledger_result(index, ledger_hash, t, validated=True):
    return {"ledger_hash": ledger_hash, "ledger_index": index, "validated": validated,
            "ledger": {"ledger_index": index, "ledger_hash": ledger_hash, "close_time": posix_to_ripple_time(t),
                       "close_time_resolution": 10, "closed": True}}


class Node:
    """Canned `ledger` responses keyed by ledger_index ("validated" or an int); counts requests."""

    def __init__(self, responses):
        self.responses, self.calls = responses, []

    def __call__(self, req):
        self.calls.append(req.ledger_index)
        return self.responses[req.ledger_index]


@pytest.fixture
def make():
    def _make(responses):
        lg = XrplLedger.__new__(XrplLedger)  # no keys / client needed
        lg._ledgers = {}
        lg._request = Node(responses)
        return lg
    return _make


def test_latest_validated_parses_and_uppercases(make):
    lg = make({"validated": Resp(ledger_result(22477354, H_NEW.lower(), T))})
    assert lg.latest_validated() == (22477354, H_NEW, T)


def test_latest_validated_raises_when_unavailable(make):
    # The pipeline catches it and signs without T0.
    lg = make({"validated": Resp({"error": "noNetwork"}, ok=False)})
    with pytest.raises(RuntimeError):
        lg.latest_validated()


def test_close_time_when_hash_matches_any_case(make):
    lg = make({100: Resp(ledger_result(100, H_OLD, T - 60))})
    assert lg.ledger_close_time(100, H_OLD.upper()) == T - 60
    assert lg.ledger_close_time(100, H_OLD) == T - 60


def test_wrong_hash_is_none(make):
    # A forged T0 (real index, made-up hash) gives no lower bound.
    lg = make({100: Resp(ledger_result(100, H_OLD, T - 60))})
    assert lg.ledger_close_time(100, H_NEW) is None


def test_unknown_or_unvalidated_ledger_is_none(make):
    lg = make({10**9: Resp({"error": "lgrNotFound"}, ok=False),
               101: Resp(ledger_result(101, H_OLD, T, validated=False))})
    assert lg.ledger_close_time(10**9, H_OLD) is None
    assert lg.ledger_close_time(101, H_OLD) is None


def test_network_error_raises(make):
    lg = make({100: Resp({"error": "tooBusy"}, ok=False)})
    with pytest.raises(RuntimeError):
        lg.ledger_close_time(100, H_OLD)


def test_validated_ledgers_are_cached(make):
    # Verifying the same photo again (page polling, public link) costs no extra request, and
    # the T0 fetched at signing time is already known when the photo is verified.
    lg = make({"validated": Resp(ledger_result(200, H_NEW, T)), 100: Resp(ledger_result(100, H_OLD, T - 60))})
    index, h, _ = lg.latest_validated()
    assert lg.ledger_close_time(index, h) == T
    lg.ledger_close_time(100, H_OLD)
    lg.ledger_close_time(100, H_NEW)
    assert lg._request.calls == ["validated", 100]


def test_unvalidated_answers_are_not_cached(make):
    lg = make({101: Resp(ledger_result(101, H_OLD, T, validated=False))})
    lg.ledger_close_time(101, H_OLD)
    lg.ledger_close_time(101, H_OLD)
    assert lg._request.calls == [101, 101]
