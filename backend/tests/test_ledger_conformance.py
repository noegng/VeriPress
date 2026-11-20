"""Both ledgers implement the whole Ledger contract (interfaces.md). Caught twice by hand during
the hackathon: a stub lost in a merge (anchor_batch) and one pasted outside its class
(credential_pq) — both silently degraded features instead of failing loudly."""

import inspect

import pytest

from veripress.ledger import FakeLedger, Ledger, XrplLedger

CONTRACT = sorted(n for n, f in vars(Ledger).items() if inspect.isfunction(f) and not n.startswith("_"))


def test_the_contract_lists_the_phase_2_methods():
    assert {"anchor", "anchor_anonymous", "anchor_passkey", "anchor_batch", "fetch_anchor", "credential_type",
            "credential_revoked_at", "credential_passkey", "credential_pq", "registry_root_at",
            "latest_validated", "ledger_close_time"} <= set(CONTRACT)


@pytest.mark.parametrize("cls", [FakeLedger, XrplLedger], ids=lambda c: c.__name__)
@pytest.mark.parametrize("name", CONTRACT)
def test_ledger_implements_the_contract(cls, name):
    method = getattr(cls, name, None)
    assert callable(method), f"{cls.__name__}.{name} is missing"
    want = list(inspect.signature(getattr(Ledger, name)).parameters)
    assert list(inspect.signature(method).parameters)[: len(want)] == want, f"{cls.__name__}.{name} signature"
