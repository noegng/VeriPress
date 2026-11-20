"""Non-retroactive revocation (phase 2 task 2) — OWNER: Dev B.  Offline: synthetic account
history in the account_tx (API v2) shape, real XrplLedger methods with the network stubbed."""

import pytest
from xrpl.utils import posix_to_ripple_time, str_to_hex

from tileproof.ledger import (
    CredentialType,
    XrplLedger,
    _credential_intervals,
    _revoked_at,
    _valid_at,
)

REG = "rRegistryXXXXXXXXXXXXXXXXXXXXXXXX"
DEV = "rDeviceXXXXXXXXXXXXXXXXXXXXXXXXXX"
OTHER = "rOtherIssuerXXXXXXXXXXXXXXXXXXXXX"
CAP = str_to_hex("CAPTURE_DEVICE").upper()
AI = str_to_hex("AI_GENERATOR").upper()
T0 = 1_795_000_000  # unix


def tx(kind, t, *, account, ctype=CAP, ok=True, validated=True, **fields):
    return {
        "tx_json": {"TransactionType": kind, "Account": account, "CredentialType": ctype,
                    "date": posix_to_ripple_time(t), **fields},
        "meta": {"TransactionResult": "tesSUCCESS" if ok else "tecNO_PERMISSION"},
        "validated": validated,
    }


def create(t, **kw):
    return tx("CredentialCreate", t, account=kw.pop("issuer", REG), Subject=kw.pop("subject", DEV), **kw)


def accept(t, **kw):
    return tx("CredentialAccept", t, account=kw.pop("subject", DEV), Issuer=kw.pop("issuer", REG), **kw)


def delete_by_registry(t, **kw):
    return tx("CredentialDelete", t, account=REG, Subject=DEV, **kw)


def intervals(entries, ctype=CAP):
    return _credential_intervals(entries, DEV, REG, ctype)


# --- the pure interval builder -------------------------------------------------------------

def test_valid_from_accept_not_from_create():
    ivs = intervals([create(T0), accept(T0 + 10)])
    assert ivs == [(T0 + 10, None, None)]
    assert not _valid_at(ivs[0], T0 + 5)  # created but not accepted yet
    assert _valid_at(ivs[0], T0 + 10) and _valid_at(ivs[0], T0 + 10**6)


def test_delete_closes_the_interval_and_is_not_retroactive():
    (iv,) = intervals([create(T0), accept(T0 + 10), delete_by_registry(T0 + 100)])
    assert iv == (T0 + 10, T0 + 100, None)
    assert _valid_at(iv, T0 + 99)  # photo anchored before the revocation stays valid
    assert not _valid_at(iv, T0 + 100) and not _valid_at(iv, T0 + 500)


def test_reissue_opens_a_new_interval_with_a_gap():
    ivs = intervals([create(T0), accept(T0 + 10), delete_by_registry(T0 + 100),
                     create(T0 + 200), accept(T0 + 210)])
    assert ivs == [(T0 + 10, T0 + 100, None), (T0 + 210, None, None)]
    assert not any(_valid_at(iv, T0 + 150) for iv in ivs)  # anchored during the gap


def test_delete_sent_by_the_subject_counts():
    entries = [create(T0), accept(T0 + 10), tx("CredentialDelete", T0 + 50, account=DEV, Issuer=REG)]
    assert intervals(entries) == [(T0 + 10, T0 + 50, None)]


def test_expiration_is_honoured():
    exp = T0 + 1000
    (iv,) = intervals([create(T0, Expiration=posix_to_ripple_time(exp)), accept(T0 + 10)])
    assert _valid_at(iv, exp - 1) and not _valid_at(iv, exp)


@pytest.mark.parametrize(
    "noise",
    [
        [create(T0, issuer=OTHER), accept(T0 + 10, issuer=OTHER)],  # someone else's credential
        [create(T0, ok=False), accept(T0 + 10, ok=False)],  # failed txs
        [create(T0, validated=False), accept(T0 + 10, validated=False)],  # not validated
        [accept(T0 + 10)],  # accept without create
    ],
)
def test_irrelevant_or_invalid_txs_are_ignored(noise):
    assert intervals(noise) == []


def test_types_are_independent():
    entries = [create(T0), accept(T0 + 10), create(T0, ctype=AI), accept(T0 + 20, ctype=AI),
               tx("CredentialDelete", T0 + 30, account=REG, Subject=DEV, ctype=AI)]
    assert intervals(entries, CAP) == [(T0 + 10, None, None)]
    assert intervals(entries, AI) == [(T0 + 20, T0 + 30, None)]


def test_delete_of_an_unaccepted_credential_opens_nothing():
    assert intervals([create(T0), delete_by_registry(T0 + 5), accept(T0 + 10)]) == []


def test_lowercase_credential_type_hex_matches():
    assert intervals([create(T0, ctype=CAP.lower()), accept(T0 + 10, ctype=CAP.lower())]) != []


# --- revoked_at ----------------------------------------------------------------------------

def test_revoked_at():
    now = T0 + 10_000
    closed = [(T0 + 10, T0 + 100, None)]
    assert _revoked_at([closed, []], now) == T0 + 100
    assert _revoked_at([closed + [(T0 + 200, None, None)], []], now) is None  # re-issued: valid now
    assert _revoked_at([[], []], now) is None  # never issued
    assert _revoked_at([[(T0 + 10, None, T0 + 500)], []], now) is None  # expired, not revoked


# --- XrplLedger methods, network stubbed ---------------------------------------------------

@pytest.fixture
def ledger(monkeypatch):
    lg = XrplLedger.__new__(XrplLedger)  # no keys / client needed
    lg.registry = REG
    lg._history_cache = {}
    history = [create(T0), accept(T0 + 10), delete_by_registry(T0 + 100), create(T0 + 200), accept(T0 + 210)]
    monkeypatch.setattr(lg, "_history", lambda address: history if address == DEV else [])
    monkeypatch.setattr("xrpl.core.keypairs.derive_classic_address", lambda pk: DEV if pk == "ED-DEV" else "rNobody")
    return lg


def test_credential_type_at_time(ledger):
    assert ledger.credential_type("ED-DEV", T0 + 50) is CredentialType.CAPTURE_DEVICE
    assert ledger.credential_type("ED-DEV", T0 + 150) is None  # anchored while revoked
    assert ledger.credential_type("ED-DEV", T0 + 5) is None  # before acceptance
    assert ledger.credential_type("ED-DEV", T0 + 300) is CredentialType.CAPTURE_DEVICE
    assert ledger.credential_type("ED-OTHER", T0 + 50) is None


def test_credential_revoked_at_is_none_once_reissued(ledger):
    assert ledger.credential_revoked_at("ED-DEV") is None
