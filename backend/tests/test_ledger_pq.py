"""Keys attested in the credential URI (passkey + ML-DSA-87, interfaces.md § Signature hybride
post-quantique) — OWNER: Dev B. Offline: URI format, and attestations read from a synthetic
account history (account_tx API v2 shape) with the network stubbed."""

import pytest
from xrpl.utils import str_to_hex

from test_ledger_revocation import AI, CAP, DEV, REG, T0, accept, create, delete_by_registry
from veripress.ledger import MLDSA87, PASSKEY, XrplLedger, _attested_uri, attestation_uri, uri_attestations

PK = "ab" * 32
PQ = "cd" * 32
PQ2 = "ef" * 32


def u(s: str) -> str:
    return str_to_hex(s).upper()  # XRPL returns URIs as upper-case hex


# --- URI format ----------------------------------------------------------------------------

def b64(h: str) -> str:
    import base64

    return base64.urlsafe_b64encode(bytes.fromhex(h)).rstrip(b"=").decode()


def test_combined_uri_roundtrip_and_fits_xrpl_limit():
    uri = attestation_uri(passkey=PK.upper(), mldsa87=PQ)
    assert uri == f"passkey={b64(PK)};mldsa87={b64(PQ)}"
    # xrpl-py caps the URI at 256 HEX characters: two hex sha256 + labels (159 bytes) failed
    assert len(str_to_hex(uri)) <= 256
    assert uri_attestations(u(uri)) == {PASSKEY: PK, MLDSA87: PQ}
    assert attestation_uri() == "" and attestation_uri(mldsa87=PQ) == f"mldsa87={b64(PQ)}"


@pytest.mark.parametrize("uri, expected", [
    (f"mldsa87={b64(PQ)};passkey={b64(PK)}", {MLDSA87: PQ, PASSKEY: PK}),  # any order
    (f"passkey:sha256:{PK}", {PASSKEY: PK}),  # first format (credentials issued before), still read
    (f"passkey:sha256:{PK};mldsa87={b64(PQ)}", {PASSKEY: PK, MLDSA87: PQ}),  # mixed
    (f"passkey={b64(PK)[:-1]};mldsa87={b64(PQ)}", {MLDSA87: PQ}),  # truncated value skipped
    (f"passkey:sha1:{PK};junk;mldsa87=!{b64(PQ)[1:]}", {}),  # wrong algo / not base64url
    ("", {}),
])
def test_uri_parsing_skips_malformed_parts(uri, expected):
    assert uri_attestations(u(uri) if uri else "") == expected


def test_unreadable_uri_is_empty():
    assert uri_attestations("ZZ") == {} and uri_attestations("FF") == {}


# --- attestation in force at a time, from the history ----------------------------------------

HISTORY = [
    create(T0, URI=u(f"passkey:sha256:{PK}")), accept(T0 + 10),
    delete_by_registry(T0 + 100),
    create(T0 + 200, URI=u(attestation_uri(passkey=PK, mldsa87=PQ))), accept(T0 + 210),
    create(T0 + 300, issuer="rSomeoneElseXXXXXXXXXXXXXXXXXXXXX", URI=u(attestation_uri(mldsa87=PQ2))),  # not the registry
    create(T0 + 400, ok=False, URI=u(attestation_uri(mldsa87=PQ2))),  # failed tx
]


def test_attested_uri_in_force_at_a_time():
    att = lambda t: uri_attestations(_attested_uri(HISTORY, DEV, REG, CAP, t) or "")  # noqa: E731
    assert _attested_uri(HISTORY, DEV, REG, CAP, T0 - 1) is None  # never issued yet
    assert att(T0 + 50) == {PASSKEY: PK}
    assert att(T0 + 150) == {PASSKEY: PK}  # revoked then: the URI it had (validity is credential_type's job)
    assert att(T0 + 250) == {PASSKEY: PK, MLDSA87: PQ}
    assert uri_attestations(_attested_uri(HISTORY, DEV, REG, CAP)) == {PASSKEY: PK, MLDSA87: PQ}  # latest
    assert _attested_uri(HISTORY, DEV, REG, AI) is None  # other credential type


@pytest.fixture
def ledger(monkeypatch):
    lg = XrplLedger.__new__(XrplLedger)  # no keys / client needed
    lg.registry = REG
    history = list(HISTORY) + [delete_by_registry(T0 + 500)]  # device revoked at the end
    monkeypatch.setattr(lg, "_history", lambda address: history if address == DEV else [])
    monkeypatch.setattr("xrpl.core.keypairs.derive_classic_address", lambda pk: DEV if pk == "ED-DEV" else "rNobody")
    return lg


def test_attestations_survive_a_revocation(ledger):
    # Photos signed (hybrid) before the revocation must keep verifying: the ML-DSA-87 key the
    # registry attested does not vanish with the CredentialDelete.
    assert ledger.credential_pq("ED-DEV") == PQ
    assert ledger.credential_passkey("ED-DEV") == PK
    assert ledger.credential_pq("ED-DEV", at_time=T0 + 50) is None  # no ML-DSA-87 key attested back then
    assert ledger.credential_pq("ED-NOBODY") is None and ledger.credential_passkey("ED-NOBODY") is None
