"""Passkey (WebAuthn, P-256) signing, server side (decisions.md Q21-Q23, interfaces.md § Phase 2).

The registry attests the passkey (sha256 of its SEC1 key) in the device's CAPTURE_DEVICE
credential; the browser signs the manifest digest as the WebAuthn challenge (Touch ID).
"""

import base64
import hashlib
import io
import json

import numpy as np
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, complete_passkey_sign, prepare_passkey_sign, sign_image, verify_image
from veripress.store import Store

ORIGIN = "http://localhost:8000"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


class Authenticator:
    """A software stand-in for Touch ID: a P-256 key producing WebAuthn assertions."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        pub = self.key.public_key()
        self.sec1 = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        self.spki = b64u(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        self.credential_id = b64u(b"cred-1")

    def assert_(self, challenge_hex, origin=ORIGIN, rp_id="localhost", flags=0x05, type_="webauthn.get"):
        cdj = json.dumps({"type": type_, "challenge": b64u(bytes.fromhex(challenge_hex)),
                          "origin": origin, "crossOrigin": False}).encode()
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + (1).to_bytes(4, "big")
        sig = self.key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {"credential_id": self.credential_id, "authenticator_data": b64u(auth),
                "client_data_json": b64u(cdj), "signature": b64u(sig), "public_key": self.spki}


@pytest.fixture
def env(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
    (d / "device.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key}))
    authn = Authenticator()
    (d / "passkey.json").write_text(json.dumps({  # format written by Dev B's /api/passkey/register
        "credential_id": authn.credential_id, "public_key": authn.sec1.hex(),
        "sha256": hashlib.sha256(authn.sec1).hexdigest(), "spki": authn.spki}))
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    ledger = FakeLedger()
    ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE, passkey_hash=hashlib.sha256(authn.sec1).hexdigest())
    return ledger, Store(tmp_path / "store"), authn, w.public_key


def sign_with_passkey(photo, ledger, store, authn, **assert_kw):
    prep = prepare_passkey_sign(photo, store, ledger=ledger)
    return complete_passkey_sign(prep["prep_id"], authn.assert_(prep["challenge"], **assert_kw), ledger, store)


def test_photo_signed_with_an_attested_passkey_is_real(photo, env):
    ledger, store, authn, device = env
    signed, png = sign_with_passkey(photo, ledger, store, authn)
    assert signed.manifest.passkey == authn.sec1.hex() and signed.manifest.signer == device
    anchor = ledger.fetch_anchor(signed.entry_id)
    assert anchor.signature == "" and anchor.bundle_hash and not anchor.anonymous
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL, report.reason
    assert report.passkey and report.signature_ok and "passkey" in report.reason.lower()
    j = signed.to_json()
    assert j["passkey"] is True and j["anonymous"] is False and j["pending"] is False and j["meta_claims"] == []


def test_prepare_returns_the_manifest_digest_as_challenge(photo, env):
    ledger, store, _, _ = env
    prep = prepare_passkey_sign(photo, store, ledger=ledger)
    assert len(prep["challenge"]) == 64 and prep["prep_id"]


@pytest.mark.parametrize("bad", [
    {"challenge_hex": "00" * 32},            # signed another digest
    {"flags": 0x01},                          # user present but not verified (no Touch ID)
    {"origin": "https://evil.example"},       # phishing origin
    {"rp_id": "evil.example"},                # wrong relying party
    {"type_": "webauthn.create"},             # registration, not an assertion
])
def test_invalid_assertions_are_refused(photo, env, bad):
    ledger, store, authn, _ = env
    prep = prepare_passkey_sign(photo, store, ledger=ledger)
    kw = {"challenge_hex": prep["challenge"], **bad}
    with pytest.raises(ValueError):
        complete_passkey_sign(prep["prep_id"], authn.assert_(kw.pop("challenge_hex"), **kw), ledger, store)


def test_assertion_from_another_key_is_refused(photo, env):
    ledger, store, _, _ = env
    with pytest.raises(ValueError, match="passkey"):
        sign_with_passkey(photo, ledger, store, Authenticator())


def test_passkey_not_attested_by_the_registry_is_refused(photo, env):
    ledger, store, authn, device = env
    ledger.passkeys[device] = "00" * 32  # registry attests another passkey
    with pytest.raises(ValueError, match="attest"):
        sign_with_passkey(photo, ledger, store, authn)


def test_attestation_changed_after_signing_makes_it_unknown(photo, env):
    """Verification re-checks the attestation: the passkey must be the one the registry vouches for."""
    ledger, store, authn, device = env
    signed, png = sign_with_passkey(photo, ledger, store, authn)
    ledger.passkeys[device] = "00" * 32
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN and "passkey" in report.reason.lower()


def test_tampered_assertion_bundle_is_unknown(photo, env):
    ledger, store, authn, _ = env
    signed, png = sign_with_passkey(photo, ledger, store, authn)
    bundle = store.get_bundle(signed.entry_id)
    bundle["signature"] = authn.assert_("00" * 32)["signature"]
    store.put_bundle(signed.entry_id, bundle)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN


def test_unknown_or_reused_prep_id_is_a_key_error(photo, env):
    ledger, store, authn, _ = env
    prep = prepare_passkey_sign(photo, store, ledger=ledger)
    complete_passkey_sign(prep["prep_id"], authn.assert_(prep["challenge"]), ledger, store)
    with pytest.raises(KeyError):  # single use
        complete_passkey_sign(prep["prep_id"], authn.assert_(prep["challenge"]), ledger, store)
    with pytest.raises(KeyError):
        complete_passkey_sign("nope", authn.assert_(prep["challenge"]), ledger, store)


def test_named_and_anonymous_sign_results_carry_the_phase2_keys(photo, env):
    ledger, store, _, _ = env
    j = sign_image(photo, "device", ledger, store)[0].to_json()
    assert j["anonymous"] is False and j["passkey"] is False and j["pending"] is False and j["meta_claims"] == []
