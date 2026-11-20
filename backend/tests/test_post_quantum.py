"""Hybrid post-quantum signature: Ed25519 + ML-DSA-87 (FIPS 204), like Apple Reference Image's
hybrid ML-DSA-87 + RSA. The ML-DSA key is attested by the registry (credential URI); the signed
manifest names it (sha256); its 4.6 kB signature lives next to the photo, not in the 1 kB memo."""

import hashlib
import io
import json

import numpy as np
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress import zk
from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, sign_image, verify_image
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


def new_mldsa():
    k = mldsa.MLDSA87PrivateKey.generate()
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    return k, {"public_key": pub.hex(), "private_pem": pem}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
    _, pq = new_mldsa()
    (d / "device.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key,
                                               "mldsa": pq}))
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    ledger = FakeLedger()
    pq_hash = hashlib.sha256(bytes.fromhex(pq["public_key"])).hexdigest()
    ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE, pq_hash=pq_hash)
    return ledger, Store(tmp_path / "store"), w.public_key, pq_hash


def test_hybrid_signature_is_real_and_says_post_quantum(photo, setup):
    ledger, store, _, pq_hash = setup
    signed, png = sign_image(photo, "device", ledger, store)
    assert signed.manifest.pq_pubkey_sha256 == pq_hash
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL, report.reason
    assert report.post_quantum == {"alg": "ML-DSA-87", "signature_ok": True, "attested": True}
    assert "post-quantum" in report.reason.lower()
    assert report.to_json()["post_quantum"] == report.post_quantum


def test_stripping_the_pq_signature_does_not_downgrade_to_ed25519(photo, setup):
    ledger, store, _, _ = setup
    signed, png = sign_image(photo, "device", ledger, store)
    (store.root / signed.entry_id / "pq.json").unlink()
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN and "post-quantum" in report.reason.lower()


def test_tampered_pq_signature_is_unknown(photo, setup):
    ledger, store, _, _ = setup
    signed, png = sign_image(photo, "device", ledger, store)
    p = store.root / signed.entry_id / "pq.json"
    pq = json.loads(p.read_text())
    sig = bytearray(bytes.fromhex(pq["signature"]))
    sig[10] ^= 1
    pq["signature"] = sig.hex()
    p.write_text(json.dumps(pq))
    assert verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)[0].verdict == FinalVerdict.UNKNOWN


def test_pq_key_swapped_for_the_attackers_own_is_unknown(photo, setup):
    """A quantum forger of Ed25519 would bring its own ML-DSA key: it is not the attested one."""
    ledger, store, _, _ = setup
    signed, png = sign_image(photo, "device", ledger, store)
    k, pq = new_mldsa()
    digest = signed.manifest.digest()
    (store.root / signed.entry_id / "pq.json").write_text(json.dumps({
        "alg": "ML-DSA-87", "public_key": pq["public_key"], "signature": k.sign(bytes.fromhex(digest)).hex()}))
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN


def test_attestation_withdrawn_after_signing_is_unknown(photo, setup):
    ledger, store, device, _ = setup
    signed, png = sign_image(photo, "device", ledger, store)
    ledger.pq_keys[device] = (0, "00" * 32)  # (attested since, sha256)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN and report.post_quantum["attested"] is False


def test_unattested_pq_key_is_not_used_at_signing(photo, setup):
    """Transition: until the registry attests the ML-DSA key, sign classic Ed25519 only."""
    ledger, store, device, _ = setup
    ledger.pq_keys.pop(device)
    signed, png = sign_image(photo, "device", ledger, store)
    assert signed.manifest.pq_pubkey_sha256 is None
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL and report.post_quantum is None


def test_anonymous_signatures_never_carry_the_pq_key(photo, setup, tmp_path):
    """The ML-DSA public key identifies the device: it would defeat the zero-knowledge anonymity."""
    from veripress.signing import keys_dir

    ledger, store, _, _ = setup
    bjj = [zk.keygen() for _ in range(3)]
    dev = json.loads((keys_dir() / "device.json").read_text())
    dev["bjj"] = bjj[0]
    (keys_dir() / "device.json").write_text(json.dumps(dev))
    (keys_dir() / "registry_devices.json").write_text(json.dumps({"pks": [k["pk"] for k in bjj]}))
    ledger.publish_registry_root(zk.root([k["pk"] for k in bjj]), at=0)
    signed, png = sign_image(photo, "device", ledger, store, anonymous=True)
    assert signed.manifest.pq_pubkey_sha256 is None
    assert not (store.root / signed.entry_id / "pq.json").exists()
    assert verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)[0].verdict == FinalVerdict.REAL
