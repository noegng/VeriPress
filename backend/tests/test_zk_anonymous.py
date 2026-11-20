"""ZK A — anonymous device attestation (docs/decisions.md Q2-Q4, Q13-Q14; interfaces.md § Phase 2)."""

import io
import json

import numpy as np
import pytest
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress import zk
from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, sign_image, verify_image
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture(scope="module")
def bjj_keys():
    """Device key + 5 fictitious registry members (Baby Jubjub), generated once per module."""
    return [zk.keygen() for _ in range(6)]


@pytest.fixture
def keys(tmp_path, monkeypatch, bjj_keys):
    d = tmp_path / "keys"
    d.mkdir()
    for name in ("device", "ai"):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        data = {"public_key": w.public_key, "private_key": w.private_key}
        if name == "device":
            data["bjj"] = bjj_keys[3]
        (d / f"{name}.json").write_text(json.dumps(data))
    (d / "registry_devices.json").write_text(json.dumps({"pks": [k["pk"] for k in bjj_keys]}))
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")  # not under test here, keeps the suite fast
    return d


@pytest.fixture
def ledger(keys, bjj_keys):
    lg = FakeLedger()
    lg.publish_registry_root(zk.root([k["pk"] for k in bjj_keys]), at=0)
    return lg


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


def test_anonymous_signature_is_real_without_revealing_the_device(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store, anonymous=True)
    assert signed.manifest.anonymous and signed.manifest.signer == ""
    anchor = ledger.fetch_anchor(signed.entry_id)
    assert anchor.anonymous and anchor.pubkey == "" and anchor.signature == ""
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL, report.reason
    assert report.anonymous and report.credential == CredentialType.CAPTURE_DEVICE
    assert "anonym" in report.reason.lower()
    j = report.to_json()
    assert j["anonymous"] is True and j["anchor"]["signer"] == ""
    assert j["zk"] == {"proof_ok": True, "registry_root": anchor.registry_root, "root_valid_at_anchor": True}


def test_device_removed_from_registry_before_signing_is_refused(photo, ledger, store, bjj_keys):
    """Revocation = new root without the device; a proof against the old root, anchored after, fails."""
    ledger.publish_registry_root(zk.root([k["pk"] for i, k in enumerate(bjj_keys) if i != 3]), at=1)
    signed, png = sign_image(photo, "device", ledger, store, anonymous=True)  # device still has the old list
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "not in force" in report.reason
    assert report.zk["proof_ok"] is True and report.zk["root_valid_at_anchor"] is False


def test_revocation_after_anchoring_is_not_retroactive(photo, ledger, store, bjj_keys):
    signed, png = sign_image(photo, "device", ledger, store, anonymous=True)
    later = ledger.fetch_anchor(signed.entry_id).timestamp + 60
    ledger.publish_registry_root(zk.root([k["pk"] for i, k in enumerate(bjj_keys) if i != 3]), at=later)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL


def test_tampered_or_swapped_proof_bundle_is_refused(photo, ledger, store):
    from conftest import photo_like

    signed, png = sign_image(photo, "device", ledger, store, anonymous=True)
    other, _ = sign_image(photo_like(seed=4), "device", ledger, store, anonymous=True)
    # 1. a valid proof, but for another photo, put in place of this one's
    store.put_bundle(signed.entry_id, store.get_bundle(other.entry_id))
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN and report.zk["proof_ok"] is False
    # 2. this photo's bundle with a forged proof element
    bundle = store.get_bundle(other.entry_id)
    bundle["proof"]["pi_a"][0] = str(int(bundle["proof"]["pi_a"][0]) + 1)
    store.put_bundle(other.entry_id, bundle)
    report, _ = verify_image(photo_like(seed=4), ledger, store, entry_id=other.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN and "zero-knowledge" in report.reason.lower()


def test_valid_proof_reanchored_for_another_manifest_is_refused(photo, ledger, store):
    """Attacker anchors photo B with photo A's (valid) proof bundle and hash."""
    from conftest import photo_like

    a, _ = sign_image(photo, "device", ledger, store, anonymous=True)
    b, png_b = sign_image(photo_like(seed=6), "device", ledger, store, anonymous=True)
    bundle_a = store.get_bundle(a.entry_id)
    forged = ledger.anchor_anonymous(b.manifest.digest(), bundle_a["public"][0],
                                     ledger.fetch_anchor(a.entry_id).bundle_hash)
    entry = store.get(b.entry_id)
    entry.id = entry.tx_hash = forged.tx_hash
    store.put(entry)
    store.put_bundle(forged.tx_hash, bundle_a)
    report, _ = verify_image(png_to_rgb(png_b), ledger, store, entry_id=forged.tx_hash)
    assert report.verdict == FinalVerdict.UNKNOWN and report.zk["proof_ok"] is False


def test_device_outside_the_registry_cannot_sign_anonymously(photo, ledger, store, keys):
    reg = keys / "registry_devices.json"
    pks = json.loads(reg.read_text())["pks"]
    reg.write_text(json.dumps({"pks": pks[:3]}))  # device (index 3) not listed
    with pytest.raises(ValueError, match="registry"):
        sign_image(photo, "device", ledger, store, anonymous=True)


def test_ai_generator_cannot_sign_anonymously(photo, ledger, store):
    with pytest.raises(ValueError, match="capture devices"):
        sign_image(photo, "ai", ledger, store, anonymous=True)
