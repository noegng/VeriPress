"""Findings of the phase-2 security review (Dev A)."""

import io
import json

import numpy as np
import pytest
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress import zk
from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, _bundle_hash, _prepare, _publish, sign_image, verify_image
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture(scope="module")
def bjj_keys():
    return [zk.keygen() for _ in range(4)]


@pytest.fixture
def setup(tmp_path, monkeypatch, bjj_keys):
    d = tmp_path / "keys"
    d.mkdir()
    w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
    (d / "device.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key,
                                               "bjj": bjj_keys[1]}))
    (d / "registry_devices.json").write_text(json.dumps({"pks": [k["pk"] for k in bjj_keys]}))
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    ledger = FakeLedger()
    ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE)
    ledger.publish_registry_root(zk.root([k["pk"] for k in bjj_keys]), at=0)
    return ledger, Store(tmp_path / "store")


def test_anonymous_develop_cannot_claim_the_same_device(photo, setup, bjj_keys):
    """Finding 1: with anonymous manifests both signers are "" — "same device" is unprovable.
    An accredited device bypassing our client crafts an anonymous develop of another anonymous RAW."""
    ledger, store = setup
    raw, raw_png = sign_image(photo, "device", ledger, store, anonymous=True)
    prep = _prepare(png_to_rgb(raw_png), "develop", "", ledger, store, parent=raw.entry_id, anonymous=True)
    digest = prep.manifest.digest()
    pks = [k["pk"] for k in bjj_keys]
    bundle = zk.prove_device(bjj_keys[2]["sk"], pks, 2, digest)  # another accredited device
    anchor = ledger.anchor_anonymous(digest, bundle["public"][0], _bundle_hash(bundle))
    forged, forged_png = _publish(prep, anchor, store, bundle)
    report, _ = verify_image(png_to_rgb(forged_png), ledger, store, entry_id=forged.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    assert "anonymous signatures cannot prove" in report.reason


@pytest.mark.parametrize("bad", ["../keys", "..", "a/b", "/etc/passwd", "", "AB" * 32 + "/../x"])
def test_store_rejects_ids_that_are_not_entry_ids(tmp_path, bad):
    """Finding 2: ids come from signed manifests (parent) too, not only from the API's checked input."""
    assert Store(tmp_path / "store").get(bad) is None
    assert Store(tmp_path / "store").get_bundle(bad) is None


def test_store_does_not_read_an_entry_outside_its_root(tmp_path, photo, setup):
    ledger, store = setup
    signed, _ = sign_image(photo, "device", ledger, store)
    outside = tmp_path / "elsewhere" / "fake"
    outside.mkdir(parents=True)
    (outside / "entry.json").write_text((store.root / signed.entry_id / "entry.json").read_text())
    rel = "../elsewhere/fake"
    assert (store.root / rel / "entry.json").exists()  # the file is reachable by path…
    assert store.get(rel) is None  # …but not as an entry id


def test_chain_with_a_passkey_signed_negative_verifies(photo, setup, monkeypatch):
    """Found while reviewing finding 1: _history only knew Ed25519 anchors, so a RAW signed with
    the passkey (Touch ID) made its developed JPEG fall back to EDITED."""
    import hashlib

    from test_passkey import Authenticator

    from veripress.pipeline import complete_passkey_sign, prepare_passkey_sign
    from veripress.signing import keys_dir

    ledger, store = setup
    authn = Authenticator()
    (keys_dir() / "passkey.json").write_text(json.dumps({
        "credential_id": authn.credential_id, "public_key": authn.sec1.hex(),
        "sha256": hashlib.sha256(authn.sec1).hexdigest(), "spki": authn.spki}))
    device = json.loads((keys_dir() / "device.json").read_text())["public_key"]
    ledger.passkeys[device] = (0, hashlib.sha256(authn.sec1).hexdigest())
    prep = prepare_passkey_sign(photo, store, ledger=ledger)
    raw, raw_png = complete_passkey_sign(prep["prep_id"], authn.assert_(prep["challenge"]), ledger, store)
    dev, dev_png = sign_image(png_to_rgb(raw_png), "device", ledger, store, parent=raw.entry_id, op="develop")
    report, _ = verify_image(png_to_rgb(dev_png), ledger, store, entry_id=dev.entry_id)
    assert [h["verified"] for h in report.history] == [True, True]
    assert report.verdict == FinalVerdict.REAL, report.reason


def test_signed_edit_of_an_anonymous_original_shows_a_verified_chain(photo, setup):
    ledger, store = setup
    raw, raw_png = sign_image(photo, "device", ledger, store, anonymous=True)
    edit, edit_png = sign_image(png_to_rgb(raw_png), "device", ledger, store, parent=raw.entry_id)
    report, _ = verify_image(png_to_rgb(edit_png), ledger, store, entry_id=edit.entry_id)
    assert [h["verified"] for h in report.history] == [True, True]
    assert "could not be verified" not in report.reason
