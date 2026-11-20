"""Content-addressed disclosures (decisions.md Q9): the signed manifest names the disclosure by
its CIDv1 (raw, sha2-256), so any mirror can serve it and the verifier knows it is the one."""

import io
import json

import numpy as np
import pytest
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress.cli import main
from veripress.contentaddr import cid_v1_raw
from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import sign_image, verify_image
from veripress.store import Store


def test_cid_matches_the_ipfs_raw_cid_of_known_bytes():
    # `ipfs add --cid-version 1 --raw-leaves` of "hello world" (single block)
    assert cid_v1_raw(b"hello world") == "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    d = tmp_path / "keys"
    d.mkdir()
    w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
    (d / "device.json").write_text(json.dumps({"public_key": w.public_key, "private_key": w.private_key}))
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    monkeypatch.setenv("VERIPRESS_C2PA", "0")
    ledger = FakeLedger()
    ledger.issue(w.public_key, CredentialType.CAPTURE_DEVICE)
    return ledger, Store(tmp_path / "store")


def test_signed_manifest_names_its_disclosure_by_cid(photo, setup, tmp_path):
    ledger, store = setup
    signed, png = sign_image(photo, "device", ledger, store)
    cid = signed.manifest.disclosure_cid
    assert cid.startswith("bafkrei")
    report, _ = verify_image(np.asarray(Image.open(io.BytesIO(png)).convert("RGB")), ledger, store,
                             entry_id=signed.entry_id)
    assert report.to_json()["disclosure_cid"] == cid
    # export for mirroring: the file is named by its CID and hashes to it
    out = tmp_path / "mirror"
    assert main(["export-disclosure", signed.entry_id, "--store", str(store.root), "-o", str(out)]) == 0
    f = out / f"{cid}.json"
    assert f.exists() and cid_v1_raw(f.read_bytes()) == cid
