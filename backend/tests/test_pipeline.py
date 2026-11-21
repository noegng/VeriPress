import io
import json

import numpy as np
import pytest
from conftest import jpeg, rescale
from PIL import Image
from xrpl.constants import CryptoAlgorithm
from xrpl.wallet import Wallet

from veripress.ledger import CredentialType, FakeLedger
from veripress.pipeline import FinalVerdict, redact_image, sign_image, verify_image, verify_stored
from veripress.store import Store


def png_to_rgb(png: bytes) -> np.ndarray:
    return np.asarray(Image.open(io.BytesIO(png)).convert("RGB"))


@pytest.fixture
def keys(tmp_path, monkeypatch):
    """Demo keys in the format written by Dev B's setup script (docs/interfaces.md)."""
    d = tmp_path / "keys"
    d.mkdir()
    out = {}
    for name in ("device", "ai"):
        w = Wallet.create(algorithm=CryptoAlgorithm.ED25519)
        data = {"seed": w.seed, "address": w.classic_address, "public_key": w.public_key, "private_key": w.private_key}
        (d / f"{name}.json").write_text(json.dumps(data))
        out[name] = w.public_key
    monkeypatch.setenv("VERIPRESS_KEYS", str(d))
    return out


@pytest.fixture
def ledger(keys):
    lg = FakeLedger()
    lg.issue(keys["device"], CredentialType.CAPTURE_DEVICE)
    lg.issue(keys["ai"], CredentialType.AI_GENERATOR)
    return lg


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "store")


def test_device_signed_untouched_image_is_real(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    report, heatmap = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL
    assert report.credential == CredentialType.CAPTURE_DEVICE
    assert report.signature_ok
    assert heatmap is not None


def test_edited_image_is_edited_with_heatmap(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    edited = png_to_rgb(png).copy()
    edited[100:200, 100:200] = (255, 0, 255)
    report, heatmap = verify_image(jpeg(edited, 85), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    assert report.tiles.counts()["changed"] > 0
    assert heatmap is not None


def test_ai_generator_signed_image_is_ai(photo, ledger, store):
    signed, png = sign_image(photo, "ai", ledger, store)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.AI
    assert report.credential == CredentialType.AI_GENERATOR


def test_revoked_credential_is_unknown(photo, ledger, store, keys):
    signed, png = sign_image(photo, "device", ledger, store)
    # Revoked as of the anchor second: revocation is not retroactive, so an undated revoke() that
    # lands a second after anchoring (C2PA makes signing slower) would rightly leave it REAL.
    ledger.revoke(keys["device"], at=ledger.fetch_anchor(signed.entry_id).timestamp)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert report.credential is None
    assert "credential" in report.reason.lower()


def test_forged_signature_is_unknown(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    a = ledger.anchors[signed.entry_id]
    bad = "00" * 64
    ledger.anchors[signed.entry_id] = type(a)(a.tx_hash, a.digest, bad, a.pubkey, a.timestamp, a.explorer_url)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert not report.signature_ok
    assert "signature" in report.reason.lower()


def test_manifest_swapped_in_store_is_unknown(photo, ledger, store):
    """The off-chain store is untrusted: its manifest must match the anchored digest."""
    from conftest import photo_like

    signed, png = sign_image(photo, "device", ledger, store)
    other, _ = sign_image(photo_like(seed=3), "device", ledger, store)
    entry, forged = store.get(signed.entry_id), store.get(other.entry_id)
    entry.manifest, entry.disclosure = forged.manifest, forged.disclosure
    store.put(entry)
    report, _ = verify_image(photo_like(seed=3), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "manifest" in report.reason.lower()


def test_tampered_disclosure_is_unknown(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    entry = store.get(signed.entry_id)
    entry.disclosure.tiles[3].f[0] += 1
    store.put(entry)
    report, heatmap = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "disclosure" in report.reason.lower()
    assert heatmap is None


def test_unknown_image_is_unknown_without_heatmap(photo, ledger, store):
    from conftest import photo_like

    sign_image(photo, "device", ledger, store)
    report, heatmap = verify_image(photo_like(seed=7), ledger, store)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert report.found_by is None and report.anchor is None and report.tiles is None
    assert heatmap is None


def test_unknown_entry_id_is_unknown(photo, ledger, store):
    report, heatmap = verify_image(photo, ledger, store, entry_id="DEADBEEF")
    assert report.verdict == FinalVerdict.UNKNOWN
    assert heatmap is None


def test_anchor_missing_on_ledger_is_unknown(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    del ledger.anchors[signed.entry_id]
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "anchor" in report.reason.lower()


def test_whatsapp_like_copy_is_found_by_phash_and_real(photo, ledger, store, monkeypatch):
    """Metadata stripped, downscaled, recompressed, no id, no watermark: perceptual hash fallback."""
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    sign_image(photo, "device", ledger, store)
    shared = jpeg(rescale(photo, 0.5), 70)
    report, _ = verify_image(shared, ledger, store)
    assert report.found_by == "phash"
    assert report.verdict == FinalVerdict.REAL
    assert report.tiles.verdict.value == "recompressed"


def test_phash_picks_the_right_image_among_several(ledger, store):
    from conftest import photo_like

    ids = {s: sign_image(photo_like(seed=s), "device", ledger, store)[0].entry_id for s in range(5)}
    report, _ = verify_image(jpeg(photo_like(seed=3), 75), ledger, store)
    assert report.entry_id == ids[3]


def test_report_json_matches_api_contract(photo, ledger, store):
    """Shape fixed in docs/interfaces.md, consumed by Dev B's page."""
    signed, png = sign_image(photo, "device", ledger, store)
    report, heatmap = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    j = report.to_json(heatmap)
    json.dumps(j)  # serialisable
    assert set(j) == {"verdict", "reason", "found_by", "entry_id", "anchor", "credential",
                      "signature_ok", "tiles", "history", "heatmap_png_b64",
                      # phase 2 (interfaces.md § Phase 2)
                      "anonymous", "zk", "credential_revoked_at", "passkey", "meta_claims", "pending",
                      "time_window", "disclosure_cid", "batch", "post_quantum"}
    assert j["anonymous"] is False and j["zk"] is None and j["meta_claims"] == [] and j["pending"] is False
    assert j["verdict"] == "real" and j["credential"] == "CAPTURE_DEVICE" and j["found_by"] == "tx_hash"
    assert set(j["anchor"]) == {"tx_hash", "timestamp", "explorer_url", "signer"}
    assert j["anchor"]["signer"] == signed.manifest.signer
    assert set(j["tiles"]) == {"verdict", "grid", "counts", "statuses", "distances"}
    assert j["tiles"]["grid"] == {"cols": 20, "rows": 15, "tile": 32}
    assert len(j["tiles"]["statuses"]) == 300 and j["tiles"]["statuses"][0] == "exact"
    assert j["heatmap_png_b64"].startswith("iVBOR")


def test_unknown_report_json_has_nulls(photo, ledger, store):
    report, heatmap = verify_image(photo, ledger, store)
    j = report.to_json(heatmap)
    assert j["verdict"] == "unknown" and j["found_by"] is None
    assert j["anchor"] is None and j["tiles"] is None and j["heatmap_png_b64"] is None


def test_sign_result_json_matches_api_contract(photo, ledger, store):
    signed, _ = sign_image(photo, "device", ledger, store)
    j = signed.to_json()
    json.dumps(j)
    assert set(j) == {"entry_id", "tx_hash", "explorer_url", "digest", "signer", "grid", "roots", "image_url",
                      "anonymous", "passkey", "pending", "meta_claims"}  # phase 2
    assert j["image_url"] == f"/api/files/{signed.entry_id}.png"
    assert j["digest"] == signed.manifest.digest()
    assert set(j["roots"]) == {"exact", "robust"}


def test_redacted_copy_stays_real_with_hidden_tiles(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(64, 64, 160, 128)], store)
    assert rid == f"{signed.entry_id}-r1"
    red = png_to_rgb(red_png)
    assert (red[64:128, 64:160] == 0).all()
    report, _ = verify_image(red, ledger, store, entry_id=rid)
    assert report.verdict == FinalVerdict.REAL
    assert report.tiles.counts()["redacted"] == 3 * 2
    assert report.anchor.tx_hash == signed.entry_id  # same anchor as the original


def test_redacted_copy_is_found_by_phash(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(0, 0, 320, 240)], store)
    report, _ = verify_image(jpeg(png_to_rgb(red_png), 80), ledger, store)
    assert report.entry_id == rid and report.verdict == FinalVerdict.REAL


def test_whatsapp_like_copy_is_found_by_watermark_and_real(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    shared = jpeg(rescale(png_to_rgb(png), 0.5), 60)
    report, _ = verify_image(shared, ledger, store)
    assert report.found_by == "watermark"
    assert report.entry_id == signed.entry_id
    assert report.verdict == FinalVerdict.REAL


def test_watermark_copied_onto_another_image_is_detected(photo, ledger, store):
    from conftest import photo_like
    from veripress.watermark import embed

    signed, _ = sign_image(photo, "device", ledger, store)
    fake = embed(photo_like(seed=11), bytes.fromhex(signed.manifest.wm_id))
    report, _ = verify_image(jpeg(fake, 85), ledger, store)
    assert report.found_by == "watermark"
    assert report.verdict == FinalVerdict.UNKNOWN
    assert "watermark" in report.reason.lower()


def test_signed_edit_links_back_to_the_original(photo, ledger, store):
    original, png = sign_image(photo, "device", ledger, store)
    edited = png_to_rgb(png).copy()
    edited[0:64, 0:64] = 0
    version, vpng = sign_image(edited, "device", ledger, store, parent=original.entry_id)
    assert version.manifest.op == "edit" and version.manifest.parent == original.entry_id
    report, _ = verify_image(png_to_rgb(vpng), ledger, store, entry_id=version.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    assert "signed edit" in report.reason.lower()
    assert [h["tx_hash"] for h in report.history] == [version.entry_id, original.entry_id]
    assert [h["op"] for h in report.history] == ["edit", "capture"]
    assert report.to_json()["history"] == report.history


def test_every_verdict_explains_itself(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    edited = png_to_rgb(png).copy()
    edited[100:200, 100:200] = 0
    ai, ai_png = sign_image(photo, "ai", ledger, store)
    for rgb, eid, needle in [
        (png_to_rgb(png), signed.entry_id, "capture_device"),
        (edited, signed.entry_id, "changed"),
        (png_to_rgb(ai_png), ai.entry_id, "ai_generator"),
    ]:
        report, _ = verify_image(rgb, ledger, store, entry_id=eid)
        assert needle in report.reason.lower()


def test_fully_redacted_record_cannot_vouch_for_an_arbitrary_image(photo, ledger, store):
    """Security review: redacting everything must not turn any image into 'real'."""
    from conftest import photo_like

    signed, png = sign_image(photo, "device", ledger, store)
    h, w = photo.shape[:2]
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(0, 0, w, h)], store)
    report, _ = verify_image(photo_like(seed=21), ledger, store, entry_id=rid)
    assert report.verdict != FinalVerdict.REAL
    report, _ = verify_image(png_to_rgb(red_png), ledger, store, entry_id=rid)
    assert report.verdict == FinalVerdict.UNKNOWN  # nothing left to authenticate
    assert "redacted" in report.reason.lower()


def test_unwatermarked_original_of_a_signed_photo_is_real(photo, ledger, store):
    """Review finding: the gallery original (no watermark) came out 'edited' — the watermark
    residual exceeded the tolerance in some tiles."""
    signed, _ = sign_image(photo, "device", ledger, store)
    for received in (photo, jpeg(rescale(photo, 0.5), 70)):
        report, _ = verify_image(received, ledger, store, entry_id=signed.entry_id)
        assert report.verdict == FinalVerdict.REAL, report.reason
        assert "original" in report.reason.lower()


def test_signing_an_edit_of_an_unknown_parent_is_refused(photo, ledger, store):
    with pytest.raises(ValueError, match="parent"):
        sign_image(photo, "device", ledger, store, parent="AB" * 32)


def test_signed_edit_whose_parent_cannot_be_verified_says_so(photo, ledger, store):
    original, png = sign_image(photo, "device", ledger, store)
    edited = png_to_rgb(png).copy()
    edited[0:64, 0:64] = 0
    version, vpng = sign_image(edited, "device", ledger, store, parent=original.entry_id)
    del ledger.anchors[original.entry_id]  # parent anchor no longer readable
    report, _ = verify_image(png_to_rgb(vpng), ledger, store, entry_id=version.entry_id)
    assert report.verdict == FinalVerdict.EDITED
    assert "could not be verified" in report.reason.lower()
    assert report.history[-1]["verified"] is False


def test_redaction_reason_does_not_claim_the_owner_did_it(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    rid, red_png = redact_image(png_to_rgb(png), signed.entry_id, [(64, 64, 160, 128)], store)
    report, _ = verify_image(png_to_rgb(red_png), ledger, store, entry_id=rid)
    assert "redacted" in report.reason.lower() and "owner" not in report.reason.lower()


def test_device_revoked_after_anchoring_stays_real_and_says_since_when(photo, ledger, store, keys):
    """Non-retroactive revocation (decisions.md Q5)."""
    signed, png = sign_image(photo, "device", ledger, store)
    revoked = ledger.fetch_anchor(signed.entry_id).timestamp + 60
    ledger.revoke(keys["device"], at=revoked)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.REAL
    assert report.credential_revoked_at == revoked
    assert report.to_json()["credential_revoked_at"] == revoked
    assert "revoked" in report.reason.lower()


def test_device_revoked_before_anchoring_is_unknown(photo, ledger, store, keys):
    ledger.revoke(keys["device"], at=0)
    signed, png = sign_image(photo, "device", ledger, store)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.verdict == FinalVerdict.UNKNOWN


def test_verify_stored_checks_the_published_image_of_an_entry(photo, ledger, store):
    """Public link /v/<tx> (decisions.md Q24): no upload, the stored published image is verified."""
    signed, _ = sign_image(photo, "device", ledger, store)
    report, heatmap = verify_stored(signed.entry_id, ledger, store)
    assert report.verdict == FinalVerdict.REAL and report.entry_id == signed.entry_id
    assert report.found_by == "tx_hash" and heatmap is not None
    rid, _ = redact_image(png_to_rgb(store.image_path(signed.entry_id).read_bytes()), signed.entry_id,
                          [(0, 0, 64, 64)], store)
    assert verify_stored(rid, ledger, store)[0].tiles.counts()["redacted"] == 4


def test_verify_stored_of_an_unknown_entry_raises_key_error(ledger, store):
    with pytest.raises(KeyError):
        verify_stored("AB" * 32, ledger, store)


def test_fast_anchoring_gives_a_pending_verdict_until_validated(photo, ledger, store):
    """Fast anchoring (decisions.md Q11): sign returns on submit, the verdict is flagged pending."""
    signed, png = sign_image(photo, "device", ledger, store, wait=False)
    assert ledger.fetch_anchor(signed.entry_id).validated is False
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert report.pending and report.to_json()["pending"] is True
    assert report.reason.startswith("Anchor pending validation")
    assert report.verdict == FinalVerdict.REAL  # provisional
    ledger.validate(signed.entry_id)
    report, _ = verify_image(png_to_rgb(png), ledger, store, entry_id=signed.entry_id)
    assert not report.pending and not report.reason.startswith("Anchor pending")


def test_lookup_suggests_the_record_a_new_version_derives_from(photo, ledger, store):
    """lookup_records: what the page offers as the parent of a new version. A shared copy of a
    signed photo finds its record (with the anchor time); an unrelated image finds nothing."""
    from conftest import photo_like

    from veripress.pipeline import lookup_records

    signed, png = sign_image(photo, "device", ledger, store)
    shared = jpeg(png_to_rgb(png), 70)
    found = lookup_records(shared, store, ledger)
    assert found and found[0]["tx_hash"] == signed.anchor.tx_hash
    assert found[0]["op"] == "capture" and found[0]["timestamp"] == signed.anchor.timestamp
    assert found[0]["image_url"] == f"/api/files/{signed.entry_id}.png"
    assert lookup_records(photo_like(seed=7), store, ledger) == []


class CountingLedger:
    """Counts the ledger reads a verification makes (any attribute access that is a call)."""

    def __init__(self, ledger):
        self.ledger, self.calls = ledger, []

    def __getattr__(self, name):
        attr = getattr(self.ledger, name)
        if not callable(attr):
            return attr

        def call(*a, **k):
            self.calls.append((name, a))
            return attr(*a, **k)

        return call


def _with_variants(photo, ledger, store, n=3):
    signed, png = sign_image(photo, "device", ledger, store)
    variants = [redact_image(png_to_rgb(png), signed.entry_id, [(32 * k, 0, 32 * k + 64, 64)], store) for k in range(n)]
    return signed, png, variants


def test_verification_stops_at_the_first_perfect_record(photo, ledger, store, monkeypatch):
    """A signed photo with redacted variants: the original record supports it perfectly (real,
    nothing changed or redacted), so the variants are not verified one by one."""
    import veripress.pipeline as pl

    signed, png, _ = _with_variants(photo, ledger, store)
    seen = []
    real_verify_entry = pl._verify_entry
    monkeypatch.setattr(pl, "_verify_entry", lambda rgb, e, *a: (seen.append(e.id), real_verify_entry(rgb, e, *a))[1])
    report, _ = verify_image(png_to_rgb(png), ledger, store)
    assert report.verdict == FinalVerdict.REAL and report.entry_id == signed.entry_id
    assert report.tiles.counts()["redacted"] == 0
    assert seen == [signed.entry_id]


def test_redacted_copy_still_gets_its_own_record_among_the_candidates(photo, ledger, store, monkeypatch):
    """No candidate is perfect for a redacted copy (it has redacted tiles): all are verified and
    the variant that matches it wins, as before."""
    signed, png, variants = _with_variants(photo, ledger, store)
    rid, red_png = variants[1]
    report, _ = verify_image(png_to_rgb(red_png), ledger, store)
    assert report.entry_id == rid and report.verdict == FinalVerdict.REAL
    assert report.tiles.counts()["redacted"] > 0


def test_one_verification_reads_each_ledger_fact_once(photo, ledger, store):
    """The candidates of an image share their anchor and signer: each ledger read is made once
    per verification, however many candidates are verified."""
    signed, png, variants = _with_variants(photo, ledger, store)
    counting = CountingLedger(ledger)
    report, _ = verify_image(png_to_rgb(variants[0][1]), counting, store)  # verifies every candidate
    assert report.verdict == FinalVerdict.REAL
    reads = [c for c in counting.calls if c[0].startswith(("fetch_", "credential_"))]
    assert reads and len(reads) == len(set(reads))
    assert sum(1 for name, _ in reads if name == "fetch_anchor") == 1


def test_ledger_read_cache_only_caches_reads():
    from veripress.pipeline import LedgerReadCache

    class L:
        n = 0

        def fetch_anchor(self, tx):
            self.n += 1
            return tx

        def credential_type(self, pk, t=None):
            self.n += 1
            return pk

        def anchor(self, d):
            self.n += 1
            return d

    lg = L()
    c = LedgerReadCache(lg)
    assert c.fetch_anchor("A") == c.fetch_anchor("A") == "A" and lg.n == 1
    assert c.credential_type("K", t=5) == "K" and c.credential_type("K", t=5) == "K" and lg.n == 2
    c.credential_type(["unhashable"]); c.credential_type(["unhashable"])
    assert lg.n == 4  # unhashable arguments bypass the cache
    c.anchor("x"); c.anchor("x")
    assert lg.n == 6  # writes are never cached


def test_heatmap_png_only_when_asked(photo, ledger, store):
    signed, png = sign_image(photo, "device", ledger, store)
    rgb = png_to_rgb(png)
    assert verify_image(rgb, ledger, store)[1] is not None
    report, hm = verify_image(rgb, ledger, store, heatmap_png=False)
    assert hm is None and report.verdict == FinalVerdict.REAL and report.tiles.statuses


def test_valid_metadata_proofs_are_checked_once(monkeypatch):
    """The ZK verifier (a Node process) runs once per valid (proof, public inputs); an invalid
    or unverifiable one is checked again each time, and a different input is never confused."""
    import veripress.pipeline as pl

    calls = []
    monkeypatch.setattr(pl, "_META_OK", set())
    monkeypatch.setattr(pl.zk, "verify_meta", lambda proof, public: calls.append(public) or proof.get("ok", False))
    good, bad = {"ok": True, "pi": [1]}, {"ok": False, "pi": [1]}
    assert pl._verify_meta(good, ["1", "2"]) and pl._verify_meta(good, ["1", "2"])
    assert len(calls) == 1
    assert not pl._verify_meta(bad, ["1", "2"]) and not pl._verify_meta(bad, ["1", "2"])
    assert len(calls) == 3
    assert pl._verify_meta(good, ["1", "3"]) and len(calls) == 4
