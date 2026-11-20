import json

from conftest import jpeg, photo_like, rescale
from PIL import Image

from veripress.cli import main


def test_calibrate_reports_margins_for_original_and_shared_pairs(tmp_path):
    orig, shared = tmp_path / "originals", tmp_path / "whatsapp"
    orig.mkdir(), shared.mkdir()
    for s in range(2):
        img = photo_like(seed=s)
        Image.fromarray(img).save(orig / f"p{s}.png")
        Image.fromarray(jpeg(rescale(img, 0.5), 60)).save(shared / f"p{s}.jpg")
    out = tmp_path / "calib.json"
    assert main(["calibrate", str(orig), str(shared), "-o", str(out)]) == 0
    r = json.loads(out.read_text())
    assert set(r["pairs"]) == {"p0", "p1"}
    p = r["pairs"]["p0"]
    assert p["changed_tiles"] == 0 and p["max_tile_distance"] <= r["tolerance"]
    assert p["phash_distance"] <= 10
    assert r["all_pass"] is True


def test_calibrate_skips_non_images_and_reports_missing_copies(tmp_path, capsys):
    orig, shared = tmp_path / "originals", tmp_path / "whatsapp"
    orig.mkdir(), shared.mkdir()
    Image.fromarray(photo_like()).save(orig / "a.png")
    Image.fromarray(photo_like(seed=1)).save(orig / "b.png")
    Image.fromarray(jpeg(photo_like(), 70)).save(shared / "a.jpg")
    (orig / ".DS_Store").write_bytes(b"\0\0\0\1Bud1")
    (shared / ".DS_Store").write_bytes(b"\0\0\0\1Bud1")
    out = tmp_path / "calib.json"
    assert main(["calibrate", str(orig), str(shared), "-o", str(out)]) == 0
    r = json.loads(out.read_text())
    assert set(r["pairs"]) == {"a"} and r["missing"] == ["b"]


def test_calibrate_pairs_shared_copies_by_content_not_by_name(tmp_path):
    """WhatsApp renames exported files: copies are matched to originals by perceptual hash."""
    orig, shared = tmp_path / "originals", tmp_path / "whatsapp"
    orig.mkdir(), shared.mkdir()
    for s in range(3):
        Image.fromarray(photo_like(seed=s)).save(orig / f"IMG_00{s}.png")
    # exported names say nothing, and come in another order
    Image.fromarray(jpeg(rescale(photo_like(seed=2), 0.5), 60)).save(shared / "WhatsApp Image 15.03.10.jpeg")
    Image.fromarray(jpeg(rescale(photo_like(seed=0), 0.5), 60)).save(shared / "WhatsApp Image 15.03.11.jpeg")
    Image.fromarray(jpeg(photo_like(seed=9), 70)).save(shared / "WhatsApp Image 15.03.12.jpeg")  # unrelated
    out = tmp_path / "calib.json"
    assert main(["calibrate", str(orig), str(shared), "-o", str(out)]) == 0
    r = json.loads(out.read_text())
    assert {k: v["shared"] for k, v in r["pairs"].items()} == {
        "IMG_000": "WhatsApp Image 15.03.11.jpeg",
        "IMG_002": "WhatsApp Image 15.03.10.jpeg",
    }
    assert r["missing"] == ["IMG_001"]
    assert r["unmatched"] == ["WhatsApp Image 15.03.12.jpeg"]
    assert r["all_pass"] is False  # an original without its copy, and a copy of nothing
