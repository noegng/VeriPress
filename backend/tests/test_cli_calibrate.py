import json

from conftest import jpeg, photo_like, rescale
from PIL import Image

from tileproof.cli import main


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
