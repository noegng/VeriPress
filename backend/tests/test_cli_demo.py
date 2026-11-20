import json

from conftest import photo_like
from PIL import Image

from tileproof.cli import main


def test_demo_plays_the_six_scenarios(tmp_path):
    src = tmp_path / "photo.png"
    Image.fromarray(photo_like()).save(src)
    out = tmp_path / "demo"
    assert main(["demo", str(src), "-o", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert {k: v["verdict"] for k, v in summary.items()} == {
        "1_capture": "real",
        "2_edited": "edited",
        "3_whatsapp": "real",
        "4_redacted": "real",
        "5_copied_watermark": "unknown",
        "6_ai": "ai",
    }
    assert (out / "2_edited.heatmap.png").exists()
