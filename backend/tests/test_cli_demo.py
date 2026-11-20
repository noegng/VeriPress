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


def test_demo_uses_a_real_ai_image_when_given(tmp_path):
    src, ai = tmp_path / "photo.png", tmp_path / "ai.png"
    Image.fromarray(photo_like()).save(src)
    Image.fromarray(photo_like(320, 240, seed=5)).save(ai)
    out = tmp_path / "demo"
    assert main(["demo", str(src), "--ai", str(ai), "-o", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["6_ai"]["verdict"] == "ai"
    assert (out / "6_ai.png").exists()
    assert Image.open(out / "6_ai.png").size == Image.open(ai).size
