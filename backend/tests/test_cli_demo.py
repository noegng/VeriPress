import json

from conftest import photo_like
from PIL import Image

from veripress.cli import main


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
        "7_anonymous": "real",
    }
    assert summary["7_anonymous"]["anonymous"] is True
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


def test_demo_runs_without_the_watermark_models(tmp_path, monkeypatch):
    """Backup demo when TrustMark is unavailable: the copied-watermark scenario is skipped."""
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    src = tmp_path / "photo.png"
    Image.fromarray(photo_like()).save(src)
    out = tmp_path / "demo"
    assert main(["demo", str(src), "-o", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["5_copied_watermark"] == {"skipped": "watermark disabled (VERIPRESS_WATERMARK=0)"}
    assert summary["3_whatsapp"]["verdict"] == "real" and summary["3_whatsapp"]["found_by"] == "phash"


def test_demo_raw_plays_negative_then_reference_jpeg(tmp_path, monkeypatch):
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    src = tmp_path / "negative.png"  # any image works; with a real RAW it is developed by LibRaw
    Image.fromarray(photo_like()).save(src)
    out = tmp_path / "raw_demo"
    assert main(["demo-raw", str(src), "-o", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert {k: v["verdict"] for k, v in summary.items()} == {
        "1_raw_negative": "real",
        "2_reference_jpeg": "real",
        "3_jpeg_whatsapp": "real",
        "4_jpeg_retouched": "edited",
    }
    assert summary["2_reference_jpeg"]["history"] == ["develop", "capture"]
    assert (out / "2_reference_jpeg.jpg").exists()


def test_demo_batch_anchors_many_photos_in_one_transaction(tmp_path, monkeypatch):
    monkeypatch.setenv("VERIPRESS_WATERMARK", "0")
    paths = []
    for s in range(4):
        p = tmp_path / f"p{s}.png"
        Image.fromarray(photo_like(seed=s)).save(p)
        paths.append(str(p))
    out = tmp_path / "batch"
    assert main(["demo-batch", *paths, "-o", str(out)]) == 0
    summary = json.loads((out / "summary.json").read_text())
    assert summary["transactions"] == 1 and summary["size"] == 4
    assert [p["verdict"] for p in summary["photos"]] == ["real"] * 4
    assert {p["batch"]["tx_hash"] for p in summary["photos"]} == {summary["batch_tx"]}
