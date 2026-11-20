import numpy as np
import pytest
from conftest import jpeg, rescale

from tileproof.commitment import Disclosure, TileStatus, Verdict, commit, redact, verify

SEED = b"s" * 32


def edit_box(rgb: np.ndarray, x0: int, y0: int, x1: int, y1: int) -> np.ndarray:
    out = rgb.copy()
    out[y0:y1, x0:x1] = (255, 0, 255)  # paste a flat magenta patch
    return out


def test_untouched_image_is_intact(photo):
    m, d = commit(photo, SEED)
    res = verify(photo, m, d)
    assert res.verdict == Verdict.INTACT
    assert set(res.statuses) == {TileStatus.EXACT}
    assert len(res.statuses) == 20 * 15  # 640x480 in 32px tiles


@pytest.mark.parametrize("quality", [50, 70, 90])
def test_jpeg_recompression_is_recompressed_not_edited(photo, quality):
    m, d = commit(photo, SEED)
    res = verify(jpeg(photo, quality), m, d)
    assert res.verdict == Verdict.RECOMPRESSED
    assert TileStatus.CHANGED not in res.statuses


def test_half_scale_then_jpeg_is_still_recompressed(photo):
    m, d = commit(photo, SEED)
    res = verify(jpeg(rescale(photo, 0.5), 80), m, d)
    assert res.verdict == Verdict.RECOMPRESSED


def test_local_edit_flags_exactly_the_edited_tiles(photo):
    m, d = commit(photo, SEED)
    edited = edit_box(photo, 64, 96, 160, 192)  # tiles cols 2-4, rows 3-5
    res = verify(jpeg(edited, 85), m, d)
    assert res.verdict == Verdict.EDITED
    changed = {i for i, s in enumerate(res.statuses) if s == TileStatus.CHANGED}
    expected = {r * 20 + c for r in range(3, 6) for c in range(2, 5)}
    assert changed == expected


def test_redacted_tiles_are_authenticated_and_hidden(photo):
    m, d = commit(photo, SEED)
    out, d2 = redact(photo, m, d, {0, 1, 21})
    assert (out[0:32, 0:64] == 0).all()
    res = verify(out, m, d2)
    assert res.exact_root_ok and res.robust_root_ok
    assert [i for i, s in enumerate(res.statuses) if s == TileStatus.REDACTED] == [0, 1, 21]
    assert res.verdict == Verdict.INTACT
    hidden = {t.i: t for t in d2.tiles}
    assert hidden[0].salt is None and hidden[0].f is None  # nothing about the content leaks


def test_tampered_disclosure_is_invalid(photo):
    m, d = commit(photo, SEED)
    data = d.to_dict()
    data["tiles"][5]["f"][0] += 1  # forge a committed feature
    res = verify(photo, m, Disclosure.from_dict(data))
    assert res.verdict == Verdict.INVALID_DISCLOSURE


def test_disclosure_from_another_image_is_invalid(photo):
    from conftest import photo_like

    m, _ = commit(photo, SEED)
    _, other = commit(photo_like(seed=1), SEED)
    assert verify(photo, m, other).verdict == Verdict.INVALID_DISCLOSURE


def test_different_seeds_give_different_roots_for_same_image(photo):
    m1, _ = commit(photo, SEED)
    m2, _ = commit(photo, b"t" * 32)
    assert m1.exact_root != m2.exact_root


def test_content_pasted_into_a_redacted_area_is_changed(photo):
    m, d = commit(photo, SEED)
    out, d2 = redact(photo, m, d, {0, 1, 21})
    forged = out.copy()
    forged[0:32, 0:64] = photo[100:132, 200:264]  # paste content where tiles were blacked out
    res = verify(jpeg(forged, 85), m, d2)
    assert res.statuses[0] == TileStatus.CHANGED and res.statuses[1] == TileStatus.CHANGED
    assert res.statuses[21] == TileStatus.REDACTED
    assert res.verdict == Verdict.EDITED


def test_jpeg_of_redacted_image_keeps_tiles_redacted(photo):
    m, d = commit(photo, SEED)
    out, d2 = redact(photo, m, d, {0, 1, 21})
    res = verify(jpeg(out, 60), m, d2)
    assert [i for i, s in enumerate(res.statuses) if s == TileStatus.REDACTED] == [0, 1, 21]


def test_odd_sized_photo_survives_strong_downscale_without_false_edits():
    """Calibration finding: edge tiles (slivers, padding) flagged after a WhatsApp-like 2.4x downscale."""
    from conftest import photo_like

    img = photo_like(1601, 1069, seed=2)  # 1601 % 32 == 1 -> 1 px sliver column; 1069 % 32 == 13
    m, d = commit(img, SEED)
    res = verify(jpeg(rescale(img, 0.41), 65), m, d)
    assert TileStatus.CHANGED not in res.statuses
    assert res.verdict == Verdict.RECOMPRESSED


def test_tile_size_adapts_to_photo_size_so_shared_copies_verify():
    """Calibrated on real 4K photos: a tile must keep ~40 px after a 1280-1600 px share."""
    from conftest import photo_like

    big = photo_like(3840, 2560, seed=4)
    m, d = commit(big, SEED)  # no tile given: chosen from the image size
    assert m.tile == 96
    res = verify(jpeg(rescale(big, 1280 / 3840), 55), m, d)
    assert TileStatus.CHANGED not in res.statuses
    assert commit(photo_like(), SEED)[0].tile == 32  # small images keep the 32 px floor


def test_iphone_heic_photo_loads_with_orientation(tmp_path, photo):
    import pillow_heif
    from PIL import Image

    from tileproof.tiling import load_rgb

    pillow_heif.from_pillow(Image.fromarray(photo)).save(tmp_path / "IMG_0001.HEIC", quality=95)
    rgb = load_rgb(tmp_path / "IMG_0001.HEIC")
    assert rgb.shape == photo.shape


def test_display_p3_photo_is_read_in_srgb_like_its_shared_copy(tmp_path, photo):
    """Real WhatsApp finding: iPhone originals are Display P3, shared copies are untagged sRGB."""
    from pathlib import Path

    from PIL import Image, ImageCms

    from tileproof.tiling import load_rgb

    p3 = ImageCms.ImageCmsProfile(str(Path(__file__).parent / "data" / "display_p3.icc"))
    srgb = ImageCms.createProfile("sRGB")
    p3_pixels = ImageCms.profileToProfile(Image.fromarray(photo), srgb, p3, outputMode="RGB")
    p3_pixels.save(tmp_path / "p3.png", icc_profile=p3.tobytes())
    back = load_rgb(tmp_path / "p3.png").astype(int)
    assert np.abs(back - photo).mean() < 1.5
    m, d = commit(load_rgb(tmp_path / "p3.png"), SEED)
    assert verify(jpeg(photo, 80), m, d).verdict == Verdict.RECOMPRESSED


def test_thin_dark_lines_on_bright_background_survive_bicubic_downscale():
    """Real WhatsApp finding (railing on a white wall): resampling overshoot is clipped at 255."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (2400, 1800), (250, 250, 248))
    d = ImageDraw.Draw(img)
    for x in range(0, 2400, 23):
        d.line((x, 0, x + 40, 1800), fill=(15, 15, 15), width=3)
    rgb = np.asarray(img)
    m, dis = commit(rgb, SEED)
    small = Image.fromarray(rgb).resize((1200, 900), Image.Resampling.BICUBIC)  # 2x: tiles keep ~32 px
    res = verify(jpeg(np.asarray(small), 70), m, dis)
    assert TileStatus.CHANGED not in res.statuses


def _fake_watermark(rgb: np.ndarray) -> np.ndarray:
    """Stand-in for TrustMark at this seam: a structured low-amplitude residual."""
    yy, xx = np.mgrid[0 : rgb.shape[0], 0 : rgb.shape[1]]
    residual = (12 * np.sin(xx / 7.0) * np.cos(yy / 5.0))[..., None]
    return np.clip(rgb.astype(float) + residual, 0, 255).astype(np.uint8)


def test_dual_commit_accepts_both_the_published_and_the_original(photo):
    marked = _fake_watermark(photo)
    m, d = commit(marked, SEED, original=photo)
    assert verify(marked, m, d).verdict == Verdict.INTACT
    res = verify(photo, m, d)
    assert TileStatus.CHANGED not in res.statuses
    assert res.original_tiles > len(res.statuses) // 2


def test_dual_commit_still_flags_edits_of_the_original(photo):
    marked = _fake_watermark(photo)
    m, d = commit(marked, SEED, original=photo)
    res = verify(jpeg(edit_box(photo, 64, 96, 160, 192), 85), m, d)
    changed = {i for i, s in enumerate(res.statuses) if s == TileStatus.CHANGED}
    assert changed == {r * 20 + c for r in range(3, 6) for c in range(2, 5)}


def test_forged_original_features_invalidate_the_disclosure(photo):
    m, d = commit(_fake_watermark(photo), SEED, original=photo)
    data = d.to_dict()
    data["tiles"][7]["g"][0] += 3
    assert verify(photo, m, Disclosure.from_dict(data)).verdict == Verdict.INVALID_DISCLOSURE
    del data["tiles"][7]["g"]  # stripping the original's features is tampering too
    assert verify(photo, m, Disclosure.from_dict(data)).verdict == Verdict.INVALID_DISCLOSURE


def test_redaction_keeps_working_with_dual_commit(photo):
    marked = _fake_watermark(photo)
    m, d = commit(marked, SEED, original=photo)
    out, d2 = redact(marked, m, d, {0, 1})
    res = verify(out, m, d2)
    assert res.robust_root_ok and res.statuses[0] == TileStatus.REDACTED
    assert d2.tiles[0].g is None and d2.tiles[0].f is None  # nothing about hidden content leaks


def test_original_of_another_size_is_rejected(photo):
    with pytest.raises(ValueError):
        commit(photo, SEED, original=photo[:-8])
