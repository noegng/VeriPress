"""Capture metadata for ZK B (docs/decisions.md Q16-Q17). OWNER: Dev A.

At signing: EXIF DateTimeOriginal (+ OffsetTimeOriginal) and GPS -> `Capture`; the signed
manifest only carries a Poseidon commitment to it (zk.commit_meta). Two claims are proven in
zero knowledge and published: the local day of capture, and a ~10 km box around the place.
The exact time and position are never published.

At verification, labels are derived from the *verified public inputs* (`describe`), never
from stored text.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from PIL import Image

T_MAX = 2**40 - 1  # circuit range for unix seconds
LAT_SHIFT, LON_SHIFT = 90_000_000, 180_000_000  # circuit works on shifted, non-negative e6 values
AREA_HALF_LAT_DEG = 0.05  # ~5.5 km each way -> a ~10 km box
MAX_UTC_OFFSET_S = 14 * 3600


@dataclass(frozen=True)
class Capture:
    time: int  # unix seconds, UTC
    lat_e6: int
    lon_e6: int
    utc_offset_min: int  # from OffsetTimeOriginal (0 if absent)


@dataclass(frozen=True)
class Claim:
    kind: str  # "day" | "area"
    label: str
    t_min: int = 0
    t_max: int = T_MAX
    lat_min_e6: int = -LAT_SHIFT
    lat_max_e6: int = LAT_SHIFT
    lon_min_e6: int = -LON_SHIFT
    lon_max_e6: int = LON_SHIFT

    def bounds(self) -> dict:
        return {k: getattr(self, k) for k in
                ("t_min", "t_max", "lat_min_e6", "lat_max_e6", "lon_min_e6", "lon_max_e6")}


def exif_from_upload(data: bytes) -> bytes | None:
    """Raw EXIF block of an uploaded image (JPEG, HEIC, PNG, TIFF…), for sign_image(exif=…)."""
    from . import tiling  # noqa: F401  (registers the HEIC opener)

    try:
        exif = Image.open(io.BytesIO(data)).getexif()
    except Exception:  # noqa: BLE001 — RAW or unreadable: simply no metadata claims
        return None
    return exif.tobytes() if len(exif) else None


def _deg(dms) -> float:
    d, m, s = (float(x) for x in dms)
    return d + m / 60 + s / 3600


def _offset_minutes(text: str | None) -> int:
    if not text or len(text) < 6 or text[0] not in "+-":
        return 0
    sign = 1 if text[0] == "+" else -1
    return sign * (int(text[1:3]) * 60 + int(text[4:6]))


def read_capture(exif: bytes | None) -> Capture | None:
    """Capture time + GPS from a raw EXIF block, or None if either is missing."""
    if not exif:
        return None
    try:
        ex = Image.Exif()
        ex.load(exif)
        sub, gps = ex.get_ifd(0x8769), ex.get_ifd(0x8825)
        when = sub.get(0x9003) or ex.get(0x0132)  # DateTimeOriginal, else DateTime
        if not when or 2 not in gps or 4 not in gps:
            return None
        offset = _offset_minutes(sub.get(0x9011))
        local = datetime.strptime(str(when).strip("\x00 "), "%Y:%m:%d %H:%M:%S")
        utc = local.replace(tzinfo=timezone.utc) - timedelta(minutes=offset)
        lat = _deg(gps[2]) * (-1 if str(gps.get(1, "N")).upper().startswith("S") else 1)
        lon = _deg(gps[4]) * (-1 if str(gps.get(3, "E")).upper().startswith("W") else 1)
    except (ValueError, TypeError, KeyError, ZeroDivisionError, SyntaxError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return None
    return Capture(int(utc.timestamp()), round(lat * 1e6), round(lon * 1e6), offset)


def claims(cap: Capture) -> tuple[Claim, Claim]:
    """(local day of capture, ~10 km box centred on the place rounded to 0.01°)."""
    local = datetime.fromtimestamp(cap.time, timezone.utc) + timedelta(minutes=cap.utc_offset_min)
    midnight_local = local.replace(hour=0, minute=0, second=0, microsecond=0)
    t_min = int((midnight_local - timedelta(minutes=cap.utc_offset_min)).timestamp())
    day = Claim("day", "", t_min=t_min, t_max=t_min + 86399)

    lat_c, lon_c = round(cap.lat_e6 / 1e6, 2), round(cap.lon_e6 / 1e6, 2)
    half_lon = AREA_HALF_LAT_DEG / max(math.cos(math.radians(lat_c)), 0.01)
    area = Claim(
        "area", "",
        lat_min_e6=max(round((lat_c - AREA_HALF_LAT_DEG) * 1e6), -LAT_SHIFT),
        lat_max_e6=min(round((lat_c + AREA_HALF_LAT_DEG) * 1e6), LAT_SHIFT),
        lon_min_e6=max(round((lon_c - half_lon) * 1e6), -LON_SHIFT),
        lon_max_e6=min(round((lon_c + half_lon) * 1e6), LON_SHIFT),
    )
    return (
        Claim(**{**day.__dict__, "label": describe(public_of(day))[1]}),
        Claim(**{**area.__dict__, "label": describe(public_of(area))[1]}),
    )


def public_of(c: Claim, commitment: str = "0") -> list[str]:
    """Public inputs of meta.circom for a claim (shifted units, decimal strings)."""
    return [str(commitment), str(c.t_min), str(c.t_max),
            str(c.lat_min_e6 + LAT_SHIFT), str(c.lat_max_e6 + LAT_SHIFT),
            str(c.lon_min_e6 + LON_SHIFT), str(c.lon_max_e6 + LON_SHIFT)]


def describe(public: list[str]) -> tuple[str, str]:
    """(kind, human label) from a claim's public inputs — the only trusted source for labels."""
    t_min, t_max, la0, la1, lo0, lo1 = (int(x) for x in public[1:7])
    lat0, lat1, lon0, lon1 = la0 - LAT_SHIFT, la1 - LAT_SHIFT, lo0 - LON_SHIFT, lo1 - LON_SHIFT
    if t_max - t_min == 86399 and (lat0, lat1, lon0, lon1) == (-LAT_SHIFT, LAT_SHIFT, -LON_SHIFT, LON_SHIFT):
        offset = (-t_min) % 86400  # local midnight = t_min + offset (unique within ±14 h)
        if offset > MAX_UTC_OFFSET_S:
            offset -= 86400
        d = datetime.fromtimestamp(t_min + offset, timezone.utc)
        return "day", f"{d.day} {d:%b %Y}"
    if (t_min, t_max) == (0, T_MAX):
        lat_c, lon_c = (lat0 + lat1) / 2e6, (lon0 + lon1) / 2e6
        size_km = max(5, round((lat1 - lat0) / 1e6 * 111 / 5) * 5)
        ns, ew = ("N" if lat_c >= 0 else "S"), ("E" if lon_c >= 0 else "W")
        return "area", f"≈ {abs(lat_c):.2f}°{ns} {abs(lon_c):.2f}°{ew} ({size_km} km)"
    return "other", "custom claim"
