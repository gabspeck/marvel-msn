"""Faithful text measurement over the real Windows fonts in `binaries/fonts/`.

GDI decides line breaks (see `drawtext.py`) by summing each glyph's
advance width — `GreGetTextExtentW` in the NT GDI source. We reproduce
that per font type:

- TrueType (`.TTF`): load through FreeType (Pillow) and call
  `ImageFont.getlength`, which sums the scaled outline advances.
- Bitmap (`.FON`: MS Sans Serif, MS Serif, …): parse the FNT
  `dfCharTable` width table out of the NE container and sum per-character
  widths directly. This is exactly the table GDI's `ExtTextOut` /
  `GetTextExtentPoint` read for a raster font. (FreeType's winfnt driver
  rescales bitmap strikes to the requested ppem and reports the wrong
  widths, so it is not used for `.FON`.)

A `.FON` carries one strike per point size. The requested size is the
LOGFONT `lfHeight` magnitude (`px_height`); the authored point size is
recovered as `round(px_height * 72/96)` (96-DPI MM_TEXT DC — the inverse
of how the WMF font height was built) and matched against each strike's
`dfPoints`, nearest wins.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path

# Pillow is imported lazily inside the TrueType branch of `_load`: the
# bitmap `.FON` path (MS Sans Serif, the common caption case) is pure
# struct parsing and needs no third-party dependency.

_DEFAULT_FACE = "arial"

# Font directory: repo `binaries/fonts/`, overridable for deploys/tests.
_FONT_DIR = Path(
    os.environ.get(
        "MSN_FONT_DIR", str(Path(__file__).resolve().parents[3] / "binaries" / "fonts")
    )
)

# face name (lowercased) -> {(bold, italic): filename}. Raster .FON faces
# have only a regular strike set; bold/italic fall back to regular.
_FONT_FILES: dict[str, dict[tuple[bool, bool], str]] = {
    "arial": {(False, False): "ARIAL.TTF", (True, False): "ARIALBD.TTF",
              (False, True): "ARIALI.TTF", (True, True): "ARIALBI.TTF"},
    "helvetica": {(False, False): "ARIAL.TTF", (True, False): "ARIALBD.TTF",
                  (False, True): "ARIALI.TTF", (True, True): "ARIALBI.TTF"},
    "times new roman": {(False, False): "TIMES.TTF", (True, False): "TIMESBD.TTF",
                        (False, True): "TIMESI.TTF", (True, True): "TIMESBI.TTF"},
    "times": {(False, False): "TIMES.TTF", (True, False): "TIMESBD.TTF",
              (False, True): "TIMESI.TTF", (True, True): "TIMESBI.TTF"},
    "courier new": {(False, False): "COUR.TTF", (True, False): "COURBD.TTF",
                    (False, True): "COURI.TTF", (True, True): "COURBI.TTF"},
    "courier": {(False, False): "COUR.TTF", (True, False): "COURBD.TTF",
                (False, True): "COURI.TTF", (True, True): "COURBI.TTF"},
    "comic sans ms": {(False, False): "COMIC.TTF", (True, False): "COMICBD.TTF"},
    "garamond": {(False, False): "Gara.ttf", (True, False): "Garabd.ttf",
                 (False, True): "Garait.ttf"},
    "verdana": {(False, False): "VERDANA.TTF", (True, False): "VERDANAB.TTF",
                (False, True): "VERDANAI.TTF", (True, True): "VERDANAZ.TTF"},
    "georgia": {(False, False): "Georgia.TTF", (True, False): "Georgiab.TTF",
                (False, True): "Georgiai.TTF", (True, True): "Georgiaz.TTF"},
    "trebuchet ms": {(False, False): "Trebuc.TTF", (True, False): "Trebucbd.TTF",
                     (False, True): "Trebucit.TTF", (True, True): "Trebucbi.TTF"},
    "lucida handwriting": {(False, False): "LHANDW.TTF"},
    "impact": {(False, False): "IMPACT.TTF"},
    "symbol": {(False, False): "SYMBOL.TTF"},
    # Bitmap (.FON) faces — one strike per point size, regular only.
    "ms sans serif": {(False, False): "sserife.fon"},
    "microsoft sans serif": {(False, False): "sserife.fon"},
    "ms serif": {(False, False): "serife.fon"},
    "small fonts": {(False, False): "smalle.fon"},
    "modern": {(False, False): "MODERN.FON"},
}


def _resolve_file(face: str, bold: bool, italic: bool) -> str:
    variants = _FONT_FILES.get(face.strip().lower())
    if variants is None:
        variants = _FONT_FILES[_DEFAULT_FACE]
    # Prefer the exact style, then drop italic, then bold, then regular.
    for key in ((bold, italic), (bold, False), (False, italic), (False, False)):
        if key in variants:
            return variants[key]
    return next(iter(variants.values()))


class _BitmapStrike:
    """One FNT strike: per-character widths + cell height. `getlength`
    sums the `dfCharTable` advance of each character (default-char width
    for anything outside dfFirstChar..dfLastChar), matching GDI.
    """

    __slots__ = ("widths", "default_width", "pix_height")

    def __init__(self, widths: dict[int, int], default_width: int, pix_height: int):
        self.widths = widths
        self.default_width = default_width
        self.pix_height = pix_height

    def getlength(self, text: str) -> int:
        w = self.widths
        d = self.default_width
        return sum(w.get(ord(ch), d) for ch in text)


def _parse_fon(path: str) -> dict[int, _BitmapStrike]:
    """Parse a Windows `.FON` (NE container) into `{point_size: strike}`.

    Reads each `RT_FONT` (0x8008) resource as an FNT v2/v3 header plus
    its `dfCharTable`. Returns empty on any structure we don't recognise
    (caller then falls back to FreeType).
    """
    data = Path(path).read_bytes()
    if data[:2] != b"MZ":
        return {}
    ne = struct.unpack_from("<I", data, 0x3C)[0]
    if data[ne:ne + 2] != b"NE":
        return {}
    res_tbl = ne + struct.unpack_from("<H", data, ne + 0x24)[0]
    shift = struct.unpack_from("<H", data, res_tbl)[0]
    offsets: list[int] = []
    p = res_tbl + 2
    while True:
        type_id = struct.unpack_from("<H", data, p)[0]
        if type_id == 0:
            break
        count = struct.unpack_from("<H", data, p + 2)[0]
        p += 8
        for _ in range(count):
            if type_id == 0x8008:  # RT_FONT
                offsets.append(struct.unpack_from("<H", data, p)[0] << shift)
            p += 12

    strikes: dict[int, _BitmapStrike] = {}
    for off in offsets:
        ver = struct.unpack_from("<H", data, off)[0]
        points = struct.unpack_from("<H", data, off + 0x44)[0]
        pix_height = struct.unpack_from("<H", data, off + 0x58)[0]
        first = data[off + 0x5F]
        last = data[off + 0x60]
        default_char = data[off + 0x61]
        if ver == 0x200:        # FNT 2.0: table at 0x76, entries (u16 w, u16 off)
            tbl, stride = 0x76, 4
        elif ver == 0x300:      # FNT 3.0: table at 0x94, entries (u16 w, u32 off)
            tbl, stride = 0x94, 6
        else:
            continue
        widths: dict[int, int] = {}
        for i, ch in enumerate(range(first, last + 1)):
            widths[ch] = struct.unpack_from("<H", data, off + tbl + i * stride)[0]
        default_width = widths.get(default_char, widths.get(0x20, 0))
        strikes[points] = _BitmapStrike(widths, default_width, pix_height)
    return strikes


@lru_cache(maxsize=64)
def _load_fon(path: str) -> dict[int, _BitmapStrike]:
    return _parse_fon(path)


@lru_cache(maxsize=256)
def _load(face: str, px_height: int, bold: bool, italic: bool):
    """Return `(font, line_height)` where `font` has `getlength(str)->int`.

    `px_height` is the pixel em-height (LOGFONT `lfHeight` magnitude).
    """
    path = str(_FONT_DIR / _resolve_file(face, bold, italic))
    px = max(1, abs(px_height))

    if path.lower().endswith(".fon"):
        strikes = _load_fon(path)
        if strikes:
            points = max(1, round(px * 72 / 96))  # inverse of -(pt*96//72)
            best = strikes.get(points)
            if best is None:
                best = min(strikes.values(),
                           key=lambda s: abs(round(s.pix_height * 72 / 96) - points))
            return best, best.pix_height
        # Unparseable .FON → fall back to the default scalable face.
        path = str(_FONT_DIR / _FONT_FILES[_DEFAULT_FACE][(False, False)])

    from PIL import ImageFont  # lazy: only TrueType measurement needs Pillow

    font = ImageFont.truetype(path, px)
    asc, desc = font.getmetrics()
    return font, asc + desc


def measure_text(face: str, px_height: int, bold: bool, italic: bool, text: str) -> int:
    """Pixel extent of `text` — the faithful analog of GreGetTextExtentW
    (sum of glyph advance widths) for the resolved font/size.
    """
    if not text:
        return 0
    font, _ = _load(face, px_height, bold, italic)
    return round(font.getlength(text))


def line_height(face: str, px_height: int, bold: bool, italic: bool) -> int:
    """Cell height in pixels — GDI's `tmHeight` (raster `dfPixHeight`),
    used as the per-line vertical advance for wrapped text.
    """
    _, lh = _load(face, px_height, bold, italic)
    return round(lh)


def text_measurer(face: str, px_height: int, bold: bool,
                  italic: bool) -> Callable[[str], int]:
    """A `measure(s) -> int` closure bound to one font, for `drawtext`."""
    font, _ = _load(face, px_height, bold, italic)

    def measure(s: str) -> int:
        return round(font.getlength(s)) if s else 0

    return measure
