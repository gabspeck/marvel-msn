"""Faithful port of the Win32 GDI ``DrawText`` word-wrap algorithm.

Ported from the NT4 source `private/ntos/w32/ntuser/rtl/drawtext.c`
(the master copy of the client/kernel DrawText). Only the subset that
BBCTL's `CLabelCtrl::OnDraw` exercises is ported:

- Western / non-FarEast path (the `FE_SB` Kanji/KINSOKU branches and the
  `aASCII_StartBreak` etc. tables are NOT ported — BBDESIGN captions are
  Latin-1).
- `DT_NOPREFIX` is assumed set (BBCTL always passes it), so the prefix
  (`&` accelerator) machinery — `GetPrefixCount` / `PSMTextOut` /
  `DT_GetExtentMinusPrefixes`' prefix subtraction — is not ported. Text
  width is just the raw extent of the substring.
- No `DT_EDITCONTROL` (so a single over-long word is NOT split mid-word
  via binary search — it overflows onto its own line, matching a plain
  label control) and no ellipsis modes.

Caller supplies a ``measure(s) -> int`` callback that returns the pixel
extent of a string — the faithful analog of GDI's `GreGetTextExtentW`,
which sums each glyph's advance width. See `textmetrics.py`.

Reference call chain in the C source:
  DrawTextExW (multiline branch) -> DT_GetLineBreak -> GetNextWordbreak
                                                    -> DT_AdjustWhiteSpaces
"""

from __future__ import annotations

from collections.abc import Callable

# Win32 DrawText format flags (winuser.h) used here.
DT_LEFT = 0x0000
DT_CENTER = 0x0001
DT_RIGHT = 0x0002
DT_WORDBREAK = 0x0010
DT_NOPREFIX = 0x0800

_DT_HFMTMASK = 0x03

_CR = "\r"
_LF = "\n"

MeasureFn = Callable[[str], int]


def get_next_wordbreak(text: str, lpch: int, end: int, break_space: bool) -> int:
    """Port of `GetNextWordbreak` (drawtext.c). Returns the index of the
    next potential break position at/after `lpch`.

    `ichNonWhite` starts at 1 so that a scan beginning ON whitespace
    advances one past it (a lone leading space becomes its own segment);
    once any non-white char is consumed it drops to 0 so a following
    space breaks AT the space (trailing space stays with the next
    cumulative segment). CR/LF always break at their own position.
    """
    ich_non_white = 1
    while lpch < end:
        ch = text[lpch]
        if ch in (_CR, _LF):
            return lpch
        if ch in (" ", "\t") and break_space:
            return lpch + ich_non_white
        # Non-break char (or a space when not breaking on spaces, the C's
        # `/*** FALL THRU ***/`): consume it and clear the leading-white flag.
        lpch += 1
        ich_non_white = 0
    return lpch


def adjust_white_spaces(text: str, next_start: int, end: int, line_length: int,
                        fmt: int) -> tuple[int, int]:
    """Port of `DT_AdjustWhiteSpaces` (drawtext.c). At a wrap boundary,
    trim the whitespace that should not show given the justification:
    leading space off the next line (LEFT), trailing space off the
    current line (RIGHT), or both (CENTER). Returns the (possibly
    adjusted) `(next_start, line_length)`.
    """
    hfmt = fmt & _DT_HFMTMASK

    def is_ws(i: int) -> bool:
        return 0 <= i < len(text) and (text[i] == " " or text[i] == "\t")

    if hfmt == DT_LEFT:
        if next_start < end and is_ws(next_start):
            next_start += 1
    elif hfmt == DT_RIGHT:
        if is_ws(next_start - 1):
            line_length -= 1
    elif hfmt == DT_CENTER:
        if is_ws(next_start - 1):
            line_length -= 1
        if next_start < end and is_ws(next_start):
            next_start += 1
    return next_start, line_length


def get_line_break(text: str, line_start: int, count: int, fmt: int,
                   measure: MeasureFn, cx_max_width: int,
                   overhang: int = 0) -> tuple[int, int]:
    """Port of `DT_GetLineBreak` (drawtext.c). Finds where the current
    line ends.

    Returns `(next_line_start, line_length)` where `line_length` is the
    number of characters to draw on this line (CR/LF and trimmed
    whitespace excluded) and `next_line_start` is the index where the
    next line begins.

    The extent is measured cumulatively from `line_start` on every word
    (not summed per word) — faithful to the C, which does this so
    simulated-bold overhang accumulation matches the whole-line draw.
    """
    end = line_start + count
    lpch_text = line_start
    lpch_line_end = line_start
    lpch = line_start
    adjust = False

    while lpch_text < end:
        lpch_line_end = lpch = get_next_wordbreak(
            text, lpch_text, end, bool(fmt & DT_WORDBREAK)
        )
        # DT_DrawStr returns extent-minus-overhang; cumulative from line start.
        cx_new_extent = measure(text[line_start:lpch]) - overhang

        if (fmt & DT_WORDBREAK) and (cx_new_extent + overhang) > cx_max_width:
            if lpch_text != line_start:
                # More than one word on the line: break before this word.
                lpch_line_end = lpch = lpch_text
                adjust = True
            else:
                # A single word is wider than the line. A plain label
                # (no DT_EDITCONTROL) leaves the whole word on the line;
                # it overflows and is clipped by the caller's rect.
                adjust = True
            break
        else:
            if lpch < end:
                ch = text[lpch]
                if ch in (_CR, _LF):
                    lpch += 1
                    # Consume the partner of a CRLF / LFCR pair.
                    if lpch < end and text[lpch] == (_LF if ch == _CR else _CR):
                        lpch += 1
                    adjust = False
                    break

        lpch_text = lpch

    line_length = lpch_line_end - line_start
    if adjust and lpch < end:
        lpch, line_length = adjust_white_spaces(text, lpch, end, line_length, fmt)
    return lpch, line_length


def wrap_text(text: str, fmt: int, measure: MeasureFn, cx_max_width: int,
              overhang: int = 0) -> list[str]:
    """Multiline driver — the loop from `DrawTextExW`'s non-SINGLELINE
    branch. Returns the list of line strings DrawText would lay out for
    `text` in a rectangle `cx_max_width` pixels wide.

    With `DT_WORDBREAK` clear, lines break only at explicit CR/LF.
    """
    lines: list[str] = []
    cursor = 0
    count = len(text)
    while cursor < count:
        next_start, line_length = get_line_break(
            text, cursor, count - cursor, fmt, measure, cx_max_width, overhang
        )
        lines.append(text[cursor:cursor + line_length])
        if next_start <= cursor:
            # Defensive: guarantee forward progress (the C relies on
            # GetNextWordbreak always advancing; mirror that invariant).
            next_start = cursor + 1
        cursor = next_start
    return lines
