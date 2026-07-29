"""Flow a Story control's `TextTree` into positioned `TextItem`s.

BBVIEW hosts BBCTL.OCX's `CQtxtCtrl`, which runs a paragraph layout
engine over the element tree: each element picks a style, the style
supplies font / size / weight / indents / space-before / space-after,
and the prose flows and wraps inside the control's rect. The MSN
client has no such engine — MOSVIEW only replays the metafile MEDVIEW
ships in the page's `bm<n>` baggage — so the flow has to be baked
here, the same way caption word-wrap already is (`blackbird/drawtext.py`).

Geometry, measured against the BBVIEW reference render of
`story_title.ttl` at `reference/screenshots/story title.png` (640x480
page, Story rect 88,24-576,448 px, which BBVIEW scales ~1.64x to fill
its client area):

- Style points convert at 96 DPI, `px = pt * 96 / 72`. `List Bullet`'s
  18 pt left indent measures 24 px on the page — a quarter inch.
- The control insets its text by `_MARGIN_PT` on every side. Body text
  starts 13.7 px inside the rect's left edge, and the first heading's
  ink sits 13.1 px below the top once its 18 pt space-before comes
  off; 10 pt (13.3 px) fits both.
- A hanging-indent paragraph (`special_line_indent == 2`, which both
  list styles set) draws its bullet at `left_indent - indent_by` — 0
  for those styles, i.e. flush with the margin, as the render shows —
  and its text at `left_indent`.
- The bullet is drawn as a filled square. Which glyph BBVIEW uses is
  not recoverable from the style sheet — `CParaProps::IsBullet @
  0x40727338` is `GetRecurseBool(10)`, so the style says only whether
  a paragraph carries a marker — and the render's marker is a solid
  8x8 screen-pixel block, ~4.9 px on the page, its bottom edge half a
  side above the baseline. `_BULLET_SIDE_DIVISOR` and
  `_BULLET_RISE_DIVISOR` reproduce that from the paragraph's em size:
  at 11 pt they give a 5 px square, the closest integer. MOSVIEW
  scales the page to its window (~1.64x in the reference capture), so
  the square lands on 8-9 device pixels depending on where the edges
  round — that last pixel cannot be pre-compensated here, because the
  zoom is chosen at display time.
- An element with no prose contributes nothing, not even a blank line:
  the render's two empty `<P>`s leave no gap around the lists.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...blackbird import drawtext, textmetrics
from ...blackbird.wire import TextItem
from . import bbstyles
from .bbstyles import ResolvedStyle
from .ccontent import TextTreeNode

# Points -> pixels on the 96 DPI MM_TEXT surface the kind=8 baggage
# sets up (`build_kind8_baggage(mapmode=1)`).
_DPI = 96
_POINTS_PER_INCH = 72

# Interior inset of the Story control. Not a style-sheet property —
# CQtxtCtrl's own margin, measured off the reference render.
_MARGIN_PT = 10

# Bullet square, as fractions of the paragraph's em size.
_BULLET_SIDE_DIVISOR = 3
_BULLET_RISE_DIVISOR = 2

_FW_NORMAL = 400
_FW_BOLD = 700

# CParaProps::EGetJustify uses the same 0/1/2 left/right/centre
# ordering as BBDESIGN's iAlignment, which is what TextItem.alignment
# carries into `build_text_metafile`'s TA_* selection.
_JUSTIFY_LEFT = 0


@dataclass(frozen=True)
class Paragraph:
    """One drawable element: its resolved style plus its prose."""
    style: ResolvedStyle
    text: str


def _pt_to_px(points: int) -> int:
    return round(points * _DPI / _POINTS_PER_INCH)


def _em_px(style: ResolvedStyle) -> int:
    return max(1, _pt_to_px(style.pt_size))


def _metric(fn, style: ResolvedStyle, fallback: int) -> int:
    """Run one `textmetrics` lookup, degrading to `fallback` when the
    font directory or Pillow is missing rather than failing the render."""
    try:
        return fn(style.font_face, _em_px(style), style.bold, style.italic) or fallback
    except (OSError, ImportError):
        return fallback


def flatten_paragraphs(
    root: TextTreeNode,
    font_map: dict[int, str] | None = None,
) -> list[Paragraph]:
    """Walk the element tree in document order, one Paragraph per
    element that carries prose.

    Container tags (document / body / the two list tags) recurse
    without drawing. `HEAD` and everything under it is dropped.
    """
    out: list[Paragraph] = []
    list_tags = (bbstyles.TAG_UNORDERED_LIST, bbstyles.TAG_ORDERED_LIST)

    def visit(node: TextTreeNode, enclosing_list: int | None) -> None:
        if node.is_text or node.tag in bbstyles.SKIPPED_TAGS:
            return
        if node.tag in bbstyles.CONTAINER_TAGS:
            nested = node.tag if node.tag in list_tags else enclosing_list
            for child in node.children:
                visit(child, nested)
            return
        text = node.text
        if text.strip():
            out.append(Paragraph(
                style=bbstyles.resolve(
                    bbstyles.style_for_element(node.tag, enclosing_list),
                    font_map,
                ),
                text=text,
            ))
        for child in node.children:
            visit(child, enclosing_list)

    visit(root, None)
    return out


def _wrap(style: ResolvedStyle, text: str, width_px: int) -> list[str]:
    """Break `text` into the lines DrawText would lay out at
    `width_px`, measuring with the real font."""
    if width_px <= 0 or not text:
        return [text]
    try:
        measure = textmetrics.text_measurer(
            style.font_face, _em_px(style), style.bold, style.italic,
        )
    except (OSError, ImportError):
        return [text]
    fmt = drawtext.DT_WORDBREAK | drawtext.DT_NOPREFIX
    return drawtext.wrap_text(text, fmt, measure, width_px) or [text]


def _text_item(style: ResolvedStyle, x: int, y: int, text: str) -> TextItem:
    return TextItem(
        x=x,
        y=y,
        text=text,
        font_face=style.font_face,
        font_height=-_em_px(style),
        font_weight=_FW_BOLD if style.bold else _FW_NORMAL,
        italic=style.italic,
        underline=style.underline,
        color_rgb=style.fore_color,
        alignment=_JUSTIFY_LEFT,
        auto_size=True,
    )


def _bullet_item(style: ResolvedStyle, x: int, baseline_y: int) -> TextItem:
    """Filled square, drawn through `build_text_metafile`'s opaque-rect
    path: brush fill, PS_NULL pen, no TextOut."""
    side = max(2, _em_px(style) // _BULLET_SIDE_DIVISOR)
    return TextItem(
        x=x,
        y=baseline_y - side - side // _BULLET_RISE_DIVISOR,
        text="",
        color_rgb=style.fore_color,
        back_color=style.fore_color,
        transparent=False,
        rect_w=side,
        rect_h=side,
        auto_size=True,
    )


def layout_story(
    root: TextTreeNode,
    rect_px: tuple[int, int, int, int],
    font_map: dict[int, str] | None = None,
) -> list[TextItem]:
    """Lay a Story's element tree out inside `rect_px` (left, top,
    right, bottom in page pixels) and return the draw list.

    The first item paints the control's background in `Normal`'s back
    colour: MOSVIEW fills only the page background, from the sec06
    record, and would otherwise leave the Story's rect showing it.
    """
    left, top, right, bottom = rect_px
    paragraphs = flatten_paragraphs(root, font_map)
    if not paragraphs:
        return []

    margin = _pt_to_px(_MARGIN_PT)
    content_left = left + margin
    content_right = right - margin

    items: list[TextItem] = [TextItem(
        x=left,
        y=top,
        text="",
        back_color=bbstyles.resolve(bbstyles.NORMAL, font_map).back_color,
        transparent=False,
        rect_w=max(0, right - left),
        rect_h=max(0, bottom - top),
        auto_size=True,
    )]

    y = top + margin
    for para in paragraphs:
        style = para.style
        em = _em_px(style)
        line_h = _metric(textmetrics.line_height, style, em)
        text_left = content_left + _pt_to_px(style.left_indent)
        text_right = content_right - _pt_to_px(style.right_indent)

        y += _pt_to_px(style.space_before)
        if style.bullet:
            hanging = (
                _pt_to_px(style.indent_by)
                if style.special_line_indent == bbstyles.SPECIAL_INDENT_HANGING
                else 0
            )
            items.append(_bullet_item(
                style,
                text_left - hanging,
                y + _metric(textmetrics.ascent, style, em),
            ))
        for line in _wrap(style, para.text.rstrip(), text_right - text_left):
            items.append(_text_item(style, text_left, y, line))
            y += line_h
        y += _pt_to_px(style.space_after)

    return items
