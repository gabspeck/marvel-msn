"""Blackbird's built-in style sheet, lifted out of `VIEWDLL.DLL`.

A `.ttl` that never edits a style ships a `CStyleSheet` with
`style_entry_count = 0` (e.g. `tests/assets/story_title.ttl`). The
renderer still has to know what "Heading 1" looks like, because every
paragraph in a `TextTree` carries only an element tag — the character
and paragraph properties come from the viewer's default table.

Source: `VIEWDLL.DLL` static table at VA `0x40770e00`, 47 records of
0x34 bytes each (`CStyle::FindNameIndex @ 0x40708221` walks it to
`0x4077178c`, then walks a second 8-byte-stride table at `0x407717c0`
holding the 7 `Wrap: …` intrusion styles as name indices 47..53). The
same 54-slot index space keys the on-disk `CStyleSheet` style map.

Record fields, named from the accessors VIEWDLL exports (each is a
one-line thunk into `CParaProps::EGetShort`/`EGetWord` or
`CCharProps::EGetWord`, which read the object's own value and fall
back to `table[style_index]` at the offsets below when the object
holds the "unset" sentinel):

    +0x00  char*  style name
    +0x04  i16    based-on style index (-1 = none, `Normal` only)
    +0x08  i16    CStyle::IsCharacterStyle
    +0x0C  u16    CCharProps id 5 — character attributes, see below
    +0x10  i16    CCharProps id 3 — font id into the CStyleSheet font map
    +0x12  i16    CCharProps id 4 — point size
    +0x14  u32    fore COLORREF
    +0x18  u32    back COLORREF
    +0x1C  i16    CParaProps::EGetJustify           (id 0)
    +0x1E  i16    CParaProps::EGetInitialCaps       (id 11)
    +0x22  i16    CParaProps::EGetBullet            (id 10)
    +0x24  i16    CParaProps::EGetLineSpacingRule   (id 2)
    +0x26  i16    CParaProps::EGetIndentBy          (id 3)
    +0x28  i16    CParaProps::EGetLeftIndent        (id 4)
    +0x2A  i16    CParaProps::EGetRightIndent       (id 5)
    +0x2C  i16    CParaProps::EGetSpaceAt           (id 8)
    +0x2E  i16    CParaProps::EGetSpecialLineIndent (id 1)
    +0x30  i16    CParaProps::EGetSpaceBefore       (id 6)
    +0x32  i16    CParaProps::EGetSpaceAfter        (id 7)

Indents and spacing are points. `Heading 1` sets space-before 18 and
`List Bullet` sets left-indent 18 — a quarter inch, which is what the
BBVIEW reference render of `story_title.ttl` measures.

The +0x0C word packs the three character attributes as
`[u8 unset_mask][u8 values]`: `CCharProps::EGetBold @ 0x40727466`
tests `AH & 0x01` and, when clear, returns `AL & 0x02`; italic uses
`AH & 0x02` / `AL & 0x04`; underline `AH & 0x04` / `AL & 0x08`. A set
mask bit means the style leaves the attribute to its based-on chain —
which is how `Heading 2` (0x7F00, nothing of its own) still renders
bold: it inherits from `Heading 1` (0x7E02).

Font ids resolve through the title's own `CStyleSheet` font map. The
viewer's built-in map is the three faces VIEWDLL names right after
`<no style>`/`Normal` in its string pool, and every `.ttl` here
carries exactly that map.
"""

from __future__ import annotations

from dataclasses import dataclass

# Sentinels the table uses for "this style does not set the property".
UNSET_SHORT = -1
UNSET_COLOR = 0xFFFFFFFF

# +0x0C packing.
_ATTR_BOLD_MASK, _ATTR_BOLD_VALUE = 0x01, 0x02
_ATTR_ITALIC_MASK, _ATTR_ITALIC_VALUE = 0x02, 0x04
_ATTR_UNDERLINE_MASK, _ATTR_UNDERLINE_VALUE = 0x04, 0x08

# CParaProps::EGetSpecialLineIndent values.
SPECIAL_INDENT_NONE = 0
SPECIAL_INDENT_FIRST_LINE = 1
SPECIAL_INDENT_HANGING = 2

# Built-in font map — VIEWDLL string pool at VA 0x40770ce4..0x40770cf8.
DEFAULT_FONT_MAP: dict[int, str] = {
    1: "Times New Roman",
    2: "Arial",
    3: "Courier New",
}


@dataclass(frozen=True)
class BuiltinStyle:
    """One record of the VIEWDLL default table, fields unresolved."""
    index: int
    name: str
    based_on: int
    is_char_style: bool
    char_attrs: int                          # +0x0C, [u8 unset_mask][u8 values]
    font_id: int                             # 0 = inherit
    pt_size: int                             # 0 = inherit
    fore_color: int
    back_color: int
    justify: int
    bullet: int
    indent_by: int
    left_indent: int
    right_indent: int
    special_line_indent: int
    space_before: int
    space_after: int


@dataclass(frozen=True)
class ResolvedStyle:
    """A style with its based-on chain collapsed. Points for every
    length; `font_face` is already mapped through the title's font
    map."""
    name: str
    font_face: str
    pt_size: int
    bold: bool
    italic: bool
    underline: bool
    fore_color: int
    back_color: int
    justify: int
    bullet: bool
    indent_by: int
    left_indent: int
    right_indent: int
    special_line_indent: int
    space_before: int
    space_after: int


# (index, name, based_on, is_char_style, char_attrs, font_id, pt_size,
#  fore, back, justify, bullet, indent_by, left_indent, right_indent,
#  special_line_indent, space_before, space_after)
_TABLE: tuple[tuple, ...] = (
    (0,  "Normal",           -1, 0, 0x0000, 1, 11, 0x000000, 0xFFFFFF,  0, 0,  0,   0,  0,  0,  0, 11),
    (1,  "Heading 1",         0, 0, 0x7E02, 2, 22, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, 18,  0),
    (2,  "Heading 2",         1, 0, 0x7F00, 0, 18, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, 14, -1),
    (3,  "Heading 3",         2, 0, 0x7F00, 0, 14, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, 12, -1),
    (4,  "Heading 4",         3, 0, 0x7D04, 0, 12, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (5,  "Heading 5",         4, 0, 0x7E02, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (6,  "Heading 6",         5, 0, 0x7D04, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (7,  "TOC 1",             0, 0, 0x7E02, 2, 12, 0x000080, UNSET_COLOR,  0, 0, -1,  18, -1, -1, -1, -1),
    (8,  "TOC 2",             7, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  36, -1, -1, -1, -1),
    (9,  "TOC 3",             8, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  54, -1, -1, -1, -1),
    (10, "TOC 4",             9, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  72, -1, -1, -1, -1),
    (11, "TOC 5",            10, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  90, -1, -1, -1, -1),
    (12, "TOC 6",            11, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, 108, -1, -1, -1, -1),
    (13, "TOC 7",            12, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, 126, -1, -1, -1, -1),
    (14, "TOC 8",            13, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, 144, -1, -1, -1, -1),
    (15, "TOC 9",            14, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, 162, -1, -1, -1, -1),
    (16, "Section 1",         0, 0, 0x7E02, 2, 14, 0x808000, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (17, "Section 2",        16, 0, 0x7F00, 0, 12, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (18, "Section 3",        17, 0, 0x7F00, 0, 10, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (19, "Section 4",        18, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (20, "Section 5",        19, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (21, "Section 6",        20, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (22, "Section 7",        21, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (23, "Section 8",        22, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (24, "Section 9",        23, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (25, "Abstract Heading",  0, 0, 0x7E02, 1, 22, UNSET_COLOR, UNSET_COLOR,  2, 0, -1,  -1, -1, -1, -1, -1),
    (26, "Term Definition",   0, 0, 0x7F00, 0,  8, UNSET_COLOR, UNSET_COLOR, -1, 0, 36,  36, -1,  2, -1, -1),
    (27, "List Bullet",       0, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 1, 18,  18, -1,  2, -1, -1),
    (28, "List Number",       0, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 1, 18,  18, -1,  2, -1, -1),
    (29, "Term",              0, 1, 0x7E02, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (30, "Hyperlink",         0, 1, 0x7B08, 0,  0, 0xFF0000, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (31, "Emphasized",        0, 1, 0x7D04, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (32, "Bold",              0, 1, 0x7E02, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (33, "Italic",            0, 1, 0x7D04, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (34, "Strikethrough",     0, 1, 0x7B08, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (35, "Preformatted",      0, 0, 0x7F00, 3,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (36, "Blockquote",        0, 0, 0x7D04, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  36, 36, -1, -1, -1),
    (37, "Address",           0, 0, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (38, "Underline",         0, 1, 0x7B08, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (39, "Strong",            0, 1, 0x7E02, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (40, "Code",              0, 1, 0x7F00, 3,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (41, "Keyboard",          0, 1, 0x7C06, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (42, "Citation",          0, 1, 0x7F00, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (43, "Variable Name",     0, 1, 0x7C06, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (44, "Fixed Width",       0, 1, 0x7F00, 3,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (45, "Abstract Body",     0, 0, 0x7D04, 1,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    (46, "Sample",            0, 1, 0x750A, 0,  0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1,  -1, -1, -1, -1, -1),
    # Name indices 47..53 — the 8-byte intrusion table. They carry an
    # intrusion kind, not character or paragraph properties.
    (47, "Wrap: Design feature",     0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
    (48, "Wrap: Supporting graphic", 0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
    (49, "Wrap: Related graphic",    0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
    (50, "Wrap: Sidebar graphic",    0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
    (51, "Wrap: Advertisement",      0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
    (52, "Wrap: Custom 1",           0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
    (53, "Wrap: Custom 2",           0, 0, 0x7F00, 0, 0, UNSET_COLOR, UNSET_COLOR, -1, 0, -1, -1, -1, -1, -1, -1),
)

BUILTIN_STYLES: tuple[BuiltinStyle, ...] = tuple(
    BuiltinStyle(
        index=row[0], name=row[1], based_on=row[2], is_char_style=bool(row[3]),
        char_attrs=row[4], font_id=row[5], pt_size=row[6],
        fore_color=row[7], back_color=row[8], justify=row[9], bullet=row[10],
        indent_by=row[11], left_indent=row[12], right_indent=row[13],
        special_line_indent=row[14], space_before=row[15], space_after=row[16],
    )
    for row in _TABLE
)

STYLE_BY_NAME: dict[str, BuiltinStyle] = {s.name: s for s in BUILTIN_STYLES}

NORMAL = STYLE_BY_NAME["Normal"]


# --------------------------------------------------------------------------
# TextTree element tags
# --------------------------------------------------------------------------

# Element tags carried by `CElementNode` records in a `TextTree` body.
# Pinned by pairing a title's Story resource against its parsed tree:
# `story_title.ttl` embeds `Story.bdf`, whose `BBML/BODY` stream reads
# `<H1>Story title</H1> <P>…</P> <H2>Second heading</H2> <P>…</P>
# <OL><LI>…</LI>×3</OL> <P></P> <UL><LI>…</LI>×3</UL> <P></P>`, and its
# tree is the same sequence of tags 7, 6, 8, 6, 1D(1E×3), 6, 1C(1E×3), 6
# under 0C, itself under 05 alongside an empty 0B. `story_test.ttl 8/2`
# repeats the 05/0B/0C/07/06 spine.
#
# The tags BBML declares but no fixture exercises (H3..H6, DL, PRE,
# TOC, …) are not in this map — the DTD's full element numbering is not
# recovered, and guessing it would put the wrong style on a paragraph.
# `style_for_element` falls back to Normal, which is what an unstyled
# BBML paragraph renders as anyway.
TAG_DOCUMENT = 0x05
TAG_PARAGRAPH = 0x06
TAG_HEADING_1 = 0x07
TAG_HEADING_2 = 0x08
TAG_HEAD = 0x0B
TAG_BODY = 0x0C
TAG_UNORDERED_LIST = 0x1C
TAG_ORDERED_LIST = 0x1D
TAG_LIST_ITEM = 0x1E

# Structural tags that hold children but draw nothing themselves.
CONTAINER_TAGS = frozenset({
    TAG_DOCUMENT, TAG_BODY, TAG_UNORDERED_LIST, TAG_ORDERED_LIST,
})

# Tags dropped along with everything under them.
SKIPPED_TAGS = frozenset({TAG_HEAD})

_TAG_STYLE_NAME: dict[int, str] = {
    TAG_PARAGRAPH: "Normal",
    TAG_HEADING_1: "Heading 1",
    TAG_HEADING_2: "Heading 2",
}

# A list item takes its style from the list that encloses it — BBML has
# one `<LI>` element and two list containers, matching VIEWDLL's split
# into `List Bullet` / `List Number`.
_LIST_STYLE_NAME: dict[int, str] = {
    TAG_UNORDERED_LIST: "List Bullet",
    TAG_ORDERED_LIST: "List Number",
}


def style_for_element(tag: int, enclosing_list: int | None = None) -> BuiltinStyle:
    """Built-in style a `TextTree` element tag paints with. Unknown tags
    take `Normal`."""
    if tag == TAG_LIST_ITEM and enclosing_list in _LIST_STYLE_NAME:
        return STYLE_BY_NAME[_LIST_STYLE_NAME[enclosing_list]]
    return STYLE_BY_NAME.get(_TAG_STYLE_NAME.get(tag, ""), NORMAL)


# --------------------------------------------------------------------------
# based-on chain resolution
# --------------------------------------------------------------------------


def _chain(style: BuiltinStyle) -> list[BuiltinStyle]:
    """`style` first, then each based-on ancestor. Self-referencing or
    cyclic tables stop at the first repeat."""
    out: list[BuiltinStyle] = []
    seen: set[int] = set()
    cur: BuiltinStyle | None = style
    while cur is not None and cur.index not in seen:
        seen.add(cur.index)
        out.append(cur)
        cur = (
            BUILTIN_STYLES[cur.based_on]
            if 0 <= cur.based_on < len(BUILTIN_STYLES)
            else None
        )
    return out


def _first_set(chain: list[BuiltinStyle], attr: str, unset) -> int:
    for style in chain:
        value = getattr(style, attr)
        if value != unset:
            return value
    return 0


def _first_attr(chain: list[BuiltinStyle], mask_bit: int, value_bit: int) -> bool:
    """Walk the chain for the nearest style that defines one character
    attribute (its unset-mask bit clear) and return that style's value
    bit. Defined-nowhere reads as off."""
    for style in chain:
        if not (style.char_attrs >> 8) & mask_bit:
            return bool(style.char_attrs & value_bit)
    return False


def resolve(style: BuiltinStyle, font_map: dict[int, str] | None = None) -> ResolvedStyle:
    """Collapse `style`'s based-on chain. `font_map` is the title's
    `CStyleSheet` font map; the built-in map fills any gap."""
    chain = _chain(style)
    fonts = dict(DEFAULT_FONT_MAP)
    if font_map:
        fonts.update(font_map)
    font_id = _first_set(chain, "font_id", 0)
    return ResolvedStyle(
        name=style.name,
        font_face=fonts.get(font_id, DEFAULT_FONT_MAP[1]),
        pt_size=_first_set(chain, "pt_size", 0) or NORMAL.pt_size,
        bold=_first_attr(chain, _ATTR_BOLD_MASK, _ATTR_BOLD_VALUE),
        italic=_first_attr(chain, _ATTR_ITALIC_MASK, _ATTR_ITALIC_VALUE),
        underline=_first_attr(chain, _ATTR_UNDERLINE_MASK, _ATTR_UNDERLINE_VALUE),
        fore_color=_first_set(chain, "fore_color", UNSET_COLOR),
        back_color=_first_set(chain, "back_color", UNSET_COLOR),
        justify=_first_set(chain, "justify", UNSET_SHORT),
        bullet=bool(_first_set(chain, "bullet", UNSET_SHORT)),
        indent_by=_first_set(chain, "indent_by", UNSET_SHORT),
        left_indent=_first_set(chain, "left_indent", UNSET_SHORT),
        right_indent=_first_set(chain, "right_indent", UNSET_SHORT),
        special_line_indent=_first_set(chain, "special_line_indent", UNSET_SHORT),
        space_before=_first_set(chain, "space_before", UNSET_SHORT),
        space_after=_first_set(chain, "space_after", UNSET_SHORT),
    )
