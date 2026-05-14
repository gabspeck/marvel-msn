"""Parse a compiled Microsoft Multimedia Viewer 2.0 (MVB) file and lower
its content to MEDVIEW wire.

Format reference: `docs/helpfile.txt` (HELPDECO HC30/HC31/MVB/HCRTF).
Sample fixture: `resources/titles/NO_NSR.MVB` (10709 B, Minor=27 mmvc).

Scope (first cut): parse |SYSTEM (TITLE + MVBWINDOW), |FONT (mvbfont
descriptors), and the first displayable-text TOPICLINK out of |TOPIC.
LZ77 compression not yet handled — NO_NSR.MVB has |SYSTEM Flags=0
(uncompressed 4 KB blocks); compressed builds will raise on parse.
Pictures, hotspots, jumps, table records, phrase compression all raise
`NotImplementedError`. The parser keeps the first paragraph's text and
its authored paragraph indents — that's everything the case-1 BF chunk
needs to render one row.
"""

from __future__ import annotations

import logging
import pathlib
import struct
from dataclasses import dataclass

from ...blackbird.wire import (
    build_baggage_container,
    build_case1_bf_chunk,
    build_kind5_raster,
    build_trailer,
)

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Compressed integer decoders (helpfile.txt §"Data inside LinkData1")
# --------------------------------------------------------------------------


def _compressed_ushort(buf: bytes, pos: int) -> tuple[int, int]:
    """1 byte if even (value/2), 2 bytes if odd (value/2 + 128*next)."""
    b = buf[pos]
    if (b & 1) == 0:
        return (b >> 1, pos + 1)
    return ((b >> 1) + 128 * buf[pos + 1], pos + 2)


def _compressed_short(buf: bytes, pos: int) -> tuple[int, int]:
    """Signed: even = byte/2 - 64; odd = byte/2 + 128*next - 16384."""
    b = buf[pos]
    if (b & 1) == 0:
        return ((b >> 1) - 64, pos + 1)
    return ((b >> 1) + 128 * buf[pos + 1] - 16384, pos + 2)


def _compressed_ulong(buf: bytes, pos: int) -> tuple[int, int]:
    """2 bytes if even (word/2), 4 bytes if odd (word/2 + 32768*next_word)."""
    word = struct.unpack_from("<H", buf, pos)[0]
    if (word & 1) == 0:
        return (word >> 1, pos + 2)
    nxt = struct.unpack_from("<H", buf, pos + 2)[0]
    return ((word >> 1) + 32768 * nxt, pos + 4)


def _compressed_long(buf: bytes, pos: int) -> tuple[int, int]:
    """Signed compressed long."""
    word = struct.unpack_from("<H", buf, pos)[0]
    if (word & 1) == 0:
        return ((word >> 1) - 16384, pos + 2)
    nxt = struct.unpack_from("<H", buf, pos + 2)[0]
    return ((word >> 1) + 32768 * nxt - 67108864, pos + 4)


# --------------------------------------------------------------------------
# File header + internal directory B+ tree
# --------------------------------------------------------------------------

_FILE_MAGIC = 0x00035F3F
_BTREE_MAGIC = 0x293B
_INTERNAL_FILE_HEADER_SIZE = 9  # ReservedSpace(4) + UsedSpace(4) + Flags(1)


def _internal_file_content(buf: bytes, file_offset: int) -> tuple[int, int]:
    """Read the per-file FILEHEADER. Returns (used_space, content_offset)."""
    _reserved, used = struct.unpack_from("<II", buf, file_offset)
    return (used, file_offset + _INTERNAL_FILE_HEADER_SIZE)


def _read_directory(buf: bytes, dir_offset: int) -> dict[str, int]:
    """Walk the directory B+ tree. Returns `name → file_offset`."""
    _used, content = _internal_file_content(buf, dir_offset)
    btree = content
    magic, _flags, page_size = struct.unpack_from("<HHH", buf, btree)
    if magic != _BTREE_MAGIC:
        raise ValueError(f"directory B+ tree magic mismatch: 0x{magic:04x}")
    structure = buf[btree + 6:btree + 22].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    if not structure.startswith("z"):
        raise ValueError(f"unexpected directory B+ tree structure: {structure!r}")
    root_page = struct.unpack_from("<H", buf, btree + 26)[0]
    n_levels = struct.unpack_from("<H", buf, btree + 32)[0]
    if n_levels != 1:
        raise NotImplementedError(
            f"directory B+ tree with NLevels={n_levels} not supported"
        )

    btree_header_size = 38
    page_offset = btree + btree_header_size + root_page * page_size
    # Leaf-page header: Unused(2), NEntries(2), PreviousPage(2), NextPage(2).
    n_entries = struct.unpack_from("<h", buf, page_offset + 2)[0]

    entries: dict[str, int] = {}
    pos = page_offset + 8
    for _ in range(n_entries):
        end = buf.index(b"\x00", pos)
        name = buf[pos:end].decode("ascii", errors="replace")
        pos = end + 1
        file_offset = struct.unpack_from("<I", buf, pos)[0]
        pos += 4
        entries[name] = file_offset
    return entries


# --------------------------------------------------------------------------
# |SYSTEM — SystemHeader + SYSTEMREC stream
# --------------------------------------------------------------------------

_SYSTEM_MAGIC = 0x036C
_SYSTEM_HEADER_SIZE = 12  # Magic(2) + Minor(2) + Major(2) + GenDate(4) + Flags(2)

_REC_TITLE = 1
_REC_WINDOW = 6

# MVBWINDOW field offsets (per helpfile.txt §6 WINDOW Viewer 2.0 form).
_MVBWIN_CAPTION_OFF = 0x15
_MVBWIN_CAPTION_LEN = 51
_MVBWIN_MORE_FLAGS_OFF = 0x48
_MVBWIN_DIMS_OFF = 0x49     # X, Y, Width, Height — i16 × 4 (per-mille 0..1000)
_MVBWIN_MAXIMIZE_OFF = 0x51
_MVBWIN_RGB1_OFF = 0x53     # SR background
_MVBWIN_RGB2_OFF = 0x58     # NSR background
_MVBWIN_RGB3_OFF = 0x5C     # separator / "Rgb3"


@dataclass(frozen=True)
class MvbWindow:
    caption: str
    x_permille: int
    y_permille: int
    width_permille: int
    height_permille: int
    maximize: int
    rgb_sr: int
    rgb_nsr: int


@dataclass(frozen=True)
class MvbSystem:
    title: str
    minor: int
    flags: int                  # 0 = uncompressed, 4 = LZ77+4 KB, 8 = LZ77+2 KB
    window: MvbWindow | None


def _parse_mvbwindow(data: bytes) -> MvbWindow:
    if len(data) < 0x6C:
        raise ValueError(f"MVBWINDOW data too short: {len(data)} B")
    caption_bytes = data[
        _MVBWIN_CAPTION_OFF:_MVBWIN_CAPTION_OFF + _MVBWIN_CAPTION_LEN
    ]
    caption = caption_bytes.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    x, y, width, height = struct.unpack_from("<hhhh", data, _MVBWIN_DIMS_OFF)
    maximize = struct.unpack_from("<h", data, _MVBWIN_MAXIMIZE_OFF)[0]
    rgb1 = struct.unpack_from("<I", data, _MVBWIN_RGB1_OFF)[0]
    rgb2 = struct.unpack_from("<I", data, _MVBWIN_RGB2_OFF)[0]
    return MvbWindow(
        caption=caption,
        x_permille=x,
        y_permille=y,
        width_permille=width,
        height_permille=height,
        maximize=maximize,
        rgb_sr=rgb1,
        rgb_nsr=rgb2,
    )


def _parse_system(buf: bytes, system_file_offset: int) -> MvbSystem:
    used, content = _internal_file_content(buf, system_file_offset)
    end = content + used

    magic, minor, _major = struct.unpack_from("<HHH", buf, content)
    if magic != _SYSTEM_MAGIC:
        raise ValueError(f"|SYSTEM magic mismatch: 0x{magic:04x}")
    flags = struct.unpack_from("<H", buf, content + 10)[0]

    title = ""
    window: MvbWindow | None = None

    pos = content + _SYSTEM_HEADER_SIZE
    while pos + 4 <= end:
        rec_type, data_size = struct.unpack_from("<HH", buf, pos)
        pos += 4
        data = buf[pos:pos + data_size]
        pos += data_size
        if rec_type == _REC_TITLE:
            title = data.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        elif rec_type == _REC_WINDOW:
            window = _parse_mvbwindow(data)

    return MvbSystem(title=title, minor=minor, flags=flags, window=window)


# --------------------------------------------------------------------------
# |FONT — mvbfont descriptor array
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MvbFontDescriptor:
    face_name: str
    height_twips: int           # signed; negative = excludes external leading
    weight: int                 # 400 = FW_NORMAL
    italic: bool
    fg_rgb: int                 # COLORREF


def _parse_font(buf: bytes, font_file_offset: int) -> tuple[MvbFontDescriptor, ...]:
    """Parse |FONT face names + descriptors.

    The descriptor record layout varies with `FacenamesOffset` (oldfont /
    newfont / mvbfont per helpfile.txt §|FONT). NO_NSR.MVB has
    FacenamesOffset=8 and 11-byte descriptor slots whose field layout
    doesn't match HELPDECO's published oldfont struct cleanly — likely a
    pre-public MVB build. Until that's RE'd, we extract face names
    (NUL-terminated within their stride) and synthesise default descriptor
    metadata pointing at face[0]. sec0 still gets a populated font table;
    only per-descriptor size/weight inheritance is lossy.
    """
    _used, content = _internal_file_content(buf, font_file_offset)
    num_facenames, num_descriptors, facenames_off, descriptors_off = struct.unpack_from(
        "<HHHH", buf, content,
    )
    face_stride = (descriptors_off - facenames_off) // max(num_facenames, 1)
    face_names: list[str] = []
    for i in range(num_facenames):
        off = content + facenames_off + i * face_stride
        raw = buf[off:off + face_stride]
        face_names.append(
            raw.split(b"\x00", 1)[0].decode("ascii", errors="replace"),
        )

    primary_face = next((n for n in face_names if n), "")
    return tuple(
        MvbFontDescriptor(
            face_name=primary_face,
            height_twips=-240,        # 12 pt default at 20 twips/pt
            weight=400,
            italic=False,
            fg_rgb=0,
        )
        for _ in range(num_descriptors)
    )


# --------------------------------------------------------------------------
# |TOPIC — TOPICBLOCKHEADER → walk TOPICLINKs → first displayable text
# --------------------------------------------------------------------------

_TOPICBLOCK_HEADER_SIZE = 12  # LastTopicLink + FirstTopicLink + LastTopicHeader
_TOPICLINK_HEADER_SIZE = 21   # BlockSize + DataLen2 + PrevBlock + NextBlock + DataLen1 + RecordType

_TOPICLINK_TYPE_HEADER = 2
_TOPICLINK_TYPE_DISPLAY = 0x20
_TOPICLINK_TYPE_TABLE = 0x23

_PARAGRAPH_BIT_UNKNOWN = 0x0001
_PARAGRAPH_BIT_SPACE_ABOVE = 0x0002
_PARAGRAPH_BIT_SPACE_BELOW = 0x0004
_PARAGRAPH_BIT_SPACE_LINES = 0x0008
_PARAGRAPH_BIT_LEFT_INDENT = 0x0010
_PARAGRAPH_BIT_RIGHT_INDENT = 0x0020
_PARAGRAPH_BIT_FIRSTLINE_INDENT = 0x0040
_PARAGRAPH_BIT_BORDER = 0x0100
_PARAGRAPH_BIT_TABS = 0x0200


@dataclass(frozen=True)
class MvbParagraph:
    text: str
    left_indent_twips: int
    right_indent_twips: int
    first_line_indent_twips: int
    space_above_twips: int
    space_below_twips: int
    font_idx: int               # first 0x80 FontNumber control byte; 0 if none


@dataclass(frozen=True)
class MvbTopicHeader:
    non_scroll: int             # TOPICPOS, 0xFFFFFFFF = no NSR
    scroll: int                 # TOPICPOS
    next_topic: int             # TOPICPOS
    topic_num: int
    title: str                  # LinkData2 first string (used for $-footnote)


def _topic_block_size(flags: int) -> int:
    """Per helpfile.txt: Flags=0 → 4 KB (uncompressed), 4 → 4 KB (LZ77),
    8 → 2 KB (LZ77). Minor <= 16 → 2 KB but we only support MVB (Minor=27)."""
    if flags in (0, 4):
        return 4096
    if flags == 8:
        return 2048
    raise NotImplementedError(f"|SYSTEM Flags=0x{flags:x} not supported")


def _parse_topic_block(buf: bytes, content_offset: int, flags: int) -> bytes:
    """Read one TOPICBLOCKHEADER + decompress the block body if needed.
    Returns the **decompressed buffer** that TOPICPOS offsets index into.
    """
    if flags != 0:
        raise NotImplementedError(
            f"LZ77-compressed |TOPIC (Flags={flags}) not yet supported"
        )
    return buf[content_offset + _TOPICBLOCK_HEADER_SIZE:]


def _read_topiclink_header(buf: bytes, pos: int) -> dict:
    """Decode the 21-byte TOPICLINK header at `pos`."""
    block_size, data_len2, prev, nxt, data_len1 = struct.unpack_from(
        "<iiiii", buf, pos
    )
    record_type = buf[pos + 20]
    return {
        "block_size": block_size,
        "data_len2": data_len2,
        "prev": prev,
        "next": nxt,
        "data_len1": data_len1,
        "record_type": record_type,
    }


def _parse_topic_header_record(link_data1: bytes, link_data2: bytes) -> MvbTopicHeader:
    """RecordType 2 (HC31 form): seven longs + topic-title in LinkData2."""
    if len(link_data1) < 28:
        raise ValueError(f"TOPICHEADER LinkData1 too short: {len(link_data1)} B")
    _block, _bck, _fwd, topic_num, non_scroll, scroll, next_topic = struct.unpack_from(
        "<iiiiIII", link_data1, 0
    )
    title = link_data2.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return MvbTopicHeader(
        non_scroll=non_scroll,
        scroll=scroll,
        next_topic=next_topic,
        topic_num=topic_num,
        title=title,
    )


def _parse_paragraph_info(link_data1: bytes, pos: int) -> tuple[dict, int]:
    """Parse Paragraphinfo struct, returning (field_dict, new_pos)."""
    # unknownUnsignedChar(1), unknownBiasedChar(1), id(2), bits(2)
    pos += 1 + 1 + 2
    bits = struct.unpack_from("<H", link_data1, pos)[0]
    pos += 2

    fields = {"left_indent": 0, "right_indent": 0, "first_line_indent": 0,
              "space_above": 0, "space_below": 0}

    if bits & _PARAGRAPH_BIT_UNKNOWN:
        _v, pos = _compressed_long(link_data1, pos)
    if bits & _PARAGRAPH_BIT_SPACE_ABOVE:
        fields["space_above"], pos = _compressed_short(link_data1, pos)
    if bits & _PARAGRAPH_BIT_SPACE_BELOW:
        fields["space_below"], pos = _compressed_short(link_data1, pos)
    if bits & _PARAGRAPH_BIT_SPACE_LINES:
        _v, pos = _compressed_short(link_data1, pos)
    if bits & _PARAGRAPH_BIT_LEFT_INDENT:
        fields["left_indent"], pos = _compressed_short(link_data1, pos)
    if bits & _PARAGRAPH_BIT_RIGHT_INDENT:
        fields["right_indent"], pos = _compressed_short(link_data1, pos)
    if bits & _PARAGRAPH_BIT_FIRSTLINE_INDENT:
        fields["first_line_indent"], pos = _compressed_short(link_data1, pos)
    if bits & _PARAGRAPH_BIT_BORDER:
        # Borderinfo: 1B flags + 2B BorderWidth = 3B
        pos += 3
    if bits & _PARAGRAPH_BIT_TABS:
        n_tabs, pos = _compressed_short(link_data1, pos)
        for _ in range(n_tabs):
            tab, pos = _compressed_ushort(link_data1, pos)
            if tab & 0x4000:
                _ttype, pos = _compressed_ushort(link_data1, pos)
    return fields, pos


def _parse_displayable_text(
    link_data1: bytes, link_data2: bytes, record_type: int,
) -> MvbParagraph:
    """Parse the first paragraph of a RecordType 0x20 TOPICLINK."""
    if record_type == _TOPICLINK_TYPE_TABLE:
        raise NotImplementedError("RecordType 0x23 (table) not supported")

    pos = 0
    _topic_size, pos = _compressed_long(link_data1, pos)
    _topic_length, pos = _compressed_ushort(link_data1, pos)
    para_fields, pos = _parse_paragraph_info(link_data1, pos)

    # Character formatting commands: pair each with the next NUL-terminated
    # string from LinkData2. Stop at 0xFF (end of formatting).
    font_idx = 0
    text_parts: list[str] = []
    str_pos = 0

    def next_string() -> str:
        nonlocal str_pos
        end = link_data2.index(b"\x00", str_pos)
        s = link_data2[str_pos:end].decode("ascii", errors="replace")
        str_pos = end + 1
        return s

    if str_pos < len(link_data2):
        text_parts.append(next_string())

    while pos < len(link_data1):
        cmd = link_data1[pos]
        pos += 1
        if cmd == 0xFF:                  # end of formatting
            break
        if cmd == 0x80:                  # FontNumber (2 bytes)
            font_idx = struct.unpack_from("<H", link_data1, pos)[0]
            pos += 2
        elif cmd == 0x81:                # line break
            text_parts.append("\n")
        elif cmd == 0x82:                # end-of-paragraph; pull next string
            break
        elif cmd == 0x83:                # tab
            text_parts.append("\t")
        elif cmd == 0x8B:                # non-break space
            text_parts.append(" ")
        elif cmd == 0x8C:                # non-break hyphen
            text_parts.append("-")
        elif cmd in (0x20, 0x21):        # vfld / dtype — 4-byte arg
            pos += 4
        elif cmd == 0x89:                # end of hotspot (no payload)
            pass
        else:
            raise NotImplementedError(
                f"unsupported formatting command 0x{cmd:02x} at LinkData1+{pos-1}"
            )
        if str_pos < len(link_data2):
            text_parts.append(next_string())

    text = "".join(c for c in "".join(text_parts) if c >= " " or c in ("\n", "\t"))
    return MvbParagraph(
        text=text,
        left_indent_twips=para_fields["left_indent"],
        right_indent_twips=para_fields["right_indent"],
        first_line_indent_twips=para_fields["first_line_indent"],
        space_above_twips=para_fields["space_above"],
        space_below_twips=para_fields["space_below"],
        font_idx=font_idx,
    )


def _walk_topic(
    buf: bytes, topic_file_offset: int, flags: int,
) -> tuple[MvbTopicHeader, MvbParagraph]:
    """Walk |TOPIC's first block and return the first TOPICHEADER plus the
    first RecordType 0x20 paragraph that follows it."""
    _used, content = _internal_file_content(buf, topic_file_offset)
    # TOPICBLOCKHEADER at content[0..12].
    first_link = struct.unpack_from("<i", buf, content + 4)[0]
    block = _parse_topic_block(buf, content, flags)
    # TOPICPOS encodes block + offset; for the first block, offset = (pos-12).
    block_offset = first_link - _TOPICBLOCK_HEADER_SIZE
    topic_header: MvbTopicHeader | None = None
    paragraph: MvbParagraph | None = None

    pos = block_offset
    while pos < len(block):
        hdr = _read_topiclink_header(block, pos)
        if hdr["block_size"] <= 0:
            break
        link_data1_start = pos + _TOPICLINK_HEADER_SIZE
        link_data1_size = hdr["data_len1"] - _TOPICLINK_HEADER_SIZE
        link_data1 = block[link_data1_start:link_data1_start + link_data1_size]
        link_data2_start = link_data1_start + link_data1_size
        link_data2_size = hdr["block_size"] - hdr["data_len1"]
        link_data2 = block[link_data2_start:link_data2_start + link_data2_size]

        if hdr["data_len2"] > link_data2_size:
            raise NotImplementedError("phrase-compressed LinkData2 not supported")

        if hdr["record_type"] == _TOPICLINK_TYPE_HEADER and topic_header is None:
            topic_header = _parse_topic_header_record(link_data1, link_data2)
        elif hdr["record_type"] == _TOPICLINK_TYPE_DISPLAY and paragraph is None:
            paragraph = _parse_displayable_text(
                link_data1, link_data2, hdr["record_type"],
            )
            break

        # Advance to next TOPICLINK via NextBlock (TOPICPOS).
        if hdr["next"] in (0, -1):
            break
        pos = hdr["next"] - _TOPICBLOCK_HEADER_SIZE

    if topic_header is None:
        raise ValueError("no TOPICHEADER record found in first |TOPIC block")
    if paragraph is None:
        # Empty topic — synthesize an empty paragraph so the lowering path
        # still has something to push (the layout walker's "skip row" form).
        paragraph = MvbParagraph(
            text="", left_indent_twips=0, right_indent_twips=0,
            first_line_indent_twips=0, space_above_twips=0, space_below_twips=0,
            font_idx=0,
        )
    return topic_header, paragraph


# --------------------------------------------------------------------------
# LoadedMVB + public entry
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LoadedMVB:
    title: str                                  # |SYSTEM RecordType 1
    caption: str                                # MVBWINDOW Caption
    window_dims_permille: tuple[int, int, int, int]  # X, Y, W, H (0..1000)
    font_table: tuple[MvbFontDescriptor, ...]
    non_scroll: int                             # TOPICHEADER NonScroll
    first_paragraph: MvbParagraph


def load_mvb(path: pathlib.Path) -> LoadedMVB | None:
    """Read a compiled MVB and return a LoadedMVB, or None on any failure."""
    try:
        buf = path.read_bytes()
    except OSError as exc:
        log.info("load_mvb path=%s open_failed=%r", path, exc)
        return None

    if len(buf) < 16:
        log.info("load_mvb path=%s too_small=%d", path, len(buf))
        return None
    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic != _FILE_MAGIC:
        log.info("load_mvb path=%s bad_magic=0x%08x", path, magic)
        return None

    try:
        dir_start = struct.unpack_from("<I", buf, 4)[0]
        directory = _read_directory(buf, dir_start)
        system = _parse_system(buf, directory["|SYSTEM"])
        fonts = _parse_font(buf, directory["|FONT"])
        topic_header, paragraph = _walk_topic(
            buf, directory["|TOPIC"], system.flags,
        )
    except Exception as exc:
        log.info("load_mvb path=%s parse_failed=%r", path, exc)
        return None

    win = system.window
    if win is None:
        log.info("load_mvb path=%s missing_mvbwindow", path)
        return None

    return LoadedMVB(
        title=system.title,
        caption=win.caption,
        window_dims_permille=(
            win.x_permille, win.y_permille, win.width_permille, win.height_permille,
        ),
        font_table=fonts,
        non_scroll=topic_header.non_scroll,
        first_paragraph=paragraph,
    )


# --------------------------------------------------------------------------
# Lowering: LoadedMVB → 9-section title body
# --------------------------------------------------------------------------

_SEC0_HEADER_SIZE = 0x12
_SEC0_FACE_ENTRY_SIZE = 0x20
_SEC0_DESCRIPTOR_SIZE = 0x2A
_SEC0_POINTER_ENTRY_SIZE = 0x04

_SEC06_RECORD_SIZE = 0x98
_SEC06_FLAG_INNER_RECT_ABSOLUTE = 0x08
_SEC06_COLOR_INHERIT = 0xFFFFFFFF
_SEC06_RECT_INHERIT = (-1, -1, -1, -1)

# Target viewport for the SR pane; the per-mille window rect (0..1000)
# scales onto this. MSN's MOSVIEW canvas is 640×480.
_VIEWPORT_W = 640
_VIEWPORT_H = 480


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack("<H", len(data)) + data


def _unique_faces(font_table: tuple[MvbFontDescriptor, ...]) -> list[str]:
    seen: dict[str, int] = {}
    for d in font_table:
        if d.face_name and d.face_name not in seen:
            seen[d.face_name] = len(seen)
    return list(seen.keys())


def _build_section0(mvb: LoadedMVB) -> bytes:
    """Build the sec0 font table from the MVB's mvbfont descriptors.

    Layout per `docs/MEDVIEW.md` §4.4: 18-byte header + face-name table
    (0x20-byte slots) + style-record table (0x2A-byte slots) + pointer
    table (one u32 per face slot).
    """
    faces = _unique_faces(mvb.font_table)
    face_count = max(len(faces), 1)

    face_table = bytearray(face_count * _SEC0_FACE_ENTRY_SIZE)
    for i, name in enumerate(faces):
        encoded = name.encode("ascii", errors="replace")
        off = i * _SEC0_FACE_ENTRY_SIZE
        face_table[off:off + len(encoded)] = encoded

    descriptors = bytearray()
    for d in mvb.font_table:
        face_slot = faces.index(d.face_name) if d.face_name in faces else 0
        descriptor = bytearray(_SEC0_DESCRIPTOR_SIZE)
        struct.pack_into("<HHH", descriptor, 0x00, face_slot, 0, 0)
        descriptor[0x06:0x09] = b"\x01\x01\x01"
        descriptor[0x09:0x0C] = b"\x01\x01\x01"
        # mvbfont Height is twips; LOGFONT lfHeight is logical units. MSN's
        # MOSVIEW pane runs at MM_TEXT (96 DPI), so 1 pt = 20 twips and
        # lfHeight = -(height_twips/20) for an "ascender height" font.
        lf_height = d.height_twips // 20 if d.height_twips else -12
        struct.pack_into(
            "<iiiii", descriptor, 0x0C, lf_height, 0, 0, 0, d.weight or 400,
        )
        descriptors += descriptor

    pointer_table = b"\x00" * (face_count * _SEC0_POINTER_ENTRY_SIZE)

    face_off = _SEC0_HEADER_SIZE
    descriptor_off = face_off + len(face_table)
    pointer_off = descriptor_off + len(descriptors)
    descriptor_count = len(mvb.font_table) if mvb.font_table else 0xFFFF

    header = bytearray(_SEC0_HEADER_SIZE)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0x00,
        0,                                                 # +0x00 reserved
        descriptor_count,
        face_off,
        descriptor_off,
        0,                                                 # +0x08 override_count
        pointer_off,
        0,                                                 # +0x0C reserved
    )
    struct.pack_into("<H", header, 0x10, pointer_off)
    return bytes(header) + bytes(face_table) + bytes(descriptors) + pointer_table


def _scale_permille(value: int, viewport: int) -> int:
    """Per-mille (0..1000) → pixels (0..viewport). Clamps the source to
    [0, 1000] because some MVB authors use 1023 (0x3FF) for "max"."""
    if value < 0:
        value = 0
    if value > 1000:
        value = 1000
    return (value * viewport) // 1000


def _build_sec06_record(mvb: LoadedMVB) -> bytes:
    """sec06 window scaffold. Flag bit 0x40 (NSR-anchor-bottom from
    `ttl_loader`) is **omitted** here because TOPICHEADER.NonScroll =
    0xFFFFFFFF in NO_NSR.MVB signals "no NSR region" — native MV renders
    heading+body in SR only. Whether MSN MOSVIEW honours sec06 alone for
    NSR suppression (or whether NSR is structurally forced via
    `lpMVDuplicate` per `project_mosview_dual_pane_paint`) is still open.
    """
    record = bytearray(_SEC06_RECORD_SIZE)
    caption_bytes = mvb.caption.encode("ascii", errors="replace") + b"\x00"
    record[0x15:0x15 + len(caption_bytes)] = caption_bytes
    record[0x48] = _SEC06_FLAG_INNER_RECT_ABSOLUTE
    _x, _y, w, h = mvb.window_dims_permille
    width_px = _scale_permille(w, _VIEWPORT_W) or _VIEWPORT_W
    height_px = _scale_permille(h, _VIEWPORT_H) or _VIEWPORT_H
    struct.pack_into("<iiii", record, 0x49, 0, 0, width_px, height_px)
    struct.pack_into("<I", record, 0x5B, _SEC06_COLOR_INHERIT)
    struct.pack_into("<II", record, 0x78, _SEC06_COLOR_INHERIT, _SEC06_COLOR_INHERIT)
    struct.pack_into("<iiii", record, 0x80, *_SEC06_RECT_INHERIT)
    return bytes(record)


_TITLE_DEID_PLACEHOLDER = b"00000000-0000-0000-0000-000000000000\x00"


def lower_mvb_to_payload(mvb: LoadedMVB) -> bytes:
    """Assemble the 9-section TitleOpen body for a LoadedMVB."""
    section0 = _build_section0(mvb)
    sec06 = _build_sec06_record(mvb)
    caption_text = mvb.caption.encode("ascii", errors="replace") + b"\x00"
    return b"".join(
        [
            _length_prefixed(section0),
            b"\x00\x00",                                   # sec07: empty
            b"\x00\x00",                                   # sec08: empty
            _length_prefixed(sec06),
            _length_prefixed(caption_text),                # sec01
            b"\x00\x00",                                   # sec02: empty
            _length_prefixed(_TITLE_DEID_PLACEHOLDER),     # sec6a
            b"\x00\x00",                                   # sec13: empty
            b"\x00\x00",                                   # sec04: count=0
        ]
    )


# --------------------------------------------------------------------------
# Lowering: LoadedMVB → bm0 baggage (empty kind=5 raster)
# --------------------------------------------------------------------------

_BM0_BPP = 1
_BM0_PIXEL_BYTES = _VIEWPORT_W * _VIEWPORT_H // 8


def build_mvb_bm0_baggage(_mvb: LoadedMVB) -> bytes:
    """bm0 baggage is the SR-pane background only. Topic text rides the
    case-1 BF chunk push path (`build_mvb_first_paragraph_chunk`), not bm0.
    """
    raster = build_kind5_raster(
        width=_VIEWPORT_W,
        height=_VIEWPORT_H,
        bpp=_BM0_BPP,
        pixel_data=b"\xFF" * _BM0_PIXEL_BYTES,
        trailer=build_trailer([], b""),
    )
    return build_baggage_container(raster)


# --------------------------------------------------------------------------
# Lowering: LoadedMVB.first_paragraph → case-1 BF chunk
# --------------------------------------------------------------------------

# `encode_signed_short_varint` wide form caps optional TLV fields at
# [-0x4000, +0x3FFF]. Indent twips beyond that range are clamped — a 20pt
# indent at 96 DPI is ~300 twips, well within range; only pathological
# authored values would clip.
_INDENT_MIN = -0x4000
_INDENT_MAX = 0x3FFF


def _clamp_indent(value: int) -> int:
    return max(_INDENT_MIN, min(_INDENT_MAX, value))


def build_mvb_first_paragraph_chunk(
    mvb: LoadedMVB, title_slot: int, key: int,
) -> bytes:
    """Build the case-1 BF chunk for the MVB's first paragraph.

    The chunk's TLV carries paragraph indents and spacing; the in-chunk
    text bytes carry the paragraph string. Font style 0 is primed via the
    default `initial_font_style=0` control stream so the layout walker
    selects the first sec0 descriptor before painting.
    """
    p = mvb.first_paragraph
    tlv_fields: dict[int, int] = {}
    if p.left_indent_twips:
        tlv_fields[0x1C] = _clamp_indent(p.left_indent_twips)
    if p.right_indent_twips:
        tlv_fields[0x1E] = _clamp_indent(p.right_indent_twips)
    if p.first_line_indent_twips:
        tlv_fields[0x20] = _clamp_indent(p.first_line_indent_twips)
    if p.space_above_twips:
        tlv_fields[0x16] = _clamp_indent(p.space_above_twips)
    if p.space_below_twips:
        tlv_fields[0x18] = _clamp_indent(p.space_below_twips)

    return build_case1_bf_chunk(
        text=p.text,
        title_byte=title_slot,
        key=key,
        tlv_fields=tlv_fields or None,
        initial_font_style=0 if mvb.font_table else None,
    )
