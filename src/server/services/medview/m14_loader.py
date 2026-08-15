"""Load compiled Microsoft Media View 1.4 titles for MEDVIEW.

An M14 is a Multimedia Viewer HFS book. Its ``|SYSTEM`` and ``|FONT``
files supply TitleOpen metadata, ``|TOPIC`` holds the native Media View
layout stream, and the remaining HFS files are title baggage. The topic
control bytes are already in the form consumed by MOSVIEW's
``MVDispatchControlRun``; the server only replaces the compiled
paragraph header with the equivalent online-cache TLV.
"""

from __future__ import annotations

import logging
import pathlib
import struct
import zlib
from dataclasses import dataclass

log = logging.getLogger(__name__)

_HFS_MAGIC = 0x00035F3F
_BTREE_MAGIC = 0x293B
_SYSTEM_MAGIC = 0x036C
_FILE_HEADER_SIZE = 9
_TOPIC_LINK_HEADER_SIZE = 21

_RECORD_TITLE = 1
_RECORD_COPYRIGHT = 2
_RECORD_CONTENTS = 3
_RECORD_TOPIC_COUNT = 11
_RECORD_DLL_MAP = 19

_TOPIC_HEADER = 0x02
_TOPIC_DISPLAY = 0x20
_TOPIC_TABLE = 0x23

_PARA_METRIC_MODE = 0x0001
_PARA_SPACE_ABOVE = 0x0002
_PARA_SPACE_BELOW = 0x0004
_PARA_SPACE_LINES = 0x0008
_PARA_LEFT_INDENT = 0x0010
_PARA_RIGHT_INDENT = 0x0020
_PARA_FIRST_INDENT = 0x0040
_PARA_BORDER = 0x0100
_PARA_TABS = 0x0200
_PARA_RIGHT_ALIGNED = 0x0400
_PARA_CENTER_ALIGNED = 0x0800

_SEC06_RECORD_SIZE = 0x98
_SEC06_OUTER_RECT_ABSOLUTE = 0x08
# PopupPaneRecord: 31 bytes, name is an inline cstring[9] at +0x02.
_SEC08_RECORD_SIZE = 0x1F
_SEC08_NAME_SIZE = 9
_PHRASE_COUNT_OFFSET = 2
_PHRASE_TEXT_SIZE_OFFSET = 6
_PHRASE_TABLE_OFFSET = 0x28
_COLOR_INHERIT = 0xFFFFFFFF
_CACHE_PROJECTION_VERSION = 2


@dataclass(frozen=True)
class M14InternalFile:
    name: str
    body: bytes


@dataclass(frozen=True)
class M14DllMap:
    alias: str
    win16_retail: str
    win16_debug: str
    win32_retail: str
    win32_debug: str


@dataclass(frozen=True)
class M14DisplayRecord:
    topic_pos: int
    topic_length: int
    address: int
    control_stream: bytes
    text_data: bytes
    tlv_fields: tuple[tuple[int, int], ...]
    tab_stops: tuple[tuple[int, int], ...]
    non_scroll: int
    scroll: int

    def fields_dict(self) -> dict[int, int]:
        return dict(self.tlv_fields)


@dataclass(frozen=True)
class M14Topic:
    title: str
    topic_number: int
    non_scroll: int
    scroll: int
    next_topic: int
    non_scroll_background: int | None
    scroll_background: int | None
    popup_background: int | None
    popup_window: str
    displays: tuple[M14DisplayRecord, ...]


@dataclass(frozen=True)
class LoadedM14:
    title: str
    copyright: str
    contents_offset: int
    generated_at: int
    font_faces: tuple[str, ...]
    font_descriptors: tuple[bytes, ...]
    dll_maps: tuple[M14DllMap, ...]
    context_map: tuple[tuple[int, int, int], ...]
    topic_count: int
    topics: tuple[M14Topic, ...]
    home_topic: M14Topic
    internal_files: tuple[M14InternalFile, ...]
    archive_name: str
    archive_bytes: bytes

    @property
    def home_display(self) -> M14DisplayRecord:
        for display in self.home_topic.displays:
            if display.topic_pos == self.home_topic.scroll:
                return display
        if self.home_topic.displays:
            return self.home_topic.displays[0]
        raise ValueError("M14 home topic has no display record")

    @property
    def contents_va(self) -> int:
        return self.home_display.topic_pos

    def cache_tuple(self, title_payload: bytes) -> tuple[int, int]:
        first = self.generated_at or len(self.archive_bytes)
        projection = struct.pack("<I", _CACHE_PROJECTION_VERSION)
        second = zlib.crc32(
            projection,
            zlib.crc32(title_payload, zlib.crc32(self.archive_bytes)),
        )
        return first & 0xFFFFFFFF, second & 0xFFFFFFFF

    @property
    def pane_backgrounds(self) -> tuple[int, int]:
        non_scroll = next(
            (
                topic.non_scroll_background
                for topic in self.topics
                if topic.non_scroll_background is not None
            ),
            _COLOR_INHERIT,
        )
        scroll = next(
            (
                topic.scroll_background
                for topic in self.topics
                if topic.scroll_background is not None
            ),
            _COLOR_INHERIT,
        )
        return non_scroll, scroll

    @property
    def popup_pane(self) -> tuple[int, str] | None:
        """Authored popup background and the window that declares it.

        `BackColorPopup` is per authored window, and every window in a
        title normally repeats the same value, so the first declaration
        stands for the title. Returns ``None`` when nothing declares one.
        """
        for topic in self.topics:
            if topic.popup_background is not None:
                return topic.popup_background, topic.popup_window
        return None

    def display_at(self, topic_pos: int) -> M14DisplayRecord | None:
        for topic in self.topics:
            for display in topic.displays:
                if display.topic_pos == topic_pos:
                    return display
        return None

    def display_neighbors(self, topic_pos: int) -> tuple[int, int]:
        """Prev/next cache tokens for one display record.

        Interior records name their real siblings. Topic edges name a
        token one below (or above) their own TOPICPOS. TOPICLINK records
        are at least `_TOPIC_LINK_HEADER_SIZE` bytes apart, so neither
        token can collide with a real record.

        The edge token has to sit adjacent to the record it terminates.
        `MVTTL14C!HfcNextPrevHfc @ 0x7e845abb` probes it over selector
        0x16, gets the `0x3F3` end-of-content status, and caches it as a
        zero-length record under that key. `HfcNear`'s lookup
        (`HfcCache_FindEntryAndPromote @ 0x7e845efa` with a companion
        out-param) falls back to the greatest cached key below its
        target whose successor key is above it, so a cached record spans
        from its own key up to the next cached key. An empty record
        selected that way makes `HfcCopyCacheRecordPayloadToGlobal @
        0x7e845cd4` return NULL, and `HfcNear` returns NULL *without*
        issuing selector 0x15 — `fMVSetAddress` then fails with `0x3ED`
        and `MOSVIEW!NavigateMosViewPane` hides the pane.

        A single shared sentinel below every TOPICPOS therefore spans
        from itself up to the lowest record cached so far and swallows
        every lookup under it. That silently broke navigation to the
        title's lowest topic (France popup `va=0x49`, confirmed under
        SoftICE 2026-07-30): the terminator cached while a later topic
        was on screen claimed the whole range beneath it.
        """
        for topic in self.topics:
            for index, display in enumerate(topic.displays):
                if display.topic_pos == topic_pos:
                    previous = (
                        topic.displays[index - 1].topic_pos
                        if index
                        else topic_pos - 1
                    )
                    following = (
                        topic.displays[index + 1].topic_pos
                        if index + 1 < len(topic.displays)
                        else topic_pos + 1
                    )
                    return previous, following
        return topic_pos - 1, topic_pos + 1

    def context_at(self, context_hash: int) -> tuple[int, int] | None:
        for candidate_hash, topic_pos, address in self.context_map:
            if candidate_hash == context_hash:
                return topic_pos, address
        return None

    def baggage_map(self) -> dict[str, bytes]:
        baggage = {
            item.name.lower(): item.body
            for item in self.internal_files
            if not item.name.startswith("|")
        }
        baggage[self.archive_name.lower()] = self.archive_bytes
        return baggage


@dataclass
class _TopicBuilder:
    title: str
    topic_number: int
    non_scroll: int
    scroll: int
    next_topic: int
    non_scroll_background: int | None
    scroll_background: int | None
    popup_background: int | None
    popup_window: str
    displays: list[M14DisplayRecord]


@dataclass(frozen=True)
class _SystemInfo:
    title: str
    copyright: str
    contents_offset: int
    generated_at: int
    minor: int
    flags: int
    topic_count_hint: int
    dll_maps: tuple[M14DllMap, ...]


def _read_internal_file(buf: bytes, offset: int) -> bytes:
    if offset < 0 or offset + _FILE_HEADER_SIZE > len(buf):
        raise ValueError(f"internal file offset out of bounds: 0x{offset:x}")
    _reserved, used = struct.unpack_from("<II", buf, offset)
    start = offset + _FILE_HEADER_SIZE
    end = start + used
    if end > len(buf):
        raise ValueError(f"internal file at 0x{offset:x} overruns archive")
    return bytes(buf[start:end])


def _btree_first_leaf(
    data: bytes,
    pages_start: int,
    page_size: int,
    root_page: int,
    level_count: int,
    what: str,
) -> int:
    """Descend a Media View B-tree from its root page to the leftmost leaf.

    An index page carries `Unused(2) NEntries(2) PreviousPage(2)` followed
    by `key, child_page` pairs. `PreviousPage` is the leftmost child, so
    taking it once per index level reaches the head of the leaf chain.
    A one-level tree is already a leaf and descends zero times.
    """
    page = root_page
    for _ in range(level_count - 1):
        start = pages_start + page * page_size
        if start + 6 > len(data):
            raise ValueError(f"{what} index page {page} overruns file")
        page = struct.unpack_from("<H", data, start + 4)[0]
    return page


def _read_directory(buf: bytes, directory_offset: int) -> dict[str, int]:
    directory = _read_internal_file(buf, directory_offset)
    if len(directory) < 38:
        raise ValueError("HFS directory is shorter than its B-tree header")
    magic, _flags, page_size = struct.unpack_from("<HHH", directory, 0)
    if magic != _BTREE_MAGIC:
        raise ValueError(f"HFS directory magic mismatch: 0x{magic:04x}")
    root_page = struct.unpack_from("<H", directory, 26)[0]
    level_count = struct.unpack_from("<H", directory, 32)[0]

    pages_start = 38
    page = _btree_first_leaf(
        directory,
        pages_start,
        page_size,
        root_page,
        level_count,
        "HFS directory",
    )
    entries: dict[str, int] = {}
    visited: set[int] = set()
    while page != 0xFFFF:
        if page in visited:
            raise ValueError("HFS directory leaf chain contains a cycle")
        visited.add(page)
        start = pages_start + page * page_size
        end = start + page_size
        if end > len(directory):
            raise ValueError(f"HFS directory page {page} overruns file")
        _unused, count, _previous, next_page = struct.unpack_from(
            "<HHhh",
            directory,
            start,
        )
        pos = start + 8
        for _ in range(count):
            name_end = directory.find(b"\x00", pos, end)
            if name_end < 0 or name_end + 5 > end:
                raise ValueError("malformed HFS directory entry")
            name = directory[pos:name_end].decode("latin-1")
            pos = name_end + 1
            file_offset = struct.unpack_from("<I", directory, pos)[0]
            pos += 4
            entries[name] = file_offset
        page = 0xFFFF if next_page < 0 else next_page
    return entries


def _parse_system(data: bytes) -> _SystemInfo:
    if len(data) < 12:
        raise ValueError("|SYSTEM is shorter than SYSTEMHEADER")
    magic, minor, _major, generated_at, flags = struct.unpack_from(
        "<HHHIH",
        data,
        0,
    )
    if magic != _SYSTEM_MAGIC:
        raise ValueError(f"|SYSTEM magic mismatch: 0x{magic:04x}")

    title = ""
    copyright_text = ""
    contents_offset = 0
    topic_count_hint = 0
    dll_maps: list[M14DllMap] = []
    pos = 12
    while pos + 4 <= len(data):
        record_type, size = struct.unpack_from("<HH", data, pos)
        pos += 4
        end = pos + size
        if end > len(data):
            raise ValueError("|SYSTEM record overruns file")
        payload = data[pos:end]
        pos = end
        if record_type == _RECORD_TITLE:
            title = payload.split(b"\x00", 1)[0].decode(
                "cp1252",
                errors="replace",
            )
        elif record_type == _RECORD_COPYRIGHT:
            copyright_text = payload.split(b"\x00", 1)[0].decode(
                "cp1252",
                errors="replace",
            )
        elif record_type == _RECORD_CONTENTS and len(payload) >= 4:
            contents_offset = struct.unpack_from("<I", payload, 0)[0]
        elif record_type == _RECORD_TOPIC_COUNT and minor == 27 and len(payload) == 4:
            topic_count_hint = struct.unpack_from("<I", payload, 0)[0]
        elif record_type == _RECORD_DLL_MAP:
            fields = payload.split(b"\x00")
            if len(fields) < 6:
                raise ValueError("|SYSTEM DLLMAP record has fewer than five strings")
            decoded = [
                field.decode("cp1252", errors="replace")
                for field in fields[:5]
            ]
            dll_maps.append(M14DllMap(*decoded))

    return _SystemInfo(
        title=title,
        copyright=copyright_text,
        contents_offset=contents_offset,
        generated_at=generated_at,
        minor=minor,
        flags=flags,
        topic_count_hint=topic_count_hint,
        dll_maps=tuple(dll_maps),
    )


def _parse_font(data: bytes) -> tuple[tuple[str, ...], tuple[bytes, ...]]:
    if len(data) < 8:
        raise ValueError("|FONT is shorter than its header")
    face_count, descriptor_count, face_offset, descriptor_offset = struct.unpack_from(
        "<HHHH", data, 0
    )
    style_count = style_offset = 0
    charmap_offset = 0
    if face_offset >= 12 and len(data) >= 12:
        style_count, style_offset = struct.unpack_from("<HH", data, 8)
    if face_offset >= 16 and len(data) >= 16:
        _charmap_count, charmap_offset = struct.unpack_from("<HH", data, 12)

    if not face_count or descriptor_offset < face_offset:
        raise ValueError("|FONT has invalid face-name offsets")
    face_stride = (descriptor_offset - face_offset) // face_count
    if face_stride <= 0:
        raise ValueError("|FONT has an empty face-name stride")

    faces: list[str] = []
    for index in range(face_count):
        start = face_offset + index * face_stride
        raw = data[start : start + face_stride].split(b"\x00", 1)[0]
        name = raw.decode("cp1252", errors="replace").rsplit(",", 1)[0]
        faces.append(name)

    descriptor_end = len(data)
    if style_count and descriptor_offset < style_offset <= len(data):
        descriptor_end = style_offset
    elif descriptor_offset < charmap_offset <= len(data):
        descriptor_end = charmap_offset
    if not descriptor_count or descriptor_end < descriptor_offset:
        raise ValueError("|FONT has invalid descriptor offsets")
    descriptor_stride = (descriptor_end - descriptor_offset) // descriptor_count
    if descriptor_stride < 0x2A:
        raise ValueError(f"|FONT descriptor stride {descriptor_stride} is shorter than 0x2a")

    descriptors = tuple(
        bytes(
            data[
                descriptor_offset + index * descriptor_stride : descriptor_offset
                + index * descriptor_stride
                + 0x2A
            ]
        )
        for index in range(descriptor_count)
    )
    return tuple(faces), descriptors


def _parse_context(data: bytes) -> tuple[tuple[int, int], ...]:
    if len(data) < 38:
        raise ValueError("|CONTEXT is shorter than its B-tree header")
    magic, _flags, page_size = struct.unpack_from("<HHH", data, 0)
    if magic != _BTREE_MAGIC:
        raise ValueError(f"|CONTEXT B-tree magic mismatch: 0x{magic:04x}")
    root_page = struct.unpack_from("<H", data, 26)[0]
    level_count = struct.unpack_from("<H", data, 32)[0]

    records: list[tuple[int, int]] = []
    page = _btree_first_leaf(data, 38, page_size, root_page, level_count, "|CONTEXT")
    visited: set[int] = set()
    while page != 0xFFFF:
        if page in visited:
            raise ValueError("|CONTEXT leaf chain contains a cycle")
        visited.add(page)
        start = 38 + page * page_size
        end = start + page_size
        if end > len(data):
            raise ValueError(f"|CONTEXT page {page} overruns file")
        _unused, count, _previous, next_page = struct.unpack_from(
            "<HHhh",
            data,
            start,
        )
        pos = start + 8
        if pos + count * 8 > end:
            raise ValueError(f"|CONTEXT page {page} records overrun page")
        records.extend(
            struct.unpack_from("<II", data, pos + index * 8)
            for index in range(count)
        )
        page = 0xFFFF if next_page < 0 else next_page
    return tuple(records)


def _compressed_ushort(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first & 1:
        return (first >> 1) + 128 * buf[pos + 1], pos + 2
    return first >> 1, pos + 1


def _compressed_short(buf: bytes, pos: int) -> tuple[int, int]:
    first = buf[pos]
    if first & 1:
        return (first >> 1) + 128 * buf[pos + 1] - 0x4000, pos + 2
    return (first >> 1) - 0x40, pos + 1


def _compressed_long(buf: bytes, pos: int) -> tuple[int, int]:
    first = struct.unpack_from("<H", buf, pos)[0]
    if first & 1:
        second = struct.unpack_from("<H", buf, pos + 2)[0]
        return (first >> 1) + 0x8000 * second - 0x4000000, pos + 4
    return (first >> 1) - 0x4000, pos + 2


def _lz77_decompress(data: bytes, limit: int = 0x4000) -> bytes:
    output = bytearray()
    pos = 0
    while pos < len(data) and len(output) < limit:
        flags = data[pos]
        pos += 1
        for bit in range(8):
            if pos >= len(data) or len(output) >= limit:
                break
            if flags & (1 << bit):
                if pos + 2 > len(data):
                    raise ValueError("truncated M14 LZ77 back-reference")
                token = data[pos] | data[pos + 1] << 8
                pos += 2
                distance = (token & 0x0FFF) + 1
                count = (token >> 12) + 3
                source = len(output) - distance
                if source < 0:
                    raise ValueError("invalid M14 LZ77 back-reference")
                for index in range(count):
                    if len(output) >= limit:
                        break
                    output.append(output[source + index])
            else:
                output.append(data[pos])
                pos += 1
    return bytes(output)


def _parse_phrases(data: bytes) -> tuple[bytes, ...]:
    """Return the `|Phrases` table that expands compressed LinkData2 runs.

    Layout confirmed against MVDOC.M14: NumPhrases sits at +2 and the
    decompressed PhraseText size at +6, the offset table of NumPhrases+1
    u16 starts at +0x28, and every offset counts from the table start.
    The table itself is stored raw and only the text it indexes is
    LZ77-compressed. Bytes +0x0A..+0x27 are zero in that sample and stay
    unidentified.
    """
    if len(data) < _PHRASE_TABLE_OFFSET + 2:
        raise ValueError("|Phrases is shorter than its header")
    count = struct.unpack_from("<H", data, _PHRASE_COUNT_OFFSET)[0]
    text_size = struct.unpack_from("<I", data, _PHRASE_TEXT_SIZE_OFFSET)[0]
    if _PHRASE_TABLE_OFFSET + (count + 1) * 2 > len(data):
        raise ValueError("|Phrases offset table overruns file")
    offsets = struct.unpack_from(f"<{count + 1}H", data, _PHRASE_TABLE_OFFSET)
    base = offsets[0]
    if base != (count + 1) * 2:
        raise ValueError("|Phrases offset table does not end where its text starts")
    if offsets[-1] - base != text_size:
        raise ValueError("|Phrases text size disagrees with its offset table")
    text = _lz77_decompress(data[_PHRASE_TABLE_OFFSET + base :], text_size)
    if len(text) != text_size:
        raise ValueError("|Phrases text decompressed to the wrong size")
    return tuple(
        text[offsets[index] - base : offsets[index + 1] - base] for index in range(count)
    )


def _phrase_expand(data: bytes, phrases: tuple[bytes, ...]) -> bytes:
    """Expand one phrase-compressed LinkData2 run.

    A byte in 0x01..0x0F opens a two-byte reference encoding
    `code = 256 * (first - 1) + second`. That selects phrase `code >> 1`
    and appends a space when `code` is odd. Every other byte is a
    literal. Verified against MVDOC.M14: each record expands to exactly
    the size its TOPICLINK declares.
    """
    out = bytearray()
    pos = 0
    while pos < len(data):
        first = data[pos]
        pos += 1
        if not 0 < first < 16:
            out.append(first)
            continue
        if pos >= len(data):
            raise ValueError("truncated LinkData2 phrase reference")
        code = 256 * (first - 1) + data[pos]
        pos += 1
        index = code >> 1
        if index >= len(phrases):
            raise ValueError(f"LinkData2 phrase {index} is out of range")
        out += phrases[index]
        if code & 1:
            out += b" "
    return bytes(out)


def _topic_block_size(system: _SystemInfo) -> int:
    if system.minor <= 16 or system.flags == 8:
        return 0x800
    if system.flags in (0, 4):
        return 0x1000
    raise NotImplementedError(f"unsupported M14 |TOPIC compression flags 0x{system.flags:x}")


def _load_topic_blocks(
    data: bytes,
    system: _SystemInfo,
) -> tuple[list[tuple[int, int, int]], list[bytes], int]:
    block_size = _topic_block_size(system)
    compressed = system.minor > 16 and system.flags in (4, 8)
    output_limit = 0x4000 if compressed else block_size - 12
    topic_pos_stride = 0x4000 if system.minor > 16 else output_limit
    headers: list[tuple[int, int, int]] = []
    blocks: list[bytes] = []
    for offset in range(0, len(data), block_size):
        raw = data[offset : offset + block_size]
        if len(raw) < 12:
            break
        headers.append(struct.unpack_from("<iii", raw, 0))
        body = raw[12:]
        blocks.append(_lz77_decompress(body, output_limit) if compressed else bytes(body))
    return headers, blocks, topic_pos_stride


def _read_topic_link(
    blocks: list[bytes],
    topic_pos_stride: int,
    topic_pos: int,
    phrases: tuple[bytes, ...],
) -> tuple[int, int, int, int, int, bytes, bytes]:
    relative = topic_pos - 12
    if relative < 0:
        raise ValueError(f"invalid TOPICPOS 0x{topic_pos:x}")
    block_index, offset = divmod(relative, topic_pos_stride)
    if block_index >= len(blocks):
        raise ValueError(f"TOPICPOS 0x{topic_pos:x} selects a missing block")
    record_data = b"".join([blocks[block_index][offset:], *blocks[block_index + 1 :]])
    if len(record_data) < _TOPIC_LINK_HEADER_SIZE:
        raise ValueError(f"TOPICLINK 0x{topic_pos:x} header overruns block")
    size, data2_size, previous, following, data1_size = struct.unpack_from(
        "<iiiii",
        record_data,
        0,
    )
    record_type = record_data[20]
    if size < data1_size or data1_size < _TOPIC_LINK_HEADER_SIZE or size > len(record_data):
        raise ValueError(f"TOPICLINK 0x{topic_pos:x} has invalid lengths")
    data1 = bytes(record_data[_TOPIC_LINK_HEADER_SIZE:data1_size])
    stored_data2 = bytes(record_data[data1_size:size])
    if data2_size > len(stored_data2):
        if not phrases:
            raise NotImplementedError("phrase-compressed M14 LinkData2 without |Phrases")
        data2 = _phrase_expand(stored_data2, phrases)
        if len(data2) != data2_size:
            raise ValueError(
                f"TOPICLINK 0x{topic_pos:x} expanded to {len(data2)} of {data2_size} bytes",
            )
    else:
        data2 = stored_data2[:data2_size]
    return (
        record_type,
        previous,
        following,
        size,
        data2_size,
        data1,
        data2,
    )


def _parse_topic_color(value: str) -> int | None:
    if not value.lower().startswith("&h"):
        return None
    try:
        return int(value[2:], 16) & 0xFFFFFF
    except ValueError:
        return None


def _parse_topic_properties(
    data: bytes,
) -> tuple[int | None, int | None, int | None, str]:
    """Decode the `<window>.<Property>=<value>` list in a TOPICHEADER.

    Returns the NSR, SR and popup backgrounds plus the window id that
    declared the popup colour. The id becomes the `PopupPaneRecord`
    name, which must not be empty: a NUL-empty name leaves
    `MosPaneState+0x68` NULL, and `MOSVIEW!FindMosViewSessionByName`
    passes that pointer straight to `lstrcmpiA` when a named popup verb
    searches the array.
    """
    non_scroll = None
    scroll = None
    popup = None
    popup_window = ""
    text = data.decode("cp1252", errors="replace")
    for assignment in text.split(";"):
        name, separator, value = assignment.partition("=")
        if not separator:
            continue
        window, _, name = name.rpartition(".")
        if name == "BackColorNSR" and non_scroll is None:
            non_scroll = _parse_topic_color(value)
        elif name == "BackColorSR" and scroll is None:
            scroll = _parse_topic_color(value)
        elif name == "BackColorPopup" and popup is None:
            popup = _parse_topic_color(value)
            if popup is not None:
                popup_window = window
    return non_scroll, scroll, popup, popup_window


def _parse_topic_header(data1: bytes, data2: bytes) -> _TopicBuilder:
    if len(data1) < 28:
        raise ValueError("M14 TOPICHEADER data is shorter than 28 bytes")
    (
        _topic_size,
        _browse_back,
        _browse_forward,
        topic_number,
        non_scroll,
        scroll,
        next_topic,
    ) = struct.unpack_from("<iiiiIII", data1, 0)
    title_bytes, separator, properties = data2.partition(b"\x00")
    title = title_bytes.decode("cp1252", errors="replace")
    (
        non_scroll_background,
        scroll_background,
        popup_background,
        popup_window,
    ) = _parse_topic_properties(properties if separator else b"")
    return _TopicBuilder(
        title=title,
        topic_number=topic_number,
        non_scroll=non_scroll,
        scroll=scroll,
        next_topic=next_topic,
        non_scroll_background=non_scroll_background,
        scroll_background=scroll_background,
        popup_background=popup_background,
        popup_window=popup_window,
        displays=[],
    )


def _parse_paragraph(
    data1: bytes,
    pos: int,
) -> tuple[dict[int, int], tuple[tuple[int, int], ...], int]:
    if pos + 6 > len(data1):
        raise ValueError("M14 paragraph header is truncated")
    pos += 4  # unknown byte, biased byte, paragraph id
    bits = struct.unpack_from("<H", data1, pos)[0]
    pos += 2

    fields: dict[int, int] = {}
    if bits & _PARA_METRIC_MODE:
        fields[0x12], pos = _compressed_long(data1, pos)
    for bit, field_offset in (
        (_PARA_SPACE_ABOVE, 0x16),
        (_PARA_SPACE_BELOW, 0x18),
    ):
        if bits & bit:
            fields[field_offset], pos = _compressed_short(data1, pos)
    if bits & _PARA_SPACE_LINES:
        fields[0x1A], pos = _compressed_short(data1, pos)
    for bit, field_offset in (
        (_PARA_LEFT_INDENT, 0x1C),
        (_PARA_RIGHT_INDENT, 0x1E),
        (_PARA_FIRST_INDENT, 0x20),
    ):
        if bits & bit:
            fields[field_offset], pos = _compressed_short(data1, pos)
    if bits & _PARA_BORDER:
        pos += 3

    tab_stops: list[tuple[int, int]] = []
    if bits & _PARA_TABS:
        count, pos = _compressed_short(data1, pos)
        for _ in range(max(0, count)):
            stop, pos = _compressed_ushort(data1, pos)
            payload = 0
            if stop & 0x4000:
                stop &= ~0x4000
                payload, pos = _compressed_ushort(data1, pos)
            tab_stops.append((stop, payload))

    if bits & _PARA_RIGHT_ALIGNED:
        fields[0x0C] = 1
    elif bits & _PARA_CENTER_ALIGNED:
        fields[0x0C] = 2
    return fields, tuple(tab_stops), pos


def _display_topic_length(data1: bytes) -> int:
    _topic_size, pos = _compressed_long(data1, 0)
    topic_length, _pos = _compressed_ushort(data1, pos)
    return topic_length


def _parse_display(
    topic_pos: int,
    address: int,
    data1: bytes,
    data2: bytes,
    non_scroll: int,
    scroll: int,
) -> M14DisplayRecord:
    _topic_size, pos = _compressed_long(data1, 0)
    topic_length, pos = _compressed_ushort(data1, pos)
    fields, tab_stops, pos = _parse_paragraph(data1, pos)
    control_stream = data1[pos:]
    if not control_stream or control_stream[-1] != 0xFF:
        raise ValueError(f"M14 display record 0x{topic_pos:x} lacks control terminator")
    return M14DisplayRecord(
        topic_pos=topic_pos,
        topic_length=topic_length,
        address=address,
        control_stream=control_stream,
        text_data=data2 or b"\x00",
        tlv_fields=tuple(sorted(fields.items())),
        tab_stops=tab_stops,
        non_scroll=non_scroll,
        scroll=scroll,
    )


def _parse_topics(
    data: bytes,
    system: _SystemInfo,
    phrases: tuple[bytes, ...],
) -> tuple[tuple[M14Topic, ...], M14Topic]:
    headers, blocks, topic_pos_stride = _load_topic_blocks(data, system)
    builders: list[_TopicBuilder] = []
    home_builder: _TopicBuilder | None = None
    contents_block = system.contents_offset >> 15
    contents_character = system.contents_offset & 0x7FFF
    if not headers or headers[0][1] < 12:
        raise ValueError("M14 contains no first TOPICLINK")

    current_pos = headers[0][1]
    current_topic: _TopicBuilder | None = None
    current_block = -1
    character_count = 0
    visited: set[int] = set()
    while current_pos not in visited:
        relative = current_pos - 12
        if relative < 0:
            raise ValueError(f"invalid TOPICPOS 0x{current_pos:x}")
        block_index = relative // topic_pos_stride
        if block_index != current_block:
            current_block = block_index
            character_count = 0

        visited.add(current_pos)
        (
            record_type,
            _previous,
            following,
            _size,
            _data2_size,
            data1,
            data2,
        ) = _read_topic_link(blocks, topic_pos_stride, current_pos, phrases)

        if record_type == _TOPIC_HEADER:
            current_topic = _parse_topic_header(data1, data2)
            builders.append(current_topic)
        elif record_type in (_TOPIC_DISPLAY, _TOPIC_TABLE):
            topic_length = _display_topic_length(data1)
            if current_topic is not None and record_type == _TOPIC_DISPLAY:
                display = _parse_display(
                    current_pos,
                    (block_index << 15) | character_count,
                    data1,
                    data2,
                    current_topic.non_scroll,
                    current_topic.scroll,
                )
                current_topic.displays.append(display)
                if (
                    block_index == contents_block
                    and character_count
                    <= contents_character
                    < character_count + max(1, topic_length)
                ):
                    home_builder = current_topic
            character_count += topic_length

        if following in (0, -1):
            break
        current_pos = following

    viable = [topic for topic in builders if topic.displays]
    if not viable:
        raise ValueError("M14 contains no displayable topic")
    if home_builder not in viable:
        home_builder = viable[0]

    converted: dict[int, M14Topic] = {}
    topics: list[M14Topic] = []
    for builder in builders:
        topic = M14Topic(
            title=builder.title,
            topic_number=builder.topic_number,
            non_scroll=builder.non_scroll,
            scroll=builder.scroll,
            next_topic=builder.next_topic,
            non_scroll_background=builder.non_scroll_background,
            scroll_background=builder.scroll_background,
            popup_background=builder.popup_background,
            popup_window=builder.popup_window,
            displays=tuple(builder.displays),
        )
        converted[id(builder)] = topic
        topics.append(topic)
    return tuple(topics), converted[id(home_builder)]


def _resolve_context_map(
    records: tuple[tuple[int, int], ...],
    topics: tuple[M14Topic, ...],
) -> tuple[tuple[int, int, int], ...]:
    displays = tuple(
        display
        for topic in topics
        for display in topic.displays
    )
    resolved = []
    unresolved = 0
    for context_hash, address in records:
        block = address >> 15
        character = address & 0x7FFF
        target = next(
            (
                display
                for display in displays
                if display.address >> 15 == block
                and display.address & 0x7FFF
                <= character
                < (display.address & 0x7FFF) + max(1, display.topic_length)
            ),
            None,
        )
        if target is None:
            # The address lands in a record that carries no display, which
            # in MVDOC.M14 is always a table (type 0x23). Tables consume
            # character space but never become an M14DisplayRecord, so
            # there is no TOPICPOS to hand back. Drop the entry: the miss
            # then reaches `context_at` as `None`, the same answer an
            # absent hash gets. Which TOPICPOS MOSVIEW expects for a
            # table-hosted target is untested.
            unresolved += 1
            continue
        resolved.append((context_hash, target.topic_pos, address))
    if unresolved:
        log.info(
            "m14 |CONTEXT: %d of %d records target a non-display record",
            unresolved,
            len(records),
        )
    return tuple(resolved)


def load_m14(path: pathlib.Path) -> LoadedM14 | None:
    """Return a parsed Media View 1.4 title, or ``None`` on invalid input."""
    try:
        buf = path.read_bytes()
        if len(buf) < 16:
            raise ValueError("M14 is shorter than its HFS header")
        magic, directory_offset, _free, declared_size = struct.unpack_from(
            "<IIII",
            buf,
            0,
        )
        if magic != _HFS_MAGIC:
            raise ValueError(f"M14 HFS magic mismatch: 0x{magic:08x}")
        if declared_size != len(buf):
            raise ValueError(f"M14 size header {declared_size} differs from file size {len(buf)}")

        directory = _read_directory(buf, directory_offset)
        internal_files = tuple(
            M14InternalFile(name, _read_internal_file(buf, offset))
            for name, offset in directory.items()
        )
        by_name = {item.name: item.body for item in internal_files}
        system = _parse_system(by_name["|SYSTEM"])
        faces, descriptors = _parse_font(by_name["|FONT"])
        phrases = _parse_phrases(by_name["|Phrases"]) if "|Phrases" in by_name else ()
        topics, home_topic = _parse_topics(by_name["|TOPIC"], system, phrases)
        context_map = _resolve_context_map(
            _parse_context(by_name["|CONTEXT"]),
            topics,
        )
        title = system.title or path.stem.title()
        return LoadedM14(
            title=title,
            copyright=system.copyright,
            contents_offset=system.contents_offset,
            generated_at=system.generated_at,
            font_faces=faces,
            font_descriptors=descriptors,
            dll_maps=system.dll_maps,
            context_map=context_map,
            topic_count=system.topic_count_hint or max(len(topics), 1),
            topics=topics,
            home_topic=home_topic,
            internal_files=internal_files,
            archive_name=path.name,
            archive_bytes=buf,
        )
    except (KeyError, OSError, struct.error, ValueError, NotImplementedError) as exc:
        log.info("load_m14 path=%s failed=%r", path, exc)
        return None


def _length_prefixed(data: bytes) -> bytes:
    return struct.pack("<H", len(data)) + data


def _build_section0(m14: LoadedM14) -> bytes:
    face_table = b"".join(
        face.encode("cp1252", errors="replace")[:31].ljust(0x20, b"\x00") for face in m14.font_faces
    )
    descriptors = b"".join(m14.font_descriptors)
    face_offset = 0x12
    descriptor_offset = face_offset + len(face_table)
    pointer_offset = descriptor_offset + len(descriptors)
    header = bytearray(0x12)
    struct.pack_into(
        "<HHHHHHH",
        header,
        0,
        0,
        len(m14.font_descriptors),
        face_offset,
        descriptor_offset,
        0,
        pointer_offset,
        0,
    )
    struct.pack_into("<H", header, 0x10, pointer_offset)
    return bytes(header) + face_table + descriptors + b"\x00" * (4 * len(m14.font_faces))


def _build_sec08(m14: LoadedM14) -> bytes:
    """Project the authored `BackColorPopup` into one PopupPaneRecord.

    Field layout per `docs/medview-service-contract.md` "PopupPaneRecord",
    pinned at `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6E51`. The
    rect is left at `-1`, which defaults the popup to the container's
    client area.

    Scope: `CreateMosViewWindowHierarchy` builds `popupCount + 1` panes
    and appends its own "[The Default Popup]" as the last one, while
    `FindMosViewSessionByName` selects index `count - 1` whenever the
    caller passes no pane name. A bare `0xE2` popup hotspot passes NULL
    (`HandleMediaTitleCommand @ 0x7F3C5C9C`), so it always lands on that
    synthetic pane, whose colour is the hardcoded `-1` at `0x7F3C71C2`
    (`GetSysColor(COLOR_WINDOW)`). This record is therefore reachable
    only through the named-window popup tags `0xEA` / `0xEE`, which
    carry a window name string.
    """
    popup = m14.popup_pane
    if popup is None:
        return b""
    background, window = popup
    record = bytearray(_SEC08_RECORD_SIZE)
    # An unprefixed property names the title's main window, authored as
    # window 0. The name must stay non-empty — see _parse_topic_properties.
    name = (window or "0").encode("cp1252", errors="replace")
    name = name[:_SEC08_NAME_SIZE - 1]
    record[0x02 : 0x02 + len(name)] = name
    struct.pack_into("<iiii", record, 0x0B, -1, -1, -1, -1)
    struct.pack_into("<I", record, 0x1B, background)
    return bytes(record)


def _build_sec06(m14: LoadedM14) -> bytes:
    record = bytearray(_SEC06_RECORD_SIZE)
    caption = m14.title.encode("cp1252", errors="replace")[:50] + b"\x00"
    record[0x15 : 0x15 + len(caption)] = caption
    record[0x48] = _SEC06_OUTER_RECT_ABSOLUTE
    struct.pack_into("<iiii", record, 0x49, 0, 0, 640, 480)
    struct.pack_into("<I", record, 0x5B, _COLOR_INHERIT)
    non_scroll_background, scroll_background = m14.pane_backgrounds
    struct.pack_into(
        "<II",
        record,
        0x78,
        non_scroll_background,
        scroll_background,
    )
    struct.pack_into("<iiii", record, 0x80, -1, -1, -1, -1)
    return bytes(record)


def _build_sec13(m14: LoadedM14) -> bytes:
    """Project M14 DLLMAP records into TitleLoadDLL's module table."""
    entries = bytearray()
    for dll_map in m14.dll_maps:
        win32_retail = dll_map.win32_retail
        if dll_map.alias.upper() in {"MVIMG", "MVIMAGE"}:
            win32_retail = "MVPR14N"
        fields = (
            dll_map.alias,
            dll_map.win16_retail,
            dll_map.win16_debug,
            win32_retail,
            dll_map.win32_debug,
        )
        entry = b"\x00".join(
            field.encode("cp1252", errors="replace")
            for field in fields
        ) + b"\x00"
        entries += struct.pack("<H", len(entry)) + entry
    if not entries:
        return b"\x00\x00"
    return struct.pack("<HH", len(entries), len(m14.dll_maps)) + entries


def lower_m14_to_payload(m14: LoadedM14, deid: str) -> bytes:
    """Build the nine-section TitleOpen body from an M14 title."""
    title = m14.title.encode("cp1252", errors="replace") + b"\x00"
    copyright_text = (
        m14.copyright.encode("cp1252", errors="replace") + b"\x00" if m14.copyright else b""
    )
    title_id = deid.encode("ascii", errors="replace") + b"\x00"
    return b"".join(
        [
            _length_prefixed(_build_section0(m14)),
            b"\x00\x00",  # sec07: no additional MOSVIEW child panes
            _length_prefixed(_build_sec08(m14)),
            _length_prefixed(_build_sec06(m14)),
            _length_prefixed(title),
            _length_prefixed(copyright_text),
            _length_prefixed(title_id),
            _build_sec13(m14),
            b"\x00\x00",  # sec04: no MOSVIEW host strings
        ]
    )


def lower_m14_to_osr2_payload(m14: LoadedM14, deid: str) -> bytes:
    """Build the OSR2 TitleOpen cache streams from an M14 title.

    OSR2 MVTTL14C splits the dynamic body into a length-prefixed font
    table and a second cache stream. The second stream starts with the
    ASCIIZ title id, followed by the caption, copyright, and DLL map.
    MOSVIEW obtains window, pane, and popup records from ``|MVPFILE``.
    """
    title = m14.title.encode("cp1252", errors="replace") + b"\x00"
    copyright_text = (
        m14.copyright.encode("cp1252", errors="replace") + b"\x00"
        if m14.copyright
        else b""
    )
    title_id = deid.encode("ascii", errors="replace") + b"\x00"
    return b"".join(
        [
            _length_prefixed(_build_section0(m14)),
            title_id,
            _length_prefixed(title),
            _length_prefixed(copyright_text),
            _build_sec13(m14),
        ]
    )


def build_m14_mvpfile(m14: LoadedM14) -> bytes:
    """Project the M14 main-window properties into OSR2 MVP text.

    `[WINDOWS]` field order is pinned at `MOSVIEW!ParseMvpWindowLine @
    0x7F3C8B6C` (OSR2 build): caption, outer rect, window aspect, window
    background, scrolling-pane colour, non-scrolling-pane colour. The
    last two land on WindowScaffoldRecord `+0x7C` and `+0x78`, the same
    slots `_build_sec06` fills on the RTM path.

    An omitted field leaves the `-1` that `InitMvpWindowRecord @
    0x7F3C835C` wrote, which `CreateMosViewWindowHierarchy` renders as
    `GetSysColor(COLOR_WINDOW)`. Only the fields the title authors are
    emitted.
    """

    def color(value: int) -> str:
        if value == _COLOR_INHERIT:
            return ""
        return f"({value & 0xff},{value >> 8 & 0xff},{value >> 16 & 0xff})"

    caption = m14.title.replace('"', "'")
    non_scroll, scroll = m14.pane_backgrounds
    window = (
        f'main="{caption}",(0,0,640,480,1),,,'
        f"{color(scroll)},{color(non_scroll)}"
    ).rstrip(",")
    return (
        "[CONFIG]\r\n\r\n"
        "[PANES]\r\n\r\n"
        "[POPUPS]\r\n\r\n"
        f"[WINDOWS]\r\n{window}\r\n"
    ).encode("cp1252", errors="replace")
