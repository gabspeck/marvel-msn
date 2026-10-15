"""CContent body decoders for TextRuns and TextTree.

TextTree: `[0x03 length text]` segment scan plus a `CElementNode` grammar
parse, pinned against `tests/assets/story_test.ttl` 8/2 (85 B, plain) and 8/6
(1516 B, picture INTRUDE). Picture records are located, not decoded.

Ghidra entry points for the full grammar (VIEWDLL.DLL), per
`docs/MEDVIEW-TEXT-ENCODING.md` §7: `CContent::Serialize @ 0x4073a185`,
`CCharProps::Serialize @ 0x40707fcc`, `CParaProps::Serialize @ 0x407082e2`,
`CStyle::Serialize @ 0x40707d6f`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PictureRef:
    """One picture-intrusion reference inside a TextTree body. The
    Blackbird writer ships these as inline records carrying a CLSID
    (e.g. `PICTURE.PictureCtrl.1`), CX/CY size strings, a
    FILE/DATA1 property pair, an embedded ASCII filename (e.g.
    `bitmap.bmp`), and a 16-byte CLSID identifying the picture in
    the title's CProxyTable.

    The full reference's baggage proxy_key is resolved by looking up
    `iuid` in the title's CProxyTable; the partial decoder surfaces
    the raw bytes."""

    byte_offset: int
    clsid: str
    filename: str = ""
    iuid: bytes = b""


@dataclass(frozen=True)
class TextRunsContent:
    """Decoded `TextRuns` body: one prose string per CElementData.

    Wire form per VIEWDLL.DLL `CTypedPtrArray<CElementData>::Serialize`
    @ 0x407092a6 and `CElementData::Serialize @ 0x40702e4c`:

      u16 count                          (CArchive::WriteCount; 0xFFFF spills to u32)
      count x [CElementData length][bytes]
    """

    blobs: tuple[str, ...] = ()


@dataclass(frozen=True)
class TextTreeNode:
    """One `CElementNode` record.

    Wire form, pinned against `story_title.ttl 6/0`, `story_test.ttl
    8/2` and `8/6`:

        u16 tag                    element tag; 0xFFFF = text/data leaf
        u8  version
        version == 2:  4 fixed bytes
        version == 3:  CElementData length + that many bytes
        version == 5:  u16 prop_count, then prop_count Pascal-string
                       name/value pairs (`CLSID`/`PICTURE.PictureCtrl.1`,
                       `CX`/`1500`, `FILE`/`DATA1`, …)
        u16 child_count, then that many nodes

    A styled paragraph is a version-1 node holding one 0xFFFF child:
    `07 00 01 01 00  FF FF 03 0B "Story title" 00 00` is
    `<H1>Story title</H1>` — tag 7, one child, and the child is a
    version-3 leaf carrying 11 bytes and no children of its own.
    """

    tag: int
    version: int
    props: tuple[tuple[str, str], ...] = ()
    data: bytes = b""
    children: tuple[TextTreeNode, ...] = ()

    @property
    def is_text(self) -> bool:
        return self.tag == TEXT_NODE_TAG

    @property
    def text(self) -> str:
        """Prose under this node — every version-3 text leaf in document
        order, concatenated. Version-2 dwords and the binary leaves of a
        picture intrusion (DATA1 / RSLT1) drop out."""
        if self.is_text:
            if self.version != _NODE_VERSION_DATA:
                return ""
            try:
                return self.data.decode("ascii")
            except UnicodeDecodeError:
                return ""
        return "".join(child.text for child in self.children)


@dataclass(frozen=True)
class TextTreeContent:
    """Decoded `TextTree` body.

    `text` joins every `[0x03 length text]` segment with `'\\n'`; `segments`
    keeps each one's byte offset. `root` is the parsed `CElementNode` tree, or
    None when the body does not fit the grammar. `raw_payload` is the body
    after the `01 05` magic.
    """

    text: str
    segments: tuple[tuple[int, str], ...]
    picture_refs: tuple[PictureRef, ...] = ()
    raw_payload: bytes = b""
    root: TextTreeNode | None = None


_TEXTTREE_MAGIC = bytes.fromhex("0105")
_TEXT_SEGMENT_OPCODE = 0x03

# `0x01` is the stream version; the root `CElementNode` starts at +1,
# so the `01 05` magic is really `[u8 version=1][u16 tag=5 …]` — the
# root element of every observed body is tag 5 (the BBML document).
_TEXTTREE_ROOT_OFFSET = 1

TEXT_NODE_TAG = 0xFFFF
_NODE_VERSION_DWORD = 2
_NODE_VERSION_DATA = 3
_NODE_VERSION_PROPS = 5
_NODE_DWORD_SIZE = 4
# Bounds the recursion and the child loop on a malformed body.
_MAX_NODE_DEPTH = 64

# Picture INTRUDE records carry `[u8 5]CLSID[u8 len]PICTURE.PictureCtrl.1`.
_PICTURE_CLSID_MARKER = b"CLSID"


def is_texttree(raw: bytes) -> bool:
    """TextTree bodies start with `01 05`. The caller strips any CK
    envelope first."""
    return len(raw) >= 2 and raw[:2] == _TEXTTREE_MAGIC


def _read_celementdata_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a CElementData-style variable-length count starting at
    `offset`. Returns `(length, bytes_consumed)`. Matches the writer
    in VIEWDLL.DLL `CElementData::Serialize @ 0x40702e4c`:

      - count < 0xFF      → 1 byte
      - count < 0xFFFE    → `0xFF` + 2-byte LE u16
      - count >= 0xFFFE   → `0xFF` + `0xFFFF` + 4-byte LE u32
    """
    if offset >= len(data):
        return (0, 0)
    b0 = data[offset]
    if b0 != 0xFF:
        return (b0, 1)
    if offset + 3 > len(data):
        return (0, 0)
    w = int.from_bytes(data[offset + 1 : offset + 3], "little")
    if w != 0xFFFF:
        return (w, 3)
    if offset + 7 > len(data):
        return (0, 0)
    dw = int.from_bytes(data[offset + 3 : offset + 7], "little")
    return (dw, 7)


def _scan_text_segments(payload: bytes) -> list[tuple[int, str]]:
    """Walk `payload` (TextTree body after the `01 05` magic) and
    yield every plausible `[0x03 length text]` segment.

    A segment qualifies when:
      - opcode byte at `i` is `0x03`
      - length-prefix decodes to `1 <= length <= 0x10000`
      - the `length` bytes that follow are printable ASCII or one
        of `\\t \\r \\n`

    Strict acceptance rules: false positives are bounded because
    `0x03` rarely appears in arbitrary binary payloads followed by
    a printable-ASCII run of matching length.
    """
    segments: list[tuple[int, str]] = []
    i = 0
    end = len(payload)
    while i < end:
        if payload[i] != _TEXT_SEGMENT_OPCODE:
            i += 1
            continue
        length, consumed = _read_celementdata_length(payload, i + 1)
        if not (1 <= length <= 0x10000) or consumed == 0:
            i += 1
            continue
        text_start = i + 1 + consumed
        text_end = text_start + length
        if text_end > end:
            i += 1
            continue
        chunk = payload[text_start:text_end]
        if not all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in chunk):
            i += 1
            continue
        segments.append((i, chunk.decode("ascii", errors="replace")))
        i = text_end
    return segments


def _find_filename_in_intrude(payload: bytes, start: int, end: int) -> str:
    """Scan a picture-intrusion record's bytes (between `start` and
    `end`) for an embedded `*.bmp` / `*.wmf` / similar filename. The
    writer emits `[u8 length][filename][NUL pad]` inside the
    property block; we accept any length-prefixed ASCII run ending
    in a known image extension."""
    pos = start
    while pos < end - 2:
        ln = payload[pos]
        if 4 <= ln <= 64 and pos + 1 + ln <= end:
            candidate = payload[pos + 1 : pos + 1 + ln]
            if all(0x20 <= b < 0x7F for b in candidate) and b"." in candidate:
                lower = candidate.lower()
                if any(
                    lower.endswith(ext)
                    for ext in (b".bmp", b".wmf", b".dib", b".jpg", b".png", b".gif", b".shg")
                ):
                    return candidate.decode("ascii")
        pos += 1
    return ""


def _find_iuid_in_intrude(payload: bytes, start: int, end: int) -> bytes:
    """Scan a picture-intrusion record's bytes for the
    `[u32 size=16][16-byte CLSID]` pattern that uniquely identifies
    the picture in the title's CProxyTable. The size prefix is
    little-endian `10 00 00 00`; the 16 GUID bytes that follow must
    not be all-zero."""
    pos = start
    while pos < end - 20:
        if payload[pos : pos + 4] == b"\x10\x00\x00\x00":
            candidate = payload[pos + 4 : pos + 20]
            if any(b != 0 for b in candidate):
                return bytes(candidate)
        pos += 1
    return b""


def _scan_picture_refs(payload: bytes) -> list[PictureRef]:
    """Find Blackbird INTRUDE-style picture records inside `payload`.

    The writer ships pictures as `[u8 ascii_len][CLSID name]` followed
    by `[u8 5][... value ...]` property pairs, then an embedded
    filename and a 16-byte CLSID. We detect by scanning for the
    literal `CLSID` token (preceded by a one-byte length = 5), then
    reading the ASCII name that follows (its length encoded the
    same way), then scanning forward for the filename + IUID.
    """
    refs: list[PictureRef] = []
    pos = 0
    while True:
        idx = payload.find(_PICTURE_CLSID_MARKER, pos)
        if idx < 0:
            break
        # The byte immediately preceding CLSID should be the
        # ASCII-length marker = 5 (len("CLSID")).
        if idx >= 1 and payload[idx - 1] == 5:
            name_len_off = idx + len(_PICTURE_CLSID_MARKER)
            if name_len_off < len(payload):
                name_len = payload[name_len_off]
                name_start = name_len_off + 1
                name_end = name_start + name_len
                if 1 <= name_len <= 0x40 and name_end <= len(payload):
                    name_bytes = payload[name_start:name_end]
                    if all(0x20 <= b < 0x7F for b in name_bytes):
                        # Scan up to 0x200 B after the CLSID name for
                        # the embedded filename + IUID.
                        scan_end = min(name_end + 0x200, len(payload))
                        filename = _find_filename_in_intrude(
                            payload,
                            name_end,
                            scan_end,
                        )
                        iuid = _find_iuid_in_intrude(
                            payload,
                            name_end,
                            scan_end,
                        )
                        refs.append(
                            PictureRef(
                                byte_offset=idx - 1,
                                clsid=name_bytes.decode("ascii"),
                                filename=filename,
                                iuid=iuid,
                            )
                        )
                        pos = name_end
                        continue
        pos = idx + len(_PICTURE_CLSID_MARKER)
    return refs


def _read_pascal_string(data: bytes, offset: int) -> tuple[str, int]:
    """`[u8 length][length B ASCII]`. Returns `(text, next_offset)`."""
    if offset >= len(data):
        raise ValueError("truncated Pascal string")
    length = data[offset]
    end = offset + 1 + length
    if end > len(data):
        raise ValueError("Pascal string runs past the body")
    return data[offset + 1 : end].decode("ascii", errors="replace"), end


def _parse_node(data: bytes, offset: int, depth: int) -> tuple[TextTreeNode, int]:
    """Parse one `CElementNode` at `offset`. Returns `(node, next_offset)`
    and raises ValueError on anything that does not fit the grammar."""
    if depth > _MAX_NODE_DEPTH:
        raise ValueError("element tree nested past the depth bound")
    if offset + 3 > len(data):
        raise ValueError("truncated element header")
    tag = int.from_bytes(data[offset : offset + 2], "little")
    version = data[offset + 2]
    pos = offset + 3

    payload = b""
    props: list[tuple[str, str]] = []
    if version == _NODE_VERSION_DWORD:
        # Fixed 4-byte payload. `story_test.ttl 8/6` puts one of these
        # in the empty `<P>` ahead of each list (0 before the bulleted
        # list, 1 before the numbered one).
        if pos + _NODE_DWORD_SIZE > len(data):
            raise ValueError("truncated element dword")
        payload = data[pos : pos + _NODE_DWORD_SIZE]
        pos += _NODE_DWORD_SIZE
    elif version == _NODE_VERSION_DATA:
        length, consumed = _read_celementdata_length(data, pos)
        if consumed == 0 or pos + consumed + length > len(data):
            raise ValueError("truncated element data")
        pos += consumed
        payload = data[pos : pos + length]
        pos += length
    elif version == _NODE_VERSION_PROPS:
        if pos + 2 > len(data):
            raise ValueError("truncated property count")
        prop_count = int.from_bytes(data[pos : pos + 2], "little")
        pos += 2
        for _ in range(prop_count):
            name, pos = _read_pascal_string(data, pos)
            value, pos = _read_pascal_string(data, pos)
            props.append((name, value))

    if pos + 2 > len(data):
        raise ValueError("truncated child count")
    child_count = int.from_bytes(data[pos : pos + 2], "little")
    pos += 2
    children: list[TextTreeNode] = []
    for _ in range(child_count):
        child, pos = _parse_node(data, pos, depth + 1)
        children.append(child)

    return (
        TextTreeNode(
            tag=tag,
            version=version,
            props=tuple(props),
            data=payload,
            children=tuple(children),
        ),
        pos,
    )


def parse_element_tree(raw: bytes) -> TextTreeNode | None:
    """Parse a `01 05`-prefixed TextTree body into its element tree, or
    None when the body does not fit the grammar. Bodies carrying picture
    intrusions parse too — their DATA/RSLT blobs ride version-3 leaves."""
    try:
        root, _ = _parse_node(raw, _TEXTTREE_ROOT_OFFSET, 0)
    except (ValueError, IndexError, RecursionError):
        return None
    return root


def decode_texttree(raw: bytes) -> TextTreeContent:
    """Decode a `01 05`-prefixed TextTree body.

    Pinned against `tests/assets/story_test.ttl` 8/2 (two segments,
    `Calendar of Events` and `here's what's been happenin' `) and 8/6 (one
    `PICTURE.PictureCtrl.1` intrusion and ten segments).
    """
    if not is_texttree(raw):
        raise ValueError(
            f"not a TextTree payload (magic = {raw[:2].hex() if len(raw) >= 2 else '<short>'})"
        )
    payload = bytes(raw[2:])
    segments = _scan_text_segments(payload)
    picture_refs = _scan_picture_refs(payload)
    # Offsets relative to `raw`, magic included.
    segments = [(off + 2, text) for off, text in segments]
    text = "\n".join(t for _, t in segments)
    return TextTreeContent(
        text=text,
        segments=tuple(segments),
        picture_refs=tuple(picture_refs),
        raw_payload=payload,
        root=parse_element_tree(raw),
    )


def _parse_textruns_blobs(payload: bytes) -> list[str]:
    """Prose strings from a `CTypedPtrArray<CElementData>` body. Stops at
    the first element that runs past the buffer."""
    if len(payload) < 2:
        return []
    count = int.from_bytes(payload[0:2], "little")
    pos = 2
    if count == 0xFFFF:
        if len(payload) < 6:
            return []
        count = int.from_bytes(payload[2:6], "little")
        pos = 6

    blobs: list[str] = []
    for _ in range(count):
        length, consumed = _read_celementdata_length(payload, pos)
        if consumed == 0 or pos + consumed + length > len(payload):
            break
        pos += consumed
        blobs.append(payload[pos : pos + length].decode("ascii", errors="replace"))
        pos += length
    return blobs


def decode_textruns(raw: bytes) -> TextRunsContent:
    """Decode a `TextRuns` body. Short or empty bodies (the `00 00`
    placeholder) decode to no blobs; a TextTree body raises ValueError."""
    if is_texttree(raw):
        raise ValueError("raw is a TextTree payload; call decode_texttree() instead")
    return TextRunsContent(blobs=tuple(_parse_textruns_blobs(bytes(raw))))
