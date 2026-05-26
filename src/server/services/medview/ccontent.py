"""CContent decoders — TextRuns (PR1) and TextTree (PR2 partial).

TextRuns: empirical header pin against
`tests/assets/story_test.ttl 8/7` (122 B). Decoder is tolerant of
short / empty payloads (returns an empty container).

TextTree: best-effort text scanner pinned against
`tests/assets/story_test.ttl 8/2` (85 B, plain) and `8/6` (1516 B,
with picture INTRUDE). Recovers the concatenated story prose by
walking `[u8 0x03][length-prefix][text]` segments — the segment
opcode used by Blackbird's text-tree writer. Style records and
picture-intrusion CLSID blocks are detected but not deeply decoded;
`style_runs` is empty and `picture_refs` counts INTRUDE-style CLSID
occurrences.

Full grammar (every node opcode, CCharProps/CParaProps streams,
style-handle table) is out of scope here — see
`docs/MEDVIEW-TEXT-ENCODING.md` §7 for the Ghidra entry points
(`CContent::Serialize @ 0x4073a185` in VIEWDLL.DLL,
`CCharProps::Serialize @ 0x40707fcc`,
`CParaProps::Serialize @ 0x407082e2`,
`CStyle::Serialize @ 0x40707d6f`)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StyleRun:
    """One per-character style annotation. `style_id` references a slot
    in the title's CStyleSheet. Reserved for future style-handle
    decoding; the partial TextTree decoder leaves this empty."""
    char_offset: int
    char_length: int
    style_id: int


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
    """Decoded CContent payload for a `TextRuns` typed body.

    Wire form per VIEWDLL.DLL `CTypedPtrArray<CElementData>::Serialize`
    @ 0x407092a6 + `CElementData::Serialize @ 0x40702e4c`:

      u16 count                          (CArchive::WriteCount narrow)
      count × CElementData:
        u8/u16/u32 length                (per CElementData length encoding)
        length B prose bytes

    `blobs` is the decoded list of prose strings (one per visible
    text run). The raw `text` attribute remains for backward-compat
    callers and is the concatenation of all blobs joined by `'\\n'`.
    """
    text: str
    style_runs: tuple[StyleRun, ...]
    header_version: int                                    # observed: 0x02 in story_test.ttl 8/7
    header_byte_1: int
    raw_payload: bytes                                     # bytes from offset 2 onwards (legacy)
    blobs: tuple[str, ...] = ()


@dataclass(frozen=True)
class TextTreeContent:
    """Decoded CContent payload for a `TextTree` typed body.

    Partial decoder surface:
      - `text`: concatenation of every `[0x03 length text]` segment
        in document order, joined by `'\\n'`.
      - `segments`: per-segment `(byte_offset, text)` tuples for
        consumers that need per-segment positioning.
      - `style_runs`: empty (full style-handle decode is out of
        scope per `docs/MEDVIEW-TEXT-ENCODING.md` §7).
      - `picture_refs`: ASCII CLSID strings found inside the body
        (one per detected INTRUDE-style picture record).
      - `raw_payload`: bytes from offset 2 onwards (after the
        `01 05` magic), for downstream tooling that needs the full
        body."""
    text: str
    segments: tuple[tuple[int, str], ...]
    style_runs: tuple[StyleRun, ...] = ()
    picture_refs: tuple[PictureRef, ...] = ()
    raw_payload: bytes = b""


_TEXTTREE_MAGIC = bytes.fromhex("0105")
_TEXT_SEGMENT_OPCODE = 0x03

# Match CLSID-bearing strings observed in TextTree picture INTRUDE
# records (e.g. `PICTURE.PictureCtrl.1`). Detection is on the raw
# bytes immediately preceded by a one-byte length matching the
# ASCII name's length — same shape as CBForm's `parse_mfc_ansi_string`.
_PICTURE_CLSID_MARKER = b"CLSID"


def is_texttree(raw: bytes) -> bool:
    """TextTree payloads start with `01 05`. Caller decompresses any
    CK wrapper before calling — TextTree bodies are also CK-wrapped
    in some TTLs."""
    return len(raw) >= 2 and raw[:2] == _TEXTTREE_MAGIC


def _read_segment_length(data: bytes, offset: int) -> tuple[int, int]:
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
    w = int.from_bytes(data[offset + 1:offset + 3], "little")
    if w != 0xFFFF:
        return (w, 3)
    if offset + 7 > len(data):
        return (0, 0)
    dw = int.from_bytes(data[offset + 3:offset + 7], "little")
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
        length, consumed = _read_segment_length(payload, i + 1)
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
            candidate = payload[pos + 1:pos + 1 + ln]
            if (
                all(0x20 <= b < 0x7F for b in candidate)
                and b"." in candidate
            ):
                lower = candidate.lower()
                if any(
                    lower.endswith(ext)
                    for ext in (b".bmp", b".wmf", b".dib", b".jpg",
                                b".png", b".gif", b".shg")
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
        if payload[pos:pos + 4] == b"\x10\x00\x00\x00":
            candidate = payload[pos + 4:pos + 20]
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
                            payload, name_end, scan_end,
                        )
                        iuid = _find_iuid_in_intrude(
                            payload, name_end, scan_end,
                        )
                        refs.append(PictureRef(
                            byte_offset=idx - 1,
                            clsid=name_bytes.decode("ascii"),
                            filename=filename,
                            iuid=iuid,
                        ))
                        pos = name_end
                        continue
        pos = idx + len(_PICTURE_CLSID_MARKER)
    return refs


def decode_texttree(raw: bytes) -> TextTreeContent:
    """Decode a `01 05`-prefixed TextTree CContent body.

    Partial — recovers text segments and picture INTRUDE
    references. Style runs and the full node opcode inventory are
    out of scope (see `docs/MEDVIEW-TEXT-ENCODING.md` §7).

    Pinned against:
      - `tests/assets/story_test.ttl 8/2` (85 B, plain text):
        `[01 05] ... [03 0x12 "Calendar of Events"] [03 0x1d
        "here's what's been happenin' "]`
      - `tests/assets/story_test.ttl 8/6` (1516 B, picture intrusion +
        list): CLSID `PICTURE.PictureCtrl.1` plus 10 text segments
        (`MSN Today (update test)`, list items, …).
    """
    if not is_texttree(raw):
        raise ValueError(
            f"not a TextTree payload (magic = {raw[:2].hex() if len(raw) >= 2 else '<short>'})"
        )
    payload = bytes(raw[2:])
    segments = _scan_text_segments(payload)
    picture_refs = _scan_picture_refs(payload)
    # Adjust segment offsets to be document-relative (account for
    # the 2-byte magic skip).
    segments = [(off + 2, text) for off, text in segments]
    text = "\n".join(t for _, t in segments)
    return TextTreeContent(
        text=text,
        segments=tuple(segments),
        style_runs=(),
        picture_refs=tuple(picture_refs),
        raw_payload=payload,
    )


def _read_celementdata_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read a CElementData length prefix per VIEWDLL.DLL
    `CElementData::Serialize @ 0x40702e4c`:

      length < 0xFF      → 1 B
      length < 0xFFFE    → `0xFF` + u16 LE
      length >= 0xFFFE   → `0xFF` + `0xFFFF` + u32 LE

    Returns `(length, bytes_consumed)`. `(0, 0)` on OOB.
    """
    if offset >= len(data):
        return (0, 0)
    b0 = data[offset]
    if b0 != 0xFF:
        return (b0, 1)
    if offset + 3 > len(data):
        return (0, 0)
    w = int.from_bytes(data[offset + 1:offset + 3], "little")
    if w != 0xFFFF:
        return (w, 3)
    if offset + 7 > len(data):
        return (0, 0)
    dw = int.from_bytes(data[offset + 3:offset + 7], "little")
    return (dw, 7)


def _parse_textruns_blobs(payload: bytes) -> tuple[list[str], int]:
    """Decode the CTypedPtrArray<CElementData>::Serialize body.

    Wire form per VIEWDLL.DLL `FUN_407092a6` (CTypedPtrArray's
    vtable+8 Serialize):

      u16 count_narrow                  (CArchive::WriteCount; 0xFFFF
                                         spills to + u32 wide)
      count × CElementData              ([length][bytes])

    Returns `(blobs, bytes_consumed)`. On malformed input the
    decoder returns what it could parse plus the consumed prefix.
    """
    if len(payload) < 2:
        return ([], 0)
    count = int.from_bytes(payload[0:2], "little")
    pos = 2
    if count == 0xFFFF:
        if len(payload) < 6:
            return ([], 2)
        count = int.from_bytes(payload[2:6], "little")
        pos = 6

    blobs: list[str] = []
    for _ in range(count):
        length, consumed = _read_celementdata_length(payload, pos)
        if consumed == 0 or pos + consumed + length > len(payload):
            break
        pos += consumed
        chunk = payload[pos:pos + length]
        blobs.append(chunk.decode("ascii", errors="replace"))
        pos += length
    return (blobs, pos)


def decode_textruns(raw: bytes) -> TextRunsContent:
    """Decode a `TextRuns` typed CContent body.

    Body grammar pinned via VIEWDLL.DLL
    `CTypedPtrArray<CElementData>::Serialize @ 0x407092a6`:

      u16 count                              (CArchive::WriteCount)
      count × [u8/u16/u32 length][bytes]

    The leading `u16 count` lives at the start of the CContent
    payload — the older `TextRuns` decoder treated the first two
    bytes as `(version, flag)` because they happen to be `02 00`
    for the canonical fixture (count = 2). Both interpretations
    decode to the same bytes; we expose the bytes via
    `header_version` / `header_byte_1` (for backward compatibility)
    while surfacing `blobs` as the structurally-correct decoded
    list of prose runs.

    Empty (`00 00` placeholder) and zero-length payloads decode
    to a `TextRunsContent` with `blobs = ()`. TextTree-magic
    payloads raise `ValueError`; callers should branch on
    `is_texttree(raw)` and call `decode_texttree` instead.
    """
    if is_texttree(raw):
        raise ValueError(
            "raw is a TextTree payload — call decode_texttree() instead"
        )
    if len(raw) < 2:
        return TextRunsContent(
            text="",
            style_runs=(),
            header_version=0,
            header_byte_1=0,
            raw_payload=b"",
        )
    version = raw[0]
    header_byte_1 = raw[1]
    payload = bytes(raw[2:])
    # Try the structurally-correct CTypedPtrArray decode against the
    # full raw buffer (count + elements).
    blobs, _consumed = _parse_textruns_blobs(bytes(raw))
    # `text` retains the legacy semantics (everything from offset +2
    # as ASCII) so existing substring-matching callers still work.
    text = payload.decode("ascii", errors="replace")
    return TextRunsContent(
        text=text,
        style_runs=(),
        header_version=version,
        header_byte_1=header_byte_1,
        raw_payload=payload,
        blobs=tuple(blobs),
    )
