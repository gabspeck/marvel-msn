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
    (e.g. `PICTURE.PictureCtrl.1`) plus a FILE / DATA1 pair pointing
    into baggage. The partial decoder surfaces the byte offset and
    raw CLSID string; the full reference's baggage proxy key is left
    open for the full grammar walk."""
    byte_offset: int
    clsid: str


@dataclass(frozen=True)
class TextRunsContent:
    """Decoded CContent payload for a `TextRuns` typed body.

    `paragraph_markers` lists the in-stream `[u8 marker][prose]` runs
    surfaced by the partial decoder (see
    `docs/MEDVIEW-TEXT-ENCODING.md` §7.4). Each tuple is
    `(byte_offset, marker_char, prose)` — the marker byte is a single
    ASCII char that selects a paragraph style in the title's
    CStyleSheet (observed values include `'S'`, `'#'`, `'3'`; the
    exhaustive inventory is not yet RE'd).
    """
    text: str
    style_runs: tuple[StyleRun, ...]
    header_version: int                                    # observed: 0x02 in story_test.ttl 8/7
    header_byte_1: int
    raw_payload: bytes                                     # bytes from offset 2 onwards
    paragraph_markers: tuple[tuple[int, str, str], ...] = ()


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


def _scan_picture_refs(payload: bytes) -> list[PictureRef]:
    """Find Blackbird INTRUDE-style picture records inside `payload`.

    The writer ships pictures as `[u8 ascii_len][CLSID name]` followed
    by `[u8 5][... value ...]` property pairs. We detect by scanning
    for the literal `CLSID` token (preceded by a one-byte length =
    5), then reading the ASCII name that follows (its length encoded
    the same way).
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
                        refs.append(PictureRef(
                            byte_offset=idx - 1,
                            clsid=name_bytes.decode("ascii"),
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


_PARAGRAPH_MARKER_CHARS = frozenset("SH#3457*&I")  # observed; extend as RE pins more


def _scan_paragraph_markers(
    payload: bytes,
) -> tuple[list[tuple[int, str, str]], str]:
    """Split a TextRuns body into `[u8 marker][prose]` runs.

    Per `docs/MEDVIEW-TEXT-ENCODING.md` §7.4, each run starts with a
    single ASCII marker byte (e.g. `'S'`, `'#'`, `'3'`) selecting a
    paragraph style. Returns `(markers, prose_only_concat)`.

    Heuristic: a marker is a single byte from
    `_PARAGRAPH_MARKER_CHARS` that appears immediately after the
    previous run's last printable text. We split conservatively —
    when the first byte of `payload` is a known marker, we treat it
    as a marker; the next ASCII run is its prose; subsequent
    marker-boundaries are inferred only when followed by printable
    prose, otherwise the byte is treated as text.
    """
    markers: list[tuple[int, str, str]] = []
    if not payload:
        return markers, ""
    first = chr(payload[0])
    if first not in _PARAGRAPH_MARKER_CHARS:
        # No recognised paragraph marker — treat whole body as one
        # default-style run with marker = empty string.
        return [(0, "", payload.decode("ascii", errors="replace"))], (
            payload.decode("ascii", errors="replace")
        )
    # First byte is a marker; scan forward greedily.
    cursor = 0
    while cursor < len(payload):
        marker_off = cursor
        marker = chr(payload[cursor])
        if marker not in _PARAGRAPH_MARKER_CHARS:
            # Ran past a marker into prose without a hand-off — append
            # the rest to the previous run.
            if markers:
                last_off, last_marker, last_prose = markers[-1]
                tail = payload[cursor:].decode("ascii", errors="replace")
                markers[-1] = (last_off, last_marker, last_prose + tail)
            break
        cursor += 1
        prose_start = cursor
        # Walk until next marker char (preceded by a space → likely
        # paragraph break) or end of payload.
        while cursor < len(payload):
            c = payload[cursor]
            if (
                cursor > prose_start
                and chr(c) in _PARAGRAPH_MARKER_CHARS
                and payload[cursor - 1] == 0x20  # ' ' before marker = boundary
            ):
                break
            cursor += 1
        prose = payload[prose_start:cursor].rstrip(b" ").decode(
            "ascii", errors="replace",
        )
        markers.append((marker_off, marker, prose))
    prose_only = "".join(p for _, _, p in markers)
    return markers, prose_only


def decode_textruns(raw: bytes) -> TextRunsContent:
    """Empirical TextRuns parser.

    - Payloads shorter than 2 B (e.g. `00 00` empty blob) decode to an
      empty container.
    - TextTree payloads raise `ValueError`; callers should branch on
      `is_texttree(raw)` and call `decode_texttree` instead.

    `paragraph_markers` is populated by `_scan_paragraph_markers` —
    one `(byte_offset, marker_char, prose)` tuple per run. `text`
    retains the legacy semantics (everything from offset +2 decoded
    as ASCII) so existing callers see no behavioural change.
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
    text = payload.decode("ascii", errors="replace")
    markers, _prose = _scan_paragraph_markers(payload)
    return TextRunsContent(
        text=text,
        style_runs=(),
        header_version=version,
        header_byte_1=header_byte_1,
        raw_payload=payload,
        paragraph_markers=tuple(markers),
    )
