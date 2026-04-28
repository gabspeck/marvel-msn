"""Blackbird authoring-side compound file (`.ttl`) parser.

Reads the COSCL / Blackbird OLE2 compound file emitted by
`BBDESIGN.EXE!CReleaseWizard_DoPublish` (Local target) and
`PUBLISH.DLL!CPublisher_PublishToMSN` (MSN target).  Format is
documented in `docs/BLACKBIRD.md` §3-§4 and §4.5.

What this module parses:

- Root stream `\\x03type_names_map` — a compact `{storage_id → class_name}`
  mapping (CTitle / CBForm / CVForm / CStyleSheet / CResourceFolder /
  CBFrame / CSection / CContent / CProxyTable on
  `resources/titles/4.ttl`).
- Per-storage `\\x03properties` streams — COSCL `CPropertyTable` single-
  property format; exposes the `name` ASCIIZ every class carries.  The
  CTitle `name` is the authored title display name and drives the
  MSN Today caption.
- Per-storage `\\x03object` streams — the C++ instance data each class
  serialises through `COSCL.DLL!extract_object`.  Three encodings:

    ver=0x01 + "CK" at offset 9 → MSZIP-compressed.  Header is
        `01 [u32 unc] [u32 cmp_with_CK]` followed by the `CK`
        signature and a raw-deflate stream of `cmp - 2` bytes.
    ver=0x01 (no CK at +9)        → small uncompressed v1; body
        is `data[1:]` (the leading 0x01 is just the serialisation tag).
    ver=0x02                      → uncompressed v2; body is
        `data[1:]`.  Class-specific schema.
    ver=0x03                      → uncompressed v3; body is
        `data[1:]`.  Empirically the body matches wire body section
        record sizes byte-for-byte (CSection at 9/1: 43-byte body =
        wire section-1 record stride), suggesting the 1996 server
        passed these bytes through verbatim.  Single-sample
        hypothesis pending more authored fixtures.
    ver=0x00                      → empty / sentinel.  Body is `b""`.

  Plaintext is exposed via `Title.objects[storage_id][substorage_id]`.
  The C++ class-member layout per blob is left for downstream consumers
  to interpret (CTitle's plaintext on 4.ttl starts with what looks like
  a font table — `09 07 00 06 00 0b "Courier New" ...`; full schema RE
  is class-by-class).

Scope — what this module does NOT parse:

- `\\x03handles` / `\\x03ref_N` streams (CDPORef monikers, cross-object
  references).  Structural only; not needed for the MSN Today caption
  or for downstream wire-body synthesis.

Callers (`medview.py`) treat this as best-effort: if the `.ttl` is
missing, olefile isn't installed, or a stream fails to parse, we fall
back to a deid-based label so MSN Today still opens cleanly.
"""

from __future__ import annotations

import io
import logging
import struct
import zlib
from dataclasses import dataclass, field

try:
    import olefile
    _HAVE_OLEFILE = True
except ImportError:  # pragma: no cover - olefile is a declared dep
    olefile = None  # type: ignore[assignment]
    _HAVE_OLEFILE = False

log = logging.getLogger(__name__)


_TYPE_NAMES_MAP_STREAM = "\x03type_names_map"
_PROPERTIES_STREAM = "\x03properties"
_OBJECT_STREAM = "\x03object"
_PROP_TYPE_STRING = 0x08
_CTITLE_CLASS = "CTitle"

_OBJ_VER_EMPTY = 0x00
_OBJ_VER_V1 = 0x01
_OBJ_VER_V2 = 0x02
_OBJ_VER_V3 = 0x03
_MSZIP_SIGNATURE = b"CK"
_OBJ_COMPRESSED_HEADER_LEN = 11  # ver(1) + unc(4) + cmp(4) + CK(2)


class TTLError(Exception):
    """Raised when a `.ttl` compound file can't be walked."""


@dataclass(frozen=True)
class Title:
    """Parsed view of a Blackbird `.ttl` compound file.

    `types` / `properties` are pinned to documented formats.  `objects`
    holds decoded `\\x03object` plaintext keyed by `(storage_id,
    substorage_id)`; per-class member layouts inside the plaintext are
    left to downstream consumers.
    """

    types: dict[int, str] = field(default_factory=dict)
    properties: dict[int, dict[str, str]] = field(default_factory=dict)
    objects: dict[int, dict[int, bytes]] = field(default_factory=dict)

    @property
    def display_name(self) -> str | None:
        """CTitle's `name` property — the viewer's caption on MSN Today."""
        for storage_id, class_name in self.types.items():
            if class_name == _CTITLE_CLASS:
                return self.properties.get(storage_id, {}).get("name")
        return None

    def class_name(self, storage_id: int) -> str | None:
        return self.types.get(storage_id)

    @classmethod
    def from_path(cls, path: str) -> Title:
        if not _HAVE_OLEFILE:
            raise TTLError("olefile not installed")
        ole = olefile.OleFileIO(path)
        try:
            return cls._from_ole(ole)
        finally:
            ole.close()

    @classmethod
    def from_bytes(cls, data: bytes) -> Title:
        if not _HAVE_OLEFILE:
            raise TTLError("olefile not installed")
        ole = olefile.OleFileIO(io.BytesIO(data))
        try:
            return cls._from_ole(ole)
        finally:
            ole.close()

    @classmethod
    def _from_ole(cls, ole) -> Title:
        if not ole.exists([_TYPE_NAMES_MAP_STREAM]):
            raise TTLError("missing type_names_map — not a Blackbird .ttl?")
        types = _parse_type_names_map(
            ole.openstream([_TYPE_NAMES_MAP_STREAM]).read()
        )
        properties: dict[int, dict[str, str]] = {}
        objects: dict[int, dict[int, bytes]] = {}
        for entry in ole.listdir(streams=True):
            if len(entry) != 3:
                continue
            try:
                sid = int(entry[0])
                sub = int(entry[1])
            except ValueError:
                continue
            if sid not in types:
                continue
            stream_name = entry[2]
            if stream_name == _PROPERTIES_STREAM and sub == 0:
                try:
                    properties[sid] = _parse_property_stream(
                        ole.openstream(entry).read()
                    )
                except TTLError as exc:
                    log.warning(
                        "properties parse sid=%d class=%r: %s",
                        sid, types[sid], exc,
                    )
                    properties[sid] = {}
            elif stream_name == _OBJECT_STREAM:
                try:
                    plain = _extract_object_stream(
                        ole.openstream(entry).read()
                    )
                except TTLError as exc:
                    log.warning(
                        "object extract sid=%d sub=%d class=%r: %s",
                        sid, sub, types[sid], exc,
                    )
                    continue
                objects.setdefault(sid, {})[sub] = plain
        return cls(types=types, properties=properties, objects=objects)


def _parse_type_names_map(data: bytes) -> dict[int, str]:
    """Parse `\\x03type_names_map` into `{storage_id: class_name}`.

    Observed layout on `resources/titles/4.ttl`:

        u32 count                    # number of entries (6 on 4.ttl)
        u16 ???                      # observed == count; opaque
        for count entries:
            u8  name_len
            char name[name_len]      # ASCII class name, no NUL
            u32 storage_id           # matches `<id>/0/...` substorage
    """
    if len(data) < 6:
        raise TTLError(f"type_names_map too short: {len(data)}B")
    (count,) = struct.unpack_from("<I", data, 0)
    pos = 6  # skip the opaque u16 that mirrors count
    out: dict[int, str] = {}
    for i in range(count):
        if pos + 1 > len(data):
            raise TTLError(f"type_names_map entry {i} truncated at {pos}")
        name_len = data[pos]
        pos += 1
        if pos + name_len + 4 > len(data):
            raise TTLError(
                f"type_names_map entry {i} wants {name_len}+4 B, only {len(data) - pos} left"
            )
        name = data[pos : pos + name_len].decode("ascii", errors="replace")
        pos += name_len
        (storage_id,) = struct.unpack_from("<I", data, pos)
        pos += 4
        out[storage_id] = name
    return out


def _extract_object_stream(data: bytes) -> bytes:
    """Decode a `\\x03object` stream to its plaintext member blob.

    Four encodings observed across authored `.ttl` fixtures:

    - `ver=0x02` (most small streams): uncompressed v2.  Body is
      everything after the version byte.  Class-specific schema —
      reflects the C++ instance state as the COSCL serialiser flushed
      it.  Downstream consumers must know the class to interpret.
    - `ver=0x01` with the `CK` MSZIP signature at offset 9: compressed.
      Header layout is `01 [u32 unc][u32 cmp_with_CK]`, then `CK`,
      then a raw-deflate (RFC 1951, no zlib wrapper) stream of
      `cmp - 2` bytes.  The compressed-size field includes the `CK`
      signature itself.
    - `ver=0x01` with no `CK` at offset 9 (small streams that happen to
      start with 0x01): uncompressed v1.  Body is `data[1:]`.  Same
      shape as v2; the leading byte is just the COSCL serialisation tag
      `extract_object` writes per class.
    - `ver=0x00`: empty / sentinel.  Body is empty.
    - `ver=0x03`: uncompressed wire-ready record (single sample so far,
      CSection 9/1 on the in-flight authored fixture; 43-byte body
      decomposes cleanly as `10 u32 + u16 + u8`, exactly matching the
      wire body section-1 record stride).  Hypothesis: ver=0x03 marks
      objects whose body is the byte-exact wire payload, so the 1996
      Marvel server memcpy'd them straight into the corresponding
      MEDVIEW body section.  Treated here identically to ver=0x02
      (body = `data[1:]`); the wire-ready interpretation is a
      consumer-side observation, not a parser-side decoding step.

    Multi-block MSZIP payloads (the algorithm allows up to 32 KB per
    deflate block, prepended with another `CK`) iterate by checking
    `unused_data` from the decompressor.  4.ttl's largest blob (CVForm
    at 6/0, 816 B uncompressed) fits in a single block so this path is
    untested on the fixture but kept for future titles.
    """
    if not data:
        return b""
    ver = data[0]
    if ver == _OBJ_VER_EMPTY:
        return b""
    if ver in (_OBJ_VER_V2, _OBJ_VER_V3):
        return bytes(data[1:])
    if ver != _OBJ_VER_V1:
        raise TTLError(f"object stream unknown version 0x{ver:02x}")
    # ver == 0x01: distinguish small-uncompressed from MSZIP
    if (
        len(data) < _OBJ_COMPRESSED_HEADER_LEN
        or data[9:11] != _MSZIP_SIGNATURE
    ):
        return bytes(data[1:])
    unc, _cmp = struct.unpack_from("<II", data, 1)
    out = bytearray()
    pos = 9  # start of first CK block
    while pos < len(data):
        if data[pos : pos + 2] != _MSZIP_SIGNATURE:
            raise TTLError(f"object stream block @{pos} missing CK signature")
        decomp = zlib.decompressobj(-zlib.MAX_WBITS)
        out += decomp.decompress(data[pos + 2 :])
        out += decomp.flush()
        unused = decomp.unused_data
        if not unused:
            break
        pos = len(data) - len(unused)
    if len(out) != unc:
        raise TTLError(
            f"object stream length: header said {unc}, decompressed {len(out)}"
        )
    return bytes(out)


def _parse_property_stream(data: bytes) -> dict[str, str]:
    """Parse a `\\x03properties` stream into `{name: string_value}`.

    Format observed on every storage in `4.ttl` (always a single
    `name` property):

        u32 prop_count
        for prop_count entries:
            u8  name_len
            char name[name_len]
            u8  type_tag             # 0x08 = ASCIIZ string
            u8  flags                # observed 0x00; opaque
            u32 value_len            # includes trailing NUL
            char value[value_len]

    Non-string type tags are logged and skipped (we've only seen 0x08
    in practice; anything else is reserved for future decode).
    """
    if len(data) < 4:
        return {}
    (count,) = struct.unpack_from("<I", data, 0)
    pos = 4
    out: dict[str, str] = {}
    for i in range(count):
        if pos + 1 > len(data):
            raise TTLError(f"properties entry {i} truncated at {pos}")
        name_len = data[pos]
        pos += 1
        if pos + name_len + 2 + 4 > len(data):
            raise TTLError(f"properties header {i} truncated at {pos}")
        name = data[pos : pos + name_len].decode("ascii", errors="replace")
        pos += name_len
        type_tag = data[pos]
        # flags byte at pos+1 is ignored for now
        pos += 2
        (value_len,) = struct.unpack_from("<I", data, pos)
        pos += 4
        if pos + value_len > len(data):
            raise TTLError(f"properties value {i} wants {value_len}B, only {len(data) - pos} left")
        raw = data[pos : pos + value_len]
        pos += value_len
        if type_tag == _PROP_TYPE_STRING:
            out[name] = raw.rstrip(b"\x00").decode("ascii", errors="replace")
        else:
            log.debug(
                "properties type 0x%02x not decoded name=%r raw=%s",
                type_tag, name, raw.hex(),
            )
    return out
