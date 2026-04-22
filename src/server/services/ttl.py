"""Blackbird authoring-side compound file (`.ttl`) parser.

Reads the COSCL / Blackbird OLE2 compound file emitted by
`BBDESIGN.EXE!CReleaseWizard_DoPublish` (Local target) and
`PUBLISH.DLL!CPublisher_PublishToMSN` (MSN target).  Format is
documented in `docs/BLACKBIRD.md` §3-§4 and §4.5.

Scope — what this module DOES parse (well-understood, static):

- Root stream `\\x03type_names_map` — a compact `{storage_id → class_name}`
  mapping (CTitle / CBForm / CVForm / CStyleSheet / CResourceFolder /
  CBFrame on `resources/titles/4.ttl`).
- Per-storage `\\x03properties` streams — COSCL `CPropertyTable` single-
  property format; exposes the `name` ASCIIZ every class carries.  The
  CTitle `name` is the authored title display name and drives the
  MSN Today caption.

Scope — what this module does NOT parse:

- Per-storage `\\x03object` streams.  CTitle / CBForm / CVForm instance
  data and the CVForm's 534 B widget layout on `4.ttl` are serialized
  by `COSCL.DLL!extract_object` and the larger streams are MS-stock
  compressed (9-byte header: `01 [u32 uncompressed_size] [u32
  compressed_size]`, then opaque compressed body — algorithm not yet
  reversed).  Decoding these requires RE of `extract_object` and the
  matching decompression routine.  Left opaque here.
- `\\x03handles` / `\\x03ref_N` streams (CDPORef monikers, cross-object
  references).  Structural only; not needed for the MSN Today caption.

Callers (`medview.py`) treat this as best-effort: if the `.ttl` is
missing, olefile isn't installed, or a stream fails to parse, we fall
back to a deid-based label so MSN Today still opens cleanly.
"""

from __future__ import annotations

import io
import logging
import struct
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
_PROP_TYPE_STRING = 0x08
_CTITLE_CLASS = "CTitle"


class TTLError(Exception):
    """Raised when a `.ttl` compound file can't be walked."""


@dataclass(frozen=True)
class Title:
    """Parsed view of a Blackbird `.ttl` compound file.

    Only the well-understood surfaces are populated; opaque streams
    (compressed `object` blobs, CDPORef monikers) are skipped.
    """

    types: dict[int, str] = field(default_factory=dict)
    properties: dict[int, dict[str, str]] = field(default_factory=dict)

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
        for storage_id in types:
            path = [str(storage_id), "0", _PROPERTIES_STREAM]
            if not ole.exists(path):
                continue
            try:
                properties[storage_id] = _parse_property_stream(
                    ole.openstream(path).read()
                )
            except TTLError as exc:
                log.warning(
                    "properties parse sid=%d class=%r: %s",
                    storage_id, types[storage_id], exc,
                )
                properties[storage_id] = {}
        return cls(types=types, properties=properties)


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
