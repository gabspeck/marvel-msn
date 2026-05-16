"""OLE compound-file helpers for Blackbird `.ttl` parsing.

Lifted from `scripts/inspect_blackbird_title.py`; the script remains the
diagnostic tool, this module is the production import surface.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

CK_MAGIC = b"CK"

# Storage-table → class-name map used by typed swizzle refs in CSection /
# CTitle records (mirrors `SPTR_TYPE_NAMES` in inspect_blackbird_title.py).
SPTR_TYPE_NAMES: dict[int, str] = {
    1: "CProject",
    2: "CTitle",
    3: "CSection",
    4: "CBForm",
    5: "CBFrame",
    6: "CMagnet",
    7: "CStyleSheet",
    8: "CShortCut",
    9: "CFolder",
    10: "CContent",
    11: "CContentFolder",
    12: "CVForm",
    13: "CRootContentFolder",
    14: "CResourceFolder",
}


def parse_type_names_map(data: bytes) -> dict[int, str]:
    """`\\x03type_names_map` stream → `{storage_table_id: class_name}`.

    Wire shape: `[u32 count][u16 max_slot]{[u8 name_len][ASCII name]
    [u32 level_specifier]}*count`. The `level_specifier` is the
    top-level storage directory number (e.g. `5` for storage `5/<n>/`).
    """
    if len(data) < 6:
        raise ValueError("type_names_map stream too short")
    count = struct.unpack_from("<I", data, 0)[0]
    pos = 6                                                # skip count + max_slot
    out: dict[int, str] = {}
    for _ in range(count):
        name_len = data[pos]
        pos += 1
        name = data[pos:pos + name_len].decode("ascii", errors="replace")
        pos += name_len
        level_specifier = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        out[level_specifier] = name
    return out


def parse_handles(data: bytes) -> tuple[int, ...]:
    """`\\x03handles` stream → tuple of u32 handles. Swizzle index `i`
    resolves to `handles[i]`."""
    count = struct.unpack_from("<I", data, 0)[0]
    if len(data) != 4 + count * 4:
        raise ValueError(
            f"handles stream length {len(data)} ≠ expected {4 + count * 4}",
        )
    return struct.unpack_from(f"<{count}I", data, 4)


def resolve_swizzle(index: int, handles: tuple[int, ...]) -> int | None:
    if 0 <= index < len(handles):
        return handles[index]
    return None


def maybe_decompress_ck(data: bytes) -> bytes:
    """Strip MSZIP envelope if present, else return the input verbatim.

    Envelope: `[u8 flag=1][u32 uncompressed_size][u32 compressed_size]
    [u8 'C'][u8 'K'][deflate stream]`.
    """
    if len(data) < 11 or data[0] != 1:
        return data
    uncompressed_size = struct.unpack_from("<I", data, 1)[0]
    compressed_size = struct.unpack_from("<I", data, 5)[0]
    if 9 + compressed_size != len(data) or data[9:11] != CK_MAGIC:
        return data
    payload = zlib.decompress(data[11:], -15)
    if len(payload) != uncompressed_size:
        raise ValueError(
            f"CK decompressed size {len(payload)} ≠ expected {uncompressed_size}",
        )
    return payload


# ---------------------------------------------------------------------------
# MFC primitives (count + ANSI string)
# ---------------------------------------------------------------------------


def parse_mfc_count(buf: bytes, off: int) -> tuple[int, int]:
    """MFC `CCount` (`CArchive::ReadCount`): u16 sentinel; 0xFFFF spills
    to u32 wide form. Returns `(count, new_offset)`."""
    count = struct.unpack_from("<H", buf, off)[0]
    off += 2
    if count == 0xFFFF:
        count = struct.unpack_from("<I", buf, off)[0]
        off += 4
    return count, off


def parse_mfc_ansi_string(buf: bytes, off: int) -> tuple[str, int]:
    """MFC `CString` ANSI serialization: u8 length sentinel; 0xFF spills
    to u16 (then to u32 on 0xFFFF). Returns `(text, new_offset)`."""
    marker = buf[off]
    off += 1
    if marker == 0xFF:
        char_count = struct.unpack_from("<H", buf, off)[0]
        off += 2
        if char_count == 0xFFFF:
            char_count = struct.unpack_from("<I", buf, off)[0]
            off += 4
    else:
        char_count = marker
    raw = buf[off:off + char_count]
    if len(raw) != char_count:
        raise ValueError("MFC ANSI string overruns buffer")
    return raw.decode("ascii", errors="replace"), off + char_count


# ---------------------------------------------------------------------------
# Section / Proxy parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TypedSwizzleRef:
    type_code: int                                         # 0 for untyped sections list
    type_name: str                                         # via SPTR_TYPE_NAMES
    swizzle_index: int
    handle: int | None                                     # resolved through per-storage handles


@dataclass(frozen=True)
class SectionProp:
    section_ref_a: TypedSwizzleRef | None
    section_ref_b: TypedSwizzleRef | None
    section_ref_c: TypedSwizzleRef | None
    u32_0: int
    u32_1: int
    u8_0: int
    form_ref: TypedSwizzleRef | None


@dataclass(frozen=True)
class SectionRecord:
    version: int
    sections: tuple[TypedSwizzleRef, ...]                  # homogeneous (CSection)
    magnets: tuple[TypedSwizzleRef, ...]
    forms: tuple[TypedSwizzleRef, ...]
    contents: tuple[TypedSwizzleRef, ...]
    styles: tuple[TypedSwizzleRef, ...]
    frames: tuple[TypedSwizzleRef, ...]
    section_prop: SectionProp


@dataclass(frozen=True)
class ProxyEntry:
    proxy_key: int                                         # e.g. 0x00001500, 0x00001400
    content_index: int
    content_handle: int | None


def _typed_ref(type_code: int, index: int, handles: tuple[int, ...]) -> TypedSwizzleRef:
    return TypedSwizzleRef(
        type_code=type_code,
        type_name=SPTR_TYPE_NAMES.get(type_code, f"type_{type_code}"),
        swizzle_index=index,
        handle=resolve_swizzle(index, handles),
    )


def _parse_homogeneous_sptr_list(
    buf: bytes, off: int, handles: tuple[int, ...], type_code: int,
) -> tuple[tuple[TypedSwizzleRef, ...], int]:
    """CSection.sections: `[CCount count]{u32 swizzle_index}*count`. The
    runtime type is implied by context (CSection always), so the on-disk
    record carries no per-entry type code."""
    count, off = parse_mfc_count(buf, off)
    refs: list[TypedSwizzleRef] = []
    for _ in range(count):
        idx = struct.unpack_from("<I", buf, off)[0]
        off += 4
        refs.append(_typed_ref(type_code, idx, handles))
    return tuple(refs), off


def _parse_typed_sptr_list(
    buf: bytes, off: int, handles: tuple[int, ...],
) -> tuple[tuple[TypedSwizzleRef, ...], int]:
    """CSection.{magnets,forms,contents,styles,frames}:
    `[CCount count]{[u16 type_code][u32 swizzle_index]}*count`."""
    count, off = parse_mfc_count(buf, off)
    refs: list[TypedSwizzleRef] = []
    for _ in range(count):
        type_code = struct.unpack_from("<H", buf, off)[0]
        off += 2
        idx = struct.unpack_from("<I", buf, off)[0]
        off += 4
        refs.append(_typed_ref(type_code, idx, handles))
    return tuple(refs), off


def _parse_section_prop(
    buf: bytes, off: int, section_version: int, handles: tuple[int, ...],
) -> tuple[SectionProp, int]:
    refs: list[TypedSwizzleRef | None] = []
    for _ in range(3):
        present = buf[off]
        off += 1
        if present:
            idx = struct.unpack_from("<I", buf, off)[0]
            off += 4
            refs.append(_typed_ref(3, idx, handles))       # presumed CSection refs
        else:
            refs.append(None)
    u32_0 = struct.unpack_from("<I", buf, off)[0]
    off += 4
    u32_1 = struct.unpack_from("<I", buf, off)[0]
    off += 4
    u8_0 = buf[off]
    off += 1
    form_ref: TypedSwizzleRef | None = None
    if section_version > 2:
        present = buf[off]
        off += 1
        if present:
            idx = struct.unpack_from("<I", buf, off)[0]
            off += 4
            form_ref = _typed_ref(4, idx, handles)         # presumed CBForm ref
    return SectionProp(
        section_ref_a=refs[0],
        section_ref_b=refs[1],
        section_ref_c=refs[2],
        u32_0=u32_0,
        u32_1=u32_1,
        u8_0=u8_0,
        form_ref=form_ref,
    ), off


def parse_section(buf: bytes, handles: tuple[int, ...]) -> SectionRecord:
    """CTitle.0/\\x03object and CSection/N/\\x03object payload shape:
    `[u8 version]{section list}{magnet list}{form list}{content list}
    {style list}{frame list}{section_prop}`. The first u8 is the
    section version; lists are MFC-counted; prop tail depends on
    version > 2 carrying a form_ref flag/handle."""
    if not buf:
        raise ValueError("empty section buffer")
    version = buf[0]
    off = 1
    sections, off = _parse_homogeneous_sptr_list(buf, off, handles, type_code=3)
    magnets, off = _parse_typed_sptr_list(buf, off, handles)
    forms, off = _parse_typed_sptr_list(buf, off, handles)
    contents, off = _parse_typed_sptr_list(buf, off, handles)
    styles, off = _parse_typed_sptr_list(buf, off, handles)
    frames, off = _parse_typed_sptr_list(buf, off, handles)
    section_prop, _ = _parse_section_prop(buf, off, version, handles)
    return SectionRecord(
        version=version,
        sections=sections,
        magnets=magnets,
        forms=forms,
        contents=contents,
        styles=styles,
        frames=frames,
        section_prop=section_prop,
    )


def parse_proxy_table(
    buf: bytes, handles: tuple[int, ...],
) -> tuple[ProxyEntry, ...]:
    """CProxyTable payload shape: `[CCount count]{[u32 proxy_key][u32
    content_swizzle_index]}*count`."""
    count, off = parse_mfc_count(buf, 0)
    entries: list[ProxyEntry] = []
    for _ in range(count):
        proxy_key = struct.unpack_from("<I", buf, off)[0]
        off += 4
        idx = struct.unpack_from("<I", buf, off)[0]
        off += 4
        entries.append(ProxyEntry(
            proxy_key=proxy_key,
            content_index=idx,
            content_handle=resolve_swizzle(idx, handles),
        ))
    return tuple(entries)


def ole_storage_id(value: int) -> str:
    """Blackbird-authored TTLs name storage directories with lowercase
    hex per nibble — table 10 → `a`, slot 12 → `c`, etc. Tables/slots in
    0..9 collapse to the same decimal-looking digit. Tables/slots ≥ 16
    are unobserved; defaults to a plain `format(value, 'x')` either way."""
    return format(value, "x")


def parse_handles_by_storage(ole) -> dict[tuple[int, int], tuple[int, ...]]:
    """Read every `<table>/<slot>/\\x03handles` stream and return a map
    keyed by `(table, slot)`. Used by callers that need to thread per-
    storage handles into object-stream parsers. Storage names are
    parsed as hex (so showcase's `a/7` resolves to `(10, 7)`)."""
    out: dict[tuple[int, int], tuple[int, ...]] = {}
    for entry in ole.listdir(streams=True, storages=False):
        if len(entry) != 3 or entry[2] != "\x03handles":
            continue
        try:
            table = int(entry[0], 16)
            slot = int(entry[1], 16)
        except ValueError:
            continue
        out[(table, slot)] = parse_handles(ole.openstream(entry).read())
    return out


def parse_simple_property_table(data: bytes) -> dict[str, object]:
    """`<table>/<slot>/\\x03properties` → `{key: value}`. Supports the
    five VT codes observed in Blackbird-authored TTLs (string, bool,
    u1, u4, blob). Unknown types raise."""
    pos = 0
    count = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    out: dict[str, object] = {}
    for _ in range(count):
        key_len = data[pos]
        pos += 1
        key = data[pos:pos + key_len].decode("ascii", errors="replace")
        pos += key_len
        vartype = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if vartype == 0x0008:                              # VT_STRING
            char_count = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            raw = data[pos:pos + char_count + 1]
            pos += char_count + 1
            out[key] = raw[:-1].decode("ascii", errors="replace")
        elif vartype == 0x000B:                            # VT_BOOL
            out[key] = bool(struct.unpack_from("<H", data, pos)[0])
            pos += 2
        elif vartype == 0x0013:                            # VT_UI4
            out[key] = struct.unpack_from("<I", data, pos)[0]
            pos += 4
        elif vartype == 0x0011:                            # VT_UI1
            out[key] = data[pos]
            pos += 1
        elif vartype == 0x0041:                            # VT_BLOB
            blob_len = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            out[key] = bytes(data[pos:pos + blob_len])
            pos += blob_len
        else:
            raise ValueError(f"unsupported vartype 0x{vartype:04x}")
    return out
