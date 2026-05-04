"""Blackbird `.ttl` (OLE2 compound file) inspector.

Lifted verbatim from `~/projetos/blackbird-re/scripts/inspect_blackbird_title.py`
with only the CLI `main()` removed. Format spec is documented in
`docs/blackbird-title-format.md`.

Public entry point: `inspect_blackbird_title(path)` returns a dict with
`type_map`, `title_props`, `object_streams`, `ref_tables_by_id`, etc.
The MediaView 1.4 synthesizer in `m14_synth.py` consumes this dict.
"""

from __future__ import annotations

import uuid
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import olefile


VT_BOOL = 0x000B
VT_UI1 = 0x0011
VT_UI4 = 0x0013
VT_STRING = 0x0008
VT_BLOB = 0x0041
NEW_CLASS_TAG = 0xFFFF
CK_MAGIC = b"CK"
SPTR_TYPE_NAMES = {
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


def read_u8(data, off):
    return data[off], off + 1


def read_u16(data, off):
    return int.from_bytes(data[off:off + 2], "little"), off + 2


def read_u32(data, off):
    return int.from_bytes(data[off:off + 4], "little"), off + 4


def read_u64(data, off):
    return int.from_bytes(data[off:off + 8], "little"), off + 8


def read_bytes(data, off, size):
    chunk = data[off:off + size]
    if len(chunk) != size:
        raise ValueError("stream overruns requested field")
    return chunk, off + size


def parse_type_names_map(data):
    off = 0
    count, off = read_u32(data, off)
    max_slot, off = read_u16(data, off)
    entries = []
    for idx in range(count):
        name_len, off = read_u8(data, off)
        name = data[off:off + name_len].decode("ascii", errors="replace")
        off += name_len
        level_specifier, off = read_u32(data, off)
        entries.append(
            {
                "slot": max_slot - idx,
                "name": name,
                "level_specifier": level_specifier,
            }
        )
    return entries


def parse_simple_property_table(data):
    off = 0
    count, off = read_u32(data, off)
    props = []
    for _ in range(count):
        key_len, off = read_u8(data, off)
        if off + key_len > len(data):
            raise ValueError("key overruns stream")
        key = data[off:off + key_len].decode("ascii", errors="replace")
        off += key_len
        vartype, off = read_u16(data, off)
        if vartype == VT_STRING:
            char_count, off = read_u32(data, off)
            raw = data[off:off + char_count + 1]
            if len(raw) != char_count + 1:
                raise ValueError("string overruns stream")
            value = raw[:-1].decode("ascii", errors="replace")
            off += char_count + 1
        elif vartype == VT_BOOL:
            raw, off = read_u16(data, off)
            value = bool(raw)
        elif vartype == VT_UI4:
            value, off = read_u32(data, off)
        elif vartype == VT_UI1:
            value, off = read_u8(data, off)
        elif vartype == VT_BLOB:
            blob_len, off = read_u32(data, off)
            raw = data[off:off + blob_len]
            if len(raw) != blob_len:
                raise ValueError("blob overruns stream")
            value = raw.hex()
            off += blob_len
        else:
            raise ValueError(f"unsupported vartype 0x{vartype:04x}")
        props.append({"key": key, "vartype": vartype, "value": value})
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return props


def parse_handles(data):
    off = 0
    count, off = read_u32(data, off)
    handles = []
    for _ in range(count):
        handle, off = read_u32(data, off)
        handles.append(handle)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return handles


def maybe_decompress_ck(data):
    if len(data) < 11 or data[0] != 1:
        return None
    uncompressed_size = int.from_bytes(data[1:5], "little")
    compressed_size = int.from_bytes(data[5:9], "little")
    if 9 + compressed_size != len(data):
        return None
    if data[9:11] != CK_MAGIC:
        return None
    payload = zlib.decompress(data[11:], -15)
    if len(payload) != uncompressed_size:
        raise ValueError(
            "decompressed payload length mismatch: "
            f"{len(payload)} != {uncompressed_size}"
        )
    return {
        "wrapper_version": data[0],
        "uncompressed_size": uncompressed_size,
        "compressed_size": compressed_size,
        "payload": payload,
    }


def parse_ref_table_prelude(data):
    off = 0
    start_word, off = read_u32(data, off)
    word_count, off = read_u32(data, off)
    capacity_words, off = read_u32(data, off)
    words = []
    for _ in range(word_count):
        word, off = read_u32(data, off)
        words.append(word)
    slot_count, off = read_u32(data, off)
    occupied = []
    for slot in range(slot_count):
        word_index = slot >> 5
        bit_index = slot & 0x1F
        if word_index < len(words) and (words[word_index] & (1 << bit_index)):
            occupied.append(slot)
    return {
        "start_word": start_word,
        "word_count": word_count,
        "capacity_words": capacity_words,
        "words": words,
        "slot_count": slot_count,
        "occupied_slots": occupied,
        "payload_offset": off,
        "payload_size": len(data) - off,
    }


def format_filetime(raw):
    ticks = int.from_bytes(raw, "little")
    if ticks == 0:
        return "0"
    base = datetime(1601, 1, 1, tzinfo=timezone.utc)
    stamp = base + timedelta(microseconds=ticks // 10)
    return f"0x{ticks:016x} ({stamp.isoformat()})"


def parse_cdpo_ref_entry(data, off):
    marker, off = read_u16(data, off)
    if marker == NEW_CLASS_TAG:
        schema, off = read_u16(data, off)
        name_len, off = read_u16(data, off)
        name_raw, off = read_bytes(data, off, name_len)
        header = {
            "kind": "new_class",
            "schema": schema,
            "class_name": name_raw.decode("ascii", errors="replace"),
        }
    else:
        header = {
            "kind": "class_ref",
            "raw_marker": marker,
            "class_ref": marker & 0x7FFF,
        }

    flags, off = read_u32(data, off)
    ref_count, off = read_u32(data, off)
    entry = {
        "header": header,
        "flags": flags,
        "obj_kind": flags >> 28,
        "moniker_flags": flags & 0x0FFFFFFF,
        "ref_count": ref_count,
    }

    if flags & (1 << 8):
        raw, off = read_bytes(data, off, 8)
        entry["obj_mod_time"] = format_filetime(raw)
    if flags & (1 << 9):
        raw, off = read_bytes(data, off, 8)
        entry["props_mod_time"] = format_filetime(raw)
    if flags & (1 << 3):
        raw, off = read_bytes(data, off, 16)
        entry["obj_guid"] = str(uuid.UUID(bytes_le=raw))

    obj_cos_path_handle, off = read_u32(data, off)
    entry["obj_cos_path_handle"] = obj_cos_path_handle
    entry["next_offset"] = off
    return entry


def parse_ref_table(data):
    info = parse_ref_table_prelude(data)
    off = info["payload_offset"]
    entries = []
    for slot in info["occupied_slots"]:
        entry = parse_cdpo_ref_entry(data, off)
        entry["slot"] = slot
        entry["offset"] = off
        off = entry.pop("next_offset")
        entries.append(entry)
    info["entries"] = entries
    info["trailing_bytes"] = len(data) - off
    return info


def parse_mfc_count(data, off):
    count, off = read_u16(data, off)
    if count == 0xFFFF:
        count, off = read_u32(data, off)
    return count, off


def parse_mfc_ansi_string(data, off):
    count_marker, off = read_u8(data, off)
    if count_marker == 0xFF:
        char_count, off = read_u16(data, off)
        if char_count == 0xFFFF:
            char_count, off = read_u32(data, off)
    else:
        char_count = count_marker
    raw, off = read_bytes(data, off, char_count)
    return raw.decode("ascii", errors="replace"), off


# Object-handle bit format (verified via every handle in the
# reference Marvel TTL `resources/titles/4.ttl` and the older
# Blackbird sample `/var/share/drop/first title.ttl` — 36/36
# handles round-trip): `handle = (table_id << 21) | slot`. The
# `table_id` is the same level-specifier that keys
# `\x03type_names_map`; `slot` is the integer that names the per-
# class sub-storage (`<table_id>/<slot>/\x03object`). The
# `\x03ref_<table_id>` stream holds one CDPORef per slot — its
# `obj_cos_path_handle` field equals the encoded handle, so any
# handle observed in an object's `\x03handles` stream points to
# both a concrete OLE storage (via decode) and an entry in the
# matching ref table (via the same value).
_HANDLE_SLOT_MASK = (1 << 21) - 1


def decode_handle(handle):
    """Split a CDPO handle into `(table_id, slot)`.

    The format is `(table_id << 21) | slot`, with `slot` occupying
    the low 21 bits (mask `0x1FFFFF`). `table_id` matches the
    level_specifier in `\\x03type_names_map`.
    """
    return (handle >> 21, handle & _HANDLE_SLOT_MASK)


def encode_handle(table_id, slot):
    """Inverse of `decode_handle`."""
    if slot & ~_HANDLE_SLOT_MASK:
        raise ValueError(f"slot 0x{slot:x} exceeds 21-bit field")
    return (table_id << 21) | slot


def resolve_swizzle(index, handles):
    handle = None
    table_id = None
    slot = None
    if 0 <= index < len(handles):
        handle = handles[index]
        table_id, slot = decode_handle(handle)
    return {
        "index": index,
        "handle": handle,
        "table_id": table_id,
        "slot": slot,
    }


def parse_homogeneous_sptr_list(data, off, handles):
    count, off = parse_mfc_count(data, off)
    refs = []
    for _ in range(count):
        index, off = read_u32(data, off)
        refs.append(resolve_swizzle(index, handles))
    return refs, off


def parse_typed_sptr_list(data, off, handles):
    count, off = parse_mfc_count(data, off)
    refs = []
    for _ in range(count):
        type_code, off = read_u16(data, off)
        index, off = read_u32(data, off)
        ref = resolve_swizzle(index, handles)
        ref["type_code"] = type_code
        ref["type_name"] = SPTR_TYPE_NAMES.get(type_code, f"type_{type_code}")
        refs.append(ref)
    return refs, off


def parse_section_prop(data, off, section_version, handles):
    prop = {}
    for key in ("section_ref_a", "section_ref_b", "section_ref_c"):
        present, off = read_u8(data, off)
        if present:
            index, off = read_u32(data, off)
            prop[key] = resolve_swizzle(index, handles)
        else:
            prop[key] = None
    prop["u32_0"], off = read_u32(data, off)
    prop["u32_1"], off = read_u32(data, off)
    prop["u8_0"], off = read_u8(data, off)
    prop["form_ref"] = None
    if section_version > 2:
        present, off = read_u8(data, off)
        if present:
            index, off = read_u32(data, off)
            prop["form_ref"] = resolve_swizzle(index, handles)
    return prop, off


def parse_csection_payload(data, off, handles):
    version, off = read_u8(data, off)
    sections, off = parse_homogeneous_sptr_list(data, off, handles)
    magnets, off = parse_typed_sptr_list(data, off, handles)
    forms, off = parse_typed_sptr_list(data, off, handles)
    contents, off = parse_typed_sptr_list(data, off, handles)
    styles, off = parse_typed_sptr_list(data, off, handles)
    frames, off = parse_typed_sptr_list(data, off, handles)
    props, off = parse_section_prop(data, off, version, handles)
    return {
        "version": version,
        "sections": sections,
        "magnets": magnets,
        "forms": forms,
        "contents": contents,
        "styles": styles,
        "frames": frames,
        "section_prop": props,
    }, off


def parse_ctitle_object(data, handles):
    off = 0
    version, off = read_u8(data, off)
    base_section, off = parse_csection_payload(data, off, handles)
    resource_index, off = read_u32(data, off)
    shortcut_count, off = parse_mfc_count(data, off)
    if shortcut_count != 0:
        raise ValueError("non-empty shortcut list not yet observed")
    trailing_name, off = parse_mfc_ansi_string(data, off)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return {
        "version": version,
        "base_section": base_section,
        "resource_folder": resolve_swizzle(resource_index, handles),
        "shortcut_count": shortcut_count,
        "trailing_name": trailing_name,
    }


def parse_csection_object(data, handles):
    section, off = parse_csection_payload(data, 0, handles)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return section


def parse_cfolder_payload(data, off, handles):
    version, off = read_u8(data, off)
    object_refs, off = parse_typed_sptr_list(data, off, handles)
    trailing_byte, off = read_u8(data, off)
    return {
        "version": version,
        "objects": object_refs,
        "trailing_byte": trailing_byte,
    }, off


def parse_cresourcefolder_object(data, handles):
    off = 0
    version, off = read_u8(data, off)
    base_folder, off = parse_cfolder_payload(data, off, handles)
    default_stylesheet_index, off = read_u32(data, off)
    default_frame_index, off = read_u32(data, off)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return {
        "version": version,
        "base_folder": base_folder,
        "default_stylesheet": resolve_swizzle(default_stylesheet_index, handles),
        "default_frame": resolve_swizzle(default_frame_index, handles),
    }


def parse_cbframe_object(data):
    off = 0
    version, off = read_u8(data, off)
    name_0, off = parse_mfc_ansi_string(data, off)
    name_1, off = parse_mfc_ansi_string(data, off)
    u64_0, off = read_u64(data, off)
    u64_1, off = read_u64(data, off)
    u32_0, off = read_u32(data, off)
    u32_1, off = read_u32(data, off)
    u8_0, off = read_u8(data, off)
    u32_2, off = read_u32(data, off)
    u8_1, off = read_u8(data, off)
    u8_2, off = read_u8(data, off)
    u8_3, off = read_u8(data, off)
    tail_present, off = read_u8(data, off)
    return {
        "version": version,
        "name_0": name_0,
        "name_1": name_1,
        "u64_0": u64_0,
        "u64_1": u64_1,
        "u32_0": u32_0,
        "u32_1": u32_1,
        "u8_0": u8_0,
        "u32_2": u32_2,
        "u8_1": u8_1,
        "u8_2": u8_2,
        "u8_3": u8_3,
        "tail_present": tail_present,
        "trailing_bytes": len(data) - off,
    }


def parse_cbform_object(data, handles):
    off = 0
    version, off = read_u8(data, off)
    form_name, off = parse_mfc_ansi_string(data, off)
    form_mode, off = read_u8(data, off)
    embedded_vform_present, off = read_u8(data, off)
    embedded_vform = None
    if embedded_vform_present:
        index, off = read_u32(data, off)
        embedded_vform = resolve_swizzle(index, handles)
    frame_index, off = read_u32(data, off)
    u32_0, off = read_u32(data, off)
    u32_1, off = read_u32(data, off)
    u32_2, off = read_u32(data, off)
    u32_3, off = read_u32(data, off)
    u64_0, off = read_u64(data, off)
    u8_0, off = read_u8(data, off)
    dpi_x, off = read_u32(data, off)
    dpi_y, off = read_u32(data, off)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return {
        "version": version,
        "form_name": form_name,
        "form_mode": form_mode,
        "embedded_vform_present": embedded_vform_present,
        "embedded_vform": embedded_vform,
        "frame": resolve_swizzle(frame_index, handles),
        "u32_0": u32_0,
        "u32_1": u32_1,
        "u32_2": u32_2,
        "u32_3": u32_3,
        "u64_0": u64_0,
        "u8_0": u8_0,
        "dpi_x": dpi_x,
        "dpi_y": dpi_y,
    }


def parse_proxy_data_map(data, handles):
    off = 0
    count, off = parse_mfc_count(data, off)
    entries = []
    for _ in range(count):
        key, off = read_u32(data, off)
        index, off = read_u32(data, off)
        entry = {
            "key": key,
            "target": resolve_swizzle(index, handles),
        }
        entries.append(entry)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes remain")
    return {
        "count": count,
        "entries": entries,
    }


def parse_stylesheet_header(data):
    off = 0
    version, off = read_u8(data, off)
    font_count, off = parse_mfc_count(data, off)
    fonts = []
    for _ in range(font_count):
        key, off = read_u16(data, off)
        name, off = parse_mfc_ansi_string(data, off)
        fonts.append({"key": key, "name": name})
    style_count, off = parse_mfc_count(data, off)
    style_first_key = None
    if style_count != 0:
        style_first_key, _ = read_u16(data, off)
    return {
        "version": version,
        "font_count": font_count,
        "fonts": fonts,
        "style_count": style_count,
        "style_map_offset": off,
        "style_first_key": style_first_key,
    }


# CCharProps mask bit → field. Each entry: (bit, size_in_bytes, name).
# Bit set in BOTH mask_explicit and mask_concrete on the wire = field has
# explicit value. Bit clear in mask_explicit + set in mask_concrete =
# "no_change" (engine sentinel 0xFFFF / 0xFFFFFFFF). Both clear, or only
# mask_explicit set = "absent" (0xFFFE / 0xFFFFFFFE).
# Field names match VIEWDLL accessors `?EGetXxx@CCharProps@@…`. Each
# accessor calls `EGetWord(kind, ...)` (`?EGetWord@CCharProps@@QAEGGH@Z`
# @ 0x4070692e) which maps kind→on-disk offset:
#   kind 5 → this+4 (flags word: bold/italic/underline/super/sub bits)
#   kind 3 → this+8 (font_id; resolved against CStyleSheet.fonts[].key)
#   kind 4 → this+10 (point size in points; default 12)
# `text_color` / `back_color` use `EGetColorRef` and read 4 raw bytes
# via `FUN_4070f2f2` (a CArchive byte-copy helper).
_CCHARPROPS_FIELDS = (
    # bit 0 — `flags_word`: bit-pairs (absent_mask, value) for the five
    # text-attribute toggles. Pinned via VIEWDLL `SetBoldState` /
    # `SetItalicState` / `SetUnderlineState` / `SetSuperscriptState` /
    # `SetSubscriptState` (each clears its absent_mask bit then sets/
    # clears its value bit) and the `SetDefault*` peers (which OR the
    # absent_mask bit back in). `IsStyle` @ 0x40707b3f and
    # `ResetCharProps` @ 0x4073194b confirm the engine reads ONLY these
    # five bit-pairs. BBDESIGN enforces super/sub mutual exclusion at
    # authoring time ("Conflicting postionng information. Check
    # superscript and subscript values.") — VIEWDLL does NOT enforce
    # it on the wire, so a malformed TTL can technically have both
    # bits set; the renderer's behavior is engine-defined.
    #
    #   attr        absent_mask  value_bit
    #   bold        0x0100       0x0002
    #   italic      0x0200       0x0004
    #   underline   0x0400       0x0008
    #   superscript 0x0800       0x0010
    #   subscript   0x1000       0x0020
    #
    # Bits 0x0040, 0x0080 (low byte), 0x2000, 0x4000, 0x8000 (high
    # byte) are RESERVED — no VIEWDLL function reads or writes them.
    # Per-style baked defaults at 0x40770e00 always set bits 0x2000
    # and 0x4000 in non-zero entries (likely a binary-data-table
    # assembler artifact); user-authored TTLs may also set 0x8000
    # (`/var/share/drop/first title.ttl` 4/1 sid=1 has flags_word
    # 0xfcfe with bit 15 set). Carry them through verbatim — the
    # renderer ignores them. Constructor (`CCharProps::CCharProps`
    # @ 0x407080ce) inits the whole word to 0xffff = "no_change".
    #
    # Field-level sentinels (whole u16): 0xfffe = "absent", 0xffff =
    # "no_change".
    (0, 2, "flags_word"),
    (1, 2, "font_id"),       # u16 — index into CStyleSheet.fonts[].key
    (2, 2, "pt_size"),       # u16 — point size (default 12 per GetPtSize)
    (3, 4, "text_color"),    # u32 colorref
    (4, 4, "back_color"),    # u32 colorref
)

# CParaProps mask bit → field, bits 0..11. Source: VIEWDLL
# `CParaProps::Serialize` @ 0x407082e2; field semantics from
# `?EGetXxx@CParaProps@@…` accessors (kind→offset map in
# `?EGetWord@CParaProps@@…` @ 0x4070733d and `?EGetShort@…` @ 0x4070812e).
# Bit 12 (mask 0x1000) is the tab list header, handled separately.
#
# VIEWDLL's `Set*` peers (`SetJustify` @ 0x40727348, `SetLineSpacingRule`
# @ 0x4072739c, `SetSpecialLineIndent` @ 0x4072736c, `SetInitialCaps` @
# 0x40727354, `SetBulletState` @ 0x407273cc, `CTab::SetTabAlignment` @
# 0x407271ca, …) are pure stores — they don't validate ranges. Enum
# bounds live in BBDESIGN.EXE (per-field validator strings "Invalid X
# argument" in its .data section, e.g. "Invalid justify argument",
# "Invalid line spacing rule argument"). Parsing here is permissive;
# wire-side lowering should accept any u8/u16 the publisher wrote.
_CPARAPROPS_FIELDS = (
    (0,  1, "justify"),               # text alignment (left/center/right/justify)
    (1,  1, "initial_caps"),          # leading caps style
    (2,  2, "drop_by"),                # drop-cap height (signed)
    (3,  1, "bullet"),                 # bullet character / kind
    (4,  1, "line_spacing_rule"),      # single / 1.5x / double / exact / multiple
    (5,  2, "space_before"),           # signed twips before paragraph
    (6,  2, "space_after"),            # signed twips after paragraph
    (7,  2, "space_at"),               # signed line-height value
    (8,  1, "special_line_indent"),    # special-line indent kind (none/first/hanging)
    (9,  2, "left_indent"),            # signed twips left indent
    (10, 2, "right_indent"),           # signed twips right indent
    (11, 2, "indent_by"),              # signed twips special-line displacement
)
_CPARAPROPS_TAB_BIT = 12


def parse_cchar_props(data, off):
    """Parse a serialized `CCharProps` v2 body. Returns ({...}, new_off).

    Wire format (`?Serialize@CCharProps@@UAEXAAVCArchive@@@Z` @ VIEWDLL
    0x40707fcc): u8 version (must be 2); u8 mask_explicit; u8 mask_concrete.
    For each bit k in 0..4 where (mask_explicit & mask_concrete) bit k is
    set, read field per `_CCHARPROPS_FIELDS` (u16 or u32)."""
    version, off = read_u8(data, off)
    if version != 2:
        raise ValueError(f"unsupported CCharProps version {version}")
    mask_explicit, off = read_u8(data, off)
    mask_concrete, off = read_u8(data, off)
    fields = {}
    both = mask_explicit & mask_concrete
    for bit, size, name in _CCHARPROPS_FIELDS:
        if not (both & (1 << bit)):
            continue
        if size == 2:
            value, off = read_u16(data, off)
        else:
            value, off = read_u32(data, off)
        fields[name] = value
    return {
        "version": version,
        "mask_explicit": mask_explicit,
        "mask_concrete": mask_concrete,
        "fields": fields,
    }, off


def parse_cpara_props(data, off):
    """Parse a serialized `CParaProps` v2 body. Returns ({...}, new_off).

    Wire format (`?Serialize@CParaProps@@UAEXAAVCArchive@@@Z` @ VIEWDLL
    0x407082e2): u8 version (must be 2); u16 LE mask_explicit; u16 LE
    mask_concrete. For each bit k in 0..11 where both masks are set, read
    field per `_CPARAPROPS_FIELDS` (u8 or u16). If mask_explicit bit 12 is
    set, read tab list (u16 count, then per tab: u16 position + u8 type)."""
    version, off = read_u8(data, off)
    if version != 2:
        raise ValueError(f"unsupported CParaProps version {version}")
    mask_explicit, off = read_u16(data, off)
    mask_concrete, off = read_u16(data, off)
    fields = {}
    both = mask_explicit & mask_concrete
    for bit, size, name in _CPARAPROPS_FIELDS:
        if not (both & (1 << bit)):
            continue
        if size == 1:
            value, off = read_u8(data, off)
        else:
            value, off = read_u16(data, off)
        fields[name] = value
    tabs = []
    if mask_explicit & (1 << _CPARAPROPS_TAB_BIT):
        tab_count, off = read_u16(data, off)
        for _ in range(tab_count):
            position, off = read_u16(data, off)
            tab_type, off = read_u8(data, off)
            tabs.append({"position": position, "type": tab_type})
    return {
        "version": version,
        "mask_explicit": mask_explicit,
        "mask_concrete": mask_concrete,
        "fields": fields,
        "tabs": tabs,
    }, off


def parse_mfc_class_tag(data, off, registered_classes):
    """Parse an MFC `CRuntimeClass` tag. Returns (class_name, new_off).

    On first occurrence of a class: u16 0xFFFF + u16 schema + u16 name_len
    + name_len ANSI bytes. On subsequent occurrences: u16
    (0x8000 | class_index_1based) referencing a previously registered
    class. `registered_classes` is a list extended in place per first
    occurrence (1-based index). Length prefix is a plain u16, NOT the
    MFC `CString` variable-length escape used by `parse_mfc_ansi_string`."""
    tag, off = read_u16(data, off)
    if tag == NEW_CLASS_TAG:
        schema, off = read_u16(data, off)
        name_len, off = read_u16(data, off)
        raw, off = read_bytes(data, off, name_len)
        name = raw.decode("ascii", errors="replace")
        registered_classes.append({"name": name, "schema": schema})
        return name, off
    if tag & 0x8000:
        index = tag & 0x7FFF
        if index < 1 or index > len(registered_classes):
            raise ValueError(
                f"MFC class index {index} out of range "
                f"(have {len(registered_classes)} registered)"
            )
        return registered_classes[index - 1]["name"], off
    raise ValueError(f"unexpected MFC class tag 0x{tag:04x} at offset {off - 2}")


# Predefined style-name dictionary recovered from VIEWDLL.DLL
# `&PTR_s_Normal_40770e00` (primary, indices 0..0x2e) and
# `DAT_40771648` (secondary, indices 0x2f..0x35), walked via
# `?GetBasedOn@CStyle@@QBEPBDXZ` @ 0x407087c6. The 54 names align 1:1
# with `style_id` (== `name_index`) in TTLs that use the default
# stylesheet — they are the Blackbird-fixed style class set, not
# per-TTL strings.
#
# Per-style defaults that the engine falls back to when an authored
# CCharProps leaves a field "absent" / "no_change" are colocated in
# the same 52-byte-stride table at `0x40770e00`:
#   +0x00: name pointer
#   +0x0c: u16 default `flags_word` (bold/italic/underline/super/sub
#          packed, same encoding as on-disk CCharProps `flags_word`)
#   +0x10: u16 default `font_id` (key into `CStyleSheet.fonts[].key`)
#   +0x12: u16 default `pt_size` (point size; 0 = inherit from parent)
# Read by `?EGetWord@CCharProps@@QAEGGH@Z` @ 0x4070692e for kinds
# 5/3/4. Mirrored for `LoadDefaultStyle` initialization at
# `0x40773224` (stride 0x34) plus an intrusion-defaults table at
# `0x40773a6c` (stride 8) for indices 0x2f..0x35.
CSTYLE_NAME_DICTIONARY = (
    "Normal",                # 0
    "Heading 1", "Heading 2", "Heading 3", "Heading 4", "Heading 5", "Heading 6",
    "TOC 1", "TOC 2", "TOC 3", "TOC 4", "TOC 5", "TOC 6", "TOC 7", "TOC 8", "TOC 9",
    "Section 1", "Section 2", "Section 3", "Section 4", "Section 5",
    "Section 6", "Section 7", "Section 8", "Section 9",
    "Abstract Heading", "Term Definition", "List Bullet", "List Number",
    "Term", "Hyperlink", "Emphasized", "Bold", "Italic", "Strikethrough",
    "Preformatted", "Blockquote", "Address", "Underline", "Strong", "Code",
    "Keyboard", "Citation", "Variable Name", "Fixed Width", "Abstract Body",
    "Sample",                # 0x2e
    "Wrap: Design feature",  # 0x2f — first intrusion style
    "Wrap: Supporting graphic", "Wrap: Related graphic", "Wrap: Sidebar graphic",
    "Wrap: Advertisement", "Wrap: Custom 1", "Wrap: Custom 2",  # 0x35
)
assert len(CSTYLE_NAME_DICTIONARY) == 54

_CSTYLE_BASED_ON_NONE = 0xFF


# Per-style runtime defaults baked into VIEWDLL.DLL at table
# `0x40770e00`. Stride 0x34 (52 bytes) per `name_index`. Indexed
# 0..0x2e (47 entries — the non-intrusion styles). Used by the
# engine when an authored CCharProps/CParaProps leaves a field
# absent — wire-side lowering should mirror the same fallback to
# keep rendering consistent with the standalone Blackbird viewer.
#
# Layout per entry (field origin in parens — `EGetWord`/`EGetShort`/
# `EGetColorRef` kind for the runtime accessor that consults this
# table; `LoadDefaultStyle` for the construction-time consumer):
#   +0x00 name_ptr               u32   (GetBasedOn)
#   +0x04 based_on                u16   (LoadDefaultStyle, sentinel
#                                       0xffff = "no parent")
#   +0x06 padding                 u16
#   +0x08 char_props_only         u32   (LoadDefaultStyle; 0/1)
#   +0x0c flags_word              u16   (CCharProps EGetWord kind 5;
#                                       high byte = "absent" mask
#                                       (bit 8=bold, 9=italic,
#                                       10=underline, 11=super,
#                                       12=sub); low byte = values
#                                       (1=bold, 2=italic, 3=ul,
#                                       4=super, 5=sub))
#   +0x0e padding                 u16
#   +0x10 font_id                 u16   (CCharProps kind 3)
#   +0x12 pt_size                 u16   (CCharProps kind 4)
#   +0x14 text_color              u32   (CCharProps EGetColorRef 0)
#   +0x18 back_color              u32   (CCharProps EGetColorRef 1)
#   +0x1c justify                 u16   (CParaProps EGetWord kind 0)
#   +0x1e initial_caps            u16   (kind 11)
#   +0x20 drop_by                 i16   (kind 12)
#   +0x22 bullet                  u16   (kind 10)
#   +0x24 line_spacing_rule       u16   (kind 2)
#   +0x26 indent_by               i16   (kind 3)
#   +0x28 left_indent             i16   (kind 4)
#   +0x2a right_indent            i16   (kind 5)
#   +0x2c space_at                i16   (kind 8)
#   +0x2e special_line_indent     u16   (kind 1)
#   +0x30 space_before            i16   (kind 6)
#   +0x32 space_after             i16   (kind 7)
#
# Sentinels: `0xffff` / `-1` = "no_change" (inherit unchanged);
# `0xfffe` / `-2` = "absent" (treated like "no_change" for getters
# but distinct in serialize masks). For `font_id`/`pt_size`,
# `0` means inherit (TTLs reserve font key 0 for the empty/inherit
# slot — e.g. `resources/titles/4.ttl`).
CSTYLE_DEFAULT_PROPS: tuple[dict, ...] = (
    # 0x00 Normal
    {'based_on': 0xffff, 'char_props_only': 0, 'flags_word': 0x0000, 'font_id': 1, 'pt_size': 11, 'text_color': 0x00000000, 'back_color': 0x00ffffff,
     'justify': 0, 'initial_caps': 0, 'drop_by': 0, 'bullet': 0, 'line_spacing_rule': 0,
     'indent_by': 0, 'left_indent': 0, 'right_indent': 0, 'space_at': 0, 'special_line_indent': 0, 'space_before': 0, 'space_after': 11},
    # 0x01 Heading 1
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7e02, 'font_id': 2, 'pt_size': 22, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': 18, 'space_after': 0},
    # 0x02 Heading 2
    {'based_on': 1, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 18, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': 14, 'space_after': -1},
    # 0x03 Heading 3
    {'based_on': 2, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 14, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': 12, 'space_after': -1},
    # 0x04 Heading 4
    {'based_on': 3, 'char_props_only': 0, 'flags_word': 0x7d04, 'font_id': 0, 'pt_size': 12, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x05 Heading 5
    {'based_on': 4, 'char_props_only': 0, 'flags_word': 0x7e02, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x06 Heading 6
    {'based_on': 5, 'char_props_only': 0, 'flags_word': 0x7d04, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x07 TOC 1 — first run of TOC indents (left_indent grows by 18 per level)
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7e02, 'font_id': 2, 'pt_size': 12, 'text_color': 0x00000080, 'back_color': 0xffffffff,
     'justify': 0, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 18, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x08 TOC 2
    {'based_on': 7, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 36, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x09 TOC 3
    {'based_on': 8, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 54, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x0a TOC 4
    {'based_on': 9, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 72, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x0b TOC 5
    {'based_on': 10, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 90, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x0c TOC 6
    {'based_on': 11, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 108, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x0d TOC 7
    {'based_on': 12, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 126, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x0e TOC 8
    {'based_on': 13, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 144, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x0f TOC 9
    {'based_on': 14, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 162, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x10 Section 1
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7e02, 'font_id': 2, 'pt_size': 14, 'text_color': 0x00808000, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x11 Section 2
    {'based_on': 16, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 12, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x12 Section 3
    {'based_on': 17, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 10, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x13 Section 4
    {'based_on': 18, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x14 Section 5
    {'based_on': 19, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x15 Section 6
    {'based_on': 20, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x16 Section 7
    {'based_on': 21, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x17 Section 8
    {'based_on': 22, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x18 Section 9
    {'based_on': 23, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x19 Abstract Heading — note `justify=2` (center)
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7e02, 'font_id': 1, 'pt_size': 22, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 2, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x1a Term Definition
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 8, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': 36, 'left_indent': 36, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 2, 'space_before': -1, 'space_after': -1},
    # 0x1b List Bullet
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 1, 'line_spacing_rule': 0xffff,
     'indent_by': 18, 'left_indent': 18, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 2, 'space_before': -1, 'space_after': -1},
    # 0x1c List Number
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 1, 'line_spacing_rule': 0xffff,
     'indent_by': 18, 'left_indent': 18, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 2, 'space_before': -1, 'space_after': -1},
    # 0x1d Term
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7e02, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x1e Hyperlink — text_color = 0x00ff0000 (pure blue COLORREF)
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7b08, 'font_id': 0, 'pt_size': 0, 'text_color': 0x00ff0000, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x1f Emphasized
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7d04, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x20 Bold
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7e02, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x21 Italic
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7d04, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x22 Strikethrough — flags_word matches Hyperlink/Underline; the
    # strike effect is name-special-cased in the renderer, not encoded here.
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7b08, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x23 Preformatted — Courier (font_id=3 by convention)
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 3, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x24 Blockquote
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7d04, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 1, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': 36, 'right_indent': 36, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x25 Address
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x26 Underline
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7b08, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x27 Strong
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7e02, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x28 Code
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7f00, 'font_id': 3, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x29 Keyboard
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7c06, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x2a Citation
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7f00, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x2b Variable Name
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7c06, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x2c Fixed Width
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x7f00, 'font_id': 3, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x2d Abstract Body
    {'based_on': 0, 'char_props_only': 0, 'flags_word': 0x7d04, 'font_id': 1, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # 0x2e Sample
    {'based_on': 0, 'char_props_only': 1, 'flags_word': 0x750a, 'font_id': 0, 'pt_size': 0, 'text_color': 0xffffffff, 'back_color': 0xffffffff,
     'justify': 0xffff, 'initial_caps': 0xffff, 'drop_by': -1, 'bullet': 0, 'line_spacing_rule': 0xffff,
     'indent_by': -1, 'left_indent': -1, 'right_indent': -1, 'space_at': -1, 'special_line_indent': 0xffff, 'space_before': -1, 'space_after': -1},
    # Indices 0x2f..0x35 are intrusion styles — no per-character
    # defaults; they ship pure metadata via `intrusion_index`.
)
assert len(CSTYLE_DEFAULT_PROPS) == 47


_CSTYLE_INTRUSION_INDEX_MAX = 8


def parse_cstyle_record(data, off):
    """Parse a serialized `CStyle` v3 body. Returns ({...}, new_off).

    Wire format (`?Serialize@CStyle@@UAEXAAVCArchive@@@Z` @ VIEWDLL
    0x40707d6f, version 3 branch):
      - u8 version (must be 3)
      - u8 packed_selector — bits 2..7 = `name_index` (look up in
        `CSTYLE_NAME_DICTIONARY`), bit 1 = `char_props_only` (skip
        CParaProps), bit 0 = `is_intrusion` (style is an "intrusion"
        — text wrapping around an inline graphic, e.g. one of the
        "Wrap: …" entries 0x2f..0x35; ships no body)
      - u8 secondary — when intrusion: `intrusion_index`, range 0..8
        per BBDESIGN.EXE validator string "Intrusion argument is
        invalid. Valid values are 0 to 8." — exposed via
        `?GetIntrusion@CStyle@@QBEGXZ` @ VIEWDLL 0x40727778; reference
        TTL ships 0 for all 7 wrap styles. When based-on: parent
        style id, `0xff` = "no parent" (root); BBDESIGN enforces
        non-existence ("Based on name '%1' does not exist") and
        non-cyclic ("would cause a circular defininition") chains.
      - if `!is_intrusion and !char_props_only`: serialized `CParaProps`
      - if `!is_intrusion`: serialized `CCharProps`"""
    version, off = read_u8(data, off)
    if version != 3:
        raise ValueError(f"unsupported CStyle version {version}")
    selector, off = read_u8(data, off)
    name_index = selector >> 2
    char_props_only = bool((selector >> 1) & 1)
    is_intrusion = bool(selector & 1)
    secondary, off = read_u8(data, off)
    name = (
        CSTYLE_NAME_DICTIONARY[name_index]
        if name_index < len(CSTYLE_NAME_DICTIONARY)
        else None
    )
    record = {
        "version": version,
        "selector": selector,
        "name_index": name_index,
        "name": name,
        "char_props_only": char_props_only,
        "is_intrusion": is_intrusion,
        "intrusion_index": secondary if is_intrusion else None,
        "based_on": (
            None
            if (is_intrusion or secondary == _CSTYLE_BASED_ON_NONE)
            else secondary
        ),
        "para_props": None,
        "char_props": None,
    }
    if not is_intrusion and not char_props_only:
        record["para_props"], off = parse_cpara_props(data, off)
    if not is_intrusion:
        record["char_props"], off = parse_cchar_props(data, off)
    return record, off


def parse_cstylesheet(data):
    """Full `CStyleSheet` payload parser, including the style map.

    Returns the same keys as `parse_stylesheet_header` plus:
      - `styles`: list of parsed `CStyle` records keyed by `style_id`
      - `linked_stylesheet_present`: trailing u8
      - `linked_stylesheet_swizzle`: u32 if `linked_stylesheet_present`
        is non-zero, else None

    Raises `ValueError` on stale/unsupported versions or trailing bytes
    (callers wrap into `SynthesisError` upstream)."""
    header = parse_stylesheet_header(data)
    off = header["style_map_offset"]
    classes: list[dict] = []
    styles = []
    for _ in range(header["style_count"]):
        style_id, off = read_u16(data, off)
        class_name, off = parse_mfc_class_tag(data, off, classes)
        if class_name != "CStyle":
            raise ValueError(
                f"style_id 0x{style_id:04x}: expected CStyle, got {class_name!r}"
            )
        record, off = parse_cstyle_record(data, off)
        record["style_id"] = style_id
        styles.append(record)
    linked_present, off = read_u8(data, off)
    linked_swizzle = None
    if linked_present:
        linked_swizzle, off = read_u32(data, off)
    if off != len(data):
        raise ValueError(
            f"CStyleSheet has {len(data) - off} trailing bytes after style map"
        )
    return {
        **header,
        "styles": styles,
        "linked_stylesheet_present": linked_present,
        "linked_stylesheet_swizzle": linked_swizzle,
    }


def parse_object_payload(class_name, payload, handles):
    if class_name == "CTitle":
        return parse_ctitle_object(payload, handles)
    if class_name == "CSection":
        return parse_csection_object(payload, handles)
    if class_name == "CResourceFolder":
        return parse_cresourcefolder_object(payload, handles)
    if class_name == "CBFrame":
        return parse_cbframe_object(payload)
    if class_name == "CBForm":
        return parse_cbform_object(payload, handles)
    if class_name == "CProxyTable":
        return parse_proxy_data_map(payload, handles)
    if class_name == "CStyleSheet":
        return parse_cstylesheet(payload)
    return None


def classify_object_payload(payload):
    if payload.startswith(b"BM"):
        return "bmp"
    if len(payload) == 2 and payload == b"\x00\x00":
        return "empty_blob"
    return "raw"


def parse_property_streams(ole):
    property_tables = {}
    property_streams = {}
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        if not path.endswith("/\x03properties"):
            continue
        data = ole.openstream(entry).read()
        wrapper = maybe_decompress_ck(data)
        payload = wrapper["payload"] if wrapper else data
        try:
            props = parse_simple_property_table(payload)
        except ValueError:
            continue
        object_root = path[:-len("/\x03properties")]
        property_tables[object_root] = props
        property_streams[object_root] = {
            "path": path,
            "wrapper": wrapper,
            "payload": payload,
            "properties": props,
        }
    return property_tables, property_streams


def parse_handle_streams(ole):
    handle_tables = {}
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        if not path.endswith("/\x03handles"):
            continue
        handle_tables[path[:-len("/\x03handles")]] = parse_handles(
            ole.openstream(entry).read()
        )
    return handle_tables


def parse_object_streams(ole, table_names, handle_tables, property_tables):
    object_streams = []
    by_root = {}
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        if not path.endswith("/\x03object"):
            continue
        stream_data = ole.openstream(entry).read()
        wrapper = maybe_decompress_ck(stream_data)
        payload = wrapper["payload"] if wrapper else stream_data
        object_root = path[:-len("/\x03object")]
        table_id = int(path.split("/")[0], 16)
        class_name = table_names.get(table_id, "?")
        handles = handle_tables.get(object_root, [])
        properties = property_tables.get(object_root, [])
        property_map = {prop["key"]: prop for prop in properties}
        try:
            parsed = parse_object_payload(class_name, payload, handles)
            decode_error = None
        except ValueError as exc:
            parsed = None
            decode_error = str(exc)
        record = {
            "path": path,
            "object_root": object_root,
            "table_id": table_id,
            "class_name": class_name,
            "wrapper": wrapper,
            "payload": payload,
            "payload_kind": classify_object_payload(payload),
            "handles": handles,
            "properties": properties,
            "property_map": property_map,
            "parsed": parsed,
            "decode_error": decode_error,
        }
        object_streams.append(record)
        by_root[object_root] = record
    return object_streams, by_root


def parse_ref_streams(ole):
    ref_tables = []
    by_table_id = {}
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        if not path.startswith("\x03ref_"):
            continue
        info = parse_ref_table(ole.openstream(entry).read())
        ref_tables.append({"path": path, "info": info})
        by_table_id[int(path.split("_", 1)[1], 16)] = info
    return ref_tables, by_table_id


def inspect_blackbird_title(path):
    title_path = Path(path)
    ole = olefile.OleFileIO(str(title_path))
    type_map = parse_type_names_map(ole.openstream("\x03type_names_map").read())
    table_names = {
        entry["level_specifier"]: entry["name"]
        for entry in type_map
    }
    # Older Blackbird TTLs (e.g. `/var/share/drop/first title.ttl`)
    # ship without a `\x03TitleProps` stream — title-level metadata
    # lives only in object 1/0/properties (CTitle's property table)
    # in those builds.
    try:
        title_props_raw = ole.openstream("\x03TitleProps").read()
    except OSError:
        title_props = []
    else:
        try:
            title_props = parse_simple_property_table(title_props_raw)
        except ValueError:
            title_props = []
    title_prop_map = {prop["key"]: prop for prop in title_props}
    handle_tables = parse_handle_streams(ole)
    property_tables, property_streams = parse_property_streams(ole)
    object_streams, object_by_root = parse_object_streams(
        ole,
        table_names,
        handle_tables,
        property_tables,
    )
    ref_tables, ref_tables_by_id = parse_ref_streams(ole)
    return {
        "path": str(title_path),
        "type_map": type_map,
        "table_names": table_names,
        "title_props": title_props,
        "title_prop_map": title_prop_map,
        "handle_tables": handle_tables,
        "property_tables": property_tables,
        "property_streams": property_streams,
        "object_streams": object_streams,
        "object_by_root": object_by_root,
        "ref_tables": ref_tables,
        "ref_tables_by_id": ref_tables_by_id,
    }
