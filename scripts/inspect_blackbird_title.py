#!/usr/bin/env python3

import argparse
from pathlib import Path
import sys
import uuid
from datetime import datetime, timedelta, timezone
import zlib

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


def resolve_swizzle(index, handles):
    handle = None
    if 0 <= index < len(handles):
        handle = handles[index]
    return {
        "index": index,
        "handle": handle,
    }


def format_u64(value):
    return f"0x{value:016x}"


def format_swizzle_ref(ref):
    if ref["handle"] is None:
        return f"#{ref['index']}"
    return f"#{ref['index']}->0x{ref['handle']:08x}"


def format_typed_swizzle_ref(ref):
    base = format_swizzle_ref(ref)
    return f"{ref['type_name']}({base})"


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
        return parse_stylesheet_header(payload)
    return None


def describe_object_payload(class_name, payload, handles):
    if class_name == "CTitle":
        info = parse_ctitle_object(payload, handles)
        base = info["base_section"]
        prop = base["section_prop"]
        return [
            f"title_version: {info['version']}",
            f"base_sections: [{', '.join(format_swizzle_ref(r) for r in base['sections'])}]",
            f"base_magnets: [{', '.join(format_typed_swizzle_ref(r) for r in base['magnets'])}]",
            f"base_forms: [{', '.join(format_typed_swizzle_ref(r) for r in base['forms'])}]",
            f"base_contents: [{', '.join(format_typed_swizzle_ref(r) for r in base['contents'])}]",
            f"base_styles: [{', '.join(format_typed_swizzle_ref(r) for r in base['styles'])}]",
            f"base_frames: [{', '.join(format_typed_swizzle_ref(r) for r in base['frames'])}]",
            "base_section_prop: "
            f"section_ref_a={format_swizzle_ref(prop['section_ref_a']) if prop['section_ref_a'] else 'None'} "
            f"section_ref_b={format_swizzle_ref(prop['section_ref_b']) if prop['section_ref_b'] else 'None'} "
            f"section_ref_c={format_swizzle_ref(prop['section_ref_c']) if prop['section_ref_c'] else 'None'} "
            f"u32_0={prop['u32_0']} u32_1={prop['u32_1']} "
            f"u8_0={prop['u8_0']} "
            f"form_ref={format_swizzle_ref(prop['form_ref']) if prop['form_ref'] else 'None'}",
            f"resource_folder: {format_swizzle_ref(info['resource_folder'])}",
            f"shortcut_count: {info['shortcut_count']}",
            f"trailing_name: {info['trailing_name']!r}",
        ]
    if class_name == "CSection":
        info = parse_csection_object(payload, handles)
        prop = info["section_prop"]
        return [
            f"section_version: {info['version']}",
            f"sections: [{', '.join(format_swizzle_ref(r) for r in info['sections'])}]",
            f"magnets: [{', '.join(format_typed_swizzle_ref(r) for r in info['magnets'])}]",
            f"forms: [{', '.join(format_typed_swizzle_ref(r) for r in info['forms'])}]",
            f"contents: [{', '.join(format_typed_swizzle_ref(r) for r in info['contents'])}]",
            f"styles: [{', '.join(format_typed_swizzle_ref(r) for r in info['styles'])}]",
            f"frames: [{', '.join(format_typed_swizzle_ref(r) for r in info['frames'])}]",
            "section_prop: "
            f"section_ref_a={format_swizzle_ref(prop['section_ref_a']) if prop['section_ref_a'] else 'None'} "
            f"section_ref_b={format_swizzle_ref(prop['section_ref_b']) if prop['section_ref_b'] else 'None'} "
            f"section_ref_c={format_swizzle_ref(prop['section_ref_c']) if prop['section_ref_c'] else 'None'} "
            f"u32_0={prop['u32_0']} u32_1={prop['u32_1']} "
            f"u8_0={prop['u8_0']} "
            f"form_ref={format_swizzle_ref(prop['form_ref']) if prop['form_ref'] else 'None'}",
        ]
    if class_name == "CResourceFolder":
        info = parse_cresourcefolder_object(payload, handles)
        base = info["base_folder"]
        return [
            f"resource_folder_version: {info['version']}",
            f"folder_version: {base['version']}",
            "folder_objects: ["
            + ", ".join(format_typed_swizzle_ref(r) for r in base["objects"])
            + "]",
            f"folder_trailing_byte: {base['trailing_byte']}",
            f"default_stylesheet: {format_swizzle_ref(info['default_stylesheet'])}",
            f"default_frame: {format_swizzle_ref(info['default_frame'])}",
        ]
    if class_name == "CBFrame":
        info = parse_cbframe_object(payload)
        return [
            f"frame_version: {info['version']}",
            f"name_0: {info['name_0']!r}",
            f"name_1: {info['name_1']!r}",
            f"u64_0: {format_u64(info['u64_0'])}",
            f"u64_1: {format_u64(info['u64_1'])}",
            f"u32_0: {info['u32_0']}",
            f"u32_1: {info['u32_1']}",
            f"u8_0: {info['u8_0']}",
            f"u32_2: {info['u32_2']}",
            f"u8_1: {info['u8_1']}",
            f"u8_2: {info['u8_2']}",
            f"u8_3: {info['u8_3']}",
            f"tail_present: {info['tail_present']}",
            f"trailing_bytes: {info['trailing_bytes']}",
        ]
    if class_name == "CBForm":
        info = parse_cbform_object(payload, handles)
        return [
            f"form_version: {info['version']}",
            f"form_name: {info['form_name']!r}",
            f"form_mode: {info['form_mode']}",
            f"embedded_vform_present: {info['embedded_vform_present']}",
            "embedded_vform: "
            + (
                format_swizzle_ref(info["embedded_vform"])
                if info["embedded_vform"] is not None
                else "None"
            ),
            f"frame: {format_swizzle_ref(info['frame'])}",
            f"u32_0: {info['u32_0']}",
            f"u32_1: {info['u32_1']}",
            f"u32_2: {info['u32_2']}",
            f"u32_3: {info['u32_3']}",
            f"u64_0: {format_u64(info['u64_0'])}",
            f"u8_0: {info['u8_0']}",
            f"dpi_x: {info['dpi_x']}",
            f"dpi_y: {info['dpi_y']}",
        ]
    if class_name == "CProxyTable":
        info = parse_proxy_data_map(payload, handles)
        return [
            f"proxy_entry_count: {info['count']}",
            "proxy_entries: ["
            + ", ".join(
                f"0x{entry['key']:08x}->{format_swizzle_ref(entry['target'])}"
                for entry in info["entries"]
            )
            + "]",
        ]
    if class_name == "CStyleSheet":
        info = parse_stylesheet_header(payload)
        return [
            f"stylesheet_version: {info['version']}",
            f"font_entry_count: {info['font_count']}",
            "font_entries: ["
            + ", ".join(f"{entry['key']}:{entry['name']!r}" for entry in info["fonts"])
            + "]",
            f"style_entry_count: {info['style_count']}",
            f"style_map_offset: 0x{info['style_map_offset']:x}",
            f"style_first_key: {info['style_first_key']}",
        ]
    return []


def dump_stream_tree(ole):
    print("== stream tree ==")
    for entry in ole.listdir(streams=True, storages=True):
        print("/".join(entry))
    print()


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
        table_id = int(path.split("/")[0], 10)
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
        by_table_id[int(path.split("_", 1)[1], 10)] = info
    return ref_tables, by_table_id


def inspect_blackbird_title(path):
    title_path = Path(path)
    ole = olefile.OleFileIO(str(title_path))
    type_map = parse_type_names_map(ole.openstream("\x03type_names_map").read())
    table_names = {
        entry["level_specifier"]: entry["name"]
        for entry in type_map
    }
    title_props = parse_simple_property_table(ole.openstream("\x03TitleProps").read())
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--dump-tree", action="store_true")
    args = parser.parse_args()

    ole = olefile.OleFileIO(args.path)
    inspection = inspect_blackbird_title(args.path)

    if args.dump_tree:
        dump_stream_tree(ole)

    print(f"file: {args.path}")
    print()

    type_map = inspection["type_map"]
    table_names = inspection["table_names"]
    print("== type_names_map ==")
    for entry in type_map:
        print(
            f"slot {entry['slot']:>2}  "
            f"name {entry['name']:<15}  "
            f"table {entry['level_specifier']}"
        )
    print()

    print("== title props ==")
    for prop in inspection["title_props"]:
        print(
            f"{prop['key']}: "
            f"vt=0x{prop['vartype']:04x} "
            f"value={prop['value']!r}"
        )
    print()

    handle_tables = inspection["handle_tables"]
    print("== handle streams ==")
    for object_root in sorted(handle_tables):
        handles = handle_tables[object_root]
        pretty = ", ".join(f"0x{handle:08x}" for handle in handles)
        print(f"{object_root}/\x03handles: [{pretty}]")
    print()

    print("== simple property streams ==")
    for object_root in sorted(inspection["property_streams"]):
        stream_info = inspection["property_streams"][object_root]
        print(stream_info["path"])
        wrapper = stream_info["wrapper"]
        if wrapper:
            print(
                "  compression: "
                f"CK v{wrapper['wrapper_version']} "
                f"compressed={wrapper['compressed_size']} "
                f"uncompressed={wrapper['uncompressed_size']}"
            )
        for prop in stream_info["properties"]:
            print(
                f"  {prop['key']}: "
                f"vt=0x{prop['vartype']:04x} "
                f"value={prop['value']!r}"
            )
    print()

    print("== object streams ==")
    for object_info in inspection["object_streams"]:
        path = object_info["path"]
        class_name = object_info["class_name"]
        payload = object_info["payload"]
        payload_kind = object_info["payload_kind"]
        handles = object_info["handles"]
        print(f"{path}: class={class_name}")
        wrapper = object_info["wrapper"]
        if wrapper:
            print(
                "  compression: "
                f"CK v{wrapper['wrapper_version']} "
                f"compressed={wrapper['compressed_size']} "
                f"uncompressed={wrapper['uncompressed_size']}"
            )
        props = object_info["properties"]
        if props:
            type_prop = next((p for p in props if p["key"] == "type"), None)
            if type_prop:
                print(f"  type_property: {type_prop['value']}")
        print(f"  payload_kind: {payload_kind}")
        print(f"  payload_size: {len(payload)}")
        print(f"  payload_head: {payload[:32].hex()}")
        if object_info["decode_error"] is not None:
            detail_lines = [f"decode_error: {object_info['decode_error']}"]
        else:
            detail_lines = describe_object_payload(class_name, payload, handles)
        for line in detail_lines:
            print(f"  {line}")
    print()

    print("== ref tables ==")
    for ref_table in inspection["ref_tables"]:
        path = ref_table["path"]
        info = ref_table["info"]
        words = ", ".join(f"0x{word:08x}" for word in info["words"])
        slots = ", ".join(str(slot) for slot in info["occupied_slots"])
        print(path)
        print(
            "  bitmap: "
            f"start_word={info['start_word']} "
            f"word_count={info['word_count']} "
            f"capacity_words={info['capacity_words']}"
        )
        print(f"  words: [{words}]")
        print(f"  slot_count: {info['slot_count']}")
        print(f"  occupied_slots: [{slots}]")
        print(
            "  entry_payload: "
            f"offset=0x{info['payload_offset']:x} "
            f"size={info['payload_size']}"
        )
        for ref_entry in info["entries"]:
            header = ref_entry["header"]
            if header["kind"] == "new_class":
                wrapper = (
                    f"new_class schema={header['schema']} "
                    f"name={header['class_name']}"
                )
            else:
                wrapper = (
                    f"class_ref raw=0x{header['raw_marker']:04x} "
                    f"id={header['class_ref']}"
                )
            print(
                f"  slot {ref_entry['slot']}: "
                f"{wrapper} "
                f"flags=0x{ref_entry['flags']:08x} "
                f"obj_kind={ref_entry['obj_kind']} "
                f"ref_count={ref_entry['ref_count']} "
                f"handle=0x{ref_entry['obj_cos_path_handle']:08x}"
            )
            print(
                f"    moniker_flags: 0x{ref_entry['moniker_flags']:07x}"
            )
            if "obj_mod_time" in ref_entry:
                print(f"    obj_mod_time: {ref_entry['obj_mod_time']}")
            if "props_mod_time" in ref_entry:
                print(f"    props_mod_time: {ref_entry['props_mod_time']}")
            if "obj_guid" in ref_entry:
                print(f"    obj_guid: {ref_entry['obj_guid']}")
        if info["trailing_bytes"] != 0:
            print(f"  trailing_bytes: {info['trailing_bytes']}")
    print()


if __name__ == "__main__":
    sys.exit(main())
