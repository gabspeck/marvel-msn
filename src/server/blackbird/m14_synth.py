"""Blackbird `.ttl` → MediaView 1.4 payload synthesizer.

Lifted from `~/projetos/blackbird-re/scripts/synthesize_m14_from_ttl.py`
with sibling-script imports rewritten to package-relative imports and
the offline `.m14`-envelope writer (`encode_synthetic_m14`,
`write_artifacts`, `serialize_source_model`, CLI main) dropped.

Public surface used by `m14_payload.build_m14_payload_for_deid`:
- `build_source_model(ttl_path)` — parse a Blackbird .ttl into a structured model
- `validate_supported_subset(model)` — assert the narrow shape this synthesizer
  knows how to lower (1 CTitle / 1 CSection / 1 CBForm / >=1 supported
  top-level topic-source entries)
- `synthesize_payload(model, mosview_open_path)` — emit the 9-section MediaView
  1.4 payload bytes (font_blob + sec07 + sec08 + sec06 + sec01 + sec02 + sec6a
  + sec13 + sec04)
- `synthesize_metadata(model, payload, mosview_open_path)` — derive the
  metadata dwords (subtype/fs_mode/va/addr/topic_count + cache CRCs)
- `SynthesisError` — raised on subset-validation or model-build failure

The structural model documented in `docs/mosview-mediaview-format.md`
"Payload Grammar" / "TitleGetInfo Selector Contract".

The structured model intentionally stops at the authored subset this repo
can currently decode with confidence: one top-level `CSection`, one
`CBForm`, and supported top-level content/proxy entries. Those entries
feed topic/address lowering; they are not authored page/window/control
descriptors.

KNOWN OFFLINE STRUCTURAL PLACEHOLDERS:
- font_blob starts with `b"FNTB"` magic; MVTTL14C reads font_count as i16
  at offset 0 and would walk off the GlobalAlloc'd copy. The live wire
  path in `m14_payload.py` replaces it with a real section-0 font table.
- Records 0x06/0x07/0x08 carry "BB06"/"BB07"/"BB08" magic at offset 0;
  acceptable for offline parser round-trips because MOSVIEW reads from
  positive named offsets, but
  flagged as a candidate suspect if downstream code ever indexes
  `record[0:4]`.
"""

from __future__ import annotations

import copy
import struct
import zlib
from pathlib import Path

from .m14_parse import parse_payload
from .ttl_inspect import inspect_blackbird_title

SUPPORTED_PROXY_KEYS = {
    "TextProxy": {0x1400: "TextTree", 0x1500: "TextRuns"},
    "ImageProxy": {0x0600: "WaveletImage"},
}


class SynthesisError(RuntimeError):
    pass


def build_stock_parser_title_path(mosview_open_path: str) -> str:
    return f"[{mosview_open_path}]0"


def extract_ascii_chunks(data: bytes, min_len: int = 3) -> list[str]:
    found: list[str] = []
    current: list[int] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
            continue
        if len(current) >= min_len:
            found.append(bytes(current).decode("ascii", errors="replace"))
        current = []
    if len(current) >= min_len:
        found.append(bytes(current).decode("ascii", errors="replace"))
    return found


def sanitize_cache_leaf(mosview_open_path: str) -> str:
    parser_title_path = build_stock_parser_title_path(mosview_open_path)
    leaf = "".join(
        "_" if ch in {":", "[", "\\", "]"} else ch
        for ch in f"MVCache_{parser_title_path}.tmp"
    )
    leaf = leaf.lstrip("_")
    if not leaf:
        raise SynthesisError("cache filename sanitization produced an empty leaf")
    return leaf


def path_prop(record: dict, key: str, default: str = "") -> str:
    prop = record["property_map"].get(key)
    if prop is None:
        return default
    return str(prop["value"])


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SynthesisError(message)


def build_handle_index(inspection: dict) -> dict[int, dict]:
    index: dict[int, dict] = {}
    object_by_root = inspection["object_by_root"]
    for table_id, table_info in inspection["ref_tables_by_id"].items():
        for entry in table_info["entries"]:
            handle = entry["obj_cos_path_handle"]
            object_root = f"{table_id}/{entry['slot']}"
            record = object_by_root.get(object_root)
            index[handle] = {
                "handle": handle,
                "object_root": object_root,
                "record": record,
                "ref_entry": entry,
            }
    return index


def resolve_handle(handle_index: dict[int, dict], ref: dict | None, expected_class: str) -> dict:
    require(ref is not None, f"missing reference for expected {expected_class}")
    handle = ref.get("handle")
    require(handle is not None, f"reference {ref} does not resolve to a handle")
    resolved = handle_index.get(handle)
    require(resolved is not None, f"no object metadata for handle 0x{handle:08x}")
    record = resolved["record"]
    require(record is not None, f"no object stream for handle 0x{handle:08x}")
    require(
        record["class_name"] == expected_class,
        f"handle 0x{handle:08x} resolved to {record['class_name']}, expected {expected_class}",
    )
    return record


def validate_supported_subset(model: dict) -> None:
    counts = model["class_counts"]
    require(counts.get("CTitle", 0) == 1, "expected exactly one CTitle")
    require(counts.get("CSection", 0) <= 1, "expected at most one CSection (inline-section titles ship 0)")
    require(counts.get("CStyleSheet", 0) == 1, "expected exactly one CStyleSheet")
    require(counts.get("CBFrame", 0) == 1, "expected exactly one CBFrame")
    require(counts.get("CBForm", 0) == 1, "expected exactly one CBForm")
    require(counts.get("CResourceFolder", 0) == 1, "expected exactly one CResourceFolder")
    require(counts.get("CVForm", 0) == 1, "expected exactly one embedded CVForm")
    require(counts.get("CMagnet", 0) == 0, "magnets are out of scope for the POC")
    require(counts.get("CShortCut", 0) == 0, "shortcuts are out of scope for the POC")

    title = model["title"]
    section = model["section"]
    form = model["form"]
    resource_folder = model["resource_folder"]
    inline_section = model["inline_section"]

    # Two structural models accepted:
    #  - "outer wrapper" (4.ttl original / showcase): CTitle.base_section
    #    holds a list of nested CSection refs. The wrapper has NO inline
    #    forms/contents/styles/frames itself — those live in the
    #    referenced CSection object.
    #  - "inline section" (Test Title.ttl): CTitle.base_section IS the
    #    content section directly — its forms/contents/styles fields are
    #    the title's content. No separate CSection object exists.
    if inline_section:
        require(not title["base_section"]["sections"], "inline-section title cannot have nested sections")
        require(not title["base_section"]["magnets"], "title magnets are unsupported")
    else:
        require(len(title["base_section"]["sections"]) == 1, "expected one top-level section")
        require(not title["base_section"]["magnets"], "title magnets are unsupported")
        require(not title["base_section"]["forms"], "title-level forms are unsupported")
        require(not title["base_section"]["contents"], "title-level contents are unsupported")
        require(not title["base_section"]["styles"], "title-level styles are unsupported")
        require(not title["base_section"]["frames"], "title-level frames are unsupported")
    require(title["shortcut_count"] == 0, "shortcuts are unsupported")

    require(not section["sections"], "nested sections are unsupported")
    require(not section["magnets"], "section magnets are unsupported")
    require(len(section["forms"]) == 1, "expected exactly one section form")
    require(not section["frames"], "section-specific frames are unsupported")

    require(form["embedded_vform_present"] == 1, "expected one embedded CVForm")
    require(resource_folder["base_folder"]["trailing_byte"] == 0, "unsupported resource folder trailer")

    supported_types = {"TextTree", "TextRuns", "WaveletImage"}
    content_types = {
        record["content_type"]
        for record in model["content_records"]
    }
    unsupported = sorted(content_types - supported_types)
    require(not unsupported, f"unsupported content types: {', '.join(unsupported)}")


def build_source_model(ttl_path: Path) -> dict:
    inspection = inspect_blackbird_title(ttl_path)
    handle_index = build_handle_index(inspection)
    object_streams = inspection["object_streams"]

    class_counts: dict[str, int] = {}
    for record in object_streams:
        class_counts[record["class_name"]] = class_counts.get(record["class_name"], 0) + 1

    def first_record(class_name: str) -> dict:
        matches = [
            record
            for record in object_streams
            if record["class_name"] == class_name
        ]
        require(matches, f"missing required object class {class_name}")
        require(
            len(matches) == 1,
            f"expected exactly one {class_name}, found {len(matches)}",
        )
        return matches[0]

    title_record = first_record("CTitle")
    form_record = first_record("CBForm")
    frame_record = first_record("CBFrame")
    stylesheet_record = first_record("CStyleSheet")
    resource_folder_record = first_record("CResourceFolder")
    vform_record = first_record("CVForm")

    title_info = title_record["parsed"]
    form_info = form_record["parsed"]
    frame_info = frame_record["parsed"]
    stylesheet_info = stylesheet_record["parsed"]
    resource_folder_info = resource_folder_record["parsed"]
    require(title_info is not None, "unable to decode CTitle payload")
    require(form_info is not None, "unable to decode CBForm payload")
    require(frame_info is not None, "unable to decode CBFrame payload")
    require(stylesheet_info is not None, "unable to decode CStyleSheet payload")
    require(resource_folder_info is not None, "unable to decode CResourceFolder payload")

    # Two structural models for the title's content section:
    #   - "outer wrapper" (4.ttl original): CSection lives as a separate
    #     object referenced by `title.base_section.sections[0]`.
    #   - "inline section" (Test Title.ttl): no CSection object; the
    #     `title.base_section` payload IS the content section.
    section_count = class_counts.get("CSection", 0)
    inline_section = section_count == 0
    if inline_section:
        section_record = None
        section_info = title_info["base_section"]
        section_name = ""
    else:
        section_record = first_record("CSection")
        section_info = section_record["parsed"]
        require(section_info is not None, "unable to decode CSection payload")
        section_name = path_prop(section_record, "name")
        section_ref = title_info["base_section"]["sections"][0]
        resolved_section = resolve_handle(handle_index, section_ref, "CSection")
        require(
            resolved_section["object_root"] == section_record["object_root"],
            "title does not reference the single top-level section object",
        )

    require(section_info["forms"], "section has no form reference")
    resolved_form = resolve_handle(handle_index, section_info["forms"][0], "CBForm")
    require(
        resolved_form["object_root"] == form_record["object_root"],
        "section does not reference the single form object",
    )
    resolve_handle(handle_index, form_info["frame"], "CBFrame")
    resolve_handle(handle_index, form_info["embedded_vform"], "CVForm")
    resolve_handle(handle_index, title_info["resource_folder"], "CResourceFolder")
    resolve_handle(
        handle_index,
        resource_folder_info["default_frame"],
        "CBFrame",
    )
    resolve_handle(
        handle_index,
        resource_folder_info["default_stylesheet"],
        "CStyleSheet",
    )

    # These are the supported top-level `CSection.contents` entries that
    # feed today's synthetic topic/address map. They are authored content
    # references, not authored page/window/control layout records.
    topic_source_entries = []
    content_records = []
    for entry_index, content_ref in enumerate(section_info["contents"]):
        proxy_record = resolve_handle(handle_index, content_ref, "CProxyTable")
        proxy_type = path_prop(proxy_record, "type")
        proxy_name = path_prop(proxy_record, "name")
        proxy_origin = path_prop(proxy_record, "origin")
        proxy_info = proxy_record["parsed"]
        require(proxy_info is not None, f"unable to decode proxy payload for {proxy_name!r}")
        expected_proxy_keys = SUPPORTED_PROXY_KEYS.get(proxy_type)
        require(
            expected_proxy_keys is not None,
            f"unsupported proxy type {proxy_type!r}",
        )
        actual_proxy_keys = {
            entry["key"]
            for entry in proxy_info["entries"]
        }
        require(
            actual_proxy_keys == set(expected_proxy_keys),
            (
                f"proxy {proxy_name!r} has unsupported key set "
                f"{sorted(actual_proxy_keys)}"
            ),
        )

        resolved_targets = {}
        for proxy_entry in proxy_info["entries"]:
            expected_kind = expected_proxy_keys[proxy_entry["key"]]
            target_record = resolve_handle(handle_index, proxy_entry["target"], "CContent")
            content_type = path_prop(target_record, "type")
            require(
                content_type == expected_kind,
                f"proxy {proxy_name!r} expected {expected_kind}, found {content_type}",
            )
            payload = target_record["payload"]
            resolved_targets[proxy_entry["key"]] = {
                "object_root": target_record["object_root"],
                "content_type": content_type,
                "name": path_prop(target_record, "name"),
                "origin": path_prop(target_record, "origin"),
                "payload_size": len(payload),
                "payload_hex_head": payload[:32].hex(),
                "ascii_chunks": extract_ascii_chunks(payload),
                "payload": payload,
                "record": target_record,
            }
            content_records.append(
                {
                    "object_root": target_record["object_root"],
                    "content_type": content_type,
                }
            )

        if proxy_type == "TextProxy":
            text_tree = resolved_targets[0x1400]
            text_runs = resolved_targets[0x1500]
            topic_source_entries.append(
                {
                    "entry_index": entry_index,
                    "kind": "text",
                    "proxy_type": proxy_type,
                    "proxy_name": proxy_name,
                    "proxy_origin": proxy_origin,
                    "proxy_size": int(path_prop(proxy_record, "size", "0") or 0),
                    "text_tree": text_tree,
                    "text_runs": text_runs,
                }
            )
        else:
            image = resolved_targets[0x0600]
            image_record = image["record"]
            topic_source_entries.append(
                {
                    "entry_index": entry_index,
                    "kind": "image",
                    "proxy_type": proxy_type,
                    "proxy_name": proxy_name,
                    "proxy_origin": proxy_origin,
                    "proxy_size": int(path_prop(proxy_record, "size", "0") or 0),
                    "width": int(path_prop(proxy_record, "width", "0") or 0),
                    "height": int(path_prop(proxy_record, "height", "0") or 0),
                    "image": image,
                    "image_payload_kind": image_record["payload_kind"],
                }
            )

    model = {
        "ttl_path": str(ttl_path),
        "title": {
            "name": path_prop(title_record, "name"),
            "trailing_name": title_info["trailing_name"],
            "shortcut_count": title_info["shortcut_count"],
            "base_section": title_info["base_section"],
            "props": inspection["title_props"],
            "localname": inspection["title_prop_map"].get("localname", {}).get("value", ""),
        },
        "section": {
            "name": section_name,
            **section_info,
        },
        "inline_section": inline_section,
        "form": {
            "name": path_prop(form_record, "name"),
            **form_info,
        },
        "frame": {
            "name": path_prop(frame_record, "name"),
            **frame_info,
        },
        "stylesheet": {
            "name": path_prop(stylesheet_record, "name"),
            **stylesheet_info,
        },
        "resource_folder": {
            "name": path_prop(resource_folder_record, "name"),
            **resource_folder_info,
        },
        "vform": {
            "object_root": vform_record["object_root"],
            "payload_size": len(vform_record["payload"]),
            "sites": (vform_record.get("parsed") or {}).get("sites", []),
        },
        "captions": [
            {
                "name": s["name"],
                "rect_twips": s["data"]["rect_twips"],
                "font_name": s["data"]["font_name"],
                "font_weight": s["data"]["font_weight"],
                "font_size_pt": s["data"]["font_size_pt"],
                "text": s["data"]["caption_text"],
            }
            for s in (vform_record.get("parsed") or {}).get("sites", [])
            if s.get("kind") == "Caption" and isinstance(s.get("data"), dict)
            and "caption_text" in s["data"]
        ],
        "topic_source_entries": topic_source_entries,
        "content_records": content_records,
        "class_counts": class_counts,
    }
    validate_supported_subset(model)
    return model


def synthetic_crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def pack_u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise SynthesisError(f"value 0x{value:x} does not fit in u16")
    return struct.pack("<H", value)


def pack_u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise SynthesisError(f"value 0x{value:x} does not fit in u32")
    return struct.pack("<I", value)


def encode_c_string(text: str) -> bytes:
    return text.encode("latin-1", errors="replace") + b"\x00"


def synthesize_font_blob(model: dict) -> bytes:
    stylesheet = model["stylesheet"]
    blob = bytearray()
    blob += b"FNTB"
    blob += pack_u16(1)
    blob += pack_u16(stylesheet["font_count"])
    blob += pack_u16(stylesheet["style_count"])
    blob += pack_u16(stylesheet["style_first_key"] or 0)
    for entry in stylesheet["fonts"]:
        name_bytes = entry["name"].encode("latin-1", errors="replace")
        require(len(name_bytes) <= 0xFF, "font name is too long for the synthetic blob")
        blob += pack_u16(entry["key"])
        blob.append(len(name_bytes))
        blob += name_bytes
    return bytes(blob)


def build_section_strings(model: dict) -> list[str]:
    strings = [
        model["title"]["name"],
        model["section"]["name"],
        model["form"]["form_name"],
        model["frame"]["caption"],
        model["stylesheet"]["name"],
        model["resource_folder"]["name"],
    ]
    for entry in model["topic_source_entries"]:
        strings.append(entry["proxy_name"])
    return strings


def build_selector_13_entries() -> list[bytes]:
    return [
        b"MMVDIB12.DLL\x00mmvdib12.dll\x00mmvdib12\x00",
        b"MVBMP2.DLL\x00mvbmp2.dll\x00mvbmp2\x00",
    ]


def printable_preview(chunks: list[str], fallback: str) -> bytes:
    if chunks:
        return " | ".join(chunks).encode("latin-1", errors="replace")
    return fallback.encode("latin-1", errors="replace")


def record_label(text: str, size: int) -> bytes:
    encoded = text.encode("latin-1", errors="replace")[:size]
    return encoded.ljust(size, b"\x00")


def build_topic_source_metadata(model: dict) -> list[dict]:
    """Attach synthetic topic/address keys to supported top-level entries.

    This is a lowering helper for MEDVIEW topic resolution only. It does
    not describe authored page/window/control layout.
    """
    first_address = 0x1000
    entries = []
    for entry in model["topic_source_entries"]:
        entry_copy = copy.deepcopy(entry)
        address = first_address + entry["entry_index"] * 0x100
        topic_number = entry["entry_index"] + 1
        context_name = entry["proxy_name"] or f"entry_{entry['entry_index']}"
        context_hash = synthetic_crc(context_name.lower().encode("latin-1", errors="replace")) or 1
        entry_copy["address"] = address
        entry_copy["topic_number"] = topic_number
        entry_copy["context_hash"] = context_hash
        entries.append(entry_copy)
    return entries


def synthesize_sec07_records(entries: list[dict], string_index: dict[str, int]) -> list[bytes]:
    records = []
    for entry in entries:
        if entry["kind"] == "text":
            primary = entry["text_tree"]["payload"]
            secondary = entry["text_runs"]["payload"]
            aux_value = len(entry["text_tree"]["ascii_chunks"])
            kind = 1
        else:
            primary = entry["image"]["payload"]
            secondary = b""
            aux_value = (entry["width"] & 0xFFFF) | ((entry["height"] & 0xFFFF) << 16)
            kind = 2
        record = bytearray()
        record += b"BB07"
        record += bytes(
            [
                kind,
                string_index[entry["proxy_name"]] & 0xFF,
                entry["entry_index"] & 0xFF,
                0x01 if entry["kind"] == "text" else 0x02,
            ]
        )
        packed_lengths = (len(primary) & 0xFFFF) | ((len(secondary) & 0xFFFF) << 16)
        record += pack_u32(entry["address"])
        record += pack_u32(entry["topic_number"])
        record += pack_u32(entry["context_hash"])
        record += pack_u32(packed_lengths)
        record += pack_u32(synthetic_crc(primary + secondary))
        record += pack_u32(aux_value)
        record += record_label(entry["proxy_name"], 11)
        require(len(record) == 0x2B, "synthetic 0x07 record size mismatch")
        records.append(bytes(record))
    return records


def synthesize_sec08_records(entries: list[dict], string_index: dict[str, int]) -> list[bytes]:
    records = []
    for entry in entries:
        record = bytearray()
        record += b"BB08"
        record += bytes(
            [
                1 if entry["kind"] == "text" else 2,
                string_index[entry["proxy_name"]] & 0xFF,
                entry["entry_index"] & 0xFF,
                0,
            ]
        )
        record += pack_u32(entry["address"])
        record += pack_u32(entry["entry_index"])
        record += pack_u32(entry.get("width", 0))
        record += pack_u32(entry.get("height", 0))
        if entry["kind"] == "text":
            preview = printable_preview(
                entry["text_tree"]["ascii_chunks"] + entry["text_runs"]["ascii_chunks"],
                entry["proxy_name"],
            )
        else:
            preview = entry["image"]["payload"][:64]
        record += pack_u32(synthetic_crc(preview))
        record += b"TXT" if entry["kind"] == "text" else b"IMG"
        require(len(record) == 0x1F, "synthetic 0x08 record size mismatch")
        records.append(bytes(record))
    return records


def synthesize_sec06_records(entries: list[dict], string_index: dict[str, int]) -> list[bytes]:
    records = []
    for entry in entries:
        if entry["kind"] == "text":
            primary = entry["text_tree"]["payload"]
            secondary = entry["text_runs"]["payload"]
            preview = printable_preview(
                entry["text_tree"]["ascii_chunks"] + entry["text_runs"]["ascii_chunks"],
                entry["proxy_name"],
            )
            width = 0
            height = 0
        else:
            primary = entry["image"]["payload"]
            secondary = b""
            preview = primary[:116]
            width = entry["width"]
            height = entry["height"]
        preview = preview[:116].ljust(116, b"\x00")
        packed_lengths = (len(primary) & 0xFFFF) | ((len(secondary) & 0xFFFF) << 16)
        record = bytearray()
        record += b"BB06"
        record += bytes(
            [
                1 if entry["kind"] == "text" else 2,
                string_index[entry["proxy_name"]] & 0xFF,
                entry["entry_index"] & 0xFF,
                0,
            ]
        )
        record += pack_u32(entry["address"])
        record += pack_u32(entry["topic_number"])
        record += pack_u32(entry["context_hash"])
        record += pack_u32(packed_lengths)
        record += pack_u32(synthetic_crc(primary + secondary))
        record += pack_u32(width)
        record += pack_u32(height)
        record += preview
        require(len(record) == 0x98, "synthetic 0x06 record size mismatch")
        records.append(bytes(record))
    return records


def encode_blob_section(payload: bytes) -> bytes:
    require(len(payload) <= 0xFFFF, "blob section is too large")
    return pack_u16(len(payload)) + payload


def encode_fixed_section(records: list[bytes], record_size: int) -> bytes:
    for record in records:
        require(len(record) == record_size, f"record does not match size 0x{record_size:x}")
    payload = b"".join(records)
    return encode_blob_section(payload)


def encode_counted_string_section(entries: list[bytes]) -> bytes:
    if not entries:
        return pack_u16(0)
    body = bytearray()
    body += pack_u16(len(entries))
    for entry in entries:
        require(len(entry) <= 0xFFFF, "0x13 entry is too large")
        body += pack_u16(len(entry))
        body += entry
    require(len(body) - 2 <= 0xFFFF, "0x13 body is too large")
    return pack_u16(len(body) - 2) + body


def encode_c_string_table(strings: list[str]) -> bytes:
    body = bytearray()
    body += pack_u16(len(strings))
    for text in strings:
        body += encode_c_string(text)
    return bytes(body)


def synthesize_payload(model: dict, mosview_open_path: str) -> tuple[bytes, dict]:
    entries = build_topic_source_metadata(model)
    strings = build_section_strings(model)
    string_index = {text: index for index, text in enumerate(strings)}

    font_blob = synthesize_font_blob(model)
    sec07_records = synthesize_sec07_records(entries, string_index)
    sec08_records = synthesize_sec08_records(entries, string_index)
    sec06_records = synthesize_sec06_records(entries, string_index)
    # sec01 → MOSVIEW title descriptor +0x58 → "About Title" message 0x414
    # ("Title name"). sec02 → +0x5c → message 0x406 ("Copyright information").
    # See `docs/mosview-mediaview-format.md` §"Selector 0x01 / 0x02 String
    # Handling". Authored TTLs don't carry a copyright property today, so
    # ship sec02 empty rather than misrouting the section name into it.
    sec01 = encode_c_string(model["title"]["name"])
    sec02 = b""
    sec6a = encode_c_string(mosview_open_path)
    sec13_entries = build_selector_13_entries()
    sec04_strings = strings

    payload = b"".join(
        [
            encode_blob_section(font_blob),
            encode_fixed_section(sec07_records, 0x2B),
            encode_fixed_section(sec08_records, 0x1F),
            encode_fixed_section(sec06_records, 0x98),
            encode_blob_section(sec01),
            encode_blob_section(sec02),
            encode_blob_section(sec6a),
            encode_counted_string_section(sec13_entries),
            encode_c_string_table(sec04_strings),
        ]
    )
    parsed = parse_payload(payload)
    require(parsed.sec07.record_count == len(sec07_records), "sec07 count mismatch after parse")
    require(parsed.sec08.record_count == len(sec08_records), "sec08 count mismatch after parse")
    require(parsed.sec06.record_count == len(sec06_records), "sec06 count mismatch after parse")
    require(parsed.sec04.count == len(sec04_strings), "sec04 count mismatch after parse")
    require(parsed.sec13.count == len(sec13_entries), "sec13 count mismatch after parse")
    require(not parsed.trailing, "synthetic payload produced trailing bytes")
    section_report = {
        "font_blob": {
            "length": len(font_blob),
            "hex": font_blob.hex(),
        },
        "0x07": {
            "record_size": 0x2B,
            "record_count": len(sec07_records),
            "records_hex": [record.hex() for record in sec07_records],
        },
        "0x08": {
            "record_size": 0x1F,
            "record_count": len(sec08_records),
            "records_hex": [record.hex() for record in sec08_records],
        },
        "0x06": {
            "record_size": 0x98,
            "record_count": len(sec06_records),
            "records_hex": [record.hex() for record in sec06_records],
        },
        "0x01": {
            "length": len(sec01),
            "hex": sec01.hex(),
        },
        "0x02": {
            "length": len(sec02),
            "hex": sec02.hex(),
        },
        "0x6a": {
            "length": len(sec6a),
            "hex": sec6a.hex(),
        },
        "0x13": {
            "entry_count": len(sec13_entries),
            "entries_hex": [entry.hex() for entry in sec13_entries],
        },
        "0x04": {
            "count": len(sec04_strings),
            "strings": sec04_strings,
        },
    }
    return payload, section_report


def synthesize_metadata(model: dict, payload: bytes, mosview_open_path: str) -> tuple[dict, list[dict]]:
    topic_source_entries = build_topic_source_metadata(model)
    parser_title_path = build_stock_parser_title_path(mosview_open_path)
    va_get_contents = topic_source_entries[0]["address"] if topic_source_entries else 0
    addr_get_contents = va_get_contents
    title_info_0b = len(topic_source_entries)
    header0 = synthetic_crc(payload)
    header1 = synthetic_crc(parser_title_path.encode("latin-1", errors="replace"))
    metadata = {
        "subtype_byte": 1,
        "file_system_mode_byte": 0,
        "va_get_contents": va_get_contents,
        "addr_get_contents": addr_get_contents,
        "title_info_0b": title_info_0b,
        "cache_header0": header0,
        "cache_header1": header1,
        "parser_title_path": parser_title_path,
        "address_map": [
            {
                "entry_index": entry["entry_index"],
                "proxy_name": entry["proxy_name"],
                "address": entry["address"],
                "topic_number": entry["topic_number"],
                "context_hash": entry["context_hash"],
            }
            for entry in topic_source_entries
        ],
    }
    unresolved = [
        {
            "field": "subtype_byte",
            "value": metadata["subtype_byte"],
            "status": "synthesized_constant",
        },
        {
            "field": "file_system_mode_byte",
            "value": metadata["file_system_mode_byte"],
            "status": "synthesized_constant",
        },
        {
            "field": "va_get_contents",
            "value": metadata["va_get_contents"],
            "status": "synthetic_address_base",
        },
        {
            "field": "addr_get_contents",
            "value": metadata["addr_get_contents"],
            "status": "synthetic_address_base",
        },
        {
            "field": "title_info_0b",
            "value": metadata["title_info_0b"],
            "status": "synthesized_constant",
        },
        {
            "field": "cache_header0/cache_header1",
            "value": [metadata["cache_header0"], metadata["cache_header1"]],
            "status": "synthetic_validation_tuple",
        },
    ]
    return metadata, unresolved
