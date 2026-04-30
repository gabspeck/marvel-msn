#!/usr/bin/env python3

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path


SELECTOR_LABELS = {
    0x04: "nul_string_table",
    0x06: "record_table_0x98",
    0x07: "record_table_0x2b",
    0x08: "record_table_0x1f",
    0x01: "blob_1",
    0x02: "blob_2",
    0x13: "counted_string_table",
    0x6A: "blob_6a",
    0x6F: "font_table_handle",
    0x69: "file_system_mode",
}


def read_u16(data: bytes, off: int) -> tuple[int, int]:
    if off + 2 > len(data):
        raise ValueError(f"u16 at 0x{off:x} overruns buffer")
    return int.from_bytes(data[off:off + 2], "little"), off + 2


def read_u32(data: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(data):
        raise ValueError(f"u32 at 0x{off:x} overruns buffer")
    return int.from_bytes(data[off:off + 4], "little"), off + 4


def read_bytes(data: bytes, off: int, size: int) -> tuple[bytes, int]:
    end = off + size
    if end > len(data):
        raise ValueError(
            f"field at 0x{off:x} size 0x{size:x} overruns buffer"
        )
    return data[off:end], end


def find_c_string_end(data: bytes, off: int) -> int:
    end = data.find(b"\x00", off)
    if end < 0:
        raise ValueError(f"missing NUL terminator for string at 0x{off:x}")
    return end + 1


def extract_ascii_strings(data: bytes, min_len: int) -> list[str]:
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


def format_hex(value: int) -> str:
    return f"0x{value:08x}"


def decode_bytes_text(data: bytes) -> str:
    text = data.rstrip(b"\x00").decode("latin-1", errors="replace")
    return repr(text)


@dataclass
class MediaViewCacheFile:
    header0: int
    header1: int
    payload: bytes
    payload_only: bool


@dataclass
class FontBlob:
    offset: int
    length: int
    data: bytes


@dataclass
class FixedRecordSection:
    selector: int
    offset: int
    byte_length: int
    record_size: int
    data: bytes

    @property
    def record_count(self) -> int:
        return self.byte_length // self.record_size

    @property
    def remainder(self) -> int:
        return self.byte_length % self.record_size


@dataclass
class BlobSection:
    selector: int
    offset: int
    length: int
    data: bytes


@dataclass
class CountedStringEntry:
    index: int
    offset: int
    length: int
    data: bytes


@dataclass
class CountedStringSection:
    selector: int
    offset: int
    entry_bytes: int
    count: int
    entries: list[CountedStringEntry]


@dataclass
class CStringEntry:
    index: int
    offset: int
    raw_length: int
    data: bytes


@dataclass
class CStringTableSection:
    selector: int
    offset: int
    count: int
    entries: list[CStringEntry]


@dataclass
class MediaViewPayload:
    font_blob: FontBlob
    sec07: FixedRecordSection
    sec08: FixedRecordSection
    sec06: FixedRecordSection
    sec01: BlobSection
    sec02: BlobSection
    sec6a: BlobSection
    sec13: CountedStringSection
    sec04: CStringTableSection
    trailing: bytes


def parse_cache_file(data: bytes, payload_only: bool) -> MediaViewCacheFile:
    if payload_only:
        return MediaViewCacheFile(
            header0=0,
            header1=0,
            payload=data,
            payload_only=True,
        )
    if len(data) < 8:
        raise ValueError("cache file is shorter than the 8-byte header")
    header0, off = read_u32(data, 0)
    header1, off = read_u32(data, off)
    return MediaViewCacheFile(
        header0=header0,
        header1=header1,
        payload=data[off:],
        payload_only=False,
    )


def parse_font_blob(data: bytes, off: int) -> tuple[FontBlob, int]:
    start = off
    length, off = read_u16(data, off)
    blob, off = read_bytes(data, off, length)
    return FontBlob(offset=start, length=length, data=blob), off


def parse_fixed_section(
    data: bytes,
    off: int,
    selector: int,
    record_size: int,
) -> tuple[FixedRecordSection, int]:
    start = off
    byte_length, off = read_u16(data, off)
    payload, off = read_bytes(data, off, byte_length)
    return (
        FixedRecordSection(
            selector=selector,
            offset=start,
            byte_length=byte_length,
            record_size=record_size,
            data=payload,
        ),
        off,
    )


def parse_blob_section(
    data: bytes,
    off: int,
    selector: int,
) -> tuple[BlobSection, int]:
    start = off
    length, off = read_u16(data, off)
    payload, off = read_bytes(data, off, length)
    return (
        BlobSection(
            selector=selector,
            offset=start,
            length=length,
            data=payload,
        ),
        off,
    )


def parse_counted_string_section(
    data: bytes,
    off: int,
    selector: int,
) -> tuple[CountedStringSection, int]:
    start = off
    entry_bytes, off = read_u16(data, off)
    count = 0
    entries: list[CountedStringEntry] = []
    if entry_bytes == 0:
        return (
            CountedStringSection(
                selector=selector,
                offset=start,
                entry_bytes=0,
                count=0,
                entries=[],
            ),
            off,
        )

    count, off = read_u16(data, off)
    entries_end = off + entry_bytes
    if entries_end > len(data):
        raise ValueError(
            f"selector 0x{selector:02x} entries overrun payload"
        )

    for index in range(count):
        entry_offset = off
        length, off = read_u16(data, off)
        chunk, off = read_bytes(data, off, length)
        entries.append(
            CountedStringEntry(
                index=index,
                offset=entry_offset,
                length=length,
                data=chunk,
            )
        )

    if off != entries_end:
        raise ValueError(
            "selector 0x13 entry bytes do not match the encoded body size"
        )

    return (
        CountedStringSection(
            selector=selector,
            offset=start,
            entry_bytes=entry_bytes,
            count=count,
            entries=entries,
        ),
        off,
    )


def parse_c_string_table(
    data: bytes,
    off: int,
    selector: int,
) -> tuple[CStringTableSection, int]:
    start = off
    count, off = read_u16(data, off)
    entries: list[CStringEntry] = []
    for index in range(count):
        entry_offset = off
        end = find_c_string_end(data, off)
        chunk = data[off:end]
        entries.append(
            CStringEntry(
                index=index,
                offset=entry_offset,
                raw_length=len(chunk),
                data=chunk,
            )
        )
        off = end
    return (
        CStringTableSection(
            selector=selector,
            offset=start,
            count=count,
            entries=entries,
        ),
        off,
    )


def parse_payload(data: bytes) -> MediaViewPayload:
    off = 0
    font_blob, off = parse_font_blob(data, off)
    sec07, off = parse_fixed_section(data, off, 0x07, 0x2B)
    sec08, off = parse_fixed_section(data, off, 0x08, 0x1F)
    sec06, off = parse_fixed_section(data, off, 0x06, 0x98)
    sec01, off = parse_blob_section(data, off, 0x01)
    sec02, off = parse_blob_section(data, off, 0x02)
    sec6a, off = parse_blob_section(data, off, 0x6A)
    sec13, off = parse_counted_string_section(data, off, 0x13)
    sec04, off = parse_c_string_table(data, off, 0x04)
    trailing = data[off:]
    return MediaViewPayload(
        font_blob=font_blob,
        sec07=sec07,
        sec08=sec08,
        sec06=sec06,
        sec01=sec01,
        sec02=sec02,
        sec6a=sec6a,
        sec13=sec13,
        sec04=sec04,
        trailing=trailing,
    )


def print_ascii_candidates(prefix: str, data: bytes, min_len: int) -> None:
    strings = extract_ascii_strings(data, min_len)
    if not strings:
        print(f"{prefix}printable_strings: []")
        return
    print(f"{prefix}printable_strings:")
    for item in strings:
        print(f"{prefix}  {item!r}")


def print_font_blob(blob: FontBlob, min_len: int) -> None:
    print(f"selector 0x6f {SELECTOR_LABELS[0x6F]}")
    print(f"  payload_offset: 0x{blob.offset:04x}")
    print(f"  blob_length: 0x{blob.length:x}")
    print(f"  head: {blob.data[:32].hex()}")
    print_ascii_candidates("  ", blob.data, min_len)
    print("  note: TitleOpenEx copies this blob into a GMEM handle.")


def print_fixed_section(
    section: FixedRecordSection,
    min_len: int,
    max_strings: int,
) -> None:
    print(f"selector 0x{section.selector:02x} {SELECTOR_LABELS[section.selector]}")
    print(f"  payload_offset: 0x{section.offset:04x}")
    print(f"  byte_length: 0x{section.byte_length:x}")
    print(f"  record_size: 0x{section.record_size:x}")
    print(f"  record_count: {section.record_count}")
    print(f"  remainder: 0x{section.remainder:x}")
    for index in range(section.record_count):
        record_off = section.offset + 2 + index * section.record_size
        record = section.data[
            index * section.record_size:(index + 1) * section.record_size
        ]
        print(f"  record[{index}] offset=0x{record_off:04x} head={record[:16].hex()}")
        strings = extract_ascii_strings(record, min_len)
        if strings:
            for item in strings[:max_strings]:
                print(f"    ascii: {item!r}")
            if len(strings) > max_strings:
                print(f"    ascii: ... {len(strings) - max_strings} more")


def print_blob_section(section: BlobSection, min_len: int) -> None:
    print(f"selector 0x{section.selector:02x} {SELECTOR_LABELS[section.selector]}")
    print(f"  payload_offset: 0x{section.offset:04x}")
    print(f"  blob_length: 0x{section.length:x}")
    print(f"  head: {section.data[:32].hex()}")
    if section.data:
        print(f"  decoded: {decode_bytes_text(section.data)}")
    print_ascii_candidates("  ", section.data, min_len)


def print_counted_string_section(section: CountedStringSection) -> None:
    print(f"selector 0x{section.selector:02x} {SELECTOR_LABELS[section.selector]}")
    print(f"  payload_offset: 0x{section.offset:04x}")
    print(f"  entry_bytes: 0x{section.entry_bytes:x}")
    print(f"  count: {section.count}")
    for entry in section.entries:
        print(
            f"  entry[{entry.index}] offset=0x{entry.offset:04x} "
            f"len=0x{entry.length:x} text={decode_bytes_text(entry.data)}"
        )


def print_c_string_table(section: CStringTableSection) -> None:
    print(f"selector 0x{section.selector:02x} {SELECTOR_LABELS[section.selector]}")
    print(f"  payload_offset: 0x{section.offset:04x}")
    print(f"  count: {section.count}")
    for entry in section.entries:
        text = entry.data[:-1].decode("latin-1", errors="replace")
        print(
            f"  entry[{entry.index}] offset=0x{entry.offset:04x} "
            f"len=0x{entry.raw_length:x} text={text!r}"
        )


def print_selector_notes() -> None:
    print("selector notes")
    print("  0x6f -> font blob materialized as a global-memory handle")
    print("  0x69 -> live file-system / mode metadata; not stored in the cache payload")
    print("  0x07 -> indexed 0x2b-byte records via arg=(index<<16)|bufsize")
    print("  0x08 -> indexed 0x1f-byte records via arg=(index<<16)|bufsize")
    print("  0x06 -> indexed 0x98-byte records via arg=(index<<16)|bufsize")
    print("  0x01 -> length-prefixed blob")
    print("  0x02 -> length-prefixed blob")
    print("  0x6a -> length-prefixed blob")
    print("  0x13 -> counted string table: u16 len + bytes entries")
    print("  0x04 -> counted table of NUL-terminated strings")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect MediaView 1.4 cache files or raw payload blobs."
    )
    parser.add_argument("path", help="Path to MVCache_*.tmp or a raw payload blob")
    parser.add_argument(
        "--payload-only",
        action="store_true",
        help="Treat the input as a raw MediaView payload without the 8-byte cache header.",
    )
    parser.add_argument(
        "--min-string",
        type=int,
        default=4,
        help="Minimum ASCII length to report from binary blobs.",
    )
    parser.add_argument(
        "--max-record-strings",
        type=int,
        default=4,
        help="Maximum ASCII candidates to print per fixed-width record.",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()
    try:
        path = Path(args.path)
        data = path.read_bytes()
        cache = parse_cache_file(data, args.payload_only)
        payload = parse_payload(cache.payload)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"file: {path}")
    print(f"mode: {'payload' if cache.payload_only else 'cache'}")
    if not cache.payload_only:
        print("cache_header")
        print(f"  header0: {format_hex(cache.header0)}")
        print(f"  header1: {format_hex(cache.header1)}")
    print(f"payload_size: 0x{len(cache.payload):x}")
    print()

    print_font_blob(payload.font_blob, args.min_string)
    print()
    print_fixed_section(payload.sec07, args.min_string, args.max_record_strings)
    print()
    print_fixed_section(payload.sec08, args.min_string, args.max_record_strings)
    print()
    print_fixed_section(payload.sec06, args.min_string, args.max_record_strings)
    print()
    print_blob_section(payload.sec01, args.min_string)
    print()
    print_blob_section(payload.sec02, args.min_string)
    print()
    print_blob_section(payload.sec6a, args.min_string)
    print()
    print_counted_string_section(payload.sec13)
    print()
    print_c_string_table(payload.sec04)
    print()
    print_selector_notes()
    if payload.trailing:
        print()
        print(f"trailing_bytes: {payload.trailing.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
