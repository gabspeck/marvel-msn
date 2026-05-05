"""MediaView 1.4 cache/payload parser.

Lifted from `~/projetos/blackbird-re/scripts/inspect_mediaview_cache.py`
with the CLI `main()` removed. Wire grammar is documented in
`docs/mosview-mediaview-format.md` ("Payload Grammar" / "TitleGetInfo
Selector Contract"). Used by `m14_synth.synthesize_payload` for round-trip
validation, and by tests to assert structural invariants of the body
shipped on the TitleOpen `0x86` dynamic section.
"""

from __future__ import annotations

from dataclasses import dataclass

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
