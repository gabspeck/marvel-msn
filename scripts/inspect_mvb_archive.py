#!/usr/bin/env python3
"""Enumerate internal files inside a Multimedia Viewer 2.0 / WinHelp
.MVB / .HLP archive.

Format per `docs/helpfile.txt` (HLP file format reference, revision 10):

  Header (16 B): u32 magic=0x00035F3F, u32 directory_start,
                 u32 first_free_block, u32 entire_file_size
  FILEHEADER (9 B): u32 reserved_space, u32 used_space, u8 file_flags
  Internal directory: a B+ tree mapping (filename → file_offset)

For each internal file, optionally scan its bytes for TextTree-style
opcode patterns (0x03 <length> <text>) — the same encoding pinned by
`src/server/services/medview/ccontent.py decode_texttree`.

Usage:
    python -m scripts.inspect_mvb_archive <archive.mvb> [--scan-text]
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

_HLP_MAGIC = 0x00035F3F
_BTREE_MAGIC = 0x293B


@dataclass(frozen=True)
class HlpHeader:
    magic: int
    directory_start: int
    first_free_block: int
    entire_file_size: int


@dataclass(frozen=True)
class FileHeader:
    reserved_space: int
    used_space: int
    file_flags: int


@dataclass(frozen=True)
class BTreeHeader:
    magic: int
    flags: int
    page_size: int
    structure: str
    page_splits: int
    root_page: int
    total_pages: int
    n_levels: int
    total_entries: int


@dataclass(frozen=True)
class InternalFile:
    name: str
    offset: int
    file_header: FileHeader
    body: bytes        # `used_space` bytes from after the 9-byte FILEHEADER


def read_hlp_header(buf: bytes) -> HlpHeader:
    if len(buf) < 16:
        raise ValueError("input shorter than HLP header")
    magic, dirstart, firstfree, total = struct.unpack("<IIII", buf[:16])
    if magic != _HLP_MAGIC:
        raise ValueError(f"not a HLP/MVB archive (magic={magic:#x})")
    return HlpHeader(magic, dirstart, firstfree, total)


def read_file_header(buf: bytes, off: int) -> FileHeader:
    if off + 9 > len(buf):
        raise ValueError("FILEHEADER overruns buffer")
    reserved, used, flags = struct.unpack_from("<IIB", buf, off)
    return FileHeader(reserved, used, flags)


def read_btree_header(buf: bytes, off: int) -> BTreeHeader:
    if off + 38 > len(buf):
        raise ValueError("BTREEHEADER overruns buffer")
    (magic, flags, page_size) = struct.unpack_from("<HHH", buf, off)
    if magic != _BTREE_MAGIC:
        raise ValueError(f"BTREEHEADER magic mismatch: {magic:#x}")
    structure = buf[off + 6:off + 22].rstrip(b"\x00").decode("ascii", errors="replace")
    (
        _must_be_zero, page_splits, root_page, _must_be_neg_one,
        total_pages, n_levels, total_entries,
    ) = struct.unpack_from("<HHHHHHI", buf, off + 22)
    return BTreeHeader(
        magic, flags, page_size, structure, page_splits, root_page,
        total_pages, n_levels, total_entries,
    )


def _read_stringz_in(buf: bytes, off: int, limit: int) -> tuple[str, int]:
    """Read a NUL-terminated string starting at `off`, refusing to
    scan past `limit`. Returns `(decoded, next_offset)`."""
    if off >= limit:
        raise ValueError("STRINGZ start out of bounds")
    end = buf.find(b"\x00", off, limit)
    if end < 0:
        raise ValueError("STRINGZ has no terminator within page bounds")
    # MS HLP filenames are ASCII; latin-1 is a safe superset.
    return buf[off:end].decode("latin-1"), end + 1


_MAX_TREE_PAGES_VISITED = 4096  # hard cap against runaway NextPage chains


def walk_directory_leaves(
    buf: bytes, dir_file_off: int, header: BTreeHeader,
) -> list[tuple[str, int]]:
    """Walk every leaf in the directory B+ tree, returning
    `(filename, file_offset)` pairs in tree order (sorted by name).

    `dir_file_off` is the offset of the directory FILEHEADER itself
    (= `HlpHeader.directory_start`). Pages begin 9 bytes (FILEHEADER)
    plus 38 bytes (BTREEHEADER) past it.

    Each leaf-page parse is strictly bounded to the page's `page_size`
    bytes; corrupt `NEntries` cannot escape and chew through the rest
    of the archive.
    """
    pages_start = dir_file_off + 9 + 38
    page_size = header.page_size
    if page_size <= 0 or page_size > 0x4000:
        raise ValueError(f"unreasonable btree page_size: {page_size}")

    def _page_bounds(idx: int) -> tuple[int, int]:
        start = pages_start + idx * page_size
        end = start + page_size
        if start < 0 or end > len(buf):
            raise ValueError(f"page {idx} bounds out of buffer")
        return start, end

    # Walk down to the leftmost leaf via PreviousPage on each index page.
    current = header.root_page
    for _ in range(max(0, header.n_levels - 1)):
        page_off, _page_end = _page_bounds(current)
        # BTREEINDEXHEADER: u16 Unused, u16 NEntries, i16 PreviousPage.
        _unused, _n_entries, previous = struct.unpack_from(
            "<HHh", buf, page_off,
        )
        if previous < 0:
            raise ValueError("index-page PreviousPage is negative")
        current = previous

    # Walk leaf pages via NextPage until -1. Cap total pages visited.
    entries: list[tuple[str, int]] = []
    visited = 0
    while current != 0xFFFF and current >= 0:
        if visited >= _MAX_TREE_PAGES_VISITED:
            raise ValueError(f"runaway leaf-page chain (visited > {_MAX_TREE_PAGES_VISITED})")
        visited += 1
        page_off, page_end = _page_bounds(current)
        # BTREENODEHEADER (8 B): u16 Unused, u16 NEntries, i16 PreviousPage, i16 NextPage.
        _unused, n_entries, _prev, nxt = struct.unpack_from(
            "<HHhh", buf, page_off,
        )
        # Sanity check NEntries — each entry is at least 5 B (1-byte name + NUL + 4-byte offset).
        if n_entries < 0 or n_entries > (page_size - 8) // 5:
            raise ValueError(
                f"leaf-page {current} NEntries={n_entries} out of sane range"
            )
        scan = page_off + 8
        for _ in range(n_entries):
            name, scan = _read_stringz_in(buf, scan, page_end)
            if scan + 4 > page_end:
                raise ValueError("FileOffset overruns leaf page")
            (file_offset,) = struct.unpack_from("<I", buf, scan)
            scan += 4
            entries.append((name, file_offset))
        current = nxt if nxt >= 0 else -1
        if current == -1:
            break
    return entries


def read_internal_file(buf: bytes, offset: int) -> InternalFile | None:
    """Read one internal file by offset.

    Returns None when bounds are inconsistent (e.g. a free-list block
    masquerading as a file). The caller can skip these gracefully.
    """
    try:
        hdr = read_file_header(buf, offset)
    except ValueError:
        return None
    body_start = offset + 9
    body_end = body_start + hdr.used_space
    if body_end > len(buf):
        return None
    return InternalFile(
        name="",          # caller fills in from directory walk
        offset=offset,
        file_header=hdr,
        body=bytes(buf[body_start:body_end]),
    )


def scan_text_segments(payload: bytes) -> list[tuple[int, str]]:
    """Same scanner as `ccontent._scan_text_segments` but standalone
    so this script doesn't import the server package."""
    out: list[tuple[int, str]] = []
    i = 0
    end = len(payload)
    while i < end:
        if payload[i] != 0x03:
            i += 1
            continue
        if i + 1 >= end:
            break
        ln = payload[i + 1]
        if ln == 0xFF or ln == 0 or i + 2 + ln > end:
            i += 1
            continue
        chunk = payload[i + 2:i + 2 + ln]
        if all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in chunk):
            out.append((i, chunk.decode("ascii", errors="replace")))
            i += 2 + ln
            continue
        i += 1
    return out


def inspect_mvb_archive(path: Path) -> dict:
    """Parse an MVB/HLP archive and return a structured view."""
    buf = path.read_bytes()
    header = read_hlp_header(buf)
    dir_fh = read_file_header(buf, header.directory_start)
    btree = read_btree_header(buf, header.directory_start + 9)
    directory = walk_directory_leaves(buf, header.directory_start, btree)
    files: list[InternalFile] = []
    for name, offset in directory:
        f = read_internal_file(buf, offset)
        if f is None:
            continue
        files.append(InternalFile(
            name=name,
            offset=f.offset,
            file_header=f.file_header,
            body=f.body,
        ))
    return {
        "path": str(path),
        "size": len(buf),
        "header": header,
        "directory_file_header": dir_fh,
        "btree": btree,
        "directory_entries": directory,
        "internal_files": files,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("archive")
    parser.add_argument(
        "--scan-text", action="store_true",
        help="scan each file body for `[0x03 length text]` segments "
             "(same opcode as Blackbird TextTree)",
    )
    args = parser.parse_args()

    info = inspect_mvb_archive(Path(args.archive))
    print(f"file: {info['path']}  size={info['size']}")
    h = info["header"]
    print(f"  magic=0x{h.magic:08x}  directory_start=0x{h.directory_start:x}  "
          f"first_free=0x{h.first_free_block:x}  total_size={h.entire_file_size}")
    b = info["btree"]
    print(f"  btree: page_size=0x{b.page_size:x} n_levels={b.n_levels} "
          f"entries={b.total_entries} structure={b.structure!r}")
    print()
    print(f"== {len(info['internal_files'])} internal files ==")
    for f in info["internal_files"]:
        head_hex = f.body[:16].hex()
        print(f"  {f.name:<24}  offset=0x{f.offset:08x}  used={f.file_header.used_space:>8}  head={head_hex}")
        if args.scan_text:
            segs = scan_text_segments(f.body)
            if segs:
                print(f"    text segments ({len(segs)}):")
                for off, text in segs[:8]:
                    print(f"      off=0x{off:06x}  {text!r}")
                if len(segs) > 8:
                    print(f"      ... +{len(segs) - 8} more")


if __name__ == "__main__":
    sys.exit(main())
