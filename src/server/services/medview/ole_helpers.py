"""OLE compound-file helpers for Blackbird titles."""

from __future__ import annotations

import struct
import zlib

CK_MAGIC = b"CK"


def parse_type_names_map(data: bytes) -> dict[int, str]:
    """`\\x03type_names_map` stream → `{storage id: class name}`.

    Layout: `[u32 count][u16 max_slot]` then `[u8 len][name][u32 storage_id]`
    per entry (docs/BLACKBIRD.md §3.1.1). The storage id is the top-level
    storage number (`5` for `5/<n>/`). A short or truncated stream yields the
    entries read so far.
    """
    if len(data) < 6:
        return {}
    count = struct.unpack_from("<I", data)[0]
    names = {}
    pos = 6
    for _ in range(count):
        if pos >= len(data):
            break
        length = data[pos]
        pos += 1
        name = data[pos : pos + length].decode("ascii", errors="replace")
        pos += length
        if pos + 4 > len(data):
            break
        names[struct.unpack_from("<I", data, pos)[0]] = name
        pos += 4
    return names


def parse_handles(data: bytes) -> list[int]:
    """`\\x03handles` swizzle table, `[u32 count][u32 handle x count]`.
    Swizzle index `i` resolves to `handles[i]`; a short stream yields none."""
    if len(data) < 4:
        return []
    count = struct.unpack_from("<I", data)[0]
    if len(data) < 4 + count * 4:
        return []
    return list(struct.unpack_from(f"<{count}I", data, 4))


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
