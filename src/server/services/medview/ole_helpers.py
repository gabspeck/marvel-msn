"""OLE compound-file helpers for Blackbird titles."""

from __future__ import annotations

import struct
import zlib

CK_MAGIC = b"CK"


def parse_type_names_map(data: bytes) -> dict[int, str]:
    """`\\x03type_names_map` stream → `{storage_table_id: class_name}`.

    Wire shape: `[u32 count][u16 max_slot]{[u8 name_len][ASCII name]
    [u32 level_specifier]}*count`. The `level_specifier` is the
    top-level storage directory number (e.g. `5` for storage `5/<n>/`).
    """
    if len(data) < 6:
        raise ValueError("type_names_map stream too short")
    count = struct.unpack_from("<I", data, 0)[0]
    pos = 6  # skip count + max_slot
    out: dict[int, str] = {}
    for _ in range(count):
        name_len = data[pos]
        pos += 1
        name = data[pos : pos + name_len].decode("ascii", errors="replace")
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
