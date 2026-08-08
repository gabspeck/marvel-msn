"""Build a MOS2 container from a file, the way FTMAPI's decompressor expects.

A MOS2 chunk is standard raw DEFLATE behind a two-byte "CK" marker, so a
correct container can be produced here instead of by the client. That matters
because `HrMos2CompFile` on the Win95 VM emits streams that do not decode back
to their input — see docs/MOSSHELL.md 7.4.6.

Layout, as validated by HrMos2DecompFile @ FTMAPI 0x7F6B34A8:

    +0x00  "MOS2"
    +0x04  u16  version, must read 0x0010
    +0x06  u16  chunk size (0x8000; both codecs clamp to it)
    +0x08  u32  uncompressed byte count
    +0x0C  8    source FILETIME, restored onto the output
    then   ceil(size / chunk) records of [u32 length]["CK" + raw deflate]

The length covers the marker. The decoder rejects a record longer than
chunk + 7, so a chunk that deflates badly is stored uncompressed instead.
"""

import struct
import zlib

MAGIC = b"MOS2"
VERSION = 0x0010
CHUNK = 0x8000
HEADER = 0x14
MARKER = b"\x43\x4b"


def _deflate_chunk(plain, level):
    """Return the smallest legal record body for one chunk."""
    for attempt_level in (level, 9, 6, 1):
        c = zlib.compressobj(attempt_level, zlib.DEFLATED, -15)
        body = MARKER + c.compress(plain) + c.flush(zlib.Z_FINISH)
        # +7 is the decompressor's own allowance (FUN_7F6B55B0).
        if len(body) <= CHUNK + 7:
            return body
    # Incompressible: emit stored deflate blocks, still within the allowance
    # for anything up to the chunk size.
    c = zlib.compressobj(0, zlib.DEFLATED, -15)
    body = MARKER + c.compress(plain) + c.flush(zlib.Z_FINISH)
    if len(body) > CHUNK + 7:
        raise ValueError(f"chunk deflates to {len(body)}, over the {CHUNK + 7} limit")
    return body


def build(plain, filetime=0, level=9):
    """Return a MOS2 container holding `plain`."""
    out = bytearray()
    out += MAGIC
    out += struct.pack("<HH", VERSION, CHUNK)
    out += struct.pack("<I", len(plain))
    out += struct.pack("<Q", filetime)
    for start in range(0, len(plain), CHUNK):
        body = _deflate_chunk(plain[start : start + CHUNK], level)
        out += struct.pack("<I", len(body)) + body
    return bytes(out)


def verify(container, plain):
    """Inflate `container` the way the client does and compare with `plain`."""
    if not container.startswith(MAGIC):
        raise ValueError("missing MOS2 magic")
    if struct.unpack_from("<H", container, 4)[0] != VERSION:
        raise ValueError("bad version word")
    chunk = struct.unpack_from("<H", container, 6)[0]
    total = struct.unpack_from("<I", container, 8)[0]
    pos = HEADER
    out = bytearray()
    for _ in range(-(-total // chunk)):
        length = struct.unpack_from("<I", container, pos)[0]
        pos += 4
        body = container[pos : pos + length]
        pos += length
        if body[:2] != MARKER:
            raise ValueError("chunk is missing its CK marker")
        if length > chunk + 7:
            raise ValueError(f"chunk record {length} exceeds {chunk + 7}")
        d = zlib.decompressobj(-15)
        # The client caps each chunk's output at the header's chunk size.
        out += (d.decompress(body[2:]) + d.flush())[:chunk]
    return bytes(out) == plain and total == len(plain)


if __name__ == "__main__":
    import sys

    src, dst = sys.argv[1], sys.argv[2]
    filetime = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    plain = open(src, "rb").read()
    blob = build(plain, filetime)
    if not verify(blob, plain):
        raise SystemExit("container failed its own round-trip")
    open(dst, "wb").write(blob)
    print(f"{dst}: {len(plain)} -> {len(blob)} bytes, round-trip OK")
