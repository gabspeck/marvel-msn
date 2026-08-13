"""Reading a published COSCL compound file, and writing `paste_object` records.

The publish leg hands the server an OLE2 compound file built by COSCL's
store-to-store `extract_object`. The retrieval leg asks for objects out of it
by GUID and expects flat records — the format COSCL's *other* `extract_object`
overload writes (`0x40216AB4`) and `paste_object` reads (`0x402178A4`). This
module bridges the two. See docs/BLACKBIRD.md §4.4.3.

What the compound file exposes, and how the pieces join up:

  \\x03type_names_map   {class name → storage id}
  \\x03ref_N            one CDPORef per storage N; its tail carries the
                        object's GUID, a sub-index, and a handle
  <id>/<sub>/\\x03object      the serialized instance
  <id>/<sub>/\\x03properties  its property bag

`ref_N` belongs to storage `N`, and the handle in its tail is `N * 0x20` —
which is what makes the join checkable rather than assumed.
"""

from __future__ import annotations

import logging
import pathlib
import struct
from dataclasses import dataclass

import olefile

log = logging.getLogger(__name__)

# Artifact-kind bits, as `paste_object` tests them.
KIND_OBJECT = 0x01
KIND_SWIZZLE = 0x02
KIND_PROPERTIES = 0x04
# Bit 3 turns off paste_object's "all three artifacts required" check. The
# check only runs when its third argument is 0 and OBCL passes 1, so this is
# belt and braces — but extract_object sets it on every record it writes.
KIND_PARTIAL_OK = 0x08

# Status-flag bits are CDPORef flag numbers. Bit 3 says the GUID is inline;
# 0x800 and 0x1000 are the flags the caller tests after a paste to decide
# whether the object arrived whole, so leaving them clear is what marks it
# complete. The top nibble is passed to AddFiatMoniker as its moniker kind.
STATUS_GUID_INLINE = 0x00000008
STATUS_OBJECT_ABSENT = 0x00000800
STATUS_PROPERTIES_ABSENT = 0x00001000
# Flag 0x0D. `extract_object` writes the swizzle section only when it is set
# and clears kind bit 1 when it is not, so it and KIND_SWIZZLE move together.
# Leaving it clear while sending a section is worse than sending none at all:
# `paste_object` reads the section, writes the handles stream, then reaches a
# tail that deletes that stream whenever flags 0x0B and 0x0D are both clear.
STATUS_SWIZZLE_PRESENT = 0x00002000
# Flag 0x0E. `extract_object` sets it whenever the source object owns a
# properties stream, and gates writing that stream on it.
STATUS_HAS_PROPERTIES = 0x00004000
STATUS_MONIKER_KIND_SHIFT = 28

_HANDLE_PER_STORAGE = 0x20

# A stored handle is `(storage_id * 0x20) << 16 | sub_id`. COSCL keys the
# transmit name table on `handle >> 21`, which reduces to the storage id, so
# every reference into one storage shares a single name-blob entry.
_HANDLE_STORAGE_SHIFT = 21

# `[GUID 16][u32 flags][u32 name_ref]`, and `name_ref` packs the name's length
# in its low 10 bits and its blob offset above them. ProcessSwizzleTable
# (COSCL:0x40219640) reads the name back as `blob[off : off + len]` by writing
# a NUL at `off + len` and restoring it after — which is why the blob is padded
# to a multiple of 4, so that write stays in bounds on the last name.
_SWIZZLE_ENTRY = struct.Struct("<16sII")
_NAME_LEN_BITS = 10
_BLOB_ALIGN = 4

# A serialized CDPORef entry runs `[u32 flags][u32][FILETIME × 0..2][GUID 16]
# [u16 sub][u16 handle]`. The FILETIME count varies by subclass — observed 2
# on CDPORefHc/HC, 1 on the CVForm ref, 0 on the short trailing entries — so
# the flags cannot be read at a fixed distance from the GUID. Step back over
# anything whose high dword scans as a FILETIME instead. The range spans
# roughly 1995 to 2100, which is far from the small counts and the flag words
# that occupy the same slot when no timestamp is present.
_FILETIME_HIGH_MIN = 0x01A00000
_FILETIME_HIGH_MAX = 0x02000000

# A moniker flag word always carries the inline-GUID bit and a non-zero kind in
# its top nibble. ProcessSwizzleTable feeds the kind straight to AddMoniker,
# and a wrong one faults the client inside the ref manager, so an entry that
# fails this check is dropped rather than transmitted.
_FLAGS_KIND_MASK = 0xF0000000


@dataclass(frozen=True)
class CosObject:
    """One object out of a published title."""

    guid: bytes  # 16 bytes, little-endian as it sits on the wire
    typename: str
    title: str  # sub-COS name the record is pasted under
    flags: int  # the object's own CDPORef flag word, from its \x03ref_N entry
    storage_id: int
    sub_id: int
    object_bytes: bytes
    properties: bytes
    swizzle: bytes  # transmit-form swizzle section, empty when the object holds no refs

    @property
    def storage_path(self):
        return f"{self.storage_id}/{self.sub_id}"


def _stream(ole, path):
    try:
        return ole.openstream(path).read()
    except OSError:
        return b""


def _parse_type_names(blob):
    """`{storage id → class name}` from `\\x03type_names_map`.

    Layout is `[u32 count][u16 opaque]` then `[u8 len][name][u32 storage_id]`
    per entry (docs/BLACKBIRD.md §3.1.1).
    """
    if len(blob) < 6:
        return {}
    count = struct.unpack_from("<I", blob)[0]
    names = {}
    pos = 6
    for _ in range(count):
        if pos >= len(blob):
            break
        length = blob[pos]
        pos += 1
        name = blob[pos : pos + length].decode("ascii", errors="replace")
        pos += length
        if pos + 4 > len(blob):
            break
        names[struct.unpack_from("<I", blob, pos)[0]] = name
        pos += 4
    return names


def _parse_ref(blob, storage_id):
    """Every `(guid, sub_id, flags)` a `\\x03ref_N` record names.

    The record opens with a fixed header and a `CDPORef*` class name; the
    entries follow it. Rather than model the header — its layout varies by
    subclass (`CDPORefHc` vs `CDPORefHC`) and is not pinned — anchor on the
    handle, which is `storage_id * 0x20` and is the last field of each entry.
    An entry is `… [GUID 16][u16 sub_id][u16 handle]`, so finding the handle
    locates the GUID, the sub-id, and the flags dword behind it.

    `flags` is the CDPORef flag word. `SwizzleTableConvertForTransmit`
    (COSCL:0x40227AA0) copies it into the transmit entry verbatim, so a
    moniker that names an object we did not publish keeps its `0x800`
    object-absent bit and the receiver treats the reference accordingly.
    """
    entries = []
    want = struct.pack("<H", storage_id * _HANDLE_PER_STORAGE)
    pos = blob.find(b"CDPORef")
    if pos < 0:
        return entries
    while True:
        found = blob.find(want, pos)
        if found < 0 or found + 2 > len(blob):
            break
        start = found - 18
        pos = found + 2
        if start < 0:
            continue
        flags = _ref_flags(blob, start)
        if flags is None:
            log.warning(
                "cos_ref_flags_unreadable storage=%d guid=%s",
                storage_id,
                blob[start : start + 16].hex(),
            )
            continue
        guid = blob[start : start + 16]
        sub_id = struct.unpack_from("<H", blob, start + 16)[0]
        entries.append((guid, sub_id, flags))
    return entries


def _ref_flags(blob, guid_start):
    """The CDPORef flag word ahead of a serialized entry's GUID, or None.

    Steps back over each preceding 8-byte block whose high dword scans as a
    FILETIME; the two dwords before the first non-timestamp are the flags and
    an entry count.
    """
    pos = guid_start
    while pos >= 8:
        (high,) = struct.unpack_from("<I", blob, pos - 4)
        if not _FILETIME_HIGH_MIN <= high <= _FILETIME_HIGH_MAX:
            break
        pos -= 8
    if pos < 8:
        return None
    (flags,) = struct.unpack_from("<I", blob, pos - 8)
    if not flags & STATUS_GUID_INLINE or not flags & _FLAGS_KIND_MASK:
        return None
    return flags


def _parse_handles(blob):
    """The stored `\\x03handles` swizzle table: `[u32 count][u32 handle × count]`."""
    if len(blob) < 4:
        return []
    count = struct.unpack_from("<I", blob)[0]
    if len(blob) < 4 + count * 4:
        return []
    return list(struct.unpack_from(f"<{count}I", blob, 4))


def _build_swizzle(handles, typenames, refs):
    """The transmit-form swizzle section for one object.

    Mirrors `SwizzleTableConvertForTransmit`: a name blob holding one class
    name per distinct storage in first-seen handle order, padded to a multiple
    of four, then one 24-byte entry per handle, then the child count.

    Child count is zero. `extract_object` emits children only while its depth
    argument is unspent; at zero it stops and leaves the monikers pointing at
    GUIDs the receiver has not been given, which is what makes it come back
    and ask for them on another method-3 request.

    A handle naming a storage or sub-object the publish left out is dropped.
    The entries and the name blob are read in lockstep, so a placeholder would
    shift every later name offset.
    """
    names = {}
    blob = bytearray()
    entries = []
    for handle in handles:
        storage_id = handle >> _HANDLE_STORAGE_SHIFT
        sub_id = handle & 0xFFFF
        target = refs.get((storage_id, sub_id))
        typename = typenames.get(storage_id)
        if target is None or typename is None:
            log.warning(
                "cos_swizzle_unresolved handle=0x%08x storage=%d sub=%d", handle, storage_id, sub_id
            )
            continue
        if storage_id not in names:
            encoded = typename.encode("ascii", errors="replace")
            names[storage_id] = (len(blob), len(encoded))
            blob += encoded
        offset, length = names[storage_id]
        guid, flags = target
        entries.append(_SWIZZLE_ENTRY.pack(guid, flags, length | (offset << _NAME_LEN_BITS)))

    if not entries:
        return b""
    blob += b"\x00" * (-len(blob) % _BLOB_ALIGN)
    return (
        struct.pack("<I", len(blob))
        + bytes(blob)
        + struct.pack("<I", len(entries))
        + b"".join(entries)
        + struct.pack("<I", 0)
    )


def load_title(path):
    """Every object in a published compound file, keyed by GUID.

    An object whose storage is missing is skipped rather than raising: the
    publish ships whichever artifacts changed, so a ref naming a storage that
    was not sent is normal for an incremental publish.
    """
    objects = {}
    title = pathlib.Path(path).stem
    with olefile.OleFileIO(str(path)) as ole:
        names = _parse_type_names(_stream(ole, "\x03type_names_map"))
        available = {"/".join(entry) for entry in ole.listdir(streams=True)}
        refs = {}
        for storage_id in names:
            for guid, sub_id, flags in _parse_ref(_stream(ole, f"\x03ref_{storage_id}"), storage_id):
                refs[(storage_id, sub_id)] = (guid, flags)

        for (storage_id, sub_id), (guid, flags) in sorted(refs.items()):
            object_path = f"{storage_id}/{sub_id}/\x03object"
            if object_path not in available:
                continue
            handles = _parse_handles(_stream(ole, f"{storage_id}/{sub_id}/\x03handles"))
            objects[guid] = CosObject(
                guid=guid,
                typename=names[storage_id],
                title=title,
                flags=flags,
                storage_id=storage_id,
                sub_id=sub_id,
                object_bytes=_stream(ole, object_path),
                properties=_stream(ole, f"{storage_id}/{sub_id}/\x03properties"),
                swizzle=_build_swizzle(handles, names, refs),
            )
    return objects


def build_paste_record(obj, *, moniker_kind=1):
    """Serialize one object the way `paste_object` reads it.

    An object that references others carries a swizzle section, without which
    the record is a dead end: the section is what registers the monikers the
    object's serialized form resolves against, so a title served without one
    pastes as a root with no way to reach anything else. Observed 2026-08-13 —
    the client asked for the CTitle GUID, pasted it, and stopped.

    The typename is written without a terminator: the writer emits the
    `CString` length from `[ptr-8]` and the reader hands the same count to
    `ReleaseBuffer`.
    """
    kind = KIND_PARTIAL_OK | KIND_OBJECT
    status = STATUS_GUID_INLINE | (moniker_kind << STATUS_MONIKER_KIND_SHIFT)
    if obj.properties:
        kind |= KIND_PROPERTIES
        status |= STATUS_HAS_PROPERTIES
    else:
        status |= STATUS_PROPERTIES_ABSENT
    if not obj.object_bytes:
        status |= STATUS_OBJECT_ABSENT
    if obj.swizzle:
        kind |= KIND_SWIZZLE
        status |= STATUS_SWIZZLE_PRESENT

    typename = obj.typename.encode("ascii", errors="replace")
    out = bytearray()
    out += struct.pack("<II", kind, status)
    out += obj.guid
    out += struct.pack("<I", len(typename))
    out += typename
    out += struct.pack("<I", len(obj.object_bytes))
    out += obj.object_bytes
    if obj.properties:
        out += struct.pack("<I", len(obj.properties))
        out += obj.properties
    out += obj.swizzle
    return bytes(out)


def build_object_stream(objects):
    """The method-3 stream body: one named `paste_object` record per object.

    `FUN_0040CD64` reads `[u32 name_len][name]` before each record and hands
    the name to `AddSubCOSToSuperCOS` as the sub-store to paste into. That name
    is the sub-COS key, one per title rather than one per object:
    `AddSubCOSToSuperCOS` (OBCL:0x0041355C) looks it up in CMapStringToCOSID
    and, on a miss, passes it to `CObjectStoreFactory::Create` as the name of a
    sub-storage inside the super COS. Every record of a title therefore repeats
    the same name and the lookup hits after the first.

    It has to be a legal OLE2 storage name — no `/`, `\\`, `:` or `!`. Create
    returns NULL for an illegal one and the broker throws 0x0E before any store
    exists, which is what a storage path like `1/0` produced: no sub-COS, no
    super COS, and no second request. Observed 2026-08-13.
    """
    out = bytearray()
    for obj in objects:
        name = obj.title.encode("ascii", errors="replace")
        out += struct.pack("<I", len(name))
        out += name
        out += build_paste_record(obj)
    return bytes(out)
