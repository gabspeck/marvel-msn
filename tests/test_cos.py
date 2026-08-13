"""Reading a published COSCL compound file and writing `paste_object` records.

The record format is the one COSCL's `CFile` overload of `extract_object`
(`0x40216AB4`) writes and `paste_object` (`0x402178A4`) reads, so the tests
that matter here decode a record the way `paste_object` does and check it
consumes exactly what was written — a record that over- or under-runs
desynchronises every object behind it in the stream.

See docs/BLACKBIRD.md §4.4.3.
"""

import pathlib
import struct
import unittest

import olefile

from server.blackbird import cos

_FIXTURE = pathlib.Path(__file__).resolve().parent / "assets" / "captions_test.ttl"


def _read_record(blob, pos=0):
    """Decode one named record, mirroring `FUN_0040CD64` + `paste_object`."""
    (name_len,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    name = blob[pos : pos + name_len].decode("ascii")
    pos += name_len

    kind, status = struct.unpack_from("<II", blob, pos)
    pos += 8
    guid = None
    if status & cos.STATUS_GUID_INLINE:
        guid = blob[pos : pos + 16]
        pos += 16
    (typename_len,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    typename = blob[pos : pos + typename_len].decode("ascii")
    pos += typename_len
    (object_len,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    object_bytes = b""
    if kind & cos.KIND_OBJECT:
        object_bytes = blob[pos : pos + object_len]
        pos += object_len
    properties = b""
    if kind & cos.KIND_PROPERTIES:
        (props_len,) = struct.unpack_from("<I", blob, pos)
        pos += 4
        properties = blob[pos : pos + props_len]
        pos += props_len
    swizzle = None
    if kind & cos.KIND_SWIZZLE:
        swizzle, pos = _read_swizzle(blob, pos)
    return {
        "name": name,
        "kind": kind,
        "status": status,
        "guid": guid,
        "typename": typename,
        "object": object_bytes,
        "properties": properties,
        "swizzle": swizzle,
    }, pos


def _read_swizzle(blob, pos):
    """Decode a swizzle section the way `ProcessSwizzleTable` reads it."""
    (blob_len,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    names = blob[pos : pos + blob_len]
    pos += blob_len
    (entry_count,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    entries = []
    for _ in range(entry_count):
        guid, flags, name_ref = struct.unpack_from("<16sII", blob, pos)
        pos += 24
        offset, length = name_ref >> 10, name_ref & 0x3FF
        entries.append(
            {
                "guid": guid,
                "flags": flags,
                "name": names[offset : offset + length].decode("ascii"),
                "offset": offset,
                "length": length,
            }
        )
    (children,) = struct.unpack_from("<I", blob, pos)
    pos += 4
    return {"names": names, "entries": entries, "children": children}, pos


class TestLoadTitle(unittest.TestCase):
    def setUp(self):
        self.objects = cos.load_title(_FIXTURE)

    def test_every_storage_in_the_type_map_resolves(self):
        by_path = {obj.storage_path: obj.typename for obj in self.objects.values()}
        self.assertEqual(
            by_path,
            {
                "1/0": "CTitle",
                "2/0": "CResourceFolder",
                "3/0": "CBFrame",
                "4/0": "CStyleSheet",
                "5/0": "CVForm",
                "6/0": "CBForm",
            },
        )

    def test_objects_are_keyed_by_their_own_guid(self):
        for guid, obj in self.objects.items():
            self.assertEqual(guid, obj.guid)
            self.assertEqual(len(guid), 16)

    def test_object_bytes_come_from_the_matching_storage(self):
        title = next(o for o in self.objects.values() if o.typename == "CTitle")
        self.assertEqual(len(title.object_bytes), 40)
        self.assertTrue(title.properties)


class TestRefFlags(unittest.TestCase):
    """`SwizzleTableConvertForTransmit` copies a CDPORef's flag word into the
    moniker entry verbatim, and `ProcessSwizzleTable` hands its top nibble to
    AddMoniker as the moniker kind. A misparsed word faults the client inside
    the ref manager, so the parse is checked against what the file holds."""

    def setUp(self):
        self.ole = olefile.OleFileIO(str(_FIXTURE))
        self.addCleanup(self.ole.close)
        self.typenames = cos._parse_type_names(cos._stream(self.ole, "\x03type_names_map"))
        self.streams = {"/".join(entry) for entry in self.ole.listdir(streams=True)}

    def _entries(self):
        for storage_id in sorted(self.typenames):
            blob = cos._stream(self.ole, f"\x03ref_{storage_id}")
            for guid, sub_id, flags in cos._parse_ref(blob, storage_id):
                yield storage_id, sub_id, guid, flags

    def test_every_entry_names_a_moniker_kind(self):
        entries = list(self._entries())
        self.assertTrue(entries)
        for storage_id, sub_id, _guid, flags in entries:
            with self.subTest(path=f"{storage_id}/{sub_id}"):
                self.assertTrue(flags & cos.STATUS_GUID_INLINE, f"0x{flags:08x}")
                self.assertTrue(flags >> cos.STATUS_MONIKER_KIND_SHIFT, f"0x{flags:08x}")

    def test_flags_agree_with_the_streams_the_file_holds(self):
        """The entry layout puts zero, one or two FILETIMEs between the flag
        word and the GUID, so the word is found by scanning back rather than at
        a fixed offset. These three bits are what proves the scan landed."""
        for storage_id, sub_id, _guid, flags in self._entries():
            path = f"{storage_id}/{sub_id}"
            with self.subTest(path=path):
                self.assertEqual(
                    bool(flags & cos.STATUS_OBJECT_ABSENT),
                    f"{path}/\x03object" not in self.streams,
                )
                self.assertEqual(
                    bool(flags & cos.STATUS_SWIZZLE_PRESENT),
                    f"{path}/\x03handles" in self.streams,
                )
                self.assertEqual(
                    bool(flags & cos.STATUS_HAS_PROPERTIES),
                    f"{path}/\x03properties" in self.streams,
                )


class TestPasteRecord(unittest.TestCase):
    def setUp(self):
        self.objects = cos.load_title(_FIXTURE)
        self.title = next(o for o in self.objects.values() if o.typename == "CTitle")

    def test_a_record_decodes_to_what_it_was_built_from(self):
        stream = cos.build_object_stream([self.title])
        record, consumed = _read_record(stream)

        self.assertEqual(consumed, len(stream), "record must consume the stream exactly")
        self.assertEqual(record["name"], self.title.title)
        self.assertEqual(record["typename"], "CTitle")
        self.assertEqual(record["guid"], self.title.guid)
        self.assertEqual(record["object"], self.title.object_bytes)
        self.assertEqual(record["properties"], self.title.properties)

    def test_the_guid_is_marked_inline(self):
        """`paste_object` reads the GUID only when status bit 3 is set, and the
        caller matches the pasted object by GUID afterwards."""
        record, _ = _read_record(cos.build_object_stream([self.title]))
        self.assertTrue(record["status"] & cos.STATUS_GUID_INLINE)

    def test_a_complete_object_clears_the_absent_flags(self):
        """Bits 0x800 and 0x1000 are CDPORef flags 0x0B and 0x0C, which
        `FUN_0040CD64` tests to decide whether the object landed whole."""
        record, _ = _read_record(cos.build_object_stream([self.title]))
        self.assertFalse(record["status"] & cos.STATUS_OBJECT_ABSENT)
        self.assertFalse(record["status"] & cos.STATUS_PROPERTIES_ABSENT)

    def test_the_partial_bit_is_set(self):
        """Without it `paste_object` demands object, swizzle and properties
        together whenever its third argument is 0."""
        record, _ = _read_record(cos.build_object_stream([self.title]))
        self.assertTrue(record["kind"] & cos.KIND_PARTIAL_OK)

    def test_several_objects_stay_in_step(self):
        ordered = sorted(self.objects.values(), key=lambda o: (o.storage_id, o.sub_id))
        stream = cos.build_object_stream(ordered)

        pos = 0
        seen = []
        for _ in ordered:
            record, pos = _read_record(stream, pos)
            seen.append((record["name"], record["typename"], record["guid"]))

        self.assertEqual(pos, len(stream))
        self.assertEqual(
            seen,
            [(o.title, o.typename, o.guid) for o in ordered],
        )

    def test_the_record_name_is_a_legal_ole_storage_name(self):
        """`AddSubCOSToSuperCOS` hands the name to `CObjectStoreFactory::Create`
        as a sub-storage inside the super COS. OLE2 rejects these four
        characters, Create returns NULL, and the broker throws 0x0E before any
        store exists."""
        for name in {o.title for o in self.objects.values()}:
            with self.subTest(name=name):
                self.assertTrue(name)
                for illegal in "/\\:!":
                    self.assertNotIn(illegal, name)

    def test_every_record_shares_one_sub_cos_name(self):
        """The name keys a sub-COS per title, not per object, so the lookup
        hits after the first record and they all paste into one store."""
        ordered = sorted(self.objects.values(), key=lambda o: (o.storage_id, o.sub_id))
        stream = cos.build_object_stream(ordered)
        pos = 0
        names = set()
        for _ in ordered:
            record, pos = _read_record(stream, pos)
            names.add(record["name"])
        self.assertEqual(len(names), 1)

    def test_a_typename_carries_no_terminator(self):
        """The writer emits the CString length and the reader hands the same
        count to ReleaseBuffer, so a NUL would land inside the name."""
        stream = cos.build_object_stream([self.title])
        record, _ = _read_record(stream)
        self.assertNotIn(b"\x00", record["typename"].encode("ascii"))


class TestSwizzleSection(unittest.TestCase):
    """The section `SwizzleTableConvertForTransmit` (0x40227AA0) writes and
    `ProcessSwizzleTable` (0x40219640) reads. Without it a pasted object
    registers no monikers, so nothing it references can be resolved."""

    def setUp(self):
        self.objects = cos.load_title(_FIXTURE)
        self.title = next(o for o in self.objects.values() if o.typename == "CTitle")
        self.record, _ = _read_record(cos.build_object_stream([self.title]))

    def test_an_object_holding_handles_declares_the_swizzle_bit(self):
        self.assertTrue(self.record["kind"] & cos.KIND_SWIZZLE)

    def test_the_swizzle_status_flag_travels_with_the_kind_bit(self):
        """`paste_object` writes the handles stream from the section, then a
        tail deletes that stream whenever flags 0x0B and 0x0D are both clear.
        Sending a section without flag 0x0D throws the work away."""
        self.assertTrue(self.record["status"] & cos.STATUS_SWIZZLE_PRESENT)

    def test_a_leaf_object_leaves_the_swizzle_flag_clear(self):
        leaf = next(o for o in self.objects.values() if o.typename == "CVForm")
        record, _ = _read_record(cos.build_object_stream([leaf]))
        self.assertFalse(record["status"] & cos.STATUS_SWIZZLE_PRESENT)

    def test_a_leaf_object_carries_no_section(self):
        """`\\x03handles` is absent for an object that references nothing, and
        a zero-entry section would still cost the reader a moniker pass."""
        leaf = next(o for o in self.objects.values() if o.typename == "CVForm")
        record, _ = _read_record(cos.build_object_stream([leaf]))
        self.assertFalse(record["kind"] & cos.KIND_SWIZZLE)
        self.assertIsNone(record["swizzle"])

    def test_entries_name_the_referenced_objects(self):
        by_guid = {o.guid: o.typename for o in self.objects.values()}
        seen = [(by_guid[e["guid"]], e["name"]) for e in self.record["swizzle"]["entries"]]
        self.assertEqual(seen, [("CBForm", "CBForm"), ("CResourceFolder", "CResourceFolder")])

    def test_the_name_blob_is_padded_to_a_multiple_of_four(self):
        """ProcessSwizzleTable NUL-terminates each name in place at
        `offset + length` before building the CString, so the last name needs a
        byte behind it that is still inside the blob."""
        names = self.record["swizzle"]["names"]
        self.assertEqual(len(names) % 4, 0)
        for entry in self.record["swizzle"]["entries"]:
            self.assertLess(entry["offset"] + entry["length"], len(names))

    def test_one_name_per_storage(self):
        """The transmit table keys on `handle >> 21`, which is the storage id,
        so two references into one storage share a blob entry."""
        folder = next(o for o in self.objects.values() if o.typename == "CResourceFolder")
        record, _ = _read_record(cos.build_object_stream([folder]))
        entries = record["swizzle"]["entries"]
        offsets = {e["name"]: e["offset"] for e in entries}
        self.assertEqual(len(offsets), len({e["offset"] for e in entries}))

    def test_no_children_are_inlined(self):
        """`extract_object` stops emitting children when its depth argument is
        spent, leaving the monikers pointing at GUIDs the receiver has to come
        back and request."""
        self.assertEqual(self.record["swizzle"]["children"], 0)

    def test_the_record_still_consumes_the_stream_exactly(self):
        stream = cos.build_object_stream([self.title])
        _, consumed = _read_record(stream)
        self.assertEqual(consumed, len(stream))

    def test_a_multi_object_stream_stays_in_step(self):
        """A section that over- or under-runs desynchronises every record
        behind it, and the swizzle section is the only variable-shape tail."""
        ordered = sorted(self.objects.values(), key=lambda o: (o.storage_id, o.sub_id))
        stream = cos.build_object_stream(ordered)
        pos = 0
        for obj in ordered:
            record, pos = _read_record(stream, pos)
            self.assertEqual(record["name"], obj.title)
        self.assertEqual(pos, len(stream))


if __name__ == "__main__":
    unittest.main()
