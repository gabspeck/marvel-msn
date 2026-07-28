"""Tests for the MOSABP service handler (Member Properties sheet).

The wire contract is documented in docs/MOSABP.md. The blob decoder here is a
deliberate re-implementation of the client's parser (`FUN_7F4DD770` walking its
*own* request tag array, widths from `FUN_7F4DD4C4`), so a test failure means
the two disagree — which is exactly the failure that shows up on screen as
fields sliding one row up.
"""

import struct
import unittest

from server.config import MOSABP_INTERFACE_GUIDS
from server.services.mosabp import (
    MOSABP_CLASS_AB,
    MOSABP_GET_USER_DETAILS,
    MOSABP_UPDATE_USER_DETAILS,
    MOSABPHandler,
    build_get_user_details_reply_payload,
    build_member_blob,
)
from server.store import app_store
from server.store.base import MemberProfile
from server.transport import parse_packet

# The 20 tags `FUN_7F4D307D` leaves after filtering the 26-entry master array at
# MOSABP32:0x7F4E8198, in the order they reach the wire.
_SHEET_TAGS = [
    0x0FFE0003,  # PR_OBJECT_TYPE
    0x3001001E,  # PR_DISPLAY_NAME
    0x3003001E,  # PR_EMAIL_ADDRESS   → "Member ID:"
    0x3002001E,  # PR_ADDRTYPE
    0x600D001E,  # → "First name:"
    0x600E001E,  # → "Last name:"
    0x6000001E,  # → "City/Town:"
    0x6001001E,  # → "State/Province:"
    0x600F0003,  # → "Country:"
    0x6003001E,  # → "Date of birth:"
    0x6004001E,  # → "Sex:"
    0x60110003,  # → "Marital status:"
    0x60100003,  # → "Language:"
    0x6007001E,  # → "Interests:"
    0x6008001E,  # → "Job description:"
    0x6009001E,  # → "Company name:"
    0x600A001E,  # → "City/Town:" (work)
    0x600B001E,  # → "State/Province:" (work)
    0x60120003,  # → "Country:" (work)
    0x39000003,  # PR_DISPLAY_TYPE
]

# Widths `FUN_7F4DD4C4` returns for the types that carry no length prefix.
_FIXED_WIDTHS = {0x02: 2, 0x03: 4, 0x04: 4, 0x05: 8, 0x06: 8, 0x07: 8, 0x0B: 2, 0x14: 8, 0x40: 8}
_LENGTH_PREFIXED = (0x1E, 0x1F, 0x102)


def _request(member_id, tags):
    """A method-2 request as `CAbConnection::HrGetUserDetails` builds it."""
    name = member_id.encode("cp1252") + b"\x00"
    tag_bytes = struct.pack(f"<{len(tags)}I", *tags)
    return (
        b"\x04"
        + bytes([0x80 | len(name)])
        + name
        + b"\x03"
        + struct.pack("<I", len(tags))
        + b"\x04"
        + bytes([(len(tag_bytes) >> 8) & 0x7F, len(tag_bytes) & 0xFF])
        + tag_bytes
        + b"\x83\x85"
    )


def _split_reply(payload):
    """Split `0x83 [status] 0x87 0x86 [blob]` into (status, blob)."""
    assert payload[0] == 0x83, payload[:4].hex()
    status = struct.unpack_from("<I", payload, 1)[0]
    assert payload[5] == 0x87, payload[:8].hex()
    assert payload[6] == 0x86, payload[:8].hex()
    return status, payload[7:]


def _parse_blob(blob, tags):
    """Decode a property blob the way the client does, keyed by its own tags.

    Returns (values_by_tag, bytes_consumed). Nothing in the blob identifies a
    tag, so this walk is only correct if the server wrote the values in request
    order with the exact widths the types imply.
    """
    count = struct.unpack_from("<I", blob)[0]
    pos = 4
    values = {}
    for tag in tags[:count]:
        prop_type = tag & 0xFFFF
        if prop_type in _LENGTH_PREFIXED:
            cb = struct.unpack_from("<I", blob, pos)[0]
            pos += 4
            raw = blob[pos : pos + cb]
            pos += cb
            values[tag] = raw if prop_type == 0x102 else raw.decode("cp1252")
        else:
            width = _FIXED_WIDTHS[prop_type]
            values[tag] = int.from_bytes(blob[pos : pos + width], "little")
            pos += width
    return count, values, pos


class TestMOSABPDiscovery(unittest.TestCase):
    def test_advertises_the_single_iid_the_client_resolves(self):
        # `HrGetMethod` @ 0x7F4D4311 hands slot 0x24 the address of one GUID,
        # 00028B22. Omitting it is E_NOINTERFACE and the sheet never opens.
        self.assertEqual(len(MOSABP_INTERFACE_GUIDS), 1)
        guid, selector = MOSABP_INTERFACE_GUIDS[0]
        self.assertEqual(guid[:4], struct.pack("<I", 0x00028B22))
        self.assertEqual(guid[4:], bytes.fromhex("00000000c000000000000046"))
        self.assertEqual(selector, MOSABP_CLASS_AB)

    def test_discovery_packet_carries_the_iid_selector_pair(self):
        handler = MOSABPHandler(pipe_idx=6, svc_name="MOSABP")
        packets = handler.build_discovery_packet(server_seq=1, client_ack=1)
        self.assertEqual(len(packets), 1)
        payload = parse_packet(packets[0]).payload
        self.assertIn(struct.pack("<I", 0x00028B22), payload)


class TestGetUserDetailsFraming(unittest.TestCase):
    def test_status_is_zero_and_the_dynamic_tag_signals_completion(self):
        # `HrGetUserDetails` returns the status DWORD verbatim as its HRESULT
        # before reading the blob, and waits on request vtable +0x10, which only
        # the 0x86 branch of ProcessTaggedServiceReply releases.
        payload = build_get_user_details_reply_payload(_request("Chris Hahn", _SHEET_TAGS))
        status, blob = _split_reply(payload)
        self.assertEqual(status, 0)
        self.assertTrue(blob)

    def test_handler_answers_class_1_method_2(self):
        handler = MOSABPHandler(pipe_idx=6, svc_name="MOSABP")
        packets = handler.handle_request(
            MOSABP_CLASS_AB,
            MOSABP_GET_USER_DETAILS,
            0,
            _request("Chris Hahn", _SHEET_TAGS),
            server_seq=1,
            client_ack=1,
        )
        self.assertEqual(len(packets), 1)

    def test_other_methods_are_left_unanswered(self):
        handler = MOSABPHandler(pipe_idx=6, svc_name="MOSABP")
        for msg_class, selector in (
            (MOSABP_CLASS_AB, MOSABP_UPDATE_USER_DETAILS),
            (MOSABP_CLASS_AB, 0x01),
            (0x02, MOSABP_GET_USER_DETAILS),
        ):
            with self.subTest(msg_class=msg_class, selector=selector):
                self.assertIsNone(
                    handler.handle_request(msg_class, selector, 0, b"", server_seq=1, client_ack=1)
                )


class TestMemberBlobLayout(unittest.TestCase):
    def test_count_matches_the_requested_tag_count(self):
        # A mismatch is 0x80040118 out of `FUN_7F4DD770` before any value is read.
        _status, blob = _split_reply(
            build_get_user_details_reply_payload(_request("Chris Hahn", _SHEET_TAGS))
        )
        count, _values, _pos = _parse_blob(blob, _SHEET_TAGS)
        self.assertEqual(count, len(_SHEET_TAGS))

    def test_blob_is_consumed_exactly(self):
        # Trailing or missing bytes mean a width disagreement with the client's
        # own walk, which slides every later field.
        _status, blob = _split_reply(
            build_get_user_details_reply_payload(_request("Chris Hahn", _SHEET_TAGS))
        )
        _count, _values, consumed = _parse_blob(blob, _SHEET_TAGS)
        self.assertEqual(consumed, len(blob))

    def test_string_lengths_exclude_the_terminator(self):
        # `FUN_7F4DD182` allocates cb+1 and writes the NUL itself; a counted NUL
        # would leave a stray byte inside the MAPI string.
        blob = build_member_blob(MemberProfile(member_id="abc", display_name="abc"), [0x3003001E])
        self.assertEqual(blob, struct.pack("<I", 1) + struct.pack("<I", 3) + b"abc")

    def test_every_requested_tag_gets_a_value_even_for_an_empty_profile(self):
        blob = build_member_blob(MemberProfile(member_id="nobody"), _SHEET_TAGS)
        count, values, consumed = _parse_blob(blob, _SHEET_TAGS)
        self.assertEqual(count, len(_SHEET_TAGS))
        self.assertEqual(consumed, len(blob))
        self.assertEqual(len(values), len(_SHEET_TAGS))

    def test_unmapped_tag_still_ships_a_value_of_the_right_width(self):
        # PT_SYSTIME is not a sheet field; it must still occupy its 8 bytes.
        tags = [0x3003001E, 0x60200040, 0x600D001E]
        blob = build_member_blob(MemberProfile(member_id="ab", first_name="cd"), tags)
        count, values, consumed = _parse_blob(blob, tags)
        self.assertEqual(count, 3)
        self.assertEqual(consumed, len(blob))
        self.assertEqual(values[0x60200040], 0)
        self.assertEqual(values[0x600D001E], "cd")

    def test_unserialisable_type_is_refused_here_not_on_the_wire(self):
        # PT_ERROR aborts the client's parse with 0x80040304, so it can never be
        # a "not found" marker; fail loudly at build time instead.
        with self.assertRaises(ValueError):
            build_member_blob(MemberProfile(member_id="x"), [0x3003000A])


class TestMemberLookup(unittest.TestCase):
    def test_sheet_fields_come_from_the_matching_profile(self):
        _status, blob = _split_reply(
            build_get_user_details_reply_payload(_request("Chris Hahn", _SHEET_TAGS))
        )
        _count, values, _pos = _parse_blob(blob, _SHEET_TAGS)
        profile = app_store.member.get_member("Chris Hahn")
        self.assertEqual(values[0x3003001E], profile.member_id)
        self.assertEqual(values[0x600D001E], profile.first_name)
        self.assertEqual(values[0x600E001E], profile.last_name)
        self.assertEqual(values[0x6000001E], profile.city)
        self.assertEqual(values[0x6001001E], profile.state)
        self.assertEqual(values[0x600F0003], profile.country_code)
        self.assertEqual(values[0x6003001E], profile.birth_date)
        self.assertEqual(values[0x6004001E], profile.sex)
        self.assertEqual(values[0x60110003], profile.marital_status_code)
        self.assertEqual(values[0x60100003], profile.language_code)
        self.assertEqual(values[0x6007001E], profile.interests)
        self.assertEqual(values[0x6008001E], profile.job_description)
        self.assertEqual(values[0x6009001E], profile.company_name)
        self.assertEqual(values[0x600A001E], profile.work_city)
        self.assertEqual(values[0x600B001E], profile.work_state)
        self.assertEqual(values[0x60120003], profile.work_country_code)

    def test_object_and_display_type_say_mail_user(self):
        _status, blob = _split_reply(
            build_get_user_details_reply_payload(_request("Chris Hahn", _SHEET_TAGS))
        )
        _count, values, _pos = _parse_blob(blob, _SHEET_TAGS)
        self.assertEqual(values[0x0FFE0003], 6)  # MAPI_MAILUSER
        self.assertEqual(values[0x39000003], 0)  # DT_MAILUSER
        self.assertEqual(values[0x3002001E], "MOS")

    def test_lookup_is_case_insensitive(self):
        self.assertEqual(
            app_store.member.get_member("chris hahn"),
            app_store.member.get_member("Chris Hahn"),
        )

    def test_unknown_member_still_yields_a_sheet_with_the_id(self):
        _status, blob = _split_reply(
            build_get_user_details_reply_payload(_request("Nobody At All", _SHEET_TAGS))
        )
        _count, values, _pos = _parse_blob(blob, _SHEET_TAGS)
        self.assertEqual(values[0x3003001E], "Nobody At All")
        self.assertEqual(values[0x600D001E], "")

    def test_every_bbs_author_has_a_profile(self):
        # The From box is the only key into this store, and BBSNAV puts
        # `BbsFields.author` there. An author without a profile opens a blank
        # sheet instead of the member's details.
        authors = {
            node.content.bbs.author
            for node in app_store.content.get_children("0:1")
            if node.content.bbs and node.content.bbs.author
        }
        self.assertTrue(authors)
        for author in authors:
            with self.subTest(author=author):
                self.assertEqual(app_store.member.get_member(author).first_name != "", True)


if __name__ == "__main__":
    unittest.main()
