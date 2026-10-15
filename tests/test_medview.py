"""MEDVIEW: title, cache-miss, notification and baggage selectors."""

import struct
import unittest

from server.config import (
    MEDVIEW_DATA_EDIT_CLASS,
    MEDVIEW_SELECTOR_ATTACH_SESSION,
    MEDVIEW_SELECTOR_CONVERT_HASH_TO_VA,
    MEDVIEW_SELECTOR_CONVERT_TOPIC_TO_VA,
    MEDVIEW_SELECTOR_DATA_EDIT_ADD,
    MEDVIEW_SELECTOR_DATA_EDIT_DELETE,
    MEDVIEW_SELECTOR_DATA_EDIT_GET_TICKET,
    MEDVIEW_SELECTOR_FETCH_NEARBY_TOPIC,
    MEDVIEW_SELECTOR_GET_TITLE_INFO_REMOTE,
    MEDVIEW_SELECTOR_LOAD_TOPIC_HIGHLIGHTS,
    MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE,
    MEDVIEW_SELECTOR_OPEN_TITLE,
    MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
    MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE,
    MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
    PIPE_LAST_DATA,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_PARTIAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from server.mpc import (
    build_host_block,
    parse_host_block,
)
from server.services.dirsrv import (
    get_ticket_reply,
)
from server.services.medview import MedviewHandler
from server.services.medview.handler import (
    _picture_chunk_limit,
    _widen_low_bpp_dib,
)
from server.services.medview.payload import BM0_BAGGAGE
from server.session import Session
from server.transport import parse_packet
from server.wire import decode_header_byte

from .support import (
    ADMIN,
    host_payload,
    reply_payload,
    signed_in,
)


def _handler(session=None):
    return MedviewHandler(5, "MEDVIEW", session or Session())


def _request(handler, selector, payload, *, request_id=1, msg_class=0x01):
    """Send one request and return the reply's host-block payload."""
    return reply_payload(handler.handle_request(msg_class, selector, request_id, payload, 5, 5))


def _open_title(handler, payload, *, request_id=1):
    return _request(handler, MEDVIEW_SELECTOR_OPEN_TITLE, payload, request_id=request_id)


def _subscribe(handler, notification_type, request_id):
    return handler.handle_request(
        0x01,
        MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
        request_id,
        bytes([0x01, notification_type, 0x85]),
        5,
        5,
    )


class TestMEDVIEWServiceMap(unittest.TestCase):
    def test_discovery_payload_size(self):
        handler = _handler()
        pkts = handler.build_discovery_packet(3, 3)
        self.assertIsInstance(pkts, list)
        self.assertGreaterEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)


class TestMEDVIEWHandshake(unittest.TestCase):
    def test_handshake_reply_is_nonzero_dword(self):
        handler = _handler()
        # Request: 0x01 0x01 (byte=1), 0x04 with 12 zero bytes, 0x83 recv.
        req_payload = bytes.fromhex("01 01 04 8c 00 00 20 00 06 40 00 00 09 04 00 00 83")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_ATTACH_SESSION, 0, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # Extract the host block payload from the pipe frame.
        # Layout: header byte + size_prefix (2B) + routing (2B) + host_block
        # host_block: class + selector + VLI req_id + reply_payload
        body = parsed.payload
        # Skip: header(1) + size(2) + routing(2) + class(1) + selector(1) + vli(1)
        reply_payload = body[8:]
        self.assertEqual(reply_payload[0], 0x83)  # dword tag
        validation = struct.unpack("<I", reply_payload[1:5])[0]
        self.assertNotEqual(validation, 0)
        self.assertEqual(reply_payload[5], TAG_END_STATIC)

    def test_handshake_unknown_selector_returns_none(self):
        handler = _handler()
        pkt = handler.handle_request(0x01, 0x99, 0, b"", 5, 5)
        self.assertIsNone(pkt)


class TestMEDVIEWTitleOpen(unittest.TestCase):
    # TitleOpen spec format is `:%d[%s]%d` (docs/MOSVIEW.md §5.3); on the
    # HRMOSExec(c=6) path MSN Today lands as `:2[4]0` — svcid=2, deid=4,
    # serial=0. The deid selects resources/titles/HANDBOOK.M14.
    _MSN_TODAY_REQ = (
        b"\x04\x87:2[4]0\x00"  # tag=0x04 var, len|0x80=0x87, 7-byte ASCIIZ
        b"\x03\x00\x00\x00\x00"  # cached checksum 1 = 0
        b"\x03\x00\x00\x00\x00"  # cached checksum 2 = 0
        b"\x81\x81\x83\x83\x83\x83\x83"
    )

    def _decode_reply(self, req_payload):
        handler = _handler()
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_OPEN_TITLE,
            1,
            req_payload,
            5,
            5,
        )
        self.assertIsNotNone(pkts)
        # Frame layout: header(1) + size(2) + routing(2) + class(1)
        # + selector(1) + vli(1) — reply tagged stream starts at +8.
        return reply_payload(pkts)

    def _split_body(self, reply):
        # Static prefix: 2×2 (tagged bytes) + 5×5 (tagged dwords) + 1 (0x87)
        # + 1 (0x86) = 31 bytes before the dynamic payload.
        return reply[31:]

    def _open_handler(self, req_payload=None):
        handler = _handler()
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_OPEN_TITLE,
            1,
            req_payload or self._MSN_TODAY_REQ,
            5,
            5,
        )
        self.assertIsNotNone(pkts)
        return handler, reply_payload(pkts)

    def test_title_open_reply_has_static_plus_dynamic(self):
        reply = self._decode_reply(self._MSN_TODAY_REQ)
        # Must start with 0x81 (title_id byte), nonzero value.
        self.assertEqual(reply[0], 0x81)
        self.assertNotEqual(reply[1], 0)  # title_id must be nonzero!
        # Second byte: 0x81 service_byte
        self.assertEqual(reply[2], 0x81)
        self.assertEqual(reply[3], 0x01)  # nonzero fileSystemMode selects remote HFS
        # Then 5×0x83 dwords
        pos = 4
        for _ in range(5):
            self.assertEqual(reply[pos], 0x83)
            pos += 5
        # End-static
        self.assertEqual(reply[pos], TAG_END_STATIC)
        pos += 1
        # Dynamic-complete
        self.assertEqual(reply[pos], TAG_DYNAMIC_COMPLETE_SIGNAL)

    def test_title_open_loads_m14_when_deid_has_fixture(self):
        handler, _reply = self._open_handler()
        self.assertIsNotNone(handler.loaded_m14)
        self.assertEqual(handler.loaded_m14.title, "Employee Handbook Example")
        self.assertEqual(handler.loaded_m14.home_display.topic_pos, 0xA7)
        self.assertEqual(handler.title_metadata.contents_va, 0xA7)
        self.assertEqual(handler.title_metadata.addr_base, 0)
        self.assertEqual(handler.title_metadata.topic_count, 22)

    def test_title_open_body_carries_m14_system_strings(self):
        handler, _reply = self._open_handler()
        self.assertIn(b"Employee Handbook Example\x00", handler.title_body)
        self.assertIn(
            "© 1996 Centric Development, Inc.\x00".encode("cp1252"),
            handler.title_body,
        )

    def test_sample_deids_select_the_two_compiled_m14_files(self):
        for deid, archive_name, title_name in (
            ("1000", "HANDBOOK.M14", "Employee Handbook Example"),
            ("1001", "FRANCE.M14", "France"),
            ("1002", "MVDOC.M14", "MediaView Online Documentation"),
        ):
            token = f":2[{deid}]0".encode("ascii") + b"\x00"
            request = (
                b"\x04"
                + bytes([0x80 | len(token)])
                + token
                + b"\x03\x00\x00\x00\x00"
                + b"\x03\x00\x00\x00\x00"
                + b"\x81\x81\x83\x83\x83\x83\x83"
            )
            handler, _reply = self._open_handler(request)
            self.assertIsNotNone(handler.loaded_m14)
            self.assertEqual(handler.loaded_m14.archive_name, archive_name)
            self.assertEqual(handler.loaded_m14.title, title_name)


class TestMEDVIEWOSR2TitleOpen(unittest.TestCase):
    _OPEN = (
        b"\x04\x8a:2[1000]0\x00"
        b"\x03\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00"
        b"\x03\x00\x00\x00\x00"
        b"\x81\x81" + b"\x83" * 8 + b"\x84\x85"
    )

    @staticmethod
    def _attach(handler, capabilities_size):
        request = (
            b"\x01\x01\x04"
            + bytes([0x80 | capabilities_size])
            + b"\x00" * capabilities_size
            + b"\x83"
        )
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_ATTACH_SESSION,
            0,
            request,
            5,
            5,
        )

    def test_rtm_attach_keeps_the_existing_reply_byte_for_byte(self):
        default_handler = _handler()
        default_reply = _open_title(default_handler, self._OPEN, request_id=1)

        rtm_handler = _handler()
        self._attach(rtm_handler, 12)
        rtm_reply = _open_title(rtm_handler, self._OPEN, request_id=1)

        self.assertEqual(rtm_reply, default_reply)

    def test_osr2_attach_selects_eight_dwords_and_osr2_body(self):
        handler = _handler()
        self._attach(handler, 92)
        reply = _open_title(handler, self._OPEN, request_id=1)

        self.assertEqual(reply[:4], b"\x81\x01\x81\x01")
        pos = 4
        dwords = []
        for _ in range(8):
            self.assertEqual(reply[pos], 0x83)
            dwords.append(struct.unpack_from("<I", reply, pos + 1)[0])
            pos += 5
        self.assertEqual(
            dwords[-3:],
            [
                handler.title_metadata.cache_header0,
                handler.title_metadata.cache_header1,
                0,
            ],
        )
        self.assertEqual(reply[pos], 0x84)
        title_id_size = reply[pos + 1] & 0x7F
        self.assertEqual(reply[pos + 2 : pos + 2 + title_id_size], b"1000\x00")
        pos += 2 + title_id_size
        self.assertEqual(reply[pos : pos + 2], b"\x87\x86")
        self.assertEqual(reply[pos + 2 :], handler.title_body)

        font_size = struct.unpack_from("<H", handler.title_body)[0]
        title_data = handler.title_body[font_size + 2 :]
        self.assertTrue(title_data.startswith(b"1000\x00"))
        self.assertIn(b"Employee Handbook Example\x00", title_data)

    def test_osr2_cache_hit_omits_only_the_matching_stream(self):
        handler = _handler()
        self._attach(handler, 92)
        _open_title(handler, self._OPEN, request_id=1)
        font_end = 2 + struct.unpack_from("<H", handler.title_body)[0]
        request = (
            b"\x04\x8a:2[1000]0\x00"
            + b"\x03\x00\x00\x00\x00" * 2
            + b"\x03"
            + struct.pack("<I", handler.title_metadata.cache_header0)
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x81"
            + b"\x83" * 8
            + b"\x84\x85"
        )

        reply = _open_title(handler, request, request_id=2)

        pos = 4 + 8 * 5
        self.assertEqual(reply[pos], 0x84)
        pos += 2 + (reply[pos + 1] & 0x7F)
        self.assertEqual(reply[pos : pos + 2], b"\x87\x86")
        self.assertEqual(reply[pos + 2 :], handler.title_body[font_end:])

    def test_osr2_pipe_mvpfile_opens_while_rtm_rejects_it(self):
        open_mvpfile = b"\x01\x01\x04\x89|MVPFILE\x00\x01\x02\x81\x83"

        osr2 = _handler()
        self._attach(osr2, 92)
        _open_title(osr2, self._OPEN, request_id=1)
        reply = _request(osr2, MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE, open_mvpfile, request_id=2)
        self.assertNotEqual(reply[2], 0)
        self.assertEqual(
            struct.unpack_from("<I", reply, 4)[0],
            len(osr2.baggage_map["mvpfile"]),
        )
        self.assertIn(b"[WINDOWS]\r\n", osr2.baggage_map["mvpfile"])

        rtm = _handler()
        self._attach(rtm, 12)
        _open_title(rtm, self._OPEN, request_id=1)
        self.assertEqual(
            _request(rtm, MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE, open_mvpfile, request_id=2)[2], 0
        )


class TestMEDVIEWTitleGetInfo(unittest.TestCase):
    def test_get_info_reply_size_zero(self):
        handler = _handler()
        # Request: 0x01 <title_byte>, 3× 0x03 dword, 0x83 recv.
        req_payload = bytes.fromhex(
            "01 01"
            "03 07 00 00 00"  # info_kind=7 (0x2B records)
            "03 00 00 2b 00"  # bufsize=0x002b, index=0
            "03 00 00 00 00"  # buffer_ptr=0
            "83"
        )
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_GET_TITLE_INFO_REMOTE, 2, req_payload, 5, 5
        )
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        body = parsed.payload
        reply = body[8:]
        # 0x83 <dword=0>
        self.assertEqual(reply[0], 0x83)
        size = struct.unpack("<I", reply[1:5])[0]
        self.assertEqual(size, 0)
        # 0x87 end-static
        self.assertEqual(reply[5], TAG_END_STATIC)
        # 0x86 dynamic-complete-signal
        self.assertEqual(reply[6], TAG_DYNAMIC_COMPLETE_SIGNAL)


class TestMEDVIEWDataEdit(unittest.TestCase):
    @staticmethod
    def _add_request():
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 271)
        properties = struct.pack("<IH", 6, 0)
        return (
            b"\x04"
            + bytes([0x80 | len(ticket)])
            + ticket
            + b"\x03\x06\x00\x00\x00"
            + b"\x04"
            + bytes([0x80 | len(record_id)])
            + record_id
            + b"\x02\xff\xff"
            + b"\x04"
            + bytes([0x80 | len(properties)])
            + properties
            + b"\x83\x83"
        )

    @staticmethod
    def _delete_request():
        return (
            b"\x04\x82\x02\x00"
            + b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + struct.pack("<II", 4098, 0)
            + b"\x02\xff\xff"
            + b"\x83\x83"
        )

    def test_data_edit_get_ticket_is_not_a_cache_miss(self):
        handler = _handler(signed_in(ADMIN))
        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_SELECTOR_DATA_EDIT_GET_TICKET,
            0,
            b"\x83\x85",
            5,
            5,
        )

        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, get_ticket_reply(handler.session))
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x87\x86\x02\x00")

    def test_data_edit_add_does_not_dispatch_as_validate_title(self):
        handler = _handler(signed_in(ADMIN))
        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_SELECTOR_DATA_EDIT_ADD,
            1,
            self._add_request(),
            5,
            5,
        )

        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87")

    def test_data_edit_delete_does_not_dispatch_as_open_title(self):
        handler = _handler(signed_in(ADMIN))

        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_SELECTOR_DATA_EDIT_DELETE,
            1,
            self._delete_request(),
            5,
            5,
        )

        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87")

    def test_data_edit_delete_refuses_anonymous_writes(self):
        handler = _handler()
        pkts = handler.handle_request(
            MEDVIEW_DATA_EDIT_CLASS,
            MEDVIEW_SELECTOR_DATA_EDIT_DELETE,
            1,
            self._delete_request(),
            5,
            5,
        )

        reply = reply_payload(pkts)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)


class TestMEDVIEWCacheMissRpcs(unittest.TestCase):
    """Selectors 0x05 / 0x06 / 0x07 / 0x15 / 0x16 ack synchronously and
    push the resolved entry on the matching notification iterator."""

    def test_cache_miss_bare_ack_without_subscription(self):
        # Without a matching subscription the handler ships only the
        # synchronous bare ack — the push has no iterator to ride.
        handler = _handler()
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        for selector in (
            MEDVIEW_SELECTOR_CONVERT_HASH_TO_VA,
            MEDVIEW_SELECTOR_CONVERT_TOPIC_TO_VA,
            MEDVIEW_SELECTOR_FETCH_NEARBY_TOPIC,
        ):
            pkts = handler.handle_request(0x01, selector, 9, req_payload, 5, 5)
            self.assertIsNotNone(pkts, f"selector 0x{selector:02x} returned None")
            self.assertEqual(len(pkts), 1)
            reply = reply_payload(pkts)
            self.assertEqual(
                reply,
                bytes([TAG_END_STATIC]),
                f"selector 0x{selector:02x} ack mismatch",
            )

    def test_unknown_hash_pushes_type3_frame_with_va_zero(self):
        handler = _handler()
        _subscribe(handler, 3, 2)
        key = 0xCAFEBABE
        hash_req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_CONVERT_HASH_TO_VA,
            9,
            hash_req,
            5,
            5,
        )
        self.assertGreaterEqual(len(pkts), 2)
        push = host_payload(pkts[1])
        self.assertEqual(push[0], 0x85)
        # type-3 op-code 4 frame: u16 op=4, u16 len=18, u8 title, u8 kind,
        # u32 key, u32 va, u32 addr.
        self.assertEqual(
            struct.unpack("<HHBBIII", push[1:19]),
            (4, 18, 0x01, 1, key, 0, 0),
        )

    def test_empty_context_hash_resolves_to_m14_contents(self):
        for deid, expected_va, expected_addr in (
            ("4", 0xA7, 0),
            ("1001", 0xC930, 0x18699),
        ):
            handler = _handler()
            token = f":2[{deid}]0".encode("ascii") + b"\x00"
            open_req = (
                b"\x04"
                + bytes([0x80 | len(token)])
                + token
                + b"\x03\x00\x00\x00\x00"
                + b"\x03\x00\x00\x00\x00"
                + b"\x81\x81\x83\x83\x83\x83\x83"
            )
            handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_OPEN_TITLE,
                1,
                open_req,
                5,
                5,
            )
            _subscribe(handler, 3, 2)
            hash_req = b"\x01\x01\x03\x01\x00\x00\x00"
            pkts = handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_CONVERT_HASH_TO_VA,
                9,
                hash_req,
                5,
                5,
            )
            push = host_payload(pkts[1])
            self.assertEqual(
                struct.unpack("<HHBBIII", push[1:19]),
                (4, 18, 0x01, 1, 1, expected_va, expected_addr),
            )

    def test_m14_link_hash_resolves_through_context_btree(self):
        handler = _handler()
        token = b":2[1001]0\x00"
        open_req = (
            b"\x04"
            + bytes([0x80 | len(token)])
            + token
            + b"\x03\x00\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_OPEN_TITLE,
            1,
            open_req,
            5,
            5,
        )
        _subscribe(handler, 3, 2)
        key = 0x6348
        hash_req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_CONVERT_HASH_TO_VA,
            9,
            hash_req,
            5,
            5,
        )
        push = host_payload(pkts[1])
        self.assertEqual(
            struct.unpack("<HHBBIII", push[1:19]),
            (4, 18, 0x01, 1, key, 0x4696, 0x8338),
        )

    def test_convert_topic_pushes_type3_kind_0(self):
        handler = _handler()
        _subscribe(handler, 3, 2)
        key = 0x00000005
        req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_CONVERT_TOPIC_TO_VA,
            10,
            req,
            5,
            5,
        )
        push = host_payload(pkts[1])
        self.assertEqual(
            struct.unpack("<HHBBIII", push[1:19]),
            (4, 18, 0x01, 0, key, 0, 0),
        )

    def test_va_resolve_pushes_empty_case1_bf_chunk(self):
        # Selector 0x15 pushes opcode 0xBF on the type-0 iterator —
        # that's the record HfcCache_InsertOrdered writes into HfcNear's
        # per-title cache at title+4, unblocking the 30-s retry loop.
        # No loaded title with captions → empty case-1 ("skip empty row").
        handler = _handler()
        _subscribe(handler, 0, 3)
        key = 0x12345678
        req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_FETCH_NEARBY_TOPIC,
            11,
            req,
            5,
            5,
        )
        push = host_payload(pkts[1])
        self.assertEqual(push[0], 0x85)
        self.assertEqual(push[1], 0xBF)
        self.assertEqual(push[2], 0x01)
        self.assertEqual(struct.unpack("<I", push[13:17])[0], key)
        self.assertEqual(push[1 + 0x2A], 0x01)

    def test_va_resolve_pushes_native_m14_control_stream(self):
        handler = _handler()
        open_req = (
            b"\x04\x87:2[4]0\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(0x01, MEDVIEW_SELECTOR_OPEN_TITLE, 1, open_req, 5, 5)
        self.assertIsNotNone(handler.loaded_m14)
        _subscribe(handler, 0, 3)
        key = handler.loaded_m14.home_display.topic_pos
        req = b"\x01\x01\x03" + struct.pack("<I", key)
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_FETCH_NEARBY_TOPIC,
            11,
            req,
            5,
            5,
        )
        push = host_payload(pkts[1])
        self.assertEqual(push[0], 0x85)
        self.assertEqual(push[1], 0xBF)
        self.assertEqual(push[1 + 0x2A], 0x20)
        self.assertIn(b"MVIMG,MVIMAGE, !homed.SHG\x00", push)

    def test_fetch_adjacent_topic_pushes_type0_a5(self):
        from server.config import MEDVIEW_SELECTOR_FETCH_ADJACENT_TOPIC

        handler = _handler()
        _subscribe(handler, 0, 1)
        req_payload = bytes.fromhex("01 01 03 00 00 00 00 01 00")
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_FETCH_ADJACENT_TOPIC,
            11,
            req_payload,
            5,
            5,
        )
        self.assertGreaterEqual(len(pkts), 2)
        sync = reply_payload(pkts)
        self.assertEqual(sync, bytes([TAG_END_STATIC]))
        push = host_payload(pkts[1])
        self.assertEqual(push[0], 0x85)
        self.assertEqual(push[1], 0xA5)

    def test_m14_topic_chunks_carry_pane_bounds_and_adjacent_records(self):
        from server.config import MEDVIEW_SELECTOR_FETCH_ADJACENT_TOPIC

        handler = _handler()
        token = b":2[1001]0\x00"
        open_req = (
            b"\x04" + bytes([0x80 | len(token)]) + token + b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(0x01, MEDVIEW_SELECTOR_OPEN_TITLE, 1, open_req, 5, 5)
        _subscribe(handler, 0, 1)

        req_payload = b"\x01\x01\x03" + struct.pack("<I", 0x4696) + b"\x01\x01"
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_FETCH_ADJACENT_TOPIC,
            11,
            req_payload,
            5,
            5,
        )
        push = host_payload(pkts[1])
        chunk = push[1:]
        name_size = struct.unpack_from("<H", chunk, 2)[0]
        self.assertEqual(chunk[0], 0xBF)
        # 0x4696 opens its topic, so its leading token is the adjacent
        # 0x4695 rather than a shared end-of-content sentinel.
        self.assertEqual(
            struct.unpack_from("<III", chunk, 8),
            (0x4695, 0x4696, 0x46D3),
        )
        self.assertEqual(
            struct.unpack_from("<II", chunk, 4 + name_size + 0x14),
            (0x4696, 0x46D3),
        )

        req_payload = b"\x01\x01\x03" + struct.pack("<I", 0x46D3) + b"\x01\x01"
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_FETCH_ADJACENT_TOPIC,
            12,
            req_payload,
            5,
            5,
        )
        push = host_payload(pkts[1])
        chunk = push[1:]
        self.assertEqual(chunk[0], 0xBF)
        self.assertEqual(
            struct.unpack_from("<III", chunk, 8),
            (0x4696, 0x46D3, 0x4968),
        )
        self.assertIn(b"The Cathars were followers", chunk)

    def test_load_topic_highlights_returns_empty_dynbytes(self):
        # Selector 0x10 (LoadTopicHighlights) returns synchronous
        # `dynbytes` per spec — NOT ack-only like the async-cache trio
        # above. Empty result = 8-byte opaque header + zero highlight
        # count = 12 bytes total. Static section: bare `0x87 0x86`
        # (no leading scalar) so the recv loop knows the dynamic body
        # follows.
        handler = _handler()
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_LOAD_TOPIC_HIGHLIGHTS,
            9,
            req_payload,
            5,
            5,
        )
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        # `0x87 0x86 <12 zero bytes>`
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], TAG_DYNAMIC_COMPLETE_SIGNAL)
        self.assertEqual(reply[2:14], b"\x00" * 12)


class TestMEDVIEWTitlePreNotify(unittest.TestCase):
    @staticmethod
    def _subscriber_state_request(notification_type, enabled):
        state_payload = bytes([notification_type]) + struct.pack(
            "<I",
            int(enabled),
        )
        return b"\x01\x00\x02\x07\x00\x04" + bytes([0x80 | len(state_payload)]) + state_payload

    @staticmethod
    def _picture_start_request(
        *,
        transfer_id,
        name="albi.bmp",
        current_size=0,
        mode=0,
        state_flags=0,
    ):
        start_payload = (
            bytes([1, mode])
            + struct.pack("<II", current_size, transfer_id)
            + bytes([state_flags])
            + name.encode("ascii")
            + b"\x00"
        )
        return (
            b"\x01\x01"
            b"\x02\x04\x00"
            b"\x04" + bytes([0x80 | len(start_payload)]) + start_payload + b"\x83"
        )

    def test_pre_notify_reply_is_end_static_only(self):
        # TitlePreNotify binds no receive-side fields. The synchronous
        # response is only the end-of-static acknowledgement.
        handler = _handler()
        # Request: 0x01 0x00, 0x02 0x0a 0x00 (opcode=10), 0x04 with 6 bytes.
        req_payload = bytes.fromhex("01 00 02 0a 00 04 86 00 00 00 00 00 00")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE, 3, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_opcode_8_heartbeat_returns_bare_ack(self):
        # Opcode 0x08 SendClientStatus per spec is the keepalive pulse
        # MVTTL14C fires every >5s while async wait loops are active.
        # It declares no receive fields and uses the same bare ack.
        # (Use a small req_id so the VLI-encoded request_id fits in 1
        # byte — the `[8:]` slice assumes that.)
        handler = _handler()
        # Request: 0x01 0x01, 0x02 0x08 0x00 (opcode=8), 0x04 0x81 0x91 (1-byte heartbeat).
        req_payload = bytes.fromhex("01 01 02 08 00 04 81 91")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE, 7, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_picture_start_pushes_status_then_file_bytes(self):
        handler = _handler()
        picture = b"BM" + b"\x00" * 12 + struct.pack("<Iii", 40, 113, 95) + b"\x00" * 12
        handler.baggage_map = {"albi.bmp": picture}
        _subscribe(handler, 3, 3)
        _subscribe(handler, 4, 4)

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            5,
            self._picture_start_request(transfer_id=0x12345678),
            10,
            5,
        )
        self.assertEqual(len(pkts), 3)

        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

        status_push = host_payload(pkts[1])
        self.assertEqual(status_push[0], TAG_DYNAMIC_PARTIAL)
        self.assertEqual(
            struct.unpack("<HHIHIIIII", status_push[1:31]),
            (1, 30, len(picture), 1, 113, 95, 0, 0, 0x12345678),
        )

        chunk_push = host_payload(pkts[2])
        self.assertEqual(chunk_push[0], TAG_DYNAMIC_PARTIAL)
        self.assertEqual(
            struct.unpack("<HHII", chunk_push[1:13]),
            (3, 12 + len(picture), 0x12345678, 0),
        )
        self.assertEqual(chunk_push[13:], picture)

    def test_picture_chunks_wait_for_type4_subscription(self):
        handler = _handler()
        picture = b"BMresume-data"
        handler.baggage_map = {"albi.bmp": picture}
        _subscribe(handler, 3, 3)

        start_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            5,
            self._picture_start_request(
                transfer_id=7,
                current_size=2,
                mode=1,
            ),
            10,
            5,
        )
        self.assertEqual(len(start_pkts), 2)
        status_push = host_payload(start_pkts[1])
        self.assertEqual(
            struct.unpack("<HHIHIIIII", status_push[1:31]),
            (1, 30, len(picture), 0, 0, 0, 0, 0, 7),
        )

        subscribe_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
            4,
            b"\x01\x04\x85",
            20,
            5,
        )
        self.assertEqual(len(subscribe_pkts), 2)
        chunk_push = host_payload(subscribe_pkts[1])
        self.assertEqual(
            struct.unpack("<HHII", chunk_push[1:13]),
            (3, 12 + len(picture) - 2, 7, 2),
        )
        self.assertEqual(chunk_push[13:], picture[2:])

    def test_dib_first_chunk_stops_on_bfoffbits(self):
        # MVPR14N!MVPicture_PlainBmpDecodeIncremental @ 0x7E866953 builds
        # the HPALETTE on the first decode pass that makes strictly more
        # than bfOffBits bytes newly available, undersizing the LOGPALETTE
        # by its 4-byte header. Ending chunk 1 on bfOffBits fails that
        # guard; every later pass fails the companion consumed < 0x36 one.
        def dib(entries: int, total: int) -> bytes:
            pixels = 0x36 + entries * 4
            return (
                b"BM"
                + struct.pack("<IHHI", total, 0, 0, pixels)
                + struct.pack("<IiiHHII", 40, 8, 8, 1, 8, 0, 0)
                + b"\x00" * 16
                + b"\xaa" * (pixels - 0x36)
                + b"\x11" * (total - pixels)
            )

        # A real 8bpp DIB: 256 entries, pixels at 1078.
        eight_bpp = dib(256, 12100)
        self.assertEqual(_picture_chunk_limit(eight_bpp, 0), 1078)
        self.assertEqual(_picture_chunk_limit(eight_bpp, 1078), 0x3F00)

        # Same rule, sized to stay inside one transport fragment so the
        # wire assertions below do not have to reassemble.
        pixel_offset = 0x36 + 16 * 4
        picture = dib(16, 400)
        self.assertEqual(len(picture), 400)

        handler = _handler()
        handler.baggage_map = {"albi.bmp": picture}
        _subscribe(handler, 3, 3)
        _subscribe(handler, 4, 4)

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            5,
            self._picture_start_request(transfer_id=7, mode=0),
            10,
            5,
        )
        chunks = [
            host_payload(p)
            for p in pkts
            if parse_packet(p[:-1]).payload[8:9] == b"\x85"
            and parse_packet(p[:-1]).payload[9:11] == struct.pack("<H", 3)
        ]
        self.assertEqual(len(chunks), 2)
        self.assertEqual(
            struct.unpack("<HHII", chunks[0][1:13]),
            (3, 12 + pixel_offset, 7, 0),
        )
        self.assertEqual(chunks[0][13:], picture[:pixel_offset])
        self.assertEqual(
            struct.unpack("<HHII", chunks[1][1:13]),
            (3, 12 + len(picture) - pixel_offset, 7, pixel_offset),
        )
        self.assertEqual(chunks[1][13:], picture[pixel_offset:])

    def test_low_bpp_dibs_are_reindexed_to_eight_bits(self):
        # A 4bpp DIB puts bfOffBits at 118, below the 400 bytes
        # MVPicture_SelectDecoderByMagic @ 0x7E865815 wants before it
        # creates the decoder, so no chunk boundary can keep the palette
        # build from running. Re-indexing to 8bpp moves bfOffBits to 1078.
        palette = b"".join(bytes((index * 16, index * 8, index * 4, 0)) for index in range(16))
        rows = [[(x + y) % 16 for x in range(5)] for y in range(3)]
        packed = b"".join(
            bytes(
                (row[x] << 4) | (row[x + 1] if x + 1 < len(row) else 0) for x in range(0, 6, 2)
            ).ljust(4, b"\x00")
            for row in rows
        )
        source = (
            b"BM"
            + struct.pack("<IHHI", 118 + len(packed), 0, 0, 118)
            + struct.pack("<IiiHHII", 40, 5, 3, 1, 4, 0, 0)
            + b"\x00" * 16
            + palette
            + packed
        )

        widened = _widen_low_bpp_dib(source)
        self.assertEqual(
            struct.unpack_from("<IHHI", widened, 2),
            (len(widened), 0, 0, 0x36 + 256 * 4),
        )
        self.assertEqual(
            struct.unpack_from("<iiHHII", widened, 18),
            (5, 3, 1, 8, 0, 8 * 3),
        )
        self.assertEqual(_picture_chunk_limit(widened, 0), 0x36 + 256 * 4)

        table = widened[0x36 : 0x36 + 256 * 4]
        self.assertEqual(table[: len(palette)], palette)
        self.assertEqual(table[len(palette) :], bytes(256 * 4 - len(palette)))
        for y, row in enumerate(rows):
            line = widened[0x36 + 256 * 4 + y * 8 :][: len(row)]
            self.assertEqual(list(line), row)

        # 8bpp and non-DIB payloads pass through untouched.
        eight_bpp = (
            b"BM"
            + struct.pack("<IHHI", 0x36 + 256 * 4 + 4, 0, 0, 0x36 + 256 * 4)
            + struct.pack("<IiiHHII", 40, 4, 1, 1, 8, 0, 0)
            + b"\x00" * 16
            + bytes(256 * 4)
            + b"\x01\x02\x03\x04"
        )
        self.assertIs(_widen_low_bpp_dib(eight_bpp), eight_bpp)
        self.assertIs(_widen_low_bpp_dib(b"lp\x01\x00shg"), b"lp\x01\x00shg")

    def test_open_title_widens_the_titles_low_bpp_baggage(self):
        handler = _handler()
        _open_title(handler, TestMEDVIEWOSR2TitleOpen._OPEN, request_id=1)

        # HANDBOOK.M14 authors mail.bmp and smokes.bmp at 4bpp.
        for name in ("mail.bmp", "smokes.bmp"):
            served = handler.baggage_map[name]
            self.assertEqual(struct.unpack_from("<H", served, 28)[0], 8, name)
            self.assertEqual(struct.unpack_from("<I", served, 10)[0], 0x36 + 256 * 4, name)
        # An 8bpp neighbour is served exactly as authored.
        self.assertEqual(
            handler.baggage_map["lion.bmp"],
            handler.loaded_m14.baggage_map()["lion.bmp"],
        )

    def test_reset_mode_start_on_valid_object_sends_status_only(self):
        # The client's transfer-teardown pass: mode 1 (subscriber reset) with
        # stateFlags bit 0 (object already valid). It reports currentSize 0 but
        # already holds the finished bytes, so re-pushing them writes a second
        # copy into a buffer it has finished with. Status record only.
        handler = _handler()
        picture = b"BMalready-delivered"
        handler.baggage_map = {"albi.bmp": picture}
        _subscribe(handler, 3, 3)
        _subscribe(handler, 4, 4)

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            5,
            self._picture_start_request(
                transfer_id=7,
                mode=1,
                state_flags=0x01,
            ),
            10,
            5,
        )
        # Reply + one type-3 status push, and no type-4 chunk push.
        self.assertEqual(len(pkts), 2)
        status_push = host_payload(pkts[1])
        self.assertEqual(
            struct.unpack("<HHIHIIIII", status_push[1:31]),
            (1, 30, len(picture), 0, 0, 0, 0, 0, 7),
        )
        self.assertEqual(handler._pending_picture_transfers, {})

    def test_reset_mode_holds_chunks_until_subscriber_reenabled(self):
        # mode 1 on a not-yet-valid object still needs the bytes, but the
        # type-4 subscriber is going down. Hold them until opcode 0x07 reports
        # the stream enabled again.
        handler = _handler()
        picture = b"BMheld-until-enabled"
        handler.baggage_map = {"albi.bmp": picture}
        _subscribe(handler, 3, 3)
        _subscribe(handler, 4, 4)

        start_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            5,
            self._picture_start_request(transfer_id=7, mode=1),
            10,
            5,
        )
        self.assertEqual(len(start_pkts), 2)
        self.assertIn(7, handler._pending_picture_transfers)

        # The client's own disable report must not release them either.
        disable_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            6,
            self._subscriber_state_request(4, False),
            20,
            5,
        )
        self.assertEqual(len(disable_pkts), 1)

        enable_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            7,
            self._subscriber_state_request(4, True),
            30,
            5,
        )
        self.assertEqual(len(enable_pkts), 2)
        chunk_push = host_payload(enable_pkts[1])
        self.assertEqual(
            struct.unpack("<HHII", chunk_push[1:13]),
            (3, 12 + len(picture), 7, 0),
        )
        self.assertEqual(chunk_push[13:], picture)
        self.assertEqual(handler._pending_picture_transfers, {})

    def test_online_start_after_disable_report_holds_chunks(self):
        # Once the client reports type 4 disabled, an online-mode start must
        # not push into the dead stream.
        handler = _handler()
        picture = b"BMno-live-stream"
        handler.baggage_map = {"albi.bmp": picture}
        _subscribe(handler, 3, 3)
        _subscribe(handler, 4, 4)
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            5,
            self._subscriber_state_request(4, False),
            10,
            5,
        )

        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_PRE_NOTIFY_TITLE,
            6,
            self._picture_start_request(transfer_id=7, mode=0),
            20,
            5,
        )
        self.assertEqual(len(pkts), 2)
        self.assertIn(7, handler._pending_picture_transfers)


class TestMEDVIEWSubscribeNotification(unittest.TestCase):
    def test_subscribe_reply_per_notification_type(self):
        # Wire-observed request: `01 <type> 85` (0x85 = dynamic-recv).
        # All 5 types reply `0x87 0x88` (iterator stream-end).  0x88
        # creates the dynamicReplyState in MPCCL!ProcessTaggedServiceReply,
        # making m_pMoreDatRef non-NULL — the master-flag check at
        # MVTTL14C 0x7E844FA7 (`MOV [ESI+0x44], 0x1` gated on
        # `*[ESI+0x28] != 0` AND HRESULT >= 0) passes for every slot.
        # Using 0x86 instead would fire SignalRequestCompletion which
        # sets request +0x18=1, suppressing ResetEvent in WaitForMessage
        # and causing a ~30%-CPU MsgWaitForSingleObject spin per request.
        handler = _handler()
        for notification_type in range(5):
            req_payload = bytes([0x01, notification_type, 0x85])
            pkts = handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
                notification_type,
                req_payload,
                5,
                5,
            )
            self.assertIsNotNone(pkts)
            reply = reply_payload(pkts)
            self.assertEqual(reply, bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]))


class TestMEDVIEWOneway(unittest.TestCase):
    def test_oneway_continuation_returns_none(self):
        handler = _handler()
        # class=0xE6 → one-way continuation, no reply expected.
        pkt = handler.handle_request(0xE6, 0x01, 0, b"\x00" * 16, 5, 5)
        self.assertIsNone(pkt)


class TestMEDVIEWTitleService(unittest.TestCase):
    """Spec class TitleService — selectors 0x00, 0x02, 0x04 (excludes
    0x01 OpenTitle and 0x03 GetTitleInfoRemote, which have dedicated
    test classes above)."""

    def _open_title(self, handler):
        # OpenTitle registers the (single) title slot so subsequent
        # ValidateTitle and CloseTitle assertions pass. Title token bytes
        # are ignored — the handler always ships the same hardcoded body.
        req = (
            b"\x04\x84:2[]0\x00\x03\x00\x00\x00\x00\x03\x00\x00\x00\x00\x81\x81\x83\x83\x83\x83\x83"
        )
        from server.config import MEDVIEW_SELECTOR_OPEN_TITLE

        handler.handle_request(0x01, MEDVIEW_SELECTOR_OPEN_TITLE, 1, req, 5, 5)

    def test_validate_title_returns_zero_when_no_title_open(self):
        from server.config import MEDVIEW_SELECTOR_VALIDATE_TITLE

        handler = _handler()
        req_payload = bytes.fromhex("01 01 81")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_VALIDATE_TITLE, 1, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        # 0x81 <byte=0> 0x87
        self.assertEqual(reply, bytes([0x81, 0x00, TAG_END_STATIC]))

    def test_validate_title_returns_nonzero_after_open(self):
        from server.config import MEDVIEW_SELECTOR_VALIDATE_TITLE

        handler = _handler()
        self._open_title(handler)
        req_payload = bytes.fromhex("01 01 81")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_VALIDATE_TITLE, 2, req_payload, 5, 5)
        reply = reply_payload(pkts)
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x01)  # is_valid != 0
        self.assertEqual(reply[2], TAG_END_STATIC)

    def test_close_title_acks(self):
        from server.config import MEDVIEW_SELECTOR_CLOSE_TITLE

        handler = _handler()
        self._open_title(handler)
        req_payload = bytes.fromhex("01 01")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_CLOSE_TITLE, 3, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_query_topics_returns_empty_session(self):
        from server.config import MEDVIEW_SELECTOR_QUERY_TOPICS

        handler = _handler()
        # Minimal request: titleSlot, queryClass, primaryText, queryFlags=0,
        # queryMode. We only care that the handler survives and emits the
        # documented static fields.
        req_payload = (
            bytes.fromhex("01 01")
            + bytes.fromhex("02 00 00")
            + b"\x04\x82query\x00"
            + bytes.fromhex("01 00")
            + bytes.fromhex("02 00 00")
        )
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_QUERY_TOPICS, 4, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        # 0x81 <highlightContext=0> 0x83 <logicalCount=0> 0x83 <secondary=0> 0x87 0x86
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], 0x83)
        self.assertEqual(struct.unpack("<I", reply[3:7])[0], 0)
        self.assertEqual(reply[7], 0x83)
        self.assertEqual(struct.unpack("<I", reply[8:12])[0], 0)
        self.assertEqual(reply[12], TAG_END_STATIC)
        self.assertEqual(reply[13], TAG_DYNAMIC_COMPLETE_SIGNAL)


class TestMEDVIEWWordWheelService(unittest.TestCase):
    """Spec class WordWheelService — selectors 0x08–0x0F. No word wheel
    is synthesized today; replies are empty/zero-result shapes that
    let the wrapper's recv loop decode cleanly."""

    def test_open_word_wheel_empty_session(self):
        from server.config import MEDVIEW_SELECTOR_OPEN_WORD_WHEEL

        handler = _handler()
        req_payload = bytes.fromhex("01 01") + b"\x04\x82wheel\x00" + bytes.fromhex("81 83")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_OPEN_WORD_WHEEL, 1, req_payload, 5, 5)
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        # 0x81 <wheel_id=0> 0x83 <count=0> 0x87
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], 0x83)
        self.assertEqual(struct.unpack("<I", reply[3:7])[0], 0)
        self.assertEqual(reply[7], TAG_END_STATIC)

    def test_query_word_wheel_zero_status(self):
        from server.config import MEDVIEW_SELECTOR_QUERY_WORD_WHEEL

        handler = _handler()
        req_payload = bytes.fromhex("01 01 02 00 00") + b"\x04\x81q\x00" + bytes.fromhex("82")
        pkts = handler.handle_request(0x01, MEDVIEW_SELECTOR_QUERY_WORD_WHEEL, 1, req_payload, 5, 5)
        reply = reply_payload(pkts)
        # 0x82 <word=0> 0x87
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)
        self.assertEqual(reply[3], TAG_END_STATIC)

    def test_close_word_wheel_acks(self):
        from server.config import MEDVIEW_SELECTOR_CLOSE_WORD_WHEEL

        handler = _handler()
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_CLOSE_WORD_WHEEL, 1, bytes.fromhex("01 00"), 5, 5
        )
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_count_key_matches_zero(self):
        from server.config import MEDVIEW_SELECTOR_COUNT_KEY_MATCHES

        handler = _handler()
        req_payload = bytes.fromhex("01 00") + b"\x04\x81k\x00" + bytes.fromhex("82")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_COUNT_KEY_MATCHES, 1, req_payload, 5, 5
        )
        reply = reply_payload(pkts)
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)


class TestMEDVIEWAddressHighlightService(unittest.TestCase):
    """Spec class AddressHighlightService — selectors 0x05, 0x11, 0x12,
    0x13 (excludes 0x06/0x07 cache-miss async + 0x10 highlight blob,
    covered above)."""

    def test_convert_address_to_va_acks_then_pushes(self):
        from server.config import MEDVIEW_SELECTOR_CONVERT_ADDRESS_TO_VA

        handler = _handler()
        req_payload = bytes.fromhex("01 01 03 be ba fe ca")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_CONVERT_ADDRESS_TO_VA, 1, req_payload, 5, 5
        )
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_find_highlight_address_zero(self):
        from server.config import MEDVIEW_SELECTOR_FIND_HIGHLIGHT_ADDRESS

        handler = _handler()
        req_payload = bytes.fromhex("01 00 03 11 11 11 11 03 22 22 22 22")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_FIND_HIGHLIGHT_ADDRESS, 1, req_payload, 5, 5
        )
        reply = reply_payload(pkts)
        self.assertEqual(reply[0], 0x83)
        self.assertEqual(struct.unpack("<I", reply[1:5])[0], 0)
        self.assertEqual(reply[5], TAG_END_STATIC)

    def test_release_highlight_context_acks(self):
        from server.config import MEDVIEW_SELECTOR_RELEASE_HIGHLIGHT_CONTEXT

        handler = _handler()
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_RELEASE_HIGHLIGHT_CONTEXT, 1, bytes.fromhex("01 01"), 5, 5
        )
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))

    def test_refresh_highlight_address_acks(self):
        from server.config import MEDVIEW_SELECTOR_REFRESH_HIGHLIGHT_ADDRESS

        handler = _handler()
        req_payload = bytes.fromhex("01 01 03 01 00 00 00")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_REFRESH_HIGHLIGHT_ADDRESS, 1, req_payload, 5, 5
        )
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))


class TestMEDVIEWSessionService(unittest.TestCase):
    """Spec class SessionService — selectors 0x17, 0x18, 0x1F. The
    existing TestMEDVIEWHandshake / TestMEDVIEWSubscribeNotification
    cover 0x1F and 0x17; this class covers the new 0x18."""

    def test_unsubscribe_acks_and_drops_state(self):
        from server.config import (
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
            MEDVIEW_SELECTOR_UNSUBSCRIBE_NOTIFICATIONS,
        )

        handler = _handler()
        # First subscribe to type 0 so there's state to drop.
        sub_payload = bytes.fromhex("01 00 85")
        handler.handle_request(0x01, MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS, 1, sub_payload, 5, 5)
        self.assertIn(0, handler._subscriptions)
        # Then unsubscribe.
        unsub_payload = bytes.fromhex("01 00")
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_UNSUBSCRIBE_NOTIFICATIONS, 2, unsub_payload, 5, 5
        )
        self.assertIsNotNone(pkts)
        reply = reply_payload(pkts)
        self.assertEqual(reply, bytes([TAG_END_STATIC]))
        self.assertNotIn(0, handler._subscriptions)

    def test_iterator_cancel_clears_subscription_state(self):
        """`handle_iterator_cancel(class, sel, req_id)` drops the one
        subscription whose `(class, req_id)` matches and leaves the rest."""
        from server.config import MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS

        handler = _handler()
        # Subscribe types 0..4 with distinct req_ids 1..5.
        for n_type, req_id in enumerate(range(1, 6)):
            sub_payload = bytes([0x01, n_type, 0x85])
            handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
                req_id,
                sub_payload,
                5,
                5,
            )
        self.assertEqual(set(handler._subscriptions.keys()), {0, 1, 2, 3, 4})

        # Cancel the type=2 iterator (req_id=3).
        handler.handle_iterator_cancel(0x01, MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS, 3)
        self.assertNotIn(2, handler._subscriptions)
        self.assertEqual(set(handler._subscriptions.keys()), {0, 1, 3, 4})

    def test_iterator_cancel_with_no_subscription_is_idempotent(self):
        from server.config import MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS

        handler = _handler()
        # No state, no exception.
        handler.handle_iterator_cancel(0x01, MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS, 42)
        self.assertEqual(handler._subscriptions, {})


class TestConnectionIteratorCancelDispatch(unittest.TestCase):
    """Connection-layer routing of the MPCCL iterator-cancel frame.

    Drives `ConnectionState._handle_service_data` directly with a fake
    socket so the cancel branch is exercised end-to-end: detect → handler
    hook → wire ack.  See `docs/MEDVIEW.md` §6d.0.
    """

    PIPE_IDX = 4

    class _FakeSocket:
        def __init__(self):
            self.sent = bytearray()

        def sendall(self, data):
            self.sent.extend(data)

        def close(self):
            pass

    def _make_conn(self):
        from server.config import MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS
        from server.connection import ConnectionState

        sock = self._FakeSocket()
        conn = ConnectionState(sock)
        handler = MedviewHandler(self.PIPE_IDX, "MEDVIEW", Session())
        # Seed 5 subscriptions matching the engine's `MVAsyncNotifyDispatch`
        # slot allocation: types 0..4 with req_ids 1..5.
        for n_type, req_id in enumerate(range(1, 6)):
            sub_payload = bytes([0x01, n_type, 0x85])
            handler.handle_request(
                0x01,
                MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS,
                req_id,
                sub_payload,
                5,
                5,
            )
        conn.services[self.PIPE_IDX] = handler
        return conn, handler, sock

    def _build_cancel_frame(self, msg_class, selector, req_id):
        """Build the raw host-block bytes the connection layer receives."""

        return build_host_block(msg_class, selector, req_id, b"\x0f")

    def _parse_wire(self, raw):
        """Strip the leading ACK packet and return the host-block payload
        of the first DATA packet (without pipe-routing prefix or VLI)."""
        from server.config import PACKET_TERMINATOR
        from server.mpc import parse_host_block
        from server.pipe import parse_pipe_frames

        packets = []
        buf = bytearray()
        for b in raw:
            if b == PACKET_TERMINATOR:
                packets.append(parse_packet(bytes(buf)))
                buf.clear()
            else:
                buf.append(b)
        data_pkts = [p for p in packets if p is not None and p.type == "DATA"]
        self.assertTrue(data_pkts, "no DATA packet produced")
        frames = parse_pipe_frames(data_pkts[0].payload)
        self.assertEqual(len(frames), 1)
        # frame.content = pipe_idx(u16) + host_block
        hb = parse_host_block(frames[0].content[2:])
        self.assertIsNotNone(hb)
        return hb

    def test_cancel_frame_emits_canonical_ack_and_clears_state(self):
        from server.config import MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS
        from server.mpc import ITERATOR_CANCEL_ACK

        conn, handler, sock = self._make_conn()
        # Cancel the type=2 iterator (req_id=3 from the seed loop).
        frame = self._build_cancel_frame(0x01, MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS, 3)

        with (
            self.assertLogs("server.services.medview.handler", level="INFO") as medview_logs,
            self.assertLogs("server.connection", level="INFO") as conn_logs,
        ):
            conn._handle_service_data(self.PIPE_IDX, frame)

        # (a) Reply payload is the canonical iterator-cancel ack.
        hb = self._parse_wire(bytes(sock.sent))
        self.assertEqual(hb.msg_class, 0x01)
        self.assertEqual(hb.selector, MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS)
        self.assertEqual(hb.request_id, 3)
        self.assertEqual(hb.payload, ITERATOR_CANCEL_ACK)

        # (b) Matching subscription is gone; others remain.
        self.assertNotIn(2, handler._subscriptions)
        self.assertEqual(set(handler._subscriptions.keys()), {0, 1, 3, 4})

        # (c) svc_iterator_cancel is logged at the connection layer.
        self.assertTrue(
            any("svc_iterator_cancel" in m for m in conn_logs.output),
            f"missing svc_iterator_cancel log: {conn_logs.output}",
        )

        # (d) subscribe_notifications is NOT logged for the cancel frame —
        # the cancel branch must come before the `handle_request` dispatch.
        cancel_phase = [m for m in medview_logs.output if "subscribe_notifications req_id=3" in m]
        self.assertEqual(
            cancel_phase,
            [],
            "cancel frame leaked into subscribe handler",
        )

    def test_cancel_frame_on_pipe_without_handler_is_ignored(self):
        from server.config import MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS

        conn, _handler, sock = self._make_conn()
        bare_pipe = self.PIPE_IDX + 1  # not registered
        frame = self._build_cancel_frame(0x01, MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATIONS, 99)

        with self.assertLogs("server.connection", level="INFO") as conn_logs:
            conn._handle_service_data(bare_pipe, frame)

        self.assertTrue(
            any("no_handler" in m for m in conn_logs.output),
            f"missing no_handler log: {conn_logs.output}",
        )
        self.assertEqual(bytes(sock.sent), b"")


class TestMEDVIEWRemoteFsError(unittest.TestCase):
    """Spec selector 0x1D GetRemoteFsError — synchronous u16."""

    def test_get_remote_fs_error_returns_zero(self):
        from server.config import MEDVIEW_SELECTOR_GET_REMOTE_FS_ERROR

        handler = _handler()
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_GET_REMOTE_FS_ERROR, 1, bytes.fromhex("82"), 5, 5
        )
        reply = reply_payload(pkts)
        # 0x82 <word=0> 0x87
        self.assertEqual(reply[0], 0x82)
        self.assertEqual(struct.unpack("<H", reply[1:3])[0], 0)
        self.assertEqual(reply[3], TAG_END_STATIC)


class TestMEDVIEWBaggageBm0(unittest.TestCase):
    """bm0 baggage delivery — kind=5 raster sized to the CBFrame.

    Container layout: 8 B preamble + 30 B kind=5 header (wide-form
    pixel_byte_count) + 38400 B all-FF pixels (640×480 1bpp) + 7 B
    empty trailer = 38445 B total. See `docs/MEDVIEW.md` §10."""

    _BM0_PREAMBLE_LEN = 8
    _BM0_KIND5_HEADER_LEN = 30  # wide pixel_byte_count varint
    _BM0_PIXEL_BYTES = 38400  # 640 × 480 / 8 for 1bpp
    _BM0_TRAILER_LEN = 7
    _BM0_CONTAINER_LEN = (
        _BM0_PREAMBLE_LEN + _BM0_KIND5_HEADER_LEN + _BM0_PIXEL_BYTES + _BM0_TRAILER_LEN
    )
    # bm0 retry form: tag=0x04 var "bm0\0" (4 B, length-prefix 0x84).
    _OPEN_REQ_BM0 = bytes.fromhex("01 01 04 84 62 6d 30 00 01 02 81 83")
    # First-probe form: tag=0x04 var "|bm0\0" (5 B, length-prefix 0x85).
    _OPEN_REQ_PIPE_BM0 = bytes.fromhex("01 01 04 85 7c 62 6d 30 00 01 02 81 83")

    def _decode_reply(self, selector, req_id, payload):
        handler = _handler()
        pkts = handler.handle_request(0x01, selector, req_id, payload, 5, 5)
        self.assertIsNotNone(pkts)
        return reply_payload(pkts)

    def test_container_size_matches_constant(self):
        self.assertEqual(self._BM0_CONTAINER_LEN, 38445)
        self.assertEqual(len(BM0_BAGGAGE), 38445)

    def test_hfs_open_pipe_bm0_is_rejected(self):
        # MVTTL14C's first probe is `|bm0` (`wsprintfA("|bm%d", idx)`);
        # rejection causes the wrapper to retry with the canonical name.
        reply = self._decode_reply(
            MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE, 10, self._OPEN_REQ_PIPE_BM0
        )
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], 0x81)
        self.assertEqual(reply[2], 0x00)  # handle = 0 → reject
        self.assertEqual(reply[3], 0x83)
        self.assertEqual(struct.unpack("<I", reply[4:8])[0], 0)

    def test_hfs_open_bm0_declares_container_size(self):
        reply = self._decode_reply(MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE, 11, self._OPEN_REQ_BM0)
        self.assertEqual(reply[0], TAG_END_STATIC)
        self.assertEqual(reply[1], 0x81)
        self.assertEqual(reply[2], 0x42)
        self.assertEqual(reply[3], 0x83)
        self.assertEqual(
            struct.unpack("<I", reply[4:8])[0],
            self._BM0_CONTAINER_LEN,
        )

    def test_hfs_read_bm0_kind_byte_passes_parser_gate(self):
        # First read of 64 B starting at offset 0 — covers preamble +
        # kind5 header. Bitmap begins at offset 8; first byte must be 5
        # to clear MVDecodeBitmapBaggage's `kind < 5` gate.
        read_req = bytes.fromhex("01 42 03 40 00 00 00 03 00 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE, 12, read_req)
        self.assertEqual(reply[0], 0x81)
        self.assertEqual(reply[1], 0x00)
        self.assertEqual(reply[2], TAG_END_STATIC)
        self.assertEqual(reply[3], TAG_DYNAMIC_COMPLETE_SIGNAL)
        chunk = reply[4 : 4 + 64]
        self.assertEqual(chunk[8], 0x05)

    def test_hfs_read_bm0_preamble_and_header_byte_sequence(self):
        # 38B = 8 preamble + 30 kind=5 header (wide-form pixel_byte_count).
        read_req = bytes.fromhex("01 42 03 26 00 00 00 03 00 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE, 12, read_req)
        chunk = reply[4 : 4 + 38]
        expected_header = bytes.fromhex(
            "00 00"  # container reserved
            "01 00"  # bitmap count = 1
            "08 00 00 00"  # offset to bitmap[0]
            "05 00"  # kind=5, compression=raw
            "00 00 00 00"  # 2x skip-int (narrow form)
            "02 02"  # byte-narrow: planes=1, bpp=1
            "00 05 c0 03"  # ushort-narrow: width=640, height=480
            "00 00 00 00"  # palette_count=0, reserved=0
            "01 2c 01 00"  # u32-wide pixel_byte_count = 38400
            "0e 00"  # ushort-narrow trailer_size = 7
            "1e 00 00 00"  # pixel_data_offset = 30
            "1e 96 00 00"  # trailer_offset = 30 + 38400 = 38430
        )
        self.assertEqual(chunk, expected_header)

    def test_hfs_read_bm0_pixel_data_is_solid_white(self):
        # Pixel data starts at container-offset 38 (= 8 preamble + 30 header).
        read_req = bytes.fromhex("01 42 03 20 00 00 00 03 26 00 00 00 81 85")
        reply = self._decode_reply(MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE, 13, read_req)
        chunk = reply[4 : 4 + 32]
        self.assertEqual(chunk, b"\xff" * 32)

    def test_hfs_read_bm0_trailer_is_empty(self):
        # Trailer at container-offset 38 + 38400 = 38438. Read 7 B.
        offset = self._BM0_PREAMBLE_LEN + self._BM0_KIND5_HEADER_LEN + self._BM0_PIXEL_BYTES
        read_req = (
            b"\x01\x42"
            + b"\x03\x07\x00\x00\x00"
            + b"\x03"
            + struct.pack("<I", offset)
            + b"\x81\x85"
        )
        reply = self._decode_reply(MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE, 14, read_req)
        chunk = reply[4 : 4 + 7]
        self.assertEqual(chunk, b"\x00" * 7)

    def test_hfs_read_bm0_full_request_is_pipe_safe(self):
        # The full bm0 fits in one host block but requires transport
        # fragmentation. Every transport packet remains within PacketSize.
        read_req = (
            b"\x01\x42"
            + b"\x03"
            + struct.pack("<I", self._BM0_CONTAINER_LEN)
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x85"
        )
        handler = _handler()
        pkts = handler.handle_request(
            0x01, MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE, 12, read_req, 5, 5
        )
        self.assertIsNotNone(pkts)
        self.assertGreater(len(pkts), 1)
        self.assertTrue(all(len(pkt) <= 1024 for pkt in pkts))


class TestMEDVIEWM14BaggageDispatch(unittest.TestCase):
    @staticmethod
    def _open_handler():
        handler = _handler()
        open_req = (
            b"\x04\x87:2[4]0\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x03\x00\x00\x00\x00"
            b"\x81\x81\x83\x83\x83\x83\x83"
        )
        handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_OPEN_TITLE,
            1,
            open_req,
            5,
            5,
        )
        return handler

    def test_open_title_exposes_compiled_m14_baggage(self):
        handler = self._open_handler()
        self.assertIn("homed.shg", handler.baggage_map)
        self.assertIn("handbook.m14", handler.baggage_map)
        self.assertNotIn("bm0", handler.baggage_map)

    def test_native_image_reference_opens_and_reads_hfs_baggage(self):
        handler = self._open_handler()
        name = b"!homed.SHG\x00"
        open_req = b"\x01\x01\x04" + bytes([0x80 | len(name)]) + name + b"\x01\x02\x81\x83"
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE,
            21,
            open_req,
            5,
            5,
        )
        reply = reply_payload(pkts)
        self.assertEqual(reply[0], TAG_END_STATIC)
        handle = reply[2]
        self.assertNotEqual(handle, 0)
        self.assertEqual(
            struct.unpack_from("<I", reply, 4)[0],
            len(handler.baggage_map["homed.shg"]),
        )

        read_req = (
            b"\x01"
            + bytes([handle])
            + b"\x03\x20\x00\x00\x00"
            + b"\x03\x00\x00\x00\x00"
            + b"\x81\x85"
        )
        pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE,
            22,
            read_req,
            5,
            5,
        )
        read_reply = reply_payload(pkts)
        self.assertEqual(
            read_reply[4:36],
            handler.baggage_map["homed.shg"][:32],
        )

    def test_large_hfs_read_streams_all_bytes_before_completion(self):
        handler = self._open_handler()
        name = b"!homed.SHG\x00"
        open_req = b"\x01\x01\x04" + bytes([0x80 | len(name)]) + name + b"\x01\x02\x81\x83"
        open_pkts = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_OPEN_REMOTE_HFS_FILE,
            21,
            open_req,
            5,
            5,
        )
        handle = parse_packet(open_pkts[0][:-1]).payload[10]
        baggage = handler.baggage_map["homed.shg"]
        offset = 5
        read_req = (
            b"\x01"
            + bytes([handle])
            + b"\x03"
            + struct.pack("<I", len(baggage) - offset)
            + b"\x03"
            + struct.pack("<I", offset)
            + b"\x81\x85"
        )
        packets = handler.handle_request(
            0x01,
            MEDVIEW_SELECTOR_READ_REMOTE_HFS_FILE,
            22,
            read_req,
            5,
            5,
        )

        dynamic_block_max = 0x4000
        pipe_blocks = []
        current = bytearray()
        expected_size = None
        for packet in packets:
            parsed = parse_packet(packet[:-1])
            self.assertTrue(parsed.crc_ok)
            header = decode_header_byte(parsed.payload[0])
            if expected_size is None:
                expected_size = struct.unpack_from("<H", parsed.payload, 1)[0]
                current.extend(parsed.payload[3:])
            else:
                current.extend(parsed.payload[1:])
            if header & PIPE_LAST_DATA:
                self.assertEqual(len(current), expected_size)
                pipe_blocks.append(bytes(current))
                current = bytearray()
                expected_size = None

        self.assertEqual(
            len(pipe_blocks),
            (len(baggage[offset:]) + dynamic_block_max - 1) // dynamic_block_max,
        )
        replies = []
        for pipe_block in pipe_blocks:
            self.assertEqual(struct.unpack_from("<H", pipe_block)[0], 5)
            host_block = parse_host_block(pipe_block[2:])
            self.assertIsNotNone(host_block)
            self.assertEqual(host_block.request_id, 22)
            replies.append(host_block.payload)

        self.assertEqual(replies[0][:4], b"\x81\x00\x87" + bytes([TAG_DYNAMIC_PARTIAL]))
        for reply in replies[1:-1]:
            self.assertEqual(reply[0], TAG_DYNAMIC_PARTIAL)
        self.assertEqual(replies[-1][0], TAG_DYNAMIC_COMPLETE_SIGNAL)
        self.assertLessEqual(len(replies[0][4:]), dynamic_block_max)
        self.assertTrue(
            all(len(reply[1:]) <= dynamic_block_max for reply in replies[1:]),
        )
        received = replies[0][4:] + b"".join(reply[1:] for reply in replies[1:])
        self.assertEqual(received, baggage[offset:])
        self.assertTrue(all(len(packet) <= 1024 for packet in packets))


if __name__ == "__main__":
    unittest.main()
