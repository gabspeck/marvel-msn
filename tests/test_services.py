"""Tests for LOGSRV and DIRSRV service payload builders."""
import unittest
import struct

from server.services.logsrv import (
    LOGSRVHandler, build_logsrv_bootstrap_payload, build_logsrv_service_map_payload,
)
from server.services.dirsrv import (
    DIRSRVHandler, build_dirsrv_reply_payload, build_dirsrv_service_map_payload,
    build_property_record,
)
from server.transport import parse_packet
from server.mpc import parse_tagged_params
from server.config import LOGSRV_INTERFACE_GUIDS, DIRSRV_INTERFACE_GUIDS
from server.models import DwordParam, VarParam, EndMarker, DirsrvRequest


class TestLOGSRVBootstrap(unittest.TestCase):
    def test_structure(self):
        payload = build_logsrv_bootstrap_payload()
        # Should contain 7 dword tags (0x83), then 0x87, then 0x84 variable
        pos = 0
        dword_count = 0
        while pos < len(payload) and payload[pos] == 0x83:
            dword_count += 1
            pos += 5  # tag + 4-byte value
        self.assertEqual(dword_count, 7)
        self.assertEqual(payload[pos], 0x87)  # end of static section
        pos += 1
        self.assertEqual(payload[pos], 0x84)  # variable tag
        pos += 1
        # Next byte is length (0x90 = inline 16)
        self.assertEqual(payload[pos], 0x90)
        pos += 1
        # 16 bytes of data
        self.assertEqual(len(payload) - pos, 16)

    def test_first_dword_is_zero(self):
        # Field 0 = login result code, should be 0 (success)
        payload = build_logsrv_bootstrap_payload()
        result_code = struct.unpack('<I', payload[1:5])[0]
        self.assertEqual(result_code, 0)

    def test_parseable(self):
        payload = build_logsrv_bootstrap_payload()
        params = parse_tagged_params(payload)
        self.assertIsNotNone(params)
        self.assertGreater(len(params), 0)
        # First 7 params should be dwords
        for p in params[:7]:
            self.assertIsInstance(p, DwordParam)
        # Then an EndMarker
        self.assertIsInstance(params[7], EndMarker)
        # Then a variable param
        self.assertIsInstance(params[8], VarParam)


class TestLOGSRVServiceMap(unittest.TestCase):
    def test_payload_size(self):
        # 10 GUIDs * 17 bytes each = 170 bytes
        payload = build_logsrv_service_map_payload()
        self.assertEqual(len(payload), len(LOGSRV_INTERFACE_GUIDS) * 17)

    def test_guid_format(self):
        payload = build_logsrv_service_map_payload()
        # Each record is 16-byte GUID + 1-byte selector
        for i, (guid_bytes, selector) in enumerate(LOGSRV_INTERFACE_GUIDS):
            record = payload[i * 17:(i + 1) * 17]
            self.assertEqual(record[:16], guid_bytes)
            self.assertEqual(record[16], selector)

    def test_produces_packet(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.build_discovery_packet(3, 3)
        parsed = parse_packet(pkt[:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)

    def test_known_wire_bytes(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.build_discovery_packet(3, 3)
        expected_start = bytes.fromhex('83 83 e3 af 00 03 00 00 00 00')
        self.assertEqual(pkt[:10], expected_start)


class TestLOGSRVReply(unittest.TestCase):
    def test_login_reply_returns_packet(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.handle_request(0x06, 0x00, 0, b'', 4, 4)
        self.assertIsNotNone(pkt)
        parsed = parse_packet(pkt[:-1])
        self.assertTrue(parsed.crc_ok)

    def test_password_change_reply(self):
        # Selector 0x01 = password change
        pw_payload = bytes.fromhex(
            '04 91 74 65 73 74 65 00 3f 27 27 01 00 00 1f 19'
            '3f 27 27 04 91 61 76 6f 63 61 64 6f 73 00 00 00'
            '00 54 2b 10 04 b8 83'
        )
        handler = LOGSRVHandler(8, 'LOGSRV')
        pkt = handler.handle_request(0x06, 0x01, 0, pw_payload, 37, 36)
        self.assertIsNotNone(pkt)
        parsed = parse_packet(pkt[:-1])
        self.assertTrue(parsed.crc_ok)

    def test_enumerator_returns_none(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.handle_request(0x06, 0x07, 1, b'', 5, 5)
        self.assertIsNone(pkt)

    def test_unknown_selector_returns_none(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.handle_request(0x06, 0xFF, 0, b'', 5, 5)
        self.assertIsNone(pkt)

    def test_known_login_reply_wire_bytes(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.handle_request(0x06, 0x00, 0, b'', 4, 4)
        expected = bytes.fromhex(
            '84 84 e3 3b 00 03 00 06 00 00 83 00 00 00 00 83'
            '00 00 00 00 83 00 00 00 00 83 00 00 00 00 83 00'
            '00 00 00 83 00 00 00 00 83 00 00 00 00 87 84 1b'
            '35 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 2b 11 96 ab 0d'
        )
        self.assertEqual(pkt, expected)


class TestDIRSRVServiceMap(unittest.TestCase):
    def test_payload_size(self):
        payload = build_dirsrv_service_map_payload()
        self.assertEqual(len(payload), len(DIRSRV_INTERFACE_GUIDS) * 17)

    def test_single_guid(self):
        payload = build_dirsrv_service_map_payload()
        self.assertEqual(payload[16], 0x01)  # selector for the one DIRSRV GUID


class TestDIRSRVReply(unittest.TestCase):
    def test_self_properties(self):
        request = DirsrvRequest(
            dword_0=0, dword_1=1, prop_group='q',
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        # Should start with two 0x83 dwords
        self.assertEqual(payload[0], 0x83)
        status = struct.unpack('<I', payload[1:5])[0]
        self.assertEqual(status, 0)
        self.assertEqual(payload[5], 0x83)
        # Then 0x87 end, then 0x88 dynamic
        self.assertIn(0x87, payload)
        self.assertIn(0x88, payload)

    def test_children_contains_msn_central(self):
        request = DirsrvRequest(
            dword_0=1, dword_1=14,
            prop_group='a\x00c\x00h\x00b\x00e\x00g\x00x\x00mf\x00wv\x00tp\x00p\x00w\x00l\x00i',
            recv_descriptors=[0x83, 0x83, 0x85],
        )
        payload = build_dirsrv_reply_payload(request)
        self.assertIn(b'MSN Central', payload)


class TestPropertyRecord(unittest.TestCase):
    def test_format(self):
        props = [(0x03, "q", struct.pack('<I', 1))]
        record = build_property_record(props)
        # total_size (4) + prop_count (2) + type(1) + "q\0"(2) + value(4) = 13
        total_size = struct.unpack('<I', record[:4])[0]
        self.assertEqual(total_size, 13)
        prop_count = struct.unpack('<H', record[4:6])[0]
        self.assertEqual(prop_count, 1)
        # Type byte
        self.assertEqual(record[6], 0x03)
        # Name
        self.assertEqual(record[7:9], b'q\x00')
        # Value
        self.assertEqual(struct.unpack('<I', record[9:13])[0], 1)

    def test_multiple_properties(self):
        props = [
            (0x03, "a", struct.pack('<I', 0)),
            (0x0E, "p", struct.pack('<I', 5) + b'Hello'),
        ]
        record = build_property_record(props)
        prop_count = struct.unpack('<H', record[4:6])[0]
        self.assertEqual(prop_count, 2)

    def test_empty_record(self):
        record = build_property_record([])
        total_size = struct.unpack('<I', record[:4])[0]
        self.assertEqual(total_size, 6)  # just header
        prop_count = struct.unpack('<H', record[4:6])[0]
        self.assertEqual(prop_count, 0)


if __name__ == '__main__':
    unittest.main()
