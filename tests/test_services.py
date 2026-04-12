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
from server.services.ftm import (
    FTMHandler, _extract_requested_filename, _build_request_download_reply,
    _build_bill_client_reply, FTM_FALLBACK_FILENAME,
)
from server.services.olregsrv import (
    OLREGSRVHandler, build_olregsrv_service_map_payload,
)
from server.transport import parse_packet
from server.mpc import (
    parse_tagged_params, build_service_packet, build_host_block,
    build_tagged_reply_var, _build_continuation_frame,
)
from server.wire import decode_header_byte
from server.config import (
    LOGSRV_INTERFACE_GUIDS, DIRSRV_INTERFACE_GUIDS, OLREGSRV_INTERFACE_GUIDS,
    PIPE_ALWAYS_SET, PIPE_CONTINUATION, PIPE_LAST_DATA,
)
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
        pkts = handler.build_discovery_packet(3, 3)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)

    def test_known_wire_bytes(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkts = handler.build_discovery_packet(3, 3)
        expected_start = bytes.fromhex('83 83 e3 af 00 03 00 00 00 00')
        self.assertEqual(pkts[0][:10], expected_start)


class TestLOGSRVReply(unittest.TestCase):
    def test_login_reply_returns_packet(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkts = handler.handle_request(0x06, 0x00, 0, b'', 4, 4)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_password_change_reply(self):
        # Selector 0x01 = password change
        pw_payload = bytes.fromhex(
            '04 91 74 65 73 74 65 00 3f 27 27 01 00 00 1f 19'
            '3f 27 27 04 91 61 76 6f 63 61 64 6f 73 00 00 00'
            '00 54 2b 10 04 b8 83'
        )
        handler = LOGSRVHandler(8, 'LOGSRV')
        pkts = handler.handle_request(0x06, 0x01, 0, pw_payload, 37, 36)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_signup_post_transfer_returns_packet(self):
        """Selector 0x02 is called on a fresh LOGSRV pipe after the FTM
        phone-book transfer finishes; client hangs at "Starting transfer..."
        if the server returns None.  Minimum viable reply is an empty 0x84
        variable satisfying the single recv descriptor.
        """
        payload = bytes.fromhex('03 5f 01 00 00 03 00 00 00 00 03 00 00 00 00 84')
        handler = LOGSRVHandler(6, 'LOGSRV')
        pkts = handler.handle_request(0x06, 0x02, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_signup_query_returns_packet(self):
        """Selector 0x07 (SIGNUP's 'product details' query) must reply.

        The client sends a single recv descriptor (0x85) and hangs when
        the server returns None; the minimum viable reply is an empty
        0x84 variable.
        """
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkts = handler.handle_request(0x06, 0x07, 1, b'\x85', 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_unknown_selector_returns_none(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkt = handler.handle_request(0x06, 0xFF, 0, b'', 5, 5)
        self.assertIsNone(pkt)

    def test_known_login_reply_wire_bytes(self):
        handler = LOGSRVHandler(3, 'LOGSRV')
        pkts = handler.handle_request(0x06, 0x00, 0, b'', 4, 4)
        expected = bytes.fromhex(
            '84 84 e3 3b 00 03 00 06 00 00 83 00 00 00 00 83'
            '00 00 00 00 83 00 00 00 00 83 00 00 00 00 83 00'
            '00 00 00 83 00 00 00 00 83 00 00 00 00 87 84 1b'
            '35 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            '00 2b 11 96 ab 0d'
        )
        self.assertEqual(pkts[0], expected)


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


class TestOLREGSRVServiceMap(unittest.TestCase):
    def test_payload_size(self):
        payload = build_olregsrv_service_map_payload()
        self.assertEqual(len(payload), len(OLREGSRV_INTERFACE_GUIDS) * 17)

    def test_guid_format(self):
        payload = build_olregsrv_service_map_payload()
        for i, (guid_bytes, selector) in enumerate(OLREGSRV_INTERFACE_GUIDS):
            record = payload[i * 17:(i + 1) * 17]
            self.assertEqual(record[:16], guid_bytes)
            self.assertEqual(record[16], selector)

    def test_produces_packet(self):
        handler = OLREGSRVHandler(4, 'OLREGSRV')
        pkts = handler.build_discovery_packet(6, 6)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.crc_ok)


class TestOLREGSRVReply(unittest.TestCase):
    def test_unknown_selector_returns_none_with_log(self):
        """Every selector currently returns None — reply shapes aren't RE'd yet."""
        handler = OLREGSRVHandler(4, 'OLREGSRV')
        self.assertIsNone(handler.handle_request(0x06, 0x01, 1, b'', 5, 5))
        self.assertIsNone(handler.handle_request(0x06, 0x05, 1, b'\x85', 5, 5))


class TestFTMHandler(unittest.TestCase):
    def test_request_download_reply_returns_packet(self):
        payload = bytes.fromhex(
            '04 bc 70 6c 61 6e 73 2e 74 78 74 00 00 00 00 00'
            ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            ' 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
            ' 00 00 00 00 00 00 00 00 00 00 00 00'
        )
        handler = FTMHandler(1, 'FTM')
        pkts = handler.handle_request(0x01, 0x00, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_bill_client_reply_returns_packet(self):
        handler = FTMHandler(1, 'FTM')
        pkts = handler.handle_request(0x01, 0x03, 0, b'', 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_unknown_selector_returns_none(self):
        handler = FTMHandler(1, 'FTM')
        self.assertIsNone(handler.handle_request(0x01, 0x02, 0, b'', 5, 5))

    def test_extract_requested_filename_requires_expected_var_layout(self):
        payload = (
            b'\x04' + bytes([0x80 | 60]) +
            b'ms_Ynt.hlp\x00' + b'\x00' * (60 - len('ms_Ynt.hlp') - 1)
        )
        self.assertEqual(_extract_requested_filename(payload), 'ms_Ynt.hlp')

    def test_extract_requested_filename_falls_back_for_unexpected_var_size(self):
        payload = b'\x04' + bytes([0x80 | 32]) + b'plans.txt\x00' + b'\x00' * 22
        self.assertEqual(_extract_requested_filename(payload), FTM_FALLBACK_FILENAME)

    def test_request_download_reply_echoes_filename(self):
        payload = _build_request_download_reply('ms_Ynt.hlp')
        self.assertEqual(payload[0], 0x84)
        self.assertIn(b'ms_Ynt.hlp\x00', payload)

    def test_request_download_reply_handles_non_ascii_filename(self):
        payload = _build_request_download_reply('pláns.txt')
        self.assertEqual(payload[0], 0x84)
        self.assertIn(b'plns.txt\x00', payload)

    def test_bill_client_reply_has_zero_chunk_length(self):
        payload = _build_bill_client_reply()
        self.assertEqual(payload[0], 0x84)
        self.assertEqual(struct.unpack('<H', payload[0x11:0x13])[0], 0)


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


class TestServicePacketFragmentation(unittest.TestCase):
    """Tests for multi-frame pipe fragmentation in build_service_packet."""

    def test_small_payload_single_packet(self):
        host_block = build_host_block(0x06, 0x00, 0, b'\x00' * 50)
        pkts = build_service_packet(3, host_block, 5, 5)
        self.assertEqual(len(pkts), 1)
        self.assertLessEqual(len(pkts[0]), 1024)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_large_payload_two_packets(self):
        # 1052-byte payload mimics the billing reply
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        self.assertEqual(len(pkts), 2)

    def test_both_packets_within_limit(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        for i, pkt in enumerate(pkts):
            self.assertLessEqual(len(pkt), 1024, f'Packet {i+1} exceeds 1024 bytes')

    def test_both_packets_valid_crc(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        for i, pkt in enumerate(pkts):
            parsed = parse_packet(pkt[:-1])
            self.assertIsNotNone(parsed, f'Packet {i+1} unparseable')
            self.assertTrue(parsed.crc_ok, f'Packet {i+1} CRC fail')

    def test_first_frame_no_last_data(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        parsed = parse_packet(pkts[0][:-1])
        # First byte of payload is the pipe frame header
        hdr = decode_header_byte(parsed.payload[0])
        self.assertTrue(hdr & PIPE_CONTINUATION, 'Frame 1 missing CONTINUATION')
        self.assertFalse(hdr & PIPE_LAST_DATA, 'Frame 1 should NOT have LAST_DATA')

    def test_second_frame_has_last_data(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        parsed = parse_packet(pkts[1][:-1])
        hdr = decode_header_byte(parsed.payload[0])
        self.assertTrue(hdr & PIPE_CONTINUATION, 'Frame 2 missing CONTINUATION')
        self.assertTrue(hdr & PIPE_LAST_DATA, 'Frame 2 missing LAST_DATA')

    def test_first_frame_has_size_prefix(self):
        """Frame 1 content starts with uint16_le(total_pipe_data_len)."""
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        parsed = parse_packet(pkts[0][:-1])
        # After frame header byte, next 2 bytes = pipe_data size prefix
        size_prefix = struct.unpack('<H', parsed.payload[1:3])[0]
        expected_pipe_data_len = 2 + len(host_block)  # routing_prefix + host_block
        self.assertEqual(size_prefix, expected_pipe_data_len)

    def test_second_frame_no_size_prefix(self):
        """Frame 2 content is raw continuation data (no 2-byte prefix)."""
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        # Reconstruct: frame1 content after header = size_prefix(2) + chunk1
        # frame2 content after header = chunk2
        chunk1 = p1.payload[3:]  # skip header(1) + size_prefix(2)
        chunk2 = p2.payload[1:]  # skip header(1) only
        pipe_data = chunk1 + chunk2
        # First 2 bytes of pipe_data = routing prefix (pipe_idx as uint16_le)
        routing = struct.unpack('<H', pipe_data[:2])[0]
        self.assertEqual(routing, 8)  # pipe_idx we passed
        # Remaining = host_block
        self.assertEqual(pipe_data[2:], host_block)

    def test_seq_increments_across_packets(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 10, 10)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        self.assertEqual(p1.seq, 10)
        self.assertEqual(p2.seq, 11)

    def test_seq_wraps_at_127(self):
        host_block = build_host_block(0x06, 0x0A, 0, build_tagged_reply_var(0x84, bytes(1052)))
        pkts = build_service_packet(8, host_block, 127, 5)
        p1 = parse_packet(pkts[0][:-1])
        p2 = parse_packet(pkts[1][:-1])
        self.assertEqual(p1.seq, 127)
        self.assertEqual(p2.seq, 0)

    def test_billing_reply_fragments(self):
        """The actual billing handler produces correctly fragmented packets."""
        handler = LOGSRVHandler(8, 'LOGSRV')
        pkts = handler.handle_request(0x06, 0x0A, 0, b'', 10, 10)
        self.assertEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertLessEqual(len(pkt), 1024)
            parsed = parse_packet(pkt[:-1])
            self.assertTrue(parsed.crc_ok)

    def test_custom_max_wire_bytes(self):
        """Fragmentation threshold is configurable."""
        host_block = build_host_block(0x06, 0x00, 0, b'\x00' * 200)
        # With default 1024 limit, this fits in one packet
        pkts_default = build_service_packet(3, host_block, 5, 5)
        self.assertEqual(len(pkts_default), 1)
        # With a tight limit, it should fragment
        pkts_tight = build_service_packet(3, host_block, 5, 5, max_wire_bytes=100)
        self.assertEqual(len(pkts_tight), 2)


class TestContinuationFrame(unittest.TestCase):
    def test_flags_with_last(self):
        frame = _build_continuation_frame(3, b'\x01\x02\x03', last=True)
        hdr = decode_header_byte(frame[0])
        self.assertTrue(hdr & PIPE_ALWAYS_SET)
        self.assertTrue(hdr & PIPE_CONTINUATION)
        self.assertTrue(hdr & PIPE_LAST_DATA)
        self.assertEqual(hdr & 0x0F, 3)

    def test_flags_without_last(self):
        frame = _build_continuation_frame(3, b'\x01\x02\x03', last=False)
        hdr = decode_header_byte(frame[0])
        self.assertTrue(hdr & PIPE_ALWAYS_SET)
        self.assertTrue(hdr & PIPE_CONTINUATION)
        self.assertFalse(hdr & PIPE_LAST_DATA)

    def test_content_follows_header_directly(self):
        data = b'\xAA\xBB\xCC'
        frame = _build_continuation_frame(3, data, last=True)
        # Frame = header(1) + raw content (no length prefix)
        self.assertEqual(len(frame), 1 + len(data))
        self.assertEqual(frame[1:], data)


if __name__ == '__main__':
    unittest.main()
