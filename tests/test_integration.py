"""Integration tests: replay client sessions against the live server.

Two flavours:

* `TestFullSession` — golden-path replays of one captured handshake +
  login flow, bytes pinned.  Add new scenarios as separate TestCases
  rather than extending these.

* `TestFullFeatureSession` — drives every implemented service handler
  (LOGSRV, DIRSRV, FTM, OLREGSRV, OnlStmt) through `handle_connection`
  over a real socketpair, asserting each reply parses and carries the
  expected status / tag shape.  Updated whenever a new selector lands.
"""
import unittest
import socket
import struct
import threading
import time

from server.connection import handle_connection
from server.transport import build_packet, parse_packet
from server.pipe import build_pipe_frame, build_control_frame
from server.mpc import (
    build_host_block, parse_host_block, parse_tagged_params,
    build_tagged_reply_var,
)
from server.models import DwordParam, VarParam, EndMarker


class TestFullSession(unittest.TestCase):
    """Replay known client packets through handle_connection and validate responses."""

    def setUp(self):
        self.server_sock, self.client_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.settimeout(5)
        self.client_sock.settimeout(5)
        self.server_thread = threading.Thread(
            target=self._run_server, daemon=True)
        self.server_thread.start()

    def _run_server(self):
        try:
            handle_connection(self.server_sock, ('test', 0))
        except (ConnectionError, OSError):
            pass

    def tearDown(self):
        try:
            self.client_sock.close()
        except OSError:
            pass
        try:
            self.server_sock.close()
        except OSError:
            pass
        self.server_thread.join(timeout=2)

    def _recv_until_0d(self, timeout=3):
        """Receive bytes until 0x0D terminator."""
        self.client_sock.settimeout(timeout)
        buf = bytearray()
        while True:
            b = self.client_sock.recv(1)
            if not b:
                break
            buf.extend(b)
            if b[0] == 0x0D:
                break
        return bytes(buf)

    def _recv_bytes(self, n, timeout=3):
        """Receive exactly n bytes."""
        self.client_sock.settimeout(timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = self.client_sock.recv(n - len(buf))
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    def _recv_packet(self, timeout=3):
        """Receive a 0x0D-terminated packet and parse it."""
        raw = self._recv_until_0d(timeout)
        if not raw or raw[-1] != 0x0D:
            return None
        return parse_packet(raw[:-1])

    def _send_raw(self, data):
        self.client_sock.sendall(data)

    def _build_client_packet(self, seq, ack, pipe_payload):
        """Build a valid client packet with pipe frame on pipe 0."""
        frame = build_pipe_frame(0, pipe_payload)
        return build_packet(seq, ack, frame)

    def test_handshake(self):
        """Send bare 0x0D, receive COM\\r + transport params."""
        self._send_raw(b'\x0D')
        time.sleep(0.1)
        com = self._recv_bytes(4, timeout=3)
        self.assertEqual(com, b'COM\r')

        pkt_raw = self._recv_until_0d()
        expected = bytes.fromhex(
            '80 80 e0 17 00 ff ff 03 00 04 00 00 00 04 00 00'
            ' 1b 32 00 00 00 01 00 00 00 58 02 00 00 38 c9 9a'
            ' 7e 0d'
        )
        self.assertEqual(pkt_raw, expected)

    def test_login_flow(self):
        """Full login sequence through bootstrap reply."""
        # Step 1: handshake
        self._send_raw(b'\x0D')
        self._recv_bytes(4)  # COM\r
        self._recv_until_0d()  # transport params

        # Step 2: control-type-4 (connection signal)
        ctrl4_content = build_control_frame(4, b'')
        ctrl4_pkt = self._build_client_packet(0, 0, ctrl4_content)
        self._send_raw(ctrl4_pkt)
        ack1 = self._recv_packet()
        self.assertIsNotNone(ack1)
        self.assertEqual(ack1.type, 'ACK')

        # Step 3: control-type-1 (connection request with params)
        ctrl1_data = b'\x06\x00\x00\x00' + b'\x00' * 169
        ctrl1_content = build_control_frame(1, ctrl1_data)
        ctrl1_pkt = self._build_client_packet(1, 1, ctrl1_content)
        self._send_raw(ctrl1_pkt)
        ack2 = self._recv_packet()
        self.assertIsNotNone(ack2)
        # Server echoes control-type-1
        echo = self._recv_packet()
        self.assertIsNotNone(echo)
        self.assertTrue(echo.crc_ok)

        # Step 4: LOGSRV pipe-open
        pipe_open_content = struct.pack('<HHH', 0, 0, 3) + b'LOGSRV\x00U\x00' + struct.pack('<I', 6)
        pipe_open_pkt = self._build_client_packet(2, 1, pipe_open_content)
        self._send_raw(pipe_open_pkt)
        ack3 = self._recv_packet()
        self.assertIsNotNone(ack3)
        open_resp = self._recv_packet()
        self.assertIsNotNone(open_resp)
        self.assertTrue(open_resp.crc_ok)
        # Discovery block
        discovery = self._recv_packet()
        self.assertIsNotNone(discovery)
        self.assertTrue(discovery.crc_ok)

        # Step 5: login request (class=0x06, selector=0x00, req_id=0)
        # Build as pipe-0 data routed to pipe 3
        login_blob = bytes(0x58)  # 88 bytes of zeros (simplified login blob)
        login_payload = (
            b'\x03' + struct.pack('<I', 0x001643) +   # dword: version
            b'\x04' + bytes([0x80 | 0x58]) + login_blob +   # variable: login blob
            b'\x83\x83\x83\x83\x83\x83\x83\x84'     # recv descriptors
        )
        host_block = bytes([0x06, 0x00, 0x00]) + login_payload  # class, selector, VLI req_id=0
        pipe_data_content = struct.pack('<H', 3) + host_block   # routing prefix = pipe 3
        login_pkt = self._build_client_packet(3, 4, pipe_data_content)
        self._send_raw(login_pkt)
        ack4 = self._recv_packet()
        self.assertIsNotNone(ack4)
        login_reply = self._recv_packet()
        self.assertIsNotNone(login_reply)
        self.assertTrue(login_reply.crc_ok)
        self.assertEqual(login_reply.type, 'DATA')
        # Reply should contain LOGSRV bootstrap (7 success dwords)
        self.assertIn(b'\x83\x00\x00\x00\x00', login_reply.payload)


def _send_param_var(data):
    return build_tagged_reply_var(0x04, data)


def _send_param_dword(value):
    return bytes([0x03]) + struct.pack('<I', value & 0xFFFFFFFF)


def _send_param_byte(value):
    return bytes([0x01, value & 0xFF])


def _send_param_word(value):
    return bytes([0x02]) + struct.pack('<H', value & 0xFFFF)


class TestFullFeatureSession(unittest.TestCase):
    """End-to-end exercise of every implemented service handler.

    Drives the live `handle_connection` event loop over a socketpair
    and walks through bootstrap → LOGSRV (login + password change +
    signup queries + billing query/commits + post-signup) → DIRSRV
    (self + children) → FTM (download + bill-client) → OLREGSRV
    (commit head + one-way continuations) → OnlStmt (summary +
    details for two periods + subscriptions + plans + cancel) →
    pipe-close cascade.
    """

    PIPE_LOGSRV = 3
    PIPE_DIRSRV = 4
    PIPE_FTM = 5
    PIPE_OLREGSRV = 6
    PIPE_ONLSTMT = 7

    def setUp(self):
        self.server_sock, self.client_sock = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_sock.settimeout(5)
        self.client_sock.settimeout(5)
        self.client_seq = 0
        self.client_ack = 0
        self.server_thread = threading.Thread(
            target=self._run_server, daemon=True)
        self.server_thread.start()

    def _run_server(self):
        try:
            handle_connection(self.server_sock, ('test', 0))
        except (ConnectionError, OSError):
            pass

    def tearDown(self):
        for sock in (self.client_sock, self.server_sock):
            try:
                sock.close()
            except OSError:
                pass
        self.server_thread.join(timeout=2)

    # --- raw socket helpers ---

    def _recv_until_0d(self, timeout=2):
        self.client_sock.settimeout(timeout)
        buf = bytearray()
        while True:
            chunk = self.client_sock.recv(1)
            if not chunk:
                break
            buf.extend(chunk)
            if chunk[0] == 0x0D:
                break
        return bytes(buf)

    def _recv_packet(self, timeout=2):
        raw = self._recv_until_0d(timeout)
        if not raw or raw[-1] != 0x0D:
            return None
        return parse_packet(raw[:-1])

    def _drain_packets(self, expected_data_packets, timeout=2):
        """Drain ACK + N data packets; return the data packets in order."""
        data_pkts = []
        deadline = time.monotonic() + timeout
        while len(data_pkts) < expected_data_packets and time.monotonic() < deadline:
            pkt = self._recv_packet(timeout=0.5)
            if pkt is None:
                continue
            if pkt.type == 'DATA':
                data_pkts.append(pkt)
        return data_pkts

    def _next_seq(self):
        seq = self.client_seq
        self.client_seq = (self.client_seq + 1) & 0x7F
        return seq

    def _send_pipe0(self, content):
        frame = build_pipe_frame(0, content)
        pkt = build_packet(self._next_seq(), self.client_ack, frame)
        self.client_sock.sendall(pkt)

    def _send_service_call(self, target_pipe, msg_class, selector, payload,
                           req_id=0):
        host_block = build_host_block(msg_class, selector, req_id, payload)
        content = struct.pack('<H', target_pipe) + host_block
        self._send_pipe0(content)

    # --- protocol-level helpers ---

    def _do_handshake(self):
        self.client_sock.sendall(b'\x0D')
        self.client_sock.settimeout(2)
        com = bytearray()
        while len(com) < 4:
            com.extend(self.client_sock.recv(4 - len(com)))
        self.assertEqual(bytes(com), b'COM\r')
        params = self._recv_packet()
        self.assertIsNotNone(params)
        self.assertTrue(params.crc_ok)

    def _do_control(self):
        self._send_pipe0(build_control_frame(4, b''))
        self._drain_packets(0, timeout=0.2)

        ctrl1_data = b'\x06\x00\x00\x00' + b'\x00' * 169
        self._send_pipe0(build_control_frame(1, ctrl1_data))
        echoes = self._drain_packets(1)
        self.assertEqual(len(echoes), 1)

    def _open_pipe(self, pipe_idx, svc_name, version):
        content = (
            struct.pack('<HHH', 0, 0, pipe_idx) +
            svc_name.encode('ascii') + b'\x00' +
            b'U\x00' +
            struct.pack('<I', version)
        )
        self._send_pipe0(content)
        pkts = self._drain_packets(2, timeout=3)
        self.assertGreaterEqual(len(pkts), 2,
            f'pipe open for {svc_name!r} did not return 2+ data packets')
        self.assertTrue(pkts[0].crc_ok)
        return pkts

    def _call_selector(self, target_pipe, msg_class, selector, payload,
                        req_id=0, expected_replies=1):
        self._send_service_call(target_pipe, msg_class, selector, payload,
                                req_id=req_id)
        return self._drain_packets(expected_replies, timeout=3)

    def _reassemble_reply(self, pkts):
        # Frame layout: header(1) + length(2) + routing(2) + data.  For
        # multi-frame replies, frames 2+ are bare header(1) + chunk.
        if not pkts:
            return None
        if len(pkts) == 1:
            return pkts[0].payload[1 + 2 + 2:]
        chunks = [pkts[0].payload[1 + 2 + 2:]]
        chunks.extend(p.payload[1:] for p in pkts[1:])
        return b''.join(chunks)

    def _reply_payload(self, pkts):
        return parse_host_block(self._reassemble_reply(pkts)).payload

    def _close_pipe(self, pipe_idx):
        # Closing the last open service pipe brings the connection down,
        # so drain quickly without waiting for data the server never sends.
        content = struct.pack('<H', pipe_idx) + bytes([0x01])
        self._send_pipe0(content)
        self._drain_packets(0, timeout=0.15)

    # --- the test ---

    def test_full_feature_session(self):
        self._do_handshake()
        self._do_control()

        self._exercise_logsrv()
        self._exercise_dirsrv()
        self._exercise_ftm()
        self._exercise_olregsrv()
        self._exercise_onlstmt()

        for pipe in (self.PIPE_LOGSRV, self.PIPE_DIRSRV, self.PIPE_FTM,
                     self.PIPE_OLREGSRV, self.PIPE_ONLSTMT):
            self._close_pipe(pipe)

    # --- per-service walks ---

    def _exercise_logsrv(self):
        self._open_pipe(self.PIPE_LOGSRV, 'LOGSRV', 6)

        login_payload = (
            _send_param_dword(0x001643) +
            _send_param_var(b'\x00' * 0x58) +
            b'\x83' * 7 + b'\x84'
        )
        pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, 0x00, login_payload)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertEqual(sum(1 for p in params if isinstance(p, DwordParam)), 7)
        self.assertEqual(params[0].value, 0)
        self.assertIsInstance(params[7], EndMarker)
        self.assertIsInstance(params[8], VarParam)

        pw_req = (
            _send_param_var(b'oldpass\x00' + b'\x00' * 9) +
            _send_param_var(b'newpass\x00' + b'\x00' * 9) +
            b'\x83'
        )
        pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, 0x01, pw_req,
                                    req_id=1)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertEqual(params[0].value, 0)

        pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, 0x07, b'\x85',
                                    req_id=2)
        self.assertEqual(self._reply_payload(pkts)[0], 0x84)

        sig_payload = bytes.fromhex(
            '03 5f 01 00 00 03 00 00 00 00 03 00 00 00 00 84')
        pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, 0x02, sig_payload,
                                    req_id=3)
        self.assertEqual(self._reply_payload(pkts)[0], 0x84)

        # Billing reply is 1052 bytes — must fragment across 2 wire packets.
        pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, 0x0A, b'\x84',
                                    req_id=4, expected_replies=2)
        self.assertEqual(len(pkts), 2,
            'billing reply must fragment into exactly 2 wire packets')
        body = self._reply_payload(pkts)
        self.assertEqual(body[0], 0x84)
        var_len = ((body[1] & 0x7F) << 8) | body[2]
        self.assertEqual(var_len, 1052)
        self.assertIn(b'Microsoft', body)
        self.assertIn(b'Redmond', body)

        # Commits MUST reply with 0x84 var; 0x83 dword passes the wait
        # but fails BillingDlg's type check (project_logsrv_commit_reply_shape).
        for sel in (0x0B, 0x0C):
            pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, sel, b'\x84',
                                        req_id=5 + (sel - 0x0B))
            reply = self._reply_payload(pkts)
            self.assertEqual(reply[0], 0x84,
                f'commit selector 0x{sel:02x} must use 0x84 var tag')
            self.assertEqual(reply[2:6], b'\x00\x00\x00\x00')

        pkts = self._call_selector(self.PIPE_LOGSRV, 0x06, 0x0D, sig_payload,
                                    req_id=7)
        self.assertEqual(self._reply_payload(pkts)[0], 0x84)

    def _exercise_dirsrv(self):
        self._open_pipe(self.PIPE_DIRSRV, 'DIRSRV', 1)

        node_id = struct.pack('<II', 0, 0)
        self_req = (
            _send_param_var(node_id) +
            _send_param_var(b'q\x00') +
            _send_param_dword(0)  # children=False
        )
        pkts = self._call_selector(self.PIPE_DIRSRV, 0x01, 0x01, self_req)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertEqual(params[0].value, 0)
        self.assertGreaterEqual(params[1].value, 1)

        prop_group = b'\x00'.join([
            b'p', b'c', b'h', b'a', b'i', b'wv', b'tp', b'w', b'l',
        ]) + b'\x00'
        kids_req = (
            _send_param_var(node_id) +
            _send_param_var(prop_group) +
            _send_param_dword(1)  # children=True
        )
        pkts = self._call_selector(self.PIPE_DIRSRV, 0x01, 0x01, kids_req,
                                    req_id=1)
        self.assertIn(b'MSN Central', self._reply_payload(pkts))

    def _exercise_ftm(self):
        self._open_pipe(self.PIPE_FTM, 'FTM', 1)

        cfi = bytearray(60)
        cfi[0:9] = b'plans.txt'
        pkts = self._call_selector(
            self.PIPE_FTM, 0x01, 0x00,
            _send_param_var(bytes(cfi)) + b'\x84')
        body = self._reply_payload(pkts)
        self.assertEqual(body[0], 0x84)
        # 72-byte download buffer; flags dword at +0x10 inside it = 0x0B.
        var_len = ((body[1] & 0x7F) << 8 | body[2]) if not (body[1] & 0x80) \
            else (body[1] & 0x7F)
        self.assertEqual(var_len, 72)
        buf_start = 2 if (body[1] & 0x80) else 3
        flags = struct.unpack('<I',
            body[buf_start + 0x10:buf_start + 0x14])[0]
        self.assertEqual(flags, 0x0B)

        pkts = self._call_selector(
            self.PIPE_FTM, 0x01, 0x03,
            _send_param_var(bytes(cfi)) + b'\x84',
            req_id=1)
        self.assertEqual(self._reply_payload(pkts)[0], 0x84)

    def _exercise_olregsrv(self):
        self._open_pipe(self.PIPE_OLREGSRV, 'OLREGSRV', 1)

        pkts = self._call_selector(
            self.PIPE_OLREGSRV, 0x01, 0x01, b'\x83', req_id=0)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertIsInstance(params[0], DwordParam)
        self.assertEqual(params[0].value, 0)

        # One-way continuations: server ACKs but returns no DATA.
        for msg_class, sel in [(0xe7, 0x01), (0xe6, 0x02), (0xe7, 0x02)]:
            self._send_service_call(
                self.PIPE_OLREGSRV, msg_class, sel, b'\x83', req_id=0)
            self._drain_packets(0, timeout=0.15)

    def _exercise_onlstmt(self):
        self._open_pipe(self.PIPE_ONLSTMT, 'OnlStmt', 3)

        pkts = self._call_selector(
            self.PIPE_ONLSTMT, 0x01, 0x00,
            b'\x83\x82\x82\x81\x81\x82\x81', req_id=0)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertEqual(len(params), 7)
        # Period count - 1; client clamps to 4 periods total.
        self.assertEqual(params[-1].value, 3)

        pkts = self._call_selector(
            self.PIPE_ONLSTMT, 0x01, 0x05,
            _send_param_byte(0) + b'\x82\x82\x85', req_id=1)
        body = self._reply_payload(pkts)
        self.assertIn(b'\x86', body)
        self.assertIn(b'Exchange rate:', body)
        self.assertIn(b'Tokyo content purchase', body)

        pkts = self._call_selector(
            self.PIPE_ONLSTMT, 0x01, 0x05,
            _send_param_byte(3) + b'\x82\x82\x85', req_id=2)
        self.assertIn(b'\x86', self._reply_payload(pkts))

        pkts = self._call_selector(
            self.PIPE_ONLSTMT, 0x01, 0x02,
            b'\x81\x84\x83\x82\x81\x82\x81\x81\x82\x81\x81', req_id=3)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertEqual(len(params), 12)
        self.assertIsInstance(params[-1], EndMarker)

        pkts = self._call_selector(
            self.PIPE_ONLSTMT, 0x01, 0x03, b'\x81\x84', req_id=4)
        params = parse_tagged_params(self._reply_payload(pkts))
        self.assertEqual(params[0].value, 3)
        self.assertIsInstance(params[1], VarParam)

        pkts = self._call_selector(
            self.PIPE_ONLSTMT, 0x01, 0x04,
            _send_param_word(0xFFFF) + b'\x81', req_id=5)
        # 0x81 0x01 => success; any other byte trips client error 0x2d.
        self.assertEqual(self._reply_payload(pkts)[:3], b'\x81\x01\x87')


if __name__ == '__main__':
    unittest.main()
