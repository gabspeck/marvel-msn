"""Integration test: replay a real client session against the server."""
import unittest
import socket
import struct
import threading
import time

from server.connection import handle_connection
from server.transport import build_packet, build_ack_packet, parse_packet
from server.pipe import build_pipe_frame, build_control_frame


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


if __name__ == '__main__':
    unittest.main()
