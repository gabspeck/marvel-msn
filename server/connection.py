"""Connection handler: the main event loop for a single client connection.

Manages the protocol state machine from telnet negotiation through
login, directory browsing, and sign-out.
"""
import socket
import time
from collections import defaultdict

from .config import (
    PACKET_TERMINATOR, DELAY_AFTER_COM, DELAY_BEFORE_REPLY,
    SOCKET_TIMEOUT, PIPE_CLOSE_CMD,
)
from .transport import build_packet, build_ack_packet, parse_packet, build_transport_params
from .pipe import parse_pipe_frames, parse_pipe0_content
from .mpc import (
    parse_host_block, build_control_type1_ack, build_pipe_open_result,
)
from .models import ControlMessage, PipeOpenRequest, PipeData
from .services import SERVICE_HANDLERS


def hexdump(data, prefix=""):
    """Pretty-print hex dump with ASCII sidebar."""
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{prefix} {offset:04x}: {hex_part:<48s} {ascii_part}')


def _strip_telnet(data, conn):
    """Remove telnet IAC negotiation sequences, responding appropriately."""
    IAC, WILL, WONT, DO, DONT = 0xFF, 0xFB, 0xFC, 0xFD, 0xFE
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == IAC and i + 2 < len(data):
            cmd, opt = data[i + 1], data[i + 2]
            if cmd == DO:
                conn.sendall(bytes([IAC, WONT, opt]))
            elif cmd == WILL:
                conn.sendall(bytes([IAC, DONT, opt]))
            i += 3
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


class ConnectionState:
    """Per-connection state and protocol state machine."""

    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.conn_start = time.monotonic()
        self.event_no = 0
        self.rx_pkt_no = 0
        self.tx_pkt_no = 0
        self.server_seq = 1  # seq 0 used for transport params
        self.client_ack = 0
        self.services = {}          # pipe_idx -> ServiceHandler
        self.pipe_buffers = defaultdict(bytearray)
        self.pipes_closed = set()
        self.buf = bytearray()
        self.transport_started = False

    def log(self, msg):
        elapsed = time.monotonic() - self.conn_start
        self.event_no += 1
        print(f'[{elapsed:7.3f} #{self.event_no:04d}] {msg}')

    def send_packet(self, pkt, label=""):
        self.tx_pkt_no += 1
        self.log(f'[TXPKT {self.tx_pkt_no:03d}] {label} ({len(pkt)} bytes)')
        hexdump(pkt, "[TX]")
        self.conn.sendall(pkt)

    def advance_seq(self):
        seq = self.server_seq
        self.server_seq = (self.server_seq + 1) & 0x7F
        return seq

    def run(self):
        """Main entry point — runs the full connection lifecycle."""
        self.log(f'[*] Waiting for initial 0x0D from MOSCP...')
        self.conn.settimeout(SOCKET_TIMEOUT)

        while True:
            try:
                data = self.conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break

            self.log(f'[RX] Raw ({len(data)} bytes)')
            hexdump(data, "[RX]")

            if not self.transport_started:
                data = _strip_telnet(data, self.conn)

            self.buf.extend(data)

            while True:
                idx = self.buf.find(PACKET_TERMINATOR)
                if idx == -1:
                    break
                packet_data = bytes(self.buf[:idx])
                del self.buf[:idx + 1]

                if not packet_data:
                    if not self.transport_started:
                        self._do_handshake()
                    continue

                self._handle_raw_packet(packet_data)

    def _do_handshake(self):
        """Send COM\\r and transport params."""
        self.log('[RX] Empty terminator (bare 0x0D)')
        self.log('[TX] Sending \'COM\' (direct transport trigger)')
        self.conn.sendall(b'COM\r')
        time.sleep(DELAY_AFTER_COM)

        params_pkt = build_transport_params()
        self.send_packet(params_pkt, "Sending transport params")
        self.transport_started = True

    def _handle_raw_packet(self, packet_data):
        """Parse and dispatch a single packet."""
        pkt = parse_packet(packet_data)
        if pkt is None:
            self.log(f'[!] Unparseable packet ({len(packet_data)} bytes)')
            return

        self.rx_pkt_no += 1
        self.log(f'[RXPKT {self.rx_pkt_no:03d}] type={pkt.type} '
                 f'seq={pkt.seq} ack={pkt.ack} '
                 f'payload_len={len(pkt.payload)} '
                 f'crc={"OK" if pkt.crc_ok else "FAIL"}')
        if pkt.payload:
            hexdump(pkt.payload, "[PKT]  ")

        if pkt.type != 'DATA':
            return
        if not pkt.crc_ok:
            self.log('[!] CRC FAIL — dropping packet')
            return

        # ACK the client's packet and update client_ack before processing
        # so that service replies built in this iteration use the correct value
        self.client_ack = (pkt.seq + 1) & 0x7F
        ack_pkt = build_ack_packet(self.client_ack)
        self.send_packet(ack_pkt, f"ACK seq={pkt.seq} ack_field={self.client_ack}")

        # Process pipe frames
        frames = parse_pipe_frames(pkt.payload)
        for pf in frames:
            self.pipe_buffers[pf.pipe_idx].extend(pf.content)

            if pf.last_data:
                assembled = bytes(self.pipe_buffers[pf.pipe_idx])
                self.pipe_buffers[pf.pipe_idx].clear()
                self.log(f'[PIPE] MESSAGE pipe={pf.pipe_idx} assembled_len={len(assembled)}')

                if pf.pipe_idx == 0:
                    self._handle_pipe0_message(assembled)
                else:
                    self._handle_service_data(pf.pipe_idx, assembled)

    def _handle_pipe0_message(self, assembled):
        """Route a pipe-0 message by its routing prefix."""
        msg = parse_pipe0_content(assembled)
        if msg is None:
            return

        if isinstance(msg, ControlMessage):
            self._handle_control(msg)
        elif isinstance(msg, PipeOpenRequest):
            self._handle_pipe_open(msg)
        elif isinstance(msg, PipeData):
            self._handle_service_data(msg.pipe_idx, msg.data)

    def _handle_control(self, msg):
        """Handle control frames (type-1 echo, type-4 ack)."""
        self.log(f'[PIPE] CONTROL type={msg.ctrl_type} data_len={len(msg.data)}')

        if msg.ctrl_type == 1:
            echo_pkt = build_control_type1_ack(
                self.server_seq, self.client_ack, msg.data)
            self.send_packet(echo_pkt,
                f"Control type-1 echo (seq={self.server_seq})")
            self.advance_seq()

    def _handle_pipe_open(self, msg):
        """Respond to a pipe-open request and send service discovery."""
        self.log(f'[PIPE] OPEN REQUEST: pipe_idx={msg.client_pipe_idx} '
                 f'svc={msg.svc_name!r} ver={msg.ver_param!r} version={msg.version}')

        open_pkt = build_pipe_open_result(msg.client_pipe_idx, self.server_seq, self.client_ack)
        self.send_packet(open_pkt,
            f"Pipe open RESPONSE for pipe {msg.client_pipe_idx} svc={msg.svc_name!r}")
        self.advance_seq()

        handler_cls = SERVICE_HANDLERS.get(msg.svc_name)
        if handler_cls:
            handler = handler_cls(msg.client_pipe_idx, msg.svc_name)
            self.services[msg.client_pipe_idx] = handler

            time.sleep(DELAY_BEFORE_REPLY)
            discovery_pkt = handler.build_discovery_packet(
                self.server_seq, self.client_ack)
            self.send_packet(discovery_pkt,
                f"{msg.svc_name} discovery for pipe {msg.client_pipe_idx}")
            self.advance_seq()

    def _handle_service_data(self, pipe_idx, data):
        """Unified service dispatch — handles data for any pipe."""
        if len(data) == 1 and data[0] == PIPE_CLOSE_CMD:
            self.log(f'[SVC] pipe-close on pipe {pipe_idx}')
            self.pipes_closed.add(pipe_idx)
            self.pipe_buffers.pop(pipe_idx, None)
            if self._all_service_pipes_closed():
                self.log('[*] All service pipes closed — disconnecting')
                self.conn.close()
                raise ConnectionError("All pipes closed")
            return

        handler = self.services.get(pipe_idx)
        if not handler:
            self.log(f'[SVC] No handler for pipe {pipe_idx}, ignoring')
            return

        hb = parse_host_block(data)
        if not hb:
            self.log(f'[SVC] Unparseable host block on pipe {pipe_idx}')
            return

        self.log(f'[SVC] pipe={pipe_idx} service={handler.svc_name!r} '
                 f'class=0x{hb.msg_class:02x} selector=0x{hb.selector:02x} '
                 f'req_id={hb.request_id} payload_len={len(hb.payload)}')
        if hb.payload:
            hexdump(hb.payload, "[SVC]  ")

        time.sleep(DELAY_BEFORE_REPLY)
        reply_pkt = handler.handle_request(
            hb.msg_class, hb.selector, hb.request_id,
            hb.payload, self.server_seq, self.client_ack)

        if reply_pkt is not None:
            self.send_packet(reply_pkt,
                f"{handler.svc_name} reply for pipe {pipe_idx} "
                f"class=0x{hb.msg_class:02x} selector=0x{hb.selector:02x} "
                f"req_id={hb.request_id}")
            self.advance_seq()
        else:
            self.log(f'[SVC] No reply for selector=0x{hb.selector:02x} '
                     f'(pending request)')

    def _all_service_pipes_closed(self):
        """Check if all registered service pipes have been closed."""
        if not self.services:
            return False
        return all(idx in self.pipes_closed for idx in self.services)


def handle_connection(conn, addr):
    """Entry point for a new TCP connection."""
    print(f'[*] Connection from {addr}')
    conn_start = time.monotonic()
    try:
        state = ConnectionState(conn, addr)
        state.run()
    except (ConnectionError, BrokenPipeError, OSError):
        elapsed = time.monotonic() - conn_start
        print(f'[{elapsed:7.3f}] [!] Connection closed')
    finally:
        try:
            conn.close()
        except OSError:
            pass
    print(f'[*] Connection from {addr} closed')
