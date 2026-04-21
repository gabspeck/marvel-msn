"""Connection handler: the main event loop for a single client connection.

Manages the protocol state machine from telnet negotiation through
login, directory browsing, and sign-out.
"""

import contextlib
import itertools
import logging
import time
from collections import defaultdict

from . import log as server_log
from .config import (
    DELAY_AFTER_COM,
    DELAY_BEFORE_REPLY,
    PACKET_TERMINATOR,
    PIPE_CLOSE_CMD,
    SOCKET_TIMEOUT,
)
from .models import ControlMessage, PipeData, PipeOpenRequest
from .mpc import (
    build_control_type1_ack,
    build_pipe_open_result,
    parse_host_block,
)
from .pipe import parse_pipe0_content, parse_pipe_frames
from .services import SERVICE_HANDLERS
from .transport import build_ack_packet, build_transport_params, parse_packet

log = logging.getLogger(__name__)

_PIPE_CTRL_NAMES = {1: "echo", 4: "ack"}

_conn_id_seq = itertools.count(1)


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

    def __init__(self, conn):
        self.conn = conn
        self.conn_start = time.monotonic()
        self.event_no = 0
        self.rx_pkt_no = 0
        self.tx_pkt_no = 0
        self.server_seq = 1  # seq 0 used for transport params
        self.client_ack = 0
        self.services = {}
        self.pipe_buffers = defaultdict(bytearray)
        self.pipes_closed = set()
        self.buf = bytearray()
        self.transport_started = False

    def _emit(self, level, msg, *args):
        if not log.isEnabledFor(level):
            return
        self.event_no += 1
        server_log.set_context(time.monotonic() - self.conn_start, self.event_no)
        log.log(level, msg, *args)

    def info(self, msg, *args):
        self._emit(logging.INFO, msg, *args)

    def debug(self, msg, *args):
        self._emit(logging.DEBUG, msg, *args)

    def warning(self, msg, *args):
        self._emit(logging.WARNING, msg, *args)

    def trace_hex(self, label, data):
        if log.isEnabledFor(server_log.TRACE):
            self._emit(server_log.TRACE, "%s len=%d hex=%s", label, len(data), data.hex())

    def _send(self, pkt, level, msg, *args):
        """`msg` must start with `n=%d` — tx_pkt_no is injected as the first arg."""
        self.tx_pkt_no += 1
        self._emit(level, msg, self.tx_pkt_no, *args)
        self.trace_hex("tx_bytes", pkt)
        self.conn.sendall(pkt)

    def advance_seq(self):
        seq = self.server_seq
        self.server_seq = (self.server_seq + 1) & 0x7F
        return seq

    def run(self):
        self.info("awaiting_initial_cr")
        self.conn.settimeout(SOCKET_TIMEOUT)

        while True:
            try:
                data = self.conn.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                break
            if not data:
                break

            self.trace_hex("rx_bytes", data)

            if not self.transport_started:
                data = _strip_telnet(data, self.conn)

            self.buf.extend(data)

            while True:
                idx = self.buf.find(PACKET_TERMINATOR)
                if idx == -1:
                    break
                packet_data = bytes(self.buf[:idx])
                del self.buf[: idx + 1]

                if not packet_data:
                    if not self.transport_started:
                        self._do_handshake()
                    continue

                self._handle_raw_packet(packet_data)

    def _do_handshake(self):
        """Send COM\\r and transport params."""
        self.info("rx_empty_terminator")
        self.info("tx_com_trigger")
        self.conn.sendall(b"COM\r")
        time.sleep(DELAY_AFTER_COM)

        params_pkt = build_transport_params()
        self._send(params_pkt, logging.INFO, "tx_transport_params n=%d len=%d", len(params_pkt))
        self.transport_started = True

    def _handle_raw_packet(self, packet_data):
        pkt = parse_packet(packet_data)
        if pkt is None:
            self.warning("unparseable_packet len=%d", len(packet_data))
            return

        self.rx_pkt_no += 1
        self.info(
            "rx_packet n=%d type=%s seq=%s ack=%s payload_len=%d crc=%s",
            self.rx_pkt_no,
            pkt.type,
            pkt.seq,
            pkt.ack,
            len(pkt.payload),
            "ok" if pkt.crc_ok else "fail",
        )
        if pkt.payload:
            self.trace_hex("rx_payload", pkt.payload)

        if pkt.type != "DATA":
            return
        if not pkt.crc_ok:
            self.warning("crc_fail action=drop")
            return

        # ACK the client's packet and update client_ack before processing
        # so that service replies built in this iteration use the correct value
        self.client_ack = (pkt.seq + 1) & 0x7F
        ack_pkt = build_ack_packet(self.client_ack)
        self._send(ack_pkt, logging.DEBUG, "tx_ack n=%d seq=%d ack=%d", pkt.seq, self.client_ack)

        # Process pipe frames
        frames = parse_pipe_frames(pkt.payload)
        for pf in frames:
            self.pipe_buffers[pf.pipe_idx].extend(pf.content)

            if pf.last_data:
                assembled = bytes(self.pipe_buffers[pf.pipe_idx])
                self.pipe_buffers[pf.pipe_idx].clear()

                if pf.pipe_idx == 0:
                    self._handle_pipe0_message(assembled)
                else:
                    self._handle_service_data(pf.pipe_idx, assembled)

    def _handle_pipe0_message(self, assembled):
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
        ctrl_name = _PIPE_CTRL_NAMES.get(msg.ctrl_type, f"0x{msg.ctrl_type:02x}")
        self.info("pipe_control type=%s data_len=%d", ctrl_name, len(msg.data))

        if msg.ctrl_type == 1:
            echo_pkt = build_control_type1_ack(self.server_seq, self.client_ack, msg.data)
            self._send(
                echo_pkt,
                logging.INFO,
                "tx_pipe_echo n=%d seq=%d len=%d",
                self.server_seq,
                len(echo_pkt),
            )
            self.advance_seq()

    def _handle_pipe_open(self, msg):
        self.info(
            "pipe_open pipe=%d svc=%s ver_param=%s version=%d",
            msg.client_pipe_idx,
            msg.svc_name,
            msg.ver_param,
            msg.version,
        )

        open_pkt = build_pipe_open_result(msg.client_pipe_idx, self.server_seq, self.client_ack)
        self._send(
            open_pkt,
            logging.INFO,
            "tx_pipe_open_response n=%d pipe=%d svc=%s",
            msg.client_pipe_idx,
            msg.svc_name,
        )
        self.advance_seq()

        handler_cls = SERVICE_HANDLERS.get(msg.svc_name)
        if handler_cls is None:
            self.warning(
                "pipe_open_unknown_service pipe=%d svc=%s version=%d",
                msg.client_pipe_idx,
                msg.svc_name,
                msg.version,
            )
        if handler_cls:
            handler = handler_cls(msg.client_pipe_idx, msg.svc_name)
            self.services[msg.client_pipe_idx] = handler

            time.sleep(DELAY_BEFORE_REPLY)
            discovery_pkts = handler.build_discovery_packet(self.server_seq, self.client_ack)
            total = len(discovery_pkts)
            for i, pkt in enumerate(discovery_pkts, 1):
                self._send(
                    pkt,
                    logging.INFO,
                    "tx_discovery n=%d pipe=%d svc=%s frag=%d/%d len=%d",
                    msg.client_pipe_idx,
                    msg.svc_name,
                    i,
                    total,
                    len(pkt),
                )
                self.advance_seq()

    def _handle_service_data(self, pipe_idx, data):
        if len(data) == 1 and data[0] == PIPE_CLOSE_CMD:
            self.info("pipe_close pipe=%d", pipe_idx)
            self.pipes_closed.add(pipe_idx)
            self.pipe_buffers.pop(pipe_idx, None)
            if self._all_service_pipes_closed():
                self.info("all_pipes_closed action=disconnect")
                self.conn.close()
                raise ConnectionError("All pipes closed")
            return

        handler = self.services.get(pipe_idx)
        if not handler:
            self.warning("no_handler pipe=%d action=ignore", pipe_idx)
            return

        hb = parse_host_block(data)
        if not hb:
            self.warning("unparseable_host_block pipe=%d", pipe_idx)
            return

        self.info(
            "svc_request pipe=%d svc=%s class=0x%02x selector=0x%02x req_id=%d payload_len=%d",
            pipe_idx,
            handler.svc_name,
            hb.msg_class,
            hb.selector,
            hb.request_id,
            len(hb.payload),
        )
        if hb.payload:
            self.trace_hex("svc_payload", hb.payload)

        time.sleep(DELAY_BEFORE_REPLY)
        reply_pkts = handler.handle_request(
            hb.msg_class, hb.selector, hb.request_id, hb.payload, self.server_seq, self.client_ack
        )

        if reply_pkts is not None:
            total = len(reply_pkts)
            for i, pkt in enumerate(reply_pkts, 1):
                self._send(
                    pkt,
                    logging.INFO,
                    "tx_svc_reply n=%d pipe=%d svc=%s class=0x%02x selector=0x%02x "
                    "req_id=%d frag=%d/%d len=%d",
                    pipe_idx,
                    handler.svc_name,
                    hb.msg_class,
                    hb.selector,
                    hb.request_id,
                    i,
                    total,
                    len(pkt),
                )
                self.advance_seq()
        else:
            self.info("svc_no_reply pipe=%d selector=0x%02x", pipe_idx, hb.selector)

    def _all_service_pipes_closed(self):
        if not self.services:
            return False
        return all(idx in self.pipes_closed for idx in self.services)


def handle_connection(conn, addr):
    server_log.reset_context()
    server_log.set_connection(next(_conn_id_seq))
    log.info("connection_open addr=%s:%d", addr[0], addr[1])
    try:
        ConnectionState(conn).run()
    except (ConnectionError, BrokenPipeError, OSError) as e:
        log.info("connection_closed addr=%s:%d reason=%s", addr[0], addr[1], type(e).__name__)
    finally:
        with contextlib.suppress(OSError):
            conn.close()
        server_log.reset_context()
        server_log.clear_connection()
