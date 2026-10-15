"""Base class for pipe service handlers."""

from ..mpc import build_discovery_payload, build_host_block, build_service_packet


class ServiceHandler:
    """One service pipe.

    A subclass sets `GUIDS`, the discovery table it advertises, and implements
    `handle_request`, which returns the reply's wire packets or None when the
    call gets no reply. The connection calls the remaining hooks; each is a
    no-op unless the service overrides it.
    """

    GUIDS: list[tuple[bytes, int]] = []

    def __init__(self, pipe_idx, svc_name, session):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous until LOGSRV signs the connection in; a pipe can open first.
        self.session = session

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(self.GUIDS)
        return self.reply(0x00, 0x00, 0, payload, server_seq, client_ack)

    def reply(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """One host block answering a call, as wire packets."""
        host_block = build_host_block(msg_class, selector, request_id, payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def reply_blocks(self, msg_class, selector, request_id, payloads, server_seq, client_ack):
        """Several host blocks answering one call, sequence-numbered back to back."""
        packets = []
        for payload in payloads:
            seq = (server_seq + len(packets)) & 0x7F
            packets.extend(self.reply(msg_class, selector, request_id, payload, seq, client_ack))
        return packets

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        raise NotImplementedError

    def bind_connection(self, connection):
        """Called once after the pipe opens, before discovery. Services that
        push outside a request keep `connection` to reach the client."""

    def handle_iterator_cancel(self, msg_class, selector, request_id):
        """An MPCCL iterator-cancel arrived for a stream this pipe opened. The
        connection sends the ack."""

    def flush_pending_events(self):
        """Called after each request, outside the connection's send lock."""

    def close(self):
        """The pipe or the connection closed."""
