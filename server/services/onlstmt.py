"""OnlStmt (Online Statement) service handler.

Launched when the user clicks Tools > Billing > Summary of Charges in
the authenticated MSN shell, which spawns ONLSTMT.EXE.  The client
opens a pipe with svc_name="OnlStmt" (version 3), receives the
27-entry IID discovery map, then immediately makes a single RPC call
(class=0x01 selector=0x00) to fetch the statement summary.

Wire request (7 recv descriptor tags, no send params):
    83 82 82 81 81 82 81
Built by ONLSTMT.EXE:7f351c57 via proxy->m0c(0, ...) followed by
m18/m1c/m20 calls registering output slots, plus m48 for the
variable buffer.  The worker thread (GetStatementSummaryWorker @
7f35301c) calls m10(INFINITE) to dispatch and block the UI until
the reply arrives.

Reply shape (static section):
    0x83 dword  — status/balance placeholder (currently 0)
    0x82 word   — transaction count; must be ≠0 else client shows
                  error 0x1e ("cannot be obtained") per the
                  if (local_c != 0) gate at 7f351efd.
    0x82 word   — year of statement date
    0x81 byte   — month (1-12)
    0x81 byte   — day (1-31)
    0x82 word   — unknown (not read back; written to stack then
                  discarded — probably a prev/future balance)
    0x81 byte   — highlighted row index; clamped to 1-4 after
                  +1 adjustment at 7f351f24.
Then 0x87 end-of-static marker and a 0x84 variable payload that
carries the per-transaction records (layout TBD).
"""
from ..config import ONLSTMT_INTERFACE_GUIDS, MPC_CLASS_ONEWAY_MASK
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_byte,
    build_tagged_reply_dword,
    build_tagged_reply_word,
)


def _build_summary_payload():
    """Build the statement-summary reply for selector=0x00.

    Request wire has exactly 7 recv tags (no 0x84), so the reply is 7
    tagged primitives and nothing else — unlike LOGSRV bootstrap which
    has an extra 0x84 recv tag from m48 and therefore ends in
    0x87 + 0x84 var.
    """
    return b"".join([
        build_tagged_reply_dword(0),     # balance/status
        build_tagged_reply_word(1),      # txn count (≠0 or client shows 0x1e)
        build_tagged_reply_word(2026),   # statement year
        build_tagged_reply_byte(4),      # month
        build_tagged_reply_byte(1),      # day
        build_tagged_reply_word(0),      # unused/discarded
        build_tagged_reply_byte(0),      # highlight row (0-based; UI clamps +1 to 1..4)
    ])


_SUMMARY_PAYLOAD = _build_summary_payload()


class OnlStmtHandler:
    """Handles OnlStmt service requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        """Build the IID->selector discovery block for OnlStmt."""
        payload = build_discovery_payload(ONLSTMT_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload,
                       server_seq, client_ack):
        """Dispatch an OnlStmt request.  Returns a wire packet or None."""
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            print(f"  [OnlStmt] one-way continuation class=0x{msg_class:02x} "
                  f"selector=0x{selector:02x} payload_len={len(payload)}")
            return None

        if selector == 0x00:
            print("  [OnlStmt] Statement summary (selector 0x00)")
            reply_payload = _SUMMARY_PAYLOAD
        else:
            print(f"  [OnlStmt] UNHANDLED class=0x{msg_class:02x} "
                  f"selector=0x{selector:02x} req_id={request_id} "
                  f"payload_len={len(payload)}")
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
