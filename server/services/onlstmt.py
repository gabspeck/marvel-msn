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

Reply shape (static section, 7 tagged primitives):
    0x83 dword  — current balance in minor units (cents for USD);
                  formatted by MOSCL balance helper via
                  GetCurrencyFormatA using slot-9 currency.
    0x82 word   — ISO 4217 numeric currency code for slot 9 (the
                  balance formatter).  Must be ≠0 else ONLSTMT
                  shows error 0x1e.  Passed to LoadCurrencyName
                  (MOSCUDLL.DLL 0x7f661c33) which formats as
                  "%03d" and looks the string up in a small
                  hardcoded table — supported codes include
                  840 (USD), 826 (GBP), 392 (JPY), 280 (DEM)
                  etc.; unknown codes fall through to string id
                  0x82 "unknown currency".
    0x82 word   — year of statement date (e.g. 2026).
    0x81 byte   — month (1-12).
    0x81 byte   — day (1-31).
    0x82 word   — remaining free connect time in minutes; divided
                  by 60 at 7f351edf and formatted "%02u:%02u".
    0x81 byte   — highlighted row index (0-based; UI clamps
                  +1 to 1..4).
"""
from ..config import (
    ONLSTMT_INTERFACE_GUIDS, MPC_CLASS_ONEWAY_MASK, TAG_END_STATIC,
)
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
        build_tagged_reply_dword(1234),  # balance in cents -> "$12.34"
        build_tagged_reply_word(840),    # ISO currency code: USD
        build_tagged_reply_word(2026),   # statement year
        build_tagged_reply_byte(4),      # month
        build_tagged_reply_byte(1),      # day
        build_tagged_reply_word(90),     # free connect minutes -> 01:30
        build_tagged_reply_byte(0),      # highlight row
    ])


_SUMMARY_PAYLOAD = _build_summary_payload()


def _build_details_payload():
    """Build the Get-Details reply for selector=0x05.

    Request wire (after host block): `01 00 82 82 85`
        0x01 0x00  — send byte: selected period index (0 = current).
        0x82 0x82  — first = record count; second = ISO currency
                     code for slot 10 (transaction-list formatter).
        0x85       — dynamic recv descriptor (transaction list).

    Dispatched by ONLSTMT.EXE FUN_7f352292 from dialog 0x69's
    WM_INITDIALOG.  Record parser at 0x7f3523b0.

    Reply shape: two words + 0x87 end-static, **no dynamic tag**.
    MPCCL.ProcessTaggedServiceReply (0x04605187) only calls
    SignalRequestCompletion — which sets the +0x18 completion flag
    m10 waits on — when either:
      (a) a 0x86 'complete chunk' tag is processed, or
      (b) static section ends (0x87) and the host-block has no
          more bytes.
    Plain 0x85/0x88 tags only raise data-ready/stream-end events;
    they do NOT complete the request, so any reply ending in 0x85
    or 0x88 hangs the Retrieving dialog forever.

    record_count=0 → ONLSTMT shows "no transactions" string 0x10.
    Real records require encoding the parser's bit-flagged layout
    (see FUN_7f352292 for offsets) — a follow-up once the round
    trip is confirmed working.
    """
    return b"".join([
        build_tagged_reply_word(0),    # record count (0 → "no transactions")
        build_tagged_reply_word(840),  # slot-10 currency: USD
        bytes([TAG_END_STATIC]),
    ])


_DETAILS_PAYLOAD = _build_details_payload()


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
        elif selector == 0x05:
            print("  [OnlStmt] Get Details (selector 0x05)")
            reply_payload = _DETAILS_PAYLOAD
        else:
            print(f"  [OnlStmt] UNHANDLED class=0x{msg_class:02x} "
                  f"selector=0x{selector:02x} req_id={request_id} "
                  f"payload_len={len(payload)}")
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
