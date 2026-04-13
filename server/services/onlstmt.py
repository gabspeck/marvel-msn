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
    0x81 byte   — period count minus 1 (0..3).  Stored at
                  this[0xe5] as `byte + 1` clamped to max 4.
                  Drives the Get-Details period listbox 0x414
                  populated by FUN_7f351fd2 — N entries: current
                  period plus N-1 prior calendar months walked
                  backwards from the statement date.
"""
import datetime
import struct

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
    build_tagged_reply_var,
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
        build_tagged_reply_dword(1904),  # balance in cents -> "$19.04"
        build_tagged_reply_word(840),    # ISO currency code: USD
        build_tagged_reply_word(2026),   # statement year
        build_tagged_reply_byte(4),      # month
        build_tagged_reply_byte(1),      # day
        build_tagged_reply_word(90),     # free connect minutes -> 01:30
        build_tagged_reply_byte(3),      # period_count - 1 -> 4 periods
    ])


_SUMMARY_PAYLOAD = _build_summary_payload()


_STMT_EPOCH = datetime.datetime(1970, 1, 1)
_DAYS_WIRE_BIAS = 0x10000 - 0x9c21  # 0x63df = 25567


def _encode_timestamp(when):
    """Encode a datetime into (days_wire, minutes) per FetchStatementDetails.

    Client decodes seconds = ((days_wire + 0x9c21) & 0xFFFF) * 1440 * 60
    + minutes * 60, so days_wire must equal `days_since_1970 + 25567`
    modulo 0x10000 and the resulting ushort must be ≥ 0x63e0 — else
    the client zeroes the days and renders a 1970 date.
    """
    delta = when - _STMT_EPOCH
    days = delta.days
    minutes = delta.seconds // 60
    days_wire = (days + _DAYS_WIRE_BIAS) & 0xFFFF
    return days_wire, minutes


def _encode_record(when, description, amount, total,
                   extra=None, foreign=None):
    """Encode a single transaction record.

    Layout (FetchStatementDetails loop at 0x7f352292):
        byte  flags    (bit 0x01 = has trailing dword `extra`,
                        bit 0x02 = has 10-byte exchange-rate tail)
        word  days     (days-since-1970 + 0x63df; clamped by client)
        word  minutes  (clamped to 1440 = 0x5a0)
        NUL-terminated ASCII description
        dword amount   (minor units; formatted via slot-10 currency)
        dword total    (minor units; formatted via slot-10 currency)
        dword extra    (if flag 0x01; foreign-amount override when 0x02
                        is also set, else local-currency sub-amount)
        [exchange-rate tail if flag 0x02]:
            dword foreign_amount     (slot-11 currency, minor units)
            word  foreign_currency   (ISO 4217 numeric)
            dword rate               (slot-10 currency, 4 dp by default)

    When flag 0x02 is set the renderer appends a wrapped second line to
    the Description cell: "<header> <foreign_amt> <f-sym> * <rate>
    <local-sym> / 1 <f-sym>".  The header string is the blob-level
    prefix read once before the record loop.
    """
    days_wire, minutes = _encode_timestamp(when)
    flags = 0
    if extra is not None:
        flags |= 0x01
    if foreign is not None:
        flags |= 0x02
    desc_bytes = description.encode("ascii") + b"\x00"
    parts = [
        bytes([flags]),
        struct.pack("<HH", days_wire, minutes),
        desc_bytes,
        struct.pack("<II", amount & 0xFFFFFFFF, total & 0xFFFFFFFF),
    ]
    if extra is not None:
        parts.append(struct.pack("<I", extra & 0xFFFFFFFF))
    if foreign is not None:
        fx_amount, fx_currency, fx_rate = foreign
        parts.append(struct.pack("<IHI",
                                 fx_amount & 0xFFFFFFFF,
                                 fx_currency & 0xFFFF,
                                 fx_rate & 0xFFFFFFFF))
    return b"".join(parts)


# Header string read once at blob start (into local_38 at 0x7f352292);
# prepended to each flag-0x02 annotation line as "\r\n<header> ".
_DETAILS_HEADER = b"Exchange rate:\x00"


# Per-period transaction lists, indexed by the period byte the client
# sends as the first send param of selector=0x05.  Period 0 is the
# current statement; periods 1..N are prior calendar months walked
# backward by FUN_7f351fd2 from the statement date in the summary.
_DETAILS_RECORDS_BY_PERIOD = [
    # Period 0 — April 2026 (current statement, $19.04 balance).
    [
        _encode_record(datetime.datetime(2026, 4, 1, 9, 15),
                       "Monthly subscription", 495, 495),
        _encode_record(datetime.datetime(2026, 4, 5, 19, 42),
                       "Premium content access", 149, 644),
        _encode_record(datetime.datetime(2026, 4, 9, 14, 3),
                       "Chat room usage", 75, 719),
        # Flag-0x02 row: ¥1,000 charged at 0.0067 USD/JPY -> $6.70.
        # Slot-11 (JPY) NumDigits=0 so foreign dword is whole yen, not
        # minor units.  Slot-10 (USD) NumDigits=2 so amount/total are
        # cents.  Rate dword uses rate-digits precision (default 4dp)
        # so value 67 renders as "0.0067".
        _encode_record(datetime.datetime(2026, 4, 11, 12, 0),
                       "Tokyo content purchase", 670, 1389,
                       foreign=(1000, 392, 67)),
        _encode_record(datetime.datetime(2026, 4, 12, 22, 30),
                       "Online statement fee", 515, 1904),
    ],
    # Period 1 — March 2026.
    [
        _encode_record(datetime.datetime(2026, 3, 1, 8, 30),
                       "Monthly subscription", 495, 495),
        _encode_record(datetime.datetime(2026, 3, 14, 21, 5),
                       "Premium content access", 149, 644),
        _encode_record(datetime.datetime(2026, 3, 28, 23, 50),
                       "Online statement fee", 250, 894),
    ],
    # Period 2 — February 2026.
    [
        _encode_record(datetime.datetime(2026, 2, 1, 7, 45),
                       "Monthly subscription", 495, 495),
        _encode_record(datetime.datetime(2026, 2, 7, 18, 22),
                       "Game zone tournament entry", 200, 695),
        _encode_record(datetime.datetime(2026, 2, 18, 20, 11),
                       "Premium content access", 149, 844),
        _encode_record(datetime.datetime(2026, 2, 27, 22, 30),
                       "Online statement fee", 250, 1094),
    ],
    # Period 3 — January 2026.
    [
        _encode_record(datetime.datetime(2026, 1, 1, 10, 0),
                       "Monthly subscription", 495, 495),
        _encode_record(datetime.datetime(2026, 1, 19, 19, 17),
                       "Premium content access", 149, 644),
        _encode_record(datetime.datetime(2026, 1, 31, 23, 59),
                       "Online statement fee", 250, 894),
    ],
]


def _build_details_payload(records):
    """Build the Get-Details reply for selector=0x05.

    Request wire (after host block): `01 NN 82 82 85`
        0x01 NN    — send byte: selected period index (0 = current).
        0x82 0x82  — first = record count; second = ISO currency
                     code for slot 10 (transaction-list formatter).
        0x85       — dynamic recv descriptor (transaction list).

    Dispatched by ONLSTMT.EXE FetchStatementDetails (0x7f352292) from
    dialog 0x69's WM_INITDIALOG and again from its Period-listbox OK
    handler.  The period byte selects which calendar-month statement
    the client is asking for; the server is expected to return the
    transactions that fall within that period.

    Reply: two words static + 0x87 end-static + 0x86 dynamic-complete
    blob.  MPCCL.ProcessTaggedServiceReply (0x04605187) requires
    either a 0x86 tag or "static done + packet end" to call
    SignalRequestCompletion and set the +0x18 flag m10 waits on —
    0x85 or 0x88 alone would hang the Retrieving dialog forever.

    ReadDynamicSectionRawData (MPCCL 0x04605809) copies all bytes
    after the 0x86 tag verbatim; there is NO length prefix.

    Dynamic blob starts with a NUL-terminated ASCII *header string*
    (prefix used by the flag-0x02 exchange-rate formatter), read
    once before the record loop at 0x7f352292.
    """
    blob = _DETAILS_HEADER + b"".join(records)
    return b"".join([
        build_tagged_reply_word(len(records)),
        build_tagged_reply_word(840),   # slot-10 currency: USD
        bytes([TAG_END_STATIC]),
        b"\x86" + blob,                  # dynamic-complete: no length prefix
    ])


_DETAILS_PAYLOADS = [_build_details_payload(r) for r in _DETAILS_RECORDS_BY_PERIOD]


def _encode_subscription_record(type_flag, service_name, description,
                                price_cents, price_currency,
                                record_currency=0):
    """Encode one entry inside the Subscriptions 0x84 variable buffer.

    Layout walked by FetchSubscriptionList loop at 0x7f35435b:
        byte    type_flag       0x01 active | 0x02 cancelled | 0x04 pending
        bytes   pad[12]         unused by the main render loop
        word    record_currency at offset 0x0d, ISO 4217 numeric
        cstr    service_name    NUL-terminated, main listbox line
        cstr    description     NUL-terminated, detail text
        dword   price_cents     slot-0xb currency, minor units;
                                0 skips the currency format call
        word    price_currency  ConfigureCurrencySlot(0xb)
    """
    return (
        bytes([type_flag & 0xFF])
        + b"\x00" * 12
        + struct.pack("<H", record_currency & 0xFFFF)
        + service_name.encode("ascii") + b"\x00"
        + description.encode("ascii") + b"\x00"
        + struct.pack("<IH",
                      price_cents & 0xFFFFFFFF,
                      price_currency & 0xFFFF)
    )


_SUBSCRIPTIONS_RECORDS = [
    # type_flag 0x01 = current: rendered as "<name> ** expires ** <date>",
    # using the "first date" slots (5/6/7).  Remove on this row emits
    # error string 0x29 "cannot remove current subscription online".
    _encode_subscription_record(
        0x01, "MSN Premium", "Monthly subscription", 495, 840,
        record_currency=840),
    # type_flag 0x02 = pending/queued change: rendered as "<name>
    # ** effective ** <date>", using the "second date" slots (8/9/10).
    # Remove on this row hits the actual cancellation flow
    # (selector 0x04).
    _encode_subscription_record(
        0x02, "MSN Plus Games", "Gaming add-on pack", 299, 840,
        record_currency=840),
]


def _build_subscriptions_payload():
    """Build the Subscriptions-tab reply for selector=0x02.

    Request wire (all recv, no send params):
        81 84 83 82 81 82 81 81 82 81 81

    Dispatched by ONLSTMT.EXE FetchSubscriptionList (0x7f35435b) from
    the Subscriptions tab DLGPROC (0x7f353c4e) on PSN_SETACTIVE.

    Reply is a pure static section of 11 tagged primitives in recv
    order, terminated by 0x87 end-static.  No dynamic section.

    Slot mapping (traced through FetchSubscriptionList byte-by-byte):
        0  byte  sub_count           gate: 1..100 (>100 clamps + warn)
        1  var   subscription_blob   one record per subscription
        2  dword account_balance_cents  (formatted via slot-9 currency)
        3  word  start_year          gate: ≠ 0 else error 0x1e
        4  byte  start_month         gate: ≠ 0 else Change button stays
                                     disabled (EnableWindow predicate on
                                     `this[3]`); ≠ 0 enables control 0x3eb.
        5  word  first_date_year     → SYSTEMTIME.wYear rendered as the
        6  byte  first_date_month      "expires"/"effective" date for
        7  byte  first_date_day        type_flag 0x01 rows
        8  word  second_date_year    → SYSTEMTIME.wYear rendered as the
        9  byte  second_date_month     date appended to type_flag 0x02
        10 byte  second_date_day       rows; 0 suppresses
    """
    records_blob = b"".join(_SUBSCRIPTIONS_RECORDS)
    return b"".join([
        build_tagged_reply_byte(len(_SUBSCRIPTIONS_RECORDS)),
        build_tagged_reply_var(0x84, records_blob),
        build_tagged_reply_dword(495),     # account balance in cents
        build_tagged_reply_word(2026),     # start year (gate ≠ 0)
        build_tagged_reply_byte(4),        # start month (gate ≠ 0 enables Change)
        build_tagged_reply_word(2026),     # first-date year
        build_tagged_reply_byte(12),       # first-date month
        build_tagged_reply_byte(31),       # first-date day
        build_tagged_reply_word(2026),     # second-date year
        build_tagged_reply_byte(5),        # second-date month
        build_tagged_reply_byte(1),        # second-date day
        bytes([TAG_END_STATIC]),
    ])


_SUBSCRIPTIONS_PAYLOAD = _build_subscriptions_payload()


def _encode_plan_record(plan_id, name, detail):
    """Encode one entry inside the Manage-Subscription 0x84 plans buffer.

    Layout walked by FUN_7f354aa2 plan loop at 0x7f354b94:
        byte  flag        always 0x01 (only observed value; not read by
                          the listbox population loop, may gate detail
                          dialog behavior)
        word  plan_id     matched against the subscription's stored plan
                          id at this+0x6da+index*0xc to pre-select the
                          current row in listbox 0x418
        cstr  name        listbox display string
        cstr  detail      detail pane (control 0x427) text shown when
                          the row is selected
    """
    return (
        b"\x01"
        + struct.pack("<H", plan_id & 0xFFFF)
        + name.encode("ascii") + b"\x00"
        + detail.encode("ascii") + b"\x00"
    )


_PLAN_RECORDS = [
    _encode_plan_record(
        0, "MSN Premium",
        "$4.95/month, includes 3 hours of online time. "
        "Additional hours billed at $2.50/hour."),
    _encode_plan_record(
        1, "MSN Plus",
        "$19.95/month, unlimited online time."),
    _encode_plan_record(
        2, "MSN Annual",
        "$49.95/year, unlimited online time. Two months free."),
]


def _build_plans_payload():
    """Build the Manage-Subscription plans reply for selector=0x03.

    Request wire (after host block): `81 84`
        0x81  — recv byte: plan count (1..100; 0 → error string 0x14).
        0x84  — recv var: plans buffer (one record per plan).

    Dispatched by ONLSTMT.EXE FUN_7f354aa2 (the Subscriptions tab
    DLGPROC's Change-button branch) which spawns a worker thread to
    issue the call and then runs DialogBoxParam(0x68) to host the
    Manage-Subscription UI.

    Reply: byte + 0x84 var blob + 0x87 end-static.  No dynamic
    section.

    The plan whose `plan_id` matches the current subscription's
    stored id (read at this+0x6da+sub_idx*0xc) is auto-selected in
    listbox 0x418 and its detail text appears in control 0x427.
    Our subscriptions reply leaves the per-row pad zeroed, so plan
    id 0 is the current one.
    """
    blob = b"".join(_PLAN_RECORDS)
    return b"".join([
        build_tagged_reply_byte(len(_PLAN_RECORDS)),
        build_tagged_reply_var(0x84, blob),
        bytes([TAG_END_STATIC]),
    ])


_PLANS_PAYLOAD = _build_plans_payload()


# Cancel-subscription ack for selector=0x04.  Request wire: one
# send word (subscription token; client falls back to 0xFFFF when the
# record carries no per-row id in its pad region) + one 0x81 recv.
# Reply is a single tagged status byte + end-static.  The byte is
# returned all the way back from FUN_7f354e24 to the Subscriptions
# DLGPROC's Remove-button handler (FUN_7f353c4e at the cVar1==2
# branch), which treats `== 1` as success (refresh list) and anything
# else as failure (string 0x2d "Cannot remove subscription").
_CANCEL_ACK_PAYLOAD = b"".join([
    build_tagged_reply_byte(1),
    bytes([TAG_END_STATIC]),
])


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
        elif selector == 0x02:
            print("  [OnlStmt] Subscriptions (selector 0x02)")
            reply_payload = _SUBSCRIPTIONS_PAYLOAD
        elif selector == 0x03:
            print("  [OnlStmt] Manage subscription / plans (selector 0x03)")
            reply_payload = _PLANS_PAYLOAD
        elif selector == 0x04:
            print("  [OnlStmt] Cancel subscription (selector 0x04)")
            reply_payload = _CANCEL_ACK_PAYLOAD
        elif selector == 0x05:
            # Request payload: `01 NN ...` — first send param is the
            # period index byte.  Fall back to 0 (current) if absent.
            period = payload[1] if len(payload) >= 2 and payload[0] == 0x01 else 0
            if period >= len(_DETAILS_PAYLOADS):
                period = 0
            print(f"  [OnlStmt] Get Details (selector 0x05) period={period}")
            reply_payload = _DETAILS_PAYLOADS[period]
        else:
            print(f"  [OnlStmt] UNHANDLED class=0x{msg_class:02x} "
                  f"selector=0x{selector:02x} req_id={request_id} "
                  f"payload_len={len(payload)}")
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
