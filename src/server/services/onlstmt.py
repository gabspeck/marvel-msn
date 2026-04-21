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
import logging
import struct

from ..config import (
    MPC_CLASS_ONEWAY_MASK,
    ONLSTMT_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_END_STATIC,
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
from ..store import app_store as _default_store

log = logging.getLogger(__name__)


def build_summary_payload():
    """Build the statement-summary reply for selector=0x00.

    Request wire has exactly 7 recv tags (no 0x84), so the reply is 7
    tagged primitives and nothing else — unlike LOGSRV bootstrap which
    has an extra 0x84 recv tag from m48 and therefore ends in
    0x87 + 0x84 var.
    """
    statement = _default_store.statement
    s = statement.get_summary()
    period_count = statement.period_count()
    log.info(
        "statement_summary_reply balance_cents=%d currency=%d date=%04d-%02d-%02d"
        " free_minutes=%d period_count=%d",
        s.balance_cents,
        s.currency_iso,
        s.year,
        s.month,
        s.day,
        s.free_connect_minutes,
        period_count,
    )
    return b"".join(
        [
            build_tagged_reply_dword(s.balance_cents),
            build_tagged_reply_word(s.currency_iso),
            build_tagged_reply_word(s.year),
            build_tagged_reply_byte(s.month),
            build_tagged_reply_byte(s.day),
            build_tagged_reply_word(s.free_connect_minutes),
            build_tagged_reply_byte(max(period_count - 1, 0)),
        ]
    )


_STMT_EPOCH = datetime.datetime(1970, 1, 1)
_DAYS_WIRE_BIAS = 0x10000 - 0x9C21  # 0x63df = 25567


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


def _encode_record(when, description, amount, total, extra=None, foreign=None):
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
        parts.append(
            struct.pack("<IHI", fx_amount & 0xFFFFFFFF, fx_currency & 0xFFFF, fx_rate & 0xFFFFFFFF)
        )
    return b"".join(parts)


# Header string read once at blob start (into local_38 at 0x7f352292);
# prepended to each flag-0x02 annotation line as "\r\n<header> ".
_DETAILS_HEADER = b"Exchange rate:\x00"


def build_details_payload(period_index):
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
    txns = _default_store.statement.get_transactions(period_index)
    records = [
        _encode_record(
            t.when, t.description, t.amount_minor, t.total_minor, extra=t.extra, foreign=t.foreign
        )
        for t in txns
    ]
    sample = ",".join(
        f'{t.when.strftime("%Y-%m-%dT%H:%M")}|{t.description!r}|amt={t.amount_minor}|tot={t.total_minor}'
        for t in txns[:3]
    )
    log.info(
        "get_details_reply period=%d record_count=%d currency=840 txns=[%s%s]",
        period_index,
        len(records),
        sample,
        "" if len(txns) <= 3 else f",...+{len(txns) - 3}",
    )
    blob = _DETAILS_HEADER + b"".join(records)
    return b"".join(
        [
            build_tagged_reply_word(len(records)),
            build_tagged_reply_word(840),  # slot-10 currency: USD
            bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]),
            blob,  # dynamic-complete: no length prefix
        ]
    )


def _encode_subscription_record(sub):
    """Encode one entry inside the Subscriptions 0x84 variable buffer.

    Layout walked by FetchSubscriptionList at 0x7f35435b (filling each
    listbox row) and re-read by the Remove-button branch in the
    Subscriptions DLGPROC at 0x7f353c4e (deciding what to do):

        byte    kind            see table below — drives both rendering
                                and Remove behavior
        bytes   pad[12]         unused by the main render loop
        word    record_currency at offset 0x0d, ISO 4217 numeric;
                                appended via LoadCurrencyName when the
                                row's price is non-zero
        cstr    name            NUL-terminated, main listbox line
        cstr    detail          NUL-terminated, detail text
        dword   price_minor     formatted in slot-0xb currency, minor
                                units; 0 suppresses the price column
        word    price_currency  fed to ConfigureCurrencySlot(0xb) so
                                GetCurrencyFormatA renders the row's
                                amount with the right symbol/format

    kind semantics (the only byte the client actually branches on):

        +------+-------------------------+------------------------------+
        | kind | listbox rendering       | Remove-button result         |
        +------+-------------------------+------------------------------+
        | 0x01 | "<name> ** expires **   | LoadString 0x29 →            |
        |      | <first-date>"           | "cannot remove your current  |
        |      | (uses slots 5/6/7 from  | subscription online"         |
        |      | the static reply)       | (the Premium/active row)     |
        +------+-------------------------+------------------------------+
        | 0x02 | "<name> ** effective ** | confirm dialog → fires       |
        |      | <second-date>"          | OnlStmt cancel selector 0x04 |
        |      | (uses slots 8/9/10)     | with the row's currency word |
        |      |                         | as the cancel ID; the *only* |
        |      |                         | flag actually cancellable    |
        +------+-------------------------+------------------------------+
        | 0x04 | plain "<name>" with     | LoadString 0x2c →            |
        |      | no date column          | the credits-can't-be-removed |
        |      |                         | message; used for promo/     |
        |      |                         | welcome credits              |
        +------+-------------------------+------------------------------+
        | else | plain "<name>" with     | LoadString 0x2d →            |
        |      | no date column          | generic "cannot remove"      |
        |      |                         | catch-all                    |
        +------+-------------------------+------------------------------+

    Source: kind is read at piVar5[-1] in both the row-builder
    (FUN_7f35435b second loop) and the Remove handler (FUN_7f353c4e
    control 0x3ef branch).  The cancel path calls FUN_7f354e24(this,
    0xffff) which posts an MPC request on selector 0x04.
    """
    return (
        bytes([sub.kind & 0xFF])
        + b"\x00" * 12
        + struct.pack("<H", sub.record_currency & 0xFFFF)
        + sub.name.encode("ascii")
        + b"\x00"
        + sub.detail.encode("ascii")
        + b"\x00"
        + struct.pack("<IH", sub.price_minor & 0xFFFFFFFF, sub.price_currency & 0xFFFF)
    )


def build_subscriptions_payload():
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
        2  dword account_balance_cents  formatted via slot-3 currency
        3  word  balance_currency    ISO 4217; gate ≠ 0 else error 0x1e.
                                     Also seeds the threshold-notification
                                     currency at HKCU\\...\\OnlineStatement\
                                     Notification Currency when registry
                                     value is missing — a wrong code shows
                                     "unknown currency" on the threshold
                                     line at the bottom of the tab.
        4  byte  flag                stored on dialog state +0x0c; purpose
                                     unclear, must be non-zero.
        5  word  first_date_year     → SYSTEMTIME.wYear rendered as the
        6  byte  first_date_month      "expires"/"effective" date for
        7  byte  first_date_day        type_flag 0x01 rows
        8  word  second_date_year    → SYSTEMTIME.wYear rendered as the
        9  byte  second_date_month     date appended to type_flag 0x02
        10 byte  second_date_day       rows; 0 suppresses
    """
    subs = _default_store.statement.get_subscriptions()
    records_blob = b"".join(_encode_subscription_record(s) for s in subs)
    sample = ",".join(
        f"kind=0x{s.kind:02x}|{s.name!r}|price={s.price_minor}|cur={s.price_currency}"
        for s in subs[:3]
    )
    log.info(
        "subscriptions_reply count=%d balance_cents=495 currency=840"
        " first_date=2026-12-31 second_date=2026-05-01 subs=[%s%s]",
        len(subs),
        sample,
        "" if len(subs) <= 3 else f",...+{len(subs) - 3}",
    )
    return b"".join(
        [
            build_tagged_reply_byte(len(subs)),
            build_tagged_reply_var(0x84, records_blob),
            build_tagged_reply_dword(495),
            build_tagged_reply_word(840),  # balance currency: USD
            build_tagged_reply_byte(1),
            build_tagged_reply_word(2026),  # first-date year
            build_tagged_reply_byte(12),  # first-date month
            build_tagged_reply_byte(31),  # first-date day
            build_tagged_reply_word(2026),  # second-date year
            build_tagged_reply_byte(5),  # second-date month
            build_tagged_reply_byte(1),  # second-date day
            bytes([TAG_END_STATIC]),
        ]
    )


def _encode_plan_record(plan):
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
        + struct.pack("<H", plan.plan_id & 0xFFFF)
        + plan.name.encode("ascii")
        + b"\x00"
        + plan.detail.encode("ascii")
        + b"\x00"
    )


def build_plans_payload():
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
    plans = _default_store.statement.get_plans()
    blob = b"".join(_encode_plan_record(p) for p in plans)
    sample = ",".join(f"id={p.plan_id}|{p.name!r}" for p in plans[:3])
    log.info(
        "plans_reply count=%d plans=[%s%s]",
        len(plans),
        sample,
        "" if len(plans) <= 3 else f",...+{len(plans) - 3}",
    )
    return b"".join(
        [
            build_tagged_reply_byte(len(plans)),
            build_tagged_reply_var(0x84, blob),
            bytes([TAG_END_STATIC]),
        ]
    )


# Cancel-subscription ack for selector=0x04.  Request wire: one
# send word (subscription token; client falls back to 0xFFFF when the
# record carries no per-row id in its pad region) + one 0x81 recv.
# Reply is a single tagged status byte + end-static.  The byte is
# returned all the way back from FUN_7f354e24 to the Subscriptions
# DLGPROC's Remove-button handler (FUN_7f353c4e at the cVar1==2
# branch), which treats `== 1` as success (refresh list) and anything
# else as failure (string 0x2d "Cannot remove subscription").
_CANCEL_ACK_PAYLOAD = b"".join(
    [
        build_tagged_reply_byte(1),
        bytes([TAG_END_STATIC]),
    ]
)


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

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch an OnlStmt request.  Returns a wire packet or None."""
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class,
                selector,
                len(payload),
            )
            return None

        if selector == 0x00:
            log.info("statement_summary")
            reply_payload = build_summary_payload()
        elif selector == 0x02:
            log.info("subscriptions")
            reply_payload = build_subscriptions_payload()
        elif selector == 0x03:
            log.info("manage_subscription")
            reply_payload = build_plans_payload()
        elif selector == 0x04:
            log.info("cancel_subscription")
            reply_payload = _CANCEL_ACK_PAYLOAD
            log.info("cancel_subscription_reply status=1")
        elif selector == 0x05:
            # Request payload: `01 NN ...` — first send param is the
            # period index byte.  Fall back to 0 (current) if absent.
            period = payload[1] if len(payload) >= 2 and payload[0] == 0x01 else 0
            log.info("get_details period=%d", period)
            reply_payload = build_details_payload(period)
        else:
            log.warning(
                "unhandled class=0x%02x selector=0x%02x req_id=%d payload_len=%d",
                msg_class,
                selector,
                request_id,
                len(payload),
            )
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
