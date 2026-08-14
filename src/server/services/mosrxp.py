"""MOSRXP service handler: MSN remote mail.

MOSRXP32.DLL is the MAPI transport provider that ships with Windows 95, not
part of the MSN client update. `CConn` (docs/MOSRXP.md) is its wire client: it
CoCreates the MPC marshaller, opens a pipe on service `"MOSRXP"` version 2,
resolves IID 00028B20, and calls `GetMethod(<ServiceMethod>)` for each
operation. The method number lands on the wire as the request `selector`; the
class byte is the selector this server assigned that IID in discovery.

The client opens the pipe right after login and drives it from the Exchange
inbox: `FUN_7F437831` deletes whatever the user flagged for removal, downloads
the header list, and hands each header to the MAPI spooler; opening a message
fetches its body; sending mail streams the serialised message back in blocks.

Attachments are not served. Their content rides a compressed stream
(docs/MOSRXP.md §5) whose codec lives in MOSMUTIL, which has not been
reverse-engineered — every message this server serves declares PR_HASATTACH
false and an empty attachment list. A submitted message carrying one is stored
without it.
"""

import datetime
import logging
import struct

from ..config import (
    MOSRXP_INTERFACE_GUIDS,
    MPC_CLASS_CONTINUATION_LAST,
    MPC_CLASS_ONEWAY_MASK,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_END_STATIC,
)
from ..models import ChunkedParam, DwordParam, VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    build_tagged_reply_var,
    parse_request_params,
)
from ..session import Session
from ..store import MailMessage, MailRecipient
from ..store import app_store as _default_store
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)

# Interface class: the selector MOSRXP_INTERFACE_GUIDS gave IID 00028B20.
MOSRXP_CLASS_XP = 0x01

# `enum ServiceMethod`, read off the immediate each `CConn` member pushes
# before `HrGetMethod` @ 0x7F431967.
MOSRXP_GET_CONN_INFO = 0x00
MOSRXP_OPEN_INBOX = 0x01
MOSRXP_CLOSE_INBOX = 0x02
MOSRXP_INIT_TRANSMIT = 0x03
MOSRXP_SEND_BLOCK = 0x04
MOSRXP_GET_HEADERS = 0x05
MOSRXP_DEL_MESSAGES = 0x06
MOSRXP_GET_MESSAGE = 0x07
MOSRXP_GET_FIRST_MESSAGE = 0x08
MOSRXP_FLAG_SERVER_MESSAGE = 0x09

# MAPI property types `CConn::HrDSrlProp` @ 0x7F432435 decodes. Anything else
# aborts its parse with 0x1A, so these are the whole vocabulary.
PT_I2 = 0x02
PT_LONG = 0x03
PT_R4 = 0x04
PT_DOUBLE = 0x05
PT_CURRENCY = 0x06
PT_APPTIME = 0x07
PT_BOOLEAN = 0x0B
PT_I8 = 0x14
PT_STRING8 = 0x1E
PT_UNICODE = 0x1F
PT_SYSTIME = 0x40
PT_CLSID = 0x48
PT_BINARY = 0x102

_FIXED_WIDTHS = {
    PT_I2: 2,
    PT_LONG: 4,
    PT_R4: 4,
    PT_DOUBLE: 8,
    PT_CURRENCY: 8,
    PT_APPTIME: 8,
    PT_BOOLEAN: 2,
    PT_I8: 8,
    PT_SYSTIME: 8,
    PT_CLSID: 16,
}

# The 12 tags `MOSMUTIL!PSptaHdr` @ 0x7E991297 returns, in array order. A
# header record carries exactly this set: `FIsHeaderProp` is a linear search
# over it, and it is what splits a serialised message's first property list
# from its third.
PR_OBJECT_TYPE = 0x0FFE0003
PR_MSG_STATUS = 0x0E170003
PR_MESSAGE_FLAGS = 0x0E070003
PR_MESSAGE_CLASS = 0x001A001E
PR_IMPORTANCE = 0x00170003
PR_SENT_REPRESENTING_NAME = 0x0042001E
PR_DISPLAY_TO = 0x0E04001E
PR_SENSITIVITY = 0x00360003
PR_HASATTACH = 0x0E1B000B
PR_SUBJECT = 0x0037001E
PR_MESSAGE_DELIVERY_TIME = 0x0E060040
PR_MESSAGE_SIZE = 0x0E080003

# Body-side props: everything `FIsHeaderProp` rejects.
PR_BODY = 0x1000001E
PR_CLIENT_SUBMIT_TIME = 0x00390040
PR_SENDER_NAME = 0x0C1A001E
PR_SENDER_ADDRTYPE = 0x0C1E001E
PR_SENDER_EMAIL_ADDRESS = 0x0C1F001E
PR_SENDER_SEARCH_KEY = 0x0C1D0102
PR_SENT_REPRESENTING_ADDRTYPE = 0x0064001E
PR_SENT_REPRESENTING_EMAIL_ADDRESS = 0x0065001E

# Recipient (ADRENTRY) props.
PR_RECIPIENT_TYPE = 0x0C150003
PR_DISPLAY_NAME = 0x3001001E
PR_ADDRTYPE = 0x3002001E
PR_EMAIL_ADDRESS = 0x3003001E

MAPI_MESSAGE = 5
MAPI_MAILUSER = 6
MSGFLAG_UNMODIFIED = 0x02
IMPORTANCE_NORMAL = 1
SENSITIVITY_NONE = 0
MESSAGE_CLASS_NOTE = "IPM.Note"

# PR_MSG_STATUS bit the client sets through FlagServerMessage to queue a
# server-side delete for the next connection. `FUN_7F4361BB` @ 0x7F4361BB
# restricts its own store on it and calls DelMessages before downloading
# headers, so the server never acts on the flag itself.
MSGSTATUS_REMOTE_DELETE = 0x2000

# The address types this transport claims, from the pointer array at
# 0x7F43CE90. `HrCompleteTransmit` marks a recipient PR_RESPONSIBILITY only
# when its PR_ADDRTYPE matches one of these, so anything else is another
# provider's delivery and never reaches us.
MOSRXP_ADDRTYPE = "MSN"
TRANSPORT_ADDRTYPES = (MOSRXP_ADDRTYPE, "MSNLIST", "MSNINET", "INTERNET", "SMTP")

# Reply tag for a variable param. The client declares the slot with a `0x84`
# receive descriptor (`IMosMethod` slot +0x14).
TAG_REPLY_VAR = 0x84

# CONNINFO, the 0xB8-byte blob method 0 answers with, is a `_usr_entryid` —
# same structure `MOSMUTIL!HrBuildUeid` @ 0x7E991036 builds for the address
# book, and the same length. Layout: abFlags, provider MAPIUID, version 2,
# EIDTYPE, then two fixed-width name fields.
CONNINFO_LEN = 0xB8
UEID_PROVIDER_UID = bytes.fromhex("1becba6c5f92101bb93d00000b70346a")
UEID_VERSION = 2
UEID_DISPLAY_NAME_OFFSET = 0x1C
UEID_DISPLAY_NAME_MAX = 0x5B
UEID_MEMBER_NAME_OFFSET = 0x77
UEID_MEMBER_NAME_MAX = 0x41
# EIDTYPE 1 keys the entry id on the member name at +0x77. MOSABP32 branches on
# `ueid[0x18] == 4` to pick its account-handle lookup instead, so type 1 is what
# routes a Member Properties sheet opened on this sender to MOSABP method 2.
EIDTYPE_MEMBER_NAME = 1

# 12-byte MOS_ENTRYID. The client memcpys it out of a header record and hands
# it back verbatim on GetMessage / DelMessages / FlagServerMessage without ever
# reading inside, so the layout is ours: version, message id, reserved.
MOS_ENTRYID_LEN = 0x0C
MOS_ENTRYID_VERSION = 1

# Transmit block size the client asks for in InitTransmit. A message larger
# than this arrives as several SendBlock calls; the split is not
# record-aligned, so only the concatenation parses.
_TRANSMIT_BLOCK_BYTES = 0x1000

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)

MAPI_E_NOT_FOUND = 0x8004010F


class ChunkStream:
    """Bytes of one chunked field, gathered from its class-0xE6/0xE7 frames."""

    def __init__(self):
        self.data = b""
        self.complete = False


class MOSRXPHandler:
    """Handles remote-mail requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands — which is the
        # normal case: the client opens this pipe immediately after LOGSRV.
        self.session = session or Session()
        # Blocks of the message currently being submitted, in arrival order.
        # A submit runs InitTransmit → SendBlock… on one pipe and the handler
        # lives as long as that pipe, so the buffer belongs here.
        self._blocks = []
        self._submit_done = False
        # Chunked-field streams, stream_id → ChunkStream. A SendBlock payload
        # is 4 KB, which never fits the inline request body, so every block
        # arrives quoted as a reference and carried on 0xE6/0xE7 frames.
        self._streams = {}

    @property
    def mailbox(self):
        return self.session.user.username

    def build_discovery_packet(self, server_seq, client_ack):
        """Advertise IID 00028B20 — the only interface MOSRXP32 resolves.

        `HrGetMethod` bails to E_NOINTERFACE before any request reaches the
        wire if this reply omits it, which is what a client sitting on an open
        MOSRXP pipe with no traffic on it is waiting for.
        """
        payload = build_discovery_payload(MOSRXP_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch by (interface class, ServiceMethod).

        Class 0xE6/0xE7 are not calls. They carry the body of a SendBlock field
        the request head was too small to hold, and expect no reply.
        """
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            self._take_continuation(msg_class, selector, payload)
            return None

        if msg_class != MOSRXP_CLASS_XP:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        if selector == MOSRXP_GET_CONN_INFO:
            reply_payload = self._get_conn_info(payload)
        elif selector == MOSRXP_OPEN_INBOX:
            reply_payload = self._open_inbox(payload)
        elif selector == MOSRXP_CLOSE_INBOX:
            reply_payload = self._close_inbox(payload)
        elif selector == MOSRXP_INIT_TRANSMIT:
            reply_payload = self._init_transmit(payload)
        elif selector == MOSRXP_SEND_BLOCK:
            reply_payload = self._send_block(payload)
        elif selector == MOSRXP_GET_HEADERS:
            reply_payload = self._get_headers(payload)
        elif selector == MOSRXP_DEL_MESSAGES:
            reply_payload = self._del_messages(payload)
        elif selector == MOSRXP_GET_MESSAGE:
            reply_payload = self._get_message(payload)
        elif selector == MOSRXP_GET_FIRST_MESSAGE:
            reply_payload = self._get_first_message(payload)
        elif selector == MOSRXP_FLAG_SERVER_MESSAGE:
            reply_payload = self._flag_server_message(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    # --- Methods ---

    def _get_conn_info(self, _payload):
        """Method 0. Reply `83 [status] 87 84 [cb] [CONNINFO]`.

        `HrGetConnInfo` @ 0x7F435991 caches the blob on the connection and
        stamps it on every outgoing message as PR_SENDER_ENTRYID, so it is the
        signed-in member's own address-book entry id.

        The variable param rides behind the end-of-static marker, the shape
        DIRSRV's GetDeidFromGoWord already answers `84` with.
        """
        user = self.session.user
        blob = build_conninfo(user.display_name, user.username)
        log.info("mosrxp_get_conn_info member=%r bytes=%d", user.username, len(blob))
        return (
            build_tagged_reply_dword(0)
            + bytes([TAG_END_STATIC])
            + build_tagged_reply_var(TAG_REPLY_VAR, blob)
        )

    def _open_inbox(self, _payload):
        """Method 1. Reply `83 [status] 83 [value] 87`.

        `HrOpenInbox` @ 0x7F4319F3 keeps the second dword only when the status
        is 0 and hands it to a caller outside this DLL, so its meaning is
        unidentified — the client fetches or skips independently of what this
        server puts there. The message count is the reading that fits the name.
        """
        count = len(_default_store.mail.list_messages(self.mailbox))
        log.info("mosrxp_open_inbox mailbox=%r messages=%d", self.mailbox, count)
        return (
            build_tagged_reply_dword(0) + build_tagged_reply_dword(count) + bytes([TAG_END_STATIC])
        )

    def _close_inbox(self, _payload):
        """Method 2. Reply `83 [status] 87`."""
        log.info("mosrxp_close_inbox mailbox=%r", self.mailbox)
        return _status_reply(0)

    def _init_transmit(self, payload):
        """Method 3. Opens a submit; the dword is the client's block size."""
        send_params, _recv = parse_request_params(payload)
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        block_bytes = dwords[0] if dwords else _TRANSMIT_BLOCK_BYTES
        self._blocks = []
        self._submit_done = False
        log.info("mosrxp_init_transmit mailbox=%r block_bytes=%d", self.mailbox, block_bytes)
        return _status_reply(0)

    def _send_block(self, payload):
        """Method 4. One block of the serialised message being submitted.

        The reply goes out now even when the block's bytes are still in flight:
        `HrSendBlock` @ 0x7F4354F5 blocks on it, and the 0xE6/0xE7 frames
        carrying the field are queued behind the call rather than ahead of it.
        `_finish_submit_if_ready` runs again as each stream closes.
        """
        send_params, _recv = parse_request_params(payload)
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        index = dwords[0] if dwords else len(self._blocks)
        is_last = bool(dwords[1]) if len(dwords) > 1 else True
        chunks = [p for p in send_params if isinstance(p, (VarParam, ChunkedParam))]

        self._blocks.append(chunks[0] if chunks else b"")
        self._submit_done = self._submit_done or is_last
        log.info(
            "mosrxp_send_block mailbox=%r index=%d last=%s blocks=%d",
            self.mailbox,
            index,
            is_last,
            len(self._blocks),
        )
        self._finish_submit_if_ready()
        return _status_reply(0)

    def _get_headers(self, _payload):
        """Method 5. Reply `83 [status] 83 [cHeaders] 87 86 [blob]`.

        The count rides the second dword, not the blob: `FUN_7F4398F2` writes
        it into the spool file itself and `FUN_7F439959` reads the record list
        against it.
        """
        messages = _default_store.mail.list_messages(self.mailbox)
        blob = b"".join(build_header_record(m) for m in messages)
        log.info(
            "mosrxp_get_headers mailbox=%r headers=%d blob_bytes=%d",
            self.mailbox,
            len(messages),
            len(blob),
        )
        return (
            build_tagged_reply_dword(0)
            + build_tagged_reply_dword(len(messages))
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
            + blob
        )

    def _del_messages(self, payload):
        """Method 6. Delete every entry id the client sends."""
        send_params, _recv = parse_request_params(payload)
        var_params = [p.data for p in send_params if isinstance(p, VarParam)]
        raw = var_params[0] if var_params else b""
        message_ids = [
            decode_entryid(raw[i : i + MOS_ENTRYID_LEN])
            for i in range(0, len(raw) - MOS_ENTRYID_LEN + 1, MOS_ENTRYID_LEN)
        ]
        removed = _default_store.mail.delete_messages(self.mailbox, message_ids)
        log.info(
            "mosrxp_del_messages mailbox=%r asked=%d removed=%d",
            self.mailbox,
            len(message_ids),
            removed,
        )
        return _status_reply(0)

    def _get_message(self, payload):
        """Method 7. Reply `83 [status] 87 86 [message blob]`.

        A miss answers MAPI_E_NOT_FOUND with no blob: `HrGetMessage` reads the
        status before it touches the stream and returns it as its HRESULT.
        """
        send_params, _recv = parse_request_params(payload)
        var_params = [p.data for p in send_params if isinstance(p, VarParam)]
        message_id = decode_entryid(var_params[0]) if var_params else None
        message = (
            _default_store.mail.get_message(self.mailbox, message_id)
            if message_id is not None
            else None
        )
        if message is None:
            log.warning("mosrxp_get_message_miss mailbox=%r id=%s", self.mailbox, message_id)
            return _status_reply(MAPI_E_NOT_FOUND)

        blob = build_message_blob(message)
        log.info(
            "mosrxp_get_message mailbox=%r id=%d subject=%r blob_bytes=%d",
            self.mailbox,
            message.message_id,
            message.subject,
            len(blob),
        )
        return (
            build_tagged_reply_dword(0)
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
            + blob
        )

    def _get_first_message(self, _payload):
        """Method 8. Same as method 7 with the entry id prefixed to the blob."""
        messages = _default_store.mail.list_messages(self.mailbox)
        if not messages:
            log.info("mosrxp_get_first_message_empty mailbox=%r", self.mailbox)
            return _status_reply(MAPI_E_NOT_FOUND)

        message = messages[0]
        blob = encode_entryid(message.message_id) + build_message_blob(message)
        log.info(
            "mosrxp_get_first_message mailbox=%r id=%d blob_bytes=%d",
            self.mailbox,
            message.message_id,
            len(blob),
        )
        return (
            build_tagged_reply_dword(0)
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
            + blob
        )

    def _flag_server_message(self, payload):
        """Method 9. Store the PR_MSG_STATUS the client pushes."""
        send_params, _recv = parse_request_params(payload)
        var_params = [p.data for p in send_params if isinstance(p, VarParam)]
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        message_id = decode_entryid(var_params[0]) if var_params else None
        status = dwords[0] if dwords else 0
        found = (
            _default_store.mail.set_status(self.mailbox, message_id, status)
            if message_id is not None
            else False
        )
        log.info(
            "mosrxp_flag_server_message mailbox=%r id=%s status=0x%04x found=%s",
            self.mailbox,
            message_id,
            status,
            found,
        )
        return _status_reply(0 if found else MAPI_E_NOT_FOUND)

    # --- Submit assembly ---

    def _take_continuation(self, msg_class, stream_id, payload):
        """Fold one class-0xE6/0xE7 frame into its stream."""
        stream = self._streams.get(stream_id)
        if stream is None:
            stream = ChunkStream()
            self._streams[stream_id] = stream
        stream.data += payload
        stream.complete = msg_class == MPC_CLASS_CONTINUATION_LAST
        log.debug(
            "mosrxp_chunk_frame id=%d frame_bytes=%d received=%d",
            stream_id,
            len(payload),
            len(stream.data),
        )
        if stream.complete:
            log.info("mosrxp_chunk_stream_done id=%d bytes=%d", stream_id, len(stream.data))
            self._finish_submit_if_ready()

    def _submitted_bytes(self):
        """The blocks concatenated, or None while any of them is still in flight."""
        out = []
        for block in self._blocks:
            if isinstance(block, ChunkedParam):
                stream = self._streams.get(block.stream_id)
                if stream is None or not stream.complete:
                    return None
                out.append(stream.data)
            elif isinstance(block, VarParam):
                out.append(block.data)
            else:
                out.append(block)
        return b"".join(out)

    def _finish_submit_if_ready(self):
        """Parse and deliver the submitted message once every block has landed."""
        if not self._submit_done:
            return
        raw = self._submitted_bytes()
        if raw is None:
            return

        self._blocks = []
        self._submit_done = False
        self._streams = {}
        try:
            subject, body, recipients = parse_message_blob(raw)
        except ValueError as exc:
            log.error("mosrxp_submit_unparseable bytes=%d error=%s", len(raw), exc)
            return

        delivered = self._deliver(subject, body, recipients)
        log.info(
            "mosrxp_submit mailbox=%r subject=%r bytes=%d recipients=%d delivered=%d",
            self.mailbox,
            subject,
            len(raw),
            len(recipients),
            delivered,
        )

    def _deliver(self, subject, body, recipients):
        """Drop the message in each local recipient's inbox.

        A recipient this server has no account for is logged and skipped: MSN
        gatewayed INTERNET/SMTP addresses out, and nothing here does that.
        """
        sender = self.session.user
        delivered = 0
        for recipient in recipients:
            if recipient.addrtype.upper() not in TRANSPORT_ADDRTYPES:
                log.warning(
                    "mosrxp_recipient_foreign addrtype=%r address=%r",
                    recipient.addrtype,
                    recipient.address,
                )
                continue
            mailbox = resolve_mailbox(recipient)
            if mailbox is None:
                log.warning(
                    "mosrxp_recipient_unknown address=%r name=%r",
                    recipient.address,
                    recipient.display_name,
                )
                continue
            _default_store.mail.deliver(
                MailMessage(
                    message_id=0,  # assigned by the store
                    mailbox=mailbox,
                    sender_name=sender.display_name,
                    sender_address=sender.username,
                    subject=subject,
                    body=body,
                    delivered=datetime.datetime.now(datetime.UTC),
                    recipients=tuple(recipients),
                )
            )
            delivered += 1
        return delivered


def resolve_mailbox(recipient):
    """The account whose inbox a recipient names, or None.

    A recipient picked out of the address book carries the member record's
    display name in PR_EMAIL_ADDRESS — MOSABP keys members on the display name,
    so an AB row's address *is* "Steve Jobs" — while a member id typed straight
    into the To: box arrives as "sjobs". Both have to land, and the display
    name is checked on PR_DISPLAY_NAME too because an unresolved recipient
    carries only that.
    """
    for candidate in (recipient.address, recipient.display_name):
        if not candidate:
            continue
        user = _default_store.users.get_user(candidate)
        if user is not None:
            return user.username
        user = _default_store.users.find_by_display_name(candidate)
        if user is not None:
            return user.username
    return None


def _status_reply(status):
    return build_tagged_reply_dword(status) + bytes([TAG_END_STATIC])


# --- Entry ids ---


def build_conninfo(display_name, member_name):
    """The signed-in member's `_usr_entryid`, the blob method 0 answers with.

    Both names are truncated one short of their field so the terminator always
    fits: `HrBuildUeid` uses `strncpy`, which writes no NUL when the source
    fills the field exactly.
    """
    blob = bytearray(CONNINFO_LEN)
    blob[0x04:0x14] = UEID_PROVIDER_UID
    struct.pack_into("<II", blob, 0x14, UEID_VERSION, EIDTYPE_MEMBER_NAME)
    for offset, limit, text in (
        (UEID_DISPLAY_NAME_OFFSET, UEID_DISPLAY_NAME_MAX, display_name),
        (UEID_MEMBER_NAME_OFFSET, UEID_MEMBER_NAME_MAX, member_name),
    ):
        encoded = text.encode("cp1252", errors="replace")[: limit - 1]
        blob[offset : offset + len(encoded)] = encoded
    return bytes(blob)


def encode_entryid(message_id):
    return struct.pack("<III", MOS_ENTRYID_VERSION, message_id, 0)


def decode_entryid(raw):
    """The message id inside a MOS_ENTRYID, or None if it is not one of ours."""
    if len(raw) < MOS_ENTRYID_LEN:
        return None
    version, message_id, _reserved = struct.unpack_from("<III", raw)
    if version != MOS_ENTRYID_VERSION:
        return None
    return message_id


# --- Serialisation ---


def encode_prop(tag, value):
    """One `[ulPropTag:u32][value]` record, width implied by the tag's type.

    `CConn::HrDSrlProp` @ 0x7F432435 carries no length and no type byte for a
    regular tag, so a value written at the wrong width shifts every property
    after it. Named properties (id >= 0x8000) carry their name inline; nothing
    served here uses one.
    """
    prop_type = tag & 0xFFFF
    head = struct.pack("<I", tag)
    if prop_type == PT_STRING8:
        return head + value.encode("cp1252", errors="replace") + b"\x00"
    if prop_type == PT_UNICODE:
        return head + value.encode("utf-16le", errors="replace") + b"\x00\x00"
    if prop_type == PT_BINARY:
        return head + struct.pack("<I", len(value)) + value
    width = _FIXED_WIDTHS.get(prop_type)
    if width is None:
        raise ValueError(f"MOSRXP tag 0x{tag:08X} has unserialisable type 0x{prop_type:04X}")
    return head + int(value).to_bytes(width, "little", signed=False)


def encode_prop_list(props):
    """`[cValues:u32]` then one record per property."""
    return struct.pack("<I", len(props)) + b"".join(encode_prop(tag, value) for tag, value in props)


def encode_recip_list(recipients):
    """`[cRecips:u32]` then one property list per ADRENTRY."""
    out = [struct.pack("<I", len(recipients))]
    for recipient in recipients:
        out.append(
            encode_prop_list(
                [
                    (PR_OBJECT_TYPE, MAPI_MAILUSER),
                    (PR_RECIPIENT_TYPE, recipient.recipient_type),
                    (PR_DISPLAY_NAME, recipient.display_name),
                    (PR_ADDRTYPE, recipient.addrtype),
                    (PR_EMAIL_ADDRESS, recipient.address),
                ]
            )
        )
    return b"".join(out)


def to_filetime(when):
    """A UTC datetime as a Windows FILETIME (100 ns ticks since 1601)."""
    return int((when - _FILETIME_EPOCH).total_seconds() * 10_000_000)


def from_filetime(ticks):
    return _FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)


def header_props(message, size):
    """The 12 `PSptaHdr` tags for one message, in array order.

    Order is not enforced by the client — `FUN_7F439959` applies whatever
    arrives — but the array is the contract the transport was written against,
    and PR_MESSAGE_SIZE has to be present for the reader to synthesise
    PR_MESSAGE_DOWNLOAD_TIME from it.
    """
    return [
        (PR_OBJECT_TYPE, MAPI_MESSAGE),
        (PR_MSG_STATUS, message.status),
        (PR_MESSAGE_FLAGS, MSGFLAG_UNMODIFIED),
        (PR_MESSAGE_CLASS, message.message_class),
        (PR_IMPORTANCE, IMPORTANCE_NORMAL),
        (PR_SENT_REPRESENTING_NAME, message.sender_name),
        (PR_DISPLAY_TO, "; ".join(r.display_name for r in message.recipients)),
        (PR_SENSITIVITY, SENSITIVITY_NONE),
        (PR_HASATTACH, 0),
        (PR_SUBJECT, message.subject),
        (PR_MESSAGE_DELIVERY_TIME, to_filetime(message.delivered)),
        (PR_MESSAGE_SIZE, size),
    ]


def body_props(message):
    """Everything `FIsHeaderProp` rejects: the body and the sender identity.

    The client drops any tag whose id lands in 0x0E00–0x0FFF, 0x6000–0x67FF or
    0x7C00–0x7FFF before calling SetProps (`HrDSrlPropList` @ 0x7F432256) — the
    transport- and store-owned ranges — so nothing here may use one.
    """
    return [
        (PR_BODY, message.body),
        (PR_CLIENT_SUBMIT_TIME, to_filetime(message.delivered)),
        (PR_SENDER_NAME, message.sender_name),
        (PR_SENDER_ADDRTYPE, MOSRXP_ADDRTYPE),
        (PR_SENDER_EMAIL_ADDRESS, message.sender_address),
        (PR_SENDER_SEARCH_KEY, _search_key(message.sender_address)),
        (PR_SENT_REPRESENTING_ADDRTYPE, MOSRXP_ADDRTYPE),
        (PR_SENT_REPRESENTING_EMAIL_ADDRESS, message.sender_address),
    ]


def _search_key(address):
    """`ADDRTYPE:ADDRESS`, the form HrSendMessage builds for its own sender key."""
    return f"{MOSRXP_ADDRTYPE}:{address}".encode("cp1252", errors="replace") + b"\x00"


def message_size(message):
    """PR_MESSAGE_SIZE: the byte count of the message as it will be served.

    Measured off a blob built with the size itself zeroed. PR_MESSAGE_SIZE is
    PT_LONG and every fixed-width value costs the same four bytes whatever it
    holds, so the placeholder measures the real thing.
    """
    return len(_build_message_blob(message, 0))


def build_message_blob(message):
    """One serialised message: header props, recipients, body props, attachments.

    `CConn::HrDSrlMsg` @ 0x7F4321C9 reads the four sections back to back and
    each one is self-delimiting, so the message carries no total length.
    """
    return _build_message_blob(message, message_size(message))


def _build_message_blob(message, size):
    return (
        encode_prop_list(header_props(message, size))
        + encode_recip_list(message.recipients)
        + encode_prop_list(body_props(message))
        + struct.pack("<I", 0)  # empty attachment list
    )


def build_header_record(message):
    """One header-blob record: `[MOS_ENTRYID:12][cValues:u32][props]`."""
    return encode_entryid(message.message_id) + encode_prop_list(
        header_props(message, message_size(message))
    )


# --- Parsing (submitted messages) ---


def _end_of_wide_string(raw, pos):
    """Offset of the UTF-16 terminator, searched on unit boundaries.

    A byte-wise search would stop on the low NUL of a character pair such as
    U+0100 and cut the string in half.
    """
    end = pos
    while end + 2 <= len(raw):
        if raw[end : end + 2] == b"\x00\x00":
            return end
        end += 2
    raise ValueError("unterminated PT_UNICODE value")


def parse_prop(raw, pos):
    """Decode one property. Returns (tag, value, next_pos).

    Mirror of `CConn::HrDSrlProp`, including its named-property preamble: a tag
    with id >= 0x8000 carries a GUID, a kind, an id-or-name and the real type
    before the value. The name resolves to nothing on this side — the tag is
    rebuilt with the inline type so the cursor stays aligned and the value is
    reachable, which is all a submitted message needs.
    """
    (tag,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    if tag >= 0x80000000:
        pos += 4  # reserved dword between the tag and the GUID
        pos += 16  # MAPIUID
        (kind,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        if kind == 0:
            pos += 4  # lID
        else:
            pos = _end_of_wide_string(raw, pos) + 2
        (prop_type,) = struct.unpack_from("<H", raw, pos)
        pos += 2
        tag = (tag & 0xFFFF0000) | prop_type

    prop_type = tag & 0xFFFF
    if prop_type == PT_STRING8:
        end = raw.index(b"\x00", pos)
        return tag, raw[pos:end].decode("cp1252", errors="replace"), end + 1
    if prop_type == PT_UNICODE:
        end = _end_of_wide_string(raw, pos)
        return tag, raw[pos:end].decode("utf-16le", errors="replace"), end + 2
    if prop_type == PT_BINARY:
        (cb,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        return tag, raw[pos : pos + cb], pos + cb

    width = _FIXED_WIDTHS.get(prop_type)
    if width is None:
        raise ValueError(f"unserialisable property type 0x{prop_type:04X}")
    return tag, int.from_bytes(raw[pos : pos + width], "little"), pos + width


def parse_prop_list(raw, pos):
    """Decode `[cValues:u32]` properties. Returns (dict, next_pos)."""
    (count,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    props = {}
    for _ in range(count):
        tag, value, pos = parse_prop(raw, pos)
        props[tag] = value
    return props, pos


def parse_recip_list(raw, pos):
    """Decode `[cRecips:u32]` ADRENTRYs. Returns (list of MailRecipient, next_pos)."""
    (count,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    recipients = []
    for _ in range(count):
        props, pos = parse_prop_list(raw, pos)
        recipients.append(
            MailRecipient(
                display_name=props.get(PR_DISPLAY_NAME, ""),
                address=props.get(PR_EMAIL_ADDRESS, ""),
                addrtype=props.get(PR_ADDRTYPE, MOSRXP_ADDRTYPE),
                recipient_type=props.get(PR_RECIPIENT_TYPE, 1),
            )
        )
    return recipients, pos


def parse_message_blob(raw):
    """Pull subject, body and recipients out of a submitted message.

    The attachment list is read for its count only — its content rides a
    compressed stream this server cannot decode — and a message that carries
    one is stored without it.
    """
    try:
        head, pos = parse_prop_list(raw, 0)
        recipients, pos = parse_recip_list(raw, pos)
        body, pos = parse_prop_list(raw, pos)
        (attachments,) = struct.unpack_from("<I", raw, pos)
    except (struct.error, IndexError, ValueError) as exc:
        raise ValueError(str(exc)) from exc

    if attachments:
        log.warning("mosrxp_submit_attachments_dropped count=%d", attachments)
    return head.get(PR_SUBJECT, ""), body.get(PR_BODY, ""), recipients
