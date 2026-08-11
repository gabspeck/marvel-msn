"""CONFLOC/CONFSRV startup path used by the MSN text-chat client."""

import logging
import struct
import threading
from dataclasses import replace

from ..config import (
    CONFLOC_INTERFACE_GUIDS,
    CONFSRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ..models import DwordParam, VarParam, WordParam
from ..mos_apps import APP_TEXT_CONFERENCE
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    build_tagged_reply_word,
    parse_request_params,
)
from ..session import Session
from ..store import ConferenceFields
from ..store import app_store as _default_store
from ._dispatch import log_unhandled_selector
from .dirsrv import (
    TREEEDCL_STATUS_REFUSED,
    _decode_property_record,
    build_get_ticket_reply_payload,
    build_property_record,
)

log = logging.getLogger(__name__)

CONFLOC_SELECTOR_LOCATE = 0x01
CONFLOC_DATA_EDIT_CLASS = 0x0C
CONFLOC_DATA_EDIT_ADD = 0x00
CONFLOC_DATA_EDIT_DELETE = 0x01
CONFLOC_DATA_EDIT_SET_PROPERTIES = 0x02
CONFLOC_DATA_EDIT_GET_PROPERTIES = 0x03
CONFLOC_DATA_EDIT_GET_TICKET = 0x05
CONFSRV_SELECTOR_JOIN = 0x03
CONFSRV_SELECTOR_SEND = 0x02

# CONFAPI!CConversation::CceJoin @ 0x7F5B16FC branches on these WORD values.
CONFLOC_RESULT_FOUND = 1
CONFLOC_RESULT_NOT_FOUND = 2
CONFSRV_JOINED = 3
# CONFAPI CceJoin maps wire status 8 to result 2; TEXTCHAT's join caller maps
# result 2 to string 0x3C, "This chat is currently full."
CONFSRV_ROOM_FULL = 8
# TEXTCHAT HostControlsDialogProc maps its spectator radio to role 0 and its
# participant radio to role 1. HandleParticipantListEvent treats role 2 as host.
CONFSRV_ROLE_SPECTATOR = 0
CONFSRV_ROLE_PARTICIPANT = 1
CONFSRV_ROLE_HOST = 2

# Event types. CONFAPI!CConversation::QueueServerEvent @ 0x7F5B1EE2 accepts
# 0 through 11 on an 8-byte header and hands the payload to the application.
# TEXTCHAT!DispatchConversationMessage @ 0x7F2D545D routes these five.
CONFSRV_EVENT_TEXT = 0
CONFSRV_EVENT_PARTICIPANT_LIST = 2
CONFSRV_EVENT_PARTICIPANT_JOINED = 4
CONFSRV_EVENT_PARTICIPANT_LEFT = 5
CONFSRV_EVENT_ROLE = 7

# Fallback for an incomplete authored room record. Seeded rooms carry their
# CONFLOC settings in the content store.
DEFAULT_MESSAGE_LENGTH = 1000


class _Room:
    """Live roster for one conference instance, shared by every connection.

    The lock covers the roster and the pushes that report a change to it, so
    every member reads joins, leaves and text in one order. It is always taken
    before a connection's send lock and never after, which is why the CONFSRV
    handler answers from `flush_pending_events` instead of `handle_request`.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.members = []
        self.next_participant_id = 1


# Keyed by room id. Rooms are authored directory nodes, so the registry stays
# bounded, and a retained room keeps its participant ids monotonic.
_rooms = {}
_rooms_lock = threading.Lock()


def _room_for(room_id):
    with _rooms_lock:
        room = _rooms.get(room_id)
        if room is None:
            room = _Room()
            _rooms[room_id] = room
        return room


def room_population(room_id):
    """How many members are in one room right now.

    Backs the chat node's `p`: MSNFIND's Size cell renders that DWORD as
    "%d people" when `c` is 4, so a room reports occupancy where a file reports
    bytes. Read by `dirsrv._size_value`.

    Never creates the room — a Find result listing every chat node would
    otherwise register a `_Room` for each one. An unvisited room is 0, which is
    also the value that leaves the cell blank.

    Takes the two locks in sequence rather than nested: the registry lock only
    guards the dict, and holding it while waiting on a room's lock would invert
    the order the push path relies on.
    """
    with _rooms_lock:
        room = _rooms.get(room_id)
    if room is None:
        return 0
    with room.lock:
        return len(room.members)


class CONFLOCHandler:
    """Resolve a DIRSRV chat node to a CONFSRV instance."""

    def __init__(self, pipe_idx, svc_name, session=None, content_store=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        self.session = session or Session()
        self.content_store = content_store or _default_store.content
        self._records = {}

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(CONFLOC_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if msg_class == CONFLOC_DATA_EDIT_CLASS and selector == CONFLOC_DATA_EDIT_GET_TICKET:
            reply_payload = build_get_ticket_reply_payload(self.session)
        elif msg_class == CONFLOC_DATA_EDIT_CLASS and selector == CONFLOC_DATA_EDIT_ADD:
            reply_payload = self.build_data_edit_add_reply_payload(request_id, payload)
        elif msg_class == CONFLOC_DATA_EDIT_CLASS and selector == CONFLOC_DATA_EDIT_DELETE:
            reply_payload = self.build_data_edit_delete_reply_payload(request_id, payload)
        elif msg_class == CONFLOC_DATA_EDIT_CLASS and selector == CONFLOC_DATA_EDIT_SET_PROPERTIES:
            reply_payload = self.build_data_edit_set_properties_reply_payload(request_id, payload)
        elif msg_class == CONFLOC_DATA_EDIT_CLASS and selector == CONFLOC_DATA_EDIT_GET_PROPERTIES:
            reply_payload = self.build_data_edit_get_properties_reply_payload(request_id, payload)
        elif selector == CONFLOC_SELECTOR_LOCATE:
            reply_payload = self.build_locate_reply_payload(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def build_data_edit_add_reply_payload(self, request_id, payload):
        """Complete DATAEDCL's CONFLOC record attached to a new chat node.

        The request uses CDataEditClient's generic Add layout: capability
        ticket, table DWORD, 8-byte record id, dataset WORD, property record,
        then status and operation-id receive descriptors.
        """
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 5
            and isinstance(send_params[0], VarParam)
            and isinstance(send_params[1], DwordParam)
            and isinstance(send_params[2], VarParam)
            and isinstance(send_params[3], WordParam)
            and isinstance(send_params[4], VarParam)
            and recv_descriptors == [0x83, 0x83]
        )
        if not valid_shape:
            log.warning(
                "data_edit_add invalid request req_id=%d params=%d recv=%s",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        ticket = send_params[0].data
        record_id = send_params[2].data
        properties = send_params[4].data
        valid_payload = (
            self.session.is_admin
            and len(ticket) >= 2
            and struct.unpack_from("<H", ticket)[0] == len(ticket)
            and len(record_id) == 8
            and len(properties) >= 4
            and struct.unpack_from("<I", properties)[0] == len(properties)
        )
        if not valid_payload:
            log.warning(
                "data_edit_add refused req_id=%d user=%s ticket_len=%d "
                "record_id_len=%d properties_len=%d",
                request_id,
                self.session.user.username or "-",
                len(ticket),
                len(record_id),
                len(properties),
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        try:
            decoded = _decode_property_record(properties)
            stored = _apply_conference_properties(
                self.content_store,
                record_id,
                decoded,
            )
        except ValueError as exc:
            log.warning(
                "data_edit_add invalid record req_id=%d record_id=%s error=%s",
                request_id,
                record_id.hex(),
                exc,
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        log.info(
            "data_edit_add status=0 req_id=%d table=%d record_id=%s dataset=0x%04x props=%s",
            request_id,
            send_params[1].value,
            record_id.hex(),
            send_params[3].value,
            ",".join(decoded),
        )
        if stored:
            self._records.pop(record_id, None)
        else:
            self._records[record_id] = properties
        return _build_data_edit_result(0)

    def build_data_edit_delete_reply_payload(self, request_id, payload):
        """Complete the application-record half of a tree-node deletion.

        Live DIRSRV deletion shows TREEEDCL removing the node first, followed
        by CDataEditClient::PrivateDelete on the node's application service.
        DATAEDCL 0x7F5A183F sends the ticket, table DWORD, 8-byte record id and
        dataset WORD, then waits for status and operation-id DWORDs.
        """
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 4
            and isinstance(send_params[0], VarParam)
            and isinstance(send_params[1], DwordParam)
            and isinstance(send_params[2], VarParam)
            and isinstance(send_params[3], WordParam)
            and recv_descriptors == [0x83, 0x83]
        )
        if not valid_shape:
            log.warning(
                "data_edit_delete invalid request req_id=%d params=%d recv=%s",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        ticket = send_params[0].data
        record_id = send_params[2].data
        if not (
            self.session.is_admin
            and len(ticket) >= 2
            and struct.unpack_from("<H", ticket)[0] == len(ticket)
            and len(record_id) == 8
        ):
            log.warning(
                "data_edit_delete refused req_id=%d user=%s ticket_len=%d record_id_len=%d",
                request_id,
                self.session.user.username or "-",
                len(ticket),
                len(record_id),
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        self._records.pop(record_id, None)
        log.info(
            "data_edit_delete status=0 req_id=%d table=%d record_id=%s dataset=0x%04x",
            request_id,
            send_params[1].value,
            record_id.hex(),
            send_params[3].value,
        )
        return _build_data_edit_result(0)

    def build_data_edit_set_properties_reply_payload(self, request_id, payload):
        """Apply DATAEDCL properties to an existing conference record.

        CDataEditClient::PrivateSetProperties sends the capability ticket,
        table DWORD, 8-byte record id, dataset WORD, and property record. It
        waits for status and operation-id DWORDs; status 0 completes the write.
        """
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 5
            and isinstance(send_params[0], VarParam)
            and isinstance(send_params[1], DwordParam)
            and isinstance(send_params[2], VarParam)
            and isinstance(send_params[3], WordParam)
            and isinstance(send_params[4], VarParam)
            and recv_descriptors == [0x83, 0x83]
        )
        if not valid_shape:
            log.warning(
                "data_edit_set_properties invalid request req_id=%d params=%d recv=%s",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        ticket = send_params[0].data
        record_id = send_params[2].data
        properties = send_params[4].data
        known_record = record_id in self._records
        if len(record_id) == 8:
            field_0, field_8 = struct.unpack("<II", record_id)
            node = self.content_store.get_node(f"{field_0}:{field_8}")
            known_record = known_record or (node is not None and node.app_id == APP_TEXT_CONFERENCE)
        valid_payload = (
            self.session.is_admin
            and len(ticket) >= 2
            and struct.unpack_from("<H", ticket)[0] == len(ticket)
            and len(record_id) == 8
            and known_record
        )
        try:
            decoded = _decode_property_record(properties)
        except ValueError as exc:
            decoded = None
            log.warning(
                "data_edit_set_properties invalid record req_id=%d record_id=%s error=%s",
                request_id,
                record_id.hex(),
                exc,
            )
        if not valid_payload or decoded is None:
            log.warning(
                "data_edit_set_properties refused req_id=%d user=%s ticket_len=%d "
                "record_id=%s properties_len=%d",
                request_id,
                self.session.user.username or "-",
                len(ticket),
                record_id.hex(),
                len(properties),
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        try:
            stored = _apply_conference_properties(
                self.content_store,
                record_id,
                decoded,
            )
        except ValueError as exc:
            log.warning(
                "data_edit_set_properties refused req_id=%d record_id=%s error=%s",
                request_id,
                record_id.hex(),
                exc,
            )
            return _build_data_edit_result(TREEEDCL_STATUS_REFUSED)

        if stored:
            self._records.pop(record_id, None)
        else:
            self._records[record_id] = properties
        log.info(
            "data_edit_set_properties status=0 req_id=%d table=%d record_id=%s "
            "dataset=0x%04x props=%s",
            request_id,
            send_params[1].value,
            record_id.hex(),
            send_params[3].value,
            ",".join(decoded),
        )
        return _build_data_edit_result(0)

    def build_data_edit_get_properties_reply_payload(self, request_id, payload):
        """Return the property record previously attached by DATAEDCL Add.

        CDataEditClient::GetProperties sends table DWORD, 8-byte record id,
        dataset WORD, requested-property count DWORD, and the NUL-separated
        property names. It binds status, record count, and an iterator. The
        iterator item is a complete CServiceProperties record.
        """
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 5
            and isinstance(send_params[0], DwordParam)
            and isinstance(send_params[1], VarParam)
            and isinstance(send_params[2], WordParam)
            and isinstance(send_params[3], DwordParam)
            and isinstance(send_params[4], VarParam)
            and recv_descriptors == [0x83, 0x83, 0x85]
        )
        if not valid_shape:
            log.warning(
                "data_edit_get_properties invalid request req_id=%d params=%d recv=%s",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
            )
            return _build_data_edit_properties_result(TREEEDCL_STATUS_REFUSED, ())

        record_id = send_params[1].data
        properties = self._records.get(record_id)
        if properties is None:
            properties = _build_stored_conference_properties(
                self.content_store,
                record_id,
            )
        if properties is None:
            log.warning(
                "data_edit_get_properties unknown record req_id=%d record_id=%s",
                request_id,
                record_id.hex(),
            )
            return _build_data_edit_properties_result(TREEEDCL_STATUS_REFUSED, ())

        names = [
            name.decode("ascii", errors="replace")
            for name in send_params[4].data.rstrip(b"\x00").split(b"\x00")
            if name
        ]
        try:
            selected = _select_dword_properties(properties, names)
        except ValueError as exc:
            log.warning(
                "data_edit_get_properties invalid stored record req_id=%d record_id=%s error=%s",
                request_id,
                record_id.hex(),
                exc,
            )
            return _build_data_edit_properties_result(TREEEDCL_STATUS_REFUSED, ())
        log.info(
            "data_edit_get_properties status=0 req_id=%d table=%d record_id=%s "
            "dataset=0x%04x requested=%d props=%s properties_len=%d selected_len=%d",
            request_id,
            send_params[0].value,
            record_id.hex(),
            send_params[2].value,
            send_params[3].value,
            ",".join(names),
            len(properties),
            len(selected),
        )
        return _build_data_edit_properties_result(0, (selected,))

    def build_locate_reply_payload(self, payload):
        """Return `[instance:WORD][result:WORD]` for locator method 1.

        CONFAPI!FUN_7F5B14D3 sends the first DWORD from the room's launch MNID
        and binds two WORD outputs. CceJoin treats result 1 as resolved and 2
        as not found, then opens `CONFSRV` with the decimal instance in the
        pipe parameter.
        """
        send_params, recv_descriptors = parse_request_params(payload)
        room_id = next(
            (param.value for param in send_params if isinstance(param, DwordParam)),
            None,
        )
        node = (
            self.content_store.find_app_instance(APP_TEXT_CONFERENCE, room_id)
            if room_id is not None
            else None
        )
        found = node is not None
        if recv_descriptors != [0x82, 0x82]:
            log.warning(
                "locate invalid request room=%s recv=%s payload=%s",
                room_id,
                [f"0x{tag:02x}" for tag in recv_descriptors],
                payload.hex(),
            )
            found = False

        instance = room_id & 0xFFFF if found else 0
        result = CONFLOC_RESULT_FOUND if found else CONFLOC_RESULT_NOT_FOUND
        log.info("locate room=%s instance=%d result=%d", room_id, instance, result)
        return (
            build_tagged_reply_word(instance)
            + build_tagged_reply_word(result)
            + bytes([TAG_END_STATIC])
        )


class CONFSRVHandler:
    """Join a text conference and service its retained event iterator.

    One handler is one participant. Everything the client sees after the join
    request — the join record, the roster, other people's text — arrives as an
    iterator push on the join subscription, so a handler can write to a client
    whose own thread is parked in `recv`.
    """

    def __init__(self, pipe_idx, svc_name, session=None, content_store=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        self.session = session or Session()
        self.content_store = content_store or _default_store.content
        self.connection = None
        self._join_subscription = None
        self._participant_id = None
        self._participant_role = None
        self._display_name = ""
        self._room = None
        self._room_id = None
        self._pending = None

    def bind_connection(self, connection):
        self.connection = connection

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(CONFSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Record the request and answer from `flush_pending_events`.

        The connection calls this while it holds the send lock. A reply that
        also reaches the other members of a room must take the room lock, and
        the room lock is taken before send locks, never after.
        """
        if selector == CONFSRV_SELECTOR_JOIN:
            self._pending = (self._deliver_join, (msg_class, request_id, payload))
        elif selector == CONFSRV_SELECTOR_SEND:
            self._pending = (self._deliver_message, (msg_class, request_id, payload))
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
        return []

    def flush_pending_events(self):
        pending, self._pending = self._pending, None
        if pending is not None:
            deliver, args = pending
            deliver(*args)

    def handle_iterator_cancel(self, msg_class, selector, request_id):
        if self._join_subscription == (msg_class, request_id):
            self._join_subscription = None
            self._leave_room()

    def close(self):
        self._join_subscription = None
        self._leave_room()

    def _deliver_join(self, msg_class, request_id, payload):
        """Answer CConversation::CceJoin and publish the roster it joins.

        CceJoin reads the reply record as status WORD at +0, participant DWORD
        at +4, role WORD at +8, message limit DWORD at +10, and a counted
        UTF-16 conference name at +14/+18. The iterator stays open and carries
        every later event. A full room returns status 8 alone; the stream-end
        marker wakes the blocking Next call in both cases.

        The joiner then gets the whole roster as one type-2 event, and every
        other member gets a type-4 event for the joiner alone. TEXTCHAT drops
        text from a participant id it has not been told about, so the roster
        has to reach a client before that participant speaks.
        """
        self._join_subscription = (msg_class, request_id)
        send_params, recv_descriptors = parse_request_params(payload)
        room_id = next(
            (param.value for param in send_params if isinstance(param, DwordParam)),
            0,
        )
        if recv_descriptors != [0x85]:
            log.warning(
                "join unexpected receive shape room=%d recv=%s payload=%s",
                room_id,
                [f"0x{tag:02x}" for tag in recv_descriptors],
                payload.hex(),
            )

        node = self.content_store.find_app_instance(APP_TEXT_CONFERENCE, room_id)
        conference = node.content.conference if node is not None else None
        room_name = node.content.name if node is not None else ""
        room_capacity = conference.room_capacity if conference is not None else 0
        message_length = (
            conference.message_length if conference is not None else DEFAULT_MESSAGE_LENGTH
        )

        self._leave_room()
        room = _room_for(room_id)
        with room.lock:
            if 0 < room_capacity <= len(room.members):
                log.info(
                    "join room=%d name=%r capacity=%d status=%d",
                    room_id,
                    room_name,
                    room_capacity,
                    CONFSRV_ROOM_FULL,
                )
                self._push(
                    msg_class,
                    request_id,
                    bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
                    + struct.pack("<H", CONFSRV_ROOM_FULL),
                    "join_refused",
                )
                return

            self._room = room
            self._room_id = room_id
            self._participant_id = room.next_participant_id
            self._participant_role = _participant_role(node, conference, self.session.user)
            self._display_name = self.session.user.display_name or self.session.user.username
            room.next_participant_id += 1
            room.members.append(self)

            name = room_name.encode("utf-16le") + b"\x00\x00"
            self._push(
                msg_class,
                request_id,
                bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
                + struct.pack(
                    "<HHIHII",
                    CONFSRV_JOINED,
                    0,
                    self._participant_id,
                    self._participant_role,
                    message_length,
                    len(name) // 2,
                )
                + name,
                "join",
            )
            self._push_event(
                _build_event(
                    CONFSRV_EVENT_PARTICIPANT_LIST,
                    0,
                    b"".join(member._participant_record() for member in room.members),
                ),
                "participant_list",
            )
            joined = _build_event(
                CONFSRV_EVENT_PARTICIPANT_JOINED,
                self._participant_id,
                self._participant_record(),
            )
            for member in room.members:
                if member is not self:
                    member._push_event(joined, "participant_joined")
            members = len(room.members)

        log.info(
            "join room=%d name=%r participant=%d role=%d capacity=%d "
            "message_limit=%d members=%d status=%d",
            room_id,
            room_name,
            self._participant_id,
            self._participant_role,
            room_capacity,
            message_length,
            members,
            CONFSRV_JOINED,
        )

    def _deliver_message(self, msg_class, request_id, payload):
        """Acknowledge CConversation::SendMessageRecord and relay its record.

        Every client-to-server conference message rides selector 2 carrying
        the same 8-byte header. The sender's own copy comes back over the
        relay, which is how TEXTCHAT renders it.

        The acknowledgement is always success. SendMessageRecord turns an RPC
        error into result 3, and TEXTCHAT reads result 3 as a lost connection:
        it shows error 0x24 and closes the chat window. A record the server
        refuses is dropped, not failed.
        """
        self._push(msg_class, request_id, bytes([TAG_END_STATIC]), "send_ack", ack=True)
        record = self._parse_record(request_id, payload)
        if record is None:
            return
        event_type = struct.unpack_from("<H", record)[0]
        if event_type == CONFSRV_EVENT_TEXT:
            self._relay_text(request_id, record)
        elif event_type == CONFSRV_EVENT_ROLE:
            self._apply_role_change(request_id, record)
        else:
            log.warning(
                "send unhandled event_type=%d req_id=%d record_len=%d",
                event_type,
                request_id,
                len(record),
            )

    def _relay_text(self, request_id, record):
        if len(record) < 10 or len(record) % 2 or record[-2:] != b"\x00\x00":
            log.warning(
                "send_text invalid record req_id=%d record_len=%d",
                request_id,
                len(record),
            )
            return
        room = self._room
        if room is None:
            log.warning("send_text not_joined req_id=%d", request_id)
            return

        event = bytearray(record)
        struct.pack_into("<I", event, 4, self._participant_id or 0)
        text = event[8:-2].decode("utf-16le", errors="replace")
        with room.lock:
            # A spectator watches and does not speak. TEXTCHAT stops its own
            # input box, so this only catches a demotion the client has not
            # processed yet.
            if self._participant_role == CONFSRV_ROLE_SPECTATOR:
                log.warning(
                    "send_text refused req_id=%d participant=%s reason=spectator",
                    request_id,
                    self._participant_id,
                )
                return
            log.info(
                "send_text req_id=%d participant=%d chars=%d text=%r",
                request_id,
                self._participant_id or 0,
                len(text),
                text,
            )
            for member in room.members:
                member._push_event(bytes(event), "text")

    def _apply_role_change(self, request_id, record):
        """Serve CConversation::ErrHostSetStatus.

        SetSelectedMembersRole @ TEXTCHAT 0x7F2D4828 sends one record per
        selected member, only ever role 0 or 1, and refuses to touch a host
        itself. HandleParticipantRoleEvent @ 0x7F2D56A5 wants a payload of
        exactly 6 bytes — participant DWORD then role WORD — and shows error
        0x3A for any other length. Both the target and the rest of the room
        need the event: CONFAPI updates the target's own cached role from it.
        """
        if len(record) != 14:
            log.warning(
                "set_role invalid record req_id=%d record_len=%d",
                request_id,
                len(record),
            )
            return
        target_id, role = struct.unpack_from("<IH", record, 8)
        room = self._room
        if room is None:
            log.warning("set_role not_joined req_id=%d", request_id)
            return

        with room.lock:
            refusal = self._role_change_refusal(room, target_id, role)
            if refusal is not None:
                log.warning(
                    "set_role refused req_id=%d participant=%s target=%d role=%d reason=%s",
                    request_id,
                    self._participant_id,
                    target_id,
                    role,
                    refusal,
                )
                return

            target = _member(room, target_id)
            target._participant_role = role
            event = bytearray(record)
            struct.pack_into("<I", event, 4, self._participant_id)
            log.info(
                "set_role req_id=%d host=%d target=%d role=%d",
                request_id,
                self._participant_id,
                target_id,
                role,
            )
            for member in room.members:
                member._push_event(bytes(event), "role")

    def _role_change_refusal(self, room, target_id, role):
        """Why this member may not set `target_id` to `role`, or None."""
        if self._participant_role != CONFSRV_ROLE_HOST:
            return "not_host"
        if role not in (CONFSRV_ROLE_SPECTATOR, CONFSRV_ROLE_PARTICIPANT):
            return "role"
        target = _member(room, target_id)
        if target is None:
            return "unknown_target"
        if target._participant_role == CONFSRV_ROLE_HOST:
            return "target_is_host"
        return None

    def _leave_room(self):
        """Drop out of the roster and tell whoever is left."""
        room, self._room = self._room, None
        if room is None:
            return
        participant_id = self._participant_id
        self._participant_id = None
        self._participant_role = None
        with room.lock:
            if self in room.members:
                room.members.remove(self)
            left = _build_event(CONFSRV_EVENT_PARTICIPANT_LEFT, participant_id)
            for member in room.members:
                member._push_event(left, "participant_left")
            members = len(room.members)
        log.info(
            "leave room=%s participant=%s members=%d",
            self._room_id,
            participant_id,
            members,
        )

    def _participant_record(self):
        """Pack this member for a TEXTCHAT roster event.

        HandleParticipantListEvent @ TEXTCHAT 0x7F2D54C0 walks the payload in
        strides of 14 header bytes plus name_length and rejects the whole
        event with error 0x3A if the last record does not land on its end. The
        name is not terminated: CreateMemberRecord copies name_length bytes
        and adds the NUL itself.
        """
        name = self._display_name.encode("cp1252", errors="replace")
        return (
            struct.pack(
                "<IHIHH",
                self._participant_id,
                self._participant_role,
                len(name),
                0,
                0,
            )
            + name
        )

    def _parse_record(self, request_id, payload):
        """The one variable parameter selector 2 carries, header checked."""
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 1
            and isinstance(send_params[0], VarParam)
            and recv_descriptors == []
        )
        record = send_params[0].data if valid_shape else b""
        if len(record) < 8:
            log.warning(
                "send invalid request req_id=%d params=%d recv=%s record_len=%d",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
                len(record),
            )
            return None
        return record

    def _push_event(self, event, label):
        """Deliver one event on this member's retained join iterator."""
        if self._join_subscription is None:
            return
        msg_class, request_id = self._join_subscription
        self._push(
            msg_class,
            request_id,
            bytes([TAG_DYNAMIC_STREAM_END]) + event,
            label,
        )

    def _push(self, msg_class, request_id, reply_payload, label, ack=False):
        if self.connection is None:
            return
        selector = CONFSRV_SELECTOR_SEND if ack else CONFSRV_SELECTOR_JOIN
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        try:
            self.connection.push_service_data(
                self.pipe_idx,
                host_block,
                f"svc={self.svc_name} {label}",
            )
        except OSError as exc:
            log.warning(
                "push failed label=%s participant=%s error=%s",
                label,
                self._participant_id,
                exc,
            )


def _build_event(event_type, sender_id, payload=b""):
    """Pack CONFAPI's 8-byte event header: type WORD, pad WORD, sender DWORD.

    QueueServerEvent copies the DWORD at +4 into CConfMsg+8 and the rest into
    the message payload. TEXTCHAT's participant-left handler reads only that
    DWORD, so a leave event carries no payload at all.
    """
    return struct.pack("<HHI", event_type, 0, sender_id) + payload


def _member(room, participant_id):
    return next(
        (member for member in room.members if member._participant_id == participant_id),
        None,
    )


def _participant_role(node, conference, user):
    username = user.username.casefold()
    if (
        node is not None
        and username
        and any(host.casefold() == username for host in node.host_usernames)
    ):
        return CONFSRV_ROLE_HOST
    if conference is None or conference.join_as_participants:
        return CONFSRV_ROLE_PARTICIPANT
    return CONFSRV_ROLE_SPECTATOR


def _build_stored_conference_properties(content_store, record_id):
    if len(record_id) != 8:
        return None
    field_0, field_8 = struct.unpack("<II", record_id)
    node_id = f"{field_0}:{field_8}"
    node = content_store.get_node(node_id)
    if (
        node is None
        or node.node_id != node_id
        or node.app_id != APP_TEXT_CONFERENCE
        or node.content.conference is None
    ):
        return None
    conference = node.content.conference
    return build_property_record(
        [
            (0x03, "mm", struct.pack("<I", conference.room_capacity)),
            (0x03, "ml", struct.pack("<I", conference.message_length)),
            (0x03, "ds", struct.pack("<I", conference.join_as_participants)),
        ]
    )


def _apply_conference_properties(content_store, record_id, properties):
    """Commit CONFLOC's room settings to the shared directory node."""
    if len(record_id) != 8:
        return False
    field_0, field_8 = struct.unpack("<II", record_id)
    node_id = f"{field_0}:{field_8}"
    node = content_store.get_node(node_id)
    if node is None or node.node_id != node_id or node.app_id != APP_TEXT_CONFERENCE:
        return False

    values = {}
    for property_name, field_name in (
        ("mm", "room_capacity"),
        ("ml", "message_length"),
        ("ds", "join_as_participants"),
    ):
        item = properties.get(property_name)
        if item is None:
            continue
        property_type, value = item
        if property_type != 0x03 or not isinstance(value, int):
            raise ValueError(f"property {property_name!r} is not a DWORD")
        if property_name == "ds" and value not in (0, 1):
            raise ValueError("property 'ds' is not a Boolean DWORD")
        values[field_name] = bool(value) if property_name == "ds" else value

    if not values:
        return False

    conference = node.content.conference
    if conference is None:
        missing = {
            "room_capacity",
            "message_length",
            "join_as_participants",
        } - values.keys()
        if missing:
            raise ValueError("new conference record is missing " + ", ".join(sorted(missing)))
        conference = ConferenceFields(**values)
    else:
        conference = replace(conference, **values)

    content_store.add_node(replace(node, content=replace(node.content, conference=conference)))
    return True


def _build_data_edit_result(status):
    return build_tagged_reply_dword(status) + build_tagged_reply_dword(0) + bytes([TAG_END_STATIC])


def _build_data_edit_properties_result(status, records):
    return (
        build_tagged_reply_dword(status)
        + build_tagged_reply_dword(len(records))
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + b"".join(records)
    )


def _select_dword_properties(record, names):
    properties = _decode_property_record(record)
    selected = []
    for name in names:
        item = properties.get(name)
        if item is None:
            raise ValueError(f"property {name!r} is missing")
        property_type, value = item
        if property_type != 0x03 or not isinstance(value, int):
            raise ValueError(f"property {name!r} is not a DWORD")
        selected.append((property_type, name, struct.pack("<I", value)))
    return build_property_record(selected)
