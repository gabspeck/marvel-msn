"""CONFLOC/CONFSRV startup path used by the MSN text-chat client."""

import logging
import struct
import threading
import weakref
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
CONFLOC_DATA_EDIT_SET_PROPERTIES = 0x02
CONFLOC_DATA_EDIT_GET_PROPERTIES = 0x03
CONFLOC_DATA_EDIT_GET_TICKET = 0x05
CONFSRV_SELECTOR_JOIN = 0x03
CONFSRV_SELECTOR_SEND = 0x02

# CONFAPI!CConversation::CceJoin @ 0x7F5B16FC branches on these WORD values.
CONFLOC_RESULT_FOUND = 1
CONFLOC_RESULT_NOT_FOUND = 2
CONFSRV_JOINED = 3
CONFSRV_EVENT_TEXT = 0
CONFSRV_EVENT_PARTICIPANTS = 2
# CONFAPI CceJoin maps wire status 8 to result 2; TEXTCHAT's join caller maps
# result 2 to string 0x3C, "This chat is currently full."
CONFSRV_ROOM_FULL = 8
# TEXTCHAT HostControlsDialogProc maps its spectator radio to role 0 and its
# participant radio to role 1. HandleParticipantListEvent treats role 2 as host.
CONFSRV_ROLE_SPECTATOR = 0
CONFSRV_ROLE_PARTICIPANT = 1
CONFSRV_ROLE_HOST = 2

# Fallback for an incomplete authored room record. Seeded rooms carry their
# CONFLOC settings in the content store.
DEFAULT_MESSAGE_LENGTH = 1000

_room_members = {}
_room_members_lock = threading.Lock()


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
        elif (
            msg_class == CONFLOC_DATA_EDIT_CLASS
            and selector == CONFLOC_DATA_EDIT_SET_PROPERTIES
        ):
            reply_payload = self.build_data_edit_set_properties_reply_payload(
                request_id, payload
            )
        elif (
            msg_class == CONFLOC_DATA_EDIT_CLASS
            and selector == CONFLOC_DATA_EDIT_GET_PROPERTIES
        ):
            reply_payload = self.build_data_edit_get_properties_reply_payload(
                request_id, payload
            )
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
                self.content_store, record_id, decoded,
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
            "data_edit_add status=0 req_id=%d table=%d record_id=%s "
            "dataset=0x%04x props=%s",
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
            known_record = known_record or (
                node is not None and node.app_id == APP_TEXT_CONFERENCE
            )
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
                self.content_store, record_id, decoded,
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
                self.content_store, record_id,
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
                "data_edit_get_properties invalid stored record req_id=%d "
                "record_id=%s error=%s",
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
    """Join a text conference and service its retained event iterator."""

    def __init__(self, pipe_idx, svc_name, session=None, content_store=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        self.session = session or Session()
        self.content_store = content_store or _default_store.content
        self._join_subscription = None
        self._participant_id = None
        self._participant_role = None
        self._joined_room_id = None

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(CONFSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if selector == CONFSRV_SELECTOR_JOIN:
            self._join_subscription = (msg_class, request_id)
            self._participant_id = 1
            reply_payload = self.build_join_reply_payload(payload)
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            packets = build_service_packet(
                self.pipe_idx, host_block, server_seq, client_ack,
            )
            display_name = self.session.user.display_name
            if display_name and self._participant_role is not None:
                packets.extend(
                    self._build_event_push_packets(
                        _build_participants_event(
                            self._participant_id,
                            self._participant_role,
                            display_name,
                        ),
                        (server_seq + len(packets)) & 0x7F,
                        client_ack,
                    )
                )
            return packets

        if selector == CONFSRV_SELECTOR_SEND:
            ack_host = build_host_block(
                msg_class, selector, request_id, bytes([TAG_END_STATIC]),
            )
            packets = build_service_packet(
                self.pipe_idx, ack_host, server_seq, client_ack,
            )
            event = self._parse_text_event(request_id, payload)
            if event is not None and self._join_subscription is not None:
                packets.extend(
                    self._build_event_push_packets(
                        event,
                        (server_seq + len(packets)) & 0x7F,
                        client_ack,
                    )
                )
            return packets

        log_unhandled_selector(log, msg_class, selector, request_id, payload)
        return None

    def build_join_reply_payload(self, payload):
        """Push CONFAPI's initial join record as one complete dynamic item.

        CConversation::CceJoin reads this packed record as status WORD at +0,
        participant DWORD at +4, role WORD at +8, message limit DWORD at
        +10, and a counted UTF-16 conference name at +14/+18. The iterator is
        retained for later chat messages. A full room returns status 8 alone;
        the complete marker wakes the blocking iterator Next call in both cases.
        """
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

        room = self.content_store.find_app_instance(APP_TEXT_CONFERENCE, room_id)
        room_name = room.content.name if room is not None else ""
        conference = room.content.conference if room is not None else None
        room_capacity = conference.room_capacity if conference is not None else 0
        message_length = (
            conference.message_length
            if conference is not None
            else DEFAULT_MESSAGE_LENGTH
        )
        self._leave_room()
        if room is not None and not _join_room(self, room_id, room_capacity):
            self._participant_role = None
            log.info(
                "join room=%d name=%r capacity=%d status=%d",
                room_id,
                room_name,
                room_capacity,
                CONFSRV_ROOM_FULL,
            )
            return (
                bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
                + struct.pack("<H", CONFSRV_ROOM_FULL)
            )
        if room is not None:
            self._joined_room_id = room_id

        name = room_name.encode("utf-16le") + b"\x00\x00"
        participant_id = self._participant_id or 1
        username = self.session.user.username.casefold()
        participant_role = (
            CONFSRV_ROLE_HOST
            if room is not None
            and username
            and any(host.casefold() == username for host in room.host_usernames)
            else (
                CONFSRV_ROLE_PARTICIPANT
                if conference is None or conference.join_as_participants
                else CONFSRV_ROLE_SPECTATOR
            )
        )
        self._participant_role = participant_role
        record = struct.pack(
            "<HHIHII",
            CONFSRV_JOINED,
            0,
            participant_id,
            participant_role,
            message_length,
            len(name) // 2,
        ) + name
        log.info(
            "join room=%d name=%r participant=%d role=%d capacity=%d "
            "message_limit=%d status=%d",
            room_id,
            room_name,
            participant_id,
            participant_role,
            room_capacity,
            message_length,
            CONFSRV_JOINED,
        )
        return bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]) + record

    def handle_iterator_cancel(self, msg_class, selector, request_id):
        if self._join_subscription == (msg_class, request_id):
            self._join_subscription = None
            self._leave_room()

    def close(self):
        self._leave_room()

    def _leave_room(self):
        room_id = self._joined_room_id
        if room_id is None:
            return
        with _room_members_lock:
            members = _room_members.get(room_id)
            if members is not None:
                members.discard(self)
                if not members:
                    _room_members.pop(room_id, None)
        self._joined_room_id = None

    def _parse_text_event(self, request_id, payload):
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 1
            and isinstance(send_params[0], VarParam)
            and recv_descriptors == []
        )
        record = send_params[0].data if valid_shape else b""
        valid_record = (
            len(record) >= 10
            and len(record) % 2 == 0
            and struct.unpack_from("<H", record)[0] == CONFSRV_EVENT_TEXT
            and record[-2:] == b"\x00\x00"
        )
        if not valid_record:
            log.warning(
                "send_text invalid request req_id=%d params=%d recv=%s record_len=%d",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
                len(record),
            )
            return None

        event = bytearray(record)
        struct.pack_into("<I", event, 4, self._participant_id or 0)
        text = event[8:-2].decode("utf-16le", errors="replace")
        log.info(
            "send_text req_id=%d participant=%d chars=%d text=%r",
            request_id,
            self._participant_id or 0,
            len(text),
            text,
        )
        return bytes(event)

    def _build_event_push_packets(self, event, server_seq, client_ack):
        msg_class, request_id = self._join_subscription
        host_block = build_host_block(
            msg_class,
            CONFSRV_SELECTOR_JOIN,
            request_id,
            bytes([TAG_DYNAMIC_STREAM_END]) + event,
        )
        return build_service_packet(
            self.pipe_idx, host_block, server_seq, client_ack,
        )


def _build_participants_event(participant_id, role, display_name):
    name = display_name.encode("cp1252", errors="replace")
    participant = struct.pack(
        "<IHIHH",
        participant_id,
        role,
        len(name),
        0,
        0,
    ) + name
    return struct.pack("<HHI", CONFSRV_EVENT_PARTICIPANTS, 0, 0) + participant


def _join_room(handler, room_id, capacity):
    with _room_members_lock:
        members = _room_members.setdefault(room_id, weakref.WeakSet())
        if capacity > 0 and handler not in members and len(members) >= capacity:
            return False
        members.add(handler)
        return True


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
    if (
        node is None
        or node.node_id != node_id
        or node.app_id != APP_TEXT_CONFERENCE
    ):
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
            raise ValueError(
                "new conference record is missing " + ", ".join(sorted(missing))
            )
        conference = ConferenceFields(**values)
    else:
        conference = replace(conference, **values)

    content_store.add_node(
        replace(node, content=replace(node.content, conference=conference))
    )
    return True


def _build_data_edit_result(status):
    return (
        build_tagged_reply_dword(status)
        + build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC])
    )


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
