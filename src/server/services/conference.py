"""CONFLOC/CONFSRV startup path used by the MSN text-chat client."""

import logging
import struct

from ..config import (
    CONFLOC_INTERFACE_GUIDS,
    CONFSRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_PARTIAL,
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
CONFLOC_DATA_EDIT_GET_PROPERTIES = 0x03
CONFLOC_DATA_EDIT_GET_TICKET = 0x05
CONFSRV_SELECTOR_JOIN = 0x03

# CONFAPI!CConversation::CceJoin @ 0x7F5B16FC branches on these WORD values.
CONFLOC_RESULT_FOUND = 1
CONFLOC_RESULT_NOT_FOUND = 2
CONFSRV_JOINED = 3

# DSNED's Conversation page constrains these fields to 2..10000 and 50..1000.
# The current directory model does not retain its unresolved `mm`/`ml` tags.
DEFAULT_ROOM_CAPACITY = 100
DEFAULT_MESSAGE_LENGTH = 1000


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

        log.info(
            "data_edit_add status=0 req_id=%d table=%d record_id=%s "
            "dataset=0x%04x properties_len=%d",
            request_id,
            send_params[1].value,
            record_id.hex(),
            send_params[3].value,
            len(properties),
        )
        self._records[record_id] = properties
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

        CONFAPI!FUN_7F5B14D3 sends the room's DWORD id and binds two WORD
        outputs. CceJoin treats result 1 as resolved and 2 as not found, then
        opens `CONFSRV` with the decimal instance in the pipe parameter.
        """
        send_params, recv_descriptors = parse_request_params(payload)
        room_id = next(
            (param.value for param in send_params if isinstance(param, DwordParam)),
            None,
        )
        node = self.content_store.get_node(f"1:{room_id}") if room_id is not None else None
        found = (
            node is not None
            and node.node_id == f"1:{room_id}"
            and node.app_id == APP_TEXT_CONFERENCE
        )
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
    """Accept the initial join that opens the text-chat window."""

    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        self.session = session or Session()

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(CONFSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if selector != CONFSRV_SELECTOR_JOIN:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        reply_payload = self.build_join_reply_payload(payload)
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def build_join_reply_payload(self, payload):
        """Push CONFAPI's initial status-3 record without ending the iterator.

        CConversation::CceJoin reads this packed record as status WORD at +0,
        participant DWORD at +4, capacity WORD at +8, message limit DWORD at
        +10, and a counted UTF-16 conference name at +14/+18. The iterator is
        retained for later chat messages, so the record uses dynamic-partial.
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

        participant_id = 1
        record = struct.pack(
            "<HHIHII",
            CONFSRV_JOINED,
            0,
            participant_id,
            DEFAULT_ROOM_CAPACITY,
            DEFAULT_MESSAGE_LENGTH,
            0,
        )
        log.info(
            "join room=%d participant=%d capacity=%d message_limit=%d status=%d",
            room_id,
            participant_id,
            DEFAULT_ROOM_CAPACITY,
            DEFAULT_MESSAGE_LENGTH,
            CONFSRV_JOINED,
        )
        return bytes([TAG_END_STATIC, TAG_DYNAMIC_PARTIAL]) + record


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
