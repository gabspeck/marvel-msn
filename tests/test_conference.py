"""CONFLOC and CONFSRV: room location, data edit and the chat event stream."""

import struct
import unittest
from dataclasses import replace

from server.config import (
    CONFLOC_INTERFACE_GUIDS,
    CONFSRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from server.services.conference import (
    CONFLOC_DATA_EDIT_CLASS,
    CONFLOC_RESULT_FOUND,
    CONFLOC_RESULT_NOT_FOUND,
    CONFLOC_SELECTOR_DATA_EDIT_ADD,
    CONFLOC_SELECTOR_DATA_EDIT_DELETE,
    CONFLOC_SELECTOR_DATA_EDIT_GET_PROPERTIES,
    CONFLOC_SELECTOR_DATA_EDIT_GET_TICKET,
    CONFLOC_SELECTOR_DATA_EDIT_SET_PROPERTIES,
    CONFSRV_EVENT_PARTICIPANT_JOINED,
    CONFSRV_EVENT_PARTICIPANT_LEFT,
    CONFSRV_EVENT_PARTICIPANT_LIST,
    CONFSRV_EVENT_ROLE,
    CONFSRV_EVENT_TEXT,
    CONFSRV_JOINED,
    CONFSRV_ROLE_HOST,
    CONFSRV_ROLE_PARTICIPANT,
    CONFSRV_ROLE_SPECTATOR,
    CONFSRV_ROOM_FULL,
    CONFSRV_SELECTOR_JOIN,
    CONFSRV_SELECTOR_SEND,
    ConflocHandler,
    ConfsrvHandler,
)
from server.services.dirsrv import (
    build_property_record,
    get_ticket_reply,
)
from server.services.rooms import _rooms as conference_rooms
from server.session import Session
from server.store import (
    ConferenceFields,
    app_store,
    reset_app_store,
)

from .support import (
    ADMIN,
    SUBSCRIBER,
    AddNodeContentStore,
    RecordingConnection,
    host_payload,
    reply_payload,
    signed_in,
)


def _join_room(handler, room_id, request_id=7, msg_class=0x01):
    """Run one CONFSRV join through the deferred-reply path."""
    handler.handle_request(
        msg_class,
        CONFSRV_SELECTOR_JOIN,
        request_id,
        b"\x03" + struct.pack("<I", room_id) + b"\x04\x81\x00\x85",
        0,
        0,
    )
    handler.flush_pending_events()


def _with_store(handler, content_store):
    """Point a conference handler at a test content store."""
    if content_store is not None:
        handler.content_store = content_store
    return handler


def _joined_handler(pipe_idx, session, room_id, content_store=None, request_id=7):
    """A CONFSRV handler bound to a recording connection and already joined."""
    handler = _with_store(ConfsrvHandler(pipe_idx, "CONFSRV", session), content_store)
    connection = RecordingConnection(pipe_idx)
    handler.bind_connection(connection)
    _join_room(handler, room_id, request_id)
    return handler, connection


def _send_text(handler, text, request_id=8, msg_class=0x01):
    """Run one CONFSRV type-0 send through the deferred-reply path."""
    record = struct.pack("<HHI", CONFSRV_EVENT_TEXT, 0, 99) + text.encode("utf-16le") + b"\x00\x00"
    handler.handle_request(
        msg_class,
        CONFSRV_SELECTOR_SEND,
        request_id,
        b"\x04" + bytes([0x80 | len(record)]) + record,
        0,
        0,
    )
    handler.flush_pending_events()


def _set_role(handler, target_id, role, request_id=9, msg_class=0x01):
    """Run one CONFSRV type-7 host-control record, as ErrHostSetStatus packs it."""
    record = struct.pack("<HHIIH", CONFSRV_EVENT_ROLE, 0, 0, target_id, role)
    handler.handle_request(
        msg_class,
        CONFSRV_SELECTOR_SEND,
        request_id,
        b"\x04" + bytes([0x80 | len(record)]) + record,
        0,
        0,
    )
    handler.flush_pending_events()


def _pushed_payloads(connection):
    """The host-block payload of every packet the connection has been given."""
    return [host_payload(pkt) for pkt in connection.packets]


def _parse_participants(payload):
    """Unpack a type-2/type-4 roster payload into (id, role, name) tuples."""
    records = []
    offset = 9
    while offset < len(payload):
        participant_id, role, name_len, reserved_1, reserved_2 = struct.unpack_from(
            "<IHIHH",
            payload,
            offset,
        )
        assert (reserved_1, reserved_2) == (0, 0)
        name = payload[offset + 14 : offset + 14 + name_len].decode("cp1252")
        records.append((participant_id, role, name))
        offset += 14 + name_len
    return records


class TestConferenceStartup(unittest.TestCase):
    def setUp(self):
        conference_rooms.clear()
        self.addCleanup(conference_rooms.clear)

    def test_discovery_catalogs_match_confapi_tables(self):
        self.assertEqual(
            [guid[0] for guid, _selector in CONFLOC_INTERFACE_GUIDS],
            [
                0x52,
                0x53,
                0x54,
                0x55,
                0x56,
                0x57,
                0x58,
                0x60,
                0x61,
                0x70,
                0x71,
                0x72,
                0x73,
                0x74,
                0x78,
                0x79,
                0x81,
            ],
        )
        self.assertEqual(
            [guid[0] for guid, _selector in CONFSRV_INTERFACE_GUIDS],
            [0xC8, 0xC9, 0xCA],
        )
        self.assertEqual(
            [selector for _guid, selector in CONFLOC_INTERFACE_GUIDS],
            list(range(1, 18)),
        )

    def test_locator_resolves_a_created_chat_node(self):
        store = AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="1:275",
            is_container=True,
            app_id=4,
            mnid_a=struct.pack("<II", 1, 275),
            content=parent.content,
        )
        store.add_child("1:16", chat)
        handler = _with_store(ConflocHandler(10, "CONFLOC", Session()), store)

        reply = handler.locate_reply(b"\x03" + struct.pack("<I", 1) + b"\x82\x82")

        self.assertEqual(struct.unpack_from("<H", reply, 1)[0], 1)
        self.assertEqual(struct.unpack_from("<H", reply, 4)[0], CONFLOC_RESULT_FOUND)
        self.assertEqual(reply[6], TAG_END_STATIC)

    def test_locator_resolves_the_default_chat_room(self):
        reset_app_store()
        room = app_store.content.get_node("1:271")
        self.assertEqual(room.content.name, "MSN Chat")
        self.assertEqual(room.app_id, 4)
        self.assertEqual(room.content.conference.room_capacity, 10)
        self.assertEqual(room.content.conference.message_length, 1000)
        self.assertTrue(room.content.conference.join_as_participants)
        self.assertEqual(room.host_usernames, ("billg",))
        self.assertIn(
            room,
            app_store.content.get_children("1:16", struct.pack("<II", 1, 0x0409)),
        )

        handler = ConflocHandler(10, "CONFLOC", Session())
        reply = handler.locate_reply(b"\x03" + struct.pack("<I", 1) + b"\x82\x82")

        self.assertEqual(struct.unpack_from("<H", reply, 1)[0], 1)
        self.assertEqual(struct.unpack_from("<H", reply, 4)[0], CONFLOC_RESULT_FOUND)

    def test_data_edit_get_ticket_returns_the_capability_blob(self):
        handler = ConflocHandler(10, "CONFLOC", signed_in())
        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_SELECTOR_DATA_EDIT_GET_TICKET,
            0,
            b"\x83\x85",
            0,
            0,
        )
        self.assertEqual(reply_payload(packets), get_ticket_reply(handler.session))

    def test_data_edit_add_completes_the_chat_record(self):
        handler = ConflocHandler(10, "CONFLOC", signed_in())
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 275)
        properties = struct.pack("<IH", 6, 0)
        request = (
            b"\x04\x82"
            + ticket
            + b"\x03\x04\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\xff\xff"
            + b"\x04\x86"
            + properties
            + b"\x83\x83"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_SELECTOR_DATA_EDIT_ADD,
            1,
            request,
            0,
            0,
        )

        self.assertEqual(
            reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )

    def test_data_edit_delete_completes_after_tree_delete(self):
        record_id = struct.pack("<II", 1, 271)
        request = (
            b"\x04\x82\x02\x00"
            + b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\xff\xff"
            + b"\x83\x83"
        )
        # TREEEDCL removes the directory node before DATAEDCL reaches CONFLOC.
        handler = _with_store(ConflocHandler(10, "CONFLOC", signed_in()), AddNodeContentStore())

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_SELECTOR_DATA_EDIT_DELETE,
            1,
            request,
            0,
            0,
        )

        self.assertEqual(
            reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )

    def test_data_edit_get_props_round_trips_record(self):
        handler = ConflocHandler(10, "CONFLOC", signed_in())
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 275)
        properties = build_property_record(
            [
                (0x03, "ds", struct.pack("<I", 1)),
                (0x03, "ml", struct.pack("<I", 1000)),
                (0x03, "mm", struct.pack("<I", 100)),
                (0x03, "unrequested", struct.pack("<I", 42)),
            ]
        )
        add_request = (
            b"\x04\x82"
            + ticket
            + b"\x03\x04\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\xff\xff"
            + b"\x04"
            + bytes([0x80 | len(properties)])
            + properties
            + b"\x83\x83"
        )
        handler.data_edit_add_reply(1, add_request)
        get_request = (
            b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\x00\x00"
            + b"\x03\x03\x00\x00\x00"
            + b"\x04\x89ds\x00ml\x00mm\x00"
            + b"\x83\x83\x85"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_SELECTOR_DATA_EDIT_GET_PROPERTIES,
            2,
            get_request,
            0,
            0,
        )
        selected = build_property_record(
            [
                (0x03, "ds", struct.pack("<I", 1)),
                (0x03, "ml", struct.pack("<I", 1000)),
                (0x03, "mm", struct.pack("<I", 100)),
            ]
        )

        self.assertEqual(
            reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x01\x00\x00\x00\x87\x86" + selected,
        )

    def test_seeded_chat_exposes_its_conference_settings(self):
        reset_app_store()
        handler = ConflocHandler(10, "CONFLOC", signed_in())
        record_id = struct.pack("<II", 1, 0x10F)
        request = (
            b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\x00\x00"
            + b"\x03\x03\x00\x00\x00"
            + b"\x04\x89mm\x00ml\x00ds\x00"
            + b"\x83\x83\x85"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_SELECTOR_DATA_EDIT_GET_PROPERTIES,
            2,
            request,
            0,
            0,
        )
        selected = build_property_record(
            [
                (0x03, "mm", struct.pack("<I", 10)),
                (0x03, "ml", struct.pack("<I", 1000)),
                (0x03, "ds", struct.pack("<I", 1)),
            ]
        )

        self.assertEqual(
            reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x01\x00\x00\x00\x87\x86" + selected,
        )

    def test_data_edit_set_props_applies_room_values(self):
        store = AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="1:275",
            is_container=True,
            app_id=4,
            mnid_a=struct.pack("<II", 1, 275),
            content=parent.content,
        )
        store.add_child("1:16", chat)
        handler = _with_store(ConflocHandler(10, "CONFLOC", signed_in()), store)
        ticket = b"\x02\x00"
        record_id = struct.pack("<II", 1, 275)
        properties = build_property_record(
            [
                (0x03, "ml", struct.pack("<I", 500)),
                (0x03, "mm", struct.pack("<I", 200)),
                (0x03, "ds", struct.pack("<I", 0)),
            ]
        )
        request = (
            b"\x04\x82"
            + ticket
            + b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\x00\x00"
            + b"\x04"
            + bytes([0x80 | len(properties)])
            + properties
            + b"\x83\x83"
        )

        packets = handler.handle_request(
            CONFLOC_DATA_EDIT_CLASS,
            CONFLOC_SELECTOR_DATA_EDIT_SET_PROPERTIES,
            3,
            request,
            0,
            0,
        )

        self.assertEqual(
            reply_payload(packets),
            b"\x83\x00\x00\x00\x00\x83\x00\x00\x00\x00\x87",
        )
        self.assertNotIn(record_id, handler._records)
        conference = store.get_node("1:275").content.conference
        self.assertEqual(conference.room_capacity, 200)
        self.assertEqual(conference.message_length, 500)
        self.assertFalse(conference.join_as_participants)

        _joined, joined_connection = _joined_handler(
            11,
            signed_in(SUBSCRIBER),
            1,
            content_store=store,
        )
        join_reply = _pushed_payloads(joined_connection)[0]
        self.assertEqual(struct.unpack_from("<H", join_reply, 10)[0], CONFSRV_ROLE_SPECTATOR)
        self.assertEqual(struct.unpack_from("<I", join_reply, 12)[0], 500)

        fresh_handler = _with_store(ConflocHandler(10, "CONFLOC", signed_in()), store)
        get_request = (
            b"\x03\x01\x00\x00\x00"
            + b"\x04\x88"
            + record_id
            + b"\x02\x00\x00"
            + b"\x03\x03\x00\x00\x00"
            + b"\x04\x89mm\x00ml\x00ds\x00"
            + b"\x83\x83\x85"
        )
        fresh_reply = fresh_handler.data_edit_get_props_reply(
            4,
            get_request,
        )
        selected = build_property_record(
            [
                (0x03, "mm", struct.pack("<I", 200)),
                (0x03, "ml", struct.pack("<I", 500)),
                (0x03, "ds", struct.pack("<I", 0)),
            ]
        )
        self.assertEqual(
            fresh_reply,
            b"\x83\x00\x00\x00\x00\x83\x01\x00\x00\x00\x87\x86" + selected,
        )

    def test_data_edit_add_rejects_anonymous_writes(self):
        handler = ConflocHandler(10, "CONFLOC", Session())
        ticket = b"\x02\x00"
        request = (
            b"\x04\x82"
            + ticket
            + b"\x03\x04\x00\x00\x00"
            + b"\x04\x88"
            + struct.pack("<II", 1, 275)
            + b"\x02\xff\xff"
            + b"\x04\x86"
            + struct.pack("<IH", 6, 0)
            + b"\x83\x83"
        )
        reply = handler.data_edit_add_reply(1, request)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0x101)

    def test_locator_rejects_an_unknown_room(self):
        handler = _with_store(ConflocHandler(10, "CONFLOC", Session()), AddNodeContentStore())
        reply = handler.locate_reply(b"\x03" + struct.pack("<I", 275) + b"\x82\x82")
        self.assertEqual(struct.unpack_from("<H", reply, 1)[0], 0)
        self.assertEqual(struct.unpack_from("<H", reply, 4)[0], CONFLOC_RESULT_NOT_FOUND)

    def test_join_designates_billg_as_host(self):
        reset_app_store()
        _handler, connection = _joined_handler(11, signed_in(), 1)
        reply = _pushed_payloads(connection)[0]

        self.assertEqual(
            reply[:2],
            bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]),
        )
        status, padding, participant, role, message_limit, name_chars = struct.unpack_from(
            "<HHIHII", reply, 2
        )
        self.assertEqual(status, CONFSRV_JOINED)
        self.assertEqual(padding, 0)
        self.assertEqual(participant, 1)
        self.assertEqual(role, CONFSRV_ROLE_HOST)
        self.assertEqual(message_limit, 1000)
        self.assertEqual(name_chars, len("MSN Chat") + 1)
        self.assertEqual(
            reply[20 : 20 + name_chars * 2].decode("utf-16le").rstrip("\x00"),
            "MSN Chat",
        )

    def test_join_pushes_billg_as_the_host_participant(self):
        reset_app_store()
        _handler, connection = _joined_handler(11, signed_in(), 1)

        self.assertEqual(connection.labels, ["svc=CONFSRV join", "svc=CONFSRV participant_list"])
        join_payload, participant_push = _pushed_payloads(connection)
        self.assertEqual(join_payload[:2], bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]))
        self.assertEqual(participant_push[0], TAG_DYNAMIC_STREAM_END)

        event_type, padding, sender = struct.unpack_from("<HHI", participant_push, 1)
        self.assertEqual(event_type, CONFSRV_EVENT_PARTICIPANT_LIST)
        self.assertEqual(padding, 0)
        self.assertEqual(sender, 0)
        self.assertEqual(
            _parse_participants(participant_push),
            [(1, CONFSRV_ROLE_HOST, "Bill Gates")],
        )

    def test_join_keeps_other_accounts_as_participants(self):
        reset_app_store()
        _handler, connection = _joined_handler(11, signed_in(SUBSCRIBER), 1)

        join_payload, participant_push = _pushed_payloads(connection)
        join_role = struct.unpack_from("<H", join_payload, 10)[0]
        _id, participant_role, _name = _parse_participants(participant_push)[0]

        self.assertEqual(join_role, CONFSRV_ROLE_PARTICIPANT)
        self.assertEqual(participant_role, CONFSRV_ROLE_PARTICIPANT)

    def test_join_uses_the_room_host_list(self):
        store = AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="275:1",
            is_container=False,
            app_id=4,
            mnid_a=struct.pack("<II", 275, 1),
            content=replace(
                parent.content,
                conference=ConferenceFields(
                    room_capacity=10,
                    message_length=1000,
                    join_as_participants=False,
                ),
            ),
            host_usernames=(SUBSCRIBER.upper(), ADMIN),
        )
        store.add_child("1:16", chat)

        roles = []
        for session in (signed_in(SUBSCRIBER), signed_in(ADMIN), Session()):
            _handler, connection = _joined_handler(
                11,
                session,
                275,
                content_store=store,
            )
            join_reply = _pushed_payloads(connection)[0]
            roles.append(struct.unpack_from("<H", join_reply, 10)[0])

        self.assertEqual(
            roles,
            [CONFSRV_ROLE_HOST, CONFSRV_ROLE_HOST, CONFSRV_ROLE_SPECTATOR],
        )

    def test_join_refuses_members_past_the_room_capacity(self):
        store = AddNodeContentStore()
        parent = store.get_node("1:16")
        chat = parent.__class__(
            node_id="275:1",
            is_container=False,
            app_id=4,
            mnid_a=struct.pack("<II", 275, 1),
            content=replace(
                parent.content,
                conference=ConferenceFields(
                    room_capacity=2,
                    message_length=1000,
                    join_as_participants=True,
                ),
            ),
        )
        store.add_child("1:16", chat)
        first, first_connection = _joined_handler(
            11,
            signed_in(ADMIN),
            275,
            content_store=store,
        )
        second, second_connection = _joined_handler(
            12,
            signed_in(SUBSCRIBER),
            275,
            content_store=store,
        )
        refused, refused_connection = _joined_handler(
            13,
            signed_in(ADMIN),
            275,
            content_store=store,
        )

        self.assertEqual(
            struct.unpack_from("<H", _pushed_payloads(first_connection)[0], 2)[0],
            CONFSRV_JOINED,
        )
        self.assertEqual(
            struct.unpack_from("<H", _pushed_payloads(second_connection)[0], 2)[0],
            CONFSRV_JOINED,
        )
        self.assertEqual(refused_connection.labels, ["svc=CONFSRV join_refused"])
        self.assertEqual(
            struct.unpack_from("<H", _pushed_payloads(refused_connection)[0], 2)[0],
            CONFSRV_ROOM_FULL,
        )

        first.close()
        _join_room(refused, 275)
        self.assertEqual(refused_connection.labels[-2], "svc=CONFSRV join")
        self.assertEqual(
            struct.unpack_from("<H", _pushed_payloads(refused_connection)[1], 2)[0],
            CONFSRV_JOINED,
        )
        second.close()
        refused.close()

    def test_send_acknowledges_and_echoes_text_on_the_join_iterator(self):
        reset_app_store()
        handler, connection = _joined_handler(11, signed_in(), 1)
        connection.packets.clear()
        connection.labels.clear()

        _send_text(handler, "hello")

        self.assertEqual(connection.labels, ["svc=CONFSRV send_ack", "svc=CONFSRV text"])
        ack, push = _pushed_payloads(connection)
        self.assertEqual(ack, bytes([TAG_END_STATIC]))
        self.assertEqual(push[0], TAG_DYNAMIC_STREAM_END)
        event_type, padding, participant_id = struct.unpack_from("<HHI", push, 1)
        self.assertEqual((event_type, padding, participant_id), (CONFSRV_EVENT_TEXT, 0, 1))
        self.assertEqual(push[9:].decode("utf-16le").rstrip("\x00"), "hello")

    def test_text_reaches_every_member_of_the_room(self):
        reset_app_store()
        speaker, speaker_connection = _joined_handler(11, signed_in(), 1)
        listener, listener_connection = _joined_handler(12, signed_in(SUBSCRIBER), 1)
        listener_connection.packets.clear()
        listener_connection.labels.clear()
        speaker_connection.packets.clear()

        _send_text(speaker, "hello")

        self.assertEqual(listener_connection.labels, ["svc=CONFSRV text"])
        speaker_copy = _pushed_payloads(speaker_connection)[1]
        listener_copy = _pushed_payloads(listener_connection)[0]
        self.assertEqual(speaker_copy, listener_copy)
        self.assertEqual(
            struct.unpack_from("<I", listener_copy, 5)[0],
            speaker._participant_id,
        )
        self.assertEqual(listener_copy[9:].decode("utf-16le").rstrip("\x00"), "hello")
        listener.close()

    def test_join_publishes_the_roster_to_everyone(self):
        reset_app_store()
        first, first_connection = _joined_handler(11, signed_in(), 1)
        first_connection.packets.clear()
        first_connection.labels.clear()

        second, second_connection = _joined_handler(12, signed_in(SUBSCRIBER), 1)

        self.assertEqual(
            _parse_participants(_pushed_payloads(second_connection)[1]),
            [(1, CONFSRV_ROLE_HOST, "Bill Gates"), (2, CONFSRV_ROLE_PARTICIPANT, "Steve Jobs")],
        )
        self.assertEqual(first_connection.labels, ["svc=CONFSRV participant_joined"])
        joined_push = _pushed_payloads(first_connection)[0]
        event_type, _padding, sender = struct.unpack_from("<HHI", joined_push, 1)
        self.assertEqual(event_type, CONFSRV_EVENT_PARTICIPANT_JOINED)
        self.assertEqual(sender, second._participant_id)
        self.assertEqual(
            _parse_participants(joined_push),
            [(2, CONFSRV_ROLE_PARTICIPANT, "Steve Jobs")],
        )
        first.close()
        second.close()

    def test_a_host_demotes_a_participant_to_spectator(self):
        reset_app_store()
        host, host_connection = _joined_handler(11, signed_in(), 1)
        member, member_connection = _joined_handler(12, signed_in(SUBSCRIBER), 1)
        host_connection.packets.clear()
        host_connection.labels.clear()
        member_connection.packets.clear()
        member_connection.labels.clear()

        _set_role(host, member._participant_id, CONFSRV_ROLE_SPECTATOR)

        # The record reaches both, and TEXTCHAT wants a 6-byte payload.
        self.assertEqual(host_connection.labels, ["svc=CONFSRV send_ack", "svc=CONFSRV role"])
        self.assertEqual(member_connection.labels, ["svc=CONFSRV role"])
        pushed = _pushed_payloads(member_connection)[0]
        event_type, _padding, sender = struct.unpack_from("<HHI", pushed, 1)
        target_id, role = struct.unpack_from("<IH", pushed, 9)
        self.assertEqual(event_type, CONFSRV_EVENT_ROLE)
        self.assertEqual(sender, host._participant_id)
        self.assertEqual((target_id, role), (2, CONFSRV_ROLE_SPECTATOR))
        self.assertEqual(len(pushed) - 9, 6)
        self.assertEqual(member._participant_role, CONFSRV_ROLE_SPECTATOR)

        # A spectator is silent, and a later roster carries the new role.
        member_connection.packets.clear()
        _send_text(member, "hello")
        self.assertEqual(member_connection.labels[-1], "svc=CONFSRV send_ack")
        self.assertEqual(len(member_connection.packets), 1)

        _later, later_connection = _joined_handler(13, signed_in(SUBSCRIBER), 1)
        self.assertEqual(
            _parse_participants(_pushed_payloads(later_connection)[1])[1][1],
            CONFSRV_ROLE_SPECTATOR,
        )

    def test_role_changes_are_refused_unless_a_host_asks(self):
        reset_app_store()
        host, _host_connection = _joined_handler(11, signed_in(), 1)
        member, member_connection = _joined_handler(12, signed_in(SUBSCRIBER), 1)
        other, _other_connection = _joined_handler(13, signed_in(SUBSCRIBER), 1)
        member_connection.packets.clear()
        member_connection.labels.clear()

        # A participant may not set anyone's role.
        _set_role(member, other._participant_id, CONFSRV_ROLE_SPECTATOR)
        self.assertEqual(other._participant_role, CONFSRV_ROLE_PARTICIPANT)

        # A host may not demote another host, invent a role, or name a stranger.
        _set_role(host, host._participant_id, CONFSRV_ROLE_SPECTATOR)
        _set_role(host, member._participant_id, CONFSRV_ROLE_HOST)
        _set_role(host, 99, CONFSRV_ROLE_SPECTATOR)

        self.assertEqual(host._participant_role, CONFSRV_ROLE_HOST)
        self.assertEqual(member._participant_role, CONFSRV_ROLE_PARTICIPANT)
        # Only the acks went out; no role event was relayed.
        self.assertEqual(member_connection.labels, ["svc=CONFSRV send_ack"])

    def test_leaving_tells_the_members_left_behind(self):
        reset_app_store()
        first, first_connection = _joined_handler(11, signed_in(), 1)
        second, _second_connection = _joined_handler(12, signed_in(SUBSCRIBER), 1)
        first_connection.packets.clear()
        first_connection.labels.clear()

        second.handle_iterator_cancel(0x01, CONFSRV_SELECTOR_JOIN, 7)

        self.assertEqual(first_connection.labels, ["svc=CONFSRV participant_left"])
        left_push = _pushed_payloads(first_connection)[0]
        event_type, _padding, sender = struct.unpack_from("<HHI", left_push, 1)
        self.assertEqual(event_type, CONFSRV_EVENT_PARTICIPANT_LEFT)
        self.assertEqual(sender, 2)
        self.assertEqual(len(left_push), 9)
        first.close()


if __name__ == "__main__":
    unittest.main()
