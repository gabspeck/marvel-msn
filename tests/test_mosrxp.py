"""Tests for the MOSRXP service handler (remote mail).

The wire contract is documented in docs/MOSRXP.md. The decoders here are a
deliberate re-implementation of the client's parsers — `CConn::HrDSrlProp`
@ 0x7F432435 for a property, `FUN_7F439959` for a header record — so a failure
means the two disagree, which on screen is an Inbox with shifted columns or a
message the reader refuses to open.
"""

import datetime
import struct
import unittest

from server.config import MOSRXP_INTERFACE_GUIDS
from server.mpc import parse_host_block
from server.services.mosrxp import (
    CONNINFO_LEN,
    MOS_ENTRYID_LEN,
    MOSRXP_CLASS_XP,
    MOSRXP_CLOSE_INBOX,
    MOSRXP_DEL_MESSAGES,
    MOSRXP_FLAG_SERVER_MESSAGE,
    MOSRXP_GET_CONN_INFO,
    MOSRXP_GET_FIRST_MESSAGE,
    MOSRXP_GET_HEADERS,
    MOSRXP_GET_MESSAGE,
    MOSRXP_INIT_TRANSMIT,
    MOSRXP_OPEN_INBOX,
    MOSRXP_SEND_BLOCK,
    PR_BODY,
    PR_DISPLAY_TO,
    PR_MESSAGE_CLASS,
    PR_MESSAGE_DELIVERY_TIME,
    PR_MESSAGE_SIZE,
    PR_SENDER_EMAIL_ADDRESS,
    PR_SENT_REPRESENTING_NAME,
    PR_SUBJECT,
    UEID_PROVIDER_UID,
    MOSRXPHandler,
    build_conninfo,
    build_header_record,
    build_message_blob,
    decode_entryid,
    encode_entryid,
    encode_prop_list,
    encode_recip_list,
    from_filetime,
    to_filetime,
)
from server.session import Session
from server.store import MailMessage, MailRecipient, app_store, reset_app_store
from server.transport import parse_packet

_FIXED_WIDTHS = {0x02: 2, 0x03: 4, 0x04: 4, 0x05: 8, 0x06: 8, 0x07: 8, 0x0B: 2, 0x14: 8, 0x40: 8}


def decode_prop(raw, pos):
    """One property, the way `HrDSrlProp` reads it: tag, then a width by type."""
    (tag,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    prop_type = tag & 0xFFFF
    if prop_type == 0x1E:
        end = raw.index(b"\x00", pos)
        return tag, raw[pos:end].decode("cp1252"), end + 1
    if prop_type == 0x1F:
        end = pos
        while raw[end : end + 2] != b"\x00\x00":
            end += 2
        return tag, raw[pos:end].decode("utf-16le"), end + 2
    if prop_type == 0x102:
        (cb,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        return tag, raw[pos : pos + cb], pos + cb
    if prop_type == 0x48:
        return tag, raw[pos : pos + 16], pos + 16
    width = _FIXED_WIDTHS[prop_type]
    return tag, int.from_bytes(raw[pos : pos + width], "little"), pos + width


def decode_prop_list(raw, pos):
    (count,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    props = {}
    for _ in range(count):
        tag, value, pos = decode_prop(raw, pos)
        props[tag] = value
    return props, pos


def decode_recip_list(raw, pos):
    (count,) = struct.unpack_from("<I", raw, pos)
    pos += 4
    out = []
    for _ in range(count):
        props, pos = decode_prop_list(raw, pos)
        out.append(props)
    return out, pos


def decode_header_blob(raw, count):
    """`FUN_7F439959`: `count` records of `[entryid:12][cValues][props]`."""
    pos = 0
    out = []
    for _ in range(count):
        entryid = raw[pos : pos + MOS_ENTRYID_LEN]
        pos += MOS_ENTRYID_LEN
        props, pos = decode_prop_list(raw, pos)
        out.append((entryid, props))
    return out, pos


def decode_message_blob(raw):
    """`HrDSrlMsg`: header props, recipients, body props, attachment list."""
    head, pos = decode_prop_list(raw, 0)
    recipients, pos = decode_recip_list(raw, pos)
    body, pos = decode_prop_list(raw, pos)
    (attachments,) = struct.unpack_from("<I", raw, pos)
    return head, recipients, body, attachments, pos + 4


def reply_payload(packets):
    """The host-block payload of a one-packet service reply.

    Frame is `[header byte][content length:u16][routing prefix:u16][host block]`
    and the packet carries its 0x0D terminator, which `parse_packet` expects to
    have been stripped already.
    """
    frame = parse_packet(packets[0][:-1]).payload
    return parse_host_block(frame[5:]).payload


MESSAGE = MailMessage(
    message_id=7,
    mailbox="billg",
    sender_name="Steve Jobs",
    sender_address="sjobs",
    subject="Re: Lunch?",
    body="Thursday works.\r\n",
    delivered=datetime.datetime(1995, 8, 26, 12, 15, tzinfo=datetime.UTC),
    recipients=(MailRecipient(display_name="Bill Gates", address="billg"),),
)


class EntryIdTest(unittest.TestCase):
    def test_round_trip(self):
        raw = encode_entryid(42)
        self.assertEqual(len(raw), MOS_ENTRYID_LEN)
        self.assertEqual(decode_entryid(raw), 42)

    def test_foreign_entryid_is_rejected(self):
        self.assertIsNone(decode_entryid(b"\xff" * MOS_ENTRYID_LEN))

    def test_short_entryid_is_rejected(self):
        self.assertIsNone(decode_entryid(b"\x00" * 4))


class FiletimeTest(unittest.TestCase):
    def test_round_trip(self):
        when = datetime.datetime(1995, 8, 24, 9, 0, tzinfo=datetime.UTC)
        self.assertEqual(from_filetime(to_filetime(when)), when)

    def test_known_value(self):
        # 1601-01-01 + 1 s
        self.assertEqual(
            to_filetime(datetime.datetime(1601, 1, 1, 0, 0, 1, tzinfo=datetime.UTC)),
            10_000_000,
        )


class SerialisationTest(unittest.TestCase):
    def test_prop_list_widths(self):
        raw = encode_prop_list([(PR_SUBJECT, "hi"), (PR_MESSAGE_SIZE, 0x1234)])
        props, end = decode_prop_list(raw, 0)
        self.assertEqual(props[PR_SUBJECT], "hi")
        self.assertEqual(props[PR_MESSAGE_SIZE], 0x1234)
        self.assertEqual(end, len(raw))

    def test_string8_carries_its_terminator(self):
        raw = encode_prop_list([(PR_SUBJECT, "ab")])
        # [count:4][tag:4]"ab\0"
        self.assertEqual(len(raw), 4 + 4 + 3)

    def test_recip_list_is_one_prop_list_per_entry(self):
        raw = encode_recip_list(
            [
                MailRecipient(display_name="Bill Gates", address="billg"),
                MailRecipient(display_name="Steve Jobs", address="sjobs"),
            ]
        )
        entries, end = decode_recip_list(raw, 0)
        self.assertEqual(end, len(raw))
        self.assertEqual([e[0x3003001E] for e in entries], ["billg", "sjobs"])
        self.assertEqual([e[0x3002001E] for e in entries], ["MSN", "MSN"])

    def test_header_record_layout(self):
        raw = build_header_record(MESSAGE)
        records, end = decode_header_blob(raw, 1)
        self.assertEqual(end, len(raw))
        entryid, props = records[0]
        self.assertEqual(decode_entryid(entryid), MESSAGE.message_id)
        self.assertEqual(props[PR_SUBJECT], "Re: Lunch?")
        self.assertEqual(props[PR_SENT_REPRESENTING_NAME], "Steve Jobs")
        self.assertEqual(props[PR_DISPLAY_TO], "Bill Gates")
        self.assertEqual(props[PR_MESSAGE_CLASS], "IPM.Note")
        self.assertEqual(from_filetime(props[PR_MESSAGE_DELIVERY_TIME]), MESSAGE.delivered)

    def test_header_record_carries_the_psptahdr_set(self):
        _records, _end = decode_header_blob(build_header_record(MESSAGE), 1)
        props = _records[0][1]
        self.assertEqual(
            sorted(props),
            sorted(
                [
                    0x0FFE0003,  # PR_OBJECT_TYPE
                    0x0E170003,  # PR_MSG_STATUS
                    0x0E070003,  # PR_MESSAGE_FLAGS
                    0x001A001E,  # PR_MESSAGE_CLASS
                    0x00170003,  # PR_IMPORTANCE
                    0x0042001E,  # PR_SENT_REPRESENTING_NAME
                    0x0E04001E,  # PR_DISPLAY_TO
                    0x00360003,  # PR_SENSITIVITY
                    0x0E1B000B,  # PR_HASATTACH
                    0x0037001E,  # PR_SUBJECT
                    0x0E060040,  # PR_MESSAGE_DELIVERY_TIME
                    0x0E080003,  # PR_MESSAGE_SIZE
                ]
            ),
        )

    def test_message_size_is_the_served_byte_count(self):
        blob = build_message_blob(MESSAGE)
        head, _recips, _body, _att, end = decode_message_blob(blob)
        self.assertEqual(end, len(blob))
        self.assertEqual(head[PR_MESSAGE_SIZE], len(blob))

    def test_message_blob_sections(self):
        head, recipients, body, attachments, _end = decode_message_blob(build_message_blob(MESSAGE))
        self.assertEqual(head[PR_SUBJECT], "Re: Lunch?")
        self.assertEqual([r[0x3003001E] for r in recipients], ["billg"])
        self.assertEqual(body[PR_BODY], "Thursday works.\r\n")
        self.assertEqual(body[PR_SENDER_EMAIL_ADDRESS], "sjobs")
        self.assertEqual(attachments, 0)

    def test_body_props_avoid_the_ranges_the_client_drops(self):
        # HrDSrlPropList skips ids 0x0E00-0x0FFF, 0x6000-0x67FF and
        # 0x7C00-0x7FFF before SetProps, so a body prop in one is dead weight.
        _head, _recips, body, _att, _end = decode_message_blob(build_message_blob(MESSAGE))
        for tag in body:
            prop_id = tag >> 16
            self.assertFalse(0x0E00 <= prop_id <= 0x0FFF, f"0x{tag:08X}")
            self.assertFalse(0x6000 <= prop_id <= 0x67FF, f"0x{tag:08X}")
            self.assertFalse(0x7C00 <= prop_id <= 0x7FFF, f"0x{tag:08X}")


def signed_in(username="billg"):
    session = Session()
    session.sign_in(app_store.users.get_user(username))
    return MOSRXPHandler(pipe_idx=4, svc_name="MOSRXP", session=session)


def request(*params):
    return b"".join(params)


def dword_param(value):
    return b"\x03" + struct.pack("<I", value)


def var_param(data):
    if len(data) < 0x80:
        return b"\x04" + bytes([0x80 | len(data)]) + data
    return b"\x04" + struct.pack(">H", len(data)) + data


class HandlerTest(unittest.TestCase):
    def setUp(self):
        reset_app_store()
        self.handler = signed_in()

    def call(self, selector, payload=b""):
        packets = self.handler.handle_request(MOSRXP_CLASS_XP, selector, 0, payload, 1, 1)
        self.assertIsNotNone(packets)
        return reply_payload(packets)

    def test_discovery_advertises_the_one_iid(self):
        self.assertEqual(len(MOSRXP_INTERFACE_GUIDS), 1)
        guid, selector = MOSRXP_INTERFACE_GUIDS[0]
        self.assertEqual(selector, MOSRXP_CLASS_XP)
        packets = self.handler.build_discovery_packet(1, 1)
        self.assertIn(guid, parse_packet(packets[0]).payload)

    def test_get_conn_info_answers_the_member_entry_id(self):
        # Observed live: the request is `83 84` — one DWORD slot and one
        # variable slot, no stream flag.
        payload = self.call(MOSRXP_GET_CONN_INFO, b"\x83\x84")
        self.assertEqual(payload[:5], b"\x83" + struct.pack("<I", 0))
        self.assertEqual(payload[5], 0x87)
        self.assertEqual(payload[6], 0x84)
        blob = payload[-CONNINFO_LEN:]
        self.assertEqual(len(blob), CONNINFO_LEN)
        self.assertEqual(blob[0x04:0x14], UEID_PROVIDER_UID)
        self.assertEqual(struct.unpack_from("<II", blob, 0x14), (2, 1))
        self.assertEqual(blob[0x1C:].split(b"\x00", 1)[0], b"Bill Gates")
        self.assertEqual(blob[0x77:].split(b"\x00", 1)[0], b"billg")

    def test_conninfo_names_are_truncated_with_room_for_a_terminator(self):
        blob = build_conninfo("D" * 200, "M" * 200)
        self.assertEqual(len(blob), CONNINFO_LEN)
        self.assertEqual(blob[0x1C : 0x1C + 0x5B].count(b"D"), 0x5A)
        self.assertEqual(blob[0x1C + 0x5A], 0)
        self.assertEqual(blob[0x77:].count(b"M"), 0x40)
        self.assertEqual(blob[CONNINFO_LEN - 1], 0)

    def test_open_inbox_answers_status_and_count(self):
        payload = self.call(MOSRXP_OPEN_INBOX, b"\x83\x83\x85")
        self.assertEqual(payload[:5], b"\x83" + struct.pack("<I", 0))
        self.assertEqual(payload[5:10], b"\x83" + struct.pack("<I", 1))
        self.assertEqual(payload[10:], b"\x87")

    def test_close_inbox_answers_status_only(self):
        self.assertEqual(self.call(MOSRXP_CLOSE_INBOX, b"\x83\x85"), b"\x83\x00\x00\x00\x00\x87")

    def test_get_headers_reply_shape(self):
        payload = self.call(MOSRXP_GET_HEADERS, b"\x83\x83\x85")
        self.assertEqual(payload[:5], b"\x83" + struct.pack("<I", 0))
        (count,) = struct.unpack_from("<I", payload, 6)
        self.assertEqual(payload[5], 0x83)
        self.assertEqual(count, 1)
        self.assertEqual(payload[10:12], b"\x87\x86")
        records, end = decode_header_blob(payload[12:], count)
        self.assertEqual(end, len(payload) - 12)
        self.assertEqual(records[0][1][PR_SUBJECT], "Welcome to The Microsoft Network")

    def test_get_headers_on_an_empty_mailbox(self):
        app_store.mail.delete_messages("billg", [1])
        payload = self.call(MOSRXP_GET_HEADERS, b"\x83\x83\x85")
        self.assertEqual(payload, b"\x83" + b"\x00" * 4 + b"\x83" + b"\x00" * 4 + b"\x87\x86")

    def test_get_message_returns_the_body(self):
        payload = self.call(MOSRXP_GET_MESSAGE, var_param(encode_entryid(1)) + b"\x83\x85")
        self.assertEqual(payload[:5], b"\x83" + struct.pack("<I", 0))
        self.assertEqual(payload[5:7], b"\x87\x86")
        _head, _recips, body, _att, _end = decode_message_blob(payload[7:])
        self.assertIn("Welcome to MSN.", body[PR_BODY])

    def test_get_message_miss_answers_not_found_with_no_blob(self):
        payload = self.call(MOSRXP_GET_MESSAGE, var_param(encode_entryid(999)) + b"\x83\x85")
        self.assertEqual(payload, b"\x83" + struct.pack("<I", 0x8004010F) + b"\x87")

    def test_get_first_message_prefixes_the_entry_id(self):
        payload = self.call(MOSRXP_GET_FIRST_MESSAGE, b"\x83\x85")
        self.assertEqual(payload[5:7], b"\x87\x86")
        blob = payload[7:]
        self.assertEqual(decode_entryid(blob[:MOS_ENTRYID_LEN]), 1)
        head, _recips, _body, _att, _end = decode_message_blob(blob[MOS_ENTRYID_LEN:])
        self.assertEqual(head[PR_SUBJECT], "Welcome to The Microsoft Network")

    def test_del_messages_removes_every_id(self):
        payload = self.call(
            MOSRXP_DEL_MESSAGES,
            dword_param(1) + var_param(encode_entryid(1)) + b"\x83\x85",
        )
        self.assertEqual(payload, b"\x83" + b"\x00" * 4 + b"\x87")
        self.assertEqual(app_store.mail.list_messages("billg"), [])

    def test_flag_server_message_stores_the_status(self):
        payload = self.call(
            MOSRXP_FLAG_SERVER_MESSAGE,
            var_param(encode_entryid(1)) + dword_param(0x2000) + b"\x83\x85",
        )
        self.assertEqual(payload, b"\x83" + b"\x00" * 4 + b"\x87")
        self.assertEqual(app_store.mail.get_message("billg", 1).status, 0x2000)

    def test_flag_unknown_message_answers_not_found(self):
        payload = self.call(
            MOSRXP_FLAG_SERVER_MESSAGE,
            var_param(encode_entryid(999)) + dword_param(0x2000) + b"\x83\x85",
        )
        self.assertEqual(payload, b"\x83" + struct.pack("<I", 0x8004010F) + b"\x87")

    def test_unknown_selector_is_left_unanswered(self):
        self.assertIsNone(self.handler.handle_request(MOSRXP_CLASS_XP, 0x7F, 0, b"", 1, 1))

    def test_foreign_class_is_left_unanswered(self):
        self.assertIsNone(self.handler.handle_request(0x02, MOSRXP_OPEN_INBOX, 0, b"", 1, 1))


class SubmitTest(unittest.TestCase):
    """The send path: InitTransmit, then the message in SendBlock payloads."""

    def setUp(self):
        reset_app_store()
        self.handler = signed_in("billg")

    def submitted_message(self, subject, body, recipients):
        return (
            encode_prop_list([(PR_SUBJECT, subject)])
            + encode_recip_list(recipients)
            + encode_prop_list([(PR_BODY, body)])
            + struct.pack("<I", 0)
        )

    def send(self, blob, block_size=None):
        self.handler.handle_request(
            MOSRXP_CLASS_XP, MOSRXP_INIT_TRANSMIT, 0, dword_param(0x1000) + b"\x83\x85", 1, 1
        )
        size = block_size or len(blob)
        blocks = [blob[i : i + size] for i in range(0, len(blob), size)] or [b""]
        for index, block in enumerate(blocks):
            last = index == len(blocks) - 1
            self.handler.handle_request(
                MOSRXP_CLASS_XP,
                MOSRXP_SEND_BLOCK,
                index,
                dword_param(index) + dword_param(int(last)) + var_param(block) + b"\x83\x85",
                1,
                1,
            )

    def test_inline_block_is_delivered(self):
        blob = self.submitted_message(
            "Thursday",
            "One o'clock.\r\n",
            [MailRecipient(display_name="Steve Jobs", address="sjobs")],
        )
        self.send(blob)
        inbox = app_store.mail.list_messages("sjobs")
        self.assertEqual([m.subject for m in inbox], ["Lunch?", "Thursday"])
        delivered = inbox[-1]
        self.assertEqual(delivered.body, "One o'clock.\r\n")
        self.assertEqual(delivered.sender_address, "billg")
        self.assertEqual(delivered.sender_name, "Bill Gates")

    def test_message_split_across_blocks_is_reassembled(self):
        blob = self.submitted_message(
            "Split", "x" * 300, [MailRecipient(display_name="Steve Jobs", address="sjobs")]
        )
        self.send(blob, block_size=64)
        self.assertEqual(app_store.mail.list_messages("sjobs")[-1].body, "x" * 300)

    def test_chunked_block_waits_for_its_stream(self):
        blob = self.submitted_message(
            "Chunked", "body\r\n", [MailRecipient(display_name="Steve Jobs", address="sjobs")]
        )
        self.handler.handle_request(
            MOSRXP_CLASS_XP, MOSRXP_INIT_TRANSMIT, 0, dword_param(0x1000) + b"\x83\x85", 1, 1
        )
        # 0x05 reference: stream id 1, length follows. The bytes arrive after
        # the reply, on 0xE6/0xE7 frames.
        reference = b"\x05" + bytes([1]) + struct.pack("<I", len(blob))
        self.handler.handle_request(
            MOSRXP_CLASS_XP,
            MOSRXP_SEND_BLOCK,
            0,
            dword_param(0) + dword_param(1) + reference + b"\x83\x85",
            1,
            1,
        )
        # Nothing delivered yet: the block's bytes have not arrived.
        self.assertEqual([m.subject for m in app_store.mail.list_messages("sjobs")], ["Lunch?"])

        half = len(blob) // 2
        self.handler.handle_request(0xE6, 1, 0, blob[:half], 1, 1)
        self.assertEqual(len(app_store.mail.list_messages("sjobs")), 1)
        self.handler.handle_request(0xE7, 1, 0, blob[half:], 1, 1)
        self.assertEqual(app_store.mail.list_messages("sjobs")[-1].subject, "Chunked")

    def test_recipient_addressed_by_display_name_is_delivered(self):
        # What the client actually sends. MOSABP keys members on the display
        # name, so a recipient picked out of the address book arrives with
        # PR_EMAIL_ADDRESS = "Steve Jobs", not "sjobs".
        blob = self.submitted_message(
            "From the address book",
            "hello\r\n",
            [MailRecipient(display_name="Steve Jobs", address="Steve Jobs")],
        )
        self.send(blob)
        self.assertEqual(
            [m.subject for m in app_store.mail.list_messages("sjobs")],
            ["Lunch?", "From the address book"],
        )

    def test_recipient_with_only_a_display_name_is_delivered(self):
        blob = self.submitted_message(
            "Unresolved",
            "hello\r\n",
            [MailRecipient(display_name="Steve Jobs", address="")],
        )
        self.send(blob)
        self.assertEqual(app_store.mail.list_messages("sjobs")[-1].subject, "Unresolved")

    def test_unknown_recipient_is_dropped(self):
        blob = self.submitted_message(
            "Nowhere", "hello", [MailRecipient(display_name="Nobody", address="nobody")]
        )
        self.send(blob)
        self.assertEqual(app_store.mail.list_messages("nobody"), [])

    def test_foreign_addrtype_is_dropped(self):
        blob = self.submitted_message(
            "Fax it",
            "hello",
            [MailRecipient(display_name="Steve Jobs", address="sjobs", addrtype="FAX")],
        )
        self.send(blob)
        self.assertEqual([m.subject for m in app_store.mail.list_messages("sjobs")], ["Lunch?"])


if __name__ == "__main__":
    unittest.main()
