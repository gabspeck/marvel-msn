"""OLREGSRV: the signup commit."""

import unittest

from server.services.olregsrv import (
    OI_FIRST_NAME,
    OI_LAST_NAME,
    USER_INFO_MEMBER_ID,
    USER_INFO_PASSWORD,
    OlregsrvHandler,
)
from server.session import Session
from server.store import app_store, reset_app_store
from server.transport import parse_packet


def _put(buf, offset, text):
    buf[offset : offset + len(text)] = text.encode()


def _commit(handler, member_id, password, first, last):
    """Head plus the three one-way records, laid out as the OSR2 client sends them."""
    user_info = bytearray(0x150)
    _put(user_info, USER_INFO_MEMBER_ID, member_id)
    _put(user_info, USER_INFO_PASSWORD, password)
    oi = bytearray(0x2F8)
    _put(oi, OI_FIRST_NAME, first)
    _put(oi, OI_LAST_NAME, last)
    handler.handle_request(0x01, 0x01, 0, b"", 5, 5)
    handler.handle_request(0xE7, 0x01, 0, bytes(user_info), 5, 5)
    handler.handle_request(0xE6, 0x02, 0, bytes(oi[:463]), 5, 5)
    handler.handle_request(0xE7, 0x02, 0, bytes(oi[463:]), 5, 5)


class TestOLREGSRVReply(unittest.TestCase):
    def test_class01_acked_with_hresult_zero(self):
        """The class=0x01 head of the commit gets an HRESULT=0 reply body."""
        handler = OlregsrvHandler(4, "OLREGSRV", Session())
        pkts = handler.handle_request(0x01, 0x01, 0, b"", 5, 5)
        self.assertIsNotNone(pkts)
        self.assertEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)
        # Payload must contain tag 0x83 followed by four zero bytes.
        self.assertIn(b"\x83\x00\x00\x00\x00", parsed.payload)

    def test_one_way_records_get_no_reply(self):
        """class=0xe6/0xe7 continuation frames are fire-and-forget."""
        handler = OlregsrvHandler(4, "OLREGSRV", Session())
        self.assertIsNone(handler.handle_request(0xE7, 0x01, 0, b"", 5, 5))
        self.assertIsNone(handler.handle_request(0xE6, 0x02, 0, b"", 5, 5))
        self.assertIsNone(handler.handle_request(0xE7, 0x02, 0, b"", 5, 5))

    def test_sel02_probe_left_unanswered(self):
        """sel=0x02 pre-check must stay silent — any reply aborts signup."""
        handler = OlregsrvHandler(4, "OLREGSRV", Session())
        self.assertIsNone(handler.handle_request(0x01, 0x02, 0, b"\x83", 5, 5))


class TestOLREGSRVAccountCreation(unittest.TestCase):
    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    def test_commit_creates_an_account_that_can_sign_in(self):
        _commit(OlregsrvHandler(4, "OLREGSRV", Session()), "alice", "msnalice1", "Alice", "Tester")
        user = app_store.users.authenticate("alice", "msnalice1")
        self.assertIsNotNone(user)
        self.assertEqual(user.display_name, "Alice Tester")

    def test_a_taken_member_id_keeps_its_account(self):
        _commit(OlregsrvHandler(4, "OLREGSRV", Session()), "billg", "hijacked", "Not", "Bill")
        self.assertIsNone(app_store.users.authenticate("billg", "hijacked"))

    def test_incomplete_buffers_create_nothing(self):
        handler = OlregsrvHandler(4, "OLREGSRV", Session())
        handler.handle_request(0x01, 0x01, 0, b"", 5, 5)
        user_info = bytearray(0x150)
        _put(user_info, USER_INFO_MEMBER_ID, "carol")
        handler.handle_request(0xE7, 0x01, 0, bytes(user_info), 5, 5)
        handler.handle_request(0xE6, 0x02, 0, bytes(463), 5, 5)
        self.assertIsNone(app_store.users.get_user("carol"))


if __name__ == "__main__":
    unittest.main()
