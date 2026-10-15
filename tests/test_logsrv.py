"""LOGSRV: sign-in, password change, billing and signup selectors."""

import struct
import unittest

from server.models import DwordParam, EndMarker, VarParam
from server.mpc import (
    build_tagged_reply_var,
    parse_tagged_params,
)
from server.services.logsrv import (
    BOOTSTRAP_PAYLOAD,
    LOGIN_BLOB_LEN,
    LOGIN_BLOB_MEMBER_ID_OFFSET,
    LOGIN_BLOB_PASSWORD_OFFSET,
    LOGIN_RESULT_BAD_MEMBER_ID,
    LOGIN_RESULT_BAD_PASSWORD,
    LogsrvHandler,
    _handle_billing_query,
    _handle_login,
    _handle_password_change,
)
from server.session import Session
from server.store import (
    app_store,
    reset_app_store,
)
from server.transport import parse_packet

from .support import (
    ADMIN,
    ADMIN_PASSWORD,
    SUBSCRIBER,
    SUBSCRIBER_PASSWORD,
    signed_in,
)


class TestLOGSRVBootstrap(unittest.TestCase):
    def test_structure(self):
        payload = BOOTSTRAP_PAYLOAD
        # Should contain 7 dword tags (0x83), then 0x87, then 0x84 variable
        pos = 0
        dword_count = 0
        while pos < len(payload) and payload[pos] == 0x83:
            dword_count += 1
            pos += 5  # tag + 4-byte value
        self.assertEqual(dword_count, 7)
        self.assertEqual(payload[pos], 0x87)  # end of static section
        pos += 1
        self.assertEqual(payload[pos], 0x84)  # variable tag
        pos += 1
        # Next byte is length (0x90 = inline 16)
        self.assertEqual(payload[pos], 0x90)
        pos += 1
        # 16 bytes of data
        self.assertEqual(len(payload) - pos, 16)

    def test_first_dword_is_zero(self):
        # Field 0 = login result code, should be 0 (success)
        payload = BOOTSTRAP_PAYLOAD
        result_code = struct.unpack("<I", payload[1:5])[0]
        self.assertEqual(result_code, 0)

    def test_parseable(self):
        payload = BOOTSTRAP_PAYLOAD
        params = parse_tagged_params(payload)
        self.assertIsNotNone(params)
        self.assertGreater(len(params), 0)
        # First 7 params should be dwords
        for p in params[:7]:
            self.assertIsInstance(p, DwordParam)
        # Then an EndMarker
        self.assertIsInstance(params[7], EndMarker)
        # Then a variable param
        self.assertIsInstance(params[8], VarParam)


def _login_blob(member_id, password):
    """The credential blob GUIDE.EXE!VerifyAccountViaLogSrv @ 0x04304024 builds."""
    blob = bytearray(LOGIN_BLOB_LEN)
    blob[LOGIN_BLOB_MEMBER_ID_OFFSET : LOGIN_BLOB_MEMBER_ID_OFFSET + len(member_id)] = (
        member_id.encode("ascii")
    )
    blob[LOGIN_BLOB_PASSWORD_OFFSET : LOGIN_BLOB_PASSWORD_OFFSET + len(password)] = password.encode(
        "ascii"
    )
    return bytes(blob)


def _login_request(member_id=ADMIN, password=ADMIN_PASSWORD):
    """A whole selector 0x00 request: version dword, blob, recv descriptors."""
    return (
        b"\x03"
        + struct.pack("<I", 0x001643)
        + build_tagged_reply_var(0x04, _login_blob(member_id, password))
        + b"\x83" * 7
        + b"\x84"
    )


# Every result `VerifyAccountViaLogSrv` @ GUIDE.EXE 0x04304024 gives its own
# dialog. Anything outside this set falls to the catch-all, string 0x2F5
# "Password not valid.", which is why the bad-password reply must stay unmapped.
_LOGIN_RESULTS_THE_CLIENT_MAPS = frozenset(
    {0x00, 0x0C, 0x01, 0x02, 0x0A, 0x0D, 0x16, 0x22, 0x23, 0x24}
)


class TestLOGSRVLogin(unittest.TestCase):
    """Selector 0x00 checks the blob against the store and signs the session in."""

    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    def _login(self, session, member_id, password):
        reply = _handle_login(_login_request(member_id, password), session)
        return struct.unpack_from("<I", reply, 1)[0]

    def test_matching_credentials_sign_the_connection_in(self):
        session = Session()
        self.assertEqual(self._login(session, ADMIN, ADMIN_PASSWORD), 0)
        self.assertTrue(session.is_authenticated)
        self.assertEqual(session.user.display_name, "Bill Gates")

    def test_a_wrong_password_names_the_password(self):
        # An unmapped result is the client's catch-all, which is string 0x2F5
        # "Password not valid. Please type it again."
        session = Session()
        self.assertEqual(
            self._login(session, ADMIN, SUBSCRIBER_PASSWORD), LOGIN_RESULT_BAD_PASSWORD
        )
        self.assertNotIn(LOGIN_RESULT_BAD_PASSWORD, _LOGIN_RESULTS_THE_CLIENT_MAPS)
        self.assertFalse(session.is_authenticated)

    def test_an_unknown_member_id_names_the_member_id(self):
        # 2 is string 0x2FC "This member ID is not valid."
        session = Session()
        self.assertEqual(self._login(session, "nobody", ADMIN_PASSWORD), LOGIN_RESULT_BAD_MEMBER_ID)
        self.assertFalse(session.is_authenticated)

    def test_a_known_member_id_is_not_reported_as_unknown(self):
        # The two failures are distinguishable, so a typo'd password must not
        # tell the member their id is wrong.
        session = Session()
        self.assertNotEqual(
            self._login(session, ADMIN, SUBSCRIBER_PASSWORD), LOGIN_RESULT_BAD_MEMBER_ID
        )

    def test_a_request_without_the_blob_is_rejected(self):
        session = Session()
        result = struct.unpack_from("<I", _handle_login(b"", session), 1)[0]
        self.assertEqual(result, LOGIN_RESULT_BAD_MEMBER_ID)
        self.assertFalse(session.is_authenticated)

    def test_reply_shape_same_when_accepted_or_rejected(self):
        # The client unmarshals seven dwords and a 16-byte variable either way;
        # only the first dword differs.
        accepted = _handle_login(_login_request(), Session())
        rejected = _handle_login(b"", Session())
        self.assertEqual(len(accepted), len(rejected))
        self.assertEqual(accepted[5:], rejected[5:])


class TestLOGSRVPasswordChange(unittest.TestCase):
    """Selector 0x01 commits only against the account that signed in."""

    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    @staticmethod
    def _request(old, new):
        return (
            build_tagged_reply_var(0x04, old.encode() + b"\x00" * (17 - len(old)))
            + build_tagged_reply_var(0x04, new.encode() + b"\x00" * (17 - len(new)))
            + b"\x83"
        )

    def test_the_right_current_password_commits_the_new_one(self):
        session = signed_in()
        reply = _handle_password_change(self._request(ADMIN_PASSWORD, "newpass"), session)
        self.assertEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, "newpass"))
        self.assertEqual(session.user.password, "newpass")

    def test_a_wrong_current_password_changes_nothing(self):
        reply = _handle_password_change(self._request("guess", "newpass"), signed_in())
        self.assertNotEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))

    def test_an_anonymous_connection_cannot_change_a_password(self):
        reply = _handle_password_change(self._request(ADMIN_PASSWORD, "newpass"), Session())
        self.assertNotEqual(struct.unpack_from("<I", reply, 1)[0], 0)
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))


class TestLOGSRVBillingQuery(unittest.TestCase):
    """Selector 0x0A describes the account the connection signed in as."""

    def _buffer(self, session):
        payload = _handle_billing_query(session)
        return parse_tagged_params(payload)[0].data

    def test_each_account_gets_its_own_address_and_card(self):
        admin = self._buffer(signed_in(ADMIN))
        subscriber = self._buffer(signed_in(SUBSCRIBER))

        self.assertIn(b"Gates\x00", admin)
        self.assertIn(b"Redmond\x00", admin)
        self.assertNotIn(b"Gates\x00", subscriber)
        self.assertIn(b"Jobs\x00", subscriber)
        self.assertIn(b"Cupertino\x00", subscriber)

    def test_the_buffer_is_always_the_full_0x41c_bytes(self):
        for session in (signed_in(ADMIN), Session()):
            with self.subTest(user=session.user.username or "anonymous"):
                self.assertEqual(len(self._buffer(session)), 0x41C)


class TestLOGSRVReply(unittest.TestCase):
    def test_login_reply_returns_packet(self):
        handler = LogsrvHandler(3, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x00, 0, _login_request(), 4, 4)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_password_change_reply(self):
        # Selector 0x01 = password change
        pw_payload = bytes.fromhex(
            "04 91 74 65 73 74 65 00 3f 27 27 01 00 00 1f 19"
            "3f 27 27 04 91 61 76 6f 63 61 64 6f 73 00 00 00"
            "00 54 2b 10 04 b8 83"
        )
        handler = LogsrvHandler(8, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x01, 0, pw_payload, 37, 36)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_signup_post_transfer_returns_packet(self):
        """Selector 0x02 is called on a fresh LOGSRV pipe after the FTM
        phone-book transfer finishes; client hangs at "Starting transfer..."
        if the server returns None.  Minimum viable reply is an empty 0x84
        variable satisfying the single recv descriptor.
        """
        payload = bytes.fromhex("03 5f 01 00 00 03 00 00 00 00 03 00 00 00 00 84")
        handler = LogsrvHandler(6, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x02, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_signup_query_returns_packet(self):
        """Selector 0x07 (SIGNUP's 'product details' query) must reply.

        The client sends a single recv descriptor (0x85) and hangs when
        the server returns None; the minimum viable reply is an empty
        0x84 variable.
        """
        handler = LogsrvHandler(3, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x07, 1, b"\x85", 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_post_signup_query_returns_packet(self):
        """Selector 0x0d fires on a fresh LOGSRV pipe right after the
        OLREGSRV commit reply.  Returning None makes the client disconnect
        before the Internet-access prompt and Congrats dialog can appear.
        """
        payload = bytes.fromhex("03 5f 01 00 00 03 00 00 00 00 03 00 00 00 00 84")
        handler = LogsrvHandler(6, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x0D, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_existing_member_phonebook_query_returns_packet(self):
        """Opcode 0x0e fires on a fresh LOGSRV pipe from SIGNUP's
        "I'm already a member → Update local phone numbers → Connect"
        path.  Caller checks recv_dword == 0 for success.
        """
        payload = bytes.fromhex("03 08 00 00 00 83")
        handler = LogsrvHandler(4, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x0E, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertIsInstance(pkts, list)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_unknown_selector_returns_none(self):
        handler = LogsrvHandler(3, "LOGSRV", Session())
        pkt = handler.handle_request(0x06, 0xFF, 0, b"", 5, 5)
        self.assertIsNone(pkt)

    def test_known_login_reply_wire_bytes(self):
        handler = LogsrvHandler(3, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, 0x00, 0, _login_request(), 4, 4)
        expected = bytes.fromhex(
            "84 84 e3 3b 00 03 00 06 00 00 83 00 00 00 00 83"
            "00 00 00 00 83 00 00 00 00 83 00 00 00 00 83 00"
            "00 00 00 83 00 00 00 00 83 00 00 00 00 87 84 1b"
            "35 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 2b 11 96 ab 0d"
        )
        self.assertEqual(pkts[0], expected)


class TestLOGSRVCommitTagType(unittest.TestCase):
    """LOGSRV billing-commit replies (selectors 0x0B/0x0C) MUST use 0x84
    (var) rather than 0x83 (dword).  BILLADD's
    BillingDlg_ProcessCommitReply unblocks on either, but its tag-type
    check rejects 0x83 — leaving the OK button stuck."""

    def _commit_reply(self, selector):
        handler = LogsrvHandler(3, "LOGSRV", Session())
        pkts = handler.handle_request(0x06, selector, 0, b"", 5, 5)
        parsed = parse_packet(pkts[0][:-1])
        # Skip pipe header(1) + length prefix(2) + routing prefix(2)
        host_block = parsed.payload[5:]
        # host_block layout: msg_class | selector | VLI req_id | reply
        # Our request_id=0 fits in 1 VLI byte → reply starts at offset 3.
        return host_block[3:]

    def test_pm_commit_uses_var_tag(self):
        reply = self._commit_reply(0x0B)
        self.assertEqual(reply[0], 0x84, "PM commit reply must use 0x84 var tag, not 0x83 dword")

    def test_billing_commit_uses_var_tag(self):
        reply = self._commit_reply(0x0C)
        self.assertEqual(
            reply[0], 0x84, "Billing commit reply must use 0x84 var tag, not 0x83 dword"
        )

    def test_var_payload_is_status_dword(self):
        # Inline length byte (bit 7 set) for a 4-byte status dword = 0x84.
        reply = self._commit_reply(0x0C)
        self.assertEqual(reply[1], 0x84)  # 0x80 | 4
        self.assertEqual(len(reply), 2 + 4)
        status = struct.unpack("<I", reply[2:6])[0]
        self.assertEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
