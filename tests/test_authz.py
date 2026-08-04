"""What each account may do, as the wire reports it.

The super admin authors the directory tree and reads the SASRV master list; the
plain subscriber browses, posts, and removes only what it wrote. Every rule here
is a server-side policy decision — no capture shows how Marvel drew these lines
— so what the tests pin is that the decision reaches the wire, not that Marvel
made the same one.
"""

import struct
import unittest

from server.models import DirsrvRequest
from server.mpc import build_tagged_reply_var
from server.services import dirsrv
from server.services.dirsrv import (
    TREEEDCL_STATUS_REFUSED,
    build_get_children_reply_payload,
    build_get_ticket_reply_payload,
)
from server.services.sasrv import SA_E_BAD_LIST_KIND, SASRV_LIST_KIND_TOKENS, SASRVHandler
from server.store import app_store, reset_app_store
from server.store.records import build_bbs_post

from .support import ADMIN, SUBSCRIBER, anonymous, seed_user, signed_in

_BOARD_ID = 100
_ADMIN_POST = 9001
_SUBSCRIBER_POST = 9002


def _status(payload, offset=1):
    """Read one tagged reply dword out of `payload`."""
    return struct.unpack_from("<I", payload, offset)[0]


def _rights_of(payload):
    """Every `x` value in a GetChildren record stream."""
    return [
        struct.unpack_from("<I", payload, i + 3)[0]
        for i in range(len(payload))
        if payload[i : i + 3] == b"\x03x\x00"
    ]


class TestDirectoryRights(unittest.TestCase):
    """Wire property `x` is the account's own mask, not a constant."""

    REQUEST = DirsrvRequest(
        node_id="1:0",
        prop_group="a\x00e\x00x",
        recv_descriptors=[0x83, 0x83, 0x85],
    )

    def test_the_admin_is_told_it_may_author(self):
        rights = _rights_of(build_get_children_reply_payload(self.REQUEST, seed_user(ADMIN).rights))
        self.assertTrue(rights)
        self.assertTrue(all(r == 0x70 for r in rights))

    def test_the_subscriber_is_told_it_may_not(self):
        # `CMosTreeNode::HasRights` succeeds on any requested bit, so 0 is what
        # keeps File > New/Delete/Unlink out of the menu.
        rights = _rights_of(
            build_get_children_reply_payload(self.REQUEST, seed_user(SUBSCRIBER).rights)
        )
        self.assertTrue(rights)
        self.assertTrue(all(r == 0 for r in rights))


class TestDirectoryTicket(unittest.TestCase):
    """The DIRSRV pipe hands out a write ticket only to an authoring account."""

    def test_the_admin_receives_a_ticket(self):
        reply = build_get_ticket_reply_payload(signed_in(ADMIN))
        self.assertEqual(_status(reply), 0)
        self.assertEqual(reply[-2:], struct.pack("<H", 2))

    def test_the_subscriber_is_refused(self):
        reply = build_get_ticket_reply_payload(signed_in(SUBSCRIBER))
        self.assertEqual(_status(reply), TREEEDCL_STATUS_REFUSED)

    def test_an_anonymous_connection_is_refused(self):
        self.assertEqual(
            _status(build_get_ticket_reply_payload(anonymous())), TREEEDCL_STATUS_REFUSED
        )


class TestBbsTicket(unittest.TestCase):
    """The BBS pipe hands one to any signed-in member, who may delete their own post."""

    def test_any_signed_in_member_receives_a_ticket(self):
        for username in (ADMIN, SUBSCRIBER):
            with self.subTest(username=username):
                reply = build_get_ticket_reply_payload(signed_in(username), require_admin=False)
                self.assertEqual(_status(reply), 0)

    def test_an_anonymous_connection_is_still_refused(self):
        reply = build_get_ticket_reply_payload(anonymous(), require_admin=False)
        self.assertEqual(_status(reply), TREEEDCL_STATUS_REFUSED)


class TestDirectoryWrites(unittest.TestCase):
    """AddNode and SetProperties refuse before the store is touched."""

    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    def test_add_node_is_refused_for_the_subscriber(self):
        before = len(app_store.content.get_children("1:0"))
        reply = dirsrv.build_add_node_reply_payload(b"", session=signed_in(SUBSCRIBER))
        self.assertEqual(_status(reply), TREEEDCL_STATUS_REFUSED)
        self.assertEqual(len(app_store.content.get_children("1:0")), before)

    def test_set_properties_is_refused_for_the_subscriber(self):
        node = app_store.content.get_node("1:256")
        reply = dirsrv.build_set_properties_reply_payload(b"", session=signed_in(SUBSCRIBER))
        self.assertEqual(_status(reply), TREEEDCL_STATUS_REFUSED)
        self.assertEqual(app_store.content.get_node("1:256"), node)


class TestDeleteOwnership(unittest.TestCase):
    """A subscriber removes their own message and nothing else."""

    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)
        for msg_id, author in (
            (_ADMIN_POST, seed_user(ADMIN).display_name),
            (_SUBSCRIBER_POST, seed_user(SUBSCRIBER).display_name),
        ):
            app_store.content.add_node(
                build_bbs_post(
                    msg_id,
                    _BOARD_ID,
                    subject="Posted from the Compose window",
                    author=author,
                    parent_subid=0,
                    body_raw=b"body",
                    body_format="TEXT",
                    size_bytes=4,
                )
            )

    @staticmethod
    def _delete_request(msg_id):
        ticket = struct.pack("<H", 2)
        mnid = struct.pack("<II", msg_id, _BOARD_ID)
        return (
            build_tagged_reply_var(0x04, ticket) + build_tagged_reply_var(0x04, mnid) + b"\x83\x83"
        )

    def _delete(self, session, msg_id):
        return _status(
            dirsrv.build_delete_node_reply_payload(self._delete_request(msg_id), session=session)
        )

    def _node_id(self, msg_id):
        return f"{msg_id}:{_BOARD_ID}"

    def test_the_subscriber_removes_its_own_post(self):
        self.assertEqual(self._delete(signed_in(SUBSCRIBER), _SUBSCRIBER_POST), 0)
        # A removed mnid falls through to the store's fallback node.
        self.assertNotEqual(
            app_store.content.get_node(self._node_id(_SUBSCRIBER_POST)).node_id,
            self._node_id(_SUBSCRIBER_POST),
        )

    def test_the_subscriber_cannot_remove_someone_elses_post(self):
        self.assertEqual(self._delete(signed_in(SUBSCRIBER), _ADMIN_POST), TREEEDCL_STATUS_REFUSED)
        self.assertEqual(
            app_store.content.get_node(self._node_id(_ADMIN_POST)).node_id,
            self._node_id(_ADMIN_POST),
        )

    def test_the_admin_removes_any_post(self):
        for msg_id in (_ADMIN_POST, _SUBSCRIBER_POST):
            with self.subTest(msg_id=msg_id):
                self.assertEqual(self._delete(signed_in(ADMIN), msg_id), 0)


class TestSecurityTokens(unittest.TestCase):
    """The Security page's master list is the account's own token grant."""

    BEGIN_ENUM = (
        b"\x03"
        + struct.pack("<I", SASRV_LIST_KIND_TOKENS)
        + b"\x03"
        + struct.pack("<I", 0)
        + b"\x01\x00"
        + b"\x83\x83"
    )

    def _begin(self, session):
        handler = SASRVHandler(6, "SASRV", session)
        return handler, handler.build_begin_enum_reply_payload(self.BEGIN_ENUM)

    def test_the_admin_enumerates_every_token(self):
        handler, reply = self._begin(signed_in(ADMIN))
        self.assertEqual(_status(reply), 0)
        handle = _status(reply, 6)
        count = _status(
            handler.build_read_enum_results_reply_payload(
                b"\x03" + struct.pack("<I", handle) + b"\x83\x83"
            )
        )
        self.assertEqual(count, 3)

    def test_the_subscriber_gets_no_list_at_all(self):
        # SA_E_BAD_LIST_KIND is what the page turns into "Cannot display
        # Security page", which is the intended outcome for a plain member.
        _handler, reply = self._begin(signed_in(SUBSCRIBER))
        self.assertEqual(_status(reply), SA_E_BAD_LIST_KIND)

    def test_an_anonymous_connection_gets_no_list_either(self):
        _handler, reply = self._begin(anonymous())
        self.assertEqual(_status(reply), SA_E_BAD_LIST_KIND)


if __name__ == "__main__":
    unittest.main()
