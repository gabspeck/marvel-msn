"""Tests for the per-connection identity object.

The property everything else rests on: a handler captures the session when its
pipe opens, and LOGSRV signs it in later on the same connection. A handler built
before the login must therefore see the account through the reference it already
holds.
"""

import unittest

from server.services import SERVICE_HANDLERS
from server.session import Session
from server.store import ANONYMOUS_USER, RIGHTS_NONE, app_store, reset_app_store

from .support import ADMIN, ADMIN_PASSWORD, SUBSCRIBER, seed_user


class TestAnonymousSession(unittest.TestCase):
    def test_a_fresh_session_is_anonymous(self):
        session = Session()
        self.assertIs(session.user, ANONYMOUS_USER)
        self.assertFalse(session.is_authenticated)
        self.assertFalse(session.is_admin)
        self.assertEqual(session.user.rights, RIGHTS_NONE)

    def test_the_anonymous_account_still_answers_every_field(self):
        # Handlers read billing and statement off the account unconditionally,
        # so the anonymous stand-in has to carry both rather than None.
        user = Session().user
        self.assertEqual(user.billing.city, "")
        self.assertEqual(user.statement.balance_cents, 0)
        self.assertEqual(user.transactions, ())
        self.assertEqual(user.subscriptions, ())


class TestSignIn(unittest.TestCase):
    def setUp(self):
        reset_app_store()

    def test_sign_in_is_visible_through_a_reference_taken_beforehand(self):
        session = Session()
        captured = session  # what a handler holds from its pipe-open

        session.sign_in(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))

        self.assertTrue(captured.is_authenticated)
        self.assertTrue(captured.is_admin)
        self.assertEqual(captured.user.display_name, "Bill Gates")

    def test_a_subscriber_is_authenticated_but_not_an_admin(self):
        session = Session()
        session.sign_in(seed_user(SUBSCRIBER))
        self.assertTrue(session.is_authenticated)
        self.assertFalse(session.is_admin)

    def test_sign_out_returns_the_session_to_anonymous(self):
        session = Session()
        session.sign_in(seed_user(ADMIN))
        session.sign_out()
        self.assertIs(session.user, ANONYMOUS_USER)
        self.assertFalse(session.is_authenticated)


class TestHandlerInjection(unittest.TestCase):
    def test_every_handler_accepts_and_keeps_the_connection_session(self):
        session = Session()
        for name, handler_cls in SERVICE_HANDLERS.items():
            with self.subTest(service=name):
                self.assertIs(handler_cls(3, name.upper(), session).session, session)

    def test_a_handler_built_without_one_gets_its_own_anonymous_session(self):
        # Tests construct handlers directly, and a pipe can open before the
        # login lands; neither may borrow another connection's identity.
        for name, handler_cls in SERVICE_HANDLERS.items():
            with self.subTest(service=name):
                first = handler_cls(3, name.upper()).session
                second = handler_cls(3, name.upper()).session
                self.assertIsNot(first, second)
                self.assertFalse(first.is_authenticated)


if __name__ == "__main__":
    unittest.main()
