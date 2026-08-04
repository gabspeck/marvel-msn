"""Tests for the account store behind the LOGSRV sign-in.

The store is what decides whether a connection may sign in at all, so its
lookups have to be strict where the other stores are lenient: an unknown key is
a failure, never a synthesised record.
"""

import unittest
from dataclasses import replace

from server.store import RIGHTS_AUTHORING, RIGHTS_NONE, app_store, default_seed, reset_app_store

from .support import (
    ADMIN,
    ADMIN_PASSWORD,
    SUBSCRIBER,
    SUBSCRIBER_PASSWORD,
)


class TestAuthenticate(unittest.TestCase):
    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    def test_the_right_password_returns_the_account(self):
        user = app_store.users.authenticate(ADMIN, ADMIN_PASSWORD)
        self.assertIsNotNone(user)
        self.assertEqual(user.username, ADMIN)
        self.assertEqual(user.display_name, "Bill Gates")

    def test_a_wrong_password_returns_nothing(self):
        self.assertIsNone(app_store.users.authenticate(ADMIN, SUBSCRIBER_PASSWORD))

    def test_an_unknown_username_returns_nothing(self):
        # Unlike MemberStore.get_member, which synthesises a blank profile for
        # an unknown id, a missing account may never resolve.
        self.assertIsNone(app_store.users.authenticate("nobody", ADMIN_PASSWORD))
        self.assertIsNone(app_store.users.get_user("nobody"))

    def test_an_empty_password_does_not_match_a_real_account(self):
        self.assertIsNone(app_store.users.authenticate(ADMIN, ""))

    def test_the_username_is_case_insensitive(self):
        # A member id is not case-sensitive on MSN and the Sign In dialog does
        # not correct what was typed.
        user = app_store.users.authenticate(ADMIN.upper(), ADMIN_PASSWORD)
        self.assertIsNotNone(user)
        self.assertEqual(user.username, ADMIN)

    def test_the_password_is_case_sensitive(self):
        self.assertIsNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD.upper()))


class TestSeededRights(unittest.TestCase):
    """The two seeded accounts differ in exactly what this change gates on."""

    def setUp(self):
        reset_app_store()

    def test_the_admin_holds_authoring_rights_and_every_token(self):
        user = app_store.users.get_user(ADMIN)
        self.assertEqual(user.rights, RIGHTS_AUTHORING)
        self.assertEqual(user.sa_tokens, (1, 2, 3))

    def test_the_subscriber_holds_neither(self):
        user = app_store.users.get_user(SUBSCRIBER)
        self.assertEqual(user.rights, RIGHTS_NONE)
        self.assertEqual(user.sa_tokens, ())

    def test_each_account_carries_its_own_billing_and_statement(self):
        admin = app_store.users.get_user(ADMIN)
        subscriber = app_store.users.get_user(SUBSCRIBER)
        self.assertNotEqual(admin.billing, subscriber.billing)
        self.assertNotEqual(admin.statement, subscriber.statement)
        self.assertNotEqual(admin.transactions, subscriber.transactions)
        self.assertNotEqual(admin.subscriptions, subscriber.subscriptions)

    def test_each_account_has_a_member_profile_under_its_display_name(self):
        # The Member Properties sheet resolves on the display name, because
        # that is what a post's From: header carries.
        for username in (ADMIN, SUBSCRIBER):
            with self.subTest(username=username):
                user = app_store.users.get_user(username)
                profile = app_store.member.get_member(user.display_name)
                self.assertEqual(profile.display_name, user.display_name)
                self.assertTrue(profile.last_name, "profile is the synthesised blank one")


class TestWrites(unittest.TestCase):
    """A committed edit replaces the account and never reaches the seed."""

    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    def test_set_password_takes_effect_and_retires_the_old_one(self):
        self.assertTrue(app_store.users.set_password(ADMIN, "newpass"))
        self.assertIsNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, "newpass"))

    def test_set_password_leaves_the_seed_untouched(self):
        app_store.users.set_password(ADMIN, "newpass")
        seeded = next(u for u in default_seed().users if u.username == ADMIN)
        self.assertEqual(seeded.password, ADMIN_PASSWORD)

    def test_reset_undoes_a_password_change(self):
        app_store.users.set_password(ADMIN, "newpass")
        reset_app_store()
        self.assertIsNotNone(app_store.users.authenticate(ADMIN, ADMIN_PASSWORD))

    def test_set_billing_replaces_only_the_billing_profile(self):
        before = app_store.users.get_user(ADMIN)
        moved = replace(before.billing, city="Albuquerque")

        self.assertTrue(app_store.users.set_billing(ADMIN, moved))

        after = app_store.users.get_user(ADMIN)
        self.assertEqual(after.billing.city, "Albuquerque")
        self.assertEqual(after.password, before.password)
        self.assertEqual(after.statement, before.statement)

    def test_a_write_to_an_unknown_account_reports_failure(self):
        self.assertFalse(app_store.users.set_password("nobody", "x"))
        self.assertFalse(app_store.users.set_billing("nobody", None))


if __name__ == "__main__":
    unittest.main()
