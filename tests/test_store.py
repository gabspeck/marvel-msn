"""The store owns its state and the seed stays immutable.

Every change a request makes lands in the store and lives until the process
ends. Nothing reaches back into `store.fixtures`, and `reset_app_store` puts the
process back to the state it booted with.
"""

import unittest

from server.store import app_store, default_seed, reset_app_store
from server.store.records import bbs_node

# The sample board, and a message id no fixture uses.
_BOARD = "0:1"
_NEW_MESSAGE = "9000:1"


def _message(node_id):
    msg_id, _sep, board_id = node_id.partition(":")
    return bbs_node(int(msg_id), int(board_id), "Test post", is_container=False)


class TestSeedIsolation(unittest.TestCase):
    """A runtime write must not reach the fixture module."""

    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    def test_add_child_leaves_the_seed_untouched(self):
        before = len(default_seed().directory_children[_BOARD])
        app_store.content.add_child(_BOARD, _message(_NEW_MESSAGE))
        self.assertEqual(len(default_seed().directory_children[_BOARD]), before)

    def test_add_node_leaves_the_seed_untouched(self):
        before = len(default_seed().directory_nodes)
        app_store.content.add_node(_message(_NEW_MESSAGE))
        self.assertEqual(len(default_seed().directory_nodes), before)

    def test_two_seeds_share_no_containers(self):
        first, second = default_seed(), default_seed()
        self.assertIsNot(first.directory_nodes, second.directory_nodes)
        self.assertIsNot(first.directory_children, second.directory_children)
        self.assertIsNot(first.directory_children[_BOARD], second.directory_children[_BOARD])
        self.assertIsNot(first.statement_transactions[0], second.statement_transactions[0])


class TestReset(unittest.TestCase):
    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    def test_reset_drops_runtime_changes(self):
        before = [node.node_id for node in app_store.content.get_children(_BOARD)]
        app_store.content.add_child(_BOARD, _message(_NEW_MESSAGE))
        self.assertEqual(
            [node.node_id for node in app_store.content.get_children(_BOARD)],
            [*before, _NEW_MESSAGE],
        )

        reset_app_store()
        self.assertEqual(
            [node.node_id for node in app_store.content.get_children(_BOARD)],
            before,
        )
        # get_node answers an unknown id with the fallback sentinel, never None.
        self.assertEqual(
            app_store.content.get_node(_NEW_MESSAGE).node_id,
            default_seed().directory_fallback.node_id,
        )

    def test_reset_keeps_store_identity(self):
        # Services bind `app_store` at import, so the four store objects have to
        # survive a re-seed — only their contents may be replaced.
        stores = (
            app_store.content,
            app_store.account,
            app_store.statement,
            app_store.member,
        )
        reset_app_store()
        self.assertEqual(
            (
                app_store.content,
                app_store.account,
                app_store.statement,
                app_store.member,
            ),
            stores,
        )

    def test_reset_reseeds_every_store(self):
        seed = default_seed()
        reset_app_store()
        self.assertEqual(app_store.account.get_billing_profile(), seed.billing_profile)
        self.assertEqual(app_store.statement.get_summary(), seed.statement_summary)
        self.assertEqual(app_store.statement.get_plans(), seed.plans)
        self.assertEqual(app_store.statement.get_subscriptions(), seed.subscriptions)
        self.assertEqual(app_store.statement.period_count(), len(seed.statement_transactions))
        self.assertEqual(
            app_store.member.get_member(seed.member_profiles[0].member_id),
            seed.member_profiles[0],
        )


if __name__ == "__main__":
    unittest.main()
