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

    def test_add_child_advances_the_parent_change_stamp(self):
        before = app_store.content.get_node(_BOARD).generation
        app_store.content.add_child(_BOARD, _message(_NEW_MESSAGE))
        self.assertEqual(app_store.content.get_node(_BOARD).generation, before + 1)

    def test_replacing_a_node_advances_its_own_change_stamp(self):
        content = app_store.content
        node = content.get_children(_BOARD)[0]
        content.add_node(node)
        self.assertEqual(content.get_node(node.node_id).generation, node.generation + 1)

    def test_add_node_leaves_the_seed_untouched(self):
        before = len(default_seed().directory_nodes)
        app_store.content.add_node(_message(_NEW_MESSAGE))
        self.assertEqual(len(default_seed().directory_nodes), before)

    def test_two_seeds_share_no_containers(self):
        first, second = default_seed(), default_seed()
        self.assertIsNot(first.directory_nodes, second.directory_nodes)
        self.assertIsNot(first.directory_children, second.directory_children)
        self.assertIsNot(first.directory_children[_BOARD], second.directory_children[_BOARD])
        self.assertIsNot(first.users, second.users)


class TestRelationshipCounts(unittest.TestCase):
    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    def test_counts_real_children_without_the_fallback_sentinel(self):
        content = app_store.content

        self.assertEqual(content.count_children("1:256"), 13)
        self.assertEqual(content.count_children("4:0"), 0)
        self.assertEqual(content.count_children("9000:1"), 0)

    def test_counts_each_parent_that_lists_the_node(self):
        content = app_store.content
        node = content.get_node("4:0")
        self.assertEqual(content.count_parents(node.node_id), 1)

        content.add_child("0:0", node)

        self.assertEqual(content.count_parents(node.node_id), 2)


class TestRemoveNode(unittest.TestCase):
    """TREEEDCL DeleteNode drops the node, its subtree and every reference."""

    def setUp(self):
        reset_app_store()

    def tearDown(self):
        reset_app_store()

    def test_removes_the_node_from_its_parent_listing(self):
        board = app_store.content
        doomed = board.get_children(_BOARD)[0].node_id

        self.assertTrue(board.remove_node(doomed))

        self.assertNotIn(doomed, [node.node_id for node in board.get_children(_BOARD)])
        self.assertEqual(
            board.get_node(doomed).node_id,
            default_seed().directory_fallback.node_id,
        )

    def test_removing_a_board_takes_its_messages(self):
        content = app_store.content
        messages = [node.node_id for node in content.get_children(_BOARD)]
        self.assertTrue(messages)

        self.assertTrue(content.remove_node(_BOARD))

        fallback = default_seed().directory_fallback.node_id
        for message in messages:
            self.assertEqual(content.get_node(message).node_id, fallback)

    def test_unknown_node_reports_no_removal(self):
        self.assertFalse(app_store.content.remove_node(_NEW_MESSAGE))

    def test_a_deleted_mnid_is_never_reissued(self):
        content = app_store.content
        doomed = content.get_children(_BOARD)[0].node_id
        self.assertFalse(content.is_node_id_free(doomed))

        self.assertTrue(content.remove_node(doomed))

        # The client caches properties per deid, so handing this mnid to a new
        # node would leave it wearing the dead node's cached 'c'.
        self.assertFalse(content.is_node_id_free(doomed))

    def test_removing_a_board_retires_its_messages_too(self):
        content = app_store.content
        messages = [node.node_id for node in content.get_children(_BOARD)]
        self.assertTrue(messages)

        self.assertTrue(content.remove_node(_BOARD))

        for message in messages:
            self.assertFalse(content.is_node_id_free(message))

    def test_an_unused_mnid_is_free(self):
        self.assertTrue(app_store.content.is_node_id_free(_NEW_MESSAGE))

    def test_the_parent_change_stamp_advances(self):
        # `g` is the only signal QueryOutOfDate acts on — without a bump the
        # deleted row survives every refresh.
        content = app_store.content
        before = content.get_node(_BOARD).generation

        content.remove_node(content.get_children(_BOARD)[0].node_id)

        self.assertEqual(content.get_node(_BOARD).generation, before + 1)

    def test_an_unrelated_parent_keeps_its_change_stamp(self):
        content = app_store.content
        board = content.get_node(_BOARD)
        doomed = content.get_children(_BOARD)[0].node_id
        other = next(
            node_id
            for node_id in default_seed().directory_children
            if node_id != _BOARD and content.get_node(node_id).node_id == node_id
        )
        before = content.get_node(other).generation

        content.remove_node(doomed)

        self.assertEqual(content.get_node(other).generation, before)
        self.assertEqual(content.get_node(_BOARD).generation, board.generation + 1)

    def test_leaves_the_seed_untouched(self):
        before = len(default_seed().directory_children[_BOARD])
        app_store.content.remove_node(app_store.content.get_children(_BOARD)[0].node_id)
        self.assertEqual(len(default_seed().directory_children[_BOARD]), before)


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
            app_store.users,
            app_store.catalog,
            app_store.member,
        )
        reset_app_store()
        self.assertEqual(
            (
                app_store.content,
                app_store.users,
                app_store.catalog,
                app_store.member,
            ),
            stores,
        )

    def test_reset_reseeds_every_store(self):
        seed = default_seed()
        reset_app_store()
        self.assertEqual(app_store.users.get_user(seed.users[0].username), seed.users[0])
        self.assertEqual(app_store.catalog.get_plans(), seed.plans)
        self.assertEqual(
            app_store.member.get_member(seed.member_profiles[0].member_id),
            seed.member_profiles[0],
        )


if __name__ == "__main__":
    unittest.main()
