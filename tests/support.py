"""Shared helpers for tests that need a signed-in connection.

Handlers and reply builders read identity off a `Session`, so a test that
exercises a per-member reply has to hand one over. These wrap the seeded
accounts so a test says which member it is acting as and nothing more.
"""

import struct

from server.mpc import build_service_packet
from server.session import Session
from server.store import app_store, default_seed

# The two seeded accounts, by username. `ADMIN` holds authoring rights and the
# whole SASRV token list; `SUBSCRIBER` holds neither.
ADMIN = "billg"
ADMIN_PASSWORD = "msn@96"
SUBSCRIBER = "sjobs"
SUBSCRIBER_PASSWORD = "whatsnext"


def seed_user(username=ADMIN):
    """The account record `username` names, straight out of the store."""
    user = app_store.users.get_user(username)
    assert user is not None, f"no seeded account named {username!r}"
    return user


def signed_in(username=ADMIN):
    """A session already signed in as `username`."""
    session = Session()
    session.sign_in(seed_user(username))
    return session


def anonymous():
    """A session that never signed in."""
    return Session()


class RecordingConnection:
    """Stand-in for `ConnectionState` on a service that pushes events.

    Frames each push the way the connection does so a test can parse the wire
    packets, and keeps the labels so a test can name the events it expects.
    """

    def __init__(self, conn_id=0):
        self.conn_id = conn_id
        self.server_seq = 0
        self.client_ack = 0
        self.packets = []
        self.labels = []

    def push_service_data(self, pipe_idx, host_block, label):
        packets = build_service_packet(
            pipe_idx,
            host_block,
            self.server_seq,
            self.client_ack,
        )
        self.server_seq = (self.server_seq + len(packets)) & 0x7F
        self.packets.extend(packets)
        self.labels.append(label)


class AddNodeContentStore:
    """The one seeded category a TREEEDCL AddNode writes under, with child
    bookkeeping a test can inspect."""

    def __init__(self):
        parent = next(node for node in default_seed().directory_nodes if node.node_id == "1:16")
        self.nodes = {parent.node_id: parent}
        self.children = {parent.node_id: []}
        self.retired = set()

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    find_node = get_node

    def is_node_id_free(self, node_id):
        return node_id not in self.nodes and node_id not in self.retired

    def get_children(self, node_id):
        return [self.nodes[child_id] for child_id in self.children.get(node_id, [])]

    def find_app_instance(self, app_id, instance_id):
        for node in self.nodes.values():
            if node.app_id == app_id and struct.unpack_from("<I", node.mnid_a)[0] == instance_id:
                return node
        return None

    def add_child(self, parent_id, node):
        self.nodes[node.node_id] = node
        self.children.setdefault(node.node_id, [])
        self.children.setdefault(parent_id, []).append(node.node_id)

    def add_node(self, node):
        self.nodes[node.node_id] = node
