"""In-memory implementations of the store protocols, seeded from fixtures.

These objects own every byte of server state that a request can change. The
state is volatile — it lives for the process and nothing writes it to disk —
and `load` is how it is (re)seeded, in place, from a `DefaultSeed`.
"""

from __future__ import annotations

import struct
from dataclasses import replace

from .base import AppStore, MemberProfile


class InMemoryContentStore:
    def __init__(self, nodes, children, fallback):
        self.load(nodes, children, fallback)

    def load(self, nodes, children, fallback):
        self._nodes = {n.node_id: n for n in nodes}
        self._children = children
        self._fallback = fallback
        self._retired = set()

    def get_node(self, node_id):
        return self._nodes.get(node_id, self._fallback)

    def all_nodes(self):
        """Every registered node, for whole-directory scans.

        The fallback is deliberately absent: it is the answer to a lookup for a
        node that does not exist, not an entry in the directory, and a FindSvc
        search that returned it would put a row in the results list whose mnid
        resolves back to the same placeholder.
        """
        return list(self._nodes.values())

    def is_node_id_free(self, node_id):
        """Report whether `node_id` has never been issued.

        A deleted mnid stays taken. MOSSHELL caches properties per deid and
        re-reads a node only when its 'g' moves, so a recycled mnid leaves the
        client holding the dead node's cached values. 'c' is the damaging one:
        DSNED's GETPMTE switches on it to pick the editor, so a new
        Download-and-Run node handed a retired Encarta node's mnid gets the
        Encarta vtable and loses its Download and Run page.
        """
        return node_id not in self._nodes and node_id not in self._retired

    def find_by_go_word(self, go_word):
        if not go_word:
            return None
        target = go_word.casefold()
        for node in self._nodes.values():
            node_go_word = node.content.go_word
            if node_go_word and node_go_word.casefold() == target:
                return node
        return None

    def find_app_instance(self, app_id, instance_id):
        for node in self._nodes.values():
            if (
                node.app_id == app_id
                and struct.unpack_from("<I", node.mnid_a)[0] == instance_id
            ):
                return node
        return None

    def has_children(self, node_id):
        # Backs 'b' bit 0x02 (SFGAO_HASSUBFOLDER). Deliberately unfiltered by
        # locale: the attribute is asked per-pidl outside any browse request,
        # so there is no LCID in hand.
        ids = self._children.get(node_id)
        if ids is None:
            # Mirrors get_children's permissive fallback, which yields one
            # sentinel child for unlisted nodes.
            return True
        return bool(ids)

    def count_children(self, node_id):
        """Return the number of real child links below `node_id`."""
        return len(self._children.get(node_id, ()))

    def count_parents(self, node_id):
        """Return the number of parents that list `node_id` as a child."""
        return len(self.get_parents(node_id))

    def get_parents(self, node_id):
        """Return direct parents in directory-link order."""
        return [
            self._nodes[parent_id]
            for parent_id, child_ids in self._children.items()
            if node_id in child_ids and parent_id in self._nodes
        ]

    def add_node(self, node):
        """Register a node by mnid, replacing any node already under that key.

        Two callers. A BBS attachment is reachable only by its mnid —
        FUN_7F5FC919 builds `(message id + k, board id)` from the message and
        asks for it directly. It is not a child of the board, so listing it
        there would put a bogus row in the reader. DIRSRV SetProperties reuses
        the same replace-by-key step to commit an edited node, which leaves its
        position in every parent's child list untouched.

        Replacing an entry advances its `g`, so the client drops what it cached
        for the node and reads the new values.
        """
        previous = self._nodes.get(node.node_id)
        if previous is not None:
            node = replace(node, generation=previous.generation + 1)
        self._nodes[node.node_id] = node

    def add_child(self, parent_id, node):
        """Register a node and append it to `parent_id`'s child list.

        Backs the BBS post channel, whose commit has to make the new message
        visible to the next GetChildren on the board. The child list is created
        empty for the node itself — get_children answers an unlisted node with
        the fallback sentinel, which would put a bogus row under the message.

        The parent's `g` advances: its child list is what changed, and that is
        the only signal the client has to re-list the folder.
        """
        self._nodes[node.node_id] = node
        self._children.setdefault(node.node_id, [])
        self._children.setdefault(parent_id, []).append(node.node_id)
        self._bump(parent_id)

    def _bump(self, node_id):
        """Advance one node's change stamp, if the node is registered."""
        node = self._nodes.get(node_id)
        if node is not None:
            self._nodes[node_id] = replace(node, generation=node.generation + 1)

    def remove_node(self, node_id):
        """Drop a node, its descendants, and every parent's reference to it.

        Backs TREEEDCL DeleteNode. The subtree goes with the node: a surviving
        child keeps its own mnid, so GetProperties would still answer for a
        message under a deleted board.

        Every parent that listed the node advances its `g`, which is what makes
        the row disappear: the client's refresh never diffs the child list, it
        only re-lists a folder whose stamp moved.

        Returns True when the node was registered, False when it was not.
        """
        if node_id not in self._nodes:
            return False
        doomed = set()
        pending = [node_id]
        while pending:
            current = pending.pop()
            if current in doomed:
                continue
            doomed.add(current)
            pending.extend(self._children.get(current, ()))
        for gone in doomed:
            self._nodes.pop(gone, None)
            self._children.pop(gone, None)
        self._retired |= doomed
        for parent_id, ids in self._children.items():
            if any(i in doomed for i in ids):
                ids[:] = [i for i in ids if i not in doomed]
                self._bump(parent_id)
        return True

    def get_children(self, node_id, locale_raw=None):
        # Permissive fallback: any node without an explicit child list resolves
        # to [fallback]. CMosTreeNode::Exec caches 'z'/'c' from the GetChildren
        # reply, so returning [] breaks dispatch with "task cannot be completed".
        ids = self._children.get(node_id)
        if ids is None:
            return [self._fallback]
        nodes = [self._nodes[i] for i in ids]
        # 8-byte locale_raw = [filter_on:u32][lcid:u32]. When filter_on=1 the
        # client wants locale-scoped results; drop children whose language is
        # neither the requested LCID nor 0 (Worldwide containers are tagged
        # language=0 specifically so they survive every filter).
        if locale_raw and len(locale_raw) >= 8:
            filter_on, lcid = struct.unpack("<II", locale_raw[:8])
            if filter_on:
                nodes = [n for n in nodes if n.content.language in (0, lcid)]
        return nodes


class InMemoryUserStore:
    def __init__(self, users):
        self.load(users)

    def load(self, users):
        self._users = {u.username.casefold(): u for u in users}

    def get_user(self, username):
        # Case-insensitive, because a member id is not case-sensitive on MSN and
        # the Sign In dialog does not correct what was typed. Unlike
        # InMemoryMemberStore.get_member, an unknown key answers None: a lenient
        # lookup here would let anyone sign in.
        return self._users.get(username.casefold())

    def authenticate(self, username, password):
        """Return the account when the password matches, None otherwise.

        The password is compared as typed. Whatever transform the client applies
        on the wire is undone in LOGSRV before the value reaches this call, so
        the store holds and compares the plain password.
        """
        user = self.get_user(username)
        if user is None or user.password != password:
            return None
        return user

    def set_password(self, username, password):
        return self._replace(username, password=password)

    def set_billing(self, username, profile):
        return self._replace(username, billing=profile)

    def _replace(self, username, **changes):
        """Commit one edit to an account. False when no such account exists."""
        key = username.casefold()
        user = self._users.get(key)
        if user is None:
            return False
        self._users[key] = replace(user, **changes)
        return True


class InMemoryMemberStore:
    def __init__(self, profiles):
        self.load(profiles)

    def load(self, profiles):
        self._profiles = {p.member_id.casefold(): p for p in profiles}

    def get_member(self, member_id):
        # Case-insensitive: the key travels through the reader's From box and a
        # member id is not case-sensitive on MSN. An unknown member still gets a
        # profile — the sheet then shows the id with empty pages, which is what a
        # member who published nothing looks like. Failing the request instead
        # would put a MosError box in front of the user.
        profile = self._profiles.get(member_id.casefold())
        if profile is None:
            return MemberProfile(member_id=member_id, display_name=member_id)
        return profile

    def list_members(self):
        """Every published profile, in seed order — the member directory."""
        return list(self._profiles.values())


class InMemoryCatalogStore:
    def __init__(self, plans):
        self.load(plans)

    def load(self, plans):
        self._plans = plans

    def get_plans(self):
        return self._plans


class InMemoryMailStore:
    """Server-side inboxes, keyed by member id.

    Message ids are unique across every mailbox, not per mailbox: the client
    keys on the 12-byte `MOS_ENTRYID` alone and never pairs it with a member.
    """

    def __init__(self, messages):
        self.load(messages)

    def load(self, messages):
        self._mailboxes = {}
        self._next_id = 1
        for message in messages:
            self._mailboxes.setdefault(message.mailbox.casefold(), []).append(message)
            self._next_id = max(self._next_id, message.message_id + 1)

    def list_messages(self, mailbox):
        # Delivery order, which is the order the header list ships in — the
        # client sorts the Inbox itself.
        return list(self._mailboxes.get(mailbox.casefold(), ()))

    def get_message(self, mailbox, message_id):
        for message in self._mailboxes.get(mailbox.casefold(), ()):
            if message.message_id == message_id:
                return message
        return None

    def delete_messages(self, mailbox, message_ids):
        key = mailbox.casefold()
        kept = []
        removed = 0
        wanted = set(message_ids)
        for message in self._mailboxes.get(key, ()):
            if message.message_id in wanted:
                removed += 1
            else:
                kept.append(message)
        self._mailboxes[key] = kept
        return removed

    def set_status(self, mailbox, message_id, status):
        key = mailbox.casefold()
        for i, message in enumerate(self._mailboxes.get(key, ())):
            if message.message_id == message_id:
                self._mailboxes[key][i] = replace(message, status=status)
                return True
        return False

    def deliver(self, message):
        stored = replace(message, message_id=self._next_id)
        self._next_id += 1
        self._mailboxes.setdefault(message.mailbox.casefold(), []).append(stored)
        return stored


def build_app_store(seed):
    return AppStore(
        content=InMemoryContentStore(
            nodes=seed.directory_nodes,
            children=seed.directory_children,
            fallback=seed.directory_fallback,
        ),
        users=InMemoryUserStore(users=seed.users),
        catalog=InMemoryCatalogStore(plans=seed.plans),
        member=InMemoryMemberStore(profiles=seed.member_profiles),
        mail=InMemoryMailStore(messages=seed.mail_messages),
    )
