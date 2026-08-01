"""In-memory implementations of the store protocols, seeded from fixtures.

These objects own every byte of server state that a request can change. The
state is volatile — it lives for the process and nothing writes it to disk —
and `load` is how it is (re)seeded, in place, from a `DefaultSeed`.
"""

from __future__ import annotations

import struct

from .base import AppStore, MemberProfile


class InMemoryContentStore:
    def __init__(self, nodes, children, fallback):
        self.load(nodes, children, fallback)

    def load(self, nodes, children, fallback):
        self._nodes = {n.node_id: n for n in nodes}
        self._children = children
        self._fallback = fallback

    def get_node(self, node_id):
        return self._nodes.get(node_id, self._fallback)

    def find_by_go_word(self, go_word):
        if not go_word:
            return None
        target = go_word.casefold()
        for node in self._nodes.values():
            node_go_word = node.content.go_word
            if node_go_word and node_go_word.casefold() == target:
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

    def add_node(self, node):
        """Register a node that hangs off no parent.

        A BBS attachment is reachable only by its mnid — FUN_7F5FC919 builds
        `(message id + k, board id)` from the message and asks for it directly.
        It is not a child of the board, so listing it there would put a bogus
        row in the reader.
        """
        self._nodes[node.node_id] = node

    def add_child(self, parent_id, node):
        """Register a node and append it to `parent_id`'s child list.

        Backs the BBS post channel, whose commit has to make the new message
        visible to the next GetChildren on the board. The child list is created
        empty for the node itself — get_children answers an unlisted node with
        the fallback sentinel, which would put a bogus row under the message.
        """
        self._nodes[node.node_id] = node
        self._children.setdefault(node.node_id, [])
        self._children.setdefault(parent_id, []).append(node.node_id)

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


class InMemoryAccountStore:
    def __init__(self, billing_profile):
        self.load(billing_profile)

    def load(self, billing_profile):
        self._profile = billing_profile

    def get_billing_profile(self):
        return self._profile


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


class InMemoryStatementStore:
    def __init__(self, summary, transactions, subscriptions, plans):
        self.load(summary, transactions, subscriptions, plans)

    def load(self, summary, transactions, subscriptions, plans):
        self._summary = summary
        self._transactions = transactions
        self._subscriptions = subscriptions
        self._plans = plans

    def get_summary(self):
        return self._summary

    def period_count(self):
        return len(self._transactions)

    def get_transactions(self, period_index):
        if period_index < 0 or period_index >= len(self._transactions):
            period_index = 0
        return self._transactions[period_index]

    def get_subscriptions(self):
        return self._subscriptions

    def get_plans(self):
        return self._plans


def build_app_store(seed):
    return AppStore(
        content=InMemoryContentStore(
            nodes=seed.directory_nodes,
            children=seed.directory_children,
            fallback=seed.directory_fallback,
        ),
        account=InMemoryAccountStore(billing_profile=seed.billing_profile),
        statement=InMemoryStatementStore(
            summary=seed.statement_summary,
            transactions=seed.statement_transactions,
            subscriptions=seed.subscriptions,
            plans=seed.plans,
        ),
        member=InMemoryMemberStore(profiles=seed.member_profiles),
    )
