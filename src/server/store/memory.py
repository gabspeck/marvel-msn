"""In-memory implementations of the store protocols, seeded from fixtures."""

from __future__ import annotations

import struct

from .base import AppStore


class InMemoryContentStore:
    def __init__(self, nodes, children, fallback):
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
        self._profile = billing_profile

    def get_billing_profile(self):
        return self._profile


class InMemoryStatementStore:
    def __init__(self, summary, transactions, subscriptions, plans):
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
    )
