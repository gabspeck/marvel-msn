import logging
from dataclasses import replace

from . import blackbird_state
from .base import (
    ANONYMOUS_USER,
    RIGHTS_AUTHORING,
    RIGHTS_NONE,
    AppStore,
    BillingProfile,
    CatalogStore,
    ConferenceFields,
    ContentStore,
    DirectoryNode,
    MemberProfile,
    MemberStore,
    NodeContent,
    Plan,
    StatementSummary,
    Subscription,
    TransactionRecord,
    User,
    UserStore,
)
from .fixtures import default_seed
from .memory import build_app_store
from .records import build_bbs_attachment_nodes, build_bbs_post

log = logging.getLogger("server.store")


def _restore_published_titles(store):
    """Put persisted Blackbird `bbix` records back on their nodes.

    A publish is the one piece of client-supplied state that outlives the
    process — see `blackbird_state`. A record whose node is no longer in the
    directory is left on disk untouched: the node may come back from a fixture
    edit, and dropping the record would silently cost a publish that can only
    be redone by hand.
    """
    for node_id, blob in blackbird_state.load_site_records().items():
        node = store.content.get_node(node_id)
        if node is None or node.node_id != node_id:
            log.warning("blackbird_site_orphaned node=%s bytes=%d", node_id, len(blob))
            continue
        store.content.add_node(replace(node, content=replace(node.content, blackbird_site=blob)))
        log.info("blackbird_site_restored node=%s bytes=%d", node_id, len(blob))
    return store


# The one store the process owns. Every change a request makes lands here and
# lives until the process ends, except a Blackbird publish, which is restored
# from disk below.
app_store = _restore_published_titles(build_app_store(default_seed()))


def reset_app_store():
    """Return the process store to its seeded state."""
    app_store.reset(default_seed())
    return _restore_published_titles(app_store)


__all__ = [
    "ANONYMOUS_USER",
    "RIGHTS_AUTHORING",
    "RIGHTS_NONE",
    "AppStore",
    "BillingProfile",
    "CatalogStore",
    "ConferenceFields",
    "ContentStore",
    "DirectoryNode",
    "MemberProfile",
    "MemberStore",
    "NodeContent",
    "Plan",
    "StatementSummary",
    "Subscription",
    "TransactionRecord",
    "User",
    "UserStore",
    "app_store",
    "build_app_store",
    "build_bbs_attachment_nodes",
    "build_bbs_post",
    "default_seed",
    "reset_app_store",
]
