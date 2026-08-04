from .base import (
    ANONYMOUS_USER,
    RIGHTS_AUTHORING,
    RIGHTS_NONE,
    AppStore,
    BillingProfile,
    CatalogStore,
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

# The one store the process owns. Every change a request makes lands here and
# lives until the process ends — nothing is written to disk.
app_store = build_app_store(default_seed())


def reset_app_store():
    """Return the process store to its seeded state."""
    app_store.reset(default_seed())
    return app_store


__all__ = [
    "ANONYMOUS_USER",
    "RIGHTS_AUTHORING",
    "RIGHTS_NONE",
    "AppStore",
    "BillingProfile",
    "CatalogStore",
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
