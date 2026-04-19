"""Default seed data for the in-memory app store."""

from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass

from .base import (
    BillingProfile,
    DirectoryNode,
    NodeContent,
    Plan,
    StatementSummary,
    Subscription,
    TransactionRecord,
)

MSN_TODAY_CONTENT = NodeContent(
    name="MSN Today",
    go_word="today",
    category="News",
    type_str="News & Features",
    price_dword=0,
    rating_dword=0,
    description="Your daily window to MSN.",
    language=1033,
    topics="News, Weather, Entertainment",
    people="Microsoft editorial staff",
    place="Redmond, WA, USA",
    u_value="",
    forum_mgr="MSN Editorial",
    vendor_id=1,
    owner="The Microsoft Network",
    created="August 24, 1995",
    modified="April 15, 2026",
    size_bytes=5 * 1024 * 1024,
)


def _container_content(name, type_str="Directory"):
    return NodeContent(
        name=name,
        go_word="",
        category="",
        type_str=type_str,
        price_dword=0,
        rating_dword=0,
        description="",
        language=1033,
        topics="",
        people="",
        place="",
        u_value="",
        forum_mgr="",
        vendor_id=0,
        owner="",
        created="",
        modified="",
        size_bytes=0,
    )


# mnid_a blob layout is `struct.pack('<II', <id1>, 0)` — 0x44000c for
# containers, 0x44000d for the MSN Today leaf, 0x44000e+ for Category folders.
_CONTAINER_MNID = struct.pack("<II", 0x44000C, 0)
_LEAF_MNID = struct.pack("<II", 0x44000D, 0)

# MSN-root special mnid: `GetSpecialMnid(idx=0) → 1:0:0:0` (MOSSHELL
# 0x7f3f9b3f). Post-login DIRSRV pipes 4/5 issue `GetProperties(1:0, [a,e])`
# and `GetChildren(1:0)` to build the breadcrumb/address-bar dropdown.
_MSN_ROOT_MNID = struct.pack("<II", 1, 0)
# HOMEBASE/GUIDENAV also synthesize MSN Today as the small special node
# `1:4:0:0`; on the wire DIRSRV only sees the 8-byte `_MosLid64` prefix,
# which our decoder logs as `4:0`.
_MSN_TODAY_SPECIAL_MNID = struct.pack("<II", 4, 0)

MSN_CENTRAL_CONTENT = _container_content("MSN Central")
ROOT_CONTENT = _container_content("Root")
MSN_ROOT_CONTENT = _container_content("The Microsoft Network")

# Categories sub-folders listed when the HOMEBASE "Categories" JUMP browses
# MSN Central's children. Each is a Browse container (app_id=1), so clicking
# one opens its own child list rather than triggering DnR.
CATEGORY_DEFS = (
    (0x44000E, "The News"),
    (0x44000F, "Entertainment"),
    (0x440010, "Computers & Software"),
    (0x440011, "Business & Finance"),
    (0x440012, "Sports, Health & Fitness"),
    (0x440013, "Science & Technology"),
    (0x440014, "Arts & Entertainment"),
    (0x440015, "Education & Reference"),
)


def _category_node(id1, name):
    return DirectoryNode(
        node_id=f"{id1}:0",
        is_container=True,
        app_id=1,
        mnid_a=struct.pack("<II", id1, 0),
        content=_container_content(name),
    )


DIRECTORY_NODES = [
    DirectoryNode(
        node_id="0:0", is_container=True, app_id=1, mnid_a=_CONTAINER_MNID, content=ROOT_CONTENT
    ),
    # MSN root as the client's GetSpecialMnid(idx=0) sees it. Served so that
    # post-login breadcrumb walks `GetProperties(1:0, [a,e])` get the real
    # "The Microsoft Network" identity instead of falling back to MSN Today.
    DirectoryNode(
        node_id="1:0",
        is_container=True,
        app_id=1,
        mnid_a=_MSN_ROOT_MNID,
        content=MSN_ROOT_CONTENT,
    ),
    # Alias for the client-synthesized MSN Today startup node. The shell asks
    # DIRSRV for `GetProperties(4:0, [a,e])` while rendering built-in startup
    # surfaces, so map it to the real MSN Today leaf instead of falling
    # through to the unknown-node sentinel.
    DirectoryNode(
        node_id="4:0",
        is_container=False,
        app_id=7,
        mnid_a=_MSN_TODAY_SPECIAL_MNID,
        content=MSN_TODAY_CONTENT,
    ),
    DirectoryNode(
        node_id="4456460:0",
        is_container=True,
        app_id=1,
        mnid_a=_CONTAINER_MNID,
        content=MSN_CENTRAL_CONTENT,
    ),
    # Alias — the wire id "0:4456460" resolves to the same MSN Central node.
    DirectoryNode(
        node_id="0:4456460",
        is_container=True,
        app_id=1,
        mnid_a=_CONTAINER_MNID,
        content=MSN_CENTRAL_CONTENT,
    ),
    DirectoryNode(
        node_id="4456461:0",
        is_container=False,
        app_id=7,
        mnid_a=_LEAF_MNID,
        content=MSN_TODAY_CONTENT,
    ),
    *[_category_node(id1, name) for id1, name in CATEGORY_DEFS],
]


DIRECTORY_CHILDREN = {
    "0:0": ["4456460:0"],
    # Start the MSN-root breadcrumb with a single child so the experiment
    # can tell whether server-vended entries surface at all before we
    # expand the real nav tree (Favorite Places / Categories / etc.).
    "1:0": ["4456460:0"],
    # The client's startup-time `4:0` special node is a leaf: explicit empty
    # children avoid the sentinel fallback path that previously introduced
    # `FFFFFFFF:FFFFFFFF` into the rendered hierarchy.
    "4:0": [],
    "4456460:0": [f"{id1}:0" for id1, _ in CATEGORY_DEFS],
    "4456461:0": [],
}


# Sentinel container for unknown mnid lookups. mnid_a must NOT alias an
# existing node's blob — otherwise the client caches "unknown == that node"
# and clicks on the unknown mnid generate a spurious `-MOS:` command line
# targeting the aliased node (e.g. MSN Central → `dsnav.nav -MOS:1:4456460:0:0
# .`, which fails "Cannot run command" when dsnav.nav is absent from the VM).
# Using UINT32_MAX:UINT32_MAX keeps the fallback's identity distinct from any
# real node while still satisfying CMosTreeNode::Exec's 'c' caching (empty
# child list breaks dispatch).
_FALLBACK_MNID = struct.pack("<II", 0xFFFFFFFF, 0xFFFFFFFF)
DIRECTORY_FALLBACK_NODE = DirectoryNode(
    node_id="4294967295:4294967295",
    is_container=True,
    app_id=1,
    mnid_a=_FALLBACK_MNID,
    content=_container_content(""),
)


BILLING_PROFILE = BillingProfile(
    first_name="Microsoft",
    last_name="User",
    country_id=1,  # US
    address="1 Microsoft Way",
    city="Redmond",
    state="WA",
    zip="98052",
    phone="425-882-8080",
    payment_type=1,  # CHARGE
    card_number="411111******1111",
)


STATEMENT_SUMMARY = StatementSummary(
    balance_cents=1904,  # formatted as "$19.04"
    currency_iso=840,  # USD
    year=2026,
    month=4,
    day=1,
    free_connect_minutes=90,  # rendered as "01:30"
)


STATEMENT_TRANSACTIONS = [
    # Period 0 — April 2026 (current statement, $19.04 balance).
    [
        TransactionRecord(datetime.datetime(2026, 4, 1, 9, 15), "Monthly subscription", 495, 495),
        TransactionRecord(
            datetime.datetime(2026, 4, 5, 19, 42), "Premium content access", 149, 644
        ),
        TransactionRecord(datetime.datetime(2026, 4, 9, 14, 3), "Chat room usage", 75, 719),
        # Flag-0x02: ¥1,000 @ 0.0067 USD/JPY -> $6.70.
        TransactionRecord(
            datetime.datetime(2026, 4, 11, 12, 0),
            "Tokyo content purchase",
            670,
            1389,
            foreign=(1000, 392, 67),
        ),
        TransactionRecord(
            datetime.datetime(2026, 4, 12, 22, 30), "Online statement fee", 515, 1904
        ),
    ],
    # Period 1 — March 2026.
    [
        TransactionRecord(datetime.datetime(2026, 3, 1, 8, 30), "Monthly subscription", 495, 495),
        TransactionRecord(
            datetime.datetime(2026, 3, 14, 21, 5), "Premium content access", 149, 644
        ),
        TransactionRecord(datetime.datetime(2026, 3, 28, 23, 50), "Online statement fee", 250, 894),
    ],
    # Period 2 — February 2026.
    [
        TransactionRecord(datetime.datetime(2026, 2, 1, 7, 45), "Monthly subscription", 495, 495),
        TransactionRecord(
            datetime.datetime(2026, 2, 7, 18, 22), "Game zone tournament entry", 200, 695
        ),
        TransactionRecord(
            datetime.datetime(2026, 2, 18, 20, 11), "Premium content access", 149, 844
        ),
        TransactionRecord(
            datetime.datetime(2026, 2, 27, 22, 30), "Online statement fee", 250, 1094
        ),
    ],
    # Period 3 — January 2026.
    [
        TransactionRecord(datetime.datetime(2026, 1, 1, 10, 0), "Monthly subscription", 495, 495),
        TransactionRecord(
            datetime.datetime(2026, 1, 19, 19, 17), "Premium content access", 149, 644
        ),
        TransactionRecord(datetime.datetime(2026, 1, 31, 23, 59), "Online statement fee", 250, 894),
    ],
]


SUBSCRIPTIONS = [
    Subscription(
        kind=0x01,
        name="MSN Premium",
        detail="Monthly subscription",
        price_minor=495,
        price_currency=840,
        record_currency=840,
    ),
    Subscription(
        kind=0x02,
        name="MSN Plus Games",
        detail="Gaming add-on pack",
        price_minor=299,
        price_currency=840,
        record_currency=840,
    ),
    Subscription(
        kind=0x04,
        name="Promotional credit",
        detail="First-month welcome credit",
        price_minor=199,
        price_currency=840,
        record_currency=840,
    ),
    Subscription(
        kind=0xFF,
        name="MSN Bookshelf",
        detail="Reference library access",
        price_minor=99,
        price_currency=840,
        record_currency=840,
    ),
]


PLANS = [
    Plan(
        plan_id=0,
        name="MSN Premium",
        detail="$4.95/month, includes 3 hours of online time. "
        "Additional hours billed at $2.50/hour.",
    ),
    Plan(plan_id=1, name="MSN Plus", detail="$19.95/month, unlimited online time."),
    Plan(
        plan_id=2, name="MSN Annual", detail="$49.95/year, unlimited online time. Two months free."
    ),
]


@dataclass
class DefaultSeed:
    directory_nodes: list
    directory_children: dict
    directory_fallback: DirectoryNode
    billing_profile: BillingProfile
    statement_summary: StatementSummary
    statement_transactions: list
    subscriptions: list
    plans: list


def default_seed():
    return DefaultSeed(
        directory_nodes=DIRECTORY_NODES,
        directory_children=DIRECTORY_CHILDREN,
        directory_fallback=DIRECTORY_FALLBACK_NODE,
        billing_profile=BILLING_PROFILE,
        statement_summary=STATEMENT_SUMMARY,
        statement_transactions=STATEMENT_TRANSACTIONS,
        subscriptions=SUBSCRIPTIONS,
        plans=PLANS,
    )
