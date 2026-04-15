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
# containers, 0x44000d for the MSN Today leaf.
_CONTAINER_MNID = struct.pack("<II", 0x44000C, 0)
_LEAF_MNID = struct.pack("<II", 0x44000D, 0)

MSN_CENTRAL_CONTENT = _container_content("MSN Central")
ROOT_CONTENT = _container_content("Root")


DIRECTORY_NODES = [
    DirectoryNode(
        node_id="0:0", is_container=True, app_id=1, mnid_a=_CONTAINER_MNID, content=ROOT_CONTENT
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
]


DIRECTORY_CHILDREN = {
    "0:0": ["4456460:0"],
}


DIRECTORY_FALLBACK_NODE = DIRECTORY_NODES[-1]  # MSN Today leaf


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
