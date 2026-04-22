"""Default seed data for the in-memory app store."""

from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass

from ..mos_apps import APP_DIRECTORY_SERVICE, APP_MEDIA_VIEWER
from .base import (
    BillingProfile,
    DirectoryNode,
    NodeContent,
    Plan,
    StatementSummary,
    Subscription,
    TransactionRecord,
)

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)


def _date_string_to_wire_filetime(s):
    """Parse a fixture `%B %d, %Y` date into a Windows FILETIME (UTC midnight).

    Returns 0 for empty input — callers use 0 as the "no date" sentinel so
    the server skips emitting the `w` property and the listview cell stays
    blank instead of rendering 1601-01-01.
    """
    if not s:
        return 0
    dt = datetime.datetime.strptime(s, "%B %d, %Y").replace(tzinfo=datetime.UTC)
    delta = dt - _FILETIME_EPOCH
    return delta.days * 86400 * 10_000_000 + delta.seconds * 10_000_000


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
    modified_filetime=_date_string_to_wire_filetime("April 15, 2026"),
)


_LCID_EN_US = 0x0409
_LCID_PT_BR = 0x0416


def _container_content(name, type_str="Directory", language=_LCID_EN_US):
    return NodeContent(
        name=name,
        go_word="",
        category="",
        type_str=type_str,
        price_dword=0,
        rating_dword=0,
        description="",
        language=language,
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


def _mnid_key(f0, f8):
    """Wire-form node_id (decimal `f0:f8`) and the 8-byte `a` blob.

    Server node_id keys are `"wire_dword_0:wire_dword_1"`, which on the
    client side are `(field_8, field_c)` of the 24-byte `_MosNodeId`
    (GetNthChild @ MOSSHELL 0x7f3fe131 stores `'a'[0]` into the child's
    `field_8` slot and `'a'[1]` into `field_c`; `field_0` is inherited
    from the parent). So if a fixture's wire key is `"X:Y"`, its `'a'`
    payload must equal `(X, Y)`, which is what this helper packs.
    """
    return f"{f0}:{f8}", struct.pack("<II", f0, f8)


# MSN root — GetSpecialMnid(idx=0) returns `(field_0=1, field_8=0, field_c=0)`,
# which lands on the wire as `(field_8=0, field_c=0)` → server key "0:0".
# This is the LJUMP 1:0:0:0 target (HOMEBASE Categories button).
_MSN_ROOT_KEY, _MSN_ROOT_MNID = _mnid_key(0, 0)
# HOMEBASE MSN Today button — LJUMP 1:4:0:0. GetSpecialMnid(idx=4) gives
# `(field_0=1, field_8=4, field_c=0)`, wire "4:0".
_MSN_TODAY_KEY, _MSN_TODAY_SPECIAL_MNID = _mnid_key(4, 0)
# Client's MSN Central — GetSpecialMnid(idx=1) returns `(field_0=1, field_8=1,
# field_c=0)`, wire "1:0". HOMEBASE Member Assistance button (LJUMP 1:1:0:0)
# dispatches here, and GetLocalizedNode descends one level. We overload this
# node as the Worldwide Member Assistance hub; its first child (MA US) is
# where clicking the button lands.
_WORLDWIDE_MEMBER_ASSISTANCE_KEY, _WORLDWIDE_MEMBER_ASSISTANCE_MNID = _mnid_key(1, 0)
# Localized wrapper mnids. The wire key `"f8:f_c"` on the server maps to the
# client's `(field_0=1 inherited, field_8, field_c)`.
_CATEGORIES_US_KEY, _CATEGORIES_US_MNID = _mnid_key(1, 0x10)
_MEMBER_ASSISTANCE_US_KEY, _MEMBER_ASSISTANCE_US_MNID = _mnid_key(1, 0x11)
_WORLDWIDE_CATEGORIES_KEY, _WORLDWIDE_CATEGORIES_MNID = _mnid_key(1, 0x12)
_CATEGORIES_BR_KEY, _CATEGORIES_BR_MNID = _mnid_key(1, 0x13)
_MEMBER_ASSISTANCE_BR_KEY, _MEMBER_ASSISTANCE_BR_MNID = _mnid_key(1, 0x14)

ROOT_CONTENT = _container_content("Root")
MSN_ROOT_CONTENT = _container_content("The Microsoft Network")

# Localized wrappers. `language=0` on the Worldwide containers marks them as
# locale-neutral so a future `filter_on=1` request with any LCID still
# accepts them.
CATEGORIES_US_CONTENT = _container_content("Categories (US)", language=_LCID_EN_US)
MEMBER_ASSISTANCE_US_CONTENT = _container_content(
    "Member Assistance (US)", language=_LCID_EN_US
)
CATEGORIES_BR_CONTENT = _container_content("Categories (BR)", language=_LCID_PT_BR)
MEMBER_ASSISTANCE_BR_CONTENT = _container_content(
    "Member Assistance (BR)", language=_LCID_PT_BR
)
WORLDWIDE_CATEGORIES_CONTENT = _container_content("Worldwide Categories", language=0)
WORLDWIDE_MEMBER_ASSISTANCE_CONTENT = _container_content(
    "Worldwide Member Assistance", language=0
)


# Categories (US) — KNOWN-CONTENT.md §"Categories (US)". `tp` is "Folder" for
# the two entries the video shows with the generic folder icon, "Category"
# for the rest.
CATEGORY_DEFS = (
    (0x100, "Arts and Entertainment", "Category"),
    (0x101, "Business and Finance", "Category"),
    (0x102, "Computers and Software", "Category"),
    (0x103, "Education and Reference", "Category"),
    (0x104, "Home and Family", "Category"),
    (0x105, "Interest, Leisure and Hobbies", "Folder"),
    (0x106, "People and Communities", "Category"),
    (0x107, "Public Affairs", "Category"),
    (0x108, "Science and Technology", "Category"),
    (0x109, "Special Events", "Category"),
    (0x10A, "Sports, Health and Fitness", "Category"),
    (0x10B, "The Internet Center", "Category"),
    (0x10C, "The MSN Member Lobby", "Folder"),
    (0x10D, "The Microsoft Network Beta", "Category"),
)


# Arts and Entertainment's sub-tree — KNOWN-CONTENT.md §"Arts and Entertainment".
A_AND_E_CHILD_DEFS = (
    (0x200, "Books and Writing"),
    (0x201, "Movies"),
    (0x202, "Art and Design"),
    (0x203, "Television and Radio"),
    (0x204, "Arts and Entertainment Kiosk"),
    (0x205, "Arts Suggestion Box"),
    (0x206, "The Big Chip"),
    (0x207, "Genres"),
    (0x208, "Comedy and Humor"),
    (0x209, "The Music Forum"),
    (0x20A, "Theater and Performance"),
    (0x20B, "Other Entertaining Places to Visit"),
    (0x20C, "Coming Attractions"),
)


# Member Assistance (US) — KNOWN-CONTENT.md §"Member assistance (US)". Slot
# index 2 ("MSN Today") is NOT in this list — the children wiring inserts
# the existing 4:0 node there so clicking it launches MOSVIEW (c=6) the same
# way the HOMEBASE MSN Today button does.
MEMBER_ASSISTANCE_LEAF_DEFS = (
    (0x300, "The MSN Member Lobby"),
    (0x301, "MSN Beta Center"),
    (0x303, "Member Assistance Kiosk - July 19"),
    (0x304, "First-Time-User Experience"),
    (0x305, "Member Guidelines"),
    (0x306, "MSN Beta News Flash - July 19"),
    (0x307, "Member Guidelines"),
    (0x308, "Member Agreement"),
)


def _dirsrv_container(f0, f8, name, *, type_str="Directory", language=_LCID_EN_US):
    key, mnid = _mnid_key(f0, f8)
    return DirectoryNode(
        node_id=key,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=mnid,
        content=_container_content(name, type_str=type_str, language=language),
    )


DIRECTORY_NODES = [
    # MSN root (wire "0:0") — client's GetSpecialMnid(idx=0). Listed as the
    # LJUMP 1:0:0:0 target (Categories button). GetLocalizedNode on this node
    # descends one level and takes the first child; the children list below
    # puts Cats US first so clicking Categories lands on Categories (US).
    DirectoryNode(
        node_id=_MSN_ROOT_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_MSN_ROOT_MNID,
        content=MSN_ROOT_CONTENT,
    ),
    # MSN Today: MedView-title leaf served by App #6 (MOSVIEW.EXE).
    #
    # Both entry points — the HOMEBASE icon click (LJUMP 1:4:0:0 →
    # CMosTreeNode::ExecuteCommand 0x3000 → 'b' bit 0x01 set → Exec) and
    # the "Show MSN Today on startup" preference (CCAPI!MOSX_GotoMosLocation
    # case 8 builds `explorer.exe …,[T]<mnid>`, Explorer calls
    # CMosShellFolder::ParseDisplayName 'T' branch, which also lands in
    # Exec without any 'b' gate — see docs/MOSSHELL.md §7.4) — terminate in
    # CMosTreeNode::Exec @ MOSSHELL 0x7F3FEBA6 with c=6, taking the
    # synchronous HRMOSExec(6, …) fall-through. MCM resolves App #6's
    # registered Filename to `mosview.exe`, formats
    # `mosview.exe -MOS:6:<shn0>:<shn1>:w` via FormatMosArgTail, and
    # CreateProcessA launches it. MOSVIEW.EXE reads the tail with
    # FGetCmdLineInfo, derives a MedView title selector from the 4:0 mnid
    # (docs/MOSVIEW.md §3.3), and opens the title through MVCL14N.
    DirectoryNode(
        node_id="4:0",
        is_container=False,
        app_id=APP_MEDIA_VIEWER,
        mnid_a=_MSN_TODAY_SPECIAL_MNID,
        content=MSN_TODAY_CONTENT,
    ),
    # Worldwide Member Assistance hub at server wire "1:0" — which is also
    # client's MSN Central (GetSpecialMnid(idx=1)). HOMEBASE Member Assistance
    # button (LJUMP 1:1:0:0) dispatches here, and GetLocalizedNode takes the
    # first child. Children are ordered so MA US comes first: clicking the
    # button lands on Member Assistance (US) with its 9 leaves visible.
    DirectoryNode(
        node_id=_WORLDWIDE_MEMBER_ASSISTANCE_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_WORLDWIDE_MEMBER_ASSISTANCE_MNID,
        content=WORLDWIDE_MEMBER_ASSISTANCE_CONTENT,
    ),
    # Localized Categories / Member Assistance wrappers and the Worldwide
    # Categories hub, following KNOWN-CONTENT.md's address-bar hierarchy.
    DirectoryNode(
        node_id=_CATEGORIES_US_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_CATEGORIES_US_MNID,
        content=CATEGORIES_US_CONTENT,
    ),
    DirectoryNode(
        node_id=_MEMBER_ASSISTANCE_US_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_MEMBER_ASSISTANCE_US_MNID,
        content=MEMBER_ASSISTANCE_US_CONTENT,
    ),
    DirectoryNode(
        node_id=_WORLDWIDE_CATEGORIES_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_WORLDWIDE_CATEGORIES_MNID,
        content=WORLDWIDE_CATEGORIES_CONTENT,
    ),
    DirectoryNode(
        node_id=_CATEGORIES_BR_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_CATEGORIES_BR_MNID,
        content=CATEGORIES_BR_CONTENT,
    ),
    DirectoryNode(
        node_id=_MEMBER_ASSISTANCE_BR_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_MEMBER_ASSISTANCE_BR_MNID,
        content=MEMBER_ASSISTANCE_BR_CONTENT,
    ),
    *[_dirsrv_container(1, f8, name, type_str=tp) for f8, name, tp in CATEGORY_DEFS],
    *[_dirsrv_container(1, f8, name) for f8, name in A_AND_E_CHILD_DEFS],
    *[_dirsrv_container(1, f8, name) for f8, name in MEMBER_ASSISTANCE_LEAF_DEFS],
]


# MSN root's children double as the address-bar combobox under "The Microsoft
# Network" (per KNOWN-CONTENT.md) and as the LJUMP 1:0:0:0 GetLocalizedNode
# target list. Cats US is listed first so the Categories button lands on it.
# WW MA is referenced by its server key (`"1:0"`) because it aliases client's
# MSN Central — same physical node, two roles (address-bar entry + LJUMP
# 1:1:0:0 target).
_ARTS_AND_ENTERTAINMENT_KEY = f"1:{0x100}"
DIRECTORY_CHILDREN = {
    _MSN_ROOT_KEY: [
        _CATEGORIES_US_KEY,
        _MEMBER_ASSISTANCE_US_KEY,
        _WORLDWIDE_CATEGORIES_KEY,
        _WORLDWIDE_MEMBER_ASSISTANCE_KEY,
    ],
    # MSN Central / WW MA hub — LJUMP 1:1:0:0 target. MA US first so the
    # HOMEBASE Member Assistance click descends to Member Assistance (US).
    _WORLDWIDE_MEMBER_ASSISTANCE_KEY: [
        _MEMBER_ASSISTANCE_US_KEY,
        _MEMBER_ASSISTANCE_BR_KEY,
    ],
    _CATEGORIES_US_KEY: [f"1:{f8}" for f8, _, _ in CATEGORY_DEFS],
    _MEMBER_ASSISTANCE_US_KEY: [
        f"1:{0x300}",        # The MSN Member Lobby
        f"1:{0x301}",        # MSN Beta Center
        "4:0",               # MSN Today — reuse existing MOSVIEW leaf
        f"1:{0x303}",        # Member Assistance Kiosk - July 19
        f"1:{0x304}",        # First-Time-User Experience
        f"1:{0x305}",        # Member Guidelines (MOSVIEW)
        f"1:{0x306}",        # MSN Beta News Flash - July 19
        f"1:{0x307}",        # Member Guidelines (document?)
        f"1:{0x308}",        # Member Agreement (document?)
    ],
    _WORLDWIDE_CATEGORIES_KEY: [_CATEGORIES_US_KEY, _CATEGORIES_BR_KEY],
    _CATEGORIES_BR_KEY: [],
    _MEMBER_ASSISTANCE_BR_KEY: [],
    _ARTS_AND_ENTERTAINMENT_KEY: [f"1:{f8}" for f8, _ in A_AND_E_CHILD_DEFS],
    # Explicit empty children for the `4:0` startup node — avoids the
    # sentinel fallback path that previously introduced `FFFFFFFF:FFFFFFFF`
    # into the rendered hierarchy. Favorite Places (`3:1`) is client-side.
    "4:0": [],
    "3:1": [],
    # Every remaining category/A&E/MA leaf is terminal — explicit empty list
    # keeps the fallback sentinel out of their listviews.
    **{
        f"1:{f8}": []
        for f8, _, _ in CATEGORY_DEFS
        if f8 != 0x100
    },
    **{f"1:{f8}": [] for f8, _ in A_AND_E_CHILD_DEFS},
    **{f"1:{f8}": [] for f8, _ in MEMBER_ASSISTANCE_LEAF_DEFS},
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
