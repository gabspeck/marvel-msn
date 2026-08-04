"""Domain model and store protocols for the MSN95 server."""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Protocol

# Wire DIRSRV property `x`. `CMosViewWnd::AddMenus` asks
# `CMosTreeNode::HasRights` for mask 0x70 before merging File >
# New/Delete/Unlink, and HasRights reads `x` as a DWORD and succeeds when any
# requested bit is present. A member holding 0 therefore gets no authoring menu.
RIGHTS_NONE = 0x00
RIGHTS_AUTHORING = 0x70


@dataclass(frozen=True)
class BbsFields:
    """BBS-only per-node fields, carried alongside NodeContent.

    The BBS read channel reuses DirectoryNode/NodeContent (it rides the same
    generic MOS tree as DIRSRV) but emits a different tag vocabulary. These
    fields back the BBS-specific tags; DIRSRV serialisation ignores them.
    See docs/bbs-service-contract.md §"Property tags".
    """

    author: str = ""  # _a (ASCIIZ)
    date_unix: int = 0  # _D — time_t seconds (MOSSHELL DWORD-as-time_t path)
    parent_subid: int = 0  # _P — parent message's f8 (0 for a top-level node)
    has_children: bool = False  # → _F bit 0x1000 CLEAR; set = leaf (no children)
    # Article body, always authored as plain text. `body_format` picks the
    # X-MOS-Format the reader is told to stream it as, and with it the encoder
    # that turns this text into wire bytes — see server.services.bbs
    # BODY_ENCODERS. RTF is the default because SF_TEXT would draw the body in
    # the RichEdit's default Courier New.
    body: str = ""
    body_format: str = "RTF"
    # Verbatim body bytes, set only on a message that arrived over the post
    # channel. The Compose window uploads its body already encoded — RTFCOMP
    # (MAPI compressed RTF) or TEXT, per the X-MOS-Format it wrote — and the
    # reader streams back whatever X-MOS-Format names, so the bytes round-trip
    # untouched. When this is set it wins over `body`/BODY_ENCODERS, which
    # exist to turn fixture-authored plain text into wire bytes.
    body_raw: bytes | None = None
    # Files attached to the message. The count is wire `_t` (one byte), which
    # BBSNAV uses to populate Attached Files view and the Properties page. An
    # attachment never travels on the message
    # channel: the article carries headers plus the body alone, and the file
    # reaches the reader as an OLE object embedded in that RTF body (CLSID
    # {00028B50-0000-0000-C000-000000000046}, MOSAF.DLL "Mos Attached File").
    # BBSNAV FUN_7F5FC7B7 @ 0x7F5FC7B7 collects the objects carrying that CLSID
    # and FUN_7F5FC919 @ 0x7F5FC919 hands object k the mnid (message id + k,
    # board id), so the count decides how many tree nodes sit behind a message.
    # `attachment_data` is what the post channel uploaded past the body — one
    # file when the count is 1, and the concatenation otherwise, since the
    # per-file boundaries are not visible on the wire.
    attachment_count: int = 0
    attachment_data: bytes = b""
    # Attachment-node wire `_r` (DWORD). MOSAF displays it as "Downloads:" in
    # the remote file's Properties page. Message nodes use the same tag for
    # read state; both start at zero.
    download_count: int = 0


@dataclass(frozen=True)
class ConferenceFields:
    """Conference-only room settings authored through CONFLOC."""

    room_capacity: int
    message_length: int
    join_as_participants: bool


@dataclass(frozen=True)
class NodeContent:
    name: str
    go_word: str
    category: str
    type_str: str
    price_dword: int
    rating_dword: int
    description: str
    language: int
    topics: str
    people: str
    place: str
    u_value: str
    forum_mgr: str
    vendor_id: int
    owner: str
    created: str
    modified: str
    size_bytes: int
    # 64-bit FILETIME (100-ns intervals since 1601-01-01 UTC) for the DSNAV
    # "Date Modified" listview column. Wire type 0x0C — MOSSHELL 0x7F3FBC12
    # case 0xC passes the 8-byte value straight to FileTimeToSz, which runs
    # GetDateFormatA + GetTimeFormatA on the localized SYSTEMTIME. Sending `w`
    # as DWORD would fall into the case-3 "%u" branch (only prop name "_D"
    # triggers the DWORD-as-time_t path; "_D" is BBSNAV territory). 0 = no
    # cached date → server skips emitting `w`, cell renders blank.
    modified_filetime: int = 0
    # Optional BBS-only sub-struct. None for DIRSRV/MEDVIEW nodes; set on BBS
    # board/conversation/reply nodes so build_bbs_props can read BBS-only tags.
    bbs: BbsFields | None = None
    # Optional CONFLOC settings. None for nodes that are not chat rooms.
    conference: ConferenceFields | None = None


@dataclass(frozen=True)
class DirectoryNode:
    """A navigable directory entry.  `node_id` is the wire "hi:lo" form."""

    node_id: str
    is_container: bool
    app_id: int  # wire 'c' property — registered MOS app id
    mnid_a: bytes  # 8-byte opaque 'a' blob
    content: NodeContent
    browse_flags: int | None = None  # wire 'b' override; None = derive from is_container
    # Hand this folder to app_id's navigator instead of browsing it over
    # DIRSRV. Emits 'b' bit 0x04 + 'c' + 'l' (= mnid_a) + 'i' (= 0), which
    # MOSSHELL HrSetupDelegate turns into the inner mnid
    # {field_0=app_id, field_8/field_c=mnid_a, field_10=0}.
    delegate: bool = False
    # Optional inner `l` MNID when it differs from the outer directory `a`.
    # Creating a BBS folder produces both: DIRSRV owns the outer category row,
    # while BBS AddNode returns the inner board id that selects BBSNAV's folder
    # property pages.
    delegate_mnid_a: bytes | None = None
    # Wire property `g` — the node's change stamp. `CMosTreeNode::QueryOutOfDate`
    # @ MOSSHELL 0x7F3FDB3F is the only reader: it compares the value the server
    # sends now against the one it cached, and marks the node out of date when
    # they differ. Every refresh — the idle poll and F5 alike — is gated on it,
    # so a node whose `g` never moves can never be re-listed.
    generation: int = 0
    # Account usernames that hold the conference host role. This is server
    # state, not a wire property, and is empty for nodes that are not rooms.
    host_usernames: tuple[str, ...] = ()


@dataclass(frozen=True)
class BillingProfile:
    first_name: str
    last_name: str
    country_id: int
    address: str
    city: str
    state: str
    zip: str
    phone: str
    payment_type: int  # 1=CHARGE, 2=DEBIT, 3=DIRECTDEBIT
    card_number: str


@dataclass(frozen=True)
class MemberProfile:
    """One member's self-published details, as the Member Properties sheet reads them.

    Field names follow the labels on MOSABP32's three property pages (dialogs
    100 "General", 101 "Personal", 102 "Professional"); see docs/MOSABP.md for
    the tag each one serialises to. Everything is optional — a member who filled
    in nothing still gets a sheet with their member id.

    `country_code`, `marital_status_code` and `language_code` are numeric
    catalogue ids, not text. The client renders them through validation lists it
    caches from `GetValidationList` (method 1); with no cached list it leaves the
    field blank, so the code that ships here is only meaningful once that
    selector exists.
    """

    member_id: str
    display_name: str = ""
    first_name: str = ""
    last_name: str = ""
    city: str = ""
    state: str = ""
    country_code: int = 0
    birth_date: str = ""
    sex: str = ""
    marital_status_code: int = 0
    language_code: int = 0
    interests: str = ""
    job_description: str = ""
    company_name: str = ""
    work_city: str = ""
    work_state: str = ""
    work_country_code: int = 0


@dataclass(frozen=True)
class StatementSummary:
    balance_cents: int
    currency_iso: int
    year: int
    month: int
    day: int
    free_connect_minutes: int
    # Dates the Subscriptions page appends to its rows: `expires` to the
    # type-flag 0x01 rows, `effective` to the 0x02 ones. The summary page uses
    # year/month/day above instead, which is a different date entirely.
    expires_date: datetime.date = datetime.date(1970, 1, 1)
    effective_date: datetime.date = datetime.date(1970, 1, 1)


@dataclass(frozen=True)
class TransactionRecord:
    when: datetime.datetime
    description: str
    amount_minor: int
    total_minor: int
    extra: int | None = None
    foreign: tuple | None = None  # (fx_amount, fx_currency, fx_rate)


@dataclass(frozen=True)
class Subscription:
    kind: int  # wire flag: 0x01 expires, 0x02 effective, 0x04 promo, 0xFF misc
    name: str
    detail: str
    price_minor: int
    price_currency: int
    record_currency: int


@dataclass(frozen=True)
class Plan:
    plan_id: int  # wire catalog slot (0, 1, 2, …)
    name: str
    detail: str


# Stand-ins so every User answers every field. A member who has published no
# billing or statement data still gets a well-formed reply — blank boxes and a
# zero balance — instead of forcing a None check into each handler.
EMPTY_BILLING_PROFILE = BillingProfile(
    first_name="",
    last_name="",
    country_id=0,
    address="",
    city="",
    state="",
    zip="",
    phone="",
    payment_type=1,
    card_number="",
)

EMPTY_STATEMENT_SUMMARY = StatementSummary(
    balance_cents=0,
    currency_iso=840,
    year=1970,
    month=1,
    day=1,
    free_connect_minutes=0,
)


@dataclass(frozen=True)
class User:
    """One MSN account: what signs in, and everything the services say about it.

    `username` and `password` are what the Sign In dialog collects and LOGSRV
    checks. `display_name` is the public identity — it goes out as a BBS post's
    `From:` header, and because MOSABP32 passes a From with no '@' through
    whole, it is also the key that resolves the Member Properties sheet.

    Billing and statement data hang off the account rather than living in
    parallel stores keyed by name: one lookup answers every per-member reply.
    """

    username: str
    password: str
    display_name: str
    rights: int = RIGHTS_NONE  # wire DIRSRV `x`
    sa_tokens: tuple = ()  # SASRV token ids this account may enumerate
    billing: BillingProfile = EMPTY_BILLING_PROFILE
    statement: StatementSummary = EMPTY_STATEMENT_SUMMARY
    transactions: tuple = ()  # one list per statement period, newest first
    subscriptions: tuple = ()


# The identity a connection carries before LOGSRV signs it in. A pipe can open
# ahead of the login — the LOGSRV pipe itself does — so an unauthenticated
# session is a real state, and giving it a User keeps `if user is None` out of
# every handler.
ANONYMOUS_USER = User(username="", password="", display_name="")


class ContentStore(Protocol):
    def load(self, nodes: list, children: dict, fallback: DirectoryNode) -> None: ...
    def get_node(self, node_id: str) -> DirectoryNode | None: ...
    def get_children(self, node_id: str) -> list: ...
    def has_children(self, node_id: str) -> bool: ...
    def count_children(self, node_id: str) -> int: ...
    def count_parents(self, node_id: str) -> int: ...
    def find_by_go_word(self, go_word: str) -> DirectoryNode | None: ...
    def find_app_instance(self, app_id: int, instance_id: int) -> DirectoryNode | None: ...
    def add_child(self, parent_id: str, node: DirectoryNode) -> None: ...
    def add_node(self, node: DirectoryNode) -> None: ...
    def remove_node(self, node_id: str) -> bool: ...


class UserStore(Protocol):
    def load(self, users: list) -> None: ...
    def authenticate(self, username: str, password: str) -> User | None: ...
    def get_user(self, username: str) -> User | None: ...
    def set_password(self, username: str, password: str) -> bool: ...
    def set_billing(self, username: str, profile: BillingProfile) -> bool: ...


class MemberStore(Protocol):
    def load(self, profiles: list) -> None: ...
    def get_member(self, member_id: str) -> MemberProfile: ...


class CatalogStore(Protocol):
    """The subscription plans on offer — a catalogue, the same for every member."""

    def load(self, plans: list) -> None: ...
    def get_plans(self) -> list: ...


@dataclass
class AppStore:
    content: ContentStore
    users: UserStore
    catalog: CatalogStore
    member: MemberStore

    def reset(self, seed) -> None:
        """Re-seed every store in place, dropping all runtime changes.

        In place, not rebuilt: each service binds `app_store` at import time, so
        swapping in a new AppStore would leave them reading the old state.
        """
        self.content.load(
            seed.directory_nodes,
            seed.directory_children,
            seed.directory_fallback,
        )
        self.users.load(seed.users)
        self.catalog.load(seed.plans)
        self.member.load(seed.member_profiles)
