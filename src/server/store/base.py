"""Domain model and store protocols for the MSN95 server."""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Protocol


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
    topic: str = ""  # _t (ASCIIZ, Properties-dialog sub-title)
    has_children: bool = False  # → _F bit 0x1000 CLEAR; set = leaf (no children)
    # Article body, always authored as plain text. `body_format` picks the
    # X-MOS-Format the reader is told to stream it as, and with it the encoder
    # that turns this text into wire bytes — see server.services.bbs
    # BODY_ENCODERS. RTF is the default because SF_TEXT would draw the body in
    # the RichEdit's default Courier New.
    body: str = ""
    body_format: str = "RTF"


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
    # board/conversation/reply nodes so build_bbs_props can read _a/_D/_P/_t/_F.
    bbs: BbsFields | None = None


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


class ContentStore(Protocol):
    def get_node(self, node_id: str) -> DirectoryNode | None: ...
    def get_children(self, node_id: str) -> list: ...
    def has_children(self, node_id: str) -> bool: ...
    def find_by_go_word(self, go_word: str) -> DirectoryNode | None: ...


class AccountStore(Protocol):
    def get_billing_profile(self) -> BillingProfile: ...


class MemberStore(Protocol):
    def get_member(self, member_id: str) -> MemberProfile: ...


class StatementStore(Protocol):
    def get_summary(self) -> StatementSummary: ...
    def get_transactions(self, period_index: int) -> list: ...
    def period_count(self) -> int: ...
    def get_subscriptions(self) -> list: ...
    def get_plans(self) -> list: ...


@dataclass
class AppStore:
    content: ContentStore
    account: AccountStore
    statement: StatementStore
    member: MemberStore
