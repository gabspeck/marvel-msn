"""Domain model and store protocols for the MSN95 server."""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Protocol


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


@dataclass(frozen=True)
class DirectoryNode:
    """A navigable directory entry.  `node_id` is the wire "hi:lo" form."""

    node_id: str
    is_container: bool
    app_id: int  # wire 'c' property — registered MOS app id
    mnid_a: bytes  # 8-byte opaque 'a' blob
    content: NodeContent
    browse_flags: int | None = None  # wire 'b' override; None = derive from is_container


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
    def find_by_go_word(self, go_word: str) -> DirectoryNode | None: ...


class AccountStore(Protocol):
    def get_billing_profile(self) -> BillingProfile: ...


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
