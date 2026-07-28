"""Default seed data for the in-memory app store."""

from __future__ import annotations

import datetime
import struct
from dataclasses import dataclass

from ..mos_apps import APP_BBS_SERVICE, APP_DIRECTORY_SERVICE, APP_MEDIA_VIEWER
from .base import (
    BbsFields,
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
CATEGORIES_BR_CONTENT = _container_content("Categorias (BR)", language=_LCID_PT_BR)
MEMBER_ASSISTANCE_BR_CONTENT = _container_content(
    "Assistencia ao Associado (BR)", language=_LCID_PT_BR
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
    # Development-only category that exposes the BBDESIGN test fixtures
    # checked into `tests/assets/` as MOSVIEW-launched leaves. The asset
    # files are mirrored into `resources/titles/{deid}.ttl` so the
    # MEDVIEW handler resolves them through the standard OpenTitle path.
    (0x10E, "MEDVIEW tests", "Category"),
)


# Children of "MEDVIEW tests" — one MOSVIEW leaf per `.ttl` fixture. The
# f0 value is the MOSVIEW deid (formatted `%X` by MOSVIEW's deid
# normalization, see docs/MOSVIEW.md §3.3), so the on-disk filename is
# `{f0:x}.ttl`. f8=0 keeps deid_hi clear so MCM picks the single-word
# `%X` path instead of `%X%8X`.
MEDVIEW_TEST_LEAF_DEFS = (
    (0x1000, "Captions Test"),
    (0x1001, "Story Test"),
    (0x1002, "Multi-page Title"),
    (0x1003, "All Controls"),
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


# Categorias (BR) — Portuguese counterparts to CATEGORY_DEFS. Names are
# ASCII-only because the SVCPROP string encoder (`_sz` in services/dirsrv.py)
# narrows to ASCII via `errors="replace"`; CP-1252 accents would land as `?`
# on the wire. Real Marvel server data isn't documented for pt-BR, so this is
# a parallel-structure mirror of the US set with localised display strings.
CATEGORY_BR_DEFS = (
    (0x180, "Artes e Entretenimento", "Categoria"),
    (0x181, "Negocios e Financas", "Categoria"),
    (0x182, "Computadores e Software", "Categoria"),
    (0x183, "Educacao e Referencia", "Categoria"),
    (0x184, "Casa e Familia", "Categoria"),
    (0x185, "Interesses, Lazer e Hobbies", "Pasta"),
    (0x186, "Pessoas e Comunidades", "Categoria"),
    (0x187, "Assuntos Publicos", "Categoria"),
    (0x188, "Ciencia e Tecnologia", "Categoria"),
    (0x189, "Eventos Especiais", "Categoria"),
    (0x18A, "Esportes, Saude e Forma Fisica", "Categoria"),
    (0x18B, "Central da Internet", "Categoria"),
    (0x18C, "Saguao dos Associados MSN", "Pasta"),
    (0x18D, "The Microsoft Network Beta", "Categoria"),
)


# Assistencia ao Associado (BR) — Portuguese counterparts. Mirrors the US slate
# minus the MSN Today reference (4:0 is locale en-US and would be filtered
# out under filter_on=1 with pt-BR anyway).
MEMBER_ASSISTANCE_BR_LEAF_DEFS = (
    (0x380, "Saguao dos Associados MSN"),
    (0x381, "Centro Beta MSN"),
    (0x382, "Quiosque de Assistencia ao Associado - 19 de Julho"),
    (0x383, "Experiencia de Primeiro Acesso"),
    (0x384, "Diretrizes do Associado"),
    (0x385, "Boletim Beta MSN - 19 de Julho"),
    (0x386, "Diretrizes do Associado"),
    (0x387, "Acordo do Associado"),
)


# Sub-tree for Artes e Entretenimento (1:0x180) — Portuguese counterparts to
# A_AND_E_CHILD_DEFS. ID range 0x280..0x28C parallels US 0x200..0x20C.
A_AND_E_BR_CHILD_DEFS = (
    (0x280, "Livros e Escrita"),
    (0x281, "Filmes"),
    (0x282, "Arte e Design"),
    (0x283, "Televisao e Radio"),
    (0x284, "Quiosque de Artes e Entretenimento"),
    (0x285, "Caixa de Sugestoes de Artes"),
    (0x286, "The Big Chip"),
    (0x287, "Generos"),
    (0x288, "Comedia e Humor"),
    (0x289, "Forum de Musica"),
    (0x28A, "Teatro e Apresentacoes"),
    (0x28B, "Outros Lugares Divertidos para Visitar"),
    (0x28C, "Proximas Atracoes"),
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


def _medview_test_leaf(f0, name):
    """MOSVIEW leaf backed by a `.ttl` fixture under `resources/titles/`.

    deid_hi=0 keeps MOSVIEW on the single-word `%X` deid normalization
    path, so f0=0x1000 → cmdline `-MOS:6:1000:0:w` → titleToken
    `:2[1000]0` → server resolves `resources/titles/1000.ttl`.
    """
    key, mnid = _mnid_key(f0, 0)
    return DirectoryNode(
        node_id=key,
        is_container=False,
        app_id=APP_MEDIA_VIEWER,
        mnid_a=mnid,
        content=NodeContent(
            name=name,
            go_word="",
            category="MEDVIEW tests",
            type_str="MedView Title",
            price_dword=0,
            rating_dword=0,
            description="",
            language=_LCID_EN_US,
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
        ),
    )


_MEDVIEW_TESTS_KEY = f"1:{0x10E}"


# --- BBS service sample board (docs/bbs-service-contract.md) ---
#
# A single forum board, "Climbing BBS", listed under the existing "Sports,
# Health and Fitness" DIRSRV category — the shape reference/screenshots show,
# where BBS boards sit as ordinary rows beside kiosks, folders and chat rooms.
# Opening the board runs the `b`-bit-0x04 delegate: HrSetupDelegate builds
# {field_0=2, field_8/field_c=(2,1), field_10=0} and hands the folder to
# bbsnav, which fetches this node and its children over svc "BBS". The inner
# node starts with an empty property cache, and that is fine — FindProperty
# (MOSSHELL 0x7F3FCE12) fetches on a cache miss via slot 14
# GetPropertyFromHost. A `news:`/`msn:` URL jump reaches the same board.
# Threading is the tree itself — a reply is a child of the message it answers,
# so recursive GetChildren yields the indented thread list. The f0=2 namespace
# keeps BBS mnids from colliding with DIRSRV's f0=1; all BBS nodes are
# language=0 (locale-neutral) so they survive a filter_on=1 GetChildren.
# Mirrors reference/screenshots/bbs.png.

# Yosemite conversation body, transcribed from bbs.png. Seeded for the deferred
# message-body wire gap: BbsFields.body is NOT yet emitted on the wire — the
# reader's body source is a contract-flagged bounded gap (RichEdit-hosted,
# GetPropertyToFile is only an inherited thunk) pending a live SoftICE trace.
_YOSEMITE_BODY = (
    "In case anyone is thinking of a trip to Yosemite, prepare for water. "
    "I just got back from a wet trip that allowed me to see the best "
    "waterfall display in over a decade, but I didn't get to climb.\n\n"
    "It was a bit frustrating to gaze up to those incredible cliffs and not "
    "be able to climb. The constant rain kept the rock wet. If it stopped "
    "raining, the saturated mountains kept the water seeping from the cracks. "
    "Most major cracks have turned into \"spring of '95\" springs feeding the "
    "Merced River.\n\n"
    "We actually climbed two pitches, dodging the wet spots on the rock "
    "before it started to rain again."
)


def _bbs_date_to_unix(s):
    """Parse a fixture `%B %d, %Y %I:%M %p` timestamp into a Unix time_t.

    The string is **local wall-clock time**, i.e. what the client should display,
    matching reference/screenshots/bbs.png whose reader header reads "10:12 AM".

    Converted with the **current** UTC offset, not the offset that was in force
    on the fixture's date. Windows 95 has no historical timezone database — it
    applies its single current rule to every timestamp — so a 1995 `_D` is
    rendered by the client with today's offset. Python's `.timestamp()` would
    instead honor the 1995 rule (e.g. Europe/Lisbon ran CEST +0200 until 1996),
    which put the Date column an hour behind the `v`/`w` dialog strings that pass
    through verbatim. Using the current offset makes the column, the dialog and
    the reference agree.

    Assumes the client's timezone matches this host's. Both live on the same
    machine here; a real deployment would format dialog strings from the
    member's profile timezone instead.

    Empty input → 0, which build_bbs_props still emits as `_D` = 0 (never
    omitted — an omitted tag truncates the record).
    """
    if not s:
        return 0
    naive = datetime.datetime.strptime(s, "%B %d, %Y %I:%M %p")
    offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
    return int((naive - offset).replace(tzinfo=datetime.UTC).timestamp())


def _bbs_node(
    f0,
    f8,
    name,
    *,
    is_container,
    author="",
    date="",
    parent_subid=0,
    topic="",
    has_children=False,
    body="",
    delegate=False,
):
    """A BBS tree node (board / conversation / reply).

    `is_container` means **board or folder**, not "has replies" — it drives `b`
    bit 0x01 (CLEAR = container, SET = message), which is bbsnav's conversation
    test. A conversation head is a message that has children, so it takes
    is_container=False with has_children=True; `_F` carries the expand gate
    independently.

    Rides DirectoryNode with app_id=APP_BBS_SERVICE and language=0; the
    BBS-specific tags (`_a/_D/_P/_t/_F`) live in the attached BbsFields, read by
    build_bbs_props and ignored by DIRSRV serialisation. `p` (Size) is the body
    byte count. `name` is the Subject (wire `e`).

    Set `delegate` on the board — the node DIRSRV lists inside a category. It
    emits `b` bit 0x04 + `c`/`l`/`i`, so MOSSHELL `HrSetupDelegate` builds the
    inner mnid `{field_0=2, field_8/field_c=mnid_a, field_10=0}` and hands the
    folder to bbsnav, which then reads this same node over svc "BBS". Nodes
    below the board inherit field_0=2 and need no delegate tags.
    """
    key, mnid = _mnid_key(f0, f8)
    return DirectoryNode(
        node_id=key,
        is_container=is_container,
        app_id=APP_BBS_SERVICE,
        mnid_a=mnid,
        delegate=delegate,
        content=NodeContent(
            name=name,
            go_word="",
            category="",
            type_str="",
            price_dword=0,
            rating_dword=0,
            description="",
            language=0,
            topics="",
            people="",
            place="",
            u_value="",
            forum_mgr="",
            vendor_id=0,
            owner=author,
            # The Properties dialog fetches the shared MOS tree tags one at a
            # time (`q,g` then `v,g` …), and build_bbs_props hands those to
            # DIRSRV's serialiser. Mirror the post date into `created`/`modified`
            # so the dialog shows the real timestamp instead of blanks; the
            # listview Date column still comes from `_D`.
            created=date,
            modified=date,
            size_bytes=len(body),
            bbs=BbsFields(
                author=author,
                date_unix=_bbs_date_to_unix(date),
                parent_subid=parent_subid,
                topic=topic,
                has_children=has_children,
                body=body,
            ),
        ),
    )


# "Sports, Health and Fitness" (CATEGORY_DEFS f8 0x10A) hosts the board.
_SPORTS_HEALTH_FITNESS_KEY = f"1:{0x10A}"

_CLIMBING_BBS = _bbs_node(
    2, 0x1, "Climbing BBS", is_container=True, has_children=True, delegate=True
)
# Conversations and messages use f0=0, so the client's mnid field_8 is 0.
# CBbsNavTreeNode_GetProperty @ 0x7F5F1538 intercepts `h` and returns icon id
# 0x59D (a bbsnav-local glyph) when node+0x18 == 0 — that is mnid.field_8 —
# and 0x86 otherwise. The board keeps f0=2 so it stays a folder; everything
# inside it must read as BBS content. Ids set in FUN_7F5F1000 @ 0x7F5F1000.
# Authors and the Yosemite timestamp are transcribed from
# reference/screenshots/bbs.png (list pane + reader header "Date: 10:12 AM
# Tuesday, May 16, 1995"). The other two timestamps are NOT in the screenshot —
# they are invented, ordered so the reply follows its parent.
_BBS_YOSEMITE = _bbs_node(
    0,
    0x100,
    "Yosemite",
    is_container=False,
    author="Chris Hahn",
    date="May 16, 1995 10:12 AM",
    has_children=True,
    body=_YOSEMITE_BODY,
)
_BBS_BRITISH_CLIMBERS = _bbs_node(
    0,
    0x101,
    "British Climbers",
    is_container=False,
    author="KEITH SUTTON",
    date="May 15, 1995 8:22 AM",
)
_BBS_RE_YOSEMITE = _bbs_node(
    0,
    0x200,
    "RE: Yosemite",
    is_container=False,
    author="Chris Shannon",
    date="May 17, 1995 3:45 PM",
    parent_subid=0x100,
)

BBS_NODES = [_CLIMBING_BBS, _BBS_YOSEMITE, _BBS_BRITISH_CLIMBERS, _BBS_RE_YOSEMITE]


DIRECTORY_NODES = [
    # MSN root (wire "0:0") — client's GetSpecialMnid(idx=0). Listed as the
    # LJUMP 1:0:0:0 target (Categories button). GetLocalizedNode on this node
    # descends one level and takes the first locale-matching child; the
    # children list below interleaves Cats(US)/Cats(BR) ahead of WW Categories
    # so each locale's filter_on=1 pass surfaces the right Categories wrapper.
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
    # first locale-matching child: en-US lands on MA(US), pt-BR drops MA(US)
    # and lands on MA(BR).
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
    *[
        _dirsrv_container(1, f8, name, type_str=tp, language=_LCID_PT_BR)
        for f8, name, tp in CATEGORY_BR_DEFS
    ],
    *[
        _dirsrv_container(1, f8, name, type_str="Diretorio", language=_LCID_PT_BR)
        for f8, name in MEMBER_ASSISTANCE_BR_LEAF_DEFS
    ],
    *[
        _dirsrv_container(1, f8, name, type_str="Diretorio", language=_LCID_PT_BR)
        for f8, name in A_AND_E_BR_CHILD_DEFS
    ],
    *[_medview_test_leaf(f0, name) for f0, name in MEDVIEW_TEST_LEAF_DEFS],
    *BBS_NODES,
]


# MSN root's children double as the address-bar combobox under "The Microsoft
# Network" (per KNOWN-CONTENT.md — the localized Cats/MA wrappers are direct
# children of MSN root, not of their worldwide hubs) and as the LJUMP 1:0:0:0
# GetLocalizedNode target list. The interleaved order keeps each locale's
# Cats wrapper ahead of WW Categories so that under filter_on=1 the
# locale-specific entry is the first survivor: pt-BR drops Cats(US)/MA(US)
# and lands on Cats(BR); en-US drops the BR variants and lands on Cats(US).
# WW MA is referenced by its server key (`"1:0"`) because it aliases client's
# MSN Central — same physical node, two roles (address-bar entry + LJUMP
# 1:1:0:0 target).
_ARTS_AND_ENTERTAINMENT_KEY = f"1:{0x100}"
_ARTES_E_ENTRETENIMENTO_KEY = f"1:{0x180}"
DIRECTORY_CHILDREN = {
    _MSN_ROOT_KEY: [
        _CATEGORIES_US_KEY,
        _CATEGORIES_BR_KEY,
        _MEMBER_ASSISTANCE_US_KEY,
        _MEMBER_ASSISTANCE_BR_KEY,
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
    _CATEGORIES_BR_KEY: [f"1:{f8}" for f8, _, _ in CATEGORY_BR_DEFS],
    _MEMBER_ASSISTANCE_BR_KEY: [f"1:{f8}" for f8, _ in MEMBER_ASSISTANCE_BR_LEAF_DEFS],
    _ARTS_AND_ENTERTAINMENT_KEY: [f"1:{f8}" for f8, _ in A_AND_E_CHILD_DEFS],
    _ARTES_E_ENTRETENIMENTO_KEY: [f"1:{f8}" for f8, _ in A_AND_E_BR_CHILD_DEFS],
    _MEDVIEW_TESTS_KEY: [f"{f0}:0" for f0, _ in MEDVIEW_TEST_LEAF_DEFS],
    # BBS board "Climbing BBS" listed under "Sports, Health and Fitness"
    # (c=2 = APP_BBS_SERVICE, b bit 0x04 = delegate). Opening it hands the
    # folder to bbsnav, which enumerates the thread list over svc "BBS".
    # Threading is the tree itself — replies are children of the message they
    # answer, so recursive GetChildren yields the indented thread view.
    _SPORTS_HEALTH_FITNESS_KEY: [_CLIMBING_BBS.node_id],
    _CLIMBING_BBS.node_id: [_BBS_YOSEMITE.node_id, _BBS_BRITISH_CLIMBERS.node_id],
    _BBS_YOSEMITE.node_id: [_BBS_RE_YOSEMITE.node_id],
    _BBS_BRITISH_CLIMBERS.node_id: [],
    _BBS_RE_YOSEMITE.node_id: [],
    # Explicit empty children for the `4:0` startup node — avoids the
    # sentinel fallback path that previously introduced `FFFFFFFF:FFFFFFFF`
    # into the rendered hierarchy. Favorite Places (`3:1`) is client-side.
    "4:0": [],
    "3:1": [],
    # Every remaining category/A&E/MA leaf is terminal — explicit empty list
    # keeps the fallback sentinel out of their listviews. 0x100 (Arts and
    # Entertainment), 0x10A (Sports, Health and Fitness → Climbing BBS) and
    # 0x10E (MEDVIEW tests) are skipped because they have their own subtrees
    # wired above.
    **{
        f"1:{f8}": []
        for f8, _, _ in CATEGORY_DEFS
        if f8 not in (0x100, 0x10A, 0x10E)
    },
    **{f"1:{f8}": [] for f8, _ in A_AND_E_CHILD_DEFS},
    **{f"1:{f8}": [] for f8, _ in MEMBER_ASSISTANCE_LEAF_DEFS},
    **{
        f"1:{f8}": []
        for f8, _, _ in CATEGORY_BR_DEFS
        if f8 != 0x180
    },
    **{f"1:{f8}": [] for f8, _ in MEMBER_ASSISTANCE_BR_LEAF_DEFS},
    **{f"1:{f8}": [] for f8, _ in A_AND_E_BR_CHILD_DEFS},
    **{f"{f0}:0": [] for f0, _ in MEDVIEW_TEST_LEAF_DEFS},
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
