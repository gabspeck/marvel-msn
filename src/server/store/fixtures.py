"""Default seed data for the in-memory app store.

Everything below is immutable declarative data. The store never holds these
objects: `default_seed()` hands out a fresh copy of every container, so a
runtime write reaches the store's own state and this module keeps describing
the state the process starts from. Every record is a frozen dataclass, which is
what makes copying the containers one level deep enough.
"""

from __future__ import annotations

import datetime
import pathlib
import struct
from dataclasses import dataclass, replace

from ..mos_apps import (
    APP_DIRECTORY_SERVICE,
    APP_DOWNLOAD_AND_RUN,
    APP_MEDIA_VIEWER,
    APP_TEXT_CONFERENCE,
)
from .base import (
    RIGHTS_AUTHORING,
    RIGHTS_NONE,
    BillingProfile,
    ConferenceFields,
    DirectoryNode,
    MemberProfile,
    NodeContent,
    Plan,
    StatementSummary,
    Subscription,
    TransactionRecord,
    User,
)
from .records import bbs_node, build_bbs_attachment_nodes, mnid_key

_FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.UTC)


def _date_string_to_wire_filetime(s):
    """Parse a fixture `%B %d, %Y` date into a Windows FILETIME (UTC midnight).

    UTC, so the client's `FileTimeToLocalFileTime` shifts it by the member's
    offset — a date-only fixture therefore displays at that offset past
    midnight, not at 00:00.

    Returns 0 for empty input, the "no date" sentinel: DIRSRV then ships `w` as
    an empty string for the details view's blank cell. Find has no blank branch
    and renders that node as the 1601 epoch, so every indexed node should carry
    a real date.
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


# Every directory row carries a last-changed date. MOSFIND's Find results
# window has no blank-cell branch for `w` — CFindNav_FillResultRow hands the
# value straight to FileTimeToLocalFileTime — so a node with no timestamp shows
# as the 1601 epoch there. The beta content drop these fixtures reproduce is
# dated to the kiosk articles in docs/KNOWN-CONTENT.md.
_CONTENT_DROP_DATE = "July 19, 1995"


def _container_content(
    name, type_str="Directory", language=_LCID_EN_US, modified=_CONTENT_DROP_DATE
):
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
        modified=modified,
        size_bytes=0,
        modified_filetime=_date_string_to_wire_filetime(modified),
    )


# The two Worldwide hubs are NOT ordinary nodes — the client pins them to
# GetSpecialMnid(0) and GetSpecialMnid(1) and supplies their display names
# from its own resources.
#
# CMosTreeNode::RememberProperty @ MOSSHELL 0x7F3FBA69, when caching the 'e'
# property, compares the node's mnid against GetSpecialMnid(0) and (1); on a
# match it DISCARDS the server's value and substitutes
# `LoadStringA(hInst, 0x8F - (field_8 == 0))`. Those two STRINGTABLE entries
# are adjacent at MOSSHELL 0x7F41C65A / 0x7F41C684:
#
#   special 0  (1,0,0) → wire "0:0" → id 0x8E → "Worldwide Categories"
#   special 1  (1,1,0) → wire "1:0" → id 0x8F → "Worldwide Member Assistance"
#
# So "0:0" IS the Worldwide Categories hub. Whatever `e` we send for it is
# overwritten client-side. Serving a separate Worldwide Categories node at an
# ordinary mnid produced a duplicate: the address-bar row named "Worldwide
# Categories" is this node, so selecting it listed this node's children.
#
# The HOMEBASE buttons follow from the same pairing — LJUMP takes the hub's
# localized child (docs/MSN_CENTRAL_HOMEBASE_MENU_MAPPING.md):
#   Categories        LJUMP 1:0:0:0 → GetLocalizedNode("0:0") → Categories (US)
#   Member Assistance LJUMP 1:1:0:0 → GetLocalizedNode("1:0") → Member Assistance (US)
_WORLDWIDE_CATEGORIES_KEY, _WORLDWIDE_CATEGORIES_MNID = mnid_key(0, 0)
_WORLDWIDE_MEMBER_ASSISTANCE_KEY, _WORLDWIDE_MEMBER_ASSISTANCE_MNID = mnid_key(1, 0)
# HOMEBASE MSN Today button — LJUMP 1:4:0:0. GetSpecialMnid(idx=4) gives
# `(field_0=1, field_8=4, field_c=0)`, wire "4:0".
_MSN_TODAY_KEY, _MSN_TODAY_SPECIAL_MNID = mnid_key(4, 0)
# Localized wrapper mnids. The wire key `"f8:f_c"` on the server maps to the
# client's `(field_0=1 inherited, field_8, field_c)`.
_CATEGORIES_US_KEY, _CATEGORIES_US_MNID = mnid_key(1, 0x10)
_MEMBER_ASSISTANCE_US_KEY, _MEMBER_ASSISTANCE_US_MNID = mnid_key(1, 0x11)
_CATEGORIES_BR_KEY, _CATEGORIES_BR_MNID = mnid_key(1, 0x13)
_MEMBER_ASSISTANCE_BR_KEY, _MEMBER_ASSISTANCE_BR_MNID = mnid_key(1, 0x14)

ROOT_CONTENT = _container_content("Root")

# Localized wrappers. `language=0` on the Worldwide hubs marks them as
# locale-neutral so a `filter_on=1` request with any LCID still accepts them.
CATEGORIES_US_CONTENT = _container_content("Categories (US)", language=_LCID_EN_US)
MEMBER_ASSISTANCE_US_CONTENT = _container_content("Member Assistance (US)", language=_LCID_EN_US)
CATEGORIES_BR_CONTENT = _container_content("Categorias (BR)", language=_LCID_PT_BR)
MEMBER_ASSISTANCE_BR_CONTENT = _container_content(
    "Assistencia ao Associado (BR)", language=_LCID_PT_BR
)
# Both names are cosmetic — RememberProperty replaces them with STRINGTABLE
# 0x8E / 0x8F. Kept matching the resource text so server logs read the same as
# the client UI.
WORLDWIDE_CATEGORIES_CONTENT = _container_content("Worldwide Categories", language=0)
WORLDWIDE_MEMBER_ASSISTANCE_CONTENT = _container_content("Worldwide Member Assistance", language=0)


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
    # Development-only category exposing compiled Media View titles.
    # MEDVIEW maps each leaf deid to its compiled M14 sample.
    (0x10E, "Media View samples", "Category"),
)


# Children of "Media View samples" — one MOSVIEW leaf per `.m14` fixture. The
# f0 value is the MOSVIEW deid (formatted `%X` by MOSVIEW's deid
# normalization, see docs/MOSVIEW.md §3.3). f8=0 keeps deid_hi clear so
# MCM picks the single-word `%X` path instead of `%X%8X`.
MEDVIEW_SAMPLE_LEAF_DEFS = (
    (0x1000, "Employee Handbook Example", 472917),
    (0x1001, "France Magazine", 972835),
    (0x1002, "MediaView Online Documentation", 3584999),
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
    key, mnid = mnid_key(f0, f8)
    return DirectoryNode(
        node_id=key,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=mnid,
        content=_container_content(name, type_str=type_str, language=language),
    )


def _medview_sample_leaf(f0, name, size_bytes):
    """MOSVIEW leaf backed by an `.m14` fixture under `resources/titles/`.

    deid_hi=0 keeps MOSVIEW on the single-word `%X` deid normalization
    path, so f0=0x1000 → cmdline `-MOS:6:1000:0:w` → titleToken
    `:2[1000]0` → server resolves `resources/titles/HANDBOOK.M14`.
    """
    key, mnid = mnid_key(f0, 0)
    return DirectoryNode(
        node_id=key,
        is_container=False,
        app_id=APP_MEDIA_VIEWER,
        mnid_a=mnid,
        content=NodeContent(
            name=name,
            go_word="",
            category="Media View samples",
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
            modified=_CONTENT_DROP_DATE,
            size_bytes=size_bytes,
            modified_filetime=_date_string_to_wire_filetime(_CONTENT_DROP_DATE),
        ),
    )


_MEDVIEW_SAMPLES_KEY = f"1:{0x10E}"

# A Download-and-Run leaf whose payload the server generates, so a transfer can
# be checked without the client's compressor in the way. The body is plain text
# served with compression code 0, which makes FTMAPI skip HrMos2DecompFile and
# write the bytes straight to disk — so the downloaded file is comparable to
# DNR_TEST_PAYLOAD byte for byte.
#
# Every line is fixed width and carries its own offset, so a diff names the
# exact byte where a transfer went wrong instead of leaving it to be inferred.
DNR_TEST_LINE_COUNT = 4096


def _build_dnr_test_payload():
    lines = [
        f"line {n:06d} offset {n * 48:08d} {'.' * 9}{(n % 10)}{'.' * 8}\r\n".encode("ascii")
        for n in range(DNR_TEST_LINE_COUNT)
    ]
    assert all(len(line) == 48 for line in lines), "payload lines must be fixed width"
    return b"".join(lines)


DNR_TEST_PAYLOAD = _build_dnr_test_payload()
DNR_TEST_SHABBY_ID = 0x00FF0001
DNR_TEST_FILE_NAME = "dnrtest.txt"

_DNR_TEST_KEY, _DNR_TEST_MNID = mnid_key(1, 0x111)
_DNR_TEST_NODE = DirectoryNode(
    node_id=_DNR_TEST_KEY,
    is_container=False,
    app_id=APP_DOWNLOAD_AND_RUN,
    mnid_a=_DNR_TEST_MNID,
    content=replace(
        _container_content("DnR Transfer Test", type_str="Download-and-Run File"),
        dnr_shabby_id=DNR_TEST_SHABBY_ID,
        dnr_file_name=DNR_TEST_FILE_NAME,
        dnr_compression=0,
        size_bytes=len(DNR_TEST_PAYLOAD),
    ),
)

# The same test, one step further along: a real MOS2 container captured from a
# DLRed upload of WINDIFF.EXE, so the compressed path can be exercised without
# re-uploading it every time. Declares 107520 uncompressed bytes in four
# 32768-byte chunks, compressed to 51700.
DNR_MOS2_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "dnr" / "windiff.mos2"
DNR_MOS2_SHABBY_ID = 0x00FF0002
DNR_MOS2_FILE_NAME = "WINDIFF.EXE"
DNR_MOS2_COMPRESSED_SIZE = 51700

_DNR_MOS2_KEY, _DNR_MOS2_MNID = mnid_key(1, 0x112)
_DNR_MOS2_NODE = DirectoryNode(
    node_id=_DNR_MOS2_KEY,
    is_container=False,
    app_id=APP_DOWNLOAD_AND_RUN,
    mnid_a=_DNR_MOS2_MNID,
    content=replace(
        _container_content("DnR Compressed Test", type_str="Download-and-Run File"),
        dnr_shabby_id=DNR_MOS2_SHABBY_ID,
        dnr_file_name=DNR_MOS2_FILE_NAME,
        dnr_compression=3,
        size_bytes=DNR_MOS2_COMPRESSED_SIZE,
    ),
)

# A second captured container, kept because its first chunk decodes wrong
# while WINDIFF's does not. HrMos2DecompFile reuses one output buffer across
# chunks and resolves an over-long back-reference by wrapping into that
# buffer's tail (FTMAPI 0x7F6B609B), so chunk 0 reads uninitialised heap and
# later chunks read the previous chunk's output. That predicts this payload's
# result varies between runs while WINDIFF's does not.
DNR_MOS2B_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "dnr" / "cdplayer.mos2"
DNR_MOS2B_SHABBY_ID = 0x00FF0003
DNR_MOS2B_FILE_NAME = "CDPLAYER.EXE"
DNR_MOS2B_COMPRESSED_SIZE = 40748

_DNR_MOS2B_KEY, _DNR_MOS2B_MNID = mnid_key(1, 0x113)
_DNR_MOS2B_NODE = DirectoryNode(
    node_id=_DNR_MOS2B_KEY,
    is_container=False,
    app_id=APP_DOWNLOAD_AND_RUN,
    mnid_a=_DNR_MOS2B_MNID,
    content=replace(
        _container_content("DnR Compressed Test B", type_str="Download-and-Run File"),
        dnr_shabby_id=DNR_MOS2B_SHABBY_ID,
        dnr_file_name=DNR_MOS2B_FILE_NAME,
        dnr_compression=3,
        size_bytes=DNR_MOS2B_COMPRESSED_SIZE,
    ),
)

# The same WINDIFF.EXE, but with the container built here by
# tools/mos2_compress.py instead of by the client. HrMos2CompFile on the VM
# emits streams that do not decode back to their input (docs/MOSSHELL.md
# 7.4.6); a MOS2 chunk is plain raw DEFLATE behind a "CK" marker, so a correct
# one can be produced server-side. Downloading this should yield a byte-exact
# WINDIFF.EXE that runs.
DNR_MOS2OK_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "data" / "dnr" / "windiff_ok.mos2"
)
DNR_MOS2OK_SHABBY_ID = 0x00FF0004
DNR_MOS2OK_FILE_NAME = "WINDIFF.EXE"
DNR_MOS2OK_COMPRESSED_SIZE = 51759

_DNR_MOS2OK_KEY, _DNR_MOS2OK_MNID = mnid_key(1, 0x114)
_DNR_MOS2OK_NODE = DirectoryNode(
    node_id=_DNR_MOS2OK_KEY,
    is_container=False,
    app_id=APP_DOWNLOAD_AND_RUN,
    mnid_a=_DNR_MOS2OK_MNID,
    content=replace(
        _container_content("DnR Server-Compressed", type_str="Download-and-Run File"),
        dnr_shabby_id=DNR_MOS2OK_SHABBY_ID,
        dnr_file_name=DNR_MOS2OK_FILE_NAME,
        dnr_compression=3,
        size_bytes=DNR_MOS2OK_COMPRESSED_SIZE,
    ),
)

_DEFAULT_CHAT_KEY, _DEFAULT_CHAT_MNID = mnid_key(1, 0x10F)
_DEFAULT_CHAT_ROOM = DirectoryNode(
    node_id=_DEFAULT_CHAT_KEY,
    is_container=False,
    app_id=APP_TEXT_CONFERENCE,
    mnid_a=_DEFAULT_CHAT_MNID,
    content=replace(
        _container_content("MSN Chat", type_str="Chat Room"),
        conference=ConferenceFields(
            room_capacity=10,
            message_length=1000,
            join_as_participants=True,
        ),
    ),
    host_usernames=("billg",),
)


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
# The tree under a board is FLAT — every message, reply included, is a direct
# child of the board. Threading is carried by `_P` alone:
# CBbsNavTreeNode_GetThreadParent (0x7F5F1C3E) copies the node's own mnid and
# overwrites field_8 with `_P`, so a parent and its reply are siblings sharing
# field_c. The reader enumerates the board once — one FUN_7F5F2E6C ingest call
# per child — and never asks a message for children, so a reply nested under
# its parent never reaches the list at all. The f0=2 namespace keeps BBS mnids
# from colliding with DIRSRV's f0=1; all BBS nodes are language=0
# (locale-neutral) so they survive a filter_on=1 GetChildren.
# Mirrors reference/screenshots/bbs.png.

# Yosemite conversation body, transcribed from bbs.png.
_YOSEMITE_BODY = (
    "In case anyone is thinking of a trip to Yosemite, prepare for water. "
    "I just got back from a wet trip that allowed me to see the best "
    "waterfall display in over a decade, but I didn't get to climb.\n\n"
    "It was a bit frustrating to gaze up to those incredible cliffs and not "
    "be able to climb. The constant rain kept the rock wet. If it stopped "
    "raining, the saturated mountains kept the water seeping from the cracks. "
    'Most major cracks have turned into "spring of \'95" springs feeding the '
    "Merced River.\n\n"
    "We actually climbed two pitches, dodging the wet spots on the rock "
    "before it started to rain again."
)


# "Sports, Health and Fitness" (CATEGORY_DEFS f8 0x10A) hosts the board.
_SPORTS_HEALTH_FITNESS_KEY = f"1:{0x10A}"

# BBS mnid layout, pinned by two bbsnav functions that must agree:
#   field_8 = message id, 0 on the board itself
#   field_c = board id
#   `_P`    = parent message id (goes into field_8), 0 on a conversation head
# `CBbsNavTreeNode_GetParent` (0x7F5F12CE) zeroes field_8 to reach the board, and
# `CBbsNavTreeNode_GetThreadParent` (0x7F5F1C3E) swaps `_P` into field_8 to reach
# the parent post — which also makes field_8 == 0 mean "no thread parent",
# correct for a board. `mnid_key(f0, f8)` puts its first argument in the
# client's field_8 and its second in field_c, so the message id comes first here.
# Getting this backwards makes GetParent return the message itself and the reader
# fails with "Cannot open message" before any wire traffic.
_BBS_BOARD_ID = 0x1

_CLIMBING_BBS = bbs_node(
    0,
    _BBS_BOARD_ID,
    "Climbing BBS",
    is_container=True,
    has_children=True,
    delegate=True,
    # The board is a DIRSRV row, so it needs a `w` like any other directory
    # entry — Find has no blank-cell branch. Dated to its newest message.
    date="May 18, 1995 9:41 AM",
)
# Authors and the Yosemite timestamp are transcribed from
# reference/screenshots/bbs.png (list pane + reader header "Date: 10:12 AM
# Tuesday, May 16, 1995"). The other two timestamps are NOT in the screenshot —
# they are invented, ordered so the reply follows its parent.
_BBS_YOSEMITE = bbs_node(
    0x100,
    _BBS_BOARD_ID,
    "Yosemite",
    is_container=False,
    author="Chris Hahn",
    date="May 16, 1995 10:12 AM",
    body=_YOSEMITE_BODY,
)
_BBS_BRITISH_CLIMBERS = bbs_node(
    0x101,
    _BBS_BOARD_ID,
    "British Climbers",
    is_container=False,
    author="KEITH SUTTON",
    date="May 15, 1995 8:22 AM",
)
_BBS_RE_YOSEMITE = bbs_node(
    0x200,
    _BBS_BOARD_ID,
    "RE: Yosemite",
    is_container=False,
    author="Chris Shannon",
    date="May 17, 1995 3:45 PM",
    parent_subid=0x100,
)

# A message carrying one attachment, captured verbatim from the Compose window
# on 2026-07-28. Both files are the client's own upload bytes:
#
#   attachment-post.rtfcomp  the body as X-MOS-Format "RTFCOMP" names it —
#       MAPI compressed RTF (`LZFu`, 1282 compressed / 6717 raw), carrying
#       `{\object\objemb{\*\objclass MOSAF}...{\*\objdata ...}}`. The objdata
#       is an OLE1 embedded-object header wrapping a 3072-byte compound file
#       whose root CLSID is {00028B50-0000-0000-C000-000000000046} — MOSAF.DLL,
#       "Mos Attached File". Its CONTENTS stream reads version 2, kind 1,
#       file_size 175, state 3, name "BIGBUT.BMP", and that name is what the
#       reader draws under the icon.
#   attachment-post.mos2     the file segment that followed the body, 175 bytes
#       of `MOS2` container — the client compresses an attachment through
#       MCM `HrMos2CompFile` before uploading it, so this is not raw BMP.
#
# Authored bytes cannot stand in for either one: the compressed RTF carries the
# object's persisted storage, and nothing here builds a docfile.
_BBS_ATTACHMENT_DIR = pathlib.Path(__file__).resolve().parents[3] / "resources" / "bbs"

_BBS_ATTACHMENT = bbs_node(
    0x201,
    _BBS_BOARD_ID,
    "Attachment test",
    is_container=False,
    author="Chris Hahn",
    date="May 18, 1995 9:03 AM",
    body_raw=(_BBS_ATTACHMENT_DIR / "attachment-post.rtfcomp").read_bytes(),
    body_format="RTFCOMP",
    # X-MOS-Size on the upload: the body length, which for a compressed body is
    # the stream length rather than any plain-text count.
    size_bytes=1286,
    attachment_count=1,
    attachment_data=(_BBS_ATTACHMENT_DIR / "attachment-post.mos2").read_bytes(),
)

_BBS_PRICED_ATTACHMENT = bbs_node(
    0x203,
    _BBS_BOARD_ID,
    "Priced attachment test",
    is_container=False,
    author="Chris Hahn",
    date="May 18, 1995 9:04 AM",
    body_raw=(_BBS_ATTACHMENT_DIR / "attachment-post.rtfcomp").read_bytes(),
    body_format="RTFCOMP",
    size_bytes=1286,
    attachment_count=1,
    attachment_data=(_BBS_ATTACHMENT_DIR / "attachment-post.mos2").read_bytes(),
)
(_BBS_PRICED_ATTACHMENT_FILE,) = build_bbs_attachment_nodes(_BBS_PRICED_ATTACHMENT)
_BBS_PRICED_ATTACHMENT_FILE = replace(
    _BBS_PRICED_ATTACHMENT_FILE,
    content=replace(
        _BBS_PRICED_ATTACHMENT_FILE.content,
        # `z`: amount in the high 24 bits, currency-table index in the low byte.
        price_dword=(250 << 8) | 3,
    ),
)

BBS_NODES = [
    _CLIMBING_BBS,
    _BBS_YOSEMITE,
    _BBS_BRITISH_CLIMBERS,
    _BBS_RE_YOSEMITE,
    _BBS_ATTACHMENT,
    # (0x202, board) — the mnid FUN_7F5FC919 builds for the one MOSAF object in
    # the body above. Off the board's child list: it is a file, not a message.
    *build_bbs_attachment_nodes(_BBS_ATTACHMENT),
    _BBS_PRICED_ATTACHMENT,
    _BBS_PRICED_ATTACHMENT_FILE,
]


DIRECTORY_NODES = [
    # Worldwide Categories hub (wire "0:0") — client's GetSpecialMnid(idx=0),
    # named from STRINGTABLE 0x8E regardless of the `e` we send. LJUMP 1:0:0:0
    # (Categories button) runs GetLocalizedNode here and takes the first
    # locale-matching child, so the children list holds only the localized
    # Categories wrappers.
    DirectoryNode(
        node_id=_WORLDWIDE_CATEGORIES_KEY,
        is_container=True,
        app_id=APP_DIRECTORY_SERVICE,
        mnid_a=_WORLDWIDE_CATEGORIES_MNID,
        content=WORLDWIDE_CATEGORIES_CONTENT,
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
    # Localized Categories / Member Assistance wrappers. Each hub holds only
    # its own locale set.
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
    *[
        _medview_sample_leaf(f0, name, size_bytes)
        for f0, name, size_bytes in MEDVIEW_SAMPLE_LEAF_DEFS
    ],
    _DEFAULT_CHAT_ROOM,
    _DNR_TEST_NODE,
    _DNR_MOS2_NODE,
    _DNR_MOS2B_NODE,
    _DNR_MOS2OK_NODE,
    *BBS_NODES,
]


# Each Worldwide hub holds exactly its own locale set — nothing else. The hub
# serves two roles at once, and both are satisfied by that list:
#   - browsing the hub (the address-bar row named from STRINGTABLE 0x8E / 0x8F)
#     shows every localized variant;
#   - LJUMP's GetLocalizedNode picks the first child surviving the filter_on=1
#     locale pass — en-US takes the (US) wrapper, pt-BR drops it and takes (BR).
# Locale order therefore matters: US first, BR second.
_ARTS_AND_ENTERTAINMENT_KEY = f"1:{0x100}"
_ARTES_E_ENTRETENIMENTO_KEY = f"1:{0x180}"
DIRECTORY_CHILDREN = {
    # Worldwide Categories hub — LJUMP 1:0:0:0 target.
    _WORLDWIDE_CATEGORIES_KEY: [
        _CATEGORIES_US_KEY,
        _CATEGORIES_BR_KEY,
    ],
    # Worldwide Member Assistance hub — LJUMP 1:1:0:0 target.
    _WORLDWIDE_MEMBER_ASSISTANCE_KEY: [
        _MEMBER_ASSISTANCE_US_KEY,
        _MEMBER_ASSISTANCE_BR_KEY,
    ],
    _CATEGORIES_US_KEY: [
        *[f"1:{f8}" for f8, _, _ in CATEGORY_DEFS],
        _DEFAULT_CHAT_ROOM.node_id,
    ],
    _MEMBER_ASSISTANCE_US_KEY: [
        f"1:{0x300}",  # The MSN Member Lobby
        f"1:{0x301}",  # MSN Beta Center
        "4:0",  # MSN Today — reuse existing MOSVIEW leaf
        f"1:{0x303}",  # Member Assistance Kiosk - July 19
        f"1:{0x304}",  # First-Time-User Experience
        f"1:{0x305}",  # Member Guidelines (MOSVIEW)
        f"1:{0x306}",  # MSN Beta News Flash - July 19
        f"1:{0x307}",  # Member Guidelines (document?)
        f"1:{0x308}",  # Member Agreement (document?)
    ],
    _CATEGORIES_BR_KEY: [f"1:{f8}" for f8, _, _ in CATEGORY_BR_DEFS],
    _MEMBER_ASSISTANCE_BR_KEY: [f"1:{f8}" for f8, _ in MEMBER_ASSISTANCE_BR_LEAF_DEFS],
    _ARTS_AND_ENTERTAINMENT_KEY: [f"1:{f8}" for f8, _ in A_AND_E_CHILD_DEFS],
    _ARTES_E_ENTRETENIMENTO_KEY: [f"1:{f8}" for f8, _ in A_AND_E_BR_CHILD_DEFS],
    _MEDVIEW_SAMPLES_KEY: [
        *[f"{f0}:0" for f0, _name, _size in MEDVIEW_SAMPLE_LEAF_DEFS],
        _DNR_TEST_NODE.node_id,
        _DNR_MOS2_NODE.node_id,
        _DNR_MOS2B_NODE.node_id,
        _DNR_MOS2OK_NODE.node_id,
    ],
    _DNR_TEST_NODE.node_id: [],
    _DNR_MOS2_NODE.node_id: [],
    _DNR_MOS2B_NODE.node_id: [],
    _DNR_MOS2OK_NODE.node_id: [],
    # BBS board "Climbing BBS" listed under "Sports, Health and Fitness"
    # (c=2 = APP_BBS_SERVICE, b bit 0x04 = delegate). Opening it hands the
    # folder to bbsnav, which enumerates the thread list over svc "BBS".
    # Threading is the tree itself — replies are children of the message they
    # answer, so recursive GetChildren yields the indented thread view.
    _SPORTS_HEALTH_FITNESS_KEY: [_CLIMBING_BBS.node_id],
    # Every message is a direct child of the board, replies included. The
    # reader enumerates the board once and never asks a message for children,
    # so a reply nested under its parent is simply never seen. Order places a
    # reply after the message it answers.
    _CLIMBING_BBS.node_id: [
        _BBS_YOSEMITE.node_id,
        _BBS_RE_YOSEMITE.node_id,
        _BBS_BRITISH_CLIMBERS.node_id,
        _BBS_ATTACHMENT.node_id,
        _BBS_PRICED_ATTACHMENT.node_id,
    ],
    # Explicit and empty: ContentStore.get_children answers an unlisted node
    # with the fallback sentinel, which would inject a bogus row.
    _BBS_YOSEMITE.node_id: [],
    _BBS_RE_YOSEMITE.node_id: [],
    _BBS_BRITISH_CLIMBERS.node_id: [],
    _BBS_ATTACHMENT.node_id: [],
    _BBS_PRICED_ATTACHMENT.node_id: [],
    # Explicit empty children for the `4:0` startup node — avoids the
    # sentinel fallback path that previously introduced `FFFFFFFF:FFFFFFFF`
    # into the rendered hierarchy. Favorite Places (`3:1`) is client-side.
    "4:0": [],
    "3:1": [],
    _DEFAULT_CHAT_ROOM.node_id: [],
    # Every remaining category/A&E/MA leaf is terminal — explicit empty list
    # keeps the fallback sentinel out of their listviews. 0x100 (Arts and
    # Entertainment), 0x10A (Sports, Health and Fitness → Climbing BBS) and
    # 0x10E (Media View samples) are skipped because they have their own subtrees
    # wired above.
    **{f"1:{f8}": [] for f8, _, _ in CATEGORY_DEFS if f8 not in (0x100, 0x10A, 0x10E)},
    **{f"1:{f8}": [] for f8, _ in A_AND_E_CHILD_DEFS},
    **{f"1:{f8}": [] for f8, _ in MEMBER_ASSISTANCE_LEAF_DEFS},
    **{f"1:{f8}": [] for f8, _, _ in CATEGORY_BR_DEFS if f8 != 0x180},
    **{f"1:{f8}": [] for f8, _ in MEMBER_ASSISTANCE_BR_LEAF_DEFS},
    **{f"1:{f8}": [] for f8, _ in A_AND_E_BR_CHILD_DEFS},
    **{f"{f0}:0": [] for f0, _name, _size in MEDVIEW_SAMPLE_LEAF_DEFS},
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


# The accounts that can sign in. `username`/`password` are what the Sign In
# dialog collects; `display_name` is what the rest of MSN shows, and doubles as
# the Member Properties key (see MEMBER_PROFILES below). Every per-member reply
# — billing, statement, subscriptions, authoring rights, SASRV tokens — reads
# off the record the login resolved.
#
# Passwords sit here in the clear. Nothing in this reconstruction protects an
# account: the value only has to match what the client sends.

_BILLG_TRANSACTIONS = (
    # Period 0 — April 2026 (current statement, $19.04 balance).
    (
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
    ),
    # Period 1 — March 2026.
    (
        TransactionRecord(datetime.datetime(2026, 3, 1, 8, 30), "Monthly subscription", 495, 495),
        TransactionRecord(
            datetime.datetime(2026, 3, 14, 21, 5), "Premium content access", 149, 644
        ),
        TransactionRecord(datetime.datetime(2026, 3, 28, 23, 50), "Online statement fee", 250, 894),
    ),
    # Period 2 — February 2026.
    (
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
    ),
    # Period 3 — January 2026.
    (
        TransactionRecord(datetime.datetime(2026, 1, 1, 10, 0), "Monthly subscription", 495, 495),
        TransactionRecord(
            datetime.datetime(2026, 1, 19, 19, 17), "Premium content access", 149, 644
        ),
        TransactionRecord(datetime.datetime(2026, 1, 31, 23, 59), "Online statement fee", 250, 894),
    ),
)


_SJOBS_TRANSACTIONS = (
    # Period 0 — April 2026 (current statement, $7.94 balance).
    (
        TransactionRecord(datetime.datetime(2026, 4, 1, 6, 5), "Monthly subscription", 495, 495),
        TransactionRecord(datetime.datetime(2026, 4, 8, 20, 18), "Chat room usage", 50, 545),
        TransactionRecord(datetime.datetime(2026, 4, 16, 21, 40), "Online statement fee", 249, 794),
    ),
    # Period 1 — March 2026.
    (
        TransactionRecord(datetime.datetime(2026, 3, 1, 6, 12), "Monthly subscription", 495, 495),
        TransactionRecord(datetime.datetime(2026, 3, 22, 19, 3), "Chat room usage", 25, 520),
    ),
)


BILL_GATES = User(
    username="billg",
    password="msn@96",
    display_name="Bill Gates",
    # Full authoring: File > New/Delete/Unlink on every node, plus the TREEEDCL
    # write channel and the Security page's whole token list.
    rights=RIGHTS_AUTHORING,
    sa_tokens=(1, 2, 3),
    billing=BillingProfile(
        first_name="Bill",
        last_name="Gates",
        country_id=1,  # US
        address="1 Microsoft Way",
        city="Redmond",
        state="WA",
        zip="98052",
        phone="425-882-8080",
        payment_type=1,  # CHARGE
        card_number="411111******1111",
    ),
    statement=StatementSummary(
        balance_cents=1904,  # formatted as "$19.04"
        currency_iso=840,  # USD
        year=2026,
        month=4,
        day=1,
        free_connect_minutes=90,  # rendered as "01:30"
        expires_date=datetime.date(2026, 12, 31),
        effective_date=datetime.date(2026, 5, 1),
    ),
    transactions=_BILLG_TRANSACTIONS,
    subscriptions=(
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
    ),
)


STEVE_JOBS = User(
    username="sjobs",
    password="whatsnext",
    display_name="Steve Jobs",
    # A plain subscriber: browses and posts, authors nothing. No token grant, so
    # the Security page has no list to show.
    rights=RIGHTS_NONE,
    sa_tokens=(),
    billing=BillingProfile(
        first_name="Steve",
        last_name="Jobs",
        country_id=1,  # US
        address="1 Infinite Loop",
        city="Cupertino",
        state="CA",
        zip="95014",
        phone="408-996-1010",
        payment_type=2,  # DEBIT
        card_number="555555******4444",
    ),
    statement=StatementSummary(
        balance_cents=794,  # formatted as "$7.94"
        currency_iso=840,  # USD
        year=2026,
        month=4,
        day=16,
        free_connect_minutes=180,  # rendered as "03:00"
        expires_date=datetime.date(2027, 3, 31),
        effective_date=datetime.date(2026, 6, 1),
    ),
    transactions=_SJOBS_TRANSACTIONS,
    subscriptions=(
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
            name="MSN Bookshelf",
            detail="Reference library access",
            price_minor=99,
            price_currency=840,
            record_currency=840,
        ),
    ),
)


USERS = [BILL_GATES, STEVE_JOBS]


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


# Member Properties fixtures, keyed by the string BBSNAV hands MOSABP32.
#
# `FUN_7F604316` (the id-0x5B0 "Member Properties..." handler) reads the reader
# window's From box (control 0x3E9), cuts at '@', rejects anything whose domain
# is not "msn.com", and passes the local part to `HrUserDetailsDlg`. The From
# header this server writes carries `BbsFields.author` verbatim, so the lookup
# key is the author string as authored — not a separate account name.
#
# The signed-in accounts appear here too, under their `display_name`, so a
# member who opens Properties on their own post gets a filled sheet.
#
# Details are invented. reference/screenshots/bbs.png shows the three authors in
# the list pane and nothing about them, and no MSN member directory survives.
MEMBER_PROFILES = [
    MemberProfile(
        member_id=BILL_GATES.display_name,
        display_name=BILL_GATES.display_name,
        first_name="Bill",
        last_name="Gates",
        city="Redmond",
        state="WA",
        country_code=1,
        birth_date="October 28, 1955",
        sex="Male",
        marital_status_code=2,
        language_code=_LCID_EN_US,
        interests="Bridge, reading, golf",
        job_description="Chairman and CEO",
        company_name="Microsoft Corporation",
        work_city="Redmond",
        work_state="WA",
        work_country_code=1,
    ),
    MemberProfile(
        member_id=STEVE_JOBS.display_name,
        display_name=STEVE_JOBS.display_name,
        first_name="Steve",
        last_name="Jobs",
        city="Palo Alto",
        state="CA",
        country_code=1,
        birth_date="February 24, 1955",
        sex="Male",
        marital_status_code=2,
        language_code=_LCID_EN_US,
        interests="Calligraphy, industrial design, Bob Dylan",
        job_description="Chairman and CEO",
        company_name="NeXT Computer",
        work_city="Redwood City",
        work_state="CA",
        work_country_code=1,
    ),
    MemberProfile(
        member_id="Chris Hahn",
        display_name="Chris Hahn",
        first_name="Chris",
        last_name="Hahn",
        city="Seattle",
        state="WA",
        country_code=1,
        birth_date="March 4, 1968",
        sex="Male",
        marital_status_code=2,
        language_code=_LCID_EN_US,
        interests="Climbing, backcountry skiing, photography",
        job_description="Structural engineer",
        company_name="Cascade Engineering",
        work_city="Bellevue",
        work_state="WA",
        work_country_code=1,
    ),
    MemberProfile(
        member_id="KEITH SUTTON",
        display_name="KEITH SUTTON",
        first_name="Keith",
        last_name="Sutton",
        city="Sheffield",
        state="South Yorkshire",
        country_code=44,
        birth_date="November 19, 1961",
        sex="Male",
        marital_status_code=2,
        language_code=0x0809,
        interests="Gritstone, trad climbing, hillwalking",
        job_description="Secondary school teacher",
        work_city="Sheffield",
        work_state="South Yorkshire",
        work_country_code=44,
    ),
    MemberProfile(
        member_id="Chris Shannon",
        display_name="Chris Shannon",
        first_name="Chris",
        last_name="Shannon",
        city="Fresno",
        state="CA",
        country_code=1,
        birth_date="July 30, 1972",
        sex="Female",
        marital_status_code=1,
        language_code=_LCID_EN_US,
        interests="Big wall climbing, trail running",
        job_description="Park ranger",
        company_name="National Park Service",
        work_city="Yosemite Village",
        work_state="CA",
        work_country_code=1,
    ),
]


@dataclass
class DefaultSeed:
    directory_nodes: list
    directory_children: dict
    directory_fallback: DirectoryNode
    users: list
    plans: list
    member_profiles: list


def default_seed():
    """A fresh seed: every container above is copied, never handed out.

    The store mutates what it is given — a post appends to a board's child list
    — so sharing these containers would let one runtime write edit the seed and
    survive a re-seed. The records inside are frozen dataclasses holding only
    immutable fields, so the copy stops at the containers.
    """
    return DefaultSeed(
        directory_nodes=list(DIRECTORY_NODES),
        directory_children={key: list(ids) for key, ids in DIRECTORY_CHILDREN.items()},
        directory_fallback=DIRECTORY_FALLBACK_NODE,
        users=list(USERS),
        plans=list(PLANS),
        member_profiles=list(MEMBER_PROFILES),
    )
