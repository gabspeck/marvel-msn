"""BBS service handler: forum/bulletin-board tree, threaded message nodes.

The BBS read/navigation channel rides the same generic MOS tree infrastructure
as DSNAV — a MOSSHELL `_NtniGroup` wrapping a TREENVCL `CTreeNavClient`, opened
on the service named "BBS" (docs/bbs-service-contract.md §Framing). The wire
request/reply shapes are therefore identical to DIRSRV; only the per-node
property vocabulary differs (`e, _a, p, _D, _P, _t, _F, _I, _f` + base `a/c/b`).
A board/conversation/reply is a `CMosTreeNode` and threading is the tree itself:
a reply is a child of the message it answers, so recursive GetChildren yields
the indented thread list.

Write/edit channel (TREEEDCL `CTreeEditClient`, selectors 0–12) is out of
scope. A Compose first sends `GetTicket` (selector 12) to obtain a capability
ticket; that selector falls into the unhandled bucket here, so a Compose
attempt is logged and left unanswered rather than crashing or being misrouted.
"""

import datetime
import logging
import struct

from ..config import BBS_INTERFACE_GUIDS, TAG_DYNAMIC_COMPLETE_SIGNAL, TAG_END_STATIC
from ..models import VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    decode_dirsrv_request,
    parse_request_params,
)
from ..store import app_store as _default_store
from ..store.base import BbsFields
from . import dirsrv
from ._dispatch import log_unhandled_selector

# A request's `msg_class` is the *interface* — the selector we handed that IID in
# the discovery table — and `selector` is the method index within it. Class 0x03
# is IID 00028B27, the CTreeNavClient read channel; class 0x0B is IID 00028B2F,
# the message-content channel the reader negotiates when a message is opened
# (BBSNAV FUN_7F5FCD1A). Dispatching on `selector` alone misroutes class-0x0B
# method 0 into GetProperties, which answers it with a meaningless record.
BBS_CLASS_TREE = 0x03
BBS_CLASS_MESSAGE = 0x0B

# BBS read-channel selectors — identical numbering to DIRSRV (the generic
# TREENVCL tree, docs/bbs-service-contract.md §"Read selectors").
BBS_SELECTOR_GET_PROPERTIES = 0x00
BBS_SELECTOR_GET_CHILDREN = 0x02
BBS_SELECTOR_GET_DEID_FROM_GO_WORD = 0x03
BBS_SELECTOR_GET_SHABBY = 0x04

# Message-content channel (class 0x0B) method index. Only one method exists:
# fetch the article for the mnid the reader was opened on.
BBS_SELECTOR_GET_ARTICLE = 0x00

# `X-MOS-Format` values BBSNAV accepts, from the strcmp chain in the body
# renderer `FUN_7F5FC56F` @ 0x7F5FC56F. It reads MAPI property 0x6801001E off
# the message, then:
#   "RTFCOMP" → EM_STREAMIN SF_RTF, stream wrapped by WrapCompressedRTFStream
#               (MAPI32 ordinal 185, behind an ordinal-21 init call)
#   "TEXT"    → EM_STREAMIN SF_TEXT
#   "RTF"     → EM_STREAMIN SF_RTF, stream passed through raw
# Any other value, or a missing header (the property then reads back PT_ERROR,
# type 0x0A), aborts the render with 0x8B0B0049.
#
# We send RTF. SF_TEXT leaves the RichEdit on its own default font, which draws
# the body in Courier New — reference/screenshots/bbs.png shows proportional MS
# Sans Serif, so the font has to come from the stream. RTF is the raw path:
# RTFCOMP would reach the same SF_RTF mode but only after MAPI32 loads and
# `WrapCompressedRTFStream` succeeds, and nothing observed so far says the
# service used compression.
BBS_FORMAT_RTF = "RTF"

# Body font for the generated RTF, matching the reader in
# reference/screenshots/bbs.png. `\fs16` is 8pt — RTF half-points.
_RTF_FONT = "MS Sans Serif"
_RTF_FONT_HALF_POINTS = 16

# Article header → MAPI property map, from the parse table BBSNAV builds at
# 0x7F610A50 (initialiser at 0x7F5FAAEF, names/lengths copied out of the
# (char*, len) array at 0x7F610978) and consumes in `FUN_7F5FB4A9`. A header
# only takes effect when its table entry has the enable dword set; the rest are
# recognised and skipped. Entries relevant here:
#   From:          0x0C1A001E PR_SENDER_NAME   enabled
#   Subject:       0x0037001E PR_SUBJECT       enabled
#   Message-ID:    0x6817001E                  enabled
#   X-MOS-Format:  0x6801001E                  enabled  (drives the renderer)
#   X-MOS-Attach:  0x68020002                  enabled
#   X-MOS-Size:    0x68030003                  enabled
#   Newsgroups:    0x6804001E                  enabled
#   Path:          0x6805001E                  enabled
#   Date:          0x6818001E                  disabled (the column reads `_D`)
# Name matching is `strncmp` against the tabled name *including its trailing
# space*, so every line must read exactly `Name: value` with one space.
_HEADER_SEP = ": "

# BBS property tags (docs/bbs-service-contract.md §"Property tags"). `e` is the
# Subject; `_a` the Author; `_D` a DWORD time_t (MOSSHELL DWORD-as-time_t date
# path keys on the name "_D"); `_P` the parent message's sub-id for threading;
# `_F`/`_I` 2-byte flag words; `_f` advertised with no client read site. `h`
# (icon) is NOT emitted — CBbsNavTreeNode_GetProperty intercepts it and returns
# a client-local glyph id.
PROP_MNID = "a"
PROP_APP_ID = "c"
PROP_BROWSE_FLAGS = "b"
PROP_NAME = "e"
PROP_AUTHOR = "_a"
PROP_SIZE = "p"
PROP_DATE = "_D"
PROP_PARENT_SUBID = "_P"
PROP_TOPIC = "_t"
PROP_HAS_CHILDREN = "_F"
PROP_PRICE_INFO = "_I"
PROP_UNKNOWN_F = "_f"
PROP_LANGUAGE = "q"

# LCID the Properties dialog displays for a BBS post. Distinct from the node's
# `language` field, which stays 0 so the node survives every locale filter in
# ContentStore.get_children — this value is display only, and the sample board
# lives under Categories (US).
BBS_DISPLAY_LCID = 0x0409

# Substituted when a node carries no BbsFields (e.g. the unknown-mnid fallback
# node routed onto the BBS pipe) so property serialisation never AttributeErrors.
_EMPTY_BBS = BbsFields()

log = logging.getLogger(__name__)


class BBSHandler:
    """Handles BBS read-channel requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        """Advertise the generic TREENVCL tree IIDs plus the message channel.

        BBS rides MOSSHELL's tree client, so it resolves the same read-channel
        IIDs as DIRSRV — it is not a self-describing MEDVIEW-style service. It
        needs one extra: 00028B2F, which the reader negotiates on a second
        CreateTnc("BBS", 3) when a message is opened. See BBS_INTERFACE_GUIDS.
        """
        payload = build_discovery_payload(BBS_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch a BBS request by (interface class, method selector).

        Two classes are served: the tree class (0x03) methods 0/2/3/4, and the
        message-content class (0x0B) method 0. Everything else — GetParents (1),
        the unimplemented enum/resolve slots, every TREEEDCL write selector
        (0–12, incl. GetTicket) — is logged unhandled and left unanswered.
        """
        if msg_class == BBS_CLASS_MESSAGE:
            if selector != BBS_SELECTOR_GET_ARTICLE:
                log_unhandled_selector(log, msg_class, selector, request_id, payload)
                return None
            reply_payload = build_bbs_article_reply_payload(payload)
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
        if msg_class != BBS_CLASS_TREE:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        if selector == BBS_SELECTOR_GET_PROPERTIES:
            request = decode_dirsrv_request(payload)
            reply_payload = build_bbs_get_properties_reply_payload(request)
        elif selector == BBS_SELECTOR_GET_CHILDREN:
            request = decode_dirsrv_request(payload)
            reply_payload = build_bbs_get_children_reply_payload(request)
        elif selector == BBS_SELECTOR_GET_DEID_FROM_GO_WORD:
            reply_payload = dirsrv.build_get_deid_from_go_word_reply_payload(payload)
        elif selector == BBS_SELECTOR_GET_SHABBY:
            reply_payload = dirsrv.build_get_shabby_reply_payload(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def build_bbs_props(requested_props, node, *, is_children):
    """Serialise a BBS tree node into (type, name, value) property tuples.

    BBS rides the generic TREENVCL tree but emits its own tag vocabulary
    (docs/bbs-service-contract.md §"Property tags"). `is_children` is accepted
    for signature parity with dirsrv.build_props; BBS tags carry one wire type
    regardless of caller, so it is unused today. Emit only requested tags;
    an unknown requested tag gets a DWORD-0 fallback, mirroring dirsrv.
    """
    content = node.content
    bbs = content.bbs or _EMPTY_BBS

    out = []
    for name in requested_props:
        if name == PROP_MNID:
            out.append((0x0E, name, struct.pack("<I", len(node.mnid_a)) + node.mnid_a))
        elif name == PROP_APP_ID:
            out.append((0x03, name, struct.pack("<I", node.app_id)))
        elif name == PROP_BROWSE_FLAGS:
            # Bit 0x01 CLEAR = container (board/folder), SET = message.
            # This is the conversation test. FUN_7F5F1CAD @ 0x7F5F1CAD sets
            # bit 0 of its out-byte when `(b & 1) == 0`; that byte becomes the
            # ingest flag and lands in the store entry at +0x1C, and
            # FUN_7F5F5DE4 @ 0x7F5F5DE4 increments the conversation counter
            # (ctx+0xC14) only when the bit is CLEAR. Sending b=0 for every BBS
            # node flagged all of them as containers → "0 conversations" and
            # folder glyphs. Confirmed live: ingest hit with flag=0x01 on
            # Yosemite (mnid field_8=0, field_c=0x100).
            leaf = not node.is_container
            out.append((0x01, name, bytes([0x01 if leaf else 0x00])))
        elif name == PROP_NAME:
            # Subject. 0x0A (ASCII cache) like DIRSRV `e`: column 0 and the
            # Properties dialog both read ANSI.
            out.append((0x0A, name, dirsrv._sz(content.name)))
        elif name == PROP_AUTHOR:
            out.append((0x0A, name, dirsrv._sz(bbs.author)))
        elif name == PROP_TOPIC:
            out.append((0x0A, name, dirsrv._sz(bbs.topic)))
        elif name == PROP_SIZE:
            out.append((0x03, name, struct.pack("<I", content.size_bytes & 0xFFFFFFFF)))
        elif name == PROP_DATE:
            # `_D` DWORD time_t, always emitted — 0 when the node has no date.
            # Never skip a requested tag: CServiceProperties::FSet @ 0x7F6418FF
            # only advances the record count on success, so a dropped property
            # also strips every property after it. Omitting `_D` here cost the
            # board its `_F` (the OkToGetChildren gate) and stalled the thread
            # fetch. Verified on the wire 2026-07-27.
            out.append((0x03, name, struct.pack("<I", bbs.date_unix & 0xFFFFFFFF)))
        elif name == PROP_PARENT_SUBID:
            out.append((0x03, name, struct.pack("<I", bbs.parent_subid & 0xFFFFFFFF)))
        elif name == PROP_HAS_CHILDREN:
            # `_F` 2-byte flags. CBbsNavTreeNode::OkToGetChildren @ 0x7F5F1427
            # reads it and tests the HIGH byte against 0x10, i.e. u16 bit
            # 0x1000. Bit SET → child count forced to 0. So the bit means
            # "leaf / no children", the inverse of its old reading here.
            out.append((0x02, name, struct.pack("<H", 0 if bbs.has_children else 0x1000)))
        elif name == PROP_PRICE_INFO:
            # `_I` 2-byte attributes. 0 = free content (no pricing checkbox).
            out.append((0x02, name, struct.pack("<H", 0)))
        elif name == PROP_UNKNOWN_F:
            # `_f` advertised but no BBSNAV read site; safe default DWORD 0.
            out.append((0x03, name, struct.pack("<I", 0)))
        elif name == PROP_LANGUAGE:
            # `q` as a type-0x10 dword array [count][lcid], NOT the 0x04 qword
            # DIRSRV uses. MOSSHELL's value formatter @ 0x7F3FBC12 switches on
            # the cached type: case 0x10 calls GetLocaleInfoA(value[1],
            # LOCALE_SLANGUAGE) and prints a language name, while case 0x04/0x08
            # falls to FUN_7F3FAE1C = wsprintfA("%u:%u", high, low) — which is
            # why the Properties dialog read "Language: 0:0". Both encodings put
            # the LCID at offset +4, so MCM's browse-language reader
            # (*(u32*)(value + 4)) is satisfied either way.
            out.append((0x10, name, struct.pack("<II", 1, BBS_DISPLAY_LCID)))
        else:
            # Anything outside the BBS vocabulary is a shared MOS tree tag, and
            # the Properties dialog fetches those one at a time as {name, 'g'}
            # groups (observed live: `q,g` then `v,g` on a BBS node). Reuse
            # DIRSRV's serialisation so each one gets its established wire type
            # instead of a DWORD-0 stand-in — `q` in particular must be the
            # 8-byte qword form, since a 4-byte value makes the client's
            # `*(u32*)(value + 4)` LCID read run off the end.
            out.extend(dirsrv.build_props([name], node, is_children=is_children))
    return out


def build_bbs_get_properties_reply_payload(request):
    """BBS GetProperties (selector 0x00): one self record for the node.

    Same single-record contract as DIRSRV GetProperties — the reader header
    and Properties dialog feed the first received record into the requesting
    CMosTreeNode, so returning children would corrupt the node's identity.
    """
    requested = _requested_props(request.prop_group)
    node = _default_store.content.get_node(request.node_id)
    log.info(
        "bbs_get_properties node=%s props=%s",
        request.node_id,
        ",".join(requested) or "-",
    )
    records = [(node.node_id, build_bbs_props(requested, node, is_children=False))]
    return dirsrv.build_tree_reply_wire(records)


def build_bbs_get_children_reply_payload(request):
    """BBS GetChildren (selector 0x02): the threaded child list.

    board → conversations, conversation → replies (recursive). `locale_raw` is
    forwarded so a filter_on=1 request still resolves — BBS nodes are
    language=0 (locale-neutral) and survive every locale filter.
    """
    requested = _requested_props(request.prop_group)
    children = _default_store.content.get_children(request.node_id, request.locale_raw)
    log.info(
        "bbs_get_children node=%s props=%s child_count=%d",
        request.node_id,
        ",".join(requested) or "-",
        len(children),
    )
    records = [
        (child.node_id, build_bbs_props(requested, child, is_children=True)) for child in children
    ]
    return dirsrv.build_tree_reply_wire(records)


def _requested_props(prop_group):
    return [p for p in prop_group.split("\x00") if p]


# --- Message-content channel (class 0x0B) ---


def build_bbs_article_reply_payload(payload):
    """Class 0x0B method 0: the opened message as an RFC-1036 news article.

    Request is `04 88 [msg_id:u32][board_id:u32] 83 85` — the 8-byte mnid the
    reader copied into its context at +0xA8, one 0x83 status DWORD to receive,
    and 0x85 marking the request as streaming (appended by MPCCL
    `DispatchBuiltServiceRequest` @ 0x046040D8 when the caller set the stream
    flag through request vtable +0x40).

    Reply is `0x83 [status=0] 0x87 0x86 [article bytes]`.

    The 0x86 tag, not 0x88. MPCCL `ProcessTaggedServiceReply` @ 0x04604F26
    branches on the dynamic tag: 0x86 calls `SignalRequestCompletion`
    (request +0x18 = 1, then SetEvent on +0x24/+0x28/+0x2c), while 0x88 only
    signals the two chunk events and leaves +0x18 clear. The reader's fetch
    thread `FUN_7F5FB15F` @ 0x7F5FB15F drains the stream through request
    vtable +0x14 `WaitIncremental` @ 0x046049BC, which returns 0x0B0B000B when
    +0x18 is set and 0x0B0B000C when it is clear. Only 0x0B0B000B ends the
    loop, so a 0x88 reply parks that thread on the next wait forever and the
    Read Message window stays blank — the hang this selector was leaving
    behind. The tree channel uses 0x88 because its consumer is TREENVCL's node
    iterator, which waits on the +0x2c stream-end event instead.

    A nonzero status DWORD makes the fetch thread bail with 0x8B0B0049 before
    reading a byte, so it is always 0 here; a missing node resolves to the
    store fallback and still ships a well-formed article.
    """
    node_id = _article_request_node_id(payload)
    node = _default_store.content.get_node(node_id)
    article = build_bbs_article(node)
    log.info("bbs_get_article node=%s article_bytes=%d", node_id, len(article))
    return (
        build_tagged_reply_dword(0) + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + article
    )


def _article_request_node_id(payload):
    """Decode the 8-byte mnid from a class-0x0B request into a store key.

    Same `[dword_0][dword_1]` packing as the tree channel's node id, so it
    reuses the `"f8:board"` fixture keys — BBS mnids put the message id in
    field_8 and the board id in field_c.
    """
    send_params, _recv = parse_request_params(payload)
    for p in send_params:
        if isinstance(p, VarParam) and len(p.data) >= 8:
            msg_id, board_id = struct.unpack("<II", p.data[:8])
            return f"{msg_id}:{board_id}"
    return ""


def build_bbs_article(node):
    """Serialise a BBS node as the news article its reader expects.

    `FUN_7F5FB15F` splits the stream at the first pair of adjacent `\\n` bytes:
    everything before goes to the header parser `FUN_7F5FB4A9`, everything
    after is written into an in-memory IStream that becomes the message body.
    Header lines therefore end in a bare LF — with CRLF the two newlines are
    never adjacent, the split never fires, and the whole article is swallowed
    as headers.

    The body is streamed into a RichEdit control by `FUN_7F5FC56F` via
    EM_STREAMIN. It is an RTF document — see BBS_FORMAT_RTF — so its own line
    breaks are RTF `\\par` control words and the raw newlines inside it are
    only source formatting, which RTF readers discard.
    """
    content = node.content
    bbs = content.bbs or _EMPTY_BBS
    body = build_body_rtf(bbs.body).encode("ascii")

    headers = [
        ("Path", "msn"),
        ("From", bbs.author),
        ("Newsgroups", _board_name(node)),
        ("Subject", content.name),
        ("Date", _article_date(bbs.date_unix)),
        ("Message-ID", _message_id(node)),
        ("X-MOS-Format", BBS_FORMAT_RTF),
        # Plain-text length, matching the tree's `p`. Both land on MAPI tag
        # 0x68030003, so a transfer-size value here would disagree with the
        # Size column the list pane already shows.
        ("X-MOS-Size", str(content.size_bytes)),
        ("X-MOS-Attach", "0"),
    ]
    head = "".join(f"{name}{_HEADER_SEP}{value}\n" for name, value in headers)
    return head.encode("ascii", "replace") + b"\n" + body


def build_body_rtf(text):
    """Wrap a plain-text body as an RTF document for EM_STREAMIN `SF_RTF`.

    One font in the table and one `\\par` per source line, so a blank line in
    the text stays a blank paragraph. The document is pure ASCII: anything
    outside it goes out as `\\'hh` cp1252 escapes, which is what an RTF reader
    of this vintage expects after `\\ansi`.

    Deliberately free of embedded objects. `FUN_7F5FC56F` runs two extra passes
    in SF_RTF mode — `FUN_7F5FC7B7` walks EM_GETOLEINTERFACE
    (`IRichEditOle::GetObjectCount`/`GetObject`) collecting objects of one
    CLSID, and `FUN_7F5FC919` resolves each against the tree. Both are no-ops
    at object count 0, which is the shape we ship.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    paragraphs = "\\par\n".join(_rtf_escape(line) for line in lines)
    return (
        "{\\rtf1\\ansi\\ansicpg1252\\deff0"
        f"{{\\fonttbl{{\\f0\\fswiss\\fcharset0 {_RTF_FONT};}}}}"
        f"\\pard\\f0\\fs{_RTF_FONT_HALF_POINTS} "
        f"{paragraphs}\\par\n}}"
    )


def _rtf_escape(text):
    """Escape one line of body text for an RTF stream."""
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ch == "\t":
            out.append("\\tab ")
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            for byte in ch.encode("cp1252", errors="replace"):
                out.append(f"\\'{byte:02x}")
    return "".join(out)


def _board_name(node):
    """Newsgroups value: the name of the board the message hangs under.

    A BBS mnid is `(message id, board id)`, and the board is that same mnid
    with the message id zeroed — the rule `CBbsNavTreeNode::GetParent`
    (0x7F5F12CE) uses. An unresolvable board falls back to the node's own name.
    """
    _msg_id, _sep, board_id = node.node_id.partition(":")
    board = _default_store.content.get_node(f"0:{board_id}")
    return board.content.name or node.content.name


def _message_id(node):
    """`<message.board@bbs.msn.com>` — synthesised from the mnid.

    The client caches it as MAPI 0x6817001E; nothing on the wire round-trips
    it back, so any stable unique form serves.
    """
    msg_id, _sep, board_id = node.node_id.partition(":")
    return f"<{msg_id}.{board_id}@bbs.msn.com>"


def _article_date(date_unix):
    """RFC-1036 date carrying the same wall clock the Date column shows.

    Inverts `_bbs_date_to_unix`: that helper subtracts the host's *current* UTC
    offset rather than the one in force on the post's date, because Windows 95
    applies one timezone rule to every timestamp. Adding the same offset back
    reproduces the wall clock; letting `astimezone` pick the historical offset
    would shift the line off the Date column by an hour.

    BBSNAV's header table has `Date:` disabled, so this line is recognised and
    skipped rather than parsed. It is here for a well-formed article, not
    because a value is read from it.
    """
    if not date_unix:
        return "Thu, 01 Jan 1970 00:00:00 +0000"
    offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
    stamp = datetime.datetime.fromtimestamp(date_unix, datetime.UTC) + offset
    return stamp.strftime("%a, %d %b %Y %H:%M:%S ") + _utc_offset_text(offset)


def _utc_offset_text(offset):
    """`+HHMM` / `-HHMM` for an RFC-1036 date line."""
    total = int(offset.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 3600:02d}{total % 3600 // 60:02d}"
