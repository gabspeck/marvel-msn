"""DIRSRV service handler: directory browsing, property records."""

import logging
import struct

from ..config import (
    DIRSRV_BROWSE_FLAGS_CONTAINER,
    DIRSRV_BROWSE_FLAGS_LEAF,
    DIRSRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ..log import TRACE
from ..models import DirsrvRequest, DwordParam
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
from . import shabby
from ._dispatch import log_unhandled_selector

# DIRSRV wire selectors. Slot indices resolve to IIDs via the discovery table
# advertised in build_discovery_packet. Names mirror TREENVCL.DLL vtable
# methods (IID table 0x7F633270..0x7F6332EC).
DIRSRV_SELECTOR_GET_PROPERTIES = 0x00  # self record (with dword_0=1 override = children)
DIRSRV_SELECTOR_GET_PARENTS = 0x01     # TODO: unhandled; warn when observed
DIRSRV_SELECTOR_GET_CHILDREN = 0x02    # GetRelatives dir=0
# Slot 4 (IID 00028B28) is GetShabby — CTreeNavClient::GetShabby
# (TREENVCL.DLL 0x7f631bab) calls proxy->method_at_offset_0xc(proxy, 4, ...).
DIRSRV_SELECTOR_GET_SHABBY = 0x04

# DIRSRV property names. Use PROTOCOL.md semantics for known props; keep
# unresolved props explicitly UNKNOWN and tentative interpretations as MAYBE.
PROP_MNID = "a"
PROP_BROWSE_FLAGS = "b"
PROP_APP_ID = "c"
PROP_CATEGORY = "ca"
PROP_NAME = "e"
PROP_UNKNOWN_G = "g"
PROP_SECONDARY_ICON = "h"
PROP_UNKNOWN_I = "i"
PROP_DESCRIPTION = "j"
PROP_GO_WORD = "k"
PROP_UNKNOWN_L = "l"
PROP_PRIMARY_ICON = "mf"
PROP_FORUM_MANAGER = "n"
PROP_RATING = "o"
PROP_OWNER = "on"
PROP_MAYBE_SIZE_OR_LEGACY_TITLE = "p"
PROP_LANGUAGE = "q"
PROP_TOPICS = "r"
PROP_PEOPLE = "s"
PROP_PLACE = "t"
PROP_TYPE = "tp"
PROP_MAYBE_HIDDEN_U = "u"
PROP_CREATED = "v"
PROP_LAST_CHANGED = "w"
PROP_SECONDARY_ICON_ALT = "wv"
PROP_EXEC_ARGS = "x"
PROP_VENDOR_ID = "y"
PROP_PRICE = "z"

# Browse-language LCIDs advertised in GetChildren replies with propList=["q"].
# Each value becomes a row in the View > Options > General "Content view"
# combobox after GetLocaleInfoA translates it to a display name. LCIDs missing
# from the Win95 client's national-language tables make GetLocaleInfoA return 0
# (success=FALSE), leaving the caller's 260-byte stack buffer uninitialised —
# so keep the list to locales actually installed in the stock VM.
SUPPORTED_BROWSE_LCIDS = (
    0x0409,  # English (United States)
    0x0416,  # Portuguese (Brazil)
)

log = logging.getLogger(__name__)


class DIRSRVHandler:
    """Handles DIRSRV service requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        """Build the IID->selector discovery block for DIRSRV."""
        payload = build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Handle a DIRSRV request — dispatch by selector.

        Unknown selectors are warned (not silently handled) so the wire log
        surfaces unmapped client paths — e.g. Go-word navigation, which comes
        through as selector 0x03 with the word as UTF-16LE in node_id_raw.
        """
        if selector == DIRSRV_SELECTOR_GET_SHABBY:
            reply_payload = build_get_shabby_reply_payload(payload)
        elif selector in (
            DIRSRV_SELECTOR_GET_PROPERTIES,
            DIRSRV_SELECTOR_GET_CHILDREN,
        ):
            request = decode_dirsrv_request(payload)
            reply_payload = build_dirsrv_reply_payload(request, selector=selector)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def build_property_record(properties):
    """Build a SVCPROP property record.

    Format: [total_size:uint32][prop_count:uint16][properties...]
    Each property: [type:byte][name:NUL-terminated string][value_data]
    """
    body = bytearray()
    for ptype, pname, pvalue in properties:
        body.append(ptype)
        body.extend(pname.encode("ascii") + b"\x00")
        body.extend(pvalue)
    total_size = 6 + len(body)
    header = struct.pack("<IH", total_size, len(properties))
    return header + bytes(body)


def _format_props_for_log(properties):
    """Render (type, name, value_bytes) tuples as `name=<decoded>` pairs.

    Matches the wire types we emit in build_props:
      0x01 byte     -> name=0xNN
      0x03 DWORD    -> name=<decimal>   (icon props flagged 0x%08x)
      0x0A / 0x0B   -> name="..."       (strip flag byte + trailing NUL)
      0x0C FILETIME -> name=<u64>
      0x0E blob     -> name=<hex>
    """
    _ICON_PROPS = {PROP_PRIMARY_ICON, PROP_SECONDARY_ICON, PROP_SECONDARY_ICON_ALT}
    parts = []
    for ptype, pname, pvalue in properties:
        if ptype == 0x01 and len(pvalue) == 1:
            parts.append(f"{pname}=0x{pvalue[0]:02x}")
        elif ptype == 0x03 and len(pvalue) == 4:
            (val,) = struct.unpack("<I", pvalue)
            if pname in _ICON_PROPS:
                parts.append(f"{pname}=0x{val:08x}")
            else:
                parts.append(f"{pname}={val}")
        elif ptype in (0x0A, 0x0B):
            text = _decode_flag_byte_string(pvalue)
            parts.append(f"{pname}={text!r}")
        elif ptype == 0x0C and len(pvalue) == 8:
            (val,) = struct.unpack("<Q", pvalue)
            parts.append(f"{pname}={val}")
        elif ptype == 0x04 and len(pvalue) == 8:
            hdr, lo = struct.unpack("<II", pvalue)
            if pname == PROP_LANGUAGE:
                parts.append(f"{pname}=0x{lo:04x}" + (f"/h=0x{hdr:08x}" if hdr else ""))
            else:
                parts.append(f"{pname}=0x{hdr:08x}:0x{lo:08x}")
        elif ptype == 0x0E:
            parts.append(f"{pname}=<{len(pvalue)}B>{pvalue.hex()}")
        else:
            parts.append(f"{pname}=<0x{ptype:02x}>{pvalue.hex()}")
    return " ".join(parts)


def _decode_flag_byte_string(value):
    """Decode the flag-byte wire body produced by _sz().

    flag & 0x02 = empty; flag & 0x01 = ASCII + NUL; else UTF-16LE + wide NUL.
    """
    if not value:
        return ""
    flag = value[0]
    body = value[1:]
    if flag & 0x02:
        return ""
    if flag & 0x01:
        return body.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return body.split(b"\x00\x00", 1)[0].decode("utf-16le", errors="replace")


def _sz(s):
    """Value body for a type-0x0A or 0x0B string property.

    Wire body is the flag-byte string format shared by 0x0A and 0x0B:
        [flag:1][string_data]
    - flag & 2: empty string, no data follows (1 byte total).
    - flag & 1: ASCII path — [flag][asciiz]; widened to UTF-16 in a temp buf.
    - else:     UTF-16LE path — [flag][utf16le-with-wide-NUL].

    The *type byte* determines where the cache stores it:
    - Type 0x0B keeps the UTF-16 temp buffer (GetProperty returns raw UTF-16).
    - Type 0x0A then runs WideCharToMultiByte, so the cache holds ASCII
      (what PropertySheetA and other ANSI consumers read via GetProperty).
    """
    if not s:
        return b"\x02"
    data = s.encode("ascii", errors="replace")
    return b"\x01" + data + b"\x00"


def build_props(requested_props, node, *, is_children):
    """Serialize `node` into (type, name, value) property tuples.

    Most props have a single canonical wire type regardless of caller; only
    `tp` and `w` switch on `is_children`:
      - is_children=True  → DSNAV details-view / MOSSHELL listview
                            (tp = 0x0A ASCIIZ, w = 0x0C FILETIME)
      - is_children=False → Properties dialog
                            (tp = 0x0B UTF-16, w = 0x0B string)

    Empirical source for the dialog wire types: memory
    `project_dirsrv_dialog_props_investigation` (2026-04-15). `e` is 0x0A for
    all callers — CMosTreeNode::Properties raw-memcpies cache into
    PropertySheetA (ANSI); 0x0B would store UTF-16 and truncate at the first
    wide NUL ("MSN Today" → "M").

    TODO: a GetParents-style caller that arrives with dword_0=1 but a
    dialog-shaped reader on the client side would get listview wire types for
    tp/w and render wrong. No such caller is known today.
    """
    content = node.content

    out = []
    for name in requested_props:
        if name == PROP_MNID:
            out.append((0x0E, PROP_MNID, struct.pack("<I", len(node.mnid_a)) + node.mnid_a))
        elif name == PROP_BROWSE_FLAGS:
            # PROTOCOL.md §SVCPROP-props: bit 0x01 CLEAR = container (Browse),
            # SET = leaf (Exec). ExecuteCommand branches on this bit to choose
            # HrBrowseObject vs CMosTreeNode::Exec.
            flag = (
                node.browse_flags
                if node.browse_flags is not None
                else (DIRSRV_BROWSE_FLAGS_CONTAINER if node.is_container else DIRSRV_BROWSE_FLAGS_LEAF)
            )
            out.append((0x01, PROP_BROWSE_FLAGS, bytes([flag & 0xFF])))
        elif name == PROP_APP_ID:
            out.append((0x03, PROP_APP_ID, struct.pack("<I", node.app_id)))
        elif name == PROP_NAME:
            # Must be 0x0A (ASCII cache). Both the dialog titlebar
            # (PropertySheetA raw memcpy) and the nav icon label expect ANSI.
            # 0x0B would store UTF-16 and truncate at the first wide NUL.
            out.append((0x0A, PROP_NAME, _sz(content.name)))
        elif name == PROP_SECONDARY_ICON:
            # 'h' = shabby_id for the listview per-item icon. MOSSHELL
            # FUN_7f404786 reads it as DWORD → vtable[0x74] GetShabbyToFile →
            # ExtractIconExA (ICO/EXE/DLL bytes, not BMP). Omitting falls
            # back to LVN_GETDISPINFO iImage=0 = forbidden glyph.
            out.append(
                (
                    0x03,
                    PROP_SECONDARY_ICON,
                    struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_ICO, 1)),
                )
            )
        elif name == PROP_EXEC_ARGS:
            out.append((0x0E, PROP_EXEC_ARGS, struct.pack("<I", 1) + b"\x00"))
        elif name == PROP_MAYBE_SIZE_OR_LEGACY_TITLE:
            # `p` = byte count, read inline as DWORD. Feeds MOSSHELL
            # FormatSizeString (listview Size column + Properties dialog Size
            # field — same vtable slot 0x140 either way).
            out.append(
                (
                    0x03,
                    PROP_MAYBE_SIZE_OR_LEGACY_TITLE,
                    struct.pack("<I", content.size_bytes & 0xFFFFFFFF),
                )
            )
        elif name == PROP_UNKNOWN_G:
            # Purpose unresolved — sentinel sweeps ruled out `g` as the icon
            # slot. Emit DWORD 0 as a harmless default.
            out.append((0x03, PROP_UNKNOWN_G, struct.pack("<I", 0)))
        elif name == PROP_SECONDARY_ICON_ALT:
            # 'wv' = GetShabby slot A. Must be inline DWORD — as a 0x0E blob
            # the cache holds a heap pointer whose low 4 bytes become the
            # shabby_id (the "0x00BE0400 garbage").
            out.append(
                (
                    0x03,
                    PROP_SECONDARY_ICON_ALT,
                    struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_BMP, 1)),
                )
            )
        elif name == PROP_PRIMARY_ICON:
            # 'mf' = primary node-icon DWORD shabby_id. MOSSHELL FUN_7F405018
            # does GetProperty('mf', &buf, 4) expecting an inline DWORD. See
            # PROP_SECONDARY_ICON_ALT for the 0x0E-vs-0x03 hazard.
            out.append(
                (
                    0x03,
                    PROP_PRIMARY_ICON,
                    struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_BMP, 1)),
                )
            )
        elif name == PROP_UNKNOWN_L:
            # DSNAV advertises 'l' but no read-site confirmed; DSNAV.md §12
            # safe default is DWORD 0.
            out.append((0x03, PROP_UNKNOWN_L, struct.pack("<I", 0)))
        elif name == PROP_UNKNOWN_I:
            # DSNAV advertises 'i' but no read-site confirmed; DSNAV.md §12
            # safe default is DWORD 0.
            out.append((0x03, PROP_UNKNOWN_I, struct.pack("<I", 0)))
        elif name == PROP_TYPE:
            # Details-view column uses 0x0A (ASCII cache for MOSSHELL's column
            # render); Properties dialog uses 0x0B (UTF-16 cache for GetPropSz).
            ptype = 0x0A if is_children else 0x0B
            out.append((ptype, PROP_TYPE, _sz(content.type_str)))
        elif name == PROP_LAST_CHANGED:
            # Details-view cell = 0x0C FILETIME (8-byte, 100-ns since 1601)
            # → MOSSHELL 0x7F3FBC12 case 0xC → FileTimeToSz. DWORD path only
            # matches prop name "_D" (BBSNAV territory).
            # Properties dialog = 0x0B human-formatted string.
            # On is_children, skip entirely when modified_filetime == 0 so
            # the listview cell stays blank vs rendering 1601-01-01.
            if is_children:
                if content.modified_filetime:
                    out.append(
                        (
                            0x0C,
                            PROP_LAST_CHANGED,
                            struct.pack("<Q", content.modified_filetime & 0xFFFFFFFFFFFFFFFF),
                        )
                    )
            else:
                out.append((0x0B, PROP_LAST_CHANGED, _sz(content.modified)))
        elif name == PROP_DESCRIPTION:
            out.append((0x0B, PROP_DESCRIPTION, _sz(content.description)))
        elif name == PROP_GO_WORD:
            out.append((0x0B, PROP_GO_WORD, _sz(content.go_word)))
        elif name == PROP_CATEGORY:
            out.append((0x0B, PROP_CATEGORY, _sz(content.category)))
        elif name == PROP_TOPICS:
            out.append((0x0B, PROP_TOPICS, _sz(content.topics)))
        elif name == PROP_PEOPLE:
            out.append((0x0B, PROP_PEOPLE, _sz(content.people)))
        elif name == PROP_PLACE:
            out.append((0x0B, PROP_PLACE, _sz(content.place)))
        elif name == PROP_MAYBE_HIDDEN_U:
            out.append((0x0B, PROP_MAYBE_HIDDEN_U, _sz(content.u_value)))
        elif name == PROP_FORUM_MANAGER:
            out.append((0x0B, PROP_FORUM_MANAGER, _sz(content.forum_mgr)))
        elif name == PROP_OWNER:
            out.append((0x0B, PROP_OWNER, _sz(content.owner)))
        elif name == PROP_CREATED:
            out.append((0x0B, PROP_CREATED, _sz(content.created)))
        elif name == PROP_LANGUAGE:
            # Wire 'q' is an 8-byte qword: [unknown_header:u32][lcid:u32].
            # MCM's browse-language worker (MCM!FUN_0410438e) reads the
            # LCID as `*(u32*)(value + 4)`, so the DWORD at offset 0 is a
            # header we don't yet understand (pack 0 until an on-wire
            # capture settles it). Type 0x04 = 8-byte qword per SVCPROP's
            # DecodePropertyValue dispatch; type 0x03 would only allocate
            # a 4-byte buffer and the client's +4 read would pick up
            # adjacent heap bytes (the root cause of the garbage combobox
            # in View > Options > General "Content view").
            out.append(
                (0x04, PROP_LANGUAGE, struct.pack("<II", 0, content.language))
            )
        elif name == PROP_VENDOR_ID:
            out.append((0x03, PROP_VENDOR_ID, struct.pack("<I", content.vendor_id)))
        elif name == PROP_PRICE:
            out.append((0x03, PROP_PRICE, struct.pack("<I", content.price_dword)))
        elif name == PROP_RATING:
            out.append((0x03, PROP_RATING, struct.pack("<I", content.rating_dword)))
        else:
            out.append((0x03, name, struct.pack("<I", 0)))
    return out


def build_dirsrv_reply_payload(request=None, *, selector=None):
    """Build a DIRSRV GetProperties reply.

    Reply: dword(status) + dword(node_count) + end-static + dynamic-complete + property records.

    Selector semantics (TREENVCL IID table 0x7F633270..0x7F6332EC):
      0x00 GetProperties — return self record
      0x02 GetChildren   — return children (GetRelatives dir=0)
    Post-login breadcrumb walks (CMosTreeNode::GetNthChild path) use selector
    0x00 with dword_0=1 as a "return children" override, so we also treat that
    as children. GetLocalizedNode calls selector 0x02 with dword_0=0 — without
    this selector gate, that fell into the properties branch and returned the
    parent's own record, poisoning the localized-child cache with self.
    """
    if request is None:
        request = DirsrvRequest()

    requested_props = [p for p in request.prop_group.split("\x00") if p]
    is_children = (
        selector == DIRSRV_SELECTOR_GET_CHILDREN
        or request.dword_0 == 1
    )

    log.info(
        "get_properties node=%s raw=%s selector=%s children=%s props=%s locale_lcid=%s locale_raw=%s",
        request.node_id,
        request.node_id_raw.hex(),
        f"0x{selector:02x}" if selector is not None else "-",
        is_children,
        ",".join(requested_props) or "-",
        f"0x{request.locale_lcid:04x}" if request.locale_lcid is not None else "-",
        request.locale_raw.hex() or "-",
    )

    content_store = _default_store.content
    node = content_store.get_node(request.node_id)

    props_per_record = []  # for logging: list of (source_node_id, prop_tuples)
    if request.node_id == "0:0" and requested_props == [PROP_LANGUAGE]:
        # MCM!FUN_0410438e drives the View > Options > General "Content
        # view" combobox by asking DIRSRV for every available browse
        # LCID in one call: node=0:0, propList=["q"], 4-byte zero
        # locale, opened on its own pipe (ver_param="U"). The worker
        # iterates the reply records and reads `*(u32*)(value + 4)` on
        # each `q` to build a packed-LCID array, caches it in HKLM, and
        # feeds it to GetLocaleInfoA for display. The observed wire
        # dispatches on selector 0x02 (is_children=False) rather than
        # the selector 0x00 GetChildren that the TREENVCL RE implied,
        # so gate on (node, propList) — works regardless of dword_0.
        # Scoped to 0:0 so per-node `q` lookups (e.g. a fixture asking
        # what language MSN Today is in) keep returning the node's own
        # language instead of the advertised browse list.
        for lcid in SUPPORTED_BROWSE_LCIDS:
            props = [(0x04, PROP_LANGUAGE, struct.pack("<II", 0, lcid))]
            props_per_record.append((f"lang:0x{lcid:04x}", props))
    elif not is_children:
        props = build_props(requested_props, node, is_children=False)
        props_per_record.append((node.node_id, props))
    elif node.node_id == "4:0":
        # Topology special-case: DIRECTORY_CHILDREN["4:0"] is empty, so an
        # ordinary GetChildren would return zero records. Return 4:0's own
        # record instead so the client has something to read on the MSN
        # Today startup path.
        props = build_props(requested_props, node, is_children=True)
        props_per_record.append((node.node_id, props))
    else:
        # get_children applies a permissive fallback; see InMemoryContentStore.
        # Pass locale_raw so `filter_on=1` requests scope the reply to the
        # client's BrowseLanguage — GetLocalizedNode relies on this to pick
        # the first localized child when descending into 1:0 / 1:1.
        for child in content_store.get_children(request.node_id, request.locale_raw):
            props = build_props(requested_props, child, is_children=True)
            props_per_record.append((child.node_id, props))

    records = [build_property_record(props) for _node_id, props in props_per_record]
    node_count = len(records)
    dynamic_data = b"".join(records)

    log.info("get_properties_reply status=0 node_count=%d", node_count)
    for i, (src_node_id, props) in enumerate(props_per_record):
        log.info(
            "get_properties_reply idx=%d node=%s %s",
            i,
            src_node_id,
            _format_props_for_log(props),
        )

    if log.isEnabledFor(TRACE):
        for i, rec in enumerate(records):
            log.trace("record idx=%d len=%d hex=%s", i, len(rec), rec.hex())

    payload = bytearray()
    payload.extend(build_tagged_reply_dword(0))  # status = success
    payload.extend(build_tagged_reply_dword(node_count))  # node count
    payload.append(TAG_END_STATIC)
    # 0x88 (stream-end), not 0x86: GetChildren's client reads property
    # records through MPCCL's dynamic iterator, which waits on +0x28/+0x2c.
    # 0x86 would signal the single-shot Wait() but skip the iterator events,
    # yielding an empty listview.
    payload.append(TAG_DYNAMIC_STREAM_END)
    payload.extend(dynamic_data)
    return bytes(payload)


def build_get_shabby_reply_payload(payload):
    """Build the reply for a DIRSRV GetShabby request.

    Request payload: `03 [4-byte LE shabby_id] 83 85`
      - `03` = DwordParam tag, value = the Shabby ID
      - `83 85` = recv descriptors telling us the reply tags

    Reply: `83 [DWORD status] 87 86 [icon file bytes — raw, to end of packet]`
    Static status DWORD, 0x87 end-static, 0x86 dynamic-complete-signal: the
    client calls pending->Wait() (MPCCL vtable[4] @ 0x04604921) which listens
    on the +0x24 completion event. Only 0x86 fires SignalRequestCompletion
    and wakes that wait. 0x88 would route through the iterator events
    (+0x28/+0x2c) and leave Wait() blocked until the pipe closes, returning
    0x8B0B0005 (the 13-second hang we chased earlier). 0x85 with a length
    prefix would also fail to signal completion. On unknown shabby_id we
    return status=0 with an empty blob; the client handles size==0 by
    leaving the cache slot NULL (forbidden glyph).
    """
    send_params, _ = parse_request_params(payload)
    shabby_id = next(
        (p.value for p in send_params if isinstance(p, DwordParam)),
        0,
    )

    blob = shabby.load_shabby_bytes(shabby_id) or b""
    fmt, content_id = shabby.unpack_shabby_id(shabby_id)
    log.info(
        "get_shabby shabby_id=0x%08x fmt=0x%02x content_id=%d blob_len=%d",
        shabby_id,
        fmt,
        content_id,
        len(blob),
    )
    log.info("get_shabby_reply status=0 blob_len=%d", len(blob))

    return (
        build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + blob
    )


# --- Payload builders used by tests ---


def build_dirsrv_service_map_payload():
    return build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
