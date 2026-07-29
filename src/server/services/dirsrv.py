"""DIRSRV service handler: directory browsing, property records."""

import logging
import struct

from ..config import (
    DIRSRV_BROWSE_FLAGS_CONTAINER,
    DIRSRV_BROWSE_FLAGS_DELEGATE,
    DIRSRV_BROWSE_FLAGS_HAS_CHILDREN,
    DIRSRV_BROWSE_FLAGS_LEAF,
    DIRSRV_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ..log import TRACE
from ..models import DirsrvRequest, DwordParam, VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    build_tagged_reply_var,
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
DIRSRV_SELECTOR_GET_DEID_FROM_GO_WORD = 0x03  # CTreeNavClient::GetDeidFromGoWord
# Slot 4 (IID 00028B28) is GetShabby — CTreeNavClient::GetShabby
# (TREENVCL.DLL 0x7f631bab) calls proxy->method_at_offset_0xc(proxy, 4, ...).
DIRSRV_SELECTOR_GET_SHABBY = 0x04
TREEEDCL_CLASS_EDIT = 0x04
TREEEDCL_SELECTOR_GET_DATASETS = 0x0B
TREEEDCL_SELECTOR_GET_TICKET = 0x0C

# Status returned in GetDeidFromGoWord's reply for an unrecognised go-word.
# MCM!FGetGoWord (0x0410423f) compares the wire status DWORD against three
# constants: 0x10002 → "Cannot find Go word." (string 0x57a); 0x103 →
# "Service not available." (string 0x57c); anything else nonzero →
# "There was a problem using Go words." (string 0x57b).
DS_E_NOT_FOUND = 0x10002

# DIRSRV property names. Use PROTOCOL.md semantics for known props; keep
# unresolved props explicitly UNKNOWN and tentative interpretations as MAYBE.
PROP_MNID = "a"
PROP_BROWSE_FLAGS = "b"
PROP_APP_ID = "c"
PROP_CATEGORY = "ca"
PROP_NAME = "e"
PROP_UNKNOWN_G = "g"
PROP_SECONDARY_ICON = "h"
PROP_DELEGATE_FIELD10 = "i"
PROP_DESCRIPTION = "j"
PROP_GO_WORD = "k"
PROP_DELEGATE_MNID = "l"
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
PROP_RIGHTS = "x"
PROP_VENDOR_ID = "y"
PROP_PRICE = "z"

# CMosViewWnd::AddMenus asks CMosTreeNode::HasRights for mask 0x70 before
# merging File > New/Delete/Unlink. HasRights reads wire property `x` as a
# DWORD and succeeds when any requested bit is present. Fixtures grant the
# complete authoring-menu mask.
DIRSRV_RIGHTS_AUTHORING = 0x70

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
        """Handle a DIRSRV request — dispatch by selector."""
        if msg_class == TREEEDCL_CLASS_EDIT and selector == TREEEDCL_SELECTOR_GET_TICKET:
            reply_payload = build_get_ticket_reply_payload()
        elif msg_class == TREEEDCL_CLASS_EDIT and selector == TREEEDCL_SELECTOR_GET_DATASETS:
            reply_payload = build_get_datasets_reply_payload()
        elif selector == DIRSRV_SELECTOR_GET_PROPERTIES:
            request = decode_dirsrv_request(payload)
            reply_payload = build_get_properties_reply_payload(request)
        elif selector == DIRSRV_SELECTOR_GET_CHILDREN:
            request = decode_dirsrv_request(payload)
            reply_payload = build_get_children_reply_payload(request)
        elif selector == DIRSRV_SELECTOR_GET_DEID_FROM_GO_WORD:
            reply_payload = build_get_deid_from_go_word_reply_payload(payload)
        elif selector == DIRSRV_SELECTOR_GET_SHABBY:
            reply_payload = build_get_shabby_reply_payload(payload)
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
    # Never emit the flag-0x02 "empty" form. SVCPROP DecodeFlagByteString
    # @ 0x7F641328 returns a NULL value with size 0 for it, and the property
    # then fails to land in the record — SoftICE BPX on the FGet-miss branch
    # @ 0x7F3FC8A2 caught exactly this for `w` on node 1:256. Because
    # CServiceProperties::FSet @ 0x7F6418FF only advances the record count on
    # success, one rejected property also drops every property after it, which
    # can silently strip `l`/`i` from a delegate record.
    # The ASCII form with a zero-length string is safe: it decodes to a real
    # 2-byte L"" with a valid pointer, and consumes 2 wire bytes either way.
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
            # Bit 0x04 = delegate: GetCChildren/GetNthChild call slot 6
            # HrSetupDelegate first, which reads 'c'/'l'/'i' and hands the
            # folder to app 'c' navigator.
            flag = (
                node.browse_flags
                if node.browse_flags is not None
                else (DIRSRV_BROWSE_FLAGS_CONTAINER if node.is_container else DIRSRV_BROWSE_FLAGS_LEAF)
            )
            if node.delegate:
                flag |= DIRSRV_BROWSE_FLAGS_DELEGATE
            # Bit 0x02 = SFGAO_HASSUBFOLDER, per CMosShellFolder::GetAttributesOf
            # @ 0x7F3F2EE0. Explorer builds its namespace tree from this word;
            # a container that leaves the bit clear is a folder Explorer
            # believes is empty. Only meaningful alongside a clear bit 0x01 —
            # GetAttributesOf ORs SFGAO_FOLDER before it looks at 0x02, so
            # setting it on a leaf yields HASSUBFOLDER without FOLDER.
            #
            # Delegates are excluded on purpose: setting 0x02 takes the JNZ at
            # 0x7F3F2F6A and skips the inner-node re-query, which is how the
            # plug-in (bbsnav) reports its own children. Let the inner node
            # answer for those.
            if (
                not (flag & DIRSRV_BROWSE_FLAGS_LEAF)
                and not node.delegate
                and _default_store.content.has_children(node.node_id)
            ):
                flag |= DIRSRV_BROWSE_FLAGS_HAS_CHILDREN
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
        elif name == PROP_RIGHTS:
            out.append((0x03, PROP_RIGHTS, struct.pack("<I", DIRSRV_RIGHTS_AUTHORING)))
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
        elif name == PROP_DELEGATE_MNID:
            # 'l' = the inner node's (field_8, field_c). MOSSHELL
            # HrSetupDelegate @ 0x7F3FC14F reads it with cap 8, type 0, so the
            # cache element must hold 8 inline bytes — wire type 0x0C (qword),
            # not 0x0E (a 0x0E element caches a heap pointer, same hazard as
            # 'wv'/'mf'). Non-delegate nodes emit DWORD 0.
            if node.delegate:
                out.append((0x0C, PROP_DELEGATE_MNID, node.mnid_a))
            else:
                out.append((0x03, PROP_DELEGATE_MNID, struct.pack("<I", 0)))
        elif name == PROP_DELEGATE_FIELD10:
            # 'i' = the inner node's field_10, read with cap 2. HrSetupDelegate
            # defaults it to 1 when the read fails, so emit an explicit WORD 0
            # on a delegate to keep the inner mnid locale-neutral.
            if node.delegate:
                out.append((0x02, PROP_DELEGATE_FIELD10, struct.pack("<H", 0)))
            else:
                out.append((0x03, PROP_DELEGATE_FIELD10, struct.pack("<I", 0)))
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
            # With no timestamp, send an EMPTY 0x0A string rather than omitting
            # the tag. The column formatter (0x7F3FBC12 case 0x0A) copies the
            # ASCIIZ through, so the cell still renders blank — and the cache
            # element is marked received. Omitting a requested tag instead
            # leaves a permanently unreceived element: SetPropertyGroupFromPsp
            # @ 0x7F3FC85A calls RememberProperty(name, NULL, 0, 0) on an FGet
            # miss, and FindProperty @ 0x7F3FCE12 only re-fetches when an
            # element is ABSENT. Every later read then returns 0x8B0B0041.
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
                    out.append((0x0A, PROP_LAST_CHANGED, _sz("")))
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
            # Wire 'q' uses the 8-byte transport type 0x04, but its value is a
            # counted DWORD array: [count:u32][lcid:u32]. MCM's browse-language
            # worker (MCM!FUN_0410438e) reads the LCID at offset 4. DSNED copies
            # the bytes into a CServiceProperties type-0x10 value for a new node.
            # CServiceProperties::FSet requires `length == count * 4 + 4`;
            # count 0 with one trailing LCID makes it reject the value and
            # DSNED reports the rejection as E_OUTOFMEMORY.
            out.append(
                (0x04, PROP_LANGUAGE, struct.pack("<II", 1, content.language))
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


def build_get_properties_reply_payload(request=None):
    """Build a DIRSRV GetProperties (selector 0x00) reply: one self record.

    The client always wants exactly one record back — the requested node's own
    properties. CMosTreeNode::GetPropertyGroupRaw → CTreeNavClient::GetProperties
    expects a single-record stream and feeds it to SetPropertyGroupFromPsp on
    the receiving CMosTreeNode. Returning multi-record (children) causes the
    receiver to be populated with its FIRST CHILD's record — observed live as
    Cats US.e = 'Arts and Entertainment' (mnid (1,0x100), not (1,0x10)).
    """
    if request is None:
        request = DirsrvRequest()

    requested_props = _parse_prop_group(request.prop_group)
    _log_request("get_properties", request, requested_props)

    node = _default_store.content.get_node(request.node_id)
    records_with_ids = [(node.node_id, build_props(requested_props, node, is_children=False))]

    _log_reply("get_properties_reply", records_with_ids)
    return build_tree_reply_wire(records_with_ids)


def build_get_children_reply_payload(request=None):
    """Build a DIRSRV GetChildren (selector 0x02) reply: child records.

    Special cases (order matters):
      1. node=0:0 + propList=["q"] → MCM browse-language enumerator.
         MCM!FUN_0410438e drives View > Options > General "Content view"
         by asking DIRSRV for every available browse LCID in one call,
         opened on its own pipe (ver_param="U"). The worker reads
         `*(u32*)(value + 4)` on each `q`, caches the packed-LCID array
         in HKLM, and feeds it to GetLocaleInfoA for display.
      2. node=4:0 → self-as-child. DIRECTORY_CHILDREN["4:0"] is empty,
         so ordinary enumeration returns zero records and stalls the
         MSN Today startup path.
      3. Normal: get_children with permissive fallback. Pass locale_raw
         so filter_on=1 requests scope the reply to the client's
         BrowseLanguage — GetLocalizedNode relies on this to pick the
         first localized child when descending into 1:0 / 1:1.
    """
    if request is None:
        request = DirsrvRequest()

    requested_props = _parse_prop_group(request.prop_group)
    _log_request("get_children", request, requested_props)

    records_with_ids = _collect_children_records(request, requested_props)

    _log_reply("get_children_reply", records_with_ids)
    return build_tree_reply_wire(records_with_ids)


def _collect_children_records(request, requested_props):
    """Return [(src_node_id, prop_tuples)] for the GetChildren body."""
    if request.node_id == "0:0" and requested_props == [PROP_LANGUAGE]:
        return [
            (
                f"lang:0x{lcid:04x}",
                [(0x04, PROP_LANGUAGE, struct.pack("<II", 1, lcid))],
            )
            for lcid in SUPPORTED_BROWSE_LCIDS
        ]

    content_store = _default_store.content
    node = content_store.get_node(request.node_id)
    if node.node_id == "4:0":
        return [(node.node_id, build_props(requested_props, node, is_children=True))]

    return [
        (child.node_id, build_props(requested_props, child, is_children=True))
        for child in content_store.get_children(request.node_id, request.locale_raw)
    ]


def _parse_prop_group(prop_group):
    return [p for p in prop_group.split("\x00") if p]


def _log_request(kind, request, requested_props):
    log.info(
        "%s node=%s raw=%s props=%s locale_lcid=%s locale_raw=%s",
        kind,
        request.node_id,
        request.node_id_raw.hex(),
        ",".join(requested_props) or "-",
        f"0x{request.locale_lcid:04x}" if request.locale_lcid is not None else "-",
        request.locale_raw.hex() or "-",
    )


def _log_reply(kind, records_with_ids):
    log.info("%s status=0 node_count=%d", kind, len(records_with_ids))
    for i, (src_node_id, props) in enumerate(records_with_ids):
        log.info(
            "%s idx=%d node=%s %s",
            kind,
            i,
            src_node_id,
            _format_props_for_log(props),
        )


def build_tree_reply_wire(records_with_ids):
    """Build the shared MOS-tree reply framing for GetProperties/GetChildren.

    Used by both DIRSRV and BBS (the BBS read channel rides the same generic
    TREENVCL tree, so its reply framing is identical — only the per-node tag
    vocabulary differs).

    status(0) + node_count + 0x87 end-static + 0x88 stream-end + records.

    0x88 (stream-end), not 0x86: GetChildren's client reads property records
    through MPCCL's dynamic iterator, which waits on +0x28/+0x2c. 0x86 would
    signal the single-shot Wait() but skip the iterator events, yielding an
    empty listview. GetProperties uses the same framing so the client's MPCCL
    code path is uniform.
    """
    records = [build_property_record(props) for _id, props in records_with_ids]
    node_count = len(records)

    if log.isEnabledFor(TRACE):
        for i, rec in enumerate(records):
            log.trace("record idx=%d len=%d hex=%s", i, len(rec), rec.hex())

    payload = bytearray()
    payload.extend(build_tagged_reply_dword(0))  # status = success
    payload.extend(build_tagged_reply_dword(node_count))
    payload.append(TAG_END_STATIC)
    payload.append(TAG_DYNAMIC_STREAM_END)
    payload.extend(b"".join(records))
    return bytes(payload)


def build_get_deid_from_go_word_reply_payload(payload):
    """Build the reply for a DIRSRV GetDeidFromGoWord request.

    Request payload (from `CTreeNavClient::GetDeidFromGoWord` @
    TREENVCL 0x7F63179F):
      - `0x04 [len] <wide_go_word + wide-NUL>`  PackSendBytes wide string
      - `0x04 [len] <count:u32 + lcid:u32 * count>`  PackSendBytes locale
      - `0x83`  PackReceiveDword desc — status
      - `0x84`  PackReceiveBytes desc — 8-byte deid via post-static buffer

    Reply: `0x83 [status] 0x87 0x84 [len=8] [deid:8]`. The 0x84 buffer
    after end-static mirrors LOGSRV bootstrap's post-static var: the
    marshal binds the 0x84 recv-descriptor to the 8-byte block, and the
    client's `local_10[+0xc] GetBasePtr` returns its base. Status DWORD
    of 0 = success (deid valid); nonzero = lookup failure (deid ignored).
    """
    send_params, _ = parse_request_params(payload)
    wide = next((p.data for p in send_params if isinstance(p, VarParam)), b"")
    go_word = wide.decode("utf-16-le", errors="replace").rstrip("\x00")

    node = _default_store.content.find_by_go_word(go_word)
    if node is not None:
        deid = node.mnid_a
        status = 0
    else:
        deid = b"\x00" * 8
        status = DS_E_NOT_FOUND
    log.info(
        "get_deid_from_go_word go_word=%r match=%s status=0x%x",
        go_word, node.node_id if node else "-", status,
    )

    return (
        build_tagged_reply_dword(status)
        + bytes([TAG_END_STATIC])
        + build_tagged_reply_var(0x84, deid)
    )


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


def build_get_ticket_reply_payload():
    """Return a minimal TREEEDCL capability ticket for fixture authoring.

    Enabling wire property `x` makes DSNAV initialize its node editors while
    building File > New. CTreeEditClient::GetTicket sends class 0x04,
    selector 0x0C and waits synchronously for a status DWORD plus a
    single-shot dynamic blob. SECURCL!HrDecodeTicket reads the blob's first
    u16 as its total length, allocates that many bytes, and copies it without
    interpreting any other fields. A two-byte self-length is therefore the
    smallest valid opaque ticket.
    """
    ticket = struct.pack("<H", 2)
    return (
        build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + ticket
    )


def build_get_datasets_reply_payload():
    """Return an empty TREEEDCL dataset property bag.

    DSNED requests datasets while enumerating node-editor menu entries.
    CTreeEditClient::PrivateGetDataSets passes the dynamic reply directly to
    SVCPROP!FDecompressPropClnt, so it must contain a complete compressed
    property record even when no datasets are available.
    """
    datasets = build_property_record([])
    return (
        build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + datasets
    )


# --- Payload builders used by tests ---


def build_dirsrv_service_map_payload():
    return build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
