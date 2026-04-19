"""DIRSRV service handler: directory browsing, property records."""

import logging
import struct

from ..config import (
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

# Within the DIRSRV interface table, slot 4 (IID 00028B28) is the GetShabby
# RPC. CTreeNavClient::GetShabby (TREENVCL.DLL 0x7f631bab) calls
# `proxy->method_at_offset_0xc(proxy, 4, ...)` — the literal 4 is the slot
# index that resolves to the GetShabby IID via the discovery table.
DIRSRV_GETSHABBY_SELECTOR = 0x04

# DIRSRV property names. Use PROTOCOL.md semantics for known props; keep
# unresolved props explicitly UNKNOWN and tentative interpretations as MAYBE.
PROP_MNID = "a"
PROP_BROWSE_FLAGS = "b"
PROP_APP_ID = "c"
PROP_CATEGORY = "ca"
PROP_NAME = "e"
PROP_FILENAME = "fn"
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

STRUCTURAL_NAV_PROPS = (
    PROP_MNID,
    PROP_APP_ID,
    PROP_SECONDARY_ICON,
    PROP_BROWSE_FLAGS,
    PROP_EXEC_ARGS,
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
        if selector == DIRSRV_GETSHABBY_SELECTOR:
            reply_payload = build_get_shabby_reply_payload(payload)
        else:
            request = decode_dirsrv_request(payload)
            reply_payload = build_dirsrv_reply_payload(request)
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


def _blob(s):
    """Length-prefixed ASCII blob body for a type-0x0E property."""
    data = s.encode("ascii", errors="replace")
    return struct.pack("<I", len(data)) + data


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


def build_nav_props(
    requested_props, *, is_container, c_value=0, mnid_a=b"\x00" * 8, title="MSN Today"
):
    """Props for DSNAV GetChildren — the navigation/list view.

    Keeps the stable-state encoding proven to not OOM:
    - a/c/h/b/x structural props
    - e = title string (0x0A ASCII cache — icon label + titlebar both ANSI).
    - p = title blob (legacy list-view title; ignored by Context tab here)
    - Unknown content props default to DWORD 0.
    """
    # DnR (c=7) worker ExecUrlWorkerProc → DownloadContentToTempPath calls
    # vt[0x40]("fn", buf, len, 1) on the node cache to build the temp file
    # name. The client's GetChildren request doesn't ask for `fn`, so we
    # emit it unilaterally — SVCPROP caches by name, so extra records are
    # absorbed. Without this, phase 1 of the worker bails before the FTM
    # download step and MSN Today renders blank.
    props_to_emit = list(requested_props)
    if c_value == 7 and PROP_FILENAME not in props_to_emit:
        props_to_emit.append(PROP_FILENAME)

    out = []
    for name in props_to_emit:
        if name == PROP_MNID:
            out.append((0x0E, PROP_MNID, struct.pack("<I", len(mnid_a)) + mnid_a))
        elif name == PROP_BROWSE_FLAGS:
            # PROTOCOL.md §SVCPROP-props (line 448): bit 0x01 CLEAR = container
            # (Browse), SET = leaf (Exec). ExecuteCommand branches on this bit
            # to choose HrBrowseObject vs CMosTreeNode::Exec.
            out.append((0x01, PROP_BROWSE_FLAGS, bytes([0x00 if is_container else 0x01])))
        elif name == PROP_APP_ID:
            out.append((0x03, PROP_APP_ID, struct.pack("<I", c_value)))
        elif name == PROP_NAME:
            # Nav 'e' = title string, wire type 0x0A (ASCII cache). Both
            # the icon label and the explorer window titlebar read 'e' via
            # paths that expect ANSI bytes. 0x0B (UTF-16 cache) rendered
            # the icon but truncated the titlebar to "M" at the first wide
            # NUL. 0x0A stores ASCII in the cache, satisfying both readers.
            out.append((0x0A, PROP_NAME, _sz(title)))
        elif name == PROP_SECONDARY_ICON:
            # "h" = shabby_id for the listview per-item icon. MOSSHELL
            # CMosViewWnd::AddPMtnToView (0x7f3f820e) calls FUN_7f404786
            # which reads "h" as DWORD and (if present) calls FUN_7f4047c2
            # → FUN_7f4049f9 → vtable[0x74] GetShabbyToFile → ExtractIconExA
            # on the downloaded temp file. ExtractIconExA expects ICO/EXE/DLL
            # bytes, not BMP — `mf` (banner) is the BMP channel; `h` is its
            # per-item counterpart. Emit a shabby_id whose registry blob is
            # a valid ICO. Omitting "h" makes FUN_7f404786 short-circuit and
            # LVN_GETDISPINFO returns iImage=0 = default slot (forbidden glyph
            # loaded from MOSSHELL icon resource #2 in FUN_7f4042a0).
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
            out.append((0x0E, PROP_MAYBE_SIZE_OR_LEGACY_TITLE, _blob(title)))
        elif name == PROP_UNKNOWN_G:
            # Purpose unresolved — sentinel sweeps ruled out `g` as the
            # icon slot. Emit DWORD 0 as a harmless default.
            out.append((0x03, PROP_UNKNOWN_G, struct.pack("<I", 0)))
        elif name == PROP_SECONDARY_ICON_ALT:
            # `wv` = GetShabby slot A (secondary icon call, req_id=1).
            # Inline DWORD shabby_id. As a 0x0E blob, SVCPROP stores a
            # heap-alloc pointer in the cache and the reader echoes the
            # pointer bytes as the shabby_id (the `0x00BE0400` garbage).
            out.append(
                (
                    0x03,
                    PROP_SECONDARY_ICON_ALT,
                    struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_BMP, 1)),
                )
            )
        elif name == PROP_PRIMARY_ICON:
            # `mf` = primary node-icon property. MOSSHELL FUN_7F405018
            # does `GetProperty("mf", &buf, 4)` → 4-byte DWORD shabby_id →
            # synthesizes cache filename via `%04X%08X` → if file missing
            # calls vtable+0x74 → GetShabbyToFile → CTreeNavClient::GetShabby
            # with this DWORD. Must be inline 0x03; as a 0x0E blob the
            # cache slot holds the heap pointer and the low 4 bytes of
            # that pointer become the shabby_id (that's what produced
            # the 0x00BE0400 we chased across multiple sessions).
            out.append(
                (
                    0x03,
                    PROP_PRIMARY_ICON,
                    struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_BMP, 1)),
                )
            )
        elif name in (PROP_TYPE, PROP_LAST_CHANGED, PROP_UNKNOWN_L):
            out.append((0x0E, name, struct.pack("<I", 1) + b"\x00"))
        elif name == PROP_FILENAME:
            # DnR temp filename base — DownloadContentToTempPath reads this
            # into a stack buf via vt[0x40]. Extension determines the handler
            # ShellExecute uses when dnr.exe launches the file. .HTM → browser.
            out.append((0x0A, PROP_FILENAME, _sz("MSNTODAY.HTM")))
        else:
            out.append((0x03, name, struct.pack("<I", 0)))
    return out


def build_dialog_props(requested_props, content):
    """Props for the Properties dialog — types from MOSSHELL Ghidra decode.

    Strings use wire type 0x0A (not 0x0B). Both share the same flag-byte wire
    body, but 0x0A causes SVCPROP to run WideCharToMultiByte so the cache
    holds ASCII. CMosTreeNode::Properties @ 0x7f3fef12 reads prop 'e' via
    GetProperty (raw memcpy) and passes the buffer straight to PropertySheetA
    (ANSI). With 0x0B the cache is UTF-16 and PropertySheetA truncates at the
    first wide NUL ("MSN Today" → "M"). 0x0A keeps the cache ASCII so both
    GetProperty (raw) and GetPropSz (ANSI) render the full string.

    `content` is a NodeContent dataclass (server.store.base).
    """
    out = []
    for name in requested_props:
        # 'e' must be 0x0A (ASCII cache) — CMosTreeNode::Properties raw-memcpies
        # it to PropertySheetA (ANSI). With 0x0B it would truncate at the first
        # wide NUL ("MSN Today" → "M"). All other strings use 0x0B: their cache
        # is consumed by GetPropSz which runs EnsurePropSzCache's
        # WideCharToMultiByte path to produce the ASCII copy at cache+0xC.
        if name == PROP_NAME:
            out.append((0x0A, PROP_NAME, _sz(content.name)))
        elif name == PROP_DESCRIPTION:
            out.append((0x0B, PROP_DESCRIPTION, _sz(content.description)))
        elif name == PROP_GO_WORD:
            out.append((0x0B, PROP_GO_WORD, _sz(content.go_word)))
        elif name == PROP_CATEGORY:
            out.append((0x0B, PROP_CATEGORY, _sz(content.category)))
        elif name == PROP_TYPE:
            out.append((0x0B, PROP_TYPE, _sz(content.type_str)))
        elif name == PROP_TOPICS:
            out.append((0x0B, PROP_TOPICS, _sz(content.topics)))
        elif name == PROP_PEOPLE:
            out.append((0x0B, PROP_PEOPLE, _sz(content.people)))
        elif name == PROP_PLACE:
            out.append((0x0B, PROP_PLACE, _sz(content.place)))
        elif name == PROP_MAYBE_HIDDEN_U:
            out.append(
                (
                    0x0B,
                    PROP_MAYBE_HIDDEN_U,
                    _sz(content.u_value) if content.u_value else _sz(""),
                )
            )
        elif name == PROP_FORUM_MANAGER:
            out.append((0x0B, PROP_FORUM_MANAGER, _sz(content.forum_mgr)))
        elif name == PROP_OWNER:
            out.append((0x0B, PROP_OWNER, _sz(content.owner)))
        elif name == PROP_CREATED:
            out.append((0x0B, PROP_CREATED, _sz(content.created)))
        elif name == PROP_LAST_CHANGED:
            out.append((0x0B, PROP_LAST_CHANGED, _sz(content.modified)))
        elif name == PROP_MAYBE_SIZE_OR_LEGACY_TITLE:
            # 'p' is a DWORD byte count. FUN_7f3fba69's special 'p' branch
            # reads `**(cache+4)` (first DWORD of value data) and calls
            # FormatSizeString (vtable+0x140), caching the formatted result
            # at cache+0xC for GetPropSzBuf.
            out.append(
                (
                    0x03,
                    PROP_MAYBE_SIZE_OR_LEGACY_TITLE,
                    struct.pack("<I", content.size_bytes),
                )
            )
        # DWORD (type 0x03) — Ghidra-confirmed dword reads
        elif name == PROP_LANGUAGE:
            out.append((0x03, PROP_LANGUAGE, struct.pack("<I", content.language)))
        elif name == PROP_VENDOR_ID:
            out.append((0x03, PROP_VENDOR_ID, struct.pack("<I", content.vendor_id)))
        elif name == PROP_PRICE:
            out.append((0x03, PROP_PRICE, struct.pack("<I", content.price_dword)))
        elif name == PROP_RATING:
            out.append((0x03, PROP_RATING, struct.pack("<I", content.rating_dword)))
        # Unknown — safe default
        else:
            out.append((0x03, name, struct.pack("<I", 0)))
    return out


def _is_dialog_request(requested_props):
    """Properties dialog requests never include structural nav props.

    Caller must also gate on `is_children=False`: the Properties dialog always
    queries a single node (GetProperties), while click dispatch / nav fetches
    may ask for content-only prop sets (e.g. `fn,g` for ExecUrlWorkerProc)
    with is_children=True.
    """
    return bool(requested_props) and not any(p in requested_props for p in STRUCTURAL_NAV_PROPS)


def build_child_props(requested_props, node, *, is_children):
    """Serialize `node` into a property record for the requested prop names."""
    if not is_children and _is_dialog_request(requested_props):
        return build_dialog_props(requested_props, node.content)
    return build_nav_props(
        requested_props,
        is_container=node.is_container,
        c_value=node.app_id,
        mnid_a=node.mnid_a,
        title=node.content.name,
    )


def build_dirsrv_reply_payload(request=None):
    """Build a DIRSRV GetProperties reply.

    Reply: dword(status) + dword(node_count) + end-static + dynamic-complete + property records.
    """
    if request is None:
        request = DirsrvRequest()

    requested_props = [p for p in request.prop_group.split("\x00") if p]
    is_children = request.dword_0 == 1

    log.info(
        "get_properties node=%s raw=%s children=%s props=%s",
        request.node_id,
        request.node_id_raw.hex(),
        is_children,
        ",".join(requested_props) or "-",
    )

    content_store = _default_store.content
    node = content_store.get_node(request.node_id)

    records = []
    if not is_children:
        records.append(
            build_property_record(build_child_props(requested_props, node, is_children=False))
        )
    else:
        # get_children applies a permissive fallback; see InMemoryContentStore.
        for child in content_store.get_children(request.node_id):
            records.append(
                build_property_record(build_child_props(requested_props, child, is_children=True))
            )

    node_count = len(records)
    dynamic_data = b"".join(records)

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

    return (
        build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + blob
    )


# --- Payload builders used by tests ---


def build_dirsrv_service_map_payload():
    return build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
