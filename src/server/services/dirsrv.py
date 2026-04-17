"""DIRSRV service handler: directory browsing, property records."""

import logging
import struct

from ..config import DIRSRV_INTERFACE_GUIDS, TAG_DYNAMIC_COMPLETE, TAG_END_STATIC
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
    if c_value == 7 and "fn" not in props_to_emit:
        props_to_emit.append("fn")

    out = []
    for name in props_to_emit:
        if name == "a":
            out.append((0x0E, "a", struct.pack("<I", len(mnid_a)) + mnid_a))
        elif name == "b":
            out.append((0x01, "b", bytes([0x01 if is_container else 0x00])))
        elif name == "c":
            out.append((0x03, "c", struct.pack("<I", c_value)))
        elif name == "e":
            # Nav 'e' = title string, wire type 0x0A (ASCII cache). Both
            # the icon label and the explorer window titlebar read 'e' via
            # paths that expect ANSI bytes. 0x0B (UTF-16 cache) rendered
            # the icon but truncated the titlebar to "M" at the first wide
            # NUL. 0x0A stores ASCII in the cache, satisfying both readers.
            out.append((0x0A, "e", _sz(title)))
        elif name == "h":
            # "h" = shabby_id of a custom .ICO/.EXE/.DLL for ExtractIconExA.
            # MOSSHELL FUN_7f404786 reads "h" as DWORD and passes the value
            # straight through FUN_7f4047c2 → FUN_7f4049f9 → vtable[0x74]
            # GetShabbyToFile. Sending h=0 triggers GetShabby(shabby_id=0) —
            # the server-side zero-blob reply leaves the HICON NULL and the
            # node renders the forbidden glyph. FUN_7f404786 skips the whole
            # icon path when GetProperty fails, so omit "h" for nodes that
            # don't have a custom icon file.
            continue
        elif name == "x":
            out.append((0x0E, "x", struct.pack("<I", 1) + b"\x00"))
        elif name == "p":
            out.append((0x0E, "p", _blob(title)))
        elif name == "g":
            # Purpose unresolved — sentinel sweeps ruled out `g` as the
            # icon slot. Emit DWORD 0 as a harmless default.
            out.append((0x03, "g", struct.pack("<I", 0)))
        elif name == "wv":
            # `wv` = GetShabby slot A (secondary icon call, req_id=1).
            # Inline DWORD shabby_id. As a 0x0E blob, SVCPROP stores a
            # heap-alloc pointer in the cache and the reader echoes the
            # pointer bytes as the shabby_id (the `0x00BE0400` garbage).
            out.append((0x03, "wv", struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_BMP, 1))))
        elif name == "mf":
            # `mf` = primary node-icon property. MOSSHELL FUN_7F405018
            # does `GetProperty("mf", &buf, 4)` → 4-byte DWORD shabby_id →
            # synthesizes cache filename via `%04X%08X` → if file missing
            # calls vtable+0x74 → GetShabbyToFile → CTreeNavClient::GetShabby
            # with this DWORD. Must be inline 0x03; as a 0x0E blob the
            # cache slot holds the heap pointer and the low 4 bytes of
            # that pointer become the shabby_id (that's what produced
            # the 0x00BE0400 we chased across multiple sessions).
            out.append((0x03, "mf", struct.pack("<I", shabby.pack_shabby_id(shabby.FORMAT_BMP, 1))))
        elif name in ("tp", "w", "l"):
            out.append((0x0E, name, struct.pack("<I", 1) + b"\x00"))
        elif name == "fn":
            # DnR temp filename base — DownloadContentToTempPath reads this
            # into a stack buf via vt[0x40]. Extension determines the handler
            # ShellExecute uses when dnr.exe launches the file. .HTM → browser.
            out.append((0x0A, "fn", _sz("MSNTODAY.HTM")))
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
        if name == "e":
            out.append((0x0A, "e", _sz(content.name)))
        elif name == "j":
            out.append((0x0B, "j", _sz(content.description)))
        elif name == "k":
            out.append((0x0B, "k", _sz(content.go_word)))
        elif name == "ca":
            out.append((0x0B, "ca", _sz(content.category)))
        elif name == "tp":
            out.append((0x0B, "tp", _sz(content.type_str)))
        elif name == "r":
            out.append((0x0B, "r", _sz(content.topics)))
        elif name == "s":
            out.append((0x0B, "s", _sz(content.people)))
        elif name == "t":
            out.append((0x0B, "t", _sz(content.place)))
        elif name == "u":
            out.append((0x0B, "u", _sz(content.u_value) if content.u_value else _sz("")))
        elif name == "n":
            out.append((0x0B, "n", _sz(content.forum_mgr)))
        elif name == "on":
            out.append((0x0B, "on", _sz(content.owner)))
        elif name == "v":
            out.append((0x0B, "v", _sz(content.created)))
        elif name == "w":
            out.append((0x0B, "w", _sz(content.modified)))
        elif name == "p":
            # 'p' is a DWORD byte count. FUN_7f3fba69's special 'p' branch
            # reads `**(cache+4)` (first DWORD of value data) and calls
            # FormatSizeString (vtable+0x140), caching the formatted result
            # at cache+0xC for GetPropSzBuf.
            out.append((0x03, "p", struct.pack("<I", content.size_bytes)))
        # DWORD (type 0x03) — Ghidra-confirmed dword reads
        elif name == "q":
            out.append((0x03, "q", struct.pack("<I", content.language)))
        elif name == "y":
            out.append((0x03, "y", struct.pack("<I", content.vendor_id)))
        elif name == "z":
            out.append((0x03, "z", struct.pack("<I", content.price_dword)))
        elif name == "o":
            out.append((0x03, "o", struct.pack("<I", content.rating_dword)))
        # Unknown — safe default
        else:
            out.append((0x03, name, struct.pack("<I", 0)))
    return out


def _is_dialog_request(requested_props):
    """Properties dialog requests never include structural props (a/c/h/b/x)."""
    return bool(requested_props) and not any(
        p in requested_props for p in ("a", "c", "h", "b", "x")
    )


def build_child_props(requested_props, node):
    """Serialize `node` into a property record for the requested prop names."""
    if _is_dialog_request(requested_props):
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

    def _log_record_node(kind, node_for_record):
        # DIAGNOSTIC: log node_id + full prop list with their packed values.
        # Helps correlate which node's cache ends up with mf=0 feeding the
        # second GetShabby(0). Remove once resolved.
        props = build_child_props(requested_props, node_for_record)
        summary = ",".join(f"{n}:{v.hex()}" for (_t, n, v) in props)
        log.info("record_emit kind=%s node=%s mnid_a=%s props=%s",
                 kind, node_for_record.node_id, node_for_record.mnid_a.hex(), summary)

    if not is_children:
        _log_record_node("self", node)
        records.append(build_property_record(build_child_props(requested_props, node)))
    else:
        # Permissive fallback: GetChildren on any non-"0:0" node returns the
        # fallback leaf (MSN Today). This causes visual endless hierarchy
        # (leaf appears as its own child) but is required for
        # CMosTreeNode::Exec to cache 'z'/'c' — returning empty broke
        # dispatch with "task cannot be completed".
        for child in content_store.get_children(request.node_id):
            _log_record_node("child", child)
            records.append(build_property_record(build_child_props(requested_props, child)))

    node_count = len(records)
    dynamic_data = b"".join(records)

    if log.isEnabledFor(TRACE):
        for i, rec in enumerate(records):
            log.trace("record idx=%d len=%d hex=%s", i, len(rec), rec.hex())

    payload = bytearray()
    payload.extend(build_tagged_reply_dword(0))  # status = success
    payload.extend(build_tagged_reply_dword(node_count))  # node count
    payload.append(TAG_END_STATIC)
    payload.append(TAG_DYNAMIC_COMPLETE)
    payload.extend(dynamic_data)
    return bytes(payload)


def build_get_shabby_reply_payload(payload):
    """Build the reply for a DIRSRV GetShabby request.

    Request payload: `03 [4-byte LE shabby_id] 83 85`
      - `03` = DwordParam tag, value = the Shabby ID
      - `83 85` = recv descriptors telling us the reply tags

    Reply: `83 [DWORD status] 87 88 [icon file bytes — raw, to end of packet]`
    Same shape as GetProperties/LOGSRV: static section terminated by 0x87,
    then 0x88 dynamic-complete with raw data (no length prefix — client
    reads to packet end). 0x85 with length-prefix hangs
    MPCCL.ProcessTaggedServiceReply because it won't signal completion
    (see onlstmt.py:175-179). On unknown shabby_id we return status=0 with
    an empty blob; the client handles size==0 by leaving the cache slot
    NULL (forbidden glyph).
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
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE])
        + blob
    )


# --- Payload builders used by tests ---


def build_dirsrv_service_map_payload():
    return build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
