"""DIRSRV service handler: directory browsing, property records."""
import struct

from ..config import DIRSRV_INTERFACE_GUIDS, TAG_END_STATIC, TAG_DYNAMIC_COMPLETE
from ..mpc import (
    build_host_block, build_discovery_host_block,
    build_service_packet, build_tagged_reply_dword,
    build_discovery_payload, decode_dirsrv_request,
)
from ..models import DirsrvRequest


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

    def handle_request(self, msg_class, selector, request_id, payload,
                       server_seq, client_ack):
        """Handle a DIRSRV GetProperties request."""
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
        body.extend(pname.encode('ascii') + b'\x00')
        body.extend(pvalue)
    total_size = 6 + len(body)
    header = struct.pack('<IH', total_size, len(properties))
    return header + bytes(body)


def _blob(s):
    """Length-prefixed ASCII blob body for a type-0x0E property."""
    data = s.encode('ascii', errors='replace')
    return struct.pack('<I', len(data)) + data


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
        return b'\x02'
    data = s.encode('ascii', errors='replace')
    return b'\x01' + data + b'\x00'


# Content for leaf nodes served to the Properties dialog.
# Wire letter → General tab field (corrected 2026-04-15 by live observation):
#   e  → Name            (ASCII cache, type 0x0A)
#   k  → Go word         (was misidentified as Category)
#   ca → Category        (was misidentified as category_price_str)
#   tp → Type
#   z  → Price DWORD     (0 formats as "Free")
#   o  → Rating DWORD    (0 formats as "Not rated")
# Context tab fields (Ghidra FUN_7f401d81):
#   q=LCID DWORD, r/s/t/n/on/v/w=strings, y=VendorID DWORD, p=size DWORD.
MSN_TODAY_CONTENT = {
    'name':        'MSN Today',                                    # e  — Name
    'go_word':     'today',                                         # k  — Go word
    'category':    'News',                                          # ca — Category
    'type_str':    'News & Features',                              # tp — Type
    'price_dword': 0,                                               # z  — Price (0 = Free)
    'rating_dword': 0,                                              # o  — Rating (0 = Not rated)
    'description': 'Your daily window to MSN.',                    # j  — Description
    'language':    1033,                                            # q  — en-US LCID
    'topics':      'News, Weather, Entertainment',                 # r  — Topics
    'people':      'Microsoft editorial staff',                    # s  — People
    'place':       'Redmond, WA, USA',                             # t  — Place
    'u_value':     '',                                              # u  — hidden
    'forum_mgr':   'MSN Editorial',                                # n  — Forum manager
    'vendor_id':   1,                                               # y  — Vendor ID
    'owner':       'The Microsoft Network',                        # on — Owner
    'created':     'August 24, 1995',                              # v  — Created
    'modified':    'April 15, 2026',                               # w  — Last changed
    'size_bytes':  5 * 1024 * 1024,                                 # p  — Size (DWORD → FormatSizeString)
}


def build_nav_props(requested_props, *, is_container, c_value=0,
                    mnid_a=b'\x00' * 8, title='MSN Today'):
    """Props for DSNAV GetChildren — the navigation/list view.

    Keeps the stable-state encoding proven to not OOM:
    - a/c/h/b/x structural props
    - e = title string (0x0B UTF-16 cache — icon label reader reads wide).
    - p = title blob (legacy list-view title; ignored by Context tab here)
    - Unknown content props default to DWORD 0.
    """
    out = []
    for name in requested_props:
        if name == 'a':
            out.append((0x0E, 'a', struct.pack('<I', len(mnid_a)) + mnid_a))
        elif name == 'b':
            out.append((0x01, 'b', bytes([0x01 if is_container else 0x00])))
        elif name == 'c':
            out.append((0x03, 'c', struct.pack('<I', c_value)))
        elif name == 'e':
            # Nav 'e' = title string, wire type 0x0A (ASCII cache). Both
            # the icon label and the explorer window titlebar read 'e' via
            # paths that expect ANSI bytes. 0x0B (UTF-16 cache) rendered
            # the icon but truncated the titlebar to "M" at the first wide
            # NUL. 0x0A stores ASCII in the cache, satisfying both readers.
            out.append((0x0A, 'e', _sz(title)))
        elif name == 'h':
            out.append((0x03, 'h', struct.pack('<I', 1 if is_container else 0)))
        elif name == 'x':
            out.append((0x0E, 'x', struct.pack('<I', 1) + b'\x00'))
        elif name == 'p':
            out.append((0x0E, 'p', _blob(title)))
        elif name in ('wv', 'tp', 'w', 'l'):
            out.append((0x0E, name, struct.pack('<I', 1) + b'\x00'))
        else:
            out.append((0x03, name, struct.pack('<I', 0)))
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
    """
    out = []
    for name in requested_props:
        # 'e' must be 0x0A (ASCII cache) — CMosTreeNode::Properties raw-memcpies
        # it to PropertySheetA (ANSI). With 0x0B it would truncate at the first
        # wide NUL ("MSN Today" → "M"). All other strings use 0x0B: their cache
        # is consumed by GetPropSz which runs EnsurePropSzCache's
        # WideCharToMultiByte path to produce the ASCII copy at cache+0xC.
        if name == 'e':
            out.append((0x0A, 'e', _sz(content['name'])))
        elif name == 'j':
            out.append((0x0B, 'j', _sz(content['description'])))
        elif name == 'k':
            out.append((0x0B, 'k', _sz(content['go_word'])))
        elif name == 'ca':
            out.append((0x0B, 'ca', _sz(content['category'])))
        elif name == 'tp':
            out.append((0x0B, 'tp', _sz(content['type_str'])))
        elif name == 'r':
            out.append((0x0B, 'r', _sz(content['topics'])))
        elif name == 's':
            out.append((0x0B, 's', _sz(content['people'])))
        elif name == 't':
            out.append((0x0B, 't', _sz(content['place'])))
        elif name == 'u':
            out.append((0x0B, 'u', _sz(content['u_value']) if content['u_value']
                        else _sz('')))
        elif name == 'n':
            out.append((0x0B, 'n', _sz(content['forum_mgr'])))
        elif name == 'on':
            out.append((0x0B, 'on', _sz(content['owner'])))
        elif name == 'v':
            out.append((0x0B, 'v', _sz(content['created'])))
        elif name == 'w':
            out.append((0x0B, 'w', _sz(content['modified'])))
        elif name == 'p':
            # 'p' is a DWORD byte count. FUN_7f3fba69's special 'p' branch
            # reads `**(cache+4)` (first DWORD of value data) and calls
            # FormatSizeString (vtable+0x140), caching the formatted result
            # at cache+0xC for GetPropSzBuf.
            out.append((0x03, 'p', struct.pack('<I', content['size_bytes'])))
        # DWORD (type 0x03) — Ghidra-confirmed dword reads
        elif name == 'q':
            out.append((0x03, 'q', struct.pack('<I', content['language'])))
        elif name == 'y':
            out.append((0x03, 'y', struct.pack('<I', content['vendor_id'])))
        elif name == 'z':
            out.append((0x03, 'z', struct.pack('<I', content['price_dword'])))
        elif name == 'o':
            out.append((0x03, 'o', struct.pack('<I', content['rating_dword'])))
        # Unknown — safe default
        else:
            out.append((0x03, name, struct.pack('<I', 0)))
    return out


def _is_dialog_request(requested_props):
    """Properties dialog requests never include structural props (a/c/h/b/x)."""
    return bool(requested_props) and not any(
        p in requested_props for p in ('a', 'c', 'h', 'b', 'x')
    )


def build_child_props(requested_props, *, is_container, c_value=0,
                      mnid_a=b'\x00' * 8, content=None, title='MSN Today'):
    if _is_dialog_request(requested_props):
        return build_dialog_props(requested_props, content or MSN_TODAY_CONTENT)
    return build_nav_props(requested_props, is_container=is_container,
                           c_value=c_value, mnid_a=mnid_a, title=title)


def build_dirsrv_reply_payload(request=None):
    """Build a DIRSRV GetProperties reply.

    Reply: dword(status) + dword(node_count) + end-static + dynamic-complete + property records.
    """
    if request is None:
        request = DirsrvRequest()

    requested_props = [p for p in request.prop_group.split('\x00') if p]
    is_children = request.dword_0 == 1

    print(f"[DIRSRV] node={request.node_id} raw={request.node_id_raw.hex()} "
          f"children={is_children} props={requested_props}")

    records = []

    # Map wire node_id → (title, is_container, c_value, mnid_a).
    # 'c' = registered MOS app_id (see reference_mos_apps_registry.md):
    #   1 = Directory_Service (for containers in DSNAV)
    #   7 = Down_Load_And_Run (for browser-URL leaves — MSN Today)
    node_table = {
        "0:0":         ("Root",        True,  1, struct.pack('<II', 0x44000c, 0)),
        "4456460:0":   ("MSN Central", True,  1, struct.pack('<II', 0x44000c, 0)),
        "0:4456460":   ("MSN Central", True,  1, struct.pack('<II', 0x44000c, 0)),
        "4456461:0":   ("MSN Today",   False, 7, struct.pack('<II', 0x44000d, 0)),
    }
    info = node_table.get(request.node_id,
                          ("MSN Today", False, 7, struct.pack('<II', 0x44000d, 0)))
    title, is_container, c_value, mnid_a = info

    msn_central_content = dict(MSN_TODAY_CONTENT, name="MSN Central",
                               type_str="Directory",
                               size_bytes=0)

    if not is_children:
        own = build_child_props(
            requested_props,
            is_container=is_container, c_value=c_value, mnid_a=mnid_a,
            content=msn_central_content if title == "MSN Central" else MSN_TODAY_CONTENT,
            title=title)
        records.append(build_property_record(own))
    else:
        # Permissive fallback: GetChildren on any non-"0:0" node returns MSN
        # Today. This causes visual endless hierarchy (leaf appears as its
        # own child) but is required for CMosTreeNode::Exec to cache 'z'/'c'
        # — returning empty broke dispatch with "task cannot be completed".
        if request.node_id == "0:0":
            msn_central = build_child_props(
                requested_props,
                is_container=True, c_value=1,
                mnid_a=struct.pack('<II', 0x44000c, 0),
                content=msn_central_content,
                title="MSN Central")
            records.append(build_property_record(msn_central))
        else:
            child = build_child_props(
                requested_props,
                is_container=False, c_value=7,
                mnid_a=struct.pack('<II', 0x44000d, 0),
                content=MSN_TODAY_CONTENT,
                title="MSN Today")
            records.append(build_property_record(child))

    node_count = len(records)
    dynamic_data = b''.join(records)

    for i, rec in enumerate(records):
        print(f"[DIRSRV] record[{i}] len={len(rec)} hex={rec.hex()}")

    payload = bytearray()
    payload.extend(build_tagged_reply_dword(0))           # status = success
    payload.extend(build_tagged_reply_dword(node_count))  # node count
    payload.append(TAG_END_STATIC)
    payload.append(TAG_DYNAMIC_COMPLETE)
    payload.extend(dynamic_data)
    return bytes(payload)


# --- Payload builders used by tests ---

def build_dirsrv_service_map_payload():
    return build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
