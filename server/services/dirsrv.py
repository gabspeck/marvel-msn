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


def build_child_props(requested_props, title, *, is_container, c_value=0, mnid_a=b'\x00' * 8):
    # 'b' is the 1-byte browse-flags property read by ExecuteCommand:
    #   bit 0x01 = container/folder, bit 0x08 = denied. 0 = openable leaf.
    # 'a' is an 8-byte blob used by CMosTreeNode::GetNthChild to build the
    #   child mnid (field_8/field_c).
    # 'c' is app_id for leaf-node Exec → HRMOSExec.
    out = []
    for name in requested_props:
        if name == 'p':
            out.append((0x0E, 'p', struct.pack('<I', len(title)) + title.encode('ascii')))
        elif name == 'a':
            out.append((0x0E, 'a', struct.pack('<I', len(mnid_a)) + mnid_a))
        elif name == 'b':
            out.append((0x01, 'b', bytes([0x01 if is_container else 0x00])))
        elif name == 'c':
            out.append((0x03, 'c', struct.pack('<I', c_value)))
        elif name == 'h':
            out.append((0x03, 'h', struct.pack('<I', 1 if is_container else 0)))
        elif name == 'x':
            # 0-length blob causes client malloc(0) → NULL → FUN_7f3fb9f5
            # returns E_OUTOFMEMORY (received_flag=1 && data_ptr==NULL).
            # Send a 1-byte NUL payload so the cache slot has a real alloc.
            out.append((0x0E, 'x', struct.pack('<I', 1) + b'\x00'))
        elif name in ('wv', 'tp', 'w', 'l'):
            out.append((0x0E, name, struct.pack('<I', 1) + b'\x00'))
        else:
            out.append((0x03, name, struct.pack('<I', 0)))
    return out


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

    if not is_children:
        own = build_child_props(
            requested_props, title=title,
            is_container=is_container, c_value=c_value, mnid_a=mnid_a)
        records.append(build_property_record(own))
    else:
        if request.node_id == "0:0":
            msn_central = build_child_props(
                requested_props, title="MSN Central",
                is_container=True, c_value=1,
                mnid_a=struct.pack('<II', 0x44000c, 0))
            records.append(build_property_record(msn_central))
        else:
            child = build_child_props(
                requested_props, title="MSN Today",
                is_container=False, c_value=7,
                mnid_a=struct.pack('<II', 0x44000d, 0))
            records.append(build_property_record(child))

    node_count = len(records)
    dynamic_data = b''.join(records)

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
