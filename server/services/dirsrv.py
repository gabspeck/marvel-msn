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


def build_dirsrv_reply_payload(request=None):
    """Build a DIRSRV GetProperties reply.

    Reply: dword(status) + dword(node_count) + end-static + dynamic-complete + property records.
    """
    if request is None:
        request = DirsrvRequest()

    requested_props = [p for p in request.prop_group.split('\x00') if p]
    is_children = request.dword_0 == 1

    print(f"[DIRSRV] node={request.node_id} children={is_children} props={requested_props}")

    records = []

    if not is_children:
        props = []
        for name in requested_props:
            if name == 'q':
                props.append((0x03, "q", struct.pack('<I', 1)))
            else:
                props.append((0x03, name, struct.pack('<I', 0)))
        records.append(build_property_record(props))
    else:
        if request.node_id == "0:0":
            msn_central = []
            for name in requested_props:
                if name == 'p':
                    msn_central.append((0x0E, "p",
                        struct.pack('<I', 11) + b'MSN Central'))
                elif name == 'c':
                    msn_central.append((0x03, "c", struct.pack('<I', 3)))
                elif name == 'h':
                    msn_central.append((0x03, "h", struct.pack('<I', 1)))
                elif name == 'a':
                    msn_central.append((0x03, "a", struct.pack('<I', 0)))
                elif name == 'i':
                    msn_central.append((0x03, "i", struct.pack('<I', 0)))
                elif name in ('wv', 'tp', 'w', 'l'):
                    msn_central.append((0x0E, name, struct.pack('<I', 0)))
                else:
                    msn_central.append((0x03, name, struct.pack('<I', 0)))
            records.append(build_property_record(msn_central))
        else:
            records.append(build_property_record([]))

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
