"""OLREGSRV service handler: On-Line Registration.

SIGNUP.EXE's "Get the latest product details / free-trial offers /
update local phone numbers" step opens a pipe on svc_name="OLREGSRV"
(version 1).  Without a discovery reply the client waits ~32 s then
pipe-closes, so at minimum we need to advertise the IID table.

Per-selector request/reply shapes still need to be reverse-engineered
from SIGNUP.EXE's COM proxy layer — for now every selector returns
None so the server log captures exactly what the client asks for and
we can flesh out the handlers one at a time.
"""
from ..config import OLREGSRV_INTERFACE_GUIDS
from ..mpc import (
    build_discovery_host_block, build_discovery_payload, build_service_packet,
)


class OLREGSRVHandler:
    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(OLREGSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload,
                       server_seq, client_ack):
        print(f"  [OLREGSRV] request class=0x{msg_class:02x} "
              f"selector=0x{selector:02x} req_id={request_id} "
              f"payload_len={len(payload)}")
        return None


def build_olregsrv_service_map_payload():
    return build_discovery_payload(OLREGSRV_INTERFACE_GUIDS)
