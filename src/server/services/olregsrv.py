"""OLREGSRV service handler: On-Line Registration.

SIGNUP.EXE's signup wizard dispatches one MOSRPC call via
FUN_004063de (page vtable 0x0040b9a0[+4]) after the Submit click:
three AddInput calls (UserInfo / OI / PM buffers) followed by a
single Dispatch, then a 90-second wait on the response proxy.
The dispatch serializes onto the wire as four records:

  class=0x01 sel=0x01  payment method  (card number, expiry, name)
  class=0xe7 sel=0x01  member ID + password
  class=0xe6 sel=0x02  personal name + company
  class=0xe7 sel=0x02  street address + phone

The first (class=0x01) record is the call head; the three
following ones (0xe0 bit set = one-way) are continuation frames
belonging to the same call.  Acking the head with an empty host
block releases the client's vtbl[0x10] wait before its 90s timer
expires.  We don't persist the submitted data yet.
"""

import logging

from ..config import OLREGSRV_INTERFACE_GUIDS
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    parse_request_params,
)

log = logging.getLogger(__name__)


class OLREGSRVHandler:
    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(OLREGSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if log.isEnabledFor(logging.INFO):
            _, recv_descs = parse_request_params(payload)
            log.info("recv_descs=%s", ",".join(f"0x{d:02x}" for d in recv_descs) or "-")
        # Only the sel=0x01 commit head gets a reply.  Replying to the
        # sel=0x02 pre-check aborts signup with "important part of
        # signup cannot be found"; the 0xe6/0xe7 continuations are
        # one-way.
        if msg_class != 0x01 or selector != 0x01:
            return None
        # HRESULT=0 (not an empty body): the proxy copies this dword
        # into its status word before the switch runs, so the success
        # branch fires and the error dialog (res=0xd2) is skipped.
        reply_body = build_tagged_reply_dword(0)
        log.info("commit_reply status=0 class=0x%02x selector=0x%02x", msg_class, selector)
        host_block = build_host_block(msg_class, selector, request_id, reply_body)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def build_olregsrv_service_map_payload():
    return build_discovery_payload(OLREGSRV_INTERFACE_GUIDS)
