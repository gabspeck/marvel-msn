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
    build_tagged_reply_dword,
    is_oneway,
    parse_request_params,
)
from ._dispatch import log_unhandled_selector
from ._handler import ServiceHandler

log = logging.getLogger(__name__)

# Only the commit head gets a reply. Replying to the pre-check aborts signup
# with "important part of signup cannot be found" (client session).
OLREGSRV_SELECTOR_COMMIT = 0x01
OLREGSRV_SELECTOR_PRECHECK = 0x02

# MOSRPC message class for a normal (non-oneway) call head. The oneway
# continuations ride on 0xe6/0xe7 which trip MPC_CLASS_ONEWAY_MASK (0xE0).
OLREGSRV_MSG_CLASS_CALL = 0x01


class OlregsrvHandler(ServiceHandler):
    GUIDS = OLREGSRV_INTERFACE_GUIDS

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if log.isEnabledFor(logging.INFO):
            _, recv_descs = parse_request_params(payload)
            log.info("recv_descs=%s", ",".join(f"0x{d:02x}" for d in recv_descs) or "-")
        # 0xe6/0xe7 continuations are known one-way frames that carry the
        # tail of the commit buffers; they must not be acked.
        if is_oneway(msg_class):
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class,
                selector,
                len(payload),
            )
            return None
        if msg_class == OLREGSRV_MSG_CLASS_CALL and selector == OLREGSRV_SELECTOR_PRECHECK:
            log.info("precheck no_reply")
            return None
        if msg_class != OLREGSRV_MSG_CLASS_CALL or selector != OLREGSRV_SELECTOR_COMMIT:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        # HRESULT=0 (not an empty body): the proxy copies this dword
        # into its status word before the switch runs, so the success
        # branch fires and the error dialog (res=0xd2) is skipped.
        reply_body = build_tagged_reply_dword(0)
        log.info("commit_reply status=0 class=0x%02x selector=0x%02x", msg_class, selector)
        return self.reply(msg_class, selector, request_id, reply_body, server_seq, client_ack)
