"""OLREGSRV service handler: On-Line Registration.

SIGNUP.EXE's signup wizard dispatches one MOSRPC call via
FUN_004063de (page vtable 0x0040b9a0[+4]) after the Submit click:
three AddInput calls (UserInfo / OI / PM buffers) followed by a
single Dispatch, then a 90-second wait on the response proxy.
The dispatch serializes onto the wire as four records (OSR2 client,
observed):

  class=0x01 sel=0x01  call head: buffer sizes, then the payment method
  class=0xe7 sel=0x01  UserInfo, 0x150 bytes: member ID + password
  class=0xe6 sel=0x02  OI, first 463 of 0x2f8 bytes: name + company
  class=0xe7 sel=0x02  OI, last 297 bytes: street address + phone

The head is the only record that gets a reply: acking it with an
empty host block releases the client's vtbl[0x10] wait before its
90s timer expires. The others are one-way (0xe0 bit set). Their
selector names the input buffer, and 0xe6 marks a fragment with more
to follow, 0xe7 the buffer's last. Once UserInfo and OI are complete
the account exists and can sign in.
"""

import logging

from ..config import OLREGSRV_INTERFACE_GUIDS
from ..mpc import (
    build_tagged_reply_dword,
    is_oneway,
    parse_request_params,
)
from ..store import User
from ..store import app_store as _default_store
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
OLREGSRV_MSG_CLASS_FRAGMENT = 0xE6
OLREGSRV_MSG_CLASS_LAST_FRAGMENT = 0xE7

# Commit input buffers, by the selector their continuations carry.
BUFFER_USER_INFO = 0x01
BUFFER_OI = 0x02

# Field offsets, observed in an OSR2 commit. The member ID field is 0x41 bytes
# wide, the width LOGSRV's login blob gives it too.
USER_INFO_MEMBER_ID = 0x0C
USER_INFO_PASSWORD = 0x4D
OI_FIRST_NAME = 0x3B
OI_LAST_NAME = 0x69


def _asciiz(buf, offset):
    end = buf.find(b"\0", offset)
    return buf[offset : end if end >= 0 else len(buf)].decode("cp1252", errors="replace")


class OlregsrvHandler(ServiceHandler):
    GUIDS = OLREGSRV_INTERFACE_GUIDS

    def __init__(self, pipe_idx, svc_name, session):
        super().__init__(pipe_idx, svc_name, session)
        self._buffers = {}  # selector -> bytes received so far
        self._complete = set()

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if log.isEnabledFor(logging.INFO):
            _, recv_descs = parse_request_params(payload)
            log.info("recv_descs=%s", ",".join(f"0x{d:02x}" for d in recv_descs) or "-")
        if is_oneway(msg_class):
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class,
                selector,
                len(payload),
            )
            self._add_fragment(msg_class, selector, payload)
            return None
        if msg_class == OLREGSRV_MSG_CLASS_CALL and selector == OLREGSRV_SELECTOR_PRECHECK:
            log.info("precheck no_reply")
            return None
        if msg_class != OLREGSRV_MSG_CLASS_CALL or selector != OLREGSRV_SELECTOR_COMMIT:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        self._buffers.clear()
        self._complete.clear()
        # HRESULT=0 (not an empty body): the proxy copies this dword
        # into its status word before the switch runs, so the success
        # branch fires and the error dialog (res=0xd2) is skipped.
        reply_body = build_tagged_reply_dword(0)
        log.info("commit_reply status=0 class=0x%02x selector=0x%02x", msg_class, selector)
        return self.reply(msg_class, selector, request_id, reply_body, server_seq, client_ack)

    def _add_fragment(self, msg_class, selector, payload):
        if msg_class not in (OLREGSRV_MSG_CLASS_FRAGMENT, OLREGSRV_MSG_CLASS_LAST_FRAGMENT):
            return
        self._buffers[selector] = self._buffers.get(selector, b"") + payload
        if msg_class == OLREGSRV_MSG_CLASS_LAST_FRAGMENT:
            self._complete.add(selector)
        if {BUFFER_USER_INFO, BUFFER_OI} <= self._complete:
            self._create_account()
            self._complete.clear()

    def _create_account(self):
        user_info, oi = self._buffers[BUFFER_USER_INFO], self._buffers[BUFFER_OI]
        member_id = _asciiz(user_info, USER_INFO_MEMBER_ID)
        password = _asciiz(user_info, USER_INFO_PASSWORD)
        name = f"{_asciiz(oi, OI_FIRST_NAME)} {_asciiz(oi, OI_LAST_NAME)}".strip()
        user = User(username=member_id, password=password, display_name=name or member_id)
        if _default_store.users.add_user(user):
            log.info("account_created member_id=%r display_name=%r", member_id, user.display_name)
        else:
            log.warning("account_exists member_id=%r", member_id)
