"""LOGSRV service handler: login, password change, service discovery."""
import logging
import struct

from ..config import (
    LOGSRV_INTERFACE_GUIDS, TAG_END_STATIC, MPC_CLASS_ONEWAY_MASK,
)
from ..mpc import (
    build_host_block, build_discovery_host_block,
    build_service_packet, build_tagged_reply_dword,
    build_tagged_reply_var, build_discovery_payload,
    parse_request_params,
)
from ..models import VarParam, DwordParam
from ..store import app_store as _default_store


log = logging.getLogger(__name__)


class LOGSRVHandler:
    """Handles LOGSRV service requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        """Build the IID->selector discovery block for LOGSRV."""
        payload = build_discovery_payload(LOGSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload,
                       server_seq, client_ack):
        """Dispatch a LOGSRV request. Returns a wire packet or None."""
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            log.info("oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                     msg_class, selector, len(payload))
            return None

        if selector == 0x00:
            reply_payload = _BOOTSTRAP_PAYLOAD
        elif selector == 0x01:
            reply_payload = _handle_password_change(payload)
        elif selector == 0x02:
            reply_payload = _handle_signup_post_transfer(payload)
        elif selector == 0x07:
            reply_payload = _handle_signup_query(payload)
        elif selector == 0x0A:
            reply_payload = _handle_billing_query()
        elif selector == 0x0B:
            reply_payload = _handle_pm_commit()
        elif selector == 0x0C:
            reply_payload = _handle_billing_commit()
        elif selector == 0x0D:
            reply_payload = _handle_post_signup_query(payload)
        elif selector == 0x0E:
            reply_payload = _handle_existing_member_phonebook_query(payload)
        else:
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def _build_bootstrap_payload():
    """Build the LOGSRV login reply: 7 dwords + end-static + 16-byte variable.

    Field 0 = login result code (0 = success).
    """
    payload = bytearray()
    for _ in range(7):
        payload.extend(build_tagged_reply_dword(0))
    payload.append(TAG_END_STATIC)
    payload.extend(build_tagged_reply_var(0x84, b'\x00' * 16))
    return bytes(payload)

_BOOTSTRAP_PAYLOAD = _build_bootstrap_payload()

# Minimum success reply for LOGSRV commit selectors (0x0b PM, 0x0c OI).
# Must be a 0x84 variable — a 0x83 dword unblocks WaitForResponse but
# fails the proxy's output_descriptor->m10() type==4 check, which
# surfaces as "Your account information cannot be updated at this time."
# First dword of the buffer is the commit status (0 = silent success,
# 0x1e/0x1f = user message box, anything else = generic error dialog).
# See BILLADD.DLL BillingDlg_ProcessCommitReply @ 0x00434912.
_COMMIT_OK_REPLY = build_tagged_reply_var(0x84, b'\x00' * 4)


def _handle_pm_commit():
    """LOGSRV selector 0x0b — Payment Options > Payment Method OK.
    BILLADD.DLL BillingDlg_CommitPM @ 0x00434b81 submits a 0x11c PM buffer.
    """
    log.info("pm_commit status=0")
    return _COMMIT_OK_REPLY


def _handle_billing_commit():
    """LOGSRV selector 0x0c — Payment Options > Name and Address OK.
    BILLADD.DLL BillingDlg_CommitOI @ 0x00434953 submits a 0x2fc OI
    buffer, fragmented on the wire as class=0xe6/0xe7 one-way
    continuations (filtered out by MPC_CLASS_ONEWAY_MASK).
    """
    log.info("billing_commit status=0")
    return _COMMIT_OK_REPLY


def _handle_billing_query():
    """Handle a billing/account info query (selector 0x0A).

    The client opens this when the user clicks Tools > Billing > Payment Method.
    Reply is a 0x84 variable containing a 0x41c (1052) byte buffer:

      Offset 0x000: dword status (0 = success)
      Offset 0x008: OI (Order Information / address) — NUL-terminated strings:
        +0x3b  First name
        +0x69  Last name
        +0x1d0 Country ID (dword)
        +0x1d8 Address line
        +0x201 City
        +0x253 State
        +0x27c ZIP code
        +0x2bd Phone
      Offset 0x300: PM (Payment Method) — 0x11c bytes:
        +0x00  Type dword (1=CHARGE, 2=DEBIT, 3=DIRECTDEBIT)
        +0x19  Card number string
    """
    log.info("billing_query")
    profile = _default_store.account.get_billing_profile()
    buf = bytearray(0x41c)  # 1052 bytes, zero-filled

    # Status = 0 (success)
    struct.pack_into('<I', buf, 0x00, 0)

    # OI: address fields (offsets relative to OI start at byte 8)
    oi = 8
    _put_str(buf, oi + 0x3b, profile.first_name)
    _put_str(buf, oi + 0x69, profile.last_name)
    struct.pack_into('<I', buf, oi + 0x1d0, profile.country_id)
    _put_str(buf, oi + 0x1d8, profile.address)
    _put_str(buf, oi + 0x201, profile.city)
    _put_str(buf, oi + 0x253, profile.state)
    _put_str(buf, oi + 0x27c, profile.zip)
    _put_str(buf, oi + 0x2bd, profile.phone)

    # PM: payment method
    pm = 0x300
    struct.pack_into('<I', buf, pm + 0x00, profile.payment_type)
    _put_str(buf, pm + 0x19, profile.card_number)

    return build_tagged_reply_var(0x84, bytes(buf))


def _put_str(buf, offset, s):
    """Write a NUL-terminated ASCII string into a buffer at offset."""
    encoded = s.encode('ascii') + b'\x00'
    buf[offset:offset + len(encoded)] = encoded


def _handle_signup_post_transfer(request_payload):
    """Handle LOGSRV selector 0x02 — opened by SIGNUP after the FTM transfer.

    After SIGNUP finishes the FTM download loop for the "LOGSRV" phone-book
    payload, it opens a fresh LOGSRV pipe and calls selector 0x02 with three
    dwords (counter, 0, 0) and one 0x84 recv descriptor.  The reply shape
    isn't RE'd — an empty 0x84 variable is the minimal well-formed payload
    that satisfies the unmarshaller so we can see what the client does next.
    """
    log.info("signup_post_transfer payload_len=%d", len(request_payload))
    return build_tagged_reply_var(0x84, b'')


def _handle_post_signup_query(request_payload):
    """Handle LOGSRV selector 0x0d — opened by SIGNUP right after the
    OLREGSRV commit reply comes back.

    Request: three dwords (country_id, 0, 0) + one 0x84 recv descriptor.
    The call runs in parallel with the OLREGSRV one-way continuation
    frames, so it's not the Congrats-gating step — but leaving it
    unanswered makes the client disconnect.  Reply shape isn't RE'd;
    an empty 0x84 variable is the minimal well-formed answer.
    """
    send_params, _ = parse_request_params(request_payload)
    country = send_params[0].value if send_params and isinstance(send_params[0], DwordParam) else None
    log.info("post_signup_query country_id=%s",
             country if country is not None else "?")
    return build_tagged_reply_var(0x84, b'')


def _handle_existing_member_phonebook_query(request_payload):
    """Handle LOGSRV opcode 0x0e — SIGNUP "I'm already a member → Update
    local phone numbers → Connect" path.

    Request: one send dword (observed=8, semantic unknown) + one 0x83 recv
    descriptor.  The caller SIGNUP.EXE!FUN_004043c1 @ 0x004043c1 opens a
    fresh LOGSRV pipe, issues this opcode, waits, and checks the recv
    dword with CMP/SBB/NEG at 0x004044a7-0x004044ae — returning TRUE iff
    the value is exactly 0.  Any other value leaves the wizard stuck at
    "Starting transfer..." so we must reply with dword=0.
    """
    send_params, _ = parse_request_params(request_payload)
    dw = send_params[0].value if send_params and isinstance(send_params[0], DwordParam) else None
    log.info("existing_member_phonebook dword=%s",
             dw if dw is not None else "?")
    return build_tagged_reply_dword(0)


def _handle_signup_query(request_payload):
    """Handle the SIGNUP.EXE LOGSRV selector 0x07 request.

    Observed on the wire during the "Get the latest product details" flow:
    the request carries no send-side params — just a single recv descriptor
    (0x85) asking for one variable-tagged reply.  The exact reply shape
    hasn't been pinned down from the COM proxy layer yet; returning an
    empty 0x84 variable is the minimal well-formed payload that matches
    the recv descriptor, letting the client's unmarshaller proceed so we
    can observe whatever it does next.
    """
    log.info("signup_query payload_len=%d", len(request_payload))
    return build_tagged_reply_var(0x84, b'')


def _handle_password_change(request_payload):
    """Handle a password change request.

    Reply: dword 0 = success, non-zero = "current password not valid"
    (client shows same message for any non-zero value).
    """
    send_params, _ = parse_request_params(request_payload)
    old_pw = new_pw = '?'
    if len(send_params) > 0 and isinstance(send_params[0], VarParam):
        old_pw = send_params[0].data.split(b'\x00', 1)[0].decode('ascii', errors='replace')
    if len(send_params) > 1 and isinstance(send_params[1], VarParam):
        new_pw = send_params[1].data.split(b'\x00', 1)[0].decode('ascii', errors='replace')
    log.info("password_change old=%s new=%s", old_pw, new_pw)
    return build_tagged_reply_dword(0)


# --- Payload builders used by tests ---

def build_logsrv_bootstrap_payload():
    return _BOOTSTRAP_PAYLOAD


def build_logsrv_service_map_payload():
    return build_discovery_payload(LOGSRV_INTERFACE_GUIDS)
