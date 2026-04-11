"""LOGSRV service handler: login, password change, service discovery."""
import struct

from ..config import LOGSRV_INTERFACE_GUIDS, TAG_END_STATIC
from ..mpc import (
    build_host_block, build_discovery_host_block,
    build_service_packet, build_tagged_reply_dword,
    build_tagged_reply_var, build_discovery_payload,
    parse_request_params,
)
from ..models import VarParam


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
        if selector == 0x00:
            reply_payload = _BOOTSTRAP_PAYLOAD
        elif selector == 0x01:
            reply_payload = _handle_password_change(payload)
        elif selector == 0x0A:
            reply_payload = _handle_billing_query()
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
    print("  [LOGSRV] Billing/account info query")
    buf = bytearray(0x41c)  # 1052 bytes, zero-filled

    # Status = 0 (success)
    struct.pack_into('<I', buf, 0x00, 0)

    # OI: address fields (offsets relative to OI start at byte 8)
    oi = 8
    _put_str(buf, oi + 0x3b, 'Microsoft')      # first name
    _put_str(buf, oi + 0x69, 'User')            # last name
    struct.pack_into('<I', buf, oi + 0x1d0, 1)  # country ID (1 = US)
    _put_str(buf, oi + 0x1d8, '1 Microsoft Way')  # address
    _put_str(buf, oi + 0x201, 'Redmond')        # city
    _put_str(buf, oi + 0x253, 'WA')             # state
    _put_str(buf, oi + 0x27c, '98052')          # ZIP
    _put_str(buf, oi + 0x2bd, '425-882-8080')   # phone

    # PM: payment method
    pm = 0x300
    struct.pack_into('<I', buf, pm + 0x00, 1)   # type = CHARGE
    _put_str(buf, pm + 0x19, '411111******1111')  # card number

    return build_tagged_reply_var(0x84, bytes(buf))


def _put_str(buf, offset, s):
    """Write a NUL-terminated ASCII string into a buffer at offset."""
    encoded = s.encode('ascii') + b'\x00'
    buf[offset:offset + len(encoded)] = encoded


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
    print(f"  [LOGSRV] Password change: '{old_pw}' -> '{new_pw}'")
    return build_tagged_reply_dword(0)


# --- Payload builders used by tests ---

def build_logsrv_bootstrap_payload():
    return _BOOTSTRAP_PAYLOAD


def build_logsrv_service_map_payload():
    return build_discovery_payload(LOGSRV_INTERFACE_GUIDS)
