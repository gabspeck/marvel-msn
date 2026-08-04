"""MOSABP service handler: MSN member address book / Member Properties sheet.

MOSABP32.DLL is the MAPI address-book provider that ships with Windows 95, not
part of the MSN client update. `CAbConnection` (docs/MOSABP.md) is its wire
client: it CoCreates the MPC marshaller, opens a pipe on service `"MOSABP"`
version 3, resolves IID 00028B22, and calls `GetMethod(<ServiceMethod>)` for
each operation. The method number lands on the wire as the request `selector`;
the class byte is the selector this server assigned that IID in discovery.

The BBS reader reaches it through menu item 0x5B0 "Member Properties...".
`BBSNAV!FUN_7F604316` reads the reader's From box (control 0x3E9), cuts the
string at '@', refuses any domain other than `msn.com`, and calls MOSABP32
ordinal 101 `HrUserDetailsDlg(hwnd, name)`. That builds a `_usr_entryid` with
`HrBuildUeid(ueid, EIDTYPE=1, name, name)` and runs a three-page property sheet
(dialogs 100 "General", 101 "Personal", 102 "Professional") whose WM_INITDIALOG
fills every field out of one `GetUserDetails` reply.

Only that one method is served. `GetValidationList` (1), `UpdateUserDetails`
(11), the table/query methods (9, 12–15) and `EnumDistList` (14) fall into the
unhandled bucket.
"""

import logging
import struct

from ..config import (
    MOSABP_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_END_STATIC,
)
from ..models import DwordParam, VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    parse_request_params,
)
from ..session import Session
from ..store import app_store as _default_store
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)

# Interface class: the selector MOSABP_INTERFACE_GUIDS gave IID 00028B22.
MOSABP_CLASS_AB = 0x01

# `enum ServiceMethod`, read off the immediate each `CAbConnection` member
# pushes before `HrGetMethod` @ 0x7F4D4311. Method 2 and method 10 are the same
# operation reached two ways: 2 keys on the member name at `ueid+0x77`, 10 on
# the account handle at `ueid+0x1C`, chosen by `ueid+0x18 == 4`. BBSNAV always
# builds EIDTYPE 1, so the reader's sheet takes method 2.
MOSABP_GET_VALIDATION_LIST = 0x01
MOSABP_GET_USER_DETAILS = 0x02
MOSABP_CLOSE_TABLE = 0x09
MOSABP_GET_USER_DETAILS_BY_HACCT = 0x0A
MOSABP_UPDATE_USER_DETAILS = 0x0B
MOSABP_QUERY_WW_ROWS = 0x0C
MOSABP_QUERY_RESTRICT_ROWS = 0x0D
MOSABP_ENUM_DIST_LIST = 0x0E
MOSABP_QUERY_ROWS_MORE = 0x0F

# MAPI property types the reply serialiser encodes, from the pair of client
# functions that consume the blob: `FUN_7F4DD472` decides whether a type
# carries a `[cb:u32]` prefix, `FUN_7F4DD4C4` gives the width of the ones that
# do not. Only 0x1E / 0x1F / 0x102 are length-prefixed.
PT_I2 = 0x02
PT_LONG = 0x03
PT_R4 = 0x04
PT_DOUBLE = 0x05
PT_CURRENCY = 0x06
PT_APPTIME = 0x07
PT_BOOLEAN = 0x0B
PT_I8 = 0x14
PT_STRING8 = 0x1E
PT_UNICODE = 0x1F
PT_SYSTIME = 0x40
PT_CLSID = 0x48
PT_BINARY = 0x102

_FIXED_WIDTHS = {
    PT_I2: 2,
    PT_LONG: 4,
    PT_R4: 4,
    PT_DOUBLE: 8,
    PT_CURRENCY: 8,
    PT_APPTIME: 8,
    PT_BOOLEAN: 2,
    PT_I8: 8,
    PT_SYSTIME: 8,
    PT_CLSID: 16,
}
_LENGTH_PREFIXED = (PT_STRING8, PT_UNICODE, PT_BINARY)

# Property tags the Member Properties sheet asks for. The master array lives at
# MOSABP32:0x7F4E8198 with 26 entries; `FUN_7F4D307D` copies it minus six tags
# it never sends (PT_NULL, 0x0FF60102, PR_ENTRYID, PR_SEARCH_KEY,
# PR_GIVEN_NAME, PR_SURNAME, PR_TRANSMITABLE_DISPLAY_NAME) and that filtered
# 20-tag array is what reaches the wire. The dialog field each one drives comes
# from the three WM_INITDIALOG handlers (0x7F4D122F / 0x7F4D12D8 / 0x7F4D136C),
# which call `FUN_7F4D1400(ctrl_id, tag)` per control.
PR_OBJECT_TYPE = 0x0FFE0003
PR_DISPLAY_NAME = 0x3001001E
PR_ADDRTYPE = 0x3002001E
PR_EMAIL_ADDRESS = 0x3003001E  # "Member ID:" (ctrl 301)
PR_DISPLAY_TYPE = 0x39000003
MOS_CITY = 0x6000001E  # "City/Town:" (ctrl 304)
MOS_STATE = 0x6001001E  # "State/Province:" (ctrl 305)
MOS_BIRTH_DATE = 0x6003001E  # "Date of birth:" (ctrl 307)
MOS_SEX = 0x6004001E  # "Sex:" (ctrl 308)
MOS_INTERESTS = 0x6007001E  # "Interests:" (ctrl 311)
MOS_JOB_DESCRIPTION = 0x6008001E  # "Job description:" (ctrl 312)
MOS_COMPANY_NAME = 0x6009001E  # "Company name:" (ctrl 313)
MOS_WORK_CITY = 0x600A001E  # "City/Town:" (ctrl 314)
MOS_WORK_STATE = 0x600B001E  # "State/Province:" (ctrl 315)
MOS_FIRST_NAME = 0x600D001E  # "First name:" (ctrl 302)
MOS_LAST_NAME = 0x600E001E  # "Last name:" (ctrl 303)
MOS_COUNTRY = 0x600F0003  # "Country:" (ctrl 306)
MOS_LANGUAGE = 0x60100003  # "Language:" (ctrl 310)
MOS_MARITAL_STATUS = 0x60110003  # "Marital status:" (ctrl 309)
MOS_WORK_COUNTRY = 0x60120003  # "Country:" (ctrl 316)

# PR_OBJECT_TYPE / PR_DISPLAY_TYPE values for one member: MAPI_MAILUSER and
# DT_MAILUSER. Neither is displayed; the sheet requests them and drops them.
MAPI_MAILUSER = 6
DT_MAILUSER = 0

# PR_ADDRTYPE for an MSN member, the address type MOSABP32 registers as its AB
# provider prefix.
MOSABP_ADDRTYPE = "MOS"


class MOSABPHandler:
    """Handles MSN address-book requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands.
        self.session = session or Session()

    def build_discovery_packet(self, server_seq, client_ack):
        """Advertise IID 00028B22 — the only interface MOSABP32 resolves.

        `HrGetMethod` bails to E_NOINTERFACE before any request reaches the wire
        if this reply omits it, and the sheet never opens.
        """
        payload = build_discovery_payload(MOSABP_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch by (interface class, ServiceMethod)."""
        if msg_class != MOSABP_CLASS_AB or selector != MOSABP_GET_USER_DETAILS:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        reply_payload = build_get_user_details_reply_payload(payload)
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def build_get_user_details_reply_payload(payload):
    """Method 2: one member's details for the tag array the sheet asked for.

    Request, built by `CAbConnection::HrGetUserDetails` @ 0x7F4D4611 through the
    MPCCL request vtable:

        04 <cb> <member id + NUL>   +0x24 PackSendBytes(ueid+0x77, strlen+1)
        03 <cValues:u32>            +0x28 PackSendDword(SPropTagArray.cValues)
        04 <cb> <cValues × u32>     +0x24 PackSendBytes(aulPropTag, cValues*4)
        83                          +0x18 PackReceiveDword(&status)
        85                          +0x48 dispatch, stream flag set by +0x40

    Reply is `0x83 [status=0] 0x87 0x86 [blob]`.

    `0x86`, not `0x88`. The caller waits on request vtable `+0x10`
    (`FUN_04604921`), which blocks on the request's `+0x24` completion event.
    Only `SignalRequestCompletion` — the `0x86` branch of MPCCL
    `ProcessTaggedServiceReply` — sets that one, so a `0x88` reply leaves the
    sheet's thread parked with the hourglass up.

    Status is checked before a byte of the blob is read and returned verbatim as
    the HRESULT, so it is always 0 here. An unknown member resolves to an
    empty-but-valid profile rather than an error, which keeps the failure out of
    a MosError box.
    """
    member_id, tags = _decode_get_user_details_request(payload)
    profile = _default_store.member.get_member(member_id)
    blob = build_member_blob(profile, tags)
    log.info(
        "mosabp_get_user_details member=%r tag_count=%d blob_bytes=%d",
        member_id,
        len(tags),
        len(blob),
    )
    return build_tagged_reply_dword(0) + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + blob


def _decode_get_user_details_request(payload):
    """Pull the member id and the requested tag array out of a method-2 request.

    Two variable params in order — the ASCIIZ member id from `ueid+0x77`, then
    `cValues` four-byte tags — with a DWORD `cValues` between them. The DWORD is
    read for the count rather than trusting the byte length, because the client
    compares its own `cValues` against the count this server writes into the
    blob and fails the call with 0x80040118 on a mismatch (`FUN_7F4DD770`).
    """
    send_params, _recv = parse_request_params(payload)
    var_params = [p.data for p in send_params if isinstance(p, VarParam)]
    dwords = [p.value for p in send_params if isinstance(p, DwordParam)]

    member_id = ""
    if var_params:
        member_id = var_params[0].split(b"\x00", 1)[0].decode("ascii", errors="replace")

    tag_bytes = var_params[1] if len(var_params) > 1 else b""
    count = dwords[0] if dwords else len(tag_bytes) // 4
    count = min(count, len(tag_bytes) // 4)
    tags = list(struct.unpack_from(f"<{count}I", tag_bytes)) if count else []
    return member_id, tags


def build_member_blob(profile, tags):
    """Serialise a member as the property blob `FUN_7F4DD770` @ 0x7F4DD770 parses.

        [count:u32]                    must equal the request's cValues
        per tag, in request order:
            0x1E / 0x1F / 0x102  →  [cb:u32][cb bytes]
            fixed-width type     →  raw bytes, width from the type

    No tag is identified on the wire and none may be skipped: the client walks
    its own request array and applies each tag to whatever sits at the cursor,
    so one missing value shifts every later field. A tag with no data in the
    profile therefore ships an empty string or a zero, never nothing.

    A PT_STRING8 length counts characters without the terminator —
    `FUN_7F4DD182` allocates `cb + 1` and writes the NUL itself.

    A requested type of PT_UNSPECIFIED / PT_NULL / PT_ERROR / PT_OBJECT aborts
    the whole call client-side with 0x80040304, so those cannot be used to
    signal "not found"; the empty value is the only way to say it.
    """
    out = [struct.pack("<I", len(tags))]
    for tag in tags:
        out.append(_encode_value(tag, _member_value(profile, tag)))
    return b"".join(out)


def _encode_value(tag, value):
    """Encode one property value for its tag's MAPI type."""
    prop_type = tag & 0xFFFF
    if prop_type == PT_STRING8:
        data = value.encode("cp1252", errors="replace")
        return struct.pack("<I", len(data)) + data
    if prop_type == PT_UNICODE:
        data = value.encode("utf-16le", errors="replace")
        return struct.pack("<I", len(data)) + data
    if prop_type == PT_BINARY:
        return struct.pack("<I", len(value)) + value
    width = _FIXED_WIDTHS.get(prop_type)
    if width is None:
        raise ValueError(f"MOSABP tag 0x{tag:08X} has unserialisable type 0x{prop_type:04X}")
    return int(value).to_bytes(width, "little", signed=False)


def _member_value(profile, tag):
    """The profile field behind one property tag.

    A tag with no mapping here still ships a value — the empty value for its
    type. Dropping it instead would desynchronise every field after it.
    """
    reader = _TAG_VALUES.get(tag)
    if reader is not None:
        return reader(profile)
    prop_type = tag & 0xFFFF
    if prop_type == PT_BINARY:
        return b""
    if prop_type in _LENGTH_PREFIXED:
        return ""
    return 0


# Tag → the profile field it carries.
_TAG_VALUES = {
    PR_OBJECT_TYPE: lambda _p: MAPI_MAILUSER,
    PR_DISPLAY_TYPE: lambda _p: DT_MAILUSER,
    PR_ADDRTYPE: lambda _p: MOSABP_ADDRTYPE,
    PR_DISPLAY_NAME: lambda p: p.display_name,
    PR_EMAIL_ADDRESS: lambda p: p.member_id,
    MOS_FIRST_NAME: lambda p: p.first_name,
    MOS_LAST_NAME: lambda p: p.last_name,
    MOS_CITY: lambda p: p.city,
    MOS_STATE: lambda p: p.state,
    MOS_COUNTRY: lambda p: p.country_code,
    MOS_BIRTH_DATE: lambda p: p.birth_date,
    MOS_SEX: lambda p: p.sex,
    MOS_MARITAL_STATUS: lambda p: p.marital_status_code,
    MOS_LANGUAGE: lambda p: p.language_code,
    MOS_INTERESTS: lambda p: p.interests,
    MOS_JOB_DESCRIPTION: lambda p: p.job_description,
    MOS_COMPANY_NAME: lambda p: p.company_name,
    MOS_WORK_CITY: lambda p: p.work_city,
    MOS_WORK_STATE: lambda p: p.work_state,
    MOS_WORK_COUNTRY: lambda p: p.work_country_code,
}
