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

Five methods are served: `GetAbContainers` (0), which the address book asks
for first and which lists the containers it can open; `QueryWWRows` (12), the
member list behind a container; `QueryRestrictRows` (13), which resolves a name
typed into a To: field; `CloseTable` (9); and `GetUserDetails` (2).

`GetValidationList` (1) is the gap with a visible symptom — without it the
sheet's Country, Language and Marital status fields render blank, because
`FUN_7F4D1400` resolves those four catalogue codes through validation lists
only that method fills. `UpdateUserDetails` (11), `EnumDistList` (14) and
`QueryRowsMore` (15) fall into the unhandled bucket.
"""

import logging
import struct
import zlib
from dataclasses import dataclass

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
MOSABP_GET_AB_CONTAINERS = 0x00
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

# PR_ADDRTYPE for an MSN member. The address types MOSABP32 knows sit in one
# block at 0x7F4E8010 — `UNKNOWN`, `MSNINET`, `MSNLIST`, `MSN` — alongside the
# `':'` search-key separator and the provider MAPIUID. A member is `MSN`, which
# is also what MOSRXP32 stamps as its own sender addrtype and one of the five
# types its transport claims delivery for (docs/MOSRXP.md §7).
MOSABP_ADDRTYPE = "MSN"

# `_usr_entryid` — a member's address book entry id, the structure
# `MOSMUTIL!HrBuildUeid` (0x7E991036) builds. 184 bytes; same shape MOSRXP
# answers GetConnInfo with.
USR_ENTRYID_LEN = 0xB8
USR_ENTRYID_VERSION = 2
UEID_DISPLAY_NAME_OFFSET = 0x1C
UEID_DISPLAY_NAME_MAX = 0x5B
UEID_MEMBER_NAME_OFFSET = 0x77
UEID_MEMBER_NAME_MAX = 0x41
# EIDTYPE 1 keys the id on the member name at +0x77 — the form
# `HrGetUserDetails` routes to method 2. Type 4 is the account-handle form.
EIDTYPE_MEMBER_NAME = 1

# PR_SEARCH_KEY is `ADDRTYPE:ADDRESS`, separator from 0x7F4E8014, uppercased by
# MAPI convention.
PR_ENTRYID = 0x0FFF0102
PR_SEARCH_KEY = 0x300B0102

# ABCONTAINER, the 0xDC-byte record method 0 answers with. Offsets are the ones
# MOSABP32 reads; see build_ab_container. The two strings are bounded by the
# gap to the next field read: the name at +0x08 runs to +0x49, the second to
# +0xD0.
ABCONTAINER_LEN = 0xDC
AB_NAME_OFFSET = 0x08
AB_NAME_MAX = 0x41
AB_ALT_NAME_OFFSET = 0x49
AB_ALT_NAME_MAX = 0x87
AB_CONTENT_COUNT_OFFSET = 0xD0
AB_DISPLAY_TYPE_OFFSET = 0xD8

# `_cont_entryid` — the container entry id, built client-side by
# `MOSMUTIL!HrBuildCeid` from the record's id field. Same provider MAPIUID as
# `_usr_entryid`, version 2, type 0, container id at +0x1C.
CONT_ENTRYID_LEN = 0x20
CONT_ENTRYID_VERSION = 2
UEID_PROVIDER_UID = bytes.fromhex("1becba6c5f92101bb93d00000b70346a")

# PR_DISPLAY_TYPE for a server-side global list.
DT_GLOBAL = 0x00020000

# MSZIP envelope on the row blob: the two magic bytes MOSMUTIL checks at
# 0x7E994D10, then a raw deflate stream.
CK_MAGIC = b"CK"

# Serialised CSRestriction. `FUN_7F4DDB9B` writes only these two types and
# rejects the rest with E_INVALIDARG. The SPropValue rides as its 16 raw struct
# bytes, so the length is the struct's, not the value's.
RES_AND = 0
RES_PROPERTY = 4
SPROPVALUE_LEN = 0x10

# PR_ANR — MAPI's ambiguous name resolution property. The only thing the client
# restricts on when it resolves a name typed into a To: field.
PR_ANR = 0x360C001E

# Output buffer `HrUncompressWWData` allocates before decompressing. The rows
# have to fit it — the decompressor writes into that buffer and nothing bounds
# it beyond this size.
WW_MAX_UNCOMPRESSED = 27000

# The one container this server publishes.
MOSABP_MEMBER_DIRECTORY_ID = 1
MOSABP_MEMBER_DIRECTORY_NAME = "The Microsoft Network"


@dataclass(frozen=True)
class AbContainer:
    """One address book container, as method 0 serialises it."""

    container_id: int
    display_name: str
    # Served back as tag 0x6013001E by the container's own GetProps
    # (`FUN_7F4D39CB`). What MSN put here is unidentified — nothing in
    # MOSABP32 reads it beyond handing it to the caller.
    alt_name: str
    content_count: int
    display_type: int


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
        if msg_class != MOSABP_CLASS_AB:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        if selector == MOSABP_GET_AB_CONTAINERS:
            reply_payload = build_get_ab_containers_reply_payload()
        elif selector == MOSABP_QUERY_WW_ROWS:
            reply_payload = build_query_ww_rows_reply_payload(payload)
        elif selector == MOSABP_QUERY_RESTRICT_ROWS:
            reply_payload = build_query_restrict_rows_reply_payload(payload)
        elif selector == MOSABP_CLOSE_TABLE:
            reply_payload = build_close_table_reply_payload(payload)
        elif selector == MOSABP_GET_USER_DETAILS:
            reply_payload = build_get_user_details_reply_payload(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def build_get_ab_containers_reply_payload():
    """Method 0: the address book's container list.

    Request carries no send params — `83 83 85`, two receive dwords and the
    `+0x40` stream flag. Reply is
    `0x83 [status=0] 0x83 [cContainers] 0x87 0x86 [cContainers × ABCONTAINER]`.

    `CAbConnection::HrGetAbContainers` (`0x7F4D4423`) allocates
    `cContainers * 0xDC` and memcpys the blob in whole, so the count dword and
    the blob length have to agree — a short blob leaves the tail of the last
    record reading uninitialised heap.

    This is the first call the address book makes on the pipe; until it is
    answered the AB has no container to open and nothing else follows.
    """
    containers = _ab_containers()
    blob = b"".join(build_ab_container(c) for c in containers)
    log.info("mosabp_get_ab_containers count=%d blob_bytes=%d", len(containers), len(blob))
    return (
        build_tagged_reply_dword(0)
        + build_tagged_reply_dword(len(containers))
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + blob
    )


def _ab_containers():
    """The containers this server publishes.

    One: the member directory. MSN's address book had no per-user containers —
    a member's personal list lived in the local .pab — so a single global
    container is the whole tree.
    """
    return [
        AbContainer(
            container_id=MOSABP_MEMBER_DIRECTORY_ID,
            display_name=MOSABP_MEMBER_DIRECTORY_NAME,
            alt_name="",
            content_count=len(_default_store.member.list_members()),
            display_type=DT_GLOBAL,
        )
    ]


def build_ab_container(container):
    """One 0xDC-byte ABCONTAINER record.

    Field offsets come from the three sites that read the array:
    `FUN_7F4DA2E6` builds a container table row out of `+0x00`, `+0x08`,
    `+0xD0` and `+0xD8`; `FUN_7F4DA4E6` and `FUN_7F4DA522` look a container up
    by its id and return the strings at `+0x08` and `+0x49`.

    `+0x04` and `+0xD4` are never read by MOSABP32 and ship zeroed.
    """
    blob = bytearray(ABCONTAINER_LEN)
    struct.pack_into("<I", blob, 0x00, container.container_id)
    for offset, limit, text in (
        (AB_NAME_OFFSET, AB_NAME_MAX, container.display_name),
        (AB_ALT_NAME_OFFSET, AB_ALT_NAME_MAX, container.alt_name),
    ):
        encoded = text.encode("cp1252", errors="replace")[: limit - 1]
        blob[offset : offset + len(encoded)] = encoded
    struct.pack_into("<I", blob, AB_CONTENT_COUNT_OFFSET, container.content_count)
    struct.pack_into("<I", blob, AB_DISPLAY_TYPE_OFFSET, container.display_type)
    return bytes(blob)


def build_usr_entryid(display_name, member_name, eidtype=EIDTYPE_MEMBER_NAME):
    """One member's `_usr_entryid`, as `MOSMUTIL!HrBuildUeid` builds it.

    A resolved recipient is addressed by this: `PR_ENTRYID` is what MAPI hands
    back to the provider to open the member, so a row that answers it with an
    empty value resolves to nothing and Check Names reports the name as
    unrecognised.

    Both names are truncated one short of their field so the terminator always
    fits — `HrBuildUeid` uses `strncpy`, which writes no NUL when the source
    fills the field exactly.
    """
    blob = bytearray(USR_ENTRYID_LEN)
    blob[0x04:0x14] = UEID_PROVIDER_UID
    struct.pack_into("<II", blob, 0x14, USR_ENTRYID_VERSION, eidtype)
    for offset, limit, text in (
        (UEID_DISPLAY_NAME_OFFSET, UEID_DISPLAY_NAME_MAX, display_name),
        (UEID_MEMBER_NAME_OFFSET, UEID_MEMBER_NAME_MAX, member_name),
    ):
        encoded = text.encode("cp1252", errors="replace")[: limit - 1]
        blob[offset : offset + len(encoded)] = encoded
    return bytes(blob)


def build_search_key(member_id):
    """`MSN:<MEMBER ID>` — the `ADDRTYPE:ADDRESS` form, uppercased."""
    return f"{MOSABP_ADDRTYPE}:{member_id}".upper().encode("cp1252", errors="replace") + b"\x00"


def build_cont_entryid(container_id):
    """The 0x20-byte `_cont_entryid` for a container.

    Built client-side by `MOSMUTIL!HrBuildCeid` (`0x7E99108C`) from the id at
    `+0x00` of the record, so this server never puts one on the wire. It is
    here because `FUN_7F4D39CB` keys the container's own GetProps on it and
    reads the id back from `+0x1C` — the shape a future method has to match.
    """
    blob = bytearray(CONT_ENTRYID_LEN)
    blob[0x04:0x14] = UEID_PROVIDER_UID
    struct.pack_into("<III", blob, 0x14, CONT_ENTRYID_VERSION, 0, container_id)
    return bytes(blob)


def build_query_ww_rows_reply_payload(payload):
    """Method 12: a page of member rows for the address book list.

    Request, from `CAbConnection::HrQueryWWRows` @ 0x7F4D4A18:

        03 <handle:u32>             +0x28  table handle, 0 to open one
        04 <cb> <name + NUL>        +0x24  prefix to match, empty for all
        03 <u32>                    +0x28  unidentified
        03 <cRows:u32>              +0x28  rows wanted (the client asks 45)
        03 <cValues:u32>            +0x28  requested tag count
        04 <cb> <cValues × u32>     +0x24  the tags
        83 83 83 83 83 85           five out dwords + the stream flag

    Reply is `83 [status] 83 [p6] 83 [p9] 83 [cRows] 83 [p8] 0x87 0x86 [blob]`,
    in that order — read off the five `+0x18` call sites. Slot 1 is the status
    (`CMP [ESP+0x28], 0` right after the wait, returned verbatim on a mismatch)
    and slot 4 is the row count that sizes the rowset. The remaining three are
    the caller's `param_6`, `param_9` and `param_8` out-params; nothing this
    server has seen reads them, and 0 is the consistent answer for a result
    delivered in one page with no table left open.

    The blob is every row's property blob concatenated and compressed — see
    build_ww_row_blob.
    """
    name, tags, row_limit = _decode_query_ww_rows_request(payload)
    members = _match_members(name, row_limit)
    blob = build_ww_row_blob(members, tags)
    log.info(
        "mosabp_query_ww_rows name=%r tags=%s rows=%d blob_bytes=%d",
        name,
        [f"0x{t:08X}" for t in tags],
        len(members),
        len(blob),
    )
    return (
        build_tagged_reply_dword(0)
        + build_tagged_reply_dword(0)
        + build_tagged_reply_dword(0)
        + build_tagged_reply_dword(len(members))
        + build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + blob
    )


def build_close_table_reply_payload(payload):
    """Method 9: release a table the row queries opened.

    ```
    request:  03 <handle:u32> 83
    reply:    83 [status:u32] 87
    ```

    `HrCloseTable` (`0x7F4D4576`) returns the status verbatim as its HRESULT, so
    a non-zero one surfaces in the address book.

    Nothing is held to release: methods 12 and 13 answer in one page and hand
    back handle 0, so the client is closing a table this server never opened.
    The acknowledgement still has to come.
    """
    send_params, _recv = parse_request_params(payload)
    dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
    handle = dwords[0] if dwords else 0
    log.info("mosabp_close_table handle=%d", handle)
    return build_tagged_reply_dword(0) + bytes([TAG_END_STATIC])


def build_query_restrict_rows_reply_payload(payload):
    """Method 13: rows matching a restriction — the name resolution path.

    Same request as method 12 with a serialised `CSRestriction` in front of the
    name (`HrQueryRestrictRows` @ 0x7F4D4C33 packs it first, straight after the
    handle), and the same five-dword-plus-compressed-rowset reply.

    The client sends this when it resolves a name typed into a To: field: the
    restriction is `RES_PROPERTY RELOP_EQ` on `PR_ANR`, MAPI's ambiguous-name
    property, carrying what was typed.
    """
    restriction, tags, row_limit = _decode_query_restrict_rows_request(payload)
    members = _match_restriction(restriction, row_limit)
    blob = build_ww_row_blob(members, tags)
    log.info(
        "mosabp_query_restrict_rows terms=%s tags=%s rows=%d blob_bytes=%d",
        [(f"0x{tag:08X}", value) for _relop, tag, value in restriction],
        [f"0x{t:08X}" for t in tags],
        len(members),
        len(blob),
    )
    return (
        build_tagged_reply_dword(0)
        + build_tagged_reply_dword(0)
        + build_tagged_reply_dword(0)
        + build_tagged_reply_dword(len(members))
        + build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
        + blob
    )


def _decode_query_restrict_rows_request(payload):
    """Pull the restriction, the requested tags and the row limit out."""
    send_params, _recv = parse_request_params(payload)
    var_params = [p.data for p in send_params if isinstance(p, VarParam)]
    dwords = [p.value for p in send_params if isinstance(p, DwordParam)]

    restriction = parse_restriction(var_params[0]) if var_params else []
    tag_bytes = var_params[2] if len(var_params) > 2 else b""
    row_limit = dwords[2] if len(dwords) > 2 else 0
    count = dwords[3] if len(dwords) > 3 else len(tag_bytes) // 4
    count = min(count, len(tag_bytes) // 4)
    tags = list(struct.unpack_from(f"<{count}I", tag_bytes)) if count else []
    return restriction, tags, row_limit


def parse_restriction(raw):
    """Decode a serialised `CSRestriction` into `[(relop, prop_tag, value)]`.

    `FUN_7F4DDB9B` (`0x7F4DDB9B`) writes only two shapes and rejects everything
    else with `E_INVALIDARG`: a bare `RES_PROPERTY` node, or a `RES_AND` header
    `[0][cSubRestrictions]` followed by that many nodes.

    Each node is `[rt][relop][ulPropTag]` then the `SPropValue`, which
    `FUN_7F4DDEBB` writes as its **16 raw struct bytes** — pointers and
    alignment padding included, all meaningless off the client's heap —
    followed by `[cb:u32][cb bytes]` for the string and binary types. A
    fixed-width value has no trailing bytes and lives in the struct's union at
    `+8`.
    """
    if len(raw) < 4:
        return []
    (rt,) = struct.unpack_from("<I", raw, 0)
    if rt == RES_AND:
        (count,) = struct.unpack_from("<I", raw, 4)
        pos = 8
        terms = []
        for _ in range(count):
            term, pos = _parse_restriction_node(raw, pos)
            terms.append(term)
        return terms
    term, _pos = _parse_restriction_node(raw, 0)
    return [term]


def _parse_restriction_node(raw, pos):
    _rt, relop, prop_tag = struct.unpack_from("<III", raw, pos)
    pos += 12
    (value_tag,) = struct.unpack_from("<I", raw, pos)
    union = raw[pos + 8 : pos + SPROPVALUE_LEN]
    pos += SPROPVALUE_LEN

    prop_type = value_tag & 0xFFFF
    if prop_type in _LENGTH_PREFIXED:
        (cb,) = struct.unpack_from("<I", raw, pos)
        pos += 4
        data = raw[pos : pos + cb]
        pos += cb
        if prop_type == PT_STRING8:
            value = data.decode("cp1252", errors="replace")
        elif prop_type == PT_UNICODE:
            value = data.decode("utf-16le", errors="replace")
        else:
            value = data
    else:
        value = int.from_bytes(union, "little")
    return (relop, prop_tag, value), pos


def _match_restriction(restriction, row_limit):
    """Members satisfying every term of the restriction.

    Only `PR_ANR` is matched. It is MAPI's ambiguous-name property — there is no
    such field on a member record, it stands for "whatever a person is called" —
    so it is tested against both the member id and the display name, as a
    prefix. A term on any other property matches nothing rather than everything:
    silently ignoring it would resolve a name the client did not ask for.
    """
    members = _default_store.member.list_members()
    for _relop, prop_tag, value in restriction:
        if prop_tag != PR_ANR or not isinstance(value, str):
            log.warning("mosabp_restriction_unmatched tag=0x%08X value=%r", prop_tag, value)
            return []
        needle = value.casefold()
        members = [
            m
            for m in members
            if m.member_id.casefold().startswith(needle)
            or m.display_name.casefold().startswith(needle)
        ]
    if row_limit:
        members = members[:row_limit]
    return members


def _decode_query_ww_rows_request(payload):
    """Pull the name prefix, the requested tags and the row limit out."""
    send_params, _recv = parse_request_params(payload)
    var_params = [p.data for p in send_params if isinstance(p, VarParam)]
    dwords = [p.value for p in send_params if isinstance(p, DwordParam)]

    name = ""
    if var_params:
        name = var_params[0].split(b"\x00", 1)[0].decode("cp1252", errors="replace")

    tag_bytes = var_params[1] if len(var_params) > 1 else b""
    # dwords: handle, unidentified, cRows, cValues
    row_limit = dwords[2] if len(dwords) > 2 else 0
    count = dwords[3] if len(dwords) > 3 else len(tag_bytes) // 4
    count = min(count, len(tag_bytes) // 4)
    tags = list(struct.unpack_from(f"<{count}I", tag_bytes)) if count else []
    return name, tags, row_limit


def _match_members(name, row_limit):
    """Members whose display name starts with `name`, capped at `row_limit`.

    An empty prefix lists the directory — that is what the address book sends
    when it opens the container rather than resolving a typed name.
    """
    members = _default_store.member.list_members()
    if name:
        prefix = name.casefold()
        members = [m for m in members if m.display_name.casefold().startswith(prefix)]
    if row_limit:
        members = members[:row_limit]
    return members


def build_ww_row_blob(members, tags):
    """One property blob per row, concatenated and MSZIP-compressed.

    `HrBuildWWSrowset` (`0x7F4D52F8`) walks the decompressed buffer with
    `ParsePropValueBlob` (`0x7F4DD770`) once per row — the same parser and the
    same per-row format method 2 answers with, so the no-gaps rule in
    build_member_blob applies to every row.

    `HrUncompressWWData` (`0x7F4D53A9`) hands the blob to
    `MOSMUTIL!HrDecompress` unconditionally; there is no uncompressed path, so
    even one row has to be compressed. That codec is MSZIP: the stream is
    checked for the `CK` magic at `0x7E994D10`, and MOSMUTIL carries the three
    deflate tables (code-length order at 0x7E99C4C70, length and distance bases
    at 0x7E99C4CE8 / 0x7E99C4D68), so `CK` + a raw deflate stream is what it
    decodes.
    """
    rows = b"".join(build_member_blob(m, tags) for m in members)
    if len(rows) > WW_MAX_UNCOMPRESSED:
        raise ValueError(
            f"row blob {len(rows)} exceeds the client's {WW_MAX_UNCOMPRESSED}-byte buffer"
        )
    deflate = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return CK_MAGIC + deflate.compress(rows) + deflate.flush()


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
    # An address book row is what a recipient is built from, so these two carry
    # real values rather than the empty default: without an entry id there is
    # nothing to address, and Check Names rejects the name.
    PR_ENTRYID: lambda p: build_usr_entryid(p.display_name, p.member_id),
    PR_SEARCH_KEY: lambda p: build_search_key(p.member_id),
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
