"""MAPI wire vocabulary shared by MOSABP and MOSRXP."""

import struct

# MAPI property types both providers' serialisers carry. MOSRXP32
# `CConn::HrDSrlProp` @ 0x7F432435 aborts on anything else with 0x1A; MOSABP32
# `FUN_7F4DD472` / `FUN_7F4DD4C4` give the same set, with only PT_STRING8,
# PT_UNICODE and PT_BINARY length-dependent.
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

FIXED_WIDTHS = {
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

PR_OBJECT_TYPE = 0x0FFE0003
PR_DISPLAY_NAME = 0x3001001E
PR_ADDRTYPE = 0x3002001E
PR_EMAIL_ADDRESS = 0x3003001E

MAPI_MAILUSER = 6

# PR_ADDRTYPE of an MSN member. MOSABP32 lists `UNKNOWN`, `MSNINET`, `MSNLIST`
# and `MSN` at 0x7F4E8010; MOSRXP32 stamps `MSN` as its sender addrtype.
MSN_ADDRTYPE = "MSN"

# `_usr_entryid`, 0xB8 bytes, as `MOSMUTIL!HrBuildUeid` @ 0x7E991036 builds
# it: abFlags, provider MAPIUID, version 2, EIDTYPE, then two fixed-width
# name fields. MOSABP addresses a member by it; MOSRXP's GetConnInfo answers
# with one.
USR_ENTRYID_LEN = 0xB8
UEID_PROVIDER_UID = bytes.fromhex("1becba6c5f92101bb93d00000b70346a")
UEID_VERSION = 2
UEID_DISPLAY_NAME_OFFSET = 0x1C
UEID_DISPLAY_NAME_MAX = 0x5B
UEID_MEMBER_NAME_OFFSET = 0x77
UEID_MEMBER_NAME_MAX = 0x41
# EIDTYPE 1 keys the id on the member name at +0x77, the form
# `HrGetUserDetails` routes to MOSABP method 2. MOSABP32 branches on
# `ueid[0x18] == 4` for the account-handle form instead.
EIDTYPE_MEMBER_NAME = 1


def build_usr_entryid(display_name, member_name, eidtype=EIDTYPE_MEMBER_NAME):
    """One member's `_usr_entryid`.

    Both names are truncated one short of their field so the terminator always
    fits: `HrBuildUeid` uses `strncpy`, which writes no NUL when the source
    fills the field exactly.
    """
    blob = bytearray(USR_ENTRYID_LEN)
    blob[0x04:0x14] = UEID_PROVIDER_UID
    struct.pack_into("<II", blob, 0x14, UEID_VERSION, eidtype)
    for offset, limit, text in (
        (UEID_DISPLAY_NAME_OFFSET, UEID_DISPLAY_NAME_MAX, display_name),
        (UEID_MEMBER_NAME_OFFSET, UEID_MEMBER_NAME_MAX, member_name),
    ):
        encoded = text.encode("cp1252", errors="replace")[: limit - 1]
        blob[offset : offset + len(encoded)] = encoded
    return bytes(blob)
