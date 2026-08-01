"""SASRV system-administration service.

SACLIENT.DLL is the wire client. `CSysAdminClient::CSysAdminClient` @
0x7F3410F1 CoCreates the MPC marshaller and opens a pipe on service `"SASRV"`
version 4 with the 29-IID table at 0x7F347570.

Only the master-list enumerator is served, because that is what the node
Properties sheet needs. `CMosTreeNode::AddSecurityPropSheet` @ MOSSHELL
0x7F3FF2B1 appends the Security page (dialog 0x68) whenever the sheet is in
edit mode, and its WM_INITDIALOG @ 0x7F4026D3 runs:

    CreateSysAdminClient(4, 0)              -- opens this pipe
    GetProperty(node, "m", &token_id, 4)    -- DIRSRV, the node's token id
    CreateSysAdminMasterTokenList(client)
      -> Fetch(kind=10)                     -- selectors 0x02 then 0x04
    GetCount(&n); GetItem(i, ...) * n       -- selector 0x05 per page
    (release)                               -- selector 0x03

A failure before `Fetch` returns raises string 0xDB "Cannot display Security
page." A `Fetch` that returns 0 with a count of 0 skips the item loop and the
page loads with an empty Token name combo — that is the state this handler
produces today.

The same `CreateSysAdminClient(4, 0)` gates the Context page: MOSSHELL
0x7F402098 calls it whenever the DIRSRV `y` property reads back, whatever its
value, and raises string 0xDE on failure. Discovery alone satisfies that call.
"""

import logging
import struct

from ..config import SASRV_INTERFACE_GUIDS, TAG_DYNAMIC_COMPLETE_SIGNAL, TAG_END_STATIC
from ..models import DwordParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    parse_request_params,
)
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)

# Selectors reached through the CSysAdminClient vtable at SACLIENT 0x7F347748.
# All four are confirmed against captured traffic.
SASRV_SELECTOR_BEGIN_ENUM = 0x02  # slot +0x04
SASRV_SELECTOR_END_ENUM = 0x03  # slot +0x08
SASRV_SELECTOR_READ_ENUM_RESULTS = 0x04  # slot +0x0C
SASRV_SELECTOR_GET_LIST_PAGE = 0x05  # slot +0x10

# Master-list kinds. `FUN_7F3438E4` rejects anything outside 7..0x0B with 0x12
# before it reaches the wire, so those five are the whole vocabulary. Only the
# token list has a confirmed caller — CreateSysAdminMasterTokenList hard-codes
# kind 10 at SACLIENT 0x7F343758.
SASRV_LIST_KIND_MIN = 7
SASRV_LIST_KIND_MAX = 0x0B
SASRV_LIST_KIND_TOKENS = 10

# Security tokens offered to the Security page's Token name combo, as
# (token_id, name). A node's DIRSRV `m` property names one of these ids, and
# the page preselects the matching row.
#
# Names are placeholders — no capture of a real Marvel token list exists.
SASRV_TOKENS = (
    (1, "Everyone"),
    (2, "MSN Staff"),
    (3, "Forum Managers"),
)

_LIST_KINDS = {SASRV_LIST_KIND_TOKENS: SASRV_TOKENS}

# Rows per page. `SaMasterTokenList_GetItem` @ SACLIENT 0x7F343973 caches a
# fetched page as `(index / 0x14) * 0x14 + n`, so one reply covers 20 rows
# starting at a multiple of 20.
SASRV_LIST_PAGE_ROWS = 0x14

# Longest name the client keeps: GetItem copies it with `lstrcpynA(dst, src,
# 0x5C)`, so anything past 91 characters plus its NUL is dropped client-side.
SASRV_TOKEN_NAME_MAX = 0x5C - 1

# Returned when the requested list kind has no backing collection here. The
# client surfaces any non-zero Fetch result as "Cannot display Security page".
SA_E_BAD_LIST_KIND = 0x12


class SASRVHandler:
    """Serve SACLIENT's master-list enumerator on one logical pipe.

    Enumeration state is per instance, which matches its lifetime on the wire:
    the client opens a pipe, runs one BeginEnum/ReadEnumResults pair per list,
    and closes it with the property sheet.
    """

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        self._enums = {}
        self._next_handle = 1

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_sasrv_service_map_payload()
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if selector == SASRV_SELECTOR_BEGIN_ENUM:
            reply_payload = self.build_begin_enum_reply_payload(payload)
        elif selector == SASRV_SELECTOR_READ_ENUM_RESULTS:
            reply_payload = self.build_read_enum_results_reply_payload(payload)
        elif selector == SASRV_SELECTOR_END_ENUM:
            reply_payload = self.build_end_enum_reply_payload(payload)
        elif selector == SASRV_SELECTOR_GET_LIST_PAGE:
            reply_payload = self.build_get_list_page_reply_payload(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def build_begin_enum_reply_payload(self, payload):
        """Open an enumeration over one master list (selector 0x02).

        `SaClient_BeginEnum` @ SACLIENT 0x7F341238 packs the list kind, a DWORD
        the caller always passes as 0, and a trailing byte, then asks for two
        DWORDs. An observed request for the token list is:

            03 0a000000  03 00000000  01 00  83 83

        The receive descriptors are bound status first, handle second, so the
        reply is `0x83 [status] 0x83 [handle] 0x87`. The handle comes back on
        selector 0x04.
        """
        send_params, _ = parse_request_params(payload)
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        kind = dwords[0] if dwords else None

        if kind not in _LIST_KINDS:
            log.warning(
                "begin_enum unsupported list kind=%s range=%d..%d payload=%s",
                kind,
                SASRV_LIST_KIND_MIN,
                SASRV_LIST_KIND_MAX,
                payload.hex(),
            )
            return _build_two_dword_reply(SA_E_BAD_LIST_KIND, 0)

        handle = self._next_handle
        self._next_handle += 1
        self._enums[handle] = kind
        log.info("begin_enum status=0 kind=%d handle=%d", kind, handle)
        return _build_two_dword_reply(0, handle)

    def build_read_enum_results_reply_payload(self, payload):
        """Report how many rows the open enumeration holds (selector 0x04).

        `SaClient_ReadEnumResults` @ SACLIENT 0x7F3413C1 sends the handle and
        binds the count descriptor before the status one, so the reply is
        `0x83 [count] 0x83 [status] 0x87`. The count lands at list+0x18, which
        is what `GetCount` @ 0x7F343965 hands the Security page.
        """
        send_params, _ = parse_request_params(payload)
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        handle = dwords[0] if dwords else None

        kind = self._enums.get(handle)
        if kind is None:
            log.warning("read_enum_results unknown handle=%s payload=%s", handle, payload.hex())
            return _build_two_dword_reply(0, SA_E_BAD_LIST_KIND)

        count = len(_LIST_KINDS[kind])
        log.info("read_enum_results status=0 handle=%d kind=%d count=%d", handle, kind, count)
        return _build_two_dword_reply(count, 0)

    def build_get_list_page_reply_payload(self, payload):
        """Return one page of list rows (selector 0x05).

        Observed request, fetching row 0 of handle 1:

            03 01000000  03 00000000  02 0400  83 85

        so `SaClient_GetListPage` @ SACLIENT 0x7F341480 sends the enumeration
        handle, the start index, and a WORD the caller hard-codes to 4. It
        binds one status DWORD plus a dynamic field (descriptor 0x85).

        The reply is `0x83 [status] 0x87 0x86 [blob]`. The `0x86` matters —
        GetListPage waits with `Wait(INFINITE)`, and only dynamic-complete
        signals that wait, the same hazard as GetShabby (PROTOCOL.md §7.2.7).

        The blob is the row page. `SaMasterTokenList_GetItem` @ 0x7F343973
        walks it as `[u32 token_id][ASCIIZ name]`, advancing `4 + strlen + 1`
        per row, and caches it as `(index / 0x14) * 0x14 + n` — so a request
        for index i wants the 20 rows starting at `(i // 20) * 20`.
        """
        send_params, _ = parse_request_params(payload)
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        handle = dwords[0] if dwords else None
        start = dwords[1] if len(dwords) > 1 else 0
        log.info(
            "get_list_page request handle=%s index=%s payload=%s",
            handle,
            start,
            payload.hex(),
        )

        # The list kind rides the handle, not the request. An unknown handle
        # still gets an empty page: GetItem reads a short blob as "row absent"
        # and returns a failure the page handles, whereas no reply at all would
        # strand its Wait(INFINITE) on the shell's UI thread.
        kind = self._enums.get(handle)
        rows = _LIST_KINDS.get(kind, ())
        if kind is None:
            log.warning("get_list_page unknown handle=%s payload=%s", handle, payload.hex())

        page_start = (start // SASRV_LIST_PAGE_ROWS) * SASRV_LIST_PAGE_ROWS
        page = rows[page_start : page_start + SASRV_LIST_PAGE_ROWS]
        blob = b"".join(
            struct.pack("<I", token_id) + name[:SASRV_TOKEN_NAME_MAX].encode("ascii") + b"\x00"
            for token_id, name in page
        )
        log.info(
            "get_list_page_reply status=0 kind=%s page_start=%d rows=%d blob_len=%d",
            kind if kind is not None else "-",
            page_start,
            len(page),
            len(blob),
        )
        return (
            build_tagged_reply_dword(0)
            + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
            + blob
        )

    def build_end_enum_reply_payload(self, payload):
        """Close an enumeration (selector 0x03).

        `SaClient_EndEnum` @ SACLIENT 0x7F341313 sends the handle and binds one
        receive DWORD, so the reply is `0x83 [status] 0x87`. The Security page
        runs it right after `ReadEnumResults`, before it touches any row — a
        count of 0 means the item loop never happens and teardown follows
        immediately. Observed as `03 <handle> 83`.

        An unknown handle still answers 0. The client discards the result, and
        failing a release would only strand the page's cleanup path.
        """
        send_params, _ = parse_request_params(payload)
        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        handle = dwords[0] if dwords else None

        kind = self._enums.pop(handle, None)
        log.info("end_enum status=0 handle=%s kind=%s", handle, kind if kind is not None else "-")
        return build_tagged_reply_dword(0) + bytes([TAG_END_STATIC])


def _build_two_dword_reply(first, second):
    return (
        build_tagged_reply_dword(first) + build_tagged_reply_dword(second) + bytes([TAG_END_STATIC])
    )


def build_sasrv_service_map_payload():
    return build_discovery_payload(SASRV_INTERFACE_GUIDS)
