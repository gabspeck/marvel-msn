"""FindSvc service handler: the Find > MSN Service directory search.

MOSFIND.DLL is the COM server behind the Find dialog. It runs two channels at
once and does not use TREENVCL for the first one:

  * `"FindSvc"` version 2, opened straight on the MPC marshaller by
    `CFindConnection::HrSearch` @ 0x7E9B136A. One method, `GetMethod(1)`. The
    request carries the assembled query string and the reply is a flat array of
    8-byte mnids — matches only, no properties.
  * `"DIRSRV"`, a normal `CTreeNavClient`. `CFindResultSet_GetNextRow` @
    0x7E9B182B takes the mnids 20 at a time (`DAT_7E9B5010`) and resolves each
    batch with one `GetProperties` call for `{f, c, a, tp, w, p}`, which is what
    fills the results window's columns.

So this service answers "which nodes match", and DIRSRV answers "what are
they". The second half is why `build_get_properties_reply_payload` has to
serve a whole mnid array, not just the first id.

The query grammar lives in `findquery`; `docs/MOSFIND.md` has the dialog-side
derivation.
"""

import logging

from ..config import (
    FINDSVC_INTERFACE_GUIDS,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
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
from .findquery import QueryError, node_fields, parse_query

log = logging.getLogger(__name__)

# Interface class: the selector FINDSVC_INTERFACE_GUIDS gave IID 00028BB0, the
# first entry of the array HrSearch hands the marshaller.
FINDSVC_CLASS_SEARCH = 0x01

# The only ServiceMethod MOSFIND asks for — the immediate pushed before
# `service->vtbl[0x0c]` at 0x7E9B1421.
FINDSVC_SEARCH = 0x01

# Status dword. HrSearch returns it verbatim as its HRESULT, so a nonzero value
# surfaces in the dialog; a query the server cannot parse answers 0 with no
# hits instead, which reads as "nothing found".
FINDSVC_STATUS_OK = 0

# Upper bound on one reply. The client streams the whole array and shows every
# row, so this only exists to keep a pathological query (`NAME contains '%'`
# against a large tree) from building a multi-megabyte dynamic section. Real
# MSN capped results too, but at an unknown number.
FINDSVC_MAX_RESULTS = 200


class FindSvcHandler:
    """Handles directory-search requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands.
        self.session = session or Session()

    def build_discovery_packet(self, server_seq, client_ack):
        """Advertise the 00028BB0 run MOSFIND's OpenChannel array asks for.

        Without 00028BB0 the marshaller's slot 0x24 fails with E_NOINTERFACE
        and the dialog reports the failure before a single request reaches the
        wire — which is exactly what a FindSvc pipe that gets no discovery at
        all looks like.
        """
        payload = build_discovery_payload(FINDSVC_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch by (interface class, ServiceMethod)."""
        if msg_class != FINDSVC_CLASS_SEARCH or selector != FINDSVC_SEARCH:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        packets = []
        for block in build_search_reply_blocks(payload):
            host_block = build_host_block(msg_class, selector, request_id, block)
            packets.extend(
                build_service_packet(
                    self.pipe_idx,
                    host_block,
                    (server_seq + len(packets)) & 0x7F,
                    client_ack,
                )
            )
        return packets


def build_search_reply_blocks(payload):
    """Method 1: the mnids of every node matching the query.

    Request, from the MPCCL calls at 0x7E9B1481..0x7E9B14C7:

        04 <cb> <query + NUL>   +0x24 PackSendBytes(szQuery, lstrlenA + 1)
        03 <dword>              +0x28 PackSendDword — always 1, see below
        83                      +0x18 PackReceiveDword(&status)
        83                      +0x18 PackReceiveDword(&cResults)
        85                      +0x40 dynamic receive, +0x48 dispatch

    The DWORD is the out-parameter `CFindDialog_BuildQueryString` @ 0x7E9B2526
    passes down to `CFindDialog_BuildScopeFragment` @ 0x7E9B2FC1, which writes a
    literal 1 into it before it looks at anything. Observed 1 live on a search
    from the stock dialog. Nothing here reads it.

    The reply takes **two** blocks on the same request id:

        0x83 [status] 0x83 [count] 0x87 0x88 [count x 8-byte mnid]
        0x86

    `CFindResultSet_PullMnidChunk` @ 0x7E9B196F reads the iterator's buffer, so
    the ids have to arrive under `0x88` — `0x86` reaches only
    SignalRequestCompletion and never the iterator, and the rows would come out
    empty. But after the last id the pump asks for eight more bytes and waits
    again, and `WaitIncremental` @ MPCCL 0x046049BC answers

        return (request+0x18 == 0) + 0x0B0B000B

    so it keeps returning 0x0B0B000C ("more may come") until something sets
    `request+0x18`. Only SignalRequestCompletion does, and only `0x86` reaches
    it. Ending on `0x88` alone leaves the dialog on "Retrieving results"
    forever with every row already resolved — observed live 2026-08-11.

    Same shape as FTM's download (`_build_start_download_blocks`), for the same
    reason: one 0x88-terminated message carrying the data, then a bare 0x86 to
    end the request. No spin risk here — the pump exits the moment it sees
    0x0B0B000B, unlike the MEDVIEW subscriptions that must avoid 0x86.
    """
    query, arg = _decode_search_request(payload)
    nodes = _search(query)
    mnids = b"".join(node.mnid_a for node in nodes)
    log.info(
        "findsvc_search arg=0x%08x hits=%d query=%r",
        arg,
        len(nodes),
        query,
    )
    for index, node in enumerate(nodes):
        log.info(
            "findsvc_search_hit idx=%d node=%s c=%d name=%r",
            index,
            node.node_id,
            node.app_id,
            node.content.name,
        )
    return [
        build_tagged_reply_dword(FINDSVC_STATUS_OK)
        + build_tagged_reply_dword(len(nodes))
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
        + mnids,
        bytes([TAG_DYNAMIC_COMPLETE_SIGNAL]),
    ]


def _decode_search_request(payload):
    """Pull the query string and the trailing dword out of a method-1 request."""
    send_params, _recv = parse_request_params(payload)
    query = ""
    for param in send_params:
        if isinstance(param, VarParam):
            query = param.data.split(b"\x00", 1)[0].decode("cp1252", errors="replace")
            break
    arg = next((param.value for param in send_params if isinstance(param, DwordParam)), 0)
    return query, arg


def _is_searchable(node):
    """Whether a node belongs in the Find index at all.

    Find lists services, not the content inside them — the "of type" combo has
    an entry for bulletin boards and file libraries but none for the messages
    in them. BBS messages and attachments ride the same content store as the
    directory, yet only the board is a DIRSRV row: `store.records.bbs_node`
    notes that messages are never even asked for `tp`. Left in, they turned up
    in the results window as rows with a blank Type column and a size rendered
    as a message count.
    """
    return node.content.bbs is None or node.is_container


def _search(query):
    """Every directory node the query selects, capped and ordered for display.

    Results come back sorted by name so the window is stable across identical
    searches; the client does not sort, it lists the mnids in the order the
    stream delivers them.
    """
    try:
        predicate = parse_query(query)
    except QueryError as error:
        log.warning("findsvc_query_rejected query=%r error=%s", query, error)
        return []

    hits = [
        node
        for node in _default_store.content.all_nodes()
        if _is_searchable(node) and predicate(node_fields(node))
    ]
    hits.sort(key=lambda node: (node.content.name.casefold(), node.node_id))
    if len(hits) > FINDSVC_MAX_RESULTS:
        log.info("findsvc_search_truncated matched=%d sent=%d", len(hits), FINDSVC_MAX_RESULTS)
        del hits[FINDSVC_MAX_RESULTS:]
    return hits
