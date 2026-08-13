"""BBIRService handler: the Blackbird information-retrieval (Find) channel.

Opened by `IRMpcConnection::DoConnect` (IRCS.DLL:0x10005fda) via
`CMPCConnection("BBIRService", {27916FC1-…}, 1, NULL)`.  Reached from the Find
UI: BBDESIGN.EXE / FINDAPP.EXE / VIEWDLL.DLL → IRFIND.DLL → IRCS.DLL.  IRCS is
the only module in the shipped tree that names the service, so there is one
caller, one IID, and — as with `Bbird_OB` — the method number is the wire
selector.

## Methods

`CMPCMethod::Init(conn, N)` sites, with the `Execute` that fills the request:

    0x02  CCmdGetSrcs       IRCS 0x10003be0 / exec 0x10003d72   one u32
    0x04  CCmdGetSrchObjs   IRCS 0x100082af / exec 0x10008429   no params
    0x05  CCmdQuery         IRCS 0x10004524 / exec 0x100046f4   the serialized
                                                                IQuerySpec + u32

A search from the Find UI goes straight to 0x05; 0x02 is not a prerequisite.
Observed head (2026-08-13, the first BBIRService request to reach a server):

    03 00000000        u32   0
    05 01 1d020000     chunked ref: stream 1, 0x21d bytes — the IQuerySpec
    03 00000000        u32   0
    85                 receive descriptor: one dynamic field

`CCmdQuery::Execute` fills a 0x400-byte CoTaskMem buffer from the IQuerySpec's
`vt[0x38]` and hands it to `AddParam(void*, ulong)`; over a threshold COSCL
turns that into a chunked reference, so the spec follows on class-0xE6/0xE7
frames rather than inline.  The head is therefore not answerable on arrival.

## Reply framing

All three command objects derive from COSCL's `CMPCDynReadDataSource` (its
vtable is stored at IRCS 0x10003c8b / 0x100045d3 / 0x1000835a), so a reply is a
dynamic read stream.  COSCL pumps it into `CCmdExec::MoreData`
(IRCS:0x10002980), which appends to `CIRClientRcvInfo` and then drains
`GetObj` until the buffer holds no complete record.

The stream is a run of records.  Header is 6 bytes, little-endian, read through
MFC `CArchive` (`CIRClientRcvInfo::PeekHeader`, IRUT.DLL:0x1000bcdd, which
requires `pos + cbBody <= avail`, so `cbBody` covers the body alone):

    WORD  wTag
    DWORD cbBody
    BYTE  body[cbBody]

`wTag` selects the class IRUT instantiates (`CIRClientRcvInfo::GetObj`,
IRUT.DLL:0x1000bdda).  Any other tag throws E_NOINTERFACE:

    0x01  IResultRow            0x21  ISrvrMsgQryProcessing  {270998B1-…}
    0x02  ISortInfos            0x22  ISrvrMsgCmdCanceled    {270998B2-…}
    0x03  IPropInfos            0x23  ISrvrMsgCmdCompleted   {270998B3-…}
    0x04  IContextInfo          0x24  ISrvrMsgCmdApproxWait  {270998B4-…}
    0x09  ISrvrObjInfo
    0x0A  body opens with a 16-byte CLSID; the object is created from it and
          QI'd to IUnknown

IRCS runs two dispatchers over those tags: 0x10002871 for GetSrcs and
GetSrchObjs (handles 0x0A, 0x22, 0x23, 0x24) and 0x10007a0c for the query
(handles 0x01-0x04 and 0x21-0x24).

`CSrvrMsgQryCompleted::Serialize` (IRUT.DLL:0x100191d9) writes two dwords —
time waited, time processed — so tag 0x23 has an 8-byte body.

The query's `0x85` descriptor confirms the shape: an empty static section, then
the whole reply in the dynamic body — `0x87 0x88 <stream>` followed by a bare
`0x86`, the same two-block pattern the Bbird_OB read side uses.

## Scope

This serves the empty answer: every method replies with a lone tag-0x23
record, which ends the command with no sources, no search objects, and no
result rows.  The streamed IQuerySpec is decoded (`blackbird.irquery`) and
logged, so the terms and scope a search asks for are visible, but nothing
matches against them yet: that needs the IIRPersistStream layouts of the
result classes (`CDocSource` behind tag 0x0A, `IResultRow`, `IPropInfos`,
`ISortInfos`, `IContextInfo`) and an index over the published title.

Every request is logged in full and written to `captures/blackbird/`, the
reassembled query spec included.
"""

import logging
import pathlib
import time

from ..blackbird import irindex
from ..blackbird.irquery import IRQueryError, parse_query_spec
from ..blackbird.irresults import (
    PROP_TYPE_STRING,
    PROP_TYPE_TIME,
    PropInfo,
    ResultRow,
    encode_bbir_time,
    encode_cmd_completed,
    encode_result_stream,
)
from ..config import (
    BBIR_INTERFACE_GUIDS,
    MPC_CLASS_CONTINUATION_LAST,
    MPC_CLASS_ONEWAY_MASK,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ..models import ChunkedParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    parse_request_params,
)
from ..session import Session
from ._dispatch import describe_param, log_unhandled_selector

log = logging.getLogger(__name__)

BBIR_SELECTOR_GET_SOURCES = 0x02
BBIR_SELECTOR_GET_SEARCH_OBJECTS = 0x04
BBIR_SELECTOR_QUERY = 0x05

_SELECTOR_NAMES = {
    BBIR_SELECTOR_GET_SOURCES: "get_sources",
    BBIR_SELECTOR_GET_SEARCH_OBJECTS: "get_search_objects",
    BBIR_SELECTOR_QUERY: "query",
}

_CAPTURE_DIR = pathlib.Path(__file__).resolve().parents[3] / "captures" / "blackbird"


def _schema_for(spec):
    """Declare one result column per property the query asked for.

    Most of the requested GUIDs are opaque, and a string column is the safe
    default: the Find UI renders it verbatim. The exception is a property the
    query's own time term filters on. IRFIND formats that column through
    `CTime` (IRFIND.DLL:0x1000e2b0) after reading it with the getter that
    demands type 0x17 (`FUN_1001a14e`), and it does not check the read — a
    column served as anything else leaves the value 0 and faults the client
    on the NULL `CTime::GetLocalTm` returns (observed at IRFIND.DLL:0x1000e425
    with a string-typed column 3).
    """
    dates = spec.time_properties()
    return [
        PropInfo(
            guid=prop.guid,
            name=f"col{index}",
            type=PROP_TYPE_TIME if prop.guid in dates else PROP_TYPE_STRING,
        )
        for index, prop in enumerate(spec.properties)
    ]


def _row_values(doc, columns):
    """Fill each column from what an indexed document offers.

    Date columns carry the document's timestamp packed as BBIR time; the
    string columns cycle through the readable fields in a fixed order, so
    whatever the Find UI renders identifies each column by what shows up.
    """
    strings = [doc.heading, doc.snippet, doc.title, doc.storage_path]
    values = []
    for index, column in enumerate(columns):
        if column.type == PROP_TYPE_TIME:
            values.append(encode_bbir_time(doc.modified))
        else:
            values.append(strings[index] if index < len(strings) else "")
    return values


class BBIRServiceHandler:
    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # The Find UI can open the pipe before the shell login lands, same as
        # the publish channel.
        self.session = session or Session()
        # stream_id → accumulated bytes for chunked fields riding class
        # 0xE6/0xE7 frames. The query spec arrives this way.
        self._streams = {}
        # stream_id → (msg_class, selector, request_id) of the head that quoted
        # it. A head with a chunked field is not answerable until the field has
        # landed, so its reply waits here.
        self._pending_queries = {}
        self._capture_stamp = time.strftime("%Y%m%d-%H%M%S")

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(BBIR_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            return self._take_continuation(msg_class, selector, payload, server_seq, client_ack)

        name = _SELECTOR_NAMES.get(selector, "unknown")
        log.info(
            "bbir_request class=0x%02x selector=0x%02x (%s) req_id=%d payload_len=%d",
            msg_class,
            selector,
            name,
            request_id,
            len(payload),
        )
        send_params, recv_descs = self._log_payload(
            f"cls{msg_class:02x}_sel{selector:02x}_req{request_id}", payload
        )

        if selector not in _SELECTOR_NAMES:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        # A chunked field carries no inline bytes — it rides class-0xE6/0xE7
        # frames that arrive after this head. Answering now would complete the
        # request while the client is still streaming, so the reply waits for
        # the stream to close.
        chunks = [p for p in send_params if isinstance(p, ChunkedParam)]
        if chunks:
            chunk = chunks[0]
            self._pending_queries[chunk.stream_id] = (msg_class, selector, request_id)
            log.info(
                "bbir_await_stream selector=0x%02x (%s) stream=%d declared_bytes=%d",
                selector,
                name,
                chunk.stream_id,
                chunk.total_length,
            )
            return None

        return self._empty_result(msg_class, selector, request_id, server_seq, client_ack)

    def _take_continuation(self, msg_class, stream_id, payload, server_seq, client_ack):
        """Fold one class-0xE6/0xE7 frame into its stream.

        0xE7 closes it, at which point the head that quoted the stream can be
        answered. A continuation payload is raw bytes, not a tagged parameter
        list, so it never goes through `parse_request_params`.
        """
        stream = self._streams.setdefault(stream_id, bytearray())
        stream += payload
        log.debug(
            "bbir_chunk_frame id=%d frame_bytes=%d received=%d",
            stream_id,
            len(payload),
            len(stream),
        )
        if msg_class != MPC_CLASS_CONTINUATION_LAST:
            return None

        del self._streams[stream_id]
        log.info("bbir_chunk_stream_done id=%d bytes=%d", stream_id, len(stream))
        self._capture(f"stream{stream_id}", bytes(stream))

        claim = self._pending_queries.pop(stream_id, None)
        if claim is None:
            log.warning("bbir_chunk_unclaimed id=%d bytes=%d", stream_id, len(stream))
            return None
        msg_class, selector, request_id = claim
        if selector == BBIR_SELECTOR_QUERY:
            body = self._build_query_results(bytes(stream))
            if body is not None:
                return self._dynamic_reply(
                    msg_class, selector, request_id, body, server_seq, client_ack
                )
        return self._empty_result(msg_class, selector, request_id, server_seq, client_ack)

    def _build_query_results(self, blob):
        """Decode the streamed IQuerySpec and answer it from the index.

        Returns None when the spec will not decode — the request still gets
        its empty answer and the capture on disk is what a fix gets written
        against, but an incomplete layout in `irquery` is logged loudly rather
        than swallowed.
        """
        try:
            spec = parse_query_spec(blob)
        except IRQueryError as exc:
            log.error("bbir_queryspec_unparsed bytes=%d err=%s", len(blob), exc)
            return None

        terms = spec.terms()
        log.info(
            "bbir_queryspec terms=%s max_results=%d properties=%d criteria=%d sources=%s",
            ",".join(repr(t) for t in terms) or "-",
            spec.max_results,
            len(spec.properties),
            len(spec.criteria),
            ",".join(str(s.guid) for c in spec.criteria for s in c.sources) or "-",
        )

        columns = _schema_for(spec)
        hits = irindex.search(terms, limit=spec.max_results or None)
        rows = [
            ResultRow(doc_id=index + 1, rank=score, values=_row_values(doc, columns))
            for index, (score, doc) in enumerate(hits)
        ]
        log.info(
            "bbir_query_results rows=%d columns=%d headings=%s",
            len(rows),
            len(columns),
            ",".join(repr(doc.heading) for _score, doc in hits) or "-",
        )
        return encode_result_stream(columns, rows)

    def _empty_result(self, msg_class, selector, request_id, server_seq, client_ack):
        """End the command with no results.

        Two blocks on the same request id: the stream, then a bare 0x86. The
        request declares a lone `0x85` receive descriptor — one dynamic field —
        so the static section is empty and everything rides the dynamic body.
        """
        log.info(
            "bbir_empty_result selector=0x%02x (%s)",
            selector,
            _SELECTOR_NAMES.get(selector, "unknown"),
        )
        return self._dynamic_reply(
            msg_class, selector, request_id, encode_cmd_completed(), server_seq, client_ack
        )

    def _dynamic_reply(self, msg_class, selector, request_id, body, server_seq, client_ack):
        """Two blocks on one request id: the stream, then a bare 0x86.

        0x88 carries the bytes and 0x86 releases the waiter; a reply that
        stops after the 0x88 block delivers everything and still leaves the
        client blocked.
        """
        blocks = [
            bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END]) + body,
            bytes([TAG_DYNAMIC_COMPLETE_SIGNAL]),
        ]
        packets = []
        for block in blocks:
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

    def _log_payload(self, tag, payload):
        """Decode a request head's tagged parameters, log them, keep the bytes.

        Heads only. A continuation payload is raw stream bytes whose first byte
        would decode as a receive descriptor, so it goes to `_capture` instead.

        Returns the decode so the caller can find the chunked field.
        """
        if not payload:
            log.info("bbir_payload %s len=0", tag)
            return [], []
        send_params, recv_descs = parse_request_params(payload)
        log.info(
            "bbir_params %s send=%s recv=%s",
            tag,
            " ".join(describe_param(p) for p in send_params) or "-",
            ",".join(f"0x{d:02x}" for d in recv_descs) or "-",
        )
        log.info("bbir_payload %s len=%d hex=%s", tag, len(payload), payload[:256].hex())
        self._capture(tag, payload)
        return send_params, recv_descs

    def _capture(self, tag, payload):
        """Persist raw request bytes.

        The IQuerySpec the query streams and the parameters the other two
        methods send are the only record of this protocol — no BBIRService
        request had ever reached a server before this handler existed.
        """
        try:
            _CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            path = _CAPTURE_DIR / f"{self._capture_stamp}_bbir_{tag}.bin"
            path.write_bytes(payload)
            log.info("bbir_capture %s bytes=%d", path, len(payload))
        except OSError as exc:
            log.warning("bbir_capture_failed tag=%s err=%s", tag, exc)
