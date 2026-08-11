"""Bbird_OB service handler: the Blackbird "Release to MSN" channel.

Opened by `COSCL!CMPCConnection::Init("Bbird_OB", {EC76D50B-…}, 1, NULL)`
(PUBLISH.DLL:0x40f01243) whenever the Blackbird Release Wizard runs its MSN
target.  `PUBLISH!CPublisher_PublishToMSN` then drives two calls over it:

  method 4  `CMPCMethod(&conn, 4)`     — incremental-publish query.  Its reply
            tells the publisher which objects the data center already holds.
  method 5  `CMPCFileWrite(&conn, 5)`  — the COSCL compound file itself,
            streamed by `stream_copy_to_mpc_filewrite` (0x40f051a5) in 8 KB
            chunks.

`PUBLISH!DELETENODE` (0x40f01210) uses method 1 on the same connection for the
symmetric teardown.

Before this handler, `Bbird_OB` had no entry in SERVICE_HANDLERS: the
connection answered the pipe-open and then sent no discovery packet, so MPCCL
never resolved the interface and the publisher sat on a dead pipe until
BBDESIGN closed it ~22 s later — no request ever reached the server.

Every request is logged in full and written to `captures/blackbird/`, and the
reassembled compound file lands there as `<stamp>_publish.ttl`. Absorbing that
file into the served content tree is not done here — it is a COSCL
compound-file parsing job, tracked against `docs/BLACKBIRD.md` §3.

## Method 4 — incremental-publish query

`CPublisher_PublishToMSN` (0x40f01c7c) builds the call through
`CMPCMethodExecution`, whose operator thunks are one-line jumps into the
execution vtable (COSCL.DLL:0x4021dda2…0x4021de74).  Slot → wire meaning:

    vt[0x24] AddParam(void*, ulong)  send var      vt[0x14] >>(IMosBuffer*&)  recv var
    vt[0x28] <<(ulong)  send dword               vt[0x18] >>(ulong&)  recv dword
                                                 vt[0x20] >>(uchar&)  recv byte

Observed request (2026-08-11, first live publish):

    03 00000000                       u32   flags/mode, 0 on a first publish
    04 9b "x2qrj4anuhas42kd2117sgjalgs"  var   title name, CString + its length
    03 01000000                       u32   client's publish version (+0x3c)
    84 84 84 81 83                    recv descriptors

The reply mirrors those descriptors in order.  What the publisher does with
each is pinned by the code that follows the wait:

    var #1   GUID array      count = size >> 4
    var #2   FILETIME array  count = size >> 3, tree timestamps   (hashtable #2)
    var #3   FILETIME array  count = size >> 3, object timestamps (hashtable #1)
    byte     mode: 0 → clear +0x38; 1 → build both hashtables
    dword    publish version, stored back into +0x3c

All three arrays must report the same count or the publisher throws 0x11.

Mode 0 is the full-publish answer.  It clears +0x38, and every branch in the
`CDPORefMgr` moniker walk that tests `+0x38 == 0` then marks the object new —
so each moniker goes out through `extract_object` and the three arrays are
never dereferenced.  That makes empty arrays correct rather than merely safe:
the client cannot read them in this mode.  Incremental publishing (mode 1)
needs a per-object timestamp store the server does not keep yet.

## Method 5 — file write

One call per 8 KB slice, the last one short.  Observed head:

    03 00000000                       u32   0
    03 01000000                       u32   1
    04 9b "x2qrj4anuhas42kd2117sgjalgs"  var   title name
    03 01000000                       u32   publish version
    05 01 00200000                    chunked ref: stream 1, 0x2000 bytes
    83                                recv descriptor: status dword

The head carries no file data — the slice follows on class-0xE6/0xE7 frames
quoting the stream id, ~463 bytes per frame.  The reply is `83 <status> 87`.
Reassembled, the stream is an OLE2 compound file (`D0 CF 11 E0 A1 B1 1A E1`).
"""

import logging
import pathlib
import time

from ..config import (
    BBIRD_OB_INTERFACE_GUIDS,
    MPC_CLASS_CONTINUATION_LAST,
    MPC_CLASS_ONEWAY_MASK,
)
from ..models import ByteParam, ChunkedParam, DwordParam, VarParam, WordParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_static_reply,
    build_tagged_reply_byte,
    build_tagged_reply_dword,
    build_tagged_reply_var,
    build_tagged_reply_word,
    parse_request_params,
)
from ..session import Session

log = logging.getLogger(__name__)

# Wire msg_class for the one interface Bbird_OB negotiates. See
# BBIRD_OB_INTERFACE_GUIDS.
BBIRD_OB_CLASS = 0x01

# Method selectors named by PUBLISH.DLL's call sites.
BBIRD_OB_SELECTOR_DELETE_NODE = 0x01
BBIRD_OB_SELECTOR_INCREMENTAL_QUERY = 0x04
BBIRD_OB_SELECTOR_FILE_WRITE = 0x05

_SELECTOR_NAMES = {
    BBIRD_OB_SELECTOR_DELETE_NODE: "delete_node",
    BBIRD_OB_SELECTOR_INCREMENTAL_QUERY: "incremental_query",
    BBIRD_OB_SELECTOR_FILE_WRITE: "file_write",
}

# Receive-descriptor sequence the method-4 request declares: three var fields
# (GUIDs, tree FILETIMEs, object FILETIMEs), a mode byte, a publish version.
# The reply is only well-defined against this exact sequence, so a request
# that declares anything else goes unanswered rather than mis-shaped.
_INCREMENTAL_QUERY_DESCRIPTORS = (0x84, 0x84, 0x84, 0x81, 0x83)

# Mode 0 tells the publisher nothing on the server is current, so it ships
# every object. See the module docstring.
_PUBLISH_MODE_FULL = 0x00

# The dword every method-5 call waits on. MSN failures are 0x8B0Bxxxx, which
# COSCL's file-write path treats as fatal; 0 lets the copy loop continue.
_STATUS_OK = 0x00000000

_CAPTURE_DIR = pathlib.Path(__file__).resolve().parents[3] / "captures" / "blackbird"


class BbirdOBHandler:
    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands. Blackbird
        # publishes over the same MOSCP transport as the shell, so a release
        # started after sign-in inherits that session.
        self.session = session or Session()
        # stream_id → accumulated bytes for chunked fields riding class
        # 0xE6/0xE7 frames. The compound file arrives this way.
        self._streams = {}
        # stream_id → (request_id, recv descriptors) of the method-5 head that
        # quoted it. The head is acked only once its frames have drained, so
        # the ack doubles as flow control on the publisher's copy loop.
        self._pending_writes = {}
        # The compound file, reassembled across every method-5 call.
        self._blob = bytearray()
        self._blob_title = ""
        self._capture_stamp = time.strftime("%Y%m%d-%H%M%S")

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(BBIRD_OB_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            return self._take_continuation(msg_class, selector, payload, server_seq, client_ack)

        name = _SELECTOR_NAMES.get(selector, "unknown")
        log.info(
            "bbird_request class=0x%02x selector=0x%02x (%s) req_id=%d payload_len=%d",
            msg_class,
            selector,
            name,
            request_id,
            len(payload),
        )
        send_params, recv_descs = self._log_payload(f"sel{selector:02x}_req{request_id}", payload)

        if msg_class == BBIRD_OB_CLASS and selector == BBIRD_OB_SELECTOR_INCREMENTAL_QUERY:
            reply_payload = self._build_incremental_query_reply(send_params, recv_descs)
            if reply_payload is None:
                return None
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

        if msg_class == BBIRD_OB_CLASS and selector == BBIRD_OB_SELECTOR_FILE_WRITE:
            return self._handle_file_write(
                send_params, recv_descs, request_id, server_seq, client_ack
            )

        if msg_class == BBIRD_OB_CLASS and selector == BBIRD_OB_SELECTOR_DELETE_NODE:
            reply_payload = self._build_delete_node_reply(send_params, recv_descs)
            if reply_payload is None:
                return None
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

        return None

    def _build_delete_node_reply(self, send_params, recv_descs):
        """Drop a title the publisher is abandoning.

        Two call sites reach method 1. `PUBLISH!DELETENODE` (0x40f01210) is the
        explicit teardown, and `FUN_40f0348e` (0x40f0348e) is the publish
        rollback: `CPublisher_PublishToMSN` throws 0x13 when the DirSrv
        registration leg fails, and the handler for it zeroes the publish
        version at +0x3c and calls this to undo the upload that already
        landed. Both send the title name and read back a **word**, not the
        dword the other methods use — `operator>>(ushort&)` is vtable slot
        0x1c (COSCL.DLL:0x4021ddde).

        The caller discards the value, so it only has to be present.
        """
        if tuple(recv_descs) != (0x82,):
            log.error(
                "bbird_delete_unexpected_descriptors got=%s want=0x82 action=no_reply",
                ",".join(f"0x{d:02x}" for d in recv_descs) or "-",
            )
            return None
        names = [p.data for p in send_params if isinstance(p, VarParam)]
        title = names[0].decode("ascii", errors="replace") if names else ""
        log.info("bbird_delete_node title=%r blob_bytes=%d", title, len(self._blob))
        return build_static_reply(build_tagged_reply_word(0))

    def _handle_file_write(self, send_params, recv_descs, request_id, server_seq, client_ack):
        """Take one 8 KB slice of the compound file.

        `stream_copy_to_mpc_filewrite` (0x40f051a5) is a `read 0x2000 / write`
        loop that stops on the first short read, so the publisher issues one
        method-5 call per slice and the last one is partial. Each call carries
        the slice as a chunked field whose bytes follow on class-0xE6/0xE7
        frames; the head itself holds no file data.

        The ack is deferred until those frames land. The copy loop blocks on
        it, so acking early would let the next slice overlap the one still
        arriving.

        The closing call declares two status dwords where a slice declares
        one, so the ack is built from the descriptors the head carried rather
        than from a fixed shape.
        """
        names = [p.data for p in send_params if isinstance(p, VarParam)]
        if names:
            self._blob_title = names[0].decode("ascii", errors="replace")
        chunks = [p for p in send_params if isinstance(p, ChunkedParam)]
        if not chunks:
            # CMPCFileWrite::Close sends a head with nothing attached.
            log.info("bbird_file_write_end req_id=%d total_bytes=%d", request_id, len(self._blob))
            self._store_blob()
            return self._ack_file_write(request_id, server_seq, client_ack, recv_descs)

        for chunk in chunks:
            self._pending_writes[chunk.stream_id] = (request_id, recv_descs)
            log.info(
                "bbird_file_write req_id=%d stream=%d expect=%d received=%d",
                request_id,
                chunk.stream_id,
                chunk.total_length,
                len(self._blob),
            )
        return None

    def _ack_file_write(self, request_id, server_seq, client_ack, recv_descs=None):
        descriptors = recv_descs if recv_descs else [0x83]
        reply_payload = build_static_reply(
            *(build_tagged_reply_dword(_STATUS_OK) for _ in descriptors)
        )
        host_block = build_host_block(
            BBIRD_OB_CLASS, BBIRD_OB_SELECTOR_FILE_WRITE, request_id, reply_payload
        )
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def _store_blob(self):
        """Write the reassembled compound file out.

        Called on every method-5 head that carries no chunk, which is how
        CMPCFileWrite::Close presents itself, so the file on disk is complete
        by the time the publisher moves on to the DirSrv registration leg.
        """
        if not self._blob:
            return
        try:
            _CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            path = _CAPTURE_DIR / f"{self._capture_stamp}_publish.ttl"
            path.write_bytes(bytes(self._blob))
            log.info(
                "bbird_publish_stored %s title=%r bytes=%d ole2=%s",
                path,
                self._blob_title,
                len(self._blob),
                self._blob[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            )
        except OSError as exc:
            log.warning("bbird_publish_store_failed err=%s", exc)

    def _build_incremental_query_reply(self, send_params, recv_descs):
        """Answer the incremental query with "publish everything".

        The publish version is echoed: the client sends its own in the last
        dword and stores whatever comes back into +0x3c, which then goes into
        the title's `\\x03Publish Version` stamp alongside a fresh GUID.
        Handing back a different number would renumber the title on a server
        that keeps no publish history to renumber it against.
        """
        if tuple(recv_descs) != _INCREMENTAL_QUERY_DESCRIPTORS:
            log.error(
                "bbird_query_unexpected_descriptors got=%s want=%s action=no_reply",
                ",".join(f"0x{d:02x}" for d in recv_descs) or "-",
                ",".join(f"0x{d:02x}" for d in _INCREMENTAL_QUERY_DESCRIPTORS),
            )
            return None

        dwords = [p.value for p in send_params if isinstance(p, DwordParam)]
        names = [p.data for p in send_params if isinstance(p, VarParam)]
        publish_version = dwords[-1] if dwords else 0
        title_name = names[0].decode("ascii", errors="replace") if names else ""
        log.info(
            "bbird_query_reply title=%r mode=%d publish_version=%d objects_known=0",
            title_name,
            _PUBLISH_MODE_FULL,
            publish_version,
        )
        return build_static_reply(
            build_tagged_reply_var(0x84, b""),  # GUIDs the server already holds
            build_tagged_reply_var(0x84, b""),  # their tree timestamps
            build_tagged_reply_var(0x84, b""),  # their object timestamps
            build_tagged_reply_byte(_PUBLISH_MODE_FULL),
            build_tagged_reply_dword(publish_version),
        )

    def _take_continuation(self, msg_class, stream_id, payload, server_seq, client_ack):
        """Fold one class-0xE6/0xE7 frame into its stream.

        0xE7 closes the stream, at which point the slice joins the compound
        file and the method-5 head that quoted it is acked. A stream nobody
        claimed still gets appended — losing bytes would corrupt the file far
        more quietly than an unmatched ack would fail.
        """
        stream = self._streams.setdefault(stream_id, bytearray())
        stream += payload
        log.debug(
            "bbird_chunk_frame id=%d frame_bytes=%d received=%d",
            stream_id,
            len(payload),
            len(stream),
        )
        if msg_class != MPC_CLASS_CONTINUATION_LAST:
            return None

        del self._streams[stream_id]
        self._blob += stream
        log.info(
            "bbird_chunk_stream_done id=%d bytes=%d total=%d",
            stream_id,
            len(stream),
            len(self._blob),
        )
        claim = self._pending_writes.pop(stream_id, None)
        if claim is None:
            log.warning(
                "bbird_chunk_unclaimed id=%d bytes=%d action=append", stream_id, len(stream)
            )
            return None
        request_id, recv_descs = claim
        return self._ack_file_write(request_id, server_seq, client_ack, recv_descs)

    def _log_payload(self, tag, payload):
        """Log the decoded parameters and persist the raw bytes.

        Both halves matter: the tagged decode is what a reader scans in the
        log, and the file is what a parser gets pointed at once the shape is
        understood. Payloads run to megabytes on the file-write leg, so the
        log line carries a bounded prefix and the file carries everything.

        Returns the decode so a caller can build a reply from it.
        """
        if not payload:
            return [], []
        send_params, recv_descs = parse_request_params(payload)
        log.info(
            "bbird_params %s send=%s recv=%s",
            tag,
            " ".join(_describe(p) for p in send_params) or "-",
            ",".join(f"0x{d:02x}" for d in recv_descs) or "-",
        )
        log.info("bbird_payload %s len=%d hex=%s", tag, len(payload), payload[:256].hex())

        try:
            _CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            path = _CAPTURE_DIR / f"{self._capture_stamp}_{tag}.bin"
            path.write_bytes(payload)
            log.info("bbird_capture %s bytes=%d", path, len(payload))
        except OSError as exc:
            log.warning("bbird_capture_failed tag=%s err=%s", tag, exc)
        return send_params, recv_descs


def _describe(param):
    if isinstance(param, ByteParam):
        return f"u8=0x{param.value:02x}"
    if isinstance(param, WordParam):
        return f"u16=0x{param.value:04x}"
    if isinstance(param, DwordParam):
        return f"u32=0x{param.value:08x}"
    if isinstance(param, ChunkedParam):
        return f"chunk[id={param.stream_id},len={param.total_length}]"
    if isinstance(param, VarParam):
        return f"var[{len(param.data)}]={param.data[:32].hex()}"
    return f"tag0x{param.tag:02x}"
