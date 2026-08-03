"""BBS service handler: forum/bulletin-board tree, threaded message nodes.

The BBS read/navigation channel rides the same generic MOS tree infrastructure
as DSNAV — a MOSSHELL `_NtniGroup` wrapping a TREENVCL `CTreeNavClient`, opened
on the service named "BBS" (docs/bbs-service-contract.md §Framing). The wire
request/reply shapes are therefore identical to DIRSRV; only the per-node
property vocabulary differs (`e, _a, p, _D, _P, _t, _F, _I, _f` + base `a/c/b`).
A board/conversation/reply is a `CMosTreeNode`, but the tree under a board is
flat: every message is a direct child of the board and threading rides the `_P`
property. The reader enumerates the board once and never asks a message for
children, so a reply nested under its parent never reaches the list.

Posting rides the same message-content class (0x0B) as the article fetch, on
methods 2/3/4/7 — a chunked upload driven by `FUN_7F5FB7CA` @ 0x7F5FB7CA. It
is not the TREEEDCL write channel.
"""

import datetime
import logging
import pathlib
import struct

from ..config import (
    BBS_INTERFACE_GUIDS,
    MPC_CLASS_CONTINUATION_LAST,
    MPC_CLASS_ONEWAY_MASK,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_END_STATIC,
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
    decode_dirsrv_request,
    parse_request_params,
)
from ..store import app_store as _default_store
from ..store.base import BbsFields
from ..store.records import build_bbs_attachment_nodes, build_bbs_post
from . import dirsrv
from ._dispatch import log_unhandled_selector

# A request's `msg_class` is the *interface* — the selector we handed that IID in
# the discovery table — and `selector` is the method index within it. Class 0x03
# is IID 00028B27, the CTreeNavClient read channel; class 0x0B is IID 00028B2F,
# the message-content channel the reader negotiates when a message is opened
# (BBSNAV FUN_7F5FCD1A). Dispatching on `selector` alone misroutes class-0x0B
# method 0 into GetProperties, which answers it with a meaningless record.
#
# Class 0x04 is the TREEEDCL write channel. BBSNAV binds a `CTreeEditClient` to
# the same "BBS" service (channel `g_BbsEcig`, docs/BBSNAV.md §9) and the shell's
# Delete verb drives it: `CMosTreeNode::Delete` @ MOSSHELL 0x7F3FFFA4 puts up the
# confirmation, takes the edit object (which fetches a ticket on selector 12),
# then calls `CTreeEditClient::DeleteNode` (selector 3). Its builders live in
# `dirsrv` — the tree edit client is generic, so the shapes are shared.
BBS_CLASS_TREE = 0x03
BBS_CLASS_MESSAGE = 0x0B

# BBS read-channel selectors — identical numbering to DIRSRV (the generic
# TREENVCL tree, docs/bbs-service-contract.md §"Read selectors").
BBS_SELECTOR_GET_PROPERTIES = 0x00
BBS_SELECTOR_GET_CHILDREN = 0x02
BBS_SELECTOR_GET_DEID_FROM_GO_WORD = 0x03
BBS_SELECTOR_GET_SHABBY = 0x04

# Message-content channel (class 0x0B) method indices.
#
# 0 fetches the article for the mnid the reader was opened on. 2/3/4/7 are the
# Compose window's post upload, driven by `FUN_7F5FB7CA` @ 0x7F5FB7CA:
# `FUN_7F5FC1D4` @ 0x7F5FC1D4 cuts the article into segments (the header block,
# then the body stream, then one per attachment) and `FUN_7F5FC2D8` @
# 0x7F5FC2D8 drains them in ≤1 MB chunks. The first chunk goes out on
# POST_START, the chunk that empties the last segment on POST_COMMIT, and
# anything between on POST_APPEND. A two-segment post with no attachments —
# the common case — is therefore START then COMMIT, never APPEND.
BBS_SELECTOR_GET_ARTICLE = 0x00
BBS_SELECTOR_POST_START = 0x02
BBS_SELECTOR_POST_APPEND = 0x03
BBS_SELECTOR_POST_COMMIT = 0x04
BBS_SELECTOR_POST_ABORT = 0x07

# Every post request receives exactly one byte (request vtable +0x20). On
# POST_START it is the upload handle, which POST_APPEND/COMMIT/ABORT send back
# as their first parameter (vtable +0x30, wire tag 0x01). On the later methods
# it is a per-chunk acknowledgement.
#
# Zero means failure in both roles: `FUN_7F5FB7CA` tests the received byte
# (`CMP byte ptr [EBP-1],0x0` @ 0x7F5FBB1A and the matching test on [EBP-2])
# and bails with 0x8B0B0001 when it is clear. So a handle is never 0.
_POST_ACK_OK = 1
_POST_HANDLE_MIN = 1
_POST_HANDLE_MAX = 0xFF

# `X-MOS-Format` values BBSNAV accepts, from the strcmp chain in the body
# renderer `FUN_7F5FC56F` @ 0x7F5FC56F. It reads MAPI property 0x6801001E off
# the message, then:
#   "RTFCOMP" → EM_STREAMIN SF_RTF, stream wrapped by WrapCompressedRTFStream
#               (MAPI32 ordinal 185, behind an ordinal-21 init call)
#   "TEXT"    → EM_STREAMIN SF_TEXT
#   "RTF"     → EM_STREAMIN SF_RTF, stream passed through raw
# Any other value, or a missing header (the property then reads back PT_ERROR,
# type 0x0A), aborts the render with 0x8B0B0049.
#
# Which one a message uses is per node — `BbsFields.body_format`. SF_TEXT
# leaves the RichEdit on its own default font, which draws the body in Courier
# New, while reference/screenshots/bbs.png shows proportional MS Sans Serif, so
# a faithful board sends RTF; TEXT stays available for a fixture that wants the
# other branch exercised.
BBS_FORMAT_TEXT = "TEXT"
BBS_FORMAT_RTF = "RTF"
BBS_FORMAT_RTF_COMPRESSED = "RTFCOMP"

# Body font for the generated RTF, matching the reader in
# reference/screenshots/bbs.png. `\fs16` is 8pt — RTF half-points.
_RTF_FONT = "MS Sans Serif"
_RTF_FONT_HALF_POINTS = 16

# Article header → MAPI property map, from the parse table BBSNAV builds at
# 0x7F610A50 (initialiser at 0x7F5FAAEF, names/lengths copied out of the
# (char*, len) array at 0x7F610978) and consumes in `FUN_7F5FB4A9`. A header
# only takes effect when its table entry has the enable dword set; the rest are
# recognised and skipped. Entries relevant here:
#   From:          0x0C1A001E PR_SENDER_NAME   enabled
#   Subject:       0x0037001E PR_SUBJECT       enabled
#   Message-ID:    0x6817001E                  enabled
#   X-MOS-Format:  0x6801001E                  enabled  (drives the renderer)
#   X-MOS-Attach:  0x68020002                  enabled
#   X-MOS-Size:    0x68030003                  enabled
#   Newsgroups:    0x6804001E                  enabled
#   Path:          0x6805001E                  enabled
#   Date:          0x6818001E                  disabled (the column reads `_D`)
# Name matching is `strncmp` against the tabled name *including its trailing
# space*, so every line must read exactly `Name: value` with one space.
_HEADER_SEP = ": "

# BBS property tags (docs/bbs-service-contract.md §"Property tags"). `e` is the
# Subject; `_a` the Author; `_D` a DWORD time_t (MOSSHELL DWORD-as-time_t date
# path keys on the name "_D"); `_P` the parent message's sub-id for threading;
# `_F`/`_I` 2-byte flag words; `_f` advertised with no client read site. `h`
# (icon) is NOT emitted — CBbsNavTreeNode_GetProperty intercepts it and returns
# a client-local glyph id.
PROP_MNID = "a"
PROP_APP_ID = "c"
PROP_BROWSE_FLAGS = "b"
PROP_NAME = "e"
PROP_AUTHOR = "_a"
PROP_SIZE = "p"
PROP_DATE = "_D"
PROP_PARENT_SUBID = "_P"
PROP_TOPIC = "_t"
PROP_HAS_CHILDREN = "_F"
PROP_PRICE_INFO = "_I"
PROP_UNKNOWN_F = "_f"
PROP_LANGUAGE = "q"

# `_F` folder-flag bits. BBSNAV dialog resource 124 "BBS Folder" is the
# authoring surface and labels each one: FUN_7F5F4346 @ 0x7F5F4346 reads `_F`
# into its controls, FUN_7F5F4418 @ 0x7F5F4418 writes them back.
#   bits 0..2  message format — 0 "Plain text (Usenet newsgroups)", 1 "Rich
#              text (MSN formatted text)", 2 "MIME (Some Usenet newsgroups)".
#              Radio 0x68 (MIME) ships with an unconditional EnableWindow(FALSE),
#              so the shipped client never authors format 2.
#   0x0400     "This bulletin board is read-only." No shipping read site.
#   0x0800     radio 0x69 "This is an MSN bulletin board", CLEAR = radio 0x6A
#              "This is a Usenet Newsgroup". Dialog display only.
#   0x1000     dialog label "All messages (even old ones) are always shown".
#              CBbsNavTreeNode_OkToGetChildren @ 0x7F5F1427 also reads this bit
#              and skips deriving node+0xB4 when it is SET. The two readings are
#              not reconciled — the child-count gate is the behaviour we rely on.
#   0x2000     posting gate, no dialog control. SET greys New Message (1101) and
#              Reply (1303) via FUN_7F600D56 @ 0x7F600D56.
#   0x4000     "No messages with attachments are allowed." FUN_7F600D84.
#   0x8000     "Attachments are automatically approved."
BBS_F_FORMAT_PLAIN_TEXT = 0x0000
BBS_F_FORMAT_RICH_TEXT = 0x0001
BBS_F_MSN_BULLETIN_BOARD = 0x0800
BBS_F_NO_CHILDREN = 0x1000

# LCID the Properties dialog displays for a BBS post. Distinct from the node's
# `language` field, which stays 0 so the node survives every locale filter in
# ContentStore.get_children — this value is display only, and the sample board
# lives under Categories (US).
BBS_DISPLAY_LCID = 0x0409

# Substituted when a node carries no BbsFields (e.g. the unknown-mnid fallback
# node routed onto the BBS pipe) so property serialisation never AttributeErrors.
_EMPTY_BBS = BbsFields()

log = logging.getLogger(__name__)


class BBSHandler:
    """Handles BBS read-channel requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # In-flight post uploads, handle byte → PostUpload. A post runs
        # START → [APPEND …] → COMMIT on one pipe, and the handler lives as
        # long as that pipe (Connection._handle_pipe_open builds one per open),
        # so the upload state belongs here rather than in a global.
        self._uploads = {}
        self._next_handle = _POST_HANDLE_MIN
        # Chunked-field streams, stream_id → ChunkStream. A field too big for
        # the inline request body arrives on class 0xE6/0xE7 frames that quote
        # the id the head referenced. The ids come off a per-connection counter
        # and the handler is per-pipe, so this dict is the whole namespace.
        self._streams = {}

    def build_discovery_packet(self, server_seq, client_ack):
        """Advertise the generic TREENVCL tree IIDs plus the message channel.

        BBS rides MOSSHELL's tree client, so it resolves the same read-channel
        IIDs as DIRSRV — it is not a self-describing MEDVIEW-style service. It
        needs one extra: 00028B2F, which the reader negotiates on a second
        CreateTnc("BBS", 3) when a message is opened. See BBS_INTERFACE_GUIDS.
        """
        payload = build_discovery_payload(BBS_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch a BBS request by (interface class, method selector).

        Three classes are served: the tree class (0x03) methods 0/2/3/4, the
        message-content class (0x0B) methods 0 (article fetch) and 2/3/4/7 (post
        upload), and the TREEEDCL edit class (0x04) methods 3 and 12 (Delete).
        Everything else — GetParents (1), the unimplemented enum/resolve slots —
        is logged unhandled and left unanswered.

        Class 0xE6/0xE7 are not calls. They carry the body of a field the head
        was too small to hold, and they expect no reply.
        """
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            self._take_continuation(msg_class, selector, payload)
            return None
        if msg_class == dirsrv.TREEEDCL_CLASS_EDIT:
            if selector == dirsrv.TREEEDCL_SELECTOR_GET_TICKET:
                reply_payload = dirsrv.build_get_ticket_reply_payload()
            elif selector == dirsrv.TREEEDCL_SELECTOR_DELETE_NODE:
                reply_payload = dirsrv.build_delete_node_reply_payload(payload)
            else:
                log_unhandled_selector(log, msg_class, selector, request_id, payload)
                return None
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
        if msg_class == BBS_CLASS_MESSAGE:
            if selector == BBS_SELECTOR_GET_ARTICLE:
                reply_payload = build_bbs_article_reply_payload(payload)
            elif selector == BBS_SELECTOR_POST_START:
                reply_payload = self._post_start(payload)
            elif selector in (BBS_SELECTOR_POST_APPEND, BBS_SELECTOR_POST_COMMIT):
                reply_payload = self._post_chunk(
                    payload, commit=selector == BBS_SELECTOR_POST_COMMIT
                )
            elif selector == BBS_SELECTOR_POST_ABORT:
                reply_payload = self._post_abort(payload)
            else:
                log_unhandled_selector(log, msg_class, selector, request_id, payload)
                return None
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
        if msg_class != BBS_CLASS_TREE:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        if selector == BBS_SELECTOR_GET_PROPERTIES:
            request = decode_dirsrv_request(payload)
            reply_payload = build_bbs_get_properties_reply_payload(request)
        elif selector == BBS_SELECTOR_GET_CHILDREN:
            request = decode_dirsrv_request(payload)
            reply_payload = build_bbs_get_children_reply_payload(request)
        elif selector == BBS_SELECTOR_GET_DEID_FROM_GO_WORD:
            reply_payload = dirsrv.build_get_deid_from_go_word_reply_payload(payload)
        elif selector == BBS_SELECTOR_GET_SHABBY:
            reply_payload = dirsrv.build_get_shabby_reply_payload(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def _post_start(self, payload):
        """Method 2: open an upload and take its first chunk.

        Answers with the handle the remaining methods quote back. Handles are
        one byte, so they wrap; an upload still open on a reused handle is
        replaced, which cannot happen in practice — the Compose window runs one
        post at a time per pipe and 255 have to complete first.
        """
        request = decode_post_start_request(payload)
        if request is None:
            log.error("bbs_post_start undecodable payload_len=%d", len(payload))
            return build_post_reply(0)
        handle = self._take_handle()
        self._uploads[handle] = PostUpload(
            parent_msg_id=request.parent_msg_id,
            board_id=request.board_id,
            total_bytes=request.total_bytes,
            attachment_count=request.attachment_count,
            chunks=[request.chunk],
            streams=self._streams,
        )
        log.info(
            "bbs_post_start handle=%d parent=%d:%d total_bytes=%d chunk_bytes=%d attachments=%d",
            handle,
            request.parent_msg_id,
            request.board_id,
            request.total_bytes,
            _chunk_len(request.chunk),
            request.attachment_count,
        )
        return build_post_reply(handle)

    def _post_chunk(self, payload, *, commit):
        """Methods 3 and 4: take one more chunk, and on 4 store the message.

        A zero ack is the client's designed failure path — `FUN_7F5FB7CA` turns
        it into 0x8B0B0001 and the Compose window reports the post failed. That
        is the right answer for an unknown handle, and it beats the silence that
        left the client waiting.
        """
        request = decode_post_chunk_request(payload)
        upload = self._uploads.get(request.handle) if request else None
        if upload is None:
            log.error(
                "bbs_post_chunk unknown_handle=%s commit=%s payload_len=%d",
                request.handle if request else "?",
                commit,
                len(payload),
            )
            return build_post_reply(0)
        upload.chunks.append(request.chunk)
        if not commit:
            log.info(
                "bbs_post_append handle=%d chunk_bytes=%d received=%d/%d",
                request.handle,
                _chunk_len(request.chunk),
                upload.received_bytes,
                upload.total_bytes,
            )
            return build_post_reply(_POST_ACK_OK)

        upload.commit_pending = True
        self._finish_if_ready(request.handle, upload)
        return build_post_reply(_POST_ACK_OK)

    def _take_continuation(self, msg_class, stream_id, payload):
        """Fold one class-0xE6/0xE7 frame into its stream.

        0xE7 closes the stream. The commit for an upload that quotes it may
        already have landed — the client does not wait for the frames to drain
        before sending method 4 — so a closing frame finishes whatever was left
        waiting on it.
        """
        stream = self._streams.get(stream_id)
        if stream is None:
            stream = ChunkStream()
            self._streams[stream_id] = stream
        stream.data += payload
        stream.complete = msg_class == MPC_CLASS_CONTINUATION_LAST
        # One line per frame is far too much at INFO: an attachment runs to
        # hundreds of ~460-byte frames. Only the closing frame is worth a line.
        log.debug(
            "bbs_chunk_frame id=%d frame_bytes=%d received=%d",
            stream_id,
            len(payload),
            len(stream.data),
        )
        if stream.complete:
            log.info("bbs_chunk_stream_done id=%d bytes=%d", stream_id, len(stream.data))
            for handle, upload in list(self._uploads.items()):
                if upload.commit_pending:
                    self._finish_if_ready(handle, upload)

    def _finish_if_ready(self, handle, upload):
        """Store a committed upload once every stream it quotes has closed."""
        pending = upload.pending_streams
        if pending:
            log.info(
                "bbs_post_commit_deferred handle=%d waiting=%s bytes=%d/%d",
                handle,
                ",".join(str(s) for s in pending),
                upload.received_bytes,
                upload.total_bytes,
            )
            return
        del self._uploads[handle]
        node = commit_post(upload)
        # Only now, with the article built, are the streams safe to drop.
        for stream_id in upload.stream_ids:
            self._streams.pop(stream_id, None)
        log.info(
            "bbs_post_commit handle=%d node=%s subject=%r parent=%d bytes=%d/%d",
            handle,
            node.node_id,
            node.content.name,
            node.content.bbs.parent_subid,
            upload.received_bytes,
            upload.total_bytes,
        )

    def _post_abort(self, payload):
        """Method 7: drop an upload the client gave up on.

        Sent only when a post fails with 0x0B0B000D (the connection went away
        mid-upload). `FUN_7F5FB7CA` dispatches it and releases the request
        without waiting, and the request carries no receive descriptor, so the
        reply is a bare end-of-static.
        """
        request = decode_post_chunk_request(payload)
        handle = request.handle if request else None
        dropped = self._uploads.pop(handle, None)
        log.info("bbs_post_abort handle=%s known=%s", handle, dropped is not None)
        return bytes([TAG_END_STATIC])

    def _take_handle(self):
        handle = self._next_handle
        self._next_handle += 1
        if self._next_handle > _POST_HANDLE_MAX:
            self._next_handle = _POST_HANDLE_MIN
        return handle


def _folder_flags(bbs):
    """The `_F` word for a BBS node.

    Every board served here is a native MSN bulletin board, so the format field
    reads "Rich text (MSN formatted text)" and the MSN-vs-Usenet radio reads
    MSN. The format field is what unlocks composition: CBbs_FIsMsnBbs @
    0x7F600D21 computes `(_F & 7) == 0`, and OnInitMenuPopup @ 0x7F5FF42C greys
    Font (1351), Paragraph (1358), Insert File (1401), Insert Object (1402),
    Paste Special (1158) and the formatting toolbar (1254) whenever that holds.
    The status bar then reads STRINGTABLE 1741 "This command is not available
    in Internet Newsgroups." Format 0 also enables ROT13 (1453) and stops
    FUN_7F5FDC68 @ 0x7F5FDC68 truncating PR_SENDER_NAME at its '@', which is
    how a Usenet author keeps a full internet address in the reader header.

    Read-only (0x2000) and no-attachments (0x4000) stay CLEAR so the board takes
    posts and accepts attachments on them.

    Every node carries the same flags, board and message alike. The Compose
    window reads `_F` off the node it holds at +0x88, and FUN_7F5F26FB @
    0x7F5F26FB reads it off the parent, so a split value would gate the same
    menu two ways.
    """
    flags = BBS_F_FORMAT_RICH_TEXT | BBS_F_MSN_BULLETIN_BOARD
    if not bbs.has_children:
        flags |= BBS_F_NO_CHILDREN
    return flags


def build_bbs_props(requested_props, node, *, is_children):
    """Serialise a BBS tree node into (type, name, value) property tuples.

    BBS rides the generic TREENVCL tree but emits its own tag vocabulary
    (docs/bbs-service-contract.md §"Property tags"). `is_children` is accepted
    for signature parity with dirsrv.build_props; BBS tags carry one wire type
    regardless of caller, so it is unused today. Emit only requested tags;
    an unknown requested tag gets a DWORD-0 fallback, mirroring dirsrv.
    """
    content = node.content
    bbs = content.bbs or _EMPTY_BBS

    out = []
    for name in requested_props:
        if name == PROP_MNID:
            out.append((0x0E, name, struct.pack("<I", len(node.mnid_a)) + node.mnid_a))
        elif name == PROP_APP_ID:
            out.append((0x03, name, struct.pack("<I", node.app_id)))
        elif name == PROP_BROWSE_FLAGS:
            # Bit 0x01 CLEAR = container (board/folder), SET = message.
            # This is the conversation test. FUN_7F5F1CAD @ 0x7F5F1CAD sets
            # bit 0 of its out-byte when `(b & 1) == 0`; that byte becomes the
            # ingest flag and lands in the store entry at +0x1C, and
            # FUN_7F5F5DE4 @ 0x7F5F5DE4 increments the conversation counter
            # (ctx+0xC14) only when the bit is CLEAR. Sending b=0 for every BBS
            # node flagged all of them as containers → "0 conversations" and
            # folder glyphs. Confirmed live: ingest hit with flag=0x01 on
            # Yosemite (mnid field_8=0, field_c=0x100).
            leaf = not node.is_container
            out.append((0x01, name, bytes([0x01 if leaf else 0x00])))
        elif name == PROP_NAME:
            # Subject. 0x0A (ASCII cache) like DIRSRV `e`: column 0 and the
            # Properties dialog both read ANSI.
            out.append((0x0A, name, dirsrv._sz(content.name)))
        elif name == PROP_AUTHOR:
            out.append((0x0A, name, dirsrv._sz(bbs.author)))
        elif name == PROP_TOPIC:
            out.append((0x0A, name, dirsrv._sz(bbs.topic)))
        elif name == PROP_SIZE:
            out.append((0x03, name, struct.pack("<I", content.size_bytes & 0xFFFFFFFF)))
        elif name == PROP_DATE:
            # `_D` DWORD time_t, always emitted — 0 when the node has no date.
            # Never skip a requested tag: CServiceProperties::FSet @ 0x7F6418FF
            # only advances the record count on success, so a dropped property
            # also strips every property after it. Omitting `_D` here cost the
            # board its `_F` (the OkToGetChildren gate) and stalled the thread
            # fetch. Verified on the wire 2026-07-27.
            out.append((0x03, name, struct.pack("<I", bbs.date_unix & 0xFFFFFFFF)))
        elif name == PROP_PARENT_SUBID:
            out.append((0x03, name, struct.pack("<I", bbs.parent_subid & 0xFFFFFFFF)))
        elif name == PROP_HAS_CHILDREN:
            out.append((0x02, name, struct.pack("<H", _folder_flags(bbs))))
        elif name == PROP_PRICE_INFO:
            # `_I` 2-byte attributes. 0 = free content (no pricing checkbox).
            out.append((0x02, name, struct.pack("<H", 0)))
        elif name == PROP_UNKNOWN_F:
            # `_f` advertised but no BBSNAV read site; safe default DWORD 0.
            out.append((0x03, name, struct.pack("<I", 0)))
        elif name == PROP_LANGUAGE:
            # `q` as a type-0x10 dword array [count][lcid], NOT the 0x04 qword
            # DIRSRV uses. MOSSHELL's value formatter @ 0x7F3FBC12 switches on
            # the cached type: case 0x10 calls GetLocaleInfoA(value[1],
            # LOCALE_SLANGUAGE) and prints a language name, while case 0x04/0x08
            # falls to FUN_7F3FAE1C = wsprintfA("%u:%u", high, low) — which is
            # why the Properties dialog read "Language: 0:0". Both encodings put
            # the LCID at offset +4, so MCM's browse-language reader
            # (*(u32*)(value + 4)) is satisfied either way.
            out.append((0x10, name, struct.pack("<II", 1, BBS_DISPLAY_LCID)))
        else:
            # Anything outside the BBS vocabulary is a shared MOS tree tag, and
            # the Properties dialog fetches those one at a time as {name, 'g'}
            # groups (observed live: `q,g` then `v,g` on a BBS node). Reuse
            # DIRSRV's serialisation so each one gets its established wire type
            # instead of a DWORD-0 stand-in — `q` in particular must be the
            # 8-byte qword form, since a 4-byte value makes the client's
            # `*(u32*)(value + 4)` LCID read run off the end.
            out.extend(dirsrv.build_props([name], node, is_children=is_children))
    return out


def build_bbs_get_properties_reply_payload(request):
    """BBS GetProperties (selector 0x00): one self record for the node.

    Same single-record contract as DIRSRV GetProperties — the reader header
    and Properties dialog feed the first received record into the requesting
    CMosTreeNode, so returning children would corrupt the node's identity.
    """
    requested = _requested_props(request.prop_group)
    node = _default_store.content.get_node(request.node_id)
    log.info(
        "bbs_get_properties node=%s props=%s",
        request.node_id,
        ",".join(requested) or "-",
    )
    records = [(node.node_id, build_bbs_props(requested, node, is_children=False))]
    return dirsrv.build_tree_reply_wire(records)


def build_bbs_get_children_reply_payload(request):
    """BBS GetChildren (selector 0x02): every message on the board.

    One flat list — replies included, since threading rides `_P` rather than
    tree position. `locale_raw` is forwarded so a filter_on=1 request still
    resolves; BBS nodes are language=0 (locale-neutral) and survive every
    locale filter.

    The board itself leads the reply when the request carries the with-self
    flag. The BBS board is a delegate, so `CMosTreeNode::QueryOutOfDate` hands
    the staleness check to the inner bbsnav node, which runs the same MOSSHELL
    code over this pipe and reads the first record as the node's own.
    """
    requested = _requested_props(request.prop_group)
    store = _default_store.content
    children = store.get_children(request.node_id, request.locale_raw)
    with_self = request.flags == dirsrv.GET_CHILDREN_FLAG_WITH_SELF
    log.info(
        "bbs_get_children node=%s props=%s flags=%d child_count=%d",
        request.node_id,
        ",".join(requested) or "-",
        request.flags,
        len(children),
    )
    nodes = [store.get_node(request.node_id), *children] if with_self else children
    records = [
        (node.node_id, build_bbs_props(requested, node, is_children=True)) for node in nodes
    ]
    return dirsrv.build_tree_reply_wire(records)


def _requested_props(prop_group):
    return [p for p in prop_group.split("\x00") if p]


# --- Message-content channel (class 0x0B) ---


def build_bbs_article_reply_payload(payload):
    """Class 0x0B method 0: the opened message as an RFC-1036 news article.

    Request is `04 88 [msg_id:u32][board_id:u32] 83 85` — the 8-byte mnid the
    reader copied into its context at +0xA8, one 0x83 status DWORD to receive,
    and 0x85 marking the request as streaming (appended by MPCCL
    `DispatchBuiltServiceRequest` @ 0x046040D8 when the caller set the stream
    flag through request vtable +0x40).

    Reply is `0x83 [status=0] 0x87 0x86 [article bytes]`.

    The 0x86 tag, not 0x88. MPCCL `ProcessTaggedServiceReply` @ 0x04604F26
    branches on the dynamic tag: 0x86 calls `SignalRequestCompletion`
    (request +0x18 = 1, then SetEvent on +0x24/+0x28/+0x2c), while 0x88 only
    signals the two chunk events and leaves +0x18 clear. The reader's fetch
    thread `FUN_7F5FB15F` @ 0x7F5FB15F drains the stream through request
    vtable +0x14 `WaitIncremental` @ 0x046049BC, which returns 0x0B0B000B when
    +0x18 is set and 0x0B0B000C when it is clear. Only 0x0B0B000B ends the
    loop, so a 0x88 reply parks that thread on the next wait forever and the
    Read Message window stays blank — the hang this selector was leaving
    behind. The tree channel uses 0x88 because its consumer is TREENVCL's node
    iterator, which waits on the +0x2c stream-end event instead.

    A nonzero status DWORD makes the fetch thread bail with 0x8B0B0049 before
    reading a byte, so it is always 0 here; a missing node resolves to the
    store fallback and still ships a well-formed article.
    """
    node_id = _article_request_node_id(payload)
    node = _default_store.content.get_node(node_id)
    article = build_bbs_article(node)
    log.info("bbs_get_article node=%s article_bytes=%d", node_id, len(article))
    return (
        build_tagged_reply_dword(0) + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + article
    )


def _article_request_node_id(payload):
    """Decode the 8-byte mnid from a class-0x0B request into a store key.

    Same `[dword_0][dword_1]` packing as the tree channel's node id, so it
    reuses the `"f8:board"` fixture keys — BBS mnids put the message id in
    field_8 and the board id in field_c.
    """
    send_params, _recv = parse_request_params(payload)
    for p in send_params:
        if isinstance(p, VarParam) and len(p.data) >= 8:
            msg_id, board_id = struct.unpack("<II", p.data[:8])
            return f"{msg_id}:{board_id}"
    return ""


def build_bbs_article(node):
    """Serialise a BBS node as the news article its reader expects.

    `FUN_7F5FB15F` splits the stream at the first pair of adjacent `\\n` bytes:
    everything before goes to the header parser `FUN_7F5FB4A9`, everything
    after is written into an in-memory IStream that becomes the message body.
    Header lines therefore end in a bare LF — with CRLF the two newlines are
    never adjacent, the split never fires, and the whole article is swallowed
    as headers.

    The body is streamed into a RichEdit control by `FUN_7F5FC56F` via
    EM_STREAMIN, in whichever mode the node's `body_format` names.
    """
    content = node.content
    bbs = content.bbs or _EMPTY_BBS
    # A posted message already holds the bytes the Compose window uploaded, in
    # the encoding X-MOS-Format names. Re-encoding is only for fixtures, whose
    # bodies are authored as plain text.
    body = bbs.body_raw if bbs.body_raw is not None else encode_body(bbs.body, bbs.body_format)

    headers = [
        ("Path", "msn"),
        ("From", bbs.author),
        ("Newsgroups", _board_name(node)),
        ("Subject", content.name),
        ("Date", _article_date(bbs.date_unix)),
        ("Message-ID", _message_id(node)),
        ("X-MOS-Format", bbs.body_format),
        # Plain-text length, matching the tree's `p`. Both land on MAPI tag
        # 0x68030003, so a transfer-size value here would disagree with the
        # Size column the list pane already shows — and it would also change
        # with body_format, which the Size column must not do.
        ("X-MOS-Size", str(content.size_bytes)),
        # Attachment count. It lands on MAPI tag 0x68020002 and no read site is
        # known — the reader counts the MOSAF objects it found in the body
        # instead (`FUN_7F5FC7B7` fills reader+0xC0, which is what the message
        # Properties page prints). Kept truthful so the header block matches the
        # body the client is about to parse.
        ("X-MOS-Attach", str(bbs.attachment_count)),
    ]
    head = "".join(f"{name}{_HEADER_SEP}{value}\n" for name, value in headers)
    return head.encode("ascii", "replace") + b"\n" + body


def encode_body(text, body_format):
    """Turn a fixture's plain-text body into wire bytes for `body_format`.

    Bodies are always authored as plain text; the format decides how they reach
    the RichEdit. An unsupported value fails here rather than on the wire — the
    client's own failure for a format it does not recognise is a bare
    0x8B0B0049 with no indication of which message caused it.
    """
    try:
        encoder = BODY_ENCODERS[body_format]
    except KeyError:
        raise ValueError(
            f"unsupported BBS body_format {body_format!r}; "
            f"expected one of {', '.join(sorted(BODY_ENCODERS))}"
        ) from None
    return encoder(text)


def build_body_text(text):
    """Plain-text body for EM_STREAMIN `SF_TEXT`.

    CRLF line breaks, like any other RichEdit text.
    """
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii", "replace")


def build_body_rtf(text):
    """Wrap a plain-text body as an RTF document for EM_STREAMIN `SF_RTF`.

    One font in the table and one `\\par` per source line, so a blank line in
    the text stays a blank paragraph. The document is pure ASCII: anything
    outside it goes out as `\\'hh` cp1252 escapes, which is what an RTF reader
    of this vintage expects after `\\ansi`. Raw newlines in the result are only
    source formatting, which RTF readers discard.

    Deliberately free of embedded objects. `FUN_7F5FC56F` runs two extra passes
    in SF_RTF mode — `FUN_7F5FC7B7` walks EM_GETOLEINTERFACE
    (`IRichEditOle::GetObjectCount`/`GetObject`) collecting objects of one
    CLSID, and `FUN_7F5FC919` resolves each against the tree. Both are no-ops
    at object count 0, which is the shape we ship.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    paragraphs = "\\par\n".join(_rtf_escape(line) for line in lines)
    return (
        "{\\rtf1\\ansi\\ansicpg1252\\deff0"
        f"{{\\fonttbl{{\\f0\\fswiss\\fcharset0 {_RTF_FONT};}}}}"
        f"\\pard\\f0\\fs{_RTF_FONT_HALF_POINTS} "
        f"{paragraphs}\\par\n}}"
    ).encode("ascii")


# `BbsFields.body_format` → encoder. RTFCOMP is absent on purpose: it needs the
# MAPI compressed-RTF container, and nothing observed says the service used it.
BODY_ENCODERS = {
    BBS_FORMAT_TEXT: build_body_text,
    BBS_FORMAT_RTF: build_body_rtf,
}


def _rtf_escape(text):
    """Escape one line of body text for an RTF stream."""
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ch == "\t":
            out.append("\\tab ")
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            for byte in ch.encode("cp1252", errors="replace"):
                out.append(f"\\'{byte:02x}")
    return "".join(out)


def _board_name(node):
    """Newsgroups value: the name of the board the message hangs under.

    A BBS mnid is `(message id, board id)`, and the board is that same mnid
    with the message id zeroed — the rule `CBbsNavTreeNode::GetParent`
    (0x7F5F12CE) uses. An unresolvable board falls back to the node's own name.
    """
    _msg_id, _sep, board_id = node.node_id.partition(":")
    board = _default_store.content.get_node(f"0:{board_id}")
    return board.content.name or node.content.name


def _message_id(node):
    """`<message.board@bbs.msn.com>` — synthesised from the mnid.

    The client caches it as MAPI 0x6817001E; nothing on the wire round-trips
    it back, so any stable unique form serves.
    """
    msg_id, _sep, board_id = node.node_id.partition(":")
    return f"<{msg_id}.{board_id}@bbs.msn.com>"


def _article_date(date_unix):
    """RFC-1036 date carrying the same wall clock the Date column shows.

    Inverts `_bbs_date_to_unix`: that helper subtracts the host's *current* UTC
    offset rather than the one in force on the post's date, because Windows 95
    applies one timezone rule to every timestamp. Adding the same offset back
    reproduces the wall clock; letting `astimezone` pick the historical offset
    would shift the line off the Date column by an hour.

    BBSNAV's header table has `Date:` disabled, so this line is recognised and
    skipped rather than parsed. It is here for a well-formed article, not
    because a value is read from it.
    """
    if not date_unix:
        return "Thu, 01 Jan 1970 00:00:00 +0000"
    offset = datetime.datetime.now().astimezone().utcoffset() or datetime.timedelta(0)
    stamp = datetime.datetime.fromtimestamp(date_unix, datetime.UTC) + offset
    return stamp.strftime("%a, %d %b %Y %H:%M:%S ") + _utc_offset_text(offset)


def _utc_offset_text(offset):
    """`+HHMM` / `-HHMM` for an RFC-1036 date line."""
    total = int(offset.total_seconds())
    sign = "-" if total < 0 else "+"
    total = abs(total)
    return f"{sign}{total // 3600:02d}{total % 3600 // 60:02d}"


# --- Post channel (class 0x0B methods 2/3/4/7) ---

# Headers the Compose window writes, in the order `FUN_7F5FBD4E` @ 0x7F5FBD4E
# appends them. Each line is `Name: value` terminated by a bare LF (the
# separator at 0x7F610C0C is a single 0x0A), and a second LF closes the block —
# the same framing the reader expects coming back.
#
# Every value is a MAPI property read off the compose message; a property that
# came back PT_ERROR (type 0x0A) writes an empty value rather than dropping its
# line. `References` is the only conditional one: it appears only when the post
# answers another message.
#
#   X-MOS-To:      0x6800001E   recipient/board text
#   X-MOS-Parent:  0x68140003   message id this post answers, 0 for a new topic
#   Subject:       0x0037001E
#   References:    0x6809001E   present only when X-MOS-Parent is nonzero
#   X-MOS-Icon:    literal 0
#   X-MOS-Format:  "RTFCOMP" or "TEXT" — never plain "RTF" on this direction
#   X-MOS-Attach:  attachment count
#   X-MOS-Size:    body length in bytes
#   X-MOS-CP:      GetACP()
POST_HEADER_PARENT = "X-MOS-Parent"
POST_HEADER_SUBJECT = "Subject"
POST_HEADER_FORMAT = "X-MOS-Format"
POST_HEADER_SIZE = "X-MOS-Size"

# Subject stamped on a post whose header block carried none. The Compose window
# always writes the line, but writes it empty when the property read back
# PT_ERROR, and an empty `e` gives a nameless row in the reader.
_POST_UNTITLED_SUBJECT = "(No subject)"


def _chunk_len(chunk):
    """Byte count a chunk contributes, or its declared size when it is a reference."""
    if isinstance(chunk, ChunkedParam):
        return chunk.total_length
    return len(chunk)


class ChunkStream:
    """Bytes of one chunked field, gathered from its class-0xE6/0xE7 frames."""

    def __init__(self):
        self.data = b""
        self.complete = False


class PostUpload:
    """One in-flight post: where it goes, and the chunks received so far.

    A chunk is either inline bytes or a ChunkedParam naming a stream that
    carries the field out of band. `streams` is the handler's stream table, so
    a reference resolves against whatever has arrived by the time it is read.
    """

    def __init__(self, parent_msg_id, board_id, total_bytes, attachment_count, chunks, streams):
        self.parent_msg_id = parent_msg_id
        self.board_id = board_id
        self.total_bytes = total_bytes
        self.attachment_count = attachment_count
        self.chunks = chunks
        self.streams = streams
        self.commit_pending = False

    def _parts(self):
        for chunk in self.chunks:
            if isinstance(chunk, ChunkedParam):
                stream = self.streams.get(chunk.stream_id)
                yield stream.data if stream else b""
            else:
                yield chunk

    @property
    def stream_ids(self):
        return [c.stream_id for c in self.chunks if isinstance(c, ChunkedParam)]

    @property
    def pending_streams(self):
        """Quoted stream ids that have not seen their closing 0xE7 yet."""
        out = []
        for stream_id in self.stream_ids:
            stream = self.streams.get(stream_id)
            if stream is None or not stream.complete:
                out.append(stream_id)
        return out

    @property
    def received_bytes(self):
        return sum(len(p) for p in self._parts())

    def article(self):
        return b"".join(self._parts())

    def split(self):
        """Cut the upload into `(header block, body, attachment bytes)`.

        `FUN_7F5FC1D4` @ 0x7F5FC1D4 builds one segment per part — the header
        block, the body stream, then one per attachment — and the method-2
        `total_bytes` dword counts the header block plus the body alone. The
        first attachment byte therefore sits at exactly that offset. Attachments
        run together past it: `FUN_7F5FC2D8` caps a chunk at 1 MB, so a chunk
        boundary is not a file boundary, and nothing on the wire says where one
        file ends and the next begins.
        """
        article = self.article()
        head_and_body, attachments = article[: self.total_bytes], article[self.total_bytes :]
        header, _sep, body = head_and_body.partition(b"\n\n")
        return header, body, attachments


class PostStartRequest:
    """Decoded method-2 parameters."""

    def __init__(self, total_bytes, parent_msg_id, board_id, attachment_count, chunk):
        self.total_bytes = total_bytes
        self.parent_msg_id = parent_msg_id
        self.board_id = board_id
        self.attachment_count = attachment_count
        self.chunk = chunk


class PostChunkRequest:
    """Decoded method-3/4/7 parameters."""

    def __init__(self, handle, chunk):
        self.handle = handle
        self.chunk = chunk


def decode_post_start_request(payload):
    """Decode method 2 — `03 total | 04 mnid | 02 1 | 04 attach | 02 n | 04 chunk | 03 len | 81`.

    Parameter order is fixed by the build sequence in `FUN_7F5FB7CA`
    (0x7F5FB8FE onwards): total size, the 8-byte target, a constant word 1, the
    attachment-id array, its count, the chunk, the chunk length, then the
    receive byte.

    The 8-byte target is `[parent message id][board id]` — the client fills it
    from `param_1+0xA8`, whose halves are MAPI 0x68140003 (X-MOS-Parent) and the
    high dword of 0x68160014. It packs like every other BBS mnid, so a reply to
    message 0x200 on board 1 arrives as `(0x200, 1)`.

    Returns None when the payload does not carry the three variable parameters,
    which is the only shape this cannot work with.
    """
    send_params, _recv = parse_request_params(payload)
    # A chunked reference stands exactly where its field would have been, so
    # position still picks the right one out of the three variable parameters.
    fields = [p for p in send_params if isinstance(p, (VarParam, ChunkedParam))]
    dwords = [p for p in send_params if isinstance(p, DwordParam)]
    words = [p for p in send_params if isinstance(p, WordParam)]
    if len(fields) < 3 or len(dwords) < 1 or not isinstance(fields[0], VarParam):
        return None
    target = fields[0].data
    parent_msg_id, board_id = struct.unpack("<II", target[:8]) if len(target) >= 8 else (0, 0)
    chunk = fields[2]
    return PostStartRequest(
        total_bytes=dwords[0].value,
        parent_msg_id=parent_msg_id,
        board_id=board_id,
        attachment_count=words[1].value if len(words) > 1 else 0,
        chunk=chunk if isinstance(chunk, ChunkedParam) else chunk.data,
    )


def decode_post_chunk_request(payload):
    """Decode method 3/4 — `01 handle | 04 chunk | 03 len | 81` — or method 7's bare handle.

    Method 7 sends the handle alone, so an absent chunk is not an error here.
    """
    send_params, _recv = parse_request_params(payload)
    handles = [p for p in send_params if isinstance(p, ByteParam)]
    chunks = [p for p in send_params if isinstance(p, (VarParam, ChunkedParam))]
    if not handles:
        return None
    chunk = chunks[0] if chunks else b""
    return PostChunkRequest(
        handle=handles[0].value,
        chunk=chunk if isinstance(chunk, (ChunkedParam, bytes)) else chunk.data,
    )


def build_post_reply(value):
    """`0x81 <byte> 0x87` — the one byte every post method receives.

    Zero is the failure signal: `FUN_7F5FB7CA` tests the byte and returns
    0x8B0B0001 when it is clear, so the Compose window reports a failed post
    instead of waiting.
    """
    return build_static_reply(build_tagged_reply_byte(value))


def commit_post(upload):
    """Turn a completed upload into a message node under its board.

    The uploaded article splits the same way the reader splits a downloaded one
    — at the first pair of adjacent LFs — into a header block and the body. The
    body is already encoded as X-MOS-Format names, so it is stored verbatim and
    goes back out untouched. Attachment bytes are kept off the body: they ride
    their own segments past `total_bytes` and never reach the reader through the
    article.

    Every attachment also gets its own tree node at `(message id + k, board id)`
    — the mnid FUN_7F5FC919 builds for the k-th embedded MOSAF object — so the
    `z`/`_r` read the reader fires while rendering the body resolves.
    """
    header_block, body, attachments = upload.split()
    headers = parse_article_headers(header_block)
    board_key = f"0:{upload.board_id}"
    msg_id = _next_message_id(board_key, upload.board_id)
    node = build_bbs_post(
        msg_id,
        upload.board_id,
        subject=headers.get(POST_HEADER_SUBJECT) or _POST_UNTITLED_SUBJECT,
        parent_subid=_header_int(headers, POST_HEADER_PARENT, upload.parent_msg_id),
        body_raw=body,
        body_format=headers.get(POST_HEADER_FORMAT) or BBS_FORMAT_TEXT,
        size_bytes=_header_int(headers, POST_HEADER_SIZE, len(body)),
        attachment_count=upload.attachment_count,
        attachment_data=attachments,
    )
    _default_store.content.add_child(board_key, node)
    for attachment_node in build_bbs_attachment_nodes(node):
        _default_store.content.add_node(attachment_node)
    _write_post_capture(node, header_block, body, attachments)
    return node


# Uploaded posts land here as three files — the header block, the body as the
# reader will stream it, and whatever followed the body. A post is the only way
# to obtain a body carrying a real MOSAF attachment object, so the capture is
# what turns one into a fixture.
_CAPTURE_DIR = pathlib.Path("captures/bbs")


def _write_post_capture(node, header_block, body, attachments):
    """Write one committed upload to `captures/bbs/<node>-<subject>/`."""
    slug = "".join(c if c.isalnum() else "-" for c in node.content.name).strip("-").lower()
    directory = _CAPTURE_DIR / f"{node.node_id.replace(':', '-')}-{slug}"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "headers.txt").write_bytes(header_block)
    (directory / "body.bin").write_bytes(body)
    if attachments:
        (directory / "attachments.bin").write_bytes(attachments)
    log.info(
        "bbs_post_capture dir=%s header_bytes=%d body_bytes=%d attachment_bytes=%d",
        directory,
        len(header_block),
        len(body),
        len(attachments),
    )


def parse_article_headers(header_block):
    """Decode an uploaded header block into `{name: value}`.

    Lines are `Name: value` with one space, terminated by a bare LF —
    `FUN_7F5FBD4E` writes exactly that. A line without the separator is skipped
    rather than failing the post; the client has already committed the message
    by the time this runs.
    """
    headers = {}
    for line in header_block.decode("ascii", "replace").split("\n"):
        name, sep, value = line.partition(_HEADER_SEP)
        if sep:
            headers[name] = value
    return headers


def _header_int(headers, name, default):
    """A numeric header value, falling back when it is absent or not a number."""
    try:
        return int(headers[name])
    except (KeyError, ValueError):
        return default


def _next_message_id(board_key, board_id):
    """One past the last id any message on the board owns.

    Message ids are the `field_8` half of the mnid and must be unique per board
    — `_P` threading and the article fetch both key on them. A message with
    attachments owns more than its own id: FUN_7F5FC919 addresses the k-th
    attachment as `message id + k`, so the next message starts past the last of
    them or the two collide on one mnid.
    """
    highest = 0
    for child in _default_store.content.get_children(board_key):
        msg_id, _sep, child_board = child.node_id.partition(":")
        if child_board == str(board_id) and msg_id.isdigit():
            bbs = child.content.bbs or _EMPTY_BBS
            highest = max(highest, int(msg_id) + bbs.attachment_count)
    return highest + 1
