"""Protocol constants and configuration for the Marvel MSN server."""

import uuid

# --- Network ---
HOST = "0.0.0.0"
PORT = 2323

# --- Packet framing ---
PACKET_TERMINATOR = 0x0D
ESCAPE_CHAR = 0x1B
ACK_SEQ_BYTE = 0x41  # Packet type: ACK
NACK_SEQ_BYTE = 0x42  # Packet type: NACK

# --- Header byte encoding ---
HEADER_XOR_MASK = 0xC0
HEADER_SPECIAL_VALUES = frozenset({0x8D, 0x90, 0x8B})
HEADER_ENCODED_VALUES = frozenset({0x4D, 0x50, 0x4B})

# --- CRC-32 ---
CRC_POLYNOMIAL = 0x248EF9BE
CRC_MASK_OR = 0x60

# --- Pipe frame bits ---
PIPE_ALWAYS_SET = 0x80
PIPE_HAS_LENGTH = 0x10
PIPE_CONTINUATION = 0x20
PIPE_LAST_DATA = 0x40
PIPE_INDEX_MASK = 0x0F

# --- Pipe-0 routing ---
ROUTING_CONTROL = 0xFFFF
ROUTING_PIPE_OPEN = 0x0000

# --- MPC reply tags ---
# See MPCCL.ProcessTaggedServiceReply (0x04605187) for the dispatch:
#   if ((tag & 0x8f) == 0x86) SignalRequestCompletion(this);   // sets +0x18, signals +0x24 (Wait)
#   else if ((tag & 0x60) != 0x40) FUN_04604e25(this);         // signals +0x28 (iterator chunk)
#   if ((tag & 0x8f) == 0x88) FUN_04604e52(this);              // signals +0x2c (iterator end)
# 0x86 and 0x88 both terminate a dynamic section with raw-to-end bytes, but
# they wake different waiters:
#   0x86 — wakes the single-shot Wait() on +0x24 (GetShabby, onlstmt).
#   0x88 — wakes the dynamic-iterator on +0x28/+0x2c (GetChildren, which
#          consumes property records through MPCCL's iterator).
# Using the wrong one silently hangs the caller: 0x86 never fires +0x28 so
# an iterator yields zero records; 0x88 never fires +0x24 so Wait() blocks
# until the pipe closes and returns 0x8B0B0005.
TAG_END_STATIC = 0x87               # End of static section marker
TAG_DYNAMIC_COMPLETE_SIGNAL = 0x86  # single-shot dynamic blob, signals Wait()
TAG_DYNAMIC_STREAM_END = 0x88       # iterator stream end, signals +0x28/+0x2c

# --- MPC host-block class bits ---
# Frames whose msg_class has the top three bits set (0xE0 mask) are one-way
# continuations of a multi-frame RPC (carrying large input buffers for the
# preceding head).  They must not be acked — see §9a.3 / §9a.5b.
MPC_CLASS_ONEWAY_MASK = 0xE0

# --- DIRSRV property 'b' browse flags ---
# PROTOCOL.md §7.2.4 / CMosTreeNode::ExecuteCommand:
#   bit 0x01 clear = container (browse)
#   bit 0x01 set   = leaf (exec)
#   bit 0x08 set   = server-denied
DIRSRV_BROWSE_FLAGS_CONTAINER = 0x00
DIRSRV_BROWSE_FLAGS_LEAF = 0x01
DIRSRV_BROWSE_FLAGS_DENIED = 0x08
DIRSRV_BROWSE_FLAGS_LEAF_DENIED = DIRSRV_BROWSE_FLAGS_LEAF | DIRSRV_BROWSE_FLAGS_DENIED

# --- Pipe commands ---
PIPE_CLOSE_CMD = 0x01

# --- Transport defaults ---
# PACKET_SIZE is the max wire-bytes per frame. Client registry default is
# 1024 (PacketSize) and MOSCP uses MIN(client, server-advertised), so we
# must advertise at least what build_service_packet actually emits.
TRANSPORT_PACKET_SIZE = 1024
TRANSPORT_MAX_BYTES = 1024
TRANSPORT_WINDOW_SIZE = 16
TRANSPORT_ACK_BEHIND = 1
TRANSPORT_ACK_TIMEOUT_MS = 600

# --- Timing ---
DELAY_AFTER_COM = 0.3
DELAY_BEFORE_REPLY = 0.1
SOCKET_TIMEOUT = 0.5

# --- Byte-stuffing maps ---
# Raw byte -> 0x1B-prefixed escape sequence
ESCAPE_SET = frozenset({0x1B, 0x0D, 0x10, 0x0B, 0x8D, 0x90, 0x8B})

STUFF_MAP = {
    0x1B: b"\x1b\x30",  # escape char
    0x0D: b"\x1b\x31",  # CR / packet terminator
    0x10: b"\x1b\x32",  # DLE
    0x0B: b"\x1b\x33",  # VT
    0x8D: b"\x1b\x34",  # high control
    0x90: b"\x1b\x35",  # high control
    0x8B: b"\x1b\x36",  # high control
}

UNSTUFF_MAP = {
    0x30: 0x1B,
    0x31: 0x0D,
    0x32: 0x10,
    0x33: 0x0B,
    0x34: 0x8D,
    0x35: 0x90,
    0x36: 0x8B,
}

# --- Service interface GUIDs ---
# Pre-computed as bytes_le (Windows in-memory layout) because
# MPCCL resolves them with memcmp() against compiled-in GUID constants.


def _guid_le(s):
    return uuid.UUID(s).bytes_le


LOGSRV_INTERFACE_GUIDS = [
    (_guid_le("00028BB6-0000-0000-C000-000000000046"), 0x01),
    (_guid_le("00028BB7-0000-0000-C000-000000000046"), 0x02),
    (_guid_le("00028BB8-0000-0000-C000-000000000046"), 0x03),
    (_guid_le("00028BC0-0000-0000-C000-000000000046"), 0x04),
    (_guid_le("00028BC1-0000-0000-C000-000000000046"), 0x05),
    (_guid_le("00028BC2-0000-0000-C000-000000000046"), 0x06),  # Login interface
    (_guid_le("00028BC3-0000-0000-C000-000000000046"), 0x07),
    (_guid_le("00028BC4-0000-0000-C000-000000000046"), 0x08),
    (_guid_le("00028BC5-0000-0000-C000-000000000046"), 0x09),
    (_guid_le("00028BC6-0000-0000-C000-000000000046"), 0x0A),
]

# DIRSRV (directory browsing / tree navigation) interfaces.  Static analysis of
# TREENVCL.CTreeNavClient (0x7f63113d) confirms IID 00028B27 as the directly
# resolved DIRSRV interface.  Adjacent memory in TREENVCL holds the contiguous
# family 00028B25..00028B2E.  We advertise all of them so whichever IID the
# client resolves for GetShabby (TREENVCL 0x7f631bab) gets a selector back —
# the (IID, selector) tuple for GetShabby is captured by Phase 0 tracing.
DIRSRV_INTERFACE_GUIDS = [
    (_guid_le("00028B25-0000-0000-C000-000000000046"), 0x01),
    (_guid_le("00028B26-0000-0000-C000-000000000046"), 0x02),
    (_guid_le("00028B27-0000-0000-C000-000000000046"), 0x03),
    (_guid_le("00028B28-0000-0000-C000-000000000046"), 0x04),
    (_guid_le("00028B29-0000-0000-C000-000000000046"), 0x05),
    (_guid_le("00028B2A-0000-0000-C000-000000000046"), 0x06),
    (_guid_le("00028B2B-0000-0000-C000-000000000046"), 0x07),
    (_guid_le("00028B2C-0000-0000-C000-000000000046"), 0x08),
    (_guid_le("00028B2D-0000-0000-C000-000000000046"), 0x09),
    (_guid_le("00028B2E-0000-0000-C000-000000000046"), 0x0A),
]

# OLREGSRV (On-Line Registration Service) interfaces.  SIGNUP.EXE holds
# the client-side IID table at 0x40b4e8 — sixteen 00028Bxx GUIDs covering
# the phone-book / trial-info / product-details sync used by its "Get the
# latest product details" flow.  Listed in the order they appear in the
# binary, paired with a selector that the server assigns contiguously so
# the client's IID→selector lookup resolves for each one.
OLREGSRV_INTERFACE_GUIDS = [
    (_guid_le("00028B73-0000-0000-C000-000000000046"), 0x01),
    (_guid_le("00028B74-0000-0000-C000-000000000046"), 0x02),
    (_guid_le("00028B78-0000-0000-C000-000000000046"), 0x03),
    (_guid_le("00028B79-0000-0000-C000-000000000046"), 0x04),
    (_guid_le("00028B81-0000-0000-C000-000000000046"), 0x05),
    (_guid_le("00028B82-0000-0000-C000-000000000046"), 0x06),
    (_guid_le("00028B83-0000-0000-C000-000000000046"), 0x07),
    (_guid_le("00028B84-0000-0000-C000-000000000046"), 0x08),
    (_guid_le("00028B85-0000-0000-C000-000000000046"), 0x09),
    (_guid_le("00028B86-0000-0000-C000-000000000046"), 0x0A),
    (_guid_le("00028B8A-0000-0000-C000-000000000046"), 0x0B),
    (_guid_le("00028B8B-0000-0000-C000-000000000046"), 0x0C),
    (_guid_le("00028B8C-0000-0000-C000-000000000046"), 0x0D),
    (_guid_le("00028B8D-0000-0000-C000-000000000046"), 0x0E),
    (_guid_le("00028B8E-0000-0000-C000-000000000046"), 0x0F),
    (_guid_le("00028B8F-0000-0000-C000-000000000046"), 0x10),
]

# FTM (File Transfer Manager) interfaces.  BILLADD's CXferService::HrInit
# opens a pipe on svc_name="FTM" and queries IID 0x00028B25.  Without a
# discovery reply the client blocks for ~58 s and the billing dialog aborts.
FTM_INTERFACE_GUIDS = [
    (_guid_le("00028B25-0000-0000-C000-000000000046"), 0x01),
    (_guid_le("00028B26-0000-0000-C000-000000000046"), 0x02),
]

# OnlStmt (Online Statement / Tools > Billing > Summary of Charges).
# Launched as ONLSTMT.EXE; opens a pipe with svc_name="OnlStmt".  The
# client holds a 27-entry IID array at ONLSTMT.EXE:0x7f35be98, passed
# as the second argument to proxy->m24("OnlStmt", iid_array, ..., 3, 0)
# at 0x7f351491.  Selectors assigned contiguously so the client's
# IID→selector lookup resolves for each one.
ONLSTMT_INTERFACE_GUIDS = [
    (_guid_le("00028B8D-0000-0000-C000-000000000046"), 0x01),
    (_guid_le("00028B8E-0000-0000-C000-000000000046"), 0x02),
    (_guid_le("00028B8F-0000-0000-C000-000000000046"), 0x03),
    (_guid_le("00028B90-0000-0000-C000-000000000046"), 0x04),
    (_guid_le("00028B91-0000-0000-C000-000000000046"), 0x05),
    (_guid_le("00028BA0-0000-0000-C000-000000000046"), 0x06),
    (_guid_le("00028BA1-0000-0000-C000-000000000046"), 0x07),
    (_guid_le("00028BB0-0000-0000-C000-000000000046"), 0x08),
    (_guid_le("00028BB1-0000-0000-C000-000000000046"), 0x09),
    (_guid_le("00028BB2-0000-0000-C000-000000000046"), 0x0A),
    (_guid_le("00028BB3-0000-0000-C000-000000000046"), 0x0B),
    (_guid_le("00028BB4-0000-0000-C000-000000000046"), 0x0C),
    (_guid_le("00028BB5-0000-0000-C000-000000000046"), 0x0D),
    (_guid_le("00028BB6-0000-0000-C000-000000000046"), 0x0E),
    (_guid_le("00028BB7-0000-0000-C000-000000000046"), 0x0F),
    (_guid_le("00028BB8-0000-0000-C000-000000000046"), 0x10),
    (_guid_le("00028BC0-0000-0000-C000-000000000046"), 0x11),
    (_guid_le("00028BC1-0000-0000-C000-000000000046"), 0x12),
    (_guid_le("00028BC2-0000-0000-C000-000000000046"), 0x13),
    (_guid_le("00028BC3-0000-0000-C000-000000000046"), 0x14),
    (_guid_le("00028BC4-0000-0000-C000-000000000046"), 0x15),
    (_guid_le("00028BC5-0000-0000-C000-000000000046"), 0x16),
    (_guid_le("00028BC6-0000-0000-C000-000000000046"), 0x17),
    (_guid_le("00028BC7-0000-0000-C000-000000000046"), 0x18),
    (_guid_le("00028BC8-0000-0000-C000-000000000046"), 0x19),
    (_guid_le("00028BC9-0000-0000-C000-000000000046"), 0x1A),
    (_guid_le("00028BCA-0000-0000-C000-000000000046"), 0x1B),
]

# MEDVIEW (MedView title loader — MOSVIEW.EXE).  Client-side IID array at
# MVTTL14C.DLL:0x7E84C1B0 — 42 IIDs consulted by hrAttachToService when
# the factory resolves the service's interface table.  Selectors assigned
# 1-based in array order, matching the in-code immediates used by
# MVTTL14C (TitleOpen=1, TitleGetInfo=3, TitlePreNotify=0x1E, handshake=0x1F).
# See docs/MEDVIEW.md §2.1.
MEDVIEW_INTERFACE_GUIDS = [
    (_guid_le(f"00028B{xx:02X}-0000-0000-C000-000000000046"), sel)
    for sel, xx in enumerate(
        (
            0x71, 0x72, 0x73, 0x74, 0x78, 0x79,
            0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
            0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91,
            0xA0, 0xA1,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
            0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
        ),
        start=0x01,
    )
]

# MEDVIEW service version advertised at pipe-open time.  Value at
# MVTTL14C.DLL:hrAttachToService (factory slot 0x24, 5th arg).  The client
# stores it locally only — the server just has to accept the pipe.
MEDVIEW_SERVICE_VERSION = 0x1400800A

# MEDVIEW selector constants per `docs/medview-service-contract.md`.
# Names mirror the spec's `Class.Method` form so call sites read like the
# wire contract.

# --- BootstrapDiscovery (class 0x00) ---
# Discovery selector 0x00 is bound to `class=0x00` and synthesised by
# `build_discovery_packet` rather than dispatched through `handle_request`,
# so no constant is exposed.

# --- TitleService ---
MEDVIEW_VALIDATE_TITLE = 0x00
MEDVIEW_OPEN_TITLE = 0x01
MEDVIEW_CLOSE_TITLE = 0x02
MEDVIEW_GET_TITLE_INFO_REMOTE = 0x03
MEDVIEW_QUERY_TOPICS = 0x04
MEDVIEW_PRE_NOTIFY_TITLE = 0x1E

# --- AddressHighlightService ---
MEDVIEW_CONVERT_ADDRESS_TO_VA = 0x05
MEDVIEW_CONVERT_HASH_TO_VA = 0x06
MEDVIEW_CONVERT_TOPIC_TO_VA = 0x07
MEDVIEW_LOAD_TOPIC_HIGHLIGHTS = 0x10
MEDVIEW_FIND_HIGHLIGHT_ADDRESS = 0x11
MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT = 0x12
MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS = 0x13

# --- WordWheelService ---
MEDVIEW_QUERY_WORD_WHEEL = 0x08
MEDVIEW_OPEN_WORD_WHEEL = 0x09
MEDVIEW_CLOSE_WORD_WHEEL = 0x0A
MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX = 0x0B
MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY = 0x0C
MEDVIEW_COUNT_KEY_MATCHES = 0x0D
MEDVIEW_READ_KEY_ADDRESSES = 0x0E
MEDVIEW_SET_KEY_COUNT_HINT = 0x0F

# --- TopicCacheService ---
MEDVIEW_FETCH_NEARBY_TOPIC = 0x15
MEDVIEW_FETCH_ADJACENT_TOPIC = 0x16

# --- SessionService ---
MEDVIEW_SUBSCRIBE_NOTIFICATIONS = 0x17
MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS = 0x18
MEDVIEW_ATTACH_SESSION = 0x1F

# --- RemoteFileService ---
MEDVIEW_OPEN_REMOTE_HFS_FILE = 0x1A
MEDVIEW_READ_REMOTE_HFS_FILE = 0x1B
MEDVIEW_CLOSE_REMOTE_HFS_FILE = 0x1C
MEDVIEW_GET_REMOTE_FS_ERROR = 0x1D

# --- Legacy aliases retained for callers that imported the old names ---
MEDVIEW_SELECTOR_TITLE_OPEN = MEDVIEW_OPEN_TITLE
MEDVIEW_SELECTOR_TITLE_GET_INFO = MEDVIEW_GET_TITLE_INFO_REMOTE
# Cache-miss fallback selectors (`docs/MEDVIEW.md` §6b).  All three
# share the same wire shape — `0x01 <title_byte> 0x03 <key:dword>` —
# and the same reply contract: ack-only via `0x87`, the real answer
# arrives through the selector-`0x17` type-3 async-push channel.
# Without ack-only handlers the engine sees `unhandled selector`,
# treats it as an RPC error, and bails the retry loop on the first
# iteration.  Empirically (live SoftIce trace 2026-04-27),
# vaConvertHash fires for the initial-selector navigation in
# `MOSVIEW!CreateMosViewWindowHierarchy` once the lp's title-handle slot is wired.
MEDVIEW_SELECTOR_VA_CONVERT_HASH = MEDVIEW_CONVERT_HASH_TO_VA
MEDVIEW_SELECTOR_VA_CONVERT_TOPIC = MEDVIEW_CONVERT_TOPIC_TO_VA
MEDVIEW_SELECTOR_HIGHLIGHTS_IN_TOPIC = MEDVIEW_LOAD_TOPIC_HIGHLIGHTS
# va→content-chunk fallback fired by `MVTTL14C!HfcNear @ 0x7E84589F` when
# the per-title cache (`HfcCache_FindEntryAndPromote`, tree at `title+4`, recent at
# `title+0x10..0x34`) misses.  Wire shape mirrors selector 0x07
# (`vaConvertTopicNumber`): `0x01 <title_byte> 0x03 <va:dword>`, ack-only
# reply.  The real answer is expected via selector 0x17 type-3 async push
# (op-code unknown — likely op-code 5 `NotificationType3_ApplyInfo6eCacheRecord`, marked "secondary
# cache, unresolved" in project memory).  Without this handler the
# request would log "unhandled selector=0x15" and the client's RPC
# returns -1, killing the retry loop.  fMVSetAddress in MVCL14N gates
# initial paint on this — `NavigateMosViewPane` (MOSVIEW pane.SetAddress)
# checks fMVSetAddress's return and sets the pane FAIL flag at +0x84
# on zero, blocking paint of the inner content panes.  Reached from
# MOSVIEW!CreateMosViewWindowHierarchy (CreateMediaViewWindow's pane attach) at
# initial open, NOT from NavigateViewerSelection (which is the
# click-handler path the original docs/MEDVIEW.md §6b assumed).
MEDVIEW_SELECTOR_VA_RESOLVE = MEDVIEW_FETCH_NEARBY_TOPIC
# `MVTTL14C!HfcNextPrevHfc @ 0x7E845ABB` — next/prev navigation on the
# per-title cache (`title+4` tree).  Same wire shape as 0x15 plus a
# direction byte (0=prev, 1=next).  Fires on cache miss when MVCL14N
# walks adjacent content during render scrollback / pagination.  Reply
# ack-only — engine retries internally; with the va=1 entry already
# cached from our 0x15 push, it falls back to local cache.
MEDVIEW_SELECTOR_HFC_NEXT_PREV = MEDVIEW_FETCH_ADJACENT_TOPIC
# Async-notification subscribe: `hrAttachToService` allocates 5 callback
# slots via `MVAsyncNotifyDispatch`, each of which fires `MVAsyncSubscriberSubscribe` to call
# selector 0x17 with a single byte (the notification-type index, 0-7).
# The reply is expected to carry an async-iterator handle; an empty
# static-only reply tells the client "subscribe declined" so it stops
# retrying this slot.  No live notification feed exists server-side yet.
MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION = MEDVIEW_SUBSCRIBE_NOTIFICATIONS
# Baggage / HFS file access (docs/MEDVIEW.md §6c).  HFS = a Marvel-
# specific bundle of supporting media (icons, sounds, helper files)
# referenced by authored content.  Fires once render starts and the
# content graph references a baggage filename.  Three-call protocol:
# OpenHfs → LcbReadHf (variable bytes) → HfCloseHf.  Decline opens
# (reply byte=0) when no baggage is hosted server-side.
MEDVIEW_SELECTOR_HFS_OPEN = MEDVIEW_OPEN_REMOTE_HFS_FILE
MEDVIEW_SELECTOR_HFS_READ = MEDVIEW_READ_REMOTE_HFS_FILE
MEDVIEW_SELECTOR_HFS_CLOSE = MEDVIEW_CLOSE_REMOTE_HFS_FILE
MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY = MEDVIEW_PRE_NOTIFY_TITLE
MEDVIEW_SELECTOR_HANDSHAKE = MEDVIEW_ATTACH_SESSION

del _guid_le
