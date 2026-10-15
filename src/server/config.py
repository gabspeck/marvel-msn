"""Protocol constants and configuration for the Marvel MSN server."""

import uuid

# --- Network ---
HOST = "0.0.0.0"
PORT = 2323
# ENGCT.EXE's TCP path. The client's port is not configurable: ENGCT pushes
# 0x239 (569) into ProxyConnectOpen, and the connector DLL writes nothing to the
# socket, so the byte stream starts at the MPC framing. 569 is privileged, so
# the host DNATs it to this unprivileged port, which keeps the direct bring-up
# on its own listener. See docs/TCP-TRANSPORT.md.
GATEWAY_PORT = 5690
# Pending connections the kernel queues while the accept loop is between
# accept() calls. Each accepted connection runs on its own thread, so this
# only has to absorb clients that dial in at the same instant.
LISTEN_BACKLOG = 8

# --- Packet framing ---
PACKET_TERMINATOR = 0x0D
ESCAPE_CHAR = 0x1B
ACK_SEQ_BYTE = 0x41  # Packet type: ACK
NACK_SEQ_BYTE = 0x42  # Packet type: NACK

# --- Header byte encoding ---
HEADER_XOR_MASK = 0xC0
HEADER_SPECIAL_VALUES = frozenset({0x8D, 0x90, 0x8B})
HEADER_ENCODED_VALUES = frozenset(v ^ HEADER_XOR_MASK for v in HEADER_SPECIAL_VALUES)

# --- CRC-32 ---
CRC_POLYNOMIAL = 0x248EF9BE
CRC_MASK_OR = 0x60

# --- Pipe frame bits ---
PIPE_ALWAYS_SET = 0x80
PIPE_HAS_LENGTH = 0x10
PIPE_CONTINUATION = 0x20
PIPE_LAST_DATA = 0x40
# Bits 3-0 name the reassembly context a message occupies while it is in
# flight, not the pipe it is for. ENGCT takes a free one from a 16-entry table
# per outbound message (`FUN_05713f8e`) and releases it on completion; the
# receiver keys its partial-message buffers on it (`recv_packet` @ 0x05714b62,
# table at transport+0x04). Routing comes from the message's own 2-byte prefix.
REASSEMBLY_INDEX_MASK = 0x0F

# --- Pipe message routing ---
ROUTING_CONTROL = 0xFFFF
ROUTING_PIPE_OPEN = 0x0000

# Shortest well-formed type-1 (connection request) type-specific field: 4-byte
# FormatVer + 4-byte LineRate + three empty NUL-terminated strings + 4-byte
# Elapsed + 28-byte OS block.
CONNECTION_REQUEST_MIN_LEN = 43

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
TAG_END_STATIC = 0x87  # End of static section marker
TAG_DYNAMIC_PARTIAL = 0x85  # raw dynamic chunk, does not signal completion
TAG_DYNAMIC_COMPLETE_SIGNAL = 0x86  # single-shot dynamic blob, signals Wait()
TAG_DYNAMIC_STREAM_END = 0x88  # iterator stream end, signals +0x28/+0x2c

# --- MPC host-block class bits ---
# A msg_class with all of 0xE0 set is a one-way continuation frame carrying a
# large input field for the preceding call. Nothing is sent back for it.
MPC_CLASS_ONEWAY_MASK = 0xE0

# A continuation frame is `[class][stream_id][raw bytes]` — no request id and no
# selector. `MPCCL!AppendChunkedRequestField @ 0x04606CB2` writes the class into
# byte 0 and the stream id into byte 1, then memcpy's the field bytes after it.
# 0xE6 means more frames follow, 0xE7 is the last one for that stream.
MPC_CLASS_CONTINUATION_MORE = 0xE6
MPC_CLASS_CONTINUATION_LAST = 0xE7
MPC_CONTINUATION_HEADER_LEN = 2

# Variable-field send tags. Bit 0x40 means the content is compressed:
# `MPCCL!AppendTaggedRequestField @ 0x046067E2` runs the buffer through the
# compressor at 0x04606558 when the caller's tag is 0x44, then emits either the
# tag itself (inline) or a chunked reference carrying the same bit. The
# compressor writes repeated [u32 chunk_len][chunk] records, each covering at
# most 0x8000 bytes of input, and tags its context "MCIC" (0x04608C00). The
# bitstream itself has not been reversed, so nothing here inflates a field —
# the compressed forms are parsed and flagged, not decoded.
MPC_TAG_VARIABLE = 0x04
MPC_TAG_VARIABLE_COMPRESSED = 0x44
MPC_TAG_CHUNKED = 0x05
MPC_TAG_CHUNKED_COMPRESSED = 0x45
MPC_CHUNKED_REF_LEN = 5  # stream_id byte + u32 length, after the tag

# --- DIRSRV property 'b' browse flags ---
# PROTOCOL.md §7.2.4 / CMosTreeNode::ExecuteCommand:
#   bit 0x01 clear = container (browse)
#   bit 0x01 set   = leaf (exec)
#   bit 0x02 set   = container has children  → SFGAO_HASSUBFOLDER
#   bit 0x04 set   = delegate (HrSetupDelegate reads 'c'/'l'/'i' and hands the
#                    folder to app 'c' navigator)
#   bit 0x08 set   = server-denied
#
# Bit 0x02 is read by CMosShellFolder::GetAttributesOf @ MOSSHELL 0x7F3F2EE0,
# which builds each pidl's SFGAO word from 'b' alone (disassembly at
# 0x7F3F2F47..0x7F3F2FA8):
#   base                 = 0x00040044
#   bit 0x01 clear       → |= 0x20000000  SFGAO_FOLDER
#   bit 0x02 set         → |= 0x80000000  SFGAO_HASSUBFOLDER, and SKIP the
#                          inner-node re-query (JNZ at 0x7F3F2F6A)
#   bit 0x02 clear       → re-ask the inner/delegate node (vtable +0x18 →
#                          its own 'b') and OR 0x80 into the attr high byte
# Leaving bit 0x02 clear tells Explorer the folder has no subfolders.
DIRSRV_BROWSE_FLAGS_CONTAINER = 0x00
DIRSRV_BROWSE_FLAGS_LEAF = 0x01
DIRSRV_BROWSE_FLAGS_HAS_CHILDREN = 0x02
DIRSRV_BROWSE_FLAGS_DELEGATE = 0x04

# --- Pipe commands ---
PIPE_CLOSE_CMD = 0x01

# --- Transport defaults ---
# Max wire bytes per packet, advertised as both PacketSize and MaxBytes. The
# client registry default is 1024 and MOSCP uses MIN(client, advertised), so
# the advertised value must cover what build_service_packet emits.
TRANSPORT_PACKET_SIZE = 1024
TRANSPORT_WINDOW_SIZE = 16
TRANSPORT_ACK_BEHIND = 1
TRANSPORT_ACK_TIMEOUT_MS = 600

# --- Timing ---
DELAY_AFTER_COM = 0.3
DELAY_BEFORE_REPLY = 0.1
SOCKET_TIMEOUT = 0.5

# --- Byte-stuffing maps ---
# Raw byte -> 0x1B-prefixed escape sequence
STUFF_MAP = {
    0x1B: b"\x1b\x30",  # escape char
    0x0D: b"\x1b\x31",  # CR / packet terminator
    0x10: b"\x1b\x32",  # DLE
    0x0B: b"\x1b\x33",  # VT
    0x8D: b"\x1b\x34",  # high control
    0x90: b"\x1b\x35",  # high control
    0x8B: b"\x1b\x36",  # high control
}

ESCAPE_SET = frozenset(STUFF_MAP)
UNSTUFF_MAP = {seq[1]: raw for raw, seq in STUFF_MAP.items()}

# --- Service interface GUIDs ---
# Each table is a service's discovery reply: (IID as bytes_le, selector), with
# selectors assigned 1.. in table order. MPCCL resolves an IID with memcmp()
# against its compiled-in GUID, so the bytes are the Windows in-memory layout.
# The resolved selector becomes the class byte of every request on that
# interface. docs/SERVICE-IIDS.md lists the IIDs each client actually resolves
# and their call sites; the tables below advertise more than that set.


def _iid_table(*iids):
    return [(uuid.UUID(iid).bytes_le, sel) for sel, iid in enumerate(iids, start=1)]


def _mos_iid_table(suffixes):
    """Table of `00028Bxx-0000-0000-C000-000000000046` IIDs, one `xx` per word."""
    return _iid_table(*(f"00028B{xx}-0000-0000-C000-000000000046" for xx in suffixes.split()))


# Resolved: 00028BC2 (selector 6).
LOGSRV_INTERFACE_GUIDS = _mos_iid_table("B6 B7 B8 C0 C1 C2 C3 C4 C5 C6")

# Resolved: 00028B27 (TREENVCL CTreeNavClient @ 0x7F63113D, selector 3) and
# 00028B28 (TREEEDCL CTreeEditClient, selector 4).
DIRSRV_INTERFACE_GUIDS = _mos_iid_table("25 26 27 28 29 2A 2B 2C 2D 2E")

# Resolved: 00028B52 (CONFAPI CmdInitializeConnection @ 0x7F5B1166) and
# 00028B72 (DATAEDCL CDataEditClient).
CONFLOC_INTERFACE_GUIDS = _mos_iid_table("52 53 54 55 56 57 58 60 61 70 71 72 73 74 78 79 81")

# Resolved: 00028BC8 (CONFAPI CceJoin @ 0x7F5B16FC).
CONFSRV_INTERFACE_GUIDS = _mos_iid_table("C8 C9 CA")

# Resolved: 00028B27, and 00028B2F when a message opens: BBSNAV @ 0x7F5FCD1A
# opens BBS a second time with parameter `agid=<locale>`. Without 00028B2F the
# reader fails with "Cannot open message" (FUN_7F5F99C1(hr, 0x44E)) before any
# request reaches the wire (SoftICE, BPX 0x7F601578).
BBS_INTERFACE_GUIDS = _mos_iid_table("25 26 27 28 29 2A 2B 2C 2D 2E 2F")

# Resolved: 00028B73 (SIGNUP.EXE @ 0x004030DC).
OLREGSRV_INTERFACE_GUIDS = _mos_iid_table("73 74 78 79 81 82 83 84 85 86 8A 8B 8C 8D 8E 8F")

# Resolved: 00028B25 (FTMAPI HrInit @ 0x7F6B1E32). Without a discovery reply
# BILLADD blocks for about 58 s and the billing dialog aborts.
FTM_INTERFACE_GUIDS = _mos_iid_table("25 26")

# Resolved: 00028B8D (ONLSTMT.EXE OnlStmt_WinMain @ 0x7F351218).
ONLSTMT_INTERFACE_GUIDS = _mos_iid_table(
    "8D 8E 8F 90 91 A0 A1 B0 B1 B2 B3 B4 B5 B6 B7 B8 C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA"
)

# Resolved: 00028B22 (MOSABP32 CAbConnection::HrGetMethod @ 0x7F4D4311).
MOSABP_INTERFACE_GUIDS = _mos_iid_table("22")

# Resolved: 00028B20 (MOSRXP32 CConn::HrGetMethod @ 0x7F431967). See docs/MOSRXP.md.
MOSRXP_INTERFACE_GUIDS = _mos_iid_table("20")

# Resolved: 00028BB0 (MOSFIND CFindConnection::HrSearch @ 0x7E9B136A), so
# HrSearch's `GetMethod(1)` arrives as class 0x01 selector 0x01.
FINDSVC_INTERFACE_GUIDS = _mos_iid_table("B0 B1 B2 B3 B4 B5")

# Resolved: 00028B8B (SACLIENT CSysAdminClient @ 0x7F3410F1).
SASRV_INTERFACE_GUIDS = _mos_iid_table(
    "8B 8C 8D 8E 8F 90 91 A0 A1 B0 B1 B2 B3 B4 B5 B6 B7 B8 C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA"
)

# Bbird_OB takes one GUID per caller through COSCL `CMPCConnection::Init`
# (`DoOpenMOSService` @ COSCL 0x4021E4E9), and two callers use different ones:
#   ...50B  write side: PUBLISH.DLL @ 0x40F01243, the Release Wizard publish.
#   ...50A  read side: OBCL.EXE, which BBVIEW goes through to fetch a title.
# A missing one gets E_NOINTERFACE and the pipe drops right after discovery.
BBIRD_OB_INTERFACE_GUIDS = _iid_table(
    "EC76D50B-BAD7-11CE-B21F-00AA004A33DB",
    "EC76D50A-BAD7-11CE-B21F-00AA004A33DB",
)

# IRCS `IRMpcConnection::DoConnect` @ 0x10005FDA, GUID at IRCS 0x10009008.
BBIR_INTERFACE_GUIDS = _iid_table("27916FC1-7F7F-11CE-A366-00AA0051EA9C")

# Resolved: 00028B71 (MVTTL14C hrAttachToService @ 0x7E844114, selector 1) and
# 00028B72 (DATAEDCL CDataEditClient, selector 2). MVTTL14C's method numbers
# are in-code immediates (TitleOpen=1, TitleGetInfo=3, TitlePreNotify=0x1E,
# handshake=0x1F). See docs/MEDVIEW.md §2.1.
MEDVIEW_INTERFACE_GUIDS = _mos_iid_table(
    "71 72 73 74 78 79 81 82 83 84 85 86 8A 8B 8C 8D 8E 8F 90 91 A0 A1"
    " B0 B1 B2 B3 B4 B5 B6 B7 B8 C0 C1 C2 C3 C4 C5 C6 C7 C8 C9 CA"
)

# MEDVIEW selectors, named after `docs/medview-service-contract.md`.

# DSNED uses the second advertised MEDVIEW interface as a DATAEDCL authoring
# channel. Its method 5 is CDataEditClient::GetTicket, distinct from the
# title proxy's selector 5.
MEDVIEW_DATA_EDIT_CLASS = 0x02
MEDVIEW_DATA_EDIT_ADD = 0x00
MEDVIEW_DATA_EDIT_DELETE = 0x01
MEDVIEW_DATA_EDIT_GET_TICKET = 0x05

# --- TitleService ---
MEDVIEW_VALIDATE_TITLE = 0x00
MEDVIEW_OPEN_TITLE = 0x01
MEDVIEW_CLOSE_TITLE = 0x02
MEDVIEW_GET_TITLE_INFO_REMOTE = 0x03
MEDVIEW_QUERY_TOPICS = 0x04
MEDVIEW_PRE_NOTIFY_TITLE = 0x1E

# --- AddressHighlightService ---
# 0x05-0x07 and 0x10 are cache-miss fallbacks (docs/MEDVIEW.md §6b), all
# `0x01 <title_byte> 0x03 <key:dword>`. vaConvertHash (0x06) fires for the
# initial navigation in `MOSVIEW!CreateMosViewWindowHierarchy` (SoftICE).
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
# 0x15: `MVTTL14C!HfcNear @ 0x7E84589F` on a per-title cache miss, shaped
# like 0x07. Reached from CreateMosViewWindowHierarchy at initial open;
# fMVSetAddress depends on it, and NavigateMosViewPane sets the pane FAIL
# flag at +0x84 when fMVSetAddress returns zero, which blocks the paint.
# 0x16: `MVTTL14C!HfcNextPrevHfc @ 0x7E845ABB`, 0x15's shape plus a
# direction byte (0 = prev, 1 = next).
MEDVIEW_FETCH_NEARBY_TOPIC = 0x15
MEDVIEW_FETCH_ADJACENT_TOPIC = 0x16

# --- SessionService ---
# 0x17: hrAttachToService allocates five callback slots through
# MVAsyncNotifyDispatch; each subscribes with one byte, the notification type.
MEDVIEW_SUBSCRIBE_NOTIFICATIONS = 0x17
MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS = 0x18
MEDVIEW_ATTACH_SESSION = 0x1F

# --- RemoteFileService ---
# Baggage access (docs/MEDVIEW.md §6c): OpenHfs, LcbReadHf, HfCloseHf.
MEDVIEW_OPEN_REMOTE_HFS_FILE = 0x1A
MEDVIEW_READ_REMOTE_HFS_FILE = 0x1B
MEDVIEW_CLOSE_REMOTE_HFS_FILE = 0x1C
MEDVIEW_GET_REMOTE_FS_ERROR = 0x1D
