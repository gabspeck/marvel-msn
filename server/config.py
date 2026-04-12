"""Protocol constants and configuration for the Marvel MSN server."""
import uuid

# --- Network ---
HOST = "0.0.0.0"
PORT = 2323

# --- Packet framing ---
PACKET_TERMINATOR = 0x0D
ESCAPE_CHAR = 0x1B
ACK_SEQ_BYTE = 0x41     # Packet type: ACK
NACK_SEQ_BYTE = 0x42    # Packet type: NACK

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
TAG_END_STATIC = 0x87       # End of static section marker
TAG_DYNAMIC_COMPLETE = 0x88 # Dynamic complete — remaining bytes are raw data

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
    0x1B: b'\x1b\x30',  # escape char
    0x0D: b'\x1b\x31',  # CR / packet terminator
    0x10: b'\x1b\x32',  # DLE
    0x0B: b'\x1b\x33',  # VT
    0x8D: b'\x1b\x34',  # high control
    0x90: b'\x1b\x35',  # high control
    0x8B: b'\x1b\x36',  # high control
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

DIRSRV_INTERFACE_GUIDS = [
    (_guid_le("00028B27-0000-0000-C000-000000000046"), 0x01),
]

# FTM (File Transfer Manager) interfaces.  BILLADD's CXferService::HrInit
# opens a pipe on svc_name="FTM" and queries IID 0x00028B25.  Without a
# discovery reply the client blocks for ~58 s and the billing dialog aborts.
FTM_INTERFACE_GUIDS = [
    (_guid_le("00028B25-0000-0000-C000-000000000046"), 0x01),
    (_guid_le("00028B26-0000-0000-C000-000000000046"), 0x02),
]

del _guid_le
