"""FTM service handler: File Transfer Manager.

Two call patterns are covered:

- BILLADD's billing path: client sends FtmClientFileId with name="plans.txt"
  and asks for one file.  Server echoes the name and returns an empty file
  via the HrBillClient fast-path.

- SIGNUP.EXE's signup path: client sends FtmClientFileId with
  name="LOGSRV" and a 4-iteration counter at CFI offset 40 (0..3).
  Server maps the counter to the four files SIGNUP.EXE validates next to
  its module (plans.txt / prodinfo.rtf / legalagr.rtf / newtips.rtf),
  overrides the echoed filename, and serves minimal placeholder content
  so the RTFs parse cleanly in RichEdit.
"""

import logging
import struct
from pathlib import Path

from ..config import FTM_INTERFACE_GUIDS
from ..models import VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_var,
    parse_request_params,
)

log = logging.getLogger(__name__)

FTM_SELECTOR_REQUEST_DOWNLOAD = 0x00
FTM_SELECTOR_BILL_CLIENT = 0x03
FTM_CLIENT_FILE_ID_SIZE = 60
FTM_FILENAME_BYTES = 32
FTM_COUNTER_OFFSET = 40  # dword in the 28-byte tail, iterates 0..3 for LOGSRV

FTM_REPLY_SIZE = 72
FTM_REPLY_FILENAME_OFFSET = 40
FTM_REPLY_STATUS_OFFSET = 0x00
FTM_REPLY_SIZE1_OFFSET = 0x08
FTM_REPLY_SIZE2_OFFSET = 0x0C
FTM_REPLY_FLAGS_OFFSET = 0x10
FTM_REPLY_COMPRESSED_SIZE_OFFSET = 0x14

FTM_BILL_CLIENT_REPLY_SIZE = 0x12
FTM_BILL_CLIENT_PAYLOAD_SIZE_OFFSET = 0x10

FTM_FLAG_HAS_COMPRESSED_SIZE = 0x01
FTM_FLAG_FAST_PATH = 0x02
FTM_FLAG_HAS_FILENAME = 0x08
FTM_REQUEST_REPLY_FLAGS = FTM_FLAG_HAS_COMPRESSED_SIZE | FTM_FLAG_FAST_PATH | FTM_FLAG_HAS_FILENAME

FTM_FALLBACK_FILENAME = "plans.txt"

_SIGNUP_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "signup"

# SIGNUP.EXE!FUN_004029d8 opens these four in order and fails if any
# CreateFile(OPEN_EXISTING) returns INVALID_HANDLE_VALUE.  The FTM client
# sends name="LOGSRV" + counter 0..3, so the counter is the only
# identifier it gives us — this tuple translates it to the filename the
# client expects to receive.
SIGNUP_LOGSRV_FILENAMES = (
    "plans.txt",
    "prodinfo.rtf",
    "legalagr.rtf",
    "newtips.rtf",
)
SIGNUP_LOGSRV_SOURCE = "LOGSRV"


def _read_signup_file(filename):
    """Return the bytes of a file in the signup data dir, or None."""
    path = _SIGNUP_DATA_DIR / filename
    if not path.is_file():
        return None
    return path.read_bytes()


class FTMHandler:
    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(FTM_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if selector == FTM_SELECTOR_REQUEST_DOWNLOAD:
            filename, content = _resolve_ftm_target(payload)
            log.info("request_download filename=%s content_len=%d", filename, len(content))
            reply_payload = _build_request_download_reply(filename, len(content))
        elif selector == FTM_SELECTOR_BILL_CLIENT:
            _, content = _resolve_ftm_target(payload)
            log.info("bill_client content_len=%d", len(content))
            reply_payload = _build_bill_client_reply(content)
        else:
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def _extract_client_file_id(payload):
    """Return the first VarParam bytes from an FTM request, or None.

    Works for both the 60-byte FtmClientFileId on selector 0x00 and the
    larger 68-byte HrBillClient request on selector 0x03 (same prefix
    layout: 32-byte name + tail).
    """
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if isinstance(p, VarParam) and p.tag == 0x04 and len(p.data) >= FTM_CLIENT_FILE_ID_SIZE:
            return p.data
    return None


def _resolve_ftm_target(payload):
    """Map an FTM request to (on-disk filename, file content).

    The client-given CFI name drives the lookup:
    - name="LOGSRV" → signup flow.  The client only sends a 0..3
      counter, not a per-request filename, so we translate the counter
      via SIGNUP_LOGSRV_FILENAMES and then read that file from disk.
      Out-of-range counter falls back to an empty file named "LOGSRV".
    - Any other name → treat the name as a filename and serve it from
      server/data/signup/ if it exists; otherwise echo name + empty
      (billing's default is name="plans.txt", which maps straight to
      the same INI SIGNUP uses).
    """
    cfi = _extract_client_file_id(payload)
    if cfi is None:
        return FTM_FALLBACK_FILENAME, b""
    name = cfi[:FTM_FILENAME_BYTES].split(b"\x00", 1)[0]
    try:
        source = name.decode("ascii") if name else FTM_FALLBACK_FILENAME
    except UnicodeDecodeError:
        source = FTM_FALLBACK_FILENAME

    if source == SIGNUP_LOGSRV_SOURCE:
        counter = struct.unpack_from("<I", cfi, FTM_COUNTER_OFFSET)[0]
        if 0 <= counter < len(SIGNUP_LOGSRV_FILENAMES):
            filename = SIGNUP_LOGSRV_FILENAMES[counter]
            content = _read_signup_file(filename)
            if content is not None:
                return filename, content
        return source, b""

    content = _read_signup_file(source)
    if content is not None:
        return source, content
    return source, b""


def _encode_reply_filename(filename):
    """Encode the echoed local filename safely for the reply buffer."""
    encoded = filename.encode("ascii", errors="ignore")[: FTM_FILENAME_BYTES - 1]
    if not encoded:
        encoded = FTM_FALLBACK_FILENAME.encode("ascii")
    return encoded + b"\x00"


def _build_request_download_reply(filename, content_len):
    """HrRequestDownload reply: 72 bytes inside a 0x84 variable tag.

      dword  0: HRESULT (0 = success)
      dword  1: echoed into param_1+0x260
      dword  2: size1 -> CXferFile+0x08 (FSetFileSize) — use content length
      dword  3: size2 -> CXferFile+0x0c  (<= 0x3ca triggers fast path) — same
      dword  4: flags  -> CXferFile+0x10  (bit 0 = has compressed_size,
                                           bit 1 = fast path via HrBillClient,
                                           bit 3 = filename follows at +40)
      dword  5: compressed_size -> CXferFile+0x14  (must be <= 3;
                                                    0 = HrUnpack no-op)
      dword  6: -> CXferFile+0x18
      dword  7..9: misc fields echoed into FTM_REQUEST_INFO
      bytes 40..: filename (read only when flags bit 3 is set)

    We use flags=0x0B (bits 0, 1, 3): fast path + has compressed_size +
    has filename override.  compressed_size=0 keeps HrUnpack on its
    close-handles-only branch.  The filename at offset 40 is copied into
    FTM_REQUEST_INFO+0x24 via lstrcpyA; HrInit appends it to the
    download dir to form "<dir>\\<filename>", so each iteration writes
    to the right local file.
    """
    buf = bytearray(FTM_REPLY_SIZE)
    struct.pack_into("<I", buf, FTM_REPLY_STATUS_OFFSET, 0)
    struct.pack_into("<I", buf, FTM_REPLY_SIZE1_OFFSET, content_len)
    struct.pack_into("<I", buf, FTM_REPLY_SIZE2_OFFSET, content_len)
    struct.pack_into("<I", buf, FTM_REPLY_FLAGS_OFFSET, FTM_REQUEST_REPLY_FLAGS)
    struct.pack_into("<I", buf, FTM_REPLY_COMPRESSED_SIZE_OFFSET, 0)
    name_bytes = _encode_reply_filename(filename)
    buf[FTM_REPLY_FILENAME_OFFSET : FTM_REPLY_FILENAME_OFFSET + len(name_bytes)] = name_bytes
    return build_tagged_reply_var(0x84, bytes(buf))


def _build_bill_client_reply(content=b""):
    """HrBillClient reply: 18-byte header + inline content payload.

      dword  0: HRESULT (0 = success; <0 aborts the transfer)
      bytes  4..15: ignored
      ushort @0x10: size of payload chunk that follows at offset 0x12
      bytes 0x12..: payload, WriteFile'd to the download file handle

    Content bytes are WriteFile'd into the local file handle — this is
    the actual file content the client ends up with on disk.
    """
    buf = bytearray(FTM_BILL_CLIENT_REPLY_SIZE + len(content))
    struct.pack_into("<I", buf, 0x00, 0)
    struct.pack_into("<H", buf, FTM_BILL_CLIENT_PAYLOAD_SIZE_OFFSET, len(content))
    buf[FTM_BILL_CLIENT_REPLY_SIZE : FTM_BILL_CLIENT_REPLY_SIZE + len(content)] = content
    return build_tagged_reply_var(0x84, bytes(buf))
