"""FTM service handler: File Transfer Manager.

Two call patterns are covered:

- BILLADD's billing path: client sends FtmClientFileId with name="plans.txt"
  and asks for one file. Server echoes the name and serves it through the
  HrBillClient fast path.

- SIGNUP.EXE's signup path: client sends FtmClientFileId with
  name="LOGSRV" and a 4-iteration counter at CFI offset 40 (0..3).
  Server maps the counter to the four files SIGNUP.EXE validates next to
  its module (plans.txt / prodinfo.rtf / legalagr.rtf / newtips.rtf),
  overrides the echoed filename, and serves minimal placeholder content
  so the RTFs parse cleanly in RichEdit.

- MOSAF's BBS attachment path: client sends name="BBS" plus a file
  resource identifier for an attachment node. Server preserves MOSAF's
  local filename and returns the uploaded MOS2 container for FTMAPI to
  decompress.

- MOSSHELL's Download-and-Run path: client sends name="DIRSRV" plus a
  file resource identifier naming a node and one of its properties.
  Server resolves the property to its uploaded shabby and streams the
  compressed payload on the selector-0x01 iterator.
"""

import logging
import struct
from dataclasses import replace
from pathlib import Path

from ..config import FTM_INTERFACE_GUIDS, TAG_DYNAMIC_STREAM_END, TAG_END_STATIC
from ..models import VarParam
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_dword,
    build_tagged_reply_var,
    parse_request_params,
)
from ..session import Session
from ..store import app_store as _default_store
from . import shabby
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)

FTM_SELECTOR_REQUEST_DOWNLOAD = 0x00
FTM_SELECTOR_START_DOWNLOAD = 0x01
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
FTM_REPLY_UNPACK_METHOD_OFFSET = 0x14

FTM_BILL_CLIENT_REPLY_SIZE = 0x12
FTM_BILL_CLIENT_PAYLOAD_SIZE_OFFSET = 0x10

FTM_FLAG_HAS_UNPACK_METHOD = 0x01
FTM_FLAG_FAST_PATH = 0x02
FTM_FLAG_HAS_FILENAME = 0x08
FTM_REQUEST_REPLY_FLAGS = (
    FTM_FLAG_HAS_UNPACK_METHOD | FTM_FLAG_FAST_PATH | FTM_FLAG_HAS_FILENAME
)

FTM_FALLBACK_FILENAME = "plans.txt"
FTM_BBS_SOURCE = "BBS"
FTM_BBS_FRI_KIND = 2
# Reply dword 5. FTMAPI runs HrMos2DecompFile @ 0x7F6B34A8 over the received
# file, which is the inverse of the HrMos2CompFile every uploader ran.
FTM_MOS2_UNPACK_METHOD = 3

FTM_DIRSRV_SOURCE = "DIRSRV"
# The only property MOSSHELL asks for over FTM. DownloadContentToTempPath @
# 0x7F3FE871 hardcodes it for the Download-and-Run worker.
FTM_DIRSRV_FILE_PROPERTY = "fi"

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
    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands.
        self.session = session or Session()

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(FTM_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        if selector == FTM_SELECTOR_REQUEST_DOWNLOAD:
            filename, content = _resolve_ftm_target(payload)
            log.info("request_download filename=%s content_len=%d", filename, len(content))
            source_names_the_file = filename in (FTM_BBS_SOURCE, FTM_DIRSRV_SOURCE)
            # A DIRSRV payload is always bigger than the 970-byte fast-path
            # window CXferFile::HrStartDownload @ FTMAPI 0x7F6B2565 allows, and
            # the caller already chose the local path, so it takes neither the
            # HrBillClient shortcut nor a filename override.
            is_streamed = filename == FTM_DIRSRV_SOURCE
            unpack_method = (
                FTM_MOS2_UNPACK_METHOD if source_names_the_file else 0
            )
            reply_payload = _build_request_download_reply(
                filename,
                len(content),
                unpack_method=unpack_method,
                override_filename=not source_names_the_file,
                fast_path=not is_streamed,
            )
            flags = FTM_FLAG_HAS_UNPACK_METHOD
            if not is_streamed:
                flags |= FTM_FLAG_FAST_PATH
            if not source_names_the_file:
                flags |= FTM_FLAG_HAS_FILENAME
            log.info(
                "request_download_reply status=0 size=%d flags=0x%02x unpack=%d filename=%r",
                len(content),
                flags,
                unpack_method,
                None if source_names_the_file else filename,
            )
        elif selector == FTM_SELECTOR_START_DOWNLOAD:
            filename, content = _resolve_ftm_target(payload)
            log.info(
                "start_download source=%s bytes=%d", filename, len(content)
            )
            reply_payload = _build_start_download_reply(content)
        elif selector == FTM_SELECTOR_BILL_CLIENT:
            _, content = _resolve_ftm_target(payload, record_download=True)
            log.info("bill_client content_len=%d", len(content))
            reply_payload = _build_bill_client_reply(content)
            log.info("bill_client_reply status=0 payload_len=%d", len(content))
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
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


def _resolve_ftm_target(payload, *, record_download=False):
    """Map an FTM request to (on-disk filename, file content).

    The client-given CFI name drives the lookup:
    - name="LOGSRV" → signup flow.  The client only sends a 0..3
      counter, not a per-request filename, so we translate the counter
      via SIGNUP_LOGSRV_FILENAMES and then read that file from disk.
      Out-of-range counter falls back to an empty file named "LOGSRV".
    - name="BBS" → resolve the four-dword file resource identifier to a
      BBS attachment node, then serve its parent message's upload bytes.
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

    if source == FTM_BBS_SOURCE:
        return source, _resolve_bbs_attachment(cfi, record_download=record_download)

    if source == FTM_DIRSRV_SOURCE:
        return source, _resolve_dirsrv_property_file(cfi)

    content = _read_signup_file(source)
    if content is not None:
        return source, content
    return source, b""


def _resolve_bbs_attachment(cfi, *, record_download=False):
    """Resolve MOSAF's BBS file resource identifier to its upload bytes.

    BBSNAV FUN_7F5FC919 gives MOSAF `(kind=2, board_id, message_id+k)`;
    MOSAF FUN_7F4C18B0 stores those values in the four-dword FRI that
    FTMAPI SetFcfi copies to offsets 0x20..0x2f of the client file id.
    """
    kind, board_id, attachment_id, reserved = struct.unpack_from(
        "<IIII", cfi, FTM_FILENAME_BYTES
    )
    log.info(
        "resolve_bbs_attachment kind=%d board_id=%d attachment_id=%d reserved=%d",
        kind,
        board_id,
        attachment_id,
        reserved,
    )
    if kind != FTM_BBS_FRI_KIND or reserved != 0:
        return b""

    attachment = _default_store.content.get_node(f"{attachment_id}:{board_id}")
    attachment_bbs = attachment.content.bbs if attachment is not None else None
    if attachment_bbs is None or attachment_bbs.parent_subid == 0:
        return b""

    message_id = attachment_bbs.parent_subid
    message = _default_store.content.get_node(f"{message_id}:{board_id}")
    message_bbs = message.content.bbs if message is not None else None
    if message_bbs is None:
        return b""
    attachment_index = attachment_id - message_id
    if not 1 <= attachment_index <= message_bbs.attachment_count:
        return b""
    content = message_bbs.attachment_data
    if record_download and content:
        download_count = attachment_bbs.download_count + 1
        attachment = replace(
            attachment,
            content=replace(
                attachment.content,
                bbs=replace(attachment_bbs, download_count=download_count),
            ),
        )
        _default_store.content.add_node(attachment)
        log.info(
            "bbs_attachment_download attachment=%s count=%d",
            attachment.node_id,
            download_count,
        )
    return content


def _resolve_dirsrv_property_file(cfi):
    """Resolve MOSSHELL's DIRSRV file request to the shabby a property names.

    `CMosTreeNode::GetShabbyViaFtm` @ MOSSHELL 0x7F3FD800 builds the 16-byte
    file resource identifier as `[node+0x1c][node+0x18][property name]` — the
    two halves of the node's wire mnid in reverse order, then up to 8 bytes of
    ASCII property name. The Download-and-Run worker
    (`DownloadContentToTempPath` @ 0x7F3FE871) always names `fi`, so the blob
    is the compressed payload the DLRed page uploaded through AddShabby.
    """
    field_8, field_0 = struct.unpack_from("<II", cfi, FTM_FILENAME_BYTES)
    raw_name = cfi[FTM_FILENAME_BYTES + 8 : FTM_FILENAME_BYTES + 16]
    prop = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
    node_id = f"{field_0}:{field_8}"
    log.info("resolve_dirsrv_file node=%s property=%r", node_id, prop)

    if prop != FTM_DIRSRV_FILE_PROPERTY:
        log.warning("resolve_dirsrv_file unsupported property=%r", prop)
        return b""

    # An unknown id yields a placeholder node, not None — match on the id it
    # came back with, the same way SetProperties does.
    node = _default_store.content.get_node(node_id)
    if node is None or node.node_id != node_id:
        log.warning("resolve_dirsrv_file unknown node=%s", node_id)
        return b""

    shabby_id = node.content.dnr_shabby_id
    if not shabby_id:
        log.warning("resolve_dirsrv_file node=%s carries no file", node_id)
        return b""

    blob = shabby.load_shabby_bytes(shabby_id) or b""
    log.info(
        "resolve_dirsrv_file node=%s shabby_id=0x%08x bytes=%d",
        node_id,
        shabby_id,
        len(blob),
    )
    return blob


def _encode_reply_filename(filename):
    """Encode the echoed local filename safely for the reply buffer."""
    encoded = filename.encode("ascii", errors="ignore")[: FTM_FILENAME_BYTES - 1]
    if not encoded:
        encoded = FTM_FALLBACK_FILENAME.encode("ascii")
    return encoded + b"\x00"


def _build_start_download_reply(content):
    """HrStartDownload reply: two status dwords, then the file on the iterator.

    `CXferFile::HrStartDownload` @ FTMAPI 0x7F6B2565 sends the 68-byte client
    file id on selector 0x01, requires a reply whose static section is at
    least 8 bytes with a non-negative first dword, and then takes the
    request's dynamic iterator through vtable `+0x48`.
    `CXferFile::HrQueryProgress` @ 0x7F6B27D7 pumps that iterator and
    WriteFile's every chunk it yields until the stream reports 0x0B0B000B.

    0x88 rather than 0x86 for the same reason GetChildren uses it: the reader
    is MPCCL's dynamic iterator waiting on +0x28/+0x2c, not a single-shot
    Wait(). The transport splits the body across pipe frames on its own.
    """
    return (
        build_tagged_reply_dword(0)
        + build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
        + content
    )


def _build_request_download_reply(
    filename,
    content_len,
    *,
    unpack_method=0,
    override_filename=True,
    fast_path=True,
):
    """HrRequestDownload reply: 72 bytes inside a 0x84 variable tag.

      dword  0: HRESULT (0 = success)
      dword  1: echoed into param_1+0x260
      dword  2: size1 -> CXferFile+0x08 (FSetFileSize) — use content length
      dword  3: size2 -> CXferFile+0x0c  (<= 0x3ca triggers fast path) — same
      dword  4: flags  -> CXferFile+0x10  (bit 0 = has unpack method,
                                           bit 1 = fast path via HrBillClient,
                                           bit 3 = filename follows at +40)
      dword  5: unpack method -> CXferFile+0x14  (0 = no-op,
                                                  3 = HrMos2DecompFile)
      dword  6: -> CXferFile+0x18
      dword  7..9: misc fields echoed into FTM_REQUEST_INFO
      bytes 40..: filename (read only when flags bit 3 is set)

    Signup downloads use flags=0x0B (bits 0, 1, 3): fast path + unpack
    method + filename override. BBS downloads use 0x03 and unpack method
    3: MOSAF already supplied the attachment filename, and the transferred
    bytes are the MOS2 container uploaded by the Compose window.

    Download-and-Run uses 0x01. Clearing bit 1 matters: with the fast path on,
    `CXferFile::HrStartDownload` @ FTMAPI 0x7F6B2565 answers the whole request
    from HrBillClient when size2 is at most 0x3CA, and seeks the local file to
    0x3CA before streaming when it is larger. A compressed program is always
    larger, so it takes the selector-0x01 iterator from byte zero instead.
    """
    buf = bytearray(FTM_REPLY_SIZE)
    struct.pack_into("<I", buf, FTM_REPLY_STATUS_OFFSET, 0)
    struct.pack_into("<I", buf, FTM_REPLY_SIZE1_OFFSET, content_len)
    struct.pack_into("<I", buf, FTM_REPLY_SIZE2_OFFSET, content_len)
    flags = FTM_FLAG_HAS_UNPACK_METHOD
    if fast_path:
        flags |= FTM_FLAG_FAST_PATH
    if override_filename:
        flags |= FTM_FLAG_HAS_FILENAME
    struct.pack_into("<I", buf, FTM_REPLY_FLAGS_OFFSET, flags)
    struct.pack_into("<I", buf, FTM_REPLY_UNPACK_METHOD_OFFSET, unpack_method)
    if override_filename:
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
