"""FTM service handler: File Transfer Manager.

BILLADD's billing path only needs two FTM calls from our server:

- selector 0x00: HrRequestDownload metadata reply
- selector 0x03: HrBillClient transfer reply

Those two replies are enough to push CXferFile down the empty-file fast path
and let BILLADD complete its local download loop without hanging.
"""
import struct

from ..config import FTM_INTERFACE_GUIDS
from ..mpc import (
    build_host_block, build_discovery_host_block, build_service_packet,
    build_discovery_payload, build_tagged_reply_var,
    parse_request_params,
)
from ..models import VarParam

FTM_SELECTOR_REQUEST_DOWNLOAD = 0x00
FTM_SELECTOR_BILL_CLIENT = 0x03
FTM_CLIENT_FILE_ID_SIZE = 60
FTM_FILENAME_BYTES = 32

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
FTM_REQUEST_REPLY_FLAGS = (
    FTM_FLAG_HAS_COMPRESSED_SIZE |
    FTM_FLAG_FAST_PATH |
    FTM_FLAG_HAS_FILENAME
)

FTM_FALLBACK_FILENAME = 'plans.txt'


class FTMHandler:
    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(FTM_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload,
                       server_seq, client_ack):
        print(f"  [FTM] request class=0x{msg_class:02x} selector=0x{selector:02x} "
              f"req_id={request_id} payload_len={len(payload)}")

        if selector == FTM_SELECTOR_REQUEST_DOWNLOAD:
            filename = _extract_requested_filename(payload)
            print(f"  [FTM] requested filename: {filename!r}")
            reply_payload = _build_request_download_reply(filename)
        elif selector == FTM_SELECTOR_BILL_CLIENT:
            reply_payload = _build_bill_client_reply()
        else:
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def _extract_requested_filename(payload):
    """Pull the source filename out of a SetFcfi / FtmClientFileId request.

    HrRequestDownload writes a 60-byte FtmClientFileId whose first 32 bytes
    are the NUL-terminated filename from CXferFile+0x34 (seeded by HrInit
    from FTM_REQUEST_INFO+4).  Falling back to 'plans.txt' keeps us working
    even if the param layout ever changes.
    """
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if not isinstance(p, VarParam):
            continue
        if p.tag != 0x04 or len(p.data) != FTM_CLIENT_FILE_ID_SIZE:
            continue
        name = p.data[:FTM_FILENAME_BYTES].split(b'\x00', 1)[0]
        if not name:
            continue
        try:
            return name.decode('ascii')
        except UnicodeDecodeError:
            continue
    return FTM_FALLBACK_FILENAME


def _encode_reply_filename(filename):
    """Encode the echoed local filename safely for the reply buffer."""
    encoded = filename.encode('ascii', errors='ignore')[:FTM_FILENAME_BYTES - 1]
    if not encoded:
        encoded = FTM_FALLBACK_FILENAME.encode('ascii')
    return encoded + b'\x00'


def _build_request_download_reply(filename):
    """HrRequestDownload reply: 72 bytes inside a 0x84 variable tag.

      dword  0: HRESULT (0 = success)
      dword  1: echoed into param_1+0x260
      dword  2: size1 -> CXferFile+0x08 (FSetFileSize)
      dword  3: size2 -> CXferFile+0x0c  (<= 0x3ca triggers fast path)
      dword  4: flags  -> CXferFile+0x10  (bit 0 = has compressed_size,
                                           bit 1 = fast path via HrBillClient,
                                           bit 3 = filename follows at +40)
      dword  5: compressed_size -> CXferFile+0x14  (must be <= 3;
                                                    also selects HrUnpack branch —
                                                    0 = no-op cleanup)
      dword  6: -> CXferFile+0x18
      dword  7..9: misc fields echoed into FTM_REQUEST_INFO
      bytes 40..: filename (read only when flags bit 3 is set)

    flags=0x0B (bits 0, 1, 3): fast path + has compressed_size + has filename.
    compressed_size=0 makes CXferFile+0x14 end up 0, so HrUnpack takes the
    close-handles-only branch.  The filename at offset 40 is copied into
    FTM_REQUEST_INFO+0x24 via lstrcpyA; HrInit then appends it to the
    download dir to form "<dir>\\<filename>".  Without this override
    FTM_REQUEST_INFO+0x24 is empty and HrInit's FPathIsDirectory check
    on the bare download directory returns TRUE, yielding error 0x8b0b0050
    ("Filename not valid.  This filename conflicts with an existing
    directory name.").  We echo the filename the client put in the
    FtmClientFileId so each enumerator iteration (plans.txt, ms_Ynt.hlp)
    writes to its own local file.
    """
    buf = bytearray(FTM_REPLY_SIZE)
    struct.pack_into('<I', buf, FTM_REPLY_STATUS_OFFSET, 0)  # HRESULT = S_OK
    struct.pack_into('<I', buf, FTM_REPLY_SIZE1_OFFSET, 0)   # size1 = 0 (empty file)
    struct.pack_into('<I', buf, FTM_REPLY_SIZE2_OFFSET, 0)   # size2 = 0 (<= 0x3ca)
    struct.pack_into('<I', buf, FTM_REPLY_FLAGS_OFFSET, FTM_REQUEST_REPLY_FLAGS)
    struct.pack_into('<I', buf, FTM_REPLY_COMPRESSED_SIZE_OFFSET, 0)
    name_bytes = _encode_reply_filename(filename)
    buf[FTM_REPLY_FILENAME_OFFSET:FTM_REPLY_FILENAME_OFFSET + len(name_bytes)] = name_bytes
    return build_tagged_reply_var(0x84, bytes(buf))


def _build_bill_client_reply():
    """HrBillClient reply: 18-byte minimum inside a 0x84 variable tag.

      dword  0: HRESULT (0 = success; <0 aborts the transfer)
      bytes  4..15: ignored
      ushort @0x10: size of payload chunk that follows at offset 0x12
      bytes 0x12..: payload, WriteFile'd to the download file handle

    size=0 produces a zero-length WriteFile — valid, leaves the empty
    plans.txt/ms_Ynt.hlp file on disk so the caller's enumerator loop
    terminates cleanly.
    """
    buf = bytearray(FTM_BILL_CLIENT_REPLY_SIZE)
    struct.pack_into('<I', buf, 0x00, 0)    # HRESULT = S_OK
    struct.pack_into('<H', buf, FTM_BILL_CLIENT_PAYLOAD_SIZE_OFFSET, 0)
    return build_tagged_reply_var(0x84, bytes(buf))
