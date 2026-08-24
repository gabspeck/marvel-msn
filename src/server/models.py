"""Protocol model classes for the Marvel MSN server."""

from dataclasses import dataclass, field

# --- Transport layer ---


@dataclass
class Packet:
    type: str  # 'DATA', 'ACK', 'NACK'
    seq: int | None
    ack: int
    payload: bytes
    crc_ok: bool


# --- Pipe layer ---


@dataclass
class PipeFrame:
    # The reassembly context this frame's message occupies, not a pipe number.
    reassembly_index: int
    has_length: bool
    continuation: bool
    last_data: bool
    content_length: int
    content: bytes


@dataclass
class ControlMessage:
    ctrl_type: int
    data: bytes


@dataclass
class PipeOpenRequest:
    client_pipe_idx: int
    svc_name: str
    ver_param: str
    version: int


@dataclass
class PipeData:
    pipe_idx: int
    data: bytes


# --- MPC layer ---


@dataclass
class HostBlock:
    msg_class: int
    selector: int
    request_id: int
    payload: bytes


# --- Tagged parameters ---


@dataclass
class ByteParam:
    tag: int
    value: int


@dataclass
class WordParam:
    tag: int
    value: int


@dataclass
class DwordParam:
    tag: int
    value: int


@dataclass
class VarParam:
    tag: int
    data: bytes


@dataclass
class ChunkedParam:
    """A variable field too large to fit in the inline request body.

    `MPCCL!AppendTaggedRequestField @ 0x046067E2` takes this path when the tag
    is variable (`tag & 0x0F == 4`) and the field needs more room than the body
    has left (`remaining <= length + 0x80`). It writes a 6-byte reference in
    place of the field — `[0x05][stream_id][u32 length]`, or tag `0x45` when the
    original tag was `0x44` — and hands the bytes to
    `AppendChunkedRequestField @ 0x04606CB2`, which queues them as class
    0xE6/0xE7 continuation frames stamped with the same `stream_id`.

    `stream_id` is a per-connection counter at `conn+0x96`, bumped under a
    critical section, so ids run 1, 2, 3 … across every chunked field on the
    connection and never collide between concurrent calls.
    """

    tag: int
    stream_id: int
    total_length: int


@dataclass
class EndMarker:
    tag: int


@dataclass
class ErrorParam:
    tag: int
    code: int


@dataclass
class UnknownParam:
    tag: int
    data: bytes


# --- Service-specific ---


@dataclass
class DirsrvRequest:
    node_id: str = "0:0"
    # Every id in the request's node array, in wire order. Left empty by
    # callers that address a single node; `__post_init__` then fills it from
    # `node_id` so a reply builder can always walk the list.
    node_ids: list[str] = field(default_factory=list)
    prop_group: str = ""
    flags: int = 0
    dword_0: int = 0
    dword_1: int = 0
    recv_descriptors: list[int] = field(default_factory=list)
    node_id_raw: bytes = b""
    locale_raw: bytes = b""
    locale_lcid: int | None = None

    def __post_init__(self):
        if not self.node_ids:
            self.node_ids = [self.node_id]
