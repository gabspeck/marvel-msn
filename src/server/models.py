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
    pipe_idx: int
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
    prop_group: str = ""
    flags: int = 0
    dword_0: int = 0
    dword_1: int = 0
    recv_descriptors: list[int] = field(default_factory=list)
    node_id_raw: bytes = b""
    locale_raw: bytes = b""
    locale_lcid: int | None = None
