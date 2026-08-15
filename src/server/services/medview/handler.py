"""MEDVIEW request dispatcher.

Maps each incoming selector to its reply builder. Tracks per-session
state needed by selectors that don't have a static answer:

- `_subscriptions` — `(msg_class, request_id)` keyed by notification
  type (0..4). Captured on `0x17` so async cache pushes can ride the
  same iterator.
- `_open_title_slots` — slots opened by `0x01`, queried by `0x00`,
  cleared by `0x02`.
- `_baggage_handles` — open `bm0` handle ids returned by `0x1A`.

Cache-miss group (`0x05`/`0x06`/`0x07`/`0x15`/`0x16`) emits a bare-ack
synchronous reply followed by an async push frame on the matching
notification iterator. Type-3 (va resolution) pushes resolve to zero
without a loaded M14. Selectors 0x15 and 0x16 wrap loaded M14 display
records in case-1 BF cache records.

OpenTitle maps the title deid to a compiled M14 file under
`resources/titles/`. Missing or malformed files fall through to the
empty `TITLE_OPEN_BODY` / `BM0_BAGGAGE`.
"""

from __future__ import annotations

import logging
import pathlib
import struct

from ...blackbird.wire import (
    build_case1_bf_chunk,
    build_case1_stream_bf_chunk,
    build_type0_status_record,
    build_type3_op4_frame,
    build_type3_transfer_status_frame,
    build_type4_transfer_chunk_frame,
)
from ...config import (
    MEDVIEW_ATTACH_SESSION,
    MEDVIEW_CLOSE_REMOTE_HFS_FILE,
    MEDVIEW_CLOSE_TITLE,
    MEDVIEW_CLOSE_WORD_WHEEL,
    MEDVIEW_CONVERT_ADDRESS_TO_VA,
    MEDVIEW_CONVERT_HASH_TO_VA,
    MEDVIEW_CONVERT_TOPIC_TO_VA,
    MEDVIEW_COUNT_KEY_MATCHES,
    MEDVIEW_DATA_EDIT_ADD,
    MEDVIEW_DATA_EDIT_CLASS,
    MEDVIEW_DATA_EDIT_DELETE,
    MEDVIEW_DATA_EDIT_GET_TICKET,
    MEDVIEW_FETCH_ADJACENT_TOPIC,
    MEDVIEW_FETCH_NEARBY_TOPIC,
    MEDVIEW_FIND_HIGHLIGHT_ADDRESS,
    MEDVIEW_GET_REMOTE_FS_ERROR,
    MEDVIEW_GET_TITLE_INFO_REMOTE,
    MEDVIEW_INTERFACE_GUIDS,
    MEDVIEW_LOAD_TOPIC_HIGHLIGHTS,
    MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY,
    MEDVIEW_OPEN_REMOTE_HFS_FILE,
    MEDVIEW_OPEN_TITLE,
    MEDVIEW_OPEN_WORD_WHEEL,
    MEDVIEW_PRE_NOTIFY_TITLE,
    MEDVIEW_QUERY_TOPICS,
    MEDVIEW_QUERY_WORD_WHEEL,
    MEDVIEW_READ_KEY_ADDRESSES,
    MEDVIEW_READ_REMOTE_HFS_FILE,
    MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS,
    MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT,
    MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX,
    MEDVIEW_SET_KEY_COUNT_HINT,
    MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
    MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS,
    MEDVIEW_VALIDATE_TITLE,
    MPC_CLASS_ONEWAY_MASK,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_PARTIAL,
)
from ...models import (
    ByteParam,
    DwordParam,
    UnknownParam,
    VarParam,
    WordParam,
)
from ...mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    parse_request_params,
)
from ...session import Session
from .._dispatch import log_unhandled_selector
from ..dirsrv import TREEEDCL_STATUS_REFUSED, build_get_ticket_reply_payload
from . import replies
from .m14_loader import (
    LoadedM14,
    build_m14_mvpfile,
    load_m14,
    lower_m14_to_osr2_payload,
    lower_m14_to_payload,
)
from .payload import (
    BM0_BAGGAGE,
    OSR2_MVPFILE,
    OSR2_TITLE_OPEN_BODY,
    TITLE_OPEN_BODY,
    TITLE_OPEN_METADATA,
    TitleOpenMetadata,
)

_TITLES_DIR = pathlib.Path(__file__).resolve().parents[4] / "resources" / "titles"
_M14_FIXTURE_FILES = {
    "4": "HANDBOOK.M14",
    "1000": "HANDBOOK.M14",
    "1001": "FRANCE.M14",
    "1002": "MVDOC.M14",
}

log = logging.getLogger(__name__)


# Maximum raw dynamic data in one HFS reply host block. MPCCL's dynamic
# receiver grows in 0x4000-byte increments, and MOSCP must copy each complete
# host block through ARENA.MOS before MPCCL can consume it. Larger logical
# reads continue with tag 0x85 and finish once with tag 0x86.
_HFS_DYNAMIC_BLOCK_DATA_MAX = 0x4000
# Keep each type-4 record within one MPCCL dynamic-buffer growth unit,
# including its 12-byte frame header and the outer 0x85 stream tag.
_PICTURE_CHUNK_DATA_MAX = 0x3F00
# BITMAPFILEHEADER + BITMAPINFOHEADER. The same 0x36 the client's decoder
# uses to tell a header-only arrival from one carrying pixel bytes.
_BMP_HEADER_BYTES = 0x36
# A full 8bpp colour table: 256 RGBQUADs.
_BMP_PALETTE_BYTES = 256 * 4
# `PictureStartPayload.modeByte`. Value 1 is the client's initial/offline
# mode: `PictureDownload_StartOrRefresh` emits it when its local transfer-mode
# flag is clear, and the same condition makes the wrapper reset the type-4
# subscriber (`MVAsyncSubscriberSetState(DAT_7E84E318, 0)`). The reset lands as
# the opcode-0x07 disable report ~130 ms behind the start request, so the mode
# byte is the only advance notice that the chunk stream is going down.
_PICTURE_MODE_SUBSCRIBER_RESET = 1
# `PictureStartPayload` entry `stateFlags` bit 0: the client's transfer object
# is already validated (`this+0x48 != 0`) by an earlier type-3 status.
_PICTURE_FLAG_OBJECT_VALID = 0x01
# Notification type carrying transfer chunks (`TransferChunkStream`).
_NOTIFICATION_TYPE_TRANSFER_CHUNK = 4
_BAGGAGE_HANDLE_BM0 = 0x42
# Per-page baggage handle base. Engine treats handles as opaque u8;
# `0x42` is the bm0 sentinel kept for log continuity. Subsequent pages
# allocate sequentially (`0x43` = bm1, `0x44` = bm2, …) up to the
# byte range — practical limit << wire spec.
_BAGGAGE_HANDLE_BASE = _BAGGAGE_HANDLE_BM0
_DIALECT_RTM = "rtm"
_DIALECT_OSR2 = "osr2"
_RTM_ATTACH_CAPABILITIES_SIZE = 12
_OSR2_ATTACH_CAPABILITIES_SIZE = 92

# Bound for the hex preview of dynamic payloads in trace logs. Keeps the
# line bounded for big bodies (TitleOpen ~6 KB, baggage chunks up to
# 60 KB) without losing the front matter that identifies the shape.
_LOG_HEX_LIMIT = 96

# `MVBuildLayoutLine`'s switch byte inside a 0xBF chunk: 4-byte header
# plus name_buf[0x26].
_BF_DISPATCH_OFFSET = 4 + 0x26

# Symbolic names for human-readable request/reply log lines.
_SELECTOR_NAMES: dict[int, str] = {
    MEDVIEW_VALIDATE_TITLE: "validate_title",
    MEDVIEW_OPEN_TITLE: "open_title",
    MEDVIEW_CLOSE_TITLE: "close_title",
    MEDVIEW_GET_TITLE_INFO_REMOTE: "get_title_info_remote",
    MEDVIEW_QUERY_TOPICS: "query_topics",
    MEDVIEW_PRE_NOTIFY_TITLE: "pre_notify_title",
    MEDVIEW_CONVERT_ADDRESS_TO_VA: "convert_address_to_va",
    MEDVIEW_CONVERT_HASH_TO_VA: "convert_hash_to_va",
    MEDVIEW_CONVERT_TOPIC_TO_VA: "convert_topic_to_va",
    MEDVIEW_LOAD_TOPIC_HIGHLIGHTS: "load_topic_highlights",
    MEDVIEW_FIND_HIGHLIGHT_ADDRESS: "find_highlight_address",
    MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT: "release_highlight_context",
    MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS: "refresh_highlight_address",
    MEDVIEW_QUERY_WORD_WHEEL: "query_word_wheel",
    MEDVIEW_OPEN_WORD_WHEEL: "open_word_wheel",
    MEDVIEW_CLOSE_WORD_WHEEL: "close_word_wheel",
    MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX: "resolve_word_wheel_prefix",
    MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY: "lookup_word_wheel_entry",
    MEDVIEW_COUNT_KEY_MATCHES: "count_key_matches",
    MEDVIEW_READ_KEY_ADDRESSES: "read_key_addresses",
    MEDVIEW_SET_KEY_COUNT_HINT: "set_key_count_hint",
    MEDVIEW_FETCH_NEARBY_TOPIC: "fetch_nearby_topic",
    MEDVIEW_FETCH_ADJACENT_TOPIC: "fetch_adjacent_topic",
    MEDVIEW_SUBSCRIBE_NOTIFICATIONS: "subscribe_notifications",
    MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS: "unsubscribe_notifications",
    MEDVIEW_ATTACH_SESSION: "attach_session",
    MEDVIEW_OPEN_REMOTE_HFS_FILE: "open_remote_hfs_file",
    MEDVIEW_READ_REMOTE_HFS_FILE: "read_remote_hfs_file",
    MEDVIEW_CLOSE_REMOTE_HFS_FILE: "close_remote_hfs_file",
    MEDVIEW_GET_REMOTE_FS_ERROR: "get_remote_fs_error",
}

# Positional names for the wire send-side parameters of each selector.
# Names mirror `docs/medview-service-contract.md`. Aligned positionally
# with `parse_request_params` output; extras are labelled `param[N]`.
_REQUEST_PARAM_NAMES: dict[int, list[str]] = {
    MEDVIEW_ATTACH_SESSION: ["clientVersion", "capabilities"],
    MEDVIEW_SUBSCRIBE_NOTIFICATIONS: ["notificationType"],
    MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS: ["notificationType"],
    MEDVIEW_VALIDATE_TITLE: ["titleSlot"],
    MEDVIEW_OPEN_TITLE: ["titleToken", "cacheHint0", "cacheHint1"],
    MEDVIEW_CLOSE_TITLE: ["titleSlot"],
    MEDVIEW_GET_TITLE_INFO_REMOTE: ["titleSlot", "infoKind", "infoArg", "callerCookie"],
    MEDVIEW_QUERY_TOPICS: [
        "titleSlot", "queryClass", "primaryText", "queryFlags", "queryMode",
        "secondaryOrSourceOrAux", "auxTail0", "auxTail1",
    ],
    MEDVIEW_PRE_NOTIFY_TITLE: ["titleSlot", "notifyOp", "notifyPayload"],
    MEDVIEW_OPEN_WORD_WHEEL: ["titleSlot", "titleName"],
    MEDVIEW_QUERY_WORD_WHEEL: ["wordWheelId", "queryMode", "queryText"],
    MEDVIEW_CLOSE_WORD_WHEEL: ["wordWheelId"],
    MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX: ["wordWheelId", "prefixText"],
    MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY: ["wordWheelId", "ordinal", "outputLimit"],
    MEDVIEW_COUNT_KEY_MATCHES: ["wordWheelId", "keyText"],
    MEDVIEW_READ_KEY_ADDRESSES: ["wordWheelId", "keyText", "startIndex", "maxCount"],
    MEDVIEW_SET_KEY_COUNT_HINT: ["wordWheelId", "keyText", "countHint"],
    MEDVIEW_CONVERT_ADDRESS_TO_VA: ["titleSlot", "addressToken"],
    MEDVIEW_CONVERT_HASH_TO_VA: ["titleSlot", "contextHash"],
    MEDVIEW_CONVERT_TOPIC_TO_VA: ["titleSlot", "topicNumber"],
    MEDVIEW_LOAD_TOPIC_HIGHLIGHTS: ["highlightContext", "topicOrAddress"],
    MEDVIEW_FIND_HIGHLIGHT_ADDRESS: ["highlightContext", "searchKey0", "searchKey1"],
    MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT: ["titleSlot"],
    MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS: ["titleSlot", "highlightId"],
    MEDVIEW_FETCH_NEARBY_TOPIC: ["titleSlot", "addressToken"],
    MEDVIEW_FETCH_ADJACENT_TOPIC: ["titleSlot", "currentToken", "direction"],
    MEDVIEW_OPEN_REMOTE_HFS_FILE: ["hfsMode", "fileName", "openMode"],
    MEDVIEW_READ_REMOTE_HFS_FILE: ["remoteHandleId", "requestedLength", "currentOffset"],
    MEDVIEW_CLOSE_REMOTE_HFS_FILE: ["remoteHandleId"],
    MEDVIEW_GET_REMOTE_FS_ERROR: [],
}

# Positional names for the tagged static-section fields of each reply,
# in the order emitted by `replies.py`. Dynamic-body labels follow.
_REPLY_FIELD_NAMES: dict[int, list[str]] = {
    MEDVIEW_ATTACH_SESSION: ["validationToken"],
    MEDVIEW_SUBSCRIBE_NOTIFICATIONS: [],
    MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS: [],
    MEDVIEW_VALIDATE_TITLE: ["isValid"],
    MEDVIEW_OPEN_TITLE: [
        "titleSlot", "fileSystemMode", "contentsVa", "contentsAddr",
        "topicUpperBound", "cacheHeader0", "cacheHeader1",
        "fontCacheHeader", "titleCacheHeader", "status",
    ],
    MEDVIEW_CLOSE_TITLE: [],
    MEDVIEW_GET_TITLE_INFO_REMOTE: ["lengthOrScalar"],
    MEDVIEW_QUERY_TOPICS: ["highlightContext", "logicalCount", "secondaryResult"],
    MEDVIEW_PRE_NOTIFY_TITLE: ["status"],
    MEDVIEW_OPEN_WORD_WHEEL: ["wordWheelId", "itemCount"],
    MEDVIEW_QUERY_WORD_WHEEL: ["status"],
    MEDVIEW_CLOSE_WORD_WHEEL: [],
    MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX: ["prefixResult"],
    MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY: [],
    MEDVIEW_COUNT_KEY_MATCHES: ["matchCount"],
    MEDVIEW_READ_KEY_ADDRESSES: [],
    MEDVIEW_SET_KEY_COUNT_HINT: ["success"],
    MEDVIEW_CONVERT_ADDRESS_TO_VA: [],
    MEDVIEW_CONVERT_HASH_TO_VA: [],
    MEDVIEW_CONVERT_TOPIC_TO_VA: [],
    MEDVIEW_LOAD_TOPIC_HIGHLIGHTS: [],
    MEDVIEW_FIND_HIGHLIGHT_ADDRESS: ["addressToken"],
    MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT: [],
    MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS: [],
    MEDVIEW_FETCH_NEARBY_TOPIC: [],
    MEDVIEW_FETCH_ADJACENT_TOPIC: [],
    MEDVIEW_OPEN_REMOTE_HFS_FILE: ["remoteHandleId", "fileSize"],
    MEDVIEW_READ_REMOTE_HFS_FILE: ["status"],
    MEDVIEW_CLOSE_REMOTE_HFS_FILE: [],
    MEDVIEW_GET_REMOTE_FS_ERROR: ["fsError"],
}

# Label applied to the post-`0x86` dynamic body when one is present.
_REPLY_BODY_NAMES: dict[int, str] = {
    MEDVIEW_OPEN_TITLE: "payloadBlob",
    MEDVIEW_GET_TITLE_INFO_REMOTE: "payload",
    MEDVIEW_QUERY_TOPICS: "auxReply",
    MEDVIEW_READ_KEY_ADDRESSES: "addressList",
    MEDVIEW_LOAD_TOPIC_HIGHLIGHTS: "highlightBlob",
    MEDVIEW_READ_REMOTE_HFS_FILE: "fileBytes",
}


def _selector_name(selector: int) -> str:
    return _SELECTOR_NAMES.get(selector, f"selector_0x{selector:02x}")


def _format_var_data(data: bytes) -> str:
    head = data[:32]
    hex_part = head.hex()
    suffix = "..." if len(data) > 32 else ""
    if data and all(0x20 <= b < 0x7F or b == 0x00 for b in head):
        text = head.rstrip(b"\x00").decode("ascii", errors="replace")
        return f"{hex_part}{suffix} ({text!r})"
    return hex_part + suffix


def _format_value(p) -> str:
    """Return only the type+value half of a named param, no leading name."""
    tag = getattr(p, "tag", -1)
    if isinstance(p, ByteParam):
        return f"byte=0x{p.value:02x}"
    if isinstance(p, WordParam):
        return f"word=0x{p.value:04x}"
    if isinstance(p, DwordParam):
        return f"dword=0x{p.value:08x}"
    if isinstance(p, VarParam):
        return f"var[{len(p.data)}B]={_format_var_data(p.data)}"
    if isinstance(p, UnknownParam):
        return f"unknown(0x{tag:02x},{len(p.data)}B)={p.data[:16].hex()}"
    return repr(p)


def _format_named(name: str, p) -> str:
    return f"{name}:{_format_value(p)}"


def _format_request_params(selector: int, payload: bytes) -> str:
    send_params, recv_descriptors = parse_request_params(payload)
    names = _REQUEST_PARAM_NAMES.get(selector, [])
    parts = []
    for i, p in enumerate(send_params):
        name = names[i] if i < len(names) else f"param[{i}]"
        parts.append(_format_named(name, p))
    send_str = "{" + ", ".join(parts) + "}"
    recv_str = "[" + ",".join(f"0x{b:02x}" for b in recv_descriptors) + "]"
    return f"send={send_str} recv={recv_str}"


def _walk_reply_tokens(payload: bytes):
    """Walk a MEDVIEW reply payload into a stream of (kind, info) tokens.

    Markers (`0x87` end-static, `0x86` dyn-complete, `0x88` stream-end)
    surface as `("marker", label)`. Tagged primitives surface as
    `("field", Param)`. Anything after `0x86` surfaces as one
    `("body", bytes)` token. Truncation or an unknown tag surfaces as
    `("trailing", bytes)`."""
    pos = 0
    n = len(payload)
    while pos < n:
        b = payload[pos]
        if b == 0x87:
            yield ("marker", "end-static")
            pos += 1
        elif b == 0x86:
            yield ("marker", "dyn-complete")
            yield ("body", payload[pos + 1:])
            return
        elif b == 0x88:
            yield ("marker", "stream-end")
            pos += 1
        elif b == 0x81 and pos + 1 < n:
            yield ("field", ByteParam(tag=b, value=payload[pos + 1]))
            pos += 2
        elif b == 0x82 and pos + 2 < n:
            val = int.from_bytes(payload[pos + 1:pos + 3], "little")
            yield ("field", WordParam(tag=b, value=val))
            pos += 3
        elif b == 0x83 and pos + 4 < n:
            val = int.from_bytes(payload[pos + 1:pos + 5], "little")
            yield ("field", DwordParam(tag=b, value=val))
            pos += 5
        else:
            yield ("trailing", payload[pos:])
            return


def _format_reply_payload(selector: int, payload: bytes) -> str:
    names = _REPLY_FIELD_NAMES.get(selector, [])
    body_name = _REPLY_BODY_NAMES.get(selector, "body")
    field_idx = 0
    parts = []
    for kind, info in _walk_reply_tokens(payload):
        if kind == "field":
            name = names[field_idx] if field_idx < len(names) else f"field[{field_idx}]"
            parts.append(_format_named(name, info))
            field_idx += 1
        elif kind == "marker":
            parts.append(f"[{info}]")
        elif kind == "body":
            parts.append(f"{body_name}={_format_payload_hex(info)}")
        elif kind == "trailing":
            parts.append(f"trailing={_format_payload_hex(info)}")
    return f"len={len(payload)} {{" + ", ".join(parts) + "}"


def _format_payload_hex(data: bytes) -> str:
    head = data[:_LOG_HEX_LIMIT].hex()
    suffix = "..." if len(data) > _LOG_HEX_LIMIT else ""
    return f"len={len(data)} hex={head}{suffix}"


_TYPE3_KIND_NAMES = {0: "topic→va+addr", 1: "hash→va", 2: "va→addr"}


def _format_push_chunk(chunk: bytes) -> str:
    """Decode the post-`0x85` push chunk into named fields."""
    if not chunk:
        return "(empty)"

    if len(chunk) >= 18 and int.from_bytes(chunk[0:2], "little") == 4:
        length = int.from_bytes(chunk[2:4], "little")
        title = chunk[4]
        kind = chunk[5]
        key = int.from_bytes(chunk[6:10], "little")
        va = int.from_bytes(chunk[10:14], "little")
        addr = int.from_bytes(chunk[14:18], "little")
        kind_name = _TYPE3_KIND_NAMES.get(kind, "?")
        return (
            f"type3_op4{{op_code=4, length={length}, title=0x{title:02x}, "
            f"kind={kind}({kind_name}), key=0x{key:08x}, "
            f"va=0x{va:08x}, addr=0x{addr:08x}}}"
        )

    if len(chunk) >= 30 and int.from_bytes(chunk[0:2], "little") == 1:
        (
            subtype,
            length,
            target_size,
            state_kind,
            _metric0,
            _metric1,
            _metric_divisor,
            _aux_status,
            transfer_id,
        ) = struct.unpack_from("<HHIHIIIII", chunk)
        return (
            f"type3_transfer_status{{subtype={subtype}, length={length}, "
            f"transfer_id=0x{transfer_id:08x}, target_size={target_size}, "
            f"state_kind={state_kind}}}"
        )

    if len(chunk) >= 12 and int.from_bytes(chunk[0:2], "little") == 3:
        opcode, length, transfer_id, chunk_offset = struct.unpack_from(
            "<HHII", chunk,
        )
        return (
            f"type4_transfer_chunk{{opcode={opcode}, length={length}, "
            f"transfer_id=0x{transfer_id:08x}, offset={chunk_offset}, "
            f"data_len={max(0, len(chunk) - 12)}}}"
        )

    if chunk[0] == 0xA5 and len(chunk) >= 8:
        title = chunk[1]
        status = int.from_bytes(chunk[2:4], "little")
        token = int.from_bytes(chunk[4:8], "little")
        return (
            f"type0_a5{{title=0x{title:02x}, status=0x{status:04x}, "
            f"contents_token=0x{token:08x}}}"
        )

    if chunk[0] == 0xBF and len(chunk) >= 16:
        title = chunk[1]
        name_size = int.from_bytes(chunk[2:4], "little")
        key = int.from_bytes(chunk[12:16], "little")
        # `MVBuildLayoutLine` switches on name_buf[0x26]: 1 = text row,
        # 3 = bitmap cell (the one that fetches `bm<n>` baggage).
        dispatch = chunk[_BF_DISPATCH_OFFSET] if len(chunk) > _BF_DISPATCH_OFFSET else 0
        return (
            f"case{dispatch}_bf{{title=0x{title:02x}, "
            f"name_size=0x{name_size:04x}, key=0x{key:08x}, "
            f"chunk_len={len(chunk)}}}"
        )

    return _format_payload_hex(chunk)


def _format_push_payload(payload: bytes) -> str:
    """Decode the full `0x85 <chunk>` subscription push payload."""
    if not payload or payload[0] != 0x85:
        return _format_payload_hex(payload)
    return f"len={len(payload)} 0x85 {_format_push_chunk(payload[1:])}"


# Selectors that ack synchronously and push on the matching notification
# iterator. Maps selector → (notification type, push-frame builder).
# Builder signature: `(handler, title_slot, key) -> bytes`.

_TYPE3_KIND_BY_SELECTOR = {
    MEDVIEW_CONVERT_ADDRESS_TO_VA: 2,
    MEDVIEW_CONVERT_HASH_TO_VA: 1,
    MEDVIEW_CONVERT_TOPIC_TO_VA: 0,
}


def _push_type3_op4(selector: int):
    kind = _TYPE3_KIND_BY_SELECTOR[selector]

    def build(handler, title_slot: int, key: int) -> bytes:
        va = addr = 0
        title = handler.loaded_m14
        if (
            title is not None
            and selector == MEDVIEW_CONVERT_HASH_TO_VA
        ):
            if key == 1:
                # MOSVIEW hashes the empty initial context string to 1.
                va = title.contents_va
                addr = title.contents_offset
            else:
                context = title.context_at(key)
                if context is not None:
                    va, addr = context
        return build_type3_op4_frame(title_slot, kind, key, va=va, addr=addr)

    return build


def _push_va_resolve(handler, title_slot: int, key: int) -> bytes:
    """0xBF chunk for 0x15 (HfcNear) cache fill.

    M14 display records already contain the control stream understood by
    Media View. Wrap the requested record without translating it into a
    Blackbird bitmap. Unknown keys retain the empty case-1 cache-fill
    response so HfcNear terminates without painting.
    """
    title = handler.loaded_m14
    if title is not None:
        display = title.display_at(key)
        if display is not None:
            previous, following = title.display_neighbors(key)
            return build_case1_stream_bf_chunk(
                display.control_stream,
                display.text_data,
                title_slot,
                key,
                topic_length=display.topic_length,
                tlv_fields=display.fields_dict(),
                tab_stops=list(display.tab_stops),
                non_scroll=display.non_scroll,
                scroll=display.scroll,
                previous=previous,
                following=following,
            )
    return build_case1_bf_chunk(
        text="", title_byte=title_slot, key=key, initial_font_style=None,
    )


def _push_type0_a5_status(_handler, title_slot: int, key: int) -> bytes:
    """0xA5 HfcStatusRecord for 0x16 (HfcNextPrevHfc).

    `status=0x3F3` is the engine's end-of-content signal: when
    `MVCL14N!MVSeekVerticalLayoutSlots` sees a leading/trailing fetch
    return NULL with this status, it sets `hitLeadingEnd=true` (or the
    trailing equivalent), exits the slot-append loop, and — when both
    edges report 0x3F3 and `currentTailGapY < 0` — clears
    `viewer[+0x84]` so the V-scroll bar disappears. The companion-side
    of this contract is `_stamp_chain_terminators` in `blackbird/wire.py`,
    which writes `1` into BF chunks' prev/next contentsToken
    fields so the engine's HfcNextPrevHfc path misses cache and reaches
    this 0x16 reply."""
    return build_type0_status_record(
        title_byte=title_slot, status=0x3F3, contents_token=key,
    )


def _push_adjacent_topic(handler, title_slot: int, key: int) -> bytes:
    if handler.loaded_m14 is not None:
        display = handler.loaded_m14.display_at(key)
        if display is not None:
            return _push_va_resolve(handler, title_slot, key)
    return _push_type0_a5_status(handler, title_slot, key)


_PUSH_DISPATCH: dict[int, tuple[int, callable]] = {
    MEDVIEW_CONVERT_ADDRESS_TO_VA: (3, _push_type3_op4(MEDVIEW_CONVERT_ADDRESS_TO_VA)),
    MEDVIEW_CONVERT_HASH_TO_VA: (3, _push_type3_op4(MEDVIEW_CONVERT_HASH_TO_VA)),
    MEDVIEW_CONVERT_TOPIC_TO_VA: (3, _push_type3_op4(MEDVIEW_CONVERT_TOPIC_TO_VA)),
    MEDVIEW_FETCH_NEARBY_TOPIC: (0, _push_va_resolve),
    MEDVIEW_FETCH_ADJACENT_TOPIC: (0, _push_adjacent_topic),
}


def _extract_cache_miss_args(payload: bytes) -> tuple[int | None, int | None]:
    """Pull `(title_slot, key)` from a cache-miss request body."""
    send_params, _ = parse_request_params(payload)
    title_slot = None
    key = None
    for p in send_params:
        tag = getattr(p, "tag", None)
        if tag == 0x01 and title_slot is None:
            title_slot = getattr(p, "value", None)
        elif tag == 0x03 and key is None:
            key = getattr(p, "value", None)
    return (title_slot, key)


def _extract_baggage_name(payload: bytes) -> str:
    """Pull the baggage filename from an `OpenRemoteHfsFile` request."""
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if getattr(p, "tag", None) == 0x04:
            data = getattr(p, "data", b"") or b""
            return data.rstrip(b"\x00").decode("ascii", errors="replace")
    return ""


def _extract_title_token(payload: bytes) -> str:
    """Pull the ASCIIZ `titleToken` out of an `OpenTitle` request."""
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if getattr(p, "tag", None) == 0x04:
            data = getattr(p, "data", b"") or b""
            data = data.rstrip(b"\x00")
            try:
                return data.decode("ascii")
            except UnicodeDecodeError:
                return data.hex()
    return ""


def _extract_attach_capabilities(payload: bytes) -> bytes:
    """Pull the capability blob used to distinguish RTM from OSR2."""
    send_params, _ = parse_request_params(payload)
    return next(
        (p.data for p in send_params if isinstance(p, VarParam)),
        b"",
    )


def _extract_open_title_cache_hints(payload: bytes) -> tuple[int, int]:
    send_params, _ = parse_request_params(payload)
    hints = [p.value for p in send_params if isinstance(p, DwordParam)]
    return (
        hints[-2] if len(hints) >= 2 else 0,
        hints[-1] if len(hints) >= 1 else 0,
    )


def _select_osr2_title_body(
    body: bytes,
    metadata: TitleOpenMetadata,
    cache_hints: tuple[int, int],
) -> bytes:
    """Return only the OSR2 cache streams whose validators changed."""
    if len(body) < 2:
        return body
    font_end = 2 + struct.unpack_from("<H", body)[0]
    if font_end > len(body):
        return body
    selected = bytearray()
    if cache_hints[0] != metadata.cache_header0:
        selected += body[:font_end]
    if cache_hints[1] != metadata.cache_header1:
        selected += body[font_end:]
    return bytes(selected)


def _deid_from_title_token(token: str) -> str:
    """Extract `<deid>` from a `:<svcid>[<deid>]<serial>` title token."""
    lb = token.find("[")
    rb = token.rfind("]")
    if lb >= 0 and rb > lb:
        return token[lb + 1:rb]
    return ""


def _extract_get_info_args(payload: bytes) -> tuple[int, int, int]:
    """Pull `(info_kind, info_arg, caller_cookie)` from a
    `GetTitleInfoRemote` request."""
    send_params, _ = parse_request_params(payload)
    dwords = [p.value for p in send_params if getattr(p, "tag", None) == 0x03]
    info_kind = dwords[0] if len(dwords) >= 1 else 0
    info_arg = dwords[1] if len(dwords) >= 2 else 0
    caller_cookie = dwords[2] if len(dwords) >= 3 else 0
    return (info_kind, info_arg, caller_cookie)


def _extract_hfs_read_args(payload: bytes) -> tuple[int | None, int, int]:
    """Pull `(handle, count, offset)` from a `ReadRemoteHfsFile` request."""
    send_params, _ = parse_request_params(payload)
    handle = None
    dwords = []
    for p in send_params:
        tag = getattr(p, "tag", None)
        if tag == 0x01 and handle is None:
            handle = getattr(p, "value", None)
        elif tag == 0x03:
            dwords.append(getattr(p, "value", 0))
    count = dwords[0] if len(dwords) >= 1 else 0
    offset = dwords[1] if len(dwords) >= 2 else 0
    return (handle, count, offset)


def _extract_pre_notify_args(
    payload: bytes,
) -> tuple[int | None, int | None, bytes]:
    """Pull ``(title_slot, notify_op, notify_payload)`` from selector 0x1E."""
    send_params, _ = parse_request_params(payload)
    title_slot = next(
        (p.value for p in send_params if isinstance(p, ByteParam)),
        None,
    )
    notify_op = next(
        (p.value for p in send_params if isinstance(p, WordParam)),
        None,
    )
    notify_payload = next(
        (p.data for p in send_params if isinstance(p, VarParam)),
        b"",
    )
    return title_slot, notify_op, notify_payload


def _parse_picture_start_payload(
    payload: bytes,
) -> tuple[int, list[tuple[int, int, int, str]]] | None:
    """Decode ``PictureStartPayload`` from PreNotifyTitle opcode 0x04."""
    if len(payload) < 2:
        return None
    entry_count = payload[0]
    mode_byte = payload[1]
    pos = 2
    entries = []
    for _ in range(entry_count):
        if pos + 9 > len(payload):
            return None
        current_size, transfer_id = struct.unpack_from("<II", payload, pos)
        state_flags = payload[pos + 8]
        name_start = pos + 9
        name_end = payload.find(b"\x00", name_start)
        if name_end < 0:
            return None
        name = payload[name_start:name_end].decode(
            "cp1252",
            errors="replace",
        )
        entries.append((current_size, transfer_id, state_flags, name))
        pos = name_end + 1
    return mode_byte, entries


def _parse_subscriber_state_payload(payload: bytes) -> tuple[int, bool] | None:
    """Decode ``SetSubscriberEnabledState`` from PreNotifyTitle opcode 0x07."""
    if len(payload) < 5:
        return None
    enabled = struct.unpack_from("<I", payload, 1)[0]
    return payload[0], bool(enabled & 0x01)


def _bmp_pixel_offset(data: bytes) -> int | None:
    """`bfOffBits` of a Windows DIB, or None when this is not one."""
    if len(data) < _BMP_HEADER_BYTES or data[:2] != b"BM":
        return None
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    if not _BMP_HEADER_BYTES <= pixel_offset <= len(data):
        return None
    return pixel_offset


def _widen_low_bpp_dib(data: bytes) -> bytes:
    """Re-index a 1bpp or 4bpp DIB as 8bpp, padding its table to 256 entries.

    Ending the first transfer chunk on `bfOffBits` keeps
    `MVPR14N!MVPicture_PlainBmpDecodeIncremental @ 0x7E866953` from running
    its four-bytes-short palette build (see `_picture_chunk_limit`), but only
    once `bfOffBits` reaches the 400 bytes
    `MVPicture_SelectDecoderByMagic @ 0x7E865815` wants before it will
    instantiate the decoder at all. Below that the decoder does not exist
    until the whole picture has arrived, and its first pass overflows
    whatever the chunking is: `bfOffBits` is 62 at 1bpp and 118 at 4bpp.

    A 256-entry table puts `bfOffBits` at 1078 and the chunk boundary back in
    reach. The re-index is lossless — every source index maps to itself and
    the source colours keep their slots, with the unused tail zeroed — and it
    leaves an ordinary 8bpp DIB, the shape the rest of the corpus already
    ships and the client already renders.

    Anything that is not an uncompressed `BITMAPINFOHEADER` DIB at 1 or 4 bpp
    is returned unchanged.
    """
    if len(data) < _BMP_HEADER_BYTES or data[:2] != b"BM":
        return data
    pixel_offset, header_size = struct.unpack_from("<II", data, 10)
    if header_size < 40 or len(data) < 14 + header_size:
        return data
    width, height, _planes, bit_count, compression = struct.unpack_from(
        "<iiHHI", data, 18
    )
    if bit_count not in (1, 4) or compression != 0 or width <= 0:
        return data
    rows = abs(height)
    source_stride = ((width * bit_count + 31) // 32) * 4
    if pixel_offset + source_stride * rows > len(data):
        return data

    table_start = 14 + header_size
    table = data[table_start:pixel_offset]
    table = table[: _BMP_PALETTE_BYTES].ljust(_BMP_PALETTE_BYTES, b"\x00")

    per_byte = 8 // bit_count
    mask = (1 << bit_count) - 1
    stride = ((width * 8 + 31) // 32) * 4
    pixels = bytearray(stride * rows)
    for row in range(rows):
        source = pixel_offset + row * source_stride
        target = row * stride
        for column in range(width):
            packed = data[source + column // per_byte]
            shift = 8 - bit_count * (column % per_byte + 1)
            pixels[target + column] = (packed >> shift) & mask

    header = bytearray(data[14 : 14 + header_size])
    struct.pack_into("<H", header, 14, 8)
    struct.pack_into("<I", header, 20, stride * rows)
    struct.pack_into("<II", header, 32, 0, 0)
    body = bytes(header) + table + bytes(pixels)
    return (
        b"BM"
        + struct.pack("<IHHI", 14 + len(body), 0, 0, table_start + len(table))
        + body
    )


def _picture_chunk_limit(data: bytes, offset: int) -> int:
    """Size of the transfer chunk that starts at `offset`.

    A DIB's first chunk ends exactly on `bfOffBits`, so header and
    palette arrive without any pixel bytes behind them.

    `MVPR14N!MVPicture_PlainBmpDecodeIncremental @ 0x7E866953` builds the
    DIB's HPALETTE on the first decode pass that makes strictly more than
    `bfOffBits` bytes newly available. It sizes the LOGPALETTE as
    `entryCount * 4` and then writes entry `k` at `buf + 4 + 4k`, never
    budgeting the 4-byte `palVersion`/`palNumEntries` header — at 8bpp a
    1024-byte block takes 1028 bytes. The spill lands on the neighbouring
    heap block header, and KERNEL32's next heap walk at `0xBFF78040`
    reads the corrupted size, runs off the end of the 1 MB heap, and
    faults. Causality proven live 2026-07-30 (SoftICE, FRANCE.M14
    `albi.bmp`); the plate comment on the function carries the trace.

    Landing the boundary on `bfOffBits` fails that guard by construction,
    and every later pass fails the companion `alreadyConsumed < 0x36`
    guard, so the palette is never built. `WltSimple_PaintDIB` still
    paints — it passes the DIB's own colour table to `SetDIBitsToDevice`
    — it just skips `RealizePalette`, which only matters on a 256-colour
    display.

    Not helped: a DIB whose `bfOffBits` sits below the decoder's own
    400-byte creation threshold, which is every 1bpp and 4bpp image. The
    decoder does not exist until more than `bfOffBits` has already
    arrived, so its first pass overflows whatever the chunking is.
    """
    pixel_offset = _bmp_pixel_offset(data)
    if pixel_offset is not None and offset < pixel_offset:
        return pixel_offset - offset
    return _PICTURE_CHUNK_DATA_MAX


def _picture_status_metrics(data: bytes) -> tuple[int, int, int]:
    """Return the nonzero picture-info kind and natural BMP dimensions."""
    if len(data) < 26 or data[:2] != b"BM":
        return 0, 0, 0
    dib_size = struct.unpack_from("<I", data, 14)[0]
    if dib_size == 12:
        width, height = struct.unpack_from("<HH", data, 18)
    elif dib_size >= 40:
        width, height = struct.unpack_from("<ii", data, 18)
        height = abs(height)
    else:
        return 0, 0, 0
    if width <= 0 or height <= 0:
        return 0, 0, 0
    return 1, width, height


class MEDVIEWHandler:
    """Per-pipe MEDVIEW handler."""

    def __init__(self, pipe_idx, svc_name, session=None):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Anonymous when the pipe opens before the login lands.
        self.session = session or Session()
        self._subscriptions: dict[int, tuple[int, int]] = {}
        self._open_title_slots: set[int] = set()
        # Per-baggage-name handle table. The handler returns one stable
        # u8 handle per open HFS name. bm0 remains available before
        # OpenTitle for the empty-title fallback.
        self._baggage_handles: dict[int, str] = {_BAGGAGE_HANDLE_BM0: "bm0"}
        # The 12-byte RTM capability blob remains the safe default for
        # callers that exercise selectors without the attach handshake.
        self._client_dialect = _DIALECT_RTM
        self.loaded_m14: LoadedM14 | None = None
        self.title_body: bytes = TITLE_OPEN_BODY
        self.baggage_map: dict[str, bytes] = {"bm0": BM0_BAGGAGE}
        self.title_metadata: TitleOpenMetadata = TITLE_OPEN_METADATA
        self._pending_picture_transfers: dict[
            int, tuple[str, int, bytes]
        ] = {}
        # Client-reported subscriber enable bit, keyed by notification type
        # (PreNotifyTitle opcode 0x07). Absent means the client has not
        # reported a transition yet, which the engine treats as deliverable:
        # the stock attach sequence enables type 4 right after subscribing.
        self._subscriber_enabled: dict[int, bool] = {}

    # --- BootstrapDiscovery ----------------------------------------

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_discovery_payload(MEDVIEW_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(
            self.pipe_idx, host_block, server_seq, client_ack,
        )

    # --- Top-level dispatch ----------------------------------------

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        log.info(
            "request selector=%s(0x%02x) class=0x%02x req_id=%d payload_len=%d %s",
            _selector_name(selector), selector, msg_class, request_id,
            len(payload), _format_request_params(selector, payload),
        )

        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class, selector, len(payload),
            )
            return None

        if msg_class == MEDVIEW_DATA_EDIT_CLASS:
            if selector == MEDVIEW_DATA_EDIT_ADD:
                reply_payload = self._handle_data_edit_add(request_id, payload)
            elif selector == MEDVIEW_DATA_EDIT_DELETE:
                reply_payload = self._handle_data_edit_delete(request_id, payload)
            elif selector == MEDVIEW_DATA_EDIT_GET_TICKET:
                reply_payload = build_get_ticket_reply_payload(self.session)
            else:
                log_unhandled_selector(
                    log, msg_class, selector, request_id, payload,
                )
                return None
            log.info(
                "reply data_edit selector=0x%02x req_id=%d %s",
                selector,
                request_id,
                _format_reply_payload(selector, reply_payload),
            )
            host_block = build_host_block(
                msg_class, selector, request_id, reply_payload,
            )
            return build_service_packet(
                self.pipe_idx, host_block, server_seq, client_ack,
            )

        if selector in _PUSH_DISPATCH:
            return self._handle_cache_miss(
                msg_class, selector, request_id, payload, server_seq, client_ack,
            )
        if selector == MEDVIEW_PRE_NOTIFY_TITLE:
            return self._handle_pre_notify(
                msg_class, request_id, payload, server_seq, client_ack,
            )

        reply_payload = self._dispatch(msg_class, selector, request_id, payload)
        if reply_payload is None:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        log.info(
            "reply selector=%s(0x%02x) req_id=%d %s",
            _selector_name(selector), selector, request_id,
            _format_reply_payload(selector, reply_payload),
        )
        if selector == MEDVIEW_READ_REMOTE_HFS_FILE:
            return self._build_hfs_read_reply_packets(
                msg_class,
                selector,
                request_id,
                reply_payload,
                server_seq,
                client_ack,
            )
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        reply_packets = build_service_packet(
            self.pipe_idx, host_block, server_seq, client_ack,
        )
        if (
            selector == MEDVIEW_SUBSCRIBE_NOTIFICATIONS
            and len(payload) >= 2
            and payload[1] == 4
        ):
            push_packets = self._flush_pending_picture_chunks(
                (server_seq + len(reply_packets)) & 0x7F,
                client_ack,
            )
            return reply_packets + push_packets
        return reply_packets

    def _handle_data_edit_add(self, request_id, payload) -> bytes:
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 5
            and isinstance(send_params[0], VarParam)
            and isinstance(send_params[1], DwordParam)
            and isinstance(send_params[2], VarParam)
            and isinstance(send_params[3], WordParam)
            and isinstance(send_params[4], VarParam)
            and recv_descriptors == [0x83, 0x83]
        )
        if not valid_shape:
            log.warning(
                "data_edit_add invalid request req_id=%d params=%d recv=%s",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
            )
            return replies.data_edit_result(TREEEDCL_STATUS_REFUSED)

        ticket = send_params[0].data
        record_id = send_params[2].data
        properties = send_params[4].data
        valid_payload = (
            self.session.is_admin
            and len(ticket) >= 2
            and struct.unpack_from("<H", ticket)[0] == len(ticket)
            and len(record_id) == 8
            and len(properties) >= 4
            and struct.unpack_from("<I", properties)[0] == len(properties)
        )
        if not valid_payload:
            log.warning(
                "data_edit_add refused req_id=%d user=%s ticket_len=%d "
                "record_id_len=%d properties_len=%d",
                request_id,
                self.session.user.username or "-",
                len(ticket),
                len(record_id),
                len(properties),
            )
            return replies.data_edit_result(TREEEDCL_STATUS_REFUSED)

        log.info(
            "data_edit_add status=0 req_id=%d table=%d record_id=%s "
            "dataset=0x%04x properties_len=%d",
            request_id,
            send_params[1].value,
            record_id.hex(),
            send_params[3].value,
            len(properties),
        )
        return replies.data_edit_result()

    def _handle_data_edit_delete(self, request_id, payload) -> bytes:
        """Complete DATAEDCL Delete after TREEEDCL removed the directory node."""
        send_params, recv_descriptors = parse_request_params(payload)
        valid_shape = (
            len(send_params) == 4
            and isinstance(send_params[0], VarParam)
            and isinstance(send_params[1], DwordParam)
            and isinstance(send_params[2], VarParam)
            and isinstance(send_params[3], WordParam)
            and recv_descriptors == [0x83, 0x83]
        )
        if not valid_shape:
            log.warning(
                "data_edit_delete invalid request req_id=%d params=%d recv=%s",
                request_id,
                len(send_params),
                [f"0x{tag:02x}" for tag in recv_descriptors],
            )
            return replies.data_edit_result(TREEEDCL_STATUS_REFUSED)

        ticket = send_params[0].data
        record_id = send_params[2].data
        if not (
            self.session.is_admin
            and len(ticket) >= 2
            and struct.unpack_from("<H", ticket)[0] == len(ticket)
            and len(record_id) == 8
        ):
            log.warning(
                "data_edit_delete refused req_id=%d user=%s ticket_len=%d "
                "record_id_len=%d",
                request_id,
                self.session.user.username or "-",
                len(ticket),
                len(record_id),
            )
            return replies.data_edit_result(TREEEDCL_STATUS_REFUSED)

        log.info(
            "data_edit_delete status=0 req_id=%d table=%d record_id=%s "
            "dataset=0x%04x",
            request_id,
            send_params[1].value,
            record_id.hex(),
            send_params[3].value,
        )
        return replies.data_edit_result()

    def _build_hfs_read_reply_packets(
        self,
        msg_class,
        selector,
        request_id,
        reply_payload,
        server_seq,
        client_ack,
    ):
        dynamic = reply_payload[4:]
        if (
            len(reply_payload) <= 4 + _HFS_DYNAMIC_BLOCK_DATA_MAX
            or reply_payload[:4]
            != bytes([0x81, 0x00, 0x87, TAG_DYNAMIC_COMPLETE_SIGNAL])
        ):
            host_block = build_host_block(
                msg_class, selector, request_id, reply_payload,
            )
            return build_service_packet(
                self.pipe_idx, host_block, server_seq, client_ack,
            )

        packets = []
        block_count = (
            len(dynamic) + _HFS_DYNAMIC_BLOCK_DATA_MAX - 1
        ) // _HFS_DYNAMIC_BLOCK_DATA_MAX
        for block_index in range(block_count):
            start = block_index * _HFS_DYNAMIC_BLOCK_DATA_MAX
            end = start + _HFS_DYNAMIC_BLOCK_DATA_MAX
            chunk = dynamic[start:end]
            is_first = block_index == 0
            is_last = block_index == block_count - 1
            block_payload = (
                (reply_payload[:3] if is_first else b"")
                + bytes([
                    TAG_DYNAMIC_COMPLETE_SIGNAL if is_last else TAG_DYNAMIC_PARTIAL
                ])
                + chunk
            )
            host_block = build_host_block(
                msg_class, selector, request_id, block_payload,
            )
            block_packets = build_service_packet(
                self.pipe_idx,
                host_block,
                (server_seq + len(packets)) & 0x7F,
                client_ack,
            )
            packets.extend(block_packets)

        log.info(
            "read_remote_hfs_file_stream req_id=%d bytes=%d host_blocks=%d "
            "transport_fragments=%d",
            request_id,
            len(dynamic),
            block_count,
            len(packets),
        )
        return packets

    def _dispatch(self, msg_class, selector, request_id, payload) -> bytes | None:
        # SessionService
        if selector == MEDVIEW_ATTACH_SESSION:
            return self._handle_attach_session(request_id, payload)
        if selector == MEDVIEW_SUBSCRIBE_NOTIFICATIONS:
            return self._handle_subscribe(msg_class, request_id, payload)
        if selector == MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS:
            return self._handle_unsubscribe(request_id, payload)

        # TitleService
        if selector == MEDVIEW_VALIDATE_TITLE:
            return self._handle_validate_title(request_id, payload)
        if selector == MEDVIEW_OPEN_TITLE:
            return self._handle_open_title(request_id, payload)
        if selector == MEDVIEW_CLOSE_TITLE:
            return self._handle_close_title(request_id, payload)
        if selector == MEDVIEW_GET_TITLE_INFO_REMOTE:
            return self._handle_get_title_info_remote(request_id, payload)
        if selector == MEDVIEW_QUERY_TOPICS:
            log.info("query_topics req_id=%d", request_id)
            return replies.query_topics()

        # WordWheelService
        if selector == MEDVIEW_OPEN_WORD_WHEEL:
            return replies.open_word_wheel()
        if selector == MEDVIEW_QUERY_WORD_WHEEL:
            return replies.query_word_wheel()
        if selector == MEDVIEW_CLOSE_WORD_WHEEL:
            return replies.ack()
        if selector == MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX:
            return replies.resolve_word_wheel_prefix()
        if selector == MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY:
            return replies.ack()
        if selector == MEDVIEW_COUNT_KEY_MATCHES:
            return replies.count_key_matches()
        if selector == MEDVIEW_READ_KEY_ADDRESSES:
            return replies.read_key_addresses()
        if selector == MEDVIEW_SET_KEY_COUNT_HINT:
            return replies.set_key_count_hint()

        # AddressHighlightService (sync — async-cache trio handled above)
        if selector == MEDVIEW_LOAD_TOPIC_HIGHLIGHTS:
            return replies.load_topic_highlights()
        if selector == MEDVIEW_FIND_HIGHLIGHT_ADDRESS:
            return replies.find_highlight_address()
        if selector == MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT:
            return replies.ack()
        if selector == MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS:
            return replies.ack()

        # RemoteFileService
        if selector == MEDVIEW_OPEN_REMOTE_HFS_FILE:
            return self._handle_open_remote_hfs_file(request_id, payload)
        if selector == MEDVIEW_READ_REMOTE_HFS_FILE:
            return self._handle_read_remote_hfs_file(request_id, payload)
        if selector == MEDVIEW_CLOSE_REMOTE_HFS_FILE:
            return self._handle_close_remote_hfs_file(request_id, payload)
        if selector == MEDVIEW_GET_REMOTE_FS_ERROR:
            return replies.get_remote_fs_error()

        return None

    # --- SessionService --------------------------------------------

    def _handle_attach_session(self, request_id, payload) -> bytes:
        capabilities = _extract_attach_capabilities(payload)
        if len(capabilities) == _OSR2_ATTACH_CAPABILITIES_SIZE:
            self._client_dialect = _DIALECT_OSR2
        elif len(capabilities) == _RTM_ATTACH_CAPABILITIES_SIZE:
            self._client_dialect = _DIALECT_RTM
        else:
            self._client_dialect = _DIALECT_RTM
        log.info(
            "attach_session req_id=%d capabilities_len=%d dialect=%s",
            request_id,
            len(capabilities),
            self._client_dialect,
        )
        return replies.attach_session()

    def _handle_subscribe(self, msg_class, request_id, payload) -> bytes:
        notification_type = payload[1] if len(payload) >= 2 else None
        log.info(
            "subscribe_notifications req_id=%d type=%r", request_id, notification_type,
        )
        if notification_type is not None:
            self._subscriptions[notification_type] = (msg_class, request_id)
            # A replacement subscription clears any hold left by a reset-mode
            # start; the client reports the enable bit again on the new object.
            self._subscriber_enabled.pop(notification_type, None)
        return replies.stream_end()

    def _handle_unsubscribe(self, request_id, payload) -> bytes:
        notification_type = payload[1] if len(payload) >= 2 else None
        log.info(
            "unsubscribe_notifications req_id=%d type=%r", request_id, notification_type,
        )
        if notification_type is not None:
            self._subscriptions.pop(notification_type, None)
        return replies.ack()

    def handle_iterator_cancel(self, msg_class, selector, request_id):
        """Clear the subscription matching the cancelled stream iterator.

        Connection layer dispatches this on `<class, sel, req_id, 0x0F>` —
        the MPCCL stream-stop frame sent by `MVAsyncSubscriberUnsubscribe`'s
        vtable[+0xc] hook on subscriber teardown.  `(msg_class, request_id)`
        is the unique key from the original `0x17` subscribe.
        """
        for n_type, (cls, rid) in list(self._subscriptions.items()):
            if cls == msg_class and rid == request_id:
                del self._subscriptions[n_type]
                log.info(
                    "iterator_cancel cleared subscription type=%d class=0x%02x req_id=%d",
                    n_type, msg_class, request_id,
                )
                return
        log.info(
            "iterator_cancel no_subscription class=0x%02x selector=0x%02x req_id=%d",
            msg_class, selector, request_id,
        )

    # --- TitleService ----------------------------------------------

    def _handle_validate_title(self, request_id, payload) -> bytes:
        send_params, _ = parse_request_params(payload)
        slot = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
            None,
        )
        is_valid = slot in self._open_title_slots
        log.info(
            "validate_title req_id=%d slot=%r is_valid=%d",
            request_id, slot, int(is_valid),
        )
        return replies.validate_title(is_valid)

    def _handle_open_title(self, request_id, payload) -> bytes:
        token = _extract_title_token(payload)
        deid = _deid_from_title_token(token).strip()
        slot = TITLE_OPEN_METADATA.title_slot
        self._open_title_slots.add(slot)

        # Resolve the compiled Media View title. The HFS archive is the
        # canonical fixture: TitleOpen metadata and topic-cache records
        # come from it, and its internal files back RemoteFileService.
        title_file = _M14_FIXTURE_FILES.get(deid, f"{deid}.m14")
        title = load_m14(_TITLES_DIR / title_file) if deid else None
        if title is not None:
            self.loaded_m14 = title
            if self._client_dialect == _DIALECT_OSR2:
                self.title_body = lower_m14_to_osr2_payload(title, deid)
            else:
                self.title_body = lower_m14_to_payload(title, deid)
            cache0, cache1 = title.cache_tuple(self.title_body)
            self.baggage_map = {
                name: _widen_low_bpp_dib(blob)
                for name, blob in title.baggage_map().items()
            }
            if self._client_dialect == _DIALECT_OSR2:
                self.baggage_map["mvpfile"] = build_m14_mvpfile(title)
            self.title_metadata = TitleOpenMetadata(
                title_slot=TITLE_OPEN_METADATA.title_slot,
                file_system_mode=0x01,
                contents_va=title.contents_va,
                addr_base=title.contents_offset,
                topic_count=title.topic_count,
                cache_header0=cache0,
                cache_header1=cache1,
            )
            caption = title.title
            source = "m14"
        else:
            self.loaded_m14 = None
            if self._client_dialect == _DIALECT_OSR2:
                self.title_body = OSR2_TITLE_OPEN_BODY
                self.baggage_map = {"mvpfile": OSR2_MVPFILE}
            else:
                self.title_body = TITLE_OPEN_BODY
                self.baggage_map = {"bm0": BM0_BAGGAGE}
            self.title_metadata = TITLE_OPEN_METADATA
            caption = None
            source = "empty"

        reply_body = self.title_body
        if self._client_dialect == _DIALECT_OSR2:
            reply_body = _select_osr2_title_body(
                self.title_body,
                self.title_metadata,
                _extract_open_title_cache_hints(payload),
            )

        log.info(
            "open_title req_id=%d slot=0x%02x token=%r deid=%r source=%s "
            "dialect=%s caption=%r body_len=%d reply_body_len=%d topics=%d "
            "topic_count=%d baggage=%s",
            request_id, slot, token, deid, source, self._client_dialect, caption,
            len(self.title_body), len(reply_body),
            title.topic_count if title is not None else 0,
            self.title_metadata.topic_count,
            ",".join(f"{k}={len(v)}" for k, v in self.baggage_map.items()),
        )
        return replies.open_title(
            reply_body,
            metadata=self.title_metadata,
            osr2=self._client_dialect == _DIALECT_OSR2,
            title_id=(deid.encode("ascii", errors="replace") + b"\x00"),
        )

    def _handle_close_title(self, request_id, payload) -> bytes:
        send_params, _ = parse_request_params(payload)
        slot = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
            None,
        )
        log.info("close_title req_id=%d slot=%r", request_id, slot)
        if slot is not None:
            self._open_title_slots.discard(slot)
            if not self._open_title_slots:
                self.loaded_m14 = None
                if self._client_dialect == _DIALECT_OSR2:
                    self.title_body = OSR2_TITLE_OPEN_BODY
                    self.baggage_map = {"mvpfile": OSR2_MVPFILE}
                else:
                    self.title_body = TITLE_OPEN_BODY
                    self.baggage_map = {"bm0": BM0_BAGGAGE}
                self.title_metadata = TITLE_OPEN_METADATA
                self._baggage_handles = {_BAGGAGE_HANDLE_BM0: "bm0"}
                self._pending_picture_transfers.clear()
        return replies.close_title()

    def _handle_pre_notify(
        self,
        msg_class,
        request_id,
        payload,
        server_seq,
        client_ack,
    ):
        title_slot, notify_op, notify_payload = _extract_pre_notify_args(
            payload,
        )
        log.info(
            "pre_notify_title req_id=%d slot=%r op=%r",
            request_id, title_slot, notify_op,
        )
        reply_payload = replies.pre_notify_title()
        log.info(
            "reply selector=%s(0x%02x) req_id=%d %s",
            _selector_name(MEDVIEW_PRE_NOTIFY_TITLE),
            MEDVIEW_PRE_NOTIFY_TITLE,
            request_id,
            _format_reply_payload(MEDVIEW_PRE_NOTIFY_TITLE, reply_payload),
        )
        host_block = build_host_block(
            msg_class,
            MEDVIEW_PRE_NOTIFY_TITLE,
            request_id,
            reply_payload,
        )
        packets = build_service_packet(
            self.pipe_idx, host_block, server_seq, client_ack,
        )
        if notify_op == 8 and len(notify_payload) > 1:
            # Opcode 0x08's long form is MOSVIEW's own failure report, not the
            # 1-byte heartbeat: the "title ... caused an EXCEPTION" /
            # "would not start" diagnostics it also shows in a dialog. The
            # generic hex preview truncates it, so record the text in full.
            log.info(
                "client_status_report req_id=%d len=%d text=%r",
                request_id,
                len(notify_payload),
                notify_payload.rstrip(b"\x00").decode("cp1252", "replace"),
            )
        if notify_op == 7:
            packets.extend(
                self._apply_subscriber_state(
                    notify_payload,
                    request_id,
                    (server_seq + len(packets)) & 0x7F,
                    client_ack,
                )
            )
            return packets
        if notify_op != 4:
            return packets

        parsed = _parse_picture_start_payload(notify_payload)
        if parsed is None:
            log.info(
                "picture_transfer_start req_id=%d malformed payload_len=%d",
                request_id, len(notify_payload),
            )
            return packets
        mode_byte, entries = parsed
        log.info(
            "picture_transfer_start req_id=%d mode=%d entries=%d",
            request_id, mode_byte, len(entries),
        )
        if mode_byte == _PICTURE_MODE_SUBSCRIBER_RESET:
            # Advance notice that the type-4 subscriber is going down. Hold
            # every chunk until the client reports the replacement stream.
            self._subscriber_enabled[_NOTIFICATION_TYPE_TRANSFER_CHUNK] = False
        next_seq = (server_seq + len(packets)) & 0x7F
        for current_size, transfer_id, state_flags, name in entries:
            canonical = name.lstrip("|!").lower()
            data = self.baggage_map.get(canonical)
            if data is None:
                log.info(
                    "picture_transfer_missing req_id=%d transfer_id=0x%08x "
                    "name=%r canonical=%r",
                    request_id, transfer_id, name, canonical,
                )
                continue
            if current_size > len(data):
                log.info(
                    "picture_transfer_restart req_id=%d transfer_id=0x%08x "
                    "current=%d target=%d",
                    request_id, transfer_id, current_size, len(data),
                )
                current_size = 0

            # A reset-mode start whose object is already valid is the client's
            # transfer-teardown pass: it holds the finished bytes, it re-reports
            # `currentSize` as 0, and it disables the chunk stream immediately
            # after. Feeding the bytes again writes a second copy through
            # `NotificationType4_ApplyChunkedBuffer` into a buffer the client
            # has finished with, which corrupts the heap it decodes from.
            # Status only, no chunks.
            if (
                mode_byte == _PICTURE_MODE_SUBSCRIBER_RESET
                and state_flags & _PICTURE_FLAG_OBJECT_VALID
            ):
                log.info(
                    "picture_transfer_ack_only req_id=%d transfer_id=0x%08x "
                    "name=%r target=%d flags=0x%02x",
                    request_id,
                    transfer_id,
                    canonical,
                    len(data),
                    state_flags,
                )
            else:
                self._pending_picture_transfers[transfer_id] = (
                    canonical,
                    current_size,
                    data,
                )
                log.info(
                    "picture_transfer_queue req_id=%d transfer_id=0x%08x "
                    "name=%r current=%d target=%d flags=0x%02x",
                    request_id,
                    transfer_id,
                    canonical,
                    current_size,
                    len(data),
                    state_flags,
                )
            state_kind, metric0, metric1 = _picture_status_metrics(data)
            status_frame = build_type3_transfer_status_frame(
                transfer_id,
                len(data),
                state_kind=state_kind,
                metric0=metric0,
                metric1=metric1,
            )
            status_packets = self._build_notification_push_packets(
                3,
                status_frame,
                next_seq,
                client_ack,
            )
            packets.extend(status_packets)
            next_seq = (next_seq + len(status_packets)) & 0x7F

        chunk_packets = self._flush_pending_picture_chunks(
            next_seq,
            client_ack,
        )
        packets.extend(chunk_packets)
        return packets

    def _build_notification_push_packets(
        self,
        notification_type,
        frame,
        server_seq,
        client_ack,
    ):
        sub = self._subscriptions.get(notification_type)
        if sub is None:
            log.info(
                "picture_transfer_push_dropped type=%d reason=no_subscriber",
                notification_type,
            )
            return []
        sub_class, sub_req_id = sub
        push_payload = bytes([TAG_DYNAMIC_PARTIAL]) + frame
        push_host = build_host_block(
            sub_class,
            MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
            sub_req_id,
            push_payload,
        )
        log.info(
            "picture_transfer_push type=%d sub_req_id=%d %s",
            notification_type,
            sub_req_id,
            _format_push_payload(push_payload),
        )
        return build_service_packet(
            self.pipe_idx,
            push_host,
            server_seq,
            client_ack,
        )

    def _apply_subscriber_state(
        self,
        notify_payload,
        request_id,
        server_seq,
        client_ack,
    ):
        """Track opcode 0x07 and release held chunks when type 4 comes back."""
        parsed = _parse_subscriber_state_payload(notify_payload)
        if parsed is None:
            log.info(
                "subscriber_state req_id=%d malformed payload_len=%d",
                request_id, len(notify_payload),
            )
            return []
        notification_type, enabled = parsed
        self._subscriber_enabled[notification_type] = enabled
        log.info(
            "subscriber_state req_id=%d type=%d enabled=%d pending_transfers=%d",
            request_id,
            notification_type,
            int(enabled),
            len(self._pending_picture_transfers),
        )
        if (
            notification_type != _NOTIFICATION_TYPE_TRANSFER_CHUNK
            or not enabled
        ):
            return []
        return self._flush_pending_picture_chunks(server_seq, client_ack)

    def _flush_pending_picture_chunks(self, server_seq, client_ack):
        if _NOTIFICATION_TYPE_TRANSFER_CHUNK not in self._subscriptions:
            if self._pending_picture_transfers:
                log.info(
                    "picture_transfer_chunks_queued count=%d reason=no_type4_subscriber",
                    len(self._pending_picture_transfers),
                )
            return []
        if not self._subscriber_enabled.get(
            _NOTIFICATION_TYPE_TRANSFER_CHUNK, True
        ):
            if self._pending_picture_transfers:
                log.info(
                    "picture_transfer_chunks_queued count=%d reason=type4_disabled",
                    len(self._pending_picture_transfers),
                )
            return []

        packets = []
        for transfer_id, (name, current_size, data) in list(
            self._pending_picture_transfers.items()
        ):
            transfer_packet_start = len(packets)
            offset = current_size
            chunk_count = 0
            while offset < len(data):
                chunk_data = data[
                    offset : offset + _picture_chunk_limit(data, offset)
                ]
                frame = build_type4_transfer_chunk_frame(
                    transfer_id,
                    offset,
                    chunk_data,
                )
                chunk_packets = self._build_notification_push_packets(
                    4,
                    frame,
                    (server_seq + len(packets)) & 0x7F,
                    client_ack,
                )
                packets.extend(chunk_packets)
                offset += len(chunk_data)
                chunk_count += 1
            del self._pending_picture_transfers[transfer_id]
            log.info(
                "picture_transfer_complete_push transfer_id=0x%08x "
                "name=%r start=%d target=%d chunks=%d transport_fragments=%d",
                transfer_id,
                name,
                current_size,
                len(data),
                chunk_count,
                len(packets) - transfer_packet_start,
            )
        return packets

    def _handle_get_title_info_remote(self, request_id, payload) -> bytes:
        info_kind, info_arg, caller_cookie = _extract_get_info_args(payload)
        log.info(
            "get_title_info_remote req_id=%d kind=0x%x arg=0x%08x cookie=0x%08x",
            request_id, info_kind, info_arg, caller_cookie,
        )
        return replies.get_title_info_remote(info_kind)

    # --- RemoteFileService -----------------------------------------

    def _handle_open_remote_hfs_file(self, request_id, payload) -> bytes:
        name = _extract_baggage_name(payload)
        canonical = name.lstrip("|!").lower()
        size = replies.baggage_size(canonical, baggage_map=self.baggage_map)
        log.info(
            "open_remote_hfs_file req_id=%d name=%r canonical=%r accept=%r",
            request_id, name, canonical, size is not None,
        )
        # RTM retries `|bm%d` without the pipe. OSR2 directly requests
        # its authored layout as `|MVPFILE`, which is a real HFS name.
        pipe_name_allowed = (
            self._client_dialect == _DIALECT_OSR2
            and name.lower() == "|mvpfile"
        )
        if size is None or (name.startswith("|") and not pipe_name_allowed):
            return replies.open_remote_hfs_file_reject()
        # Allocate (or reuse) a stable handle per name. bm0 keeps the
        # legacy `0x42` for log continuity; subsequent pages allocate
        # sequentially.
        handle = next(
            (h for h, n in self._baggage_handles.items() if n == canonical),
            None,
        )
        if handle is None:
            if canonical == "bm0":
                handle = _BAGGAGE_HANDLE_BM0
            else:
                used = set(self._baggage_handles)
                handle = _BAGGAGE_HANDLE_BASE
                while handle in used:
                    handle += 1
            self._baggage_handles[handle] = canonical
        return replies.open_remote_hfs_file_accept(handle, size)

    def _handle_read_remote_hfs_file(self, request_id, payload) -> bytes:
        handle, count, offset = _extract_hfs_read_args(payload)
        name = self._baggage_handles.get(handle) if handle is not None else None
        if name is None or count <= 0:
            log.info(
                "read_remote_hfs_file req_id=%d handle=%r count=%d offset=%d → error",
                request_id, handle, count, offset,
            )
            return replies.read_remote_hfs_file_error()
        chunk = replies.baggage_chunk(
            name, offset, count, baggage_map=self.baggage_map,
        )
        log.info(
            "read_remote_hfs_file req_id=%d handle=%r name=%r count=%d "
            "offset=%d returned=%d",
            request_id, handle, name, count, offset, len(chunk),
        )
        return replies.read_remote_hfs_file_chunk(chunk)

    def _handle_close_remote_hfs_file(self, request_id, payload) -> bytes:
        send_params, _ = parse_request_params(payload)
        handle = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
            None,
        )
        log.info("close_remote_hfs_file req_id=%d handle=%r", request_id, handle)
        if handle is not None:
            self._baggage_handles.pop(handle, None)
        return replies.ack()

    # --- Cache-miss group (sync ack + async push) ------------------

    def _handle_cache_miss(
        self, msg_class, selector, request_id, payload, server_seq, client_ack,
    ):
        title_slot, key = _extract_cache_miss_args(payload)
        log.info(
            "cache_miss_rpc selector=0x%02x req_id=%d title_slot=%r key=%s",
            selector, request_id, title_slot,
            f"0x{key:08x}" if key is not None else None,
        )
        ack_payload = replies.ack()
        log.info(
            "reply selector=%s(0x%02x) req_id=%d %s",
            _selector_name(selector), selector, request_id,
            _format_reply_payload(selector, ack_payload),
        )
        host_block = build_host_block(msg_class, selector, request_id, ack_payload)
        reply_pkts = build_service_packet(
            self.pipe_idx, host_block, server_seq, client_ack,
        )
        if title_slot is None or key is None:
            return reply_pkts
        next_seq = (server_seq + len(reply_pkts)) & 0x7F
        push_pkts = self._build_cache_push_packet(
            title_slot, selector, key, next_seq, client_ack,
        )
        if push_pkts is not None:
            return reply_pkts + push_pkts
        return reply_pkts

    def _build_cache_push_packet(self, title_slot, selector, key, server_seq, client_ack):
        sub_type, builder = _PUSH_DISPATCH.get(selector, (None, None))
        if builder is None:
            return None
        sub = self._subscriptions.get(sub_type)
        if sub is None:
            log.info(
                "cache_push_dropped selector=%s(0x%02x) title_slot=0x%02x "
                "key=0x%08x sub_type=%d reason=no_subscriber",
                _selector_name(selector), selector, title_slot, key, sub_type,
            )
            return None
        sub_class, sub_req_id = sub
        chunk = builder(self, title_slot, key)
        push_payload = bytes([0x85]) + chunk
        push_host = build_host_block(
            sub_class, MEDVIEW_SUBSCRIBE_NOTIFICATIONS, sub_req_id, push_payload,
        )
        log.info(
            "cache_push selector=%s(0x%02x) title_slot=0x%02x key=0x%08x "
            "sub_type=%d sub_req_id=%d %s",
            _selector_name(selector), selector, title_slot, key,
            sub_type, sub_req_id, _format_push_payload(push_payload),
        )
        return build_service_packet(self.pipe_idx, push_host, server_seq, client_ack)
