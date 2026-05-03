"""MEDVIEW service handler.

Wire contract pinned in `docs/medview-service-contract.md` (lifted from
`~/projetos/blackbird-re/docs/`). The contract groups selectors into
logical service classes; this module mirrors that grouping. Spec-aligned
identifiers (`titleSlot`, `fileSystemMode`, `contentsVa`, …) are used
on call sites so the wire reply layout reads like the spec table.

Service classes:
  - BootstrapDiscovery (class=0x00 / selector=0x00) — `build_discovery_packet`
  - SessionService                (0x17, 0x18, 0x1F)
  - TitleService                  (0x00, 0x01, 0x02, 0x03, 0x04, 0x1E)
  - WordWheelService              (0x08–0x0F)
  - AddressHighlightService       (0x05, 0x06, 0x07, 0x10–0x13)
  - TopicCacheService             (0x15, 0x16)
  - RemoteFileService             (0x1A–0x1D)

Async data paths:
  - Type-0 cache push (selector 0x15 case-1 0xBF chunk) — authored topic body
  - Type-3 op-code 4 frame (selectors 0x05/0x06/0x07) — va/addr conversion
"""

from __future__ import annotations

import logging
import struct

from ..blackbird.m14_payload import (
    M14PayloadResult,
    TitleOpenMetadata,
    TopicEntry,
    _SECTION0_FONT_BLOB,
    _build_sec06_window_scaffold_record,
    build_m14_payload_for_deid,
)
from ..blackbird.m14_synth import (
    build_selector_13_entries,
    build_stock_parser_title_path,
    encode_blob_section,
    encode_c_string,
    encode_c_string_table,
    encode_counted_string_section,
    synthetic_crc,
)
from ..blackbird.wire import (
    build_baggage_container,
    build_case1_bf_chunk,
    build_kind5_raster,
    build_trailer,
    build_type0_status_record,
    build_type3_op4_frame,
    case1_text_budget,
)
from ..config import (
    MEDVIEW_ATTACH_SESSION,
    MEDVIEW_CLOSE_REMOTE_HFS_FILE,
    MEDVIEW_CLOSE_TITLE,
    MEDVIEW_CLOSE_WORD_WHEEL,
    MEDVIEW_CONVERT_ADDRESS_TO_VA,
    MEDVIEW_CONVERT_HASH_TO_VA,
    MEDVIEW_CONVERT_TOPIC_TO_VA,
    MEDVIEW_COUNT_KEY_MATCHES,
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
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_static_reply,
    build_tagged_reply_byte,
    build_tagged_reply_dword,
    build_tagged_reply_var,
    build_tagged_reply_word,
    parse_request_params,
)
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# Title slot returned by `OpenTitle.titleSlot`. MUST be nonzero — a zero
# here short-circuits MVTTL14C `TitleOpenEx` to LAB_7E8432D4 and the
# viewer shows "service temporarily unavailable".
_TITLE_SLOT_PRIMARY = 0x01

# Synthetic non-zero handle returned by `OpenRemoteHfsFile` for the only
# baggage open we currently service (`bm0`). MVTTL14C `HfOpenHfs @
# 0x7E84771E` gates allocation of its tracking struct on `(char) != 0`.
_BAGGAGE_HANDLE_BM0 = 0x42

# Highlight context byte returned synchronously by `QueryTopics` (zero =
# no highlight session). The spec says nonzero opens a highlight-aware
# query session, which we don't implement.
_NO_HIGHLIGHT_CONTEXT = 0x00

# Title source branch used by the live MEDVIEW handler. The older
# Blackbird-backed lowering path remains available in `_resolve_title_result`
# but is no longer the default path for MOSVIEW.
_TITLE_SOURCE_SYNTHETIC = "synthetic"
_TITLE_SOURCE_BLACKBIRD = "blackbird"
_TITLE_SOURCE_BRANCH = _TITLE_SOURCE_SYNTHETIC

_SYNTHETIC_TITLE_CAPTION = "Synthetic MEDVIEW"
_SYNTHETIC_SECTION_NAME = "Synthetic Section"
_SYNTHETIC_FORM_NAME = "Synthetic Form"
_SYNTHETIC_FRAME_NAME = "Synthetic Window"
_SYNTHETIC_STYLE_NAME = "Synthetic Style"
_SYNTHETIC_RESOURCE_FOLDER_NAME = "Synthetic Resources"
_SYNTHETIC_TOPIC_NAME = "Synthetic Story"
_SYNTHETIC_TOPIC_TEXT = (
    "This title is served by the MEDVIEW synthetic branch. "
    "Blackbird title lowering is bypassed on purpose."
)
_SYNTHETIC_TOPIC_ADDRESS = 0x1000


def _encode_fixed_section(records: list[bytes], record_size: int) -> bytes:
    """Encode one fixed-record MEDVIEW section."""
    for record in records:
        if len(record) != record_size:
            raise ValueError(f"record does not match size 0x{record_size:x}")
    payload = b"".join(records)
    if len(payload) > 0xFFFF:
        raise ValueError(f"fixed-record section too large: 0x{len(payload):x}")
    return struct.pack("<H", len(payload)) + payload


def _build_synthetic_title_result(title_token: str, deid: str) -> M14PayloadResult:
    """Build a hardcoded title body for the live synthetic branch.

    This bypasses Blackbird `.ttl` lowering entirely while keeping the
    same `OpenTitle` / cache-miss contract the rest of the handler uses.
    """
    mosview_open_path = deid or title_token or _SYNTHETIC_TITLE_CAPTION
    topic_text = _SYNTHETIC_TOPIC_TEXT.encode("latin-1", errors="replace")
    context_hash = synthetic_crc(
        _SYNTHETIC_TOPIC_NAME.lower().encode("latin-1", errors="replace"),
    ) or 1
    topics = (
        TopicEntry(
            topic_number=1,
            address=_SYNTHETIC_TOPIC_ADDRESS,
            context_hash=context_hash,
            proxy_name=_SYNTHETIC_TOPIC_NAME,
            kind="text",
            text=topic_text,
        ),
    )

    sec01 = encode_c_string(_SYNTHETIC_TITLE_CAPTION)
    sec02 = b""
    sec6a = encode_c_string(mosview_open_path)
    sec13_entries = build_selector_13_entries()
    sec04_strings = [
        _SYNTHETIC_TITLE_CAPTION,
        _SYNTHETIC_SECTION_NAME,
        _SYNTHETIC_FORM_NAME,
        _SYNTHETIC_FRAME_NAME,
        _SYNTHETIC_STYLE_NAME,
        _SYNTHETIC_RESOURCE_FOLDER_NAME,
        _SYNTHETIC_TOPIC_NAME,
    ]
    payload = b"".join(
        [
            encode_blob_section(_SECTION0_FONT_BLOB),
            _encode_fixed_section([], 0x2B),
            _encode_fixed_section([], 0x1F),
            _encode_fixed_section([_build_sec06_window_scaffold_record()], 0x98),
            encode_blob_section(sec01),
            encode_blob_section(sec02),
            encode_blob_section(sec6a),
            encode_counted_string_section(sec13_entries),
            encode_c_string_table(sec04_strings),
        ]
    )
    parser_title_path = build_stock_parser_title_path(mosview_open_path)
    metadata = TitleOpenMetadata(
        va_get_contents=_SYNTHETIC_TOPIC_ADDRESS,
        addr_get_contents=_SYNTHETIC_TOPIC_ADDRESS,
        topic_count=len(topics),
        cache_header0=synthetic_crc(payload),
        cache_header1=synthetic_crc(parser_title_path.encode("latin-1", errors="replace")),
    )
    return M14PayloadResult(
        payload=payload,
        caption=_SYNTHETIC_TITLE_CAPTION,
        metadata=metadata,
        topics=topics,
    )


def _resolve_title_result(title_token: str, deid: str) -> tuple[str, M14PayloadResult]:
    """Choose the live title source branch while preserving the old path."""
    if _TITLE_SOURCE_BRANCH == _TITLE_SOURCE_SYNTHETIC:
        return (_TITLE_SOURCE_SYNTHETIC, _build_synthetic_title_result(title_token, deid))
    return (_TITLE_SOURCE_BLACKBIRD, build_m14_payload_for_deid(deid))


# --------------------------------------------------------------------------
# bm0 baggage backdrop
# --------------------------------------------------------------------------

_BM0_WIDTH = 640
_BM0_HEIGHT = 480
_BM0_BPP = 24
_BM0_PIXEL_BYTES = _BM0_WIDTH * _BM0_HEIGHT * 3  # 921600 B for 640×480 24bpp


def _build_bm0_container():
    """Build the bm0 baggage container — the parent cell's backdrop bitmap.

    `MVCL14N!FUN_7e886310` opens the bm0 baggage HFS file, hands the
    bytes to `FUN_7e886820` (which extracts the trailer) and
    `FUN_7e887a40` (which parses the kind=5 raster). The resulting
    HBITMAP is `BitBlt`'d at paint time by `FUN_7e887180`.

    Architecture note (`docs/mosview-authored-text-and-font-re.md`
    §"Bitmap Child Trailer Boundary"): bm0 is engine-synthesized
    parent-cell backdrop, NOT authored title content. Authored images
    (e.g. the `bitmap.bmp` WaveletImage in the reference .ttl) ship as
    `bm1+` baggage and are referenced by image-tag (`0x03`/`0x22`)
    topic items. The synthetic branch forces a solid yellow 24bpp fill
    here as a visibility probe; the empty-trailer recipe still matches
    the doc's "first authored text milestone does not need this
    trailer" deferment.
    """
    bitmap = build_kind5_raster(
        width=_BM0_WIDTH,
        height=_BM0_HEIGHT,
        bpp=_BM0_BPP,
        pixel_data=b"\x00\xFF\xFF" * (_BM0_WIDTH * _BM0_HEIGHT),
        trailer=build_trailer([], b""),
    )
    return build_baggage_container(bitmap)


_BM0_CONTAINER = _build_bm0_container()


# --------------------------------------------------------------------------
# Reply primitives — match each selector's spec return shape
# --------------------------------------------------------------------------


def _ack() -> bytes:
    """Bare static-end ack reply. Used for selectors whose spec return
    is `ack` with no meaningful payload."""
    return bytes([TAG_END_STATIC])


def _dynamic_complete(static_fields: bytes, dynbytes: bytes = b"") -> bytes:
    """Static-section + 0x86 dynamic-complete + raw bytes.

    `TAG_DYNAMIC_COMPLETE_SIGNAL` (0x86) wakes MVTTL14C's `Wait()` on
    slot 0x24 once. Used for selectors that return a dynbytes payload
    synchronously (`OpenTitle`, `GetTitleInfoRemote`, `LoadTopicHighlights`,
    `ReadKeyAddresses`, `QueryTopics`, `ReadRemoteHfsFile`)."""
    return static_fields + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + dynbytes


def _stream_end(static_fields: bytes = b"") -> bytes:
    """Static-end + 0x88 dynamic-stream-end. Used for `SubscribeNotifications`
    iterator replies. `0x88` keeps `m_pMoreDatRef` non-NULL (passes the
    master-flag check at MVTTL14C 0x7E844FA7) without firing
    `SignalRequestCompletion`. `0x86` here would set request +0x18=1 in
    MPCCL `ProcessTaggedServiceReply`, skipping `ResetEvent` and
    producing a tight `MsgWaitForSingleObject` spin (~30 % CPU per
    request × 3 ⇒ 90 % total)."""
    return static_fields + bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])


def _empty_highlight_blob() -> bytes:
    """`LoadTopicHighlights` return — empty highlight blob.

    Per spec runtime layout: `8-byte opaque header, highlightCount:u32,
    then repeated entries`. Empty result = 8 zero bytes + zero count =
    12 bytes total. Lets the highlight-load path complete without
    crashing the viewer."""
    return b"\x00" * 12


# --------------------------------------------------------------------------
# Cache-miss arg extractors and per-topic resolution
# --------------------------------------------------------------------------


def _extract_cache_miss_args(payload):
    """Unpack `(titleSlot, key)` from a cache-miss request payload.

    Wire shape: `0x01 <title_slot> 0x03 <key:u32>` (+ recv descriptor
    on 0x15). Shared by selectors 0x05 / 0x06 / 0x07 / 0x10 / 0x15.
    """
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


def _extract_baggage_name(payload):
    """Pull the baggage filename from an `OpenRemoteHfsFile` payload.

    Wire shape: `0x01 <hfs_mode> 0x04 <name> 0x01 <open_mode>` plus the
    recv descriptor pair `0x81 0x83`."""
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if getattr(p, "tag", None) == 0x04:
            data = getattr(p, "data", b"") or b""
            return data.rstrip(b"\x00").decode("ascii", errors="replace")
    return ""


def _extract_title_token(payload):
    """Pull the ASCIIZ `titleToken` out of an `OpenTitle` request.

    Wire shape: `0x04 <token> 0x03 <cacheHint0> 0x03 <cacheHint1>`."""
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if getattr(p, "tag", None) == 0x04:
            data = p.data.rstrip(b"\x00")
            try:
                return data.decode("ascii")
            except UnicodeDecodeError:
                return data.hex()
    return ""


def _deid_from_title_token(token: str) -> str:
    """Extract `<name>` from a `:<svcid>[<name>]<serial>` title token."""
    lb = token.find("[")
    rb = token.rfind("]")
    if lb >= 0 and rb > lb:
        return token[lb + 1 : rb]
    return ""


def _extract_get_info_args(payload):
    """Unpack `(infoKind, infoArg, callerCookie)` from a
    `GetTitleInfoRemote` request.

    Wire shape (spec §0x03): `0x01 titleSlot, 0x03 infoKind, 0x03
    infoArg, 0x03 callerCookie`."""
    send_params, _ = parse_request_params(payload)
    dwords = [p.value for p in send_params if getattr(p, "tag", None) == 0x03]
    info_kind = dwords[0] if len(dwords) >= 1 else 0
    info_arg = dwords[1] if len(dwords) >= 2 else 0
    caller_cookie = dwords[2] if len(dwords) >= 3 else 0
    return (info_kind, info_arg, caller_cookie)


# --------------------------------------------------------------------------
# TitleService: GetTitleInfoRemote per-kind classification
# --------------------------------------------------------------------------

# Spec §"Remote `GetTitleInfoRemote` Kinds": each kind has a specific
# return shape. We don't have authored data behind any of these on the
# first-paint path, so each classification ships an empty payload that
# matches the kind's wire shape so the recv loop decodes cleanly.
_REMOTE_INFO_KIND_CLASS: dict[int, str] = {
    0x03: "cstring",   # RemoteCString03
    0x05: "cstring",   # RemoteCString05
    0x0A: "cstring",   # RemoteCString0A
    0x0C: "cstring",   # RemoteCString0C
    0x0D: "cstring",   # RemoteCString0D
    0x0E: "bytes_cap",  # RemoteBytes0E (infoArg low u16 = byte cap)
    0x0F: "cstring",   # RemoteCString0F
    0x10: "cstring",   # RemoteCString10
    0x66: "cstring",   # RemoteCString66
    0x67: "exact",     # RemoteExactBytes67
    0x68: "exact",     # RemoteExactBytes68
    0x6B: "scalar",    # RemoteScalar6B
    0x6D: "scalar",    # RemoteScalar6D
    0x6E: "cached",    # CachedRemoteCString
}

# Local-only kinds the spec says are served from the cached title body
# without hitting the wire — receiving them on selector 0x03 means the
# client failed to find them locally, which would be unexpected.
_LOCAL_INFO_KINDS = frozenset(
    {0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0B, 0x13, 0x69, 0x6A, 0x6E, 0x6F}
)


def _build_get_title_info_remote_reply(info_kind: int) -> bytes:
    """`GetTitleInfoRemote.lengthOrScalar : u32, payload : dynbytes`.

    Spec §`Remote GetTitleInfoRemote Kinds` shape per kind:
      cstring: lengthOrScalar = strlen+1, payload = cstring (we ship `\\0`)
      bytes_cap: lengthOrScalar = byte_count, payload = bytes (we ship 0/empty)
      exact: lengthOrScalar = byte_count, payload = bytes (we ship 0/empty)
      scalar: lengthOrScalar = scalar value, no payload (we ship 0)
      cached: lengthOrScalar = strlen+1, payload = cstring (we ship `\\0`)
    """
    classification = _REMOTE_INFO_KIND_CLASS.get(info_kind)
    if classification == "cstring" or classification == "cached":
        return _dynamic_complete(build_tagged_reply_dword(1), b"\x00")
    if classification == "bytes_cap" or classification == "exact":
        return _dynamic_complete(build_tagged_reply_dword(0), b"")
    if classification == "scalar":
        return _dynamic_complete(build_tagged_reply_dword(0), b"")
    # Unknown kind — treat as scalar=0 (safe default).
    return _dynamic_complete(build_tagged_reply_dword(0), b"")


# --------------------------------------------------------------------------
# Cache-push dispatch
# --------------------------------------------------------------------------

# Maps async-cache selector → (notification subscription type, chunk builder).
# Each builder takes (handler, title_slot, key) and returns
# (chunk_bytes, channel_label_for_log).
_PUSH_DISPATCH: dict[int, tuple[int, "callable"]] = {}


def _push_case1_text(handler, title_slot, key):
    text = handler._case1_text_for_key(key)
    return build_case1_bf_chunk(text, title_slot, key), "type0_bf_case1"


def _push_a5_status(handler, title_slot, key):
    return (
        build_type0_status_record(title_byte=title_slot, status=0, contents_token=key),
        "type0_a5_status",
    )


def _push_type3_op4(kind: int):
    def build(handler, title_slot, key):
        topic = handler._topic_for_wire_key(key)
        va = topic.address if topic else key
        addr = topic.address if topic else key
        log.info(
            "type3_op4_resolve kind=%d key=0x%08x → va=0x%08x addr=0x%08x topic=%s",
            kind, key, va, addr, topic.proxy_name if topic else "<unmatched>",
        )
        return build_type3_op4_frame(title_slot, kind, key, va=va, addr=addr), "type3_op4"
    return build


_PUSH_DISPATCH[MEDVIEW_FETCH_NEARBY_TOPIC] = (0, _push_case1_text)
_PUSH_DISPATCH[MEDVIEW_FETCH_ADJACENT_TOPIC] = (0, _push_a5_status)
_PUSH_DISPATCH[MEDVIEW_CONVERT_TOPIC_TO_VA] = (3, _push_type3_op4(0))
_PUSH_DISPATCH[MEDVIEW_CONVERT_HASH_TO_VA] = (3, _push_type3_op4(1))
_PUSH_DISPATCH[MEDVIEW_CONVERT_ADDRESS_TO_VA] = (3, _push_type3_op4(2))


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------


class MEDVIEWHandler:
    """Handles MEDVIEW service requests on a logical pipe.

    State retained across the session:
      - Notification subscription handles (per spec class StreamFamily)
      - Per-topic mapping from the active title (drives cache pushes)
      - Title caption for fallbacks
    """

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Notification subscription `(class, request_id)` keyed by type
        # 0–4 — captured at `SubscribeNotifications` and reused for
        # async pushes (type-0 0xBF chunks, type-3 op-4 frames).
        self._subscriptions: dict[int, tuple[int, int]] = {}
        # Per-title mapping from `M14PayloadResult.topics` — populated
        # at OpenTitle, used by 0x05/0x06/0x07/0x15 cache pushes to ship
        # real va/addr/text instead of echo-key placeholders.
        self.topics: tuple[TopicEntry, ...] = ()
        self.title_caption: str = ""
        # Title slot is owned by the server — we hand out
        # `_TITLE_SLOT_PRIMARY` on OpenTitle and accept `CloseTitle`
        # against it. Multi-title sessions aren't exercised today.
        self._open_title_slots: set[int] = set()

    # --- BootstrapDiscovery -----------------------------------------

    def build_discovery_packet(self, server_seq, client_ack):
        """Emit the IID→selector discovery block (42 entries).

        Class=0x00, selector=0x00, request_id=0 per spec §`BootstrapDiscovery`.
        """
        payload = build_discovery_payload(MEDVIEW_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    # --- Topic resolution helper -----------------------------------

    def _topic_for_wire_key(self, key: int) -> TopicEntry | None:
        """Resolve a cache-miss key to its `TopicEntry`. Selectors
        0x05/0x06/0x07/0x15 each carry a different key class (addr /
        hash / topic / va) but the engine sometimes uses one when the
        doc says another — match across all three projections."""
        for topic in self.topics:
            if (
                topic.address == key
                or topic.topic_number == key
                or topic.context_hash == key
            ):
                return topic
        return None

    def _case1_text_for_key(self, key: int) -> str:
        """Resolve the ANSI text shipped in a case-1 0xBF chunk for `key`.

        Falls back to the title caption when no topic matches the key
        or the matched entry is image-kind. Truncates to fit the case-1
        chunk's in-name_buf budget."""
        topic = self._topic_for_wire_key(key)
        if topic is not None and topic.text:
            text_bytes = topic.text
        else:
            text_bytes = (self.title_caption or "Untitled").encode("latin-1", errors="replace")
        budget = case1_text_budget() - 1  # -1 for NUL appended by builder
        if len(text_bytes) > budget:
            text_bytes = text_bytes[:budget]
        return text_bytes.decode("latin-1", errors="replace")

    # --- Async cache push (selectors 0x05 / 0x06 / 0x07 / 0x15) ----

    def _build_cache_push_packet(self, title_slot, selector, key, server_seq, client_ack):
        """Build the async cache-push packet for a cache-miss selector.

        Per-selector subscription type and chunk shape live in
        `_PUSH_DISPATCH`. Returns `None` when the matching subscription
        isn't open yet or `selector` has no push handler.
        """
        sub_type, builder = _PUSH_DISPATCH.get(selector, (None, None))
        if builder is None:
            return None
        sub = self._subscriptions.get(sub_type)
        if sub is None:
            return None
        sub_class, sub_req_id = sub
        chunk, channel = builder(self, title_slot, key)
        # 0x85 chunk tag + raw chunk bytes — MPCCL parses 0x85 as a
        # dynamic-recv chunk on the matching subscription iterator.
        push_payload = bytes([0x85]) + chunk
        push_host = build_host_block(
            sub_class,
            MEDVIEW_SUBSCRIBE_NOTIFICATIONS,
            sub_req_id,
            push_payload,
        )
        log.info(
            "cache_push selector=0x%02x title_slot=0x%02x key=0x%08x channel=%s chunk_len=%d",
            selector, title_slot, key, channel, len(chunk),
        )
        return build_service_packet(self.pipe_idx, push_host, server_seq, client_ack)

    # --- Top-level dispatch ----------------------------------------

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch a MEDVIEW request to its spec class handler."""
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class, selector, len(payload),
            )
            return None

        # Cache-miss group: ack synchronously, push async on the
        # matching subscription. Per-selector chunk shape lives in
        # `_PUSH_DISPATCH`.
        if selector in _PUSH_DISPATCH:
            return self._handle_cache_miss(
                msg_class, selector, request_id, payload, server_seq, client_ack,
            )

        reply_payload = self._dispatch(msg_class, selector, request_id, payload)
        if reply_payload is None:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def _dispatch(self, msg_class, selector, request_id, payload) -> bytes | None:
        """Return the reply payload for selectors that produce a single
        synchronous reply packet. Returns `None` for unknown selectors."""
        # SessionService
        if selector == MEDVIEW_ATTACH_SESSION:
            return self._handle_attach_session(request_id, payload)
        if selector == MEDVIEW_SUBSCRIBE_NOTIFICATIONS:
            return self._handle_subscribe_notifications(msg_class, request_id, payload)
        if selector == MEDVIEW_UNSUBSCRIBE_NOTIFICATIONS:
            return self._handle_unsubscribe_notifications(request_id, payload)

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
            return self._handle_query_topics(request_id, payload)
        if selector == MEDVIEW_PRE_NOTIFY_TITLE:
            return self._handle_pre_notify_title(request_id, payload)

        # WordWheelService
        if selector == MEDVIEW_OPEN_WORD_WHEEL:
            return self._handle_open_word_wheel(request_id, payload)
        if selector == MEDVIEW_QUERY_WORD_WHEEL:
            return self._handle_query_word_wheel(request_id, payload)
        if selector == MEDVIEW_CLOSE_WORD_WHEEL:
            return _ack()
        if selector == MEDVIEW_RESOLVE_WORD_WHEEL_PREFIX:
            return self._handle_resolve_word_wheel_prefix(request_id, payload)
        if selector == MEDVIEW_LOOKUP_WORD_WHEEL_ENTRY:
            return _ack()
        if selector == MEDVIEW_COUNT_KEY_MATCHES:
            return self._handle_count_key_matches(request_id, payload)
        if selector == MEDVIEW_READ_KEY_ADDRESSES:
            return self._handle_read_key_addresses(request_id, payload)
        if selector == MEDVIEW_SET_KEY_COUNT_HINT:
            return self._handle_set_key_count_hint(request_id, payload)

        # AddressHighlightService — synchronous selectors (the async
        # converters 0x05/0x06/0x07 are handled by the cache-miss group
        # above; 0x10 has a dynbytes reply, not an async push)
        if selector == MEDVIEW_LOAD_TOPIC_HIGHLIGHTS:
            return self._handle_load_topic_highlights(request_id, payload)
        if selector == MEDVIEW_FIND_HIGHLIGHT_ADDRESS:
            return self._handle_find_highlight_address(request_id, payload)
        if selector == MEDVIEW_RELEASE_HIGHLIGHT_CONTEXT:
            return _ack()
        if selector == MEDVIEW_REFRESH_HIGHLIGHT_ADDRESS:
            return _ack()  # actual result would push via type-2 — we don't push

        # TopicCacheService — both 0x15 and 0x16 are routed through
        # the cache-miss group above (ack + async push); no sync handler.

        # RemoteFileService
        if selector == MEDVIEW_OPEN_REMOTE_HFS_FILE:
            return self._handle_open_remote_hfs_file(request_id, payload)
        if selector == MEDVIEW_READ_REMOTE_HFS_FILE:
            return self._handle_read_remote_hfs_file(request_id, payload)
        if selector == MEDVIEW_CLOSE_REMOTE_HFS_FILE:
            return _ack()
        if selector == MEDVIEW_GET_REMOTE_FS_ERROR:
            return self._handle_get_remote_fs_error(request_id, payload)

        return None

    # --- SessionService --------------------------------------------

    def _handle_attach_session(self, request_id, payload) -> bytes:
        """`AttachSession.validationToken : u32`. Spec: nonzero accepted,
        zero triggers "Handshake validation failed" MessageBox + detach.
        Static-only reply, no dynamic section."""
        log.info("attach_session req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(build_tagged_reply_dword(1))

    def _handle_subscribe_notifications(self, msg_class, request_id, payload) -> bytes:
        """`SubscribeNotifications.notificationStream` — long-lived
        streamed pending handle. We capture (msg_class, request_id) for
        each notification type so subsequent cache pushes ride the same
        iterator. Reply `0x87 0x88` keeps the iterator open without
        firing SignalRequestCompletion."""
        notification_type = payload[1] if len(payload) >= 2 else None
        log.info(
            "subscribe_notifications req_id=%d type=%r payload=%s",
            request_id, notification_type, payload.hex(),
        )
        if notification_type is not None:
            self._subscriptions[notification_type] = (msg_class, request_id)
        return _stream_end()

    def _handle_unsubscribe_notifications(self, request_id, payload) -> bytes:
        """`UnsubscribeNotifications.ack`."""
        notification_type = payload[1] if len(payload) >= 2 else None
        log.info(
            "unsubscribe_notifications req_id=%d type=%r payload=%s",
            request_id, notification_type, payload.hex(),
        )
        if notification_type is not None:
            self._subscriptions.pop(notification_type, None)
        return _ack()

    # --- TitleService ----------------------------------------------

    def _handle_validate_title(self, request_id, payload) -> bytes:
        """`ValidateTitle.isValid : u8`. Zero = invalid; nonzero = valid."""
        send_params, _ = parse_request_params(payload)
        slot = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
            None,
        )
        is_valid = 1 if slot in self._open_title_slots else 0
        log.info(
            "validate_title req_id=%d slot=%r is_valid=%d",
            request_id, slot, is_valid,
        )
        return build_static_reply(build_tagged_reply_byte(is_valid))

    def _handle_open_title(self, request_id, payload) -> bytes:
        """`OpenTitle` static section + `payloadBlob` dynbytes.

        Spec return order:
          titleSlot:u8, fileSystemMode:u8, contentsVa:u32,
          contentsAddr:u32, topicUpperBound:u32, cacheHeader0:u32,
          cacheHeader1:u32, payloadBlob:dynbytes
        """
        title_token = _extract_title_token(payload)
        deid = _deid_from_title_token(title_token).strip()
        log.info("open_title req_id=%d token=%r deid=%r", request_id, title_token, deid)
        source_branch, result = _resolve_title_result(title_token, deid)
        # Stash per-topic mapping + caption on the handler so subsequent
        # selector 0x05 / 0x06 / 0x07 / 0x15 cache pushes can ship
        # authored values (`_case1_text_for_key`, `_topic_for_wire_key`).
        self.topics = result.topics
        self.title_caption = result.caption
        self._open_title_slots.add(_TITLE_SLOT_PRIMARY)
        log.info(
            "open_title_reply source=%s title_slot=0x%02x fs_mode=%d body_len=%d "
            "va=0x%08x addr=0x%08x topic_upper=%d cache_header0=0x%08x",
            source_branch, _TITLE_SLOT_PRIMARY, 0, len(result.payload),
            result.metadata.va_get_contents,
            result.metadata.addr_get_contents,
            result.metadata.topic_count,
            result.metadata.cache_header0,
        )
        return _build_open_title_reply(result.payload, result.metadata)

    def _handle_close_title(self, request_id, payload) -> bytes:
        """`CloseTitle.ack`."""
        send_params, _ = parse_request_params(payload)
        slot = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
            None,
        )
        log.info("close_title req_id=%d slot=%r", request_id, slot)
        if slot is not None:
            self._open_title_slots.discard(slot)
            if not self._open_title_slots:
                # All titles closed — drop per-title state so the next
                # OpenTitle starts clean.
                self.topics = ()
                self.title_caption = ""
        return _ack()

    def _handle_get_title_info_remote(self, request_id, payload) -> bytes:
        """`GetTitleInfoRemote.lengthOrScalar : u32, payload : dynbytes`."""
        info_kind, info_arg, caller_cookie = _extract_get_info_args(payload)
        kind_class = (
            "local_should_not_hit_wire" if info_kind in _LOCAL_INFO_KINDS
            else _REMOTE_INFO_KIND_CLASS.get(info_kind, "remote_unknown")
        )
        log.info(
            "get_title_info_remote req_id=%d kind=0x%x arg=0x%08x cookie=0x%08x class=%s",
            request_id, info_kind, info_arg, caller_cookie, kind_class,
        )
        return _build_get_title_info_remote_reply(info_kind)

    def _handle_query_topics(self, request_id, payload) -> bytes:
        """`QueryTopics` reply.

        Spec return: highlightContext:u8, logicalCount:u32,
        secondaryResult:u32, auxReply:dynbytes, sideband12:bytes[12].

        First-paint client doesn't drive search, so we return the
        empty-result shape: highlight=0, count=0, secondary=0, no aux,
        no sideband. The dynamic section is empty — `0x86` wakes Wait()
        with zero bytes."""
        log.info(
            "query_topics req_id=%d payload_len=%d payload=%s",
            request_id, len(payload), payload.hex(),
        )
        static = (
            build_tagged_reply_byte(_NO_HIGHLIGHT_CONTEXT)
            + build_tagged_reply_dword(0)
            + build_tagged_reply_dword(0)
        )
        return _dynamic_complete(static, b"")

    def _handle_pre_notify_title(self, request_id, payload) -> bytes:
        """`PreNotifyTitle.status : i32`. `0` = queued+acked,
        `0xFFFFFFFF` = setup/send failure. Local-only opcodes
        (0x09/0x0B/0x0C/0x0F) are absorbed by the client wrapper and
        never reach the wire."""
        send_params, _ = parse_request_params(payload)
        opcode = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x02),
            None,
        )
        log.info(
            "pre_notify_title req_id=%d opcode=%r payload_len=%d payload=%s",
            request_id, opcode, len(payload), payload.hex(),
        )
        return build_static_reply(build_tagged_reply_dword(0))

    # --- WordWheelService ------------------------------------------

    def _handle_open_word_wheel(self, request_id, payload) -> bytes:
        """`OpenWordWheel.wordWheelId:u8, itemCount:u32`. Empty wheel
        (no word-wheel index synthesized today)."""
        log.info("open_word_wheel req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(
            build_tagged_reply_byte(0),       # wordWheelId
            build_tagged_reply_dword(0),      # itemCount
        )

    def _handle_query_word_wheel(self, request_id, payload) -> bytes:
        """`QueryWordWheel.status : u16`."""
        log.info("query_word_wheel req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(build_tagged_reply_word(0))

    def _handle_resolve_word_wheel_prefix(self, request_id, payload) -> bytes:
        """`ResolveWordWheelPrefix.prefixResult : u32`."""
        log.info("resolve_word_wheel_prefix req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(build_tagged_reply_dword(0))

    def _handle_count_key_matches(self, request_id, payload) -> bytes:
        """`CountKeyMatches.matchCount : u16`."""
        log.info("count_key_matches req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(build_tagged_reply_word(0))

    def _handle_read_key_addresses(self, request_id, payload) -> bytes:
        """`ReadKeyAddresses.addressList : dynbytes`. Empty result."""
        log.info("read_key_addresses req_id=%d payload=%s", request_id, payload.hex())
        return _dynamic_complete(b"", b"")

    def _handle_set_key_count_hint(self, request_id, payload) -> bytes:
        """`SetKeyCountHint.success : u8`. Zero = no-op."""
        log.info("set_key_count_hint req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(build_tagged_reply_byte(0))

    # --- AddressHighlightService -----------------------------------

    def _handle_load_topic_highlights(self, request_id, payload) -> bytes:
        """`LoadTopicHighlights.highlightBlob : dynbytes`. Empty blob:
        8-byte opaque header + zero highlightCount = 12 bytes."""
        title_slot, key = _extract_cache_miss_args(payload)
        log.info(
            "load_topic_highlights req_id=%d title_slot=%r key=%s",
            request_id, title_slot,
            f"0x{key:08x}" if key is not None else None,
        )
        return _dynamic_complete(b"", _empty_highlight_blob())

    def _handle_find_highlight_address(self, request_id, payload) -> bytes:
        """`FindHighlightAddress.addressToken : u32`. No highlight
        session — return zero."""
        log.info("find_highlight_address req_id=%d payload=%s", request_id, payload.hex())
        return build_static_reply(build_tagged_reply_dword(0))

    # --- RemoteFileService -----------------------------------------

    def _handle_open_remote_hfs_file(self, request_id, payload) -> bytes:
        """`OpenRemoteHfsFile.remoteHandleId : u8, fileSize : u32`.

        We only host bm0 (engine-synthesised parent-cell backdrop, see
        `_build_bm0_container` docstring). Anything else replies handle=0,
        size=0, which the wrapper treats as failure (`HfOpenHfs` returns
        no handle)."""
        name = _extract_baggage_name(payload)
        # `wsprintfA("|bm%d", index)` — strip the leading '|' marker.
        canonical = name.lstrip("|")
        log.info(
            "open_remote_hfs_file req_id=%d name=%r canonical=%r",
            request_id, name, canonical,
        )
        if canonical == "bm0":
            handle = _BAGGAGE_HANDLE_BM0
            size = len(_BM0_CONTAINER)
        else:
            handle = 0
            size = 0
        return (
            bytes([TAG_END_STATIC])
            + build_tagged_reply_byte(handle)
            + build_tagged_reply_dword(size)
        )

    def _handle_read_remote_hfs_file(self, request_id, payload) -> bytes:
        """`ReadRemoteHfsFile.status : u8, fileBytes : dynbytes`.

        Wire shape: `0x81 status=0 0x87 0x86 <bytes>`. Status byte is
        0 on success."""
        send_params, _ = parse_request_params(payload)
        handle_byte = next(
            (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
            None,
        )
        dwords = [p.value for p in send_params if getattr(p, "tag", None) == 0x03]
        count = dwords[0] if len(dwords) >= 1 else 0
        offset = dwords[1] if len(dwords) >= 2 else 0
        log.info(
            "read_remote_hfs_file req_id=%d handle=%r count=%d offset=%d",
            request_id, handle_byte, count, offset,
        )
        if handle_byte == _BAGGAGE_HANDLE_BM0 and count > 0:
            end = min(offset + count, len(_BM0_CONTAINER))
            chunk = _BM0_CONTAINER[offset:end]
            return _dynamic_complete(build_tagged_reply_byte(0), chunk)
        return build_static_reply(build_tagged_reply_byte(0xFF))

    def _handle_get_remote_fs_error(self, request_id, payload) -> bytes:
        """`GetRemoteFsError.fsError : u16`. Spec: wrapper initialises
        to `8` before request and keeps that on setup failure. Returning
        `0` means "no error" — the wrapper overwrites its initial 8."""
        log.info("get_remote_fs_error req_id=%d", request_id)
        return build_static_reply(build_tagged_reply_word(0))

    # --- Shared cache-miss handler (selectors 0x05 / 0x06 / 0x07 / 0x15) ---

    def _handle_cache_miss(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Common handler for the four cache-miss selectors.

        The ack reply lets the engine's retry loop poll the cache again;
        the cache push delivers the actual result async on the matching
        notification iterator (type-0 for 0x15, type-3 for 0x05/0x06/0x07).
        """
        title_slot, key = _extract_cache_miss_args(payload)
        log.info(
            "cache_miss_rpc selector=0x%02x req_id=%d title_slot=%r key=%s",
            selector, request_id, title_slot,
            f"0x{key:08x}" if key is not None else None,
        )
        host_block = build_host_block(msg_class, selector, request_id, _ack())
        reply_pkts = build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)
        if title_slot is None or key is None:
            return reply_pkts
        next_seq = (server_seq + len(reply_pkts)) & 0x7F
        push_pkts = self._build_cache_push_packet(
            title_slot, selector, key, next_seq, client_ack,
        )
        if push_pkts is not None:
            return reply_pkts + push_pkts
        return reply_pkts


# --------------------------------------------------------------------------
# OpenTitle reply builder (top-level so tests can pin the byte layout)
# --------------------------------------------------------------------------


def _build_open_title_reply(title_body: bytes, metadata: TitleOpenMetadata) -> bytes:
    """Build the `OpenTitle` reply per spec §0x01.

    Static section (7 tagged primitives, exact order required by the
    MVTTL14C `TitleOpenEx` recv loop, mapped to the spec's return field
    names):

        0x81 <byte=titleSlot>          → spec.titleSlot       → title +0x02
        0x81 <byte=fileSystemMode>     → spec.fileSystemMode  → title +0x88
        0x83 <dword=contentsVa>        → spec.contentsVa      → title +0x8c
        0x83 <dword=contentsAddr>      → spec.contentsAddr    → title +0x90
        0x83 <dword=topicUpperBound>   → spec.topicUpperBound → title +0x94
        0x83 <dword=cacheHeader0>      → spec.cacheHeader0    → MVCache.tmp half 1
        0x83 <dword=cacheHeader1>      → spec.cacheHeader1    → MVCache.tmp half 2
        0x87                           end-static
        0x86 <payloadBlob>             dynamic-complete
    """
    # `fileSystemMode` is 0 on the synthesized model — older code shipped
    # 1 here mistakenly (we'd called it `_TITLE_ID_SERVICE_BYTE`). Per
    # spec §0x01, fs_mode is the byte later surfaced through local
    # `TitleGetInfo(0x69)`, NOT a duplicate title-id.
    file_system_mode = 0
    static = b"".join(
        [
            build_tagged_reply_byte(_TITLE_SLOT_PRIMARY),
            build_tagged_reply_byte(file_system_mode),
            build_tagged_reply_dword(metadata.va_get_contents),
            build_tagged_reply_dword(metadata.addr_get_contents),
            build_tagged_reply_dword(metadata.topic_count),
            build_tagged_reply_dword(metadata.cache_header0),
            build_tagged_reply_dword(metadata.cache_header1),
        ]
    )
    return static + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + title_body
