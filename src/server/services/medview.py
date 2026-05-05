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

from ..blackbird.m14_payload import (
    TitleOpenMetadata,
    TopicEntry,
    build_m14_payload_for_deid,
)
from ..blackbird.wire import (
    build_baggage_container,
    build_case1_bf_chunk,
    build_case3_bf_chunk,
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
_TITLE_FILE_SYSTEM_MODE = 0x01

# Synthetic non-zero handle returned by `OpenRemoteHfsFile` for the only
# baggage open we currently service (`bm0`). MVTTL14C `HfOpenHfs @
# 0x7E84771E` gates allocation of its tracking struct on `(char) != 0`.
_BAGGAGE_HANDLE_BM0 = 0x42

# Logical pipe messages carry a uint16 reassembly length before the
# transport-level 1024-byte fragmentation. Keep each HFS read reply below
# that pipe-frame ceiling; the client advances by the returned byte count
# and can issue subsequent reads for the remainder.
_HFS_READ_CHUNK_MAX = 0xF000

# Highlight context byte returned synchronously by `QueryTopics` (zero =
# no highlight session). The spec says nonzero opens a highlight-aware
# query session, which we don't implement.
_NO_HIGHLIGHT_CONTEXT = 0x00

# --------------------------------------------------------------------------
# bm0 baggage backdrop
# --------------------------------------------------------------------------

_BM0_WIDTH = 64
_BM0_HEIGHT = 64
_BM0_BPP = 24
_BM0_PIXEL_BYTES = _BM0_WIDTH * _BM0_HEIGHT * 3  # 12288 B for 64×64 24bpp


def _build_bm0_container():
    """Build the bm0 baggage container — the parent cell's backdrop bitmap.

    `MVCL14N!FUN_7e886310` opens the bm0 baggage HFS file, hands the
    bytes to `FUN_7e886820` (which extracts the trailer) and
    `FUN_7e887a40` (which parses the kind=5 raster). The resulting
    HBITMAP is `BitBlt`'d at paint time by `FUN_7e887180`.

    Ships a solid-white 64×64 24bpp raster as the backdrop. Authored
    bitmap content from the title's CBFrame backdrop is RE-deferred —
    until that lowering exists, white keeps the parent cell visually
    neutral so authored text rendering on top of it (when the case-1
    push path is wired) reads correctly.
    """
    bitmap = build_kind5_raster(
        width=_BM0_WIDTH,
        height=_BM0_HEIGHT,
        bpp=_BM0_BPP,
        pixel_data=b"\xFF" * _BM0_PIXEL_BYTES,
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
_PUSH_DISPATCH: dict[int, tuple[int, callable]] = {}


def _push_case1_text(handler, title_slot, key):
    """Push a 0xBF chunk satisfying HfcNear's cache miss on selector 0x15.

    Three content sources, in priority order:
      1. **Topic paragraph** — `_case1_paragraph_for_key` resolves a
         topic-bearing title's first authored paragraph (with its
         section-0 style id).
      2. **Caption control** — pages without topics but with a single
         authored Caption (Test Title fixture) ship the caption text;
         font index defaults to `0` (engine's default style) since the
         font table has no entry for the Caption's authored typeface.
      3. **Empty skip-row** — no topics, no captions: empty text
         triggers `FUN_7e891810`'s "skip empty row" pre-test (return 5)
         which still populates HfcNear's cache so `fMVSetAddress`
         completes. Returning `None` here would leave the HfcNear
         retry loop waiting indefinitely (stuck hourglass).
    """
    if handler.topics:
        text, style_id = handler._case1_paragraph_for_key(key)
        chunk = build_case1_bf_chunk(
            text, title_slot, key, initial_font_style=style_id,
        )
        return chunk, "type0_bf_case1"
    if handler.captions:
        caption = handler.captions[0]
        # Without an `\x80 <style>` control byte the layout walker leaves
        # `slot+0x3F` at the 0xFFFF sentinel and `FUN_7e896760` selects
        # an invisible HFONT — pane paints blank. Style 0 maps to the
        # one descriptor in `_build_minimal_section0` (currently Times
        # New Roman 12pt; lowering Caption's authored font onto section
        # 0 is a separate iteration).
        style_id = 0
        budget = case1_text_budget(initial_font_style=style_id) - 1
        text = caption.text[:budget]
        chunk = build_case1_bf_chunk(
            text, title_slot, key, initial_font_style=style_id,
        )
        return chunk, "type0_bf_case1_caption"
    chunk = build_case1_bf_chunk(
        "", title_slot, key, initial_font_style=None,
    )
    return chunk, "type0_bf_case1_empty"


def _push_case3_bitmap(handler, title_slot, key):
    return build_case3_bf_chunk(title_slot, key), "type0_bf_case3_bitmap"


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
        self.captions: tuple = ()
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

    def _case1_paragraph_for_key(self, key: int) -> tuple[str, int]:
        """Resolve `(text, style_id)` for the case-1 0xBF chunk at `key`.

        Picks the topic's first authored paragraph when available and
        falls back to the title caption (rendered as Normal / `style 0`)
        when no topic matches, the matched entry is image-kind, or the
        topic has no authored paragraphs (e.g. empty TextRuns). Truncates
        text to fit the case-1 chunk's in-name_buf budget."""
        topic = self._topic_for_wire_key(key)
        if topic is not None and topic.paragraphs:
            first = topic.paragraphs[0]
            text = first.text
            style_id = first.style_id
        else:
            text = self.title_caption or "Untitled"
            style_id = 0
        budget = case1_text_budget(initial_font_style=style_id) - 1  # -1 for NUL appended by builder
        if len(text) > budget:
            text = text[:budget]
        return text, style_id

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
        if chunk is None:
            log.info(
                "cache_push_skipped selector=0x%02x title_slot=0x%02x key=0x%08x channel=%s",
                selector, title_slot, key, channel,
            )
            return None
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
        result = build_m14_payload_for_deid(deid)
        # Stash per-topic mapping + caption on the handler so subsequent
        # selector 0x05 / 0x06 / 0x07 / 0x15 cache pushes can ship
        # authored values (`_case1_paragraph_for_key`, `_topic_for_wire_key`).
        self.topics = result.topics
        self.captions = result.captions
        self.title_caption = result.caption
        self._open_title_slots.add(_TITLE_SLOT_PRIMARY)
        log.info(
            "open_title_reply title_slot=0x%02x fs_mode=%d body_len=%d "
            "va=0x%08x addr=0x%08x topic_upper=%d cache_header0=0x%08x",
            _TITLE_SLOT_PRIMARY, _TITLE_FILE_SYSTEM_MODE, len(result.payload),
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
                self.captions = ()
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
        if handle_byte == _BAGGAGE_HANDLE_BM0 and count > 0:
            read_count = min(count, _HFS_READ_CHUNK_MAX)
            end = min(offset + read_count, len(_BM0_CONTAINER))
            chunk = _BM0_CONTAINER[offset:end]
            log.info(
                "read_remote_hfs_file req_id=%d handle=%r count=%d offset=%d returned=%d",
                request_id, handle_byte, count, offset, len(chunk),
            )
            return _dynamic_complete(build_tagged_reply_byte(0), chunk)
        log.info(
            "read_remote_hfs_file req_id=%d handle=%r count=%d offset=%d returned=error",
            request_id, handle_byte, count, offset,
        )
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
    # Nonzero fileSystemMode selects the remote HFS baggage path. The
    # synthetic bitmap probe depends on that path so Mosview fetches `bm0`
    # from the server instead of trying local baggage files.
    file_system_mode = _TITLE_FILE_SYSTEM_MODE
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
