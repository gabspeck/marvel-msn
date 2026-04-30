"""MEDVIEW service handler: MediaView 1.4 title loader for MOSVIEW.EXE.

Bound to svc_name="MEDVIEW", version 0x1400800A. MSN Today (wire node
`4:0`, App #6) is the first surface that opens a pipe here via
`HRMOSExec(c=6)` → `MOSVIEW.EXE -MOS:6:<spec>` → `MVTTL14C!TitleConnection`.

Wire contract: `docs/MEDVIEW.md` (project-internal RE notes) and
`docs/mosview-mediaview-format.md` (code-proven payload grammar lifted
from blackbird-re). The TitleOpen reply's 0x86 dynamic section is the
flat MediaView 1.4 payload consumed by `MVTTL14C!TitleOpenEx @ 0x7E842D4E`
and `TitleGetInfo @ 0x7E842558` — NOT Blackbird's authoring-side OLE2
compound file (`docs/BLACKBIRD.md`).

The payload is synthesized at query-time from the authored `.ttl`
fixture at `resources/titles/<deid>.ttl` via
`src/server/blackbird/m14_synth.py`. The `m14_payload` adapter handles
the wire-mode font_blob strip and the empty-fallback path for missing
or unsynthesizable titles.
"""

import logging
import struct

from ..config import (
    MEDVIEW_INTERFACE_GUIDS,
    MEDVIEW_SELECTOR_HANDSHAKE,
    MEDVIEW_SELECTOR_HFC_NEXT_PREV,
    MEDVIEW_SELECTOR_HFS_CLOSE,
    MEDVIEW_SELECTOR_HFS_OPEN,
    MEDVIEW_SELECTOR_HFS_READ,
    MEDVIEW_SELECTOR_HIGHLIGHTS_IN_TOPIC,
    MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
    MEDVIEW_SELECTOR_TITLE_GET_INFO,
    MEDVIEW_SELECTOR_TITLE_OPEN,
    MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY,
    MEDVIEW_SELECTOR_VA_CONVERT_HASH,
    MEDVIEW_SELECTOR_VA_CONVERT_TOPIC,
    MEDVIEW_SELECTOR_VA_RESOLVE,
    MPC_CLASS_ONEWAY_MASK,
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ..blackbird.m14_payload import (
    M14PayloadResult,
    TitleOpenMetadata,
    build_m14_payload_for_deid,
)
from ..blackbird.wire import (
    _CASE1_NAME_BUF_TEXT_BUDGET,
    build_baggage_container,
    build_case1_bf_chunk,
    build_kind5_raster,
    build_trailer,
)
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    build_tagged_reply_byte,
    build_tagged_reply_dword,
    parse_request_params,
)
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)


def _load_title_body(title_spec: str) -> M14PayloadResult:
    """Resolve a TitleOpen spec to a wire-ready MediaView 1.4 payload.

    Delegates to `blackbird.m14_payload.build_m14_payload_for_deid`,
    which synthesizes the 9-section body from `<deid>.ttl` (or returns
    an empty caption-only fallback on missing / unsynthesizable .ttl).
    The returned `M14PayloadResult` carries the wire bytes plus the
    static-section metadata dwords and per-topic ANSI text buffers
    consumed by the case-1 cache push.
    """
    deid = _title_name_from_spec(title_spec).strip()
    result = build_m14_payload_for_deid(deid)
    log.info(
        "synthesized_title_body spec=%r deid=%r caption=%r body_len=%d "
        "topics=%d topic_texts=%d",
        title_spec, deid, result.caption, len(result.payload),
        result.metadata.topic_count, len(result.topic_texts),
    )
    return result


def _title_name_from_spec(spec: str) -> str:
    """Extract <name> from a `:<svcid>[<name>]<serial>` title spec."""
    lb = spec.find("[")
    rb = spec.rfind("]")
    if lb >= 0 and rb > lb:
        return spec[lb + 1 : rb]
    return ""

# Placeholder title_id byte stored in the title struct at +0x02 and
# echoed back on every subsequent per-title RPC (TitleGetInfo,
# TitlePreNotify).  MUST be nonzero — a zero here short-circuits
# TitleOpenEx to LAB_7E8432D4 and the viewer shows "service
# temporarily unavailable".
_TITLE_ID_PRIMARY = 0x01
_TITLE_ID_SERVICE_BYTE = 0x01

# Synthetic non-zero handle returned for the only baggage open we
# currently accept (`bm0`).  MVTTL14C!HfOpenHfs @ 0x7E84771E gates
# allocation of its 12-byte tracking struct on `(char)local_5 != 0`,
# so any nonzero byte advances the engine; 0x42 is just memorable.
_BAGGAGE_HANDLE_BM0 = 0x42


def _build_handshake_reply_payload():
    """Static-only reply: one dword = 1 (validation_result), end-static.

    MVTTL14C!hrAttachToService reads the dword and gates on `!= 0`.  Zero
    triggers a MessageBox ("Handshake validation failed — Ver ...") and
    detach.  Any nonzero value is accepted; use 1 as the canonical ack.
    """
    return build_tagged_reply_dword(1) + bytes([TAG_END_STATIC])


def _build_title_pre_notify_reply_payload():
    """TitlePreNotify ack: static end-of-static, no content.

    The client dispatches this on opcode 10 after a successful attach to
    flush a cache hint (6 zero bytes sourced from DAT_7E84E2EC).  It
    waits on slot 0x48 for the async reply handle then immediately
    releases it — a bare end-of-static is enough for the Wait() to
    unblock cleanly.
    """
    return bytes([TAG_END_STATIC])


def _build_title_open_reply_payload(title_body: bytes, metadata: TitleOpenMetadata) -> bytes:
    """TitleOpen reply: static section + dynamic-complete blob.

    Static shape (7 tagged primitives, exact order required by
    `MVTTL14C!TitleOpenEx @ 0x7E842D4E` recv loop, per
    `docs/mosview-mediaview-format.md` "Materialized Title Object Fields"):

        0x81 <byte=title_id>            → title +0x02 (primary tid, nonzero)
        0x81 <byte=fs_mode>             → title +0x88 (HFS volume mode byte)
        0x83 <dword=va_get_contents>    → title +0x8c (vaGetContents)
        0x83 <dword=addr_get_contents>  → title +0x90 (addrGetContents)
        0x83 <dword=topic_count>        → title +0x94 (TitleGetInfo 0x0b cap)
        0x83 <dword=cache_header0>      → 8-byte validation tuple, half 1
        0x83 <dword=cache_header1>      → 8-byte validation tuple, half 2
        0x87                            end-static
        0x86 <title_body>               dynamic-complete (raw to end of host block)

    The 0x86 tag (TAG_DYNAMIC_COMPLETE_SIGNAL) wakes MVTTL14C's
    `Wait()` on slot 0x24 (same pattern as DIRSRV GetShabby). Cache
    headers are CRC32 of the wire payload (header0) and the synthesizer's
    parser_title_path (header1) — both compared against `MVCache_*.tmp`
    on the next open.
    """
    static = b"".join(
        [
            build_tagged_reply_byte(_TITLE_ID_PRIMARY),
            build_tagged_reply_byte(_TITLE_ID_SERVICE_BYTE),
            build_tagged_reply_dword(metadata.va_get_contents),
            build_tagged_reply_dword(metadata.addr_get_contents),
            build_tagged_reply_dword(metadata.topic_count),
            build_tagged_reply_dword(metadata.cache_header0),
            build_tagged_reply_dword(metadata.cache_header1),
        ]
    )
    return static + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + title_body


# info_kinds the MVTTL14C client serves locally from the cached body
# (these never reach the wire selector 0x03). Per
# `docs/mosview-mediaview-format.md` "Useful implementation constraints":
#   0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0B, 0x13, 0x69, 0x6A, 0x6E, 0x6F
#
# Selector 0x03 fires for the OTHER info_kinds:
#   0x03, 0x05, 0x0A, 0x0C..0x10, 0x66..0x68, 0x6B..0x6D
# The doc does not pin semantics for these; first-paint clients in
# practice hit only 0x03 (per the RE notes), and even then the empty
# size=0 reply is enough to let lMVTitleGetInfo return without
# crashing MVCL14N. Document this here rather than guess at fields.
_TITLE_GET_INFO_LOCAL_KINDS = frozenset(
    {0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0B, 0x13, 0x69, 0x6A, 0x6E, 0x6F}
)
_TITLE_GET_INFO_REMOTE_KINDS = frozenset(
    {0x03, 0x05, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x66, 0x67, 0x68, 0x6B, 0x6C, 0x6D}
)


def _build_title_get_info_reply_payload(info_kind: int) -> bytes:
    """TitleGetInfo wire reply.

    Wire selector 0x03 carries info_kinds the client cannot serve from
    its local cache — the doc lists `_TITLE_GET_INFO_REMOTE_KINDS` as
    the eligible set. Without RE on each kind's expected payload, we
    answer with size dword = 0 + dynamic-complete + empty body. The
    dynamic-complete signal (0x86) wakes Wait() exactly like TitleOpen.

    Defensive note: a `lMVTitleGetInfo(client, kind, 0, 0)` call with
    a "size probe" pattern (`pBuf == 0`) is satisfied by the size dword
    alone — caller knows there's nothing to copy. For real `pBuf != 0`
    calls the empty 0x86 payload still terminates the recv loop
    cleanly.
    """
    return (
        build_tagged_reply_dword(0)
        + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
    )


def _build_va_resolve_reply_payload():
    """va→content-chunk ack: static end-of-static, no dynamic.

    `MVTTL14C!HfcNear @ 0x7E84589F` retry loop fires this selector when
    the per-title cache misses.  The reply iface is acquired via
    `proxy[+0x48]` and immediately released by HfcNear (it never reads
    a payload).  The real answer is expected via the selector-0x17
    type-3 async push channel.  Bare `0x87` lets the client's
    `iVar2 = (proxy +0x48)(...)` return success so the retry loop
    can poll the cache again, instead of bailing on RPC error
    (`iVar2 < 0`) and giving up after 6 retries (~6 s wall clock).
    """
    return bytes([TAG_END_STATIC])


def _extract_cache_miss_args(payload):
    """Unpack (title_byte, key) from a cache-miss selector request.

    Shared by selectors 0x06 (vaConvertHash), 0x07 (vaConvertTopicNumber),
    0x10 (HighlightsInTopic), and 0x15 (vaResolve / HfcNear).  Wire
    shape: `0x01 <title_byte> 0x03 <key:dword>` plus a recv descriptor
    (`0x85` for vaResolve, omitted for the others).

    Returns (None, None) on malformed input — diagnostic only, the
    reply is the same either way until the type-3 cache push channel
    is wired.
    """
    send_params, _ = parse_request_params(payload)
    title_byte = None
    key = None
    for p in send_params:
        tag = getattr(p, "tag", None)
        if tag == 0x01 and title_byte is None:
            title_byte = getattr(p, "value", None)
        elif tag == 0x03 and key is None:
            key = getattr(p, "value", None)
    return (title_byte, key)


def _extract_baggage_name(payload):
    """Pull the baggage filename from a 0x1A/0x1B/0x1C request payload.

    Wire shape per docs/MEDVIEW.md §6c: `0x01 <hfs_byte> 0x04 <name>
    0x01 <mode> 0x81 0x83`.  Returns the decoded ASCII name with any
    trailing NUL stripped, or empty string if absent.
    """
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if getattr(p, "tag", None) == 0x04:
            data = getattr(p, "data", b"") or b""
            return data.rstrip(b"\x00").decode("ascii", errors="replace")
    return ""


_BM0_WIDTH = 640
_BM0_HEIGHT = 480
_BM0_BPP = 1
# 1bpp packed: 1 byte per 8 pixels, no row padding inferred from the
# parser (`FUN_7e887a40` raw branch memcpy's `pixel_byte_count` bytes
# verbatim from input to output without alignment fixup).
_BM0_PIXEL_BYTES = (_BM0_WIDTH // 8) * _BM0_HEIGHT  # 38400 B for 640×480 1bpp


def _build_bm0_container():
    """Build the bm0 baggage container — the parent cell's backdrop bitmap.

    `MVCL14N!FUN_7e886310` opens the bm0 baggage HFS file, hands the
    bytes to `FUN_7e886820` (which extracts the trailer) and
    `FUN_7e887a40` (which parses the kind=5 raster). The resulting
    HBITMAP is `BitBlt`'d at paint time by `FUN_7e887180`.

    Architecture note (`docs/mosview-authored-text-and-font-re.md`
    §"Bitmap Child Trailer Boundary"):

    - bm0 is an ENGINE-SYNTHESIZED parent-cell backdrop, NOT authored
      title content. `wsprintfA("|bm%d", index)` inside MVCL14N spans
      the whole baggage namespace; bm0 specifically is the default
      backdrop for the topic's rendering surface.
    - Authored images (e.g. the `bitmap.bmp` WaveletImage in the
      reference .ttl) ship as `bm1+` baggage and are referenced by
      image-tag (`0x03`/`0x22`) topic items. Until those items
      appear in the topic body, the engine never asks for `bm1+`.
    - The doc explicitly defers full image-child fidelity for the
      first authored text milestone: "the first authored text
      milestone does not need this trailer at all… or emit only the
      parent image record with `child_count = 0`, `raw_tail_blob_len
      = 0`". Our trailer matches this recipe exactly.

    Layout breakdown:

    - 8-byte container preamble (`FUN_7e886310` reads `+0x04` u32 to
      find bitmap[0] offset).
    - 30-byte kind=5 raster header — wide-form `pixel_byte_count`
      (38400 doesn't fit narrow ushort/2). Layout per `FUN_7e887a40`:
      kind/compression bytes, 2 narrow skip-ints, planes (byte-narrow),
      bpp (byte-narrow), width/height/palette_count/reserved
      (ushort-narrow), pixel_byte_count (u32-wide), trailer_size
      (ushort-narrow), pixel_data_offset (u32), trailer_offset (u32).
    - 38400 bytes of all-`0xFF` pixel data — for a 1bpp DDB this
      renders as the destination DC's background colour (typically
      white) on a colour display.
    - Empty trailer — a 1-byte reserved field + 2 zero count + 4 zero
      tail_size = 7 bytes that `FUN_7e886de0` reads as "no children, no
      tail". The parent cell paints the bitmap; no overlaid text. Per
      doc, this is the documented "first authored text milestone"
      shape and not a regression.
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


def _build_type3_op4_frame(title_byte, kind, key, va, addr):
    """Build a selector-0x17 type-3 op-code 4 cache-insert frame.

    Inserts into the global kind-0/1/2 cache at PTR_DAT_7e84e130
    (FUN_7e8420f6 → FUN_7e841be4 / FUN_7e841bff / FUN_7e841c1a /
    FUN_7e841a50).  This is what `vaConvertHash` /
    `vaConvertTopicNumber` consult — NOT what HfcNear uses.

    Frame (18 bytes):
        +0x00 u16 op_code = 4
        +0x02 u16 length  = 18
        +0x04 u8  title_byte
        +0x05 u8  kind   (0 = topic→va+addr, 1 = hash→va, 2 = va→addr)
        +0x06 u32 key    (topic_no / hash / va)
        +0x0A u32 va
        +0x0E u32 addr
    """
    payload = struct.pack(
        "<BBIII",
        title_byte & 0xFF,
        kind & 0xFF,
        key & 0xFFFFFFFF,
        va & 0xFFFFFFFF,
        addr & 0xFFFFFFFF,
    )
    return struct.pack("<HH", 4, 18) + payload


class MEDVIEWHandler:
    """Handles MEDVIEW service requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name
        # Type-0 cache-pump subscription state (per-title `title+4`
        # tree; opcode 0xBF via FUN_7e8460df).  Captured from
        # selector-0x17 type=0 subscribe; reused for vaResolve /
        # HfcNear cache pushes.
        self.type0_sub_class = None
        self.type0_sub_req_id = None
        # Type-3 cache-pump subscription state (op-code 4 → global
        # kind-0/1/2 cache).  Captured from selector-0x17 type=3
        # subscribe; reused for vaConvertHash / Topic cache pushes.
        self.type3_sub_class = None
        self.type3_sub_req_id = None
        # Per-topic ANSI story buffer extracted from each TextProxy's
        # TextRuns CContent at TitleOpen-time.  Indexed by topic_number
        # (= the synthesizer's vaConvertTopicNumber key, which is also
        # what selector 0x15 / 0x07 cache-miss requests carry).  Empty
        # until TitleOpen runs; falls back to caption on miss.
        self.topic_texts: dict[int, bytes] = {}
        self.title_caption: str = ""

    def build_discovery_packet(self, server_seq, client_ack):
        """Emit the IID→selector discovery block (42 entries, 1-based selectors)."""
        payload = build_discovery_payload(MEDVIEW_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def _case1_text_for_key(self, key: int) -> str:
        """Resolve the ANSI text shipped in a case-1 0xBF chunk for `key`.

        Selector 0x15 cache-miss requests use `vaConvertTopicNumber`-style
        keys, which the synthesizer assigns as `topic_number = entry_index + 1`
        (`m14_synth.build_visible_entry_metadata`). Look up the matching
        TextRuns body in `self.topic_texts`; truncate to fit the case-1
        chunk's in-name_buf text budget. Falls back to the title caption
        (or `Untitled`) when the key doesn't map to a TextProxy entry.
        """
        text_bytes = self.topic_texts.get(key)
        if text_bytes is None:
            text_bytes = (self.title_caption or "Untitled").encode("latin-1", errors="replace")
        # +1 for the trailing NUL `build_case1_bf_chunk` appends.
        budget = _CASE1_NAME_BUF_TEXT_BUDGET - 1
        if len(text_bytes) > budget:
            text_bytes = text_bytes[:budget]
        # build_case1_bf_chunk takes a str — decode latin-1 (round-trip
        # safe for any byte sequence).
        return text_bytes.decode("latin-1", errors="replace")

    def _build_cache_push_packet(self, title_byte, selector, key, server_seq, client_ack):
        """Build a packet that pushes a cache-fill chunk on the right channel.

        Selector → push channel + frame:
            0x15 (HfcNear / vaResolve) → type-0, opcode 0xBF case-1.
                Inserts into the per-title `title+4` tree via
                FUN_7e8452d3 → FUN_7e8460df, then drives
                FUN_7e890fd0 → FUN_7e894c50 case 1 → slot tag 1 →
                ExtTextOutA. Section-0 (`m14_payload._SECTION0_FONT_BLOB`)
                resolves the slot+0x3F font id to a real HFONT via
                descriptor 0 (Times New Roman).
            0x06 (vaConvertHash) → type-3, op-code 4 kind 1 (hash→va,
                global cache via FUN_7e841bff).
            0x07 (vaConvertTopicNumber) → type-3, op-code 4 kind 0
                (topic→va+addr, global cache via FUN_7e841be4).
            0x10 (HighlightsInTopic) → not pushed.

        TODO: derive the case-1 text from the title's authored
        TextTree/TextRuns rather than the hardcoded caption — placeholder
        until VIEWDLL.DLL CContent serializers are RE'd.
        """
        if selector == MEDVIEW_SELECTOR_VA_RESOLVE:
            if self.type0_sub_req_id is None:
                return None
            text = self._case1_text_for_key(key)
            chunk = build_case1_bf_chunk(text, title_byte, key)
            channel = "type0_bf_case1"
            sub_class = self.type0_sub_class
            sub_req_id = self.type0_sub_req_id
        elif selector in (MEDVIEW_SELECTOR_VA_CONVERT_HASH, MEDVIEW_SELECTOR_VA_CONVERT_TOPIC):
            if self.type3_sub_req_id is None:
                return None
            kind = 1 if selector == MEDVIEW_SELECTOR_VA_CONVERT_HASH else 0
            # Stub answer: va = addr = key.  Real values come from
            # the title's authored content; without that we just
            # echo the key so vaConvertHash returns *something* and
            # the engine can drive forward to HfcNear.
            chunk = _build_type3_op4_frame(title_byte, kind, key, va=key, addr=key)
            sub_class = self.type3_sub_class
            sub_req_id = self.type3_sub_req_id
            channel = "type3_op4"
        else:
            return None
        # 0x85 chunk tag + raw chunk bytes.  MPCCL parses 0x85 as a
        # dynamic-recv chunk on the matching subscription iterator
        # (key = req_id), fires chunk signal at +0x28's event, and
        # the type-N callback consumes the chunk.
        push_payload = bytes([0x85]) + chunk
        push_host = build_host_block(
            sub_class,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
            sub_req_id,
            push_payload,
        )
        log.info(
            "cache_push selector=0x%02x title_byte=0x%02x key=0x%08x channel=%s chunk_len=%d",
            selector, title_byte, key, channel, len(chunk),
        )
        return build_service_packet(self.pipe_idx, push_host, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch a MEDVIEW request.  Returns packet list or None."""
        if (msg_class & MPC_CLASS_ONEWAY_MASK) == MPC_CLASS_ONEWAY_MASK:
            log.info(
                "oneway_continuation class=0x%02x selector=0x%02x payload_len=%d",
                msg_class, selector, len(payload),
            )
            return None

        if selector == MEDVIEW_SELECTOR_HANDSHAKE:
            log.info("handshake req_id=%d payload=%s", request_id, payload.hex())
            reply_payload = _build_handshake_reply_payload()
            log.info("handshake_reply validation=1")
        elif selector == MEDVIEW_SELECTOR_TITLE_PRE_NOTIFY:
            log.info(
                "title_pre_notify req_id=%d payload_len=%d payload=%s",
                request_id, len(payload), payload.hex(),
            )
            reply_payload = _build_title_pre_notify_reply_payload()
        elif selector == MEDVIEW_SELECTOR_TITLE_OPEN:
            title_spec = _extract_title_spec(payload)
            log.info("title_open req_id=%d spec=%r", request_id, title_spec)
            result = _load_title_body(title_spec)
            # Stash per-topic text + caption on the handler so subsequent
            # selector 0x15 cache pushes can ship authored TextRuns content
            # instead of the title caption (`_case1_text_for_key`).
            self.topic_texts = dict(result.topic_texts)
            self.title_caption = result.caption
            reply_payload = _build_title_open_reply_payload(result.payload, result.metadata)
            log.info(
                "title_open_reply title_id=0x%02x body_len=%d "
                "va=0x%08x addr=0x%08x topics=%d cache_header0=0x%08x",
                _TITLE_ID_PRIMARY, len(result.payload),
                result.metadata.va_get_contents,
                result.metadata.addr_get_contents,
                result.metadata.topic_count,
                result.metadata.cache_header0,
            )
        elif selector == MEDVIEW_SELECTOR_TITLE_GET_INFO:
            info_kind, index, bufsize = _extract_get_info_args(payload)
            kind_class = (
                "local_should_not_hit_wire" if info_kind in _TITLE_GET_INFO_LOCAL_KINDS
                else "remote_documented" if info_kind in _TITLE_GET_INFO_REMOTE_KINDS
                else "remote_unknown"
            )
            log.info(
                "title_get_info req_id=%d info_kind=0x%x index=%d bufsize=%d class=%s",
                request_id, info_kind, index, bufsize, kind_class,
            )
            reply_payload = _build_title_get_info_reply_payload(info_kind)
        elif selector in (
            MEDVIEW_SELECTOR_VA_CONVERT_HASH,
            MEDVIEW_SELECTOR_VA_CONVERT_TOPIC,
            MEDVIEW_SELECTOR_HIGHLIGHTS_IN_TOPIC,
            MEDVIEW_SELECTOR_VA_RESOLVE,
        ):
            title_byte, key = _extract_cache_miss_args(payload)
            log.info(
                "cache_miss_rpc selector=0x%02x req_id=%d title_byte=%r key=%s payload=%s",
                selector,
                request_id,
                title_byte,
                f"0x{key:08x}" if key is not None else None,
                payload.hex(),
            )
            reply_payload = _build_va_resolve_reply_payload()
            host_block = build_host_block(msg_class, selector, request_id, reply_payload)
            reply_pkts = build_service_packet(
                self.pipe_idx, host_block, server_seq, client_ack
            )
            # On selector 0x15 (HfcNear) with type-0 subscription
            # registered, push a `0xBF` chunk on the type-0 iterator.
            # The chunk gets consumed by HfcNear's own retry loop via
            # FUN_7e845875 → FUN_7e8451bf(idx=0, …) → FUN_7e8450d5 →
            # FUN_7e844a3b → FUN_7e8452d3 → FUN_7e8460df, which
            # inserts (key → 60-byte content) into the title+4 tree.
            # On the next iteration FUN_7e845efa finds the entry and
            # HfcNear returns success → fMVSetAddress returns 1.
            if title_byte is not None and key is not None:
                next_seq = (server_seq + len(reply_pkts)) & 0x7F
                push_pkts = self._build_cache_push_packet(
                    title_byte, selector, key, next_seq, client_ack
                )
                if push_pkts is not None:
                    return reply_pkts + push_pkts
            return reply_pkts
        elif selector == MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION:
            notification_type = payload[1] if len(payload) >= 2 else None
            log.info(
                "subscribe_notification req_id=%d type=%r payload=%s",
                request_id, notification_type, payload.hex(),
            )
            if notification_type == 0:
                # Type 0 is the topic-metadata subscriber
                # (FUN_7e8452d3).  Capture the iface coordinates so
                # later vaResolve cache pushes (selector 0x15) can
                # ride the same iterator and trigger
                # FUN_7e8460df → title+4 tree insert.  Reply
                # `0x87 0x88` (iterator stream-end) so the subscribe
                # iface advances cleanly.
                self.type0_sub_class = msg_class
                self.type0_sub_req_id = request_id
                reply_payload = bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
            elif notification_type == 3:
                # Type 3 is the va/addr cache-pump subscriber
                # (FUN_7e8451ec, op-code 4 frames into the global
                # kind-0/1/2 cache at PTR_DAT_7e84e130).  Iterator
                # reply for the pump thread (FUN_7e844c7c).
                self.type3_sub_class = msg_class
                self.type3_sub_req_id = request_id
                reply_payload = bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
            else:
                # Types 1/2/4: same iterator-stream-end reply as 0/3.
                # 0x88 alone makes m_pMoreDatRef non-NULL (passes the
                # master-flag check at MVTTL14C 0x7E844FA7) without
                # firing SignalRequestCompletion.  0x86 sets request
                # +0x18=1 in MPCCL!ProcessTaggedServiceReply, which in
                # turn skips ResetEvent in WaitForMessage/PollDynMsg
                # and produces a tight MsgWaitForSingleObject spin
                # (~30% CPU per request × 3 ⇒ 90% total).
                reply_payload = bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
        elif selector == MEDVIEW_SELECTOR_HFC_NEXT_PREV:
            # 0x16 HfcNextPrevHfc — same wire shape as vaResolve (0x15)
            # plus a direction byte.  Reply ack-only; engine retries
            # ~6× internally then falls back to its in-cache entries.
            log.info(
                "hfc_next_prev req_id=%d payload_len=%d payload=%s",
                request_id, len(payload), payload.hex(),
            )
            reply_payload = bytes([TAG_END_STATIC])
        elif selector == MEDVIEW_SELECTOR_HFS_OPEN:
            # 0x1A HfOpenHfs — baggage open.  Per docs/MEDVIEW.md §6c.
            # `bm<N>` filenames come from MVCL14N!FUN_7e886980 @
            # 0x7E886980 via wsprintfA("|bm%d", index) with index from
            # the layout descriptor; on 0x3EC the same call retries
            # without the leading `|`.  Accept the canonical `bm<N>`
            # form with a synthetic handle to expose the next gate
            # (whether 0x1B HFS_READ fires, or the engine short-
            # circuits via the size DWORD).  Decline anything else
            # with byte=0 — engine treats that as 0x3EC.
            name = _extract_baggage_name(payload)
            canonical = name.lstrip("|")
            log.info(
                "hfs_open req_id=%d name=%r canonical=%r payload=%s",
                request_id, name, canonical, payload.hex(),
            )
            if canonical == "bm0":
                reply_payload = (
                    bytes([TAG_END_STATIC])
                    + build_tagged_reply_byte(_BAGGAGE_HANDLE_BM0)
                    + build_tagged_reply_dword(len(_BM0_CONTAINER))
                )
            else:
                reply_payload = (
                    bytes([TAG_END_STATIC])
                    + build_tagged_reply_byte(0)
                    + build_tagged_reply_dword(0)
                )
        elif selector == MEDVIEW_SELECTOR_HFS_READ:
            # 0x1B LcbReadHf.  See docs/MEDVIEW.md §6c.
            # Wire request: 0x81 (status byte) + 0x85 (dynamic-recv,
            # single-shot blob — NOT 0x88 iterator).  Reply pattern
            # is the GetShabby shape with byte-status: 0x81 <status=0>
            # 0x87 0x86 <bytes>.  LcbReadHf @ 0x7E847C45 waits, then
            # reply_iface->m0x1c(&iter) → iter->m0x10()=length →
            # iter->m0xC()=ptr (MPCCL chunk-walker over the 0x86
            # blob).  Probe with 1 zero byte: FUN_7e887a40 @
            # 0x7E887A40 sees kind=0 < 5 → returns -2 → caller
            # zeroes slot → bitmap NULL but no AV.
            send_params, _ = parse_request_params(payload)
            handle_byte = next(
                (p.value for p in send_params if getattr(p, "tag", None) == 0x01),
                None,
            )
            dwords = [p.value for p in send_params if getattr(p, "tag", None) == 0x03]
            count = dwords[0] if len(dwords) >= 1 else 0
            offset = dwords[1] if len(dwords) >= 2 else 0
            log.info(
                "hfs_read req_id=%d handle=%r count=%d offset=%d payload=%s",
                request_id, handle_byte, count, offset, payload.hex(),
            )
            if handle_byte == _BAGGAGE_HANDLE_BM0 and count > 0:
                end = min(offset + count, len(_BM0_CONTAINER))
                chunk = _BM0_CONTAINER[offset:end]
                reply_payload = (
                    build_tagged_reply_byte(0)
                    + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL])
                    + chunk
                )
            else:
                reply_payload = (
                    build_tagged_reply_byte(0xFF)
                    + bytes([TAG_END_STATIC])
                )
        elif selector == MEDVIEW_SELECTOR_HFS_CLOSE:
            # 0x1C HfCloseHf — same comment as 0x1B.
            log.info(
                "hfs_close req_id=%d payload_len=%d payload=%s",
                request_id, len(payload), payload.hex(),
            )
            reply_payload = bytes([TAG_END_STATIC])
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None

        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def _extract_title_spec(payload):
    """Pull the ASCIIZ title spec out of a TitleOpen request (first 0x04 var)."""
    send_params, _ = parse_request_params(payload)
    for p in send_params:
        if getattr(p, "tag", None) == 0x04:
            data = p.data.rstrip(b"\x00")
            try:
                return data.decode("ascii")
            except UnicodeDecodeError:
                return data.hex()
    return ""


def _extract_get_info_args(payload):
    """Unpack (info_kind, index, buffer_size) from a TitleGetInfo request.

    Wire layout (send side): 0x01 <title_byte> 0x03 <info_kind> 0x03
    <dwBufCtl> 0x03 <buffer_ptr>.  The client packs `(buffer_size << 16)
    | index` into dwBufCtl at call time.  Return zeros on malformed
    input — the MVP reply is identical either way.
    """
    send_params, _ = parse_request_params(payload)
    dwords = [p.value for p in send_params if getattr(p, "tag", None) == 0x03]
    if len(dwords) < 2:
        return (0, 0, 0)
    info_kind = dwords[0]
    dw_buf_ctl = dwords[1]
    index = (dw_buf_ctl >> 16) & 0xFFFF
    bufsize = dw_buf_ctl & 0xFFFF
    return (info_kind, index, bufsize)
