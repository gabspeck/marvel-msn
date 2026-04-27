"""MEDVIEW service handler: MedView title loader for MOSVIEW.EXE.

Bound to svc_name="MEDVIEW", version 0x1400800A.  MSN Today (wire node
`4:0`, App #6) is the first surface that opens a pipe here via
`HRMOSExec(c=6)` → `MOSVIEW.EXE -MOS:6:<spec>` → `MVTTL14C!TitleConnection`.

Wire contract is documented end-to-end in `docs/MEDVIEW.md`.  The title
body shipped in TitleOpen's 0x86 dynamic section is a flat 9-section
stream consumed by `MVTTL14C!TitleOpenEx @ 0x7E842D4E` + TitleGetInfo —
NOT Blackbird's "Release" OLE2 compound file (that's the authoring-side
format; see `docs/BLACKBIRD.md` §4.4).  The 1996 MSN server synthesised
the 9-section stream at query-time from the Blackbird publish upload.

This handler replicates that synthesis from the authored `.ttl`
compound file: `resources/titles/<deid>.ttl` → `Title` object → body
with `CTitle.name` placed in section 4 (info_kind=1), the only field
MSN Today actually reads at startup (see docs/MEDVIEW.md §4.4).  The
remaining sections stay empty pending RE of COSCL's `extract_object`
compression scheme (tracked in docs/BLACKBIRD.md §7).
"""

import logging
import os
import struct
from pathlib import Path

from ..config import (
    MEDVIEW_INTERFACE_GUIDS,
    MEDVIEW_SELECTOR_HANDSHAKE,
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
from .ttl import Title, TTLError

log = logging.getLogger(__name__)


# Root directory for per-title fixtures.  Override with MSN_TITLES_ROOT;
# default is the repo's `resources/titles/` checked in alongside the
# server source (4 levels up from services/medview.py:
# services → server → src → repo).
def _titles_root() -> Path:
    env = os.environ.get("MSN_TITLES_ROOT")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "resources" / "titles"


def _resolve_display_name(deid: str) -> str:
    """Map a DIRSRV deid to the title caption shown in MSN Today.

    Parses `<_titles_root()>/<deid>.ttl` when present and returns the
    authored `CTitle.name`; otherwise falls back to `"Title <deid>"`
    so unknown deids still show something informative instead of the
    client's `"Unknown Title Name"` default.
    """
    if not deid:
        return "Untitled"
    path = _titles_root() / f"{deid}.ttl"
    if not path.is_file():
        log.info("ttl_missing deid=%r path=%s — using deid fallback", deid, path)
        return f"Title {deid}"
    try:
        title = Title.from_path(str(path))
    except TTLError as exc:
        log.warning("ttl_parse_failed deid=%r path=%s: %s", deid, path, exc)
        return f"Title {deid}"
    name = title.display_name
    if not name:
        log.warning("ttl_no_display_name deid=%r path=%s types=%r", deid, path, title.types)
        return f"Title {deid}"
    log.info("ttl_loaded deid=%r path=%s display_name=%r", deid, path, name)
    return name


def _build_title_body(display_name: str) -> bytes:
    """Synthesize a minimum-viable MedView 9-section body.

    Layout (little-endian; see docs/MEDVIEW.md §4.4):

        sections 0-3:  4 × [u16 size=0]          # DIB + 3 record arrays, all empty
        section 4:     [u16 size=N][N ASCII bytes]  # title name (raw blob)
        sections 5-7:  3 × [u16 size=0]          # copyright + 2 raw blobs, empty
        section 8:     [u16 count=0]             # string table, empty

    Section 0 empty (`u16==0`) steers `MVTTL14C!TitleOpenEx @ 0x7E842D4E`
    into the safe `LAB_7e8432c4` branch that skips the DIB alloc /
    `memcpy.REP` DIB copy.  Sections 1-3 empty make the fixed-record
    queries in `TitleGetInfo @ 0x7E842558` return -1.

    Section 4 carries the title name.  `MOSVIEW!OpenMediaTitleSession @
    0x7F3C6575` queries `TitleGetInfo(info_kind=1, dwBufCtl=0xBB8, buf)`
    right before the "Unknown Title Name" fallback — info_kind=1 is the
    raw-blob section 4, copied verbatim into the caller's buffer (no
    implicit NUL), then run through `UnquoteCommandArgument` (strips
    backticks / double-quotes) and stored at `title+0x58` as the
    viewer's caption.  Including a trailing NUL in the blob keeps
    downstream string walks safe.

    Section 6 (`info=0x6A` "title string") MUST be non-empty.  Live
    SoftIce trace 2026-04-27 at `MVCL14N!fMVSetTitle @ 0x7E882910`
    confirmed the path: `dwBytes = lMVTitleGetInfo(title, 0x6A, 0, 0)`
    queries section-6 size, then `GlobalAlloc(GMEM_MOVEABLE |
    GMEM_ZEROINIT, dwBytes)` allocates the buffer.  On Win95
    `GlobalAlloc` with `cb=0` returns NULL, so fMVSetTitle bails
    BEFORE its `*(int *)(lp + 0x18) = title_handle` assignment at
    `0x7E882988`.  The lp's title-handle slot stays NULL, then
    `fMVSetAddress(lp, va, ...)` calls `FUN_7e885fc0(*(int *)(lp +
    0xc), ...)` = `FUN_7e885fc0(NULL, ...)` which short-circuits at
    its `if (param_1 != 0)` guard — `GetProcAddress("HfcNear")` is
    never attempted.  HfcNear never runs, fMVSetAddress returns 0,
    `MOSVIEW!FUN_7f3c3670` sets pane FAIL flag at `pane+0x84`, panes
    don't paint.  Verified by inspecting lp at 0x00406C70 with
    SoftIce: `lp[0x18] == 0` at the fMVSetAddress entry.

    Sections 5 and 7 stay empty.  Selector `0x02` (copyright) and
    `0x13` etc. fall through to -1; MOSVIEW's second-string query at
    `0x7F3C6634` drops the result silently.
    """
    name = display_name.rstrip("\x00") or "Untitled"
    name_bytes = name.encode("ascii", errors="replace") + b"\x00"
    section6 = name_bytes  # reuse caption as the section-6 title-string blob
    return (
        b"\x00\x00" * 4                             # Sections 0-3: empty
        + struct.pack("<H", len(name_bytes))        # Section 4 size
        + name_bytes                                # Section 4 data (ASCIIZ caption)
        + b"\x00\x00"                               # Section 5: empty
        + struct.pack("<H", len(section6))          # Section 6 size — MUST be non-zero
        + section6                                  # Section 6 data (title string)
        + b"\x00\x00"                               # Section 7: empty
        + b"\x00\x00"                               # Section 8: string count=0
    )


def _load_title_body(title_spec: str) -> bytes:
    """Resolve a TitleOpen spec to a synthesized 9-section title body."""
    deid = _title_name_from_spec(title_spec).strip()
    display = _resolve_display_name(deid)
    body = _build_title_body(display)
    log.info(
        "synthesized_title_body spec=%r deid=%r display=%r body_len=%d",
        title_spec, deid, display, len(body),
    )
    return body


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


def _build_title_open_reply_payload(title_body):
    """TitleOpen reply: static section + dynamic-complete blob.

    Static shape (7 tagged primitives, exact order required by MVTTL14C
    TitleOpenEx recv loop):
        0x81 <byte=title_id>      → title struct +0x02 (primary tid, must be nonzero)
        0x81 <byte=hfs_volume>    → title struct +0x88 (HFS vol byte for baggage)
        0x83 <dword=contents_va>  → title struct +0x8c (`vaGetContents`)
        0x83 <dword=???>          → title struct +0x90 (unresolved)
        0x83 <dword=topic_count>  → title struct +0x94 (`TitleGetInfo(0x0B)`)
        0x83 <dword=chk1>         → persisted to MVCache\\<title>.tmp
        0x83 <dword=chk2>         → persisted to MVCache\\<title>.tmp
        0x87                      end-static
        0x86 <title_body>         dynamic-complete (raw to end of host block)

    The 0x86 tag (TAG_DYNAMIC_COMPLETE_SIGNAL) is what wakes MVTTL14C's
    Wait() on slot 0x24 (same pattern as DIRSRV GetShabby — see
    PROTOCOL.md §MPC reply tags).  0x88 would route through the
    dynamic-iterator instead and leave Wait() blocked.

    All three server-supplied DWORDs ship as zero.  Empirically (probe
    with contents_va ∈ {0x00010000, 0xCAFEBABE} on 2026-04-27),
    crossing the §4.3 hide-on-failure value gate alone does not unblock
    paint — the client emits no follow-up wire traffic.  Some prior
    condition gates entry to the paint path; see docs/MEDVIEW.md §10.
    """
    chk1, chk2 = _derive_checksums(title_body)
    static = b"".join(
        [
            build_tagged_reply_byte(_TITLE_ID_PRIMARY),
            build_tagged_reply_byte(_TITLE_ID_SERVICE_BYTE),
            build_tagged_reply_dword(0),
            build_tagged_reply_dword(0),
            build_tagged_reply_dword(0),
            build_tagged_reply_dword(chk1),
            build_tagged_reply_dword(chk2),
        ]
    )
    return static + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + title_body


def _derive_checksums(body):
    """Produce a stable (chk1, chk2) pair from the body bytes.

    The checksum semantics aren't fully RE'd (see docs/MEDVIEW.md §10);
    they're opaque to the client except for cache-hit decisions on
    subsequent opens.  Use the body length as chk1 and a 16-bit rolling
    XOR as chk2 — stable per body content, both nonzero for nonempty
    bodies, both zero for the empty MVP body.
    """
    chk1 = len(body)
    chk2 = 0
    for i in range(0, len(body), 2):
        word = body[i] | (body[i + 1] << 8 if i + 1 < len(body) else 0)
        chk2 ^= word
    return chk1, chk2


def _build_title_get_info_reply_payload():
    """TitleGetInfo reply: size dword = 0, end-static, empty dynamic.

    Reached only when the info_kind is one TitleGetInfo doesn't serve
    locally from the cached body (see docs/MEDVIEW.md §5.1).  With an
    empty body every lookup falls through to the wire, so answering
    size=0 lets `lMVTitleGetInfo` return 0 without crashing MVCL14N.
    The 0x86 dynamic-complete signal wakes Wait() the same way as
    TitleOpen.
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


def _build_op4_cache_frame(title_byte, kind, key, va, addr):
    """Build a selector-0x17 type-3 op-code 4 cache-insert frame.

    Wire shape (project_medview_cache_push_format):
        +0x00 u16 op_code = 4
        +0x02 u16 length  = 18 (includes 4-byte header)
        +0x04 u8  title_byte
        +0x05 u8  kind   (0 = topic→va+addr, 1 = hash→va, 2 = va→addr)
        +0x06 u32 key    (topic_no / hash / va lookup-key)
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
        # Type-3 cache-pump subscription state.  Captured from the
        # selector-0x17 subscribe with type=3; reused later to push
        # op-code 4 cache-fill frames as `0x85` chunks on the
        # subscription's iterator (project_medview_cache_push_format).
        self.type3_sub_class = None
        self.type3_sub_req_id = None

    def build_discovery_packet(self, server_seq, client_ack):
        """Emit the IID→selector discovery block (42 entries, 1-based selectors)."""
        payload = build_discovery_payload(MEDVIEW_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def _build_cache_push_packet(self, title_byte, selector, key, server_seq, client_ack):
        """Build a packet that pushes one op-code 4 cache frame.

        Selector → kind mapping:
            0x06 (vaConvertHash) → kind 1 (hash → va)
            0x07 (vaConvertTopicNumber) → kind 0 (topic → va + addr)
            0x15 (HfcNear / vaResolve) → kind 2 (va → addr)
            others (0x10 etc.) → no push
        """
        if selector == MEDVIEW_SELECTOR_VA_CONVERT_HASH:
            kind = 1
        elif selector == MEDVIEW_SELECTOR_VA_CONVERT_TOPIC:
            kind = 0
        elif selector == MEDVIEW_SELECTOR_VA_RESOLVE:
            kind = 2
        else:
            return None
        # Stub answer: va = addr = key.  Real values would come from
        # the title's COSCL streams; as a probe we just give the
        # engine "something" so vaGetContents() returns nonzero and
        # downstream paint can advance.  If the engine rejects the
        # synthetic value the next selector firing will tell us.
        frame = _build_op4_cache_frame(title_byte, kind, key, va=key, addr=key)
        # 0x85 chunk tag + raw frame bytes; chunk dispatches to
        # FUN_7e8451ec via the type-3 callback.
        push_payload = bytes([0x85]) + frame
        push_host = build_host_block(
            self.type3_sub_class,
            MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION,
            self.type3_sub_req_id,
            push_payload,
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
            title_body = _load_title_body(title_spec)
            reply_payload = _build_title_open_reply_payload(title_body)
            log.info(
                "title_open_reply title_id=0x%02x body_len=%d",
                _TITLE_ID_PRIMARY, len(title_body),
            )
        elif selector == MEDVIEW_SELECTOR_TITLE_GET_INFO:
            info_kind, index, bufsize = _extract_get_info_args(payload)
            log.info(
                "title_get_info req_id=%d info_kind=0x%x index=%d bufsize=%d",
                request_id, info_kind, index, bufsize,
            )
            reply_payload = _build_title_get_info_reply_payload()
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
            # If the type-3 cache-pump subscription is registered AND
            # we have a (title_byte, key) we can answer, append a push
            # packet on the same pipe carrying op-code 4 frame.  The
            # client's MPCCL parses 0x85 in the push payload as a
            # chunk on the original subscribe iterator → fires chunk
            # signal → pump (FUN_7e844c7c) calls FUN_7e8451ec →
            # FUN_7e8420f6 inserts into the kind-0/1/2 cache.
            if (
                self.type3_sub_req_id is not None
                and title_byte is not None
                and key is not None
            ):
                next_seq = (server_seq + len(reply_pkts)) & 0x7F
                push_pkts = self._build_cache_push_packet(
                    title_byte, selector, key, next_seq, client_ack
                )
                if push_pkts is not None:
                    log.info(
                        "cache_push selector=0x%02x title_byte=0x%02x key=0x%08x kind=%s",
                        selector,
                        title_byte,
                        key,
                        {0x06: 1, 0x07: 0, 0x15: 2}[selector],
                    )
                    return reply_pkts + push_pkts
            return reply_pkts
        elif selector == MEDVIEW_SELECTOR_SUBSCRIBE_NOTIFICATION:
            notification_type = payload[1] if len(payload) >= 2 else None
            log.info(
                "subscribe_notification req_id=%d type=%r payload=%s",
                request_id, notification_type, payload.hex(),
            )
            if notification_type == 3:
                # Type 3 is the cache-pump subscriber (FUN_7e8451ec).
                # Reply with `0x87 0x88` (iterator stream-end) so MPC's
                # Execute returns an iterator iface — that's what the
                # pump thread (FUN_7e844c7c) reads chunks from.
                # Capture (msg_class, request_id) so we can later send
                # `0x85` chunks on this same iterator carrying op-code
                # 4 cache-fill frames when 0x06/0x07/0x15 fire.
                self.type3_sub_class = msg_class
                self.type3_sub_req_id = request_id
                reply_payload = bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])
            else:
                # Types 0/1/2/4: dynamic-complete with non-empty body
                # to make MPC's Execute return a non-NULL iface (see
                # MVTTL14C 0x7E844FA7 `MOV [ESI+0x44], 0x1` gated on
                # `*[ESI+0x28] != 0` and HRESULT >= 0).  Required for
                # the master flag DAT_7e84e2fc to set in
                # hrAttachToService — without it FUN_7e8440ab returns
                # 0 and every cache-miss retry loop bails before
                # firing 0x06/0x07/0x10/0x15.
                reply_payload = bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + b"\x00" * 8
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
