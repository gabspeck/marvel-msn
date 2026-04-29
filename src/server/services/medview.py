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
from ..blackbird.wire import (
    build_baggage_container,
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


def _resolve_title(deid: str) -> tuple[str, Title | None]:
    """Map a DIRSRV deid to (caption, Title-or-None).

    Parses `<_titles_root()>/<deid>.ttl` when present.  Returns the
    authored `CTitle.name` plus the parsed Title object (so callers
    can inspect class objects); on missing / invalid `.ttl`, returns
    a `"Title <deid>"` fallback caption and `None`.
    """
    if not deid:
        return ("Untitled", None)
    path = _titles_root() / f"{deid}.ttl"
    if not path.is_file():
        log.info("ttl_missing deid=%r path=%s — using deid fallback", deid, path)
        return (f"Title {deid}", None)
    try:
        title = Title.from_path(str(path))
    except TTLError as exc:
        log.warning("ttl_parse_failed deid=%r path=%s: %s", deid, path, exc)
        return (f"Title {deid}", None)
    name = title.display_name
    if not name:
        log.warning("ttl_no_display_name deid=%r path=%s types=%r", deid, path, title.types)
        return (f"Title {deid}", title)
    log.info("ttl_loaded deid=%r path=%s display_name=%r", deid, path, name)
    return (name, title)


def _resolve_display_name(deid: str) -> str:
    """Backwards-compat wrapper used by tests and callers that only
    need the caption string.  See `_resolve_title` for the full form."""
    name, _ = _resolve_title(deid)
    return name


def _section1_records_from_csections(title: Title | None) -> bytes:
    """Concatenate every CSection's ver=0x03 body into wire body
    section 1 (43-byte topic records, see docs/MEDVIEW.md §4.4).

    Hypothesis (single-sample, see ttl.py): BBDESIGN release path
    flattens authored CSection instances to wire-ready records and
    tags them ver=0x03 so the 1996 Marvel server could memcpy each
    body straight into wire section 1.  Each CSection sub-storage
    contributes one 43-byte record; multiple sub-storages
    concatenate in sub-id order.

    Records that aren't exactly 43 bytes are skipped with a warning
    rather than poisoning the wire body — better blank than corrupt.
    """
    if title is None:
        return b""
    records: list[bytes] = []
    for sid, class_name in sorted(title.types.items()):
        if class_name != "CSection":
            continue
        for sub, body in sorted(title.objects.get(sid, {}).items()):
            if len(body) != 43:
                log.warning(
                    "csection_skip sid=%d sub=%d len=%d — not 43-byte wire record",
                    sid, sub, len(body),
                )
                continue
            records.append(body)
    return b"".join(records)


def _build_title_body(display_name: str, title: Title | None = None) -> bytes:
    """Synthesize a MedView 9-section body from authored title state.

    Layout (little-endian; see docs/MEDVIEW.md §4.4):

        section 0:     [u16 size=0]              # font table — empty
        section 1:     [u16 size=N][N bytes]     # 43-byte topic records,
                                                 #   one per CSection (ver=0x03 hypothesis)
        sections 2-3:  2 × [u16 size=0]          # link / layout — empty
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
    section1 = _section1_records_from_csections(title)
    return (
        b"\x00\x00"                                 # Section 0: empty (font table)
        + struct.pack("<H", len(section1)) + section1  # Section 1: CSection records
        + b"\x00\x00"                               # Section 2: empty
        + b"\x00\x00"                               # Section 3: empty
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
    display, title = _resolve_title(deid)
    body = _build_title_body(display, title)
    section1_len = 0
    if title is not None:
        section1_len = sum(
            len(b)
            for sid, cls in title.types.items() if cls == "CSection"
            for b in title.objects.get(sid, {}).values()
            if len(b) == 43
        )
    log.info(
        "synthesized_title_body spec=%r deid=%r display=%r body_len=%d section1_len=%d",
        title_spec, deid, display, len(body), section1_len,
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
      tail". The parent cell paints the bitmap; no overlaid text.

    The empty trailer is intentional: tag-`0x07` and `0x01` children
    require additional RE (FUN_7e893010 text drawer + tail-byte
    layout) before they can be synthesised correctly. The visible
    white pane at this stage is the verification milestone for the
    Phase 1/2 RE — paint-loop reaches the cell, BitBlt fires with a
    real-sized bitmap, screen no longer renders blank.
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


def _build_type0_bf_chunk(title_byte, key):
    """Build a selector-0x17 type-0 opcode-0xBF cache-insert chunk.

    HfcNear's per-title cache lives in the title struct's `title+4`
    tree (walked by `MVTTL14C!FUN_7e845efa`).  The only function that
    inserts into this tree is `MVTTL14C!FUN_7e8460df` (sole caller is
    the type-0 callback `FUN_7e8452d3` when it parses opcode 0xBF).

    Wire layout (size=0x40 form, 132 bytes total).  After HfcNear
    returns the cache entry, MVCL14N!fMVSetAddress walks the
    name_buf via FUN_7e890fd0 → FUN_7e894c50.  The walker reads
    `name_buf[0x26]` and dispatches a switch on it (cases
    1/3/4/5/0x20/0x22/0x23/0x24).  With a zero-fill or 8-byte
    buffer the dispatch lands on default, the post-switch loop
    iterates with `param_6[1]` uninitialised (FUN_7e890fd0 leaves
    `local_2e` unset on its stack frame), and the iteration walks
    off the end of `lp+0xf6`'s table → AV at `0x7E894D4C`.

    To steer into case 1 (`FUN_7e8915d0`), inject `0x01` at offset
    0x26 of the name_buf.  FUN_7e897ed0 then sets local_c[0] = 1,
    FUN_7e894c50 enters case 1, FUN_7e8915d0 zeros local_120,
    calls FUN_7e897ad0 with a zero u32 → presence bitmap = 0,
    only the length field gets a non-zero value (-0x4000 for the
    "compact" branch).  Then FUN_7e8915d0 enters its do-while
    loop calling FUN_7e891810.

    FUN_7e891810's early-exit at entry tests two conditions:
        cond1: *(byte *)(local_68 + local_30) == 0
               where local_68 = chunk content pointer (the param_4
               cascade), local_30 = local_120[0] = -0x4000.
        cond2: *(byte *)local_2a == -1
               where local_2a = pointer to chunk content past the
               header section.
    Both fail with zero-fill content → fall through into the main
    loop body.  Whether the main loop survives is unverified —
    empirically test by observing the AV address (or success).

        +0x00  u8   opcode = 0xBF
        +0x01  u8   title_byte
        +0x02  u16  name_size = 0x40
        +0x04..0x43  64-byte name buffer (memcpy'd into entry+0x20).
                     name_buf[0x26] = 0x01 (case 1 dispatch).
                     Other bytes zero.
        +0x0C  u32  key — at offset 0xC of the chunk, INSIDE the
                     name buffer; FUN_7e8452d3 reads the lookup key
                     from this fixed offset regardless of name_size.
        +0x44..0x83  60-byte content block (zeroed; bytes 0x2C and
                     0x34 of the content block are pinned HGLOBAL
                     fields per HfcNear's FUN_7e84a1d0 calls — zeros
                     yield NULL handles, treated as "absent").
    """
    name_size = 0x40
    chunk = bytearray(4 + name_size + 60)  # 132 bytes
    chunk[0] = 0xBF
    chunk[1] = title_byte & 0xFF
    chunk[2:4] = struct.pack("<H", name_size)
    # Place 0x03 at offset 0x26 of the name_buf to dispatch
    # FUN_7e894c50's case 3 (FUN_7e894560).  Hypothesis (from VIEWDLL
    # RE 2026-04-28): MVCL14N's chunk parser is the same code as
    # VIEWDLL's CArchive deserialiser, and 0x03 is the CSection
    # version byte its CSection::Serialize writes.  If correct, the
    # bytes following 0x26 are CSection state (6 typed-pointer lists +
    # CSectionProp); if wrong, expect a different AV address than
    # case-1's known sites.
    chunk[4 + 0x26] = 0x03
    # Key at chunk offset 0xC — inside the name_buf.  FUN_7e8452d3
    # reads it at this fixed offset regardless of name_size.
    chunk[12:16] = struct.pack("<I", key & 0xFFFFFFFF)
    # bytes 0x44..0x83 stay zero (60-byte content block)
    return bytes(chunk)


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

    def build_discovery_packet(self, server_seq, client_ack):
        """Emit the IID→selector discovery block (42 entries, 1-based selectors)."""
        payload = build_discovery_payload(MEDVIEW_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def _build_cache_push_packet(self, title_byte, selector, key, server_seq, client_ack):
        """Build a packet that pushes a cache-fill chunk on the right channel.

        Selector → push channel + frame:
            0x15 (HfcNear / vaResolve) → type-0, opcode 0xBF.  Inserts
                into the per-title `title+4` tree via
                FUN_7e8452d3 → FUN_7e8460df.  Required to unblock
                HfcNear; downstream the engine walks the buffer
                through `FUN_7e890fd0 → FUN_7e894c50` and currently
                AVs at 0x7E894D4C with zero-filled content.  The
                engine's SEH catches that, surfaces "service is not
                available", and MOSVIEW stays alive — strictly
                better signal than the silent no-paint state we get
                with ack-only.
            0x06 (vaConvertHash) → type-3, op-code 4 kind 1 (hash→va,
                global cache via FUN_7e841bff).
            0x07 (vaConvertTopicNumber) → type-3, op-code 4 kind 0
                (topic→va+addr, global cache via FUN_7e841be4).
            0x10 (HighlightsInTopic) → not pushed.
        """
        if selector == MEDVIEW_SELECTOR_VA_RESOLVE:
            if self.type0_sub_req_id is None:
                return None
            chunk = _build_type0_bf_chunk(title_byte, key)
            sub_class = self.type0_sub_class
            sub_req_id = self.type0_sub_req_id
            channel = "type0_bf"
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
