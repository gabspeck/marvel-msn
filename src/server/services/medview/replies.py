"""Per-selector reply byte builders for MEDVIEW.

Pure functions — no handler state, no side effects. Each function returns
the reply payload to wrap in a host block. Call sites are in `handler.py`.

Wire shapes per `docs/medview-service-contract.md` and `docs/MEDVIEW.md` §9.
"""

from __future__ import annotations

from ...config import (
    TAG_DYNAMIC_COMPLETE_SIGNAL,
    TAG_DYNAMIC_STREAM_END,
    TAG_END_STATIC,
)
from ...mpc import (
    build_static_reply,
    build_tagged_reply_byte,
    build_tagged_reply_dword,
    build_tagged_reply_word,
)
from .payload import (
    BM0_BAGGAGE,
    TITLE_OPEN_BODY,
    TITLE_OPEN_METADATA,
)

# --------------------------------------------------------------------------
# Generic shapes
# --------------------------------------------------------------------------


def ack() -> bytes:
    """Bare end-static (`0x87`)."""
    return bytes([TAG_END_STATIC])


def stream_end() -> bytes:
    """`0x87 0x88` — iterator stream-end. Used for SubscribeNotifications
    so MPCCL allocates a non-NULL `m_pMoreDatRef` without firing
    SignalRequestCompletion (which would set request +0x18=1 and produce
    a tight MsgWaitForSingleObject spin)."""
    return bytes([TAG_END_STATIC, TAG_DYNAMIC_STREAM_END])


def _dynamic_complete(static_fields: bytes, dyn: bytes = b"") -> bytes:
    """Static section + `0x87` end-static + `0x86` dynamic-complete + bytes."""
    return static_fields + bytes([TAG_END_STATIC, TAG_DYNAMIC_COMPLETE_SIGNAL]) + dyn


# --------------------------------------------------------------------------
# SessionService
# --------------------------------------------------------------------------


def attach_session() -> bytes:
    """`0x1F` — `validationToken : u32`. Nonzero passes the handshake;
    zero triggers MessageBox + detach in MVTTL14C."""
    return build_static_reply(build_tagged_reply_dword(1))


def pre_notify_title() -> bytes:
    """`0x1E` — `status : i32`. `0` = queued+acked."""
    return build_static_reply(build_tagged_reply_dword(0))


# --------------------------------------------------------------------------
# TitleService
# --------------------------------------------------------------------------


def open_title(body: bytes = TITLE_OPEN_BODY) -> bytes:
    """`0x01` — TitleOpen. Static fields per spec §0x01 then `0x86` +
    9-section title body. Caller may inject a per-session body."""
    md = TITLE_OPEN_METADATA
    static = (
        build_tagged_reply_byte(md.title_slot)
        + build_tagged_reply_byte(md.file_system_mode)
        + build_tagged_reply_dword(md.contents_va)
        + build_tagged_reply_dword(md.addr_base)
        + build_tagged_reply_dword(md.topic_count)
        + build_tagged_reply_dword(md.cache_header0)
        + build_tagged_reply_dword(md.cache_header1)
    )
    return _dynamic_complete(static, body)


def validate_title(is_valid: bool) -> bytes:
    """`0x00` — `isValid : u8`."""
    return build_static_reply(build_tagged_reply_byte(1 if is_valid else 0))


def close_title() -> bytes:
    """`0x02` — ack."""
    return ack()


# `0x03 GetTitleInfoRemote` reply per kind (`docs/medview-service-contract.md`
# §"Remote GetTitleInfoRemote Kinds"). For the empty path each kind ships
# the smallest valid response that decodes cleanly:
#
#   cstring / cached  → lengthOrScalar = 1, payload = `\0`
#   bytes_cap / exact → lengthOrScalar = 0, payload = empty
#   scalar            → lengthOrScalar = 0, no payload

_REMOTE_INFO_KIND_CLASS: dict[int, str] = {
    0x03: "cstring",
    0x05: "cstring",
    0x0A: "cstring",
    0x0C: "cstring",
    0x0D: "cstring",
    0x0E: "bytes_cap",
    0x0F: "cstring",
    0x10: "cstring",
    0x66: "cstring",
    0x67: "exact",
    0x68: "exact",
    0x6B: "scalar",
    0x6D: "scalar",
    0x6E: "cached",
}


def get_title_info_remote(info_kind: int) -> bytes:
    classification = _REMOTE_INFO_KIND_CLASS.get(info_kind)
    if classification in ("cstring", "cached"):
        return _dynamic_complete(build_tagged_reply_dword(1), b"\x00")
    return _dynamic_complete(build_tagged_reply_dword(0), b"")


def query_topics() -> bytes:
    """`0x04` — empty-result shape: highlightContext=0, logicalCount=0,
    secondaryResult=0, no aux blob, no sideband."""
    static = (
        build_tagged_reply_byte(0)
        + build_tagged_reply_dword(0)
        + build_tagged_reply_dword(0)
    )
    return _dynamic_complete(static, b"")


# --------------------------------------------------------------------------
# WordWheelService
# --------------------------------------------------------------------------


def open_word_wheel() -> bytes:
    """`0x09` — `wordWheelId : u8, itemCount : u32`. Empty wheel."""
    return build_static_reply(
        build_tagged_reply_byte(0),
        build_tagged_reply_dword(0),
    )


def query_word_wheel() -> bytes:
    """`0x08` — `status : u16`."""
    return build_static_reply(build_tagged_reply_word(0))


def resolve_word_wheel_prefix() -> bytes:
    """`0x0B` — `prefixResult : u32`."""
    return build_static_reply(build_tagged_reply_dword(0))


def count_key_matches() -> bytes:
    """`0x0D` — `matchCount : u16`."""
    return build_static_reply(build_tagged_reply_word(0))


def read_key_addresses() -> bytes:
    """`0x0E` — empty `addressList` dynbytes."""
    return _dynamic_complete(b"", b"")


def set_key_count_hint() -> bytes:
    """`0x0F` — `success : u8` = 0 (no-op)."""
    return build_static_reply(build_tagged_reply_byte(0))


# --------------------------------------------------------------------------
# AddressHighlightService
# --------------------------------------------------------------------------


def load_topic_highlights() -> bytes:
    """`0x10` — empty highlight blob (8B opaque header + u32 count=0)."""
    return _dynamic_complete(b"", b"\x00" * 12)


def find_highlight_address() -> bytes:
    """`0x11` — `addressToken : u32` = 0."""
    return build_static_reply(build_tagged_reply_dword(0))


# --------------------------------------------------------------------------
# RemoteFileService
# --------------------------------------------------------------------------


def open_remote_hfs_file_reject() -> bytes:
    """`0x1A` rejection — `0x87 0x81 <handle=0> 0x83 <size=0>`. Used when
    the requested baggage name is not `bm0` (e.g. the engine's first probe
    `|bm0`); MVCL14N then retries with the canonical `bm0`."""
    return (
        bytes([TAG_END_STATIC])
        + build_tagged_reply_byte(0)
        + build_tagged_reply_dword(0)
    )


def open_remote_hfs_file_accept(handle: int, size: int) -> bytes:
    """`0x1A` accept — `0x87 0x81 <handle> 0x83 <size>`."""
    return (
        bytes([TAG_END_STATIC])
        + build_tagged_reply_byte(handle)
        + build_tagged_reply_dword(size)
    )


def read_remote_hfs_file_chunk(chunk: bytes) -> bytes:
    """`0x1B` — `0x81 <status=0> 0x87 0x86 <chunk bytes>`."""
    return _dynamic_complete(build_tagged_reply_byte(0), chunk)


def read_remote_hfs_file_error() -> bytes:
    """`0x1B` error — `0x81 <status=0xFF> 0x87`."""
    return build_static_reply(build_tagged_reply_byte(0xFF))


def get_remote_fs_error() -> bytes:
    """`0x1D` — `fsError : u16` = 0."""
    return build_static_reply(build_tagged_reply_word(0))


# --------------------------------------------------------------------------
# bm0 baggage helpers
# --------------------------------------------------------------------------


_BM0_NAMES = frozenset({"bm0"})


def baggage_size(canonical_name: str, container_len: int = len(BM0_BAGGAGE)) -> int | None:
    """Return baggage byte count for a canonical name, or None to reject.

    `container_len` defaults to the hardcoded MSN Today bm0; caller may
    pass a per-session container length.
    """
    if canonical_name in _BM0_NAMES:
        return container_len
    return None


def baggage_chunk(
    offset: int,
    count: int,
    max_chunk: int,
    container: bytes = BM0_BAGGAGE,
) -> bytes:
    """Slice `container[offset : offset + min(count, max_chunk)]`."""
    end = min(offset + min(count, max_chunk), len(container))
    return container[offset:end]
