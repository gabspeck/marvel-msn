"""Shared selector-dispatch helpers.

Service handlers all share the same idiom: branch on wire selector, warn on
unknowns. This module centralises the warning so every handler reports
unmapped client behaviour in the same format — including a payload hex prefix
that lets a reader eyeball wire shapes (e.g. UTF-16LE text in a node-id field)
without pulling a pcap.
"""

from ..models import ByteParam, ChunkedParam, DwordParam, VarParam, WordParam

_UNHANDLED_PAYLOAD_PREFIX = 32


def log_unhandled_selector(logger, msg_class, selector, request_id, payload):
    """Warn about a selector we don't dispatch, with payload hex to aid RE.

    Payload is truncated to the first _UNHANDLED_PAYLOAD_PREFIX bytes so the
    log line stays bounded; the prefix is enough to see wire shapes at a
    glance (e.g. `73006800...` → UTF-16LE "shoes" for a Go-word request).
    """
    prefix = payload[:_UNHANDLED_PAYLOAD_PREFIX].hex()
    ellipsis = "..." if len(payload) > _UNHANDLED_PAYLOAD_PREFIX else ""
    logger.error(
        "unhandled class=0x%02x selector=0x%02x req_id=%d payload_len=%d payload=%s%s",
        msg_class,
        selector,
        request_id,
        len(payload),
        prefix,
        ellipsis,
    )


def describe_param(param):
    """One-token rendering of a decoded send-side parameter, for log lines."""
    if isinstance(param, ByteParam):
        return f"u8=0x{param.value:02x}"
    if isinstance(param, WordParam):
        return f"u16=0x{param.value:04x}"
    if isinstance(param, DwordParam):
        return f"u32=0x{param.value:08x}"
    if isinstance(param, ChunkedParam):
        return f"chunk[id={param.stream_id},len={param.total_length}]"
    if isinstance(param, VarParam):
        return f"var[{len(param.data)}]={param.data[:32].hex()}"
    return f"tag0x{param.tag:02x}"
