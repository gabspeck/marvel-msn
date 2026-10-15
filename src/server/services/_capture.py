"""Diagnostic copies of client-supplied bytes."""

import logging
import pathlib

from ..mpc import parse_request_params
from ._dispatch import describe_param

log = logging.getLogger(__name__)

CAPTURE_ROOT = pathlib.Path(__file__).resolve().parents[3] / "captures"
BLACKBIRD_CAPTURE_DIR = CAPTURE_ROOT / "blackbird"


def write_capture(path, data):
    """Write `data` to `path`. Runs inside request handlers, so an I/O error
    is logged and swallowed: it must not drop the client's connection.
    Returns the path, or None when the write failed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    except OSError as exc:
        log.warning("capture_failed path=%s err=%s", path, exc)
        return None
    log.info("capture path=%s bytes=%d", path, len(data))
    return path


def log_request_params(logger, prefix, tag, payload):
    """Log a request head's decoded parameters and a bounded hex prefix.

    Heads only: a continuation payload is raw stream bytes whose first byte
    would decode as a receive descriptor. Returns `(send_params, recv_descs)`.
    """
    if not payload:
        logger.info("%s_payload %s len=0", prefix, tag)
        return [], []
    send_params, recv_descs = parse_request_params(payload)
    logger.info(
        "%s_params %s send=%s recv=%s",
        prefix,
        tag,
        " ".join(describe_param(p) for p in send_params) or "-",
        ",".join(f"0x{d:02x}" for d in recv_descs) or "-",
    )
    logger.info("%s_payload %s len=%d hex=%s", prefix, tag, len(payload), payload[:256].hex())
    return send_params, recv_descs
