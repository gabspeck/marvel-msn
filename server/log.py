"""Server-wide logging configuration.

One top-level `server` logger with per-module children. Records carry
connection-local `elapsed` and `event_no` fields injected by a
`ContextVar`-backed filter — callers inside a connection loop call
`set_context()` at each event boundary so any handler that logs on that
call gets the right prefix. Outside a connection (boot, shutdown, stray
exceptions) the filter defaults both to zero.

TRACE (level 5) is added below DEBUG for hex-dump firehose.
"""
from __future__ import annotations

import contextvars
import logging
import os
import sys

TRACE = 5
logging.addLevelName(TRACE, "TRACE")


def _trace(self, msg, *args, **kwargs):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, msg, args, **kwargs)


logging.Logger.trace = _trace


_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "server_log_ctx", default={"elapsed": 0.0, "event_no": 0},
)


class _CtxFilter(logging.Filter):
    def filter(self, record):
        ctx = _ctx.get()
        record.elapsed = ctx["elapsed"]
        record.event_no = ctx["event_no"]
        return True


def set_context(elapsed, event_no):
    _ctx.set({"elapsed": elapsed, "event_no": event_no})


def reset_context():
    _ctx.set({"elapsed": 0.0, "event_no": 0})


def configure(level=None):
    level_name = (level or os.environ.get("MSN_LOG_LEVEL", "INFO")).upper()
    resolved = getattr(logging, level_name, None)
    if resolved is None:
        resolved = TRACE if level_name == "TRACE" else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-5s "
        "[%(elapsed)7.3f #%(event_no)04d] %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    ))
    handler.addFilter(_CtxFilter())

    root = logging.getLogger("server")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(resolved)
    root.propagate = False
