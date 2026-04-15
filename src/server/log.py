"""Server-wide logging configuration.

One top-level `server` logger with per-module children. Records carry
connection-local `conn_id`, `elapsed`, and `event_no` fields injected by
a `ContextVar`-backed filter. `conn_id` is set once per connection via
`set_connection()`; `elapsed` + `event_no` advance per event via
`set_context()`. Outside a connection (boot, shutdown, stray
exceptions) the filter reports zeros for all three.

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


_conn_id: contextvars.ContextVar[int] = contextvars.ContextVar(
    "server_log_conn_id",
    default=0,
)

_ctx: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "server_log_ctx",
    default=None,
)


class _CtxFilter(logging.Filter):
    def filter(self, record):
        record.conn_id = _conn_id.get()
        ctx = _ctx.get()
        if ctx is None:
            record.elapsed = 0.0
            record.event_no = 0
        else:
            record.elapsed = ctx["elapsed"]
            record.event_no = ctx["event_no"]
        return True


def set_connection(conn_id):
    _conn_id.set(conn_id)


def clear_connection():
    _conn_id.set(0)


def set_context(elapsed, event_no):
    _ctx.set({"elapsed": elapsed, "event_no": event_no})


def reset_context():
    _ctx.set(None)


def configure(level=None):
    level_name = (level or os.environ.get("MSN_LOG_LEVEL", "INFO")).upper()
    resolved = getattr(logging, level_name, None)
    if resolved is None:
        resolved = TRACE if level_name == "TRACE" else logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s.%(msecs)03d %(levelname)-5s "
            "[c=%(conn_id)03d %(elapsed)7.3f #%(event_no)04d] %(name)s %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    handler.addFilter(_CtxFilter())

    root = logging.getLogger("server")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(resolved)
    root.propagate = False
