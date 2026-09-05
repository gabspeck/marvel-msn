"""Entry point: python -m server"""

import contextlib
import datetime
import logging
import selectors
import socket
import threading

from . import log as server_log
from .config import GATEWAY_PORT, HOST, LISTEN_BACKLOG, PORT
from .connection import handle_connection
from .store import app_store

log = logging.getLogger("server")


def _serve(conn, addr, direct):
    """Run one client connection to completion on its own thread.

    Each connection owns its socket, its sequence numbers, and its `Session`.
    The log context is `ContextVar`-backed, so a thread starting with a fresh
    context keeps its `conn_id` and event counter separate from every other
    connection.
    """
    try:
        handle_connection(conn, addr, direct=direct)
    except Exception:
        log.exception("unhandled_exception")


def _listen(port):
    """Bind and listen, or return None after saying why not.

    Either transport is worth serving without the other, so a bind that fails
    drops that port and leaves the one that came up running.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((HOST, port))
    except OSError as e:
        srv.close()
        log.warning("listen_failed port=%d reason=%s", port, e)
        return None
    srv.listen(LISTEN_BACKLOG)
    return srv


def main():
    server_log.configure()
    log.info(
        "listen host=%s port=%d gateway_port=%d date=%s",
        HOST,
        PORT,
        GATEWAY_PORT,
        datetime.date.today().isoformat(),
    )
    # The store restores persisted Blackbird publishes while it is imported,
    # which happens before the handlers above exist — so say so here instead,
    # where it is visible. Silent state restoration is a trap when the next
    # session is spent wondering why a node is already published.
    published = [
        node.node_id for node in app_store.content.all_nodes() if node.content.blackbird_site
    ]
    log.info("blackbird_published nodes=%s", ",".join(published) or "-")

    # Two ways in, one protocol: the modem port carries MOSCP.EXE over the
    # 86Box modem emulator, the gateway port carries ENGCT.EXE straight over
    # TCP. Only the bring-up differs (docs/TCP-TRANSPORT.md §2).
    listeners = {PORT: False, GATEWAY_PORT: True}
    sel = selectors.DefaultSelector()
    try:
        for port, direct in listeners.items():
            srv = _listen(port)
            if srv is not None:
                sel.register(srv, selectors.EVENT_READ, direct)

        if not sel.get_map():
            raise SystemExit("no listening socket")

        while True:
            for key, _ in sel.select():
                conn, addr = key.fileobj.accept()
                threading.Thread(
                    target=_serve,
                    args=(conn, addr, key.data),
                    name=f"conn-{addr[0]}:{addr[1]}",
                    daemon=True,
                ).start()
    finally:
        for key in list(sel.get_map().values()):
            with contextlib.suppress(OSError):
                key.fileobj.close()
        sel.close()


if __name__ == "__main__":
    main()
