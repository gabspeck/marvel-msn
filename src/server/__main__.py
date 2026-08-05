"""Entry point: python -m server"""

import datetime
import logging
import socket
import threading

from . import log as server_log
from .config import HOST, LISTEN_BACKLOG, PORT
from .connection import handle_connection

log = logging.getLogger("server")


def _serve(conn, addr):
    """Run one client connection to completion on its own thread.

    Each connection owns its socket, its sequence numbers, and its `Session`.
    The log context is `ContextVar`-backed, so a thread starting with a fresh
    context keeps its `conn_id` and event counter separate from every other
    connection.
    """
    try:
        handle_connection(conn, addr)
    except Exception:
        log.exception("unhandled_exception")


def main():
    server_log.configure()
    log.info("listen host=%s port=%d date=%s", HOST, PORT, datetime.date.today().isoformat())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(LISTEN_BACKLOG)

        while True:
            conn, addr = srv.accept()
            threading.Thread(
                target=_serve,
                args=(conn, addr),
                name=f"conn-{addr[0]}:{addr[1]}",
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
