"""Entry point: python -m server"""
import logging
import socket

from . import log as server_log
from .config import HOST, PORT
from .connection import handle_connection


def main():
    server_log.configure()
    log = logging.getLogger("server")
    log.info("listen host=%s port=%d", HOST, PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)

        while True:
            conn, addr = srv.accept()
            try:
                handle_connection(conn, addr)
            except Exception:
                log.exception("unhandled_exception")


if __name__ == '__main__':
    main()
