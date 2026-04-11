"""Entry point: python -m server"""
import sys
import os
import socket

from .config import HOST, PORT
from .connection import handle_connection


def main():
    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)
    print(f"[*] MSN dial-up server listening on {HOST}:{PORT}")
    print()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)

        while True:
            conn, addr = srv.accept()
            try:
                handle_connection(conn, addr)
            except Exception as e:
                print(f"[!] Error: {e}")
                import traceback
                traceback.print_exc()
            print()


if __name__ == '__main__':
    main()
