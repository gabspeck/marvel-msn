#!/usr/bin/env python3
"""
AT command responder for MSN95 dial-up emulation.
Uses a PTY directly — no socat needed.

Point 86Box COM1 at /tmp/vmodem.

Control: send SIGUSR1 to reset to AT mode without destroying the PTY.
  kill -USR1 <pid>
"""

import os
import select
import signal
import sys
import termios
import time

LINK_PATH = "/tmp/vmodem"
BAUD = 9600

# Global state for signal handler
state = {"connected": False, "buf": b""}


def reset_handler(signum, frame):
    """SIGUSR1 resets to AT command mode."""
    state["connected"] = False
    state["buf"] = b""
    print(f"\n[*] RESET to AT mode (signal {signum})")


def configure_pty(fd):
    """Configure PTY: raw mode, no flow control."""
    attrs = termios.tcgetattr(fd)
    attrs[0] &= ~(termios.IXON | termios.IXOFF | termios.IXANY |
                   termios.BRKINT | termios.ICRNL | termios.INLCR |
                   termios.IGNCR | termios.ISTRIP)
    attrs[1] &= ~(termios.OPOST)
    try:
        CRTSCTS = termios.CRTSCTS
    except AttributeError:
        CRTSCTS = 0o20000000000
    attrs[2] &= ~(CRTSCTS | termios.PARENB | termios.CSTOPB | termios.CSIZE)
    attrs[2] |= (termios.CS8 | termios.CLOCAL | termios.CREAD)
    attrs[3] &= ~(termios.ECHO | termios.ECHOE | termios.ECHOK |
                   termios.ECHONL | termios.ICANON | termios.ISIG |
                   termios.IEXTEN)
    attrs[6][termios.VMIN] = 1
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def main():
    sys.stdout = os.fdopen(sys.stdout.fileno(), "w", buffering=1)

    signal.signal(signal.SIGUSR1, reset_handler)

    master_fd, slave_fd = os.openpty()
    slave_name = os.ttyname(slave_fd)

    configure_pty(master_fd)
    configure_pty(slave_fd)

    if os.path.islink(LINK_PATH) or os.path.exists(LINK_PATH):
        os.unlink(LINK_PATH)
    os.symlink(slave_name, LINK_PATH)

    print(f"[*] PTY: {slave_name} -> {LINK_PATH}")
    print(f"[*] PID: {os.getpid()}  (kill -USR1 {os.getpid()} to reset)")
    print(f"[*] Waiting for AT commands...")
    print()

    try:
        while True:
            r, _, _ = select.select([master_fd], [], [], 0.5)
            if not r:
                continue

            data = os.read(master_fd, 4096)
            if not data:
                print("[!] PTY closed")
                break

            if state["connected"]:
                hex_str = data.hex(" ")
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
                print(f"[DATA] <-- ({len(data)} bytes) {hex_str}")
                print(f"[DATA]     ASCII: {ascii_str}")
                if 0x0D in data:
                    packets = data.split(b"\x0d")
                    for i, pkt in enumerate(packets):
                        if len(pkt) >= 2:
                            seq = pkt[0] & 0x7F
                            ack = pkt[1] & 0x7F
                            ptype = "DATA"
                            if pkt[0:1] == b"A":
                                ptype = "ACK"
                            elif pkt[0:1] == b"B":
                                ptype = "NACK"
                            print(f"[PKT]  #{i}: type={ptype} seq={seq} ack={ack} len={len(pkt)}")
                continue

            state["buf"] += data
            while b"\r" in state["buf"]:
                line, state["buf"] = state["buf"].split(b"\r", 1)
                line_str = line.decode("ascii", errors="replace").strip()

                if not line_str:
                    continue

                print(f"[AT] <-- {line_str!r}")
                upper = line_str.upper()

                if upper.startswith("ATDT") or upper.startswith("ATDP"):
                    number = line_str[4:]
                    print(f"[AT] Dialing: {number}")
                    time.sleep(0.5)
                    resp = f"\r\nCONNECT {BAUD}\r\n"
                    os.write(master_fd, resp.encode())
                    print(f"[AT] --> CONNECT {BAUD}")
                    state["connected"] = True
                    state["buf"] = b""
                    break
                elif upper.startswith("AT"):
                    os.write(master_fd, b"\r\nOK\r\n")
                    print(f"[AT] --> OK")
                else:
                    print(f"[AT] (non-AT: {data.hex(' ')})")

            if not state["connected"] and b"\r" not in data:
                print(f"[RAW] ({len(data)} bytes) {data.hex(' ')} = {data!r}")

    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        os.close(master_fd)
        os.close(slave_fd)
        if os.path.islink(LINK_PATH):
            os.unlink(LINK_PATH)


if __name__ == "__main__":
    main()
