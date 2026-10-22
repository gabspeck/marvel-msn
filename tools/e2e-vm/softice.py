#!/usr/bin/env python3
"""Drive SoftICE in the e2e VM through 86Box's automation socket.

  softice.py popup                 pop SoftICE up (Ctrl+D) unless it is up
  softice.py cmd CMD [CMD ...]     run commands at the prompt, print their output
  softice.py screen                print SoftICE's 80x25 screen
  softice.py resume                leave SoftICE (X)
  softice.py wait [SECONDS]        wait for SoftICE to pop up, e.g. on a breakpoint

`cmd` pops SoftICE up first if needed and leaves it up. The socket takes one
client at a time; from a test that already holds it, use SoftIce(Automation).

When SoftICE pops up it switches the S3 card into 80x25 text mode itself, and
the BIOS data area still says 0x69, so the automation `text` and `wait text`
commands refuse it. The text buffer at 0xB8000 is read with `memr` instead,
and `wait mem` on the status line tells when SoftICE sits at its prompt.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vm import VM, Automation  # noqa: E402

TEXT_BUFFER = 0xB8000
COLS, ROWS = 80, 25
# Bottom row while SoftICE waits at its prompt: "Enter a command" from column
# 5, black on cyan (attribute 0x30). Observed in this VM's SoftICE build; the
# row shows a command's syntax instead while one is being typed.
IDLE = "Enter a command"
IDLE_ADDR = TEXT_BUFFER + ((ROWS - 1) * COLS + 5) * 2
IDLE_BYTES = "".join(f"{ord(c):02x}30" for c in IDLE)


class SoftIce:
    def __init__(self, vm):
        self.vm = vm

    def screen(self):
        """The 25 rows of the text buffer, trailing blanks stripped."""
        data = bytes.fromhex(self.vm("memr", TEXT_BUFFER, COLS * ROWS * 2)["data"])
        # SoftICE pads some rows with NUL or 0xFF, and marks a scrollable window
        # with an arrow (0x18/0x19) in the last column.
        chars = bytearray(data[::2].replace(b"\0", b" ").replace(b"\xff", b" "))
        for r in range(ROWS):
            if chars[r * COLS + COLS - 1] in (0x18, 0x19):
                chars[r * COLS + COLS - 1] = 0x20
        return [chars[r * COLS:(r + 1) * COLS].decode("cp437").rstrip() for r in range(ROWS)]

    def command_window(self):
        """Rows below the last window divider, down to the status line."""
        rows = self.screen()[:ROWS - 1]
        top = max(i for i, r in enumerate(rows) if r.startswith("\u2500"))
        return rows[top + 1:]

    def idle(self, timeout_ms=0):
        """Whether SoftICE is up at its prompt, waiting up to timeout_ms of emulated time."""
        return self.vm("wait", "mem", timeout_ms, hex(IDLE_ADDR), IDLE_BYTES)["matched"]

    def popup(self):
        if self.idle():
            return
        self.vm("key", "down", 0x1D)  # Ctrl+D; it also leaves SoftICE, hence the check
        self.vm.press(0x20)
        self.vm("key", "up", 0x1D)
        if not self.idle(5000):
            raise TimeoutError("SoftICE did not pop up")

    def cmd(self, text, timeout_ms=30000):
        """Run one command and return the lines it printed in the command window.

        Output longer than the window, or a command that redraws the layout
        (WC, WR, ...), leaves no echo to anchor on; the whole window comes back.
        Commands that open an editor (R, E with no data) never return to IDLE.
        """
        self.popup()
        self.vm.type(text + "\n")
        self.vm("step", 200)  # let the status line leave IDLE before waiting on it
        if not self.idle(timeout_ms):
            raise TimeoutError(f"{text!r} did not return to the prompt")
        rows = self.command_window()
        echo = ":" + text
        start = max((i for i, r in enumerate(rows) if r.lower() == echo.lower()), default=-1)
        end = max(i for i, r in enumerate(rows) if r.startswith(":"))  # the new prompt
        return rows[start + 1:end]

    def resume(self):
        self.vm.type("x\n")
        self.vm("step", 1000)

    def wait(self, timeout_ms):
        """Run Windows until SoftICE pops up (a breakpoint, Ctrl+D) or timeout_ms passes."""
        return self.idle(timeout_ms)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--socket", default=str(VM / "automation.sock"), help="automation socket")
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("popup")
    c = sub.add_parser("cmd")
    c.add_argument("commands", nargs="+")
    sub.add_parser("screen")
    sub.add_parser("resume")
    w = sub.add_parser("wait")
    w.add_argument("seconds", nargs="?", type=float, default=60)
    args = p.parse_args()

    si = SoftIce(Automation(args.socket))
    if args.action == "popup":
        si.popup()
    elif args.action == "cmd":
        for command in args.commands:
            print(":" + command)
            print("\n".join(si.cmd(command)))
    elif args.action == "screen":
        print("\n".join(si.screen()))
    elif args.action == "resume":
        si.resume()
    elif not si.wait(int(args.seconds * 1000)):
        sys.exit("SoftICE did not pop up")


if __name__ == "__main__":
    main()
