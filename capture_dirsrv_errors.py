#!/usr/bin/env python3
"""Capture error codes from DIRSRV reply processing.

Breakpoints:
  - ResultFromDsStatus (0x7f3fabb5) — DS status → HRESULT conversion
  - FUN_046010a5 in MPCCL — MPC-level error handler

Only reads memory at addresses from registers (safe).
"""

import struct
import sys
import time
from gdb_debug import GDBClient

BREAKPOINTS = {
    0x7f3fabb5: "ResultFromDsStatus",
    0x046010a5: "MPCCL_ErrorHandler",
}

def main():
    timeout = int(sys.argv[1]) if len(sys.argv) >= 2 else 90
    gdb = GDBClient()
    print("Connecting to GDB stub...")
    gdb.connect()

    for addr, name in BREAKPOINTS.items():
        ok = gdb.set_hw_breakpoint(addr)
        print(f"  HW BP 0x{addr:08x} ({name}): {'OK' if ok else 'FAILED'}")

    print(f"Resuming. Waiting up to {timeout}s — trigger MSN Sign In now...")
    gdb.continue_exec()

    deadline = time.time() + timeout
    hit_count = 0

    try:
        while time.time() < deadline:
            remaining = max(1, deadline - time.time())
            result = gdb.wait_for_stop(timeout=remaining)
            if result is None:
                break

            sig, regs = result
            eip = regs.get(8, 0)
            esp = regs.get(4, 0)
            hit_count += 1

            name = BREAKPOINTS.get(eip, f"0x{eip:08x}")
            print(f"\n  Hit {hit_count}: {name} (EIP=0x{eip:08x})")

            if esp and eip == 0x7f3fabb5:
                # __cdecl: [ESP] = ret_addr, [ESP+4] = param_1 (DS status code)
                ds_status = gdb.read_dword(esp + 4)
                if ds_status is not None:
                    print(f"    DS status = 0x{ds_status:08x} ({ds_status})")
                ret_addr = gdb.read_dword(esp)
                if ret_addr is not None:
                    print(f"    Return addr = 0x{ret_addr:08x}")

            elif esp and eip == 0x046010a5:
                # Read first two stack args (LPCSTR error_code, something)
                arg1 = gdb.read_dword(esp + 4)
                arg2 = gdb.read_dword(esp + 8)
                if arg1 is not None:
                    print(f"    arg1 (HRESULT?) = 0x{arg1:08x}")
                if arg2 is not None:
                    print(f"    arg2 = 0x{arg2:08x}")

            gdb.continue_exec()

    except KeyboardInterrupt:
        print("\nInterrupted")

    print(f"\n--- {hit_count} total hits ---")
    print("Cleaning up...")
    gdb.send_break()
    for addr in BREAKPOINTS:
        gdb.remove_hw_breakpoint(addr)
    gdb.disconnect()
    print("Done.")

if __name__ == '__main__':
    main()
