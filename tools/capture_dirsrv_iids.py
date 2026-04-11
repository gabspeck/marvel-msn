#!/usr/bin/env python3
"""Capture IIDs passed to ResolveServiceSelectorForInterface at runtime.

Sets a HW breakpoint on the function, resumes, and on each hit reads
the IID pointer from the stack (ESP+4 for __thiscall) and prints the GUID.

SAFE MODE: Only reads memory at addresses obtained from registers
(known to be valid in current context). Never probes arbitrary addresses.

Usage: python3 capture_dirsrv_iids.py [timeout_seconds]
  Default timeout is 120s. Start this BEFORE the client connects.
"""

import struct
import sys
import time
from gdb_debug import GDBClient

# ResolveServiceSelectorForInterface in MPCCL.DLL
# Ghidra base: 0x04600000, function offset: 0x73db
BP_ADDR = 0x046073db

def format_guid(data):
    """Format 16 raw bytes as a GUID string."""
    if len(data) != 16:
        return data.hex()
    d1 = struct.unpack_from('<I', data, 0)[0]
    d2 = struct.unpack_from('<H', data, 4)[0]
    d3 = struct.unpack_from('<H', data, 6)[0]
    d4 = data[8:10]
    d5 = data[10:16]
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4.hex().upper()}-{d5.hex().upper()}"

def main():
    timeout = int(sys.argv[1]) if len(sys.argv) >= 2 else 120
    seen = {}

    gdb = GDBClient()
    print("Connecting to GDB stub...")
    gdb.connect()

    print(f"Setting HW breakpoint at 0x{BP_ADDR:08x} (no memory reads)...")
    ok = gdb.set_hw_breakpoint(BP_ADDR)
    if not ok:
        print("Failed to set breakpoint!")
        gdb.disconnect()
        return

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

            print(f"  Hit {hit_count}: EIP=0x{eip:08x} ESP=0x{esp:08x}")

            if esp:
                # __thiscall: [ESP] = ret_addr, [ESP+4] = param_1 (IID ptr)
                iid_ptr = gdb.read_dword(esp + 4)
                if iid_ptr:
                    iid_bytes = gdb.read_memory(iid_ptr, 16)
                    if iid_bytes:
                        guid_str = format_guid(iid_bytes)
                        count = seen.get(guid_str, 0) + 1
                        seen[guid_str] = count
                        tag = "" if count == 1 else f" (seen {count}x)"
                        print(f"         IID = {{{guid_str}}}{tag}")
                    else:
                        print(f"         IID ptr 0x{iid_ptr:08x} — read failed")
                else:
                    print(f"         ESP+4 read failed")

            # Resume for next hit
            gdb.continue_exec()

    except KeyboardInterrupt:
        print("\nInterrupted by user")

    print(f"\n--- Summary: {hit_count} hits, {len(seen)} unique IIDs ---")
    for guid_str, count in sorted(seen.items()):
        print(f"  {{{guid_str}}}  x{count}")

    print("\nCleaning up...")
    gdb.send_break()
    gdb.remove_hw_breakpoint(BP_ADDR)
    gdb.disconnect()
    print("Done.")

if __name__ == '__main__':
    main()
