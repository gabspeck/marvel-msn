#!/usr/bin/env python3
"""Trace CServiceProperties::FGet calls to discover which property names
MOSSHELL reads from DIRSRV reply records.

FGet signature (from SVCPROP.DLL decompile):
  int __thiscall CServiceProperties::FGet(
      CServiceProperties *this,   // ECX (thiscall)
      char *prop_name,            // [ESP+4] after call
      char *out_type,             // [ESP+8]
      void **out_value,           // [ESP+C]
      ulong *out_size             // [ESP+10]
  )

We break at the function entry, read the prop_name from [ESP+4],
log it, then continue.

Also traces FDecompressPropClnt to confirm records reach the parser.
"""

import time
from gdb_debug import GDBClient

# SVCPROP.DLL addresses (from Ghidra)
FGET_ADDR = 0x7f641460       # CServiceProperties::FGet entry
FDECOMPRESS_ADDR = 0x7f6416c5  # FDecompressPropClnt entry

def read_string(gdb, addr, maxlen=64):
    """Read a NUL-terminated string from memory."""
    data = gdb.read_memory(addr, maxlen)
    if data is None:
        return None
    nul = data.find(b'\x00')
    if nul >= 0:
        data = data[:nul]
    return data.decode('ascii', errors='replace')

def main():
    gdb = GDBClient()
    gdb.connect()

    # Check if CPU is already halted (86Box halts on GDB connect)
    print("[*] Checking CPU state...")
    reason = gdb.halt_reason()
    if reason and isinstance(reason, tuple):
        sig, regs = reason
        eip = regs.get(8, 0)
        print(f"[*] CPU already halted at EIP=0x{eip:08x}")
    else:
        print("[*] Breaking into VM...")
        stop = gdb.send_break()
        if stop is None:
            print("[!] Failed to break into VM")
            gdb.disconnect(resume=True)
            return
        _, regs = stop
        eip = regs.get(8, 0)
        print(f"[*] Stopped at EIP=0x{eip:08x}")

    # Clear any stale HW breakpoints from previous sessions, then set fresh ones
    gdb.remove_hw_breakpoint(FGET_ADDR)
    gdb.remove_hw_breakpoint(FDECOMPRESS_ADDR)

    print(f"[*] Setting HW breakpoint on FGet @ 0x{FGET_ADDR:08x}")
    ok1 = gdb.set_hw_breakpoint(FGET_ADDR)
    print(f"    Result: {'OK' if ok1 else 'FAILED'}")

    print(f"[*] Setting HW breakpoint on FDecompressPropClnt @ 0x{FDECOMPRESS_ADDR:08x}")
    ok2 = gdb.set_hw_breakpoint(FDECOMPRESS_ADDR)
    print(f"    Result: {'OK' if ok2 else 'FAILED'}")

    print("[*] Resuming, waiting for hits... (Ctrl+C to stop)")
    gdb.continue_exec()

    hit_count = 0
    prop_names = []
    try:
        while True:
            stop = gdb.wait_for_stop(timeout=120)
            if stop is None:
                print("[*] Timeout waiting for breakpoint, continuing...")
                break

            regs = gdb.read_registers()
            eip = regs.get(8, 0)
            esp = regs.get(4, 0)  # ESP

            if eip == FDECOMPRESS_ADDR or eip == FDECOMPRESS_ADDR + 1:
                # FDecompressPropClnt(void* buf, ulong buf_len, CServiceProperties* out)
                buf_ptr = gdb.read_dword(esp + 4)
                buf_len = gdb.read_dword(esp + 8)
                print(f"[HIT] FDecompressPropClnt buf=0x{buf_ptr:08x} len={buf_len}")
                if buf_ptr:
                    data = gdb.read_memory(buf_ptr, min(buf_len or 64, 128))
                    if data:
                        print(f"       data: {data[:64].hex()}")

            elif eip == FGET_ADDR or eip == FGET_ADDR + 1:
                # FGet(this=ECX, char* name=[ESP+4], ...)
                name_ptr = gdb.read_dword(esp + 4)
                if name_ptr:
                    name = read_string(gdb, name_ptr)
                    hit_count += 1
                    if name not in prop_names:
                        prop_names.append(name)
                    print(f"[HIT #{hit_count}] FGet prop_name=\"{name}\"")
                else:
                    print(f"[HIT] FGet prop_name=NULL")

            # Resume
            gdb.continue_exec()

    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        gdb.send_break()

    # Clean up
    print("\n[*] Removing breakpoints...")
    gdb.remove_hw_breakpoint(FGET_ADDR)
    gdb.remove_hw_breakpoint(FDECOMPRESS_ADDR)

    print(f"\n[*] Summary: {hit_count} FGet hits")
    print(f"[*] Unique property names queried: {prop_names}")

    gdb.disconnect(resume=True)
    print("[*] Done, VM resumed")

if __name__ == '__main__':
    main()
