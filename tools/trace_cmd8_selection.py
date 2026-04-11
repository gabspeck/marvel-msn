#!/usr/bin/env python3
"""One-shot MOSCP cmd-8 selector snapshot.

Stops once at FUN_7f4569dc, dumps the incoming cmd-8 payload and the current
transport registry entries, then detaches cleanly.

Use this only when the Win95 client is ready to click Connect. The script will
print a clear READY line before waiting for the hit.
"""

import functools
import struct
import sys
import time

from gdb_debug import GDBClient

print = functools.partial(print, flush=True)

BP_ADDR = 0x7F4569DC
REGISTRY_ADDR = 0x7F45E928


def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def read_dword_safe(gdb, addr):
    try:
        return gdb.read_dword(addr)
    except Exception:
        return None


def read_mem_safe(gdb, addr, length):
    try:
        return gdb.read_memory(addr, length)
    except Exception:
        return None


def read_cstr_safe(gdb, addr, limit=64):
    if not addr or addr >= 0x80000000:
        return None
    data = read_mem_safe(gdb, addr, limit)
    if not data:
        return None
    end = data.find(b"\x00")
    if end == -1:
        end = limit
    raw = data[:end]
    if not raw:
        return ""
    if any(b < 0x20 or b > 0x7E for b in raw):
        return None
    try:
        return raw.decode("ascii")
    except Exception:
        return None


def dump_registry_entry(gdb, idx, entry_addr):
    blob = read_mem_safe(gdb, entry_addr, 0x1a0)
    if not blob or len(blob) < 0x18c:
        print(f"  [{idx}] 0x{entry_addr:08x} unreadable")
        return

    vtable = read_u32(blob, 0x00)
    state = read_u32(blob, 0x178)
    obj_type = read_u32(blob, 0x188)
    name_ptr = read_u32(blob, 0x48)
    backend_ptr = read_u32(blob, 0x4C)
    aux_id = read_u32(blob, 0x70)
    slot_1c = read_dword_safe(gdb, vtable + 0x1C) if vtable else None
    slot_2c = read_dword_safe(gdb, vtable + 0x2C) if vtable else None
    name = read_cstr_safe(gdb, name_ptr)
    backend = read_cstr_safe(gdb, backend_ptr)

    print(
        f"  [{idx}] entry=0x{entry_addr:08x} vtable=0x{vtable:08x} "
        f"type={obj_type} state={state} aux_id={aux_id}"
    )
    print(
        f"       name_ptr=0x{name_ptr:08x} name={name!r} "
        f"backend_ptr=0x{backend_ptr:08x} backend={backend!r}"
    )
    print(
        f"       vtbl+1c=0x{(slot_1c or 0):08x} "
        f"vtbl+2c=0x{(slot_2c or 0):08x}"
    )


def main():
    gdb = GDBClient()
    try:
        print("Connecting to 86Box GDB stub...")
        gdb.connect()
        resp = gdb._send_and_recv("?", timeout=5)
        print(f"Initial stop: {resp[:60] if resp else '(none)'}")

        print("Pausing CPU briefly to install breakpoint...")
        gdb.send_break()
        regs = gdb.read_registers()
        if regs:
            print(f"Paused at EIP=0x{regs.get(8, 0):08x}")

        ok = gdb.set_hw_breakpoint(BP_ADDR)
        print(f"HW breakpoint @ 0x{BP_ADDR:08x}: {'OK' if ok else 'FAILED'}")
        if not ok:
            return 1

        gdb.continue_exec()
        print("\nREADY — Click Connect in the MSN client now. Only once.\n")

        result = gdb.wait_for_stop(timeout=120)
        if result is None:
            print("Timed out waiting for cmd-8 selector hit.")
            return 1

        sig, regs = result
        eip = regs.get(8, 0)
        esp = regs.get(4, 0)
        ecx = regs.get(1, 0)
        print(f"HIT signal={sig} EIP=0x{eip:08x} ESP=0x{esp:08x} ECX=0x{ecx:08x}")

        param1 = read_dword_safe(gdb, esp + 4)
        param2 = read_dword_safe(gdb, esp + 8)
        param3 = read_dword_safe(gdb, esp + 12)
        param4 = read_dword_safe(gdb, esp + 16)
        print(
            f"args: param1=0x{(param1 or 0):08x} param2=0x{(param2 or 0):08x} "
            f"param3=0x{(param3 or 0):08x} param4=0x{(param4 or 0):08x}"
        )

        if param1:
            cmd = read_mem_safe(gdb, param1, 0x80)
            if cmd:
                print(f"cmd8 payload @ 0x{param1:08x}: {cmd.hex()}")
                if len(cmd) >= 8:
                    print(
                        f"cmd words: {[hex(read_u16(cmd, i)) for i in range(0, min(len(cmd), 24), 2)]}"
                    )
                    print(f"cmd subtype word @ +2 = 0x{read_u16(cmd, 2):04x}")
                for off in (0x06, 0x10, 0x20, 0x30):
                    if off < len(cmd):
                        frag = cmd[off:off + 24]
                        if frag:
                            try:
                                txt = frag.split(b'\x00', 1)[0].decode("ascii")
                            except Exception:
                                txt = None
                            if txt:
                                print(f"ascii @ +0x{off:02x}: {txt!r}")

        reg_blob = read_mem_safe(gdb, REGISTRY_ADDR, 0x40)
        if reg_blob and len(reg_blob) >= 0x30:
            count = read_u32(reg_blob, 0x04)
            table = read_u32(reg_blob, 0x08)
            reg_count = read_u32(reg_blob, 0x2C)
            reg_table = read_u32(reg_blob, 0x30)
            print(
                f"registry @ 0x{REGISTRY_ADDR:08x}: "
                f"count={count} table=0x{table:08x} reg_count={reg_count} reg_table=0x{reg_table:08x}"
            )

            if count and table:
                print("\nActive transport objects:")
                for idx in range(min(count, 16)):
                    entry = read_dword_safe(gdb, table + idx * 4)
                    if entry:
                        dump_registry_entry(gdb, idx, entry)

            if reg_count and reg_table:
                print("\nRegistered transport templates:")
                for idx in range(min(reg_count, 16)):
                    entry = read_dword_safe(gdb, reg_table + idx * 4)
                    if entry:
                        name_ptr = read_dword_safe(gdb, entry + 0x48) or 0
                        backend_ptr = read_dword_safe(gdb, entry + 0x4C) or 0
                        aux_id = read_dword_safe(gdb, entry + 0x70) or 0
                        print(
                            f"  [{idx}] tpl=0x{entry:08x} aux_id={aux_id} "
                            f"name={read_cstr_safe(gdb, name_ptr)!r} "
                            f"backend={read_cstr_safe(gdb, backend_ptr)!r}"
                        )

        gdb.remove_hw_breakpoint(BP_ADDR)
        return 0
    finally:
        try:
            gdb.disconnect(resume=True)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
