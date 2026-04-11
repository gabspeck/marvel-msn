#!/usr/bin/env python3
"""Long quiet transport trace for late post-connect transitions.

Uses a small hardware-breakpoint set that avoids the noisy MOSCP writer path:
- MOSCP dispatcher
- MOSCL open-response handler
- MPCCL return from _OpenMOSPipeWithNotifyEx_28
- MOSCP pipe-data handler
- MOSCP cmd7 candidate

Important: MOSCP dispatcher at 0x7f45552b is __fastcall:
- ECX = dispatcher object
- [ESP+4] = param_1
- [ESP+8] = param_2
- [ESP+0xc] = param_3 (command buffer)
"""

import functools
import struct
import sys

from gdb_debug import GDBClient

print = functools.partial(print, flush=True)

BPS = {
    0x7F45552B: "MOSCP_DispatchMosclCmd",
    0x7F671FD7: "MOSCL_PipeObj_HandleOpenResponse",
    0x04602963: "MPCCL_ReturnFrom_OpenMOSPipeWithNotifyEx",
    0x7F455BCA: "MOSCP_Channel_PipeDataHandler",
    0x7F455CB1: "MOSCP_Cmd7Candidate",
}


def rd(g, a):
    try:
        return g.read_dword(a)
    except Exception:
        return None


def rm(g, a, n):
    try:
        return g.read_memory(a, n)
    except Exception:
        return None


def dump_words(data, max_words=12):
    count = min(len(data) // 2, max_words)
    return [hex(struct.unpack_from("<H", data, i * 2)[0]) for i in range(count)]


def dump_dispatch_cmd(g, esp):
    param1 = rd(g, esp + 4)
    param2 = rd(g, esp + 8)
    cmd_ptr = rd(g, esp + 0xC)
    print(
        f"  fastcall: param1=0x{(param1 or 0):08x} "
        f"param2=0x{(param2 or 0):08x} cmd_ptr=0x{(cmd_ptr or 0):08x}"
    )
    if cmd_ptr and 0x10000 <= cmd_ptr < 0x80000000:
        data = rm(g, cmd_ptr, 0x80)
        if data:
            print(f"  cmdbuf=0x{cmd_ptr:08x} words={dump_words(data)}")
            if len(data) >= 16:
                print(f"  cmdbuf_hex={data[:32].hex()}")


def main():
    g = GDBClient()
    installed = []
    try:
        print("Connecting to 86Box GDB stub...")
        g.connect()
        resp = g._send_and_recv("?", timeout=5)
        print(f"Initial stop: {resp[:60] if resp else '(none)'}")
        print("Pausing CPU briefly to install breakpoints...")
        g.send_break()
        regs = g.read_registers()
        if regs:
            print(f"Paused at EIP=0x{regs.get(8, 0):08x}")
        print("Installing hardware breakpoints:")
        for addr, name in BPS.items():
            ok = g.set_hw_breakpoint(addr)
            print(f"  0x{addr:08x} {name:40s} [{'OK' if ok else 'FAILED'}]")
            if ok:
                installed.append((addr, name))

        g.continue_exec()
        print(
            "\nREADY — Click Connect in the MSN client now. Only once. "
            "Then leave it alone for 30 seconds.\n"
        )

        hits = 0
        while hits < 20:
            result = g.wait_for_stop(timeout=180)
            if result is None:
                print("Timed out waiting 180s for another hit.")
                break

            sig, regs = result
            eip = regs.get(8, 0)
            esp = regs.get(4, 0)
            ecx = regs.get(1, 0)
            hits += 1
            name = next((n for a, n in installed if a == eip), f"UNKNOWN_0x{eip:08x}")

            print("=" * 72)
            print(f"HIT #{hits}: {name} @ 0x{eip:08x} signal={sig}")
            print(f"  ESP=0x{esp:08x} ECX=0x{ecx:08x}")
            ret = rd(g, esp)
            if ret is not None:
                print(f"  RET=0x{ret:08x}")

            if eip == 0x7F45552B:
                dump_dispatch_cmd(g, esp)
            else:
                args = [rd(g, esp + 4 + i * 4) for i in range(4)]
                print("  args=" + " ".join(f"0x{(a or 0):08x}" for a in args))
                if eip == 0x7F671FD7:
                    blob = rm(g, ecx, 0x80)
                    if blob:
                        print(f"  thismem={blob.hex()}")

            g.continue_exec()

    finally:
        try:
            for addr, _ in installed:
                try:
                    g.remove_hw_breakpoint(addr)
                except Exception:
                    pass
            g.disconnect(resume=True)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
