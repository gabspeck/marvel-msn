#!/usr/bin/env python3
"""Live MOSCP trace for MSN95 reverse engineering.

Supports two breakpoint strategies:
- `hw`: small four-slot hardware set on core MOSCP functions
- `callers`: four hardware breakpoints on distinct state/caller sites
- `wide`: broader software-breakpoint net on the concrete MOSCP call sites
  observed in prior runs

The wide set is intentionally aggressive. It is meant to answer "which state
machine path actually runs during login?" in one pass rather than retargeting
breakpoints by hand.

Prerequisites:
  - 86Box running with GDB stub on port 12345
  - "Force interpretation" enabled in 86Box (required for HW breakpoints)
  - MSN client ready to connect, but do not click Connect until prompted
"""

import functools
import logging
import struct
import sys
import time

from gdb_debug import GDBClient

print = functools.partial(print, flush=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    stream=sys.stdout,
)
log = logging.getLogger("trace_moscp")


MOSCP_BREAKPOINTS = {
    0x7F454464: "notify_event",
    0x7F455895: "MosSlot_WriteToClient",
    0x7F455BCA: "Channel_PipeDataHandler",
    0x7F455CB1: "OpenResponseCandidate_StraightNeighbor",
}

MOSCP_CALLER_BREAKPOINTS = {
    0x7F456A6F: "caller_after_notify_0c",
    0x7F456D5F: "caller_after_notify_0d",
    0x7F458F16: "caller_after_notify_11",
    0x7F4535ED: "state_path_07",
}

MOSCP_WIDE_BREAKPOINTS = {
    0x7F454464: "notify_event",
    0x7F455895: "MosSlot_WriteToClient",
    0x7F455BCA: "Channel_PipeDataHandler",
    0x7F455CB1: "OpenResponseCandidate_StraightNeighbor",
    0x7F456A6F: "caller_after_notify_0c",
    0x7F456D5F: "caller_after_notify_0d",
    0x7F458F16: "caller_after_notify_11",
    0x7F4535ED: "state_path_07",
    0x7F453655: "state_path_08",
    0x7F458D02: "state_path_02",
    0x7F459518: "state_path_05",
    0x7F453E8F: "state_path_23",
}


def gdb_connect(gdb):
    log.info("Connecting to 86Box GDB stub on localhost:12345...")
    gdb.connect()
    resp = gdb._send_and_recv("?", timeout=5)
    log.info("GDB ready. Initial stop response: %s", resp[:60] if resp else "(none)")


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


def setup_breakpoints(gdb, mode):
    installed = {}
    if mode == "wide":
        targets = MOSCP_WIDE_BREAKPOINTS
        setter = gdb.set_sw_breakpoint
        kind = "software"
    elif mode == "callers":
        targets = MOSCP_CALLER_BREAKPOINTS
        setter = gdb.set_hw_breakpoint
        kind = "hardware"
    else:
        targets = MOSCP_BREAKPOINTS
        setter = gdb.set_hw_breakpoint
        kind = "hardware"

    log.info("Setting %d MOSCP %s breakpoints...", len(targets), kind)
    for addr, name in targets.items():
        ok = setter(addr)
        log.info("  0x%08x  %-32s [%s]", addr, name, "OK" if ok else "FAILED")
        if ok:
            installed[addr] = name
    return installed


def parse_words(data):
    return [struct.unpack_from("<H", data, i)[0] for i in range(0, len(data) - 1, 2)]


def dump_common(gdb, regs):
    eip = regs.get(8, 0)
    esp = regs.get(4, 0)
    ebp = regs.get(5, 0)
    eax = regs.get(0, 0)
    ecx = regs.get(1, 0)
    edx = regs.get(2, 0)
    ebx = regs.get(3, 0)
    esi = regs.get(6, 0)
    edi = regs.get(7, 0)

    print(f"  EIP={eip:08x} ESP={esp:08x} EBP={ebp:08x}")
    print(f"  EAX={eax:08x} ECX={ecx:08x} EDX={edx:08x} EBX={ebx:08x}")
    print(f"  ESI={esi:08x} EDI={edi:08x}")

    ret_addr = read_dword_safe(gdb, esp)
    if ret_addr is not None:
        print(f"  RET={ret_addr:08x}")

    stack = read_mem_safe(gdb, esp, 0x30)
    if stack:
        print(f"  STACK={stack.hex()}")


def dump_notify_event(gdb, regs):
    esp = regs.get(4, 0)
    ecx = regs.get(1, 0)
    print(f"  this={ecx:08x}")
    for i in range(3):
        arg = read_dword_safe(gdb, esp + 4 + i * 4)
        if arg is not None:
            print(f"  arg{i+1}=0x{arg:08x}")


def dump_write_to_client(gdb, regs):
    esp = regs.get(4, 0)
    ecx = regs.get(1, 0)
    buf_ptr = read_dword_safe(gdb, esp + 8)
    length = read_dword_safe(gdb, esp + 12)
    print(f"  this={ecx:08x}")
    if buf_ptr is not None:
        print(f"  buf_ptr=0x{buf_ptr:08x}")
    if length is not None:
        print(f"  length=0x{length:08x}")

    if buf_ptr and length and 0 < length <= 0x40:
        data = read_mem_safe(gdb, buf_ptr, length)
        if data:
            print(f"  MSG={data.hex()}")
            print(f"  WORDS={[hex(x) for x in parse_words(data)]}")

    if ecx:
        obj = read_mem_safe(gdb, ecx, 0x20)
        if obj:
            print(f"  THISMEM={obj.hex()}")


def dump_pipe_handler(gdb, regs):
    esp = regs.get(4, 0)
    ecx = regs.get(1, 0)
    print(f"  this={ecx:08x}")
    for i in range(4):
        arg = read_dword_safe(gdb, esp + 4 + i * 4)
        if arg is not None:
            print(f"  arg{i+1}=0x{arg:08x}")

    if ecx:
        obj = read_mem_safe(gdb, ecx, 0x40)
        if obj:
            print(f"  THISMEM={obj.hex()}")


def dump_unknown(gdb, regs):
    esp = regs.get(4, 0)
    ecx = regs.get(1, 0)
    print(f"  this/ecx={ecx:08x}")
    for i in range(4):
        arg = read_dword_safe(gdb, esp + 4 + i * 4)
        if arg is not None:
            print(f"  arg{i+1}=0x{arg:08x}")


def dump_hit(gdb, bp_name, regs, hit_num):
    print(f"\n{'=' * 72}")
    print(f"HIT #{hit_num}: {bp_name} @ 0x{regs.get(8, 0):08x}")
    print(f"{'=' * 72}")
    dump_common(gdb, regs)

    if bp_name == "notify_event":
        dump_notify_event(gdb, regs)
    elif bp_name == "MosSlot_WriteToClient":
        dump_write_to_client(gdb, regs)
    elif bp_name == "Channel_PipeDataHandler":
        dump_pipe_handler(gdb, regs)
    else:
        dump_unknown(gdb, regs)


def trace(gdb, mode):
    log.info("Sending break to pause CPU briefly...")
    gdb.send_break()
    regs = gdb.read_registers()
    if regs:
        log.info("CPU paused at EIP=0x%08x", regs.get(8, 0))

    breakpoints = setup_breakpoints(gdb, mode)
    if not breakpoints:
        log.error("No breakpoints installed.")
        gdb.continue_exec()
        return 1

    log.info("Resuming CPU.")
    gdb.continue_exec()

    print(f"\n{'=' * 72}")
    print("READY — Click Connect in the MSN client now.")
    if mode == "wide":
        print("This run is using the wide MOSCP software-breakpoint net.")
    else:
        print("This run is tracing the compact MOSCP hardware-breakpoint set.")
    print(f"{'=' * 72}\n")

    hit_log = []
    try:
        while True:
            result = gdb.wait_for_stop(timeout=120)
            if result is None:
                print("\nTimed out waiting for another breakpoint hit.")
                break

            _, regs = result
            eip = regs.get(8, 0)
            name = breakpoints.get(eip, f"UNKNOWN(0x{eip:08x})")
            hit_log.append((time.strftime("%H:%M:%S"), name, eip))
            dump_hit(gdb, name, regs, len(hit_log))

            if len(hit_log) >= 20:
                print("\nHit limit reached; stopping trace.")
                break

            gdb.continue_exec()
    finally:
        log.info("Removing breakpoints...")
        for addr in breakpoints:
            if mode == "wide":
                gdb.remove_sw_breakpoint(addr)
            else:
                gdb.remove_hw_breakpoint(addr)

        print(f"\n{'=' * 72}")
        print(f"TRACE SUMMARY — {len(hit_log)} hit(s)")
        print(f"{'=' * 72}")
        for ts, name, addr in hit_log:
            print(f"[{ts}] 0x{addr:08x} {name}")

        log.info("Resuming CPU.")
        gdb.continue_exec()

    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "wide"
    if mode not in ("hw", "callers", "wide"):
        print("Usage: python3 trace_moscp.py [hw|callers|wide]")
        raise SystemExit(2)

    gdb = GDBClient()
    try:
        gdb_connect(gdb)
        rc = trace(gdb, mode)
        gdb.disconnect(resume=False)
        raise SystemExit(rc)
    except ConnectionRefusedError:
        log.error("Connection refused — is 86Box running with GDB stub on port 12345?")
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        try:
            gdb.disconnect()
        except Exception:
            pass
        raise SystemExit(130)
    except Exception:
        import traceback
        traceback.print_exc()
        try:
            gdb.disconnect()
        except Exception:
            pass
        raise SystemExit(1)


if __name__ == "__main__":
    main()
