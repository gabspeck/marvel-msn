#!/usr/bin/env python3
"""Live login trace for MSN95 reverse engineering.

Connects to 86Box GDB stub and sets breakpoints on MOSCL.DLL dispatch
points to trace the pipe-open flow during login. MOSCL-only approach
avoids needing to find ENGCT's runtime base (which requires slow memory
scanning that crashes Win95).

When a MOSCL breakpoint hits, we read the return address from the stack
to discover ENGCT's runtime addresses organically.

Prerequisites:
  - 86Box running with GDB stub on port 12345
  - MSN client ready to connect (but NOT yet clicked Connect)

Usage:
  python3 trace_login.py              # Set BPs on MOSCL, wait for login
  python3 trace_login.py status       # Quick: pause, read regs, resume
"""

import struct
import sys
import time
import logging
from gdb_debug import GDBClient

# Flush stdout immediately
import functools
print = functools.partial(print, flush=True)

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
    stream=sys.stdout,
)
log = logging.getLogger('trace')

# ---------------------------------------------------------------------------
# Ghidra-known addresses — MOSCL.DLL only (runtime base = Ghidra base)
# ---------------------------------------------------------------------------

MOSCL_FUNCTIONS = {
    # Central IPC dispatcher — switch on cmd word (3, 7, 0xC, etc.)
    'MosSlot_MessageDispatch':    0x7f672380,
    # Sends cmd 6 (open request) to ENGCT, then blocks on Event
    'PipeObj_OpenAndWait':        0x7f671c8c,
    # cmd 7 handler — sets arena offsets + server handle (SUCCESS path)
    'PipeObj_HandleOpenResponse': 0x7f671fd7,
    # cmd 0xC handler — signals event but NO arena offsets (FAILURE path)
    'PipeObj_FlushAndSignal':     0x7f6720f8,
    # cmd 3 handler — signals semaphore for data ready
    'PipeObj_DataReady':          0x7f672170,
}

# Interesting interior points for more detail
MOSCL_INTERIOR = {
    # Inside MosSlot_MessageDispatch, right at the switch jump
    # The cmd word is in AX after: movzx eax, word ptr [esi]; sub eax, 0xf
    # Actually let's use the function entry — simpler and we read the message
    # buffer from the stack to get the cmd word.
}


def gdb_connect(gdb):
    """Connect to GDB stub with verbose logging."""
    import socket as _socket
    log.info("Connecting to 86Box GDB stub on localhost:12345...")
    gdb.sock = _socket.socket()
    gdb.sock.settimeout(10)
    log.debug("  socket created, calling connect()...")
    gdb.sock.connect((gdb.host, gdb.port))
    log.debug("  TCP connected")
    gdb._buf = b''
    time.sleep(0.3)
    log.debug("  sending + ack...")
    gdb.sock.send(b'+')
    time.sleep(0.1)
    log.debug("  querying halt reason (?)...")
    resp = gdb._send_and_recv('?', timeout=5)
    if resp:
        log.info(f"  stub alive, response: {resp[:60]}")
    else:
        log.warning("  no response to ? — stub may need a break signal")
    # GDB stub starts with CPU paused (gdbstub_step=BREAK), which freezes
    # mouse processing in 86Box. Resume immediately to unfreeze.
    log.info("Resuming CPU (GDB stub starts paused, mouse frozen until resume)...")
    gdb.continue_exec()
    log.info("GDB connection ready — CPU running, mouse unfrozen.")


def setup_moscl_breakpoints(gdb):
    """Set breakpoints on the 4 most diagnostic MOSCL functions.

    Tries HW breakpoints first (Z1), falls back to SW breakpoints (Z0).
    HW breakpoints are checked per-instruction by gdbstub_instruction()
    and don't need memory writability. SW breakpoints patch INT3 but
    require the target memory page to be writable.

    These tell us:
    - MosSlot_MessageDispatch: what IPC commands arrive (cmd word in message)
    - PipeObj_OpenAndWait: MPCCL requested a pipe-open (sends cmd 6 to MOSCP)
    - PipeObj_HandleOpenResponse: cmd 7 arrived (pipe open SUCCESS)
    - PipeObj_FlushAndSignal: cmd 0xC arrived (pipe CLOSE/FAIL)
    """
    targets = {
        # MOSCL.DLL
        'MosSlot_MessageDispatch':    0x7f672380,
        'PipeObj_OpenAndWait':        0x7f671c8c,
        'PipeObj_HandleOpenResponse': 0x7f671fd7,
        'PipeObj_FlushAndSignal':     0x7f6720f8,
        # MOSCP.EXE — Select protocol dispatch chain
        'MOSCP_SelectProto_Callback': 0x7f455de4,
        'MOSCP_SelectProto_Dispatch': 0x7f456071,
    }

    breakpoints = {}
    log.info(f"Setting {len(targets)} HW breakpoints on MOSCL.DLL:")
    for name, addr in targets.items():
        # Remove any stale breakpoint from a previous session first
        gdb.remove_hw_breakpoint(addr)
        ok = gdb.set_hw_breakpoint(addr)
        status = 'OK' if ok else 'FAILED'
        log.info(f"  0x{addr:08x}  {name}  [{status}]")
        if ok:
            breakpoints[addr] = name

    return breakpoints


def dump_hit(gdb, bp_name, regs, hit_num):
    """Print context for a breakpoint hit. Minimal memory reads."""
    eip = regs.get(8, 0)
    esp = regs.get(4, 0)
    ebp = regs.get(5, 0)

    print(f"\n{'='*70}")
    print(f"  HIT #{hit_num}: {bp_name} @ 0x{eip:08x}")
    print(f"{'='*70}")

    # Print key registers on one line
    eax = regs.get(0, 0)
    ecx = regs.get(1, 0)
    edx = regs.get(2, 0)
    ebx = regs.get(3, 0)
    esi = regs.get(6, 0)
    edi = regs.get(7, 0)
    print(f"  EAX={eax:08x} ECX={ecx:08x} EDX={edx:08x} EBX={ebx:08x}")
    print(f"  ESP={esp:08x} EBP={ebp:08x} ESI={esi:08x} EDI={edi:08x}")

    # Return address — tells us who called this function
    ret_addr = gdb.read_dword(esp)
    if ret_addr:
        print(f"  Return addr: 0x{ret_addr:08x}")

    # Function-specific context
    if 'MosSlot_MessageDispatch' in bp_name:
        # param_1 is the message buffer pointer, at [esp+4] on entry
        # (cdecl: args pushed right-to-left, ret addr at [esp])
        msg_ptr = gdb.read_dword(esp + 4)
        if msg_ptr:
            msg_data = gdb.read_memory(msg_ptr, 16)
            if msg_data:
                cmd = struct.unpack_from('<H', msg_data, 0)[0]
                cmd_names = {
                    1: 'init', 3: 'data_ready', 5: 'read_complete',
                    6: 'pipe_open_request', 7: 'PIPE_OPEN_RESPONSE',
                    9: 'notify_event', 0xC: 'FLUSH/CLOSE',
                    0xF: 'set_event', 0x10: 'pipe_error_close'
                }
                name = cmd_names.get(cmd, f'unknown_{cmd}')
                print(f"  >>> MosSlot CMD = {cmd} (0x{cmd:x}) = {name}")
                print(f"  >>> Message hex: {msg_data.hex()}")
                if cmd == 9:
                    # cmd 9 layout: [cmd:2][conn_idx:2][value:2][event_code:2][param:4]
                    if len(msg_data) >= 10:
                        conn_idx = struct.unpack_from('<H', msg_data, 2)[0]
                        evt_val = struct.unpack_from('<H', msg_data, 4)[0]
                        evt_code = struct.unpack_from('<H', msg_data, 6)[0]
                        evt_param = struct.unpack_from('<I', msg_data, 8)[0] if len(msg_data) >= 12 else 0
                        evt_names = {
                            2: 'CONNECTED', 3: 'tapi_error', 5: 'carrier_detect',
                            6: 'carrier_lost', 0x0A: 'DISCONNECTED', 0x0B: 'write_error',
                            0x0C: 'baud_rate', 0x0D: 'modem_connected', 0x0E: '1200bps',
                            0x0F: '2400bps', 0x10: '4800bps', 0x11: '9600bps',
                            0x12: '12000bps', 0x13: '14400bps', 0x14: '16800bps',
                            0x15: '19200bps', 0x16: '21600bps', 0x17: '24400bps',
                            0x18: '26400bps', 0x19: '28800bps', 0x1A: '57600bps',
                            0x1B: 'error', 0x1D: 'x25_error', 0x1E: 'pipe_data',
                            0x1F: 'packet_error1', 0x20: 'retransmit_exhausted',
                            0x21: 'packet_error2', 0x22: 'tapi_make_call_error',
                            0x23: 'TRANSPORT_PARAMS_DONE',
                        }
                        evt_name = evt_names.get(evt_code, f'unknown_0x{evt_code:x}')
                        print(f"  >>> CMD 9 EVENT: conn={conn_idx} code={evt_code} "
                              f"(0x{evt_code:x}) = {evt_name} val={evt_val} param={evt_param}")
                elif cmd == 7:
                    # Parse cmd 7 payload: [cmd:2][pipe_handle:2][server_pipe:2][read_arena:4][write_arena:4][error:2]
                    if len(msg_data) >= 16:
                        pipe_h = struct.unpack_from('<H', msg_data, 2)[0]
                        srv_pipe = struct.unpack_from('<H', msg_data, 4)[0]
                        rd_arena = struct.unpack_from('<I', msg_data, 6)[0]
                        wr_arena = struct.unpack_from('<I', msg_data, 10)[0]
                        err = struct.unpack_from('<H', msg_data, 14)[0]
                        print(f"  >>> CMD 7 PAYLOAD: pipe={pipe_h} srv_pipe={srv_pipe} "
                              f"rd_arena=0x{rd_arena:08x} wr_arena=0x{wr_arena:08x} err={err}")
                elif cmd == 0xC:
                    if len(msg_data) >= 4:
                        pipe_h = struct.unpack_from('<H', msg_data, 2)[0]
                        print(f"  >>> CMD 0xC: pipe_handle={pipe_h}")
                elif cmd == 3:
                    if len(msg_data) >= 8:
                        pipe_h = struct.unpack_from('<H', msg_data, 2)[0]
                        arena_off = struct.unpack_from('<I', msg_data, 4)[0]
                        print(f"  >>> CMD 3: pipe_handle={pipe_h} arena_offset=0x{arena_off:08x}")

    elif 'PipeObj_HandleOpenResponse' in bp_name:
        print(f"  >>> CMD 7 PATH HIT — pipe open will SUCCEED!")
        # 'this' pointer is ECX (thiscall) or first stack arg
        # Read a few stack args
        for i in range(4):
            val = gdb.read_dword(esp + 4 + i * 4)
            if val is not None:
                print(f"      arg{i}: 0x{val:08x}")

    elif 'PipeObj_FlushAndSignal' in bp_name:
        print(f"  >>> CMD 0xC PATH HIT — pipe will be flushed/closed!")

    elif 'MOSCP_SelectProto_Callback' in bp_name:
        # __cdecl: param_1=[esp+4] (protocol obj), param_2=[esp+8] (pipe buffer)
        proto_obj = gdb.read_dword(esp + 4)
        buf_ptr = gdb.read_dword(esp + 8)
        print(f"  >>> SelectProtocol_DataCallback! proto=0x{proto_obj or 0:08x} buf=0x{buf_ptr or 0:08x}")
        if buf_ptr:
            # Read flag from buffer metadata at buf[10]+4 (same as PipeObj_DeliverData)
            meta_ptr = gdb.read_dword(buf_ptr + 0x28)  # buf[10] at offset 0x28
            if meta_ptr:
                flag = gdb.read_memory(meta_ptr + 4, 1)
                if flag:
                    flag_val = flag[0]
                    if flag_val in (1, 2):
                        path = "CMD 5 path (WRONG — will not trigger handler table)"
                    else:
                        path = "DISPATCH path (GOOD — will go to handler table)"
                    print(f"  >>> Flag byte: 0x{flag_val:02x} → {path}")
            # Also read buffer content size and first bytes
            buf_size = gdb.read_dword(buf_ptr + 0x08)
            data_ptr = gdb.read_dword(buf_ptr + 0x2c)
            print(f"  >>> Buffer size={buf_size}")
            if data_ptr and buf_size and buf_size > 0:
                head = gdb.read_memory(data_ptr, min(buf_size, 16))
                if head:
                    print(f"  >>> Buffer data head: {head.hex()}")

    elif 'MOSCP_SelectProto_Dispatch' in bp_name:
        # __thiscall: this=ECX (protocol obj), param_1=[esp+4] (pipe buffer)
        proto_obj = regs.get(1, 0)  # ECX
        buf_ptr = gdb.read_dword(esp + 4)
        print(f"  >>> SelectProtocol_DispatchToHandler! proto=0x{proto_obj:08x} buf=0x{buf_ptr or 0:08x}")
        if buf_ptr:
            buf_size = gdb.read_dword(buf_ptr + 0x08)
            data_ptr = gdb.read_dword(buf_ptr + 0x2c)
            print(f"  >>> Buffer size={buf_size}")
            if data_ptr and buf_size and buf_size >= 4:
                head = gdb.read_memory(data_ptr, min(buf_size, 16))
                if head and len(head) >= 4:
                    # Dispatch reads: skip 2 bytes, then LE uint16 command
                    cmd = head[2] | (head[3] << 8)
                    handler_names = {0: 'ret_stub', 1: 'PipeOpen_SendCmd7ToMOSCL'}
                    hname = handler_names.get(cmd, f'handler_{cmd}')
                    print(f"  >>> Command index: {cmd} → {hname}")
                    print(f"  >>> Full data: {head.hex()}")

    elif 'PipeObj_OpenAndWait' in bp_name:
        # PipeObj_OpenAndWait(this, param_1, param_2, param_3, param_4, param_5, param_6, param_7)
        # __thiscall: this=ECX, params on stack after ret addr
        # this = pipe object, params include service name etc.
        # param_1 (short) at [esp+4], param_6 (timeout) at [esp+24]
        print(f"  >>> PIPE OPEN ATTEMPT! MPCCL is trying to open a service pipe!")
        print(f"  >>> this (PipeObj) = ECX = 0x{regs.get(1, 0):08x}")
        # Try to read the service name from the pipe object
        # PipeObj has svc_name at *this (first pointer) and ver_param at *(this+4)
        pipe_this = regs.get(1, 0)  # ECX
        if pipe_this:
            svc_ptr = gdb.read_dword(pipe_this)
            if svc_ptr:
                svc_data = gdb.read_memory(svc_ptr, 32)
                if svc_data:
                    try:
                        svc_str = svc_data.split(b'\x00')[0].decode('ascii', errors='replace')
                        print(f"  >>> Service name (from PipeObj): '{svc_str}'")
                    except:
                        print(f"  >>> Service name bytes: {svc_data[:16].hex()}")

    print()


def trace_login(gdb):
    """Main trace: set MOSCL breakpoints, resume, log hits during login."""

    # Pause CPU just long enough to set breakpoints, then resume immediately
    log.info("Sending break to pause CPU...")
    result = gdb.send_break()
    if result:
        sig, regs = result
        log.info(f"CPU paused at EIP=0x{regs.get(8,0):08x}")
    else:
        log.warning("No stop response — trying ? query...")
        resp = gdb._send_and_recv('?', timeout=3)
        log.info(f"  ? response: {resp[:40] if resp else '(none)'}")

    # Set breakpoints (4 HW BPs, very fast — no memory scanning)
    breakpoints = setup_moscl_breakpoints(gdb)
    if not breakpoints:
        log.error("No breakpoints set! DLLs may not be loaded yet — try after MSN UI appears.")
        gdb.continue_exec()
        return

    # Resume IMMEDIATELY to minimize CPU pause time
    log.info("Resuming CPU...")
    gdb.continue_exec()

    print(f"\n{'='*70}")
    print(f"  READY — Click 'Connect' in the MSN client now!")
    print(f"  Waiting for breakpoint hits... (Ctrl+C to stop)")
    print(f"{'='*70}\n")

    hit_count = 0
    hit_log = []

    try:
        while True:
            result = gdb.wait_for_stop(timeout=120)
            if result is None:
                log.warning("Timed out (120s). No breakpoint hit.")
                log.warning("Is MSN connecting?")
                break

            sig, regs = result
            eip = regs.get(8, 0)
            hit_count += 1

            bp_name = breakpoints.get(eip, f'UNKNOWN(0x{eip:08x})')
            timestamp = time.strftime('%H:%M:%S')
            hit_log.append((timestamp, bp_name, eip))

            dump_hit(gdb, bp_name, regs, hit_count)

            if hit_count >= 50:
                log.info("50 hits reached, stopping.")
                break

            # Resume quickly
            gdb.continue_exec()

    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        try:
            gdb.send_break()
        except:
            pass

    # ---- Summary ----
    print(f"\n{'='*70}")
    print(f"  TRACE SUMMARY — {hit_count} breakpoint hits")
    print(f"{'='*70}")
    for ts, name, addr in hit_log:
        marker = ''
        if 'OpenAndWait' in name:
            marker = ' *** PIPE OPEN ATTEMPT ***'
        elif 'HandleOpenResponse' in name:
            marker = ' *** SUCCESS PATH ***'
        elif 'FlushAndSignal' in name:
            marker = ' *** CLOSE PATH ***'
        print(f"  [{ts}] {name}{marker}")

    # Count by type
    dispatch_hits = sum(1 for _, n, _ in hit_log if 'MessageDispatch' in n)
    open_hits = sum(1 for _, n, _ in hit_log if 'OpenAndWait' in n)
    cmd7_hits = sum(1 for _, n, _ in hit_log if 'HandleOpenResponse' in n)
    cmdC_hits = sum(1 for _, n, _ in hit_log if 'FlushAndSignal' in n)

    print(f"\n  Counts:")
    print(f"    MessageDispatch (all cmds): {dispatch_hits}")
    print(f"    PipeObj_OpenAndWait:        {open_hits} {'<-- PIPE OPEN ATTEMPTED' if open_hits > 0 else '<-- NEVER CALLED (MPCCL never tried)'}")
    print(f"    HandleOpenResponse (cmd 7): {cmd7_hits} {'<-- GOOD!' if cmd7_hits > 0 else '<-- NEVER HIT'}")
    print(f"    FlushAndSignal (cmd 0xC):   {cmdC_hits} {'<-- pipe closed' if cmdC_hits > 0 else ''}")

    if open_hits == 0:
        print(f"\n  DIAGNOSIS: MPCCL/GUIDE never attempted to open a pipe.")
        print(f"  The connection established (events 2/0x23) but no service pipe was requested.")
        print(f"  Either GUIDE is waiting for something else, or the event callback failed.")
    elif open_hits > 0 and cmd7_hits == 0:
        print(f"\n  DIAGNOSIS: Pipe-open was attempted but cmd 7 never arrived.")
        print(f"  MOSCP either didn't send the pipe-open on the wire, or the server")
        print(f"  didn't respond correctly, or MOSCP couldn't route the response.")
    elif cmd7_hits > 0:
        print(f"\n  GOOD: Pipe-open succeeded (cmd 7 arrived)!")

    # Clean up breakpoints
    log.info("Removing breakpoints...")
    for addr in breakpoints:
        gdb.remove_hw_breakpoint(addr)

    # Resume CPU so Win95 doesn't stay frozen
    log.info("Resuming CPU...")
    gdb.continue_exec()
    log.info("Done.")


def quick_status(gdb):
    """Quick connect, read regs, resume. Minimal pause time."""
    log.info("Sending break...")
    result = gdb.send_break()
    if result:
        sig, regs = result
        gdb.print_registers(regs)
    else:
        log.info("No break response, reading registers directly...")
        regs = gdb.read_registers()
        if regs:
            gdb.print_registers(regs)
        else:
            log.error("Cannot read registers.")
    log.info("Resuming CPU...")
    gdb.continue_exec()


def resume_only(gdb):
    """Just resume the CPU. Use right after 86Box starts to unfreeze mouse."""
    log.info("Resuming CPU (unfreezing mouse)...")
    gdb.continue_exec()
    log.info("Done — mouse should work now.")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'trace'

    gdb = GDBClient()

    try:
        gdb_connect(gdb)

        if cmd == 'resume':
            resume_only(gdb)
        elif cmd == 'status':
            quick_status(gdb)
        elif cmd == 'trace':
            trace_login(gdb)
        else:
            print(f"""Usage: python3 trace_login.py [command]

Commands:
  trace    Set MOSCL breakpoints and trace login flow (default)
  resume   Just resume CPU (unfreeze mouse after 86Box start)
  status   Quick: pause, read registers, resume
""")

        gdb.disconnect()

    except ConnectionRefusedError:
        log.error("Connection refused — is 86Box running with GDB stub on port 12345?")
    except KeyboardInterrupt:
        print("\nAborted.")
        try:
            gdb.disconnect()
        except:
            pass
    except Exception as e:
        log.error(f"{e}")
        import traceback
        traceback.print_exc()
        try:
            gdb.disconnect()
        except:
            pass


if __name__ == '__main__':
    main()
