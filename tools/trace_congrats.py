#!/usr/bin/env python3
"""Trace BP hits along the post-commit Congrats path.

Stays connected to the 86Box GDB stub and logs each BP hit in
order, resuming after each.  Designed to capture the sequence
from `DispatchSignupCommitAndWait` return through either the
Congrats dialog or the abort merge point.
"""
import sys
import time
from gdb_debug import GDBClient

# Mirrors hunt_bp.TARGETS for the Congrats trace subset, plus the
# existing commit BPs we want context on.
LABELS = {
    0x00406562: 'commit_post_wait',
    0x0040658b: 'commit_success_case0',
    0x0040664c: 'commit_error_ShowSignupErrorDialog',
    0x004060d1: 'credpage_EndDialog(EBX=result)',
    0x004016df: 'case8_entry',
    0x004016ef: 'case8_after_FUN_00401332(EAX=return)',
    0x00401706: 'case8_call_Congrats',
    0x00405b28: 'Congrats_entry',
    0x00405b4b: 'Congrats_after_DialogBoxParamA(EAX=result)',
    0x00401737: 'switch_exit_merge',
    0x0040353f: 'ShowSignupErrorDialog_entry',
}


def main():
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    gdb = GDBClient()
    gdb.connect()

    # Sample current state; if already paused at a known BP, report it
    # first, then resume.  Otherwise just resume and wait.
    initial = gdb.halt_reason()
    if isinstance(initial, tuple):
        sig, regs = initial
        eip = regs.get(8, 0)
        if eip in LABELS:
            dump(eip, regs, gdb)
    gdb.continue_exec()

    start = time.time()
    hits = 0
    while time.time() - start < budget:
        remaining = budget - (time.time() - start)
        result = gdb.wait_for_stop(timeout=min(remaining, 30))
        if result is None:
            continue
        sig, regs = result
        eip = regs.get(8, 0)
        cs = regs.get(10, 0)
        if eip in LABELS and (cs & 3) == 3:
            hits += 1
            dump(eip, regs, gdb)
            # If we're at the abort merge or Congrats-after, we've
            # likely captured what we need — keep going a bit longer
            # in case more fires.
        else:
            # Spurious HW BP hit in another process — resume silently.
            pass
        gdb.continue_exec()

    # Clean disconnect — leave CPU running, keep BPs armed.
    if gdb.sock:
        try:
            gdb._send_packet('c')
        except Exception:
            pass
        gdb.sock.close()
    print(f'\n[trace] done. {hits} tagged hits in {int(time.time()-start)}s.')


def dump(eip, regs, gdb):
    label = LABELS[eip]
    t = time.strftime('%H:%M:%S')
    print(f'[{t}] 0x{eip:08x}  {label}')
    print(f'  EAX=0x{regs.get(0,0):08x}  ECX=0x{regs.get(1,0):08x}  '
          f'EDX=0x{regs.get(2,0):08x}  EBX=0x{regs.get(3,0):08x}')
    print(f'  ESP=0x{regs.get(4,0):08x}  EBP=0x{regs.get(5,0):08x}  '
          f'ESI=0x{regs.get(6,0):08x}  EDI=0x{regs.get(7,0):08x}')
    # Stack: ret addr + first few args
    esp = regs.get(4, 0)
    args = []
    for i in range(5):
        v = gdb.read_dword(esp + 4*i)
        args.append(v if v is not None else -1)
    print(f'  [esp+00]={args[0]:#010x} (ret)  '
          f'[esp+04]={args[1]:#010x}  [esp+08]={args[2]:#010x}  '
          f'[esp+0c]={args[3]:#010x}  [esp+10]={args[4]:#010x}')


if __name__ == '__main__':
    main()
