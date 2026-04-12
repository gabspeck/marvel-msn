#!/usr/bin/env python3
"""Hunt for our MPCCL breakpoint hits, auto-resume spurious ones.

HW BPs fire on linear address, so they hit in ANY process where MPCCL
happens to be mapped at that VA. We inspect each stop; if EIP matches
one of our target addresses and CS is user-mode (ring 3), we report and
stop. Otherwise we resume.
"""
import sys
from gdb_debug import GDBClient

TARGETS = {
    0x04603e17: 'RegisterFixedReplyDwordField',
    0x04603ebc: 'RegisterVariableReplyBuffer',
    0x04604f26: 'ProcessTaggedServiceReply',
    0x046035bf: 'DispatchReplyByRequestId',
    0x04604350: 'DispatchReplyToRequestObject',
    0x004025cf: 'SIGNUP!HresultClassifier (FUN_004025cf)',
    0x004030ee: 'SIGNUP!ErrorDispatcher (FUN_004030ee)',
    0x0040353f: 'SIGNUP!ShowSignupErrorDialog (16 callers)',
    0x00406562: 'DispatchSignupCommitAndWait post-wait (EBX=wait result)',
    0x0040658b: 'DispatchSignupCommitAndWait case 0 SUCCESS (status_word==0)',
    0x0040664c: 'DispatchSignupCommitAndWait error call to ShowSignupErrorDialog',
    # Phase 1: trace Congrats path.  Expected healthy flow after submit:
    #   0x00406562 (commit success) -> 0x004060d1 (EndDialog, EBX=0x19)
    #   -> 0x004016df (case 8 entry) -> 0x004016ef (FUN_00401332 returned)
    #   -> 0x00401706 (call Congrats) -> 0x00405b28 (Congrats entry)
    #   -> 0x00405b4b (DialogBoxParamA returned; EAX = dialog result)
    # Hitting 0x00401737 without hitting 0x004016df means an abort arm fired.
    0x004060d1: 'credentials page EndDialog(EBX=iVar3, [EBP+8]=hwnd)',
    0x004016df: 'FUN_00401469 case 8 entry (success finalize)',
    0x004016ef: 'FUN_00401469 after FUN_00401332 (EAX=its return)',
    0x00401706: 'FUN_00401469 call FUN_00405b28 (Congrats)',
    0x00405b28: 'FUN_00405b28 entry (Congrats DialogBoxParamA wrapper)',
    0x00405b4b: 'FUN_00405b28 after DialogBoxParamA(0x3e8) (EAX=dialog result)',
    0x00401737: 'FUN_00401469 exit merge (abort arms jump here)',
}

def main():
    budget = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    gdb = GDBClient()
    gdb.connect()

    # Check current state — if already stopped at our target, use that.
    # Otherwise send a break to sample current EIP and decide.
    spurious = 0
    initial = gdb.halt_reason()
    if isinstance(initial, tuple):
        sig, regs = initial
        eip = regs.get(8, 0)
        cs = regs.get(10, 0)
        if eip in TARGETS and (cs & 3) == 3:
            result = initial
        else:
            gdb.continue_exec()
            result = None
    else:
        gdb.continue_exec()
        result = None

    while True:
        if result is None:
            result = gdb.wait_for_stop(timeout=budget)
        if result is None:
            print(f'Timed out after {budget}s (spurious hits so far: {spurious})')
            break
        sig, regs = result
        eip = regs.get(8, 0)
        cs = regs.get(10, 0)
        if eip in TARGETS and (cs & 3) == 3:
            print(f'*** HIT {TARGETS[eip]} at 0x{eip:08x} (cs=0x{cs:04x}) ***')
            print(f'  EAX=0x{regs.get(0,0):08x}  ECX=0x{regs.get(1,0):08x}  EDX=0x{regs.get(2,0):08x}  EBX=0x{regs.get(3,0):08x}')
            print(f'  ESP=0x{regs.get(4,0):08x}  EBP=0x{regs.get(5,0):08x}  ESI=0x{regs.get(6,0):08x}  EDI=0x{regs.get(7,0):08x}')
            # Dump stack args (first 6 dwords above ESP — ret addr + params)
            esp = regs.get(4, 0)
            for i in range(6):
                v = gdb.read_dword(esp + 4*i)
                label = 'ret' if i == 0 else f'arg{i}'
                print(f'  [esp+{4*i:2d}] {label:5s} = 0x{v:08x}' if v is not None else f'  [esp+{4*i:2d}] read failed')
            break
        else:
            spurious += 1
            if spurious <= 5 or spurious % 20 == 0:
                print(f'  spurious #{spurious}: EIP=0x{eip:08x} CS=0x{cs:04x} — resuming')
            gdb.continue_exec()
            result = None

    # Don't send detach packet — that clears HW BPs. Just close the
    # socket so the armed BPs survive for the next hunt_bp invocation.
    if gdb.sock:
        try:
            gdb._send_packet('c')  # ensure CPU is running before we drop
        except Exception:
            pass
        gdb.sock.close()
        gdb.sock = None

if __name__ == '__main__':
    main()
