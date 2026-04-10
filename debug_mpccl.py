#!/usr/bin/env python3
"""Debug the MPCCL InitializeLoginServiceSession flow.

Connects to 86Box GDB stub, sets breakpoints on key addresses inside
InitializeLoginServiceSession, resumes, and reports which breakpoints
fire and what register values are at each.

Run this AFTER Windows 95 has booted and you're about to click Connect
in the MSN login dialog.
"""

import sys
sys.path.insert(0, '/home/gabriels/projetos/msn95_reveng')
from gdb_debug import GDBClient
import time

# Key addresses inside InitializeLoginServiceSession
BREAKPOINTS = {
    0x0460263F: 'InitializeLoginServiceSession entry',
    0x0460273B: 'after InitializeServiceInterfaceSelectorState (check EAX: 0=early exit, 1=continue)',
    0x0460284B: 'after credential copy, sessionHandle check (JNZ)',
    0x04602859: 'FMCMOpenSession call',
    0x04602861: 'after FMCMOpenSession (check EAX: 0=fail)',
    0x046028C4: 'after FGetConDetails (check EAX: 0=fail)',
    0x04602906: 'convergence point before pipe-open prep',
    0x0460295E: '_OpenMOSPipeWithNotifyEx_28 call',
    0x04602963: 'after pipe open (check AX: FFFF=fail)',
}

def main():
    gdb = GDBClient()
    gdb.connect()

    # Get initial state
    regs = gdb.read_registers()
    eip = regs.get(8, 0)
    cs = regs.get(10, 0)
    print(f'Connected. CPU paused at EIP=0x{eip:08x} CS=0x{cs:04x}')

    # Set hardware breakpoints (limited to 4 by x86 debug registers)
    # Start with the most important ones
    phase1 = [
        (0x0460273B, 'after InitializeServiceInterfaceSelectorState'),
        (0x0460284B, 'after credential copy / sessionHandle check'),
        (0x04602906, 'convergence before pipe-open prep'),
        (0x04602963, 'after pipe open'),
    ]

    print('\n--- Phase 1: Setting breakpoints ---')
    for addr, desc in phase1:
        ok = gdb.set_hw_breakpoint(addr)
        print(f'  HW BP 0x{addr:08x} ({desc}): {"OK" if ok else "FAILED"}')

    print('\nBreakpoints set. Resuming CPU.')
    print('Start the MSN login now. Waiting for breakpoint hits...\n')
    gdb.continue_exec()

    hits = []
    while True:
        result = gdb.wait_for_stop(timeout=120)
        if not result:
            print('Timed out waiting (120s). No more breakpoints hit.')
            break

        sig, regs = result
        eip = regs.get(8, 0)
        eax = regs.get(0, 0)
        ecx = regs.get(1, 0)
        edx = regs.get(2, 0)
        ebx = regs.get(3, 0)
        esp = regs.get(4, 0)
        ebp = regs.get(5, 0)
        esi = regs.get(6, 0)
        edi = regs.get(7, 0)

        desc = BREAKPOINTS.get(eip, f'unknown (0x{eip:08x})')
        hits.append((eip, eax, desc))

        print(f'=== BREAKPOINT HIT: 0x{eip:08x} ===')
        print(f'  Description: {desc}')
        print(f'  EAX=0x{eax:08x}  ECX=0x{ecx:08x}  EDX=0x{edx:08x}  EBX=0x{ebx:08x}')
        print(f'  ESP=0x{esp:08x}  EBP=0x{ebp:08x}  ESI=0x{esi:08x}  EDI=0x{edi:08x}')

        if eip == 0x0460273B:
            print(f'  >>> InitializeServiceInterfaceSelectorState returned EAX={eax}')
            if eax == 0:
                print(f'  >>> FAILURE: selector state init failed, will early-exit')
            else:
                print(f'  >>> SUCCESS: continuing to session open')

        elif eip == 0x0460284B:
            # This is JNZ after CMP word ptr [EDI], 0xFFFF
            # EDI points to sessionHandle
            edi_val = gdb.read_dword(edi)
            print(f'  >>> sessionHandle at [EDI=0x{edi:08x}] = 0x{edi_val:08x}' if edi_val is not None else '  >>> could not read [EDI]')

        elif eip == 0x04602861:
            print(f'  >>> FMCMOpenSession returned EAX={eax}')
            if eax == 0:
                print(f'  >>> FAILURE: MCM session open failed')

        elif eip == 0x04602906:
            print(f'  >>> Reached convergence point - session is open, pipe-open prep next')

        elif eip == 0x04602963:
            ax = eax & 0xFFFF
            print(f'  >>> _OpenMOSPipeWithNotifyEx_28 returned AX=0x{ax:04x}')
            if ax == 0xFFFF:
                print(f'  >>> FAILURE: pipe open failed')
            else:
                print(f'  >>> SUCCESS: pipe handle = {ax}')

        print()

        # Continue to next breakpoint
        gdb.continue_exec()

    # Summary
    print('\n=== SUMMARY ===')
    if not hits:
        print('No breakpoints hit. MPCCL may not have been loaded yet.')
        print('Make sure you started the MSN login before the timeout.')
    else:
        print(f'{len(hits)} breakpoints hit:')
        for eip, eax, desc in hits:
            print(f'  0x{eip:08x} EAX=0x{eax:08x} - {desc}')

        last_eip = hits[-1][0]
        if last_eip == 0x0460273B:
            print('\nExecution stopped after selector state init.')
            print('Check EAX value above.')
        elif last_eip == 0x0460284B:
            print('\nExecution reached credential/session section.')
        elif last_eip == 0x04602906:
            print('\nExecution reached pipe-open prep - session open succeeded!')
        elif last_eip == 0x04602963:
            print('\nExecution reached pipe open result!')
        else:
            print(f'\nLast hit was at 0x{last_eip:08x}')

        # Check what was NOT hit
        expected = [0x0460273B, 0x0460284B, 0x04602906, 0x04602963]
        hit_addrs = set(e for e, _, _ in hits)
        missed = [a for a in expected if a not in hit_addrs]
        if missed:
            print(f'\nNEVER reached:')
            for a in missed:
                print(f'  0x{a:08x} - {BREAKPOINTS.get(a, "?")}')

    # Clean up breakpoints
    print('\nCleaning up breakpoints...')
    for addr, _ in phase1:
        gdb.remove_hw_breakpoint(addr)

    gdb.disconnect()
    print('Done.')

if __name__ == '__main__':
    main()
