#!/usr/bin/env python3
"""Watch BILLADD.DLL show/hide dispatcher FUN_00433a63.

At entry ECX = billing handle.  Dumps:
  this+0x12c = sel_idx (just stored by LBN_SELCHANGE handler)
  this + 0x130 + sel_idx*0xb8 = 4-byte field the code reads as 'iVar3'
                                and compares against 1/2 to decide
                                whether to show credit-card controls.
  Also dumps row[0..2] type-numbers (at row+0) and label-prefixes (at row+4)
  so we can see whether row 0's type was clobbered by sel_idx storage.
"""
import sys
from gdb_debug import GDBClient

BP = 0x00433a63

def dump(gdb, regs):
    this = regs.get(1, 0)  # ECX
    sel = gdb.read_dword(this + 0x12c)
    iVar3 = None
    if sel is not None and sel != 0xffffffff:
        iVar3 = gdb.read_dword(this + 0x130 + (sel & 0xffff) * 0xb8)
    print(f'  this=0x{this:08x}  [this+0x12c]=0x{sel:08x}  iVar3(row[sel]+4)={iVar3 and hex(iVar3)}')
    for i in range(3):
        base = this + 0x12c + i * 0xb8
        t = gdb.read_dword(base)
        l0 = gdb.read_dword(base + 4)
        l1 = gdb.read_dword(base + 8)
        label = b''
        for j in range(12):
            b = gdb.read_dword(base + 4 + j)
            if b is None: break
            label += bytes([b & 0xff])
        label = label.split(b'\x00', 1)[0]
        print(f'  row[{i}] @0x{base:08x}  type=0x{t:08x}  label={label!r}')

def main():
    gdb = GDBClient()
    gdb.connect()
    ok = gdb.set_hw_breakpoint(BP)
    print(f'arm HW BP @ 0x{BP:08x} -> {ok}')
    gdb.continue_exec()
    hits = 0
    try:
        while True:
            r = gdb.wait_for_stop(timeout=300)
            if r is None:
                print('timeout')
                break
            sig, regs = r
            eip = regs.get(8, 0)
            cs = regs.get(10, 0)
            if eip == BP and (cs & 3) == 3:
                hits += 1
                print(f'*** HIT #{hits} FUN_00433a63 eip=0x{eip:08x} cs=0x{cs:04x} ***')
                dump(gdb, regs)
                sys.stdout.flush()
            else:
                print(f'  spurious eip=0x{eip:08x} cs=0x{cs:04x}')
            gdb.continue_exec()
    finally:
        # leave BP armed; socket close auto-resumes
        if gdb.sock:
            try: gdb._send_packet('c')
            except: pass
            gdb.sock.close()

if __name__ == '__main__':
    main()
