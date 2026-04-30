from ghidra.program.model.symbol import SymbolType


args = getScriptArgs()
if len(args) < 1 or len(args) > 2:
    raise RuntimeError("usage: -postScript dump_vtable.py <addr_hex> [count]")

addr = toAddr(args[0])
count = int(args[1], 0) if len(args) == 2 else 12
ptr_size = currentProgram.getDefaultPointerSize()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
symtab = currentProgram.getSymbolTable()


def read_ptr(at):
    data = bytearray(ptr_size)
    got = memory.getBytes(at, data)
    if got != ptr_size:
        raise RuntimeError(f"short read at {at}: {got} != {ptr_size}")
    value = 0
    for i, b in enumerate(data):
        value |= (b & 0xFF) << (8 * i)
    return toAddr(value)


primary = symtab.getPrimarySymbol(addr)
print(f"vtable: {addr} {primary.getName() if primary else ''}")

for idx in range(count):
    slot_addr = addr.add(idx * ptr_size)
    target = read_ptr(slot_addr)
    func = getFunctionAt(target)
    symbol = symtab.getPrimarySymbol(target)
    if func is not None:
        name = func.getName()
    elif symbol is not None:
        name = symbol.getName()
    else:
        name = "<no symbol>"
    print(f"[{idx:02d}] {slot_addr} -> {target} {name}")
