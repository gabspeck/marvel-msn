from ghidra.app.decompiler import DecompInterface


args = getScriptArgs()
if len(args) != 1:
    raise RuntimeError("usage: -postScript list_callers.py <target_addr_hex>")
target = args[0]


program = currentProgram
addr = toAddr(target)
func = getFunctionAt(addr)
if func is None:
    raise RuntimeError(f"no function at {target}")

print(f"target: {func.getEntryPoint()} {func.getName()}")

decomp = DecompInterface()
decomp.openProgram(program)

refs = getReferencesTo(addr)
seen = set()
for ref in refs:
    from_addr = ref.getFromAddress()
    caller = getFunctionContaining(from_addr)
    if caller is None:
        continue
    entry = caller.getEntryPoint()
    if entry in seen:
        continue
    seen.add(entry)
    result = decomp.decompileFunction(caller, 30, monitor)
    print(f"\ncaller: {entry} {caller.getName()}")
    if result is None or not result.decompileCompleted():
        print("  <decompile failed>")
        continue
    text = result.getDecompiledFunction().getC()
    for line in text.splitlines():
        if func.getName() in line or target.lower() in line.lower():
            print("  " + line.strip())
