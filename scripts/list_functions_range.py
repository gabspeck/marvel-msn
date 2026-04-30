args = getScriptArgs()
if len(args) != 2:
    raise RuntimeError("usage: -postScript list_functions_range.py <start_hex> <end_hex>")

start = toAddr(args[0])
end = toAddr(args[1])
func = getFirstFunction()
while func is not None:
    entry = func.getEntryPoint()
    if start <= entry <= end:
        print(f"{entry} {func.getName()} :: {func.getSignature()}")
    func = getFunctionAfter(func)
