args = getScriptArgs()
if len(args) != 1:
    raise RuntimeError("usage: -postScript list_refs_to.py <target_addr_hex>")

target = toAddr(args[0])
print(f"target: {target}")
for ref in getReferencesTo(target):
    from_addr = ref.getFromAddress()
    func = getFunctionContaining(from_addr)
    func_name = func.getName() if func is not None else "<no function>"
    print(f"{from_addr} {ref.getReferenceType()} {func_name}")
