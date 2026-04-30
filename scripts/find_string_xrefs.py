def iter_defined_strings(program):
    data_iter = program.getListing().getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        try:
            if not data.hasStringValue():
                continue
            value = data.getDefaultValueRepresentation()
        except Exception:
            value = None
        if value is None:
            continue
        yield data, str(value)


def main():
    script_args = getScriptArgs()
    if not script_args:
        print("usage: find_string_xrefs.py <substring>")
        return

    needle = script_args[0].lower()
    count = 0

    for data, text in iter_defined_strings(currentProgram):
        if needle not in text.lower():
            continue

        count += 1
        addr = data.getAddress()
        print("STRING {} {}".format(addr, repr(text)))

        refs = getReferencesTo(addr)
        saw_ref = False
        for ref in refs:
            saw_ref = True
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            if func is None:
                print("  XREF {} <no function>".format(from_addr))
            else:
                print(
                    "  XREF {} {} {}".format(
                        from_addr, func.getEntryPoint(), func.getName()
                    )
                )

        if not saw_ref:
            print("  XREF <none>")

    print("matches={}".format(count))


main()
