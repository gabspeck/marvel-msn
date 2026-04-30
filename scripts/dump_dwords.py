def main():
    script_args = getScriptArgs()
    if len(script_args) < 2:
        print("usage: dump_dwords.py <start_addr> <count>")
        return

    addr = toAddr(script_args[0])
    count = int(script_args[1], 0)
    mem = currentProgram.getMemory()

    for i in range(count):
        cur = addr.add(i * 4)
        value = mem.getInt(cur) & 0xFFFFFFFF
        print("{}: {:08x}".format(cur, value))


main()
