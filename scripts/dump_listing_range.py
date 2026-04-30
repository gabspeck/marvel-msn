from ghidra.program.model.address import Address


def main():
    script_args = getScriptArgs()
    if len(script_args) < 2:
        print("usage: dump_listing_range.py <start_addr> <count>")
        return

    start = toAddr(script_args[0])
    count = int(script_args[1], 0)
    listing = currentProgram.getListing()
    inst = listing.getInstructionAt(start)
    if inst is None:
        inst = listing.getInstructionAfter(start.subtract(1))

    seen = 0
    while inst is not None and seen < count:
        print("{}: {} {}".format(inst.getAddress(), inst.getMnemonicString(), inst))
        inst = inst.getNext()
        seen += 1


main()
