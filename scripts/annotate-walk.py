"""
Worklist generator + progress tracker for the MOSVIEW total-decomp pass.

Run via the ghidra-headless MCP `ghidra_script` tool against an OPEN program
session. The script reads its mode from `script_args[0]` and writes to/from
the controlling project's `scratch/` tree.

Modes
-----
* `worklist <out_path>`
    Walk every function in `currentProgram`. BFS from exports + entry point
    tagging each address with reachable depth. Emit `<out_path>` containing
    one address per line (hex, no `0x` prefix), sorted ascending by:
        (reachable_from_export ? 0 : 1, depth, addr)
    Non-thunk auto-named functions go first; reachable-from-export thunks
    come at the end of their depth bucket; orphans come last.

* `unnamed <out_path>`
    Same as `worklist` but only emits addresses whose primary symbol still
    matches an auto-name regex (FUN_/SUB_/thunk_FUN_).

* `report`
    Emit one JSON line per binary on stdout: total fns, named, FUN_, SUB_,
    thunks, exports, and current reachability stats.

Caller responsibilities
-----------------------
The actual annotation BFS is driven externally via direct MCP-tool calls
(ghidra-annotate skill or hand-driven) reading the worklist file. This
script does NOT mutate the program; it is a pure generator + reporter.

The progress file is maintained by the caller at
`scratch/annotate-progress/<binary>.json` with shape:
    {"completed": ["7f3c1000", ...], "skipped": [], "lastUpdated": "..."}

Conventions
-----------
* `scratch/annotate-worklist/<BIN>.txt` -- the worklist
* `scratch/annotate-worklist/<BIN>.unnamed.txt` -- subset still FUN_/SUB_
* `scratch/annotate-progress/<BIN>.json` -- progress
"""

import json
import os
import re
import sys
from collections import deque

AUTO_NAME = re.compile(r"^(FUN_|SUB_|thunk_FUN_)[0-9a-fA-F]+$")


def _addr_hex(addr):
    return addr.toString().lower().lstrip("0") or "0"


def _fn_kind(fn):
    name = fn.getName()
    if fn.isThunk():
        return "thunk"
    if AUTO_NAME.match(name):
        return "auto"
    return "named"


def _function_manager():
    return currentProgram.getFunctionManager()  # noqa: F821 -- pyghidra inject


def _symbol_table():
    return currentProgram.getSymbolTable()  # noqa: F821


def _exports():
    out = []
    st = _symbol_table()
    for sym in st.getAllSymbols(False):
        if sym.isExternalEntryPoint():
            fn = _function_manager().getFunctionAt(sym.getAddress())
            if fn is not None:
                out.append(fn)
    return out


def _entry_point_fns():
    """Functions referenced by program-level entry-point symbols."""
    out = []
    st = _symbol_table()
    for ep in st.getExternalEntryPointIterator():
        fn = _function_manager().getFunctionAt(ep)
        if fn is not None:
            out.append(fn)
    return out


def _bfs_depth(seeds):
    """Map address -> shortest depth from any seed via getCalledFunctions."""
    depth = {}
    queue = deque()
    for fn in seeds:
        addr = fn.getEntryPoint()
        if addr in depth:
            continue
        depth[addr] = 0
        queue.append(fn)
    while queue:
        fn = queue.popleft()
        d = depth[fn.getEntryPoint()]
        for callee in fn.getCalledFunctions(monitor):  # noqa: F821
            ce = callee.getEntryPoint()
            if ce in depth:
                continue
            depth[ce] = d + 1
            queue.append(callee)
    return depth


def _all_functions():
    return list(_function_manager().getFunctions(True))


def _sorted_worklist(only_unnamed=False):
    seeds = _exports() + _entry_point_fns()
    depth = _bfs_depth(seeds)
    fns = _all_functions()
    rows = []
    for fn in fns:
        kind = _fn_kind(fn)
        if only_unnamed and kind == "named":
            continue
        addr = fn.getEntryPoint()
        d = depth.get(addr, 1 << 30)
        reach_bucket = 0 if d < (1 << 30) else 1
        kind_bucket = {"auto": 0, "thunk": 1, "named": 2}[kind]
        rows.append((reach_bucket, d, kind_bucket, addr.getOffset(), fn))
    rows.sort()
    return rows


def _write_worklist(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        for reach, depth, kind, _addr, fn in rows:
            entry = fn.getEntryPoint()
            f.write(
                "{addr}\t{reach}\t{depth}\t{kind}\t{name}\n".format(
                    addr=_addr_hex(entry),
                    reach="reach" if reach == 0 else "orphan",
                    depth=depth if depth < (1 << 30) else "-",
                    kind={0: "auto", 1: "thunk", 2: "named"}[kind],
                    name=fn.getName(),
                )
            )


def _report():
    fns = _all_functions()
    named = sum(1 for fn in fns if _fn_kind(fn) == "named")
    auto = sum(1 for fn in fns if _fn_kind(fn) == "auto")
    thunk = sum(1 for fn in fns if _fn_kind(fn) == "thunk")
    exports = _exports()
    epoints = _entry_point_fns()
    seeds = exports + epoints
    depth = _bfs_depth(seeds)
    reachable = sum(1 for fn in fns if fn.getEntryPoint() in depth)
    print(
        json.dumps(
            {
                "program": currentProgram.getName(),  # noqa: F821
                "total": len(fns),
                "named": named,
                "auto": auto,
                "thunk": thunk,
                "exports": len(exports),
                "entry_points": len(epoints),
                "reachable_from_seeds": reachable,
                "orphans": len(fns) - reachable,
            }
        )
    )


def main():
    args = list(getScriptArgs() or [])  # noqa: F821
    if not args:
        print("usage: annotate-walk.py <worklist|unnamed|report> [out_path]")
        sys.exit(2)
    mode = args[0]
    if mode == "report":
        _report()
        return
    if len(args) < 2:
        print("usage: annotate-walk.py %s <out_path>" % mode)
        sys.exit(2)
    out_path = args[1]
    rows = _sorted_worklist(only_unnamed=(mode == "unnamed"))
    _write_worklist(out_path, rows)
    print(
        "wrote {n} addresses to {p}".format(n=len(rows), p=out_path)
    )


main()
