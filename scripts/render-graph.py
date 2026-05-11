"""
Render-pipeline call-graph emitter.

Run via the ghidra-headless MCP `ghidra_script` tool against the MOSVIEW.EXE
session. Produces a Graphviz DOT file capturing the call graph from the
host-side render entry points (MosViewMain, OpenMediaTitleSession,
NavigateViewerSelection) outward, walking through every linked DLL session
the caller has loaded.

Inputs
------
* `script_args[0]` -- output DOT path
* `script_args[1:]` -- optional extra session IDs to walk (in addition to
  the active program). Each is a sibling-program session_id from
  ghidra_call("project.list_sessions").

Algorithm
---------
1. Start a worklist seeded with each program's render-entry exports plus
   `entry`.
2. BFS over `getCalledFunctions`. Cross-program edges are identified via
   externally-resolved imports: the callee's symbol matches a `<SIBLING>::*`
   entry, look it up in the matching session, recurse there.
3. Emit nodes per (program, address); edges per call. Nodes carry the
   function's chosen name (or FUN_XXXX), the program filename, and a
   confidence colour (named=blue, auto=red, thunk=grey).

Usage from a Claude session
---------------------------
After Tiers 0+1 are annotated, open MOSVIEW.EXE + MVCL14N + MMVDIB12 +
MVTTL14C + MOSCOMP via project_program_open_existing, then call
ghidra_script with this file passing all the session_ids. The script
streams a single DOT graph spanning all of them.

Status
------
Skeleton. The cross-program traversal requires shared session-table
access that the headless harness exposes only via direct
program_list_open. The full implementation lands in the
`render-graph` close-out task (#11).
"""

import sys


def main():
    args = list(getScriptArgs() or [])  # noqa: F821
    if not args:
        print("usage: render-graph.py <out.dot> [session_id ...]")
        sys.exit(2)
    print("render-graph.py: skeleton -- full implementation pending.")


main()
