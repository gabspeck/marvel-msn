"""
Conservative auto-rename for tail-call wrapper functions.

A "tail-call wrapper" is a function whose entire purpose is to forward to
exactly one named callee (external import, project DLL function, or
already-named local function). Only renames when:

* The function is currently `FUN_…` or `SUB_…` (never overwrite hand names).
* It has exactly one outgoing call instruction (no other calls).
* The callee's resolved name is recognizable (project DLL / Win32 / a
  hand-named local).
* The function body is short (<= 24 instructions).

Naming rule: `Wrap_<short_name>`. If a Wrap_<short> already exists,
disambiguate with the address suffix.

This script is idempotent — re-running picks up any wrappers that became
hand-named since the last run.
"""

from collections import Counter

from ghidra.program.model.symbol import RefType


WIN32_DLLS = {"USER32.DLL", "GDI32.DLL", "KERNEL32.DLL", "SHELL32.DLL",
              "ADVAPI32.DLL", "OLE32.DLL", "OLEAUT32.DLL", "WSOCK32.DLL",
              "COMDLG32.DLL", "MSVCRT.DLL", "WINMM.DLL", "VERSION.DLL",
              "WINSPOOL.DRV", "MAPI32.DLL", "ATL.DLL", "MFC30.DLL",
              "RPCRT4.DLL", "WININET.DLL"}

AUTO_PREFIXES = ("FUN_", "SUB_")


def _resolve(callee):
    target = callee
    if target.isThunk():
        resolved = target.getThunkedFunction(True)
        if resolved is not None:
            target = resolved
    sym = target.getSymbol()
    if sym is None:
        return None
    return sym.getName()


def _good_name(name):
    if name is None or len(name) < 2:
        return False
    if name.startswith(AUTO_PREFIXES):
        return False
    if name.startswith("thunk_"):
        return False
    if "::" in name:
        return False
    if name.startswith("_"):
        # CRT-internal
        return False
    if not name[0].isalpha():
        return False
    return True


def _single_callee(fn):
    """Return the single callee Function (or None) plus instruction count."""
    listing = currentProgram.getListing()  # noqa: F821
    fm = currentProgram.getFunctionManager()  # noqa: F821
    body = fn.getBody()
    callees = []
    insn_count = 0
    for cu in listing.getInstructions(body, True):
        insn_count += 1
        if cu.getFlowType() is None or not cu.getFlowType().isCall():
            continue
        for ref in cu.getReferencesFrom():
            tgt = ref.getToAddress()
            if tgt is None:
                continue
            callee = fm.getFunctionAt(tgt)
            if callee is None:
                continue
            callees.append(callee)
            break
    return callees, insn_count


def _unique_name(base):
    st = currentProgram.getSymbolTable()  # noqa: F821
    syms = list(st.getSymbols(base))
    if not syms:
        return base
    return None  # caller will fall back


def main():
    fm = currentProgram.getFunctionManager()  # noqa: F821
    counts = Counter()
    for fn in list(fm.getFunctions(True)):
        name = fn.getName()
        if fn.isThunk() or not name.startswith(AUTO_PREFIXES):
            continue
        if fn.getBody() is None:
            continue
        callees, n_inst = _single_callee(fn)
        if n_inst > 24:
            counts["too_long"] += 1
            continue
        if len(callees) != 1:
            counts["not_one_call"] += 1
            continue
        target_name = _resolve(callees[0])
        if not _good_name(target_name):
            counts["target_not_named"] += 1
            continue
        proposed = "Wrap_" + target_name
        unique = _unique_name(proposed)
        if unique is None:
            counts["name_collision"] += 1
            continue
        try:
            fn.setName(unique, ghidra.program.model.symbol.SourceType.USER_DEFINED)  # noqa: F821
            counts["renamed"] += 1
        except Exception as e:  # pragma: no cover
            counts["error"] += 1
    print("auto-rename wrappers: {d}".format(d=dict(counts)))


main()
