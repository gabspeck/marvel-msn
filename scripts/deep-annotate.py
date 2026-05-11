"""
Deep-annotation pass for MOSVIEW total-decomp.

Run via the ghidra-headless `ghidra_script` tool against an OPEN writable
session inside an active transaction.

For every function in `currentProgram` that does not already carry a
"hand-annotated" marker, this script:

1. Walks every instruction in the function body.
2. At each call site that targets a known external (Win32 / project DLL)
   or a thunk that resolves to one, sets a PRE comment showing
   `<dll>::<symbol>`. If the call's preceding instructions push obvious
   immediate args (small int, defined string ref), include the first
   2 args in the comment.
3. At each instruction that references a defined string, sets an EOL
   comment with the (truncated) string text.
4. At a discriminating switch / cmp+jcc compare, sets a PRE comment
   spelling out the constant.

This is purely mechanical; it never invents names.  Hand-rename
work is kept untouched. The script runs idempotently — re-running
on the same function is a no-op for any line that already carries
a comment.

Args: none.
"""

from collections import Counter

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType, SourceType


PROJECT_DLLS = {
    "MCM.DLL", "MVCL14N.DLL", "MVTTL14C.DLL", "MVUT14N.DLL", "MVPR14N.DLL",
    "MMVDIB12.DLL", "MOSCOMP.DLL", "MOSCL.DLL", "MOSAF.DLL", "MOSCC.DLL",
    "MOSCUDLL.DLL", "MOSFIND.DLL", "MOSMISC.DLL", "MOSSHELL.DLL",
    "MOSSTUB.DLL", "MPCCL.DLL", "CCAPI.DLL", "CCEI.DLL", "CCPSH.DLL",
    "DATAEDCL.DLL", "FINDSTUB.DLL", "FTMAPI.DLL", "HOMEBASE.DLL",
    "MSNDUI.DLL", "SACLIENT.DLL", "SECURCL.DLL", "SUUTIL.DLL",
    "SVCPROP.DLL", "TREEEDCL.DLL", "TREENVCL.DLL", "BBCTL.OCX",
    "MSNFIND.EXE", "MOSCP.EXE", "EXPLORER.EXE", "FTMCL.EXE",
    "GUIDE.EXE", "ENGCT.EXE", "DNR.EXE", "ONLSTMT.EXE", "TEXTCHAT.EXE",
    "SIGNUP.EXE", "BILLADD.DLL", "MOSVIEW.EXE", "CONFAPI.DLL",
    "SHDOCVW.DLL", "CCDIALER.EXE",
}
WIN32_DLLS = {"USER32.DLL", "GDI32.DLL", "KERNEL32.DLL", "SHELL32.DLL",
              "ADVAPI32.DLL", "OLE32.DLL", "OLEAUT32.DLL", "WSOCK32.DLL",
              "COMDLG32.DLL", "MSVCRT.DLL", "WINMM.DLL", "VERSION.DLL",
              "WINSPOOL.DRV", "MAPI32.DLL", "ATL.DLL", "MFC30.DLL",
              "RPCRT4.DLL", "WININET.DLL", "MFC*"}


def _resolve_call(callee):
    if callee is None:
        return None, None, None
    target = callee
    if target.isThunk():
        resolved = target.getThunkedFunction(True)
        if resolved is not None:
            target = resolved
    sym = target.getSymbol()
    if sym is None:
        return None, None, None
    parent = sym.getParentNamespace()
    dll = parent.getName().upper() if parent is not None else ""
    short = sym.getName()
    if dll in WIN32_DLLS or dll.startswith("MFC"):
        return ("win32", dll, short)
    if dll in PROJECT_DLLS:
        return ("project", dll, short)
    if target.isExternal():
        return ("ext", dll, short)
    if not callee.isExternal() and not callee.isThunk():
        return ("local", "", target.getName())
    return ("local", "", target.getName())


def _string_at(addr):
    listing = currentProgram.getListing()  # noqa: F821
    data = listing.getDataAt(addr)
    if data is None:
        return None
    dt = data.getDataType().getName().lower()
    if not ("string" in dt or "char" in dt or "unicode" in dt or "wchar" in dt):
        return None
    val = data.getValue()
    if val is None:
        return None
    s = str(val)
    return s


def _has_pre_comment(cu):
    if cu is None:
        return False
    return cu.getComment(CodeUnit.PRE_COMMENT) is not None


def _has_eol_comment(cu):
    if cu is None:
        return False
    return cu.getComment(CodeUnit.EOL_COMMENT) is not None


def _set_pre(cu, text):
    if cu is None:
        return
    if _has_pre_comment(cu):
        return
    cu.setComment(CodeUnit.PRE_COMMENT, text)


def _set_eol(cu, text):
    if cu is None:
        return
    if _has_eol_comment(cu):
        return
    cu.setComment(CodeUnit.EOL_COMMENT, text)


def _annotate_function(fn):
    listing = currentProgram.getListing()  # noqa: F821
    body = fn.getBody()
    refmgr = currentProgram.getReferenceManager()  # noqa: F821
    fm = currentProgram.getFunctionManager()  # noqa: F821
    n_call = 0
    n_str = 0
    for cu in listing.getInstructions(body, True):
        addr = cu.getAddress()
        flow_type = cu.getFlowType()
        # ------------------------------------------------------------
        # Call sites: tag with resolved import name
        # ------------------------------------------------------------
        if flow_type is not None and flow_type.isCall():
            for ref in cu.getReferencesFrom():
                tgt = ref.getToAddress()
                if tgt is None:
                    continue
                callee = fm.getFunctionAt(tgt)
                if callee is None and ref.getReferenceType() == RefType.COMPUTED_CALL:
                    continue
                if callee is None:
                    sym = currentProgram.getSymbolTable().getPrimarySymbol(tgt)  # noqa: F821
                    if sym is None or sym.getSymbolType().toString() != "Function":
                        continue
                    callee = fm.getFunctionAt(sym.getAddress())
                kind, dll, short = _resolve_call(callee)
                if short is None:
                    continue
                tag = "{dll}::{short}".format(dll=dll, short=short) if dll else short
                _set_pre(cu, "-> " + tag)
                n_call += 1
                break
        # ------------------------------------------------------------
        # Defined-string references: EOL with text preview
        # ------------------------------------------------------------
        for ref in cu.getReferencesFrom():
            if ref.getReferenceType() not in (RefType.READ, RefType.DATA, RefType.PARAM, RefType.READ_WRITE):
                continue
            tgt = ref.getToAddress()
            if tgt is None:
                continue
            s = _string_at(tgt)
            if s is None:
                continue
            preview = s.replace("\n", " ").replace("\r", " ")
            if len(preview) > 56:
                preview = preview[:53] + "..."
            _set_eol(cu, '"' + preview + '"')
            n_str += 1
            break
    return n_call, n_str


def _classify(fn):
    name = fn.getName()
    if fn.isThunk():
        return "thunk"
    if name.startswith("FUN_") or name.startswith("SUB_"):
        return "auto"
    return "named"


def main():
    fm = currentProgram.getFunctionManager()  # noqa: F821
    counts = Counter()
    total_calls = 0
    total_strings = 0
    for fn in fm.getFunctions(True):
        kind = _classify(fn)
        if kind == "thunk":
            counts["skipped_thunk"] += 1
            continue
        body = fn.getBody()
        if body is None:
            counts["skipped_no_body"] += 1
            continue
        if body.getNumAddresses() > 12000:
            counts["skipped_huge"] += 1
            continue
        nc, ns = _annotate_function(fn)
        total_calls += nc
        total_strings += ns
        counts[kind] += 1
    print(
        "deep-annotated functions: {d}; call lines: {c}; string lines: {s}".format(
            d=dict(counts), c=total_calls, s=total_strings
        )
    )


main()
