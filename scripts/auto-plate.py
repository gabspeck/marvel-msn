"""
Bulk plate-comment generator for the MOSVIEW total-decomp pass.

Every function in `currentProgram` receives a plate comment if it does not
already have one:

* **Named function, no plate**     -> "Goal: <name> (named earlier — no plate
                                       on file). Body shape: <calls leaf
                                       Win32/import family>."
* **Thunk (`thunk_FUN_…`)**        -> "Thunk -> <thunked_function_name>" plus
                                       a one-line role hint when the thunked
                                       symbol's namespace is a known Win32 or
                                       project DLL.
* **Auto FUN_…/SUB_…**             -> structural snapshot:
                                         signature, callers count, callees
                                         count, distinct Win32 / project
                                         imports it touches, count of UTF-16
                                         and ASCII string refs. Marked
                                         `Notes: bulk-plated, awaiting deep
                                         annotation.` so the manual pass
                                         knows to overwrite.

Run via `ghidra_script` against an open writable session. One transaction is
opened around the whole walk.

Args
----
* `script_args[0]` -- "all" (default), "auto", "thunks", or "named".
                     Selects which families get plates this run.

This script DOES mutate the program. Always re-run after a fresh analysis
pass; existing non-empty plates are preserved.
"""

import sys
from collections import Counter

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType, SymbolType


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
              "COMDLG32.DLL", "MFC*", "MSVCRT.DLL", "WINMM.DLL", "VERSION.DLL",
              "WINSPOOL.DRV", "MAPI32.DLL", "ATL.DLL", "MFC30.DLL",
              "RPCRT4.DLL", "WININET.DLL"}


def _import_origin(callee):
    """Return ('win32'|'project'|'crt'|'unknown', dll, short_name) for an external.

    Follows thunks recursively so a local `thunk_FUN_xxxx -> USER32::Foo`
    still reports as ('win32', 'USER32.DLL', 'Foo').
    """
    target = callee
    if target.isThunk():
        resolved = target.getThunkedFunction(True)
        if resolved is not None:
            target = resolved
    if not target.isExternal():
        return None
    sym = target.getSymbol()
    if sym is None:
        return None
    parent = sym.getParentNamespace()
    dll = parent.getName().upper() if parent is not None else ""
    short = sym.getName()
    if dll in WIN32_DLLS or dll.startswith("MFC"):
        return ("win32", dll, short)
    if dll in PROJECT_DLLS:
        return ("project", dll, short)
    if dll == "MSVCRT.DLL" or short.startswith("_") and "@" in short:
        return ("crt", dll, short)
    return ("unknown", dll, short)


def _existing_plate(fn):
    cu = currentProgram.getListing().getCodeUnitAt(fn.getEntryPoint())  # noqa: F821
    if cu is None:
        return None
    txt = cu.getComment(CodeUnit.PLATE_COMMENT)
    return txt or None


def _set_plate(fn, body):
    cu = currentProgram.getListing().getCodeUnitAt(fn.getEntryPoint())  # noqa: F821
    if cu is None:
        return False
    cu.setComment(CodeUnit.PLATE_COMMENT, body)
    return True


def _classify(fn):
    if fn.isThunk():
        return "thunk"
    name = fn.getName()
    if name.startswith("FUN_") or name.startswith("SUB_"):
        return "auto"
    return "named"


def _string_refs(fn):
    """Return (utf16_count, ascii_count, sample_text)."""
    listing = currentProgram.getListing()  # noqa: F821
    body = fn.getBody()
    refmgr = currentProgram.getReferenceManager()  # noqa: F821
    utf16 = 0
    ascii_n = 0
    samples = []
    for ref in refmgr.getReferenceIterator(body.getMinAddress()):
        if not body.contains(ref.getFromAddress()):
            break
        if ref.getReferenceType() != RefType.READ and ref.getReferenceType() != RefType.DATA:
            continue
        target = ref.getToAddress()
        data = listing.getDataAt(target)
        if data is None:
            continue
        dt = data.getDataType().getName().lower()
        if "unicode" in dt or "wchar" in dt:
            utf16 += 1
            if len(samples) < 3:
                v = data.getValue()
                if v is not None:
                    samples.append(str(v))
        elif "string" in dt or dt in ("char[]",) or dt.startswith("char"):
            ascii_n += 1
            if len(samples) < 3:
                v = data.getValue()
                if v is not None:
                    samples.append(str(v))
    return utf16, ascii_n, samples


def _imports_touched(fn):
    """Counter of import labels (Win32 / project) reached."""
    bag = Counter()
    for callee in fn.getCalledFunctions(monitor):  # noqa: F821
        info = _import_origin(callee)
        if info is None:
            continue
        kind, dll, short = info
        bag["{kind}:{dll}::{short}".format(kind=kind, dll=dll, short=short)] += 1
    return bag


def _build_thunk_plate(fn):
    target = fn.getThunkedFunction(True)
    if target is None:
        return "Thunk -> (unresolved)"
    info = _import_origin(target)
    if info is None:
        return "Thunk -> {n}".format(n=target.getName())
    kind, dll, short = info
    return "Thunk -> {dll}::{short}\nKind: {kind}".format(
        dll=dll, short=short, kind=kind
    )


def _build_named_plate(fn):
    """Plate for an already-named function that doesn't have one."""
    sig = fn.getSignature(True).getPrototypeString(True)
    callers = sum(1 for _ in fn.getCallingFunctions(monitor))  # noqa: F821
    bag = _imports_touched(fn)
    win32 = sorted({k.split("::", 1)[1] for k in bag if k.startswith("win32:")})
    project = sorted({k.split("::", 1)[1] for k in bag if k.startswith("project:")})
    utf16, ascii_n, samples = _string_refs(fn)
    lines = []
    lines.append("Goal: {n} (named in earlier RE pass; auto-plated by total-decomp sweep).".format(
        n=fn.getName()
    ))
    lines.append("Sig: {s}".format(s=sig))
    lines.append("Callers: {c}".format(c=callers))
    if win32:
        lines.append("Win32: {x}".format(x=", ".join(win32[:8])))
    if project:
        lines.append("Project: {x}".format(x=", ".join(project[:8])))
    if utf16 or ascii_n:
        lines.append("Strings: {u} UTF-16, {a} ASCII".format(u=utf16, a=ascii_n))
        if samples:
            preview = "; ".join(s[:48] for s in samples)
            lines.append("Sample: {p}".format(p=preview))
    lines.append("Notes: auto-plate; deepen during render-pipeline pass.")
    return "\n".join(lines)


def _build_auto_plate(fn):
    sig = fn.getSignature(True).getPrototypeString(True)
    callers = sum(1 for _ in fn.getCallingFunctions(monitor))  # noqa: F821
    callees = sum(1 for _ in fn.getCalledFunctions(monitor))  # noqa: F821
    bag = _imports_touched(fn)
    win32 = sorted({k.split("::", 1)[1] for k in bag if k.startswith("win32:")})
    project = sorted({k.split("::", 1)[1] for k in bag if k.startswith("project:")})
    utf16, ascii_n, samples = _string_refs(fn)
    lines = []
    lines.append("Goal: unresolved (bulk-plated; FUN_/SUB_ awaiting hand annotation).")
    lines.append("Sig: {s}".format(s=sig))
    lines.append("Callers: {ci}, Callees: {co}".format(ci=callers, co=callees))
    if win32:
        lines.append("Win32: {x}".format(x=", ".join(win32[:8])))
    if project:
        lines.append("Project: {x}".format(x=", ".join(project[:8])))
    if utf16 or ascii_n:
        lines.append("Strings: {u} UTF-16, {a} ASCII".format(u=utf16, a=ascii_n))
        if samples:
            preview = "; ".join(s[:48] for s in samples)
            lines.append("Sample: {p}".format(p=preview))
    lines.append("Notes: bulk-plated, awaiting deep annotation.")
    return "\n".join(lines)


BULK_PLATE_MARKERS = (
    "Notes: bulk-plated, awaiting deep annotation.",
    "Notes: auto-plate; deepen during render-pipeline pass.",
    "Thunk -> ",  # any auto-emitted thunk plate
)


def _is_bulk_plate(text):
    if text is None:
        return False
    for m in BULK_PLATE_MARKERS:
        if m in text:
            return True
    return False


def main():
    args = list(getScriptArgs() or [])  # noqa: F821
    mode = args[0] if args else "all"
    force_refresh = "force" in args[1:]
    fm = currentProgram.getFunctionManager()  # noqa: F821
    counts = Counter()
    skipped_existing = 0
    refreshed = 0
    for fn in fm.getFunctions(True):
        kind = _classify(fn)
        if mode != "all" and mode != kind + "s" and mode != kind:
            counts["skipped_mode"] += 1
            continue
        existing = _existing_plate(fn)
        if existing:
            if force_refresh and _is_bulk_plate(existing):
                refreshed += 1
            else:
                skipped_existing += 1
                continue
        if kind == "thunk":
            body = _build_thunk_plate(fn)
        elif kind == "named":
            body = _build_named_plate(fn)
        else:
            body = _build_auto_plate(fn)
        if _set_plate(fn, body):
            counts[kind] += 1
        else:
            counts["failed"] += 1
    print(
        "auto-plated: {d}; refreshed bulk-plates: {r}; preserved hand plates: {n}".format(
            d=dict(counts), r=refreshed, n=skipped_existing
        )
    )


main()
