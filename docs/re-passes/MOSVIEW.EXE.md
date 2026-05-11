# MOSVIEW.EXE — total-decomp coverage

Image base `0x7F3C0000`. PE GUI EXE, ~54 KiB. App #6 (`Media_Viewer`).

## Function inventory (170 total)

- 31 named at session start (verb handlers, public exports, structural helpers).
- 84 auto-named functions resolved during this pass.
- 55 thunks to project DLLs and Win32 imports, all named.
- 0 `FUN_*`, `SUB_*`, or `thunk_FUN_*` symbols remain.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Bulk plate | 150 plates emitted (87 auto + 9 named-no-plate + 54 thunks). 20 hand plates preserved. |
| Deep line comments | 933 call-site PRE comments + 80 string-ref EOL comments across 115 functions. |
| Hand-renamed | All 84 starting `FUN_*` entries now have project or CRT names. Final six closed: `__heap_alloc_region`, `__heap_extend_region`, `__heap_release_region`, `__heap_add_committed_range`, `__heap_link_block_descriptor`, `__heap_locate_block`. |

## Render-path call chain

```
entry (CRT)
└── MosViewMain (0x7f3c1053)
    ├── FGetCmdLineInfo (MCM)
    ├── single-instance probe via WM_USER 0x414 (replied 0x456734AF)
    ├── CreateMosViewShellWindow (0x7f3c1805)
    │   ├── MosViewInit (0x7f3c2183, exported)
    │   └── RegisterClassA "MosMediaViewShell" with MosViewShellWindowProc
    ├── CreateMediaViewWindow (0x7f3c4f26, exported)
    │   ├── cached-session lookup
    │   └── OpenMediaTitleSession (0x7f3c61ce) when miss
    │       ├── MosViewStartConnection (0x7f3c4504, exported)
    │       ├── MVCL14N!hMVTitleOpen
    │       ├── MVCL14N!lpMVNew
    │       ├── MVCL14N!MVSetKerningBoundary(0x24)
    │       ├── MVCL14N!lMVTitleGetInfo (0x6f, 0x69, 0x07, 0x08, 0x06, 0x04, 0x01, 0x02)
    │       └── MVCL14N!hMVSetFontTable / MVSetFileSystem
    ├── HandleMediaTitleCommand (0x7f3c5150)  — verb dispatch (JumpID, PopupID, etc.)
    └── MosViewTerminate (0x7f3c219d, exported)
```

Window-proc layer:
```
MosViewShellWindowProc (0x7f3c191c)
├── WM_PAINT  — loading splash via LoadStringA(id=12) + DrawTextA
├── WM_CREATE — MosViewAlloc(1) → SetWindowLongA(GWLP_USERDATA)
├── WM_DESTROY — relay to top child + WinHelpA(close) + PostQuitMessage
├── WM_ACTIVATE — relay 0x412 to child
├── WM_ERASEBKGND — fills with sys-color or child's 0x403 reply color
├── WM_CLOSE — relay to child + DefWindowProcA
├── WM_COMMAND
│   ├── 0x66 → MOSX_HrCreateCCFromAppidDeid(1) (CCAPI menu open)
│   ├── 0x67 → WM_CLOSE
│   ├── 0x68 → relay 0x404 to child (back)
│   ├── 0x69 → WinHelpA(MSN.HLP, kind=11)
│   ├── 0x6a → title-info MessageBox (4-string template)
│   └── 0x6b → MosAbout
├── 0x113 → PostQuitMessage(0)
├── 0x30f / 0x311 — drag-target relay to active child
├── 0x402 → AppendMenu Previous/Next + DrawMenuBar
├── 0x407 → EnableMenuItem(Back) + DrawMenuBar
└── 0x414 → liveness probe; ShowWindow + BringWindowToTop + SetForegroundWindow → return 0x456734AF
```

Session teardown:
```
CloseMosViewSession (0x7f3c34fb)
├── MVCL14N!hMVGetTitle
├── MVCL14N!MVTitlePreNotify(op=0xc, payload {kind=2, seq, state})
├── MOSCOMP!ProgClose
├── MosViewFree(cached metadata)
├── AssociateMosViewChildHwnd(NULL)  (0x7f3c34cc)
└── DestroyMosViewerInstance (0x7f3c2261)
    ├── fMVGetHotspotCallback(NULL out)
    ├── MVCL14N!hMVGetTitle
    ├── MVTitleCloseIfLastRef (0x7f3c2239)
    └── MVCL14N!MVDelete
```

## Per-function status

Every function is documented in two places:

1. The PLATE comment at its entry address — signature, callers/callees,
   resolved Win32/project import set, string-ref count + samples.
2. The Ghidra symbol table — every function has a chosen name.

Renamed functions carry hand-written or bulk-derived plates. Each non-thunk
function additionally has PRE comments at call sites identifying resolved
imports or local callees and EOL comments at defined-string references. The
close-out pass rewrote stale `FUN_*` / `PTR_FUN_*` comment text across MOSVIEW
to the current function names or address-based function-pointer-table wording.

Worklist file: `scratch/annotate-worklist/MOSVIEW.EXE.txt`
Progress: `scratch/annotate-progress/MOSVIEW.EXE.json`

## Imports surface

External libraries reached: USER32 (60+ APIs), GDI32 (10+),
KERNEL32 (40+), MCM, MVCL14N, MMVDIB12, MOSCOMP, CCAPI.

## Exports

| Export | Address | Status |
|--------|---------|--------|
| `CreateMediaViewWindow` | `0x7F3C4F26` | named, plated |
| `MosViewInit` | `0x7F3C2183` | named, plated |
| `MosViewStartConnection` | `0x7F3C4504` | named, plated |
| `MosViewTerminate` | `0x7F3C219D` | named, plated |

## Deep-dives

- [`MOSVIEW-STARTUP.md`](MOSVIEW-STARTUP.md) — DID-launch path from PE
  entry to first frame, branch-by-branch with error-exit
  enumeration and cross-binary call boundary table.
