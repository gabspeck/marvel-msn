# MOSVIEW.EXE — DID-launch startup deep-dive

End-to-end enumeration of the **DID-launch** path
(`MOSVIEW.EXE -MOS:6:<deid_lo>:<deid_hi>:<tail>`) from the PE entry to the
first `BitBlt` / `PlayMetaFile`. Static analysis only; references to
`docs/MOSVIEW.md` / `docs/MOSVIEW-RENDER-PIPELINE.md` / `docs/MEDVIEW.md`
for narrative summaries, this doc for branch-by-branch detail.

Image base `0x7F3C0000` (project base; PE header `0x7F390000`).
Engine binaries reach through MVCL14N (`0x7E88xxxx`–`0x7E89xxxx`),
MVTTL14C (`0x7E84xxxx`), MMVDIB12 (`0x7F4Fxxxx`).

Out of scope: raw `MOSVIEW.EXE <titlePath>` fallback (covered by
`docs/MOSVIEW.md §3.2`), single-instance re-route, in-document verbs
(`JumpID`/`PopupID`/`PaneID` — `docs/MOSVIEW.md §8`), teardown
(`CloseMosViewSession`, `MosViewTerminate` — `docs/MOSVIEW-RENDER-PIPELINE.md §7`).

---

## 1. Scope and entry contract

The user clicks a MOSSHELL item whose `c` property is `6`. The MCM
dispatcher resolves it through `HRMOSExec(6, args)`
(`project_mcm_hrmosexec`) and spawns:

```
CreateProcessA(NULL,
  "MOSVIEW.EXE -MOS:6:<deid_lo_hex>:<deid_hi_hex>:<raw_tail>",
  ...)
```

The child reads the tail back via `MCM!FGetCmdLineInfo` rather than
re-parsing argv; that is the DID contract. On this path the deid pair
is the user-clicked node's id; `<raw_tail>` may be empty or an
`initialSelector` (typically empty on first jump from MSN Today / icon
dispatch).

MOSVIEW exits when one of the slot owners answers the single-instance
probe, when title open fails, when the `MEDIATIMEOUT` watchdog fires,
or normally when the message pump returns `WM_QUIT`.

---

## 2. Code-path map (DID branch only)

```
PE entry → CRT scaffold (mainCRTStartup → _setargv → _setenvp → __mtinit
                          → __ioinit → __setmbcp_apply → __initmbcp)
└─ MosViewMain (0x7F3C1053)
   ├─ FGetCmdLineInfo (MCM thunk @ 0x7F3C767E)
   │     writes:  DAT_7f3cd040=appid, DAT_7f3cd048=deid_lo,
   │              DAT_7f3cd04c=deid_hi, DAT_7f3cd054=raw_tail
   ├─ deid_hi != 0 → wsprintfA "%X%8X" → titleIdBuffer  [LAB_7f3c1128]
   │  deid_hi == 0 && deid_lo != 0 → wsprintfA "%X" → titleIdBuffer
   │  both zero && tail empty → MosErrorP(0,hInst,3,4,0); return 0
   ├─ SetThreadPriority(GetCurrentThread, THREAD_PRIORITY_HIGHEST=2)
   ├─ GetEnvironmentVariableA("MEDIAMULTI", buf, 0x28)
   │  set → DAT_7f3cd03c=0 (single-instance disabled)
   │  unset → DAT_7f3cd03c=1
   │     ├─ CreateSemaphoreA("Mosview Single Instance Semaphore")
   │     ├─ WaitForSingleObject(sem, 30000)
   │     ├─ CreateFileMappingA(INVALID_HANDLE,_,PAGE_READWRITE,0,0x644,
   │     │                     "Mosview Single Instance Segment")
   │     ├─ MapViewOfFile(map, FILE_MAP_WRITE, 0,0,0)
   │     ├─ GetLastError == ERROR_ALREADY_EXISTS (0xB7):
   │     │   enumerate up to count slots {hwnd, _, deid_lo, deid_hi}
   │     │   stride 0x10; on (deid_lo,deid_hi) match call
   │     │     SendMessageA(slot.hwnd, 0x414, 1, 0)
   │     │     == 0x456734AF → owner alive (bVar3=true)
   │     │ else (first to create mapping):
   │     │   zero 0x191 dwords; *count = 100
   │     ├─ ReleaseSemaphore(sem,1,NULL)
   │     └─ if owner alive: UnmapViewOfFile + CloseHandle×2 → return 1
   ├─ CreateMosViewShellWindow (0x7F3C1805)
   │  ├─ LoadIconA(hInst, 7)                → DAT_7f3cd030
   │  ├─ LoadAcceleratorsA(hInst, 8)        → DAT_7f3cd02c
   │  ├─ MosViewInit (0x7F3C2183, exported)
   │  │  ├─ MVCL14N!MVSetInstance(DAT_7f3cd038)
   │  │  └─ InitializeMosViewUi (0x7F3C5D29)
   │  │     ├─ GetSystemMetrics(SM_CXSCREEN) → _DAT_7f3cd2f4
   │  │     ├─ GetSystemMetrics(SM_CYSCREEN) → _DAT_7f3cd2f8
   │  │     ├─ InitializeCriticalSection(&DAT_7f3cbca0)
   │  │     ├─ LoadCursorA(NULL, IDC_ARROW=0x7F00) → DAT_7f3cd2e4
   │  │     ├─ MMVDIB12!InitiateMVDIB
   │  │     ├─ RegisterClassA(MosViewContainer @ 0x7F3C474B,
   │  │     │                 cbWndExtra=4)
   │  │     └─ RegisterClassA(MosChildView pane @ 0x7F3C2301)
   │  ├─ LoadStringA(hInst, 1, DAT_7f3ca450, 0x50)  (class-name)
   │  ├─ LoadStringA(hInst, 2, DAT_7f3cbc78, 0x28)  (window-caption)
   │  ├─ LoadCursorA(NULL, IDC_ARROW)
   │  ├─ RegisterClassA("MosMediaViewShell" → MosViewShellWindowProc)
   │  ├─ CreateWindowExA(0, "MosMediaViewShell", caption,
   │  │       0x02CF0000 = WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
   │  │       4× CW_USEDEFAULT, parent=NULL, menu=NULL, hInst, NULL)
   │  └─ if NULL → MosErrorP(0,hInst,5,6,0); return 0
   ├─ GetMenu + EnableMenuItem(menu, 0x66, MF_GRAYED) + DrawMenuBar
   │  (disable "Open my MSN" entry while host is loading)
   ├─ GetEnvironmentVariableA("MEDIATIMEOUT", buf, 0x28)
   │  set → ParseSignedDecimalString(buf) → ms
   │  ms == 0 → ms = 40000
   │  SetTimer(host, 1, ms, NULL)            (WM_TIMER 0x113 watchdog)
   ├─ slot claim under semaphore (writes hwnd=0xFFFFFFFF placeholder
   │  + deid pair into first free or matching slot)
   ├─ CreateMediaViewWindow(DAT_7f3cd054, DAT_7f3cd058, DAT_7f3cd028)
   │  ↓ (§G–§I)
   ├─ slot finalise: replace 0xFFFFFFFF with the live hwnd
   ├─ message pump: GetMessageA / TranslateAcceleratorA(haccel)
   │                / TranslateMessage / DispatchMessageA
   ├─ on CreateMediaViewWindow == 0 && DAT_7f3cd2ec != 0x407:
   │     wsprintfA into DAT_7f3cb4a8 ("The title… Appid=%d deid=%X%8X")
   │     SendMedViewStatusMessage(1, DAT_7f3cb4a8)   (synthetic
   │       :%d service title via PreNotify)
   │     MosErrorP(GetActiveWindow(), hInst, 1, 9, 0)
   ├─ KillTimer(host, 1); ShowWindow(host, SW_HIDE)
   ├─ release slot (zero deid pair under semaphore)
   ├─ CloseHandle(mapping); CloseHandle(semaphore)
   └─ MosViewTerminate
```

`MosErrorP` resolves to MCM's `0x191` dialog through the `MosErrorInfo`
struct (`project_moserror_info_struct`).

---

## 3. Per-section deep-dive

### A. CRT scaffold (entry → MosViewMain)

PE entry runs the MSVC 1.x CRT (`__amsg_exit @ 0x7F3C7A15`,
`__local_unwind2 @ 0x7F3C7A8A`, `__chkstk @ 0x7F3C7DEC`,
`_setargv @ 0x7F3C8263`, `_setenvp @ 0x7F3C8198`,
`__crt0_parse_cmdline @ 0x7F3C82F9`, `__initmbcp @ 0x7F3C8746`,
`__mtinit @ 0x7F3C8843`, `__ioinit @ 0x7F3C8751`,
`_XcptFilter @ 0x7F3C8024`, heap helpers
`_heap_alloc_base @ 0x7F3C8B3C`, `__heap_alloc_region @ 0x7F3C9164`,
…).

CRT entry calls `MosViewMain(hInstance, startupMode, rawCommandLine)`.
`startupMode != 0` is a CRT-side guard (used for second invocations in
DLL/static-lib scenarios) and is **never set** on the DID path; it
exits with `WPARAM=0` immediately.

### B. `MosViewMain` prologue + `FGetCmdLineInfo`  (0x7F3C1053)

Stack frame allocated through `_chkstk`:

| Slot | Use |
|------|-----|
| `mediaMultiEnv[0x28]` | `MEDIAMULTI` env value read by `GetEnvironmentVariableA`. |
| `mediaTimeoutEnv[0x28]` | `MEDIATIMEOUT` env value. |
| `local_70` (`tagMSG`) | Message-pump buffer; `local_70.wParam` is the function return. |
| `titleIdBuffer[24]` | Formatted deid string (`%X` or `%X%8X`); becomes `DAT_7f3cd054` after `LAB_7f3c1128`. |
| `startupTimerId` (`UINT_PTR`) | Watchdog timer id. |
| `createResult` (int) | `CreateMediaViewWindow` return. |
| `instanceMapping`, `instanceTableView`, `instanceSemaphore`, `selectedInstanceSlot` | Single-instance handles. |

`DAT_7f3cd038 = hInstance` is set before any subsystem fires; both
`MosViewInit` (`MVSetInstance`) and `MosViewShellWindowProc` (`LoadStringA`)
depend on it.

`FGetCmdLineInfo` is a thunk at `0x7F3C767E` jumping into MCM. The four
`out` parameters resolve to MOSVIEW globals at `0x7F3CD040`,
`0x7F3CD048`, `0x7F3CD050`, `0x7F3CD054`. Effective reads downstream:

| Global | Source | Use |
|--------|--------|-----|
| `DAT_7f3cd040` | appid from `-MOS:6:…` | Logged into status text on failure. |
| `DAT_7f3cd048` | deid_lo (low 32 bits of the 8-byte deid pair at offset `0x48`) | Format input, single-instance key. |
| `DAT_7f3cd04c` | deid_hi (high 32 bits of the same 8-byte pair) | Format input, single-instance key. |
| `DAT_7f3cd054` | raw_tail pointer (into the inherited command buffer) | Becomes either `titlePath` (after format) or the raw fallback. |

When `FGetCmdLineInfo` returns 0 (no `-MOS:` tail), the fallback sets
`appid=6`, clears deids, and treats `rawCommandLine` as the tail
(`docs/MOSVIEW.md §3.2`). The DID path always takes the success branch.

### C. Deid → titlePath normalization

After `FGetCmdLineInfo` succeeds:

| Predicate | Action | Buffer contents |
|-----------|--------|-----------------|
| `deid_hi != 0` | `wsprintfA(titleIdBuffer, "%X%8X", deid_hi, deid_lo)` — fmt @ `0x7F3CD0B4` (`s__X_8X_7f3cd0b4`) | `<hex_hi><hex_lo padded to 8>` |
| `deid_hi == 0 && deid_lo != 0` | `wsprintfA(titleIdBuffer, "%X", deid_lo)` — fmt @ `0x7F3CD0BC` | `<hex_lo>` |
| both zero, tail non-empty | XOR-fold tail bytes into deid pair, split at first space; `titleIdBuffer` unused (raw path, out of scope) | n/a |
| both zero, tail empty | `MosErrorP(0,hInst,3,4,0)`, `return 0` | n/a |

`LAB_7f3c1128` swaps the globals so the next layer reads from
`titleIdBuffer`:

```
DAT_7f3cd058 = DAT_7f3cd054;  // raw tail preserved as initialSelector
DAT_7f3cd054 = titleIdBuffer; // titlePath is the formatted deid
```

`DAT_7f3cd058` is passed to `CreateMediaViewWindow` as
`initialSelector`. On most DID jumps it is empty; `JumpID`-style
follow-ons (`docs/MOSVIEW.md §8`) repurpose it after first paint.

### D. Single-instance gate

Driven by `DAT_7f3cd03c = (GetEnvironmentVariableA("MEDIAMULTI", …) == 0)`.
When set, the whole gate is bypassed. `MEDIAMULTI` is the only env-var
exit from this section.

When `DAT_7f3cd03c=1`:

1. `CreateSemaphoreA(NULL, 1, 1, "Mosview Single Instance Semaphore")`.
   The semaphore is binary, used as a cross-process mutex over the
   mapping below.
2. `WaitForSingleObject(sem, 30000)`. On timeout the whole single-instance
   path is skipped — equivalent to `MEDIAMULTI` for one launch.
3. `CreateFileMappingA(INVALID_HANDLE, NULL, PAGE_READWRITE, 0, 0x644,
   "Mosview Single Instance Segment")`. The mapping is anonymous
   (page-file backed), `0x644 = 100*16 + 4` bytes: one DWORD count
   plus 100 slots × 16 bytes.
4. `MapViewOfFile(map, FILE_MAP_WRITE, 0, 0, 0)` (size 0 → whole
   mapping).
5. **First creator** (`GetLastError() != ERROR_ALREADY_EXISTS`) zeroes
   the `0x191 = 401` dwords (0x644/4) and writes `*count = 100`.
6. **Subsequent creators** enumerate slots:
   ```
   slot[0] = HWND       (0 = empty, 0xFFFFFFFF = placeholder/transient)
   slot[1] = unused / aux
   slot[2] = deid_lo
   slot[3] = deid_hi
   ```
   On (deid_lo, deid_hi) match: probe with
   `SendMessageA(slot.hwnd, 0x414, 1, 0)`. The live shell answers
   `0x456734AF` after `ShowWindow + BringWindowToTop + SetForegroundWindow`
   (`MosViewShellWindowProc` 0x414 handler — `docs/MOSVIEW-RENDER-PIPELINE.md §2`).
   `bVar3 = true` triggers the early-exit teardown
   (`UnmapViewOfFile`, two `CloseHandle`s, return `WPARAM=1`).

Later, after `CreateMosViewShellWindow` has succeeded, the same
semaphore is re-acquired to:

- walk the slot table again with a second-pass `SendMessageA(_,0x414,0,0)`
  cleanup probe — dead slots (reply ≠ `0x456734AF`) are zeroed and
  candidate-selected (`selectedInstanceSlot`);
- either reuse the matching slot (if a previous owner died without
  cleanup) or claim the first free slot, writing the placeholder
  `0xFFFFFFFF` HWND and the current deid pair.

The hwnd is finalised only after `CreateMediaViewWindow` returns
success, so a slot is reserved-but-not-broadcast while title open is
in flight. The 30-second semaphore wait keeps cleanup from blocking
other launchers.

### E. `MEDIATIMEOUT` watchdog

`GetEnvironmentVariableA("MEDIATIMEOUT", mediaTimeoutEnv, 0x28)`. When
set, `ParseSignedDecimalString` (`0x7F3C7B9C`) consumes the buffer; a
`0` result substitutes `40000` ms.

`SetTimer(DAT_7f3cd028, 1, ms, NULL)` arms `WM_TIMER 0x113` on the
shell frame. `MosViewShellWindowProc`'s 0x113 handler
(`docs/MOSVIEW-RENDER-PIPELINE.md §2`) calls `PostQuitMessage(0)`.

The timer is killed (`KillTimer(host, 1)`) once the message pump
exits — the watchdog is only meaningful while the pump is running
the loading splash and waiting for the engine.

### F. Shell-window bootstrap (`CreateMosViewShellWindow @ 0x7F3C1805`)

Sequential resource loads gate the function: any zero return aborts
back to `MosErrorP(0,hInst,5,6,0)`.

```
LoadIconA(hInst, MAKEINTRESOURCE(7))           → DAT_7f3cd030
LoadAcceleratorsA(hInst, MAKEINTRESOURCE(8))   → DAT_7f3cd02c
MosViewInit() != 0
LoadStringA(hInst, 1, DAT_7f3ca450, 0x50)  ("MOSVIEW" class name)
LoadStringA(hInst, 2, DAT_7f3cbc78, 0x28)  ("Online-Viewer" caption)
LoadCursorA(NULL, IDC_ARROW)                — discarded, sets nothing
RegisterClassA(&stack0xffffffd4)
  WNDCLASSA.style       = (composed on stack)
  WNDCLASSA.lpfnWndProc = MosViewShellWindowProc (0x7F3C191C)
  WNDCLASSA.hInstance   = hInstance
  WNDCLASSA.hIcon       = DAT_7f3cd030
  WNDCLASSA.hCursor     = (IDC_ARROW result)
  WNDCLASSA.lpszMenuName= MAKEINTRESOURCE(0x64)   (MENU id 100)
  WNDCLASSA.lpszClassName = "MosMediaViewShell" (`s_MosMediaViewShell_7f3cd238`)
CreateWindowExA(0, "MosMediaViewShell", DAT_7f3ca450,
                0x02CF0000 = WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
                CW_USEDEFAULT×4,
                NULL, NULL, hInst, NULL)        → DAT_7f3cd028
```

`MosViewInit @ 0x7F3C2183` is a 2-call wrapper:

```
MVCL14N!MVSetInstance(DAT_7f3cd038)  — engine learns host HINSTANCE
InitializeMosViewUi (0x7F3C5D29)
```

`InitializeMosViewUi @ 0x7F3C5D29`:

```
_DAT_7f3cd2f4 = GetSystemMetrics(SM_CXSCREEN)
_DAT_7f3cd2f8 = GetSystemMetrics(SM_CYSCREEN)
InitializeCriticalSection(&DAT_7f3cbca0)         (shared MOSVIEW guard)
DAT_7f3cd2e4 = LoadCursorA(NULL, IDC_ARROW)
MMVDIB12!InitiateMVDIB()                          (DIB engine bring-up)
RegisterClassA(MosViewContainer @ 0x7F3C474B, cbWndExtra=4, …)
  != 0 → RegisterClassA(MosChildView pane @ 0x7F3C2301, …)
return both registrations succeeded
```

Failure here cascades: `InitializeMosViewUi` returns 0 →
`MosViewInit` reports failure → `CreateMosViewShellWindow` returns
NULL → `MosViewMain` fires `MosErrorP(0,hInst,5,6,0)` (localized
"cannot start MediaView" / MCM dialog `0x191` via
`MosErrorInfo` body id 6 — `project_moserror_info_struct`).

The two child window classes registered here back the panes that get
created in §G. `MosViewContainer` is the splitter/host that owns the
two `MosChildView` panes (`project_mosview_dual_pane_paint`).

After the frame is created, `MosViewMain` immediately
`EnableMenuItem(menu, 0x66, MF_GRAYED) + DrawMenuBar` — the
"Open my MSN" command is held grey until title open finishes.

### G. `CreateMediaViewWindow @ 0x7F3C4F26` — cache lookup + session

Exported entry. The DID path runs through the **first-launch /
miss** branch because the per-process cache list `DAT_7f3cbcdc` is
empty on first jump.

```
GetDC(NULL)
DAT_7f3cd30c = GetDeviceCaps(hdc, LOGPIXELSX = 0x58)
DAT_7f3cd310 = GetDeviceCaps(hdc, LOGPIXELSY = 0x5A)
ReleaseDC(NULL, hdc)
if (DAT_7f3cd30c > 1000) DAT_7f3cd30c = DAT_7f3cd310 = 0x60      (96 DPI)
if (titlePath == NULL || titlePath[0]==0 || hostWindow==NULL) return 0
BroadcastMedViewShutdown()                                       (§9 ref)
for (iVar6 = DAT_7f3cbcdc; iVar6; iVar6 = *(iVar6+0x1c))
   if (lstrcmpiA(titlePath, *(LPCSTR*)(iVar6+0x24)) == 0
       || *(int*)(iVar6+0x20) == -1) goto hit
// DID first-launch: cache empty, falls through to miss branch
```

**Miss branch (DID path):**

```
puVar3 = MosViewAlloc(0x68 = 104)      → zero-init MosViewSession (§ struct below)
puVar3 = MosViewSession_ctor(puVar3)   (writes vtable + slot)
iVar2  = MosViewSession_AddPaneNode(&DAT_7f3cbcc0, puVar3)  (insert into cache list)
DAT_7f3cd314 += 1                                            (viewSerial++)
iVar4  = OpenMediaTitleSession(titlePath, DAT_7f3cd314, hostWindow)  (§H)
iVar6  = iVar2
if (iVar4 == 0) { MosViewSession_RemovePaneNode; return 0 }
if (*(LPCSTR*)(iVar6+0x58)) SetWindowTextA(hostWindow, *(LPCSTR*)(iVar6+0x58))
```

`*(session+0x58)` is the display-title string copied out of
`info_kind=0x01` by `OpenMediaTitleSession` (§H). When the engine
ships a real `info_kind=1` reply, the host caption updates from the
generic "Online-Viewer" loaded by `CreateMosViewShellWindow` to the
title's authored name.

`MosViewSession` layout (relevant slots only — anchored from
`OpenMediaTitleSession` writes):

| Off | Field |
|-----|-------|
| `+0x1c` | next pointer (linked-list cache). |
| `+0x20` | viewSerial cookie (`-1` marks a session as stale and hit-eligible). |
| `+0x24` | `MosViewAlloc`'d copy of `titlePath`. |
| `+0x30` | `lpMVNew` viewer pointer (MVCL14N opaque). |
| `+0x38` / `+0x3c` | `info_kind=0x07` (43-byte ChildPaneRecord) count + buffer. |
| `+0x40` / `+0x44` | `info_kind=0x08` (31-byte PopupPaneRecord). |
| `+0x48` / `+0x4c` | `info_kind=0x06` (152-byte WindowScaffoldRecord). |
| `+0x50` / `+0x54` | `info_kind=0x04` ExtraTitleString array. |
| `+0x58` | `info_kind=0x01` TitleNameText. |
| `+0x5c` | `info_kind=0x02` CopyrightText. |
| `+0x60` | `vaMVGetContents()` result (= `title+0x8c`). |

After the session is built, `MosViewAlloc(0x60 = 96)` allocates the
pane state block (the per-window MosPaneState, distinct from the
title-shared MosViewSession). The block is initialised before
`CreateMosViewWindowHierarchy`:

```
puVar3[0x13] = 0
puVar3[0xc]  = &PTR_MosViewPopupNode_dtorDerived_7f3c964c   (vtable v1)
puVar3[0xc]  = &PTR_MosViewPopupNode_dtorDerivedAlt_7f3c9650 (vtable v2; overwrite)
InitializeCriticalSection(puVar3 + 0xd)
puVar3[0..6] = 0
puVar3[7]    = hostWindow
puVar3[8]    = GetSysColor(COLOR_WINDOW = 5)               (bg color)
puVar3[9..b] = 0
puVar3[14..16] = 0
```

`CreateMosViewWindowHierarchy(pane, session, initialSelector)` builds
the splitter + two `MosChildView` panes (scrolling style
`0x42300000 = WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|WS_CLIPSIBLINGS`,
non-scrolling style `0x42000000 = WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS`).
Each pane gets its own viewer via `MVCL14N!lpMVDuplicate`
(`project_mosview_dual_pane_paint`). Failure here unwinds the full
cleanup chain (`CloseMosViewSession`, `MosViewFree`, `MosViewSession_vdtor`,
`MosViewSession_array_vdtor` ×2, `MosViewSession_dtor`).

### H. `OpenMediaTitleSession @ 0x7F3C61CE` — wire emission

Stack frame allocated via `__chkstk` (3000-byte `titleInfoText`,
1000-byte `titleOpenSpec`, `titleInfoRecord[31]`). Implicit
`extraout_ECX` is the just-allocated `MosViewSession` (caller
convention).

```
if (titleSpec[0]==0 || !MosViewStartConnection("MEDVIEW")) return 0
ShowWindow(host, SW_SHOWNORMAL=1)
RedrawWindow(host, NULL, NULL,
             RDW_INVALIDATE|RDW_UPDATENOW|RDW_ERASE|RDW_ALLCHILDREN
             = 0x105)
session+0x20 = viewSerial
session+0x24 = MosViewAlloc(strlen(titleSpec)+1) + memcpy(titleSpec)
wsprintfA(titleOpenSpec, ":%d[%s]%d",                    (fmt 0x7F3CD4EC)
          DAT_7f3cd2e8 /*=2*/, titleSpec, viewSerial)
```

`MosViewStartConnection("MEDVIEW")` (`0x7F3C4504`) wraps
`MVCL14N!MVTitleConnection(DAT_7f3cd2e8, 1, "MEDVIEW")` and stores
the status in `DAT_7f3cd2ec`. Internally this drives:

```
MVCL14N!MVTitleConnection → MVTTL14C!TitleConnection
   → MVTTL14C!hrAttachToService (0x7E844114)
       MPCCL service-factory slot 0x24
       MEDVIEW service version 0x1400800A
       — fires selector 0x1F ATTACH (handshake)
       — reply must include 0x87+0x88 ATTACH-ACK; bare 0x87 leaves
         the master flag at 0 (project_medview_master_flag)
       — primes via MVTitlePreNotify(0, opcode=10, &DAT_7e84e2ec, 6)
       — registers 5 async-callback iterators (selector 0x17 SubscribeNotification):
         DAT_7e84e308 (type 0, HfcCache_DispatchContentNotification)
         DAT_7e84e30c (type 1, LAB_7e849251 / pictures)
         DAT_7e84e310 (type 2, HighlightCache_DeserializeAndRegister)
         DAT_7e84e314 (type 3, NotificationType3_DispatchRecord)
         DAT_7e84e318 (type 4, NotificationType4_ApplyChunkedBuffer)
       — every reply must be 0x87 0x88 (stream-end iterator); a 0x86
         hit triggers MPCCL!SignalRequestCompletion spin
         (project_mpccl_signalcompletion_spin).
```

On `hrAttachToService` failure, `DAT_7f3cd2ec = 0x407` (ATTACH-NACK
sentinel). `MosViewMain`'s post-pump branch checks this value to
suppress the title-open error dialog: when the service refuses the
attach, MOSVIEW reports through `SendMedViewStatusMessage` only and
does not double-report via `MosErrorP`.

After the connection is up:

```
hMVTitleOpen(spec)                       → titleHandle (engine opaque)
  └─ hMVTitleOpenEx(spec, 0, 0)
       slot index from spec[1] ('2' → MVTTL14C slot 1)
       LoadLibraryA("MVTTL14C.DLL")
       GetProcAddress("TitleOpenEx")
       MVTTL14C!TitleOpenEx(spec, 0, 0)            (selector 0x01)
          reads HKLM\…\MVCache\<title>.tmp first 8 bytes (cache hint)
          wire request: 0x04 spec, 0x03 hint_lo, 0x03 hint_hi, recv stubs
          wire reply (project_medview_wire_contract):
            0x81 title_id (nonzero)        → title+0x02
            0x81 hfs_volume                → title+0x88
            0x83 contents_va               → title+0x8c
            0x83 ?                         → title+0x90
            0x83 topic_count               → title+0x94
            0x83 checksum_pair (2 dwords)
            dynbytes payloadBlob (= 9-section body)
lpMVNew(titleHandle)                    → viewer; session+0x30 = viewer
MVSetKerningBoundary(0x24)              (engine config)
lMVTitleGetInfo(title, 0x6F, …)         (font table)
  └─ hMVSetFontTable
lMVTitleGetInfo(title, 0x69, …)         (HFS volume / FileSystem)
  └─ MVSetFileSystem
session+0x60 = vaMVGetContents()        (= title+0x8c)
```

The contents-va check is critical: `NavigateMosViewPane` hides the
pane when this is zero. The MEDVIEW server must therefore either
ship a non-zero `contents_va` plus a non-empty body or populate the
client's topic cache via type-3 async pushes
(`project_medview_cache_push_format`).

Then four `lMVTitleGetInfo` enumeration loops fan out:

| Loop | `info_kind` | Stride | Target | Memory backing |
|------|------------:|-------:|--------|----------------|
| 1 | `0x07` | `0x2B` (43) | `session+0x3c` | `GlobalAlloc`/`GlobalReAlloc GMEM_MOVEABLE\|GMEM_ZEROINIT` |
| 2 | `0x08` | `0x1F` (31) | `session+0x44` | same |
| 3 | `0x06` | `0x98` (152) | `session+0x4c` | same |
| 4 | `0x04` | variable (≤3000-byte buffers) | `session+0x54` | `GlobalAlloc` for ptr table, `MosViewAlloc` per entry |

Each iteration packs `(info_kind << 16) | recordSize` and stops when
the engine reports `lMVTitleGetInfo < 1`. The 152-byte section-3
records are cached but no MOSVIEW function consumes them with a
literal `0x98` size constant; the consumer reads them with register
displacement (`project_medview_page_render_chain` §"Section 3 open
question"). Stride `0x2B` matches the section-1 topic/TOC record
shape; stride `0x1F` matches section-2 link/jump records.

Final two single-shot reads:

```
lMVTitleGetInfo(0x01) → UnquoteCommandArgument → session+0x58
                       (or "Unknown Title Name" @ 0x7F3CD4D8 if empty)
lMVTitleGetInfo(0x02) → UnquoteCommandArgument → session+0x5c
```

`return 1` on success. The caller (`CreateMediaViewWindow`) then
applies `SetWindowTextA(host, session+0x58)` if the engine provided
a non-empty display title.

### I. First-frame paint (window proc → BitBlt / PlayMetaFile)

`MosViewShellWindowProc @ 0x7F3C191C` fires before
`CreateMediaViewWindow` returns — `CreateWindowExA` in §F dispatches
`WM_CREATE` synchronously.

| Msg (order) | Branch | Behaviour |
|------------:|--------|-----------|
| `WM_CREATE` (0x01) | hWnd_child = NULL | `MosViewAlloc(1)` → `SetWindowLongA(hwnd, 0, slot)` (`cbWndExtra=4`). Return `-1` on alloc failure (cancels window creation). |
| `WM_ERASEBKGND` (0x14) | no child yet | `FillRect(hdc, client, CreateSolidBrush(GetSysColor(COLOR_WINDOW)))` + DeleteObject. |
| `WM_PAINT` (0x0F) | no child yet | `BeginPaint`; if `fErase`: erase as above. Zero 400-byte stack buffer. `LoadStringA(hInst, 12, buf, 400)` ("title is being prepared, please wait"). `GetClientRect`. `SystemParametersInfoA(SPI_GETICONTITLELOGFONT=0x1F)` + `lfWeight=FW_NORMAL=400` + `lfHeight = -(LOGPIXELSY*12)/96`. `CreateFontIndirectA` + `SelectObject`. `DrawTextA(hdc, buf, len, rect, DT_CENTER\|DT_VCENTER\|DT_SINGLELINE\|DT_NOPREFIX = 0x825)`. Restore font + `DeleteObject`. `GdiFlush`. |
| `WM_PAINT` | child present | `DefWindowProcA`. |
| `WM_ERASEBKGND` | child present | `SendMessageA(child, 0x403, 0, 0)` for child-supplied colour, else `GetSysColor(COLOR_WINDOW)`. |
| `WM_TIMER` 0x113 | `MEDIATIMEOUT` expired | `PostQuitMessage(0)`. |
| `0x414` w=1 | single-instance probe (§D) | `ShowWindow(SW_SHOWNORMAL)` + `BringWindowToTop` + `SetForegroundWindow` → return `0x456734AF`. |

Child panes are created by `CreateMosViewWindowHierarchy` (§G); each
pane installs its own `MosChildView` WindowProc registered in
`InitializeMosViewUi`. First content paint flows:

```
NavigateViewerSelection(session, target_va, paneFlags)
  ↳ MVCL14N!fMVSetAddress(viewer, va)
  ↳ MVCL14N!fMVRealize(viewer, va)
      MVCL14N!MVRealizeView @ 0x7E88E440
        ├─ MVCheckMasterFlag (DAT_7e84e2fc)    project_medview_master_flag
        ├─ HfcNear(viewer, va)
        │     cache miss → MVTTL14C selector 0x15 (vaResolve)
        │     (vaConvert* selectors 0x06 / 0x07 / 0x10 also gated here)
        ├─ MVParseLayoutChunk @ 0x7E890FD0
        │     case dispatch on chunk[0x26] (project_medview_page_render_chain):
        │     1/0x20 → MVBuildTextItem        (paragraph)
        │     3/0x22 → MVBuildLayoutLine      (CSection + bitmap)
        │     4/0x23 → MVBuildColumnLayoutItem(table)
        │     5/0x24 → MVBuildEmbeddedWindowItem (widget)
        ├─ MVWalkLayoutSlots @ 0x7E894C50    slot walker
        └─ MVRequestBaggageBitmap @ 0x7E886980
              wsprintfA("|bm%d", index)      (project_medview_baggage_bm0_synthetic)
              wire request: 0x1A HfOpenHfs    (`|bm0` then retry `bm0`)
                            0x1B LcbReadHf
                            0x1C HfCloseHf
              MVDecodeBitmapBaggage @ 0x7E887A40 — kind≥5 raster parse
```

Paint-pass leaves run from each pane's `WM_PAINT`:

```
MosChildView WindowProc receives WM_PAINT
  ↳ MVCL14N!MVPaneOnPaint @ 0x7E889B70
      BeginPaint(hwnd)
      MVCL14N!MVDispatchSlotPaint @ 0x7E891220
         slot[0]==1 → DrawTextSlot
         slot[0]==3 → MVPaintBitmapSlot → MVPaintBitmapRecord  (BitBlt SRCCOPY)
         slot[0]==4 → MVPaintRectangleSlot
         slot[0]==5 → MVPaintBorderSlot
         slot[0]==6 → MVPaintEmbeddedMediaSlot
         slot[0]==7 → MVInvertRunHighlightLines
      EndPaint(hwnd)
```

MMVDIB12 GDI primitives reached on the first frame:

```
MMVDIB12!CPlayMeta::Meta_GetDC                          DC accessor
MMVDIB12!CPlayMeta_StretchDIBits @ 0x7F4F10F5           StretchDIBits + DPI rescale (kind=5)
MMVDIB12!CPlayMeta_BlitMetaPair  @ 0x7F4F1F52           SetViewportOrgEx + SelectPalette + BitBlt SRCCOPY
MMVDIB12!PlayMetaFile                                   caption baggage (kind=8)
```

Both panes paint the same baggage independently
(`project_mosview_dual_pane_paint`): scrolling pane at host-client
~(42, 30) height ~218; non-scrolling at ~(42, 248). Caption metafiles
authored at page Y < 218 render twice. The Y-scrollbar is forced on
unconditionally by `MVRealizeView+0x74` setting `title+0x84=1`
(`project_mosview_scrollbar_root_cause`).

---

## 4. First-frame timing budget

| Step | Bound |
|------|-------|
| `CreateProcessA` return to `MosViewMain` entry | one CRT scaffold (msvc-1.x) — no I/O, no engine. |
| `MosViewMain` entry to `CreateWindowExA("MosMediaViewShell", …)` | `LoadIconA`, `LoadAcceleratorsA`, `LoadStringA` ×2, two `RegisterClassA`. No wire. |
| Frame visible (loading splash) | first `WM_PAINT` after `ShowWindow`/`UpdateWindow`. `DrawTextA(LoadStringA(12))`. |
| `OpenMediaTitleSession` start | re-`ShowWindow(SW_SHOWNORMAL)` + `RedrawWindow(RDW_INVALIDATE\|RDW_UPDATENOW\|…)` forces the splash to repaint over the synchronous wire path. |
| First wire emission | selector `0x1F` ATTACH (`MosViewStartConnection`). |
| First content paint | `TitleOpenEx` reply must include nonzero `contents_va` and the master flag must latch (`0x87 0x88` on the 5× `0x17` SubscribeNotification iterators). |
| Watchdog | `WM_TIMER 0x113` fires `PostQuitMessage(0)`; default 40 000 ms unless `MEDIATIMEOUT` overrides. |

The pump is single-threaded; engine async callbacks
(`SubscribeNotification` deliveries) re-enter through `MPCCL` worker
hooks. `MOSCP.EXE` enforces a 1024-byte recv buffer
(`project_client_recv_buffer`); any reply > 1024 wire bytes
fragments — `TitleOpen` reply with a real body always does.

---

## 5. Error / exit-early paths

Every place this path can exit without painting a content frame:

| Trigger | Detection site | Action |
|---------|----------------|--------|
| `startupMode != 0` | `MosViewMain` prologue | `return WPARAM=0`. Not used on DID launch. |
| Live single-instance owner | `bVar3=true` after `SendMessageA(0x414,1,0)` returns `0x456734AF` | `UnmapViewOfFile + CloseHandle×2; return WPARAM=1`. |
| Empty deids and empty tail | both `DAT_7f3cd048` and `DAT_7f3cd04c` are 0 after fallback | `MosErrorP(0,hInst,3,4,0); return 0`. |
| `CreateMosViewShellWindow == NULL` | post-call check in `MosViewMain` | `MosErrorP(0,hInst,5,6,0); return 0`. Causes: missing icon (id 7) / accelerator (id 8) / class-name string (id 1) / window-caption string (id 2); `MosViewInit` returning 0 (=`InitializeMosViewUi` `RegisterClassA` failure); `RegisterClassA("MosMediaViewShell")` failure; `CreateWindowExA` failure. |
| `MEDIATIMEOUT` expires | `WM_TIMER 0x113` reaches `MosViewShellWindowProc` | `PostQuitMessage(0)`; `GetMessageA` returns 0, pump exits. |
| `MosViewStartConnection` fails (`hrAttachToService`) | `DAT_7f3cd2ec != 0` (`MVTitleConnection` return nonzero) | `OpenMediaTitleSession` returns 0 → `CreateMediaViewWindow` returns 0 → `MosViewMain` checks `DAT_7f3cd2ec == 0x407` to suppress the dialog; status pre-notify still goes via `SendMedViewStatusMessage(1, …)`. |
| `hMVTitleOpen` fails | `iVar4 == 0` after the wsprintfA spec build | `OpenMediaTitleSession` returns 0; cleanup as above; `DAT_7f3cd2ec` is 0 here (connection succeeded), so the dialog **does** fire. |
| `lpMVNew` fails | `iVar4 == 0` after `hMVTitleOpen` succeeded | as above. |
| `CreateMosViewWindowHierarchy` fails | inside `CreateMediaViewWindow` | full pane teardown (`CloseMosViewSession`, `MosViewFree`, `MosViewSession_vdtor` ×3, `MosViewSession_dtor`); `CreateMediaViewWindow` returns 0; dialog as above. |
| Normal exit | `GetMessageA` returns 0 (WM_QUIT from `WM_DESTROY` → `PostQuitMessage`, or 0x113 watchdog) | `local_70.wParam` carries the WM_QUIT exit code. |

Failure dialog body wsprintfA template:
`"The title (Appid=%d, deid=%X%8X) is currently unavailable…"`
(`s_The_title_Appid__d__deid__X_8X__i_7f3cd1d4`).

---

## 6. Cross-binary call boundary

| From | To | Symbols used on DID path |
|------|-----|-------------------------|
| MOSVIEW.EXE | MCM.DLL | `FGetCmdLineInfo`, `MosErrorP`, `MosAbout` (menu 0x6B only). |
| MOSVIEW.EXE | MVCL14N.DLL | `MVSetInstance`, `MVTitleConnection`, `hMVTitleOpen`, `hMVTitleOpenEx`, `lpMVNew`, `MVSetKerningBoundary`, `lMVTitleGetInfo`, `hMVSetFontTable`, `MVSetFileSystem`, `vaMVGetContents`, `MVTitlePreNotify`; engine-internal: `MVRealizeView`, `MVParseLayoutChunk`, `MVWalkLayoutSlots`, `MVBuildTextItem`, `MVBuildLayoutLine`, `MVBuildColumnLayoutItem`, `MVBuildEmbeddedWindowItem`, `MVPaneOnPaint`, `MVDispatchSlotPaint`, `MVRequestBaggageBitmap`, `MVDecodeBitmapBaggage`, `MVCheckMasterFlag`, `HfcNear`. |
| MVCL14N.DLL | MVTTL14C.DLL | `TitleConnection`, `hrAttachToService`, `TitleOpenEx`, `TitleGetInfo` (skipped on MSN Today path — local body decode), `MVAwaitWireReply`, `MVAsyncNotifyDispatch`, `HfsRead`, `SubscribeNotification` / `UnsubscribeNotification`. |
| MVTTL14C.DLL | MPCCL.DLL | service-factory slot `0x24`, `sendRequest`, `SignalRequestCompletion`, `WaitForMessage`. |
| MPCCL.DLL | MOSCP.EXE (separate process) | local named pipe (`MOSCP`-named), 1024-byte recv frame cap (`project_client_recv_buffer`). |
| MOSVIEW.EXE | MMVDIB12.DLL | `InitiateMVDIB`, `TerminateMVDIB`, `CPlayMeta::Meta_GetDC`, `CPlayMeta_StretchDIBits`, `CPlayMeta_BlitMetaPair`, `PlayMetaFile`. |
| MOSVIEW.EXE | MOSCOMP.DLL | `ProgCreate`, `ProgAddData`, `ProgSetOutput`, `ProgPaint`, `ProgClose` (per-title progress UI). |
| MOSVIEW.EXE | CCAPI.DLL | `MOSX_HrCreateCCFromAppidDeid` (menu 0x66 only — not on DID startup path). |
| MOSVIEW.EXE | USER32.DLL | `RegisterClassA`, `CreateWindowExA`, `LoadIconA`, `LoadAcceleratorsA`, `LoadStringA`, `LoadCursorA`, `ShowWindow`, `RedrawWindow`, `SetWindowTextA`, `GetSysColor`, `SystemParametersInfoA`, `BeginPaint`, `EndPaint`, `FillRect`, `DrawTextA`, `GetDC`, `ReleaseDC`, `SendMessageA`, `GetTopWindow`, `GetWindowLongA`, `SetWindowLongA`, `WinHelpA`, `GetMenu`, `EnableMenuItem`, `DrawMenuBar`, `AppendMenuA`, `BringWindowToTop`, `SetForegroundWindow`, `SetTimer`, `KillTimer`, `PostQuitMessage`, `GetActiveWindow`, `GetParent`, `GetClientRect`, `SetCursor`, `GetMessageA`, `TranslateAcceleratorA`, `TranslateMessage`, `DispatchMessageA`. |
| MOSVIEW.EXE | GDI32.DLL | `GetDeviceCaps`, `CreateFontIndirectA`, `SelectObject`, `CreateSolidBrush`, `DeleteObject`, `GdiFlush`. |
| MOSVIEW.EXE | KERNEL32.DLL | `CreateSemaphoreA`, `WaitForSingleObject`, `ReleaseSemaphore`, `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile`, `CloseHandle`, `GetEnvironmentVariableA`, `GetCurrentThread`, `SetThreadPriority`, `GetLastError`, `GlobalAlloc`, `GlobalReAlloc`, `InitializeCriticalSection`, `lstrcmpiA`, `lstrlenA`, `wsprintfA` (USER32 import). |

---

## 7. Cross-references

- `docs/MOSVIEW.md` §3 narrative overview of the launch path; §4
  single-instance summary; §5.2/5.3 the cached-session and
  title-open contracts.
- `docs/MOSVIEW-RENDER-PIPELINE.md` §1 bring-up; §3 title open;
  §4 layout walk; §5 paint dispatch.
- `docs/MEDVIEW.md` and `docs/medview-service-contract.md` for the
  full wire selector table, body shape, and the 9-section title
  payload format.
- `docs/MOSSHELL.md` and `docs/MCM.DLL` notes for `HRMOSExec` and
  command-tail construction.
- `docs/BLACKBIRD.md` for the on-disk title shape consumed by
  TitleOpen replies.
- Memory anchors used above:
  `project_mcm_hrmosexec`, `project_medview_wire_contract`,
  `project_medview_master_flag`, `project_medview_page_render_chain`,
  `project_medview_paint_call_graph`,
  `project_medview_baggage_bm0_synthetic`,
  `project_medview_cache_push_format`,
  `project_mosview_dual_pane_paint`,
  `project_mosview_scrollbar_root_cause`,
  `project_mpccl_signalcompletion_spin`,
  `project_client_recv_buffer`,
  `project_moserror_info_struct`.

---

## 8. State of this document

Static-analysis pass against Ghidra `MSN95.gpr`, MOSVIEW.EXE
session of 2026-05-11 (image base `0x7F3C0000`). Every address
listed has a hand-written or bulk-derived plate in the Ghidra
database. Engine-side (MVCL14N / MVTTL14C / MMVDIB12) function
addresses cross-reference the memory entries listed in §7, which
themselves were established through SoftIce live debugging
documented in their own provenance notes.

Items in this document that have **not** been independently
re-confirmed live during this pass:

- The 5 SubscribeNotification iterator types and their callbacks
  (anchored from `project_medview_master_flag`, last live trace
  2026-04-27).
- The `0x87 0x88` reply requirement on selector `0x17` (same).
- The `WindowExStyle = 0x02CF0000` decode (composed on the stack;
  decompiler shows the constant directly).
- The two child class names registered by `InitializeMosViewUi`
  (the `WNDCLASSA.lpszClassName` strings are loaded from
  `DAT_7f3cd4ac` and the equivalent for the second class via
  on-stack composition; the entry-point addresses `0x7F3C474B` and
  `0x7F3C2301` are confirmed via the deep-annotated function table
  in `scratch/annotate-progress/MOSVIEW.EXE.json`).

These items are static-confidence: re-confirm via SoftIce
(`docs/SOFTICE.md` flow) before relying on them for a server
behaviour change.
