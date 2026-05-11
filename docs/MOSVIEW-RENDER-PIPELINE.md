# MOSVIEW render pipeline

End-to-end trace from the MSN process-launch contract down to the
GDI leaves that emit pixels. Built from the
total-decomp pass driven by `.claude/plans/serene-knitting-corbato.md`.

For per-binary inventory and per-function status see
`docs/re-passes/<binary>.md`. For wire framing see
`docs/MEDVIEW.md` and `docs/medview-service-contract.md`. For on-disk
formats see `docs/blackbird-title-format.md` and
`docs/mosview-mediaview-format.md`.

This is a static-analysis document. Renders are described as the
chains of code that *should* execute, sourced from Ghidra
decompilation plus the body of memory-anchored RE notes. Pixel-level
behaviour is advisory until the live-debug pass runs (out of scope
for this doc).

Current view is aligned to `docs/re-passes` as of 2026-05-09.

---

## 1. Process bring-up

For the branch-by-branch DID-launch walk (entry → first frame, error
exits, env knobs, single-instance gate, wire selectors), see
[`re-passes/MOSVIEW-STARTUP.md`](re-passes/MOSVIEW-STARTUP.md). This
section is the call-graph summary.

```
HRMOSExec(c=6, args)            ← MCM dispatcher
└─ CreateProcessA("MOSVIEW.EXE -MOS:6:<deid_lo>:<deid_hi>:<tail>")
   └─ entry (CRT scaffold)
      └─ MosViewMain (0x7f3c1053)
         ├─ FGetCmdLineInfo          → appid, deid_lo, deid_hi, tail
         ├─ if MEDIAMULTI unset:
         │    OpenSemaphore "Mosview Single Instance Semaphore"
         │    OpenFileMappingA "Mosview Single Instance Segment" (size 0x644, slots=100)
         │    foreach live slot: SendMessage(WM_USER 0x414) -- expect 0x456734AF
         │       if my deid pair owns a live slot → ExitProcess(1)
         ├─ MEDIATIMEOUT env knob: timer id 1, default 40000 ms
         ├─ CreateMosViewShellWindow (0x7f3c1805)
         │    ├─ MosViewInit (0x7f3c2183, exported)
         │    │    └─ InitializeMosViewUi (0x7f3c5d29)
         │    │         ├─ GetSystemMetrics screen snapshot
         │    │         ├─ InitializeCriticalSection (shared)
         │    │         ├─ InitiateMVDIB ........... [MMVDIB12]
         │    │         └─ register MedView child window classes
         │    ├─ LoadIconA(7), LoadAcceleratorsA(8)
         │    ├─ LoadStringA(class_name), LoadStringA(window_caption)
         │    ├─ RegisterClassA "MosMediaViewShell" → MosViewShellWindowProc
         │    └─ CreateWindowExA top-level frame
         ├─ CreateMediaViewWindow(titleSpec, initialSelector, host)
         └─ message loop: GetMessageA / TranslateAcceleratorA /
                           TranslateMessage / DispatchMessageA
```

---

## 2. Window proc layer

`MosViewShellWindowProc` (`0x7f3c191c`) is the top-frame
WindowProc. Decoded message handling:

| Msg | Branch |
|----:|--------|
| `WM_CREATE` (0x01) | `MosViewAlloc(1)` → `SetWindowLongA(GWLP_USERDATA)` |
| `WM_DESTROY` (0x02) | relay to top child, `WinHelpA(close)`, `MosViewFree(slot)`, `PostQuitMessage(0)` |
| `WM_ACTIVATE` (0x05) | relay 0x412 to child |
| `WM_PAINT` (0x0F) | if no child: `BeginPaint` + `DrawTextA(LoadStringA(12))` (loading splash). With child: `DefWindowProcA`. |
| `WM_CLOSE` (0x10) | relay to child, `DefWindowProcA` |
| `WM_ERASEBKGND` (0x14) | `FillRect` with `GetSysColor(5)` or child's reply to msg 0x403 |
| `WM_KEYDOWN` (0x100) | relay to child |
| `WM_COMMAND` (0x111) | menu verbs: 0x66 open (CCAPI), 0x67 close, 0x68 back, 0x69 help, 0x6a info dialog, 0x6b about |
| `0x113` (WM_TIMER) | `PostQuitMessage(0)` |
| `0x30f` / `0x311` (drag) | walk parent chain; relay if target is not the frame |
| `0x402` | `AppendMenuA(Previous/Next)` + `DrawMenuBar` |
| `0x407` | `EnableMenuItem(0x68 Back)` + `DrawMenuBar` |
| `0x414` | single-instance probe: ShowWindow + BringWindowToTop + SetForegroundWindow → return `0x456734AF` |
| default | `DefWindowProcA` |

Each MedView pane has its own child WindowProc (MVCL14N-hosted) which
forwards 0x404 (back), 0x406 (current title id
for info dialog), 0x412 (activation), 0x413 (window-aspect packed
script), 0x414 (probe-alive ack), 0x42E (background-pic args).

---

## 3. Title open

`CreateMediaViewWindow` (`0x7f3c4f26`, exported):

```
CreateMediaViewWindow(titlePath, initialSelector, hostWindow)
├─ probe display DPI (GetDeviceCaps LOGPIXELSY)
├─ search global linked list of cached MosViewSession by case-insensitive titlePath
├─ if hit:                   reuse session
└─ if miss:
   ├─ allocate MosViewSession block (size 0xb8+)
   ├─ increment per-process viewSerial
   ├─ OpenMediaTitleSession(titlePath, viewSerial, hostWindow)
   └─ cache the new session
```

`OpenMediaTitleSession` (`0x7f3c61ce`):

```
OpenMediaTitleSession(titlePath, viewSerial, host)
├─ MosViewStartConnection("MEDVIEW")     ─ exported wrapper
│   └─ MVCL14N!MVTitleConnection
│       └─ MVTTL14C!TitleConnection
│           └─ hrAttachToService          [0x7e844114]
│               ├─ MPCCL service-factory slot 0x24
│               ├─ ATTACH selector 0x1F   ─ handshake (clientVersion, capabilities, lcid)
│               ├─ TitlePreNotify(0, opcode=10, &DAT_7e84e2ec, 6)  ─ post-attach prime
│               └─ register five async callback slots
├─ ShowWindow + RedrawWindow on host (paint loading splash)
├─ wsprintfA(spec, ":%d[%s]%d", DAT_7f3cd2e8 /*=2*/, titlePath, viewSerial)
├─ MVCL14N!hMVTitleOpen(spec)
│   └─ hMVTitleOpenEx(spec, 0, 0)
│       ├─ if spec[0..1] == ':1'..':5': use slot index spec[1]-'1'
│       │   else: scan registered parsers
│       ├─ LoadLibraryA("MVTTL14C.DLL") (slot 1 in MOSVIEW context)
│       ├─ GetProcAddress("TitleOpenEx")
│       └─ MVTTL14C!TitleOpenEx(spec, 0, 0)         ─ selector 0x01
│           ├─ read HKLM\...\MVCache\<title>.tmp first 8 bytes (cacheHint pair)
│           ├─ wire request: 0x04 spec, 0x03 hint0, 0x03 hint1, recv stubs
│           └─ wire reply (per docs/medview-service-contract.md §4):
│              0x81 title_id (≠0)
│              0x81 hfs_volume
│              0x83 contents_va           → title+0x8c
│              0x83 ?                      → title+0x90
│              0x83 topic_count           → title+0x94
│              0x83 new_checksum_pair
│              dynbytes payloadBlob
├─ MVCL14N!lpMVNew(titleHandle)            ─ create viewer instance
├─ MVCL14N!MVSetKerningBoundary(0x24)
├─ MVCL14N!lMVTitleGetInfo(title, 0x6f, 0, ...)   ─ font table
│   └─ MVCL14N!hMVSetFontTable
├─ MVCL14N!lMVTitleGetInfo(title, 0x69, 0, ...)   ─ HFS file system mode
│   └─ MVCL14N!MVSetFileSystem
├─ MVCL14N!vaMVGetContents(title)          ─ contents va (= title+0x8c)
├─ enumerate TitleGetInfo info_kind=0x07 records (ChildPaneRecord, 0x2b B)
├─ enumerate TitleGetInfo info_kind=0x08 records (PopupPaneRecord, 0x1f B)
├─ enumerate TitleGetInfo info_kind=0x06 records (WindowScaffoldRecord, 0x98 B)
├─ enumerate TitleGetInfo info_kind=0x04 strings (ExtraTitleString, ≤3000-byte buffers)
├─ fetch TitleGetInfo info_kind=0x01 / 0x02 (TitleNameText / CopyrightText)
└─ if title exposes display_title: SetWindowTextA on host
```

The wire ingress (selector 0x1F handshake, 0x01 TitleOpen) crosses
the local MOSCP.EXE pipe via MPCCL → MVTTL14C client. MOSCP demuxes
to the MEDVIEW server thread which runs in the same process via the
service-factory at slot 0x24.

---

## 4. Layout walk

After the title is open, `NavigateViewerSelection` resolves a
target topic (deid or title_id) and asks the engine to lay it out.
`HandleMediaTitleCommand` (`0x7f3c5150`) dispatches the in-document
script verbs. JumpID / PopupID / PaneID all funnel into
`NavigateViewerSelection`.

```
NavigateViewerSelection(titleSession, target_va, paneFlags)
└─ MVCL14N!fMVRealize(viewer, va)
   └─ MVRealizeView (0x7e88e440)        — paint orchestrator
      ├─ MVCheckMasterFlag (DAT_7e84e2fc) — requires handshake reply 0x87 0x88 (not 0x87 alone)
      ├─ probe HfcNear(viewer, va)
      │   └─ if cache miss → MVTTL14C selector 0x15 (vaResolve)
      ├─ MVParseLayoutChunk (0x7e890fd0) — case dispatch on 0xBF chunk kind:
      │   kind 1: 128B text-row chunk (3B preamble + null TLV + 0xFF + ASCII text)
      │   kind 5: bitmap container, CBFrame-sized 1bpp white DIB
      │   kind 8: caption metafile baggage (MEDVIEW selector 0x1A bm0)
      ├─ MVWalkLayoutSlots (0x7e894c50) — slot walker, kind dispatch
      │   ├─ MVBuildLayoutLine (0x7e894560) — line builder
      │   ├─ embedded-kind payload → MVBuildEmbeddedWindowItem → MVCreateEmbeddedWindow
      │   │   └─ MVPR14N::MVIMAGEWndProc (embedded image child)
      │   │       ├─ embedded directives / hotspot dispatch
      │   │       ├─ codec registry: BMP "BM", SHG "lp"/"lP", mono-BMP WLT path
      │   │       └─ render + clipboard hooks (MVIMAGE_RenderToDC, MVIMAGE_CopyToClipboard)
      ├─ MVRequestBaggageBitmap (0x7e886980) — wsprintfA "|bm%d", 0x1A/0x1B/0x1C HFS read
      │   └─ MVDecodeBitmapBaggage (0x7e887a40) — kind>=5 raster parse
      └─ HFS read replies via MVAwaitWireReply (MVTTL14C 0x7e843dcb)
```

Text item builder chain (per `docs/mosview-authored-text-and-font-re.md`):
```
MVBuildTextItem (0x7e8915d0)
├─ MVDecodeTopicItemPrefix (0x7e897ed0)  topic-item prefix decode
├─ MVDecodePackedTextHeader (0x7e897ad0) packed text-item header decode
│   ├─ alignment_mode, space_before, space_after, min_line_extent
│   ├─ left_indent, right_indent, first_line_indent, tab_interval
│   ├─ edge_metric_flags
│   └─ inline_runs[] (count at +0x27, 4-byte stride starting +0x29)
├─ MVScaleTextMetrics (0x7e892b90)  scale by LOGPIXELSX/Y * title_scale (title+0x7c)
├─ MVTextLayoutFSM (0x7e891810)     per-character layout state machine
└─ DrawTextSlot (0x7e893010)        final text draw (deferred to paint pass)
```

Font/style descriptor lookup:
```
hMVSetFontTable(table, count)
├─ CopyResolvedTextStyleRecord (0x7e896590) name_index → descriptor offset (stride 0x2a)
└─ ResolveTextStyleFromViewer  (0x7e896610) descriptor_count clamp
```

---

## 5. Paint dispatch

`WM_PAINT` arrives at the child pane WindowProc:

```
child_pane_WndProc(hwnd, WM_PAINT, ...)
├─ MVCL14N!MVPaneOnPaint (0x7e889b70)
│   ├─ BeginPaint(hwnd)
│   └─ MVDispatchSlotPaint (0x7e891220)  — dispatch by slot[0]
│       └─ slot+0x13 va is highlight key only, NOT wire-cache
└─ EndPaint(hwnd)
```

`MVDispatchSlotPaint` walks the parsed-chunk tree built by §4 and
emits the actual GDI calls. For raster and caption paths, the paint
leaf is `PlayMetaFile` / `BitBlt` through MMVDIB12.

```
MMVDIB12 paint primitives
├─ CPlayMeta_* helpers                  DC allocation + state + lifecycle helpers for image/metafile playback
├─ CPlayMeta::Meta_GetDC               DC accessor for the metafile pane
├─ CPlayMeta_StretchDIBits (0x7f4f10f5) StretchDIBits with optional DPI rescale (kind=5)
├─ CPlayMeta_BlitMetaPair  (0x7f4f1f52) viewport map + SelectPalette + BitBlt SRCCOPY
├─ PlayMetaFile (bm0 baggage)          caption text rendering, kind=8 path
└─ palette ops via MOSCOMP
```

Per `project_mosview_dual_pane_paint`: two MosChildView panes
(scrolling + non-scrolling) share an `lpMVDuplicate`'d title.
Each calls selector 0x15 separately, and both PlayMetaFile bm0
draw at distinct pane origins — the same caption text appears in
both panes.

---

## 6. Verbs and command interpreter

`HandleMediaTitleCommand` (`0x7f3c5150`) recognises:

- Hard-coded simple verbs: `CopyTopic()`, `TestSearch()`,
  `Unsearch()`, `Exit()` (posts WM_CLOSE), `Back()` (sends 0x404),
  `DontForceToForeground()`, `Contents()`.
- Structured `name(args)` verbs: `JumpID`, `PopupID`, `PaneID`,
  `ClosePane`, `PositionTopic`, `WindowAspect` (sends 0x413),
  `JumpContents`, `MasterSRColor`, `MasterNSRColor`,
  `BackgroundPic` (sends 0x42E), `ExecProgram` (CreateProcessA),
  `PreloadID`, `PreloadPic`, `SequencePic`.

JumpID/PopupID/PaneID parse a title id via `ParseTitleIdentifier`
(`0x7f3c77d9`) accepting `0x`-prefixed hex or a base-43 alphabet
(digits, letters, `!`, `.`, `_`).

---

## 7. Session teardown

```
CloseMosViewSession (0x7f3c34fb)              [host-side teardown]
├─ MVCL14N!hMVGetTitle
├─ MVCL14N!MVTitlePreNotify(op=0xc, payload {kind=2, seq, state})
├─ MOSCOMP!ProgClose
├─ MosViewFree(cached metadata)
├─ AssociateMosViewChildHwnd(NULL)            (0x7f3c34cc)
└─ DestroyMosViewerInstance (0x7f3c2261)
   ├─ fMVGetHotspotCallback(NULL out)
   ├─ MVCL14N!hMVGetTitle
   ├─ MVTitleCloseIfLastRef (cached title-state free)
   └─ MVCL14N!MVDelete

MosViewTerminate (0x7f3c219d, exported)        [process exit]
├─ broadcast shutdown PreNotify (op=0xb)
├─ TerminateMVDIB                              [MMVDIB12]
└─ disconnect MEDVIEW service
```

---

## 8. Cross-process wire flow

```
MOSVIEW.EXE                          MOSCP.EXE (MoscpWinMain → MoscpRunPump)
   │                                    │
   │  pipe (MOSCP-named pipe)           │
   │  1024-byte frame cap via            │
   │  project_client_recv_buffer         │
   │                                    │
   ├── MPCCL!sendRequest ──────────►    ├── MOSCP receive loop in WindowProc
   │   selector 0x1F handshake         │   ├── frame demux
   │                                    │   ├── packetized I/O (1024-byte frame boundary)
   │                                    │   └── route to MEDVIEW server (per-app dispatch
   │                                    │       table populated by MoscpInitServer)
   │  ◄────────────────────────── reply │
   ├── MVTTL14C!hrAttachToService       │
   │   stores proxy in DAT_7e84e2f8    │
   │                                    │
   ├── selector 0x01 TitleOpen ─────►   │
   │   spec ":2[<path>]<serial>"        │
   │   cacheHint pair from MVCache      │
   │  ◄────────────────────────── reply │
   │   title_id, hfs_volume, va, count, │
   │   payload, checksum                │
   │                                    │
   ├── selector 0x06/0x07/0x10 ─────►   │   content fetch
   ├── selector 0x15 vaResolve ────►   │   cache-near miss
   ├── selector 0x17 Subscribe ─────►   │   async pump
   ├── selector 0x18 Unsubscribe ───►   │   async stop
   ├── selector 0x1A/0x1B/0x1C ─────►   │   baggage HFS read
   ├── selector 0x1E TitlePreNotify ◄►  │   bidirectional notify
   ├── selector 0x1F (handshake)        │
   │                                    │
   └── (close path) PreNotify op=0xc, │
       service-shutdown PreNotify op=0xb │
```

---

## 9. State of this document

Static, fully sourced from Ghidra symbols + line annotations + the
existing per-feature RE notes.

The render-critical chain is now hand-named end-to-end:

- Host: `MosViewMain` → `MosViewShellWindowProc`,
  `CreateMediaViewWindow` → `OpenMediaTitleSession`,
  `CloseMosViewSession` / `AssociateMosViewChildHwnd`
  / `DestroyMosViewerInstance`, `HandleMediaTitleCommand`.
- Engine: `hMVTitleOpen` / `hMVTitleOpenEx`,
  `MVRealizeView`, `MVParseLayoutChunk`, `MVWalkLayoutSlots`,
  `MVBuildLayoutLine`, `MVBuildEmbeddedWindowItem`,
  `MVCreateEmbeddedWindow`, `MVBuildTextItem`, `MVTextLayoutFSM`,
  `MVDecodePackedTextHeader` / `MVDecodeTopicItemPrefix`,
  `MVScaleTextMetrics`, `MVPaneOnPaint`, `MVDispatchSlotPaint`,
  `MVRequestBaggageBitmap`, `MVDecodeBitmapBaggage`,
  `DrawTextSlot`, `CopyResolvedTextStyleRecord`,
  `ResolveTextStyleFromViewer`.
- Wire: `TitleConnection`, `hrAttachToService`, `TitleOpenEx`,
  `TitleGetInfo`, `vaGetContents`, `MVAwaitWireReply`,
  `MVAsyncNotifyDispatch`, `MVCheckMasterFlag`,
  `HfsRead` (`0x1A/0x1B/0x1C`), `SubscribeNotification` (`0x17/0x18`).
- Paint primitives: `CPlayMeta::Meta_GetDC`,
  `CPlayMeta_StretchDIBits`, `CPlayMeta_BlitMetaPair`,
  `InitiateMVDIB`, `TerminateMVDIB`.
- Wire peer: `MoscpWinMain`, `MoscpInitServer`,
  `MoscpRegisterClass`, `MoscpRunPump`, `MoscpShutdown`.
- Embedded image side-path: `MVIMAGEWndProc`, `MVIMAGE_RenderToDC`,
  `WltPicture_*` / `Shed_*` codec families, `MVIMAGE_HotspotDispatch`.

Specific gaps (in priority order from
`docs/re-passes/INDEX.md`):

- `CCAPI.DLL`: 24 `FUN_*` remain.
- `MCM.DLL`: 82 `FUN_*` remain.
- `MOSCOMP.DLL`: 144 `FUN_*` remain.
- `MPCCL.DLL`: 164 `FUN_*` remain.
- `MOSCP.EXE`: 243 `FUN_*` remain.
- `MVUT14N.DLL`: 1 documented non-FUN entry (alignment stub in `0x7e83198e`).

Every function in scope still carries a structural plate (signature,
caller/callee counts, dominant Win32 / project imports, string
samples). Completed binaries are fully named; remaining work is tracked
in the per-binary `next_priorities` lists.
