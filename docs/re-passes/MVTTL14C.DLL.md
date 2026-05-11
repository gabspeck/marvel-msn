# MVTTL14C.DLL — total-decomp coverage

Image base `0x7E840000`. MEDVIEW wire client — owns the MPC pipe to
MOSCP.EXE for title open, vaResolve, HFS read, async notification.
Also hosts the per-DLL MSVC C runtime (heap arena allocator, atexit
table, mbcinfo, parse_cmdline, lowio init).

## Function inventory (232 total)

- 232 functions deep-annotated (181 hand-named + 51 still using a
  meaningful inherited or session-2/4 name).
- 0 `FUN_*` remain after session 5.
- 3 thunks (kept as-is).

## Annotation deltas across sessions

| Pass | Delta |
|------|-------|
| Bulk plate (session 1) | 223 plates emitted; 9 hand plates preserved. |
| Deep line comments (session 2/4) | 1824 PRE call-site comments + 40 EOL string-ref comments across 232 functions. |
| Hand annotation (session 5) | 56 final FUN_ entries deep-annotated: rename + plate + targeted PRE/EOL block headers. |

Three FUN_ entries kept their canonical names with a low-confidence
plate (read-sides not located in this binary):

| Address | Reason |
|---------|--------|
| `0x7e843bd9` | SEH-shape table-pointer install at `_DAT_7e851810`; read-side classes (hrAttachToService, fDetachFromService, MVPumpHfcContentNotifications) still pending. |
| `0x7e843c5d` | Single-DWORD `.CRT$XCU` clear of `DAT_7e8517c8`; only one ref, read-side not in this DLL. |
| `0x7e848f03` | Body identical to `PictureSinkList_Destroy`; vtable `PTR_FUN_7e84c474` owner class not located. |

## Wire surface (per docs/MEDVIEW.md)

| Selector | Symbol | Address | Role |
|---------:|--------|---------|------|
| `0x00` | `TitleValid` | `0x7E8423AD` | sync title-slot validity probe (IID-less) |
| `0x01` | `TitleOpenEx` | `0x7E842D4E` | title open + dynamic body |
| `0x02` | `TitleClose` | `0x7E842C3A` | refcount-gated close |
| `0x03` | `TitleGetInfo` | `0x7E842558` | local cache + remote info_kinds |
| `0x04` | `TitleQuery` | `0x7E841653` | highlight-aware query |
| `0x05` | `vaConvertAddr` | `0x7E841D64` | addr → va (NotificationType3 kind=2) |
| `0x06` | `vaConvertHash` | `0x7E841E9A` | hash → va (NotificationType3 kind=1) |
| `0x07` | `vaConvertTopicNumber` | `0x7E841FCF` | topic → va (NotificationType3 kind=0) |
| `0x08` | `WordWheelQuery` | `0x7E849E99` | WordWheel query |
| `0x09` | `WordWheelOpenTitle` | `0x7E849328` | WordWheel open |
| `0x0A` | `WordWheelClose` | `0x7E8495B1` | WordWheel close |
| `0x0B` | `WordWheelPrefix` | `0x7E849935` | prefix probe |
| `0x0C` | `WordWheelLookup` | `0x7E849658` | ordinal → string (NotificationType1) |
| `0x0D` | `KeyIndexGetCount` | `0x7E849A27` | key match count |
| `0x0E` | `KeyIndexGetAddrs` | `0x7E849B6E` | key addresses (dynamic stream) |
| `0x0F` | `fKeyIndexSetCount` | `0x7E849D8A` | count hint push |
| `0x10` | `HighlightsInTopic` | `0x7E841526` | highlight blob (dynamic stream) |
| `0x11` | `addrSearchHighlight` | `0x7E8413FE` | sync highlight key → addressToken |
| `0x12` | `HighlightDestroy` | `0x7E841180` | release highlight context |
| `0x13` | `HighlightLookup` | `0x7E841235` | refresh highlight (NotificationType2) |
| `0x15` | `HfcNear` | `0x7E84589F` | cache-near resolve (NotificationType0) |
| `0x16` | `HfcNextPrevHfc` | `0x7E845ABB` | next/prev topic (NotificationType0) |
| `0x17` | `MVAsyncSubscriberSubscribe` | `0x7E844EE6` | open type-N stream |
| `0x18` | `MVAsyncSubscriberUnsubscribe` | `0x7E844FE3` | close type-N stream |
| `0x1A` | `HfOpenHfs` / `BaggageOpen` | `0x7E847656` / `0x7E848205` | HFS file open |
| `0x1B` | `LcbReadHf` / `LcbReadHfProgressive` / `BaggageRead` | `0x7E847C45` / `0x7E847DF6` / `0x7E84818E` | HFS read |
| `0x1C` | `RcCloseHf` / `HfsCloseRemoteHandle` / `BaggageClose` | `0x7E847BAD` / `0x7E847BD8` / `0x7E848023` | HFS close |
| `0x1D` | `RcGetFSError` | `0x7E847F2B` | last filesystem error |
| `0x1E` | `TitlePreNotify` | `0x7E843941` | local + wire opcode dispatch |
| `0x1F` | `hrAttachToService` | `0x7E844114` | handshake (immediate `0x1F`) |
| `0x14`, `0x19`, `0x20`–`0x2A` | (none) | — | dead — zero call sites; see `docs/MEDVIEW.md §6e` |

Master flag `DAT_7e84e2fc` (per memory `project_medview_master_flag`)
gates HfcNear / vaConvert*; requires reply pattern `0x87 0x88` not
`0x87` alone. Without it, `MVCheckMasterFlag` returns 0 and content
selectors never fire.

## Subsystems wired up this pass

- **HighlightCache** — head DAT_7e851468, RegisterEntry / DeserializeAndRegister / StaticInit.
- **MVGlobalVaAddrCache** — three Kind heads at DAT_7e851470/4/8, StaticInit.
- **Info6eCache** — head DAT_7e85147c, StaticInit.
- **HfcCache** — InsertOrdered (ordered by va), DispatchContentNotification (handles 0xa5/0xbf/0x37 records).
- **PictureSinkList family** — PictureSink_BaseConstruct/Destroy, PictureSinkList_PushHead/RemoveAndDestroy/Destroy, PictureSink_Destroy.
- **PictureTransfer / MediaTransferList** — PictureTransfer_Destroy (composite outer object), MediaTransferList_StaticInit/Destroy (singleton at DAT_7e851a20).
- **WordWheelCache** — head DAT_7e851a58, StaticInit.
- **MVTitle storage** — MVTitle_BuildStorageFileName, TryDeleteFileExclusive, MV_strtoui64hex, MV_IsValidIdentifier.
- **MV CRT** — CRT_InitOrTerm (DllMain), CRT_AdjustHeapLimitsForWin32s, CRT_ReleaseHeapArenas, CRT_InitTlsAndPerThreadData / FreeTlsAndPerThreadData, CRT_FreeMtCriticalSections / InitMtCriticalSections, CRT_InitEnvironmentVector, CRT_InitArgvFromCommandLine, CRT_parse_cmdline, CRT_InitMBCInfoFromLocale, CRT_InitLowIoFromStartupInfo, _setmbcp / _setmbcp_resolveCP / _setmbcp_lcidForCP / _setmbcp_clearTables, _calloc_lk, MVHeap_realloc_lk, MVHeap_TryCoalesceForward, MVHeap_msize_lk, MVHeap_BlockUsableSize, _onexit_lk, atexit, _cexit, __allshl_iter.
- **Wait & UI** — MVWaitVtable_PollWithModalPrompt, ModemInProgress_DialogThreadProc.
- **Misc** — MV_GetLastErrorMessage, MV_GlobalAllocStringCopy, MVCSObject_AtomicSwapField20.

## Imports surface

USER32 / KERNEL32 (handle / sync), MPCCL (RPC framing), MVCL14N (callbacks).

## Per-function status

Worklist: `scratch/annotate-worklist/MVTTL14C.DLL.txt`
Progress: `scratch/annotate-progress/MVTTL14C.DLL.json`
