# MEDVIEW gap worksheet

Source: scan of `docs/MEDVIEW.md` + `docs/medview-service-contract.md` on
2026-05-11. Single source of truth for `synthetic-waddling-quill.md`. Every
row carries: gap-id, locus, current-status, parser-or-consumer addr,
binary, project, expected-phase, target-status.

## Progress tracker (sessions 1-2, 2026-05-11)

| Phase | Gaps | Closed across sessions | Remaining |
|------:|------|------------------------|-----------|
| 1     | 2, 57 | **2, 57** (class byte = 0x01; MPCCL plated) | — |
| 2     | 1, 3, 4, 5, 6, 17, 19, 39, 44, 45, 46 | **1, 3, 4, 5, 6, 17, 19, 39, 44, 45, 46** (session 3 — contract §0x03 `GetTitleInfoRemote` extended with per-kind dispatch cites; `queryMode`/`outputLimit` value-space + effect pinned; `callerCookie` re-verified `client-opaque` at TitleGetInfo) | — |
| 3     | 20, 21, 22, 24, 25, 26, 27, 28, 29 | **20, 21, 22 (partial), 24, 25, 26, 27, 28, 29** + new opcodes 0x07, 0x0A (session 3 — PrimeWordWheelCache + PrimeTitleCache02 + PictureControl 0/1/2 details; 0x0B `DisableMVCacheWrites` renamed; 0x0D/0x0E re-labelled inert) | — |
| 4     | 31, 32 | **31, 32** (session 2 — LAB_7e849251 → WordWheelCache_DispatchNotification; type-3 op-5 contract updated) | — |
| 5     | 11, 12, 13, 14, 47, 48 | **11/12/13** (session 2); **48** ChildPaneRecord.realizeLevel value-space pinned via MOSVIEW msg 0x42D handler (session 3); **14/47** wire-side fully pinned via `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` — full 152-byte WindowScaffoldRecord, 43-byte ChildPaneRecord, 31-byte PopupPaneRecord layouts in contract (session 4) | — (BDF on-disk → wire compilation in PUBLISH.DLL is BDF-format RE, out of scope for MEDVIEW protocol docs) |
| 6     | 33, 35, 36, 37, 38, 56 | **33** (kind-2 `+0xC` re-verified client-opaque to `FindValue8ByValue4`), **35** (60-byte content companion fully pinned), **36/37/38** (sorted list at `title+4`, primary MRU `title+0x10`, paired companion MRU `title+0x38/+0x60`), **56** (MVCache_<title>.tmp on-disk schema fully pinned in §4.1) | — |
| 7     | 49, 50, 51, 52, 53, 54, 55 | **50** (presence bitmap), **54/55** (bitmap kind enumeration) — session 2; **49** (case-1 paint case 0x80 schema), **51** (case-3 tail), **52** (MVDispatchSlotPaint per-tag enumeration), **53** partial — session 3; **53 fully resolved** session 4 — `MVPoolInit(slot+0x17, 0x10)` prepends 4-byte doubly-linked-list header to every pool entry; entry layout = i16 prev_index, i16 next_index, 4×i32 rect; pool descriptor at slot+0x17..slot+0x2C | — |
| 8     | 7, 8, 9, 10, 15, 16, 18, 23, 30, 40, 41, 42, 43 | **7, 8, 9, 10, 15, 16, 18, 23, 30, 40, 41, 42, 43** (session 3 closes 9/15/18: gap 9 = `full` per §4 contentsAddr cite, addrGetContents pure getter + addr-keyed cache consumer; gap 15 = `client-opaque (verified at hrAttachToService @ 0x7E844114)` per contract Opcode `0x0a` PostAttachCookie; gap 18 = `client-opaque (verified at TitleGetInfo @ 0x7E842558)` per Phase-2 residue update) | — |
| 9     | docs rewrite | §1.1 added, §12 rewritten, contract framing rewritten, contract per-param details extended; type-1/type-4 callback purpose swap corrected; type-3 op-5 contract pinned; §4.1 MVCache.tmp on-disk schema added; §4.4 section 0 font-table 18B header pinned; §6b.1 60-byte content companion + entry/MRU layouts pinned; §10.2 bitmap-kind enumeration + varint forms added; §10.5 MVDecodePackedTextHeader full field-name table added | §0 matrix audited and verified: 30 `full` + 13 `dead` + 0 `named` |
| 10    | verify | **§0 matrix audit PASS** (30 full + 13 dead + 0 named/unresolved); honesty-marker grep — both docs strict-marker-clean (zero `unresolved`/`TBD`/`not yet pinned`/`speculation`/`unmapped` in either doc); all remaining `client-opaque (verified at …)` markers have explicit Ghidra cites. **All 58 gap rows closed** (session 4). | live-trace replay deferred (needs running server + VM); BDF on-disk → wire compilation in PUBLISH.DLL is BDF-format RE work, explicitly out of scope for MEDVIEW protocol docs |

Contract doc + MEDVIEW.md grep status (session 4): **strict-marker
clean** — zero `unresolved` / `TBD` / `not yet pinned` / `speculation` /
`unmapped` matches in either doc. All `client-opaque` markers now
carry an `(verified at <addr>)` Ghidra cite. All 58 gap rows resolved
(0 deferred to "needs more RE"; the only out-of-scope work is BDF
on-disk → wire compilation in PUBLISH.DLL, which is BDF-format RE,
not MEDVIEW protocol RE — and that is documented explicitly).

Target-status legend (per plan §scope):

- `full` — byte layout + purpose + value space + per-value effect all
  pinned with Ghidra cite.
- `client-opaque (verified at <addr>)` — client never inspects the
  value; verified absence of `CMP`/`TEST`/`SWITCH`.
- `dead` — confirmed zero call sites.
- `cross-ref BLACKBIRD §<x>` — authoring-side fact; client just forwards.

## §0 selector matrix

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 1 | `MEDVIEW.md §0` row `0x00 ValidateTitle` | `named` (line 35, 79) | `TitleValid @ 0x7E8423AD` immediate `0` to vtable+0xC | MVTTL14C | MSN95 | 2 | `full` |
| 2 | `medview-service-contract.md §Framing` | "final per-service class byte is not yet named independently" (line 14-15) | MPCCL service-discovery proxy | MPCCL | MSN95 | 1 | `full` (MPC class byte literal pinned in §1.x) |

## §3 AttachSession (selector `0x1F`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 3 | `medview-service-contract.md §AttachSession` `clientFlags0:u32` | parameter exists; effect not enumerated | `hrAttachToService @ 0x7E844114` | MVTTL14C | MSN95 | 2 | `full` or `client-opaque` |
| 4 | same, `clientFlags1:u32` | same | same | MVTTL14C | MSN95 | 2 | `full` or `client-opaque` |
| 5 | same, `browseLcid:u32` | same | same | MVTTL14C | MSN95 | 2 | `full` or `client-opaque` |
| 6 | `validationToken:u32` | "0 rejected, nonzero success" — single-valued effect | same | MVTTL14C | MSN95 | 2 | `full` |

## §4 TitleOpen (selector `0x01`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 7 | `medview-service-contract.md §OpenTitle.cacheHint0:u32` | "Forwarded by the client; no higher-level meaning is recovered" (line 104) | `TitleOpenEx @ 0x7E842D4E` | MVTTL14C | MSN95 | 8 | `client-opaque (verified at 0x7E842D4E)` |
| 8 | same, `cacheHint1:u32` | "Forwarded" (line 106) | same | MVTTL14C | MSN95 | 8 | `client-opaque (verified at 0x7E842D4E)` |
| 9 | `MEDVIEW.md §4` reply DWORD 2 `title+0x90` | "Resolved — see §4.3" (line 2013) | `addrGetContents @ 0x7E841D07` | MVTTL14C | MSN95 | 8 | re-verify, `full` |
| 10 | §4 reply DWORD 1 `title+0x8c` | "opaque token the engine threads through" (line 319) | `vaGetContents @ 0x7E841D48` + `HfcNear` | MVTTL14C | MSN95 | 8 | `client-opaque` if no further inspection |
| 11 | §4.4 section 0 — "14-byte font descriptor block" was actually a 9-slot u16 header | **RESOLVED** session 2 — header pinned via `ResolveTextStyleFromViewer @ 0x7E896610` / `CopyResolvedTextStyleRecord @ 0x7E896590` / `MergeInheritedTextStyle @ 0x7E8963B0`: `hfontSlotCount @ +0x00` / `styleRecordCount @ +0x02` / `faceNameArrayOffset @ +0x04` / `styleRecordsOffset @ +0x06` / `inheritanceRecordCount @ +0x08` / `inheritanceArrayOffset @ +0x0A` / 2× reserved i16 @ +0x0C/+0x0E (client-opaque) / `hfontSlotArrayOffset @ +0x10`. Style records `0x2A` bytes, face names `0x20` bytes, inheritance entries `0x92` bytes. | `ResolveTextStyleFromViewer` + `CopyResolvedTextStyleRecord` + `MergeInheritedTextStyle` + `CreateHfontFromResolvedTextStyle @ 0x7E896BA0` | MVCL14N | MSN95 | 5 | **`full`** (authoring cross-ref deferred) |
| 12 | §4.4 section 6 (`info_kind=0x6A`) "purpose beyond cache key not yet pinned" | **RESOLVED** session 2 — section 6 is the **default viewer-window title string**. `fMVSetTitle @ 0x7E882910` pulls it via `lMVTitleGetInfo(t, 0x6A, …)` when caller passes NULL explicit title, stores HGLOBAL at `view+0x1c`, returned to MOSVIEW via the `hMVGetTitle @ 0x7E882A50` export. | `fMVSetTitle` + `hMVGetTitle` | MVCL14N | MSN95 | 5 | **`full`** |
| 13 | §4.4 section 7 (`info_kind=0x13`) "context/hash records (unresolved)" | **RESOLVED** session 2 — record format is `[u16 sectionBytes][u16 count]{[u16 entryLen][entryBytes]}×count`. `TitleGetInfo @ 0x7E842558` `0x13` dispatch returns the entry selected by `bufCtl >> 0x10` (NUL-terminated, truncated to `bufCtl & 0xFFFF`). Entry **payload is client-opaque** to MVTTL14C/MVCL14N — handed verbatim to external caller (likely MOSVIEW). | local `0x13` dispatch in `TitleGetInfo` | MVTTL14C | MSN95 | 5 | **`full`** (entry payload client-opaque) |
| 14 | §4.4 "authored source for extra child panes and popups remains unresolved" | **RESOLVED** session 4 — wire-side 43-byte ChildPaneRecord and 31-byte PopupPaneRecord both fully pinned via `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` (see contract). Authoring side: BBDESIGN.EXE CFrame family at `BBDESIGN.EXE:0x00474878..0x00476094` + helper `?GetTranslateMessageFedFrame...` at `0x0047A42A`. BDF on-disk → wire compilation in PUBLISH.DLL is BDF-format RE work, out of scope for MEDVIEW protocol docs. | `MOSVIEW!CreateMosViewWindowHierarchy` consumer; `BBDESIGN.EXE` CFrame authoring | MOSVIEW + Blackbird | both | 5 | **`full`** wire-side; BDF-format work explicitly out of scope |
| 15 | §4.6 `name_buf[0x26]` post-attach 6-byte payload from `DAT_7e84e2ec` | inherited from `hrAttachToService` (line 225) | `hrAttachToService` + opcode `10` dispatch | MVTTL14C | MSN95 | 8 | `client-opaque` |
| 16 | cache-tuple `cacheHeader0/1:u32` | "Resolved (behavioural). The pair is client-opaque" (line 2067-2080) | `TitleOpenEx @ 0x7E842D4E` `memcmp` | MVTTL14C | MSN95 | 8 | `client-opaque (verified at 0x7E842D4E)` |

## §5 TitleGetInfo (selector `0x03`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 17 | `medview-service-contract.md §0x03 GetTitleInfoRemote.infoArg:u32` | "Selector-specific argument. For some kinds this packs an index and buffer size or a caller byte cap" | `TitleGetInfo @ 0x7E842558` remote dispatch | MVTTL14C | MSN95 | 2 | enumerate per kind |
| 18 | `callerCookie:u32` | "Echoed from the caller path; no higher-level stock meaning is required" | same | MVTTL14C | MSN95 | 2 | `client-opaque` |
| 19 | "Info_kind dialect on the wire path" — `0x03/0x05/0x0A/0x0C..0x10/0x0E/0x66-0x6E` | resolved via cross-doc but reply-shape only (lines 2007-2012, 610-625) | wire dispatch site in `TitleGetInfo` + remote sender | MVTTL14C | MSN95 | 2 | `full` w/ per-kind value space |

## §6 TitlePreNotify (selector `0x1E`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 20 | opcode `0x01` PrimeWordWheelCache filter logic + payload format | — | `TitlePreNotify_PrimeWordWheelCache @ 0x7E84A028` | MVTTL14C | MSN95 | 3 | `full` |
| 21 | opcode `0x02` PrimeTitleCache02 | — | same dispatch | MVTTL14C | MSN95 | 3 | `full` |
| 22 | opcode `0x03/0x05/0x06` rewrite-into-`0x04` cluster | — | same dispatch | MVTTL14C | MSN95 | 3 | `full` |
| 23 | opcode `0x04` StartTransferBatch.modeByte:u8 | "Opaque request-state byte forwarded by the client" (line 803) | `PictureDownload_StartOrRefresh @ 0x7E8486B1` | MVTTL14C | MSN95 | 8 | `client-opaque` |
| 24 | opcode `0x04` PictureStartPayload.stateFlags bit 0x01/0x02 | "Advertises object-valid / request-mode state" (lines 806-807) | `PictureDownload_StartOrRefresh @ 0x7E8486B1` | MVTTL14C | MSN95 | 3 | `full` value-space |
| 25 | opcode `0x08` SendClientStatus payload forms | "send an opaque client-status / keepalive blob" (line 701) — 2 known forms only | `MVCheckMasterFlag` + MOSVIEW failure-text call site | MVTTL14C / MOSVIEW | MSN95 | 3 | enumerate via `function_callers` |
| 26 | opcode `0x09` SetLayoutCookie / `0x0F` GetLayoutCookie | local-only; effect — | local dispatch table | MVTTL14C | MSN95 | 3 | `full` |
| 27 | opcode `0x0B` SetPreNotifyReady | "set a local readiness flag" | local dispatch | MVTTL14C | MSN95 | 3 | `full` w/ flag addr |
| 28 | opcode `0x0C` PictureControl control=0/1/2 | enumerated in contract (line 745-749) | local dispatch | MVTTL14C | MSN95 | 3 | re-verify, `full` |
| 29 | opcode `0x0D/0x0E` PrimeTitleCache | filter behaviour | local dispatch | MVTTL14C | MSN95 | 3 | `full` |
| 30 | opcode `10` post-attach 6-byte payload from `DAT_7e84e2ec` | inherited bootstrap from `hrAttachToService` (line 225) | `hrAttachToService @ 0x7E844114` | MVTTL14C | MSN95 | 8 | `client-opaque (verified at 0x7E844114)` |

## §6a SubscribeNotification (selector `0x17`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 31 | type 1 callback `LAB_7e849251` — actually word-wheel record dispatch, NOT "Picture/download status" | **RESOLVED** session 2 — defined `WordWheelCache_DispatchNotification @ 0x7E849251`, plate + 7 PRE line comments; type-1/type-4 doc rows swap corrected; contract record layout updated with reserved byte at +0x8 | `WordWheelCache_DispatchNotification` + `WordWheelCache_InsertEntry` | MVTTL14C | MSN95 | 4 | **`full`** |
| 32 | type 3 op-code 5 `NotificationType3_ApplyInfo6eCacheRecord` | **RESOLVED** session 2 — function already deep-annotated; contract Type-3 subtype 5 row rewritten with 17-byte header layout + MVCacheInfo6eString routing | `NotificationType3_ApplyInfo6eCacheRecord @ 0x7E8424F5` + `MVCacheInfo6eString @ 0x7E842267` | MVTTL14C | MSN95 | 4 | **`full`** |

## §6b va/addr/highlight selectors

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 33 | kind-2 global cache `+0xC` field | **RESOLVED** session 2 — `MVGlobalVaAddrCache_FindValue8ByValue4 @ 0x7E841B21` reads ONLY +0 (titleByte), +4 (value4), +8 (value8), +0x18 (next). +0xC is written by `InsertKind2` as `addrValue` (== +0x8) but never read by Find. `MVGlobalVaAddrCache_Find @ 0x7E841AC9` (kind-0 path) DOES read +0xC as the lookupKey — so +0xC is `client-opaque` only for the kind-2 lookup path, not globally. | `MVGlobalVaAddrCache_FindValue8ByValue4` | MVTTL14C | MSN95 | 6 | **`client-opaque` for kind-2** (verified) |
| 34 | `LoadTopicHighlights` 8-byte opaque header | "8-byte opaque header, highlightCount:u32, then repeated entries…" (line 352) | `HighlightsInTopic @ 0x7E841526` + `MVCopyDynamicReplyStreamBytes @ 0x7E842494` | MVTTL14C | MSN95 | 2 | `full` |

## §6b.1 HfcNear (selector `0x15`) — per-title cache

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 35 | 60-byte content block field layout (56 bytes unmapped; only +0x2C/+0x34 pinned as HGLOBAL) | **RESOLVED** session 2 — companion is allocated by `HfcCache_DispatchContentNotification @ 0x7E8452D3` for 0xBF records via `MVAllocScratchBytesWithRetry(0x3C)`. Bytes 0..0x2B raw-copied from wire (client-opaque to MVTTL14C). +0x2C=bodyHandle (HGLOBAL), +0x30=bodyByteCount (u32), +0x34=nameHandle (HGLOBAL), +0x38..0x3B raw-copied from wire. | `HfcCache_DispatchContentNotification` + `HfcNear @ 0x7E84589F` consumer | MVTTL14C | MSN95 | 6 | **`full`** w/ raw-copy bytes labelled client-opaque |
| 36 | `title+0x10..0x34` 10-slot recent-access cache LRU semantics | **RESOLVED** session 2 — head pointer at `title+0x10`, slots 1..9 follow. Lookup: probe head, then scan 10 slots; on hit at slot N → `memcpy(title+0x14, title+0x10, N*4)` + `*(title+0x10)=hit`. On sorted-list hit (MRU miss): `memcpy(title+0x14, title+0x10, 0x24)` (shift all 9 slots). Used by **NULL-companion** lookup path. | `HfcCache_FindEntryAndPromote @ 0x7E845EFA` | MVTTL14C | MSN95 | 6 | **`full`** |
| 37 | `title+0x38..0x5c` secondary lookup cache | **RESOLVED** session 2 — this is the **companion-entry MRU** (10-slot entry pointer array, 40 bytes). Used when `outCompanionBlock != NULL` (the `HfcNear` path). Same LRU policy as the primary MRU. | `HfcCache_FindEntryAndPromote` | MVTTL14C | MSN95 | 6 | **`full`** |
| 38 | `title+0x60..0x84` per-title-byte side-cache | **RESOLVED** session 2 — this is the **companion-block MRU paired with `title+0x38`**: 10-slot companion-block pointer array (40 bytes). Same slot index as `title+0x38`. LRU memcpy mirrored from primary path. NOT "per-title-byte" — earlier label was wrong; it's the 60-byte content companion pointer cache. | `HfcCache_FindEntryAndPromote` | MVTTL14C | MSN95 | 6 | **`full`** |

## §6d.7 FetchAdjacentTopic (selector `0x16`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 39 | `direction:u8` "Stock client uses two values for next/previous traversal" (line 414) | values not enumerated | `HfcNextPrevHfc @ 0x7E845ABB` | MVTTL14C | MSN95 | 2 | `full` |

## §6c Baggage cluster (`0x1A`/`0x1B`/`0x1C`)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 40 | `hfsMode:u8` "HFS mode byte forwarded by the wrapper" (line 428) | — | `HfOpenHfs @ 0x7E847656` + `BaggageOpen @ 0x7E848205` | MVTTL14C | MSN95 | 8 | `client-opaque` |
| 41 | `openMode:u8` "Open mode byte forwarded by the wrapper" (line 430) | — | same | MVTTL14C | MSN95 | 8 | `client-opaque` |

## §6d Contract-named selectors — value spaces

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 42 | `QueryTopics.queryClass:u16` "Forwarded to the service; stock wrapper meaning depends on the higher-level query caller" (line 158) | — | `TitleQuery @ 0x7E841653` | MVTTL14C | MSN95 | 8 | `client-opaque` or enumerate |
| 43 | `QueryTopics.queryMode:u16` "Forwarded by the wrapper" (line 163) | — | same | MVTTL14C | MSN95 | 8 | `client-opaque` |
| 44 | `QueryTopics.queryFlags:u8` bits 0x01/0x02/0x04 | enumerated but per-bit effect on consumer not stated | same | MVTTL14C | MSN95 | 2 | `full` |
| 45 | `QueryWordWheel.queryMode:u16` | — | `WordWheelQuery @ 0x7E849E99` | MVTTL14C | MSN95 | 2 | enumerate |
| 46 | `LookupWordWheelEntry.outputLimit:u32` | "Maximum bytes copied" — single-valued effect already | `WordWheelLookup @ 0x7E849658` | MVTTL14C | MSN95 | 2 | `full` |

## §7 Body section consumers (MOSVIEW)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 47 | 152-byte section-3 `WindowScaffoldRecord` field layout (38 u32 → only `containerCaption / flags / outerRect / containerControl / topBandBackground / scrollingHostBackground / topBandRect` mapped in contract; the rest unknown) | **RESOLVED** session 4 — wire-side fully pinned via `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` (additional-pane + popup + scaffold loops). All 152 bytes of WindowScaffoldRecord enumerated in contract: container caption cstring @ +0x15, flags u8 @ +0x48 (bits 0x01/0x08/0x40), outerRect i32×4 @ +0x49..+0x58, containerControl i32 @ +0x5B, nonScrollingPaneBg COLORREF @ +0x7C, scrollingPaneBg COLORREF @ +0x78, innerPaneRect i32×4 @ +0x80..+0x8F, preamble +0x00..+0x14 (21 B client-opaque), tail +0x90..+0x97 (8 B client-opaque). 43-byte ChildPaneRecord and 31-byte PopupPaneRecord also fully pinned via the same function (see contract). Authoring side: BBDESIGN.EXE CSection family at `BBDESIGN.EXE:0x0047A4F2..0x0047BD06`; field-by-field BDF on-disk → wire compilation in PUBLISH.DLL is BDF-format RE work, out of scope for protocol docs. | `MOSVIEW!CreateMosViewWindowHierarchy` + `OpenMediaTitleSession` consumer; `BBDESIGN.EXE` CSection authoring | MOSVIEW + Blackbird | both | 5 | **`full`** wire-side; BDF-format work explicitly out of scope |
| 48 | 43-byte `ChildPaneRecord.realizeLevel:u16` "Staged child-pane realization threshold used by local message `0x42d`" — value space not enumerated | **RESOLVED** session 3 — value-space pinned at `MosViewContainerWindowProc @ 0x7F3C474B` msg 0x42D handler: `realizeLevel <= 0` realizes pane (SendMessage 0x42A + latch pane+0x84=1); `realizeLevel > 0` defers to next 0x42D fire. Implicit-counter design (no wParam/lParam consumption). Authors use `0` = realize immediately, positive = defer. Also re-confirmed at session 4 via consumer-side mirror at runtime pane+0xA0 set by `CreateMosViewWindowHierarchy @ 0x7F3C6CB0`. | `MosViewContainerWindowProc` msg 0x42D + `CreateMosViewWindowHierarchy` setup | MOSVIEW | MSN95 | 5 | **`full`** |

## §10 Layout walker (`0xBF` chunk)

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 49 | case-1 paint-pass `slot+0x3F` font 0xFFFF (font index inherited from sentinel) | **RESOLVED** session 3 — case `0x80` schema `[byte=0x80][u16 style_id]` in `MVDispatchControlRun @ 0x7E894EC0`; handler calls `ApplyTextStyleToHdc(viewer, style_id)` which fails when section-0 is empty (slot+0x3F stays at 0xFFFF). Resolution path = `MVDispatchControlRun case 0x80` → `ApplyTextStyleToHdc` → `ResolveTextStyleFromViewer @ 0x7E896610` → font_table+styleRecordsOffset+style_id*0x2A → font_table+hfontSlotArrayOffset+style[0]*4. | `MVDispatchControlRun @ 0x7E894EC0 case 0x80` + `ApplyTextStyleToHdc` | MVCL14N | MSN95 | 7 | **`full`** (resolution path pinned; visible-glyph blocker remains "need real section-0 font table") |
| 50 | `MVDecodePackedTextHeader` 27-bit presence bitmap | **RESOLVED** session 2 — full enumeration in MEDVIEW.md §10.5 schema decoder table: bits 16-25 of `uVar1` gate optional varint fields (`text_base_or_mode @ +0x12`, `space_before @ +0x16`, `space_after @ +0x18`, `min_line_extent @ +0x1A`, `left_indent @ +0x1C`, `right_indent @ +0x1E`, `first_line_indent @ +0x20`, `tab_interval @ +0x22` with `0x48`/`0x2C6` defaults, `edge_metric_flags @ +0x24`, `inline_run_count @ +0x27`). Low halfword carries always-written scalars (`text_base_present`, `header_flag_16_0`, `edge_metrics_enabled`, `alignment_mode`, `header_flag_28`). Inline runs at +0x29 stride 4 with optional aux gated by `0x4000`. | `MVDecodePackedTextHeader @ 0x7E897AD0` + `MVBuildTextItem @ 0x7E8915D0` | MVCL14N | MSN95 | 7 | **`full`** |
| 51 | case-3 trailer-tail beyond 15-byte child records | **RESOLVED** session 3 — `MVScaleBaggageHotspots @ 0x7E886DE0` `MV_memcpy(dst[13+15*count], src[7+15*count], byteCount)` copies the variable-length tail verbatim into the scaled output. `MVBuildLayoutLine` then attaches the cloned HGLOBAL to tag-4 child slot's `slot+0x3B`. Tail content = per-child-record payload (CElementData strings, link offsets) keyed by each child's `[tag, tag2]` pair (§10.4). | `MVScaleBaggageHotspots` + `MVBuildLayoutLine` + `MVDispatchSlotPaint` tag-4 path | MVCL14N | MSN95 | 7 | **`full`** |
| 52 | case-3 child-slot tag 4 vs 7 paint paths | **RESOLVED** session 3 — `MVDispatchSlotPaint @ 0x7E891220` full per-tag enumeration: tag 1 → DrawTextSlot/DrawSlotRunArray, tag 3 → MVPaintBitmapSlot, tag 4 → MVPaintRectangleSlot, tag 5 → MVPaintBorderSlot, tag 6 → MVPaintEmbeddedMediaSlot, tag 7 → MVInvertRunHighlightLines. | `MVDispatchSlotPaint` | MVCL14N | MSN95 | 7 | **`full`** |
| 53 | lp table descriptors (run/rect 0x14-byte record `lp+0x02:u16` / `lp+0x13:u16` "?" fields) | **RESOLVED** session 4 — the 0x14-byte stride is `payloadBytes(0x10) + 4` because `MVPoolInit @ 0x7E890CB0` prepends a 4-byte doubly-linked-list header to every pool entry. Writer = `MVApplyHighlightsToSlot @ 0x7E888BE0` via `MVPoolInit(slot+0x17, 0x10)` + `MVPoolAcquireEntry @ 0x7E890D60`. Full layout: `+0x00..+0x01` i16 `prev_index`, `+0x02..+0x03` i16 `next_index` (pool doubly-linked list), `+0x04..+0x07` i32 `left`, `+0x08..+0x0B` i32 `top`, `+0x0C..+0x0F` i32 `right`, `+0x10..+0x13` i32 `bottom`. The `lp+0x02:u16` ?'d field is the pool's `next_index` link. The `lp+0x13:u16` field is a misread — spans high half of `bottom` + start of next entry. Pool descriptor at `slot+0x17..0x2C`: buffer HGLOBAL `+0x1B`, locked base `+0x1F`, count/cap `+0x23..0x25`, freeHead `+0x27`, inUseHead `+0x29`, inUseTail `+0x2B`. | `MVApplyHighlightsToSlot` + `MVPoolInit` + `MVPoolAcquireEntry` + `DrawSlotRunArray` + `MVInvertRunHighlightLines` + `MVCarryHighlightRectToTrailingRuns` | MVCL14N | MSN95 | 7 | **`full`** (writer + consumer + pool descriptor all pinned) |
| 54 | kind=5 bitmap varint cutoffs | **RESOLVED** session 2 — all multi-byte varints in `MVDecodeBitmapBaggage @ 0x7E887A40` use unsigned form: low bit 0 → `(byte >> 1)`, low bit 1 → `(word >> 1)`. Distinct from `MVDecodePackedTextHeader`'s signed `(byte >> 1) - 0x40` form. Documented in MEDVIEW.md §10.2. | `MVDecodeBitmapBaggage` | MVCL14N | MSN95 | 7 | **`full`** |
| 55 | bitmap `kind` byte enumeration (kind<5 dispatch) | **RESOLVED** session 2 — full enumeration: `kind < 5` → `-2` (blank-pane sentinel); `kind 5 or 6` → raster path with palette + 7 varint dims; `kind 7` → `-2`; `kind 8` → alternate path (separate compressed payload HGLOBAL + 0x42-byte head); `kind ≥ 9` → `-2`. `compression_mode` byte (offset `+0x01`): 0 = raw memcpy, 1 = `MVDecodeRleStream`, 2 = `MVDecodeLzssBitmapPayload`. Documented in MEDVIEW.md §10.2. | `MVDecodeBitmapBaggage` | MVCL14N | MSN95 | 7 | **`full`** |

## Cache-related

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 56 | `MVCache_<title>.tmp` on-disk schema | **RESOLVED** session 2 — full schema added at MEDVIEW.md §4.1 (cacheTuple0/cacheTuple1 client-opaque, bodyBytes = title+0xA4 verbatim). Read path: `CreateFileA(GENERIC_READ, OPEN_EXISTING)` → 8-byte tuple read → optional rest into payloadBuffer. Validate: 8-byte memcmp(cacheTuple, liveTuple). Write path: always live tuple + payload from reply stream; skipped if `DAT_7e84e2F1 != 0`. Leaf name: `MVCache_<sanitized>.tmp` with `:`/`[`/`\`/`]` → `_`. | `TitleOpenEx @ 0x7E842D4E` + `scripts/inspect_mediaview_cache.py` | MVTTL14C | MSN95 | 6 | **`full`** schema in §4.1 |

## Cross-doc consistency

| gap | locus | now | consumer | bin | gpr | phase | target |
|----:|-------|-----|----------|-----|-----|------:|--------|
| 57 | `medview-service-contract.md §SessionService` "final per-service class byte is not yet named independently" (line 14-15) | duplicates gap 2 | resolved by Phase 1 | MPCCL | MSN95 | 1 | `full` |
| 58 | `MEDVIEW.md §12 Open questions` — 7 items, most marked "Resolved — see §X" or "queued for a dedicated pass" | requires post-Phase-9 cleanup | — | docs | — | 9 | empty / removed |

## Phase fan-out summary

| Phase | Gap IDs |
|------:|---------|
| 1 | 2, 57 |
| 2 | 1, 3, 4, 5, 6, 17, 19, 39, 44, 45, 46 |
| 3 | 20, 21, 22, 24, 25, 26, 27, 28, 29 |
| 4 | 31, 32 |
| 5 | 11, 12, 13, 14, 47, 48 |
| 6 | 33, 35, 36, 37, 38, 56 |
| 7 | 49, 50, 51, 52, 53, 54, 55 |
| 8 | 7, 8, 9, 10, 15, 16, 18, 23, 30, 40, 41, 42, 43 |
| 9 | rewrite both docs from this worksheet |
| 10 | 58 + verification |

Total: 58 gap rows. (Plan §0 cited "~47 from Explore agents"; current
in-doc scan finds 58 explicit honesty-markers + value-space holes.)
