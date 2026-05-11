# MVPR14N.DLL — total-decomp coverage

Image base `0x7E860000`. "Marvel Picture Renderer" — MVIMAGE child window
class plus the codec dispatch / image cache / asset loader the renderer
shares with WinHelp-derived embedded picture handling. Hosts:

- the **MVIMAGE** child window class (`MVIMAGEWndProc` and message handlers).
- a per-thread **ImageProcs registry** with three codecs registered at DLL
  attach: BMP, SHG (`lp` / `lP`), and a 1bpp-typed BMP variant that turns
  out to be the **WLT progressive picture** stream (CSG / CPG / progressive
  metafile / plain DIB sub-classes).
- the per-thread **image cache** + **busy-LRU eviction**.
- the **SHG / MRB sub-image** decoder family (DefaultShedRead/Render/Release,
  RLE / LZ77 expanders, hotspot table, kd-tree hit-test).
- the on-disk **PLY2** hotspot blob parser (`mvimagePrepareFromPointer`).
- a private **MS C runtime** (heap arenas, atexit, _setmbcp tables, parse_cmdline,
  TLS per-thread data, _amsg_exit message tables).

## Function inventory (216 total)

- 160 FUN_ deep-annotated this pass (renamed + plate; 0 remain).
- 31 originally-named exports / thunks / runtime symbols (preserved).
- 25 thunks (kept as-is).

## Annotation deltas across sessions

| Pass | Delta |
|------|-------|
| Bulk plate (session 1) | 209 plates emitted; 7 hand plates preserved. |
| Deep line comments (session 2/4) | 1,082 PRE call-site + 25 EOL string-ref comments across 191 functions. |
| Hand annotation (session 6) | 160 final FUN_ entries deep-annotated: rename + plate; family-grouped commits with full Ghidra `program_save` + per-function `scratch/annotate-progress` JSON updates. |

## Subsystems wired up this pass

- **MVIMAGE child window class** — `MVIMAGEWndProc` dispatch plus
  WM_CREATE (`MVIMAGE_OnCreateParseDirectives` — full directive grammar:
  CAPTION / HOTMACRO / HOTSPOTS / 16COLOR / FILENAME / FORCETYPE / NOPRINT /
  NOINVERT / COPYRIGHT), WM_PAINT (`MVIMAGE_OnPaint` →
  `MVIMAGE_RenderToDC`), WM_DESTROY (`MVIMAGE_OnDestroy`),
  WM_LBUTTONDOWN/UP (`MVIMAGE_SetInvertHotState`), get-natural-size
  (`MVIMAGE_OnGetNaturalSize`), copy / clipboard
  (`MVIMAGE_BuildClipboardObject`, `MVIMAGE_CopyToClipboard`,
  `MVIMAGE_RenderToHBITMAP`, `HBitmapToCFDIB`), hotspot message
  (`MVIMAGE_OnHotspotMessage` → `MVIMAGE_HotspotDispatch` with five
  WH_HOTSPOT_* commands).

- **Image-procs registry** — `ImageProcsRegistry_FindByThread` head
  `DAT_7e86c094`; `_GetOrCreateProcsBlock`, `_SetCacheCtrl`,
  `_GetCacheCtrl`, `_RemoveThread`, `_RemoveAllThreads`. Codec entries
  are 28-byte (next, Read, Render, Release, cookie, bpp, magic[4]).

- **Codec dispatch** — `ImageProcs_FindOrInsertByMagic`,
  `ImageProcs_MatchByMagic`, `ImageProcs_LookupByMagic` (per-thread
  fallback to thread-0 catch-all). Three default codecs installed via
  `MVIMAGE_RegisterClassAndCodecs` (BMP `"BM"`, SHG `"lp"`, MRB `"lP"`)
  and a fourth via `MVIMAGE_RegisterMonoBmpCodec` for the WLT
  progressive-picture variant.

- **Per-thread image cache** — `ImageCache_InitOrResize`,
  `_AcquireBusySlot`, `_PopBusyHead`, `_FlushBusyList`,
  `_LookupByPath`, `_LookupByCookie`, `_Destroy`. Slot pool linked
  by indices; busy list is FIFO (oldest-evicted-first).

- **Asset loader** — `MVIMAGE_LoadAssetBytes` resolves three prefix
  schemes: `!asset` (HFS baggage via `hMVBaggageOpen`), `+ID` (resource
  via `FindResourceA(RT_BITMAP)` with synthesised `BITMAPFILEHEADER`),
  bare filename (`mmioOpenA` + path resolution via
  `Path_ResolveAcrossSearchPath`). Auto-detects codec from header
  magic.

- **MVIMAGE_LazyLoadAndFinalizeSize** — first-paint loader: pulls
  asset bytes via `MVTitle::lMVTitleGetInfo(0x6a, …)`, splits
  HOTSPOTS-prefix tab, dispatches codec ReadProc, runs the optional
  hotspot replay, finalises natural cx/cy including caption/copyright
  measurement, and posts the new size to the host via
  `Hotspots_SetExtent`.

- **Hotspots table** — `Hotspots_Construct` (40-byte table backed by
  a chunked bump arena), `_GrowIndexedArray`, `_AddRecord`,
  `_BumpAlloc`. Three hotspot kinds (rect / circle / polygon) live
  in two parallel structures: a flat indexed array for tab traversal
  and a 2D kd-tree for hit-tests. The kd-tree uses
  `Hotspots_KdTreeInsert` (alternating x/y splits) for placement and
  `Hotspots_HitTestKdNode` / `_HitTestSubtree` /
  `_HitTestAllSubtrees` for hit-tests, with `DistSquared2D` for
  circles and `PointInPolygon` for regions.

- **Hotspot host messages** — `MVIMAGE_HotspotDispatch` implements
  the WH_HOTSPOT 0x7073 / 0x7074 / 0x7075 / 0x7078 / 0x7079 protocol;
  `Hotspots_FindNextVisibleByStep` powers the next/prev tab walk;
  `MVIMAGE_PaintHotspotDecorations` paints focus rects / push-stack
  overlays / inverted state. Public extension API:
  `mvimagePrepareFromPointer` parses a PLY2 (Polygon-2) blob via
  `Hotspots_ParsePLY2` and merges the existing instance hotspots
  in.

- **SHG / MRB Shed codec** (BM-magic generic + `lp` / `lP` SHG +
  the 0xC8/0xCC/0xE2/0xE3/0xE6/0xE7/0xEA/0xEB/0xEE/0xEF kind codes) —
  `Shed_DecodeSubImage` (per-record header parser),
  `Shed_DecompressRle` / `Shed_DecompressLz` (RLE and LZ77/LZSS
  decoders), `Shed_FreeSubImage`, `Shed_LoadAssetFromHFSorFile`
  (HFS module bound at runtime via `MVFS_LazyLoadModule`),
  `Shed_ParseHotspotsFromShg`, `Shed_CloneAbsoluteHotspotTable`,
  `Shed_ExtractMetafile`, `MapMode_HiMetricToPixels`. Includes the
  encoder counterparts `Shed_CompressRle` and
  `Shed_DecompressRleReverse` (orphans).

- **WLT progressive picture client** — registered by
  `MVIMAGE_RegisterMonoBmpCodec` against magic `"BM"` + bpp 1.
  `WltPicture_Read` allocates the 0x40-byte instance, `_Init` sets
  it up from MVTitle DownloadPicture handles, `_Release` /
  `_FreeState` tear it down. Three render-state subclasses keyed
  off the wire-bytes signature, with shared base sentinel vtable
  `PTR_LAB_7e86b030`:

  | Class | Signature | State size | Vtable | Decode | Paint |
  |-------|-----------|-----------:|--------|--------|-------|
  | `WltCsg`     | `'CSG'` / `'CPG'` at +0x0b | 0x50 | `PTR_FUN_7e86b000` | `WltCsg_DecodeIncremental` | `WltCsg_DecompressAndPaint` (uses `WLTPITDecompress`) + `WltCsg_PaintDIB` |
  | `WltMeta`    | progressive metafile signature at +0x04 | 0x6c | `PTR_FUN_7e86b048` | `WltMeta_DecodeIncremental` | `WltMeta_Blit` + `WltMeta_PlayPair` |
  | `WltSimple`  | none (≥ 400 bytes or fully arrived) | 0x48 | `PTR_FUN_7e86b018` | `WltSimple_DecodeIncremental` | `WltSimple_PaintDIB` (SetDIBitsToDevice / StretchDIBits) |

  Drives MOSCOMP `WLTPITCreateProgTransInfo` /
  `WLTPITInitHuffDecoder` / `WLTPITCompressHuffDecoder` /
  `WLTPITDecompress` / `WLTPITPaintDIB` /
  `WLTPITTerminateHuffDecoder` /
  `WLTPITDeleteProgTransInfo`. Async paint via auto-reset event +
  `PostMessageA(0x40f)` (`WltPicture_AsyncPaint` /
  `WltPicture_PaintNow`); resize via 0x411
  (`WltPicture_OnSizeChange` / `WltPicture_PostNewSize`); release-
  frames via 0x40d. Optional hotspot prefix consumed by
  `WltPicture_PrependHotspots` (handles both `"shg"` and `"ply"`
  variants).

- **MS C runtime** — full suite mirroring MVTTL14C: `CRT_InitOrTerm`
  (DllMain), `_AdjustHeapLimitsForWin32s`, `_FreeHeapArenas`,
  `_FreeTlsAndPerThreadData`, `_InitTlsAndPerThreadData`,
  `_InitMtCriticalSections`, `_FreeMtCriticalSections`,
  `_InitArgvFromCommandLine`, `_InitEnvironmentVector`,
  `_InitLowIoFromStartupInfo`, `CRT_parse_cmdline`,
  `_InitMBCInfoFromLocale`, `_setmbcp_resolveCP`,
  `_setmbcp_metaCPResolver`, `_setmbcp_lcidForCP`,
  `_setmbcp_clearTables`, `_FatalErrorAndExit`,
  `_amsg_exit_prefixSuffix`, `_amsg_exit_msgWrite`, `_amsg_exit_18`,
  `_lock`, `_unlock`, `_lock_atexit`, `_unlock_atexit`, `_doexit`,
  `_lockexit`, `_exit`. Heap: `malloc`, `malloc_base`, `_calloc_lk`,
  `_free_lk`, `_free_base`, `_heap_alloc`, `_heap_split`,
  `_heap_grow`, `_heap_reserve`, `_heap_commit`, `_heap_release`,
  `_heap_register_range`, `_heap_link_block`, `_heap_find_block`,
  `_findfree`, `_get_free_node`, `_chunk_pool_grow`,
  `CRT_AllocStub`, `CRT_FreeStub`, `_memcpy_stdcall`, `strncpy`.

- **Misc** — `BmpRle8Decode`, `BmpRle4Decode`, `CreateBitmapLogPalette`,
  `DuplicateHPalette`, `MeasureCaptionExtent`, `Path_ResolveAcrossSearchPath`,
  `MVPR14N_DllMain` / `_DllAttach`, `MVFS_LazyLoadModule`,
  `GlobalUnlockAndFree`.

## Imports surface

USER32 / GDI32 (window class, paint, metafile / DIB), KERNEL32 (heap,
TLS, sync), MOSCOMP (WLT-PIT family, Meta_*), MVTTL14C
(DownloadPicture / GetDownloadStatus / GetPictureInfo /
GetPictureName / DetachPicture), MVCL14N (MV file system, baggage,
hMVUnwrapHandle), MVFS14N (HfOpenHfs / RcCloseHf / LcbReadHf /
LcbSizeHf — runtime-bound).

## Per-function status

Worklist: `scratch/annotate-worklist/MVPR14N.DLL.txt`
Progress: `scratch/annotate-progress/MVPR14N.DLL.json`
