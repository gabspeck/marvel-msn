# CCAPI.DLL — total-decomp coverage

Image base `0x05560000`. Cross-component API shared by HOMEBASE and the
MSN Central UI. The MOSVIEW reach is narrow — only
`MOSX_HrCreateCCFromAppidDeid` is invoked from MOSVIEW (the menu 0x66
"open" verb in `MosViewShellWindowProc`); the rest of the surface is
exercised by HOMEBASE icon clicks and Explorer drag/drop on `.mcc`
calling-card files.

## Function inventory (78 total)

- 64 named after this pass (40 carried in from earlier RE + 24 hand-named).
- 0 still `FUN_*`.
- 14 thunks.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Auto-analysis | First-time analysis on this binary; 78 functions discovered. |
| Bulk plate (2026-05-06) | 52 plates emitted; 26 hand plates preserved. |
| Deep line comments (2026-05-06) | 266 call-site PRE comments + 36 string-ref EOL comments across 64 functions. |
| Deep hand pass (2026-05-09) | 24 functions hand-named with replacement plates; 0 FUN_ remaining. |

## Surface

`MOSX_GotoMosLocation` is the dispatcher hub for MSN Central icon
clicks (case 2 → ShellExecute `EXCHNG32` for E-Mail; cases 0/1/3/4 →
`HrShellExecMsnHandler` with kind tags 'X'/'A'). MOSVIEW only reaches
`MOSX_HrCreateCCFromAppidDeid` for its "open my MSN" menu relay.

The `.mcc` calling-card pipeline is the meatier code path. A typical
"Save Calling Card As..." flow in HOMEBASE follows:

```
HrSaveCallingCard
  → ConfirmSaveCcDlgProc          (DialogBoxParam, .mcc-suffix strip + "Always confirm" pref)
  → HrCreateMosDataObj            (operator_new(0xCC) + ctor + HrInitFromCCDIArray)
      → CMosDataObj_ctor          (vptr + Init)
        → CMosDataObj_Init        (cache 6 CF_*, populate 7 MosFmtRecord[7])
      → CMosDataObj_HrInitFromCCDIArray (per-CCDI: operator_new(0x184) CCcStorage + HrInitFromCCDI)
  → IDataObject::GetData          (vtable, on demand)
      ├─ CF_EMBEDSOURCE          → CMosDataObj_HrGetMfPictWithIcon
      ├─ CF_OBJECTDESCRIPTOR     → CMosDataObj_HrFillObjectDescriptor (CLSID_MosCallingCard)
      ├─ CF_FILECONTENTS         → CMosDataObj_HrCopyStorageByIndex (lindex picks the storage)
      ├─ CF_SHELLOBJECTOFFSETS   → CMosDataObj_HrBuildShellObjectOffsets
      │     └─ SplitPidlToParentAndLeafMnid (per CCcStorage HrGetItemIdList)
      └─ CF_FILEGROUPDESCRIPTOR  → CMosDataObj_HrBuildFileGroupDescriptor
  → CMosDataObj_Release           (refcount → 0 → CMosDataObj_dtor → operator_delete)
```

The MNID parser triplet (`HrPathToMosPidl` → `ParseMnidQuadInPlace` →
`IParseDecimalToSep`) lives in this DLL too — it converts a slash-
separated MNID path like `300:45:1:0/300:45:42:0` into a chain of
0x28-byte MOS PIDL items (magic `0x0001B70A`). Sole consumer is
`MOSX_HrExecSzMnid` for command-line / pasted-link launches.

## Globals introduced this pass

| Address | Symbol | Role |
|---|---|---|
| `0x05565000` | `g_hinstCcapi` | DLL HMODULE captured on DLL_PROCESS_ATTACH. |
| `0x05565004` | `g_fOleInited` | Tracks whether the lazy `OleInitialize` ran. |
| `0x05565008` | `g_himlIcons` | Cached HIMAGELIST (released on detach). |
| `0x0556500c` | `g_hicon1` | Cached calling-card large icon. |
| `0x05565010` | `g_hicon2` | Cached calling-card small icon. |
| `0x05565160` | `g_cfEmbedSource` | RegisterClipboardFormatA("Embed Source"). |
| `0x05565164` | `g_cfObjectDescriptor` | RegisterClipboardFormatA("Object Descriptor"). |
| `0x05565168` | `g_cfFileContents` | RegisterClipboardFormatA("FileContents"). |
| `0x0556516c` | `g_cfFileGroupDescriptor` | RegisterClipboardFormatA("FileGroupDescriptor"). |
| `0x05565170` | `g_cfShellObjectOffsets` | RegisterClipboardFormatA("Shell Object Offsets"). |
| `0x05565174` | `g_cfSysopToolsInternal` | RegisterClipboardFormatA("Sysop Tools Internal Format"). |
| `0x055653b0` | `g_winverHint` | CRT helper's cached Win9x-vs-NT branch (+1/-1). |
| `0x055653b8` | `g_cAttach` | DLL attach refcount used by the CRT helper. |
| `0x055653dc` | `g_atexitTop` | High water mark of the atexit table. |
| `0x055653e0` | `g_atexitTable` | 0x80-byte atexit function-pointer table. |
| `0x05564050` | `CLSID_MosCallingCard` | `{00028B05-0000-0000-C000-000000000046}`. |
| `0x05564840` | `CMosDataObj_vtbl_pointer` | CMosDataObj instance vtable. |

## Hand-named in this pass

| Address | Symbol | Role |
|---|---|---|
| `0x0556110c` | `DllUserInitForReason` | User-side DllMain helper (OLE/icons/imagelist lifecycle). |
| `0x05561431` | `ConfirmSaveCcDlgProc` | "Save calling card?" dialog (HKCU `ShowConfirmSaveCC`). |
| `0x0556193c` | `CMosDataObj_Init` | Populates IDataObject sub-object + 7 MosFmtRecord entries. |
| `0x05561a94` | `CMosDataObj_ctor` | vptr install + Init. |
| `0x05561ab2` | `CMosDataObj_ctorEx` | vptr + Init + extra context dwords at +0xC4/+0xC8. |
| `0x05561ae4` | `CMosDataObj_dtor` | Releases temp dir, CCcStorage array, optional cleanup callback. |
| `0x05561b5f` | `CMosDataObj_HrInitFromCCDIArray` | Per-CCDI: operator_new CCcStorage + HrInitFromCCDI. |
| `0x05561c84` | `CMosDataObj_Release` | Refcount → 0 ⇒ dtor + operator_delete. |
| `0x05561cac` | `CMosDataObj_HrGetMfPictWithIcon` | OleMetafilePictFromIconAndLabel for CF_EMBEDSOURCE path. |
| `0x05561d86` | `CMosDataObj_HrCopyFirstStorage` | First-storage CopyTo wrapper. |
| `0x05561d97` | `CMosDataObj_HrCopyStorageByIndex` | lindex-driven CopyTo (CF_FILECONTENTS). |
| `0x05561dbe` | `CMosDataObj_HrFillObjectDescriptor` | Builds OBJECTDESCRIPTOR HGLOBAL (CF_OBJECTDESCRIPTOR). |
| `0x05561e46` | `CMosDataObj_HrBuildFileGroupDescriptor` | Builds FILEGROUPDESCRIPTORA HGLOBAL. |
| `0x05561f98` | `SplitPidlToParentAndLeafMnid` | 24-byte MNID-payload extractor for the last two PIDL items. |
| `0x05561fd5` | `CMosDataObj_HrBuildShellObjectOffsets` | Private CF_SHELLOBJECTOFFSETS builder. |
| `0x05562247` | `CMosDataObj_DAdvise` | IDataObject::DAdvise tear-off (lazy CreateDataAdviseHolder). |
| `0x05562bd2` | `IParseDecimalToSep` | Decimal parser stopping at ':' / '.'. |
| `0x05562c38` | `ParseMnidQuadInPlace` | Parse n1[:.]n2[:.]n3[:.]n4 into a 24-byte MNID payload. |
| `0x05562ce1` | `ILFindLastID_local` | Inline `ILFindLastID` over a MOS PIDL chain. |
| `0x05562cfa` | `CbValidateMosPidl` | Total bytes if every item carries magic `0x0001B70A`, else 0. |
| `0x05562d2e` | `HrShellExecMsnHandler` | Build marvel.msn cmdline ",[%c]" + payload, `ShellExecuteA`. |
| `0x055630cf` | `HrPathToMosPidl` | Slash-separated path → freshly LocalAlloc'd MOS PIDL chain. |
| `0x0556332d` | `BuildPathToMosBinResource` | `<MOSBin>\<resource_or_fallback>` composer. |
| `0x05563700` | `CrtDllInitForReason` | MSVC `_CRT_INIT` clone (atexit table + initterm). |

## CMosDataObj instance layout (size = 0xCC)

| Offset | Size | Field |
|---|---|---|
| `0x00` | 4  | vptr → `CMosDataObj_vtbl_pointer` |
| `0x04` | 4  | source DWORD #1 (param_1 to ctor) |
| `0x08` | 4  | source DWORD #2 (param_2 to ctor) |
| `0x0C` | 4  | refcount (IUnknown) |
| `0x10` | 4  | `pszTempDir` — created during file-content streaming |
| `0x14` | 4  | `rgStorage` — heap array of CCcStorage* |
| `0x18` | 4  | `cStorage` |
| `0x1C` | 4  | `g_cfEmbedSource` (cached) |
| `0x20` | 4  | `g_cfShellObjectOffsets` (cached) |
| `0x24` | 4  | `g_cfObjectDescriptor` (cached) |
| `0x28` | 4  | `g_cfFileGroupDescriptor` (cached) |
| `0x2C` | 4  | `g_cfFileContents` (cached) — overloaded with `LPDATAADVISEHOLDER` once DAdvise fires |
| `0x30` | 4  | `g_cfSysopToolsInternal` (cached) |
| `0x34` | 4  | `cFmtRecords` = 7 |
| `0x38` | 2  | `fmtState` = 3 |
| `0x3C..+0xC3` | 7×0x14 | `MosFmtRecord[7]` (`{ ptd; dwAspect; lindex; tymed; cfFormat; }`) |
| `0xC4` | 4  | `pfnCleanup` — optional thiscall callback (set by ctorEx) |
| `0xC8` | 4  | `ctxToken` — opaque (passed to CF_SHELLOBJECTOFFSETS header) |

The 7 `MosFmtRecord` entries (all `dwAspect=DVASPECT_CONTENT`, `lindex=-1`, `ptd=NULL`):

| # | cfFormat | tymed | Notes |
|---|---|---|---|
| 0 | `CF_EMBEDSOURCE` | `0x20` (TYMED_MFPICT) | Goes through `OleMetafilePictFromIconAndLabel`. |
| 1 | `CF_OBJECTDESCRIPTOR` | `0x08` (TYMED_ISTORAGE) | OBJECTDESCRIPTOR HGLOBAL. |
| 2 | `CF_FILECONTENTS` | `0x01` (TYMED_HGLOBAL) | One file per `lindex`. |
| 3 | `CF_SHELLOBJECTOFFSETS` | `0x08` (TYMED_ISTORAGE) | Private MOS PIDL roundtrip. |
| 4 | `CF_FILEGROUPDESCRIPTOR` | `0x01` (TYMED_HGLOBAL) | FILEDESCRIPTORA × cStorage. |
| 5 | `CF_SYSOPTOOLSINTERNAL` | `0x01` (TYMED_HGLOBAL) | Internal MSN sysop format. |
| 6 | `0` (sentinel) | `0x01` | Terminator. |

## MOS PIDL item layout (size = 0x28)

| Offset | Size | Field |
|---|---|---|
| `0x00` | 2  | `cb = 0x28` |
| `0x02` | 2  | pad |
| `0x04` | 4  | magic `0x0001B70A` |
| `0x08` | 4  | reserved (zero) |
| `0x0C` | 4  | reserved (zero) |
| `0x10` | 4  | `n1` (appid) |
| `0x14` | 4  | reserved (zero) |
| `0x18` | 4  | `n2` |
| `0x1C` | 4  | `n3` |
| `0x20` | 2  | `n4` (WORD) + 2 pad |
| `0x24` | 4  | reserved (zero) |

Used by `HrPathToMosPidl` (parser), `CbValidateMosPidl` (size + magic
check), `ILFindLastID_local`, `SplitPidlToParentAndLeafMnid`.

## Per-function status

Worklist: `scratch/annotate-worklist/CCAPI.DLL.txt`
Progress: `scratch/annotate-progress/CCAPI.DLL.json`
