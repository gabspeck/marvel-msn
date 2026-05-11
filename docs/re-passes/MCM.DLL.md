# MCM.DLL — total-decomp coverage

Image base `0x04100000`. MOS Common Module — argv decode, generic
app-launch dispatcher (`HRMOSExec`), the `MCMMsgQSM`/`InMCM` IPC
primitives that talk to MOSCP, and the MSN phone-book engine.

## Function inventory (205 total)

- 66 named at session start.
- 24 hand-named in session 1.
- 9 hand-named in session 2.
- 15 hand-named in session 3.
- 15 hand-named in session 4.
- 7 hand-named in session 5.
- 7 hand-named in session 6.
- 1 hand-named + 5 deep-annotated in session 7 (this pass).
- 4 still `FUN_*` after session 7 — all compiler boilerplate; every one carries a structural plate explaining the lack of role.
- 57 thunks.

## Annotation deltas

| Pass | Delta |
|------|-------|
| Bulk plate | 199 plates emitted. 6 hand plates preserved. |
| Deep line comments | 1,102 call-site PRE comments + 109 string-ref EOL comments across 148 functions. |
| Session 1 (2026-05-09) | 24 hand renames + plates; touches MCM↔MOSCP IPC primitives, MOSCP launcher, COM/CS lifecycle helpers, CCAPI dispatch thunk, and the PBK phone-book pipeline. |
| Session 2 (2026-05-09) | 9 hand renames + plates: PBKState destructor, the toll-free LCID lookup chain (Find/Format + LINECOUNTRYLIST walker), PBKEntry registry load/save pair, the PBK out-of-memory popup, the HLOCAL RAII pair driving PBKSyncPhoneBooks' SEH frame, and the connection-settings dialog launcher. |
| Session 3 (2026-05-09) | 15 hand renames + plates: the 6-fn CSV streaming reader behind `phone.pbk`/`state.pbk`, the 4-fn TAPIScratch helper cluster used to canonicalise `+CC` numbers and read `dwCountryID`, the PBK error-toast helper, and the connection-settings + toll-free picker DLGPROCs (incl. `LoadFields` companion and the NPANXX validator). |
| Session 4 (2026-05-10) | 15 hand renames + plates: the 7-fn toll-free picker render pipeline (subtitles → country combo → country seed → area-code combo → entries listbox → row formatter → dispatch flag), the 2-fn protocol seed/combo pair shared with the connection-settings dialog, the 2-fn entry-blob string formatters (`+0x40` / `+0x80` slots of the toll-free pick result), and the full 4-fn modem-properties (resource 0xC1C) cluster — DLGPROC, field refresher, TAPI modem combo, and primary-number-sans-name reader. |
| Session 5 (2026-05-10) | 7 hand renames + plates: the 4-fn `phone.pbk` CSV pipeline (load / merge / row reader / row writer) — full field map locked in against the 0x50-byte PBKEntry slot, including the field-6 ("city") column doubling as the tombstone tag; the 2-fn MCM About dialog (DLGPROC + populate) reading FormatMessage templates 0xC0001002/0xC0001003 plus HKLM ProductId; one MSVC SEH unwind trampoline plated. Two further `FUN_*` (empty-stub RET, dead-init constant writer) plated as low-confidence rename skipped. |
| Session 7 (2026-05-10) | Deep pass over named-at-start dispatchers — `FGetGoWord` (0x04103d5f) gets a full ctx-struct plate + 9 line comments tracing the dialog → MOSX_HrExecFromDeid handoff; the orphan DLGPROC at LAB_04103f83 is promoted to a named function `FGetGoWord_DialogProc` (0x04103f83) with `INT_PTR (HWND, UINT, WPARAM, LPARAM)` signature, ctx layout, three-way TCP/news/goword dispatch documented, and 12 line comments at the GetWindowLongA/SetWindowLongA, FIsTCP/CheckURLType/ShellExecuteA, App #3 + DIRSRV App #7 CreateTnc, IsValid, ResolveNewsURLToDeid, GetDeidFromGoWord (selector 0x03), success/error mapping, MosErrorP, EM_SETSEL, and EN_CHANGE sites; `HRMOSExec` (0x041020d8) gets typed parameters + 5 named locals + 8 line comments at FGetNamesForApp / FormatMosArgTail / lstrcpy+lstrcat chain / CreateProcessA(0x30 = NORMAL+NEW_CONSOLE) / GetLastError mapping (FILE_NOT_FOUND→0x52d, OOM→0x52e, default→0x52a) / MosErrorP / WaitForInputIdle (textchat-only sync); the 4-fn MosError family (`MosError` 0x04102fc7, `MosErrorExP` 0x04102f66, `MosErrorP` 0x04102faa, `MosCommonError` 0x0410301f) gets the full 36-byte `MosErrorInfo` struct documented (font slots, button bank, hInst, sev_or_titleId, body, icon, checkbox), typed signatures, and per-function plates explaining how each wrapper builds and forwards. |
| Session 6 (2026-05-10) | 7 hand renames + plates targeting the orphan-FUN_ tail: `MCMSignalLineCreate` (0x041023d4 — pulses the named "MCMLineCreate" event from the TAPI LINECALLBACK at LAB_041023fd on LINEDEVSTATE_REINIT); `NoModemSetupPromptDlgProc` (0x04102966 — DLGPROC for resource 0x2c5 used by FInsureModemTAPI when no TAPI device is installed); the 2-fn MosError dialog cluster — `MosErrorDialog_OnInitDialog` (0x04103063, splits the body on `##` into bold-heading + body, lays out icon + button bank from the MosErrorInfo struct) + `CloneFontWithWeight` (0x04103812, GetTextMetrics-seeded LOGFONT clone); `MCMReadOrInitShortPref_2B` (0x04103e9e — PVReadReg + WriteRegDword default-init for MCM pref 0x2b); `ResolveNewsURLToDeid` (0x04103ee3 — strips `news:`, seeds well-known news-root deid pair, MultiByteToWideChar + CTreeNavClient::ResolveMoniker, called from NewsProtocolHandler); and `GoWord_FetchMatchingDeids` (0x0410438e — DIRSRV App #7 GetChildren walker harvesting `q` properties into a LocalAlloc'd dword array, used by the FGetGoWord dialog). Two further `FUN_*` (`FUN_04103c83` 8-constant init twin of `FUN_04104955`; `FUN_041053e2` RET-stub twin of `FUN_041089c4`) plated as compiler boilerplate, rename skipped. |

## Surface

### MCM ↔ MOSCP IPC

- `MCMSubmitOpAndWait(hms, opcode, arg1, arg2)` — submit a request through
  the named `MCMMsgQSM` shared section, signal `MCMMsgQAdd`, block on the
  per-slot `MCMMsgQ%d` semaphore, return MOSCP's reply written back into
  slot[0]. All `FMCMMakeCall`/`MCMCloseSession`/`FGetConDetails`/etc.
  funnel through here.
- `MCMEnterIPC()` / `MCMLeaveIPC(HANDLE)` — boundary mutex `InMCM` that
  serialises MCM IPC across all client DLLs talking to the same MOSCP.
- `FMCMEnsureMOSCPRunning(flags)` — bootstrap: open `logmanhwnd` mapping
  if MOSCP is alive; otherwise `CreateProcess` it with the cmd-line from
  resource 0x11, wait on the `MCM` event, then map `logmanhwnd` and
  publish the session id into `DAT_0410c01c` (`g_hms`).

### Generic app-launcher / argv

- `HRMOSExec(app_id, cmdStr, nodeF10, nodeF20, &deidPair)` — generic
  app dispatcher. Reads `HKLM\SOFTWARE\Microsoft\MOS\Applications\App
  #<app_id>!Filename` via `FGetNamesForApp`, builds a command line of the
  form `<Filename> -MOS:<f10>:<deid_lo>:<deid_hi>:<f20> <cmdStr>` via
  `FormatMosArgTail` + two `lstrcatA`s, then `CreateProcessA(NULL, cmdLine,
  …, 0x30 = NORMAL_PRIORITY_CLASS|CREATE_NEW_CONSOLE, …)`. On failure
  `GetLastError` is mapped: 2..3 → string 0x52d ("can't find Filename"),
  8/0xe → 0x52e ("out of memory"), other → 0x52a (generic with cmdLine
  echo); the formatted body is shown by `MosErrorP(NULL, hInst, 0x529,
  errMsg, 0)`. `WaitForInputIdle(hProc, 5min)` is invoked only for
  `app_id == 4` (textchat) where the IPC handshake races the child's pump.
  The `c==7` URL-launcher special case lives one frame up in
  `CCAPI!MOSX_HrExecFromDeid`, not here — HRMOSExec is the registry-launch
  path that runs for every non-container app id with a real EXE filename.
  Container navigators (c=1/2/3/10) silently no-op because their registry
  `Filename` is a `.nav` DLL and `FGetNamesForApp` either returns 0 or
  `CreateProcessA` fails (and the shell never reaches HRMOSExec for them
  anyway).
- `FormatMosArgTail(out, dwordA, &qwordBC, wordD, suffix)` — emits the
  `-MOS:%d:%d:%d:%d %s` argv tail consumed by `FGetCmdLineInfo`.
- `FGetCmdLineInfo` — decodes `-MOS:appid:deid_lo:deid_hi:tail` syntax.
- `ParseMOSArgDecimal` — single-field decimal parser for the `-MOS:`
  argv shape.
- `FRunModemSetupAndWait(hwnd)` — launch the helper command in MCM
  string resource 0x11 (TAPI/modem setup wizard) and block on it.

### Standard error/info dialog (resource 0x191)

- `MosError(hwndParent, MosErrorInfo *info)` — entry point that runs
  `DialogBoxParamA(g_hInstance_mcm, 0x191, …, MosErrorDialog_DialogProc,
  info)`, then `DeleteObject`s the two HFONTs the DLGPROC cached at
  `info[+0x00]/[+0x04]`. Returns the EndDialog button id.
- `MosErrorInfo` (36 B):
  - `+0x00` HFONT default (DLGPROC owns; MosError destroys),
  - `+0x04` HFONT bold heading (cloned via CloneFontWithWeight),
  - `+0x0c` button bank (0=OK, 1=OK/Cancel, 2=Yes/No, 3=Yes/No/Cancel),
  - `+0x10` HINSTANCE for body LoadString,
  - `+0x14` severity / title string id,
  - `+0x18` body string id or direct LPSTR,
  - `+0x1c` icon resource id (`-1`→0x191, `0`→0x7F04, custom otherwise),
  - `+0x20` checkbox flag (non-zero shows IDC 0x69).
- `MosErrorExP(hwnd, hInst, sev_or_title, body, button_or_aux, icon)` —
  `memset(info,0,0x24)` + slot writes + `MosError`.
- `MosErrorP(hwnd, hInst, sev_or_title, body, button_or_aux)` — thunk
  `MosErrorExP(... icon=0)` (DLGPROC maps icon=0 to IDI_HAND 0x7F04).
- `MosCommonError(hwnd, idx)` — fixed `info{ hInst=g_hInstance_mcm,
  title=0x191, body=0x192+idx, button=0, icon=0 }` toast for the
  packed common-error string range starting at MCM string 0x192.

### Module init / lifetime

- `InitMCMGlobalCS` / `DeleteMCMGlobalCS` — DLL_PROCESS_{ATTACH,DETACH}
  bookends for the module-wide CS at `DAT_0410a460` (held by
  `LoadAndCallW` while it touches the load-on-demand DLL table).
- `FNewComScope(int **)` / `FreeComScope(int **)` — RAII pair around
  `CoInitialize`/`CoUninitialize`; the slot stores the HRESULT so the
  destructor only `CoUninitialize`s when init succeeded.

### Cross-DLL dispatch

- `FInvokeMosxHrExecFromDeid` — thunks into `CCAPI!MOSX_HrExecFromDeid`
  via `LoadAndCallW(3, "MOSX_HrExecFromDeid")`, forwarding the caller's
  stack frame.

### TCP/connection helpers

- `LocalStrdupA` — `strdup` via `LocalAlloc(LMEM_ZEROINIT, len+1)`;
  caller frees with `LocalFree`.
- `ScanNextDecimalRun(cur, end, &tail)` — locate next ASCII decimal
  substring in `[cur, end)`, NUL-terminate it, and return start +
  remainder pointer.
- `FParsePhonebookRegEntry(hkey, conn, isSecondary)` — read MSN
  connection entry from registry value 0x15/0x16 and parse
  `+CC AAA NNNNNNN:E` into the connection-info struct (slot at +0x14
  for secondary, +0x58 for primary).
- `EnsureURLProtocolList` — lazily build the cached lowercased URL
  protocol list at `DAT_0410c308` (separator-padded) by enumerating
  `HKEY_CLASSES_ROOT` subkeys with a `URL Protocol` REG_SZ. Skips the
  `msn` subkey to avoid recursion. Used by `CheckURLType`.

### PBK phone-book engine

- `PBKState_Construct` (this-call) — zero/default-init the PBK state
  object; sets country sentinel +0x2c = 0xFFFFFFFF and LCID +0x34 = 1.
- `PBKState_Destruct(this)` (fastcall thunk used by PBKClose) — release
  every allocation the state owns: `+0x00` area-code dispatch index,
  `+0x04` TAPI lineGetCountry blob, `+0x08` moveable entries blob
  (LocalHandle/Unlock/Free dance), `+0x18` per-area-code table.
- `PBKLoadPhoneBookFromFile(forceLoad)` (this-call) — load
  `phone.pbk`+`state.pbk`. Allocates the per-area-code table at
  `this+0x18` (0x28-byte rows), grows the entries blob at `this+0x08`
  (0x50-byte rows) by `LocalReAlloc` doubling, parses every record's
  colon-separated fields into the slot layout documented in the plate,
  builds the area-code-keyed `*this` index, and `qsort`s it. Caches
  `lineGetCountry(0x10003)` once into `this+0x04`.
- `PBKLoadTollFreeStrings(primary, fallback)` — fill the toll-free
  strings: registry first (key id 0x834 / value id 0x83c), else
  resource pair 0x7d2/0x7d6.
- `LookupPhonebookFile(filename, &hit)` — mmap a sorted 102-byte-record
  phonebook file, `bsearch` using key staged in `DAT_0410a408`, copy
  result through the now-unmapped pointer (caller-only safety).
- `PBKWriteAutoPickEntry(entry, connKind)` — persist an auto-picked
  phonebook entry under section 0x834 *and* section
  `0x9c4 + ConnectProtocolToIndex(connKind)`; cache `connKind` and
  protocol index into `DAT_04110548 + 0x22/0x24`.
- `PBKReadCountryIdAdHoc()` — cold-path country-id reader used when
  the PBK state hasn't been constructed yet (init/extract/destroy a
  20-byte TAPI scratch).
- `PBKEntry_SetPrimary(this, num, validate)` /
  `PBKEntry_SetSecondary(this, num, validate)` — thin thunks that
  forward to:
- `PBKEntry_SetNumber(this, num, isSecondary, validate)` — write the
  user-entered phone number into the entry at +0x00/+0x33 (number) and
  +0x66/+0x99 (friendly name after `:`); when validating, restrict to
  the dial set `0123456789 -.()+*#,`, require ≥1 digit, enforce a
  50-byte budget minus the already-stored name, and canonicalise a
  leading `+CC` through TAPI helpers.
- `PBKEntry_LoadFromRegistry(this, sectionId)` — fill the 0x131-byte
  PBKEntry from MOSMISC `PVReadRegSt`: 94 B blob from `(sectionId,
  0x836)` into +0x100, display name from `(0x834, 0x002)` into +0xcc,
  and the colon-split primary/secondary lines from `(sectionId, 0x15)`
  /`0x16` into +0x000/+0x033 with tails at +0x066/+0x099. Missing
  values reset the corresponding region; size sentinel 0x5e is stamped
  into +0x100 when the blob is absent.
- `PBKEntry_SaveToRegistry(this, sectionId, hwndForOhare, notifyOhare)`
  — companion writer; `lstrcat`s number+tail back into one ASCIIZ value
  per slot and emits `FWriteRegSt` for `(0x834, 0x002)`, `(sectionId,
  0x836 [0x5e B])`, `(sectionId, 0x015)`, `(sectionId, 0x016)`, plus a
  commit DWORD at `(sectionId, 0x83e)`. When `notifyOhare`, calls
  `IfTCPthenUpdateOhare(hwnd, NULL, NULL)` so RNAA picks up the new
  dial-up config.

### TAPI country index

- `PBKFindTapiCountryEntry(this, lcid)` — linear-scan the
  LINECOUNTRYLIST blob at `this+0x04` for the LINECOUNTRYENTRY whose
  `dwCountryID == lcid`. Walk start `&blob + blob.dwCountryListOffset`
  (TAPI `+0x14`); stride 0x2c (11 ints); loop guard
  `dwNextCountryID == 0`. The returned entry is interned into the PBK
  dispatch table by `PBKLoadPhoneBookFromFile`, which repurposes
  `dwSameAreaRuleSize`/`dwSameAreaRuleOffset` (entry+0x14/+0x18) to
  cache the first-entry-index and country ushort.
- `PBKFindTollFreeForLcid(this, lcid, outPhone, outName)` — locate the
  toll-free row for `lcid` and emit a formatted dial string + 11-byte
  name tail. Walks the dispatch array (count `this+0x14`), follows the
  first-entry-index, then steps through consecutive same-country
  entries until one with `entry+0x05 == 1` is hit. Both outputs are
  NUL-cleared on entry; missing rows leave them empty so
  `PBKGetTollFree` can fall back to the toll-free dialog.
- `PBKFormatEntryPhoneNumber(this, outBuf, entryIndex, dispatchIdx)` —
  wsprintf helper used by the toll-free path and the dial-list dialog
  proc. Picks `"+%d %s"` when entry+0x0c == -1 (no numeric prefix) and
  `"+%d (%s) %s"` otherwise; `+CC` comes from `dispatch[+0x04]`
  (`dwCountryCode`), `(prefix)` from entry+0x47, name2 from entry+0x2c.

### UI / RAII helpers

- `PBKShowOutOfMemoryMsg()` — `MessageBoxA(NULL, g_szOutOfMemoryMsg,
  NULL, MB_ICONERROR | MB_TASKMODAL)`. The message buffer at
  `0x0410a2b0` is populated once by `PBKInit` via
  `LoadStringA(0x899, ..., 64)`. Used wherever a PBK alloc fails.
- `PBKShowErrorMessage(bodyStringId, aux)` — wrapper around
  `MosError`. Builds a 36-byte descriptor with body string from
  `g_hInstance_mcm`, flags `0x07D0`, no custom title; used for the
  `0x8A0`/`0x8A1`/`0x8A2` phone-book parse errors,
  `0x8A6` "phone book changed", `0x8A7` "no entries selected",
  `0x89C/0x89D/0x8A3` NPANXX validation errors. Parent HWND is read
  from `DAT_0410a2f0` (callers cache the dialog hwnd into the slot
  for the call's duration).
- `HLocalScope_Construct(slot)` / `HLocalScope_Destruct(slot)` — RAII
  guard for an HLOCAL inside `PBKSyncPhoneBooks`. The MSVC SEH frame
  installed at `0x041084e2` runs the destructor on unwind label
  `LAB_04109af8`; ctor zeroes `*slot` so an early unwind is safe.
- `ShowConnectionSettingsDialog(hwndParent, errorMode)` — modal launcher
  for the MSN connection-settings property sheet (resource `0xc1c`,
  proc `FUN_04109605`); calls `MOSCC.InitCustomControls` first.
  `errorMode==1` is forced by `LConnectionSettingsError` and by
  `ChangeConnectionSettings` when invoked without a parent HWND.

### `phone.pbk` / `state.pbk` streaming reader

A 0x414-byte, on-stack tiny CSV parser drives every PBK file load.
Layout: `+0x000..+0x3FF` 1 KB read buffer, `+0x400` cursor, `+0x404`
end pointer, `+0x408` last char, `+0x40C` `bytes_read` scratch,
`+0x410` `HANDLE`. Field separators are `,` and `\n`; `\r` is dropped
silently. Members:

- `CSVStream_Init(stream)` — zero-init the four cursor / handle
  slots. `CSVStream_Term()` is the symmetric (single `RET`) terminator
  the compiler kept; the 1 KB buffer dies with the caller's frame.
- `CSVStream_Open(this, path)` — `CreateFileA(GENERIC_READ |
  FILE_SHARE_READ, OPEN_EXISTING)`; arms cursor/end to 0 so the first
  read forces a refill.
- `CSVStream_Refill(stream)` — synchronous `ReadFile` of up to
  0x400 bytes; returns 1 if any bytes were read.
- `CSVStream_ReadField(this, outBuf, budget)` — copy the next
  CSV field into `outBuf` (≤ `budget-1` bytes + NUL). Empty fields
  return TRUE with an empty string; immediate EOF returns FALSE so the
  loader can break.
- `CSVStream_Close(stream)` — idempotent `CloseHandle` on the file.

Sized buffers in `PBKLoadPhoneBookFromFile`:
`0x100` numeric scratch (`atoi`), `0x1F` country language tag,
`0x14` country display name, `0x10` second name, `0x07` protocol
prefix, `0x0B` 11-byte tail.

### `phone.pbk` CSV pipeline (entries blob persistence)

A second `phone.pbk`-class file is also processed via the CSVStream
plumbing, but with a 0x50-byte PBKEntry layout (cf.
`PBKLoadPhoneBookFromFile` for the dispatch table). Four functions
form the pipeline:

- `PBKReadEntryFromCsv(slot, stream)` (0x04108cb4) — parse one
  CSV row of 11 fields into the 0x50-byte slot. Field-to-offset map
  (matches the writer's `"%lu,%lu,%lu,%s,%s,%s,%lu,%lu,%lu,%lu,%s\r\n"`
  format string at 0x0410c7ec):
  - f1 atol → +0x00 (entry id)
  - f2 atol → +0x08
  - f3 atoi → +0x06 (short)
  - f4 raw  → +0x18 (`char[0x14]` primary string)
  - f5 raw  → +0x47 (`char[7]` NPA prefix), then re-parsed by atol
    into +0x0c
  - f6 raw  → +0x2c (`char[0x10]` secondary/city — also the
    tombstone tag; "0" marks a delete record)
  - f7 atol → +0x10
  - f8 atol → +0x14
  - f9 atoi → +0x04 (byte; protocol bitmask)
  - f10 atoi → +0x05 (byte; accept-flag for
    `PBKFindTollFreeForLcid`)
  - f11 raw → +0x3c (`char[0x0b]` tail)
  Returns FALSE at EOF (caller stops the merge loop).
- `PBKWriteEntriesCsv(this, dirPrefix, fileName)` (0x04108e40) —
  symmetric writer. `wsprintfA "%s%s"` to build the 260-byte path,
  `CreateFileA(GENERIC_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL)`,
  iterate `this[2]` 0x50-byte rows emitting one row per
  `WriteFile`. WriteFile failure → close + `DeleteFileA` the
  partial output and return FALSE.
- `PBKLoadEntriesCsv(this, dirPrefix, fileName)` (0x041089f4) —
  initial bulk load. Drops any prior `this[0]`, seeds capacity at
  `0x100` rows × 0x50 = 0x5000-byte `LocalAlloc`, opens stream,
  appends rows growing capacity by doubling on need. Counterpart
  to `PBKMergeCsvIntoEntries`.
- `PBKMergeCsvIntoEntries(this, dirPrefix, fileName, forceMode)`
  (0x04108b31) — delta merge. For each row: if the city/secondary
  field at slot+0x2c equals `"0"`, linear-scan
  `entries[0..count)` for a matching entry id (slot+0x00) and
  `memmove`-delete it; otherwise `memcpy`-append after
  doubling-grow. Tombstone for a missing id with `forceMode==0`
  bails the merge with FALSE; with `forceMode!=0` the miss is
  silently ignored.

### MCM About dialog

- `MosAboutDialogProc(hwndDlg, message, wParam, lParam)`
  (0x04103a0c) — DLGPROC. WM_INITDIALOG → `MosAboutDialog_Populate`;
  WM_COMMAND IDOK/IDCANCEL → `EndDialog`. Standard "About" shape;
  `lParam` is the caller's 4-DWORD struct.
- `MosAboutDialog_Populate(hwndDlg, aboutInfo)` (0x041038a9) — fill
  the dialog. `aboutInfo` slots: `[0]` = product name (LPSTR),
  `[1]` = version (LPSTR, used twice), `[2]` = HICON for IDC `0x6d`
  via `STM_SETIMAGE` (0x170), `[3]` = optional subtitle for IDC
  `0x76` (skipped if NULL). `FormatMessageA(0x2900,
  g_hInstance_mcm, 0xC0001003, en-US)` populates IDC `0x6e` (brand
  banner). When `HKLM Software\Microsoft\Windows\CurrentVersion!ProductId`
  reads, message `0xC0001002` is formatted with the ProductId into
  IDC `0x71`. IDC `0x74` / `0x75` come from `PVReadReg(HKLM,
  g_hInstance_mcm, sec=0x1B, val=0x1C / 0x1D)` — registered
  user/organisation. Closes with `SetForegroundWindow`. The DLGPROC
  is reached only via a function-pointer `DialogBoxParamA` call
  (Ghidra reports 0 callers).

### TAPI scratch (`+CC` canonicalisation)

A 20-byte caller-stack block (sometimes 24-byte aligned) used by the
PBK code to talk to TAPI without standing the full `FInsureModemTAPI`
machinery up. Layout: `+0x00` ready flag, `+0x04` `HLINEAPP`, `+0x08`
`numDevs`, `+0x0C` `dwAPIVersion`, `+0x10` `dwDeviceID`. Members:

- `TAPIScratch_Open(scratch)` — zero `ready_flag/hLineApp`,
  `lineInitialize` against `g_hInstance_mcm`, on success
  `FGetDeviceID(&tmp, scratch+0xC, scratch+0x10)` to elect a modem.
  The temporary `HLINEAPP` `FGetDeviceID` returned is `lineShutdown`'d
  immediately; only the original `hLineApp` survives. `ready_flag = 1`
  on success.
- `TAPIScratch_Close(scratch)` — `lineShutdown` if `hLineApp != 0`;
  idempotent (safe even after a failed Open).
- `TAPIScratch_QueryCurrentCountryID(scratch)` —
  `lineGetTranslateCaps` size-probe → `LocalAlloc` →
  `lineGetTranslateCaps` for real → walk the location list at
  `caps + dwLocationListOffset` (stride **0x44** — the Win95 build of
  `LINELOCATIONENTRY` carries one extra `DWORD` over the documented
  16) and return `*(entry+0x34)` of the entry whose
  `dwPermanentLocationID == dwCurrentLocationID`. Returns 0 on any
  error.
- `TAPIScratch_ValidateDialableNumber(scratch, addressIn)` —
  `lineTranslateAddress` size-probe → `LocalAlloc` →
  `lineTranslateAddress` for real → `LocalFree` → return TRUE iff the
  second call succeeded. Result string is discarded — callers
  (`PBKEntry_SetNumber`) only need the syntax check.

Owners: `PBKReadCountryIdAdHoc` (open / query / close in three lines),
`PBKLoadPhoneBookFromFile` (open / close around the parse window),
`FUN_04107827` (open / close around the area-code populate),
`PBKEntry_SetNumber` (validator).

### Connection-settings dialog (resource 0x410)

- `PBKConnectionDialogProc(hwndDlg, message, wParam, lParam)` —
  DLGPROC handed to `DialogBoxParamA` from `PBKDisplayPhoneBook` /
  `PBKDisplayPhoneBookX25` / `PBKDisplayPhoneBookTCP` /
  `ShowConnectionSettingsDialog`. Wires the protocol combo (IDC
  `0x3FB`), the four phone-edit + display-name pairs, the
  Modify/Choose buttons (IDC `0x3EB`/`0x3EC` → toll-free picker), and
  the `IDOK` commit path (writes to MOSMISC sections `0x834` and
  `0x9C4 + protoIdx`). `lParam` bit 1 toggles "validate-only" mode;
  bit 2 selects an X.25/TCP protocol initial section.
- `PBKConnectionDialog_LoadFields(hwndDlg, sectionId)` — refresh
  every IDC from the sticky `DAT_0410a048` PBKEntry global after
  `PBKEntry_LoadFromRegistry(sectionId)`. IDC map: `1000` ← number,
  `0x3ED` ← name, `0x3E9` ← secondary number, `0x3EE` ← second name,
  `0x3F8` ← primary tail, `0x3F9` ← secondary tail.

### Toll-free picker dialog (resource 0x1F7)

- `PBKTollFreePickerDialogProc(hwndDlg, message, wParam, lParam)` —
  driven by the connection dialog's Modify/Choose buttons. Builds the
  country combo (IDC `0x3F3`), area-code listbox (IDC `0x3F4`,
  persists last selection in MOSMISC `(0x834, 0x83D)`), entries combo
  (IDC `0x3F5`), and area-code description pane (IDC `0x3F6`). On
  `IDOK` allocates a 0x100-byte heap blob with the formatted phone
  number at `+0x00`, the service name at `+0x40`, and the friendly
  description at `+0x80`, and `EndDialog`s with the pointer; the
  caller `LocalFree`s after reading. Optional subtitle on IDC `0x3F7`
  is loaded from `g_hInstance_mcm` only when init `lParam != 0`.
- `PBKTollFreePicker_SetSubtitles(state, hwndDlg)` — refresh the two
  static labels above the country combo and area-code listbox
  (IDC `0x3FD` / IDC `0x3FC`). Source resources are
  `5000 + protocol_idx` and `5000 + 0x1390 + protocol_idx` indexed by
  `state+0x24`. Called once at WM_INITDIALOG.
- `PBKTollFreePicker_PopulateCountryCombo(state, hwndDlg, idcCombo)` —
  walks the dispatch table (`state[0..0x14]`) and emits one
  `"%s (%d)"` row per LINECOUNTRYENTRY. Stage 1 of the WM_INITDIALOG
  combo build.
- `PBKTollFreePicker_SeedCountrySelection(state, hwndDlg, idcCombo)` —
  CB_SETCURSEL the cached `state+0x2c`; on the sentinel value
  (`0xFFFFFFFF`) it instead opens TAPIScratch, queries the current
  Telephony location's country ID, finds the dispatch row via
  `PBKFindTapiCountryEntry`, and CB_SELECTSTRINGs by display name.
- `PBKTollFreePicker_PopulateAreaCodeCombo(state, hwndDlg, idcDescPane,
  idcAreaCombo, countryIdx)` — refills IDC `0x3F4` with the area-code
  rows whose `dwCountryID` matches the active country, and
  enables/disables the description pane (IDC `0x3F6`) and the combo
  itself based on `PBKDispatchHasAreaCodes`. Restores the user's
  last area pick from `state+0x30`.
- `PBKTollFreePicker_PopulateEntriesList(state, hwndDlg, idcEntriesList,
  countryIdx, idcAreaCombo)` — refills IDC `0x3F5`. Two walk modes
  selected by `PBKDispatchHasAreaCodes`: country-direct (entries blob
  walked while `entry+0x08 == dwCountryID`) and area-walk (after a
  `lstrcmpA` match against the listed area row, walks entries while
  `entry+0x06 - row_idx == 1`). Acceptance is `entry+0x05 ==
  state+0x22` for `state+0x22 < 2` and bitmask `&` otherwise so the
  dialog can show every protocol the active mask covers.
- `PBKEntry_CopyServiceName(state, outBuf, entryIdx)` — `lstrcpyA`
  the ANSI service name at `entry+0x3c` into `outBuf`. Drives the
  `+0x40` slot of the toll-free pick result blob.
- `PBKEntry_FormatDescription(state, outBuf, entryIdx)` — formats
  the friendly locality string for the `+0x80` slot. `"%s (%d %s)"`
  for single-area-code entries (`entry+0x10 == entry+0x14`),
  `"%s (%d-%d %s)"` for ranges; tail string is
  `DAT_0410a410` (timezone / language tag scratch loaded once by
  `PBKLoadPhoneBookFromFile`).
- `PBKFormatEntryComboLine(state, outBuf, pEntry)` — builds one row
  for the IDC `0x3F5` listbox. Two-stage: stage 1 prints
  `"%d"` / `"%d-%d"` from `entry+0x10`/`entry+0x14`; stage 2 emits
  `"%s  (%s) %s  (%s %s) %d"` with the city, NPA prefix, secondary
  name, area string, timezone tag, and the entry index `(entry -
  state+0x08) / 0x50` so the `IDOK` handler can recover the entry
  identity via `atoi` after the `\t`.
- `PBKDispatchHasAreaCodes(state, countryIdx)` — read the
  `uses_area_codes` byte at `dispatch[countryIdx]+0x18` (the cached
  TAPI `dwSameAreaRuleOffset` slot, repurposed by
  `PBKLoadPhoneBookFromFile`). Used to gate area-code-aware combo
  populators.
- `PBKValidateNPANXXFields(hwndDlg)` — validator for the NPA + NXX
  edits (IDC `0x44D`/`0x44F`) on the NANP confirmation dialog used
  during auto-pick. Country gate: only LCID 1 (US) and 0x6B (Canada)
  trigger numeric range checks; everything else short-circuits TRUE.
  Errors raise `PBKShowErrorMessage(0x89C/0x89D/0x8A3)` and `SetFocus`
  the offending edit. Caches the parsed values into
  `DAT_0410a3FC/DAT_0410a400/DAT_0410a408`.

### Connection-settings dialog protocol pair

- `PBKConnectionDialog_LoadProtocolFromRegistry(state)` —
  `__fastcall` helper that seeds `state+0x22` (connKind / protocol
  bit-mask filtering PBK entries) and `state+0x24` (1-based protocol
  index) from the HKCU value located via two `MOSMISC.GetSz(0x83e)`
  + `GetSz(0x834)` + `FGetRegistryDword(HKEY_CURRENT_USER, …)` calls.
  The first-set-bit scanner only inspects mask values 2 and 4 even
  though the do-while reads `iVar2 < 8` — the inner `if (4 < uVar3)
  return;` exits once `uVar3` reaches 8, so registry-derived
  selections are limited to the lower two protocol indices. Called
  by `PBKConnectionDialogProc` WM_INITDIALOG before the combo is
  populated.
- `PBKConnectionDialog_PopulateProtocolCombo(state, hwndDlg, idcCombo)` —
  fill IDC `0x3FB` from the available-bitmask cached at
  `state+0x21`. Always emits a generic row (`GetSz(5000)`) at index 0
  then iterates bit values 2…128 (protocol idx 1..7) and
  CB_ADDSTRINGs `GetSz(5000 + idx)` for each set bit. Final
  `CB_SETCURSEL → state+0x24` re-selects the active protocol; the
  IDC `0x3FC` static-text subtitle is refreshed via
  `GetSz((state+0x24>>16<<16) | ((state+0x24&0xFFFF)+0x1390))`.
  Lock path (`state+0x28 != 0`): `EnableWindow(combo, FALSE)`,
  hide IDC `0x3F1` (Modify…), reveal IDC `0x3F2` (locked-state
  label).

### Connection-settings (modem-properties) dialog (resource 0xC1C)

- `ConnectionSettingsDialogProc(hwndDlg, message, wParam, lParam)` —
  modem-properties DLGPROC handed to `DialogBoxParamA` from
  `ShowConnectionSettingsDialog` and the modem-setup helper. WM_HELP
  → `HandleHelp("msn.hlp", 0x410c818, …)`; WM_INITDIALOG centres the
  dialog and overrides IDOK / IDC `0xCED` captions when init
  `lParam != 0` (entry-error / "modem required" mode); WM_COMMAND
  IDOK persists IDC `0xCEC` modem-name into MOSMISC `(1, 2)`,
  `0xCE4` opens the toll-free phonebook (`PBKInit` →
  `PBKSyncPhoneBooks` if online → `PBKDisplayPhoneBook` →
  `PBKClose`), `0xCE5` raises `lineTranslateDialog` for dialing
  properties, `0xCE6` runs `lineConfigDialog "comm/datamodem"` and
  caches the resulting blob into MOSMISC `(1, 0x20)` prefixed with
  the modem name, `0xCF3` calls `WinHelpA("msnpss.hlp", 0x352)`.
  `WM_DEVICECHANGE / DBT_DEVNODES_CHANGED (7)` re-runs
  `RefreshFields` so the modem combo reflects fresh TAPI state.
- `ConnectionSettingsDialog_RefreshFields(hwndDlg)` — driver for
  the dialog's read-only labels. Reads the connection-protocol byte
  via the same registry path as `LoadProtocolFromRegistry`, calls
  `ConnectProtocolToIndex` to map it into the dense index used as
  `GetSz(0xBEA + idx)` for IDC `0xCF4`. IDC `0xCEA` is filled with
  `wsprintfA(GetSz(0xBBA), GetPrimaryNumberSansName)`. IDC `0xCEB`
  is the dial-location summary — `FGetCurrentLocation` ++
  `lineTranslateAddress` displayable digits formatted into
  `GetSz(0xBBB)`. Closes by re-driving the modem combo via
  `ConnectionSettingsDialog_PopulateModemCombo`.
- `ConnectionSettingsDialog_PopulateModemCombo(hwndCombo)` —
  CB_RESETCONTENT, then `lineInitialize` (callback at
  `0x041023fd`, GetSz(0xF) caller name = "msn.dll"), then per
  device id: `lineNegotiateAPIVersion(0x10004)`, `lineGetDevCaps`,
  filter by `dev_caps[0x3c] & 0x14 == 0x14`
  (DIALDIALTONE | HIGHLEVCOMP — data modem subset),
  `lineGetDevConfig "comm/datamodem"` with a `>0x95F`-byte sanity
  gate, then a second `lineGetDevCaps` into a properly-sized
  `LocalAlloc`'d buffer for the line-name field. Each match gets
  `CB_ADDSTRING` + `CB_SETITEMDATA` carrying the dwDeviceID for the
  IDC `0xCE6` Configure-modem path. `CB_SELECTSTRING` order:
  PVReadRegSt(`(1, 2)`) → first cached match → original
  `GetWindowTextA`. `LINEERR_REINIT` raises `MosErrorExP(9, 0x1A,
  0x7F01)` and bails.
- `ConnectionSettings_GetPrimaryNumberSansName()` — read MOSMISC
  `(1, 0x15)` (the `+CC AAA NNNNNNN:friendly-name` primary number
  string), NUL-terminate at the first `:` so the friendly tail is
  stripped, `lstrcpyA` into the global scratch `DAT_0410a420`, and
  return `&DAT_0410a420`. Called by `RefreshFields` (the modem-name
  label) and by `ConnectionSettingsDialogProc` IDC `0xCE5`'s
  `lineTranslateDialog` arg.

### TAPI line callback (orphan code)

- `LAB_041023fd` — TAPI LINECALLBACK shared by `FGetDeviceID` and
  `ConnectionSettingsDialog_PopulateModemCombo`. Filters the 6-arg
  callback for `dwMsg == LINE_LINEDEVSTATE (8) && dwParam1 ==
  LINEDEVSTATE_REINIT (0x40000)`; on hit it calls
  `MCMSignalLineCreate` and falls through. `RET 0x18` (6×DWORD).
- `MCMSignalLineCreate()` (0x041023d4) — open the named event
  `MCMLineCreate` with `EVENT_MODIFY_STATE`, `SetEvent`,
  `CloseHandle`. Lets a sibling thread blocked on the event resume
  TAPI initialisation after the system reinit.

### "No modem installed" prompt (resource 0x2C5)

- `NoModemSetupPromptDlgProc(hDlg, msg, wParam, lParam)` —
  generic Yes/No DLGPROC raised by `FInsureModemTAPI` when
  `FGetDeviceID` returns no TAPI device. WM_HELP / WM_CONTEXTMENU
  → `HandleHelp("msn.hlp", &g_helpTbl_0410c130)`; WM_INITDIALOG
  centres + foregrounds; WM_COMMAND IDYES (6) → `EndDialog(1)` so
  the caller runs `FRunModemSetupAndWait`, IDNO/IDCANCEL → 0.

### Generic MosError dialog

- `MosErrorDialog_OnInitDialog(hDlg, MosErrorInfo*)` — WM_INITDIALOG
  helper for the MosError DLGPROC at `LAB_041036e7`. Splits
  the message text on `##` into bold-heading (IDC 0x65) + body
  (IDC 0x66), uses `DrawTextA(DT_CALCRECT|DT_WORDBREAK)` to size
  both rects and reflow the dialog vertically, loads icon (info
  `[+0x1C]` resource id, `-1` → 0x191, `0` → 0x7F04), picks button
  bank (info `[+0xC]` ∈ {0:OK, 1:OK/Cancel, 2:Yes/No,
  3:Yes/No/Cancel}) and optional checkbox at IDC 0x69 when info
  `[+0x20] != 0`. Sets the default-pushbutton style on the focus
  button via `GetWindowLongA|0x1`/`SetWindowLongA`.
- `CloneFontWithWeight(base, weight)` — produce a new HFONT that
  inherits `base`'s metrics (height, ave-char-width, italic,
  underline, strikeout, charset, pitch-and-family) and face name
  but with `lfWeight = weight`. Used by `MosErrorDialog_OnInitDialog`
  to bold the heading slot. Returns the new HFONT in EAX (Ghidra
  decompiles as void).

### Go-Word dialog (resource 0x578)

- `FGetGoWord(hwndParent)` — exported launcher. Stages a 24-byte ctx
  on the stack `{tnc1=NULL, tnc2=NULL, deid_lo=DAT_0410b7d8,
  deid_hi=DAT_0410b7dc, flag=-1}`, runs `DialogBoxParamA(0x578,
  hwndParent, FGetGoWord_DialogProc, &ctx)`. Non-zero return →
  `SetCursor(IDC_WAIT) → FNewComScope(&comScope) →
  FInvokeMosxHrExecFromDeid(deid_lo, deid_hi, flag)` (LoadAndCallW
  slot 3 → CCAPI!MOSX_HrExecFromDeid); HRESULT < 0 raises
  `MosErrorP(hwndParent, MCM, 9, 0x57b, NULL)`. Cleanup tail releases
  tnc1/tnc2 via `PTR_Release_0410d6b4` and `FreeComScope` —
  reachable both via fall-through and the SEH unwind handler at
  LAB_04109af8.
- `FGetGoWord_DialogProc(hwndDlg, msg, wParam, lParam)` — DLGPROC for
  resource 0x578 (created from former `LAB_04103f83` in this pass).
  Reads ctx via `GetWindowLongA(DWL_USER)` (seeded by WM_INITDIALOG
  via `SetWindowLongA(lParam)`). On `IDOK` reads IDC 0x579 text,
  computes `isTCP = FIsTCP(0)` and `urlType = CheckURLType(buf)`, then:
  - `urlType==2` (full URL with scheme handler) AND `isTCP` →
    `ShellExecuteA(buf)` + `EndDialog(0)` (handler took over);
  - `urlType==2` AND `!isTCP` → fall through to error 0x57d ("URL
    needs TCP/IP");
  - `urlType==1` (`news:…`) → lazy `CreateTnc(DAT_0410c25c, 3,
    MCMReadOrInitShortPref_2B(), …)` into ctx[1], cache, then
    `ResolveNewsURLToDeid(tnc2, buf, &resolvedDeid)`; flag=2;
  - else (plain go-word) → re-read text, lazy `CreateTnc("DIRSRV", 7,
    0xffff, …)` into ctx[0], `memset(localesArray,0,4)`, then
    `CTreeNavClient::GetDeidFromGoWord(tnc1, buf, localesArray,
    &resolvedDeid)` (DIRSRV selector 0x03 — see memory
    `project_dirsrv_get_deid_from_go_word`); flag=1.
  Success writes `ctx[2..4] = {deid_lo, deid_hi, flag}` and
  `EndDialog(1)`. HRESULT mapping: `0x103` → string 0x57c ("no
  match"), `0x10002` → 0x57a, anything else → 0x57b. Error path
  releases both tnc slots so a retry rebuilds them, raises the
  toast via MosErrorP, and `SendMessageA(textbox, EM_SETSEL, 0, -1)`
  selects all so the user can immediately retype. EN_CHANGE handler
  enables IDOK only when the textbox is non-empty.

### Go-Word dialog plumbing

- `MCMReadOrInitShortPref_2B()` — `PVReadReg(HKCU, MCM, idx 1,
  value-name id 0x2B)` returning the first uint16 of the registry
  blob. On miss writes the default DWORD `1` via `WriteRegDword`
  before returning. Caller is the orphan FGetGoWord DLGPROC body
  (LAB_04103F83 region) — used as a boolean preference probe.
- `ResolveNewsURLToDeid(tnc, "news:…", &deid)` — strip the optional
  `news:` scheme, seed `deid` with the well-known news-root pair
  (`DAT_0410B7D8` / `DAT_0410B7DC`), `MultiByteToWideChar` the rest
  into a 254-WCHAR buffer, then `CTreeNavClient::ResolveMoniker` to
  walk the moniker chain. Caller: `NewsProtocolHandler` (export #1
  at 0x04104862; orphan code).
- `GoWord_FetchMatchingDeids(out)` — DIRSRV App #7 (`CreateTnc`)
  child enumeration for the FGetGoWord dialog. `GetChildren` on the
  caller-supplied deid pair, then per child `GetNextNode` +
  `CServiceProperties::FGet('q', …)` harvests the 4-byte payload
  (offset +0x04 of the property blob) into a `LocalAlloc`'d dword
  array; result tuple `{ok=1, count, dwords}` is written into the
  caller's 3-int output struct. Final `PeekMessageA(NULL, 0, 0, 0)`
  flushes the message queue post-COM-roundtrip.

### Compiler boilerplate (no observable role)

- `FUN_04103c83`, `FUN_04104955` — twin 8-constant init writers
  populating distinct global blocks at 0x0410A000+ and 0x0410A0B0+.
  Both reached only via tail-JMP thunks listed in the export
  pointer table at 0x04111000; the readers of the targeted globals
  all sit inside PE-header metadata regions (no live code uses
  them).
- `FUN_041089c4`, `FUN_041053e2` — twin single-byte RET stubs.
  Both reached only via export-pointer-table thunks at 0x04111000
  / orphan-thunk LAB_041089d3.

## Per-function status

Worklist: `scratch/annotate-worklist/MCM.DLL.txt`
Progress: `scratch/annotate-progress/MCM.DLL.json`
