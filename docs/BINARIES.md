# MSN95 Client Binary Catalog

Inventory of every file shipped in `binaries/` — the stock MSN 1.0 for Windows 95 client surface (build `5699`, `MSNVER.TXT`). For each component: role in the stack, curated public entry points, and pointers to deeper documentation.

Sources used to enrich descriptions (in priority order when in conflict): active memory files under `~/.claude/projects/.../memory/`, `PROTOCOL.md`, `docs/JOURNAL.md`, `README.md`, raw PE export tables, patents `US5956509` (MPC/Marvel), `US5907837` (content), `US5774668` (gateway), `reference/Blackbird.html`.

Totals: **54 entries** — 47 PE modules (32 DLLs, 11 EXEs, 4 content bundles `.NAV`/`.NED`) + 6 data/config files + 1 directory (`CACHE/`). All PE files are `IMAGE_FILE_MACHINE_I386` (`0x14c`), subsystem GUI, except `MMVDIB12.DLL` which targets subsystem 1 (Native/NT driver value — historical MedView quirk).

Legend:
- **Ghidra status** — *Annotated* (imported to `MSN95.gpr` with RE notes), *Imported* (raw, no notes), *Not imported*.
- **Exports** — selective; max ~12 per entry, prioritising named entries invoked from other modules, framework hooks (`DllGetClassObject`, `DllMain`), and anything already reverse-engineered.

---

## 1. Protocol & Transport Core

The wire layer — everything that moves Marvel RPC packets between the PE host and the server farm.

### MPCCL.DLL — *Marvel Protocol Client Library* (DLL, 88 KB)

Primary MPC client-side runtime implementing the "Marvel" RPC protocol described in US5956509. Instantiated as a COM object; every higher-level service client (TREENVCL, TREEEDCL, DATAEDCL, FTMAPI, CCAPI) sits on top of it. Handles method marshalling, retries, and dispatch over the shared MOSCL session.

**Key exports**
- `DllGetClassObject` [1] — COM class-factory entry; SVC service clients use this to acquire MPC interfaces.
- `DllCanUnloadNow` [2]
- `_DllMain@12` [3]

Everything else is ordinal/class-object mediated (no named method exports).

**Ghidra status**: Annotated. **Imports**: `MOSCL.DLL` (transport), `MCM.DLL`, `CRTDLL.dll`.

### MOSCP.EXE — *MOS Communication Provider* (EXE, 68 KB)

The process that owns the actual modem/TAPI connection to the MSN data centre. No exports (it's a host, not a library). Ground truth for the **1024-byte client receive buffer** (see `project_client_recv_buffer.md`) — any server reply larger than that must be fragmented at the wire layer.

**Imports**: `USER32`, `KERNEL32`, `ADVAPI32`, `MOSMISC.DLL`, `TAPI32.dll`.

**Ghidra status**: Annotated (receive-side buffer and packet handlers). **Notes**: Communicates with clients via MOS pipes (see `MOSCL.DLL`) and ARENA.MOS shared memory.

### MOSCL.DLL — *MOS Client Library* (DLL, 36 KB)

Shared-memory + named-pipe IPC between the various client EXEs (Explorer, Guide, MosView, …) and `MOSCP.EXE`. Exposes the MOS pipe/slot abstraction layered underneath MPCCL.

**Key exports**
- `_OpenMOSPipe@8` [18], `_OpenMOSPipeEx@12` [19], `_OpenMOSPipeWithNotify@24` [20]
- `_ReadMOSPipe@16` [27], `_WriteMOSPipe@20` [32]
- `_OpenMOSSession@8` [23], `_CloseMOSSession@4` [4]
- `_OpenMOSConnection@16` [17], `_CloseMOSConnection@4` [2]
- `CreateMosSlot` [8], `OpenMosSlot` [25], `ReadMosSlot` [28], `WriteMosSlot` [33]
- `_InitMOS@8` [16], `_TerminateMOS@0` [31]
- `_GetMOSLastError@4` [11]

**Ghidra status**: Annotated. **Imports**: only `USER32`, `KERNEL32`, `ADVAPI32` — sits at the bottom of the stack. **Notes**: MosSlot shared-mem IPC uses `ARENA.MOS` as the backing object.

### ENGCT.EXE — *ENG Communication Transport* (EXE, 72 KB)

Alternate transport for internet-era MSN (post-dial-up). Links `WSOCK32`, `RASAPI32`, and `MOSMISC` but **not** `MPCCL`/`MOSCL` — it's a parallel TCP/IP-oriented connection manager (sockets + RAS). No exports.

**Imports**: `USER32`, `KERNEL32`, `ADVAPI32`, `WSOCK32.dll`, `MOSMISC.DLL`, `RASAPI32.dll`.

**Ghidra status**: Annotated. **Notes**: Pair with the `IfTCPthen*` exports in `MCM.DLL` — together they form the TCP-aware code paths.

---

## 2. Application Hosts (process owners)

Each `.EXE` is a separate MSN-aware process hosted by the user. Most delegate their real work to service-client DLLs.

### GUIDE.EXE — *The Guide / login shell* (EXE, 116 KB)

The "invisible" master-process. First thing to launch after connection; keeps the MPC session alive, proxies ShellExecute-style navigation, and drives the MSN Central / MSN Today windows via HOMEBASE resources. Suicide of Guide → `FGuideIsDead` in MCM → forced disconnect.

**Key exports**
- `SzExpandDataCenter` [1] — only named export (data-centre resolution for hostname macros).

**Ghidra status**: Annotated. **Imports**: `MOSCL`, `MCM`, `MOSMISC`, `MOSCC`, `ole32`. **Notes**: see `project_msn_today_worker_debug.md` and `project_msn_central_icon_dispatch.md` for the click-dispatch flow that routes through HOMEBASE → GUIDENAV.

### MOSVIEW.EXE — *MedView document viewer host* (EXE, 54 KB)

Registered as App #6 (`Media_Viewer`) in the MOS Applications table (see `archive/data_dumps.md`). Spawned via `HRMOSExec` when the user opens an MVC title. Loads the MedView DLLs (MVCL14N/MMVDIB12/MOSCOMP) and talks to CCAPI for linking.

**Key exports**
- `CreateMediaViewWindow` [1]
- `MosViewInit` [2], `MosViewStartConnection` [3], `MosViewTerminate` [4]

**Ghidra status**: Annotated. **Imports**: `MVCL14N`, `MMVDIB12`, `MOSCOMP`, `MCM`, `CCAPI`. **Notes**: see `docs/MOSVIEW.md` for the launch contract, single-instance table, title selector formats, and embedded MedView command language.

### SIGNUP.EXE — *New-member sign-up host* (EXE, 163 KB)

Launched via CCAPI's `MOSX_HrExecFromDeid` → `ShellExecute` on `"SIGNUP.EXE /b"` (case 0x18). Hosts **BILLADD.DLL**, which in turn RPCs a per-process MPC session to Billing — billing runs out-of-proc from Explorer. No exports.

**Imports**: `MCM`, `ftmapi.DLL`, `MOSCUDLL`, `MOSCC`, `SUUTIL`, **`BILLADD.dll`**.

**Ghidra status**: Annotated (billing dialog chain, Price dialog entry). **Notes**: See `project_signup_process.md` + `project_signup_price_dialog.md` for the `FSetPricingPlanText` / `plans.txt` contract.

### MSNFIND.EXE — *Directory Find front-end* (EXE, 51 KB)

The "Find → MSN Member / Bulletin Board / Service" dialog surface. Thin Win32 host that delegates to `FINDSTUB.DLL → MOSFIND.DLL` COM objects. No exports.

**Imports**: `TREENVCL.DLL`, `CCAPI.DLL`, `SVCPROP.DLL`, `MCM`, `MOSCUDLL`, `MSVCRT20.dll` (note: MSVCRT, not CRTDLL — possibly an in-tree tool rebuilt later).

**Ghidra status**: Not imported.

### TEXTCHAT.EXE — *Text chat host* (EXE, 52 KB)

CF (Conversation/Conference) client host. Re-exports a pair of `CConversation` methods so plug-in DLLs can probe/rejoin via `GetProcAddress` without a hard link on `CONFAPI.DLL`.

**Key exports**
- `?FInConversation@CConversation@@QAEHXZ` [1]
- `?SzConfName@CConversation@@QAEPADXZ` [2]

**Ghidra status**: Not imported. **Imports**: `CONFAPI.DLL`.

### CCDIALER.EXE — *Calling-card dialer launcher* (EXE, 21 KB)

Tiny shim invoked via CCAPI Calling-Card storage (`?HrExecute@CCcStorage@@`) to dial a saved MSN calling card. No exports; imports `CCAPI.DLL` + `ole32`.

**Ghidra status**: Not imported.

### DNR.EXE — *Down-n-Run* (EXE, 3.5 KB)

Trivial launcher registered as App #7 (`Down_Load_And_Run`). Called after FTM downloads an EXE bundle; imports only `KERNEL32` + `SHELL32` and forwards execution to the downloaded payload. No exports.

**Ghidra status**: Not imported. **Notes**: See MCM `HRMOSExec` dispatch for case c==7 URL-launcher semantics (`project_mcm_hrmosexec.md`); DNR is the default for App#7.

### FTMCL.EXE — *File Transfer Manager client UI* (EXE, 45 KB)

The taskbar "Transfer Queue" / download progress UI. Imports `ftmapi.DLL` + `MOSCUDLL` + `MOSCL` — the heavy lifting is in FTMAPI; this process owns the window. No exports.

**Imports**: `ftmapi.DLL`, `MCM`, `MOSCUDLL`, `MOSCL`, `OLEAUT32`.

**Ghidra status**: Not imported.

### ONLSTMT.EXE — *Online Statement viewer* (EXE, 72 KB)

App #8-ish in the MOS table — shows billing statements pulled from the server. No exports. Uses MOSCUDLL's OLE worker-thread helpers + standard COMCTL32 UI.

**Imports**: `MOSCUDLL`, `MCM`, `COMCTL32`, `ole32`.

**Ghidra status**: Imported (per `gitStatus`: `src/server/services/onlstmt.py` is tracked — server side handled; client is raw).

---

## 3. Shell & Namespace

MSN's Explorer namespace extension. `MOSSHELL.DLL` is the core shell extension registered as the `Microsoft Network` IShellFolder; the others are data-edit/tree-edit clients it consumes.

### MOSSHELL.DLL — *MSN Shell Extension* (DLL, 178 KB)

The biggest single DLL: IShellFolder/IShellView/IContextMenu/IExtractIcon implementation that makes "The Microsoft Network" a first-class Explorer namespace. Hosts `CMosTreeNode`, `CMosViewWnd`, `CMosTreeEdit`, `CDIBWindow` — nodes, views, editors, and the banner DIB window. Loads **only inside EXPLORER.EXE** (see `reference_mosshell_host_process.md`).

**Key exports** (311 total — selected)
- COM: `DllGetClassObject` [310], `DllCanUnloadNow` [309], `DllPrepareToUnload` [311]
- Node lifecycle: `?Exec@CMosTreeNode@@` [95], `?ExecuteCommand@CMosTreeNode@@` [99], `?GetChildren@` (via IMosTreeNode), `?Properties@CMosTreeNode@@` [250]
- Icon pipeline: `?GetShabbyToFile@CMosTreeNode@@` [173], `?GetShabbyViaFtm@` [174], `?HrSaveResIconToFile@@` [208]
- Property cache: `?GetProperty@CMosTreeNode@@` [159], `?RememberProperty@` [267], `?HrFindPropertyInCache@` [198]
- Navigation: `?HrGetPMtn@@` [202], `?HrBrowseObject@@` [186], `?LinkNode@` [225]
- Favorites/MFP: `?MFP_FAdd@@` [228], `?MFP_Delete@@` [227], `?MFP_GetCount@@` [230]
- View: `?CreateBannerWindow@CMosViewWnd@@` [74], `?FillContextMenu@CMosViewWnd@@` [115]

**Ghidra status**: Annotated (heavy — shabby pipeline, property dispatch, `DIRSRV` click routing). **Notes**: `project_mosshell_shabby_call_path.md`, `project_dirsrv_click_dispatch.md`.

### TREENVCL.DLL — *Tree Navigation Client* (DLL, 16 KB)

MPC client-side wrapper for the `IMosTree` *navigation* interface — the service-agnostic "walk this subtree" API. Consumed by MOSSHELL and every `.NAV` bundle. Provides `CTreeNavClient` (navigation) and ships a tiny `CServiceProperties` (property-bag) surface.

**Key exports**
- `?CreateTnc@@YAPAVCTreeNavClient@@...` [15]
- `?GetChildren@CTreeNavClient@@` [19] — returns `CServiceProperties` per child.
- `?GetProperties@CTreeNavClient@@` [28], `?GetNextNode@CTreeNavClient@@` [23], `?GetNthNode@CTreeNavClient@@` [25]
- `?GetParents@CTreeNavClient@@` [27]
- `?GetShabby@CTreeNavClient@@` [30], `?FreeShabby@CTreeNavClient@@` [18]
- `?GetDeidFromGoWord@CTreeNavClient@@` [21]
- `?ResolveMoniker@CTreeNavClient@@` [36], `?FreeMoniker@CTreeNavClient@@` [17]
- `?ConnectionDropped@CTreeNavClient@@` [14], `?IsValid@CTreeNavClient@@` [31]
- `?SetTimeOut@CTreeNavClient@@` [38]
- `_DllMain@12` [39]

**Ghidra status**: Annotated. **Notes**: Wire↔cache property name mapping for DIRSRV documented in `project_dirsrv_click_dispatch.md` (`'a'/'e'` ≠ internal `'z'/'c'`).

### TREEEDCL.DLL — *Tree Edit Client* (DLL, 17 KB)

Sibling of TREENVCL for the *edit* side — `CTreeEditClient` exposes mutate/reorder/delete against a subtree. Used by navigators that permit user-created content (e.g., Favorites folders, BBS posts).

**Key exports**
- `?AddNode@CTreeEditClient@@` [13], `?DeleteNode@CTreeEditClient@@` [17]
- `?LinkNode@CTreeEditClient@@` [26], `?UnlinkNode@CTreeEditClient@@` [43]
- `?OrderChildren@CTreeEditClient@@` [28]
- `?AddShabby@CTreeEditClient@@` [15], `?DeleteShabby@CTreeEditClient@@` [18]
- `?GetDataSets@CTreeEditClient@@` [20]
- `?SetProperties@CTreeEditClient@@` [42]
- `?Lock@CTreeEditClient@@` [27], `?Unlock@CTreeEditClient@@` [44]
- `CreateTec` [45], `_DllMain@12` [46]

**Ghidra status**: Imported raw.

### DATAEDCL.DLL — *Data Edit Client* (DLL, 12 KB)

Record-level editor for tabular data services (the non-tree sibling of TREEEDCL). `CDataEditClient` talks to a `CServiceProperties` and mutates individual rows keyed by `T_LARGE_INTEGER`.

**Key exports**
- `?Add@CDataEditClient@@` [10], `?Delete@CDataEditClient@@` [13], `?SetProperties@CDataEditClient@@` [25]
- `?GetProperties@CDataEditClient@@` [15]
- `?AddRef@CDataEditClient@@` [11], `?Release@CDataEditClient@@` [23]
- `?ConnectionDropped@CDataEditClient@@` [12], `?IsValid@CDataEditClient@@` [19]
- `?GetIMos@CDataEditClient@@` [14]
- `?SetFInteractive@CDataEditClient@@` [24]
- `CreateDec` [26] — factory.

**Ghidra status**: Not imported. **Imports**: `SVCPROP.DLL`, `securcl.DLL`.

---

## 4. Service Clients (MPC-layer libraries)

The "business-logic" DLLs: each wraps a service interface on top of MPCCL.

### SVCPROP.DLL — *Service Properties* (DLL, 11 KB)

Shared `CServiceProperties` property-bag used by every service. Serialises/deserialises the tagged-property blobs that travel on the wire — the structure read by `FDecompressPropClnt` is what the Python server writes in `src/server/store/fixtures.py`.

**Key exports**
- `?FDecompressPropClnt@@` [14], `?FDecompressPropSrv@@` [15], `?FDecompressPropSrvFromSrv@@` [16]
- `?CompressPropClnt@@` [9], `?CompressPropSrv@@` [10]
- `?FCompressPropClntInBuffer@@` [12], `?FCompressPropSrvInBuffer@@` [13]
- `?GetCompressedSizeClnt@@` [28], `?GetCompressedSizeSrv@@` [29]
- `?FInit@CServiceProperties@@` [22], `?FGet@CServiceProperties@@` [20,21], `?FSet@CServiceProperties@@` [24,25]
- `?FDelete@CServiceProperties@@` [17], `?FExtendProp@CServiceProperties@@` [18]

**Ghidra status**: Annotated. **Notes**: Ground-truth for property type bytes (0x0A ANSI, 0x0B char, 0x41 blob, …). See `project_dirsrv_dialog_props_investigation.md`.

### MCM.DLL — *MSN Central Manager* (DLL, 111 KB)

The client-wide singleton: session orchestration (connect, disconnect, reconnect), phonebook / TAPI dialing, application dispatch (`HRMOSExec`), command-line parsing, error reporting. Every EXE in the client talks to it.

**Key exports** (71 total — selected)
- App dispatch: `HRMOSExec` [33], `HRMOSExtract` [34], `HandleHelp` [35]
- Session: `FMCMOpenSession` [27], `MCMCloseSession` [41], `FMCMMakeCall` [26], `FMCMCancelCall` [25]
- Dial/phonebook: `PBKDisplayPhoneBook` [54], `PBKAutoPick` [49], `PBKSyncPhoneBooks` [62], `PBKPickNumber` [61], `MSNAutoDialer` [2]
- State queries: `FAmIOnline` [7], `FGuideIsDead` [21], `FGetCurrentLocation` [11], `FGetDeviceID` [12]
- URL: `CheckURLType` [5], `NewsProtocolHandler` [1]
- Error: `MosError` [45], `MosErrorP` [47], `MosCommonError` [44], `GetLastMCMError` [31]
- Util: `LoadAndCallW` [40], `MsgWaitForSingleObject` [48]

**Ghidra status**: Annotated. **Notes**: `HRMOSExec` @ `0x041020d8` dispatches via `HKLM\SOFTWARE\Microsoft\MOS\Applications\App #N`; App-table in `archive/data_dumps.md`. `project_mcm_hrmosexec.md` documents the c==7 URL-launcher path.

### CCAPI.DLL — *Calling Card API* (DLL, 29 KB)

The MSN "Calling Card" storage + navigation-dispatch engine. `MOSX_*` entry points are how HOMEBASE/GUIDENAV commands get turned into actions (goto, exec, favorite-add, email-launch).

**Key exports** (39 total — selected)
- `MOSX_GotoMosLocation` [30]
- `MOSX_HrExecFromDeid` [33], `MOSX_HrExecSzMnid` [35], `MOSX_HrExecPidl` [34]
- `MOSX_HrAddToFavoritePlaces` [31], `MOSX_HrCreateCCFromAppidDeid` [32]
- `MOSX_HrGetDataObjFromAppidDeid` [36], `MOSX_HrShowMnid` [37]
- `HrCreateMosDataObj` [27], `HrCreateMosDataObjEx` [28], `HrSaveCallingCard` [29]
- `?HrExecute@CCcStorage@@` [7], `?HrInitFromCCDI@CCcStorage@@` [14]
- `?HrLoadFromFile@CCcStorage@@` [15], `?HrGetIcon@CCcStorage@@` [11]
- `ReportCCErr` [38]

**Ghidra status**: Annotated. **Notes**: Case 2 of `MOSX_GotoMosLocation` ShellExecutes EXCHNG32 for EMAIL icons (`project_msn_central_email_dispatch.md`).

### HOMEBASE.DLL — *MSN Central resource pack* (DLL, 57 KB)

Resource-only DLL — **0 exports, 0 imports**. Ships the RCDATA bitmaps / hot-spot definitions that paint the MSN Central home screen. Read by GUIDENAV at click-time to resolve icon → command (JUMP / LJUMP / EMAIL / EXECUTE 0x3000).

**Ghidra status**: Annotated (RCDATA parsing in GUIDENAV references this module). **Notes**: See `project_msn_central_icon_dispatch.md` — 'b' bit 0x01 controls Browse vs Exec.

### FTMAPI.DLL — *File Transfer Manager API* (DLL, 64 KB)

Client wrapper for the File Transfer service — chunked downloads with resume, progress, and post-download unpack. `CXferService` is the per-session singleton; `CXferFile` is one in-flight transfer.

**Key exports** (55 total — selected)
- `HrGetXferService` [2], `HrReleaseXferService` [3]
- `HrRequestDownload` [4], `?HrRequestDownload@CXferFile@@` [34]
- `?HrStartDownload@CXferFile@@` [35]
- `HrFinishRequest` [5], `HrDeleteRequest` [6]
- `HrQueryProgress` [7], `?HrQueryProgress@CXferFile@@` [33], `?GetPercentageDone@CXferFile@@` [27]
- `?HrUnpack@CXferFile@@` [36]
- `HrMos2CompFile` [51], `HrMos2DecompFile` [52]
- `FFtmApproxTime` [1], `FormatTimeString` [50]
- `_FGetDefaultDownloadDir@4` [46], `_FGetTempFileName@8` [48]

**Ghidra status**: Annotated.

### MOSCUDLL.DLL — *MOS Client Utility DLL* (DLL, 21 KB)

Kitchen-sink utilities: OLE worker-thread factory (used by the login path and by DnR c==7 `Exec`), price/currency formatting, menu merging, FTM-with-UI wrapper.

**Key exports**
- `?CreateOleWorkerThread@@` [1], `?PulseOleWorkerThread@@` [14], `?ShutdownOleWorkerThread@@` [15], `?WaitForOleWorkerThread@@` [17]
- `?HrFtmDownloadWithUI@@` [10], `?HrFtmDownloadWithUIFRI@@` [11]
- `?FFormatPrice@@` [3], `?LoadCurrencyName@@` [13], `?g_rgISOCurrencyCodes@@` [19]
- `?HrEnsureMsnInstalled@@` [9]
- `?HrSzForByteCount@@` [12]
- `?FMergeMenus@@` [4], `?HMenuSubFromId@@` [8]
- `?GetAssociatedExecutable@@` [6]
- `FEnsureMarvelDesktopFile` [20]

**Ghidra status**: Annotated. **Notes**: `CreateOleWorkerThread` has two callers — sync login vs async DnR (`Exec c==7` / `ExecUrlWorkerProc`) (`project_msn_today_worker_debug.md`). MSN Today itself dispatches via App #6 (MOSVIEW.EXE), not this worker.

### CONFAPI.DLL — *Conference API* (DLL, 22 KB)

Real-time conference/chat service client. `CConversation` is the session; `CConfMsg` is a single message frame.

**Key exports**
- `?CceJoin@CConversation@@` [5]
- `?ErrSendData@CConversation@@` [7], `?ErrSendText@CConversation@@` [8]
- `?ReceiveMessage@CConversation@@` [12], `?ReleaseMessage@CConversation@@` [13]
- `?ErrHostSetStatus@CConversation@@` [6]
- `?Exit@CConversation@@` [9], `?FInConversation@CConversation@@` [10]
- `?FInitMsg@CConfMsg@@` [11]
- `?SzConfName@CConversation@@` [14]
- `CmdInitializeConnection` [15], `TerminateConnection` [19]
- `FGetConferenceList` [17], `FreeConferenceList` [18]
- `DisplayUserInfo` [16]

**Ghidra status**: Annotated.

### SACLIENT.DLL — *SysAdmin Client* (DLL, 28 KB)

Admin-only client for the System-Admin service (forum sysop / moderator controls). All factory exports — each returns an interface pointer on a concrete admin object.

**Key exports**
- `CreateSysAdminClient` [1]
- `CreateSysAdminDistList` [2], `CreateSysAdminMailContainer` [3]
- `CreateSysAdminMasterContainerList` [4], `CreateSysAdminMasterDistList` [5]
- `CreateSysAdminMasterInetAddrList` [6], `CreateSysAdminMasterList` [7]
- `CreateSysAdminMasterTokenList` [8], `CreateSysAdminMasterUserGroupList` [9]
- `CreateSysAdminToken` [10], `CreateSysAdminUserGroup` [11]

**Ghidra status**: Annotated. **Imports**: only `KERNEL32` + `ole32` — pure COM surface, business logic pulled from MPC service.

### SECURCL.DLL — *Security Client* (DLL, 15 KB)

Tiny security-ticket decoder. Two exports, both on `TICKET` structures — used by DATAEDCL/TREEEDCL to validate per-row write rights.

**Key exports**
- `?HrDecodeTicket@@YAJPAUTICKET@@PAPAU1@@Z` [1]
- `?HrFreeTicket@@YAJPAUTICKET@@@Z` [2]

**Ghidra status**: Not imported.

### BILLADD.DLL — *Billing & Address dialog pack* (DLL, 80 KB)

All billing/address collection dialogs used during Sign-up and plan-change flows. Hosted exclusively by `SIGNUP.EXE` (own process → own MPC session). All exports prefixed `FDw*` / `FDo*` / `FSet*`.

**Key exports**
- `FDoPlansDlg` [1], `FDoPriceDlg` [2] — *Plans* and *Price* modal dialogs.
- `FSetPricingPlanText` [19] — reads `[Plans]Plan<id>` from `plans.txt` (`^` → newline); documented in `project_signup_price_dialog.md`.
- `FDwGetBillingHandle` [14], `FDwCloseBillingHandle` [6]
- `FDwDoBillingDlg` [8], `FDwChangePaymentMethod` [4]
- `FDwGetAddressHandle` [11], `FDwCloseAddressHandle` [5]
- `FDwDoAddressDlg` [7], `FDwAddressInitFromRegistry` [3]
- `FDwGetAddressCountry` [10], `FDwSetAddressCountry` [15]
- `FDwGetBillingAsPM` [13], `FDwSetBillingFromPM` [16]

**Ghidra status**: Annotated (Price/Plans dialog chain).

### SUUTIL.DLL — *Sign-Up Utility* (DLL, 18 KB)

Small helper DLL for the sign-up UI (TAPI country list, editbox helpers, process-heap wrappers). Used exclusively by SIGNUP.EXE / BILLADD.DLL.

**Key exports**
- `FGetTAPICountryList` [11], `FCountryIDFromName` [7], `DwCountryIDToIndex` [5]
- `FSetEditBoxSz` [17] — the function BILLADD's Price dialog targets (hwnd 0x12e).
- `FEditBoxLimitText` [9], `FSetDlgItemStrRsrc` [16]
- `FEnableControl` [10], `FShowControl` [19]
- `FSzNumbersOnly` [20], `FRemoveSpaces` [15]
- `FOwnerDrawButtonIcon` [12]
- `FProcessHeapAlloc` [13], `FProcessHeapFree` [14]
- `DwCbSz` [4], `Sz2Dw` [21]

**Ghidra status**: Annotated.

### MSNDUI.DLL — *MSN Dial-UI* (DLL, 24 KB)

Standard COM stub — `DllCanUnloadNow` + `DllGetClassObject` only. Probably the sign-up / connect dialog UI COM server (paired with MCM.DLL's dialing calls).

**Imports**: `USER32`, `SHELL32`, `COMCTL32` — dialog-shaped imports.

**Ghidra status**: Not imported. **Notes**: Role inferred from name + imports; no wire-level evidence.

### MOSFIND.DLL — *Find service COM server* (DLL, 25 KB)

COM stub backing MSNFIND.EXE's Find dialog. Two exports: the COM lifecycle. Imports TREENVCL/SVCPROP — i.e., it navigates the Find service subtree.

**Imports**: `SVCPROP.DLL`, `TREENVCL.DLL`, `MSVCRT20.dll`.

**Ghidra status**: Not imported.

### FINDSTUB.DLL — *Find client stub* (DLL, 10 KB)

Even thinner — `DllCanUnloadNow`, `DllGetClassObject`, **`MSNFind` [3]**. The `MSNFind` symbol is the public API other code calls to launch the find dialog (which then hands off to MOSFIND.DLL / MSNFIND.EXE).

**Ghidra status**: Not imported.

### MOSCOMP.DLL — *MOS Compression & Progressive Graphics* (DLL, 146 KB)

Image/metafile decompression + progressive rendering (PITS — Progressive Image Transmission Scheme). `WLTPIT*` exports do Huffman-coded DIB decode used by MedView content.

**Key exports** (38 total — selected)
- `WLTPITInitialize` [30], `WLTPITTerminate` [32]
- `WLTPITCompressHuffDecoder` [25], `WLTPITInitHuffDecoder` [29], `WLTPITTerminateHuffDecoder` [33]
- `WLTPITDecompress` [27]
- `WLTPITPaintDIB` [31], `WLTPITWndPaletteChanged` [34], `WLTPITWndQueryNewPalette` [35]
- `WLTPITCreateProgTransInfo` [26], `WLTPITDeleteProgTransInfo` [28]
- `PlayMetaFileJR` [21], `PlayMetaFileProgressiveJR` [22]
- `?Meta_play@CPlayMeta@@` [6], `?Meta_add@CPlayMeta@@` [4]
- `?ProgCreate@@` [9], `?ProgAddData@@` [7], `?ProgPaint@@` [10]
- `ghUniversalPalette` [38], `g_dwXFactor` / `g_dwYFactor` [36,37]

**Ghidra status**: Not imported. **Imports**: only `KERNEL32`/`GDI32`/`USER32` — low-level rendering.

### MOSCC.DLL — *MOS Custom Controls* (DLL, 46 KB)

Custom control (hot-spot bitmap) library used by HOMEBASE and the navigators. Tiny API.

**Key exports**
- `InitCustomControls` [4]
- `GetBitmapCCSize` [2]
- `GetHotspotCount` [3], `FGetNthHotspot` [1]

**Ghidra status**: Not imported. **Notes**: Paired with the RCDATA hot-spot maps in HOMEBASE / `.NAV` bundles.

### MOSMISC.DLL — *MOS Miscellaneous* (DLL, 9 KB)

General-purpose client helpers — registry wrappers, path checks, dialog utilities. Linked by virtually every EXE/DLL.

**Key exports**
- `FGetRegistryBool` [5], `FGetRegistryDword` [6], `FGetRegistrySz` [8], `FGetRegistryPvAlloc` [7]
- `FRegistryBoolSet` [11], `FRegistryKeyExists` [12], `SetRegistryBool` [22], `SetRegistryRaw` [23]
- `PVReadReg` [20], `PVReadRegSt` [21], `FreeRegistryPv` [15]
- `DeleteRegistryValue` [2], `FWriteRegSt` [14]
- `FFindMSNFile` [3], `GetModulePath` [16]
- `CenterDlg` [1], `MOSDefDlgProc` [19], `SetSelFocus` [24]
- `Sz2Int` [25], `FSzIsSingleByte` [13]

**Ghidra status**: Annotated.

### MOSSTUB.DLL — *MOS stub COM server* (DLL, 7 KB)

Minimum-viable COM stub — the smallest DLL in the shipment. Two exports, `DllCanUnloadNow` + `DllGetClassObject`, and nothing else. Exact CLSID and purpose **unknown** from static evidence alone — imports are only `USER32/KERNEL32/ADVAPI32`.

**Ghidra status**: Not imported. **Notes**: Role inferred from the COM-stub shape; no wire evidence.

### MOSAF.DLL — *MOS "AF"* (DLL, 24 KB)

Another COM stub — `DllCanUnloadNow` + `DllGetClassObject`. Imports are beefy (`ftmapi`, `mcm`, `MOSCUDLL`) so it's doing real work behind the class object, just nothing named. **"AF"** likely = **Audio/Forums** or **Application Framework**; true role unknown.

**Ghidra status**: Not imported. **Notes**: Role inferred from imports; honest gap — no memory/wire evidence.

### CCEI.DLL — *Calling Card Extension Interface* (DLL, 13 KB)

COM stub; paired imports on `COMCTL32`/`ole32`/`CRTDLL`. Two exports.

**Key exports**
- `DllCanUnloadNow` [2], `DllGetClassObject` [3]

**Ghidra status**: Not imported. **Notes**: Name suggests a CCAPI shell-extension plugin.

### CCPSH.DLL — *Calling Card Property Sheet Handler* (DLL, 13 KB)

COM stub. Imports `CCAPI.DLL` + `SHELL32`/`COMCTL32` — classic Explorer property-sheet-handler shape.

**Key exports**
- `DllCanUnloadNow` [2], `DllGetClassObject` [3]

**Ghidra status**: Not imported.

---

## 5. MedView / Multimedia

MedView (`MV*`) is the Microsoft multimedia viewer engine (shipped earlier with Encarta / Bookshelf). MSN uses it for "Download and Read" titles and the Media Viewer app.

### MVTTL14C.DLL — *MedView Title (Client)* (DLL, 75 KB)

MedView title-loader with MSN service hooks. Exports `TitleConnection`, `TitleOpenEx`, `TitleClose`, plus the baggage-fetch primitives that pull title media over FTM.

**Key exports** (60 total — selected)
- `TitleConnection` [10], `TitleNotifyLayout` [11], `TitlePreNotify` [12], `TitleClose` [38]
- `TitleOpenEx` [41], `TitleQuery` [42], `TitleValid` [43], `TitleGetInfo` [39]
- `TitleLoadDLL` [40]
- `DetachPicture` [1], `DownloadPicture` [2], `GetDownloadStatus` [3], `GetPictureInfo` [4], `GetPictureName` [5]
- `BaggageOpen` [17], `BaggageClose` [15], `BaggageRead` [18], `BaggageGetFile` [16]
- `WordWheelOpenTitle` [47], `WordWheelLookup` [46], `WordWheelQuery` [49]
- `?hrAttachToService@@` [14], `?fDetachFromService@@` [13]

**Ghidra status**: Annotated.

### MVCL14N.DLL — *MedView Client Library (Native)* (DLL, 109 KB)

The MedView rendering/scrolling/selection engine — 154 exports, all `MV*` / `fMV*` / `hMV*` / etc. Text layout, hotspot navigation, word-wheel search, embedded-window support.

**Key exports** (154 total — *heavily* curated)
- `MVActivate` [1], `MVTerminate` [34]
- `MVTitleConnection` [36], `MVTitleClose` [35], `hMVTitleOpenEx` [98]
- `hMVTopicListCreate` [100], `hMVTopicListFromQuery` [101], `hMVTopicListFromTopicNo` [102]
- `MVSelectKey` [21], `MVSelectPoint` [22], `MVSetSelection` [30]
- `fMVScrollToAddr` [70], `xMVScrollX` [152], `yMVScrollY` [154]
- `MVGroupCreate` [12], `MVGroupDuplicate` [13], `MVGroupOr` [17], `MVGroupAnd` [11]
- `MVWordWheelSearch` [43], `hMVWordWheelOpenTitle` [105]
- `MVBaggageAsyncClose` [2], `MVBaggageAsyncGetFile` [3], `MVBaggageAsyncState` [4]
- `fMVSetHotspotCallback` [74], `fMVGetHotspotInfo` [59]

**Ghidra status**: Not imported.

### MVPR14N.DLL — *MedView Presenter* (DLL, 50 KB)

Image-dithering / embedded-window search / metafile playback — the "presenter" layer between MVCL14N and the OS.

**Key exports**
- `MVIMAGEInitialize` [16], `MVIMAGETerminate` [21]
- `MVIMAGEInstallImageProcs` [17], `MVIMAGEInstallMeta` [18]
- `MVIMAGEDither` [12], `MVIMAGEEnableDither` [13], `MVIMAGESetDitherParams` [20]
- `MVIMAGEFlushCache` [14], `MVIMAGESetCacheSize` [19]
- `MVIMAGEWndProc` [22]
- `MetaRead` [23], `MetaRender` [25], `MetaRelease` [24]
- `DefaultBitmapRead` [5], `DefaultBitmapRender` [7], `DefaultBitmapRelease` [6]
- `GetEmbeddedWindowSearchableText` [11]
- `WEP` [1] — Win16-style Windows Exit Procedure (see notes).

**Ghidra status**: Not imported. **Notes**: `WEP` export indicates a partial Win16 heritage even though the PE header is i386 — MedView was originally a 16-bit library.

### MVUT14N.DLL — *MedView Utilities* (DLL, 10 KB)

Low-level MedView utility DLL — memory blocks, group bit-sets, global-heap wrappers. Imports only `KERNEL32`.

**Key exports**
- `BlockInitiate` [6], `BlockCopy` [1], `BlockFree` [2], `BlockGrowth` [5], `BlockReset` [7]
- `GroupCreate` [14], `GroupDuplicate` [15], `GroupFree` [16], `GroupAnd` [13], `GroupOr` [19], `GroupNot` [18]
- `GlobalLockedStructMemAlloc` [10], `GlobalLockedStructMemFree` [11]
- `_GlobalAlloc` [26], `_GlobalFree` [27], `_GlobalLock` [28], `_GlobalUnlock` [32]
- `CheckMem` [8], `DebugSetErr` [9]

**Ghidra status**: Not imported.

### MMVDIB12.DLL — *MedView MM DIB extension* (DLL, 52 KB)

MedView DIB display extension with a MedView hotspot cursor. **Subsystem 1** in the PE header — oddball value (NT native) presumably inherited from an earlier Win16 build.

**Key exports**
- `InitiateMVDIB` [5], `TerminateMVDIB` [6]
- `?Meta_GetDC@CPlayMeta@@` [2], `?Meta_GetPalette@CPlayMeta@@` [3], `?Meta_SetPanic@CPlayMeta@@` [4]
- `gMVDIBHotSpotCursor` [7]
- `WEP` [1]

**Ghidra status**: Not imported. **Imports**: `CCAPI.DLL`, `MVTTL14C`, `MOSCOMP.DLL`, `MVCL14N`. **Notes**: Role inferred from imports + name; no wire evidence.

---

## 6. Navigation / Content Bundles

The `.NAV` / `.NED` files are PE DLLs with non-standard extensions. They carry bitmap art + per-service click-dispatch overrides; MOSSHELL loads them on demand when entering a service.

### GUIDENAV.NAV — *MSN Central / Today navigator* (DLL, 40 KB)

Navigator bundle for the MSN Central (home screen) and MSN Today surfaces. Wire-dispatches JUMP/LJUMP/EMAIL/EXECUTE clicks from the HOMEBASE hot-spot bitmaps into CCAPI `MOSX_*` calls. Minimal exports — real payload is resources.

**Key exports**
- `DISCONNECT` [1]
- `GETPMTN` [2]

**Ghidra status**: Annotated. **Notes**: Click-dispatcher function `DispatchHomebaseClick` → CCAPI (see `project_msn_central_icon_dispatch.md`).

### DSNAV.NAV — *Directory Services navigator* (DLL, 31 KB)

Navigator bundle for the Directory Service (DIRSRV) — the member/BBS/ForumGuide listings. Paired with DSNED.NED (its edit companion).

**Key exports**
- `?FStretchBanner@CDIBWindow@@` [17]
- `?SzClassName@CMosXWndClass@@` [20]
- `DISCONNECT` [21]
- `GETPMTN` [22]

**Ghidra status**: Annotated. **Notes**: Dispatches DIRSRV `'a'/'c'` wire props into MOSSHELL's node-click path (`project_dirsrv_click_dispatch.md`).

### BBSNAV.NAV — *BBS navigator* (DLL, 209 KB)

The biggest `.NAV` — all forum/BBS rendering and posting UI. Exports full `CMos*` subclasses (`CMosTreeNode`, `CMosViewWnd`, `CMosTreeEdit`) overriding the shell defaults for the BBS surface, plus a banner-DIB override.

**Key exports**
- `DISCONNECT` [38]
- `GETPMTN` [39]
- `?DeletePmtn@CMosTreeNode@@` [32], `?DeleteViewWnd@CMosViewWnd@@` [33]
- `?FStretchBanner@CDIBWindow@@` [34]
- Class-lifetime: vtable+ctor/dtor for `CMosTreeNode`, `CMosTreeEdit`, `CMosViewWnd`, `CDIBWindow`, `CMosXWindow` (exports 1–31, mangled)

**Ghidra status**: Not imported. **Imports**: `MOSSHELL.DLL`, `TREENVCL.DLL`, `SVCPROP.DLL`, `MAPI32.dll`, `MOSABP32.DLL` — MAPI usage fits BBS mail gateway.

### DSNED.NED — *Directory Services editor* (DLL, 36 KB)

Edit-side companion to DSNAV for DIRSRV (paired with DSNAV at service-load time). Exposes `CDirSrvTreeEdit` and a minimum `GetPropertyDispatch` override.

**Key exports**
- `?FillSPForNewNode@CDirSrvTreeEdit@@` [8]
- `?FormatSizeString@CDirSrvTreeEdit@@` [9]
- `?GetPropertyDispatch@CDirSrvTreeEdit@@` [10]
- `DISCONNECT` [11]
- `GETPMTE` [12] — "Get ProMaster Tree Edit" (edit counterpart of GETPMTN).
- Lifetime: `??0CDirSrvTreeEdit@@` ctors, `??1` dtor, `??_E` / `??_G` vector-delete/scalar-delete dtors.

**Ghidra status**: Annotated (`project_dirsrv_dialog_props_investigation.md`).

---

## 7. Data & Config Files

Non-PE assets shipped alongside the binaries.

### PHONE.PBK — *Marvel phonebook* (data, 44 KB)

Comma-separated phone-access list consumed by `PBKDisplayPhoneBook` / `PBKAutoPick` in MCM.DLL. Columns (inferred from file content): `NPANXX, flag1, flag2, city, areacode, phone, min_bps, max_bps, line_style, type, :S|:A`. `:S` / `:A` tags are the connection-selector (Sync vs Async).

Example rows:
```
65031,1,1,Anniston,205,2369711,2400,2400,2,0,:S
65034,1,1,Birmingham,205,3285719,2400,14400,2,0,:S
2,1,1,Nationwide,,9501288,2400,14400,10,1,:A
```

**Ghidra status**: N/A (text). **Notes**: Shape documented in README.md; consumer in `MCM.DLL`.

### STATE.PBK — *State/Province list* (data, 851 B)

CRLF-delimited list of ~71 state/province names prefixed by a count. Used by the sign-up dialog (BILLADD's address dialog) to populate the "State" combo. First line is the count ("71"), followed by `Alabama`, `Alaska`, `Alberta`, … `British Columbia` is present (intermixed US states + Canadian provinces, no grouping).

**Ghidra status**: N/A (text). **Notes**: Consumed by BILLADD address dialog.

### 800950.DAT — *Opaque binary blob* (data, 10098 B)

Role **unknown**. 10 KB opaque binary — 256 distinct byte values, ~30% zero, no recognised magic (MZ/PK/LZ absent), no embedded strings. Filename `800950` is the decimal of a dial-in access code (US 800-950-xxxx range) — possibly an offline bootstrap phonebook or cached packet. No binary in the ship references the literal `"800950"`.

**Ghidra status**: Not applicable (data). **Notes**: Honest gap — no callers identified. Candidate for future investigation.

### MSNVER.TXT — *Client build tag* (text, 4 B)

Single token: `5699` (no newline). This is the build number referenced by `GUIDE.EXE`'s `FMsnVer`-style checks and the server-side "client version" gate. Matches the MSN 1.0 retail build date range.

**Ghidra status**: N/A.

### The Microsoft Network.MSN — *Desktop-shortcut sentinel* (data, 4 B)

Four bytes: `". \r\n"`. Installed to the user's Desktop; Explorer opens `.MSN` files via the registered verb (goes through MCM `FGetCmdLineInfo` → navigate to MSN root). Content is intentionally trivial — the file's *extension* is what matters.

**Ghidra status**: N/A. **Notes**: `MOSCUDLL!FEnsureMarvelDesktopFile` is the writer.

### INSTBE.BAT — *Back-end installer batch* (text, 2456 B)

MS-DOS batch that moves the BSEN payload to `C:\PROGRA~1\THEMIC~1\BSEN.EXE` (or D:, or prompts for a drive letter via `choice /c:cdefghijklmnopqrstuvwxyz`), runs it with `/o <dir>` to complete the install, then erases itself. Fallback messages reference "Member Assistance → Troubleshooting".

**Ghidra status**: N/A.

### CACHE/ — *Shabby / icon cache* (directory, empty)

Empty directory in the shipment — populated at runtime by `GetShabbyToFile` / `HrSaveResIconToFile` with ICO/EXE/DLL payloads pulled via FTM. Referenced by MOSSHELL.DLL's shabby pipeline (see `project_mosshell_shabby_call_path.md`).

---

## Cross-references

- **Wire protocol**: `../PROTOCOL.md` — packet layout, selectors, property types.
- **Reverse-engineering journal**: `./JOURNAL.md` — chronological notes per component.
- **Active memory index**: `~/.claude/projects/-home-gabriels-projetos-marvel-msn/memory/MEMORY.md` — per-topic RE memories.
- **MOS Applications table** (App #1 – #28 registry dump): `~/.claude/projects/.../memory/archive/data_dumps.md`.
- **Patents**: US5956509 (Marvel/MPC), US5907837 (content), US5774668 (gateway) — historical ground truth for the architecture.
