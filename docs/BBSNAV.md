# BBSNAV.NAV

Reverse-engineering notes for `binaries/BBSNAV.NAV`, the navigator plug-in for
the **BBS service** (App #2 MSN BBS and App #10 Internet Newsgroups). At 214 KiB
it is the largest `.NAV`: unlike the thin DSNAV shim it embeds its **own**
`CMosTreeNode`, `CMosViewWnd` (message-list + reader window) and `CMosTreeEdit`
(posting) subclasses.

Sources: static binary (`wrestool`, PE-resource parse) + live decompilation
against the MSN95 Ghidra project (session `4041a548ca854bd19596d689d4fc5d66` for
`/BBSNAV.NAV`; `3befd2b30ccd4ceb9b033ac5a9c8e6b7` for `/TREEEDCL.DLL`). All
addresses are at BBSNAV's link-time image base `0x7F5F0000` unless prefixed.
Companions:

- `docs/bbs-service-contract.md` — the wire contract this binary implements.
- `docs/DSNAV.md` — structural template (the other DIRSRV-style NAV).
- `docs/TREENVCL.md` — read-side RPC; `docs/BINARIES.md` §TREEEDCL — write-side RPC.
- `docs/MOSSHELL.md` — the shell host whose base classes BBSNAV subclasses.

## 1. Identity

- PE DLL, 214 KiB, image base `0x7F5F0000`, 598 functions, 8 sections.
- Version resource: `FileDescription = "Microsoft Network BBS Navigator"`,
  `InternalName = BBSNAV`, `OriginalFilename = BBSNAV.NAV`.
- Registered as `App #2` (MSN BBS) and reached as `App #10` (Internet
  Newsgroups) — the same binary serves both; see §10.
- **40 exports** across five MSVC subclass surfaces (RTTI-recovered):

  | Surface | Exports | Role |
  |---|---|---|
  | Plug-in entry | `GETPMTN` [39] `0x7F5F4BD0`, `DISCONNECT` [38] `0x7F5F4C0C`, `entry` `0x7F609467` | shell-facing contract + DllMain |
  | `CMosTreeNode` subclass (`CBbsNavTreeNode`) | ctor `0x7F5F8EF5`, `DeletePmtn` `0x7F5F8B0D`, op=, dtors, vftable | the BBS tree node |
  | `CMosViewWnd` subclass (`CBbsViewWnd`) | ctor `0x7F5F9244`, `DeleteViewWnd` `0x7F5F8B2C`, op=, dtors, vftable | message-list + reader window |
  | `CMosTreeEdit` subclass (`CBbsTreeEdit`) | ctor `0x7F5F8DFA`, op=, dtors, vftable | posting / edit object |
  | `CDIBWindow` / `CMosXWindow` / `CMosXWndClass` / `CMosXAllocator` | banner-DIB + frame wrappers + allocator | as in DSNAV |

- **Static imports**: `MOSSHELL.DLL` (194), `USER32` (94), `KERNEL32` (76),
  `GDI32` (25), `ADVAPI32` (5), `COMCTL32` (4), `SHELL32` (2). **That is all.**
  BBSNAV reaches TREENVCL / TREEEDCL / SVCPROP **transitively through MOSSHELL**
  (the `Initialize{Ntnigr,Ecig}` + `CMosTree{Node,Edit}::*` surface), not by
  direct link. `MAPI32.DLL` and `riched32.dll` are **dynamic** `LoadLibrary`
  targets (§9, §8). The `TREEEDCL.DLL` / `MOSABP32.DLL` / `TREENVCL.DLL` /
  `SVCPROP.DLL` name strings present in `.data` are unreferenced hints, not
  loads.
- MOSSHELL surface used: `InitializeNtnigr`/`CleanupNtnigr`/`HrDisconnectNtnigr`,
  `InitializeEcig`/`CleanupEcig`/`HrDisconnectEcig`, the full `CMosTreeNode::*`
  and `CMosViewWnd::*` base vtables, `CMosTreeEdit::*` (incl. `GetTec`,
  `GetPecigTec`, `LinkNode`, `SetProperty`, `AddShabby`, `GetDataSets`,
  `NewObject`, `FillSPForNewNode`), `RgmdsFromRcdata`, `HrAddButtonsFromRcdata`,
  `EnumMosWindows`/`RefreshEmw`, `ReportMosXErr`, `MnidToSz`, `HrGetPMtn`,
  `GetSpecialMnid`.
- ADVAPI32 `Reg*` → window-placement persistence (§7). COMCTL32 `ImageList_*`
  → list-view icons.
- Resources (PE `.rsrc`): bitmaps 1000/1002/1004/6000/6010, icons 1–11,
  menus 103/104/105 + 200–206, dialogs 101/102/107–125, string tables, and
  **RCDATA 6000/6010/6011** (6011 = the list-view column descriptor, §6).

## 2. How the shell reaches it

`MOSSHELL!HrGetPMtn(mnid, IMosTreeNode**, int)` is the gateway. When the mnid's
`app_id` is the BBS service, MOSSHELL `LoadLibrary`s `bbsnav.nav`, resolves
`GETPMTN`, and calls it. Unlike GUIDENAV (client-local), every browse into a BBS
board is a live wire roundtrip over the `"BBS"` service channel.

## 3. Plug-in contract

### 3.1 `GETPMTN(_MosNodeId* mnid, IMosTreeNode** out)` — `0x7F5F4BD0`

Single-branch (no root/child split). Allocs a **256-byte** (`0x100`)
`CBbsNavTreeNode` (`FUN_7F608713(0x100)`), runs `CBbsNavTreeNode_Construct`
(`0x7F5F1051`), AddRefs via vtbl[1]. `E_OUTOFMEMORY` on alloc failure.

`CBbsNavTreeNode_Construct`:
- `CMosTreeNode::CMosTreeNode(this, mnid, &g_BbsNtniGroup)` — base ctor binds the
  read/nav channel.
- installs `vtbl_CBbsNavTreeNode` (`0x7F60E880`).
- `this+0xF0 = FUN_7F5F7ECE(this+0x1C)`; `this+0xF4 = this+0xF8 = this+0xB4 = 0`
  (children-config cache + flags, used by `OkToGetChildren`/threading).
- `g_BbsLiveInstanceCount` (`0x7F610178`) ++.

### 3.2 `DISCONNECT()` — `0x7F5F4C0C`

`HrDisconnectEcig(&g_BbsEcig)` (write channel) then
`HrDisconnectNtnigr(&g_BbsNtniGroup)` (read channel).

### 3.3 `entry` / `BBSNAV_DllMainLogic` — `0x7F609467` / `0x7F5F4C29`

DllMain logic. `DLL_PROCESS_ATTACH`:

```c
g_BbsHInstance = hInst;
InitializeNtnigr(&g_BbsNtniGroup, "BBS", 3, 8, &g_BbsExtraPropTags); // read/nav
InitializeEcig  (&g_BbsEcig,      "BBS", 3, 0);                       // write/edit
InitializeCriticalSection(&g_BbsRefreshCS);
g_BbsAccelerators = LoadAcceleratorsA(hInst, 200);
FUN_7F5F9406(hInst);   // RegisterClass BBSMsgWndClass; LoadLibrary("riched32.dll")
```

`DLL_PROCESS_DETACH`: free `g_BbsCachedColumns`, `CleanupNtnigr`, `CleanupEcig`,
`DeleteCriticalSection`.

## 4. `vtbl_CBbsNavTreeNode` — `0x7F60E880`

89-slot `IMosTreeNode` vtable inheriting `MOSSHELL!CMosTreeNode` (base vftable
`0x7F40CAE0`); un-overridden slots are `jmp [iat]` thunks. Slot numbering = raw
vtable index (slot 0 = `QueryInterface`). **25 BBSNAV-local overrides** (vs
DSNAV's 8) — slot → MOSSHELL method → BBSNAV function:

| Slot | Method | BBSNAV fn | Group |
|---:|---|---|---|
| 5  | `DeletePmtn`          | `0x7F5F109A` | lifetime |
| 9  | `NeedConnection`      | `0x7F5F1107` | nav |
| 16 | `GetProperty`         | `0x7F5F1538` | synthesises `h` (icon) locally; else base |
| 28 | `GetDetailsStruct`    | `0x7F5F14A3` | column descriptor (RCDATA 6011) |
| 29 | `GetShabbyToFile`     | `0x7F5F137B` | icon/banner blob |
| 30 | `GetShabbyPropToFile` | `0x7F5F13E3` | icon/banner blob |
| 36 | `GetViewWndObject`    | `0x7F5F1307` | builds `CBbsViewWnd` (§8) |
| 44 | `OkToGetChildren`     | `0x7F5F1427` | pre-reads `_F`; gates child fetch |
| 46 | `GetParent`           | `0x7F5F12CE` | tree topology |
| 51 | `Exec`                | `0x7F5F110C` | leaf verb |
| 52 | `AddActivationKey`    | `0x7F5F11CC` | verb keys |
| 53 | `ExecOneActivationKey`| `0x7F5F121B` | verb keys |
| 55 | `AddPropPages`        | `0x7F5F17AE` | Properties sheet (§5) |
| 56 | `GetContextMenu`      | `0x7F5F1957` | context menu |
| 57 | `AddMenus`            | `0x7F5F198E` | menu merge |
| 59 | `GetCmdText`          | `0x7F5F19D6` | command text |
| 60 | `GetCmdState`         | `0x7F5F1A9E` | command enable/check |
| 61 | `ExecuteCommand`      | `0x7F5F1ADB` | verb dispatch (Compose/Reply/Forward) |
| 65 | `GetRightsMask`       | `0x7F5F1671` | permissions |
| 67 | `GetCutCopyFlags`     | `0x7F5F16F2` | clipboard |
| 68 | `HrCanSourceJunctions`| `0x7F5F17A6` | junction policy |
| 72 | `HrGetPMte`           | `0x7F5F1593` | builds/returns `CBbsTreeEdit` (§module write) |
| 82 | `NewObject`           | `0x7F5F1623` | Compose / new folder → `AddNode` |
| 85 | `GetCParentsTotal`    | `0x7F5F16B5` | tree topology |
| 86 | `GetCChildrenTotal`   | `0x7F5F16C4` | tree topology |

`CBbsNavTreeNode_GetThreadParent` (`0x7F5F1C3E`, an internal helper) reads `_P`
(`0x03` DWORD), splices it into a copy of the node's mnid and calls `HrGetPMtn`
to materialize the parent message — the explicit RE: thread linkage.

## 5. Properties dialog

`CBbs_FillPropertiesDialogPage` (`0x7F5F385E`) populates the BBS folder/message
property page: item 0x66 ← `e` (name), item 0x68 ← `MnidToSz(mnid)`, item 0x6A ←
`_D` (date), item 0x70 ← `_t` (attachment count). Reads `_I` (2-byte flags): bit `0x8000` →
checkbox 0x6E; bit `0x4000` → checkbox 0x72 + label string `0x190F`/`0x1910`.
When pricing is supported it reads `z` (DWORD price) and `FFormatPrice`s it into
a currency combo (items 0x73/0x75/0x77/0x79).

## 6. Column descriptor (RCDATA 6011)

`CBbsNavTreeNode_GetDetailsStruct` (`0x7F5F14A3`): if a real/localized node
exists, delegate to its slot 28; else `RgmdsFromRcdata(g_BbsHInstance, 0x177B,
&count)` → cache in `g_BbsCachedColumns`. RCDATA 6011 (rva `0x2D558`, 28 B) =
4 columns: `(6530,e,220)` Subject, `(6531,_a,120)` Author, `(6532,p,80)` Size,
`(6533,_D,118)` Date.

## 7. Window-placement persistence (registry)

`HKCU\SOFTWARE\Microsoft\MOS\BBS Viewer`, four 24-byte values `{MSN,Net}
{Comp,Read} Wnd`. `CBbs_LoadWindowPlacement` (`0x7F600DB2`, `RegQueryValueExA`),
`CBbs_SaveWindowPlacement` (`0x7F600EC5`, `RegCreateKeyExA`+`RegSetValueExA`).
The `MSN` vs `Net` prefix comes from `CBbs_FIsMsnBbs` (`0x7F600D21`):
`(FUN_7F6017B3(obj+0x88) & 7) == 0`. **No message read-state in the registry** —
unread tracking is server-side (a node flag bit).

## 8. View window + body (`CBbsViewWnd`)

`CBbsNavTreeNode_GetViewWndObject` (slot 36, `0x7F5F1307`) allocs 104 B
(`0x68`), runs `CBbsViewWnd_Construct` (`0x7F5F1F8B`), `CMosViewWnd::HrInit`s it,
QueryInterfaces out. Registered as window class **`BBSMsgWndClass`**. The
message **body** is a **RichEdit** control — `riched32.dll` is `LoadLibrary`d in
`FUN_7F5F9406` at init. The list-view columns are §6; the threaded view nests
replies via tree structure (recursive `GetChildren`).

The body arrives on the message-content channel (class `0x0B`, IID `00028B2F`)
as an RFC-1036 news article. `FUN_7F5FB056` spawns the fetch thread
`LAB_7F5FB0D3` → `FUN_7F5FB15F`, which drains a `0x86` dynamic reply through the
MPCCL iterator, splits it at the first blank line, hands the headers to
`FUN_7F5FB4A9` (header → MAPI tag table at `0x7F610A50`) and the rest to an
in-memory IStream. `FUN_7F5FC56F` then reads `X-MOS-Format` (`0x6801001E`) back
and streams the body into the RichEdit via EM_STREAMIN as `TEXT`, `RTF` or
`RTFCOMP`. `TEXT` draws in the control's default Courier New, so the body font
in `reference/screenshots/bbs.png` means the real bodies were RTF. Full shape in
`docs/bbs-service-contract.md` §Message-content channel.

## 9. Write / posting pipeline

`CBbsNavTreeNode_HrGetPMte` (slot 72, `0x7F5F1593`) lazily builds a 72-byte
(`0x48`) `CBbsTreeEdit` (`CMosTreeEdit` subclass), `CMosTreeEdit::CMosTreeEdit(
this, node, mnid, &g_BbsEcig, NULL)`, installs `vtbl_CBbsTreeEdit` (`0x7F60E9E8`),
caches at node+0xBC.

`vtbl_CBbsTreeEdit` = 29-slot `CMosTreeEdit` base (`MOSSHELL` `0x7F40C888`) with
**4 overrides** + secondary interface vtables (property-dispatch / dataset
source, mostly local):

| Slot | Method | BBSNAV fn |
|---:|---|---|
| 5  | `GetPropertyDispatch` | `0x7F5F1D08` |
| 9  | `FormatSizeString`    | `0x7F5F1E4F` |
| 12 | `NewObject`           | `0x7F5F1D17` |
| 13 | `FillSPForNewNode`    | `0x7F5F1DCF` |

`CBbsTreeEdit_NewObject` (`0x7F5F1D17`): get `CTreeEditClient` (edit vtbl+0xC),
`FillSPForNewNode` (seeds `e` = `LoadString(0x1901)` default name, type 0x0A),
then `CTreeEditClient::AddNode` (sel 2) → new mnid; `EnumMosWindows(RefreshEmw)`.
Edits go through `SetProperties` (sel 4); reply linkage through `LinkNode`
(sel 5). All ride the **ticket** obtained via `GetTicket` (sel 12). Full TREEEDCL
selector table in `docs/bbs-service-contract.md` §Write selectors.

## 10. MSN BBS vs Internet Newsgroups + MAPI gateway

One binary, two app ids. `CBbs_FIsMsnBbs` (`0x7F600D21`) branches MSN vs Net for
the registry prefix and command gating ("…not available in Internet
Newsgroups." / "…available only in Internet Newsgroups."; `Newsgroups: ` header
at `0x7F610CD8`).

`CBbs_MapiForwardOrReply` (`0x7F6044CB`) = Forward/Reply-by-email:
`LoadLibrary("MAPI32.DLL")` + `MAPILogon`/`MAPISendMail`/`MAPILogoff` (dynamic).
`mode==0` → subject "FW: %s"; `mode==1` → "RE: %s" + recipient from dlg 0x3E9;
body from the RichEdit (dlg 0x3ED). `MOSABP32.DLL` (MSN MAPI address-book
provider) participates via the MAPI subsystem, not loaded by BBSNAV directly.
Gateway callee protocol deferred (out of binary set).

## 11. Node-shape contract on the wire

See `docs/bbs-service-contract.md` §Property tags. Summary: per-node SVCPROP
record with MOSSHELL base tags + 8 BBS extras `{_a,_D,_P,_f,_t,p,_F,_I}`;
columns `e/_a/p/_D`; threading via tree + `_P`; `_t` attachment count; flags
`_F`/`_I`; price `z`; attachment download count `_r`; icon `h` synthesised
client-side.

## 12. Known gaps / follow-ups

- `_f` is advertised but no read site is known.
- Attachments: the object and FTM paths are traced (MOSAF.DLL, CLSID
  `{00028B50-…}`, mnid `message id + k`; see `docs/bbs-service-contract.md`
  §Attachments). The attachment node's `_r` is the download count MOSAF shows
  in Properties. `X-MOS-Attach` (`0x68020002`) is parsed and enabled, but the
  attachment count the message Properties page shows comes from the objects
  found in the body.
- TREEEDCL selector 9 unused by the client.
- Secondary `CBbsTreeEdit` interface vtables (after the first 29-slot table at
  `0x7F60E9E8`) are mostly local but not individually annotated (property
  dispatch / dataset source for `GetDataSets`).
- Internal `MnidToSz`/mnid layout: BBS mnid copied as 6 dwords (24 B) in
  `GetThreadParent`; the full mnid sub-field carrying `_P` not byte-mapped.

## 13. Ghidra annotations shipped

Session `4041a548ca854bd19596d689d4fc5d66` (`/BBSNAV.NAV`). Functions renamed:
`BBSNAV_DllMainLogic`, `CBbsNavTreeNode_Construct`, all 25 `CBbsNavTreeNode_*`
overrides, `CBbsNavTreeNode_GetThreadParent`, `CBbsViewWnd_Construct`,
`CBbsTreeEdit_NewObject`, `CBbsTreeEdit_FillSPForNewNode`,
`CBbs_FillPropertiesDialogPage`, `CBbs_LoadWindowPlacement`,
`CBbs_SaveWindowPlacement`, `CBbs_FIsMsnBbs`, `CBbs_MapiForwardOrReply`. Labels:
`vtbl_CBbsNavTreeNode`, `vtbl_CBbsTreeEdit`, `g_BbsNtniGroup`, `g_BbsEcig`,
`g_BbsRefreshCS`, `g_BbsHInstance`, `g_BbsAccelerators`, `g_BbsLiveInstanceCount`,
`g_BbsExtraPropTags`, `g_BbsCachedColumns`. Plate comments on `GETPMTN`,
`DISCONNECT`, `BBSNAV_DllMainLogic`, the node ctor, the vtable, and
`CBbs_MapiForwardOrReply`. TREEEDCL `CTreeEditClient` `Private*` selectors
documented (session `3befd2b30ccd4ceb9b033ac5a9c8e6b7`).
