# DSNAV.NAV

Reverse-engineering notes for `binaries/DSNAV.NAV`, the `App #1
Directory_Service` navigator plug-in — the NAV that materializes the
server's DIRSRV tree into shell-visible `CMosTreeNode` instances.

Sources: static binary (`wrestool`, `objdump`) plus live decompilation against
the MSN95 Ghidra project (session `d2c93d059e7c4b70945d11c35eb4de65`). All
addresses in this document are at DSNAV's link-time image base
`0x7F580000`. Companion to:

- `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` — MOSSHELL/TREENVCL/SVCPROP side of
  the wire pipeline.
- `docs/TREENVCL.md` — the RPC client library DSNAV opens (via
  `InitializeNtnigr("DIRSRV", …)`) and drives through MOSSHELL imports.
- `docs/GUIDENAV.md` — structural template for this writeup.

## 1. Identity

- PE DLL, 31 KiB total, link-time 1995-04, image base `0x7F580000`.
- Version resource (wrestool type=16 name=1): `FileDescription =
  "Microsoft Network Directory Service Navigator"`, `InternalName = DSNAV`,
  `OriginalFilename = DSNAV.NAV`, `FileVersion = 1.60.0`.
- Registered as `App #1 Directory_Service` in `HKLM\Software\Microsoft\MOS\
  Applications\App #1` with `Filename = dsnav.nav`. The `Node Editor App #`
  for DSNAV is `App #18 DSED` → `dsned.ned` (the authoring-side plug-in DSNAV
  calls into via `MCM!FGetNedForApp`).
- 23 exports (four subclass surfaces):

  | Surface | Export(s) | Role |
  |---|---|---|
  | Plug-in entry | `GETPMTN @ 0x7F581F1F`, `DISCONNECT @ 0x7F581F5B`, `entry @ 0x7F5830FE` | shell-facing contract + DllMain |
  | `CDIBWindow` subclass | copy-ctor `0x7F581192`, `FStretchBanner 0x7F58105C`, scalar/vector dtors, vtable `??_7CDIBWindow@@6B@ = 0x7F58600C` | banner flag carrier |
  | `CMosXWindow` subclass | copy-ctor `0x7F5810F1`, `GetWindow 0x7F581054`, `PvParam 0x7F581058`, dtors, vtable `??_7CMosXWindow@@6B@ = 0x7F586008` | frame-window wrapper |
  | `CMosXWndClass` subclass | `SzClassName 0x7F581051`, dtors | raw char-array holding RegisterClassA name |
  | `CMosXAllocator` operator=/dtors | (4 exports) | per-module allocator helper |

- Imports prove the pipeline:
  - `MOSSHELL.DLL` — full `CMosTreeNode` vtable thunks (ord 0x30–0x7f, 0x91–0x94),
    the base-class WndProcs `CDIBWindow::MessageHandler` / `CMosXWindow::MessageHandler`,
    NtniGroup lifecycle (`InitializeNtnigr`, `CleanupNtnigr`, `HrDisconnectNtnigr`),
    shell-global state (`g_caid`, `g_rgaidNodes`, `FEnsureRgaidNodes`, `g_mxa`),
    shell-wide refresh (`EnumMosWindows`, `RefreshEmw`), the column-descriptor
    loader `RgmdsFromRcdata`, error dispatch `ReportMosXErr`, and the tree-node
    ctor `CMosTreeNode::CMosTreeNode(_MosNodeId*, _NtniGroup*)`.
  - `SVCPROP.DLL` — `CServiceProperties` ctor/dtor/`FInit`/`FGet`. The DIRSRV
    per-child property reader.
  - `MCM.DLL` — `HRMOSExtract` (plug-in path lookup), `FGetNedForApp`
    (app-id → NED DLL ordinal). Used by the plug-in registry (below).
  - `MOSCUDLL.DLL` — `FMergeMenus`, `HMenuSubFromId` (context-menu build).
  - `USER32.DLL` — `LoadMenuA`, `InsertMenuA`, `DeleteMenu`, `CreateMenu`,
    `GetSubMenu`, `DestroyMenu`, `GetMenuItemCount`, `GetMenuItemID`.
- `.rsrc` (2 KiB) resources confirmed via `wrestool -l`:

  | Type | Id | Size | Role |
  |---|---:|---:|---|
  | MENU | 128 (`0x80`) | 172 B | Main context menu (slot 56 gatekeeper). |
  | MENU | 129 (`0x81`) | 48 B | "Tail" submenu merged by slot 57 (flag 0). |
  | MENU | 130 (`0x82`) | 94 B | "Secondary" submenu merged by slot 57 (flag 0/2 for container/leaf). |
  | MENU | 131 (`0x83`) | 32 B | "Base" submenu merged by slot 57 (flag 0/4 for container/leaf). |
  | RCDATA | 129 (`0x81`) | 27 B | Column descriptor (4 columns; see §10). |
  | STRING | 9 | 124 B | Column-header string IDs 140–143; UI labels "&Print"/"&Quick View". |
  | VERSION | 1 | 828 B | Version resource above. |

## 2. How the shell reaches it

MOSSHELL's `HrGetPMtn(_MosNodeId*, IMosTreeNode**, int)` is the canonical
entry to the tree. When the mnid's `app_id` matches `APP_DIRECTORY_SERVICE`
(1), MOSSHELL `LoadLibrary`s `dsnav.nav`, resolves `GETPMTN`, and calls it.

Root discovery comes from the server: the initial DIRSRV `GetProperties`
response contains the tree root's mnid, and any subsequent DIRSRV node's
wire `'a'` (mnid) + `'c' = 1` drives the shell back into `dsnav.nav`'s
`GETPMTN`.

Unlike GUIDENAV (which is reached through client-local HOMEBASE JUMPs and
the local MFP store), **DSNAV is reached through live wire traffic**: every
browse into a DIRSRV container is a roundtrip.

## 3. Plug-in contract

### 3.1 `GETPMTN(_MosNodeId* mnid, IMosTreeNode** out) -> HRESULT`

Decomp at `0x7F581F1F`. Single-branch — unlike GUIDENAV there is no
root-vs-child split. Every DSNAV mnid produces a 240-byte
`CDsNavTreeNode`:

1. `FUN_7f582ec9(0xF0)` — malloc 240 bytes.
2. `CDsNavTreeNode_Construct(node, mnid)` at `0x7F581365`:
   - `CMosTreeNode::CMosTreeNode(node, mnid, &g_DsNavNtniGroup)` — base ctor.
     The `_NtniGroup*` argument (`g_DsNavNtniGroup`, a .bss block at
     `0x7F585020`) is what binds this node to the shared DIRSRV service
     channel opened in `DSNAV_Init`.
   - Overwrite the vtable pointer with `&vtbl_CDsNavTreeNode` (at
     `0x7F586020`). The CMosTreeNode base ctor only installs slots IT uses;
     DSNAV's 8 overrides (slots 9, 28, 56, 57, 71, 72, 81, 82 — see §4)
     take effect here.
   - Zero `node+0xBC` — the cached inner-node slot used by slot 72
     (`EnsureInner`) to lazily delegate to the per-app plug-in node (§6).
   - Bump `g_DsNavLiveInstanceCount` (diagnostic refcount at `0x7F587004`).
3. `node->vtbl[1](node)` — AddRef before returning `*out`.
4. On OOM, return `E_OUTOFMEMORY` (`0x8007000E`).

### 3.2 `DISCONNECT() -> HRESULT`

Decomp at `0x7F581F5B`. **Active teardown** — unlike GUIDENAV's no-op:

1. `HrDisconnectNtnigr(&g_DsNavNtniGroup)` — close the DIRSRV service
   channel.
2. Walk the global plug-in registry (`g_DsNavPluginRegistry` at `0x7F5851B4`,
   guarded by `g_DsNavPluginRegistryCS` at `0x7F5851B8`). For every NED/NAV
   DLL DSNAV loaded lazily through `DSNAV_LoadAppPluginNode` (§6):
   `GetProcAddress(hmod, "DISCONNECT")`, call it, then `FreeLibrary(hmod)`.
   DSNAV owns the lifetime of every NED it pulled in.
3. Destroy the registry's two critical sections, free its storage, null
   `g_DsNavPluginRegistry`.
4. Return 0.

### 3.3 `entry(hinst, reason, reserved) -> BOOL` — DllMain

Decomp at `0x7F5830FE`. Standard MS VC CRT stub; the DSNAV-specific work
lives in `DSNAV_DllMainLogic` (`0x7F582154`):

- `DLL_PROCESS_ATTACH` → `DSNAV_Init()` (see §5.1) + stash `hinst` in
  `g_DsNavHInstance` (`0x7F587000`).
- `DLL_PROCESS_DETACH` → null `g_DsNavHInstance` + `DSNAV_Cleanup()`.

## 4. Vtable layout (`vtbl_CDsNavTreeNode`)

89 slots at `0x7F586020`, inheriting from `MOSSHELL!CMosTreeNode`. Every
slot DSNAV does NOT override is a 6-byte `jmp [iat]` thunk into
`MOSSHELL.DLL`. Slot numbering verified against MOSSHELL imports: slot 0
= `QueryInterface` (ord `0x7e`), slot 42 = `GetCChildren` (ord `0x56`).

The 8 DSNAV-local overrides:

| Slot | Offset | Function | Purpose |
|---:|---:|---|---|
| 9 | `+0x44` | `0x7F581393` — 5-byte stub (`xor eax, eax; ret 4`) | S_OK no-op — swallows a 1-arg inheritance-only method. |
| 28 | `+0x90` | `CDsNavTreeNode::GetDetailsStruct` @ `0x7F581621` | Return column descriptors (RCDATA 0x81). |
| 56 | `+0x100` | `CDsNavTreeNode::Override_Slot56` @ `0x7F581398` | Menu gatekeeper — reads `'b'` (browse-flags), loads MENU 0x80, scans for item 0x3002. |
| 57 | `+0x104` | `CDsNavTreeNode::Override_Slot57_ContextMenu` @ `0x7F58143A` | Context-menu builder — `FMergeMenus` of MENUs 0x81/0x82/0x83. |
| 71 | `+0x13C` | `CDsNavTreeNode::Override_Slot71_DelegateExec` @ `0x7F581E8C` | Verb dispatcher — forward to inner plug-in node's slot 12, then `EnumMosWindows(RefreshEmw)`. |
| 72 | `+0x140` | `CDsNavTreeNode::Override_Slot72_EnsureInner` @ `0x7F58185D` | Lazy-load the inner plug-in node for this DSNAV node's `'c'` app_id. |
| 81 | `+0x164` | `CDsNavTreeNode::Override_Slot81_BuildServicesMenu` @ `0x7F5819D7` | Build the "Services" top-level menu listing every registered MOS app + its activation keys. |
| 82 | `+0x168` | `CDsNavTreeNode::Override_Slot82_InvokeServicesMenuItem` @ `0x7F581DD0` | Handle menu selection from slot 81's output. |

Importantly: **`GetCChildren` / `GetNthChild` / `OkToGetChildren`
are INHERITED**, not overridden. DSNAV does not customize child
enumeration — it leans on MOSSHELL's default that routes through
`CTreeNavClient::GetChildren` via the `g_DsNavNtniGroup`. DSNAV's
contribution to the GetChildren request is the 7-tag extension set at
init time (§5.2).

## 5. DSNAV process-wide state

### 5.1 `DSNAV_Init()` @ `0x7F58205F`

Runs once on `DLL_PROCESS_ATTACH`:

1. Allocate 84 bytes; `CDsNavPluginRegistry_Construct` (`0x7F5821A4`) stamps
   the plug-in registry: vtable `vtbl_CDsNavPluginRegistry`
   (`0x7F586188`), two critical sections (offsets `+4` and `+0x1C`),
   hash-table head at `+0x4C`, load count at `+0x50`. Stored as
   `g_DsNavPluginRegistry` (`.bss` `0x7F5851B4`).
2. `InitializeCriticalSection(&g_DsNavPluginRegistryCS)` — the outer
   registry lock.
3. **`InitializeNtnigr(&g_DsNavNtniGroup, "DIRSRV", 7, 7,
   &g_DsNavExtraPropTags)`** — this is the pivotal call. It hands MOSSHELL
   the NtniGroup that:
   - Names the wire service (`"DIRSRV"` — matches the server's service
     table key).
   - Declares 7 **extra** per-child property tags DSNAV wants the server
     to emit beyond MOSSHELL's default 7. The `&g_DsNavExtraPropTags`
     argument is a 7-pointer array (`0x7F587010..0x7F58702C`) of tag-name
     asciiz strings, populated statically at link time.

After this returns, DSNAV is ready: the shared NtniGroup can route
`GetChildren` / `GetShabby` / `GetProperties` through the DIRSRV channel,
and the registry can demand-load NED/NAV plug-ins for any `'c'` app-id it
later encounters in wire data.

### 5.2 Extra per-child property tags (`g_DsNavExtraPropTags`)

The 7-pointer array at `0x7F587010` feeds the plug-in-extended tag path
described in `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md § Property tag request
lists`: MOSSHELL merges DSNAV's extras on top of the default set
`{'a','c','b','e','g','h','x'}`.

| Index | Ptr | Tag | Meaning in DSNAV |
|---:|---|---|---|
| 0 | `0x7F587058` | `mf` | primary icon (DWORD shabby_id). |
| 1 | `0x7F587054` | `wv` | secondary icon variant (DWORD shabby_id). |
| 2 | `0x7F587050` | `tp` | localized type label (ASCII string). |
| 3 | `0x7F58704C` | `p`  | size, DWORD (MOSSHELL `FormatSizeString`). |
| 4 | `0x7F587048` | `w`  | last-changed timestamp, **FILETIME (type 0x0C, 8 bytes)** — see §14.2 for the MOSSHELL column-format trace. |
| 5 | `0x7F587044` | `l`  | unresolved; reserved column. |
| 6 | `0x7F587040` | `i`  | unresolved; reserved column. |

So every DIRSRV `GetChildren` reply — for a DSNAV folder with no local
overrides — is asked to carry **14 tags**:
`{a, c, b, e, g, h, x, mf, wv, tp, p, w, l, i}`.

### 5.3 `DSNAV_Cleanup()` @ `0x7F5820B3`

Mirrors `DSNAV_Init`:

1. Delete `g_DsNavPluginRegistryCS`.
2. `CleanupNtnigr(&g_DsNavNtniGroup)`.
3. Walk `g_DsNavAppMenuTable` (see §8), free each row's malloc'd label,
   free the table itself, zero the count.
4. If `g_DsNavCachedColumns` holds a decoded `MDS[]` array (from the
   RCDATA 0x81 load), release it back to `MOSSHELL!g_mxa` via
   `CMosXAllocator::Free`.

## 6. Delegation to per-app NED plug-ins

DSNAV is a **multiplexer**: once the shell asks it for anything other than
"enumerate children of this folder", DSNAV's first move is to resolve the
node's `'c'` (app_id) and hand the verb off to the NED/NAV plug-in
responsible for that app.

### 6.1 `DSNAV_LoadAppPluginNode` @ `0x7F5816B6`

Given `app_id`, return an `IMosTreeNode*` that represents the node as
the responsible plug-in sees it:

1. Recursive bootstrap: the function first calls itself with `app_id=0` to
   obtain a "blank" parent node local_c (used so plug-ins can re-use a
   parent node handle).
2. `MCM!FGetNedForApp(app_id or 1, &ord)` — registry lookup under
   `HKLM\Software\Microsoft\MOS\Applications\App #<id>\"Node Editor App #"`.
   Returns the ordinal for the NED (e.g. app 1 → App #18 DSED → `dsned.ned`).
3. Under `g_DsNavPluginRegistry`'s sub-CS, hash-lookup the registry
   (`FUN_7f582a40`). On hit, reuse the cached `hmod`. On miss:
   `HRMOSExtract(ord, path, MAX_PATH)` resolves the full NED filename,
   `LoadLibraryA(path)` pulls it in, `CDsNavPluginRegistry_Insert`
   (`0x7F5821D5`) stashes the `hmod` keyed by `ord`.
4. `GetProcAddress(hmod, "GETPMTE")` — note: the node-editor's
   **`GETPMTE`** extract entry, not GETPMTN. Call it with
   `(app_id, mnid_hi, this, arg3, blank_parent, out)`. The plug-in
   returns the IMosTreeNode for that (app_id, mnid) pair.
5. On success, AddRef `this` (the originating DSNAV node).

Errors:

- `0x8007000E` — registry insert OOM.
- `0x8B0B0003` — MCM lookup, LoadLibraryA, or GetProcAddress failed.
- `0x80004001` (E_NOTIMPL) — plug-in returned "not implemented".

`ReportMosXErr` on all paths so the shell surfaces the failure as a
dialog box instead of a silent hang.

### 6.2 Slot 72 — `EnsureInner`

When the shell calls slot 72 on a DSNAV node, DSNAV caches the inner
plug-in node at `this+0xBC` (DWORD offset `0x2F`) so subsequent operations
don't re-load the DLL:

1. If `this+0xBC` is already populated, reuse.
2. `GetProperty("c", &app_id, 4, 1)` via vtable slot 16 — read wire `'c'`.
3. `DSNAV_LoadAppPluginNode(&this->inner, this, this+0x10, app_id,
   (short)this[8])`. The mnid passed through is the 8-byte field at
   `this+0x10` (CMosTreeNode's wire mnid slot). `(short)this[8]` is a
   locale/flags field inherited from the base class.
4. Return the cached pointer, AddRef'd.

### 6.3 Slots 71 / 82 — verb dispatchers

Both slots dispatch to the inner plug-in's vtable slot 12 (+0x30), after
`LockRefresh` (slot 73 `+0x124`) and followed by `EnumMosWindows(RefreshEmw,
0)` + `UnlockRefresh`. Difference:

- **Slot 71** uses the cached `this+0xBC` node directly (with a defensive
  re-load via `DSNAV_LoadAppPluginNode`). Most likely `Delete` / `Exec`:
  runs the verb on the already-chosen node and refreshes all MSN shell
  windows.
- **Slot 82** takes an index into `g_DsNavAppMenuTable`, reads the stored
  app_id, re-resolves the plug-in node for THAT app, and runs slot 12.
  This is the dispatcher for "Services" menu clicks (§8).

## 7. GetChildren pipeline (DSNAV side)

DSNAV does not override `GetCChildren`/`GetNthChild`/`OkToGetChildren`, so
the MOSSHELL base-class logic from
`docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` runs verbatim. DSNAV's only
influence is the advertised tag set:

- When `CMosTreeNode::OkToGetChildren` builds the request-tag list, it reads
  `this->field_2E + 0x18C` (the extra-count = 7) and `this->field_2E +
  0x400` (the extra-array = `&g_DsNavExtraPropTags`) from the NtniGroup
  installed in §5.1, and merges them into the default 7-tag list via
  `FUN_7F40305B` in MOSSHELL.
- The merged 14-tag list `{a, c, b, e, g, h, x, mf, wv, tp, p, w, l, i}`
  is serialized by `TREENVCL!PackPropNames` and sent to the DIRSRV server.
- Per-child record decoding runs in `SVCPROP!FDecompressPropClnt`. Once
  the properties land on the new child, they are projected onto the
  child's cache via `MOSSHELL!CMosTreeNode::SetPropertyGroupFromPsp`
  (ord 0x75).

## 8. "Services" top-level menu

### 8.1 Build — slot 81 `BuildServicesMenu` @ `0x7F5819D7`

First call (when `g_DsNavAppMenuBuilt == 0`):

1. `FEnsureRgaidNodes()` populates `MOSSHELL!g_caid` (count) and
   `g_rgaidNodes` (array of DWORD app_ids the shell knows about).
2. For each `app_id` in `g_rgaidNodes[0..g_caid-1]`:
   - `DSNAV_LoadAppPluginNode(&node, ...)` to obtain that app's node.
   - Read canonical command text via `node->vtbl[11]` (`+0x2C`) into a
     260-byte buffer — this is the menu-item label.
   - Check exec-capability flag via `node->vtbl[20]` (`+0x50`).
   - Read the activation-key property set via
     `node->vtbl[27]` (`+0x6C`) into a second buffer and
     `node->vtbl[28]` (`+0x70`) into a `CServiceProperties` bag.
   - For each property in the bag (treated as an activation-key list):
     - `SzToUnsLong(prop_value)` → command word.
     - `DSNAV_AppMenuTable_Append` caches the row in
       `g_DsNavAppMenuTable`.
     - `InsertMenuA(param_2, -1, 0x400, 0x2100+slot, label)`.
3. `g_DsNavAppMenuBuilt = 1` (cached).

Subsequent calls iterate the cached table; rows whose `verb_word == 0xFFFF`
are submenu headers (`CreateMenu` + child `InsertMenuA` loop with
flag `0x410`).

### 8.2 Invoke — slot 82 `InvokeServicesMenuItem` @ `0x7F581DD0`

Pair: the shell passes `menu_idx` when the user picks an item. DSNAV reads
`g_DsNavAppMenuTable[menu_idx]` to recover the `app_id` + verb word, then
runs the verb on the plug-in node for that app (§6.3).

### 8.3 Layout of `g_DsNavAppMenuTable`

Each row is 12 bytes:

| Offset | Size | Field |
|---:|---:|---|
| `0x00` | `u32` | `app_id` (the MOS Applications table entry the plug-in registers against; see `docs/BINARIES.md` §3 for the catalogue). |
| `0x04` | `u16` | verb word (`SzToUnsLong(prop_value)`, or `0xFFFF` sentinel for submenu headers). |
| `0x06` | `u16` | pad. |
| `0x08` | `LPSTR` | malloc'd ASCII label (freed in `DSNAV_Cleanup`). |

Companion globals (`.data`):

- `g_DsNavAppMenuCount`    (`0x7F587034`) — rows populated.
- `g_DsNavAppMenuCapacity` (`0x7F587038`) — allocated row count (grows by 3).
- `g_DsNavAppMenuBuilt`    (`0x7F58703C`) — 0 = not yet built, 1 = cached.

## 9. Context menu (per-node)

### 9.1 Build — slot 57 @ `0x7F58143A`

1. First call `this->vtbl[1]` (`GetLocalizedNode` / `GetRealNode`). If it
   returns a different node (the inner plug-in node), delegate the whole
   menu build to **that** node's slot 57 (`+0xE4`) — DSNAV lets the plug-in
   own its own context menu.
2. Else, check `this->vtbl[64]` (`+0x100`) for a "container vs leaf" flag
   from property `0x70` (a CMosTreeNode cache bit set from wire `'b'`).
   Bit picked determines the merge flags.
3. Obtain the target submenu via `HMenuSubFromId(shell_menu, 0x8000)`.
4. `LoadMenuA(g_DsNavHInstance, 0x83)` → `FMergeMenus` (flag = 4 if
   container else 0) → `DestroyMenu`.
5. Repeat with MENU 0x82 (flag 0 or 2) and MENU 0x81 (flag 0).

Resources:

- **MENU 131 (`0x83`)**: "base" set — `&Open` / `&Explore`. Container
  branch adds an `&Explore` entry; leaf branch just has `&Open`.
- **MENU 130 (`0x82`)**: "secondary" set — `Create &Shortcut`, `Add to
  Favorite P&laces`.
- **MENU 129 (`0x81`)**: "tail" set — `P&roperties`.

Compared to GUIDENAV (whose verb set is {`&Open`, `&Explore`, `&Delete`,
`P&roperties`} from a single MENU 128), DSNAV's merged menu is
{`&Open`, `&Explore`, `Create &Shortcut`, `Add to Favorite P&laces`,
`P&roperties`}. `&Delete` is not in the DSNAV resources — deletion of
server-owned nodes routes through the editor plug-in (DSED, via slot 71's
forward-to-inner path).

### 9.2 Gatekeeper — slot 56 @ `0x7F581398`

Small query override: reads `'b'` (browse-flags byte) via vtable slot 16,
then `LoadMenuA(hInst, 0x80)` and walks items looking for command id
`0x3002`. The command id is stashed if found. Likely a "which MENU entry
should host the default verb for container/leaf" lookup — less clear than
slot 57.

## 10. Column descriptor (RCDATA 0x81)

Loaded by slot 28 `CDsNavTreeNode::GetDetailsStruct` via
`RgmdsFromRcdata(g_DsNavHInstance, 0x81, &g_DsNavCachedColumnCount)`.
Result is cached in `g_DsNavCachedColumns` until `DSNAV_Cleanup`.

Raw bytes at `.rsrc` offset `0x7F58C31C` (27 bytes):

```
04 00                                 ; count = 4 columns
8c 00 65 00         c8 00             ; col 0: sid 140 "&Name",          tag "e",  width 200
8d 00 74 70 00      78 00             ; col 1: sid 141 "&Type",          tag "tp", width 120
8e 00 70 00         64 00             ; col 2: sid 142 "Si&ze",          tag "p",  width 100
8f 00 77 00         64 00             ; col 3: sid 143 "&Date Modified", tag "w",  width 100
```

String IDs 140–143 live in STRING table 9 (`.rsrc` offset `0x7F58C6D0+`).

Format matches GUIDENAV's RCDATA 1000 but with a different resource ID and
a different fourth column (GUIDENAV also shows Name/Type/Size/Date).

## 11. Folder-view rendering (banner + WndProc)

DSNAV's window subclasses are **thin wrappers** around MOSSHELL base
classes; DSNAV ships no own WndProc.

### 11.1 `CDIBWindow` — banner strip

- Vtable `vtbl_CDsNav_CDIBWindow` @ `0x7F58600C`, **1 slot**: thunk →
  `MOSSHELL!CDIBWindow::MessageHandler` (ord `0x8D`).
- Only custom method: `FStretchBanner` — a 2-instruction accessor
  returning `(this[0x14] & 1)`. MOSSHELL's base CDIBWindow paint pipeline
  calls it to choose `StretchBlt` vs `BitBlt` on the cached banner HBITMAP.
- The `'mf'` wire property (advertised in §5.2) supplies the banner
  shabby_id. MOSSHELL's `FUN_7F405018`-style path in
  `project_mosshell_shabby_call_path` resolves that into the HBITMAP.
- No DSNAV code reads WM_PAINT / WM_SIZE / WM_LBUTTONDOWN itself.

### 11.2 `CMosXWindow` — frame wrapper

- Vtable `vtbl_CDsNav_CMosXWindow` @ `0x7F586008`, **1 slot**: thunk →
  `MOSSHELL!CMosXWindow::MessageHandler` (ord `0x8F`).
- Accessors: `GetWindow` → `*(this+4)` (HWND), `PvParam` → `*(this+8)`
  (back-pointer to the owning `CMosTreeNode`, which MOSSHELL's
  WM_COMMAND handler uses to route verbs).

### 11.3 `CMosXWndClass` — class-name carrier

- `SzClassName` is a 2-instruction identity (`mov eax, ecx; ret`).
  The `CMosXWndClass` instance IS the zero-terminated class-name buffer;
  DSNAV exports the symbol so MOSSHELL can register its `WNDCLASS` using
  whatever name string the shell stamps into the instance.
- No DSNAV vtable is shipped for this class.

## 12. Node-shape contract DSNAV expects on the wire

Combined list = default 7 + DSNAV's 7 extras = 14 tags every DIRSRV
`GetChildren` reply must carry (or explicitly decide to skip) for the
DSNAV read path to populate its view. The "Purpose in DSNAV" column
reflects the READ path after `CServiceProperties::FInit` has parsed the
per-child record; unless a tag is flagged **Required**, wrong-type data
generally produces blank columns rather than a broken listview.

| Tag | Set | Wire type | Required? | Purpose in DSNAV | Failure mode when missing | Failure mode when wrong-type |
|---|---|---|---|---|---|---|
| `a`  | default | `0x0E` blob (8 B) | **Yes** | 8-byte mnid; drives `HrGetPMtn` when shell materializes the child. | Child isn't constructable; tree stops here. | 8-byte slot re-interpreted → wrong node id, lookup miss. |
| `c`  | default | `0x03` DWORD | **Yes** | app_id; slot 72 reads it via GetProperty("c",4) to pick the NED DLL. | Slot 72 fails → slots 71/82 return `E_UNEXPECTED`. | Cache slot holds 4 wrong bytes → wrong NED loaded. |
| `b`  | default | `0x01` byte | **Yes** | browse-flags; bit 0 clear = container (Browse), set = leaf (Exec). Read by MOSSHELL's `ExecuteCommand` and by DSNAV slot 56. | `ExecuteCommand` falls back to base → Browse/Exec choice becomes wrong. | As missing. |
| `e`  | default | `0x0A` ASCIIZ | **Yes** | display name; icon label AND explorer titlebar both consume ANSI cache. | Blank title/label. | `0x0B` truncates to "M" (see `project_dirsrv_nav_e_encoding`). |
| `g`  | default | `0x03` DWORD | No | unresolved ("unknown g" — sentinel sweeps ruled out icon slot). Safe wire value is 0. | No observable effect. | — |
| `h`  | default | `0x03` DWORD | *Conditional* | secondary icon shabby_id; if present, `FUN_7F404786` kicks off the per-item ICO `ExtractIconEx` path (see `project_dirsrv_h_property_icon_path`). | `iImage=0` → forbidden-glyph default icon. | Non-DWORD breaks the shabby-id readback. |
| `x`  | default | `0x0E` blob | No | exec-args; consumed only by launcher paths, not the listview. | — | — |
| `mf` | DSNAV | `0x03` DWORD | *Conditional* | primary icon (banner); MOSSHELL `FUN_7F405018` reads as DWORD and feeds `GetShabbyToFile`. **Must be inline 0x03** — 0x0E blob stores a pointer and the low-4 become garbage. | Blank banner. | Wrong bytes → wrong shabby, banner loads fail. |
| `wv` | DSNAV | `0x03` DWORD | No | secondary icon variant shabby_id. Same encoding rule as `mf`. | Fallback to base icon. | As `mf`. |
| `tp` | DSNAV | `0x0A` ASCIIZ | No | "Type" column text (column 1 in RCDATA 0x81). | Blank "Type" cell. | Wrong type → truncation or cache miss. |
| `p`  | DSNAV | `0x03` DWORD | No | size in bytes; FormatSizeString in the "Size" column. | Blank "Size" cell. | Wrong size display. |
| `w`  | DSNAV | `0x0C` FILETIME (8 B) | No | last-changed timestamp; "Date Modified" column. MOSSHELL `FUN_7F3FBC12` case `0xC` passes the 8 bytes straight to `FileTimeToSz` → `GetDateFormatA` + `GetTimeFormatA`. DWORD encoding does **not** work — only prop name `_D` triggers the DWORD-as-`time_t` fast path (BBSNAV territory). | Blank "Date" cell. | `0x03` DWORD → renders as `%u` decimal, not a date. |
| `l`  | DSNAV | *unresolved* | No | Advertised by DSNAV but no read-site confirmed in this pass. DWORD 0 is a safe wire value. | — | — |
| `i`  | DSNAV | *unresolved* | No | Advertised by DSNAV; no read-site confirmed. DWORD 0 is a safe wire value. | — | — |

Additional notes:

- DSNAV does NOT ask for `'z'` in the `GetChildren` request — see
  `project_dirsrv_getchildren_pipeline`. Wire replies can omit it.
- `fn` is not in DSNAV's advertised set. It is read only by DnR's
  `ExecUrlWorkerProc` (`c == 7` / `APP_DOWNLOAD_AND_RUN`) to build the
  temp filename. DnR leaves are the only nodes that need `fn`; non-DnR
  children can leave it out entirely.

## 13. Comparison to the other NAV plug-ins

| Plug-in | Size | Role | Consumes DIRSRV props? | Override count |
|---|---:|---|---|---:|
| `GUIDENAV.NAV` | 40 KiB | MSN Central welcome + Favorite Places | No (client-local HOMEBASE + MFP) | Multiple full vtables (root + FP) |
| **`DSNAV.NAV`** | **31 KiB** | **Directory Service listings** | **Yes — 14 tags** | **8 (single vtable)** |
| `BBSNAV.NAV`  | 209 KiB | Full BBS/forum UI (own tree + view) | Yes | Many (has its own shell view) |

DSNAV is uniquely *thin* among the three: it does not render its own
listview or ship its own WndProc. The shell's generic `CDIBWindow`/
`CMosXWindow` classes do all UI rendering; DSNAV only contributes:

1. A tree-node vtable with 8 behavioral overrides (§4).
2. The DIRSRV `NtniGroup` + 7 extra per-child tags (§5.2).
3. A plug-in registry that lets it delegate per-app verbs to NED DLLs
   (most commonly DSED, §6).
4. Menu + column resource templates (MENUs 0x80–0x83, RCDATA 0x81).

## 14. Known gaps / follow-ups

### 14.1 Gaps in this RE pass

- Property `'l'` and `'i'` are advertised but no read-site was confirmed.
  If a listview column or UI cell starts rendering these, the type will
  need re-checking.
- The exact MOSSHELL method corresponding to the slot 9 no-op stub is not
  individually identified — adjacent slots are ords `0x76` (`GetMosEvents`)
  and `0x75` (`SetPropertyGroupFromPsp`), so slot 9 is one of the
  inheritance-only helpers in that region. Net effect is a no-op
  regardless.
- Slots 56 and 57's exact MOSSHELL method names (from the `CMosTreeNode`
  vtable) were not cross-checked against the MOSSHELL vtable layout —
  they are identified here by behavior: slot 57 is a classic context-menu
  builder, slot 56 a smaller query paired with it (likely
  `AddToolbarButtons` / `GetCmdText` family).
- The one-slot vtables on the `CDIBWindow` / `CMosXWindow` subclasses
  suggest the full MOSSHELL base classes have more virtual methods; this
  document only captures the slot DSNAV actually installs.

### 14.2 `w` format — FILETIME vs DWORD

Confirmed 2026-04-21 via static disassembly of the MOSSHELL column
formatter `FUN_7F3FBC12` (the one caller of `FileTimeToSz`, reached
through `GetPropSz` / `GetPropSzBuf` on every listview cell paint):

- Type `0x03` (DWORD) path: `wsprintfA(buf, "%u", value)` by default.
  Only property **name** `"_D"` (hard-coded string at MOSSHELL
  `DAT_7F40EA08`) triggers the `TimetToFileTime → FileTimeToSz` fast
  path that treats the DWORD as a Unix `time_t`. `"_D"` is a BBSNAV
  property, not a DSNAV one — so `w`-as-DWORD renders as raw decimal
  (or "0" when the DWORD is 0).
- Type `0x0C` (8-byte qword) path: `FileTimeToSz(value_ptr, buf, 260)`
  directly — the cache's 8 bytes ARE the `FILETIME` (100-ns intervals
  since 1601-01-01 UTC). Formats as
  `GetDateFormatA(DATE_SHORTDATE) + " " + GetTimeFormatA(TIME_NOSECONDS)`
  on the localized SYSTEMTIME (after
  `FileTimeToLocalFileTime → FileTimeToSystemTime`).

SVCPROP's per-type decoder (see
`DIRSRV_GETCHILDREN_CLIENT_PATH.md §"DecodePropertyValue"`) consumes 8
bytes for type `0x0C`, matching this shape. Conclusion: emit `w` as
type `0x0C` FILETIME when a real timestamp is available; omit the tag
entirely when there isn't one, so the listview cell stays blank rather
than rendering a `1601-01-01` placeholder.

Ghidra session for the MOSSHELL trace: `759698c6b00f47acb7b4d1f44356aac1`
(read-only); the findings are captured in the plate comments above.

## 15. Ghidra annotations shipped in this pass

All changes live in the MSN95 project (`MSN95.gpr`), session
`d2c93d059e7c4b70945d11c35eb4de65` for `/DSNAV.NAV`. Renamed functions
and labeled globals:

- Functions: `DSNAV_Init`, `DSNAV_Cleanup`, `DSNAV_DllMainLogic`,
  `DSNAV_LoadAppPluginNode`, `DSNAV_AppMenuTable_Append`,
  `CDsNavTreeNode_Construct`, `CDsNavTreeNode_GetDetailsStruct`,
  `CDsNavTreeNode_Override_Slot56` / `…_Slot57_ContextMenu` /
  `…_Slot71_DelegateExec` / `…_Slot72_EnsureInner` /
  `…_Slot81_BuildServicesMenu` / `…_Slot82_InvokeServicesMenuItem`,
  `CDsNavPluginRegistry_Construct`, `CDsNavPluginRegistry_Insert`.
- Labels: `vtbl_CDsNavTreeNode` (`0x7F586020`),
  `vtbl_CDsNavPluginRegistry` (`0x7F586188`),
  `vtbl_CDsNav_CDIBWindow` (`0x7F58600C`),
  `vtbl_CDsNav_CMosXWindow` (`0x7F586008`),
  `g_DsNavHInstance` / `g_DsNavLiveInstanceCount` /
  `g_DsNavCachedColumns` / `g_DsNavCachedColumnCount` /
  `g_DsNavExtraPropTags` / `g_DsNavAppMenuTable` / `…Count` / `…Capacity`
  / `…Built`, `g_DsNavNtniGroup`, `g_DsNavPluginRegistry`,
  `g_DsNavPluginRegistryCS`.
- Plate comments on every plug-in entry + each override; vtable plate
  enumerates all 8 DSNAV-local slots with addresses.
