# MOSSHELL.DLL

Reverse-engineering notes for `binaries/MOSSHELL.DLL`, the Microsoft Network
namespace extension that hosts the entire MSN tree inside `EXPLORER.EXE`.

Sources: static binary plus live decompilation against the MSN95 Ghidra project
(`MSN95.gpr`, session `ff98dba06705481b93229137d27cca66` — MOSSHELL at link-time
image base `0x7F3F0000`). All addresses in this document are at that base.
Companions:

- `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` — MOSSHELL/TREENVCL/SVCPROP side of
  the `GetChildren` wire pipeline (record walker + SVCPROP decoder).
- `docs/TREENVCL.md` — the RPC client library MOSSHELL drives via
  `OkToGetChildren` / `GetNthChild` / `GetShabbyToFile`.
- `docs/DSNAV.md` — how the `App #1` navigator plug-in extends MOSSHELL.
- `docs/GUIDENAV.md` — the shape of a non-DIRSRV plug-in (welcome screen +
  Favorite Places).

## 1. Identity

- PE DLL, ~200 KiB on disk, link-time 1995-04, image base `0x7F3F0000`,
  max `0x7F421DFF`. Sections: `.text` ~100 KiB, `.rdata` 5.6 KiB,
  `.data` 8.7 KiB, `.idata` 9 KiB, `.edata` 16 KiB, `.rsrc` 31 KiB.
- **312 exports** across 8 C++ classes + ~30 globals; **715 functions** total.
- Loads **only inside EXPLORER.EXE** (see
  `reference_mosshell_host_process` memory). The MSN shell window is an
  Explorer folder-view backed by a MOSSHELL namespace extension; the only
  standalone MSN process that also interacts with MOSSHELL is MOSCP, which
  uses it as a marshaling target via exported helpers (not class methods).

### 1.1 Export surface

MSVC name mangling is fully demangled in the Ghidra project. Counts by class:

| Class | Exports | Role |
|---|---:|---|
| `CMosTreeNode` | 100 | Node COM object — implements IShellFolder + IMosTreeNode. Shell's hook into every MSN wire node. |
| `CMosViewWnd` | 52 | Folder-view window (listview + icons, context menu, toolbar). |
| `CMosTreeEdit` | 36 | In-place rename edit control (out of scope, §13). |
| `CMosXWindow` | 14 | Generic frame-window wrapper (used by NAV plug-ins too — see DSNAV §11.2). |
| `CDIBWindow` | 14 | Banner-strip paint carrier (§6.3 / out of scope for internals). |
| `CMosXWndClass` | 11 | RegisterClassA class-name buffer carrier. |
| `CMosXAllocator` | 10 | Per-module heap (`PvAlloc` / `PvRealloc` / `Free`). Exposed as `g_mxa`. |
| `CPlayMeta` | 3 | Audio/PlayMeta metadata (out of scope). |

Global entry points (non-class) relevant to this document:

| Export | Role |
|---|---|
| `DllGetClassObject` | Shell COM entry — returns IClassFactory for the MOSSHELL namespace extension. |
| `HrGetPMtn`, `HrGetPMtnFromPIdl` | Resolve a wire node-id / pidl to an `IMosTreeNode*`. **The single demand-load entry to every `.NAV` plug-in.** §7. |
| `HrBrowseObject` | Drive IShellBrowser navigation for a given pidl + flags. Called from `CMosTreeNode::ExecuteCommand` and `IMosShellView::OnCommand`. |
| `HrExecCommand` | Forward WM_COMMAND IDs 0x1050-0x1070 to the shell browser. |
| `IDL_New`, `IDL_Clone`, `IDL_Free`, `IDL_Append`, `IDL_PIdLast`, `IDL_Stats` | IShellFolder pidl helpers. |
| `MFP_*` | Favorite Places API (covered by `docs/GUIDENAV.md`). |
| `MnidToSz`, `SzToMnid`, `FileTimeToSz` | Wire-id ↔ display-string helpers. |
| `EnumMosWindows`, `RefreshEmw` | Enumerate every MOSSHELL-hosted window in the process (used by plug-ins to force refresh after a verb). |
| `CreateToolbarButtonSet`, `CreateRegExtMenu` | Toolbar + context-menu construction. |
| `ResultFromMcmErr`, `ResultFromDsStatus` | Error-code translators (MCM and DIRSRV status → HRESULT). |
| Globals `g_mxa`, `g_caid`, `g_rgaidNodes`, `g_szCanonicalCut/Copy/Paste/Delete/Properties` | Shell-wide state referenced by plug-ins. |

## 2. Process context

```
EXPLORER.EXE
├── MOSSHELL.DLL              ← this DLL
│   ├── CMosShellFolder       (IShellFolder tear-off wrapping CMosTreeNode; see §4.1)
│   ├── CMosEnumIDList        (IEnumIDList; 12-byte object; §5)
│   ├── CMosTreeNode          (IMosTreeNode; full COM surface; §3)
│   ├── CMosViewWnd           (the listview; hosts per-item icon cache + context menu)
│   └── CDIBWindow            (banner; out of scope — §13)
│
└── LoadLibraryA (via MCM!HRMOSExtract, see §7)
    ├── DSNAV.NAV             (App #1 Directory_Service — docs/DSNAV.md)
    ├── GUIDENAV.NAV          (App #3 Guide — docs/GUIDENAV.md)
    ├── BBSNAV.NAV            (App #2 BBS)
    └── …one NAV per registered MOS app
```

The shell enters MOSSHELL through `DllGetClassObject` (for the MSN namespace
extension CLSID). Once instantiated, all tree walking goes through
`CMosTreeNode` and its plug-in delegations. Plug-ins never talk to the shell
directly — they always mount on top of MOSSHELL's framework.

## 3. CMosTreeNode — the node COM object

`CMosTreeNode` is the heart of MOSSHELL. It implements **two interfaces on a
single object**:

- **`IShellFolder`** (Win32 shell namespace extension contract) — Explorer
  uses this to enumerate, name, and invoke nodes. Full vtable is labeled in
  the Ghidra project (`QueryInterface`, `AddRef`, `Release`,
  `ParseDisplayName`, `EnumObjects`, `BindToObject`, `BindToStorage`,
  `CompareIDs`, `CreateViewObject`, `GetAttributesOf`, `GetUIObjectOf`,
  `GetDisplayNameOf`, `SetNameOf`).
- **`IMosTreeNode`** — MSN-internal COM interface exposing everything a
  plug-in (or the view window) needs to drive a node. This is the vtable
  plug-ins override (DSNAV overrides 8 of its slots — §3.2).

Methods reached during normal use: `CMosTreeNode::CMosTreeNode(_MosNodeId*, _NtniGroup*)` is the base ctor; plug-ins call it then overwrite the vtable. The IShellFolder side is always the MOSSHELL one (plug-ins don't override it).

### 3.1 `IMosTreeNode` vtable — observed slots

Byte offsets into the IMosTreeNode vtable (from decompiled call sites; all
confirmed against live functions). "DSNAV slot N" is DSNAV.md's slot-numbering
convention; the relationship is
`DSNAV_slot = raw_byte_offset - 0x20) / 4` (slots 0-7 are IUnknown +
cross-interface plumbing that plug-ins never override).

| Byte offset | DSNAV slot | Name / inferred purpose | Key reader / writer in MOSSHELL |
|---:|---:|---|---|
| `+0x00` | 0 | `QueryInterface` | standard IUnknown |
| `+0x04` | 1 | `AddRef` | standard IUnknown |
| `+0x08` | 2 | `Release` | standard IUnknown |
| `+0x0C` | 3 | `GetChildrenEnum` (returns a child-enumerator sub-iface) | `CMosEnumIDList_Init` @ `0x7F3FB199` |
| `+0x1C` | 7 | `GetConnection` (returns `CTreeNavClient*`) | `CMosTreeNode::GetShabbyToFile` @ `0x7F3FD6DF` |
| `+0x24` | 9 | inheritance-only 1-arg helper (5-byte xor/ret) | DSNAV override slot 9 |
| `+0x28` | 10 | `GetNthChild` | — |
| `+0x40` | 16 | `HrGetPropertyEx(pMtn, &tag, buf, size, type)` | Used everywhere — property read ABI. |
| `+0x50` | 20 | query "can-exec" flag | DSNAV slot 81 uses it |
| `+0x68` | 26 | `GetIdTuple` (writes service/content id pair) | `LoadShabbyIconForNode` @ `0x7F405018`; `CacheNodeIconsIntoImageLists` @ `0x7F4047C2` |
| `+0x6C` | 27 | `BuildIdl` (allocate + populate a pidl for self) | `CMosEnumIDList_Next` @ `0x7F3FB27F` |
| `+0x74` | 29 | **`GetShabbyToFile`** (download shabby blob to disk; DIRSRV sel=4) | `LoadShabbyIconForNode`, `FetchShabbyIconToTempAndExtract` @ `0x7F4049F9` |
| `+0x90` | 28 | `GetDetailsStruct` (column descriptor `MDS[]`) | DSNAV override slot 28 |
| `+0xA8` | 42 | `GetCChildren` (synchronous child count) | from DIRSRV GetChildren doc |
| `+0xB0` | 44 | `OkToGetChildren` (lazy wire loader) | from DIRSRV GetChildren doc |
| `+0xB4` | 45 | `GetSnap` (take snapshot of children for enumeration) | `CMosEnumIDList_Init` |
| `+0xB8` | 46 | `GetCanonicalMnid` | `CanonicalizePidlSpecialAlias` @ `0x7F3F24D9` |
| `+0xBC` | — | DSNAV's inner-node slot (cache-pointer, zero'd by plug-in ctor) | DSNAV §6.2 |
| `+0xC4` | 49 | `GetSubObject` (returns DSINK/IDocHost-like sub-node for label-qualifier) | `CMosShellFolder::GetDisplayNameOf` @ `0x7F3F3161` |
| `+0xCC` | 51 | **`Exec`** (leaf-only dispatch; no browse) | `CMosTreeNode::ExecuteCommand` @ `0x7F3FF693` — verb 0x3000/0x3001 when `b`-bit set |
| `+0xD8` | 54 | DSNAV slot verb-0x3003 target | — |
| `+0xE0` | 56 | menu gatekeeper | DSNAV override slot 56 |
| `+0xE4` | 57 | context-menu builder | DSNAV override slot 57 |
| `+0xF4` | 61 | `CMosViewWnd` → node bridge (0x300D path) | `CMosViewWnd::ExecuteCommand` @ `0x7F3F7CDA` (IDM 0x2100-0x2200 range) |
| `+0x100`-`+0x148` | 64-82 | plug-in extension slots | DSNAV overrides slots 71, 72, 81, 82 |

(MOSSHELL's own `CMosTreeNode` vtable is the default — MOSSHELL installs full
implementations for every slot. Plug-ins like DSNAV replace a few and leave
the rest as thunks back into MOSSHELL via the import table.)

### 3.2 `CMosTreeNode_inst` — node instance layout (observed)

Instance offsets gleaned from `CMosTreeNode::CMosTreeNode` callers and from
every decompilation that accesses `*(this+N)`. Marked **obs** for offsets
confirmed by two or more independent read sites.

| Offset | Size | Field | Source |
|---:|---:|---|---|
| `+0x00` | 4 | `vtable` (IMosTreeNode) | every method call |
| `+0x04` | 4 | `refcount` | IUnknown convention |
| `+0x10` | 16 | `_MosNodeId` (mnid, incl. `app_id` DWORD at `+0x10`) | `CMosTreeNode::CMosTreeNode(mnid,...)` — DSNAV §3.1 copies from here **obs** |
| `+0x18` | 8 | node-id LARGE_INTEGER (secondary wire id) | `DIRSRV_GETCHILDREN_CLIENT_PATH.md` |
| `+0x2C` | 4 | `pInner` pointer (used by `CMosShellFolder::EnumObjects` tear-off outer→inner access) | `CMosShellFolder::EnumObjects` @ `0x7F3F2B90` **obs** |
| `+0x48` | 4 | snapshot / enum-cache ptr (legacy memory note) | `project_mosshell_addrbar_enum_path` |
| `+0x5C` | 24 | CRITICAL_SECTION for `OkToGetChildren` re-entry guard | `DIRSRV_GETCHILDREN_CLIENT_PATH.md` |
| `+0xA4` | 4 | TREENVCL dynamic-iterator handle (out of `OkToGetChildren`) | DIRSRV doc |
| `+0xB0` | 4 | cached child count | DIRSRV doc |
| `+0xB4` | 4 | token/handle passed to `CTreeNavClient::GetChildren` | DIRSRV doc |
| `+0xBC` | 4 | DSNAV-inner-node cache (plug-in-specific use; zero'd on construct) | DSNAV §3.1 |
| `+0xE4` | 1 | `flags_3B` (bit `0x04` = no-more-children sentinel, bit `0x02` = alt-tag-list) | DIRSRV doc |
| `+0x100`… | — | NtniGroup pointer + per-plug-in state | DSNAV §5.1 |

The `CMosShellFolder` tear-off is a **separate small object**:

```
+0x00  vtable (IShellFolder)
+0x04  outer CMosTreeNode back-pointer
+0x08  auxiliary (refcount or state — not fully RE'd)
```

Explorer holds `CMosShellFolder*`; `CMosTreeNode` is reached via
`(*(this+4) + 0x2C)` in every IShellFolder method. Plug-ins never see the
tear-off — they live on the inner `CMosTreeNode`.

## 4. The property bag (`HrGetPropertyEx`)

Every MOSSHELL read of a wire property goes through vtable `+0x40`:

```c
// CMosTreeNode_vtable[16] — HrGetPropertyEx signature:
HRESULT HrGetPropertyEx(
    IMosTreeNode *this,
    const char   *tag,      // 1-2 char asciiz, address in MOSSHELL .rdata
    void         *buf,      // out
    DWORD         cap,      // buffer capacity
    DWORD         type);    // requested wire type (1 = ANSI, 4 = DWORD, …)
```

Tag strings live in `.rdata`. Key addresses (for decomp cross-reference):

| Addr | Tag | Seen as |
|---|---|---|
| `0x7F40E1C0` | `'c'` | `&DAT_7f40e1c0` — app_id DWORD |
| `0x7F40E1C4` | `'b'` | `&DAT_7f40e1c4` — browse-flags byte |
| `0x7F40E1E8` | `'e'` | `&DAT_7f40e1e8` — ANSI display name |
| `0x7F40E1EC` | `'_F'` | `&DAT_7f40e1ec` — sub-object flag byte (§5.3) |
| `0x7F40EBD0` | `'t'` | label sub-menu helper |
| `0x7F40EBD4` | `'mf'` | `s_prop_mf` — primary icon shabby_id |
| `0x7F40EBE4` | `'wv'` | secondary icon shabby_id |

### 4.1 Default request-tag list

From `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md § Property tag request lists`:

| Buffer | Addr | Tags | When used |
|---|---|---|---|
| Default | `0x7F40E868` | `{a, c, b, e, g, h, x}` | standard `GetChildren` |
| Alt | `0x7F40E888` | `{g, a}` | when `flags_3B & 2` set |
| Plug-in-extended | computed | Default ∪ `g_<Plugin>ExtraPropTags` | when NtniGroup advertises extras (DSNAV merges 7 extras → 14) |

### 4.2 Tags MOSSHELL reads, with consumer

| Tag | Wire type MOSSHELL expects | Read site (function, vtable slot, cap) | Consumer in MOSSHELL |
|---|---|---|---|
| `a`  | 0x0E blob (8 B mnid) | Embedded in pidl; not read via `HrGetPropertyEx`. | `HrGetPMtn` — drives plug-in load. |
| `b`  | 0x01 byte | `CMosTreeNode::ExecuteCommand` @ `0x7F3FF693`; `HrResolvePidlAndWaitChildren` @ `0x7F3F270A`. Slot `+0x40`, cap 1, type 1. | **Bit 0x01 clear → Browse (HrBrowseObject); set → Exec (vtable[+0xCC]).** Bit `0x08` set → server-denied, abort. |
| `c`  | 0x03 DWORD | `HrResolvePidlAndWaitChildren` @ `0x7F3F270A`. Slot `+0x40`, cap 4, type 0. | `c == 7` (Download-and-Run) → wait for children indefinitely. Also drives DSNAV plug-in delegation (§7). |
| `e`  | 0x0A ASCIIZ | `CMosShellFolder::GetDisplayNameOf` @ `0x7F3F3161`. Slot `+0x40`, cap 0x104, **type 1 (ANSI)**. | Listview label + address-bar + explorer titlebar. 0x0B truncates at first wide NUL → "M" bug; memory `project_dirsrv_nav_e_encoding`. |
| `g`  | 0x03 DWORD | — | No MOSSHELL read site identified; server emits 0 as safe default. |
| `h`  | 0x03 DWORD (ICO shabby_id) | `CacheNodeIconsIntoImageLists` @ `0x7F4047C2` → `FetchShabbyIconToTempAndExtract` @ `0x7F4049F9`. | Per-item listview icon (`ExtractIconExA` on downloaded ICO/EXE/DLL). Missing → forbidden-glyph default icon. |
| `mf` | 0x03 DWORD (BMP/WMF/EMF shabby_id, packed `fmt<<24 \| content_id24`) | `LoadShabbyIconForNode` @ `0x7F405018`. Slot `+0x40`, cap 4, type 0. | Banner + primary-icon paint. Format byte selects loader: `1`=EMF, `3`=raw WMF, `4`=placeable WMF, `5`=BMP. |
| `wv` | 0x03 DWORD | — (handed to `LoadShabbyIconForNode`-style paths by plug-ins via `GetShabbyProp`) | Variant icon. |
| `x`  | 0x0E blob | — | Consumed by launcher paths (`CMosTreeNode::Exec` slot `+0xCC` implementations). |
| `_F` | 0x01 byte (sub-object flag) | `GetDisplayNameOf` via `GetSubObject` (vtable `+0xC4`). Cap 2, type 2. | Bit `0x20` triggers STRINGTABLE 0x88 suffix append to the `e` string. |
| `tp` | 0x0A ASCIIZ (DSNAV contract) | `CDsNavTreeNode::GetDetailsStruct` (DSNAV §10) | "Type" column — tag travels through MOSSHELL only as an opaque cache slot. |
| `p`  | 0x03 DWORD | Properties dialog `FUN_7F3FBA69` special branch | Formats as "Size" via `FormatSizeString`; see §4.3 for the `pInner` delegation that leaves the dialog field blank on `app_id=1` nodes. |
| `w`  | 0x03 DWORD | Column descriptor (DSNAV) | "Date Modified" column. |
| `l`, `i` | reserved | — | No confirmed read site. |

**Full server cross-check is in `docs/DSNAV.md` §12 and §14.2.** MOSSHELL
itself is tag-agnostic for everything except `a`, `b`, `c`, `e`, `h`, `mf`,
and `_F` — the rest flow through to plug-ins or column descriptors.

### 4.3 `p` rendering in the Properties dialog

The Context tab (`FUN_7F401D81`) reads `p` through a three-step chain:

1. `EnsurePropertyGroup(&PTR_DAT_7F40E988)` batches
   `{q,r,s,t,u,n,y,on,v,w,p}` into one `GetProperties(children=True)`
   wire request.
2. For each prop, `RememberProperty` (`CMosTreeNode` slot 11, offset
   `+0x2C`) inserts the wire bytes into the node's per-prop cache. Inner
   helper `FUN_7F3FBA69` runs a name-matched special branch for `"p"`:
   `vtable[+0x140] FormatSizeString(this, **(cache+4), buf, 0x104)` —
   the DWORD is formatted into `buf`, then `lstrcpyA`-ed to `cache+0xC`
   (the ANSI copy slot read by `GetPropSz`).
3. The dialog finally does
   `SetDlgItemTextA(hwnd, 0x7F, GetPropSzBuf("p"))`, rendering whatever
   is at `cache+0xC`.

`CMosTreeNode::FormatSizeString @ 0x7F3FFE00` branches on `node+0xBC`
(`pInner`):

```c
if (pInner == NULL)
    wsprintfA(buf, "%d", dword);       // raw decimal — e.g. "5242880"
else
    pInner->vtable[+0x24](pInner, pInner, dword, buf, 0x104);
```

`pInner` is populated lazily by DSNAV's `EnsureInner` (slot 72) when the
shell first needs a per-app plug-in node — for `app_id=1` DIRSRV
containers, that resolves to **DSED** (`App #18`, `dsned.ned`) through
`DSNAV_LoadAppPluginNode` (DSNAV §6.1). Once cached, every subsequent
`FormatSizeString` delegates to DSED's slot `+0x24`, which empirically
writes an empty string and returns success. `lstrlenA(buf)==0` makes
`cache+0xC` a 1-byte `""` allocation, and the Properties-dialog Size
field renders blank.

The Size column in the DSNAV details-view listview does not go through
this path — MOSSHELL reads `p` directly from the cache into
`FormatSizeString` with the listview's own column buffer, so the column
still renders. The blank-Size behavior is specific to the dialog.

## 5. Enumeration pipeline

### 5.1 `CMosShellFolder::EnumObjects` @ `0x7F3F2B90`

Invoked by Explorer to populate the listview. Trivial wrapper:

1. `CMosXAllocator::PvAlloc(g_mxa, 12)` — 12-byte `CMosEnumIDList`.
2. `CMosEnumIDList_ctor` @ `0x7F3FB14B` — set vtable `PTR_LAB_7f40cfe0`,
   zero refcount, zero snapshot ptr.
3. `CMosEnumIDList_Init(this, pMtn)` @ `0x7F3FB199` where
   `pMtn = *(*(this_shellfolder+4) + 0x2C)` (tear-off → outer CMosTreeNode →
   `pInner`).
4. AddRef + return.

The 7-slot IEnumIDList vtable at `0x7F40CFE0`:

| Offset | Addr | Method |
|---|---|---|
| `+0x00` | `0x7F3FB1F5` | `QueryInterface` |
| `+0x04` | `0x7F3FB249` | `AddRef` |
| `+0x08` | `0x7F3FB257` | `Release` |
| `+0x0C` | `0x7F3FB27F` | `Next` ← `CMosEnumIDList_Next` |
| `+0x10` | `0x7F3FB3F2` | `Skip` |
| `+0x14` | `0x7F3FB406` | `Reset` |
| `+0x18` | `0x7F3FB418` | `Clone` |

### 5.2 `CMosEnumIDList_Init` @ `0x7F3FB199`

Delegates into the wire-fed snapshot:

1. `pMtn->vtable[+0x0C](pMtn, &childEnumIface)` — get a child-enumerator
   sub-interface (not full IEnumIDList; an internal iterator).
2. `childEnumIface->vtable[+0xB4](childEnumIface, &this->snapshot)` —
   **GetSnap** — writes a snapshot handle into `this+8`. This is the
   moment the wire `GetChildren` request fires (transitively through
   `CTreeNavClient::GetChildren`).
3. Release the sub-iface; AddRef the snapshot.

Init failure → caller runs the destructor and returns E_OUTOFMEMORY.

### 5.3 `CMosEnumIDList_Next` @ `0x7F3FB27F`

Batches `celt` children into the caller's `rgelt[]`:

1. Read parent's `'e'` (diagnostic prefix, up to 31 chars).
2. `snapshot->vtable[+0x28](snapshot, celt, buf[], &fetched)` — pull N
   children as `IMosTreeNode*` array.
3. For each child: `child->vtable[+0x6C](child, &rgelt[i])` — `BuildIdl`
   allocates + stamps a pidl. Release the child.
4. Return S_OK (0) if `fetched == celt`, S_FALSE (1) otherwise.

The snapshot owns child references; the enumerator only holds pidls.

### 5.4 `CMosShellFolder::BindToObject`

Not decompiled in detail here, but its contract is documented in memory
`project_mosshell_addrbar_enum_path`:

> Explorer's address-bar drop-down calls **BindToObject**; that fires the
> wire `HrGetPMtn` → plug-in `GETPMTN` for the target. The listview's
> refresh-existing-folder path calls **EnumObjects**, which reuses the
> already-materialized snapshot without further wire traffic.

### 5.5 PIDL helpers used by navigation

- **`CanonicalizePidlSpecialAlias`** @ `0x7F3F24D9` — rewrites a two-segment
  pidl in place to a single-segment canonical form when the tail MNID matches
  `GetSpecialMnid(0..2)` (MSN root / Current User / My Places). Allocates a
  fresh `0x28 + tail_size`-byte pidl stamped with
  `{cb=0x28, mnidType=0x1B70A, flags=1}` and the parent's canonical MNID.
  No wire traffic.
- **`HrResolvePidlAndWaitChildren`** @ `0x7F3F270A` — used by address-bar
  navigation to synchronously wait until a node's children are populated
  before Explorer asks `EnumObjects`. Resolves the pidl via `HrGetPMtn`,
  reads `'b'` (folder vs leaf) and `'c'` (app_id), then waits on
  `DAT_7F40E03C` (the DNR/child-ready event):
  `c == 7` blocks forever, else 30s bounded with `DnrJobCount` bumped.

## 6. Render pipeline

Three separable render stages: label, per-item icon, banner.

### 6.1 Label — `CMosShellFolder::GetDisplayNameOf` @ `0x7F3F3161`

1. Reject `SHGDN_FORPARSING` (`0x8000`) with `E_NOTIMPL`.
2. `HrGetPMtnFromPIdl(pidl_last, &pMtn, 0)` — resolve target node.
3. `pMtn->HrGetPropertyEx('e', pName+4, 0x104, 1 /* ANSI */)` — copy display
   name into STRRET buffer at offset +4.
4. `pMtn->GetSubObject(&pSubNode)` (`+0xC4`) — optional sub-node.
5. If `subNode->GetDetails()[0] == 2`: read sub-node's `'_F'` byte; if bit
   `0x20` set, `LoadStringA(hInstRes, 0x88, suffix, remaining)` and append
   " <suffix>" to the name (e.g., " (Not responding)" qualifier).
6. Release subNode, release pMtn.
7. Stamp STRRET type `STRRET_CSTR (2)` and return.

Encoding is always ANSI — 0x0B wire-type strings get truncated at first
wide-NUL (memory `project_dirsrv_nav_e_encoding`).

### 6.2 Per-item icon — `CacheNodeIconsIntoImageLists` @ `0x7F4047C2`

Maintains two HIMAGELIST on the owning `CMosViewWnd`:
- `*this` = small (16×16) icons
- `*(this+4)` = large (32×32) icons
- `this+0x120` = CRITICAL_SECTION guarding both lists

Per node:

1. `FUN_7F4042A0(this)` — validate the view object.
2. `pMtn->GetIdTuple(&local_18)` (`+0x68`) — service/content id pair.
3. `FUN_7F4053AB(this, key, ...)` — look up cached row by key.
4. On cache miss, under critical section:
   a. `FetchShabbyIconToTempAndExtract(pMtn, key, &hLarge, &hSmall)` @
      `0x7F4049F9`:
      - `GetTempPathA(MAX_PATH, path)` (fallback `\\` from `0x7F40EA84`).
      - `GetTempFileNameA(path, "MSN", 0, temp)` (prefix from `0x7F40EA80`).
      - `pMtn->GetShabbyToFile(key, temp, ...)` (`+0x74`) — download ICO
        blob via DIRSRV selector 4.
      - `ExtractIconExA(temp, 0, &hLarge, &hSmall, 1)`.
      - `DeleteFileA(temp)` unconditionally.
   b. `ImageList_ReplaceIcon(*(this+4), -1, hLarge)` then same for small.
   c. `FUN_7F40533B(this, ...)` — insert the (key, index) row.
5. Return cached image-list index (or `0xFFFFFFFF` on failure).

This path is **for property `'h'`** — the ICO/EXE/DLL secondary-icon
channel. Missing `'h'` → no cache row → LVN_GETDISPINFO returns `iImage=0`
= forbidden-glyph default (memory `project_dirsrv_h_property_icon_path`).

### 6.3 Banner — `CMosTreeNode::GetHbmpForPMtn` @ `0x7F3FD885` → `LoadShabbyIconForNode` @ `0x7F405018`

```c
HANDLE LoadShabbyIconForNode(CMosTreeNode *this, int *pMtn,
                             int no_network_ok,
                             HBITMAP *out_hbmp, void *extra);
```

1. `pMtn->GetIdTuple(&ids)` (`+0x68`) — service/content ids (used as
   `%04X:%08X` cache filename components; `0x7F40EB74`).
2. `pMtn->HrGetPropertyEx('mf', &shabby_id, 4, 0)` — DWORD packed as
   `format<<24 | content_id24`.
3. `BuildShabbyCachePath(this, path, hi_id, lo_id, shabby_id, 0)` @
   `0x7F405211` — deterministic on-disk cache path.
4. `GetFileAttributesA(path)` — cache hit shortcuts to step 5.
5. On miss:
   - If `no_network_ok != 0`: return `(HANDLE)0xFFFFFFFF` ("not cached,
     don't block"). Used by the tree-refresh path to avoid synchronous
     network I/O.
   - Else: `pMtn->GetShabbyToFile(shabby_id, path, ...)` (`+0x74`).
6. Dispatch by `shabby_id >> 24` (the format byte):

| Fmt byte | Loader | Image type |
|---:|---|---|
| `1` | `GetEnhMetaFileA` + `PlayEnhMetaFile` | EMF |
| `3` | `LoadShabbyWMF(path, 1, …)` | raw WMF |
| `4` | `LoadShabbyWMF(path, 0, …)` | placeable WMF (magic `0x9AC6CDD7`) |
| `5` | `LoadShabbyBMP` (`LoadImageA`, flags `LR_LOADFROMFILE \| LR_CREATEDIBSECTION`) | BMP |
| other | — | NULL |

This is the **BMP family** — `'mf'` / `'wv'` channel. No ICO loader here;
that lives exclusively in §6.2.

`CDIBWindow` subclasses (used by plug-ins like DSNAV §11.1) consume the
resulting HBITMAP for the banner strip. Banner paint internals are out of
scope (§13).

### 6.4 `CMosTreeNode::GetShabbyToFile` @ `0x7F3FD6DF`

The single wire shuttle for all shabby fetches. Called from both render
paths (§6.2 and §6.3):

1. `pMtn->GetConnection(&treeNav)` (`+0x1C`) → `CTreeNavClient*`.
2. `CTreeNavClient::GetShabby(treeNav, shabby_id, &buf, &size, &status)`
   sends DIRSRV(sel=4) with one `DwordParam(shabby_id)`. Reply parser
   binds status DWORD to tag `0x83` and gates on `status==0` before
   malloc'ing from the `0x88`-tagged dynamic payload.
3. `CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, …)` +
   `WriteFile(h, buf, size, …)`. On short write → `DeleteFileA`.
4. `CTreeNavClient::FreeShabby` + `CloseHandle` + `CTreeNavClient::Release`
   always on exit.

See memory `project_mosshell_shabby_call_path` for deeper notes.

## 7. Click dispatch

**Two separate dispatchers** — don't confuse them:

### 7.1 `CMosTreeNode::ExecuteCommand` @ `0x7F3FF693` — per-node verb dispatcher

Signature: `long ExecuteCommand(uint this, uint verb, long pExec, long pShellBrowser)`.

Gatekeeper: reads `'b'` (`&DAT_7F40E1C4`) byte; if bit `0x08` set (wire-reported
"denied"), bail with `ReportMosXErr`.

Verb switch (0x3000-0x300D):

| Verb | Name | Action |
|---:|---|---|
| `0x3000` | Open (default) | `b` bit 0 clear → Browse (§7.1.1); set → `this->vtable[+0xCC](this, pShellBrowser)` = `Exec`. |
| `0x3001` | Open-in-new-window | Browse branch with `SBSP_NEWBROWSER` (flags `0x10`/`0x12`). |
| `0x3002` | Explore | Browse branch with `SBSP_EXPLOREMODE` (`0x20`/`0x22`). On leaf → error via `ReportMosXErrX(0xB)` ("Cannot Explore a launch-only node"). |
| `0x3003` | — (plug-in-specific) | `this->vtable[+0xD8](this, 0)`. |
| `0x3004` | Add to Favorites | `MFP_FAdd(&this->mnid, !isLeaf)`. |
| `0x3005` | — | `pShellBrowser->vtable[+0x0C](pShellBrowser, ...)` then `pExec->vtable[+0x28](...)`. |
| `0x300B` | (bypasses `'b'` gate) | `this->vtable[+0x160](this)`. |
| `0x300D` | — | Multi-stage: `vtable[+0x104]` + `vtable[+0x100]` + `vtable[+0x148]`. |

#### 7.1.1 Browse branch

When `b` bit 0 is clear, the verb resolves the view-attached state then
computes SBSP flags from (a) verb, (b) `SingleWindowMode` preference
(`s_SingleWindowMode_7F40E2DC` under `SOFTWARE\Microsoft\MOS\Preferences`).
Calls `HrBrowseObject(pShellBrowser, NULL, pidl, flags)` and frees the
pidl with `IDL_Free` on return.

**Single source of truth for the `'b'` bit:** `0` = folder (Browse), `1` = leaf (Exec). See plate comment on `CMosTreeNode::ExecuteCommand` in the Ghidra project. Server side: `src/server/config.py :: DIRSRV_BROWSE_FLAGS_CONTAINER / _LEAF`.

### 7.2 `IMosShellView::OnCommand` @ `0x7F3F5406` — frame-window menu dispatcher

WM_COMMAND handler for the MSN shell frame. **NOT per-node dispatch** — this
is for the application menu and toolbar. Command IDs 0x1000-0x100F:

| IDM | Action |
|---:|---|
| `0x1000` | `HrForceConnection` — Connect. |
| `0x1001` | `FRequestAppShutdown` — File → Exit. |
| `0x1002` | `FGetGoWord` — Go-word dialog. |
| `0x1003` / `0x100C` / `0x100E` / `0x100F` | `MOSX_GotoMosLocation(0/3/1/6)` — Go → MSN/Home/Favs/Help. |
| `0x1004` | `ChangePassword`. |
| `0x1005` / `0x1006` | `MOSX_GotoMosLocation(4/5)`. |
| `0x1008` | `ChangeConnectionSettings`. |
| `0x1009` / `0x100B` | `WinHelpA` with topic from STRINGTABLE 0x86/0x87. |
| `0x100A` | About box — `LoadIconA(1)` + STRINGTABLE 0x83 + `MosAbout`. |
| `0x100D` | View → Open — `HrBrowseObject(browser, view, NULL, 0x2001\|0x2002)` (`SingleWindowMode` chooses). |
| `0x1050`-`0x1070` | Forward to `HrExecCommand(*(this+0x18), wID)` — pShellBrowser. |

Per-node clicks go through §7.1, not here.

### 7.3 `CMosViewWnd::ExecuteCommand` @ `0x7F3F7CDA` — view-level dispatcher

IDM 0x2000-0x2300: listview display-mode changes (icons/details/list/small)
via `SetWindowLongA(-16, …)`, sort toggles, IDM 0x2100-0x2200 forwards to
the currently-selected node's `vtable[+0xF4]` with verb `0x300D`. IDM
0x2200-0x2300 `SendMessage(listview, LVM_…)` for column-specific cell ops.

### 7.4 `CMosShellFolder::ParseDisplayName` 'T'/'F' — startup auto-Exec entry

`CMosShellFolder::ParseDisplayName @ 0x7F3F2984` is the `IShellFolder`
tear-off method Explorer calls to resolve a display name string to a PIDL.
For the MSN namespace it dispatches on the **second** ANSI byte of the
display name (`szAnsi[1]`, after `WideCharToMultiByte`):

| Dispatch | `GetSpecialMnid` arg | Target | Action |
|---|---|---|---|
| `'A'` | — | absolute mnid (hex) | `SzToMnid` + `HrGetPMtn` + `MFP_FAdd` (favorites-style). |
| `'X'` | — | registry-stashed PIDL | `FUN_7F3F28BC` pulls bytes from `HKCU\SOFTWARE\Microsoft\MOS\Mosxapi\<key>` (see §7.4.1 below on how CCAPI populates this). |
| `'T'` | 4 | MSN Today (shn `4:0`) | `HrGetPMtn` → `GetLocalizedNode` → `Exec`. **No `'b'` gate.** |
| `'F'` | 5 | Favorite Places (shn `3:1`) | Same shape as `'T'`. |

**This is the sole path that reaches `CMosTreeNode::Exec` without honoring
the `'b'` leaf/container gate.** `ExecuteCommand` (§7.1) is the only other
Exec caller and requires `'b' & 0x01 == 1` (leaf); an exhaustive
`search_instructions` sweep for `CALL [<reg>+0xCC]` across every address
mode confirms no third site hits `CMosTreeNode::vftable[0xCC] = Exec @
0x7F3FEBA6` (data-ref at `0x7F40CBAC`).

Decomp excerpt of the 'T'/'F' branch:

```c
GetSpecialMnid((dispatchChar == 'F') + 4, mnid);
hr = HrGetPMtn(mnid, &pNode, 0);
if (hr < 0) goto LAB_7f3f2afe;
hr = (*pNode->vtable[0xC8])(pNode, &pSubNode);    // GetLocalizedNode
(*pNode->vtable[0x08])(pNode);                    // Release pNode
if (hr < 0) goto LAB_7f3f2afe;
(*pSubNode->vtable[0xCC])(pSubNode, 0);           // ← CMosTreeNode::Exec, unconditional
(*pSubNode->vtable[0x08])(pSubNode);              // Release pSubNode
```

#### 7.4.1 The "Show MSN Today on startup" flag (CCAPI contract)

The 'T' branch is the MOSSHELL half of a two-DLL contract with CCAPI that
implements the **"Show MSN Today on startup"** user preference. When the
preference is set (likely a value under
`HKCU\SOFTWARE\Microsoft\MOS\Preferences`; exact value-name not yet
pinned), startup code invokes **`CCAPI!MOSX_GotoMosLocation @ 0x05563394`**
with case 8:

```c
case 8:
    pCVar5 = &DAT_05565390;
    cVar4 = 'T';
    goto LAB_05563625;       // FUN_05562d2e('T', pCVar5, 0)
```

Case 9 is the 'F' / Favorite Places twin; cases 0/1/3/4/5/6 are the
Go-menu commands listed in §7.2. `CCAPI!FUN_05562D2E` builds a compound
Explorer command line and `ShellExecuteA`s it:

```
explorer.exe /root,{00028B00-…},"<…>TheMic~1.msn",[T]<mnid>
```

(Format string `",[%c]"` at `0x0556527C`; the quoted `.msn` path is the
Marvel desktop file located via `FEnsureMarvelDesktopFile`.) Windows
launches a new Explorer instance mounting the MSN namespace; Explorer's
path parser calls `IShellFolder::ParseDisplayName` with the `[T]<mnid>`
tail, landing in the 'T' branch above.

The `'X'` row in the table earlier is the same mechanism one level down:
`CCAPI!MOSX_HrExecPidl @ 0x05562EBD` stashes an arbitrary PIDL under
`HKCU\…\Mosxapi\PidlEx %pid %d`, then spawns Explorer with
`,[X]PidlEx %pid %d`; ParseDisplayName 'X' re-reads the registry and
resolves to the original PIDL. It is the generic "goto this node"
contract; 'T'/'F' are the hardcoded specials.

#### 7.4.2 `Exec` behavior by `'c'` on the unguarded 'T'/'F' path

Since the 'T' branch ignores `'b'`, what happens after
`CMosTreeNode::Exec @ 0x7F3FEBA6` runs depends entirely on the wire
`'c'` (app_id) property cached on the node:

- **`c = 7`** (APP_DOWNLOAD_AND_RUN) — intended design. `Exec` takes the
  `CreateOleWorkerThread(ExecUrlWorkerProc)` branch at `0x7F3FED53`.
  The worker reads the node's `'fn'` property, FTM-downloads the named
  file to a temp path, then calls `HRMOSExec(7, "-\"<tempfile>\"")`.
  App #7's registered Filename is `dnr.exe`; DNR's command-line parser
  (`DNR.EXE 0x7F591046`, the entire EXE is 3 functions +
  `ShellExecuteExA`) only accepts the `-"<quotedpath>"` form, then
  `ShellExecuteExA`'s it with `lpVerb=NULL` — `.htm` opens in the
  default browser.
- **`c != 7`** — `Exec` falls through to the synchronous
  `HRMOSExec(c, cmdstr, node.f10, node.f20, &node.f18)` branch.
  MCM's `HRMOSExec` reads
  `HKLM\SOFTWARE\Microsoft\MOS\Applications\App #<c>\Filename`,
  formats `"<Filename> -MOS:c:shn0:shn1:w"` via `FormatMosArgTail`, and
  `CreateProcessA`s it. If App #c has no registered `Filename`,
  `HRMOSExec` returns 0 silently — no dialog. If `Filename` resolves
  to a `.nav` plug-in (DSNAV / BBSNAV / GUIDENAV — LoadLibrary-only,
  not a PE with an entry point), `CreateProcessA` fails and MCM pops
  `MosErrorP(0x529)` "MSN Network cannot run …".

Notably: the `-MOS:…` argument format is only produced on the
`c != 7` sync path. The `dnr.exe` worker path never sees it — the
worker constructs its own `-"<tempfile>"` command line after the
download completes, matching DNR's parser.

## 8. Plug-in hand-off

### 8.1 `HrGetPMtn` @ `0x7F3FB546` — the gateway

Every resolution of a wire node-id to an `IMosTreeNode*` passes through
here. Pseudo-code (plate comment on the function):

```c
HRESULT HrGetPMtn(_MosNodeId *node_id, IMosTreeNode **out, int allow_missing) {
    // 1. cache lookup (global node-id → IMosTreeNode*)
    node = CacheLookup(g_nodeCache, node_id);
    if (node) { *out = node; return S_OK; }
    if (allow_missing) return 1;

    // 2. plug-in DLL cache lookup (app_id → HMODULE)
    EnterCriticalSection(&g_pluginCacheCS);
    record = PluginCache_Lookup(g_pluginCache, node_id->app_id);
    if (!record) {
        // 3. demand-load the plug-in DLL
        HRMOSExtract(node_id->app_id, path, MAX_PATH);   // MCM lookup
        hmod = LoadLibraryA(path);                       // e.g. dsnav.nav
        PluginCache_Insert(g_pluginCache, node_id->app_id, hmod);
    }
    // 4. call plug-in's GETPMTN
    getpmtn = GetProcAddress(hmod, "GETPMTN");
    status = getpmtn(node_id, out);
    CacheInsert(g_nodeCache, *out);
    return status;
}
```

Error codes on failure: `0x8B0B0003` (MCM / LoadLibrary / GetProcAddress
failed), `0x8007000E` (cache insert OOM). All errors flow through
`ReportMosXErr` before returning.

Cache globals: `g_nodeCache = DAT_7F40E010`, `g_pluginCache = DAT_7F40E01C`,
`g_pluginCacheCS = DAT_7F40B088`.

### 8.2 Plug-in contract (from MOSSHELL's side)

MOSSHELL asks every NAV DLL for one export:

```c
HRESULT GETPMTN(_MosNodeId *node_id, IMosTreeNode **out);
```

The plug-in returns a freshly-allocated `IMosTreeNode`-compatible object
(the plug-in decides layout — DSNAV makes a 240-byte `CDsNavTreeNode`;
GUIDENAV makes different shapes). MOSSHELL owns the node-cache lifetime
but calls the plug-in's vtable for everything.

See `docs/DSNAV.md` §3.1 for DSNAV's `GETPMTN` implementation and
§6 for how DSNAV multiplexes further to NED editor DLLs via
`MCM!FGetNedForApp` + GETPMTE.

## 9. Collaborator DLLs

MOSSHELL imports from:

| DLL | Purpose |
|---|---|
| `TREENVCL.DLL` | Wire client: `CTreeNavClient::GetChildren/GetNextNode/GetShabby/FreeShabby`. The RPC marshal + SVCPROP-record walker. |
| `SVCPROP.DLL` | Per-child record decoder: `FDecompressPropClnt` + `CServiceProperties::FGet/FInit`. |
| `MCM.DLL` | Plug-in registry: `HRMOSExtract` (app_id → filename), `HRMOSExec` (app-specific launcher), `FGetNedForApp` (NED ordinal lookup). Both `HRMOSExec` and `HRMOSExtract` exist in MOSSHELL as 6-byte thunks at `0x7F4077DA`/`0x7F4077D4`. |
| `MOSMISC.DLL` | Misc utilities (referenced by string). |
| `MOSCUDLL.DLL` | `FMergeMenus`, `HMenuSubFromId` — shell-standard menu builders. Also referenced by plug-ins (DSNAV §1). |
| `USER32.DLL` | `LoadMenuA`, `InsertMenuA`, `SendMessageA`, `GetWindowLongA`, … — standard Win32 UI. |
| `KERNEL32.DLL` | `LoadLibraryA`, `GetProcAddress`, `CreateFileA`, `EnterCriticalSection`, temp-path helpers. |
| `SHELL32.DLL` | `ExtractIconExA`. The only SHELL32 call used by the icon path. |
| `COMCTL32.DLL` | `ImageList_ReplaceIcon`, `ImageList_Remove` (CacheNodeIconsIntoImageLists). |
| `GDI32.DLL` | `LoadImageA`, `GetEnhMetaFileA`, `PlayEnhMetaFile` (banner). |

MOSSHELL exports consumed by plug-ins (see DSNAV §1 imports for the full
list): the `CMosTreeNode` vtable thunks (ords `0x30-0x7F`, `0x91-0x94`),
`NtniGroup` lifecycle (`InitializeNtnigr`, `CleanupNtnigr`,
`HrDisconnectNtnigr`), shell-wide refresh (`EnumMosWindows`, `RefreshEmw`),
the column-loader `RgmdsFromRcdata`, the error dispatcher `ReportMosXErr`,
and the tree-node ctor `CMosTreeNode::CMosTreeNode(_MosNodeId*, _NtniGroup*)`.

## 10. Registry & on-disk state

### 10.1 Registry keys read

| Key | Role |
|---|---|
| `HKLM\SOFTWARE\Microsoft\MOS\Directories` | Shabby-icon cache root / service data dirs. |
| `HKLM\SOFTWARE\Microsoft\MOS\Mosxapi` | MOSX API registration (referenced near tag `'osxapi'` at `0x7F40E1E0`). |
| `HKLM\SOFTWARE\Microsoft\MOS\Preferences` | `SingleWindowMode` and other user prefs (`FGetPreferenceBool`). |
| `HKLM\SOFTWARE\Microsoft\MOS\Streams` | Persisted CMosTreeNode property streams (advanced cache). |
| `HKLM\SOFTWARE\Microsoft\MOS\Favorite Places` | MFP store (covered by GUIDENAV). |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FindExtensions` | Shell-view "Find..." integration. |
| `HKLM\SOFTWARE\Microsoft\MOS\Applications\App #<n>` | Read by `HRMOSExtract` (via MCM) to resolve app_id → NAV filename. |

### 10.2 On-disk state

- **`MOSPMTN.DAT`** (strings at `0x7F40E8E8` ANSI, `0x7F41C4E4` UCS-2) —
  persisted node-cache serialization. Exact format not covered here;
  opened by `CMosTreeNode::LoadMosPmtn` / `SaveMosPmtn` (named exports).
- **Shabby cache** — directories from `MOS\Directories`; filenames built
  by `BuildShabbyCachePath` @ `0x7F405211` using the `%08X:%04X` template
  at `0x7F40EB74` (content-id : service-id).
- **Temp files** — created per-icon-extract under `GetTempPathA` with the
  "MSN" prefix (`0x7F40EA80`), always `DeleteFileA`'d after extraction.
- **Plug-in DLLs** — `.NAV` / `.NED` — loaded from paths returned by MCM's
  `HRMOSExtract`, demand-loaded by `HrGetPMtn` and cached per-app.

## 11. Cross-check — server emission vs MOSSHELL reads

Complete table is in `docs/DSNAV.md` §14.2. MOSSHELL-specific notes:

- `'e'` must be type **0x0A**. 0x0B truncates to "M" because SVCPROP stores
  the raw UTF-16 temp buffer in the cache and the ANSI readers (both
  `GetDisplayNameOf` and the titlebar paint path) stop at the first wide
  NUL. Server is correct at `src/server/services/dirsrv.py :: build_props`.
- `'mf'` and `'wv'` must be type **0x03 DWORD** (inline). A 0x0E blob puts
  a heap pointer in the cache slot and the low 4 bytes of the pointer
  become the shabby_id — this was the "0x00BE0400 garbage" symptom chased
  across multiple sessions. Fixed.
- `'h'` must be type **0x03 DWORD** (ICO shabby_id). Missing → forbidden
  glyph; wrong type → random id, download fails, forbidden glyph anyway.
- `'b'` is a **single byte**. `DIRSRV_BROWSE_FLAGS_CONTAINER / _LEAF` in
  `src/server/config.py` must agree with §7.1: bit 0 clear = folder, set
  = leaf.
- Column-descriptor tags (`tp`, `p`, `w`) are consumed by DSNAV, not
  MOSSHELL directly; see DSNAV §10 and §14.2 for the current mismatch list
  (`tp`/`p`/`w` are emitted as 0x0E but should be 0x0A/0x03/0x03).

## 12. Ghidra annotations shipped in this pass

Live changes in session `ff98dba06705481b93229137d27cca66` on `/MOSSHELL.DLL`:

Renamed functions (plate comments on each):

| Addr | New name | Section in this doc |
|---|---|---|
| `0x7F3F24D9` | `CanonicalizePidlSpecialAlias` | §5.5 |
| `0x7F3F270A` | `HrResolvePidlAndWaitChildren` | §5.5 |
| `0x7F3F5406` | `IMosShellView_OnCommand` | §7.2 |
| `0x7F3FB14B` | `CMosEnumIDList_ctor` | §5.1 |
| `0x7F3FB199` | `CMosEnumIDList_Init` | §5.2 |
| `0x7F3FB27F` | `CMosEnumIDList_Next` | §5.3 |
| `0x7F4047C2` | `CacheNodeIconsIntoImageLists` | §6.2 |
| `0x7F4049F9` | `FetchShabbyIconToTempAndExtract` | §6.2 |

Already-annotated functions cross-referenced (not re-renamed):
`HrGetPMtn`, `HrGetPMtnFromPIdl`, `HrBrowseObject`, `HrExecCommand`,
`CMosShellFolder::EnumObjects`, `CMosShellFolder::GetDisplayNameOf`,
`CMosTreeNode::GetShabbyToFile`, `CMosTreeNode::GetHbmpForPMtn`,
`LoadShabbyIconForNode`, `BuildShabbyCachePath`, `CMosTreeNode::ExecuteCommand`
(4-arg), `CMosViewWnd::ExecuteCommand` (2-arg).

## 13. Out of scope / known gaps

Called out deliberately — these were left for follow-up passes:

- **`CDIBWindow` banner paint internals** — StretchBlt/BitBlt dispatch,
  palette handling, and GDI state are untouched. DSNAV §11.1 notes the
  single-slot subclass; the full base class has more virtuals.
- **`CMosViewWnd` listview plumbing** — aside from context-menu/toolbar
  bootstrap and the IDM dispatch in §7.3, the listview-notification
  handlers (LVN_GETDISPINFO, LVN_COLUMNCLICK, custom-draw) are not
  documented here.
- **`CMosTreeEdit`** — in-place rename edit control.
- **`CPlayMeta`** — audio/video metadata (3 exports).
- **`CMosXAllocator` internals** — the shell allocator's free-list /
  slab layout.
- **Properties `'l'`, `'i'`** — advertised by DSNAV, no MOSSHELL read
  site confirmed. Server emits safe defaults.
- **The exact vtable-slot ↔ method-name map** for slot numbers not hit by
  any of the decompilations surveyed here. Ghidra ords `0x30-0x94` on
  `CMosTreeNode` identify ~100 slots, but only the ~25 enumerated in §3.1
  are tied to code paths in this pass.
- **`MOSPMTN.DAT` format** — file is opened by named MOSSHELL exports but
  its serialization format wasn't decompiled in this pass.
- **`CMosShellFolder::BindToObject`** — wire-firing path is only
  documented by delegation (§5.4); the function itself isn't walked
  line-by-line here.
- **Favorite Places (`MFP_*`)** — covered by `docs/GUIDENAV.md`.

The deliberate focus here was the minimum call graph a future NAV plug-in
RE needs: node shape, property ABI, enum + bind split, render (label +
icon), and dispatch. Everything else is cleanly separable.
