# GUIDENAV.NAV

Reverse-engineering notes for `binaries/GUIDENAV.NAV`, the `App #3
Guide_Service` navigator plug-in.  Purpose of this writeup: describe the
plug-in's shape precisely enough that the server team knows what (if anything)
the server must send to make the MSN Central welcome surface and the Favorite
Places list behave correctly.

Sources: static binary (`objdump`, `winedump`, `wrestool`) plus live
decompilation against the MSN95 Ghidra project.

> Note: unlike `DSNAV.NAV`, GUIDENAV does **not** use `TREENVCL.DLL`.
> The welcome screen + Favorite Places list are served from a
> client-local HOMEBASE / MFP store. See `docs/TREENVCL.md` for the
> RPC client that DSNAV (and BBSNAV) use instead.

## 1. Identity

- PE DLL, 40 KiB, link-time 1995-06-30, image base `0x7F510000`.
- Version resource: `FileDescription = "MSN Central Navigator"`,
  `InternalName = GUIDENAV`, `ProductName = The Microsoft Network`.
- Registered as `App #3 Guide_Service` in `HKLM\Software\Microsoft\MOS\
  Applications\App #3` with `Filename = guidenav.nav` and `Node Editor
  App # = 0x1C` (pairs with DSed/App #28-style editor stub; no dedicated
  `guideed` ships).
- Exports **only** two named entries, matching the thin NAV plug-in
  contract used by MOSSHELL:
  - `GETPMTN` (ordinal 2, RVA `0x1391`)
  - `DISCONNECT` (ordinal 1, RVA `0x1434`)
- Imports from `MOSSHELL.DLL` include the full `CMosTreeNode` virtual
  vtable, `HrGetPMtn`, `MFP_GetCount/FGetNth/GetFolderCount/Delete`,
  `RgmdsFromRcdata`, `HrSaveResIconToFile`. Also `MCM!LoadAndCallW`,
  `MOSMISC!FGetRegistrySz/FGetPreferenceBool`, `OLEAUT32!
  RegisterActiveObject` with moniker `ShellAuto`.

GUIDENAV does **not** link against `TREENVCL.DLL` or `SVCPROP.DLL` — unlike
DSNAV, it never consumes DIRSRV wire properties.

## 2. How the shell reaches it

MOSSHELL's `HrGetPMtn(_MosNodeId*, IMosTreeNode** out, int flags)` is the
canonical entry to the tree.  When the mnid it is asked about belongs to the
Guide service it `LoadLibrary`s `guidenav.nav`, resolves `GETPMTN`, and calls
it with the mnid.  The typical entry path is **client-local**: HOMEBASE
`JUMP`/`LJUMP` clicks in the MSN Central home screen (`HOMEBASE.DLL` RCDATA,
see `docs/MSN_CENTRAL_HOMEBASE_MENU_MAPPING.md`).  DIRSRV nodes do not
normally target `app_id = APP_GUIDE_SERVICE` — the server never needs to
construct one.

## 3. Plug-in contract

### 3.1 `GETPMTN(_MosNodeId* mnid, IMosTreeNode** out_node) -> HRESULT`

Decomp at `7F511391`.  Two branches, selected by inspecting offsets 8 and
12 of the shell's in-memory `_MosNodeId` wrapper (MOSSHELL passes a struct
larger than the 8-byte wire mnid — the upper dwords are shell context):

1. **Welcome-screen root** (both dwords zero):
   - Allocate a 240-byte `CMosTreeNode` subclass (ctor `FUN_7F511051`,
     vtable `0x7F516858`).
   - Ensure the process-global welcome-screen state exists by allocating
     a 816-byte record `DAT_7F517008` and calling
     `LoadHomebaseMenuTable` to populate it.
2. **Non-root** (any other mnid):
   - Allocate a 520-byte `CMosTreeNode` subclass (ctor `FUN_7F511B3F`,
     vtable `0x7F516A58`).
   - Cache `LoadString(128)` ("Favorite Places") at instance offset
     `0xF8` as the shell display title.

Both branches `AddRef` via `vtable[1]` before returning `*out_node`.  A
failure to construct returns `0x8007000E` (E_OUTOFMEMORY mapped).

### 3.2 `DISCONNECT() -> HRESULT`

Decomp at `7F511434`.  No-op stub (`return 0;`).  Present for the shell's
plug-in lifecycle parity; GUIDENAV owns no long-lived connection resources.

## 4. Welcome-screen rendering pipeline

### 4.1 `LoadHomebaseMenuTable` at `7F5123CE`

Resolves the HOMEBASE source file:

1. `FGetRegistrySz(HKLM, "Software\Microsoft\MOS\Directories", "MOSBin",
   path, 260)` → path prefix.
2. `lstrcat(path, "\")` (constant at `7F517104`).
3. `FGetRegistrySz(HKCU, "Software\Microsoft\MOS\Preferences",
   "HomebaseFile", path_tail, remaining)`; on miss
   `lstrcpy(path_tail, "HOMEBASE.DLL")`.
4. `LoadLibraryA(path)` on the resulting file.

Loads the menu table:

5. `FindResourceA(hmod, "HOMEBASE", RT_RCDATA=10)` →
   `LoadResource` → `LockResource`.
6. First WORD is the entry count `N` (capped at 10 — the final
   allocation budget).
7. For each entry:
   - `label_sid`, `x1`, `y1`, `x2`, `y2`, `command_sid` (six WORDs).
   - `LoadStringA(label_sid)` into the entry's label buffer
     (up to 32 bytes); strip `&` and remember the accelerator character.
   - `LoadStringA(command_sid)` into a scratch buffer.
   - Split on the first space; match the verb against the table
     `{EMAIL=0, JUMP=1, LJUMP=2}` (string pointer array at
     `7F517090`).  Unknown verb → fail the whole load with `0x8007000E`.
   - For `JUMP`/`LJUMP` (1/2) the tail must exist and be parseable;
     `SzToMnid(tail, &entry.mnid)` fills the entry's 8-byte
     `_MosNodeId`.  `EMAIL` (0) tolerates a missing tail and does not
     populate an mnid.
8. `LoadImageA(hmod, "HOMEBASE", 0, 0, 0, LR_DEFAULTCOLOR|…=0x3000)`
   loads the accompanying `BITMAP` resource and caches the HBITMAP at
   `menu_table[0xCA]` (byte offset 808).

Record layout (80 bytes, one per menu entry), confirmed from the
hit-tester `FUN_7F51278D` and the action dispatcher `7F5127E5`:

| Offset | Size | Field                                             |
|-------:|-----:|---------------------------------------------------|
| `0x00` |   32 | Label text (ANSI, `&` stripped in place)          |
| `0x20` |    1 | Accelerator character (post-`&`)                  |
| `0x24` |    4 | Verb index: `0=EMAIL`, `1=JUMP`, `2=LJUMP`        |
| `0x28` |   16 | `RECT {x1, y1, x2, y2}` on the HOMEBASE bitmap    |
| `0x38` |    8 | `_MosNodeId` (wire mnid; valid only when verb≥1)  |

Menu table header: `menu_table[0] = count`, `menu_table[1] =
jump_count (verbs 1/2 with a parsed mnid)`, `menu_table[0xCA] = HBITMAP`.

### 4.2 Input dispatch

- **Mouse**: `FUN_7F51278D(this, x, y, &entry)` walks the record array and
  returns the entry whose `RECT` contains `(x,y)`.  `FUN_7F512955` wraps
  the hit-test and hands the entry to `ExecuteHomebaseEntryAction`.
- **Keyboard**: `FUN_7F51298A(this, char, browser)` scans for an entry
  whose accelerator char (offset `0x20`) matches and dispatches the same
  way.

`ExecuteHomebaseEntryAction` at `7F5127E5`:

- Verb `1` (`JUMP`) or `2` (`LJUMP`): `ResolveHomebaseEntryNode(entry)`
  calls `HrGetPMtn(entry.mnid)`, then:
  - `JUMP` → invoke `IMosTreeNode::ExecuteCommand(0x3000, 0, 1,
    browser)` on the resolved node (vtable `+0xF4`, slot 61).
  - `LJUMP` → unwrap one child via `vtable +0xC8` on the resolved
    node (localized-node/real-node accessor), release the parent, and
    run `ExecuteCommand(0x3000, …)` on the child.
- Any other verb (in practice: `EMAIL` = 0) → `MCM!LoadAndCallW(3,
  "MOSX_GotoMosLocation", 2)` — dynamic call into `CCAPI.DLL` to run
  the dedicated launcher path.  This matches existing memory:
  `project_msn_central_email_dispatch`.

Command id `0x3000` is the shell-wide "navigate/activate" verb already
documented in `project_msn_central_icon_dispatch`.

### 4.3 Paint

`FUN_7F512B28(hwnd)`:

1. `SystemParametersInfoA(SPI_GETKEYBOARDCUES=0x46, …, &show_accel)` —
   honours the "underline accelerators" UI setting.
2. `GetDC(hwnd)` → for each menu entry, `FUN_7F512A36(menu_table, i,
   &x, &y, text, 260)` yields the draw position and the label text,
   then `ExtTextOutA(hdc, x, y, ETO_CLIPPED, &rect, text, len, NULL)`.
3. Bitmap itself is painted elsewhere (`StretchBlt` or `BitBlt` — not in
   this helper); what matters here is that labels overlay the cached
   `HBITMAP` as live text, so localization stays in the HOMEBASE string
   table rather than baked into the bitmap.

## 5. Favorite Places (non-root `CMosTreeNode` subclass)

The 520-byte class at vtable `0x7F516A58` is the Favorite Places list
surface.  Key evidence:

- Ctor caches `"Favorite Places"` (string id 128) at instance
  offset `0xF8` as the shell display title.
- `GetDetailsStruct` override at `7F511F87`:
  - First delegates to the "real" underlying node via its own
    `vtable +0x18` (the real-node / localized-node accessor); if that
    returns one, it forwards to that node's `GetDetailsStruct`
    (`vtable +0x70`) so the per-item columns come from whatever
    service actually owns the favorite (usually DIRSRV).
  - Fallback: `RgmdsFromRcdata(hmod, 1000, &col_count)` loads GUIDENAV's
    own `RCDATA` resource id `1000` as the default column descriptor
    (headers `&Name`, `&Type`, `Si&ze`, `&Date Modified`, from string
    table block 63).
- List enumeration uses `MOSSHELL!MFP_GetCount`, `MFP_FGetNth`,
  `MFP_GetFolderCount` (MFP = MosFavoritePlaces).  The MFP store is
  entirely client-side; no wire traffic.
- Delete routes through `MFP_Delete` with the confirmation string
  `"Delete this item?##Are you sure you want to remove '%s' from your
  Favorite Places list?"` (string id 131 — the `##` is the title/body
  separator used by `MessageBox` wrappers elsewhere in the shell).
- Context-menu verbs: `&Open`, `&Explore`, `&Delete`, `P&roperties`
  (menu resource id 128).  Standard shell verbs — the plug-in does not
  add service-specific commands.

Fallback placeholder `"(Item not valid)"` (string id 132) is used when
MFP hands out a stale or unresolvable mnid.

## 6. DIRSRV node-shape expectations

GUIDENAV is reached through client-local HOMEBASE JUMPs and the
client-local MFP store, so **no DIRSRV node with
`app_id = APP_GUIDE_SERVICE` is required for it to function**.
Confirmed by the imports: GUIDENAV does not link `TREENVCL`/`SVCPROP`
and never reads DIRSRV properties (`e`/`n`/`d`/`y`/`t`/`u`/`h`/`p`/`c`/
`b`/`a` — none of these token names appear anywhere in the binary).
All display text for the welcome screen comes from `HOMEBASE.DLL`
string tables, and the Favorite Places list is populated from
`MOSSHELL!MFP_*` (client registry/disk).

If the welcome screen were exposed as the child of a DIRSRV container,
the minimum wire shape would be:

- `app_id = APP_GUIDE_SERVICE` (3) so the shell routes to GUIDENAV.
- A valid 8-byte `a` mnid; the content-specific props (`e`, `n`, `d`,
  `y`, `c`, `b`) would be ignored by the plug-in.
- The shell's in-memory `_MosNodeId` wrapper's upper 8 bytes drive the
  root vs Favorite Places branch at GUIDENAV `GETPMTN`; the wire
  doesn't influence those, so the branch choice would depend on how
  MOSSHELL's routing wraps the mnid. For the observed navigation
  flows this has not mattered in practice.

## 7. Comparison to the other NAV plug-ins

| Plug-in       | Size    | Role                                    | Consumes DIRSRV props? |
|---------------|--------:|-----------------------------------------|-----------------------:|
| `GUIDENAV.NAV`| 40 KiB  | MSN Central welcome + Favorite Places   | No                     |
| `DSNAV.NAV`   | 31 KiB  | Directory Service listings (`CMosTree…`)| Yes                    |
| `BBSNAV.NAV`  | 209 KiB | Full BBS/forum UI (own tree + view)     | Yes                    |

GUIDENAV is unique among the three in that it is essentially stateless
with respect to the wire: its content is hard-wired into resource files
shipped on the client (HOMEBASE bitmap + RCDATA + string tables + local
MFP store). DIRSRV wire content does not affect what GUIDENAV renders.

## 8. Pointers for further work

- Ghidra function annotations in the MSN95 project:
  `LoadHomebaseMenuTable`, `ExecuteHomebaseEntryAction`,
  `ResolveHomebaseEntryNode` (prior passes) plus the four helpers and
  two vtables named in the 2026-04-21 pass — see §9 below.
- Ordinal-to-vtable mapping for the two installed vtables has not been
  fully resolved in this pass (21 self-override slots + ~34 thunks).
  If the shell's view-window hooks (`CMosViewWnd` block after the
  `0x00,0xFF,0xFF` separator in each vtable) become relevant, that is
  the next thing to chase.

## 9. Ghidra annotations shipped in this pass

All changes live in the MSN95 project (`MSN95.gpr`), session
`5a4d41c981bc4ea2a0e8e099a044c691` for `/GUIDENAV.NAV` (2026-04-21).
Renamed functions and labeled globals:

- Functions (4):
  - `CGuideNavFavPlaces_GetDetailsStruct` (was `FUN_7F511F87`) — the
    Favorite Places-class `GetDetailsStruct` override. Delegates to the
    real-node via vtable `+0x18`; fallback loads RCDATA 1000.
  - `PaintHomebaseLabels` (was `FUN_7F512B28`) — welcome-screen label
    paint helper. `SystemParametersInfoA(SPI_GETKEYBOARDCUES)` +
    `ExtTextOutA` over the cached HOMEBASE bitmap.
  - `HitTestHomebaseEntry` (was `FUN_7F51278D`) — mouse hit-tester on
    the 80-byte record array. `PtInRect` on `RECT` at `+0x28`.
  - `DispatchHomebaseAccelerator` (was `FUN_7F51298A`) — keyboard
    accelerator dispatcher. Walks entries, matches accel char at
    `+0x20` via `lstrcmpiA`, tail-calls `ExecuteHomebaseEntryAction`.
- Labels (2):
  - `vtbl_CGuideNavWelcomeScreen` (was `PTR_LAB_7f516858`) — root /
    welcome-screen `CMosTreeNode` vtable, 89 slots. Installed by the
    240-byte ctor `FUN_7F511051`.
  - `vtbl_CGuideNavFavPlaces` (was `PTR_LAB_7f516a58`) — Favorite
    Places `CMosTreeNode` vtable, 89 slots. Installed by the 520-byte
    ctor `FUN_7F511B3F`. Slot at `+0x70` is
    `CGuideNavFavPlaces_GetDetailsStruct`.
- Plate comments authored on every renamed function and on both
  vtables; the vtable plates enumerate the GUIDENAV-local (non-thunk)
  override addresses so future passes can reconstruct slot↔method
  mapping without re-dumping the table.

Intentionally **not** tackled: naming individual slots of either
vtable. The thunk band `0x7F512E50..0x7F512FE2` makes the
ordinal-to-slot map mechanical if anyone needs it, but without a
consumer driving the work (e.g. a WndProc hook chase) the labels would
be speculative.
