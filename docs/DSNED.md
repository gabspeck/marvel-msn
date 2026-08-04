# DSNED.NED — node editor + the DIRSRV Properties sheet

Reverse-engineering notes for `binaries/DSNED.NED`, the `App #18 DSED`
node-editor plug-in, and for the property-sheet machinery in MOSSHELL that it
extends. Together these decide every field the user sees when they open
Properties on a DIRSRV node, which of those fields are editable, and what each
one reads and writes.

Sources: static resource dumps plus decompilation against the MSN95 Ghidra
project. DSNED addresses are at image base `0x7F570000`; MOSSHELL at
`0x7F3F0000`; SACLIENT at `0x7F340000`; TREEEDCL at `0x7F2C0000`.

Companions:

- `docs/DSNAV.md` — the read-side navigator DSNED pairs with.
- `docs/MOSSHELL.md` — `CMosTreeNode` ABI and property cache.
- `PROTOCOL.md` §7.2 — DIRSRV / TREEEDCL wire selectors.

## 1. Identity

- PE DLL, 36 KiB, version 1.60.0, `FileDescription` "Microsoft Network
  Directory Service Node Editor".
- Exports `GETPMTE` [12] and `DISCONNECT` [11], plus the three
  `CDirSrvTreeEdit` virtuals it overrides at class level:
  `GetPropertyDispatch` [10], `FormatSizeString` [9], `FillSPForNewNode` [8].
- Statically imports MOSSHELL (`CMosTreeEdit` base class), SVCPROP
  (`CServiceProperties`), MCM (`MosError`), MOSCUDLL (`HrSzForByteCount`),
  COMCTL32 (`CreatePropertySheetPageA`) and COMDLG32 (`GetOpenFileNameA`).
- Help file for every page it owns: `forummgr.hlp`.

## 2. How the editor is reached

`CMosTreeNode::HrGetPMte` is vtable slot 72 (`+0x120`). MOSSHELL's base
returns `E_NOTIMPL`; `CDsNavTreeNode` overrides it at DSNAV `0x7F58185D`:

1. `GetProperty("c", &app_id, 4)` — the node's wire `c` property.
2. `DSNAV_LoadAppPluginNode` → `MCM!FGetNedForApp(app_id)` → registry
   `App #<id>\Node Editor App #` → `HRMOSExtract` → `LoadLibraryA` →
   `GetProcAddress("GETPMTE")`.
3. `GETPMTE(app_id, …, &pMte)`; the result is cached at node `+0xBC`.

So **wire `c` selects the editor class**, and with it the whole per-type
behaviour of the sheet.

### 2.1 GETPMTE type table

`GETPMTE` @ `0x7F57109E` switches on `app_id` and stamps one of eight vtables.
Per-type strings come from DSNED's STRINGTABLE.

| `c` | vtable | "New …" (id) | Type string (id) | Extra page | `HrSupportsPricing` |
|-----|--------|--------------|------------------|-----------|---------------------|
| 0 | `0x7F576008` | base | base | — | S_FALSE |
| 1 | `0x7F576080` | New Folder (102) | Folder (120) | Banner (0x69) | S_FALSE |
| 2 | `0x7F576260` | New Bulletin Board Folder (106) | Bulletin Board Folder (124) | — | S_FALSE |
| 3, 5 | — | — | — | `E_NOINTERFACE` | — |
| 4 | `0x7F5760F8` | New Chat Room (103) | Chat Room (121) | Conversation (0x64) | S_FALSE |
| 6 | `0x7F5761E8` | New Media Viewer Title (105) | Media Viewer Title (123) | Media Viewer (0x68) | S_FALSE |
| 7 | `0x7F576170` | New Download-and-Run File (104) | Download-and-Run File (122) | Download and Run (0x67) | **S_OK** |
| 0xB | `0x7F5762D8` | New Microsoft Encarta Viewer (107) | Microsoft Encarta Viewer (125) | — | S_FALSE |
| 0xC | `0x7F576350` | New Microsoft Bookshelf Viewer (108) | Microsoft Bookshelf Viewer (126) | — | S_FALSE |

A **category is `c` = 1** — the Folder editor.

### 2.2 CMosTreeEdit vtable slots used here

Derived from the import-name order and confirmed against the three exported
overrides plus `AddPropPages`' call to `+0x20`:

| Offset | Method |
|--------|--------|
| `+0x10` | `SetProperty` |
| `+0x14` | `GetPropertyDispatch` |
| `+0x20` | `AddNedPropPages` |
| `+0x24` | `FormatSizeString` |
| `+0x28` | `GetNewObjectName` |
| `+0x2C` | `GetNewObjectType` |
| `+0x34` | `FillSPForNewNode` |
| `+0x38` | `GetFlagsForNewNode` |
| `+0x3C` | `GetShidIcon` |
| `+0x54` | `HrSupportsPricing` |

## 3. Page assembly

`CMosTreeNode::Properties` @ MOSSHELL `0x7F3FEF12` reads `e` for the caption,
calls `HasRights`, then `AddPropPages` @ `0x7F3FF0AA` on a worker thread.

`HasRights` @ `0x7F3FF99E` reads wire `x` as a DWORD and returns `S_OK` when
**any** requested bit is set, `S_FALSE` when none is. `Properties` passes
`(HasRights == S_OK)` down as the edit flag.

`AddPropPages` then:

1. In edit mode, `LoadLibraryA("saclient.dll")` and resolve
   `CreateSysAdminClient`, `CreateSysAdminMasterTokenList`,
   `CreateSysAdminToken`. A miss aborts the **whole sheet** with
   `0x8B0B0003`.
2. Create exactly **two** pages from a table — `0x7F40E8A8` read-only,
   `0x7F40E8C0` edit. Each entry is `[u16 template][u16 pad][DLGPROC][callback]`.
3. In edit mode, when node `+0xBC` holds an editor: call
   `CMosTreeNode::AddSecurityPropSheet` (vtable `+0x134`, `0x7F3FF2B1`) to
   append the Security page from `0x7F40E8D8`, then the editor's
   `AddNedPropPages` (`+0x20`) for the plug-in's own pages.

Resulting tab order for a category: **General, Context, Security, Banner**.

| Mode | Template | Title | DlgProc |
|------|----------|-------|---------|
| read-only | 0x65 | General | `0x7F401ACE` |
| read-only | 0x66 | Context | `0x7F402507` |
| edit | 0x65 | General | `0x7F401ACE` |
| edit | 0x67 | Context | `0x7F402507` |
| edit | 0x68 | Security | `0x7F402E7B` |

The two modes share one General template and hide the half they do not want
(`ShowWindow(SW_HIDE)` over a NUL-terminated control-id list): read-only hides
the edit controls (`0x7F40E918`), edit hides the statics **and the Price
label/value pair 1015/1016** (`0x7F40E948`).

## 4. General page (MOSSHELL dialog 0x65)

Property group requested up front (`0x7F40E8F8`): `e, j, k, ca, tp, z, o`.

Population is `0x7F400B1C`; it runs only if `HrGetPMte` succeeds, so a node
with no registered editor shows an empty General page.

| Field | Static id | Edit id | Tag | Read as |
|-------|-----------|---------|-----|---------|
| Name | 1002 | 1003 | `e` | GetPropSz |
| Go word | 1005 | 1006 | `k` | GetPropSz |
| Category | 1008 | 1009 | `ca` | GetPropSz |
| Type | 1011 | — | `tp` | GetPropSz (never editable) |
| Rating | 1013 | 1014 (combo) | `o` | GetProperty DWORD |
| Price | 1016 | — | `z` | GetProperty DWORD |
| Currency | — | 1020 (combo) | `z` low byte | GetProperty DWORD |
| Amount per use | — | 1022 | `z` >> 8 | GetProperty DWORD |
| Description | 1023 (RO edit) | 1024 | `j` | GetPropSz |

Fallbacks when a tag is missing or empty: Go word → string 0xBE `<none>`,
Type → 0xBF `<unknown type>`, Rating → 0xD0 `Not rated`, `z` → `0xFF` (no
currency).

Rating combo rows are strings 0xCD–0xD0; the stored value is `index + 1`, and
only 1–4 are treated as valid.

The currency combo is filled from `g_rgISOCurrencyCodes` (19 entries, stride
0x10) through `LoadCurrencyName`; the item data is the row index, which is
what lands in `z`'s low byte.

### 4.1 Why Currency and Amount per use are disabled

At `0x7F400B70`:

```c
if (pMte->HrSupportsPricing(pMte) != 0)      /* vtable +0x54 */
    DisableControls(hwnd, {1019, 1020, 1021, 1022});
```

`CMosTreeEdit::HrSupportsPricing` @ MOSSHELL `0x7F403D34` is
`return 1;` — S_FALSE, "does not support pricing". Only DSNED's `c` = 7
(Download-and-Run) overrides it, at `0x7F572263`, with `return 0;`.

So for a category (`c` = 1) the two pricing controls are **always** disabled.
It is a hard-coded, per-node-type client rule keyed on `c` — no wire property
and no server flag participate. Serving a non-zero `z` still fills the fields;
they just stay greyed. The only way to get editable pricing is a node whose
`c` is 7, which also changes its type string, icon and NED page.

### 4.2 Validation and apply

`PSN_KILLACTIVE` → `0x7F400F60`, `PSN_APPLY` → `0x7F4010A3`.

Writes go through `CMosTreeNode::SetPropertyIfChanged` (vtable `+0x130`),
which skips the wire entirely when the value is unchanged. Order and wire
types are in `PROTOCOL.md` §7.2.10.

`k` is written first and its failure is special-cased: `0x8B0B003C` produces
"Go word in use" (string 0xD4) and refocuses the field. Everything else goes
through `ReportMosXErr`.

`z` is written **only when the Amount edit is non-empty**, assembled as
`(currency_index & 0xFF) | (amount << 8)` after `FParseAmount`.

Error strings the page can raise: 0xD2 name required, 0xD3 currency required,
0xD5 whole number required, 0xD6 too many decimals, 0xD7 number required.

## 5. Context page (dialogs 0x66 read-only / 0x67 edit)

Property group (`0x7F40E988`): `q, r, s, t, u, n, y, on, v, w, p`.
(`u` is fetched but no control consumes it.)

Population is `0x7F401D81`.

| Field | RO id | Edit id | Tag | Notes |
|-------|-------|---------|-----|-------|
| Language | 102 | 103 (listbox) | `q` | rows from `MCM!FGetRglcidBrowse`, item data = LCID, multi-select |
| Topics | 105 | 106 | `r` | |
| People | 108 | 109 | `s` | empty → string 0xC1 `Everyone` in RO mode |
| Place | 111 | 112 | `t` | empty → string 0xC3 `The world` in RO mode |
| Forum manager | 115 | 114 | `n` | empty → 0xC0 `None` in RO mode |
| Owner / Vendor name | 129 | 129 (static) | `on` | never typed into; RO label is "Owner:", edit label is "Vendor name:" |
| Vendor ID | — | 121 | `y` | `SetDlgItemInt`, signed |
| Created | 123 | 123 | `v` | |
| Last changed | 125 | 125 | `w` | |
| Size | 127 | 127 | `p` | empty → 0xC4 `N/A` |

### 5.1 The `y` / SACLIENT coupling

In **edit mode only**, immediately after reading `y`:

```c
if (GetProperty(node, "y", &vendor_id, 4, 0) >= 0) {
    client = CreateSysAdminClient(4, 0);
    if (!client || client->status != 0) { MosError(0xDE); return FALSE; }
}
```

String 0xDE is "Cannot display Context page." The check fires on a *successful
read of `y`*, whatever its value — including 0. A server that omits `y`
entirely skips the branch and the page loads; a server that sends `y` makes
the page depend on the SASRV pipe opening.

Typing into the Vendor ID box runs `0x7F402151`, which additionally calls
`client->vtbl[0x28](vendor_id, buf)` to resolve the member and fills static
129 with "first last". Failure paths: 0xE1 non-numeric, 0xDF client
unavailable, 0xE2 unknown owner id.

`PSN_APPLY` is `0x7F4022AE`; it packs the listbox's selected LCIDs into a
type-0x10 `[count][lcid…]` array for `q` and writes the rest as listed in
`PROTOCOL.md` §7.2.10.

## 6. Security page (dialog 0x68) — needs the SASRV service

Added by `CMosTreeNode::AddSecurityPropSheet` @ `0x7F3FF2B1`. Controls:
"Token name" combo 102 and "Exclude…" button 106.

`WM_INITDIALOG` is `0x7F4026D3`:

1. `CreateSysAdminClient(4, 0)`. NULL or non-zero status → `MosError(0xDB)`
   "Cannot display Security page." and the page gives up.
2. `GetProperty(node, "m", &token_id, 4, 1)` — wire **`m`** is the node's
   token id.
3. `CreateSysAdminMasterTokenList(client)` → `list->Fetch(10)` →
   `GetCount(&n)` → `GetItem(i, &id, name, 260)` for each row; the row whose
   id equals `m` is preselected.

`CreateSysAdminClient` @ SACLIENT `0x7F3410B2` builds the object at
`0x7F3410F1`: `CoCreateInstance` on the MPC connection, `Initialize`, then
`OpenService("SASRV", <29-IID table @0x7F347570>, &pipe, version=4, 0)`.
Discovery alone is enough for this call to succeed — which is why the Context
page's `y` check passes while the Security page still fails one step later, at
the token enumeration.

Token enumeration is three SASRV selectors on the client object's vtable
(`0x7F347748`):

| Slot | Selector | Purpose |
|------|----------|---------|
| `+0x04` | 2 | begin enum: send `list_kind`(=10 for tokens), DWORD, blob; receive status + count |
| `+0x0C` | 4 | read enum results into the caller's buffer |
| `+0x10` | 5 | fetch one page: send start index, DWORD, WORD; receive status + dynamic blob |

The page blob is a packed run of `[u32 token_id][ASCIIZ name]` records,
`4 + strlen + 1` bytes each, cached 20 to a page in 0x68-byte slots (name
capped at 0x5C bytes) — `0x7F343973`.

Other Security strings: 0xB5 "Token change not valid.", 0xD8 "Token not
valid.", 0xDC/0xDD "Cannot verify token.", 0xE5 "Token already open.".

## 7. DSNED's own pages

`AddNedPropPages` (vtable `+0x20`) chains to the MOSSHELL base and then
appends one `PSP` with `PSP_USECALLBACK`.

| `c` | Template | Title | Adder |
|-----|----------|-------|-------|
| 1 | 0x69 | Banner | `0x7F571582` |
| 4 | 0x64 | Conversation | `0x7F571C5C` |
| 6 | 0x68 | Media Viewer | `0x7F5727B0` |
| 7 | 0x67 | Download and Run | `0x7F572277` |

### 7.1 Banner (0x69) — the page a category gets

`WM_INITDIALOG` `0x7F57167B`: `GetProperty("mf", &shabby_id, 4)`, then
`GetShabby` through node vtable `+0x80`, then `StretchBlt` with
`HALFTONE` into a bitmap handed to static 102 via `STM_SETIMAGE`. A failed
`mf` read leaves the preview empty and the page otherwise usable.

"Change Banner…" is `0x7F5717C8`: `GetOpenFileNameA` filtered to
`*.bmp;*.emf;*.wmf;*.mtf`, extension → format byte (`.emf` 1, `.mtf` 3,
`.wmf` 4, `.bmp` 5), `CreateFileMapping`/`MapViewOfFile`, then node vtable
`+0x138` `AddShabby(format, data, size, &shabby_id)` followed by
`SetProperty("mf", 0x0F, &shabby_id, 4)` and `SetProperty("p", 0x03, &size, 4)`.
Rejections: string 0x132 wrong extension, 0x138 empty file.

### 7.2 Conversation (0x64)

Room capacity edit 102, message length edit 105, "join as participants"
checkbox 107. Validation strings 0xC8–0xCD bound capacity to 2–10,000 and
message length to 50–1000.

## 8. Creating nodes

`GetFlagsForNewNode` (`+0x38`) returns the `b` byte for a new child — `0` for
`c` = 1 (container), `1` for `c` = 7 (leaf).

`CDirSrvTreeEdit::FillSPForNewNode` @ `0x7F571305` seeds the
`CServiceProperties` record that `CTreeEditClient::AddNode` (class 0x04,
selector 0x02) uploads. `q` is stored as a type-0x10 counted DWORD array;
`CServiceProperties::FSet` requires `length == count * 4 + 4`, and a
mismatch surfaces as `E_OUTOFMEMORY` from DSNED.

`CDirSrvTreeEdit::GetPropertyDispatch` @ `0x7F5712EA` returns `1` for every
property name, which pins all DIRSRV writes to TREEEDCL selector 0x04.

## 9. Property-name vocabulary

DSNED's own table at `0x7F577188`: `tp t s r l n j k mf h mm ml ds q o ca m f
b g c p`, plus `fn zc fi i _F` further on. `m`, `mm`, `ml`, `ds`, `fn`, `zc`
and `fi` have no consumer in the property sheets covered here — `m` is the
Security token id (§6); the rest are unresolved.

Service names DSNED knows: `DIRSRV`, `CONFLOC`, `MEDVIEW`, `BBS`.

## 10. Open questions

- The `mm` / `ml` / `ds` / `fn` / `zc` / `fi` tags: no observed reader.
- SASRV selector 2/4/5 argument marshalling is read off the decompiler's
  shifted stack frames and has not been checked live.
