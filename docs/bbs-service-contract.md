# BBS Service Contract

The client-behaviour wire contract for the **BBS service** — the forum /
bulletin-board surface in `reference/screenshots/bbs.png` (board hierarchy,
threaded Subject/Author conversation lists, a message reader, Compose/Reply
posting). Derived entirely from static analysis of the stock Win95 client's
`binaries/BBSNAV.NAV` (the App #2 / App #10 navigator) against the MSN95 Ghidra
project. Client behaviour **is** the protocol; this document is the server's
required behaviour. No `src/server/**` references.

Companions: `docs/BBSNAV.md` (binary shape), `docs/TREENVCL.md` (read-side RPC),
`docs/BINARIES.md` §TREEEDCL (write-side RPC), `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md`
(per-record SVCPROP format), `docs/MOSSHELL.md` (the shell host).

All addresses are at BBSNAV's link-time image base `0x7F5F0000` unless prefixed
with another module.

---

## Framing

The BBS surface is **not** a dedicated message service with its own IID table
(it is *not* MEDVIEW-shaped — no bootstrap `DiscoverServiceInterfaces`, no
`class=0/sel=0` enumerate). It rides the generic MOS **tree** infrastructure
through MOSSHELL, exactly like DSNAV, but opens **two** channels instead of one.
`BBSNAV_DllMainLogic` (`0x7F5F4C29`) on `DLL_PROCESS_ATTACH`:

```c
InitializeNtnigr(&g_BbsNtniGroup /*0x7F60D000*/, "BBS", 3, 8, &g_BbsExtraPropTags);
InitializeEcig  (&g_BbsEcig      /*0x7F60D198*/, "BBS", 3, 0);
```

- **Service name = `"BBS"`** (the server's service-table key; *not* "MSNBBS"
  or "BBSSRV"). Both channels name the same service.
- **Read / navigation channel** — `g_BbsNtniGroup`, a MOSSHELL `_NtniGroup`
  wrapping a TREENVCL `CTreeNavClient`. Selectors **0–6** (see §Read selectors).
- **Write / edit channel** — `g_BbsEcig`, a MOSSHELL `_EditClientInfoGroup`
  ("Ecig") wrapping a TREEEDCL `CTreeEditClient`. Selectors **0–12** (see
  §Write selectors). Teardown in `DISCONNECT` (`0x7F5F4C0C`):
  `HrDisconnectEcig` then `HrDisconnectNtnigr`.
- The 5-arg `InitializeNtnigr(group, name, base, extra_count, extras[])` stores
  `name`→+0x184, `base`→+0x188, `extra_count`→+0x18C, `extras`→+0x190 (MOSSHELL
  `0x7F3FB7AA`). BBS requests **`extra_count = 8`** extra per-node property tags
  on top of MOSSHELL's base set; `base = 3` (cf. DSNAV `"DIRSRV",7,7`).

Everything below — boards, threads, messages — is a `CMosTreeNode` carrying an
SVCPROP property record, fetched/edited over these two channels. Posting is
`AddNode` + `SetProperties` + `LinkNode` on the edit channel. There is no
BBS-specific opcode space.

### Node model

| Tree level | What it is | Children |
|---|---|---|
| Board folder | a BBS board / forum (e.g. "Climbing BBS") | conversations (top-level messages) |
| Conversation root | a top-level message | its replies |
| Reply | a `RE:` message | its replies (recursive) |

Threading is **the tree itself**: a reply is a child node of the message it
answers, so `GetChildren` recursion yields the indented thread view. Each node
*also* carries an explicit parent pointer in `_P`, and its exact meaning is
fixed by `CBbsNavTreeNode_GetThreadParent` (`0x7F5F1C3E`):

```c
memcpy(mnid, node+0x10, 24);          // the node's own 24-byte mnid
if (mnid.field_8 == 0)      return 1; // no parent — this is a conversation head
GetProperty("_P", &mnid.field_8, 4);  // _P OVERWRITES field_8
if (mnid.field_8 == 0)      return 1; // _P == 0 — also a conversation head
HrGetPMtn(mnid, &parent);             // parent = same mnid, field_8 := _P
```

So **`_P` is the parent's `field_8`**, and a parent must share the child's
`field_0`, `field_c` and `field_10`. Two consequences: a node whose own
`field_8` is 0 can never have a thread parent, and `_P` cannot address a parent
that differs in any other mnid field.

The return value is the conversation test. `FUN_7F5F2E6C` (view slot `+0x50`)
calls it and passes "has a parent" as the ingest flag, which lands in the store
entry at `+0x1C`. `FUN_7F5F5DE4` increments the conversation counter
(`ctx+0xC14`) only when that bit is clear, and the status bar
(`FUN_7F5F33C2`, slot `+0x68`) just formats the precomputed counters with
string `0x1904 + view_mode` — it never counts rows itself. A board showing
"0 conversations" means the ingest never ran or every entry was flagged as a
reply.

---

## Property tags (the node-shape contract)

Every BBS `GetChildren`/`GetProperties` reply is a per-child SVCPROP record in
the standard shape `[u32 size][u16 prop_count]{[u8 type][asciiz name][value]}*`
(`DIRSRV_GETCHILDREN_CLIENT_PATH.md`). BBS requests MOSSHELL's `base` tags plus
the **8 extra tags** advertised at `g_BbsExtraPropTags` (`0x7F6101A8`, in array
order): `_a, _D, _P, _f, _t, p, _F, _I`.

| Tag | Wire type | Role | Read site / evidence |
|---|---|---|---|
| `e`  | `0x0A` ASCIIZ | **Subject** (display name). Column 0; Properties dlg item 0x66; new-post seed. | RCDATA 6011 col0; `CBbs_FillPropertiesDialogPage` `0x7F5F385E`; `CBbsTreeEdit_FillSPForNewNode` `0x7F5F1DCF`. `e` is a MOSSHELL base tag, not a BBS extra. |
| `_a` | `0x0A` ASCIIZ | **Author**. Column 1 (width 120). | RCDATA 6011 col1. Advertised-only (no BBSNAV read site → consumed by MOSSHELL's list-view formatter). |
| `p`  | `0x03` DWORD | **Size** (bytes). Column 2 (width 80). | RCDATA 6011 col2. |
| `_D` | `0x03` DWORD time_t | **Date**. Column 3 (width 118); Properties dlg item 0x6A. | RCDATA 6011 col3. `_D` triggers MOSSHELL's DWORD-as-`time_t`→date fast path (`docs/DSNAV.md` §14.2; `MOSSHELL` `0x7F3FBC12` `"_D"` string). |
| `_P` | `0x03` DWORD | **Parent / thread linkage**. Spliced into the node's own mnid → `HrGetPMtn` resolves the parent message (RE: threading / junction). | `CBbsNavTreeNode_GetThreadParent` `0x7F5F1C3E`. Also read in the write path `0x7F60162B`. |
| `_t` | `0x0A` ASCIIZ | Short text field shown in the Properties dialog (item 0x70). Topic/sub-title; **not** the message body. | `CBbs_FillPropertiesDialogPage` `0x7F5F385E`. |
| `_F` | 2-byte flags | Child-fetch gate, **inverted**: bit `0x1000` SET → child count forced to 0 (leaf message). CLEAR → the count is derived and the node expands. | `CBbsNavTreeNode_OkToGetChildren` `0x7F5F1427` reads `_F` (`&DAT_7F610234`) cap 2, then tests the HIGH byte against `0x10`. |
| `_I` | 2-byte flags/attributes | Folder attributes. **bit `0x8000`** → checkbox 0x6E; **bit `0x4000`** → checkbox 0x72 + selects label string `0x190F`/`0x1910` + drives the pricing display. | `CBbs_FillPropertiesDialogPage` `0x7F5F385E`. |
| `_f` | (unresolved) | Advertised but **no BBSNAV read site** found. Server-filled; safe value 0. | — |

Synthesised / non-extra tags BBS also touches:

- **`b`** (`0x01` byte) is the **conversation test**, not just a browse/exec
  gate. `FUN_7F5F1CAD` (`0x7F5F1CAD`) reads it and sets bit 0 of its out-byte
  when `(b & 1) == 0`. `FUN_7F5F2E6C` passes that byte as the ingest flag,
  `FUN_7F5F8784` stores it at store-entry `+0x1C`, and `FUN_7F5F5DE4`
  increments the conversation counter (`ctx+0xC14`) **only when the bit is
  clear**. So:
  - board / folder → `b` bit 0x01 **CLEAR** (container),
  - conversation head and reply → `b` bit 0x01 **SET** (message).

  A conversation head that has replies is still a message: it takes `b` bit
  0x01 set and expresses "expandable" through `_F` bit `0x1000` CLEAR. Sending
  `b = 0` for every node makes the reader draw folder glyphs, leave
  Author/Size/Date blank, and report "0 conversations" while still listing the
  rows. Confirmed live 2026-07-28 (`BPX 0x7F5F5DE4`, flag `0x01` on a node with
  mnid `field_8=0, field_c=0x100`), and fixed by sending the leaf bit.
- **`h`** (icon) is *not* taken from the wire. `CBbsNavTreeNode_GetProperty`
  (`0x7F5F1538`) intercepts `GetProperty("h")` and returns one of two local icon
  ids (`g_0x7F60D380` if node+0x18 == 0, else `g_0x7F60D35C`). Emit nothing for
  `h`; the client supplies the BBS folder/message glyphs from its own icon
  resources (icons 1–11).
- **`z`** (`0x03` DWORD) = **price**, read in the Properties dialog via
  `FFormatPrice` only when the node `HrSupportsPricing` flag (`_I` bit `0x4000`
  region) is set. Premium/paid BBS folders. Omit for free content.

Required for a usable thread list: `e` (Subject), `_a` (Author). Recommended:
`_D` (Date), `p` (Size), `_F`/`_I` (flags), `_P` (threading). The standard mnid
tag (`a`), app_id (`c`) and browse-flag (`b`) base tags apply as in DIRSRV.

### Columns (RCDATA 6011)

`CBbsNavTreeNode_GetDetailsStruct` (`0x7F5F14A3`) loads the list-view column
descriptor from **RCDATA `0x177B` (6011)** via `RgmdsFromRcdata` (cached in
`g_BbsCachedColumns`). Decoded (`[u16 count]{[u16 header_sid][asciiz tag][u16 width]}`):

| Col | Header string id | Tag | Width | Label |
|---:|---:|---|---:|---|
| 0 | 6530 | `e`  | 220 | Subject |
| 1 | 6531 | `_a` | 120 | Author |
| 2 | 6532 | `p`  | 80  | Size |
| 3 | 6533 | `_D` | 118 | Date |

(For a node with a "real"/localized node, GetDetailsStruct delegates the column
descriptor to that node's slot 28 first.)

---

## Read selectors (TREENVCL `CTreeNavClient`, channel `g_BbsNtniGroup`)

BBS does **not** override child enumeration — `GetCChildren`/`GetNthChild` are
inherited from MOSSHELL, which drives the TREENVCL selectors below
(`docs/TREENVCL.md` §14). The wire request/reply shapes are identical to DIRSRV;
the only BBS-specific input is the 8-tag extra set merged into the request.

| Sel | Op | Use in BBS |
|---:|---|---|
| 0 | `GetProperties` | one node's own properties (reader header, properties dialog) |
| 1 | `GetParents` | parent chain |
| 2 | `GetChildren` | board → conversations, message → replies (the thread list) |
| 3 | `GetDeidFromGoWord` | Go-word → board deid |
| 4 | `GetShabby` | icon/banner blobs (overridden wrappers `GetShabbyToFile` slot 29, `GetShabbyPropToFile` slot 30) |
| 5 | `EnumShn` | numeric-handle enumeration |
| 6 | `ResolveMoniker` | moniker → deid |

`CBbsNavTreeNode_OkToGetChildren` (`0x7F5F1427`) runs once per node before the
first child fetch. It reads `_F` cap 2 and tests the high byte against `0x10`
(u16 bit `0x1000`): SET → the cached child count is forced to **0**; CLEAR (or a
failed read) → the count comes from `FUN_7F5F7F89`. It then calls the MOSSHELL
base. So a node that should expand must send `_F` with bit `0x1000` CLEAR.

---

## Write selectors (TREEEDCL `CTreeEditClient`, channel `g_BbsEcig`)

Recovered from TREEEDCL `Private*` marshalling functions (base `0x7F2C0000`).
Each opens a pipe via `marshal->vtbl[+0x0C](marshal, SELECTOR, &pipe)`, packs
args with `pipe vtbl+0x24` (send-bytes), sends via `+0x48`, advances `+0x10`
(timeout), then **polls `GetStatus` while status == 1 (`Sleep(1000)`)**. Every
op first sends the **session ticket** (`this+0x54`, u16-length-prefixed) and
returns `0x116` if no ticket is held.

| Sel | Op | Wire payload (after ticket) |
|---:|---|---|
| 0  | `Lock`          | ticket |
| 1  | `Unlock`        | ticket |
| 2  | `AddNode`       | parent mnid (8 B) + compressed `CServiceProperties` → reply: **new node mnid (8 B)** |
| 3  | `DeleteNode`    | node mnid (8 B) |
| 4  | `SetProperties` | node mnid (8 B) + compressed `CServiceProperties` |
| 5  | `LinkNode`      | node mnid (8 B) + parent mnid (8 B) |
| 6  | `UnlinkNode`    | node mnid (8 B) + parent mnid (8 B) |
| 7  | `AddShabby`     | shabby id + blob |
| 8  | `DeleteShabby`  | shabby id |
| 9  | *(unused by client)* | — |
| 10 | `OrderChildren` | parent mnid + ordering |
| 11 | `GetDataSets`   | dataset query |
| 12 | `GetTicket`     | (open) → server returns a capability **ticket** blob; `HrDecodeTicket` stores it at `this+0x54` |

The property blob is wrapped by `SVCPROP!CompressPropClnt` / `FreeCompressed`
around the send. `CompressPropClnt` produces the same tagged-property byte shape
the read path decompresses.

### Posting flow (Compose / new folder)

`CBbsNavTreeNode_NewObject` (slot 82, `0x7F5F1623`) →
`CBbsTreeEdit_NewObject` (slot 12, `0x7F5F1D17`):

1. Obtain the `CTreeEditClient` from the edit object (`GetTec`, edit vtbl+0xC).
2. `CBbsTreeEdit_FillSPForNewNode` (slot 13, `0x7F5F1DCF`): `CServiceProperties::FInit`,
   then `FSet("e", type 0x0A, LoadString(0x1901))` — seeds the new node's
   **Subject** with the default object name (e.g. "New BBS Folder" / "BBS Message").
3. `CTreeEditClient::AddNode` (sel 2): `[ticket][parent mnid][compressed SP]` →
   new mnid. `EnumMosWindows(RefreshEmw)` refreshes all shell views.

Subsequent user edits (subject/body) → `SetProperties` (sel 4). Threading a
reply under its parent → `LinkNode` (sel 5). The 72-byte edit object
(`CBbsTreeEdit`, vtable `vtbl_CBbsTreeEdit` `0x7F60E9E8`) is bound to `g_BbsEcig`
and cached at node+0xBC by `CBbsNavTreeNode_HrGetPMte` (slot 72, `0x7F5F1593`).

**Ticket gate**: the server must answer `GetTicket` (sel 12) with a capability
ticket before any mutate succeeds; it is replayed on every edit op and validated
server-side (cf. `SECURCL` `TICKET` decode used by TREEEDCL/DATAEDCL).

---

## Message reader & body

The board's list-view (Subject/Author/Size/Date columns) is hosted by a
`CMosViewWnd` subclass, **`CBbsViewWnd`** (104 B / `0x68`, ctor `0x7F5F1F8B`,
`HrInit`), built by `CBbsNavTreeNode_GetViewWndObject` (slot 36, `0x7F5F1307`)
and registered under window class **`BBSMsgWndClass`**. The reader header fields
(From/Date/To/Subject in `bbs.png`) come from the node's `e`/`_a`/`_D` properties
and the board context.

The **message body** is shown/edited in a **RichEdit** control —
`BBSNAV_DllMainLogic`'s class-registration helper (`0x7F5F9406`) loads
`riched32.dll` (`0x7F5F9444`). Body source on the wire: not pinned in this static
pass (`GetPropertyToFile` appears only as an inherited vtable thunk, with no
BBSNAV-local call). `p` = byte size implies a sized content blob delivered as the
node's content. **Bounded gap — recommend a live SoftICE trace of the Read-window
open to pin the body property/blob tag.**

---

## Read-state & preferences

`HKCU\SOFTWARE\Microsoft\MOS\BBS Viewer` holds **only window placement** — a
24-byte struct under value names `{MSN,Net} {Comp,Read} Wnd` (i.e. four values:
`MSN Comp Wnd`, `Net Comp Wnd`, `MSN Read Wnd`, `Net Read Wnd`). Load:
`CBbs_LoadWindowPlacement` (`0x7F600DB2`, `RegQueryValueExA`); save:
`CBbs_SaveWindowPlacement` (`0x7F600EC5`, `RegSetValueExA`).

**Message read/unread state is NOT client-local.** The registry carries no
per-message read flags, so unread tracking ("3 conversations, 2 with unread
messages" in `bbs.png`) is **server-side** — surfaced as a flag bit on the node
(`_F`/`_I`) and rendered by the list-view (bold/icon). A server BBS handler must
track per-user read state and reflect it in the per-node flags; marking-read is
expected to ride the edit channel (`SetProperties`) or be inferred server-side on
open.

---

## MSN BBS vs Internet Newsgroups

BBSNAV.NAV serves **both** App #2 (MSN BBS) and App #10 (Internet Newsgroups).
The variant is a **runtime branch**, not a separate binary:
`CBbs_FIsMsnBbs` (`0x7F600D21`) returns `(FUN_7F6017B3(win+0x88) & 7) == 0` →
"MSN" vs "Net" (selects the registry value prefix and gates commands; strings
"This command is not available in Internet Newsgroups." / "…available only in
Internet Newsgroups."). The Internet path also formats RFC-822/NNTP headers
("Newsgroups: " `0x7F610CD8`).

### Internet / email gateway (call-sites only)

`CBbs_MapiForwardOrReply` (`0x7F6044CB`) is the **Forward / Reply-by-email**
feature. It **dynamically** `LoadLibraryA("MAPI32.DLL")` +
`GetProcAddress("MAPILogon"/"MAPILogoff"/"MAPISendMail")` (hence MAPI is absent
from BBSNAV's static import table). Flow:

```
MAPILogon(0, NULL, NULL, 0x48, 0) -> session
subject = (mode==0) "FW: %s" : "RE: %s"   // mode arg: 0=Forward, 1=Reply
recipient <- dialog item 0x3E9 ; body <- dialog edit 0x3ED (the RichEdit body)
MAPISendMail(0, session, &MapiMessage{subject, noteText=body, ...}, 8, 0)
MAPILogoff(session, ...)
```

This emails a BBS post through the user's **local MAPI client** (Exchange). The
MSN address-book provider `MOSABP32.DLL` participates as a MAPI AB provider
loaded by the MAPI subsystem (not by BBSNAV directly — the string is present but
unreferenced in BBSNAV code). **The gateway's own protocol (MAPI32 / MOSABP32
internals) is deferred** — those callees are Windows/MSN components outside our
binary set.

---

## Verification

- **Static, internal consistency**: every selector and tag above cites a Ghidra
  call-site at BBSNAV `0x7F5F0000` (or TREEEDCL `0x7F2C0000` / MOSSHELL
  `0x7F3F0000`). The service-model verdict is backed by the proven *absence* of
  an IID/bootstrap table and the *presence* of the dual `InitializeNtnigr` /
  `InitializeEcig("BBS", …)` calls in `BBSNAV_DllMainLogic`.
- **North-star acceptance** (defines "done"): a minimal server BBS handler that,
  on service `"BBS"`, returns one board → one conversation → one reply, each as a
  tree node carrying `{e, _a, p, _D, _F}` (+ `_P` on the reply pointing at the
  conversation), and answers `GetTicket`, should make the stock client render the
  thread list + reader exactly like `bbs.png` and accept a Compose → `AddNode`.
- **Live confirmation** (for the one bounded gap): SoftICE `BPX` on the
  Read-window open to capture the message-body property/blob fetch.
