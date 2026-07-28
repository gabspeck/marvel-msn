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
| Board folder | a BBS board / forum (e.g. "Climbing BBS") | every message on the board |
| Message | a post, whether a conversation head or a `RE:` reply | none |

The tree under a board is **flat**. The reader enumerates the board once — one
`FUN_7F5F2E6C` ingest call per child — and never asks a message for children,
so a reply nested under the message it answers never reaches the list at all.
A board therefore returns replies alongside conversation heads, and a message
sets `_F` bit `0x1000` (no children).

Threading rides `_P` alone, and its exact meaning is fixed by
`CBbsNavTreeNode_GetThreadParent` (`0x7F5F1C3E`):

```c
memcpy(mnid, node+0x10, 24);          // the node's own 24-byte mnid
if (mnid.field_8 == 0)      return 1; // no parent — this is a conversation head
GetProperty("_P", &mnid.field_8, 4);  // _P OVERWRITES field_8
if (mnid.field_8 == 0)      return 1; // _P == 0 — also a conversation head
HrGetPMtn(mnid, &parent);             // parent = same mnid, field_8 := _P
```

So **`_P` is the parent's `field_8`**, and a parent must share the child's
`field_0`, `field_c` and `field_10`. Three consequences: a node whose own
`field_8` is 0 can never have a thread parent, `_P` cannot address a parent
that differs in any other mnid field, and a message and its reply are
**siblings** — which is why the tree under a board is flat.

`FUN_7F5F2E6C` calls `GetThreadParent` per ingested node and passes the low
byte of the resulting pointer to `FUN_7F5F5B4A` as the ingest flag, so "has a
thread parent" is the only thread fact recorded at ingest time. It lands in the
store entry at `+0x1C`, and `FUN_7F5F5DE4` counts a conversation only when that
bit is clear.

### BBS mnid layout

`CBbsNavTreeNode::GetParent` (`0x7F5F12CE`) pins the rest of it — it copies the
node's mnid, **zeroes `field_8`**, and resolves that:

```c
memcpy(mnid, node+0x10, 24);
mnid.field_8 = 0;
HrGetPMtn(mnid, &parent);      // → the board
```

Both functions only make sense under one assignment:

| field | meaning |
|---|---|
| `field_8` | **message id**; `0` on the board itself |
| `field_c` | **board id** |
| `_P` | parent *message id* (swapped into `field_8`); `0` on a conversation head |

Everything checks out against it: zeroing the message id yields the board,
`_P` names a sibling post in the same board, and `field_8 == 0` short-circuits
"no thread parent" because a board has no thread. Inverting the pair makes
`GetParent` resolve a message **to itself**, and the reader's open path rejects
that with "Cannot open message.##This task cannot be completed" — reported by
`FUN_7F5F99C1(hr, 0x44E)` before any wire traffic, so the server log stays
silent.

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
- **Shared MOS tree tags** (`j, k, ca, r, s, t, u, n, on, v, w, y, o, z`) are
  fetched from a BBS node too, one at a time as `{name, 'g'}` groups, when the
  Properties dialog opens — observed live as `q,g` then `v,g` on a message node.
  They keep their DIRSRV wire types; answering any with a DWORD-0 stand-in
  leaves the dialog blank or garbled.
- **`q`** (language) is the exception: send it as type **`0x10`** dword array
  `[count=1][lcid]`, not DIRSRV's `0x04` qword. MOSSHELL's value formatter
  (`0x7F3FBC12`) switches on the cached type — case `0x10` calls
  `GetLocaleInfoA(value[1], LOCALE_SLANGUAGE)` and prints a language name, while
  case `0x04`/`0x08` falls through to `FUN_7F3FAE1C` =
  `wsprintfA("%u:%u", high, low)`, which renders as a bare `0:0`. Both encodings
  place the LCID at offset +4, so MCM's browse-language reader
  (`*(u32*)(value + 4)`) is satisfied either way.
- **Dates must agree across representations.** `_D` is a `time_t` the client
  renders through its own timezone; `v`/`w` are server-formatted strings passed
  through verbatim. Derive both from the same wall-clock instant, or the listview
  Date column and the dialog's Created field differ by the client's UTC offset.

  When converting a wall clock to `_D`, use the client's **current** UTC offset,
  not the offset in force on the timestamp's date. Windows 95 carries no
  historical timezone database — it applies its single current rule to every
  timestamp — so a 1995 `_D` is displayed with today's offset. Any server-side
  conversion that honors historical rules (Python's `datetime.timestamp()` does)
  drifts wherever the two disagree: Europe/Lisbon ran CEST +0200 in 1995 and WEST
  +0100 today, which put the Date column an hour behind the dialog.
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

## Interface classes

A request's `msg_class` is the **interface** — the selector the server assigned
that IID in the discovery reply — and `selector` is the **method index** within
it. BBS uses two:

| class | IID | channel |
|---|---|---|
| `0x03` | `00028B27` | `CTreeNavClient` read channel (methods below) |
| `0x0B` | `00028B2F` | message content, negotiated when a message is opened |

Dispatching on `selector` alone therefore misroutes: class-`0x0B` method 0 lands
on GetProperties, which answers with a record the reader cannot use — and the
client ACKs it rather than complaining.

### Message-content channel (class `0x0B`)

`CBbsNavTreeNode::Exec` (`0x7F5F110C`) → `FUN_7F5F116B` → `FUN_7F5F9618` builds
the reader. Inside it `FUN_7F6014DA` assembles a five-property MAPI array from
node reads through vtable `+0x44` (`GetPropertyBuf`) — `e`→`0x6800001E`,
`a`→`0x68160014`, `_D`→`0x68150040` PT_SYSTIME, `_P`→`0x68140003`,
`p`→`0x68030003` — and before that calls `FUN_7F5FCD1A`, which opens the content
channel:

```c
tnc = CreateTnc("BBS", 3, locale, …);
marshaller = tnc[+0x24];
wsprintfA(buf, "agid=%d", locale);
hr = marshaller->vtable[0x24]("BBS", IID 00028B2F, &out, 3, buf);
```

If the discovery reply omits `00028B2F` this returns **E_NOINTERFACE**
(`0x80004002`) and `FUN_7F5F99C1(hr, 0x44E)` reports "Cannot open message.##This
task cannot be completed" *before any request reaches the wire* — the server log
stays silent. Note `0x1F42`, the detail string used there, is that reporter's
default branch, i.e. an HRESULT it has no specific mapping for.

#### Method 0 — fetch the article

`FUN_7F5FB056` copies the 8-byte mnid into the reader context at `+0xA8` and
spawns the fetch thread `LAB_7F5FB0D3`, whose body is `FUN_7F5FB15F`. That
function builds one request on the object `FUN_7F5FCD1A` left at `+0x20`:

| call | MPCCL | wire |
|---|---|---|
| request vtable `+0x24`(mnid, 8) | `RegisterVariableReplyBuffer` peer | `04 88` + 8 bytes |
| request vtable `+0x18`(&status) | `RegisterFixedReplyDwordField` `0x04603E17` | `83` |
| request vtable `+0x40`() | sets the request's streaming flag | — |
| request vtable `+0x48`(&iterator) | `DispatchBuiltServiceRequest` `0x046040D8` | `85` |

```
class=0x0B selector=0x00
payload: 04 88 [msg_id:u32][board_id:u32] 83 85
```

The `0x85` byte is appended by `DispatchBuiltServiceRequest` only because the
streaming flag is set, and it is what makes the reply's dynamic section legal —
`ProcessTaggedServiceReply` (`0x04604F26`) rejects a dynamic tag with "MPC
Problem: Receiving Dynamic w…" when the flag is clear.

Reply:

```
83 [status:u32] 87 86 [article bytes …]
```

`status` must be `0`. `FUN_7F5FB15F` checks it after the first wait and bails
with `0x8B0B0049` on anything else, before reading a byte of the body.

The dynamic tag must be **`0x86`, not `0x88`**. `ProcessTaggedServiceReply`
branches on it:

- `0x86` → `SignalRequestCompletion` (`0x04604DDC`): sets request `+0x18 = 1`,
  then `SetEvent` on `+0x24`, `+0x28` and `+0x2C`.
- `0x88` → `FUN_04604E25` + `FUN_04604E52`: signals `+0x28` and `+0x2C` only,
  leaving `+0x18` clear.

The fetch thread drains the stream through iterator vtable `+0x14`
`WaitIncremental` (`0x046049BC`), which waits on `+0x28` and returns
`0x0B0B000B` when `+0x18` is set and `0x0B0B000C` when it is clear. Only
`0x0B0B000B` ends the loop, so a `0x88` reply parks the thread on the next wait
and the Read Message window stays blank. The tree channel uses `0x88` because
its consumer is TREENVCL's node iterator, which waits on the `+0x2C` stream-end
event instead.

Each pass reads the chunk through iterator vtable `+0x1C`, whose object exposes
the accumulation buffer at `+0xC` (`+0x20` offset added) and the running total
at `+0x10`; the thread tracks how much it has already consumed, so a single
`0x86` blob arrives as one full chunk.

#### Article format

The payload is an RFC-1036 news article: header lines, a blank line, then the
body. `FUN_7F5FB15F` splits at the **first two adjacent `\n` bytes** — header
lines therefore end in a bare LF. With CRLF the two newlines are never adjacent,
the split never fires, and the whole article is swallowed as headers.

Headers go to `FUN_7F5FB4A9`, which parses against a 22-entry table it copies
from `0x7F610A50`. That table is filled in at runtime by the initialiser at
`0x7F5FAAEF` out of the `(char*, len)` array at `0x7F610978` — on disk the
template is zeroed apart from the first tag, so a static dump of `.data` shows
an empty table. Each entry is 20 bytes: MAPI tag, name pointer, name length
(word), seen flag, enable flag. Matching is `strncmp` against the tabled name
*including its trailing space*, so a line must read `Name: value` with exactly
one space. A recognized name whose enable flag is clear is marked seen and
skipped.

| header | MAPI tag | enabled |
|---|---|---|
| `From: ` | `0x0C1A001E` PR_SENDER_NAME | yes |
| `Subject: ` | `0x0037001E` PR_SUBJECT | yes |
| `Message-ID: ` | `0x6817001E` | yes |
| `X-MOS-Format: ` | `0x6801001E` | yes |
| `X-MOS-Attach: ` | `0x68020002` | yes |
| `X-MOS-Size: ` | `0x68030003` | yes |
| `Newsgroups: ` | `0x6804001E` | yes |
| `Path: ` | `0x6805001E` | yes |
| `Date: ` | `0x6818001E` | no |
| `X-MOS-To: ` | `0x6800001E` | no |
| `X-MOS-Parent: ` | `0x68140003` | no |
| `X-MOS-Icon: ` | `0x68190002` | no |
| `X-MOS-Info: ` | — | no |

The rest of the table covers plain news headers (`Reply-To`, `Sender`,
`Followup-To`, `Expires`, `References`, `Control`, `Distribution`,
`Organization`, `Keywords`, `Summary`, `Approved`, `Lines`, `Xref`).

`X-MOS-Parent` shares tag `0x68140003` with the node property `_P`, and
`X-MOS-Size` shares `0x68030003` with `p`, so an article can restate what the
tree already supplied.

Body bytes after the blank line go into an in-memory IStream (`FUN_7F605B02` is
its `Write`). `FUN_7F5FC56F` then reads `0x6801001E` back off the message and
strcmps it to pick the RichEdit stream mode:

| `X-MOS-Format` | EM_STREAMIN wParam |
|---|---|
| `TEXT` | `SF_TEXT` (1) |
| `RTF` | `SF_RTF` (2), stream passed through |
| `RTFCOMP` | `SF_RTF` (2), wrapped by `WrapCompressedRTFStream` (MAPI32 ordinal 185, behind an ordinal-21 init call) |

The header is mandatory. Omit it and the property reads back PT_ERROR (type
`0x0A`), which aborts the render with `0x8B0B0049`.

`SF_TEXT` leaves the RichEdit on its own default font and the body draws in
Courier New. The reference screenshot `reference/screenshots/bbs.png` shows
proportional MS Sans Serif, so the font has to arrive inside the stream — i.e.
the body is RTF, not plain text. `RTF` and `RTFCOMP` reach the same `SF_RTF`
mode; nothing observed so far says which one the service used.

In `SF_RTF` mode two extra passes run after the stream:

- `FUN_7F5FC7B7` — `EM_GETOLEINTERFACE` (`0x043C`), then
  `IRichEditOle::GetObjectCount` / `GetObject` over every embedded object,
  keeping those whose CLSID matches `DAT_7F60E3E0` in an array at reader
  `+0xC4` (count at `+0xC0`).
- `FUN_7F5FC919` — reads `0x68160014` + `0x68150040` off the message and
  resolves each kept object against the tree through `FUN_7F5FCEE5`.

Both are guarded on a nonzero object count, so an RTF body with no embedded
objects skips them entirely.

Opening a message also makes the client read `_r` and `z` on the node
(`props=_r,g` then `z,g`), and the status bar's unread count drops — so `_r` is
the read-state tag.

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
