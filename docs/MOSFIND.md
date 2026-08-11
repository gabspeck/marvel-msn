# MOSFIND.DLL — the Find dialog and the FindSvc query language

Reverse-engineering notes for `binaries/MOSFIND.DLL`, "The Microsoft Network
Find DLL" (1.60.0, image base `0x7E9B0000`, 25 KB). It is the COM server behind
**Find > MSN Service**: it owns the dialog, compiles what the user typed into a
query string, sends that string to the `FindSvc` service, and turns the mnids
that come back into result rows.

Sources: static decompilation against the MSN95 Ghidra project (`/MOSFIND.DLL`)
plus the resource string table, confirmed on the wire 2026-08-11 — a search for
`search term` with the Name and Subject boxes ticked and the default scope
arrived as

```
class=0x01 selector=0x01 payload_len=91  arg=0x00000001
"(SUBJ_NAME contains 'search' & 'term') AND (APPID <> 2 or BBS_FOLDER_FLAGS <> 0)"
```

which matches the derivation below down to the checkbox mask. A later 74-hit
search drove the result-row half end to end: DIRSRV GetProperties on its own
pipe with `nodes=20 / 20 / 20 / 14`, `dwords=<count>,6`, every row resolved and
displayed.

Companions: `PROTOCOL.md` §7.8 (wire shapes), `docs/TREENVCL.md` (the DIRSRV
half), `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` (the property record format).

## 1. Shape

Two COM objects, both handed out by `DllGetClassObject` @ 0x7E9B3491:

- **CFindConnection** (vtable `0x7E9B4810`, `QueryInterface` accepts
  `00028BB3` / `00028BB4` / `IUnknown`). Owns the two channels and the search
  call. Slot 7 is `HrSearch`, slot 8 `Cancel`.
- **CFindDialog** (vtable around `0x7E9B4900`). Owns the dialog window and
  builds the query string.

Imports say the same thing: `SVCPROP.DLL` for `CServiceProperties::FGet`,
`TREENVCL.DLL` for the `CTreeNavClient` ctor, `GetProperties`, `GetNthNode` and
`CloseHDyn`, and `MOSMISC.DLL` for the two preferences.

## 2. Channels

`CFindConnection::HrSearch` @ 0x7E9B136A brings up the FindSvc channel on first
use:

```c
CoCreateInstance(CLSID 00028B07, ..., IID 00028B08, &this->marshal);
marshal->vtbl[0x24]("FindSvc", &IID_00028BB0_array, &this->service, 2, 0);
service->vtbl[0x0c](1, &request);          // GetMethod(1)
```

Pipe open is `svc_name="FindSvc" ver_param="U" version=2`. The IID array based
at `0x7E9B45E8` starts at `00028BB0`; its length is not encoded anywhere in the
binary, but `00028BB6` begins LOGSRV's own table, so the run reads as
`00028BB0..00028BB5`. Only the first entry matters on the wire — the class byte
of every request is whatever selector the discovery reply assigned it.

The second channel is an ordinary `CTreeNavClient` on `"DIRSRV"`
(string at `0x7E9B5014`), built lazily by `FUN_7E9B1ABA`.

## 3. Search — FindSvc method 1

Request, from the MPCCL calls at `0x7E9B1481`..`0x7E9B14C7`:

```
04 <cb> <query ASCIIZ>   +0x24 PackSendBytes(szQuery, lstrlenA + 1)
03 <dword>               +0x28 PackSendDword — always 1
83                       +0x18 PackReceiveDword(&status)
83                       +0x18 PackReceiveDword(&cResults)
85                       +0x40 dynamic receive, +0x48 dispatch
```

The DWORD is the out-parameter `CFindDialog_BuildQueryString` hands down to
`CFindDialog_BuildScopeFragment` @ 0x7E9B2FC1, which writes a literal 1 into it
before it reads the combo. Observed as `0x00000001` on a live search from the
stock dialog.

Reply — **two blocks on the same request id**:

```
83 <status> 83 <count> 87 88 <count × 8-byte mnid>
86
```

`status` is returned verbatim as `HrSearch`'s HRESULT, before any of the stream
is read. `count` lands in the result set's `this+8` and is what its `GetCount`
(vtable slot 3, `0x7E9B1821`) returns.

The dynamic section is a flat array of 8-byte mnids and nothing else.
`CFindResultSet_PullMnidChunk` @ 0x7E9B196F walks it by asking the stream
iterator for at least `cursor + 8` bytes and pumping `vtbl[0x14]` until either
enough arrive or the call returns `0x0B0B000B` (stream ended). A partial id at
the tail is simply "not available yet".

**Both tags are needed, in that order.** The ids have to ride `0x88`, because
`0x86` reaches only `SignalRequestCompletion` and never the iterator — under
`0x86` alone the pump reads an empty buffer. But after the last id the pump
asks for eight more bytes and waits again, and `WaitIncremental` @ MPCCL
`0x046049BC` ends with

```c
return (request+0x18 == 0) + 0x0B0B000B;
```

so it answers `0x0B0B000C` ("more may come") until something sets
`request+0x18`. Only `SignalRequestCompletion` does, and only `0x86` reaches
it. Ending on `0x88` alone hangs the dialog on "Retrieving results" with every
row already fetched and rendered — observed live 2026-08-11, fixed by appending
the bare `0x86`.

This is the same shape FTM's download uses for the same reason: one
`0x88`-terminated message carrying the data, then a bare `0x86`. The `0x86`
CPU-spin hazard (`project_mpccl_signalcompletion_spin`) does not apply — it
bites consumers that keep waiting after completion, and this pump exits the
moment it sees `0x0B0B000B`.

`0x0B0B000D` anywhere in the chain means the search was cancelled —
`CFindConnection::Cancel` @ 0x7E9B157D sets the event that
`CFindResultSet_GetNextRow` tests first.

## 4. Result rows — DIRSRV GetProperties

`CFindResultSet_GetNextRow` @ 0x7E9B182B batches
`DAT_7E9B5010` = **20** mnids per resolution and calls

```c
CTreeNavClient::GetProperties(mnid_array, batch_count,
                              {"f","c","a","tp","w","p"},
                              locale_blob, &out_total, &iterator);
```

then pulls the records out one at a time with `GetNthNode`. This is the only
caller in the client that sends a multi-id node array, so a server that answers
GetProperties with a single record fails every row after the first.

`CFindNav_FillResultRow` @ 0x7E9B1D6A decodes one record into the row struct:

| Offset | Tag | Read as | Required |
|-------:|-----|---------|:--------:|
| `0x00` | `c` | app id, DWORD | yes |
| `0x08` | `a` | 8-byte mnid | yes |
| `0x10` | `f` | UTF-16 name, narrowed with `WideCharToMultiByte`, cap 128 | yes |
| `0x90` | `tp` | ANSI type text via `lstrcpynA`, cap 32 | no |
| `0xB0` | `w` | FILETIME through `FileTimeToLocalFileTime` | yes |
| `0xB8` | `p` | size in bytes, DWORD | no (0 when absent) |

Any missing required tag fails the row with `0x8B0B0080`.

The wire types therefore differ from the Properties sheet's for the same tag
names: `f` must be 0x0B (the row narrows the value itself), `tp` must be 0x0A,
and `w` must be 0x0C — including for a node with no recorded date, where the
details view instead sends an empty 0x0A string to render a blank cell.

`f`, not `e`. Reads elsewhere use `e`; `f` is the tag MOSSHELL's
`CMosTreeEdit::SetProperty` writes the name under, and the Find row is the only
reader of it.

## 5. The query string

`CFindDialog_BuildQueryString` @ 0x7E9B2526 joins up to four fragments, each in
its own parentheses, with `" AND "`:

```
(SEARCH_PROPS contains 'yosemite') AND (APPID = 1) AND (PLACES contains 'seattle')
```

At least one fragment must report `0x00040200` — "a real criterion" — or the
build fails with `0x8B0B0064` and nothing goes on the wire.

### 5.1 Containing box — `<FIELD> contains <expr>`

`CFindDialog_BuildTextFragment` @ 0x7E9B2DE9. Control 500 is the text box; the
three checkboxes form a 3-bit mask that indexes the field-name table at
`0x7E9B48A8`:

| Checkbox | Bit | Mask | Field name |
|----------|----:|-----:|------------|
| `0x1F5` | 0 | 1 | `NAME` |
| `0x1F6` | 1 | 2 | `SUBJECT` |
| `0x1F7` | 2 | 3 | `SUBJ_NAME` |
| | | 4 | `DESCRIPTION` |
| | | 5 | `NAME_DESC` |
| | | 6 | `SUBJ_DESC` |
| | | 7 | `SEARCH_PROPS` |

Mask 0 returns `0x80040202` and no fragment. The combined names are unions, not
separate columns.

### 5.2 Search-text compilation

`CQueryLexer_Compile` @ 0x7E9B3C6E runs `CQueryLexer_EmitToken` @ 0x7E9B37F8
twice over the box text — once to measure, once to write. What it emits:

| Input | Output |
|-------|--------|
| a word | `'word'` — quote opened on the first char, closed by the next space |
| space between terms | `' & ` (implicit AND) |
| `and` / `or` / `not` (whole words, from STRINGTABLE) | `&` / `\|` / `~` |
| `,` | ` \| ` |
| `(` `)` | passed through, nesting counted |
| `*` | `%` |
| `?` | `_` |
| `"` | toggles literal mode; no operator applies inside |
| `%` `_` `\` `-` | backslash-escaped |
| `'` | doubled to `''` |

So `red shoes` → `'red' & 'shoes'`, and `cat*` → `'cat%'`.

`contains` is substring matching: the lexer adds no leading or trailing `%`.

### 5.3 Type combo — the scope fragment

`CFindDialog_BuildScopeFragment` @ 0x7E9B2FC1 reads control `0x1F8` and loads
STRINGTABLE `0x4EAC + index`. **The resource string is the query fragment.**

| Idx | Display name (0x4EA0 block) | Fragment (0x4EAC block) |
|----:|------------------------------|--------------------------|
| 0 | All services of The Microsoft Network | `APPID <> 2 or BBS_FOLDER_FLAGS <> 0` |
| 1 | Folders and forums | `APPID = 1` |
| 2 | Bulletin boards and file libraries | `APPID = 2 AND BBS_FOLDER_FLAGS = 1` |
| 3 | Chat rooms | `APPID = 4` |
| 4 | Multimedia titles | `APPID in (6,11,12)` |
| 5 | Kiosks and other files | `APPID = 7` |
| 6 | Internet newsgroups | `APPID = 2 AND BBS_FOLDER_FLAGS = 0` |
| 7 | All services (MSN and Internet) | *(empty)* |

Index 0 returns `0x00040201` rather than `0x00040200`, so picking it alone does
not satisfy the "at least one real criterion" test — the dialog needs search
text as well. Index 7's empty string produces no fragment at all.

`BBS_FOLDER_FLAGS` is what separates the two things App #2 hosts: MSN bulletin
boards and file libraries carry 1, Internet newsgroups carry 0.

The 0x4E98 block holds the short forms the results-window title uses
(`FUN_7E9B2731`): "All MSN services", "Folders", "BBSs and libraries", "Chat
rooms", "Titles", "Kiosks and other files", "Internet Newsgroups", "All
services".

### 5.4 Place box

`CFindDialog_BuildPlaceFragment` @ 0x7E9B30F9. Control `0x1F9`, field name from
STRINGTABLE `0x3EC` = `PLACES`, right-hand side compiled by the same lexer:
`PLACES contains 'seattle'`.

### 5.5 Language filter

`CFindDialog_BuildLocaleFragment` @ 0x7E9B2D46. Emits nothing while
`ShowAllLanguages` is on (the stock default). Off, it appends

```
LOCALES contains '00000409'
```

— field name from STRINGTABLE `0x3EE`, LCID formatted `'%08X'` from the
`BrowseLanguage` preference. Both preferences are read by `FUN_7E9B3347`
through `MOSMISC!FGetPreferenceBool` / `GetPreferenceDword`; see
`project_mosfind_showalllanguages`.

## 6. What belongs in the index

Find lists **services**, not the content inside them. The "of type" combo has an
entry for bulletin boards and file libraries but none for the messages in them,
and `store.records.bbs_node` notes that only the board is a DIRSRV row —
messages are never even asked for `tp`. BBS messages and attachments ride the
same content store as the directory, so the server filters them out explicitly;
left in, they appeared in the results window as rows with a blank Type column
and a Size rendered as a message count.

Every indexed node also needs a real `w`. `CFindNav_FillResultRow` has no
blank-cell branch — an undated node renders as `1/1/01`, the 1601 epoch shifted
by the member's UTC offset. The details view's empty-string form for `w` is a
DSNAV-only behaviour and never reaches this window.

### 6.1 `p` is not a byte count

MSNFIND's Size-cell formatter @ `0x7F37318B` picks the unit from `c`:

| `c` | Rendering | STRINGTABLE |
|----:|-----------|-------------|
| 2 | `"%d message"` / `"%d messages"` | 0x458 / 0x459 |
| 4 | `"%d person"` / `"%d people"` | 0x456 / 0x457 |
| 7 | `HrSzForByteCount` → `192KB` | — |
| anything else | cell left empty | — |

`p == 0` leaves the cell empty whatever `c` is, which is why plain containers
show nothing there.

So a bulletin board's `p` is its article count, and the server counts it live
off the child list rather than storing it — a post has to move the number the
next time the board is listed. Attachment nodes are registered by mnid but
deliberately off the board's child list, so they do not inflate it.

A chat room's `p` should likewise be its current occupancy. That number lives
in the conference service, not the content store, so rooms still report 0 and
show a blank cell.

MOSSHELL runs the same tag through `FormatSizeString` unconditionally, so the
board's row in Explorer renders the message count as a byte size. That is the
client's own inconsistency — one tag, two readers, and only MSNFIND carries the
per-app rule.

## 7. Open

- Whether the real service capped result counts, and at what number. The
  server's own 200 is arbitrary and has not been reached.
- `SUBJECT` is read here as the node's `r` (topics) property and `DESCRIPTION`
  as `j`. Nothing in the client names the mapping — it is inferred from the
  checkbox labels and the DIRSRV property vocabulary.
