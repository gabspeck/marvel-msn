# MOSABP — MSN member address book / Member Properties

Client side of the `MOSABP` service, reverse-engineered from `MOSABP32.DLL`
(Windows 95 RTM, 1995-07-11, 107520 bytes, `WINDOWS\SYSTEM\MOSABP32.DLL`).
The DLL ships with Windows 95 itself, not with the MSN client update, so it is
absent from a `binaries/` tree assembled from the MSN files alone.

Addresses are at the DLL's preferred base `0x7F4D0000`. `MOSMUTIL.DLL` is at
`0x7E990000`, `MPCCL.DLL` at `0x04600000`.

---

## 1. What it is

`MOSABP32.DLL` is a MAPI address-book provider (`ABProviderInit`, ordinal 100)
plus two dialog entry points:

| Ordinal | Export | Purpose |
|---:|---|---|
| 100 | `ABProviderInit` | MAPI AB provider entry |
| 101 | `HrUserDetailsDlg(HWND, char *name)` | member sheet, keyed by member name |
| 102 | `HrUserDetailsDlgHacct(HWND, ULONG hacct)` | member sheet, keyed by account handle |

Its wire client is the C++ class `CAbConnection` (34 exported members, all with
decorated names intact — the DLL is trivially readable). One `CAbConnection`
holds the MPC marshaller, the open service object, a critical section, and the
three MAPI allocator callbacks the caller passes to the constructor.

---

## 2. Framing

`CAbConnection::HrGetMethod` (`0x7F4D4311`) is the only site that opens the
service, and every operation funnels through it:

```c
HrGetMosObjs(this);                      // CoInitialize + CoCreateInstance
                                         //   CLSID 00028B07 → IID 00028B08
marshal->vtbl[0x10](0, 0, 0x80, 0);      // init
marshal->vtbl[0x24]("MOSABP",            // svc_name
                    &IID_00028B22,       // one IID, not an array
                    &service,
                    3,                   // version
                    0);                  // no parameter string
service->vtbl[0x0c](iMethod, &method);   // GetMethod(ServiceMethod)
```

Pipe open is therefore `svc_name="MOSABP" ver_param="U" version=3`.

**Discovery must contain IID `00028B22-0000-0000-C000-000000000046`.** It is the
only interface the DLL resolves — the `&DAT_7F4E6330` it hands slot `0x24` points
at that GUID, and the seven GUIDs following it in `.rdata` (`00028B23` …
`00028B29`) are a contiguous run nothing references. Without it slot `0x24`
returns `E_NOINTERFACE` and the sheet never opens, with no wire traffic to show
for it.

A request's `msg_class` is the selector the server assigned that IID in the
discovery reply, and `selector` is the `ServiceMethod` number verbatim.

### `enum ServiceMethod`

Read off the immediate each member pushes before `HrGetMethod`:

| # | `CAbConnection` member |
|---:|---|
| 0 | `HrGetAbContainers` |
| 1 | `HrGetValidationList` |
| 2 | `HrGetUserDetails` — member-name form |
| 9 | `HrCloseTable` |
| 10 | `HrGetUserDetails` — hacct form |
| 11 | `HrUpdateUserDetails` |
| 12 | `HrQueryWWRows` |
| 13 | `HrQueryRestrictRows` |
| 14 | `HrEnumDistList` |
| 15 | `HrQueryRowsMore` |

`HrGetAbContainers` (`0x7F4D4423`) pushes its method number as a `push 0`
folded into the call setup rather than a `push imm8`, which is why it reads as
absent from the list above. It is method **0**, confirmed live 2026-08-14: the
address book's first request on the pipe is `class=0x01 selector=0x00` with
payload `83 83 85`.

---

## 3. Getting there from the BBS reader

BBSNAV menu 103 carries **`Member &Properties...`, command id `0x5B0`**.
`FUN_7F5FE8FE` routes it to `FUN_7F604316`:

```c
GetWindowTextA(GetDlgItem(reader_hwnd, 0x3E9), buf, 0x104);  // the From box
if (!buf[0]) return 0;
at = strchr(buf, '@');
if (at) {
    *at = 0;
    if (_stricmp(at + 1, "msn.com")) return 0x8004010F;      // MAPI_E_NOT_FOUND
}
return HrUserDetailsDlg(hwnd, buf);                          // ordinal 101
```

Consequences for the article a BBS server serves:

- The lookup key is the **`From:` header value**, not an account name.
- A `From:` with an `@` is accepted only when the domain is exactly `msn.com`
  (case-insensitive). Any other domain fails before the wire, and
  `FUN_7F5F99C1(hr, 0x5B0)` puts up string `0x1B6D` with the generic detail
  `0x1F42`.
- A `From:` with no `@` is passed through whole.

`HrUserDetailsDlg` then builds the entry id and runs the sheet:

```c
HrBuildUeid(&ueid, /*EIDTYPE*/ 1, name, name);
FUN_7F4D1AE5();   // new CAbConnection(MAPIAllocateBuffer, MAPIAllocateMore,
                  //                   MAPIFreeBuffer, NULL)
                  //   → FUN_7F4D107E: fetch  → FUN_7F4D1170: PropertySheetA
```

### `_usr_entryid`

`MOSMUTIL!HrBuildUeid` (`0x7E991036`) fills a 184-byte structure:

| Offset | Size | Contents |
|---:|---:|---|
| `0x00` | 4 | `abFlags`, zeroed |
| `0x04` | 16 | provider MAPIUID |
| `0x14` | 4 | `2` — entry-id version |
| `0x18` | 4 | `EIDTYPE` |
| `0x1C` | 0x5B | display name (`strncpy`) |
| `0x77` | 0x41 | member name (`strncpy`, 65 bytes max) |

`HrGetUserDetails` branches on `ueid[0x18] == 4`: type 4 sends the dword at
`0x1C` under method 10, anything else sends the string at `0x77` under method 2.
`HrBuildUeid` from BBSNAV always writes type 1, so the reader's sheet is
**always method 2**.

---

## 3.5 `GetAbContainers` (method 0)

The address book's first request on the pipe. No send params.

```
request:  83 83 85
reply:    83 [status:u32] 83 [cContainers:u32] 87 86 [cContainers × ABCONTAINER]
```

`HrGetAbContainers` (`0x7F4D4423`) allocates `cContainers * 0xDC` from the
count dword and memcpys the blob whole, so the count and the blob length have
to agree — a short blob leaves the tail of the last record reading
uninitialised heap.

### `ABCONTAINER`

0xDC (220) bytes. Offsets are the ones MOSABP32 reads:

| Offset | Size | Contents | Read by |
|---:|---:|---|---|
| `0x00` | 4 | container id | all three sites, as the lookup key |
| `0x04` | 4 | never read | — |
| `0x08` | 0x41 | display name | `FUN_7F4DA4E6`, → `PR_DISPLAY_NAME` |
| `0x49` | 0x87 | second string | `FUN_7F4DA522`, → tag `0x6013001E` |
| `0xD0` | 4 | content count | `FUN_7F4DA2E6`, → `PR_CONTENT_COUNT` |
| `0xD4` | 4 | never read | — |
| `0xD8` | 4 | display type | `FUN_7F4DA2E6`, → `PR_DISPLAY_TYPE` |

The string field widths are bounded by the gap to the next field the client
reads, not by anything that states a length.

What the `0x6013001E` string is meant to hold is unidentified — nothing in
MOSABP32 reads it beyond handing it to the caller, and `FUN_7F4D39CB`
substitutes an empty string when the lookup misses.

`FUN_7F4DA2E6` turns each record into one container-table row of seven
properties: `PR_DISPLAY_NAME`, `PR_ENTRYID` (a `_cont_entryid`, cb 0x20),
`PR_CONTENT_COUNT`, `PR_OBJECT_TYPE` = 4 `MAPI_ABCONT`, `PR_DISPLAY_TYPE`,
`PR_CONTAINER_FLAGS` = `0x29` (`AB_RECIPIENTS | AB_UNMODIFIABLE |
AB_NOT_DEFAULT`) and `PR_INSTANCE_KEY`.

### `_cont_entryid`

0x20 bytes, built client-side by `MOSMUTIL!HrBuildCeid` (`0x7E99108C`) from the
record's id — this server never puts one on the wire, but `FUN_7F4D39CB` keys
the container's own GetProps on it and reads the id back from `+0x1C`.

| Offset | Size | Contents |
|---:|---:|---|
| `0x00` | 4 | `abFlags`, zeroed |
| `0x04` | 16 | provider MAPIUID, the same one `_usr_entryid` carries |
| `0x14` | 4 | `2` — version |
| `0x18` | 4 | `0` — type |
| `0x1C` | 4 | container id |

## 4. `GetUserDetails` (method 2)

### Request

`CAbConnection::HrGetUserDetails` (`0x7F4D4611`) drives the MPCCL request
object:

| Call | Wire |
|---|---|
| `+0x24 PackSendBytes(ueid+0x77, strlen+1)` | `04 <cb> <member id + NUL>` |
| `+0x28 PackSendDword(tags->cValues)` | `03 <cValues:u32>` |
| `+0x24 PackSendBytes(tags->aulPropTag, cValues*4)` | `04 <cb> <cValues × u32>` |
| `+0x18 PackReceiveDword(&status)` | `83` |
| `+0x40` (set stream flag) | `85` |
| `+0x48 Dispatch(&iterator)` | — |

```
class=<selector of 00028B22> selector=0x02
payload: 04 <cb> <member id + NUL> 03 <cValues> 04 <cb> <tags…> 83 85
```

Note the member id **includes its NUL** in the byte count (`strlen + 1`), unlike
the strings in the reply.

### Reply

```
83 [status:u32] 87 86 [blob]
```

`status` must be `0`. `HrGetUserDetails` tests it right after the wait and
returns it verbatim as its HRESULT, before touching the blob.

The dynamic tag must be **`0x86`, not `0x88`**. The caller waits through request
vtable `+0x10` (`MPCCL!FUN_04604921`), which blocks on `MsgWaitForSingleObject`
over the request's `+0x24` event. Only `SignalRequestCompletion` — the `0x86`
branch of `ProcessTaggedServiceReply` — sets that event; `0x88` signals `+0x28`
and `+0x2C` only, so a `0x88` reply parks the sheet's thread with the hourglass
up.

The blob is then read out of the stream chunk:

```c
iterator->vtbl[0x1c](&chunk);       // MPCCL DispatchRequestOnPipe 0x04604E5F
cb  = chunk->vtbl[0x10](chunk);     // 0x04606335: return chunk[0x10]
if (cb) ptr = chunk->vtbl[0x0c](chunk);   // 0x04606328: chunk[0xc] + chunk[0x20]
FUN_7F4DD770(&rowset, ptr, cb, tags, 0);
```

---

## 5. Property blob format

`FUN_7F4DD770` (`0x7F4DD770`) parses it:

```
[count:u32]
per requested tag, in request order:
    variable-length type → [cb:u32][cb bytes]
    fixed-width type     → cb bytes, width implied by the type
```

`count` must equal the request's `cValues`, or the call fails with `0x80040118`
before any value is read.

**Nothing in the blob identifies a tag.** The parser walks the client's *own*
request array and applies `tags[i]` to whatever sits at the cursor. A skipped
value therefore shifts every later field by one; a value must be emitted for
every requested tag, empty if there is nothing to say. This is the same
no-gaps rule SVCPROP enforces on the tree channel, for a different reason.

`FUN_7F4DD472` (`0x7F4DD472`) decides which types carry the `[cb:u32]` prefix —
only three do:

| Type | | Wire |
|---|---|---|
| `0x1E` | `PT_STRING8` | `[cb][cb bytes]`, **no NUL counted** |
| `0x1F` | `PT_UNICODE` | `[cb][cb bytes]` |
| `0x102` | `PT_BINARY` | `[cb][cb bytes]` |

`FUN_7F4DD4C4` (`0x7F4DD4C4`) gives the widths of the rest:

| Type | | Bytes |
|---|---|---:|
| `0x02` | `PT_I2` | 2 |
| `0x03` | `PT_LONG` | 4 |
| `0x04` | `PT_R4` | 4 |
| `0x05` | `PT_DOUBLE` | 8 |
| `0x06` | `PT_CURRENCY` | 8 |
| `0x07` | `PT_APPTIME` | 8 |
| `0x0B` | `PT_BOOLEAN` | 2 |
| `0x14` | `PT_I8` | 8 |
| `0x40` | `PT_SYSTIME` | 8 |
| `0x48` | `PT_CLSID` | 16 |

`PT_UNSPECIFIED` (0), `PT_NULL` (1), `PT_ERROR` (0x0A) and `PT_OBJECT` (0x0D)
return `0x80040304` and abort the whole call. **A `PT_ERROR` value cannot be
used to signal "property not found"** — the client never reads a type off the
wire, so the only way to say "nothing here" is an empty value of the requested
type.

`PT_STRING8` lengths exclude the terminator: `FUN_7F4DD182` (`0x7F4DD182`)
allocates `cb + 1` through the caller's `AllocateMore`, memcpys `cb` bytes and
writes the NUL itself.

`PT_UNICODE` is handled inconsistently in the original: it allocates `cb*2 + 2`,
copies `cb` bytes, and terminates at `dst + cb*2`, i.e. it mixes a byte count
with a character count. The sheet uses no `PT_UNICODE` tag, so the branch is
never exercised.

---

## 5.5 `QueryWWRows` (method 12)

The member list behind a container. `HrQueryWWRows` (`0x7F4D4A18`):

```
request:  03 <handle:u32>          table handle, 0 to open one
          04 <cb> <name + NUL>     prefix to match, empty lists the container
          03 <u32>                 unidentified
          03 <cRows:u32>           rows wanted — the client asks 45
          03 <cValues:u32>
          04 <cb> <cValues × u32>  requested tags
          83 83 83 83 83 85

reply:    83 [status] 83 [p6] 83 [p9] 83 [cRows] 83 [p8] 87 86 [blob]
```

Reply dword order is the five `+0x18` call sites in sequence. Slot 1 is the
status — `CMP [ESP+0x28], 0` right after the wait, returned verbatim as the
HRESULT on a mismatch — and slot 4 is the row count that sizes the rowset and
gates decompression. Slots 2, 3 and 5 are the caller's `param_6`, `param_9` and
`param_8` out-params, in that order; what they carry is unidentified. Serving 0
for all three is consistent with a result delivered in one page with no table
left open, and the client accepts it.

### The row blob is MSZIP

`HrUncompressWWData` (`0x7F4D53A9`) hands the blob straight to
`MOSMUTIL!HrDecompress` with no uncompressed path, so even one row has to be
compressed. The codec is **MSZIP**: `0x7E994D10` rejects anything whose first
two bytes are not `CK`, and MOSMUTIL carries all three deflate tables — the
code-length order at `0x7E99C4C70`, the length and distance bases at
`0x7E99C4CE8` and `0x7E99C4D68`. `CK` followed by a raw deflate stream is what
it decodes, which `zlib` produces directly.

The decompressed buffer is a fixed **27000** bytes (`HrUncompressWWData`
allocates it before inflating), so the uncompressed rows have to fit it.
`FUN_7E993620` also rejects the call outright when the *compressed* length
exceeds that buffer by more than 7.

Decompressed, the blob is one §5 property blob per row, concatenated —
`HrBuildWWSrowset` (`0x7F4D52F8`) walks it with the same `ParsePropValueBlob`
(`0x7F4DD770`) method 2 uses, so the no-gaps rule applies to every row. At a
row count of 0 it allocates an empty rowset and reads nothing, so an empty
result needs no blob at all.

The same codec sits under MOSRXP's compressed streams (docs/MOSRXP.md §5),
which is what attachment bodies ride.

## 5.6 `QueryRestrictRows` (method 13)

Name resolution — what the client sends when a name typed into a To: field has
to become a recipient. `HrQueryRestrictRows` (`0x7F4D4C33`) packs the same
request as method 12 with a serialised restriction in front of the name, and
answers with the same five dwords and compressed rowset:

```
request:  03 <handle:u32>
          04 <cb> <CSRestriction>
          04 <cb> <name + NUL>
          03 <u32>  03 <cRows:u32>  03 <cValues:u32>
          04 <cb> <cValues × u32>
          83 83 83 83 83 85
```

### Serialised `CSRestriction`

`FUN_7F4DDB9B` (`0x7F4DDB9B`) writes two shapes and rejects everything else
with `E_INVALIDARG`:

```
RES_PROPERTY (4):  <node>
RES_AND (0):       [0:u32][cSubRestrictions:u32] <node> × cSubRestrictions
```

A node (`FUN_7F4DDC29`) is:

```
[rt:u32][relop:u32][ulPropTag:u32][SPropValue][value data]
```

`FUN_7F4DDEBB` writes the `SPropValue` as its **16 raw struct bytes** — the tag,
the alignment padding and the union, so the client's own heap and stack pointers
travel on the wire and mean nothing on this side. A `PT_STRING8`, `PT_UNICODE`
or `PT_BINARY` value then appends `[cb:u32][cb bytes]`, `cb` from `lstrlenA`
with **no terminator**; a fixed-width value has no trailing bytes and sits in
the union at `+8`.

A 5-character name therefore serialises to 37 bytes — 12 + 16 + 4 + 5 — which
is what the client sent live 2026-08-14.

The restriction is `RES_PROPERTY RELOP_EQ` on **`PR_ANR`** (`0x360C001E`),
MAPI's ambiguous-name property. No member record has such a field: it stands
for "whatever a person is called", so both the member id and the display name
have to answer to it, and an ambiguous prefix returns every candidate for the
client to disambiguate.

## 6. The Member Properties sheet

`FUN_7F4D1170` runs `PropertySheetA` with caption string `0x468` and three
pages:

| Dialog | Caption | Page proc |
|---:|---|---|
| 100 | General | `0x7F4D122F` |
| 101 | Personal | `0x7F4D12D8` |
| 102 | Professional | `0x7F4D136C` |

Each page's `WM_INITDIALOG` calls `FUN_7F4D1400(ctrl_id, tag)` per field, which
finds the tag in the fetched `_SRow` and `WM_SETTEXT`s the control.

| Page | Ctrl | Label | Tag | Type |
|---|---:|---|---|---|
| General | 301 | Member ID: | `0x3003001E` | `PR_EMAIL_ADDRESS` |
| General | 302 | First name: | `0x600D001E` | |
| General | 303 | Last name: | `0x600E001E` | |
| General | 304 | City/Town: | `0x6000001E` | |
| General | 305 | State/Province: | `0x6001001E` | |
| General | 306 | Country: | `0x600F0003` | validation list |
| Personal | 307 | Date of birth: | `0x6003001E` | free text |
| Personal | 308 | Sex: | `0x6004001E` | free text |
| Personal | 309 | Marital status: | `0x60110003` | validation list |
| Personal | 310 | Language: | `0x60100003` | validation list |
| Personal | 311 | Interests: | `0x6007001E` | |
| Professional | 312 | Job description: | `0x6008001E` | |
| Professional | 313 | Company name: | `0x6009001E` | |
| Professional | 314 | City/Town: | `0x600A001E` | |
| Professional | 315 | State/Province: | `0x600B001E` | |
| Professional | 316 | Country: | `0x60120003` | validation list |

Date of birth and Sex are plain `PT_STRING8` — the client formats neither, so
whatever text is sent appears verbatim.

The four `PT_LONG` fields are catalogue ids, not text. `FUN_7F4D1400` resolves
them through `FUN_7F4DC605(list, code, &text)` against three cached validation
lists in `.bss` — `DAT_7F4E4000` (country, shared by both Country fields),
`DAT_7F4E4010` (language) and `DAT_7F4E4020` (marital status). Each is a
16-byte descriptor `{kind:u32, count:u32, data:ptr, …}` whose row stride depends
on `kind` (1 → `0x48`, 2 → `0x2C`, 3 → `0x18`). Nothing inside the DLL fills
them: `HrGetValidationList` has zero internal callers, so the lists arrive only
when a host calls that export. **Until `GetValidationList` (method 1) is served,
those four fields render blank** — `FUN_7F4D1400` returns early when the lookup
misses, leaving the control untouched. Every other field is unaffected.

There is a fourth dialog, `INTERNETDETAILS` (ids 317 `&Name:` and 301
`&E-mail address:`), not part of this sheet.

### Requested tags

The master `SPropTagArray` is at `0x7F4E8198` with `cValues = 26`.
`FUN_7F4D307D` copies it minus any tag with type `PT_NULL` plus six named
exclusions — `0x0FF60102`, `0x0FFF0102` `PR_ENTRYID`, `0x300B0102`
`PR_SEARCH_KEY`, `0x3A06001E` `PR_GIVEN_NAME`, `0x3A11001E` `PR_SURNAME`,
`0x3A20001E` `PR_TRANSMITABLE_DISPLAY_NAME` — and that 20-tag result is what
reaches the wire, in this order:

```
0x0FFE0003  PR_OBJECT_TYPE
0x3001001E  PR_DISPLAY_NAME
0x3003001E  PR_EMAIL_ADDRESS
0x3002001E  PR_ADDRTYPE
0x600D001E  0x600E001E  0x6000001E  0x6001001E  0x600F0003
0x6003001E  0x6004001E  0x60110003  0x60100003  0x6007001E
0x6008001E  0x6009001E  0x600A001E  0x600B001E  0x60120003
0x39000003  PR_DISPLAY_TYPE
```

`PR_OBJECT_TYPE`, `PR_DISPLAY_NAME`, `PR_ADDRTYPE` and `PR_DISPLAY_TYPE` are
fetched and never displayed. They still need values — see the no-gaps rule
above. `MAPI_MAILUSER` (6) and `DT_MAILUSER` (0) are the consistent pair for a
single member.

---

## 7. Not implemented

`GetValidationList` (1) is the one method with a visible effect on this sheet:
it is what turns the four catalogue codes into Country / Language / Marital
status text. Its request and reply shapes are RE'd only as far as
`HrGetValidationList` (`0x7F4D5043`) and the `FUN_7F4DC605` row strides; the
`VALLIST` enum and the per-row layout for each `kind` are not pinned.

`UpdateUserDetails` (11) backs an editable sheet — the pages here are read-only
so nothing sends it. `HrQueryWWRows`, `HrQueryRestrictRows`, `HrQueryRowsMore`,
`HrEnumDistList` and `HrCloseTable` belong to the MAPI address-book
browse/lookup surface, reached through `ABProviderInit` rather than this sheet.

`HrQueryRowsMore` (15) pages an open table and `HrEnumDistList` (14) expands a
distribution list; both share `QueryWWRows`' compressed row blob (§5.5) and are
unserved.

`HrCloseTable` (9) releases a table a row query opened:

```
request:  03 <handle:u32> 83
reply:    83 [status:u32] 87
```

It returns the status verbatim as its HRESULT. Observed live right after a
method 13 resolution.
