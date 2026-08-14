# MOSRXP — MSN remote mail transport

Client side of the `MOSRXP` service, reverse-engineered from `MOSRXP32.DLL`
(Windows 95 RTM, 1995-07-11, 56832 bytes, `WINDOWS\SYSTEM\MOSRXP32.DLL`).
Like `MOSABP32.DLL` it ships with Windows 95 itself, not with the MSN client
update, so a `binaries/` tree assembled from the MSN files alone does not
contain it.

Addresses are at the DLL's preferred base `0x7F430000`. `MOSMUTIL.DLL` is at
`0x7E990000`.

---

## 1. What it is

Version resource: *"MOS Remote Transport DLL"*. It is the MAPI **transport
provider** (`XPProviderInit`, ordinal 100) behind the Windows Messaging /
Exchange inbox when the MSN mail service is installed — the remote-mail path
that downloads message *headers* over the Marvel connection and fetches bodies
on demand.

Its wire client is the C++ class `CConn`; all 84 members carry decorated names,
so the class reads directly. One `CConn` holds the MPC marshaller, a critical
section, the pending iterator, and the transmit buffer.

`MOSMUTIL.DLL` supplies the header property-tag array and the stream
compressor/decompressor.

---

## 2. Framing

`CConn::HrGetMethod` (`0x7F431967`) is the only site that opens the service:

```c
marshal->vtbl[0x24]("MOSRXP",            // svc_name
                    &IID_00028B20,       // one IID, not an array
                    &service,
                    2,                   // version
                    0);                  // no parameter string
service->vtbl[0x0c](iMethod, &method);   // GetMethod(ServiceMethod)
```

Pipe open is `svc_name="MOSRXP" ver_param="U" version=2`.

**Discovery must contain IID `00028B20-0000-0000-C000-000000000046`** (the GUID
at `0x7F43C950`). It is the only interface the DLL resolves; without it slot
`0x24` returns `E_NOINTERFACE` and no request ever reaches the wire.

The marshaller itself is the same one MOSABP uses: `CoCreateInstance(CLSID
00028B07 → IID 00028B08)` at `0x7F43C7C0`/`0x7F43C7D0`.

A request's `msg_class` is the selector the server assigned that IID in the
discovery reply; `selector` is the `ServiceMethod` number verbatim.

### `enum ServiceMethod`

Read off the immediate each member pushes before `HrGetMethod`:

| # | `CConn` member | Address |
|---:|---|---|
| 0 | `HrGetConnInfo` | `0x7F435991` |
| 1 | `HrOpenInbox` | `0x7F4319F3` |
| 2 | `HrCloseInbox` | `0x7F431ADE` |
| 3 | `HrInitTransmit` | `0x7F4334A4` |
| 4 | `HrSendBlock` | `0x7F4354F5` |
| 5 | `HrGetHeaders` | `0x7F431B9A` |
| 6 | `HrDelMessages` | `0x7F431EE3` |
| 7 | `HrGetMessage` | `0x7F431D6F` |
| 8 | `HrGetFirstMessage` | `0x7F43207B` |
| 9 | `HrFlagServerMessage` | `0x7F431FCD` |

Every member drives the MPCCL request object through the same vtable slots as
`CAbConnection` (docs/MOSABP.md §4):

| Slot | Call | Wire |
|---|---|---|
| `+0x24` | PackSendBytes | `04 <cb> <bytes>` |
| `+0x28` | PackSendDword | `03 <u32>` |
| `+0x18` | PackReceiveDword | `83` |
| `+0x14` | PackReceiveBytes | `84` |
| `+0x40` | set stream flag | `85` |
| `+0x48` | Dispatch | — |

`+0x48` writes nothing: every request length below matches its member's slot
sequence exactly with dispatch contributing zero bytes, and `0x85` tracks
`+0x40` alone. Sizes verified live 2026-08-14 against the client — methods 0, 1,
2, 5 and 7 landed at 2, 2, 1, 3 and 16 payload bytes.

The reply's first receive dword is always the status the member returns as its
HRESULT; it is tested before any blob is touched.

---

## 3. `MOS_ENTRYID`

12 bytes, opaque to the client. It is `memcpy`d out of a header record or a
`GetFirstMessage` reply and handed straight back to `GetMessage`,
`DelMessages` and `FlagServerMessage`; nothing in the DLL reads inside it.
`FUN_7F43113E` (`0x7F43113E`) copies exactly `0xC` bytes into the message's
`PR_ENTRYID`.

---

## 4. Methods

### 0 — `GetConnInfo`

```
request:  83 84
reply:    83 [status:u32] 87 84 [cb] [CONNINFO]
```

`CONNINFO` is 0xB8 bytes (§4.1). `HrGetConnInfo` caches it on the connection and
never asks twice; `HrSendMessage` stamps it on every outgoing message as
`PR_SENDER_ENTRYID`.

The variable param rides *behind* the `0x87` end-of-static marker, the shape
DIRSRV's GetDeidFromGoWord already answers `84` with.

#### 4.1 `CONNINFO`

184 bytes — the same structure `MOSMUTIL!HrBuildUeid` (`0x7E991036`) builds for
the address book, and the same length (docs/MOSABP.md §3):

| Offset | Size | Contents |
|---:|---:|---|
| `0x00` | 4 | `abFlags`, zeroed |
| `0x04` | 16 | provider MAPIUID `1BECBA6C-5F92-101B-B93D-00000B70346A` |
| `0x14` | 4 | `2` — entry-id version |
| `0x18` | 4 | `EIDTYPE` |
| `0x1C` | 0x5B | display name |
| `0x77` | 0x41 | member name |

`EIDTYPE` 1 keys the id on the member name at `+0x77`, which is the form
MOSABP32 routes to its `GetUserDetails` method 2; type 4 would send it down the
account-handle path instead.

### 1 — `OpenInbox`

```
request:  83 83
reply:    83 [status:u32] 83 [value:u32] 87
```

`HrOpenInbox(fConnect, &value)` returns `value` to its caller only when
`status == 0`. `fConnect` never reaches the wire — it is `HrGetMethod`'s
"connect first if the pipe is down" flag.

`value` is unidentified. No call site for it survives in MOSRXP32 — the caller
is outside the DLL — and client behaviour does not pin it down: two background
polls served the same `0` went different ways, the first closing the inbox
without fetching and the next going on to `GetHeaders` regardless (observed
live 2026-08-14). Whatever gates the fetch, it is not this dword. The message
count is the reading that fits the name, and nothing observed contradicts it.

### 2 — `CloseInbox`

```
request:  83
reply:    83 [status:u32] 87
```

### 3 — `InitTransmit`

```
request:  03 [cbBlock:u32] 83
reply:    83 [status:u32] 87
```

`HrSendMessage` calls it with `0x1000`; that is the transmit buffer size the
client will use for the blocks that follow.

### 4 — `SendBlock`

```
request:  03 [iBlock:u32] 03 [fLast:u32] 04 <cb> <bytes> 83
reply:    83 [status:u32] 87
```

`iBlock` counts from 0 and increments on each successful block. The payload is
the raw serialised message (§5) split at buffer boundaries — the split is not
record-aligned, so the concatenation of every block's bytes is the message.
`HrCompleteTransmit` sends the last block with `fLast=1`.

### 5 — `GetHeaders`

```
request:  83 83 85
reply:    83 [status:u32] 83 [cHeaders:u32] 87 86 [blob]
```

No send parameters: the reply is the whole inbox header list. The blob is §6.
`cHeaders` comes from the second receive dword, **not** from the blob.

Reply must end in `0x86`, not `0x88` — same constraint as MOSABP: the caller
waits on the request's completion event, which only the `0x86` branch sets.

### 6 — `DelMessages`

```
request:  03 [cMessages:u32] 04 <cMessages*12> <MOS_ENTRYID × cMessages> 83
reply:    83 [status:u32] 87
```

Driven by `FUN_7F4361BB` (`0x7F4361BB`): before each header download the client
queries its own store for rows with `PR_MSG_STATUS & 0x2000`
(`MSGSTATUS_REMOTE_DELETE`) and deletes them server-side in one call.

### 7 — `GetMessage`

```
request:  04 0C <MOS_ENTRYID> 83 85
reply:    83 [status:u32] 87 86 [message blob]
```

The blob is a §5 message. `AddRcvdProps` then stamps the receive-side props and
the message is saved into the store.

### 8 — `GetFirstMessage`

```
request:  83 85
reply:    83 [status:u32] 87 86 [MOS_ENTRYID:12][message blob]
```

Same as method 7 with the entry id prefixed, for "give me whatever is next"
polling. `HrGetFirstMessage` waits in 250 ms slices and pumps messages between
them, so a slow reply does not freeze the UI.

### 9 — `FlagServerMessage`

```
request:  04 0C <MOS_ENTRYID> 03 [flags:u32] 83
reply:    83 [status:u32] 87
```

---

## 5. Message serialisation

`CConn::HrDSrlMsg` (`0x7F4321C9`) and its mirror `HrTransmitMsg`
(`0x7F4335D0`) define one format used in both directions:

```
message := prop_list      // header props   (FIsHeaderProp true)
           recip_list
           prop_list      // body props     (FIsHeaderProp false)
           attach_list
```

`HrTransmitHdr` sends the props `MOSMUTIL!FIsHeaderProp` accepts,
`HrTransmitBody` sends the rest, so the split is by tag, not by meaning.
Both sides skip tags whose *id* falls in `0x0E00–0x0FFF`, `0x6000–0x67FF` or
`0x7C00–0x7FFF` — the transport-owned and store-owned ranges.

### `prop_list`

```
[cValues:u32] [prop × cValues]
```

### `prop`

`CConn::HrDSrlProp` (`0x7F432435`); the standalone header-side copy is
`FUN_7F431183` (`0x7F431183`) and both agree.

```
[ulPropTag:u32] [value]
```

There is no length field and no type byte: the low 16 bits of the tag give the
width.

| Type | Value encoding |
|---|---|
| `0x02` PT_I2 | 2 bytes |
| `0x03` PT_LONG | 4 |
| `0x04` PT_R4 | 4 |
| `0x05` PT_DOUBLE | 8 |
| `0x06` PT_CURRENCY | 8 |
| `0x07` PT_APPTIME | 8 |
| `0x0B` PT_BOOLEAN | 2 |
| `0x14` PT_I8 | 8 |
| `0x1E` PT_STRING8 | ASCIIZ, terminator included |
| `0x1F` PT_UNICODE | UTF-16LE, NUL included |
| `0x40` PT_SYSTIME | 8 (FILETIME) |
| `0x48` PT_CLSID | 16 |
| `0x102` PT_BINARY | `[cb:u32][cb bytes]` |

Any other type aborts the parse with `0x1A`. No multi-value type is supported.

A tag with id `>= 0x8000` is a **named property** and carries its name inline
before the value:

```
[ulPropTag:u32] [reserved:u32] [MAPIUID:16] [ulKind:u32]
    ulKind == 0 → [lID:u32]
    ulKind == 1 → [name: UTF-16LE, NUL-terminated]
[propType:u16] [value]
```

The client resolves it through `GetIDsFromNames` and rebuilds the local tag as
`(resolved_id & 0xFFFF0000) | propType`.

### `recip_list`

```
[cRecips:u32] [recip × cRecips]
recip := [cValues:u32] [prop × cValues]
```

Each recipient is one `ADRENTRY`.

### `attach_list`

`CConn::HrDSrlAttach` (`0x7F432CD3`):

```
[cAttach:u32] [attach × cAttach]
attach := [cValues:u32]
          prop            // must be PR_ATTACH_METHOD 0x37050003, else 0x80004005
          <method body>
          [prop × (cValues-2)]
```

| `PR_ATTACH_METHOD` | Body |
|---:|---|
| 1 ATTACH_BY_VALUE | `[ulPropTag:u32]` then `stream` |
| 5 ATTACH_EMBEDDED_MSG | `[ulPropTag:u32][IID:16]` then a nested `message` |
| 6 ATTACH_OLE | `[ulPropTag:u32][IID:16]` then `storage` (IID `0x7F43C0C0`) or `stream` (IID `0x7F43C0D0`) |

### `stream`

`CConn::HrDSrlStream` (`0x7F432FB6`) — the only compressed part of the format:

```
[cbChunkMax:u32] [cChunks:u32] [chunk × cChunks]
chunk := [cbCompressed:u32] [compressed bytes]
```

Each chunk decompresses to at most `cbChunkMax` bytes through
`MOSMUTIL!HrDecompress`, and the decompressor is reset between chunks.

That codec is **MSZIP** — `CK` followed by a raw deflate stream. See
docs/MOSABP.md §5.5 for the identification.

---

## 6. Header blob (method 5)

A flat concatenation, no count of its own:

```
header := [MOS_ENTRYID:12] [cValues:u32] [prop × cValues]
```

The client writes `[cHeaders:u32]` (the reply's second dword) followed by the
blob verbatim into a spool file (`FUN_7F4398F2`), then `FUN_7F439959` reads it
back and turns each record into one spooler row:

- `PR_ENTRYID` = the 12 entry-id bytes
- `0x60000003` = the record's index in the list
- every serialised prop
- `PR_MESSAGE_DOWNLOAD_TIME` (`0x0E180003`) synthesised from
  `PR_MESSAGE_SIZE / CConn::CbConnectionXferPerSecond()` when
  `PR_MESSAGE_SIZE` is present

### Header property set

`MOSMUTIL!PSptaHdr` (`0x7E991297`) returns the 12-tag array at `0x7E99C438`;
`FIsHeaderProp` is a linear search over it. This is the set a header record is
expected to carry:

| Tag | Name |
|---|---|
| `0x0FFE0003` | PR_OBJECT_TYPE |
| `0x0E170003` | PR_MSG_STATUS |
| `0x0E070003` | PR_MESSAGE_FLAGS |
| `0x001A001E` | PR_MESSAGE_CLASS |
| `0x00170003` | PR_IMPORTANCE |
| `0x0042001E` | PR_SENT_REPRESENTING_NAME |
| `0x0E04001E` | PR_DISPLAY_TO |
| `0x00360003` | PR_SENSITIVITY |
| `0x0E1B000B` | PR_HASATTACH |
| `0x0037001E` | PR_SUBJECT |
| `0x0E060040` | PR_MESSAGE_DELIVERY_TIME |
| `0x0E080003` | PR_MESSAGE_SIZE |

---

## 7. Send path

`CConn::HrSendMessage` (`0x7F4332E6`) stamps the sender identity on the
outgoing message before serialising it, from the `CONNINFO` the connection
holds:

| Tag | Value |
|---|---|
| `0x0C190102` PR_SENDER_ENTRYID | 0xB8-byte `CONNINFO` blob |
| `0x0C1A001E` PR_SENDER_NAME | member display name |
| `0x0C1F001E` PR_SENDER_EMAIL_ADDRESS | member id |
| `0x0C1E001E` PR_SENDER_ADDRTYPE | `"MSN"` |
| `0x0C1D0102` PR_SENDER_SEARCH_KEY | `"MSN:<member id>"` |
| `0x58000003` | `GetACP()` |
| `0x58010003` | `GetOEMCP()` |

then runs `InitTransmit(0x1000)` → `HrTransmitMsg` → `HrCompleteTransmit`.

`HrCompleteTransmit` (`0x7F43566C`) sends the final block, then walks the
recipient table and sets `PR_RESPONSIBILITY` (`0x0E0F000B`) to 1 on every
recipient whose `PR_ADDRTYPE` matches one of the five address types at
`0x7F43CE90`: `MSN`, `MSNLIST`, `MSNINET`, `INTERNET`, `SMTP` — the set this
transport claims delivery for.

---

## 8. Download flow

`FUN_7F437831` (`0x7F437831`) is the worker thread behind "check for new mail":

1. `HrConnect` if not already online
2. `FUN_7F4361BB` — `DelMessages` for every row flagged `MSGSTATUS_REMOTE_DELETE`
3. `HrGetHeaders`
4. `HrCloseInbox`
5. spool `[cHeaders][blob]` to a temp file, then deliver each row to the spooler
6. read profile prop `0x6601000B`; if set, `Disconnect(1, 0x80)` — "disconnect
   after downloading"

Progress strings are resource ids `0x7D1`–`0x7DC`, pushed through
`FUN_7F4366EA`.

Observed live 2026-08-14, downloading and opening one message:

```
OpenInbox (1) → GetHeaders (5) → CloseInbox (2)
OpenInbox (1) → GetMessage (7) → GetConnInfo (0)
```

`GetConnInfo` follows the body fetch rather than preceding it: the transport
asks for the blob the first time it needs a sender identity, then caches it for
the life of the connection.

## 8.1 Whole-message download

A second, distinct flow — retrieve-and-delete rather than headers-first —
observed the same day:

```
OpenInbox (1) → 1 waiting
GetFirstMessage (8) → GetConnInfo (0) → DelMessages (6)
GetFirstMessage (8) → MAPI_E_NOT_FOUND
CloseInbox (2)
```

Method 8 is the loop's cursor: each pass takes whatever is next, deletes it by
the entry id the reply prefixed, and asks again. **`0x8004010F`
(MAPI_E_NOT_FOUND) is how the loop ends** — served it on an empty mailbox the
client closes the inbox instead of retrying. Any other error status, or a
success with no blob, would leave it spinning or fail the download.
