# MOSVIEW / MediaView 1.4 Format Notes

## Scope

`MOSVIEW.EXE` is not parsing Blackbird `.ttl` files directly. Its title open
path is:

1. `MOSVIEW.EXE`
2. `MVCL14N.DLL`
3. `MVTTL14C.DLL`

The actionable target format for MOSVIEW is therefore the MediaView 1.4 title
pipeline implemented by `MVTTL14C.DLL`, with Blackbird acting only as a
possible logical source model for a later converter.

## Evidence Base

The notes below are grounded in the following code paths recovered with Ghidra:

- `MOSVIEW.EXE`
  - `FUN_7f3c61ce`: main MediaView construction path
  - `FUN_7f3c5ff4`: transient title open + pre-notify opcode `8`
  - `FUN_7f3c60a5`: transient title open + pre-notify opcodes `9` and `0xb`
- `MVCL14N.DLL`
  - `hMVTitleOpen` at `0x7e8851d0`
  - `hMVTitleOpenEx` at `0x7e8851f0`
  - `MVTitlePreNotify` at `0x7e885130`
  - `MVTitleNotifyLayout` at `0x7e885180`
  - `MVTitleClose` at `0x7e8853a0`
  - `lMVTitleGetInfo` at `0x7e885ac0`
- `MVTTL14C.DLL`
  - `TitleOpenEx` at `0x7e842d4e`
  - `TitleGetInfo` at `0x7e842558`
- `MPCCL.DLL`
  - `DllGetClassObject` at `0x046016f9`
  - session `QueryInterface` at `0x04601d25`
  - service attach / pipe open path at `0x04601f75` and `0x0460263f`
- `DSNED.NED`
  - `FUN_7f573273`: service-node registration via `InitializeEcig`

Static corroboration from `BLACKB/AUTHOR.HLP` also matters here:

- `Blackbird includes utilities to convert HTML, BBML, and MediaView files to Blackbird Data Format files.`

That matches the code evidence: MediaView is an older, distinct source format,
not a renamed Blackbird `.ttl`.

## MOSVIEW Open Pipeline

`MOSVIEW.EXE!FUN_7f3c61ce` drives the steady-state open path used to build a
view instance:

1. Format a title path string.
2. Call `hMVTitleOpen`.
3. Call `lpMVNew` on the returned title handle.
4. Call `MVSetKerningBoundary(0x24)`.
5. Call `lMVTitleGetInfo(title, 0x6f, 0, ...)`.
6. Feed that result to `hMVSetFontTable`.
7. Call `lMVTitleGetInfo(title, 0x69, 0, ...)`.
8. Feed that result to `MVSetFileSystem`.
9. Call `vaMVGetContents(title)`.
10. Enumerate selector `0x07` records of size `0x2b`.
11. Enumerate selector `0x08` records of size `0x1f`.
12. Enumerate selector `0x06` records of size `0x98`.
13. Enumerate selector `0x04` strings.
14. Fetch selector `0x01`.
15. Fetch selector `0x02`.

Other MOSVIEW helpers do short-lived opens followed by parser notifications:

- `FUN_7f3c5ff4`:
  - `hMVTitleOpen`
  - `MVTitlePreNotify(title, 8, payload, size)`
  - `MVTitleClose`
- `FUN_7f3c60a5`:
  - `hMVTitleOpen`
  - `MVTitlePreNotify(title, 9, ..., 4)`
  - `MVTitlePreNotify(title, 0xb, 0, 0)`
  - `MVTitleClose`
- Layout-time code later calls `MVTitleNotifyLayout`.

The important point is that MOSVIEW is a consumer of parser-provided title
selectors. It is not walking Blackbird OLE storages.

One additional detail matters for stock behavior: `MOSVIEW.EXE!FUN_7f3c61ce`
does not pass a raw Windows path to `MVTTL14C`. It formats the parser open
token as `:2[%s]0`, where slot `2` is the MediaView parser and the bracketed
string is the underlying Windows path.

## `MVCL14N` Parser Dispatch Contract

`MVCL14N!hMVTitleOpen` is only a convenience wrapper:

```c
hMVTitleOpen(path) -> hMVTitleOpenEx(path, 0, 0)
```

`MVCL14N!hMVTitleOpenEx` is the real dispatcher:

- If the path begins with `:1` through `:5`, it treats that as an explicit
  parser slot selector.
- Otherwise it scans the registered parser slots until one parser returns a
  non-zero handle.
- Parser DLLs are lazily loaded with `LoadLibraryA`.
- Parser entry points are looked up by name with `GetProcAddress`.
- The required open entry point is `TitleOpenEx`.

Recovered behavior:

- Explicit prefix:
  - `:1foo` -> slot `0`, inner path `foo`
  - `:5foo` -> slot `4`, inner path `foo`
  - any other prefix -> fail
- Lazy slot loading:
  - slot DLL names live in the `s_MVTL14N_DLL_7e8991c0 + slot * 0x88` array
  - current binary strings show at least `MVTL14N.DLL` and `MVTTL14C.DLL`
- Connection handshake:
  - `FUN_7e884f20` optionally calls parser export `TitleConnection` after load

The handle returned to MOSVIEW is not the parser's raw title handle. `MVCL14N`
wraps it in a 12-byte local handle:

```text
MVCLHandle
  +0x04 inner parser title handle
  +0x08 parser slot index
```

Every later thunk resolves the slot from `+0x08`, re-finds the parser export,
and forwards the inner handle at `+0x04`:

- `MVTitlePreNotify` -> `TitlePreNotify`
- `MVTitleNotifyLayout` -> `TitleNotifyLayout`
- `lMVTitleGetInfo` -> `TitleGetInfo`
- `MVTitleClose` -> `TitleClose`

For stock MOSVIEW specifically:

- `DAT_7f3cd2e8 == 2`
- `MOSVIEW.EXE` formats title opens as `:2[%s]0`
- `MVCL14N!hMVTitleOpenEx` strips the leading `:2` and passes `[%s]0` into
  `MVTTL14C!TitleOpenEx`

That means the cache key seen by `MVTTL14C` is based on the parser token
`[%s]0`, not on a bare Windows path string.

For a local file open such as `E:\\MSN Today.m14`, the client-side title string
that actually reaches `MVTTL14C` is:

```text
[E:\MSN Today.m14]0
```

That parser token matters more than the raw filename. The later `MEDVIEW`
request uses this token as the title-name input, and the local cache name is
derived from it.

## `MEDVIEW` Service Boundary

`MVTTL14C.DLL` is not a self-contained on-disk `.m14` parser. It is a client
stub for the server-side `MEDVIEW` service.

Code-proven path:

- `MOSVIEW.EXE!MosViewStartConnection` calls `MVTitleConnection(2, 1, "MEDVIEW")`
- `MVCL14N!MVTitleConnection` loads the parser slot and forwards to parser
  export `TitleConnection`
- `MVTTL14C!TitleConnection` defaults an empty service name to `MEDVIEW`
- `MVTTL14C!hrAttachToService` calls `CoCreateInstance` for
  CLSID `{00028B07-0000-0000-C000-000000000046}` with IID
  `{00028B08-0000-0000-C000-000000000046}`
- `MPCCL.DLL` implements that COM class/interface pair and opens a MOS pipe to
  the requested service name
- `DSNED.NED!FUN_7f573273` registers `DIRSRV`, `CONFLOC`, `MEDVIEW`, and `BBS`
  as service-node types with `InitializeEcig`

The result is a real service boundary, not a local helper callback. Static
request IDs recovered from `MVTTL14C` include:

| request | caller path |
| --- | --- |
| `0` | `TitleValid` |
| `1` | `TitleOpenEx` |
| `2` | `TitleClose` |
| `3` | `TitleGetInfo` remote fallback |
| `4` | `TitleQuery` |
| `5` | `vaConvertAddr` refresh |
| `6` | `vaConvertHash` refresh |
| `7` | `vaConvertTopicNumber` refresh |
| `8` | `WordWheelQuery` |
| `9` | `WordWheelOpenTitle` |
| `0xa` | `WordWheelClose` |
| `0xb` | `WordWheelPrefix` |
| `0xc` | `WordWheelLookup` |
| `0xd` | `KeyIndexGetCount` |
| `0xe` | `KeyIndexGetAddrs` |
| `0xf` | `fKeyIndexSetCount` |
| `0x10` | `HighlightsInTopic` |
| `0x11` | `addrSearchHighlight` |
| `0x12` | `HighlightDestroy` |
| `0x13` | `HighlightLookup` |
| `0x15` | `HfcNear` refresh |
| `0x16` | `HfcNextPrevHfc` refresh |
| `0x17` | notification subscribe |
| `0x18` | notification unsubscribe |
| `0x1a` | `HfOpenHfs` |
| `0x1b` | `LcbReadHf` |
| `0x1c` | `RcCloseHf` / HFS close |
| `0x1d` | `RcGetFSError` |
| `0x1e` | `TitlePreNotify` |
| `0x1f` | attach-time handshake |

Practical implication:

- the cache payload grammar recovered in this repo is real
- but stock compatibility requires satisfying the server-side `MEDVIEW`
  contract that produces the live metadata tuple, address conversions, HFS
  handles, and cache-validation header
- a synthetic cache plus a guessed outer file is therefore not sufficient on
  its own

## MPC Request Builder Surface

Across `MVTTL14C`, the request object returned by the service proxy's
`vtbl+0x0c` method behaves consistently:

| method | inferred wire role | evidence |
| --- | --- | --- |
| `+0x30` | append send-side byte tag `0x01` | `TitleValid`, `TitleOpenEx`, `HfOpenHfs`, `TitlePreNotify` |
| `+0x2c` | append send-side word tag `0x02` | `TitlePreNotify`, `TitleQuery` |
| `+0x28` | append send-side dword tag `0x03` | `TitleOpenEx`, `TitleGetInfo`, `vaConvert*`, `LcbReadHf` |
| `+0x24` | append send-side variable tag `0x04` | `TitleOpenEx`, `HfOpenHfs`, handshake, `TitlePreNotify`, `TitleQuery` |
| `+0x20` | bind recv-side byte tag `0x81` | `TitleValid`, `TitleOpenEx`, `HfOpenHfs`, `LcbReadHf`, `TitleQuery` |
| `+0x1c` | bind recv-side word tag `0x82` | `WordWheelQuery` |
| `+0x18` | bind recv-side dword tag `0x83` | handshake, `TitleOpenEx`, `HfOpenHfs`, `TitleGetInfo`, `TitleQuery` |
| `+0x14` | bind recv-side variable/blob stream | `TitleQuery`, `HighlightsInTopic` |
| `+0x40` | enable dynamic reply capture on the pending handle | `TitleOpenEx`, `TitleGetInfo`, `LcbReadHf`, selector `0x17` subscribe |
| `+0x48` | execute request and return a pending request handle | every wire-using path |

The generic MPC transport from the working server implementation matches this
surface:

- host block = `class` byte, `selector` byte, VLI request id, payload
- send-side payload = tagged params (`0x01`/`0x02`/`0x03`/`0x04`)
- recv-side payload = tagged reply fields (`0x81`..`0x8f`)

## Startup Conversation

The attach sequence for `MEDVIEW` is now pinned down from `hrAttachToService`:

1. `CoCreateInstance` the `MPCCL` marshal object.
2. Call the marshal's attach method with:
   - service name `MEDVIEW`
   - IID table `DAT_7e84c1b0`
   - out pointer for the live service proxy (`DAT_7e84e2f8`)
   - service version `0x1400800a`
3. Receive the generic MPC discovery block from the server:
   - host block class `0x00`, selector `0x00`, request id `0`
   - payload = 17-byte records of `{ IID bytes_le[16], selector_byte }`
4. Issue selector `0x1f` handshake:
   - send byte `0x01`
   - send 12-byte blob:
     - `u32 0x00002000`
     - `u32 0x00004006`
     - `u32 browse_lcid`
   - bind one recv dword
5. Require a nonzero handshake dword reply; zero triggers the stock
   "Handshake validation failed" path and detaches.
6. Send `TitlePreNotify(0, 10, &DAT_7e84e2ec, 6)` over selector `0x1e`.
7. Open five long-lived selector-`0x17` notification subscriptions for types
   `0` through `4`.
8. On teardown, selector `0x18` is used to unsubscribe each type.

The selector-`0x17` subscriptions are not simple one-shot acks. The client
stores the returned pending handle, creates a worker thread, and repeatedly
pulls streamed reply chunks from that pending object. The selector-`0x18`
unsubscribe path sends just the notification-type byte.

Implementation detail from `hrAttachToService`:

- notification types `0`, `1`, and `2` are created without worker threads and
  are pumped on demand by the exported APIs that need them
- notification types `3` and `4` are created with worker threads immediately
  after attach; type `4` is also explicitly enabled via
  `NotificationSubscriber_SetEnabledState(..., 1)`

## Wire Selector Summary

This is the code-proven client-side contract so far:

| selector | client entry | request shape | reply shape | sync vs async |
| --- | --- | --- | --- | --- |
| `0x00` | `TitleValid` | `0x01 title_byte` | `0x81 valid_byte`, end static | synchronous |
| `0x01` | `TitleOpenEx` | `0x04 title_token`, `0x03 cache0`, `0x03 cache1` | `0x81`, `0x81`, `0x83` x5, dynamic body | synchronous |
| `0x02` | `TitleClose` | `0x01 title_byte` | static ack | synchronous |
| `0x03` | `TitleGetInfo` remote path | `0x01 title_byte`, `0x03 kind`, `0x03 arg`, `0x03 caller_ptr` | `0x83 length/status`, optional dynamic body | synchronous |
| `0x04` | `TitleQuery` | byte + word + string + option flags + optional vars | byte + 2 dwords + up to 2 blob streams | synchronous |
| `0x08` | `WordWheelQuery` | `0x01 wordwheel_id`, `0x02 mode_or_flags`, `0x04 query_string` | `0x82 status_word`, dynamic iterator body | synchronous |
| `0x09` | `WordWheelOpenTitle` | `0x01 title_byte`, `0x04 title_name` | `0x81 wordwheel_id`, `0x83 item_count` | synchronous |
| `0x0a` | `WordWheelClose` | `0x01 wordwheel_id` | static ack | synchronous |
| `0x0b` | `WordWheelPrefix` | `0x01 wordwheel_id`, `0x04 prefix_string` | `0x83 prefix_result` | synchronous |
| `0x0c` | `WordWheelLookup` | `0x01 wordwheel_id`, `0x03 ordinal`, `0x03 output_limit` | ack only; string result arrives via notification type `1` | async-refresh |
| `0x0d` | `KeyIndexGetCount` | `0x01 wordwheel_id`, `0x04 key_string` | `0x82 count_word` | synchronous |
| `0x0e` | `KeyIndexGetAddrs` | `0x01 wordwheel_id`, `0x04 key_string`, `0x02 start_index`, `0x02 max_count` | dynamic iterator body of address dwords | synchronous |
| `0x0f` | `fKeyIndexSetCount` | `0x01 wordwheel_id`, `0x04 key_string`, `0x02 count_word` | `0x81 success_byte` | synchronous |
| `0x05` | `vaConvertAddr` | `0x01 title_byte`, `0x03 addr_token` | ack only; result arrives via notification type `3` subtype `4` | async-refresh |
| `0x06` | `vaConvertHash` | `0x01 title_byte`, `0x03 hash` | ack only; result arrives via notification type `3` subtype `4` | async-refresh |
| `0x07` | `vaConvertTopicNumber` | `0x01 title_byte`, `0x03 topic_no` | ack only; result arrives via notification type `3` subtype `4` | async-refresh |
| `0x10` | `HighlightsInTopic` | `0x01 arg0_low_byte`, `0x03 topic_or_addr` | one returned blob stream | synchronous |
| `0x11` | `addrSearchHighlight` | `0x01 arg0_low_byte`, `0x03 key0`, `0x03 key1` | `0x83 addr_token` | synchronous |
| `0x12` | `HighlightDestroy` | `0x01 title_byte` | static ack | synchronous |
| `0x13` | `HighlightLookup` | `0x01 title_byte`, `0x03 highlight_id` | ack only; result arrives via notification type `2` | async-refresh |
| `0x15` | `HfcNear` miss | `0x01 title_byte`, `0x03 addr_token` | ack only; content cache filled via notification type `0` | async-refresh |
| `0x16` | `HfcNextPrevHfc` miss | `0x01 title_byte`, `0x03 current_token`, `0x01 direction` | ack only; content cache filled via notification type `0` | async-refresh |
| `0x17` | notification subscribe | `0x01 notification_type` + dynamic capture | long-lived streamed pending handle | asynchronous |
| `0x18` | notification unsubscribe | `0x01 notification_type` | static ack | synchronous |
| `0x1a` | `HfOpenHfs` | `0x01 hfs_mode`, `0x04 filename`, `0x01 open_mode` | `0x81 handle_byte`, `0x83 file_size` | synchronous |
| `0x1b` | `LcbReadHf` | `0x01 handle_byte`, `0x03 requested_len`, `0x03 current_offset` | `0x81 status`, end static, dynamic raw bytes | synchronous |
| `0x1c` | `RcCloseHf` | `0x01 handle_byte` | static ack | synchronous |
| `0x1d` | `RcGetFSError` | no payload | `0x82 fs_error_word` | synchronous |
| `0x1e` | `TitlePreNotify` | `0x01 title_byte`, `0x02 opcode`, `0x04 payload` | usually static ack only | synchronous |
| `0x1f` | attach handshake | `0x01 1`, `0x04 capabilities_blob_12` | `0x83 validation_dword`, end static | synchronous |

Useful implementation constraints from the client code:

- `TitleGetInfo` serves these kinds entirely locally and does not hit the
  server for them: `0x01`, `0x02`, `0x04`, `0x06`, `0x07`, `0x08`, `0x0b`,
  `0x13`, `0x69`, `0x6a`, `0x6e`, `0x6f`.
- `TitleGetInfo` falls through to selector `0x03` for kinds such as `0x03`,
  `0x05`, `0x0a`, `0x0c`..`0x10`, `0x66`..`0x68`, and `0x6b`..`0x6d`.
- `TitlePreNotify` opcodes `9`, `0xb`, `0xc`, and `0xf` have local special
  handling and do not always produce a wire request.
- `TitlePreNotify` opcode `0xc` is a purely local picture-control dispatcher:
  - control `0` starts or refreshes a picture transfer via
    `PictureDownload_StartOrRefresh`
  - control `1` snapshots transfer status/info back into the caller buffer
  - control `2` detaches a previously attached picture consumer
- `HighlightGetGroup`, `WordWheelLength`, `vaConvertContextString`,
  `addrConvertContextString`, and `LcbSizeHf` are local wrappers/helpers and do
  not introduce additional wire selectors beyond the ones listed above.
- The async refresh selectors are split across three different
  selector-`0x17` notification families:
  - `0x15` and `0x16` wait on notification type `0`
  - `0x0c` waits on notification type `1`
  - `0x13` waits on notification type `2`
  - `0x05`, `0x06`, and `0x07` wait on notification type `3`, specifically
    subtype-`4` records inside that stream
- The synchronous replies on those selectors are just acks; the actual answer
  is expected to arrive later through the relevant notification subscription.

## Selector `0x17` Notification Families

The client opens five long-lived subscriptions at attach time, and each one
feeds a different cache/update path.

- type `0` callback = `HfcNotification_ApplyStream`
  - pumped on demand by `HfcNear` and `HfcNextPrevHfc` via
    `NotificationSubscriber_PumpByType(0, ...)`
  - parses record leaders `0x37`, `0xa5`, and `0xbf`
  - keys records by title byte and contents-address token and stores them in
    the per-title HFC cache built by `HfcCache_InsertEntry`
  - `0xa5` is a status-only / no-payload record:
    - `u8 0xa5`
    - `u8 title_byte`
    - `u16 status_word`
    - `u32 contents_token`
  - `0x37` and `0xbf` are payload-bearing topic-body records:
    - `u8 record_kind`
    - `u8 title_byte`
    - `u16 payload_bytes`
    - `u8[payload_bytes] topic_blob`
    - `u32 contents_token` at payload-relative offset `0x08`
  - `0xbf` additionally carries a `0x3c`-byte companion block plus up to two
    optional text handles that `HfcNear` clones into the caller-supplied
    metadata buffer
  - that companion block is not decorative cache baggage; the viewer uses it as
    the navigation/export context for scrolling, next/prev traversal, and copy
    operations
- type `1` callback = raw function at `0x7e849251`
  - pumped on demand by `WordWheelLookup` and helper `FUN_7e84a028`
  - now recovered as `WordWheelNotification_ApplyRecord`
  - record layout is:
    - `u16 record_bytes`
    - `u8 wordwheel_id`
    - `u8 range_span_or_0xff`
    - `u32 ordinal_base`
    - `u16 entry_count`
    - `u32[max(entry_count, 1)] entry_index_table`
    - optional NUL-terminated payload string at `0x0b + 4 * max(entry_count, 1)`
  - `range_span_or_0xff == 0xff` is normalized to zero before updating the
    live range tracker and is also forwarded as a boolean mode bit into
    `WordWheelCache_InsertEntry`
  - when the optional payload string is present, the callback materializes a
    cached lookup result via `WordWheelCache_InsertEntry`
  - also maintains the per-word-wheel range trackers at
    `DAT_7e84e668..DAT_7e84e671`
- type `2` callback = `HighlightNotification_ApplyRecord`
  - pumped on demand by `HighlightLookup` via
    `NotificationSubscriber_PumpByType(2, ...)`
  - parses a length-prefixed record format keyed by title byte and highlight
    id
  - updates both the rolling highlight-window trackers at
    `DAT_7e84d02c..DAT_7e84d035` and the linked-list cache populated by
    `HighlightCache_Insert`
- type `3` callback = `NotificationType3_DispatchRecords`
  - created with a worker thread, but also pumped explicitly by
    `vaConvertAddr`, `vaConvertHash`, `vaConvertTopicNumber`, and a few other
    wait loops through `NotificationSubscriber_PumpByType(3, ...)`
  - record header = low word subtype, high word record length
  - subtype `4` updates the three address/hash/topic conversion tables through
    `NotificationType3_ApplyAddrConversionRecord` ->
    `AddrConversionCache_Insert`
  - subtype `5` updates the word-wheel query cache through
    `NotificationType3_ApplyWordWheelQueryRecord` ->
    `WordWheelQueryCache_Insert`
  - subtypes `1` and `2` update a separate object-state list through
    `FUN_7e846bb1`
- type `4` callback = `NotificationType4_ApplyChunkedBuffer`
  - created with a worker thread and then enabled explicitly
  - appends chunked bodies into registered file/content objects and posts
    `WM_USER+0x0e` notifications to attached windows
  - stream frame header matches the type-3 style packing:
    - low word = chunk opcode
    - high word = frame bytes
  - opcode `3` is code-proven and uses this payload:
    - `u32 transfer_id`
    - `u32 chunk_offset`
    - `u8[frame_bytes - 0x0c] chunk_data`
  - the callback resolves `transfer_id` against the active picture/file object
    list at `PTR_DAT_7e84e628 + 0x1c`, grows the destination buffer if needed,
    copies `chunk_data` at `chunk_offset`, updates the contiguous-received
    cursor, and signals listeners through `WM_USER+0x0e`
  - this path is not used by `vaConvert*`, `Hfc*`, highlights, or the
    word-wheel lookup stream

## Picture Transfer Side Channel

Static analysis now pins down a separate picture/content transfer contract that
is adjacent to, but distinct from, the title metadata selectors.

### Local control API

`TitlePreNotify` opcode `0xc` never goes to the server. It dispatches a local
control buffer through `TitlePreNotify_LocalPictureControl`:

- control `0`
  - start or refresh a transfer through `DownloadPicture`
- control `1`
  - query current transfer status/info back into the same caller buffer
- control `2`
  - detach a previously attached picture handle from a window

The status query returns the live fields exposed by `GetDownloadStatus` and
`GetPictureInfo`, not a wire reply.

### Remote start request

When the transfer is not already satisfied from a direct local file open,
`PictureDownload_StartOrRefresh` builds a selector-`0x1e` / opcode-`4` payload
and sends it through `TitlePreNotify`:

```text
PictureStartPayload
  u8  constant_1
  u8  mode_byte
  u32 current_size
  u32 transfer_id
  u8  state_flags
  char[] nul_terminated_name
```

Code-proven field origins:

- `current_size` = object `+0x38`
- `transfer_id` = object `+0x24`
- `state_flags`
  - bit `0x01` reflects object `+0x48 != 0`
  - bit `0x02` reflects object `+0x4c != 0`

The client-visible contract for these fields is fixed:

- `mode_byte` is an opaque request-state byte that the client forwards without
  any recovered local interpretation
- `state_flags`
  - bit `0x01` advertises object `+0x48 != 0`
  - bit `0x02` advertises object `+0x4c != 0`
- no stock client path in this pass decodes richer semantics out of those bits
  after transmission

### Remote completion/update path

The corresponding server-to-client data path is notification type `4`, not
selector `0x1b`.

- `NotificationType4_ApplyChunkedBuffer` receives opcode-`3` chunk frames
- each frame targets one transfer object by `transfer_id`
- the chunk bytes are copied into that object's in-memory buffer at the stated
  offset
- after each update the client notifies attached windows with `WM_USER+0x0e`

This is the stock chunked-content delivery path for picture/file objects that
were not satisfied from a direct local file mapping.

## `MPCCL` Reply Framing And Delivery

`MPCCL` does not hand `MVTTL14C` a single flat application struct. The reply
path has two stages:

1. `MpcReplyPacket_ReadAndParse` reads the raw MOS-pipe message and peels a
   small host block
   off the front:
   - bytes `0..1`: copied verbatim into a 12-byte host-block object
   - byte `2`: starts a variable-width field whose top bits select the width
     (`1`, `2`, or `4` bytes)
   - the remaining bytes become the payload pointer and payload length
2. `FUN_0460307d` routes the parsed packet:
   - if host-block byte `0` is `0`, `MpcAsyncTable_ApplyRecords` treats the
     payload as
     `0x11`-byte transport-level async records and applies them to an internal
     `MPCCL` table
   - otherwise `MpcDispatchReplyByCorrelationId` extracts a `6`/`14`/`30`-bit
     correlation id from the variable-width host-block field and dispatches the
     packet to the waiting request object

The `byte0 == 0` path is real, but the `MVTTL14C` flows pinned down in this
document currently rely on selector-`0x17` subscriptions instead. Static
analysis in this pass did not tie any exported `MVTTL14C` API directly to that
generic `MPCCL` async-table consumer.

The waiter then processes a typed field stream in
`MpcRequestReceiver_ConsumeReplyFields`.

Observed response item classes:

- `0x81`..`0x84`
  - fixed/static receives
  - copy directly into pre-bound caller buffers
  - `0x84` can carry a variable-length item: the stream provides a length
    first, then that many bytes
- `0x85`, `0x86`, `0x88`
  - dynamic receives
  - appended into an internal buffer builder
  - if the packet flags request it, `FUN_04605d61` runs the accumulated chunks
    through the MDI decompressor before exposing the final byte stream to the
    caller
- `0x87`
  - end-of-static-fields marker
- `0x8f`
  - service-side error packet containing a 4-byte MPC error code

Practical consequence:

- request methods such as `TitleOpenEx` bind output slots ahead of time
- the `MEDVIEW` reply fills those slots through this typed receive stream
- larger returned blobs arrive as dynamic stream objects rather than inline
  fixed structs

## `MVTTL14C` Title Open Pipeline

`MVTTL14C!TitleOpenEx` is the MediaView 1.4 parser implementation that matters
for MOSVIEW.

High-level behavior:

1. Reject empty paths.
2. Copy the caller-supplied title token into a request buffer.
3. If the token ends in a bare `.m14` suffix, trim that suffix before sending
   it to the service.
4. Bind that normalized title-name string into `MEDVIEW` request `1`.
5. Read `HKLM\\SOFTWARE\\Microsoft\\MOS\\Directories\\MOSBin`.
6. Build a cache path with `MVCache_%s.tmp`.
7. Sanitize the formatted cache name by replacing `:`, `[`, `\\`, and `]` with
   `_`, then trim leading underscores before concatenating to `MOSBin`.
8. If the cache file exists:
   - read `8` bytes of header
   - read the remaining payload blob
9. Open the real source title through the parser's internal service object.
10. Recover live metadata:
   - parser subtype byte
   - file-system / mode byte
   - three additional dwords
   - a fresh 8-byte validation tuple
   - a stream object that can emit the flat payload blob
11. Allocate or reuse a title object of size `0xb0`.
12. If the cached 8-byte header does not match the live 8-byte header:
    - discard cached payload
    - rebuild from the live stream
    - rewrite the cache file
13. Materialize:
    - font blob into a global-memory handle
    - payload blob pointer and size into the title object
    - file-system mode into the title object

Important implication:

- The cache file is not a standalone title.
- `TitleOpenEx` does not open the caller's title file locally.
- `TitleOpenEx` still talks to the real source container every time in order to
  fetch live metadata and validate the cache header.
- Direct cache replacement is therefore not sufficient unless the server-side
  `MEDVIEW` implementation also accepts the source title and produces the
  expected metadata tuple.

More precisely:

- the only `CreateFileA` operations in `TitleOpenEx` are against the companion
  `MVCache_*.tmp` file under `MOSBin`
- the user-supplied filename is instead serialized into request `1` via the
  request-builder `+0x24` method
- for stock MOSVIEW's `[%s]0` wrapper, the `.m14` trimming path does not fire,
  so `MEDVIEW` receives the bracketed parser token rather than a bare path

More concretely, after the request-`1` reply is decoded:

- subtype byte selects or creates the `0xb0`-byte title instance
- file-system / mode byte is stored at title `+0x88`
- the three reply dwords are stored at title `+0x8c`, `+0x90`, and `+0x94`
- the 8-byte validation tuple is compared against the cache file header
- the returned dynamic stream supplies the flat payload blob when the cache
  must be rebuilt
- the payload pointer and payload size are stored at title `+0xa4` and
  `+0xa8`
- the leading font blob is copied into a global-memory handle stored at
  title `+0x08`

## Cache File Structure

The cache file shape is simple:

```text
MediaViewCacheFile
  u32 header0
  u32 header1
  u8[payload_size] payload
```

The client-visible role of `header0` and `header1` is resolved: together they
form an opaque 8-byte validation tuple. Code proves that:

- they are read first
- they are compared against a live 8-byte tuple recovered during `TitleOpenEx`
- a mismatch forces payload regeneration
- they are not surfaced as user-visible fields or interpreted structurally by
  `MOSVIEW` or `MVCL14N`

The repo parser `scripts/inspect_mediaview_cache.py` treats these as a raw
validation header, not as user-visible fields.

## Materialized Title Object Fields

The title object allocated by `FUN_7e845d4e` is `0xb0` bytes. The selectors
MOSVIEW cares about land in fixed offsets:

- `+0x08`: global-memory font-table handle returned by selector `0x6f`
- `+0x88`: file-system / mode code returned by selector `0x69`
- `+0x8c`: `vaGetContents` base dword returned by the `TitleOpenEx` reply
- `+0x90`: `addrGetContents` base dword returned by the `TitleOpenEx` reply
- `+0x94`: topic-count upper bound exposed through selector `0x0b`
- `+0xa4`: pointer to the flat payload blob parsed below
- `+0xa8`: payload blob size

The payload itself is what backs selectors `0x07`, `0x08`, `0x06`, `0x01`,
`0x02`, `0x6a`, `0x13`, and `0x04`.

## Payload Grammar

`MVTTL14C!TitleGetInfo` walks the payload in a fixed order. This is the
code-proven layout:

```text
MediaViewPayload
  u16 font_blob_len
  u8[font_blob_len] font_blob

  u16 sec07_bytes
  u8[sec07_bytes] sec07_records         ; fixed-width records, 0x2b each

  u16 sec08_bytes
  u8[sec08_bytes] sec08_records         ; fixed-width records, 0x1f each

  u16 sec06_bytes
  u8[sec06_bytes] sec06_records         ; fixed-width records, 0x98 each

  u16 sec01_len
  u8[sec01_len] sec01_blob

  u16 sec02_len
  u8[sec02_len] sec02_blob

  u16 sec6a_len
  u8[sec6a_len] sec6a_blob

  u16 sec13_entry_bytes                 ; excludes the count field
  if sec13_entry_bytes != 0:
    u16 sec13_count
    repeat sec13_count:
      u16 entry_len
      u8[entry_len] entry_bytes

  u16 sec04_count
  repeat sec04_count:
    char[] nul_terminated_string
```

Notes:

- The first `font_blob_len + font_blob` prefix is not addressed as a payload
  section. `TitleOpenEx` copies it into a global handle, and `TitleGetInfo(0x6f)`
  later returns that handle.
- Selector `0x69` is not sourced from the cache payload at all. It comes from
  live metadata recovered during `TitleOpenEx`.
- Section `0x04` is last and does not carry a total byte length, only a count.

## `TitleGetInfo` Selector Contract

`MVTTL14C!TitleGetInfo(title, selector, arg, out)` uses selectors as follows:

| selector | source | behavior |
| --- | --- | --- |
| `0x6f` | title object `+0x08` | return font-table handle |
| `0x69` | title object `+0x88` | return file-system / mode code |
| `0x0b` | title object `+0x94` | return topic-count upper bound |
| `0x07` | payload | indexed fixed-width records, size `0x2b` |
| `0x08` | payload | indexed fixed-width records, size `0x1f` |
| `0x06` | payload | indexed fixed-width records, size `0x98` |
| `0x01` | payload | length-prefixed blob |
| `0x02` | payload | length-prefixed blob |
| `0x6a` | payload | length-prefixed blob |
| `0x13` | payload | indexed string table: `u16 len + bytes` |
| `0x04` | payload | indexed NUL-terminated string table |

Selector argument packing:

- `0x07`, `0x08`, `0x06`
  - `arg >> 16` = record index
  - `arg & 0xffff` = caller buffer size
- `0x13`, `0x04`
  - `arg >> 16` = string index
  - `arg & 0xffff` = caller buffer size
- `0x01`, `0x02`, `0x6a`
  - `arg & 0xffff` = caller buffer size

Return behavior:

- fixed record selectors return the fixed record size on success
- variable string/blob selectors return copied length
- `0xffffffff` signals failure or absence

## Selectors MOSVIEW Actually Consumes

The main open path in `MOSVIEW.EXE!FUN_7f3c61ce` uses:

| selector | MOSVIEW use |
| --- | --- |
| `0x6f` | hand to `hMVSetFontTable` |
| `0x69` | hand to `MVSetFileSystem` |
| `0x07` | collect `0x2b` records into a heap array |
| `0x08` | collect `0x1f` records into a heap array |
| `0x06` | collect `0x98` records into a heap array |
| `0x04` | collect a heap array of duplicated C strings |
| `0x01` | copy the title-name string into object field `+0x58` |
| `0x02` | copy the copyright-information string into object field `+0x5c` |

The parser also exposes `0x6a` and `0x13`, but those selectors were not hit by
the main MOSVIEW construction function in this pass.

## Resolved Live Metadata Dwords

The three reply dwords from selector `0x01` are no longer equally ambiguous:

- title `+0x8c`
  - code-proven contents virtual address
  - exported directly by `MVTTL14C!vaGetContents`
  - wrapped by `MVCL14N!vaMVGetContents`
  - consumed by `MOSVIEW.EXE!FUN_7f3c61ce` as the first-paint entry address
- title `+0x94`
  - code-proven topic-count upper bound
  - exported locally by `TitleGetInfo(selector=0x0b)`
  - consumed by `MVCL14N!hMVTopicListFromQuery` and
    `MVCL14N!hMVTopicListFromTopicNo`
  - `hMVTopicListFromTopicNo` rejects `topic_no < 0 || topic_no >= count`
- title `+0x90`
  - code-proven address-contents base
  - exported directly by `MVTTL14C!addrGetContents`
  - wrapped by `MVCL14N!addrMVGetContents`
  - not consumed by the stock `MOSVIEW` first-paint path, but still part of the
    title-open contract for clients that request address-space rather than
    virtual-address-space contents

## Selector `0x01` / `0x02` String Handling

`MOSVIEW.EXE!FUN_7f3c61ce` does not treat selectors `0x01` and `0x02` as opaque
binary blobs. It copies each into a stack buffer, runs `FUN_7f3c4427`, and only
then duplicates the result into the title descriptor at `+0x58` and `+0x5c`.

`FUN_7f3c4427` is a recursive wrapper around two simple unquoters:

- `FUN_7f3c445e` strips one layer of `` `...\' `` quoting
- `FUN_7f3c44b1` strips one layer of `"..."` quoting

No other decoding or escaping happens in this pass. Code therefore proves that
selectors `0x01` and `0x02` are expected to be ordinary NUL-terminated strings,
possibly wrapped in one or more layers of those quote syntaxes.

Later, the main child-view window proc `FUN_7f3c2301` returns duplicated copies
of:

- title descriptor `+0x5c` for message `0x406`
- title descriptor `+0x58` for message `0x414`

Those two strings are then surfaced by the top-level `MOSVIEW` shell through
the "About Title" dialog:

- message `0x414` is labeled `Title name`
- message `0x406` is labeled `Copyright information`

So selectors `0x01` and `0x02` are now fully pinned as user-visible metadata
strings, not hidden control fields.

## Fixed Record Semantics In MOSVIEW

Static analysis of `MOSVIEW.EXE!FUN_7f3c6790` and the child-view window proc
`FUN_7f3c2301` now pins down most of the fixed-record layouts.

### Selector `0x07`: `0x2b`-byte Child-Pane Descriptors

Each `0x07` record feeds one extra `MosChildView` window.

- `+0x0b`: flags byte
  - bit `0x08` selects coordinate interpretation
- `+0x0c`: inline NUL-terminated pane title
  - the title lives in a 9-byte slot ending before the first rect dword at
    `+0x15`
- `+0x15`, `+0x19`, `+0x1d`, `+0x21`: `x`, `y`, `w`, `h`
- `+0x25`: `COLORREF` background color passed through `FUN_7f3c1f86`
- `+0x29`: `u16` propagated into child object `+0xa0`

Behavior:

- if bit `0x08` is clear, `x/y/w/h` are treated as fractions of the parent
  window rect with denominator `0x400`
- if bit `0x08` is set, `x/y` are treated as absolute offsets and `w/h` as
  direct logical sizes
- after that transform, all four values are scaled by
  `DAT_7f3cd310 / 0x60`, so the direct units are code-consistent with
  96-DPI logical coordinates
- the trailing `u16` at `+0x29` is later compared against message `0x42d`
  thresholds and acts like a pane-id / visibility-tier field

### Selector `0x08`: `0x1f`-byte Popup Descriptors

Each `0x08` record feeds one popup `MosChildView`. MOSVIEW allocates one extra
synthetic popup after the real records and titles it `[The Default Popup]`.

- `+0x01`: flags byte
  - bit `0x08` selects coordinate interpretation
- `+0x02`: inline NUL-terminated popup title
  - again confined to the 9-byte slot before `+0x0b`
- `+0x0b`, `+0x0f`, `+0x13`, `+0x17`: `x`, `y`, `w`, `h`
- `+0x1b`: `COLORREF` background color passed through `FUN_7f3c1f86`

Behavior:

- if bit `0x08` is clear, `x/y/w/h` are treated as fractions of the desktop
  work area with denominator `0x400`
- if bit `0x08` is set, `x/y` are treated as absolute work-area offsets while
  `w/h` remain direct logical sizes
- all four values are then scaled by `DAT_7f3cd310 / 0x60`

### Selector `0x06`: `0x98`-byte Window-Scaffold Records

The main open path only consumes the first `0x06` record. Additional records, if
any, were not used in the constructor recovered here.

Code-proven fields in that first record:

- `+0x15`: inline container caption string used for the outer
  `MosViewContainer` window
- `+0x48`: flags byte
  - bit `0x08` selects the outer-container rect mode
  - bit `0x01` selects the non-scrolling child rect mode
  - bit `0x40` sets child object `+0x9c`, which later bottom-aligns the
    non-scrolling pane during resize
- `+0x49`, `+0x4d`, `+0x51`, `+0x55`: outer container `x`, `y`, `w`, `h`
- `+0x5b`: unaligned dword copied into the viewer object at `+0x20`
  - the recovered constructor path stores it as an opaque container-side
    control/id field and does not interpret it as geometry or text
- `+0x78`: `COLORREF` for the synthetic `Non Scrolling Pane`
- `+0x7c`: `COLORREF` for the main scrolling pane
- `+0x80`, `+0x84`, `+0x88`, `+0x8c`: non-scrolling pane `x`, `y`, `w`, `h`

Behavior:

- outer container rects go through `FUN_7f3c1fd5`, which:
  - applies either `0x400`-relative or absolute-origin coordinates
  - compensates for the parent window's chrome
  - scales sizes by `DAT_7f3cd310 / 0x60`
- the main scrolling pane and synthetic `Non Scrolling Pane` are then created
  from this one scaffold record
- if selector `0x06` is absent, MOSVIEW falls back to the literal outer caption
  `Online Viewer Container`

## Coordinate Helper Semantics

The fixed-record coordinate bits are now code-proven:

- `FUN_7f3c5e1c`
  - interpret `x/y/w/h` as fractions of a parent rect using denominator `0x400`
- `FUN_7f3c5ea5`
  - add the parent rect origin to `x/y` only
  - leave `w/h` untouched
- `FUN_7f3c1fd5`
  - wraps those helpers for the outer container and compensates for borders and
    title-bar chrome before final size scaling

## HFC Topic-Body Payload Grammar

The HFC payload delivered through notification type `0` is no longer just a
cache blob. `MVCL14N` parses it into concrete topic-body records that drive
point lookup, hotspot dispatch, scrolling, next/prev traversal, and clipboard
export.

Code-proven raw shape:

```text
TopicBodyBlob
  u8[0x26] topic_header
  TopicItem item0
  TopicItem item1
  ...
```

Important header fields that the viewer reads directly:

- `+0x08`: contents token for the blob
- `+0x1c`: trailing-range / extent dword used in navigation and export math
- topic items begin at `+0x26`

`FUN_7e897ed0` normalizes the on-wire item tag. Tags `0x20`..`0x24` are the
same semantic families as `0x01`..`0x05`, but with widened packed integers.

The viewer-side dispatcher `FUN_7e894c50` proves these item families:

- `0x01` / `0x20`
  - text/paragraph flow
  - parsed by `FUN_7e8915d0`
  - produces one or more positioned line/item records and updates scrolling
    extents
- `0x03` / `0x22`
  - image bundle with optional hotspot children
  - parsed by `FUN_7e894560`
  - creates a parent image record plus child hotspot records
- `0x04` / `0x23`
  - proportional horizontal composition group
  - parsed by `FUN_7e8938c0`
  - splits available width across child items and recursively parses each child
- `0x05` / `0x24`
  - embedded/external object descriptor
  - parsed by `FUN_7e893600`
  - consumes a comma-separated triple string and materializes a type-`6`
    viewer item

The parsed per-item array uses `0x47`-byte viewer records. The stock hit-test
and hotspot paths operate on those viewer records, not on the raw wire blob.

## Outer Source Container: What Is Known

The client-side `.m14` question is now resolved negatively.

Code proves:

- `.m14` is only a canonical suffix recognized by `TitleOpenEx`
- `MVCL14N!hMVTitleOpenEx` passes the parser token `[%s]0` into
  `MVTTL14C!TitleOpenEx`
- `TitleOpenEx` never opens the caller's title file locally
- the only local file I/O in `TitleOpenEx` is against the companion
  `MVCache_*.tmp`
- `HfOpenHfs` also does not open local title-side storage; it forwards its HFS
  string to selector `0x1a` and waits for the `MEDVIEW` reply

So the shipped clients do not contain a local `.m14` parser in the path that
stock MOSVIEW uses. The real title/container grammar, if one exists as an
on-disk file format at all, lives behind the server-side `MEDVIEW` contract.
What the client actually requires is smaller and already concrete:

- selector-`0x01` must return:
  - parser subtype byte
  - file-system / mode byte
  - contents VA dword
  - address-contents (`addrGetContents`) dword
  - topic-count dword
  - 8-byte cache validation tuple
  - flat payload blob
- optional later selectors / notifications must satisfy the async conversion,
  HFC, and HFS paths

This fully recovers the client-visible contract. What remains outside these
client binaries is the server-internal source/storage format that `MEDVIEW`
uses to manufacture those reply fields.

## Converter Target

The right converter target is not "Blackbird `.ttl` bytes". It is:

1. a MediaView 1.4 logical title
2. lowered to the `MVTTL14C` payload grammar above
3. plus whatever server-side source/container state is required to recreate:
   - the cache validation header
   - the file-system / mode byte
   - the additional live metadata dwords

Minimum fields a converter must populate for MOSVIEW compatibility:

- font-table blob for selector `0x6f`
- file-system / mode metadata for selector `0x69`
- selector `0x07` record table
- selector `0x08` record table
- selector `0x06` record table
- user-visible text blobs for selectors `0x01`, `0x02`, and `0x6a`
- string tables for selectors `0x13` and `0x04`

## Blackbird To MediaView Lowering Notes

The input should be the Blackbird logical title model, not the OLE container
layout. A Blackbird `.ttl` is still useful as source material because the repo
already decodes its logical objects.

Concrete sample: `msn today.ttl`

- title name: `MSN Today`
- resource folder: `Resources`
- default frame: `Default Window`
- default style sheet: `Default Style Sheet`
- top-level section object:
  - properties name: `Section 1`
  - linked form list: one `CBForm`
  - linked content list: three `CContent` refs
- proxy/source content visible in properties:
  - `Homepage.bdf`
  - `Calendar of Events_.bdf`
  - `bitmap.bmp`

Practical lowering sketch:

- Blackbird title / section / resource names:
  - candidate sources for selectors `0x01`, `0x02`, `0x04`, `0x13`, and `0x6a`
- Blackbird content ordering:
  - candidate source for the indexed fixed-record tables `0x07`, `0x08`, `0x06`
- Blackbird style-sheet and frame choices:
  - candidate source for the font blob that becomes selector `0x6f`

Blackbird concepts with no direct MediaView equivalent yet:

- OLE storages and numbered ref streams
- swizzled Blackbird object handles
- `CProxyTable` and Blackbird-specific object-store indirection
- distinct `TextTree` / `TextRuns` / `WaveletImage` object taxonomy
- arbitrary Blackbird property bags such as origin paths and MSN site metadata

These will require lossy lowering or outright omission. The good news is that
MOSVIEW's steady-state open path only consumes the selector set listed above, so
Blackbird-only metadata outside that set is a plausible omission candidate.

## Verification Status

Completed in this pass:

- static MOSVIEW thunk mapping
- static `MVCL14N` dispatch recovery
- static `MVTTL14C` cache path recovery
- static `MVTTL14C!TitleGetInfo` payload grammar recovery
- parser implementation in `scripts/inspect_mediaview_cache.py`

Still open:

- acquire an authentic `.m14` or `MVCache_*.tmp`
- compare the parser output against live MOSVIEW-visible strings and tables
- assign semantics to the still-unknown bytes inside the `0x2b`, `0x1f`, and
  `0x98` records

No authentic MediaView cache sample exists in this workspace today, so the
layout claims above are code-proven but not yet sample-validated.
