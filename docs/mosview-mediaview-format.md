# MOSVIEW / MediaView 1.4 Format Notes

Short docstring-style reference: `docs/medview-service-contract.md`.

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
  - `OpenTitleIntoDescriptor` (`FUN_7f3c61ce`): main MediaView construction path
  - `FUN_7f3c5ff4`: transient title open + pre-notify opcode `8`
  - `FUN_7f3c60a5`: transient title open + pre-notify opcodes `9` and `0xb`
- `MVCL14N.DLL`
  - `hMVTitleOpen` at `0x7e8851d0`
  - `hMVTitleOpenEx` at `0x7e8851f0`
  - `MVTitlePreNotify` at `0x7e885130`
  - `MVTitleNotifyLayout` at `0x7e885180`
  - `MVTitleClose` at `0x7e8853a0`
  - `hMVTopicListFromQuery` at `0x7e884060`
  - `hMVTopicListFromTopicNo` at `0x7e884190`
  - `hMVTopicListLoad` at `0x7e883f50`
  - `lMVTopicListLength` at `0x7e884240`
  - `lMVTopicListLookup` at `0x7e884290`
  - `MVWordWheelSearch` at `0x7e884640`
  - `nMVWordWheelQuery` at `0x7e8858a0`
  - `lMVTitleGetInfo` at `0x7e885ac0`
- `MVTTL14C.DLL`
  - `TitleOpenEx` at `0x7e842d4e`
  - `TitleGetInfo` at `0x7e842558`
  - `TitleQuery` at `0x7e841653`
  - `WordWheelOpenTitle` at `0x7e849328`
  - `WordWheelQuery` at `0x7e849e99`
  - `WordWheelLookup` at `0x7e849658`
  - `WordWheelClose` at `0x7e8495b1`
  - `KeyIndexGetCount` at `0x7e849a27`
  - `KeyIndexGetAddrs` at `0x7e849b6e`
  - `HighlightDestroy` at `0x7e841180`
  - `HighlightLookup` at `0x7e841235`
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

`MOSVIEW.EXE!OpenTitleIntoDescriptor` drives the steady-state open path used to build a
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
  - one recovered stock payload shape:
    - `u8 status_code`
    - immediately followed by an ANSI NUL-terminated diagnostic string
  - the only recovered stock caller uses `status_code = 1` and sends the
    formatted text `"The title Appid=%d, deid %X%8X, info='%s' would not start."`
- `FUN_7f3c60a5`:
  - `hMVTitleOpen`
  - `MVTitlePreNotify(title, 9, ..., 4)`
  - `MVTitlePreNotify(title, 0xb, 0, 0)`
  - `MVTitleClose`
- Layout-time code later calls `MVTitleNotifyLayout`.

The important point is that MOSVIEW is a consumer of parser-provided title
selectors. It is not walking Blackbird OLE storages.

One additional detail matters for stock behavior: `MOSVIEW.EXE!OpenTitleIntoDescriptor`
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

## Selector `0x04`: `TitleQuery` And Topic Lists

`MVTTL14C!TitleQuery` is the service entry that powers
`MVCL14N!hMVTopicListFromQuery`. The request is more structured than the older
"byte + word + string" shorthand suggested.

Client-side packing:

- required fields
  - `0x01 title_byte`
  - `0x02 query_class_word`
  - `0x04 primary_query_string`
  - `0x01 option_flags`
  - `0x02 query_mode_word`
- `option_flags` bits
  - bit `0x01`: append a second query string
  - bit `0x02`: append an existing group/query context blob
  - bit `0x04`: append a caller-supplied `0x40`-byte auxiliary blob and bind a
    first dynamic reply stream for it
- when bit `0x01` is set
  - append `0x04 secondary_query_string`
  - `hMVTopicListFromQuery` sources this from a file-backed/deferred topic list
    passed as the "existing list" argument
- when bit `0x02` is set
  - append a `0x40`-byte fixed blob from the existing in-memory group handle
  - then append a variable tail whose pointer lives at group-handle offset
    `+0x1e` and whose byte length lives at offset `+0x04`
- when bit `0x04` is set
  - append the caller-owned `0x40`-byte auxiliary blob verbatim

Reply binding:

- `0x81`: one returned byte
- `0x83`: first returned dword
- `0x83`: second returned dword
- optional dynamic stream `0`
  - only bound when the caller supplied the auxiliary `0x40`-byte blob
  - if the caller blob has a non-null pointer at offset `+0x1e`, the returned
    dynamic bytes are copied there verbatim
- optional dynamic stream `1`
  - always bound
  - if present and exactly `0x0c` bytes long, it is copied into the caller's
    12-byte sideband output buffer

The returned byte is not a generic status code. `MVTTL14C!TitleQuery`
initializes highlight-tracker state from it, and later `HighlightLookup` /
`HighlightDestroy` use that byte as the highlight-query context key. A nonzero
`TitleQuery` reply therefore opens a highlight-capable query session.

The first returned dword is the one `MVCL14N!hMVTopicListFromQuery` keeps as the
logical list length. The second returned dword is preserved by `TitleQuery`, but
the stock `hMVTopicListFromQuery` wrapper overwrites its temporary slot with the
title's selector-`0x0b` topic-count upper bound, so that second dword is not a
first-order consumer dependency on the main client path.

### `MVCL14N` Topic-List Handle Layout

`MVCL14N` wraps query/topic results in a small movable global block created by
`MVTopicListAllocEmpty`:

```text
MVTopicListHandle   ; 0x1e bytes, GMEM_MOVEABLE | GMEM_ZEROINIT
  +0x00 u32 magic = 0x544c2100  ; "!LT\0"
  +0x04 u32 logical_count
  +0x08 u32 title_topic_upper_bound_or_loaded_count
  +0x0c u32 realized_group_handle
  +0x10 u32 parser_query_handle_or_zero
  +0x14 u32 deferred_source_string_or_zero
  +0x18 u32 deferred_source_title_handle_or_zero
  +0x1c u16 scratch/status slot used during group creation/load
```

Operational cases:

- query-created list
  - `+0x04` = first dword returned by `TitleQuery`
  - `+0x08` = selector-`0x0b` topic-count upper bound
  - `+0x0c` = local group handle built by `GroupInitiate` / `GroupTrimmed`
  - `+0x10` = local wrapper around the parser-side query handle returned by
    `TitleQuery`
- direct topic-number list
  - `+0x04 = 1`
  - `+0x0c` = single-item group handle
- file-backed/deferred list from `hMVTopicListLoad`
  - `+0x14` = duplicated source string
  - `+0x18` = owning title handle
  - `+0x0c` and `+0x10` can remain zero until the list is materialized

Client-visible consequences:

- `lMVTopicListLength` returns `+0x04`
- `lMVTopicListLookup`
  - uses the realized group at `+0x0c` when present
  - otherwise falls back to the parser-side query handle at `+0x10`
- `MVTopicListGroupGet` duplicates the realized group on demand
- `hMVTopicListCombine` only operates on realized groups and produces a fresh
  `MVTopicListHandle`

## Word-Wheel Request/Cache Model

The word-wheel selectors are not just isolated RPCs. `MVTTL14C` and `MVCL14N`
maintain a local cache/mapping layer around the remote IDs.

### Selector `0x09`: `WordWheelOpenTitle`

Request:

- `0x01 title_byte`
- `0x04 title_name`

Reply:

- `0x81 wordwheel_id`
- `0x83 item_count`

Local behavior:

- the client keeps a name/title-byte keyed cache of open word-wheel sessions
- repeated opens for the same title reuse the existing remote `wordwheel_id`
  and only increment a local refcount
- selector `0x0a` (`WordWheelClose`) is sent only when that refcount reaches
  zero

### Selector `0x08`: `WordWheelQuery`

Request:

- `0x01 wordwheel_id`
- `0x02 mode_or_flags`
- `0x04 query_string`

Reply consumed by the stock wrapper:

- `0x82 status_word`

The wrapper does enable dynamic capture, but the first-order client code uses
the returned status word and then relies on the separate word-wheel caches to
materialize lookup/search state.

`MVCL14N!MVWordWheelSearch` shows the intended higher-level flow:

1. read the cached/opened title item count
2. allocate a group of that capacity
3. issue `WordWheelQuery`
4. trim/finalize the group after the query path populates the cache-backed
   results

### Selector `0x0c`: `WordWheelLookup`

Request:

- `0x01 wordwheel_id`
- `0x03 ordinal`
- `0x03 output_limit`

Behavior:

- the synchronous reply is just an ack
- the actual lookup string arrives via notification type `1`
- `MVTTL14C!WordWheelLookup` polls the cache up to `0x40` iterations
- every `0x14` iterations it resends selector `0x0c`
- when the cache finally yields a payload string, the wrapper copies at most
  `output_limit` bytes into the caller buffer

The type-1 cache entry matched by `FUN_7e849199` carries:

- `wordwheel_slot`
- `ordinal_base`
- optional key string
- returned status word
- optional dword array payload
- returned string pointer
- a "pending/consumed" dword at `+0x20` that the polling wrappers set to `1`
  when they observe or request a record

### Selectors `0x0d` / `0x0e`: Key Index

`KeyIndexGetCount` and `KeyIndexGetAddrs` probe that same cache first and only
fall through to the wire on miss.

- selector `0x0d`
  - request: `0x01 wordwheel_id`, `0x04 key_string`
  - reply: `0x82 count_word`
- selector `0x0e`
  - request: `0x01 wordwheel_id`, `0x04 key_string`, `0x02 start_index`,
    `0x02 max_count`
  - reply: dynamic dword array
  - wrapper return value = copied byte count, not element count

### Selector `0x0b`: `WordWheelPrefix`

`WordWheelPrefix` is a simple synchronous probe over the same word-wheel slot.

- request:
  - `0x01 wordwheel_id`
  - `0x04 prefix_string`
- reply:
  - `0x83 prefix_result`
- no notification wait loop is involved; the wrapper just waits for the
  request to complete and returns the dword reply

### Selector `0x0f`: `fKeyIndexSetCount`

`fKeyIndexSetCount` is another direct synchronous request.

- request:
  - `0x01 wordwheel_id`
  - `0x04 key_string`
  - `0x02 count_word`
- reply:
  - `0x81 success_byte`
- if the caller passes a null key string, the wrapper fails locally and no
  `MEDVIEW` request is sent

## Highlight And Conversion Families

The remaining highlight and address-conversion selectors are more structured
than the request matrix alone suggests.

### Selector `0x10`: `HighlightsInTopic`

Client behavior:

- binds one dynamic reply stream
- sends:
  - `0x01` low byte of the title/highlight context
  - `0x03` topic-or-address token
- waits synchronously for the request to complete
- copies the returned dynamic stream byte-for-byte into a fresh
  `GMEM_MOVEABLE` global block via `FUN_7e844738(..., 0)`

So the stock parser contract is:

- no required static reply fields
- one returned dynamic blob
- the returned value surfaced by `HighlightsInTopic` /
  `hMVHighlightsInTopic` is a movable global-memory handle containing the exact
  dynamic reply bytes

The client does impose a partial higher-level structure on that blob once
`MVCL14N` installs it on a viewer object:

```text
TopicHighlightBlob
  +0x00 u8[8] opaque_header
  +0x08 u32 highlight_count
  +0x0c TopicHighlightEntry[highlight_count]

TopicHighlightEntry   ; 0x0d bytes
  +0x00 u32 highlight_anchor_token
  +0x04 u32 aux_dword_04        ; not consumed on the recovered paths
  +0x08 u32 aux_dword_08        ; not consumed on the recovered paths
  +0x0c u8  span_or_count
```

Code-proven consumer behavior:

- `lMVTopicHighlightCount` returns `highlight_count`
- `addrMVTopicHighlightAddress` returns `highlight_anchor_token` for a chosen
  entry
- the rect/scroll path treats the entries as ordered by
  `highlight_anchor_token`
- `span_or_count` is used as the highlight span/count when projecting one topic
  highlight into on-screen rectangles
- the hotspot/focus path does not recover any additional meaning for the middle
  dwords either; it operates on generated `0x47` viewer records and their local
  grouping dwords instead

The two middle dwords remain deferred: they are preserved in the topic blob,
but they were not consumed on the recovered first-order MVCL14N paths in this
pass.

### Selectors `0x11` / `0x12` / `0x13`: Highlight Search Lifecycle

`MVTTL14C` keeps a separate per-highlight cache keyed by:

- highlight-query context byte
- highlight id / ordinal

Code-proven cached values:

- `addr_token`
- a second dword returned by `HighlightLookup`, used as the positive lookup
  result

`HighlightLookup` (`0x13`) is an async-refresh selector:

- request:
  - `0x01 title_byte`
  - `0x03 highlight_id`
- synchronous reply:
  - ack only
- actual result source:
  - notification type `2`

Polling behavior is now code-proven:

- total timeout: `30000` ms
- maximum loop count: `0x40`
- resend cadence: every `0x14` iterations
- between retries the client pumps notification type `2` and uses the rolling
  range trackers at `DAT_7e84d02c..DAT_7e84d035` to decide whether a short
  sleep-only wait is sufficient

`addrSearchHighlight` (`0x11`) is not a blind RPC wrapper:

- if the caller passes third arg `0`
  - first run `HighlightLookup`
  - then re-read the highlight cache
  - if a cached `addr_token` now exists, return it without hitting the wire
- otherwise fall through to selector `0x11`
  - request:
    - `0x01` low byte of the title/highlight context
    - `0x03 key0`
    - `0x03 key1`
  - reply:
    - `0x83 addr_token`

`HighlightDestroy` (`0x12`) is refcounted locally:

- the parser only sends selector `0x12` when the local per-context refcount
  drops to zero
- otherwise the destroy is absorbed entirely in client state

`HighlightGetGroup` is not a real remote selector family in this client:

- exported `HighlightGetGroup` returns the fixed value `0x7df`
- it does not issue a `MEDVIEW` request

### Selectors `0x05` / `0x06` / `0x07`: Address Conversion Contract

The three conversion selectors all share the same wait/retry skeleton.

- `vaConvertAddr`
  - request: `0x01 title_byte`, `0x03 addr_token`
- `vaConvertHash`
  - request: `0x01 title_byte`, `0x03 hash`
- `vaConvertTopicNumber`
  - request: `0x01 title_byte`, `0x03 topic_no`

Shared behavior:

- initial lookup is against a local notification-fed cache
- on miss, the client pumps notification type `3`
- total timeout: `30000` ms
- resend cadence: every `4000` ms
- the synchronous reply is only an ack
- real answers arrive through notification type `3`, subtype `4`

Input validation proven by code:

- `vaConvertAddr` rejects `addr_token == -1`
- `vaConvertHash` rejects `hash == 0`
- all three reject null title handles

`vaConvertContextString` and `addrConvertContextString` are purely local sugar:

- `vaConvertContextString`
  - hashes the ANSI context string with `FUN_7e84a2bc`
  - then calls `vaConvertHash`
- `addrConvertContextString`
  - calls `vaConvertContextString`
  - then projects the returned VA through the address-conversion cache

### Notification Type `3`, Subtype `4`: Cache Shape

The notification-fed conversion cache now has a concrete read-side contract.
Each entry is title-scoped and stores:

```text
AddrConversionCacheEntry
  +0x00 u8  title_byte
  +0x04 u32 va_result
  +0x08 u32 secondary_mapped_token
  +0x0c u32 input_key
  +0x18 u32 next_ptr
```

There are three parallel linked-list heads:

- table `0`: keyed by topic number
- table `1`: keyed by hash
- table `2`: keyed by address token

The `vaConvert*` wrappers read `va_result` directly from the matching table for
their input domain.

The `addrConvert*` wrappers are two-stage:

1. run the corresponding `vaConvert*`
2. translate the returned VA back through the cache entry whose `va_result`
   matches, trying table order:
   - hash-derived entries first
   - then topic-number entries
   - then address-token entries

That second-stage lookup returns `secondary_mapped_token`, which is the
client-visible address-space result used by the `addrConvert*` exports.

## HFS And Baggage File Path

The HFS selectors are a narrow remote file API. They do not introduce a local
title-file parser; they only let the client read named title-side baggage
streams through the `MEDVIEW` service.

### Selector `0x1a`: `HfOpenHfs`

Request:

- `0x01 hfs_mode`
- `0x04 filename`
- `0x01 open_mode`

Reply:

- `0x81 handle_byte`
- `0x83 file_size`

Client behavior:

- the wrapper waits synchronously up to `30000` ms
- if `handle_byte == 0`, the open is treated as failure
- on success it allocates a 12-byte local wrapper with code-proven live fields:

```text
RemoteHfsHandle
  +0x00 u32 file_size
  +0x04 u32 current_offset
  +0x08 u8  remote_handle_id
```

Only those three fields are consumed by later helpers. The padding bytes after
`remote_handle_id` are not read on the recovered path.

### Selector `0x1b`: `LcbReadHf`

Request:

- `0x01 handle_byte`
- `0x03 requested_len`
- `0x03 current_offset`

Reply:

- `0x81 status_byte`
- dynamic raw byte stream

Client behavior:

- if `current_offset >= file_size`, the wrapper returns `0` without sending a
  request
- otherwise it enables dynamic capture, waits synchronously, then copies the
  exact returned dynamic bytes into the caller buffer
- the wrapper return value is the copied byte count
- on successful copy it advances `current_offset` by the actual returned byte
  count
- if the dynamic stream is empty or any stage fails, the wrapper returns
  `0xffffffff`

### Selector `0x1c`: `RcCloseHf`

`RcCloseHf` consumes the local `RemoteHfsHandle` wrapper:

- read `remote_handle_id` from `+0x08`
- free the local 12-byte wrapper
- send selector `0x1c` with `0x01 handle_byte = remote_handle_id`
- wait for the static ack

### Selector `0x1d`: `RcGetFSError`

`RcGetFSError` sends a zero-payload synchronous request and binds one
`0x82 fs_error_word` reply.

The local wrapper initializes the result to `8` before issuing the request, so
`8` is the code-proven fallback when request setup or completion fails before
the server overwrites the bound word.

### Baggage Layering

The exported baggage helpers are a two-path adapter:

- `param_3 == 0`
  - local filesystem path via `_lopen`, `_lread`, `_llseek`, `GetFileSize`
- `param_3 != 0`
  - remote title-side path via `HfOpenHfs`, `LcbReadHf`, `LSeekHf`, `LcbSizeHf`

`BaggageOpen` allocates a 12-byte movable global block whose locked contents
are:

```text
BaggageHandle
  +0x00 u32 underlying_handle_or_ptr
  +0x04 u32 title_handle
  +0x08 u32 path_mode
```

`path_mode` selects the backend:

- `0` = local Win16 file handle in `underlying_handle_or_ptr`
- nonzero = pointer to `RemoteHfsHandle`

`BaggageRead`, `BaggageSeek`, and `BaggageSize` just lock that block, branch on
`path_mode`, and dispatch to the local or remote backend.

For the remote path:

- `BaggageOpen` passes `hfs_mode = *(title + 0x88)` and `open_mode = 2`
- `LSeekHf` is purely local and updates `RemoteHfsHandle.current_offset`
  according to origin `0`, `1`, or `2`
- `LcbSizeHf` is purely local and returns `RemoteHfsHandle.file_size`

So the server-visible HFS contract is only:

1. open a named stream and report `(handle_byte, file_size)`
2. read byte ranges from that stream by explicit offset
3. close the remote handle
4. optionally report the last filesystem error word

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
  - attach-time binding now proves the callback function is `0x7e841109`
  - the record layout consumed by that callback is:
    - `u16 record_bytes`
    - `u8 highlight_context_slot`
    - `u8 range_span`
    - `u32 highlight_id`
    - `u32 addr_token`
    - `u32 lookup_result`
    - optional trailing bytes, if any, are not consumed on the recovered path
  - `highlight_context_slot` is normalized through `DAT_7e84e028` before
    indexing the live per-context trackers or the linked-list cache
  - updates both the rolling highlight-window trackers at
    `DAT_7e84d02c..DAT_7e84d035`
    - base/id tracker = `highlight_id`
    - span tracker = `range_span`
  - inserts one cache entry keyed by `(normalized_context, highlight_id)` and
    storing:
    - `addr_token`
    - `lookup_result`
  - when the currently pending `HighlightLookup` request matches the incoming
    `(context, highlight_id)` pair, the callback returns
    `record_bytes | 0x80000000` so the polling wrapper can treat that frame as
    the targeted wakeup
- type `3` callback = `NotificationType3_DispatchRecords`
  - created with a worker thread, but also pumped explicitly by
    `vaConvertAddr`, `vaConvertHash`, `vaConvertTopicNumber`, and a few other
    wait loops through `NotificationSubscriber_PumpByType(3, ...)`
  - record header = low word subtype, high word record length
  - subtypes `1` and `2` share a 26-byte status payload that updates the
    picture/file-object list rooted at `PTR_DAT_7e84e628 + 0x1c`
    - packed layout of that shared 26-byte block is now partially pinned:

```text
Type3ObjectStatus26
  +0x00 u32 target_size_bytes
  +0x04 u16 state_kind
  +0x06 u32 metric_or_value_0
  +0x0a u32 metric_or_value_1
  +0x0e u32 metric_divisor_or_aux_0
  +0x12 u32 aux_status_dword
  +0x16 u32 object_id
```

    - subtype `1`
      - payload is just that 26-byte block
      - resolves an existing object by `object_id`
    - subtype `2`
      - payload = 26-byte block, `u8 object_kind`, NUL-terminated object name
      - resolves an existing object by `(object_name, object_kind)` or creates a
        fresh `0x98`-byte object if none exists
    - both subtypes then:
      - resize/update the object's backing buffer state through
        `FUN_7e8485bd`
      - copy the remaining status fields into object fields `+0x80..+0x90`
        - set object valid flag `+0x48`
      - when the status kind equals `5`, rescale two metric fields by
        `MulDiv(value, 0x60, denominator)`
    - code-proven field landing in the object is:
      - `target_size_bytes` -> backing-buffer target size / download total
      - `state_kind` -> object `+0x80`, later surfaced by `GetPictureInfo`
      - `metric_or_value_0` -> object `+0x84`
      - `metric_or_value_1` -> object `+0x88`
      - `metric_divisor_or_aux_0` -> object `+0x8c`
      - `aux_status_dword` -> object `+0x90`
      - `object_id` -> object identity token used by subtype `1`

### Runtime Picture/File Object

The shared list at `PTR_DAT_7e84e628 + 0x1c` contains `0x98`-byte runtime
objects used by:

- type-`3` subtypes `1` and `2`
- type-`4` chunk frames
- `DownloadPicture` / `GetDownloadStatus` / `GetPictureInfo`
- the `TitlePreNotify` opcode-`4` / `5` picture-side paths

Code-proven field map so far:

```text
MediaTransferObject   ; 0x98 bytes
  +0x1c u32 next_ptr
  +0x20 char *object_name
  +0x24 u32 object_id_or_transfer_id
  +0x28 u32 owner_title_handle_or_zero
  +0x2c u32 title_mode_or_object_kind
  +0x30 u32 buffer_ptr
  +0x34 u32 target_size_bytes
  +0x38 u32 bytes_received_or_committed
  +0x3c u32 download_source_cookie
  +0x40 u32 last_tick
  +0x44 u32 picture_name_claim_cookie
  +0x48 u32 object_valid_flag
  +0x4c u32 request_mode_flag
  +0x50 u32 completion_flag
  +0x58 list/attach critical section
  +0x70 u32 attached_consumer_list
  +0x74 u32 attached_consumer_count
  +0x78 u32 detach_pending_flag
  +0x7c u32 layout_notify_pending_flag
  +0x80 u16 state_kind
  +0x84 u32 metric_or_value_0
  +0x88 u32 metric_or_value_1
  +0x8c u32 metric_divisor_or_aux_0
  +0x90 u32 aux_status_dword
  +0x94 u32 unused_or_future_field
```

Important client-visible semantics:

- `GetDownloadStatus` returns `buffer_ptr`, `bytes_received_or_committed`, and
  `target_size_bytes`
- `GetPictureInfo` returns `object_valid_flag`, `state_kind`,
  `metric_or_value_0`, and `metric_or_value_1`
- `GetPictureName` sets `picture_name_claim_cookie` on first claimant and then
  returns `object_name`
- notification type `4` opcode `3` writes `chunk_data` into `buffer_ptr` at the
  supplied offset and advances `bytes_received_or_committed`
- `completion_flag` is maintained as
  `(bytes_received_or_committed == target_size_bytes)`
- `+0x94` is only observed being cleared to zero in the recovered constructor /
  refresh paths (`FUN_7e84845b`, `DownloadPicture`, and the opcode-`3` / `5` /
  `6` rewrite helper); no recovered client path reads it
- subtype `4` updates the three address/hash/topic conversion tables through
    `NotificationType3_ApplyAddrConversionRecord` ->
    `AddrConversionCache_Insert`
  - subtype `5` updates the selector-`0x6e` title-info cache through
    `FUN_7e8424f5` -> `FUN_7e842267`
    - keyed by title byte and the selector-specific dword argument
    - when a payload is present, the callback caches a private byte copy and
      timestamps the entry
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

## Selector `0x1e`: `TitlePreNotify`

`TitlePreNotify` is not one homogeneous "byte + word + blob" RPC. The client
has a real opcode dispatcher in front of selector `0x1e`, and several opcodes
are either rewritten or absorbed locally.

General wire packing for opcodes that do reach the server:

- `0x01 title_byte`
  - if the caller passes title handle `-1`, the wrapper normalizes it to
    title byte `0`
- `0x02 opcode`
- `0x04 payload`
- reply handling is usually static-ack only

One wire-log pitfall matters here: the selector-`0x1e` request body remains
tag-encoded on the wire. For example:

- `01 00 02 08 00 04 81 81`
  - `0x01` byte param = title byte `0`
  - `0x02` word param = opcode `8`
  - `0x04` variable param = length `1`, payload byte `0x81`

So a naive server log can misreport that frame as an `8`-byte opcode payload
when the real opcode-specific payload is only `1` byte.

Opcode families:

- pure local opcodes
  - `0x09`
    - stores `*(u32 *)payload` into `DAT_7e84e2e0`
    - no `MEDVIEW` request is sent
  - `0x0b`
    - sets `DAT_7e84e2f1 = 1`
    - no `MEDVIEW` request is sent
  - `0x0c`
    - dispatches the local picture-control API covered below
  - `0x0f`
    - returns `DAT_7e84e2ec`
    - no `MEDVIEW` request is sent
- opcode `0x01`
  - expects a dword array at least two elements long
  - keeps the first dword unchanged as a context/slot id
  - filters the remaining dwords against the local word-wheel cache
    (`FUN_7e849199`)
  - if at least one miss remains, sends only the reduced dword array and primes
    the first missing entry through `FUN_7e849043`
  - if every requested entry is already cached, the helper suppresses the wire
    request entirely
- opcodes `0x02`, `0x0d`, `0x0e`
  - expect a dword array
  - filter that list against the title-scoped cache table also used by
    `vaConvertHash`
  - only still-missing entries survive into the transmitted payload
  - if nothing remains after filtering, no request is sent
- opcodes `0x03`, `0x05`, `0x06`
  - do not go out with their original payload shape
  - the helper walks a counted list of NUL-terminated object names, resolves or
    creates picture/file-object records, drops entries that are already fully
    satisfied locally, and repacks the survivors into opcode `0x04`
  - opcode `0x05` is the "force refresh" variant: it can keep entries that the
    other two variants would suppress
- opcode `0x08`
  - has no special local rewrite in `MVTTL14C!TitlePreNotify`
  - the wrapper sends it as a normal `0x01 title_byte` + `0x02 opcode` +
    `0x04 payload` request and waits only for the transport ack
  - `MVTTL14C!TitlePreNotify` binds no recv-side byte/word/dword/blob fields
    for this opcode, so a non-empty reply body is not required on recovered
    stock paths
  - one recovered `MOSVIEW.EXE` helper opens the bare parser control
    title token `":%d"` and transmits a payload shaped as:
    - `u8 status_code`
    - `char[] diagnostic_text_nul`
  - the only recovered stock value is `status_code = 1`, used for the
    formatted startup failure text
    `"The title Appid=%d, deid %X%8X, info='%s' would not start."`
  - a second recovered stock client path is `MVTTL14C!FUN_7e8440ab`, which
    sends `TitlePreNotify(0, 8, &tick_count_dword, 1)` every `>5s` while long
    async wait loops are active
  - that helper is called from recovered wait/retry loops including:
    - `vaConvertAddr`
    - `vaConvertHash`
    - `vaConvertTopicNumber`
    - `HighlightLookup`
    - `HfcNear`
    - `HfcNextPrevHfc`
    - `WordWheelLookup`
  - the changing one-byte wire sequence `0x81, 0x92, 0xb0, ...` therefore
    matches a real stock keepalive/status pulse, not a diagnostic string path
- all other nonzero opcodes below `0x10`
  - forward the caller payload as-is

For rewritten payloads, the helper allocates a temporary buffer, transmits that
buffer, then frees it immediately after the request object is queued.

`TitleNotifyLayout` is a thin exported toggle over that same picture/file
machinery:

- `TitleNotifyLayout(..., 0)` disables layout-driven refresh batching
- `TitleNotifyLayout(..., nonzero)` enables it
- the implementation batches pending object names by title slot and drives the
  existing opcode-`5` rewrite path, which in turn repacks to opcode `4`

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

Code-proven query result packing for control `1` is:

- `param_3[0]` = download buffer pointer
- `param_3[1]` = bytes received so far
- `param_3[2]` = target/total byte count
- `param_3[3]` = object valid/state flag at `+0x48`
- `param_3[4]` = subtype-`1`/`2` `state_kind` field at object `+0x80`
- `param_3[5]` = object `+0x84`
- `param_3[6]` = object `+0x88`

The type-3 subtype-`1`/`2` status block above is what feeds those object-side
fields.

### Remote start request

When the transfer is not already satisfied from a direct local file open,
`PictureDownload_StartOrRefresh` builds a selector-`0x1e` / opcode-`4` payload
and sends it through `TitlePreNotify`:

```text
PictureStartPayload
  u8  entry_count
  u8  mode_byte
  repeated entry_count times:
    u32 current_size
    u32 transfer_id
    u8  state_flags
    char[] nul_terminated_name
```

Code-proven field origins:

- `entry_count`
  - direct `PictureDownload_StartOrRefresh` emits `1`
  - the broader `TitlePreNotify` opcode `3` / `5` / `6` rewrite path can emit
    larger counts
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
| `0x6a` | payload | length-prefixed default title string |
| `0x13` | payload | indexed length-prefixed multisz record table |
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

Selector-specific payload semantics recovered from consumers:

- `0x6a`
  - `MVCL14N!fMVSetTitle` fetches this selector only when the caller did not
    provide an explicit title string
  - the returned bytes are stored in the viewer object's title-string handle at
    `+0x1c`
  - `MVCL14N!hMVGetTitle` later locks that same handle and copies it back out
  - so selector `0x6a` is the title-supplied default view title string, not an
    opaque side blob
- `0x13`
  - the payload section begins with `u16 section_bytes`, `u16 entry_count`,
    then repeated `u16 entry_bytes + u8[entry_bytes] entry_blob`
  - `TitleGetInfo` copies one `entry_blob` by index and forces a trailing NUL in
    the caller buffer
  - `MVTTL14C!TitleLoadDLL` proves each `entry_blob` is itself a small
    NUL-separated record
    - first string = requested DLL / driver alias
    - later strings = candidate load names or paths used for fallback loading
  - before lookup, `TitleLoadDLL` folds `mvdib12(.dll)` and `mvbmp2(.dll)` onto
    the canonical alias `mmvdib12`
  - this is the module-resolution table for title-specific viewer DLL loading,
    not a generic display string table

Return behavior:

- fixed record selectors return the fixed record size on success
- variable string/blob selectors return copied length
- `0xffffffff` signals failure or absence

Remote-fallback classes recovered from the selector-`0x03` path:

- NUL-terminated dynamic strings/blobs
  - selectors `0x03`, `0x05`, `0x0a`, `0x0c`, `0x0d`, `0x0f`, `0x10`, `0x66`
  - the client copies the returned dynamic bytes, then appends a NUL terminator
    in the caller buffer
- raw dynamic bytes with caller-supplied length cap
  - selector `0x0e`
  - copies up to `arg & 0xffff` bytes and does not append a terminator
- raw dynamic bytes of exact returned length
  - selectors `0x67`, `0x68`
  - copies `returned_length` bytes and treats failure to copy as fatal
- scalar/length-only results
  - selectors `0x6b`, `0x6d`
  - the wrapper returns the bound `0x83` dword and does not consume a dynamic
    body into `out`
- cached string-like selector
  - selector `0x6e`
  - first probes a local title-scoped cache keyed by `(title_byte, arg)`
  - on miss, falls through to selector `0x03`, copies a NUL-terminated dynamic
    body, then caches the result through `FUN_7e842267`
  - notification type `3`, subtype `5` can also populate that same cache
    asynchronously

So even where higher-level semantics remain unnamed, the client-side reply
grammar for the remote `TitleGetInfo` kinds is now split into concrete payload
classes rather than one opaque "optional dynamic body" bucket.

Negative evidence from the stock clients further narrows the open set:

- no recovered `MVCL14N` or `MOSVIEW` path issues `lMVTitleGetInfo(..., 0x6b, ...)`
  or `lMVTitleGetInfo(..., 0x6d, ...)`
- the only recovered `0x67` / `0x68` immediates in `MVCL14N` are not
  `TitleGetInfo` selectors
  - they are local subtype bytes written into generated `0x47` viewer records by
    the authored-text layout path
  - so the remote `TitleGetInfo` selectors `0x67` / `0x68` remain unconsumed by
    the stock client paths recovered in this pass
- the `0x66`..`0x6b` compare ladder in `MOSVIEW.EXE!MosMainWndProc` is also not a
  `TitleGetInfo` consumer
  - it is the shell `WM_COMMAND` menu dispatcher
  - `0x66` = create Internet Shortcut
  - `0x67` = close the top-level window
  - `0x68` = forward shell command `0x404` to the active child view
  - `0x69` = open help
  - `0x6a` = build the "About Title" dialog from child messages `0x406` and
    `0x414`
  - `0x6b` = open the generic `MosAbout` dialog
- the `0x68` values seen in `MOSVIEW.EXE!OpenTitlePathOrHash` and
  `MOSVIEW.EXE!MosViewContainerWndProc` are just heap-allocation sizes for local tracker
  nodes, not selector numbers

## Selectors MOSVIEW Actually Consumes

The main open path in `MOSVIEW.EXE!OpenTitleIntoDescriptor` uses:

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

The main open path does not consume `0x6a` or `0x13`, but both are now pinned
through non-MOSVIEW clients:

- `0x6a` backs `MVCL14N!hMVGetTitle` when `fMVSetTitle` was given only a title
  handle
- `0x13` is consumed by `MVTTL14C!TitleLoadDLL` as the title-specific
  module-resolution table

## Resolved Live Metadata Dwords

The three reply dwords from selector `0x01` are no longer equally ambiguous:

- title `+0x8c`
  - code-proven contents virtual address
  - exported directly by `MVTTL14C!vaGetContents`
  - wrapped by `MVCL14N!vaMVGetContents`
  - consumed by `MOSVIEW.EXE!OpenTitleIntoDescriptor` as the first-paint entry address
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

`MOSVIEW.EXE!OpenTitleIntoDescriptor` does not treat selectors `0x01` and `0x02` as opaque
binary blobs. It copies each into a stack buffer, runs `FUN_7f3c4427`, and only
then duplicates the result into the title descriptor at `+0x58` and `+0x5c`.

`FUN_7f3c4427` is a recursive wrapper around two simple unquoters:

- `FUN_7f3c445e` strips one layer of `` `...\' `` quoting
- `FUN_7f3c44b1` strips one layer of `"..."` quoting

No other decoding or escaping happens in this pass. Code therefore proves that
selectors `0x01` and `0x02` are expected to be ordinary NUL-terminated strings,
possibly wrapped in one or more layers of those quote syntaxes.

Later, the main child-view window proc `MosChildViewWndProc` returns duplicated copies
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

Static analysis of `MOSVIEW.EXE!BuildTitleViewWindows` and the child-view window
proc `MosChildViewWndProc` now pins down most of the fixed-record layouts.

### Selector `0x07`: `0x2b`-byte Child-Pane Descriptors

`OpenMediaTitleSession` enumerates selector `0x07` in its own loop, separate
from both selector `0x08` and selector `0x06`. Each `0x07` record then feeds
one extra `MosChildView` window.

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
- the trailing `u16` at `+0x29` is later compared against the parent
  `0x42d` staged-realization level
  - panes whose threshold is `<= wParam` become eligible for first
    instantiation through the local `0x42a` path
  - so this field is a lazy-open threshold / visibility-tier, not a static pane
    id
- no recovered `MOSVIEW` read in this constructor path treats any `0x07` bytes
  as a content pointer, authored object handle, or section/form index

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

`OpenMediaTitleSession` enumerates selector `0x06` in a third independent loop.
The main open path only consumes the first `0x06` record. Additional records,
if any, were not used in the constructor recovered here.

Code-proven fields in that first record:

- `+0x15`: inline container caption string used for the outer
  `MosViewContainer` window
- `+0x48`: flags byte
  - bit `0x08` selects the outer-container rect mode
  - bit `0x01` selects the top-child-band rect mode
  - bit `0x40` sets child object `+0x9c`, which later bottom-aligns the
    top child band during resize
- `+0x49`, `+0x4d`, `+0x51`, `+0x55`: outer container `x`, `y`, `w`, `h`
- `+0x5b`: unaligned dword copied into the viewer object at `+0x20`
  - the recovered constructor path stores it as a container-side control field
  - the synthetic title currently sends a red `COLORREF` here as the
    MosViewContainer color probe
- `+0x78`: `COLORREF` for the thin top child band tied to the child rect below
- `+0x7c`: `COLORREF` for the scrolling host strip; in the synthetic-title
  probe this is the white strip that carries the vertical scrollbar
- `+0x80`, `+0x84`, `+0x88`, `+0x8c`: top child band `x`, `y`, `w`, `h`

Behavior:

- outer container rects go through `FUN_7f3c1fd5`, which:
  - applies either `0x400`-relative or absolute-origin coordinates
  - compensates for the parent window's chrome
  - scales sizes by `DAT_7f3cd310 / 0x60`
- the first `0x06` record creates the outer container plus two visible layers:
  - a thin top child band from `+0x78` / `+0x80..+0x8c`
  - a separate scrolling host strip from `+0x7c`
- empiric synthetic-title probes show the deeper black content surface sits
  below that scrolling host strip and is not recolored by either `+0x78` or
  `+0x7c`
- this record does not substitute for selector `0x07`: extra child panes are
  still created only by the separate `0x07` table
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

Detailed first-authored text and section-0 notes now live in
`docs/mosview-authored-text-and-font-re.md`.

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
  - linked content list: three top-level authored content/proxy refs
  - no authored fixed-width pane table analogous to MediaView selectors
    `0x07`, `0x08`, or `0x06`
- proxy/source content visible in properties:
  - `Homepage.bdf`
  - `Calendar of Events_.bdf`
  - `bitmap.bmp`
- AUTHOR.HLP / BBDESIGN.HLP model:
  - project → title → section / page → window / controls → story / media assets
  - so `CSection.contents` is only one authored layer, not the whole display tree

What the recovered client behavior now pins down:

- Blackbird title / section / resource names:
  - candidate sources for selectors `0x01`, `0x02`, `0x04`, `0x13`, and `0x6a`
- selector `0x06`:
  - container scaffold only
  - drives the outer `MosViewContainer`, the thin top child band, and the
    scrolling host strip
- selector `0x07`:
  - separate child-pane table
  - each record creates one extra `MosChildView`
  - carries per-window metadata only on the recovered stock path
- Blackbird style-sheet and frame choices:
  - candidate source for the font blob that becomes selector `0x6f`

Practical lowering sketch:

- Blackbird section structure, not OLE container geometry, should drive the
  lowering input model
- the authored `CSection.contents` list is real authored data, but those
  entries are not themselves MediaView pane records
- the authored `CSection.forms` list is separate from `contents`, so treating
  the sample's three content proxies as a serialized child-pane table is not
  supported by the TTL object model
- the fixed-width MediaView tables `0x07`, `0x08`, and `0x06` should therefore
  be treated as lowering products synthesized from authored page/window/control
  structure, not from proxy count alone
- current live subset uses supported top-level proxy order only for
  topic/address/context mapping and string-table population; it emits one
  code-proven `0x06` scaffold and empty `0x07` / `0x08`
- the exact historical rule used by MSN's original lowering path is still open;
  authored child-pane and popup sources remain RE work

Blackbird concepts with no direct MediaView equivalent:

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
- stock-client negative-evidence pass for the remaining apparent selector
  collisions in `MOSVIEW.EXE`

Still open:

- acquire an authentic `.m14` or `MVCache_*.tmp`
- compare the parser output against live MOSVIEW-visible strings and tables
- assign semantics to the still-unknown bytes inside the `0x2b`, `0x1f`, and
  `0x98` records when a real sample or non-stock consumer proves them

At this point the remaining uncertainty is sample validation and a handful of
unconsumed/non-stock semantic names, not missing stock-client wire selectors or
missing request/reply classes.

No authentic MediaView cache sample exists in this workspace today, so the
layout claims above are code-proven but not yet sample-validated.
