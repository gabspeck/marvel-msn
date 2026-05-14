# MEDVIEW Service Contract

Docstring-style client-visible API reference recovered from stock
`MOSVIEW.EXE`, `MVCL14N.DLL`, and `MVTTL14C.DLL`.

## Framing

- `Request ID`: the per-call discriminator in the MEDVIEW host block. The
  selector numbers from the longer RE note are these request IDs.
- `Wire class byte`: the host-block class discriminator emitted as wire byte
  `0` of every request. Two literal values are pinned:
  - `class=0x00`, `selector=0x00`, `requestId=0` — bootstrap discovery frame,
    sent before any service wrapper exists.
  - `class=0x01` — every MEDVIEW-proxy request. Derived as the
    server-assigned selector for IID `00028B71` (TitleOpen — the first IID in
    the client's IID table; the client expects the server's index+1 rule to
    map idx 0 → `0x01`). Implementation walked in
    `docs/MEDVIEW.md §1.1`: stored at `MPCCL!ConstructServiceSelectorWrapper
    @ 0x0460320E` wrapper+0x10, copied into request builder+0x14 by
    `ConstructServiceRequestBuilder @ 0x046036C8`, emitted by
    `AppendRequestIdHeaderToWireBuilder @ 0x046064E4`.
- All logical API classes below ride the shared MEDVIEW proxy class byte
  `0x01`. Per-call selectors (`0x01`..`0x2A`, `0x1F`, `0x00`) sit at wire
  byte 1.
- Scalar types are little-endian.
- `cstring` means ANSI NUL-terminated string.
- `dynbytes` means a variable-length dynamic reply blob.
- `pack(index:u16, size:u16)` means `(index << 16) | size`.

## Class `BootstrapDiscovery`

Wire class: `0x00`

### `0x00` `DiscoverServiceInterfaces`

Purpose: enumerate the interface table exported by the remote service node
before the MEDVIEW-specific proxy is used.

Parameters:
- none.

Returns:
- `interfaceTable: bytes[17 * n]`. Repeated entries of
  `interfaceIid: bytes[16]`, `selectorByte: u8`.

## Class `SessionService`

Wire class: `0x01` (shared MEDVIEW proxy class; see Framing above). The
stock client does not expose separate class bytes for the logical groups
below — all of them ride the single proxy wrapper bound to IID
`00028B71`.

### `0x1f` `AttachSession`

Purpose: start the MEDVIEW protocol session and validate client capabilities.

Parameters:
- `clientVersion: u8`. Stock client emits the literal `1` at
  `hrAttachToService @ 0x7E844114`. No other value is observed.
- `capabilities: bytes[12]`. Layout: `clientFlags0:u32`, `clientFlags1:u32`,
  `browseLcid:u32`.
  - `clientFlags0`: literal `0x00002000`. Client never inspects after
    send. `client-opaque (verified at hrAttachToService @ 0x7E844114)`.
  - `clientFlags1`: literal `0x00004006`. Client never inspects after
    send. `client-opaque (verified at hrAttachToService @ 0x7E844114)`.
  - `browseLcid`: `GetPreferenceDword("BrowseLanguage",
    GetDwDefLcidBrowse())` — Win95-locale default overridden by
    `HKCU\Software\Microsoft\MOS\Preferences\BrowseLanguage` if present.
    Client never reads it back after send.

Returns:
- `validationToken: u32`. The single field bound to the reply slot.
  Effect (per `hrAttachToService @ 0x7E844114`):
  - `0` → `MessageBoxA("Handshake validation failed — Ver …")` followed
    by `fDetachFromService()`. The attach call returns failure.
  - Any nonzero value → handshake accepted, attach continues to install
    notification subscribers (selector `0x17` × 5).

### `0x17` `SubscribeNotifications`

Purpose: open a long-lived streamed notification channel.

Parameters:
- `notificationType: u8`. Valid values on stock paths: `0`, `1`, `2`, `3`,
  `4`.

Returns:
- `notificationStream`. A pending streamed reply handle that yields notification
  records until unsubscribed or detached.

On subscriber destroy the client also ships an MPCCL iterator-cancel
control frame on the same `(class, selector, req_id)` triple — see
`docs/MEDVIEW.md` §6d.0. The framing-layer cancel always fires;
selector `0x18` below is only sent when `skipWireUnsubscribe == 0`.

### `0x18` `UnsubscribeNotifications`

Purpose: stop one notification stream.

Parameters:
- `notificationType: u8`. Valid values on stock paths: `0`, `1`, `2`, `3`,
  `4`.

Returns:
- `ack`. No meaningful payload.

## Class `TitleService`

Wire class: `0x01` (shared MEDVIEW proxy).

### `0x00` `ValidateTitle`

Purpose: check whether a title slot is still valid. Wire selector `0x00`
in the proxy class is IID-less — see `docs/MEDVIEW.md §2.1.1` for the
relationship to the discovery-class `0x00` and the `MVTTL14C!TitleValid
@ 0x7E8423AD` call site.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.

Returns:
- `isValid: u8`. Zero means invalid; nonzero means valid.

### `0x01` `OpenTitle`

Purpose: open a title, recover live metadata, and return the cache-backed
payload blob.

Parameters:
- `titleToken: cstring`. For stock MOSVIEW this is a parser token like
  `:2[path]0`, not a bare filesystem path.
- `cacheHint0: u32`. Read from the first 4 bytes of
  `HKLM\Software\Microsoft\MOS\Directories\MOSBin\MVCache\<title>.tmp`
  (zero if absent). `client-opaque (verified at TitleOpenEx @
  0x7E842D4E)` — the client only ever `memcmp`'s the reply's
  `cacheHeader0` against it and, on match, replays the cached body. No
  semantic inspection.
- `cacheHint1: u32`. Same source/role as `cacheHint0` but the trailing 4
  bytes of the cache file's 8-byte header. `client-opaque (verified at
  TitleOpenEx @ 0x7E842D4E)`.

Returns:
- `titleSlot: u8`. The live title slot used by later requests. Zero is
  rejected (open fails, viewer surfaces NULL).
- `fileSystemMode: u8`. Stored at `title+0x88`; later surfaced by local
  `TitleGetInfo(0x69)` and passed as HFS mode to baggage open
  (`HfOpenHfs`, §6c).
- `contentsVa: u32`. Stored at `title+0x8c`; surfaced by local
  `vaGetContents @ 0x7E841D48` (which returns the field verbatim).
  Threaded through `MVCL14N!fMVSetAddress @ 0x7E883600` into
  `HfcNear @ 0x7E84589F`. `0` or `0xFFFFFFFF` both route
  `NavigateViewerSelection` into the `hideOnFailure` branch.
- `contentsAddr: u32`. Stored at `title+0x90`; surfaced by local
  `addrGetContents @ 0x7E841D07` (wrapped by `MVCL14N!addrMVGetContents
  @ 0x7E8854D0`). Companion to `contentsVa` for the kind-2 va→addr
  cache. MSN Today's first-paint chain does not read it; zero is
  harmless on the welcome screen.
- `topicUpperBound: u32`. Stored at `title+0x94`; surfaced by local
  `TitleGetInfo(0x0b)`. Used as upper bound by
  `hMVTopicListFromTopicNo`; zero means no topic resolves.
- `cacheHeader0: u32`. The new authoritative half of the cache key.
  `client-opaque (verified at TitleOpenEx @ 0x7E842D4E)`: client
  `memcmp`s `(cacheHeader0, cacheHeader1)` against the cached pair; on
  match reuses the cached `payloadBlob`, on mismatch writes the new
  header + body back to `MVCache_<title>.tmp`. Server contract:
  emit a stable nonzero pair per (title, content) tuple; flip on
  content change.
- `cacheHeader1: u32`. Companion to `cacheHeader0`. Same role and
  treatment.
- `payloadBlob: dynbytes`. Flat MediaView 9-section title body — see
  `docs/MEDVIEW.md §4.4`.

### `0x02` `CloseTitle`

Purpose: release a previously opened title slot.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.

Returns:
- `ack`. No meaningful payload.

### `0x03` `GetTitleInfoRemote`

Purpose: remote fallback for title-info kinds not served from the local cached
  title payload. Issued by `TitleGetInfo @ 0x7E842558` whenever the requested
  `infoKind` is not one of the locally-served kinds (`0x01`/`0x02`/`0x04`/`0x06`/`0x07`/`0x08`/`0x0B`/`0x13`/`0x69`/`0x6A`/`0x6F`) or when `0x6E`
  misses the local `MVLookupCachedInfo6eString` cache.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`. Emitted at `TitleGetInfo @ 0x7E842BD9` via builder+0x30.
- `infoKind: u32`. Selector switch. Emitted at `TitleGetInfo @ 0x7E842BDF` via
  builder+0x28. Full enumeration is the `Remote GetTitleInfoRemote Kinds`
  block below; each kind selects one of four reply post-processing paths
  (`string-copy`, `byte-capped-copy`, `raw-copy`, `cached-string-copy`) at
  `TitleGetInfo @ 0x7E842B1E..0x7E842BC4`.
- `infoArg: u32`. Selector-specific argument. The per-kind table below
  lists the exact bit-packing rule applied at `TitleGetInfo` — typically
  either a caller buffer-byte cap in the low `u16`, an index packed in the
  high `u16` with size in the low `u16`, or a cache key dword. Kinds that
  do not consume `infoArg` send it as zero.
- `callerCookie: u32`. Emitted at `TitleGetInfo @ 0x7E842BE5` via
  builder+0x28; sourced from the caller-supplied `outBuffer` pointer. The
  client never binds it back from the reply — `client-opaque (verified
  at TitleGetInfo @ 0x7E842558 — the only reply binding is `lengthOrScalar`
  via builder+0x18; outBuffer is consumed in-process by `MVCopyDynamicStreamBytes`,
  the wire echo is purely a server-side request-correlation token)`.

Returns:
- `lengthOrScalar: u32`. Bound from the reply via builder+0x18 at
  `TitleGetInfo @ 0x7E842BEB`. For `string-copy` and `byte-capped-copy`
  kinds, the value is the returned byte count of `payload` (truncated to
  the bufsize cap when applicable). For `scalar` kinds (`0x6B`, `0x6D`),
  the value is the scalar result and `payload` is absent.
- `payload: dynbytes`. Present only for kinds that return dynamic bytes;
  copied via `MVCopyDynamicStreamBytes` (`FUN_7e842494`).

### `0x04` `QueryTopics`

Purpose: execute a title query and open a highlight-aware topic-list session.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`. Sourced from `*(byte *)(param_1 + 2)` at `TitleQuery @
  0x7E841653`.
- `queryClass: u16`. Caller-supplied class word emitted at builder+0x2c.
  `client-opaque (verified at TitleQuery @ 0x7E841653)` — the wrapper
  emits `param_2` verbatim and never inspects it again.
- `primaryText: cstring`. Main query string (param_3). Emitted at
  builder+0x24 as `[len bytes]`. NULL caller returns 0 before any wire
  traffic — the stock guard at `TitleQuery @ 0x7E841653`.
- `queryFlags: u8`. Synthesised by the wrapper from caller pointer
  arguments. Bit derivations (see `TitleQuery @ 0x7E841653`):
  - bit `0x01` `HasSecondaryText` — set when `param_5` (secondaryText)
    is non-NULL. Effect: append `secondaryText:cstring` after the
    queryFlags byte.
  - bit `0x02` `HasSourceGroup` — set when `param_4`
    (sourceGroupBlob) is non-NULL. Effect: append the `0x40`-byte
    header at `param_4` plus the dynamic blob at
    `*(u32 *)(param_4+0x1E)` with size `*(u32 *)(param_4+0x04)`.
  - bit `0x04` `HasAuxRequest40` — set when `param_7`
    (auxRequest40) is non-NULL. Effect: append exactly `0x40` bytes
    from `param_7`.
- `queryMode: u16`. Caller-supplied mode word emitted at builder+0x2c
  after the queryFlags byte. `client-opaque (verified at TitleQuery @
  0x7E841653)`.
- `secondaryText: cstring`. Required when `queryFlags & 0x01` is set.
- `sourceGroupBlob: dynbytes`. Required when `queryFlags & 0x02` is set.
- `auxRequest40: bytes[0x40]`. Required when `queryFlags & 0x04` is set.

Returns:
- `highlightContext: u8`. Bound at builder+0x20. Nonzero result opens a
  highlight-aware query session; the client stores it into
  `&DAT_7e84e028[ctx]` plus the 16-byte slot at
  `&DAT_7e84d028 + ctx*0x10` (init: status=1, addr=`0xffffffff`,
  flags=0). Zero leaves no per-context state.
- `logicalCount: u32`. Bound at builder+0x18 #1 (local_28). Returned in
  `*param_8`.
- `secondaryResult: u32`. Bound at builder+0x18 #2 (local_24). Returned
  in `*param_9`. `client-opaque (verified at TitleQuery @ 0x7E841653)` —
  the wrapper writes the dword to the caller's out-parameter but never
  inspects it; no CMP/TEST in the wrapper body.
- `auxReply: dynbytes`. Bound at builder+0x14 when `queryFlags & 0x04`
  is set. Memcpy'd to `*(void **)(param_7 + 0x1E)`.
- `sideband12: bytes[12]`. Second dynbytes binding at builder+0x14;
  copied to `*param_10` only when the dynamic reply is exactly `0x0C`
  bytes long. Default value of `*param_10` (when caller passes a
  buffer) is `(0x7d1, 0, 0)`.

### `0x1e` `PreNotifyTitle`

Purpose: send title-side pre-notification control operations. Some opcodes are
rewritten or absorbed locally before any wire send occurs.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`. The local wrapper also normalizes title handle `-1` to slot `0`.
- `notifyOp: u16`. Valid values: documented `PreNotifyTitle` opcodes below.
- `notifyPayload: dynbytes`. Opcode-specific payload.

Returns:
- `status: i32`. For wire-reaching opcodes, `0` means the request was queued
  and transport-acked; `0xffffffff` means setup or send failure.
- local result. For local-only opcodes such as `PictureControl` and
  `GetLayoutCookie`.

## Class `WordWheelService`

Wire class: `0x01` (shared MEDVIEW proxy).

### `0x09` `OpenWordWheel`

Purpose: open or reuse a word-wheel session for one title.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `titleName: cstring`. Title name string used as the word-wheel key.

Returns:
- `wordWheelId: u8`. Remote word-wheel slot identifier.
- `itemCount: u32`. Item count cached by the client.

### `0x08` `QueryWordWheel`

Purpose: execute a word-wheel search/update operation.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`. Emitted via builder+0x30 at `WordWheelQuery @ 0x7E849EE3`.
- `queryMode: u16`. Caller-supplied mode word emitted via builder+0x2C at
  `WordWheelQuery @ 0x7E849EE6`. `client-opaque (verified at WordWheelQuery
  @ 0x7E849E99 — the wrapper passes `param_2` verbatim and never branches
  on its value; semantic meaning lives in the external caller (MOSFIND /
  MOSVIEW search UI))`.
- `queryText: cstring`. Query string emitted as `[len bytes]` via
  builder+0x24 at `WordWheelQuery @ 0x7E849EFB`. Length computed via
  `strlen`-style scan immediately before the emit.

Returns:
- `status: u16`. Bound via builder+0x1C at `WordWheelQuery @ 0x7E849F03`;
  returned directly to the caller (initialised to `0x3E9` failure
  sentinel; overwritten by the reply binding on success).

### `0x0a` `CloseWordWheel`

Purpose: release a word-wheel session when the local refcount reaches zero.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`.

Returns:
- `ack`. No meaningful payload.

### `0x0b` `ResolveWordWheelPrefix`

Purpose: probe a prefix result for a word-wheel.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`.
- `prefixText: cstring`. Prefix string.

Returns:
- `prefixResult: u32`. Prefix result word returned synchronously.

### `0x0c` `LookupWordWheelEntry`

Purpose: resolve one word-wheel ordinal to a string.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`. Emitted via builder+0x30 at `WordWheelLookup @ 0x7E8497A1`.
- `ordinal: u32`. Entry ordinal to resolve. Emitted via builder+0x28
  immediately after. Also used by the in-process race-against-cache loop:
  matched against `WordWheelCache_FindEntry(wordWheelId, &local_20,
  &local_40 := param_2, …)` and against the per-wordwheel slot at
  `DAT_7e84e668[wordWheelId * 0x1c]` for pendingFlag / recent-completion
  detection.
- `outputLimit: u32`. Caller's maximum byte cap. Emitted via builder+0x28
  on the wire **and** consumed locally at `WordWheelLookup @ 0x7E8498B7`
  as the cap when copying the cached entry text into the caller's
  outBuffer: `if ((int)param_4 < (int)copyLen) copyLen = param_4;`.
  Single-valued effect (truncation cap); no branching.

Returns:
- `ack`. The function returns `true` once the matching cache entry has
  been copied. The actual string arrives later through notification type
  `1` (`WordWheelCache_DispatchNotification @ 0x7E849251`) — the wrapper
  polls the cache every ~100 ms while pumping notifications, with a
  ~30 s hard timeout and a periodic re-emit of the selector-`0x0C` wire
  request every 20 poll iterations (~2 s).

### `0x0d` `CountKeyMatches`

Purpose: count matches for one word-wheel key string.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`.
- `keyText: cstring`. Key string.

Returns:
- `matchCount: u16`. Count word.

### `0x0e` `ReadKeyAddresses`

Purpose: fetch address dwords for a key string.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`.
- `keyText: cstring`. Key string.
- `startIndex: u16`. Starting entry index.
- `maxCount: u16`. Maximum element count requested.

Returns:
- `addressList: dynbytes`. Packed dword array. The wrapper interprets the
  return as copied byte count, not element count.

### `0x0f` `SetKeyCountHint`

Purpose: push a count hint for a key string.

Parameters:
- `wordWheelId: u8`. Valid values: word-wheel ids previously returned by
  `OpenWordWheel`.
- `keyText: cstring`. Key string. Null is rejected locally.
- `countHint: u16`. Count hint word.

Returns:
- `success: u8`. Zero/nonzero success byte.

## Class `AddressHighlightService`

Wire class: `0x01` (shared MEDVIEW proxy).

### `0x05` `ConvertAddressToVa`

Purpose: refresh the VA for one address token.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `addressToken: u32`. Valid value on stock path: anything except `0xffffffff`.

Returns:
- `ack`. Actual result arrives via notification type `3`, subtype `4`.

### `0x06` `ConvertHashToVa`

Purpose: refresh the VA for one context hash.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `contextHash: u32`. Stock client rejects `0`.

Returns:
- `ack`. Actual result arrives via notification type `3`, subtype `4`.

### `0x07` `ConvertTopicToVa`

Purpose: refresh the VA for one topic number.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `topicNumber: u32`. Topic number in the title's topic space.

Returns:
- `ack`. Actual result arrives via notification type `3`, subtype `4`.

### `0x10` `LoadTopicHighlights`

Purpose: fetch the highlight blob for one topic or address token.

Parameters:
- `highlightContext: u8`. Low byte of the active highlight/query context.
- `topicOrAddress: u32`. Topic token or address token, depending on caller.

Returns:
- `highlightBlob: dynbytes`. Runtime layout:
  - `bytes[8]` header — `client-opaque (verified at HighlightsInTopic
    @ 0x7E841526)`; the wrapper memcpys the leading 8 bytes through
    `MVCopyDynamicReplyStreamBytes @ 0x7E842494` but never branches on
    them.
  - `highlightCount: u32` — entry count.
  - `count × (anchorToken:u32, aux0:u32, aux1:u32, spanOrCount:u8)` —
    13-byte highlight entries.

### `0x11` `FindHighlightAddress`

Purpose: resolve a highlight search key pair to an address token.

Parameters:
- `highlightContext: u8`. Low byte of the active highlight/query context.
- `searchKey0: u32`. Search key dword.
- `searchKey1: u32`. Search key dword.

Returns:
- `addressToken: u32`. Address-space result token.

### `0x12` `ReleaseHighlightContext`

Purpose: drop a remote highlight context when the local refcount reaches zero.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.

Returns:
- `ack`. No meaningful payload.

### `0x13` `RefreshHighlightAddress`

Purpose: refresh the cached address for one highlight id.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `highlightId: u32`. Highlight id / ordinal.

Returns:
- `ack`. Actual result arrives via notification type `2`.

## Class `TopicCacheService`

Wire class: `0x01` (shared MEDVIEW proxy).

### `0x15` `FetchNearbyTopic`

Purpose: refresh the topic-body cache entry nearest one address token.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `addressToken: u32`. Topic/address token.

Returns:
- `ack`. Actual topic body arrives via notification type `0`.

### `0x16` `FetchAdjacentTopic`

Purpose: refresh the next or previous topic-body cache entry.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `currentToken: u32`. Current topic/address token (the va the client wants
  to step from). Source: `pvVar2+4` for backward step, `pvVar2+0xC` for
  forward step — both cache slots inside the caller's HGLOBAL.
- `direction: u8`. Wire byte computed as `0x01 - (param_2 == 0)` at
  `HfcNextPrevHfc @ 0x7E845ABB`:
  - `0x00` — previous (caller param_2 = 0).
  - `0x01` — next (caller param_2 != 0).
  No other values are emitted by the client.

Returns:
- `ack`. Actual topic body arrives via notification type `0`.

## Class `RemoteFileService`

Wire class: `0x01` (shared MEDVIEW proxy).

### `0x1a` `OpenRemoteHfsFile`

Purpose: open one title-side baggage/HFS file through MEDVIEW.

Parameters:
- `hfsMode: u8`. Wrapper-supplied byte. Stock callers feed the
  low byte of `title+0x88` (the TitleOpen `fileSystemMode` reply
  field). `client-opaque (verified at HfOpenHfs @ 0x7E847656,
  BaggageOpen @ 0x7E848205)` — both wrappers `MOV`/emit `param_1`
  verbatim with no CMP/TEST on its value.
- `fileName: cstring`. Title-side file name (param_2 of `HfOpenHfs`),
  copied via `strlen+1`.
- `openMode: u8`. The stock `BaggageOpen` wrapper hardcodes literal
  `2` for the remote path; no other value reaches the wire.
  `client-opaque (verified at HfOpenHfs @ 0x7E847656)`.

Returns:
- `remoteHandleId: u8`. Bound at builder+0x20. Zero is treated as
  failure by the stock `HfOpenHfs` wrapper (allocates no handle,
  returns NULL).
- `fileSize: u32`. Bound at builder+0x18. Stored at `handle+0`.

### `0x1b` `ReadRemoteHfsFile`

Purpose: read raw bytes from one remote HFS file handle.

Parameters:
- `remoteHandleId: u8`. Valid values: handle ids previously returned by
  `OpenRemoteHfsFile`.
- `requestedLength: u32`. Requested byte count.
- `currentOffset: u32`. Current read offset.

Returns:
- `status: u8`. Status byte bound by the wrapper.
- `fileBytes: dynbytes`. Exact returned byte stream.

### `0x1c` `CloseRemoteHfsFile`

Purpose: close one remote HFS file handle.

Parameters:
- `remoteHandleId: u8`. Valid values: handle ids previously returned by
  `OpenRemoteHfsFile`.

Returns:
- `ack`. No meaningful payload.

### `0x1d` `GetRemoteFsError`

Purpose: read the current remote filesystem error word.

Parameters:
- none.

Returns:
- `fsError: u16`. Stock wrapper initializes this to `8` before the request and
  keeps that fallback on setup failure.

## Family `TitleGetInfoKind`

These are local title-info selectors served from the title object or cached
payload before the wrapper falls back to remote request `0x03`.

### Kind `0x6f` `FontTableHandle`

Purpose: return the title font-table handle.

Parameters:
- `infoArg: u32`. Unused.

Returns:
- `fontHandle: u32`. Global-memory handle used by the viewer.

### Kind `0x69` `FileSystemMode`

Purpose: return the file-system / mode code from `OpenTitle`.

Parameters:
- `infoArg: u32`. Unused.

Returns:
- `fileSystemMode: u32`.

### Kind `0x0b` `TopicCountUpperBound`

Purpose: return the title topic upper bound.

Parameters:
- `infoArg: u32`. Unused.

Returns:
- `topicUpperBound: u32`.

### Kind `0x07` `ChildPaneRecord`

Purpose: return one fixed-width child-pane descriptor.

Parameters:
- `infoArg: u32`. Use `pack(recordIndex, bufferBytes)`.
- `recordIndex: u16`. Child-pane record index.
- `bufferBytes: u16`. Caller buffer size. Must be at least `0x2b`.

Returns:
- copied `ChildPaneRecord`.
- function result `0x2b` on success.

### Kind `0x08` `PopupPaneRecord`

Purpose: return one fixed-width popup descriptor.

Parameters:
- `infoArg: u32`. Use `pack(recordIndex, bufferBytes)`.
- `recordIndex: u16`. Popup record index.
- `bufferBytes: u16`. Caller buffer size. Must be at least `0x1f`.

Returns:
- copied `PopupPaneRecord`.
- function result `0x1f` on success.

### Kind `0x06` `WindowScaffoldRecord`

Purpose: return one fixed-width window scaffold descriptor.

Parameters:
- `infoArg: u32`. Use `pack(recordIndex, bufferBytes)`.
- `recordIndex: u16`. Scaffold record index.
- `bufferBytes: u16`. Caller buffer size. Must be at least `0x98`.

Returns:
- copied `WindowScaffoldRecord`.
- function result `0x98` on success.

### Kind `0x01` `TitleNameText`

Purpose: return the title-name string.

Parameters:
- `infoArg: u32`. Low `u16` is caller buffer size.

Returns:
- copied byte length.
- `titleName: cstring`.

### Kind `0x02` `CopyrightText`

Purpose: return the copyright string.

Parameters:
- `infoArg: u32`. Low `u16` is caller buffer size.

Returns:
- copied byte length.
- `copyrightText: cstring`.

### Kind `0x6a` `DefaultViewTitle`

Purpose: return the title-supplied default window title.

Parameters:
- `infoArg: u32`. Low `u16` is caller buffer size.

Returns:
- copied byte length.
- `defaultViewTitle: cstring`.

### Kind `0x13` `ViewerModuleMapEntry`

Purpose: return one title-specific viewer DLL resolution record.

Parameters:
- `infoArg: u32`. Use `pack(entryIndex, bufferBytes)`.
- `entryIndex: u16`. Module map record index.
- `bufferBytes: u16`. Caller buffer size.

Returns:
- copied byte length.
- one NUL-separated module-resolution entry.

### Kind `0x04` `ExtraTitleString`

Purpose: return one indexed extra title string.

Parameters:
- `infoArg: u32`. Use `pack(stringIndex, bufferBytes)`.
- `stringIndex: u16`. String index.
- `bufferBytes: u16`. Caller buffer size.

Returns:
- copied byte length.
- `extraString: cstring`.

### Remote `GetTitleInfoRemote` Kinds

Purpose: describe the proven payload classes for remote title-info kinds whose
full semantics are not always consumed by stock clients.

- `0x03` `RemoteCString03`. Returns a NUL-terminated dynamic string.
- `0x05` `RemoteCString05`. Returns a NUL-terminated dynamic string.
- `0x0a` `RemoteCString0A`. Returns a NUL-terminated dynamic string.
- `0x0c` `RemoteCString0C`. Returns a NUL-terminated dynamic string.
- `0x0d` `RemoteCString0D`. Returns a NUL-terminated dynamic string.
- `0x0f` `RemoteCString0F`. Returns a NUL-terminated dynamic string.
- `0x10` `RemoteCString10`. Returns a NUL-terminated dynamic string.
- `0x66` `RemoteCString66`. Returns a NUL-terminated dynamic string.
- `0x0e` `RemoteBytes0E`. `infoArg` low `u16` is the caller byte cap. Returns
  capped raw bytes.
- `0x67` `RemoteExactBytes67`. Returns exact-length raw bytes.
- `0x68` `RemoteExactBytes68`. Returns exact-length raw bytes.
- `0x6b` `RemoteScalar6B`. Returns a scalar `u32`.
- `0x6d` `RemoteScalar6D`. Returns a scalar `u32`.
- `0x6e` `CachedRemoteCString`. `infoArg` is a cache key dword. Returns a
  cached NUL-terminated string.

## Family `PreNotifyTitleOpcode`

### Opcode `0x01` `PrimeWordWheelCache`

Purpose: prime word-wheel-result-cache entries by reporting which ordinals are
  not yet locally cached, so the server can push the missing entries via
  the type-`1` notification stream.

Consumer: `TitlePreNotify_PrimeWordWheelCache @ 0x7E84A028`.

Parameters:
- `notifyPayload: u32[>=2]`. Caller-supplied DWORD array.
  - element `[0]`: `wordWheelId` (preserved verbatim in the filtered payload
    as element `[0]`). Indexes the per-wordwheel slot at
    `DAT_7e84e668[DAT_7e850258[wordWheelId] × 0x1c]`.
  - elements `[1..N-1]`: candidate ordinals. Each is probed against the
    local `WordWheelCache_FindEntry(wordWheelId, ordinal, …)`; cache misses
    are appended to the filtered payload, cache hits are marked locally
    satisfied (`entry[0x20] = 1`) and omitted from the wire.
  - The **first** miss in a single PrimeWordWheelCache call seeds a
    placeholder local entry via `WordWheelCache_InsertEntry(wordWheelId,
    pending=1, ordinal, NULL, status=0xFFFF, NULL)` to dedupe future
    in-flight probes.

Returns:
- `ack` if at least one ordinal misses (filtered payload contains
  `wordWheelId` + ≥1 missing ordinal — total ≥5 bytes).
- **local suppression** (`MVFreeBytes(filteredPayload)`, no wire send)
  when every candidate was already cached.

### Opcode `0x02` `PrimeTitleCache02`

Purpose: prime kind-1 va/addr cache entries by reporting which values are
  not yet locally cached, so the server can push the missing entries via
  the type-`3` op-`4` notification stream.

Consumer: `TitlePreNotify_BuildUncachedKind2List @ 0x7E842162`.

Parameters:
- `notifyPayload: u32[]`. Caller-supplied DWORD array. Each entry is probed
  against `MVGlobalVaAddrCache_FindKind1Value4(value, titleByte, &cached)`;
  cache misses are appended verbatim to the filtered payload, cache hits
  are dropped.

Returns:
- `ack` if at least one entry missed (filtered payload non-empty).
- **local suppression** (`MVFreeBytes(filteredPayload)`, no wire send)
  when every entry was already cached.

Notes:
- Same helper (`TitlePreNotify_BuildUncachedKind2List`) is dispatched for
  opcodes `0x0D` and `0x0E`, but the helper rejects unless
  `*notifyKind == 2`. In practice opcodes `0x0D` / `0x0E` always return
  `0xFFFFFFFF` (no wire send, no local state change) — they are reachable
  through `TitlePreNotify @ 0x7E843941` but functionally inert. See
  opcodes `0x0D` / `0x0E` below.

### Opcode `0x03` `QueueTransferNames`

Purpose: queue picture/file object names for transfer refresh.

Parameters:
- `notifyPayload`. Counted list of NUL-terminated object names.

Returns:
- rewritten local path. The stock wrapper repacks the surviving entries into
  opcode `0x04`.

### Opcode `0x04` `StartTransferBatch`

Purpose: start one or more remote picture/content transfers.

Parameters:
- `notifyPayload: PictureStartPayload`.

Returns:
- `ack`.

### Opcode `0x05` `ForceRefreshTransferNames`

Purpose: force-refresh queued transfer names.

Parameters:
- `notifyPayload`. Counted list of NUL-terminated object names.

Returns:
- rewritten local path. The stock wrapper repacks the surviving entries into
  opcode `0x04`.

### Opcode `0x06` `RefreshTransferNames`

Purpose: refresh queued transfer names without the force-refresh behavior of
opcode `0x05`.

Parameters:
- `notifyPayload`. Counted list of NUL-terminated object names.

Returns:
- rewritten local path. The stock wrapper repacks the surviving entries into
  opcode `0x04`.

### Opcode `0x07` `SetSubscriberEnabledState`

Purpose: report a subscriber's enable transition (used as a heartbeat
when subscribers come/go).

Parameters:
- `notifyPayload: bytes[5]`. Layout: `subscriberType:u8`,
  `enabled:u32` (low bit reflects the new state). Sent by
  `MVAsyncSubscriberSetState @ 0x7E84490C` when bit 0 of the subscriber
  state flips. `client-opaque (verified at MVAsyncSubscriberSetState
  @ 0x7E84490C)` — the wrapper only writes the bytes.

Returns:
- `ack`. `TitlePreNotify @ 0x7E843941` deliberately **skips**
  `MVMarkPendingNotificationsBeforeRequest` for kind 7 (the only
  opcode treated specially in the dispatch tail).

### Opcode `0x08` `SendClientStatus`

Purpose: send a client-status / keepalive blob through `PreNotifyTitle`.
The wrapper does not inspect the payload it forwards; the two known
stock callers each emit their own fixed shape (`client-opaque (verified
at TitlePreNotify @ 0x7E843941)` — kind 8 hits the default branch which
forwards `payload`/`payloadBytes` verbatim).

Parameters:
- `notifyPayload: dynbytes`. Caller-supplied bytes, no wrapper
  inspection.

Observed stock payload forms:
- `heartbeatByte: u8`. `MVTTL14C!MVCheckMasterFlag @ 0x7E8440AB` sends
  one byte every `>5s` while async wait loops are active. The byte is
  copied from the current tick-count dword and acts as a changing
  keepalive pulse.
- `statusCode: u8`, `diagnosticText: cstring`. `MOSVIEW.EXE` uses this
  shape on the title-start failure path. The recovered stock value is
  `statusCode=1` with text of the form
  `"The title Appid=%d, deid %X%8X, info='%s' would not start."`

Returns:
- `status: i32`. `0` on queued/acked send, `0xffffffff` on setup failure.
- no dynamic reply payload. `MVTTL14C!TitlePreNotify` binds no recv-side
  fields for this opcode.

### Opcode `0x0a` `PostAttachCookie`

Purpose: hand the server the layout-cookie seed at attach time. Sent
exactly once per attach by `hrAttachToService @ 0x7E844114`
immediately after the selector `0x1F` handshake succeeds.

Parameters:
- `notifyPayload: bytes[6]`. Source: `&DAT_7E84E2EC`, the same slot
  later read by opcode `0x0F GetLayoutCookie`. Bootstrapped from
  `DAT_7E851808` (stock value: 0). All zero bytes on the stock
  open path.

Returns:
- `ack`. Client never inspects the seed after send.
  `client-opaque (verified at hrAttachToService @ 0x7E844114)`.

### Opcode `0x09` `SetLayoutCookie`

Purpose: store one local layout cookie.

Parameters:
- `notifyPayload: u32`. Caller's 4 bytes.

Returns:
- local only. Stores `*(u32 *)payload` at `DAT_7E84E2E0`
  (`TitlePreNotify @ 0x7E843941` case 9). No MEDVIEW request is sent.

### Opcode `0x0b` `DisableMVCacheWrites`

Purpose: disable on-disk `MVCache_<title>.tmp` writes for the rest of
  the session.

Parameters:
- ignored.

Returns:
- local only. Sets `DAT_7E84E2F1 = 1` (`TitlePreNotify @ 0x7E843941`
  case 0xB). The flag is consumed at `TitleOpenEx @ 0x7E842D4E` to
  skip the `CreateFileA(GENERIC_WRITE, CREATE_ALWAYS, …)` + payload
  `WriteFile` after a live-stream title-body fetch. Reads (loading an
  existing `.tmp`) are unaffected. No MEDVIEW request is sent.

### Opcode `0x0c` `PictureControl`

Purpose: dispatch local picture-transfer control operations.

Consumer: `TitlePreNotify_LocalPictureControl @ 0x7E84753C`.

Parameters:
- `notifyPayload: PictureControlRequest`. Buffer ≥4 bytes; first u32
  is `control:u32`:
  - `control = 0` `StartOrRefresh`: requires `titleState != 0` and at
    least 8 bytes plus a NUL-terminated object name; the wrapper reads
    `buffer[1]` as consumer HWND and `buffer[2..]` as the name string;
    calls `DownloadPicture(out_handle, hwnd, titleState, name)`.
  - `control = 1` `QueryStatus`: requires `controlBytes >= 0x28` and
    `buffer[1] != 0` (picture handle); calls `GetDownloadStatus +
    GetPictureInfo`; on success packs the 7-DWORD `PictureControlQueryResult`
    in-place over the caller buffer (`bufferPtr, bytesReceived,
    targetBytes, objectValidFlag, stateKind, metric0, metric1`).
  - `control = 2` `Detach`: calls `DetachPicture(buffer[2] /* handle */,
    buffer[1] /* hwnd */)`.
  - Any other `control` value: returns `0` (reject).

Returns:
- `control = 0`: picture handle u32 (or 0 on failure).
- `control = 1`: `1` on success (with `PictureControlQueryResult` packed
  into the caller buffer); `0` on failure (buffer too small, status
  query failed, or info query failed).
- `control = 2`: always `0`.
- No MEDVIEW request is sent.

### Opcode `0x0d` `PrimeTitleCache0D` (inert)

Purpose: nominally prime title cache entries, but functionally inert in
  stock builds.

Parameters:
- `notifyPayload: u32[]`. Accepted but not consumed.

Returns:
- always **local suppression** (no wire send, returns `0xFFFFFFFF`).
  `TitlePreNotify @ 0x7E843941` dispatches opcode `0x0D` to the shared
  `TitlePreNotify_BuildUncachedKind2List @ 0x7E842162` helper, which
  rejects unless `*notifyKind == 2`. Result: the helper returns without
  writing `outPayload`, and the wire send is skipped.

### Opcode `0x0e` `PrimeTitleCache0E` (inert)

Purpose: nominally prime title cache entries, but functionally inert in
  stock builds.

Parameters:
- `notifyPayload: u32[]`. Accepted but not consumed.

Returns:
- always **local suppression** (no wire send, returns `0xFFFFFFFF`).
  Same dispatch path and rejection reason as opcode `0x0D` (the helper
  only accepts `notifyKind == 2`).

### Opcode `0x0f` `GetLayoutCookie`

Purpose: read the current attach-time layout cookie slot.

Parameters:
- none.

Returns:
- `layoutCookie: u32`. Reads `DAT_7E84E2EC` (`TitlePreNotify @
  0x7E843941` case 0xF). This is a **different** slot from the one
  `SetLayoutCookie` writes (`DAT_7E84E2E0`). The Get-slot is seeded by
  `hrAttachToService @ 0x7E844114` from `DAT_7E851808` (stock value:
  `0`) and then sent to the server as the 6-byte payload of opcode
  `10`; the server never updates it on stock paths, so
  `GetLayoutCookie` keeps returning the attach-time seed.

### `PictureControl` Query Result

When `PictureControl` uses `control=1`, the caller buffer is filled as:

- `bufferPtr:u32`. Transfer buffer pointer.
- `bytesReceived:u32`. Bytes received so far.
- `targetBytes:u32`. Total target size.
- `isValid:u32`. Object valid flag.
- `stateKind:u32`. Transfer state kind.
- `metric0:u32`. Auxiliary metric.
- `metric1:u32`. Auxiliary metric.

### `PictureStartPayload`

Layout (source: `PictureDownload_StartOrRefresh @ 0x7E8486B1`):

- `entryCount:u8`. Stock direct path emits `1`. Rewritten paths
  (opcodes `0x03/0x05/0x06` → `0x04`) may emit more.
- `modeByte:u8`. Derived from the local transfer-mode flag
  `DAT_7E84E620`: emitted as `(DAT_7E84E620 == 0)`. Stock observed
  values:
  - `1` — initial / offline mode (`DAT_7E84E620 == 0`). Same condition
    causes the wrapper to also reset the type-4 subscriber via
    `MVAsyncSubscriberSetState(DAT_7E84E318, 0)`.
  - `0` — online / normal mode (`DAT_7E84E620` nonzero).
  Client never re-reads the value after send.
  `client-opaque (verified at PictureDownload_StartOrRefresh @
  0x7E8486B1)` — the byte is a write-once snapshot of the local flag.
- repeated entry:
  `currentSize:u32`, `transferId:u32`, `stateFlags:u8`, `objectName:cstring`.
- `currentSize:u32` — source `this+0x38` (bytes already received locally).
- `transferId:u32` — source `this+0x24`.
- `stateFlags:u8` bits:
  - `0x01` `ObjectValid`. Set when `this+0x48 != 0`. `this+0x48` is the
    "object already validated" flag set by inbound notification type-3
    (`AddressConversionResult` etc.) when a previous start finished.
  - `0x02` `RequestInProgress`. Set when `this+0x4c != 0`. `this+0x4c`
    is the wrapper-managed "request in flight" flag — set by the
    caller before invoking `PictureDownload_StartOrRefresh`, cleared
    at function end. The server sees this when refreshes overlap
    pending requests.
- `objectName:cstring` — source `*(char **)(this+0x20)`, copied with
  the trailing NUL.

## Stream Family `NotificationType`

Wire class: `0x01` (shared MEDVIEW proxy), reached through
`SubscribeNotifications(0x17)` / `UnsubscribeNotifications(0x18)`.

### Type `0` `TopicCacheStream`

Purpose: deliver topic-body cache records for `FetchNearbyTopic` and
`FetchAdjacentTopic`.

Record kinds:
- `0xa5` `HfcStatusRecord`. Fields: `titleSlot:u8`, `status:u16`,
  `contentsToken:u32`.
- `0x37` `HfcTopicRecord`. Fields: `titleSlot:u8`, `payloadBytes:u16`,
  `topicBlob:dynbytes`.
- `0xbf` `HfcRichTopicRecord`. Fields: `titleSlot:u8`, `payloadBytes:u16`,
  `topicBlob:dynbytes`, plus rich companion metadata used by navigation and
  export paths.

### Type `1` `WordWheelLookupStream`

Purpose: deliver asynchronous string lookup results for `LookupWordWheelEntry`
and the request-completion sentinel for `QueryWordWheel` / `ResolveWordWheelPrefix`.

Consumer: `WordWheelCache_DispatchNotification @ 0x7E849251`.

Record layout:
- `recordBytes:u16`. Total record size including this header. Returning 0xffffffff to
  the dispatcher when `recordBytes > availableBytes` leaves the chunk unconsumed.
- `wordWheelId:u8`. Slot id; the client indexes `DAT_7e850258[wordWheelId]` to map it
  to the per-wordwheel state at `DAT_7e84e668` (stride `0x1c`).
- `rangeSpan:u8`. Pending/completion flag. Value `0xFF` is the "request-done" sentinel
  that forces the dispatcher's probe-match short-circuit and stores `0` at slot+9;
  any other value is stored verbatim at slot+9.
- `ordinalBase:u32`. Lookup key. Stored at slot+0 and matched against the caller's
  optional probe context (struct `{u8 wordWheelId; u8[3] pad; u32 ordinal}`).
- `reserved:u8`. Client-opaque (verified at `WordWheelCache_DispatchNotification` —
  no `CMP`/`TEST`/`SWITCH` is emitted against byte at `+0x8`).
- `entryCount:u16`. Clamped to `≥1` by the client before sizing the payload allocation.
- `entryIndexTable:u32[entryCount]`. Forwarded verbatim to `WordWheelCache_InsertEntry`.
- `payloadString:cstring`. Optional NUL-terminated lookup string. Consumed only when
  its offset (`0xB + entryCount*4`) lies inside `recordBytes` and the byte at that
  offset is nonzero.

Effect per record: prepend a `0x24`-byte cache record to the global word-wheel list
(`PTR_DAT_7e85035c`) via `WordWheelCache_InsertEntry`. Side-effects on the slot table:
`slot+0=ordinalBase`, `slot+9=rangeSpan` (or `0` for the `0xFF` sentinel form).
A probe-context match also OR's `0x80000000` into the consume count so the dispatcher
breaks out of the chunk loop after this record.

### Type `2` `HighlightLookupStream`

Purpose: deliver asynchronous highlight lookup results.

Record layout:
- `recordBytes:u16`.
- `highlightContext:u8`.
- `rangeSpan:u8`.
- `highlightId:u32`.
- `addressToken:u32`.
- `lookupResult:u32`.

### Type `3` `MixedAsyncStream`

Purpose: deliver address-conversion updates, title-info cache updates, and
transfer status records.

Common record header:
- `subtype:u16`.
- `recordBytes:u16`.

Known subtypes:
- `1` `TransferStatusById`. Fields:
  `targetBytes:u32`, `stateKind:u16`, `metric0:u32`, `metric1:u32`,
  `metricDivisorOrAux:u32`, `auxStatus:u32`, `objectId:u32`.
- `2` `TransferStatusByName`. Same fields as subtype `1`, then
  `objectKind:u8`, `objectName:cstring`.
- `4` `AddressConversionResult`. Populates one cache entry with
  `titleSlot:u8`, `vaResult:u32`, `secondaryToken:u32`, `inputKey:u32`.
- `5` `TitleInfoCacheUpdate`. Populates the MVTTL `info-kind 0x6e` string cache for
  a title. Consumer: `NotificationType3_ApplyInfo6eCacheRecord @ 0x7E8424F5`.
  Fixed 17-byte header `{u8 titleSlot, u24+u8 infoKind, u24+u8 resultLength,
  u24+u8 bufCtl, u24+u8 payloadBytes}` followed by `payloadBytes` payload bytes
  (or the inline 4-byte value at offset +13 when `payloadBytes==0`). Routes to
  `MVCacheInfo6eString @ 0x7E842267` only when `MVFindTitleStateByTitleByte(titleSlot)`
  resolves and `infoKind == 0x6e`; other infoKinds are accepted on the wire and
  discarded by the client.

### Type `4` `TransferChunkStream`

Purpose: deliver chunked picture/file transfer bytes for `StartTransferBatch`
(`TitlePreNotify` opcode `0x04`) initiated downloads.

Consumer: `NotificationType4_ApplyChunkedBuffer @ 0x7E8468D5`.

Common record header:
- `chunkOp:u16`. Valid values `1..5`; only opcode `3` mutates state, opcodes
  `1`/`2`/`4`/`5` are consumed silently. Opcode `0` or `>5` short-circuits the
  callback and returns `frameBytes` without inspecting the payload.
- `frameBytes:u16`. Total record size including this header. The dispatcher returns
  `0xffffffff` (no-consume) when `frameBytes > availableBytes`.

Known opcode:
- `3` `TransferChunk`. Fields: `transferId:u32`, `chunkOffset:u32`,
  `chunkData:bytes[frameBytes-0x0c]`. The callback resolves `transferId` against the
  active media-transfer list at `PTR_DAT_7e84e628+0x1c`, grows/allocates the transfer
  object's buffer at `+0x30` to `chunkOffset + len(chunkData)`, copies bytes into
  `buffer + chunkOffset`, advances the committed-byte cursor `+0x38`, and posts
  `WM_USER+0x0e` (0x40e) to each attached sink HWND (or `DAT_7e84e330` for the
  marker-buffer special case). Chunks with `chunkOffset > +0x38` are ignored
  (gap-tolerance is the caller's responsibility).

## Value Type `FixedRecord`

### `ChildPaneRecord`

Purpose: describe one extra `MosChildView` window MOSVIEW creates beneath
the outer `MosViewContainer`, beyond the two main panes the
`WindowScaffoldRecord` already provides.

Consumer: `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` (additional-
pane loop at `~0x7F3C6C00..0x7F3C6D9F`). Caches the array at
`MosViewState+0x3C` (HGLOBAL), count at `+0x38`, then iterates one
pane per record.

Fields (43 bytes / `0x2B`; offsets verified at
`CreateMosViewWindowHierarchy @ 0x7F3C6C2A..0x7F3C6D6E`):

- `+0x00..+0x0A` 11 bytes of preamble (no reader RE'd consumes them;
  `client-opaque (verified at CreateMosViewWindowHierarchy — no
  CMP/TEST/SWITCH at record+0x00..+0x0A)`).
- `+0x0B` `flags:u8`. Known bit: `0x08` switches coordinate interpretation
  (set = absolute pixels at `+0x15..+0x24`; clear = per-mille → scaled
  via `ScalePerMilleRectToWindow`).
- `+0x0C..+0x14` `title:cstring[9]`. Inline pane title. NUL-empty title
  yields a NULL `MosPaneState+0x68` (default fall-through label).
- `+0x15..+0x18` `x:i32`. Pane left.
- `+0x19..+0x1C` `y:i32`. Pane top.
- `+0x1D..+0x20` `width:i32`. Pane width.
- `+0x21..+0x24` `height:i32`. Pane height. Any of the four set to `-1`
  defaults the whole rect to the container's client area.
- `+0x25..+0x28` `backgroundColor:u32` (`COLORREF`). Applied via
  `ApplyMosViewBackgroundColor(MosPaneState+0x40, record+0x25)`.
- `+0x29..+0x2A` `realizeLevel:i16`. Signed threshold; mirrored verbatim
  into the runtime `MosPaneState+0xA0` at pane construction. Consumed
  by `MosViewContainerWindowProc @ 0x7F3C474B` on local message `0x42D`:
  panes with `realizeLevel <= 0` are realized immediately (handler
  posts `SendMessageA(container+0x18, 0x42A, MosPaneState,
  MosPaneState+0x44)` and latches `MosPaneState+0x84 = 1`); panes with
  `realizeLevel > 0` are skipped and re-evaluated on the next `0x42D`
  fire (the realization counter is implicit — `wParam`/`lParam` are
  not consumed; the loop always compares against `0`). Stock authors
  typically encode `0` to "realize immediately" and a positive value
  to "defer realization to a later navigation step".

### `PopupPaneRecord`

Purpose: describe one popup `MosChildView` window MOSVIEW creates for
the title's popup verbs.

Consumer: `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` (popup
loop at `~0x7F3C6E20..0x7F3C7077`). Caches the array at
`MosViewState+0x44` (HGLOBAL), count at `+0x40`, then iterates one
popup per record plus one synthetic trailing record using the
`"[The Default Popup]"` literal for unauthored popup targets.

Fields (31 bytes / `0x1F`; offsets verified at
`CreateMosViewWindowHierarchy @ 0x7F3C6E51..0x7F3C7028`):

- `+0x00` 1 byte preamble (no reader RE'd consumes it;
  `client-opaque (verified at CreateMosViewWindowHierarchy — no
  CMP/TEST/SWITCH at record+0x00)`).
- `+0x01` `flags:u8`. Known bit: `0x08` switches coordinate interpretation
  (set = absolute pixels at `+0x0B..+0x1A`, applies through
  `OffsetPointByWindowOrigin`; clear = per-mille via
  `ScalePerMilleRectToWindow`).
- `+0x02..+0x0A` `title:cstring[9]`. Inline popup title. NUL-empty
  title yields a NULL `MosPaneState+0x68`.
- `+0x0B..+0x0E` `x:i32`. Popup left.
- `+0x0F..+0x12` `y:i32`. Popup top.
- `+0x13..+0x16` `width:i32`. Popup width.
- `+0x17..+0x1A` `height:i32`. Popup height. Any of the four set to
  `-1` defaults the whole rect to the container's client area.
- `+0x1B..+0x1E` `backgroundColor:u32` (`COLORREF`). Applied via
  `ApplyMosViewBackgroundColor(MosPaneState+0x40, record+0x1B)`. The
  synthetic trailing popup record forces `0xFFFFFFFF` (transparent).

### `WindowScaffoldRecord`

Purpose: describe the outer container, the scrolling pane, and the
non-scrolling pane that MOSVIEW creates for the title's main view.

Consumer: `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790`. The function
caches the array via `OpenMediaTitleSession @ 0x7F3C61CE` at
`MosViewState+0x4C` (HGLOBAL), count at `+0x48`, then expands the first
record (index 0) into the outer container HWND and the two `MosChildView`
panes. Subsequent records are not consumed by the stock viewer.

Fields (152 bytes / `0x98`; offsets verified at
`CreateMosViewWindowHierarchy @ 0x7F3C679A..0x7F3C6CB0`):

- `+0x00..+0x14` 21 bytes of preamble (no reader RE'd consumes them;
  `client-opaque (verified at CreateMosViewWindowHierarchy — no
  CMP/TEST/SWITCH at record+0x00..+0x14)`).
- `+0x15..` `containerCaption:cstring`. Outer container window caption.
  Read as `(char *)(record + 0x15)` and copied through `MosViewAlloc`
  for the outer `MosViewContainer` `CreateWindowExA` title.
- `+0x48` `flags:u8`. Known bits:
  - `0x01`: outer-container rect mode (set = absolute pixels at
    `+0x49`..`+0x58`; clear = per-mille → scaled via
    `ScalePerMilleRectToWindow`).
  - `0x08`: inner-pane rect mode (set = absolute pixels at
    `+0x80`..`+0x8F`; clear = per-mille).
  - `0x40`: when set, the non-scrolling pane's "no-scroll" flag at
    `MosPaneState+0x9C` is forced to `1`.
- `+0x49..+0x58` `outerRect`. `left:i32` `+0x49`, `top:i32` `+0x4D`,
  `width:i32` `+0x51`, `height:i32` `+0x55`. Used by `MoveWindow` on
  the existing MosView frame. `(-1,-1,-1,-1)` skips the resize.
- `+0x5B..+0x5E` `containerControl:i32`. Stored at `MosViewContainer+0x20`
  via `*(int *)(this + 0x20) = *(int *)(record + 0x5B)` when the value
  is not `-1`.
- `+0x78..+0x7B` `scrollingPaneBackground:COLORREF`. Applied to the
  scrolling (second-created) `MosChildView` via
  `ApplyMosViewBackgroundColor(MosPaneState+0x40, record+0x78)`.
- `+0x7C..+0x7F` `nonScrollingPaneBackground:COLORREF`. Applied to the
  non-scrolling (first-created) `MosChildView` via
  `ApplyMosViewBackgroundColor(MosPaneState+0x40, record+0x7C)`.
- `+0x80..+0x8F` `innerPaneRect`. `left:i32` `+0x80`, `top:i32`
  `+0x84`, `width:i32` `+0x88`, `height:i32` `+0x8C`. Defines the
  rectangle of the two main `MosChildView` panes inside the
  `MosViewContainer` client area. `(-1,-1,-1,-1)` defaults to the
  full container client rect.
- `+0x90..+0x97` 8 bytes — no reader RE'd consumes them
  (`client-opaque (verified at CreateMosViewWindowHierarchy —
  no CMP/TEST/SWITCH at record+0x90..+0x97)`).

The historical field names `topBandBackground` / `scrollingHostBackground`
/ `topBandRect` in earlier doc revisions were guesses; the consumer-side
RE shows the two COLORREFs are simply the two MosChildView backgrounds
(non-scrolling at `+0x7C`, scrolling at `+0x78`), and there is no
separate "top band" rect in the record.

## Runtime Handle Shapes

### `RemoteHfsHandle`

Purpose: local wrapper returned by the client around one remote HFS handle.

Fields:
- `fileSize:u32`.
- `currentOffset:u32`.
- `remoteHandleId:u8`.

### `MVTopicListHandle`

Purpose: local movable wrapper around query/topic-list results.

Fields:
- `magic:u32 = 0x544c2100`.
- `logicalCount:u32`.
- `topicUpperBoundOrLoadedCount:u32`.
- `realizedGroupHandle:u32`.
- `parserQueryHandle:u32`.
- `deferredSourceString:u32`.
- `deferredSourceTitle:u32`.
- `scratchStatus:u16`.
