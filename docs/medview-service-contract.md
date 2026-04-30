# MEDVIEW Service Contract

Docstring-style client-visible API reference recovered from stock
`MOSVIEW.EXE`, `MVCL14N.DLL`, and `MVTTL14C.DLL`.

## Framing

- `Request ID`: the per-call discriminator in the MEDVIEW host block. The
  selector numbers from the longer RE note are these request IDs.
- `Wire class byte`: the host-block class discriminator. Only the bootstrap
  discovery frame is fully pinned as a literal class value:
  `class=0x00`, `selector=0x00`, `requestId=0`.
- The sections below are logical API classes. On recovered stock paths they all
  ride one discovered MEDVIEW service proxy class, but that final per-service
  class byte is not yet named independently in the client.
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

Wire class: shared discovered MEDVIEW proxy class. The stock client does not
expose separate class bytes for the logical groups below.

### `0x1f` `AttachSession`

Purpose: start the MEDVIEW protocol session and validate client capabilities.

Parameters:
- `clientVersion: u8`. Valid value in stock client: `1`.
- `capabilities: bytes[12]`. Layout: `clientFlags0:u32`, `clientFlags1:u32`,
  `browseLcid:u32`.

Returns:
- `validationToken: u32`. `0` is rejected by the stock client. Any nonzero
  value is treated as success.

### `0x17` `SubscribeNotifications`

Purpose: open a long-lived streamed notification channel.

Parameters:
- `notificationType: u8`. Valid values on stock paths: `0`, `1`, `2`, `3`,
  `4`.

Returns:
- `notificationStream`. A pending streamed reply handle that yields notification
  records until unsubscribed or detached.

### `0x18` `UnsubscribeNotifications`

Purpose: stop one notification stream.

Parameters:
- `notificationType: u8`. Valid values on stock paths: `0`, `1`, `2`, `3`,
  `4`.

Returns:
- `ack`. No meaningful payload.

## Class `TitleService`

Wire class: shared discovered MEDVIEW proxy class.

### `0x00` `ValidateTitle`

Purpose: check whether a title slot is still valid.

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
- `cacheHint0: u32`. Forwarded by the client; no higher-level meaning is
  recovered on stock paths.
- `cacheHint1: u32`. Forwarded by the client; no higher-level meaning is
  recovered on stock paths.

Returns:
- `titleSlot: u8`. The live title slot used by later requests.
- `fileSystemMode: u8`. Copied into title metadata and later surfaced by local
  `TitleGetInfo(0x69)`.
- `contentsVa: u32`. Virtual-address contents base used by `vaGetContents`.
- `contentsAddr: u32`. Address-space contents base used by `addrGetContents`.
- `topicUpperBound: u32`. Topic count upper bound later surfaced by local
  `TitleGetInfo(0x0b)`.
- `cacheHeader0: u32`.
- `cacheHeader1: u32`.
- `payloadBlob: dynbytes`. Flat MediaView payload backing local title-info
  selectors.

### `0x02` `CloseTitle`

Purpose: release a previously opened title slot.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.

Returns:
- `ack`. No meaningful payload.

### `0x03` `GetTitleInfoRemote`

Purpose: remote fallback for title-info kinds not served from the local cached
  title payload.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `infoKind: u32`. Valid values: remote title-info kinds listed below.
- `infoArg: u32`. Selector-specific argument. For some kinds this packs an
  index and buffer size or a caller byte cap.
- `callerCookie: u32`. Echoed from the caller path; no higher-level stock
  meaning is required for compatibility.

Returns:
- `lengthOrScalar: u32`. Either returned byte count or a scalar result.
- `payload: dynbytes`. Present only for kinds that return dynamic bytes.

### `0x04` `QueryTopics`

Purpose: execute a title query and open a highlight-aware topic-list session.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`.
- `queryClass: u16`. Query-class word. Forwarded to the service; stock wrapper
  meaning depends on the higher-level query caller.
- `primaryText: cstring`. Main query string.
- `queryFlags: u8`. Valid bits:
  `0x01=HasSecondaryText`, `0x02=HasSourceGroup`, `0x04=HasAuxRequest40`.
- `queryMode: u16`. Query-mode word forwarded by the wrapper.
- `secondaryText: cstring`. Required when `queryFlags & 0x01` is set.
- `sourceGroupBlob: dynbytes`. Required when `queryFlags & 0x02` is set.
- `auxRequest40: bytes[0x40]`. Required when `queryFlags & 0x04` is set.

Returns:
- `highlightContext: u8`. Nonzero result opens a highlight-aware query session.
- `logicalCount: u32`. Logical topic-list length.
- `secondaryResult: u32`. Preserved by the low-level wrapper, but not required
  by the main stock consumer path.
- `auxReply: dynbytes`. Optional auxiliary dynamic reply for the `0x04` flag
  path.
- `sideband12: bytes[12]`. Optional second dynamic reply when exactly 12 bytes
  are returned.

### `0x1e` `PreNotifyTitle`

Purpose: send title-side pre-notification control operations. Some opcodes are
rewritten or absorbed locally before any wire send occurs.

Parameters:
- `titleSlot: u8`. Valid values: title slots previously returned by
  `OpenTitle`. The local wrapper also normalizes title handle `-1` to slot `0`.
- `notifyOp: u16`. Valid values: documented `PreNotifyTitle` opcodes below.
- `notifyPayload: dynbytes`. Opcode-specific payload.

Returns:
- `ack`. For wire-reaching opcodes.
- local result. For local-only opcodes such as `PictureControl` and
  `GetLayoutCookie`.

## Class `WordWheelService`

Wire class: shared discovered MEDVIEW proxy class.

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
  `OpenWordWheel`.
- `queryMode: u16`. Query mode or flag word.
- `queryText: cstring`. Query string.

Returns:
- `status: u16`. Status word used by the wrapper.

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
  `OpenWordWheel`.
- `ordinal: u32`. Entry ordinal to resolve.
- `outputLimit: u32`. Maximum bytes copied into the caller buffer when the
  asynchronous notification result arrives.

Returns:
- `ack`. The actual string arrives later through notification type `1`.

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

Wire class: shared discovered MEDVIEW proxy class.

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
  8-byte opaque header, `highlightCount:u32`, then repeated entries of
  `anchorToken:u32`, `aux0:u32`, `aux1:u32`, `spanOrCount:u8`.

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

Wire class: shared discovered MEDVIEW proxy class.

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
- `currentToken: u32`. Current topic/address token.
- `direction: u8`. Stock client uses two values for next/previous traversal.

Returns:
- `ack`. Actual topic body arrives via notification type `0`.

## Class `RemoteFileService`

Wire class: shared discovered MEDVIEW proxy class.

### `0x1a` `OpenRemoteHfsFile`

Purpose: open one title-side baggage/HFS file through MEDVIEW.

Parameters:
- `hfsMode: u8`. HFS mode byte forwarded by the wrapper.
- `fileName: cstring`. Title-side file name.
- `openMode: u8`. Open mode byte forwarded by the wrapper.

Returns:
- `remoteHandleId: u8`. Zero is treated as failure by the stock wrapper.
- `fileSize: u32`. File length in bytes.

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

Purpose: prime or filter word-wheel-related cache entries.

Parameters:
- `notifyPayload: u32[>=2]`.
- element `0`. Context slot id preserved unchanged.
- remaining elements. Candidate dwords filtered against the local word-wheel
  cache before any wire send.

Returns:
- `ack` if a reduced payload is sent.
- local suppression if every requested entry is already cached.

### Opcode `0x02` `PrimeTitleCache02`

Purpose: prime title-scoped cache entries through a filtered dword list.

Parameters:
- `notifyPayload: u32[]`. Entries already satisfied locally are removed before
  any send.

Returns:
- `ack` if any entries remain after filtering.
- local suppression otherwise.

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

### Opcode `0x09` `SetLayoutCookie`

Purpose: store one local layout cookie.

Parameters:
- `notifyPayload: u32`.

Returns:
- local only. No MEDVIEW request is sent.

### Opcode `0x0b` `SetPreNotifyReady`

Purpose: set a local readiness flag.

Parameters:
- ignored.

Returns:
- local only. No MEDVIEW request is sent.

### Opcode `0x0c` `PictureControl`

Purpose: dispatch local picture-transfer control operations.

Parameters:
- `notifyPayload: PictureControlRequest`.
- `control=0`. Start or refresh a picture transfer.
- `control=1`. Query current picture status into the same caller buffer.
- `control=2`. Detach a previously attached picture sink.

Returns:
- local status or local query data. No MEDVIEW request is sent.

### Opcode `0x0d` `PrimeTitleCache0D`

Purpose: prime title cache entries through a filtered dword list.

Parameters:
- `notifyPayload: u32[]`.

Returns:
- `ack` if any entries remain after filtering.
- local suppression otherwise.

### Opcode `0x0e` `PrimeTitleCache0E`

Purpose: prime title cache entries through a filtered dword list.

Parameters:
- `notifyPayload: u32[]`.

Returns:
- `ack` if any entries remain after filtering.
- local suppression otherwise.

### Opcode `0x0f` `GetLayoutCookie`

Purpose: read the current local layout cookie.

Parameters:
- none.

Returns:
- `layoutCookie: u32`. Local-only value.

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

Layout:

- `entryCount:u8`. Stock direct path emits `1`; rewritten paths may emit more.
- `modeByte:u8`. Opaque request-state byte forwarded by the client.
- repeated entry:
  `currentSize:u32`, `transferId:u32`, `stateFlags:u8`, `objectName:cstring`.
- `stateFlags` bit `0x01`. Advertises object-valid state.
- `stateFlags` bit `0x02`. Advertises request-mode state.

## Stream Family `NotificationType`

Wire class: shared discovered MEDVIEW proxy class, reached through
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

Purpose: deliver asynchronous string lookup results for `LookupWordWheelEntry`.

Record layout:
- `recordBytes:u16`.
- `wordWheelId:u8`.
- `rangeSpan:u8`.
- `ordinalBase:u32`.
- `entryCount:u16`.
- `entryIndexTable:u32[]`.
- `payloadString:cstring`. Optional trailing lookup string.

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
- `5` `TitleInfoCacheUpdate`. Populates one cached string keyed by
  `(titleSlot, infoArg:u32)`.

### Type `4` `TransferChunkStream`

Purpose: deliver chunked picture/file transfer bytes.

Common record header:
- `chunkOp:u16`.
- `frameBytes:u16`.

Known opcode:
- `3` `TransferChunk`. Fields:
  `transferId:u32`, `chunkOffset:u32`, `chunkData:bytes[frameBytes-0x0c]`.

## Value Type `FixedRecord`

### `ChildPaneRecord`

Purpose: describe one extra child pane created by MOSVIEW.

Fields:
- `flags:u8`. Known bit: `0x08` switches coordinate interpretation.
- `title:cstring[9]`. Inline pane title.
- `x:u32`, `y:u32`, `width:u32`, `height:u32`. Pane rectangle.
- `backgroundColor:u32`. `COLORREF`.
- `realizeLevel:u16`. Staged child-pane realization threshold used by local
  message `0x42d`.

### `PopupPaneRecord`

Purpose: describe one popup pane created by MOSVIEW.

Fields:
- `flags:u8`. Known bit: `0x08` switches coordinate interpretation.
- `title:cstring[9]`. Inline popup title.
- `x:u32`, `y:u32`, `width:u32`, `height:u32`. Popup rectangle.
- `backgroundColor:u32`. `COLORREF`.

### `WindowScaffoldRecord`

Purpose: describe the outer container and optional non-scrolling pane.

Fields:
- `containerCaption:cstring`. Outer container caption.
- `flags:u8`. Known bits:
  `0x08` outer-container rect mode,
  `0x01` non-scrolling rect mode,
  `0x40` bottom-align non-scrolling pane.
- `outerRect`. `x:u32`, `y:u32`, `width:u32`, `height:u32`.
- `containerControl:u32`. Carried into runtime state; not interpreted on the
  recovered stock path.
- `nonScrollingBackground:u32`. `COLORREF`.
- `scrollingBackground:u32`. `COLORREF`.
- `nonScrollingRect`. `x:u32`, `y:u32`, `width:u32`, `height:u32`.

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
