# MEDVIEW service

Wire and format reference for the **MEDVIEW** MPC service — the RPC channel
`MOSVIEW.EXE` opens to fetch MedView titles. This document is the wire-format
contract: it captures the bytes `MVTTL14C.DLL` expects so the title session
unblocks and hands control to `MVCL14N.DLL`.

Host-side behaviour (process launch, title spec, command dispatch) lives in
`docs/MOSVIEW.md`. This document is strictly the wire contract.

Sources: static decompilation against `MSN95.gpr`
(`MVTTL14C.DLL` rebased at `0x7E840000`, `MOSVIEW.EXE` at `0x7F3C0000`,
`MVCL14N.DLL` at `0x7E880000`), PE export tables, `PROTOCOL.md` §5–§6 for
the generic MPC framing.

Companions:

- `PROTOCOL.md` §7 (services) — updates §7.6 to point here.
- `docs/MOSVIEW.md` — MSN-side host process behaviour.
- `docs/BINARIES.md` §5 — MedView DLL catalogue.

---

## 0. Selector matrix

42-row IID-bound selector table plus the IID-less `0x00` ValidateTitle.

Status legend:
- `full` — byte layout + per-field purpose + value space + per-value
  effect all pinned in this doc, with Ghidra cite. `client-opaque
  (verified at <addr>)` sub-fields are allowed when the client demonstrably
  never inspects a byte.
- `dead` — confirmed zero client call sites in MVTTL14C (cite xref count).

| Sel    | IID idx | Name                          | MVTTL14C entry / immediate site                                  | Status   | §             | Notes |
|--------|--------:|-------------------------------|------------------------------------------------------------------|----------|---------------|-------|
| `0x00` | — (IID-less) | `ValidateTitle`           | `TitleValid @ 0x7E8423AD` passes immediate `0` to vtable+0xC      | full     | §2.1.1        | One-byte titleSlot in / one-byte isValid out |
| `0x01` |       0 | `TitleOpen` / `OpenTitle`     | `TitleOpenEx @ 0x7E842D4E`                                       | full     | §4            | Cache-tuple + dynamic body; reply DWORDs gate render |
| `0x02` |       1 | `CloseTitle`                  | `TitleClose @ 0x7E842C3A`                                        | full     | §6d.2         | titleSlot byte; sent only on last refcount |
| `0x03` |       2 | `TitleGetInfo` / `GetTitleInfoRemote` | `TitleGetInfo @ 0x7E842558` (local + remote dispatch)    | full     | §5            | 9-section body + remote info_kinds |
| `0x04` |       3 | `QueryTopics`                 | `TitleQuery @ 0x7E841653`                                        | full     | §6d.3         | Variable-shape request driven by queryFlags |
| `0x05` |       4 | `ConvertAddressToVa`          | `vaConvertAddr @ 0x7E841D64`                                     | full     | §6d.4         | Reply via NotificationType3 subtype 4 (kind=2) |
| `0x06` |       5 | `vaConvertHash` / `ConvertHashToVa` | `vaConvertHash @ 0x7E841E9A`                               | full     | §6b           | Reply via NotificationType3 subtype 4 |
| `0x07` |       6 | `vaConvertTopicNumber` / `ConvertTopicToVa` | `vaConvertTopicNumber @ 0x7E841FCF`                | full     | §6b           | Reply via NotificationType3 subtype 4 |
| `0x08` |       7 | `QueryWordWheel`              | `WordWheelQuery @ 0x7E849E99`                                    | full     | §6d.5.1       | u16 status |
| `0x09` |       8 | `OpenWordWheel`               | `WordWheelOpenTitle @ 0x7E849328`                                | full     | §6d.5.2       | wordWheelId + itemCount |
| `0x0A` |       9 | `CloseWordWheel`              | `WordWheelClose @ 0x7E8495B1`                                    | full     | §6d.5.3       | ack |
| `0x0B` |      10 | `ResolveWordWheelPrefix`      | `WordWheelPrefix @ 0x7E849935`                                   | full     | §6d.5.4       | u32 prefix result |
| `0x0C` |      11 | `LookupWordWheelEntry`        | `WordWheelLookup @ 0x7E849658`                                   | full     | §6d.5.5       | Result via NotificationType1 |
| `0x0D` |      12 | `CountKeyMatches`             | `KeyIndexGetCount @ 0x7E849A27`                                  | full     | §6d.5.6       | u16 count |
| `0x0E` |      13 | `ReadKeyAddresses`            | `KeyIndexGetAddrs @ 0x7E849B6E`                                  | full     | §6d.5.7       | Packed u32 array (byte count) |
| `0x0F` |      14 | `SetKeyCountHint`             | `fKeyIndexSetCount @ 0x7E849D8A`                                 | full     | §6d.5.8       | u8 success |
| `0x10` |      15 | `LoadTopicHighlights` / `HighlightsInTopic` | `HighlightsInTopic @ 0x7E841526`                   | full     | §6b           | Highlight blob with 8-byte header + repeated 13-byte entries |
| `0x11` |      16 | `FindHighlightAddress`        | `addrSearchHighlight @ 0x7E8413FE`                               | full     | §6d.6.1       | u32 addressToken |
| `0x12` |      17 | `ReleaseHighlightContext`     | `HighlightDestroy @ 0x7E841180`                                  | full     | §6d.6.2       | ack |
| `0x13` |      18 | `RefreshHighlightAddress`     | `HighlightLookup @ 0x7E841235`                                   | full     | §6d.6.3       | Result via NotificationType2 |
| `0x14` |      19 | (none — dead)                 | no caller                                                        | dead     | §6e           | Zero `CALL [EAX+0xc]` immediate-14 sites |
| `0x15` |      20 | `vaResolve` / `FetchNearbyTopic` | `HfcNear @ 0x7E84589F` (immediate `0x15` at `0x7E845973`)     | full     | §6b.1         | Topic body via NotificationType0 |
| `0x16` |      21 | `FetchAdjacentTopic`          | `HfcNextPrevHfc @ 0x7E845ABB`                                    | full     | §6d.7         | Topic body via NotificationType0 |
| `0x17` |      22 | `SubscribeNotifications`      | `MVAsyncSubscriberSubscribe @ 0x7E844EE6` (called 5× by `hrAttachToService`) | full | §6a   | Reply must be `0x87 0x88` (stream-end iterator); see B1 |
| `0x18` |      23 | `UnsubscribeNotifications`    | `MVAsyncSubscriberUnsubscribe @ 0x7E844FE3`                       | full     | §6d.1         | ack |
| `0x19` |      24 | (none — dead)                 | no caller                                                        | dead     | §6e           | Zero `CALL [EAX+0xc]` immediate-19 sites |
| `0x1A` |      25 | `HfOpenHfs` / `BaggageOpen`   | `HfOpenHfs @ 0x7E847656`, `BaggageOpen @ 0x7E848205`             | full     | §6c           | hfs_vol + ASCIIZ name + mode → handle byte + size |
| `0x1B` |      26 | `LcbReadHf` / `BaggageRead`   | `LcbReadHf @ 0x7E847C45`, `LcbReadHfProgressive @ 0x7E847DF6`, `BaggageRead @ 0x7E84818E` | full | §6c | handle + count + pos → status byte + bytes |
| `0x1C` |      27 | `RcCloseHf` / `BaggageClose`  | `RcCloseHf @ 0x7E847BAD`, `HfsCloseRemoteHandle @ 0x7E847BD8`, `BaggageClose @ 0x7E848023` | full | §6c | handle → ack |
| `0x1D` |      28 | `GetRemoteFsError`            | `RcGetFSError @ 0x7E847F2B`                                      | full     | §6d.8         | u16 fsError |
| `0x1E` |      29 | `TitlePreNotify`              | `TitlePreNotify @ 0x7E843941`                                    | full     | §6            | Local + wire opcode dispatch |
| `0x1F` |      30 | `Handshake` / `AttachSession` | `hrAttachToService @ 0x7E844114` (immediate `0x1F` in attach path) | full   | §3            | clientVersion + 12B caps → validation u32 |
| `0x20` |      31 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x21` |      32 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x22` |      33 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x23` |      34 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x24` |      35 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x25` |      36 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x26` |      37 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x27` |      38 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x28` |      39 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x29` |      40 | (none — dead)                 | no caller                                                        | dead     | §6e           | |
| `0x2A` |      41 | (none — dead)                 | no caller                                                        | dead     | §6e           | |

Tally: `full` = 30 (29 IID-bound + 1 IID-less `0x00`), `dead` = 13 = `0x14, 0x19, 0x20`–`0x2A`. Total 42 IID-bound + 1 IID-less = 43 wire selectors.

Notification streams (out-of-band; carried by selector `0x17` subscription
slots) catalogued in `docs/medview-service-contract.md` `NotificationType`
family: type 0 (TopicCacheStream, records 0x37 / 0xA5 / 0xBF), type 1
(WordWheelLookupStream), type 2 (HighlightLookupStream), type 3
(MixedAsyncStream — subtypes 1, 2, 4, 5), type 4 (TransferChunkStream).

---

## 1. Service identity

| Field | Value | Source |
|-------|-------|--------|
| Service name | `MEDVIEW` | `DAT_7e84e340` (default svc name), `DAT_7e84e3d0` (`TitleConnection` fallback), `OpenMediaTitleSession` `wsprintfA` format reference. |
| Version | `0x1400800A` | `hrAttachToService` → factory slot `0x24`, last but one argument. |
| Client pipe host | `MOSVIEW.EXE` (App #6) | MOS Applications registry entry, `HRMOSExec` c==6. |
| Attach fn | `MVTTL14C!hrAttachToService @ 0x7E844114` | — |
| Service proxy ptr | `DAT_7e84e2f8` (in MVTTL14C) | saved after factory slot `0x24`. |

`MVTTL14C!TitleConnection @ 0x7E8446F3` is the public wrapper (exported
ordinal `10`) — it falls back to `"MEDVIEW"` when the caller passes NULL /
empty. `MVCL14N!MVTitleConnection` (ordinal 36) calls it via
`hrAttachToService`.

### 1.1 Per-service wire class byte (wire byte 0)

Every host block MEDVIEW emits carries two routing bytes in front of
the request-id VLI: a **class byte** (byte 0) and a **per-call
selector** (byte 1). The class byte is the same for every MEDVIEW
request; the per-call selector is what selects e.g. handshake vs.
TitleOpen vs. ConvertHashToVa.

For MEDVIEW the class byte is **`0x01`** — the server-assigned selector
for IID `00028B71` (TitleOpen), which is the first IID in the client's
IID table (§2.1) and thus the IID the proxy wrapper is bound to. Under
the index+1 selector-assignment rule the client expects (§2.1), the
first IID resolves to selector `0x01`, and that byte propagates as the
class byte for every subsequent MEDVIEW request.

Mechanism (entry: `MVTTL14C!hrAttachToService @ 0x7E844114`):

1. `hrAttachToService` calls `(*marshal)->vtable[0x24](marshal,
   serviceName, &DAT_7E84C1B0, &DAT_7E84E2F8, 0x1400800A, 0)`.
   Slot `0x24` of the marshal vtable is implemented by
   `MPCCL!OpenOrCreateNamedService @ 0x04601F75`. `&DAT_7E84C1B0` is
   the client IID table (42 × 16-byte IIDs); the call treats its first
   16 bytes as the requested IID.
2. `OpenOrCreateNamedService` constructs the opened-service container
   via `MPCCL!ConstructOpenedService @ 0x0460253D`, initialises the MOS
   pipe / session via `MPCCL!InitializeLoginServiceSession @ 0x0460263F`
   (sends discovery selector `0x00` and waits for the per-service IID→
   selector reply), then invokes vtable slot 0 of the opened service
   (`MPCCL!QueryOpenedServiceInterface @ 0x04602EBB`) with the IID
   table pointer treated as the requested IID.
3. `QueryOpenedServiceInterface` short-circuits when the requested IID
   is `IID_IUnknown` (`{00000000-…-46}` at `DAT_0460CE80`); otherwise
   calls `MPCCL!ResolveServiceSelectorForInterface @ 0x046073DB`. This
   waits up to 20 s for the discovery map and looks the IID up through
   the binary-tree at `state[+0x10][+0x4C]` (`MPCCL!ServiceInterfaceMap_FindByIid
   @ 0x046086B6`). Tree-node layout:
   `+0x00 u32 iid_ptr`, `+0x04 u8 selector`, `+0x0C comparator`,
   `+0x14 left`, `+0x18 right`. The lookup returns
   `*(byte *)(node+4)` — the **server-assigned selector byte** for the
   queried IID.
4. With the resolved selector byte in `local_5`,
   `QueryOpenedServiceInterface` allocates a `0x54`-byte wrapper via
   `MPCCL!ConstructServiceSelectorWrapper @ 0x0460320E`. The constructor
   stores the byte at `wrapper+0x10`. Wrapper vtable is at
   `PTR_WrapperQueryInterface_0460CD48`.
5. Each call to wrapper-slot `0x0c`
   (`MPCCL!CreateServiceRequestBuilderInterface @ 0x04603331`) builds a
   `0x11C`-byte request via `MPCCL!ConstructServiceRequestBuilder @
   0x046036C8`. The constructor copies `wrapper+0x10 → builder+0x14`
   (class byte) and writes the caller's per-call selector at
   `builder+0x15` (the immediate `0x1F` for handshake, `0x01` for
   TitleOpen, etc.).
6. On send, `MPCCL!AppendRequestIdHeaderToWireBuilder @ 0x046064E4`
   memcpys `builder+0x14` into the wire `ByteBuffer`. Source pointer
   is `builder+0x14`, length = `*(byte *)(builder+0x1A) + 2` — so the
   first two bytes copied are exactly `class_byte`, `per_call_selector`,
   followed by `N` VLI request-id bytes.

Discovery is the sole exception: its wire bytes are `class=0x00,
selector=0x00, request_id=0` — sent before any wrapper exists, from
inside `InitializeLoginServiceSession`'s pipe-open sequence.

The IID table only ever produces ONE bound wrapper (for IID idx 0 =
TitleOpen). The other 41 IIDs do not get their own wrappers; their
selectors are resolved to per-call bytes that the client hard-codes as
immediates (`TitleOpenEx` passes `0x01`, `TitleClose` passes `0x02`,
…). The class byte is fixed at attach time and never re-evaluated.

---

## 2. Discovery

### 2.1 IID array (client side)

`MVTTL14C` holds the client-side IID table at `DAT_7E84C1B0` — **42** IIDs,
16 bytes each (in-memory GUID layout with the first three fields LE). All
follow the MSN/Marvel `{00028Bxx-0000-0000-C000-000000000046}` template.

Positions (selector = index + 1 once the server assigns contiguous selectors):

| Idx | XX | Selector | Known use |
|----:|---:|---------:|-----------|
| 0 | `71` | `0x01` | **TitleOpen** (selector passed to slot `0x0C` in `TitleOpenEx`) |
| 1 | `72` | `0x02` | |
| 2 | `73` | `0x03` | **TitleGetInfo** |
| 3 | `74` | `0x04` | (observed: queried by title-close/cache path) |
| 4 | `78` | `0x05` | |
| 5 | `79` | `0x06` | |
| 6 | `81` | `0x07` | |
| 7 | `82` | `0x08` | |
| 8 | `83` | `0x09` | |
| 9 | `84` | `0x0A` | |
| 10 | `85` | `0x0B` | |
| 11 | `86` | `0x0C` | |
| 12 | `8A` | `0x0D` | |
| 13 | `8B` | `0x0E` | |
| 14 | `8C` | `0x0F` | |
| 15 | `8D` | `0x10` | |
| 16 | `8E` | `0x11` | |
| 17 | `8F` | `0x12` | |
| 18 | `90` | `0x13` | |
| 19 | `91` | `0x14` | |
| 20 | `A0` | `0x15` | **vaResolve** (HfcNear cache-miss fallback) |
| 21 | `A1` | `0x16` | |
| 22 | `B0` | `0x17` | **SubscribeNotification** (async event subscribe) |
| 23 | `B1` | `0x18` | |
| 24 | `B2` | `0x19` | |
| 25 | `B3` | `0x1A` | |
| 26 | `B4` | `0x1B` | |
| 27 | `B5` | `0x1C` | |
| 28 | `B6` | `0x1D` | |
| 29 | `B7` | `0x1E` | **TitlePreNotify** |
| 30 | `B8` | `0x1F` | **Handshake** (version/capabilities/LCID) |
| 31 | `C0` | `0x20` | |
| 32 | `C1` | `0x21` | |
| 33 | `C2` | `0x22` | |
| 34 | `C3` | `0x23` | |
| 35 | `C4` | `0x24` | |
| 36 | `C5` | `0x25` | |
| 37 | `C6` | `0x26` | |
| 38 | `C7` | `0x27` | |
| 39 | `C8` | `0x28` | |
| 40 | `C9` | `0x29` | |
| 41 | `CA` | `0x2A` | |

The selector assignment rule (1-based, in-order) is the same one used by
LOGSRV / DIRSRV / OnlStmt — the client stores a selector per IID in the
array order, so selector `0x1F` resolves to IID `00028BB8` and so on. The
client hard-codes selectors as immediates in the MVTTL14C call sites; the
server side is free to advertise any mapping that puts the right selectors
in front of the client's IID lookup.

### 2.1.1 IID-less selector 0x00 — `ValidateTitle`

Wire selector `0x00` in the **proxy class** (distinct from the
discovery class — see §2.2) is `ValidateTitle`. `MVTTL14C!TitleValid
@ 0x7E8423AD` calls `(**(*DAT_7e84e2f8 + 0xc))(DAT_7e84e2f8, 0,
&requestObj)` with the immediate `0` as the selector byte — same
vtable slot used by `TitleOpenEx` (immediate `1` for selector
`0x01`). The proxy treats `0x00` as a regular synchronous request:
one-byte argument `titleSlot`, one-byte reply `isValid`. No IID is
required because the operation is a probe of an already-open title
slot. The IID array enumerates only the 42 IID-bound operations
(selectors `0x01`–`0x2A`); ValidateTitle sits outside that array.

### 2.2 Discovery block

Standard PROTOCOL.md §5.3 — first message on the pipe carries
`selector=0x00, opcode=0x00` and a payload of 42 consecutive 17-byte
records `(16-byte IID LE | 1-byte selector)`. The client reads the
block through MPC's discovery parser and caches selector-per-IID into
its lookup array.

---

## 3. Handshake (selector `0x1F`)

Called from `hrAttachToService` immediately after the factory slot-`0x24`
attach succeeds. Validates server compatibility; a zero `validation_result`
triggers the **"Handshake validation failed — Ver …"** MessageBox (string at
`0x7E84E37C`) and MVTTL14C detaches.

### 3.1 Request

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | Literal `0x01` |
| `0x04` | 12 | Three LE DWORDs: `0x00002000`, `0x00004006`, `lcid` |
| `0x83` | 0 | Recv descriptor: one DWORD reply |

`lcid` is the client's browse language, `GetDwDefLcidBrowse()` default
overridden by `HKCU\...\Preferences\BrowseLanguage` (via
`GetPreferenceDword`).

### 3.2 Reply

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x83` | 4 LE | `validation_result` — **must be nonzero** (any nonzero value accepted; 1 is the minimum success indicator) |
| `0x87` | 0 | End of static section |

No dynamic section. The client's wait uses `MVAwaitWireReply` with a 30-second
timeout.

### 3.3 Post-handshake behaviour

After a good handshake, `hrAttachToService` also:

1. Fires `TitlePreNotify(0, opcode=10, buf=&DAT_7e84e2ec, size=6)` —
   selector `0x1E`. `DAT_7e84e2ec` holds a value bootstrapped from
   `DAT_7e851808` (observed zero). Server can reply with empty static +
   `0x87`.
2. Allocates five async callback slots (per-notification-type,
   `MVAsyncNotifyDispatch` @ `0x7E84485F`). These are client-side listeners; they
   do not require the server to initiate any traffic.

---

## 4. TitleOpen (selector `0x01`)

Called by `MVTTL14C!TitleOpenEx @ 0x7E842D4E` (export ordinal 41) to open
one title. Invoked from `MVCL14N!hMVTitleOpenEx`, itself called by
`MOSVIEW!OpenMediaTitleSession @ 0x7F3C61CE` once per open.

### 4.1 MVCache_<title>.tmp on-disk schema

`TitleOpenEx @ 0x7E842D4E` materializes the title body by either
reusing a cached on-disk copy or pulling it from the live reply
stream. The on-disk cache file lives under
`HKLM\SOFTWARE\Microsoft\MOS\Directories\MOSBin\MVCache_<title>.tmp`.
The leaf name is `wsprintfA("MVCache_%s.tmp", titleSpec)` with the
characters `:` / `[` / `\\` / `]` mapped to `_` and leading
underscores stripped after the substitution.

On-disk byte layout:

| Offset | Width | Field | Notes |
|-------:|------:|-------|-------|
| `+0x00` | u32 | `cacheTuple0` | client-opaque (memcmp only); server-controlled validation token |
| `+0x04` | u32 | `cacheTuple1` | client-opaque (memcmp only); server-controlled validation token |
| `+0x08..end` | bytes | `bodyBytes` | identical bytes to the live reply's dynamic body — `title+0xA4` allocation, `title+0xA8` byte count |

**Read path:**

1. `CreateFileA(GENERIC_READ, OPEN_EXISTING)`. Missing file → both
   request DWORDs sent as zero.
2. `ReadFile(8 bytes)` into `{cacheTuple0, cacheTuple1}`.
3. If file size > 8, `ReadFile(file_size - 8)` into a heap buffer.

**Send + validate:**

1. Request DWORDs 2 and 3 (selector `0x01` request below) are
   `cacheTuple0` / `cacheTuple1`.
2. Reply binds `liveTuple0` / `liveTuple1` (the last two DWORD reply
   bindings) from the server.
3. **8-byte `memcmp(cacheTuple, liveTuple)`** decides cache validity.
   Match → reuse cached buffer as `title+0xA4..0xA8`. Mismatch →
   discard cached buffer and pull bytes from the reply's dynamic
   stream.

**Write path (live stream):**

1. `CreateFileA(GENERIC_WRITE, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN |
   FILE_ATTRIBUTE_SYSTEM)`.
2. `WriteFile(liveTuple0/liveTuple1, 8)` — always the **live**
   tuple, not the stale `cacheTuple` (the file always ends up
   containing the most recent server-validated tuple).
3. `WriteFile(payloadBuffer, payloadByteCount)`.
4. Skipped entirely when `DAT_7e84e2F1 != 0` (the cache-disabled
   flag set by some MOSMISC paths).

The `scripts/inspect_mediaview_cache.py` utility parses the above
schema for offline analysis.

### 4.2 Request

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x04` | var | Title spec, NUL-terminated ASCII. `MOSVIEW` builds it as `":%d[%s]%d"` (service id / title name / index). |
| `0x03` | 4 LE | Cached checksum 1 (or 0) |
| `0x03` | 4 LE | Cached checksum 2 (or 0) |
| `0x81` | 0 | Recv: byte — `title_id` |
| `0x81` | 0 | Recv: byte — `title_id_byte2` (reused as the first request byte for `TitlePreNotify`/`TitleGetInfo`) |
| `0x83` | 0 | Recv: DWORD (copied to title struct +0x46) |
| `0x83` | 0 | Recv: DWORD (copied to title struct +0x48) |
| `0x83` | 0 | Recv: DWORD (copied to title struct +0x4A) |
| `0x83` | 0 | Recv: DWORD — new checksum 1 (server's canonical cache key) |
| `0x83` | 0 | Recv: DWORD — new checksum 2 |

The trailing seven bytes written by MPC's client stub are receive-only
descriptors — the server sees zero of them in the payload it parses; it
just has to produce matching reply fields in order.

### 4.3 Reply

Static section (exactly these tags, in order):

| Tag | Bytes | Role |
|-----|-------|------|
| `0x81` | 1 | `title_id` — any nonzero byte. Must NOT be zero; a zero byte routes to `LAB_7e8432d4` and title open returns NULL (viewer fails). |
| `0x81` | 1 | `hfs_volume` — low byte of `*(u32 *)(title+0x88)`. Served locally via `TitleGetInfo(info_kind=0x69)`; passed into baggage as the HFS mode byte (`HfOpenHfs`, §6c). |
| `0x83` | 4 LE | DWORD → `title+0x8c` = **contents va**. Served locally via `vaGetContents @ 0x7E841D48`. This is the entry-point virtual address navigation hands to the MedView engine (`NavigateViewerSelection` → `vaMVGetContents` → paint). `0xFFFFFFFF` / `0` both route `NavigateViewerSelection` into the "hideOnFailure" branch — **nothing paints**. |
| `0x83` | 4 LE | DWORD → `title+0x90` = **contents addr**. Served locally via `addrGetContents @ 0x7E841D07`; the MVCL14N export `addrMVGetContents @ 0x7E8854D0` wraps it. Address-space companion to `title+0x8c` (contents va); used by highlight / next-prev navigation paths that index into the addr-keyed cache list (§6b kind-2). MSN Today's first-paint chain (`vaMVGetContents` only) doesn't read it, so a zero is harmless on the welcome-screen path. |
| `0x83` | 4 LE | DWORD → `title+0x94` = **topic count**. Served locally via `TitleGetInfo(info_kind=0x0B)`. `hMVTopicListFromTopicNo(title, N)` uses this as the upper bound; zero means no topic resolves. |
| `0x83` | 4 LE | New checksum 1 |
| `0x83` | 4 LE | New checksum 2 |
| `0x87` | 0 | End of static |
| `0x86` | var | Dynamic "title body" — raw bytes to end of host block (see §4.4). Sent as `TAG_DYNAMIC_COMPLETE_SIGNAL` so the client's `Wait()` on slot `0x48` fires (same pattern as DIRSRV GetShabby). |

All three server-supplied DWORDs are read from the title struct on
demand by local `TitleGetInfo` paths and by the engine's paint chain.
Empirical (2026-04-27): shipping a nonzero `contents_va`
(`0x00010000` and `0xCAFEBABE` both probed) does NOT unblock paint
on the **initial-open path** — no follow-up wire traffic, the content
pane stays blank.

The reason `NavigateViewerSelection` is misleading on this path: it's
only the **interactive click handler** (sole caller is
`MOSVIEW!HandleMediaTitleCommand`), not the initial paint chain. The
actual initial-open flow is:

```
MOSVIEW!CreateMediaViewWindow  @ 0x7F3C4F26
  └─ MOSVIEW!OpenMediaTitleSession @ 0x7F3C61CE   (TitleOpen + body cache)
       └─ MVCL14N!vaMVGetContents @ 0x7E885660    (returns title+0x8c)
            └─ MVTTL14C!vaGetContents @ 0x7E841D48
       …stored at session+0x60
  └─ MOSVIEW!CreateMosViewWindowHierarchy        @ 0x7F3C6790    (pane attach + nav)
       └─ MOSVIEW!NavigateMosViewPane   @ 0x7F3C3670    (pane.SetAddress)
            └─ MVCL14N!fMVSetAddress @ 0x7E883600
                 └─ MVCL14N!MVHfcNear @ 0x7E885FC0
                      └─ GetProcAddress(per_title_module, "HfcNear")
                           └─ MVTTL14C!HfcNear @ 0x7E84589F   ← gate
```

`HfcNear` walks a **per-title cache** (binary tree at `title+4`,
recent-cache array at `title+0x10..0x34`; entries store 60-byte
content chunks at `entry+0x18`) via `HfcCache_FindEntryAndPromote`. On miss, it fires
selector `0x15` (§6b.1) up to 6 times in a retry loop with ~300 ms
spacing before returning NULL. If `HfcNear` returns NULL,
`fMVSetAddress` returns 0, `NavigateMosViewPane` sets the pane FAIL flag at
`pane+0x84` and skips paint.

`MVCL14N!vaMVGetContents` itself does NOT read memory at the va — it
calls `MVTTL14C!vaGetContents @ 0x7E841D48` via per-title
GetProcAddress, which just returns `title+0x8c` verbatim. The va is
therefore a `client-opaque` token (verified at `vaGetContents @
0x7E841D48`) the engine threads through to `HfcNear`'s cache lookup;
the cache is what knows how to render it.

### 4.4 Title body layout

The dynamic bytes `B` attached to the reply are a flat **9-section
stream**. Ground-truth from the `MVTTL14C!TitleOpenEx @ 0x7E842D4E` and
`TitleGetInfo @ 0x7E842558` decompiles:

1. `TitleOpenEx` saves `B` at `title + 0x52` and its length at
   `title + 0x54`.
2. It reads `b0 = *(u16 LE)B` as the size of **section 0**, the
   **font table**. Served to MVCL14N via `TitleGetInfo(info_kind=0x6F)`
   which returns `*(HGLOBAL *)(title+0x08)` — the same allocation built
   in this step. `fMVSetTitle` passes that handle to `hMVSetFontTable`.
   - `b0 == 0` → branch `LAB_7e8432c4`: skip the header decode, zero
     `title+0x08` (no font table). `TitleGetInfo(0x6F)` returns `0`.
     The MedView engine runs on its default font table with whatever
     built-in faces it has, but custom fonts for the title are absent.
     This is the empty-section-0 safe path.
   - `b0 != 0` → `GlobalAlloc(GPTR=0x40, b0)`, `MOVSD.REP` the `b0`
     bytes from `B+2`, then read `*(i16)(copy+0x00)` as the HFONT-slot
     count, `*(i16)(copy+0x10)` as the slot-array offset, and zero
     `count` dwords starting at `copy + slots_offset`. Raw-instruction
     source: `MOVSX ECX, [EAX]` at `0x7E843291` and
     `MOVSX ESI, [EAX+0x10]` at `0x7E8432A9`. The 18-byte header (offsets
     `+0x00..+0x11`) is consumed by `MVCL14N!ResolveTextStyleFromViewer
     @ 0x7E896610`, `CopyResolvedTextStyleRecord @ 0x7E896590`, and
     `MergeInheritedTextStyle @ 0x7E8963B0` as follows:

     | Offset | Width  | Field                       | Consumer cite |
     |-------:|-------:|-----------------------------|---------------|
     | `+0x00`| i16    | hfontSlotCount              | `TitleOpenEx @ 0x7E843291`; sized zero-loop for the runtime-allocated HFONT slot array. |
     | `+0x02`| i16    | styleRecordCount            | `ResolveTextStyleFromViewer @ 0x7E89661C`; bound check on the requested `style_id` (`<=` triggers fallback to descriptor 0). |
     | `+0x04`| i16    | faceNameArrayOffset         | `CopyResolvedTextStyleRecord @ 0x7E8965B5`; base for the `0x20`-byte face-name strings indexed by the resolved face id at `resolved_style[0]`. |
     | `+0x06`| i16    | styleRecordsOffset          | `CopyResolvedTextStyleRecord @ 0x7E8965A4`; base for the `0x2A`-byte style records indexed by `style_id`. |
     | `+0x08`| i16    | inheritanceRecordCount      | `CopyResolvedTextStyleRecord @ 0x7E8965E7`; passed as the `style_count` argument to `MergeInheritedTextStyle`. |
     | `+0x0A`| i16    | inheritanceArrayOffset      | same — base for the parent-style-chain entries (stride `0x92` bytes; up to 20 levels of recursion). |
     | `+0x0C`| i16    | reserved (client-opaque, verified across `ResolveTextStyleFromViewer`/`CopyResolvedTextStyleRecord`/`MergeInheritedTextStyle`) | — |
     | `+0x0E`| i16    | reserved (client-opaque, same verification) | — |
     | `+0x10`| i16    | hfontSlotArrayOffset        | `ResolveTextStyleFromViewer @ 0x7E896650`; base for the `u32[hfontSlotCount]` HFONT-wrapper pointer array. Slot lookup: `*(u32*)(base + hfontSlotArrayOffset + resolved_style[0] * 4)`. Slot+`0x16` dword is cached into `viewer+0xB4` for the layout engine. |

     The on-disk authoring source (`Blackbird.gpr / BBVIEW.EXE`) is
     `CFontTable` / `CFontDescriptor`; cross-reference is queued in
     §13 of `docs/BLACKBIRD.md` (Phase 5 cross-ref pass).
3. `TitleGetInfo` walks the remaining 8 sections on demand to answer
   field queries. Its `param_2` argument is the **selector kind**, not
   a section index — the dispatch table maps selector → section.

Section-by-section (`u16` = little-endian 16-bit):

| # | `TitleGetInfo` selector(s) | Header | Payload | Role |
|--:|---------------------------|--------|---------|------|
| 0 | `0x6F` (returns `title+0x08`, the copy handle) | `[u16 size]` | Font table — 18-byte header (`hfontSlotCount @ +0x00`, `styleRecordCount @ +0x02`, `faceNameArrayOffset @ +0x04`, `styleRecordsOffset @ +0x06`, `inheritanceRecordCount @ +0x08`, `inheritanceArrayOffset @ +0x0A`, two reserved i16 @ +0x0C/+0x0E, `hfontSlotArrayOffset @ +0x10`); engine zeros `hfontSlotCount` dwords at `base + hfontSlotArrayOffset` at load time. Style records: `0x2A` bytes each; face names: `0x20` bytes each; parent-style entries: `0x92` bytes each. Consumers in MVCL14N: `ResolveTextStyleFromViewer @ 0x7E896610` → `CopyResolvedTextStyleRecord @ 0x7E896590` → `MergeInheritedTextStyle @ 0x7E8963B0` → `CreateHfontFromResolvedTextStyle @ 0x7E896BA0`. | font table |
| 1 | `7` | `[u16 size]` | array of fixed **43-byte** records (10 u32 + u16 + byte) | extra child-pane descriptors |
| 2 | `8` | `[u16 size]` | array of fixed **31-byte** records (7 u32 + u16 + byte) | popup descriptors |
| 3 | `6` | `[u16 size]` | array of fixed **152-byte** records (38 u32) | outer-container / pane scaffold descriptors |
| 4 | `1` | `[u16 size]` | raw blob | title caption (ASCII) |
| 5 | `2` | `[u16 size]` | raw blob | second string (subtitle / copyright) |
| 6 | `0x6A` | `[u16 size]` | raw blob | default viewer-window title string — `fMVSetTitle @ 0x7E882910` stores the `GlobalAlloc` copy at `view+0x1c`; surfaced by the `hMVGetTitle @ 0x7E882A50` export (consumed by MOSVIEW for window-title display) |
| 7 | `0x13` | `[u16 sectionBytes][u16 count]` | `count × [u16 entryLen][entryBytes]` | indexed length-prefixed entry table; `TitleGetInfo @ 0x7E842558` returns the entry selected by `bufCtl>>0x10` (NUL-terminated, truncated to `bufCtl & 0xFFFF`). Entry payload is client-opaque to MVTTL14C/MVCL14N — handed verbatim to the external caller. |
| 8 | `4` (fallthrough for `4`/`0x6B`/`0x6D`/`0x6E`) | `[u16 count]` | `count × ASCIIZ` — **the string table** | strings referenced by the record arrays |

Section 7's empty form is just `[u16 size=0]` (the walker uses
`(size==0) ? 2 : size+4` to advance). Sections 0-6 are straight
`[u16 size][size bytes]`. Section 8 alone has no `size` — its header
is a direct string count.

The 43/31/152-byte record sizes are hard-coded inside `TitleGetInfo`
and come from the 1996 server's lowering of an authored Blackbird title
into the MedView wire body (see `docs/BLACKBIRD.md` §4.4). MVTTL14C
never touches `ole32`'s `IStorage` APIs — the section stream is the MSN
wire format; the OLE2 compound file is purely the authoring-side /
Local-target artifact.

These record shapes are wire-only facts, not proven direct dumps of one
Blackbird class. Current RE no longer supports flattening raw
`CSection` bodies into section 1: the sampled `CSection` serialization
is authored section membership data (form refs + top-level content/proxy
refs), while selectors `7` / `8` / `6` are consumed as separate
child-pane / popup / scaffold tables by MOSVIEW. The wire-side field
layouts of selectors `7`/`8`/`6` are fully pinned via
`MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` (see contract
`ChildPaneRecord`, `PopupPaneRecord`, `WindowScaffoldRecord`); the
on-disk BDF → wire compilation in `PUBLISH.DLL` is BDF-format work
out of scope for the protocol docs.

**Empty-but-valid body** (18 bytes): `00 00 × 8` (sections 0-7 all
empty) followed by `00 00` (section 8 count=0). The first `u16 == 0`
takes `LAB_7e8432c4` (no header decode), every `TitleGetInfo` lookup
returns -1, MOSVIEW's metadata-population loops exit cleanly on the
first iteration, and the title name falls back to `"Unknown Title Name"`.

**Name-populated body** (18 bytes + `len(name)+1`): sections 0-3 empty,
section 4 carrying `[u16 size=N][N ASCII bytes]` with a NUL-terminated
title name, sections 5-8 empty. `MOSVIEW!OpenMediaTitleSession @
0x7F3C6575` calls `TitleGetInfo(info_kind=1, dwBufCtl=0xBB8, buf)` —
info_kind=1 reads **section 4**, copies its raw bytes into `buf`, runs
them through `UnquoteCommandArgument` (strips backticks / double-quotes),
and stores the result at `title+0x58` as the viewer's window caption.
This is the minimal caption-only body.

Note: the string table in section 8 (info_kind=4) is a **separate**
field — a variable-length list of ASCIIZ items MOSVIEW pulls earlier in
the open flow, not the title name. Putting the title name in section 8
does nothing for the caption.

**Do NOT ship a zero-byte body.** With a truly empty wire payload,
`*(u16 LE)lpBuffer` reads adjacent heap memory; if the two bytes
happen to be nonzero, the header-decode branch is taken with an
arbitrary section size and the copy loop AVs at `MVTTL14C.DLL:0x7E843253`
(or `0x7E843288` / `+0x35` if the trailing bytes walk off the end of
the short buffer). MOSVIEW echoes the crash back via `TitlePreNotify`
opcode `0x08`:

```
"The title Appid=1, deid 0 ... , info='<name>' caused an EXCEPTION.
Winbase.h Code=xc0000005, Flag=x0, Address=x7e843253,
Parameters=2 on a client."
```

The **8-byte MVP body** used previously (`00 00 × 4`) also works, but
only by luck: `GlobalAlloc`'s minimum-granule padding returns zeros
for the extra `u16` reads `TitleGetInfo` makes past the declared end.
Prefer the 18-byte form — it exercises the same code paths without
relying on allocator behaviour.

### 4.5 Title spec format

MOSVIEW builds the TitleOpen spec string via `wsprintfA(":%d[%s]%d",
svcid, name, serial)` (see `docs/MOSVIEW.md` §5.3). Observed on the
wire:

```
':2[4]0'        MSN Today — svcid=2, name="4", serial=0
```

The `<name>` field is the caller-supplied title selector. On the
standard `HRMOSExec(c=6, deid, …)` path it's the deid formatted via
`%X` or `%X%8X` in MOSVIEW's deid normalization (§3.3), so for DIRSRV
nodes like MSN Today (`4:0`) it reduces to the decimal deid (`"4"`)
with no hex width.

The display name the authoring tool intends to surface here is
`CTitle.name` — a single ASCIIZ in the CTitle storage's
`\x03properties` stream inside the authored `.ttl` compound file
(`docs/BLACKBIRD.md` §3.1.2). The MedView viewer reads it via
`TitleGetInfo(info_kind=1)` against section 4 of the 9-section body
(§4.4) and runs it through `UnquoteCommandArgument` before storing at
`title+0x58` as the window caption. Rich title content comes from a
server-side lowering step over authored object streams such as
`CBForm`, `CVForm`, `CProxyTable`, and `CContent`; the fixed record
arrays in the 9-section body are not a proven direct dump of one on-disk
class (`docs/BLACKBIRD.md` §3.1.3 and §7).

### 4.6 Layout walker dispatch byte is engine-internal, not on-disk

`MVCL14N!MVParseLayoutChunk @ 0x7E890FD0` reads `name_buf[0x26]` from a
type-0 cache buffer and dispatches `MVWalkLayoutSlots @ 0x7E894C50` on
that byte. The byte at `+0x26` looks like a class-version tag —
`VIEWDLL!CSection::Serialize @ 0x4070E6AF` writes `bVar3 = 3` as its
on-disk version — but the resemblance is coincidental. Evidence:

1. `MVBuildLayoutLine @ 0x7E894560` (the case-3 handler) writes the
   layout-row tag itself: `*puVar10 = 3` at `+0xfd`, `*puVar9 = 7`
   at `+0x1d4`, `*puVar9 = 4` at `+0x21f`, into freshly-`GlobalAlloc`'d
   0x47-byte slots. The walker dispatches on bytes the engine
   wrote — not bytes that came over the wire. Cases 1/3/4/5/0x20/
   0x22/0x23/0x24 are layout-table-row tags (CSection, link,
   typed-element child, …), not on-disk class versions.
2. `VIEWDLL!CContent::Serialize @ 0x4073A185` writes no class-version
   byte at all. It chunked-reads `0x1000`-byte blocks from a
   `CFile *` stored at `this+0x14` (set by
   `CContent::CContent(CFile*) @ 0x4073A07F`) and copies them
   verbatim into the CArchive. CContent on disk is opaque blob —
   raw HTML/GIF/text — not a layout descriptor.
3. `MVCL14N!MVResolveBitmapForRun @ 0x7E886310`, called by case 3 with the
   u16 key `*(short *)(param_3 + (short)pbVar4)` at `name_buf+0x26+3`,
   is a font/bitmap/HMETAFILE resource loader. It calls
   `GetDeviceCaps`, `GlobalAlloc(0x40, …)`, builds an HBITMAP. A
   CContent record fed through this code path would AV.
4. Fixture confirms: `Title.objects[8][1]` (CContent sub=1) starts
   with ASCII `R` then `This is an exa…` — raw stream payload, not
   a layout descriptor. CContent's `\x03properties` stream also
   fails the CTitle/CSection-shape parser (`_parse_property_stream`
   in `src/server/services/ttl.py`, "value 1 wants 140865657B").
   The CContent property-tag layout differs.

Implication: the type-0 cache (`title+4` tree, fed by `0xBF` pushes)
holds layout-section descriptors keyed by va. Pushing a CContent
record into it will be parsed as a malformed layout descriptor and
either AV or be silently discarded. **CContent on the wire flows
through the baggage path** (selectors `0x1A` / `0x1B` / `0x1C`) —
see §6c.

---

## 5. TitleGetInfo (selector `0x03`)

`MVTTL14C!TitleGetInfo @ 0x7E842558` (export ordinal 39). Serves most
metadata from the cached body bytes locally; only a few `info_kind` values
actually go out on the wire (case `LAB_7E842B4B` / `LAB_7E842B1E` in the
decompile).

### 5.1 Local path (no RPC)

`info_kind` in {`0x01`, `0x02`, `0x04`, `0x06`, `0x07`, `0x08`, `0x0B`,
`0x13`, `0x69`, `0x6A`, `0x6E`, `0x6F`} is served locally without any
network traffic. Three of those are **scalars read from the title
struct** (populated from the TitleOpen reply, not the body bytes):

| `info_kind` | Returns | Source |
|------------:|---------|--------|
| `0x0B` | `*(u32 *)(title + 0x94)` — **topic count** | TitleOpen reply DWORD 3 |
| `0x69` | `*(u32 *)(title + 0x88)` — HFS volume byte (low 8 bits live in the DWORD) | TitleOpen reply byte 2 |
| `0x6F` | `*(HGLOBAL *)(title + 0x08)` — **font table handle** | Section 0 of body → GlobalAlloc copy |

All other local kinds read the body directly — see the per-section
table in §4.4.

### 5.2 Wire path (when RPC is needed)

Everything else — notably `info_kind` values around `0x03/0x05/0x0A/0x0C`..
`0x10/0x0E/0x66-0x6E` — goes out on selector `0x03`:

Request:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `title_id_byte2` (the second reply byte from TitleOpen) |
| `0x03` | 4 LE | `info_kind` |
| `0x03` | 4 LE | `dwBufCtl` = `(buffer_size << 16) | index` (client packs these into one DWORD) |
| `0x03` | 4 LE | `buffer_ptr` sentinel |
| `0x83` | 0 | Recv: DWORD (size) |

Reply:

| Tag | Bytes | Role |
|-----|-------|------|
| `0x83` | 4 LE | Size of the data in the dynamic chunk (0 = not found) |
| `0x87` | 0 | End of static |
| `0x86` | var | Dynamic: raw buffer of the requested length (or empty if size==0) |

**MVP contract**: always reply with `size=0` + empty dynamic. The client
stores 0 in its output buffer; MOSVIEW's `lMVTitleGetInfo` returns 0 and
the caller skips the info.

---

## 6. TitlePreNotify (selector `0x1E`)

`MVTTL14C!TitlePreNotify @ 0x7E843941` (export ordinal 12). Cache hints /
invalidation messages sent from the client to the server.

Opcodes with early returns (NO RPC): `9`, `0xB`, `0xC`, `0xF`.
Opcodes `1`/`2`/`3`/`5`/`6`/`0xD`/`0xE` run a local transform then go to
the wire; opcode `10` (the one fired from `hrAttachToService`) goes to the
wire with the original buffer.

Request:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `title_id_byte2` (or 0 when `param_1 == -1`) |
| `0x02` | 2 LE | `opcode` (low 16 bits of `param_2`) |
| `0x04` | var | Opcode-specific payload (for opcode 10: 6 bytes sourced from `DAT_7e84e2ec`, observed all zeros) |

Reply: none of substance. The client's `slot 0x48` waits for completion,
then immediately releases the reply handle (`slot 8`). A trivial
`0x87`-only reply (no body) is sufficient. The server can also drop the
message on the floor if the client's timeout tolerates it — but the clean
path is to ack.

**MVP contract**: reply static-only with `0x87` end-of-static.

Additionally, `lMVTitleGetInfo` maps 5/6 in OpenMediaTitleSession to two
more wire-path `info_kind`s — the **title name** is `info_kind=1`
(section 4 of the body, copied through `UnquoteCommandArgument` into
`title+0x58`, which becomes the window caption) and the **optional
second string** is `info_kind=2` (section 5 → `title+0x5c`). Both are
served locally from the body bytes (§5.1); no extra RPC.

---

## 6a. SubscribeNotification (selector `0x17`)

Immediately after the handshake ack, `MVTTL14C!hrAttachToService`
allocates **5** async-notification subscriber objects via
`MVAsyncNotifyDispatch @ 0x7E84485F` — one per notification type. Each
subscriber's constructor calls `MVAsyncSubscriberSubscribe @ 0x7E844EE6` which
invokes selector `0x17` on the service proxy with a single tagged byte
(the notification-type index, observed `0..4`) and waits on slot `0x48`
for an async-iterator handle.

Request (3 bytes), wire-observed `01 <type> 85`:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | Notification type index |
| `0x85` | 0 | Recv descriptor: dynamic-recv (single-shot blob, NOT iterator) |

Reply semantics: if the server hands back a non-NULL iterator handle,
the subscriber starts a `CreateThread(MVAsyncSubscriberWorkerPump, …)` pump that waits
on that handle for push notifications (title invalidation, cache
flush, etc.). If the handle is NULL or slot-0x48 returns an error, the
subscriber leaves `param_1[2].LockCount == 0`, never starts a thread,
and `hrAttachToService` moves on to the next subscriber.

**Wire contract**: reply `0x87 0x88` (end-static + iterator
stream-end) for every notification type. `MPCCL!ProcessTaggedServiceReply
@ 0x04604F26` allocates a `dynamicReplyState` in the
`LAB_04605187` path on the `0x88` tag, leaves
`subscriber+0x28` (m_pMoreDatRef) non-NULL, and signals
`m_heventMoreDat` + `m_heventDynMsg`. The success branch in
MPC's Execute then sets `subscriber+0x44 = 1`, and once all 5
subscribers report `+0x44 != 0` the master flag `DAT_7e84e2fc`
sets in `hrAttachToService`.

The alternative `0x87 0x86 + 8 zeros` reply also leaves
`+0x28` non-NULL, but `0x86` fires `MPCCL!SignalRequestCompletion
@ 0x04604DDC` which writes `*(req+0x18) = 1`. That flag suppresses
the `ResetEvent` call in `MPCCL!WaitForMessage @ 0x04604BA4` and
`MPCCL!FUN_046049BC @ 0x046049BC`, leaving the manual-reset events
permanently signaled. The waiter then spins on
`MsgWaitForSingleObject` returning `WAIT_OBJECT_0` instantly and
the caller loops on `0xb0b000b/c` returns — observed as ~30 % CPU
per spinning request × 3 (types 1/2/4) ⇒ ~90 % MOSVIEW.EXE CPU.

Server-initiated push of cache-update frames (op-code 4 kind-2
va→addr per project memory) flows through the type-3 subscription's
notification-pump thread `MVAsyncSubscriberWorkerPump`, not the initial reply —
which is why an empty-body iterator reply is sufficient.

### Master-flag gate (`DAT_7e84e2fc`)

`hrAttachToService @ 0x7E844114` only sets `DAT_7e84e2fc = 1` when
**all 5** subscribers report a non-NULL handle at `+0x44`:

```c
if ((DAT_7e84e308 != 0 && *(int *)(DAT_7e84e308 + 0x44) != 0) &&
    (DAT_7e84e30c != 0 && *(int *)(DAT_7e84e30c + 0x44) != 0) &&
    (DAT_7e84e310 != 0 && *(int *)(DAT_7e84e310 + 0x44) != 0) &&
    (DAT_7e84e314 != 0 && *(int *)(DAT_7e84e314 + 0x44) != 0) &&
    (DAT_7e84e318 != 0 && *(int *)(DAT_7e84e318 + 0x44) != 0)) {
    DAT_7e84e2fc = 1;
}
```

`MVCheckMasterFlag @ 0x7E8440AB` (the "service ready" check called from
every cache-miss retry loop) returns `0` when `DAT_7e84e2fc == 0`.
That kills `HfcNear`'s retry loop on its first iteration —
`if (iVar2 == 0) return 0;` — so selectors `0x06` / `0x07` / `0x10`
/ `0x15` never fire on the wire and `fMVSetAddress` returns 0,
setting the pane FAIL flag at `pane+0x84`. Empirical observation
2026-04-27: with the static-only `0x87` reply, MSN Today opens with
caption only and the inner panes never paint, regardless of what
`contents_va` value the TitleOpen reply ships.

**Implication**: lighting up the cache-push channel for type 3 only
is not enough. ALL 5 subscriptions must establish iterator handles
or the master flag never sets. The cheapest fix is the empty-stream
reply (`0x87 0x88`) for every subscription type — content for the
non-3 types can stay un-pushed indefinitely.

---

## 6b.1. vaResolve (selector `0x15`) — HfcNear cache-miss fallback

`MVTTL14C!HfcNear @ 0x7E84589F` is the per-title cache lookup the
engine calls via `MVCL14N!fMVSetAddress @ 0x7E883600` →
`MVCL14N!MVHfcNear @ 0x7E885FC0` → `GetProcAddress(module,
"HfcNear")`. On cache miss it fires this selector. Sole caller in
MVTTL14C; `PUSH 0x15` at `0x7E845973`.

Request:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `title_byte` (= `*(title+0x02)`, echoed across all per-title RPCs) |
| `0x03` | 4 LE | `va` (the virtual address the engine wants the matching content chunk for) |
| `0x88` | 0 | Recv: dynamic-iterator handle (immediately released by HfcNear, never read) |

Reply: static `0x87` only, no dynamic. The reply iface is acquired
via the request iface's `+0x48` execute method and immediately
released with no payload read. Critically, **`iVar2 < 0` from execute
kills the retry loop** — without a server-side handler we'd return
"unhandled selector", the proxy would surface that as a negative
HRESULT, and HfcNear would bail on the first retry without polling
the cache again.

Pattern matches selector `0x07` (`vaConvertTopicNumber`) exactly:
ack-only, with the actual answer expected through the
selector-`0x17` type-3 async-push channel. The server must populate
the per-title 60-byte content cache (binary tree at `title+4`)
before HfcNear's next iteration of `HfcCache_FindEntryAndPromote` (~300 ms later).

### Cache structure (per-title, distinct from MVTTL14C global cache)

The cache HfcNear consults is stored **inside the title struct** and
the underlying entries are populated by `HfcCache_DispatchContentNotification
@ 0x7E8452D3` (type-0 callback). Three layered structures share the same
title state — a sorted entry list, a primary MRU, and a paired
companion MRU.

#### Entry record layout (`HfcCache_InsertOrdered @ 0x7E8460DF`)

Each cache entry is `0x20 + payloadBytes` bytes, allocated by
`MVAllocScratchBytesWithRetry`:

| Offset | Width | Field | Source |
|-------:|------:|-------|--------|
| `+0x00` | u32 | `next`              | next-pointer in the sorted list at `title+0x04` |
| `+0x04` | u32 | `va`                | cache key (ordering key for the list) |
| `+0x08` | u32 | `prev_va`           | payload\[1\] from the 0xbf wire frame; `-1` for sentinel |
| `+0x0C` | u32 | `next_va`           | payload\[3\] from the 0xbf wire frame; `-1` for sentinel |
| `+0x10` | u32 | `payloadPtr`        | always `entry + 0x20` — inline trailing array |
| `+0x14` | u32 | `payloadBytes`      | bytes copied from the wire payload |
| `+0x18` | u32 | `extraScratchPtr`   | pointer to the 60-byte content companion (or NULL) |
| `+0x1C` | u32 | `flags`             | zero-init by the inserter; not touched on lookup |
| `+0x20..` | bytes | inline `payload`  | `payloadBytes` bytes copied verbatim from the wire 0xbf payload |

After an insert, neighbour links are fixed up so `prev->next_va` and
`next->prev_va` stay coherent for range walks.

#### Sorted list (`title+0x04`)

Singly-linked, ordered ascending by `entry+0x04` (`va`). Walked by
`HfcCache_InsertOrdered` to find the insertion point and by
`HfcCache_FindEntryAndPromote @ 0x7E845EFA` as the fallback when the
MRU misses. `va` is the only field consulted for ordering; the
"key < head" branch returns NULL on probe.

#### Primary MRU (`title+0x10 .. title+0x34`)

10-slot pointer array (40 bytes) used by the **NULL-companion**
lookup path (passed `outCompanionBlock == NULL` to
`HfcCache_FindEntryAndPromote`). Slot 0 is the most-recently-used
entry; slots 1..9 are previous hits in ascending age.

Lookup probes the head pointer first (fast path), then scans slots
0..9 sequentially. On a hit at slot `N`:

```
memcpy(title+0x14, title+0x10, N*4);  // shift slots 0..N-1 down
*(int*)(title+0x10) = hit;            // install hit at slot 0
```

On a sorted-list hit (MRU miss), the full 10-slot array is shifted by
one (`memcpy(title+0x14, title+0x10, 0x24)`) and the hit is installed
at slot 0.

#### Companion MRU (`title+0x38 .. title+0x5C` paired with `title+0x60 .. title+0x84`)

10-slot **entry pointer** array at `title+0x38` (40 bytes), paired
with a 10-slot **companion-block pointer** array at `title+0x60` (40
bytes). Used when `HfcCache_FindEntryAndPromote` is called with a
non-NULL `outCompanionBlock` — i.e., the `HfcNear` path that needs
the 60-byte content companion. Slot index is shared between both
arrays; `title+0x60 + idx*4` is the companion-block pointer for
`title+0x38 + idx*4`'s entry.

LRU promotion is identical to the primary MRU (slide on hit), and
the secondary array is mirrored — `memcpy(title+0x64, title+0x60,
shiftBytes)` keeps the companion slot aligned with its entry slot.

#### 60-byte content companion (`entry+0x18` pointer; `0x3C` bytes)

Allocated by `HfcCache_DispatchContentNotification` for type-0
`0xBF` (rich topic record) notifications via
`MVAllocScratchBytesWithRetry(0x3C)`. Bytes 0..0x2B are copied
verbatim from the wire's 0xbf-record metadata block (the 60 bytes
sitting at `notifyBuf + payloadSize + 4`). The two 4-byte "present"
markers at wire offsets `+0x2C` and `+0x34` are replaced in-memory
with HGLOBAL handles that wrap the variable-length **body** and
**name** buffers extracted from the same wire frame:

| Offset | Width | Field | Source |
|-------:|------:|-------|--------|
| `+0x00..+0x2B` | 44 bytes | wire-metadata header | raw-copied from notifyBuf; client-opaque to MVTTL14C (consumed by the picture/glyph rendering path that reads the companion via `param_3+0x2C / +0x34`) |
| `+0x2C` | HGLOBAL | `bodyHandle` | `GlobalAlloc(GMEM_FIXED, bodyByteCount+1)`, locked, filled from notifyBuf body region, NUL-terminated |
| `+0x30` | u32 | `bodyByteCount` | raw-copied from wire (drives the GlobalAlloc size) |
| `+0x34` | HGLOBAL | `nameHandle` | `GlobalAlloc(GMEM_FIXED, nameLen)`, locked, filled from the trailing ASCIIZ name in notifyBuf |
| `+0x38..+0x3B` | 4 bytes | wire-tail metadata | raw-copied from notifyBuf; client-opaque |

`HfcNear @ 0x7E84589F` consumes the companion as follows:

```
memcpy(param_3, companion, 0x3C);
param_3[0x2C] = MVCloneGlobalBlock(companion[0x2C]);  // bodyHandle clone
param_3[0x34] = MVCloneGlobalBlock(companion[0x34]);  // nameHandle clone
```

The destination `param_3` is `fMVSetAddress`'s `lp+0x40 / lp+0x68`
pane content-record slot.

Frame format that drives the companion fill is the type-0 callback
chain: kind `0xBF` records carry `[u16 payloadSize][...payload...][60-byte metadata]
[body bytes][ASCIIZ name]`. Kind `0xA5` records update only the
metadata token at `entry+0x18` status path; kind `0x37` records carry
incremental trailers for a previously-started `0xBF` entry.

## 6b. Content selectors (va / addr / highlight resolution)

MVCL14N's render path pulls most content off a local 3-list cache at
`MVTTL14C.DLL:PTR_DAT_7e84e130`, keyed by `(title_byte, topic_no)`
(list 0), `(title_byte, hash)` (list 1), `(title_byte, va)` (list 2).
The primary consumers walk the cache via `MVGlobalVaAddrCache_Find` / `MVGlobalVaAddrCache_FindValue8ByValue4`:

- `vaGetContents(title) @ 0x7E841D48` — returns `*(u32 *)(title+0x8c)`
  (TitleOpen reply DWORD 1). No RPC.
- `vaConvertTopicNumber(title, N) @ 0x7E841FCF` — cache lookup first;
  on miss, fires wire **selector `0x07`** with `{0x01=title_byte,
  0x03=topic_no}` then polls the cache with a 30 s timeout.
- `vaConvertHash(title, hash) @ 0x7E841E9A` — same shape, wire
  **selector `0x06`**.
- `addrConvertTopicNumber`, `addrConvertContextString`, `vaConvertAddr`
  are thin wrappers that feed the same two fallback selectors.
- `HighlightsInTopic(title, topic) @ 0x7E841526` — wire **selector
  `0x10`**; dynamic-iterator reply (slot `0x14` + slot `0x48` wait).
  Reply bytes are consumed by `MVCopyDynamicReplyStreamBytes`.

The selectors `0x06` / `0x07` do NOT themselves return a va in the
reply — the client waits on `slot 0x48`, releases immediately, and
re-checks the cache. The actual answer arrives **through the async
subscription channel** (selector `0x17`, one iterator per notification
type; see §6a). `MVAsyncSubscriberWorkerPump @ 0x7E844C7C` is the pump thread that
reads chunks via `piVar1->m0x1c(iter, &chunk)` and hands them to the
per-type callback registered in the subscriber struct at `+0x20`.

### Subscription types and callbacks

`hrAttachToService @ 0x7E844114` installs 5 subscribers, one per
notification type index sent on selector `0x17`:

| Type | Callback | Purpose |
|-----:|----------|---------|
| 0 | `HfcCache_DispatchContentNotification` | Topic metadata / string attachments (opcodes `0xBF`, `0xA5`, `0x37`) — **opcode 0xBF inserts into HfcNear's per-title cache** at `title+4` via `HfcCache_InsertOrdered`. Driven by HfcNear's own retry loop (`MVPumpHfcContentNotifications` → `MVPumpNotificationType(idx=0, …)` → `MVAsyncSubscriberPumpNotifications` → `MVAsyncSubscriberDispatchChunk` → `HfcCache_DispatchContentNotification`), no pump thread required (`param_3 = 0` to `MVAsyncNotifyDispatch`). |
| 1 | `WordWheelCache_DispatchNotification @ 0x7E849251` | **Word-wheel result records.** Each record header is 11 bytes (u16 recordSize, u8 wordWheelId, u8 pendingFlag, u32 ordinal, u8 reserved, u16 payloadCount) followed by `payloadCount × u32` payload DWORDs and an optional ASCIIZ name. Per-record side-effect: writes `ordinal` and `pendingFlag` into the per-wordwheel slot at `DAT_7e84e668[DAT_7e850258[wordWheelId] × 0x1c]`, then prepends a 0x24-byte cache record via `WordWheelCache_InsertEntry`. `pendingFlag==0xFF` is a synthetic "request-done" sentinel (slot+9 zeroed, probe-match forced). Caller can pass `{u8 wordWheelId; u8[3] pad; u32 ordinal}` via the subscriber context to break the dispatch loop on the matching record (OR 0x80000000 into the consume count). |
| 2 | `HighlightCache_DeserializeAndRegister` | Context-string / global-state updates (writes `DAT_7e84d02c`-family tables) |
| 3 | `NotificationType3_DispatchRecord` | **va / addr cache pushes** (populates `PTR_DAT_7e84e130` global kind-0/1/2 cache via op-code 4 → `NotificationType3_ApplyAddressConversionResult`). **Different cache from HfcNear's `title+4` tree.** |
| 4 | `NotificationType4_ApplyChunkedBuffer @ 0x7E8468D5` | **Picture / media transfer chunks.** Opcode-3 frames carry `{u16 op=3, u16 frameBytes, u32 transferId, u32 chunkOffset, u8 data[frameBytes-0xc]}`. The callback resolves `transferId` against the active media-transfer list at `PTR_DAT_7e84e628+0x1c`, lazily allocates / grows the `+0x30` buffer to `chunkOffset + payloadBytes`, copies the chunk in, advances the committed byte cursor `+0x38`, and posts `WM_USER+0x0e` (0x40e) to each attached sink HWND (or the global notify window `DAT_7e84e330` for the marker-buffer case). Other opcodes 1, 2, 4, 5 are accepted but discarded; opcode 0 or >5 returns frameBytes without inspection. |

### Type-3 frame format (cache push)

`NotificationType3_DispatchRecord @ 0x7E8451EC` is the callback. Each chunk the pump
delivers is a sequence of framed messages:

```
+0x00  u16 op_code   (1..5; 0 and >5 skipped silently)
+0x02  u16 length    (includes the 4-byte header; must be ≤ chunk remaining)
+0x04  payload       (length - 4 bytes, op_code-specific)
```

Op-code dispatch inside type-3:

| op_code | Dispatch | Handles |
|--------:|----------|---------|
| 1, 2 | `NotificationType3_ApplyObjectStatus` | Topic / hash invalidation |
| 3 | — (silently skipped, length still consumed) | Reserved |
| **4** | `NotificationType3_ApplyAddressConversionResult` | **va / addr cache insert** |
| 5 | `NotificationType3_ApplyInfo6eCacheRecord @ 0x7E8424F5` | **MVTTL info-kind 0x6e string cache push.** 17-byte header `{u8 titleId, u24+u8 infoKind, u24+u8 resultLength, u24+u8 bufCtl, u24+u8 payloadBytes}` followed by `payloadBytes` of value bytes (or the inline 4-byte value at offset +13 when `payloadBytes==0`). Routes to `MVCacheInfo6eString @ 0x7E842267` only when the title-byte resolves an attached title state and `infoKind == 0x6e`. Other infoKinds are accepted on the wire but discarded. |

### Op-code 4 payload (14 bytes)

| Offset | Size | Kind 0 (topic→va+addr) | Kind 1 (hash→va) | Kind 2 (va→addr) |
|-------:|-----:|------------------------|------------------|------------------|
| +0 | 1 | title_byte | title_byte | title_byte |
| +1 | 1 | `0x00` | `0x01` | `0x02` |
| +2 | 4 LE | topic_no | hash | (any; stored at cache+0xC, not consulted by list-2 lookup) |
| +6 | 4 LE | va | va | va (becomes cache+4 — the lookup key) |
| +10 | 4 LE | addr | (ignored but stored) | addr (becomes cache+8 — the return value) |

Total framed message = 18 bytes. Kinds 0/1/2 route into the three
parallel lists at `PTR_DAT_7e84e130[0..2]`. Lookups:

- Kind 0: `MVGlobalVaAddrCache_Find` matches `(title_byte, topic_no@+0xC)` →
  returns `(va, addr)` from `(+4, +8)`.
- Kind 1: `MVGlobalVaAddrCache_FindValue8ByValue4(list=1)` matches `(title_byte, hash@+4)` →
  returns `va` from `+8`.
- Kind 2: `MVGlobalVaAddrCache_FindValue8ByValue4(list=2)` matches `(title_byte, va@+4)` →
  returns `addr` from `+8`.

### HfcNear's per-title cache (`title+4` tree)

`MVTTL14C!HfcNear @ 0x7E84589F` is the gate `fMVSetAddress` calls
during initial pane attach (via `MVHfcNear` →
`GetProcAddress("HfcNear")`). It walks `*(int **)(title + 4)` (binary
tree of cache entries, 32-byte node + name buffer) via
`HfcCache_FindEntryAndPromote`. On miss, it fires selector `0x15` and waits for the
cache to fill. **The only function that inserts into this tree is
`HfcCache_InsertOrdered`** (sole caller: type-0 callback `HfcCache_DispatchContentNotification` when
parsing opcode `0xBF`). Op-code 4 on type-3 writes to
`PTR_DAT_7e84e130` (global kind-0/1/2 cache for `vaConvertHash` /
`vaConvertTopicNumber`) — **not the same cache** as HfcNear walks.

Wire layout for opcode 0xBF push (size=8 form, 72 bytes):

```
+0x00  u8   opcode = 0xBF
+0x01  u8   title_byte (matched in MVFindTitleStateByTitleByte's title list)
+0x02  u16  name_size (must be > 0; HfcCopyCacheRecordPayloadToGlobal returns NULL when
                       entry+0x14 = name_len = 0, killing HfcNear's
                       success path)
+0x04..0x0B  8-byte name buffer (memcpy'd into entry+0x20)
+0x0C  u32  key (the va HfcNear looks up; stored at entry+4 and
                 matched at `entry[1] == key` in HfcCache_FindEntryAndPromote)
+0x10..0x47  56 bytes of 60-byte content block (key field at +0xC
              doubles as content[0..3] for size=8 because
              HfcCache_DispatchContentNotification reads key at fixed offset 0xC and copies
              60 bytes starting at offset (size + 4) = 0xC).
```

**60-byte content companion** — Resolved (Phase 6, 2026-05-11). Full
layout pinned via `HfcCache_DispatchContentNotification @ 0x7E8452D3`
producer and `HfcNear @ 0x7E84589F` consumer; see §6b.1's
"60-byte content companion" subsection. Bytes 0..0x2B + 0x38..0x3B
are raw-copied wire-metadata bytes (client-opaque to MVTTL14C), and
the HGLOBAL slots at `+0x2C` / `+0x34` wrap body / name buffers.

**Layout-walker AV (root cause for "service is not available" dialog).**
Pushing a 0xBF chunk with zero name buffer (any size 0x08..0x40 tested)
unblocks HfcNear successfully, but the buffer flows downstream into
`MVCL14N!MVParseLayoutChunk → MVWalkLayoutSlots` (called from `MVRealizeView`'s
section walker) and trips an AV at `0x7E894D4C`:

```
0x7E894D41  LEA ECX, [ECX + ECX*8]       ; ECX = sVar3*9
0x7E894D44  SUB ECX, EAX                 ; ECX = 0x47*sVar3
0x7E894D46  ADD ECX, [EDI + 0xf6]        ; ECX += lp[+0xf6] (table base)
0x7E894D4C  MOVSX EAX, word ptr [ECX + 0xb]   ; AV — sVar3 walks past valid records
```

Mechanism (Ghidra-traced 2026-04-28):

1. `MVParseLayoutChunk` declares `local_30..local_24` and explicitly inits
   `local_30 = 0`, `local_2c = 0`, `local_2a = 0`, `local_24 = 0` —
   but **leaves `local_2e` uninitialized** (stack frame `SUB ESP,
   0x2c` allocates the space, no MOV zeroes it).
2. `MVParseLayoutChunk` calls `MVWalkLayoutSlots(lp, &puVar2[6], name_buf+0x26,
   ..., &local_30)`. `param_6 = &local_30`, so `param_6[0] = 0` and
   `param_6[1] = local_2e = garbage`.
3. `MVWalkLayoutSlots` calls `MVDecodeTopicItemPrefix(local_c, name_buf+0x26)` to
   decode the first record. With our zero-filled name buffer, byte
   `0x26` = 0 → `local_c[0] = 0`.
4. `switch(local_c[0])` matches no case (cases are 1, 3, 4, 5, 0x20,
   0x22, 0x23, 0x24) → default → break, **no record added, no
   `param_6[1]` update**.
5. Post-switch loop `if (param_6[4] == 0 && param_6[5] == 0 && *param_6
   < param_6[1])` — guards on 4/5 forced to 0 by MVWalkLayoutSlots itself.
   `*param_6 = 0`, `param_6[1] = local_2e = garbage`. Loop walks
   garbage records → AV.

The engine's exception handler catches the AV and surfaces "This
service is not available at this time" via `TitlePreNotify opcode 8`
echo with full diagnostic string (`Code=xc0000005 Address=x7e894d4c
Parameters=2`). Graceful degradation — MOSVIEW stays alive.

**Avoidance requires byte 0x26 of name_buf to land on a switch case
(1/3/4/5/0x20/0x22/0x23/0x24) AND the case handler must complete
without itself AV'ing.** Each handler depends on chunk content
populating internal state via `MVDecodePackedTextHeader`'s schema decoder:

- Case 1 (`MVBuildTextItem`): do-while loop `while (MVTextLayoutFSM < 5)`.
  Early-exit at `MVTextLayoutFSM` entry checks
  `*(char *)(local_120[2] + local_120[0x10]) == 0` — both fields are
  populated by `MVDecodePackedTextHeader` from the chunk's 32-bit "presence
  bitmap" header.  Zero-fill chunk → `local_120[2] = 0`,
  `local_120[0x10] = 0` (uninitialised local stack), deref vaddr 0
  AVs immediately.  To pass cleanly: encode chunk with bitmap bits
  17 + bit 0 of high u16 set so `local_120[2]` gets a non-zero base,
  AND `local_120[+0x27] >= 6` so the trailing records loop writes
  past byte 0x40 (= int index 0x10) with values that sum back to a
  readable NUL byte.  Plus several `lp+0x102 / 0xf6 / 0x80 / 0x10a`
  state fields that have to be primed.
- Case 3 (`MVBuildLayoutLine`): calls `MVResolveBitmapForRun(lp, fontspec)` which
  always returns a non-NULL HGLOBAL (alloc'd inside) → no early exit
  → continues into `lp+0xee/+0xf6` table reallocations with
  case-3-specific schema fields.
- Cases 4/5 (`MVBuildColumnLayoutItem`, `MVBuildEmbeddedWindowItem`): similar lp dependencies
  plus their own chunk-content schemas.

### `MVDecodePackedTextHeader` schema decoder (chunk → local_120)

`MVBuildTextItem` parses chunk content right after `MVDecodeTopicItemPrefix`
consumed the opcode byte.  Entry chunk pointer = `chunk + 0x26 +
opcode_consumed_bytes` (3 for compact opcodes).  First u32
(`*chunk_content`) is the **presence bitmap**:

**Always-written inline scalars** (extracted from `uVar1` bits 0-15):

| local_120 offset | Width | Field                          | Source bits (in uVar1 low halfword) |
|-----------------:|------:|--------------------------------|-------------------------------------|
| `+0x00`          | i32   | `text_start_index`             | Sign-magnitude varint preceding uVar1; low bit selects byte vs word form |
| `+0x04`          | u16   | `text_base_present`            | bit 0 of low byte (`uVar1 & 1`) |
| `+0x08`          | u16   | `header_flag_16_0`             | bit 0 of high byte of low halfword (`(uVar1 >> 16) & 1`, treated as `uStack_6 & 1`) |
| `+0x0A`          | u16   | `edge_metrics_enabled`         | `(uStack_6 & 0x100) >> 8` |
| `+0x0C`          | u16   | `alignment_mode` (0=left, 1=right, 2=center) | `(uStack_6 & 0xC00) >> 10` |
| `+0x0E`          | u16   | `header_flag_28`               | `(uStack_6 & 0x1000) >> 12` |

**Presence bits and gated fields** (bits 16-25 of `uVar1`):

| Bit | Gates field                   | Offset | Width | Default if absent |
|----:|-------------------------------|-------:|------:|-------------------|
| 16 (`0x10000`)   | `text_base_or_mode`        | `+0x12` | i32 | 0 |
| 17 (`0x20000`)   | `space_before`             | `+0x16` | i16 | 0 |
| 18 (`0x40000`)   | `space_after`              | `+0x18` | i16 | 0 |
| 19 (`0x80000`)   | `min_line_extent`          | `+0x1A` | i16 | 0 |
| 20 (`0x100000`)  | `left_indent`              | `+0x1C` | i16 | 0 |
| 21 (`0x200000`)  | `right_indent`             | `+0x1E` | i16 | 0 |
| 22 (`0x400000`)  | `first_line_indent`        | `+0x20` | i16 | 0 |
| 23 (`0x800000`)  | `tab_interval`             | `+0x22` | i16 | `0x48` when `text_base_or_mode & 1 == 0`; `0x2C6` when set |
| 24 (`0x1000000`) | `edge_metric_flags` (3-byte raw read) | `+0x24` | u16 | 0 |
| 25 (`0x2000000`) | `inline_run_count`         | `+0x27` | i16 | 0 |

Every gated value (except `edge_metric_flags`) is a self-describing
length-encoded varint: low bit 0 → byte form (`(b>>1) - 0x40`),
low bit 1 → word form (`(w>>1) + 0xC000`). `text_base_or_mode`
follows the same scheme as `text_start_index` (4-byte form when the
selector bit is set).

**Inline runs** (after the header): if `inline_run_count > 0`, the
trailing loop writes `inline_run_count × 4-byte` entries at
`local_120 + 0x29 + 4*N` (stride 4). Each entry is
`[offset_flags: varint u16][aux: varint u16 only when bit 0x4000 of
offset_flags is set]`. The high bit `0x4000` of `offset_flags` is
cleared after the aux read.

**Until either a known-good chunk capture or RE of all 50+ derived
fields lands**, pushing 0xBF chunks creates more harm than good.
The server currently leaves selector `0x15` as ack-only `0x87` —
HfcNear retries ~6× (~6 s) then `fMVSetAddress` returns 0, the pane
stays blank, no error dialog.

**Next-step RE targets** (when work resumes):

1. Map `MVBuildTextItem`'s prep block (lines after `MVScaleTextMetrics` call):
   what does each `local_38..local_2a` capture from chunk content?
   These directly drive the do-while loop's exit conditions.
2. Trace `MVTextLayoutFSM`'s state machine — the loop body sets
   `local_4c` to 1..5 based on lp + chunk state.  Find the path that
   returns 5 from chunk content alone (without lp state from a real
   prior title body).
3. Locate `local_120[0x10]`'s real provenance — if the trailing
   records loop is the only writer and the records are themselves
   encoded structures with sub-fields, decode their schema too.

### lp table descriptors

`lpMVNew` initializes four layout-pool descriptors for the viewer via
`MVInitViewerLayoutPools @ 0x7E889990` (called from `0x7E882597`):

| Offset | Record size | Purpose | Init function |
|-------:|-----------:|---------|---------------|
| `lp+0xd8` | 0x26 (38 B) | Linked layout-slot table | `MVPoolInit` (with free-list) |
| `lp+0xee` | 0x47 (71 B) | Item-record pool | `MVPoolAllocBuffer` |
| `lp+0xfe` | 0x1e (30 B) | Auxiliary layout-record pool | `MVPoolAllocBuffer` |
| `lp+0x10e` | 0x14 (20 B) | Run/rectangle pool | `MVPoolAllocBuffer` |

Each descriptor is 0x16 bytes:
- `+0x00` to `+0x03`: ?
- `+0x04`: HGLOBAL handle (`*(HGLOBAL *)(table + 4)`)
- `+0x08`: locked pointer (`*(LPVOID *)(table + 8)`)
- `+0x0c`: u16 count
- `+0x0e`: u16 capacity
- `+0x10`: u16 free-list head (-1 if empty; `MVPoolAcquireEntry`'s entry point)
- `+0x12`: u16 list link
- `+0x14`: u16 list link

`MVPoolAllocBuffer(table, record_size)` sets `table+4 = GlobalAlloc(GMEM_MOVEABLE
| GMEM_ZEROINIT, record_size * 4)` and `table+0xc = 0`, `table+0xe = 4`.
`MVPoolEnsureCapacity` is the GlobalReAlloc-based expander.

### Server implications

- Selector `0x15` (HfcNear) — push opcode `0xBF` chunk on the type-0
  subscription. HfcNear's retry loop drives consumption synchronously
  via `MVPumpHfcContentNotifications`; no pump thread needed for type 0 even though
  `param_3 = 0` to `MVAsyncNotifyDispatch` skips the threaded pump.
- Selectors `0x06` / `0x07` — push op-code 4 frame on the type-3
  subscription. Type 3 has a real pump thread (`MVAsyncSubscriberWorkerPump`) that
  reads chunks asynchronously and dispatches via `NotificationType3_DispatchRecord`.
- All five subscribe calls need their `+0x44` slot non-zero for the
  master flag (§6a).
- Type-0 reply must be `0x87 0x88` (iterator) so MPC's Execute hands
  back a readable iface that chunk-pushes can attach to. Same for
  type-3.

### 6b.2. ConvertHashToVa (selector `0x06`)

`MVTTL14C!vaConvertHash @ 0x7E841E9A` (export ordinal 58). Cache-miss
fallback issued by `vaConvertHash` itself — the function loops on the
kind-1 cache, fires selector `0x06` every 4000 ms while waiting up
to 30 000 ms for the answer to land via NotificationType3 op-code 4.

#### Request

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `titleSlot` — `titleState[2]` |
| `0x03` | 4 LE | `contextHash` — caller-supplied hash key (`0` is rejected client-side, never reaches the wire) |

#### Reply

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x87` | 0 | End of static section |

No dynamic. The client submits the request, immediately releases the
reply object without binding any recv slot, and re-checks the kind-1
cache. The server's actual answer lands on the type-3 subscription
iterator as an op-code 4 frame (kind=1) — see `Op-code 4 payload`
above.

#### Server obligations

1. Acknowledge selector `0x06` with `0x87` (any timing).
2. Push a NotificationType3 op-code 4 frame on the type-3 subscription
   iterator with `kind=1`, `title_byte`, `hash`, `va`. The cache pump
   re-runs the kind-1 lookup `(title_byte, hash@+4)` and returns
   `va@+8` to the calling `vaConvertHash`. With a real va the engine
   resumes its render path; without one, `vaConvertHash` times out
   after 30 s and returns `0xFFFFFFFF`.

### 6b.3. ConvertTopicToVa (selector `0x07`)

`MVTTL14C!vaConvertTopicNumber @ 0x7E841FCF` (export ordinal 59).
Identical request/reply shape to `0x06`; the cache, kind, and
notification dispatch differ.

#### Request

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `titleSlot` — `titleState[2]` |
| `0x03` | 4 LE | `topicNumber` — topic ordinal in the title's topic space |

#### Reply

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x87` | 0 | End of static section |

#### Server obligations

1. Acknowledge selector `0x07` with `0x87`.
2. Push NotificationType3 op-code 4 with `kind=0`, `title_byte`,
   `topic_no`, `va`, `addr`. The kind-0 cache lookup
   `(title_byte, topic_no@+0xC)` returns `(va@+4, addr@+8)`; the
   client returns the va to its caller (typically
   `MVCL14N!fMVSetAddress` resolving an authored topic reference).

`addrConvertTopicNumber @ 0x7E841CC9` and `addrConvertContextString @
0x7E841CE8` are thin wrappers that share the same selector `0x07` /
`0x06` request path; their callers consume the cached `addr` field
instead of the `va` field.

### 6b.4. LoadTopicHighlights (selector `0x10`)

`MVTTL14C!HighlightsInTopic @ 0x7E841526` (export ordinal 28). Unlike
`0x06` / `0x07`, this selector is synchronous — the client binds a
dynamic-iterator reply slot and waits up to 30 000 ms via
`MVAwaitWireReply`.

#### Request

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `highlightContext` — low byte of the active highlight session id (`param_1 == 0` is rejected client-side) |
| `0x03` | 4 LE | `topicOrAddress` — topic token or address token, depending on caller |
| `0x88` | 0 | Recv: dynamic-iterator handle (consumed by `MVCopyDynamicReplyStreamBytes` after the wait) |

#### Reply

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x87` | 0 | End of static section |
| `0x88` | var | Dynamic stream — highlight blob (see below) |

#### Highlight blob layout

`MVCopyDynamicReplyStreamBytes` returns a 32-bit-aligned movable
HGLOBAL with the iterator's bytes verbatim. Per
`docs/medview-service-contract.md`:

```
+0x00  bytes[8]                    opaque header (ignored on stock paths)
+0x08  u32 highlightCount
+0x0C  highlightCount * 13 B       repeated entry:
                                     +0  u32 anchorToken
                                     +4  u32 aux0
                                     +8  u32 aux1
                                     +12 u8  spanOrCount
```

Empty result is a zero-byte stream (or `highlightCount=0`); the
client returns NULL and the engine renders the topic without
highlights.

## 6c. Baggage (HFS file access, selectors `0x1A` / `0x1B` / `0x1C`)

MVTTL14C exports a 7-function Baggage API (ordinals 15-22) that
routes to either a local Win16 `_lopen` file handle or an HFS
("Hierarchical File System") handle opened over the wire:

| Export | Addr | Wire? | Wire selector |
|--------|------|------|---|
| `BaggageOpen` | `0x7E848205` | only when `param_3 != 0` (HFS mode) | delegates to `HfOpenHfs` |
| `HfOpenHfs` | `0x7E847656` | yes | **`0x1A`** |
| `BaggageRead` / `LcbReadHf` / `LcbReadHfProgressive` | `0x7E84818E` / `0x7E847C45` / `0x7E847DF6` | HFS mode only | **`0x1B`** |
| `BaggageClose` / `RcCloseHf` / `HfsCloseRemoteHandle` | `0x7E848023` / `0x7E847BAD` / `0x7E847BD8` | HFS mode only | **`0x1C`** |
| `BaggageSize` / `LcbSizeHf` | `0x7E848084` / `0x7E847F1E` | no (size cached at open) | — |
| `BaggageSeek` / `LSeekHf` / `LTellHf` | `0x7E848123` / `0x7E847ED1` / `0x7E848015` | no (position in-process) | — |
| `BaggageSeekRead` / `BaggageGetFile` | `0x7E80ED` / `0x7E82B8` | via Open+Seek+Read+Close | — |

The HFS mode byte is `(char)*(u32 *)(title + 0x88)` — the low byte of
TitleOpen reply byte 2. Zero → local-file path. Nonzero → HFS path
through the wire.

### `0x1A` HfOpenHfs — request / reply

Request (in order):

| Tag | Value |
|-----|-------|
| `0x01` | HFS mode byte (from title+0x88) |
| `0x04` | ASCIIZ filename + length |
| `0x01` | open mode byte (`2` in the observed call site) |
| `0x81` | Recv: byte — new HFS handle byte (stored at the returned 12-byte struct offset 0x08) |
| `0x83` | Recv: DWORD — file size (stored at offset 0x00; `LcbSizeHf` returns it) |

Reply: static ack + byte + DWORD; if byte is nonzero the client
allocates a 12-byte tracking struct and returns it. Zero byte declines
the open.

### `0x1B` LcbReadHf — request / reply

Request:

| Tag | Value |
|-----|-------|
| `0x01` | HFS handle byte (from the open struct's `+0x08`) |
| `0x03` | byte count requested |
| `0x03` | current read position (maintained client-side) |
| `0x81` | Recv: byte — status (0 on success) |

Reply: `0x81 <status> 0x87 0x86 <bytes>` — bit-identical to DIRSRV
`GetShabby` (`build_get_shabby_reply_payload` in
`services/dirsrv.py`) except for the status width (`0x81` byte here,
`0x83` dword there). The `0x86` (`TAG_DYNAMIC_COMPLETE_SIGNAL`) wakes
`LcbReadHf @ 0x7E847C45`'s `Wait` on slot 0x24, then
`reply_iface->m0x1c(&iter)` → `iter->m0x10()=length` →
`iter->m0xC()=ptr` is MPCCL's chunk-walker over the single-shot
blob — NOT a `0x88` stream-end iterator. Position advances by the
returned length. Standard fragmentation applies (>1024 B requires
chunking through `build_service_packet`).

### `0x1C` HfCloseHf — request / reply

Request:

| Tag | Value |
|-----|-------|
| `0x01` | HFS handle byte |

Reply: static ack. Client immediately frees the local tracking struct.

### Bitmap baggage names: engine-synthesised `|bm%d`

Filenames the case-3 layout walker requests are not on disk — they
are synthesised at `MVCL14N!MVRequestBaggageBitmap @ 0x7E886980` via
`wsprintfA(&local_1c, "|bm%d", index)` (format string at
`0x7E8997E0`). The bitmap index comes from the engine's layout
descriptor (zero-fills out of our synthetic `0xBF` chunk content,
giving index `0`).

Each request fires twice from the same call:

1. First attempt: `&local_1c` = `"|bm0\0"` (5-byte var, tag length
   `0x85`).
2. On reply byte = 0 the client sets `local_6 = 0x3EC` and the retry
   path at `0x7E886A22` calls `hMVBaggageOpen(..., local_1b, ...)`
   where `local_1b = &local_1c + 1` — so the second wire request
   ships `"bm0\0"` (4-byte var, tag length `0x84`) from the same
   stack buffer.

Treat the leading `|` as disambiguation noise; the canonical name
the engine wants is `bm<N>`. Accepting either form advances the
state machine.

### Synthetic kind=5 minimum-viable bm0 container

A 1-byte `kind=0` read reply fails graceful (parser returns -2,
NULL slot) but `MVPaintBitmapRecord @ 0x7E887180` re-fires `MVRequestBaggageBitmap`
on the next windows-repaint heartbeat — the engine retries `bm0`
every ~2 minutes until the bitmap slot is non-NULL. To break the
loop without authored bitmap bytes, ship a minimum-viable kind=5
container that survives `MVDecodeBitmapBaggage @ 0x7E887A40`'s parser and
`MVCreateHbitmapFromBaggage @ 0x7E886FB0`'s `CreateBitmap(1, 1, 1, 1, ...)` call.

38-byte payload (open-size = 38, single read at offset 0):

| Offset | Bytes | Field |
|--------|-------|-------|
| 0x00 | `00 00` | container reserved (unread by `MVPickBestBitmapVariant`) |
| 0x02 | `01 00` | bitmap count = 1 (single-bitmap path; skips DPI scoring `MVScoreBitmapVariant`) |
| 0x04 | `08 00 00 00` | offset to bitmap[0] header = 8 |
| 0x08 | `05` | kind = 5 (clears `local_50 < 5` gate) |
| 0x09 | `00` | compression = raw (no `MVDecodeRleStream` RLE / `MVDecodeLzssBitmapPayload`) |
| 0x0a | `00 00` | skip-int #1 (low-bit-clear narrow form) |
| 0x0c | `00 00` | skip-int #2 (low-bit-clear narrow form) |
| 0x0e | `02` | byte-narrow varint: planes = 1 |
| 0x0f | `02` | byte-narrow varint: bpp = 1 |
| 0x10 | `02 00` | ushort-narrow varint: width = 1 |
| 0x12 | `02 00` | ushort-narrow varint: height = 1 |
| 0x14 | `00 00` | ushort-narrow varint: palette_count = 0 |
| 0x16 | `00 00` | ushort-narrow varint: _ = 0 |
| 0x18 | `04 00` | ushort-narrow varint: pixel_byte_count = 2 |
| 0x1a | `00 00` | ushort-narrow varint: trailer_size = 0 |
| 0x1c | `1c 00 00 00` | u32 pixel-data offset = 0x1c (rel. to bitmap start) |
| 0x20 | `1c 00 00 00` | u32 trailer offset (irrelevant; trailer_size=0) |
| 0x24 | `00 00` | 1x1 monochrome pixel + WORD-alignment pad |

The varint encoding has two widths inside the kind=5 branch:

- Varints 1-2 (planes, bpp) read as **bytes** via
  `(byte)*puVar >> 1`. Narrow form is `(v << 1) | 0` in 1 byte.
- Varints 3-8 (width, height, palette_count, _, pixel_byte_count,
  trailer_size) read as **ushorts** via `(ushort)*puVar >> 1`.
  Narrow form is `(v << 1) | 0` in 2 bytes (ushort little-endian).
- Wide form (low bit set) consumes one extra byte/word and shifts
  the full value right 1 — not used here since all values fit narrow.

`MVDecodeBitmapBaggage` allocates `palette_count*4 + trailer_size + 0x3a +
pixel_byte_count = 0 + 0 + 58 + 2 = 60 bytes` for its parsed output
struct, copies a 0x3a-byte snapshot of stack locals (width at +0x16,
height at +0x1a, planes at +0x1e, bpp at +0x20), memcpys palette
(0 bytes when palette_count=0), then memcpys 2 pixel bytes at
+0x3a. `MVCreateHbitmapFromBaggage` then resolves to `CreateBitmap(1, 1, 1, 1,
&output[0x3a])`. With a valid HBITMAP, `MVPaintBitmapRecord`'s paint
stops re-firing `MVRequestBaggageBitmap` and the 2-minute retry pattern
breaks.

Authored bitmaps would override this — Blackbird's import dialog
runs the `MVDecodeRleStream` / `MVDecodeLzssBitmapPayload` compressor at ingestion
time to emit kind=5/6 wire-ready bytes inline in the .ttl
storage, but the on-disk form retains a `BM`-prefixed file header
that the release-time PUBLISH.DLL strips before shipping. Until
that release pipeline is implemented, the synthetic container is
the only path to a non-NULL bitmap slot.

### When does the client call these?

Empirically, post-`33a0746` (case-3 cache push lands and the layout
walker survives) MSN Today fires `hfs_open` for `bm0` immediately
after the `0x06` / `0x15` cache pushes complete — see the bitmap
provenance subsection above. The two earlier callers `MVGroupLoad`
(ordinal 15) and `MVFileIOProcOpen / 7e886980 / 7e886b80` in MVCL14N
trigger from authored content referencing baggage by filename during
render. Until the engine has a non-empty layout cache it never reaches
those callers, which is why a caption-only body never received
`0x1A/0x1B/0x1C`.

## 6d. Contract-named selectors (byte-level framing)

Per-selector wire layouts for the selectors named in
`docs/medview-service-contract.md` and resolved against the MVTTL14C
stubs. Tag widths follow the request-builder vtable convention
established in §3 / §4 / §5:

| vtable slot | Operation | Wire tag |
|------------:|-----------|---------:|
| `+0x18` | bind recv-DWORD | `0x83` |
| `+0x1c` | bind recv-WORD | `0x82` |
| `+0x20` | bind recv-BYTE | `0x81` |
| `+0x14` | bind dynamic-iterator recv | `0x84` (handle) |
| `+0x24` | send variable-length data | `0x04` |
| `+0x28` | send DWORD | `0x03` |
| `+0x2c` | send WORD | `0x02` |
| `+0x30` | send BYTE | `0x01` |
| `+0x40` | enable dynamic-stream recv | `0x88` (or `0x86` for single-shot) |
| `+0x48` | submit | — |
| `+0x08` | release | — |
| `+0x0c` | (proxy vtable) create selector-N request builder | — |

Reply tags: server emits the recv tags above plus `0x87` end-static
and (when a dynamic body is bound) `0x86` for single-shot completion
or `0x88` for stream-end iterator (same rule as §6a).

### 6d.1. UnsubscribeNotifications (selector `0x18`)

`MVTTL14C!MVAsyncSubscriberUnsubscribe @ 0x7E844FE3` (called from
subscriber teardown when `skipWireUnsubscribe == 0`).

Request: `0x01 notificationType` (1 byte, value `0`–`4` matching the
type set up by §6a). Reply: `0x87` only — no static or dynamic body.
The client immediately releases the ack handle.

### 6d.2. CloseTitle (selector `0x02`)

`MVTTL14C!TitleClose @ 0x7E842C3A`. Sent only when the local title
refcount drops to 1; the function is otherwise local-only (decrements
the refcount and runs `MVReleaseTitleState`).

Request: `0x01 titleSlot` (1 byte, low byte of `titleState[1]`).
Reply: `0x87`. Client waits 30 s via `MVAwaitWireReply`.

### 6d.3. QueryTopics (selector `0x04`)

`MVTTL14C!TitleQuery @ 0x7E841653`. Variable-shape request driven by
`queryFlags`; reply binds two synchronous DWORDs plus optional
dynamic streams.

Request:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `titleSlot` (`titleState[2]`) |
| `0x02` | 2 | `queryClass` (caller-supplied) |
| `0x04` | var | `primaryText` ASCIIZ |
| `0x01` | 1 | `queryFlags` — bit `0x01` HasSecondaryText, `0x02` HasSourceGroup, `0x04` HasAuxRequest40 (forced when `param_7 != 0`) |
| `0x04` | var | `secondaryText` (only if flag `0x01`) |
| `0x04` | 0x40 | `sourceGroupBlob` (when flag `0x02`; encoded as `(ptr, 0x40)` plus a follow-on `(ptr+0x1e, *(u32 *)(ptr+4))` chunk) |
| `0x02` | 2 | `queryMode` (caller-supplied) |
| `0x04` | 0x40 | `auxRequest40` (when flag `0x04`) |
| `0x81` | 0 | recv: `highlightContext` byte |
| `0x83` | 0 | recv: `logicalCount` DWORD |
| `0x83` | 0 | recv: `secondaryResult` DWORD |
| `0x84` | 0 | recv dynamic-iterator: `auxReply` (only when flag `0x04`) |
| `0x84` | 0 | recv dynamic-iterator: `sideband12` (always; client copies first 12 bytes) |

Reply:

| Tag | Bytes | Role |
|-----|-------|------|
| `0x81` | 1 | `highlightContext` — nonzero opens a highlight-aware session |
| `0x83` | 4 LE | `logicalCount` |
| `0x83` | 4 LE | `secondaryResult` (often 0) |
| `0x87` | 0 | End of static |
| `0x84` | var | (optional) `auxReply` iterator for the `auxRequest40` flag path |
| `0x84` | 12 | `sideband12` (verbatim 12 bytes copied to caller) |

### 6d.4. ConvertAddressToVa (selector `0x05`)

`MVTTL14C!vaConvertAddr @ 0x7E841D64`. Same poll-loop pattern as
§6b.2 / §6b.3: cache-miss fallback on the kind-2 cache, fires every
4000 ms, totals 30 000 ms, real answer arrives via NotificationType3
op-code 4 with `kind=2`.

Request: `0x01 titleSlot` (1 byte) + `0x03 addrToken` (4 LE; client
rejects `0xFFFFFFFF` before fire). Reply: `0x87`.

### 6d.5. WordWheelService (selectors `0x08`–`0x0F`)

#### 6d.5.1. QueryWordWheel (selector `0x08`)

`MVTTL14C!WordWheelQuery @ 0x7E849E99`.

Request: `0x01 titleSlot` (1 B) + `0x02 queryMode` (2 LE) +
`0x04 queryText` (ASCIIZ) + `0x82 (recv-word) status` + `+0x40`
enable dynamic.

Reply: `0x82 status` + `0x87` + `0x86`/`0x88` (single-shot complete or
stream end). Client acquires the iterator handle then releases
without consuming bytes.

#### 6d.5.2. OpenWordWheel (selector `0x09`)

`MVTTL14C!WordWheelOpenTitle @ 0x7E849328`.

Request: `0x01 titleSlot` (1 B) + `0x04 titleName` (ASCIIZ) +
`0x81 (recv-byte) wordWheelId` + `0x83 (recv-dword) itemCount`.

Reply: `0x81 wordWheelId` (nonzero) + `0x83 itemCount` + `0x87`.
Client caches `wordWheelId` keyed by `(titleByte, titleName)` and
treats `wordWheelId=0` as failure.

#### 6d.5.3. CloseWordWheel (selector `0x0A`)

`MVTTL14C!WordWheelClose @ 0x7E8495B1`.

Request: `0x01 wordWheelId` (1 B). Reply: `0x87` ack only.

#### 6d.5.4. ResolveWordWheelPrefix (selector `0x0B`)

`MVTTL14C!WordWheelPrefix @ 0x7E849935`.

Request: `0x01 wordWheelId` + `0x04 prefixText` (ASCIIZ) +
`0x83 (recv-dword) prefixResult`. Reply: `0x83 prefixResult` +
`0x87`. Client returns the DWORD synchronously.

#### 6d.5.5. LookupWordWheelEntry (selector `0x0C`)

`MVTTL14C!WordWheelLookup @ 0x7E849658`. Synchronous request that
re-fires every 20 outer loop iterations while polling
NotificationType1 cache.

Request: `0x01 wordWheelId` + `0x03 ordinal` + `0x03 outputLimit`.
Reply: `0x87` ack only — actual string arrives on the
NotificationType1 stream and is consumed by `WordWheelCache_FindEntry`.

#### 6d.5.6. CountKeyMatches (selector `0x0D`)

`MVTTL14C!KeyIndexGetCount @ 0x7E849A27`.

Request: `0x01 wordWheelId` + `0x04 keyText` (ASCIIZ) +
`0x82 (recv-word) matchCount`. Reply: `0x82 matchCount` + `0x87`.

#### 6d.5.7. ReadKeyAddresses (selector `0x0E`)

`MVTTL14C!KeyIndexGetAddrs @ 0x7E849B6E`. Returns up to
`maxCount` u32 addresses through a dynamic-stream iterator.

Request: `0x01 wordWheelId` + `0x04 keyText` (ASCIIZ) +
`0x02 startIndex` + `0x02 maxCount` + `+0x40` enable dynamic.

Reply: `0x87` + dynamic stream. Client uses iterator `+0x10`
(byte size) and `+0x0c` (data ptr) to copy `min(streamSize,
maxCount * 4)` bytes into the caller buffer. Returns the byte count
copied (NOT element count).

#### 6d.5.8. SetKeyCountHint (selector `0x0F`)

`MVTTL14C!fKeyIndexSetCount @ 0x7E849D8A`.

Request: `0x01 wordWheelId` + `0x04 keyText` (ASCIIZ) +
`0x02 countHint` + `0x81 (recv-byte) success`. Reply:
`0x81 success` + `0x87`.

### 6d.6. AddressHighlight cluster (selectors `0x11`–`0x13`)

#### 6d.6.1. FindHighlightAddress (selector `0x11`)

`MVTTL14C!addrSearchHighlight @ 0x7E8413FE`. Synchronous DWORD
return after a `MVAwaitWireReply` (30 s).

Request: `0x01 highlightContext` + `0x03 searchKey0` +
`0x03 searchKey1` + `0x83 (recv-dword) addressToken`.
Reply: `0x83 addressToken` + `0x87`. The client also runs an
internal fallback through `HighlightLookup` (selector `0x13`) when
`addressToken` comes back negative.

#### 6d.6.2. ReleaseHighlightContext (selector `0x12`)

`MVTTL14C!HighlightDestroy @ 0x7E841180`. Sent only when the local
highlight-context refcount drops to 0.

Request: `0x01 highlightContext` (1 B). Reply: `0x87` ack only.

#### 6d.6.3. RefreshHighlightAddress (selector `0x13`)

`MVTTL14C!HighlightLookup @ 0x7E841235`. Re-fires every 20 outer
loop iterations while polling NotificationType2 via
`HighlightCache_FindResult`. Total wait 0x40 iterations × pump
window.

Request: `0x01 highlightContext` + `0x03 highlightId`. Reply:
`0x87` ack only — answer arrives on NotificationType2.

### 6d.7. FetchAdjacentTopic (selector `0x16`)

`MVTTL14C!HfcNextPrevHfc @ 0x7E845ABB`. Sibling of `vaResolve`
(§6b.1) for next/previous topic navigation against the per-title
HfcNear cache; pumps `MVPumpHfcContentNotifications` between fires.

Request: `0x01 titleSlot` (`titleState[2]`) +
`0x03 currentToken` (the va of the current topic) +
`0x01 direction` (`1` = next, `0` = previous; encoded as
`'\x01' - (param_2 == 0)`).

Reply: `0x87` ack only — the actual topic body arrives as a
NotificationType0 record (`0xBF` / `0xA5` / `0x37` opcodes; same
inserter as §6b.1).

### 6d.8. GetRemoteFsError (selector `0x1D`)

`MVTTL14C!RcGetFSError @ 0x7E847F2B`. Cheapest selector — single
WORD recv.

Request: `0x82 (recv-word) fsError` only (no send tags, no
`titleSlot`). Client-side default of `8` is left in place on any
failure path. Reply: `0x82 fsError` + `0x87`. Client returns the
WORD as the last MEDVIEW filesystem error.

## 6e. Dead selectors

The following IID-bound selectors have **zero client call sites**
in `MVTTL14C.DLL` (the only binary that holds the discovered MEDVIEW
proxy `DAT_7e84e2f8`). Verified by walking every `CALL [EAX + 0xc]`
instance whose `EAX` was loaded from `DAT_7e84e2f8` — 30 unique
selectors fire on the wire (`0x00`–`0x13`, `0x15`–`0x18`,
`0x1A`–`0x1F`); the rest are dead.

| Selector | IID idx | XX | Status |
|----------|--------:|---:|--------|
| `0x14`   |      19 | `91` | dead — no caller |
| `0x19`   |      24 | `B2` | dead — no caller |
| `0x20`   |      31 | `C0` | dead — no caller |
| `0x21`   |      32 | `C1` | dead — no caller |
| `0x22`   |      33 | `C2` | dead — no caller |
| `0x23`   |      34 | `C3` | dead — no caller |
| `0x24`   |      35 | `C4` | dead — no caller |
| `0x25`   |      36 | `C5` | dead — no caller |
| `0x26`   |      37 | `C6` | dead — no caller |
| `0x27`   |      38 | `C7` | dead — no caller |
| `0x28`   |      39 | `C8` | dead — no caller |
| `0x29`   |      40 | `C9` | dead — no caller |
| `0x2A`   |      41 | `CA` | dead — no caller |

The IIDs still appear in `DAT_7E84C1B0` (MEDVIEW pre-allocates 42
slots for forward compatibility), so server discovery must still
return all 42 records — just nothing routes through them.

A server is free to advertise these selectors with any handler or to
respond `0x87` if accidentally reached; the stock client never sends
them.

---

## 7. Post-TitleOpen calls made by MOSVIEW

`MOSVIEW!OpenMediaTitleSession @ 0x7F3C61CE` enumerates the cached body
via `lMVTitleGetInfo` (MVCL14N wrapper around `TitleGetInfo`) and
caches the records in the per-session state struct:

| info_kind | Section | Stride | Cached at | Count at |
|-----------|---------|--------|-----------|----------|
| **7** | 1 | 0x2B (43) | state+0x3c | state+0x38 |
| **8** | 2 | 0x1F (31) | state+0x44 | state+0x40 |
| **6** | 3 | 0x98 (152) | state+0x4c | state+0x48 |
| **4** | 8 | varlen × N | state+0x54 | state+0x50 |
| **1** | 4 | varlen | state+0x58 (UnquoteCommandArgument) | — |
| **66** (0x42) | — | varlen | state+0x5c | — |

The 152-byte section-3 records are the **page-layout descriptors**
that the TOC / navigation views resolve. Field layout unknown without
RE'ing the consumer, but every authored page in the project tree (per
the user's Blackbird hierarchy: `Project → Title → Section → Pages`)
contributes one 152-byte record here.

Before the first TitleGetInfo it also calls `MVSetKerningBoundary`,
`hMVSetFontTable`, `MVSetFileSystem`, `vaMVGetContents` — all MVCL14N
engine calls with no direct wire traffic at this stage.

### 7.1 Render-trigger chain

After `OpenMediaTitleSession`, MOSVIEW navigates to the requested
selector via the chain:

```
NavigateViewerSelection @ 0x7F3C4528
  vaMVGetContents() / vaMVConvertHash()  → iVar6 = va
  if iVar6 == -1 AND hideOnFailure: ShowWindow(0); return
  Allocate 0x40-byte selector descriptor: [va, session_id, ...]
  → NavigateMosViewPane(pane_state, descriptor)
    Copies descriptor into per-pane state (offsets 0..0x40)
    MVCL14N!fMVSetAddress(title_ctx, va, ...)
      ↓ triggers HfcNear cache lookup → wire 0x06/0x15 cache pushes
      ↓ engine receives 0xBF chunk for va → MVParseLayoutChunk walker
    Performs SetWindowPos / InvalidateRect / UpdateWindow
```

The render is gated on `vaMVGetContents()` (which reads `title+0x8c` —
our TitleOpen reply DWORD 1) returning anything other than `-1`. We
currently ship `0`, which passes the gate; the engine then fires
`fMVSetAddress(title, 0, ...)` and runs the layout walker against the
0xBF chunk we push for va=0.

### 7.2 What populates a visible pane

The case-3 walker (`MVCL14N!MVBuildLayoutLine`) creates a CSection cell from
the 0xBF chunk's bitmap reference. **The cell only renders content if
its bitmap has a non-empty trailer** — the trailer carries `N × 15-byte`
records describing the section's children (heading, body text, lists,
embedded sub-bitmaps). Each child becomes a child cell with tag 4
(CElementData) or 7 (text/link), and case-4 / case-7 / MVPaintBitmapRecord
paint the actual visible content.

With our current `_BM0_CONTAINER` (kind=5, 1×1 mono, **trailer_size=0**),
the case-3 cell has zero children → blank pane. Populating the trailer
with real CElementData/text records is the next forward step toward
visible page content.

See `project_medview_page_render_chain.md` (memory) for the full
call-graph trace and the 15-byte child-record field layout.

---

## 8. Surfaces MSN Today does NOT exercise at startup

- **Baggage** (`BaggageOpen/Read/GetFile`): if an authored BDF references
  baggage, the client issues `MVBaggageAsync*` calls against the baggage
  selectors. A "not found" (empty file) reply is enough to let authoring
  iterate. No known MOSVIEW startup path blocks on baggage.
- **DownloadPicture / GetDownloadStatus / GetPictureInfo** — picture
  selectors (ordinals `1-5`). Not on the initial-open path.
- **WordWheel** (`WordWheelOpenTitle / Lookup / Query`) — Find UI only,
  not on the initial-open path.

These selectors can be filled in later when a feature calls for them;
the MSN Today open path doesn't require any of them.

---

## 9. Minimum wire behaviour required by MSN Today

Compiled from the client-side reads elsewhere in this document. Anything
that emits these bytes in this order will get MSN Today past
"service temporarily unavailable":

1. On pipe-open: a discovery block with the 42 IIDs from §2.1.
2. Selector `0x1F` (handshake, §3): static `0x83` = `1`, `0x87`. No
   dynamic.
3. Selector `0x1E` (TitlePreNotify, §6): static `0x87`. No dynamic.
4. Selector `0x17` (SubscribeNotification, §6a): `0x87` end-static
   + `0x86` dynamic-complete with empty blob. All 5 invocations
   (types 0..4) need this — the master flag `DAT_7e84e2fc` won't set
   unless every subscriber's `+0x28` reply-iface slot is non-NULL,
   and without that flag every cache-miss retry loop in MVTTL14C
   bails before firing the `0x06`/`0x07`/`0x10`/`0x15` fallback
   selectors. Wire request descriptor is `0x85` (dynamic-recv);
   `0x86` is what fires `SignalRequestCompletion`.
5. Selector `0x01` (TitleOpen, §4): static `0x81 01 0x81 01 0x83 0 0x83
   0 0x83 0 0x83 <chk1> 0x83 <chk2> 0x87`, then `0x86` + 9-section
   title body (§4.4). Even an empty-but-valid body carries the title
   name in section 4 (raw blob, info_kind=1) — makes MSN Today surface
   a real label instead of `"Unknown Title Name"`.
6. Selector `0x03` (TitleGetInfo, §5): static `0x83 00000000 0x87 0x86`
   + empty dynamic.

Everything else can safely be ignored (empty reply, no crash) for the
MSN Today open path.

---

## 10. Paint-loop / layout-walker call graph

End-to-end trace from page address change to BitBlt, recovered from
static decompilation of `MVCL14N.DLL` 2026-04-29.

```
fMVSetAddress(title, va, ...)         (sets title+0xc2 = va, drives HfcNear)
  └─> HfcNear (HfcNear)          (per-title cache lookup; type-0 0xBF
                                       cache-fill via HfcCache_InsertOrdered → title+4 tree)
fMVRealize(title, rect, perr)         (page layout entry; @0x7E883890)
  ├─ guard: title+0xc2 != -1          (va must be set)
  ├─ guard: InterlockedExchange(title+0xce, 1) == 0  (re-entry)
  ├─ MVRealizeView(title, hdc, 0, perr)
  │   ├─ MVHfcNear(hdc, va, ...)      (cache lookup → BF chunk HGLOBAL)
  │   ├─ MVParseLayoutChunk(title, BF_chunk, 0, 1, 0)
  │   │   ├─ MVPoolAcquireEntry(...)        (allocates row index in title+0xd8 table)
  │   │   ├─ row record at title+0xe0[+4 + row_idx*0x2a]:
  │   │   │     +0x00 HGLOBAL slot table (set later)
  │   │   │     +0x06 HGLOBAL name buffer (= BF chunk)
  │   │   │     +0x0a u32 va_key (MVChunkHandleGetField08)
  │   │   │     +0x0e u16 y-offset
  │   │   │     +0x12 / +0x14 layout extents (set after MVWalkLayoutSlots returns)
  │   │   │     +0x16 u16 slot count
  │   │   │     +0x1e u32 ascender
  │   │   │     +0x22 u32 descender
  │   │   ├─ varint at name_buf[+0x26] decoded as chunk_tag (MVDecodeTopicItemPrefix)
  │   │   ├─ MVWalkLayoutSlots(title, row_record, name_buf+0x26, ...)
  │   │   │     switch chunk_tag:
  │   │   │       case 1, 0x20 → MVBuildTextItem (text-row chunk; produces slot tag 1)
  │   │   │       case 3, 0x22 → MVBuildLayoutLine (cell+children; bm0 baggage)
  │   │   │       case 4, 0x23 → MVBuildColumnLayoutItem
  │   │   │       case 5, 0x24 → MVBuildEmbeddedWindowItem
  │   │   ├─ allocates HGLOBAL of (slot_count*0x47+1) bytes
  │   │   ├─ memcpy slot scratch (title+0xf6) → row's HGLOBAL
  │   │   └─ returns row_idx
  │   └─ MVSeekVerticalLayoutSlots(...)  recursively fetch prev/next chunks
  │                                      via MVDispatchHfcNextPrevHfc → fill page rows
  └─ MVTitleNotifyLayout(...)         (notify host; window invalidates)

WM_PAINT:
fMVPaint → MVPaneOnPaint(title, hdc)   (paint walker; @0x7E889B70)
  ├─ guard: title+0x48 < title+0x58   (viewport y range valid)
  ├─ guard: title+0xea != -1          (head row idx; -1 means no rows)
  ├─ row chain: title+0xea → row[+2 ushort next_idx] → ... → -1 sentinel
  └─ for each row:
       MVDispatchSlotPaint(title, row_idx, x_origin, y_top, …)
         (per-row dispatch; @0x7E891220)
         pcVar5 = row_slots + slot_idx*0x47
         switch (slot[0]):
           1 -> DrawTextSlot(title, name_buf+0x26+after_varint, slot, x, y, ...)
                 text drawer; reads BF chunk content past varint
           3 → MVPaintBitmapSlot(title, slot, x, y)
                 applies slot+0x41 style, computes x/y from slot deltas,
                 and uses slot+0x13 only for selection highlight
                 → MVPaintBitmapRecord(slot+0x39 HGLOBAL, title, x, y, highlight)
                       BitBlt/StretchBlt of parsed kind-5/6 bitmap, or
                       PlayMetaFile for kind=8 (mapmode 7/8 vector)
           4 → MVPaintRectangleSlot(title, slot, x, y, selectionHint)
                 outline pass only paints when slot[+0x39]&0xd4 == 0xc0;
                 selected/caller-hint pass fills a one-pixel-inset interior
           5 → MVPaintBorderSlot(title, slot, x, y)
                 border/rectangle drawer; slot+0x39 bit0 selects rectangle
                 mode, bits 1/2/3/4 select top/left/bottom/right sides,
                 bits 5..7 select style
           6 → MVPaintEmbeddedMediaSlot(title, slot, x, y)
                 forwards slot+0x39 HWND, slot+0x3d mediaKind, and
                 slot+0x41 HGLOBAL to MVRenderEmbeddedMedia
           7 → MVInvertRunHighlightLines(title, slot, x, y)
                 reads slot+0x1b HGLOBAL (run array), iterates 0x14-byte
                 entries from slot[+0x29]..slot[+0x2b] to MVInvertHighlightRect
```

### 10.1. Slot layout (0x47 bytes)

| Offset | Size | Purpose |
|-------:|-----:|---------|
| 0x00 | u8 | slot tag (1/3/4/5/6/7) — paint dispatch key |
| 0x01 | u32 | flags / state (low bits via MVBuildLayoutLine) |
| 0x05 | i16 | delta_x (cell-relative) |
| 0x07 | i16 | delta_y (cell-relative) |
| 0x09 | i16 | (parent-cell only) inherited y_top from trailer header |
| 0x0b | i16 | extent_x |
| 0x0d | i16 | extent_y |
| 0x0f | u32 | per-cell highlight key (`title+0x130` increments) |
| 0x13 | u32 | va — `0xFFFFFFFF` sentinel for tag-0x8A children; for non-0x8A children copied from trailer record bytes 11..14. **Used only by MVPaintBitmapSlot to compute highlight flag.** Not a wire-cache key. |
| 0x1b | HGLOBAL | (tag-7 only) run-array HGLOBAL for MVInvertRunHighlightLines |
| 0x29..0x2b | i16,i16 | (tag-7) run-array start/end indices |
| 0x2d | u32 | x_left (mapped to col / page coord) |
| 0x31 | u32 | y_top |
| 0x35 | u32 | x_right |
| 0x39 | HGLOBAL or u32 | parent (tag 3): HGLOBAL of MVResolveBitmapForRun's bitmap render record (slot+0x39 = `pvVar5`); child (tag 4): bytes 0..1 = trailer record's tag word; child (tag 5): border flags; child (tag 6): HWND |
| 0x3b | HGLOBAL | (tag-4 child) shared trailer-tail HGLOBAL allocated in MVBuildLayoutLine: `[u16 nonbar_count][tail_size bytes]` |
| 0x3d | byte* / u32 | (tag 3) name_buf offset for caption / case 1 child rendering; (tag 6) mediaKind |
| 0x41 | i16 / HGLOBAL | parent cell-id passed to ApplyTextStyleToHdc; (tag 6) textHandle |
| 0x43 | i16 | first child slot idx |
| 0x45 | i16 | last child slot idx (exclusive) |

### 10.2. Bitmap kind byte enumeration (`MVDecodeBitmapBaggage @ 0x7E887A40`)

The first byte of the baggage blob is the `kind` discriminator; the
second byte is the `compression_mode`. The client dispatches:

| kind  | Effect | Notes |
|------:|--------|-------|
| 0..4  | Returns `-2` (caller maps to NULL slot → blank pane) | Sentinel for "unsupported kind". |
| 5     | Raster bitmap parse path | 9 sequential varints decode header + palette/data offsets, then DIB-shaped allocation of `palette_count*4 + trailer_size + 0x3A + pixel_bytes`. |
| 6     | Same path as kind 5 | Identical decoder branch (`5 ≤ kind < 7`). |
| 7     | Returns `-2` | Not handled. |
| 8     | Alternate bitmap path | Reads `lookup_count:varint`, two raw u16s, three more varints, two raw u32s; allocates a `0x42 + metadata_bytes` head + a separate `compressed_payload_bytes` HGLOBAL. |
| ≥ 9   | Returns `-2` | Not handled. |

The `compression_mode` byte (offset `+0x01`) only affects how pixel
bytes (kinds 5/6) or the compressed payload (kind 8) are decoded:

| compression_mode | Decoder | Source |
|-----------------:|---------|--------|
| 0 | Raw `MV_memcpy` of `pixel_byte_count` bytes | kind 5/6/8 |
| 1 | `MVDecodeRleStream @ 0x7E887FF0` | kind 5/6/8 |
| 2 | `MVDecodeLzssBitmapPayload @ 0x7E8970B0` | kind 5/6/8 |

All multi-byte varints in this decoder share the same self-describing
length-encoding scheme:

| Low bit of first byte | Form | Value |
|----------------------:|------|-------|
| 0 | `u7` byte | `(byte >> 1)` (no sign offset for the dimension/offset varints) — note the byte form does **not** apply the `-0x40` sign offset that `MVDecodePackedTextHeader` uses; here `(byte >> 1)` is the raw value |
| 1 | `u15` word | `(word >> 1)` (no sign offset) |

The discrepancy with `MVDecodePackedTextHeader`'s `(byte >> 1) - 0x40`
form is real — `MVDecodeBitmapBaggage`'s varints are unsigned. See
the inline branch at `0x7E887AC0..0x7E887B30` for the canonical
unsigned form, and `MVDecodePackedTextHeader @ 0x7E897AD0` for the
signed form.

### 10.2.1. Bitmap container trailer (parsed by MVCloneBaggageBytes → MVScaleBaggageHotspots)

The kind=5/6/8 raster's trailer bytes (the `trailer_size` block at the end
of the kind-5 header) decode as:

| Offset | Size | Field |
|-------:|-----:|-------|
| 0x00 | u8 | reserved (zero) |
| 0x01 | u16 | child_count |
| 0x03 | u32 | tail_size |
| 0x07 + 15*N | 15 bytes | child records (count = child_count) |
| 0x07 + 15*N | tail_size | tail bytes (referenced by non-0x8A children) |

### 10.3. Child record (15 bytes, in trailer)

| Offset | Size | Field |
|-------:|-----:|-------|
| 0x00 | u8 | tag (`0x8A` text/link, `0x01` CElementData, `0x07` other) |
| 0x01 | u8 | tag2 (used as second byte of slot+0x39 for tag-4 children) |
| 0x02 | u8 | flags |
| 0x03 | i16 | x_offset (DPI-scaled from src→dest in MVScaleBaggageHotspots) |
| 0x05 | i16 | y_offset |
| 0x07 | i16 | x_extent |
| 0x09 | i16 | y_extent |
| 0x0b | u32 | va — copied to slot+0x13 for non-0x8A children |

### 10.4. Why MSN Today paints blank

Two root causes, independent of any wire-cache key gate. Both must be
fixed for visible output:

1. **bm0 container is 1×1 monochrome.** `_build_bm0_container` produces a
   38-byte kind=5 raster with `width=1 height=1 trailer_size=0`. At paint
   time `MVPaintBitmapRecord` calls `BitBlt(hdc, x, y, 1, 1, …)` — one pixel.
   Invisible.
2. **trailer_size=0 → child records have no tail content.** Even with a
   real-sized bitmap and a child trailer, each non-0x8A child looks up its
   payload bytes at `tail_HGLOBAL[2 + offset_indexed_by_slot+0x39]`. With
   tail_size=0 there are no bytes to draw.

Fix: ship a kind=5 raster sized to the authored CBFrame (e.g. 640×480)
with a trailer carrying `child_count > 0` and `tail_size > 0`, plus a
populated tail block carrying CElementData strings / link offsets keyed by
each child's `[tag, tag2]` pair.

### 10.5. Rendering text via slot tag 1 (case-1 BF chunk)

For chunks whose `name_buf[0x26]` decodes to chunk_tag = 1 / 0x20,
`MVBuildTextItem` (case 1) creates slot tag 1 entries that paint via
`DrawTextSlot` reading text bytes **directly from the BF chunk content**.
This is the plain-text row path; complementary to case-3 (which paints
backdrop bitmaps).

#### Wire layout (128-byte type-0 0xBF chunk, case-1 form)

```
+0x00  0xBF                                cache opcode
+0x01  title_byte                          per-title routing
+0x02  name_size = 0x40 (LE u16)           memcpy length into entry
+0x04..0x0B  zero padding                  name_buf[0..7]
+0x0C  key (LE u32)                        HfcCache_DispatchContentNotification reads here
+0x10..0x29  zero padding                  name_buf[12..0x25]
+0x2A  0x01                                name_buf[0x26] — case-1 dispatch
+0x2B..0x2C  preamble length raw           narrow varint, decoded = 7
+0x2D..0x32  null TLV (6 bytes)            length=0, bitmap=0
+0x33  0xFF                                end-of-chunk control byte
+0x34..      ASCII text + NUL              up to 13 bytes (incl. NUL)
+...         zero padding to 0x44
+0x44..0x7F  60-byte content block         zeros (HGLOBAL slots NULL)
```

After the cache strips the 4-byte wire header, the entry stores
chunk[4..0x7F] at entry[0..0x7B]. So `entry+0x26` = `name_buf[0x26]`
= the case-dispatch byte, and the walker reads from there.

#### Preamble parser (`MVDecodeTopicItemPrefix`)

Reads from `entry+0x26`:
- byte 0: type tag (switched on by `MVWalkLayoutSlots`)
- bytes 1..2 (narrow) or 1..4 (wide): signed-int length value
  - narrow form (1-bit LSB clear): 2-byte LE u16, decoded `(raw>>1) - 0x4000`
  - wide form (LSB set): 4-byte LE u32, decoded `(raw>>1) - 0x40000000`
- For type tag > 0x10: additional 1-byte (narrow) or 2-byte (wide) varint at offset +5
- For type tag <= 0x10: preamble is 3 bytes (narrow) or 5 bytes (wide)

The decoded `length_value` becomes the byte offset from
`entry+0x26+preamble_size` to `local_c` (TEXT_BASE pointer). With
preamble length = 7 and TLV size = 6, TEXT_BASE = `entry+0x26+3+7` =
`entry+0x30`, so the 0xFF byte at `entry+0x2F` (= end_of_TLV) sits
between the TLV and the text bytes.

#### TLV parser (`MVDecodePackedTextHeader`)

Reads from `entry+0x26 + preamble_size` and writes to a 168-byte
zero-initialised local struct (`local_120` in `MVBuildTextItem`):

| TLV offset | Field | Source | Bias |
|-----------|-------|--------|------|
| `+0x00` | length (signed int) | first varint | -0x4000 / -0x40000000 |
| `+0x04` | flag bit 0 | bitmap bit 0 | unconditional |
| `+0x08` | flag bit 0x10000 | bitmap bit 16 | unconditional + presence for `+0x12` |
| `+0x0A` | flag bit 0x01000000 | bitmap bit 24 | unconditional + presence for `+0x24` |
| `+0x0C` | 2-bit field | bitmap bits 26-27 | unconditional |
| `+0x0E` | flag bit 0x10000000 | bitmap bit 28 | unconditional |
| `+0x12` | signed int | varint, gated by bit 16 | -0x4000 / -0x40000000 |
| `+0x16` | signed short | varint, gated by bit 17 | -0x40 / -0x4000 |
| `+0x18` | signed short | varint, gated by bit 18 | -0x40 / -0x4000 |
| `+0x1A` | signed short | varint, gated by bit 19 | -0x40 / -0x4000 |
| `+0x1C` | signed short | varint, gated by bit 20 | -0x40 / -0x4000 |
| `+0x1E` | signed short | varint, gated by bit 21 | -0x40 / -0x4000 |
| `+0x20` | signed short | varint, gated by bit 22 | -0x40 / -0x4000 |
| `+0x22` | signed short | varint, gated by bit 23; default formula otherwise | -0x40 / -0x4000 |
| `+0x24` | ushort | 3-byte raw read (low 2 bytes stored), gated by bit 24 | none |
| `+0x27` | signed short | varint, gated by bit 25 (= count of trailing pairs) | -0x40 / -0x4000 |
| `+0x29..` | pair entries | `(varint, varint)` × `[+0x27]` | unbiased |

Encoded by `src/server/blackbird/wire.py`'s `encode_signed_int_varint`,
`encode_signed_short_varint`, `encode_null_tlv`, and `decode_case1_tlv`
(round-trip verifier).

The DPI scale pass (`MVScaleTextMetrics`) immediately after parse rescales
`+0x16..+0x22` and each pair entry's first ushort by
`(devCaps × field × dpi_scale) / (base × 100)`, where `base = 144`
when `TLV[0x12] & 1 == 0` else `1440`. Suggests fields are
sub-pixel layout values in points×10 / twips.

#### Slot tag-1 emission (`MVTextLayoutFSM` / `MVEmitTextRunSlot`)

`MVBuildTextItem` initialises a 42-byte working template (`local_5c`)
copied from `local_74 + 0x36`, then calls `MVTextLayoutFSM` repeatedly
until it returns ≥ 5. Inside `MVTextLayoutFSM`:

- Pre-test: `chunk_content_base[TLV[0x00]] == 0` AND
  `*end_of_TLV == 0xFF` → "skip empty row," return 5. Both must be
  true; the encoder picks layouts where one or both fail.
- Main loop: dispatches via `MVLayoutTextLine → MVLayoutTextRunStream` →
  - text byte at current idx ≠ NUL: `MVFitPlainTextRun` walks ASCII
    classifying NUL=0 / space=2 / letter=1, breaks on word
    boundaries, emits slot via `MVEmitTextRunSlot`.
  - text byte at current idx == NUL: `MVDispatchControlRun` reads byte at
    control walker (`template[+0x14]` = end_of_TLV). 0xFF → return 5,
    advance walker +1. Other bytes dispatch to font-change /
    paragraph / nested-chunk handlers. Default: treat byte as a link
    tag and read `*(ushort *)(walker+1)` as length-prefix → walker
    advances by `length+3`. **Without a 0xFF terminator at
    end_of_TLV, the default case mis-reads ASCII text as link tags
    and walks out of bounds → "service is not available" dialog.**

Slot fields written by `MVEmitTextRunSlot` (slot at
`title+0xf6 + slot_idx*0x47`):

| Slot offset | Source | Notes |
|-----|--------|-------|
| `+0x00` | const 1 | slot tag = 1 (text) |
| `+0x01..+0x04` | template + flag | bit 1 of flags1 = "active" |
| `+0x05` | `template[+0x15]` | X local |
| `+0x07` | `template[+0x17]` | Y local |
| `+0x09` | title font width metric | computed |
| `+0x0B` | `template[+0x16]` + metric | width |
| `+0x0D` | title line height metric | computed |
| `+0x0F` | `template[+0x18]` u32 | (4-byte field) |
| `+0x13` | `template[+0x0E]` u32 | (4-byte field) |
| `+0x39` | `template[+0x18]` int | **text byte offset** within `chunk_content_base`. Set to `TLV[0x00]` (= 0 for null TLV) on `MVFitPlainTextRun` entry. |
| `+0x3D` | `template[+0x1A]` short | **text length** — computed by walk, terminates at NUL or chunk_end (= initial offset + 32) |
| `+0x3F` | `template[+0]` short | **font index** — inherited from `puVar2[+0x18]` (initialised to 0xFFFF in `MVParseLayoutChunk`) |

Paint-time `DrawTextSlot` reads `slot+0x39`, `+0x3D`, `+0x3F` and
calls `ExtTextOutA(hdc, x, y, …, content_base + slot+0x39,
slot+0x3D, …)`.

#### Status (2026-04-29)

Encoder shipped behind env var `MSN_MEDVIEW_CASE1_TEXT`
(`build_case1_bf_chunk` in `src/server/blackbird/wire.py`). Live
SoftIce trace confirms:

- Chunk delivered byte-perfect to `MVParseLayoutChunk` at the cache buffer
  (verified at 0x0040539C; bytes match wire encoding exactly).
- Layout pass dispatches case 1 → `MVBuildTextItem` → `MVTextLayoutFSM` →
  `MVLayoutTextLine` → `MVLayoutTextRunStream` → `MVFitPlainTextRun` → `MVEmitTextRunSlot`
  (slot tag-1 emit reached, text length = 9 for "MSN Today").
- Connection stays alive; "service is not available" dialog gone
  after the 0xFF fix.
- Paint not yet visibly producing text — engine clears hourglass and
  shows blank pane; possibly font index 0xFFFF (slot+0x3F inherited
  from sentinel, not yet diverted) or X/Y outside visible region.

## 11. End-to-end wire trace (MSN Today open → bm0 paint)

Recorded 2026-04-29 after the bm0 sizing fix (`_BM0_CONTAINER` now
38445 B, kind=5 raster 640×480 1bpp `0xFF` pixels, empty trailer):

```
17:13:49 handshake req=0                        validation_result=1
17:13:50 title_pre_notify req=1                 opcode-10 ack
17:13:50 subscribe_notification req=2 type=0    type-0 sub captured
17:13:50 subscribe_notification req=3 type=1    iter end ack
17:13:50 subscribe_notification req=4 type=2    iter end ack
17:13:50 subscribe_notification req=5 type=3    type-3 sub captured
17:13:50 subscribe_notification req=6 type=4    iter end ack
17:13:50 title_pre_notify req=7                 opcode-7 ack
17:13:50 title_open req=8 spec='[4]0'           deid=4 → display='MSN Today'
17:13:50 synthesized_title_body body_len=81 section1_len=43
17:13:50 title_open_reply title_id=0x01 body_len=81

17:13:51 cache_miss_rpc selector=0x06 key=0x01  vaConvertHash; ack + push
17:13:51 cache_push selector=0x06 type3_op4 chunk_len=18
17:13:51 cache_miss_rpc selector=0x15 key=0x01  HfcNear; ack + push
17:13:51 cache_push selector=0x15 type0_bf chunk_len=128
                                                BF chunk inserted into
                                                title+4 tree; case-3
                                                dispatch via name_buf[0x26]
17:13:52 hfs_open name='|bm0' canonical='bm0'   handle=0x42 size=38445
17:13:52 hfs_read handle=66 count=38445 offset=0
                                                full container in one read,
                                                fragmented to 38 wire pkts
                                                ≤1024 B by build_service_packet
17:14:58 hfs_close handle=66                    clean ack (engine took ~66s
                                                to parse + paint on 86Box)

(steady state: title_pre_notify heartbeat every ~10s,
 hfc_next_prev poll every ~30s — ack-only response makes engine
 fall back to in-cache entries.)

17:17:27 hfs_open canonical='bm0'               periodic ~2.5min refresh
17:17:27 hfs_read count=38445 offset=0          (same as initial)
17:18:38 hfs_close
```

### Visual

`reference/screenshots/msn_today_authored.png` captured at the
post-paint steady state. The MSN Today window paints a 640×480
inner pane in window-grey (`0xC0C0C0`, the 1bpp DDB's `bkColor` —
all-`0xFF` pixels render as set bits = background colour) with a
right-edge scrollbar. Scrolling triggers `hfc_next_prev` polls and
modem activity in the VM as the engine probes for adjacent pages.

### Call graph (from chunk arrival to BitBlt)

```
fMVSetAddress(va)
  → HfcNear retry (HfcNear) consults title+4 tree
fMVRealize (@0x7E883890)
  → MVRealizeView → MVHfcNear(va) → MVParseLayoutChunk
       → row at title+0xe0[+4 + idx*0x2a] populated
       → MVWalkLayoutSlots case-3 (name_buf[0x26]=0x03)
       → MVBuildLayoutLine
            → MVResolveBitmapForRun opens bm0 baggage
                → MVCloneBaggageBytes extracts trailer HGLOBAL
                → MVDecodeBitmapBaggage parses kind=5 raster
                → MVCreateHbitmapFromBaggage → CreateBitmap(640, 480, 1, 1, ...)
            → parent slot+0x39 = HGLOBAL of bitmap render record
WM_PAINT
  → MVPaneOnPaint walks row chain title+0xea
  → MVDispatchSlotPaint dispatches slot[0]=3 → MVPaintBitmapSlot
  → MVPaintBitmapRecord BitBlt(hdc, x, y, 640, 480, src_dc, 0, 0, SRCCOPY)
```

Empty trailer means no overlaid text/glyph children. Next-step RE
target: slot-tag-1 / DrawTextSlot text drawer + case-1 BF chunk
schema (see §10.5).

## 12. Open questions

This section is intentionally short. Each entry below is a layout/value
hole still waiting for a dedicated RE pass; the wider catalogue of
known gaps with phase assignments lives in
`scratch/medview-gap-worksheet.md`.

- **Section 0 font-table header** — Resolved §4.4 (Phase 5, 2026-05-11).
  18-byte header pinned via `ResolveTextStyleFromViewer @ 0x7E896610`,
  `CopyResolvedTextStyleRecord @ 0x7E896590`, and `MergeInheritedTextStyle
  @ 0x7E8963B0`. Empty-section-0 path (`u16 size=0`) skips the decode
  entirely and MedView falls back to its built-in faces. Authoring-side
  reverse engineering of the BBDESIGN.EXE font-table classes is BDF
  format work and is out of scope for the MEDVIEW protocol docs.
- **Section 3 `WindowScaffoldRecord`** — Resolved (Phase 5 follow-up,
  2026-05-11). Full 152-byte / `0x98` wire-side layout pinned by
  consumer-side RE of `MOSVIEW!CreateMosViewWindowHierarchy
  @ 0x7F3C6790` (see `docs/medview-service-contract.md`
  `WindowScaffoldRecord`). Authoring-side cross-reference: the
  in-memory data model is the `CSection` MFC class in `BBDESIGN.EXE`
  (`?classCSection@CSection@@2UCRuntimeClass@@A` at
  `BBDESIGN.EXE:0x0047A4F2`; member functions including
  `AddSectionAt`/`AddContentAt`/`AddFormAt`/`AddFrameAt`/`AddStyleSheetAt`/
  `AddMagnetAt` at `0x0047A8DA..0x0047B6DA`; `CSectionProperties` at
  `0x00476838`). The on-disk-to-wire compilation runs through
  `PUBLISH.DLL` (per `project_blackbird_release_wire`). Field-by-field
  mapping from in-memory `CSection` → on-disk `.bdf` →
  wire `WindowScaffoldRecord` is BDF-format reverse engineering and
  is out of scope for the MEDVIEW protocol docs — only the wire side
  needs to be pinned for protocol compatibility, and it is.
- **Section 6 `info_kind=0x6A`** — Resolved (Phase 5, 2026-05-11).
  Raw blob carrying the title's default display title string.
  `fMVSetTitle @ 0x7E882910` pulls it via `lMVTitleGetInfo(t, 0x6A, …)`
  when the caller passes a NULL explicit title, stores the
  `GlobalAlloc(GMEM_FIXED, len)` handle at `view+0x1c`, and surfaces
  it through the `hMVGetTitle @ 0x7E882A50` export (consumed by
  MOSVIEW for the viewer window title and "back" navigation labels).
- **Section 7 `info_kind=0x13`** — Resolved (Phase 5, 2026-05-11).
  Indexed length-prefixed entry table: `[u16 sectionBytes][u16 count]
  { [u16 entryLen][entryBytes] } × count`. `TitleGetInfo @ 0x7E842558`
  dispatch for `0x13` reads `bufCtl >> 0x10` as the entry index,
  copies the matching entry into the caller's buffer (truncated to
  `bufCtl & 0xFFFF`), and forces a trailing NUL at the last byte
  before returning the entry length. The entry payload itself is
  client-opaque to MVTTL14C / MVCL14N — bytes are handed verbatim
  to the external caller (typically a MOSVIEW context-lookup path).
- **HfcNear 60-byte content block** — Resolved (Phase 6, 2026-05-11).
  Allocated by `HfcCache_DispatchContentNotification @ 0x7E8452D3` for
  `0xBF` records; bytes 0..0x2B raw-copied from the wire 0xbf-metadata
  block (client-opaque to MVTTL14C — consumed by the picture/glyph
  paint path through `param_3+0x2C / +0x34`), HGLOBAL slots at
  `+0x2C` / `+0x34` wrap body / name buffers, u32 byte count at
  `+0x30`, last 4 bytes at `+0x38` raw-copied from wire. See §6b.1.
- **Case-1 paint pass** — Resolved (Phase 7 follow-up, 2026-05-11).
  Case `0x80` schema is `[byte tag=0x80][u16 style_id]`. Handler at
  `MVDispatchControlRun @ 0x7E894EC0 case 0x80` calls
  `ApplyTextStyleToHdc(viewer, style_id)` which resolves the style via
  the section-0 font table. With an empty section-0 (size=0) the style
  lookup fails and `slot+0x3F` stays at `0xFFFF` (font index sentinel) —
  `ExtTextOutA` then produces no visible glyphs. A real section-0 font
  table (or a SoftIce trace under a synthesized fixture) is required to
  drive the case-1 paint pass to visible output.
- **Case-3 trailer-tail beyond the 15-byte child records** — Resolved
  (Phase 7 follow-up, 2026-05-11). `MVScaleBaggageHotspots @ 0x7E886DE0`
  copies the variable-length tail bytes via `MV_memcpy(dst[13+15*count],
  src[7+15*count], byteCount)` (`byteCount` is the u32 at source `+0x3`).
  The scaled output is consumed by `MVBuildLayoutLine` which stores the
  tail HGLOBAL at each tag-4 child slot's `slot+0x3B`. Tail content is
  per-child-record payload (CElementData strings, link offsets) keyed
  by each child's `[tag, tag2]` pair (§10.4).
- **Layout-walker `0xBF` paint dispatch for tags 4/7** — Resolved
  (Phase 7 follow-up, 2026-05-11). `MVDispatchSlotPaint @ 0x7E891220`
  per-tag enumeration: `tag 1` → `DrawTextSlot` / `DrawSlotRunArray`;
  `tag 3` → `MVPaintBitmapSlot`; `tag 4` → `MVPaintRectangleSlot`;
  `tag 5` → `MVPaintBorderSlot`; `tag 6` → `MVPaintEmbeddedMediaSlot`;
  `tag 7` → `MVInvertRunHighlightLines`. Other tags are skipped.
- **`lp` pool descriptors** — Resolved (Phase 7 follow-up, 2026-05-11).
  `MVInitViewerLayoutPools @ 0x7E889990` pins three viewer-level pool
  record sizes (`viewer+0xEE` = `0x47` slot record, `viewer+0xFE` =
  `0x1E` aux record, `viewer+0x10E` = `0x14` run/rect record). Each
  slot record additionally carries an **inline per-slot highlight pool**
  whose descriptor lives at `slot+0x17`, initialized lazily by
  `MVApplyHighlightsToSlot @ 0x7E888BE0` via
  `MVPoolInit(slot+0x17, payloadBytes=0x10)`. The `0x14`-byte stride is
  `payloadBytes(0x10) + 4` because `MVPoolInit @ 0x7E890CB0` prepends a
  4-byte doubly-linked-list header to every pool entry. Full
  per-entry layout (consumers in `DrawSlotRunArray @ 0x7E889170`,
  `MVInvertRunHighlightLines @ 0x7E889340`,
  `MVCarryHighlightRectToTrailingRuns @ 0x7E888B60`):
  - `+0x00..+0x01` i16 `prev_index` — pool's doubly-linked in-use list
  - `+0x02..+0x03` i16 `next_index` — same list (also "next free" while
    on freelist; `0xFFFF` sentinel)
  - `+0x04..+0x07` i32 `left` (highlight rect)
  - `+0x08..+0x0B` i32 `top`
  - `+0x0C..+0x0F` i32 `right`
  - `+0x10..+0x13` i32 `bottom`

  Pool descriptor (at `slot+0x17`, ending at `slot+0x2C`):
  - `slot+0x1B` HGLOBAL of the slot pool buffer
  - `slot+0x1F` locked base pointer (`GlobalLock` result)
  - `slot+0x23..+0x25` i16 count / capacity
  - `slot+0x27..+0x29` i16 freeHead / inUseHead
  - `slot+0x2B` i16 inUseTail

  Slot consumers walk `slot+0x29..slot+0x2B` (`inUseHead..inUseTail`,
  inclusive) and dereference each entry as `pool_base + idx * 0x14 + 4`
  to skip the link header and land at the rect's `left` field. The
  original gap-53 phrasing "`lp+0x02:u16` / `lp+0x13:u16` (?)" was a
  misread: `+0x02` is `next_index` (pool list link), and `+0x13:u16`
  spans the high half of `bottom` plus the start of the next entry —
  not a separate field.
- **Extra child panes (`ChildPaneRecord`) and popups (`PopupPaneRecord`)**
  — Resolved (Phase 5 follow-up, 2026-05-11). Full 43-byte / `0x2B`
  `ChildPaneRecord` and 31-byte / `0x1F` `PopupPaneRecord` wire-side
  layouts pinned via consumer-side RE of
  `MOSVIEW!CreateMosViewWindowHierarchy @ 0x7F3C6790` (additional-pane
  + popup loops; see `docs/medview-service-contract.md`). Authoring-side
  cross-reference: the in-memory data model is the `CFrame` MFC class
  family in `BBDESIGN.EXE` (`CFrameListElem` at `0x00474878`,
  `CFrameProperties` at `0x00476094`,
  `?GetTranslateMessageFedFrame@@YAPAVCFrameWnd@@H@Z` runtime helper
  at `0x0047A42A`). Edit→wire compilation runs through `PUBLISH.DLL`.
  Field-by-field mapping from in-memory `CFrame` → on-disk `.bdf` →
  wire `ChildPaneRecord`/`PopupPaneRecord` is BDF-format reverse
  engineering and is out of scope for the MEDVIEW protocol docs.
