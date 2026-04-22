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
| 20 | `A0` | `0x15` | |
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

No dynamic section. The client's wait uses `FUN_7e843dcb` with a 30-second
timeout.

### 3.3 Post-handshake behaviour

After a good handshake, `hrAttachToService` also:

1. Fires `TitlePreNotify(0, opcode=10, buf=&DAT_7e84e2ec, size=6)` —
   selector `0x1E`. `DAT_7e84e2ec` holds a value bootstrapped from
   `DAT_7e851808` (observed zero). Server can reply with empty static +
   `0x87`.
2. Allocates five async callback slots (per-notification-type,
   `FUN_7e84485f` @ `0x7E84485F`). These are client-side listeners; they
   do not require the server to initiate any traffic.

---

## 4. TitleOpen (selector `0x01`)

Called by `MVTTL14C!TitleOpenEx @ 0x7E842D4E` (export ordinal 41) to open
one title. Invoked from `MVCL14N!hMVTitleOpenEx`, itself called by
`MOSVIEW!OpenMediaTitleSession @ 0x7F3C61CE` once per open.

### 4.1 Cache hint

Before opening, `TitleOpenEx` tries to read
`HKLM\SOFTWARE\Microsoft\MOS\Directories\MOSBin\MVCache\<title>.tmp`. The
first 8 bytes of that file are two LE DWORDs (prior checksum pair). If the
cache file exists and has those 8 bytes, they are sent as the two `0x03`
request DWORDs below; otherwise both DWORDs are zero.

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
| `0x81` | 1 | `title_id_byte2` — stored as the "service byte" the client sends back on subsequent per-title RPCs. |
| `0x83` | 4 LE | DWORD → title+0x46 |
| `0x83` | 4 LE | DWORD → title+0x48 |
| `0x83` | 4 LE | DWORD → title+0x4A |
| `0x83` | 4 LE | New checksum 1 |
| `0x83` | 4 LE | New checksum 2 |
| `0x87` | 0 | End of static |
| `0x86` | var | Dynamic "title body" — raw bytes to end of host block (see §4.4). Sent as `TAG_DYNAMIC_COMPLETE_SIGNAL` so the client's `Wait()` on slot `0x48` fires (same pattern as DIRSRV GetShabby). |

### 4.4 Title body layout

The dynamic bytes `B` attached to the reply are a flat **9-section
stream**. Ground-truth from the `MVTTL14C!TitleOpenEx @ 0x7E842D4E` and
`TitleGetInfo @ 0x7E842558` decompiles:

1. `TitleOpenEx` saves `B` at `title + 0x52` and its length at
   `title + 0x54`.
2. It reads `b0 = *(u16 LE)B` as the size of a **structural header**
   consumed by `TitleOpenEx` itself (purpose not yet pinned — see §10):
   - `b0 == 0` → branch `LAB_7e8432c4`: skip the header decode, zero
     `title[4]`/`title[5]`. **This is the safe path.**
   - `b0 != 0` → `GlobalAlloc(GPTR=0x40, b0)`, `MOVSD.REP` the `b0`
     bytes from `B+2`, then read `*(u32 LE)` of the copy as a
     **child-count** and zero that many dword slots starting at
     `psVar7 + psVar7[8]` (word-index 8 = byte offset 0x10). That
     "count + slot array at +0x10" deserialization pattern argues
     against this being a bitmap (nobody interprets DIB bytes that
     way); it looks more like a MedView object descriptor with
     placeholder child pointers the engine fills in later.
3. `TitleGetInfo` walks the remaining 8 sections on demand to answer
   field queries. Its `param_2` argument is the **selector kind**, not
   a section index — the dispatch table maps selector → section.

Section-by-section (`u16` = little-endian 16-bit):

| # | `TitleGetInfo` selector(s) | Header | Payload |
|--:|---------------------------|--------|---------|
| 0 | — (consumed by TitleOpenEx) | `[u16 size]` | Structural header (u32 child-count + slot array at +0x10); exact layout unknown — **not a bitmap**, see §10 |
| 1 | `7` | `[u16 size]` | array of fixed **43-byte** records (10 u32 + u16 + byte) |
| 2 | `8` | `[u16 size]` | array of fixed **31-byte** records (7 u32 + u16 + byte) |
| 3 | `6` | `[u16 size]` | array of fixed **152-byte** records (38 u32) |
| 4 | `1` | `[u16 size]` | raw blob |
| 5 | `2` | `[u16 size]` | raw blob |
| 6 | `0x6A` | `[u16 size]` | raw blob |
| 7 | `0x13` | `[u16 size][u16 count]` | `count × [u16 len][bytes]` (length-prefixed records) |
| 8 | `4` (fallthrough for `4`/`0x6B`/`0x6D`/`0x6E`) | `[u16 count]` | `count × ASCIIZ` — **the string table** |

Section 7's empty form is just `[u16 size=0]` (the walker uses
`(size==0) ? 2 : size+4` to advance). Sections 0-6 are straight
`[u16 size][size bytes]`. Section 8 alone has no `size` — its header
is a direct string count.

The 43/31/152-byte record sizes are hard-coded inside `TitleGetInfo`
and come from the 1996 server's synthesis of these sections from a
Blackbird "Release" compound-file upload (see `docs/BLACKBIRD.md` §4.4).
MVTTL14C never touches `ole32`'s `IStorage` APIs — the section stream
is the MSN wire format; the OLE2 compound file is purely the
authoring-side / Local-target artifact.

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
This is the MVP the server ships today.

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
`title+0x58` as the window caption. Rich title content — the structural
header (section 0) and the fixed-size record arrays
(sections 1/2/3/7) — is carried in the compound file's per-class
`\x03object` streams, which are opaque pending RE of
`COSCL.DLL!extract_object` and the MS-stock compression on larger
streams (`docs/BLACKBIRD.md` §3.1.3 and §7).

---

## 5. TitleGetInfo (selector `0x03`)

`MVTTL14C!TitleGetInfo @ 0x7E842558` (export ordinal 39). Serves most
metadata from the cached body bytes locally; only a few `info_kind` values
actually go out on the wire (case `LAB_7E842B4B` / `LAB_7E842B1E` in the
decompile).

### 5.1 Local path (no RPC)

`info_kind` in {`0x01`, `0x02`, `0x04`, `0x06`, `0x07`, `0x08`, `0x0B`,
`0x13`, `0x69`, `0x6A`, `0x6E`, `0x6F`} is served from the saved body
bytes (see §4.4) without any network traffic.

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
`FUN_7e84485f @ 0x7E84485F` — one per notification type. Each
subscriber's constructor calls `FUN_7e844ee6 @ 0x7E844EE6` which
invokes selector `0x17` on the service proxy with a single tagged byte
(the notification-type index, observed `0..4`) and waits on slot `0x48`
for an async-iterator handle.

Request (3 bytes):

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | Notification type index |
| `0x88` | 0 | Recv descriptor: async-iterator handle |

Reply semantics: if the server hands back a non-NULL iterator handle,
the subscriber starts a `CreateThread(FUN_7e844c7c, …)` pump that waits
on that handle for push notifications (title invalidation, cache
flush, etc.). If the handle is NULL or slot-0x48 returns an error, the
subscriber leaves `param_1[2].LockCount == 0`, never starts a thread,
and `hrAttachToService` moves on to the next subscriber.

**MVP contract**: static-only `0x87` reply. No dynamic section → the
client's slot-`0x48` sets `*ppvVar1 = NULL`, subscribe declines
cleanly, and the 5 calls (one per notification type) each complete in
under a round-trip. Live notification push is out of scope until an
event-feed emitter is wired; MSN Today doesn't depend on any of these
feeds at startup.

---

## 7. Post-TitleOpen calls made by MOSVIEW

`MOSVIEW!OpenMediaTitleSession` enumerates the cached body via
`lMVTitleGetInfo` (MVCL14N wrapper around `TitleGetInfo`):

1. `0x2B`-byte records — indexed loop, one per 43-byte "topic/TOC" slot.
2. `0x1F`-byte records — indexed loop, one per 31-byte slot.
3. `0x98`-byte records — indexed loop, one per 152-byte slot (the large
   per-title metadata block).
4. String-list loop — pulls ASCIIZ items until exhausted.
5. Title name — single ASCIIZ.
6. Optional second string — single ASCIIZ.

All of these resolve from the body bytes locally (§5.1). If the body is
empty they all return quickly with no records and the viewer still opens
(title name becomes `"Unknown Title Name"`).

Before the first TitleGetInfo it also calls `MVSetKerningBoundary`,
`hMVSetFontTable`, `MVSetFileSystem`, `vaMVGetContents` — all MVCL14N
engine calls with no direct wire traffic at this stage.

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
4. Selector `0x17` (SubscribeNotification, §6a): static `0x87`. No
   dynamic.
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

## 10. Open questions

- **Dialect of `info_kind`**. `TitleGetInfo` serves constants we haven't
  mapped to MedView API names (`0x13`, `0x6A`, `0x6E`, `0x6F`, `0x69`,
  `0x0B`). MVCL14N's `lMVTitleGetInfo` wrapper is the authoritative
  mapping — Phase 4 catalogued the MSN-facing surface only.
- **Checksum semantics**. The new checksums returned in the TitleOpen
  reply are written back into `MVCache\<title>.tmp`. Whether the server
  treats them as (a) a content hash, (b) a version stamp, or (c) a
  client-opaque token is not yet nailed down; for the MVP they can be any
  stable non-zero pair.
- **Section 0 semantics**. The first section of the body is copied into
  a separate `GPTR GlobalAlloc`'d buffer and the first DWORD of the copy
  is read as a **child-count**; that many dword slots at offset `+0x10`
  are zeroed. The "count + slot array" deserialization rules out a
  bitmap — this looks more like a MedView top-level object descriptor
  (a CTitle header with placeholder children the engine fills in later).
  Exact field layout is not yet RE'd; shipping an empty body (`u16 0`)
  takes the safe `LAB_7e8432c4` path and sidesteps the decode entirely.
  (Earlier docs in this repo described section 0 as "the title banner"
  — that was a guess based on the `MOVSD.REP` superficially resembling
  bitmap handling; the directory-node banner painted by `CDIBWindow`
  on DSNAV/BBSNAV nodes is a **different** thing, sourced via the
  `'mf'` DIRSRV property and MOSSHELL's shabby-fetch path. See
  `docs/MOSSHELL.md` §6.3 and `docs/DSNAV.md` §11.1.)
