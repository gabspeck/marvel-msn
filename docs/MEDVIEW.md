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
| `0x81` | 1 | `hfs_volume` — low byte of `*(u32 *)(title+0x88)`. Served locally via `TitleGetInfo(info_kind=0x69)`; passed into baggage as the HFS mode byte (`HfOpenHfs`, §6c). |
| `0x83` | 4 LE | DWORD → `title+0x8c` = **contents va**. Served locally via `vaGetContents @ 0x7E841D48`. This is the entry-point virtual address navigation hands to the MedView engine (`NavigateViewerSelection` → `vaMVGetContents` → paint). `0xFFFFFFFF` / `0` both route `NavigateViewerSelection` into the "hideOnFailure" branch — **nothing paints**. |
| `0x83` | 4 LE | DWORD → `title+0x90` — purpose unresolved on MSN Today's path. Observed unread by local `TitleGetInfo` paths; possibly a notification-epoch token consumed by the async-subscription pump. |
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
  └─ MOSVIEW!FUN_7f3c6790        @ 0x7F3C6790    (pane attach + nav)
       └─ MOSVIEW!FUN_7f3c3670   @ 0x7F3C3670    (pane.SetAddress)
            └─ MVCL14N!fMVSetAddress @ 0x7E883600
                 └─ MVCL14N!FUN_7e885fc0 @ 0x7E885FC0
                      └─ GetProcAddress(per_title_module, "HfcNear")
                           └─ MVTTL14C!HfcNear @ 0x7E84589F   ← gate
```

`HfcNear` walks a **per-title cache** (binary tree at `title+4`,
recent-cache array at `title+0x10..0x34`; entries store 60-byte
content chunks at `entry+0x18`) via `FUN_7e845efa`. On miss, it fires
selector `0x15` (§6b.1) up to 6 times in a retry loop with ~300 ms
spacing before returning NULL. If `HfcNear` returns NULL,
`fMVSetAddress` returns 0, `FUN_7f3c3670` sets the pane FAIL flag at
`pane+0x84` and skips paint.

`MVCL14N!vaMVGetContents` itself does NOT read memory at the va — it
calls `MVTTL14C!vaGetContents` via per-title GetProcAddress, which
just returns `title+0x8c` verbatim. The va is therefore an **opaque
token** the engine threads through to `HfcNear`'s cache lookup; the
cache is what knows how to render it.

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
     **This is the safe path** — what the server ships today.
   - `b0 != 0` → `GlobalAlloc(GPTR=0x40, b0)`, `MOVSD.REP` the `b0`
     bytes from `B+2`, then:
     - Read `i16` at copy+0x00 as **font count** (sign-extended; zero
       swapped to 1 for the zero-loop's bound).
     - Read `i16` at copy+0x10 as **slots_offset** (signed, relative to
       copy base).
     - Zero `count` dwords starting at `copy + slots_offset`. These are
       the HFONT slots the engine fills at runtime as fonts get loaded.
     Raw-instruction source: `MOVSX ECX, [EAX]` at `0x7E843291` and
     `MOVSX ESI, [EAX+0x10]` at `0x7E8432A9`. The 14 bytes between the
     two signed halfwords carry the font descriptors (face name /
     charset / size index) the runtime consumes to populate slots —
     exact field layout is not yet RE'd and is not required for the
     empty-table path.
3. `TitleGetInfo` walks the remaining 8 sections on demand to answer
   field queries. Its `param_2` argument is the **selector kind**, not
   a section index — the dispatch table maps selector → section.

Section-by-section (`u16` = little-endian 16-bit):

| # | `TitleGetInfo` selector(s) | Header | Payload | Role |
|--:|---------------------------|--------|---------|------|
| 0 | `0x6F` (returns `title+0x08`, the copy handle) | `[u16 size]` | Font table — `i16 count @ +0x00`, `i16 slots_offset @ +0x10`, engine zeros `count` dwords at `base+slots_offset` at load time. 14 bytes of font descriptors in the gap (unresolved). | font table |
| 1 | `7` | `[u16 size]` | array of fixed **43-byte** records (10 u32 + u16 + byte) | topic / TOC table |
| 2 | `8` | `[u16 size]` | array of fixed **31-byte** records (7 u32 + u16 + byte) | link / jump table |
| 3 | `6` | `[u16 size]` | array of fixed **152-byte** records (38 u32) | per-title layout / style table |
| 4 | `1` | `[u16 size]` | raw blob | title caption (ASCII) |
| 5 | `2` | `[u16 size]` | raw blob | second string (subtitle / copyright) |
| 6 | `0x6A` | `[u16 size]` | raw blob | "title string" — `fMVSetTitle` allocates it to `view+0x1c` when called with NULL path; purpose beyond cache key not yet pinned |
| 7 | `0x13` | `[u16 size][u16 count]` | `count × [u16 len][bytes]` (length-prefixed records) | context / hash records (unresolved) |
| 8 | `4` (fallthrough for `4`/`0x6B`/`0x6D`/`0x6E`) | `[u16 count]` | `count × ASCIIZ` — **the string table** | strings referenced by the record arrays |

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

**ver=0x03 object stream → wire-ready record (single-sample
hypothesis).** A second authored MSN Today fixture emits CSection
storages (e.g. `9/1/object`) with a new version byte `0x03` whose
44-byte raw stream strips to a **43-byte body** — exactly the section-1
record stride. Decomposes as `10 u32 + u16 + u8` per the documented
record shape, with no compression header and no class-specific
serialisation prefix. Strong inference: the 1996 BBDESIGN release path
flattens CSection instances to wire-ready records and tags them
`ver=0x03` so the server can `memcpy` the body straight into wire
section 1 (concatenating across multiple CSections in DPORef-handle
order). If this holds, populating section 1 needs no engine RE — just
walk `Title.objects[csection_sid][sub]` and concatenate. Pending
empirical verification (need a fixture with multiple CSections to
confirm ordering and lookup semantics).

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

### 4.6 Layout walker dispatch byte is engine-internal, not on-disk

`MVCL14N!FUN_7e890fd0 @ 0x7E890FFE` reads `name_buf[0x26]` from a
type-0 cache buffer and dispatches `FUN_7e894c50 @ 0x7E894C50` on
that byte. The byte at `+0x26` looks like a class-version tag —
`VIEWDLL!CSection::Serialize @ 0x4070E6AF` writes `bVar3 = 3` as its
on-disk version — but the resemblance is coincidental. Evidence:

1. `FUN_7e894560 @ 0x7E894560` (the case-3 handler) writes the
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
3. `MVCL14N!FUN_7e886310 @ 0x7E886310`, called by case 3 with the
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
`FUN_7e84485f @ 0x7E84485F` — one per notification type. Each
subscriber's constructor calls `FUN_7e844ee6 @ 0x7E844EE6` which
invokes selector `0x17` on the service proxy with a single tagged byte
(the notification-type index, observed `0..4`) and waits on slot `0x48`
for an async-iterator handle.

Request (3 bytes), wire-observed `01 <type> 85`:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | Notification type index |
| `0x85` | 0 | Recv descriptor: dynamic-recv (single-shot blob, NOT iterator) |

Reply semantics: if the server hands back a non-NULL iterator handle,
the subscriber starts a `CreateThread(FUN_7e844c7c, …)` pump that waits
on that handle for push notifications (title invalidation, cache
flush, etc.). If the handle is NULL or slot-0x48 returns an error, the
subscriber leaves `param_1[2].LockCount == 0`, never starts a thread,
and `hrAttachToService` moves on to the next subscriber.

**Wire contract**: reply `0x87 0x86` (end-static + dynamic-complete
with empty blob). The request descriptor is `0x85` (dynamic-recv,
not the iterator-recv `0x88` previously assumed). Per OnlStmt
selector `0x05`'s reference pattern (`services/onlstmt.py:189-201`):
"`0x85` or `0x88` alone would hang the Retrieving dialog forever".
The `0x86` reply tag fires `SignalRequestCompletion` at
`MPCCL.ProcessTaggedServiceReply`, unblocking MPC's Execute on
slot 0x48 inside `MVTTL14C!FUN_7e844ee6 @ 0x7E844EE6`. Execute
then writes a non-NULL reply iface to `subscriber+0x28`, the
success branch sets `subscriber+0x44 = 1`, and the master flag
`DAT_7e84e2fc` can finally set after all 5 subscribers complete.
0x88 alone in the reply does NOT fire SignalRequestCompletion
(only the iterator-end signal at +0x2c), so Execute hangs.

Empty blob (zero bytes after `0x86`) is fine: the subscriber only
needs `+0x28` non-NULL, not specific blob contents. Server-initiated
push of cache-update frames (op-code 4 kind-2 va→addr per project
memory) flows through a separate channel — the subscription's
notification-pump path (`FUN_7e844c7c`), not the initial reply.

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

`FUN_7e8440ab @ 0x7E8440AB` (the "service ready" check called from
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
`MVCL14N!FUN_7e885fc0 @ 0x7E885FC0` → `GetProcAddress(module,
"HfcNear")`. On cache miss it fires this selector. Sole caller in
MVTTL14C; `PUSH 0x15` at `0x7E845973`.

Request:

| Tag | Bytes | Meaning |
|-----|-------|---------|
| `0x01` | 1 | `title_byte` (= `*(title+0x02)`, echoed across all per-title RPCs) |
| `0x03` | 4 LE | `va` (the unresolved virtual address; engine wants the matching content chunk) |
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
before HfcNear's next iteration of `FUN_7e845efa` (~300 ms later).

### Cache structure (per-title, distinct from MVTTL14C global cache)

The cache HfcNear consults is stored **inside the title struct**:

- `title+0x04` — root of a binary tree keyed by va. Each entry has
  `[next, va, ?, va_max?, ?, ?, payload_ptr, ...]` (offsets in
  4-byte words). Lookup compares `entry[1] == request_va`.
- `title+0x10..0x34` — 10-slot recent-access cache (array of pointers
  into the tree). Hot entries get promoted via memcpy.
- `title+0x38..0x5c` — secondary lookup cache (parallel structure,
  semantics partially RE'd).
- `title+0x60..0x84` — title-byte side-cache (per-title-byte index).

Each cache entry's payload is **60 bytes** (`for iVar2 = 0xf` at
`HfcNear+0x???`, i.e. `0xf × 4 = 0x3c`). Field layout is unresolved;
`HfcNear` memcpy's the 60 bytes into the caller-provided buffer
(`fMVSetAddress`'s `param_1+0x1c`, the pane's content-record slot).

Frame format on the selector-`0x17` type-3 push channel that
populates this cache is unresolved (likely op-code 5,
`FUN_7e8424f5`, marked "secondary cache, unresolved" in
project memory).

## 6b. Content selectors (va / addr / highlight resolution)

MVCL14N's render path pulls most content off a local 3-list cache at
`MVTTL14C.DLL:PTR_DAT_7e84e130`, keyed by `(title_byte, topic_no)`
(list 0), `(title_byte, hash)` (list 1), `(title_byte, va)` (list 2).
The primary consumers walk the cache via `FUN_7e841ac9` / `FUN_7e841b21`:

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
  Reply bytes are consumed by `FUN_7e844738`.

The selectors `0x06` / `0x07` do NOT themselves return a va in the
reply — the client waits on `slot 0x48`, releases immediately, and
re-checks the cache. The actual answer arrives **through the async
subscription channel** (selector `0x17`, one iterator per notification
type; see §6a). `FUN_7e844c7c @ 0x7E844C7C` is the pump thread that
reads chunks via `piVar1->m0x1c(iter, &chunk)` and hands them to the
per-type callback registered in the subscriber struct at `+0x20`.

### Subscription types and callbacks

`hrAttachToService @ 0x7E844114` installs 5 subscribers, one per
notification type index sent on selector `0x17`:

| Type | Callback | Purpose (inferred) |
|-----:|----------|--------------------|
| 0 | `FUN_7e8452d3` | Topic metadata / string attachments (opcodes `0xBF`, `0xA5`, `0x37`) — **opcode 0xBF inserts into HfcNear's per-title cache** at `title+4` via `FUN_7e8460df`. Driven by HfcNear's own retry loop (`FUN_7e845875` → `FUN_7e8451bf(idx=0, …)` → `FUN_7e8450d5` → `FUN_7e844a3b` → `FUN_7e8452d3`), no pump thread required (`param_3 = 0` to `FUN_7e84485f`). |
| 1 | `LAB_7e849251` | Picture / download status |
| 2 | `FUN_7e841109` | Context-string / global-state updates (writes `DAT_7e84d02c`-family tables) |
| 3 | `FUN_7e8451ec` | **va / addr cache pushes** (populates `PTR_DAT_7e84e130` global kind-0/1/2 cache via op-code 4 → `FUN_7e8420f6`). **Different cache from HfcNear's `title+4` tree.** |
| 4 | `FUN_7e8468d5` | WordWheel / key-index refresh |

### Type-3 frame format (cache push)

`FUN_7e8451ec @ 0x7E8451EC` is the callback. Each chunk the pump
delivers is a sequence of framed messages:

```
+0x00  u16 op_code   (1..5; 0 and >5 skipped silently)
+0x02  u16 length    (includes the 4-byte header; must be ≤ chunk remaining)
+0x04  payload       (length - 4 bytes, op_code-specific)
```

Op-code dispatch inside type-3:

| op_code | Dispatch | Handles |
|--------:|----------|---------|
| 1, 2 | `FUN_7e846bb1` | Topic / hash invalidation |
| 3 | — (silently skipped, length still consumed) | Reserved |
| **4** | `FUN_7e8420f6` | **va / addr cache insert** |
| 5 | `FUN_7e8424f5` | Secondary cache (unresolved) |

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

- Kind 0: `FUN_7e841ac9` matches `(title_byte, topic_no@+0xC)` →
  returns `(va, addr)` from `(+4, +8)`.
- Kind 1: `FUN_7e841b21(list=1)` matches `(title_byte, hash@+4)` →
  returns `va` from `+8`.
- Kind 2: `FUN_7e841b21(list=2)` matches `(title_byte, va@+4)` →
  returns `addr` from `+8`.

### HfcNear's per-title cache (`title+4` tree)

`MVTTL14C!HfcNear @ 0x7E84589F` is the gate `fMVSetAddress` calls
during initial pane attach (via `FUN_7e885fc0` →
`GetProcAddress("HfcNear")`). It walks `*(int **)(title + 4)` (binary
tree of cache entries, 32-byte node + name buffer) via
`FUN_7e845efa`. On miss, it fires selector `0x15` and waits for the
cache to fill. **The only function that inserts into this tree is
`FUN_7e8460df`** (sole caller: type-0 callback `FUN_7e8452d3` when
parsing opcode `0xBF`). Op-code 4 on type-3 writes to
`PTR_DAT_7e84e130` (global kind-0/1/2 cache for `vaConvertHash` /
`vaConvertTopicNumber`) — **not the same cache** as HfcNear walks.

Wire layout for opcode 0xBF push (size=8 form, 72 bytes):

```
+0x00  u8   opcode = 0xBF
+0x01  u8   title_byte (matched in FUN_7e845eb7's title list)
+0x02  u16  name_size (must be > 0; FUN_7e845cd4 returns NULL when
                       entry+0x14 = name_len = 0, killing HfcNear's
                       success path)
+0x04..0x0B  8-byte name buffer (memcpy'd into entry+0x20)
+0x0C  u32  key (the va HfcNear looks up; stored at entry+4 and
                 matched at `entry[1] == key` in FUN_7e845efa)
+0x10..0x47  56 bytes of 60-byte content block (key field at +0xC
              doubles as content[0..3] for size=8 because
              FUN_7e8452d3 reads key at fixed offset 0xC and copies
              60 bytes starting at offset (size + 4) = 0xC).
```

**Open: 60-byte content block field layout.** Two of the 60 bytes
ARE pinned: bytes `0x2C` and `0x34` are HGLOBAL handles (HfcNear's
success path passes them to `FUN_7e84a1d0` and stores results at
`lp+0x64` / `lp+0x6C`). The remaining 56 bytes are unmapped.

**Layout-walker AV (root cause for "service is not available" dialog).**
Pushing a 0xBF chunk with zero name buffer (any size 0x08..0x40 tested)
unblocks HfcNear successfully, but the buffer flows downstream into
`MVCL14N!FUN_7e890fd0 → FUN_7e894c50` (called from `FUN_7e88e440`'s
section walker) and trips an AV at `0x7E894D4C`:

```
0x7E894D41  LEA ECX, [ECX + ECX*8]       ; ECX = sVar3*9
0x7E894D44  SUB ECX, EAX                 ; ECX = 0x47*sVar3
0x7E894D46  ADD ECX, [EDI + 0xf6]        ; ECX += lp[+0xf6] (table base)
0x7E894D4C  MOVSX EAX, word ptr [ECX + 0xb]   ; AV — sVar3 walks past valid records
```

Mechanism (Ghidra-traced 2026-04-28):

1. `FUN_7e890fd0` declares `local_30..local_24` and explicitly inits
   `local_30 = 0`, `local_2c = 0`, `local_2a = 0`, `local_24 = 0` —
   but **leaves `local_2e` uninitialized** (stack frame `SUB ESP,
   0x2c` allocates the space, no MOV zeroes it).
2. `FUN_7e890fd0` calls `FUN_7e894c50(lp, &puVar2[6], name_buf+0x26,
   ..., &local_30)`. `param_6 = &local_30`, so `param_6[0] = 0` and
   `param_6[1] = local_2e = garbage`.
3. `FUN_7e894c50` calls `FUN_7e897ed0(local_c, name_buf+0x26)` to
   decode the first record. With our zero-filled name buffer, byte
   `0x26` = 0 → `local_c[0] = 0`.
4. `switch(local_c[0])` matches no case (cases are 1, 3, 4, 5, 0x20,
   0x22, 0x23, 0x24) → default → break, **no record added, no
   `param_6[1]` update**.
5. Post-switch loop `if (param_6[4] == 0 && param_6[5] == 0 && *param_6
   < param_6[1])` — guards on 4/5 forced to 0 by FUN_7e894c50 itself.
   `*param_6 = 0`, `param_6[1] = local_2e = garbage`. Loop walks
   garbage records → AV.

The engine's exception handler catches the AV and surfaces "This
service is not available at this time" via `TitlePreNotify opcode 8`
echo with full diagnostic string (`Code=xc0000005 Address=x7e894d4c
Parameters=2`). Graceful degradation — MOSVIEW stays alive.

**Avoidance requires byte 0x26 of name_buf to land on a switch case
(1/3/4/5/0x20/0x22/0x23/0x24) AND the case handler must complete
without itself AV'ing.** Each handler depends on chunk content
populating internal state via `FUN_7e897ad0`'s schema decoder:

- Case 1 (`FUN_7e8915d0`): do-while loop `while (FUN_7e891810 < 5)`.
  Early-exit at `FUN_7e891810` entry checks
  `*(char *)(local_120[2] + local_120[0x10]) == 0` — both fields are
  populated by `FUN_7e897ad0` from the chunk's 32-bit "presence
  bitmap" header.  Zero-fill chunk → `local_120[2] = 0`,
  `local_120[0x10] = 0` (uninitialised local stack), deref vaddr 0
  AVs immediately.  To pass cleanly: encode chunk with bitmap bits
  17 + bit 0 of high u16 set so `local_120[2]` gets a non-zero base,
  AND `local_120[+0x27] >= 6` so the trailing records loop writes
  past byte 0x40 (= int index 0x10) with values that sum back to a
  readable NUL byte.  Plus several `lp+0x102 / 0xf6 / 0x80 / 0x10a`
  state fields that have to be primed.
- Case 3 (`FUN_7e894560`): calls `FUN_7e886310(lp, fontspec)` which
  always returns a non-NULL HGLOBAL (alloc'd inside) → no early exit
  → continues into `lp+0xee/+0xf6` table reallocations with
  case-3-specific schema fields.
- Cases 4/5 (`FUN_7e8938c0`, `FUN_7e893600`): similar lp dependencies
  plus their own chunk-content schemas.

### `FUN_7e897ad0` schema decoder (chunk → local_120)

`FUN_7e8915d0` parses chunk content right after `FUN_7e897ed0`
consumed the opcode byte.  Entry chunk pointer = `chunk + 0x26 +
opcode_consumed_bytes` (3 for compact opcodes).  First u32
(`*chunk_content`) is the **presence bitmap**:

```
byte 0           bit 0:           length encoding (0 = compact
                                  u8 → param_2[0] = (u16>>1)-0x4000;
                                  1 = extended u32 → param_2[0] =
                                  (u32>>1)+0xC0000000)
high u16 of *uVar1:
    bit 16 (uVar1 & 0x10000)      gates +0x12 (extended u32)
    bit 17 (uVar1 & 0x20000)      gates +0x16 (length-encoded u16)
    bit 18 (uVar1 & 0x40000)      gates +0x18 (length-encoded u16)
    bit 19 (uVar1 & 0x80000)      gates +0x1a
    bit 20 (uVar1 & 0x100000)     gates +0x1c
    bit 21 (uVar1 & 0x200000)     gates +0x1e
    bit 22 (uVar1 & 0x400000)     gates +0x20
    bit 23 (uVar1 & 0x800000)     gates +0x22 (special init from +0x12 bit)
    bit 24 (uVar1 & 0x1000000)    gates +0x24 (3-byte read)
    bit 25 (uVar1 & 0x2000000)    gates +0x27 (record count for trailing loop)
```

Bits in the LOW u16 of the presence bitmap fan out to `param_2[1]`,
`param_2[2]`, `+10`, `param_2[3]`, `+0xe` (single-bit / 2-bit / 4-bit
extracts).  These ARE always written, regardless of upper bits.

The trailing records loop (`if (0 < *(short *)(param_2 + 0x27))`)
writes to bytes `0x29 + 4*N` in 4-byte strides; with N=6, the 6th
write hits byte 0x40 (= int index 0x10).  Each entry is a length-
encoded u16 + optional second u16.

**Until either a known-good chunk capture or RE of all 50+ derived
fields lands**, pushing 0xBF chunks creates more harm than good.
The server currently leaves selector `0x15` as ack-only `0x87` —
HfcNear retries ~6× (~6 s) then `fMVSetAddress` returns 0, the pane
stays blank, no error dialog.

**Next-step RE targets** (when work resumes):

1. Map `FUN_7e8915d0`'s prep block (lines after `FUN_7e892b90` call):
   what does each `local_38..local_2a` capture from chunk content?
   These directly drive the do-while loop's exit conditions.
2. Trace `FUN_7e891810`'s state machine — the loop body sets
   `local_4c` to 1..5 based on lp + chunk state.  Find the path that
   returns 5 from chunk content alone (without lp state from a real
   prior title body).
3. Locate `local_120[0x10]`'s real provenance — if the trailing
   records loop is the only writer and the records are themselves
   encoded structures with sub-fields, decode their schema too.

### lp table descriptors

`lpMVNew` allocates four record tables for the lp via
`FUN_7e889990 @ 0x7E889990` (called from `0x7E882512`):

| Offset | Record size | Purpose | Init function |
|-------:|-----------:|---------|---------------|
| `lp+0xd8` | 0x26 (38 B) | Topic display records (referenced by `FUN_7e890fd0`'s `param_2 = HGLOBAL` argument) | `FUN_7e890cb0` (with free-list) |
| `lp+0xee` | 0x47 (71 B) | Layout records (the `FUN_7e894c50` walk target) | `FUN_7e890b80` |
| `lp+0xfe` | 0x1e (30 B) | Unknown — third table | `FUN_7e890b80` |
| `lp+0x10e` | 0x14 (20 B) | Unknown — fourth table | `FUN_7e890b80` |

Each descriptor is 0x16 bytes:
- `+0x00` to `+0x03`: ?
- `+0x04`: HGLOBAL handle (`*(HGLOBAL *)(table + 4)`)
- `+0x08`: locked pointer (`*(LPVOID *)(table + 8)`)
- `+0x0c`: u16 count
- `+0x0e`: u16 capacity
- `+0x10`: u16 free-list head (-1 if empty; `FUN_7e890d60`'s entry point)
- `+0x12`: u16 list link
- `+0x14`: u16 list link

`FUN_7e890b80(table, record_size)` sets `table+4 = GlobalAlloc(GMEM_MOVEABLE
| GMEM_ZEROINIT, record_size * 4)` and `table+0xc = 0`, `table+0xe = 4`.
`FUN_7e890c20` is the GlobalReAlloc-based expander.

### Server implications

- Selector `0x15` (HfcNear) — push opcode `0xBF` chunk on the type-0
  subscription. HfcNear's retry loop drives consumption synchronously
  via `FUN_7e845875`; no pump thread needed for type 0 even though
  `param_3 = 0` to `FUN_7e84485f` skips the threaded pump.
- Selectors `0x06` / `0x07` — push op-code 4 frame on the type-3
  subscription. Type 3 has a real pump thread (`FUN_7e844c7c`) that
  reads chunks asynchronously and dispatches via `FUN_7e8451ec`.
- All five subscribe calls need their `+0x44` slot non-zero for the
  master flag (§6a).
- Type-0 reply must be `0x87 0x88` (iterator) so MPC's Execute hands
  back a readable iface that chunk-pushes can attach to. Same for
  type-3.

## 6c. Baggage (HFS file access, selectors `0x1A` / `0x1B` / `0x1C`)

MVTTL14C exports a 7-function Baggage API (ordinals 15-22) that
routes to either a local Win16 `_lopen` file handle or an HFS
("Hierarchical File System") handle opened over the wire:

| Export | Addr | Wire? | Wire selector |
|--------|------|------|---|
| `BaggageOpen` | `0x7E848205` | only when `param_3 != 0` (HFS mode) | delegates to `HfOpenHfs` |
| `HfOpenHfs` | `0x7E847656` | yes | **`0x1A`** |
| `BaggageRead` / `LcbReadHf` / `LcbReadHfProgressive` | `0x7E84818E` / `0x7E847C45` / `0x7E847DF6` | HFS mode only | **`0x1B`** |
| `BaggageClose` / `RcCloseHf` / `FUN_7e847bd8` | `0x7E848023` / `0x7E847BAD` / `0x7E847BD8` | HFS mode only | **`0x1C`** |
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

Reply: static ack + dynamic-iterator. Client calls `iter->m0x10(iter)`
to get chunk length and `iter->m0xC(iter)` to get the bytes. Position
advances by the returned length. Standard DIRSRV-`GetShabby`-style
fragmentation applies (>1024 B requires chunking through
`build_service_packet`).

### `0x1C` HfCloseHf — request / reply

Request:

| Tag | Value |
|-----|-------|
| `0x01` | HFS handle byte |

Reply: static ack. Client immediately frees the local tracking struct.

### When does the client call these?

**Not on the MSN Today initial-open path.** Empirically, the current
server log with a caption-only body never receives `0x1A/0x1B/0x1C`.
The baggage callers in MVCL14N are `MVGroupLoad` (ordinal 15) and
the internal functions `FUN_7e883c50 / 7e886980 / 7e886b80` —
triggered by authored content referencing baggage by filename during
render, not by title open.

Baggage fires the first time the MedView engine's `MVFileIOProc` hits
a file the content graph references. So exercising this code path
requires MSN Today to actually enter its render path first (which
depends on `vaGetContents` returning non-zero; see §6b).

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

## 10. Open questions

- **Info_kind dialect on the wire path**. `TitleGetInfo`'s wire
  dispatch serves constants the local path doesn't
  (`0x03/0x05/0x0A/0x0C`..`0x10/0x0E/0x66-0x6E`). The
  local-path catalogue is now pinned: `0x6F` → font table handle
  (`title+0x08`), `0x69` → HFS volume byte (`title+0x88`), `0x0B` →
  topic count (`title+0x94`). Everything else is a body-section read.
- **TitleOpen reply DWORD 2** (`title+0x90`). Not read by any
  currently-catalogued `TitleGetInfo` local path; possibly a
  notification-epoch / session cookie consumed by the subscription
  pump (`FUN_7e844c7c`). Unverified.
- **Font table field layout** (section 0, bytes 2-15 and trailing
  descriptor block). The count + slot-offset pair is pinned but the
  font descriptor format the engine reads to populate HFONT slots is
  not. Safe today because the empty body path (`u16 size=0`) skips the
  decode entirely; MedView renders with its built-in default font.
- **152-byte record field layout** (section 3). Largest of the fixed
  records and the least documented in the MedView literature. MVTTL14C
  exposes no setters — the engine is the sole consumer. Blocks any
  attempt to synthesise layout/style from `4.ttl` content.
- **Cache notification format** (selectors `0x06` / `0x07` push
  answers). The wire payload shape used by the 1996 server to populate
  `PTR_DAT_7e84e130` via the subscription iterators is not yet RE'd —
  trace `FUN_7e844a3b @ 0x7E841A75` (third reference to the cache
  head) to recover it. Until then, va conversions fall through.
- **Per-title content cache** (`title+4` tree). Push channel is
  type-0 opcode `0xBF` via `FUN_7e8452d3 → FUN_7e8460df`. Current
  state (post-`33a0746`): `name_buf[0x26]=0x03` steers the layout
  walker `FUN_7e890fd0 → FUN_7e894c50` into case 3, which exits
  cleanly through the empty-children short-circuit at
  `FUN_7e894560 + 0x88` (`param_4[1] = *param_4`). Two empty pane
  rectangles paint top-left. The 0x03 dispatch is a layout-table-row
  tag the engine writes itself (§4.6), not the on-disk CSection
  version byte; the case-3 selection works because case 3 is the
  least-AV path for empty layout state. Two real forward steps from
  here, each requires its own scoped plan:
  1. **CSection CElementData children**. To populate the empty
     rectangles, the cached CSection must carry a non-empty
     children list. Requires pinning `VIEWDLL!CElementData::Serialize
     @ 0x40702E4C` and the case-4 / case-7 walker handlers.
  2. **Baggage delivery for CContent**. The actual content payload
     (HTML / image bytes from `Title.objects[8][sub]`) flows through
     selectors `0x1A` / `0x1B` / `0x1C`, which `medview.py` currently
     declines (ack-only / status=0). Requires a name → bytes resolver
     against `Title.objects` and a fragmenting reader honouring the
     1024-B client recv buffer.
- **Checksum semantics**. The new checksums returned in the TitleOpen
  reply are written back into `MVCache\<title>.tmp`. Whether the server
  treats them as (a) a content hash, (b) a version stamp, or (c) a
  client-opaque token is not yet nailed down; for the MVP they can be any
  stable non-zero pair.
