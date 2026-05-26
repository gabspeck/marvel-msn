# MEDVIEW Text-Stream Encoding

Wire-format specification for the MEDVIEW case-1 text-row chunk and its
adjacent navigation primitives, derived from static RE of MVCL14N.DLL
(MSN95 build, image base `0x7e880000`). Documents what the Win95 client
demands; the matching encoder/decoder is an implementation detail.

## 0. Scope & Sources

This doc pins every byte that flows past the type-0 `0xBF` cache push
when the client renders authored text. Companion docs:

- `docs/MEDVIEW.md` — selector matrix, attach handshake, 0xA5 status
  semantics.
- `docs/mosview-authored-text-and-font-re.md` — TopicItemPrefix tag
  inventory, packed text header field map, section-0 font table,
  border/style decoding, paint path.
- `docs/MOSVIEW-RENDER-PIPELINE.md` — end-to-end trace from
  TitleOpen reply to GDI text-out.

Ghidra ground truth (MSN95.gpr / MVCL14N.DLL):

- `MVDecodeTopicItemPrefix @ 0x7e897ed0` — preamble.
- `MVDecodePackedTextHeader @ 0x7e897ad0` — TLV body.
- `MVParseLayoutChunk @ 0x7e890fd0` — chunk envelope reader.
- `MVWalkLayoutSlots @ 0x7e894c50` — prefix-tag dispatch.
- `MVBuildTextItem @ 0x7e8915d0` — case-1 builder entry.
- `MVTextLayoutFSM @ 0x7e891810` — line-fit FSM.
- `MVDispatchControlRun @ 0x7e894ec0` — control-byte alphabet.
- `MVResolveNextTabStop @ 0x7e895620` — tab-stop consumer.
- `MVDispatchHfcNextPrevHfc @ 0x7e886010` — adjacent-chunk RPC dispatcher.
- `fMVHasNSR @ 0x7e8835b0` — NSR-collapse flag.
- `HfcNear @ 0x7e84589f` (MVTTL14C) — companion-buffer memcpy.

## 1. Wire Shape Overview

```
type-0 push  →  client cache (HfcCache keyed by (title_byte, key))
                    │
                    ▼
              MVParseLayoutChunk  (locks chunk via GlobalLock)
                    │
                    ▼   reads name_buf[0x26] as TopicItemPrefix tag
              MVDecodeTopicItemPrefix
                    │
                    ▼   normalized prefix → dispatched by tag
              MVWalkLayoutSlots
                    │
        ┌───────────┼─────────────────────────────┐
       text(1,0x20)  image-row(3,0x22)         col(4,0x23)   embed(5,0x24)
        │
        ▼
   MVBuildTextItem → MVTextLayoutFSM → MVLayoutTextRunStream
                                            │
                              ┌─────────────┼────────────┐
                            text walker             control walker
                            (text bytes)            (control stream)
                                            │
                                            ▼
                                  MVDispatchControlRun
                                  (style/tab/link/EOF)
                                            │
                                            ▼
                                    DrawTextSlot
                                  (ExtTextOutA)
```

End-of-content signalling rides selectors `0x16` (HfcNextPrevHfc) and
the type-0 `0xA5` status record. See §9.

## 2. Case-1 Chunk Anatomy (Byte-by-Byte)

A 0xBF cache push for a case-1 text row has this layout. All
offsets are relative to the wire start; `MVParseLayoutChunk` calls
`GlobalLock` on the chunk then reads `name_buf` (starting at
chunk+0x04) and the 60-byte content_block (starting at chunk+0x04 +
name_size).

| Wire offset       | Size      | Field                  | Notes                                                   |
|-------------------|-----------|------------------------|---------------------------------------------------------|
| `+0x00`           | 1         | `0xBF` opcode          | type-0 cache-insert marker                              |
| `+0x01`           | 1         | `title_byte`           | per-title routing key                                   |
| `+0x02`           | 2 LE      | `name_size`            | memcpy length; minimum `0x40`, capped at u16            |
| `+0x04..+0x07`    | 4         | zero pad               | `name_buf[0..3]`                                        |
| `+0x08`           | 4 LE      | prev contentsToken     | wire+0x8 — see §9.2                                     |
| `+0x0C`           | 4 LE      | `key`                  | cache key the engine matches                            |
| `+0x10`           | 4 LE      | next contentsToken     | wire+0x10 — see §9.2                                    |
| `+0x14..+0x29`    | 22        | zero pad               | `name_buf[0x10..0x25]`                                  |
| `+0x2A`           | 1         | TopicItemPrefix tag    | `name_buf[0x26]` — dispatched by MVWalkLayoutSlots      |
| `+0x2B..`         | variable  | preamble length varint | signed-int varint (§3)                                  |
| `+0x2B+P`         | variable  | (wide tag only) prefix_u16 varint | PackedUnsignedSmall — see §3.2                       |
| after preamble    | 6+        | packed text header TLV | §4                                                      |
| after TLV         | variable  | control stream + text  | §5; terminated by `0xFF`                                |
| pad to `+0x04+name_size` | 0+ | zero pad           | unused remainder of `name_buf`                          |
| `+0x04+name_size` | 60        | content_block          | NSR sentinel at offset +0x14 (= 0xFFFFFFFF for no NSR)  |

Dispatch on `name_buf[0x26]`:

| Tag           | Builder                       | Use                                                |
|---------------|-------------------------------|----------------------------------------------------|
| `1` / `0x20`  | MVBuildTextItem               | Text row (narrow / widened)                        |
| `3` / `0x22`  | MVBuildLayoutLine             | Bitmap / layout-line                               |
| `4` / `0x23`  | MVBuildColumnLayoutItem       | Column / multi-track row                           |
| `5` / `0x24`  | MVBuildEmbeddedWindowItem     | Embedded window / OLE                              |
| anything else | NO BUILDER → default arm      | AVs at +0xfc when `param_6[1]` is stale stack data |

`0x02` is recognised by `MVDecodeTopicItemPrefix` (raw-pair
short-circuit branch — copies four bytes verbatim into the normalized
prefix) but **falls through `MVWalkLayoutSlots`' default arm**, which
walks slot indices `[0..param_6[1])` over an uninitialised slot count
and faults on the slot-pool MOVSX read. There is no case-2
TOPICHEADER consumer; per-topic NSR collapse rides exclusively on the
content_block +0x14 sentinel.

## 3. Preamble Grammar

`MVDecodeTopicItemPrefix(out_norm, in_bytes)` decodes the leading
TopicItemPrefix into a 7-byte normalized block (`out_norm[0..6]`).
General form:

```
TopicItemPrefix
  out[0]   = u8 tag                       (raw byte from wire)
  out[1:5] = i32 length_value             (PackedWideScalar, signed-int varint)
  out[5:7] = u16 prefix_u16               (PackedUnsignedSmall) — wide tag only
            else 0
```

Short-circuit form (tag in {`0x02`, `0x21`}): verbatim 4-byte copy
into `out[1:5]` (no varint decode); if tag == `0x21`, an additional
u16 is verbatim-copied into `out[5:7]`. These tags are not exercised
by the case-1 text path.

### 3.1 Narrow form (tag ≤ 0x10)

Wire bytes: `[tag][PackedWideScalar length_value]`. `out[5..6]`
forced to 0 by the decoder.

### 3.2 Wide form (tag > 0x10)

Wire bytes: `[tag][PackedWideScalar length_value][PackedUnsignedSmall prefix_u16]`.

`prefix_u16` is consumer-stored at the per-chunk cache entry +0x1e
(`MVParseLayoutChunk` writes `entry+0x1e = (uint)local_f`). The
function computes `local_18 = entry+0x1e + entry+0x22 + 1` (where
`entry+0x22` is the chunk-handle's field_1c) but **does not use
local_18 in any subsequent expression** — it's a dead store. All
five callers of `MVParseLayoutChunk` (MVScanHotspotsForIndexOrCount,
MVRealizeView, MVApplyAbsoluteScrollPosition,
MVSeekVerticalLayoutSlots, MVCopyMediaToClipboard) were audited and
none read `entry+0x1e`. The field is effectively unused in MSN's
MVCL14N.DLL build. Wire chunks can encode `prefix_u16 = 0` safely.

### 3.3 `length_value` semantics

`MVParseLayoutChunk` computes the TEXT BASE pointer as:

```
text_base = chunk+0x2A + preamble_size + length_value
```

where `preamble_size` is `(short)prefix_advance_return - 0x2A` (the
delta from the start of `name_buf[0x26]` to the byte after the
preamble). Setting `length_value = TLV_size + control_stream_size`
places the first text byte immediately after the trailing `0xFF`
control byte.

### 3.4 PackedWideScalar / PackedUnsignedSmall

| Form               | LSB clear (narrow)               | LSB set (wide)                    |
|--------------------|----------------------------------|-----------------------------------|
| PackedWideScalar   | 2-byte u16: `(raw>>1) - 0x4000`. Range `[-0x4000, +0x3FFF]`. | 4-byte u32: `(raw>>1) + 0xC0000000`. Range `[-0x40000000, +0x3FFFFFFF]`. |
| PackedSignedSmall  | 1-byte: `(raw>>1) - 0x40`. Range `[-0x40, +0x3F]`. | 2-byte u16: `(raw>>1) + 0xC000`. Range `[-0x4000, +0x3FFF]`. |
| PackedUnsignedSmall| 1-byte: `raw>>1`. Range `[0, 0x7F]`. | 2-byte u16: `raw>>1`. Range `[0, 0x7FFF]`. |

Note: narrow vs wide for the **signed-int `length_value`** varint is
independent of narrow vs wide for the **TAG**. Text bodies larger
than 0x3FFF bytes are handled by the wide signed-int varint and stay
on the narrow tag `0x01`.

## 4. Packed Text Header (TLV)

`MVDecodePackedTextHeader(view, in_ptr, out_header)` consumes the
TLV that immediately follows the preamble and writes the normalized
header block (used by `MVTextLayoutFSM` and the layout walkers).
Minimum size: 6 bytes (narrow length + bitmap, no optional fields).

### 4.1 Length + presence bitmap

```
TLV
  PackedWideScalar  text_start_index    → out[0x00] i32
  u32 LE             presence_bitmap     → drives the optional sub-fields
```

`text_start_index` is treated by the engine as the offset (in text
bytes) from the chunk's text base to the run's first character.

### 4.2 Bitmap bit map

| Bit             | Effect                                                       |
|-----------------|--------------------------------------------------------------|
| `0x00000001`    | `out[0x04] u16 text_base_present` = 1                       |
| `0x00010000`    | `out[0x08] u16 header_flag_16_0` = 1; reads optional i32 at +0x12 |
| `0x01000000`    | `out[0x0a] u16 edge_metrics_enabled` = 1; reads optional u16 at +0x24 (3-byte read, low 2 stored) |
| `0x0C000000`    | `out[0x0c] u16 alignment_mode` = `(bitmap >> 26) & 3` (0=left, 1=right, 2=center) |
| `0x10000000`    | `out[0x0e] u16 header_flag_28` = 1                          |
| `0x00020000`    | reads PackedSignedSmall at +0x16 — `space_before` i16        |
| `0x00040000`    | reads PackedSignedSmall at +0x18 — `space_after` i16         |
| `0x00080000`    | reads PackedSignedSmall at +0x1a — `min_line_extent` i16     |
| `0x00100000`    | reads PackedSignedSmall at +0x1c — `left_indent` i16         |
| `0x00200000`    | reads PackedSignedSmall at +0x1e — `right_indent` i16        |
| `0x00400000`    | reads PackedSignedSmall at +0x20 — `first_line_indent` i16   |
| `0x00800000`    | reads PackedSignedSmall at +0x22 — `tab_interval` i16; if absent, defaults to `0x0048` when `(out[0x12] & 1) == 0`, else `0x02C6` |
| `0x02000000`    | reads PackedSignedSmall at +0x27 — `tab_stop_count` i16, then tab_stops[] (§4.4) |

Bit usage that does NOT cleanly fit (decoder-side observations):
- Bit `0x00010000` (16) does **two** things: gates the optional i32
  at +0x12 AND sets `header_flag_16_0` at +0x08. They share one
  presence flag.
- Bit `0x01000000` (24) similarly gates the +0x24 edge-metric u16
  AND sets `edge_metrics_enabled` at +0x0a.

### 4.3 Tab stops (bitmap bit `0x02000000`)

`tab_stops[]` is a length-prefixed list of `(stop_x, stop_payload)`
short pairs at normalized-header offset `+0x29` stride 4. Wire form
per pair:

```
PackedUnsignedSmall stop_x_raw          → bit 14 of decoded value flags "second follows"
if (stop_x_raw & 0x4000):
  PackedUnsignedSmall stop_payload      → out[0x2b + i*4] u16
stop_x = stop_x_raw & ~0x4000           → out[0x29 + i*4] u16
```

Constraints: `stop_x ∈ [0, 0x3FFF]` (bit 14 reserved as the
second-follows flag). `stop_payload ∈ [0, 0x7FFF]`; `stop_payload ==
0` is the engine's default (no special alignment) and is omitted
from the wire (no second short, bit 14 of `stop_x_raw` clear).

Consumer (`MVResolveNextTabStop @ 0x7e895620`): scans pairs in order;
the first pair whose `stop_x > current_x` wins. The engine returns
`stop_x` as the target column; `stop_payload` (when present) is
captured as a deferred alignment tag that `MVTextLayoutFSM` applies
when the next text run lands.

When no stop matches, the engine falls back to the default tab step:
`((current_x / tab_interval) + 1) * tab_interval`.

### 4.4 Multi-run styling is NOT in the TLV

The bit `0x02000000` pair list is exclusively tab stops. Mid-run
font / weight / colour switches happen via the `0x80` control byte
in the case-1 text stream (§5.1) — not via TLV pairs. Earlier
drafts mislabelled this field `inline_run_count`.

### 4.5 Round-trip table

| Decoded offset | Wire form                          | Gating bit       |
|----------------|------------------------------------|------------------|
| `+0x00` i32    | PackedWideScalar                   | (length, always) |
| `+0x04` u16    | bitmap bit 0                       | flag             |
| `+0x08` u16    | bitmap bit 16                      | flag             |
| `+0x0a` u16    | bitmap bit 24                      | flag             |
| `+0x0c` u16    | bitmap bits 26-27                  | 2-bit field      |
| `+0x0e` u16    | bitmap bit 28                      | flag             |
| `+0x12` i32    | PackedWideScalar                   | `0x10000`        |
| `+0x16` i16    | PackedSignedSmall                  | `0x20000`        |
| `+0x18` i16    | PackedSignedSmall                  | `0x40000`        |
| `+0x1a` i16    | PackedSignedSmall                  | `0x80000`        |
| `+0x1c` i16    | PackedSignedSmall                  | `0x100000`       |
| `+0x1e` i16    | PackedSignedSmall                  | `0x200000`       |
| `+0x20` i16    | PackedSignedSmall                  | `0x400000`       |
| `+0x22` i16    | PackedSignedSmall (default 0x48 or 0x2C6) | `0x800000`|
| `+0x24` u16    | 3-byte read, low 2 stored          | `0x1000000`      |
| `+0x27` i16    | PackedSignedSmall (count)          | `0x2000000`      |
| `+0x29 + i*4`  | tab_stops[i] = (stop_x, stop_payload) | (per pair)    |

## 5. Control-Stream Alphabet

`MVDispatchControlRun @ 0x7e894ec0` is the per-control-byte dispatcher.
Each entry's wire form, byte advance, walker side effect, and return
status form the table below. The "status" column is `MVTextLayoutFSM`'s
0-6 alphabet: `0`=continue, `1`=run boundary, `2`=retry/split,
`3`/`4`=deferred status markers, `5`=EOF, `6`=allocation fail.

| Wire tag        | Wire form                          | Effect                                                                                                                                              | Status |
|-----------------|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|--------|
| `0x20`          | `[0x20][5 B opaque]`               | Emit pending text slot; advance control cursor +5; marker byte at slot+0x3d = `'2'`                                                                 | 0      |
| `0x21`          | `[0x21][3 B opaque]`               | Same as 0x20 but advance +3                                                                                                                          | 0      |
| `0x22`          | `[0x22][7 B opaque]`               | Same as 0x20 but advance +7                                                                                                                          | 0      |
| `0x80`          | `[0x80][u16 style_id]`             | Emit text; `ApplyTextStyleToHdc(viewer, style_id)`; refresh line metrics via `MVUpdateTextFlowEdges`; runTemplate[0] = style_id; advance +3          | 0      |
| `0x81`          | `[0x81]`                           | Record pending marker `'4'` at slot+0x3d; advance +1                                                                                                | 3      |
| `0x82`          | `[0x82]`                           | Record pending marker `'3'` at slot+0x3d; advance +1                                                                                                | 4      |
| `0x83`          | `[0x83]`                           | Emit text; `MVResolveNextTabStop` resolves target x; if `target_x > right_edge` AND nested-depth==0 → status 2; else apply tab-stop payload         | 1 or 2 |
| `0x85`          | `[0x85][u16 span]`                 | Store deferred-span value in runTemplate[0x1b]; record marker `'6'`; advance +3                                                                     | 2      |
| `0x86`          | `[0x86][TopicItemPrefix]`           | Emit text; `MVDecodeTopicItemPrefix` reads nested child stream's preamble; advance text source to child stream; runTemplate[1] = 1                  | 0      |
| `0x87`          | `[0x87][TopicItemPrefix]`           | `MVPoolEnsureCapacity(viewer+0xfe, 0x1e)` allocates a 0x1e continuation record; `*nestedRecord = 1`; `MVWalkLayoutSlots` walks child slots          | 1 / 6  |
| `0x88`          | `[0x88][TopicItemPrefix]`           | Same as 0x87 but `*nestedRecord = 0`                                                                                                                | 1 / 6  |
| `0x89`          | `[0x89]`                           | Emit text; clear active link (runTemplate[7] = runTemplate[8] = -1); advance text +1                                                                | 0      |
| `0x8b`          | `[0x8b]`                           | `MeasureTextRunWidth(viewer, &DAT_7e899b80, 1, 0)` adds a measured spacer; record marker `'7'`; advance +1                                          | 0      |
| `0x8c`          | `[0x8c]`                           | Decrement run length by 1; `MeasureTextRunWidth` over the shortened run; record marker `'8'`; advance text +2                                       | 1      |
| `0xC0..0xC7`    | `[tag][4 B opaque]`                | Emit text; new link group: runTemplate[7] = layoutState[2] - cursor_offset; viewer+0x130 link counter increments; advance +5                        | 0      |
| any tag with `(tag & 0xD8) != 0xC0` not listed above | `[tag][u16 payload_len][payload_len B]` | Same as 0xC0..0xC7 but variable payload                                                                                  | 0      |
| `0xFF`          | `[0xFF]`                           | EOF — record marker `'9'`; advance +1                                                                                                               | 5      |

Line-edge override: if `viewer+0x10a` (nested depth) > 0 AND
`layoutState[3] == 0` AND `runTemplate[0x15] == layoutState[0xb]`
(current x == line.x_start), the dispatcher forces status = 2 after
the per-tag branch, regardless of the tag's own return.

### 5.1 Style switch (`0x80`)

The single primitive for mid-run styling. `style_id` is a `u16`
index into the title's CStyleSheet font/colour table; on
`ApplyTextStyleToHdc` success, line metrics refresh against the new
font's ascent/descent and any subsequent text in the same chunk
paints with the new style. Multiple `0x80` runs in one chunk are
permitted — each emits a fresh tag-1 slot.

### 5.2 Hyperlink groups (`0xC0..0xC7` and default link)

The default-arm group covers tags `0xC8..0xFE` (excluding `0xFF`)
plus anything else that didn't hit a specific case. The mask
`(tag & 0xD8) == 0xC0` chooses between:

- Fixed 5-byte form (mask match): `[tag][4 B opaque payload]`.
- Variable form (otherwise): `[tag][u16 payload_len][payload_len B
  payload]`.

In both forms the engine records `runTemplate[7] = layoutState[2] -
cursor_offset` so subsequent text bytes carry the link group's base
offset.

### 5.3 Walker invariants

- Text walker and control walker are independent cursors. The text
  walker advances over printable bytes; on encountering NUL (or
  reaching the chunk's text-end pad), control passes to the control
  walker which reads tags from end-of-TLV onward.
- The minimum-viable control stream is `0x80 <style u16> 0xFF`
  (3 bytes for the style switch + 1 byte EOF). Without a leading
  `0x80`, `MVDispatchControlRun`'s default case treats the first
  text byte as a link tag and reads `*(u16 *)(text+1)`, walking
  out of bounds.

## 6. Tag-1 Slot Field Map

See `docs/mosview-authored-text-and-font-re.md` §"0x47 viewer record"
for the per-slot byte layout (47-byte stride at `viewer+0xf6`).
Fields that the case-1 path writes:

| Slot offset | Field                                                                |
|-------------|----------------------------------------------------------------------|
| `+0x00`     | tag byte (= 1 for text)                                              |
| `+0x05`     | `x` after `param_6[2]` bias                                          |
| `+0x07`     | `y` after `param_6[3]` bias                                          |
| `+0x0B`     | `w` (used by extent fold)                                            |
| `+0x0D`     | `h`                                                                  |
| `+0x39`     | text byte offset into chunk's text base (= TLV[0x00])                |
| `+0x3D`     | walked text length (NUL- or chunk_end-terminated)                    |
| `+0x3F`     | font style id (set by `0x80` control or primed at chunk entry)       |

## 7. TextTree CContent Body Grammar — PARTIAL

TextTree is the rich-text container Blackbird-authored stories use
(prefix `01 05` after CK-decompression). The full on-disk grammar
is not yet pinned, but the **text-segment opcode** is.

### 7.1 Text-segment opcode (pinned)

Each visible run of prose in a TextTree body is encoded as:

```
TextSegment
  u8 opcode = 0x03
  count_varint length         (CElementData-style: 1 B if <0xFF,
                               else 0xFF + u16, else 0xFF + 0xFFFF + u32)
  byte[length] ascii_text
```

The `length` encoding matches `CElementData::Serialize @ 0x40702e4c`
(VIEWDLL.DLL) — the same variable-length count used elsewhere in
Blackbird's MFC persist streams.

Pinned against two fixtures:

- `tests/assets/story_test.ttl 8/2` (85 B, plain prose):
  `[01 05] ... [03 12 "Calendar of Events"] ... [03 1d "here's
  what's been happenin' "]`
- `tests/assets/story_test.ttl 8/6` (1516 B, picture-INTRUDE +
  itemised list): 10 text segments preceded by a `PICTURE.PictureCtrl.1`
  CLSID + `FILE`/`DATA1` property pair.

### 7.2 Picture intrusion (pinned shape)

A picture record embeds an OLE-style property table inside the
TextTree body. Layout pinned against `tests/assets/story_test.ttl
8/6`:

```
[u8 5][CLSID][u8 name_len][CLSID name e.g. "PICTURE.PictureCtrl.1"]
[u8 2][CX][u8 4][width digits]
[u8 2][CY][u8 3][height digits]
[u8 4][FILE][u8 5][DATA1]
[control bytes / placeholder values, varies by encoder]
[u8 name_len][ASCII filename e.g. "bitmap.bmp"][NUL padding]
[u32 size=16][16-byte CLSID — picture's IUID into title's CProxyTable]
[trailing metadata]
```

Decoder surface:

- `PictureRef.clsid` — `"PICTURE.PictureCtrl.1"` (the BBCTL control
  CLSID).
- `PictureRef.filename` — embedded picture filename (e.g.
  `"bitmap.bmp"`).
- `PictureRef.iuid` — 16-byte CLSID identifying the picture's COM
  control instance.

Note: `PictureRef.iuid` is **not** a direct key into the title's
`CProxyTable`. CProxyTable entries are flat `(u32 proxy_key,
u32 handle_index)` pairs with no IUID field — confirmed by parsing
`story_test.ttl`'s `7/0`..`7/2` proxy tables. The picture's
bitmap CContent is enumerated positionally via the title's
resource folder (Nth picture INTRUDE record → Nth proxy_key in the
resource folder, by document order). The IUID is the engine's
identifier for per-picture state (size, layout properties)
allocated at authoring time.

### 7.3 Parallel-streams architecture

**A Blackbird story persists as TWO parallel CContent streams**,
written by `CRemoteText::AddTreeAndRuns @ 0x40720c1c` (VIEWDLL.DLL):

| Proxy key | CContent type | Header magic | Role                          |
|-----------|---------------|--------------|--------------------------------|
| `0x1400`  | `"TextTree"`  | `01 05`      | Segmented text + picture INTRUDE records (§7.1, §7.2) |
| `0x1500`  | `"TextRuns"`  | `02 00`      | Per-run paragraph-style markers + prose bytes |

Per the decompile, `AddTreeAndRuns`:

1. Opens a 0x1000-byte buffer on the remote proxy at key `0x1400`,
   writes a leading `0x01` byte, then serializes `this+0x44`
   (CTextTree) via vtable+8. Names the stream `"TextTree"`.
2. Opens a 0x1000-byte buffer at key `0x1500`, serializes
   `this+0x48` (CTextRuns array, populated by
   `CRemoteText::ExtractRuns @ 0x40720917`) via vtable+8. Names
   the stream `"TextRuns"`.

`ExtractRuns` walks the in-memory CElementNode tree (the same one
that gets serialized as TextTree) and builds the runs array from
nodes whose element-data flags `(byte & 3) == 3` AND data length
> 0x20 — i.e. one entry per styled prose run.

### 7.4 TextRuns body grammar (pinned)

The TextRuns CContent body is
`CTypedPtrArray<CElementData>::Serialize @ 0x407092a6` (VIEWDLL.DLL)
output — a flat array of prose blobs with no inline style metadata:

```
TextRuns body
  u16 count                      (CArchive::WriteCount — narrow form
                                  if < 0xFFFF, else 0xFFFF + u32 wide)
  count × CElementData:
    u8 length                    (CElementData::Serialize — 1-byte
                                  form if < 0xFF; else 0xFF + u16;
                                  else 0xFF + 0xFFFF + u32)
    length B prose bytes         (ASCII)
```

Pinned against `tests/assets/story_test.ttl 8/7` (122 B):

| Offset | Bytes              | Meaning                                                |
|--------|--------------------|--------------------------------------------------------|
| `+0x00` | `02 00`           | u16 count = 2                                          |
| `+0x02` | `53`              | element[0] length = 0x53 (83)                          |
| `+0x03` | "This is an example…Extensions! " (83 B) | element[0] prose             |
| `+0x56` | `23`              | element[1] length = 0x23 (35)                          |
| `+0x57` | "Ordered list is supported as well: " (35 B) | element[1] prose        |

Earlier drafts of this doc misread the leading length bytes (`0x53`
= 'S', `0x23` = '#') as paragraph-style markers. They are length
prefixes, not data. **Per-segment style information is not present
in the TextRuns stream**; it lives in the parallel TextTree stream
(§7.5).

### 7.5 TextTree generation (external COM parser)

The TextTree stream is **not generated inside VIEWDLL.DLL** — it's
produced by an external COM component that VIEWDLL instantiates
via `CoCreateInstance` from `CRemoteText::CreateParseTree @
0x40720462`:

- CLSID at `0x407508e0`: `f6a0e000-f5c6-11cd-9945-00aa0051f5b7`
- IID  at `0x407506e0`: `f3a6c930-f599-11cd-9945-00aa0051f5b7`

The vendor suffix `9945-00aa0051f5b7` matches the Microsoft Blackbird
OUI; the component is the text-document parser that VIEWDLL feeds a
Word/RTF document into and gets back a serialized CElementNode tree
+ IStorage. The tree pointer is stashed at `this+0x44`; calling
`vtable[2]` (Serialize) on it emits the TextTree bytes.

This means the exhaustive TextTree opcode inventory is **owned by
the external COM component**, not VIEWDLL. Static RE of VIEWDLL
alone cannot enumerate every opcode; the partial decoder (§7.6) is
the practical ceiling for static analysis. Further pinning requires
either RE-ing the COM component (separate binary) or runtime
profiling.

### 7.6 Per-element style serializers (pinned wire layout)

When the COM parser emits CCharProps / CParaProps / CStyle records
inside the TextTree byte stream, they use these MFC-virtual
serializer layouts (all in VIEWDLL.DLL):

- `CContent::Serialize @ 0x4073a185` — outer pipe; loops 0x1000-byte
  reads/writes between a CFile-derived source and the CArchive.
- `CCharProps::Serialize @ 0x40707fcc` — variant 0x02 form is
  `[u8 0x02][u8 pres_a][u8 pres_b]<gated fields>`; fields gated by
  `pres_a` bit set AND `pres_b` bit set: `u16 font_index`,
  `u16 field_08`, `u16 field_0a`, `u32 field_0c`, `u32 field_10`.
  `pres_a` bit clear ⇒ value = -1 (cleared); `pres_b` bit clear
  ⇒ value = -2 (inherited from parent style). Legacy variant
  `0x01` form: 14 B fixed record.
- `CParaProps::Serialize @ 0x407082e2`
- `CStyle::Serialize @ 0x40707d6f`
- `CElementData::Serialize @ 0x40702e4c` — generic blob wrapper:
  variable-length count (1 B if <0xFF, else `0xFF + u16`, else
  `0xFF + 0xFFFF + u32`) followed by raw bytes.

### 7.7 Current decoder surface

`server.services.medview.ccontent.decode_texttree(raw)` returns a
`TextTreeContent` with:

- `.text` — concatenated text segments joined by `'\n'` (document
  order).
- `.segments` — `tuple[(byte_offset, text), ...]` for callers that
  need per-segment positioning.
- `.style_runs` — empty (style metadata lives in TextTree's
  interleaved CCharProps/CParaProps records, written by an external
  COM parser per §7.5; not resolvable from VIEWDLL static RE alone).
- `.picture_refs` — `tuple[PictureRef, ...]` of CLSID names.
- `.raw_payload` — bytes after the 2-byte `01 05` magic.

## 8. Authored → Wire Mapping

### 8.1 Pinned

| Authored side                                             | Wire side                                            |
|-----------------------------------------------------------|------------------------------------------------------|
| TextTree `[0x03 length text]` segment                     | `0x80 <style_id u16>` control + NUL + text in case-1 |
| TextRuns CElementData blob (§7.4)                         | `0x80 <style_id u16>` control + NUL + prose in case-1 |
| `CStyleSheet` font key (CStyleSheet's font_entries array) | Section-0 face slot index (per `docs/mosview-authored-text-and-font-re.md` §"Section 0 Font Table") |

### 8.2 Per-segment style_id resolution — external

TextRuns has no inline style metadata (§7.4) and TextTree's
opcode-level interleaving is owned by an external COM component
(§7.5). Until the COM parser is RE'd or runtime-profiled, every
case-1 segment ships with `style_id = 0` (the title's default
CStyleSheet entry). The server's `_collect_styled_segments`
defaults to that value; the wire encoder accepts arbitrary
style_id values, so future style resolution slots in without
changing the lowering path.

## 9. Multi-Chunk Topic Navigation

Vertical scroll inside a topic walks adjacent chunks via
`MVSeekVerticalLayoutSlots` and the `0x16` (HfcNextPrevHfc) selector.
Horizontal topic switching (browse back / browse forward) is
handled by `MOSVIEW.NavigateViewerSelection` opening a fresh title
session — not by case-1 chunk chains.

### 9.1 contentsToken value space

Each 0xBF chunk carries two 32-bit contentsToken slots:

- `wire+0x08` — prev contentsToken (leading probe target).
- `wire+0x10` — next contentsToken (trailing probe target).

Sentinel values:

| Value          | Meaning                                                            |
|----------------|--------------------------------------------------------------------|
| `0x00000000`   | "first cache key" — collides with the initial chunk's `key=0`. Setting wire+0x8 / wire+0x10 to 0 causes `MVSeekVerticalLayoutSlots` to re-parse the same chunk and append duplicate slots. |
| `0xFFFFFFFF`   | `HfcCache_FindEntryAndPromote` early-returns NULL → engine spins in HfcNextPrevHfc's retry wait with `errOut=0`. Avoid. |
| any other      | Cache lookup; on miss → `0x16` RPC.                                |

Recommended terminator: `0xFFFFFFFE` (unambiguous, neither sentinel
nor collision with key=0). This forces the cache lookup to miss,
firing a `0x16` RPC, and the server's `0xA5` reply (status `0x3F3`)
terminates the seek loop.

### 9.2 wire+0x8 / wire+0x10 cache probes

`MVTTL14C!HfcNextPrevHfc` reads `name_buf[+4]` (= wire+0x8) for
direction=0 leading probes and `name_buf[+0xc]` (= wire+0x10) for
direction=1 trailing probes, then looks up that token in HfcCache.

### 9.3 `0x16` firing conditions

Triggered when `MVSeekVerticalLayoutSlots` walks past the leading
or trailing chunk and the cache lookup misses (i.e. the
contentsToken at wire+0x8 / wire+0x10 isn't in HfcCache). Each
miss spawns one `0x16` RPC.

### 9.4 `0xA5` HfcStatusRecord status codes

Type-0 8-byte record on the cache subscription:

```
+0x00 u8  0xA5
+0x01 u8  title_byte
+0x02 u16 status
+0x04 u32 contents_token
```

Observed status codes:

| Value     | Meaning                                                                 |
|-----------|-------------------------------------------------------------------------|
| `0`       | Success-but-empty; seek loop short-circuits without paging              |
| `0x3F3`   | End-of-content; seek loop sets `hitLeadingEnd` or `hitTrailingEnd` true |
| `0xFFFF`  | "no data" per the wrappers' fail-on-zero patterns; not observed in practice |

When `0x3F3` arrives, the engine clears `viewer[+0x84]` (V-scrollbar
enable flag) iff `currentTailGapY < 0`.

### 9.5 case-2 TOPICHEADER

**Dead**. `MVWalkLayoutSlots` dispatches only on tags
{1, 3, 4, 5, 0x20, 0x22, 0x23, 0x24}. Tag `0x02` is decodable by
`MVDecodeTopicItemPrefix` but falls through `MVWalkLayoutSlots`'
default arm and triggers an AV at +0xfc when `param_6[1]`
(`last_view_record`) is uninitialised stack data. Per-topic NSR
collapse is achieved exclusively via the 60-byte content_block's
+0x14 sentinel (`fMVHasNSR` reads `viewer+0x4c` after `HfcNear`
copies the companion buffer).

## 10. Wire Byte Specifications (Encoder Targets)

Implementer's checklist. Each encoder must satisfy:

1. **case1_preamble(length_value, tag, prefix_u16=None)** — emits
   `[tag][PackedWideScalar][PackedUnsignedSmall?]`. `prefix_u16` is
   present only when `tag > 0x10`.
2. **packed_text_header(...)** — emits the TLV with at minimum
   `[PackedWideScalar text_start_index][u32 bitmap]`; optional
   fields gated by their bitmap bits per §4.2; tab stops per §4.3.
3. **case1_chunk(text, style_runs, tab_stops, …)** — composes (1)
   + (2) + control stream + text into the 4 + name_size + 60 byte
   envelope. The minimum-viable control stream is `0x80 <style
   u16> 0xFF` followed by `<NUL>text<NUL>`. Each style switch
   inside the text emits a `0x80` control plus a NUL in the text
   walker (to cede to the control walker).
4. **topic_chain_terminator()** — stamps wire+0x8 / wire+0x10 with
   `0xFFFFFFFE` so adjacent-chunk seeks terminate cleanly via the
   server's `0xA5` reply.
5. **content_block_no_nsr()** — stamps the 60-byte content_block's
   offset +0x14 with `0xFFFFFFFF` so per-topic NSR pane collapses.

## 11. Fixture Coverage Matrix

| Fixture path                                        | Path exercised                                                       |
|-----------------------------------------------------|----------------------------------------------------------------------|
| `tests/assets/story_test.ttl` `8/7` (TextRuns 122 B) | TextRuns decoder + case-3 (BBDESIGN captions fallback)               |
| `tests/assets/story_test.ttl` `8/2` (TextTree 85 B) | TextTree text-segment decode (2 segments, no picture)                |
| `tests/assets/story_test.ttl` `8/6` (TextTree 1516 B) | TextTree text-segment decode + picture INTRUDE detection             |
| `tests/assets/all_controls.ttl`                     | BBCTL site coverage (captions / shortcuts / outlines / audio / buttons) |
| `tests/assets/captions_test.ttl`                    | BBDESIGN caption-only title (case-3 + kind=8 WMF baggage)            |
| `tests/assets/multi_page_title.ttl`                 | Multi-page lower (per-page bm baggage map)                           |
| `binaries/MVPUBKIT/{MMAG,MVAPIREF,MVAUTHOR}.MVB`    | Multimedia Viewer 2.0 archive enumeration (NOT TextTree)             |

Note on MVPUBKIT: the `.MVB` archives use Microsoft Multimedia
Viewer 2.0's archive format (magic `3F5F0300`, B+ tree directory).
Their `|TOPIC` streams carry MV's own RTF-token-stream encoding, NOT
Blackbird TextTree CContent. The plan's original W7 premise (carve
TextTree from MVPUBKIT) was incorrect — TextTree is exclusively a
Blackbird-side container. The MVB parser at
`scripts/inspect_mvb_archive.py` exists for enumerating the archive
internals; deeper |TOPIC RTF-token decode is a separate workstream
(out of scope here).

## 12. Open Questions

All previously-open questions for this doc are now resolved within
the static-RE-of-MSN-binaries scope:

- §3.2 (prefix_u16): Closed. Field is a dead write in
  `MVParseLayoutChunk` — no caller reads `entry+0x1e`. Safe to
  encode as 0.
- §7.2 (picture INTRUDE): Closed. `PictureRef.iuid` is the COM
  control instance ID; resolution to bitmap CContent is positional
  via the title's resource folder, not key-based via CProxyTable.
- §7.5 (external COM parser opcodes): Identified scope. CLSID
  `f6a0e000-f5c6-11cd-9945-00aa0051f5b7` is referenced by VIEWDLL,
  BBDESIGN.EXE, FIND.OCX, and PPG.OCX in an MFC class-factory
  list. The TextTree byte stream is the COM service's output;
  exhaustive opcode enumeration requires running that registered
  server (out of scope for MSN client RE since the partial decoder
  is sufficient for first-pass rendering).

Out-of-scope items (intrinsically external):

- MV 2.0 `|TOPIC` RTF-token decode for MVPUBKIT's
  MMAG/MVAPIREF/MVAUTHOR archives. Distinct format from Blackbird
  TextTree; not needed for MSN MOSVIEW since MSN titles are
  always Blackbird-authored.
