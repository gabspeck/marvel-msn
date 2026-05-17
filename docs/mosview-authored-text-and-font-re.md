# MediaView First Authored Text / Section-0 RE Notes

This note records the static RE pass for the first stock-MOSVIEW milestone:
rendering one authored text story with a real MediaView text item and a real
section-0 font table.

Related consumer paths in `MVCL14N.DLL`:

- `MVDecodeTopicItemPrefix`
  - normalized topic-item prefix decode
- `MVDecodePackedTextHeader`
  - packed text-item header decode
- `MVBuildTextItem`
  - top-level text item builder
- `MVTextLayoutFSM`
  - text layout state machine
- `DrawTextSlot`
  - final text draw path
- `hMVSetFontTable`
- `FUN_7e896590`
- `FUN_7e896610`
- `FUN_7e896760`
- `FUN_7e896ba0`
- `FUN_7e8963b0`

The current `scripts/synthesize_m14_from_ttl.py` font blob is still a synthetic
placeholder. It does not implement the real section-0 schema below.

## Text Item Prefix

`MVDecodeTopicItemPrefix` normalizes the leading topic-item prefix into a
7-byte block before `MVDecodePackedTextHeader` (or any sibling builder)
runs. The decoder splits on the tag byte:

```text
TopicItemPrefix (general form)
  u8 tag
  PackedWideScalar scalar_dword       # written to out+1
  if tag > 0x10:
    PackedUnsignedSmall prefix_u16    # written to out+5
  else:
    out+5 = 0                         # narrow form sentinel

TopicItemPrefix (raw-pair short-circuit; tag == 0x02 or tag == 0x21)
  u8 tag
  u32 raw_dword                       # copied verbatim to out+1
  if tag == 0x21:
    u16 raw_u16                       # copied verbatim to out+5
```

Tag inventory accepted by the layout walker (`MVWalkLayoutSlots`, decoded
prefix tag at `out[0]`):

| tag    | family                            | builder dispatched              |
| ------ | --------------------------------- | ------------------------------- |
| `0x01` | narrow text item                  | `MVBuildTextItem`               |
| `0x20` | widened text item                 | `MVBuildTextItem`               |
| `0x03` | narrow layout-line / image row    | `MVBuildLayoutLine`             |
| `0x22` | widened layout-line / image row   | `MVBuildLayoutLine`             |
| `0x04` | narrow column / multi-track row   | `MVBuildColumnLayoutItem`       |
| `0x23` | widened column / multi-track row  | `MVBuildColumnLayoutItem`       |
| `0x05` | narrow embedded window / OLE      | `MVBuildEmbeddedWindowItem`     |
| `0x24` | widened embedded window / OLE     | `MVBuildEmbeddedWindowItem`     |

Any other tag falls through the `MVWalkLayoutSlots` switch with no
builder dispatched — see §"Layout Walker AV Conditions".

Widened-form `prefix_u16` consumer: `MVParseLayoutChunk` reads it as
`local_f` from the normalized prefix block and stores it at the chunk
record offset `+0x1e`. The downstream code computes
`extent_total = chunk+0x1e + chunk+0x22 + 1`, where `chunk+0x22` is the
chunk-handle's `field_1c` (set by `MVChunkHandleGetField1c`). This pins
the widened prefix_u16 as a per-chunk extent contribution (an
inline-resource size or trailing-blob length); its exact semantic in the
extent math is not yet pinned beyond the additive role. For first plain
text emission the narrow `0x01` form (which forces `prefix_u16 = 0`) is
sufficient.

Packed integer forms used by the text path:

- `PackedWideScalar`
  - if low bit is `0`: consume `u16`, decode as `(raw >> 1) - 0x4000`
  - if low bit is `1`: consume `u32`, decode as `(raw >> 1) - 0x40000000`
- `PackedSignedSmall`
  - if low bit is `0`: consume `u8`, decode as `(raw >> 1) - 0x40`
  - if low bit is `1`: consume `u16`, decode as `(raw >> 1) - 0x4000`
- `PackedUnsignedSmall`
  - if low bit is `0`: consume `u8`, decode as `raw >> 1`
  - if low bit is `1`: consume `u16`, decode as `raw >> 1`

## Text Header Grammar

`MVDecodePackedTextHeader` expands the packed text-item header into a normalized local
buffer. The names below are consumer-derived. Some provenance on the authored
side is still open, but all fields required by the first text-paint path are
named.

### Normalized Header Layout

| offset | size | name | first-paint role |
| --- | --- | --- | --- |
| `0x00` | `i32` | `text_start_index` | starting character index in the shared story buffer |
| `0x04` | `u16` | `text_base_present` | whether `0x12` was explicitly present |
| `0x08` | `u16` | `header_flag_16_0` | decoded flag bit; not a first-paint blocker |
| `0x0a` | `u16` | `edge_metrics_enabled` | gates `FUN_7e893cb0(..., 1/4)` side metrics |
| `0x0c` | `u16` | `alignment_mode` | `0 = left`, `1 = right`, `2 = center` from caller behavior |
| `0x0e` | `u16` | `header_flag_28` | decoded flag bit; not a first-paint blocker |
| `0x12` | `i32` | `text_base_or_mode` | optional signed scalar; only its low bit is proven to affect the default tab interval |
| `0x16` | `i16` | `space_before` | added to the running Y before line layout |
| `0x18` | `i16` | `space_after` | added after line completion |
| `0x1a` | `i16` | `min_line_extent` | minimum line height / vertical extent |
| `0x1c` | `i16` | `left_indent` | initial horizontal extent contribution for the line |
| `0x1e` | `i16` | `right_indent` | subtracted from the available width |
| `0x20` | `i16` | `first_line_indent` | one-shot extra horizontal extent applied at line start |
| `0x22` | `i16` | `tab_interval` | default-tab horizontal spacing used by `MVResolveNextTabStop` |
| `0x24` | `u16` | `edge_metric_flags` | border side mask + style bits (see below) |
| `0x27` | `i16` | `tab_stop_count` | count of trailing explicit tab-stop entries |
| `0x29` | `4 * count` | `tab_stops[]` | repeated `(u16 stop_x, u16 stop_payload)`; see below |

### `edge_metric_flags` Bit Layout (`MVResolveBorderSideThickness`)

The `+0x24` field is the layout item's border bitmask. `MVResolveBorderSideThickness`
(side selector `1=top`, `2=left`, `3=bottom`, `4=right`) takes
`itemRecord+0x24` and returns 0 when the requested side is disabled,
otherwise the pixel thickness selected by the style bits:

| bit       | mask   | meaning                                                                  |
| --------- | ------ | ------------------------------------------------------------------------ |
| 0         | `0x01` | rectangle / all-sides; sets every side regardless of the side bits below |
| 1         | `0x02` | top side                                                                  |
| 2         | `0x04` | left side                                                                 |
| 3         | `0x08` | bottom side                                                               |
| 4         | `0x10` | right side                                                                |
| 5..7      | `0xE0` | border style selector (`(flags >> 5) & 7`):                              |
|           |        |   `0`,`4` → 5 px thickness                                               |
|           |        |   `1`,`3` → 6 px thickness                                               |
|           |        |   `2`     → 7 px thickness                                               |
|           |        |   other   → 0 (no draw)                                                   |

`edge_metrics_enabled` (header+0x0a) is the master gate. When zero,
`MVTextLayoutFSM` skips the `MVResolveBorderSideThickness` calls on
sides 1 and 4 entirely. When set, those calls subtract the resolved
thickness from `available_width` (right side) and add it to the line's
y baseline contribution (top side).

The same flags field is consumed for paint by `MVPaintBorderSlot` (slot
+0x39): bit 0 selects rectangle mode (`GDI32::Rectangle`); bits 1..4
choose which sides emit `LineTo` segments; bits 5..7 select the
border style (single line / double line / inset / shadow).

### `tab_stops[]` Entry Layout (`MVResolveNextTabStop`)

Each entry is 4 bytes: `(u16 stop_x, u16 stop_payload)` at
`header+0x29 + i*4`. Decoded by `MVDecodePackedTextHeader`:

1. Read `pair.first` as a `PackedUnsignedSmall`. If bit `0x4000` of the
   raw decoded word is set, the wire stream contains a second
   `PackedUnsignedSmall` for `pair.second` (the payload). Otherwise
   `pair.second = 0`.
2. After both reads, the decoder masks bit `0x4000` off `pair.first`,
   so the resulting `stop_x` is the position with no flag residue.

Scaling: `MVScaleTextMetrics` walks the array and scales each
`stop_x` by `LOGPIXELSX * title_scale / (sVar3 * 100)` — identical to
the indent / first_line_indent / tab_interval scaling. `stop_payload`
is not scaled.

Consumer (`MVResolveNextTabStop`):

```c
for (i = 0; i < tab_stop_count; i++) {
    if (runTemplate.x < tab_stops[i].stop_x) {
        *payloadOut = tab_stops[i].stop_payload;
        return tab_stops[i].stop_x;
    }
}
*payloadOut = 0;
return ((runTemplate.x / tab_interval) + 1) * tab_interval;
```

When the tab dispatcher (`MVDispatchControlRun` case `0x83`) hits an
explicit stop with a non-zero payload, it stashes the payload into
`runTemplate[0x21]` for deferred alignment by the next slot emission.
A zero payload means "plain left tab — just move pen X to `stop_x`."

### Fields That Matter Immediately

The first authored text render only needs these fields to be correct:

- `text_start_index`
- `alignment_mode`
- `space_before`
- `space_after`
- `min_line_extent`
- `left_indent`
- `right_indent`
- `first_line_indent`
- `tab_interval`
- `edge_metrics_enabled`
- `edge_metric_flags`

The remaining scalar bits are currently pass-through / mode bits. They should be
preserved if known, but they are not blockers for one plain left-aligned text
block.

### Metric Scaling

`MVScaleTextMetrics` proves that the header is still in authored/logical units when
decoded:

- `0x16`, `0x18`, `0x1a` scale with `LOGPIXELSY`
- `0x1c`, `0x1e`, `0x20`, `0x22`, and each explicit `tab_stops[i].stop_x`
  scale with `LOGPIXELSX`
- both axes also multiply by the title scale factor at `title + 0x7c`

If `tab_interval` is omitted, `MVDecodePackedTextHeader` synthesizes a default from
`text_base_or_mode & 1`:

- low bit clear -> default becomes `0x0048`
- low bit set -> default becomes `0x02c6`

## `MVBuildTextItem`: Item Builder Mapping

`MVBuildTextItem` does not draw directly. It:

1. decodes the topic-item prefix with `MVDecodeTopicItemPrefix`
2. decodes the packed header with `MVDecodePackedTextHeader`
3. scales header metrics with `MVScaleTextMetrics`
4. seeds a transient layout state block
5. loops `MVTextLayoutFSM` until the item finishes or allocation fails
6. post-adjusts emitted viewer records and writes extents back to the caller

The important state projections are:

- `state.header = decoded_header`
- `state.paragraph_ctx = caller_paragraph_ctx`
- `state.current_char_index = header.text_start_index`
- `state.current_y = caller_paragraph_ctx->y`
- `state.first_view_record = *item_out`
- `state.available_width = requested_width - header.right_indent - optional edge metric`
- `state.current_line_width = header.left_indent`, then `header.first_line_indent`
  is applied once at the beginning of a new line

The builder writes the caller output block as:

- `item_out[0]`
  - first viewer-record index on entry
- `item_out[1]`
  - first viewer-record index after the item
- `item_out[4]`
  - maximum emitted width
- `item_out[5]`
  - maximum emitted height
- `*(u32 *)(item_out + 8)`
  - caller-carried trailing source/context dword propagated through the item

## Layout FSM: Return Codes

The layout pipeline has three nested FSMs. Status codes flow upward
through `MVDispatchControlRun → MVLayoutTextRunStream → MVLayoutTextLine →
MVTextLayoutFSM → MVBuildTextItem`. Each layer narrows what the caller
above it can observe.

### `MVDispatchControlRun` (origin of the 0..6 alphabet)

`MVDispatchControlRun` is the canonical source of the 0..6 alphabet —
every other layer either passes the code through or loops on it. The
control tag at `runTemplate+0x14` determines the return:

| status | control tag(s)                              | meaning at this layer                           |
| ------ | ------------------------------------------- | ----------------------------------------------- |
| `0`    | `0x20`/`0x21`/`0x22`/`0x80`/`0x86`/`0x89`/`0x8b`/default `0xC0..0xC7`/length-prefixed link | continue (text/control fits) |
| `1`    | `0x83` tab (pre-resolved), `0x87`/`0x88` nested-walk OK, `0x8c` split | control break — re-iterate next slot |
| `2`    | `0x83` tab (overflow), `0x85` deferred span, line-edge nested fallback | retry / split this line          |
| `3`    | `0x81`                                      | pending control status; deferred marker `'4'`   |
| `4`    | `0x82`                                      | pending control status; deferred marker `'3'`   |
| `5`    | `0xFF` EOF                                  | pending control status; deferred marker `'9'`   |
| `6`    | any `MVEmit*Slot` / `MVPoolEnsureCapacity` / `MVWalkLayoutSlots` allocation fail | hard failure |

Line-edge override: after the switch, if the viewer has unresolved
nested depth (`viewer+0x10a > 0`) AND `layoutState[3] == 0` AND
`runTemplate[0x15]` equals the current line's left edge, the dispatcher
forces status `2` regardless of the tag's natural return.

### `MVFitPlainTextRun` (plain text fitter)

| status | trigger                                                                                  |
| ------ | ---------------------------------------------------------------------------------------- |
| `0`    | scan reached NUL or hotspot boundary — full span fits                                    |
| `1`    | overflowed `initialTextOffset + 0x20` window without finding a NUL/space class drop      |
| `2`    | overflow AND backward scan from the candidate end couldn't find an ASCII space (`0x20`)  |

Status `1` allows the caller to bisect (`retryStep >>= 1`) and retry;
status `2` forces a wrap with no break point.

### `MVLayoutTextRunStream` (stream loop)

Passes through `MVFitPlainTextRun` / `MVDispatchControlRun` / nested /
hotspot layouts. Codes `2/3/4/5` flush the accumulated text slot plus
the pending marker recorded at `runTemplate+0x3d` (suppressed when
that byte is `'2'`). Codes `0/1` enter the line-boundary handler at
`caseD_0`:

- If line still has horizontal room AND no deferred marker AND no
  parent continuation, the loop re-enters the dispatch — code `1`
  additionally refreshes the rollback template.
- Otherwise it finalizes slots added since the rollback point, pops
  any pending nested depth, restores the backed-up template, emits the
  terminal line slot, trims a trailing split marker `'8'` or trailing
  nested marker `'\x06'`, applies alignment, emits the pending marker,
  and returns `1`.

### `MVLayoutTextLine` (line post-processor)

Pure passthrough of `MVLayoutTextRunStream`'s status, with one twist:
`6` short-circuits before the slot post-processing pass (no ascent/
descent collection, no alignment slack). For `0..5` it performs:

1. Slot ascent/descent collection.
2. Vertical-align: writes `slot+0x07` (y) for every active slot using
   `(max_ascent - slot_ascent) + lineY`.
3. Y-advance by `max(paragraph_min, ascent+descent+extra)`.
4. Alignment slack (only when `header.alignment_mode != 0`).
5. Synthetic line-height advance when no Y movement and status `!= 5`.

### `MVTextLayoutFSM` (item pump — caller-visible API)

`MVTextLayoutFSM` loops on `MVLayoutTextLine` until either a fatal or a
terminal status reaches the top. **The caller (`MVBuildTextItem`) only
ever observes the API-boundary statuses below — codes 0..3 are
loop-internal and never escape this layer.**

| status | meaning at the API boundary                                                                 |
| ------ | ------------------------------------------------------------------------------------------- |
| `4`    | line-finalization terminal — pending marker `'3'` (from control tag `0x82`) reached here    |
| `5`    | item/blob terminal — end-of-text sentinel, `MVResolveTextFlowEdge` returned `-1`, or pending marker `'9'` (EOF) |
| `6`    | hard allocation failure (`MVPoolEnsureCapacity` for the `0x47` slot or the `0x1e` nested record) |

The end-of-text shortcut fires when item bytes are exhausted: if the
viewer is in measuring mode (`viewer+0x80 & 2`), the FSM appends a
tag-`0x66` sentinel slot via `MVPoolEnsureCapacity` and returns `5`;
otherwise it returns `5` with no sentinel.

`MVBuildTextItem` consumes the FSM as:

```c
do { iVar4 = MVTextLayoutFSM(...); } while ((ushort)iVar4 < 5);
if ((ushort)iVar4 == 6) return 0;
```

so `4` re-enters the loop, `5` exits clean, and `6` propagates as item
failure.

## `0x47` Viewer Record Fields Used By Text Paint

`DrawTextSlot` proves the minimum text-draw contract for a tag-`1` (text run)
viewer record:

| offset | size | meaning | written by | consumer |
| --- | --- | --- | --- | --- |
| `0x00` | `u8`  | slot tag (`1` for text run)                | `MVEmitTextRunSlot` | `MVPaintSlotByTag` switch |
| `0x01` | `u32` | flags: bit0 = link active, bit1 = slot active | `MVEmitTextRunSlot` | layout post-processing |
| `0x05` | `i16` | x offset within the topic pane             | `MVEmitTextRunSlot` (from `runTemplate[0x15]`) | added to draw X |
| `0x07` | `i16` | y offset / line baseline                   | `MVLayoutTextLine` post-pass (`(max_ascent - slot_ascent) + lineY`) | added to draw Y |
| `0x09` | `i16` | font width metric (`textmetric+0x138 + +0x14c`) | `MVEmitTextRunSlot` | `MVLayoutTextLine` ascent collection |
| `0x0b` | `i16` | rendered text width                        | `MVEmitTextRunSlot` (from `runTemplate[0x16]`) | used by alignment-slack pass; not by `ExtTextOutA` |
| `0x0d` | `i16` | line-height contribution (`textmetric+0x158 + +0x148`) | `MVEmitTextRunSlot` | `MVLayoutTextLine` descent collection; `DrawTextSlot::PatBlt` height for selection fill |
| `0x0f` | `u32` | link/style grouping token                  | `MVEmitTextRunSlot` (from `runTemplate[0xc]`) | compared with `viewer + 0x130` during decorated draws |
| `0x13` | `i32` | selection/background token                 | `MVEmitTextRunSlot` (from `runTemplate[7]`)  | `-1` skips the special decorated branch |
| `0x2d` | `i32` | anchor start (link-group origin)           | `MVEmitTextRunSlot` (anchor or text start)   | text selection / hit-test |
| `0x31` | `i32` | text start (running char index)            | `MVEmitTextRunSlot` (from `runTemplate[0xe]`) | text selection / hit-test |
| `0x35` | `i32` | text end (`text_start + length - 1`)       | `MVEmitTextRunSlot`                          | text selection / hit-test |
| `0x39` | `u32` | byte offset into the shared story buffer   | `MVEmitTextRunSlot` (from `runTemplate[0x18]`) | `ExtTextOutA` source pointer (after `text_base` add) |
| `0x3d` | `i16` | character count                            | `MVEmitTextRunSlot` (from `runTemplate[0x1a]`) | `ExtTextOutA` length |
| `0x3f` | `i16` | font/style id                              | `MVEmitTextRunSlot` (from `runTemplate[0]`)  | `ApplyTextStyleToHdc` style index |

Everything else on the text first-paint path is secondary. If these fields are
right and the selected style resolves to a valid section-0 descriptor, stock
MOSVIEW reaches `ExtTextOutA`.

Note: the `slot+0x07` y coordinate is **not** written by `MVEmitTextRunSlot`.
The emit-time stack template leaves a 2-byte hole at slot offset `+0x07`;
`MVLayoutTextLine`'s vertical-align pass (`slot+0x07 = (max_ascent -
slot_ascent) + lineY`) fills it after the run-stream pass completes for
the current line.

A previous documentation pass listed `slot+0x0d` as "rendered height /
baseline delta" — `MVPaintBorderSlot::PatBlt` and `MVLayoutTextLine`'s
descent collection both treat it as a descent / line-height contribution
seeded from `TEXTMETRIC.tmAscent + tmDescent`-class fields stored at
`viewer+0x158` and `viewer+0x148`. The slot's *actual* drawn width is
re-measured by `DrawTextSlot::MeasureTextRunWidth` at paint time.

## Minimal Plain-Text Recipe

This is the smallest consumer-truth recipe for one authored text block:

1. Provide one shared ANSI story buffer, for example `Hello World`.
2. Emit one topic item with family `0x01`.
3. Set `text_start_index = 0`.
4. Set `alignment_mode = 0` and leave `space_before`, `space_after`,
   `min_line_extent`, `left_indent`, `right_indent`, and `first_line_indent`
   as zero.
5. Leave `edge_metrics_enabled = 0` and `edge_metric_flags = 0`.
6. Leave `tab_stop_count = 0` (relies on `tab_interval` default).
7. Ensure the surrounding paragraph state resolves the viewer-record style id to
   section-0 style `0`.

Expected result:

- one type-`1` text viewer record
- `record + 0x39 = 0`
- `record + 0x3d = 11`
- `record + 0x3f = 0`

The text bytes are not embedded inline in the item header. The item points into
the shared story buffer consumed by the surrounding paragraph/text parser.

## Section-0 Header Schema

All offsets below are `u16` relative to the start of the selector-`0x6f` font
blob after it has been copied into a GMEM handle.

| offset | size | name | meaning |
| --- | --- | --- | --- |
| `0x00` | `u16` | `header_word_0` | not consumed on the first-paint path |
| `0x02` | `u16` | `descriptor_count` | upper bound for descriptor/style indices |
| `0x04` | `u16` | `face_name_table_off` | base of `0x20`-byte ANSI face strings |
| `0x06` | `u16` | `descriptor_table_off` | base of `descriptor_count` records, stride `0x2a` |
| `0x08` | `u16` | `override_count` | number of override/inheritance records |
| `0x0a` | `u16` | `override_table_off` | base of override records, stride `0x92` |
| `0x0c` | `u16` | `header_word_0c` | not consumed on the first-paint path |
| `0x10` | `u16` | `pointer_table_off` | base of a dword pointer table used to seed `title + 0xb4` |

`hMVSetFontTable` and `FUN_7e896610` are the proving consumers:

- descriptor lookup uses `descriptor_table_off + style_id * 0x2a`
- face lookup uses `face_name_table_off + face_slot_index * 0x20`
- override lookup uses `override_table_off + override_id * 0x92`
- the pointer table is keyed by `descriptor.face_slot_index`

The client-side text path recovered in this pass never dereferences `title +
0xb4` after these stores. It is still part of the stock runtime shape, but it
is not a first authored text blocker.

## Descriptor Record (`0x2a` Stride)

| offset | size | name | meaning |
| --- | --- | --- | --- |
| `0x00` | `u16` | `face_slot_index` | face-table index, also used for pointer-table lookup |
| `0x02` | `u16` | `descriptor_aux_id` | copied through merge, not consumed by `CreateFontIndirectA` in this pass |
| `0x04` | `u16` | `override_style_id` | `0` means no override chain |
| `0x06` | `rgb24` | `text_color` | sentinel `0x010101` means keep title default |
| `0x09` | `rgb24` | `back_color` | sentinel `0x010101` means keep title default |
| `0x0c` | `i32` | `lfHeight` | copied into `LOGFONTA` |
| `0x10` | `i32` | `lfWidth` | copied into `LOGFONTA` |
| `0x14` | `i32` | `lfEscapement` | copied into `LOGFONTA` |
| `0x18` | `i32` | `lfOrientation` | copied into `LOGFONTA` |
| `0x1c` | `i32` | `lfWeight` | copied into `LOGFONTA` |
| `0x20` | `u8` | `lfItalic` | copied into `LOGFONTA` |
| `0x21` | `u8` | `lfUnderline` | copied into `LOGFONTA` |
| `0x22` | `u8` | `lfStrikeOut` | copied into `LOGFONTA` |
| `0x23` | `u8` | `lfCharSet` | copied into `LOGFONTA` |
| `0x24` | `u8` | `lfOutPrecision` | copied into `LOGFONTA` |
| `0x25` | `u8` | `lfClipPrecision` | copied into `LOGFONTA` |
| `0x26` | `u8` | `lfQuality` | copied into `LOGFONTA` |
| `0x27` | `u8` | `lfPitchAndFamily` | copied into `LOGFONTA` |
| `0x28` | `u8` | `style_flags` | extra MediaView flags, not direct `LOGFONTA` bytes |
| `0x29` | `u8` | `extra_flags` | copied through merge; not consumed by first text paint |

`FUN_7e896ba0` proves that `descriptor + 0x0c .. descriptor + 0x27` is the
exact `LOGFONTA` prefix copied into `CreateFontIndirectA`, and that the face
name comes from the `0x20`-byte face table entry selected by
`face_slot_index`, optionally replaced by the override string.

## Override Record (`0x92` Stride)

| offset | size | name | meaning |
| --- | --- | --- | --- |
| `0x00` | `u16` | `style_id` | current override record id |
| `0x02` | `u16` | `parent_style_id` | recursive parent link |
| `0x04` | `u16` | `face_slot_override` | nonzero overrides `descriptor.face_slot_index` |
| `0x06` | `u16` | `descriptor_aux_override` | nonzero overrides `descriptor.descriptor_aux_id` |
| `0x0a` | `rgb24` | `text_color_override` | `0x010101` means inherit |
| `0x0d` | `rgb24` | `back_color_override` | `0x010101` means inherit |
| `0x10` | `i32` | `lfHeight_override` | nonzero overrides descriptor field |
| `0x14` | `i32` | `lfWidth_override` | nonzero overrides descriptor field |
| `0x18` | `i32` | `lfEscapement_override` | nonzero overrides descriptor field |
| `0x1c` | `i32` | `lfOrientation_override` | nonzero overrides descriptor field |
| `0x20` | `i32` | `lfWeight_override` | nonzero overrides descriptor field |
| `0x24` | `u8` | `lfItalic_override` | zero means inherit |
| `0x25` | `u8` | `lfUnderline_override` | zero means inherit |
| `0x26` | `u8` | `lfStrikeOut_override` | zero means inherit |
| `0x27` | `u8` | `lfCharSet_override` | zero means inherit |
| `0x28` | `u8` | `lfOutPrecision_override` | zero means inherit |
| `0x29` | `u8` | `lfClipPrecision_override` | zero means inherit |
| `0x2a` | `u8` | `lfQuality_override` | zero means inherit |
| `0x2b` | `u8` | `lfPitchAndFamily_override` | zero means inherit |
| `0x2c` | `u8` | `style_flags_value` | MediaView flag byte merged into descriptor `0x28` |
| `0x2d` | `u8` | `extra_flags_value` | copied into descriptor `0x29` when nonzero |
| `0x2e` | `u8` | `style_flags_merge_mode` | bit `0`: `0 = replace`, `1 = OR` |
| `0x30` | `char[]` | `face_name_override` | optional ANSI replacement string |

### Merge Semantics

`FUN_7e8963b0` proves:

- parent styles are merged first
- recursion stops after depth `0x14`
- `face_slot_override` and `descriptor_aux_override` overwrite when nonzero
- both colors only overwrite when not equal to `0x010101`
- each `LOGFONTA` integer field only overwrites when nonzero
- each one-byte `LOGFONTA` field only overwrites when nonzero
- `style_flags_merge_mode & 1`
  - clear -> replace descriptor `style_flags`
  - set -> OR override bits into descriptor `style_flags`
- `style_flags_value & 0x08` explicitly clears the merged underline byte
- `face_name_override` replaces the face-table string when its first byte is
  nonzero

## Minimal Valid Section-0 Recipe

The smallest section-0 blob that satisfies the first text-paint path is:

1. one face-table entry
   - slot `0`
   - face string `Times New Roman`
2. one descriptor
   - `face_slot_index = 0`
   - `descriptor_aux_id = 0`
   - `override_style_id = 0`
   - `text_color = 0x010101`
   - `back_color = 0x010101`
   - `lfHeight = -12`
   - `lfWidth = 0`
   - `lfEscapement = 0`
   - `lfOrientation = 0`
   - `lfWeight = 400`
   - `lfItalic = 0`
   - `lfUnderline = 0`
   - `lfStrikeOut = 0`
   - `lfCharSet = 0`
   - `lfOutPrecision = 0`
   - `lfClipPrecision = 0`
   - `lfQuality = 0`
   - `lfPitchAndFamily = 0`
   - `style_flags = 0`
   - `extra_flags = 0`
3. zero override records
4. one null pointer-table entry

For this first milestone, a null pointer-table entry is acceptable from the
client-side evidence currently recovered. The real first-paint blocker is a
valid descriptor and face string that reach `CreateFontIndirectA`.

## On-Disk → Wire Field Mapping

The on-disk authored format is documented in `docs/blackbird-title-format.md`
(`CStyle` / `CCharProps` / `CParaProps` sections). The mapping into the wire
descriptor / override layout above:

| on-disk source                          | wire target                          |
| --------------------------------------- | ------------------------------------ |
| `CStyleSheet.fonts[].name`              | face name table entry, slot = `key`  |
| `CStyle.name_index`                     | descriptor index (`style_id`)        |
| `CStyle.based_on`                       | override `parent_style_id`           |
| `CCharProps.fields.font_id`             | descriptor `face_slot_index`         |
| `CCharProps.fields.pt_size`             | descriptor `lfHeight` (negate; MM_TEXT) |
| `CCharProps.fields.flags_word` bold     | descriptor `lfWeight` (700 vs 400)   |
| `CCharProps.fields.flags_word` italic   | descriptor `lfItalic`                |
| `CCharProps.fields.flags_word` underline | descriptor `lfUnderline`            |
| `CCharProps.fields.flags_word` super/sub | NOT in section-0 — handled by item  |
|                                         | records; informational here          |
| `CCharProps.fields.text_color`          | descriptor `text_color`              |
| `CCharProps.fields.back_color`          | descriptor `back_color`              |
| `CCharProps.mask_concrete` bit clear    | "-2 absent" → wire `0x010101`        |
|                                         | inherit sentinel for colors, or skip |
|                                         | the override field for LOGFONTA      |
| `CStyle.is_intrusion`                   | text-wrap metadata, NOT a descriptor |
|                                         | — these styles ship empty bodies     |
|                                         | and are consumed by the layout pass  |
|                                         | (intrusion / image-wrap), not the    |
|                                         | font/glyph descriptor                |
| `CStyle.char_props_only`                | descriptor without paragraph data;   |
|                                         | wire side is unaffected (paragraphs  |
|                                         | live outside section-0)              |
| inheritance through `CStyle.based_on`   | wire override-record `parent_style_id` |
|                                         | chain (depth limit 0x14, both sides) |
| `CParaProps` fields                     | NOT in section-0 — paragraph layout  |
|                                         | is driven by item-record headers     |

Note: strikethrough is NOT a `flags_word` bit. The predefined-style
default for `name_index 0x22` ("Strikethrough") at VIEWDLL
`0x40770e00 + 0x22 * 0x34` carries `flags_word = 0x7b08` —
**identical** to Hyperlink (0x1e) and Underline (0x26): underline ON,
others absent. The visual strike effect is delivered by the renderer
special-casing the style NAME, not by a font/glyph descriptor bit.
The `flags_word` proper carries only bold / italic / underline /
superscript / subscript bits.

Per-style typography defaults (used when an authored CCharProps or
CParaProps leaves a field absent) live in VIEWDLL at `0x40770e00`,
stride `0x34` (52 bytes) per name_index, captured verbatim in
`CSTYLE_DEFAULT_PROPS` at `src/server/blackbird/ttl_inspect.py`.
Layout per entry:

| offset | size | field                | runtime accessor              |
| ------ | ---- | -------------------- | ----------------------------- |
| 0x00   | u32  | name pointer         | `CStyle::GetBasedOn`          |
| 0x04   | u16  | based_on             | `LoadDefaultStyle` (sentinel `0xffff`) |
| 0x08   | u32  | char_props_only      | `LoadDefaultStyle` (0/1)      |
| 0x0c   | u16  | flags_word           | `CCharProps::EGetWord` kind 5 |
| 0x10   | u16  | font_id              | kind 3                        |
| 0x12   | u16  | pt_size              | kind 4                        |
| 0x14   | u32  | text_color           | `CCharProps::EGetColorRef` 0  |
| 0x18   | u32  | back_color           | kind 1                        |
| 0x1c   | u16  | justify              | `CParaProps::EGetWord` kind 0 |
| 0x1e   | u16  | initial_caps         | kind 11                       |
| 0x20   | i16  | drop_by              | `CParaProps::EGetShort` k12   |
| 0x22   | u16  | bullet               | `EGetWord` kind 10            |
| 0x24   | u16  | line_spacing_rule    | kind 2                        |
| 0x26   | i16  | indent_by            | `EGetShort` kind 3            |
| 0x28   | i16  | left_indent          | kind 4                        |
| 0x2a   | i16  | right_indent         | kind 5                        |
| 0x2c   | i16  | space_at             | kind 8                        |
| 0x2e   | u16  | special_line_indent  | `EGetWord` kind 1             |
| 0x30   | i16  | space_before         | `EGetShort` kind 6            |
| 0x32   | i16  | space_after          | kind 7                        |

Pinned highlights (full set in `CSTYLE_DEFAULT_PROPS`):

| name_index               | flags_word | font_id | pt_size | text_color   | extras                |
| ------------------------ | ---------- | ------- | ------- | ------------ | --------------------- |
| 0x00 Normal              | 0x0000     | 1       | 11      | 0x00000000   | root, Times New Roman |
| 0x01 Heading 1           | 0x7e02     | 2       | 22      | inherit      | bold, Arial 22pt      |
| 0x07 TOC 1               | 0x7e02     | 2       | 12      | 0x00000080   | dark red, left=18tw   |
| 0x10 Section 1           | 0x7e02     | 2       | 14      | 0x00808000   | teal heading          |
| 0x19 Abstract Heading    | 0x7e02     | 1       | 22      | inherit      | `justify=2` (center)  |
| 0x1e Hyperlink           | 0x7b08     | 0       | 0       | 0x00ff0000   | blue + underline      |
| 0x22 Strikethrough       | 0x7b08     | 0       | 0       | inherit      | name-special-cased    |
| 0x23 Preformatted        | 0x7f00     | 3       | 0       | inherit      | Courier (monospace)   |
| 0x29 Keyboard            | 0x7c06     | 0       | 0       | inherit      | bold + italic         |

The TOC and Section indent ladders are encoded directly in the
`left_indent` field: TOC 1..9 → 18, 36, 54, …, 162 twips (multiples
of 18). Wire-side lowering should mirror these defaults whenever an
authored CCharProps/CParaProps field is "absent" — otherwise
rendering will diverge from how the standalone Blackbird viewer
handles the same TTL.

A second copy of the same data lives at `0x40773224` (stride 0x34,
no name pointer prefix — entry +0x00 = `based_on`, +0x04 = `cpo`).
Engine-internal duplication for `LoadDefaultStyle`'s construction
fast-path; semantics match `0x40770e00` exactly.

Open questions deferred until a TTL exercises them:
- charset / lfPitchAndFamily / lfQuality lowering — none are exposed
  on disk, so the wire descriptor uses `0` for all of them
- linked stylesheet inheritance (`linked_stylesheet_present` is `0` in
  the reference TTL)
- `CStyle.intrusion_index` content/proxy reference semantics
  (`?GetIntrusion@CStyle@@…` reads the byte raw — always `0` in the
  reference TTL, suggesting a "no specific target" sentinel)

## Authored Lowering Checklist

Current minimal authored-to-runtime lowering should be:

- `CStyleSheet.fonts`
  - lower to the section-0 face table (slot index = font key)
- `CStyleSheet.styles` plus linked stylesheet inheritance
  - lower to the section-0 descriptor table and override table
  - parser pinned: `parse_cstylesheet` in
    `src/server/blackbird/ttl_inspect.py`
- `TextRuns`
  - lower to the shared ANSI story buffer consumed by `ExtTextOutA`
- `TextTree`
  - lower to item family `0x01/0x20` headers carrying start index, spacing,
    indents, alignment, and inline runs

First text paint does not require reopening broader `VIEWDLL` archaeology as
long as:

- the story buffer is preserved
- paragraph/style defaults resolve to section-0 style `0`
- the item header fields above are emitted faithfully

## Layout Walker AV Conditions

`MVWalkLayoutSlots` (entry `0x7e894c50`) is the chunk dispatcher invoked by
`MVParseLayoutChunk` for every wire-pushed `0xBF` chunk and by the nested-
stream / column / hotspot layouts internally. The AV documented in
`project_medview_layout_walker_av` happens at offset `+0xfc` inside this
function, instruction `MOVSX EAX, word ptr [ECX + 0xb]`.

### Trigger

```c
short slotState[6];     // param_6
MVDecodeTopicItemPrefix(prefix, chunk_body);
switch (prefix[0]) {
case 1: case 0x20:                       /* text item */
    MVBuildTextItem(...);                /* writes slotState[1] = last_view_record */
    break;
case 3: case 0x22:                       /* layout-line item */
    MVBuildLayoutLine(...);              /* writes slotState[1] */
    break;
case 4: case 0x23:                       /* column item */
    MVBuildColumnLayoutItem(...);        /* writes slotState[1] */
    break;
case 5: case 0x24:                       /* embedded window item */
    MVBuildEmbeddedWindowItem(...);      /* writes slotState[1] */
    break;
default:
    /* NO builder ran — slotState[1] left at caller-supplied value */
    break;
}

if (slotState[4] == 0 && slotState[5] == 0 && slotState[0] < slotState[1]) {
    short sVar4 = slotState[0];
    do {
        int slot = sVar4 * 0x47 + *(int *)(viewer + 0xf6);
        int width  = *(short *)(slot + 0xb) + *(short *)(slot + 5);  /* +0xfc AV */
        ...
    } while (sVar4 < slotState[1]);
}
```

The walker zeroes `slotState[4]` and `slotState[5]` at entry, so the
`max_x/max_y == 0` gate is unconditionally true on a default-case
fall-through. The loop bound `slotState[1]` (`last_view_record`) is the
only remaining lever — and on the default branch nothing writes to it.

### Caller-supplied stack residue

`MVParseLayoutChunk` declares `slotState` as the contiguous stack
locals `local_30..local_26`. Before the `MVWalkLayoutSlots` call it
explicitly zeroes only `local_30` (`slotState[0]`), `local_2c`
(`slotState[2]`), and `local_2a` (`slotState[3]`). `local_2e`
(`slotState[1] = last_view_record`) is **never written before the
call**. When the walker takes the default branch, the loop bound is
whatever stale stack word the compiler left in `local_2e`.

If that stale word is a positive integer (which is overwhelmingly the
case in a long-running viewer), the loop iterates `sVar4 ∈ [0,
stale_count)` and computes `slot_va = sVar4 * 0x47 + viewer+0xf6`.
The slot pool at `viewer+0xf6` is GMEM-allocated and frequently
smaller than `stale_count * 0x47` bytes; the first read of
`*(short *)(slot_va + 0xb)` past the commit boundary AVs.

### Encoder-side invariants that avoid the AV

The chunk body emitted on wire selector `0x15` MUST begin (after the
chunk-header preamble that `MVDecodeTopicItemPrefix` consumes) with a
prefix byte in `{1, 3, 4, 5, 0x20, 0x22, 0x23, 0x24}`. Any other byte
falls through and AVs. In particular, custom synthetic tags pulled
from internal experiments — `0x06`, `0x07`, `0x40`, etc. — all
exercise the default branch.

### Ack-only `0x87` on selector `0x15` fallback

The current server emits a bare `0x87` ack on selector `0x15` instead
of pushing a chunk body (`project_medview_layout_walker_av`). This
keeps the client from invoking `MVParseLayoutChunk` for that push,
sidestepping `MVWalkLayoutSlots` entirely. Trade-off:

- Safe: the AV never fires; the viewer continues to process other
  selectors (HfcNear cache via `0x06`, etc.).
- Lossy: the layout walker receives no content for the acked push,
  so the pane stays blank at that scroll position. Any future case-1
  chunk lowering must emit a real `0x01` / `0x20` prefix to make
  text visible.

### Out-of-scope: fixing the walker

`MVCL14N.DLL` is the stock 1996 client binary — the `MVParseLayoutChunk`
caller bug is the proximate cause but cannot be patched. The encoder
side therefore owns the invariant: **never ship a `0xBF` chunk whose
prefix byte is not in the accepted-tag set above.**

## Case-1 Chunk → Slot Tag-1 Round Trip

This section walks the full on-wire-to-paint path for the `0xBF` case-1
text-row chunk produced by `src/server/blackbird/wire.py`'s
`build_case1_bf_chunk` / `encode_text_item_tlv` pair. Each step cites
the function name pinned in this RE pass; addresses in `MVCL14N.DLL` /
image base `0x7e880000`.

### 1. On-wire chunk shape

Wire output (per `build_case1_bf_chunk` docstring):

```text
case1_chunk = preamble(3 B) + null_tlv(6 B) + tlv_text(N) + trailer
where
  preamble  = packed prefix tag + scalar dword + (optional widened u16)
  null_tlv  = (...) inert TLV consumed by the chunk-handle field decoders
  tlv_text  = encode_text_item_tlv(...) carrying the inline text item bytes
  trailer   = 0xFF terminator + ASCII story bytes (zero-padded)
```

The first byte after the chunk preamble — the byte fed to
`MVDecodeTopicItemPrefix` — must be `0x01` (narrow text) or `0x20`
(widened text) for the walker to dispatch into `MVBuildTextItem`.

### 2. Wire delivery to client

The chunk arrives via MEDVIEW selector `0x15` (TitleOpen-driven page
content; see `project_medview_wire_contract`). The client's MEDVIEW
service routes the chunk handle to `MVParseLayoutChunk`
(`0x7e890fd0`), which:

1. Acquires a 0x26-stride chunk record from `viewer+0xd8` via
   `MVPoolAcquireEntry`.
2. Locks the chunk HGLOBAL at `viewer+0xf2`; the locked base becomes
   `viewer+0xf6` — the 0x47-byte slot pool.
3. Calls `MVDecodeTopicItemPrefix` on `chunk_handle + 0x26` to produce
   the normalized prefix and advance the body cursor.
4. Calls `MVWalkLayoutSlots(viewer, chunk_record, chunk_body, trailer,
   available_width, slotState)` to dispatch by prefix tag.

### 3. Walker dispatch (`MVWalkLayoutSlots`, `0x7e894c50`)

For prefix tag `0x01` or `0x20`, the walker calls
`MVBuildTextItem(viewer, chunk_record, chunk_body, available_width,
selection_hint, slotState)` (`0x7e8915d0`).

### 4. Text-item assembly (`MVBuildTextItem`)

`MVBuildTextItem`:

1. Re-runs `MVDecodeTopicItemPrefix` on the body to capture the
   prefix into a local 10-byte block (used for the widened
   `prefix_u16` if present).
2. Calls `MVDecodePackedTextHeader` (`0x7e897ad0`) to expand the
   packed text header into the `0x29 + 4*N`-byte normalized block
   (text_start_index, alignment_mode, indents, tab_interval,
   edge_metric_flags, tab_stops[]).
3. Calls `MVScaleTextMetrics` (`0x7e892b90`) to scale logical units
   to device pixels.
4. Locks the viewer's nested-record HGLOBAL at `viewer+0x102` (used
   by `MVDispatchControlRun` for `0x87`/`0x88` continuations).
5. Pumps `MVTextLayoutFSM` (`0x7e891810`) in a
   `do { } while (status < 5)` loop until the item terminates.

### 5. Layout FSM (`MVTextLayoutFSM`)

Each FSM tick:

1. Sets up the line bounds via `MVResolveTextFlowEdge` calls (one
   per active flow edge bit in `edge_metrics_enabled`).
2. Calls `MVLayoutTextLine` (`0x7e891f50`), which delegates to
   `MVLayoutTextRunStream` (`0x7e892200`).
3. The run-stream loops over `MVFitPlainTextRun` (`0x7e8925d0`),
   `MVDispatchControlRun` (`0x7e894ec0`), and hotspot/nested
   helpers; each iteration either appends a tag-`1` text slot via
   `MVEmitTextRunSlot` (`0x7e892d30`) or a control/marker slot.
4. On a `0/1` line-boundary status, the run-stream finalizes slots
   added since the rollback point, restores the run template, and
   `MVEmitTextRunSlot`s the terminal line slot.
5. On `4`/`5`/`6`, `MVTextLayoutFSM` exits the loop and returns to
   `MVBuildTextItem`.

The slots emitted are `0x47`-byte records appended into the slot
pool at `viewer+0xf6`, each carrying the fields documented in
§"0x47 Viewer Record Fields Used By Text Paint".

### 6. Slot post-processing

`MVLayoutTextLine`'s post-pass:

- Collects `max(slot+0x09)` and `max(slot+0x0d - slot+0x09)` to find
  the line's max-ascent / max-descent.
- Writes `slot+0x07 = (max_ascent - slot_ascent) + lineY` for every
  active slot — this is when the slot's vertical position is fixed.
- Trims trailing spaces from the last slot (`slot+0x39`-based bytes)
  when `alignment_mode != 0`, then re-measures via
  `MeasureTextRunWidth`.
- Shifts every active non-spacer slot by the alignment slack
  (`(right_edge - line_width) / 2` for center, full slack for right).

### 7. Paint dispatch (`MVPaintSlotByTag`, `0x7e891220`)

When the pane next repaints, `MVPaneOnPaint` (`0x7e889b70`) walks the
chunk linked list at `viewer+0xea` and forwards each chunk's slot
range to `MVPaintSlotByTag`. For each slot with `slot[0] == 1`,
the dispatcher:

1. Locks the chunk metadata HGLOBAL at `chunk+0x06`.
2. Decodes the chunk's `TopicItemPrefix` to compute the text base —
   `text_base = chunk_metadata + 0x26 + decoded_offset + prefix_advance`.
3. Calls `DrawTextSlot(viewer, text_base, slot, xOff, yOff, clip_rect,
   selection_hint)` (`0x7e893010`).

### 8. Pixel emit (`DrawTextSlot`)

`DrawTextSlot`:

- `ApplyTextStyleToHdc(viewer, slot+0x3f)` resolves the slot's
  style id through the viewer font cache (per §"Section-0 Header
  Schema").
- Computes `draw_x = origin_x + slot+0x05`, `draw_y = origin_y +
  slot+0x07`.
- Calls `MeasureTextRunWidth(viewer, text_base + slot+0x39,
  slot+0x3d, dx_buffer)` for kerning.
- Emits via `ExtTextOutA(hdc, draw_x, draw_y, ..., text_base +
  slot+0x39, slot+0x3d, dx_buffer)`.
- Optionally calls `DrawSlotRunArray` to draw the slot's per-run
  decoration array (underline, strike, hyperlink box).

End-to-end: an emitted `0x01`/`0x20` chunk turns into one
`ExtTextOutA` call per text run on the line, with style/alignment
resolved against the section-0 font table and the line's
`alignment_mode`.

## Bitmap Child Trailer Boundary

This pass does not promote image-child fidelity to a first-paint blocker, but
the child trailer boundary is now concrete enough to defer cleanly.

### Scaled Image Trailer

`FUN_7e886de0` produces a scaled intermediate trailer:

```text
ScaledImageChildTrailer
  u8 reserved0
  u16 scaled_image_width
  u16 scaled_image_height
  u16 reserved1
  u16 child_count
  u32 raw_tail_blob_len
  repeat child_count:
    ImageChildRecord
  u8[raw_tail_blob_len] raw_tail_blob
```

`ImageChildRecord` is `0x0f` bytes:

| offset | size | meaning |
| --- | --- | --- |
| `0x00` | `u8` | child discriminator; `0x8a` becomes viewer type `7`, everything else becomes viewer type `4` |
| `0x01` | `u8` | secondary tag byte, copied to type-`4` viewer records but still unresolved |
| `0x03` | `i16` | child x |
| `0x05` | `i16` | child y |
| `0x07` | `i16` | child width/right metric |
| `0x09` | `i16` | child height/bottom metric |
| `0x0b` | `u32` | child metadata dword copied into the viewer record |

### Tail HGLOBAL Shared By Type-`4` Children

`MVBuildLayoutLine` allocates a second HGLOBAL for type-`4` children only:

```text
ImageChildTailHandle
  u16 interactive_child_count
  u8[raw_tail_blob_len] raw_tail_blob
```

The first recovered consumer pair is:

- `FUN_7e889340`
- `FUN_7e8892f0`

They prove that:

- the handle is locked once per highlight pass
- the caller indexes entries at `base + 4 + child_index * 0x14`
- each `0x14`-byte entry begins with four dwords consumed as
  `left, top, right, bottom_minus_one`

What is still deferred:

- the exact meaning of `raw_tail_blob[0:2]`
- the semantic role of the second per-child tag byte
- the meaning of the trailing dword in each `0x14` tail entry
- any authored-side source object that feeds this tail blob

### What Can Stay Stubbed For First Text Paint

The first authored text milestone does not need this trailer at all. Safe
deferment options are:

- omit item family `0x03` entirely
- or emit only the parent image record with:
  - `child_count = 0`
  - `raw_tail_blob_len = 0`
  - no type-`4` / type-`7` child records

This leaves image hotspots and rich child metadata unresolved without blocking
plain text render.
