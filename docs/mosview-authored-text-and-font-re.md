# MediaView First Authored Text / Section-0 RE Notes

This note records the static RE pass for the first stock-MOSVIEW milestone:
rendering one authored text story with a real MediaView text item and a real
section-0 font table.

Related consumer paths in `MVCL14N.DLL`:

- `FUN_7e897ed0`
  - normalized topic-item prefix decode
- `FUN_7e897ad0`
  - packed text-item header decode
- `FUN_7e8915d0`
  - top-level text item builder
- `FUN_7e891810`
  - text layout state machine
- `FUN_7e893010`
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

`FUN_7e897ed0` normalizes the leading topic-item prefix before
`FUN_7e897ad0` sees the packed text header.

```text
TopicItemPrefix
  u8 tag
  PackedWideScalar prefix_dword
  if tag > 0x10:
    PackedUnsignedSmall prefix_u16
```

Notes:

- Use `0x01` for the narrow text form and `0x20` for the widened text form.
- `FUN_7e897ed0` preserves the semantic item family while hiding the narrow vs
  widened integer encoding from later code.
- For first plain text emission, the narrow `0x01` form is sufficient.

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

`FUN_7e897ad0` expands the packed text-item header into a normalized local
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
| `0x22` | `i16` | `tab_interval` | horizontal spacing quantum used by the line parser |
| `0x24` | `u16` | `edge_metric_flags` | bitfield consumed by `FUN_7e893cb0` |
| `0x27` | `i16` | `inline_run_count` | count of trailing inline metadata entries |
| `0x29` | `4 * count` | `inline_runs[]` | repeated `u16 offset_flags`, optional `u16 aux` when bit `0x4000` is set |

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

`FUN_7e892b90` proves that the header is still in authored/logical units when
decoded:

- `0x16`, `0x18`, `0x1a` scale with `LOGPIXELSY`
- `0x1c`, `0x1e`, `0x20`, `0x22`, and each inline-run position scale with
  `LOGPIXELSX`
- both axes also multiply by the title scale factor at `title + 0x7c`

If `tab_interval` is omitted, `FUN_7e897ad0` synthesizes a default from
`text_base_or_mode & 1`:

- low bit clear -> default becomes `0x0048`
- low bit set -> default becomes `0x02c6`

## `FUN_7e8915d0`: Item Builder Mapping

`FUN_7e8915d0` does not draw directly. It:

1. decodes the topic-item prefix with `FUN_7e897ed0`
2. decodes the packed header with `FUN_7e897ad0`
3. scales header metrics with `FUN_7e892b90`
4. seeds a transient layout state block
5. loops `FUN_7e891810` until the item finishes or allocation fails
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

## `FUN_7e891810`: Layout Return Codes

`FUN_7e891810` is the caller-visible layout state machine for one text item.
The exact symbolic names are not present in the binary, but caller behavior
pins the classes below:

- `0`
  - non-terminal progress; keep parsing the current line
- `1`
  - non-terminal progress after an internal retry / rewind path
- `2`, `3`, `4`
  - normal line-finalization states returned through `FUN_7e892200`
  - `FUN_7e891f50` still post-processes alignment and baseline after these
- `5`
  - caller-visible line/item boundary ready now
  - used for blank-line sentinel emission and other successful no-more-work
    paths in the current call
- `6`
  - hard failure
  - every observed path to `6` is a failed `0x47` viewer-record allocation

The distinction between `2`, `3`, and `4` is still tied to inner line-parser
events, but they are all normal progress states, not fatal states.

## `0x47` Viewer Record Fields Used By Text Paint

`FUN_7e893010` proves the minimum text-draw contract for a viewer record:

| offset | size | meaning | consumer |
| --- | --- | --- | --- |
| `0x05` | `i16` | x offset within the topic pane | added to draw X |
| `0x07` | `i16` | y offset within the topic pane | added to draw Y |
| `0x0b` | `i16` | rendered width | used by layout/extents |
| `0x0d` | `i16` | rendered height / baseline delta | used by layout/extents |
| `0x0f` | `u32` | link/style grouping token | compared with `title + 0x130` during decorated draws |
| `0x13` | `i32` | selection/background token | `-1` skips the special decorated branch |
| `0x39` | `u32` | byte offset into the shared story text buffer | `ExtTextOutA` source pointer |
| `0x3d` | `i16` | character count | `ExtTextOutA` length |
| `0x3f` | `i16` | font/style id | passed to `FUN_7e896760` |

Everything else on the text first-paint path is secondary. If these fields are
right and the selected style resolves to a valid section-0 descriptor, stock
MOSVIEW reaches `ExtTextOutA`.

## Minimal Plain-Text Recipe

This is the smallest consumer-truth recipe for one authored text block:

1. Provide one shared ANSI story buffer, for example `Hello World`.
2. Emit one topic item with family `0x01`.
3. Set `text_start_index = 0`.
4. Set `alignment_mode = 0` and leave `space_before`, `space_after`,
   `min_line_extent`, `left_indent`, `right_indent`, and `first_line_indent`
   as zero.
5. Leave `edge_metrics_enabled = 0` and `edge_metric_flags = 0`.
6. Leave `inline_run_count = 0`.
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

## Authored Lowering Checklist

Current minimal authored-to-runtime lowering should be:

- `CStyleSheet.fonts`
  - lower to the section-0 face table
- `CStyleSheet.styles` plus linked stylesheet inheritance
  - lower to the section-0 descriptor table and override table
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

`FUN_7e894560` allocates a second HGLOBAL for type-`4` children only:

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
