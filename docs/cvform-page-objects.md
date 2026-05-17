# CVForm "Page" Object Structure

Pinned by hex-diffing a series of single-property probe TTLs authored
in BBDESIGN. The reference TTL (`/var/share/drop/first title.ttl`,
"showcase") has a Front Matter section containing a single Page named
"Home" with five embedded controls: Story, Caption, Audio,
CaptionButton, Outline. The CVForm object holds the Page's layout +
control properties as an OLE compound stream.

## CVForm container shape

`CVForm` (table_id `7`) is the embedded layout payload of a `CBForm`
(Page). `CBForm.embedded_vform` is a swizzle handle pointing at the
CVForm slot for that Page. The CVForm payload is a Microsoft Forms
1.0 stream:

```
+0x00..+0x27   form preamble + form CLSID
               {5728F10E-27CC-101B-A8EF-00000B65C5F8} = MS Forms 1.0 Form
+0x28..        site descriptor for control 0
               site descriptor for control 1
               …
+0x540..       OLE class strings:
                 "Microsoft Forms 1.0 Form"
                 "Embedded Object"
                 "Forms.Form.1"
+(tail)        UTF-16 "CompObj" sentinel (only present when the form
               is hosting an embedded OLE object such as a tiled BMP)
```

Each embedded control is preceded by a **16-byte site descriptor**
that records the control's identity within the form:

```
seq:u32               ; 1-based sequence number; gaps signal a removed
                      ; or hidden site (showcase has 1,2,3,4,6 — no 5)
0x00030073:u32        ; constant marker
size:u32              ; per-control property-block length (see below)
flags:u32             ; high bit set, low byte = 0-based index reused
                      ; in references; e.g. 0x80000000 | i
ASCII name [+ NUL]    ; e.g. "Story1R\0" / "Caption1" (names that
                      ; happen to be exactly 8 chars don't pad; shorter
                      ; names take a single NUL byte to round to 8)
i32 x_twips           ; control top-left X in twips (20 twips = 1pt)
i32 y_twips           ; control top-left Y in twips
... per-control inline data ...
```

**Note on `size`.** Empirically:

- For a CBForm whose only descriptor is a Caption (4.ttl: `size=121`),
  the descriptor's inline tail carries the full property block plus
  some trailer; `size` is not the inline tail's length.
- For mixed pages (showcase: Story / Caption / Audio / CaptionButton /
  Outline), each descriptor has a tight inline header (rect + a few
  bytes), and the per-control property blocks live in a single
  post-descriptor property region in seq order. The size of each block
  is approximately `descriptor.size`, but boundaries are not exact —
  showcase Caption1's text "First section" lands past the 122-byte
  block end the descriptor advertises.

The current loader treats `descriptor.size` as the seq-ordered slice
length of the property region (good enough to localize Story1R's
`Homepage.bdf` reference in msn_today.ttl), and falls back to scanning
for the StdFont CLSID when Caption text lookup runs past block bounds.
Fully reconciling block sizes will require RE'ing the BBCTL.OCX
PropertyExchange persist for each control kind.

In the showcase form the 5 sites are:

| seq | site name | top-left twips | top-left pt | content reference |
| --- | --- | --- | --- | --- |
| 1 | `Story1R` | (3175, 2328) | (158.8, 116.4) | TextProxy 9/1 ("Blackbird Document.bdf") |
| 2 | `Caption1` | (4233, 846) | (211.7, 42.3) | inline text "First section" |
| 3 | `Audio1R` | (211, 2328) | (10.6, 116.4) | AudioProxy 9/5 ("Canyon.mid") |
| 4 | `CaptionButton1R` | (9101, 846) | (455.1, 42.3) | inline text "A button!" |
| 6 | `Outline1` | (211, 4445) | (10.6, 222.2) | inline outline rows (no proxy ref) |

The control kind (Story / Caption / Audio / CaptionButton / Outline)
is encoded as a CLSID in the site descriptor's preceding header bytes;
those CLSIDs are emitted by BBCTL.OCX. Pinning each kind's CLSID is
deferred — it's not needed yet because the site name suffix is enough
to disambiguate during diffing.

## Story1R property block

Story1R's property data sits inside the showcase CVForm's post-
descriptor property region. The offsets below were originally probed
against single-property TTL diffs and recorded as **CVForm-absolute**;
on showcase 7/0 they sit at:

| CVForm-absolute | property-region offset | size | name | observed values |
| --- | --- | --- | --- | --- |
| `+0x02F7` | `+0x008C` | u16 LE | `margin_top` (pt) | 10 → 3 |
| `+0x02F9` | `+0x008E` | u16 LE | `margin_bottom` (pt) | 10 → 4 |
| `+0x02FB` | `+0x0090` | u16 LE | `margin_left` (pt) | 10 → 1 |
| `+0x02FD` | `+0x0092` | u16 LE | `margin_right` (pt) | 10 → 2 |
| `+0x0302` | `+0x0097` | u16 LE | `default_tab_stops` (pt) | 36 → 97 |
| `+0x0306` | `+0x009B` | u8 | `scroll_vertically` (bool) | 1 → 0 |
| `+0x0307` | `+0x009C` | u8 | `transparent_background` (bool) | 0 → 1 |
| `+0x0308..+0x030B` | `+0x009D..+0x00A0` | 4 B | candidate `solid_bg` COLORREF; unconfirmed |
| `+0x030C..+0x031B` | `+0x00A1..+0x00B0` | 16 B (CLSID) | `stylesheet_picker_clsid` |

Property-region offsets are CVForm-absolute minus `0x026B` (showcase
post-list region start). They land beyond `descriptor.size=152` for
Story1R, which confirms that the seq-ordered slicing the loader does
is approximate — Story1R's actual data extends past the 152 B
boundary the descriptor advertises. The msn_today Story1R block
(`size=142`) is smaller because msn_today doesn't carry the full set
of margin / tab / stylesheet fields (only stylesheet defaulted).

All margin / tab values are stored in **points** directly, not twips.
That's a different unit from CVForm's site geometry (twips), and
matches BBDESIGN's UI which displays them in points.

## Stylesheet picker — CLSID encoding

The stylesheet picker rewrites a 16-byte CLSID-shaped field at
`+0x030C`. Trailing 12 bytes (`-11F1-B405-000C875355C8`) are stable
across picks (machine + sequence half of a UUIDv1); only the leading
4-byte `data1` varies per selection:

| picker selection (BBDESIGN dropdown) | full CLSID at `+0x030C` | `data1` |
| --- | --- | --- |
| Home Stylesheet | `{0E7044EC-47FE-11F1-B405-000C875355C8}` | `0x0E7044EC` |
| Default Style Sheet | `{0E7044E4-47FE-11F1-B405-000C875355C8}` | `0x0E7044E4` |
| Copy #1 of Home Stylesheet | `{F6951B21-4870-11F1-B405-000C875355C8}` | `0xF6951B21` |

`Home` vs `Default` differs by exactly **bit `0x08` of the low byte**
(`EC` vs `E4`) — suggesting `Default` is encoded as "Home + use_default
flag", not a free CLSID rotation. `Copy #1` uses a wholly different
data1, so the encoding likely composes `(stylesheet_handle_index,
use_default_bit)` into the CLSID.

Resolution model: `CSection.styles` is the section's published
**stylesheet pool**; each Story holds a CLSID-encoded reference into
that pool plus a "use_default" bit:

- `use_default = 1` (bit 8 of CLSID's low byte clear) → ignore the
  pool index, use the title's resource-folder default stylesheet.
- `use_default = 0` and `index = 0` → pool[0] = `Home Stylesheet`
- `use_default = 0` and `index = 1` → pool[1] = `Copy #1 of Home`

Across saves with the *same* selection, the CLSID is **deterministic**
(showcase and the standalone stylesheet probe — saved on different
days — produced the identical `0E7044EC-...`). So this isn't a fresh
UUIDv1 per save; it's derived.

## Bookkeeping bytes that flip every save (ignore)

These are noise — they change on every BBDESIGN save regardless of
which property the author touched. They've shown up in every probe
diff:

| offset | role |
| --- | --- |
| `+0x016C` | save counter (1-byte) |
| `+0x0234..+0x0235` | "dirty mask" word; values like `52 00` / `ff 14` / `55 00` / `00 a0` rotate across saves |
| `+0x027A..+0x027B` | property-mask word; same kind of rotation |
| `+0x02B3` | per-control "modified" flag; flips between `00` and `01` |
| `+0x059E..+0x059F` | trailer counter |

When diffing future probe TTLs, immediately discard these regions
before interpreting the surviving differences.

## Probe methodology (for future RE)

The "single-property probe" technique used here is cheap and high
signal:

1. Establish a baseline TTL with a stable known state.
2. Author a copy in BBDESIGN with **exactly one property changed**.
3. Hex-diff the CVForm payload byte-for-byte. Discard the bookkeeping
   regions listed above.
4. The remaining 1–4 byte changes pinpoint the property's offset and
   encoding (u8 / u16 / packed CLSID / ...).

When BBDESIGN re-serializes due to a major content change (e.g.
embedding a BMP for a tiled background) the OLE form reorganizes and
fixed-offset diffs become unreliable — those probes need to be on top
of an already-tiled-bg baseline so the BMP is a constant.

## Open / not yet probed

- **Solid background COLORREF** — believed to live at `+0x0308..+0x030B`
  but never directly probed; needs a TTL with `transparent_background`
  off and a deliberately distinctive RGB (e.g. `RGB(255, 0, 255)` →
  bytes `FF 00 FF` would jump out).
- **`scroll_horizontally`** — inferred to be at `+0x0307` *before* the
  transparent probe overwrote that hypothesis. Likely sits within the
  `+0x0304..+0x0305` or `+0x0308..+0x030B` runs; needs a probe that
  enables horizontal scrolling.
- **The 3-byte gap at `+0x02FF..+0x0301`** and **2-byte gap at
  `+0x0304..+0x0305`** — small fields, possibly enum/flag bytes for
  story behavior (line spacing, paragraph alignment defaults, etc.).
- **Per-control CLSIDs for the BBCTL.OCX kinds** — Story / Caption /
  Audio / CaptionButton / Outline — each has a class GUID inside its
  site descriptor. Pinning these from BBCTL.OCX would let the parser
  identify control types instead of relying on name-suffix parsing.
- **CaptionButton / Audio / Outline / Shortcut property layouts** —
  Caption1 is pinned below by hex-diffing `4.ttl` (single Caption
  "Test caption" / MS Sans Serif) against `first title.ttl` slot
  `7/1` (single Caption "This is another page" / Comic Sans MS).
  The other four currently carry through as `raw_block` bytes on
  `StoryControl` / `AudioControl` / `CaptionButtonControl` /
  `OutlineControl` / `ShortcutControl`; only the descriptor's
  `xy_twips` is decoded.

## Caption1 property block

Pinned from `BBCTL.OCX!CLabelCtrl::DoPropExchange` (`FUN_40009356`,
v=4) plus its border parent `FUN_40003dbc` (v=3), with the
ExchangeStockProps mask `0xD2` set by `FUN_40008e81` (constructor).
Persist call order:

1. `CPropExchange::ExchangeVersion` v=4 (CLabelCtrl outer)
2. parent border persist:
   - `CPropExchange::ExchangeVersion` v=3
   - `COleControl::ExchangeStockProps` (writes mask-gated stock props
     in MFC alphabetical order; mask 0xD2 includes `BackColor` and
     `Font` at minimum — other bits pending more probes)
   - `PX_Long BevelWidth` (default 0)
   - `PX_Long FrameStyle` (default 0)
   - `PX_Long BevelHilight` (default `0xFFFFFF`, v ≥ 3)
   - `PX_Long BevelShadow` (default 0, v ≥ 3)
   - `PX_Long FrameColor` (default 0, v ≥ 2)
3. `PX_Long idTag` (default `-1`, `-1` = no script binding)
4. `PX_String strCaption` (the visible label; v ≥ 4 always written)
5. `PX_Bool fWordWrap` (default FALSE)
6. `PX_Bool fAutoSize` (default FALSE)
7. `PX_Long iAlignment` (default 0 = left)
8. `PX_Long fTransparent` (default TRUE, v ≥ 3)

On-disk layout in the LAST descriptor's `inline_tail` (which carries
the actual per-caption record buffer for multi-caption pages, or the
single descriptor's inline_tail for single-caption pages):

| offset (rel to inline_tail start) | size | field | source / meaning |
| --- | --- | --- | --- |
| `+0x00` | 16 | rect | i32 LE × 4: `left, top, right, bottom` (HIMETRIC) |
| `+0x10` | 6 | site_wrapper_a | `u16` (varies) + `u32` size echo |
| `+0x16` | 4 | form_size | u32, total CVForm payload size |
| `+0x1A` | 4 | constant 4 | u32 — site descriptor constant |
| `+0x1E` | 4 | CLabelCtrl version | u32 = 4 |
| `+0x22` | 4 | border parent version | u32 = 3 |
| `+0x26` | 4 | width_redundant | i32 = `rect.right - rect.left` |
| `+0x2A` | 4 | height_redundant | i32 = `rect.bottom - rect.top` |
| `+0x2E` | 4 | constant 0x1D | u32 = 29 |
| `+0x32` | 4 | (stock pad / zero) | u32 = 0 |
| `+0x36` | 1 | font_pre_clsid tag | u8 = 0 |
| `+0x37` | 4 | **back_color** | COLORREF (stock prop, BackColor; default `0xC8D0D8` = COLOR_3DFACE) |
| `+0x3B` | 1 | font_pre_clsid tail | u8 = 0 |
| `+0x3C` | 16 | StdFont CLSID | `{0BE35203-8F91-11CE-9DE3-00AA004BB851}` |
| `+0x4C` | 1 | font_version | `0x01` |
| `+0x4D` | 2 | font_charset | u16, LOGFONTA `lfCharSet` |
| `+0x4F` | 1 | font_attrs | u8: italic 0x02, underline 0x04, strikeout 0x08 |
| `+0x50` | 2 | font_weight | u16, e.g. 400 (FW_NORMAL), 700 (FW_BOLD) |
| `+0x52` | 4 | font_size_cy_lo | u32 = points × 10000 (12pt → `0x0001D4C0`) |
| `+0x56` | 1 | font_name_len | u8 |
| `+0x57` | N | font_name | ASCII (no NUL) |
| `+0x57+N` | 4 | **BevelWidth** | LONG (default 0) |
| `+0x57+N+4` | 4 | **FrameStyle** | LONG (default 0) |
| `+0x57+N+8` | 4 | **BevelHilight** | COLORREF (default `0xFFFFFF`) |
| `+0x57+N+12` | 4 | **BevelShadow** | COLORREF (default 0) |
| `+0x57+N+16` | 4 | **FrameColor** | COLORREF (default 0) |
| `+0x57+N+20` | 4 | **idTag** | LONG (default `-1`) |
| `+0x57+N+24` | 1 | strCaption_len | u8 |
| `+0x57+N+25` | M | strCaption | ASCII (no NUL) |
| `+0x57+N+25+M` | 2 | **fWordWrap** | u16 BOOL (default 0) |
| `+0x57+N+27+M` | 2 | **fAutoSize** | u16 BOOL (default 0) |
| `+0x57+N+29+M` | 2 | **iAlignment** | u16 short (default 0; 0=left, 1=center, 2=right) |
| `+0x57+N+31+M` | 4 | **fTransparent** | u32 LONG (default 1) |
| `+0x57+N+35+M` | ... | MS Forms 1.0 form trailer (varies; not part of CLabelCtrl persist) |

The `font_pre_clsid` (`+0x36..+0x3B`) is a 6-byte wrapper around the
stock `back_color` COLORREF: `[u8 0][u32 COLORREF][u8 0]`. Observed
values: `0xC8D0D8` (default, COLOR_3DFACE), `0x0000FF` (red), `0xFFF0FF`
(ivory) — confirmed across `4.ttl` page 0 Caption 1/2/3.

The font_attrs byte at `+0x4F` packs StdFont's `fItalic` /
`fUnderline` / `fStrikethrough` bits — pinned by hex-diff of
`4.ttl` page 0 captions (default styling vs italic Comic Sans MS at
0x02 vs underline+strikethrough Garamond at 0x0C).

### Post-strCaption block (10 bytes, layout pinned)

`fWordWrap`, `fAutoSize`, `iAlignment`, `fTransparent` are written
unconditionally by `FUN_40009356` as a 10-byte block immediately after
`strCaption`'s bytes:

| offset (rel to strCaption end) | size | field | type | default |
| --- | --- | --- | --- | --- |
| `+0x00` | 2 | `fWordWrap` | u16 BOOL | 0 (FALSE) |
| `+0x02` | 2 | `fAutoSize` | u16 BOOL | 0 (FALSE) |
| `+0x04` | 2 | `iAlignment` | u16 short | 0 (left; 1=center, 2=right) |
| `+0x06` | 4 | `fTransparent` | u32 LONG | 1 (TRUE) |

Pinned empirically: `4.ttl` pages 1/2 (V/H scrollbar variants, both
single-Caption pages with default "Test caption" / MS Sans Serif) and
`/var/share/drop/first title.ttl` page 1 (Comic Sans MS "This is
another page") all carry the same 10 bytes
`00 00 00 00 00 00 01 00 00 00` after their respective strCaption
texts — decoding to `(fWordWrap=0, fAutoSize=0, iAlignment=0,
fTransparent=1)`, the exact MFC defaults. `4.ttl` page 0's 3-caption
record buffer also exhibits the same 10-byte block between Caption 1's
text and Caption 2's pre-Font header.

The encoding (u16/u16/u16/u32) doesn't match a stock MFC PX_Long /
PX_Bool binary-stream output (which would write 4 bytes each =
16 B). It matches a property-bag-style VARIANT-typed write where
BOOL → VARIANT_BOOL (2 B) and short integers get truncated. The
decoder uses the pinned (u16, u16, u16, u32) layout pending a
non-default-value probe to verify on fixtures with a non-default
`iAlignment` or `fTransparent`.

Parser implementation: `_walk_cbform` + `_decode_caption` +
`_decode_label_persist` in `src/server/services/medview/ttl_loader.py`.
The decoder anchors on the StdFont CLSID landmark
(`0352e30b918fce119de300aa004bb851`) so the same offsets apply whether
the Caption's data is inline (collapsed format, `4.ttl` single-Caption
pages) or carried in the multi-caption shared record buffer
(`4.ttl` page 0 with 3 captions).

### Caption interactivity (deferred)

`idTag` indexes into a per-title script table that binds Click /
RightClick events to script macros. The event entry points are pinned
via string refs in BBCTL.OCX:

- `"Click"` @ `0x4002b298`
- `"RightClick"` @ `0x4002b2d0`

These are MFC OLE event names (`COleControl::FireEvent`). When
`idTag >= 0`, the event handler looks up the macro via the title's
script table (storage path not yet RE'd — likely a `CDPO` / CScript
object reachable from `CSection`). Lowering click → macro dispatch to
the MEDVIEW wire is a separate RE pass; the current decoder just
surfaces `id_tag` as a tagged LONG for offline inspection.

## Walker output (current parser)

`load_title()` returns a `LoadedTitle` whose `controls` tuple holds
one `Control` per site descriptor, dispatched by name prefix:

| name prefix | dataclass | depth |
| --- | --- | --- |
| `Caption` (8 chars exactly) | `CaptionControl` | rect + font + size + weight + text |
| `CaptionButton` | `CaptionButtonControl` | rect + raw block |
| `Story` | `StoryControl` | rect + raw block |
| `Audio` | `AudioControl` | rect + raw block |
| `Outline` | `OutlineControl` | rect + raw block |
| `Shortcut` | `ShortcutControl` | rect + raw block |
| anything else | `UnknownControl` | raw block only |

For msn_today.ttl the loader yields `(StoryControl Story1R xy=(3810,
0), ShortcutControl Shortcut1=R xy=(211, 1481))` with raw blocks of
142 / 91 bytes. For the showcase 7/0 it yields all five expected
controls in seq order (1, 2, 3, 4, 6) with the rect coordinates from
the showcase site table.

The `captions` accessor on `LoadedTitle` filters `controls` to just
the `CaptionControl` entries — preserves the prior lowering surface
that `lower_to_payload` / `build_bm0_baggage` rely on.

## Multi-page enumeration

`LoadedTitle.pages: tuple[LoadedPage, ...]` is the per-page container.
Each `LoadedPage` holds one CBForm's `(name, cbform_table, cbform_slot,
cvform_handle, page_bg, page_pixel_w, page_pixel_h, scrollbar_flags,
controls)`. Backcompat properties on `LoadedTitle`
(`controls` / `captions` / `page_bg` / `page_pixel_w` / `page_pixel_h`
/ `scrollbar_flags`) delegate to `pages[0]` so the PR1 lowering surface
(`lower_to_payload`, `build_bm0_baggage`) keeps emitting the page-0
body; PR3 drops the shims when both lift to per-page emission.

### CBForm collection

`load_title()` walks the section tree rooted at `CTitle.0/\x03object`:

1. CTitle is `[u8 title_version][CSection payload]
   [u32 resource_idx][CCount shortcut][MFC ansi trailing_name]`. The
   CSection payload is parsed via `parse_section()` (in
   `ole_helpers.py`) which returns
   `(version, sections, magnets, forms, contents, styles, frames,
   section_prop)`.
2. **If `base_section.forms` is non-empty** (4.ttl: CTitle hangs three
   CBForms directly off `base_forms`), use those refs in declared
   order.
3. **Else DFS through `base_section.sections`** (msn_today, showcase).
   At each node emit `.forms` BEFORE recursing into `.sections`. This
   matches BBDESIGN's tree-view ordering (forms-of-this-section first,
   then nested subsections):
   - msn_today: `base.sections = [9/1]` → CSection 9/1 has
     `forms = [5/0]` → 1 page.
   - showcase: `base.sections = [5/0]` → CSection "Front Matter" has
     `forms = [6/0]` + `sections = [5/1]` (CSection "Subsection") →
     "Subsection" has `forms = [6/1]` → 2 pages
     `[Home (6/0), Second Page (6/1)]`.
4. Fallback (no forms reachable anywhere in the tree): one
   `_CBFormRef` for slot 0 of the CBForm storage table. Defensive
   only; not exercised by any current fixture.

### Per-storage handle tables

`<table>/<slot>/\x03handles` is **local** to that storage — each CBForm
has its own handle table for resolving its `embedded_vform` swizzle
index; each CSection has its own handle table for resolving its
`sections` / `forms` / `contents` references; the CTitle has its own
for resolving `base_sections` / `base_forms`. The loader pre-reads all
handle streams up-front (`parse_handles_by_storage`) and keys the
result on `(table, slot)`.

### OLE storage names are hex-per-nibble

Blackbird-authored TTLs name OLE storage directories using lowercase
hex per nibble — table 10 / slot 12 are directory `a/c`, not `10/12`.
The showcase fixture uses table 10 for CContent; tables 0..9 collapse
to the same decimal-looking digit and are parsed identically. Helper:
`ole_storage_id()` in `ole_helpers.py`.

### Per-page properties

| Field | Source |
|---|---|
| `name` | `<table>/<slot>/\x03properties` `name` key (e.g. "Home", "Second Page") |
| `cbform_table` / `cbform_slot` | Position in the OLE compound file |
| `cvform_handle` | Resolved via `CBForm.embedded_vform_present + handle_idx`, swizzled through the per-storage `\x03handles` |
| `page_bg` / `page_pixel_w` / `page_pixel_h` / `scrollbar_flags` | CVForm Page properties block (`_parse_cvform_page`) |
| `controls` | Site descriptors of the embedded CVForm (`_decode_controls`) |

### 4.ttl page table

| Page | CBForm | scrollbar_flags |
|---|---|---|
| Test Page | 5/0 | 0 |
| Test Page Vertical Scrollbar | 5/1 | 2 (bit 1 = V) |
| Test Page Horizontal Scrollbar | 5/2 | 1 (bit 0 = H) |

Authored to differentiate the three pages by their scrollbar-config
dropdown only; everything else (Caption text, geometry, font) is
identical.

## CLSID-first dispatch (BBCTL classes pinned)

`_BBCTL_CLSIDS` in `ttl_loader.py` pins the 6 BBCTL.OCX site-class
CLSIDs to their site-class names. Each CVForm body's preamble carries
a class-CLSID table at offset `+0x9A` (154), stride 40 B; each site
descriptor's `flags & 0xFF` indexes into it. Dispatch is CLSID-first
with a name-prefix fallback for descriptors that lack a matching
table entry (or for non-BBCTL embeds, which keep dispatching as
`UnknownControl`).

CLSID → site class name map (pinned from
`docs/re-passes/BBCTL.OCX.md`):

| Site class | BBCTL.OCX class | ProgID | CLSID |
|---|---|---|---|
| Story | CQtxtCtrl | QTXT.QtxtCtrl.1 | `{9283AE00-6ABF-11CE-B942-00AA004A7ABF}` |
| Caption | CLabelCtrl | LABEL.LabelCtrl.1 | `{1A6F09D0-6574-11CE-A25F-00AA003E4475}` |
| Audio | CAudioCtrl | AUDIO.AudioCtrl.1 | `{58903560-57EB-11CE-A685-00AA005F54D7}` |
| CaptionButton | CLabelBtnCtrl | LABELBTN.LabelBtnCtrl.1 | `{B678F18B-8784-101B-BD52-00AA003E4475}` |
| Outline | CInfomapCtrl | INFOMAP.InfomapCtrl.1 | `{DED253E0-F4E2-11CD-AB6D-00AA003E4475}` |
| Shortcut | CBblinkCtrl | BBLINK.BblinkCtrl.1 | `{06F766A0-4F09-11CE-9A00-00AA006B1E42}` |

The `_SiteDescriptor` dataclass gains `class_index` and
`clsid: bytes | None`; the `UnknownControl` dataclass also carries
`clsid` for offline inspection. Per-control compound decoders
(StoryControl etc.) currently surface only what PR1 already extracted
(xy_twips + raw_block + Story content chase). Deep persist-stream
field decoding per control is a follow-up pass documented in
`docs/re-passes/BBCTL.OCX.md` §IPersistStreamInit::Save per class.

## Story content_proxy_ref chase (PR1 heuristic)

`StoryControl.content_proxy_ref: int | None` and
`StoryControl.content: TextRunsContent | None` are populated by an
empirical chase in `load_title()`:

1. **Find a Pascal-prefixed ASCII name in `raw_block`.** Pattern:
   `[u8 pascal_len in 4..127][N printable ASCII]` (greedy printable run
   enforces a clean non-printable boundary). For msn_today's Story1R:
   `\x0cHomepage.bdf`. For showcase's Story1R:
   `\x16Blackbird Document.bdf`. The leading u32 LE before the Pascal
   byte is a constant `0x0c` in both samples regardless of the actual
   name length, so the heuristic does NOT gate on it. PR2 BBCTL.OCX
   RE replaces this with the exact persist-stream offset.
2. **Walk the owning `CSection.contents`** (typed CProxyTable refs).
   Each CProxyTable carries a `name` property — match it against the
   Pascal name. CProxyTable / CContent property streams are
   MSZIP-wrapped (`maybe_decompress_ck` strips the envelope).
3. **Walk the matched CProxyTable's entries.** Pick the first whose
   target CContent's `type` property is `"TextRuns"` (skips
   `TextTree`, `ImageProxy`, `WaveletImage`, etc.). The matched
   `proxy_key` becomes `StoryControl.content_proxy_ref` (e.g.
   `0x00001500` for msn_today's Homepage.bdf).
4. **Decode the CContent payload** via `decode_textruns`
   (`ccontent.py`). See `docs/ccontent.md` for the body shape and
   PR1 caveats.

Failures at any step set `content_proxy_ref = None` and
`content = None` (logged at INFO `story_chase ...`). 4.ttl pages have
no owning CSection (`CTitle.base_forms` path) and no Story controls;
the chase short-circuits.
