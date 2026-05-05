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
seq:u32              ; 1-based sequence number; gaps signal a removed
                     ; or hidden site (showcase has 1,2,3,4,6 — no 5)
0x00030073:u32        ; constant marker
size:u32              ; bytes consumed by this site's name + properties
                     ; before the next site descriptor
flags:u32             ; high bit set, low byte = 0-based index reused
                     ; in references; e.g. 0x80000000 | i
ASCII name + NUL      ; e.g. "Story1R\0" / "Caption1\0"
i32 x_twips           ; control top-left X in twips (20 twips = 1pt)
i32 y_twips           ; control top-left Y in twips
... per-control properties ...
```

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

Story1R's property data sits at fixed offsets inside the showcase
CVForm payload (control sequence 1, payload starts at `+0x178`).
Tested via single-property probe TTLs:

| offset (in CVForm) | size | name | observed values | probe TTL |
| --- | --- | --- | --- | --- |
| `+0x02F7` | u16 LE | `margin_top` (pt) | 10 → 3 | `first title - new margins.ttl` |
| `+0x02F9` | u16 LE | `margin_bottom` (pt) | 10 → 4 | same |
| `+0x02FB` | u16 LE | `margin_left` (pt) | 10 → 1 | same |
| `+0x02FD` | u16 LE | `margin_right` (pt) | 10 → 2 | same |
| `+0x02FF..+0x0301` | 3 bytes | unmapped (always zero in samples) | — | — |
| `+0x0302` | u16 LE | `default_tab_stops` (pt) | 36 → 97 | `tabs-97pt-only.ttl` |
| `+0x0304..+0x0305` | 2 bytes | unmapped | — | — |
| `+0x0306` | u8 | `scroll_vertically` (bool) | 1 → 0 | `first title - scroll off.ttl` |
| `+0x0307` | u8 | `transparent_background` (bool) | 0 → 1 | `first title - transparent.ttl` |
| `+0x0308..+0x030B` | 4 bytes | candidate **solid bg COLORREF** when `transparent_background == 0`; unconfirmed | — | open probe |
| `+0x030C..+0x031B` | 16 bytes (CLSID-shaped) | `stylesheet_picker_clsid` | rotates per stylesheet pick (table below) | `first title - default stylesheet.ttl`, `first title - stylesheet.ttl`, `first title - more changes.ttl` |

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
- **CaptionButton / Audio / Outline property layouts** — Caption1
  was pinned (table below) by hex-diffing `4.ttl` (single Caption
  "Test caption" / MS Sans Serif) against `first title.ttl` slot
  `7/1` (single Caption "This is another page" / Comic Sans MS).
  CaptionButton / Audio / Outline still open.

## Caption1 property block

Caption1 follows its 16-byte site descriptor (`seq + marker + size +
flags`) immediately, with the rect inline:

| offset (rel to "Caption1" name start) | size | field | source / meaning |
| --- | --- | --- | --- |
| `+0x00` | 8 | name "Caption1" | site descriptor name (ASCII, no NUL) |
| `+0x08` | 16 | rect | i32 LE × 4: `left, top, right, bottom` (twips) |
| `+0x18` | 6 | site_wrapper_a | `u16` (varies) + `u32` size echo |
| `+0x1E` | 4 | form_size | u32, total CVForm payload size |
| `+0x22` | 12 | constants | three u32s: `(4, 4, 3)` |
| `+0x2E` | 4 | width_redundant | i32, equals `rect.right - rect.left` |
| `+0x32` | 4 | height_redundant | i32, equals `rect.bottom - rect.top` |
| `+0x36` | 4 | constant | u32 = `0x0000001D` (29) |
| `+0x3A` | 4 | zero | u32 = 0 |
| `+0x3E` | 6 | font_pre_clsid | `00 d8 d0 c8 00 00` |
| `+0x44` | 16 | StdFont CLSID | `{0BE35203-8F91-11CE-9DE3-00AA004BB851}` |
| `+0x54` | 1 | font_version | `0x01` (FONT_VERSION) |
| `+0x55` | 3 | font_charset / flags | varies per Caption styling |
| `+0x58` | 2 | font_weight | u16, e.g. 400 (FW_NORMAL) |
| `+0x5A` | 4 | font_size_cy_lo | u32 = points × 10000 (12pt → `0x0001D4C0`) |
| `+0x5E` | 1 | font_name_len | u8 |
| `+0x5F` | N | font_name | ASCII (no NUL) |
| `+0x5F+N` | 2 | pad | `00 00` |
| `+0x5F+N+2` | 22 | trailer_constants | parent-class persist defaults |
| `+0x5F+N+24` | 1 | caption_text_len | u8 |
| `+0x5F+N+25` | M | caption_text + NUL | ASCII text terminated by NUL |

Round-trip: in `4.ttl`, caption_text starts at file offset `0x167` for
Caption1 at `0xE2` (relative `0x84` + 1 = `0x85`, i.e. `0x167`).

Parser implementation: `parse_cvform_object` in
`src/server/blackbird/ttl_inspect.py` walks the CVForm by scanning for
the `0x00030073` site marker and dispatches Caption sites to
`_parse_caption_block`. The 22-byte `trailer_constants` block was
verified identical across both probes
(`00 00 00 00 00 00 ff ff ff 00 00 00 00 00 00 00 00 00 ff ff ff ff`),
so its bytes are inherited from the BBCTL.OCX parent control class
(MFC OLE control persist) rather than per-Caption state.

The single byte at `+0x57` (font_charset / flags) is the only observed
font-block variation: `0x00` for `4.ttl`'s default styling vs `0x0c`
for the showcase Caption (which authored Comic Sans MS). Whether this
is the IFont charset slot or a flags byte (bold/italic/underline/
strikethrough packed) is not yet RE'd from BBCTL.OCX; not blocking
since plain Caption rendering doesn't need it.
