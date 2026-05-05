# Typography Lowering Plan

Concrete steps to bring MOSVIEW's rendering in line with BBVIEW for
the typography pass. The on-disk → wire pipeline for fonts and styles
is fully RE'd in `docs/blackbird-title-format.md` and
`docs/mosview-authored-text-and-font-re.md`. This doc captures the
implementation work that the parser RE has unblocked.

## Current state

`src/server/blackbird/m14_payload.py:_build_section0_font_table()`
emits a hardcoded section-0:

- 1 face table entry: `Times New Roman`
- 1 descriptor: `face_slot=0, lfHeight=-12, lfWeight=400`, white text
- `descriptor_count = 0xFFFF` (sign-extended `-1`) so every authored
  `style_id` clamps to descriptor 0 via `MVCL14N!FUN_7e896610`
- 0 override records, 1 null pointer-table entry

Net effect: every paragraph renders in 12pt Times New Roman regardless
of authored style. Headings, code blocks, hyperlinks, etc. all collapse
to the same default.

## Target state

For each authored `CStyle` in the title's stylesheet (resolved through
its `linked_stylesheet` chain), emit a corresponding wire descriptor
with merged-from-defaults LOGFONTA. MOSVIEW already consumes
`name_index 0..0x35` style refs via `MVCL14N!FUN_7e896590` and looks up
the descriptor at `descriptor_table_off + style_id * 0x2a`. Filling
descriptor[0..N] with real values is a record-shape transform — no new
wire-protocol work, no client patching.

## Phase 1 — Multi-face font table from `CStyleSheet.fonts`

Replace the single hardcoded face entry with one entry per font in the
parsed CStyleSheet, keyed by font key.

- Input: `model["stylesheet"]["fonts"]` (list of `{key, name}`) from
  `parse_cstylesheet`. The reference Marvel TTL has 7 fonts with keys
  0–6 (key 0 = empty); the older Blackbird sample has 4 fonts adding
  Garamond at key 4.
- Output: face table sized to `max(key) + 1`, with `_encode_face_table_entry(name)`
  at index `key`. Empty slots (no font with that key) get
  `b"\x00" * 0x20`.
- Authored `face_slot_index` in CCharProps directly indexes this table
  — no remapping needed.

## Phase 2 — Multi-descriptor section-0 with merged LOGFONTA

For each `style_id` in the merged stylesheet (linked-stylesheet base
+ section-local overrides), build one descriptor by walking the
attribute resolution chain:

1. Start with `CSTYLE_DEFAULT_PROPS[name_index]` (VIEWDLL's per-style
   bake at `0x40770e00`).
2. If the parsed `CStyle.based_on` is set, recursively merge that
   style's resolution (depth limit 0x14 per
   `mosview-authored-text-and-font-re.md` §"Merge Semantics").
3. Apply the local `CCharProps.fields`, treating `0xFFFE` ("absent")
   and `0xFFFF` ("no_change") as transparent.
4. Decode `flags_word` bit-pairs (`absent_mask`, `value`) per
   `_CCHARPROPS_FIELDS[0]` to set `lfWeight`/`lfItalic`/`lfUnderline`
   in the descriptor.
5. Special-case `name_index 0x22` ("Strikethrough") — set descriptor
   `lfStrikeOut = 1` regardless of `flags_word`, since the
   strikethrough effect is name-tagged not bit-tagged (per the
   "Reserved bits" finding).

Field-by-field mapping into the `0x2a`-byte descriptor:

| descriptor field      | source                                         |
| --------------------- | ---------------------------------------------- |
| `face_slot_index`     | resolved `font_id` (CCharProps + chain)        |
| `descriptor_aux_id`   | `0` (informational; not consumed first paint)  |
| `override_style_id`   | `0` (no chain; encoded in override table)      |
| `text_color`          | resolved `text_color` colorref or sentinel     |
| `back_color`          | resolved `back_color` colorref or sentinel     |
| `lfHeight`            | `-MulDiv(pt_size, 96, 72) = -(pt_size * 4 // 3)` (Win32 pt-to-px at 96 DPI), `-12` if 0. NOT `-(pt_size * 20)` — that would be twips, but MOSVIEW's DC is `MM_TEXT` (logical units = device pixels). Live test: 22pt with `-440` produces 440-px-tall red rectangles spanning the pane. |
| `lfWidth`             | `0`                                            |
| `lfEscapement`        | `0`                                            |
| `lfOrientation`       | `0`                                            |
| `lfWeight`            | `700` if bold value bit, else `400`            |
| `lfItalic`            | `1` if italic value bit, else `0`              |
| `lfUnderline`         | `1` if underline value bit, else `0`           |
| `lfStrikeOut`         | `1` if `name_index == 0x22`, else `0`          |
| `lfCharSet`           | `0` (DEFAULT_CHARSET; not on disk)             |
| `lfOutPrecision`      | `0`                                            |
| `lfClipPrecision`     | `0`                                            |
| `lfQuality`           | `0`                                            |
| `lfPitchAndFamily`    | `0`                                            |
| `style_flags`         | `0`                                            |
| `extra_flags`         | `0`                                            |

`descriptor_count` in the header switches from `0xFFFF` to the actual
count `N`; the `MVCL14N!FUN_7e896610` clamp then accepts every authored
`style_id < N` and routes it to its real descriptor.

## Phase 3 — Override records for the inheritance chain

Emit one `0x92`-byte override record per non-root `CStyle.based_on`
relationship, stored at the override table after the descriptors. Each
record:

- `style_id` = child style id
- `parent_style_id` = `CStyle.based_on`
- `face_slot_override`/`*_override` per-field values that DIFFER from
  the parent's resolved attributes (sentinel `0xfffe`/`0` for fields
  that should inherit, real value for explicit overrides)

The merge in MVCL14N walks parent first, then applies the child's
overrides — same semantics as our resolution chain in Phase 2. With
the descriptor table already pre-merged in Phase 2, override records
are mostly redundant and could ship empty (`override_count = 0`); they
become important if/when MOSVIEW callers query individual override
flags.

**Decision**: ship `override_count = 0` for the first pass, since
Phase 2's descriptors are already fully merged.

## Phase 4 — Linked-stylesheet merge

Where the section-local stylesheet has `linked_stylesheet_present = 1`,
walk its handle table (`<storage>/\x03handles[swizzle]`), decode the
target via `decode_handle()`, and merge the section-local CStyle list
on top of the title-level base. Each `style_id` in the section's local
table overrides the same id in the base; ids absent in the local table
fall through to the base.

Helpers ready:
- `decode_handle(h)` → `(table_id, slot)`
- `parsed.linked_stylesheet_swizzle` is the index into the per-storage
  `\x03handles` table.

## Out of scope (later)

- **Item-record headers (sec07/sec08)** — paragraph layout flows
  through items, not CParaProps. Ships zero items today; Phase 1–4
  doesn't touch this. Visible result: paragraphs still render in the
  default block layout, but each paragraph's TEXT is now styled
  correctly. List numbering, indent ladders, drop caps not yet
  rendered.
- **TextRuns/TextTree story-buffer lowering** — the case-1 0xBF
  chunks the server ships use a single `title_caption` fallback text
  per topic. After Phase 1–4 land, headings/body/code paragraphs will
  appear styled but with the same placeholder text per topic.
- **Image wrap (`INTRUDE` / proxy_key 0x0601)** — needs the picture
  control's CContent variant lowered into an item record with the
  right `style_id` reference (one of `0x2f..0x35`).

## Verification

1. **Round-trip the wire bytes**: load `resources/titles/4.ttl`,
   build the new section-0, parse it back through
   `m14_parse.parse_payload`, assert face table entries, descriptor
   count, and per-descriptor LOGFONTA bytes match expectations.
2. **Pin the merge resolution**: for each of the 54 styles in the
   reference TTL, assert the resolved descriptor has the right
   `face_slot_index`, `lfHeight`, `lfWeight`. Pin specifically:
   - `Normal` (0x00) → font 1, lfHeight `-14` (= -MulDiv(11, 96, 72)), lfWeight 400
   - `Heading 1` (0x01) → font 2 (Arial), lfHeight `-29` (= -MulDiv(22, 96, 72)),
     lfWeight 700
   - `Hyperlink` (0x1e) → text_color blue, lfUnderline 1
   - `Strikethrough` (0x22) → lfStrikeOut 1 (name-tagged)
   - `Preformatted` (0x23) → font 3 (Courier — monospace)
3. **Live render check**: launch the MSN client (per `manage-server`
   skill, the Win95 VM at the standard 86Box launch). Open MSN Today.
   Compare visible heading typography against a screenshot of BBVIEW
   loading the same TTL standalone. Headings should now appear in
   Arial 22pt bold, body text in Times New Roman 11pt, etc.
4. **Existing test suite stays green** — the wire is a strict
   superset of today's minimal section-0; no test should regress.

## Critical files

To modify:
- `src/server/blackbird/m14_payload.py` — replace
  `_build_section0_font_table()` with the multi-face/multi-descriptor
  builder; consumes `model["stylesheet"]` from the parsed inspection
- `tests/test_services.py::TestMEDVIEWTitleOpen` — update the existing
  pin assertions (currently `parsed.font_blob.length == 0x60` and
  hardcoded face name) to reflect the new sized table
- `tests/test_ttl_inspect.py` — extend with end-to-end tests that
  walk a parsed CStyleSheet through the new lowering and validate
  per-style descriptor output

Read-only references:
- `src/server/blackbird/ttl_inspect.py` —
  - `parse_cstylesheet`, `CSTYLE_DEFAULT_PROPS`, `CSTYLE_NAME_DICTIONARY`
  - `decode_handle` for linked-stylesheet swizzle resolution
- `src/server/blackbird/m14_payload.py:200-368` — existing section-0
  helpers (`_encode_face_table_entry`, `_encode_descriptor`,
  `_build_section0_font_table`)
- `docs/mosview-authored-text-and-font-re.md` — wire schema +
  `0x40770e00` defaults table layout
- `docs/blackbird-title-format.md` — on-disk CStyle/CCharProps/CParaProps
  grammar + `flags_word` bit semantics

VIEWDLL functions cited (for sanity checks during review):
- `CCharProps::EGetWord` @ `0x4070692e` (kind→offset map)
- `CCharProps::EGetColorRef` @ `0x40707ae2`
- `CStyle::ResetCharProps` @ `0x4073194b` (the comprehensive merger)
- `MVCL14N::FUN_7e896610` (style-id clamp at the consumer side)
