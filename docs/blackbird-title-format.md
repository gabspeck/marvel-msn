# Blackbird Title Container Notes

For `MOSVIEW.EXE` and the MSN MediaView runtime, see
`docs/mosview-mediaview-format.md`. This document covers the standalone
Blackbird OLE title store, not the MediaView 1.4 title pipeline consumed by
`MVCL14N.DLL` and `MVTTL14C.DLL`.

## Scope

These notes describe the standalone Blackbird title container used by:

- `msn today.ttl`
- `/var/share/drop/prj60a5.tmp`

Both files are OLE Compound Document files and carry the same logical title payload. The `.tmp` file differs only in outer compound-document layout details; every logical stream payload matches the sample `.ttl`.

## High-level model

- `.prj` is a project container.
- `Title0` inside the `.prj` is the title subtree.
- A standalone `.ttl` is the `Title0` subtree lifted to the compound root.
- `BBVIEW`/Blackbird runtime code consumes this title object-store format through `VIEWDLL.DLL` and `COSCL.DLL`.

Help-file model (`AUTHOR.HLP`, `BBDESIGN.HLP`):

- project → title → section / page → window / controls → story / media assets
- story text is authored separately (`.bdf` in Word) and attached through story controls
- pages choose windows; windows and controls own layout semantics

So the standalone `.ttl` is an authored object graph, not a precomputed
MEDVIEW pane/layout cache.

## Root layout

Observed root streams/storages:

- `\x03TitleProps`
- `\x03type_names_map`
- `\x03ref_1` .. `\x03ref_9`
- numbered storages `1` .. `9`
- nested storages such as `1/0`, `7/1`, `8/5`, `9/1`
- per-object artifact streams:
  - `N/M/\x03object`
  - `N/M/\x03properties`
  - `N/M/\x03handles`

Artifact names come from `COSCL.DLL::GetObjectArtifactStreamName`:

- artifact `1` -> `\x03object`
- artifact `2` -> `\x03handles`
- artifact `4` -> `\x03properties`

Relevant code paths:

- `COSCL.DLL::CObjectStoreFactory::Open`
- `COSCL.DLL::CObjectStore::AccessTitleProperties`
- `COSCL.DLL::CObjectStore::StreamWrite`
- `COSCL.DLL::CDPORefMgr::AccessObjectStream`

## `type_names_map`

`COSCL.DLL::CDPORefMgr::TypeIndexToTypeString` and `TypeIndexToLevelSpecifier` show that `\x03type_names_map` maps:

- logical type slot -> class name
- logical type slot -> level specifier / ref-table id

Observed wire format:

1. `uint32 entry_count`
2. `uint16 max_slot`
3. repeated `entry_count` times:
   - `uint8 name_len`
   - `char[name_len] type_name`
   - `uint32 level_specifier`

The sample decodes cleanly if the first slot is `max_slot` and later slots descend by stream order. That produces:

| slot | class name         | table |
| ---- | ------------------ | ----- |
| 9    | `CTitle`           | 1     |
| 8    | `CContent`         | 8     |
| 7    | `CBForm`           | 5     |
| 6    | `CBFrame`          | 3     |
| 5    | `CSection`         | 9     |
| 4    | `CVForm`           | 6     |
| 3    | `CProxyTable`      | 7     |
| 2    | `CStyleSheet`      | 4     |
| 1    | `CResourceFolder`  | 2     |

Use `scripts/inspect_blackbird_title.py` to print the exact decoded table.

## Handles and ref tables

`COSCL.DLL::CDPORefMgr::HandleDereference` shows that object handles are split into:

- top bits: ref-table selector (`handle >> 0x15`)
- low 21 bits: slot within that ref table

This matches the numbered root ref streams and numbered top-level storages:

- table `1` -> title objects
- table `2` -> resource folders
- table `3` -> frames
- table `4` -> style sheets
- table `5` -> forms
- table `6` -> vforms
- table `7` -> proxy tables
- table `8` -> content objects
- table `9` -> sections

Observed `\x03handles` format:

1. `uint32 handle_count`
2. `uint32 handles[handle_count]`

Semantically, this is the per-object swizzle table used by `CSmartPtr::Serialize`:

- `COSCL.DLL::SwizzleHandleToIndex` converts a real handle into a zero-based index
- that zero-based index is what gets written inside serialized object payloads
- `COSCL.DLL::SwizzleIndexToHandle` resolves the index back through the `\x03handles` array
- `COSCL.DLL::AccessObjectStream` applies the swizzle table when flag `0x0d` says an object stream has one

Example:

- `1/0/\x03handles = [2, 0x01200001, 0x00400000]`
- `9/1/\x03handles = [4, 0x00A00000, 0x00E00000, 0x00E00001, 0x00E00002]`

`handle_count` is the exact number of valid zero-based swizzle indices for that object.

### Handle bit format

Each `uint32` handle stored in `\x03handles` (and mirrored as
`obj_cos_path_handle` in the matching `\x03ref_<table_id>` CDPORef
entry) packs two fields:

```
handle = (table_id << 21) | slot
table_id = handle >> 21
slot     = handle & 0x1FFFFF
```

`table_id` is the same level-specifier that keys the
`\x03type_names_map` entries. `slot` names the per-class sub-storage
(`<table_id>/<slot>/\x03object`). 11 bits are nominally available
for `table_id` (max observed = `0xa = 10` for `CContent`) and 21 for
`slot` (max observed = `0x7`).

Verified across the reference Marvel TTL (`resources/titles/4.ttl`,
15 handles) and the older Blackbird sample
(`/var/share/drop/first title.ttl`, 21 handles) — 36/36
round-trip cleanly. Helpers `decode_handle` / `encode_handle` in
`src/server/blackbird/ttl_inspect.py` expose the format.

Concrete example: in `/var/share/drop/first title.ttl`, the
section-local CStyleSheet `4/1` has
`linked_stylesheet_present=1` and `linked_stylesheet_swizzle=0`. Its
own `\x03handles` table reads `[0x00800000]`. Decode:
`(0x800000 >> 21, 0x800000 & 0x1FFFFF)` = `(4, 0)` → CStyleSheet
slot 0 → `4/0/\x03object`, the title-level base stylesheet. The
section thus inherits everything not overridden in `4/1`.

Observed MFC count/string conventions inside object payloads:

- list and map container counts are written through MFC `CArchive::WriteCount` / `ReadCount`
- in the sample, every count lands in the small form:
  - `uint16 count`
- the standard `0xffff` extended-count escape is implied by the MFC API but not exercised by the sample
- short ANSI `CString` values in object payloads use the expected MFC short form:
  - `uint8 char_count`
  - `char[char_count]`
- the sample uses only the short ANSI case; longer/count-escape forms were not needed

`VIEWDLL.DLL::SPtrTypeFromSPtr` gives the smart-pointer type codes that appear in typed smart-pointer lists:

| code | class |
| ---- | ----- |
| 1 | `CProject` |
| 2 | `CTitle` |
| 3 | `CSection` |
| 4 | `CBForm` |
| 5 | `CBFrame` |
| 6 | `CMagnet` |
| 7 | `CStyleSheet` |
| 8 | `CShortCut` |
| 9 | `CFolder` |
| 10 | `CContent` |
| 11 | `CContentFolder` |
| 12 | `CVForm` |
| 13 | `CRootContentFolder` |
| 14 | `CResourceFolder` |

## `CK` compression wrapper

Some `\x03object` and `\x03properties` artifacts are wrapped in a generic compression envelope. `COSCL.DLL::CompressArtifactIfBeneficial` and `DecompressObject` show the wire format:

1. `uint8 wrapper_version`
   - observed value `1`
2. `uint32 uncompressed_size`
3. `uint32 compressed_size`
   - includes the `CK` marker
4. `char[2] magic`
   - literal `CK`
5. `uint8[compressed_size - 2]`
   - raw deflate payload

Observations:

- decompression uses zlib raw-deflate mode (`wbits = -15`)
- object compression flag is `0x0f`
- properties compression flag is `0x11`
- `CContent` object streams with property type other than `TextTree` or `TextRuns` are explicitly marked no-compress via flag `0x10`
- sample compressed artifacts include:
  - `4/0/\x03object`
  - `6/0/\x03object`
  - `7/0/\x03properties`
  - `7/1/\x03properties`
  - `7/2/\x03properties`
  - `8/5/\x03properties`
  - `8/6/\x03object`

## `\x03TitleProps`

`COSCL.DLL::CObjectStore::AccessTitleProperties` opens `\x03TitleProps` as the title-level property storage.

Simple property bags observed in `\x03TitleProps` and many `\x03properties` streams use this format:

1. `uint32 property_count`
2. repeated `property_count` times:
   - `uint8 key_len`
   - `char[key_len] key`
   - `uint16 vartype`
   - value payload

Observed value payloads:

- `0x0008` -> string
  - `uint32 char_count`
  - `char[char_count + 1]` including trailing NUL
- `0x000b` -> bool
  - `uint16 value`
- `0x0011` -> `uint8`
- `0x0013` -> `uint32`
- `0x0041` -> blob
  - `uint32 byte_count`
  - `uint8[byte_count]`

Example from `1/0/\x03properties`:

- count `1`
- key `name`
- vartype `0x0008`
- value `MSN Today`

Example keys from `\x03TitleProps`:

- `localname`
- `msnsiteimagelength`
- `msnsitenodeid`
- `msn`
- `local`
- `intro`

Not every `\x03properties` stream is stored raw. Some property tables are wrapped in the `CK` compression envelope first, then decode cleanly as the same simple property-table grammar.

## `\x03object` payloads

Most per-object `\x03object` artifacts are written by class-specific `Serialize` methods in `VIEWDLL.DLL`. They are not the same thing as the archive/export path used by `WriteObjectToArchive` / `CreateObjectFromArchive`.

The archive/export path is still relevant for class relationships:

- `WriteObjectToArchive`
- `CreateObjectFromArchive`
- class-specific `SaveToArchive` / `ConstructFromArchive`

High-confidence semantics:

- `CTitle`
  - wire grammar:
    1. `uint8 version = 2`
    2. embedded `CSection` base payload
    3. `uint32 resource_folder_swizzle_index`
    4. `WriteCount(shortcut_count)`
    5. repeated `shortcut_count` times:
       - one serialized `CShortCut`
    6. trailing MFC ANSI `CString`
  - observed sample:
    - one child section in the base section list: swizzle index `0` -> handle `0x01200001`
    - resource-folder swizzle index `1` -> handle `0x00400000`
    - shortcut count `0`
    - trailing string empty

- `CSection`
  - wire grammar:
    1. `uint8 version = 3`
    2. sections list
       - `WriteCount(section_count)`
       - repeated `section_count` times:
         - `uint32 section_swizzle_index`
    3. typed smart-pointer lists for:
       - magnets
       - forms
       - contents
       - style sheets
       - frames
       - each entry is:
         - `uint16 s_ptr_type`
         - `uint32 swizzle_index`
    4. trailing `CSectionProp`
  - `CSectionProp` wire grammar:
    1. presence byte for section ref A, then optional `uint32 swizzle_index`
    2. presence byte for section ref B, then optional `uint32 swizzle_index`
    3. presence byte for section ref C, then optional `uint32 swizzle_index`
    4. `uint32 field_0`
    5. `uint32 field_1`
    6. `uint8 field_2`
    7. for section version `> 2`: presence byte for trailing form ref, then optional `uint32 swizzle_index`
  - observed sample `9/1/\x03object`:
    - sections `[]`
    - magnets `[]`
    - forms `[type 4, index 0 -> handle 0x00A00000]`
    - contents `[type 10, indices 1..3 -> handles 0x00E00000..0x00E00002]`
    - styles `[]`
    - frames `[]`
    - `CSectionProp = {all refs absent, field_0 = 0, field_1 = 2, field_2 = 0, form ref absent}`
  - lowering note:
    - the serialized `CSection` payload contains section/form/content/style/frame
      lists plus `CSectionProp`; there is no authored fixed-width pane-descriptor
      table analogous to MediaView selectors `0x07`, `0x08`, or `0x06`
    - in the sample, the three top-level authored content refs are section
      membership entries, not authored child-pane records
    - help-file hierarchy puts page/window/control semantics elsewhere, so
      `CSection.contents` is a topic/media source layer, not a direct pane map

- `CResourceFolder`
  - wire grammar:
    1. `uint8 version = 1`
    2. embedded `CFolder` payload
    3. `uint32 default_stylesheet_swizzle_index`
    4. `uint32 default_frame_swizzle_index`
  - observed sample:
    - default stylesheet index `1` -> handle `0x00800000`
    - default frame index `0` -> handle `0x00600000`

- `CFolder`
  - wire grammar:
    1. `uint8 version = 3`
    2. typed smart-pointer list of owned objects
       - `WriteCount(object_count)`
       - repeated `object_count` times:
         - `uint16 s_ptr_type`
         - `uint32 swizzle_index`
    3. trailing `uint8 field_2c`
  - observed sample `2/0/\x03object`:
    - object count `2`
    - entry 0: `type 5 (CBFrame)`, index `0` -> handle `0x00600000`
    - entry 1: `type 7 (CStyleSheet)`, index `1` -> handle `0x00800000`
    - trailing byte `0`

- `CBForm`
  - wire grammar:
    1. `uint8 version = 2`
    2. MFC ANSI form-name `CString`
    3. `uint8 form_mode`
    4. `uint8 embedded_vform_present`
    5. optional `uint32 embedded_vform_swizzle_index`
    6. `uint32 frame_swizzle_index`
    7. `uint32 field_2c`
    8. `uint32 field_30`
    9. `uint32 field_34`
    10. `uint32 field_38`
    11. `uint64 field_3c_40`
    12. `uint8 field_44`
    13. `uint32 dpi_x`
    14. `uint32 dpi_y`
  - observed sample:
    - form name empty
    - embedded vform present with index `0` -> handle `0x00C00000`
    - frame index `1` -> handle `0x00600000`
    - trailing DPI values `96`, `96`

- `CVForm`
  - sample object artifact `6/0/\x03object` is stored inside the `CK` compression wrapper
  - the decompressed payload starts with `uint8 version = 1`
  - the remainder is a fixed-layout view/form state block with numeric fields and GUID-bearing records
  - importantly for the title container format, it is still just one normal per-object `\x03object` artifact referenced by a `CSmartPtr`; it does not introduce any extra streams or container rules beyond the generic object-store model

- `CBFrame`
  - wire grammar:
    1. `uint8 version = 2`
    2. MFC ANSI `CString` at `this + 0x04`
    3. MFC ANSI `CString` at `this + 0x08`
    4. `uint64 field_10_17`
    5. `uint64 field_18_1f`
    6. `uint32 field_20`
    7. `uint32 field_24`
    8. `uint8 field_28`
    9. `uint32 field_2c`
    10. `uint8 field_30`
    11. `uint8 field_34`
    12. `uint8 field_0c`
    13. `uint8 tail_present`
    14. optional trailing serialized object if `tail_present != 0`
  - observed sample:
    - first string empty
    - second string `MSN Today`
    - `tail_present = 0`

- `CStyleSheet`
  - wire grammar:
    1. `uint8 version`
       - sample value `9`
    2. font map (`CMap<unsigned short, CString>`)
       - `WriteCount(font_entry_count)`
       - repeated `font_entry_count` times:
         - `uint16 font_id`
         - MFC ANSI `CString font_name`
    3. style map (`CMapWordToOb`)
       - `WriteCount(style_entry_count)`
       - repeated `style_entry_count` times:
         - `uint16 style_id`
         - one MFC object-serialized `CStyle`
    4. `uint8 linked_stylesheet_present`
    5. optional `uint32 linked_stylesheet_swizzle_index`
  - observed sample:
    - font entries:
      - `6 -> "Courier New"`
      - `5 -> "Courier New"`
      - `4 -> "Courier New"`
      - `3 -> "Courier New"`
      - `2 -> "Arial"`
      - `1 -> "Times New Roman"`
      - `0 -> ""`
    - style entry count `54`
    - first style entry key `0`
    - first `CStyle` object begins with the MFC runtime-class wrapper for `CStyle`:
      - `0xffff`
      - `schema = 1`
      - `class_name = CStyle`
  - older versions upgrade through explicit load-time shims before version 9 state is normalized

- `CProxyTable`
  - `Serialize` delegates to the contained map object at `this + 0x1c`
  - the contained helper serializes a proxy-data map:
    1. `WriteCount(entry_count)`
    2. repeated `entry_count` times:
       - `uint32 proxy_key`
       - one serialized `CProxyData`
  - `CProxyData::Serialize` is just one `CSmartPtr<CContent>`, so the per-entry on-wire shape is:
    - `uint32 proxy_key`
    - `uint32 content_swizzle_index`
  - observed sample:
    - `7/0/\x03object`:
      - `0x00001500 -> index 0 -> handle 0x01000007`
      - `0x00001400 -> index 1 -> handle 0x01000006`
    - `7/2/\x03object`:
      - `0x00000600 -> index 0 -> handle 0x01000005`
  - in the supported sample, top-level `CSection.contents` handles land here
    first; proxy keys then fan out to the actual `CContent` payloads

- `CStyle`
  - source: `?Serialize@CStyle@@UAEXAAVCArchive@@@Z` @ VIEWDLL.DLL
    `0x40707d6f`; intrusion semantics from
    `?GetIntrusion@CStyle@@QBEGXZ` @ `0x40727778`; based-on name
    table from `?GetBasedOn@CStyle@@QBEPBDXZ` @ `0x407087c6`
  - version `3` body grammar:
    1. `uint8 version` (must be `3`)
    2. `uint8 packed_selector`
       - bits `2..7` = `name_index` — index into the **predefined
         54-entry name dictionary** baked into VIEWDLL (see below);
         valid range `0..0x35`
       - bit `1` = `char_props_only`: when set, skip `CParaProps`
         (style modifies character properties only)
       - bit `0` = `is_intrusion`: when set, this is a wrap/intrusion
         style; no `CParaProps` and no `CCharProps` body follow
    3. `uint8 secondary_index`
       - if `is_intrusion`: `intrusion_index` — range `0..8` per
         BBDESIGN.EXE validator string "Intrusion argument is
         invalid. Valid values are 0 to 8."; consumed by
         `CStyle::GetIntrusion`. Always `0` in the reference TTL.
       - else: `based_on` style index — `0xff` = root / no parent.
         BBDESIGN validates non-existence ("Based on name '%1' does
         not exist") and non-cyclic chains ("would cause a circular
         defininition")
    4. if `!is_intrusion and !char_props_only`: serialized `CParaProps`
    5. if `!is_intrusion`: serialized `CCharProps`
  - older versions (`1`, `2`) read names or u16 indices; legacy paths
    upgrade in-place during deserialize. The on-disk format the
    publisher writes today is version `3` only.

- **Predefined style-name dictionary** (54 entries, indexed by
  `name_index` and `based_on`). Recovered from VIEWDLL.DLL data
  tables `&PTR_s_Normal_40770e00` (entries 0..0x2e, stride `0xd`
  dwords) and `DAT_40771648 + idx*8` (entries 0x2f..0x35).
  Captured verbatim in `CSTYLE_NAME_DICTIONARY` at
  `src/server/blackbird/ttl_inspect.py`:
  - `0x00`: `Normal` (root)
  - `0x01..0x06`: `Heading 1` … `Heading 6`
  - `0x07..0x0f`: `TOC 1` … `TOC 9`
  - `0x10..0x18`: `Section 1` … `Section 9`
  - `0x19`: `Abstract Heading`
  - `0x1a`: `Term Definition`
  - `0x1b`: `List Bullet`
  - `0x1c`: `List Number`
  - `0x1d`: `Term`
  - `0x1e`: `Hyperlink`
  - `0x1f`: `Emphasized`
  - `0x20`: `Bold`
  - `0x21`: `Italic`
  - `0x22`: `Strikethrough`
  - `0x23`: `Preformatted`
  - `0x24`: `Blockquote`
  - `0x25`: `Address`
  - `0x26`: `Underline`
  - `0x27`: `Strong`
  - `0x28`: `Code`
  - `0x29`: `Keyboard`
  - `0x2a`: `Citation`
  - `0x2b`: `Variable Name`
  - `0x2c`: `Fixed Width`
  - `0x2d`: `Abstract Body`
  - `0x2e`: `Sample`
  - `0x2f`: `Wrap: Design feature` *(first intrusion style)*
  - `0x30`: `Wrap: Supporting graphic`
  - `0x31`: `Wrap: Related graphic`
  - `0x32`: `Wrap: Sidebar graphic`
  - `0x33`: `Wrap: Advertisement`
  - `0x34`: `Wrap: Custom 1`
  - `0x35`: `Wrap: Custom 2`

  Effects like strikethrough are NOT bits in CCharProps — they're
  delivered by inheriting from (or alt-referencing) one of these
  named styles. The "Bold" / "Italic" / "Underline" entries are
  parallel to the CCharProps `flags_word` bits — a style can either
  set the bit directly or inherit from the corresponding named
  style. Intrusion styles (`0x2f..0x35`) are pure-metadata records
  marking text-wrap behavior around an inline graphic.

- `CCharProps`
  - source: `?Serialize@CCharProps@@UAEXAAVCArchive@@@Z` @ VIEWDLL.DLL
    `0x40707fcc`; field semantics from `?EGetWord@CCharProps@@…`
    @ `0x4070692e` (kind→on-disk offset map) plus `EGetBold` /
    `EGetItalic` / `EGetUnderline` / `EGetSuperscriptPos` /
    `EGetSubscriptPos`
  - version `2` body grammar:
    1. `uint8 version` (must be `2`)
    2. `uint8 mask_explicit` — bit set = field has explicit value
    3. `uint8 mask_concrete` — bit clear = field is "absent" sentinel
       (`0xfffe` for u16 / `0xfffffffe` for u32); bit set + bit clear
       in `mask_explicit` = "no_change" sentinel (`0xffff` /
       `0xffffffff`)
    4. for each bit `k` where `(mask_explicit & mask_concrete)` bit
       `k` is set, read field:
       - bit `0`: `uint16 flags_word` — packed bold/italic/underline/
         superscript/subscript bits
       - bit `1`: `uint16 font_id` — index into
         `CStyleSheet.fonts[].key`
       - bit `2`: `uint16 pt_size` — point size (engine default `12`
         when unset, per `GetPtSize` @ `0x40706b85`)
       - bit `3`: `uint32 text_color` COLORREF
       - bit `4`: `uint32 back_color` COLORREF
  - `flags_word` bit layout (high byte = "absent" mask, low byte =
    value bits) — pinned via VIEWDLL's `Set*State` setters:
    - bold (`SetBoldState` @ `0x407275f3`):
      absent `0x0100` / value `0x0002`
    - italic (`SetItalicState` @ `0x40727615`):
      absent `0x0200` / value `0x0004`
    - underline (`SetUnderlineState` @ `0x40727637`):
      absent `0x0400` / value `0x0008`
    - superscript (`SetSuperscriptState` @ `0x40727659`):
      absent `0x0800` / value `0x0010`
    - subscript (`SetSubscriptState` @ `0x4072767b`):
      absent `0x1000` / value `0x0020`
  - Each `Set*State(int v)` clears the absent bit then sets/clears
    the value bit per `v`. The peer `SetDefault*` (e.g.
    `SetDefaultBold` @ `0x4072769d`) ORs the absent bit back in
    (= "inherit from parent"). Authoring-time pattern: explicit
    on/off ⇒ absent=0; inherit ⇒ absent=1.
  - **superscript and subscript are mutually exclusive at authoring
    time** — BBDESIGN.EXE validator "Conflicting postionng
    information. Check superscript and subscript values." refuses
    to author styles that set both. VIEWDLL's wire-side setters do
    NOT enforce this, so a malformed TTL can technically have both
    bits set; rendering behavior in that case is engine-defined.
  - **Reserved bits**: `0x0040`, `0x0080` (low byte) and `0x2000`,
    `0x4000`, `0x8000` (high byte) are NOT consumed by VIEWDLL —
    confirmed via exhaustive bit-immediate search and the `IsStyle`
    @ `0x40707b3f` / `ResetCharProps` @ `0x4073194b` consumers,
    which only read the 5 documented pairs. The per-style baked
    defaults table at `0x40770e00` always sets bits `0x2000` and
    `0x4000` in non-zero entries (likely an assembler/data-table
    artifact); user-authored TTLs may also set bit `0x8000`
    (observed in `/var/share/drop/first title.ttl` 4/1 sid=1
    `flags_word=0xfcfe`). Carry them through verbatim — the
    renderer ignores them.
  - version `1` reads four `uint16`s + two `uint32`s without masks;
    not produced by current publishers.

- `CParaProps`
  - source: `?Serialize@CParaProps@@UAEXAAVCArchive@@@Z` @ VIEWDLL.DLL
    `0x407082e2`; field semantics from `?EGetWord@CParaProps@@…`
    @ `0x4070733d` and `?EGetShort@CParaProps@@…` @ `0x4070812e`
    (kind→on-disk offset maps) plus the `EGetXxx` accessors that
    name each kind
  - version `2` body grammar:
    1. `uint8 version` (must be `2`)
    2. `uint16 mask_explicit` (LE) — same semantics as `CCharProps`
    3. `uint16 mask_concrete` (LE)
    4. for each bit `k` in `0..11` where both masks set, read field
       (size = 1 byte for bits `0`, `1`, `3`, `4`, `8`; 2 bytes for
       the rest. The engine reads the 1-byte fields back as `u16`
       in memory but only the low byte is on the wire):
       - bit `0`: `uint8 justify` (text alignment)
       - bit `1`: `uint8 initial_caps`
       - bit `2`: `int16 drop_by` (drop-cap height)
       - bit `3`: `uint8 bullet`
       - bit `4`: `uint8 line_spacing_rule`
       - bit `5`: `int16 space_before`
       - bit `6`: `int16 space_after`
       - bit `7`: `int16 space_at` (line-height value)
       - bit `8`: `uint8 special_line_indent`
       - bit `9`: `int16 left_indent`
       - bit `10`: `int16 right_indent`
       - bit `11`: `int16 indent_by` (special-line displacement)
    5. if `mask_explicit` bit `12` is set, read tab list:
       - `uint16 tab_count`
       - per tab: `uint16 position` (must be > 0 per BBDESIGN
         validator "Invalid tab position. Must be greater than
         zero.") + `uint8 type` (alignment enum — exact values not
         pinned today; runtime accessor `GetTabAlignmentAt` reads
         it as `u16` from the in-memory CTab struct at offset +6)
  - in the reference TTL only `bit 0 (justify)` (sid 1) and the tab
    list (sids 7–24) carry explicit values. The MOSVIEW wire
    descriptor does not consume CParaProps fields directly;
    paragraph layout flows through item-record headers (see
    `docs/mosview-authored-text-and-font-re.md` §"Authored Lowering
    Checklist"). VIEWDLL's `CParaProps::Set*` setters
    (`SetJustify` @ `0x40727348`, `SetLineSpacingRule` @
    `0x4072739c`, `SetSpecialLineIndent` @ `0x4072736c`,
    `SetInitialCaps` @ `0x40727354`, `SetBulletState` @
    `0x407273cc`, `CTab::SetTabAlignment` @ `0x407271ca`, …) are
    **pure stores — no range validation**. Enum bounds live in
    BBDESIGN.EXE: each field has a generic "Invalid X argument"
    validator string but the binary doesn't emit the value list
    inline. Specific values (e.g. `justify` 0=left/2=center per
    the per-style defaults table — Abstract Heading uses 2;
    `line_spacing_rule` 0=single per Normal's default) can be
    inferred from the per-style defaults at `0x40770e00` but the
    full enum range remains unconfirmed.

- `CContent`
  - handled specially
  - object bytes come from the object broker / remote-proxy interface, not the regular `SaveToArchive` pattern
  - the payload is content-type-specific raw data, keyed by the accompanying properties table
  - sample content/property pairs:
    - `type = TextTree`
      - object is text-tree payload, raw or `CK`-compressed depending on size
    - `type = TextRuns`
      - object is text-runs payload
      - `8/7/\x03object` is a short ANSI text blob with a leading version/length prefix
    - `type = WaveletImage`
      - object bytes are a BMP file in the sample (`8/5/\x03object`)
      - object compression is explicitly skipped for this non-text type, but the properties table itself can still be `CK`-compressed

The practical split is:

- semantic classes like `CTitle`, `CSection`, `CBForm`, `CBFrame`, `CStyleSheet`, and `CResourceFolder` use native MFC `Serialize()` payloads
- `CContent` uses broker-owned raw payload bytes
- any of those artifacts may then be wrapped in the `CK` compression envelope when the relevant `CDPORef` flags request it

## `\x03ref_N`

`COSCL.DLL` names these as serialized `CDPORef` tables. The streams contain:

- a serialized slot-occupancy bitmap
- a dense slot-count field
- one serialized `CDPORef` object for each occupied slot

High-confidence framing from `CDPORefMgr::StreamInRefTables`, `CommitRefTables`, and the ref-table serializer at `402080d3`:

1. bitset object:
   - `uint32 start_word`
   - `uint32 word_count`
   - `uint32 capacity_words`
   - `uint32 words[word_count]`
2. `uint32 slot_count`
3. repeated for each occupied slot in bitmap order:
   - one MFC object-serialized `CDPORef`

Observed wrapper grammar for the occupied-slot records:

- first `CDPORef` in the stream:
  1. `uint16 0xffff`
  2. `uint16 schema`
  3. `uint16 class_name_len`
  4. `char[class_name_len] class_name`
- later `CDPORef` records of the same class:
  1. `uint16 0x8001`
  2. raw `CDPORef` body

In the sample, the first record declares `schema = 1` and `class_name = CDPORef`. Later records reuse that class with the 2-byte `0x8001` marker instead of repeating the name. This is consistent with MFC runtime-class serialization.

Observed sample for `\x03ref_1`:

- `start_word = 0`
- `word_count = 4`
- `capacity_words = 4`
- `words = [1, 0, 0, 0]`
- `slot_count = 1`
- occupied slot `0`

Observed sample for `\x03ref_7`:

- bitmap marks three occupied slots
- `slot_count = 3`
- first serialized `CDPORef` entry is 57 bytes including the new-class wrapper
- later same-class entries are 46 bytes each and start with `0x8001`

The literal class name `CDPORef` appears in the entry payloads. These streams are not OLE property sets.

## `CDPORef` serialized fields

`CDPORef::Serialize` writes the semantic fields in this order after the outer MFC object wrapper:

1. `uint32 flags_and_objkind`
   - top nibble stores `ObjKind`
   - low 28 bits are the moniker flag word
   - `CDPORef::GetTransientFlagsMask()` returns `7`, so bits `0..2` are transient
   - bit 1 is masked off when written
2. `uint32 ref_count`
3. optional `FILETIME obj_mod_time` if flag `8` is set
4. optional `FILETIME props_mod_time` if flag `9` is set
5. optional `GUID obj_guid` if flag `3` is set
6. `uint32 obj_cos_path_handle`

Field locations confirmed by accessors:

- `this+0x0c` -> `GetObjModTime`
- `this+0x14` -> `GetPropsModTime`
- `this+0x1c` -> `GetObjGUID`
- `this+0x2c` -> `GetObjCOSPathHandle`

High-confidence flag meanings from `AddMoniker`, `AccessObjectStream`, `StreamWrite`, `CommitObjectArtifact`, `CommitPropertiesArtifact`, and `CompressArtifactIfBeneficial`:

- bit `1`
  - object artifact dirty
- bit `2`
  - properties artifact dirty
- bit `3`
  - object GUID present
- bit `6`
  - cached `IPropertyStorage *` pointer present at `this + 0x58`
- bit `7`
  - cached `CString *` pointer present at `this + 0x5c`
- bit `8`
  - object modification time present at `this + 0x0c`
- bit `9`
  - properties modification time present at `this + 0x14`
- bit `0x0a`
  - file-path strings are serialized by `CDPOPathRef::Serialize`
- bit `0x0b`
  - object artifact missing / purged, so open must go through the broker path
- bit `0x0c`
  - properties artifact missing / purged, so open must go through the broker path
- bit `0x0d`
  - companion object swizzle table exists (`\x03handles`)
- bit `0x0e`
  - properties artifact exists (`\x03properties`)
- bit `0x0f`
  - object artifact stored in `CK` compressed form
- bit `0x10`
  - object artifact marked no-compress
- bit `0x11`
  - properties artifact stored in `CK` compressed form
- bit `0x13`
  - ref-table extinct/live-accounting marker used while rebuilding occupancy
- bit `0x14`
  - external/source filetime supplied for object access

The remaining unresolved details are the exact semantics of a few lifecycle-only bits such as `0x13` and the full meaning of every lower moniker-flag combination. The wrapper grammar, ref-table framing, compression format, and artifact-state bits are established.

- `\x03ref_N` defines the ref table for top-level table `N`
- object handles refer into these tables
- per-object storages `N/M/...` hold the artifacts for those handles

## Temp-file result

`/var/share/drop/prj60a5.tmp` is not a different format. It is the same standalone title object store as `msn today.ttl`:

- same root stream tree
- same `\x03TitleProps`
- same `\x03type_names_map`
- same payload for every logical stream

Only the outer compound-document allocation/layout differs.
