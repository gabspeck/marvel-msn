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
  - version byte `3` in the sample
  - begins with one packed byte:
    - high 6 bits -> primary style/name index
    - bit 1 -> inherit-char-props flag
    - bit 0 -> alternate/based-on selector
  - then serializes one or two style-index bytes/words depending on version and selector
  - if the style does not fully defer to another style, it serializes:
    - `CParaProps`
    - `CCharProps`
  - the exact inner bit grammar of `CParaProps` / `CCharProps` is more detailed than the container-level title format and is not needed to reconstruct stream boundaries

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
