# Blackbird's built-in style sheet

A `TextTree` paragraph carries only an element tag. Everything the
viewer draws it with — face, size, weight, colour, indents, spacing —
comes from a style, and a title that edits no style ships a
`CStyleSheet` with `style_entry_count = 0` (`story title.ttl`). The
defaults it falls back to are a static table in `VIEWDLL.DLL`.

## Where the table lives

`CStyle::FindNameIndex @ 0x40708221` is the map. It walks 47 records of
`0x34` bytes from VA `0x40770e00` to `0x4077178c`, comparing the `char*`
at `+0x00`, then walks a second table of 8-byte records at
`0x407717c0`..`0x407717f8` and returns `index + 47` on a hit there. That
second table is the 7 `Wrap: …` intrusion styles, which carry an
intrusion kind rather than character or paragraph properties.

So the style index space is 0..53. That is the same space a title's own
`CStyleSheet` style map keys — `story_test.ttl` overrides all 54.

`CStyleSheet::CreateStyleSheetFromTable` and
`CStyleSheet::LoadDefaultStyle` are the exported entry points that build
a live sheet out of it.

## Record layout

Each field is named from the accessor VIEWDLL exports for it. Every
accessor is a one-line thunk into `CParaProps::EGetShort` /
`CParaProps::EGetWord` (`0x4070812e` / `0x4070733d`) or
`CCharProps::EGetWord` (`0x4070692e`), which read the live object's own
value and fall back to `table[style_index]` at the offset below when the
object holds the unset sentinel `0xFFFE`.

| Offset | Type | Field | Accessor |
|---|---|---|---|
| `+0x00` | `char*` | style name | `CStyle::GetName` |
| `+0x04` | `i16` | based-on index, `-1` = none | `CStyle::GetBasedOnIndex` |
| `+0x08` | `i16` | is a character style | `CStyle::IsCharacterStyle` |
| `+0x0C` | `u16` | character attributes | `CCharProps` id 5 |
| `+0x10` | `i16` | font id | `CCharProps::GetFontID` (id 3) |
| `+0x12` | `i16` | point size | `CCharProps::EGetPtSize` (id 4) |
| `+0x14` | `u32` | fore COLORREF | `CCharProps::EGetForeColor` |
| `+0x18` | `u32` | back COLORREF | `CCharProps::EGetBackColor` |
| `+0x1C` | `i16` | justify | `CParaProps::EGetJustify` (id 0) |
| `+0x1E` | `i16` | initial caps | `CParaProps::EGetInitialCaps` (id 11) |
| `+0x22` | `i16` | bullet | `CParaProps::EGetBullet` (id 10) |
| `+0x24` | `i16` | line spacing rule | `CParaProps::EGetLineSpacingRule` (id 2) |
| `+0x26` | `i16` | indent by | `CParaProps::EGetIndentBy` (id 3) |
| `+0x28` | `i16` | left indent | `CParaProps::EGetLeftIndent` (id 4) |
| `+0x2A` | `i16` | right indent | `CParaProps::EGetRightIndent` (id 5) |
| `+0x2C` | `i16` | space at | `CParaProps::EGetSpaceAt` (id 8) |
| `+0x2E` | `i16` | special line indent | `CParaProps::EGetSpecialLineIndent` (id 1) |
| `+0x30` | `i16` | space before | `CParaProps::EGetSpaceBefore` (id 6) |
| `+0x32` | `i16` | space after | `CParaProps::EGetSpaceAfter` (id 7) |

`-1` in an `i16` field and `0xFFFFFFFF` in a colour mean the style sets
nothing and the based-on chain supplies the value. `0` in the font id
and point size fields means the same.

Indents and spacing are points. `List Bullet`'s 18 pt left indent
measures 24 px on the page in the BBVIEW reference render of
`story title.ttl` — a quarter inch at 96 DPI.

`special_line_indent` is an enum: `0` none, `1` first-line, `2` hanging.
Both list styles set hanging, so their first line — the one carrying the
bullet — starts at `left_indent - indent_by`, which for them is 0.

`bullet` is a boolean, not a character code: `CParaProps::IsBullet @
0x40727338` is `GetRecurseBool(10)` over the same property
`CParaProps::EGetBullet` reads. The style says only *whether* a
paragraph carries a marker — the glyph is the renderer's own choice and
is not recoverable from the style sheet. BBVIEW draws a small filled
square, 8 px wide in the reference render at its 1.64x scale, i.e.
about 4.9 px on the page.

### Character attributes (`+0x0C`)

The word packs value and mask: `[u8 unset_mask][u8 values]`.
`CCharProps::EGetBold @ 0x40727466` tests `AH & 0x01` and, when clear,
returns `AL & 0x02`. Italic uses `AH & 0x02` / `AL & 0x04`, underline
`AH & 0x04` / `AL & 0x08`.

A set mask bit means the style defines nothing and defers to its
based-on chain. That is how `Heading 2` renders bold: its own word is
`0x7F00`, every mask bit set, so bold comes from `Heading 1`'s `0x7E02`.

`Strikethrough` and `Underline` hold identical records, so this build
draws them the same.

### Font ids

Font ids index the title's `CStyleSheet` font map. VIEWDLL's own map is
the three faces its string pool names right after `<no style>` and
`Normal`, at `0x40770ce4`..`0x40770cf8`:

| Id | Face |
|---|---|
| 1 | Times New Roman |
| 2 | Arial |
| 3 | Courier New |

Every `.ttl` inspected so far carries exactly that map. On disk the map
is `[u8 version=9][u16 font_count]{ [u16 key][u8 namelen][ASCII name] }`
— the key leads its name — followed by `[u16 style_count]` and, when
non-zero, the style overrides.

## The table

| # | Name | Based on | Char | Chr attrs | Font | Pt | Fore | Just | Bul | Indent by | Left | Right | Special | Before | After |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | Normal |  |  | 0x0000 | 1 | 11 | 0x000000 | 0 |  | 0 | 0 | 0 | 0 | 0 | 11 |
| 1 | Heading 1 | Normal |  | 0x7E02 | 2 | 22 |  |  |  |  |  |  |  | 18 | 0 |
| 2 | Heading 2 | Heading 1 |  | 0x7F00 |  | 18 |  |  |  |  |  |  |  | 14 |  |
| 3 | Heading 3 | Heading 2 |  | 0x7F00 |  | 14 |  |  |  |  |  |  |  | 12 |  |
| 4 | Heading 4 | Heading 3 |  | 0x7D04 |  | 12 |  |  |  |  |  |  |  |  |  |
| 5 | Heading 5 | Heading 4 |  | 0x7E02 |  |  |  |  |  |  |  |  |  |  |  |
| 6 | Heading 6 | Heading 5 |  | 0x7D04 |  |  |  |  |  |  |  |  |  |  |  |
| 7 | TOC 1 | Normal |  | 0x7E02 | 2 | 12 | 0x000080 | 0 |  |  | 18 |  |  |  |  |
| 8 | TOC 2 | TOC 1 |  | 0x7F00 |  |  |  |  |  |  | 36 |  |  |  |  |
| 9 | TOC 3 | TOC 2 |  | 0x7F00 |  |  |  |  |  |  | 54 |  |  |  |  |
| 10 | TOC 4 | TOC 3 |  | 0x7F00 |  |  |  |  |  |  | 72 |  |  |  |  |
| 11 | TOC 5 | TOC 4 |  | 0x7F00 |  |  |  |  |  |  | 90 |  |  |  |  |
| 12 | TOC 6 | TOC 5 |  | 0x7F00 |  |  |  |  |  |  | 108 |  |  |  |  |
| 13 | TOC 7 | TOC 6 |  | 0x7F00 |  |  |  |  |  |  | 126 |  |  |  |  |
| 14 | TOC 8 | TOC 7 |  | 0x7F00 |  |  |  |  |  |  | 144 |  |  |  |  |
| 15 | TOC 9 | TOC 8 |  | 0x7F00 |  |  |  |  |  |  | 162 |  |  |  |  |
| 16 | Section 1 | Normal |  | 0x7E02 | 2 | 14 | 0x808000 |  |  |  |  |  |  |  |  |
| 17 | Section 2 | Section 1 |  | 0x7F00 |  | 12 |  |  |  |  |  |  |  |  |  |
| 18 | Section 3 | Section 2 |  | 0x7F00 |  | 10 |  |  |  |  |  |  |  |  |  |
| 19 | Section 4 | Section 3 |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 20 | Section 5 | Section 4 |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 21 | Section 6 | Section 5 |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 22 | Section 7 | Section 6 |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 23 | Section 8 | Section 7 |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 24 | Section 9 | Section 8 |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 25 | Abstract Heading | Normal |  | 0x7E02 | 1 | 22 |  | 2 |  |  |  |  |  |  |  |
| 26 | Term Definition | Normal |  | 0x7F00 |  | 8 |  |  |  | 36 | 36 |  | 2 |  |  |
| 27 | List Bullet | Normal |  | 0x7F00 |  |  |  |  | 1 | 18 | 18 |  | 2 |  |  |
| 28 | List Number | Normal |  | 0x7F00 |  |  |  |  | 1 | 18 | 18 |  | 2 |  |  |
| 29 | Term | Normal | yes | 0x7E02 |  |  |  |  |  |  |  |  |  |  |  |
| 30 | Hyperlink | Normal | yes | 0x7B08 |  |  | 0xFF0000 |  |  |  |  |  |  |  |  |
| 31 | Emphasized | Normal | yes | 0x7D04 |  |  |  |  |  |  |  |  |  |  |  |
| 32 | Bold | Normal | yes | 0x7E02 |  |  |  |  |  |  |  |  |  |  |  |
| 33 | Italic | Normal | yes | 0x7D04 |  |  |  |  |  |  |  |  |  |  |  |
| 34 | Strikethrough | Normal | yes | 0x7B08 |  |  |  |  |  |  |  |  |  |  |  |
| 35 | Preformatted | Normal |  | 0x7F00 | 3 |  |  |  |  |  |  |  |  |  |  |
| 36 | Blockquote | Normal |  | 0x7D04 |  |  |  |  |  |  | 36 | 36 |  |  |  |
| 37 | Address | Normal |  | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 38 | Underline | Normal | yes | 0x7B08 |  |  |  |  |  |  |  |  |  |  |  |
| 39 | Strong | Normal | yes | 0x7E02 |  |  |  |  |  |  |  |  |  |  |  |
| 40 | Code | Normal | yes | 0x7F00 | 3 |  |  |  |  |  |  |  |  |  |  |
| 41 | Keyboard | Normal | yes | 0x7C06 |  |  |  |  |  |  |  |  |  |  |  |
| 42 | Citation | Normal | yes | 0x7F00 |  |  |  |  |  |  |  |  |  |  |  |
| 43 | Variable Name | Normal | yes | 0x7C06 |  |  |  |  |  |  |  |  |  |  |  |
| 44 | Fixed Width | Normal | yes | 0x7F00 | 3 |  |  |  |  |  |  |  |  |  |  |
| 45 | Abstract Body | Normal |  | 0x7D04 | 1 |  |  |  |  |  |  |  |  |  |  |
| 46 | Sample | Normal | yes | 0x750A |  |  |  |  |  |  |  |  |  |  |  |
| 47 | Wrap: Design feature | — intrusion table, kind `0x002F0000` |
| 48 | Wrap: Supporting graphic | kind `0x00300000` |
| 49 | Wrap: Related graphic | kind `0x00310000` |
| 50 | Wrap: Sidebar graphic | kind `0x00320000` |
| 51 | Wrap: Advertisement | kind `0x00330000` |
| 52 | Wrap: Custom 1 | kind `0x00340000` |
| 53 | Wrap: Custom 2 | kind `0x00350000` |

## Which element takes which style

The element tags are in `docs/ccontent.md`. Only these are pinned:

| Tag | Element | Style |
|---|---|---|
| `0x06` | `P` | Normal |
| `0x07` | `H1` | Heading 1 |
| `0x08` | `H2` | Heading 2 |
| `0x1E` | `LI` inside `0x1C` (`UL`) | List Bullet |
| `0x1E` | `LI` inside `0x1D` (`OL`) | List Number |

`LI` is one element; the enclosing list picks which of the two list
styles applies. Both set `bullet`, which is why the BBVIEW render draws
the same square marker on numbered and bulleted items alike.

## What the reference render confirms

`reference/screenshots/story title.png` is BBVIEW showing
`story title.ttl`, a title with no style overrides, so every value below
comes out of the table above. BBVIEW scales the 640x480 page ~1.64x to
fill its client, so page-pixel figures are measured ink divided back
down.

| Element | Table says | Render measures |
|---|---|---|
| `H1` | Arial bold 22 pt = 29.3 px | 29 px em, bold sans |
| `H2` | Arial bold 18 pt = 24 px | 24 px em, bold sans |
| `P` | Times New Roman 11 pt = 14.7 px | 14 px em, serif |
| `LI` left indent | 18 pt = 24 px | 23.8 px |
| `LI` bullet position | hanging to indent 0 | flush with the body margin |
| `H1` space before | 18 pt = 24 px | first ink 13.1 px below the rect top after the 24 px |
| `Normal` space after | 11 pt = 14.7 px | 33 px list pitch against a 16.2 px Times cell |

The Story control also insets its text by about 10 pt on every side.
That is not a style-sheet property — it is `CQtxtCtrl`'s own margin, and
it is measured, not pinned.

## Open

- The BBML DTD's full element numbering (see `docs/ccontent.md`).
- `+0x06`, `+0x0A`, `+0x0E`, `+0x20` are always 0 or 1 across all 47
  records and have no exported accessor pointing at them.
- `Sample`'s attribute word `0x750A` sets value bits whose mask bits are
  also set, which the bold/italic/underline reading does not explain.
