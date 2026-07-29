# CContent bodies — TextTree and TextRuns

A Story control's prose lives in a pair of `CContent` streams reached
through the site's `CProxyTable` (the chase is in
`docs/cvform-page-objects.md`). `CRemoteText::AddTreeAndRuns @
0x40720c1c` writes both: proxy key `0x1400` for the `TextTree`, `0x1500`
for the `TextRuns`.

The TextTree carries the document — its element structure and every
run of prose. The TextRuns stream carries paragraph markers, and is the
two-byte empty placeholder `00 00` in a title that overrides no style
(`story title.ttl 6/1`).

## TextTree

`raw[0]` is the stream version (`0x01` in every observed body). The root
`CElementNode` starts at `+1`, and its tag is `0x0005` — which is why
every TextTree body opens `01 05`.

### CElementNode

    u16 tag                    element tag; 0xFFFF = text/data leaf
    u8  version
    version == 2:  4 fixed bytes
    version == 3:  CElementData length + that many bytes
    version == 5:  u16 prop_count, then prop_count Pascal-string
                   name/value pairs
    u16 child_count, then that many nodes

The CElementData length prefix is the one `CElementData::Serialize @
0x40702e4c` writes: one byte below `0xFF`, else `0xFF` + `u16`, else
`0xFF` + `0xFFFF` + `u32`.

A styled paragraph is a version-1 node holding one version-3 leaf:

    07 00 01  01 00  FF FF 03 0B "Story title"  00 00

is `<H1>Story title</H1>` — tag 7, one child, and the child carries 11
bytes and no children of its own.

Version 5 is the picture intrusion. `story_test.ttl 8/6` nests three of
them under its heading:

    2E 00 05  03 00  05 "CLSID" 15 "PICTURE.PictureCtrl.1"
                     02 "CX" 04 "1500"  02 "CY" 03 "750"
              02 00  <2F 00 05 … FILE/DATA1 …>
                     <30 00 05 … FILE/RSLT1 …>

`DATA1` and `RSLT1` each hold one version-3 leaf of binary picture
bytes, not prose.

Version 2 is a fixed dword. `story_test.ttl 8/6` puts one inside the
empty `<P>` ahead of each list — `0` before the bulleted list, `1`
before the numbered one.

### Element tags

Pinned by pairing a title's Story resource against its parsed tree.
`story title.ttl` embeds `Story.bdf`, whose `BBML/BODY` stream reads

    <H1>…</H1> <P>…</P> <H2>…</H2> <P>…</P>
    <OL><LI>…</LI>×3</OL> <P></P> <UL><LI>…</LI>×3</UL> <P></P>

and its tree is that same sequence of tags 07, 06, 08, 06, 1D(1E×3),
06, 1C(1E×3), 06 under 0C, itself under 05 beside an empty 0B.
`story_test.ttl 8/2` repeats the 05 / 0B / 0C / 07 / 06 spine.

| Tag | Element |
|---|---|
| `0x05` | document root |
| `0x06` | `P` |
| `0x07` | `H1` |
| `0x08` | `H2` |
| `0x0B` | `HEAD` |
| `0x0C` | `BODY` |
| `0x1C` | `UL` |
| `0x1D` | `OL` |
| `0x1E` | `LI` |
| `0x2E`, `0x2F`, `0x30` | picture intrusion, FILE/DATA1, FILE/RSLT1 |

**Open**: the rest of the BBML DTD's element numbering. `H3`..`H6`
cannot be extrapolated from `H1`=7 / `H2`=8, because `HEAD` already
holds `0x0B`. No fixture exercises them, and VIEWDLL carries no element
name table to read the numbering off. What each tag paints with is in
`docs/blackbird-style-sheet.md`.

## TextRuns

Body grammar per `CTypedPtrArray<CElementData>::Serialize @ 0x407092a6`:

    u16 count                      (CArchive::WriteCount; 0xFFFF spills
                                    to a following u32)
    count × CElementData           ([length][bytes])

`story_test.ttl 8/7` is 122 B with `count = 2`. The two-byte `00 00`
placeholder decodes as an empty array.

## Related

- `docs/blackbird-style-sheet.md` — the styles the element tags resolve to.
- `docs/MEDVIEW-TEXT-ENCODING.md` §7 — Ghidra entry points for
  `CContent::Serialize @ 0x4073a185`, `CCharProps::Serialize @
  0x40707fcc`, `CParaProps::Serialize @ 0x407082e2`, `CStyle::Serialize
  @ 0x40707d6f`.
