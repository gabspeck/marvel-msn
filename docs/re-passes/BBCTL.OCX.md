# BBCTL.OCX — BBDESIGN control suite + CLSID dispatch

Image base `0x40000000`. MFC OLE control container shipped with
Blackbird; hosts the 10 site classes BBDESIGN can place inside a
CVForm. The 6 visible to the CVForm site-name dispatcher
(`Story` / `Caption` / `Audio` / `CaptionButton` / `Outline` /
`Shortcut`) are what `ttl_loader._BBCTL_CLSIDS` decodes; the other 4
(`PictureButton` / `PrintPsf` / `Picture` / `Psf`) are BBCTL controls
not exercised by any current TTL fixture.

## Factory registration (DllRegisterServer chain)

`DllRegisterServer` (`0x40014fd5`) calls `Ordinal_1035` with
`&DAT_40021f30` (the form's TypeLib IID) and `Ordinal_5630(1)` which
in turn dispatches to the per-class init functions. Each class has a
self-registration function that calls
`Ordinal_403(&CLSID, &PTR_CClass, 0, "PROGID")` — MFC's `COleObjectFactory`
construction pattern. The 10 functions and their pinned CLSIDs:

| Class (CRuntimeClass) | ProgID | Init function | CLSID data | CLSID |
|---|---|---|---|---|
| `CActionCtrl` | `PICTUREBUTTON.PictureButtonCtrl.1` | `Register_CActionCtrl_PICTUREBUTTON` @ `0x40007948` | `CLSID_CActionCtrl_PICTUREBUTTON` @ `0x4001e9a8` | `{B678F186-8794-101B-BD52-00AA003E4475}` |
| `CWaveletCtrl` | `PICTURE.PictureCtrl.1` | `Register_CWaveletCtrl_PICTURE` @ `0x40007a1a` | `CLSID_CWaveletCtrl_PICTURE` @ `0x400216a0` | `{E012CCB0-101A-11CE-B33D-00AA004A5B7E}` |
| `CQtxtCtrl` | `QTXT.QtxtCtrl.1` | `Register_CQtxtCtrl_QTXT_BBCTL_STORY` @ `0x40007b05` | `CLSID_CQtxtCtrl_QTXT_BBCTL_STORY` @ `0x40023fd8` | `{9283AE00-6ABF-11CE-B942-00AA004A7ABF}` |
| `CLabelCtrl` | `LABEL.LabelCtrl.1` | `Register_CLabelCtrl_LABEL_BBCTL_CAPTION` @ `0x40007ce7` | `CLSID_CLabelCtrl_LABEL_BBCTL_CAPTION` @ `0x40021c50` | `{1A6F09D0-6574-11CE-A25F-00AA003E4475}` |
| `CPsfCtrl` | `PSF.PsfCtrl.1` | `Register_CPsfCtrl_PSF` @ `0x40007d30` | `CLSID_CPsfCtrl_PSF` @ `0x400209b8` | `{3EF5FF70-EF93-11CD-AB6D-00AA003E4475}` |
| `CAudioCtrl` | `AUDIO.AudioCtrl.1` | `Register_CAudioCtrl_AUDIO_BBCTL_AUDIO` @ `0x40007e53` | `CLSID_CAudioCtrl_AUDIO_BBCTL_AUDIO` @ `0x4001fe90` | `{58903560-57EB-11CE-A685-00AA005F54D7}` |
| `CBblinkCtrl` | `BBLINK.BblinkCtrl.1` | `Register_CBblinkCtrl_BBLINK_BBCTL_SHORTCUT` @ `0x40007f3e` | `CLSID_CBblinkCtrl_BBLINK_BBCTL_SHORTCUT` @ `0x400210b0` | `{06F766A0-4F09-11CE-9A00-00AA006B1E42}` |
| `CLabelBtnCtrl` | `LABELBTN.LabelBtnCtrl.1` | `Register_CLabelBtnCtrl_LABELBTN_BBCTL_CAPTIONBUTTON` @ `0x40007f87` | `CLSID_CLabelBtnCtrl_LABELBTN_BBCTL_CAPTIONBUTTON` @ `0x4001f888` | `{B678F18B-8784-101B-BD52-00AA003E4475}` |
| `CPrintPsfCtrl` | `PRINTPSF.PrintPsfCtrl.1` | `Register_CPrintPsfCtrl_PRINTPSF` @ `0x40008008` | `CLSID_CPrintPsfCtrl_PRINTPSF` @ `0x4001ed50` | `{AFD3E953-6474-11CE-8C18-00AA005746F2}` |
| `CInfomapCtrl` | `INFOMAP.InfomapCtrl.1` | `Register_CInfomapCtrl_INFOMAP_BBCTL_OUTLINE` @ `0x40008166` | `CLSID_CInfomapCtrl_INFOMAP_BBCTL_OUTLINE` @ `0x40022d58` | `{DED253E0-F4E2-11CD-AB6D-00AA003E4475}` |

Site-name ↔ class mapping (verified empirically against
`resources/titles/{4,msn_today}.ttl` + `/var/share/drop/first title.ttl`):

| CVForm site name | BBCTL class | Reason for mapping |
|---|---|---|
| `Story` (e.g. `Story1R`) | `CQtxtCtrl` (QTXT) | Verified — CLSID at preamble slot 0 in msn_today CVForm 6/0 |
| `Caption` (e.g. `Caption1`) | `CLabelCtrl` (LABEL) | Verified — CLSID at preamble slot 0 in 4.ttl pages + slot 1 in showcase 7/0 |
| `Audio` (e.g. `Audio1R`) | `CAudioCtrl` (AUDIO) | Verified — CLSID at preamble slot 2 in showcase 7/0 |
| `CaptionButton` (e.g. `CaptionButton1R`) | `CLabelBtnCtrl` (LABELBTN) | Verified — CLSID at preamble slot 3 in showcase 7/0 |
| `Outline` (e.g. `Outline1`) | `CInfomapCtrl` (INFOMAP) | Verified — CLSID at preamble slot 4 in showcase 7/0 |
| `Shortcut` (e.g. `Shortcut1=R`) | `CBblinkCtrl` (BBLINK) | Verified — CLSID at preamble slot 1 in msn_today CVForm 6/0 |

The trailing `R` / `=R` on site names is empirical noise from BBDESIGN
(possibly "Remote", matching `CRemoteAudio` class names in symbol
exports); the CLSID is authoritative for dispatch.

## CVForm preamble class table

Each CVForm body (`<table>/<slot>/\x03object` after CK decompression)
starts with an MS-Forms-1.0 preamble that includes a class-CLSID table
at a fixed offset:

| Slot | Offset | Size | Notes |
|---|---|---|---|
| 0 | `+0x9A` (154) | 16 B | First BBCTL class CLSID referenced by sites |
| 1 | `+0xC2` (194) | 16 B | Stride 40 B from slot 0 |
| 2 | `+0xEA` (234) | 16 B | |
| 3 | `+0x112` (274) | 16 B | |
| 4 | `+0x13A` (314) | 16 B | |
| ... | ... | ... | Continues until first non-BBCTL CLSID terminates |

The 24 B between consecutive CLSIDs are MS Forms per-class registration
metadata (size/flags/version triplet — not yet pinned offset by offset;
walked as opaque padding by the loader).

Each site descriptor's `flags & 0xFF` indexes into this table:

| Site (showcase 7/0) | flags | class_index | class table CLSID | dispatch |
|---|---|---|---|---|
| Story1R   seq=1 | `0x80000000` | 0 | CQtxtCtrl | StoryControl |
| Caption1  seq=2 | `0x80010001` | 1 | CLabelCtrl | CaptionControl |
| Audio1R   seq=3 | `0x80020002` | 2 | CAudioCtrl | AudioControl |
| CaptionButton1R seq=4 | `0x80030003` | 3 | CLabelBtnCtrl | CaptionButtonControl |
| Outline1  seq=6 | `0x80040004` | 4 | CInfomapCtrl | OutlineControl |

High 16 bits = `0x8000xxxx` (purpose unpinned). Low byte mirrors the
class index in BOTH the low word and the high word of the dword.

Loader implementation: `_parse_cvform_class_table` +
`_dispatch_class` in `src/server/services/medview/ttl_loader.py`.

## IPersistStreamInit::Save per class

### `CLabelCtrl` (Caption) — pinned

`CLabelCtrl::DoPropExchange` @ `0x40009356` (v=4) and its border parent
`FUN_40003dbc` (v=3) are decompiled. Persist call sequence (MFC 4.x
ordinals via `BBCTL.OCX`):

| Ordinal | MFC function | Field | Type | Default | Version gate |
|---|---|---|---|---|---|
| 2378 | `CPropExchange::ExchangeVersion` | (CLabelCtrl) | u32 | 4 | always |
| 2378 | `CPropExchange::ExchangeVersion` | (parent border) | u32 | 3 | always |
| 2223 | `COleControl::ExchangeStockProps` | stock-prop block (mask `0xD2`, written in MFC alphabetical order) | varies | — | always |
| 4736 | `PX_Long` | `BevelWidth` | LONG | 0 | always |
| 4736 | `PX_Long` | `FrameStyle` | LONG | 0 | always |
| 4736 | `PX_Long` | `BevelHilight` | COLORREF | `0xFFFFFF` | v ≥ 3 |
| 4736 | `PX_Long` | `BevelShadow` | COLORREF | 0 | v ≥ 3 |
| 4736 | `PX_Long` | `BevelColor` (legacy) | COLORREF | `0xFFFFFF` | 1 ≤ v < 3 |
| 4736 | `PX_Long` | `FrameColor` | COLORREF | 0 | v ≥ 2 |
| 4736 | `PX_Long` | `idTag` | LONG | `-1` | always |
| 4742 | `PX_String` | `strCaption` | CString | LoadString | v ≥ 4 always; v < 4 when `idTag == -1` |
| 4724 | `PX_Bool` | `fWordWrap` | BOOL | FALSE | always |
| 4724 | `PX_Bool` | `fAutoSize` | BOOL | FALSE | always |
| 4736 | `PX_Long` | `iAlignment` | LONG | 0 | always |
| 4736 | `PX_Long` | `iBackStyle` (legacy) | LONG | 0 | v < 3 |
| 4736 | `PX_Long` | `fTransparent` | LONG | 1 | v ≥ 3 |

The stock prop mask `0xD2` (set by `FUN_40008e81` constructor at
`this+0x318`) gates which of MFC's alphabetical-order stock props
ExchangeStockProps writes. Empirically, the back_color stock prop
lands in the 6-byte `font_pre_clsid` wrapper at file offset
`font_off - 5` (4 B COLORREF). Other bits in the mask have not been
disambiguated against MFC 4.x source.

The post-strCaption fields (`fWordWrap`, `fAutoSize`, `iAlignment`,
`fTransparent`) are emitted as a 10-byte block immediately after
`strCaption`'s bytes. Encoding: `[u16 fWordWrap][u16 fAutoSize][u16
iAlignment][u32 fTransparent]`. Pinned empirically (see
`docs/cvform-page-objects.md` §"Post-strCaption block") across four
default-valued single-Caption fixtures — non-default-value
verification deferred to future probes.

On-disk byte layout pinned in `docs/cvform-page-objects.md`
§"Caption1 property block".

Decoder: `_decode_caption` + `_decode_label_persist` in
`src/server/services/medview/ttl_loader.py`.

Event entry points (string refs):
- `"Click"` @ `0x4002b298`
- `"RightClick"` @ `0x4002b2d0`

These bind script macros via `idTag`. Lowering of Click → script
dispatch is deferred (script table storage path not yet RE'd).

### Other classes — TODO

Per-class persist-stream layouts for `CQtxtCtrl` (Story),
`CAudioCtrl`, `CLabelBtnCtrl` (CaptionButton), `CInfomapCtrl`
(Outline), `CBblinkCtrl` (Shortcut) are not yet pinned. Locator: each
class's CreateObject (constructor) sets the interface vtable pointer
at `this+0x410`; the IPersistStreamInit Save slot is at vtable offset
`+0x18` (entry 7 — QueryInterface, AddRef, Release, GetClassID,
IsDirty, Load, Save, GetSizeMax, InitNew).

The Save method body for these MFC controls is a thin thunk to a
shared serialiser (`Ordinal_1097` + helper); the per-class write
sequence lives in the COleControl::ExchangeProperties dispatch table
which is set up in the constructor. For each control, follow
`Ordinal_3452` calls in the constructor to find the
property-exchange table, then enumerate each entry.

Known-good probe seeds (from showcase Story1R):
- Pascal-prefixed CProxyTable name `"\x16Blackbird Document.bdf"` lives
  in `raw_block` starting around offset 31.
- 16-B CDPORef GUID immediately after the name (likely the resolved
  proxy GUID — observed `{0E7044F2-47FE-11F1-B405-000C875355C8}`).

`StoryControl.content_proxy_ref` is populated heuristically from the
matched CProxyTable's entry (PR1 chase); the structural CLSID
dispatch lands without exact persist-stream offset decoding for the
other compound fields. Per-field deep decode is queued as a follow-up
pass.

## Ghidra annotation pass

This pass landed:
- 10 factory init function renames (`Register_C*` pattern).
- 10 CLSID data labels (`CLSID_C*` pattern).
- One transaction commit + program save.

Not in scope:
- Property-page CLSIDs (separate set of 10+ classes — irrelevant for
  CVForm decode).
- COleControl `ExchangeProperties` table per class.
- IPersistStreamInit::Save body trace.
- DispID enumeration (only relevant for runtime control automation,
  not on-disk decode).
