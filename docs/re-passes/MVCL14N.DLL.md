# MVCL14N.DLL — total-decomp coverage

Image base `0x7E880000`. PE DLL. The MediaView 1.4 engine — owns title
open dispatch, layout walker, paint orchestration, font / style
resolution. Largest single binary in the dep tree.

## Function inventory (434 total)

- 164 named at session start (engine API surface, layout helpers, font
  table accessors, walker entry points).
- 251 functions hand-named during the pass, including verified phantom
  hotpatch prefixes.
- 0 `FUN_*` symbols remain in `MVCL14N.DLL` as of 2026-05-07.
- 13 thunks.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Bulk plate | 425 plates emitted (257 auto + 155 named-no-plate + 13 thunks). 9 hand plates preserved. |
| Deep line comments | 1,953 call-site PRE comments + 82 string-ref EOL comments across 421 functions. |
| Completion | Final auto names resolved: embedded-window layout, column layout, text-story normalization, border metrics, LZSS bitmap payload, and hotpatch phantom prefixes. |

## Render-path call chain (recovered + memory-anchored)

Title open path:
```
hMVTitleOpen (0x7e8851d0)
└── hMVTitleOpenEx (0x7e8851f0)        — `:slot[path]index` dispatcher
    └── MVTTL14C!TitleConnection / hrAttachToService    — wire attach
        └── MVTTL14C!TitleOpenEx (selector 0x01)
```

Run-time view ops:
```
NavigateViewerSelection
├── vaMVGetContents
└── fMVRealize
    └── MVRealizeView      paint orchestrator   (master flag DAT_7e84e2fc)
        ├── MVParseLayoutChunk  parse layout chunk   (case 0..N dispatch)
        ├── MVWalkLayoutSlots  slot walker          (kind dispatch)
        │   └── MVBuildLayoutLine  paint helper / line builder
        └── HfcNear        cache-near probe → vaResolve fallback
```

Text rendering:
```
hMVSetFontTable
├── CopyResolvedTextStyleRecord      name_index → descriptor offset (0x2a stride)
├── ResolveTextStyleFromViewer      descriptor_count clamp
└── descriptor table reader (face_slot_index, lfHeight, lfWeight, ...)

MVBuildTextItem  text item builder
├── MVDecodeTopicItemPrefix  topic-item prefix decode
├── MVDecodePackedTextHeader  packed text-item header decode
├── MVScaleTextMetrics  metric scaling (LOGPIXELSX/Y * title scale @0x7c)
├── MVTextLayoutFSM  text layout state machine
│   └── MVResolveBorderSideThickness  text edge-metric side insets
└── DrawTextSlot  final text draw

MVBuildColumnLayoutItem  proportional horizontal composition group
├── MVEmitLayoutMarkerSlot  synthetic 0x67/0x68 marker slots
└── MVWalkLayoutSlots  recursive child item walker

MVBuildEmbeddedWindowItem  embedded/external object descriptor
└── MVCreateEmbeddedWindow  DLL/class/window-text triple resolver
```

WM_PAINT chain (per memory `project_medview_paint_call_graph`):
```
WM_PAINT MVPaneOnPaint
└── MVDispatchSlotPaint dispatch by slot[0]
    └── final raster via PlayMetaFile / BitBlt (in MMVDIB12)
```

Bitmap baggage decode:
```
MVDecodeBitmapBaggage
├── MVDecodeRleStream               compression mode 1
└── MVDecodeLzssBitmapPayload       compression mode 2
```

Edit-menu Copy Advanced (clipboard export):
```
hMVCopyAdvanced (export 0x2290)
└── MVCopyMediaToClipboard (0x7e890380)            outer chunk loop
    ├── MVHfcNear / MVParseLayoutChunk / MVDiscardLayoutChunkSlot
    ├── MVDecodePackedTextHeader / MVDecodeTopicItemPrefix
    ├── MVEmitRtfParagraphFormat (0x7e88f5d0)      \pard\qX\fi…\plain
    ├── MVEmitClippedTextRunPlain (0x7e88fa90)     CF_TEXT path
    │   └── MVTranscodeOrCopyTextRun (0x7e88f470)  per-font codepage map
    ├── MVEmitClippedTextRunRtf (0x7e88fb50)       RTF run group {\f\fs… text}
    │   ├── MVResolveAndRecordRunFont (0x7e88f910) cache + \fonttbl id
    │   └── ASCII guard 0x20..0x7a + \\'XX escape
    ├── MVExportEmbeddedWindowClipFormats (0x7e890180) WM_USER 0x7076 to embedded HWND
    │   └── MVEmitRtfPictureFromDib (0x7e890010)   StretchDIBits → wmf
    │       └── MVEmitRtfPictureFromMetafile / MVCopyMetafileBitsToGlobal / MVEmitHexEscapedBytes
    ├── Buffer plumbing: MVInitGlobalBuffer / MVReserveBufferAndLock /
    │   MVAppendToGlobalBuffer / MVEnsureGlobalBufferCapacity /
    │   MVFinalizeGlobalBufferState / MVFreeGlobalBufferState
    ├── MVCloseRtfBuffer (0x7e88f880)
    │   └── MVWrapRtfBufferWithHeader (0x7e88f640)  prepend "{\rtf\ansi {\fonttbl…}"
    └── MVAppendClipFormatEntry (0x7e890110)        list = [count][format,hData]*
```
Clip formats published: CF_TEXT (1) and RegisterClipboardFormatA("Rich Text Format").

## Imports surface

USER32 / GDI32 / KERNEL32 (paint, DC, fonts, regions),
MVTTL14C (TitleOpen, vaResolve, HfsRead, SubscribeNotification),
MMVDIB12 (DIB blit / PlayMetaFile), MVUT14N (block memory),
MVPR14N (image dither), MOSCOMP (palette).

## Per-function status

Worklist: `scratch/annotate-worklist/MVCL14N.DLL.txt`
Progress: `scratch/annotate-progress/MVCL14N.DLL.json`
