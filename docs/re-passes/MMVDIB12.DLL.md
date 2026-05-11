# MMVDIB12.DLL — total-decomp coverage

Image base `0x7F4F0000`. DIB / metafile playback engine. Where MedView
pixels actually land on screen. CPlayMeta C++ class is the central
helper. Bootstrapped by `InitiateMVDIB`; torn down by `TerminateMVDIB`.

## Function inventory (222 total)

- 10 named at session start (CPlayMeta::* methods, InitiateMVDIB, TerminateMVDIB).
- 192 still `FUN_*` after this pass — every one carries a structural plate.
- 20 thunks.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Bulk plate | 216 plates emitted. 6 hand plates preserved. |
| Deep line comments | 840 call-site PRE comments + 24 string-ref EOL comments across 202 functions. |

## Pixel landing

`CPlayMeta::Meta_GetDC` (`0x7f4f1000`) is the metafile DC accessor.
Caption rendering (commit `0967433`) currently lands through the
kind=8 metafile baggage path: server emits a CBFrame-sized white DIB
with a bm0 metafile that draws the caption text via Win32; MMVDIB12
plays it onto the pane DC.

Per memory `project_medview_paint_call_graph` and
`project_mosview_dual_pane_paint`, MMVDIB12 is invoked twice per
title open (scrolling + non-scrolling pane), each calling
`PlayMetaFile` on the same bm0 baggage at distinct pane origins.

## Imports surface

GDI32 (PlayMetaFile, BitBlt, StretchDIBits, CreateDIBSection, palette
ops), USER32 (DC management), KERNEL32 (memory).

## Per-function status

Worklist: `scratch/annotate-worklist/MMVDIB12.DLL.txt`
Progress: `scratch/annotate-progress/MMVDIB12.DLL.json`
