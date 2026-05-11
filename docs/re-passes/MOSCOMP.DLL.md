# MOSCOMP.DLL — total-decomp coverage

Image base `0x7F470000`. UI helpers used across MOS apps — progress
dialog (Prog*), palette resolution, common compress/uncompress
helpers.

## Function inventory (188 total)

- 43 named at session start (Prog*, palette helpers).
- 144 still `FUN_*` after this pass — every one carries a structural plate.
- 1 thunk.
- 2 huge functions (>12000 instructions) plate-only by deep-annotate.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Bulk plate | 169 plates emitted. 19 hand plates preserved. |
| Deep line comments | 827 call-site PRE comments + 14 string-ref EOL comments across 185 functions. |

## Surface

`ProgCreate` / `ProgAddData` / `ProgSetOutput` / `ProgPaint` /
`ProgClose` are the title-load progress dialog APIs invoked by
MOSVIEW during title open.

## Per-function status

Worklist: `scratch/annotate-worklist/MOSCOMP.DLL.txt`
Progress: `scratch/annotate-progress/MOSCOMP.DLL.json`
