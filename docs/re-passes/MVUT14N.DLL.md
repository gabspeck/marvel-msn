# MVUT14N.DLL — total-decomp coverage

Image base `0x7E830000`. Tiny utility DLL (~10 KiB) split between two
sub-libraries: a small **block** allocator (chunked free-list / bump
allocator) and a **group** bitmap (Win32 `GlobalAlloc`-backed boolean
sets). One orphan alignment NOP rounds out the inventory.

## Function inventory (43 total)

- 42 named (34 from auto-analysis on KERNEL32 thunks + 8 hand-named in
  this deep pass).
- 1 plated, name withheld — `0x7e83198e` is a 2-byte `MOV EDI,EDI`
  alignment NOP preceding `GroupTrimmed`, mis-flagged as a function.
- 0 hand-thunks.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Auto-analysis | First-time analysis; 43 functions discovered. |
| Bulk plate (2026-05-06) | 42 plates emitted; 1 hand plate preserved. |
| Deep line comments (2026-05-06) | 67 call-site PRE comments across 43 functions. |
| Deep hand pass (2026-05-09) | 8 functions hand-named with replacement plates; 1 orphan documented; 11 new PRE comments at allocator/validator sites. |

## Surface

Public exports remain `BlockInitiate`, `BlockCopy`, `BlockFree`,
`BlockGrowth`, `BlockReset` plus the `Group*` and `Lrgb*` family. The
hand pass resolved the supporting privates:

| Address | Symbol | Role |
|---|---|---|
| `0x7e8310f0` | `DllProcessAttach` | Stub returning TRUE (called by `entry` on `fdwReason==1`). |
| `0x7e831100` | `DllProcessDetach` | Stub returning TRUE (called by `entry` on `fdwReason==0`). |
| `0x7e831150` | `BlockChainFreeList` | Lay singly-linked free-list across a fresh chunk's data area; `cbElem==0` no-op, single-slot path NULLs the lone link. |
| `0x7e831250` | `BlockSetActiveChunk` | Install `chunk` as Block's active chunk: head/free pointers, byte total, cursor (free-count vs bytes-remaining picked by flags at `+0x1e`). |
| `0x7e8315a0` | `BitMsbInByte` | Bit index 0..7 of highest set bit in a byte (used by `GroupTrimmed`). |
| `0x7e8315c0` | `BitLsbInByte` | Bit index 0..7 of lowest set bit in a byte (used by `GroupTrimmed`). |
| `0x7e8315e0` | `FInvalidGroup` | Validate a Group handle: magic `0x3333` at `+0x0`, version word at `+0x2` in 7..10. Returns 0 if valid, 1 if NULL/corrupt. |
| `0x7e831e10` | `GroupCreateForPair` | Allocate a result Group sized for `max(grpA.cb, grpB.cb)` / `max(grpA.extra, grpB.extra)`; sets `*pErr=0x7d7` on validation failure. Used by `GroupOr` / `GroupAnd`. |

Block error-code pool: `0x7df` BAD_HANDLE, `0x7d4` OOM, `0x7d7`
BAD_GROUP. Group header layout (per `GroupCreate` at `0x7e8317f0`):

| Offset | Size | Field |
|---|---|---|
| `0x00` | 2  | magic `0x3333` |
| `0x02` | 2  | version (10 at create time, validator accepts 7..10) |
| `0x04` | 4  | cb — buffer length in bytes |
| `0x08` | 4  | high-bit cursor (set by `GroupTrimmed`) |
| `0x0c` | 4  | low-bit cursor (set by `GroupTrimmed`) |
| `0x10` | 4  | popcount cache (`LrgbBitCount` result) |
| `0x14` | 4  | user `extra` payload (passed through by `GroupCreate`) |
| `0x18` | 2  | trim-state flag (2 = trimmed) |
| `0x1a` | … | private |
| `0x1e` | 4  | locked buffer pointer (`GlobalLock` of the data global) |
| `0x22` | 4  | data HGLOBAL |
| `0x26` | 4  | header HGLOBAL |
| `0x34` | 4  | caller's pErr (saved at create time) |
| `0x3a` | 4  | trim-dirty bookkeeping |

Block header layout (per `BlockInitiate` at `0x7e831360` / consumed by
`BlockSetActiveChunk` and `BlockGrowth`):

| Offset | Size | Field |
|---|---|---|
| `0x04` | 4  | guard `0x4d2` |
| `0x08` | 4  | first chunk (master) |
| `0x0c` | 4  | active chunk |
| `0x10` | 4  | next-free pointer |
| `0x14` | 2  | cbBuffer (chunk data area length) |
| `0x16` | 2  | max chunks (`0xffff` ≡ unbounded) |
| `0x18` | 2  | chunk count |
| `0x1a` | 2  | cbElem |
| `0x1c` | 2  | cursor — free slots used (flags!=0) or bytes remaining (flags==0) |
| `0x1e` | 2  | flags (free-list mode when non-zero) |
| `0x20` | 4  | cbAllocTotal (running sum of `cbBuffer + 0xc` per chunk) |

Chunk header is 12 bytes: `[next? @+0x4][guard 0x4d2 @+0x8]` then data
at `+0xc`.

## Per-function status

Worklist: `scratch/annotate-worklist/MVUT14N.DLL.txt`
Progress: `scratch/annotate-progress/MVUT14N.DLL.json`

Hand-named in this pass: `DllProcessAttach`, `DllProcessDetach`,
`BlockChainFreeList`, `BlockSetActiveChunk`, `BitMsbInByte`,
`BitLsbInByte`, `FInvalidGroup`, `GroupCreateForPair`. Documented skip:
`0x7e83198e` (alignment NOP).
