# MPCCL.DLL — total-decomp coverage

Image base `0x04600000`. MPC RPC client. Underlying transport for
MEDVIEW (via MVTTL14C), DIRSRV (via TREENVCL), LOGSRV, etc.

## Function inventory (294 total)

- 102 named at session start.
- 164 still `FUN_*` after this pass — every one carries a structural plate.
- 27 thunks.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Bulk plate | 271 plates emitted. 23 hand plates preserved. |
| Deep line comments | 1,209 call-site PRE comments + 135 string-ref EOL comments across 267 functions. |

## Wire surface (per memory `project_mpccl_signalcompletion_spin` and
`project_blackbird_release_wire`)

- `FUN_0x04601f75` / `FUN_0x0460263f` — service attach / pipe open.
- `FUN_0x04601d25` — session QueryInterface.
- `SignalRequestCompletion` — gates the `0x86` reply spin invariant
  (long-lived requests must reply `0x87 0x88`, not `0x86` alone, to
  avoid `MsgWaitForSingleObject` tight-loop).

## Per-function status

Worklist: `scratch/annotate-worklist/MPCCL.DLL.txt`
Progress: `scratch/annotate-progress/MPCCL.DLL.json`
