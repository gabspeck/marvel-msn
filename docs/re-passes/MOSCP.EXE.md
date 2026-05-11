# MOSCP.EXE — total-decomp coverage

Image base `0x7F450000`. The MSN client-side wire daemon. Owns the
named pipe each app DLL talks over via MPCCL. For MEDVIEW
specifically, every selector frame from MOSVIEW (via MVTTL14C ->
MPCCL) crosses this process before reaching the network.

## Function inventory (302 total)

- 39 named at session start (handshake, dispatch helpers).
- 248 still `FUN_*` after this pass — every one carries a structural plate.
- 15 thunks.

## Annotation deltas this pass

| Pass | Delta |
|------|-------|
| Bulk plate | 276 plates emitted. 26 hand plates preserved. |
| Deep line comments | 1,222 call-site PRE comments + 106 string-ref EOL comments across 287 functions. |

## Surface

`PacketSize` / receive-buffer is 1024 bytes (per memory
`project_client_recv_buffer`). Replies > 1024 must be fragmented by
the server.

## Per-function status

Worklist: `scratch/annotate-worklist/MOSCP.EXE.txt`
Progress: `scratch/annotate-progress/MOSCP.EXE.json`
