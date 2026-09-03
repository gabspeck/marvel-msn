# Client bugs

Defects in the shipped MSN client. Each entry records what the client does
wrong and what it means for the server. Nothing here is worked around
server-side: the server implements the protocol, and these stay documented
rather than compensated for.

## "Service unexpectedly disappeared" after a rejected login

Signing in with a wrong password raises the MPC dialog `Server error occurred:
Service unexpectedly disappeared` (SCODE `0x8b0b0006`) before the client shows
its own bad-password message. The cause is entirely inside the client's IPC
stack and no server traffic is involved. On a non-zero login result GUIDE.EXE
calls `MOSCL!_CloseMOSConnection`, which tears down the whole MOS connection
rather than just the LOGSRV pipe: MOSCL sends command `0x0E` to MOSCP
(`MOSCL!FUN_7f671c41`), MOSCP's request dispatcher runs the connection teardown
at vtable slot `0x2C` (`MOSCP!FUN_7f45552b` case `0x0E` -> `MOSCP!FUN_7f452d93`),
and that answers command `0x10` for every pipe still open. MOSCL's handler for
`0x10` (`MOSCL!FUN_7f6720f8`) finds the LOGSRV pipe still in state 1 with
MPCCL's read callback registered at `+0x74`, so it notifies that callback with
a read size of `-1` on the line *before* it clears the callback. MPCCL reads the
`-1` in its pipe-read callback (`MPCCL!FUN_0460307d`), routes it to
`MPCCL!FUN_04602bff`, and reports the error. Established by live SoftICE capture
in the `Guide` and `Moscp` contexts plus static analysis of all three modules.

The dialog only appears when `DisplayMpcErrors` is set under
`HKLM\SOFTWARE\Microsoft\MOS\Debug` (see README). A stock client sets the same
SCODE silently and shows only the bad-password message, which is the correct
outcome. Two server-side attempts to avoid it were tested and both rejected:
sending the client a pipe-close makes it worse — the `0x01` byte is a
client-to-server command only, and the client feeds it to the host-block parser
and fails with `0x80004005` / `Unable to parse Host Block` — and closing the TCP
connection immediately after the rejection reply changes nothing, because the
teardown is decided before the wire is consulted.
