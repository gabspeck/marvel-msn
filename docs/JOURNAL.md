# MSN95 Reverse Engineering Journal

> Chronological research journal documenting the reverse engineering of MSN for
> Windows 95. For the protocol specification, see [PROTOCOL.md](../PROTOCOL.md).

Last updated: 2026-04-11

## Goal

Reverse-engineer the MSN 1.0 for Windows 95 ("Marvel") wire protocol from client
binaries and build a working emulated server.

## Current Runtime State

- Full dial-up bootstrap, login, service discovery, and idle flow working.
- **MSN Shell renders** — Explorer window opens showing "The Microsoft Network"
  with MSN Today, E-Mail, Favorite Places, Member Assistance, and Categories.
- DIRSRV directory browsing active — client navigates the tree, requesting
  child nodes with 14-property records (a, c, h, b, e, g, x, mf, wv, tp, p, w, l, i).
- Sign-out completes cleanly (all pipes close, process exits).
- CPU spin bug fixed (enumerator requests left pending, not replied to).

Latest observed trace pattern (2026-04-10):

1. client control type `1`
2. server control type `1` echo
3. client `LOGSRV` open (on pipe 0, routing=0x0000)
4. **server pipe-open RESPONSE** (on pipe 1, continuation format, cmd=1)
5. **MOSCP dispatches to handler 1 → PipeOpen_SendCmd7ToMOSCL**
6. **CMD 7 reaches MOSCL → PipeObj_HandleOpenResponse fires**
7. server discovery block (LOGSRV selector map)
8. **CMD 3 (data_ready)** — client reads discovery data from arena
9. **client sends login request** on pipe 3 (host block class=6, selector=0)
10. no server response → carrier_lost after timeout

## Live Debugging Findings

### Debugger Setup

Two debuggers have been used:

- **SoftICE 3.2** — kernel-mode VxD debugger for Windows 95 (earlier sessions).
- **86Box GDB stub** — built-in GDB remote serial protocol stub in the 86Box
  emulator, accessed via a custom Python client (`gdb_debug.py`). Supports HW
  breakpoints, memory reads/writes, register inspection (2026-04-10 session).

Key 86Box gdbstub notes:

- **Fix applied**: `response_event` initialized as signaled so the first GDB
  packet is processed without deadlock.
- **HW breakpoints require interpreter mode**: the dynamic recompiler (dynarec)
  only checks `gdbstub_instruction()` at block boundaries, missing mid-block
  addresses. 86Box's "Force interpretation" UI toggle or `cpu_use_dynarec = 0`
  in config enables per-instruction HW breakpoint checking.
- **Per-process address spaces**: Win95 maps DLLs below 0x80000000 in
  per-process page directories. MPCCL.DLL at 0x04600000 is only visible when
  the MSN process's CR3 is active. Memory reads via `readmembl()` from the
  idle/system context (V86 HLT loop) return 0xFF for those addresses. This is
  not a problem when stopped at HW breakpoints inside MPCCL code (correct
  process context).
- **Current live workflow**: use one-shot breakpoint scripts only. Repeated
  break/resume polling and reconnecting while stopped can destabilize Win95 and
  trigger protection errors. The repo now has `trace_moscp.py` to arm the
  current best four MOSCP breakpoints in one pass instead of retargeting them
  one at a time.

### Debugger: SoftICE

### Runtime Layout Confirmed

- GUIDE.EXE `.text` at `0137:04301000`, size `00006923` — matches Ghidra base `04300000`.
- MPCCL.DLL `.text` at `0137:04601000`, size `0000C000` — matches Ghidra base `04600000`.
- Selector `0137` is flat Code32: Base=`00000000`, Limit=`FFFFFFFF`, DPL=3.
- Process tree: `GUIDE` > `MOSCP` > `TAPIEXE` > `LIGHTS`.
- `ENGCT.EXE` is NOT visible as a separate module (`MAP32`, `MOD` show nothing). Its loading mechanism is unknown.

### MPCCL.DLL Is Loaded Dynamically

- MPCCL is NOT preloaded when GUIDE starts.
- It is loaded during `CALL 043076B0` at address `04304064` inside `VerifyAccountViaLogSrv`.
- SoftICE shows `WINICE: Load32` messages for all 7 MPCCL sections during this CALL.
- Consequence: BPX breakpoints set on MPCCL addresses before login starts are
  overwritten when LoadLibrary maps the DLL. Breakpoints must be set AFTER
  the Load32 event.

### Confirmed Call Flow During Login

Breakpoints that fire (in order):

1. `04304064` — `CALL 043076B0` in GUIDE (loads MPCCL)
2. `04601F75` — `OpenOrCreateNamedService` in MPCCL
3. `0460263F` — `InitializeLoginServiceSession` in MPCCL

Breakpoints that NEVER fire:

- `04602EBB` — `QueryOpenedServiceInterface` — **never reached**
- `0460307D` — `DispatchMosPipeReadEvent` — **never reached**
- `04607342` — `LoadServiceInterfaceSelectorMap` — **never reached**
- `046073DB` — `ResolveServiceSelectorForInterface` — **never reached**

### Tracing Inside `InitializeLoginServiceSession`

Call chain confirmed via STACK:
```
GUIDE:04304151 (inside VerifyAccountViaLogSrv)
  → GUIDE:04304765 (inside RunLoginVerification area)
    → MPCCL:0460263F (InitializeLoginServiceSession)
```

Internal breakpoint results inside `InitializeLoginServiceSession`:

- `0460273B` (after `InitializeServiceInterfaceSelectorState`) — **fires, EAX=1** (success).
  The selector state (Event object + GUID comparator map) is created successfully.
- `04602963` (after `_OpenMOSPipeWithNotifyEx_28`) — **never fires**.
  The MOS pipe open call is never reached.
- `04603047` (`OnMosPipeNotify` callback) — **never fires**.
  No pipe data notification is ever delivered.

This means execution exits `InitializeLoginServiceSession` somewhere between
the successful selector-state init (`0460273D`) and the pipe open call
(`0460295E`). That section handles:

- userId copy + length check (max 0x41 bytes) — exits via `04602791` if too long
- password copy + length check (max 0x11 bytes) — exits via `046027D1` if too long
- phoneNumber copy + length check (max 0x80 bytes) — exits via `04602810` if too long
- `FMCMOpenSession` call at `04602859` — exits via `0460287C` if it fails (returns 0)
- `FGetConDetails` call at `046028BC` — exits via `046028EC` if it fails
- service name alloc — exits via `04602922` if alloc fails

### Key Conclusion (RESOLVED)

**`_OpenMOSPipeWithNotifyEx_28` previously blocked forever.** Root cause: the
server was sending a transport-level open-ack (flag 0x01) instead of a
protocol-level pipe-open-response through the "Select" handler table.

The full chain has been traced through three binaries:

1. **MPCCL** calls `_OpenMOSPipeWithNotifyEx_28` → **MOSCL** sends MosSlot cmd 6 to ENGCT
2. **ENGCT** `MosSlot_Dispatch` case 6 creates a PipeObj, sends pipe-open request over the wire
3. The server receives the pipe-open request and sends a response
4. **ENGCT** `PipeObj_DeliverData` receives the response, dispatches to `Channel_PipeDataHandler`
5. `Channel_PipeDataHandler` sends MosSlot **cmd 0xC** (not cmd 7!) to MOSCL
6. **MOSCL** `PipeObj_FlushAndSignal` signals `SetEvent(pipe+0x5c)` but does NOT set arena offsets
7. **MOSCL** `PipeObj_OpenAndWait` wakes up, finds `read_arena == 0` → **pipe open fails**

The correct path requires MosSlot **cmd 7** which carries `[read_arena:4][write_arena:4]`.
Only `X25Pipe_HandleOpenResponse` (in the X25PIPE vtable at `0x057223ac`) sends cmd 7.
This function is **never called for Straight (dial-up) connections**.

### Automated Debugging (86Box GDB stub, 2026-04-10)

Four HW breakpoints set on `InitializeLoginServiceSession` internals
(interpreter mode, `cpu_use_dynarec = 0`):

| Address      | Description                     | Result   | EAX        |
|--------------|---------------------------------|----------|------------|
| `0x0460273B` | after SelectorState init        | **HIT**  | `0x00000001` (OK) |
| `0x0460284B` | after credential copy           | **HIT**  | `0x000002A4` |
| `0x04602906` | convergence before pipe-open    | **HIT**  | `0x000002A4` |
| `0x04602963` | after `_OpenMOSPipeWithNotifyEx`| **MISSED** | — |

Register snapshot at `0x04602906` (convergence point):
```
EAX=0x000002a4  ECX=0x00000000  EDX=0x00400554  EBX=0x00400764
ESP=0x00ccfc5c  EBP=0x00ccfe44  ESI=0x004006d4  EDI=0x0040050c
```

**Key finding**: execution reaches the convergence point (0x04602906) — meaning
credentials copied OK, `FMCMOpenSession` succeeded, and `FGetConDetails`
succeeded. Pipe-name construction and allocation also succeed.

Second pass with finer breakpoints:

| Address      | Description                          | Result     | EAX          |
|--------------|--------------------------------------|------------|--------------|
| `0x04602906` | convergence before pipe-open         | **HIT**    | `0x00000294` |
| `0x04602922` | after service name alloc             | **HIT**    | `0x00400b9c` (non-NULL = OK) |
| `0x0460293E` | after name construction              | **HIT**    | `0x00000006` |
| `0x0460295E` | `_OpenMOSPipeWithNotifyEx` call      | **HIT**    | `0x00500ed0` |
| `0x04602963` | after pipe open (return value)       | **MISSED** | — |

**Critical finding**: `_OpenMOSPipeWithNotifyEx_28` is **called but never
returns**. It does not crash (no GPF). It **blocks forever** — waiting for a
completion event from the transport layer (ENGCT/MOSCL) that never arrives.

The server sees the LOGSRV pipe-open request on the wire, and sends a
pipe-open response. But the response never reaches MPCCL's completion path.
Either ENGCT never delivers the response upward, or the response format is
wrong and ENGCT/MOSCL drops it silently.

**This eliminates all MPCCL-internal failures.** The entire
`InitializeLoginServiceSession` flow succeeds up to and including the pipe
open call. The bug is in the transport layer's response delivery, not in
MPCCL.

### Other Observations

- Login never times out. The `MsgWaitForSingleObject` loop in GUIDE wakes on
  every Windows message and re-enters with a fresh timeout value.
- SoftICE P (step-over) does not work reliably inside MPCCL code — after
  stepping over a CALL, SoftICE loses the return context and drops to the
  desktop. Explicit BPX on specific addresses works. This is likely related
  to the "Invalid Address" issue below.
- SoftICE reports "Invalid Address" for MPCCL pages in some contexts despite
  valid selector and present page table entry (page type "System"). This
  appears to be a SoftICE context/timing issue, not a real memory problem.

### Ghidra Decompilation of `InitializeLoginServiceSession`

Full flow confirmed from decompilation:

1. AddRef on connection object (vtable call at `0460265A` → `04601B07`)
2. Construct `ServiceInterfaceSelectorState` (stores at `this+0x90`)
3. Allocate three 0x54-byte objects with GUID comparator vtables
   (stored at `this+0x68`, `this+0x6c`, `this+0x70`)
4. Call `InitializeServiceInterfaceSelectorState` (`04602736`)
   — creates Event + selector map, returns 1 on success
   — if returns 0: early exit with `return 0`
5. Copy userId (max 65 bytes), password (max 17 bytes), phoneNumber (max 128 bytes)
6. If `sessionHandle == -1`: call `FMCMOpenSession` (`04602859`)
   — if fails: `GetLastMCMError`, `return 0`
   — if succeeds: call `FGetConDetails`, store connectionId
7. Allocate service name buffer: `"U" + serviceName`
8. Call `_OpenMOSPipeWithNotifyEx_28` (`0460295E`) with:
   — `OnMosPipeNotify` (04603047) as data callback
   — `OnMosPipeShutdown` (046031DE) as shutdown callback
   — default notify message ID `0x1643`
9. If pipe handle == -1: error, `return 0`
10. Construct `LogSrvPipeWorker` (stores at `this+0x18`)
11. `return 1`

`OnMosPipeNotify` (04603047) simply calls `DispatchMosPipeReadEvent` —
confirming this is the sole data delivery path into MPCCL.

## Confirmed Binary Findings

### GUIDE.EXE

Relevant functions already renamed in Ghidra:

- `0x04304885` `LoginDialogProc`
- `0x0430484e` `LoginVerificationThreadProc`
- `0x04304632` `RunLoginVerification`
- `0x04304024` `VerifyAccountViaLogSrv`
- `0x04302389` `AbortLoginConnection`
- `0x04303df1` `GetVersionOfLastUpdate`
- `0x043036b7` `RunPostLoginLogSrvTransferFlow`
- `0x0430348b` `LogSrvTransferProgressDialogProc`
- `0x04303242` `PollLogSrvTransferRequestProgress`

What the `Verifying account...` path does:

1. Open MOS session
2. Open `LOGSRV` version `6`
3. Query interface IID `{00028BC2-0000-0000-C000-000000000046}`
4. Request request-builder opcode `0`
5. Build first login RPC
6. Dispatch request
7. Wait synchronously for completion

Unlock condition:

- The first login result code must be `0` or `0x0c`.
- On success, the worker posts the success path.
- On failure, it posts `WM_CLOSE`.

The client is currently stuck before step 5/6 on the wire: it never emits the first real `LOGSRV` request.

There is also a second `LOGSRV` path:

- `RunPostLoginLogSrvTransferFlow`
- This is a later transfer/update flow, not the login gate.
- It uses request-builder opcode `8`.

### MPCCL.DLL

Relevant functions already renamed/commented in Ghidra:

- `0x0460263f` `InitializeLoginServiceSession`
- `0x04601f75` `OpenOrCreateNamedService`
- `0x0460253d` `ConstructOpenedService`
- `0x04602ebb` `QueryOpenedServiceInterface`
- `0x04607342` `LoadServiceInterfaceSelectorMap`
- `0x046073db` `ResolveServiceSelectorForInterface`
- `0x0460307d` `DispatchMosPipeReadEvent`
- `0x04607569` `ParseHostBlockFromPipe`
- `0x04603331` `CreateServiceRequestBuilderInterface`
- `0x046036c8` `ConstructServiceRequestBuilder`
- `0x046037ad` `InitializeServiceRequestBuilder`
- `0x046034c6` `AllocateRequestIdVliHeader`
- `0x046063b7` `ConstructRequestWireBuilder`
- `0x046063f6` `InitializeRequestWireBuilder`
- `0x046064e4` `AppendRequestIdHeaderToWireBuilder`
- `0x046040d8` `DispatchBuiltServiceRequest`
- `0x046069b9` `WriteBuiltRequestToMosPipe`
- `0x04604350` `DispatchReplyToRequestObject`
- `0x04604f26` `ProcessTaggedServiceReply`
- `0x04603aaa` `AppendSendDwordField`
- `0x04603c0a` `AppendSendBufferField`
- `0x04603e17` `RegisterFixedReplyDwordField`
- `0x04603ebc` `RegisterVariableReplyBuffer`
- `0x04602aab` `CompareGuidBytes16`

What is confirmed:

- `LoadServiceInterfaceSelectorMap` consumes the payload as repeated `IID(16) + selector(1)` records.
- `ResolveServiceSelectorForInterface` waits for that map, then resolves the requested IID to a one-byte selector.
- The selector map is keyed by a raw 16-byte GUID compare (`CompareGuidBytes16`), not by string form.
- If the IID lookup fails, `QueryOpenedServiceInterface` fails and the login request is never built/sent.

### MOSCL.DLL — MosSlot IPC & Pipe Object Model

Fully decompiled pipe-open and IPC paths. Named functions in Ghidra:

| Address      | Name                         | Role                                          |
|--------------|------------------------------|-----------------------------------------------|
| `0x7f672380` | `MosSlot_MessageDispatch`    | Main IPC dispatcher (switch on cmd word)      |
| `0x7f6710da` | `MosSlot_ReaderThread`       | Thread loop: `ReadMosSlot` → dispatch         |
| `0x7f6710b0` | `MosSlot_SendMessage`        | Write message to MosSlot (`WriteMosSlot`)     |
| `0x7f6716d8` | `PipeObj_Constructor`        | Alloc events (0x5c, 0x64), semaphore (0x60), critsecs |
| `0x7f671adb` | `PipeObj_AllocAndOpen`       | Alloc pipe obj, add to table, call OpenAndWait |
| `0x7f671c8c` | `PipeObj_OpenAndWait`        | Send cmd 6, block on event at pipe+0x5c       |
| `0x7f67102e` | `WaitOnEventWithMsgPump`     | `MsgWaitForMultipleObjects` loop with `PeekMessage` |
| `0x7f671fd7` | `PipeObj_HandleOpenResponse` | Cmd 7 handler: stores arena offsets + server handle |
| `0x7f6720f8` | `PipeObj_FlushAndSignal`     | Cmd 0xC handler: SetEvent(+0x5c), SetEvent(+0x64) |
| `0x7f6721f4` | `PipeObj_DataReady`          | Cmd 3 handler: ReleaseSemaphore(+0x60)        |
| `0x7f672242` | `PipeObj_ReadComplete`       | Cmd 5 handler: SetEvent on queued waiter      |
| `0x7f671f39` | `PipeObj_SignalAndClose`     | Close path: SetEvent(+0x5c) if state==0       |
| `0x7f671a5f` | `PipeObj_CloseByIndex`       | Iterate pipes, close matching                 |
| `0x7f671f1d` | `PipeObj_EnterCritSec`       | Enter pipe critical section                   |
| `0x7f671f2b` | `PipeObj_LeaveCritSec`       | Leave pipe critical section                   |

**MOSCL pipe object layout** (0xE4 bytes):

| Offset | Type    | Field               | Set by                          |
|--------|---------|---------------------|---------------------------------|
| +0x5c  | HANDLE  | open_event          | `CreateEventA` (auto-reset, non-signaled) |
| +0x60  | HANDLE  | data_semaphore      | `CreateSemaphoreA(0, 0x7FFFFFFF)` |
| +0x64  | HANDLE  | flush_event         | `CreateEventA` (auto-reset)     |
| +0x68  | DWORD   | read_arena_offset   | `PipeObj_HandleOpenResponse` (cmd 7 only) |
| +0x6c  | DWORD   | write_arena_offset  | `PipeObj_HandleOpenResponse` (cmd 7 only) |
| +0x70  | WORD    | server_pipe_handle  | `PipeObj_HandleOpenResponse` (cmd 7 only) |
| +0x72  | WORD    | pipe_handle         | `PipeObj_OpenAndWait`           |
| +0x74  | PTR     | data_callback       | `PipeObj_OpenAndWait`           |
| +0x78  | PTR     | shutdown_callback   | `PipeObj_OpenAndWait`           |
| +0x84  | DWORD   | state               | 0=waiting, 1=open, 2=flushed, 3=async-nocb, 4=async-cb |
| +0x8c  | CRITSEC | critsec_0           |                                 |
| +0xa4  | CRITSEC | critsec_1           |                                 |
| +0xbc  | CRITSEC | critsec_2           |                                 |
| +0xd4  | WORD    | error_word          | `PipeObj_HandleOpenResponse`    |
| +0xe0  | DWORD   | flags               |                                 |

**MosSlot command table** (MOSCL side, dispatcher at `0x7f672380`):

| Cmd  | Name             | Action                                                  |
|------|------------------|---------------------------------------------------------|
| 1    | ConnInit         | `OpenProcess`, open arena, `SetEvent(DAT_7f679224)`    |
| 3    | DataReady        | `ReleaseSemaphore(pipe+0x60)`, call data callback       |
| 5    | ReadComplete     | `SetEvent` on queued read waiter                        |
| 7    | PipeOpenResponse | Store arena+handle, `SetEvent(pipe+0x5c)` ← **UNBLOCKS** |
| 9    | ConnNotify       | Notification on connection object table                 |
| 0xC  | PipeFlush        | `SetEvent(pipe+0x5c)` + `SetEvent(pipe+0x64)` + close  |
| 0xF  | ConnSignal       | `SetEvent(conn+0x24)`                                  |
| 0x10 | PipeError        | Same as 0xC with error flag                            |

### ENGCT.EXE — NOT USED AT RUNTIME

**ENGCT.EXE is never loaded during Straight (dial-up/TCP) connections.** Process
Explorer on Win95 shows only GUIDE.EXE, MOSCP.EXE, TAPIEXE.EXE, and LIGHTS.EXE
during login. ENGCT.EXE is not visible as a running process, a loaded module, or
a DLL import of any running process. SoftICE `MAP32`/`MOD` also show nothing.

All prior static analysis of ENGCT.EXE (Channel_PipeDataHandler, MosSlot_Dispatch,
X25Pipe_HandleOpenResponse, PipeObj_DeliverData, etc.) describes a binary that is
**not part of the runtime call chain** for our configuration. ENGCT.EXE may only be
used in X25PIPE (Named Pipe) or other non-Straight transport modes.

**MOSCP.EXE is the actual transport engine.** It contains the same architecture:
MosSlot IPC, Straight/BuiltIn channel init, arena shared memory, and an equivalent
`Channel_PipeDataHandler` (FUN_7f455bca). Analysis must focus on MOSCP.EXE instead.

<details>
<summary>ENGCT.EXE Ghidra analysis (kept for reference, not runtime-relevant)</summary>

Named functions in Ghidra:

| Address      | Name                          | Role                                          |
|--------------|-------------------------------|-----------------------------------------------|
| `0x05711177` | `MosSlot_Dispatch`            | IPC dispatcher for cmds from MOSCL            |
| `0x057114e1` | `MosSlot_WriteToClient`       | Send IPC message to MOSCL via MosSlot         |
| `0x05717a1d` | `Channel_PipeDataHandler`     | Straight channel data handler (+0x28 callback)|
| `0x05717b04` | `X25Pipe_HandleOpenResponse`  | X25PIPE open-response handler (sends cmd 7)   |
| `0x05717e6a` | `Channel_Init`                | Initialize channel (BuiltIn+Straight or Select)|
| `0x0571584a` | `PipeObj_CreateAndRegister`   | Create pipe, add to connection's pipe array   |
| `0x057125ec` | `PipeObj_Init`                | Initialize 0x130-byte pipe object             |
| `0x05712a39` | `PipeObj_SetHandles`          | Store MOSCL handles, alloc arenas, state→4    |
| `0x05712900` | `PipeObj_DeliverData`         | Flag dispatch: 0x01=open-ack, 0x02=close      |
| `0x05712a7e` | `PipeObj_CreateChannel`       | Create sub-channel for opened pipe            |
| `0x0571384c` | `PipeBuf_SetFlagFromContent`  | Extract flag byte from content[2]             |

</details>

### MOSCP.EXE — Actual Transport Engine

MOSCP.EXE (image base `0x7f450000`, 68K) is the transport process for dial-up
connections. It runs as a child of GUIDE.EXE and communicates with MOSCL.DLL via
MosSlot shared-memory IPC.

Named/identified functions in Ghidra:

| Address      | Name                             | Role                                          |
|--------------|----------------------------------|-----------------------------------------------|
| `0x7f4597f4` | `MosSlot_Init`                   | Create "MosSlot" file mapping + "MosArena" mutex |
| `0x7f455895` | `MosSlot_SendMessage`            | Write IPC message to MOSCL via MosSlot        |
| `0x7f455f16` | `PipeProtocol_Initialize`        | Init pipe protocol: Select or Straight        |
| `0x7f455de4` | `SelectProtocol_DataCallback`    | Select transport +0x28 callback; routes by flag |
| `0x7f456071` | `SelectProtocol_DispatchToHandler` | Reads cmd index, dispatches to handler table |
| `0x7f455cb1` | `PipeOpen_SendCmd7ToMOSCL`       | **Handler 1**: sends CMD 7 to MOSCL, switches to Straight |
| `0x7f455bca` | `PipeCallback_DeliverOrClose`    | Straight transport +0x28 callback             |
| `0x7f451d16` | `PipeData_SendCmd5ToMOSCL`       | Sends CMD 5 (read_complete) to MOSCL          |
| `0x7f4520c7` | `PipeFlush_SendCmd5`             | Sends CMD 5 for flush state                   |
| `0x7f453fd9` | `PipeAll_SendCmd0xC_Close`       | Sends CMD 0xC (close) for all pipes           |
| `0x7f452ed4` | `Connection_SendCmd0xF`          | Sends CMD 0xF (connection signal)             |
| `0x7f45552b` | `MosSlot_IncomingCmdDispatch`    | Dispatch MosSlot cmds from MOSCL (cases 0,4,6,8,10,0xB,0xD,0xE) |
| `0x7f452507` | `PipeBuf_SetFlagFromContent`     | Extract flag byte from content[2] (has_length only) |
| `0x7f451e00` | `PipeObj_DeliverData`            | Flag dispatch: 0x01=open-ack, 0x02=data       |
| `0x7f452181` | `Pipe_DeliverDataFromArena`      | Arena read → pipe buffer → delivery + event 0x1E |
| `0x7f45384f` | `WireReceiver_ProcessPacket`     | Wire packet parsing, CRC, pipe routing        |
| `0x7f451610` | `decode_header_byte`             | XOR 0xC0 for values {0x4D, 0x50, 0x4B}       |
| `0x7f4523cc` | `PipeBuf_ReadByte`               | Read one byte from pipe buffer, advance pos   |
| `0x7f45506c` | `PipeBuf_ReadUInt16LE`           | Read LE uint16 from pipe buffer               |
| `0x7f454464` | `notify_event`                   | Send CMD 9 (event notification) to MOSCL      |

**Pipe protocol architecture (SOLVED):**

New pipes start in **"Select"** transport mode during negotiation. The Select
protocol has a handler table (`PipeProtocol_HandlerTable` at `0x7f4602d0`, 6 entries):

- Handler 0: `ret` stub (no-op)
- Handler 1: `PipeOpen_SendCmd7ToMOSCL` — **pipe-open response handler**
- Handlers 2-5: stub/unused

`SelectProtocol_DataCallback` (the +0x28 callback for Select pipes) routes by flag:
- Flag 0x01 or 0x02 → CMD 5 path (read_complete) — **wrong for pipe-open**
- Flag 0x00 → `SelectProtocol_DispatchToHandler` → handler table dispatch

The dispatch reads 4 bytes from the pipe buffer:
- Bytes 0-1: routing prefix (skipped)
- Bytes 2-3: LE uint16 command index → selects handler

After handler 1 processes the response, it switches the pipe to **"Straight"**
transport via `FUN_7f451f7e(pipe, "Straight", ...)`. Subsequent data uses
`PipeCallback_DeliverOrClose` instead of the handler table.

**Wire format for pipe-open response (server → client):**

MUST use **continuation format** (PipeHdr bit 5 set, bit 4 clear) so that
`PipeBuf_SetFlagFromContent` does NOT extract a flag byte. With has_length
format, `content[2]` = routing byte = pipe_idx, which is mistaken for flag
0x01 (OPEN_ACK) and routes to the CMD 5 path.

Content layout (8 bytes):
```
[routing:2LE = pipe_idx]      — MOSCP pipe routing
[command:2LE = 0x0001]        — Select handler 1
[server_pipe_idx:2LE]         — server's pipe index
[error:2LE = 0x0000]          — 0 = success
```

### MOSCP.EXE — Live Trace Results (2026-04-10)
### MOSCP.EXE — Cmd 8 Selector Snapshot (2026-04-10)

A one-shot hardware breakpoint at `FUN_7f4569dc` captured the exact object selected by
MOSCP's `cmd 8` dispatcher after the user clicks `Connect`. The stop did trigger a
Win95 GPF afterward, but the snapshot itself completed first and produced usable data.

Snapshot result:

- `param1`/command buffer subtype = `7`
- registry `count = 1` live object
- the single live object is:
  - `entry = 0x006404c4`
  - `type = 2`
  - `state = 3`
  - `vtable = 0x7f45d588`
  - `vtable + 0x1c = 0x7f4575d6`

Static analysis of `0x7f4575d6` shows it is the **initial modem/TAPI dial request** path:

- validates cmd header `0x14` and subtype `7`
- stores phonebook/config blob
- initializes TAPI (`lineInitialize`, `lineOpen`, `lineGetDevCaps`, `lineGetDevConfig`)
- configures modem options
- issues `lineMakeCall(...)` and sets transport state to `4`

This is important because it means the previous dynamic focus on `cmd 8` was too early.
`cmd 8/subtype 7` is the pre-wire dial/connect setup, not the later service-pipe open
contract that blocks `LOGSRV`.

**Updated implication:** the next dynamic target should be a later dispatcher message
(probably `cmd 6` from MOSCL's `_OpenMOSPipeWithNotifyEx_28` path), not `cmd 8`.


MosSlot breakpoint trace during login (4 HW BPs on MOSCL dispatch functions):

| Hit | Time     | Function                  | Cmd | Payload (hex)                      |
|-----|----------|---------------------------|-----|------------------------------------|
| 1   | 15:22:26 | MosSlot_MessageDispatch   | 1   | `010000000a00df03fdff000000000000` |
| 2   | 15:22:29 | MosSlot_MessageDispatch   | 9   | `0900000000000c000000000000000000` |
| 3   | 15:22:30 | MosSlot_MessageDispatch   | 9   | `0900000000000d000000000000000000` |
| 4   | 15:22:30 | MosSlot_MessageDispatch   | 9   | `09000000000011000000000000000000` |
| 5   | 15:22:31 | MosSlot_MessageDispatch   | 9   | `09000000000002000000000000000000` |
| 6   | 15:22:32 | MosSlot_MessageDispatch   | 9   | `09000000000005003701000000000000` |
| 7   | 15:22:32 | MosSlot_MessageDispatch   | 9   | `09000000000007003701000000000000` |
| 8   | 15:22:33 | MosSlot_MessageDispatch   | 9   | `09000000000008003701000000000000` |
| 9   | 15:22:33 | MosSlot_MessageDispatch   | 9   | `09000000000023000000000000000000` |
| 10  | 15:22:33 | MosSlot_MessageDispatch   | 9   | `09000000000007001101000000000000` |
| 11  | 15:22:34 | MosSlot_MessageDispatch   | 9   | `09000000000008001101000000000000` |
| 12  | 15:22:35 | MosSlot_MessageDispatch   | 9   | `0900000000001e001101000000000000` |
| 13  | 15:22:36 | MosSlot_MessageDispatch   | 9   | `09000000000006001101000000000000` |

**Key findings:**
- Cmd 1 (init) fires once — MOSCP initializing the MosSlot IPC channel
- Cmd 9 fires 12 times — connection property notifications (parameters 0x02, 0x05, 0x06, 0x07, 0x08, 0x0C, 0x0D, 0x11, 0x1E, 0x23 with varying values)
- **Cmd 7 (pipe open response): NEVER fires** — confirmed root cause
- **Cmd 0xC (flush/close): never fires** — MOSCP's PipeDataHandler isn't even called
- **Cmd 3 (data ready): never fires** — no pipe data delivery at all
- After 13 dispatches (~10s), silence — client stuck at "Verifying account..."

## First Login RPC Shape

Once selector resolution succeeds, the first login RPC on `LOGSRV` is built like this:

- opcode `0`
- send tag `0x03` with a 4-byte value from `GetVersionOfLastUpdate`
- send tag `0x04` with a `0x58`-byte login blob
- register seven fixed 4-byte reply fields (`0x83`)
- register one variable 16-byte reply buffer (`0x84`)
- auto-add a completion/helper slot
- dispatch and wait

This means the current blocker is before tagged login-reply semantics. The client is not even reaching the first real request.

## Host Block Framing: Current Understanding

For normal service traffic, the currently traced model is:

- Byte 0: selector
- Byte 1: opcode / method id
- Then VLI request id
- Then payload

However, `ENGCT.EXE` added a more important correction than the host-block
bytes themselves:

- Completed non-control pipe messages are **routed by the first uint16 inside
  the pipe content**, not only by the outer PipeHdr nibble.
- `recv_packet()` assembles a pipe frame, then reads the first 2 bytes of the
  completed content:
  - `0xFFFF` => control frame
  - `0x0000` => new pipe / open request
  - any other value => route to the existing pipe object with that index
- Only after that inner routing step does ENGCT call `PipeBuf_SetFlagFromContent`
  and `PipeObj_DeliverData`.

Practical consequence for the server:

- Nonzero-pipe server-to-client traffic must be:
  - `[route_pipe_idx:2][host_block...]`
- Our previous server builds omitted that inner 2-byte routing prefix and sent
  only `[host_block...]` on `LOGSRV`.
- For the discovery block, that meant the leading bytes `00 00` were being
  interpreted by ENGCT as a **new pipe request**, not as service-pipe data for
  the existing `LOGSRV` pipe.
- This is the first server change in a while that is directly supported by the
  transport binary rather than by inference from higher-level client behavior.

For discovery/status traffic:

- `DispatchMosPipeReadEvent` routes a parsed host block into `LoadServiceInterfaceSelectorMap` when header byte 0 is `0`.
- The exact full discovery-frame semantics beyond that are still not fully closed.

## What We Know Is Not The Problem

- Dial transport bootstrap
- CRC / packet framing / ACK handling
- Opening `LOGSRV`
- The existence of the requested IID `28BC2`
- GUID byte order in the server payload
- Raw selector-map payload schema `IID(16)+selector(1)`

The server is already publishing the GUID family in correct little-endian Windows layout:

- `00028BB6..00028BC6`
- `28BC2` is emitted as raw bytes `c2 8b 02 00 00 00 00 00 c0 00 00 00 00 00 00 46`

## What Is Still Unknown

The pipe-open problem is **SOLVED**. The primary unknown is now: **what does
the login response look like?**

The client sends a login request as a host block on the LOGSRV service pipe:
```
class=6, selector=0, request_id=0
payload: 43 16 00 00 04 d8 00 00 00 00 "microsoft" ... "test" ...
```

Open questions:

1. **Login response format**: What host block structure does MPCCL expect as a
   login reply? The client registers 7 fixed dword reply fields (tag `0x83`)
   and 1 variable 16-byte reply buffer (tag `0x84`). The response must match.

2. **Login result codes**: GUIDE expects result code `0` or `0x0c` for success.
   What field in the reply carries this code?

3. **Post-login flow**: After login succeeds, does the client open additional
   pipes or send further LOGSRV requests?

4. **Discovery timing**: Is the discovery block needed before or after the login
   response, or is the current ordering (discovery then login) correct?

## Current Server State

Current `server.py` behavior:

- transport bootstrap works (COM trigger + type-3 params)
- control type `1` is echoed back
- **pipe-open WORKS**: `build_pipe_open_result()` sends protocol-level
  pipe-open response using continuation frame format (NOT has_length), routed
  through Select protocol handler 1 → CMD 7 to MOSCL → `PipeObj_OpenAndWait`
  unblocks
- discovery payload contains the 10-entry `28BB6..28BC6` catalog
- selectors are currently sequential (`1..10`)
- **login WORKS**: reply uses header[0]=service selector from discovery map
  (e.g., 0x06 for IID 28BC2), header[1]=method opcode from request, VLI
  matching the pending request_id.  Tagged payload: 7×0x83 dwords + 0x87
  terminator + 1×0x84 variable (16 bytes).  Completion triggers automatically
  when data ends after 0x87.
- **pipe-0 routing WORKS**: all logical pipe data arrives on physical pipe 0
  with a 2-byte LE routing prefix; server now processes routed service traffic
- post-login: client sends second LOGSRV request (selector=0x07, req_id=1),
  then opens two DIRSRV pipes; GUIDE icon appears in systray

**Current blocker**: DIRSRV pipes open but have no discovery maps or request
handling.  Client sends 1-byte `0x01` messages on all pipes (meaning unknown),
then disconnects after ~90s.

## Next Steps

1. **Investigate the 1-byte `0x01` pipe messages:**
   After login, the client sends a single `0x01` byte on pipes 1, 2, and 3.
   This is too short for a host block.  It might be a pipe-level status probe,
   keepalive, or flow-control message.  Check MPCCL/MOSCP for non-host-block
   pipe protocol messages.

2. **Handle DIRSRV service pipes:**
   The client opens two DIRSRV pipes (ver='Uagid=0', version=7).  These need
   discovery maps (IID→selector) and request handling, similar to LOGSRV.
   Find the DIRSRV IIDs in GUIDE.EXE or MPCCL.DLL.

3. **Handle the second LOGSRV request (selector=0x07, req_id=1):**
   Payload is just `0x85`.  This is a tag byte — might be requesting dynamic/
   incremental data.  Understand what GUIDE expects from this request.

4. **Keep the connection alive:**
   The client disconnects after ~90s.  Determine if this is due to unanswered
   requests, missing keepalives, or the 1-byte probe not being acknowledged.

## Files To Keep Updating

- `RE_STATUS.md` for working status and open questions
- `PROTOCOL.md` for stable findings that are strong enough to keep
