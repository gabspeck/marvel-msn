# MSN95 Reverse Engineering Journal

> Chronological research journal documenting the reverse engineering of MSN for
> Windows 95. For the protocol specification, see [PROTOCOL.md](../PROTOCOL.md).

Last updated: 2026-04-14 (second update: MSN Today 'b' not-received root cause)

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

## 2026-04-12 — Signup Wizard End-to-End

Goal: run SIGNUP.EXE's new-account wizard to completion on a fresh
VM and reach the "Congratulations! You are now a member!" dialog
(resource `0x3e8` in SIGNUP.EXE).

### Summary of the path we had to clear

| Step | What broke | Fix |
|------|------------|-----|
| Credentials Submit | OLREGSRV commit head (class=0x01 sel=0x01) needed a reply — without it the vtbl[0x10] wait burns the 90s timeout and the wizard shows the generic error dialog | Reply with `HRESULT=0` as a single `0x83` dword tag; do NOT reply to the 0xE7/0xE6 continuation frames (they're one-way) and do NOT reply to the sel=0x02 pre-check (causes "important part of signup cannot be found") |
| After commit reply | Client disconnected before showing Internet-access prompt | **LOGSRV sel=0x0D** was unhandled; our `None` return made the client drop.  Reply with empty `0x84` variable |
| FTM loop | Wizard opens `CreateFile(OPEN_EXISTING)` on four RTFs next to `SIGNUP.EXE`; the FTM "LOGSRV" name + 0..3 counter is how the server is supposed to serve those | Map counter → `plans.txt` / `prodinfo.rtf` / `legalagr.rtf` / `newtips.rtf`; override the echoed filename via sel=0x00 reply flag bit 3 |
| Internet-access & phonebook | Needed no server work once the transport stayed up | None — PBKDisplayPhoneBook renders the IP we put in registry for the TCP path |

See `PROTOCOL.md` §9a for the stable wire spec.

### Key RE landmarks (SIGNUP.EXE)

| Addr | Symbol | Role |
|------|--------|------|
| `0x00401469` | `FUN_00401469` | Master wizard state machine.  `case 8` is the success arm that calls `FUN_00401332` then `FUN_00405b28`. |
| `0x004016df` | case 8 entry | Post-credentials success. |
| `0x00401332` | `FUN_00401332` | Chains MSN install / MAPI / DUN / internet setup; shows Internet-access prompt and PBKDisplayPhoneBook. |
| `0x00405b28` | Congrats dialog launcher | `DialogBoxParamA(0x3e8, FUN_00405b51)`. |
| `0x00406030` | credentials DlgProc | Runs `DispatchSignupCommitAndWait`; returns `0x19` on success. |
| `0x004063de` | `DispatchSignupCommitAndWait` | Wraps the MOSRPC commit call and the 90s wait on `vtbl[0x10]`. |
| `0x00406562` | wait-post BP | Useful HW BP — EBX=0 here means `WaitForSingleObject` returned wait-success. |
| `0x0040b9a0` | credentials page vtable | `[+4] = DispatchSignupCommitAndWait`. |

### Debugger lessons learned

- **86Box GDB stub event loop runs inside the CPU tick.**
  `gdbstub_cpu_exec` handles GDB I/O between instructions, so a paused
  CPU = a paused stub.  Sending `D` (detach) from our Python client
  deadlocks: the stub neither clears BPs nor reliably processes client
  cleanup, leaving sockets stacked in CLOSE-WAIT.  Use socket close
  only, preceded by `c` to unfreeze the CPU.
- **HW BPs match on linear address** (`cs_base + pc`; `cs_base=0` in
  flat user-mode processes).  The stub does NOT scope by CR3.  Any
  BP in the `0x00400000–0x0040FFFF` range fires in *every* PE EXE
  loaded at the default base — during Windows boot that includes
  `winlogon.exe`, `explorer.exe`, and most Win95 system EXEs, which
  is enough to freeze login.  Only arm EXE BPs after Windows is idle
  and the target app is running; disarm before state transitions
  that could launch a new EXE.
- **BPs persist across GDB client disconnects but are lost when 86Box
  itself restarts.**  The stub's `first_hwbreak` list is a global,
  not per-client.  Re-inserting an already-armed BP returns `E22`
  (not "no slots").
- **Dynarec misses HW BPs.**  86Box's dynamic recompiler only checks
  `gdbstub_instruction()` at block boundaries.  Force interpretation
  (`cpu_use_dynarec = 0`) for per-instruction BP granularity.

### What the Congrats dialog does NOT do

Congrats is shown entirely offline — once the commit and FTM loop
complete, SIGNUP.EXE disconnects from the server before the dialog
renders.  Closing it doesn't flip GUIDE.EXE into authenticated
mode either: `WinMain` (`FUN_0040185d`) only prompts for reboot if
`state[0x1a1] != 0`, which requires
`INETCFG.DLL!ConfigureSystemForInternet` plus a real DUN phonebook
entry — both no-ops in our 86Box setup.  The user has to relaunch
MSN (or the VM) before an authenticated LOGSRV login appears in
the server log.  Out of scope for now.

### Commits

- `4fa7ce2` — FTM billing handler + multi-frame pipe fragmentation.
- `2d31ab9` — Product-details / phone-book flow (LOGSRV 0x07).
- `ce7e1d5` — FTM LOGSRV file loop (plans.txt → newtips.rtf).
- `bf74777` — **LOGSRV sel=0x0D post-signup query** (unblocked Congrats).
- `10389b9` — Test coverage for sel=0x0D.

## 2026-04-13 — DIRSRV Consumer / IID Recovery

Goal: resume the post-login DIRSRV analysis after the MCP session dropped and
pin down which client binaries and interface GUIDs are actually involved.

### New static findings

#### 1. `MOSSHELL.DLL` is a confirmed DIRSRV consumer

`CMosTreeNode::GetShabbyViaFtm` at `0x7f3fd800` calls:

```c
HrFtmDownloadWithUI(..., "DIRSRV", ..., 1, 7, 1);
```

So the shell/tree path is not using LOGSRV for content fetches after login; it
explicitly routes FTM downloads through `DIRSRV`.

Key point:

- This strongly supports the runtime observation that the post-login traffic
  opening additional pipes is real service work, not a spurious reconnect path.

#### 2. `TREENVCL.DLL` opens a DIRSRV-facing helper and resolves IID `28B27`

`CTreeNavClient::CTreeNavClient` at `0x7f63113d` does:

- `CoCreateInstance(&GUID_00028B07, ..., &GUID_00028B08, &this->helper)`
- then helper `vtbl[0x24/4]` with `&GUID_00028B27`, service name, account id,
  and locale string, storing the resulting interface pointer at `this+0x28`

Raw GUIDs recovered from `.rdata`:

- `0x7f633070` = `{00028B07-0000-0000-C000-000000000046}`
- `0x7f633080` = `{00028B08-0000-0000-C000-000000000046}`
- `0x7f633270` = `{00028B27-0000-0000-C000-000000000046}`

This is the first confirmed **DIRSRV interface IID** from static analysis in
the client-side tree stack.

#### 3. `TREENVCL.DLL` contains a contiguous DIRSRV GUID family

Memory at `0x7f633250` contains:

- `{00028B25-0000-0000-C000-000000000046}`
- `{00028B26-0000-0000-C000-000000000046}`
- `{00028B27-0000-0000-C000-000000000046}`
- `{00028B28-0000-0000-C000-000000000046}`
- `{00028B29-0000-0000-C000-000000000046}`
- `{00028B2A-0000-0000-C000-000000000046}`
- `{00028B2B-0000-0000-C000-000000000046}`
- `{00028B2C-0000-0000-C000-000000000046}`
- `{00028B2D-0000-0000-C000-000000000046}`
- `{00028B2E-0000-0000-C000-000000000046}`

Implication:

- DIRSRV likely uses its own selector map in the `28B25..28B2E` range, just as
  LOGSRV used the `28BB6..28BC6` family.
- Publishing at least `28B27` in the server's DIRSRV discovery block is likely
  necessary before tree navigation calls can proceed.

#### 4. Tree navigation methods are layered on top of that interface

`MOSSHELL.DLL` methods such as:

- `OkToGetChildren` (`0x7f3fe333`)
- `GetNthChild` (`0x7f3fdfc4`)
- `EnumShn` (`0x7f3fd8ab`)

all call into `TREENVCL.DLL`:

- `CTreeNavClient::GetChildren`
- `CTreeNavClient::GetNthNode`
- `CTreeNavClient::EnumShn`

Those return **DS status codes**, which `MOSSHELL.DLL!ResultFromDsStatus`
(`0x7f3fabb5`) maps into HRESULTs. So any missing DIRSRV selector/reply is
expected to surface later as a DS status failure in MOSSHELL.

### What this changes

The most concrete next runtime target is no longer "find any DIRSRV IID" in
the abstract. We now have:

- a confirmed consumer path: `MOSSHELL` / `TREENVCL`
- a confirmed interface IID: `28B27`
- a plausible full DIRSRV discovery GUID family: `28B25..28B2E`

### Updated next steps

1. Publish a DIRSRV selector map that includes at least `28B27`
   (and probably the full `28B25..28B2E` family) and see whether the
   post-login client progresses beyond the current disconnect.

2. Instrument `ResolveServiceSelectorForInterface` (`MPCCL 0x046073db`)
   during a post-login tree navigation attempt to confirm which of
   `28B25..28B2E` are requested at runtime.

3. Break on `MOSSHELL.DLL!ResultFromDsStatus` (`0x7f3fabb5`) after the
   selector map is added. If failures remain, the returned DS status code
   should narrow the missing method/reply semantics quickly.

## 2026-04-13: Live click-path breakpoint confirms `MSN Today` dies at cached property `b`

After adding the provisional DIRSRV selector map (`28B25..28B2E`), I armed the
Claude-noted click-path breakpoints with `tools/gdb_debug.py` against the
`86Box_dbg` GDB stub:

- `0x7f3ff693` `CMosTreeNode::ExecuteCommand`
- `0x7f3fce71` `GetProperty`
- `0x7f3fb9f5` cache cell reader
- `0x7f3fa1da` `ReportMosXErr`
- `0x7f3fa179` `ReportMosXErrX`

On an `MSN Today` click, the target stopped at:

- `EIP = 0x7f3fb9f5`

Registers at the stop:

- `EDI = 0x7f40e1c4`

That address matches the property token for wire property `b` from the earlier
static RE. So the runtime path is not failing in some later OLE/service-launch
step yet; it is first trying to resolve the cached `b` attribute for the clicked
node and stopping in the cache reader.

This is consistent with the current server logs for the same click:

- DIRSRV request targets node `0:4456508`
- requested props include `b`
- our fallback reply for that node returns no meaningful child/property data

Implication:

- The current `Cannot open service` failure remains best explained by the node
  lacking cached property `b`, not by a bad `e`/launch-class value.
- The next productive server change is to emit a real per-child record for the
  parent/child path that leads to `0:4456508`, with at least `a`, `b`, and `p`
  populated so `CMosTreeNode::ExecuteCommand` can classify the clicked node.

## 2026-04-13: `MSN Today` launch path reaches `HRMOSExec`, but app `5` does not yield a usable filename

This session pushed the `MSN Today` path further with live breakpoints in
`MOSSHELL.DLL` and `MCM.DLL`, plus a server-side experiment on the `c` app id
advertised for the `MSN Today` icon under node `0:4456508`.

### Breakpoint progression

With the click-path breakpoints re-armed, the `MSN Today` path was traced
through:

- `0x7f3ff693` `CMosTreeNode::ExecuteCommand`
- `0x7f3feba6` `CMosTreeNode::Exec`
- `0x041020d8` `MCM.DLL!HRMOSExec`

This confirms the click is no longer dying before dispatch; it reaches the
launcher logic in `MCM.DLL`.

### `CMosTreeNode::Exec` semantics

Decompilation of `CMosTreeNode::Exec` (`0x7f3feba6`) in `MOSSHELL.DLL`
clarified the launch properties:

- property `c` is the MOS app id passed directly to `HRMOSExec`
- property `ri` is fetched as a string/blob and passed as the trailing launch
  argument
- for non-DNR apps (`c != 7`), the code path is:
  `GetProperty("ri") -> HRMOSExec(c, ri, ...)`

So the central-icon metadata needs to be valid enough for `HRMOSExec`, not just
for tree rendering.

### `HRMOSExec` argument format

Decompilation of `MCM.DLL!HRMOSExec` (`0x041020d8`) and its helper
`FUN_04102091` (`0x04102091`) showed the exact launch-string format:

1. `FGetNamesForApp(app_id, NULL, 0, filename_buf)` resolves the app registry
   entry
2. `FUN_04102091` formats:

   `-MOS:<app_id>:<node_hi>:<node_lo>:<type> <ri>`

3. `HRMOSExec` then builds:

   `<Filename> <formatted_args>`

4. It calls `CreateProcessA`
5. On failure it calls `MosErrorP`

Important addresses:

- `0x04102016` immediately after `FGetNamesForApp`
- `0x04102185` `CreateProcessA` call site
- `0x04102faa` `MosErrorP`

### Live result for provisional `MSN Today -> c=5`

The original server mapping advertised:

- `MSN Today` -> `c = 5`
- `ri = ""`

Live breakpoints showed:

- `HRMOSExec` is reached for `MSN Today`
- at `0x04102016`, `EAX = 1`, so `FGetNamesForApp(5)` reports success
- but reading the expected stack filename buffer at that stop produced only
  `0xFF` fill bytes, not a usable executable path
- resuming from that same invocation did **not** trip:
  - `0x04102185` `CreateProcessA`
  - `0x04102faa` `MosErrorP`

The practical interpretation is that app id `5` is recognized by name but is
not yielding a usable launch target in this client build, so `MSN Today` with
`c=5` is not a viable launch mapping.

### Offline Win95 image correlation

The offline `win95_c.raw` string dump still shows the MOS app registry table.
Relevant entries:

- `FilenameC:\Progra~1\TheMic~1\dsnav.nav` + `Friendly nameDirectory_Service`
- `FilenameC:\Progra~1\TheMic~1\guidenav.nav` + `Friendly nameGuide_Service`
- `FilenameC:\Progra~1\TheMic~1\mosview.exe` + `Friendly nameMedia_Viewer`
- `FilenameC:\Progra~1\TheMic~1\dnr.exe` + `Friendly nameDown_Load_And_Run`
- `Friendly nameWhatsNew`

Notably, `App #5` appears as `Friendly nameWhatsNew`, but in the simple raw
string dump it does **not** appear with the adjacent `Filename...` pattern that
the working app entries do. That matches the live `HRMOSExec` result above.

### Server-side experiment: reroute `MSN Today` to app `6`

To test a launchable app record instead of the broken `WhatsNew` mapping, the
server was patched so node `0:4456524` now advertises:

- `c = 6` (`Media_Viewer`)
- `ri = ""`

Files changed:

- `server/services/dirsrv.py`
- `tests/test_services.py`

Tests passed after the patch:

- `python -m unittest tests.test_services -v`
- `python -m unittest tests.test_integration -v`

### Live behavior after the `c=6` patch

After restarting the live server and clearing breakpoints, `MSN Today`
behavior changed again:

- the first click produced traffic
- the client queried node `0:4456508` for `ri,g`
- it accepted the reply
- then it sat for roughly 27 seconds with no meaningful second-stage request
- it retried a tiny root query (`payload=0x0f`)
- eventually, around 60 seconds, it closed `DIRSRV` pipe `8`
- the UI later surfaced:
  `"This service is not available at this time"`

This means the current failure is **not** a raw transport outage anymore. The
client can still talk to the server, but the launched path is waiting on some
additional local/service-side condition and timing out into the generic
availability dialog.

### Error-path breakpoint attempt

I re-armed:

- `0x7f3fa1da` `ReportMosXErr`
- `0x7f3fa179` `ReportMosXErrX`

Results:

- `0x7f3fa1da` armed successfully
- `0x7f3fa179` returned `E22` from the 86Box stub and did not arm
- reproducing the `"This service is not available at this time"` dialog did
  **not** hit `ReportMosXErr`

So the dialog is likely not coming through that exact helper, or the stub
failed to preserve the breakpoint state at the relevant moment.

### 86Box GDB stub note

The local debugger helper `tools/gdb_debug.py` was improved this session after
reading `86box/src/gdbstub.c`:

- added a file lock to serialize access to the single-client stub
- added `batch` mode to keep multi-step operations on one connection
- documented that merely connecting pauses the guest and that reconnects can
  cause `BrokenPipe` / stray pauses

This reduced some debugger churn, but the 86Box stub still behaves
inconsistently under repeated breakpoint work.

### Best next steps

1. Break in the launched `Media_Viewer` / post-launch process rather than in
   `HRMOSExec`, because the path is now clearly getting beyond the earlier
   dispatch stage.

2. Capture the exact command line or module name for the rerouted
   `MSN Today -> c=6` launch, ideally by stopping closer to the successful
   `CreateProcessA` transition or by trapping the child process startup path.

3. Revisit the missing second-stage request on `DIRSRV` pipe `8`:
   the server sees the pipe open but still does not see the meaningful content
   query that should follow a healthy `MSN Today` launch.

4. If breakpointing remains unreliable, mine the client install / registry
   more directly to recover the intended `WhatsNew` executable or a more
   authoritative `MSN Today` app mapping than the current `Media_Viewer`
   fallback experiment.

## 2026-04-13: Deep static RE narrows the `MSN Today` timeout to `MVTTL14C!hrAttachToService`

After the live `MSN Today -> app_id 6` experiment produced:

- one burst of traffic
- a new `DIRSRV` pipe (`pipe 8`)
- then ~30 seconds of silence
- then the UI dialog:
  `"This service is not available at this time"`

I switched to static analysis of the media-view stack in:

- `MOSVIEW.EXE`
- `MVCL14N.DLL`
- `MVTTL14C.DLL`

### 1. `MOSVIEW.EXE` startup path

`MOSVIEW.EXE` main startup is `FUN_7f3c1053`.

Important behavior:

- it calls `FGetCmdLineInfo` imported from `MCM.DLL`
- for a normal `-MOS:` command line, it parses:
  - app id
  - node id high dword
  - node id low dword
  - type
  - trailing `ri` string after the first space

`MCM.DLL!FGetCmdLineInfo` (`0x041022ba`) confirms the syntax:

`-MOS:<appid>:<node_hi>:<node_lo>:<type> <ri>`

For the `MSN Today` node id we were serving (`0:4456524 = 0x0044004c`):

- `DAT_7f3cd04c = 0`
- `DAT_7f3cd048 = 0x0044004c`

and `MOSVIEW` rewrites its internal launch token to a simple hex string:

- `DAT_7f3cd054 = "44004C"`

So by the time `CreateMediaViewWindow(...)` runs, it is **not** operating on
the raw `-MOS:` command line anymore.  It operates on the normalized title key
`"44004C"` plus the trailing `ri` string.

### 2. `CreateMediaViewWindow` gates

`CreateMediaViewWindow` is `0x7f3c4f26`.

Its control flow:

1. Look up / create a handler record for the normalized key (`"44004C"`)
2. Call `FUN_7f3c61ce(param_1, app_seq, hwnd)`
3. If that returns `0`, abort startup immediately
4. Otherwise call `FUN_7f3c6790(...)` to build the actual view hierarchy

The important point is that `FUN_7f3c61ce` is the earliest stage where
`MOSVIEW` establishes the title/service connection.  If it fails, later UI
construction never happens.

### 3. `FUN_7f3c61ce`: MEDVIEW title open sequence

`FUN_7f3c61ce` is `0x7f3c61ce`.

It does:

1. `MosViewStartConnection("MEDVIEW")`
2. build a title-open string using:

   `":%d[%s]%d"`

   with:
   - the global title type id (`DAT_7f3cd2e8 = 2`)
   - the normalized key (`"44004C"`)
   - trailing integer `0`

   producing effectively:

   `":2[44004C]0"`

3. `hMVTitleOpen(":2[44004C]0")`
4. `lpMVNew()`
5. pull multiple title-info record classes (`0x2b`, `0x1f`, `0x98`, string list)
6. if all that succeeds, later `FUN_7f3c6790` lays out windows and topics

So the viewer connection is:

- title family = `MEDVIEW`
- title type = `2`
- title key = `44004C`

### 4. `MVCL14N.DLL`: title type `2` maps to `MVTTL14C.DLL`

`MVCL14N.DLL!MVTitleConnection` is `0x7e885090`.

For title type `2`, it loads the second provider DLL from its title-provider
table:

- title type `1` -> `MVTL14N.DLL`
- title type `2` -> `MVTTL14C.DLL`

and then calls that provider's exported `TitleConnection`.

### 5. `MVTTL14C.DLL!TitleConnection`

`MVTTL14C.DLL!TitleConnection` is `0x7e8446f3`.

Behavior:

- if passed `NULL`, it detaches
- if passed empty string, it substitutes `"MEDVIEW"`
- otherwise it calls:

  `hrAttachToService(param_1, NULL, NULL)`

and maps errors as:

- if `hrAttachToService` returns `0x8b0b0011`, remap to `0x8b0b0407`
- otherwise any negative HRESULT becomes:
  `high_word(original) | 0x07d1`

This is important because `MOSVIEW.EXE`'s top-level startup later does:

- if `CreateMediaViewWindow(...) == 0` and `DAT_7f3cd2ec != 0x407`
  - call `MosErrorP(..., 1, 9, 0)`

That is the generic `"This service is not available..."` path.  So the exact
dialog the user saw is consistent with:

- `TitleConnection` failing
- but **not** with the special remapped `0x407` case

### 6. `MVTTL14C.DLL!hrAttachToService` is the likely timeout site

`hrAttachToService` is `0x7e844114`.

This is the deepest useful finding from the session.

It:

1. lazily initializes COM
2. `CoCreateInstance` with:
   - CLSID `00028B07-0000-0000-C000-000000000046`
   - IID   `00028B08-0000-0000-C000-000000000046`
3. on the resulting helper object, calls method `+0x24` with:
   - service name `"MEDVIEW"`
   - IID `00028B71-0000-0000-C000-000000000046`
   - out pointer for a service object
   - flags `0x1400800a`
4. obtains another object from the service object
5. pulls an async waiter / notifier object from that
6. waits on it with:

   `FUN_7e843dcb(local_c, 30000, 0xffffffff)`

#### Related GUID block in `MVTTL14C`

Near the attach IID there is a contiguous GUID cluster:

- `00028B60`
- `00028B61`
- `00028B70`
- `00028B71`
- `00028B72`
- `00028B73`

Only `28B71` is referenced directly in `hrAttachToService`, but the adjacent
family strongly suggests another media-view selector/IID block, analogous to
the previously recovered DIRSRV family `28B25..28B2E`.

### 7. The 30-second wait matches the live symptom exactly

`FUN_7e843dcb` (`0x7e843dcb`) polls the async object every 100 ms.

It treats HRESULT `-0x74f4fff7` as "still pending" and loops until either:

- the call completes with another status, or
- the supplied timeout expires

In the `hrAttachToService` call site, the timeout is **30000 ms**.

This matches the live run very closely:

- first click opens a new `DIRSRV` pipe after launch
- then there is about half a minute of no meaningful traffic
- then the UI eventually reports service unavailable

The best current hypothesis is:

- the async attach object never transitions out of the pending HRESULT
- after ~30 seconds `hrAttachToService` returns failure
- `TitleConnection` maps that failure to generic `...07d1`
- `MOSVIEW` converts that into the service-unavailable dialog

### 8. Static interpretation of the remaining server gap

The earlier runtime traces showed:

- `MSN Today` click can now reach `MOSVIEW`
- a fresh post-launch `DIRSRV` pipe opens
- but the server never sees the meaningful follow-up RPC that should satisfy
  the media attach path

Combined with the `MVTTL14C` analysis above, that strongly suggests the real
missing piece is **not** the old shell-tree metadata anymore.  It is some
initial media-view service/interface attach flow that our current discovery /
selector catalog does not satisfy.

Most concrete candidate:

- publish or otherwise support the `00028B71` / likely `00028B72` media-view
  interface family in the relevant service map (very possibly still under the
  transport's `DIRSRV`-backed attach path)

### 9. Recommended next RE steps

1. Inspect `MVTTL14C` around the service-object method invoked after the
   `00028B71` attach to recover the exact async object semantics and the error
   codes it returns.

2. Trace where `00028B72` is used in `MVTTL14C` (likely via vtable/QueryInterface
   paths rather than a direct static GUID reference).

3. Revisit the server's interface discovery catalogs with the new media-view
   family in mind:
   - `00028B71`
   - probably `00028B72`
   - possibly the broader nearby cluster `28B60/61/70/71/72/73`

4. Correlate the new IIDs with the post-launch `DIRSRV` pipe (`pipe 8`) seen
   on the wire, because that pipe is the most likely runtime manifestation of
   `hrAttachToService("MEDVIEW", IID 28B71, ...)`.

### Operational handoff state

At the end of this session:

- the Win95 VM was restarted with:

  `QT_QPA_PLATFORM=xcb 86Box_dbg -P "/home/gabriels/86Box VMs/Windows 95/" -R "/home/gabriels/projetos/86BoxROMs/"`

- the guest CPU was resumed with:

  `python3 tools/gdb_debug.py batch "resume"`

- live 86Box process observed:
  - `pid 94090`
  - command `86Box_dbg -P /home/gabriels/86Box VMs/Windows 95/ -R /home/gabriels/projetos/86BoxROMs/`

- no useful breakpoints should be assumed active for handoff

- the dial-up server log still reports:
  - `[*] MSN dial-up server listening on 0.0.0.0:2323`

The practical next-session starting point should be:

1. verify the server is still actually listening on `:2323`
2. if needed, relaunch it in a persistent attached session rather than a
   shell-backgrounded process
3. continue from the `MVTTL14C!hrAttachToService` / `00028B71` attach path
   rather than the older shell-tree-property analysis

## 2026-04-13 — Course correction on the DIRSRV-tree hypothesis

Critical re-read of the previous two journal entries showed the chain
`MSN Today click → MOSVIEW launch → 30 s wait on MEDVIEW IID 28B71` was
reached by **feeding the client invented data**, not by tracing the real
dispatch path.  Reverting that scaffolding now to keep the foundation honest.

### What is being kept (sound static evidence)

- `MOSSHELL.CMosTreeNode::GetShabbyViaFtm` (`0x7f3fd800`) calls
  `HrFtmDownloadWithUI("DIRSRV", ...)` — confirms MOSSHELL is a DIRSRV
  consumer.
- `TREENVCL.CTreeNavClient` ctor (`0x7f63113d`) does
  `CoCreateInstance(CLSID 28B07, IID 28B08)` then resolves IID **28B27** —
  this is the only DIRSRV IID confirmed as actually requested.
- Adjacent GUID family `28B25..28B2E` exists at `0x7f633250` in TREENVCL
  but only `28B27` has been seen in use.  Memory adjacency is **not**
  evidence the others are needed.
- `MVTTL14C.hrAttachToService` (`0x7e844114`) waits 30 s on IID `28B71`
  for service `MEDVIEW`; `FUN_7e843dcb` polls every 100 ms for HRESULT
  `-0x74f4fff7` ("still pending").  This explains the 30-second timeout
  symptom **whenever** MOSVIEW is actually launched, regardless of how it
  got launched.
- App registry table from `win95_c.raw`:
  - app 1 = `dsnav.nav` (Directory_Service)
  - app 3 = `guidenav.nav` (Guide_Service)
  - app 4 = `mosview.exe` (Media_Viewer)  *(unverified id)*
  - app 5 = `WhatsNew` — friendly name only, **no Filename entry** in the
    raw dump.  In this client build app 5 is registered but unlaunchable.
  - app 7 = `dnr.exe` (Down_Load_And_Run)
- `MCM.HRMOSExec` (`0x041020d8`) builds command line
  `<Filename> -MOS:<app_id>:<node_hi>:<node_lo>:<type> <ri>` and calls
  `CreateProcessA`.
- `MOSVIEW.FUN_7f3c1053` parses `-MOS:` args; for type `2` it eventually
  calls `MVCL14N.MVTitleConnection` which loads `MVTTL14C.DLL` and calls
  its `TitleConnection` export.

### What is being reverted (speculative scaffolding)

1. `DIRSRV_NODES` tree in `server/services/dirsrv.py` — the hardcoded
   `0:0 → 0:4456508 (MSN Central) → [5 icon children]` structure was
   invented.  `sub_id` values, `app_id` assignments (MSN Today→6,
   E-Mail→3, Favorite Places→1, Member Asst→13, Categories→3), and the
   `b=0x01 for folders / 0x00 for non-folders` rule had no static evidence.
   The only "validation" was that the symptom changed from "Cannot open
   service" → "service not available after 30 s", which is what would
   happen for any forced MOSVIEW launch with a missing MEDVIEW service.
2. Tests `test_msn_central_children_include_shell_icons` and
   `test_msn_central_children_expose_exec_metadata` — these pinned the
   invented tree as expected behavior.
3. Selector-map expansion to `28B25..28B2E` (selectors `0x01..0x0A`).
   Reverted to single `(28B27, 0x01)` to match the only IID actually
   resolved at runtime; reshaping selector numbering for unverified IIDs
   risks breaking future runtime behavior the server has not been
   exercised against.

### What is being kept (instrumentation)

- `DirsrvRequest.node_id_raw` field (`server/models.py`) — useful for
  observing the wire bytes of the 8-byte `_MosLid64`.
- Extended `decode_dirsrv_request` doc + raw capture in `server/mpc.py`.
- Improved `[DIRSRV] node=… raw=…` log line in
  `server/services/dirsrv.py`.
- `test_guid_records_match_catalog` (replaces the rigid
  `payload[16] == 0x01` assertion with a loop over the catalog) — works
  for any catalog size and is strictly better.

### Why the "progress" was misleading

The original "Cannot open service" error happened with **no DIRSRV query
for `0:4456508`** in the trace — that node only got queried after
`DIRSRV_NODES` was populated to advertise it as a child of `0:0`.  So the
node-not-found cache miss the live BP captured at `FUN_7f3fb9f5` was on
something else (probably a node returned by `GUIDENAV.GETPMTN` for the
JUMP target, whose property cache nobody ever populates because GUIDENAV
overrides `GetProperty` instead of seeding the cache).

The `c=6` patch then forced HRMOSExec to launch `mosview.exe`, which then
necessarily hit the 30-second `hrAttachToService` wait because the server
serves no MEDVIEW.  Both effects are downstream of the invented tree, not
evidence the tree is right.

### Real next steps

1. **Verify icon source.**  Set a one-shot HW BP on
   `GUIDENAV.FUN_7f5123ce` (HOMEBASE icon-table loader, `0x7f5123ce`).
   If it fires during home-view rendering, the 5 icons are sourced from
   the HOMEBASE custom resource and the previous-session memory is
   correct — DIRSRV is **not** the icon source.
2. **Capture the cache miss in detail.**  Re-arm the BP on
   `0x7f3fb9f5` and dump full registers + the first 8 stack dwords.
   `ECX` (the `this` for `CPropertyCacheElt`) and the return address tell
   us which node owns the empty cache and what code path is asking.
3. **Trace the JUMP dispatch.**  HOMEBASE action `LJUMP 1:4:0:0` for
   MSN Today routes to GUIDENAV (field_0=1).  Step through
   `GUIDENAV.GETPMTN(1:4:0:0)` and the subsequent `ExecuteCommand` to
   see who reads `c` and from where; that is what `c` should actually be
   for MSN Today (rather than guessing 5 vs 6).
4. **Only then** decide whether MEDVIEW + IID 28B71 needs server support.
   That work is real and will be needed if MSN Today's real path goes
   through MOSVIEW — but not before the dispatch architecture is
   understood.

## 2026-04-14 — MSN Today click root cause pinned: DSNAV node, 'b' bit 3

Live SoftICE session (VT100 serial bridge) while stopped inside Explorer at
`ExecuteCommand` entry confirmed the exact failure point. Prior sessions had
speculated about GUIDENAV overrides, HrBrowseObject, and
`CMosTreeNode::GetProperty`'s cache-miss fallback at `0x7F3FCF03`; all were
wrong. The dialog originates from the **outer guard at the top of
`CMosTreeNode::ExecuteCommand` itself**.

### Trace of one click

1. Click MSN Today → `MOSSHELL.CMosTreeNode::ExecuteCommand` (0x7F3FF693)
   entered with `this = 0x00BE06DC`, `cmd = 0x3000` (default open),
   `param_4 = IShellBrowser (0x004414AC)`, return = 0x7F512860 (GUIDENAV JUMP
   dispatcher).
2. Outer guard at 0x7F3FF6CB issues `vt[0x40]("b", &byte, 1, 0)` on `this`.
3. Guard reads byte, `TEST byte [ESP+0x13], 0x8` — **bit 3 is set**, so
   `JZ 0x7F3FF701` is NOT taken.
4. Falls through to 0x7F3FF6E4 `MOV [ESP+0x14], 0x8B0B0041` (local_14
   overwritten with MSN error code).
5. `CALL 0x7F3FA1DA` = `ReportMosXErr`. HRESULT at `*arg1` confirmed
   `0x8B0B0041`. Caller return `0x7F3FF6F8` (right after the CALL).
6. `ReportMosXErr` internally calls `ReportMosXErrX` (0x7F3FA179) which
   displays the "Cannot open service." dialog — hosted by Explorer.

Both `ReportMosXErr` and `ReportMosXErrX` BPs fired; HrBrowseObject (0x7F3FA76C)
BP did NOT fire. So the switch body for case 0x3000 never runs.

### The object is DSNAV, not GUIDENAV

`this = 0x00BE06DC` has vtable `0x7F586020`. That vtable lives in
**DSNAV.NAV** (SoftICE reports `DSNAV!.text+1E5C` for the thunks at
`0x7F582E5C+`). DSNAV's vtable is populated with import thunks that forward
to MOSSHELL exports:

- slot 15 (+0x3C) → `JMP [0x7F589494]` → `0x7F3FCE12` (MOSSHELL FindProperty)
- slot 16 (+0x40) → `JMP [0x7F589490]` → `0x7F3FCE71` (MOSSHELL GetProperty)

So DSNAV does **not** override the property accessors; it uses MOSSHELL's
generic `GetProperty` which in turn calls `FindProperty` (cache search) +
`FUN_7F3FB9F5` (read by index). For MSN Today, `FindProperty("b")` succeeded
(guard's HRESULT was 0 at 0x7F3FF6D4), so 'b' *is* in the DSNAV node's
property cache — with bit 3 set.

The node fields after the vtable pointer are `field_0=2, field_1=0,
field_2=0, field_3=0` (all dwords). This differs from the GUIDENAV small-node
`(1:4:0:0)` encoding. DSNAV and GUIDENAV use the same MOSSHELL base class
but live in different module trees.

### Correction to prior understanding

- Prior memory held that GUIDENAV's `vt[0x10]` override returns 'b'=0x02 for
  every node (bit 3 clear) and that the "Cannot open service" error was
  therefore the GetProperty cache-miss fallback. **That memory was about the
  wrong module.** MSN Today click never enters GUIDENAV from the user's
  click; it enters DSNAV directly.
- Prior memory called slot 16 "GetPropertyFromHost". Its real name is just
  `GetProperty` (0x7F3FCE71). The confusion came from inspecting GUIDENAV's
  override side only.

### The actual question now: who sets 'b' bit 3 on the DSNAV node?

The 'b' byte is cached on the DSNAV node before the click. Bit 3's semantics
per the ExecuteCommand guard are "non-browsable / must not be opened via
this path." Server-side, `server/services/dirsrv.py` returns all-zero
properties except `q=1` for non-children requests — so DIRSRV is NOT putting
bit 3 in 'b'. Candidates:

- DSNAV seeds its own property cache at node construction with some default
  `b` value (possibly reading from a HOMEBASE-like resource / service map).
- A different service writes 'b' into the cache — `MCM` / `MOSAF` / the
  catalog GUID family are candidates.
- The 'b' cache value was copied from a parent node whose 'b' should have
  been different.

### Next steps

1. Import `binaries/DSNAV.NAV` into the Ghidra project (not currently
   imported — only GUIDENAV.NAV is). Base 0x7F580000 at runtime.
2. Find the DSNAV code path that creates/populates the MSN Today node's
   property cache. Specifically: where it calls the MOSSHELL `AddProperty`
   equivalent for 'b' (or the setter exposed via the import table).
3. Re-click with a live BP at 0x7F3FF6D6 (TEST byte) and read the actual
   byte value to confirm the exact `b` (not just "bit 3 set"). Then walk
   back to see the write.
4. Once the write site is known, decide whether:
   - the server needs to send a non-default 'b' for this node, or
   - the client needs a different upstream property (e.g. a missing parent
     'a'/'e' that would flip the DSNAV's default 'b' computation), or
   - this is the wrong click path entirely and the HOMEBASE 5-icon view
     should never dispatch MSN Today through DSNAV's
     `ExecuteCommand(cmd=0x3000)`.

### Why prior "real next steps" 1–3 were partly misdirected

The previous plan focused on GUIDENAV.GETPMTN and the
`FUN_7F3FB9F5` cache-miss return — both are real code paths, but neither
is on the failing click's hot path. GUIDENAV's JUMP dispatcher is in the
caller chain (return address = 0x7F512860 is inside GUIDENAV), but the
object that `ExecuteCommand` runs against is DSNAV's, not GUIDENAV's. The
outer-guard bit-3 check fails before any code that would touch GUIDENAV
overrides or `FUN_7F3FB9F5` for MSN Today's own data.

## 2026-04-14 — 'b' was "not-received", not "bit-3-set"; fix exposes MCM layer

### Live SoftICE BP nailed the real HRESULT

With `ADDR explorer` and BP at `0x7F3FF6D2` (TEST EAX after the GetProperty
vtable call — fires on both success and failure paths), the second MSN
Today click stopped with `EAX = 0x8B0B0041`. That's the COM-style
"property not received" return from MOSSHELL's FUN_7f3fb9f5 cache read
(returns 0x8B0B0041 when `this+8 == 0`), NOT a successful GetProperty
whose 'b' byte has bit 3 set.

So the outer guard in ExecuteCommand never reached its `TEST byte 0x8`
branch on first click — GetProperty itself failed, `iVar3 < 0` took the
`JL` at 0x7F3FF6D4 directly to the `MOV [ESP+0x14], 0x8B0B0041; CALL
ReportMosXErr` sequence. (The `TEST byte` is only executed on the second
click, for reasons we haven't yet traced — likely because one call path
seeds the cache as side-effect while the other doesn't.)

**Prior memory `project_msn_today_property_b_check.md` had the final
mechanism wrong.** It's not "bit 3 set on a successfully-returned 'b'";
it's "'b' never got written to the node's cache, GetProperty returns the
not-received sentinel."

### Why 'b' was empty: DIRSRV GetChildren reply had no properties

`server/services/dirsrv.py`'s pre-fix GetChildren branch for MSN Central's
children returned a 33-byte SVCPROP record with zero property entries
(just the header). The client accepted the reply, allocated DSNAV nodes
for each child, but populated nothing into their property caches. When
MSN Today's node got clicked, `GetProperty("b", …)` hit FUN_7f3fb9f5 →
`this+8 == 0` → 0x8B0B0041.

### Fix (shipped in this session)

Added `build_child_props(requested_props, title, children)` to
`server/services/dirsrv.py`. The children branch now populates every
requested property with a default value (`p` = title string, `c` = int,
`h` = 1, `b` = 0, etc.) and emits one `build_property_record` per child
node. Hardcoded node-id check removed (IDs aren't stable across sessions).

Live result: the "Cannot open service." dialog is gone. A new dialog
appears — "This task cannot be completed at this time.##Please try again
later." — which confirms we pushed past the outer 'b' guard and hit the
next layer.

### Static analysis of the new dialog

The new string lives at MCM.DLL `0x0411f9b2` (PE `/PascalUnicode`
STRINGTABLE, 68 chars, no direct xref). The `##` separator pattern is
the MosError dialog proc's convention (MCM `FUN_04103063`): the primary
text goes to dialog item 0x65, the secondary text (after `##`) to 0x66.

Dialog entry points in MCM (`MosErrorP → MosErrorExP → MosError`), plus
the common-error shim:

- `MosCommonError(hwnd, N)` — builds a param block with
  `text_id = N + 0x192` and calls `MosError`. The base `0x192` is the
  MCM STRINGTABLE resource ID for the first common-error string.
- MOSSHELL's `ReportMosXErr` (0x7F3FA1DA) dispatches HRESULTs:
  - `0x8B0B0041` → `iVar2 = 6` → `ReportMosXErrX(6, node)` → MosError
    with MOSSHELL STRINGTABLE entry at table-slot 6 (resource 0xB0,
    "Cannot open service.##This service is not available at this time.
    Please try again later." at MOSSHELL 0x7F41D0F8).
  - Many other 0x8B0B00xx codes → explicit `MosCommonError(hwnd, 1..10)`.
  - **Default fallback** (`LAB_7f3fa357`): `MosCommonError(hwnd, 0)` →
    MCM resource `0x192`. The observed "This task cannot be completed
    at this time." string is the best fit for this generic
    resource-0-based dialog.

### 'c' is app_id, not children-count — current server fix is semantically wrong

Decompiling `CMosTreeNode::Exec` (MOSSHELL `0x7F3FEBA6`):

```c
iVar3 = vt_GetProperty(this, "z", &pricing, 4, 0);  // pricing confirm
iVar3 = vt_GetProperty(this, "c", &app_id, 4, 0);
if (app_id == 7) {
    CreateOleWorkerThread(FUN_7f3fea8c, …);          // browser URL path
} else {
    vt_GetProperty(this, "x", &args, 0);              // cmdline args
    local_8 = HRMOSExec(app_id, args, …);             // MCM: CreateProcessA
}
```

`HRMOSExec(app_id, args, …)` (MCM `0x041020d8`):

1. `FGetNamesForApp(app_id, …)` reads `HKLM\SOFTWARE\Microsoft\MOS\
   Applications\App #<app_id>\{Filename, Friendly name}`.
2. If no registry entry → returns 0 silently (no dialog).
3. Else: builds cmdline, `CreateProcessA`. On failure:
   `LoadStringA(0x52a/0x52d/0x52e)` + `wsprintfA` + `MosErrorP(NULL,
   hInst, 0x529, formatted_text, 0)` — a custom MCM dialog, NOT the
   "This task cannot be completed" one.

`build_child_props` currently sets `c = children_count` for MSN Today
(`children=0`), so `HRMOSExec(0, …)` runs. With no `App #0` registry
entry, this path returns silently. **Therefore the dialog isn't coming
from HRMOSExec.** It's coming earlier — a `GetProperty("z" | "c" | "x")`
still returns 0x8B0B0041 for some property we haven't populated, OR the
shell post-processes Exec's return and maps it through `MosCommonError`.

### Next-steps shortlist

1. Correct `build_child_props` to set `c` semantically — an app_id, not
   a children count. Candidate values from journal context:
   - `c = 7` → browser worker thread (needs a URL as the associated
     string). Safe default if no real MSN Today app exists locally.
   - `c = 5` (Media_Viewer) / `c = 6` (MOSVIEW) per earlier probes, but
     only if the VM actually has `App #5` / `App #6` registered.
2. Verify MSN Central is labeled as a container (`h = 1` for the parent
   that's the 0:0 → MSN Central link, non-leaf), and MSN Today's
   `c/h` combination matches the child-leaf semantics the shell expects.
3. Populate `z` (pricing) and `x` (args) explicitly in the children
   reply to avoid any `GetProperty` miss on a subsequent click.
4. Live-trace (BP at 0x7F3FEC02 entry to `CMosTreeNode::Exec` + print of
   all GetProperty HRESULT returns) to confirm which property read still
   hits 0x8B0B0041 post-fix. Then either populate it server-side or
   satisfy the node via DSNAV's own property defaults.

### Corrections to prior entries

- **`project_msn_today_property_b_check.md`**: the "'b' bit 3 set" story
  is wrong. The real failure was 'b' not-received (cache flag 0 at
  `this+8`). Will update.
- **Journal "DSNAV seeds bit 3"** (earlier section): scrap that line of
  investigation. The DSNAV node's property cache was simply empty
  because our server never sent property records for its children.

## 2026-04-14 (later) — DIRSRV stable state: '0'-icon children, no OOM

### What was actually wrong with the empty-blob path

Walking the working state back from a regression chase: the original
DIRSRV reply for `('wv', 'tp', 'w', 'l')` and `'x'` sent type-0x0E blobs
with a 4-byte length prefix of `0`. SVCPROP delivers the blob to the
client's property cache as `(length=0, data=NULL_after_malloc(0))`.
MOSSHELL's `FUN_7f3fb9f5` (cache reader) treats `received_flag=1 &&
data_ptr==NULL` as `E_OUTOFMEMORY` (`0x8007000E`), which `ReportMosXErr`
maps to `MosCommonError(1)` → the "Out of memory" dialog.

Sending a **1-byte NUL payload** (length=1, data=`\x00`) makes the
client's `malloc(1)` return a non-NULL pointer; the cache slot is
considered valid and `GetProperty` returns the blob without tripping the
OOM check. This is the minimum-viable fix for those four blob props.

### `c` and the 8-byte mnid — what landed

`build_child_props(requested_props, title, *, is_container, c_value,
mnid_a)` in `server/services/dirsrv.py` now centralises:

- `'p'` = title as length-prefixed ASCII blob (visible icon label, root
  level — still renders as a literal `"0"` because that's the placeholder
  numeric form the shell uses when no proper Name is supplied; the
  actual title hasn't reached the icon label path yet).
- `'a'` = 8-byte mnid blob `pack('<II', 0x44000c-or-d, 0)` (formerly a
  DWORD 0). This is what `CMosTreeNode::GetNthChild` reads to construct
  the child node's mnid (`field_8`/`field_c`).
- `'b'` = 1-byte byte-tag (0x01) — `0x01` for containers, `0x00` for
  leaves. Browse-flags semantics: bit 0 = container, bit 3 = denied.
- `'c'` = registered MOS app_id DWORD, **not** child count. `1` =
  `Directory_Service` (DSnav containers), `7` = `Down_Load_And_Run`
  (browser-URL leaves; `CMosTreeNode::Exec` short-circuits to
  `CreateOleWorkerThread` for `c == 7`).
- `'h'` = DWORD 1/0 (container/leaf).
- `'x'`, `('wv','tp','w','l')` = length-1 NUL blob (see above).
- everything else = DWORD 0 catch-all.

A `node_table` keyed by wire `node_id` (`f0:f8` decoded from the 8-byte
`_MosLid64` `'a'` blob) selects `(title, is_container, c_value, mnid_a)`
per node. `0:0` → "Root" (container), `0:4456460`/`4456460:0` → "MSN
Central" (container), unknown ids default to "MSN Today" leaf.

### Observed behaviour (this session)

- Login completes; MSN Shell renders.
- MSN Central icon clicks open without "Out of memory" or "Cannot open
  service".
- Child icon shows the forbidden-circle "0" placeholder (no proper Name
  routed through to the listview yet).
- Double-click on the "0" icon navigates into an identical view (MSN
  Today's children = MSN Today recursively, since unknown ids fall back
  to that leaf).

### Regressions this session caused (and how they were resolved)

1. Promoting `'p'` from DWORD-0 (catch-all) to a length-prefixed title
   blob in the `not is_children` path → MSN Central stopped opening,
   "Out of memory" returned. Reverted that path to use the same
   `build_child_props` so types stay consistent.
2. Adding `name in string_blob_props` without defining the variable →
   `NameError` raised mid-DIRSRV-reply, killed the connection, surfaced
   as "task cannot be completed at this time". Removed the dead branch.
3. Reverted too far back to the committed code → `build_property_record([])`
   for children → "Cannot open service." Re-restored the
   `build_child_props` + `node_table` shape from the working snapshot
   in `~/.claude/projects/.../abfc885a-...jsonl` line 2139.

### Next steps (still open)

1. Route the title into the icon-view label so the child renders as
   "MSN Today" instead of "0". Decode of MOSSHELL's General-tab dialog
   procedure (template #101) is still pending — the wire-property → label
   mapping there will tell us which prop the listview reads.
2. Stop the recursive MSN-Today-under-MSN-Today behaviour. Either return
   no children for the leaf node, or route the `node_table` lookup off a
   real child id sent in the `'a'` mnid blob.
3. Once `c=7` actually runs, MSN Today should hand a URL to the browser
   worker thread (`CMosTreeNode::Exec` → `CreateOleWorkerThread(FUN_7f3fea8c)`).
   We don't yet populate the URL; expect the worker thread to fail
   silently or pop a custom MCM dialog.

## 2026-04-15 — Properties dialog strings render: SVCPROP type 0x0B wire format

Strings in the MSN Today Properties dialog now render correctly. Root cause
was a wrong wire encoding for type 0x0B — not an empty-blob / missing-flag
issue, and not fixable by changing cache reader paths.

### What the client actually does

`SVCPROP.DLL!FDecompressPropClntImpl @ 0x7f641592` parses a property
record as:

```
[total_size:u32][prop_count:u16] [type:u8][name:asciiz][value_data]…
```

`DecodePropertyValue @ 0x7f64143a` dispatches on `type`. For `0x0B` (and
`0x0A` when its 5th arg is non-zero), it calls `FUN_7f641328` — a
**flag-byte string decoder**, not a raw UTF-16 copy:

```c
byte flag = *value_data;
if (flag & 2) {                // empty
    *out_size = 0; *out_consumed = 1; return NULL;
}
if (flag & 1) {                // ASCII, widened in cache
    int n = lstrlenA(value_data+1);
    _Dst = malloc(n*2 + 2);
    for (each byte b) *w++ = (ushort)b;
    *out_size = n*2 + 2;
    *out_consumed = n + 2;     // flag + ascii + NUL
} else {                       // raw UTF-16LE
    size_t w = wcslen((wchar_t*)(value_data+1));
    _Dst = malloc(w*2 + 2);
    memcpy(_Dst, value_data+1, w*2 + 2);
    *out_consumed = w*2 + 3;   // flag + utf16 + wide NUL
}
```

Cache always stores UTF-16LE; the ASCII path is just a wire-size
optimisation for 7-bit strings.

### The bug we had

`server/services/dirsrv.py::_sz()` emitted bare UTF-16LE with no flag
byte: `s.encode('utf-16-le') + b'\x00\x00'`. For prop `e` = "MSN Today",
the client read the first byte `0x4D` ("M") as the flag, saw `flag & 1`,
went down the ASCII path, and `lstrlenA("\x00\x53\x00\x4E…")` returned 0
(first byte is NUL) — so the cache slot got `length=2, data=""`. Every
string prop landed as empty and the dialog fields fell back to
placeholders.

### Verified live with SoftICE

Set `BPX 0x7f3fc8f8` (entry of `CMosTreeNode::RememberProperty`, the
vtable-slot-3 cache writer called by `SetPropertyGroupFromPsp @ 0x7f3fc85a`).
`ADDR explorer` first — MOSSHELL maps into Explorer's context (shell
namespace extension host), not guide/moscp.

Before fix — stack args at BP entry, decoded via
`D esp l 20`:

```
ret=0x7F3FC8CB  this=0x00BE04D4  name=0x7F40E1E8("e")
data_ptr=0x00447234  length=2  type=0x0B
```

`D 00447234 l 2` → `00 00`. Two bytes of NUL — empty wide string. Matches
the ASCII-path-with-first-byte-NUL analysis above.

After fix (`_sz()` now emits `\x01 + ascii + \x00`):

```
data_ptr=0x00443100  length=20  type=0x0B
D 00443100 l 20 → 4D 00 53 00 4E 00 20 00 54 00 6F 00 64 00 61 00 79 00 00 00
```

Properly widened `"MSN Today\0"`. Dialog fields populate.

### Fix

```python
def _sz(s):
    """Type-0x0B flag-byte string: flag=0x01 ASCII (widened in cache)."""
    if not s:
        return b'\x02'                         # empty-string flag
    return b'\x01' + s.encode('ascii', errors='replace') + b'\x00'
```

PROTOCOL.md §9.4/§9.5 updated: 0x0B added to the type table with
full wire-format description; every dialog string prop
(`e, j, k, ca, tp, r, s, t, u, n, on, v, w, p`) retyped from `0x0E` blob
to `0x0B` string.

### Still open

- **Icon** on the MSN Today leaf still renders as the forbidden-`0` glyph.
  `g` prop is sent as DWORD 0 catch-all; shape of `g` on the wire for a
  real icon handle is not yet confirmed.
- **Context tab "Cannot open service"** (resource ID 0xDE) — unrelated
  to DIRSRV wire format. Factory call `param_2[4](4, 0)` at
  `FUN_7f401d81 @ 0x7f402098` returns failure. Triggered when the
  container/LCID-list branch activates (`local_18 != 0`), after the
  `y` vendor-id DWORD read succeeds. Fires twice — possibly
  PropertySheet init-twice or on-tab-switch re-init.
