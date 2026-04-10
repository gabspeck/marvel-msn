# MSN95 "Marvel" Wire Protocol Specification

**Status**: Derived from static reverse engineering and live runtime tracing of MSN95 client binaries (July 11, 1995) using Ghidra decompilation and a custom emulated server. Login flow confirmed working as of 2026-04-10.

## 1. Overview

The Microsoft Network (MSN) for Windows 95, internally codenamed "Marvel," uses a layered
protocol stack built around **MPC (Marvel Protocol Client)** — a COM-based RPC-like system
that communicates through named pipes with a local transport engine.

### Architecture

```
+------------------------------------------------------------------+
| Application Layer                                                |
|   MOSSHELL.DLL - Tree-based navigation (Explorer shell model)    |
|   CONFAPI.DLL  - Conferencing / chat (CConversation)             |
|   BBSNAV.NAV   - BBS / forums                                   |
|   FTMCL.EXE    - File transfer                                  |
+------------------------------------------------------------------+
| Content Layer                                                    |
|   MVTTL14C.DLL - Multimedia Viewer titles (WinHelp-derived HFS) |
|   MOSCOMP.DLL  - Content rendering                               |
+------------------------------------------------------------------+
| MPC Protocol Layer                                               |
|   MPCCL.DLL    - Marvel Protocol Client (COM DLL)                |
|     CLSID: {00028B07-0000-0000-C000-000000000046}                |
|     Interface: IMos (IUnknown + 9 custom methods)                |
|     Imports pipe I/O from MOSCL.DLL                              |
+------------------------------------------------------------------+
| MCM Session Layer                                                |
|   GUIDE.EXE    - Login manager, session lifecycle                |
|   SACLIENT.DLL - System administration client (users/groups)     |
|   MOSCL.DLL    - Low-level pipe and session primitives           |
+------------------------------------------------------------------+
| Transport Engine                                                 |
|   ENGCT.EXE    - "MOSEngine Chicago"                             |
|     Winsock (WSOCK32.DLL) for TCP/IP                             |
|     Named Pipes for local IPC                                    |
|     RAS (RASAPI32.DLL) for dial-up                               |
|     Shared memory arena (ARENA.MOS)                              |
+------------------------------------------------------------------+
| Connection Layer                                                 |
|   MOSCP.EXE    - Connection settings, modem, transport selection |
|     TAPI for telephony                                           |
|     X.25 PAD support (AUSTPAC, TELENET, MCI, AT&T)              |
+------------------------------------------------------------------+
```

## 2. Transport Layer (ENGCT.EXE)

ENGCT.EXE ("MOSEngine Chicago") is a standalone transport engine (483 functions) that
manages all network I/O. It communicates with MPCCL.DLL via named pipes and shared memory,
and with the remote server via Winsock TCP or serial/X.25.

### 2.1 Transport Modes

Configured via registry key `SOFTWARE\Microsoft\MOS\Transport`:

| Key | Default | Description |
|-----|---------|-------------|
| PacketSize | (from server) | Inbound packet buffer size |
| PacketOutSize | (from server) | Outbound packet buffer size |
| WindowSize | 16 | Sliding window size |
| AckBehind | 1 | Packets behind before forcing ACK |
| AckTimeout | 600 (ms) | ACK/retransmit timeout |
| ArenaSize | 0x40000 (256KB) | Shared memory arena size |
| LogTrace | 0 | Enable transport tracing |
| TransportPriority | — | Preferred transport mode |
| ModemSetting | — | Modem configuration string |

Two transport channels are initialized at startup:
- **"Select" / "BuiltIn"**: Primary transport
- **"Straight" / "BuiltIn"**: Fallback transport

### 2.2 Packet Format (Wire Frame)

Each transport packet has the following structure:

```
+-------+-------+---...---+----------+------+
| SeqNo | AckNo | Payload | CRC-32   | 0x0D |
| 1 byte| 1 byte| N bytes | 4 bytes  | 1 B  |
+-------+-------+---...---+----------+------+
```

- **SeqNo**: Sequence number, high bit set (value & 0x7F gives 7-bit seq, range 0-127)
- **AckNo**: Piggybacked ACK number (value & 0x7F), acknowledges received packets
- **Payload**: Byte-stuffed data (see §2.3)
- **CRC-32**: CRC-32 computed over all bytes before it (SeqNo + AckNo + Payload)
- **0x0D**: Packet terminator (carriage return)

Minimum packet size: 7 bytes (header + CRC + terminator, no payload).

**Special packet types** (identified by first byte):
- **'A' (0x41)**: ACK-only packet — carries no payload, just acknowledges receipt.
  CRC is computed via a 256-entry precomputed lookup table (fast path).
- **'B' (0x42)**: NACK/reset packet — signals retransmission needed.
  Byte 1 & 0x7F = last successfully received sequence number.

### 2.3 Byte-Stuffing (Character Escape)

The payload uses PPP-like byte-stuffing to escape control bytes. The escape
character is **0x1B (ESC)**. On the wire, any byte in the escape set is replaced
by a two-byte sequence `0x1B` followed by a digit character:

| Raw Byte | Wire Encoding | Meaning |
|----------|---------------|---------|
| 0x0B | `1B 33` | Vertical tab (control) |
| 0x0D | `1B 31` | Carriage return (packet terminator) |
| 0x10 | `1B 32` | DLE (data link escape) |
| 0x1B | `1B 30` | ESC (escape character itself) |
| 0x8B | `1B 36` | High control byte |
| 0x8D | `1B 34` | High control byte |
| 0x90 | `1B 35` | High control byte |

The receiver reverses the encoding: on seeing 0x1B, it reads the next byte
and maps `'0'→0x1B, '1'→0x0D, '2'→0x10, '3'→0x0B, '4'→0x8D, '5'→0x90, '6'→0x8B`.

### 2.4 CRC-32

Integrity checking uses a **custom CRC-32** with polynomial **0x248EF9BE** and a
256-entry lookup table (generated at runtime, stored in ENGCT.EXE .bss at
DAT_0571F810). The table generation uses a NOT twist on the XOR path:

```c
// Table generation (from FUN_05712db0)
for (int i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int j = 0; j < 8; j++) {
        if (c & 1) {
            c = ~(c ^ 0x248EF9BE);  // NOT after XOR
            c >>= 1;
        } else {
            c >>= 1;
        }
    }
    table[i] = c;
}

// CRC computation (from FUN_05712e18)
uint32_t crc = 0;  // init = 0, no final XOR
for (int i = 0; i < length; i++)
    crc = (crc >> 8) ^ table[(data[i] ^ (uint8_t)crc) & 0xFF];
```

**Important**: CRC is computed over the **wire bytes** (after header encoding and
payload byte-stuffing), not the raw/decoded bytes. On the wire, the 4-byte CRC
itself is masked using OR 0x60 (see §2.3.1).

### 2.4.1 Three-Zone Wire Encoding

A single packet uses three different encoding schemes depending on the field:

1. **Header bytes** (SeqNo, AckNo): XOR 0xC0 if value is in {0x8D, 0x90, 0x8B}
   (from FUN_05713172)
2. **Payload bytes**: 0x1B escape stuffing (see §2.3)
3. **CRC bytes**: OR 0x60 masking for any byte in the escape set
   {0x1B, 0x0D, 0x10, 0x0B, 0x8D, 0x90, 0x8B} (from FUN_05713125)

The CRC is computed over the already-encoded header and payload bytes (zones 1+2),
then the CRC bytes themselves are masked (zone 3) before being appended.

### 2.5 Sliding Window (Go-Back-N ARQ)

The transport implements a **Go-Back-N** automatic repeat request protocol:

- **Sequence space**: 7-bit (0–127), wraps with `(seq + 1) & 0x7F`
- **Window size**: Default 16 packets, negotiable down to 1
- **ACK piggybacking**: ACK number is always in byte 1 of data packets
- **Pure ACK**: Sent as type 'A' packet when no data is queued
- **Retransmit timeout**: 6000 ms watchdog timer
- **Max retransmissions**: 12 attempts before disconnect (status 0x20 = timeout)
- **Congestion control**: On each timeout, the window size is **halved**
  (`window = window >> 1; if (window == 0) window = 1`), then all unacked
  packets are retransmitted in order
- **AckBehind**: Forces an ACK after N packets received without one

### 2.6 Transport Parameter Negotiation

After connection establishment, the server sends a control frame (pipe data
with marker 0xFFFF, type 3) containing negotiated transport parameters:

```
+------------+------------+------------+------------+------------+------------+
| PacketSize | MaxBytes   | WindowSize | AckBehind  | AckTimeout | Keepalive  |
| uint32 LE  | uint32 LE  | uint32 LE  | uint32 LE  | uint32 LE  | uint32 LE  |
+------------+------------+------------+------------+------------+------------+
```

Each value is negotiated as the **minimum** of the server's offer and the
client's configured maximum. The Keepalive field is optional (present only if
the frame exceeds 0x18 bytes).

### 2.7 Pipe Multiplexing Within Packets

A single transport packet can carry data for multiple logical pipes. The payload
(after byte-unstuffing) contains a sequence of pipe frames:

```
+----------+----------+--------...--------+
| PipeHdr  | DataLen  | PipeData          |
| 1 byte   | 0-1 byte | DataLen bytes     |
+----------+----------+--------...--------+
```

**PipeHdr byte** (after VLI decode):
- Bits 0–3: Pipe index (0–15, up to 16 simultaneous pipes)
- Bit 4 (0x10): "has length" flag
- Bit 5 (0x20): "continuation" — more fragments follow for this pipe
- Bit 6 (0x40): "last data" flag — final fragment for this message

**DataLen byte** (if present): payload length for this pipe frame (& 0x7F).

**Control frames** are identified by pipe data starting with `0xFF 0xFF`:

| Type (uint16) | Description |
|---------------|-------------|
| 1 | Connection request (contains session parameters) |
| 3 | Transport parameter negotiation (see §2.6) |
| 4 | Connection establishment/teardown signal |

### 2.8 Shared Memory Arena

- **ARENA.MOS**: File-mapped shared memory region, default 256KB (configurable
  via `ArenaSize` registry value). Used for large data exchange between
  ENGCT.EXE and client processes.

### 2.9 MosSlot (IPC Mailslot)

MosSlot is a shared memory IPC mechanism (total size: **0xC546 bytes**):

```
Offset  Size    Description
0x0000  4       Free list head pointer (offset into data region)
0x0004  2       Reference count
0x0010  0x540   Slot directory (48 entries × 0x1C bytes each)
0x0546  0xC000  Data region (48 slots × 1024 bytes each)
```

- Protected by a named mutex "**MosArena**"
- Named memory mapping: "**MosSlot**"
- Slots form a **linked free list**: each slot's first 4 bytes point to the
  next free slot (or -1 for the last)
- Up to 48 concurrent IPC messages, each up to 1KB

### 2.10 Named Pipe Transport (X25PIPE)

ENGCT.EXE creates named pipes for local IPC with MPCCL.DLL:

- **Pipe name base**: `X25PIPE`
- Default buffer size: 512 bytes
- Max instances: 8
- Server mode: `PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED`
- Message mode: `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE`
- Client mode: `GENERIC_READ | GENERIC_WRITE`, `FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING`

### 2.11 Async I/O Architecture

ENGCT.EXE uses **overlapped I/O** exclusively — `ReadFile`/`WriteFile` with
`OVERLAPPED` structures rather than Winsock `send()`/`recv()`. This provides
a unified I/O model for both TCP sockets and named pipes.

The I/O thread uses **double-buffered reads**: two read buffers alternate
(`local_c = 1 - local_c`) so a new read is posted before the previous one
is processed.

### 2.12 Winsock Integration

- Window class: `"ENGCT Winsock Response Window"` — hidden message-pump window
- Custom messages: **0x550** and **0x551** for WSAAsyncSelect notifications
- HIWORD(lParam) carries the Winsock error code
- Error 0x2747 (WSAEWOULDBLOCK) is treated as non-error
- On receive: events signal the I/O thread via `SetEvent`

### 2.13 Network Transports

- **TCP/IP**: Via WSOCK32.DLL (ordinal imports: socket, connect, closesocket,
  ioctlsocket, htons, htonl, gethostbyname, WSAAsyncSelect, WSAStartup,
  WSACleanup, WSAGetLastError, WSACancelAsyncRequest)
- **Named Pipes**: Local IPC via `X25PIPE` (see §2.10)
- **RAS**: Dial-up via RASAPI32.DLL (RasDial, RasHangUp, RasGetConnectStatus,
  RasGetErrorString, RasEnumEntries)
- **MosSlot IPC**: Inter-component communication via `MOSCL.MOS` channel name

### 2.14 Transport Channel Object (0x350 bytes)

```
Offset  Size  Field
0x000   4     Vtable pointer (16 methods)
0x004   16×4  Pipe slot pointers (16 pipes)
0x084   12    Pipe array metadata (base/count/pointer)
0x0AC   4     Send window start position
0x0B0   4     Unacknowledged packet count
0x0B4   4     Window size (negotiated)
0x0B8   4     Base sequence number (7-bit)
0x0BC   4     Negotiated PacketSize
0x0C0   4     Max window size (configured)
0x0C8   4     Max bytes per send
0x0CC   4     Negotiated max bytes
0x0D0   4     AckBehind
0x0D4   4     AckTimeout (ms)
0x0D8   4     Expected receive sequence number
0x0DC   4     Negotiated window size (from server)
0x0E0   4     Last ACK position
0x0EC   4     Timer handle
0x0FC   4     Send buffer array pointer
0x100   4     Current send buffer
0x160   24    CRITICAL_SECTION
0x178   4     Connection state (0=waiting, 1=active, 2=closing, 3=IPC wait, 6=reconnect)
0x184   4     File/socket handle
0x188   4     Transport type (0=pipe server, 1=pipe client, 3=named pipe, 7=TCP)
0x1F0   4     MosSlot handle
0x224   4     Packet header size (= 4)
0x23C   4     Last sent sequence number
0x25C   var   Statistics/timing data
0x280   4     Round-trip time (ms, from GetTickCount)
0x2B0   4     Pending handshake flag
0x2C4   4     Retransmission counter (reset on ACK, disconnect at 12)
0x2C8   4     Send-in-progress flag
0x2CC   4     Send pump state
0x2D4   4     Force NACK flag (triggers 'B' packet)
0x2D8   4     Connection reset flag
0x2E0   4     Duplicate detection
0x2E4   var   Timer structure
```

### 2.15 File Naming

- `%08lx.MOS`: MOS data files (hex-numbered)
- `MOSCL.MOS`: Core MOS client data / IPC channel name

## 3. Connection Layer (MOSCP.EXE)

### 3.1 Modem Initialization

- AT command string: `AT&C1E0W2S46=136`
- `EnableAbove19200`: High-speed modem support flag
- TAPI integration: `lineOpen`, `lineMakeCall`, `lineClose`, etc.

### 3.2 Modem Connection State Machine

MOSCP.EXE implements a multi-state modem connection handler (FUN_7f457f1c):

```
State 0: Send "AT" init command (timeout 5s)
State 1: Wait for OK, send modem settings (timeout 2s)
State 2: PurgeComm, send "ATDT" + phone number (timeout 100s)
State 4: Parse modem response:
           "CONNECT NNNNN" → connected (parse baud rate, goto State 6)
           "BUSY"          → error: busy signal
           "NO DIAL"       → error: no dial tone
           "NO CARRIER"    → error: no carrier
State 6: Post-CONNECT server handshake (timeout 20s)
           → Client sends 0x0D (CR) to server
           → Strips leading 0x8D/0x0A/0x00/0x8A from response
           → Pattern-matches server's first message (see §3.5)
State 8: X.25 PAD parameter exchange (timeout 10s)
State 10/11: X.25 login prompt handling (timeout 15s)
```

**Baud rate detection** from CONNECT response:

| Baud | Code | Bytes/sec |
|------|------|-----------|
| 1200 | 0x0E | 150 |
| 2400 | 0x0F | 300 |
| 4800 | 0x10 | 600 |
| 9600 | 0x11 | 1200 |
| 12000 | — | 1500 |
| 14400 | 0x12 | 1800 |
| 16800 | 0x14 | 2100 |
| 19200 | 0x15 | 2400 |
| 21600 | 0x16 | 2700 |
| 24400 | 0x17 | 3050 |
| 26400 | 0x18 | 3300 |
| 28800 | 0x19 | 3600 |
| 57600 | 0x1A | 7200 |

The baud rate ÷ 8 is stored as the throughput limit for the transport
rate limiter (see §2.11).

### 3.3 X.25 PAD Support

MSN95 supported connecting through X.25 packet-switched networks.

**Network detection** (text pattern matching on received data):

| Pattern | Network | Type |
|---------|---------|------|
| `AUSTPAC:` | AUSTPAC (Australia) | 5 |
| `TELENET` | Telenet (USA) | 4 |
| `Welcome to MCI's Global Network Service` | MCI | 3 |
| `WELCOME TO AT&T INFORMATION ACCESS` | AT&T | 2 |
| `Please Sign-on:` | Generic | 2 |
| `please log in:` | Generic | 3 |

**X.25 PAD Login Sequence**:

```
1. Modem connects to X.25 PAD
2. Client detects network banner
3. PAD prompt detected ("." character)
4. Client sends X.3 PAD parameters:
     set 2:0\r    (echo off)
     set 5:0\r    (no flow control)
     set 12:0\r   (no XON/XOFF)
     set 15:0\r   (no editing)
5. Terminal identification requested:
     → Client sends "microsoft" (or custom terminal ID from config)
     → 500ms delay before sending
6. Login prompt detected:
     "Please Sign-on:" / "please log in:" / "user name:"
     → Client sends username
7. If "YOUR AREA CODE AND LOCAL EXCHANGE..." prompt:
     → Client sends area code + exchange info
8. Connection established
```

**PAD Errors** (retry up to 3 times):
- `ILLEGAL ADDRESS`, `NOT REACHABLE`, `REJECTING`, `CONGESTION`,
  `NOT OPERATING`, `NOT PERMITTED`

### 3.4 Connection States

The connection handler tracks two key state fields:

**Main state** (`this+0x2F8`) — controls the state machine switch:
```
State 0:  Send AT init
State 1:  Wait for OK
State 2:  Send ATDT + dial
State 4:  Wait for CONNECT/BUSY/NO CARRIER
State 6:  Post-CONNECT: waiting for server's first message
State 8:  X.25 PAD parameter exchange
State 10: X.25 login prompt handling (waiting for prompt)
State 11: X.25 login data exchange (waiting for response)
```

**Transport mode** (`this+0x178`) — set after handshake:
```
0: Pre-transport (modem/X.25 negotiation in progress)
1: Direct transport — all received data forwarded to ENGCT via vtable[3]
2: Error / disconnecting
```

**Network type** (`this+0x340`) — detected from server banner:
```
0: Default (direct modem)
1: X.25 PAD (after PAD prompt detection)
2: AT&T / "Please Sign-on:" network
3: MCI / "please log in:" / "user name:" network
4: TELENET
5: AUSTPAC
```

### 3.5 Post-CONNECT Server Handshake (State 6)

After modem CONNECT, MOSCP sends a single 0x0D (CR) byte to the server via
the modem, then enters State 6 (FUN_7f457e55). In State 6, it waits up to
**20 seconds** (5 seconds for AUSTPAC) for the server's first message.

The server's first bytes are pattern-matched to determine the transport mode:

| Server sends | Match length | Action |
|-------------|-------------|--------|
| `COM` | 3 bytes | **Direct transport mode** → `this+0x178 = 1`, data forwarded to ENGCT |
| `CONNECT` | 7 bytes | Re-enter State 6 (secondary CONNECT handling) |
| `@` (0x40) | 1 byte | X.25 login trigger → sends username |
| 0xA3 | 1 byte | X.25 PAD mode → sends PAD parameters, transitions to State 8 |
| `Please Sign-on:` | 15 bytes | Network type 2, sends username |
| `please log in:` | 14 bytes | Network type 3, sends username |
| `user name:` | 11 bytes | Network type 3, sends username |
| `and press RETURN:` | 18 bytes | Network type 3, sends username |
| `TERMINAL ` | 9 bytes | Terminal ID mode |
| `please type your terminal identifier` | 36 bytes | Sends terminal ID |
| `TELENET` | 7 bytes | Network type 4 (TELENET) |
| `AUSTPAC:` | 8 bytes | Network type 5 (AUSTPAC), sends username |
| `WELCOME TO AT&T INFORMATION ACCE...` | 20+ bytes | Network type 2 (AT&T) |
| `Welcome to MCI's Global Network S...` | 41 bytes | Network type 3 (MCI) |

**For direct dial-up (non-X.25) connections, the server must respond with
"COM" to trigger transport mode.** Without this, MOSCP remains in State 6
until the 20-second timeout expires, resulting in a connection failure.

Once "COM" is matched, MOSCP:
1. Sets transport mode to 1 (direct)
2. Initializes the ENGCT transport pipe (writes 0xFF 0xFF 0x04 to pipe)
3. Notifies GUIDE.EXE of connection state change (event code 2)
4. All subsequent data from the modem is forwarded to ENGCT

The complete server-side handshake for direct connections:
```
Client → Server: 0x0D                        (CR, "I'm ready")
Server → Client: "COM\r"                     (trigger direct transport)
Server → Client: [ENGCT transport params]    (§2.6 negotiation packet)
```

### 3.6 Registry

- `SOFTWARE\Microsoft\MOS\Connection`: Connection settings
- `SOFTWARE\Microsoft\MOS\Transport`: Transport settings

## 4. MPC Protocol Layer (MPCCL.DLL)

### 4.1 COM Architecture

MPCCL.DLL is a COM in-process server:

- **CLSID**: `{00028B07-0000-0000-C000-000000000046}`
- **Interface**: `IMos` (extends IUnknown with 9 custom methods)
- **Class Factory**: Standard `IClassFactory` implementation
- **Error facility**: Custom HRESULT facility `0xB0B` (e.g., `0x8B0B0017` = bad password)

### 4.2 Session Lifecycle

```
FMCMOpenSession(connectionInfo, &sessionHandle)
  → session handle (WORD, -1 = invalid)
  → FGetConDetails(sessionHandle, &details)
  
OpenMOSPipeWithNotifyEx(session, serviceVersion, "U"+serviceName,
                         readCallback, context, writeCallback, timeout)
  → pipe handle (SHORT, -1 = error)

... communicate with service via ReadMOSPipe / WriteMOSPipe ...

CloseMOSPipe(pipeHandle)
MCMCloseSession(sessionHandle, flags)
```

### 4.3 Connection Info Structure

Size: 0x174 (372) bytes. Key fields:
- **pszUserId**: User ID string (max 65 chars)
- **pszPassword**: Password string (max 17 chars)  
- **pszPhoneNumber**: Phone number string (max 128 chars)
- Additional connection parameters

### 4.4 Service Discovery

Services are addressed by **name** and **version**:

- Service name is prefixed with `U` (0x55) byte before pipe open
- Default timeout: 5699 (0x1643) — matches MSNVER.TXT version number
- Errors:
  - 0x1F: Service not found (`Unable to locate service '%s'`)
  - 0x21: Version mismatch (`Unable to locate service '%s' because of version mismatch`)

### 4.5 MOSCL.DLL API (Session and Pipe Primitives)

MOSCL.DLL provides all low-level session management and pipe I/O functions.
MPCCL.DLL imports these via its IAT. See §7 for full implementation details
(object layouts, MosSlot IPC protocol, ARENA.MOS shared memory). API surface:

```c
// === Session Management ===

// Open a new session with credentials
BOOL FMCMOpenSession(CONNECTION_INFO* connInfo, WORD* sessionHandle);

// Establish transport connection (dial/TCP/X.25)
BOOL FMCMMakeCall(WORD sessionHandle);

// Cancel in-progress connection attempt
BOOL FMCMCancelCall(WORD sessionHandle);

// Close session and release resources
void MCMCloseSession(WORD sessionHandle, DWORD flags);

// Check if currently connected
BOOL FAmIOnline(void);

// Get connection details after successful connect
BOOL FGetConDetails(WORD sessionHandle, void* details);

// Get last MCM error code (see §6)
UINT GetLastMCMError(WORD sessionHandle);

// Wait with message pump (allows UI to remain responsive)
DWORD MsgWaitForSingleObject(HANDLE handle, DWORD timeout);

// === Pipe I/O ===

// Open a pipe to a named service with async notification callbacks
SHORT OpenMOSPipeWithNotifyEx(
    WORD sessionHandle,
    DWORD serviceVersion,
    LPCSTR serviceName,      // "U" + service name
    PIPE_READ_CALLBACK readCb,
    LPVOID context,
    PIPE_WRITE_CALLBACK writeCb,
    DWORD timeout             // default 5699
);

// Read data from pipe (synchronous)
UINT ReadMOSPipe(SHORT pipeHandle, LPVOID buffer, UINT size, DWORD flags);

// Write data to pipe (returns -2 for async pending)
INT WriteMOSPipe(SHORT pipeHandle, LPVOID buffer, LPVOID data, UINT size, DWORD flags);

// Get pending read size
UINT GetMOSPipeReadSize(SHORT pipeHandle, DWORD flags);

// Close pipe
void CloseMOSPipe(SHORT pipeHandle);

// Get last pipe error
UINT GetMOSLastError(WORD sessionHandle);
```

### 4.6 Host Block Format (Wire Message)

Every message read from the pipe ("Host Block") has this structure:

```
+--------+--------+---------------------+------------------+
| Byte 0 | Byte 1 | Request ID (VLI)    | Payload          |
|selector| opcode | (1-4 bytes)         | (variable)       |
+--------+--------+---------------------+------------------+
```

Earlier notes in this document referred to Byte 1 as generic "flags," and later
as the selector byte. That is incorrect for the MPCCL paths currently traced.
For normal service traffic:

- **Byte 0** is the one-byte selector used to route a message to the correct
  opened-service wrapper
- **Byte 1** is the per-request opcode / method id used to match a reply to the
  concrete request object

**Variable-Length Integer (VLI) encoding** for Request ID:

The first byte's top 2 bits determine the field length:

| Bits 7-6 | Length | Max Value   | Encoding                           |
|----------|--------|-------------|------------------------------------|
| 00       | 1 byte | 63          | `byte & 0x3F`                      |
| 10       | 2 bytes| 16,383      | `(b[0] & 0x3F) << 8 | b[1]`       |
| 11       | 4 bytes| 1,073,741,823| `(b[0..3]) & 0x3FFFFFFF`          |

This is similar to ASN.1 BER length encoding.

**Message dispatch** (confirmed via Ghidra decompilation of MPCCL.DLL):

`DispatchMosPipeReadEvent` (0x0460307d) is the entry point for all incoming
pipe data.  It calls `ParseHostBlockFromPipe` to parse the header, then routes:

- **Byte 0 == 0x00**: service-discovery block
  - Routed to `LoadServiceInterfaceSelectorMap` which populates the
    IID→selector lookup table
  - For `LOGSRV`, this is the post-open block that maps interface IIDs
    (e.g., `{00028BC2-...}`) to one-byte selectors (e.g., `0x06`)
- **Byte 0 != 0x00**: service reply — three-level routing:
  1. **Byte 0** (service selector): looked up in the session-level service
     handler map (`connection+0x6c→0x4c`) via `FUN_046086b6`.  This map was
     populated during service registration with selectors from the discovery
     block.  If not found, the reply is **silently dropped**.
  2. **VLI request ID**: extracted from the header, looked up in the service
     handler's pending-request map (`handler+0x18→0x4c`).  Routes to the
     specific in-flight request object.
  3. **Byte 1** (method opcode): verified against the request object's stored
     opcode at `request+0x15`.  Must match exactly or the reply is discarded.
     `DispatchReplyToRequestObject` (0x04604350) performs this check before
     calling `ProcessTaggedServiceReply`.

**Consequence for server implementations**: the reply host block must echo
back the same byte 0 (service selector) and byte 1 (method opcode) that the
client used in its request, along with the matching VLI request ID.  Using
the wrong selector silently drops the reply with no error.

**Pipe-0 multiplexing** (confirmed by runtime tracing):

All logical pipe data is multiplexed on **physical pipe 0** with a 2-byte LE
routing prefix.  This applies to both directions (server→client and
client→server).  The routing layer works identically in both ENGCT.EXE and
MOSCP.EXE:

- `0xFFFF` → control frame
- `0x0000` → new pipe / open request
- any other value → data for the logical pipe with that index

Therefore all service traffic on the wire must be framed as:

```text
[route_pipe_idx:2LE][host_block...]
```

The outer PipeHdr nibble is always 0 (pipe 0).  The inner routing prefix
determines the actual logical pipe destination.  This applies to **both**
server→client replies and client→server requests.

**Service-pipe open completion — MOSCP Select protocol** (confirmed working):

New pipes start in **"Select"** transport mode during negotiation.  MOSCP.EXE
has a handler table (`PipeProtocol_HandlerTable` at `0x7f4602d0`, 6 entries)
dispatched by `SelectProtocol_DispatchToHandler` (0x7f456071):

- Handler 0: `ret` stub (no-op)
- Handler 1: `PipeOpen_SendCmd7ToMOSCL` (0x7f455cb1) — **pipe-open response**
- Handlers 2-5: stub/unused

`SelectProtocol_DataCallback` (0x7f455de4) routes incoming data by flag byte:
- Flag 0x01 or 0x02 → CMD 5 path (read_complete) — **wrong for pipe-open**
- Flag 0x00 → `SelectProtocol_DispatchToHandler` → handler table dispatch

The dispatch reads 4 bytes from the pipe buffer:
- Bytes 0-1: routing prefix (skipped)
- Bytes 2-3: LE uint16 command index → selects handler from table

Handler 1 reads the server pipe index and error code, switches the pipe to
**"Straight"** transport, and sends **MosSlot CMD 7** to MOSCL.DLL, which
unblocks `PipeObj_OpenAndWait`.

**Wire format** (server→client, on the opened logical pipe):

MUST use **continuation frame format** (PipeHdr bit 5 set, bit 4 clear).
The `has_length` format causes `PipeBuf_SetFlagFromContent` to extract
`content[2]` as a flag byte, which misroutes to the CMD 5 path.

```text
Content (8 bytes, continuation format):
[routing:2LE = pipe_idx]      — MOSCP pipe routing
[command:2LE = 0x0001]        — Select handler 1
[server_pipe_idx:2LE]         — server's pipe index (mirror client's)
[error:2LE = 0x0000]          — 0 = success
```

**LOGSRV service-discovery payload**:
- The traced consumer expects a table of **17-byte records**
- Each record is:
  - 16-byte COM interface IID
  - 1-byte selector
- `GUIDE.EXE` requests IID `{00028BC2-0000-0000-C000-000000000046}` when opening
  the login service interface
- `GUIDE.EXE` also contains adjacent `28BC1` / `28BC3` globals, but the login
  path currently traced references only `28BC2`
- The client will not issue the first real `LOGSRV` RPC until this IID has been
  mapped to a selector via the discovery block

### 4.7 MPC Tagged Parameter System

Response payloads contain a sequence of **tagged parameters** using a TLV-like scheme:

```
+------+-----------+--------...--------+
| Tag  | [Length]  | Data              |
| (1B) | (opt 1-2B)| (variable)       |
+------+-----------+--------...--------+
```

**Tag byte** structure (bitmask 0x8F for type, bits 6-5 for flags):

| Tag & 0x8F | Type                | Description                        |
|------------|---------------------|------------------------------------|
| 0x81-0x84  | Static parameter    | Fixed-size data, copied to pre-registered buffer |
| 0x84       | Compressed static   | Length-prefixed compressed data     |
| 0x85-0x88  | Dynamic parameter   | Variable-size streaming data (16KB chunks) |
| 0x86       | Dynamic more        | More data follows                  |
| 0x87       | Dynamic last        | Last chunk marker                  |
| 0x88       | Dynamic complete    | Transfer complete notification     |
| 0x8F       | Server error        | 4-byte error code follows          |

**Flag bits** (bits 6-5 of tag byte):
- 0x00: Normal
- 0x40: Signal completion
- 0x60: Other flags

**Parameter matching**: Each client request pre-registers up to 16 send and 16 receive
parameter descriptors. Each descriptor has a type byte. The server's response tags are
matched against the registered receive descriptors by type byte.

For the first `GUIDE.EXE` login RPC on `LOGSRV`, the traced request builder does:
- send tag `0x03` with the 4-byte "Version of last update" value
- send tag `0x04` with a `0x58`-byte login blob (contains username + password)
- register seven fixed 4-byte receive fields (`0x83`)
- register one variable 16-byte receive buffer (`0x84`)
- auto-add a completion/helper slot (`0x84`) before dispatch

**Confirmed working login reply format** (tagged payload):

```
[0x83][result_code:4LE]    — field 0: login result (0 = success, 0x0C = success)
[0x83][0x00000000]         — fields 1-6: seven dwords total, all zero for success
[0x83][0x00000000]
[0x83][0x00000000]
[0x83][0x00000000]
[0x83][0x00000000]
[0x83][0x00000000]
[0x87]                     — static section terminator
[0x84][length][data]       — 16-byte variable buffer (zeros)
```

The completion helper's `0x84` slot is NOT included in the reply.
`ProcessTaggedServiceReply` triggers completion automatically when data
runs out after the `0x87` terminator.

The full host block reply is:
```
[service_selector:1]    — byte 0: from IID→selector discovery map (e.g., 0x06)
[method_opcode:1]       — byte 1: must match request's byte 1 (0x00 for login)
[VLI request_id]        — must match pending request (0x00 for first request)
[tagged_payload]        — as above
```

**Maximum limits**:
- 16 send parameters per request
- 16 receive parameters per request
- Send params must be added before recv params (strict ordering)
- 1,073,741,823 requests per service lifetime

### 4.8 Server Error Codes (tag 0x8F)

| Code       | Description                                          |
|------------|------------------------------------------------------|
| 0xE0000001 | Client parameter type mismatch                       |
| 0xE0000002 | Buffer not formatted according to MPC rules          |
| 0xE0000003 | Problem with adding/sending parameters               |
| 0xE0000004 | Method not registered on server                      |
| 0xE0000005 | Memory error                                         |
| 0xE0000006 | Bug in MPC code                                      |
| 0xE0000007 | Invalid parameter passed                             |
| 0xE0000008 | Error during send                                    |
| 0xE0000009 | Error during upload block receive                    |
| 0xE000000A | Application asserted                                 |

## 5. Data Compression

### 5.1 Format

MPC uses Microsoft's compression libraries (MRCI/LZ-based) for data transfer:

- **MCI** (Microsoft Compression Interface): Client → Server compression
- **MDI** (Microsoft Decompression Interface): Server → Client decompression

### 5.2 Compressed Data Format

Compressed data is organized as a sequence of chunks:

```
+--------------------+--compressed-data--+----+--data--+
| chunk1_size (4B LE)| chunk1_data       | sz | chunk2 | ...
+--------------------+--compressed-data--+----+--data--+
```

Each chunk:
- 4-byte little-endian uint32 compressed size
- Followed by that many bytes of compressed data
- Chunks are decompressed independently
- Max uncompressed chunk size: 32KB (0x8000)
- Output buffer per chunk: 32KB
- Compression output buffer: 2x input size (pre-allocated via VirtualAlloc)

## 6. MCM Error Codes

MCM (Marvel Connection Manager) error codes returned by `GetLastMCMError()`:

| Code | HRESULT      | Description                                |
|------|--------------|--------------------------------------------|
| 1    | 0x8B0B0011   | User cancelled login                       |
| 2    | 0x8B0B0012   | Busy signal                                |
| 3    | 0x8B0B0013   | No dial tone                               |
| 4    | 0x8B0B0014   | No carrier detected                        |
| 5    | 0x8B0B0015   | Network error                              |
| 6    | 0x8B0B0016   | No LOGIN service detected                  |
| 7    | 0x8B0B0017   | Bad password                               |
| 8    | 0x8B0B0018   | Bad user ID                                |
| 9    | 0x8B0B0006   | InitMos() failed                           |
| 12   | 0x8B0B0022   | Registry keys missing (Marvel not set up)  |
| 13   | 0x8B0B0024   | Modem or TAPI error                        |
| 14   | 0x8B0B0006   | Connection dropped                         |
| 15   | 0x8B0B0023   | Modem busy or not found                    |
| 16   | 0x8B0B001E   | GUIDE.EXE missing                          |
| 19   | 0x8B0B0006   | Shared memory creation failed              |
| 21   | 0x8B0B0011   | User cancelled (alternate)                 |
| 23   | 0x8B0B0006   | Win32 API error                            |

Debug display controlled by: `SOFTWARE\Microsoft\MOS\Debug\DisplayMcmErrors`

## 7. Session Layer Primitives (MOSCL.DLL)

MOSCL.DLL is the low-level client library that provides pipe I/O and session management
primitives. It acts as the bridge between application-level code (MPCCL.DLL, GUIDE.EXE)
and the transport engine processes (ENGCT.EXE, MOSCP.EXE) via MosSlot IPC.

### 7.1 Transport Engine Selection

`_InitMOS_8(0, transportType)` launches the appropriate engine process:

| Transport Type | Engine Process | Description |
|---------------|----------------|-------------|
| 0 | MOSCP.EXE | Default (connection manager) |
| 2 | *(none)* | Returns immediately (local/no network) |
| 4 | *(none)* | Engine assumed already running |
| 6 | ENGCU | Unknown transport ("U") |
| 7 | MOSCP.EXE | Dial-up modem / X.25 |
| 8 | ENGCT.EXE | TCP/IP ("Chicago TCP") |

The function checks if the engine is already running by attempting to open a named
semaphore. If not found, it launches the engine via `CreateProcessA`. It also reads
the `Latency` value from `HKLM\SOFTWARE\Microsoft\MOS\Transport` for artificial
send delays (debug/simulation).

### 7.2 MosSlot IPC

Communication between MOSCL.DLL and the engine uses **MosSlot** — a custom shared-memory
mailslot system. The engine creates the arena; the client connects on init.

#### MosSlot Arena Structure (0xC546 bytes)

```
Offset   Size       Field
0x000    4          Free list head (offset to first free data buffer)
0x004    2          Reference count
0x006    ...        (padding)
0x010    48 × 28    Slot descriptors (28 bytes each)
0x546    48 × 1024  Slot data buffers (1024 bytes each)
```

- Slot name: `"MosSlot"` (file mapping), `"MosArena"` (mutex)
- 48 slots total, each with a 1KB data buffer
- Free buffers form a linked list (first 4 bytes of each buffer → next offset, -1 = end)
- Notification via named semaphores: `"{slot_index}_mss"` (e.g., `"5_mss"`)

#### Slot Descriptor (28 bytes each, starting at offset 0x10)

```
Offset  Size  Field
0x00    1     Active flag (0=free, nonzero=in use)
0x01    ...   (padding)
0x04    4     Write head offset within data buffer
0x08    2     Reference count
0x0A    13    Slot name (max 12 chars + NUL, e.g., "MOSCL_MOS")
0x17    1     (padding)
0x18    4     Flags (bit 0=open, bit 1=bidirectional, bits 4-6=status tracking)
```

#### Data Buffer Layout (1024 bytes each, starting at offset 0x546)

```
Offset  Size  Field
0x00    4     Next buffer offset (-1 = end of chain)
0x04    4     Bytes used in this buffer
0x08    4     (reserved)
0x0C    ...   Message data: [uint32 msg_size][msg_bytes][uint32 msg_size][msg_bytes]...
```

Max message payload per buffer: 0x3F4 (1012) bytes. When a buffer fills, a new
buffer is allocated from the free list and chained.

#### WriteMosSlot Optimization

WriteMosSlot has a special fast-path for connection status messages (command 9).
Certain status values toggle flag bits on the slot descriptor instead of writing
to the buffer, reducing IPC overhead for frequent status updates:

| Status | Flag toggle |
|--------|-------------|
| 5 | bit 4 ↔ bit 5 |
| 6 | bit 5 ↔ bit 4 |
| 7 | bit 2 ↔ bit 3 |
| 8 | bit 3 ↔ bit 2 |
| 0x1E | set bit 6 |

### 7.3 Client-Engine IPC Protocol

On initialization, MOSCL.DLL:

1. Polls for the MosSlot arena (up to 60 retries × 500ms = 30s)
2. Opens the engine's slot `"MOSCL_MOS"`
3. Creates its own slot `"{pid:08X}_MOS"` (e.g., `"000001A4_MOS"`)
4. Sends command 0 (registration) with its PID
5. Waits for command 1 (registration response) from engine
6. Opens `"ARENA.MOS"` shared memory for bulk data transfer
7. Starts a receive thread (above-normal priority) polling at 500ms

#### Command Types (Client → Engine)

| Cmd | Name | Payload |
|-----|------|---------|
| 0 | Register | `[cmd:2][pad:2][PID:4]` |
| 4 | Write pipe | `[cmd:2][pipe_handle:2][data...]` |
| 6 | Open pipe | `[cmd:2][session_id:2][pipe_handle:2][conn_handle:2][version:4][svc_name\0][svc_version\0]` |
| 8 | Open connection | `[cmd:2][session_id:2][conn_handle:2][params:0x14][conn_string\0]` |
| 0xA | Terminate | `[cmd:2][session_id:2]` |
| 0xB | Close pipe (abort) | `[cmd:2][pipe_id:2][conn_handle:2]` |
| 0xD | Close pipe | `[cmd:2][pipe_id:2][conn_handle:2]` |

#### Command Types (Engine → Client)

| Cmd | Name | Payload |
|-----|------|---------|
| 1 | Registration OK | `[cmd:2][session_id:2][pad:2][engine_PID:4]` |
| 3 | Pipe read ready | `[cmd:2][pipe_handle:2][arena_offset:4]` |
| 5 | Pipe write done | `[cmd:2][pipe_handle:2][result:4]` |
| 7 | Pipe open result | `[cmd:2][pipe_handle:2][pipe_id:2][read_arena:4][write_arena:4][error:2]` |
| 9 | Connection status | `[cmd:2][conn_handle:2][conn_type:2][status:2][extra:4]` |
| 0xC | Pipe closed | `[cmd:2][pipe_handle:2]` |
| 0xF | Connection event | `[cmd:2][conn_handle:2]` |
| 0x10 | Pipe reset | `[cmd:2][pipe_handle:2]` |

### 7.4 ARENA.MOS Shared Memory

Bulk pipe data is transferred through `"ARENA.MOS"` — a file-mapped shared memory
region (default 256KB, configured via `ArenaSize` registry key). MosSlot control
messages carry offsets into this arena rather than the data itself, allowing
efficient transfer of up to 12KB pipe writes without copying through the 1KB
MosSlot buffers.

### 7.5 Connection Object (0x38 bytes)

```
Offset  Size  Field
0x00    4     Status callback function pointer
0x04    4     Callback context
0x08    4     Connection string (allocated, transformed copy)
0x0C    0x14  Connection params (copied from caller)
0x20    2     State
0x22    2     Connection handle (short)
0x24    4     Event handle
0x28    2     Connection type
0x2A    2     Connection status (0x0C=initial, 2=connected, 10=disconnected)
0x2C    4     Connection readiness (1=ready, 2=error)
0x30    4     Suppress duplicate notifications flag
0x34    4     Extra state
```

#### Connection Status Codes

| Status | Meaning |
|--------|---------|
| 0x02 | Connected (sets readiness=1) |
| 0x03 | Status update |
| 0x0A | Disconnected (sets readiness=2) |
| 0x0C | Initial (no notification sent) |
| 0x1B | Error |
| 0x1D | Error |

For dial-up connections (type 7 or 0), the connection string is transformed:
`"number:location"` → `"\x02number\x03location"`. For TCP (type 8), the string
`"P:user:server\0"` is passed through unchanged.

### 7.6 Pipe Object (0xE4 bytes)

```
Offset  Size  Field
0x00    4     Pointer to service name string
0x04    4     Pointer to version string
0x08    4     Pointer to parent connection object
0x0C    ...   Write completion queue
0x34    ...   Async write data pointer
0x5C    4     Open-response event handle
0x60    4     Read-ready semaphore handle
0x64    4     (reserved)
0x68    4     Read arena offset (set by engine on pipe open)
0x6C    4     Write arena offset (set by engine on pipe open)
0x70    2     Pipe ID assigned by engine (-1 = invalid)
0x72    2     Local pipe handle
0x74    4     Read notification callback
0x78    4     Write notification callback
0x7C    4     Open-complete callback (async pipe open)
0x80    4     Callback context
0x84    4     Pipe state (1=ready, 2=closed, 3=timed-out-no-cb, 4=timed-out-has-cb)
0x8C    24    Critical section (write serialization)
0xA4    24    Critical section (queue management)
0xD4    2     Last error code from engine
```

### 7.7 API Summary

| Export | Parameters | Returns |
|--------|-----------|---------|
| `_InitMOS@8` | (0, transportType) | bool success |
| `_TerminateMOS@0` | () | bool success |
| `_OpenMOSConnection@16` | (connString, callback, context, params[0x14]) | handle or 0xFFFF |
| `_CloseMOSConnection@4` | (connHandle) | void |
| `_OpenMOSSession@8` | (connHandle, serviceName) | handle or 0xFFFF |
| `_OpenMOSPipeWithNotifyEx@28` | (session, version, name, readCb, ctx, writeCb, flags) | handle or 0xFFFF |
| `_ReadMOSPipe@16` | (pipeHandle, buffer, size, timeout) | bytes read or -1 |
| `_WriteMOSPipe@20` | (pipeHandle, asyncCtx, data, size, asyncFlag) | 0=ok, -2=pending, -1=error |
| `_GetMOSPipeReadSize@8` | (pipeHandle, timeout) | bytes available or -1 |
| `_GetMOSLastError@4` | (0) | error code |
| `_GetMOSConnectionStatus@4` | (connHandle) | status code |
| `_GetMOSSysInfo@8` | (0, infoId) | value or -1 |

System info values: `infoId=1` → max write size (0x3000 = 12KB), `infoId=2` → default timeout (6000ms).

### 7.8 Shutdown Sequence

`_TerminateMOS_0` performs:

1. Sends command 0xA (terminate) to engine via MosSlot
2. Waits for receive thread to exit (5 second timeout)
3. Closes MosSlots and arena
4. Finds `"MOSEngine Chicago"` window (class `"Generic"`) and posts WM_CLOSE
5. Waits for engine process to terminate (8 second timeout)

## 8. Session Flow

### 7.1 Login Sequence (GUIDE.EXE)

#### Initialization

GUIDE.EXE startup (`FUN_0430122b`) creates:

| Resource | Type | Purpose |
|----------|------|---------|
| `"LoginMan"` | Semaphore | Single-instance guard |
| `"InMCM"` | Mutex | MCM access synchronization |
| `"logmanhwnd"` | File mapping (4 bytes) | Stores LoginMan window HWND |
| `"MCMSHM"` | File mapping (0x354 bytes) | Session state shared memory |
| `"Service Guide"` | Hidden window (class `"LoginMan"`) | Message loop for login events |

#### Credential Dialog

The login dialog (`FUN_04304885`) presents:

| Control | Item ID | Constraint |
|---------|---------|------------|
| Username | 0x72 | Max 64 characters (EM_LIMITTEXT 0x40) |
| Password | 0x73 | Max 16 characters (EM_LIMITTEXT 0x10) |
| Remember password | 0x74 | Checkbox |
| Phone / status | 0x71 | Display only |
| Connect | 0x75 | Initiates connection |
| Cancel | 0x02 | Calls `_CloseMOSConnection_4` |
| Settings | 0x76 | Opens `ChangeConnectionSettings` / `FGetPortDetails` |

Saved credentials are loaded from registry via `PVReadRegSt`. Cached passwords
are retrieved via `WNetGetCachedPassword`. If the `SkipLoginUI` preference is
set, the dialog auto-posts the Connect command (button 0x75) without showing UI.

#### "Verifying account..." Gate

Once the dialog transitions to **"Verifying account..."**, `GUIDE.EXE` has already:

1. Opened the MOS session
2. Opened the `LOGSRV` service pipe
3. Spawned the background login verification thread

At this point the relevant code path is:

1. `LoginDialogProc`
2. `LoginVerificationThreadProc`
3. `RunLoginVerification`
4. `VerifyAccountViaLogSrv`

Inside `VerifyAccountViaLogSrv`, the client:

1. Opens `LOGSRV` version `6`
2. Queries interface IID `{00028BC2-0000-0000-C000-000000000046}`
3. Requests request-builder opcode `0`
4. Builds and dispatches the first login RPC
5. Waits synchronously for completion

At this point the client is blocked on two `LOGSRV` protocol preconditions:

1. A post-open **service-discovery** host block that maps the requested interface
   IID `{00028BC2-0000-0000-C000-000000000046}` to a one-byte selector
2. The first real `LOGSRV` RPC reply, whose first returned dword is the login
   result code (`0` or `0x0C` are success)

**Both preconditions are now satisfied by the emulated server** (confirmed
2026-04-10).  The client accepts the login reply, the GUIDE icon appears in
the system tray, and the client proceeds to open `DIRSRV` pipes.

`GUIDE.EXE` also has a second `LOGSRV` path, `RunPostLoginLogSrvTransferFlow`,
which is a later transfer/update flow reached only after login when
`DAT_0430a09c` requests additional work. That path uses request-builder opcode
`8`.

#### Post-Login Flow (confirmed by runtime trace)

After the login reply is accepted:

1. Client sends a second `LOGSRV` request: selector=0x07, request_id=1,
   payload=`0x85` (dynamic/incremental tag — may be requesting streamed data)
2. Client opens two **`DIRSRV`** pipes (directory service, ver=`Uagid=0`,
   version=7) — these are for browsing MSN content
3. Client sends 1-byte `0x01` messages on all open pipes (meaning unknown —
   possibly pipe-level status probe or keepalive)
4. If DIRSRV requests are not answered, client disconnects after ~90s

#### Password Caching

When "Remember password" is checked:

1. Password cached via `WNetCachePassword` (Windows credential store)
2. On success: password buffer is zeroed (16 bytes)
3. On failure: bytes after the null terminator are filled with `rand()` data
   (security padding to prevent memory scanning)
4. Password buffer is then encrypted via `FUN_043016ec` before storage
5. Full credential block (0x5A bytes) saved to registry via `FWriteRegSt`

Credential block layout (0x5A bytes, stored in registry):

```
Offset  Size  Field
0x00    4     Header
0x04    65    Username (ANSI, null-terminated)
0x45    17    Password (encrypted, null-terminated + random padding)
0x56    4     Flags (bit 0 = remember password)
```

#### TCP Connection String Format

For TCP connections (transport type 8), the connect function (`FUN_0430248c`)
builds a connection string:

```
+------+------+-----...-----+------+-----...-----+------+
| Type | ':'  | Username     | ':'  | Server Addr | NUL  |
| 1 B  | 1 B  | ≤47 bytes    | 1 B  | ≤47 bytes   | 1 B  |
+------+------+-----...-----+------+-----...-----+------+
```

- **Type byte**: `'P'` (0x50) = primary datacenter, `'B'` (0x42) = backup datacenter
- **Username**: From user profile (offset 0x17C in MCMSHM) or dialog input, max 47 bytes
- **Server address**: From DataCenter registry entry (offset 0x1BD in MCMSHM)

Primary/backup datacenter addresses are read from registry (PVReadRegSt indices 6 and 7).
On first attempt and even retries, 'P' (primary) is used; on odd retries, 'B' (backup).

#### Dial-up Connection String

For modem connections (transport type 7):

1. `lineTranslateAddress` (TAPI) canonicalizes the raw phone number
2. Country code and city code appended with delimiters:
   ```
   {translated_number}\x05{country_code}\x06{city_code}
   ```
3. Phone number displayed in dialog field 0x71

#### Connection Establishment

```
1. [TCP only] IfTCPthenUpdateOhare(hwnd, username, password)
   → "Ohare" component update check (via MOSCL.DLL thunk)

2. [TCP only] IfTCPthenSecurityCheck(hwnd, hInstance)
   → Security validation (via MOSCL.DLL thunk)
   → On failure: prompts user, may set vMCMNeedSecurityReboot flag and abort

3. _InitMOS_8(0, transportType)
   → transportType: 7 = dial-up/modem, 8 = TCP/IP
   → Cached in vfInitMos — skipped if already initialized
   → Provided by MOSCL.DLL

4. _OpenMOSConnection_16(&connectionString, callback, 0, &transportType)
   → connectionString: "P:user:server\0" (TCP) or phone number (dial-up)
   → callback: async status notification function
   → Returns connection handle (short), -1 on failure
   → Provided by MOSCL.DLL

5. CreateEvent("MakeCancelCallSync")
   → Signaled immediately — enables cancel operations during connect
```

#### Retry Logic

On connection failure, the dialog retries automatically (up to 5 attempts):

- Alternates between primary (`'P'`) and backup (`'B'`) datacenter on each retry
- Non-fatal errors display a status message and trigger the next attempt
- Fatal errors terminate the dialog immediately:

| Error Code | Meaning | Fatal? |
|------------|---------|--------|
| 0x03 | Server busy | Yes |
| 0x05 | Network error (TCP: fatal) | Conditional |
| 0x07 | Authentication failure | Yes |
| 0x09 | Connection failed (default) | Yes (after retries) |
| 0x0F | Protocol error | Yes |
| 0x11 | Already online | Yes (pre-check) |
| 0x12 | Invalid window handle | Yes (pre-check) |
| 0x16 | Concurrent connection attempt | Yes (pre-check) |
| 0x18 | Timeout | Yes |
| 0x19 | Server-specific error | Varies |
| 0x1D–0x20 | Security/certificate errors | Yes |
| 0x22–0x25 | Ohare update errors | Yes |

#### Transport Types

| Value | Transport | Connection String Format |
|-------|-----------|--------------------------|
| 7 | Dial-up (modem/X.25) | TAPI-translated phone number with `\x05`/`\x06` delimiters |
| 8 | TCP/IP | `[P|B]:username:server_address\0` |

#### MCMSHM Shared Memory (0x354 bytes)

Key fields identified from GUIDE.EXE access patterns:

```
Offset  Size   Field
0x000   4      Event handle (MakeCancelCallSync)
0x091   2      Connection handle (short, -1 = not connected)
0x10D   varies DataCenter string
0x17C   varies User profile: username (at +4 from base of profile)
0x1BD   varies Server address string
0x244   2      Connection handle (alternate, set to 0xFFFF on init)
0x340   varies Port details (passed to FGetPortDetails)
0x342   2      Transport type (7=dial-up, 8=TCP)
0x354   ---    End of structure
```

### 7.2 Service Access

```
1. OpenMOSPipeWithNotifyEx(session, version, "U"+name, readCb, ctx, writeCb, timeout)
   - Engine locates service by name and version
   - Returns pipe handle
2. Server sends service-discovery host block(s)
   - Byte0 = 0x00
   - Payload = one or more 17-byte records: IID(16) + selector(1)
   - Client resolves the requested interface IID to a selector byte
   - For login, the traced IID is `28BC2`
3. Client builds request: send parameters (up to 16)
   - Login opcode `0` request:
     - send `0x03` dword
     - send `0x04` 0x58-byte blob
     - receive `0x83` × 7
     - receive `0x84` × 1 (16 bytes)
4. WriteMOSPipe(pipe, buffer, data, size, flags)
   - Returns -2 (async pending) on success
5. Server processes request
6. ReadMOSPipe callback fires:
   - Parse Host Block header (class + selector + VLI request ID)
   - Route by selector byte to the waiting request object
   - Match tagged parameters to registered receive descriptors
   - Decompress if needed (MDIC chunks)
7. CloseMOSPipe(pipe) when done
```

### 7.3 Chat / Conferencing (CONFAPI.DLL)

#### Connection Setup

```c
// 1. Initialize COM and create IMos object
CmdInitializeConnection(callback, userId, password, phoneNumber)
  → CoCreateInstance({00028B07-...}, IID_IMos)
  → IMos::SetConnectionInfo(userId, password, phoneNumber)
  → IMos::CreateServiceInstance("CONFLOC", version, &locator)
```

#### Joining a Conversation

```c
// 2. Join via CONFLOC → CONFSRV service chain
CConversation::CceJoin(confId, flags, callback, name, context)
  → Open "CONFLOC" service (Conference Locator)
  → Look up conference by ID (up to 4 retries)
  → Open "CONFSRV" service (Conference Server) with conf number
  → Send join request (MPC request type 3)
  → Send display name (ANSI string)
  → Read join response:
      status 3 = success (copies convId, maxMsgSize, serverAddr, displayName)
      status 6 = retry (loop back)
      status 8 = error: conversation full (code 2)
      status 9 = error: not found (code 4)
      status 11 = error: access denied (code 7)
  → On success: starts background receive thread
```

#### Chat Message Wire Format

Messages are sent via the MPC service pipe with this 8-byte header:

```
+----------+----------+----------+----------...----------+
| MsgType  | (pad)    | ConvID   | Data                  |
| uint16   | 2 bytes  | uint32   | variable              |
+----------+----------+----------+----------...----------+
```

- **MsgType**: 0 = text (Unicode/UTF-16LE), 1 = binary data
- **ConvID**: Conversation ID assigned during join
- **Data**: Message payload (max size from join response, stored at offset 0x28)

For text messages, ANSI input is converted to Unicode (UTF-16LE) before sending.

Special sender/destination values:
- `0xFFFFFFFF` (-1) = self (outgoing messages)
- `0xFFFFFFFE` (-2) = broadcast to all participants

#### CConfMsg Object Structure

```
Offset  Size  Field
0x00    2     Message type (0=text, 1=binary)
0x04    4     Destination (CDummy*/userId, -2=broadcast)
0x08    4     Sender (CDummy*/userId, -1=self)
0x0C    4     Data buffer pointer
0x10    4     Data length (bytes)
```

#### Receiving Messages

The background thread receives messages via the service pipe and enqueues
them in a mutex-protected linked list. `ReceiveMessage()` dequeues from
this list, returning the `CConfMsg*` and a flag indicating if more messages
are available.

#### Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Max message size exceeded |
| 3 | Server rejected (HRESULT 0x8B0B0006) |
| 4 | Out of memory |
| 5 | Not connected / empty input |
| 6 | Already in conversation |
| 7 | Access denied |

## 9. System Administration (SACLIENT.DLL)

SACLIENT.DLL is **not** an authentication library — it is a system administration
client for managing MSN server-side objects. Its exports:

| Export | Description |
|--------|-------------|
| CreateSysAdminClient | Create admin session |
| CreateSysAdminDistList | Manage distribution lists |
| CreateSysAdminUserGroup | Manage user groups |
| CreateSysAdminMailContainer | Manage mail containers |
| CreateSysAdminToken | Manage authentication tokens |
| CreateSysAdminMasterList | Master object list |
| CreateSysAdminMasterDistList | Master distribution list index |
| CreateSysAdminMasterUserGroupList | Master user group index |
| CreateSysAdminMasterTokenList | Master token index |
| CreateSysAdminMasterInetAddrList | Master internet address list |
| CreateSysAdminMasterContainerList | Master container index |

This suggests MSN95 included built-in administrative tools for server operators
to manage users, groups, mail containers, and internet address mappings.

## 10. Content System

### 9.1 Multimedia Viewer (MVTTL14C.DLL)

MSN95 renders content using Microsoft's **Multimedia Viewer** engine (same as Encarta):

- Based on the Windows Help (HFS) file system
- `TitleConnection` / `TitleOpenEx` / `TitleClose` - connect to content titles
- `Baggage*` functions - packaged content/resources
- `WordWheel*` - search/index functionality
- `Highlight*` - search result highlighting
- `DownloadPicture` / `GetPictureInfo` - image handling
- Sound playback via waveOut*

### 9.2 Content Service Connection ("MEDVIEW")

The content system connects via MPC service named **"MEDVIEW"** (default):

```c
hrAttachToService(serviceName, NULL, NULL)
  → CoCreateInstance(CLSID_IMos) → IMos object
  → IMos::SetNotifyHandler(handler)
  → IMos::CreateServiceInstance("MEDVIEW", version=0x1400800A)
```

### 9.3 Version Handshake

After service connection, the client sends a capabilities handshake:

```
MPC Request type 0x1F:
  Send parameters (12 bytes):
    +----------+----------+--------------+
    | MaxSize  | Flags    | BrowseLanguage|
    | uint32   | uint32   | uint32       |
    | 0x2000   | 0x4006   | LCID         |
    +----------+----------+--------------+

  Response:
    - Non-zero = success (versions compatible)
    - Zero = "Handshake validation failed. Versions of client
              and server may not be the same."
```

- **MaxSize** (0x2000 = 8KB): Maximum response buffer size
- **Flags** (0x4006): Client capability flags
- **BrowseLanguage**: Win32 LCID from registry `BrowseLanguage` preference

On success, the client creates **5 worker channels** (indices 0–4) for concurrent
content requests, each with a dedicated callback handler.

### 9.3 Navigation Model (MOSSHELL.DLL)

Tree-based navigation using OLE/COM Shell Extension model:
- `CMosTreeNode` - tree node (properties, children, navigation)
- `CMosViewWnd` - view window (list view, drag-drop, context menus)
- `CMosTreeEdit` - editing operations
- `CTreeNavClient` - navigation client
- Node IDs: `_MosNodeId` structures, serializable as `_ITEMIDLIST` (PIDL)
- Properties fetched from host: `GetPropertyFromHost`, `GetPropertyGroupFromHost`
- `MOSPMTN.DAT` - cached tree node data
- `ICOCACHE.DAT` - cached icons

## 11. Registry Configuration

| Key | Purpose |
|-----|---------|
| `SOFTWARE\Microsoft\MOS\Transport` | Transport settings (PacketSize, WindowSize, etc.) |
| `SOFTWARE\Microsoft\MOS\Connection` | Connection configuration |
| `SOFTWARE\Microsoft\MOS\Debug` | Debug settings (DisplayMcmErrors, DisplayMpcErrors) |
| `SOFTWARE\Microsoft\MOS\Directories` | File/directory paths |
| `SOFTWARE\Microsoft\MOS\Favorite Places` | User bookmarks |
| `SOFTWARE\Microsoft\MOS\Preferences` | User preferences |
| `SOFTWARE\Microsoft\MOS\Mosxapi` | MOSX API configuration |
| `SOFTWARE\Microsoft\MOS\Streams` | Stream settings |
| `SOFTWARE\Microsoft\MOS\Applications` | Registered applications |

## 12. Key Binary Components

| Binary | Size | Role |
|--------|------|------|
| MPCCL.DLL | 88K | MPC protocol client (COM DLL) |
| MOSCL.DLL | 37K | Low-level pipe/session primitives, MosSlot IPC |
| ENGCT.EXE | 72K | Transport engine "MOSEngine Chicago" |
| MOSCP.EXE | 68K | Connection manager (modem, X.25) |
| GUIDE.EXE | 116K | Main app, login, session manager |
| MOSSHELL.DLL | 180K | Shell/navigation (largest component) |
| CONFAPI.DLL | 24K | Conference/chat API |
| MVTTL14C.DLL | 77K | Multimedia Viewer content engine |
| MOSCOMP.DLL | 149K | Content rendering |
| SACLIENT.DLL | 29K | System admin client (users, groups, tokens, dist lists) |
| SIGNUP.EXE | 164K | Registration wizard |
| TEXTCHAT.EXE | 52K | Chat client (uses CConversation) |
| BBSNAV.NAV | 212K | BBS/forum navigation |
| FTMCL.EXE | 47K | File transfer client |

## 13. Internal Object Model (from MPCCL.DLL decompilation)

### 12.1 IMos COM Object (0x4C bytes)

```
Offset  Size  Field
0x00    4     Vtable pointer (IMos interface - 12 methods)
0x04    4     Reference count
0x08    2     Session handle (WORD, 0xFFFF = no session)
0x0A    2     (padding)
0x0C    4     Global state pointer
0x10    4     Connection status object
0x14    4     Service dispatch object
0x18    4     Allocated buffer 1
0x1C    4     Allocated buffer 2
0x20    4     Reserved
0x24    4     Allocated buffer 3
0x28    24    CRITICAL_SECTION
0x40    2     Flags (default: 0x40)
0x42    2     Secondary session handle (0xFFFF)
0x44    4     Reserved
0x48    4     Reserved
```

### 12.2 Service Instance Object (0x98 bytes)

Created per-service by `CreateServiceInstance()`:

```
Offset  Size  Field
0x00    4     Vtable pointer (service methods)
0x04    4     Error/status code
0x08    4     Parent IMos object
0x0C    4     Service descriptor
0x10    4     Connection context
0x14    4     Last error HRESULT
0x18    4     Read buffer
0x1C    24    CRITICAL_SECTION (read lock)
0x34    24    CRITICAL_SECTION (dispatch lock)
0x4C    4     Reserved
0x50    24    CRITICAL_SECTION (request lock)
0x68    4     Request queue head
0x6C    4     Request queue (receive dispatch)
0x70    4     Request queue (upload dispatch)
0x74    4     Active flag (1=active)
0x78    24    CRITICAL_SECTION (notification lock)
0x90    4     Notification handler
0x94    2     Pipe handle (SHORT, -1 = invalid)
0x96    1     Flag byte
```

### 12.3 Request Object (0x54 bytes)

Created per-request, holds send/receive parameter descriptors:

Each parameter descriptor is 0xC bytes:
```
Offset  Size  Field
0x00    1     Tag type byte (matched against server response tags)
0x04    4     Buffer size
0x08    4     Buffer pointer
```

### 12.4 IMos Interface Methods (vtable at 0x0460CC98)

| Index | Address    | Method                   |
|-------|------------|--------------------------|
| 0     | 0x04601D25 | QueryInterface           |
| 1     | 0x04601B07 | AddRef                   |
| 2     | 0x04601B1C | Release                  |
| 3     | 0x04601E98 | Method3 (init/connect?)  |
| 4     | 0x04601D85 | Method4                  |
| 5     | 0x04602304 | Method5 (HangUp?)        |
| 6     | 0x04601EB1 | Method6 (GetConnectionInfo?) |
| 7     | 0x04601EDD | Method7 (SetConnectionInfo?) |
| 8     | 0x04601F07 | Method8 (WithdrawNotification?) |
| 9     | 0x04601F75 | CreateServiceInstance    |
| 10    | 0x04601AFF | Method10                 |
| 11    | 0x0460222A | Method11                 |

## 14. Complete Request Lifecycle (Wire Level)

```
CLIENT                                          SERVER
  |                                                |
  |  1. FMCMOpenSession(credentials)               |
  |  ──────── transport connect ──────────────────>|
  |  <─────── session handle ─────────────────────|
  |                                                |
  |  2. OpenMOSPipeWithNotifyEx("U"+serviceName)   |
  |  ──────── locate service by name+version ─────>|
  |  <─────── pipe handle ────────────────────────|
  |                                                |
  |  3. Receive service-discovery block(s)         |
  |  <──────── Host Block (class=0) ───────────────|
  |  │ Body: IID(16) + selector(1) records         |
  |  │ Example: 028BC2... -> selector byte         |
  |                                                |
  |  4. Build request:                             |
  |     - Login path uses request-builder opcode 0 |
  |     - Send tag 0x03: 4-byte update version     |
  |     - Send tag 0x04: 0x58-byte login blob      |
  |     - Recv tags: 0x83 x7, 0x84 x1              |
  |     - Post-login transfer path instead uses op 8|
  |                                                |
  |  5. WriteMOSPipe(pipe, request_data)           |
  |  ──────── Host Block ─────────────────────────>|
  |  │ Byte0: selector                             |
  |  │ Byte1: opcode / method id                  |
  |  │ VLI:   request sequence number              |
  |  │ Body:  tagged send parameters               |
  |  │   [tag 0x81-0x84] + [data]  (static)       |
  |  │   [tag 0x85-0x88] + [data]  (dynamic/stream)|
  |                                                |
  |  <──────── Host Block response ────────────────|
  |  6. ReadMOSPipe callback fires:                |
  |  │ Byte0: selector (0=discovery/status)        |
  |  │ Byte1: opcode / method id                  |
  |  │ VLI:   request sequence number              |
  |  │ Body:  tagged receive parameters            |
  |  │   [0x81-0x84] static recv into buffer       |
  |  │   [0x84] compressed: len + MDIC chunks      |
  |  │   [0x85-0x88] dynamic recv (streaming)      |
  |  │   [0x86] more data notification             |
  |  │   [0x87] last chunk                         |
  |  │   [0x88] transfer complete                  |
  |  │   [0x8F] server error + 4B error code       |
  |                                                |
  |  7. CloseMOSPipe(pipe)                         |
  |  8. MCMCloseSession(session)                   |
```

### 14.1 Compressed Data Transfer Detail

When a parameter is compressed (tag 0x84 variant):

```
[tag byte] [length: 1-2 bytes] [compressed payload]

Compressed payload format:
  [uint32 chunk1_compressed_size] [chunk1_data]
  [uint32 chunk2_compressed_size] [chunk2_data]
  ...

Each chunk decompresses to max 32KB (0x8000 bytes)
Compression: Microsoft MRCI (LZ-based, same era as MRSF/SZDD)
```

### 14.2 Dynamic (Streaming) Data Transfer

For large data that can't fit in a single response:

```
SERVER sends sequence of Host Blocks:
  [0x85 + data chunk]     ← first chunk
  [0x86 + data chunk]     ← more data (client notified)
  [0x86 + data chunk]     ← more data
  [0x87 + data chunk]     ← last data chunk
  [0x88]                  ← transfer complete signal

Each chunk up to 16KB (0x4000 bytes)
Client can call RequestDynamicParam() + WaitIncremental() to stream
```

---

*This document was derived from static reverse engineering of MSN95 client binaries
dated July 11, 1995, using Ghidra decompilation of MOSCL.DLL (session primitives),
MPCCL.DLL (MPC protocol), ENGCT.EXE (transport engine), GUIDE.EXE (login manager),
MOSCP.EXE (connection manager), CONFAPI.DLL (conferencing), MVTTL14C.DLL (content),
and SACLIENT.DLL (system administration), plus string/import analysis of all 43
binaries. No server-side code or network captures were available. Some field
interpretations are inferred from code patterns, error messages, and C++ mangled
symbol names.*
