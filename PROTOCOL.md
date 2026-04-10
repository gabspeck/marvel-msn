# MSN95 "Marvel" Wire Protocol

Reverse-engineered from MSN for Windows 95 client binaries (July 11, 1995)
using Ghidra decompilation and a custom emulated server. The login handshake
is confirmed working end-to-end as of 2026-04-10.

## Is this protocol based on anything?

No. This is a completely bespoke Microsoft protocol stack, built in-house for
the MSN online service circa 1994-1995. It does not implement or extend any
public standard (X.25 LAPB, PPP, OSI, DCE RPC, etc.), though individual
pieces borrow common ideas:

- The **byte-stuffing** scheme resembles PPP's ACCM octet-stuffing (RFC 1662),
  but uses a different escape character (0x1B instead of 0x7D) and a different
  complement operation (lookup table instead of XOR 0x20).
- The **sliding window** is textbook Go-Back-N ARQ with a 7-bit sequence space,
  similar to HDLC or LAPB, but the framing is different.
- The **CRC-32** uses a non-standard polynomial (0x248EF9BE) with an unusual
  NOT-after-XOR twist, not matching any known CRC catalog entry.
- The **variable-length integer** encoding looks like ASN.1 BER length encoding
  (top 2 bits select 1/2/4-byte form), but the bit patterns differ.
- The **service model** is loosely COM-shaped (IID GUIDs, interface selectors,
  method opcodes) because the client-side library (MPCCL.DLL) is a COM DLL,
  but the wire format is not DCOM/ORPC — it's a custom tagged-parameter RPC.

The internal codename was **"Marvel"** and the protocol layer is called **MPC**
(Marvel Protocol Client).

---

## Protocol Layers

```
 Application     GUIDE.EXE, MOSSHELL.DLL, CONFAPI.DLL
                      |
 Service RPC     MPCCL.DLL — tagged-parameter request/reply over named pipes
                      |
 Session/IPC     MOSCL.DLL — MosSlot shared-memory IPC to transport engine
                      |
 Transport       MOSCP.EXE — packet framing, sliding window, CRC,
                              modem/X.25 handshake, TCP connect
                      |
                   TCP socket / serial modem
```

All layers are confirmed by decompilation. The transport and service layers
are confirmed by a working emulated server.

**Note on ENGCT.EXE**: The binaries include a standalone transport engine
called ENGCT.EXE ("MOSEngine Chicago"), which contains the same packet
framing, CRC, and sliding-window code. However, **ENGCT.EXE is never loaded
at runtime** for dial-up or TCP connections. Process inspection during login
shows only GUIDE.EXE, MOSCP.EXE, TAPIEXE.EXE, and LIGHTS.EXE. MOSCP.EXE
is the actual transport engine for these connection types. ENGCT.EXE may only
be used for Named Pipe (X25PIPE) or other transport modes not yet tested.
The wire protocol is the same regardless of which engine handles it.

---

## 1. Transport Packets

Every message on the wire is a **packet** terminated by byte `0x0D`.

### 1.1 Packet Format

```
 SeqNo    AckNo    Payload (byte-stuffed)    CRC-32     0x0D
[1 byte] [1 byte] [0..N bytes]              [4 bytes]  [1 byte]
```

- **SeqNo**: Sequence number. Bits 6-0 are the 7-bit sequence (0-127).
  Bit 7 is always set for data packets. Value 0x41 = ACK-only, 0x42 = NACK.
- **AckNo**: Piggybacked acknowledgement. Bits 6-0 = last-received + 1.
  Bit 7 always set.
- **Payload**: Pipe-multiplexed data (see section 2). Byte-stuffed on the wire.
- **CRC-32**: Computed over the wire bytes (encoded SeqNo + AckNo + stuffed
  payload), then masked before transmission.
- **0x0D**: Packet terminator.

Minimum packet: 7 bytes (SeqNo + AckNo + CRC + terminator, no payload).

### 1.2 Special Packet Types

| First byte | Type | Description |
|------------|------|-------------|
| 0x41 | ACK | Acknowledgement only — no payload |
| 0x42 | NACK | Retransmission request — byte 1 & 0x7F = last good seq |
| other | DATA | Normal data packet |

### 1.3 Byte Stuffing

The payload uses escape-based stuffing. Escape character is **0x1B**.

| Raw byte | Wire encoding | Why escaped |
|----------|---------------|-------------|
| 0x0D | `1B 31` | Packet terminator |
| 0x1B | `1B 30` | Escape character |
| 0x10 | `1B 32` | DLE |
| 0x0B | `1B 33` | VT |
| 0x8D | `1B 34` | High control |
| 0x90 | `1B 35` | High control |
| 0x8B | `1B 36` | High control |

To decode: on seeing 0x1B, read the next byte and map
`'0'->0x1B, '1'->0x0D, '2'->0x10, '3'->0x0B, '4'->0x8D, '5'->0x90, '6'->0x8B`.

### 1.4 Three-Zone Wire Encoding

A single packet uses **three different** encoding rules depending on the field:

1. **Header bytes** (SeqNo, AckNo): If the value (after setting bit 7) is
   0x8D, 0x90, or 0x8B, XOR it with 0xC0.
2. **Payload bytes**: 0x1B escape stuffing (above).
3. **CRC bytes**: OR 0x60 on any byte that's in the escape set.

The CRC is computed over the already-encoded zones 1 and 2. Then the CRC
bytes themselves get zone-3 masking before being appended.

### 1.5 CRC-32

Custom polynomial **0x248EF9BE**, init = 0, no final XOR. Table generation
uses NOT after XOR on the odd path:

```c
for (int i = 0; i < 256; i++) {
    uint32_t c = i;
    for (int j = 0; j < 8; j++) {
        if (c & 1)
            c = ~((c ^ 0x248EF9BE) >> 1);
        else
            c >>= 1;
    }
    table[i] = c;
}

uint32_t crc = 0;
for (int i = 0; i < len; i++)
    crc = (crc >> 8) ^ table[(data[i] ^ (uint8_t)crc) & 0xFF];
```

CRC is over the **wire bytes** (after header encoding + payload stuffing),
not the decoded bytes.

### 1.6 Sliding Window

Go-Back-N ARQ:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Sequence space | 7-bit (0-127) | Wraps with `(seq + 1) & 0x7F` |
| Window size | 16 | Negotiable, halved on timeout |
| ACK timeout | 6000 ms | Retransmit timer |
| Max retransmissions | 12 | Disconnect after 12 failures |
| AckBehind | 1 | Force ACK after N unacked receives |

On timeout: window halved (`w >>= 1; if w == 0 w = 1`), all unacked packets
retransmitted in order. Pure ACKs use the 0x41 packet type.

---

## 2. Pipe Multiplexing

A single packet payload carries data for one or more **logical pipes**.
The payload (after byte-unstuffing) is a sequence of pipe frames.

### 2.1 Pipe Frame Format

```
 PipeHdr   [LenByte]   PipeData
[1 byte]   [0-1 byte]  [variable]
```

**PipeHdr** (after decode_header_byte):

| Bits | Mask | Meaning |
|------|------|---------|
| 3-0 | 0x0F | Pipe index (0-15) |
| 4 | 0x10 | has_length — LenByte follows |
| 5 | 0x20 | continuation — rest of packet is this pipe's data |
| 6 | 0x40 | last_data — final fragment of this message |
| 7 | 0x80 | Always set |

If **has_length** is set, the next byte (& 0x7F) gives the content byte count.
If **continuation** is set, all remaining packet bytes belong to this pipe
(no length byte needed). These are mutually exclusive in practice.

**PipeData** always starts with a `uint16 LE` content-length prefix, followed
by the content bytes.

### 2.2 Pipe 0 Routing

All logical pipe traffic is multiplexed on **physical pipe 0**. The first two
bytes of pipe-0 content are a **routing prefix** (uint16 LE):

| Routing value | Meaning |
|---------------|---------|
| 0x0000 | New pipe open request |
| 0xFFFF | Control frame |
| any other | Data for that logical pipe index |

This means the outer PipeHdr nibble is always 0. The routing prefix determines
the actual destination pipe.

### 2.3 Control Frames

Control frames have routing `0xFFFF` followed by a 1-byte type:

```
 FF FF   Type    Payload
[2 bytes][1 byte][variable]
```

| Type | Description |
|------|-------------|
| 1 | Connection request (echoed back by server) |
| 3 | Transport parameter negotiation |
| 4 | Connection establishment signal |

### 2.4 Transport Parameter Negotiation (Type 3)

Sent by the server immediately after the modem handshake. Six uint32 LE values:

```
 PacketSize  MaxBytes  WindowSize  AckBehind  AckTimeout  [Keepalive]
[4 bytes]   [4 bytes] [4 bytes]   [4 bytes]  [4 bytes]   [4 bytes optional]
```

The client takes the **minimum** of each server value and its own configured
maximum. Keepalive is only present if the frame exceeds 0x18 bytes.

---

## 3. Modem Handshake

Before the transport protocol starts, MOSCP.EXE performs a text-based handshake
over the modem connection.

### 3.1 Sequence (confirmed working)

```
Client -> Server:  0x0D                    (bare carriage return)
Server -> Client:  "COM\r"                 (triggers direct transport mode)
Server -> Client:  [transport params packet]  (type-3 control frame, section 2.4)
```

The server **must** respond with the ASCII string `COM` followed by `\r`.
This tells MOSCP to switch from modem-negotiation state to binary packet mode
and hand off to ENGCT. Any other response (or no response within 20 seconds)
results in connection failure.

### 3.2 X.25 / Dial-up Networks (from static analysis)

MOSCP also supports connecting through X.25 packet-switched networks (AUSTPAC,
TELENET, MCI, AT&T). The server's first bytes are pattern-matched:

| Server sends | Action |
|-------------|--------|
| `COM` | Direct transport mode (binary protocol starts) |
| `AUSTPAC:` | AUSTPAC network login |
| `TELENET` | TELENET network |
| `Please Sign-on:` | Send username |
| `please log in:` | Send username |
| X.25 PAD prompt (0xA3) | Send PAD parameters |

For TCP connections (transport type 8), the connection string format is
`P:username:server_address\0` where `P` = primary datacenter, `B` = backup.

---

## 4. Pipe Open Protocol

When the client wants to connect to a service (like LOGSRV), it sends a
**pipe open request** on pipe 0.

### 4.1 Client Request (pipe 0, routing = 0x0000)

```
 0000    0000    PipeIdx   ServiceName\0   VerParam\0   Version
[2 LE]  [2 LE]  [2 LE]   [string]        [string]     [4 LE]
```

- **PipeIdx**: Client's chosen pipe index for this service
- **ServiceName**: ASCII name (e.g., `LOGSRV`, `DIRSRV`)
- **VerParam**: Version parameter string
- **Version**: uint32 service version number

### 4.2 Server Response — Select Protocol (confirmed working)

New pipes start in **"Select"** transport mode. The server must respond using
**continuation frame format** (PipeHdr bit 5 set, bit 4 clear). Using
has_length format causes a misroute in the client.

Response content (8 bytes, sent on the pipe being opened):

```
 Routing    Command    ServerPipeIdx   Error
[2 LE]     [2 LE]     [2 LE]          [2 LE]
 =pipe_idx  =0x0001    =pipe_idx       =0x0000
```

- **Routing**: The client's pipe index (for MOSCP's internal routing)
- **Command**: 0x0001 = "pipe open success" handler
- **ServerPipeIdx**: Server's pipe index (mirror the client's)
- **Error**: 0x0000 = success

This triggers MOSCP's handler table -> handler 1 -> CMD 7 to MOSCL -> unblocks
the client's `PipeObj_OpenAndWait`.

---

## 5. Service Protocol (MPC RPC)

Once a pipe is open, the client and server exchange **host blocks** — the MPC
service-level message format.

### 5.1 Host Block Format

```
 Selector   Opcode    RequestID (VLI)    Payload
[1 byte]   [1 byte]  [1-4 bytes]        [variable]
```

- **Selector** (byte 0): Routes the message to the correct service handler.
  Assigned during service discovery (section 5.2). The reply **must** echo the
  same selector the client used, or the message is silently dropped.
- **Opcode** (byte 1): Method/operation code within the service. The reply
  **must** echo the same opcode from the request.
- **RequestID**: Variable-length integer identifying the specific request.
  The reply **must** echo the same ID.

### 5.2 Variable-Length Integer (VLI)

| Top 2 bits | Length | Max value | Encoding |
|------------|--------|-----------|----------|
| 00xxxxxx | 1 byte | 63 | `byte & 0x3F` |
| 10xxxxxx | 2 bytes | 16,383 | `(b[0] & 0x3F) << 8 | b[1]` |
| 11xxxxxx | 4 bytes | 1,073,741,823 | `(b[0..3]) & 0x3FFFFFFF` |

### 5.3 Service Discovery (confirmed working)

After a pipe is opened, the server sends a **discovery block** — a host block
with selector = 0x00, opcode = 0x00. The payload is a table of **17-byte
records**, each mapping a COM interface IID to a 1-byte selector:

```
 IID (Windows LE layout)   Selector
[16 bytes]                 [1 byte]
```

The IIDs must be in **Windows in-memory byte order** (little-endian for the
first three fields of the GUID), because the client resolves them with
`memcmp()` against compiled-in GUID constants.

The client will not issue any RPC requests until the discovery block has
mapped its requested IID to a selector. For LOGSRV, the login path requests
IID `{00028BC2-0000-0000-C000-000000000046}`.

### 5.4 Three-Level Reply Routing (confirmed by decompilation)

When the client receives a host block reply, it routes through three levels:

1. **Selector** (byte 0): Looked up in the session's service handler map
   (populated from the discovery block). If not found -> silently dropped.
2. **RequestID** (VLI): Looked up in the service handler's pending-request
   map. Routes to the specific in-flight request object.
3. **Opcode** (byte 1): Verified against the request object's stored opcode.
   Must match exactly or the reply is discarded.

**Consequence**: The reply must echo all three values from the client's
request. Getting any one wrong causes a silent drop with no error.

### 5.5 Service Data on the Wire

All service data travels through pipe 0 with a 2-byte LE routing prefix
(the logical pipe index). So a complete service message on the wire is:

```
[pipe-0 frame header]
  [routing_prefix:2LE = logical_pipe_idx]
    [host_block: selector | opcode | VLI_request_id | tagged_payload]
```

---

## 6. Tagged Parameter System

Request and reply payloads use a **tagged parameter** scheme (TLV-like).
Each parameter has a 1-byte tag, an optional length, and data.

### 6.1 Tag Types

| Tag & 0x8F | Name | Size | Description |
|------------|------|------|-------------|
| 0x81 | Byte | 1 | Fixed 1-byte value |
| 0x82 | Word | 2 | Fixed 2-byte value (LE) |
| 0x83 | Dword | 4 | Fixed 4-byte value (LE) |
| 0x84 | Variable | length-prefixed | Variable-length data |
| 0x85 | Dynamic start | length-prefixed | Start of streamed data |
| 0x86 | Dynamic more | length-prefixed | More streamed data follows |
| 0x87 | Dynamic last | 0 | End of static section / last chunk marker |
| 0x88 | Dynamic complete | length-prefixed | Transfer complete |
| 0x8F | Error | 4 | Server error code (uint32 LE) |

### 6.2 Length Encoding (for variable/dynamic tags)

For tags 0x84-0x88, the length byte uses bit 7 as a flag:

- **Bit 7 set**: Inline 7-bit length (`byte & 0x7F` = length, max 127)
- **Bit 7 clear**: 15-bit big-endian length across two bytes
  (`(b[0] & 0x7F) << 8 | b[1]`, max 32767)

### 6.3 Parameter Matching

Each client request pre-registers up to **16 send** and **16 receive**
parameter descriptors, each with a type tag. The server's response tags are
matched sequentially against the registered receive descriptors. Send
parameters must be added before receive parameters.

Additionally, the client **auto-adds a completion slot** (tag 0x84) after all
registered receive parameters. The server should NOT include data for this
slot — completion triggers automatically when data runs out after tag 0x87.

### 6.4 Server Error Codes (tag 0x8F)

| Code | Description |
|------|-------------|
| 0xE0000001 | Client parameter type mismatch |
| 0xE0000002 | Buffer not formatted per MPC rules |
| 0xE0000003 | Problem adding/sending parameters |
| 0xE0000004 | Method not registered on server |
| 0xE0000005 | Memory error |
| 0xE0000006 | Bug in MPC code |
| 0xE0000007 | Invalid parameter |
| 0xE0000008 | Error during send |
| 0xE0000009 | Error during upload block receive |
| 0xE000000A | Application asserted |

---

## 7. Login Handshake (LOGSRV)

This is the complete sequence to get the client past "Verifying account..."
and into a signed-in state. Confirmed working end-to-end.

### 7.1 Full Sequence

```
 Step  Direction        What
 ──────────────────────────────────────────────────────────────
  1    Client->Server   0x0D (bare CR)
  2    Server->Client   "COM\r"
  3    Server->Client   Transport params (type-3 control frame)
  4    Client->Server   Control type 4 (connection signal)
  5    Client->Server   Control type 1 (connection request)
  6    Server->Client   Control type 1 echo (echo payload back)
  7    Client->Server   Pipe open for LOGSRV, version 6
  8    Server->Client   Pipe open response (Select protocol, cmd=1)
  9    Server->Client   LOGSRV discovery block (IID->selector map)
  10   Client->Server   Login RPC request
  11   Server->Client   Login RPC reply
  ──────────────────────────────────────────────────────────────
       Result: GUIDE icon appears in system tray. Client is logged in.
```

### 7.2 Step 6: Control Type 1 Echo

The server echoes back the client's control type 1 payload verbatim.
The client will not proceed to open service pipes until this is received.

### 7.3 Step 8: Pipe Open Response

See section 4.2. Must use continuation frame format, command 0x0001.

### 7.4 Step 9: Discovery Block

Host block with selector=0x00, opcode=0x00, request_id=0. Payload is a table
of 17-byte records. For LOGSRV, the working server sends 10 IID records:

| IID | Selector |
|-----|----------|
| {00028BB6-...-46} | 0x01 |
| {00028BB7-...-46} | 0x02 |
| {00028BB8-...-46} | 0x03 |
| {00028BC0-...-46} | 0x04 |
| {00028BC1-...-46} | 0x05 |
| **{00028BC2-...-46}** | **0x06** |
| {00028BC3-...-46} | 0x07 |
| {00028BC4-...-46} | 0x08 |
| {00028BC5-...-46} | 0x09 |
| {00028BC6-...-46} | 0x0A |

The client requests IID `{00028BC2-0000-0000-C000-000000000046}` for the login
interface, which maps to selector **0x06**.

### 7.5 Step 10: Login Request

The client sends a host block on the LOGSRV pipe:

```
Selector:   0x06  (from discovery map for IID 28BC2)
Opcode:     0x00  (login method)
RequestID:  0x00  (first request)
Payload:    tagged parameters
```

Tagged send parameters:
- Tag 0x03: 4-byte "version of last update" value
- Tag 0x04: 0x58-byte login blob (contains username + password)

Registered receive parameters (what the client expects back):
- 7x tag 0x83 (fixed 4-byte dwords)
- 1x tag 0x84 (variable, 16-byte buffer)
- 1x tag 0x84 (auto-added completion slot — do NOT send data for this)

### 7.6 Step 11: Login Reply (confirmed working)

The server replies with a host block that echoes the request's routing:

```
Selector:   0x06  (same as request)
Opcode:     0x00  (same as request)
RequestID:  0x00  (same as request)
Payload:
  [0x83][00 00 00 00]    field 0: login result (0 = success)
  [0x83][00 00 00 00]    field 1: zero
  [0x83][00 00 00 00]    field 2: zero
  [0x83][00 00 00 00]    field 3: zero
  [0x83][00 00 00 00]    field 4: zero
  [0x83][00 00 00 00]    field 5: zero
  [0x83][00 00 00 00]    field 6: zero
  [0x87]                 end of static section
  [0x84][90][16 zero bytes]   variable field (16 bytes, all zero)
```

The first dword (field 0) is the login result code. Values 0x00 and 0x0C
both mean success. The 0x87 tag ends the static section. The 0x84 variable
field uses the reply-side length encoding (0x90 = 0x80 | 16 = inline length
16). Do NOT include a second 0x84 for the auto-added completion slot —
completion triggers automatically when data runs out.

### 7.7 Post-Login Behavior (observed, not fully understood)

After accepting the login reply:

1. Client sends a second LOGSRV request (selector=0x07, request_id=1,
   payload=tag 0x85 — possibly requesting streamed data)
2. Client opens two **DIRSRV** pipes (directory service, version 7)
3. Client sends 1-byte `0x01` messages on all open pipes (unknown purpose —
   possibly keepalive or status probe)
4. If DIRSRV is not answered, client disconnects after ~90 seconds

---

## 8. Data Compression (from static analysis)

MPC supports compression for bulk data transfer:

- **MCI** (Microsoft Compression Interface): Client -> Server
- **MDI** (Microsoft Decompression Interface): Server -> Client

Compressed data is a sequence of independently-decompressible chunks:

```
[chunk_size:4LE][compressed_data: chunk_size bytes]
[chunk_size:4LE][compressed_data: chunk_size bytes]
...
```

Max uncompressed chunk size: 32KB (0x8000).

---

## 9. Known Services

| Service | Version | Description | Status |
|---------|---------|-------------|--------|
| LOGSRV | 6 | Login/authentication | Confirmed working |
| DIRSRV | 7 | Directory service (content browsing) | Pipe open confirmed |
| MEDVIEW | 0x1400800A | Content/page rendering (Multimedia Viewer) | From static analysis |
| CONFLOC | varies | Conference locator (chat) | From static analysis |
| CONFSRV | varies | Conference server (chat) | From static analysis |

---

## 10. Error Codes

### MCM (Marvel Connection Manager) Errors

| Code | Description |
|------|-------------|
| 1 | User cancelled |
| 2 | Busy signal |
| 3 | No dial tone |
| 4 | No carrier |
| 5 | Network error |
| 6 | No LOGIN service |
| 7 | Bad password |
| 8 | Bad user ID |
| 9 | InitMos() failed |
| 12 | Registry keys missing |
| 13 | Modem/TAPI error |
| 14 | Connection dropped |
| 15 | Modem busy/not found |

### HRESULT Facility

Custom facility code **0xB0B** (e.g., `0x8B0B0017` = bad password).

---

## 11. Registry Configuration

Key: `HKLM\SOFTWARE\Microsoft\MOS\Transport`

| Value | Default | Description |
|-------|---------|-------------|
| PacketSize | (from server) | Inbound packet buffer |
| PacketOutSize | (from server) | Outbound packet buffer |
| WindowSize | 16 | Sliding window size |
| AckBehind | 1 | Packets before forced ACK |
| AckTimeout | 600 | ACK timeout in ms |
| ArenaSize | 0x40000 | Shared memory size (256KB) |
| TransportPriority | — | Preferred transport |
| Latency | 0 | Artificial send delay (debug) |

Key: `HKLM\SOFTWARE\Microsoft\MOS\Connection` — connection settings.

Key: `HKLM\SOFTWARE\Microsoft\MOS\Debug\DisplayMcmErrors` — show error dialog.

---

## Appendix A: Client Binary Map

| Binary | Size | Role |
|--------|------|------|
| MPCCL.DLL | 88K | Core MPC protocol: pipes, services, tagged params |
| MOSCP.EXE | 68K | Transport engine at runtime: packets, CRC, modem handshake |
| MOSCL.DLL | — | Low-level pipe/session primitives, MosSlot IPC |
| ENGCT.EXE | 72K | Alternate transport engine (not loaded for dial-up/TCP) |
| GUIDE.EXE | 116K | Login manager, session lifecycle |
| MOSSHELL.DLL | 180K | Shell/tree navigation |
| CONFAPI.DLL | 24K | Chat/conferencing API |
| SACLIENT.DLL | 32K | System administration (users, groups) |
| MVTTL14C.DLL | 36K | Multimedia Viewer (content rendering) |

## Appendix B: Internal IPC (MOSCL.DLL <-> MOSCP.EXE)

Not needed for a server implementation, but documented for completeness.

Communication between the client libraries and the transport engine uses
**MosSlot** — a custom shared-memory mailslot (`"MosSlot"` file mapping,
`"MosArena"` mutex, 48 slots x 1KB each). Bulk pipe data goes through
`"ARENA.MOS"` shared memory (default 256KB).

### Command Types (Client -> Engine)

| Cmd | Name |
|-----|------|
| 0 | Register (with PID) |
| 4 | Write pipe data |
| 6 | Open pipe |
| 8 | Open connection |
| 0xA | Terminate |
| 0xB | Close pipe (abort) |
| 0xD | Close pipe |

### Command Types (Engine -> Client)

| Cmd | Name |
|-----|------|
| 1 | Registration OK |
| 3 | Pipe read ready |
| 5 | Pipe write done |
| 7 | Pipe open result |
| 9 | Connection status |
| 0xC | Pipe closed |
| 0xF | Connection event |
| 0x10 | Pipe reset |
