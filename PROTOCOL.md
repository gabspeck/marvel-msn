# MSN95 "Marvel" Wire Protocol

Reverse-engineered from MSN for Windows 95 client binaries (July 11, 1995)
using Ghidra decompilation and a custom emulated server. Login, directory
browsing (MSN Shell), and password change are confirmed working end-to-end.

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

---

## Glossary

Quick reference for the protocol's vocabulary. Terms are grouped by layer,
bottom-up. The patent (US 5,956,509) names are given in parentheses where
they differ from names used in this document.

### Physical / Transport

| Term | What it is |
|------|------------|
| **Connection** | A single physical link — TCP socket or modem serial line. One connection carries everything. Handle type: `HMCONNECT` (WORD). |
| **Packet** | The atomic unit on the wire. Header (SeqNo + AckNo) + payload + CRC-32 + 0x0D terminator. Max ~600 bytes at default MTU. See §1. |
| **Byte stuffing** | Escape encoding that keeps reserved bytes (0x0D, 0x1B, etc.) out of the payload. The wire never contains a bare 0x0D except as a packet terminator. See §1.3. |
| **Sliding window** | Go-Back-N ARQ flow control. The sender may have up to *WindowSize* unacknowledged packets in flight. The receiver ACKs cumulatively. See §1.6. |
| **ACK / NACK** | Acknowledgement / negative-acknowledgement packets (first byte 0x41 / 0x42). ACKs piggyback on data packets too. |
| **Transport engine** | The process that owns the physical connection and runs the packet state machine. At runtime this is **MOSCP.EXE**; the codebase also contains **ENGCT.EXE**, an alternate engine not loaded for dial-up or TCP. |

### Pipe Multiplexing

| Term | What it is |
|------|------------|
| **Pipe** | A logical bidirectional channel between client and server, multiplexed inside a single connection. Think of it like a TCP port number inside a single TCP stream — many independent conversations share one wire. Each pipe carries traffic for one service instance. Handle type: `HMPIPE` (WORD). Pipe index range: 0–15. The patent calls these **"segments"**. |
| **Pipe 0** | The physical carrier pipe. All logical pipe traffic is routed through pipe 0 using a 2-byte LE routing prefix. Routing 0x0000 = pipe-open request, 0xFFFF = control frame, anything else = data for that pipe index. See §2.2. |
| **Pipe frame** | A single chunk of pipe data inside a packet payload. Has a 1-byte header (pipe index + flags) and variable-length content. Multiple frames for different pipes can share one packet. The patent calls these **"segment headers"**. See §2.1. |
| **Pipe open** | The handshake to create a new logical pipe for a service. Client sends a request on pipe 0 (routing 0x0000) naming the service; server responds with a Select Protocol reply. See §4. |
| **Pipe close** | A 1-byte `0x01` message sent on a pipe to signal teardown. During sign-out, the client closes all pipes in sequence (DIRSRV first, LOGSRV last). |
| **Control frame** | A pipe-0 message with routing 0xFFFF. Used for connection-level signaling: type 1 = connection params exchange, type 3 = transport negotiation, type 4 = connection established. See §2.3. |

### Session / Service

| Term | What it is |
|------|------------|
| **Session** | The authenticated context between login and sign-out. One connection has one session. Handle type: `HMSESSION` (WORD). The session starts when LOGSRV login succeeds and ends when all pipes close. |
| **Service** | A named server-side endpoint that the client connects to via a pipe. Examples: `LOGSRV` (login), `DIRSRV` (directory/content browsing). Each service has its own pipe(s) and its own set of RPC methods. The patent calls these **"service objects"**. See §9. |
| **MPC** | **Marvel Protocol Client** — the overall RPC framework implemented by MPCCL.DLL. Encompasses the service model, host blocks, tagged parameters, and the discovery mechanism. The patent calls the wire format the **"Remote Procedure Layer"**. |
| **MosSlot** | Shared-memory IPC (`"MosSlot"` file mapping, 48 slots × 1KB) used by client libraries (MOSCL.DLL) to send commands to the transport engine (MOSCP.EXE). Not on the wire — purely intra-machine. See Appendix B. |
| **ARENA.MOS** | Shared memory region (default 256KB) for bulk pipe data transfer between MOSCL.DLL and MOSCP.EXE. Also purely intra-machine. |

### Service RPC (Host Blocks)

| Term | What it is |
|------|------------|
| **Host block** | The MPC message format for service RPCs. Structure: selector + opcode + request_id + tagged payload. This is what travels inside pipe data. The patent calls these **"messages"** (FIG. 8A). See §5.1. |
| **Selector** | A 1-byte routing ID that maps to a COM interface within a service. Assigned by the server during discovery (§5.3). The client obtained IID `{00028BC2-...}` → selector 0x06 for LOGSRV login. The patent calls this the **"Service Interface ID"**. Replies must echo the request's selector or they are silently dropped. |
| **Opcode** | The method number within a service interface. Byte 1 of a host block. Example: LOGSRV selector 0x06 opcode 0x00 = login, opcode 0x07 = enumerator. The patent calls this the **"Method ID"**. Replies must echo the request's opcode. |
| **Request ID** | A VLI-encoded identifier for a specific in-flight RPC call. The client picks it (typically incrementing), and the server must echo it in the reply so the client can match it to the waiting request object. The patent calls this the **"Method Instance ID"**. See §5.2. |
| **Discovery block** | The server's first message on a newly-opened pipe: a host block with selector=0, opcode=0 containing a table of 17-byte records (16-byte IID + 1-byte selector). This is how the client learns which selector byte to use for each COM interface. See §5.3. |
| **Tagged parameter** | TLV-like data encoding for RPC payloads. Each parameter has a 1-byte type tag (0x81–0x8F), an optional length, and data. Types include fixed-size (byte/word/dword), variable-length blobs, streamed "dynamic" data, and error codes. See §6. |
| **VLI** | **Variable-Length Integer** — a compact encoding where the top 2 bits of the first byte select 1/2/4-byte form. Used for request IDs and some length fields. See §5.2. |
| **Dynamic data** | A streaming transfer mode within tagged parameters. Tags 0x85 (start), 0x86 (more), 0x87 (last/end) allow large or open-ended data to be delivered incrementally rather than in a single blob. |

### Hierarchy Summary

```
Connection (physical TCP/modem link)
 └─ Session (authenticated login context)
     └─ Pipe 3: LOGSRV ──── host blocks with tagged params
     └─ Pipe 4: DIRSRV ──── host blocks with tagged params
     └─ Pipe 5: DIRSRV ──── host blocks with tagged params
     └─ ...up to 15 pipes
```

One connection, one session, many pipes. Each pipe is an independent RPC
channel to a service. All pipe data is multiplexed through pipe 0 on the
wire and demultiplexed by the transport engine.

---

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

Sent by the server immediately after the modem handshake. Five uint32 LE values
(optionally six with Keepalive):

```
 PacketSize  MaxBytes  WindowSize  AckBehind  AckTimeout  [Keepalive]
[4 bytes]   [4 bytes] [4 bytes]   [4 bytes]  [4 bytes]   [4 bytes optional]
```

The client takes the **minimum** of each server value and its own configured
maximum. Keepalive is only present if the frame exceeds 0x18 (24) bytes.

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

Tags use bit 7 to distinguish direction: **reply tags** (server -> client)
have bit 7 set (0x81–0x8F), **send tags** (client -> server) have bit 7
clear (0x01–0x05). The low nibble encodes the same type in both directions.

**Reply tags** (bit 7 set — in server responses):

| Tag | Name | Size | Description |
|-----|------|------|-------------|
| 0x81 | Byte | 1 | Fixed 1-byte value |
| 0x82 | Word | 2 | Fixed 2-byte value (LE) |
| 0x83 | Dword | 4 | Fixed 4-byte value (LE) |
| 0x84 | Variable | length-prefixed | Variable-length data |
| 0x85 | Dynamic start | length-prefixed | Start of streamed data |
| 0x86 | Dynamic more | length-prefixed | More streamed data follows |
| 0x87 | Dynamic last | 0 | End of static section / last chunk marker |
| 0x88 | Dynamic complete | to end of host block | Transfer complete (all remaining bytes are data) |
| 0x8F | Error | 4 | Server error code (uint32 LE) |

**Send tags** (bit 7 clear — in client requests):

| Tag | Name | Size | Description |
|-----|------|------|-------------|
| 0x01 | Byte | 1 | Fixed 1-byte value |
| 0x02 | Word | 2 | Fixed 2-byte value (LE) |
| 0x03 | Dword | 4 | Fixed 4-byte value (LE) |
| 0x04 | Variable | length-prefixed | Variable-length data |
| 0x05 | Dynamic | length-prefixed | Dynamic/streamed data |

In a client request payload, send tags (with data) come first, followed by
**receive descriptors** — tags with bit 7 set but no data — declaring what
types the client expects in the reply. For example, a payload ending with
`0x83 0x83 0x85` means "I expect two dwords then a dynamic section."

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

### 7.7 Password Change (LOGSRV Opcode 0x01) (confirmed working)

Triggered by the user via Tools > Password in the MSN client.

**Request** (host block on LOGSRV pipe):

```
Selector:   0x06  (from discovery map for IID 28BC2)
Opcode:     0x01  (password change method)
RequestID:  0x00
Payload:
  [0x04][91][17 bytes]   current password (NUL-terminated, 17-byte buffer)
  [0x04][91][17 bytes]   new password (NUL-terminated, 17-byte buffer)
  [0x83]                 receive descriptor: expects one dword back
```

Both passwords are sent as send-side variable params (tag 0x04) in fixed
17-byte buffers. The password string is NUL-terminated; bytes after the NUL
are uninitialized buffer contents. Length byte 0x91 = 0x80 | 17 (inline
length 17).

**Reply**:

```
Selector:   0x06  (same as request)
Opcode:     0x01  (same as request)
RequestID:  0x00  (same as request)
Payload:
  [0x83][XX XX XX XX]    result code (uint32 LE)
```

- Result `0x00000000` = success. The dialog closes.
- Any non-zero value = failure. The client shows "Cannot change password.
  The current password is not valid. Please type it again." (same message
  regardless of the specific non-zero value).

### 7.8 Post-Login Behavior (confirmed by wire capture)

After accepting the login reply, the client enters a setup phase:

1. **LOGSRV enumerator** (T+0.3s): Client sends LOGSRV selector=0x07,
   req_id=1, payload=tag 0x85. This is a long-lived enumerator request —
   the server must NOT reply or the client spins (see §7.8). The request
   stays pending until sign-out.

2. **DIRSRV pipe opens** (T+0.9s–1.4s): Client opens **four** DIRSRV pipes:
   - Pipes 4,5 with version string `"Uagid=0"` (agent-qualified)
   - Pipes 6,7 with version string `"U"` (bare)
   Each gets a pipe-open response and a discovery block.

3. **DIRSRV requests** (T+1.5s): Pipes 6 and 7 each send a DIRSRV request
   (class=0x01, selector=0x02, req_id=0) with identical tagged payloads.
   Pipes 4 and 5 remain idle — they may be reserved for UI-triggered
   directory browsing that never happens.

4. **Idle**: No traffic until user signs out.

### 7.9 LOGSRV Enumerator (Opcode 0x07) — Critical Behavior

The LOGSRV opcode 0x07 request creates a **MosEnumeratorLoop** thread
in GUIDE.EXE that calls `WaitForMessage` in a loop, waiting for streamed
items. The completion object's `+0x18` flag controls the loop:

- `+0x18 = 0` → WaitForMessage blocks on `MsgWaitForSingleObject(INFINITE)` — correct
- `+0x18 = 1` → WaitForMessage returns immediately with "more data" — CPU spin

If the server replies with any host block (even a bare 0x87 end marker),
`ProcessTaggedServiceReply` sets `+0x18 = 1` permanently, signaling
"transfer complete". The loop then spins at 80% CPU.

**Server rule**: Do NOT reply to LOGSRV enumerator requests (opcode 0x07).
Leave the request pending.

### 7.10 Sign-Out Sequence (confirmed by wire capture)

Sign-out is a ~285ms burst initiated by the client:

```
 T+0ms    pipe-close 0x01 on pipe 6 (DIRSRV)
 T+44ms   pipe-close 0x01 on pipe 4 (DIRSRV)
 T+88ms   pipe-close 0x01 on pipe 7 (DIRSRV)
 T+132ms  pipe-close 0x01 on pipe 5 (DIRSRV)
 T+184ms  LOGSRV selector=0x07, payload=0x0F (sign-off notification)
 T+284ms  pipe-close 0x01 on pipe 3 (LOGSRV)
 T+285ms  All pipes closed → connection drops
```

Key observations:
- **DIRSRV pipes close first**, LOGSRV pipe closes last
- Pipe close order is not sequential (6→4→7→5), possibly reflecting
  internal cleanup order in MOSSHELL
- A **second LOGSRV opcode 0x07** is sent just before closing pipe 3,
  with payload `0x0F` instead of `0x85` — likely a "sign-off" notification
- The server does not need to reply to any sign-out messages; the client
  tears down unilaterally
- After all pipes close, GUIDE.EXE's CleanupThread drains `g_cOpenSessions`
  and the process exits (takes a few seconds due to polling)

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

## 9. Directory Browsing (DIRSRV) (confirmed working)

DIRSRV provides the content tree that MOSSHELL.DLL renders in the MSN Shell
window. After login, the client opens four DIRSRV pipes and queries the root
node to build the navigation tree.

### 9.1 Discovery

DIRSRV has one interface:

| IID | Selector |
|-----|----------|
| {00028B27-0000-0000-C000-000000000046} | 0x01 |

### 9.2 GetProperties Request

The client sends a host block with selector=0x01, opcode=0x02:

```
Selector:    0x01  (from discovery)
Opcode:      0x02  (GetProperties method)
RequestID:   0x00
Payload:
  [0x04][variable]    node ID (LARGE_INTEGER, 8 bytes: lo:u32 + hi:u32)
  [0x01][byte]        flags (0x00 = self-properties, 0x01 = children)
  [0x03][dword]       unknown (often 0 or 1)
  [0x03][dword]       property count hint
  [0x04][variable]    property group (NUL-separated property names)
  [0x04][variable]    locale string
  [0x83][0x83][0x85]  receive descriptors: two dwords + dynamic section
```

The **node ID** `0:0` (all zeros) is the root. For child nodes, the client
sends the node ID from the parent's property records.

The **property group** is a NUL-separated list of property name strings.
Known property names for children queries: `a`, `c`, `h`, `b`, `e`, `g`,
`x`, `mf`, `wv`, `tp`, `p`, `w`, `l`, `i`.

### 9.3 GetProperties Reply

```
Payload:
  [0x83][XX XX XX XX]    status (0 = success)
  [0x83][XX XX XX XX]    node count
  [0x87]                 end of static section
  [0x88]                 dynamic complete — all remaining bytes are raw data
  [property records...]  concatenated SVCPROP records
```

Tag 0x88 signals "transfer complete". The client's `ReadDynamicSectionRawData`
(MPCCL.DLL @ 0x04605809) reads **all remaining host-block bytes** as raw data
after the 0x88 tag. Do NOT prefix the dynamic data with a length — it would
corrupt the property record parsing.

### 9.4 Property Record Format (SVCPROP.DLL)

Parsed by `FDecompressPropClnt` (SVCPROP.DLL @ 0x7f641592):

```
 TotalSize   PropCount   Properties...
[4 LE]      [2 LE]      [variable]
```

Each property within a record:

```
 Type    Name\0          ValueData
[1 byte][NUL-string]    [variable, type-dependent]
```

**Property types** (from `DecodePropertyValue` @ 0x7f64143a):

| Type | Name | Value size | Description |
|------|------|------------|-------------|
| 0x01 | byte | 1 | uint8 |
| 0x02 | word | 2 | uint16 LE |
| 0x03 | dword | 4 | uint32 LE |
| 0x04 | int64 | 8 | int64 LE |
| 0x0A | string | compressed | Compressed string (MCI/MDI) |
| 0x0E | blob | 4 + data | `[length:u32][data]` |

### 9.5 Known Properties

| Name | Type | Meaning |
|------|------|---------|
| `p` | blob (0x0E) | Display name (e.g., "MSN Central") |
| `c` | dword (0x03) | Child count |
| `h` | dword (0x03) | Has children flag |
| `a` | dword (0x03) | Attributes |
| `q` | dword (0x03) | Quick-check (node exists probe) |
| `i` | dword (0x03) | Icon index |
| `g` | dword (0x03) | Group flag |
| `wv` | blob (0x0E) | Content view data |
| `tp` | blob (0x0E) | Type/template |
| `w` | blob (0x0E) | Unknown blob |
| `l` | blob (0x0E) | Unknown blob |

---

## 9a. Signup Wizard (SIGNUP.EXE) (confirmed working)

SIGNUP.EXE runs the new-account wizard in its own process (hosting
BILLADD.DLL for payment-method entry) and drives several services over
the same MPC transport the main shell uses.  The wizard finishes when
the "Congratulations! You are now a member!" dialog (resource id
`0x3e8`) appears.

### 9a.1 End-to-end sequence

After the user clicks Submit on the credentials page, the client
performs a fixed sequence.  All of these must succeed or the wizard
bails silently without showing Congrats:

```
 1. OLREGSRV commit         — class=0x01 sel=0x01 + three 0xE7/0xE6 one-way frames
 2. LOGSRV sel=0x0D         — post-signup query (country id)
 3. LOGSRV sel=0x02         — post-transfer query (opens a fresh pipe)
 4. FTM selector 0x00 + 0x03 loop for the four signup RTFs
 5. Internet-access prompt (resource 0x44c) → phone-book picker (PBKDisplayPhoneBook)
 6. Congrats dialog (resource 0x3e8)
```

The commit itself succeeds as soon as the class=0x01 sel=0x01 head is
acked with `HRESULT=0` (a single `0x83` dword tag); the three 0xE7/0xE6
continuation frames are one-way and MUST NOT be acked.  See §9a.3.

### 9a.2 LOGSRV signup selectors

These share LOGSRV's IID→selector map (interface `{00028BC2-...}` at
selector `0x06`, same as login) and are only issued from SIGNUP.EXE.

| Selector | Method | Payload | Reply |
|----------|--------|---------|-------|
| 0x02 | Post-transfer query | three dwords (counter, 0, 0) + recv `0x84` | empty `0x84` variable |
| 0x07 | Product-details query | single recv `0x85` | empty `0x84` variable |
| 0x0A | Billing/account info | none | 0x41c (1052) byte buffer in a `0x84` variable (see §9a.5) |
| 0x0B | PM commit (Payment Options → Payment Method OK) | 0x11c PM buffer | `0x84` var, first dword = status (see §9a.5b) |
| 0x0C | OI commit (Payment Options → Name and Address OK) | 0x2fc OI buffer, fragmented as 0xE6/0xE7 one-way continuations | `0x84` var, first dword = status (see §9a.5b) |
| 0x0D | Post-signup query | three dwords (country_id, 0, 0) + recv `0x84` | empty `0x84` variable |

Selectors 0x02/0x07/0x0D have not been RE'd in the COM proxy layer;
an empty `0x84` variable is the minimum well-formed reply that
satisfies the recv descriptor and lets the client's unmarshaller
proceed.  Returning `None` (unhandled selector) on any of them causes
the client to disconnect and the wizard to close without Congrats —
selector 0x0D is the one that specifically gates the Internet-access
prompt and Congrats dialog.

### 9a.3 OLREGSRV commit (Submit button)

SIGNUP.EXE dispatches a single MOSRPC call that serializes as four
records on the wire, in this order:

```
 class=0x01 sel=0x01   payment method (card number, expiry, name)   — call head
 class=0xE7 sel=0x01   member ID + password                         — one-way
 class=0xE6 sel=0x02   personal name + company                      — one-way
 class=0xE7 sel=0x02   street address + phone                       — one-way
```

Only the `class=0x01` head expects a reply.  Reply payload is a single
`0x83` dword HRESULT:

```
[0x83][00 00 00 00]   HRESULT = 0 (success)
```

The proxy copies this dword into its status word before its
post-commit switch runs; success steers to `case 0` which produces
`result_code = 0x19` and unblocks the credentials page's modal wait
(`DispatchSignupCommitAndWait` @ `0x004063de` in SIGNUP.EXE).

Replying to the `class=0x01 sel=0x02` pre-check that precedes the
commit aborts signup with "An important part of signup cannot be
found" — that selector must return `None`.

### 9a.4 FTM — signup RTF loop

FTM implements two request selectors (both use the `FtmClientFileId`
60-byte send buffer via tag 0x04):

| Selector | Name | Used by |
|----------|------|---------|
| 0x00 | `HrRequestDownload` | billing, signup RTFs |
| 0x03 | `HrBillClient` (fast-path) | billing, signup RTFs |

During signup, the wizard runs this loop four times:

- Name in the CFI = the literal string `"LOGSRV"` (not a filename).
- Counter (`dword` at CFI offset `40`) iterates `0..3`.
- Server maps the counter to one of `plans.txt`, `prodinfo.rtf`,
  `legalagr.rtf`, `newtips.rtf` — these are the four files
  `SIGNUP.EXE!FUN_004029d8` opens with `CreateFile(OPEN_EXISTING)`
  next to its own module path and fails if any is missing.
- Server puts the real filename into the sel=0x00 reply at offset
  `+40`, with reply flag `0x0B` (bits 0, 1, 3 = has compressed size,
  fast path, has filename override).  HrInit appends the override
  to the client download dir to form the final local path.
- Sel=0x00 reply is 72 bytes in a `0x84` variable.  Sel=0x03 reply
  is an 18-byte header + inline content bytes (WriteFile'd to the
  local file handle by the client).

Empty RTF content is acceptable — the client's RichEdit silently
renders an empty document, which is enough for the wizard to
progress.

### 9a.5 LOGSRV billing info (selector 0x0A)

Opened when the user clicks Tools → Billing → Payment Method in the
authenticated shell.  Reply is a single `0x84` variable containing a
0x41c (1052) byte buffer:

```
 Offset 0x000: dword status (0 = success)
 Offset 0x008: Order Information (address) — NUL-terminated strings at:
   +0x3B  First name            +0x1D8 Address line
   +0x69  Last name             +0x201 City
   +0x1D0 Country ID (dword)    +0x253 State
                                +0x27C ZIP code
                                +0x2BD Phone
 Offset 0x300: Payment Method (0x11c bytes):
   +0x00  Type dword (1=CHARGE, 2=DEBIT, 3=DIRECTDEBIT)
   +0x19  Card number string
```

### 9a.5b LOGSRV billing commit (selectors 0x0B and 0x0C)

Opened when the user clicks OK in Tools → Billing → Payment Options
after editing Payment Method (→ sel=0x0B) or Name and Address
(→ sel=0x0C) in the authenticated shell.  Both call sites are twins
in BILLADD.DLL (`BillingDlg_CommitPM` @ `0x00434b81`,
`BillingDlg_CommitOI` @ `0x00434953`) — the only differences are the
method index (0xB vs 0xC) and the input buffer (0x11c PM vs 0x2fc
OI).

The OI buffer is large enough to exceed one MPC frame, so sel=0x0C
arrives as a `class=0x06` head with a 7-byte envelope followed by
`class=0xE6` and `class=0xE7` continuation frames carrying the OI
data.  Same convention as §9a.3: only the head expects a reply,
continuation frames are one-way and MUST NOT be acked — the server's
LOGSRV dispatcher drops any frame with the `0xE0` class bits set.

Reply to the head is a `0x84` variable whose first dword is the
commit status.  A `0x83` dword reply hangs the post-wait check: the
proxy's `output_descriptor->m10()` must return 4 (VAR) or
`BillingDlg_ProcessCommitReply` is skipped and the caller shows
"Your account information cannot be updated at this time."

```
[0x84][len][status_dword][...]
  status = 0      → silent success, dialog dismisses
  status = 0x1e   → MessageBox with string ID 0x134
  status = 0x1f   → MessageBox with string ID 0x135
  anything else   → "cannot be updated" error dialog
```

Minimal successful reply: `0x84` var of 4 NUL bytes.

### 9a.6 Known wizard-flow gotchas

- **Pipe re-use**: sel=0x02 is called on a *fresh* LOGSRV pipe
  opened right after the FTM transfer finishes — not on the
  original login pipe.
- **Parallel replies**: sel=0x0D runs in parallel with the OLREGSRV
  one-way continuation frames.  The server must reply to sel=0x0D
  without waiting for the 0xE6/0xE7 frames to finish arriving.
- **DIRECTDEBIT form**: BILLADD.DLL has no dispatch for payment
  type 3 — `BillingPicker_UpdateVisibility` (`0x00433a63`), the
  init-fill, and the IDOK validator all only branch on types 1/2.
  Shipped disabled in this build.  Resolved 2026-04-12 by removing
  the DIRECTDEBIT line from `server/data/signup/plans.txt`; only
  CHARGE and BANK are offered now.
- **Post-Congrats session**: once the commit and FTM loop complete,
  SIGNUP.EXE disconnects from the server before Congrats renders.
  Congrats is shown entirely offline.  The authenticated session
  only appears when the user relaunches MSN (or reboots the VM).

---

## 10. Known Services

| Service | Version | Description | Status |
|---------|---------|-------------|--------|
| LOGSRV | 6 | Login/authentication, password change, signup queries, billing info | Confirmed working |
| DIRSRV | 7 | Directory service (content browsing) | Confirmed working |
| FTM | — | File Transfer Manager (signup RTF downloads, billing "plans") | Confirmed working |
| OLREGSRV | — | On-line registration (signup wizard Submit) | Confirmed working |
| MEDVIEW | 0x1400800A | Content/page rendering (Multimedia Viewer) | From static analysis |
| CONFLOC | varies | Conference locator (chat) | From static analysis |
| CONFSRV | varies | Conference server (chat) | From static analysis |

---

## 11. Error Codes

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

## 12. Registry Configuration

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
