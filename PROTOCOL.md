# MSN95 "Marvel" Wire Protocol

Reverse-engineered reference for the MSN for Windows 95 client (July 11, 1995).
Internal codename **"Marvel"**; RPC layer is **MPC** (Marvel Protocol Client).
Bespoke Microsoft stack — not DCOM, not PPP, not OSI. See US patent 5,956,509
for the original design sketch.

Companion docs: `docs/JOURNAL.md` (chronological findings), `TODO.md` (open
work), Ghidra project at `~/apps/MSN95.gpr`.

---

## 1. Overview

```
 Application     GUIDE.EXE, MOSSHELL.DLL, SIGNUP.EXE, CONFAPI.DLL
 Service RPC     MPCCL.DLL        — tagged-parameter host blocks
 Session/IPC     MOSCL.DLL        — MosSlot shared-memory IPC
 Transport       MOSCP.EXE        — framing, CRC, window, modem handshake
 Wire            TCP socket or serial modem
```

Hierarchy: one **Connection** → one **Session** → up to 16 **Pipes** →
per-pipe RPC traffic as **Host Blocks** containing **Tagged Parameters**.

ENGCT.EXE is an alternate transport engine shipped but not loaded for dial-up
or TCP — MOSCP.EXE handles both. Same wire format either way.

---

## 2. Transport (MOSCP)

### 2.1 Packet frame

```
 SeqNo    AckNo    Payload (byte-stuffed)    CRC-32     0x0D
[1]      [1]      [0..N]                    [4]        [1]
```

- SeqNo: bit 7 set for data; `0x41` = ACK-only, `0x42` = NACK. Bits 6-0 = seq.
- AckNo: bit 7 always set. Bits 6-0 = last-received + 1.
- Payload: pipe-multiplexed frames, byte-stuffed.
- CRC-32 of the already-encoded wire bytes; zone-3 masked after computation.
- Min packet: 7 bytes.

### 2.2 Byte stuffing (payload only)

Escape = `0x1B`. Raw → wire:

| Raw | Wire | Raw | Wire |
|-----|------|-----|------|
| 0x1B | 1B 30 | 0x0B | 1B 33 |
| 0x0D | 1B 31 | 0x8D | 1B 34 |
| 0x10 | 1B 32 | 0x90 | 1B 35 |
|      |       | 0x8B | 1B 36 |

### 2.3 Three-zone encoding

1. **Header** (SeqNo/AckNo): if post-bit7 value ∈ {0x8D, 0x90, 0x8B}, XOR 0xC0.
2. **Payload**: stuffing table above.
3. **CRC bytes**: OR 0x60 on any byte in the escape set.

### 2.4 CRC-32

Custom polynomial `0x248EF9BE`, init 0, no final XOR, `NOT` on the odd path.
Computed over wire bytes (zones 1+2 after encoding).

```c
if (c & 1) c = ~((c ^ 0x248EF9BE) >> 1); else c >>= 1;
```

### 2.5 Sliding window

Go-Back-N ARQ. 7-bit seq space. Default window 16, ACK timeout 6000ms,
AckBehind 1, max retransmits 12. On timeout: `w >>= 1` (min 1), resend
all unacked in order.

### 2.6 Special packets

| First byte | Type |
|-----------|------|
| 0x41 | ACK-only |
| 0x42 | NACK (byte 1 & 0x7F = last good seq) |
| other | DATA |

---

## 3. Pipe multiplexing

### 3.1 Pipe frame

```
 PipeHdr   [LenByte]   PipeData
[1]        [0-1]        [variable]
```

PipeHdr (after `decode_header_byte`):

| Bits | Mask | Meaning |
|------|------|---------|
| 3-0 | 0x0F | Pipe index (0-15) |
| 4 | 0x10 | has_length — next byte (& 0x7F) = content length |
| 5 | 0x20 | continuation — rest of packet belongs to this pipe |
| 6 | 0x40 | last_data — final fragment of this message |
| 7 | 0x80 | always set |

PipeData begins with a `uint16 LE` content-length prefix, then content bytes.

### 3.2 Pipe-0 routing

All logical pipe traffic multiplexes on **physical pipe 0**. First two bytes
of pipe-0 content are a routing prefix (uint16 LE):

| Routing | Meaning |
|---------|---------|
| 0x0000 | Pipe-open request |
| 0xFFFF | Control frame |
| other  | Data for that logical pipe index |

### 3.3 Control frames (routing 0xFFFF)

| Type | Meaning |
|------|---------|
| 1 | Connection request — server echoes payload back |
| 3 | Transport parameter negotiation (see 3.4) |
| 4 | Connection established |

### 3.4 Transport params (type 3)

Five or six `uint32 LE`: `PacketSize, MaxBytes, WindowSize, AckBehind,
AckTimeout, [Keepalive]`. Keepalive present only if frame > 0x18 bytes.
Client takes min of server value and its own configured max.

### 3.5 Multi-frame reassembly

When a single logical message (routing_prefix + host_block) exceeds
`PacketSize` (client default 0x400 = 1024 wire bytes), the sender splits
it across N continuation frames in N successive packets. Reassembly is
driven by the `uint16 LE` prefix on the first frame and the `last_data`
flag on the last — intermediate frames carry **no** length prefix.

```
Frame 1 (continuation, !last_data):
  PipeHdr | u16 LE total_pipe_data_len | chunk1

Frame 2..N-1 (continuation, !last_data):
  PipeHdr | chunk_i                            (no prefix)

Frame N (continuation, last_data):
  PipeHdr | chunk_N                            (no prefix)

Reassembled content = chunk1 ‖ chunk2 ‖ … ‖ chunk_N
                    = exactly total_pipe_data_len bytes
```

Client-side receiver is `MOSCP!WireReceiver_ProcessPacket` (Ghidra:
`FUN_7f45384f`), which keeps one per-pipe reassembly context at
`this + (pipe_idx+1)*4`. The context struct (alloc size 0x38 via
`FUN_7f45a519`) is initialised lazily on the pipe's first frame and
freed once a message is delivered (`*ctx = 0` for that slot). Relevant
fields (dword offsets; `puVar12[N]` = `ctx + N*4`):

| Offset | Field | Set by | Notes |
|--------|-------|--------|-------|
| +0x14 | `phase` (`puVar12[5]`) | state machine | 0=len-low, 1=len-high, 2=body |
| +0x08 | `total_len` (`puVar12[2]`) | phase 0→1 | Assembled u16 LE from frame 1 |
| +0x10 | `write_offset` (`puVar12[4]`) | unstuff worker | Running cursor |
| +0x28 | `alloc_ptr` (`puVar12[10]`) | phase 1 | `FUN_7f45a519(total_len + 5)` |
| +0x2C | `buffer_base` (`puVar12[0xb]`) | phase 1 | `alloc_ptr + 5` (5-byte internal header) |
| +0x18 | `escape_pending` (`puVar12[6]`) | unstuff worker | Set when last byte of frame is `0x1b` |

Phase transitions on the inbound byte stream (per pipe):
- **phase 0** (frame 1, first byte of u16): stash low byte into
  `total_len`, advance to phase 1.
- **phase 1** (frame 1, second byte of u16): combine `(high << 8) | low`
  into `total_len`, allocate `total_len + 5`, set `buffer_base`,
  advance to phase 2.
- **phase 2** (rest of frame 1 + all of frames 2..N): call the unstuff
  worker `FUN_7f452524(ctx, src, src_len)` which copies into
  `buffer_base[write_offset..]` until either `src_len` bytes are
  consumed or `write_offset == total_len`.

The context is retained across packets so long as `last_data` is clear;
a `last_data` frame ends the message, dispatches the buffer
(`PipeObj_DeliverData` if routing ≠ 0x0000/0xFFFF), and clears the slot.
Consequently only frame 1 carries a length prefix — subsequent frames
are raw unstuff input that feeds directly into the pre-allocated
`buffer_base`.

**Fatal failure mode** (observed 2026-04-18): if frame 1's prefix is
anything less than the true total, the buffer fills during frame 1 and
`write_offset == total_len` before the last frame arrives. The unstuff
worker then returns 0 consumed (dest full), `local_14` never
decrements, and `WireReceiver_ProcessPacket` spins forever re-invoking
unstuff on the same source pointer. Specifically, sending
`size_prefix = len(chunk1)` instead of `len(total)` hangs MOSCP in a
tight loop at frame 2's first unstuff call — do **not** use a per-frame
length convention here, and do **not** prefix frame 2 with its own u16
(those bytes get written into the buffer as data, skewing the payload).

The `continuation` bit (0x20) is set on every frame in the sequence;
`last_data` (0x40) is set only on frame N. Server sender at
`src/server/mpc.py::build_service_packet`.

---

## 4. Connection bring-up

### 4.1 Modem handshake

```
Client → 0x0D                          (bare CR)
Server → "COM\r"                       (switch to binary)
Server → type-3 control frame          (transport params)
Client → type-4 control frame          (connection signal)
Client → type-1 control frame          (connection request)
Server → type-1 echo                   (echo payload verbatim)
```

Any response other than `COM\r` within 20s aborts. `ENGCT.EXE` notes:
static analysis shows X.25 prompts (`AUSTPAC:`, `TELENET`, `please log in:`,
`please Sign-on:`, PAD 0xA3); not exercised at runtime.

For TCP: connection string `P:username:server_address\0` (`P`=primary,
`B`=backup datacenter).

### 4.2 Pipe open (pipe 0, routing 0x0000)

```
Client:
 0000   0000   PipeIdx   ServiceName\0   VerParam\0   Version
 [2LE]  [2LE]  [2LE]     [string]         [string]     [4LE]

Server (continuation frame — PipeHdr bit 5 set, bit 4 clear):
 Routing=pipe_idx   Cmd=0x0001   ServerPipeIdx=pipe_idx   Error=0x0000
 [2LE]              [2LE]         [2LE]                    [2LE]
```

Using has_length format instead of continuation format causes a misroute.

---

## 5. Service RPC (MPC)

### 5.1 Host block

```
 Selector   Opcode    RequestID (VLI)    Payload
 [1]        [1]       [1-4]              [variable]
```

Reply **must** echo selector, opcode, and request ID exactly. Any mismatch →
silent drop.

### 5.2 VLI (variable-length integer)

| Top 2 bits | Length | Max | Decode |
|-----------|--------|------|--------|
| 00 | 1 byte | 63 | `b & 0x3F` |
| 10 | 2 bytes | 16,383 | `(b0 & 0x3F) << 8 \| b1` |
| 11 | 4 bytes | 2³⁰-1 | `b0..b3 & 0x3FFFFFFF` |

### 5.3 Service discovery

First server message on a new pipe: host block with `selector=0x00,
opcode=0x00, request_id=0`. Payload is a table of 17-byte records:

```
 IID (Windows in-memory GUID layout)   Selector
 [16]                                   [1]
```

Client resolves via `memcmp` against compiled-in GUIDs; first three GUID
fields are little-endian. No RPCs are issued until the client's requested
IID has a selector mapped.

### 5.4 Three-level reply routing

Incoming replies route through: (1) selector → service handler map,
(2) VLI request ID → pending request slot, (3) opcode → stored opcode match.
Miss at any level → silent drop with no error.

### 5.5 Message classes

The `class` byte (at host-block offset 0, alias for "selector" in old
terminology) also carries framing flags for large requests:

| Class | Meaning |
|-------|---------|
| 0x01 | Normal call head (two-way) |
| 0x06 | Call head with continuation frames following |
| 0xE6 / 0xE7 | One-way continuation frames (drop if bit `0xE0` is set) |

Continuation frames (0xE6/0xE7) carry extra payload for the preceding call
head but expect **no reply**. Server must ignore them.

---

## 6. Tagged parameters

### 6.1 Tags

Send tags (client → server) have bit 7 clear; reply tags (server → client)
have bit 7 set. Low nibble = type.

| Send | Reply | Name | Size |
|------|-------|------|------|
| 0x01 | 0x81 | byte | 1 |
| 0x02 | 0x82 | word | 2 LE |
| 0x03 | 0x83 | dword | 4 LE |
| 0x04 | 0x84 | variable | length-prefixed |
| 0x05 | 0x85 | dynamic-start | length-prefixed |
|      | 0x86 | dynamic-more | length-prefixed |
|      | 0x87 | dynamic-last / end-of-static | 0 |
|      | 0x88 | dynamic-complete (rest of host block is raw) | — |
|      | 0x8F | error code | 4 LE |

In a client request, send tags with data come first, followed by **receive
descriptors** — bit-7-set tags with no data declaring expected reply types.
Up to 16 send and 16 receive descriptors per request. The client auto-adds
a final `0x84` completion slot — server must **not** send data for it.

### 6.2 Length encoding (tags 0x84–0x88)

| Byte 0 bit 7 | Format |
|--------------|--------|
| set | Inline 7-bit length (`byte & 0x7F`, max 127) |
| clear | 15-bit big-endian across two bytes (max 32767) |

### 6.3 Server error codes (tag 0x8F)

| Code | Meaning |
|------|---------|
| 0xE0000001 | Client parameter type mismatch |
| 0xE0000002 | Buffer not MPC-formatted |
| 0xE0000003 | AddParam/Send failure |
| 0xE0000004 | Method not registered |
| 0xE0000005 | Memory error |
| 0xE0000006 | MPC internal bug |
| 0xE0000007 | Invalid parameter |
| 0xE0000008 | Send error |
| 0xE0000009 | Upload-block receive error |
| 0xE000000A | Application asserted |

---

## 7. Services

| Service | Ver | Purpose | Status |
|---------|-----|---------|--------|
| LOGSRV | 6 | Login, password, signup queries, billing info | working |
| DIRSRV | 7 | Directory tree browsing (MOSSHELL) | working |
| FTM | — | File Transfer Manager (signup RTFs, billing plans) | working |
| OLREGSRV | — | Signup wizard Submit | working |
| ONLSTMT | 3 | Account statement (subscriptions, usage, plans) | working |
| MEDVIEW | 0x1400800A | Multimedia content viewer (MOSVIEW titles) | MVP (see `docs/MEDVIEW.md`) |
| CONFLOC | — | Conference locator (chat) | not implemented |
| CONFSRV | — | Conference server (chat) | not implemented |

### 7.1 LOGSRV

**IIDs (selector map sent in discovery block, 10 entries):**

| IID | Sel | Use |
|-----|-----|-----|
| {00028BB6-…-46} | 0x01 | — |
| {00028BB7-…-46} | 0x02 | — |
| {00028BB8-…-46} | 0x03 | — |
| {00028BC0-…-46} | 0x04 | — |
| {00028BC1-…-46} | 0x05 | — |
| **{00028BC2-…-46}** | **0x06** | Login interface (authoritative) |
| {00028BC3-…-46} | 0x07 | — |
| {00028BC4-…-46} | 0x08 | — |
| {00028BC5-…-46} | 0x09 | — |
| {00028BC6-…-46} | 0x0A | — |

All LOGSRV methods below run on selector **0x06**. Opcodes:

| Op | Method | Request | Reply |
|----|--------|---------|-------|
| 0x00 | Login | `0x03` dword (last-update ver) + `0x04` 0x58-byte login blob; recv: 7×`0x83`, 1×`0x84` (16) | 7 dwords, `0x87`, `0x84`(16 zero bytes). First dword = result (0 or 0x0C = success) |
| 0x01 | Change password | `0x04`×2 (17-byte NUL-terminated bufs for old/new) | `0x83` result (0 = success) |
| 0x02 | Post-transfer query (signup) | 3 dwords + recv `0x84` | empty `0x84` |
| 0x07 | Enumerator (post-login) | `0x85` | **DO NOT REPLY** — server leaves pending forever (see 7.1.1) |
| 0x07 | Sign-off notification | payload `0x0F` byte | no reply expected |
| 0x0A | Billing info fetch | none | `0x84` with 0x41C-byte Account buffer (see 7.1.2) |
| 0x0B | PM commit (billing Payment Method OK) | 0x11C PM buffer | `0x84` var, first dword = status (see 7.1.3) |
| 0x0C | OI commit (billing Name and Address OK) | 0x2FC OI buffer fragmented as 0x06 head + 0xE6/0xE7 continuations | `0x84` var, first dword = status (see 7.1.3) |
| 0x0D | Post-signup query | 3 dwords (country_id, 0, 0) + recv `0x84` | empty `0x84` |
| 0x0E | Phone-book update | `0x03` dword=8, recv `0x83` | `0x83` dword=0 stub (see Open Questions) |

#### 7.1.1 Opcode 0x07 enumerator

Creates a `MosEnumeratorLoop` thread calling `WaitForMessage` on the reply
completion. Replying (even a bare `0x87`) sets `+0x18 = 1` permanently →
`MsgWaitForSingleObject` returns instantly → 80% CPU spin. Leave pending.

#### 7.1.2 Billing info (selector 0x0A) — 0x41C-byte Account buffer

```
 0x000  dword status (0 = success)
 0x008  Order Information block
   +0x3B  First name        +0x1D0 Country ID (dword)
   +0x69  Last name         +0x1D8 Address line
                             +0x201 City
                             +0x253 State
                             +0x27C ZIP
                             +0x2BD Phone
 0x300  Payment Method block (0x11C bytes)
   +0x00  Type dword (1=CHARGE, 2=DEBIT, 3=DIRECTDEBIT)
   +0x19  Card number (ASCIIZ)
```

DIRECTDEBIT (type 3) has no client dispatch — `BillingPicker_UpdateVisibility`
(BILLADD @ 0x00433A63) only handles 1/2. Shipped disabled; remove from
`server/data/signup/plans.txt`.

#### 7.1.3 Billing commits (0x0B / 0x0C)

Reply **must** be a `0x84` variable (not a `0x83` dword — the proxy's
`output_descriptor->m10()` must return 4 (VAR) or the post-wait check
skips processing and shows "Your account information cannot be updated at
this time."). First dword of the variable:

| Status | Effect |
|--------|--------|
| 0x00 | Silent success; dialog dismisses |
| 0x1E | MessageBox string ID 0x134 |
| 0x1F | MessageBox string ID 0x135 |
| other | "cannot be updated" error |

Minimum success reply: `0x84` var, 4 NUL bytes.

#### 7.1.4 Post-login behavior

After login reply:
- T+0.3s: LOGSRV 0x07 enumerator (leave pending).
- T+0.9–1.4s: four DIRSRV pipes open — pipes 4/5 version `"Uagid=0"`, pipes
  6/7 version `"U"`. Each gets pipe-open reply + discovery block.
- T+2.8s (pipes 6/7): capability probe `GetProperties(0:0, self, ['q'])` —
  the `q` LCID prop, reply `q=0` (see §7.2.4). Each probe is followed by
  a one-byte `0x0F` commit on the same req_id. Not navigation.
- T+3.2–4.9s (pipes 4/5, in parallel): five-request breadcrumb / address-bar
  walk. Req IDs increment per pipe.

  | Req | Selector | Shape | Source of mnid |
  |-----|----------|-------|----------------|
  | 0 | 0x00 | GetChildren(0:0) | Wire root — 14-prop `nav` group |
  | 1 | 0x02 | GetProperties(1:0, [a,e]) | `GetSpecialMnid(idx=0)` — MSN root |
  | 2 | 0x00 | GetChildren(a-blob from req 1) | MSN-root children (14-prop) |
  | 3 | 0x02 | GetProperties(0:0, [a,e]) | Wire root self |
  | 4 | 0x00 | GetChildren(a-blob from req 0 rec 0) | Wire-root's first child's children |

  Populates the MOSSHELL address-bar dropdown, which merges client-hardcoded
  special folders (`Favorite Places`, `Worldwide Categories` — string table)
  with server-enumerated MSN-root children.

  **Canonical record** — req 0's single reply record (MSN Central, nav
  group `a,c,h,b,e,g,x,mf,wv,tp,p,w,l,i`), log line 712:

  ```
  88 00 00 00  0e 00  0e 61 00 08 00 00 00 0c 00 44 00 00 00 00
  03 63 00 01 00 00 00  03 68 00 01 00 00 00 05  02 01 62 00 00
  0a 65 00 01 4d 53 4e 20 43 65 6e 74 72 61 6c 00
  03 67 00 00 00 00 00  0e 78 00 01 00 00 00 00
  03 6d 66 00 01 00 00 05  03 77 76 00 01 00 00 05
  0e 74 70 00 01 00 00 00 00
  0e 70 00 0b 00 00 00 4d 53 4e 20 43 65 6e 74 72 61 6c
  0e 77 00 01 00 00 00 00  0e 6c 00 01 00 00 00 00
  03 69 00 00 00 00 00
  ```

  First 4 bytes = record total size (0x88 = 136). See §7.2.3 for layout.
  Req 4's first record (category "The News", log line 910) has identical
  shape with `a` = `0E 00 44 00 00 00 00 00` and `e` = `"The News"`.

  **Fallback trap** — if the server has no fixture for mnid `1:0`, req 1's
  `a` blob leaks the permissive-fallback node's identity into the client
  cache. Req 2 then walks `GetChildren` on that blob, and if the fallback
  is itself self-referencing (e.g. MSN Today leaf), the walk recurses
  endlessly. Vend a real `1:0` node (see `store/fixtures.py`) and keep
  the fallback a neutral container.

#### 7.1.5 Sign-out (client-initiated, ~285ms)

```
 T+0ms    pipe-close 0x01 on DIRSRV pipe 6
 T+44ms   pipe-close 0x01 on DIRSRV pipe 4
 T+88ms   pipe-close 0x01 on DIRSRV pipe 7
 T+132ms  pipe-close 0x01 on DIRSRV pipe 5
 T+184ms  LOGSRV sel=0x07 payload 0x0F (sign-off)
 T+284ms  pipe-close 0x01 on LOGSRV pipe 3
```

DIRSRV pipes close first, LOGSRV last. Server does not reply to any of
these — client tears down unilaterally.

### 7.2 DIRSRV

Discovery: the DIRSRV IID family `{00028B25..2E-…-46}` → selectors
`0x01..0x0A`. Selector `0x01` = GetProperties (`{00028B27-…}`);
selector `0x04` = GetShabby (`{00028B28-…}`). `CTreeNavClient::GetShabby`
(TREENVCL.DLL `0x7F631BAB`) calls `proxy->method_at_offset_0xC(proxy, 4, ...)`
— the literal `4` is the slot index that resolves to the GetShabby IID
via the discovery table, so the server discovery block must publish the
full family (not just `28B27`) or the client's proxy marshaller will
route the shabby request to the wrong selector.

#### 7.2.1 GetProperties request (selector 0x01, opcode 0x02)

```
 [0x04][var]  node ID          — 8 bytes: lo:u32 + hi:u32 (root = 0:0)
 [0x01][u8]   flags            — 0x00 self-props, 0x01 children
 [0x03][u32]  request_kind     — 0 or 1
 [0x03][u32]  property count hint
 [0x04][var]  property group   — NUL-separated names
 [0x04][var]  locale descriptor — observed as 8 bytes `[u32 unknown][u32 lcid]`;
                                  empty probe/fallback requests send `00000000`
recv: [0x83][0x83][0x85]      — two dwords + dynamic
```

#### 7.2.2 GetProperties reply

```
 [0x83][u32]  status (0 = success)
 [0x83][u32]  node count
 [0x87]       end-of-static
 [0x88]       dynamic-complete — rest of host block is raw
 <concatenated SVCPROP records>
```

`0x88` has no length prefix — `ReadDynamicSectionRawData` (MPCCL @
0x04605809) reads all remaining host-block bytes. Prefixing a length
corrupts the record parse.

#### 7.2.3 SVCPROP property record

`FDecompressPropClnt` (SVCPROP @ 0x7F641592):

```
 TotalSize   PropCount   <properties>
 [4LE]       [2LE]
```

Each property: `[type:1][name-asciiz][value-data]`. Wire types are in §8.

#### 7.2.4 Master property table

Request contexts:
- **nav** — GetChildren / list view (`flags=0x01`).
- **dlg-general** — Properties dialog General tab. Request group:
  `['e', 'j', 'k', 'ca', 'tp', 'z', 'o', 'g']`.
- **dlg-context** — Properties dialog Context tab. Request group:
  `['q', 'r', 's', 't', 'u', 'n', 'y', 'on', 'v', 'w', 'p', 'g']`.

Both tab requests use `dword_0=1` (GetChildren-shape) against the leaf.

| Name | Wire | Context | Consumer / dialog field | Semantics |
|------|------|---------|-------------------------|-----------|
| `a`  | 0x0E | nav | — | 8-byte mnid blob `pack('<II', f8, fc)` — builds `_MosNodeId.field_8/_c` in `GetNthChild` |
| `b`  | 0x01 | nav + click | Browse vs Exec gate | Dispatch flags read by `CMosTreeNode::ExecuteCommand` @ 0x7F3FF693. bit 0x01 **CLEAR** = container (click → `HrBrowseObject`, folder view); **SET** = leaf (click → `CMosTreeNode::Exec`, launches App #`c`). bit 0x08 = server-denied (aborts with HRESULT 0x8B0B0041 → "Cannot open service."). Missing / failed property read also triggers the same denied error |
| `c`  | 0x03 | nav + click | Exec dispatch | Registered MOS app_id (HKLM\SOFTWARE\Microsoft\MOS\Applications\App #<c>). 1 = Directory_Service, 6 = Media_Viewer, 7 = Down_Load_And_Run (browser URL) |
| `ca` | 0x0B | dlg-general | Category | — |
| `e`  | **0x0A** | nav + dlg-general + titlebar | Name (icon label + explorer titlebar + General Name) | ASCII-cache string. Both icon label and `IShellFolder::GetDisplayNameOf` (STRRET ANSI) read 'e'; 0x0B truncates titlebar to "M" |
| `g`  | 0x03 | nav + dlg-general + dlg-context | — | Purpose unresolved. Ruled out as the icon slot (sentinel sweeps 2026-04-16 showed `mf`/`wv`, not `g`, drive GetShabby). Emit DWORD 0 until a consumer trace pins it down |
| `h`  | 0x03 | nav | **Secondary icon (GetShabby ICO/EXE/DLL path)** | Shabby ID DWORD of a custom icon-bearing file (.ICO/.EXE/.DLL). `MOSSHELL FUN_7F404786` reads "h" as 4-byte DWORD and, on success, calls `FUN_7F4047C2` → `FUN_7F4049F9` (GetTempFileNameA + vtable[0x74] GetShabbyToFile + ExtractIconExA). On GetProperty failure the whole ICO path is skipped. **Omit entirely** for nodes without a custom icon — emitting `h=0` triggers `GetShabby(shabby_id=0)` → zero-blob reply → NULL HICON → forbidden glyph. Prior container-flag interpretation was wrong (container-ness is carried in `b` bit 0) |
| `i`  | 0x03 | nav | — | Unknown; send 0 |
| `j`  | 0x0B | dlg-general | Description / Go word | — |
| `k`  | 0x0B | dlg-general | Go word | — |
| `l`  | 0x03 | nav | — | Unknown; send 0 |
| `mf` | **0x03** | nav | **Primary node icon (GetShabby slot B, `req_id=9`)** | Shabby ID DWORD. `MOSSHELL FUN_7F405018` does `GetProperty("mf", &buf, 4)` → 4-byte DWORD → synthesizes filename via `%04X%08X` → if absent, calls `vtable+0x74` → `GetShabbyToFile` → `CTreeNavClient::GetShabby`. **Must not be 0x0E** — as a blob, SVCPROP stores the heap-alloc pointer in the cache and the low 4 bytes of that pointer become the shabby_id (the `0x00BE0400` garbage). Adjacent string `PlaySound` at `0x7F40EBD8` hints `mf` may double as a sound-cue key |
| `n`  | 0x0B | dlg-context | Forum manager | — |
| `o`  | 0x03 | dlg-general | Rating | DWORD 0 → "Not rated" |
| `on` | 0x0B | dlg-context | Owner | Two-letter prop name |
| `p`  | **context-dependent** | nav / dlg-context | Size | nav: `0x0E` blob carrying legacy title. dlg-context: `0x03` DWORD byte count — `FUN_7F3FBA69`'s `"p"` branch reads `**(cache+4)` and calls FormatSizeString (vtable +0x140) |
| `q`  | 0x03 | dlg-context | Language | LCID. Non-zero required — 0 triggers downstream OOM |
| `r`  | 0x0B | dlg-context | Topics | — |
| `s`  | 0x0B | dlg-context | People | — |
| `t`  | 0x0B | dlg-context | Place | — |
| `tp` | 0x0B | dlg-general | Type | — |
| `u`  | 0x0B | dlg-context | (hidden) | Requested but no visible field |
| `v`  | 0x0B | dlg-context | Created | Timestamp string |
| `w`  | 0x0B | dlg-context | Last changed | Timestamp string |
| `wv` | **0x03** | nav | **Secondary icon (GetShabby slot A, `req_id=1`)** | Shabby ID DWORD `(format<<24) \| content_id`. Fires GetShabby before `mf` does — likely the list-view/small-icon variant (exact consumer not yet isolated). Same 0x0E blob pitfall as `mf` |
| `x`  | 0x0E | nav | — | Cmdline args for `HRMOSExec(c, args)`. Empty → length-1 NUL |
| `y`  | 0x03 | dlg-context | (VendorID, hidden) | `SetDlgItemInt` on item 0x79, not laid out |
| `z`  | 0x03 | dlg-general | Price | DWORD 0 → "Free" |

**Property `e` rationale** — Both the nav titlebar *and* the dialog
titlebar read 'e' via ANSI paths:
- `CMosTreeNode::Properties @ 0x7F3FEF12` does `GetProperty("e", buf, 0x104)`
  (raw memcpy from cache) and passes buf to **PropertySheetA** (ANSI). UTF-16
  bytes truncate at the first wide NUL → "M".
- `IShellFolder::GetDisplayNameOf` on the DSNAV shell extension routes
  `STRRET_CSTR` through an ANSI path for the explorer titlebar.

Since `GetProperty` is raw memcpy (vtable slot 16 = `FUN_7F3FCE71`),
the cache itself must hold ASCII. Type 0x0A runs `WideCharToMultiByte`
after decode and stores ASCII. Type 0x0B leaves UTF-16 in cache.

**Other dialog strings stay 0x0B** — `GetPropSz` (vtable slot 19 =
`FUN_7F3FD065`) lazily populates an ASCII copy at `cache+0xC` via
`EnsurePropSzCache → WideCharToMultiByte`. Field renderers call
`GetPropSz`, which works for either type. Empirically switching
n/on/v/w to 0x0A blanks those fields; keep them 0x0B.

#### 7.2.5 Empty-blob OOM trap

Any `0x0E` blob with `length=0` makes the client `malloc(0)` → NULL on
the MSVC runtime in this VM. MOSSHELL's cache reader `FUN_7F3FB9F5`
returns `E_OUTOFMEMORY` (`0x8007000E`) → `ReportMosXErr` → "Out of memory"
dialog. Always send ≥ 1 byte (e.g. `\x00`) for blob props.

#### 7.2.6 Click dispatch

Wire property letters `'a' / 'e'` ≠ internal dispatch keys `'z' / 'c'`.
`CMosTreeNode::Exec` reads the **cached** `'c'` from the GetChildren reply,
not from a per-click GetProperties. `c=7` → browser URL; anything else →
`CreateProcessA` using `HKLM\SOFTWARE\Microsoft\MOS\Applications\App #<c>`.

#### 7.2.7 GetShabby (selector 0x04) — icon fetch

After `GetProperties`/`GetChildren` populates the DSNAV cache, the client
issues a follow-up GetShabby RPC **per node** to fetch the icon bytes.
The argument is the DWORD it cached from property `wv` (see §7.2.4).

**Request payload:**
```
 [0x03][u32]  shabby_id         — cached value of property 'wv'
 recv: [0x83][0x85]             — status DWORD + dynamic blob
```

**Reply payload:**
```
 [0x83][u32]  status (0 = success)
 [0x87]                         — end-static
 [0x88]                         — dynamic-complete
 <raw icon file bytes — no length prefix, read to end of packet>
```

The client writes the blob to a temp file and loads it with the Win32
API selected by the `shabby_id`'s top byte (decoded by `MOSSHELL.DLL
FUN_7F405018`):

| Top byte | Loader | Format |
|----------|--------|--------|
| 0x01 | `GetEnhMetaFileA` | EMF |
| 0x03 | `Meta_init/add/play/close` | raw WMF |
| 0x04 | (magic `0x9AC6CDD7`) | placeable WMF |
| 0x05 | `LoadImageA(IMAGE_BITMAP, LR_LOADFROMFILE \| LR_DEFAULTSIZE)` | BMP |

Low 24 bits are an opaque content ID — the server's registry decides
which file to serve. Unknown IDs: reply status=0 with an empty blob;
client leaves the cache slot NULL and renders the forbidden glyph.

**Reply tag gotcha:** use `0x87/0x88` (end-static + dynamic-complete),
not `0x85` (length-prefixed dynamic-start). `0x85` hangs
`MPCCL.ProcessTaggedServiceReply` because it never signals completion
(the client's dispatch loop waits for `0x88`).

**Slot B:** a second GetShabby fires per node with `req_id=9`. Which
property drives it is unresolved — see §11.

### 7.3 FTM

Both selectors use the `FtmClientFileId` 60-byte CFI buffer via tag `0x04`:

| Sel | Method | Reply |
|-----|--------|-------|
| 0x00 | `HrRequestDownload` | `0x84` var, 72 bytes; flag byte `0x0B` = bits 0+1+3 (has compressed size, fast path, filename override); filename at CFI offset +40 |
| 0x03 | `HrBillClient` fast path | 18-byte header + inline content bytes (client WriteFile's these to the local file) |

CFI layout: name field is a literal service-level identifier (e.g.
`"LOGSRV"` during signup RTF loop, not a filename). Counter at offset +40
iterates 0..3 during signup; server maps to `plans.txt`, `prodinfo.rtf`,
`legalagr.rtf`, `newtips.rtf` (all must exist next to `SIGNUP.EXE` —
checked via `CreateFile(OPEN_EXISTING)` in `FUN_004029D8`).

Empty RTF content is acceptable — RichEdit renders an empty document.

### 7.4 OLREGSRV (signup commit)

One call from SIGNUP.EXE's `DispatchSignupCommitAndWait @ 0x004063DE`,
serialized as four wire records:

```
 class=0x01 sel=0x01   payment method (card number, expiry, name)  — CALL HEAD
 class=0xE7 sel=0x01   member ID + password                        — one-way
 class=0xE6 sel=0x02   personal name + company                     — one-way
 class=0xE7 sel=0x02   street address + phone                      — one-way
```

Only the `class=0x01` head expects a reply:

```
 [0x83][00 00 00 00]   HRESULT = 0 — unblocks credentials page's 90s wait
```

The proxy's post-commit switch sees result=0 → case 0 → `result_code = 0x19`.
Replying to the `class=0x01 sel=0x02` pre-check aborts signup with "An
important part of signup cannot be found" — pre-check must return None.

### 7.5 ONLSTMT (account statement)

Pipe name `"OnlStmt"`, service version **3**. Discovery table has 27 IIDs.

| Sel | Method | Reply shape |
|-----|--------|-------------|
| 0x00 | Statement summary | 7 tagged: `0x83` balance, `0x82` currency, `0x82` year, `0x81` month, `0x81` day, `0x82` minutes, `0x81` period_count−1 |
| 0x02 | Subscriptions list | 11 tagged primitives + `0x84` record blob |
| 0x03 | Plans | `0x84` variable |
| 0x04 | Cancel | `0x83` status |
| 0x05 | Get Details | **must end in `0x86` dynamic-complete** (not `0x85` or `0x88`) or `ProcessTaggedServiceReply` hangs |

Encodings:
- Currency: ISO 4217 numeric code.
- Date wire form: `days_wire = days_since_1970 + 0x63DF`.

### 7.6 MEDVIEW

Service version `0x1400800A`. Host = `MOSVIEW.EXE` (App #6). Used by MSN
Today (`4:0`, App #6, selector `T`) and any content surface that hands
control to the MedView viewer.

**Discovery**: 42 IIDs (`00028B71..74`, `78..79`, `81..86`, `8A..91`,
`A0..A1`, `B0..B8`, `C0..CA` in the Marvel `-…C000-…46` template). Selector
assignment is 1-based in array order, so `00028BB8` → selector `0x1F`
(handshake) and `00028BB7` → selector `0x1E` (TitlePreNotify).

**Selectors used on the initial-open path**:

| Sel | Purpose | Request | Reply |
|----:|---------|---------|-------|
| `0x1F` | Handshake | `0x01 <byte=1>` + `0x04 <12B: 0x2000, 0x4006, lcid>` + `0x83` | `0x83 <nonzero>` + `0x87` |
| `0x1E` | TitlePreNotify | `0x01 <title_byte>` + `0x02 <opcode>` + `0x04 <body>` | `0x87` |
| `0x01` | TitleOpen | `0x04 <title_spec>` + `0x03 <chk1>` + `0x03 <chk2>` + 7 recv descriptors | 2×`0x81` + 5×`0x83` + `0x87` + `0x86 <title body>` |
| `0x03` | TitleGetInfo | `0x01 <title_byte>` + 3×`0x03 <dword>` + `0x83` | `0x83 <size>` + `0x87` + `0x86 <buffer>` |

See `docs/MEDVIEW.md` for full details including the title body layout
(DIB section + fixed-size record arrays + string lists) and the MVP
handler checklist.

### 7.7 CONFLOC / CONFSRV

Static-only — not implemented on the server side. See Open Questions.

---

## 8. SVCPROP wire types

`DecodePropertyValue @ 0x7F64143A` — decoder dispatch.

| Type | Name | Wire body | Cache storage |
|------|------|-----------|---------------|
| 0x01 | byte | 1 byte | byte |
| 0x02 | word | 2 LE | word |
| 0x03 | dword | 4 LE | dword |
| 0x04 | int64 | 8 LE | int64 |
| 0x0A | string | `[flag:1][body]` | **ASCII** — `FUN_7F6413CA` runs `WideCharToMultiByte` after decode; UTF-16 temp freed |
| 0x0B | string | `[flag:1][body]` | **UTF-16LE** — raw temp buffer kept |
| 0x0E | blob | `[len:u32][data]` | `(len, data_ptr)` |
| 0x10 | dword array | `[count:u32][values:u32×n]` | array |

### 8.1 Flag-byte string body (0x0A and 0x0B)

Decoded by `DecodeFlagByteString @ 0x7F641328`:

| flag bit | body | temp buffer |
|----------|------|-------------|
| `& 2` | (none; 1 byte total) | empty |
| `& 1` | `[ascii…][NUL]` | ASCII widened to UTF-16 |
| else | `[utf16le…][wide NUL]` | raw UTF-16 |

**0x0A vs 0x0B is cache-side, not wire-side** — both read the same flag
body. 0x0A tells SVCPROP to narrow the temp back to ASCII before caching;
0x0B keeps the UTF-16. This is the NT-server (UTF-16 native) / Win95 client
(ANSI native) split.

### 8.2 Consumer dispatch

- `GetProperty` (vtable slot 16 @ `0x7F3FCE71`) — raw memcpy from cache +4.
  Encoding must match cache (0x0A returns ASCII bytes; 0x0B returns UTF-16).
- `GetPropSz` (vtable slot 19 @ `0x7F3FD065`) — lazy-populates ASCII at
  `cache+0xC` via `EnsurePropSzCache → WideCharToMultiByte`. Tolerates
  either wire type; always returns ASCII.

ANSI consumers reached via `GetProperty` (titlebar, PropertySheetA, shell
`STRRET_CSTR`) need 0x0A. Consumers reached via `GetPropSz` (most dialog
field renderers) work with 0x0B.

---

## 9. Error codes

### 9.1 MCM (Marvel Connection Manager)

| Code | Meaning | Code | Meaning |
|------|---------|------|---------|
| 1 | User cancelled | 8 | Bad user ID |
| 2 | Busy | 9 | InitMos() failed |
| 3 | No dial tone | 12 | Registry missing |
| 4 | No carrier | 13 | Modem/TAPI error |
| 5 | Network error | 14 | Connection dropped |
| 6 | No LOGIN service | 15 | Modem busy/not found |
| 7 | Bad password | | |

### 9.2 HRESULT facility

Custom facility **0xB0B** — e.g. `0x8B0B0017` = bad password,
`0x8B0B0041` = property NOT-RECEIVED.

### 9.3 MPC server errors (tag 0x8F)

See §6.3.

---

## 10. Registry

`HKLM\SOFTWARE\Microsoft\MOS\Transport`:

| Value | Default | Purpose |
|-------|---------|---------|
| PacketSize | (from server) | Inbound buffer |
| PacketOutSize | (from server) | Outbound buffer |
| WindowSize | 16 | Sliding window |
| AckBehind | 1 | Forced-ACK threshold |
| AckTimeout | 600 | ms |
| ArenaSize | 0x40000 | ARENA.MOS shared region |
| TransportPriority | — | Preferred transport |
| Latency | 0 | Debug send delay |

Other keys:
- `HKLM\SOFTWARE\Microsoft\MOS\Connection` — connection settings.
- `HKLM\SOFTWARE\Microsoft\MOS\Debug\DisplayMcmErrors` — show error UI.
- `HKLM\SOFTWARE\Microsoft\MOS\Applications\App #<N>` — `c` property
  dispatch table (Filename + NED for each app_id).

---

## 11. Open questions

| Area | Question |
|------|----------|
| LOGSRV 0x0E | Real phone-book update contract. Current stub replies dword=0 → client ticks "done" without a real FTM fetch. Need: meaning of send dword=8, whether non-zero reply triggers a fetch, versioning scheme. Tracked in `TODO.md`; Ghidra: `SIGNUP.EXE!FUN_004043C1`. |
| LOGSRV 0x02 / 0x07 / 0x0D | COM-proxy unmarshaller layer not RE'd. Empty `0x84` reply is the minimum that works — specific semantics unknown. |
| DIRSRV `g` | Present in nav + both dialog tabs; purpose unresolved. Ruled out as the icon slot. |
| DIRSRV `u` | Requested on dlg-context but no visible field — possibly currency/unit tied to price. |
| DIRSRV `l` / `i` | Present in nav request group; shapes/meanings unknown. Catch-all defaults. |
| DIRSRV `wv` vs `mf` split | Two GetShabby calls fire per node (`req_id=1` driven by `wv`, `req_id=9` driven by `mf` via `FUN_7F405018`). Presumably two icon sizes / display modes, but the exact consumer on the `wv` side isn't traced yet. |
| Properties titlebar | Blank on **first** open of each node's Properties dialog — only shows "MSN Today" on re-open (cache hit). Suggests 'e' cache-population timing vs `CMosTreeNode::Properties` read order. |
| `CMosTreeNode::Properties` Context tab | "Cannot open service" (resource 0xDE). Factory call at `FUN_7F402098` returns failure — unrelated to wire format. |
| CONFLOC / CONFSRV | Conference services referenced in static strings; not implemented. |
| MEDVIEW title body | MVP ships 9-section stream with only the string-table populated (deid-keyed title name). Rich content (banner + fixed-size record arrays) requires decoding Blackbird's COSCL compound-file upload; see `docs/MEDVIEW.md` §4.4 and `docs/BLACKBIRD.md` §4.4. |
| X.25 handshake | Static analysis only; never exercised. |

---

## Appendix A: Client binary map

| Binary | Size | Role |
|--------|------|------|
| MPCCL.DLL | 88K | MPC RPC: pipes, host blocks, tagged params |
| MOSCP.EXE | 68K | Transport engine (runtime): framing, CRC, window |
| MOSCL.DLL | — | Pipe/session primitives, MosSlot IPC |
| ENGCT.EXE | 72K | Alternate transport engine (not loaded) |
| GUIDE.EXE | 116K | Login manager, session lifecycle |
| MOSSHELL.DLL | 180K | Shell tree navigation, DSNAV, Properties |
| SVCPROP.DLL | — | Property record decoder |
| SIGNUP.EXE | — | New-account wizard (hosts BILLADD.DLL) |
| BILLADD.DLL | — | Billing / payment UI, in-process under SIGNUP |
| CONFAPI.DLL | 24K | Chat / conferencing |
| SACLIENT.DLL | 32K | System administration |
| MVTTL14C.DLL | 36K | Multimedia Viewer |

## Appendix B: Internal IPC (MOSCL ↔ MOSCP)

MosSlot shared memory: `"MosSlot"` file mapping, `"MosArena"` mutex,
48 slots × 1KB. Bulk pipe data via `"ARENA.MOS"` (default 256KB).

Client → Engine commands:

| Cmd | Name | Cmd | Name |
|-----|------|-----|------|
| 0 | Register (PID) | 0xA | Terminate |
| 4 | Write pipe data | 0xB | Close pipe (abort) |
| 6 | Open pipe | 0xD | Close pipe |
| 8 | Open connection | | |

Engine → Client commands:

| Cmd | Name | Cmd | Name |
|-----|------|-----|------|
| 1 | Registration OK | 9 | Connection status |
| 3 | Pipe read ready | 0xC | Pipe closed |
| 5 | Pipe write done | 0xF | Connection event |
| 7 | Pipe open result | 0x10 | Pipe reset |
