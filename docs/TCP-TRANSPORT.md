# TCP transport and LAN service discovery

Static analysis of the OSR2 client (MSN 4.2.5799 / build 5900, `osr2/` in the
Ghidra project) plus one wire capture of a failed LAN connect
(`captures/lan/osr2-lan-20260815-211137.pcap`, 2026-08-15).

Serial dial-up is `MOSCP.EXE`. TCP is `ENGCT.EXE`: it is the only module that
loads the connector DLLs, and it holds the gateway host names and the port.
`MOSCL.DLL` picks between the two engines by name (`ENGCT`, `MOSCP` and
`SOFTWARE\Microsoft\MOS\Transport` all live in its string table).

In the 1.0 client `ENGCT.EXE` linked `WSOCK32` and `RASAPI32` directly. In OSR2
the dial and connect steps moved behind a connector DLL:

| Export | TCPCONN.DLL | MSNPROXY.DLL |
|---|---|---|
| `ProxyDllStartup` / `ProxyDllShutdown` | yes | yes |
| `ProxyDialOpen` / `Close` / `GetResult` | RAS dial of phonebook entry `The Microsoft Network` (`(Backup)`) | stub |
| `ProxyConnectOpen` / `Close` / `GetResult` | direct `connect()` | connect to a LAN proxy found by service discovery |
| `ProxyConnectGetMyIPAddrs` | yes | absent (ENGCT NULL-checks the slot) |
| `ProxyDialGetErrorLogString` | yes | absent |

`ENGCT!Transport_ConnectAndRun` (`0x057124a5`) reads the DLL name from
`SOFTWARE\Microsoft\MOS\Connection!ConnectProtocol`, resolves the entry points
into `ctx[0xe4..0xea]`, dials, then calls

```c
ProxyConnectOpen(primary, backup, 0x239 /* 569 */, 0, 0, cb, cb, ctx, &hThread, &conn);
```

`0x239` is the only occurrence of that constant in the binary — the port is not
configurable on this path. The host names come from
`ENGCT!LoadGatewayNamesFromRegistry` (`0x05712298`):

| `HKCU\Software\Microsoft\Mos\Connection` | default (ENGCT string resource) |
|---|---|
| `PrimaryMSNGateway` | `gateway.moswest.msn.net` (0x6b) |
| `BackupMSNGateway` | `gw-backup.moswest.msn.net` (0x6c) |

A missing value is written back with the resource default.

---

## 1. Service discovery

Only `MSNPROXY.DLL` discovers anything. It imports no resolver at all; its
server list can only come from `INETSLOC.DLL!INetDiscoverServers`, and
`PreferredServer`(`2`..`9`) merely filters that list
(`RejectServersNotInPreferredList`, `0x7d7b13db`).

`INETSLOC.DLL` — *"Internet Service Location protocol library"*,
`WINDOWS\SYSTEM\INETSLOC.DLL`, 21856 bytes, 1996-08-24 — carries both a NetBIOS
and a UDP implementation of the same message format. The observed OSR2 client
takes the NetBIOS path.

### 1.1 Call shape

```c
INetDiscoverServers(0x20, 0, 2, &list);   // masks, wait seconds, out
```

Mask 1 bit `0x20` is the MSN gateway service. Results are cached for 300 s; a
second call inside that window re-uses the cache. MSNPROXY calls twice: once to
kick discovery, then after `WaitTime` seconds (registry, default 2) to collect.

### 1.2 NetBIOS mechanics

`SvcLoc_NetBiosSendQuery` (`0x7e3f2740`), per LANA:

| NCB | Detail |
|---|---|
| `NCBADDNAME` 0x30 | reply name `I~5` + computer name, space-padded to 15, suffix `0x20` |
| `NCBDGRECV` 0xA1 ×3 | 1 KB buffers, `ncb_rto` 60 |
| `NCBDGSEND` 0x20 | `ncb_callname` = `INet~Services  ` suffix `0x1C` (group), body = the query message |
| `NCBCANCEL` 0x35 / `NCBDELNAME` 0x31 | teardown after the wait expires |

Capture, frames 138–149: NBT registration of `I~586BOXOSR2<20>` ×4, the same
name over raw NetBEUI ×3, then the datagram to `INet~Services<1c>` and three NBT
name queries for it, then the release. The NBT leg never sends a datagram
because the group-name query goes unanswered; the NetBEUI leg broadcasts the
datagram regardless.

`INetGetServerInfo` reuses the same code with a specific callname instead of the
group name.

### 1.3 Message frame

Both directions share the frame (`SvcLoc_BuildQueryMessage` `0x7e3f21b9`,
validated in `SvcLoc_ValidateAndStoreAdvert` `0x7e3f1d8c`), all `u32` LE:

```
+0x00       total size, must equal the datagram length
+0x04       message type, low 16 bits must be 2
+0x08 ...   body
size-8      checksum: XOR of the u32s from +0x04 through size-12
size-4      0xFFFFFFFF
```

A message failing any of those four checks is dropped with `0x57`.

**Query body** (client → group):

```
+0x08  u32 service mask 1        (0x20)
+0x0C  u32 service mask 2        (0)
+0x10  requester computer name, ASCIIZ, zero-padded
```

Total size is `((strlen(name)+1 + 0x1a) & ~3) + 4`. The captured 40-byte
datagram matches byte for byte, checksum `0x1d117970` included.

**Advert body** (server → `I~5<name><20>`), parsed by `CServerAdvert_Parse`
(`0x7e3f4329`):

```
+0x08  server name, ASCIIZ, padded to 4        <- dedup key, and the name the
                                                  client feeds to gethostbyname
 Q+0x00 u32 load metric                        <- lowest wins, must be < 100
 Q+0x04 u32 service mask 1                     <- must intersect the query masks
 Q+0x08 u32 service mask 2
 Q+0x0C u32 service entry count
 Q+0x10 entries, each: u8 length in a u32 slot, then `length` bytes, advance 4+length
```

Service entry body (`CServiceEntry_ToRecord`, `0x7e3f4027`):

```
+0x00  u32 service mask      MSNPROXY requires bit 0x20
+0x04  u32                   unused by MSNPROXY
+0x08  u32                   MSNPROXY requires == 1
+0x0C  service name, ASCIIZ, padded to 4
 next  u32 address count
 then  count x { u32 length; length bytes padded to 4 }   each blob is a sockaddr
```

### 1.4 What the client does with an advert

`MSNPROXY!PickAndConnectDiscoveredServer` (`0x7d7b177f`): take the record with
the smallest load metric below 100, its first entry with mask bit `0x20` and
field `+0x08 == 1`, then walk that entry's address blobs. A blob is used only if
`sa_family` is 2 (AF_INET) or 6 (AF_IPX) and the corresponding stack is loaded.
`ResolveAndConnect` (`0x7d7b1462`) then **overwrites the blob's address bytes
with `gethostbyname(server name)`** and keeps only the port, so the advertised
name must resolve on the client. A tried record is stamped with load 0x65 (101)
so the next round skips it.

### 1.5 Answering discovery is not enough

The machine found this way is an *MSN proxy*, not a gateway. After the TCP
connect `MSNPROXY` speaks its own packet protocol — 16-bit opcodes, a
`GetHostByName` request/response pair (`GetHostByNameReturn`), and SSPI tokens
(`InitSecurityInterfaceA`, `secur32.dll`/`security.dll`) — and only then relays
to `<gateway>:569`. Serving the LAN mode means implementing that proxy protocol
plus its authentication; serving the direct mode does not.

Its own parameters live in
`SOFTWARE\Microsoft\ProxyConnector\CurrentVersion\ConnectParameters`:
`PreferredProtocol` (a Winsock address family: 2 = TCP/IP, 6 = IPX/SPX),
`TcpPort` (default `0x238` = 568), `TcpMatchSD`, `WaitTime` (2),
`ConnTimeOutVal` (30000 ms, applied as `SO_RCVTIMEO`),
`OverrideServiceDiscovery`, `PreferredServer`…`PreferredServer9`.

---

## 2. Connection handshake

Direct path, `TCPCONN!TcpConnectWorkerThread` (`0x7cc21390`): resolve the
primary and backup names into a candidate list, `connect()` each in turn on port
569, leave the socket for `ProxyConnectGetResult`. **Nothing is written to the
socket** — there is no greeting, no CONNECT line, no version string in front of
the MPC stream. Failed candidates are logged to
`SOFTWARE\Microsoft\MOS\Transport!FailedAddresses` as
`host!err|count|MMDDYYHHMM` records.

`ProxyConnectGetResult` returns the connected `SOCKET` itself (`conn+0x28`), and
ENGCT drives it as an overlapped file handle: `SocketWritePacket`
(`0x05711c07`) calls `WriteFile`, `SocketReceiveLoop` (`0x05712c1d`) calls
`GetOverlappedResult`. ENGCT imports exactly one Winsock function,
`WSAStartup`.

ENGCT contains no modem code (no `AT`, no `COM`, no `CONNECT` strings), so the
`0x0D` / `COM\r` exchange of PROTOCOL.md §4.1 does not happen. Observed
bring-up:

```
Client → type-4 control frame          immediately after connect, unprompted
Server → type-3 control frame          transport params
Client → type-1 control frame          connection request
Server → type-1 echo
```

The client sends its type-4 without waiting, then goes quiet until the
parameters arrive; a server that stays silent stalls it there. The type-1
payload is a connection log — modem description and the addresses the client
failed on, the same `host!err|count|time` records ENGCT keeps in
`FailedAddresses`:

```
||||||||00000409|..T05006062.1.212.Standard Modem.!10|1|0815322002
C204.79.197.203;gw-backup.moswest.msn.net;192.168.1.170!10060|2|...
```

---

## 3. Framing: Straight, not Select

The pipe traffic is identical; the framing under it is not. On TCP a record is

```
uint16 LE total length, counting itself | uint8 pipe index | pipe content
```

and nothing else — no sequence numbers, no ACKs, no byte stuffing, no CRC, no
`0x0D` terminator. TCP already provides ordering and integrity, so the Select
machinery has nothing to do. ENGCT still carries all of it — CRC-32
`0x248EF9BE` at `0x05714e59`, the escape table at `0x057167b0`–`0x05716860`
(`0x1B→1B 30`, `0x0D→1B 31`, `0x10→1B 32`, `0x0B→1B 33`, `0x8D→1B 34`,
`0x90→1B 35`, `0x8B→1B 36`) — because `FUN_057145c5` registers both protocol
objects, `Select` and `Straight`, against provider `BuiltIn`.

Content rules, all observed against the client:

- Control and pipe-0 records keep the in-band routing prefix: `FFFF` for
  control frames, `0000` for a pipe open, otherwise the logical pipe.
- Service records keep it too — the record for a reply on pipe 3 is
  `[len][03][03 00][host block]`, the same content the Select builder puts in a
  frame.
- The **pipe-open response carries no prefix**: `[len][03][03 00 01 00 03 00 00
  00]`, the bare result addressed by the record's pipe number. Prefixing it the
  way service records are prefixed stops the client dead at "Verifying account".
- `PacketSize` does not bound a record. Replies of 16396 bytes go through in one
  record where the serial link had to split them; the uint16 length is the only
  ceiling.

Above the transport nothing changes. `MPCCL.DLL` and the application DLLs talk
to the engine through the same `MOSCL.MOS` / `ARENA.MOS` MosSlot IPC, so pipes,
host blocks, tagged parameters and the whole service RPC are untouched — an
OSR2 client over TCP signs in through NTLM on LOGSRV and browses DIRSRV and
MEDVIEW exactly as it does over the modem.

---

## 4. Server side

`src/server` listens on both ports: 2323 for MOSCP over the 86Box modem
emulator, `GATEWAY_PORT` 569 for ENGCT. The listening port is what tells the two
apart — `handle_connection(conn, addr, direct=True)` skips the telnet stripping
and the bare-CR wait and sends the type-3 transport parameters as soon as the
connection is accepted.

The service handlers know nothing about any of this. They keep building Select
packets, and `transport.reframe_as_straight` converts a builder's output at the
send boundary, rejoining a message the Select builder had to split into the one
record Straight carries. Inbound, `take_straight_records` splits the stream and
`_handle_straight_record` feeds the same pipe-0 and service dispatchers.

569 is privileged. Without one of

```sh
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=569
```

or running as root, the gateway listener logs `listen_denied` and the server
carries on serving 2323 alone. A port redirect is not equivalent: the direct
bring-up is selected by which listener accepted the connection, so 569 has to
land on the gateway listener itself.

Guest side:

1. `ConnectProtocol` under `SOFTWARE\Microsoft\MOS\Connection` selects the
   connector; TCPCONN is the one that connects straight to a host.
2. `PrimaryMSNGateway` = our host, or point `gateway.moswest.msn.net` at it in
   the guest's `HOSTS`.
3. ENGCT calls `ProxyDialOpen` before connecting, and TCPCONN dials the RAS
   entry `The Microsoft Network`. It does not block a guest that already has a
   LAN: the OSR2 VM reaches the gateway without a dial-up connection defined.

A client that has failed to connect a few times keeps the pipe numbers it
burned, and a reused number can leave a service waiting on an open that never
lands. A stalled service pipe after several failed attempts is worth retrying
from a freshly started client before it is treated as a protocol fault.
