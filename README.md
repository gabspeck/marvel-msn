# MSN for Windows 95: Reverse-Engineering the Marvel Protocol

Reverse engineering the undocumented wire protocol used by **MSN 1.0 for
Windows 95** (July 1995). The protocol, internally codenamed **"Marvel"**, is a
completely bespoke Microsoft protocol stack — not PPP, not DCOM, not any public
standard.

This project includes a working **emulated server** that drives the original
1995 client through dial-up bootstrap, login, service discovery, and directory
browsing. The MSN Shell window renders and displays the content tree.

## Protocol implementation status

|Feature|Status|
|-------|------|
|New account sign-up|✅|
|Login|✅|
|Change password|✅|
|Manage subscriptions|✅|
|Manage payment method|✅|
|Directory navigation|✅|
|"Go to word" navigation|✅|
|Blackbird content|In progress|
|BBS|Pending|
|Chat|Pending|

## What's been decoded

- **Transport layer** — packet framing, byte-stuffing (0x1B escape), CRC-32
  with custom polynomial (0x248EF9BE), Go-Back-N sliding window (7-bit seq)
- **Pipe multiplexing** — 16 logical pipes over one connection, Select/Straight
  protocol negotiation, pipe-open handshake
- **Service RPC** — host blocks, tagged parameters (TLV), variable-length
  integers, COM-shaped interface discovery (IID GUIDs to selector bytes)
- **LOGSRV** — login handshake, service map bootstrap, enumerator requests
- **DIRSRV** — directory service for content browsing, property record format
  (FDecompressPropClnt), 14-property child node records
- **MSN Shell** — Explorer namespace extension (IShellFolder), tree navigation
  via CTreeNavClient, property-driven node rendering

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol specification.

## Repository layout

```
PROTOCOL.md          Wire protocol specification (the main deliverable)
server/
  server.py          Emulated MSN server — drives the real 1995 client
  phonebook.txt      Test dial-up phone numbers (localhost:2323)
tools/
  gdb_debug.py       GDB stub client library for 86Box debugging
  trace_*.py         Runtime tracing scripts (breakpoint-based)
  capture_*.py       Runtime capture scripts (IID/error sniffing)
  debug_mpccl.*      MPCCL login flow debugger
  watch_signout.py   Sign-out flow monitor (native GDB Python script)
docs/
  JOURNAL.md         Chronological research journal
```

## Running the server

### Prerequisites

- [86Box](https://86box.net/) with a Windows 95 VM and the MSN client installed
- Python 3.6+
- 86Box configured with a serial modem on COM1 or COM2

### 86Box modem setup

1. **Ports (COM & LPT):** Set the serial port you want the modem on (e.g. COM2)
   to **None** — the modem network adapter claims it directly.
2. **Network:** Add a network card of type **[COM] Standard Hayes-compliant
   Modem**. Click **Configure** and assign it to the serial port from step 1.
3. **Phonebook:** Create a phonebook file (see `server/phonebook.txt`) that maps
   the MSN dial-up number to `localhost:2323`. Point 86Box's modem config at
   this file.

### Start the server

```sh
python3 server/server.py
```

The server listens on TCP port 2323. Open the MSN client in Windows 95, click
"Connect", and the dial-up handshake begins. The server handles the full flow:
modem AT commands, transport negotiation, pipe multiplexing, LOGSRV login,
DIRSRV directory browsing.

## Tests

```sh
make test                       # run the full unittest suite
pip install coverage && make coverage   # statement coverage report
```

## Tracing tools

The `tools/` directory contains scripts that connect to 86Box's GDB stub
(port 12345) to set hardware breakpoints on client DLL functions and trace
protocol behavior at runtime.

These scripts are not needed to run the server — they are for programmatic
debugging of the emulated machine. They require a custom build of 86Box with
the GDB stub compile flag enabled (this is a build-time option, not a runtime
setting). Once built, the stub listens on port 12345.

| Script | Target | Purpose |
|--------|--------|---------|
| `trace_login.py` | MOSCL.DLL | Trace pipe-open and login dispatch flow |
| `trace_moscp.py` | MOSCP.EXE | Trace transport state machine paths |
| `trace_fget.py` | SVCPROP.DLL | Discover which property names MOSSHELL reads |
| `trace_cmd8_selection.py` | MOSCP.EXE | Snapshot cmd-8 selector payload |
| `trace_late_transport.py` | MOSCP.EXE | Trace post-handshake transport flow |
| `watch_signout.py` | (native GDB) | Monitor sign-out sequence |
| `capture_dirsrv_iids.py` | MPCCL.DLL | Capture DIRSRV interface GUIDs at runtime |
| `capture_dirsrv_errors.py` | MPCCL.DLL | Capture DIRSRV error codes |
| `debug_mpccl.py` | MPCCL.DLL | Step through InitializeLoginServiceSession |

## Client error dialogs (HKLM\SOFTWARE\Microsoft\MOS\Debug)

`MPCCL.DLL` carries a built-in diagnostic mode that pops a message box naming the
exact failure whenever an MPC or MCM call fails. It is off by default and is
enabled through two registry values under
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MOS\Debug`:

| Value | Type | Enables |
|-------|------|---------|
| `DisplayMpcErrors` | `REG_SZ` = `yes` | MPC layer errors (facility `0x8b0b`) |
| `DisplayMcmErrors` | `REG_SZ` = `yes` | MCM dial/login errors |

Comparison is case-insensitive against the literals `yes` and `no`; the value
type is read but never checked, and anything longer than 10 bytes is discarded.
Missing key, missing value, or any other content means disabled. The registry is
re-read on every error, so the values take effect without restarting the client.

`DisplayMpcErrors` gates `MPCCL.DLL:FUN_046010a5`, the central error funnel of
the library (50+ call sites, from `DllGetClassObject` through request building,
parameter marshalling and pipe I/O). It decodes the SCODE and interpolates the
caller's detail string, so failures arrive named rather than silent:

| SCODE | Message |
|-------|---------|
| `0x8b0b0005` | returns silently, no dialog |
| `0x8b0b0006` | Could not maintain connection with MOS / Reason: %s |
| `0x8b0b0007` | OLE libraries are out of date |
| `0x8b0b0008` | Server error occurred: %s |
| `0x8b0b0009` | Timeout while waiting for data from service! |
| `0x8b0b000a` | Limit of 1,073,741,823 requests per service has been reached |
| `0x8b0b000e` | Invalid MPC usage: %s |
| `0x8b0b0019` | caller-supplied text, verbatim |
| `0x8b0b001a` | Unable to locate service '%s' |
| `0x8b0b001b` | Bad pointer to CMosEvents object passed to IMos::WithdrawNotification() |
| `0x8b0b001c` | Unable to locate service '%s' because of version mismatch |
| `0x8b0b001f` / `0x8b0b0020` | De-compression / Compression problem |
| `0x8b0b0021` | Static buffer returned from service is larger than buffer specified in AddParam! |
| `0x8b0b0025` | The following behavior should be fixed later: %s |
| `0x80004002` | Invalid OLE interface was requested |
| `0x80004005` | Catastrophic error: %s / Last Error: 0x%lx |
| `0x8007000e` | Out of memory error occurred |
| `0x80070057` | The following parameter to ::SetConnectionInfo() was too long: '%s' |
| other | Unknown error SCODE is returned: '0x%lx' |

The `%s` detail comes from the call site — service name, parameter name,
`pszUserId` / `pszPassword` / `pszPhoneNumber`, or a usage diagnostic such as
`Unable to open pipe to service '%s', locate param '%s': Error %d`.

`DisplayMcmErrors` gates `MPCCL.DLL:FUN_04601376`, which maps MCM connection
status codes reached from the login path and the MCM notification window proc:

| Code | Message | SCODE |
|------|---------|-------|
| 1, 0x15 | User cancelled login to MOS | `0x8b0b0011` |
| 2 | bad user id | `0x8b0b0012` |
| 3 | no LOGIN service detected | `0x8b0b0013` |
| 4 | no dial tone | `0x8b0b0014` |
| 5 | bad password | `0x8b0b0015` |
| 6 | no carrier | `0x8b0b0016` |
| 7 | busy signal | `0x8b0b0017` |
| 8 | network error | `0x8b0b0018` |
| 9 | InitMos() failed | `0x8b0b0006` |
| 0x0c | Registry keys missing -- Marvel not correctly set up | `0x8b0b0022` |
| 0x0d | Modem or TAPI error during initialization | `0x8b0b0024` |
| 0x0e | Connection was dropped for unkown reasons | `0x8b0b0006` |
| 0x0f | Modem is busy or not found | `0x8b0b0023` |
| 0x10 | GUIDE.EXE is missing | `0x8b0b001e` |
| 0x13 | Shared memory for mcm.dll/guide.exe creation failed | `0x8b0b0006` |
| 0x17 | Win32 API returned the following error: 0x%lx | `0x8b0b0006` |

Unrecognised MCM codes are formatted as `%ld` and forwarded to the MPC reporter
as `0x8b0b0006`, so they surface under `DisplayMpcErrors` instead.

Both paths set the caller's SCODE regardless of the registry values — the
setting only controls the dialog. The dialog is `MB_ABORTRETRYIGNORE` with a
NULL owner: **Abort calls `ExitProcess(0)`** and kills the client, while Retry
and Ignore return and let the failing HRESULT propagate.

`DisplayMpcErrors` is the more useful of the two for server work. Version
mismatch, unknown service, request timeout and pipe-open failure each produce a
distinct message naming the service and parameter involved, which is faster than
inferring the fault from wire silence. `DisplayMcmErrors` covers the dial and
login phase before MPC is running.

## Obtaining the MSN client binaries

The MSN 1.0 client shipped with Windows 95 RTM (August 1995). The binaries are
in the `\MSN\` directory of the Windows 95 CD-ROM. Key files:

| File | Role |
|------|------|
| `GUIDE.EXE` | Main MSN application |
| `MPCCL.DLL` | Marvel Protocol Client COM library |
| `MOSCP.EXE` | Transport engine (packet framing, sliding window) |
| `MOSCL.DLL` | IPC layer (MosSlot shared memory) |
| `ENGCT.EXE` | Alternate transport engine |
| `MOSSHELL.DLL` | Explorer shell namespace extension |
| `SVCPROP.DLL` | Service properties parser |
| `TREENVCL.DLL` | Tree navigation client |

Install MSN from the Windows 95 Add/Remove Programs control panel or copy the
files from the CD directly.

## Ghidra project

The reverse engineering was done with Ghidra. The full project database
(MSN95.gpr/MSN95.rep) is included in this repository via Git LFS, with
analysis annotations for 9 binaries including MPCCL, ENGCT, MOSCP, MOSSHELL,
SVCPROP, TREENVCL, MOSCL, MCM, and GUIDE. Cloning requires Git LFS to be
installed. A narrative of the analysis is in [docs/JOURNAL.md](docs/JOURNAL.md).

## References

- **US 5,956,509** — *System and method for communication between a remote
  client and server using MPC and RPC* (the Marvel protocol patent)
- **US 5,907,837** — *System and method for presenting content from an
  information resource over a network* (MSN content/IR service)
- **US 5,774,668** — *System for on-line service in which gateway operator
  provides service map* (gateway, service maps, load balancing)

## Acknowledgments

This project is done with the help of [Claude Code](https://claude.ai/claude-code).

## License

TBD
