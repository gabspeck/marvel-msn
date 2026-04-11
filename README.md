# MSN for Windows 95: Reverse-Engineering the Marvel Protocol

Reverse engineering the undocumented wire protocol used by **MSN 1.0 for
Windows 95** (July 1995). The protocol, internally codenamed **"Marvel"**, is a
completely bespoke Microsoft protocol stack — not PPP, not DCOM, not any public
standard.

This project includes a working **emulated server** that drives the original
1995 client through dial-up bootstrap, login, service discovery, and directory
browsing. The MSN Shell window renders and displays the content tree.

## Demo

Currently we can sign in, display the home page and sign out. 

https://github.com/user-attachments/assets/1d8861a0-0a3d-4df9-ba5a-276dedcee68f

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
