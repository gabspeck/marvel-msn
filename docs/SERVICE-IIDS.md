# Service IIDs requested by the client

Every interface ID the MSN client asks MPCCL to resolve on a service pipe. The
server's discovery reply (PROTOCOL.md §5.3) must map each IID listed for a
service to a selector, or the call fails with `E_NOINTERFACE` before any request
reaches the wire.

Source: static analysis of the RTM build in `MSN95.gpr` (root folder), with the
OSR2 build (`osr2/`) checked for differences. Every imm32 occurrence of a
`00028Bxx-0000-0000-C000-000000000046` address was located in every module's
executable sections, including code Ghidra had not disassembled, and each hit
was classified by its call site. The Blackbird rows come from the notes in
`src/server/config.py`; they were not re-checked in this pass because the
Blackbird Ghidra project was not available.

## How the client resolves an IID

- `marshal->vtbl[0x24](name, piid, &svc, version, param)` is
  `MPCCL!OpenOrCreateNamedService` @ `0x04601F75`. It opens the pipe, waits for
  the discovery table, and resolves the single IID at `piid`. When `piid`
  points into a longer run of GUIDs in `.rdata`, only the first 16 bytes are
  read (docs/MEDVIEW.md §2).
- `svc->vtbl[0]` is `MPCCL!QueryOpenedServiceInterface` @ `0x04602EBB`. Calling
  it with another IID resolves that IID against the same discovery table.
- The resolved selector becomes the class byte of every request on that
  interface. Per-call method numbers (`svc->vtbl[0xC](n, …)`) are separate and
  do not need IIDs.

`marshal` is always `CoCreateInstance(CLSID 00028B07, IID 00028B08)`.

## Inventory

`00028Bxx` is shorthand for `{00028Bxx-0000-0000-C000-000000000046}`.

| Service | IID | Version | Param | Call site |
|---|---|---|---|---|
| `LOGSRV` | `00028BC2` | 6 | 0 | `GUIDE.EXE!VerifyAccountViaLogSrv` @ `0x04304024`; `BILLADD.DLL!BillingDlg_FetchWorker` @ `0x004345B2`, `BillingDlg_CommitOI` @ `0x00434953`, `BillingDlg_CommitPM` @ `0x00434B81`; `MCM.DLL!PBKAutoPick` @ `0x04105E7F`, `PBKAutoPickIP` @ `0x04106071`, unnamed site @ `0x04102D33`; `SIGNUP.EXE!OpenPipe_LOGSRV` @ `0x004042EA` |
| `DIRSRV` | `00028B27` | 7 | 0 | `TREENVCL.DLL!CTreeNavClient` @ `0x7F63113D`, created by `MCM.DLL!FGetGoWord_DialogProc`, `GoWord_FetchMatchingDeids`, and `MOSFIND.DLL` @ `0x7E9B1B7C` |
| `BBS` | `00028B27` | 3 | 0 | `CTreeNavClient` via `CreateTnc("BBS", 3, …)` from `BBSNAV.NAV` @ `0x7F5FCD1A` and `MCM.DLL!FGetGoWord_DialogProc` (news URLs) |
| `BBS` | `00028B2F` | 3 | `agid=<n>` | `BBSNAV.NAV` @ `0x7F5FCD1A`: second `vtbl[0x24]` open on the same service after the `CreateTnc`, on opening a message |
| per node | `00028B27` | per node | 0 | `MOSSHELL.DLL!CMosTreeNode::GetConnection` @ `0x7F3FC6B4` |
| per node | `00028B28` | per node | 0 | `TREEEDCL.DLL!CTreeEditClient` @ `0x7F2C11BF`, created by `MOSSHELL.DLL!CMosTreeEdit::GetTec` @ `0x7F403397` |
| per node | `00028B72` | per node | 0 | `DATAEDCL.DLL` @ `0x7F5A13AE` (`CDataEditClient`), created by `MOSSHELL.DLL!CMosTreeEdit::GetDec` @ `0x7F403D44` |
| `FTM` | `00028B25` | 2 | 0 | `FTMAPI.DLL!HrInit` @ `0x7F6B1E32` |
| `OLREGSRV` | `00028B73` | 1 | 0 | `SIGNUP.EXE` @ `0x004030DC` → `FUN_004021E8` |
| `OnlStmt` | `00028B8D` | 3 | 0 | `ONLSTMT.EXE!OnlStmt_WinMain` @ `0x7F351218` and `FUN_7F351084` (reconnect); name is string resource 5 |
| `SASRV` | `00028B8B` | caller | 0 | `SACLIENT.DLL!CSysAdminClient` @ `0x7F3410F1` |
| `MEDVIEW` | `00028B71` | `0x1400800A` | 0 | `MVTTL14C.DLL!hrAttachToService` @ `0x7E844114`, name from `TitleConnection` @ `0x7E8446F3` |
| `FindSvc` | `00028BB0` | 2 | 0 | `MOSFIND.DLL!CFindConnection::HrSearch` @ `0x7E9B136A` |
| `MOSABP` | `00028B22` | 3 | 0 | `MOSABP32.DLL!CAbConnection::HrGetMethod` @ `0x7F4D4311`, `HrDisconnect` @ `0x7F4D428E` |
| `MOSRXP` | `00028B20` | 2 | 0 | `MOSRXP32.DLL!CConn::HrGetMethod` @ `0x7F431967` and `0x7F435B3A`; the site at `0x7F43190E` takes the version from its argument or `this+0x34` |
| `CONFLOC` | `00028B52` | 7 | 0 | `CONFAPI.DLL!CmdInitializeConnection` @ `0x7F5B1166`, `CceJoin` @ `0x7F5B16FC` |
| `CONFSRV` | `00028BC8` | 7 | room string built by `wsprintfA` | `CONFAPI.DLL!CceJoin` @ `0x7F5B16FC` |
| `Bbird_OB` | `{EC76D50B-BAD7-11CE-B21F-00AA004A33DB}` | — | — | `PUBLISH.DLL` @ `0x40F01243` via `COSCL!CMPCConnection::Init` |
| `Bbird_OB` | `{EC76D50A-BAD7-11CE-B21F-00AA004A33DB}` | — | — | `OBCL.EXE` via `COSCL!CMPCConnection::Init` |
| `BBIRService` | `{27916FC1-7F7F-11CE-A366-00AA0051EA9C}` | 1 | — | `IRCS.DLL!IRMpcConnection::DoConnect` @ `0x10005FDA` |

"Per node" rows take the service name and version from the MOSSHELL node's
navigator info (`+0x1AC` name, `+0x1B0` version), so the IID is requested on
whatever service the node's app names. Wire traffic places `CTreeEditClient`
on `DIRSRV` (PROTOCOL.md §7.2.8) and `CDataEditClient` on the node's
application service, observed for `MEDVIEW` and `CONFLOC` (PROTOCOL.md
§7.2.12).

Per service, the IID set the discovery reply has to cover:

| Service | IIDs |
|---|---|
| `LOGSRV` | `00028BC2` |
| `DIRSRV` | `00028B27`, `00028B28` |
| `BBS` | `00028B27`, `00028B2F` |
| `FTM` | `00028B25` |
| `OLREGSRV` | `00028B73` |
| `OnlStmt` | `00028B8D` |
| `SASRV` | `00028B8B` |
| `MEDVIEW` | `00028B71`, `00028B72` |
| `FindSvc` | `00028BB0` |
| `MOSABP` | `00028B22` |
| `MOSRXP` | `00028B20` |
| `CONFLOC` | `00028B52`, `00028B72` |
| `CONFSRV` | `00028BC8` |
| `Bbird_OB` | `EC76D50B…`, `EC76D50A…` |
| `BBIRService` | `27916FC1…` |

## OSR2 differences

- `MSNAPI.DLL` (OSR2 only) opens `BBS` version 3 with `00028B27` @
  `0x7D833E56`, then calls `vtbl[0]` on that service for `00028B2F` @
  `0x7D83547E`, `0x7D836295`, `0x7D8374D8`. It also opens `LOGSRV` version 6
  with `00028BC2` @ `0x7D83339B`.
- Every other service IID and version matches RTM for the modules imported
  under `osr2/`. `TREENVCL`, `CONFAPI`, `FTMAPI`, `MOSABP32` and `MOSRXP32` are
  not imported there.

## `00028Bxx` GUIDs that are not service IIDs

Each module links the same header-generated block of about 116 `00028Bxx`
GUIDs into `.rdata`, so contiguous runs in a binary do not indicate a service
table. These referenced GUIDs are COM class or interface IDs and never go to
MPCCL:

| GUID | Use |
|---|---|
| `00028B07`, `00028B08` | MPC marshal CLSID and interface |
| `00028B00`–`00028B0B`, `00028B1D` | MOSSHELL namespace objects and QIs |
| `00028B2C`, `00028B2E`, `00028BA0` | `MOSSHELL.DLL` `QueryInterface` checks |
| `00028B05` | `CCAPI.DLL`, `CCDIALER.EXE`, `BBSNAV.NAV` (`OleCreateFromFile` CLSID) |
| `00028B0C`, `00028B1E` | `CCEI.DLL`, `CCPSH.DLL` class checks |
| `00028B24`, `00028B81`–`00028B83` | `FTMCL.EXE` `QueryInterface` checks |
| `00028B29`–`00028B2B` | `TEXTCHAT.EXE` automation interface and type library |
| `00028B50`, `00028B51` | `MOSAF.DLL` OLE object CLSID and interface (`BBSNAV`, `MOSAF`) |
| `00028B8E` | `GUIDENAV.NAV` `RegisterActiveObject` CLSID |
| `00028BA1` | `MSNDUI.DLL` class factory |
| `00028BB2`–`00028BB7` | `MOSFIND.DLL`, `MSNFIND.EXE`, `FINDSTUB.DLL` class factories |
