# MOSVIEW.EXE

Reverse-engineering notes for `binaries_de/MOSVIEW.EXE`, the MSN MediaView
host process that opens MedView titles and drives their in-document command
scripts.

Sources: static binary (`objdump`, `wrestool`, `strings`) plus live
decompilation against the `MSN95.gpr` Ghidra project (session
`9ae1a961cac4482cae76c19816dfe875`). The checked-in project currently has
`MOSVIEW.EXE` rebased to `0x7F3C0000`; the raw PE header still reports image
base `0x7F390000`. Addresses below use the **project** base
`0x7F3C0000`.

Companions:

- `docs/BINARIES.md` — catalog entry for the client binary set.
- `docs/MOSSHELL.md` — `HRMOSExec` / app-launch background for App #6.
- `PROTOCOL.md` — app-id table (`c = 6`, `Media_Viewer`) and the generic
  `HRMOSExec(c, args)` contract.

## 1. Identity

- PE GUI EXE, ~54 KiB on disk, timestamp `1995-07-16 22:34:07`.
- PE header image base `0x7F390000`; Ghidra project base `0x7F3C0000`.
- Version resource:
  - `FileDescription = "MSN MediaView Shell"`
  - `InternalName = "MOSVIEW"`
  - `OriginalFilename = "MOSVIEW.EXE"`
  - `FileVersion = 1.60.0`
- 4 exports:

  | Export | Address | Role |
  |---|---:|---|
  | `CreateMediaViewWindow` | `0x7F3C4F26` | Public host-side entry to create or reuse a MediaView session in a shell window. |
  | `MosViewInit` | `0x7F3C2183` | One-time process init for the MedView runtime. |
  | `MosViewStartConnection` | `0x7F3C4504` | Thin wrapper around `MVTitleConnection(..., "MEDVIEW")`. |
  | `MosViewTerminate` | `0x7F3C219D` | Disconnect + teardown of cached sessions and DIB support. |

- Imports prove the role split:
  - `MCM.DLL` — command-line decode (`FGetCmdLineInfo`), UI/errors
    (`MosAbout`, `MosErrorP`).
  - `MVCL14N.DLL` — the real MediaView engine (`hMVTitleOpen`,
    `lpMVNew`, `MVTitleConnection`, `MVTitlePreNotify`, contents/hash APIs).
  - `MMVDIB12.DLL` — MedView DIB/window bootstrap (`InitiateMVDIB`,
    `TerminateMVDIB`).
  - `MOSCOMP.DLL` — progress / palette helpers (`ProgCreate`,
    `ProgAddData`, `ProgSetOutput`, `ProgPaint`).
  - `CCAPI.DLL` — imported for cross-component linking
    (`MOSX_HrCreateCCFromAppidDeid`).

### 1.1 Resources

`wrestool -l` shows a small UI resource set:

| Type | Id | Role |
|---|---:|---|
| `MENU` | 100 | Main viewer menu. |
| `STRING` | 1 | Shell/menu/UI strings ("Online-Viewer", title-info labels, error text). |
| `ACCELERATOR` | 8 | Main accelerator table. |
| `GROUP_ICON` | 7 | Process icon loaded by the shell window bootstrap. |
| `VERSION` | 1 | Standard version metadata. |

The localized strings confirm the user-facing contract:

- invalid-parameter error if nothing title-like is supplied
- "title is being prepared, please wait" loading text
- a temporary-service-unavailable error path
- a `Title info` / copyright UI path

## 2. Role In The Client

`MOSVIEW.EXE` is **App #6** (`Media_Viewer`) in the MOS application table
(`PROTOCOL.md`, field `c`). It is the dedicated out-of-proc host for MedView
titles:

- receives a title selector from the generic MSN app-launch path
- opens a `MEDVIEW` service connection through `MVCL14N`
- creates one top-level shell window class (`MosMediaViewShell`)
- caches per-title MedView sessions so later jumps/popups can reuse them
- executes the command script language embedded in the title payload

Unlike `MOSSHELL.DLL`, it does **not** talk to tree navigation services
directly. It is a content-viewer endpoint that expects to be handed a title id,
title path, or deid-derived selector.

## 3. How It Is Called

For the branch-by-branch enumeration of the DID-launch path
(`MOSVIEW.EXE -MOS:6:<deid_lo>:<deid_hi>:<tail>`) from PE entry to the
first `BitBlt`/`PlayMetaFile`, see
[`re-passes/MOSVIEW-STARTUP.md`](re-passes/MOSVIEW-STARTUP.md). The
sub-sections below summarise the contract; the deep-dive doc owns
the per-branch detail.

## 3.1 Standard MSN launch path

`MosViewMain @ 0x7F3C1053` starts by calling:

```c
FGetCmdLineInfo(&appid, &deid_lo, &unknown, &raw_tail)
```

This is the same MCM-level decode path used by other app hosts. For MOSVIEW,
the expected caller is the generic app dispatcher (`HRMOSExec`) described in
`docs/MOSSHELL.md`: on the common non-DNR path, MCM formats an app-specific
`-MOS:...` command tail and the child process reads it back through
`FGetCmdLineInfo` instead of parsing the raw string itself.

For App #6, that means:

- `appid` defaults to `6` (`Media_Viewer`)
- the deid/title selector is delivered as one or two 32-bit pieces
- any remainder becomes the secondary raw tail

`MOSVIEW.EXE` itself does **not** re-implement the `-MOS:` grammar; it trusts
`FGetCmdLineInfo` to populate the globals it consumes.

## 3.2 Standalone / raw invocation path

If `FGetCmdLineInfo` fails, MOSVIEW falls back to:

- `appid = 6`
- `raw_tail = raw command line after argv[0]`
- `deid_hi = 0`
- `deid_lo = 0`

From there startup accepts two raw forms:

1. A raw title/path token, optionally followed by a space and a second token.
2. Nothing usable, which triggers the localized "invalid parameter" dialog and
   exits.

On the raw path MOSVIEW also synthesizes a stable **single-instance key** by
XOR-folding the raw title text into the two 32-bit deid globals. That key is
not used to open the title; it is used to deduplicate windows in the
single-instance table.

The raw tail is then split at the first space:

- first token -> `titlePath`
- remainder after the first space -> `initialSelector`

`CreateMediaViewWindow(titlePath, initialSelector, hostWindow)` receives those
two values directly.

## 3.3 Deid normalization

Startup turns MCM-provided deid data into the text selector passed down into
the MedView layer:

- if only one 32-bit word is present, it formats it as `%X`
- if two words are present, it formats them as `%X%8X`

So the host accepts deid-derived title selectors in either:

```text
<hex32>
<hex32><hex32-padded-to-8>
```

That normalized selector becomes the primary `titlePath` argument to
`CreateMediaViewWindow`.

## 4. Single-Instance Behavior

Unless the environment variable `MEDIAMULTI` is present, `MosViewMain` enforces
cross-process deduplication:

- named semaphore: `Mosview Single Instance Semaphore`
- named mapping: `Mosview Single Instance Segment`
- mapping size: `0x644`
- slot count initialized to `100`

The shared table is used as a per-title ownership map. Each slot stores:

- a window handle
- unused/auxiliary state
- the synthesized low deid word
- the synthesized high deid word

Liveness is probed with a private message:

- probe message: `0x414`
- expected success reply: `0x456734AF`

If a live slot already owns the same deid pair, MOSVIEW exits early with
`wParam = 1` instead of opening another copy of the same title. A second pass
clears stale slots whose windows no longer answer the probe.

`MEDIATIMEOUT` is a separate environment knob:

- if set, its value is parsed as a signed decimal
- `0` falls back to `40000` ms
- startup arms timer id `1` on the main shell window

## 5. Window And Session Model

## 5.1 Top-level shell window

`CreateMosViewShellWindow @ 0x7F3C1805`:

- loads icon resource 7 and accelerator table 8
- calls `MosViewInit()`
- loads two localized strings for the window class/title
- registers `MosMediaViewShell`
- creates the main host window

`InitializeMosViewUi @ 0x7F3C5D29` runs during init and:

- snapshots screen metrics
- initializes a shared critical section
- boots the DIB support DLL
- registers the MedView child window classes

## 5.2 Per-title cached sessions

`CreateMediaViewWindow @ 0x7F3C4F26` is the public host-side entry:

- probes display DPI/caps
- searches a global linked list of cached title sessions by case-insensitive
  `titlePath`
- reuses an existing session if the path matches
- otherwise allocates a new session record, increments a per-process serial,
  and calls `OpenMediaTitleSession(titlePath, serial, hostWindow)`

If the session exposes a display title, MOSVIEW mirrors it into the main window
caption with `SetWindowTextA`.

This cache is what powers intra-title popups and pane jumps: later commands can
reuse a previously opened title instead of reopening it from scratch.

## 5.3 Opening a MedView title

`OpenMediaTitleSession @ 0x7F3C61CE` is the core loader:

1. Ensures a `MEDVIEW` connection via
   `MosViewStartConnection("MEDVIEW")`.
2. Shows/redraws the host window while loading.
3. Builds the MedView open spec:

   ```text
   :%d[%s]%d
   ```

   using:
   - current MEDVIEW service id (`DAT_7f3cd2e8`, initialized to `2`)
   - caller-supplied `titleSpec`
   - per-process `viewSerial`

4. Calls `hMVTitleOpen`.
5. Allocates a runtime object with `lpMVNew`.
6. Pulls metadata through repeated `lMVTitleGetInfo` scans.

The host copies several opaque metadata buckets into process memory without
trying to interpret the on-disk format itself:

- fixed-size records of `0x2B`
- fixed-size records of `0x1F`
- fixed-size records of `0x98`
- a variable string table (up to 3000-byte buffers)
- display title and copyright-like strings

This is an important boundary: **MVCL14N owns the actual MediaView file/content
format. MOSVIEW only brokers logical title ids, cached metadata blocks, and UI
commands.**

## 6. Parameters And Selector Formats It Accepts

MOSVIEW accepts three meaningful selector families:

### 6.1 App-launch / deid selectors

Produced by the standard MCM app-launch path and normalized to:

```text
%X
%X%8X
```

These are used as the initial `titlePath`.

### 6.2 Raw title/path selectors

Passed directly on the standalone/raw invocation path as the first token after
the executable name:

```text
MOSVIEW.EXE <titlePath>
MOSVIEW.EXE <titlePath> <initialSelector>
```

The second token is preserved separately and forwarded as
`initialSelector`.

### 6.3 In-document title identifiers

`ParseTitleIdentifier @ 0x7F3C77D9` accepts either:

- `0x`-prefixed 8-digit hex
- a compact non-hex alphabet encoding

The non-hex path is a base-43-style accumulator over:

- digits / letters
- `!`
- `.`
- `_`

This is the identifier parser used by verbs like `JumpID`, `PopupID`, and
`PaneID`.

## 7. Embedded Command Script Grammar

The command interpreter is split across:

- `ParseCommandScript @ 0x7F3C436C`
- `ParseCommandTokensRecursive @ 0x7F3C4112`
- `UnquoteCommandArgument`, `StripBacktickQuotes`,
  `StripDoubleQuotes`

The grammar MOSVIEW understands is:

- commands separated by `;`
- command head followed by `(...)`
- nested argument splitting on `,` and `)`
- delimiter suppression inside:
  - double-quoted strings
  - backtick ... apostrophe quoted spans

The parser works in-place on a copied mutable buffer and returns:

- one token vector
- one `{token_ptr, token_count}` span table describing each command

That is why later dispatch code can walk a command list as a flat buffer of
argument pointers.

## 8. Recognized Command Verbs

`HandleMediaTitleCommand @ 0x7F3C5150` recognizes two classes of verbs.

### 8.1 Hard-coded simple commands

These are matched as exact strings:

- `CopyTopic()` — copies the current media/topic blob.
- `TestSearch()` — debug-like search/highlight path using the literal query
  `"trick"`.
- `Unsearch()` — recognized but effectively a no-op in MOSVIEW itself.
- `Exit()` — posts `WM_CLOSE` (`0x10`) to the outer shell frame.
- `Back()` — sends message `0x404` to the parent view.
- `DontForceToForeground()` — flips a global foreground-suppression flag.
- `Contents()` — navigates to the title contents view.

### 8.2 Structured commands parsed from `name(args...)`

These are recognized by command name plus argument count:

- `JumpID`
- `PopupID`
- `PaneID`
- `ClosePane`
- `PositionTopic`
- `WindowAspect`
- `JumpContents`
- `MasterSRColor`
- `MasterNSRColor`
- `BackgroundPic`
- `ExecProgram`
- `PreloadID`
- `PreloadPic`
- `SequencePic`

Observed behaviors:

- `JumpID` / `PopupID` / `PaneID` normalize quoted args, strip any trailing
  `>` suffix, parse the target title id, then route through
  `NavigateViewerSelection`.
- `ClosePane` resolves a child pane and destroys its associated state.
- `PositionTopic` applies saved placement to either the main shell frame or a
  named child view.
- `WindowAspect` sends a private `0x413` pane-control message with packed
  script bytes.
- `BackgroundPic` sends a private `0x42E` pane-control message with background
  image/layout parameters.
- `ExecProgram` feeds a command line directly to `CreateProcessA`.
- `PreloadID` pre-resolves one or more title ids and sends them back through
  `MVTitlePreNotify`.
- `PreloadPic` / `SequencePic` build counted string blobs and pre-notify them
  back into the MedView engine.

The important point is that MOSVIEW is **not** just a passive viewer. The title
payload can script window placement, pane styling, popup navigation, process
launches, and prefetch behavior.

## 9. Service-Side Control Titles

Two helper paths use synthetic service titles rather than normal content titles:

- `SendMedViewStatusMessage @ 0x7F3C5FF4`
- `BroadcastMedViewShutdown @ 0x7F3C60A5`

They open a short `:%d` service title keyed only by the current MEDVIEW service
id and drive it via `MVTitlePreNotify`. MOSVIEW uses that path to:

- report startup/title-open failures
- send a shutdown-style notification during teardown

This is the mechanism behind the "service temporarily unavailable" and
"application will be terminated" style strings in the resource set.

## 10. What It Does *Not* Accept

MOSVIEW does **not** appear to be a generic filesystem media opener:

- no direct `.mvc` / arbitrary filename parser in the host EXE
- no `ShellExecute`-style raw file open path
- no standalone content decoder in the EXE itself

The host accepts:

- MedView title selectors / deid strings
- compact title ids for in-document jumps
- inline command scripts

Actual MediaView content decoding and container parsing is delegated to
`MVCL14N.DLL`.

## 11. Summary

`MOSVIEW.EXE` is the MSN 1.0 **MedView session host**, not the format parser.
Its real responsibilities are:

- decode the app-launch contract from MCM
- normalize raw titles and deids into MedView title strings
- enforce one-window-per-title unless `MEDIAMULTI` disables that gate
- own the top-level shell window and child view classes
- cache live title sessions for later jumps and popups
- interpret the MedView command script language embedded in title payloads

For "how is this invoked?" the short answer is:

- normally by App #6 / `HRMOSExec`
- optionally as `MOSVIEW.EXE <title> [selector]`
- internally always converted into a MedView open spec of the form
  `:%d[%s]%d`

For "what formats does it accept?" the short answer is:

- deid/title hex strings
- compact title identifiers
- inline command scripts

and **not** raw media files. The actual content format lives below MOSVIEW in
`MVCL14N.DLL`.
