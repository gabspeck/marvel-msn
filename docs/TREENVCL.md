# TREENVCL.DLL

Reverse-engineering notes for `binaries/TREENVCL.DLL`, the **MPC-marshalling
RPC client that ties MOSSHELL's tree node abstraction to the DIRSRV
service**. TREENVCL is the wire half of the GetChildren / GetParents /
GetProperties / GetShabby / EnumShn / ResolveMoniker pipeline that shows up
inside Explorer when the shell is browsing an MSN directory tree.

Sources: static binary + live decompilation against the MSN95 Ghidra
project (session `864cce991bd2450ca5dcd788ff878635` for
`/TREENVCL.DLL`). All addresses in this document are at TREENVCL's
link-time image base `0x7F630000`. Companion to:

- `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` — overlapping coverage of the
  GetChildren-specific call chain and the SVCPROP record layout that
  TREENVCL hands off to.
- `docs/MOSSHELL.md` — the consumer side: how MOSSHELL drives the exports
  here (`OkToGetChildren` → `GetChildren`, `GetNthChild` → `GetNthNode`,
  `GetShabbyToFile` → `GetShabby` / `FreeShabby`).
- `docs/DSNAV.md`, `docs/GUIDENAV.md` — structural template + the
  per-NAV plug-ins that sit one layer up.

## 1. Identity

- PE DLL, 37 KiB total, image base `0x7F630000`, link-time 1995–1996.
- Version resource: `FileDescription = "Microsoft Network TreeNav Client"`,
  `OriginalFilename = TREENVCL.DLL`, `FileVersion = 1.60.0`.
- 40 exported names — all in or related to `CTreeNavClient` — plus the
  ``__stdcall _DllMain@12`` no-op stub. See the inventory table in §3.
- Imports prove the role:
  - `SVCPROP.DLL` — `FDecompressPropClnt` (per-record property decoder),
    `CServiceProperties::~CServiceProperties` / `operator delete`. The
    record-walker hands every record to SVCPROP; this DLL never decodes
    properties itself.
  - `OLE32.DLL` — `CoInitialize` / `CoUninitialize` / `CoCreateInstance`.
    The marshal interface is created via COM (CLSID `00028B07-…`,
    interface IID `00028B08-…`).
  - `KERNEL32.DLL` — `InitializeCriticalSection` / `EnterCriticalSection`
    / `LeaveCriticalSection` / `DeleteCriticalSection` (ref-count guard);
    `GlobalAlloc` / `GlobalFree` (CRT exit handler);
    `MultiByteToWideChar` (`GetDeidFromGoWord`).
  - `USER32.DLL` — `wsprintfA` (`FormatAgentIdString` for the `agid=%d`
    string).
  - CRT — `_strdup` / `malloc` / `free` / `memcpy` / `strcpy` / `strlen` /
    `wcslen` / `_initterm` / new / delete.
- No resources: no MENU / RCDATA / STRING / ICON. Pure RPC client.
- Static data: 4 tables of 8 ulong RPC opcode codes
  (`0x599`, `0x59b`, `0x59c`, `0x59d`, `0xa4c`, `0xe`, `0x73`, `0x86`)
  at `0x7F634014`, `…34`, `…54`, `…74` — one per polymorphic class
  (CTreeNavClient, NodeIterator, CMosEventSink, ShnIterator). Each
  filled lazily by an `_initterm`-style init function. The 8 IIDs at
  `0x7F633270..0x7F6332EC` (`00028B27-…` through `00028B2E-…`) are the
  per-operation interface descriptors registered with the channel at
  open time.

## 2. How the shell reaches it

TREENVCL is **library code**, not a plug-in. Every NAV that wants to talk
to a backing MOS service instantiates a `CTreeNavClient` (typically once
per service) via `MOSSHELL!InitializeNtnigr` / `CreateTnc`, then calls
the export surface as needed. There is no `GETPMTN` here — TREENVCL
itself is invisible to the shell namespace.

The two NAVs that ship with MSN95 and rely on TREENVCL:

- **DSNAV.NAV** (App #1, `Directory_Service`) — calls
  `MOSSHELL!InitializeNtnigr(&g_DsNavNtniGroup, "DIRSRV", 7, 7, &g_DsNavExtraPropTags)`
  on `DLL_PROCESS_ATTACH`. The NtniGroup ends up holding the
  `CTreeNavClient*` and the extras-tag list; per-child enumeration goes
  through MOSSHELL's `CMosTreeNode::OkToGetChildren` →
  `CTreeNavClient::GetChildren` import thunk. Reference:
  `docs/DSNAV.md` §5.1.
- **BBSNAV.NAV** (App #N, BBS / forum service) — same shape, registers
  its own NtniGroup against `"BBSSRV"` (or the equivalent service name).
  Not yet documented in this repo.

The MOSSHELL-level call chain for the most common operation
(`GetChildren`) is:

```
EXPLORER.EXE
  MOSSHELL!CMosShellFolder::EnumObjects           (7F3F2B90)
    MOSSHELL!CMosEnumIDList::Init                 (7F3FB199)
      snapshot->vtbl[3]   GetSnap                 (7F3F35C2)
      snapshot->vtbl[42]  GetCChildren            (7F3FDF47)
        this->vtbl[44]    OkToGetChildren         (7F3FE333)
          TREENVCL!CTreeNavClient::GetChildren    (7F631778)
            CTreeNavClient::GetRelatives(this, 0, ...)
              PackPropNames -> wire send -> open NodeIterator
            CreateNodeIteratorWrapper(0, NodeIterator*)
```

`GetNthChild` later pulls each record via `GetNthNode` →
`NodeIterator_GetAtIndex` → `SVCPROP!FDecompressPropClnt`. The full
GetChildren-specific chain is in
`docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md`. The `GetShabby` icon-blob
fetch (separate RPC, separate selector) is in
`docs/MOSSHELL.md` §"GetShabbyToFile" / `project_mosshell_shabby_call_path`.

## 3. Exports inventory

40 exports, all `__cdecl` factories or `CTreeNavClient` thiscall methods
(four marked `static` are dispatched on the iterator wrapper, not on a
`CTreeNavClient` instance). Ordinals are from the export directory.
Renames in column "Symbol" reflect the names committed to the Ghidra
project on this pass; raw addresses are the entry points.

| Addr | Ord | Symbol | Surface | Purpose |
|---|---:|---|---|---|
| `0x7F6310FE` | 15 | `CreateTnc` | factory | Allocate + construct a `CTreeNavClient` (88 B). |
| `0x7F63113D` | 2 | `CTreeNavClient::CTreeNavClient(server, …, 10 args)` | ctor | Full ctor: dup strings, init CS, optional `CoInitialize`, `CoCreateInstance` marshal, build `CMosEventSink`, register listeners, call marshal `Init`, then `OpenChannel` with the 8-IID list. Sets `error_status` on any failure. |
| `0x7F631368` | 1 | `CTreeNavClient::CTreeNavClient(CTreeNavClient&)` | copy ctor | **Effectively dead.** Constructs a transient local from the source's fields, immediately destructs it, then copies only `timeout`. The `this` object is left mostly uninitialized. |
| `0x7F6313B4` | 3 | `CTreeNavClient::~CTreeNavClient` | dtor | Disconnect via `marshal->vtbl[0x2c](mode)` (mode = 0x40 if `f_interactive`, 0x80 otherwise), unregister own sink, release marshal/channel/co_init_hresult, free strdups, `DeleteCriticalSection`. |
| `0x7F631487` | 12 | `CTreeNavClient::AddRef(CMosEvents*)` | ref | EnterCS; `++ref_count`; if sink != NULL also `marshal->vtbl[6](sink)` (register listener); LeaveCS. |
| `0x7F6314C2` | 34 | `CTreeNavClient::Release(CMosEvents*)` | ref | EnterCS; if sink != NULL `marshal->vtbl[7](sink)` (unregister); `--ref_count`; LeaveCS; if 0 → `~CTreeNavClient` + `operator delete`. |
| `0x7F631515` | 28 | `CTreeNavClient::GetProperties(mnid, prop_count, &tags, *locale, &out_total, &out_iter)` | RPC | Selector ?: open channel pipe, pack `prop_count`, pack tag-name buffer, packs locale, send + receive into `NodeIterator`. Returns iterator wrapper containing the raw property record(s) for **the addressed node itself**. |
| `0x7F631752` | 27 | `CTreeNavClient::GetParents(mnid, max, &tags, *locale, &out_count, &out_iter)` | RPC | `GetRelatives(this, 1, ...)` — direction = parents. |
| `0x7F631778` | 19 | `CTreeNavClient::GetChildren(mnid, max, flags, &tags, *locale, &out_count, &out_iter)` | RPC | `GetRelatives(this, 0, ...)` — direction = children. |
| `0x7F63179F` | 21 | `CTreeNavClient::GetDeidFromGoWord(go_word, *locale, *out_deid)` | RPC | Selector 3: ANSI→wide, send wide string + locale, receive 8-byte deid. |
| `0x7F63190E` | 29 | `CTreeNavClient::GetRelatives(direction, mnid, max, flags, &tags, *locale, &out_count, &out_iter)` | RPC | Selector 2 if `direction==0`, selector 1 if `direction==1`. The wire marshalling core for both `GetChildren` and `GetParents`. Builds wire request via `PackPropNames`, sends, receives into a `NodeIterator`, returns wrapped via `CreateNodeIteratorWrapper(0, …)`. |
| `0x7F631B54` | 35 | `CTreeNavClient::Reset(wrapper*)` | iter | If `wrapper.kind == 0`: zero `NodeIterator.current_index` and `current_offset`. Else: zero `ShnIterator.current_index` (a u16). |
| `0x7F631B72` | 23 | `CTreeNavClient::GetNextNode(wrapper*, *out_props)` | iter | `NodeIterator_GetNext(wrapper.iterator, ...)`. |
| `0x7F631B85` | 25 | `CTreeNavClient::GetNthNode(wrapper*, n, *out_props)` | iter | `NodeIterator_GetAtIndex(wrapper.iterator, n, ...)`. |
| `0x7F631B9C` | 32 | `CTreeNavClient::NodesAvailableNow(wrapper*)` | iter | `NodeIterator_CountRemaining(wrapper.iterator)` — tells the caller how many more records can be served without another wire round-trip. |
| `0x7F631BAB` | 30 | `CTreeNavClient::GetShabby(shabby_id, &out_blob, &out_size, &out_status)` | RPC | Selector 4: pack shabby_id (DWORD), receive `IMosStatus*` + dynamic-section blob. Caller frees blob via `FreeShabby`. |
| `0x7F631D1F` | 16 | `CTreeNavClient::EnumShn(key, &out_id, &out_iter)` | RPC | Selector 5: pack 1-byte key, receive `id` (u16) + a fixed-stride dword stream wrapped as `ShnIterator`. Returned via `CreateNodeIteratorWrapper(1, …)`. |
| `0x7F631E76` | 24 | `CTreeNavClient::GetNextShn(wrapper*, *out_dword)` | iter (static) | `ShnIterator_GetNext(wrapper.iterator, ...)`. |
| `0x7F631E87` | 26 | `CTreeNavClient::GetNthShn(wrapper*, n, *out_dword)` | iter (static) | `ShnIterator_GetAtIndex(wrapper.iterator, n, ...)`. |
| `0x7F631E9C` | 36 | `CTreeNavClient::ResolveMoniker(wide_str, *out_deid, *locale, *out_path)` | RPC | Selector 6: send wide moniker string + locale, receive 8-byte deid + optional malloc'd wide path string. Caller frees with `FreeMoniker`. |
| `0x7F632040` | 31 | `CTreeNavClient::IsValid()` | accessor | Returns `error_status` (note: returns the **status**, not a boolean — caller must `== 0`). |
| `0x7F632044` | 13 | `CTreeNavClient::CloseHDyn(wrapper*)` | iter (static) | If `kind` is 0 or 1 and `iterator` non-NULL: invoke `iterator->vtable[0](1)` (vector dtor with delete), then `free(wrapper)`. |
| `0x7F632051` | 17 | `CTreeNavClient::FreeMoniker(wide_str)` | mem | `free(ptr)`. |
| `0x7F632060` | 18 | `CTreeNavClient::FreeShabby(blob)` | mem | `free(ptr)`. |
| `0x7F63206F` | 33 | `CTreeNavClient::PackPropNames(&tags, &out_count, &out_size)` | helper | Concatenate the NULL-terminated ASCII-string list `tags` into one malloc'd buffer of NUL-separated names, returning that buffer plus `count` and total `size`. |
| `0x7F631000` | 20 | `CServiceProperties::GetCount` | accessor (re-export) | Returns `*(ulong*)this`. Re-exported here because TREENVCL's headers ship the iterator surface together with this read accessor. |
| `0x7F631054` | 22 | `CTreeNavClient::GetIMos(*out)` | accessor | AddRef the marshal (`marshal->vtbl[1]`); write marshal pointer to out. |
| `0x7F63106D` | 14 | `CTreeNavClient::ConnectionDropped()` | event | Public mirror of the event-sink's slot-1 callback: writes `error_status = 0x104`. |
| `0x7F631075` | 37 | `CTreeNavClient::SetFInteractive(int)` | setter | Writes `f_interactive`. Influences disconnect mode in dtor. |
| `0x7F63107F` | 38 | `CTreeNavClient::SetTimeOut(ulong)` | setter | Writes `timeout`. Snapshotted into iterator at construction. |
| `0x7F6310F6` | 39 | `_DllMain@12` | DllMain | `return 1;` — no per-process or per-thread setup. The CRT-side init runs out of `entry`/`CRTDllExitHandler`. |
| `0x7F6320F0` | 6 | `CServiceProperties::operator=` | re-export | 12-byte copy (`(uint*)this[0..2] = (uint*)from[0..2]`). Same comment as `GetCount`. |
| `0x7F632102` | (n/a) | `CServiceProperties::scalar_deleting_destructor` | re-export | dtor + `operator delete(this)` if flag bit 0 set. |
| `0x7F632120` | (n/a) | `CServiceProperties::vector_deleting_destructor` | re-export | per-element dtor loop + `operator delete[]` if flag bit 0 set. |
| `0x7F632178` | (n/a) | `CTreeNavClient::operator=` | (compiler-emitted) | Memberwise copy. |
| `0x7F63218E` | (n/a) | `CTreeNavClient::scalar_deleting_destructor` | (compiler-emitted) | `~CTreeNavClient` + optional delete. |
| `0x7F6321AC` | (n/a) | `CTreeNavClient::vector_deleting_destructor` | (compiler-emitted) | per-element dtor + optional `delete[]`. |
| `0x7F632370` | (n/a) | `NodeIterator_GetNext` | helper | Bound check + `NodeIterator_GetAtIndex(this, current_index, &props)`. |
| `0x7F63238A` | (n/a) | `NodeIterator_GetAtIndex` | helper | Walk the dynamic-section buffer record-by-record, refresh on `0xB0B000B`, dispatch each record body to `SVCPROP!FDecompressPropClnt`. The hot path. |
| `0x7F63286B` | (n/a) | `CreateNodeIteratorWrapper` | helper | `malloc(8)` then store `kind` and `iterator` — the 8-byte handle the shell receives. |

> Address fix: an earlier copy of
> `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` cited a wrong page-3
> address for `NodeIterator_GetAtIndex`. The correct address is
> `0x7F63238A`. The companion doc is updated in this pass.

## 4. CTreeNavClient shape

`CTreeNavClient` is 88 (`0x58`) bytes, allocated via `operator new(0x58)`
in `CreateTnc`. Layout (carved into `/Demangler/CTreeNavClient` in the
Ghidra project):

| Off | Size | Field | Notes |
|---:|---:|---|---|
| `0x00` | 4 | `server_name` | `_strdup(CreateTnc.param_1)`. Server hostname. |
| `0x04` | 4 | `open_arg_b` | `CreateTnc.param_2`. Passed as 4th positional arg to `marshal->OpenChannel`, after the IID list. Treat as opaque for now. |
| `0x08` | 2 | `agent_id` | `CreateTnc.param_3`. Rendered into `"agid=%d"` via `FormatAgentIdString`. `0xFFFF` means "no agent id" → NULL string passed to `OpenChannel`. |
| `0x0a` | 2 | `agent_id_pad` | Alignment pad. |
| `0x0c` | 4 | `init_arg1` | `_strdup(CreateTnc.param_5)`. Sent as 1st argument to `marshal->Init`. |
| `0x10` | 4 | `init_arg2` | `_strdup(CreateTnc.param_6)`. 2nd arg to `marshal->Init`. |
| `0x14` | 4 | `init_arg3` | `CreateTnc.param_7`. 3rd arg to `marshal->Init`. |
| `0x18` | 4 | `init_arg4` | `_strdup(CreateTnc.param_8)`. 4th arg to `marshal->Init`. |
| `0x1c` | 4 | `f_interactive` | `CreateTnc.param_9`. `SetFInteractive` setter. dtor passes `0x40` if non-zero, `0x80` otherwise to `marshal->vtbl[0x2c]` (disconnect mode). |
| `0x20` | 4 | `f_co_init` | `CreateTnc.param_10`. If non-zero ctor calls `CoInitialize` on this thread and dtor calls `CoUninitialize`. |
| `0x24` | 4 | `marshal` | `CoCreateInstance(CLSID 00028B07-…, IID 00028B08-…)`. The `IMpcInterface` marshal. NULL on init failure. |
| `0x28` | 4 | `channel` | Open channel handle from `marshal->OpenChannel`. **Every export tests `channel != 0` first** and returns `0x100` if NULL. |
| `0x2c` | 4 | `own_event_sink` | `operator new(8)`-allocated `CMosEventSink`; vtable `0x7F633748`. Slot 1 = `OnConnectionDropped` writes `error_status = 0x104` to the owner. The ctor registers it with the marshal as the listener for transport events. |
| `0x30` | 4 | `co_init_hresult` | If `f_co_init`: heap-allocated `HRESULT*` holding `CoInitialize` return. dtor calls `CoUninitialize` iff `*coinit_hresult >= 0`, then `delete`. NULL when `f_co_init == 0`. |
| `0x34` | 4 | `timeout` | RPC wait timeout. Default `0xFFFFFFFF` (INFINITE), settable via `SetTimeOut`. Passed as `timeout` arg to data-iface `vtbl[5]` (advance) and `vtbl[7]` (refresh). Snapshotted into `NodeIterator.timeout` / `ShnIterator.timeout` at iterator construction. |
| `0x38` | 4 | `error_status` | DS status code. `0` = valid; `0x100` = generic init failure; `0x101` = bad ctor argument; `0x104` = connection dropped (set by event sink); `0x106` = OOM. `IsValid()` returns this. |
| `0x3c` | 4 | `ref_count` | Initial 1. `AddRef` / `Release` update under `cs`. Release drops to 0 → `~CTreeNavClient` + `operator delete`. |
| `0x40` | 24 | `cs` | `CRITICAL_SECTION`. Protects `ref_count` and AddRef/Release listener (un)registration. |

`error_status` is the only multi-source field: ctor writes it on any
init failure, the event sink slot 1 callback writes it on connection
loss, and `ConnectionDropped` exposes that callback as a public method.

## 5. Expected input shape

Each hot-path export imposes very specific argument requirements on the
caller. The tables below are the contract a CMosTreeNode (or whatever
callsite) must satisfy.

### 5.1 GetChildren / GetParents / GetRelatives

```
ulong GetChildren( CTreeNavClient* this,
                   _LARGE_INTEGER  mnid,        // 8-byte node id
                   int             max_count,   // hard cap, 0 = no cap
                   ulong           flags,       // 0 in current MOSSHELL paths
                   char**          tags,        // NULL-terminated array of ASCIIZ tag names
                   _LOCALES*       locale,      // count-prefixed dword array
                   ulong*          out_count,   // server's reported child count
                   void**          out_iter ); // wrapper(0, NodeIterator*)
```

Required:

- `tags` non-NULL, points to an array of `char*`, NULL-terminated. Each
  string is a 1-3 char ASCII property name (`"a"`, `"c"`, `"b"`, `"e"`,
  `"g"`, `"h"`, `"x"`, plus any plug-in extras — see `docs/DSNAV.md` §5.2).
- `max_count` non-zero (callers always pass a positive cap).
- `out_count`, `out_iter` both non-NULL.
- `channel != 0` (else returns `0x100`).

If any of `tags` / `max_count` / `out_count` / `out_iter` is missing,
returns `0x101` (bad-arg).

### 5.2 GetProperties

```
ulong GetProperties( CTreeNavClient* this,
                     _LARGE_INTEGER* mnid,       // pointer (not value) to 8-byte node id
                     ulong           prop_count, // number of tags requested
                     char**          tags,
                     _LOCALES*       locale,
                     ulong*          out_total,
                     void**          out_iter );
```

Same shape as GetRelatives but for **a single node's own** properties
(returns one record). The wire selector is distinct from selectors
1/2 (the ctor RPC opcode table is laid out for at least 8 selectors;
GetProperties uses one of the entries past 1/2/3/4/5/6 — exact value
not yet pinned down, see §14).

### 5.3 GetShabby

```
ulong GetShabby( CTreeNavClient* this,
                 ulong           shabby_id,    // resource id; same domain as MOSSHELL's GetShabbyToFile
                 void**          out_blob,
                 ulong*          out_size,
                 IMosStatus**    out_status ); // optional (NULL ok)
```

`out_status`, if non-NULL, receives an AddRef'd `IMosStatus*` describing
the server's status response. The caller may use it for retry / progress
UI; if `NULL`, the status object is created and released internally.

### 5.4 GetDeidFromGoWord

```
ulong GetDeidFromGoWord( CTreeNavClient* this,
                         char*            ansi_keyword,    // ASCII Go Word
                         _LOCALES*        locale,
                         _LARGE_INTEGER*  out_deid );      // 8 bytes filled in
```

`MultiByteToWideChar` is invoked internally (CP_ACP, length -1, max 512
WCHARs). The wide string is what actually goes on the wire.

### 5.5 EnumShn

```
ulong EnumShn( CTreeNavClient* this,
               uchar           key,        // 1-byte enum key
               ushort*         out_id,     // capacity / handle for the iterator
               void**          out_iter ); // wrapper(1, ShnIterator*)
```

The 16-byte ShnIterator returned wraps a fixed-stride dword stream — each
`GetNextShn` / `GetNthShn` call yields one `ulong` to the caller.

### 5.6 ResolveMoniker

```
ulong ResolveMoniker( CTreeNavClient* this,
                      ushort*         wide_moniker,
                      _LARGE_INTEGER* out_deid,
                      ulong*          locale_array,  // count-prefixed dword array
                      ushort**        out_path );    // optional malloc'd wide path
```

`*out_path`, if returned, is allocated with `malloc` and must be
released by the caller through `FreeMoniker` (which is just `free`).

## 6. Wire request — `PackPropNames`

Property tag lists in MOS are the C layout:

```
char* tags[N] = { "a", "c", "b", "e", "g", "h", "x", NULL };
                 // each entry NUL-terminated ASCII; array NULL-terminated
```

`PackPropNames` (`0x7F63206F`) flattens this into one packed buffer
suitable for marshal `vtbl[9]`-style "send opaque bytes":

1. First pass — count: walk `tags[]` until NULL, summing
   `strlen(tags[i]) + 1` (the +1 keeps the trailing NUL of each entry).
2. `malloc(total_size)`.
3. Second pass — copy: `strcpy` each entry, then advance the destination
   pointer by `strlen(dest) + 1` so the next `strcpy` lands right after
   the previous NUL.
4. Write `count` and `size` into the caller's out-parameters; return
   the malloc'd buffer.

Result for the default DSNAV 7-tag list `{a,c,b,e,g,h,x}`:

```
'a' 0x00 'c' 0x00 'b' 0x00 'e' 0x00 'g' 0x00 'h' 0x00 'x' 0x00
size = 14   count = 7
```

For DSNAV's full 14-tag list (default + 7 extras `{mf,wv,tp,p,w,l,i}`),
the buffer is 27 bytes and `count = 14`. The caller is responsible for
`free`-ing this buffer after the wire send completes — `GetRelatives`
and `GetProperties` each do exactly that around the marshal call.

## 7. Wire reply — `NodeIterator` walk

The reply comes back in two tracks:

- **Static fields** in the receive descriptors (status word, total node
  count). For `GetRelatives` these are written into the iterator at
  construction; for `GetProperties` the count is the property record
  count for the addressed node.
- **Dynamic section** — a stream of variable-length records, each prefixed
  by its own size. The MPC marshal exposes this stream via a
  data-iface object whose vtable shape is:

  | Offset | Method | Notes |
  |---:|---|---|
  | `+0x08` | `Release` | drop ref, may invalidate buffer pointers |
  | `+0x0c` | `GetBasePtr` | returns `void*` to start of currently-loaded slab |
  | `+0x10` | `GetSize` | returns `ulong` total bytes in currently-loaded slab |
  | `+0x14` | `Advance(timeout, 0)` | release current slab and pull the next; returns `0xB0B000B` to signal "block boundary" |
  | `+0x1c` | `Refresh` | reacquire after Advance; returns the new buffer ptr indirectly via re-call of `GetBasePtr` |

`NodeIterator_GetAtIndex` (`0x7F63238A`) is the hot loop. For target
index `i`:

```
if (i >= node_count)            return 0x105;   // "no more nodes"
if (i < current_index)
  current_index = current_offset = 0;          // rewind
                                                 // (caller may seek back)

while (current_index <= i):
  ensure (record header at current_offset is in-buffer);
    if buffer too small:
      Advance(timeout, 0);
        if status < 0  -> HResultToDsStatus
        if status == 0xB0B000B  -> mark "end-of-block"
      Refresh()
      if exhausted:
        node_count = NodeIterator_CountRemaining(this) + current_index;
        if node_count <= i  return 0x105;
  stride = *(uint32*)(buffer + current_offset);
  next_offset = current_offset + stride;
  ensure (entire record up to next_offset is in-buffer); same Advance/Refresh dance
  if (current_index < i)        current_offset = next_offset;
  current_index++;

# At this point the i-th record sits at buffer[current_offset .. current_offset + stride].
status = FDecompressPropClnt( (ulong*)(buffer + current_offset),
                              *(ulong*)(buffer + current_offset),
                              out_props );
if (status == 0)                return 0x113;     # decompress failed
current_offset = found_offset;
current_index  = i + 1;
return 0;
```

Key invariants:

- Each record begins with a `uint32 stride` whose value is the **byte
  count of this record including the stride dword itself**.
- The record body (after the stride dword) is what `FDecompressPropClnt`
  parses — total_size, prop_count, then `[type][asciiz name][value]`
  triples. See `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` §"SVCPROP.DLL
  — record parser" for the per-record format.
- `0xB0B000B` is the block-boundary sentinel: the data-iface refuses to
  return more bytes until you Refresh. The walker treats it as "fetch
  more" rather than as an error.
- `0x105` ("no more nodes") and `0x113` (decompress failed) are the only
  negative outcomes the walker emits itself; everything else is a passed
  through `HResultToDsStatus` translation of the marshal HRESULT.
- `node_count` is **not** trusted as a hard upper bound — the walker
  re-derives it from `NodeIterator_CountRemaining` whenever a refresh
  exhausts the current block.

## 8. Materialization

TREENVCL's job ends at handing the caller a `CServiceProperties` per
record. The shell's transcription path is:

```
CMosTreeNode::GetNthChild  (MOSSHELL 7F3FDFC4)
  CTreeNavClient::GetNthNode(handle, parent->dyn_handle, idx, &props)
    NodeIterator_GetAtIndex   ; FDecompressPropClnt populates &props
  CServiceProperties::FGet(props, "a", ..., out_mnid_blob)
  HrGetPMtn(out_mnid, &child, 0)              ; reuse or build the child node
  child->vtbl[10](child, &props, request_tags) ; CMosTreeNode::SetPropertyGroupFromPsp
```

`SetPropertyGroupFromPsp` (`MOSSHELL` ord `0x75`) is the boundary —
beyond it, the properties live in MOSSHELL's per-node cache and TREENVCL
is no longer involved.

## 9. Icon path — `GetShabby` / `FreeShabby`

A separate RPC from the tree-walk. `GetShabby` (selector 4) round-trips:

- **Send**: shabby_id (DWORD, packed via `pipe->vtbl[10]/+0x28`).
- **Receive**: status (DWORD); on completion, a status object
  (`IMosStatus*`) whose `vtbl[7]/+0x1c` exposes a data-iface from which
  the blob is read end-to-end via `GetSize` + `GetBasePtr` + `memcpy`
  into a fresh `malloc`.
- **Output**: `*out_blob` = malloc'd buffer (caller frees via
  `FreeShabby` = `free`); `*out_size` = bytes; optional `*out_status` =
  AddRef'd `IMosStatus*` (caller may inspect / Release).

If the optional `IMosStatus**` argument is non-NULL, the function
**AddRefs the status object** and writes the pointer; otherwise it
releases internally. The blob itself is what MOSSHELL's `GetShabbyToFile`
(MOSSHELL `FUN_7F4049F9`) feeds into `ExtractIconEx` for `.ico`/`.exe`/
`.dll` resources, or writes to disk and `LoadImage`s for bitmap data —
see `project_mosshell_shabby_call_path` for the consumer side.

## 10. Moniker family

A 3-method group for resolving symbolic `wchar_t*` monikers into 8-byte
mnids (deids):

- `ResolveMoniker(wide_str, *out_deid, *locale, *out_path)` — selector 6.
  Sends the wide string + locale, receives:
  - 8 bytes (memcpy'd into `*out_deid`),
  - optionally a malloc'd wide path / canonical name in `*out_path`
    (only if the data-iface reports a non-zero size).
- `IsValid()` — exposes `error_status`. `0` means the client is in a
  state where `ResolveMoniker` (and the rest of the surface) is callable.
- `FreeMoniker(wide_str)` — releases what `*out_path` returned. Just
  `free(ptr)`.

DSNAV does not invoke `ResolveMoniker` from any code path identified in
this RE pass; it is reachable from `MOSSHELL` (the verb-launch / "Go"
field path) and from external callers that synthesize a wire-friendly
deid out of a user-typed keyword.

## 11. Enum family — Shn

`Shn` denotes a numeric handle / ID enumeration. The wire shape is a
**fixed-stride dword stream** rather than per-record property bags:

- `EnumShn(key, *out_id, *out_iter)` — selector 5. Sends a 1-byte enum
  key, receives:
  - status DWORD,
  - capacity / handle (`u16` → `ShnIterator.capacity`),
  - data-iface to a packed `ulong[]`.
- `GetNextShn(wrapper, *out_dword)` — advance `ShnIterator.current_index`
  if `< capacity`, then `ShnIterator_GetAtIndex(this, prev_index, out)`.
- `GetNthShn(wrapper, n, *out_dword)` — pull from `data_iface` until the
  buffer covers `n*4 + 4` bytes, then `*out = data_buffer[n]`. The walker
  uses the same Advance/Refresh dance with the same `0xB0B000B`
  sentinel as the property-record walker.
- `CloseHDyn(wrapper)` — generic wrapper destructor: invokes
  `iterator->vtable[0](1)` (vector dtor with delete) then `free(wrapper)`.

The wrapper's `kind` field (`0` for `NodeIterator`, `1` for `ShnIterator`)
is what `Reset` and `CloseHDyn` use to dispatch to the right backing
type. Both kinds share the exact same `data_iface` vtable shape and the
same `0xB0B000B` block-boundary protocol.

## 12. Error taxonomy

DS status codes (returned in `error_status` and from RPC exports) seen
in this DLL:

| Code | Symbol (from MOSSHELL/SVCPROP) | Meaning in TREENVCL |
|---:|---|---|
| `0`     | `S_OK` | success |
| `0x100` | `DS_E_GENERIC` | generic failure; no channel, or fallback when no specific mapping |
| `0x101` | `DS_E_BADARG` | required out-pointer or input was NULL |
| `0x104` | `DS_E_DISCONNECTED` | event-sink slot 1 fired (`OnConnectionDropped`) |
| `0x105` | `DS_E_NOMORENODES` | iterator exhausted |
| `0x106` | `DS_E_OUTOFMEMORY` | `operator_new` / `malloc` returned NULL |
| `0x107` | `DS_E_…` | from HRESULT `0x8B0B0006` |
| `0x108` | `DS_E_…` | from HRESULT `0x8B0B0007` |
| `0x109` | `DS_E_…` | from HRESULT `0x8B0B0009` |
| `0x10a..0x111` | `DS_E_…` | from HRESULTs `0x8B0B0011..0x8B0B0018` (each maps individually) |
| `0x113` | `DS_E_DECOMPRESS` | `FDecompressPropClnt` returned 0 (record body parse failed) |
| `0x119` | `DS_E_…` | from HRESULT `0x8B0B0022` |
| `0xB0B000B` | (raw HRESULT) | "end of block" — internal, consumed by the walker |

The `HResultToDsStatus` table at `0x7F632204` is the one place that knows
the HRESULT → DS-status mapping; the rest of the file just calls into it.

## 13. Related DLLs and docs

- **`SVCPROP.DLL`** — owns `FDecompressPropClnt` and `CServiceProperties`.
  Per-record property layout, type-byte → encoding table, and the
  `0x0A` / `0x0B` gotcha are documented in
  `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` §"SVCPROP.DLL — record
  parser" and §"DecodePropertyValue (7F64143A)".
- **`MOSSHELL.DLL`** — consumes TREENVCL via its NtniGroup abstraction.
  The shell-side walk for `GetChildren` / `GetNthChild` /
  `GetShabbyToFile` is in `docs/MOSSHELL.md` and the GetChildren-specific
  detail in `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md`.
- **`DSNAV.NAV`** — the App #1 plug-in that registers `"DIRSRV"` as the
  service name and contributes 7 extra per-child property tags; reachable
  from every DIRSRV browse. See `docs/DSNAV.md`.
- **`GUIDENAV.NAV`** — does *not* use TREENVCL (HOMEBASE / Favorite Places
  is a client-local store), but its tree-shape and plug-in template are
  documented in `docs/GUIDENAV.md`.
- **MPC marshal** — CLSID `00028B07-0000-0000-C000-000000000046`,
  interface IID `00028B08-…`. Defined in OLE, registered by MOSCP /
  MPCCL. Not yet RE'd in this repo; for now, treat the marshal vtable
  slots TREENVCL touches as opaque entry points (see §4 column "marshal").

## 14. Known gaps / follow-ups

- **`GetProperties` selector** — not pinned down. The opcode-table
  init functions allocate room for 8 selectors per class; selectors 1,
  2, 3, 4, 5, 6 are accounted for by GetParents / GetChildren /
  GetDeidFromGoWord / GetShabby / EnumShn / ResolveMoniker. GetProperties
  uses one of the remaining slots; identifying which would need a live
  trace (e.g. SoftICE bp on the marshal `vtbl[3]` open) or a more careful
  decompile of the deadcode-mangled GetProperties body.
- **Marshal vtable shape** — slots `+0x04` (AddRef-ish?), `+0x08`
  (Release), `+0x0c` (open-pipe/operation), `+0x10` (Init: 4 args),
  `+0x18` (RegisterListener), `+0x1c` (UnregisterListener), `+0x24`
  (OpenChannel), `+0x2c` (Disconnect/mode) are all that TREENVCL touches.
  The full IID `00028B08` interface should be RE'd from MOSCP / MPCCL
  (out of scope here).
- **Pipe vtable shape** — TREENVCL uses `vtbl[2]/+0x08` (Release),
  `vtbl[6]/+0x18` (PackReceiveDword), `vtbl[7]/+0x1c` (PackReceiveU16),
  `vtbl[9]/+0x24` (PackSendBytes), `vtbl[10]/+0x28` (PackSendDword),
  `vtbl[12]/+0x30` (PackSendByte), `vtbl[16]/+0x40` (FinalizeSend),
  `vtbl[18]/+0x48` (Receive). Slot names inferred from argument shape;
  not cross-checked against MPC documentation.
- **`open_arg_b`** — `CTreeNavClient.open_arg_b` (offset `0x04`) is
  passed as the 4th arg to `marshal->OpenChannel` after the IID list
  pointer. Likely the IID count (= 8), but treat as opaque until
  confirmed.
- **The 8 IIDs at `0x7F633270..0x7F6332EC`** — `00028B27-…` through
  `00028B2E-…`. Each presumably corresponds to one of the operation
  selectors (1..8) but the selector → IID mapping is not enumerated
  in TREENVCL; lives in the MPC marshal's registration logic.
- **Copy ctor** at `0x7F631368` is the buggy pattern noted in §3:
  constructs a transient stack copy then immediately destructs it,
  copying only `timeout` to `this`. Likely never called in practice
  (the export exists because the C++ class declaration mandates it).
  Worth confirming with a callers query in MOSSHELL/DSNAV/BBSNAV.

## 15. Ghidra annotations shipped in this pass

All changes live in the MSN95 project (`MSN95.gpr`), session
`864cce991bd2450ca5dcd788ff878635` for `/TREENVCL.DLL`. Renamed
functions and structures:

- Functions (15): `CMosEventSink_Construct`, `FormatAgentIdString`,
  `CTreeNavClient_OpcodeTableInit`, `NodeIterator_OpcodeTableInit`,
  `NodeIterator_Destruct`, `NodeIterator_VectorDtor`,
  `CMosEventSink_OpcodeTableInit`, `ShnIterator_Construct`,
  `ShnIterator_Destruct`, `ShnIterator_GetNext`, `ShnIterator_GetAtIndex`,
  `ShnIterator_VectorDtor`, `ShnIterator_OpcodeTableInit`,
  `CloseHDyn_Impl`, `CRTDllExitHandler`.
- Structs (4):
  - `/Demangler/CTreeNavClient` — resized to 88 bytes; 18 fields named.
  - `/MSN/NodeIterator` — 24 bytes, 6 fields.
  - `/MSN/ShnIterator` — 16 bytes, 5 fields.
  - `/MSN/NodeIteratorWrapper` — 8 bytes, 2 fields.
- Plate comments authored on `NodeIterator_GetAtIndex`,
  `NodeIterator_GetNext`, `CreateNodeIteratorWrapper`,
  `NodeIterator_Constructor`, `NodeIterator_CountRemaining`,
  `GetProperties`, `HResultToDsStatus`, `GetNextNode` (existing
  passes plus this one).

Functions intentionally **left as `param_N` / `iVar`** — the wire
marshalling exports (`GetRelatives`, `GetProperties`) trip Ghidra's
deadcode-elimination pass; the decompiler emits `unaff_*` registers in
place of the trailing parameters. A more ambitious cleanup would set
explicit `__thiscall`-with-stack signatures and force re-decomp; not
attempted in this pass because the doc above is the canonical reference
for those signatures.
