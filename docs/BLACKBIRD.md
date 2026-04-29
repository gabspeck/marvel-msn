# Microsoft Blackbird — Authoring Tool

Documents the Blackbird 11.0.06.0206 authoring suite shipped alongside MSN 1.0 and 2.0. Blackbird is the Microsoft-internal content-authoring tool used to create and publish MSN titles (the MOSVIEW content MSN Today opens). All addresses are image-base-relative in the newly-created `Blackbird.gpr` project at repo root.

The authoring-side OLE2 container is the familiar `.TTL` compound file. One reference sample ships in `resources/titles/4.ttl`.

---

## 1. Package contents

Blackbird's on-disk footprint under `ftp/BlackBird/` is ~5 MB of PE modules plus help/palette resources. Priority binaries imported to `Blackbird.gpr`:

| Binary | Size | Role |
|---|---:|---|
| `PUBLISH.DLL` | 39 KB | **MSN release publisher.** In-proc COM server exporting the publisher class factory. Converts a content object into a COSCL compound file and ships it to the data center. |
| `COSCL.DLL` | 287 KB | **Compound Object Store Client Library.** Owns all OLE2 compound-file I/O (`StgCreateDocfileOnILockBytes` / `StgOpenStorageOnILockBytes`) plus local MS-RPC to `OBCL.EXE`. Exports `CObjectStore`, `CObjectStoreFactory`, `CPropertyTable`, `CMPCFileWrite`, `extract_object`, the `CDPO*` reference machinery. |
| `BBDESIGN.EXE` | 730 KB | **Authoring host.** The Blackbird IDE. Contains the `CReleasePageMSN` wizard page, the `CReleaseData` model, and the `CReleaseWizard_*` dispatch glue that drives `PUBLISH.DLL`. |
| `OBCL.EXE` | 137 KB | **Object Broker.** Caching proxy between the authoring client and the server (`SuperCOS` / `SubCOS` archive pattern). Listens for MS-RPC from COSCL. Out of the publish critical path but participates in object retrieval / cache prefetch. |
| `BBVIEW.EXE` | 190 KB | **Local-preview viewer.** Opens `.TTL` files produced by the Local-target release branch. |
| `BBCTL.OCX` | 264 KB | Control library used by authoring surfaces. |
| `BBCONV.EXE` / `CVRT.EXE` | 57 / 41 KB | Authoring-format converter (BBML / HTML / BDF). Off the MSN release path; imported for completeness. |

Skipped on the first pass (low relevance): `FORMS3.DLL`, `IRCS/IRFIND/IRUT`, `WLTFOR55`, `QDOC32`, `MSBMP/GIF/JPEG/PCX/TGA/TIFF32`, `VIEWDLL.DLL`, `NODEEXEC.EXE`, `FINDAPP.EXE`, `REGSVR32.EXE`, `MOSCOMP.DLL`, `FIND.OCX`, `PPG.OCX`.

---

## 2. Process model

Authoring runs as ordinary user processes on the Blackbird workstation:

- **`BBDESIGN.EXE`** — the IDE. Holds the content object graph (`CRootContentFolder`, `CTitle`, `CBForm`, `CVForm`, `CStyleSheet`, `CResourceFolder`) in memory, backed by a COSCL `CObjectStore`.
- **`OBCL.EXE`** — started separately as the object broker; talks to BBDESIGN via the `{EC76D50B-BAD7-11CE-B21F-00AA004A33DB}` "Bbird_OB" MS-RPC interface.
- **`PUBLISH.DLL`** — loaded in-process into `BBDESIGN.EXE` via `CoCreateInstance`.
- **`BBVIEW.EXE`** — user-launched on `.TTL` files from disk.

Key registry roots consulted by BBDESIGN during release:

| Path | Values | Purpose |
|---|---|---|
| `HKLM\Software\Microsoft\BlackBird\ObjectBroker` | `SecurclLocation`, `TreeEditLocation` | Fully-qualified DLL paths; used to `LoadLibraryA` the MSN client libraries before CoCreateInstance. Defaults to `C:\program files\the microsoft network\{securcl,treeedcl}.dll` if absent. |
| `HKLM\Software\Microsoft\BlackBird\Obj` | `MakeDirSrvNodes` (REG_DWORD) | Gates whether the MSN publish path also pushes DirSrv metadata (the node registration). |

---

## 3. Authoring format

Blackbird uses OLE2 structured storage for on-disk and wire representations of the content graph. A title is a rooted tree of Blackbird objects (`CTitle`, `CBForm`, `CVForm`, `CStyleSheet`, `CResourceFolder`, typed media proxies such as `TextProxy`/`VideoProxy`/`AudioProxy`/`ImageProxy`). Media streams embedded in a title are tagged as one of `BitmapImage`, `WaveletImage`, `MetafileImage`, `WaveAudio`, `StreamingWaveAudio`, `MIDIAudio`, `StreamingMIDIAudio`, `AVIVideo`, `StreamingAVIVideo`, or `Generic`.

Persistence goes through **COSCL** rather than direct ole32 calls:

- `CObjectStoreFactory::Create(path, mode, flags)` builds a fresh compound file. Mode `0x12` (used by the MSN publisher) is create-for-write; Blackbird also uses `CObjectStoreFactory::Create` to open an existing docfile for read.
- Per-object serialization lives in the free function `extract_object(CObjectStore *src, moniker, CObjectStore *dst, 1, 1, NULL, ObjectArtifact)`. The `ObjectArtifact` enum (5th non-count argument) selects which portion of an object to extract:
  - `3` — object bytes only
  - `4` — tree bytes only
  - `8` — both
- References between objects are carried as `CDPORef` monikers in a `CDPORefMgr` iterator. External references are preserved without copying their bytes via `CObjectStore::AddFiatMoniker(dst, 2, typename, guid, flags=0x80000, kind=1, ...)`.
- Title-wide metadata lives in a separate property table accessed via `CObjectStore::AccessTitlePropertiesTable` and manipulated with `CPropertyTable::SetAt / Lookup / RemoveKey / Commit`.

`resources/titles/4.ttl` (8704 B) is a Local-target snapshot of this compound-file layout: a stripped-down CTitle graph written by the same `extract_object` path the MSN publisher uses.

### 3.1 Compound file layout

The root and per-storage streams produced by `extract_object` (as observed on `resources/titles/4.ttl`, confirmed against the COSCL import surface):

| Path | Size | Purpose |
|---|---:|---|
| `\x03type_names_map` | 87 B | Maps storage id → class name (see §3.1.1). |
| `\x03ref_1` … `\x03ref_N` | 81-89 B | `CDPORef*` / `CDPORefHc`/`CDPORefHC` records. Cross-object monikers with GUID + FILETIME. One entry per serialized object. |
| `<id>/0/\x03object` | var | Opaque class instance bytes (see §3.1.3). |
| `<id>/0/\x03properties` | var | Single-property `CPropertyTable` — every named class carries `name=<ASCIIZ>`. |
| `<id>/0/\x03handles` | 12 B | `[u32 count][GUID-handle][GUID-handle]…` of references this storage emits. Absent on leaf classes (e.g., CBFrame, CStyleSheet, CVForm on `4.ttl`). |

The storage id in `type_names_map` matches the decimal storage directory name — `<id>/0/…` reaches the instance.

#### 3.1.1 `\x03type_names_map`

```
u32 count                     // number of entries (6 on 4.ttl)
u16 opaque                    // mirrors `count` on 4.ttl; semantics not pinned
for `count` entries:
  u8  name_len
  char name[name_len]         // ASCII class name, no NUL
  u32 storage_id              // matches the `<id>/0/...` substorage
```

4.ttl's table (in file order):

| name | storage_id |
|---|---:|
| CTitle | 1 |
| CBForm | 5 |
| CBFrame | 3 |
| CVForm | 6 |
| CStyleSheet | 4 |
| CResourceFolder | 2 |

#### 3.1.2 `\x03properties` (per-storage)

COSCL's `CPropertyTable` persisted form. Every named class on 4.ttl carries a single `name` string; the format supports more but only string (type 0x08) has been observed:

```
u32 prop_count
for `prop_count` entries:
  u8  name_len
  char name[name_len]         // ASCII key
  u8  type_tag                // 0x08 = ASCIIZ string; others reserved
  u8  flags                   // observed 0x00; opaque
  u32 value_len               // includes trailing NUL when type_tag=0x08
  char value[value_len]
```

The CTitle `name` (`"MSN Today"` on 4.ttl) is the authored display name the MSN Today viewer surfaces as the window caption; see `docs/MEDVIEW.md` §4.4 for how the server relays it in the 9-section MedView body.

#### 3.1.3 `\x03object` (per-storage)

The opaque instance stream produced by `extract_object`. On 4.ttl:

- Small classes (CTitle 40 B, CBFrame 36 B, CBForm 45 B, CStyleSheet 46 B, CResourceFolder 25 B) store serialized C++ members directly.
- CVForm (534 B on 4.ttl) carries a 9-byte header (`01 [u32 uncompressed_size] [u32 compressed_size]`) followed by a compressed body. The algorithm is some MS-stock legacy variant (not zlib / deflate / gzip); decompression requires RE of `COSCL.DLL!extract_object` and the matching decoder.

The 9-section MedView body the viewer consumes (`docs/MEDVIEW.md` §4.4) does NOT need these bytes for the caption — only `CTitle.name` from §3.1.2 drives that — but populating the fixed-size record sections (1/2/3/7) of the MedView body from authored content would require decoding this layer.

---

## 4. Release targets

The wizard page `CReleasePageMSN` collects three independently-toggleable targets into a single `CReleaseData` struct persisted on the content object:

```c
struct CReleaseData {
    BOOL  msn;                  // +0x00   'Release to MSN' checkbox
    BYTE  pad[3];
    BYTE  siteNodeID[0x18];     // +0x08   24-byte DEID; zero if never published
    CString siteName;           // +0x20
    BYTE*   siteImage;          // +0x24   malloc'd banner bitmap
    ULONG   siteImageLength;    // +0x28
    BOOL  internet;             // +0x2c
    CString internetSiteURL;    // +0x30
    CString internetSiteID;     // +0x34
    CString internetSitePwd;    // +0x38
    BOOL  local;                // +0x3c
    CString localName;          // +0x40   filename (relative or absolute)
};
```

The struct is load/save-marshalled to the content's CPropertyTable by `BBDESIGN!CReleaseData_Serialize` at `0x0042d411` (same implementation copy-pasted into `PUBLISH!CReleaseData_Serialize` at `0x40f04ebe` — static linkage of the shared source). Keys on the property bag: `Version`, `MSNSiteNodeID`, `MSNSiteName`, `MSNSiteImage`, `MSNSiteImageLength`, `Internet`, `InternetSiteURL`, `InternetSiteID`, `InternetSitePwd`, `Local`, `LocalName`. The strings `EnableReleaseToMsn` / `EnableReleaseToLocal` / `ReleaseLocalFilename` appear in `.rdata` with zero cross-references — historical keys from an older serialization format, dead in 11.0.06.

### 4.1 Per-target release entry

`BBDESIGN!CReleaseWizard_Dispatch` at `0x004552d6` runs once per active target with two args:
- `param_1` — target (`0` = MSN, `1` = Local)
- `param_2` — secondary flag (for MSN, requests fresh site-metadata lookup)

It:
1. Gates via `CReleaseWizard_ShouldPublishMSN` (`0x0043e6d4`) which rejects if the target bit is clear, short-circuits to "no DirSrv nodes" when `HKLM\...\BlackBird\Obj\MakeDirSrvNodes == 0`, and checks whether the 24-byte `MSNSiteNodeID` is all-zero (first publish) or already populated.
2. Reads `HKLM\...\BlackBird\ObjectBroker\{SecurclLocation, TreeEditLocation}` and `LoadLibraryA`s `svcprop.dll`, `securcl.dll`, `treeedcl.dll`.
3. `CoCreateInstance(CLSID={F82DB6A1-192A-11CF-A2ED-00AA00B92A96}, IID={F82DB6A7-192A-11CF-A2ED-00AA00B92A96}, CLSCTX=7)` — the factory lives in `PUBLISH.DLL`.
4. Calls `CReleaseWizard_DoPublish(gProject, content, target, publisher, treeedcl_path, NULL)` at `0x0043e823`.

### 4.2 Local branch (`param_2 == 1`)

`CReleaseWizard_DoPublish` assembles a `.TTL` path from `CReleaseData.localName` (relative paths resolve against the treeedcl.dll directory) plus the `.ttl` extension, then calls the file-writer (`FUN_0043ef8a`) to drop the compound file to disk. This is the path that produced `resources/titles/4.ttl`.

### 4.3 MSN branch (`param_2 == 0`)

`CReleaseWizard_DoPublish` attaches the content to the publisher (`publisher->vtable[0x0C]`), probes (`publisher->vtable[0x10]`, expects `0`/`1`/`2`), optionally re-reads the `MakeDirSrvNodes` registry flag, then invokes `publisher->vtable[0x18]` with a hint path. The publisher is `PUBLISH.DLL`'s `CObjectStoreFactory`-backed COM class; slot `0x18` resolves to `CPublisher_PublishToMSN` (`0x40f01c7c`).

### 4.4 Wire contract — `PUBLISH.DLL!CPublisher_PublishToMSN`

The monster publish function at `0x40f01c7c` drives the full MSN release on a single worker thread (guarded by `DAT_40f09748` mutex). In order:

1. **Temp compound file** — `GetTempFileNameA` then `CObjectStoreFactory::Create(tempPath, 0x12, 0)` allocates a fresh COSCL compound file that will hold the delta to ship.
2. **DirSrv lookup** — `CTreeNavClient("DirSrv", 7, 0xffff, …).GetProperties / GetNextNode` resolves the site node this title publishes under.
3. **Incremental query** — `CMPCMethod(&gBbirdConnection, method=4)` executes against the Object Broker, returning three arrays of `{GUID, FILETIME}` pairs (what the server already has, what the client thinks it has, what has changed) and a `BYTE` mode flag (`0` = no-op, `1` = incremental).
4. **Per-object decision** — walks the client `CDPORefMgr` iterator; for each moniker consults flags `0x0B` / `0x0C` / `0x0E` / `0x13` and the corresponding GUID→FILETIME hashtable built from step 3's output:
   - flag `0x13` set → `CObjectStore::AddFiatMoniker(dst, 2, typename, guid, 0x80000, 1, ...)` (external reference, bytes not shipped)
   - flags `0x0B`+`0x0E` both newer than server → `extract_object(..., kind=8)` (object + tree)
   - flag `0x0B` only → `extract_object(..., kind=3)` (object bytes)
   - flag `0x0E` only → `extract_object(..., kind=4)` (tree bytes)
5. **Title-level stamping** — `CObjectStore::AccessTitlePropertiesTable` followed by `CPropertyTable::SetAt("\x03Publish Version", titleGuid, 0x14)` writes a 20-byte stamp into the title properties table.
6. **Commit** — `CObjectStore::Commit(0)` finalises the temp compound file.
7. **Ship the blob** — `CMPCFileWrite(&gBbirdConnection, method=5, 0)` opens an MPC file-write stream on the Object-Broker service, then `stream_copy_to_mpc_filewrite(writer, paramAdder, -1, 0x2000)` at `0x40f051a5` copies the compound file out in **8 KB chunks**. Close.
8. **Site-metadata push** — `CTreeEditClient("DirSrv", 7, 0xffff, …).SetProperties(locid_lo, locid_hi, props)` on service 7, where `props` contains a single `FSet` entry of type `0x0E` and length `0x54` carrying the `CReleaseData.siteNodeID` (24 bytes) plus the companion registration fields from the struct.

So the publish splits cleanly into two wire legs:
- **Content blob** → `CMPCFileWrite` on service "Bbird_OB" method 5 (the COSCL compound file the server receives and absorbs).
- **Site registration** → `CTreeEditClient::SetProperties` on DirSrv (service 7) with a 0x54-byte property record.

PUBLISH.DLL imports **no** IStorage-family ole32 APIs directly; the only `ole32` entry point it links is `CoCreateGuid`. Compound-file byte-layout responsibility lives entirely inside COSCL.

### 4.5 Delete

`PUBLISH.DLL!DELETENODE` at `0x40f01210` runs the symmetric teardown: open a `CMPCConnection("Bbird_OB", guid={EC76D50B-BAD7-11CE-B21F-00AA004A33DB})`, navigate DirSrv to locate the node, confirm the property at offset `0x31` of the 0x54-byte site record, and invoke `CMPCMethod(&conn, method=1)` with the node ID. Returns `0x8b0b001b` on cancellation and `0` on success.

### 4.6 SETPROP stub

`PUBLISH.DLL!SETPROP` at `0x40f0154a` is an unconditional `return 0x8b0b001b;` stub — the legacy one-shot property writer is unimplemented in 11.0.06 and superseded by the IPublisher path.

---

## 5. Key classes

| Class | Home | Role |
|---|---|---|
| `CObjectBroker` | `OBCL.EXE` | Local cache/broker in front of the server's compound store (`SuperCOS`/`SubCOS`). |
| `CObjectStore` / `CObjectStoreFactory` | `COSCL.DLL` | OLE2-compound-file abstraction; wraps `IStorage` over `ILockBytes`. |
| `CDPORef` / `CDPORefMgr` / `CDPORefTable` | `COSCL.DLL` | The "Deep-Persistent-Object reference" machinery — monikers into the object store plus the iterator/dereference APIs. |
| `CMPCConnection` / `CMPCMethod` / `CMPCMethodExecution` / `CMPCFileWrite` / `CMPCFileWriteParamAdder` | `COSCL.DLL` | Client side of the MSN RPC ("Marvel Protocol Client") — both method-call and file-write flavours. |
| `CPropertyTable` | `COSCL.DLL` | Property-bag abstraction over a storage stream; the title's title-level properties and the per-object property bags both use this. |
| `CServiceProperties` | `SVCPROP.DLL` | Service-protocol property record (the `FSet` / `FGet` typed wire marshaller). |
| `CTreeNavClient` / `CTreeEditClient` | `TREENVCL.DLL` / `TREEEDCL.DLL` | DirSrv-facing tree navigation + edit (same classes the stock MSN 1.0 client ships). |
| `CReleaseData` | `BBDESIGN.EXE` (+ inline copy in `PUBLISH.DLL`) | Wizard state struct; see §4. |
| `CObjectStoreFactory` (publisher flavour) | `PUBLISH.DLL` | COM class exported via `DllGetClassObject`; vtable slot `0x18` is the "publish to MSN" entry. |

---

## 6. MSN site-registration record

The four `MSNSite*` properties are what a published title advertises on MSN's DirSrv tree. From `CReleaseData`:

| Property | Type | Offset | Notes |
|---|---|---:|---|
| `MSNSiteNodeID` | 24-byte binary | `+0x08` | DEID-style node identifier assigned by the server on first publish. All-zero = never published. |
| `MSNSiteName` | `CString` | `+0x20` | Human-readable directory-node name. |
| `MSNSiteImage` | blob of `MSNSiteImageLength` bytes | `+0x24` | Directory-node banner DIB. Painted by MOSSHELL's `CDIBWindow` strip above the listview when the node is opened in the shell — same surface DSNAV's `'mf'` shabby feeds (`docs/MOSSHELL.md` §6.3, `docs/DSNAV.md` §11.1). NOT consumed by the MedView viewer. |
| `MSNSiteImageLength` | `ULONG` | `+0x28` | Size in bytes of the `MSNSiteImage` blob. |

All four values are written to the `CReleaseData`-local `CPropertyTable` during wizard edit (round-tripped by `CReleaseData_Serialize`) and consumed together by `CPublisher_PublishToMSN` — either as the `0x54`-byte `CTreeEditClient::SetProperties` record (site metadata) or as properties inside the published compound file (content side).

---

## 7. Authored fixture inventory — `resources/titles/4.ttl` (MSN Today)

Decoded by `server.services.ttl.Title.from_path` via `_extract_object_stream`:

| Storage | Class | Body | Notes |
|---|---|---|---|
| 1/0 | `CTitle` | 37 B | Title metadata; CTitle's serialized state. |
| 2/0 | `CResourceFolder` | 24 B | Resource container; aggregates the project's resources. |
| 3/0 | `CBFrame` | 44 B | "MSN Today\\0" caption + `0x0280 × 0x01E0` (640×480). The frame the engine renders. |
| 4/0 | `CStyleSheet` | 880 B | Font table — multiple "Courier New" entries indexed by style id `0x03..0x06`. |
| 5/0 | `CBForm` | 44 B | Form-level page bounds: 640×480 at 96 DPI (`0x60`). |
| 6/0 | `CVForm` | 816 B | **MS Word 95 OLE-embedded document** — UTF-16 `"CompObj"` trailer is the OLE compound-doc marker. The actual page content (formatted runs + embedded refs) lives in this Word DOC. |
| 7/0 | `CProxyTable` | 17 B | Cross-reference table 0. |
| 7/1 | `CProxyTable` | 17 B | Cross-reference table 1. |
| 8/0 | `CContent` | 319 B | Structured records embedding "MSN Today" + "Hello, all folks." text. |
| 8/1 | `CContent` | 119 B | Body text: "RThis is an example of content authored using MS Word 95 with Blackbird Extensions! ... supported as well:" |
| 8/2 | `CContent` | 84 B | Structured records embedding "Calendar of Events" + "what's been happenin'". |
| 8/3 | `CContent` | 0 B | Empty placeholder. |
| 8/5 | `CContent` | 3446 B | **Raw `BM`-prefixed bitmap** (`bitmap.bmp`); custom 310-B DIB header + `TLWC`-compressed pixel data. The `bitmap.bmp` resource. |
| 8/6 | `CContent` | 544 B | MSZIP-compressed `ver=0x01` body — second page content. |
| 8/7 | `CContent` | 122 B | Raw `ver=0x02` body, "SThis is an exa..." — additional text fragment. |
| 9/1 | `CSection` | 43 B | Section-record matching MEDVIEW wire-section-1 stride exactly. The "Section 1" container. |

The `CVForm` (6/0) is decisive — it carries an entire Word 95 binary
document with the rendered page. The original 1996 MSN MedView
*server* converted this published-blob into wire-ready chunks
(9-section title body + 0xBF cache pushes + baggage payloads) before
shipping to the MOSVIEW client. We don't have that server binary, so
faithful conversion has to be re-implemented server-side here.

The conversion logic, however, is fully recoverable from the
binaries we DO have:

- **`extract_object` @ COSCL.DLL `0x40216AB4`** writes the
  PUBLISH.DLL output blob: `[u32 kind][u32 status_flags]
  [optional u128 GUID][u32 typename_len + name][u32 obj_len + obj
  bytes][optional prop stream][optional swizzle table + recursive
  embedded objects]`. This is what the server receives via
  `Bbird_OB` method 5.
- **Per-class `Serialize` in VIEWDLL.DLL** defines the on-disk byte
  layout for every authored class. Sample (CSection, ~50 lines):
  writes byte `3`, then calls the typed-pointer-list `Serialize` at
  this+8/+2c/+50/+74/+bc/+98 (six member lists), then
  `CSectionProp::Serialize` on this+0xe0. CTitle, CBFrame, CBForm,
  CContent, CElementData, CStyleSheet, CResourceFolder, CProxyTable,
  CVForm all follow the same pattern at corresponding offsets in
  VIEWDLL.
- **MEDVIEW wire format** (the destination) is documented in
  `docs/MEDVIEW.md` and continuously refined by RE of MVCL14N and
  MOSVIEW.

So the path from `.ttl` → on-screen pixels is:

```
.ttl (compound file)
  → server reads each \x03object stream
  → server applies each class's Serialize-deserialize logic to
    recover the in-memory object tree (CTitle → CBFrame → CSection →
    children)
  → server walks the tree and emits the MEDVIEW wire chunks the
    engine expects (TitleOpen body sections 1/2/3, 0xBF cache pushes
    with case-3 dispatch + populated trailers, baggage HFS
    responses)
  → MOSVIEW + MVCL14N consume the wire chunks and BitBlt the
    result
```

The first two arrows are bounded RE work — every byte is in
VIEWDLL's Serialize methods. The third arrow is what we've been
incrementally building in `src/server/services/medview.py`. The
gap is the middle layer (object-tree-aware emitter), not a
mysterious unknown converter.

The smaller proof-of-concept path skips the .ttl entirely:
hand-build a CSection cache push with a non-empty trailer carrying
one text child (tag 0x8A) pointing at a synthetic va that resolves
to a buffer of glyph data. This validates the
case-3 → trailer → CElementData chain documented in
`docs/MEDVIEW.md §7.2` without needing the full deserializer.

`_parse_property_stream` currently fails on `CProxyTable` and
`CContent` `\x03properties` streams (their property layouts differ
from `CTitle/CSection/CBForm`-shaped streams the parser handles).
This is logged-and-skipped; resolving it requires extending the
parser to the additional class-specific property formats.

---

## 8. VIEWDLL Serialize methods — on-disk schemas

Each authored class in `4.ttl` ships through `extract_object` driven by
its `Serialize(CArchive&)` virtual. RE'd from VIEWDLL.DLL @ `0x40700000`
(read-mode dispatch under `param_1[0x14]&1 != 0` branch; write-mode
under `==0`). The `CArchive` write cursor is `param_1+0x24`, buffer end
at `param_1+0x28`.

### 8.1 CSection (`?Serialize@CSection@@UAEXAAVCArchive@@@Z` @ 0x4070E6AF)

```
write byte 0x03                       # version tag
this+0x08 → list.Serialize             # children list 1
this+0x2c → list.Serialize             # children list 2
this+0x50 → list.Serialize             # children list 3
this+0x74 → list.Serialize             # children list 4
this+0xbc → list.Serialize             # children list 5
this+0x98 → list.Serialize             # children list 6
this+0xe0 → CSectionProp::Serialize
```

Read mode: byte at cursor is the version byte `bVar3`; six lists
deserialised in same order; `if (bVar3 < 3) Ordinal_781(this+4)` reads
an additional pre-v3 field. CSectionProp::Serialize is invoked with the
version byte as third arg.

The 43-byte `9/1` body in `4.ttl` is exactly this serialised form with
six empty lists + a small CSectionProp tail. Wire body section 1 ships
the raw 43 bytes through unchanged (`_section1_records_from_csections`
in `medview.py`).

### 8.2 CElementData (`?Serialize@CElementData@@UAEXAAVCArchive@@@Z` @ 0x40702E4C)

```
let n = this+0x04   # data length
if n < 0xFF        : write u8 n
elif n < 0xFFFE    : write u8 0xFF + u16 n
else               : write u8 0xFF + u16 0xFFFF + u32 n
write n bytes from this+0x08            # raw data buffer
```

Read mode is symmetric: `ReadDataLength` recovers `n` then `Ordinal_4817`
mempys `n` bytes into a freshly allocated buffer (sentinel-NUL-terminated).

This is the simplest format — used for variable-length glyph runs and
text strings inside CSection's children lists.

### 8.3 CContent (`?Serialize@CContent@@UAEXAAVCArchive@@@Z` @ 0x4073A185)

```
if read mode            : (read path; not analysed here — uses IStream
                          chunked transfer through this+0x14's IStream
                          vtable at +0x28/+0x3c/+0x54)
else (write mode):
    if this+0x14 != NULL:                 # has source IStream
        if  *(this+8)-8  != 0:             # has target storage
            CreateStream(...)
        loop:
            buf = malloc(0x1000)
            n = this->vtable[0x14]->Read(buf, 0x1000)
            if n == 0: break
            archive->vtable[0x40]->Write(buf, n)
            if n < 0x1000: break
        free(buf)
        commit_stream()
```

CContent is **opaque IStream chunks** — there is no class-version prefix
or header. The body bytes are whatever the source stream provides
(text, structured records, BM-prefixed bitmap, MSZIP-compressed page
content, etc.). This matches `project_medview_ccontent_not_via_bf.md`:
CContent ships through baggage selectors `0x1A`/`0x1B`/`0x1C` verbatim,
NOT through type-0 BF cache pushes.

### 8.4 Other classes (CTitle, CBFrame, CBForm, CVForm, CStyleSheet,
CResourceFolder, CProxyTable)

Same pattern as CSection: write a version byte (0x00..0x09 depending on
class), then `this+offset → ChildClass::Serialize` calls in fixed order,
optionally followed by inline fields. The `4.ttl` body bytes for each
storage are byte-exact what `Serialize` emitted in write mode against
the wizard-edited in-memory tree.

For the MEDVIEW wire path we don't need to re-parse most class bodies —
the 1996 server consumed these via virtual `Serialize(read)` calls,
walked the recovered C++ tree, and emitted MEDVIEW chunks. Today's
shortcut: ship CContent bytes verbatim (they're the actual content
bytes), CSection's 43-byte wire-ready body verbatim into wire section 1,
and synthesise BF chunks + bm0 baggage from a small subset of the
authored data needed by the MVCL14N layout walker (Phase 1/2 RE).

---

## 9. Constraints and unknowns

- The COSCL compound-file object layout (the per-stream format produced by `extract_object`) is documented only through its PE implementation. Full structural reversing is scoped out here; `extract_object` at `COSCL.DLL` ordinal ≈ `0x236` is the authoritative reference.
- The `CMPCFileWriteParamAdder` frame — the wrapper `PUBLISH.DLL` prepends to the compound-file byte stream when shipping through `CMPCFileWrite` (service "Bbird_OB" method 5) — is not documented here. `stream_copy_to_mpc_filewrite` at `0x40f051a5` is the entry point; the param block at `local_278` carries the title name, length, publish GUID, and a vtable pointer that provides the chunk reader.
- `MakeDirSrvNodes == 0` (the registry flag) is honoured both by `CReleaseWizard_ShouldPublishMSN` (fast-path exit) and inside `CReleaseWizard_DoPublish` (skips the TreeEdit push). This lets a deployed Blackbird author bypass the DirSrv leg while still shipping the content blob.
- `OBCL.EXE`'s cache semantics (`AddSubCOSToSuperCOS`, `LoadSuperCOS`, `PrefetchObject`, `ReprioritizeObject`) are a separate subsystem; they do not participate in `CPublisher_PublishToMSN`'s critical path but do mediate ordinary object retrieval during authoring.

---

## See also

- `docs/TREENVCL.md` — the DirSrv navigation client shared with the MSN 1.0 MOSSHELL path.
- `docs/DIRSRV_GETCHILDREN_CLIENT_PATH.md` — per-record `[u32 size][u16 prop_count]{[u8 type][asciiz][value]}*` wire format used by `CServiceProperties::FSet`/`FGet` in step 8 above.
- `docs/MEDVIEW.md` — the MedView service the MSN Today viewer reads from.

[//]: # (Section 8 was renumbered; "Constraints and unknowns" is now §9.)
- `resources/titles/4.ttl` — reference Local-target compound file (same `extract_object` output format the MSN branch ships, minus the MPC framing).
