# BBSNAV.NAV — RE pass coverage

Focused reverse-engineering pass producing the BBS service wire contract.
Driven by the plan `.claude/plans/sparkling-sauteeing-thimble.md`. Distinct from
the MOSVIEW total-decomp pass tracked in `INDEX.md` — this pass is **wire-path
deep, rest light** (per the plan), not a full every-function ledger.

## Scope & outputs

- **Imported** `binaries/BBSNAV.NAV` (base `0x7F5F0000`, 598 fns) and
  `binaries/TREEEDCL.DLL` (base `0x7F2C0000`) into `MSN95.gpr`; auto-analyzed,
  saved.
- **Deliverables**: `docs/bbs-service-contract.md` (the spec) +
  `docs/BBSNAV.md` (binary shape). This file is the coverage record.
- Progress JSON: `scratch/annotate-progress/BBSNAV.NAV.json` (worklist + findings).

## Verdict (the spine)

BBS rides the generic MOS **tree** infra via MOSSHELL — **no dedicated message
service / IID table** (not MEDVIEW-shaped). `BBSNAV_DllMainLogic` opens two
channels against service name `"BBS"`: `InitializeNtnigr` (read → TREENVCL
`CTreeNavClient`, sel 0–6) and `InitializeEcig` (write → TREEEDCL
`CTreeEditClient`, sel 0–12). Boards/threads/messages are tree nodes with SVCPROP
records; posting is `AddNode`/`SetProperties`/`LinkNode` under a `GetTicket`
capability ticket. Static imports are MOSSHELL + Win32 only; MAPI32 + riched32
are dynamic loads.

## Coverage by area

| Area | Status | Key functions / evidence |
|---|---|---|
| Plug-in entry + init | deep | `GETPMTN` `0x7F5F4BD0`, `DISCONNECT` `0x7F5F4C0C`, `BBSNAV_DllMainLogic` `0x7F5F4C29`, ctor `0x7F5F1051` |
| `CBbsNavTreeNode` vtable | deep | `vtbl_CBbsNavTreeNode` `0x7F60E880`, 25 overrides mapped & named (BBSNAV.md §4) |
| Read path / columns | deep | `OkToGetChildren` `0x7F5F1427`, `GetDetailsStruct` `0x7F5F14A3` → RCDATA 6011 (`e/_a/p/_D`) |
| Property tags | deep | 8 extras `{_a,_D,_P,_f,_t,p,_F,_I}` @ `g_BbsExtraPropTags` `0x7F6101A8`; roles in contract |
| Threading | deep | `CBbsNavTreeNode_GetThreadParent` `0x7F5F1C3E` (`_P` → `HrGetPMtn`) + tree nesting |
| View / body | medium | `CBbsViewWnd_Construct` `0x7F5F1F8B`, `BBSMsgWndClass`, RichEdit body (`riched32` @ `0x7F5F9444`); body wire tag = bounded gap |
| Write path | deep | `HrGetPMte` `0x7F5F1593`, `CBbsTreeEdit` vtbl `0x7F60E9E8`, `NewObject` `0x7F5F1D17`, `FillSPForNewNode` `0x7F5F1DCF` |
| TREEEDCL selectors | deep | `CTreeEditClient` Private* sel 0–12 (Lock/Unlock/AddNode/DeleteNode/SetProperties/LinkNode/UnlinkNode/AddShabby/DeleteShabby/OrderChildren/GetDataSets/GetTicket) |
| Read-state / prefs | deep | `HKCU\…\BBS Viewer` window-placement only; `CBbs_Load/SaveWindowPlacement` `0x7F600DB2`/`0x7F600EC5`; read-state server-side |
| MSN vs Net + MAPI gw | deep (call-sites) | `CBbs_FIsMsnBbs` `0x7F600D21`; `CBbs_MapiForwardOrReply` `0x7F6044CB` (dynamic MAPI32); MOSABP32 deferred |
| Properties dialog | medium | `CBbs_FillPropertiesDialogPage` `0x7F5F385E` |

## Annotations shipped

~36 functions renamed (entry points, 25 node overrides, 2 edit overrides, view
ctor, thread-parent, properties dialog, window-placement load/save, MSN/Net
discriminator, MAPI gateway), 10 globals + 2 vtable labels named, 6 plate
comments. TREEEDCL `Private*` selectors decoded. Light/bulk-plate of the
remaining ~560 functions not performed (out of plan scope — wire paths only).

## Gaps

- Message-body wire property/blob tag (RichEdit-hosted; recommend SoftICE trace).
- `_f` tag has no read site; `_t` is a topic text field, not the body.
- Secondary `CBbsTreeEdit` interface vtables (post the 29-slot base) not
  individually annotated.
- BBS mnid sub-field layout carrying `_P` not byte-mapped.
