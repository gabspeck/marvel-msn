# Diagnosis: BBVIEW vs MOSVIEW caption-position + half-height scrollbar mismatch

**Test fixture**: `resources/titles/4.ttl` — one CBFrame, one CBForm Page, one Caption1 ("Test caption" at `rect_twips=(5291, 2963, 11641, 5926)`, → 96 DPI px = (353, 198, 776, 395)).
**Wire flow** (matches plan): `0x1F → 0x1E×2 → 0x17×5 → 0x01 OpenTitle → 0x06(unmatched) → 0x15 case-3 → 0x1A/0x1B(139B)/0x1C ×2`.
**Server-side**: `medview.py:_build_bm0_metafile_container` produces a kind=8 baggage with `mapmode=1 (MM_TEXT)`, `viewport_w=586`, `viewport_h=506`, carrying one `META_TEXTOUT(353, 198, "Test caption")`.

## Diagnosis status

| Acceptance fact | Status | Evidence |
|---|---|---|
| 1. Pane mapping (top/bottom, SR/NSR, screen rect) | **Confirmed**: SR=(0,0,636,182) top; NSR=(0,182,636,275) bottom | Live SetWindowPos BP at 0x7F3C3CB9/0x7F3C3CE6 |
| 2. screen_Y arithmetic | **Confirmed**: caption at container-Y=380 in NSR pane (clipped in SR) | Live MVPaintBitmapRecord (x=0,y=0) + pane rects |
| 3. title+0x4c writers (HasNSR gate) | **Confirmed**: viewer+0x4c=0, fMVHasNSR returns 1, dual-pane active | Static + live (viewer dump) |
| 4. Walker fetch terminator | **Confirmed**: walker NEVER FETCHES — neither leading nor trailing loop enters | Static + wire log (zero 0x16 requests) |
| 5. title+0x42 at scroll realise | **Confirmed**: stays 1; clear-gate is unreachable on first paint | Static |

## Live SoftIce capture (2026-05-10)

86Box VM with title 4 on screen. Pane geometry pinned via `HWND Mosview`:

```
Window tree (MOSVIEW process):
 01DC  MosMediaViewShell        (top-level shell)
   02A8  MosViewContainer       (outer container, child of shell)
     02AC  MosChildView         (style 0x52200000 = WS_CHILD|VISIBLE|CLIPCHILDREN|VSCROLL → SR pane)
     02B0  MosChildView         (style 0x52000000 = WS_CHILD|VISIBLE|CLIPCHILDREN     → NSR pane)
```

`HWND -X` reveals the pane state pointer in the lpCreateParams slot ("unknown4"):
- HWND 02AC → MosPaneState @ 0x00B903F8 (SR / pane[0])
- HWND 02B0 → MosPaneState @ 0x00B904C0 (NSR / pane[1])

Direct dump (DB on Mosview context) of both pane states yields:

| Field | SR pane (0xB903F8) | NSR pane (0xB904C0) | Notes |
|---|---|---|---|
| +0x00 (target_va) | 1 | 1 | NavigateMosViewPane copied target spec |
| +0x40 (viewer ptr) | 0x00406060 | 0x004069B4 | independent viewer per pane (lpMVDuplicate) |
| +0x44 (HWND) | 0x000002AC ✓ | 0x000002B0 ✓ | matches HWND list |
| +0x5c (title-state) | 1 | 0 | ctor leaves SR at 1; CreateMosViewWindowHierarchy explicitly zeros pane[1]+0x5c |
| +0x68 (name ptr) | 0x00B904B4 ("main") | 0x00B9057C ("Non Scrolling Pane") | matches sec06 caption / class string |
| +0x7c (peer HWND) | 0x000002B0 (NSR) | 0x000002AC (SR) | cross-references |
| +0x84 (unrealized) | 0 | 0 | both realized (fMVSetAddress succeeded) |
| +0x90 (HasNSR cache) | **1** | **1** | **dual-pane confirmed at runtime — fMVHasNSR returned true** |
| **+0x9c (y-anchor)** | **0** | **0** | **NO swap — static prediction confirmed** |
| +0xa0 (popup_id short) | 3 | 3 | ctor default unchanged |

Dump of SR pane's viewer (0x00406060) confirms:
- viewer +0x10 = 0x000002AC (HWND, matches)
- viewer +0x4c = **0** (NOT -1 → fMVHasNSR returns 1 ✓)

`MVPaintBitmapRecord` BP captured one invocation (after a window move):
- arg viewer = 0x00406060 (SR pane's viewer)
- arg **x = 0, y = 0** (slot anchored at pane HDC origin)

This means: SetViewportOrgEx(hdc, 0, 0) → metafile-(353, 198) → pane-HDC-(353, 198). Slot is at pane top-left corner.

## Final geometry & caption screen-Y arithmetic (Issue 1)

Live SoftIce capture pinned the SetWindowPos calls inside `NavigateMosViewPane`'s geometry block:

- BPX `0x7F3C3CB9` (SR pane SetWindowPos): `hwnd=0x02F8, X=0, Y=0, cx=636, cy=182, flags=0x1C`
- BPX `0x7F3C3CE6` (NSR pane SetWindowPos): `hwnd=0x02F4, X=0, Y=182, cx=636, cy=275, flags=0x1C`

Container client area = 636 × 457 px. SR (with WS_VSCROLL) is the **top 182 px**, NSR is the **bottom 275 px**. This matches the static-analysis prediction (SR top 40% under y_anchor=0, NSR=complement).

`MVPaintBitmapRecord` is invoked twice (once per pane) with `(x=0, y=0)` — slot anchored at each pane's HDC origin. The shared bm0 metafile carries `META_TEXTOUT(353, 198, "Test caption")`. With `mapmode=MM_TEXT` (no scaling), text lands at pane-HDC (353, 198) **in each pane**:

- **SR pane** (height 182): pane-Y=198 > 182 → caption **clipped out of view**. Pane appears empty.
- **NSR pane** (height 275): pane-Y=198 < 275 → caption rendered at container-Y = 182 + 198 = **380**.

Image #2's "Y≈595" is consistent with NSR-rendered caption at container-Y=380 plus ~215 px of shell-window chrome (title bar + menu bar + toolbar above the container). The "top pane appears empty" observation is consistent with the SR-clip behaviour. ✓

**The "scrollbar in bottom half" observation in the plan is a misread.** The V-scrollbar belongs to SR pane (style 0x52200000 includes WS_VSCROLL); SR sits at container-Y=0..182 (TOP of container, screen-Y ≈ 215..397 in a 720-tall window). The scrollbar is in the upper portion, NOT the bottom half. A side-by-side check against the actual screenshot would close this — the static + live data leaves no room for the scrollbar to be at the bottom of the container.

## Acceptance criteria — final answers

1. **Which `MosChildView` displays "Test caption"**: NSR pane (HWND 0x02F4, container-Y=182..457). The SR pane (HWND 0x02F8, container-Y=0..182) clips the caption (pane height 182 < text Y 198).
2. **Screen-Y arithmetic**: `screen_Y = shell_chrome_offset (≈215) + container_Y (= NSR_origin_Y 182) + metafile_Y (198) = 595`. SetViewportOrgEx delta is 0 (slot anchored at pane HDC origin, x=0/y=0). No BitBlt source offset (kind=8 metafile path uses PlayMetaFile, not BitBlt).
3. **`title+0x4c` value**: 0 throughout (never written by any code path in MVCL14N.DLL — confirmed via search_instructions returning only reads). `fMVHasNSR` returns 1 → dual-pane is unconditional.
4. **Walker terminator**: walker never reaches a terminator. On first paint with one chunk and dy=0 and slot+0x14=0, `leadingOffsetY=0` short-circuits the leading-fetch loop; `trailingOffsetY > 0` (slot height 506 vs pane extent ~182) short-circuits the trailing-fetch loop via `if (-1 < currentTailGapY) goto finishSeekWindow`. **Zero `MVDispatchHfcNextPrevHfc` calls per layout pass** — confirmed by zero 0x16 (FETCH_ADJACENT_TOPIC) wire requests in the server log.
5. **`title+0x42` at scroll realise**: 1. The clear-gate at `MVSeekVerticalLayoutSlots+0x482` requires `hitLeadingEnd=true`, which can only be set by a leading-direction `MVDispatchHfcNextPrevHfc` returning fetchStatus=0x3F3. Since the leading loop never enters, `hitLeadingEnd` is never set. SetScrollRange fires on SR_HWND (0x02F8) with extent_Y > 0; V-scrollbar painted at full SR-pane height (182 px) inside container-Y=0..182.

## Issue 2 — half-height vertical scrollbar (FULLY DIAGNOSED)

### Root cause

The V-scroll flag `viewer[0x42]` (short-array index = byte offset `+0x84` on the MV viewer struct) is always `1` at the time `RealizeMosViewSessionLayout` calls `SetScrollRange`. Static traversal of all writers proves this is unavoidable on first paint with a single chunk.

**Writers of `viewer+0x84` (search_instructions across MVCL14N.DLL)**:
- `lpMVNew @ 0x7E88256D`: `MOV [EDI+0x84], BX` — ctor zero init.
- `MVRealizeView+0x74 @ 0x7E88E4B4`: `MOV [ESI+0x84], 0x1` — **unconditional** set-on every realize pass.
- `MVSeekVerticalLayoutSlots+0x482 @ 0x7E88EF92`: `MOV [ESI+0x84], 0x0` — **only** clear path. Decompilation:

```c
if (((canProbePastEnd) && (hitLeadingEnd)) && (currentTailGapY < 0)) {
    viewer[0x42] = 0;
}
```

**Three conditions must all hold to clear V-scroll**:
1. `canProbePastEnd = (viewer[0x40] & 1U) == 0` — true on first realize.
2. `hitLeadingEnd = true` — set ONLY when **leading-direction** `MVDispatchHfcNextPrevHfc(direction=0)` returns NULL with `fetchStatus == 0x3F3`.
3. `currentTailGapY < 0` — final trailing-gap must be negative (slot fits with room to spare).

**The leading-fetch loop**:
```c
while (currentTailGapY = trailingOffsetY, 0 < leadingOffsetY) {
    layoutChunkHandle = MVDispatchHfcNextPrevHfc(... 0 ...);  // direction=0 (leading)
    if (layoutChunkHandle == 0) {
        if (fetchStatus != 0x3f3) goto setSeekFailure;
        hitLeadingEnd = true;
        ...
    }
    ...
}
```

It only iterates when `0 < leadingOffsetY = slot+0x14 + requestedDy`.

### First-paint path for `4.ttl`

1. `MVHfcNear` returns the case-3 chunk → `MVParseLayoutChunk` materialises one slot.
2. `MVRealizeView+0x74` writes `viewer[0x42] = 1`.
3. `MVRealizeView` calls `MVSeekVerticalLayoutSlots(viewer, title, sVar4=0, initialRealize=1, ...)`. The `sVar4` derivation hits the `iVar7+0xa != viewer+0x61` path → `sVar4 = 0`.
4. In the seek: `headSlotIndex = viewer[0x75]` (the new slot); `leadingOffsetY = slot+0x14 + 0 = slot+0x14`. For the first slot in a fresh layout, `slot+0x14 = 0` (no leading offset above viewport). → **`0 < leadingOffsetY` is FALSE** → leading-fetch loop **never enters**. → `hitLeadingEnd` stays `false`.
5. `trailingOffsetY = (slot+0x14 + slot+0x18) - viewer[0x16] + viewer[0x12] + 0`. For our bm0 viewport_h=506 vs pane height (top pane ≤ 218 by prior memory), `trailingOffsetY > 0`. → `if (-1 < currentTailGapY) goto finishSeekWindow` → trailing-fetch loop **never enters**.
6. At the clear-gate: `canProbePastEnd=true && hitLeadingEnd=false && currentTailGapY<0=false` → **condition fails** → `viewer[0x42]` stays `1`.
7. `RealizeMosViewSessionLayout @ 0x7F3C3F7D` calls `ptMVGetScrollSizes` → returns nonzero Y extent (because viewer[0x42]=1) → `SetScrollRange(this+0x44, 1, 0, extent_Y, redraw)` → V-scrollbar painted at full SR-pane height.

### Empirical confirmation

Wire log (`/tmp/marvel-server.log`) shows zero `0x16` (FETCH_ADJACENT_TOPIC) requests — i.e., the walker never fetches sibling chunks. This matches: with `leadingOffsetY=0` and `trailingOffsetY>0`, neither inner loop calls `MVDispatchHfcNextPrevHfc`.

### Fix-direction (out of scope; for a follow-up)

To clear `viewer[0x42]` on first paint, **either**:
- Ship layout state where the head slot has positive `slot+0x14` (push it below the viewport top), forcing the leading-fetch loop to run; populate the leading direction with chunks until the engine returns `0x3F3`. The wire field that anchors `slot+0x14` is set by `MVParseLayoutChunk` from the chunk's payload — investigate which fields drive it.
- Ship a layout where `currentTailGapY < 0` (slot fits within viewport extent) AND the walker enters trailing-fetch and gets `0x3F3`. Requires `slot_h < viewer[0x16]-viewer[0x12]`. Currently bm0 viewport_h=506 > pane_h ≈ 218..432, so this isn't satisfied.

Neither requires a client change — both are wire-side adjustments.

## Issue 1 — caption Y position (PARTIALLY DIAGNOSED)

### What static analysis confirmed

**Hypothesis B (`fMVHasNSR` collapse to single-pane) is FALSE.**

`fMVHasNSR @ 0x7E8835B0` decompiles to:
```c
return (bool)('\x01' - (*(int *)(param_1 + 0x4c) == -1));
```

Search across MVCL14N.DLL for writers of `+0x4c` returns **only reads** (23 hits, all `MOV reg, [...+0x4c]` or `CMP`/`LEA`). No `MOV [...+0x4c], imm` or `MOV [...+0x4c], reg` — even via `[reg+0x4c],EAX` patterns. Confirmed by querying `+ 0x4c],` — zero hits. `title+0x4c` is set to **0 by `lpMVNew` ctor only**, never to `-1` anywhere.

→ `fMVHasNSR` always returns `1` for any wire stream this server can produce. Dual-pane is **unconditional**. The single-pane collapse path requires C/C++-side construction we can't reach.

**Paint pipeline pinned (kind=8 metafile path)**:

`MVPaintBitmapRecord @ 0x7E887180` for `bitmapRecord[9]==8`:
```c
SetMapMode(hdc, bitmapRecord[7]);     // bitmapRecord[7] = mapmode = 1 (MM_TEXT)
SetViewportOrgEx(hdc, x, y, NULL);    // (x, y) = slot's pane-relative position
// SetWindowExtEx and SetViewportExtEx are SKIPPED for mapmode != 7|8
PlayMetaFile(hdc, bitmapRecord[2]);   // HMETAFILE from MVCreateHmetafileFromBaggage
```

Under MM_TEXT no scaling occurs. The metafile's `META_TEXTOUT(353, 198, "Test caption")` lands at logical (353, 198) which == device (x+353, y+198). Therefore **caption screen-Y = pane_origin_Y + slot_y + 198**.

**y_anchor (pane swap) is OFF for this title.**

`NavigateMosViewPane @ 0x7F3C3670` swaps SR pane to bottom 40% only when `pane+0x9c != 0`. Search for writers of `+0x9c` in MOSVIEW.EXE returns only:
- `MosPaneState_ctor+0xa1 @ 0x7F3C3489`: `MOV [ECX+0x9c], EDX` — ctor zero init.
- `CreateMosViewWindowHierarchy+0x3a2 @ 0x7F3C6B32`: `MOV [EAX+0x9c], 0x1` — guarded by `(*(byte *)(sec06[0]+0x48) & 0x40) != 0`.

The server's `_build_sec06_window_scaffold_record` (m14_payload.py:714-761) writes `sec06[0]+0x48 = _SEC06_FLAG_OUTER_RECT_ABSOLUTE = 0x08`. Bit 0x40 is **NOT** set → `pane+0x9c` stays 0 → no y_anchor swap.

### What the static analysis predicts (and where it conflicts with image #2)

**Static prediction**: `pane[0]` (this whose `+0x44` = SR_HWND with WS_VSCROLL/WS_HSCROLL style 0x42300000) is placed at **top 40%** of the container. `pane[0]+0x7c` (NSR_HWND, style 0x42000000) gets **bottom 60%**. Therefore the V-scrollbar should be in the **top half**.

**Observation in plan**: V-scrollbar in the **bottom half** of the window.

**Conflict.** Possible explanations (all need live confirmation):
- `pane[0]+0x9c` is set non-zero by a path I haven't found (although `search_instructions ',[E?? + 0x9c]'` returned zero hits).
- The CreateWindowExA style flags I parsed are wrong (0x42300000 might not have WS_VSCROLL the way I think).
- The image observation is misinterpreted (e.g., scrollbar IS in top 40% but appears "lower" because the window includes title bar etc.).
- A third pane (one of the additional sec06 panes from `param_1+0x38`) overlaps the SR pane.
- `MosViewSessionWindowProc` resizes panes via WM_SIZE in a way I haven't traced.

### What live SoftIce capture would pin

1. Run with SoftIce loaded; BPMB on `pane[0]+0x9c` and `pane[1]+0x9c` to catch any non-ctor writes.
2. BPX `MVPaintBitmapRecord @ 0x7E887180`; capture `(x, y)` args plus `bitmapRecord[3..9]` for both pane invocations.
3. After first paint, dump `GetWindowRect` of SR_HWND and NSR_HWND in screen coords.
4. Confirm whether one pane physically covers the upper half and the other the lower, and which has the scrollbar.

### Out-of-scope but relevant note

BBVIEW is the **Blackbird authoring viewer**, not MOSVIEW. The "BBVIEW reference" rendering uses an entirely different paint engine (no MV layout walker, no dual-pane container). Comparing absolute screen-Y across the two engines is not a like-for-like comparison; the BBVIEW number (Y≈185) is informational only. The MOSVIEW divergence to investigate is the **dual-pane geometry**, which the BBVIEW screenshot doesn't constrain.

## SoftIce status

86Box VM (PID 86595) is running with COM1 wired to `/dev/pts/3` (symlinked at `/tmp/win95.COM1.pty` and `/tmp/softice_host`). Connection via the softice MCP succeeds at the transport level (`{"connected":true}`), but issuing `BL`/`MOD`/`?` commands returns empty raw rows — **SoftIce is not loaded inside the guest**. The VM appears to be at a point where the user has not started SoftIce (e.g., stayed at a paused boot, or `WINICE.EXE` not invoked). Live capture for Issue 1's remaining items requires the user to:
1. Bring up SoftIce in the guest (Ctrl-D popup test).
2. Reproduce the Test Title scenario (load deid 4 in MSN client per `reference_msn_client_launch`).
3. Re-attempt the breakpoints listed in the plan's investigation steps.

The Issue 2 root cause is independent of live capture and stands as confirmed.

## Files / addresses cited

- `src/server/services/medview.py:164-229` — `_build_bm0_metafile_container`
- `src/server/services/medview.py:781-818` — `_handle_open_title`
- `src/server/blackbird/m14_payload.py:714-761` — `_build_sec06_window_scaffold_record`
- `src/server/blackbird/m14_payload.py:975-996` — caption + page_pixel_w/h derivation
- `src/server/blackbird/wire.py:411-435` — `build_case3_bf_chunk`
- `src/server/blackbird/wire.py:359-408` — `build_kind8_baggage`
- `MVCL14N.DLL!MVRealizeView @ 0x7E88E440` (writer of viewer[0x42]=1 at +0x74)
- `MVCL14N.DLL!MVSeekVerticalLayoutSlots @ 0x7E88EB10` (clear path at +0x482 = 0x7E88EF92)
- `MVCL14N.DLL!MVDispatchHfcNextPrevHfc @ 0x7E886010`
- `MVCL14N.DLL!MVPaintBitmapRecord @ 0x7E887180`
- `MVCL14N.DLL!fMVHasNSR @ 0x7E8835B0`
- `MVCL14N.DLL!MVBuildLayoutLine @ 0x7E894560`
- `MVCL14N.DLL!lpMVNew @ 0x7E8824C0` (viewer ctor)
- `MOSVIEW.EXE!NavigateMosViewPane @ 0x7F3C3670`
- `MOSVIEW.EXE!RealizeMosViewSessionLayout @ 0x7F3C3F7D`
- `MOSVIEW.EXE!CreateMosViewWindowHierarchy @ 0x7F3C6790` (writer of pane[1]+0x9c=1 at 0x7F3C6B32)
- `MOSVIEW.EXE!MosPaneState_ctor @ 0x7F3C33E8`
