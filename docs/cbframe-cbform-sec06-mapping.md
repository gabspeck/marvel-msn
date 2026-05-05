# CBFrame / CBForm → Wire `sec06` Field Mapping

Pinned via Ghidra static RE plus single-property probe TTLs in BBDESIGN:

- `VIEWDLL.DLL!CBFrame::Serialize @ 0x4071151e` (load order)
- `VIEWDLL.DLL!CBFrame::SetDefaults @ 0x407114b7` (initial values)
- `VIEWDLL.DLL!CBFrame::GetCaption / GetFrameName / GetIcon / GetProperties / IsDefaultFrame` (accessor offsets)
- `VIEWDLL.DLL!CBFrameProp::operator==` @ 0x4072e998 (struct width = 10 dwords = 0x28 B)
- `VIEWDLL.DLL!CBForm::Serialize @ 0x4070dee3`
- `MOSVIEW.EXE!MosViewContainer_WndProc @ 0x7f3c474b` (`WM_ERASEBKGND` consumer of `View+0x20`)
- `MOSVIEW.EXE!MosView_BuildContainerHierarchy @ 0x7f3c6790` (sec06 consumer)
- `MOSVIEW.EXE!MosView_SetPaneBackColor @ 0x7f3c1f86` (`MVSetBkColor` thunk for child panes)
- `MOSVIEW.EXE!MosView_RectFromContainer @ 0x7f3c1fd5` (outer-rect coord helper)

## BBDESIGN UI vocabulary

| BBDESIGN UI label | C++ class | Properties dialog tabs |
| --- | --- | --- |
| **Title** | `CTitle` | General + Display + MSN Site + Local Site |
| **Section** (Frontmatter / Sidebar / Definitions / etc.) | `CSection` | General + Display |
| **Page** | `CBForm` (and its embedded `CVForm`) | General + Display |
| **Window** | `CBFrame` | General + Display |
| **Resources** / Resource folder | `CResourceFolder` | (no editable properties) |

Page embedded controls (Story / Caption / Audio / CaptionButton /
Outline) are BBCTL.OCX components hosted inside the Page's CVForm.
Their on-disk layout is documented in `docs/cvform-page-objects.md`.

## Wire `sec06` record (0x98 B, selector 0x06)

`MosView_BuildContainerHierarchy` reads sec06 record `[0]` from `param_1+0x4c` after
checking `param_1+0x48 != 0` for "sec06 present". Field offsets within the record:

| offset | size | name | semantic |
| --- | --- | --- | --- |
| `+0x15` | up to ~0x33 ANSI bytes | `caption` | Inline NUL-terminated ASCII window caption for the outer `MosViewContainer` window. Falls back to literal "Online Viewer Container" if no sec06 record is present. |
| `+0x48` | u8 | `flags` | bit `0x01` = top-band rect mode (0 = fractional /0x400, 1 = absolute); bit `0x08` = outer-rect mode (0 = fractional, 1 = absolute); bit `0x40` = scroll-related flag forced onto `MosChildView+0x9c` of the non-scrolling pane |
| `+0x49` | i32 | `outer_rect.x` | outer container left/x. -1 sentinel = use parent client area |
| `+0x4D` | i32 | `outer_rect.y` | outer container top |
| `+0x51` | i32 | `outer_rect.w` | outer container width |
| `+0x55` | i32 | `outer_rect.h` | outer container height |
| `+0x5B` | u32 | `outer_color` | COLORREF stored at `View+0x20` (cached for later WM_ERASEBKGND / paint). -1 = use `GetSysColor(COLOR_WINDOW)` per `MosView_SetPaneBackColor`. |
| `+0x78` | u32 | `non_scroll_back_color` | COLORREF for the non-scrolling pane (top child band), fed to `MVSetBkColor` via `MosView_SetPaneBackColor`. -1 = `GetSysColor(COLOR_WINDOW)` |
| `+0x7C` | u32 | `scroll_back_color` | COLORREF for the scrolling pane, fed to `MVSetBkColor`. -1 = `GetSysColor(COLOR_WINDOW)` |
| `+0x80` | i32 | `top_band.x` | top child band rect x. -1 = use full client area |
| `+0x84` | i32 | `top_band.y` | top child band rect y |
| `+0x88` | i32 | `top_band.w` | top child band rect w |
| `+0x8C` | i32 | `top_band.h` | top child band rect h |

After read each rect goes through one of:
- `MosView_RectFromContainer(hwnd, &x, &y, &w, &h, !(flags & 8))` — outer rect; chrome-compensated
- `FUN_7f3c5e1c(&x, &y, &w, &h, hwnd)` — fractional /0x400 (top band when `(flags & 1) == 0`)
- `FUN_7f3c5ea5(&x, &y, &w, &h, hwnd)` — absolute, add parent origin (top band when `(flags & 1) != 0`)

Then each component is scaled by `DAT_7f3cd310 / 0x60` (LOGPIXELSY / 96 — DPI scaling).

Two `MosChildView` windows are created inside the outer `MosViewContainer`:
- **Scrolling pane** (style `0x42300000`, "MosViewContainer" caption stored in DAT_7f3cd538) — receives `scroll_back_color` from sec06 +0x7C.
- **Non-scrolling pane** (style `0x42000000`, "Non Scrolling Pane" caption from DAT_7f3cd514) — receives `non_scroll_back_color` from sec06 +0x78. If `(flags & 0x40)` is set, this pane's `+0x9c` slot is forced to 1 (suppresses some scroll behavior).

## On-disk `CBFrame` (VIEWDLL `CBFrame::Serialize` v2)

Read order matches `parse_cbframe_object` in `src/server/blackbird/ttl_inspect.py`. Offsets shown are in-memory (which match Serialize's writes via `[ECX+...]`).

| in-memory offset | wire size | proposed name | accessor / source |
| --- | --- | --- | --- |
| `this+0x04` | CString | `frame_name` | `GetFrameName` returns `&this->frame_name` |
| `this+0x08` | CString | `caption` | `GetCaption` returns `&this->caption` |
| `this+0x0C` | u8 | `is_default_frame` | `IsDefaultFrame` returns `*this+0xc` |
| `this+0x10` | u32 | `rect_left` | `SetDefaults` init = 0 |
| `this+0x14` | u32 | `rect_top` | init = 0 |
| `this+0x18` | u32 | `rect_right` | init = 640 (0x280) |
| `this+0x1C` | u32 | `rect_bottom` | init = 480 (0x1E0) |
| `this+0x20` | u32 | `border_style` | init = 0. BBDESIGN Window dialog "Border style:" enum. `0` = "Single fixed", `1` = "Double fixed" (showcase TTL pin); other enum values open. |
| `this+0x24` | u32 | `prop_u32_b` | init = 0; semantic open |
| `this+0x28` | u8 | `prop_flag_a` | init = 1 |
| `this+0x2C` | u32 | `window_style` | init = `0x00CE0000`. **Packed Win32 window-style bitmask, NOT a COLORREF.** `Properties@CViewerFrameWnd @ 0x40711227` ANDs with `0xA0000` (mid bits), tests byte +0x2E for `0xC0` and ORs `WS_CAPTION` (`0xC00000`). Default decodes as `WS_CAPTION \| WS_SYSMENU \| WS_GROUP`. The value happens to look like a valid blue COLORREF — coincidence. |
| `this+0x30` | u8 | `prop_flag_b` | init = 0 |
| `this+0x34` | u8 | `prop_flag_c` | init = 1 (written as DWORD by SetDefaults but Serialize reads as BYTE) |
| `this+0x3C` | HICON (runtime only) | `icon` | `GetIcon` returns `*this+0x3c`. Tail byte controls whether to load. |

Compatibility OR: if Serialize's local version byte `< 2`, sets bits `0xC0` at byte `this+0x2E` (high byte of `back_color`'s middle word). Default `0xCE` already has `0xC0` set; older v0/v1 records may have stripped them.

`CBFrameProp` struct is a public 10-dword view of `this+0x10..this+0x37` (40 B):
- `props+0x00..0x0F`: rect (left, top, right, bottom)
- `props+0x10`: prop_u32_a
- `props+0x14`: prop_u32_b
- `props+0x18`: prop_flag_a + 3 pad
- `props+0x1C`: window_style (Win32 style bitmask, see above)
- `props+0x20`: prop_flag_b + 3 pad
- `props+0x24`: prop_flag_c + 3 pad

## On-disk `CBForm` (VIEWDLL `CBForm::Serialize` v2)

`CBForm` is what BBDESIGN calls a **Page**. The "Properties for <page>"
Display tab maps directly to the named fields below; the remaining
anonymous fields aren't editable from this dialog.

| in-memory offset | wire size | name | BBDESIGN Page property |
| --- | --- | --- | --- |
| `this+0x04` | CString | form_name | (page name in browser tree, e.g. "Home") |
| `this+0x08` | u8 | form_mode | (open) |
| `this+0x0C` | u8 | embedded_vform_present (0/1) | — |
| `this+0x14` | swizzle | embedded_vform handle | — |
| `this+0x20` | swizzle | frame handle (CBFrame ref) | **Window:** dropdown |
| `this+0x2C` | u32 | u32_0 | open; `0` in both 4.ttl and showcase. |
| `this+0x30` | u32 | **background_color** | **Background color:** picker. COLORREF (RGB(R,G,B) = bytes [low,mid,high]). showcase TTL pinned `0x0000FFFF` (yellow) when picker explicitly set. 4.ttl: `0x009098A8` (RGB 168,152,144 — light tan; BBDESIGN's small swatch displayed as approximately the system color). |
| `this+0x34` | u32 | **mouse_pointer** | **Mouse Pointer:** dropdown (Win32 cursor ID). 4.ttl: `0x00007F00` = `IDC_ARROW`; showcase: `0x00007F01` = `IDC_IBEAM`. |
| `this+0x38` | u32 | **scrollbar_flags** | **Vertical scroll bar** = bit 1, **Horizontal scroll bar** = bit 0 (showcase TTL: `2` = V only, matches rendered window). 4.ttl: `3` = both. |
| `this+0x3C..0x43` | 8 bytes | dpi_scaled_geometry (open; rescaled by current DPI / stored DPI ratio at runtime) | (open — 4.ttl: low dword `0`, high dword `0x1E0`/480) |
| `this+0x44` | u8 | u8_0 | (open) |
| `this+0x48` | u32 | dpi_x (LOGPIXELSX at authoring time) | implicit |
| `this+0x4C` | u32 | dpi_y (LOGPIXELSY at authoring time) | implicit |

Note that **Page Height / Width** in the BBDESIGN dialog are NOT stored
on `CBForm` — they're `CBFrame.rect_bottom - rect_top` /
`rect_right - rect_left`, edited from a different angle than the
Window properties dialog (which only exposes Top/Left).

The actual **Page contents** (its embedded controls — Story, Caption,
Audio, Button, Outline, etc.) live in the `CVForm` swizzled by
`CBForm.embedded_vform`. CVForm is a Microsoft Forms 1.0 OLE compound
stream; its layout, the per-control site-descriptor format, and the
Story1R property block (margins / tabs / scroll flags / transparent
background / stylesheet picker CLSID) are documented in
`docs/cvform-page-objects.md`.

## Lowering rules (current pass)

Source: parsed `CBFrame` (the title's default frame, resolved from `CTitle.resource_folder.default_frame` swizzle). Target: sec06 record fields.

| sec06 wire field | source (authored) | reason |
| --- | --- | --- |
| `caption` (+0x15) | `CBFrame.caption` (this+0x08, `GetCaption`) | direct match. 4.ttl ships "MSN Today" |
| `flags` (+0x48) | `0x08` (constant) | outer rect is absolute pixels, top-band mode bit clear (rect is `-1`) |
| `outer_rect` (+0x49..+0x58) | `(CBFrame.rect_left, rect_top, rect_right, rect_bottom)` | direct match. 4.ttl: (0, 0, 640, 480) |
| `outer_color` (+0x5B) | `CBForm.background_color` (or `-1` if `0`) | Same authored color as the children. 4.ttl: `0x009098A8`; showcase: `0x0000FFFF`. |
| `non_scroll_back_color` (+0x78) | `CBForm.background_color` (or `-1` if `0`) | BBDESIGN Page dialog has a single "Background color" picker — applied uniformly across MOSVIEW's three pane COLORREF slots. |
| `scroll_back_color` (+0x7C) | `CBForm.background_color` (or `-1` if `0`) | same |
| `top_band` rect (+0x80..+0x8F) | `(-1, -1, -1, -1)` (sentinels) | use full client area until an authored top-band source is RE'd |

Open follow-ups (not yet mapped):
- `CBFrame.prop_u32_b` (this+0x24): default 0; both 4.ttl and showcase ship zero. May correspond to "Window style:" enum dropdown — needs a probe.
- `CBFrame.prop_flag_a/b/c`: small flags. The Window dialog's six checkboxes ("Title bar", "Menu bar", "Always on top", "Modal window", "Minimize button", "Control box") may collapse into `window_style` bits or distribute across the three prop_flag_* slots — needs a probe with several toggled.
- `CBForm.u32_0`, `CBForm.u64_0`, `CBForm.u8_0`: still anonymous after the showcase probe (all unchanged from default).
- Sec06 top-band rect (`+0x80..+0x8F`): no obvious authored source; the BBDESIGN Page dialog has no top-band concept exposed.
- Sec07 (child panes) / Sec08 (popups): empty in 4.ttl. The showcase TTL has multiple sections / forms — may surface authored sec07 records when actually opened by MOSVIEW.

## How `View+0x20` (= sec06+0x5B) is consumed

`MOSVIEW.EXE!FUN_7f3c474b` is the `MosViewContainer` window procedure:

- `WM_ERASEBKGND` (msg `0x14`): `color = (View == NULL) ? GetSysColor(COLOR_WINDOW) : View->[+0x20]; FillRect(hdc, &client, CreateSolidBrush(color))`. Direct paint.
- Custom `0x403` (Get-BackColor query): returns `View->[+0x20]` or `GetSysColor(COLOR_WINDOW)` if no View.
- Custom `0x413` (Set-BackColor): `View->[+0x20] = wParam; InvalidateRect`.

When sec06+0x5B equals `-1`, `MosView_BuildContainerHierarchy` skips the View+0x20 write — leaving it at `FUN_7f3c7c8a` zero-init = black. The black is invisible because the inner `MosChildView` panes (which use `MosView_SetPaneBackColor` with sec06+0x78 / +0x7C) paint immediately over the entire client area.
