"""Shabby icon protocol — DIRSRV GetShabby RPC.

The client requests a node icon by sending a Shabby ID (DWORD) on the DIRSRV
pipe. Two consumers:

- `mf` property (banner BMP at top of folder view): MOSSHELL.DLL
  LoadShabbyIconForNode (0x7f405018) reads `mf` as DWORD, selects the loader
  by the top byte — BMP/EMF/WMF — and hands the downloaded bytes to the
  matching Win32 API.
- `h` property (per-item listview icon): MOSSHELL.DLL FUN_7f4049f9 calls
  GetShabbyToFile with the `h` DWORD, then ExtractIconExA on the temp file.
  ExtractIconExA auto-detects the file type (ICO/EXE/DLL), so the top byte
  is irrelevant to the client — we just use it to namespace our registry.

Server replies with raw file bytes; no header synthesis beyond what the
source file itself carries.

The Change Icon picker (DIRSRV EnumShn, selector 0x05) draws from the
pickable window below and writes the chosen id back into `h`.
"""

from pathlib import Path

# Format byte values — top byte of the Shabby ID DWORD.
# Used by MOSSHELL LoadShabbyIconForNode switch (mf path) and by us to
# namespace the ICON_REGISTRY (h path doesn't care).
FORMAT_EMF = 0x01            # GetEnhMetaFileA
FORMAT_ICO = 0x02            # ExtractIconExA (ICO/EXE/DLL) — h property
FORMAT_WMF_RAW = 0x03        # LoadAndCallW Meta_init/add/play/close
FORMAT_WMF_PLACEABLE = 0x04  # magic 0x9AC6CDD7
FORMAT_BMP = 0x05            # LoadImageA(IMAGE_BITMAP, LR_LOADFROMFILE | LR_DEFAULTSIZE)

# Format 0 is the MOSSHELL Change Icon dialog's generic ICO/EXE/DLL path.
# The DSNED Banner page supplies the remaining values after checking the file
# extension. These values come from live client calls and static analysis of
# MOSSHELL 0x7F40481B and DSNED 0x7F5717C8.
UPLOAD_FORMATS = {
    0x00,
    FORMAT_EMF,
    FORMAT_WMF_RAW,
    FORMAT_WMF_PLACEABLE,
    FORMAT_BMP,
}


def pack_shabby_id(fmt, content_id):
    return ((fmt & 0xFF) << 24) | (content_id & 0xFFFFFF)


def unpack_shabby_id(shabby_id):
    return (shabby_id >> 24) & 0xFF, shabby_id & 0xFFFFFF


_ICONS_DIR = Path(__file__).resolve().parent.parent / "data" / "icons"

# Change Icon picker window. MOSSHELL's list builder (FUN_7f40136c @
# 0x7F40136C, WM_INITDIALOG of ChangeIconDlgProc @ 0x7F401886) walks the
# EnumShn stream and applies two guards per id: it skips anything <= 0x598
# and *breaks* on the first id > 0xA48. Ids outside the window are therefore
# invisible to the picker, and the enumeration has to be ascending or the
# break truncates it early.
#
# Ids in this window are plain ordinals with no format byte: the picker draws
# them through the same ExtractIconExA path as `h` (WM_DRAWITEM →
# FUN_7f40149e → FUN_7f4049f9), which sniffs the file type itself.
PICKABLE_ID_MIN = 0x0599
PICKABLE_ID_MAX = 0x0A48

PICKABLE_ICONS = {
    0x0599: _ICONS_DIR / "folder.ico",
    0x059A: _ICONS_DIR / "default.ico",
}

# What `h` carries by default. Sits inside the pickable window so the picker
# opens with the node's current icon selected — ChangeIconDlgProc's builder
# matches each enumerated id against GetProperty("h") and sends LB_SETCURSEL
# on a hit.
DEFAULT_NODE_ICON_ID = 0x0599

ICON_REGISTRY = {
    pack_shabby_id(FORMAT_BMP, 1): _ICONS_DIR / "default_16.bmp",
    pack_shabby_id(FORMAT_ICO, 1): _ICONS_DIR / "folder.ico",
    pack_shabby_id(FORMAT_ICO, 2): _ICONS_DIR / "default.ico",
    **PICKABLE_ICONS,
}


def enum_pickable_shabby_ids():
    """Return the Change Icon picker's shabby ids, ascending."""
    return sorted(PICKABLE_ICONS)


def load_shabby_bytes(shabby_id):
    """Return the raw icon-file bytes for `shabby_id`, or None if unknown."""
    entry = ICON_REGISTRY.get(shabby_id)
    if entry is None:
        return None
    if isinstance(entry, (bytes, bytearray)):
        return bytes(entry)
    if not entry.exists():
        return None
    return entry.read_bytes()


def add_shabby_bytes(fmt, blob):
    """Register an uploaded shabby and return its new ID, or None on failure.

    Format 0 is a Change Icon entry and therefore needs a plain ordinal in the
    picker's visible window. Banner formats keep the format byte in the high
    byte so MOSSHELL selects the matching Win32 image loader.
    """
    if fmt not in UPLOAD_FORMATS or not blob:
        return None

    if fmt == 0:
        shabby_id = max(PICKABLE_ICONS, default=PICKABLE_ID_MIN - 1) + 1
        if shabby_id > PICKABLE_ID_MAX:
            return None
        PICKABLE_ICONS[shabby_id] = bytes(blob)
    else:
        used_content_ids = [
            unpack_shabby_id(shabby_id)[1]
            for shabby_id in ICON_REGISTRY
            if unpack_shabby_id(shabby_id)[0] == fmt
        ]
        content_id = max(used_content_ids, default=0) + 1
        if content_id > 0xFFFFFF:
            return None
        shabby_id = pack_shabby_id(fmt, content_id)

    ICON_REGISTRY[shabby_id] = bytes(blob)
    return shabby_id
