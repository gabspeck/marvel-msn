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


def pack_shabby_id(fmt, content_id):
    return ((fmt & 0xFF) << 24) | (content_id & 0xFFFFFF)


def unpack_shabby_id(shabby_id):
    return (shabby_id >> 24) & 0xFF, shabby_id & 0xFFFFFF


_ICONS_DIR = Path(__file__).resolve().parent.parent / "data" / "icons"

ICON_REGISTRY = {
    pack_shabby_id(FORMAT_BMP, 1): _ICONS_DIR / "default_16.bmp",
    pack_shabby_id(FORMAT_ICO, 1): _ICONS_DIR / "folder.ico",
    pack_shabby_id(FORMAT_ICO, 2): _ICONS_DIR / "default.ico",
}


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
