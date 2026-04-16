"""Shabby icon protocol — DIRSRV GetShabby RPC.

The client requests a node icon by sending a Shabby ID (DWORD) on the DIRSRV
pipe. The high byte selects the loader (BMP/EMF/WMF) used by
MOSSHELL.DLL FUN_7f405018; the low 24 bits are an opaque content id.

Server replies with raw file bytes — the client writes them to disk and
loads via the matching Win32 API (LoadImageA for BMP, GetEnhMetaFileA for
EMF, etc.). No header synthesis on our side.
"""

from pathlib import Path

# Format byte values — top byte of the Shabby ID DWORD.
# Decoded by MOSSHELL.DLL FUN_7f405018 switch.
FORMAT_EMF = 0x01            # GetEnhMetaFileA
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
}


def load_shabby_bytes(shabby_id):
    """Return the raw icon-file bytes for `shabby_id`, or None if unknown."""
    path = ICON_REGISTRY.get(shabby_id)
    if path is None or not path.exists():
        return None
    return path.read_bytes()
