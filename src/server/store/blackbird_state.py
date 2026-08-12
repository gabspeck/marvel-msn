"""On-disk persistence for what a Blackbird publish leaves behind.

Everything else this server holds is either an authored fixture or lives for
the process. A publish is neither. It is client-supplied state the Release
Wizard expects to still be there the next time it looks — it reads `bbix` back
before publishing to tell a first publish from a re-publish — and NODEEXEC.EXE
refuses to launch the viewer without it. Reproducing it means driving the
wizard by hand, so a server restart must not throw it away.

Only the `bbix` record is stored here. The compound file the publish streams
is written to `captures/blackbird/` by the Bbird_OB handler; associating it
with a node is retrieval-side work and belongs with the COSCL readers.

The records are opaque: 84 bytes written by the client and handed back
unchanged (docs/BLACKBIRD.md §6.1). Nothing in this module interprets them,
so a format change on the client side needs no change here.
"""

from __future__ import annotations

import logging
import pathlib

log = logging.getLogger(__name__)

# Runtime state, not authored content — `resources/` is checked in and this is
# not. Sits under the already-ignored `captures/` tree so a publish never shows
# up as a working-tree change.
STATE_DIR = pathlib.Path(__file__).resolve().parents[3] / "captures" / "blackbird" / "sites"

_SUFFIX = ".bbix"


def _path_for(node_id):
    """Map a `f0:f8` node id onto a filename.

    The colon is legal on this server's filesystem but not on the one the
    client runs, and these files get copied around during debugging.
    """
    return STATE_DIR / f"{node_id.replace(':', '_')}{_SUFFIX}"


def load_site_records():
    """Every stored record, as `{node_id: blob}`.

    A missing directory is the normal state before the first publish, not an
    error. An unreadable file is skipped with a warning rather than taking the
    whole server down at import time — one corrupt record should cost one node,
    not the process.
    """
    records = {}
    if not STATE_DIR.is_dir():
        return records
    for path in sorted(STATE_DIR.glob(f"*{_SUFFIX}")):
        node_id = path.stem.replace("_", ":")
        try:
            records[node_id] = path.read_bytes()
        except OSError as exc:
            log.warning("blackbird_site_load_failed node=%s path=%s err=%s", node_id, path, exc)
    return records


def save_site_record(node_id, blob):
    """Persist one node's record, or drop it when the record is empty.

    Written through a temporary file and renamed, so a restart during the write
    finds either the old record or the new one — never a truncated blob that
    would read back as NODEEXEC's "version is incorrect".
    """
    path = _path_for(node_id)
    try:
        if not blob:
            path.unlink(missing_ok=True)
            return
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f"{_SUFFIX}.tmp")
        tmp.write_bytes(blob)
        tmp.replace(path)
    except OSError as exc:
        log.warning("blackbird_site_save_failed node=%s path=%s err=%s", node_id, path, exc)
