"""Text index over published Blackbird titles, for BBIRService queries.

Substring matching over the text of every `CContent` object in every stored
title.  This is not what the real data centre ran — Blackbird's IR service was
a full inverted index with ranking, stemming and the AIR term language the
query spec describes — but it answers a query with real hits from real
published content, which is what the client needs to display a result list.

Only the `TextTree` bodies carry readable text; `TextRuns` bodies in the
observed titles hold picture data whose decode is byte noise, so they are
skipped rather than indexed as garbage (`docs/MEDVIEW-TEXT-ENCODING.md`).

The AIR query tree is flattened to its string terms and joined with AND.  The
combiner ops and the time term the client sends are read but not applied:
op semantics are not pinned, and every object in a published title carries the
same publish timestamp, so a date filter has nothing to discriminate on.
"""

from __future__ import annotations

import datetime
import logging
import pathlib
from dataclasses import dataclass

from ..services.medview import ccontent
from ..store import blackbird_state
from . import cos

log = logging.getLogger(__name__)

# The heading is the first line of a TextTree body; the rest is the story.
_SNIPPET_CHARS = 120


@dataclass
class Document:
    """One indexed object: what to show, and what to match against."""

    guid: bytes
    storage_path: str
    title: str
    text: str
    # When the title file carrying this object was written. Blackbird stamps
    # no per-object publish time the loader recovers, so the file's mtime is
    # the closest thing to one, and a date column has to carry something a
    # CTime accepts.
    modified: datetime.datetime = datetime.datetime(1995, 8, 24, 0, 0)

    @property
    def heading(self):
        """First non-empty line, falling back to the storage path."""
        for line in self.text.splitlines():
            if line.strip():
                return line.strip()
        return self.storage_path

    @property
    def snippet(self):
        flat = " ".join(self.text.split())
        return flat[:_SNIPPET_CHARS]


def load_documents():
    """Every indexable object across every stored title.

    Re-read per query rather than cached, matching how `services.bbird_ob`
    treats the same files: a publish can land between two searches, and
    serving a stale hit is worse than re-parsing a few tens of KB.
    """
    documents = []
    for path in blackbird_state.iter_titles():
        try:
            objects = cos.load_title(path)
        except Exception as exc:  # noqa: BLE001 - a bad title must not kill the pipe
            log.warning("irindex_title_unreadable path=%s err=%s", path, exc)
            continue
        modified = _modified_at(path)
        for guid, obj in objects.items():
            text = _extract_text(obj)
            if text:
                documents.append(
                    Document(
                        guid=guid,
                        storage_path=obj.storage_path,
                        title=obj.title,
                        text=text,
                        modified=modified,
                    )
                )
    return documents


def _modified_at(path):
    try:
        return datetime.datetime.fromtimestamp(pathlib.Path(path).stat().st_mtime)
    except OSError as exc:
        log.warning("irindex_mtime_unreadable path=%s err=%s", path, exc)
        return Document.modified


def _extract_text(obj):
    if obj.typename != "CContent" or not ccontent.is_texttree(obj.object_bytes):
        return ""
    try:
        return ccontent.decode_texttree(obj.object_bytes).text
    except Exception as exc:  # noqa: BLE001 - one bad body must not kill the query
        log.warning("irindex_content_undecodable path=%s err=%s", obj.storage_path, exc)
        return ""


def search(terms, documents=None, limit=None):
    """Documents containing every term, case-insensitively.

    Ordered by total term occurrences, descending, so the strongest match
    leads; ties keep index order, which is title then storage path.
    """
    if documents is None:
        documents = load_documents()
    needles = [t.casefold() for t in terms if t]
    if not needles:
        return []

    hits = []
    for doc in documents:
        haystack = doc.text.casefold()
        counts = [haystack.count(n) for n in needles]
        if all(counts):
            hits.append((sum(counts), doc))

    hits.sort(key=lambda pair: -pair[0])
    ranked = [(score, doc) for score, doc in hits]
    return ranked[:limit] if limit else ranked
