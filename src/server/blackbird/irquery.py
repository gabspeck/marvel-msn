"""IQuerySpec decoder — the search request BBIRService clients stream.

`CCmdQuery::Execute` (IRCS.DLL:0x100046f4) serializes the IQuerySpec object
graph into a flat buffer through each class's `vt[0x1c]` and ships it as a
chunked field.  IRUT.DLL carries the matching reader, and that reader — not the
writers — is what this module mirrors, because it is the authority on which
byte counts and tag values are legal:

    BuildQuerySpec            IRUT.DLL:0x1000d14d
    BuildDocPropertyList      IRUT.DLL:0x1000d2cc
    BuildSortDocPropertyList  IRUT.DLL:0x1000d3db
    BuildCriteriaSpecList     IRUT.DLL:0x1000d4ea
    BuildSortDocProperty      IRUT.DLL:0x1000d5f9
    BuildCriteriaSpec         IRUT.DLL:0x1000d72c
    BuildDocSourceList        IRUT.DLL:0x1000d871
    BuildDocSource            IRUT.DLL:0x1000d97d
    BuildCriteria             IRUT.DLL:0x1000cb70

Every record opens with a `WORD` class tag; list records follow it with a
`WORD` element count.  All integers are little-endian.  GUIDs are 16 raw bytes
in `bytes_le` order.

    0x00C0  QuerySpec            WORD tag, WORD nChildren (2 or 3), DWORD max_results
                                 → DocPropertyList, CriteriaSpecList,
                                   SortDocPropertyList when nChildren == 3
    0x0080  DocPropertyList      WORD tag, WORD count (must be nonzero)
    0x00B0  SortDocPropertyList  WORD tag, WORD count (must be nonzero)
    0x000A  DocProperty          26 bytes + `extra`; see DocProperty below
    0x00A0  CriteriaSpecList     WORD tag, WORD count
    0x0090  CriteriaSpec         28 bytes; nChildren is 0 or 2, and 2 means a
                                 DocSourceList and an Air query tree follow
    0x0070  DocSourceList        WORD tag, WORD count
    0x0009  DocSource            WORD tag, WORD 0, GUID  (20 bytes)

The Air query tree under a CriteriaSpec is its own tag space, read by the one
recursive `BuildCriteria`:

    0x0000  AirRelativeTerm (op 5)      0x0004  AirTimeTerm          28 bytes
    0x0001  AirRelativeTerm (op 2)      0x0006  AirPastTimeTerm      24 bytes
    0x0002  AirStringTerm               0x0010  AirMaxCountCombiner  10 bytes
    0x0003  AirExpandedTerm             0x0020  AirQueryCombiner      6 bytes
    0x0005  AirStringContextTerm

Combiners carry their child count in the WORD at +2 and the children follow
inline.  The five term tags share a body — GUID, a typed value, and per-tag
trailers — laid out in `_parse_air_term`.

`BuildCriteria` reads a combiner's child count but the terms themselves are
positional, so a tree is only walkable front-to-back; there are no lengths to
skip by.  A short or malformed buffer therefore raises rather than resyncing.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

# Object tags, from the tag compared in each Build* reader.
TAG_QUERY_SPEC = 0x00C0
TAG_DOC_PROPERTY_LIST = 0x0080
TAG_SORT_DOC_PROPERTY_LIST = 0x00B0
TAG_DOC_PROPERTY = 0x000A
TAG_CRITERIA_SPEC_LIST = 0x00A0
TAG_CRITERIA_SPEC = 0x0090
TAG_DOC_SOURCE_LIST = 0x0070
TAG_DOC_SOURCE = 0x0009

# Air query node tags, from the switch in BuildCriteria.
AIR_RELATIVE_TERM_5 = 0x0000
AIR_RELATIVE_TERM_2 = 0x0001
AIR_STRING_TERM = 0x0002
AIR_EXPANDED_TERM = 0x0003
AIR_TIME_TERM = 0x0004
AIR_PAST_TIME_TERM = 0x0006
AIR_STRING_CONTEXT_TERM = 0x0005
AIR_MAX_COUNT_COMBINER = 0x0010
AIR_QUERY_COMBINER = 0x0020

_AIR_TERM_NAMES = {
    AIR_RELATIVE_TERM_5: "relative_term",
    AIR_RELATIVE_TERM_2: "relative_term",
    AIR_STRING_TERM: "string_term",
    AIR_EXPANDED_TERM: "expanded_term",
    AIR_TIME_TERM: "time_term",
    AIR_STRING_CONTEXT_TERM: "string_context_term",
    AIR_PAST_TIME_TERM: "past_time_term",
    AIR_MAX_COUNT_COMBINER: "max_count_combiner",
    AIR_QUERY_COMBINER: "query_combiner",
}

# The `IRAssert` at BuildCriteria+0x6d admits exactly these two value types.
VALUE_TYPE_DWORD = 3
VALUE_TYPE_STRING = 8


class IRQueryError(ValueError):
    """A buffer the client's own reader would have thrown on.

    IRUT signals these as 0xF0000351 (wrong class tag), 0xF0000352 (illegal
    child count) and 0xF0000353 (unexpected fixed field).
    """


@dataclass
class DocProperty:
    """Tag 0x0A. `BuildSortDocProperty` sizes it 26 + the WORD at +24, checks
    the tag and that the WORD at +22 is 8, and reads the sort direction from
    the WORD at +2."""

    guid: uuid.UUID
    direction: int
    extra: bytes = b""


@dataclass
class DocSource:
    """Tag 0x09 — one searchable source, identified by GUID."""

    guid: uuid.UUID


@dataclass
class AirTerm:
    """A leaf of the Air query tree."""

    tag: int
    name: str
    guid: uuid.UUID | None = None
    value: str | int | None = None
    value_type: int | None = None
    flag: int = 0
    contexts: list[uuid.UUID] = field(default_factory=list)
    # Time terms only.
    time_op: int | None = None
    time_from: int | None = None
    time_to: int | None = None


@dataclass
class AirCombiner:
    """An interior node: `op` over `children`."""

    tag: int
    name: str
    op: int
    children: list = field(default_factory=list)
    # AirMaxCountCombiner only — the cap it carries in the DWORD at +6.
    max_count: int | None = None


@dataclass
class CriteriaSpec:
    """Tag 0x90 — one criterion: where to look and what to match."""

    guid: uuid.UUID
    value: int
    sources: list[DocSource] = field(default_factory=list)
    criteria: AirTerm | AirCombiner | None = None


@dataclass
class QuerySpec:
    """Tag 0xC0 — the whole search request."""

    max_results: int
    properties: list[DocProperty] = field(default_factory=list)
    criteria: list[CriteriaSpec] = field(default_factory=list)
    sort_properties: list[DocProperty] = field(default_factory=list)

    def _walk(self):
        """Every Air node in the criteria trees, depth first."""

        def walk(node):
            if isinstance(node, AirCombiner):
                for child in node.children:
                    yield from walk(child)
            elif node is not None:
                yield node

        for spec in self.criteria:
            yield from walk(spec.criteria)

    def terms(self):
        """Every string a term matches on, in tree order.

        The Find UI runs the typed query through `CQueryExprParser::Parse`
        (IRCS.DLL) and emits one term per token, so this is the token list the
        user actually typed.
        """
        return [n.value for n in self._walk() if isinstance(n, AirTerm) and isinstance(n.value, str)]

    def time_properties(self):
        """GUIDs of the properties a time term filters on.

        A column named here has to be served as a date: the Find UI reads it
        with the getter that expects type 0x17 and hands the value straight to
        `CTime`, so serving it as anything else crashes the client.  Reading
        the set off the query is what keeps that in step — the client names
        the date property in the request itself.
        """
        return {
            n.guid
            for n in self._walk()
            if isinstance(n, AirTerm)
            and n.tag in (AIR_TIME_TERM, AIR_PAST_TIME_TERM)
            and n.guid is not None
        }


class _Reader:
    """A cursor over the spec buffer.

    `BuildCriteria` advances by computed sizes rather than delimiters, so
    every read is bounds-checked: overrunning means the layout is wrong, and
    silently returning short data would corrupt the parse downstream.
    """

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def _need(self, n):
        if self.pos + n > len(self.data):
            raise IRQueryError(
                f"buffer overrun at offset {self.pos}: want {n} bytes, "
                f"{len(self.data) - self.pos} left"
            )

    def word(self):
        self._need(2)
        (value,) = struct.unpack_from("<H", self.data, self.pos)
        self.pos += 2
        return value

    def dword(self):
        self._need(4)
        (value,) = struct.unpack_from("<I", self.data, self.pos)
        self.pos += 4
        return value

    def byte(self):
        self._need(1)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def raw(self, n):
        self._need(n)
        value = self.data[self.pos : self.pos + n]
        self.pos += n
        return value

    def guid(self):
        return uuid.UUID(bytes_le=self.raw(16))

    def peek_word(self, offset=0):
        self._need(offset + 2)
        (value,) = struct.unpack_from("<H", self.data, self.pos + offset)
        return value

    def expect_tag(self, tag, what):
        got = self.word()
        if got != tag:
            raise IRQueryError(
                f"{what}: expected tag 0x{tag:04X} at offset {self.pos - 2}, got 0x{got:04X}"
            )


def parse_query_spec(data):
    """Decode a serialized IQuerySpec. Raises IRQueryError on anything the
    client's own reader would reject, including trailing bytes."""
    reader = _Reader(data)
    spec = _parse_query_spec(reader)
    if reader.pos != len(data):
        raise IRQueryError(f"{len(data) - reader.pos} trailing bytes after offset {reader.pos}")
    return spec


def _parse_query_spec(reader):
    reader.expect_tag(TAG_QUERY_SPEC, "QuerySpec")
    n_children = reader.word()
    if not 2 <= n_children <= 3:
        raise IRQueryError(f"QuerySpec: child count {n_children} outside 2..3")
    max_results = reader.dword()

    spec = QuerySpec(max_results=max_results)
    spec.properties = _parse_property_list(reader, TAG_DOC_PROPERTY_LIST, "DocPropertyList")
    spec.criteria = _parse_criteria_spec_list(reader)
    if n_children == 3:
        spec.sort_properties = _parse_property_list(
            reader, TAG_SORT_DOC_PROPERTY_LIST, "SortDocPropertyList"
        )
    return spec


def _parse_property_list(reader, tag, what):
    reader.expect_tag(tag, what)
    count = reader.word()
    if count == 0:
        raise IRQueryError(f"{what}: empty list")
    return [_parse_doc_property(reader) for _ in range(count)]


def _parse_doc_property(reader):
    start = reader.pos
    reader.expect_tag(TAG_DOC_PROPERTY, "DocProperty")
    direction = reader.word()
    guid = reader.guid()
    reader.word()
    marker = reader.word()
    if marker != 8:
        raise IRQueryError(f"DocProperty at {start}: field at +22 is {marker}, expected 8")
    extra_len = reader.word()
    return DocProperty(guid=guid, direction=direction, extra=reader.raw(extra_len))


def _parse_criteria_spec_list(reader):
    reader.expect_tag(TAG_CRITERIA_SPEC_LIST, "CriteriaSpecList")
    return [_parse_criteria_spec(reader) for _ in range(reader.word())]


def _parse_criteria_spec(reader):
    start = reader.pos
    reader.expect_tag(TAG_CRITERIA_SPEC, "CriteriaSpec")
    n_children = reader.word()
    if n_children not in (0, 2):
        raise IRQueryError(f"CriteriaSpec at {start}: child count {n_children} not 0 or 2")
    value = reader.dword()
    guid = reader.guid()
    # The reader fixes the record at 0x1C bytes and never reads this trailing
    # dword back, so its meaning is unknown; skipping it keeps the cursor right.
    reader.dword()

    spec = CriteriaSpec(guid=guid, value=value)
    if n_children == 2:
        spec.sources = _parse_doc_source_list(reader)
        spec.criteria = _parse_air_node(reader)
    return spec


def _parse_doc_source_list(reader):
    reader.expect_tag(TAG_DOC_SOURCE_LIST, "DocSourceList")
    return [_parse_doc_source(reader) for _ in range(reader.word())]


def _parse_doc_source(reader):
    reader.expect_tag(TAG_DOC_SOURCE, "DocSource")
    reader.word()
    return DocSource(guid=reader.guid())


def _parse_air_node(reader):
    tag = reader.peek_word()
    if tag in (AIR_MAX_COUNT_COMBINER, AIR_QUERY_COMBINER):
        return _parse_air_combiner(reader, tag)
    if tag == AIR_TIME_TERM:
        return _parse_air_time_term(reader)
    if tag == AIR_PAST_TIME_TERM:
        return _parse_air_past_time_term(reader)
    if tag in _AIR_TERM_NAMES:
        return _parse_air_term(reader, tag)
    raise IRQueryError(f"Air node: unknown tag 0x{tag:04X} at offset {reader.pos}")


def _parse_air_combiner(reader, tag):
    reader.word()
    n_children = reader.word()
    op = reader.byte()
    reader.byte()
    max_count = reader.dword() if tag == AIR_MAX_COUNT_COMBINER else None
    node = AirCombiner(tag=tag, name=_AIR_TERM_NAMES[tag], op=op, max_count=max_count)
    node.children = [_parse_air_node(reader) for _ in range(n_children)]
    return node


def _parse_air_time_term(reader):
    reader.word()
    op = reader.byte()
    reader.byte()
    time_from = reader.dword()
    time_to = reader.dword()
    return AirTerm(
        tag=AIR_TIME_TERM,
        name=_AIR_TERM_NAMES[AIR_TIME_TERM],
        guid=reader.guid(),
        time_op=op,
        time_from=time_from,
        time_to=time_to,
    )


def _parse_air_past_time_term(reader):
    # 24 bytes: tag, WORD, DWORD at +4, GUID at +8.
    reader.word()
    reader.word()
    time_from = reader.dword()
    return AirTerm(
        tag=AIR_PAST_TIME_TERM,
        name=_AIR_TERM_NAMES[AIR_PAST_TIME_TERM],
        guid=reader.guid(),
        time_from=time_from,
    )


def _parse_air_term(reader, tag):
    """The body shared by tags 0, 1, 2, 3 and 5.

    Layout, from the pointer arithmetic in BuildCriteria: the GUID sits at +2,
    the value type at +18, its length at +20, and the value itself at +22.
    Tags 2 and 5 then carry a flag byte and a pad byte; tag 5 adds a context
    GUID array; tag 0 a trailing word; tag 3 twelve trailing bytes.
    """
    reader.word()
    guid = reader.guid()
    value_type = reader.word()
    length = reader.word()
    raw = reader.raw(length)

    if value_type == VALUE_TYPE_STRING:
        value = raw.split(b"\0", 1)[0].decode("latin-1")
    elif value_type == VALUE_TYPE_DWORD:
        value = struct.unpack_from("<I", raw)[0]
    else:
        raise IRQueryError(f"Air term at {reader.pos}: value type {value_type} is not 3 or 8")

    term = AirTerm(
        tag=tag,
        name=_AIR_TERM_NAMES[tag],
        guid=guid,
        value=value,
        value_type=value_type,
    )

    if tag == AIR_RELATIVE_TERM_5:
        reader.word()
    elif tag == AIR_EXPANDED_TERM:
        reader.raw(12)
    elif tag in (AIR_STRING_TERM, AIR_STRING_CONTEXT_TERM):
        term.flag = reader.byte()
        reader.byte()
        if tag == AIR_STRING_CONTEXT_TERM:
            n_contexts = reader.word()
            term.contexts = [reader.guid() for _ in range(n_contexts)]
    return term
