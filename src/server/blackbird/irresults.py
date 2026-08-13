"""IR result-stream encoder — what BBIRService sends back for a query.

A reply is a run of records pushed through COSCL's dynamic read data source
into `CCmdExec::MoreData` (IRCS.DLL:0x10002980), which appends to a
`CIRClientRcvInfo` and drains `GetObj` (IRUT.DLL:0x1000bdda) until the buffer
holds no complete record.  Header, from `CIRClientRcvInfo::PeekHeader`
(IRUT.DLL:0x1000bcdd), which requires `pos + cbBody <= avail`:

    WORD  wTag
    DWORD cbBody
    BYTE  body[cbBody]

`wTag` picks the class; the body is that class's `Serialize(CFile&, FALSE)`.
Those serializers use IRUT's own stream primitives, not MFC's escaped ones
(`operator<<` overloads at IRUT.DLL:0x1001c8ae…0x1001c97f):

    ulong   4 bytes, little-endian
    ushort  2 bytes, little-endian
    GUID    16 raw bytes (`bytes_le` order)
    CString DWORD length, then that many chars — no NUL

Records this module emits, with the serializer each mirrors:

    0x03  CPropInfos   0x100177d0   DWORD count, then count × CPropInfo
          CPropInfo    0x10016ef1   GUID, CString name, WORD type, DWORD flags
    0x02  CSortInfos   0x10014d70   DWORD count, then count × CSortInfo
          CSortInfo    0x10014542   GUID, WORD direction
    0x01  CResultRow   0x1001a93c   DWORD doc_id, DWORD rank, CBetterByteArray
    0x23  CSrvrMsgQryCompleted 0x100191d9   DWORD time waited, DWORD time processed

Order matters.  The query dispatcher (IRCS.DLL:0x10007a0c) routes tag 3 to
`IQueryResultsCreate` vt[0x48] and tag 1 to vt[0x54], and a row resolves each
column's type by asking the schema (`FUN_1001a074` → PropInfos[col] →
GetType), so the schema has to arrive before the first row.

## Row values

`CBetterByteArray::Serialize` (0x1001b3c6) writes `DWORD length` then that many
raw bytes.  Inside, the first `4 × ncolumns` bytes are one DWORD slot per
column, indexed by `AtDWORD(col * 4)` in `FUN_1001a105`.

**Every slot holds a byte offset into the same array, never the value.**  The
slot table is an offset table and nothing else; each getter reads the slot,
then reads the value from where it points:

    8     `GetAt` (0x1001b5dc)   NUL-terminated string
    0x48  `AtGUID`               16 raw bytes
    0x17  `AtDWORD`              the DWORD, via FUN_1001a14e
    0x13  `AtDWORD`              same function, tried after 0x17 fails

Confirmed live for 0x17 under SoftICE (2026-08-14): FUN_1001a14e at
IRUT.DLL:0x1001a18d pushes the slot value it just read and calls `AtDWORD`
with it.  A value written inline is therefore dereferenced as an offset —
`CBetterByteArray::AssureGet` (0x1001b52a) throws 0x800401BF when
`offset + size` exceeds the array, nothing catches it, and the CRT aborts with
"abnormal program termination".

Types 2, 3 and 0x12 route through other getters that this module does not
emit; they are assumed to follow the same indirection, which is the only model
consistent with an offset table, but that is untested.

`FUN_1001a420` formats a column for display and admits exactly the type codes
above; anything else logs "CResultRow::XResultRow::GetValue" and fails.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

# Record tags, from the switch in CIRClientRcvInfo::GetObj.
TAG_RESULT_ROW = 0x01
TAG_SORT_INFOS = 0x02
TAG_PROP_INFOS = 0x03
TAG_CONTEXT_INFO = 0x04
TAG_SRVR_OBJ_INFO = 0x09
TAG_QRY_PROCESSING = 0x21
TAG_CMD_CANCELED = 0x22
TAG_CMD_COMPLETED = 0x23
TAG_CMD_APPROX_WAIT = 0x24

# Column type codes, from the dispatch in FUN_1001a420.
PROP_TYPE_WORD = 0x02
PROP_TYPE_DWORD = 0x03
PROP_TYPE_STRING = 0x08
PROP_TYPE_LONG = 0x12
PROP_TYPE_ULONG = 0x13
PROP_TYPE_TIME = 0x17
PROP_TYPE_GUID = 0x48

# How each type's payload is encoded once the slot points at it. Every type is
# indirect — see the module docstring.
_PAYLOAD_DWORD = frozenset(
    {PROP_TYPE_WORD, PROP_TYPE_DWORD, PROP_TYPE_LONG, PROP_TYPE_ULONG, PROP_TYPE_TIME}
)


class IRResultError(ValueError):
    """A result set the client could not read back."""


# BBIR time is a packed calendar field, not an epoch offset.  From
# `CTimeToBBIRTime` (IRUT.DLL:0x1001b7f3) and its inverse `BBIRTimeToCTime`
# (0x1001b76b), which feeds `CTime(year, month, day, hour, min, 0, -1)`:
#
#     value = (year * 13 + month) * 46080 + day * 1440 + hour * 60 + minute
#
# with `month` 1-based.  The 13 is the divisor that separates year from month
# on the way back out (46080 = 32 * 24 * 60, 599040 = 46080 * 13), and seconds
# are dropped — the resolution is one minute.
_BBIR_MONTHS_PER_YEAR = 13
_BBIR_MINUTES_PER_MONTH = 46080
_BBIR_MINUTES_PER_DAY = 1440


def encode_bbir_time(when):
    """Pack a datetime the way a date column must carry it.

    A column the client reads with `FUN_1001a14e` goes straight into
    `BBIRTimeToCTime` and then `CTime::GetLocalTm`, which returns NULL for a
    value that is not a real date — and IRFIND does not check for that
    (IRFIND.DLL:0x1000e425 dereferences it regardless), so a bogus time here
    is a client-side null dereference, not a display glitch.
    """
    return (
        (when.year * _BBIR_MONTHS_PER_YEAR + when.month) * _BBIR_MINUTES_PER_MONTH
        + when.day * _BBIR_MINUTES_PER_DAY
        + when.hour * 60
        + when.minute
    )


def decode_bbir_time(value):
    """Unpack to `(year, month, day, hour, minute)`, mirroring BBIRTimeToCTime."""
    year, rest = divmod(value, _BBIR_MINUTES_PER_MONTH * _BBIR_MONTHS_PER_YEAR)
    month, rest = divmod(rest, _BBIR_MINUTES_PER_MONTH)
    day, rest = divmod(rest, _BBIR_MINUTES_PER_DAY)
    hour, minute = divmod(rest, 60)
    return year, month, day, hour, minute


def ir_record(tag, body):
    """Frame one record: `WORD tag`, `DWORD cbBody`, body."""
    return struct.pack("<HI", tag, len(body)) + body


def _put_ulong(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def _put_ushort(value):
    return struct.pack("<H", value & 0xFFFF)


def _put_guid(value):
    return value.bytes_le if isinstance(value, uuid.UUID) else bytes(value)


def _put_string(value):
    raw = value.encode("latin-1")
    return _put_ulong(len(raw)) + raw


@dataclass
class PropInfo:
    """One result column: what it is, what to call it, how to read it."""

    guid: uuid.UUID
    name: str
    type: int = PROP_TYPE_STRING
    flags: int = 0

    def encode(self):
        return (
            _put_guid(self.guid)
            + _put_string(self.name)
            + _put_ushort(self.type)
            + _put_ulong(self.flags)
        )


@dataclass
class SortInfo:
    """One sort key. `direction` is the WORD CSortInfo carries after the GUID."""

    guid: uuid.UUID
    direction: int = 0

    def encode(self):
        return _put_guid(self.guid) + _put_ushort(self.direction)


@dataclass
class ResultRow:
    """One hit. `values` runs parallel to the schema's columns."""

    doc_id: int = 0
    rank: int = 0
    values: list = field(default_factory=list)


def encode_prop_infos(columns):
    """Tag 0x03 — the result schema. Must precede any row."""
    return ir_record(
        TAG_PROP_INFOS, _put_ulong(len(columns)) + b"".join(c.encode() for c in columns)
    )


def encode_sort_infos(keys):
    """Tag 0x02 — the sort keys, empty list included."""
    return ir_record(TAG_SORT_INFOS, _put_ulong(len(keys)) + b"".join(k.encode() for k in keys))


def encode_result_row(row, columns):
    """Tag 0x01 — one row, packed against `columns`."""
    if len(row.values) != len(columns):
        raise IRResultError(
            f"row has {len(row.values)} values but the schema declares {len(columns)} columns"
        )
    array = _pack_row_values(row.values, columns)
    body = _put_ulong(row.doc_id) + _put_ulong(row.rank) + _put_ulong(len(array)) + array
    return ir_record(TAG_RESULT_ROW, body)


def _pack_row_values(values, columns):
    """Build the CBetterByteArray: a DWORD offset per column, then the payloads.

    Every slot is an offset — writing a value inline gets it dereferenced as
    one, which throws 0x800401BF out of `AssureGet` and aborts the client.
    Payloads therefore always land after the slot table, which is why the
    first offset is `4 * len(columns)`.
    """
    slots = bytearray(4 * len(columns))
    payload = bytearray()

    for index, (value, column) in enumerate(zip(values, columns, strict=True)):
        offset = len(slots) + len(payload)
        if column.type == PROP_TYPE_STRING:
            payload += value.encode("latin-1") + b"\0"
        elif column.type == PROP_TYPE_GUID:
            payload += _put_guid(value)
        elif column.type in _PAYLOAD_DWORD:
            payload += _put_ulong(int(value))
        else:
            raise IRResultError(
                f"column {index} ({column.name}): type 0x{column.type:02X} is not one "
                "CResultRow can read back"
            )
        struct.pack_into("<I", slots, index * 4, offset)

    return bytes(slots) + bytes(payload)


def encode_cmd_completed(time_waited=0, time_processed=0):
    """Tag 0x23 — ends the command. Without it the execution stays open."""
    return ir_record(TAG_CMD_COMPLETED, _put_ulong(time_waited) + _put_ulong(time_processed))


def encode_result_stream(columns, rows, sort_keys=(), time_waited=0, time_processed=0):
    """The whole reply body: schema, sort keys, rows, then the completion."""
    parts = [encode_prop_infos(columns), encode_sort_infos(list(sort_keys))]
    parts += [encode_result_row(row, columns) for row in rows]
    parts.append(encode_cmd_completed(time_waited, time_processed))
    return b"".join(parts)
