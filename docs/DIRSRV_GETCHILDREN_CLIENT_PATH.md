# DIRSRV GetChildren — client call path and property request

## Call chain

```
EXPLORER.EXE
  MOSSHELL!CMosShellFolder::EnumObjects           (7F3F2B90)
    MOSSHELL!CMosEnumIDList::Init                 (7F3FB199)
      snapshot->vtbl[3]   GetSnap (read +0x48)    (7F3F35C2)
      snapshot->vtbl[42]  CMosTreeNode::GetCChildren (7F3FDF47)
        this->vtbl[6]     try delegate (parent/shared cache)
          if S_OK -> recurse into returned MTN
          else (S_FALSE) -> we are the root:
        this->vtbl[44]    CMosTreeNode::OkToGetChildren (7F3FE333)
          TREENVCL!CTreeNavClient::GetChildren    (import @ MOSSHELL 0x7F41190C)
```

`OkToGetChildren` is the lazy loader. Re-entry is guarded by critical section
at `this+0x5C` and the `flags_3B & 4` bit (set once the server returns 0 kids).

## CTreeNavClient::GetChildren arguments

From `CMosTreeNode::OkToGetChildren`:

| arg | source | meaning |
|-----|--------|---------|
| 1 | `local_9` (stack CTreeNavClient) | client state |
| 2 | `*(LARGE_INTEGER*)(this+0x18)` | node id (8 bytes) |
| 3 | `0` | reserved / flags |
| 4 | `this->field_2D` (+0xB4 dword) | handle / token |
| 5 | `ppuVar5` | **requested property tag list** |
| 6 | `&DAT_7F40B038` | locale descriptor / LCID blob |
| 7 | `&this->field_2C` (+0xB0) | out: child count |
| 8 | `&this->field_29` (+0xA4) | out: children array ptr |

On success, child count and array pointer land in the node struct. On zero
children the `no-more-children` flag (`flags_3B |= 4`) gets set, suppressing
future calls. On wire error the array pointer is cleared to 0.

## Property tag request lists

Client dictates which per-child DIRSRV properties the server should emit:

### Default list @ 0x7F40E868 (7 tags, NULL terminator)

```
{ 'a', 'c', 'b', 'e', 'g', 'h', 'x' }
```

### Alt list @ 0x7F40E888 (used when `flags_3B & 2`, 2 tags)

```
{ 'g', 'a' }
```

### Plugin-extended path

```
iVar1 = *(int*)(this->field_2E + 0x18C);
if (iVar1 != 0)
    ppuVar5 = FUN_7F40305B(&default_list, 7, *(field_2E+0x400), iVar1);
```

`FUN_7F40305B` merges the default list with extra tags the plugin advertises at
`field_2E+0x18C` (count) and `field_2E+0x400` (pointer). The merged buffer is
freed via `CMosXAllocator::Free(&g_mxa, ...)` after the wire call.

## Consequences for server fixtures

- `'z'` is **never** in the request list on this call — the client doesn't want
  it back from GetChildren on the DIRSRV tree path. Sending it wastes bytes
  but shouldn't break parsing (unknown tags are ignored by the walker, assumed).
- `'h'` **is** in the default list — if your icon property isn't taking effect,
  the drop is downstream of the wire (parser side in TREENVCL).
- The `'c'`, `'b'`, `'e'` fields the server sends are all asked for in the
  default case; mismatches between wire encoding and parser type will show up
  as truncated strings or dropped children.

## Where the reply gets parsed

### TREENVCL.DLL — record walker

```
CTreeNavClient::GetChildren  (7F631778)  →  GetRelatives(this, 0, ...)
CTreeNavClient::GetRelatives (7F63190E)
  PackPropNames(this, prop_list, &local_buf, &cap)   ; serialize tag list
  marshal request via IMpcMarshal vtable             ; build wire frame
  send/recv RPC                                      ; SOCK round-trip
  NodeIterator_Constructor(mem, data_iface, count, locale_field)
    creates iterator @ +0x00=vtable +0x04=data +0x08=count +0x0C=idx +0x10=offset +0x14=locale
  CreateNodeIteratorWrapper(0, iterator) → out param

CTreeNavClient::GetNextNode  (7F631B72)  →  NodeIterator_GetNext
NodeIterator_GetNext         (7F632370)
  if idx >= count return 0x105 (no-more-nodes)
  return NodeIterator_GetAtIndex(this, idx, &props)

NodeIterator_GetAtIndex      (7F63238A)
  walks dynamic-section buffer as back-to-back records
  each record begins with [u32 stride to next]
  block-fetch via data->vtbl[7]; advance via data->vtbl[5]
  status 0xB0B000B → end-of-block, fetch next
  status 0x100     → data error; status 0x105 → exhausted
  per-record: FDecompressPropClnt(record_data, record_size, &out_props)
```

### SVCPROP.DLL — record parser

```
FDecompressPropClnt          (7F6416C5)  →  FDecompressPropClntImpl(.., 0)
FDecompressPropClntImpl      (7F641592)
  read u32 total_size at offset 0
  read u16 prop_count at offset 4
  pointer = base+6
  for i in 0..prop_count-1:
    type   = *ptr++
    name   = lstrlenA(ptr); ptr += name_len + 1   ; NUL-term ASCII name
    value  = DecodePropertyValue(type, ptr, &meta, &consumed, 0)
    CServiceProperties::FSet(props, i, name, type, value, meta)
    ptr   += consumed
    free(value)
```

### Per-record on-wire format

```
+0  u32  total_size                     ; size of this record
+4  u16  prop_count                     ; number of properties below
+6  property[0]
    +0  u8       type                    ; see table below
    +1  asciiz   name                    ; e.g. "a", "b", "c", "h"
    +N  bytes    value                   ; encoding per type
    property[1] ...
```

### DecodePropertyValue (7F64143A) — type byte → encoding

| Type | Encoding | Notes |
|------|----------|-------|
| 0x01, 0x05 | 1 byte | byte |
| 0x02, 0x06 | 2 bytes | word |
| 0x03, 0x07, 0x0D, 0x0F, 0x11 | 4 bytes | dword |
| 0x04, 0x08, 0x09, 0x0C | 8 bytes | qword |
| **0x0A** | ASCIIZ | plain NUL-terminated ANSI string (`FUN_7F6413CA`) |
| **0x0B** | flag-byte string | `[u8 flag][asciiz string]` — first byte consumed as flag |
| 0x0E | blob | `[u32 length][bytes]` |
| 0x10 | dword array | `[u32 count][count*4 bytes]` |
| other | empty | no bytes consumed |

> **0x0A vs 0x0B is the gotcha.** Sending plain string data with type 0x0B
> consumes the first character as the flag byte and the parser thinks the
> string starts at offset 1. Memory `project_dirsrv_dialog_props_investigation`
> records the "0x0B truncates to 'M'" symptom — that is exactly this dispatch.

## Implications for "tree doesn't match what we sent"

A child appears in the tree only if all of:

1. The DIRSRV reply contains a record at the right stride offset.
2. The record's `total_size` and `prop_count` are coherent (impl bails if `total_size > caller_size`).
3. Every property has a name terminated by NUL and a value sized exactly per its type byte (otherwise `ptr` advances incorrectly and subsequent properties read garbage).
4. The 'a' (display name) is type 0x0A (ASCIIZ), per the DSNAV nav-encoding memory.
5. The dynamic section's outer record-count matches the actual record list (no over/undercount).

Anything that **drops a child** is most likely:
- Wrong record `total_size` causes `*param_1 <= param_2` check to fail → entire record skipped.
- Wrong `prop_count` walks off the end → next record's stride is wrong → cascade.
- A type-byte mismatch on an early property advances `ptr` wrong → all later properties in that record corrupted.

Anything that **shows wrong text** is most likely:
- Type 0x0B used where 0x0A was intended → first char eaten.
- Locale parameter (`field_2E+0x400` extras) requesting a property the server doesn't emit → unset on the client.

## Next debugging steps

1. Hex-dump the DIRSRV GetChildren reply for a reproducible click on the
   server side, including the dynamic section bytes verbatim.
2. Walk it by hand with the format above to verify the stride/size/count
   chain is internally consistent.
3. For each property, confirm type byte matches the table — especially 'a'
   and 'e' must be 0x0A.
4. If a child is missing, the cause is in steps 2–3 above. If a child is
   present but renders wrong, the cause is the type byte for that property.
