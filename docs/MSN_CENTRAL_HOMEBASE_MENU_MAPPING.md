# MSN Central HOMEBASE Menu Mapping

This note captures the static mapping between the five visible MSN Central
buttons, the HOMEBASE command strings, and the `_MosNodeId` values ultimately
fed into `MOSSHELL!HrGetPMtn`.

## Source

Static reconstruction from:

- `binaries/HOMEBASE.DLL` resource type `RCDATA`, name `HOMEBASE`
- `GUIDENAV.NAV` loader `FUN_7f5123ce`

Direct confirmation from raw resources:

- `wrestool -x --raw --type=10 --name='HOMEBASE' binaries/HOMEBASE.DLL`
- `wrestool -x --raw --type=6 --name=1 binaries/HOMEBASE.DLL`
- `wrestool -x --raw --type=6 --name=2 binaries/HOMEBASE.DLL`

`FUN_7f5123ce` reads the HOMEBASE RCDATA table as:

- `u16 item_count`
- repeated 6-word records:
  - `label_string_id`
  - `x1`
  - `y1`
  - `x2`
  - `y2`
  - `command_string_id`

It loads the label and command strings from the HOMEBASE string tables. For
command verbs `JUMP` and `LJUMP`, it parses the command tail with
`SzToMnid(...)`, yielding the `_MosNodeId` passed into `HrGetPMtn`.

Accepted verbs in `GUIDENAV` are:

- `JUMP`
- `LJUMP`
- `EMAIL`

`EMAIL` is a separate direct-launch path and does not go through `HrGetPMtn`.

## Raw Resource Decode

Direct decode of the `HOMEBASE` RCDATA record list plus string tables yields
these seven entries:

1. label `F&avorite Places`
   - rect: `(16,160)-(493,200)`
   - command: `JUMP 3:1:0:0`
2. label `Member A&ssistance`
   - rect: `(16,213)-(493,253)`
   - command: `LJUMP 1:1:0:0`
3. label `&Categories`
   - rect: `(15,264)-(493,304)`
   - command: `LJUMP 1:0:0:0`
4. label `Worldwide Member Assistance`
   - rect: `(0,0)-(0,0)`
   - command: `JUMP 1:0:0:0`
5. label `Worldwide Categories`
   - rect: `(0,0)-(0,0)`
   - command: `JUMP 1:1:0:0`
6. label `MSN T&oday`
   - rect: `(16,53)-(493,92)`
   - command: `LJUMP 1:4:0:0`
7. label `E-&Mail`
   - rect: `(16,107)-(493,148)`
   - command: `EMAIL`

The ampersands are accelerator markers from the original string-table
resources; they do not change the mnid mapping.

## Visible MSN Central Buttons

These are the five visible buttons in the MSN Central window:

1. `MSN Today`
   - rect: `(16,53)-(493,92)`
   - command: `LJUMP 1:4:0:0`
   - result: `_MosNodeId = 1:4:0:0`
2. `E-Mail`
   - rect: `(16,107)-(493,148)`
   - command: `EMAIL`
   - result: no `_MosNodeId`; launches via the email-specific path
3. `Favorite Places`
   - rect: `(16,160)-(493,200)`
   - command: `JUMP 3:1:0:0`
   - result: `_MosNodeId = 3:1:0:0`
4. `Member Assistance`
   - rect: `(16,213)-(493,253)`
   - command: `LJUMP 1:1:0:0`
   - result: `_MosNodeId = 1:1:0:0`
5. `Categories`
   - rect: `(15,264)-(493,304)`
   - command: `LJUMP 1:0:0:0`
   - result: `_MosNodeId = 1:0:0:0`

## Hidden / Related HOMEBASE Entries

The same HOMEBASE resource also includes two zero-rectangle entries:

1. `Worldwide Member Assistance`
   - rect: `(0,0)-(0,0)`
   - command: `JUMP 1:0:0:0`
2. `Worldwide Categories`
   - rect: `(0,0)-(0,0)`
   - command: `JUMP 1:1:0:0`

Each hidden entry shares a target with a visible button:

- `1:0:0:0` is used by `Categories` and by one hidden Worldwide entry
- `1:1:0:0` is used by `Member Assistance` and by the other

That sharing is the design, not a defect: `LJUMP` descends into a hub and
takes its localized child, `JUMP` opens the hub itself. The two targets are
`GetSpecialMnid(0)` and `GetSpecialMnid(1)`, which MOSSHELL names from its
own STRINGTABLE (`docs/MOSSHELL.md` §6.1.1):

| mnid | wire key | Hub |
|---|---|---|
| `1:0:0:0` | `0:0` | Worldwide **Categories** |
| `1:1:0:0` | `1:0` | Worldwide **Member Assistance** |

So `Categories` (`LJUMP 1:0:0:0`) localizes inside Worldwide Categories, and
`Member Assistance` (`LJUMP 1:1:0:0`) localizes inside Worldwide Member
Assistance. The label→command pairing listed above for the two zero-rect
entries is the raw record order from the resource decode; the authoritative
label for each mnid is MOSSHELL's string `0x8E`/`0x8F`, not this list.

## Conclusion

The authoritative HOMEBASE-defined mapping for the visible MSN Central menu is:

- `MSN Today` -> `1:4:0:0`
- `E-Mail` -> `EMAIL`
- `Favorite Places` -> `3:1:0:0`
- `Member Assistance` -> `1:1:0:0`
- `Categories` -> `1:0:0:0`

The visible buttons and the hidden "Worldwide ..." entries deliberately share
two mnids. `LJUMP` enters a hub and localizes; `JUMP` opens the hub itself.
Both hubs are client-pinned special mnids — see the table above and
`docs/MOSSHELL.md` §6.1.1.
