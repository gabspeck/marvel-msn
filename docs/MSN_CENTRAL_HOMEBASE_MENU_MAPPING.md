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

These help explain why the client-side hierarchy can look cross-wired even
before any DIRSRV data is involved:

- `1:0:0:0` is used by `Categories` and also by hidden `Worldwide Member Assistance`
- `1:1:0:0` is used by `Member Assistance` and also by hidden `Worldwide Categories`

## Conclusion

The authoritative HOMEBASE-defined mapping for the visible MSN Central menu is:

- `MSN Today` -> `1:4:0:0`
- `E-Mail` -> `EMAIL`
- `Favorite Places` -> `3:1:0:0`
- `Member Assistance` -> `1:1:0:0`
- `Categories` -> `1:0:0:0`

This mismatch between visible labels and the hidden "Worldwide ..." aliases is
present in the original client-side HOMEBASE resource data. It is not caused by
the DIRSRV server hierarchy.
