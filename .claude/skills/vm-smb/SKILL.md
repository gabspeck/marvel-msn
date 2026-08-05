---
name: vm-smb
description: Read and write files inside the 86Box Windows 95 VM over SMB — list shares, pull MSN client binaries, copy files in or out, inspect the Win95 filesystem. Use when the user asks to fetch a DLL/OCX/INI from the VM, copy something into the VM, check what is on the Win95 disk, or refresh a binary before a Ghidra pass.
version: 1.0.0
---

# vm-smb

File transfer between the host and the 86Box Windows 95 VM. The VM shares its
whole `C:` drive with no password. Use this instead of shutting the VM down or
mounting the disk image.

## The host

| Field | Value |
|---|---|
| NetBIOS name | `86BOXW95` |
| IP at last check | `192.168.1.120` |
| Workgroup | `WORKGROUP` |
| MAC | `00-0C-87-53-55-C8` |

The name resolves two ways: an entry in DNS or `/etc/hosts`, and NetBIOS
broadcast. Use the name, never a hard-coded IP. If the name stops resolving,
run `nmblookup 86BOXW95` to find the current address.

## Four constraints that break plain smbclient

1. **Port 139 only.** Port 445 is closed. Windows 95 predates SMB over TCP.
2. **The NetBIOS name is mandatory.** Given an IP, `smbclient` sends the called
   name `*SMBSERVER`. Windows 95 rejects it with
   `NT_STATUS_RESOURCE_NAME_NOT_FOUND`. Pass `86BOXW95` and put an IP in `-I`
   only when the name does not resolve.
3. **SMB1 with LANMAN auth.** Modern Samba disables both by default. The
   protocol and auth options are required, not optional.
4. **Server-side `cd` does not work.** Every `cd` returns
   `NT_STATUS_UNSUCCESSFUL`, including short 8.3 names. Pass the full
   backslash path as an argument to `ls`, `get`, or `put` instead.

## Commands

```
.claude/skills/vm-smb/scripts/vm-smb.fish <command> [args]
```

- `shares` — list the shares.
- `ls [mask]` — list a path. A directory needs a trailing `\*`. Default is the
  share root.
- `get <remote> [local]` — download one file. The local name defaults to the
  remote basename.
- `put <local> <remote>` — upload one file.
- `pull <remotedir> <localdir>` — download a whole tree through smbclient tar
  mode. This is the only reliable way to copy a directory.
- `del <remote>` — delete one file.
- `sh <cmds>` — raw `-c` passthrough for anything the wrappers do not cover.

Examples:

```fish
.claude/skills/vm-smb/scripts/vm-smb.fish ls 'Program Files\The Microsoft Network\*'
.claude/skills/vm-smb/scripts/vm-smb.fish get 'WINDOWS\SYSTEM\MOSCP.EXE' binaries/MOSCP.EXE
.claude/skills/vm-smb/scripts/vm-smb.fish pull 'Program Files\The Microsoft Network' /tmp/msn
```

Env overrides: `VM_HOST` (NetBIOS name), `VM_IP` (adds `-I`), `VM_SHARE`
(default `C`).

## Shares

- `C` — the Win95 system drive. Read and write, no password.
- `D` — the Visual C++ / MSDN CD-ROM. Read-only content.
- `IPC$` — no file content.

## Paths worth knowing

- `Program Files\The Microsoft Network` — the MSN client binaries. 62 files,
  about 2.6 MB. This is the source for every DLL and OCX the project reverse
  engineers. Locale variants exist as `.de`, `.pt`, and `.pt-br` siblings.
- `WINDOWS\SYSTEM` — system DLLs.
- `WINDOWS\WIN.INI`, `AUTOEXEC.BAT`, `CONFIG.SYS` — machine configuration.

Most MSN files carry the hidden attribute. `smbclient` lists them anyway.

## Troubleshooting

- **`NT_STATUS_RESOURCE_NAME_NOT_FOUND`** — you passed an IP where the name
  belongs. See constraint 2.
- **`NT_STATUS_UNSUCCESSFUL` on a `cd`** — expected. Use a full path argument.
- **`Error opening local file <remote path>`** on `mget` — `mget` recreates the
  remote path under the local directory, and it does not create the parent
  directories. Use `pull` instead.
- **Connection fails and ping succeeds** — check that the VM finished booting.
  The file server service registers NetBIOS name `86BOXW95<20>`. Confirm it
  with `nmblookup -A 192.168.1.120`.

## Don't

- Do not write to `C` while the Win95 client is running against a file you are
  replacing. Close the client first.
- Do not edit the 86Box disk image on the host while the VM is running.
- Do not drop the protocol or auth options to shorten a command. Every one of
  them is load-bearing.
