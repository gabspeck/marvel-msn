# E2E test VM

Windows 95 OSR2 (4.00.1111) with the OSR2 MSN client (MSN 1.3, OPK2) under
86Box, built unattended by `tools/e2e-vm/vm.py` and driven through 86Box's
automation socket (`86Box/doc/specifications/automation.md`).

```sh
tools/e2e-vm/vm.py build   # everything, cached; under 4 min once media is downloaded
tools/e2e-vm/vm.py reset   # working VM back to the built state
tools/e2e-vm/vm.py run     # 86Box on the working VM, automation socket on
```

`build` and `run` start 86Box headless (Qt `offscreen`); `--no-headless`
shows the window. `run --held` starts the machine held (`--automation-hold`). The socket is
`unix:~/.cache/marvel-msn-vm/vm/automation.sock`.

## Cache

`$MSN_VM_CACHE`, default `~/.cache/marvel-msn-vm`:

| Path | Content |
|---|---|
| `downloads/` | `W95_FULL_AR.iso` (archive.org `Windows95-4.00.1111-OSR2`), `Windows95b.img` (OSR2 boot floppy, `Windows95OSR2boot`), MD5-checked |
| `iso/win95/` | the CD's `WIN95` directory, copied to `C:\WIN95` as setup's source |
| `softice/` | SoftICE runtime files (see below) |
| `golden/` | the built VM: `c.img`, `nvr/`, `86box.cfg`; files read-only |
| `vm/` | the working copy `run` boots |

`build` skips every stage whose output exists; delete `golden/` to rebuild
the VM. `reset` copies `golden/` with `cp --reflink=auto`, which is instant on
btrfs. The disk is a 1 GiB sparse raw image (CHS 2080/16/63, FAT16).

## Machine

| Part | Choice | Why |
|---|---|---|
| Board | ASUS KN97 (`kn97`), i440FX/PIIX3 | OSR2 has drivers for every PIIX3 function; PIIX4 boards leave unknown devices that prompt at boot |
| CPU | Pentium II Klamath 300, dynarec | KN97 accepts 2.8–3.5 V parts only, so Deschutes and Mendocino are refused (86Box falls back to a Pentium Pro 90) |
| RAM | 64 MB | |
| Video | S3 Vision968 PCI | OSR2 in-box driver; matches SoftICE's `[Siwvid]` settings |
| HDD | IDE, speed `ramdisk` | |
| NIC | PCnet-FAST III, TAP on `br0` | in-box `NETAMD.INF` |
| COM1 | 86Box virtual console, PTY linked at `/tmp/msn-e2e.COM1.pty` | optional SoftICE serial console |
| COM2 | Hayes modem, phonebook `/phonebook.txt` | MSN dial-up |
| Sound | none | |

Measured at 100 % speed in real time on an Intel Core Ultra 7 356H.

## Connecting to the server

TCP: `PrimaryMSNGateway`/`BackupMSNGateway` are `br0`'s host address, and
ENGCT dials it on 569, which the host redirects to `GATEWAY_PORT` 5690 (see
`TCP-TRANSPORT.md` §4). The guest takes its address from DHCP on `br0`.
86Box opens the TAP device itself and needs `CAP_NET_ADMIN`; without it the
NIC has no link and only dial-up works. `build` and `run` warn when the
capability is missing:

```sh
sudo setcap cap_net_admin+ep "$(realpath ~/.local/bin/86Box)"
```

Dial-up: the client dials `05006062`; `/phonebook.txt` maps it to
`localhost:2323`.

The VM starts on TCP (`ConnectProtocol` 0x0a). Sign In → Settings switches
between "Connect using my local area network" and "MSN is my dial-up
Internet access provider"; `build --transport modem` builds a modem-first
image. Both sides are preset as on the reference VM: service type "MSN
only", Standard Modem on COM2, default dialing location.

Windows logs on as `e2e` with a blank password and does not prompt. `C:` is
shared read/write without a password under NetBIOS name `MSNE2E`.

## SoftICE

The only SoftICE installer on the Internet Archive (NuMega SoftICE 3.2) asks
for a serial number, so `build` copies the runtime out of an existing VM
disk (`--softice-from`, default `~/86Box VMs/Windows 95 OSR2/c.vhd`):
`WINICE.EXE`, `WINICE.VXD`, `WINICE.DAT`, `SIWVID.386` and
`Program Files\SoftIce` (DriverStudio build, 2002). `AUTOEXEC.BAT` loads
`WINICE.EXE`.

The console is the local display: `build` drops the `SERIAL` commands from
`WINICE.DAT`'s `INIT`. `tools/e2e-vm/softice.py` drives it through the
automation socket:

```sh
tools/e2e-vm/softice.py cmd "bpx CreateProcessA" "bl"   # pops SoftICE up first
tools/e2e-vm/softice.py resume
tools/e2e-vm/softice.py wait 30                          # until a breakpoint pops it up
tools/e2e-vm/softice.py screen
```

From Python, `SoftIce(Automation(sock))` has the same operations; the socket
takes one client at a time.

When SoftICE pops up it puts the S3 card into 80x25 text mode itself, while
the BIOS data area keeps Windows' mode 0x69, so the automation `text` and
`wait text` commands refuse it. `softice.py` reads the buffer at `0xB8000`
with `memr`, types with `key`, and detects the prompt with `wait mem` on the
status line ("Enter a command" from column 5 of row 25, attribute 0x30).
`status` reports 720x400 while SoftICE has the screen and 640x480 under
Windows. Commands that open an editor (`R`, `E` without data) do not return to
the prompt; Esc leaves them.

COM1 keeps its PTY at `/tmp/msn-e2e.COM1.pty`: `SERIAL VT100 COM1 115200` at
the prompt moves the console there, `SERIAL OFF` brings it back. A bare
`SERIAL ON` selects the `SERIAL.EXE` remote protocol and fails to attach.

## How the build works

1. Host: partition and format the disk (FAT16), copy `WIN95`, stage
   `C:\STAGE\{MSBATCH.INF,POST.BAT,POST.REG}` and an `AUTOEXEC.BAT` that runs
   `SETUP.EXE C:\STAGE\MSBATCH.INF /IS /IQ /ID /IM /IW` until `WIN.COM` exists.
2. First boot, from the floppy: Award Setup is entered once to set the boot
   order to A,C (the default C,A executes the blank MBR) and to save CMOS,
   which clears the checksum error that otherwise stops POST at F1. The
   floppy's `AUTOEXEC.BAT` runs `FDISK /MBR` and `SYS C:`.
3. Windows setup, unattended. Three dialogs still appear and are answered
   from screenshots: the OEM product key, the first logon, and the blank
   password confirmation.
4. First logon: `POST.BAT` runs from `RunOnce`, imports `POST.REG` and writes
   `E2E-POST-DONE` to COM1. The builder waits a minute for setup's own
   `RunOnce` entries, then shuts Windows down from the Start menu.
5. Host: SoftICE files with a local-console `WINICE.DAT`, `[Siwvid]` in
   `SYSTEM.INI`, `TELEPHON.INI` (one dialing location, so TAPI never asks for
   an area code), `BootDelay=0` and `Logo=0` in `MSDOS.SYS`; `C:\STAGE` is
   removed.

COM1 is the automation backend during the build: guest batch files report
progress with `ECHO ...> COM1` and the builder waits with `wait serial`.

### Setup behaviour found on the way

- SUWIN ignores the command-line script while the source directory holds a
  file named `MSBATCH.INF`, and accepts it elsewhere (`Batchfile=` appears in
  `SETUPLOG.TXT` only then).
- An OEM CD stops at the Certificate of Authenticity page under MSBATCH and
  rejects the key until it is typed again (KB 263281, by design). The three
  boxes advance on their own when full. The key is the one published with
  the ISO on archive.org.
- The PCI NIC is found by PnP after the first reboot and its TCP/IP binding
  takes the defaults, so `[MSTCP]` static values land on the Dial-Up
  Adapter's binding instead. DHCP is used, with `VxD\DHCP\PopupFlag` cleared
  so a missing lease does not prompt. That key needs `Version`=1 as well:
  VDHCP takes a pre-existing key without it as configured and never asks for
  a lease (observed: no frames from the guest until `Version` was added).
- With Client for Microsoft Networks as primary logon, Windows asks for the
  network password on every boot once the NIC has a link. `POST.REG` sets
  `HKLM\Network\Logon\PrimaryProvider=""`, which is what the Network control
  panel writes for "Windows Logon"; with a blank password that never prompts.
  The value set from `MSBATCH.INF` is overwritten when PnP installs the NIC,
  so the build still answers the prompt once.
- MSN needs Windows Messaging, whose Inbox Setup Wizard is queued as
  `RunOnce` and `RunOnce\Setup` values named "Windows Messaging";
  `MSBATCH.INF` deletes both.
- MSN's desktop icon opens the first-run wizard (`MSNSIG13.EXE`) until
  `HKLM\SOFTWARE\Microsoft\MOS\SoftwareInstalled` exists, and the wizard
  rewrites the connection settings. `POST.REG` creates the key.
