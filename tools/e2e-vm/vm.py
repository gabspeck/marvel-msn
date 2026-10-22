#!/usr/bin/env python3
"""Windows 95 OSR2 + MSN 1.3 VM for end-to-end testing the server under 86Box.

  vm.py build          download media, install Windows unattended, snapshot the result
  vm.py reset [N ...]  make instance N (default 1) a fresh copy of the snapshot
  vm.py run [-i N]     start 86Box on instance N with the automation socket

Everything lives under $MSN_VM_CACHE (default ~/.cache/marvel-msn-vm):
downloads/ (installation media), iso/ (the CD's WIN95 directory), softice/
(SoftICE files), build/ (scratch), golden/ (pristine VM) and vm/N/ (the
instances that run, side by side). Each build stage is skipped when its
output exists. See docs/E2E-VM.md.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
GUEST = HERE / "guest"

CACHE = Path(os.environ.get("MSN_VM_CACHE", "~/.cache/marvel-msn-vm")).expanduser()
DOWNLOADS = CACHE / "downloads"
SOFTICE = CACHE / "softice"
BUILD = CACHE / "build"
GOLDEN = CACHE / "golden"
VMS = CACHE / "vm"

MEDIA = {
    "W95_FULL_AR.iso": (
        "https://archive.org/download/Windows95-4.00.1111-OSR2/W95_FULL_AR.iso",
        "771d31eb6992abe546af43037b2dbcab",
    ),
    "Windows95b.img": (
        "https://archive.org/download/Windows95OSR2boot/Windows95b.img",
        "0966a429efffba9739991982d15b000f",
    ),
}
# Published with the ISO on its archive.org item. OEM setup ignores a key in
# MSBATCH.INF and stops at the COA page (KB 263281), so it is typed in.
PRODUCT_KEY = "24796-OEM-0014736-66386"

# 1 GiB disk. Cylinders stay below 1024 so the BIOS and DOS see all of it in CHS.
SPT, HEADS, CYLS = 63, 16, 2080
DISK_SECTORS = SPT * HEADS * CYLS
PART_START = SPT

COMPUTER_NAME = "MSNE2E"
PHONE = "05006062"  # mapped to the server's modem port in /phonebook.txt
PTY_LINK = "/tmp/msn-e2e.$PORT.pty"  # $PORT expands to COM1
GOLDEN_MAC = "4d:53:4e"  # 86Box prepends 00:0c:87 for the PCnet

MTOOLS_ENV = {**os.environ, "MTOOLS_SKIP_CHECK": "1"}


def log(msg):
    print(f"[vm] {msg}", flush=True)


def run(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


# --- media ------------------------------------------------------------------


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def fetch():
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    for name, (url, digest) in MEDIA.items():
        dest = DOWNLOADS / name
        if dest.exists():
            continue
        log(f"downloading {url}")
        part = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(url) as r, open(part, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
        if md5(part) != digest:
            part.unlink()
            sys.exit(f"{name}: MD5 mismatch")
        part.rename(dest)


def extract_win95():
    """The CD's WIN95 directory, which setup installs from and keeps as its source."""
    out = CACHE / "iso"
    if not out.exists():
        log("extracting WIN95 from the ISO")
        tmp = out.with_name("iso.tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        run("7z", "x", "-y", f"-o{tmp}", DOWNLOADS / "W95_FULL_AR.iso", "win95/*",
            stdout=subprocess.DEVNULL)
        tmp.rename(out)
    return out / "win95"


def extract_softice(source):
    """SoftICE (DriverStudio build) taken from an existing Win95 VM disk.

    The only SoftICE installer on the Internet Archive (3.2) needs a serial
    number, so the files come from the user's own installation.
    """
    if (SOFTICE / "WINICE.VXD").exists():
        return
    log(f"extracting SoftICE from {source}")
    BUILD.mkdir(parents=True, exist_ok=True)
    raw = BUILD / "softice-source.raw"
    run("qemu-img", "convert", "-O", "raw", source, raw)
    try:
        img = f"{raw}@@{partition_offset(raw)}"
        tmp = SOFTICE.with_name("softice.tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir(parents=True)
        for name in ("WINICE.EXE", "WINICE.VXD", "WINICE.DAT", "SIWVID.386"):
            run("mcopy", "-n", "-i", img, f"::/WINDOWS/{name}", tmp / name, env=MTOOLS_ENV)
        run("mcopy", "-s", "-n", "-i", img, "::/Program Files/SoftIce", tmp, env=MTOOLS_ENV)
        tmp.rename(SOFTICE)
    finally:
        raw.unlink()


def partition_offset(image):
    out = subprocess.run(["sfdisk", "-J", str(image)], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)["partitiontable"]["partitions"][0]["start"] * 512


# --- guest files ------------------------------------------------------------


def dos_text(text):
    return text.replace("\r\n", "\n").replace("\n", "\r\n").encode("latin-1")


def render(name, net, connect_protocol):
    text = (GUEST / name).read_text()
    if name.endswith(".REG"):
        # Win95 REGEDIT has no comment syntax.
        text = "\n".join(line for line in text.splitlines() if not line.startswith(";")) + "\n"
    for key, value in {
        "COMPUTER_NAME": COMPUTER_NAME,
        "HOST_IP": str(net["host"]),
        "PHONE": PHONE,
        "CONNECT_PROTOCOL": f"{connect_protocol:08x}",
    }.items():
        text = text.replace(f"@{key}@", value)
    return dos_text(text)


def mput(img, data, dest):
    tmp = BUILD / "mput.tmp"
    tmp.write_bytes(data)
    run("mcopy", "-o", "-i", img, tmp, dest, env=MTOOLS_ENV)
    tmp.unlink()


def mget(img, src):
    return subprocess.run(["mtype", "-i", img, src], check=True, capture_output=True,
                          env=MTOOLS_ENV).stdout


# --- disk and boot floppy ---------------------------------------------------


def make_disk(net, connect_protocol):
    """Partitioned, FAT16-formatted disk holding the setup source and the staging files.

    The MBR code and the boot sector are left to the boot floppy (FDISK /MBR, SYS C:).
    """
    disk = BUILD / "c.img"
    win95 = extract_win95()
    log("creating the hard disk image")
    BUILD.mkdir(parents=True, exist_ok=True)
    disk.unlink(missing_ok=True)
    with open(disk, "wb") as f:
        f.truncate(DISK_SECTORS * 512)
    part_sectors = DISK_SECTORS - PART_START
    run("sfdisk", "-q", disk, input=f"start={PART_START}, size={part_sectors}, type=6, bootable\n",
        text=True)
    run("mkfs.fat", "-F", "16", "-n", COMPUTER_NAME, "-h", PART_START, "-D", "0x80",
        "--offset", PART_START, disk, part_sectors // 2, stdout=subprocess.DEVNULL)
    img = f"{disk}@@{PART_START * 512}"
    run("mcopy", "-s", "-i", img, win95, "::/WIN95", env=MTOOLS_ENV)
    run("mmd", "-i", img, "::/STAGE", env=MTOOLS_ENV)
    # Not in WIN95: SUWIN ignores the command-line script while the source
    # directory holds an MSBATCH.INF.
    for name in ("MSBATCH.INF", "POST.BAT", "POST.REG"):
        mput(img, render(name, net, connect_protocol), f"::/STAGE/{name}")
    # Runs setup until it has put WIN.COM in place; afterwards setup owns the boot.
    mput(img, dos_text(
        "@ECHO OFF\n"
        "IF EXIST C:\\WINDOWS\\WIN.COM GOTO END\n"
        "ECHO E2E-SETUP-START> COM1\n"
        "C:\\WIN95\\SETUP.EXE C:\\STAGE\\MSBATCH.INF /IS /IQ /ID /IM /IW\n"
        ":END\n"
    ), "::/AUTOEXEC.BAT")
    return disk


def make_floppy():
    floppy = BUILD / "boot.img"
    shutil.copyfile(DOWNLOADS / "Windows95b.img", floppy)
    img = str(floppy)
    mput(img, dos_text("FILES=30\nBUFFERS=20\n"), "::/CONFIG.SYS")
    mput(img, dos_text(
        "@ECHO OFF\n"
        "FDISK /MBR\n"
        "SYS C:\n"
        "ECHO E2E-SYS-DONE> COM1\n"
    ), "::/AUTOEXEC.BAT")
    return floppy


# --- 86Box ------------------------------------------------------------------


def network(bridge):
    out = subprocess.run(["ip", "-j", "-4", "addr", "show", bridge], check=True,
                         capture_output=True, text=True)
    info = json.loads(out.stdout)[0]["addr_info"][0]
    iface = ipaddress.ip_interface(f"{info['local']}/{info['prefixlen']}")
    return {"bridge": bridge, "host": iface.ip}


def config(net, com1, floppy=None):
    """86box.cfg. com1 is 'automation' while building and 'pty' for SoftICE afterwards."""
    if com1 == "automation":
        serial = "[Ports (COM & LPT)]\nserial1_device = automation\n"
    else:
        serial = (
            "[Ports (COM & LPT)]\nserial1_device = stdio\n\n"
            "[Virtual Console (COM) #1]\nmode = 3\n"
            f"command = ln -sf $PTY {PTY_LINK}\n"
        )
    fdd = f"fdd_01_fn = {floppy}\n" if floppy else ""
    return f"""[General]
vid_renderer = qt_software
sound_muted = 1

[Machine]
machine = kn97
cpu_family = pentium2_klamath
cpu_speed = 300000000
cpu_multi = 4.5
cpu_use_dynarec = 1
fpu_type = internal
mem_size = 65536

[Video]
gfxcard = s3_vision968_pci

[Input devices]
keyboard_type = keyboard_ps2
mouse_type = ps2

[Sound]
sndcard = none

[Network]
net_01_card = pcnetfast
net_01_net_type = tap
net_01_host_device = {net["bridge"]}
net_01_link = 0
net_02_card = modem
net_02_net_type = slirp
net_02_link = 0

[AMD PCnet-FAST III #1]
mac = {GOLDEN_MAC}

[Standard Hayes-compliant Modem #2]
port = 1
baudrate = 115200
phonebook_file = {REPO / "phonebook.txt"}

{serial}
[Hard disks]
hdd_01_fn = c.img
hdd_01_ide_channel = 0:0
hdd_01_parameters = {SPT}, {HEADS}, {CYLS}, 0, ide
hdd_01_speed = ramdisk

[Floppy and CD-ROM drives]
fdd_01_type = 35_2hd
fdd_02_type = none
{fdd}"""


def emulator():
    exe = os.environ.get("EMU86BOX") or shutil.which("86Box")
    if not exe:
        sys.exit("86Box not found; set EMU86BOX")
    return exe


def check_tap(exe):
    """86Box opens the guest NIC's TAP device itself, which takes CAP_NET_ADMIN.

    Without it the NIC falls back to no backend: the guest boots, but the TCP
    path to the server is down.
    """
    out = subprocess.run(["getcap", exe], capture_output=True, text=True).stdout
    if "cap_net_admin" not in out:
        log(f"warning: {exe} lacks CAP_NET_ADMIN, so the guest NIC has no link. Fix with:")
        log(f"  sudo setcap cap_net_admin+ep {os.path.realpath(exe)}")


def emulator_env(headless):
    """Qt's offscreen platform: no window; screenshots and automation still work."""
    return {**os.environ, "QT_QPA_PLATFORM": "offscreen"} if headless else os.environ


def launch(vmdir, headless):
    sock = vmdir / "automation.sock"
    sock.unlink(missing_ok=True)
    cmd = [emulator(), "-P", str(vmdir), "-N", "--automation", f"unix:{sock}"]
    env = emulator_env(headless)
    with open(vmdir / "86box.log", "w") as out:
        proc = subprocess.Popen(cmd, env=env, stdout=out, stderr=subprocess.STDOUT)
    for _ in range(300):
        if sock.exists():
            return proc, Automation(sock)
        if proc.poll() is not None:
            sys.exit(f"86Box exited with {proc.returncode}; see {vmdir / '86box.log'}")
        time.sleep(0.1)
    proc.kill()
    sys.exit("86Box did not open the automation socket")


# US layout, set-1 make codes. SHIFTED maps a character to the key it shares.
SCANCODES = {
    **{c: 0x02 + i for i, c in enumerate("1234567890-=")},
    **{c: 0x10 + i for i, c in enumerate("qwertyuiop[]")},
    **{c: 0x1E + i for i, c in enumerate("asdfghjkl;'`")},
    **{c: 0x2B + i for i, c in enumerate("\\zxcvbnm,./")},
    "\t": 0x0F, "\n": 0x1C, " ": 0x39,
}
SHIFTED = dict(zip('!@#$%^&*()_+{}:"~|<>?', "1234567890-=[];'`\\,./", strict=True))


class Automation:
    """Line-oriented client for 86Box's automation socket (doc/specifications/automation.md)."""

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(str(path))
        self.file = self.sock.makefile("rwb")

    def __call__(self, *words):
        self.file.write((" ".join(str(w) for w in words) + "\n").encode())
        self.file.flush()
        line = self.file.readline()
        if not line:
            raise ConnectionError("86Box closed the automation socket")
        reply = json.loads(line)
        if not reply.get("ok"):
            raise RuntimeError(f"{' '.join(map(str, words))}: {reply.get('error')}")
        return reply

    def press(self, *scancodes):
        for code in scancodes:
            self("key", "down", code)
            self("key", "up", code)

    def type(self, text):
        for c in text:
            base = SHIFTED.get(c, c.lower())
            shift = c in SHIFTED or c.isupper()
            if shift:
                self("key", "down", 0x2A)
            self.press(SCANCODES[base])
            if shift:
                self("key", "up", 0x2A)

    def wait_text(self, text, timeout_ms):
        if not self("wait", "text", timeout_ms, text).get("matched"):
            raise TimeoutError(f"{text!r} did not appear on the text screen")

    def wait_serial(self, text, start, timeout_ms, shots=None):
        """Run until COM1 carries text. Saves a screenshot per emulated minute when shots is set."""
        pos, waited = start, 0
        while waited < timeout_ms:
            r = self("wait", "serial", 60000, 1, pos, text)
            if r.get("matched"):
                return r["next"]
            pos, waited = max(pos, r["next"] - len(text)), waited + 60000
            if shots:
                shots.mkdir(parents=True, exist_ok=True)
                self("screenshot", shots / f"{r['ms']:09d}.png")
            log(f"  waiting for {text} ({r['ms'] // 1000} s emulated)")
        raise TimeoutError(f"{text} did not arrive within {timeout_ms // 1000} s")


def read_png(path):
    """(width, rgb rows) of an 8-bit RGB PNG, as 86Box writes its screenshots."""
    data = Path(path).read_bytes()
    pos, idat, width = 8, b"", 0
    while pos < len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width = int.from_bytes(body[:4], "big")
            assert body[8:10] == b"\x08\x02", "expected 8-bit RGB"
        elif kind == b"IDAT":
            idat += body
        pos += 12 + length
    raw, stride, rows, prev = zlib.decompress(idat), width * 3, [], bytearray(width * 3)
    for i in range(0, len(raw), stride + 1):
        ftype, row = raw[i], bytearray(raw[i + 1:i + 1 + stride])
        for x in range(stride):
            a = row[x - 3] if x >= 3 else 0
            b, c = prev[x], prev[x - 3] if x >= 3 else 0
            if ftype == 1:
                row[x] = (row[x] + a) & 0xFF
            elif ftype == 2:
                row[x] = (row[x] + b) & 0xFF
            elif ftype == 3:
                row[x] = (row[x] + (a + b) // 2) & 0xFF
            elif ftype == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                row[x] = (row[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 0xFF
        rows.append(row)
        prev = row
    return width, rows


class Screen:
    """A 640x480 screenshot, for recognising the dialogs that unattended setup still shows.

    Signatures are runs of pixels in a dialog's title bar and edit fields, taken
    from screenshots of this build: they depend on the S3 driver's palette and
    on the dialogs' fixed positions, nothing else.
    """

    def __init__(self, png):
        self.width, self.rows = read_png(png)

    def run(self, y, x0, x1, rgb):
        return self.width == 640 and all(
            tuple(self.rows[y][x * 3:x * 3 + 3]) == rgb for x in range(x0, x1 + 1)
        )


VGA_NAVY, NAVY, WHITE = (0, 0, 170), (0, 0, 129), (255, 255, 255)


def coa_rejected(s):
    """"The Certificate of Authenticity number you entered is not valid" (mini-Windows palette)."""
    return s.run(66, 300, 300, WHITE) and s.run(148, 380, 470, VGA_NAVY) and s.run(162, 380, 470, VGA_NAVY)


def logon_prompt(s):
    """"Enter Windows Password", first boot after the file copy."""
    return s.run(70, 280, 500, NAVY) and s.run(186, 260, 430, WHITE) and s.run(224, 260, 430, WHITE)


def network_logon_prompt(s):
    """"Enter Network Password" for Microsoft Networking, user name filled in."""
    return s.run(88, 250, 510, NAVY) and s.run(171, 300, 455, WHITE) and s.run(201, 245, 455, WHITE)


def password_confirm(s):
    """"Set Windows Password", confirming the blank password."""
    return s.run(170, 280, 450, NAVY) and s.run(261, 280, 380, WHITE) and s.run(291, 280, 380, WHITE)


# --- stages -----------------------------------------------------------------


def setup_bios(vm):
    """First boot on a blank NVR: stop in Award Setup, boot A: before C:, save.

    The defaults boot C: first, and the fresh disk has no MBR code until the
    boot floppy runs FDISK /MBR. Saving also clears the checksum error that
    would otherwise stop every POST at "Press F1".
    """
    log("BIOS setup: boot sequence A,C")
    vm.wait_text("to enter SETUP", 30000)
    for _ in range(80):  # Del is only polled late in POST
        vm.press(0x153)
        if vm("wait", "text", 250, "CMOS SETUP UTILITY").get("matched"):
            break
    else:
        raise TimeoutError("BIOS setup did not open")
    vm.press(0x150, 0x1C)  # BIOS FEATURES SETUP
    vm.wait_text("BIOS FEATURES SETUP", 5000)
    vm.press(*[0x150] * 9, 0x149)  # Boot Sequence, PgUp: C,A -> A,C
    vm.wait_text("Boot Sequence              : A,C ", 5000)
    vm.press(0x01, 0x44)  # Esc, F10
    vm.wait_text("SAVE to CMOS and EXIT", 5000)
    vm.press(0x15, 0x1C)  # Y, Enter


def enter_product_key(vm):
    """Re-enter, then the key; the three boxes advance on their own when full."""
    vm.press(0x1C)
    vm("step", 2000)
    vm.type(PRODUCT_KEY.replace("-OEM-", "").replace("-", ""))
    vm.press(0x1C)


# Dialogs that MSBATCH.INF cannot suppress: (signature, what it is, answer).
PROMPTS = [
    (coa_rejected, "product key", enter_product_key),
    (logon_prompt, "logon as e2e, blank password", lambda vm: vm.type("e2e\n")),
    (network_logon_prompt, "network logon, blank password", lambda vm: vm.press(0x1C)),
    (password_confirm, "blank password confirmation", lambda vm: vm.press(0x1C)),
]


def run_setup(vm, pos, shots):
    """Wait for POST.BAT's signal, answering PROMPTS as they come up."""
    probe = BUILD / "probe.png"
    for tick in range(180 * 6):
        r = vm("wait", "serial", 10000, 1, pos, "E2E-POST-DONE")
        if r.get("matched"):
            return r["next"]
        vm("screenshot", probe)
        screen = Screen(probe)
        for matches, what, answer in PROMPTS:
            if matches(screen):
                log(f"  answering: {what}")
                answer(vm)
                vm("step", 3000)
                break
        if tick % 6 == 5:
            shutil.copyfile(probe, shots / f"{r['ms']:09d}.png")
            log(f"  waiting for E2E-POST-DONE ({r['ms'] // 1000} s emulated)")
    raise TimeoutError("E2E-POST-DONE did not arrive within 3 h emulated")


def shut_down(vm):
    """Start menu, Shut Down, Yes."""
    vm("key", "down", 0x1D)
    vm.press(0x01)
    vm("key", "up", 0x1D)
    vm("step", 2000)
    vm.press(0x16)  # u
    vm("step", 3000)
    vm.press(0x1C)


def install(net, connect_protocol, headless):
    """Unattended Windows setup in build/, ending with the guest shut down."""
    disk = make_disk(net, connect_protocol)
    floppy = make_floppy()
    shutil.rmtree(BUILD / "nvr", ignore_errors=True)
    (BUILD / "86box.cfg").write_text(config(net, "automation", floppy.name))
    proc, vm = launch(BUILD, headless)
    shots = BUILD / "shots"
    shutil.rmtree(shots, ignore_errors=True)
    shots.mkdir()
    try:
        vm("ff", "on")
        setup_bios(vm)
        log("boot floppy: FDISK /MBR, SYS C:")
        pos = vm.wait_serial("E2E-SYS-DONE", 0, 5 * 60000, shots)
        vm("fdd", "eject", 0)
        vm("reset", "hard")
        log("Windows setup (unattended)")
        pos = vm.wait_serial("E2E-SETUP-START", pos, 5 * 60000, shots)
        run_setup(vm, pos, shots)
        # Setup's own RunOnce entries (time zone, control registrations) run after POST.BAT.
        log("post-install registry imported; shutting Windows down")
        vm("step", 60000)
        shut_down(vm)
        vm("step", 60000)
        vm("screenshot", shots / "shutdown.png")
        vm("quit")
    except BaseException:
        proc.kill()
        raise
    proc.wait(30)
    return disk


def local_console(winice_dat):
    """WINICE.DAT with the serial console commands dropped from INIT.

    SoftICE then pops up on the VGA in text mode, where softice.py reads it
    through the automation socket. COM1 keeps its PTY, so typing
    SERIAL VT100 COM1 115200 at the prompt still moves the console there.
    """
    lines = winice_dat.decode("latin-1").splitlines()
    for i, line in enumerate(lines):
        if line.upper().startswith("INIT="):
            cmds = line[len("INIT="):].strip('"').split(";")
            keep = [c for c in cmds if not c.strip().upper().startswith(("SERIAL", "O 3FA"))]
            lines[i] = 'INIT="' + ";".join(keep) + '"'
    return "\r\n".join(lines).encode("latin-1") + b"\r\n"


def finish(disk):
    """Host-side changes to the installed disk: SoftICE, boot options, cleanup."""
    img = f"{disk}@@{PART_START * 512}"
    log("installing SoftICE and boot settings")
    for name in ("WINICE.EXE", "WINICE.VXD", "SIWVID.386"):
        run("mcopy", "-o", "-i", img, SOFTICE / name, f"::/WINDOWS/{name}", env=MTOOLS_ENV)
    mput(img, local_console((SOFTICE / "WINICE.DAT").read_bytes()), "::/WINDOWS/WINICE.DAT")
    run("mcopy", "-s", "-o", "-i", img, SOFTICE / "SoftIce", "::/Program Files", env=MTOOLS_ENV)
    mput(img, dos_text("C:\\WINDOWS\\WINICE.EXE\n"), "::/AUTOEXEC.BAT")
    system_ini = mget(img, "::/WINDOWS/SYSTEM.INI").rstrip(b"\r\n\x1a")
    mput(img, system_ini + dos_text(
        "\n\n[Siwvid]\nVideoManufacturer=ELSA\nVideoBoard=ELSA WINNER 2000PRO\n"
        "VidType=94\nMono=0\nDdraw=0\n"
    ), "::/WINDOWS/SYSTEM.INI")
    mput(img, dos_text((GUEST / "TELEPHON.INI").read_text()), "::/WINDOWS/TELEPHON.INI")
    msdos = mget(img, "::/MSDOS.SYS").decode("latin-1")
    msdos = msdos.replace("[Options]\r\n", "[Options]\r\nBootDelay=0\r\nLogo=0\r\n", 1)
    run("mattrib", "-r", "-s", "-h", "-i", img, "::/MSDOS.SYS", env=MTOOLS_ENV)
    mput(img, msdos.encode("latin-1"), "::/MSDOS.SYS")
    run("mattrib", "+r", "+s", "+h", "-i", img, "::/MSDOS.SYS", env=MTOOLS_ENV)
    run("mdeltree", "-i", img, "::/STAGE", env=MTOOLS_ENV)


def build(args):
    if GOLDEN.exists():
        log(f"{GOLDEN} exists; delete it to rebuild")
    else:
        net = network(args.bridge)
        log(f"MSN gateway {net['host']} on {net['bridge']}")
        check_tap(emulator())
        fetch()
        extract_softice(Path(args.softice_from).expanduser())
        finish(install(net, 0x0A if args.transport == "tcp" else 0, args.headless))
        snapshot(net)
    make_instance(1)


def snapshot(net):
    """Move the finished disk and CMOS into golden/, read-only, with the runtime config."""
    tmp = GOLDEN.with_name("golden.tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    (BUILD / "c.img").rename(tmp / "c.img")
    shutil.copytree(BUILD / "nvr", tmp / "nvr")
    (tmp / "86box.cfg").write_text(config(net, "pty"))
    for f in tmp.rglob("*"):
        if f.is_file():
            f.chmod(0o444)
    tmp.rename(GOLDEN)
    shutil.rmtree(BUILD)
    log(f"golden image in {GOLDEN}")


def instance_dir(n):
    return VMS / str(n)


def make_instance(n):
    """vm/N: a copy of golden/ with its own MAC, NetBIOS name and SoftICE PTY.

    The disk carries C:\\E2E.REG, which AUTOEXEC.BAT imports with real-mode
    REGEDIT and deletes on the first boot, before Windows reads the registry.
    Instances that share a name would collide on the LAN.
    """
    if not GOLDEN.exists():
        sys.exit(f"{GOLDEN} missing; run build")
    if not 1 <= n <= 255:
        sys.exit("instance numbers run from 1 to 255")
    vm = instance_dir(n)
    shutil.rmtree(vm, ignore_errors=True)
    VMS.mkdir(exist_ok=True)
    # Reflink copy: instant on btrfs/XFS, a plain copy elsewhere.
    run("cp", "-a", "--reflink=auto", GOLDEN, vm)
    run("chmod", "-R", "u+w", vm)
    cfg = (vm / "86box.cfg").read_text()
    cfg = cfg.replace(f"mac = {GOLDEN_MAC}", f"mac = {GOLDEN_MAC[:6]}{n:02x}")
    cfg = cfg.replace(PTY_LINK, instance_pty(n))
    (vm / "86box.cfg").write_text(cfg)
    name = f"{COMPUTER_NAME}-{n}"
    img = f"{vm / 'c.img'}@@{PART_START * 512}"
    BUILD.mkdir(exist_ok=True)
    mput(img, dos_text(
        "REGEDIT4\n\n"
        "[HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\control\\ComputerName\\ComputerName]\n"
        f'"ComputerName"="{name}"\n\n'
        "[HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\VxD\\VNETSUP]\n"
        f'"ComputerName"="{name}"\n'
    ), "::/E2E.REG")
    autoexec = mget(img, "::/AUTOEXEC.BAT")
    mput(img, dos_text(
        "@IF EXIST C:\\E2E.REG C:\\WINDOWS\\REGEDIT.EXE /L:C:\\WINDOWS\\SYSTEM.DAT "
        "/R:C:\\WINDOWS\\USER.DAT C:\\E2E.REG\n"
        "@IF EXIST C:\\E2E.REG DEL C:\\E2E.REG\n"
    ) + autoexec, "::/AUTOEXEC.BAT")
    log(f"instance {n} reset from {GOLDEN}: {vm}, {name}, {instance_pty(n).replace('$PORT', 'COM1')}")


def instance_pty(n):
    return PTY_LINK.replace("msn-e2e.", f"msn-e2e-{n}.")


def reset(args):
    for n in args.instances or [1]:
        make_instance(n)


def start(args):
    vm = instance_dir(args.instance)
    if not vm.exists():
        make_instance(args.instance)
    check_tap(emulator())
    cmd = [emulator(), "-P", str(vm), "-N", "-V", f"e2e-{args.instance}",
           "--automation", f"unix:{vm / 'automation.sock'}"]
    if args.held:
        cmd.append("--automation-hold")
    os.execvpe(cmd[0], cmd, emulator_env(args.headless))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build the golden VM (cached) and reset the working copy")
    b.add_argument("--bridge", default="br0", help="host bridge the guest NIC joins (default br0)")
    b.add_argument("--transport", choices=("tcp", "modem"), default="tcp",
                   help="MSN connection the client starts with (default tcp)")
    b.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True,
                   help="run 86Box without a window (default); --no-headless shows it")
    b.add_argument("--softice-from", default="~/86Box VMs/Windows 95 OSR2/c.vhd",
                   help="Win95 disk image with SoftICE installed")
    rs = sub.add_parser("reset", help="make instances fresh copies of the golden image")
    rs.add_argument("instances", nargs="*", type=int, help="instance numbers (default 1)")
    r = sub.add_parser("run", help="start 86Box on an instance, creating it if missing")
    r.add_argument("-i", "--instance", type=int, default=1, help="instance number (default 1)")
    r.add_argument("--held", action="store_true", help="start held (--automation-hold)")
    r.add_argument("--headless", action=argparse.BooleanOptionalAction, default=True,
                   help="run 86Box without a window (default); --no-headless shows it")
    args = p.parse_args()
    {"build": build, "reset": reset, "run": start}[args.cmd](args)


if __name__ == "__main__":
    main()
