#!/usr/bin/env python3
"""GDB stub client for 86Box MSN95 reverse engineering.

Connects to the 86Box GDB stub and provides commands for
setting breakpoints, reading registers/memory, and stepping.
"""

import socket
import struct
import sys
import time

class GDBClient:
    # x86 register indices (GDB standard i386 ordering)
    REG_NAMES = [
        'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',  # 0-7
        'eip', 'eflags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs',      # 8-15
    ]

    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.sock = None
        self._buf = b''

    def connect(self):
        self.sock = socket.socket()
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        self._buf = b''
        # Give stub time to process connection and pause CPU
        time.sleep(0.3)
        # Prime the response_event — 86Box gdbstub creates events as
        # non-signaled but waits on response_event before processing the
        # first command. Sending + signals it via the ack path.
        self.sock.send(b'+')
        time.sleep(0.1)

    def disconnect(self, resume=True):
        # 86Box's gdb stub deadlocks if we send `D` (detach): it neither
        # clears BPs nor reliably triggers client cleanup, and the stub's
        # event loop runs *inside* the CPU tick — so if D leaves CPU
        # paused, no new commands can land and sockets stack up in
        # CLOSE-WAIT.  The right shutdown is `c` (or nothing) + socket
        # close; the stub auto-resumes when the last client disappears.
        if self.sock:
            try:
                if resume:
                    self._send_packet('c')
                    time.sleep(0.1)
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    def _checksum(self, data):
        return sum(data.encode()) & 0xff

    def _send_packet(self, cmd):
        cs = self._checksum(cmd)
        pkt = ('$' + cmd + '#%02x' % cs).encode()
        self.sock.send(pkt)

    def _recv_bytes(self, timeout=5):
        """Receive available bytes."""
        self.sock.settimeout(timeout)
        try:
            return self.sock.recv(4096)
        except (socket.timeout, BlockingIOError):
            return b''

    def _recv_packet(self, timeout=5):
        """Receive a complete $data#XX packet. Returns the data portion."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            chunk = self._recv_bytes(timeout=remaining)
            if chunk:
                self._buf += chunk
            # Try to extract a packet from buffer
            buf_str = self._buf.decode('latin-1', errors='replace')
            dollar = buf_str.find('$')
            if dollar >= 0:
                hash_pos = buf_str.find('#', dollar + 1)
                if hash_pos >= 0 and hash_pos + 2 < len(buf_str):
                    # Complete packet found
                    data = buf_str[dollar+1:hash_pos]
                    self._buf = self._buf[hash_pos+3:]
                    return data
        return ''

    def _drain_acks(self):
        """Consume any pending + or - acks from the buffer."""
        while self._buf and self._buf[0:1] in (b'+', b'-'):
            self._buf = self._buf[1:]

    def _send_and_recv(self, cmd, timeout=5):
        """Send a command and receive the response.
        Protocol: we send $cmd#XX, stub sends + (ack), then $response#XX.
        We then send + to ack the response.
        """
        self._send_packet(cmd)
        # Wait for ack (+) and response packet
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.1, deadline - time.time())
            chunk = self._recv_bytes(timeout=remaining)
            if chunk:
                self._buf += chunk
            self._drain_acks()
            # Try to extract response packet
            buf_str = self._buf.decode('latin-1', errors='replace')
            dollar = buf_str.find('$')
            if dollar >= 0:
                hash_pos = buf_str.find('#', dollar + 1)
                if hash_pos >= 0 and hash_pos + 2 < len(buf_str):
                    data = buf_str[dollar+1:hash_pos]
                    self._buf = self._buf[hash_pos+3:]
                    # Ack the response
                    self.sock.send(b'+')
                    return data
        return ''

    def _parse_t_packet(self, data):
        """Parse a T-packet stop reason into signal + registers."""
        if not data.startswith('T'):
            return None
        signal = int(data[1:3], 16)
        regs = {}
        parts = data[3:].rstrip(';').split(';')
        for part in parts:
            if ':' in part:
                key, val = part.split(':', 1)
                if key in ('swbreak', 'hwbreak'):
                    regs[key] = True
                else:
                    try:
                        idx = int(key, 16)
                        # Values are little-endian hex bytes
                        raw_bytes = bytes.fromhex(val)
                        if len(raw_bytes) == 4:
                            regs[idx] = struct.unpack('<I', raw_bytes)[0]
                        elif len(raw_bytes) == 2:
                            regs[idx] = struct.unpack('<H', raw_bytes)[0]
                        else:
                            regs[idx] = raw_bytes
                    except (ValueError, struct.error):
                        pass
        return signal, regs

    def _parse_registers(self, hex_data):
        """Parse a 'g' response (all registers concatenated as LE hex)."""
        regs = {}
        # First 16 registers are 32-bit (eax..gs = 4 bytes each = 8 hex chars)
        for i in range(min(16, len(hex_data) // 8)):
            raw = bytes.fromhex(hex_data[i*8:(i+1)*8])
            val = struct.unpack('<I', raw)[0]
            regs[i] = val
        return regs

    def halt_reason(self):
        """Query halt reason (? command)."""
        resp = self._send_and_recv('?')
        if resp and resp.startswith('T'):
            return self._parse_t_packet(resp)
        return resp

    def read_registers(self):
        """Read all registers."""
        resp = self._send_and_recv('g')
        if resp and resp.startswith('T'):
            # Got a T-packet (stop reason) instead of register dump
            _, regs = self._parse_t_packet(resp)
            return regs
        elif resp:
            return self._parse_registers(resp)
        return {}

    def read_register(self, idx):
        """Read a single register by index."""
        resp = self._send_and_recv('p%x' % idx)
        if resp:
            raw = bytes.fromhex(resp)
            if len(raw) == 4:
                return struct.unpack('<I', raw)[0]
            elif len(raw) == 2:
                return struct.unpack('<H', raw)[0]
        return None

    def write_register(self, idx, value):
        """Write a single register."""
        val_hex = struct.pack('<I', value).hex()
        resp = self._send_and_recv('P%x=%s' % (idx, val_hex))
        return resp == 'OK'

    def read_memory(self, addr, length):
        """Read memory at addr for length bytes."""
        resp = self._send_and_recv('m%x,%x' % (addr, length))
        if resp and resp.startswith('E'):
            return None
        if resp:
            return bytes.fromhex(resp)
        return None

    def read_dword(self, addr):
        """Read a 32-bit value from memory."""
        data = self.read_memory(addr, 4)
        if data and len(data) == 4:
            return struct.unpack('<I', data)[0]
        return None

    def set_hw_breakpoint(self, addr):
        """Set a hardware breakpoint."""
        resp = self._send_and_recv('Z1,%x,1' % addr)
        if resp != 'OK':
            print(f"  [Z1] 0x{addr:08x} response: '{resp}' (expected 'OK')", flush=True)
        return resp == 'OK'

    def remove_hw_breakpoint(self, addr):
        """Remove a hardware breakpoint."""
        resp = self._send_and_recv('z1,%x,1' % addr)
        return resp == 'OK'

    def set_sw_breakpoint(self, addr):
        """Set a software breakpoint."""
        resp = self._send_and_recv('Z0,%x,1' % addr)
        if resp != 'OK':
            print(f"  [Z0] 0x{addr:08x} response: '{resp}' (expected 'OK')", flush=True)
        return resp == 'OK'

    def remove_sw_breakpoint(self, addr):
        """Remove a software breakpoint."""
        resp = self._send_and_recv('z0,%x,1' % addr)
        return resp == 'OK'

    def set_write_watchpoint(self, addr, length=4):
        """Set a write watchpoint."""
        resp = self._send_and_recv('Z2,%x,%x' % (addr, length))
        return resp == 'OK'

    def continue_exec(self):
        """Resume execution. Returns when a breakpoint hits."""
        self._send_packet('c')
        # Don't try to receive immediately - we need to wait for stop

    def step(self):
        """Single step. Returns stop info."""
        self._send_packet('s')
        return self.wait_for_stop(timeout=10)

    def wait_for_stop(self, timeout=60):
        """Wait for the target to stop (breakpoint hit, etc)."""
        resp = self._recv_packet(timeout=timeout)
        if resp and resp.startswith('T'):
            self.sock.send(b'+')
            return self._parse_t_packet(resp)
        return None

    def send_break(self):
        """Send break signal (Ctrl+C) to pause execution."""
        self.sock.send(b'\x03')
        return self.wait_for_stop(timeout=5)

    def print_registers(self, regs=None):
        """Pretty-print registers."""
        if regs is None:
            regs = self.read_registers()
        for i, name in enumerate(self.REG_NAMES):
            if i in regs:
                val = regs[i]
                if isinstance(val, int):
                    print(f"  {name:8s} = 0x{val:08x}", end='')
                    if i % 4 == 3:
                        print()
            if i == 7 and i % 4 != 3:
                print()
        if 8 in regs:
            print()
            eip = regs.get(8, 0)
            cs_val = regs.get(10, 0)
            print(f"  eip      = 0x{eip:08x}  (cs=0x{cs_val:04x})")
        print()


def print_help():
    print("""Usage: python3 gdb_debug.py <command> [args...]

Commands:
  status          Connect, read registers, disconnect
  break           Send break signal, show where CPU stopped
  resume          Resume CPU execution
  bp <addr>       Set hardware breakpoint (hex addr, e.g. 0460263F)
  bps <addr>      Set software breakpoint
  bpd <addr>      Remove hardware breakpoint
  watch <addr> [len] Set write watchpoint (default 4 bytes)
  mem <addr> <n>  Read n bytes at addr (hex)
  dword <addr>    Read 32-bit value at addr
  run-to <addr>   Set HW breakpoint, resume, wait for hit
  wait [timeout]  Wait for breakpoint hit (default 60s)
  regs            Read and print registers
""")


def main():
    if len(sys.argv) < 2:
        print_help()
        return

    cmd = sys.argv[1]
    gdb = GDBClient()

    try:
        gdb.connect()

        if cmd == 'status':
            regs = gdb.read_registers()
            gdb.print_registers(regs)

        elif cmd == 'break':
            result = gdb.send_break()
            if result:
                sig, regs = result
                print(f"Stopped (signal {sig})")
                gdb.print_registers(regs)
            else:
                print("No response to break")

        elif cmd == 'resume':
            gdb.continue_exec()
            print("CPU resumed")

        elif cmd == 'bp' and len(sys.argv) >= 3:
            addr = int(sys.argv[2], 16)
            ok = gdb.set_hw_breakpoint(addr)
            print(f"HW breakpoint at 0x{addr:08x}: {'OK' if ok else 'FAILED'}")

        elif cmd == 'bps' and len(sys.argv) >= 3:
            addr = int(sys.argv[2], 16)
            ok = gdb.set_sw_breakpoint(addr)
            print(f"SW breakpoint at 0x{addr:08x}: {'OK' if ok else 'FAILED'}")

        elif cmd == 'bpd' and len(sys.argv) >= 3:
            addr = int(sys.argv[2], 16)
            ok = gdb.remove_hw_breakpoint(addr)
            print(f"Remove HW bp at 0x{addr:08x}: {'OK' if ok else 'FAILED'}")

        elif cmd == 'watch' and len(sys.argv) >= 3:
            addr = int(sys.argv[2], 16)
            length = int(sys.argv[3], 0) if len(sys.argv) >= 4 else 4
            ok = gdb.set_write_watchpoint(addr, length)
            print(f"Write watchpoint at 0x{addr:08x} len={length}: {'OK' if ok else 'FAILED'}")

        elif cmd == 'mem' and len(sys.argv) >= 4:
            addr = int(sys.argv[2], 16)
            length = int(sys.argv[3], 0)
            data = gdb.read_memory(addr, length)
            if data:
                for i in range(0, len(data), 16):
                    hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
                    print(f"  {addr+i:08x}: {hex_part:<48s} {ascii_part}")
            else:
                print("Memory read failed")

        elif cmd == 'dword' and len(sys.argv) >= 3:
            addr = int(sys.argv[2], 16)
            val = gdb.read_dword(addr)
            if val is not None:
                print(f"  [{addr:08x}] = 0x{val:08x}")
            else:
                print("Read failed")

        elif cmd == 'run-to' and len(sys.argv) >= 3:
            addr = int(sys.argv[2], 16)
            ok = gdb.set_hw_breakpoint(addr)
            if not ok:
                print(f"Failed to set breakpoint at 0x{addr:08x}")
                return
            print(f"HW breakpoint set at 0x{addr:08x}, resuming...")
            gdb.continue_exec()
            timeout = int(sys.argv[3]) if len(sys.argv) >= 4 else 60
            result = gdb.wait_for_stop(timeout=timeout)
            if result:
                sig, regs = result
                eip = regs.get(8, 0)
                print(f"Stopped at EIP=0x{eip:08x} (signal {sig})")
                gdb.print_registers(regs)
            else:
                print(f"Timed out after {timeout}s")
            gdb.remove_hw_breakpoint(addr)

        elif cmd == 'wait':
            timeout = int(sys.argv[2]) if len(sys.argv) >= 3 else 60
            print(f"Waiting for breakpoint (timeout {timeout}s)...")
            result = gdb.wait_for_stop(timeout=timeout)
            if result:
                sig, regs = result
                eip = regs.get(8, 0)
                print(f"Stopped at EIP=0x{eip:08x} (signal {sig})")
                gdb.print_registers(regs)
            else:
                print("Timed out")

        elif cmd == 'regs':
            regs = gdb.read_registers()
            gdb.print_registers(regs)

        else:
            print_help()

        gdb.disconnect()

    except ConnectionRefusedError:
        print("Connection refused — is 86Box running with GDB stub?")
    except Exception as e:
        print(f"Error: {e}")
        try:
            gdb.disconnect()
        except:
            pass

if __name__ == '__main__':
    main()
