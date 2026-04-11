"""
GDB script: watch g_cOpenSessions and sign-out flow in GUIDE.EXE / MCM.DLL

Usage (inside 86Box GDB):
  source /path/to/watch_signout.py

Watches:
  - g_cOpenSessions (MCM.DLL 0x0410c028) — increment/decrement
  - CleanupThread entry (GUIDE.EXE 0x043016b3)
  - DisconnectAndCleanup entry (GUIDE.EXE 0x043015e8)
  - WndProc WM_USER handler (DestroyWindow path)
"""

import gdb

G_COPEN_SESSIONS = 0x0410c028
CLEANUP_THREAD   = 0x043016b3
DISCONNECT_FUNC  = 0x043015e8
WNDPROC_WM_USER  = 0x04301934  # JMP to DestroyWindow in WndProc

class WatchSessionCounter(gdb.Breakpoint):
    """Hardware watchpoint on g_cOpenSessions."""
    def __init__(self):
        # Use awatch to catch both reads and writes — but hw watchpoint is better
        # We'll use a software approach: break at the InterlockedIncrement/Decrement sites
        pass

class BreakIncrementSession(gdb.Breakpoint):
    """Break at InterlockedIncrement(&g_cOpenSessions) in FMCMOpenSession."""
    def __init__(self):
        super().__init__("*0x04101395", internal=False)
        self.silent = True
    def stop(self):
        val = int(gdb.parse_and_eval(f"*(int*){G_COPEN_SESSIONS}"))
        print(f"[SIGNOUT] FMCMOpenSession: InterlockedIncrement(&g_cOpenSessions) — current value: {val} (will become {val+1})")
        # Print caller
        frame = gdb.newest_frame()
        if frame and frame.older():
            caller = frame.older()
            print(f"[SIGNOUT]   caller: {caller.pc():#x}")
        return False  # don't stop

class BreakDecrementSession(gdb.Breakpoint):
    """Break at InterlockedDecrement(&g_cOpenSessions) in MCMCloseSession offline path."""
    def __init__(self):
        super().__init__("*0x04101423", internal=False)
        self.silent = True
    def stop(self):
        val = int(gdb.parse_and_eval(f"*(int*){G_COPEN_SESSIONS}"))
        print(f"[SIGNOUT] MCMCloseSession(offline): InterlockedDecrement(&g_cOpenSessions) — current value: {val} (will become {val-1})")
        return False

class BreakDecrementProcessDeath(gdb.Breakpoint):
    """Break at InterlockedDecrement in CleanupProcessSessions (FUN_043057d8).
    At 0x0430582e: MOV EAX, [0x0430b568]  ; load &g_cOpenSessions
    At 0x04305834: CALL InterlockedDecrement"""
    def __init__(self):
        super().__init__("*0x04305834", internal=False)
        self.silent = True
    def stop(self):
        val = int(gdb.parse_and_eval(f"*(int*){G_COPEN_SESSIONS}"))
        print(f"[SIGNOUT] CleanupProcessSessions: InterlockedDecrement — current value: {val} (will become {val-1})")
        return False

class BreakCleanupThread(gdb.Breakpoint):
    """Break when cleanup thread starts."""
    def __init__(self):
        super().__init__(f"*{CLEANUP_THREAD:#x}", internal=False)
        self.silent = True
    def stop(self):
        val = int(gdb.parse_and_eval(f"*(int*){G_COPEN_SESSIONS}"))
        print(f"[SIGNOUT] CleanupThread entered! g_cOpenSessions = {val}")
        if val == 0:
            print(f"[SIGNOUT]   Counter is 0 — will post WM_USER immediately")
        else:
            print(f"[SIGNOUT]   Counter > 0 — will poll until 0")
        return True  # STOP here so we can inspect

class BreakDisconnect(gdb.Breakpoint):
    """Break at DisconnectAndCleanup (FUN_043015e8)."""
    def __init__(self):
        super().__init__(f"*{DISCONNECT_FUNC:#x}", internal=False)
        self.silent = True
    def stop(self):
        # The hidden parameter is at [ESP+4] (first arg, cdecl)
        esp = int(gdb.parse_and_eval("$esp"))
        # After CALL, return address is at ESP, param at ESP+4
        ret_addr = int(gdb.parse_and_eval(f"*(int*){esp}"))
        param = int(gdb.parse_and_eval(f"*(int*){esp + 4}"))
        val = int(gdb.parse_and_eval(f"*(int*){G_COPEN_SESSIONS}"))
        print(f"[SIGNOUT] DisconnectAndCleanup(spawn_thread={param}) called from {ret_addr:#x}")
        print(f"[SIGNOUT]   g_cOpenSessions = {val}")
        return False

class BreakWmUser(gdb.Breakpoint):
    """Break when WM_USER triggers DestroyWindow."""
    def __init__(self):
        super().__init__(f"*{WNDPROC_WM_USER:#x}", internal=False)
        self.silent = True
    def stop(self):
        print(f"[SIGNOUT] WM_USER received — about to DestroyWindow!")
        return True  # STOP

def check_sessions():
    """Print current g_cOpenSessions value."""
    try:
        val = int(gdb.parse_and_eval(f"*(int*){G_COPEN_SESSIONS}"))
        print(f"[SIGNOUT] g_cOpenSessions = {val}")
    except gdb.error as e:
        print(f"[SIGNOUT] Cannot read g_cOpenSessions: {e}")

def setup():
    print("[SIGNOUT] Setting up sign-out monitoring breakpoints...")
    try:
        BreakIncrementSession()
        print("[SIGNOUT]   - FMCMOpenSession increment @ 0x04101395")
    except Exception as e:
        print(f"[SIGNOUT]   - FMCMOpenSession increment FAILED: {e}")

    try:
        BreakDecrementSession()
        print("[SIGNOUT]   - MCMCloseSession decrement @ 0x04101423")
    except Exception as e:
        print(f"[SIGNOUT]   - MCMCloseSession decrement FAILED: {e}")

    try:
        BreakCleanupThread()
        print("[SIGNOUT]   - CleanupThread entry @ 0x043016b3")
    except Exception as e:
        print(f"[SIGNOUT]   - CleanupThread FAILED: {e}")

    try:
        BreakDisconnect()
        print("[SIGNOUT]   - DisconnectAndCleanup @ 0x043015e8")
    except Exception as e:
        print(f"[SIGNOUT]   - DisconnectAndCleanup FAILED: {e}")

    try:
        BreakDecrementProcessDeath()
        print("[SIGNOUT]   - CleanupProcessSessions decrement @ 0x04305834")
    except Exception as e:
        print(f"[SIGNOUT]   - CleanupProcessSessions decrement FAILED: {e}")

    try:
        BreakWmUser()
        print("[SIGNOUT]   - WM_USER handler @ 0x04301934")
    except Exception as e:
        print(f"[SIGNOUT]   - WM_USER handler FAILED: {e}")

    print("[SIGNOUT] Ready. Login, then sign out. Use 'check_sessions' to print counter.")
    print("[SIGNOUT] The script will STOP at CleanupThread and WM_USER for inspection.")

# Register convenience command
class CheckSessionsCmd(gdb.Command):
    """Print g_cOpenSessions value."""
    def __init__(self):
        super().__init__("check_sessions", gdb.COMMAND_USER)
    def invoke(self, arg, from_tty):
        check_sessions()

CheckSessionsCmd()
setup()
