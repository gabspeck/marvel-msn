---
name: debugging-with-softice
description: instructions on how to debug using the softice MCP
---

* The SoftICE serial transport base path is `/tmp/win95.com1` — pass that to `mcp__softice__connect`.

* Always use `ADDR <context handle>` to set the correct address context for your breakpoints before arming them, 
otherwise they won't hit

* When you need to set a breakpoint on EXPLORER.EXE, use `ADDR` to disambiguate from the desktop instance. You want the 
one that is hosting the MSN DLLs.

* Always resume CPU execution before handing control of the VM back to the user

* After resuming the CPU post breakpoint arming, use the `wait_for_popup` tool with a timeout of 1 minute and a polling
interval of 500ms to wait for breakpoint hits instead of waiting on the user to report back.

* Do not resort to the raw commands `popup`, `screen`, `raw_cmd`, `send_keys` if there is a tool that covers what you 
need. If you do need to use a raw command, justify it with a terse, one-line justification 

* If the user has indicated that the MSN Client has crashed or the VM has rebooted, do NOT set any breakpoints until
told that the VM is ready for you to do so.
