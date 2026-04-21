Guidelines
===

Debugging
---
* Always check for the correct `ADDR` context on SoftIce before setting a breakpoint. Most of them will be set on the
EXPLORER.EXE instance that hosts MOSSHELL.DLL.

Searching for resources
---
* Use `strings -fel *` in the `binaries` directory a resource string comes from, then  with the filename, look it up in
Ghidra to have the exact source and trace its usage.

Tracing MSN Client errors
---
* Errors are not rendered with MessageBoxA, but with a custom procedure ReportMosXErrX exported by MOSSHELL.DLL
