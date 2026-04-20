Guidelines
===

Searching for resources
---
* Use `strings -fel *` in the `binaries` directory a resource string comes from, then  with the filename, look it up in
Ghidra to have the exact source and trace its usage.

Tracing MSN Client errors
---
* Errors are not rendered with MessageBoxA, but with a custom procedure ReportMosXErrX exported by MOSSHELL.DLL
