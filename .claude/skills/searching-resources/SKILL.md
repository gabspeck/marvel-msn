---
name: searching for string resources in PE binaries
description: How to effectively pinpoint the source of a string in a Portable Executable binary (DLL, EXE, NAV)
---

* Use `strings -fel *` in the `binaries` directory a resource string comes from. Once you have the the filename, look 
it up in Ghidra to have the exact source and trace its usage.
