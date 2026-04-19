Guidelines
===

Searching for resources
---


Tracing MSN Client errors
---
* Errors are not rendered with MessageBoxA, but with a custom procedure ReportMosXErrX exported by MOSSHELL.DLL

MSN Central menu handling
---
* Menu item click handler: 
  * HrGetPMtn
  * GUIDENAV caller -> MOSSHELL!CMosTreeNode::ExecuteCommand(this=00ED078C, cmd=0x3000, ...)
  * mnids:
    - MSN Today: 1:4:0:0
    - Favorite Places: 3:1:0:0
    - Member assistance: 1:1:0:0
    - Categories: 1:0:0:0
