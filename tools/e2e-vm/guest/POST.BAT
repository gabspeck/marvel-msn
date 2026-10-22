@ECHO OFF
REM First logon after setup (MSBATCH.INF RunOnce). REGEDIT is a Windows app,
REM so START /W keeps the signal behind the import. vm.py shuts Windows down
REM once this window has closed.
START /W REGEDIT /S C:\STAGE\POST.REG
ECHO E2E-POST-DONE> COM1
CLS
