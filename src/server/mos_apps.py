"""Registered MOS application IDs.

Values mirror the `HKLM\\SOFTWARE\\Microsoft\\MOS\\Applications\\App #N` keys
installed on the Win95 client (see `ftp/mos.reg`). The wire 'c' property on a
DIRSRV node is the app id that CMosTreeNode::Exec dispatches into:
  - `APP_DIRECTORY_SERVICE` (1) → Browse container (child enumeration)
  - `APP_DOWN_LOAD_AND_RUN` (7) → DnR URL worker (ExecUrlWorkerProc)
  - other ids → CreateProcessA on the registered Filename.
"""

from __future__ import annotations

# dsnav.nav
APP_DIRECTORY_SERVICE = 1
# bbsnav.nav
APP_BBS_SERVICE = 2
# guidenav.nav
APP_GUIDE_SERVICE = 3
# textchat.exe
APP_TEXT_CONFERENCE = 4
# no filename
APP_WHATS_NEW = 5
# mosview.exe
APP_MEDIA_VIEWER = 6
# dnr.exe
APP_DOWNLOAD_AND_RUN = 7
APP_HELLOCLA = 8
APP_HELLOCLB = 9
# bbsnav.nav
APP_BBS_INTERNET_SERVICE = 10
APP_ENCARTA = 11
APP_BOOKSHELF = 12
APP_CORE_HELP = 13
APP_REGISTRATION = 14
# no filename
APP_BILLING = 15
# no filename
APP_PHONE_BOOK = 16
# no filename
APP_SIGNUP = 17
# dsned.ned until the end (node editor - authoring tool?)
APP_DSED = 18
APP_BBSED = 19
APP_TEXTCHATED = 20
APP_MEDVIEWED = 21
APP_DLRED = 22
APP_HELLOCLAED = 23
APP_HELLOCLBED = 24
APP_BBSINETED = 25
APP_ENCARTAED = 26
APP_BSHELFED = 27
APP_GUIDEED = 28
