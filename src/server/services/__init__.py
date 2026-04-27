from ._dispatch import log_unhandled_selector
from .dirsrv import DIRSRVHandler
from .ftm import FTMHandler
from .logsrv import LOGSRVHandler
from .medview import MEDVIEWHandler
from .olregsrv import OLREGSRVHandler
from .onlstmt import OnlStmtHandler

SERVICE_HANDLERS = {
    "logsrv": LOGSRVHandler,
    "dirsrv": DIRSRVHandler,
    "ftm": FTMHandler,
    "olregsrv": OLREGSRVHandler,
    "onlstmt": OnlStmtHandler,
    "medview": MEDVIEWHandler,
}

__all__ = ["SERVICE_HANDLERS", "log_unhandled_selector"]
