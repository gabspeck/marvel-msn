from ._dispatch import log_unhandled_selector
from .dirsrv import DIRSRVHandler
from .ftm import FTMHandler
from .logsrv import LOGSRVHandler
from .medview import MEDVIEWHandler
from .olregsrv import OLREGSRVHandler
from .onlstmt import OnlStmtHandler

SERVICE_HANDLERS = {
    "LOGSRV": LOGSRVHandler,
    "DIRSRV": DIRSRVHandler,
    "FTM": FTMHandler,
    "OLREGSRV": OLREGSRVHandler,
    "OnlStmt": OnlStmtHandler,
    "MEDVIEW": MEDVIEWHandler,
}

__all__ = ["SERVICE_HANDLERS", "log_unhandled_selector"]
