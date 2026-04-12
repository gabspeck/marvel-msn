from .logsrv import LOGSRVHandler
from .dirsrv import DIRSRVHandler
from .ftm import FTMHandler
from .olregsrv import OLREGSRVHandler
from .onlstmt import OnlStmtHandler

SERVICE_HANDLERS = {
    'LOGSRV': LOGSRVHandler,
    'DIRSRV': DIRSRVHandler,
    'FTM': FTMHandler,
    'OLREGSRV': OLREGSRVHandler,
    'OnlStmt': OnlStmtHandler,
}
