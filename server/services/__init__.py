from .logsrv import LOGSRVHandler
from .dirsrv import DIRSRVHandler

SERVICE_HANDLERS = {
    'LOGSRV': LOGSRVHandler,
    'DIRSRV': DIRSRVHandler,
}
