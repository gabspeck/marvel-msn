from .logsrv import LOGSRVHandler
from .dirsrv import DIRSRVHandler
from .ftm import FTMHandler

SERVICE_HANDLERS = {
    'LOGSRV': LOGSRVHandler,
    'DIRSRV': DIRSRVHandler,
    'FTM': FTMHandler,
}
