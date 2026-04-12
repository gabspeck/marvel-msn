from .logsrv import LOGSRVHandler
from .dirsrv import DIRSRVHandler
from .ftm import FTMHandler
from .olregsrv import OLREGSRVHandler

SERVICE_HANDLERS = {
    'LOGSRV': LOGSRVHandler,
    'DIRSRV': DIRSRVHandler,
    'FTM': FTMHandler,
    'OLREGSRV': OLREGSRVHandler,
}
