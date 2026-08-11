from ._dispatch import log_unhandled_selector
from .bbs import BBSHandler
from .conference import CONFLOCHandler, CONFSRVHandler
from .dirsrv import DIRSRVHandler
from .findsvc import FindSvcHandler
from .ftm import FTMHandler
from .logsrv import LOGSRVHandler
from .medview import MEDVIEWHandler
from .mosabp import MOSABPHandler
from .olregsrv import OLREGSRVHandler
from .onlstmt import OnlStmtHandler
from .sasrv import SASRVHandler

SERVICE_HANDLERS = {
    "logsrv": LOGSRVHandler,
    "dirsrv": DIRSRVHandler,
    "findsvc": FindSvcHandler,
    "ftm": FTMHandler,
    "olregsrv": OLREGSRVHandler,
    "onlstmt": OnlStmtHandler,
    "medview": MEDVIEWHandler,
    "bbs": BBSHandler,
    "confloc": CONFLOCHandler,
    "confsrv": CONFSRVHandler,
    "mosabp": MOSABPHandler,
    "sasrv": SASRVHandler,
}

__all__ = ["SERVICE_HANDLERS", "log_unhandled_selector"]
