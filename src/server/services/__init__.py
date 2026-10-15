from ._dispatch import log_unhandled_selector
from .bbir import BbirHandler
from .bbird_ob import BbirdObHandler
from .bbs import BbsHandler
from .conference import ConflocHandler, ConfsrvHandler
from .dirsrv import DirsrvHandler
from .findsvc import FindsvcHandler
from .ftm import FtmHandler
from .logsrv import LogsrvHandler
from .medview import MedviewHandler
from .mosabp import MosabpHandler
from .mosrxp import MosrxpHandler
from .olregsrv import OlregsrvHandler
from .onlstmt import OnlstmtHandler
from .sasrv import SasrvHandler

SERVICE_HANDLERS = {
    "logsrv": LogsrvHandler,
    "dirsrv": DirsrvHandler,
    "findsvc": FindsvcHandler,
    "ftm": FtmHandler,
    "olregsrv": OlregsrvHandler,
    "onlstmt": OnlstmtHandler,
    "medview": MedviewHandler,
    "bbs": BbsHandler,
    "confloc": ConflocHandler,
    "confsrv": ConfsrvHandler,
    "mosabp": MosabpHandler,
    "mosrxp": MosrxpHandler,
    "sasrv": SasrvHandler,
    "bbird_ob": BbirdObHandler,
    "bbirservice": BbirHandler,
}

__all__ = ["SERVICE_HANDLERS", "log_unhandled_selector"]
