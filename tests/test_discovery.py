"""Discovery tables: each service advertises the IIDs its clients resolve
(docs/SERVICE-IIDS.md) under the selectors its handler dispatches on."""

import struct
import unittest

from server.config import MEDVIEW_DATA_EDIT_CLASS
from server.services import SERVICE_HANDLERS
from server.services.bbs import BBS_CLASS_MESSAGE, BBS_CLASS_TREE
from server.services.conference import CONFLOC_DATA_EDIT_CLASS
from server.services.dirsrv import DIRSRV_CLASS_TREE, TREEEDCL_CLASS_EDIT

_MOS_TAIL = bytes.fromhex("00000000c000000000000046")


def _advertised(service):
    """`{00028Bxx suffix or full GUID: selector}` for one service's table."""
    out = {}
    for guid, selector in SERVICE_HANDLERS[service].GUIDS:
        if guid[4:] == _MOS_TAIL:
            out[f"{struct.unpack_from('<I', guid)[0] & 0xFF:02X}"] = selector
        else:
            out[guid.hex()] = selector
    return out


class TestDiscoveryTables(unittest.TestCase):
    def test_mos_services_advertise_exactly_the_resolved_iids(self):
        expected = {
            "logsrv": {"C2": 0x06},
            "dirsrv": {"27": DIRSRV_CLASS_TREE, "28": TREEEDCL_CLASS_EDIT},
            "bbs": {"27": BBS_CLASS_TREE, "28": TREEEDCL_CLASS_EDIT, "2F": BBS_CLASS_MESSAGE},
            "ftm": {"25": 0x01},
            "olregsrv": {"73": 0x01},
            "onlstmt": {"8D": 0x01},
            "sasrv": {"8B": 0x01},
            "medview": {"71": 0x01, "72": MEDVIEW_DATA_EDIT_CLASS},
            "findsvc": {"B0": 0x01},
            "mosabp": {"22": 0x01},
            "mosrxp": {"20": 0x01},
            "confloc": {"52": 0x01, "72": CONFLOC_DATA_EDIT_CLASS},
            "confsrv": {"C8": 0x01},
        }
        for service, iids in expected.items():
            with self.subTest(service=service):
                self.assertEqual(_advertised(service), iids)

    def test_blackbird_services_advertise_their_coscl_guids(self):
        self.assertEqual(len(SERVICE_HANDLERS["bbird_ob"].GUIDS), 2)
        self.assertEqual(len(SERVICE_HANDLERS["bbirservice"].GUIDS), 1)


if __name__ == "__main__":
    unittest.main()
