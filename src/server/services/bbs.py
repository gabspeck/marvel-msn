"""BBS service handler: forum/bulletin-board tree, threaded message nodes.

The BBS read/navigation channel rides the same generic MOS tree infrastructure
as DSNAV — a MOSSHELL `_NtniGroup` wrapping a TREENVCL `CTreeNavClient`, opened
on the service named "BBS" (docs/bbs-service-contract.md §Framing). The wire
request/reply shapes are therefore identical to DIRSRV; only the per-node
property vocabulary differs (`e, _a, p, _D, _P, _t, _F, _I, _f` + base `a/c/b`).
A board/conversation/reply is a `CMosTreeNode` and threading is the tree itself:
a reply is a child of the message it answers, so recursive GetChildren yields
the indented thread list.

Write/edit channel (TREEEDCL `CTreeEditClient`, selectors 0–12) is out of
scope. A Compose first sends `GetTicket` (selector 12) to obtain a capability
ticket; that selector falls into the unhandled bucket here, so a Compose
attempt is logged and left unanswered rather than crashing or being misrouted.
"""

import logging
import struct

from ..config import DIRSRV_INTERFACE_GUIDS
from ..mpc import (
    build_discovery_host_block,
    build_discovery_payload,
    build_host_block,
    build_service_packet,
    decode_dirsrv_request,
)
from ..store import app_store as _default_store
from ..store.base import BbsFields
from . import dirsrv
from ._dispatch import log_unhandled_selector

# BBS read-channel selectors — identical numbering to DIRSRV (the generic
# TREENVCL tree, docs/bbs-service-contract.md §"Read selectors"). Slots map to
# IIDs via the same discovery table DSNAV advertises.
BBS_SELECTOR_GET_PROPERTIES = 0x00
BBS_SELECTOR_GET_CHILDREN = 0x02
BBS_SELECTOR_GET_DEID_FROM_GO_WORD = 0x03
BBS_SELECTOR_GET_SHABBY = 0x04

# BBS property tags (docs/bbs-service-contract.md §"Property tags"). `e` is the
# Subject; `_a` the Author; `_D` a DWORD time_t (MOSSHELL DWORD-as-time_t date
# path keys on the name "_D"); `_P` the parent message's sub-id for threading;
# `_F`/`_I` 2-byte flag words; `_f` advertised with no client read site. `h`
# (icon) is NOT emitted — CBbsNavTreeNode_GetProperty intercepts it and returns
# a client-local glyph id.
PROP_MNID = "a"
PROP_APP_ID = "c"
PROP_BROWSE_FLAGS = "b"
PROP_NAME = "e"
PROP_AUTHOR = "_a"
PROP_SIZE = "p"
PROP_DATE = "_D"
PROP_PARENT_SUBID = "_P"
PROP_TOPIC = "_t"
PROP_HAS_CHILDREN = "_F"
PROP_PRICE_INFO = "_I"
PROP_UNKNOWN_F = "_f"

# Substituted when a node carries no BbsFields (e.g. the unknown-mnid fallback
# node routed onto the BBS pipe) so property serialisation never AttributeErrors.
_EMPTY_BBS = BbsFields()

log = logging.getLogger(__name__)


class BBSHandler:
    """Handles BBS read-channel requests on a logical pipe."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        """Advertise the generic TREENVCL tree IIDs (same table as DSNAV).

        BBS resolves the same read-channel IIDs as DIRSRV — it is not a
        self-describing MEDVIEW-style service, it rides MOSSHELL's tree client.
        """
        payload = build_discovery_payload(DIRSRV_INTERFACE_GUIDS)
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        """Dispatch a BBS request by selector.

        Read selectors 0/2/3/4 are answered; everything else — GetParents (1),
        the unimplemented enum/resolve slots, and every TREEEDCL write selector
        (0–12, incl. GetTicket) — is logged unhandled and left unanswered.
        """
        if selector == BBS_SELECTOR_GET_PROPERTIES:
            request = decode_dirsrv_request(payload)
            reply_payload = build_bbs_get_properties_reply_payload(request)
        elif selector == BBS_SELECTOR_GET_CHILDREN:
            request = decode_dirsrv_request(payload)
            reply_payload = build_bbs_get_children_reply_payload(request)
        elif selector == BBS_SELECTOR_GET_DEID_FROM_GO_WORD:
            reply_payload = dirsrv.build_get_deid_from_go_word_reply_payload(payload)
        elif selector == BBS_SELECTOR_GET_SHABBY:
            reply_payload = dirsrv.build_get_shabby_reply_payload(payload)
        else:
            log_unhandled_selector(log, msg_class, selector, request_id, payload)
            return None
        host_block = build_host_block(msg_class, selector, request_id, reply_payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)


def build_bbs_props(requested_props, node, *, is_children):
    """Serialise a BBS tree node into (type, name, value) property tuples.

    BBS rides the generic TREENVCL tree but emits its own tag vocabulary
    (docs/bbs-service-contract.md §"Property tags"). `is_children` is accepted
    for signature parity with dirsrv.build_props; BBS tags carry one wire type
    regardless of caller, so it is unused today. Emit only requested tags;
    an unknown requested tag gets a DWORD-0 fallback, mirroring dirsrv.
    """
    content = node.content
    bbs = content.bbs or _EMPTY_BBS

    out = []
    for name in requested_props:
        if name == PROP_MNID:
            out.append((0x0E, name, struct.pack("<I", len(node.mnid_a)) + node.mnid_a))
        elif name == PROP_APP_ID:
            out.append((0x03, name, struct.pack("<I", node.app_id)))
        elif name == PROP_BROWSE_FLAGS:
            # All BBS tree nodes browse (bit 0x01 clear). Opening a message in
            # the reader is a bbsnav verb, not a 'b'-exec gate.
            out.append((0x01, name, b"\x00"))
        elif name == PROP_NAME:
            # Subject. 0x0A (ASCII cache) like DIRSRV `e`: column 0 and the
            # Properties dialog both read ANSI.
            out.append((0x0A, name, dirsrv._sz(content.name)))
        elif name == PROP_AUTHOR:
            out.append((0x0A, name, dirsrv._sz(bbs.author)))
        elif name == PROP_TOPIC:
            out.append((0x0A, name, dirsrv._sz(bbs.topic)))
        elif name == PROP_SIZE:
            out.append((0x03, name, struct.pack("<I", content.size_bytes & 0xFFFFFFFF)))
        elif name == PROP_DATE:
            # `_D` DWORD time_t, always emitted — 0 when the node has no date.
            # Never skip a requested tag: CServiceProperties::FSet @ 0x7F6418FF
            # only advances the record count on success, so a dropped property
            # also strips every property after it. Omitting `_D` here cost the
            # board its `_F` (the OkToGetChildren gate) and stalled the thread
            # fetch. Verified on the wire 2026-07-27.
            out.append((0x03, name, struct.pack("<I", bbs.date_unix & 0xFFFFFFFF)))
        elif name == PROP_PARENT_SUBID:
            out.append((0x03, name, struct.pack("<I", bbs.parent_subid & 0xFFFFFFFF)))
        elif name == PROP_HAS_CHILDREN:
            # `_F` 2-byte flags. CBbsNavTreeNode::OkToGetChildren @ 0x7F5F1427
            # reads it and tests the HIGH byte against 0x10, i.e. u16 bit
            # 0x1000. Bit SET → child count forced to 0. So the bit means
            # "leaf / no children", the inverse of its old reading here.
            out.append((0x02, name, struct.pack("<H", 0 if bbs.has_children else 0x1000)))
        elif name == PROP_PRICE_INFO:
            # `_I` 2-byte attributes. 0 = free content (no pricing checkbox).
            out.append((0x02, name, struct.pack("<H", 0)))
        elif name == PROP_UNKNOWN_F:
            # `_f` advertised but no BBSNAV read site; safe default DWORD 0.
            out.append((0x03, name, struct.pack("<I", 0)))
        else:
            out.append((0x03, name, struct.pack("<I", 0)))
    return out


def build_bbs_get_properties_reply_payload(request):
    """BBS GetProperties (selector 0x00): one self record for the node.

    Same single-record contract as DIRSRV GetProperties — the reader header
    and Properties dialog feed the first received record into the requesting
    CMosTreeNode, so returning children would corrupt the node's identity.
    """
    requested = _requested_props(request.prop_group)
    node = _default_store.content.get_node(request.node_id)
    log.info(
        "bbs_get_properties node=%s props=%s",
        request.node_id,
        ",".join(requested) or "-",
    )
    records = [(node.node_id, build_bbs_props(requested, node, is_children=False))]
    return dirsrv.build_tree_reply_wire(records)


def build_bbs_get_children_reply_payload(request):
    """BBS GetChildren (selector 0x02): the threaded child list.

    board → conversations, conversation → replies (recursive). `locale_raw` is
    forwarded so a filter_on=1 request still resolves — BBS nodes are
    language=0 (locale-neutral) and survive every locale filter.
    """
    requested = _requested_props(request.prop_group)
    children = _default_store.content.get_children(request.node_id, request.locale_raw)
    log.info(
        "bbs_get_children node=%s props=%s child_count=%d",
        request.node_id,
        ",".join(requested) or "-",
        len(children),
    )
    records = [
        (child.node_id, build_bbs_props(requested, child, is_children=True))
        for child in children
    ]
    return dirsrv.build_tree_reply_wire(records)


def _requested_props(prop_group):
    return [p for p in prop_group.split("\x00") if p]
