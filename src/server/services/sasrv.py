"""SASRV system-administration service discovery."""

import logging

from ..config import SASRV_INTERFACE_GUIDS
from ..mpc import build_discovery_host_block, build_discovery_payload, build_service_packet
from ._dispatch import log_unhandled_selector

log = logging.getLogger(__name__)


class SASRVHandler:
    """Advertise the interfaces used by SACLIENT.DLL."""

    def __init__(self, pipe_idx, svc_name):
        self.pipe_idx = pipe_idx
        self.svc_name = svc_name

    def build_discovery_packet(self, server_seq, client_ack):
        payload = build_sasrv_service_map_payload()
        host_block = build_discovery_host_block(payload)
        return build_service_packet(self.pipe_idx, host_block, server_seq, client_ack)

    def handle_request(self, msg_class, selector, request_id, payload, server_seq, client_ack):
        log_unhandled_selector(log, msg_class, selector, request_id, payload)
        return None


def build_sasrv_service_map_payload():
    return build_discovery_payload(SASRV_INTERFACE_GUIDS)
