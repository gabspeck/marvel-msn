"""FTM: billing, signup, BBS attachment and Download-and-Run transfers."""

import hashlib
import struct
import unittest
from dataclasses import replace

from server.mpc import (
    build_tagged_reply_var,
    parse_host_block,
)
from server.services.ftm import (
    FTM_BBS_SOURCE,
    FTM_CLIENT_FILE_ID_SIZE,
    FTM_COUNTER_OFFSET,
    FTM_DIRSRV_SOURCE,
    FTM_FALLBACK_FILENAME,
    FTM_MOS2_UNPACK_METHOD,
    FtmHandler,
    _build_bill_client_reply,
    _build_request_download_reply,
    _build_start_download_blocks,
    _resolve_ftm_target,
    mos2_chunk_spans,
    mos2_original_size,
)
from server.session import Session
from server.store import (
    app_store,
    reset_app_store,
)
from server.transport import parse_packet


class TestFTMHandler(unittest.TestCase):
    def test_request_download_reply_returns_packet(self):
        payload = bytes.fromhex(
            "04 bc 70 6c 61 6e 73 2e 74 78 74 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            " 00 00 00 00 00 00 00 00 00 00 00 00"
        )
        handler = FtmHandler(1, "FTM", Session())
        pkts = handler.handle_request(0x01, 0x00, 0, payload, 5, 5)
        self.assertIsNotNone(pkts)
        self.assertEqual(len(pkts), 1)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_bill_client_reply_returns_packet(self):
        handler = FtmHandler(1, "FTM", Session())
        pkts = handler.handle_request(0x01, 0x03, 0, b"", 5, 5)
        self.assertIsNotNone(pkts)
        parsed = parse_packet(pkts[0][:-1])
        self.assertTrue(parsed.crc_ok)

    def test_unknown_selector_returns_none(self):
        handler = FtmHandler(1, "FTM", Session())
        self.assertIsNone(handler.handle_request(0x01, 0x02, 0, b"", 5, 5))

    def test_resolve_ftm_target_returns_name_for_expected_var_layout(self):
        payload = (
            b"\x04"
            + bytes([0x80 | 60])
            + b"ms_Ynt.hlp\x00"
            + b"\x00" * (60 - len("ms_Ynt.hlp") - 1)
        )
        filename, _ = _resolve_ftm_target(payload)
        self.assertEqual(filename, "ms_Ynt.hlp")

    def test_resolve_ftm_target_falls_back_for_unexpected_var_size(self):
        payload = b"\x04" + bytes([0x80 | 32]) + b"plans.txt\x00" + b"\x00" * 22
        filename, _ = _resolve_ftm_target(payload)
        self.assertEqual(filename, FTM_FALLBACK_FILENAME)

    def test_request_download_reply_echoes_filename(self):
        payload = _build_request_download_reply("ms_Ynt.hlp", 0)
        self.assertEqual(payload[0], 0x84)
        self.assertIn(b"ms_Ynt.hlp\x00", payload)

    def test_request_download_reply_handles_non_ascii_filename(self):
        payload = _build_request_download_reply("pláns.txt", 0)
        self.assertEqual(payload[0], 0x84)
        self.assertIn(b"plns.txt\x00", payload)

    def test_request_download_reply_size_matches_content_len(self):
        payload = _build_request_download_reply("prodinfo.rtf", 42)
        # After 2-byte 0x84 length prefix, size1 at offset 0x08 and
        # size2 at offset 0x0C must both equal content_len.
        body = payload[2:]
        self.assertEqual(struct.unpack("<I", body[0x08:0x0C])[0], 42)
        self.assertEqual(struct.unpack("<I", body[0x0C:0x10])[0], 42)

    def test_bill_client_reply_has_zero_chunk_length(self):
        payload = _build_bill_client_reply()
        self.assertEqual(payload[0], 0x84)
        self.assertEqual(struct.unpack("<H", payload[0x11:0x13])[0], 0)

    def test_bill_client_reply_carries_content(self):
        content = b"{\\rtf1 hi}"
        payload = _build_bill_client_reply(content)
        body = payload[2:]  # strip 0x84 + length prefix
        self.assertEqual(struct.unpack("<H", body[0x10:0x12])[0], len(content))
        self.assertEqual(body[0x12 : 0x12 + len(content)], content)


def _make_logsrv_request(counter, selector=0x00):
    """Synthesize a signup-path FTM request with LOGSRV+counter CFI."""
    cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
    cfi[:6] = b"LOGSRV"
    struct.pack_into("<I", cfi, FTM_COUNTER_OFFSET, counter)
    return build_tagged_reply_var(0x04, bytes(cfi)) + b"\x84"


class TestFTMSignupLogsrvMapping(unittest.TestCase):
    def test_counter_0_maps_to_plans_txt(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(0))
        self.assertEqual(filename, "plans.txt")
        self.assertIn(b"[Countries]", content)
        self.assertIn(b"[PaymentOptions]", content)
        self.assertIn(b"PaymentOption1=CHARGE", content)

    def test_counter_1_maps_to_prodinfo(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(1))
        self.assertEqual(filename, "prodinfo.rtf")
        self.assertTrue(content.startswith(b"{\\rtf1"))

    def test_counter_2_maps_to_legalagr(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(2))
        self.assertEqual(filename, "legalagr.rtf")
        self.assertTrue(content.startswith(b"{\\rtf1"))

    def test_counter_3_maps_to_newtips(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(3))
        self.assertEqual(filename, "newtips.rtf")
        self.assertTrue(content.startswith(b"{\\rtf1"))

    def test_counter_out_of_range_falls_through(self):
        filename, content = _resolve_ftm_target(_make_logsrv_request(99))
        # Unknown counter leaves the source name intact — no content served.
        self.assertEqual(filename, "LOGSRV")
        self.assertEqual(content, b"")

    def test_direct_filename_is_served_from_disk(self):
        # Billing path: client sends "plans.txt" directly — resolved
        # against server/data/signup/plans.txt dynamically.
        cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
        cfi[: len(b"plans.txt")] = b"plans.txt"
        payload = build_tagged_reply_var(0x04, bytes(cfi))
        filename, content = _resolve_ftm_target(payload)
        self.assertEqual(filename, "plans.txt")
        self.assertIn(b"[PaymentOptions]", content)

    def test_unknown_direct_filename_returns_empty(self):
        cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
        cfi[: len(b"missing.bin")] = b"missing.bin"
        payload = build_tagged_reply_var(0x04, bytes(cfi))
        filename, content = _resolve_ftm_target(payload)
        self.assertEqual(filename, "missing.bin")
        self.assertEqual(content, b"")

    def test_request_download_reply_encodes_mapped_filename(self):
        handler = FtmHandler(5, "FTM", Session())
        pkts = handler.handle_request(
            0x01,
            0x00,
            0,
            _make_logsrv_request(1),
            10,
            10,
        )
        self.assertIsNotNone(pkts)
        # The mapped filename must appear in the on-wire reply.
        joined = b"".join(pkts)
        self.assertIn(b"prodinfo.rtf\x00", joined)

    def test_bill_client_reply_emits_rtf_for_counter_1(self):
        handler = FtmHandler(5, "FTM", Session())
        pkts = handler.handle_request(
            0x01,
            0x03,
            1,
            _make_logsrv_request(1, selector=0x03),
            10,
            10,
        )
        self.assertIsNotNone(pkts)
        joined = b"".join(pkts)
        _, expected = _resolve_ftm_target(_make_logsrv_request(1))
        self.assertIn(expected, joined)


def _make_bbs_attachment_request(attachment_id=0x202, board_id=1):
    """Synthesize MOSAF's BBS FRI for one attachment node."""
    cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
    cfi[: len(FTM_BBS_SOURCE)] = FTM_BBS_SOURCE.encode("ascii")
    struct.pack_into("<IIII", cfi, 32, 2, board_id, attachment_id, 0)
    return build_tagged_reply_var(0x04, bytes(cfi)) + b"\x84"


class TestFTMBbsAttachment(unittest.TestCase):
    def setUp(self):
        reset_app_store()
        self.addCleanup(reset_app_store)

    def test_bbs_fri_resolves_the_fixture_upload(self):
        filename, content = _resolve_ftm_target(_make_bbs_attachment_request())
        self.assertEqual(filename, FTM_BBS_SOURCE)
        self.assertEqual(len(content), 175)
        self.assertEqual(content[:4], b"MOS2")

    def test_reply_preserves_mosaf_filename_and_selects_mos2_unpack(self):
        payload = _build_request_download_reply(
            FTM_BBS_SOURCE,
            175,
            unpack_method=FTM_MOS2_UNPACK_METHOD,
            override_filename=False,
        )
        reply = payload[2:]
        self.assertEqual(struct.unpack_from("<I", reply, 0x08)[0], 175)
        self.assertEqual(struct.unpack_from("<I", reply, 0x0C)[0], 175)
        self.assertEqual(struct.unpack_from("<I", reply, 0x10)[0], 0x03)
        self.assertEqual(
            struct.unpack_from("<I", reply, 0x14)[0],
            FTM_MOS2_UNPACK_METHOD,
        )
        self.assertEqual(reply[0x28:], b"\x00" * 32)

    def test_bill_client_carries_the_mos2_container(self):
        handler = FtmHandler(5, "FTM", Session())
        pkts = handler.handle_request(
            0x01,
            0x03,
            1,
            _make_bbs_attachment_request(),
            10,
            10,
        )
        self.assertIn(b"MOS2", b"".join(pkts))

    def test_request_download_does_not_increment_the_download_count(self):
        handler = FtmHandler(5, "FTM", Session())
        handler.handle_request(
            0x01,
            0x00,
            1,
            _make_bbs_attachment_request(),
            10,
            10,
        )
        attachment = app_store.content.get_node("514:1")
        self.assertEqual(attachment.content.bbs.download_count, 0)

    def test_bill_client_increments_the_download_count(self):
        handler = FtmHandler(5, "FTM", Session())
        for expected in (1, 2):
            handler.handle_request(
                0x01,
                0x03,
                expected,
                _make_bbs_attachment_request(),
                10,
                10,
            )
            attachment = app_store.content.get_node("514:1")
            self.assertEqual(attachment.content.bbs.download_count, expected)


def _make_dirsrv_file_request(node_id="1:272", prop="fi"):
    """Synthesize the FRI CMosTreeNode::GetShabbyViaFtm builds for a node."""
    field_0, field_8 = (int(part) for part in node_id.split(":"))
    cfi = bytearray(FTM_CLIENT_FILE_ID_SIZE)
    cfi[: len(FTM_DIRSRV_SOURCE)] = FTM_DIRSRV_SOURCE.encode("ascii")
    struct.pack_into("<II", cfi, 32, field_8, field_0)
    name = prop.encode("ascii")
    cfi[40 : 40 + len(name)] = name
    return build_tagged_reply_var(0x04, bytes(cfi)) + b"\x84"


class TestFTMDownloadAndRun(unittest.TestCase):
    """MOSSHELL's c==7 worker pulling the payload the DLRed page uploaded."""

    NODE_ID = "1:272"
    # What the captured Windiff.exe upload declared.
    ORIGINAL_SIZE = 107520
    # A 0x84 variable field holding two dwords, then end-of-static. Sending
    # 0x83 dwords here instead is what MPCCL answered 0x8B0B0008 to.
    STATIC_PREFIX = b"\x84\x88" + b"\x00" * 8 + b"\x87"

    def setUp(self):
        from server.services import shabby as shabby_mod

        reset_app_store()
        self.addCleanup(reset_app_store)
        self._registry = dict(shabby_mod.SHABBY_REGISTRY)

        def restore():
            shabby_mod.SHABBY_REGISTRY.clear()
            shabby_mod.SHABBY_REGISTRY.update(self._registry)

        self.addCleanup(restore)

        # A MOS2 container in the shape HrMos2DecompFile @ 0x7F6B34A8
        # validates, long enough to cross the 0x4000 dynamic-block boundary.
        header = (
            b"MOS2"
            + struct.pack("<HH", 0x0010, 0x8000)
            + struct.pack("<I", self.ORIGINAL_SIZE)
            + b"\x00" * 8
        )
        self.blob = header + bytes(range(256)) * 160
        self.shabby_id = shabby_mod.add_shabby_bytes(shabby_mod.FORMAT_MOS_COMPRESSED, self.blob)
        node = app_store.content.get_node("1:256")
        app_store.content.add_node(
            replace(
                node,
                node_id=self.NODE_ID,
                app_id=7,
                content=replace(
                    node.content,
                    dnr_shabby_id=self.shabby_id,
                    dnr_file_name="WINDIFF.EXE",
                    dnr_compression=3,
                    size_bytes=len(self.blob),
                ),
            )
        )

    def test_fri_resolves_the_uploaded_payload(self):
        source, content = _resolve_ftm_target(_make_dirsrv_file_request(self.NODE_ID))
        self.assertEqual(source, FTM_DIRSRV_SOURCE)
        self.assertEqual(content, self.blob)

    def test_unknown_property_resolves_to_nothing(self):
        _, content = _resolve_ftm_target(_make_dirsrv_file_request(self.NODE_ID, prop="mf"))
        self.assertEqual(content, b"")

    def test_request_download_skips_fast_path_and_name(self):
        handler = FtmHandler(5, "FTM", Session())
        pkts = handler.handle_request(
            0x01, 0x00, 1, _make_dirsrv_file_request(self.NODE_ID), 10, 10
        )

        reply = _build_request_download_reply(
            FTM_DIRSRV_SOURCE,
            len(self.blob),
            unpack_method=FTM_MOS2_UNPACK_METHOD,
            override_filename=False,
            fast_path=False,
        )[2:]
        self.assertEqual(struct.unpack_from("<I", reply, 0x08)[0], len(self.blob))
        self.assertEqual(struct.unpack_from("<I", reply, 0x0C)[0], len(self.blob))
        # bit 0 only: no HrBillClient shortcut, no filename override.
        self.assertEqual(struct.unpack_from("<I", reply, 0x10)[0], 0x01)
        self.assertEqual(struct.unpack_from("<I", reply, 0x14)[0], FTM_MOS2_UNPACK_METHOD)
        self.assertEqual(reply[0x28:], b"\x00" * 32)
        self.assertIsNotNone(pkts)

    def test_start_download_streams_the_payload_on_the_iterator(self):
        handler = FtmHandler(5, "FTM", Session())

        pkts = handler.handle_request(
            0x01, 0x01, 2, _make_dirsrv_file_request(self.NODE_ID), 10, 10
        )

        from server.pipe import parse_pipe_frames

        # 8 static bytes then 0x87 — the shape HrStartDownload checks before
        # it takes the request's dynamic iterator.
        self.assertIsNotNone(pkts)
        opening = parse_host_block(
            parse_pipe_frames(parse_packet(pkts[0][:-1]).payload)[0].content[2:]
        )
        self.assertEqual(opening.payload[:11], self.STATIC_PREFIX)
        # A payload this size has to cross pipe frames, and every packet has
        # to stay inside the client's receive buffer.
        self.assertGreater(len(pkts), 1)
        self.assertTrue(all(len(pkt) <= 1024 for pkt in pkts))
        for pkt in pkts:
            self.assertTrue(parse_packet(pkt[:-1]).crc_ok)

    def test_stream_raises_all_three_signals(self):
        """ProcessTaggedServiceReply @ MPCCL 0x04604F26 pins every rule here.

        It allocates the dynamic receive state with a 0x4000 capacity, and
        routes the tags to three different signals: 0x85 delivers a chunk,
        0x88 also ends the iterator message, and only 0x86 reaches
        SignalRequestCompletion. HrFinishRequest @ FTMAPI 0x7F6B1800 loops on
        the message-complete code, so ending on 0x88 hangs at 100%.
        """
        blocks = _build_start_download_blocks(self.blob)
        *data_blocks, completion = blocks

        self.assertGreater(len(data_blocks), 1)
        self.assertEqual(completion, bytes([0x86]))
        self.assertEqual(data_blocks[0][:11], self.STATIC_PREFIX)
        # Every block closes its own message: 0x85 would append into one
        # 0x4000 receive state and corrupt everything past the first block.
        self.assertEqual(data_blocks[0][11], 0x88)
        for block in data_blocks[1:]:
            self.assertEqual(block[0], 0x88)
        # No block's dynamic payload may exceed the receive buffer.
        self.assertLessEqual(len(data_blocks[0]) - 12, 0x4000)
        for block in data_blocks[1:]:
            self.assertLessEqual(len(block) - 1, 0x4000)
        # Every byte, in order.
        rebuilt = data_blocks[0][12:] + b"".join(block[1:] for block in data_blocks[1:])
        self.assertEqual(rebuilt, self.blob)

    def test_reply_sizes_both_state_the_transferred_length(self):
        """size1 pre-sizes the receiving file — HrInit @ FTMAPI 0x7F6B1FC4."""
        reply = _build_request_download_reply(
            FTM_DIRSRV_SOURCE,
            len(self.blob),
            unpack_method=FTM_MOS2_UNPACK_METHOD,
            override_filename=False,
            fast_path=False,
        )[2:]

        # Both are the transferred length: size1 pre-sizes the file that
        # receives the compressed bytes, so the container's larger
        # uncompressed count would pad it with a garbage tail.
        self.assertEqual(struct.unpack_from("<I", reply, 0x08)[0], len(self.blob))
        self.assertEqual(struct.unpack_from("<I", reply, 0x0C)[0], len(self.blob))
        self.assertEqual(mos2_original_size(self.blob), self.ORIGINAL_SIZE)

    def test_seeded_node_serves_payload_without_unpack(self):
        """The generated payload is plain text, so it must reach disk as-is.

        HrMos2DecompFile @ FTMAPI 0x7F6B34A8 rejects anything that does not
        open with a valid MOS2 header, so asking for unpack method 3 on an
        uncompressed payload fails the transfer.
        """
        from server.store import fixtures

        source, content = _resolve_ftm_target(
            _make_dirsrv_file_request(fixtures._DNR_TEST_NODE.node_id)
        )

        self.assertEqual(source, FTM_DIRSRV_SOURCE)
        self.assertEqual(content, fixtures.DNR_TEST_PAYLOAD)
        self.assertIsNone(mos2_original_size(content))

        handler = FtmHandler(5, "FTM", Session())
        pkts = handler.handle_request(
            0x01,
            0x00,
            1,
            _make_dirsrv_file_request(fixtures._DNR_TEST_NODE.node_id),
            10,
            10,
        )
        self.assertIsNotNone(pkts)
        reply = _build_request_download_reply(
            FTM_DIRSRV_SOURCE,
            len(content),
            unpack_method=0,
            override_filename=False,
            fast_path=False,
        )[2:]
        self.assertEqual(struct.unpack_from("<I", reply, 0x14)[0], 0)
        self.assertEqual(struct.unpack_from("<I", reply, 0x08)[0], len(content))
        self.assertEqual(struct.unpack_from("<I", reply, 0x0C)[0], len(content))

    def test_seeded_compressed_node_serves_a_real_container(self):
        """The captured DLRed upload, so the MOS2 path needs no re-upload."""
        from server.store import fixtures

        source, content = _resolve_ftm_target(
            _make_dirsrv_file_request(fixtures._DNR_MOS2_NODE.node_id)
        )

        self.assertEqual(source, FTM_DIRSRV_SOURCE)
        self.assertEqual(len(content), fixtures.DNR_MOS2_COMPRESSED_SIZE)
        self.assertEqual(mos2_original_size(content), 107520)
        self.assertEqual(
            [f"{s}-{e}" for s, e in mos2_chunk_spans(content)],
            ["20-17063", "17063-35079", "35079-45864", "45864-51700"],
        )

    def test_server_built_container_round_trips(self):
        """The seeded container must decode back to WINDIFF.EXE exactly.

        A MOS2 chunk is raw DEFLATE behind a "CK" marker, so the container is
        built here rather than by the client, whose HrMos2CompFile emits
        streams that do not decode back to their input.
        """
        import sys
        import zlib

        sys.path.insert(0, "tools")
        from mos2_compress import CHUNK, MARKER

        from server.store import fixtures

        blob = fixtures.DNR_MOS2OK_PATH.read_bytes()
        self.assertEqual(len(blob), fixtures.DNR_MOS2OK_COMPRESSED_SIZE)
        total = mos2_original_size(blob)
        self.assertEqual(total, 107520)

        pos, out = 0x14, b""
        for _ in range(-(-total // CHUNK)):
            length = struct.unpack_from("<I", blob, pos)[0]
            pos += 4
            body = blob[pos : pos + length]
            pos += length
            self.assertEqual(body[:2], MARKER)
            # FUN_7F6B55B0 refuses a record longer than chunk + 7.
            self.assertLessEqual(length, CHUNK + 7)
            d = zlib.decompressobj(-15)
            out += (d.decompress(body[2:]) + d.flush())[:CHUNK]

        # Digest rather than a second copy of the binary.
        self.assertEqual(len(out), total)
        self.assertEqual(hashlib.md5(out).hexdigest(), "2591b2b19f3edfba8180aac8df673a65")

    def test_mos2_header_is_validated_before_its_size_is_trusted(self):
        self.assertEqual(mos2_original_size(self.blob), self.ORIGINAL_SIZE)
        self.assertIsNone(mos2_original_size(b"MOS2" + b"\x00" * 32))
        self.assertIsNone(mos2_original_size(b"not a container"))


if __name__ == "__main__":
    unittest.main()
