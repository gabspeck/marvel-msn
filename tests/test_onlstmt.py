"""Tests for the Online Statement (ONLSTMT) service handler.

Covers the static payload builders, period dispatch, record encoding
quirks, and the wire-format invariants documented in onlstmt.py:

  * summary's trailing period-count byte (drives Get-Details listbox)
  * days_wire bias (must be >= 0x63e0 for non-1970 dates)
  * JPY whole-yen scale on the flag-0x02 exchange-rate tail
  * 0x87 end-static terminator for static-only replies
  * cancel-ack success byte (anything other than 1 trips error 0x2d)
"""
import datetime
import io
import struct
import unittest
from contextlib import redirect_stdout

from server.services.onlstmt import (
    OnlStmtHandler,
    _CANCEL_ACK_PAYLOAD,
    _DETAILS_PAYLOADS,
    _DETAILS_RECORDS_BY_PERIOD,
    _PLANS_PAYLOAD,
    _SUBSCRIPTIONS_PAYLOAD,
    _SUMMARY_PAYLOAD,
    _encode_record,
    _encode_timestamp,
)
from server.config import TAG_END_STATIC
from server.mpc import parse_host_block, parse_tagged_params
from server.models import (
    ByteParam, DwordParam, EndMarker, VarParam, WordParam,
)
from server.transport import parse_packet


def _extract_host_block(wire_packets):
    """Strip transport+pipe framing from a single-frame service packet."""
    assert len(wire_packets) == 1, "expected one packet, got fragmentation"
    raw = wire_packets[0]
    # parse_packet wants the packet without the trailing terminator byte.
    pkt = parse_packet(raw[:-1])
    assert pkt is not None and pkt.crc_ok, "packet failed transport parse"
    # Frame: pipe header byte + 2-byte length prefix + 2-byte routing
    # prefix + host block
    return pkt.payload[1 + 2 + 2:]


class TestSummaryPayload(unittest.TestCase):
    """Static section: 7 tagged primitives in fixed order."""

    def test_parses_to_seven_primitives(self):
        params = parse_tagged_params(_SUMMARY_PAYLOAD)
        self.assertEqual(len(params), 7)
        kinds = [type(p) for p in params]
        self.assertEqual(kinds, [
            DwordParam, WordParam, WordParam,
            ByteParam, ByteParam, WordParam, ByteParam,
        ])

    def test_currency_slot_is_usd(self):
        params = parse_tagged_params(_SUMMARY_PAYLOAD)
        self.assertEqual(params[1].value, 840)  # ISO 4217 USD

    def test_period_count_byte_is_three(self):
        # Last primitive = period_count - 1; client clamps to max 4.
        # 0 here would shrink the Get-Details period listbox to one row.
        params = parse_tagged_params(_SUMMARY_PAYLOAD)
        self.assertEqual(params[-1].value, 3)

    def test_period_count_byte_position_pinned(self):
        # The last byte of the static reply IS the period counter.
        # Pin the byte position to catch a re-order regression.
        self.assertEqual(_SUMMARY_PAYLOAD[-1], 3)
        self.assertEqual(_SUMMARY_PAYLOAD[-2], 0x81)


class TestDetailsPayloads(unittest.TestCase):
    def test_one_payload_per_period(self):
        self.assertEqual(len(_DETAILS_PAYLOADS), 4)
        self.assertEqual(len(_DETAILS_RECORDS_BY_PERIOD), 4)

    def test_each_payload_has_dynamic_complete_tag(self):
        # Reply must end with a 0x86 dynamic-complete blob — the
        # client's m10 hangs forever otherwise (per onlstmt.py docstring).
        for period, payload in enumerate(_DETAILS_PAYLOADS):
            with self.subTest(period=period):
                self.assertIn(b"\x86", payload)
                # 0x87 end-static must precede the 0x86 blob.
                idx_87 = payload.index(TAG_END_STATIC)
                idx_86 = payload.index(b"\x86")
                self.assertLess(idx_87, idx_86)

    def test_record_count_word_matches_period(self):
        # First static word = record count for that period.
        for period, payload in enumerate(_DETAILS_PAYLOADS):
            with self.subTest(period=period):
                self.assertEqual(payload[0], 0x82)
                count = struct.unpack("<H", payload[1:3])[0]
                self.assertEqual(count, len(_DETAILS_RECORDS_BY_PERIOD[period]))


class TestDetailsPeriodDispatch(unittest.TestCase):
    def setUp(self):
        self.handler = OnlStmtHandler(pipe_idx=1, svc_name="OnlStmt")

    def _dispatch(self, payload):
        with redirect_stdout(io.StringIO()):
            wire = self.handler.handle_request(
                msg_class=0x01, selector=0x05, request_id=0,
                payload=payload, server_seq=0, client_ack=0,
            )
        host_block = _extract_host_block(wire)
        parsed = parse_host_block(host_block)
        return parsed.payload

    def test_period_zero_returned_for_period_byte_0(self):
        reply = self._dispatch(b"\x01\x00")
        self.assertEqual(reply, _DETAILS_PAYLOADS[0])

    def test_period_three_returned_for_period_byte_3(self):
        reply = self._dispatch(b"\x01\x03")
        self.assertEqual(reply, _DETAILS_PAYLOADS[3])

    def test_period_clamped_when_out_of_range(self):
        # Anything >= 4 falls back to current period.
        reply = self._dispatch(b"\x01\x09")
        self.assertEqual(reply, _DETAILS_PAYLOADS[0])

    def test_empty_payload_falls_back_to_period_zero(self):
        reply = self._dispatch(b"")
        self.assertEqual(reply, _DETAILS_PAYLOADS[0])

    def test_missing_send_byte_tag_falls_back_to_period_zero(self):
        # If the leading tag isn't 0x01 (send byte), treat as period 0.
        reply = self._dispatch(b"\x02\x03")
        self.assertEqual(reply, _DETAILS_PAYLOADS[0])


class TestDetailsRecordEncoding(unittest.TestCase):
    WHEN = datetime.datetime(2026, 4, 1, 9, 15)

    def test_plain_record_no_flags(self):
        rec = _encode_record(self.WHEN, "X", 100, 200)
        self.assertEqual(rec[0], 0x00)
        days_wire, minutes = struct.unpack("<HH", rec[1:5])
        expected_days, expected_min = _encode_timestamp(self.WHEN)
        self.assertEqual(days_wire, expected_days)
        self.assertEqual(minutes, expected_min)
        # description NUL-terminated, then amount, total — no tail.
        self.assertEqual(rec[5:7], b"X\x00")
        amount, total = struct.unpack("<II", rec[7:15])
        self.assertEqual(amount, 100)
        self.assertEqual(total, 200)
        self.assertEqual(len(rec), 15)

    def test_extra_only_sets_flag_bit_0(self):
        rec = _encode_record(self.WHEN, "X", 100, 200, extra=42)
        self.assertEqual(rec[0], 0x01)
        # +4 bytes for trailing dword, no exchange-rate tail.
        self.assertEqual(len(rec), 19)
        extra = struct.unpack("<I", rec[15:19])[0]
        self.assertEqual(extra, 42)

    def test_foreign_only_sets_flag_bit_1_with_jpy_whole_yen(self):
        # JPY (392) NumDigits=0: foreign dword is whole yen, NOT minor
        # units.  Caller passes 1000 => renders as ¥1,000 (not ¥10).
        rec = _encode_record(self.WHEN, "X", 670, 1389,
                             foreign=(1000, 392, 67))
        self.assertEqual(rec[0], 0x02)
        # 1 + 4 + 2 + 8 + 10 (fx tail) = 25 bytes
        self.assertEqual(len(rec), 25)
        fx_amount, fx_currency, fx_rate = struct.unpack("<IHI", rec[15:25])
        self.assertEqual(fx_amount, 1000)
        self.assertEqual(fx_currency, 392)
        self.assertEqual(fx_rate, 67)

    def test_both_flags_set_when_both_provided(self):
        rec = _encode_record(self.WHEN, "X", 100, 200,
                             extra=7, foreign=(1, 840, 1))
        self.assertEqual(rec[0], 0x03)
        # Layout: ... amount, total, extra dword, then 10-byte fx tail.
        self.assertEqual(len(rec), 1 + 4 + 2 + 8 + 4 + 10)


class TestDaysWireBias(unittest.TestCase):
    """Client decoder requires (days_since_1970 + 0x63df) & 0xFFFF >= 0x63e0,
    else it zeroes the days and renders 1970-01-01."""

    def test_known_date_matches_formula(self):
        when = datetime.datetime(2026, 4, 1)
        days = (when - datetime.datetime(1970, 1, 1)).days
        days_wire, minutes = _encode_timestamp(when)
        self.assertEqual(days_wire, (days + 0x63df) & 0xFFFF)
        self.assertEqual(minutes, 0)

    def test_minutes_packed_as_seconds_div_60(self):
        when = datetime.datetime(2026, 4, 1, 14, 37)
        _, minutes = _encode_timestamp(when)
        self.assertEqual(minutes, 14 * 60 + 37)

    def test_2030_jan_1_above_safety_threshold(self):
        days_wire, _ = _encode_timestamp(datetime.datetime(2030, 1, 1))
        self.assertGreaterEqual(days_wire, 0x63e0)

    def test_records_in_real_payloads_above_safety_threshold(self):
        # Sanity: every record in our fixture data passes the gate.
        for period_records in _DETAILS_RECORDS_BY_PERIOD:
            for rec in period_records:
                days_wire = struct.unpack("<H", rec[1:3])[0]
                self.assertGreaterEqual(days_wire, 0x63e0)

    def test_wraps_within_16_bits(self):
        # Far-future date sums past 0x10000 — verify the mask applies
        # rather than overflowing.  2100-01-01 lands in the wrap region.
        days_wire, _ = _encode_timestamp(datetime.datetime(2100, 1, 1))
        self.assertEqual(days_wire & ~0xFFFF, 0)


class TestSubscriptionsPayload(unittest.TestCase):
    def test_ends_with_end_static(self):
        self.assertEqual(_SUBSCRIPTIONS_PAYLOAD[-1], TAG_END_STATIC)

    def test_no_dynamic_section(self):
        self.assertNotIn(b"\x86", _SUBSCRIPTIONS_PAYLOAD)

    def test_has_eleven_static_primitives(self):
        params = parse_tagged_params(_SUBSCRIPTIONS_PAYLOAD)
        # 11 data primitives + 1 EndMarker
        self.assertEqual(len(params), 12)
        self.assertIsInstance(params[-1], EndMarker)

    def test_balance_currency_is_valid_iso_4217(self):
        # Slot 3 = balance currency code, used to format the threshold
        # billing line at the bottom of the tab.  ≠ 0 passes the error
        # 0x1e gate, but a code not in g_rgISOCurrencyCodes renders as
        # "unknown currency" — must be a real ISO 4217 numeric code.
        params = parse_tagged_params(_SUBSCRIPTIONS_PAYLOAD)
        self.assertEqual(params[3].value, 840)  # USD

    def test_slot4_flag_nonzero(self):
        # Slot 4 byte stored on dialog state +0x0c; purpose unclear but
        # must be non-zero (matches captured server replies).
        params = parse_tagged_params(_SUBSCRIPTIONS_PAYLOAD)
        self.assertNotEqual(params[4].value, 0)


class TestPlansPayload(unittest.TestCase):
    def test_ends_with_end_static(self):
        self.assertEqual(_PLANS_PAYLOAD[-1], TAG_END_STATIC)

    def test_count_byte_matches_records(self):
        # First primitive = byte plan_count; it gates listbox 0x418.
        params = parse_tagged_params(_PLANS_PAYLOAD)
        self.assertIsInstance(params[0], ByteParam)
        self.assertEqual(params[0].value, 3)

    def test_plan_blob_contains_three_records_with_ids_0_1_2(self):
        params = parse_tagged_params(_PLANS_PAYLOAD)
        blob = params[1].data
        # Record layout: byte flag=0x01, word plan_id, cstr name, cstr detail
        seen_ids = []
        pos = 0
        while pos < len(blob):
            self.assertEqual(blob[pos], 0x01)  # flag always 0x01
            pos += 1
            plan_id = struct.unpack("<H", blob[pos:pos + 2])[0]
            seen_ids.append(plan_id)
            pos += 2
            # consume two NUL-terminated cstrs
            for _ in range(2):
                end = blob.index(b"\x00", pos)
                pos = end + 1
        self.assertEqual(seen_ids, [0, 1, 2])


class TestCancelAck(unittest.TestCase):
    def test_payload_is_success_byte_then_end_static(self):
        # Anything other than success byte=1 triggers error string 0x2d.
        self.assertEqual(_CANCEL_ACK_PAYLOAD, b"\x81\x01\x87")


class TestUnknownSelectorReturnsNone(unittest.TestCase):
    def test_unhandled_selector_returns_none(self):
        handler = OnlStmtHandler(pipe_idx=1, svc_name="OnlStmt")
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = handler.handle_request(
                msg_class=0x01, selector=0x09, request_id=0,
                payload=b"", server_seq=0, client_ack=0,
            )
        self.assertIsNone(result)
        self.assertIn("UNHANDLED", buf.getvalue())

    def test_oneway_continuation_returns_none(self):
        # MPC_CLASS_ONEWAY_MASK in msg_class -> drop without reply.
        handler = OnlStmtHandler(pipe_idx=1, svc_name="OnlStmt")
        with redirect_stdout(io.StringIO()):
            result = handler.handle_request(
                msg_class=0xE6, selector=0x05, request_id=0,
                payload=b"data", server_seq=0, client_ack=0,
            )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
