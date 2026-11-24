"""ISO-8601 timestamp parsing must behave the same on every supported Python.

`datetime.fromisoformat` before 3.11 accepts only 3- or 6-digit fractional
seconds and no `Z` suffix. The script routes every timestamp parse through
`parse_iso8601`, which normalises first. These tests pin that.
"""
import datetime
import re
import unittest
from unittest import mock

from _load_nc_export import load_nc_export

nc = load_nc_export()

UTC = datetime.timezone.utc
EST = datetime.timezone(datetime.timedelta(hours=-5))


_STRICT_39_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.(\d{3}|\d{6}))?([+-]\d{2}:\d{2})?", re.ASCII
)


def strict_39_fromisoformat(value):
    """Stand-in for Python 3.9's fromisoformat: 3 or 6 fraction digits, no `Z`."""
    if _STRICT_39_RE.fullmatch(value) is None:
        raise ValueError(f"Invalid isoformat string: {value!r}")
    return datetime.datetime.fromisoformat(value)


class TestParseIso8601(unittest.TestCase):
    """Runs against a strict 3.9-style fromisoformat, so a 3.11+ job catches a regression too."""

    def setUp(self):
        patcher = mock.patch.object(nc, "_fromisoformat", strict_39_fromisoformat)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_stub_rejects_what_python_39_rejects(self):
        for text in ("2026-01-05T10:00:00.5+00:00", "2026-01-05T10:00:00Z", "2026-01-05T10:00:00.1234567+00:00"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                strict_39_fromisoformat(text)

    def test_fraction_lengths(self):
        cases = {
            "": 0,
            ".5": 500000,
            ".50": 500000,
            ".12345": 123450,
            ".123456": 123456,
            ".1234567": 123456,  # truncated, not rounded
            ".123456789": 123456,
            ".9999999": 999999,  # rounding would carry into the seconds
        }
        for fraction, micro in cases.items():
            with self.subTest(fraction=fraction):
                parsed = nc.parse_iso8601(f"2026-11-18T23:59:59{fraction}-05:00")
                self.assertEqual(parsed, datetime.datetime(2026, 11, 18, 23, 59, 59, micro, tzinfo=EST))
                self.assertEqual(parsed.second, 59)

    def test_z_suffix_is_utc(self):
        for text in ("2026-01-05T10:00:00Z", "2026-01-05T10:00:00.5Z", "2026-01-05T10:00:00.1234567Z"):
            with self.subTest(text=text):
                self.assertEqual(nc.parse_iso8601(text).utcoffset(), datetime.timedelta(0))

    def test_numeric_offsets(self):
        self.assertEqual(
            nc.parse_iso8601("2026-01-05T10:00:00+00:00"), datetime.datetime(2026, 1, 5, 10, tzinfo=UTC)
        )
        self.assertEqual(
            nc.parse_iso8601("2026-01-05T10:00:00-05:00").astimezone(UTC),
            datetime.datetime(2026, 1, 5, 15, tzinfo=UTC),
        )

    def test_no_offset_is_naive(self):
        self.assertIsNone(nc.parse_iso8601("2026-01-05T10:00:00.5").tzinfo)

    def test_invalid_input_raises_value_error(self):
        for text in ("last tuesday", "", "2026-13-05T10:00:00Z", "Z"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    nc.parse_iso8601(text)


class TestWindowBoundAndUtcConversion(unittest.TestCase):
    END = "2026-12-01T00:00:00Z"

    def test_window_bound_accepts_any_fraction_length_and_z(self):
        for text in (
            "2026-11-18T23:59:59.5-05:00",
            "2026-11-18T23:59:59.1234567-05:00",
            "2026-11-18T23:59:59.12Z",
            "2026-11-18T23:59:59Z",
        ):
            with self.subTest(text=text):
                self.assertTrue(nc._window_bound_utc("--export-window-end", text).endswith("Z"))

    def test_window_bound_errors(self):
        with self.assertRaisesRegex(nc.ExportError, "is not an ISO-8601 timestamp"):
            nc.resolve_export_window("last tuesday", self.END)
        for naive in ("2026-11-18T23:59:59.5", "2026-11-18T23:59:59"):
            with self.subTest(naive=naive), self.assertRaisesRegex(nc.ExportError, "needs a UTC offset"):
                nc.resolve_export_window(naive, self.END)

    def test_forms_outside_the_regexes_are_rejected_the_same_everywhere(self):
        # Newer Pythons' fromisoformat accepts some of these; the script must not.
        for text in (
            "2026-11-18T10:00:00-0500",
            "2026-11-18 10:00:00Z",
            "2026-11-18T10:00:00z",
            "2026-11-18T10:00:00,5Z",
            "2026-11-18T10:00:00ZZ",
        ):
            with self.subTest(text=text), self.assertRaisesRegex(nc.ExportError, "is not an ISO-8601 timestamp"):
                nc.resolve_export_window(text, self.END)

    def test_window_is_ordered_across_fraction_lengths(self):
        self.assertEqual(
            nc.resolve_export_window("2026-11-18T00:00:00.1234567Z", "2026-11-18T00:00:00.5Z"),
            {"start": "2026-11-18T00:00:00.1234567Z", "end": "2026-11-18T00:00:00.5Z"},
        )

    def test_sub_microsecond_inversion_is_rejected(self):
        cases = [
            ("2026-11-18T00:00:00.1234567Z", "2026-11-18T00:00:00.1234561Z"),
            # Mixed offsets: 10:00:00.1234567-05:00 is 15:00:00.1234567Z.
            ("2026-11-18T10:00:00.1234567-05:00", "2026-11-18T15:00:00.1234561Z"),
            ("2026-11-18T15:00:00.1234567Z", "2026-11-18T10:00:00.1234561-05:00"),
        ]
        for start, end in cases:
            with self.subTest(start=start, end=end), self.assertRaisesRegex(nc.ExportError, "is after"):
                nc.resolve_export_window(start, end)

    def test_equal_instants_are_accepted(self):
        self.assertIsNotNone(
            nc.resolve_export_window("2026-11-18T10:00:00.1234567-05:00", "2026-11-18T15:00:00.1234567Z")
        )

    def test_resolve_export_window_with_odd_fractions(self):
        self.assertEqual(
            nc.resolve_export_window("2026-11-11T00:00:00.12-05:00", "2026-11-18T23:59:59.1234567-05:00"),
            {"start": "2026-11-11T05:00:00.12Z", "end": "2026-11-19T04:59:59.1234567Z"},
        )

    def test_console_csv_date_formats(self):
        # The Admin console writes local time with an offset; the Reports API writes Z.
        self.assertEqual(nc.to_utc_z("2026-11-18T14:08:23-05:00"), "2026-11-18T19:08:23Z")
        self.assertEqual(nc.to_utc_z("2026-11-18T14:08:23.5-05:00"), "2026-11-18T19:08:23.5Z")
        self.assertEqual(nc.to_utc_z("2026-11-18T14:08:23.1234567-05:00"), "2026-11-18T19:08:23.1234567Z")
        self.assertEqual(nc.to_utc_z("2026-11-18T19:08:23.5Z"), "2026-11-18T19:08:23.5Z")

    def test_to_utc_z_still_rejects_invalid_input(self):
        for text in ("last tuesday", "2026-11-18T14:08:23", "2026-13-18T14:08:23-05:00"):
            with self.subTest(text=text):
                self.assertIsNone(nc.to_utc_z(text))


if __name__ == "__main__":
    unittest.main()
