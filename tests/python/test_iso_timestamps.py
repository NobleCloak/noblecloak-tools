"""ISO-8601 timestamp parsing must behave the same on every supported Python.

`datetime.fromisoformat` before 3.11 accepts only 3- or 6-digit fractional
seconds and no `Z` suffix. The script routes every timestamp parse through
`parse_iso8601`, which normalises first. These tests pin that.
"""
import datetime
import unittest

from _load_nc_export import load_nc_export

nc = load_nc_export()

UTC = datetime.timezone.utc
EST = datetime.timezone(datetime.timedelta(hours=-5))


class TestParseIso8601(unittest.TestCase):
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
    def test_window_bound_accepts_any_fraction_length_and_z(self):
        for text in (
            "2026-11-18T23:59:59.5-05:00",
            "2026-11-18T23:59:59.1234567-05:00",
            "2026-11-18T23:59:59.12Z",
            "2026-11-18T23:59:59Z",
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(nc._parse_window_bound("--export-window-end", text).tzinfo)

    def test_window_bound_errors_are_unchanged(self):
        with self.assertRaisesRegex(nc.ExportError, "is not an ISO-8601 timestamp"):
            nc._parse_window_bound("--export-window-end", "last tuesday")
        with self.assertRaisesRegex(nc.ExportError, "needs a UTC offset"):
            nc._parse_window_bound("--export-window-end", "2026-11-18T23:59:59.5")

    def test_window_bound_is_ordered_across_fraction_lengths(self):
        early = nc._parse_window_bound("s", "2026-11-18T00:00:00.1234567Z")
        late = nc._parse_window_bound("e", "2026-11-18T00:00:00.5Z")
        self.assertLess(early, late)

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
