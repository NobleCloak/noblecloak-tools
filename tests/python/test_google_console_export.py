"""CLI-level tests for `nc-export.py google` reading the Admin console download.

The Google Admin console's Reporting > Audit and investigation > OAuth log
events > Download > CSV file uses display-name headers (`Date`, `App ID`,
`App name`, `User`, `Scope`, `OAuth event`, ...), separates scopes with
", ", and includes non-Authorize events (e.g. `Revoke`). These tests pin
that the script reads that file as downloaded, with no hand conversion.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NC_EXPORT = REPO_ROOT / "scripts" / "nc-export.py"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from def_validator import validate_def_file

SALT = "a0891513aba11b839e9a5072e4e8fc3de92477b14428a45f67ad7aba856063f5"

# Header row exactly as the Admin console wrote it on 2026-11-18.
CONSOLE_HEADER = (
    "Date,App ID,App name,OAuth event,Description,User,Scope,API name,Method,"
    "Number of response bytes,IP address,Product,Client type,Network info,"
    "By an agent,Agent info,User approved\n"
)
API_HEADER = "time,actorEmail,clientId,displayText,scopes\n"


def console_row(date, app_id, app_name, event, user, scope):
    # Unused console columns are left blank; Scope is quoted because it holds ", ".
    return f'{date},{app_id},{app_name},{event},,{user},"{scope}",,,,,,Web,,false,,false\n'


def run(args, cwd):
    return subprocess.run(
        [sys.executable, str(NC_EXPORT), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


class TestGoogleConsoleExport(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.salt_file = self.tmp / "salt.txt"
        self.salt_file.write_text(SALT + "\n", encoding="utf-8")

    def _write(self, name: str, content: str, bom: bool = False) -> pathlib.Path:
        path = self.tmp / name
        data = content.encode("utf-8")
        path.write_bytes((b"\xef\xbb\xbf" + data) if bom else data)
        return path

    def _export(self, audit: pathlib.Path, *extra, out_dir=None):
        return run(
            [
                "google",
                "--audit-csv", str(audit),
                "--out-dir", str(out_dir or self.out_dir),
                "--salt-file", str(self.salt_file),
                "--generated-at", "2026-08-17T00:00:00Z",
                *extra,
            ],
            cwd=self.tmp,
        )

    def _lines(self, out_dir=None):
        text = ((out_dir or self.out_dir) / "discover-export.ndjson").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()]

    def test_console_download_matches_the_same_data_in_api_columns(self):
        console = self._write(
            "console.csv",
            CONSOLE_HEADER
            + console_row(
                "2026-01-05T10:00:00Z", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                "alice@example.com",
                "https://www.googleapis.com/auth/drive.readonly, https://www.googleapis.com/auth/userinfo.email",
            ),
        )
        api = self._write(
            "api.csv",
            API_HEADER
            + "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,"
            "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/userinfo.email\n",
        )
        r1 = self._export(console)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        api_out = self.tmp / "api-out"
        r2 = self._export(api, out_dir=api_out)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(
            (self.out_dir / "discover-export.ndjson").read_bytes(),
            (api_out / "discover-export.ndjson").read_bytes(),
        )

    def test_comma_separated_scopes_become_separate_scopes(self):
        audit = self._write(
            "console.csv",
            CONSOLE_HEADER
            + console_row(
                "2026-01-05T10:00:00Z", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                "alice@example.com", "https://www.googleapis.com/auth/userinfo.email, openid",
            ),
        )
        result = self._export(audit)
        self.assertEqual(result.returncode, 0, result.stderr)
        grant = self._lines()[1]
        self.assertEqual(grant["scopes"], ["https://www.googleapis.com/auth/userinfo.email", "openid"])

    def test_comma_separated_scopes_in_api_columns_are_split_too(self):
        audit = self._write(
            "api.csv",
            API_HEADER
            + '2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,'
            '"https://www.googleapis.com/auth/userinfo.email,openid"\n',
        )
        result = self._export(audit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._lines()[1]["scopes"], ["https://www.googleapis.com/auth/userinfo.email", "openid"]
        )

    def test_non_authorize_events_are_ignored_not_skipped(self):
        audit = self._write(
            "console.csv",
            CONSOLE_HEADER
            + console_row(
                "2026-01-05T10:00:00Z", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                "alice@example.com", "openid",
            )
            + console_row(
                "2026-01-06T10:00:00Z", "222-bbb.apps.googleusercontent.com", "Zoom", "Revoke",
                "bob@example.com", "openid",
            ),
        )
        result = self._export(audit)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = self._lines()
        self.assertEqual(len(lines), 2)  # header + the Authorize grant only
        self.assertEqual(lines[1]["appDisplayName"], "Slack")
        # A Revoke is not a malformed grant row, so it is not counted as skipped.
        self.assertEqual(lines[0]["skippedRows"], 0)
        self.assertIn("Skipped rows: 0", result.stdout)
        self.assertIn("1 non-Authorize event", result.stderr)
        self.assertNotIn("bob@example.com", result.stderr)

    def test_console_row_missing_user_is_skipped_with_warning(self):
        audit = self._write(
            "console.csv",
            CONSOLE_HEADER
            + console_row(
                "2026-01-05T10:00:00Z", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize", "  ", "openid",
            ),
        )
        result = self._export(audit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("User", result.stderr)
        self.assertEqual(self._lines()[0]["skippedRows"], 1)

    def test_utf8_bom_on_the_header_is_accepted(self):
        for header, row in (
            (CONSOLE_HEADER, console_row(
                "2026-01-05T10:00:00Z", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                "alice@example.com", "openid",
            )),
            (API_HEADER, "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n"),
        ):
            with self.subTest(header=header[:10]):
                audit = self._write("bom.csv", header + row, bom=True)
                out_dir = self.tmp / ("out-" + header[:4])
                result = self._export(audit, out_dir=out_dir)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(self._lines(out_dir)), 2)

    def test_unrecognized_header_names_both_accepted_layouts(self):
        audit = self._write("odd.csv", "when,who,what\n2026-01-05T10:00:00Z,alice@example.com,Slack\n")
        result = self._export(audit)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("actorEmail", result.stderr)
        self.assertIn("App ID", result.stderr)
        self.assertFalse(self.out_dir.exists())


# Header row of the Admin console's Directory > Users > Download users >
# "All user info columns" > CSV, exactly as written on 2026-11-18.
CONSOLE_USERS_HEADER = (
    "First Name [Required],Last Name [Required],Email Address [Required],Password [Required],"
    "Password Hash Function [UPLOAD ONLY],Org Unit Path [Required],New Primary Email [UPLOAD ONLY],"
    "Status [READ ONLY],Last Sign In [READ ONLY],Recovery Email,Home Secondary Email,Work Secondary Email\n"
)


def console_user(email, status="Active", recovery=""):
    return f"A,B,{email},****,,/,,{status},Never logged in,{recovery},,\n"


class TestGoogleConsoleUsersDownload(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.audit = self.tmp / "api.csv"
        self.audit.write_text(
            API_HEADER + "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n",
            encoding="utf-8",
        )

    def _export(self, users: pathlib.Path):
        return run(
            ["google", "--audit-csv", str(self.audit), "--users-csv", str(users), "--out-dir", str(self.out_dir)],
            cwd=self.tmp,
        )

    def _header(self):
        first = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0]
        return json.loads(first)

    def test_console_users_download_counts_every_directory_user(self):
        users = self.tmp / "users.csv"
        users.write_text(
            CONSOLE_USERS_HEADER
            + console_user("alice@example.com", recovery="alice.home@example.org")
            + console_user("Bob@Example.com")
            + console_user("bob@example.com")  # same user, different case
            + console_user("carol@example.com", status="Suspended"),
            encoding="utf-8",
        )
        result = self._export(users)
        self.assertEqual(result.returncode, 0, result.stderr)
        # A suspended account is still a directory user; a recovery address is not a user.
        self.assertEqual(self._header()["userCountTotal"], 3)

    def test_users_csv_with_bom_is_accepted_in_both_layouts(self):
        # The `email` layout is the one a BOM breaks: there the email column is
        # the first header, so an unstripped BOM renames it to "﻿email".
        for name, content in (
            ("api", "email\nalice@example.com\n"),
            ("console", CONSOLE_USERS_HEADER + console_user("alice@example.com")),
        ):
            with self.subTest(layout=name):
                users = self.tmp / f"users-{name}.csv"
                users.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
                self.out_dir = self.tmp / f"out-{name}"
                result = self._export(users)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self._header()["userCountTotal"], 1)

    def test_users_csv_without_an_email_column_names_both_accepted_headers(self):
        users = self.tmp / "users.csv"
        users.write_text("Date,Event status,User,Event\n2026-01-05T10:00:00Z,,alice@example.com,Login\n", encoding="utf-8")
        result = self._export(users)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("'email'", result.stderr)
        self.assertIn("Email Address [Required]", result.stderr)
        self.assertFalse(self.out_dir.exists())


class TestGoogleExportWindow(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"
        self.audit = self.tmp / "api.csv"
        self.audit.write_text(
            API_HEADER + "2026-01-05T10:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n",
            encoding="utf-8",
        )

    def _export(self, *extra):
        return run(
            ["google", "--audit-csv", str(self.audit), "--out-dir", str(self.out_dir), *extra],
            cwd=self.tmp,
        )

    def _header(self):
        first = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0]
        return json.loads(first)

    def test_window_is_null_without_the_flags(self):
        result = self._export()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(self._header()["exportWindow"])

    def test_window_flags_are_written_in_utc(self):
        result = self._export(
            "--export-window-start", "2026-11-11T00:00:00-05:00",
            "--export-window-end", "2026-11-18T23:59:59.5-05:00",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._header()["exportWindow"],
            {"start": "2026-11-11T05:00:00Z", "end": "2026-11-19T04:59:59.5Z"},
        )
        validate_def_file(self.out_dir / "discover-export.ndjson")

    def test_window_flags_already_in_utc_are_unchanged(self):
        result = self._export(
            "--export-window-start", "2026-01-01T00:00:00Z", "--export-window-end", "2026-01-31T23:59:59Z"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self._header()["exportWindow"], {"start": "2026-01-01T00:00:00Z", "end": "2026-01-31T23:59:59Z"}
        )

    def test_one_window_flag_without_the_other_errors(self):
        for flag in ("--export-window-start", "--export-window-end"):
            with self.subTest(flag=flag):
                result = self._export(flag, "2026-01-01T00:00:00Z")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("both", result.stderr)
                self.assertFalse(self.out_dir.exists())

    def test_invalid_window_timestamp_errors(self):
        result = self._export("--export-window-start", "last tuesday", "--export-window-end", "2026-01-31T00:00:00Z")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ISO-8601", result.stderr)
        self.assertFalse(self.out_dir.exists())

    def test_window_start_after_end_errors(self):
        result = self._export(
            "--export-window-start", "2026-02-01T00:00:00Z", "--export-window-end", "2026-01-01T00:00:00Z"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("after", result.stderr)
        self.assertFalse(self.out_dir.exists())

    def test_window_without_an_offset_errors(self):
        # Both bounds lack an offset, so they would compare cleanly: only the
        # offset check can refuse this (a naive/aware pair would fail on the
        # comparison instead and hide a missing check).
        result = self._export(
            "--export-window-start", "2026-01-01T00:00:00", "--export-window-end", "2026-01-31T00:00:00"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("needs a UTC offset", result.stderr)
        self.assertFalse(self.out_dir.exists())


class TestGoogleTimestampsInUtc(unittest.TestCase):
    """Discover accepts only UTC `Z` timestamps; the console writes local offsets."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = pathlib.Path(self._tmp.name)
        self.out_dir = self.tmp / "out"

    def _export(self, content: str):
        audit = self.tmp / "audit.csv"
        audit.write_text(content, encoding="utf-8")
        return run(["google", "--audit-csv", str(audit), "--out-dir", str(self.out_dir)], cwd=self.tmp)

    def _grants(self):
        text = (self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8")
        return [json.loads(line) for line in text.splitlines()[1:]]

    def test_offset_times_become_utc_and_keep_fractional_digits(self):
        result = self._export(
            CONSOLE_HEADER
            + console_row("2026-11-17T12:44:17-05:00", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                          "alice@example.com", "openid")
            + console_row("2026-11-18T10:38:26.1230-05:00", "111-aaa.apps.googleusercontent.com", "Slack",
                          "Authorize", "alice@example.com", "openid")
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        grant = self._grants()[0]
        self.assertEqual(grant["firstSeen"], "2026-11-17T17:44:17Z")
        self.assertEqual(grant["lastUsed"], "2026-11-18T15:38:26.1230Z")
        validate_def_file(self.out_dir / "discover-export.ndjson")

    def test_min_and_max_across_mixed_offsets_use_the_instant(self):
        # 01:30-05:00 is 06:30Z, later than 05:00+00:00 (05:00Z) though it sorts
        # first as text. Across a DST change one file carries both -04:00 and -05:00.
        result = self._export(
            CONSOLE_HEADER
            + console_row("2026-11-01T01:30:00-05:00", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                          "alice@example.com", "openid")
            + console_row("2026-11-01T05:00:00+00:00", "111-aaa.apps.googleusercontent.com", "Slack", "Authorize",
                          "alice@example.com", "openid")
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        grant = self._grants()[0]
        self.assertEqual(grant["firstSeen"], "2026-11-01T05:00:00Z")
        self.assertEqual(grant["lastUsed"], "2026-11-01T06:30:00Z")

    def test_time_without_an_offset_is_skipped_with_warning(self):
        result = self._export(
            API_HEADER
            + "2026-11-17T12:44:17,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n"
            + "2026-11-17T12:44:17Z,bob@example.com,222-bbb.apps.googleusercontent.com,Zoom,openid\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("UTC offset", result.stderr)
        self.assertNotIn("alice@example.com", result.stderr)
        grants = self._grants()
        self.assertEqual([g["appDisplayName"] for g in grants], ["Zoom"])
        header = json.loads((self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(header["skippedRows"], 1)

    def test_min_and_max_compare_fractional_seconds_as_time_not_text(self):
        # As text, "00.5Z" sorts before "00Z" ('.' < 'Z'), which would make
        # firstSeen later than lastUsed. Offset conversion keeps fractional
        # digits, so one console file can mix both lengths.
        result = self._export(
            API_HEADER
            + "2026-01-01T00:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n"
            + "2026-01-01T00:00:00.5Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        grant = self._grants()[0]
        self.assertEqual(grant["firstSeen"], "2026-01-01T00:00:00Z")
        self.assertEqual(grant["lastUsed"], "2026-01-01T00:00:00.5Z")

    def test_invalid_or_non_ascii_times_are_skipped_not_emitted(self):
        rows = [
            "2026-13-45T99:99:99Z",                 # matches the shape, not a real time
            "\uff12\uff10\uff12\uff16-01-01T00:00:00Z",  # fullwidth digits
            "0001-01-01T00:00:00+01:00",            # shifts before year 1
        ]
        body = "".join(
            f"{t},user{i}@example.com,{i}-x.apps.googleusercontent.com,App{i},openid\n" for i, t in enumerate(rows)
        )
        result = self._export(API_HEADER + body + "2026-01-01T00:00:00Z,ok@example.com,ok.apps.googleusercontent.com,Ok,openid\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([g["appDisplayName"] for g in self._grants()], ["Ok"])
        header = json.loads((self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(header["skippedRows"], 3)

    def test_early_year_is_zero_padded(self):
        result = self._export(
            API_HEADER + "0999-06-01T12:00:00+02:00,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._grants()[0]["firstSeen"], "0999-06-01T10:00:00Z")

    def test_header_with_both_layouts_still_filters_on_oauth_event(self):
        header = "time,actorEmail,clientId,displayText,scopes,OAuth event\n"
        result = self._export(
            header
            + "2026-01-01T00:00:00Z,alice@example.com,111-aaa.apps.googleusercontent.com,Slack,openid,Authorize\n"
            + "2026-01-02T00:00:00Z,bob@example.com,222-bbb.apps.googleusercontent.com,Miro,openid,Revoke\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([g["appDisplayName"] for g in self._grants()], ["Slack"])
        self.assertIn("1 non-Authorize event", result.stderr)

    def test_generated_at_override_must_be_utc(self):
        audit = self.tmp / "a.csv"
        audit.write_text(API_HEADER, encoding="utf-8")
        result = run(
            ["google", "--audit-csv", str(audit), "--out-dir", str(self.out_dir), "--generated-at", "2026-11-18T10:00:00-05:00"],
            cwd=self.tmp,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        header = json.loads((self.out_dir / "discover-export.ndjson").read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(header["generatedAt"], "2026-11-18T15:00:00Z")


if __name__ == "__main__":
    unittest.main()
