#!/usr/bin/env python3
"""nc-export.py -- offline, zero-network export to the Discover Export Format (DEF) v1.

Reads a Google Workspace OAuth Token Audit CSV (and optionally a Users
CSV) or a Microsoft Entra ID users/servicePrincipals/oauth2PermissionGrants
JSON triplet (and optionally an appRoleAssignments JSON export), and
writes a pseudonymized (by default) DEF v1 NDJSON file.

See spec/discover-export-format-v1.md for the exact output format this
script must produce, and fixtures/ for golden input/output pairs.

This script performs no network I/O. It only reads the local files named
on the command line and writes to --out-dir.

Requires Python 3.9 or newer (the standard library only). macOS's built-in
python3 is 3.9.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from typing import Optional

DEF_KIND = "discover-export"
DEF_VERSION = "1"
HASH_ALGO = "hmac-sha256"

# Printed to stdout after a successful run. This is the core trust/UX
# guarantee of the tool -- the operator gets explicit, on-screen
# confirmation that nothing left the machine. Kept identical (same text)
# to the closing message nc-export-entra.ps1 prints -- see
# spec/discover-export-format-v1.md and README.md's privacy model.
CLOSING_MESSAGE = (
    "Nothing has been sent anywhere. Review discover-export.ndjson, "
    "then upload it in the Discover app."
)

HEADER_KEYS = [
    "kind",
    "version",
    "vendor",
    "generatedAt",
    "pseudonymized",
    "hashAlgo",
    "script",
    "exportWindow",
    "userCountTotal",
    "skippedRows",
]

GRANT_KEYS = [
    "userRef",
    "consentType",
    "clientId",
    "appDisplayName",
    "scopes",
    "firstSeen",
    "lastUsed",
]

GOOGLE_AUDIT_REQUIRED_COLUMNS = ["time", "actorEmail", "clientId", "displayText", "scopes"]
# scopes is intentionally excluded here: per spec/discover-export-format-v1.md
# grant.scopes "May be empty" -- an empty scopes cell is valid input, not a
# malformed row, and must not be skipped the way a missing actorEmail is.
GOOGLE_AUDIT_REQUIRED_NONEMPTY_COLUMNS = ["time", "actorEmail", "clientId", "displayText"]

# The Admin console's own download (Reporting > Audit and investigation >
# OAuth log events > Download > CSV) names the same fields differently, and
# also carries an "OAuth event" column. Maps each canonical column above to
# its console header.
GOOGLE_CONSOLE_COLUMNS = {
    "time": "Date",
    "actorEmail": "User",
    "clientId": "App ID",
    "displayText": "App name",
    "scopes": "Scope",
}
GOOGLE_CONSOLE_EVENT_COLUMN = "OAuth event"
# Only an Authorize event is evidence of a grant. Every other event (e.g.
# Revoke) is left out of the export: it is not a grant row, so it is not
# counted in skippedRows either.
GOOGLE_GRANT_EVENT = "Authorize"
GOOGLE_USERS_REQUIRED_COLUMNS = ["email"]
# The Admin console's Directory > Users > Download users CSV names the
# primary address "Email Address [Required]". Only that column counts:
# recovery and secondary addresses are not directory users.
GOOGLE_CONSOLE_USERS_EMAIL_COLUMN = "Email Address [Required]"

OWNER_ONLY_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0600


class ExportError(Exception):
    """Raised for any user-facing export failure (bad input, missing file, ...)."""


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _is_blank(value) -> bool:
    """True when value is missing (None) or, if a string, empty/whitespace-only."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return value.strip() == ""


def derive_user_ref(salt_bytes: bytes, email: str, pseudonymized: bool) -> str:
    normalized = normalize_email(email)
    if not pseudonymized:
        return normalized
    digest = hmac.new(salt_bytes, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return "user_" + digest[:16]


def dedupe_grants(raw_grants: list[dict], time_key=None) -> list[dict]:
    """Collapse raw (event-level) grant rows into one entry per (email, clientId) --
    or, for an "AllPrincipals" row (no associated user), per clientId alone.

    Each raw grant dict has keys: email (str|None), clientId, appDisplayName,
    consentType ("Principal"|"AllPrincipals"), scopes (list[str]),
    firstSeen (str|None), lastUsed (str|None).

    Returns a list of dicts with the same shape, `scopes` deduplicated and
    sorted, `firstSeen`/`lastUsed` reduced to min/max of the non-null
    values seen. A "Principal" row and an "AllPrincipals" row for the same
    clientId are never merged with each other -- they key differently.

    `time_key` orders the firstSeen/lastUsed values. None compares the
    strings ordinally, which is what nc-export-entra.ps1 does
    ([string]::CompareOrdinal), so the Entra path keeps it for byte-identical
    parity. The Google path passes utc_instant_key, which compares instants.
    """
    grouped: dict[tuple[str, str], dict] = {}
    for raw in raw_grants:
        if raw.get("consentType") == "AllPrincipals":
            key = ("\x00ALLPRINCIPALS\x00", raw["clientId"])
        else:
            key = (normalize_email(raw["email"]), raw["clientId"])

        entry = grouped.get(key)
        if entry is None:
            entry = {
                "email": raw.get("email"),
                "clientId": raw["clientId"],
                "appDisplayName": raw["appDisplayName"],
                "consentType": raw.get("consentType", "Principal"),
                "scopes": set(),
                "firstSeen": None,
                "lastUsed": None,
            }
            grouped[key] = entry

        entry["scopes"].update(raw["scopes"])

        key = time_key or (lambda v: v)

        first_seen = raw.get("firstSeen")
        if first_seen is not None and (entry["firstSeen"] is None or key(first_seen) < key(entry["firstSeen"])):
            entry["firstSeen"] = first_seen

        last_used = raw.get("lastUsed")
        if last_used is not None and (entry["lastUsed"] is None or key(last_used) > key(entry["lastUsed"])):
            entry["lastUsed"] = last_used

    return list(grouped.values())


def build_grant_objects(grouped_grants: list[dict], salt_bytes: bytes, pseudonymized: bool) -> list[dict]:
    grants = []
    for entry in grouped_grants:
        if entry["consentType"] == "AllPrincipals":
            user_ref = None
        else:
            user_ref = derive_user_ref(salt_bytes, entry["email"], pseudonymized)
        grants.append(
            {
                "userRef": user_ref,
                "email": entry["email"],
                "clientId": entry["clientId"],
                "appDisplayName": entry["appDisplayName"],
                "consentType": entry["consentType"],
                "scopes": sorted(entry["scopes"]),
                "firstSeen": entry["firstSeen"],
                "lastUsed": entry["lastUsed"],
            }
        )
    # A null userRef ("AllPrincipals") sorts as if it were "" -- see
    # spec/discover-export-format-v1.md "Grant line ordering".
    grants.sort(key=lambda g: (g["userRef"] or "", g["clientId"]))
    return grants


def dump_line(obj: dict, keys: list[str]) -> str:
    ordered = {k: obj[k] for k in keys}
    return json.dumps(ordered, ensure_ascii=False, separators=(", ", ": "))


# ---------------------------------------------------------------------------
# Google parsing
# ---------------------------------------------------------------------------


def _google_audit_layout(path: str, fieldnames: list[str]) -> tuple[dict[str, str], Optional[str]]:
    """Pick the column layout of a Google audit CSV from its header row.

    Returns (columns, event_column): `columns` maps each canonical column
    name to the header that holds it in this file, and `event_column` names
    the column holding the OAuth event type whenever the header has one
    (in either layout), or None. Raises ExportError naming both accepted layouts when the header
    matches neither.
    """
    present = set(fieldnames)
    # Filter on the event column whenever it is there, whichever layout
    # matched: a header carrying both layouts must not turn a Revoke into a grant.
    event_column = GOOGLE_CONSOLE_EVENT_COLUMN if GOOGLE_CONSOLE_EVENT_COLUMN in present else None
    if all(c in present for c in GOOGLE_AUDIT_REQUIRED_COLUMNS):
        return {c: c for c in GOOGLE_AUDIT_REQUIRED_COLUMNS}, event_column

    console_required = list(GOOGLE_CONSOLE_COLUMNS.values()) + [GOOGLE_CONSOLE_EVENT_COLUMN]
    if all(c in present for c in console_required):
        return dict(GOOGLE_CONSOLE_COLUMNS), GOOGLE_CONSOLE_EVENT_COLUMN

    missing_api = [c for c in GOOGLE_AUDIT_REQUIRED_COLUMNS if c not in present]
    missing_console = [c for c in console_required if c not in present]
    raise ExportError(
        f"audit CSV '{path}' is missing required column(s): {', '.join(missing_api)} "
        f"(Reports API columns: {', '.join(GOOGLE_AUDIT_REQUIRED_COLUMNS)}); "
        f"as an Admin console download it is missing: {', '.join(missing_console)} "
        f"(console columns: {', '.join(console_required)})"
    )


# re.ASCII: Python's \d also matches non-ASCII digits (e.g. fullwidth), which
# Discover's JavaScript check does not. Matched with fullmatch, never `$`
# (which also matches before a trailing newline).
_UTC_Z_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z", re.ASCII)
_OFFSET_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?([+-]\d{2}:\d{2})", re.ASCII)


_FRACTION_RE = re.compile(r"(T\d{2}:\d{2}:\d{2})\.(\d+)", re.ASCII)


def _fromisoformat(value: str) -> "datetime.datetime":
    import datetime

    return datetime.datetime.fromisoformat(value)


def parse_iso8601(value: str) -> "datetime.datetime":
    """Normalise `Z` and the fraction length, then call `fromisoformat`.

    `datetime.fromisoformat` before 3.11 takes only 3- or 6-digit fractional
    seconds and no `Z`. So `Z` becomes `+00:00` and the fraction is padded or
    truncated (never rounded) to 6 digits. This is all it does: what else
    `fromisoformat` accepts still depends on the Python version. The accepted
    set is fixed by the regexes in to_utc_z, which every caller goes through
    first. Raises ValueError for anything `fromisoformat` rejects.
    """
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    value = _FRACTION_RE.sub(lambda m: m.group(1) + "." + m.group(2)[:6].ljust(6, "0"), value, count=1)
    return _fromisoformat(value)


def _parse_whole_seconds(whole: str):
    """Calendar-check YYYY-MM-DDTHH:MM:SS; returns a naive datetime or None."""
    import datetime

    try:
        return datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def utc_instant_key(value: str):
    """Ordering key for a UTC `Z` timestamp: (whole seconds, fraction).

    Comparing the strings themselves is wrong when fractional lengths differ
    ("...00.5Z" sorts before "...00Z" because '.' < 'Z'). Only called on
    values to_utc_z produced, so the match cannot fail.
    """
    from decimal import Decimal

    match = _UTC_Z_RE.fullmatch(value)
    whole, fraction = match.groups()
    return (_parse_whole_seconds(whole), Decimal("0" + (fraction or "")))


def to_utc_z(value: str) -> Optional[str]:
    """Return `value` as an ISO-8601 UTC timestamp ending in `Z`, or None.

    DEF timestamps are UTC with a `Z` suffix (the Discover intake refuses
    anything else). A value already in that form is returned unchanged, byte
    for byte. A value with a numeric offset (the Admin console writes local
    time, e.g. `2026-11-18T14:08:23-05:00`) is shifted to UTC, and its
    fractional-second digits are kept exactly as written. Anything else (no
    offset, not ISO-8601) returns None: the instant is unknown, so it is not
    guessed.
    """
    import datetime

    value = value.strip()
    z_match = _UTC_Z_RE.fullmatch(value)
    if z_match is not None:
        return value if _parse_whole_seconds(z_match.group(1)) is not None else None
    match = _OFFSET_TS_RE.fullmatch(value)
    if match is None:
        return None
    whole, fraction, offset = match.groups()
    if _parse_whole_seconds(whole) is None:
        return None
    try:
        # `whole` has no fraction (kept aside in `fraction` and re-attached below).
        local = parse_iso8601(whole + offset)
        utc = local.astimezone(datetime.timezone.utc)
    except (ValueError, OverflowError):
        return None
    # isoformat zero-pads the year (strftime("%Y") does not on glibc before 1000).
    return utc.replace(tzinfo=None).isoformat(timespec="seconds") + (fraction or "") + "Z"


def _split_scopes(value: str) -> list[str]:
    """Split a scopes cell on spaces and/or commas.

    The Reports API joins scopes with a space and the Admin console download
    joins them with ", ". An OAuth scope token never contains either
    character (RFC 6749 section 3.3), so splitting on both is lossless.
    """
    return [s for s in re.split(r"[,\s]+", value) if s]


def parse_google_audit_csv(path: str) -> tuple[list[dict], list[str], int]:
    """Parse a Google OAuth Token Audit CSV.

    Accepts either the Reports API column names (`time, actorEmail,
    clientId, displayText, scopes`) or the Admin console's OAuth log events
    download, as downloaded (see GOOGLE_CONSOLE_COLUMNS). A UTF-8 byte order
    mark on the header is ignored.

    Returns (raw_grants, warnings, ignored_events). Raises ExportError for a
    header that matches neither layout or a completely empty (headerless)
    file. A row with a missing, explicit-empty, or whitespace-only required
    value is skipped with a warning rather than raising. In the console
    layout, a row whose OAuth event is not Authorize is not a grant: it is
    left out and counted in `ignored_events`, not in `warnings`.
    """
    try:
        fh = open(path, "r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ExportError(f"cannot open audit CSV '{path}': {exc}") from exc

    with fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ExportError(f"audit CSV '{path}' has no header row")

        columns, event_column = _google_audit_layout(path, list(reader.fieldnames))

        raw_grants: list[dict] = []
        warnings: list[str] = []
        ignored_events = 0
        for row_number, row in enumerate(reader, start=2):  # header is line 1
            if event_column is not None and (row.get(event_column) or "").strip() != GOOGLE_GRANT_EVENT:
                ignored_events += 1
                continue

            values = {col: row.get(header) for col, header in columns.items()}
            missing_values = [
                columns[col]
                for col in GOOGLE_AUDIT_REQUIRED_NONEMPTY_COLUMNS
                if (values.get(col) or "").strip() == ""
            ]
            if missing_values:
                warnings.append(
                    f"skipping malformed row {row_number} in '{path}': "
                    f"missing/blank value(s) for {', '.join(missing_values)}"
                )
                continue

            time_utc = to_utc_z(values["time"])
            if time_utc is None:
                warnings.append(
                    f"skipping malformed row {row_number} in '{path}': "
                    f"{columns['time']} is not an ISO-8601 timestamp with a UTC offset"
                )
                continue

            scopes = _split_scopes(values.get("scopes") or "")
            raw_grants.append(
                {
                    "email": values["actorEmail"],
                    "clientId": values["clientId"],
                    "appDisplayName": values["displayText"],
                    "consentType": "Principal",
                    "scopes": scopes,
                    "firstSeen": time_utc,
                    "lastUsed": time_utc,
                }
            )

        return raw_grants, warnings, ignored_events


def _read_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as exc:
        raise ExportError(f"cannot open '{path}': {exc}") from exc

    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ExportError(f"invalid JSON in '{path}': {exc}") from exc


def _graph_values(document: dict, path: str) -> list[dict]:
    values = document.get("value")
    if not isinstance(values, list):
        raise ExportError(f"'{path}' is not a Graph list response (missing a top-level \"value\" array)")
    return values


def parse_app_role_assignments(
    path: str, users_by_id: dict[str, dict], sps_by_id: dict[str, dict]
) -> tuple[list[dict], list[str]]:
    """Parse an optional appRoleAssignments.json Graph list-response export.

    Produces raw grants in the same shape as the oauth2PermissionGrants
    path, so both feed the same dedupe_grants()/build_grant_objects()
    pass -- see spec/discover-export-format-v1.md "Grant sources".
    Returns (raw_grants, warnings).
    """
    doc = _read_json(path)
    assignments = _graph_values(doc, path)

    warnings: list[str] = []
    raw_grants: list[dict] = []
    for index, assignment in enumerate(assignments, start=1):
        principal_id = assignment.get("principalId")
        resource_id = assignment.get("resourceId")
        app_role_id = assignment.get("appRoleId")

        sp = sps_by_id.get(resource_id)
        if sp is None:
            warnings.append(
                f"skipping app role assignment {index} in '{path}': "
                f"resourceId {resource_id!r} not found among service principals"
            )
            continue

        app_id = sp.get("appId")
        if _is_blank(app_id):
            warnings.append(
                f"skipping app role assignment {index} in '{path}': "
                f"servicePrincipal {resource_id!r} has a missing/blank appId"
            )
            continue

        display_name = sp.get("displayName")
        if _is_blank(display_name):
            warnings.append(
                f"skipping app role assignment {index} in '{path}': "
                f"servicePrincipal {resource_id!r} has a missing/blank displayName"
            )
            continue

        user = users_by_id.get(principal_id)
        if user is None:
            warnings.append(
                f"skipping app role assignment {index} in '{path}': "
                f"principalId {principal_id!r} not found among users"
            )
            continue

        upn = user.get("userPrincipalName")
        if _is_blank(upn):
            warnings.append(
                f"skipping app role assignment {index} in '{path}': "
                f"user {principal_id!r} has a missing/blank userPrincipalName"
            )
            continue

        roles_by_id = {
            role["id"]: role.get("value")
            for role in (sp.get("appRoles") or [])
            if isinstance(role, dict) and isinstance(role.get("id"), str)
        }
        role_value = roles_by_id.get(app_role_id)
        if _is_blank(role_value):
            role_value = app_role_id if not _is_blank(app_role_id) else "unknown"

        raw_grants.append(
            {
                "email": upn,
                "clientId": app_id,
                "appDisplayName": display_name,
                "consentType": "Principal",
                "scopes": [f"appRole:{role_value}"],
                "firstSeen": assignment.get("createdDateTime"),
                "lastUsed": None,
            }
        )

    return raw_grants, warnings


def parse_entra_triplet(
    users_path: str,
    service_principals_path: str,
    grants_path: str,
    app_role_assignments_path: Optional[str] = None,
) -> tuple[int, list[dict], list[str]]:
    """Parse a users/servicePrincipals/oauth2PermissionGrants Graph JSON triplet,
    plus an optional appRoleAssignments export.

    Returns (user_count_total, raw_grants, warnings). raw_grants have the
    same shape dedupe_grants() expects: email, clientId, appDisplayName,
    consentType, scopes, firstSeen, lastUsed.
    """
    users_doc = _read_json(users_path)
    sps_doc = _read_json(service_principals_path)
    grants_doc = _read_json(grants_path)

    users = _graph_values(users_doc, users_path)
    service_principals = _graph_values(sps_doc, service_principals_path)
    grants = _graph_values(grants_doc, grants_path)

    users_by_id = {u["id"]: u for u in users if "id" in u}
    sps_by_id = {sp["id"]: sp for sp in service_principals if "id" in sp}

    warnings: list[str] = []
    raw_grants: list[dict] = []
    for index, grant in enumerate(grants, start=1):
        client_object_id = grant.get("clientId")
        principal_id = grant.get("principalId")
        consent_type = "AllPrincipals" if grant.get("consentType") == "AllPrincipals" else "Principal"

        sp = sps_by_id.get(client_object_id)
        if sp is None:
            warnings.append(
                f"skipping grant {index} in '{grants_path}': "
                f"clientId {client_object_id!r} not found in '{service_principals_path}'"
            )
            continue

        app_id = sp.get("appId")
        if _is_blank(app_id):
            warnings.append(
                f"skipping grant {index} in '{grants_path}': "
                f"servicePrincipal {client_object_id!r} has a missing/blank appId"
            )
            continue

        display_name = sp.get("displayName")
        if _is_blank(display_name):
            warnings.append(
                f"skipping grant {index} in '{grants_path}': "
                f"servicePrincipal {client_object_id!r} has a missing/blank displayName"
            )
            continue

        scope_string = grant.get("scope") or ""
        scopes = [s for s in scope_string.split(" ") if s]

        if consent_type == "AllPrincipals":
            # Tenant-wide admin consent: no associated user, never skipped,
            # never counted in skippedRows -- see spec "Grant object".
            raw_grants.append(
                {
                    "email": None,
                    "clientId": app_id,
                    "appDisplayName": display_name,
                    "consentType": "AllPrincipals",
                    "scopes": scopes,
                    "firstSeen": grant.get("createdDateTime"),
                    "lastUsed": None,
                }
            )
            continue

        user = users_by_id.get(principal_id)
        if user is None:
            warnings.append(
                f"skipping grant {index} in '{grants_path}': "
                f"principalId {principal_id!r} not found in '{users_path}'"
            )
            continue

        upn = user.get("userPrincipalName")
        if _is_blank(upn):
            warnings.append(
                f"skipping grant {index} in '{grants_path}': "
                f"user {principal_id!r} has a missing/blank userPrincipalName"
            )
            continue

        raw_grants.append(
            {
                "email": upn,
                "clientId": app_id,
                "appDisplayName": display_name,
                "consentType": "Principal",
                "scopes": scopes,
                "firstSeen": grant.get("createdDateTime"),
                "lastUsed": None,
            }
        )

    if app_role_assignments_path is not None:
        ar_raw_grants, ar_warnings = parse_app_role_assignments(
            app_role_assignments_path, users_by_id, sps_by_id
        )
        raw_grants.extend(ar_raw_grants)
        warnings.extend(ar_warnings)

    return len(users), raw_grants, warnings


def parse_google_users_csv(path: str) -> int:
    """Return the distinct user count from a Google Users CSV.

    Accepts a CSV with an `email` column, or the Admin console's Users
    download as is (primary address in "Email Address [Required]"). Every
    row is a directory user whatever its status, so a suspended account is
    counted. A UTF-8 byte order mark on the header is ignored.
    """
    try:
        fh = open(path, "r", encoding="utf-8-sig", newline="")
    except OSError as exc:
        raise ExportError(f"cannot open users CSV '{path}': {exc}") from exc

    with fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames is None:
            raise ExportError(f"users CSV '{path}' has no header row")

        fieldnames = list(reader.fieldnames)
        if all(c in fieldnames for c in GOOGLE_USERS_REQUIRED_COLUMNS):
            email_column = "email"
        elif GOOGLE_CONSOLE_USERS_EMAIL_COLUMN in fieldnames:
            email_column = GOOGLE_CONSOLE_USERS_EMAIL_COLUMN
        else:
            raise ExportError(
                f"users CSV '{path}' is missing required column(s): {', '.join(GOOGLE_USERS_REQUIRED_COLUMNS)} "
                f"(or, as an Admin console Users download: '{GOOGLE_CONSOLE_USERS_EMAIL_COLUMN}'); "
                f"expected 'email' or '{GOOGLE_CONSOLE_USERS_EMAIL_COLUMN}'"
            )

        emails = {
            normalize_email(row[email_column])
            for row in reader
            if (row.get(email_column) or "").strip()
        }
        return len(emails)


# ---------------------------------------------------------------------------
# Salt + output writing (shared across vendors)
# ---------------------------------------------------------------------------


def load_or_generate_salt(salt_file: Optional[str]) -> bytes:
    if salt_file is not None:
        try:
            with open(salt_file, "r", encoding="utf-8") as fh:
                salt_hex = fh.read().strip()
            return bytes.fromhex(salt_hex)
        except OSError as exc:
            raise ExportError(f"cannot open salt file '{salt_file}': {exc}") from exc
        except ValueError as exc:
            raise ExportError(f"salt file '{salt_file}' does not contain valid hex: {exc}") from exc
    return secrets.token_bytes(32)


def write_outputs(
    out_dir: str,
    vendor: str,
    script_name: str,
    pseudonymized: bool,
    user_count_total: Optional[int],
    export_window,
    grant_objects: list[dict],
    salt_bytes: bytes,
    generated_at: str,
    skipped_rows: int,
) -> None:
    os.makedirs(out_dir, exist_ok=True)

    header = {
        "kind": DEF_KIND,
        "version": DEF_VERSION,
        "vendor": vendor,
        "generatedAt": generated_at,
        "pseudonymized": pseudonymized,
        "hashAlgo": HASH_ALGO,
        "script": script_name,
        "exportWindow": export_window,
        "userCountTotal": user_count_total,
        "skippedRows": skipped_rows,
    }

    lines = [dump_line(header, HEADER_KEYS)]
    for grant in grant_objects:
        lines.append(dump_line(grant, GRANT_KEYS))

    ndjson_path = os.path.join(out_dir, "discover-export.ndjson")
    with open(ndjson_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    if pseudonymized:
        salt_path = os.path.join(out_dir, "salt.txt")
        with open(salt_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(salt_bytes.hex() + "\n")
        os.chmod(salt_path, OWNER_ONLY_MODE)

        seen_emails = {}
        for grant in grant_objects:
            if grant["userRef"] is None:  # "AllPrincipals": no user to map
                continue
            seen_emails[grant["userRef"]] = grant["email"]

        mapping_path = os.path.join(out_dir, "mapping.csv")
        with open(mapping_path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh, lineterminator="\n")
            writer.writerow(["userRef", "email"])
            for user_ref, email in sorted(seen_emails.items()):
                writer.writerow([user_ref, normalize_email(email)])
        os.chmod(mapping_path, OWNER_ONLY_MODE)


def _resolve_generated_at(override: Optional[str]) -> str:
    """The header's generatedAt: now, or the test-only --generated-at override in UTC."""
    if override is None:
        return _generated_at()
    resolved = to_utc_z(override)
    if resolved is None:
        raise ExportError(f"--generated-at '{override}' is not an ISO-8601 timestamp with a UTC offset")
    return resolved


def _generated_at() -> str:
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _warn_if_empty_result(user_count_total: Optional[int], grant_objects: list[dict]) -> None:
    """Loud, non-fatal warning: a zero-record result may be a permission/consent
    problem, not a genuinely empty tenant -- see spec "Skipped-row / empty-result
    signals". Still exits 0; an empty tenant is a legitimate outcome.
    """
    if user_count_total == 0:
        print(
            "warning: 0 users were found in the source data -- this may indicate "
            "a permission or consent problem, not an empty tenant",
            file=sys.stderr,
        )
    if not grant_objects:
        print(
            "warning: 0 grants were found in the source data -- this may indicate "
            "a permission or consent problem, not an empty tenant",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_NAIVE_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?", re.ASCII)


def _window_bound_utc(flag: str, value: str) -> str:
    """Return a window flag as a UTC `Z` timestamp, or raise ExportError.

    The accepted forms (and so the error wording) come from the to_utc_z
    regexes, not from `fromisoformat`, so they are the same on every Python.
    """
    naive = _NAIVE_TS_RE.fullmatch(value.strip())
    if naive is not None and _parse_whole_seconds(naive.group(1)) is not None:
        raise ExportError(f"{flag} '{value}' needs a UTC offset (e.g. 'Z' or '-05:00')")
    utc = to_utc_z(value)
    if utc is None:
        raise ExportError(f"{flag} '{value}' is not an ISO-8601 timestamp")
    return utc


def resolve_export_window(start: Optional[str], end: Optional[str]) -> Optional[dict]:
    """Build the header's exportWindow from the operator's --export-window-* flags.

    The spec forbids guessing the window, so it is only ever what the
    operator states: both flags (the date range they chose in the console),
    written in UTC (see to_utc_z), or neither (null). Raises ExportError for
    one flag without the other, a timestamp that is not ISO-8601 with an
    offset, or a start after the end.
    """
    if start is None and end is None:
        return None
    if start is None or end is None:
        raise ExportError("--export-window-start and --export-window-end must be given both or neither")
    start_utc = _window_bound_utc("--export-window-start", start)
    end_utc = _window_bound_utc("--export-window-end", end)
    # Exact comparison: fractions longer than 6 digits must not be truncated away.
    if utc_instant_key(start_utc) > utc_instant_key(end_utc):
        raise ExportError(f"--export-window-start '{start}' is after --export-window-end '{end}'")
    return {"start": start_utc, "end": end_utc}


def run_google(args: argparse.Namespace) -> None:
    export_window = resolve_export_window(args.export_window_start, args.export_window_end)

    raw_grants, warnings, ignored_events = parse_google_audit_csv(args.audit_csv)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if ignored_events:
        print(
            f"note: left out {ignored_events} non-Authorize event row(s) (e.g. Revoke); "
            "they are not grants and are not counted as skipped",
            file=sys.stderr,
        )

    user_count_total = None
    if args.users_csv is not None:
        user_count_total = parse_google_users_csv(args.users_csv)

    pseudonymized = not args.no_pseudonymize
    salt_bytes = load_or_generate_salt(args.salt_file) if pseudonymized else b""

    grouped = dedupe_grants(raw_grants, time_key=utc_instant_key)
    grant_objects = build_grant_objects(grouped, salt_bytes, pseudonymized)

    _warn_if_empty_result(user_count_total, grant_objects)

    write_outputs(
        out_dir=args.out_dir,
        vendor="google",
        script_name="nc-export.py",
        pseudonymized=pseudonymized,
        user_count_total=user_count_total,
        export_window=export_window,
        grant_objects=grant_objects,
        salt_bytes=salt_bytes,
        generated_at=_resolve_generated_at(args.generated_at),
        skipped_rows=len(warnings),
    )

    print(f"Skipped rows: {len(warnings)}")
    print(CLOSING_MESSAGE)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nc-export.py",
        description="Export a Google Workspace or Entra ID OAuth grant inventory to DEF v1.",
    )
    subparsers = parser.add_subparsers(dest="vendor", required=True)

    google = subparsers.add_parser("google", help="Export from a Google Workspace audit CSV export.")
    google.add_argument(
        "--audit-csv",
        required=True,
        help=(
            "Path to the OAuth audit CSV: the Admin console's OAuth log events download as is, "
            "or a Reports API export with columns time, actorEmail, clientId, displayText, scopes."
        ),
    )
    google.add_argument(
        "--export-window-start",
        default=None,
        help="Start of the date range the export covers (ISO-8601 with offset). Give with --export-window-end.",
    )
    google.add_argument(
        "--export-window-end",
        default=None,
        help="End of the date range the export covers (ISO-8601 with offset). Give with --export-window-start.",
    )
    google.add_argument("--users-csv", default=None, help="Optional path to a Users CSV export.")
    google.add_argument("--out-dir", required=True, help="Directory to write DEF output into.")
    google.add_argument("--salt-file", default=None, help="Path to a fixed hex salt (for reproducible output).")
    google.add_argument(
        "--no-pseudonymize",
        action="store_true",
        help="Write raw email addresses as userRef instead of HMAC-SHA256 pseudonyms.",
    )
    google.add_argument(
        "--generated-at",
        default=None,
        help=argparse.SUPPRESS,  # reproducible-output override, used by the test suite
    )
    google.set_defaults(func=run_google)

    entra = subparsers.add_parser(
        "entra", help="Export from Microsoft Entra ID (file mode; live mode is PowerShell-only)."
    )
    entra.add_argument("--users-json", required=True, help="Path to a Graph users list-response JSON export.")
    entra.add_argument(
        "--service-principals-json", required=True, help="Path to a Graph servicePrincipals list-response JSON export."
    )
    entra.add_argument(
        "--grants-json", required=True, help="Path to a Graph oauth2PermissionGrants list-response JSON export."
    )
    entra.add_argument(
        "--app-role-assignments-json",
        default=None,
        help=(
            "Optional path to a Graph appRoleAssignments list-response JSON export. "
            "When omitted, app-role assignments are simply not included (back-compatible)."
        ),
    )
    entra.add_argument("--out-dir", required=True, help="Directory to write DEF output into.")
    entra.add_argument("--salt-file", default=None, help="Path to a fixed hex salt (for reproducible output).")
    entra.add_argument(
        "--no-pseudonymize",
        action="store_true",
        help="Write raw UPNs as userRef instead of HMAC-SHA256 pseudonyms.",
    )
    entra.add_argument(
        "--generated-at",
        default=None,
        help=argparse.SUPPRESS,  # reproducible-output override, used by the test suite
    )
    entra.set_defaults(func=run_entra)

    return parser


def run_entra(args: argparse.Namespace) -> None:
    user_count_total, raw_grants, warnings = parse_entra_triplet(
        args.users_json,
        args.service_principals_json,
        args.grants_json,
        args.app_role_assignments_json,
    )
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    pseudonymized = not args.no_pseudonymize
    salt_bytes = load_or_generate_salt(args.salt_file) if pseudonymized else b""

    grouped = dedupe_grants(raw_grants)
    grant_objects = build_grant_objects(grouped, salt_bytes, pseudonymized)

    _warn_if_empty_result(user_count_total, grant_objects)

    write_outputs(
        out_dir=args.out_dir,
        vendor="entra",
        script_name="nc-export-entra",
        pseudonymized=pseudonymized,
        user_count_total=user_count_total,
        export_window=None,
        grant_objects=grant_objects,
        salt_bytes=salt_bytes,
        generated_at=_resolve_generated_at(args.generated_at),
        skipped_rows=len(warnings),
    )

    print(f"Skipped rows: {len(warnings)}")
    print(CLOSING_MESSAGE)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- last-resort guard: never surface a raw traceback
        print(f"error: unexpected error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
