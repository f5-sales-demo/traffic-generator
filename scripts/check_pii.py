"""Detect PII-shaped values in tracked Git content without reading the worktree.

The scanner deliberately has two modes:

* ``enforce`` reports only deterministic, high-confidence findings suitable for
  a commit or CI gate.
* ``audit`` includes review-required surfaces and lower-confidence indicators
  used during a repository sweep.

Exit 0 means no findings, 1 means findings, and 2 means the scan could not run.
Finding messages never contain the matched value.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

EXCLUDED_PATHS = {
    "scripts/check_pii.py",
    "scripts/check-pii.sh",
    "scripts/check-repo-hygiene.sh",
    "tests/test-check-pii.sh",
    "tests/test-check-repo-hygiene.sh",
}
LEGAL_BASENAMES = ("license", "copying", "notice", "authors")
MEDIA_SUFFIXES = {
    ".gif",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp4",
    ".pdf",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webm",
    ".webp",
}
TEXT_MEDIA_SUFFIXES = {".svg"}
SOURCE_CODE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".m",
    ".mm",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}

EMAIL_RE = re.compile(
    r"(?<![-A-Za-z0-9._%+/])"
    r"[A-Za-z0-9][-A-Za-z0-9.!#$%&'*+=?^_`{|}~]*[A-Za-z0-9]@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}"
)
HOME_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:"
    r"(?P<prefix>/Users/|/home/)(?P<user>[A-Za-z0-9._${}<>-]+)"
    r"|(?P<winprefix>[A-Za-z]:\\+(?:Users)\\+)(?P<winuser>[A-Za-z0-9._${}<>-]+)"
    r")"
)
PHONE_FIELD_RE = re.compile(
    r"(?i)(?:^|[,{\s])['\"]?(?:phone(?:_number)?|mobile|telephone|fax)['\"]?"
    r"\s*[:=]\s*['\"]?(?P<value>\+?[0-9][0-9(). \-]{7,}[0-9])"
)
PERSON_FIELD_RE = re.compile(
    r"(?i)(?:^|[,{\s])['\"]?"
    r"(?P<key>full_name|first_name|last_name|given_name|family_name|display_name)"
    r"['\"]?\s*[:=]\s*(?P<quote>['\"`]?)"
    r"(?P<value>(?:(?!\\[rn])[^'\"`#,\r\n}\]])+)"
)
IDENTITY_FIELD_RE = re.compile(
    r"(?i)(?:^|[,{\s])['\"]?"
    r"(?P<key>tenant(?:_name|_id)?|customer(?:_name|_id)?|account(?:_name|_id)?|"
    r"subscription(?:_name|_id)|project(?:_name|_id)|namespace)"
    r"['\"]?\s*[:=]\s*(?P<quote>['\"`]?)"
    r"(?P<value>(?:(?!\\[rn])[^'\"`#,\r\n}\]])+)"
)
ADDRESS_FIELD_RE = re.compile(
    r"(?i)(?:^|[,{\s])['\"]?"
    r"(?P<key>street_address|postal_address|postal_code|zip_code|date_of_birth|dob|"
    r"social_security_number|ssn)"
    r"['\"]?\s*[:=]\s*(?P<quote>['\"`]?)"
    r"(?P<value>(?:(?!\\[rn])[^'\"`#,\r\n}\]])+)"
)
QUERY_RE = re.compile(
    r"(?i)[?&](?P<key>email|phone|mobile|full_name|first_name|last_name|address|dob|ssn)="
    r"(?P<value>[^&#\s]+)"
)
IPV4_RE = re.compile(r"(?<![A-Za-z0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9.])")
DOTTED_VERSION_PREFIX_RE = re.compile(
    r"(?i)(?:"
    r"(?:chrome|headlesschrome|chromium|firefox|safari|edg|edge|opera)/\s*$"
    r"|[A-Za-z0-9_.-]*version[A-Za-z0-9_.-]*\s*[:=]\s*['\"`]?\s*$"
    r"|version[A-Za-z0-9_.-]*\)?\.to(?:be|equal)\(\s*['\"`]?\s*$"
    r")"
)
SVG_PATH_ATTRIBUTE_RE = re.compile(r"(?:^|\s)d\s*=\s*(?P<quote>['\"])", re.IGNORECASE)
PDF_AUTHOR_RE = re.compile(
    r"/(?:Author|Subject)\s*\((?P<value>[^)]{2,})\)",
    re.IGNORECASE,
)
SENSITIVE_MEDIA_TAG_RE = re.compile(
    r"GPSLatitude|GPSLongitude|OwnerName|CameraOwnerName", re.IGNORECASE
)
MEDIA_AUTHOR_METADATA_RE = re.compile(
    r"(?:^|\n)(?:Author|Artist|Creator|OwnerName|CameraOwnerName)"
    r"(?:\s*[:=]\s*|\n+)(?P<value>[^\r\n]+)",
    re.IGNORECASE,
)
PROVENANCE_TRAILER_RE = re.compile(
    r"^(?:Co-authored-by|Signed-off-by|Reviewed-by|Acked-by|Tested-by):",
    re.IGNORECASE,
)
URI_USERINFO_PREFIX_RE = re.compile(
    r"(?i)\b(?P<scheme>[a-z][a-z0-9+.-]*):(?://)?[^\s/]*$",
)
PRINTABLE_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
NUMERIC_LITERAL_RE = re.compile(
    r"[+-]?(?:"
    r"0[xX][0-9A-Fa-f_]+|0[bB][01_]+|0[oO][0-7_]+|"
    r"[0-9][0-9_]*(?:\.[0-9_]+)?"
    r");?"
)

SAFE_EMAIL_DOMAINS = {"example.com", "example.net", "example.org"}
PROVENANCE_EMAIL_DOMAINS = {"noreply.github.com", "users.noreply.github.com"}
SAFE_HOME_USERS = {
    "you",
    "user",
    "users",
    "username",
    "userid",
    "your-user",
    "your_username",
    "me",
    "example",
    "alice",
    "bob",
    "runner",
    "circleci",
    "travis",
    "vsts",
    "ubuntu",
    "node",
    "jenkins",
    "gitpod",
    "index",
    "vscode",
    "...",
}
SAFE_PERSON_NAMES = {
    "dana r.",
    "kiran m.",
    "quinn n.",
    "alex t.",
    "yuri s.",
    "amal b.",
    "noam k.",
    "rosario l.",
}
SCHEMA_SENTINELS = {
    "0",
    "any",
    "boolean",
    "integer",
    "null",
    "number",
    "object",
    "optional",
    "required",
    "string",
    "unknown",
    "value",
}
SAFE_IDENTITY_VALUES = {
    "123456789012",
    "default",
    "demo",
    "demo-app",
    "example-corp",
    "library",
    "production",
    "shared",
    "staging",
    "system",
}
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)
SAFE_IDENTITY_VALUES_LOWER = {item.lower() for item in SAFE_IDENTITY_VALUES}


@dataclass(frozen=True, order=True)
class Finding:
    """A redacted, actionable result from one tracked blob."""

    path: str
    line: int
    category: str
    severity: str
    message: str


def input_blobs(input_dir: Path) -> Iterator[tuple[str, bytes]]:
    """Read the shell-materialized path/blob pairs in deterministic order."""

    def record_number(path: Path) -> int:
        return int(path.stem)

    for path_file in sorted(input_dir.glob("*.path"), key=record_number):
        blob_file = path_file.with_suffix(".blob")
        if not blob_file.is_file():
            message = f"materialized blob is missing for record {path_file.stem}"
            raise OSError(message)
        path = path_file.read_bytes().decode("utf-8", "surrogateescape")
        yield path, blob_file.read_bytes()


def is_legal_attribution_path(path: str) -> bool:
    """Return whether a path carries a narrow legal attribution exception."""
    basename = PurePosixPath(path).name.lower()
    return basename.startswith(LEGAL_BASENAMES)


def is_excluded(path: str) -> bool:
    """Return whether a scanner implementation fixture must be self-excluded."""
    return path in EXCLUDED_PATHS


def safe_email(value: str) -> bool:
    """Return whether an email-shaped value is reserved or provenance-only."""
    if value.lower() == "git@github.com":
        return True
    domain = value.rsplit("@", 1)[1].lower().rstrip(".")
    return domain in SAFE_EMAIL_DOMAINS | PROVENANCE_EMAIL_DOMAINS or any(
        domain.endswith(f".{safe_domain}") for safe_domain in SAFE_EMAIL_DOMAINS
    )


def is_uri_userinfo(line: str, match: re.Match[str]) -> bool:
    """Return whether an address-shaped value belongs to URI authority userinfo."""
    prefix = URI_USERINFO_PREFIX_RE.search(line[: match.start()])
    return bool(prefix and prefix.group("scheme").lower() != "mailto")


def safe_home_user(user: str) -> bool:
    """Return whether a home path uses a documented portable placeholder."""
    if user.isdigit() or user in SAFE_HOME_USERS:
        return True
    return user.startswith(("$", "{", "<")) or "${" in user


def normalized_value(value: str) -> str:
    """Remove serialization punctuation surrounding a structured value."""
    return value.strip().strip("'\"").strip()


def placeholder_value(value: str) -> bool:
    """Return whether a value is synthetic, schematic, or schema syntax."""
    value = normalized_value(value)
    if not value:
        return True
    lower = value.lower()
    if lower in SCHEMA_SENTINELS or lower in SAFE_IDENTITY_VALUES_LOWER:
        return True
    if re.fullmatch(r"example(?:[-_.][a-z0-9]+)*", lower):
        return True
    first, separator, second = value.partition("|")
    safe_composite = bool(
        first
        and separator
        and second
        and "|" not in second
        and placeholder_value(first)
        and placeholder_value(second)
    )
    return (
        safe_composite
        or lower in SAFE_PERSON_NAMES
        or value.startswith(("$", "{", "<", "{{", "[%", "*", "&"))
        or bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", value))
    )


def is_nonliteral_code_expression(path: str, match: re.Match[str]) -> bool:
    """Return whether a structured field is executable or type syntax, not data."""
    if PurePosixPath(path).suffix.lower() not in SOURCE_CODE_SUFFIXES:
        return False
    if match.group("quote"):
        return False
    value = normalized_value(match.group("value"))
    return not bool(NUMERIC_LITERAL_RE.fullmatch(value))


def safe_phone(value: str) -> bool:
    """Return whether a phone number uses NANP's fictional 555-0100--0199 block."""
    digits = re.sub(r"\D", "", value)
    if len(digits) in {8, 11} and digits.startswith("1"):
        digits = digits[1:]
    return bool(re.fullmatch(r"(?:[2-9][0-9]{2})?55501[0-9]{2}", digits))


def add_finding(
    findings: set[Finding],
    *,
    path: str,
    line: int,
    category: str,
    message: str,
) -> None:
    """Add one redacted and deduplicated finding."""
    findings.add(
        Finding(
            path=redact_path(path),
            line=line,
            category=category,
            severity="high",
            message=message,
        )
    )


def add_review_finding(
    findings: set[Finding],
    *,
    path: str,
    line: int,
    category: str,
    message: str,
) -> None:
    """Add one redacted and deduplicated manual-review finding."""
    findings.add(
        Finding(
            path=redact_path(path),
            line=line,
            category=category,
            severity="review",
            message=message,
        )
    )


def redact_path(path: str) -> str:
    """Prevent a sensitive filename from being copied into scanner output."""
    redacted = EMAIL_RE.sub("<redacted-email>", path)

    def replace_home(match: re.Match[str]) -> str:
        prefix = match.group("prefix") or match.group("winprefix") or ""
        return f"{prefix}<redacted-user>"

    redacted = HOME_RE.sub(replace_home, redacted)
    if redacted != path:
        encoded_path = path.encode("utf-8", "surrogateescape")
        digest = hashlib.sha256(encoded_path).hexdigest()[:12]
        return f"{redacted} [path-sha256:{digest}]"
    return redacted


def scan_contacts(
    path: str,
    line_number: int,
    line: str,
    attribution_context: bool,
    findings: set[Finding],
) -> None:
    """Scan one line for contact details, home paths, and person names."""
    if not attribution_context:
        for match in EMAIL_RE.finditer(line):
            if not safe_email(match.group(0)) and not is_uri_userinfo(line, match):
                add_finding(
                    findings,
                    path=path,
                    line=line_number,
                    category="email",
                    message="email address does not use a documentation-reserved domain",
                )
        for match in PERSON_FIELD_RE.finditer(line):
            value = normalized_value(match.group("value"))
            if NUMERIC_LITERAL_RE.fullmatch(value):
                continue
            if is_nonliteral_code_expression(path, match):
                continue
            if not placeholder_value(value):
                add_finding(
                    findings,
                    path=path,
                    line=line_number,
                    category="person-name",
                    message=f"{match.group('key')} contains a literal person name",
                )

    for match in HOME_RE.finditer(line):
        user = match.group("user") or match.group("winuser") or ""
        if not safe_home_user(user):
            add_finding(
                findings,
                path=path,
                line=line_number,
                category="home-path",
                message="home-directory path contains a non-placeholder user segment",
            )

    for match in PHONE_FIELD_RE.finditer(line):
        if not safe_phone(match.group("value")):
            add_finding(
                findings,
                path=path,
                line=line_number,
                category="phone",
                message="phone field does not use the fictional NANP range",
            )


def scan_structured_identity(
    path: str, line_number: int, line: str, findings: set[Finding]
) -> None:
    """Scan structured fields for customer identifiers and personal records."""
    for match in IDENTITY_FIELD_RE.finditer(line):
        if is_nonliteral_code_expression(path, match):
            continue
        if not placeholder_value(match.group("value")):
            add_finding(
                findings,
                path=path,
                line=line_number,
                category="customer-identifier",
                message=f"{match.group('key')} contains a literal organization identifier",
            )

    for match in ADDRESS_FIELD_RE.finditer(line):
        if is_nonliteral_code_expression(path, match):
            continue
        if not placeholder_value(match.group("value")):
            add_finding(
                findings,
                path=path,
                line=line_number,
                category="personal-record",
                message=f"{match.group('key')} contains a literal personal value",
            )


def scan_query_parameters(
    path: str,
    line_number: int,
    line: str,
    findings: set[Finding],
) -> None:
    """Scan URL query parameters for embedded identity values."""
    for match in QUERY_RE.finditer(line):
        value = urllib.parse.unquote_plus(match.group("value"))
        if placeholder_value(value):
            continue
        if match.group("key").lower() == "email" and safe_email(value):
            continue
        add_finding(
            findings,
            path=path,
            line=line_number,
            category="pii-query-parameter",
            message=f"URL query parameter {match.group('key')} contains a literal value",
        )


def scan_public_ips(
    path: str,
    line_number: int,
    line: str,
    findings: set[Finding],
) -> None:
    """Report globally routable unicast IPv4 values outside documentation ranges."""
    for match in IPV4_RE.finditer(line):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if not address.is_global or address.is_multicast:
            continue
        if any(address in network for network in DOCUMENTATION_NETWORKS):
            continue
        prefix = line[max(0, match.start() - 96) : match.start()]
        if DOTTED_VERSION_PREFIX_RE.search(prefix):
            continue
        for attribute in SVG_PATH_ATTRIBUTE_RE.finditer(line, 0, match.start()):
            value = line[attribute.end() : match.start()]
            if attribute.group("quote") not in value:
                break
        else:
            attribute = None
        if attribute is not None:
            continue
        add_review_finding(
            findings,
            path=path,
            line=line_number,
            category="public-ip-review",
            message="globally routable unicast IPv4 address is outside documentation ranges",
        )


def scan_text(path: str, text: str, findings: set[Finding]) -> None:
    """Apply structured and line-oriented detectors to one text blob."""
    legal_path = is_legal_attribution_path(path)
    for line_number, line in enumerate(text.splitlines(), 1):
        is_commit_message = path.startswith("<commit:")
        trailer_match = PROVENANCE_TRAILER_RE.match(line)
        provenance_trailer = bool(is_commit_message and trailer_match)
        scan_contacts(
            path,
            line_number,
            line,
            legal_path or provenance_trailer,
            findings,
        )
        scan_structured_identity(path, line_number, line, findings)
        scan_query_parameters(path, line_number, line, findings)
        scan_public_ips(path, line_number, line, findings)


def looks_binary(data: bytes) -> bool:
    """Use NUL bytes as a conservative binary-content signal."""
    return b"\0" in data[:8192]


def scan_binary(path: str, data: bytes, findings: set[Finding], *, media: bool) -> None:
    """Inspect ASCII-compatible binary metadata without rendering the file."""
    # Keep only printable metadata runs. Treating every byte as Latin-1 lets
    # compression noise masquerade as contact syntax across arbitrary bytes.
    text = "\n".join(
        (match.group(0).decode("ascii") for match in PRINTABLE_ASCII_RE.finditer(data)),
    )
    if not media:
        scan_text(path, text, findings)
        return

    for metadata in MEDIA_AUTHOR_METADATA_RE.finditer(text):
        value = metadata.group("value")
        emails = list(EMAIL_RE.finditer(value))
        for email in emails:
            if not safe_email(email.group(0)):
                add_finding(
                    findings,
                    path=path,
                    line=0,
                    category="email",
                    message="media metadata contains a non-reserved email address",
                )
        if not emails and not placeholder_value(value):
            add_finding(
                findings,
                path=path,
                line=0,
                category="media-author",
                message="binary media contains literal author metadata",
            )
    if SENSITIVE_MEDIA_TAG_RE.search(text):
        add_finding(
            findings,
            path=path,
            line=0,
            category="location-metadata",
            message="binary media contains a location or owner metadata tag",
        )
    for match in PDF_AUTHOR_RE.finditer(text):
        if not placeholder_value(match.group("value")):
            add_finding(
                findings,
                path=path,
                line=0,
                category="media-author",
                message="binary media contains literal author metadata",
            )


def scan_blob(path: str, data: bytes, findings: set[Finding]) -> None:
    """Classify and scan one materialized tracked blob."""
    if is_excluded(path):
        return
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in MEDIA_SUFFIXES:
        add_review_finding(
            findings,
            path=path,
            line=0,
            category="media-review",
            message="media requires metadata, OCR, and visual review",
        )
    if suffix in MEDIA_SUFFIXES - TEXT_MEDIA_SUFFIXES:
        scan_binary(path, data, findings, media=True)
        return
    if looks_binary(data):
        scan_binary(path, data, findings, media=False)
        return
    scan_text(path, data.decode("utf-8", "replace"), findings)


def scan(input_dir: Path) -> set[Finding]:
    """Scan every blob materialized by the trusted shell wrapper."""
    findings: set[Finding] = set()
    for path, data in input_blobs(input_dir):
        scan_blob(path, data, findings)
    return findings


def selected_findings(findings: Iterable[Finding], mode: str) -> list[Finding]:
    """Filter advisory results from enforcement mode and sort the remainder."""

    def should_include(finding: Finding) -> bool:
        return mode == "audit" or finding.severity == "high"

    return sorted(filter(should_include, findings))


def render_text(findings: Sequence[Finding], *, scope: str, mode: str) -> str:
    """Render redacted findings as GitHub-compatible annotations."""
    if not findings:
        return f"PII {mode}: clean ({scope} scope)."
    lines = []
    for finding in findings:
        location = finding.path
        if finding.line:
            location = f"{location}:{finding.line}"
        lines.append(
            f"::error file={finding.path},line={finding.line}::"
            f"[{finding.category}] {finding.message} ({location})"
        )
    lines.append(f"PII {mode}: {len(findings)} finding(s) in {scope} scope.")
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse arguments supplied by the shell wrapper."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument(
        "--scope",
        choices=("staged", "head", "history"),
        default="head",
    )
    parser.add_argument("--mode", choices=("audit", "enforce"), default="audit")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the content scan and map its result to the documented exit codes."""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if not args.input_dir.is_dir():
        print(
            f"PII scan error: materialized input directory is missing: {args.input_dir}",
            file=sys.stderr,
        )
        return 2
    try:
        findings = selected_findings(scan(args.input_dir), args.mode)
    except OSError as error:
        print(f"PII scan error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(
            json.dumps(
                {
                    "scope": args.scope,
                    "mode": args.mode,
                    "findings": [asdict(finding) for finding in findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(render_text(findings, scope=args.scope, mode=args.mode))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
