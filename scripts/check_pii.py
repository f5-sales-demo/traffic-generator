"""Detect PII-shaped values in tracked Git content without reading the worktree.

The scanner deliberately has two modes:

* ``enforce`` reports only deterministic, high-confidence findings suitable for
  a commit or CI gate.
* ``audit`` includes review-required surfaces and lower-confidence indicators
  used during a repository sweep.

Exit 0 means no findings, 1 means findings, and 2 means the scan could not run.
Finding messages never contain the matched value.
"""

# The scanner remains one auditable policy unit until the parser seams tracked in
# issues #932, #933, #939, and #940 are implemented.
# pylint: disable=too-many-lines

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import unicodedata
import urllib.parse
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
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
    ".hcl",
    ".java",
    ".js",
    ".jq",
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
    ".tf",
    ".ts",
    ".tsx",
}
PROSE_DOCUMENT_SUFFIXES = {".adoc", ".asciidoc", ".md", ".mdx", ".rst", ".txt"}
SOURCE_FENCE_LANGUAGES = {
    "c",
    "cpp",
    "csharp",
    "go",
    "hcl",
    "java",
    "javascript",
    "js",
    "jq",
    "jsx",
    "kotlin",
    "php",
    "py",
    "python",
    "rb",
    "ruby",
    "rust",
    "swift",
    "terraform",
    "ts",
    "tsx",
    "typescript",
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
    r"(?i)(?P<field_prefix>^|[^A-Za-z0-9_/-])"
    r"(?P<key_open>[*_~`'\"]*)"
    r"(?P<key>tenant(?:_name|_id)?|customer(?:_name|_id)?|account(?:_name|_id)?|"
    r"subscription(?:_name|_id)|project(?:_name|_id)|namespace)"
    r"(?P<key_close>[*_~`'\"]*)\s*(?P<separator>[:=])\s*(?P<quote>['\"`]?)"
    r"(?P<value>(?:(?!\\[rn])[^'\"`#,\r\n}\]])+)"
)
PROSE_IDENTITY_QUANTIFIER_RE = re.compile(
    r"(?:^|\s)(?:any|each|every|no)$",
    re.IGNORECASE,
)
PROSE_SAFE_LANGUAGE_RE = re.compile(
    r"(?:use\s+the\s+documented\s+example\s+"
    r"(?:tenant|customer|account|project|namespace)"
    r"|use\s+the\s+synthetic\s+placeholder\s+value"
    r"|use\s+the\s+customer['\u2019]s\s+documented\s+example\s+tenant"
    r")[.!?]",
    re.IGNORECASE,
)
PROSE_SAFE_CONTINUATION_RE = re.compile(
    r"(?:continue\s+with\s+the\s+setup\s+instructions[.!?])?",
    re.IGNORECASE,
)
JQ_COMMAND_RE = re.compile(
    r"(?:^|[|;&(])\s*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
    r"(?:(?:command(?:\s+--)?|exec(?:\s+--)?|nohup|"
    r"(?:[^\s;|&]*/)?nice(?:\s+(?:-n\s+\S+|-[0-9]+))?|"
    r"(?:[^\s;|&]*/)?timeout\s+\S+|"
    r"stdbuf(?:(?:\s+-(?:i|o|e)\S+))*|"
    r"(?:[^\s;|&]*/)?time(?:\s+-\S+)*|"
    r"xargs(?:(?:\s+-(?:L|n|P)\s*[0-9]+)|(?:\s+(?:-0|--null))|"
    r"(?:\s+-I(?:\s+\S+|\S+))|"
    r"(?:\s+--max-args(?:=\S+|\s+\S+))|(?:\s+-r)|"
    r"(?:\s+-d(?:\s+\S+|\S+))|(?:\s+--replace(?:=\S+)?))*|"
    r"sudo(?:(?:\s+-[nEHSkK]+)|(?:\s+-(?:g|u)\s+\S+)|"
    r"(?:\s+--group(?:=\S+|\s+\S+))|"
    r"(?:\s+--user(?:=\S+|\s+\S+))|"
    r"(?:\s+--preserve-env(?:=\S+)?)|(?:\s+--))*|"
    r"(?:[^\s;|&]*/)?env(?:(?:\s+-i)|(?:\s+-u\s+\S+)|"
    r"(?:\s+--ignore-environment)|"
    r"(?:\s+--unset(?:=\S+|\s+\S+))|(?:\s+--))*)\s+"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*"
    r")*"
    r"(?:[^\s;|&]*/)?jq(?:\s|$)"
)
FENCE_RE = re.compile(
    r"^(?P<leading> {0,3})"
    r"(?P<container>(?:(?:> ?|(?:[-+*]|[0-9]{1,9}[.)])[ \t]{1,4}))*)"
    r"(?P<indent> {0,3})"
    r"(?P<marker>`{3,}|~{3,})(?P<info>[^\r\n]*)$",
)
FENCE_CLOSE_RE = re.compile(
    r"^\s*(?:>\s*)*(?:(?:[-+*]|[0-9]{1,9}[.)])\s+)*"
    r"(?P<marker>`{3,}|~{3,})\s*$"
)
FENCE_CLASS_RE = re.compile(r"(?:^|[\s,])\.([A-Za-z0-9_+-]+)(?=[\s,]|$)")
ANSI_ESCAPE_RE = re.compile(
    r"(?:(?:\x1b\]|\x9d).*?(?:\x07|\x9c|\x1b\\)|"
    r"(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*?(?:\x9c|\x1b\\)|"
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~]|"
    r"\x1b[ -/]*[0-~]|[\x80-\x9f])",
    re.DOTALL,
)
ZERO_WIDTH_CONTROL_RE = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f\x7f]")
YAML_ANCHOR_VALUE_RE = re.compile(r"&(?P<name>[A-Za-z0-9_.-]+)")
YAML_TAG_CHARACTER = r"(?:%[0-9A-Fa-f]{2}|[!A-Za-z0-9_.:/+@;&=?$~,'()#*-])"
YAML_TAG_RE = re.compile(rf"!(?:<[^>\r\n]+>|{YAML_TAG_CHARACTER}+)?\s+")
YAML_BLOCK_START_RE = re.compile(
    r":\s*(?:&(?P<anchor>[A-Za-z0-9_.-]+)\s+)?"
    r"[|>](?:[+-]?[1-9]?|[1-9][+-])\s*$"
)
SAFE_BLOCK_PROSE_RE = re.compile(
    r"(?:documented\s+example|synthetic\s+placeholder)\s+text[.!?]?",
    re.IGNORECASE,
)
TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^{}\s]+\}|"
    r"\{[A-Za-z_][A-Za-z0-9_.-]*\}|<[A-Za-z_][A-Za-z0-9_.-]*>|"
    r"\{\{\s*[^{}\r\n]+?\s*\}\}|\[%\s*[^%\r\n]+?\s*%\])"
)
SHELL_DOUBLE_ESCAPE_RE = re.compile(r'\\(["\\])')
NON_OUTPUT_JQ_STRING_FUNCTIONS = {
    "IN",
    "all",
    "any",
    "bsearch",
    "capture",
    "combinations",
    "contains",
    "delpaths",
    "endswith",
    "error",
    "getpath",
    "group_by",
    "has",
    "in",
    "index",
    "indices",
    "inside",
    "isempty",
    "ltrimstr",
    "match",
    "max_by",
    "min_by",
    "rindex",
    "rtrimstr",
    "scan",
    "select",
    "sort_by",
    "split",
    "splits",
    "startswith",
    "strptime",
    "test",
    "unique_by",
    "paths",
}
NON_OUTPUT_JQ_NUMBER_FUNCTIONS = NON_OUTPUT_JQ_STRING_FUNCTIONS | {
    "combinations",
    "flatten",
}
POSITIONAL_JQ_OUTPUT_ARGUMENTS = {
    "gsub": {1},
    "limit": {1},
    "nth": {1},
    "setpath": {1},
    "sub": {1},
    "until": {1},
}
JQ_RANGE_OUTPUT_ARGUMENTS = {0, 1}
JQ_NON_INDEX_KEYWORDS = {
    "as",
    "catch",
    "do",
    "elif",
    "else",
    "end",
    "foreach",
    "if",
    "label",
    "or",
    "reduce",
    "then",
    "try",
}
SOURCE_COMMENT_EXPRESSION_RE = re.compile(
    r"(?:[A-Za-z_$][A-Za-z0-9_$]*(?:\.|::|->))+[A-Za-z_$][A-Za-z0-9_$]*"
    r"|[A-Za-z_$][A-Za-z0-9_$]*\s*\([^\r\n]*\)"
)
JQ_OPTION_ARITY = {
    "--arg": 2,
    "--argfile": 2,
    "--argjson": 2,
    "--indent": 1,
    "--rawfile": 2,
    "--slurpfile": 2,
    "-L": 1,
}
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
    r"GPSLatitude|GPSLongitude|OwnerName|CameraOwnerName",
    re.IGNORECASE,
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
    r"[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9][0-9_]*)?"
    r");?"
)
MAX_COMMONMARK_INDENT = 3
DEFAULT_IGNORABLE_RANGES = (
    (0x034F, 0x034F),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
SURROGATE_ESCAPE_BASE = 0xDC00
SURROGATE_ESCAPE_FIRST = 0xDC80
SURROGATE_ESCAPE_C1_LAST = 0xDC9F
SURROGATE_ESCAPE_LAST = 0xDCFF

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
    "prefix",
    "required",
    "string",
    "suffix",
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


@dataclass
class JqScope:
    """One nested jq delimiter with its function argument position."""

    opener: str
    context: str
    argument: int = 0


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


def invisible_format_character(character: str) -> bool:
    """Return whether Unicode renders a format mark without visible width."""
    codepoint = ord(character)
    ranges = (first <= codepoint <= last for first, last in DEFAULT_IGNORABLE_RANGES)
    default_ignorable = any(ranges)
    return unicodedata.category(character) == "Cf" or default_ignorable


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


def serialization_nesting(text: str) -> int:
    """Count unmatched flow-collection delimiters outside quoted strings."""
    nesting = 0
    quote: str | None = None
    escaped = False
    for character in text:
        if quote:
            if character == quote and not escaped:
                quote = None
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
        elif character in {"'", '"'}:
            quote = character
        elif character in "[{":
            nesting += 1
        elif character in "]}" and nesting:
            nesting -= 1
    return nesting


def structured_field_value(path: str, line: str, match: re.Match[str]) -> str:
    """Read one field value without truncating quoted punctuation or YAML scalars."""
    start = match.start("value")
    quote = match.group("quote")
    if quote:
        index = start
        while index < len(line):
            backslashes = 0
            before = index - 1
            while before >= start and line[before] == "\\":
                backslashes += 1
                before -= 1
            yaml_single_quote = quote == "'"
            next_character_is_quote = index + 1 < len(line) and line[index + 1] == quote
            doubled_yaml_quote = yaml_single_quote and next_character_is_quote
            if line[index] == quote and doubled_yaml_quote:
                index += 2
                continue
            if line[index] == quote and backslashes % 2 == 0:
                return line[start:index]
            index += 1
        return line[start:]

    yaml = PurePosixPath(path).suffix.lower() in {".yaml", ".yml"}
    prefix = line[:start]
    flow_context = serialization_nesting(prefix) > 0
    placeholder = TEMPLATE_PLACEHOLDER_RE.match(line, start)
    if placeholder:
        raw_remainder = line[placeholder.end() :]
        remainder = raw_remainder.lstrip()
        whitespace_comment = raw_remainder != remainder and remainder.startswith("#")
        flow_delimiter = bool(remainder) and remainder[0] in ",}]"
        if not remainder or whitespace_comment or (flow_context and flow_delimiter):
            return placeholder.group()

    index = start
    while index < len(line):
        character = line[index]
        if character in "}]`" or (character == "," and (not yaml or flow_context)):
            break
        if character == "#" and (index == start or line[index - 1].isspace()):
            break
        index += 1
    return line[start:index]


def unwrapped_identity_value(value: str) -> str:
    """Remove YAML reference syntax and Markdown emphasis from a field value."""
    value = normalized_value(value)
    if tag := YAML_TAG_RE.match(value):
        return unwrapped_identity_value(value[tag.end() :])
    anchor = re.fullmatch(r"&[A-Za-z0-9_.-]+(?:\s+(.*))?", value)
    if anchor:
        return unwrapped_identity_value(anchor.group(1) or "")
    strong_emphasis = re.fullmatch(r"(?:\*\*|__)(.+?)(?:\*\*|__)", value)
    if strong_emphasis:
        return unwrapped_identity_value(strong_emphasis.group(1))
    emphasis = re.fullmatch(r"[*_](.+?)[*_]", value)
    if emphasis:
        return unwrapped_identity_value(emphasis.group(1))
    alias = re.fullmatch(r"\*([A-Za-z0-9_.-]+)", value)
    return unwrapped_identity_value(alias.group(1)) if alias else value


def placeholder_value(value: str) -> bool:
    """Return whether a value is synthetic, schematic, or schema syntax."""
    value = unwrapped_identity_value(value)
    if not value:
        return True
    lower = value.lower()
    if (
        lower in SCHEMA_SENTINELS
        or lower in SAFE_IDENTITY_VALUES_LOWER
        or lower in {"false", "true", "~"}
        or decimal_numeric_value(value) == 0
        or bool(re.fullmatch(r"[|>](?:[+-]?[1-9]?|[1-9][+-])", value))
    ):
        return True
    if re.fullmatch(r"example(?:[-_.][a-z0-9]+)*", lower):
        return True
    if re.fullmatch(r"x[A-Z][A-Z0-9_]*x", value):
        return True
    first, separator, second = value.partition("|")
    if first and separator and second and "|" not in second:
        safe_composite = placeholder_value(first) and placeholder_value(second)
    else:
        safe_composite = False
    return (
        safe_composite
        or lower in SAFE_PERSON_NAMES
        or bool(TEMPLATE_PLACEHOLDER_RE.fullmatch(value))
        or bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", value))
    )


def is_proven_prose_identity_label(path: str, line: str, match: re.Match[str]) -> bool:
    """Return whether an identity-shaped token is demonstrably an ordinary prose label."""
    if (
        PurePosixPath(path).suffix.lower() not in PROSE_DOCUMENT_SUFFIXES
        or match.group("separator") != ":"
        or not match.group("field_prefix").isspace()
        or bool(match.group("key_open"))
        or bool(match.group("key_close"))
    ):
        return False
    before = line[: match.start()].rstrip()
    if not PROSE_IDENTITY_QUANTIFIER_RE.search(before):
        return False
    prose = line[match.start("separator") + 1 :].strip()
    quote_pairs = {"'": "'", '"': '"', "\u2018": "\u2019", "\u201c": "\u201d"}
    closing_quote = quote_pairs.get(prose[:1])
    if closing_quote:
        closing = prose.find(closing_quote, 1)
        if closing < 0:
            return False
        trailing_prose = prose[closing + 1 :].strip()
        if not PROSE_SAFE_CONTINUATION_RE.fullmatch(trailing_prose):
            return False
        prose = prose[1:closing]
    return bool(PROSE_SAFE_LANGUAGE_RE.fullmatch(prose))


def is_structured_identity_field(path: str, line: str, match: re.Match[str]) -> bool:
    """Return whether an identity-shaped token should be enforced as structured data."""
    key_open = match.group("key_open")
    key_close = match.group("key_close")
    whole_inline_field = key_open == "`" and "`" in line[match.end() :]
    balanced_wrappers = sorted(key_open) == sorted(key_close)
    if not balanced_wrappers and not whole_inline_field:
        return False
    if match.group("field_prefix") == "." and match.group("separator") != "=":
        return False
    return not is_proven_prose_identity_label(path, line, match)


def is_source_comment(line: str, match: re.Match[str]) -> bool:
    """Return whether a field-shaped token occurs after a source comment marker."""
    prefix = line[: match.start("key")]
    return bool(re.search(r"(?:^|[\s;])(?://|#|/\*|\*)\s*[^\r\n]*$", prefix))


def match_is_in_spans(match: re.Match[str], spans: tuple[tuple[int, int], ...]) -> bool:
    """Return whether a field key begins inside one of the supplied source spans."""
    key_start = match.start("key")
    return any(start <= key_start < end for start, end in spans)


def jq_field_expression(line: str, start: int, shell_quote: str | None) -> str:
    """Return one jq field expression, honoring strings and nested delimiters."""
    expression = line[start:]
    if shell_quote == '"':
        expression = SHELL_DOUBLE_ESCAPE_RE.sub(r"\1", expression)
    quote: str | None = None
    escaped = False
    nesting = 0
    for index, character in enumerate(expression):
        if quote:
            if character == quote and not escaped:
                quote = None
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in "([{":
            nesting += 1
        elif character in ")]}":
            if nesting:
                nesting -= 1
            elif character == "}":
                return expression[:index]
        elif character == "," and not nesting:
            return expression[:index]
    return expression


def jq_bracket_is_index(prefix: str) -> bool:
    """Return whether an opening bracket indexes a preceding jq filter."""
    structured_filter = bool(
        re.search(
            r"(?:[)\]}]|\$[A-Za-z_]\w*|\.(?:[A-Za-z_]\w*)?|"
            r"[A-Za-z_$]\w*(?:\.[A-Za-z_$]\w*)+)\s*$",
            prefix,
        )
    )
    bare_filter = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
    if not bare_filter:
        return structured_filter
    return structured_filter or bare_filter.group(1) not in JQ_NON_INDEX_KEYWORDS


def decimal_numeric_value(value: str) -> Decimal | None:
    """Parse a jq-compatible decimal literal for semantic comparisons."""
    compact = value.replace("_", "").rstrip(";")
    try:
        return Decimal(compact)
    except InvalidOperation:
        return None


def jq_arithmetic_literal_is_neutral(value: str) -> bool:
    """Return whether a numeric operand is a conventional arithmetic modifier."""
    numeric = decimal_numeric_value(value)
    return numeric in {Decimal(-1), Decimal(0), Decimal(1)}


def jq_interpolation_end(value: str, start: int) -> int | None:
    """Return the closing parenthesis for one jq string interpolation."""
    quote: str | None = None
    escaped = False
    depth = 1
    index = start
    while index < len(value):
        character = value[index]
        if quote:
            if character == quote and not escaped:
                quote = None
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
        elif character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if not depth:
                return index
        index += 1
    return None


def jq_string_end(value: str, start: int, quote: str) -> int:
    """Return a jq string's closing quote without stopping inside interpolation."""
    index = start
    while index < len(value):
        if value[index] == "\\":
            run_end = index
            while run_end < len(value) and value[run_end] == "\\":
                run_end += 1
            odd_backslashes = (run_end - index) % 2 == 1
            interpolation = quote == '"' and odd_backslashes
            interpolation = interpolation and value[run_end : run_end + 1] == "("
            if interpolation:
                closing = jq_interpolation_end(value, run_end + 1)
                if closing is None:
                    return len(value)
                index = closing + 1
                continue
            escaped_character = (run_end - index) % 2 == 1 and run_end < len(value)
            index = run_end + 1 if escaped_character else run_end
            continue
        if value[index] == quote:
            return index
        index += 1
    return len(value)


def jq_unwrap_outer_groups(value: str) -> str:
    """Remove redundant parentheses enclosing an entire jq expression."""
    candidate = value.strip()
    while candidate.startswith("("):
        closing = jq_interpolation_end(candidate, 1)
        if closing != len(candidate) - 1:
            break
        candidate = candidate[1:closing].strip()
    return candidate


def jq_top_level_pipe_parts(value: str) -> list[str]:
    """Split a jq expression only at pipelines outside strings and delimiters."""
    parts: list[str] = []
    quote: str | None = None
    escaped = False
    nesting = 0
    start = 0
    for index, character in enumerate(value):
        if quote:
            if character == quote and not escaped:
                quote = None
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in "([{":
            nesting += 1
        elif character in ")]}" and nesting:
            nesting -= 1
        elif character == "|" and not nesting:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def jq_expression_is_identity_filter(value: str) -> bool:
    """Return whether a jq expression is only grouped identity filters."""
    candidate = jq_unwrap_outer_groups(value)
    parts = jq_top_level_pipe_parts(candidate)
    if len(parts) > 1:
        return all(jq_expression_is_identity_filter(part) for part in parts)
    return candidate == "."


def jq_identity_constant_expression(value: str) -> str:
    """Remove redundant groups and identity-only pipes from a jq expression."""
    candidate = jq_unwrap_outer_groups(value)
    while candidate:
        parts = jq_top_level_pipe_parts(candidate)
        if len(parts) == 1 or not jq_expression_is_identity_filter(parts[-1]):
            break
        candidate = jq_unwrap_outer_groups("|".join(parts[:-1]))
    return candidate


def jq_constant_string(value: str) -> str | None:
    """Return the content of a simple constant jq interpolation expression."""
    candidate = jq_identity_constant_expression(value)
    if not candidate or candidate[0] not in {"'", '"'}:
        return None
    closing = jq_string_end(candidate, 1, candidate[0])
    if closing != len(candidate) - 1:
        return None
    return candidate[1:closing]


def jq_constant_scalar(value: str) -> str | None:
    """Return a scalar jq interpolation followed only by identity filters."""
    candidate = jq_identity_constant_expression(value)
    if candidate in {"false", "null", "true"}:
        return candidate
    if NUMERIC_LITERAL_RE.fullmatch(candidate):
        numeric = decimal_numeric_value(candidate)
        return str(numeric) if numeric is not None else candidate.rstrip(";")
    return None


def jq_literal_fragments(value: str) -> list[str]:
    """Remove real jq interpolations while retaining escaped interpolation text."""
    fragments: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            current.append(value[index])
            index += 1
            continue
        run_end = index
        while run_end < len(value) and value[run_end] == "\\":
            run_end += 1
        backslashes = run_end - index
        interpolation = run_end < len(value) and value[run_end] == "("
        if not interpolation or backslashes % 2 == 0:
            current.extend("\\" * backslashes)
            index = run_end
            continue
        current.extend("\\" * (backslashes // 2))
        closing = jq_interpolation_end(value, run_end + 1)
        if closing is None:
            current.extend(value[index:])
            break
        constant = jq_constant_string(value[run_end + 1 : closing])
        if constant is not None:
            nested_fragments = jq_literal_fragments(constant)
            constant = nested_fragments[0] if len(nested_fragments) == 1 else None
        if constant is None:
            expression = value[run_end + 1 : closing]
            constant = jq_constant_scalar(expression)
        if constant is None:
            fragments.append("".join(current))
            current = []
        else:
            current.extend(constant)
        index = closing + 1
    fragments.append("".join(current))
    return fragments


def jq_open_scope(expression: str, index: int) -> JqScope:
    """Classify a jq opening delimiter as a call, group, container, or index."""
    opener = expression[index]
    prefix = expression[:index]
    if opener == "(":
        function = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", prefix)
        return JqScope(opener, function.group(1) if function else "group")
    if opener == "[":
        context = "index" if jq_bracket_is_index(prefix) else "array"
        return JqScope(opener, context)
    return JqScope(opener, "object")


def jq_close_scope(scopes: list[JqScope], closer: str) -> None:
    """Close a well-formed jq delimiter without corrupting outer context."""
    opener = {")": "(", "]": "[", "}": "{"}[closer]
    if scopes and scopes[-1].opener == opener:
        scopes.pop()


def jq_advance_argument(scopes: list[JqScope]) -> None:
    """Advance only a semicolon's immediate function/group argument."""
    if scopes and scopes[-1].opener == "(":
        scopes[-1].argument += 1


def jq_positional_roles(scopes: list[JqScope]) -> tuple[bool, bool]:
    """Return whether active jq calls place a literal in output/control roles."""
    output = False
    control = False
    for scope in scopes:
        output_arguments = POSITIONAL_JQ_OUTPUT_ARGUMENTS.get(scope.context)
        if output_arguments is None:
            continue
        if scope.argument in output_arguments:
            output = True
        else:
            control = True
    return output, control


def jq_range_bound_is_identifier_sized(value: str) -> bool:
    """Return whether a range bound is large enough to resemble an identifier."""
    numeric = decimal_numeric_value(value)
    return numeric is not None and abs(numeric) >= Decimal(100000)


def decode_jq_unicode_escapes(value: str) -> str:
    """Decode parity-valid jq Unicode escapes for placeholder comparison."""
    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\":
            decoded.append(value[index])
            index += 1
            continue
        run_end = index
        while run_end < len(value) and value[run_end] == "\\":
            run_end += 1
        backslashes = run_end - index
        escape_end = run_end + 5
        unicode_escape = (
            backslashes % 2 == 1
            and escape_end <= len(value)
            and value[run_end : run_end + 1] == "u"
            and bool(re.fullmatch(r"[0-9A-Fa-f]{4}", value[run_end + 1 : escape_end]))
        )
        decoded.extend("\\" * (backslashes // 2))
        if unicode_escape:
            decoded.append(chr(int(value[run_end + 1 : escape_end], 16)))
            index = escape_end
        else:
            decoded.extend("\\" * (backslashes % 2))
            index = run_end
    return "".join(decoded)


# pylint: disable-next=too-many-locals
def jq_output_strings(expression: str) -> list[str]:
    """Return jq strings that contribute to the field value, not control functions."""
    strings: list[str] = []
    scopes: list[JqScope] = []
    index = 0
    while index < len(expression):
        character = expression[index]
        if character in "([{":
            scopes.append(jq_open_scope(expression, index))
            index += 1
            continue
        if character in ")]}":
            jq_close_scope(scopes, character)
            index += 1
            continue
        if character == ";":
            jq_advance_argument(scopes)
            index += 1
            continue
        if character not in {"'", '"'}:
            index += 1
            continue
        string_start = index
        quote = character
        index = jq_string_end(expression, index + 1, quote)
        value = expression[string_start + 1 : index]
        active_functions = {scope.context for scope in scopes}
        _, positional_control = jq_positional_roles(scopes)
        prefix = expression[:string_start]
        suffix = expression[index + 1 :]
        comparison_before = bool(re.search(r"(?:==|!=|<=|>=|<|>)\s*$", prefix))
        comparison_after = bool(re.match(r"\s*(?:==|!=|<=|>=|<|>)", suffix))
        object_key = bool(re.match(r"\s*:", suffix))
        control_string = bool(active_functions & NON_OUTPUT_JQ_STRING_FUNCTIONS)
        comparison_string = comparison_before or comparison_after
        predicate_input = bool(re.match(r"\s*\|\s*(?:IN|all|any|in|isempty)\b", suffix))
        conditional_prefix = bool(re.search(r"\b(?:elif|if)\s*$", prefix))
        suffix_has_then = bool(re.search(r"\bthen\b", suffix))
        conditional_control = conditional_prefix and suffix_has_then
        ignored_string = comparison_string or object_key or control_string
        ignored_string = ignored_string or positional_control
        ignored_string = ignored_string or predicate_input or conditional_control
        if not ignored_string:
            strings.append(value)
        index += 1
    return strings


# pylint: disable-next=too-many-locals,too-many-statements
def jq_output_numbers(expression: str) -> list[str]:
    """Return numeric literals that contribute to a jq field value."""
    numbers: list[str] = []
    scopes: list[JqScope] = []
    index = 0
    number_re = re.compile(
        r"[+-]?(?:0[xX][0-9A-Fa-f_]+|0[bB][01_]+|0[oO][0-7_]+|"
        r"[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9][0-9_]*)?)"
    )
    while index < len(expression):
        character = expression[index]
        if character in {"'", '"'}:
            index = jq_string_end(expression, index + 1, character) + 1
            continue
        if character in "([{":
            scopes.append(jq_open_scope(expression, index))
            index += 1
            continue
        if character in ")]}":
            jq_close_scope(scopes, character)
            index += 1
            continue
        if character == ";":
            jq_advance_argument(scopes)
            index += 1
            continue
        number = number_re.match(expression, index)
        if not number:
            index += 1
            continue
        prefix = expression[:index]
        suffix = expression[number.end() :]
        leading_operator = number.group().startswith(("+", "-")) and bool(
            re.search(r"(?:[A-Za-z0-9_$.)\]}])\s*$", prefix)
        )
        identifier_prefix = index > 0 and expression[index - 1].isalnum()
        identifier_fragment = identifier_prefix and not leading_operator
        comparison = bool(re.search(r"(?:==|!=|<=|>=|<|>)\s*$", prefix))
        comparison = comparison or bool(re.match(r"\s*(?:==|!=|<=|>=|<|>)", suffix))
        object_key = bool(re.match(r"\s*:", suffix))
        active_functions = {scope.context for scope in scopes}
        control_number = bool(active_functions & NON_OUTPUT_JQ_NUMBER_FUNCTIONS)
        control_number = control_number or "index" in active_functions
        range_scopes = [scope for scope in scopes if scope.context == "range"]
        range_args = (scope.argument for scope in range_scopes)
        range_control = any(arg not in JQ_RANGE_OUTPUT_ARGUMENTS for arg in range_args)
        control_number = control_number or range_control
        positional_output, positional_control = jq_positional_roles(scopes)
        control_number = control_number or positional_control
        object_value = bool(
            re.search(
                r"(?:^|[{,])\s*(?:[A-Za-z_]\w*|['\"][^'\"]+['\"])\s*:\s*$",
                prefix,
            )
        )
        literal_container = "array" in active_functions or object_value
        output_branch = bool(re.search(r"(?:then|else|try|catch)\s*$", prefix))
        output_function = bool(
            active_functions
            - NON_OUTPUT_JQ_NUMBER_FUNCTIONS
            - POSITIONAL_JQ_OUTPUT_ARGUMENTS.keys()
            - {"array", "group", "index", "object", "range"}
        )
        group_starts_literal = bool(re.search(r"(?:^|[(:,;])\s*$", prefix))
        grouped_literal = "group" in active_functions and group_starts_literal
        arithmetic = leading_operator or bool(re.search(r"[+*/%-]\s*$", prefix))
        arithmetic = arithmetic or bool(re.match(r"\s*[+*/%-]", suffix))
        dynamic_expression = bool(
            re.search(
                r"(?:\.[A-Za-z_]|\$[A-Za-z_]|(?:env|input)\b)",
                expression,
            )
        )
        pipe_output = bool(re.search(r"\|\s*$", prefix))
        pipe_passthrough = bool(re.fullmatch(r"(?:\s*\|\s*\.)+\s*", suffix))
        constant_arithmetic = arithmetic and not dynamic_expression
        cancels_input = bool(re.search(r"(?:\*\s*0\b|\b0\s*\*)", expression))
        cancels_dynamic_input = dynamic_expression and cancels_input
        nonneutral = not jq_arithmetic_literal_is_neutral(number.group())
        sensitive_arithmetic = arithmetic and (nonneutral or cancels_dynamic_input)
        range_bound = any(s.argument in JQ_RANGE_OUTPUT_ARGUMENTS for s in range_scopes)
        identifier_sized_range = jq_range_bound_is_identifier_sized(number.group())
        range_output = range_bound and identifier_sized_range
        output_literal = literal_container or output_branch or output_function
        output_literal = (
            output_literal
            or grouped_literal
            or positional_output
            or range_output
            or pipe_output
            or pipe_passthrough
            or constant_arithmetic
            or sensitive_arithmetic
        )
        ignored = (
            identifier_fragment
            or comparison
            or object_key
            or control_number
            or (arithmetic and dynamic_expression and not sensitive_arithmetic)
        )
        if output_literal and not ignored:
            numbers.append(number.group())
        index = number.end()
    return numbers


def jq_value_is_expression(
    line: str,
    match: re.Match[str],
    jq_spans: tuple[tuple[int, int], ...],
) -> bool:
    """Return whether a value inside a jq program is computed rather than literal."""
    shell_quote: str | None = None
    for span_start, span_end in jq_spans:
        if span_start <= match.start("key") < span_end:
            if span_start and line[span_start - 1] in {"'", '"'}:
                shell_quote = line[span_start - 1]
            break
    expression = jq_field_expression(line, match.start("separator") + 1, shell_quote)
    for quoted_value in jq_output_strings(expression):
        for fragment in jq_literal_fragments(quoted_value):
            decoded_fragment = decode_jq_unicode_escapes(fragment)
            literal_fragment = decoded_fragment.strip(" -_.:/\\")
            has_identity_text = any(map(str.isalnum, literal_fragment))
            if not literal_fragment or not has_identity_text:
                continue
            repeated_example_root = literal_fragment.lower().count("example") > 1
            numeric_suffix = bool(re.search(r"[A-Za-z][0-9]{6,}$", literal_fragment))
            unsafe_composition = repeated_example_root or numeric_suffix
            if unsafe_composition or not placeholder_value(literal_fragment):
                return False
    for number in jq_output_numbers(expression):
        if not placeholder_value(number):
            return False
    fallback_numbers = re.findall(
        r"//\s*([+-]?[0-9][0-9_]*(?:\.[0-9_]+)?"
        r"(?:[eE][+-]?[0-9][0-9_]*)?)",
        expression,
    )
    return all(placeholder_value(number) for number in fallback_numbers)


def is_nonliteral_code_expression(
    line: str,
    match: re.Match[str],
    *,
    source_code: bool,
    jq_spans: tuple[tuple[int, int], ...],
    value_override: str | None = None,
) -> bool:
    """Return whether a structured field is executable or type syntax, not data."""
    value = normalized_value(value_override or match.group("value"))
    numeric_literal = bool(NUMERIC_LITERAL_RE.fullmatch(value))
    in_jq_filter = match_is_in_spans(match, jq_spans)
    in_source_comment = (source_code or in_jq_filter) and is_source_comment(line, match)
    if numeric_literal:
        return False
    if in_source_comment:
        expression = value.rstrip(";").strip()
        return bool(SOURCE_COMMENT_EXPRESSION_RE.fullmatch(expression))
    groups = match.groupdict()
    inline_key_opener = groups.get("key_open") == "`"
    inline_key_closer = bool(groups.get("key_close"))
    inline_field_closer = "`" in line[match.end() :]
    unclosed_inline_key = inline_key_opener and not inline_key_closer
    whole_inline_field = unclosed_inline_key and inline_field_closer
    if whole_inline_field:
        expression = value.rstrip(";").strip()
        named_expression = bool(SOURCE_COMMENT_EXPRESSION_RE.fullmatch(expression))
        return expression.startswith(".") or named_expression
    if in_jq_filter:
        return jq_value_is_expression(line, match, jq_spans)
    return source_code and not bool(match.group("quote"))


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


def closing_shell_quote(line: str, start: int, quote: str) -> int | None:
    """Find the end of one shell-quoted jq filter on a physical line."""
    index = start
    while index < len(line):
        backslashes = 0
        before = index - 1
        while before >= 0 and line[before] == "\\":
            backslashes += 1
            before -= 1
        quote_is_unescaped = quote == "'" or backslashes % 2 == 0
        if line[index] == quote and quote_is_unescaped:
            return index
        index += 1
    return None


def shell_words(
    line: str,
    start: int,
) -> list[tuple[int, int, int, str | None, bool]]:
    """Split a shell command into word spans without evaluating its contents."""
    words: list[tuple[int, int, int, str | None, bool]] = []
    index = start
    while index < len(line):
        while index < len(line) and line[index].isspace():
            index += 1
        if index >= len(line) or line[index] in ";|&":
            break
        quote = line[index] if line[index] in {"'", '"'} else None
        if quote:
            content_start = index + 1
            closing = closing_shell_quote(line, content_start, quote)
            if closing is None:
                words.append((content_start, len(line), len(line), quote, False))
                break
            words.append((content_start, closing, closing + 1, quote, True))
            index = closing + 1
            continue
        content_start = index
        while index < len(line):
            if line[index].isspace() or line[index] in ";|&":
                break
            index += 1
        words.append((content_start, index, index, None, True))
    return words


def jq_program_word(
    line: str,
    words: list[tuple[int, int, int, str | None, bool]],
) -> tuple[int, int, int, str | None, bool] | None:
    """Return jq's filter word after consuming options and their arguments."""
    index = 0
    while index < len(words):
        word = words[index]
        word_text = line[word[0] : word[1]]
        if word_text == "--":
            return words[index + 1] if index + 1 < len(words) else None
        if not word_text.startswith("-") or word_text == "-":
            return word
        option = word_text.split("=", 1)[0]
        index += 1 + JQ_OPTION_ARITY.get(option, 0)
    return None


def jq_filter_spans(
    line: str,
    active_quote: str | None,
) -> tuple[tuple[tuple[int, int], ...], str | None]:
    """Locate shell-quoted jq programs without leaking across command boundaries."""
    spans: list[tuple[int, int]] = []
    cursor = 0
    if active_quote:
        closing = closing_shell_quote(line, 0, active_quote)
        if closing is None:
            return ((0, len(line)),), active_quote
        spans.append((0, closing))
        cursor = closing + 1

    while command := JQ_COMMAND_RE.search(line, cursor):
        program = jq_program_word(line, shell_words(line, command.end()))
        if program is None:
            break
        content_start, content_end, raw_end, quote, closed = program
        spans.append((content_start, content_end))
        if not closed:
            return tuple(spans), quote
        cursor = raw_end
    return tuple(spans), None


def scan_contacts(
    path: str,
    line_number: int,
    line: str,
    attribution_context: bool,
    findings: set[Finding],
    *,
    source_code: bool,
    jq_spans: tuple[tuple[int, int], ...],
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
            value = structured_field_value(path, line, match)
            if NUMERIC_LITERAL_RE.fullmatch(value):
                continue
            if is_nonliteral_code_expression(
                line,
                match,
                source_code=source_code,
                jq_spans=jq_spans,
                value_override=value,
            ):
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


# pylint: disable-next=too-many-arguments
def scan_structured_identity(
    path: str,
    line_number: int,
    line: str,
    findings: set[Finding],
    *,
    source_code: bool,
    jq_spans: tuple[tuple[int, int], ...],
    yaml_aliases: dict[str, bool],
    yaml_alias_events: tuple[tuple[int, str, bool], ...],
) -> None:
    """Scan structured fields for customer identifiers and personal records."""
    for match in IDENTITY_FIELD_RE.finditer(line):
        if not is_structured_identity_field(path, line, match):
            continue
        value = structured_field_value(path, line, match)
        jq_literal = match_is_in_spans(match, jq_spans) and not jq_value_is_expression(
            line,
            match,
            jq_spans,
        )
        if is_nonliteral_code_expression(
            line,
            match,
            source_code=source_code,
            jq_spans=jq_spans,
            value_override=value,
        ):
            continue
        alias = None
        if not match.group("quote"):
            alias = re.fullmatch(r"\*([A-Za-z0-9_.-]+)", normalized_value(value))
        if alias:
            aliases_at_value = yaml_aliases.copy()
            for position, name, safe in yaml_alias_events:
                if position >= match.start("value"):
                    break
                aliases_at_value[name] = safe
            safe_alias = aliases_at_value.get(alias.group(1), False)
        else:
            safe_alias = None
        if jq_literal or not (safe_alias if alias else placeholder_value(value)):
            add_finding(
                findings,
                path=path,
                line=line_number,
                category="customer-identifier",
                message=f"{match.group('key')} contains a literal organization identifier",
            )

    for match in ADDRESS_FIELD_RE.finditer(line):
        value = structured_field_value(path, line, match)
        if is_nonliteral_code_expression(
            line,
            match,
            source_code=source_code,
            jq_spans=jq_spans,
            value_override=value,
        ):
            continue
        if not placeholder_value(value):
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


def parse_fence_language(info: str) -> str:
    """Extract a language from CommonMark, Pandoc, or RMarkdown fence info."""
    info = info.strip()
    if not info:
        return ""
    if info.startswith("{") and info.endswith("}"):
        attributes = info[1:-1].strip()
        candidates = FENCE_CLASS_RE.findall(attributes)
        if not candidates:
            items = re.split(r"[\s,]+", attributes)
            candidates = []
            for item in items:
                if not item.startswith("#"):
                    candidates.append(item.rstrip(","))
        for candidate in candidates:
            if candidate.lower() in SOURCE_FENCE_LANGUAGES | {"jq"}:
                return candidate.lower()
        return candidates[0].lower() if candidates else ""
    return info.split(maxsplit=1)[0].lower()


def yaml_syntax(line: str) -> str:
    """Mask quoted values and comments before inspecting YAML control syntax."""
    syntax: list[str] = []
    quote: str | None = None
    escaped = False
    for character in line:
        if quote:
            syntax.append(" ")
            if character == quote and not escaped:
                quote = None
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
            continue
        if character in {"'", '"'}:
            quote = character
            syntax.append(" ")
        elif character == "#" and (not syntax or syntax[-1].isspace()):
            break
        else:
            syntax.append(character)
    return "".join(syntax)


def yaml_value_text(line: str) -> str:
    """Remove a YAML comment while preserving quoted scalar content."""
    value: list[str] = []
    quote: str | None = None
    escaped = False
    for character in line:
        if character == "#" and quote is None and (not value or value[-1].isspace()):
            break
        value.append(character)
        if quote:
            if character == quote and not escaped:
                quote = None
            escaped = character == "\\" and not escaped
            if character != "\\":
                escaped = False
        elif character in {"'", '"'}:
            quote = character
    return "".join(value)


def yaml_anchor_value(line: str, start: int) -> str:
    """Extract the scalar node immediately following a YAML anchor."""
    tail = yaml_value_text(line[start:]).lstrip()
    while tag := YAML_TAG_RE.match(tail):
        tail = tail[tag.end() :]
    if not tail:
        return ""
    quote = tail[0] if tail[0] in {"'", '"'} else None
    if quote:
        index = 1
        while index < len(tail):
            if quote == "'" and tail[index : index + 2] == "''":
                index += 2
                continue
            if tail[index] == quote:
                backslashes = 0
                before = index - 1
                while before >= 0 and tail[before] == "\\":
                    backslashes += 1
                    before -= 1
                if quote == "'" or backslashes % 2 == 0:
                    return normalized_value(tail[: index + 1])
            index += 1
        return normalized_value(tail)
    flow_context = serialization_nesting(line[:start]) > 0
    delimiter = re.search(r"[],}]", tail) if flow_context else None
    return normalized_value(tail[: delimiter.start()] if delimiter else tail)


def update_yaml_aliases(
    line: str,
    aliases: dict[str, bool],
) -> tuple[tuple[int, str, bool], ...]:
    """Apply scalar anchor declarations in source order within one YAML document."""
    events: list[tuple[int, str, bool]] = []
    syntax = yaml_syntax(line)
    for anchor in YAML_ANCHOR_VALUE_RE.finditer(syntax):
        value = yaml_anchor_value(line, anchor.end("name"))
        referenced = re.fullmatch(r"\*([A-Za-z0-9_.-]+)", value)
        if referenced:
            safe = aliases.get(referenced.group(1), False)
        else:
            block_value = bool(re.fullmatch(r"[|>](?:[+-]?[1-9]?|[1-9][+-])", value))
            safe = bool(value) and not block_value and placeholder_value(value)
        name = anchor.group("name")
        aliases[name] = safe
        events.append((anchor.start(), name, safe))
    return tuple(events)


def safe_yaml_block_content(value: str) -> bool:
    """Return whether a YAML block line is explicitly synthetic identity content."""
    value = normalized_value(value)
    safe_block_prose = bool(SAFE_BLOCK_PROSE_RE.fullmatch(value))
    safe_label_prose = bool(PROSE_SAFE_LANGUAGE_RE.fullmatch(value))
    safe_prose = safe_block_prose or safe_label_prose
    return not value or safe_prose or placeholder_value(value)


def scan_yaml_identity_blocks(path: str, text: str, findings: set[Finding]) -> None:
    """Inspect scalar bodies owned by YAML identity fields."""
    active_block_indent: int | None = None
    block_key = ""
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = ANSI_ESCAPE_RE.sub("", raw_line)
        stripped = line.strip()
        indentation = len(line) - len(line.lstrip())
        if active_block_indent is not None and stripped:
            if indentation > active_block_indent:
                value = normalized_value(stripped)
                if not safe_yaml_block_content(value):
                    add_finding(
                        findings,
                        path=path,
                        line=line_number,
                        category="customer-identifier",
                        message=f"{block_key} contains a literal organization identifier",
                    )
                continue
            active_block_indent = None
        for match in IDENTITY_FIELD_RE.finditer(line):
            value = normalized_value(match.group("value"))
            if re.fullmatch(r"[|>](?:[+-]?[1-9]?|[1-9][+-])", value):
                active_block_indent = indentation
                block_key = match.group("key")
                break


# pylint: disable-next=too-many-locals,too-many-branches,too-many-statements
def scan_text(path: str, text: str, findings: set[Finding]) -> None:
    """Apply structured and line-oriented detectors to one text blob."""
    text = ANSI_ESCAPE_RE.sub("", text)
    text = ZERO_WIDTH_CONTROL_RE.sub("", text)
    visible = (char for char in text if not invisible_format_character(char))
    text = "".join(visible)
    legal_path = is_legal_attribution_path(path)
    suffix = PurePosixPath(path).suffix.lower()
    yaml = suffix in {".yaml", ".yml"}
    aliases: dict[str, bool] = {}
    scan_yaml_identity_blocks(path, text, findings)
    fence_marker: str | None = None
    fence_language: str | None = None
    fence_close_column: int | None = None
    active_jq_quote: str | None = None
    yaml_block_indent: int | None = None
    yaml_block_anchor: str | None = None
    yaml_block_safe = False
    yaml_block_has_content = False
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = ANSI_ESCAPE_RE.sub("", raw_line)
        line_aliases = aliases.copy()
        yaml_alias_events: tuple[tuple[int, str, bool], ...] = ()
        if yaml:
            syntax_line = yaml_syntax(line)
            syntax = syntax_line.strip()
            indentation = len(line) - len(line.lstrip())
            inside_block = False
            if yaml_block_indent is not None:
                if not line.strip() or indentation > yaml_block_indent:
                    inside_block = True
                    if line.strip() and yaml_block_anchor:
                        yaml_block_has_content = True
                        yaml_block_safe &= safe_yaml_block_content(line.strip())
                else:
                    if yaml_block_anchor:
                        resolved_safe = yaml_block_has_content and yaml_block_safe
                        aliases[yaml_block_anchor] = resolved_safe
                    yaml_block_indent = None
                    yaml_block_anchor = None
            if not inside_block:
                if syntax in {"---", "..."}:
                    aliases.clear()
                    line_aliases = aliases.copy()
                else:
                    line_aliases = aliases.copy()
                    yaml_alias_events = update_yaml_aliases(line, aliases)
                    block = YAML_BLOCK_START_RE.search(syntax_line)
                    if block:
                        yaml_block_indent = indentation
                        yaml_block_anchor = block.group("anchor")
                        yaml_block_safe = True
                        yaml_block_has_content = False
        fence = FENCE_RE.match(line)
        fence_indent = 0
        if fence:
            fence_indent = len(fence.group("leading")) + len(fence.group("indent"))
        top_level_fence = fence and not fence.group("container")
        if top_level_fence and fence_indent > MAX_COMMONMARK_INDENT:
            fence = None
        if fence and fence.group("indent"):
            container = fence.group("container").rstrip()
            if container and container[-1] in "-+*.)":
                fence = None
        invalid_backtick_info = False
        if fence:
            backtick_marker = fence.group("marker").startswith("`")
            invalid_backtick_info = backtick_marker and "`" in fence.group("info")
        if invalid_backtick_info:
            fence = None
        close = FENCE_CLOSE_RE.match(line) if fence_marker else None
        closing_fence = bool(
            close
            and fence_marker
            and fence_close_column is not None
            and "\t" not in line[: close.start("marker")]
            and close.start("marker") <= fence_close_column
            and fence_marker.startswith(close.group("marker")[0])
            and len(close.group("marker")) >= len(fence_marker)
        )
        opening_fence = bool(fence and fence_marker is None)
        if opening_fence and fence:
            fence_marker = fence.group("marker")
            fence_language = parse_fence_language(fence.group("info"))
            if fence.group("container"):
                fence_close_column = fence.start("marker") + 3
            else:
                fence_close_column = 3
            active_jq_quote = None

        fence_boundary = closing_fence or opening_fence
        effective_language = None if fence_boundary else fence_language
        suffix_is_source = suffix in SOURCE_CODE_SUFFIXES
        fence_is_source = effective_language in SOURCE_FENCE_LANGUAGES
        source_code = suffix_is_source or fence_is_source
        spans: tuple[tuple[int, int], ...]
        if suffix == ".jq" or effective_language == "jq":
            spans = ((0, len(line)),)
            active_jq_quote = None
        elif source_code:
            spans = ()
            active_jq_quote = None
        else:
            spans, active_jq_quote = jq_filter_spans(line, active_jq_quote)

        is_commit_message = path.startswith("<commit:")
        trailer_match = PROVENANCE_TRAILER_RE.match(line)
        provenance_trailer = bool(is_commit_message and trailer_match)
        scan_contacts(
            path,
            line_number,
            line,
            legal_path or provenance_trailer,
            findings,
            source_code=source_code,
            jq_spans=spans,
        )
        scan_structured_identity(
            path,
            line_number,
            line,
            findings,
            source_code=source_code,
            jq_spans=spans,
            yaml_aliases=line_aliases,
            yaml_alias_events=yaml_alias_events,
        )
        scan_query_parameters(path, line_number, line, findings)
        scan_public_ips(path, line_number, line, findings)

        if closing_fence:
            fence_marker = None
            fence_language = None
            fence_close_column = None
            active_jq_quote = None


def looks_binary(data: bytes) -> bool:
    """Use NUL bytes as a conservative binary-content signal."""
    return b"\0" in data[:8192]


def scan_binary(path: str, data: bytes, findings: set[Finding], *, media: bool) -> None:
    """Inspect ASCII-compatible binary metadata without rendering the file."""
    # Keep only printable metadata runs. Treating every byte as Latin-1 lets
    # compression noise masquerade as contact syntax across arbitrary bytes.
    printable_data = data if media else data.replace(b"\0", b"")
    matches = PRINTABLE_ASCII_RE.finditer(printable_data)
    text = "\n".join(match.group(0).decode("ascii") for match in matches)
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
    decoded = data.decode("utf-8", "surrogateescape")
    text: list[str] = []
    for character in decoded:
        codepoint = ord(character)
        if SURROGATE_ESCAPE_FIRST <= codepoint <= SURROGATE_ESCAPE_C1_LAST:
            text.append(chr(codepoint - SURROGATE_ESCAPE_BASE))
        elif not SURROGATE_ESCAPE_FIRST <= codepoint <= SURROGATE_ESCAPE_LAST:
            text.append(character)
    scan_text(path, "".join(text), findings)


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
        annotation = f"[{finding.category}] {finding.message} ({location})"
        lines.append(f"::error file={finding.path},line={finding.line}::{annotation}")
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
