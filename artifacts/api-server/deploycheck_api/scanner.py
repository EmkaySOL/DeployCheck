from __future__ import annotations

import io
import re
import stat
import time
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import PurePosixPath
from uuid import uuid4

from .schemas import Finding, ScanResponse, Severity, SeverityCounts

MAX_ARCHIVE_BYTES = 12 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 40 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 1000
MAX_FILES = 500
MAX_PATH_DEPTH = 16
MAX_FINDINGS = 250
MAX_SCAN_SECONDS = 8
MAX_COMPRESSION_RATIO = 100

IGNORED_DIRECTORIES = {
    ".cache",
    ".git",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".turbo",
    ".venv",
    "__pycache__",
    "bower_components",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "venv",
    "vendor",
}

SUPPORTED_SUFFIXES = {
    ".bash",
    ".cfg",
    ".conf",
    ".cjs",
    ".go",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".php",
    ".pem",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".key",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zsh",
}

SPECIAL_FILENAMES = {
    ".dockerignore",
    ".gitignore",
    "dockerfile",
    "makefile",
}

ENV_SAMPLE_FILENAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}

BUILTIN_ENVIRONMENT_VARIABLES = {
    "CI",
    "EDITOR",
    "HOME",
    "HOSTNAME",
    "LANG",
    "LOGNAME",
    "NODE_ENV",
    "PATH",
    "PORT",
    "PWD",
    "SHELL",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "USER",
}

TOKEN_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{12,}\b"),
)

PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)

SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(?P<key>
        (?:[A-Za-z_][A-Za-z0-9-]*[_-])?
        (?:API[_-]?KEY|ACCESS[_-]?TOKEN|CLIENT[_-]?SECRET|
           SECRET(?:[_-]?KEY)?|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY)
    )\b
    \s*(?:=|:)\s*
    (?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,#;]+)
    """
)

DEBUG_ENABLED_PATTERN = re.compile(
    r"""(?ix)
    \b(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG)\b
    \s*(?:=|:)\s*
    ["']?(?:true|1|yes|on)["']?
    """
)

ENV_DECLARATION_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")

ENV_REFERENCE_PATTERNS = (
    re.compile(r"\b(?:process|import\.meta)\.env\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(
        r"""\b(?:process\.env|import\.meta\.env)\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""
    ),
    re.compile(
        r"""\bos\.environ(?:\.get)?\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""
    ),
    re.compile(
        r"""\bos\.environ\s*\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\]"""
    ),
    re.compile(r"""\bgetenv\s*\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""),
    re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:[^}]*)\}"),
    re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\b"),
)

PLACEHOLDER_VALUES = {
    "",
    "***",
    "changeme",
    "change_me",
    "change-me",
    "false",
    "none",
    "null",
    "placeholder",
    "redacted",
    "todo",
    "true",
    "undefined",
    "xxx",
}


class InvalidArchiveError(ValueError):
    """The uploaded archive is malformed or contains an unsafe path."""


class ArchiveLimitError(ValueError):
    """The uploaded archive exceeds a documented processing limit."""


class ScanTimeoutError(TimeoutError):
    """Static analysis exceeded its request time budget."""


def _validate_archive_path(name: str) -> str:
    if not name or len(name) > 300 or "\\" in name:
        raise InvalidArchiveError
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise InvalidArchiveError

    is_directory = name.endswith("/")
    normalized = name[:-1] if is_directory else name
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
    ):
        raise InvalidArchiveError

    parts = normalized.split("/")
    if (
        len(parts) > MAX_PATH_DEPTH
        or any(part in {"", ".", ".."} or len(part) > 100 for part in parts)
    ):
        raise InvalidArchiveError

    return PurePosixPath(*parts).as_posix()


def _is_ignored(path: str) -> bool:
    return any(
        part.casefold() in IGNORED_DIRECTORIES
        for part in PurePosixPath(path).parts[:-1]
    )


def _is_supported_text_file(path: str) -> bool:
    basename = PurePosixPath(path).name.casefold()
    if basename in SPECIAL_FILENAMES or basename.startswith(".env"):
        return True
    return PurePosixPath(path).suffix.casefold() in SUPPORTED_SUFFIXES


def _is_env_sample(path: str) -> bool:
    return PurePosixPath(path).name.casefold() in ENV_SAMPLE_FILENAMES


def _is_private_env_file(path: str) -> bool:
    basename = PurePosixPath(path).name.casefold()
    return basename.startswith(".env") and not _is_env_sample(path)


def _looks_like_placeholder(value: str) -> bool:
    cleaned = value.strip().strip("\"'").strip().casefold()
    if cleaned in PLACEHOLDER_VALUES:
        return True
    if re.search(
        r"(?:os\.getenv|os\.environ|getenv|process\.env|import\.meta\.env|config\()",
        cleaned,
    ):
        return True
    return cleaned.startswith(
        ("your_", "your-", "replace_", "replace-", "example_", "sample_", "placeholder_")
    ) or cleaned.startswith("${") or cleaned.startswith("$")


def _redact_line(line: str) -> str:
    redacted = line
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = SENSITIVE_ASSIGNMENT_PATTERN.sub(
        lambda match: f"{match.group('key')} = [REDACTED]", redacted
    )
    return redacted.strip()[:240]


def _iter_token_matches(line: str) -> Iterable[re.Match[str]]:
    for pattern in TOKEN_PATTERNS:
        yield from pattern.finditer(line)


def _add_finding(
    findings: list[Finding],
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    message: str,
    file_path: str,
    line_number: int | None,
    evidence: str,
    recommendation: str,
) -> None:
    if any(
        finding.rule_id == rule_id
        and finding.file_path == file_path
        and finding.line_number == line_number
        for finding in findings
    ):
        return
    if len(findings) >= MAX_FINDINGS:
        return
    findings.append(
        Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            message=message,
            file_path=_redact_line(file_path) or "unavailable-path",
            line_number=line_number,
            evidence=evidence[:240],
            recommendation=recommendation,
        )
    )


def _read_supported_files(
    archive_bytes: bytes,
) -> tuple[dict[str, str], int]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise InvalidArchiveError from exc

    text_files: dict[str, str] = {}
    skipped_files = 0
    seen_paths: set[str] = set()

    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            raise ArchiveLimitError

        total_uncompressed = 0
        regular_file_count = 0

        for entry in entries:
            safe_path = _validate_archive_path(entry.filename)
            if entry.is_dir():
                continue

            regular_file_count += 1
            if regular_file_count > MAX_FILES:
                raise ArchiveLimitError
            if safe_path in seen_paths:
                raise InvalidArchiveError
            seen_paths.add(safe_path)

            if entry.file_size < 0 or entry.compress_size < 0:
                raise InvalidArchiveError
            total_uncompressed += entry.file_size
            if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ArchiveLimitError

            file_mode = entry.external_attr >> 16
            if stat.S_IFMT(file_mode) == stat.S_IFLNK:
                skipped_files += 1
                continue
            if _is_ignored(safe_path) or not _is_supported_text_file(safe_path):
                skipped_files += 1
                continue
            if entry.flag_bits & 0x1:
                skipped_files += 1
                continue
            if entry.file_size > MAX_FILE_BYTES:
                skipped_files += 1
                continue
            if entry.compress_type not in {
                zipfile.ZIP_STORED,
                zipfile.ZIP_DEFLATED,
            }:
                skipped_files += 1
                continue
            if (
                entry.file_size > 1024
                and entry.file_size / max(entry.compress_size, 1)
                > MAX_COMPRESSION_RATIO
            ):
                skipped_files += 1
                continue

            try:
                with archive.open(entry, "r") as member:
                    raw_content = member.read(MAX_FILE_BYTES + 1)
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError) as exc:
                raise InvalidArchiveError from exc

            if len(raw_content) > MAX_FILE_BYTES:
                skipped_files += 1
                continue
            if len(raw_content) != entry.file_size:
                raise InvalidArchiveError
            if b"\x00" in raw_content:
                skipped_files += 1
                continue

            try:
                text_files[safe_path] = raw_content.decode("utf-8")
            except UnicodeDecodeError:
                skipped_files += 1

    return text_files, skipped_files


def _collect_environment_data(
    files: dict[str, str],
) -> tuple[set[str], dict[str, tuple[str, int]], dict[str, tuple[str, int]]]:
    declared: set[str] = set()
    empty_declarations: dict[str, tuple[str, int]] = {}

    for path, content in files.items():
        if not _is_env_sample(path):
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            match = ENV_DECLARATION_PATTERN.match(line)
            if not match:
                continue
            name, value = match.groups()
            declared.add(name)
            if not value.strip().strip("\"'").strip():
                empty_declarations.setdefault(name, (path, line_number))

    references: dict[str, tuple[str, int]] = {}
    for path, content in files.items():
        if PurePosixPath(path).name.casefold().startswith(".env"):
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            for pattern in ENV_REFERENCE_PATTERNS:
                for match in pattern.finditer(line):
                    name = match.group(1)
                    if name not in BUILTIN_ENVIRONMENT_VARIABLES:
                        references.setdefault(name, (path, line_number))

    return declared, references, empty_declarations


def _scan_text_files(
    files: dict[str, str], started_at: float
) -> tuple[list[Finding], int, bool, list[str]]:
    findings: list[Finding] = []
    declared, references, empty_declarations = _collect_environment_data(files)
    sample_available = any(_is_env_sample(path) for path in files)
    limitations = [
        "Static checks can produce false positives and false negatives; verify findings manually.",
        "Project code is not executed. Binary files and ignored build or dependency directories are skipped.",
    ]

    if not sample_available:
        limitations.append(
            "No .env.example, .env.sample, or .env.template was found, so environment references could not be compared with declarations."
        )

    if ".gitignore" not in files:
        _add_finding(
            findings,
            rule_id="CFG001",
            title="No .gitignore file found",
            severity=Severity.LOW,
            message="A missing .gitignore does not prove files are tracked, but it increases the chance of committing local files by mistake.",
            file_path=".gitignore",
            line_number=None,
            evidence="No .gitignore file was found in the archive.",
            recommendation="Add ignore rules for environment files, virtual environments, dependency folders, caches, and build output.",
        )

    for path in files:
        if not _is_private_env_file(path):
            continue
        _add_finding(
            findings,
            rule_id="CFG002",
            title="Private environment file is present",
            severity=Severity.MEDIUM,
            message="A non-example environment file is included in the uploaded archive. The archive alone cannot establish whether Git tracks it.",
            file_path=path,
            line_number=None,
            evidence="Environment file contents are never included in this finding.",
            recommendation="Keep real environment files out of commits and shared archives. Confirm the file is ignored, and rotate values if they were exposed.",
        )

    for path, content in files.items():
        for line_number, line in enumerate(content.splitlines(), start=1):
            if time.monotonic() - started_at > MAX_SCAN_SECONDS:
                raise ScanTimeoutError

            if PRIVATE_KEY_PATTERN.search(line):
                _add_finding(
                    findings,
                    rule_id="SECRET001",
                    title="Possible private key",
                    severity=Severity.CRITICAL,
                    message="A private-key header was found in a text file.",
                    file_path=path,
                    line_number=line_number,
                    evidence="[REDACTED PRIVATE KEY BLOCK]",
                    recommendation="Remove the key from source control and rotate or revoke it. Store private keys in a managed secret store.",
                )

            token_matches = list(_iter_token_matches(line))
            if token_matches:
                _add_finding(
                    findings,
                    rule_id="SECRET002",
                    title="Possible credential token",
                    severity=Severity.HIGH,
                    message="Text matches a documented token format. This is a potential finding, not proof that the value is active.",
                    file_path=path,
                    line_number=line_number,
                    evidence=_redact_line(line) or "[REDACTED]",
                    recommendation="Move the value to an environment variable or secret manager. Rotate it if it was exposed.",
                )

            if not token_matches and not line.lstrip().startswith("#"):
                suspicious_keys: list[str] = []
                for match in SENSITIVE_ASSIGNMENT_PATTERN.finditer(line):
                    value = match.group("value")
                    if not _looks_like_placeholder(value):
                        suspicious_keys.append(match.group("key"))
                if suspicious_keys:
                    key_names = ", ".join(dict.fromkeys(suspicious_keys))
                    _add_finding(
                        findings,
                        rule_id="SECRET003",
                        title="Possible hardcoded credential",
                        severity=Severity.HIGH,
                        message=f"A non-placeholder value is assigned to a sensitive setting ({key_names}).",
                        file_path=path,
                        line_number=line_number,
                        evidence=_redact_line(line) or "[REDACTED]",
                        recommendation="Move the value into an environment variable or secret manager. Rotate it if it was exposed.",
                    )

            if DEBUG_ENABLED_PATTERN.search(line):
                _add_finding(
                    findings,
                    rule_id="CFG003",
                    title="Debug mode appears enabled",
                    severity=Severity.MEDIUM,
                    message="A debug setting is enabled in a source or configuration file; confirm it is disabled in production.",
                    file_path=path,
                    line_number=line_number,
                    evidence="A debug setting is set to true.",
                    recommendation="Disable debug mode in production and configure detailed diagnostics through protected server-side logs.",
                )

    if sample_available:
        for name, (path, line_number) in references.items():
            if name in declared:
                continue
            _add_finding(
                findings,
                rule_id="ENV001",
                title="Environment variable is not declared in the sample",
                severity=Severity.MEDIUM,
                message=f"{name} is referenced by project files but is absent from the supported sample environment file.",
                file_path=path,
                line_number=line_number,
                evidence=f"Reference to {name}; no value is shown.",
                recommendation=f"Add {name} to the sample environment file with a safe placeholder, or document how it is supplied at deploy time.",
            )

        for name, (path, line_number) in empty_declarations.items():
            _add_finding(
                findings,
                rule_id="ENV002",
                title="Sample environment value is blank",
                severity=Severity.LOW,
                message=f"{name} is declared without an example value. This may be intentional, but deployers need to know it must be supplied.",
                file_path=path,
                line_number=line_number,
                evidence=f"{name}= (blank sample value)",
                recommendation=f"Add a safe placeholder or a short note explaining how to provide {name}. Never put a real credential in the sample file.",
            )

    if len(findings) >= MAX_FINDINGS:
        limitations.append(
            f"Findings are capped at {MAX_FINDINGS}; additional matches may not be shown."
        )

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    findings.sort(
        key=lambda finding: (
            severity_order[finding.severity],
            finding.file_path.casefold(),
            finding.line_number or 0,
            finding.rule_id,
        )
    )
    return findings, len(references), sample_available, limitations


def _safe_archive_name(filename: str | None) -> str:
    candidate = (filename or "project.zip").replace("\\", "/").split("/")[-1]
    safe = "".join(
        char for char in candidate if char.isprintable() and char not in {"/", "\\"}
    ).strip()
    return _redact_line(safe)[:120] or "project.zip"


def scan_project_archive(archive_bytes: bytes, filename: str | None) -> ScanResponse:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ArchiveLimitError

    started_at = time.monotonic()
    files, skipped_files = _read_supported_files(archive_bytes)
    findings, reference_count, sample_available, limitations = _scan_text_files(
        files, started_at
    )

    if skipped_files:
        limitations.append(
            f"{skipped_files} file(s) were skipped because they were binary, unsupported, oversized, encrypted, or inside an ignored directory."
        )

    severity_counts = SeverityCounts(
        critical=sum(finding.severity == Severity.CRITICAL for finding in findings),
        high=sum(finding.severity == Severity.HIGH for finding in findings),
        medium=sum(finding.severity == Severity.MEDIUM for finding in findings),
        low=sum(finding.severity == Severity.LOW for finding in findings),
        info=sum(finding.severity == Severity.INFO for finding in findings),
    )

    return ScanResponse(
        scan_id=uuid4(),
        archive_name=_safe_archive_name(filename),
        scanned_at=datetime.now(UTC),
        files_scanned=len(files),
        files_skipped=skipped_files,
        environment_references_checked=reference_count,
        environment_declarations_available=sample_available,
        severity_counts=severity_counts,
        findings=findings,
        limitations=limitations,
    )
