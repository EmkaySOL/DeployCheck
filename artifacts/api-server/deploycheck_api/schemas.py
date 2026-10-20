from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    title: str
    severity: Severity
    message: str
    file_path: str
    line_number: int | None
    evidence: str
    recommendation: str


class SeverityCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


class ScanResponse(BaseModel):
    scan_id: UUID
    archive_name: str
    scanned_at: datetime
    files_scanned: int
    files_skipped: int
    environment_references_checked: int
    environment_declarations_available: bool
    severity_counts: SeverityCounts
    findings: list[Finding]
    limitations: list[str]


class ErrorResponse(BaseModel):
    error: str
