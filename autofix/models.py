"""The single findings model used by every stage, plus converters from Veracode JSON."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from enum import Enum

SEVERITY_NAMES = {
    5: "Very High",
    4: "High",
    3: "Medium",
    2: "Low",
    1: "Very Low",
    0: "Informational",
}


class FixStatus(str, Enum):
    PENDING = "pending"
    FIXED_VERACODE = "fixed_veracode"
    FIXED_AI = "fixed_ai"
    NOT_FIXED = "not_fixed"


@dataclass
class Finding:
    issue_id: str
    scan_type: str  # "STATIC" or "SCA"
    severity: int
    title: str
    # STATIC
    cwe_id: int | None = None
    file_path: str | None = None
    line: int | None = None
    # SCA
    cve: str | None = None
    component: str | None = None
    component_version: str | None = None
    guidance: str = ""
    # Filled in during remediation
    status: FixStatus = FixStatus.PENDING
    reason: str = ""
    patched_by: str | None = None  # "veracode" or "ai" once a patch touched it
    commit: str | None = None

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, str(self.severity))

    @property
    def match_key(self) -> tuple:
        """Key used to match this finding against re-scan results.

        Line numbers move once code is patched, so SAST findings are matched on
        CWE + file name, and SCA findings on CVE.
        """
        if self.scan_type == "STATIC":
            return ("STATIC", self.cwe_id, normalise_path(self.file_path))
        return ("SCA", (self.cve or "").upper())

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity_name"] = self.severity_name
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        data["status"] = FixStatus(data.get("status", "pending"))
        return cls(**data)


def normalise_path(path: str | None) -> str:
    """Compare files by name only; Veracode and repo paths use different roots."""
    if not path:
        return ""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()


def is_open(raw: dict) -> bool:
    """Open and not mitigated (an approved mitigation means accepted risk)."""
    status = raw.get("finding_status", {})
    return status.get("status") == "OPEN" and status.get("resolution_status") != "APPROVED"


def finding_from_veracode(raw: dict) -> Finding:
    """Convert one Findings API item into a Finding."""
    details = raw.get("finding_details", {})
    scan_type = raw.get("scan_type", "STATIC")
    severity = int(details.get("severity", 0))
    guidance = strip_html(raw.get("description", ""))

    if scan_type == "SCA":
        cve = (details.get("cve") or {}).get("name")
        component = details.get("component_filename") or details.get("component_id")
        return Finding(
            issue_id=str(raw.get("issue_id") or f"{component}:{cve}"),
            scan_type="SCA",
            severity=severity,
            title=f"{cve or 'Vulnerability'} in {component}",
            cve=cve,
            component=component,
            component_version=details.get("version"),
            guidance=guidance,
        )

    cwe = details.get("cwe") or {}
    return Finding(
        issue_id=str(raw.get("issue_id")),
        scan_type="STATIC",
        severity=severity,
        title=cwe.get("name") or details.get("finding_category", {}).get("name", "Flaw"),
        cwe_id=int(cwe["id"]) if cwe.get("id") is not None else None,
        file_path=details.get("file_path"),
        line=details.get("file_line_number"),
        guidance=guidance,
    )
