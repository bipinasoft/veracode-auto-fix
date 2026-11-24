"""Build the counts report (Markdown for the MR, JSON for automation)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .models import SEVERITY_NAMES, Finding, FixStatus


@dataclass
class Counts:
    identified: int = 0
    fixed_veracode: int = 0
    fixed_ai: int = 0
    not_fixed: int = 0

    def add(self, finding: Finding) -> None:
        self.identified += 1
        if finding.status == FixStatus.FIXED_VERACODE:
            self.fixed_veracode += 1
        elif finding.status == FixStatus.FIXED_AI:
            self.fixed_ai += 1
        else:
            self.not_fixed += 1

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def summarise(findings: list[Finding]) -> tuple[dict[tuple[str, int], Counts], Counts]:
    rows: dict[tuple[str, int], Counts] = defaultdict(Counts)
    total = Counts()
    for finding in findings:
        rows[(finding.scan_type, finding.severity)].add(finding)
        total.add(finding)
    # Invariant the report promises: every identified finding lands in exactly one bucket.
    assert total.identified == total.fixed_veracode + total.fixed_ai + total.not_fixed
    return dict(rows), total


def _scan_label(scan_type: str) -> str:
    return "SAST" if scan_type == "STATIC" else "SCA"


def build_json(findings: list[Finding], context: dict, fix_branch: str | None) -> dict:
    rows, total = summarise(findings)
    return {
        "context": context,
        "fix_branch": fix_branch,
        "totals": total.as_dict(),
        "by_scan_and_severity": [
            {"scan": _scan_label(scan), "severity": SEVERITY_NAMES.get(sev, sev), **c.as_dict()}
            for (scan, sev), c in sorted(rows.items(), key=lambda kv: (kv[0][0], -kv[0][1]))
        ],
        "findings": [f.to_dict() for f in findings],
    }


def build_markdown(findings: list[Finding], context: dict, fix_branch: str | None) -> str:
    rows, total = summarise(findings)
    lines = [
        "## Veracode Auto-Fix report",
        "",
        f"- **Application:** {context.get('application', '-')}",
        f"- **Findings source:** {context.get('scan_context', '-')} (branch `{context.get('branch', '-')}`)",
    ]
    if fix_branch:
        lines.append(f"- **Fix branch:** `{fix_branch}`")
    lines += [
        "",
        "| Scan | Severity | Identified | Fixed by Veracode Fix | Fixed by AI | Not fixed |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for (scan, sev), c in sorted(rows.items(), key=lambda kv: (kv[0][0], -kv[0][1])):
        lines.append(
            f"| {_scan_label(scan)} | {SEVERITY_NAMES.get(sev, sev)} | {c.identified} | "
            f"{c.fixed_veracode} | {c.fixed_ai} | {c.not_fixed} |"
        )
    lines.append(
        f"| **Total** | | **{total.identified}** | **{total.fixed_veracode}** | "
        f"**{total.fixed_ai}** | **{total.not_fixed}** |"
    )

    fixed = [f for f in findings if f.status in (FixStatus.FIXED_VERACODE, FixStatus.FIXED_AI)]
    if fixed:
        lines += ["", "### Fixed", "", "| Issue | Scan | Severity | Detail | Fixed by | Commit |",
                  "|---|---|---|---|---|---|"]
        for f in fixed:
            engine = "AI" if f.status == FixStatus.FIXED_AI else "Veracode Fix"
            lines.append(f"| {f.issue_id} | {_scan_label(f.scan_type)} | {f.severity_name} | "
                         f"{_detail(f)} | {engine} | {(f.commit or '')[:8]} |")

    not_fixed = [f for f in findings if f.status == FixStatus.NOT_FIXED]
    if not_fixed:
        lines += ["", "### Not fixed (needs manual review)", "",
                  "| Issue | Scan | Severity | Detail | Reason |", "|---|---|---|---|---|"]
        for f in sorted(not_fixed, key=lambda x: -x.severity):
            lines.append(f"| {f.issue_id} | {_scan_label(f.scan_type)} | {f.severity_name} | "
                         f"{_detail(f)} | {f.reason} |")

    lines += ["", "_AI-generated changes must be reviewed by a developer before merging._"]
    return "\n".join(lines) + "\n"


def _detail(f: Finding) -> str:
    if f.scan_type == "SCA":
        return f"{f.cve} in `{f.component}` {f.component_version or ''}".strip()
    return f"CWE-{f.cwe_id} `{f.file_path}:{f.line}`"
