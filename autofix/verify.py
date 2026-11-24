"""Decide the final status of every finding by comparing scans before and after.

Rules (kept deliberately simple so the numbers are easy to explain):
  * A finding nobody patched is NOT FIXED ("no fix generated").
  * SAST: for each (CWE, file) the number of fixed flaws is
        baseline Pipeline Scan count - re-scan count.
    That many patched findings in the group are marked fixed; the rest are not.
  * SCA: a patched finding is fixed when its CVE no longer appears in the
    re-scan.
  * If a re-scan is not available, patched findings stay NOT FIXED with the
    reason "not verified" - nothing is reported as fixed without evidence.
The engine credited is whichever one patched the finding (Veracode or AI).
"""

from __future__ import annotations

from collections import Counter, defaultdict

from .models import Finding, FixStatus


def _mark_fixed(finding: Finding) -> None:
    finding.status = FixStatus.FIXED_AI if finding.patched_by == "ai" else FixStatus.FIXED_VERACODE
    finding.reason = ""


def _mark_not_fixed(finding: Finding, reason: str) -> None:
    finding.status = FixStatus.NOT_FIXED
    finding.reason = finding.reason or reason


def classify(
    findings: list[Finding],
    sast_before: Counter | None,
    sast_after: Counter | None,
    sca_after: set[str] | None,
) -> None:
    """Set status and reason on every finding, in place."""
    sast_groups: dict[tuple, list[Finding]] = defaultdict(list)

    for finding in findings:
        if finding.patched_by is None:
            _mark_not_fixed(finding, "No fix generated")
        elif finding.scan_type == "SCA":
            if sca_after is None:
                _mark_not_fixed(finding, "Patched but not verified (no SCA re-scan)")
            elif (finding.cve or "").upper() in sca_after:
                _mark_not_fixed(finding, "Still reported after re-scan")
            else:
                _mark_fixed(finding)
        else:
            sast_groups[finding.match_key].append(finding)

    for key, group in sast_groups.items():
        if sast_before is None or sast_after is None:
            for finding in group:
                _mark_not_fixed(finding, "Patched but not verified (no SAST re-scan)")
            continue
        fixed_slots = max(0, sast_before.get(key, 0) - sast_after.get(key, 0))
        # Credit the most severe findings first when only some were fixed.
        for finding in sorted(group, key=lambda f: f.severity, reverse=True):
            if fixed_slots > 0:
                _mark_fixed(finding)
                fixed_slots -= 1
            else:
                _mark_not_fixed(finding, "Still reported after re-scan")
