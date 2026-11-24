"""Unit tests for the pure logic: parsing, matching, classification, reporting."""

import json
from collections import Counter

from autofix.fixers.ai_fix import extract_diff, locate_source_file
from autofix.models import Finding, FixStatus, finding_from_veracode, is_open
from autofix.report import build_markdown, summarise
from autofix.scans import sast_counts, sca_cves
from autofix.veracode_api import build_hmac_header
from autofix.verify import classify

STATIC_RAW = {
    "issue_id": 101,
    "scan_type": "STATIC",
    "description": "<span>Use parameterized queries.</span>",
    "finding_status": {"status": "OPEN", "resolution_status": "NONE"},
    "finding_details": {
        "severity": 4,
        "cwe": {"id": 89, "name": "SQL Injection"},
        "file_path": "com/acme/UserDao.java",
        "file_line_number": 42,
    },
}

SCA_RAW = {
    "scan_type": "SCA",
    "finding_status": {"status": "OPEN"},
    "finding_details": {
        "severity": 5,
        "component_filename": "log4j-core-2.14.1.jar",
        "version": "2.14.1",
        "cve": {"name": "CVE-2021-44228"},
    },
}


def test_hmac_header_is_deterministic_and_well_formed():
    args = ("my-id", "ab" * 32, "https://api.veracode.com/appsec/v1/applications?name=x", "GET")
    h1 = build_hmac_header(*args, timestamp_ms=1700000000000, nonce_hex="00" * 16)
    h2 = build_hmac_header(*args, timestamp_ms=1700000000000, nonce_hex="00" * 16)
    assert h1 == h2
    assert h1.startswith("VERACODE-HMAC-SHA-256 id=my-id,ts=1700000000000,nonce=")
    assert len(h1.split("sig=")[1]) == 64


def test_static_finding_conversion():
    f = finding_from_veracode(STATIC_RAW)
    assert (f.issue_id, f.cwe_id, f.line, f.severity_name) == ("101", 89, 42, "High")
    assert f.guidance == "Use parameterized queries."
    assert f.match_key == ("STATIC", 89, "userdao.java")


def test_sca_finding_conversion():
    f = finding_from_veracode(SCA_RAW)
    assert f.cve == "CVE-2021-44228"
    assert f.match_key == ("SCA", "CVE-2021-44228")


def test_mitigated_findings_are_not_open():
    mitigated = {"finding_status": {"status": "OPEN", "resolution_status": "APPROVED"}}
    assert is_open(STATIC_RAW) and not is_open(mitigated)


def _static(issue, cwe=89, file="UserDao.java", sev=4, patched_by=None):
    return Finding(issue_id=issue, scan_type="STATIC", severity=sev, title="t",
                   cwe_id=cwe, file_path=file, line=1, patched_by=patched_by)


def test_classify_sast_uses_before_minus_after():
    findings = [
        _static("1", patched_by="veracode"),
        _static("2", patched_by="veracode", sev=5),
        _static("3", cwe=79, patched_by="ai"),
        _static("4", cwe=22),  # never patched
    ]
    before = Counter({("STATIC", 89, "userdao.java"): 2, ("STATIC", 79, "userdao.java"): 1})
    after = Counter({("STATIC", 89, "userdao.java"): 1})
    classify(findings, before, after, sca_after=None)

    statuses = {f.issue_id: f.status for f in findings}
    assert statuses["2"] == FixStatus.FIXED_VERACODE  # most severe credited first
    assert statuses["1"] == FixStatus.NOT_FIXED
    assert statuses["3"] == FixStatus.FIXED_AI
    assert statuses["4"] == FixStatus.NOT_FIXED
    assert findings[3].reason == "No fix generated"


def test_classify_without_rescan_never_claims_fixed():
    findings = [_static("1", patched_by="ai")]
    classify(findings, None, None, None)
    assert findings[0].status == FixStatus.NOT_FIXED
    assert "not verified" in findings[0].reason


def test_classify_sca_by_cve():
    f1 = finding_from_veracode(SCA_RAW)
    f1.patched_by = "veracode"
    classify([f1], None, None, sca_after={"CVE-2020-0001"})
    assert f1.status == FixStatus.FIXED_VERACODE


def test_report_counts_add_up():
    findings = [_static("1"), _static("2")]
    findings[0].status = FixStatus.FIXED_AI
    findings[1].status = FixStatus.NOT_FIXED
    _, total = summarise(findings)
    assert (total.identified, total.fixed_ai, total.not_fixed) == (2, 1, 1)
    md = build_markdown(findings, {"application": "app"}, "veracode-fix/main-1")
    assert "| **Total** | | **2** | **0** | **1** | **1** |" in md


def test_sast_counts_and_sca_cves(tmp_path):
    results = tmp_path / "results.json"
    results.write_text(json.dumps({"findings": [
        {"cwe_id": "89", "files": {"source_file": {"file": "com/acme/UserDao.java", "line": 40}}},
        {"cwe_id": "89", "files": {"source_file": {"file": "com/acme/UserDao.java", "line": 90}}},
    ]}))
    assert sast_counts(results) == Counter({("STATIC", 89, "userdao.java"): 2})

    sca = tmp_path / "sca.json"
    sca.write_text('{"records":[{"vulnerabilities":[{"cve":"cve-2021-44228"}]}]}')
    assert sca_cves(sca) == {"CVE-2021-44228"}


def test_extract_diff():
    reply = "Here you go\n```diff\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n```"
    assert extract_diff(reply).startswith("--- a/x.py")
    assert extract_diff("SKIP") is None
    assert extract_diff("no diff here") is None


def test_locate_source_file():
    files = ["app/src/main/java/com/acme/UserDao.java", "web/index.js"]
    assert locate_source_file(files, "com/acme/UserDao.java") == files[0]
    assert locate_source_file(files, "index.js") == "web/index.js"
    assert locate_source_file(files, "missing.java") is None
