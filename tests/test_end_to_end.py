"""End-to-end run of `remediate` against a throwaway git repo.

Veracode CLI and the scanners are replaced by tiny shell/Python commands so the
whole flow (baseline scan -> fix -> re-scan -> classify -> commit cleanup ->
report) runs offline in dry-run mode.
"""

import json
import os
import subprocess
import sys
import textwrap

from autofix.__main__ import main

# Fake Pipeline Scan: one CWE-89 finding per line containing "BAD" in *.java files.
FAKE_SCAN = textwrap.dedent("""
    import json, pathlib, sys
    findings = []
    for path in pathlib.Path('.').rglob('*.java'):
        for n, line in enumerate(path.read_text().splitlines(), 1):
            if 'BAD' in line:
                cwe = 79 if path.name == 'View.java' else 89
                findings.append({'cwe_id': str(cwe),
                                 'files': {'source_file': {'file': str(path), 'line': n}}})
    pathlib.Path(sys.argv[1]).write_text(json.dumps({'findings': findings}))
""")


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


def test_remediate_dry_run(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "UserDao.java").write_text("class UserDao {\n  String q = BAD;\n}\n")
    (repo / "src" / "View.java").write_text("class View {\n  String h = BAD;\n}\n")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")

    scanner = tmp_path / "fake_scan.py"
    scanner.write_text(FAKE_SCAN)
    out = tmp_path / "out"
    out.mkdir()
    (out / "findings.json").write_text(json.dumps({
        "context": {"application": "demo", "scan_context": "policy", "branch": "main"},
        "findings": [
            {"issue_id": "1", "scan_type": "STATIC", "severity": 4, "title": "SQL Injection",
             "cwe_id": 89, "file_path": "UserDao.java", "line": 2},
            {"issue_id": "2", "scan_type": "STATIC", "severity": 3, "title": "XSS",
             "cwe_id": 79, "file_path": "View.java", "line": 2},
        ],
    }))

    env = {
        "REPO_DIR": str(repo),
        "OUTPUT_DIR": str(out),
        "TARGET_BRANCH": "main",
        "CI_PIPELINE_ID": "42",
        "BUILD_CMD": "true",
        "SCAN_ARTIFACT": "unused",
        "SAST_SCAN_CMD": f"{sys.executable} {scanner} {{output}}",
        # Fake Veracode Fix: fixes UserDao.java, touches View.java without fixing it
        "VERACODE_FIX_SAST_CMD": "sed -i 's/BAD/GOOD/' src/UserDao.java && echo '// x' >> src/View.java",
        "ENABLE_VERACODE_FIX_SCA": "false",
        "ENABLE_AI_FIX": "false",
        "DRY_RUN": "true",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    assert main(["remediate"]) == 0

    report = json.loads((out / "fix-report.json").read_text())
    assert report["totals"] == {"identified": 2, "fixed_veracode": 1, "fixed_ai": 0, "not_fixed": 1}
    assert report["fix_branch"] == "veracode-fix/main-42"

    branch = subprocess.run(["git", "branch", "--show-current"], cwd=repo,
                            capture_output=True, text=True).stdout.strip()
    log = subprocess.run(["git", "log", "--oneline"], cwd=repo, capture_output=True, text=True).stdout
    assert branch == "veracode-fix/main-42"
    assert "fix(veracode-fix-sast): src/UserDao.java" in log
    assert "src/View.java" not in log  # commit that fixed nothing was dropped
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                          text=True).stdout.strip()
    fixed = [f for f in report["findings"] if f["status"] == "fixed_veracode"]
    assert fixed[0]["commit"] == head  # SHA updated after the branch was rebuilt
    assert "GOOD" in (repo / "src" / "UserDao.java").read_text()
    assert os.path.exists(out / "fix-report.md")
