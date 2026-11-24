"""Command line entry point.

    python -m autofix collect     # fetch findings only -> findings.json
    python -m autofix remediate   # fix, verify, report, open MR (uses findings.json)
    python -m autofix run         # collect + remediate in one go
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .collect import collect_findings, load_findings, save_findings
from .config import Config
from .fixers.ai_fix import apply_ai_fixes
from .fixers.veracode_fix import apply_veracode_fix_sast, apply_veracode_fix_sca
from .gitlab import publish
from .models import FixStatus
from .report import build_json, build_markdown, summarise
from .scans import run_sast_scan, run_sca_scan, sast_counts, sca_cves
from .shell import Git
from .verify import classify

log = logging.getLogger("autofix")


def cmd_collect(cfg: Config, out_dir: Path) -> Path:
    findings, context = collect_findings(cfg)
    path = out_dir / "findings.json"
    save_findings(path, findings, context)
    log.info("Saved %d findings to %s", len(findings), path)
    return path


def cmd_remediate(cfg: Config, out_dir: Path) -> int:
    findings_path = out_dir / "findings.json"
    if not findings_path.exists():
        cmd_collect(cfg, out_dir)
    findings, context = load_findings(findings_path)
    if not findings:
        log.info("No open findings - nothing to fix.")

    git = Git(cfg.repo_dir)
    git.configure_author(cfg.git_author_name, cfg.git_author_email)
    git.checkout_new_branch(cfg.fix_branch)
    base = git.head()

    has_sast = any(f.scan_type == "STATIC" for f in findings)
    has_sca = any(f.scan_type == "SCA" for f in findings)

    # 1. Baseline local scans: inputs for Veracode Fix and the "before" for verification.
    sast_baseline = run_sast_scan(cfg, out_dir / "sast-baseline.json") if has_sast else None
    sca_baseline = run_sca_scan(cfg, out_dir / "sca-baseline.json") if has_sca else None

    # 2. Fix: Veracode Fix first, AI only for what is left.
    apply_veracode_fix_sast(cfg, git, findings, sast_baseline)
    apply_veracode_fix_sca(cfg, git, findings, sca_baseline)
    apply_ai_fixes(cfg, git, findings)

    # 3. Verify with re-scans of the patched code.
    sast_patched = any(f.patched_by and f.scan_type == "STATIC" for f in findings)
    sca_patched = any(f.patched_by and f.scan_type == "SCA" for f in findings)
    sast_after_path = run_sast_scan(cfg, out_dir / "sast-after.json") if sast_patched else None
    sca_after_path = run_sca_scan(cfg, out_dir / "sca-after.json") if sca_patched else None

    classify(
        findings,
        sast_before=sast_counts(sast_baseline) if sast_baseline else None,
        sast_after=sast_counts(sast_after_path) if sast_after_path else None,
        sca_after=sca_cves(sca_after_path) if sca_after_path else None,
    )

    # 4. Keep only commits that fixed at least one finding.
    fixed_statuses = (FixStatus.FIXED_VERACODE, FixStatus.FIXED_AI)
    useful = {f.commit for f in findings if f.status in fixed_statuses and f.commit}
    all_commits = git.commits_since(base)
    keep = [sha for sha in all_commits if sha in useful]
    if len(keep) != len(all_commits):
        log.info("Dropping %d commit(s) that did not fix anything.", len(all_commits) - len(keep))
        new_shas = git.keep_only_commits(base, keep)
        for finding in findings:
            if finding.commit not in new_shas:
                continue
            finding.commit = new_shas[finding.commit]
            if finding.commit is None:  # its commit no longer applied on its own
                finding.status = FixStatus.NOT_FIXED
                finding.reason = "Fix depended on a dropped change"

    # 5. Report and publish.
    _, totals = summarise(findings)
    fixed_count = totals.fixed_veracode + totals.fixed_ai
    has_commits = bool(git.commits_since(base))
    fix_branch = cfg.fix_branch if has_commits else None

    markdown = build_markdown(findings, context, fix_branch)
    report = build_json(findings, context, fix_branch)

    mr_url = None
    if has_commits:
        mr_url = publish(cfg, git, markdown, fixed_count)
    else:
        log.info("No verified fixes - no branch or merge request created.")
    report["merge_request_url"] = mr_url

    (out_dir / "fix-report.md").write_text(markdown)
    (out_dir / "fix-report.json").write_text(json.dumps(report, indent=2))
    print(markdown)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="autofix", description="Veracode Auto-Fix for GitLab")
    parser.add_argument("command", choices=["collect", "remediate", "run"])
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    cfg = Config()
    out_dir = Path(cfg.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.command == "collect":
        cmd_collect(cfg, out_dir)
        return 0
    if args.command == "run":
        cmd_collect(cfg, out_dir)
    return cmd_remediate(cfg, out_dir)


if __name__ == "__main__":
    sys.exit(main())
