"""Run Veracode Fix (CLI) for SAST and SCA and commit what it changes.

Veracode Fix in batch mode patches many files in one go, so commits are made
per changed file. The findings in those files are marked as patched by
Veracode; the re-scan later decides whether each one is really fixed.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..config import Config
from ..models import Finding, normalise_path
from ..scans import run_build
from ..shell import Git, run

log = logging.getLogger(__name__)


def _commit_each_file(git: Git, files: list[str], prefix: str) -> dict[str, str]:
    commits = {}
    for path in files:
        commits[path] = git.commit_files([path], f"{prefix}: {path}")
    return commits


def apply_veracode_fix_sast(
    cfg: Config, git: Git, findings: list[Finding], sast_results: Path | None
) -> list[str]:
    """Returns the list of files Veracode Fix changed (and that still build)."""
    if not cfg.enable_veracode_fix_sast:
        return []
    if sast_results is None:
        log.warning("No Pipeline Scan results: Veracode Fix for SAST skipped.")
        return []

    start = git.head()
    cmd = cfg.veracode_fix_sast_cmd.format(source=cfg.fix_source_dir, results=sast_results.resolve())
    run(cmd, cwd=cfg.repo_dir)
    changed = git.changed_files()
    if not changed:
        log.info("Veracode Fix for SAST produced no changes.")
        return []

    commits = _commit_each_file(git, changed, "fix(veracode-fix-sast)")
    if not run_build(cfg):
        log.warning("Build failed after Veracode Fix for SAST: reverting its changes.")
        git.reset_hard(start)
        return []

    changed_names = {normalise_path(p): p for p in changed}
    for finding in findings:
        if finding.scan_type == "STATIC" and normalise_path(finding.file_path) in changed_names:
            finding.patched_by = "veracode"
            finding.commit = commits[changed_names[normalise_path(finding.file_path)]]
    log.info("Veracode Fix for SAST changed %d file(s).", len(changed))
    return changed


def apply_veracode_fix_sca(
    cfg: Config, git: Git, findings: list[Finding], sca_results: Path | None
) -> list[str]:
    """Returns the list of dependency files Veracode Fix for SCA changed."""
    if not cfg.enable_veracode_fix_sca:
        return []
    if sca_results is None:
        log.warning("No SCA agent results: Veracode Fix for SCA skipped.")
        return []

    start = git.head()
    cmd = cfg.veracode_fix_sca_cmd.format(repo=Path(cfg.repo_dir).resolve(), results=sca_results.resolve())
    run(cmd, cwd=cfg.repo_dir)
    changed = git.changed_files()
    if not changed:
        log.info("Veracode Fix for SCA produced no changes.")
        return []

    commit = git.commit_files(changed, "fix(veracode-fix-sca): upgrade vulnerable dependencies")
    if not run_build(cfg):
        log.warning("Build failed after Veracode Fix for SCA: reverting its changes.")
        git.reset_hard(start)
        return []

    for finding in findings:
        if finding.scan_type == "SCA":
            finding.patched_by = "veracode"
            finding.commit = commit
    return changed
