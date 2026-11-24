"""Running local scans and reading their results.

Two local scans are used:
  * Veracode Pipeline Scan (SAST): its results.json is the input Veracode Fix
    needs, and a second run after patching shows which flaws are gone.
  * Veracode SCA agent (srcclr): its JSON is the input for Veracode Fix for SCA,
    and a second run shows which CVEs are gone.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path

from .config import Config
from .models import normalise_path
from .shell import run

log = logging.getLogger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def run_build(cfg: Config) -> bool:
    if not cfg.build_cmd:
        return True
    if not run(cfg.build_cmd, cwd=cfg.repo_dir).ok:
        return False
    if cfg.test_cmd and not run(cfg.test_cmd, cwd=cfg.repo_dir).ok:
        return False
    return True


def run_sast_scan(cfg: Config, output: Path) -> Path | None:
    """Build and run a Pipeline Scan. Returns the results path, or None if unavailable."""
    if not (cfg.build_cmd and cfg.scan_artifact):
        log.warning("BUILD_CMD/SCAN_ARTIFACT not set: skipping SAST pipeline scan.")
        return None
    if not run_build(cfg):
        return None
    cmd = cfg.sast_scan_cmd.format(artifact=cfg.scan_artifact, output=output.resolve())
    run(cmd, cwd=cfg.repo_dir)  # non-zero exit is normal when flaws are found
    return output if output.exists() else None


def run_sca_scan(cfg: Config, output: Path) -> Path | None:
    if not cfg.sca_scan_cmd:
        return None
    cmd = cfg.sca_scan_cmd.format(repo=Path(cfg.repo_dir).resolve(), output=output.resolve())
    run(cmd, cwd=cfg.repo_dir)
    return output if output.exists() and output.stat().st_size > 0 else None


def sast_counts(results_path: Path) -> Counter:
    """Count Pipeline Scan findings per (CWE, file name)."""
    data = json.loads(results_path.read_text())
    counts: Counter = Counter()
    for item in data.get("findings", []):
        source = item.get("files", {}).get("source_file", {})
        try:
            cwe = int(item.get("cwe_id"))
        except (TypeError, ValueError):
            continue
        counts[("STATIC", cwe, normalise_path(source.get("file")))] += 1
    return counts


def sca_cves(results_path: Path) -> set[str]:
    """All CVE ids mentioned in an SCA agent JSON report.

    The agent's JSON nests vulnerabilities in several shapes depending on the
    version, so collecting every CVE id string is the most robust approach.
    """
    return {match.upper() for match in CVE_PATTERN.findall(results_path.read_text())}
