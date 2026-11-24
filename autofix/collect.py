"""Stage 1: find the Veracode application/sandbox and collect open findings."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from .config import Config
from .models import Finding, finding_from_veracode, is_open
from .veracode_api import VeracodeClient

log = logging.getLogger(__name__)


def collect_findings(cfg: Config, client: VeracodeClient | None = None) -> tuple[list[Finding], dict]:
    """Return (findings, scan_context) for the configured app and branch."""
    cfg.require("veracode_api_id", "veracode_api_secret", "veracode_app_name")
    client = client or VeracodeClient(cfg.veracode_api_id, cfg.veracode_api_secret, cfg.veracode_api_base)

    app = client.find_application(cfg.veracode_app_name)
    app_guid = app["guid"]

    # Branch -> sandbox. An explicit sandbox name wins; otherwise look for a
    # sandbox named after the branch; otherwise use the policy scan.
    sandbox_name = cfg.veracode_sandbox_name or cfg.target_branch
    sandbox = client.find_sandbox(app_guid, sandbox_name)
    if cfg.veracode_sandbox_name and not sandbox:
        raise SystemExit(f"Sandbox '{cfg.veracode_sandbox_name}' not found in '{cfg.veracode_app_name}'.")
    sandbox_guid = sandbox["guid"] if sandbox else None

    context = {
        "application": cfg.veracode_app_name,
        "application_guid": app_guid,
        "scan_context": f"sandbox:{sandbox_name}" if sandbox else "policy",
        "sandbox_guid": sandbox_guid,
        "branch": cfg.target_branch,
    }
    log.info("Reading findings from %s (%s)", cfg.veracode_app_name, context["scan_context"])

    findings: list[Finding] = []
    for scan_type in ("STATIC", "SCA"):
        raw_items = client.get_findings(app_guid, scan_type, sandbox_guid)
        open_items = [item for item in raw_items if is_open(item)]
        converted = [finding_from_veracode(item) for item in open_items]
        kept = [f for f in converted if f.severity >= cfg.min_severity]
        log.info("%s: %d open findings (%d at or above severity %d)",
                 scan_type, len(open_items), len(kept), cfg.min_severity)
        findings.extend(kept)

    return findings, context


def save_findings(path: Path, findings: list[Finding], context: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"context": context, "findings": [f.to_dict() for f in findings]}
    path.write_text(json.dumps(payload, indent=2))


def load_findings(path: Path) -> tuple[list[Finding], dict]:
    payload = json.loads(path.read_text())
    return [Finding.from_dict(f) for f in payload["findings"]], payload.get("context", {})
