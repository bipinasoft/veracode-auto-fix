"""AI fallback for SAST findings that Veracode Fix did not patch.

For each finding the model gets: the CWE, Veracode's own remediation guidance,
and a window of code around the flawed line. It must answer with a unified
diff. The diff is only applied if `git apply --check` accepts it, and (by
default) only kept if the project still builds.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from ..config import Config
from ..http import request_json
from ..models import Finding, normalise_path
from ..scans import run_build
from ..shell import Git

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior application security engineer fixing a single \
static analysis finding reported by Veracode.

Rules:
- Fix only the reported flaw. Keep the change as small as possible.
- Do not change behaviour beyond what the fix requires.
- Do not add new third-party dependencies.
- Preserve the file's existing style and indentation.
- Reply with ONLY a unified diff (git format, paths prefixed a/ and b/) inside a
  ```diff code block. If you cannot fix it safely, reply with the single word SKIP."""


def locate_source_file(repo_files: list[str], veracode_path: str | None) -> str | None:
    """Map a Veracode file path (often package-relative) to a path in the repo."""
    if not veracode_path:
        return None
    wanted = veracode_path.replace("\\", "/").lstrip("/")
    by_suffix = [f for f in repo_files if f == wanted or f.endswith("/" + wanted)]
    if len(by_suffix) == 1:
        return by_suffix[0]
    by_name = [f for f in repo_files if normalise_path(f) == normalise_path(wanted)]
    return by_name[0] if len(by_name) == 1 else None


def build_prompt(finding: Finding, repo_path: str, source: str, context_lines: int) -> str:
    lines = source.splitlines()
    line = max(1, finding.line or 1)
    start = max(1, line - context_lines)
    end = min(len(lines), line + context_lines)
    numbered = "\n".join(f"{n:>5}: {lines[n - 1]}" for n in range(start, end + 1))
    return (
        f"File: {repo_path}\n"
        f"Finding: Veracode issue {finding.issue_id}, CWE-{finding.cwe_id} ({finding.title}), "
        f"severity {finding.severity_name}, reported at line {finding.line}.\n\n"
        f"Veracode guidance:\n{finding.guidance[:3000]}\n\n"
        f"Code (lines {start}-{end}, line numbers are for reference only):\n{numbered}\n"
    )


def extract_diff(reply: str) -> str | None:
    if reply.strip().upper() == "SKIP":
        return None
    match = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", reply, re.DOTALL)
    diff = (match.group(1) if match else reply).strip()
    if "--- " not in diff or "+++ " not in diff:
        return None
    return diff + "\n"


def ask_model(cfg: Config, prompt: str) -> str:
    response = request_json(
        "POST",
        cfg.llm_api_url,
        headers={"x-api-key": cfg.llm_api_key, "anthropic-version": "2023-06-01"},
        body={
            "model": cfg.llm_model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    return "".join(block.get("text", "") for block in response.get("content", []))


def apply_ai_fixes(cfg: Config, git: Git, findings: list[Finding]) -> int:
    """Try the AI fallback on unpatched SAST findings. Returns patches committed."""
    if not cfg.enable_ai_fix:
        return 0
    if not cfg.llm_api_key:
        log.warning("LLM_API_KEY not set: AI fallback skipped.")
        return 0

    candidates = [f for f in findings if f.scan_type == "STATIC" and f.patched_by is None]
    candidates.sort(key=lambda f: f.severity, reverse=True)  # most severe first
    repo_files = git.ls_files()
    applied = 0

    for finding in candidates[: cfg.ai_max_findings]:
        repo_path = locate_source_file(repo_files, finding.file_path)
        if not repo_path:
            finding.reason = "AI: source file not found in repository"
            continue

        source = (Path(cfg.repo_dir) / repo_path).read_text(errors="replace")
        try:
            reply = ask_model(cfg, build_prompt(finding, repo_path, source, cfg.ai_context_lines))
        except Exception as err:  # keep going with the next finding
            log.warning("AI request failed for issue %s: %s", finding.issue_id, err)
            finding.reason = "AI: request failed"
            continue

        diff = extract_diff(reply)
        if not diff:
            finding.reason = "AI: no safe fix proposed"
            continue
        if not git.apply_patch(diff):
            finding.reason = "AI: patch did not apply"
            continue
        if cfg.ai_build_each_patch and not run_build(cfg):
            git.discard_changes()
            finding.reason = "AI: patch broke the build"
            continue

        changed = git.changed_files()
        finding.commit = git.commit_files(
            changed,
            f"fix(ai): CWE-{finding.cwe_id} Veracode issue {finding.issue_id} in {repo_path}",
        )
        finding.patched_by = "ai"
        applied += 1

    log.info("AI fallback committed %d patch(es).", applied)
    return applied
