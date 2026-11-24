"""Push the fix branch and open (or replace) the merge request in GitLab."""

from __future__ import annotations

import logging
from urllib.parse import quote, urlparse

from .config import Config
from .http import request_json
from .shell import Git

log = logging.getLogger(__name__)


class GitLabClient:
    def __init__(self, api_url: str, project_id: str, token: str):
        self.base = f"{api_url.rstrip('/')}/projects/{quote(str(project_id), safe='')}"
        self.headers = {"PRIVATE-TOKEN": token}

    def _call(self, method: str, path: str, body: dict | None = None):
        return request_json(method, f"{self.base}{path}", headers=self.headers, body=body)

    def open_fix_mrs(self, target_branch: str, label: str) -> list[dict]:
        query = f"?state=opened&labels={quote(label)}&target_branch={quote(target_branch)}"
        return self._call("GET", f"/merge_requests{query}") or []

    def create_mr(self, source: str, target: str, title: str, description: str, label: str) -> dict:
        return self._call("POST", "/merge_requests", {
            "source_branch": source,
            "target_branch": target,
            "title": title,
            "description": description,
            "labels": label,
            "remove_source_branch": True,
        })

    def close_mr(self, iid: int, note: str) -> None:
        self._call("POST", f"/merge_requests/{iid}/notes", {"body": note})
        self._call("PUT", f"/merge_requests/{iid}", {"state_event": "close"})


def authenticated_remote(cfg: Config) -> str:
    """HTTPS remote URL that uses the project access token for the push."""
    server = urlparse(cfg.gitlab_server_url)
    return f"{server.scheme}://oauth2:{cfg.gitlab_token}@{server.netloc}/{cfg.gitlab_project_path}.git"


def publish(cfg: Config, git: Git, report_markdown: str, fixed_count: int) -> str | None:
    """Push the branch and open the MR. Returns the MR URL (or None in dry-run)."""
    if cfg.dry_run:
        log.info("DRY_RUN: not pushing %s or opening a merge request.", cfg.fix_branch)
        return None
    cfg.require("gitlab_api_url", "gitlab_project_id", "gitlab_token",
                "gitlab_server_url", "gitlab_project_path")

    git.push(authenticated_remote(cfg), cfg.fix_branch)
    client = GitLabClient(cfg.gitlab_api_url, cfg.gitlab_project_id, cfg.gitlab_token)

    previous = client.open_fix_mrs(cfg.target_branch, cfg.mr_label)
    mr = client.create_mr(
        source=cfg.fix_branch,
        target=cfg.target_branch,
        title=f"Veracode Auto-Fix: {fixed_count} security finding(s) fixed on {cfg.target_branch}",
        description=report_markdown,
        label=cfg.mr_label,
    )
    # Keep one live fix MR per branch: close older ones in favour of this run.
    for old in previous:
        client.close_mr(old["iid"], f"Superseded by !{mr['iid']} from a newer Veracode Auto-Fix run.")
    log.info("Merge request created: %s", mr.get("web_url"))
    return mr.get("web_url")
