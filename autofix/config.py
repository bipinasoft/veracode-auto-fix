"""Runtime configuration, read from environment variables.

Every setting has one place where it is defined, documented and defaulted, so
the rest of the code never reads os.environ directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool) -> bool:
    value = _env(name)
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    return int(value) if value else default


@dataclass
class Config:
    # --- Veracode platform -------------------------------------------------
    veracode_api_id: str = field(default_factory=lambda: _env("VERACODE_API_KEY_ID"))
    veracode_api_secret: str = field(default_factory=lambda: _env("VERACODE_API_KEY_SECRET"))
    veracode_api_base: str = field(
        default_factory=lambda: _env("VERACODE_API_BASE", "https://api.veracode.com")
    )
    # Application profile name; defaults to the GitLab project name.
    veracode_app_name: str = field(
        default_factory=lambda: _env("VERACODE_APP_NAME") or _env("CI_PROJECT_NAME")
    )
    # Sandbox to read findings from. Empty = sandbox named like the branch,
    # falling back to the policy scan when no such sandbox exists.
    veracode_sandbox_name: str = field(default_factory=lambda: _env("VERACODE_SANDBOX_NAME"))
    # Only findings at or above this severity are processed (5 = Very High ... 0 = Info).
    min_severity: int = field(default_factory=lambda: _env_int("MIN_SEVERITY", 0))

    # --- Repository / branch -------------------------------------------------
    target_branch: str = field(
        default_factory=lambda: _env("TARGET_BRANCH") or _env("CI_COMMIT_REF_NAME", "main")
    )
    repo_dir: str = field(default_factory=lambda: _env("REPO_DIR", "."))
    output_dir: str = field(default_factory=lambda: _env("OUTPUT_DIR", "autofix-output"))

    # --- Build and scan commands (shell commands from trusted CI config) ------
    build_cmd: str = field(default_factory=lambda: _env("BUILD_CMD"))
    test_cmd: str = field(default_factory=lambda: _env("TEST_CMD"))
    # Built artifact that Veracode Pipeline Scan analyses, e.g. target/app.jar
    scan_artifact: str = field(default_factory=lambda: _env("SCAN_ARTIFACT"))
    sast_scan_cmd: str = field(
        default_factory=lambda: _env(
            "SAST_SCAN_CMD", "veracode static scan {artifact} --results-file {output}"
        )
    )
    sca_scan_cmd: str = field(
        default_factory=lambda: _env("SCA_SCAN_CMD", "srcclr scan {repo} --allow-dirty --json={output}")
    )

    # --- Veracode Fix -------------------------------------------------------
    enable_veracode_fix_sast: bool = field(
        default_factory=lambda: _env_bool("ENABLE_VERACODE_FIX_SAST", True)
    )
    enable_veracode_fix_sca: bool = field(
        default_factory=lambda: _env_bool("ENABLE_VERACODE_FIX_SCA", True)
    )
    # Source folder Veracode Fix should patch, e.g. src/main/java
    fix_source_dir: str = field(default_factory=lambda: _env("FIX_SOURCE_DIR", "."))
    veracode_fix_sast_cmd: str = field(
        default_factory=lambda: _env(
            "VERACODE_FIX_SAST_CMD",
            "veracode fix {source} --type directory --apply --results {results}",
        )
    )
    veracode_fix_sca_cmd: str = field(
        default_factory=lambda: _env(
            "VERACODE_FIX_SCA_CMD", "veracode fix sca {repo} --remote --results {results}"
        )
    )

    # --- AI fallback --------------------------------------------------------
    enable_ai_fix: bool = field(default_factory=lambda: _env_bool("ENABLE_AI_FIX", True))
    llm_api_key: str = field(default_factory=lambda: _env("LLM_API_KEY"))
    llm_api_url: str = field(
        default_factory=lambda: _env("LLM_API_URL", "https://api.anthropic.com/v1/messages")
    )
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL", "claude-sonnet-5-5"))
    ai_max_findings: int = field(default_factory=lambda: _env_int("AI_MAX_FINDINGS", 20))
    # Lines of code sent to the model on each side of the flawed line.
    ai_context_lines: int = field(default_factory=lambda: _env_int("AI_CONTEXT_LINES", 40))
    # Run BUILD_CMD after every AI patch and drop patches that break the build.
    ai_build_each_patch: bool = field(
        default_factory=lambda: _env_bool("AI_BUILD_EACH_PATCH", True)
    )

    # --- GitLab -------------------------------------------------------------
    gitlab_api_url: str = field(
        default_factory=lambda: _env("GITLAB_API_URL") or _env("CI_API_V4_URL")
    )
    gitlab_project_id: str = field(
        default_factory=lambda: _env("GITLAB_PROJECT_ID") or _env("CI_PROJECT_ID")
    )
    gitlab_token: str = field(default_factory=lambda: _env("GITLAB_FIX_TOKEN"))
    gitlab_server_url: str = field(default_factory=lambda: _env("CI_SERVER_URL"))
    gitlab_project_path: str = field(default_factory=lambda: _env("CI_PROJECT_PATH"))
    pipeline_id: str = field(default_factory=lambda: _env("CI_PIPELINE_ID", "local"))
    mr_label: str = field(default_factory=lambda: _env("MR_LABEL", "veracode-auto-fix"))
    git_author_name: str = field(
        default_factory=lambda: _env("GIT_AUTHOR_NAME", "Veracode Auto-Fix Bot")
    )
    git_author_email: str = field(
        default_factory=lambda: _env("GIT_AUTHOR_EMAIL", "veracode-auto-fix@noreply.local")
    )

    # --- Behaviour ------------------------------------------------------------
    dry_run: bool = field(default_factory=lambda: _env_bool("DRY_RUN", False))

    @property
    def fix_branch(self) -> str:
        return f"veracode-fix/{self.target_branch}-{self.pipeline_id}"

    def require(self, *names: str) -> None:
        """Fail fast with a clear message when required settings are missing."""
        missing = [name for name in names if not getattr(self, name)]
        if missing:
            raise SystemExit(
                "Missing required configuration: "
                + ", ".join(missing)
                + ". See README 'Configuration' section."
            )
