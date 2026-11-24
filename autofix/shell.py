"""Running external commands (build, scanners, Veracode CLI) and git."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class CommandResult:
    returncode: int
    output: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(command: str, cwd: str = ".", timeout: int = 3600) -> CommandResult:
    """Run a shell command from trusted CI configuration and capture its output."""
    log.info("$ %s", command)
    proc = subprocess.run(
        command, shell=True, cwd=cwd, text=True, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if proc.returncode != 0:
        log.warning("Command failed (exit %s). Last output:\n%s", proc.returncode, proc.stdout[-2000:])
    return CommandResult(proc.returncode, proc.stdout)


class Git:
    """Thin wrapper over the git CLI for the operations this tool needs."""

    def __init__(self, repo_dir: str):
        self.repo_dir = repo_dir

    def _git(self, *args: str, check: bool = True) -> str:
        proc = subprocess.run(
            ["git", *args], cwd=self.repo_dir, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        if check and proc.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
        return proc.stdout.strip()

    def configure_author(self, name: str, email: str) -> None:
        self._git("config", "user.name", name)
        self._git("config", "user.email", email)

    def checkout_new_branch(self, branch: str) -> None:
        self._git("checkout", "-B", branch)

    def head(self) -> str:
        return self._git("rev-parse", "HEAD")

    def changed_files(self) -> list[str]:
        """Tracked files modified in the working tree (ignores untracked files)."""
        out = self._git("diff", "--name-only")
        return [line for line in out.splitlines() if line]

    def commit_files(self, files: list[str], message: str) -> str:
        self._git("add", "--", *files)
        self._git("commit", "-m", message)
        return self.head()

    def discard_changes(self) -> None:
        self._git("checkout", "--", ".")

    def reset_hard(self, ref: str) -> None:
        self._git("reset", "--hard", ref)

    def apply_patch(self, patch: str) -> bool:
        """Apply a unified diff; returns False (and changes nothing) if it does not apply."""
        check = subprocess.run(
            ["git", "apply", "--check", "--recount", "-"], cwd=self.repo_dir,
            input=patch, text=True, capture_output=True,
        )
        if check.returncode != 0:
            log.warning("Patch does not apply: %s", check.stderr.strip())
            return False
        subprocess.run(["git", "apply", "--recount", "-"], cwd=self.repo_dir,
                       input=patch, text=True, check=True)
        return True

    def commits_since(self, ref: str) -> list[str]:
        """Commit SHAs after `ref`, oldest first."""
        out = self._git("rev-list", "--reverse", f"{ref}..HEAD")
        return [line for line in out.splitlines() if line]

    def keep_only_commits(self, base: str, keep: list[str]) -> dict[str, str | None]:
        """Rebuild the branch from `base` with only the `keep` commits (in order).

        Cherry-picking gives commits new SHAs, so this returns a map of
        old SHA -> new SHA, or None for a commit that no longer applied cleanly.
        """
        self.reset_hard(base)
        new_shas: dict[str, str | None] = {}
        for sha in keep:
            picked = subprocess.run(["git", "cherry-pick", sha], cwd=self.repo_dir,
                                    capture_output=True, text=True)
            if picked.returncode != 0:
                self._git("cherry-pick", "--abort", check=False)
                new_shas[sha] = None
            else:
                new_shas[sha] = self.head()
        return new_shas

    def push(self, remote_url: str, branch: str) -> None:
        self._git("push", remote_url, f"HEAD:refs/heads/{branch}")

    def ls_files(self) -> list[str]:
        return self._git("ls-files").splitlines()
