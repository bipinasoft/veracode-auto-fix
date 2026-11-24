# Veracode Auto-Fix for GitLab (PoC)

An innovation proof of concept that connects a GitLab repository to its mapped Veracode application, pulls the latest SAST and SCA findings for the configured branch, fixes them with **Veracode Fix** (and an **AI fallback** for what Veracode Fix can't handle), verifies each fix, and opens a **fix merge request** that clearly reports what was identified, what was fixed, and by whom.

> Status: design / scaffolding. See [`docs/architecture.md`](docs/architecture.md) for the diagram and [`.gitlab-ci.yml`](.gitlab-ci.yml) for the pipeline skeleton.

---

## 1. Problem statement (refined prompt)

Build a proof of concept, "Veracode Auto-Fix for GitLab", that runs as a GitLab CI pipeline.

**Inputs:** a GitLab project ID and target branch. The tool resolves the mapped Veracode application profile (by name or a mapping file) and, if the branch is scanned into a Veracode sandbox, the matching sandbox; otherwise it uses the latest policy scan.

**Steps:**

1. Fetch the latest open findings for that application/branch from the Veracode REST Findings API — both STATIC (code flaws) and SCA (vulnerable dependencies) — including severity, CWE/CVE, file, line, and Veracode's remediation guidance.
2. Normalise them into one findings model and save it as a pipeline artifact (`findings.json`).
3. Remediate in this order:
   1. **Veracode Fix for SAST** (CLI, batch mode) for supported languages/CWEs.
   2. **Veracode Fix for SCA** (CLI) for dependency upgrades.
   3. **AI fallback** only for findings Veracode Fix skipped, using Veracode's guidance and the code context as input, with guardrails (one finding per patch, minimal diff, no new dependencies).
4. **Verify:** build, run unit tests, re-run a Veracode Pipeline Scan + SCA agent scan on the fixed code. Any patch that breaks the build or does not clear the finding is reverted and marked "not fixed".
5. Create branch `veracode-fix/<branch>-<pipelineId>`, commit each fix separately (message references the Veracode issue ID/CWE), push, and open a merge request to the source branch. Never push to protected branches directly.
6. Publish a report (MR description + `fix-report.json` + `fix-report.md` artifact) showing, per scan type and severity:
   - **Identified** – total open findings from Veracode
   - **Fixed by Veracode Fix** (SAST / SCA)
   - **Fixed by AI fallback**
   - **Not fixed** – with reason (unsupported language/CWE, build failed, re-scan still flags it, needs design change)

   Invariant: `Identified = Fixed (Veracode) + Fixed (AI) + Not fixed`.

**Non-functional:** secrets in masked/protected CI variables, idempotent re-runs (reuse/update an open fix MR), dry-run mode, structured logs, human review required before merge.

---

## 2. Architecture

```
GitLab trigger (schedule / manual / API / webhook)
        │
        ▼
Orchestrator CI job (Python, Docker image with Veracode CLI + srcclr + build toolchain)
        │  1. resolve mapping  ─────────────►  Veracode Applications & Sandboxes API
        │  2. fetch findings   ─────────────►  Veracode Findings API (STATIC, SCA)
        ▼
Normalised findings.json
        │
        ├──► Veracode Fix SAST  (veracode fix --type directory --apply --results results.json)
        ├──► Veracode Fix SCA   (veracode fix sca ... --results <srcclr results.json>)
        └──► AI fallback        (only for skipped findings)
        ▼
Verify: build + tests + Pipeline Scan + SCA agent re-scan → keep / revert each patch
        ▼
GitLab API: create branch, commits, MR with counts report; artifacts for audit
```

### Components

| Component | Responsibility | Tech |
|---|---|---|
| Trigger | Start the run for a repo/branch | `.gitlab-ci.yml` `rules:` for schedules, manual, `CI_PIPELINE_SOURCE == "api"` |
| Mapping resolver | GitLab project → Veracode app GUID (+ sandbox GUID for branch) | `GET /appsec/v1/applications?name=`, `GET /appsec/v1/applications/{guid}/sandboxes`; optional `veracode-mapping.yml` override |
| Findings collector | Latest open findings | `GET /appsec/v2/applications/{guid}/findings?scan_type=STATIC&context={sandbox_guid}` and a separate call with `scan_type=SCA` (SCA can't be combined with other types); paginated; HMAC auth |
| Normaliser | One schema across STATIC/SCA: id, type, severity, CWE/CVE, file, line, component, guidance, status | Python dataclasses / pydantic |
| Fix engine – Veracode SAST | Generate and apply top-ranked patches | Veracode CLI `veracode fix` (batch). Needs a static results JSON → produced by `veracode static scan` (Pipeline Scan) on the built artifact |
| Fix engine – Veracode SCA | Dependency upgrade patches | `veracode fix sca` with srcclr agent results |
| Fix engine – AI fallback | Patch what Veracode Fix skipped | LLM API with prompt = finding + guidance + code window; returns a unified diff; applied with `git apply --check` first |
| Verifier | Prove fixes are safe and effective | Build + unit tests; re-scan; compare issue fingerprints (CWE + file + function) before vs after |
| SCM publisher | Branch, commits, MR | GitLab REST API (`python-gitlab`) with a project access token (`api`, `write_repository`) |
| Reporter | Counts & audit trail | MR description (Markdown table), `fix-report.json`, optional note on the source MR |

### Key design decisions

1. **Platform findings are the source of truth for "identified"; a fresh Pipeline Scan is the source for "fixed".** Veracode Fix CLI consumes scan-results JSON from a static scan, not the Findings API JSON, so the job runs a Pipeline Scan on the same commit to feed Veracode Fix and to verify. Findings are matched via CWE + file + line/function.
2. **Veracode Fix first, AI second.** Keeps the PoC aligned with the licensed, Veracode-trained tool; AI only handles the gaps (e.g. CWEs excluded from batch mode, unsupported languages).
3. **One commit per finding** so reviewers can drop individual fixes, and each commit links to a Veracode issue ID.
4. **Fail safe.** Any patch that fails build/tests or re-scan is reverted and counted as "Not fixed – verification failed".
5. **GitLab CI over an external service** for the PoC: no new infrastructure, uses existing runners and CI variables. Can later move to a central webhook-driven service across all repos.

---

## 3. Report format (MR description)

| Scan | Severity | Identified | Fixed – Veracode Fix | Fixed – AI | Not fixed |
|---|---|---|---|---|---|
| SAST | Very High | 3 | 2 | 1 | 0 |
| SAST | High | 10 | 6 | 2 | 2 |
| SCA | High | 5 | 4 | 0 | 1 |
| **Total** | | **18** | **12** | **3** | **3** |

Followed by a "Not fixed" table: Veracode issue ID, CWE/CVE, file:line, reason, Veracode guidance link.

---

## 4. Configuration

Required CI/CD variables (masked + protected):

| Variable | Purpose |
|---|---|
| `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` | Veracode REST API (HMAC) and CLI |
| `SRCCLR_API_TOKEN` | Veracode SCA agent scan |
| `GITLAB_FIX_TOKEN` | Project access token to push the fix branch and open the MR |
| `LLM_API_KEY` | AI fallback fixer |

Optional: `VERACODE_APP_NAME` (defaults to the project name), `DRY_RUN=true` to skip pushing/MR creation.

---

## 5. PoC scope

- 1–2 pilot repos (e.g. one Java/Maven, one JS/Node) with an existing Veracode app mapping and recent scans.
- Success criteria: identified counts match the Veracode UI, at least one fix from each engine, MR created with the report, zero direct pushes to protected branches.

## 6. Risks / open questions

- Veracode Fix licence/entitlement and data-handling approval for both Veracode Fix and the external LLM.
- Branch → sandbox naming convention in the Veracode setup (needed by the resolver).
- Build reproducibility in CI for the Pipeline Scan artifact.
- Platform results only update after the next policy/sandbox scan — the MR shows verified counts from the pipeline re-scan until then.

## 7. Planned repository layout

```
autofix/
  collect.py     # mapping resolver + findings collector + normaliser
  fix.py         # Veracode Fix SAST/SCA runners + AI fallback
  verify.py      # build/test/re-scan and keep/revert decisions
  publish.py     # branch, commits, MR, report
docs/
  architecture.md
.gitlab-ci.yml
```
