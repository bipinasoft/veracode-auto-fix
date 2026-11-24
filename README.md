# Veracode Auto-Fix for GitLab

Connects a GitLab repository to its Veracode application profile, pulls the latest **SAST** (code flaws) and **SCA** (vulnerable dependencies) findings for the configured branch, fixes them with **Veracode Fix** and an **AI fallback**, verifies every fix with a re-scan, and opens a **fix merge request** that shows exactly how many findings were identified, fixed by Veracode Fix, fixed by AI, and left for a human.

```
GitLab pipeline ─► collect Veracode findings ─► Veracode Fix (SAST, SCA) ─► AI fallback (leftovers)
                 ─► build + tests + re-scan ─► keep only verified fixes ─► fix branch + MR + report
```

Design details, the diagram and the refined requirements are in [`docs/architecture.md`](docs/architecture.md).

---

## Contents

1. [What you get](#what-you-get)
2. [Repository layout](#repository-layout)
3. [Prerequisites](#prerequisites)
4. [Setup (one time)](#setup-one-time)
5. [Enable it on a repository](#enable-it-on-a-repository)
6. [Run it](#run-it)
7. [Run locally (dry run)](#run-locally-dry-run)
8. [Configuration reference](#configuration-reference)
9. [How fixes are counted](#how-fixes-are-counted)
10. [Testing the tool](#testing-the-tool)
11. [Limitations and notes](#limitations-and-notes)

---

## What you get

For every run, in the GitLab merge request description and in `autofix-output/`:

| Scan | Severity | Identified | Fixed by Veracode Fix | Fixed by AI | Not fixed |
|---|---|---:|---:|---:|---:|
| SAST | Very High | 3 | 2 | 1 | 0 |
| SAST | High | 10 | 6 | 2 | 2 |
| SCA | High | 5 | 4 | 0 | 1 |
| **Total** | | **18** | **12** | **3** | **3** |

followed by a **Fixed** table (issue, detail, engine, commit) and a **Not fixed** table with the reason for each (no fix generated, patch broke the build, still reported after re-scan, ...).

Output files:

| File | Content |
|---|---|
| `findings.json` | Open findings pulled from Veracode for the branch |
| `sast-baseline.json`, `sast-after.json` | Pipeline Scan results before / after fixing |
| `sca-baseline.json`, `sca-after.json` | SCA agent results before / after fixing |
| `fix-report.md` | The report posted in the MR |
| `fix-report.json` | Same report, machine readable, plus the MR URL |

## Repository layout

```
autofix/
  __main__.py          # CLI: collect | remediate | run  (the orchestrator)
  config.py            # every setting, read from environment variables
  veracode_api.py      # Veracode REST client + HMAC authentication
  collect.py           # app/sandbox lookup, findings download, filtering
  models.py            # Finding model and Veracode JSON conversion
  scans.py             # build, Pipeline Scan, SCA agent scan, result parsing
  fixers/
    veracode_fix.py    # Veracode Fix for SAST and SCA (CLI)
    ai_fix.py          # AI fallback for unpatched SAST findings
  verify.py            # decides fixed / not fixed from before vs after scans
  report.py            # counts table (Markdown + JSON)
  gitlab.py            # push fix branch, open MR, close superseded MRs
  shell.py             # running commands and git
templates/
  veracode-autofix.gitlab-ci.yml   # include this in target repositories
tests/                 # unit + offline end-to-end tests
Dockerfile             # runner image (Python, Veracode CLI, SCA agent, build tools)
.gitlab-ci.yml         # CI for this tool: tests + image build
```

The runtime uses the **Python standard library only** (Python 3.10+).

## Prerequisites

| Need | Why | Where to get it |
|---|---|---|
| Veracode API ID + secret | Read applications, sandboxes, findings; run Pipeline Scan and Veracode Fix | Veracode Platform > your user > *API Credentials* (account needs the Results API / Reviewer role and Veracode Fix entitlement) |
| Veracode SCA agent token | Run the SCA agent scan that Veracode Fix for SCA needs | Veracode Platform > *Software Composition Analysis* > Agents > create an agent (CLI) |
| GitLab project access token | Push the fix branch and open the MR | Target project > *Settings > Access tokens*, role **Developer**, scopes `api`, `write_repository` |
| LLM API key (optional) | AI fallback | Your approved LLM provider (defaults to the Anthropic Messages API) |
| GitLab runner with Docker | Runs the jobs | Existing shared/group runners |
| Container registry | Hosts the runner image | GitLab Container Registry of this project |

> Get security / data-handling approval before sending source code to Veracode Fix and to an external LLM.

## Setup (one time)

### 1. Mirror this repository into GitLab

Create a GitLab project, e.g. `security/veracode-auto-fix`, and push this repository to it (or set up a pull mirror from GitHub):

```bash
git clone https://github.com/bipinasoft/veracode-auto-fix.git
cd veracode-auto-fix
git remote add gitlab https://gitlab.example.com/security/veracode-auto-fix.git
git push gitlab main
```

### 2. Build the runner image

The image needs the build toolchain of the projects you will fix. It defaults to Java 17 + Maven; change `BUILD_PACKAGES` for other stacks.

- **Automatically:** the `build_image` job in [`.gitlab-ci.yml`](.gitlab-ci.yml) builds and pushes `$CI_REGISTRY_IMAGE:latest` on every push to `main`. Set a CI variable `BUILD_PACKAGES` to change the toolchain.
- **Manually:**

  ```bash
  docker build --build-arg BUILD_PACKAGES="openjdk-17-jdk-headless maven" \
    -t registry.example.com/security/veracode-auto-fix:latest .
  docker push registry.example.com/security/veracode-auto-fix:latest
  ```

Make sure the projects you want to fix are allowed to pull this image (*Settings > CI/CD > Job token permissions*, or a public/internal registry).

### 3. Add CI/CD variables

Add these as **masked** and **protected** variables, at group level (shared by all repos) or per project, in *Settings > CI/CD > Variables*:

| Variable | Value |
|---|---|
| `VERACODE_API_KEY_ID` | Veracode API ID |
| `VERACODE_API_KEY_SECRET` | Veracode API secret |
| `SRCCLR_API_TOKEN` | SCA agent token |
| `GITLAB_FIX_TOKEN` | Project access token (per project) |
| `LLM_API_KEY` | LLM key (optional; without it the AI fallback is skipped) |

Because the variables are *protected*, run the pipeline on a protected branch (e.g. `main`).

## Enable it on a repository

Add this to the target repository's `.gitlab-ci.yml` and adjust the build settings:

```yaml
include:
  - project: "security/veracode-auto-fix"
    ref: main
    file: "templates/veracode-autofix.gitlab-ci.yml"

variables:
  VERACODE_AUTOFIX_IMAGE: "registry.example.com/security/veracode-auto-fix:latest"
  # VERACODE_APP_NAME: "My Service"     # only if the Veracode profile name differs from the GitLab project name
  BUILD_CMD: "mvn -B -q package -DskipTests"
  TEST_CMD: "mvn -B -q test"            # optional, recommended
  SCAN_ARTIFACT: "target/my-service.jar"
  FIX_SOURCE_DIR: "src/main/java"
```

Examples for other stacks:

| Stack | `BUILD_CMD` | `SCAN_ARTIFACT` | `FIX_SOURCE_DIR` |
|---|---|---|---|
| Java / Maven | `mvn -B -q package -DskipTests` | `target/app.jar` | `src/main/java` |
| Java / Gradle | `./gradlew assemble` | `build/libs/app.jar` | `src/main/java` |
| Node / TypeScript | `npm ci && zip -r app.zip src package.json` | `app.zip` | `src` |
| Python | `zip -r app.zip src requirements.txt` | `app.zip` | `src` |

The template adds two jobs that run **only when asked**: `veracode_autofix_collect` (report only) and `veracode_autofix_remediate` (fix + MR). They never run on normal pushes.

**Branch → Veracode mapping:** the tool reads findings from the sandbox named like the branch (e.g. sandbox `develop` for branch `develop`). If there is no such sandbox it uses the latest **policy scan**. Set `VERACODE_SANDBOX_NAME` to force a specific sandbox.

## Run it

All runs need the variable `VERACODE_AUTOFIX=true`.

**Manually:** *Build > Pipelines > Run pipeline*, pick the branch, add variable `VERACODE_AUTOFIX` = `true`, run.

**On a schedule:** *Build > Pipeline schedules > New schedule*, e.g. every Monday 06:00, target branch `main`, variable `VERACODE_AUTOFIX` = `true`.

**From the API** (e.g. to trigger many repos from a script):

```bash
curl --request POST \
  --form "token=$TRIGGER_TOKEN" \
  --form "ref=main" \
  --form "variables[VERACODE_AUTOFIX]=true" \
  "https://gitlab.example.com/api/v4/projects/<project-id>/trigger/pipeline"
```

**Try it safely first:** add `DRY_RUN` = `true`. Everything runs and the report is produced, but nothing is pushed and no MR is opened.

### What happens in a run

1. **Collect** – finds the Veracode application and sandbox, downloads open STATIC and SCA findings (mitigated findings are excluded) → `findings.json`.
2. **Baseline scans** – builds the project, runs a Pipeline Scan and an SCA agent scan. These results are the input Veracode Fix needs and the "before" picture.
3. **Veracode Fix for SAST** – patches the source folder in batch mode; one commit per changed file. Reverted if the build/tests fail.
4. **Veracode Fix for SCA** – upgrades vulnerable dependencies; one commit. Reverted if the build/tests fail.
5. **AI fallback** – for each SAST finding Veracode Fix did not touch (most severe first, up to `AI_MAX_FINDINGS`): sends the CWE, Veracode's guidance and the surrounding code to the LLM, applies the returned diff only if it applies cleanly and the build still passes; one commit per finding.
6. **Verify** – rebuilds and re-runs both scans on the patched code, then decides fixed / not fixed (see below).
7. **Clean up** – drops every commit that did not fix at least one finding.
8. **Publish** – pushes `veracode-fix/<branch>-<pipeline id>`, opens an MR to the source branch with the report and label `veracode-auto-fix`, and closes older open auto-fix MRs for the same branch. If nothing was fixed, no branch or MR is created; the report is still saved as an artifact.

Review the MR like any other: each commit is one fix, so individual fixes can be dropped.

## Run locally (dry run)

Useful to try the tool on a pilot repository from your machine. You need Python 3.10+, git, the [Veracode CLI](https://docs.veracode.com/r/Install_the_Veracode_CLI), the [SCA agent](https://docs.veracode.com/r/t_sc_cli_agent) and the project's build tools.

```bash
git clone https://github.com/bipinasoft/veracode-auto-fix.git
git clone https://gitlab.example.com/team/my-service.git
cd veracode-auto-fix

cp .env.example .env        # fill in credentials and build settings; keep DRY_RUN=true
set -a; source .env; set +a

python -m autofix collect   # 1) check the findings Veracode returns -> autofix-output/findings.json
python -m autofix run       # 2) full flow on a local fix branch, no push
cat autofix-output/fix-report.md
```

`run` creates the branch `veracode-fix/<branch>-local` in your clone of the target repo. Inspect it with `git log`, and delete it when done.

## Configuration reference

All settings are environment variables. GitLab's predefined variables (`CI_*`) are used automatically in pipelines.

**Veracode**

| Variable | Default | Description |
|---|---|---|
| `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET` | – (required) | API credentials |
| `VERACODE_API_BASE` | `https://api.veracode.com` | Use `https://api.veracode.eu` for the EU region |
| `VERACODE_APP_NAME` | `$CI_PROJECT_NAME` | Application profile name (exact match) |
| `VERACODE_SANDBOX_NAME` | sandbox named like the branch, else policy scan | Force a sandbox |
| `MIN_SEVERITY` | `0` | Only process findings at or above this severity (5 Very High … 0 Informational) |
| `SRCCLR_API_TOKEN` | – | SCA agent token (read by `srcclr`) |

**Build and scans**

| Variable | Default | Description |
|---|---|---|
| `BUILD_CMD` | – | Builds the project; also used to check every fix |
| `TEST_CMD` | – | Optional tests run after `BUILD_CMD` |
| `SCAN_ARTIFACT` | – | Built file for Pipeline Scan. Without it SAST scans are skipped |
| `SAST_SCAN_CMD` | `veracode static scan {artifact} --results-file {output}` | Pipeline Scan command |
| `SCA_SCAN_CMD` | `srcclr scan {repo} --allow-dirty --json={output}` | SCA agent command |

**Veracode Fix**

| Variable | Default | Description |
|---|---|---|
| `ENABLE_VERACODE_FIX_SAST` / `ENABLE_VERACODE_FIX_SCA` | `true` | Turn each engine on/off |
| `FIX_SOURCE_DIR` | `.` | Folder Veracode Fix patches |
| `VERACODE_FIX_SAST_CMD` | `veracode fix {source} --type directory --apply --results {results}` | SAST fix command |
| `VERACODE_FIX_SCA_CMD` | `veracode fix sca {repo} --remote --results {results}` | SCA fix command |

**AI fallback**

| Variable | Default | Description |
|---|---|---|
| `ENABLE_AI_FIX` | `true` | Turn the fallback on/off (also off when no key) |
| `LLM_API_KEY` | – | API key |
| `LLM_API_URL` | `https://api.anthropic.com/v1/messages` | Messages-compatible endpoint (point at an internal gateway if you have one) |
| `LLM_MODEL` | `claude-sonnet-5-5` | Model name |
| `AI_MAX_FINDINGS` | `20` | Max findings sent to the model per run |
| `AI_CONTEXT_LINES` | `40` | Lines of code on each side of the flaw sent as context |
| `AI_BUILD_EACH_PATCH` | `true` | Build after every AI patch and drop the ones that break it |

**GitLab and behaviour**

| Variable | Default | Description |
|---|---|---|
| `GITLAB_FIX_TOKEN` | – (required to publish) | Project access token |
| `TARGET_BRANCH` | `$CI_COMMIT_REF_NAME` | Branch to read findings for and target the MR at |
| `MR_LABEL` | `veracode-auto-fix` | Label used to find and supersede older fix MRs |
| `GIT_AUTHOR_NAME` / `GIT_AUTHOR_EMAIL` | `Veracode Auto-Fix Bot` | Commit author |
| `REPO_DIR` | `.` | Path to the repository to fix |
| `OUTPUT_DIR` | `autofix-output` | Where reports and scan results are written |
| `DRY_RUN` | `false` | `true` = no push, no MR |

## How fixes are counted

The report always satisfies **Identified = Fixed by Veracode Fix + Fixed by AI + Not fixed**.

- **Identified** = open, non-mitigated findings returned by Veracode for the branch (at or above `MIN_SEVERITY`).
- A finding counts as **fixed** only with evidence from the re-scan:
  - **SAST:** flaws are grouped by CWE + file. If the baseline Pipeline Scan had 3 CWE-89 flaws in `UserDao.java` and the re-scan has 1, then 2 patched findings in that group are fixed (most severe first). Line numbers are not used because patches move code.
  - **SCA:** a patched finding is fixed when its CVE no longer appears in the re-scan.
- **Fixed by** is the engine that patched the finding: Veracode Fix, or AI when the AI fallback produced the patch.
- Anything else is **Not fixed**, with a reason. If a re-scan could not run, patched findings are reported as *"Patched but not verified"* – never as fixed.

The Veracode Platform itself updates after the next policy/sandbox scan of the merged code.

## Testing the tool

```bash
pip install pytest
python -m pytest -q
```

`tests/test_end_to_end.py` runs the whole `remediate` flow offline against a throwaway git repo, with the Veracode CLI and scanners replaced by small fake commands.

## Limitations and notes

- **CLI flags:** the default `veracode fix`, `veracode static scan` and `srcclr` commands follow current Veracode docs. If your CLI version differs, override `VERACODE_FIX_SAST_CMD`, `VERACODE_FIX_SCA_CMD`, `SAST_SCAN_CMD` or `SCA_SCAN_CMD`; no code change needed.
- **Veracode Fix coverage:** batch mode skips some CWEs and languages; those findings flow to the AI fallback.
- **AI fallback is SAST only.** Dependency upgrades are left to Veracode Fix for SCA.
- **Matching platform vs local scans:** SAST findings are matched by CWE + file name. Two files with the same name and the same CWE in different folders are counted together.
- **Build time:** every verification step rebuilds the project. Use `MIN_SEVERITY` and `AI_MAX_FINDINGS` to keep runs short, and set `AI_BUILD_EACH_PATCH=false` on slow builds (the final re-scan still verifies).
- **Human review is required.** The tool never pushes to the source branch; it only opens merge requests.
