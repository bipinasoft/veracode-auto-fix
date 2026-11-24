# Architecture

```mermaid
flowchart TD
    T["GitLab trigger<br/>schedule · manual · API"] --> O["Orchestrator CI job<br/>repo, branch, app mapping"]
    O --> C["Collect Veracode findings<br/>Applications · Sandboxes · Findings API<br/>STATIC + SCA"]
    C --> N["Normalised findings.json"]
    N --> FS["Veracode Fix SAST<br/>code flaw patches"]
    N --> FC["Veracode Fix SCA<br/>dependency upgrades"]
    N --> AI["AI fallback<br/>leftover flaws only"]
    FS --> V["Verify<br/>build · tests · pipeline re-scan"]
    FC --> V
    AI --> V
    V -->|keep| P["Fix branch + merge request<br/>counts report"]
    V -->|revert| X["Not fixed<br/>with reason"]
    X --> P

    classDef veracode fill:#EEEDFE,stroke:#534AB7,color:#3C3489
    classDef ai fill:#E1F5EE,stroke:#0F6E56,color:#085041
    class C,FS,FC veracode
    class AI ai
```

## Flow

1. **Trigger** – a scheduled, manual or API-triggered pipeline starts for a project and branch.
2. **Collect** – resolve the Veracode application (and branch sandbox, if any) and fetch the latest open STATIC and SCA findings (two separate Findings API calls).
3. **Fix** – Veracode Fix (SAST, then SCA) runs first; the AI fallback only receives findings Veracode Fix skipped.
4. **Verify** – each patch must build, pass tests and clear the finding in a fresh Pipeline Scan / SCA agent scan; otherwise it is reverted.
5. **Publish** – push `veracode-fix/<branch>-<pipelineId>`, open an MR, and post the Identified / Fixed (Veracode) / Fixed (AI) / Not fixed counts.
