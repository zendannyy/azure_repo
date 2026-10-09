# azure_repo

Azure Sentinel Detection-as-Code (analytics rules as Bicep / ARM JSON).

## Layout

| Path | Purpose |
|------|---------|
| `CustomDetections/*.bicep` | Authoritative scheduled alert rules (Bicep) |
| `CustomDetections/*.json` | ARM equivalents (Sentinel repo deploy / legacy) |
| `Templates/` | A template to use for new rules |
| `scripts/precommit/` | Local + CI validation hooks |
| `.github/workflows/sentinel-deploy-*.yml` | Sentinel GitHub App content deploy |
| `.github/workflows/dac-validate.yml` | Pre-deploy validation (lint / build / schema) |

## Pre-commit (required locally)
Catches Bicep/ARM issues before they hit the Sentinel deploy pipeline.

## How To Get Started

### One-time setup

```bash
# Azure CLI + Bicep (lint/build hooks)
az bicep install

# pre-commit framework (prefer pipx or a venv on macOS)
pipx install pre-commit
# or: python3 -m venv .venv && .venv/bin/pip install pre-commit

pre-commit install
```

### Run

```bash
pre-commit run --all-files
```

### What it checks

| Hook | Why |
|------|-----|
| trailing whitespace / EOF / JSON / YAML / large files | Repo hygiene |
| gitleaks | No accidental secrets |
| `az bicep lint` | Bicep language + `bicepconfig.json` rules |
| `az bicep build` | Compile to ARM (deployability) |
| unique `analytic_id` | No colliding rule IDs in `CustomDetections/` |
| alert-rule schema | Required Scheduled properties, severity, tactics, ISO-8601 durations |

`BCP174` (nested `/providers/` types) is a **warning** and does not fail lint. Prefer `scope:` on new rules when you rewrite them.

### Skip (emergency only)

```bash
SKIP=bicep-lint,bicep-build git commit -m "..."
# or
git commit --no-verify
```

## CI

`dac-validate` runs the same pre-commit suite on PRs that touch detections. Deploy to the workspace still goes through the existing Sentinel workflow on `main`.
