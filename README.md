# simple-container-com/actions

Centralized **reusable GitHub Actions workflows** for the Simple Container org. Private — visible only to org members. Other org repos call workflows from here so we maintain CI security plumbing in one place.

## Workflows

| Workflow | Purpose | Trigger in consumer |
|---|---|---|
| [`security-scan.yml`](.github/workflows/security-scan.yml) | TruffleHog (secrets) + Syft (SBOM) + Trivy & Grype (SCA) | `pull_request`, `push` |
| [`security-scan-comment.yml`](.github/workflows/security-scan-comment.yml) | Posts/updates the sticky PR comment built by `security-scan.yml` | `workflow_run` |

The split is deliberate: the scan workflow runs in the **PR context** (read-only token, no secrets, safe for fork PRs) and uploads a pre-rendered comment body as an artifact. The comment workflow runs in the **base-repo context** (privileged token) but never touches PR code — it only reads the artifact and posts. This is the [GitHub Security Lab pattern for preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).

## How to consume

Add **two** workflows to the consumer repo. Both files are short.

### `.github/workflows/security-scan.yml`

```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  security:
    uses: simple-container-com/actions/.github/workflows/security-scan.yml@main
    permissions:
      contents: read
```

### `.github/workflows/security-scan-comment.yml`

```yaml
name: Security Scan Comment
on:
  workflow_run:
    workflows: ["Security Scan"]
    types: [completed]
permissions:
  contents: read
  pull-requests: write
  actions: read
jobs:
  comment:
    if: github.event.workflow_run.event == 'pull_request'
    uses: simple-container-com/actions/.github/workflows/security-scan-comment.yml@main
    permissions:
      contents: read
      pull-requests: write
      actions: read
```

The `workflows: ["Security Scan"]` value must match the `name:` of the consumer's scan workflow exactly.

## Org access

This is a private repo. For other org repos to call its workflows, the org/repo Actions access setting must be **"Accessible from repositories owned by the same organization"**:

```bash
gh api -X PUT repos/simple-container-com/actions/actions/permissions/access \
  -f access_level=organization
```

## Threat model

The workflows are designed assuming the consumer is a **public repo** that may receive PRs from external forks.

- **Untrusted PR code is never executed.** No `npm install`, no `go build`, no test runs. Tools (TruffleHog, Syft, Trivy, Grype) are file/SBOM analyzers only.
- **Secrets are never exposed to PR-controlled code.** The scan job uses `pull_request` (not `pull_request_target`) so fork PRs receive a read-only `GITHUB_TOKEN` and no org secrets.
- **PR-controlled strings are never inlined into shell.** Title, branch, body, etc. are passed through `env:` vars and validated where they reach commands.
- **Third-party actions are minimized and pinned.** Only first-party `actions/*`, all referenced by full 40-char commit SHA.
- **Tool images are pinned by version tag.** TruffleHog, Syft, Trivy, Grype run as Docker containers from upstream registries — no `curl ... | sh` installers.
- **Comment posting cannot read PR code.** The privileged comment job runs on `workflow_run` and consumes only the rendered artifact from the scan run.

## Roadmap

Planned for follow-up PRs (not in scope for this initial release):

- Semgrep SAST workflow
- Cosign / SLSA artifact signing
- Signature verification on the consume side
- Composite actions (split scanners into `./trufflehog`, `./sbom-generate`, `./sbom-scan`) once a second piecewise consumer appears
- Wiring private SC repos (`forge`, `cloud`, `forge-runtime`, …) once the public-repo design is proven

## Versioning

Pin consumers to `@main` while the workflow stabilizes. After the first consumer (`forge-action`) is green for a release cycle, we cut a `v1` tag and pin consumers to it.
