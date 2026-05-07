# simple-container-com/actions

Centralized **reusable GitHub Actions workflows + composite actions** for the Simple Container org. Private — visible only to org members. Other org repos consume from here so we maintain CI security plumbing in one place.

## Layout

```
.
├── .github/workflows/
│   ├── security-scan.yml           # workflow_call — orchestrator
│   ├── security-scan-comment.yml   # workflow_call — privileged comment poster
│   ├── lint.yml                    # actionlint + shellcheck on every PR
│   └── semgrep.yml                 # custom semgrep ruleset + rule tests
├── trufflehog-scan/                # composite action — TruffleHog filesystem scan
├── sbom-generate/                  # composite action — Syft → CycloneDX SBOM
├── sbom-scan/                      # composite action — Trivy + Grype against SBOM
├── build-pr-comment/               # composite action — render comment body to artifact
├── post-pr-comment/                # composite action — gh CLI sticky-comment poster
└── .semgrep/
    ├── rules/                      # custom Semgrep rules (shell + GHA)
    ├── tests/                      # fixture files validating each rule
    └── run-tests.sh                # rule-test runner used in CI
```

Every composite action ships its own `.sh` script alongside its `action.yml`, so the heavy logic is testable, lintable, and Semgrep-scannable in isolation. The workflow YAML stays a thin orchestrator.

## Why composite actions for the heavy lifting

This repo is private. A reusable `workflow_call` workflow runs on the consumer's runner, but the consumer's `GITHUB_TOKEN` is scoped to the consumer repo — it cannot `actions/checkout` this private repo to read its `scripts/` directory. **Composite actions** are the clean way to ship `.sh` files alongside YAML: GitHub fetches a composite action's directory using its own internal mechanism, regardless of whether the action's repo is private (provided org-level Actions access is granted).

## Workflows

| Workflow | Purpose | Trigger in consumer |
|---|---|---|
| [`security-scan.yml`](.github/workflows/security-scan.yml) | TruffleHog → Syft → Trivy + Grype, render PR comment artifact, status gate | `pull_request`, `push` |
| [`security-scan-comment.yml`](.github/workflows/security-scan-comment.yml) | Downloads the PR comment artifact and posts/updates a sticky comment | `workflow_run` |

The split is deliberate: the scan workflow runs in **PR context** (read-only token, no secrets — safe for fork PRs) and uploads a pre-rendered comment body as an artifact. The comment workflow runs in **base-repo context** (privileged token) but never touches PR code — it only reads the artifact. This is the [GitHub Security Lab pattern for preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).

## How to consume

Add **two** workflows to the consumer repo.

### `.github/workflows/security-scan.yml`

```yaml
name: Security Scan
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
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

This is a private repo. For other org repos to call its workflows or use its composite actions, the Actions access setting must be **"Accessible from repositories owned by the same organization"**:

```bash
gh api -X PUT repos/simple-container-com/actions/actions/permissions/access \
  -f access_level=organization
```

## Threat model

The workflows are designed assuming the consumer is a **public repo** that may receive PRs from external forks.

- **Untrusted PR code is never executed.** No `npm install`, no `go build`, no test runs. Tools (TruffleHog, Syft, Trivy, Grype) are file/SBOM analyzers only.
- **Secrets are never exposed to PR-controlled code.** The scan job uses `pull_request` (not `pull_request_target`) so fork PRs receive a read-only `GITHUB_TOKEN` and no org secrets.
- **PR-controlled strings are never inlined into shell.** PR title, body, branch, etc. are passed through `env:` vars and validated where they reach commands. Each `.sh` script asserts its inputs match a strict regex before use.
- **Third-party actions are pinned by 40-char commit SHA.** Only first-party `actions/*` is used; the SHA is recorded with a `# vN` trailing comment for readability.
- **Tool images are pinned by version tag.** TruffleHog, Syft, Trivy, Grype run as Docker containers from upstream registries — no `curl ... | sh` installers.
- **Image references are validated.** Every `.sh` script that runs `docker run` first asserts the image reference matches `^[a-zA-Z0-9._/-]+:[A-Za-z0-9._-]+$` before passing it to docker.
- **Comment posting cannot read PR code.** The privileged comment job runs on `workflow_run` and consumes only the rendered artifact.

## Custom Semgrep rules

The `.semgrep/rules/` ruleset runs against this repo on every PR (`semgrep.yml` workflow). It catches mistakes that `actionlint` and `shellcheck` miss.

### Shell rules — [`.semgrep/rules/shell.yml`](.semgrep/rules/shell.yml)

| ID | Severity | Detects |
|---|---|---|
| `shell-eval-usage` | ERROR | `eval` in shell scripts (use `printf -v` or `declare -n` instead) |
| `shell-curl-pipe-to-shell` | ERROR | `curl ... \| sh` / `wget ... \| bash` installer pattern |
| `shell-rm-rf-root` | ERROR | `rm -rf /` and similar disasters |
| `shell-source-of-variable-path` | WARNING | `source $VAR` / `. ${VAR}/...` — RCE if attacker controls VAR |
| `shell-cat-without-double-dash` | INFO | `cat "$F"` (use `cat -- "$F"` so leading-dash filenames don't smuggle flags) |

### GitHub Actions rules — [`.semgrep/rules/github-actions.yml`](.semgrep/rules/github-actions.yml)

| ID | Severity | Detects |
|---|---|---|
| `gha-script-injection-via-github-event` | ERROR | `${{ github.event.* }}` interpolated into a `run:` block (single- and multi-line) |
| `gha-script-injection-via-attacker-controlled-context` | ERROR | `head_ref`, `head_commit.message`, `issue.title`, etc. interpolated into `run:` |
| `gha-pull-request-target-with-pr-head-checkout` | ERROR | Classic pwn-request: `pull_request_target` + `actions/checkout` of the PR head |
| `gha-unpinned-third-party-action` | WARNING | Third-party action referenced by tag instead of 40-char commit SHA |
| `gha-unpinned-first-party-action` | INFO | `actions/*` referenced by tag (defence-in-depth) |
| `gha-permissions-write-all` | ERROR | Top-level `permissions: write-all` |
| `gha-checkout-persist-credentials-true` | ERROR | `actions/checkout` with explicit `persist-credentials: true` |
| `gha-self-hosted-runner` | WARNING | `runs-on: self-hosted` (PR code on shared org hardware) |
| `gha-secret-echoed` | ERROR | `echo "${{ secrets.X }}"` writes secrets to logs |

### Tests

[`.semgrep/run-tests.sh`](.semgrep/run-tests.sh) runs each rule against [`.semgrep/tests/`](.semgrep/tests/) fixtures and asserts that every `# ruleid: <id>` marker matches and every `# ok: <id>` marker doesn't. It then runs the rules against the whole repo and asserts zero findings. Wired into `semgrep.yml` so a broken rule fails CI.

Run it locally:

```bash
.semgrep/run-tests.sh
```

## Roadmap

Planned for follow-up PRs:

- Cosign / SLSA artifact signing
- Signature verification on the consume side
- More Semgrep rules as they prove their worth (e.g., explicit allowlist for `${{ env.X }}` interpolation in `run:`)
- Wiring private SC repos once the public-repo design is proven

## Versioning

Pin consumers to `@main` while the design stabilizes. Once the first consumer is green, cut a `v1` tag and migrate consumers to it.
