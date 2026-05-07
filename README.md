# simple-container-com/actions

Centralized **reusable GitHub Actions workflows + composite actions** for the Simple Container org. Private — visible only to org members. Other org repos consume from here so we maintain CI security plumbing in one place.

## Layout

```
.
├── .github/
│   ├── workflows/
│   │   ├── security-scan.yml         # workflow_call — TruffleHog + Syft + Trivy + Grype
│   │   ├── security-scan-comment.yml # workflow_call — sticky PR comment for security-scan
│   │   ├── semgrep.yml               # workflow_call — Semgrep with SC ruleset
│   │   ├── semgrep-comment.yml       # workflow_call — sticky PR comment for semgrep
│   │   ├── lint.yml                  # self — actionlint + shellcheck
│   │   └── semgrep-self-test.yml     # self — runs semgrep-scan/run-tests.sh
│   └── dependabot.yml                # weekly bumps for github-actions ecosystem
├── trufflehog-scan/                  # composite — TruffleHog filesystem scan
├── sbom-generate/                    # composite — Syft → CycloneDX SBOM
├── sbom-scan/                        # composite — Trivy + Grype against SBOM
├── build-pr-comment/                 # composite — render security-scan PR comment
├── build-semgrep-comment/            # composite — render Semgrep PR comment
├── post-pr-comment/                  # composite — gh CLI sticky-comment poster
└── semgrep-scan/                     # composite — Semgrep runner
    ├── action.yml
    ├── scan.sh
    ├── summary.sh
    ├── rules/                        # SC custom Semgrep ruleset
    ├── tests/                        # rule-fixture tests
    └── run-tests.sh                  # rule-validation suite
```

Every composite action ships its own `.sh` script alongside its `action.yml`, so the heavy logic is testable, lintable, and Semgrep-scannable in isolation. The reusable workflow YAML stays a thin orchestrator.

## Why composite actions for the heavy lifting

This repo is private. A reusable `workflow_call` workflow runs on the consumer's runner, but the consumer's `GITHUB_TOKEN` is scoped to the consumer repo — it cannot `actions/checkout` this private repo to read its `scripts/` directory. **Composite actions** are the clean way to ship `.sh` files alongside YAML: GitHub fetches a composite action's directory using its own internal mechanism, regardless of whether the action's repo is private (provided org-level Actions access is granted).

## Reusable workflows (consumer-facing)

| Workflow | Purpose | Trigger in consumer wrapper |
|---|---|---|
| [`security-scan.yml`](.github/workflows/security-scan.yml) | TruffleHog → Syft → Trivy + Grype, render comment artifact, status gate | `pull_request`, `push` |
| [`security-scan-comment.yml`](.github/workflows/security-scan-comment.yml) | Posts/updates sticky comment for security-scan results | `workflow_run` |
| [`semgrep.yml`](.github/workflows/semgrep.yml) | Semgrep with SC ruleset (and optional consumer rules / registry packs), comment artifact, status gate | `pull_request`, `push` |
| [`semgrep-comment.yml`](.github/workflows/semgrep-comment.yml) | Posts/updates sticky comment for Semgrep results | `workflow_run` |

Each scan workflow uses `pull_request` (not `pull_request_target`), so fork PRs receive a read-only `GITHUB_TOKEN` and the workflow never sees org secrets. The privileged comment workflows run via `workflow_run` in the **base-repo context** but never read PR code — they consume only the rendered comment artifact. This is the [GitHub Security Lab pattern for preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).

## How to consume

Each consumer repo adds **four** thin wrapper workflows.

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

### `.github/workflows/semgrep.yml`

```yaml
name: Semgrep
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
  workflow_dispatch:
permissions:
  contents: read
jobs:
  semgrep:
    uses: simple-container-com/actions/.github/workflows/semgrep.yml@main
    permissions:
      contents: read
    # Optional inputs:
    # with:
    #   consumer-rules: '.semgrep/rules'      # additional rules in your repo
    #   registry-packs: 'p/security-audit'    # comma-separated semgrep registry packs
    #   fail-on-severity: 'ERROR'             # ERROR / WARNING / INFO
```

### `.github/workflows/semgrep-comment.yml`

```yaml
name: Semgrep Comment
on:
  workflow_run:
    workflows: ["Semgrep"]
    types: [completed]
permissions:
  contents: read
  pull-requests: write
  actions: read
jobs:
  comment:
    if: github.event.workflow_run.event == 'pull_request'
    uses: simple-container-com/actions/.github/workflows/semgrep-comment.yml@main
    permissions:
      contents: read
      pull-requests: write
      actions: read
```

The `workflows: [...]` value in each comment workflow must match the `name:` of the consumer's scan workflow exactly.

## Org access

This is a private repo. For other org repos to call its workflows or use its composite actions, the Actions access setting must be **"Accessible from repositories owned by the same organization"**:

```bash
gh api -X PUT repos/simple-container-com/actions/actions/permissions/access \
  -f access_level=organization
```

## Threat model

The workflows are designed assuming the consumer is a **public repo** that may receive PRs from external forks.

- **Untrusted PR code is never executed.** No `npm install`, no `go build`, no test runs. Tools (TruffleHog, Syft, Trivy, Grype, Semgrep) are file/AST/SBOM analyzers only.
- **Secrets are never exposed to PR-controlled code.** Scan jobs use `pull_request` (not `pull_request_target`) so fork PRs receive a read-only `GITHUB_TOKEN` and no org secrets.
- **PR-controlled strings are never inlined into shell.** PR title, body, branch, etc. are passed through `env:` vars and validated where they reach commands. Each `.sh` script asserts its inputs match a strict regex before use.
- **Third-party action surface is minimal and pinned.** Only first-party `actions/*` is used (checkout, upload-artifact, download-artifact). Each is referenced by full 40-char commit SHA with a `# vN` trailing comment for readability.
- **Tool Docker images are pinned by tag AND `@sha256` digest.** A digest is immutable; even if upstream re-publishes the same tag, the runner pulls the bytes we audited.
- **Image references are validated.** Every `.sh` script that runs `docker run` first asserts the image reference matches `^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$` before passing it to docker. The trailing `@sha256:` digest is **mandatory**, and a leading `-` is rejected.
- **Comment posting cannot read PR code.** The privileged comment workflows run on `workflow_run` and consume only the rendered comment artifact.

## Third-party action / tool audit

This repo intentionally minimises external dependencies.

| Kind | Reference | Why we use it | Removable? |
|---|---|---|---|
| Action | `actions/checkout@de0fac2…` (v6.0.2) | First-party. Required for any workflow that needs the workspace. | No |
| Action | `actions/upload-artifact@043fb46…` (v7.0.1) | First-party. The mechanism for cross-job/cross-workflow data passing. | No |
| Action | `actions/download-artifact@3e5f45b…` (v8.0.1) | First-party. Pair of upload-artifact. | No |
| Image | `ghcr.io/trufflesecurity/trufflehog:3.95.2@sha256:49d1c4f…` | Secret scanner — no first-party alternative. | No |
| Image | `ghcr.io/anchore/syft:v1.44.0@sha256:86fde64…` | SBOM generator — pairs with Grype/Trivy. | No |
| Image | `ghcr.io/anchore/grype:v0.112.0@sha256:391bfda…` | Vuln scanner against SBOM (Anchore side). | No |
| Image | `public.ecr.aws/aquasecurity/trivy:0.70.0@sha256:be1190a…` | Vuln scanner (Aqua side). Run alongside Grype to cross-check. | No |
| Image | `semgrep/semgrep:1.161.0@sha256:326e5f4…` | SAST engine — required by the user's choice of tool. | No |
| Image | `rhysd/actionlint:1.7.12@sha256:b1934ee…` | The de-facto GitHub Actions linter (catches expression issues GitHub itself doesn't). | No |
| Image | `koalaman/shellcheck:v0.11.0@sha256:61862eb…` | The de-facto shell linter. | No |

There are **no** third-party `uses:` actions. Every action is from the first-party `actions/*` org owned by GitHub. Every Docker image is the canonical upstream of the tool we picked, pinned by tag **and** sha256 digest.

### Bumping tool versions

- **Actions** (`actions/*`) are bumped automatically by Dependabot via the `github-actions` ecosystem — see [`.github/dependabot.yml`](.github/dependabot.yml). Weekly check; minor + patch grouped into a single PR.
- **Docker images** are tracked through [`versions/Dockerfile`](versions/Dockerfile) — a never-built catalogue of every tool image, with one `FROM image:tag@sha256:digest AS <stage>` line each. Dependabot's `docker` ecosystem watches it and opens auto-bump PRs. The image references in composite actions and shell scripts are kept in sync by [`tools/sync-tool-versions.sh`](tools/sync-tool-versions.sh):
  - The [`Tool Version Sync`](.github/workflows/tool-version-sync.yml) workflow runs `--check` on every PR and fails if any consumer is out of step with the Dockerfile.
  - When Dependabot opens a Dockerfile bump PR, the sync-check goes red. Pull the branch, run `tools/sync-tool-versions.sh --apply`, commit, push. Workflow goes green; merge.
  - Adding a new tool image: add a `FROM ... AS <stage>` row to the Dockerfile, the consumer reference in the relevant action.yml/script, and a `[<stage>]='<file>'` row to the targets map at the top of `tools/sync-tool-versions.sh`.

## Custom Semgrep rules

The [`semgrep-scan/rules/`](semgrep-scan/rules/) ruleset ships with the `semgrep-scan` composite action. It runs in this repo via [`semgrep-self-test.yml`](.github/workflows/semgrep-self-test.yml), and in any consumer that uses the [`semgrep.yml`](.github/workflows/semgrep.yml) reusable workflow.

### Shell rules — [`semgrep-scan/rules/shell.yml`](semgrep-scan/rules/shell.yml)

| ID | Severity | Detects |
|---|---|---|
| `shell-eval-usage` | ERROR | `eval` in shell scripts (use `printf -v` or `declare -n` instead) |
| `shell-curl-pipe-to-shell` | ERROR | `curl ... \| sh` / `wget ... \| bash` installer pattern |
| `shell-rm-rf-root` | ERROR | `rm -rf /` and similar disasters |
| `shell-source-of-variable-path` | WARNING | `source $VAR` / `. ${VAR}/...` — RCE if attacker controls VAR |
| `shell-cat-without-double-dash` | INFO | `cat "$F"` (use `cat -- "$F"` so leading-dash filenames don't smuggle flags) |

### GitHub Actions rules — [`semgrep-scan/rules/github-actions.yml`](semgrep-scan/rules/github-actions.yml)

| ID | Severity | Detects |
|---|---|---|
| `gha-script-injection-via-github-event` | ERROR | `${{ github.event.* }}` interpolated into a `run:` block (single- and multi-line, step-bounded) |
| `gha-script-injection-via-attacker-controlled-context` | ERROR | `head_ref`, head commit message, issue/PR title/body, comment/review body, `workflow_run.head_*`, `inputs.*`, `ref_name` interpolated into `run:` |
| `gha-pull-request-target-with-pr-head-checkout` | ERROR | Classic pwn-request: `pull_request_target` + `actions/checkout` of the PR head |
| `gha-unpinned-third-party-action` | WARNING | Third-party action referenced by tag instead of 40-char commit SHA (catches quoted variants) |
| `gha-unpinned-first-party-action` | INFO | `actions/*` referenced by tag (defence-in-depth) |
| `gha-permissions-write-all` | ERROR | Top-level `permissions: write-all` (incl. quoted) |
| `gha-checkout-persist-credentials-true` | ERROR | `actions/checkout` with explicit `persist-credentials: true` (scoped to checkout) |
| `gha-self-hosted-runner` | WARNING | `runs-on: self-hosted` — single-string, inline-array, or block-list form |
| `gha-secret-echoed` | ERROR | echo / printf / tee / heredoc that writes a secret to a log |
| `gha-cache-key-attacker-controlled` | ERROR | `actions/cache` key/restore-keys built from PR/issue/comment/inputs context (cache poisoning) |
| `gha-security-job-continue-on-error` | ERROR | `continue-on-error: true` on a security-named job (semgrep / sbom-scan / trufflehog / …) |
| `gha-workflow-run-checkout-head-sha` | ERROR | Privileged `workflow_run` job that checks out the upstream head SHA — re-introduces pwn-request risk |
| `gha-reusable-workflow-self-call` | WARNING | `uses: ./.github/workflows/<self>` recursion |
| `gha-security-job-permanently-disabled` | ERROR | `if: false` on a security-named job (silent gate disable) |
| `gha-comment-body-via-argv` | WARNING | `gh ... --body "$(cat ...)"` — switch to `jq -n --rawfile body … \| gh api --input -` |

### Tests

[`semgrep-scan/run-tests.sh`](semgrep-scan/run-tests.sh) runs each rule against [`semgrep-scan/tests/`](semgrep-scan/tests/) fixtures and asserts that every `# ruleid: <id>` marker matches and every `# ok: <id>` marker doesn't. It then runs the rules against the whole repo and asserts zero findings. Wired into [`semgrep-self-test.yml`](.github/workflows/semgrep-self-test.yml) so a broken rule fails CI.

Run it locally:

```bash
semgrep-scan/run-tests.sh
```

## Roadmap

Planned for follow-up PRs:

- Cosign / SLSA artifact signing
- Signature verification on the consume side
- More Semgrep rules as patterns prove their worth (next batch: artifact-name collision detection, secret-detector for non-`run:` script-style steps, allowlist of registry packs)
- Wiring private SC repos once the public-repo design is proven
- Cut a `v1` tag and migrate internal `@main` references to it

## Versioning

Pin consumers to `@main` while the design stabilizes. Once the first consumer is green, cut a `v1` tag and migrate consumers to it.
