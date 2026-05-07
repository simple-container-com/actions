# simple-container-com/actions

Centralized reusable GitHub Actions workflows + composite actions for the Simple Container org. Private repo. Other org repos (public or private) consume from here so CI security plumbing lives in one place.

## Layout

```
.
├── .github/
│   ├── workflows/
│   │   ├── security-scan.yml          # workflow_call — TruffleHog + Syft + Trivy + Grype
│   │   ├── security-scan-comment.yml  # workflow_call — sticky PR comment for security-scan
│   │   ├── semgrep.yml                # workflow_call — Semgrep with the SC ruleset
│   │   ├── semgrep-comment.yml        # workflow_call — sticky PR comment for Semgrep
│   │   ├── lint.yml                   # self — actionlint + shellcheck
│   │   ├── semgrep-self-test.yml      # self — runs semgrep-scan/run-tests.sh
│   │   └── tool-version-sync.yml      # self — sync-tool-versions.sh --check
│   └── dependabot.yml                 # github-actions + docker (versions/Dockerfile)
├── trufflehog-scan/                   # composite — TruffleHog filesystem scan
├── sbom-generate/                     # composite — Syft → CycloneDX SBOM
├── sbom-scan/                         # composite — Trivy + Grype against SBOM
├── build-pr-comment/                  # composite — render security-scan PR comment artifact
├── build-semgrep-comment/             # composite — render Semgrep PR comment artifact
├── post-pr-comment/                   # composite — gh CLI sticky-comment poster (privileged)
├── semgrep-scan/                      # composite — Semgrep runner (rules + tests + run-tests.sh)
├── notify-telegram/                   # composite — Telegram Bot API sender (token-masked)
├── tools/sync-tool-versions.sh        # propagate versions/Dockerfile → consumer files
└── versions/Dockerfile                # tool image catalogue (Dependabot tracks this)
```

## Composite actions (also consumer-facing)

| Action | Purpose |
|---|---|
| [`install-sc`](install-sc/) | Install the `sc` CLI at a pinned version. Downloads `dist.simple-container.com/sc-<platform>-<arch>-v<version>.tar.gz`, extracts to `~/.local/bin`, adds to `$GITHUB_PATH`. Optional `sha256` input for defense-in-depth (SC does not publish checksums today). Replaces the curl-pipe install bootstrap so consumer workflows never pipe remote content into a shell. |
| [`install-welder`](install-welder/) | Same shape for the `welder` CLI. Note: the welder dist server only publishes `latest`; passing a `version` input that doesn't resolve fails with a clear error. Optional `sha256` input. |
| [`notify-telegram`](notify-telegram/) | Send a Telegram message via the Bot API. Token is registered with `::add-mask::` so it is redacted from any subsequent log output. Inputs are validated; text is sent as plain text (no `parse_mode`) so attacker-controlled commit messages cannot inject formatting. Replaces unpinned third-party telegram-notify actions. |

Use directly from a consumer workflow:

```yaml
- uses: simple-container-com/actions/install-sc@v1
  with:
    version: '2026.4.12'
    # sha256: 'aaaa...'   # optional, recommended once you've pinned a version
- uses: simple-container-com/actions/install-welder@v1
- run: sc --version && welder --version

# Telegram notification (token redacted from logs):
- uses: simple-container-com/actions/notify-telegram@v1
  if: always()
  with:
    chat-id: ${{ secrets.TG_CHAT_ID }}
    token:   ${{ secrets.TG_BOT_TOKEN }}
    text:    "✅ Build ${{ job.status }} on ${{ github.ref_name }}"
```

## Reusable workflows (consumer-facing)

| Workflow | Purpose | Trigger in consumer |
|---|---|---|
| [`security-scan.yml`](.github/workflows/security-scan.yml) | TruffleHog → Syft → Trivy + Grype, comment artifact, status gate | `pull_request`, `push` |
| [`security-scan-comment.yml`](.github/workflows/security-scan-comment.yml) | Posts/updates sticky comment for security-scan | `workflow_run` |
| [`semgrep.yml`](.github/workflows/semgrep.yml) | Semgrep with SC ruleset (+ optional consumer rules / registry packs), comment artifact, status gate | `pull_request`, `push` |
| [`semgrep-comment.yml`](.github/workflows/semgrep-comment.yml) | Posts/updates sticky comment for Semgrep | `workflow_run` |

Scan workflows use `pull_request` (never `pull_request_target`) and run with read-only `GITHUB_TOKEN`. Comment workflows trigger via `workflow_run`, run in base-repo context with `pull-requests: write`, and never read PR code — they consume only the rendered comment artifact. Pattern: [GitHub Security Lab "preventing pwn requests"](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).

## How to consume

Each consumer adds **four** wrapper workflows.

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
  pull-requests: write
  actions: read
jobs:
  comment:
    if: github.event.workflow_run.event == 'pull_request'
    uses: simple-container-com/actions/.github/workflows/security-scan-comment.yml@main
    permissions:
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
    #   consumer-rules: '.semgrep/rules'    # additional rules in your repo
    #   registry-packs: 'p/security-audit'  # comma-separated semgrep registry packs
    #   fail-on-severity: 'ERROR'           # ERROR / WARNING / INFO (default ERROR)
```

### `.github/workflows/semgrep-comment.yml`

```yaml
name: Semgrep Comment
on:
  workflow_run:
    workflows: ["Semgrep"]
    types: [completed]
permissions:
  pull-requests: write
  actions: read
jobs:
  comment:
    if: github.event.workflow_run.event == 'pull_request'
    uses: simple-container-com/actions/.github/workflows/semgrep-comment.yml@main
    permissions:
      pull-requests: write
      actions: read
```

The `workflows: [...]` value MUST match the consumer's wrapper `name:` exactly — a typo silently disables comments.

## Org access (one-time, after first merge)

```bash
gh api -X PUT repos/simple-container-com/actions/actions/permissions/access \
  -f access_level=organization
```

Without this, public consumers calling private reusable workflows / composite actions get "workflow not accessible".

## Standards (mandatory for every change)

These rules are enforced by [`lint.yml`](.github/workflows/lint.yml), [`semgrep-self-test.yml`](.github/workflows/semgrep-self-test.yml), and [`tool-version-sync.yml`](.github/workflows/tool-version-sync.yml). PRs that break them go red.

**Workflows**
- Use `pull_request`, never `pull_request_target`, in any workflow that touches PR code.
- `permissions:` is least-privilege per job; never `write-all`. Comment posting lives in a `workflow_run`-triggered job that does NOT checkout PR code.
- Every `actions/checkout` sets `persist-credentials: false`.
- All `actions/*` references pinned by 40-char commit SHA with a `# vN` trailing comment.

**Composite actions**
- Heavy logic lives in a sibling `.sh`, never inline in `action.yml`. Reason: composite actions are the only way to ship script files to consumer runners from this private repo (consumer's `GITHUB_TOKEN` can't checkout this repo).
- Every `run:` step in a composite action declares `shell: bash`.

**Shell scripts**
- Start with `set -euo pipefail`.
- Validate every env-var input with a regex before passing it to `docker`, `gh`, `jq`, or any other command. Image refs must satisfy `^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$` (`@sha256:<digest>` is **mandatory**).
- Prefer `printf -v` to `eval` for indirect assignment.
- Use `cat -- "$F"` for any path that comes from a variable.
- Capture scanner exit codes; tolerate only the documented "findings present" code (TruffleHog 0/183, Trivy 0, Grype 0, Semgrep 0/1). Anything else fails the job.

**Tool images**
- Every image referenced anywhere in the repo lives in [`versions/Dockerfile`](versions/Dockerfile) as a `FROM image:tag@sha256:<digest> AS <stage>` line. Dependabot's `docker` ecosystem tracks it.
- Adding a new tool: (1) add a `FROM ... AS <stage>` row to `versions/Dockerfile`, (2) add the consumer reference in the relevant `action.yml`/script, (3) add a `[<stage>]='<file>'` row to the `targets` map in [`tools/sync-tool-versions.sh`](tools/sync-tool-versions.sh).
- Bumping a tool: Dependabot opens a PR against `versions/Dockerfile`; pull the branch and run `tools/sync-tool-versions.sh --apply` to propagate; commit; push. CI's `Tool Version Sync` job will go red until the propagation is committed.

**Semgrep rules**
- Every rule has at least one `# ruleid:` and one `# ok:` fixture in [`semgrep-scan/tests/`](semgrep-scan/tests/).
- The full ruleset must produce **zero** findings on the repo itself (excluding `semgrep-scan/{rules,tests}` which are deliberately scan targets / negative cases).
- New rule = new commit that adds rule + fixtures + passes [`semgrep-scan/run-tests.sh`](semgrep-scan/run-tests.sh).

**Secret-scan FP handling — fix at source, exclude only as last resort**
- This actions repo is **public**. Any path pattern listed in a `secret-scan-extra-excludes` value (anywhere in the org) is a hint to attackers about which paths the scanner skips. Default to fixing the source instead.
- Universal detector exclude: `--exclude-detectors=FormBucket`. That detector matches generic Go SDK symbols (`sdk.Bool`, `sdk.BoolPtr`) with extreme FP rate; no SC repo legitimately uses formbucket.com APIs.
- Source-level fixes (preferred): replace placeholder credentials with syntax that defeats the detector regex AND keeps the docs/tests valid. Avoid preserving provider-specific token prefixes (`ghp_`, `sk-`, `xoxb-`), JWT-like multi-part shapes, full PEM armor, or parseable URI userinfo with realistic credential slots. TruffleHog also scans **decoded base64**, so an "innocuous" base64 fixture can still trigger after decoding.
  - URIs: `mongodb+srv://user:pass@host` → `mongodb+srv://<USER>:<PASS>@<host>` (angle brackets break the alphanumeric password match)
  - GCP service-account emails: `name@project.iam.gserviceaccount.com` → `<service-account>@<project>.iam.gserviceaccount.com`
  - Random-looking tokens (Cloudflare / Mailgun / Gitlab): replace value with `<your-token>` literal
- Inline ignore (good for tests with comment syntax): `# trufflehog:ignore` (Python/YAML/shell) or `// trufflehog:ignore` (Go/JS/etc.) at the end of the line tells TruffleHog to skip that line. Confirmed empirically with TruffleHog 3.95. Best fit for test fixtures that need format-preserving values but where a comment is welcome.
- Path exclusion (last resort): `secret-scan-extra-excludes` input on `security-scan.yml`. One regex per line, TruffleHog Go-regex semantics, substring-matched against the full container path. Use only for files that admit no comment syntax (raw OpenSSH key bodies, base64 blobs, etc.).
  ```yaml
  secret-scan-extra-excludes: |
    /testdata/.*\.ssh/test_id_rsa$
  ```
  Default exclusions remain `\.sc/secrets\.yaml` and `\.sc/stacks/[^/]+/secrets\.yaml`.
- Validation rejects lines containing shell-control characters (`;`, `&`, backtick, `$(`) or control bytes. Regex metacharacters are allowed.

## Threat model

Workflows are designed assuming the consumer is a **public repo** receiving PRs from external forks.

- Untrusted PR code is never executed (no `npm install`, no `go build`, no test runs). Tools are file/AST/SBOM analyzers only.
- Scan jobs use `pull_request`; fork PRs receive a read-only `GITHUB_TOKEN` and no org secrets.
- PR-controlled strings reach shell only via `env:` and pass a regex check before use.
- Privileged comment workflow derives the PR number from `github.event.workflow_run.pull_requests[0]` (with a `commits/{sha}/pulls` API fallback for fork PRs); marker is hardcoded; freshness check skips posting if the PR head has moved past our scan SHA.
- All `uses:` first-party. All tool images pinned tag + `@sha256:`.
- Every `docker run` validates its image ref before the call.
- Comment posting uses `jq -n --rawfile body | gh api --input -` (no argv length limit, no double-escape) and caps body at 64 KiB.

## Custom Semgrep rules

[`semgrep-scan/rules/shell.yml`](semgrep-scan/rules/shell.yml) — 5 rules

| ID | Severity | Detects |
|---|---|---|
| `shell-eval-usage` | ERROR | `eval` (incl. `command eval` / `builtin eval` / after `;` `&` `|`) |
| `shell-curl-pipe-to-shell` | ERROR | `curl ... | sh`, `| sudo bash`, `bash <(curl …)`, `sh -c "$(curl …)"` |
| `shell-rm-rf-root` | ERROR | `rm -rf /`, `rm -rf "${VAR}/"`, `rm -rf -- /`, `rm -fr /`, `rm -rf "$X"/*` |
| `shell-source-of-variable-path` | WARNING | `source $VAR` / `. ${VAR}/...`, with or without quotes |
| `shell-cat-without-double-dash` | INFO | `cat "$F"` (skips runner-owned paths like `$GITHUB_OUTPUT`) |

[`semgrep-scan/rules/github-actions.yml`](semgrep-scan/rules/github-actions.yml) — 15 rules

| ID | Severity | Detects |
|---|---|---|
| `gha-script-injection-via-github-event` | ERROR | `${{ github.event.* }}` in `run:` (single + multi-line, step-bounded) |
| `gha-script-injection-via-attacker-controlled-context` | ERROR | `head_ref`, head commit message, issue/PR title/body, comment/review body, `workflow_run.head_*`, `inputs.*`, `ref_name` in `run:` |
| `gha-pull-request-target-with-pr-head-checkout` | ERROR | Classic pwn-request: `pull_request_target` + `actions/checkout` of the PR head |
| `gha-unpinned-third-party-action` | WARNING | Third-party action pinned by tag (catches quoted variants) |
| `gha-unpinned-first-party-action` | INFO | `actions/*` pinned by tag (defence-in-depth) |
| `gha-permissions-write-all` | ERROR | Top-level `permissions: write-all` (incl. quoted) |
| `gha-checkout-persist-credentials-true` | ERROR | `actions/checkout` with explicit `persist-credentials: true` (scoped to checkout, step-bounded) |
| `gha-self-hosted-runner` | WARNING | `runs-on: self-hosted` — single-string, inline-array, or block-list |
| `gha-secret-echoed` | ERROR | `echo`/`printf`/`tee`/heredoc that writes a secret to a log |
| `gha-cache-key-attacker-controlled` | ERROR | `actions/cache` key built from PR/issue/comment/inputs context |
| `gha-security-job-continue-on-error` | ERROR | `continue-on-error: true` on a security-named job |
| `gha-workflow-run-checkout-head-sha` | ERROR | Privileged `workflow_run` job that checks out the upstream head SHA |
| `gha-reusable-workflow-self-call` | WARNING | `uses: ./.github/workflows/<self>` recursion |
| `gha-security-job-permanently-disabled` | ERROR | `if: false` on a security-named job |
| `gha-comment-body-via-argv` | WARNING | `gh ... --body "$(cat …)"` — switch to `jq -n --rawfile body … | gh api --input -` |

## Verify locally

```bash
docker run --rm -v "$PWD:/repo:ro" -w /repo rhysd/actionlint:1.7.12 -color   # workflows
docker run --rm -v "$PWD:/mnt:ro" -w /mnt koalaman/shellcheck:v0.11.0 \
  --severity=warning $(find . -name '*.sh' -not -path './.git/*' -not -path './semgrep-scan/tests/*')
./tools/sync-tool-versions.sh --check
./semgrep-scan/run-tests.sh
```

## Roadmap

- Cut a `v1` tag and migrate internal `@main` references + consumer pins
- Cosign / SLSA artifact signing + signature verification on the consume side
- Wire private SC repos (`forge`, `forge-conductor`, `cloud`, …) once the public-repo design has run for a release cycle or two
- More Semgrep rules: artifact-name collision detection, secrets in non-`run:` action inputs (`with: script:`), allowlist of registry packs
