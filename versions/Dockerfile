# Tool image catalogue.
#
# This file is NEVER built (`docker build`). Every image listed here is
# consumed at runtime via `docker run` from one of the composite actions
# in this repo. The file exists so that:
#
#   1. There is a single place to audit which third-party tool images we
#      depend on, and at which exact bytes (tag + sha256 digest).
#
#   2. Dependabot's `docker` ecosystem can scan it and open auto-bump PRs.
#      Dependabot does not parse `image:tag@sha256:...` strings inside
#      shell scripts or action.yml `default:` values, so the FROMs here
#      are the ONLY thing it sees.
#
# When Dependabot opens a PR bumping a FROM, the new pin must be
# propagated to the consumer files or the `tool-version-sync` CI job
# fails. Two ways to do that, neither needing a local clone of a
# Dependabot branch:
#
#   * Run the `Tool Version Autosync` workflow from the Actions tab and
#     give it the PR's branch name. It propagates and pushes for you.
#   * Or run `tools/sync-tool-versions.sh --apply` on the branch
#     locally, then commit and push.
#
# The script does an in-place literal-string replace via Python.

FROM ghcr.io/trufflesecurity/trufflehog:3.97.0@sha256:ff4c95e9df7d645daf2140e3ca1039031c63106268d5fbb25feb43ceca1bcc33 AS trufflehog
FROM ghcr.io/anchore/syft:v1.51.0@sha256:678bfa565b60f747aac0f8e964fe5588a24445b8d0a480e91f6efd70020dfbb0 AS syft
FROM public.ecr.aws/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy
FROM ghcr.io/anchore/grype:v0.117.0@sha256:ddf9e9f204049f3a4a0955ef70873cabab6a31432125ad4f20a490b54950a253 AS grype
FROM semgrep/semgrep:1.174.0@sha256:f1f7b71861c7b28b6e0f661225a2c4f58a484f5d0f182465c6d6b3b22f972ade AS semgrep
FROM rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS actionlint
FROM koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d AS shellcheck
