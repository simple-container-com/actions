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
# When Dependabot opens a PR bumping a FROM, the `tool-version-sync`
# CI job will fail until the new pin is propagated to the consumer
# files. Run `tools/sync-tool-versions.sh --apply` on the PR branch
# to do that (in-place literal-string replace via Python), commit,
# push.

FROM ghcr.io/trufflesecurity/trufflehog:3.95.9@sha256:59b244249d1a1aef4baa24fe73d3c931616264482580d806d77f6c74d26b3e42 AS trufflehog
FROM ghcr.io/anchore/syft:v1.48.0@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c AS syft
FROM public.ecr.aws/aquasecurity/trivy:0.72.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f AS trivy
FROM ghcr.io/anchore/grype:v0.116.0@sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821 AS grype
FROM semgrep/semgrep:1.169.0@sha256:2b33f46ba66cf8cc2ad59ccfa7d22951fd00c632c38f1339e84ec8e6e641a942 AS semgrep
FROM rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS actionlint
FROM koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d AS shellcheck
