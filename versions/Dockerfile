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

FROM ghcr.io/trufflesecurity/trufflehog:3.97.4@sha256:562bc231afa9de3d04de44cfe624252b08207de1fc3cebc5e7ed92bed7f279e4 AS trufflehog
FROM ghcr.io/anchore/syft:v1.51.1@sha256:95fe0835e5bebc6f8b1f8acef68d47d63d594ef4c0f25c097ff853b23cbac74c AS syft
FROM public.ecr.aws/aquasecurity/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969 AS trivy
FROM ghcr.io/anchore/grype:v0.118.0@sha256:8a93fc48da96bd6ec5981279d099b69de11541dc68fdf222fb9161f8ff284af7 AS grype
FROM semgrep/semgrep:1.176.1@sha256:34ab619bf1391a24bfda3f05debd0d8a6ce3093c2d5f9d39cfc00f83c1397823 AS semgrep
FROM rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS actionlint
FROM koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d AS shellcheck
