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
FROM ghcr.io/anchore/syft:v1.46.0@sha256:473a60e3a58e29aca3aedb3e99e787bb4ef273917e44d10fcbea4330a07320bb AS syft
FROM public.ecr.aws/aquasecurity/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e AS trivy
FROM ghcr.io/anchore/grype:v0.115.0@sha256:decd87500a90c1e4faa1706f77b0b2cbc1d2f9364e976f1898ce9037de09cc3a AS grype
FROM semgrep/semgrep:1.168.0@sha256:59fbed6127ea7c5dde3ba6a85142733bb20ea9aaa36120c953904f1539aaf66e AS semgrep
FROM rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS actionlint
FROM koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d AS shellcheck
