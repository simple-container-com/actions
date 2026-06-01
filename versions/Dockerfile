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

FROM ghcr.io/trufflesecurity/trufflehog:3.95.3@sha256:9cc33bb080cac0efbbf228a17667172875b529eeeab01efcc4697adfb55f568a AS trufflehog
FROM ghcr.io/anchore/syft:v1.44.0@sha256:86fde6445b483d902fe011dd9f68c4987dd94e07da1e9edc004e3c2422650de6 AS syft
FROM public.ecr.aws/aquasecurity/trivy:0.70.0@sha256:be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e AS trivy
FROM ghcr.io/anchore/grype:v0.112.0@sha256:391bfda62888fb4e98ff5c4c81598f7431a3c1eac3f8519d69d1ff00df247c1d AS grype
FROM semgrep/semgrep:1.161.0@sha256:326e5f41cc972bb423b764a14febbb62bbad29ee1c01820805d077dd868fea48 AS semgrep
FROM rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS actionlint
FROM koalaman/shellcheck:v0.11.0@sha256:61862eba1fcf09a484ebcc6feea46f1782532571a34ed51fedf90dd25f925a8d AS shellcheck
