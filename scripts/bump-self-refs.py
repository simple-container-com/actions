#!/usr/bin/env python3
"""Bump SELF-REF SHAs in this repo's workflow / composite-action files.

When a sibling action in this same repo is referenced by SHA with a
`# SELF-REF` annotation, this script rewrites the SHA to a target value
(usually the current main HEAD).

Designed to be invoked from `.github/workflows/bump-self-refs.yml`
after a SELF-REF-target file changes on main; opens or updates a
`chore(self-refs)` PR via `gh` CLI.

Required env vars:
    NEW_SHA            Target commit SHA (40 hex chars).
    GH_TOKEN           gh CLI auth token (for the `git push` over HTTPS
                       and `gh pr create`).
    GITHUB_REPOSITORY  owner/repo slug for the git remote URL.

Optional env vars:
    DRY_RUN            When set to a truthy value, skip the git commit /
                       push / gh-pr-create steps. Useful for local
                       testing — just verifies the rewrite logic.

Exit codes:
    0   Success: PR opened/updated, OR no SELF-REFs needed bumping.
    1   Bad input (e.g. NEW_SHA not 40 hex chars).
    2   Required env var missing.
    >2  git/gh subprocess error.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys


SHA_RE = re.compile(r"[a-f0-9]{40}")

# Pattern for a SELF-REF line. Matches:
#     uses:  <one or more whitespace>
#     simple-container-com/actions/<path-without-@-or-whitespace>
#     @<40 hex>
#     <optional whitespace>
#     # ...SELF-REF...   (trailing comment, preserved verbatim)
SELF_REF_RE = re.compile(
    r"(uses:\s+simple-container-com/actions/[^@\s]+@)"
    r"([a-f0-9]{40})"
    r"(\s*#[^\n]*SELF-REF[^\n]*)",
    re.MULTILINE,
)

BRANCH = "chore/bump-self-refs"


def fatal(code: int, msg: str) -> None:
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(code)


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess[str]:
    """Run a subprocess; surface stderr inline; default check=True."""
    kw.setdefault("check", True)
    kw.setdefault("text", True)
    return subprocess.run(cmd, **kw)


def find_self_ref_files() -> list[pathlib.Path]:
    """Return all yml/yaml files in the repo that contain a SELF-REF marker."""
    result = subprocess.run(
        ["grep", "-rlE", "SELF-REF",
         "--include=*.yml", "--include=*.yaml", "."],
        capture_output=True, text=True, check=False,
    )
    return [pathlib.Path(p) for p in result.stdout.splitlines() if p]


def rewrite_file(path: pathlib.Path, new_sha: str) -> int:
    """Rewrite SELF-REF SHAs in `path` to `new_sha`. Returns # of replacements."""
    text = path.read_text()
    new_text, n = SELF_REF_RE.subn(
        lambda m: m.group(1) + new_sha + m.group(3),
        text,
    )
    if n and new_text != text:
        path.write_text(new_text)
    return n


def open_or_update_pr(new_sha: str, short_sha: str) -> None:
    """gh CLI: open a chore(self-refs) PR, or refresh title if one exists."""
    existing = run(
        ["gh", "pr", "list", "--head", BRANCH, "--base", "main",
         "--json", "number", "--jq", ".[0].number // empty"],
        capture_output=True,
    ).stdout.strip()

    title = f"chore(self-refs): bump SELF-REF SHAs to {short_sha}"

    if not existing:
        body = (
            f"Auto-bump by `.github/workflows/bump-self-refs.yml` "
            f"triggered by commit `{new_sha}`.\n\n"
            "The SELF-REF SHAs in this repo's reusable workflows + "
            "composite actions are rewritten to point at the latest "
            "`main` HEAD. Merging this PR re-aligns the inner pin "
            "chain in one click. See "
            "[`scripts/bump-self-refs.py`](../blob/main/scripts/bump-self-refs.py) "
            "for the rewrite logic.\n\n"
            f"This PR uses a fixed branch (`{BRANCH}`) and is "
            "force-pushed on every run, so it always reflects the "
            "latest `main` HEAD even after several SELF-REF-target "
            "commits land back-to-back."
        )
        run([
            "gh", "pr", "create",
            "--title", title,
            "--body", body,
            "--base", "main",
            "--head", BRANCH,
            "--label", "dependencies",
            "--label", "automated",
        ])
    else:
        run([
            "gh", "pr", "edit", existing,
            "--title", title,
        ])
        print(f"Updated existing PR #{existing}")


def main() -> None:
    new_sha = os.environ.get("NEW_SHA")
    if not new_sha:
        fatal(2, "NEW_SHA env var is required")
    if not SHA_RE.fullmatch(new_sha):
        fatal(1, f"Invalid NEW_SHA (need 40 hex chars): {new_sha}")
    short_sha = new_sha[:10]
    dry_run = bool(os.environ.get("DRY_RUN"))

    files = find_self_ref_files()
    if not files:
        print("No SELF-REF markers found; nothing to bump.")
        return
    print(f"Scanning {len(files)} file(s) for SELF-REF lines:")
    for f in files:
        print(f"  - {f}")

    for f in files:
        n = rewrite_file(f, new_sha)
        if n:
            print(f"BUMPED {f}: {n} ref(s)")

    # Has anything actually changed on disk?
    diff_rc = subprocess.run(["git", "diff", "--quiet"], check=False).returncode
    if diff_rc == 0:
        print("SELF-REFs already at the target SHA; no bump needed.")
        return

    print("Files modified:")
    run(["git", "diff", "--name-only"])

    if dry_run:
        print("DRY_RUN set — skipping git commit / push / gh pr create.")
        return

    gh_token = os.environ.get("GH_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not gh_token or not repo:
        fatal(2, "GH_TOKEN and GITHUB_REPOSITORY required for non-DRY_RUN")

    run(["git", "config", "user.name", "github-actions[bot]"])
    run(["git", "config", "user.email",
         "41898282+github-actions[bot]@users.noreply.github.com"])
    run(["git", "checkout", "-b", BRANCH])
    run(["git", "add", "-A"])
    run(["git", "commit", "-m",
         f"chore(self-refs): bump SELF-REF SHAs to {short_sha}"])

    # Use a token-authenticated remote so the push works without ssh.
    run(["git", "remote", "set-url", "origin",
         f"https://x-access-token:{gh_token}@github.com/{repo}.git"])
    run(["git", "push", "--force-with-lease", "origin", BRANCH])

    open_or_update_pr(new_sha, short_sha)


if __name__ == "__main__":
    main()
