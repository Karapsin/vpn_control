#!/usr/bin/env python3
"""First step of the `Gradle Cache Warm` workflow (.github/workflows/gradle-cache-warm.yml).

Run in a full checkout of `dev`. It refuses any ref other than the repository's
default branch, because only default-branch caches are readable from other
branches, and resolves the commit to build: the `dev_sha` input or, when it is
empty, the current `dev` tip. The commit must be contained in `dev`. It writes
`sha=<commit>` to `$GITHUB_OUTPUT` for the workflow's build jobs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = "gradle-cache-warm.yml"
INPUT = "dev_sha"
_SHA = re.compile(r"[0-9a-f]{40}\Z")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()


def default_branch(environment: dict[str, str]) -> str:
    output = subprocess.run(["gh", "api", f"repos/{environment['GITHUB_REPOSITORY']}", "--jq", ".default_branch"],
                            check=True, capture_output=True, text=True).stdout.strip()
    if not output:
        raise SystemExit("Could not read the repository default branch.")
    return output


def resolve(environment: dict[str, str], *, branch=default_branch, run_git=git) -> str:
    expected = "refs/heads/" + branch(environment)
    if environment.get("GITHUB_REF") != expected:
        raise SystemExit(f"Gradle Cache Warm writes the shared cache only from {expected}; "
                         f"this run is on {environment.get('GITHUB_REF')!r}.")
    requested = (environment.get("REQUESTED_SHA") or "").strip().lower()
    sha = requested or run_git("rev-parse", "HEAD")
    if not _SHA.fullmatch(sha):
        raise SystemExit(f"{INPUT} must be a full 40-character commit SHA: {sha!r}")
    try:
        run_git("merge-base", "--is-ancestor", sha, "HEAD")
    except subprocess.CalledProcessError:
        raise SystemExit(f"{sha} is not contained in dev.") from None
    return sha


def main() -> int:
    sha = resolve(dict(os.environ))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(f"sha={sha}\n")
    print("[vpn-control] Gradle cache warm " + json.dumps({"sha": sha}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
