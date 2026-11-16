#!/usr/bin/env python3
"""Decide whether a `dev` push run of a required workflow reuses a ci/* result.

RELEASE-001 gates a candidate on its own `ci/<sha12>` branch, then fast-forwards
`dev` to the same SHA, which triggers every required push workflow again. The
first job of each required workflow runs this script. On a `dev` push it asks
the Actions API whether this same workflow file already has a successful push
run for this exact SHA on a `ci/*` branch. If so it writes `skip=true` to
`$GITHUB_OUTPUT`; every expensive job needs this job and runs only when skip is
not true, so the run stays green without repeating the checks.

Every other event or ref, no matching run, or any API failure writes
`skip=false`, so the jobs run. Reuse never weakens a check: a skipped run is
green only because the identical source already passed the identical workflow.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

CI_BRANCH_PREFIX = "ci/"
DEV_REF = "refs/heads/dev"


def workflow_file(workflow_ref: str) -> str:
    """`owner/repo/.github/workflows/name.yml@refs/heads/dev` -> `name.yml`."""
    path = workflow_ref.split("@", 1)[0]
    marker = "/.github/workflows/"
    if marker not in path or not path.endswith((".yml", ".yaml")):
        raise ValueError(f"unexpected GITHUB_WORKFLOW_REF: {workflow_ref!r}")
    return path.rsplit("/", 1)[1]


def matching_run(runs: list[dict], sha: str, run_id: str) -> dict | None:
    """Return a successful ci/* push run of this workflow for exactly this SHA."""
    for run in runs:
        if (run.get("head_sha") == sha and run.get("event") == "push"
                and run.get("status") == "completed" and run.get("conclusion") == "success"
                and str(run.get("head_branch") or "").startswith(CI_BRANCH_PREFIX)
                and str(run.get("id")) != str(run_id)):
            return run
    return None


def fetch_runs(environment: dict[str, str], workflow: str) -> list[dict]:
    api = environment.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    query = urllib.parse.urlencode({"event": "push", "status": "success",
                                    "head_sha": environment["GITHUB_SHA"], "per_page": "100"})
    url = f"{api}/repos/{environment['GITHUB_REPOSITORY']}/actions/workflows/{workflow}/runs?{query}"
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {environment['GH_TOKEN']}",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response).get("workflow_runs", [])


def decide(environment: dict[str, str], fetch=None) -> dict[str, str]:
    if environment.get("GITHUB_EVENT_NAME") != "push" or environment.get("GITHUB_REF") != DEV_REF:
        return {"skip": "false", "reason": "not a dev push"}
    try:
        workflow = workflow_file(environment["GITHUB_WORKFLOW_REF"])
        run = matching_run((fetch or fetch_runs)(environment, workflow), environment["GITHUB_SHA"],
                           environment.get("GITHUB_RUN_ID", ""))
    except Exception as error:  # Unknown reuse state runs every job.
        return {"skip": "false", "reason": f"reuse lookup failed: {type(error).__name__}: {error}"}
    if run is None:
        return {"skip": "false", "reason": "no successful ci/* push run of this workflow for this SHA"}
    return {"skip": "true", "reason": f"reusing {run.get('head_branch')} run {run.get('id')} {run.get('html_url', '')}".rstrip()}


def main() -> int:
    decision = decide(dict(os.environ))
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        raise SystemExit("GITHUB_OUTPUT is required")
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(f"skip={decision['skip']}\n")
    if decision["reason"].startswith("reuse lookup failed"):
        print(f"::warning::{decision['reason']}", file=sys.stderr)
    print("[vpn-control] ci/* reuse " + json.dumps(decision, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
