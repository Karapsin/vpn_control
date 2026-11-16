#!/usr/bin/env python3
"""A dev push reuses its exact-SHA ci/* result; nothing else skips, and the publisher still finds packages."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_run_reuse as subject  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
REQUIRED = ("fast-checks.yml", "android-release.yml", "linux-desktop.yml", "windows-desktop.yml", "macos-desktop.yml")
PRESERVED = ROOT / "agent_tools/tests/fixtures/agent_ci_shards/ci-gate.workflow.before.yml"
SHA = "a" * 40
GATE = "needs.reuse.outputs.skip != 'true'"
DEV_PUSH = "if: github.event_name == 'push' && github.ref == 'refs/heads/dev'"
REUSE_JOB = """  reuse:
    name: Reuse ci/* result
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions:
      actions: read
      contents: read
    outputs:
      skip: ${{ steps.reuse.outputs.skip }}
    steps:
      - name: Checkout reuse policy
        if: github.event_name == 'push' && github.ref == 'refs/heads/dev'
        uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          sparse-checkout: scripts/ci_run_reuse.py
          sparse-checkout-cone-mode: false

      - name: Find a successful ci/* run of this workflow for this SHA
        id: reuse
        if: github.event_name == 'push' && github.ref == 'refs/heads/dev'
        env:
          GH_TOKEN: ${{ github.token }}
        run: python3 scripts/ci_run_reuse.py

"""


def jobs(text):
    body = text.split("\njobs:\n", 1)[1]
    return {match.group(1): match.group(2) for match in
            re.finditer(r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", body, re.M | re.S)}


def header(job):
    return job.split("    steps:\n", 1)[0] if "    steps:\n" in job else job


def gate_problems(name, text):
    """Problems that let a reused dev push still run expensive jobs, or skip anything else."""
    found = jobs(text)
    if "\njobs:\n" + REUSE_JOB not in text:
        return [f"{name}: the first job must be the exact ci/* reuse job"]
    problems = []
    for job, body in found.items():
        if job == "reuse":
            continue
        head = header(body)
        condition = (re.search(r"(?m)^    if: (.+)$", head) or [None, ""])[1]
        if "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/dev'" in condition:
            continue  # Dispatch-only fixture jobs never run on a push.
        needs = (re.search(r"(?m)^    needs: (.+)$", head) or [None, ""])[1]
        if needs != "reuse" and not re.fullmatch(r"\[reuse, [^\]]+\]", needs):
            problems.append(f"{name}:{job}: must need the reuse job")
        if not (condition == GATE or condition.startswith(GATE + " && (") or condition == "always() && " + GATE):
            problems.append(f"{name}:{job}: must run only when the reuse job did not skip")
    return problems


class DecisionTests(unittest.TestCase):
    ENV = {"GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/dev", "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "9",
           "GITHUB_REPOSITORY": "owner/repo", "GH_TOKEN": "token",
           "GITHUB_WORKFLOW_REF": "owner/repo/.github/workflows/fast-checks.yml@refs/heads/dev"}

    @staticmethod
    def run_row(**changes):
        row = {"id": 5, "head_sha": SHA, "event": "push", "status": "completed", "conclusion": "success",
               "head_branch": "ci/aaaaaaaaaaaa", "html_url": "https://example.invalid/run/5"}
        row.update(changes)
        return row

    def decide(self, rows, **environment):
        calls = []

        def fetch(env, workflow):
            calls.append(workflow)
            return rows
        return subject.decide({**self.ENV, **environment}, fetch=fetch), calls

    def test_dev_push_skips_only_after_an_exact_sha_ci_branch_success_of_the_same_workflow(self):
        decision, calls = self.decide([self.run_row()])
        self.assertEqual("true", decision["skip"])
        self.assertEqual(["fast-checks.yml"], calls)
        self.assertIn("ci/aaaaaaaaaaaa run 5", decision["reason"])

    def test_every_other_run_or_state_runs_the_jobs(self):
        cases = {
            "dev branch run": [self.run_row(head_branch="dev")],
            "other SHA": [self.run_row(head_sha="b" * 40)],
            "failed": [self.run_row(conclusion="failure")],
            "in progress": [self.run_row(status="in_progress", conclusion=None)],
            "dispatch": [self.run_row(event="workflow_dispatch")],
            "itself": [self.run_row(id=9)],
            "feature branch": [self.run_row(head_branch="feature/ci/x")],
            "none": [],
        }
        for label, rows in cases.items():
            with self.subTest(label):
                self.assertEqual("false", self.decide(rows)[0]["skip"])
        for environment in ({"GITHUB_REF": "refs/heads/ci/aaaaaaaaaaaa"}, {"GITHUB_REF": "refs/heads/main"},
                            {"GITHUB_EVENT_NAME": "workflow_dispatch"}, {"GITHUB_EVENT_NAME": "pull_request"}):
            with self.subTest(environment=environment):
                decision, calls = self.decide([self.run_row()], **environment)
                self.assertEqual(("false", []), (decision["skip"], calls))

    def test_only_the_newest_ci_run_of_the_sha_decides(self):
        # An older green ci/* run never hides a newer red, cancelled or unfinished one.
        newer = {
            "red": self.run_row(id=7, conclusion="failure"),
            "cancelled": self.run_row(id=7, conclusion="cancelled"),
            "re-run in progress": self.run_row(id=7, status="in_progress", conclusion=None),
            "queued": self.run_row(id=7, status="queued", conclusion=None),
        }
        for label, row in newer.items():
            for order in ((self.run_row(id=5), row), (row, self.run_row(id=5))):
                with self.subTest(label, order=[run["id"] for run in order]):
                    decision = self.decide(list(order))[0]
                    self.assertEqual("false", decision["skip"])
                    self.assertIn("newest ci/* push run", decision["reason"])
        # The newest ci/* run wins; dev runs, other SHAs and the run itself do not count.
        rows = [self.run_row(id=3, conclusion="failure"), self.run_row(id=8),
                self.run_row(id=9, conclusion="failure"), self.run_row(id=11, head_branch="dev", conclusion="failure"),
                self.run_row(id=12, head_sha="b" * 40, conclusion="failure")]
        decision = self.decide(rows)[0]
        self.assertEqual("true", decision["skip"])
        self.assertIn("run 8", decision["reason"])

    def test_lookup_failure_runs_the_jobs(self):
        def fail(env, workflow):
            raise OSError("network down")
        decision = subject.decide(dict(self.ENV), fetch=fail)
        self.assertEqual("false", decision["skip"])
        self.assertIn("reuse lookup failed: OSError", decision["reason"])
        self.assertEqual("false", subject.decide({**self.ENV, "GITHUB_WORKFLOW_REF": "bogus"}, fetch=fail)["skip"])

    def test_main_writes_the_step_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            with mock.patch.dict("os.environ", {**self.ENV, "GITHUB_OUTPUT": str(output)}, clear=True), \
                    mock.patch.object(subject, "fetch_runs", return_value=[self.run_row()]):
                self.assertEqual(0, subject.main())
            self.assertEqual("skip=true\n", output.read_text(encoding="utf-8"))

    def test_query_names_the_exact_workflow_sha_and_every_push_run_state(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, *args):
                return b'{"workflow_runs": []}'

        def urlopen(request, timeout):
            captured["url"], captured["auth"] = request.full_url, request.get_header("Authorization")
            return Response()
        with mock.patch.object(subject.urllib.request, "urlopen", urlopen):
            self.assertEqual([], subject.fetch_runs(dict(self.ENV), "linux-desktop.yml"))
        self.assertEqual("https://api.github.com/repos/owner/repo/actions/workflows/linux-desktop.yml/runs?"
                         f"event=push&head_sha={SHA}&per_page=100", captured["url"])
        self.assertEqual("Bearer token", captured["auth"])


class WorkflowGateTests(unittest.TestCase):
    def test_required_workflows_gate_every_push_job_on_the_reuse_job(self):
        problems = []
        for name in REQUIRED:
            problems += gate_problems(name, (WORKFLOWS / name).read_text(encoding="utf-8"))
        self.assertEqual([], problems)

    def test_reuse_only_looks_up_on_dev_pushes_and_cannot_write(self):
        self.assertEqual(2, REUSE_JOB.count(DEV_PUSH))
        self.assertNotIn("write", REUSE_JOB)
        for name in sorted(path.name for path in WORKFLOWS.glob("*.yml")):
            text = (WORKFLOWS / name).read_text(encoding="utf-8")
            self.assertEqual(name in REQUIRED, "scripts/ci_run_reuse.py" in text, name)

    def test_coverage_gate_still_verifies_shards_whenever_they_run(self):
        coverage = header(jobs((WORKFLOWS / "fast-checks.yml").read_text(encoding="utf-8"))["agent-test-coverage"])
        self.assertIn("    if: always() && " + GATE + "\n", coverage)
        self.assertIn("    needs: [reuse, agent-tests-shard-0,", coverage)

    def test_a34e07cb_fast_checks_reran_every_job_on_the_dev_fast_forward(self):
        # RED: the preserved workflow has no reuse job, so dev repeats the ci/* run.
        self.assertEqual(["fast-checks.yml: the first job must be the exact ci/* reuse job"],
                         gate_problems("fast-checks.yml", PRESERVED.read_text(encoding="utf-8")))


def publisher_candidates(text, rows):
    """Run the publisher's own --jq program, as bash expands it, over one runs page."""
    line = next(line for line in text.splitlines() if '--jq ".workflow_runs | map(select(.head_sha == ' in line)
    quoted = line.split("--jq ", 1)[1].rstrip().removesuffix(")")  # closes the $( ... ) substitution
    program = subprocess.run(["bash", "-c", "printf '%s' " + quoted], env={**os.environ, "TARGET_SHA": SHA},
                             capture_output=True, text=True, check=True).stdout
    result = subprocess.run(["jq", "-r", program], input=json.dumps({"workflow_runs": rows}),
                            capture_output=True, text=True, check=True)
    return [int(value) for value in result.stdout.split()]


class PublisherTests(unittest.TestCase):
    # The publisher runs on ubuntu; Windows hygiene may resolve bash to the WSL launcher.
    @unittest.skipIf(os.name == "nt" or not shutil.which("jq") or not shutil.which("bash"), "POSIX bash and jq")
    def test_publisher_takes_only_the_unbroken_successes_from_the_newest_run(self):
        text = (WORKFLOWS / "release-publish.yml").read_text(encoding="utf-8")
        run = lambda identifier, conclusion="success", status="completed", sha=SHA: {
            "id": identifier, "head_sha": sha, "status": status, "conclusion": conclusion}
        cases = {
            # A reused dev run (no artifacts) above its green ci/* run: both eligible, newest first.
            "reused": ([run(5), run(9)], [9, 5]),
            # An older green run never stands in for a newer red, cancelled or unfinished one.
            "newer red": ([run(5), run(9, "failure")], []),
            "newer cancelled": ([run(5), run(9, "cancelled")], []),
            "newer in progress": ([run(5), run(9, None, "in_progress")], []),
            "red between": ([run(3), run(5, "failure"), run(9)], [9]),
            "other SHA ignored": ([run(5), run(9, "failure", sha="b" * 40)], [5]),
            "none": ([], []),
        }
        for label, (rows, expected) in cases.items():
            with self.subTest(label):
                self.assertEqual(expected, publisher_candidates(text, rows))

    def test_publisher_downloads_each_package_from_a_successful_run_that_has_it(self):
        text = (WORKFLOWS / "release-publish.yml").read_text(encoding="utf-8")
        self.assertIn("head_sha=$TARGET_SHA", text)
        self.assertNotIn("status=completed&head_sha", text)
        self.assertIn('\\$run.conclusion == \\"success\\"', text)
        self.assertIn("sort_by(.id) | reverse | reduce .[] as", text)
        self.assertNotIn("| last | .id\")\n            [[ -n \"$run_id\"", text)
        self.assertIn('actions/runs/$candidate/artifacts?name=$artifact', text)
        self.assertIn("select(.expired == false)", text)
        self.assertLess(text.index("artifacts?name=$artifact"), text.index('gh run download "$run_id"'))


if __name__ == "__main__":
    unittest.main()
