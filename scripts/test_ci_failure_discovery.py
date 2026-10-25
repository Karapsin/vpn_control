#!/usr/bin/env python3
"""TEST-006 RED/GREEN: required CI jobs keep reporting after a failed check."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BEFORE = ROOT / "scripts/testdata/ci-failure-discovery"
SPEC = importlib.util.spec_from_file_location("check_ci_failure_discovery", ROOT / "scripts/check_ci_failure_discovery.py")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


def workflow(steps: str, job_if: str = "") -> str:
    condition = f"    if: {job_if}\n" if job_if else ""
    return f"name: Sample\non: push\njobs:\n  sample:\n    runs-on: ubuntu-latest\n{condition}    steps:\n{steps}"


class CiFailureDiscoveryTests(unittest.TestCase):
    def test_whole_before_workflows_hide_later_checks_current_required_workflows_report_all(self):
        required = policy.required_workflows(ROOT)
        self.assertEqual({"fast-checks.yml", "android-release.yml", "linux-desktop.yml", "windows-desktop.yml", "macos-desktop.yml"},
                         {path.name for path in required})
        for path in required:
            with self.subTest(workflow=path.name):
                before = policy.violations((BEFORE / path.name.replace(".yml", ".before.yml")).read_text(), path.name)
                self.assertTrue(any("an earlier failed check would skip this step" in problem for problem in before))
                self.assertEqual([], policy.violations(path.read_text(encoding="utf-8"), path.name))

    def test_every_step_after_the_first_check_needs_an_explicit_continuation(self):
        steps = ("      - name: Checkout\n        uses: actions/checkout@v4\n"
                 "      - name: Check first\n        run: ./first\n"
                 "      - name: Set up JDK 17\n        uses: actions/setup-java@v4\n"
                 "      - name: Check second\n        run: ./second\n")
        problems = policy.violations(workflow(steps))
        self.assertEqual(["workflow:sample:Set up JDK 17: an earlier failed check would skip this step",
                          "workflow:sample:Check second: an earlier failed check would skip this step"], problems)
        continued = steps.replace("      - name: Set up JDK 17\n", "      - name: Set up JDK 17\n        if: ${{ !cancelled() }}\n")
        continued = continued.replace("      - name: Check second\n", "      - name: Check second\n        if: always()\n")
        self.assertEqual([], policy.violations(workflow(continued)))

    def test_consumer_conditions_name_only_an_earlier_step(self):
        steps = ("      - name: Check first\n        run: ./first\n"
                 "      - name: Upload\n        if: ${{ !cancelled() && steps.build.outcome == 'success' }}\n        uses: actions/upload-artifact@v4\n"
                 "      - name: Build\n        id: build\n        if: ${{ !cancelled() }}\n        run: ./build\n")
        self.assertEqual(["workflow:sample:Upload: condition references a missing or later step build"],
                         policy.violations(workflow(steps)))

    def test_multi_task_gradle_invocations_continue_past_a_failed_task(self):
        steps = "      - name: Run tests\n        run: ./gradlew :a:test :b:test\n"
        self.assertEqual(["workflow:sample:Run tests: multi-task Gradle invocation without --continue: gradlew :a:test :b:test"],
                         policy.violations(workflow(steps)))
        for allowed in ("./gradlew --continue :a:test :b:test", "./gradlew :a:test", ".\\gradlew.bat --continue clean build"):
            with self.subTest(command=allowed):
                self.assertEqual([], policy.violations(workflow("      - name: Run tests\n        run: " + allowed + "\n")))

    def test_dispatch_only_jobs_are_outside_the_push_policy(self):
        steps = "      - name: Check first\n        run: ./first\n      - name: Check second\n        run: ./second\n"
        self.assertTrue(policy.violations(workflow(steps)))
        self.assertEqual([], policy.violations(workflow(steps, "github.event_name == 'workflow_dispatch' && inputs.base != ''")))

    def test_folded_and_literal_run_blocks_keep_their_commands(self):
        steps = ("      - name: Check first\n        run: >-\n          ./gradlew\n          :a:test\n          :b:test\n"
                 "      - name: Check second\n        if: ${{ !cancelled() }}\n        run: |\n          echo one\n          echo two\n")
        jobs = policy.workflow_jobs(workflow(steps))
        self.assertEqual("./gradlew :a:test :b:test\n", jobs["sample"]["steps"][0]["run"])
        self.assertEqual("echo one\necho two\n", jobs["sample"]["steps"][1]["run"])
        self.assertEqual(["workflow:sample:Check first: multi-task Gradle invocation without --continue: gradlew :a:test :b:test"],
                         policy.violations(workflow(steps)))


if __name__ == "__main__":
    unittest.main()
