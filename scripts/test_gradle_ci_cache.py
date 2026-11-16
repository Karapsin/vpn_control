#!/usr/bin/env python3
"""Hosted Gradle build-cache policy: only the default-branch warm workflow writes, release sources never reuse outputs, tests always run."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gradle_cache_warm as warm  # noqa: E402
import gradle_cache_warm_source as warm_source  # noqa: E402
import gradle_ci_cache as subject  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PUSH_WORKFLOWS = ("fast-checks.yml", "android-release.yml", "linux-desktop.yml", "windows-desktop.yml", "macos-desktop.yml")
SETUP = "uses: gradle/actions/setup-gradle@"
INPUTS = "        with:\n          cache-read-only: true\n"
WARM = "gradle-cache-warm.yml"
CACHED_STEPS = {
    "fast-checks.yml": ("Run fast unit tests",),
    "linux-desktop.yml": ("Build Linux packages",),
    "macos-desktop.yml": ("Build macOS package",),
    "windows-desktop.yml": ("Build Windows packages", "Run native desktop tests", "Run portable desktop tests"),
}
PRESERVED = ROOT / "agent_tools/tests/fixtures/agent_ci_shards/ci-gate.workflow.before.yml"


def jobs(text):
    """{job: [(step name, step text)]} for the top-level jobs of one workflow."""
    body = text.split("\njobs:\n", 1)[1]
    result = {}
    for match in re.finditer(r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", body, re.M | re.S):
        steps = re.split(r"(?m)^(?=      - )", match.group(2))[1:]
        result[match.group(1)] = [(re.search(r"name: (.+)", step).group(1) if re.search(r"name: (.+)", step) else "", step)
                                  for step in steps]
    return result


def wiring_problems(name, text):
    problems = []
    cached = CACHED_STEPS.get(name, ())
    for job, steps in jobs(text).items():
        names = [step for step, unused in steps]
        for index, (step, body) in enumerate(steps):
            if SETUP in body and INPUTS not in body:
                problems.append(f"{name}:{job}:{step}: setup-gradle is not cache-read-only")
            uses_cache = "GRADLE_OPTS: ${{ env.GRADLE_BUILD_CACHE_OPTS }}" in body
            if uses_cache != (step in cached):
                problems.append(f"{name}:{job}:{step}: GRADLE_OPTS cache wiring differs from the product build steps")
            if uses_cache:
                policy = [i for i, other in enumerate(names) if other == "Set up Gradle build cache"]
                setup = [i for i, (unused, other) in enumerate(steps) if SETUP in other]
                if len(policy) != 1 or not setup or not setup[0] < policy[0] < index:
                    problems.append(f"{name}:{job}:{step}: cache policy must run after setup-gradle and before the build")
        for step, body in steps:
            if step == "Set up Gradle build cache" and not re.search(r"run: python3? scripts/gradle_ci_cache.py\n", body):
                problems.append(f"{name}:{job}: unexpected cache policy command")
    for step in cached:
        if not any(step == other for steps in jobs(text).values() for other, unused in steps):
            problems.append(f"{name}: product build step {step} is missing")
    return problems


class DecisionTests(unittest.TestCase):
    def test_release_ready_sources_never_use_the_build_cache_on_any_ref(self):
        refs = ("refs/heads/main", "refs/heads/dev", "refs/heads/ci/0123456789ab", "refs/pull/1/merge")
        for ready, mode in ((False, "enabled"), (True, "disabled")):
            with mock.patch.object(subject, "release_ready", return_value=ready):
                for ref in refs:
                    self.assertEqual(mode, subject.decide({"GITHUB_REF": ref})["mode"], ref)

    def test_release_ready_matches_the_publishers_metadata_check(self):
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check_release_metadata.py"), "--require-release-ready"],
                                cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode == 0, subject.release_ready(ROOT), result.stdout + result.stderr)

    def test_enabled_job_never_caches_tests_and_passes_only_the_caching_property(self):
        for mode, expected in (("enabled", "-Dorg.gradle.caching=true"), ("disabled", "")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                home, output = Path(temporary) / "gradle-home", Path(temporary) / "github-env"
                subject.apply({"mode": mode}, {"GRADLE_USER_HOME": str(home), "GITHUB_ENV": str(output)})
                self.assertEqual("GRADLE_BUILD_CACHE_OPTS=%s\n" % expected, output.read_text(encoding="utf-8"))
                init = home / "init.d" / subject.INIT_SCRIPT_NAME
                self.assertEqual(mode == "enabled", init.is_file())
                if init.is_file():
                    text = init.read_text(encoding="utf-8")
                    self.assertIn("tasks.withType(Test).configureEach", text)
                    self.assertIn('outputs.doNotCacheIf("VPN Control CI executes every test") { true }', text)
                    self.assertIn('rootProject.name == "vpn_control"', text)
        self.assertIn('rootProject.name = "vpn_control"', (ROOT / "settings.gradle.kts").read_text(encoding="utf-8"))


class WorkflowWiringTests(unittest.TestCase):
    def test_push_workflows_only_read_the_cache_and_cache_only_product_builds(self):
        problems = []
        for name in PUSH_WORKFLOWS:
            problems += wiring_problems(name, (WORKFLOWS / name).read_text(encoding="utf-8"))
        self.assertEqual([], problems)

    def test_only_the_warm_workflow_writes_and_nothing_disables_by_main(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            values = re.findall(r"(?m)^\s+cache-read-only:\s*(.+)$", text)
            expected = ["false"] if path.name == WARM else ["true"] * len(values)
            self.assertEqual(expected, values, path.name)
            self.assertNotIn("cache-disabled:", text, path.name)
            self.assertNotIn("refs/heads/main", text.replace("git/ref/heads/main", ""), path.name)
            if SETUP in text and path.name != WARM:
                self.assertEqual(text.count(SETUP), len(values), path.name)

    def test_warm_workflow_runs_only_on_dispatch_and_schedule_and_builds_a_dev_commit(self):
        text = (WORKFLOWS / WARM).read_text(encoding="utf-8")
        self.assertEqual("Gradle Cache Warm", re.search(r"(?m)^name: (.+)$", text).group(1))
        triggers = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(["workflow_dispatch", "schedule"], re.findall(r"(?m)^  ([a-z_]+):", triggers))
        self.assertEqual([warm_source.INPUT], re.findall(r"(?m)^      ([a-z_]+):\n", triggers))
        self.assertEqual(WARM, warm_source.WORKFLOW)
        self.assertIn("run: python3 scripts/gradle_cache_warm_source.py", text)
        self.assertIn("ref: ${{ needs.resolve.outputs.sha }}", text)
        self.assertIn("GRADLE_BUILD_ACTION_CACHE_KEY_JOB_EXECUTION: ${{ needs.resolve.outputs.sha }}-${{ github.run_id }}-${{ github.run_attempt }}", text)
        warm_jobs = jobs(text)
        names = [step for step, unused in warm_jobs["warm"]]
        self.assertLess(names.index("Checkout dev commit"), names.index("Set up Gradle"))
        self.assertLess(names.index("Set up Gradle"), names.index("Set up Gradle build cache"))
        self.assertLess(names.index("Set up Gradle build cache"), names.index("Build the CI Gradle tasks"))
        self.assertIn("GRADLE_OPTS: ${{ env.GRADLE_BUILD_CACHE_OPTS }}", dict(warm_jobs["warm"])["Build the CI Gradle tasks"])
        # One warm entry per runner image that a cache-reading push job uses.
        matrix = set(re.search(r"os: \[(.+)\]", text).group(1).replace(" ", "").split(","))
        images = set()
        for name in PUSH_WORKFLOWS:
            for job, steps in jobs((WORKFLOWS / name).read_text(encoding="utf-8")).items():
                if any(SETUP in body for unused, body in steps):
                    body = (WORKFLOWS / name).read_text(encoding="utf-8").split(f"\n  {job}:\n", 1)[1]
                    images.add(re.search(r"runs-on: (\S+)", body).group(1))
        self.assertEqual(images, matrix)
        self.assertEqual({"ubuntu-24.04": "Linux", "macos-15": "macOS", "windows-2025": "Windows"}.keys(), matrix)

    def test_a34e07cb_fast_checks_had_no_cache_policy(self):
        # RED: the preserved workflow restores but never writes a dev cache and
        # reuses no task output; GREEN above.
        problems = wiring_problems("fast-checks.yml", PRESERVED.read_text(encoding="utf-8"))
        self.assertTrue(any("is not cache-read-only" in problem for problem in problems), problems)
        self.assertTrue(any("Run fast unit tests" in problem for problem in problems), problems)


class WarmTests(unittest.TestCase):
    ENV = {"GITHUB_REF": "refs/heads/main", "GITHUB_REPOSITORY": "owner/repo"}

    def git(self, *args):
        if args[0] == "rev-parse":
            return "a" * 40
        if args[2] == "b" * 40:
            raise subprocess.CalledProcessError(1, "git")
        return ""

    def test_resolve_writes_only_from_the_default_branch_and_only_dev_commits(self):
        main = lambda environment: "main"
        self.assertEqual("a" * 40, warm_source.resolve(dict(self.ENV), branch=main, run_git=self.git))
        self.assertEqual("c" * 40, warm_source.resolve({**self.ENV, "REQUESTED_SHA": "C" * 40}, branch=main, run_git=self.git))
        for environment, message in (({**self.ENV, "GITHUB_REF": "refs/heads/dev"}, "only from refs/heads/main"),
                                     ({**self.ENV, "GITHUB_REF": "refs/heads/ci/0123456789ab"}, "only from"),
                                     ({**self.ENV, "REQUESTED_SHA": "b" * 40}, "not contained in dev"),
                                     ({**self.ENV, "REQUESTED_SHA": "abc"}, "full 40-character")):
            with self.subTest(environment=environment), self.assertRaisesRegex(SystemExit, message):
                warm_source.resolve(environment, branch=main, run_git=self.git)

    def test_build_compiles_the_ci_tasks_without_running_tests(self):
        self.assertEqual({"Linux", "macOS", "Windows"}, set(warm.TASKS))
        for name, tasks in warm.TASKS.items():
            self.assertEqual(len(tasks), len(set(tasks)), name)
            for task in tasks:
                self.assertRegex(task, r"^(:[A-Za-z]+)+$")
                self.assertNotRegex(task.rsplit(":", 1)[1], r"(?i)^(test|desktopTest|test\w*UnitTest)$", task)
            self.assertEqual("--continue", warm.build_command(name)[1])
        self.assertTrue(warm.build_command("Windows")[0].endswith("gradlew.bat"))
        # The Linux entry backs Fast Checks, Android Release APK and Linux Desktop Package.
        fast = (WORKFLOWS / "fast-checks.yml").read_text(encoding="utf-8")
        for module in (":shared:model", ":shared:core", ":shared:ui"):
            self.assertIn(module + ":desktopTest", fast)
            self.assertIn(module + ":desktopTestClasses", warm.TASKS["Linux"])
        self.assertIn(":app:compileReleaseKotlin", warm.TASKS["Linux"])


if __name__ == "__main__":
    unittest.main()
