#!/usr/bin/env python3
"""Hosted Gradle build-cache policy: dev pushes write, release sources never reuse outputs, tests always run."""
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
import gradle_ci_cache as subject  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PUSH_WORKFLOWS = ("fast-checks.yml", "android-release.yml", "linux-desktop.yml", "windows-desktop.yml", "macos-desktop.yml")
SETUP = "uses: gradle/actions/setup-gradle@"
INPUTS = ("        with:\n"
          "          cache-read-only: ${{ !(github.event_name == 'push' && github.ref == 'refs/heads/dev') }}\n"
          "          cache-disabled: ${{ github.ref == 'refs/heads/main' }}\n")
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
                problems.append(f"{name}:{job}:{step}: setup-gradle lacks the dev-write/main-off cache inputs")
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
    def test_main_and_release_ready_sources_never_use_the_build_cache(self):
        with mock.patch.object(subject, "release_ready", return_value=False):
            self.assertEqual("disabled", subject.decide({"GITHUB_REF": "refs/heads/main"})["mode"])
            self.assertEqual("enabled", subject.decide({"GITHUB_REF": "refs/heads/dev"})["mode"])
            self.assertEqual("enabled", subject.decide({"GITHUB_REF": "refs/pull/1/merge"})["mode"])
        with mock.patch.object(subject, "release_ready", return_value=True):
            self.assertEqual("disabled", subject.decide({"GITHUB_REF": "refs/heads/dev"})["mode"])

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
    def test_push_workflows_write_only_on_dev_and_cache_only_product_builds(self):
        problems = []
        for name in PUSH_WORKFLOWS:
            problems += wiring_problems(name, (WORKFLOWS / name).read_text(encoding="utf-8"))
        self.assertEqual([], problems)

    def test_a34e07cb_fast_checks_had_no_cache_policy(self):
        # RED: the preserved workflow restores but never writes a dev cache and
        # reuses no task output; GREEN above.
        problems = wiring_problems("fast-checks.yml", PRESERVED.read_text(encoding="utf-8"))
        self.assertTrue(any("setup-gradle lacks" in problem for problem in problems), problems)
        self.assertTrue(any("Run fast unit tests" in problem for problem in problems), problems)


if __name__ == "__main__":
    unittest.main()
