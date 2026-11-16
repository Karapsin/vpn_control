#!/usr/bin/env python3
"""Hosted Gradle build-cache policy: only the default-branch warm workflow writes, release sources never reuse outputs, tests always run."""
from __future__ import annotations

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
import gradle_cache_warm as warm  # noqa: E402
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
RESTORE_STEP = "Choose Gradle cache restore"
RESTORE_RUN = "run: ${{ runner.os == 'Windows' && 'python' || 'python3' }} scripts/gradle_ci_cache.py --restore-policy\n"
RESTORE_INPUT = "          cache-disabled: ${{ steps.gradle-restore.outputs.restore != 'true' }}\n"
# Main's frozen copy of the warm workflow runs a newer dev commit, so these
# repository paths are its whole interface with dev: renaming one on dev breaks
# every warm until a release. Change this set only together with a release.
STABLE_WARM_INTERFACE = {"scripts/gradle_cache_warm.py", "desktopApp/native/windows/toolchain.lock.json"}


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


def restore_problems(name, text):
    """Problems that let a release-ready source restore the dev-written Gradle User Home."""
    problems = []
    for job, steps in jobs(text).items():
        for index, (step, body) in enumerate(steps):
            if SETUP not in body:
                continue
            if RESTORE_INPUT not in body:
                problems.append(f"{name}:{job}:{step}: setup-gradle restores without the release restore policy")
            previous_name, previous = steps[index - 1] if index else ("", "")
            condition = re.search(r"(?m)^        if: (.+)$", body)
            expected_condition = f"        if: {condition.group(1)}\n" if condition else ""
            if (previous_name != RESTORE_STEP or "        id: gradle-restore\n" not in previous
                    or RESTORE_RUN not in previous or "        shell: bash\n" not in previous
                    or (re.search(r"(?m)^        if: .+\n", previous) or [""])[0] != expected_condition):
                problems.append(f"{name}:{job}:{step}: the restore policy must run right before setup-gradle")
    return problems


class DecisionTests(unittest.TestCase):
    def test_restore_policy_restores_only_into_development_builds(self):
        for ready, restore in ((False, "true"), (True, "false")):
            with self.subTest(ready=ready), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "output"
                home = Path(temporary) / "gradle-home"
                environment = {"GITHUB_OUTPUT": str(output), "GRADLE_USER_HOME": str(home)}
                with mock.patch.object(subject, "release_ready", return_value=ready), \
                        mock.patch.dict("os.environ", environment, clear=True):
                    self.assertEqual(0, subject.main(["--restore-policy"]))
                self.assertEqual(f"restore={restore}\n", output.read_text(encoding="utf-8"))
                # It runs before setup-gradle: writing the Gradle User Home would stop its restore.
                self.assertFalse(home.exists())
        with self.assertRaises(SystemExit):
            subject.main(["--restore"])

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
            # Restore is disabled by source readiness only, never by ref.
            disabled = re.findall(r"(?m)^\s+cache-disabled:.*\n", text)
            self.assertEqual([] if path.name == WARM else [RESTORE_INPUT] * len(values), disabled, path.name)
            self.assertNotIn("refs/heads/main", text.replace("git/ref/heads/main", ""), path.name)
            if SETUP in text and path.name != WARM:
                self.assertEqual(text.count(SETUP), len(values), path.name)

    def test_release_ready_sources_never_restore_the_dev_written_gradle_home(self):
        # Every setup-gradle outside the warm workflow, push or dispatch, takes the restore policy.
        problems = []
        for path in sorted(WORKFLOWS.glob("*.yml")):
            if path.name != WARM:
                problems += restore_problems(path.name, path.read_text(encoding="utf-8"))
        self.assertEqual([], problems)

    def test_warm_workflow_runs_only_on_dispatch_and_schedule_and_builds_a_dev_commit(self):
        text = (WORKFLOWS / WARM).read_text(encoding="utf-8")
        self.assertEqual("Gradle Cache Warm", re.search(r"(?m)^name: (.+)$", text).group(1))
        triggers = text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(["workflow_dispatch", "schedule"], re.findall(r"(?m)^  ([a-z_]+):", triggers))
        self.assertEqual(["dev_sha"], re.findall(r"(?m)^      ([a-z_]+):\n", triggers))
        self.assertIn("ref: ${{ needs.resolve.outputs.sha }}", text)
        self.assertIn("GRADLE_BUILD_ACTION_CACHE_KEY_JOB_EXECUTION: ${{ needs.resolve.outputs.sha }}-${{ github.run_id }}-${{ github.run_attempt }}", text)
        warm_jobs = jobs(text)
        names = [step for step, unused in warm_jobs["warm"]]
        self.assertLess(names.index("Checkout dev commit"), names.index("Set up Gradle"))
        self.assertEqual("Build the CI Gradle tasks", names[-1])
        self.assertLess(names.index("Set up Gradle"), names.index("Build the CI Gradle tasks"))
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


def warm_interface(text):
    """Repository paths the warm workflow's non-comment lines name, outside its own path."""
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return set(re.findall(r"\b((?:scripts|agent_tools|desktopApp|app|shared|\.github)/[\w./-]+)", code)) - {
        ".github/workflows/" + WARM}


class WarmTests(unittest.TestCase):
    def test_main_frozen_warm_workflow_names_only_the_stable_dev_interface(self):
        # RED on bf8d2da2: it ran scripts/gradle_cache_warm_source.py, scripts/gradle_ci_cache.py
        # and scripts/prepare_android_native_tools.sh from the dev checkout by name.
        text = (WORKFLOWS / WARM).read_text(encoding="utf-8")
        self.assertEqual(STABLE_WARM_INTERFACE, warm_interface(text))
        for path in STABLE_WARM_INTERFACE:
            self.assertTrue((ROOT / path).is_file(), path)
        self.assertIn("run: ${{ runner.os == 'Windows' && 'python' || 'python3' }} scripts/gradle_cache_warm.py\n", text)
        self.assertIn("STABLE INTERFACE", warm.__doc__)

    def resolve_script(self):
        steps = dict(jobs((WORKFLOWS / WARM).read_text(encoding="utf-8"))["resolve"])
        body = steps["Require the default branch and a dev commit"]
        self.assertIn("        shell: bash\n", body)
        return "\n".join(line[10:] for line in body.split("        run: |\n", 1)[1].splitlines())

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash") or not shutil.which("git"), "POSIX bash and git")
    def test_inline_resolve_writes_only_from_the_default_branch_and_only_dev_commits(self):
        script = self.resolve_script()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo, tools = root / "repo", root / "bin"
            tools.mkdir()
            (tools / "gh").write_text("#!/bin/sh\necho main\n", encoding="utf-8")
            (tools / "gh").chmod(0o755)
            git = lambda *args: subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                                               text=True).stdout.strip()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for name in ("one", "two"):
                git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", name)
            first, head = git("rev-parse", "HEAD~1"), git("rev-parse", "HEAD")
            git("checkout", "-q", "--orphan", "other")
            git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "x")
            foreign = git("rev-parse", "HEAD")
            git("checkout", "-q", head)

            def run(ref, requested=""):
                output = root / "output"
                output.write_text("", encoding="utf-8")
                result = subprocess.run(["bash", "-c", script], cwd=repo, capture_output=True, text=True, env={
                    "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}", "GITHUB_REF": ref, "GITHUB_OUTPUT": str(output),
                    "GITHUB_REPOSITORY": "owner/repo", "REQUESTED_SHA": requested})
                return result.returncode, output.read_text(encoding="utf-8"), result.stderr

            self.assertEqual((0, f"sha={head}\n"), run("refs/heads/main")[:2])
            self.assertEqual((0, f"sha={first}\n"), run("refs/heads/main", first.upper())[:2])
            for ref, requested, message in (("refs/heads/dev", "", "only from refs/heads/main"),
                                            ("refs/heads/ci/0123456789ab", "", "only from"),
                                            ("refs/heads/main", foreign, "not contained in dev"),
                                            ("refs/heads/main", "abc", "full 40-character")):
                with self.subTest(ref=ref, requested=requested):
                    code, output, stderr = run(ref, requested)
                    self.assertNotEqual(0, code)
                    self.assertEqual("", output)
                    self.assertIn(message, stderr)

    def test_entry_point_prepares_linux_tools_and_applies_the_cache_policy_itself(self):
        self.assertEqual([["bash", str(ROOT / "scripts/prepare_android_native_tools.sh")]], warm.prepare_commands("Linux"))
        self.assertEqual([], warm.prepare_commands("macOS"))
        self.assertEqual([], warm.prepare_commands("Windows"))
        for ready, options in ((False, "-Dorg.gradle.caching=true"), (True, "")):
            with self.subTest(ready=ready), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary) / "home"
                with mock.patch.object(subject, "release_ready", return_value=ready):
                    environment = warm.build_environment({"GRADLE_USER_HOME": str(home), "GRADLE_OPTS": "-Xmx2g"})
                self.assertEqual(" ".join(part for part in ("-Xmx2g", options) if part), environment["GRADLE_OPTS"])
                self.assertEqual(not ready, (home / "init.d" / subject.INIT_SCRIPT_NAME).is_file())

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
