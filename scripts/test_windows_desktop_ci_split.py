#!/usr/bin/env python3
"""Windows Desktop Package runs its package, two test partitions and hygiene guards as parallel jobs.

The run still fails when any job fails, and the stable publisher only downloads
installers from a run whose overall conclusion is success. Every check of the
a34e07cb single job still runs once, and the two desktop-test partitions are
complementary halves of :desktopApp:test.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/windows-desktop.yml"
FIXTURES = ROOT / "scripts/tests/fixtures/windows_desktop_ci_split"
PUSH_JOBS = ("package-windows-desktop", "windows-desktop-tests-native", "windows-desktop-tests-portable",
             "windows-hygiene-native-guards")
CONDITION = "    if: github.event_name != 'workflow_dispatch' || inputs.fixture_base_version == ''\n"
# The only dependency: a dev push skips every job when this SHA already passed on a ci/* branch.
REUSE = ("    needs: reuse\n"
         "    if: needs.reuse.outputs.skip != 'true' && (github.event_name != 'workflow_dispatch' || inputs.fixture_base_version == '')\n")
PACKAGE = r"run: .\scripts\package_windows_desktop.ps1"


def before():
    provenance = json.loads((FIXTURES / "provenance.json").read_text(encoding="utf-8"))
    row = provenance["files"][0]
    raw = (FIXTURES / row["path"]).read_bytes()
    if len(raw) != row["sourceBytes"] or hashlib.sha256(raw).hexdigest() != row["sourceSha256"]:
        raise ValueError("Preserved Windows workflow changed")
    return raw.decode("utf-8")


def jobs(text):
    body = text.split("\njobs:\n", 1)[1]
    return {match.group(1): match.group(2) for match in
            re.finditer(r"^  ([A-Za-z0-9_-]+):\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", body, re.M | re.S)}


def step_names(job):
    return re.findall(r"(?m)^      - name: (.+)$", job)


def split_problems(text):
    """Problems that keep the MSI, the desktop tests and the guards serial or incomplete."""
    problems = []
    found = jobs(text)
    missing = [key for key in PUSH_JOBS if key not in found]
    if missing:
        return ["missing parallel jobs: " + ", ".join(missing)]
    for key in PUSH_JOBS:
        job = found[key]
        gated = job.startswith(REUSE) and job.count("\n    needs:") == 0
        if not (gated or CONDITION in job and "\n    needs:" not in job) or "continue-on-error" in job:
            problems.append(key + ": must run on every push, in parallel, and fail the run normally")
    package = found["package-windows-desktop"]
    if PACKAGE + " -SkipTests -SkipReleaseHygiene\n" not in package or "choco install wixtoolset" not in package:
        problems.append("package job must only package")
    uploads = [key for key, job in found.items() if "name: vpn-control-windows-installers" in job]
    if uploads != ["package-windows-desktop"]:
        problems.append("only the package job may upload the installers: %s" % uploads)
    for key, partition in (("windows-desktop-tests-native", "Native"), ("windows-desktop-tests-portable", "Portable")):
        if PACKAGE + " -TestsOnly -SkipReleaseHygiene -DesktopTestPartition " + partition + "\n" not in found[key]:
            problems.append(key + ": must run the " + partition + " desktop test partition only")
    guards = found["windows-hygiene-native-guards"]
    if text.count("run: ./scripts/check_release_hygiene.sh") != 1 or "run: ./scripts/check_release_hygiene.sh" not in guards:
        problems.append("release hygiene must run once, in the guard job")
    current = {name for key in PUSH_JOBS for name in step_names(found[key])}
    original = jobs(before())["package-windows-desktop"]
    lost = [name for name in step_names(original) if name not in current]
    if lost:
        problems.append("checks lost from the single job: " + ", ".join(lost))
    return problems


class WindowsDesktopSplitTests(unittest.TestCase):
    def test_current_workflow_runs_package_tests_and_guards_in_parallel(self):
        self.assertEqual([], split_problems(WORKFLOW.read_text(encoding="utf-8")))

    def test_a34e07cb_single_serial_job_is_refused(self):
        problems = split_problems(before())
        self.assertEqual(["missing parallel jobs: windows-desktop-tests-native, windows-desktop-tests-portable, "
                          "windows-hygiene-native-guards"], problems)

    def test_partitions_are_complementary_halves_of_the_desktop_test_task(self):
        init = (ROOT / "scripts/desktop_test_partition.init.gradle").read_text(encoding="utf-8")
        include = re.findall(r'includeTestsMatching\("([^"]+)"\)', init)
        exclude = re.findall(r'excludeTestsMatching\("([^"]+)"\)', init)
        self.assertEqual(["*NativeTest"], include)
        self.assertEqual(include, exclude)
        self.assertIn('tasks.named("test", Test)', init)
        self.assertIn('partition in ["native", "portable"]', init)
        script = (ROOT / "scripts/package_windows_desktop.ps1").read_text(encoding="utf-8")
        self.assertIn('[ValidateSet("All", "Native", "Portable")]', script)
        self.assertIn('"-PvpnControlDesktopTestPartition=$($DesktopTestPartition.ToLowerInvariant())"', script)
        self.assertIn("vpnControlDesktopTestPartition", init)
        # Tests-only runs stop before packaging; a partial partition never packages.
        self.assertLess(script.index("if ($TestsOnly) {"), script.index("building Windows desktop packages"))
        self.assertIn("-DesktopTestPartition requires -TestsOnly", script)
        # Helper and package-input checks run once, in the portable partition.
        self.assertEqual(3, script.count("$RunsPortableChecks"))
        self.assertIn('$RunsPortableChecks = $DesktopTestPartition -ne "Native"', script)

    def test_publisher_takes_installers_only_from_a_successful_run(self):
        publisher = (ROOT / ".github/workflows/release-publish.yml").read_text(encoding="utf-8")
        self.assertIn("windows-desktop.yml", publisher)
        self.assertIn('.conclusion == \\"success\\"', publisher)
        self.assertIn("vpn-control-windows-installers", publisher)


if __name__ == "__main__":
    unittest.main()
