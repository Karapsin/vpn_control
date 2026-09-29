"""Causal admission tests for the fixed Linux package fixture build."""

from pathlib import Path
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import linux_package_fixture_build as fixture


SOURCE = "a" * 40
CORRELATION = "11111111-1111-4111-8111-111111111111"
REQUEST = {"sourceSha": SOURCE, "baseVersion": "2.2.0",
           "targetVersion": "2.2.1", "correlationId": CORRELATION}


class LinuxPackageFixtureBuildTest(unittest.TestCase):
    def _built(self, root):
        fingerprint = "b" * 64
        code = "c" * 64
        for family, kinds in (("default", ("deb", "rpm", "arch-bundle")), ("arch", ("arch-bundle",))):
            directory = root / family
            directory.mkdir()
            (directory / "snapshot.json").write_text(json.dumps({"sourceHead": SOURCE,
                                                                    "sourceFingerprint": fingerprint}))
            (directory / "build-plan.json").write_text(json.dumps({"sourceFingerprint": fingerprint,
                                                                      "packageFamily": family}))
            builds = []
            for label, version in (("base", "2.2.0"), ("target", "2.2.1")):
                assets = []
                package_directory = directory / "packages" / label
                package_directory.mkdir(parents=True)
                for kind in kinds:
                    name = f"vpn-control-{version}.{kind}"
                    content = (family + kind + label).encode()
                    (package_directory / name).write_bytes(content)
                    assets.append({"packageType": kind, "fileName": name,
                                   "sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
                builds.append({"label": label, "version": version,
                               "sourceFingerprint": fingerprint,
                               "codeFingerprint": code, "assets": assets})
            (directory / "fixture-receipt.json").write_text(json.dumps({
                "sourceFingerprint": fingerprint, "testOnly": True,
                "productionTrustChanged": False, "builds": builds,
                "manifest": {"assets": builds[1]["assets"]}}))

    def test_missing_fixed_route_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                fixture.preflight(root, {**REQUEST, "command": "sh"})

    def test_one_shot_intent_and_uncertain_submission_never_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            class LostDriver:
                def submit(self, request):
                    calls.append(request)
                    raise OSError("response lost")

                def status(self, request):
                    return {"state": "unknown", "correlationId": request["correlationId"]}

            result = fixture.start(root, REQUEST, driver=LostDriver(), admission=lambda *_: {"ready": True})
            self.assertEqual(result["state"], "unknown")
            again = fixture.start(root, REQUEST, driver=LostDriver(), admission=lambda *_: {"ready": True})
            self.assertEqual(again["state"], "unknown")
            self.assertEqual(len(calls), 1)
            self.assertFalse(again["replayAllowed"])

    def test_distinct_correlation_cannot_concurrently_claim_fixed_build_host(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            class Driver:
                def submit(self, request):
                    return {"state": "submitted", "correlationId": request["correlationId"]}

                def status(self, request):
                    return {"state": "running", "correlationId": request["correlationId"]}

            first = fixture.start(root, REQUEST, driver=Driver(), admission=lambda *_: {"ready": True})
            second = fixture.start(root, {**REQUEST, "correlationId": "22222222-2222-4222-8222-222222222222"},
                                   driver=Driver(), admission=lambda *_: {"ready": True})
            self.assertEqual(first["state"], "submitted")
            self.assertEqual(second["state"], "blocked")

    def test_receipt_verifies_both_families_and_rejects_mutated_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._built(root)
            self.assertEqual(len(fixture._verify_built(root, REQUEST)), 14)
            (root / "arch/packages/target/vpn-control-2.2.1.arch-bundle").write_bytes(b"mutated")
            with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                fixture._verify_built(root, REQUEST)

    def test_timing_receipt_binds_exact_source_run_and_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phase.json"
            value = {"schemaVersion": 1, "sourceSha": SOURCE,
                     "pipelineId": "linux-package-arch", "runId": CORRELATION,
                     "hostAlias": "archlinux", "phase": "packaging",
                     "startedMonotonicNs": 100, "finishedMonotonicNs": 200}
            path.write_text(json.dumps(value))
            self.assertEqual(fixture._verify_timing(path, REQUEST), value)
            value["runId"] = "22222222-2222-4222-8222-222222222222"
            path.write_text(json.dumps(value))
            with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                fixture._verify_timing(path, REQUEST)

    def test_source_remote_probe_is_bound_to_requested_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def run(argv, **_):
                calls.append(argv)
                if "rev-parse" in argv:
                    return subprocess.CompletedProcess(argv, 0, SOURCE + "\n", "")
                if "--porcelain=v1" in argv:
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "ls-remote" in argv:
                    return subprocess.CompletedProcess(argv, 0, SOURCE + "\trefs/heads/dev\n", "")
                return subprocess.CompletedProcess(argv, 0, "vpnControlVersion=2.2.1\n", "")

            with patch.object(fixture.subprocess, "run", side_effect=run), \
                 patch("agent_tools.ssh_transport.load_config", return_value=type("Config", (), {"hosts": {"archlinux": object()}})()):
                self.assertEqual(fixture.preflight(root, REQUEST)["state"], "ready")
            remote = next(call for call in calls if "ls-remote" in call)
            self.assertEqual(remote[:3], ["git", "-C", str(root.resolve())])

    def test_oversized_remote_stream_is_rejected_before_disk_write(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"a" * 64)
            os.close(write_fd)
            write_fd = -1
            target = io.BytesIO()
            with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                fixture._stream_bounded(read_fd, target, 32, fixture.time.monotonic() + 1)
            self.assertEqual(target.getvalue(), b"")
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)

    def test_missing_stage_timing_cannot_report_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = {"schemaVersion": 1, "sourceSha": SOURCE,
                     "pipelineId": "linux-package-default", "runId": CORRELATION,
                     "hostAlias": "archlinux", "phase": "gradle",
                     "startedMonotonicNs": 100, "finishedMonotonicNs": 200}
            (root / f"linux-package-default-{CORRELATION}-gradle-base.json").write_text(json.dumps(value))
            with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                fixture._timing_inventory(root, REQUEST)

    def test_dead_detached_worker_downgrades_running_to_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = fixture._directory(root, create=True)
            fixture._write_once(journal / (CORRELATION + ".json"), REQUEST)
            job = journal / CORRELATION
            job.mkdir(mode=0o700)
            fixture._write_once(job / "state.json", {"state": "running",
                "correlationId": CORRELATION, "sourceSha": SOURCE})
            fixture._write_once(job / "worker-pid.json", {"pid": 12345,
                "start": "Mon Jan  1 00:00:00 2024"})
            with patch.object(fixture, "_process_generation", return_value=None):
                observed = fixture.FixedArchDriver(root).status(REQUEST)
            self.assertEqual(observed["state"], "unknown")

    def test_verified_timing_is_published_for_source_bound_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "phase.json"
            source.write_text(json.dumps({"schemaVersion": 1, "sourceSha": SOURCE,
                "pipelineId": "linux-package-arch", "runId": CORRELATION,
                "hostAlias": "archlinux", "phase": "gradle",
                "startedMonotonicNs": 100, "finishedMonotonicNs": 200},
                sort_keys=True, separators=(",", ":")) + "\n")
            refs = fixture._publish_timing(root, [source])
            from agent_tools import native_build_timing
            report = native_build_timing.report(root, SOURCE, {"sourceSha": SOURCE,
                "pipelineId": "linux-package-arch", "runId": CORRELATION,
                "receipts": refs})
            self.assertEqual(report["state"], "measured")


if __name__ == "__main__":
    unittest.main()
