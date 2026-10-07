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
from agent_tools import ssh_transport


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

    @staticmethod
    def _metadata_probe_timeout(argv, **_):
        if "show" in argv:
            raise subprocess.TimeoutExpired(argv, 30)
        if "rev-parse" in argv:
            return subprocess.CompletedProcess(argv, 0, SOURCE + "\n", "")
        if "--porcelain=v1" in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if "ls-remote" in argv:
            return subprocess.CompletedProcess(argv, 0, SOURCE + "\trefs/heads/dev\n", "")
        raise AssertionError("Unexpected source probe")

    def test_final_metadata_probe_timeout_refuses_before_private_config(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(fixture.subprocess, "run", side_effect=self._metadata_probe_timeout) as run, \
                patch("agent_tools.ssh_transport.load_config") as config:
            with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                fixture.preflight(Path(directory), REQUEST)
            config.assert_not_called()
            self.assertEqual(4, run.call_count)
            self.assertIn("show", run.call_args.args[0])

    def test_actual_mcp_preflight_final_metadata_timeout_is_finite_unknown(self):
        from agent_tools import mcp_server as server
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(server, "REPO_ROOT", Path(directory)), \
                patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                patch.object(fixture.subprocess, "run", side_effect=self._metadata_probe_timeout) as run, \
                patch("agent_tools.ssh_transport.load_config") as config, \
                patch.object(fixture.subprocess, "Popen", side_effect=AssertionError("No child permitted")) as child:
            observed = server.vm_workflow("linux-package-fixture-build-preflight", dict(REQUEST))
            self.assertEqual("unknown", observed["state"])
            self.assertFalse(observed["ok"])
            self.assertFalse(observed["nativeActionAllowed"])
            self.assertFalse(observed["replayAllowed"])
            self.assertEqual(CORRELATION, observed["correlationId"])
            config.assert_not_called()
            child.assert_not_called()
            self.assertEqual(4, run.call_count)

    def test_clean_linked_source_uses_its_git_checks_but_coordinator_config(self):
        with tempfile.TemporaryDirectory() as directory:
            coordinator = Path(directory) / "coordinator"
            source_root = Path(directory) / "clean-source"
            coordinator.mkdir()
            source_root.mkdir()
            calls = []

            def run(argv, **_):
                calls.append(argv)
                if "--git-common-dir" in argv:
                    return subprocess.CompletedProcess(argv, 0, "/shared/common.git\n", "")
                if "rev-parse" in argv:
                    return subprocess.CompletedProcess(argv, 0, SOURCE + "\n", "")
                if "--porcelain=v1" in argv:
                    return subprocess.CompletedProcess(argv, 0, "", "")
                if "ls-remote" in argv:
                    return subprocess.CompletedProcess(argv, 0, SOURCE + "\trefs/heads/dev\n", "")
                return subprocess.CompletedProcess(argv, 0, "vpnControlVersion=2.2.1\n", "")

            config = type("Config", (), {"hosts": {"archlinux": object()}})()
            with patch.object(fixture.subprocess, "run", side_effect=run), \
                    patch("agent_tools.ssh_transport.load_config", return_value=config) as load_config:
                observed = fixture.preflight(coordinator, REQUEST, source_root=source_root)
            self.assertEqual(observed["state"], "ready")
            self.assertEqual(observed["sourceSha"], REQUEST["sourceSha"])
            json.dumps(observed)
            source_calls = [call for call in calls if "ls-remote" in call or "--porcelain=v1" in call]
            self.assertTrue(source_calls)
            self.assertTrue(all(str(source_root.resolve()) in call for call in source_calls))
            load_config.assert_called_once_with(coordinator.resolve())

    def test_foreign_dirty_or_mismatched_clean_source_is_rejected_before_config(self):
        cases = {
            "foreign": ("/coordinator/.git", "/foreign/.git", SOURCE, ""),
            "dirty": ("/shared/.git", "/shared/.git", SOURCE, "changed\\n"),
            "mismatched": ("/shared/.git", "/shared/.git", "b" * 40, ""),
        }
        for name, (coordinator_common, source_common, head, status) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                coordinator = Path(directory) / "coordinator"
                source_root = Path(directory) / "source"
                coordinator.mkdir()
                source_root.mkdir()

                def run(argv, **_):
                    if "--git-common-dir" in argv:
                        common = coordinator_common if str(coordinator.resolve()) in argv else source_common
                        return subprocess.CompletedProcess(argv, 0, common + "\n", "")
                    if "rev-parse" in argv:
                        return subprocess.CompletedProcess(argv, 0, head + "\n", "")
                    if "--porcelain=v1" in argv:
                        return subprocess.CompletedProcess(argv, 0, status, "")
                    if "ls-remote" in argv:
                        return subprocess.CompletedProcess(argv, 0, SOURCE + "\trefs/heads/dev\n", "")
                    return subprocess.CompletedProcess(argv, 0, "vpnControlVersion=2.2.1\n", "")

                with patch.object(fixture.subprocess, "run", side_effect=run), \
                        patch("agent_tools.ssh_transport.load_config") as load_config:
                    with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                        fixture.preflight(coordinator, REQUEST, source_root=source_root)
                load_config.assert_not_called()

    def test_unusable_source_root_is_rejected_before_config(self):
        with tempfile.TemporaryDirectory() as directory:
            coordinator = Path(directory)
            with patch("agent_tools.ssh_transport.load_config") as load_config:
                with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                    fixture.preflight(coordinator, REQUEST,
                                      source_root=coordinator / "missing-worktree")
            load_config.assert_not_called()

    def test_symlinked_caller_source_root_is_rejected_before_git_or_config(self):
        with tempfile.TemporaryDirectory() as directory:
            coordinator = Path(directory) / "coordinator"
            target = Path(directory) / "clean-source"
            supplied = Path(directory) / "source-link"
            coordinator.mkdir()
            target.mkdir()
            supplied.symlink_to(target, target_is_directory=True)
            with patch.object(fixture.subprocess, "run") as run, \
                    patch("agent_tools.ssh_transport.load_config") as load_config:
                with self.assertRaises(fixture.LinuxPackageFixtureBuildError):
                    fixture.preflight(coordinator, REQUEST, source_root=supplied)
            run.assert_not_called()
            load_config.assert_not_called()

    def test_existing_coordinator_claim_blocks_clean_source_without_dispatch_or_new_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            coordinator = Path(directory) / "coordinator"
            clean_source = Path(directory) / "clean-source"
            coordinator.mkdir()
            clean_source.mkdir()
            journal = fixture._directory(coordinator, create=True)
            existing = {"correlationId": "be60b777-7593-40e9-9e95-91fb474ba3c8",
                        "host": "archlinux"}
            fixture._write_once(journal / "archlinux.claim", existing)
            next_request = {**REQUEST, "correlationId": "22222222-2222-4222-8222-222222222222"}

            class Driver:
                def submit(self, _request):
                    raise AssertionError("existing claim must prevent dispatch")

            with patch.object(fixture, "preflight", side_effect=AssertionError("must not preflight")) as preflight:
                observed = fixture.start(coordinator, next_request, source_root=clean_source,
                                         driver=Driver())
            self.assertEqual(observed["state"], "blocked")
            self.assertEqual(observed["reason"], "build-host-already-claimed")
            preflight.assert_not_called()
            self.assertEqual(fixture._read(journal / "archlinux.claim"), existing)
            self.assertFalse((journal / (next_request["correlationId"] + ".json")).exists())

    def test_start_passes_clean_source_only_to_preflight_and_keeps_driver_at_coordinator(self):
        with tempfile.TemporaryDirectory() as directory:
            coordinator = Path(directory) / "coordinator"
            clean_source = Path(directory) / "clean-source"
            coordinator.mkdir()
            clean_source.mkdir()
            seen = []

            class Driver:
                def submit(self, request):
                    seen.append(request)
                    return {"state": "submitted", "correlationId": request["correlationId"]}

            with patch.object(fixture, "preflight", return_value={"state": "ready"}) as preflight:
                observed = fixture.start(coordinator, REQUEST, source_root=clean_source,
                                         driver=Driver())
            self.assertEqual(observed["state"], "submitted")
            preflight.assert_called_once_with(coordinator.resolve(), REQUEST, source_root=clean_source)
            self.assertEqual(seen, [REQUEST])
            journal = fixture._directory(coordinator, create=False)
            self.assertEqual(fixture._read(journal / (CORRELATION + ".json")), REQUEST)

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

    def test_remote_bootstrap_passes_real_ssh_command_guard_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = fixture._directory(root, create=True)
            fixture._write_once(journal / (CORRELATION + ".json"), REQUEST)
            job = journal / CORRELATION
            job.mkdir(mode=0o700)
            host = ssh_transport.SshHost(
                alias="archlinux", host="example.invalid", port=22, user="kardinal",
                identity_file=root / "identity", known_hosts_file=root / "known_hosts")
            config = ssh_transport.SshConfig(root=root, hosts={"archlinux": host})
            with patch.object(ssh_transport, "load_config", return_value=config), \
                    patch.object(fixture.subprocess, "Popen", side_effect=RuntimeError("spawn sentinel")) as spawn:
                fixture._local_worker(root, CORRELATION)
            self.assertEqual(spawn.call_count, 1)
            self.assertNotIn("\n", spawn.call_args.args[0][-1])

    def test_pre_effect_closure_preserves_unknown_intent_and_blocks_remote_trace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = fixture._directory(root, create=True)
            fixture._write_once(journal / (CORRELATION + ".json"), REQUEST)
            fixture._write_once(journal / "archlinux.claim",
                                {"correlationId": CORRELATION, "host": "archlinux"})
            job = journal / CORRELATION
            job.mkdir(mode=0o700)
            fixture._write_once(job / "state.json", {"state": "unknown", "reason": "SshConfigError",
                "correlationId": CORRELATION, "sourceSha": SOURCE})
            fixture._write_once(job / "worker-pid.json", {"pid": 12345,
                "start": "Mon Jan  1 00:00:00 2024"})
            (job / "worker.log").write_bytes(b"")
            (job / "worker.log").chmod(0o644)  # Historical worker used open("xb").
            with patch.object(fixture.subprocess, "run", return_value=
                    subprocess.CompletedProcess(["ps"], 1, "", "")):
                observed = fixture.pre_effect_status(root, {"correlationId": CORRELATION})
                self.assertEqual(observed["state"], "ready")
                (job / "remote.log").write_bytes(b"")
                self.assertEqual(fixture.pre_effect_status(root, {"correlationId": CORRELATION})["state"],
                                 "unknown")
                (job / "remote.log").unlink()
                with patch.object(Path, "unlink", side_effect=OSError("interrupted after closure write")):
                    with self.assertRaises(OSError):
                        fixture.pre_effect_close(root, {"correlationId": CORRELATION,
                            "closureDigest": observed["closureDigest"]})
                self.assertEqual(fixture.pre_effect_status(root, {"correlationId": CORRELATION})["state"],
                                 "closing")
                closed = fixture.pre_effect_close(root, {"correlationId": CORRELATION,
                    "closureDigest": observed["closureDigest"]})
            self.assertEqual(closed["state"], "closed")
            self.assertFalse((journal / "archlinux.claim").exists())
            self.assertEqual(fixture._read(journal / (CORRELATION + ".json")), REQUEST)
            self.assertTrue((job / "pre-effect-closure.json").exists())

    def test_terminal_ready_collect_releases_only_verified_original_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal = fixture._directory(root, create=True)
            fixture._write_once(journal / (CORRELATION + ".json"), REQUEST)
            fixture._write_once(journal / "archlinux.claim",
                                {"correlationId": CORRELATION, "host": "archlinux"})
            job = journal / CORRELATION
            job.mkdir(mode=0o700)
            output = job / "output"
            output.mkdir()
            self._built(output)
            fixture._write_once(job / "state.json", {"state": "ready", "liveReady": True,
                "correlationId": CORRELATION, "sourceSha": SOURCE})
            fixture._write_once(job / "worker-pid.json", {"pid": 12345,
                "start": "Mon Jan  1 00:00:00 2024"})
            timing = output / ".rag_index/build-timings"
            timing.mkdir(parents=True)
            for family in ("default", "arch"):
                for phase in ("runtime-prep", "gradle", "packaging"):
                    for stage in ("base", "target"):
                        fixture._write_once(timing / f"linux-package-{family}-{CORRELATION}-{phase}-{stage}.json",
                            {"schemaVersion": 1, "sourceSha": SOURCE,
                             "pipelineId": "linux-package-" + family, "runId": CORRELATION,
                             "hostAlias": "archlinux", "phase": phase,
                             "startedMonotonicNs": 100, "finishedMonotonicNs": 200})
            collected = fixture.collect(root, {"correlationId": CORRELATION})
            self.assertEqual(collected["state"], "ready")
            next_request = {**REQUEST, "correlationId": "22222222-2222-4222-8222-222222222222"}
            self.assertEqual(fixture.start(root, next_request)["reason"], "build-host-already-claimed")
            with patch.object(fixture, "_ended_worker", return_value=False):
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": CORRELATION})["state"], "unknown")
            with patch.object(fixture, "_ended_worker", return_value=True):
                observed = fixture.terminal_ready_status(root, {"correlationId": CORRELATION})
                self.assertEqual(observed["state"], "ready")
                self.assertEqual(fixture.terminal_ready_close(root, {"correlationId": CORRELATION,
                    "closureDigest": "0" * 64})["state"], "unknown")
                self.assertTrue((journal / "archlinux.claim").exists())
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": next_request["correlationId"]})["state"], "unknown")
                (journal / "archlinux.claim").unlink()
                fixture._write_once(journal / "archlinux.claim",
                                    {"correlationId": next_request["correlationId"], "host": "archlinux"})
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": CORRELATION})["state"], "unknown")
                self.assertEqual(fixture.terminal_ready_close(root, {"correlationId": CORRELATION,
                    "closureDigest": observed["closureDigest"]})["state"], "unknown")
                self.assertTrue((journal / "archlinux.claim").exists())
                (journal / "archlinux.claim").unlink()
                fixture._write_once(journal / "archlinux.claim",
                                    {"correlationId": CORRELATION, "host": "archlinux"})
                observed = fixture.terminal_ready_status(root, {"correlationId": CORRELATION})
                package = output / "default/packages/base/vpn-control-2.2.0.deb"
                original = package.read_bytes()
                package.write_bytes(b"changed")
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": CORRELATION})["state"], "unknown")
                package.write_bytes(original)
                with patch.object(Path, "unlink", side_effect=OSError("interrupted after marker")):
                    with self.assertRaises(OSError):
                        fixture.terminal_ready_close(root, {"correlationId": CORRELATION,
                            "closureDigest": observed["closureDigest"]})
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": CORRELATION})["state"], "closing")
                saved_claim = journal / "archlinux.saved-claim"
                (journal / "archlinux.claim").rename(saved_claim)
                fixture._write_once(journal / "archlinux.claim",
                                    {"correlationId": next_request["correlationId"], "host": "archlinux"})
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": CORRELATION})["state"], "unknown")
                self.assertEqual(fixture.terminal_ready_close(root, {"correlationId": CORRELATION,
                    "closureDigest": observed["closureDigest"]})["state"], "unknown")
                self.assertTrue((journal / "archlinux.claim").exists())
                (journal / "archlinux.claim").unlink()
                saved_claim.rename(journal / "archlinux.claim")
                closed = fixture.terminal_ready_close(root, {"correlationId": CORRELATION,
                    "closureDigest": observed["closureDigest"]})
                self.assertEqual(closed["state"], "closed")
                self.assertFalse((journal / "archlinux.claim").exists())
                self.assertEqual(fixture.terminal_ready_status(root,
                    {"correlationId": CORRELATION})["state"], "closed")
                self.assertEqual(fixture.terminal_ready_close(root, {"correlationId": CORRELATION,
                    "closureDigest": observed["closureDigest"]})["state"], "closed")
            self.assertTrue((job / "terminal-ready-closure.json").exists())
            self.assertEqual(fixture._read(journal / (CORRELATION + ".json")), REQUEST)

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
