"""Causal transfer and host one-shot tests without a VM effect."""

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace
from agent_tools import linux_deb_arch_acceptance as acceptance
from agent_tools import linux_deb_arch_guest_prepare as prep

from agent_tools import linux_deb_arch_guest_prepare_remote as subject


ROLE = "ubuntu-update"
CORRELATION = "12345678-1234-1234-1234-123456789abc"
SOURCE = "a" * 40
ARTIFACTS = {key: "sha256-" + character * 64 for key, character in
             (("fixtureReceipt", "b"), ("basePackage", "c"),
              ("targetPackage", "d"), ("bundleManifest", "e"))}


def bundle(changed=False):
    files = {"host/prepare_linux_install_vm.py": b"# fixed prepare\n",
             "host/fixture_environment.py": b"# fixed environment\n",
             "host/worker.py": b"# worker",
             "guest/agent_tools/linux_deb_arch_guest_prepare_remote.py": b"# guest prep",
             "guest/agent_tools/linux_deb_arch_native_driver.py": b"# native worker",
             "guest/agent_tools/linux_deb_arch_rollback.py": b"# rollback worker",
             "guest/fixture/fixture-receipt.json": b"{}\n",
             "guest/target.deb": b"target package"}
    manifest = {"schemaVersion": 1, "correlationId": CORRELATION,
                "sourceSha": SOURCE, "sourceFingerprint": "f" * 64,
                "guestRole": ROLE, "guestPort": 2331, "artifactIds": ARTIFACTS,
                "files": {name: {"sizeBytes": len(content),
                                  "sha256": hashlib.sha256(content).hexdigest()}
                          for name, content in files.items()}}
    if changed:
        files["guest/target.deb"] = b"foreign target"
    files["transfer-manifest.json"] = (json.dumps(manifest, sort_keys=True,
                                                separators=(",", ":")) + "\n").encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


class RemotePreparationTest(unittest.TestCase):
    def test_ready_admission_rejects_active_package_process_before_registration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle_path = root / "bundle.json"
            bundle_path.write_text(json.dumps({"files": [{"path": "scripts/test_linux_public_install.py",
                                                     "sha256": "9" * 64}]}))
            request = SimpleNamespace(profile="package-update", distribution="ubuntu",
                guest_role=ROLE, guest_port=2331, correlation_id=CORRELATION,
                source_sha=SOURCE, artifact_ids=ARTIFACTS)
            guest = {"qemuPid": 123, "qemuStartTicks": 456, "diskDevice": 7, "diskInode": 8}
            receipt = {"fixture": {"trustStoreSha256": "8" * 64}}
            remote = {"guestManifest": guest, "preparationReceipt": receipt}
            fixture = {"sourceFingerprint": "f" * 64, "targetVersion": "2.2.0"}
            def captured(_, identifier, kind, source):
                return {"path": bundle_path, "record": {}}
            observation = {"ready": True, **guest, "ownerRuntimeOff": True,
                "protectedJobsTerminal": True, "profileUnused": True,
                "packageProcessesOff": False}
            with mock.patch.object(acceptance, "_verified_artifact", side_effect=captured), \
                 mock.patch.object(acceptance, "_fixture", return_value=fixture), \
                 mock.patch.object(acceptance, "_bundle"), \
                 mock.patch.object(prep, "validate_receipt"), \
                 mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(returncode=0,stdout=b"script")), \
                 mock.patch("agent_tools.linux_deb_arch_transport.FixedLiveObserver", return_value=lambda *args: observation), \
                 mock.patch("agent_tools.native_artifact_registry.register_artifact") as registered:
                with self.assertRaisesRegex(subject.RemotePreparationError, "live guest differs"):
                    subject.FixedRemoteDriver(root)._admit_ready(request, remote)
                registered.assert_not_called()

    def test_host_capacity_counts_other_qemu_and_rejects_unknown_allocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            proc = Path(temporary)
            (proc / "meminfo").write_text("MemTotal:       33554432 kB\nMemAvailable:   20971520 kB\n"
                                           "SwapTotal:       4194304 kB\nSwapFree:        4194304 kB\n")
            guest = proc / "123"
            guest.mkdir()
            (guest / "comm").write_text("qemu-system-x86\n")
            (guest / "cmdline").write_bytes(b"qemu-system-x86_64\0-m\0" + b"6144\0")
            observed = subject._host_capacity(proc_root=proc)
            self.assertEqual(1, observed["runningQemuCount"])
            self.assertEqual(6144, observed["runningQemuMiB"])
            (guest / "cmdline").write_bytes(b"qemu-system-x86_64\0-m\0unknown\0")
            with self.assertRaisesRegex(subject.RemotePreparationError, "allocation is unknown"):
                subject._host_capacity(proc_root=proc)

    def test_arch_displayed_version_rejects_substring_and_ambiguous_versions(self):
        self.assertEqual("2.1.19", subject._arch_displayed_version("VPN Control 2.1.19\n"))
        self.assertEqual("2.1.190", subject._arch_displayed_version("VPN Control 2.1.190\n"))
        self.assertNotEqual("2.1.19", subject._arch_displayed_version("VPN Control 2.1.190\n"))
        self.assertIsNone(subject._arch_displayed_version("2.1.19 2.2.0"))

    def test_dangling_protected_job_symlink_is_not_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            jobs = Path(temporary) / "vpn-control-install-jobs"
            jobs.symlink_to(Path(temporary) / "missing")
            self.assertFalse(subject._guest_jobs_clear(jobs))
            self.assertIn("jobs.exists() or jobs.is_symlink()", subject._GUEST_BOOTSTRAP)

    def test_guest_idle_does_not_mistake_bootstrap_source_for_running_app(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc = root / "proc"
            proc.mkdir()
            process = proc / "123"
            process.mkdir()
            (process / "cmdline").write_bytes(b"python3\0-c\0/opt/vpn-control/ apt-get\0")
            (process / "exe").symlink_to("/usr/bin/python3")
            with mock.patch.object(subject.os, "geteuid", return_value=0), \
                 mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(returncode=1)), \
                 mock.patch.object(subject, "_run", return_value=SimpleNamespace(stdout=b"")):
                subject._guest_idle("ubuntu", proc_root=proc,
                    app_root=root / "absent-app", jobs=root / "absent-jobs")
                (process / "exe").unlink()
                (process / "exe").symlink_to("/usr/bin/apt-get")
                with self.assertRaisesRegex(subject.RemotePreparationError, "active"):
                    subject._guest_idle("ubuntu", proc_root=proc,
                        app_root=root / "absent-app", jobs=root / "absent-jobs")

    def test_embedded_fixed_programs_compile(self):
        compile(subject._REMOTE_SUBMIT, "remote-submit", "exec")
        compile(subject._REMOTE_STATUS, "remote-status", "exec")
        compile(subject._GUEST_BOOTSTRAP, "guest-bootstrap", "exec")

    def test_tampered_transfer_blocks_before_role_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            with self.assertRaisesRegex(subject.RemotePreparationError, "file differs"):
                subject.host_submit(bundle(changed=True), ROLE, CORRELATION,
                                    SOURCE, ARTIFACTS, root=root, worker_source=b"# worker")
            self.assertFalse(root.exists())

    def test_host_role_claim_is_durable_before_single_worker_and_no_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            with mock.patch.object(subject.subprocess, "Popen") as launched, \
                 mock.patch.object(subject, "_ticks", return_value=456), \
                 mock.patch.object(subject, "_process_state", return_value="R"):
                launched.return_value.pid = 123
                result = subject.host_submit(bundle(), ROLE, CORRELATION,
                                             SOURCE, ARTIFACTS, root=root,
                                             worker_source=b"# worker")
                self.assertEqual({"state": "submitted", "correlationId": CORRELATION}, result)
                self.assertEqual("running", subject.host_status(ROLE, CORRELATION, root=root)["state"])
                with self.assertRaises(FileExistsError):
                    subject.host_submit(bundle(), ROLE, CORRELATION, SOURCE, ARTIFACTS,
                                        root=root, worker_source=b"# worker")
                self.assertEqual(1, launched.call_count)
                self.assertEqual(0o600, (root / (ROLE + ".claim")).stat().st_mode & 0o777)
                with mock.patch.object(subject, "_process_state", return_value="Z"):
                    observed = subject.host_status(ROLE, CORRELATION, root=root)
                self.assertEqual("unknown", observed["state"])
                self.assertEqual("worker-exited-or-unreadable", observed["reason"])

    def test_host_status_rejects_foreign_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            with mock.patch.object(subject.subprocess, "Popen") as launched, \
                 mock.patch.object(subject, "_ticks", return_value=456), \
                 mock.patch.object(subject, "_process_state", return_value="R"):
                launched.return_value.pid = 123
                subject.host_submit(bundle(), ROLE, CORRELATION, SOURCE, ARTIFACTS,
                                    root=root, worker_source=b"# worker")
            other = "87654321-4321-4321-4321-cba987654321"
            with self.assertRaises(subject.RemotePreparationError):
                subject.host_status(ROLE, other, root=root)

    def test_worker_initial_state_read_precedes_identity_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            with mock.patch.object(subject, "host_status", side_effect=RuntimeError("stop-before-effect")) as status:
                with self.assertRaisesRegex(RuntimeError, "stop-before-effect"):
                    subject.run_host_worker(ROLE, CORRELATION, root=root)
                self.assertFalse(status.call_args.kwargs["check_worker"])
            self.assertFalse(root.exists())

    def test_host_ready_requires_matching_sealed_receipt_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "jobs"
            with mock.patch.object(subject.subprocess, "Popen") as launched, \
                 mock.patch.object(subject, "_ticks", return_value=456), \
                 mock.patch.object(subject, "_process_state", return_value="R"):
                launched.return_value.pid = 123
                subject.host_submit(bundle(), ROLE, CORRELATION, SOURCE, ARTIFACTS,
                                    root=root, worker_source=b"# worker")
            job = root / CORRELATION
            subject._replace_state(job, {"state": "ready", "guestRole": ROLE,
                "correlationId": CORRELATION, "sourceSha": SOURCE,
                "artifactIds": ARTIFACTS, "guestManifest": {}, "preparationReceipt": {}})
            with self.assertRaisesRegex(subject.RemotePreparationError, "sealed receipts"):
                subject.host_status(ROLE, CORRELATION, root=root)


if __name__ == "__main__":
    unittest.main()
