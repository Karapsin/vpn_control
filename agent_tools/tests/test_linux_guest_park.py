"""Causal admission and response-loss tests for fixed Linux guest parking."""
from __future__ import annotations

import tempfile
import json
import hashlib
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_tools import linux_guest_park as park
from agent_tools import linux_deb_arch_guest_prepare as prep
from agent_tools import native_artifact_registry as registry


SOURCE = "a" * 40
PREP = "11111111-1111-4111-8111-111111111111"
PARK = "22222222-2222-4222-8222-222222222222"


def evidence() -> tuple[dict, dict]:
    role = "ubuntu-update"
    tree = "/home/kardinal/vpn-control-install-vm-parity-" + role
    guest = {"schemaVersion": 1, "host": "archlinux", "profile": "package-update",
             "distribution": "ubuntu", "guestRole": role, "sourceSha": SOURCE,
             "tree": tree, "sshPort": 2331, "qemuPid": 42, "qemuStartTicks": 1234,
             "diskDevice": 23, "diskInode": 45, "pristine": True}
    receipt = {"schemaVersion": 1, "host": "archlinux", "profile": "package-update",
               "distribution": "ubuntu", "guestRole": role, "sourceSha": SOURCE,
               "correlationId": PREP, "state": "ready",
               "qemu": {"pid": 42, "startTicks": 1234, "diskDevice": 23,
                        "diskInode": 45, "sshPort": 2331, "tree": tree},
               "safety": {"ownerRuntimeOff": True, "protectedJobsTerminal": True,
                          "rootOwnedStage": True}}
    return guest, receipt


class Driver:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or {"state": "parked", "correlationId": PARK,
                                 "qemuPid": 42, "qemuStartTicks": 1234,
                                 "diskDevice": 23, "diskInode": 45,
                                 "qmpInode": 99, "ownerRuntimeOff": True,
                                 "terminalAbsence": True}

    def preflight(self, intent):
        self.calls.append("preflight")
        return {"ready": True, "qmpInode": 99, "ownerRuntimeOff": True,
                "packageProcessesOff": True, "protectedJobsTerminal": True,
                "qemuPid": 42, "qemuStartTicks": 1234,
                "diskDevice": 23, "diskInode": 45}

    def start(self, intent):
        self.calls.append("start")
        return self.result

    def status(self, intent):
        self.calls.append("status")
        return self.result


class ParkTests(unittest.TestCase):
    def setUp(self):
        self.guest, self.receipt = evidence()
        self.real_loader = park.load_prepared_evidence
        self.loader = patch.object(park, "load_prepared_evidence",
            side_effect=lambda _root, _raw: (self.guest, self.receipt))
        self.loader.start()
        self.addCleanup(self.loader.stop)

    def test_source_bound_preparation_loader_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = {key: "sha256-" + (str(index) * 64) for index, key in
                         enumerate(("fixtureReceipt", "basePackage", "targetPackage",
                                    "bundleManifest"), 1)}
            request = prep.Request.parse({"profile": "package-update", "distribution": "ubuntu",
                "correlationId": PREP, "sourceSha": SOURCE, "artifactIds": artifacts})
            prep._claim_role(root, request)
            prep._save(root, request.public_mapping())
            folder = root / ".rag_index" / "linux-deb-arch-guest-prepare" / PREP
            folder.mkdir(mode=0o700)
            guest = dict(self.guest)
            receipt = dict(self.receipt)
            receipt["guestManifestArtifactId"] = "sha256-" + hashlib.sha256(
                park._canonical(guest)).hexdigest()
            receipt["sourceFingerprint"] = "f" * 64
            paths = []
            for name, kind, value in (("guest-manifest.json", "guest-manifest", guest),
                                      ("preparation-receipt.json", "linux-guest-preparation", receipt)):
                path = folder / name
                raw = park._canonical(value)
                path.write_bytes(raw)
                path.chmod(0o600)
                registry.register_artifact(root, {"platform": "linux", "artifactKind": kind,
                    "localPath": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw), "evidenceClass": "local-verified",
                    "sourceSha": SOURCE, "sourceFingerprint": "f" * 64})
                paths.append(path)
            raw = {"correlationId": PARK, "preparationCorrelationId": PREP,
                   "guestRole": "ubuntu-update", "sourceSha": SOURCE}
            self.assertEqual((guest, receipt), self.real_loader(root, raw))
            with self.assertRaises(ValueError):
                self.real_loader(root, {**raw, "sourceSha": "b" * 40})
            paths[0].write_bytes(b"{}\n")
            with self.assertRaises(ValueError):
                self.real_loader(root, raw)

    def test_fake_proc_unreadable_live_process_and_disk_holder_block_terminal(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            tree = base / "guest"
            tree.mkdir(mode=0o700)
            disk = tree / "task.qcow2"
            disk.write_bytes(b"disk")
            disk.chmod(0o600)
            disk_info = disk.stat()
            prep_root = base / "prep"
            prep_root.mkdir(mode=0o700)
            prep_job = prep_root / PREP
            prep_job.mkdir(mode=0o700)
            park_root = base / "park"
            park_root.mkdir(mode=0o700)
            fake_proc = base / "proc"
            (fake_proc / "net").mkdir(parents=True)
            for name in ("tcp", "tcp6", "unix"):
                (fake_proc / "net" / name).write_text("header\n")
            payload = {"correlationId": PARK, "preparationCorrelationId": PREP,
                       "guestRole": "ubuntu-update", "sourceSha": SOURCE,
                       "qemuPid": 42, "qemuStartTicks": 1234,
                       "diskDevice": disk_info.st_dev, "diskInode": disk_info.st_ino,
                       "qmpInode": 99}
            def put(path, value):
                path.write_text(json.dumps(value) + "\n")
                path.chmod(0o600)
            put(prep_root / "ubuntu-update.claim", {"guestRole": "ubuntu-update",
                "correlationId": PREP, "sourceSha": SOURCE})
            put(prep_job / "state.json", {"state": "ready", "guestRole": "ubuntu-update",
                "sourceSha": SOURCE})
            put(prep_job / "guest-manifest.json", {"schemaVersion": 1, "host": "archlinux",
                "guestRole": "ubuntu-update", "sourceSha": SOURCE, "tree": str(tree),
                "sshPort": 2331, "qemuPid": 42, "qemuStartTicks": 1234,
                "diskDevice": disk_info.st_dev, "diskInode": disk_info.st_ino})
            put(prep_job / "preparation-receipt.json", {"schemaVersion": 1,
                "state": "ready", "guestRole": "ubuntu-update", "sourceSha": SOURCE,
                "correlationId": PREP,
                "qemu": {"pid": 42, "startTicks": 1234, "diskDevice": disk_info.st_dev,
                         "diskInode": disk_info.st_ino, "sshPort": 2331, "tree": str(tree)}})
            put(park_root / "ubuntu-update.claim", {"guestRole": "ubuntu-update",
                "correlationId": PARK, "preparationCorrelationId": PREP, "sourceSha": SOURCE})
            put(park_root / (PARK + ".json"), payload)
            put(park_root / (PARK + ".result.json"), {"state": "parked",
                "correlationId": PARK, "qemuPid": 42, "qemuStartTicks": 1234,
                "diskDevice": disk_info.st_dev, "diskInode": disk_info.st_ino,
                "qmpInode": 99, "ownerRuntimeOff": True, "terminalAbsence": True})
            source = park._REMOTE.replace("'/home/kardinal/vpn-control-install-vm-parity-'+role", repr(str(tree)))
            source = source.replace("'/home/kardinal/.vpn-control-parity-prepare'", repr(str(prep_root)))
            source = source.replace("'/home/kardinal/.vpn-control-parity-park'", repr(str(park_root)))
            source = source.replace("'/home/kardinal/.vpn-control-parity-jobs'", repr(str(base / "jobs")))
            source = source.replace("/proc", str(fake_proc))
            source = source.replace("if os.geteuid()!=0:raise SystemExit(2)", "if False:raise SystemExit(2)")
            source = source.replace("pwd.getpwnam('kardinal').pw_uid;PARK_OWNER=0",
                "os.getuid();PARK_OWNER=os.getuid()")
            source = source.replace("except Exception:\n print(json.dumps({'state':'unknown'",
                "except Exception as error:\n print(json.dumps({'reason':str(error),'state':'unknown'")
            def run():
                return subprocess.run([sys.executable, "-I", "-B", "-c", source,
                    "status", json.dumps(payload)], capture_output=True, text=True,
                    timeout=5)
            self.assertEqual("parked", json.loads(run().stdout)["state"])
            process = fake_proc / "777"
            process.mkdir()
            self.assertEqual("live-cmdline-unreadable", json.loads(run().stdout)["reason"])
            (process / "cmdline").write_bytes(b"other\0")
            (process / "cmdline").chmod(0)
            self.assertEqual("live-cmdline-unreadable", json.loads(run().stdout)["reason"])
            (process / "cmdline").chmod(0o600)
            (process / "fd").mkdir()
            self.assertEqual("parked", json.loads(run().stdout)["state"])
            (process / "fd" / "0").symlink_to(disk)
            self.assertEqual("park-result", json.loads(run().stdout)["reason"])

    def test_remote_driver_requires_fixed_privileged_census_command(self):
        with tempfile.TemporaryDirectory() as directory:
            commands = []
            config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(user="kardinal", password=None)})
            def build(_config, _host, _timeout, command):
                commands.append(command)
                return ["ssh", "fixed"]
            def runner(_argv, **_kwargs):
                return SimpleNamespace(returncode=0, stdout=b'{"state":"unknown"}')
            with patch.object(park.ssh_transport, "load_config", return_value=config), \
                 patch.object(park.ssh_transport, "build_ssh_argv", side_effect=build):
                park.FixedRemoteDriver(Path(directory), runner=runner).status({"guestRole": "ubuntu-update"})
            self.assertEqual(("sudo", "-n", "python3", "-I", "-B", "-c"), commands[0][:6])
            self.assertIn("if os.geteuid()!=0:raise SystemExit(2)", commands[0][6])

    def test_fake_proc_prefix_disk_fd_does_not_admit_qemu(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            tree = base / "guest"
            tree.mkdir(mode=0o700)
            disk = tree / "task.qcow2"
            disk.write_bytes(b"exact")
            disk.chmod(0o600)
            decoy = tree / "task.qcow2-other"
            decoy.write_bytes(b"decoy")
            decoy.chmod(0o600)
            qmp = tree / "qmp.sock"
            server = socket.socket(socket.AF_UNIX)
            server.bind(str(qmp))
            try:
                fake_proc = base / "proc"
                process = fake_proc / "42"
                (process / "fd").mkdir(parents=True)
                (process / "stat").write_text("42 (qemu) " + " ".join(["S"] + ["0"] * 18 + ["1234"]))
                (process / "cmdline").write_bytes(
                    b"qemu-system-x86_64\0file=" + str(disk).encode() +
                    b",if=virtio,format=qcow2\0hostfwd=tcp:127.0.0.1:2331-:22\0unix:" +
                    str(qmp).encode() + b",server=on,wait=off\0")
                (process / "fd" / "0").symlink_to(decoy)
                payload = {"correlationId": PARK, "preparationCorrelationId": PREP,
                           "guestRole": "ubuntu-update", "sourceSha": SOURCE,
                           "qemuPid": 42, "qemuStartTicks": 1234,
                           "diskDevice": disk.stat().st_dev, "diskInode": disk.stat().st_ino,
                           "qmpInode": qmp.stat().st_ino}
                source = park._REMOTE.replace("'/home/kardinal/vpn-control-install-vm-parity-'+role", repr(str(tree)))
                source = source.replace("/proc", str(fake_proc))
                source = source.replace("if os.geteuid()!=0:raise SystemExit(2)", "if False:raise SystemExit(2)")
                source = source.replace("pwd.getpwnam('kardinal').pw_uid;PARK_OWNER=0",
                    "os.getuid();PARK_OWNER=os.getuid()")
                source = source.replace("try:\n claims()", "try:\n proc_identity();raise SystemExit(9)\n claims()")
                source = source.replace("except Exception:\n print(json.dumps({'state':'unknown'",
                    "except Exception as error:\n print(json.dumps({'reason':str(error),'state':'unknown'")
                done = subprocess.run([sys.executable, "-I", "-B", "-c", source,
                    "start", json.dumps(payload)], capture_output=True, text=True,
                    timeout=5)
                self.assertEqual("unknown", json.loads(done.stdout)["state"])
                self.assertEqual("disk-fd", json.loads(done.stdout)["reason"])
                self.assertEqual(0, done.returncode)
            finally:
                server.close()

    def test_fixed_remote_program_compiles_and_preflight_discovers_qmp_inode(self):
        compile(park._REMOTE, "<fixed-linux-park>", "exec")
        self.assertIn("mode!='preflight' and q.st_ino!=intent['qmpInode']", park._REMOTE)
        self.assertIn("'system_powerdown'", park._REMOTE)
        self.assertNotIn("system_reset", park._REMOTE)
        self.assertNotIn("'quit'", park._REMOTE)

    def test_exact_ready_receipts_and_qmp_inode_required(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver()
            adapter = park.Adapter(Path(directory), driver=driver)
            preview = adapter.preflight({"correlationId": PARK,
                "preparationCorrelationId": PREP, "guestRole": "ubuntu-update",
                "sourceSha": SOURCE})
            self.assertEqual("ready", preview["state"])
            self.assertFalse(preview["nativeActionAllowed"])
            self.assertFalse((Path(directory) / ".rag_index" / "linux-guest-park" /
                (PARK + ".json")).exists())
            result = adapter.start({"correlationId": PARK, "preparationCorrelationId": PREP,
                                    "guestRole": "ubuntu-update", "sourceSha": SOURCE})
            self.assertEqual("parked", result["state"])
            self.assertEqual(["preflight", "preflight", "start"], driver.calls)
            self.assertEqual(99, adapter.status(PARK)["qmpInode"])
            self.assertEqual(["preflight", "preflight", "start", "status"], driver.calls)

    def test_changed_generation_or_claim_refuses_without_effect(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver()
            adapter = park.Adapter(Path(directory), driver=driver)
            guest["qemuStartTicks"] += 1
            result = adapter.start({"correlationId": PARK, "preparationCorrelationId": PREP,
                                    "guestRole": "ubuntu-update", "sourceSha": SOURCE})
            self.assertEqual("blocked", result["state"])
            self.assertEqual([], driver.calls)

    def test_caller_supplied_manifest_is_not_an_admission_input(self):
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver()
            adapter = park.Adapter(Path(directory), driver=driver)
            raw = {"correlationId": PARK, "preparationCorrelationId": PREP,
                   "guestRole": "ubuntu-update", "sourceSha": SOURCE,
                   "guestManifest": self.guest}
            self.assertEqual("blocked", adapter.preflight(raw)["state"])
            self.assertEqual([], driver.calls)

    def test_lost_start_response_is_unknown_and_never_replayed(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver()
            def lost(_intent):
                driver.calls.append("start")
                raise TimeoutError()
            driver.start = lost
            adapter = park.Adapter(Path(directory), driver=driver)
            raw = {"correlationId": PARK, "preparationCorrelationId": PREP,
                   "guestRole": "ubuntu-update", "sourceSha": SOURCE}
            self.assertEqual("unknown", adapter.start(raw)["state"])
            self.assertEqual("unknown", adapter.start(raw)["state"])
            self.assertEqual(["preflight", "start"], driver.calls)

    def test_runtime_on_refuses_before_durable_intent(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver()
            driver.preflight = lambda _: {"ready": True, "qmpInode": 99,
                                          "ownerRuntimeOff": False}
            adapter = park.Adapter(Path(directory), driver=driver)
            self.assertEqual("blocked", adapter.start({"correlationId": PARK,
                "preparationCorrelationId": PREP, "guestRole": "ubuntu-update",
                "sourceSha": SOURCE})["state"])
            self.assertFalse((Path(directory) / ".rag_index" / "linux-guest-park" / (PARK + ".json")).exists())

    def test_second_park_correlation_cannot_reuse_role(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver()
            adapter = park.Adapter(Path(directory), driver=driver)
            raw = {"correlationId": PARK, "preparationCorrelationId": PREP,
                   "guestRole": "ubuntu-update", "sourceSha": SOURCE}
            self.assertEqual("parked", adapter.start(raw)["state"])
            raw["correlationId"] = "33333333-3333-4333-8333-333333333333"
            self.assertEqual("unknown", adapter.start(raw)["state"])
            self.assertEqual(["preflight", "start", "preflight"], driver.calls)

    def test_forged_terminal_receipt_does_not_pass(self):
        guest, receipt = self.guest, self.receipt
        with tempfile.TemporaryDirectory() as directory:
            driver = Driver({"state": "parked", "correlationId": PARK,
                             "qemuPid": 42, "qemuStartTicks": 1234,
                             "diskDevice": 23, "diskInode": 45,
                             "qmpInode": 98, "ownerRuntimeOff": True,
                             "terminalAbsence": True})
            adapter = park.Adapter(Path(directory), driver=driver)
            self.assertEqual("unknown", adapter.start({"correlationId": PARK,
                "preparationCorrelationId": PREP, "guestRole": "ubuntu-update",
                "sourceSha": SOURCE})["state"])


if __name__ == "__main__":
    unittest.main()
