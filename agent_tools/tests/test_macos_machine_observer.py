"""Causal Mac owner/public readback tests without a Tart invocation."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import macos_machine_acceptance as gate
from agent_tools import macos_machine_boundary as boundary
from agent_tools import macos_machine_observer as subject


SOURCE = "a" * 40
PAIR = boundary.VerifiedPair(SOURCE, "e" * 64, "sha256-" + "f" * 64,
                             "sha256-" + "c" * 64, "sha256-" + "d" * 64)
FIXED = gate._fixed_paths({"sourceSha": SOURCE})
LAUNCHER = FIXED["app"] + "/Contents/MacOS/vpn-control"
STATE = FIXED["guestRoot"] + "/state"


def ps(pid=123, prompts=0):
    owner = f"{pid} Tue Sep 29 10:00:00 2026 {LAUNCHER} --state-dir {STATE} serve"
    secure = "\n456 Tue Sep 29 10:00:01 2026 /System/Library/CoreServices/SecurityAgent" if prompts else ""
    return owner + secure + "\n"


class Runner:
    def __init__(self):
        self.calls = []
        self.process_reads = 0
        self.second_pid = 123
        self.phase = "ready"
        self.prompts = 0
        self.memory_mb = 4096
        self.pressure = "1"

    def __call__(self, argv, **options):
        self.calls.append(argv)
        if argv[:2] == ["tart", "list"]:
            output = [{"Name": gate.VM_NAME, "Source": "local", "Running": True, "State": "running"}]
        elif argv[:2] == ["tart", "get"]:
            output = {"Running": True, "State": "running", "Memory": self.memory_mb}
        elif argv[:2] == ["/usr/sbin/sysctl", "-n"]:
            output = self.pressure + "\n"
        elif argv == ["/usr/bin/vm_stat"]:
            output = 'Mach Virtual Memory Statistics: (page size of 16384 bytes)\n' + \
                     'Pages free: 600000.\nPages inactive: 100000.\nPages speculative: 100000.\n'
        elif "/usr/bin/python3" in argv:
            output = {"schemaVersion": 1, "sourceSha": SOURCE, **FIXED,
                      "baseDevice": 1, "baseInode": 2, "baseRootOwned": True,
                      "baseSignatureValid": True, "baseJarSha256": "b" * 64,
                      "baseDmgSha256": "c" * 64, "targetDmgSha256": "d" * 64}
        elif "/bin/ps" in argv:
            self.process_reads += 1
            output = ps(self.second_pid if self.process_reads > 1 else 123, self.prompts)
        elif "/usr/sbin/sysctl" in argv:
            output = "boot-session\n"
        else:
            data = {"runtimeRunning": False, "configuredMode": "proxy-only"} if "updates" not in argv else \
                   {"phase": self.phase, "installations": []}
            output = {"ok": True, "code": "OK", "final": True, "controllerId": "controller",
                      "data": data}
        return SimpleNamespace(returncode=0, stdout=output if isinstance(output, str) else json.dumps(output), stderr="")


class TartMacObserverTest(unittest.TestCase):
    def observer(self, runner):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        observer = subject.TartMacObserver(Path(temporary.name), runner=runner)
        self.enterContext(patch.object(observer, "_reservation", return_value="env-owned"))
        return observer

    def test_exact_owner_public_readback_binds_resource_and_boot(self):
        runner = Runner()
        observation = self.observer(runner).observe_admission(gate.VM_NAME, SOURCE, PAIR)
        self.assertTrue(observation["resourceAdmitted"])
        self.assertTrue(observation["ownerReady"])
        self.assertEqual(observation["reservationId"], "env-owned")
        self.assertEqual(observation["ownerPid"], 123)
        self.assertEqual(observation["controllerId"], "controller")
        self.assertEqual(observation["bootSessionUuid"], "boot-session")
        self.assertEqual(observation["conflictingJobCount"], 0)
        self.assertFalse(observation["legacyUnknownPreserved"])
        self.assertEqual(runner.process_reads, 2)
        self.assertFalse(any("password" in repr(argv).lower() for argv in runner.calls))

    def test_owner_generation_change_or_unready_update_rejects(self):
        runner = Runner(); runner.second_pid = 999
        with self.assertRaisesRegex(ValueError, "owner or public state changed"):
            self.observer(runner).observe_admission(gate.VM_NAME, SOURCE, PAIR)
        runner = Runner(); runner.phase = "idle"
        with self.assertRaisesRegex(ValueError, "not ready"):
            self.observer(runner).observe_admission(gate.VM_NAME, SOURCE, PAIR)

    def test_stale_reservation_does_not_create_resource_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            observer = subject.TartMacObserver(Path(directory), runner=Runner())
            with self.assertRaises((FileNotFoundError, ValueError)):
                observer.observe_admission(gate.VM_NAME, SOURCE, PAIR)

    def test_saved_reservation_requires_matching_fresh_tart_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "state"
            state.mkdir(mode=0o700)
            record = {"id": "env-owned", "hostAlias": "local-macos", "environment": gate.VM_NAME,
                      "operator": "macos-parity-agent", "allocationState": "running",
                      "requestedMemoryBytes": 4096 * 1024 * 1024,
                      "lastObservation": {"state": "OBSERVED", "observedAtUnixMs": 1000}}
            runner = Runner()
            observer = subject.TartMacObserver(root, runner=runner, clock_ms=lambda: 1001)
            with patch.object(subject.native_environment, "_root_paths", return_value=(state, state / "reservations.json")), \
                 patch.object(subject.native_environment, "_load", return_value={"reservations": [record]}):
                self.assertEqual(observer._reservation(), "env-owned")
                runner.memory_mb = 8192
                with self.assertRaisesRegex(ValueError, "differs from its reservation"):
                    observer._reservation()
                runner.memory_mb = 4096; runner.pressure = "3"
                with self.assertRaisesRegex(ValueError, "pressure is unsafe"):
                    observer._reservation()

    def test_pair_snapshot_is_required_without_summary_reread(self):
        observer = self.observer(Runner())
        with self.assertRaisesRegex(ValueError, "pair snapshot"):
            observer.observe_admission(gate.VM_NAME, SOURCE)
        observation = observer.observe_admission(gate.VM_NAME, SOURCE, PAIR)
        self.assertEqual(observation["sourceFingerprint"], PAIR.source_fingerprint)
        self.assertEqual(observation["fixtureReceiptArtifactId"], PAIR.fixture_receipt_artifact_id)

    def test_admission_rejects_reservation_or_boot_change_during_readback(self):
        runner = Runner()
        observer = self.observer(runner)
        with patch.object(observer, "_reservation", side_effect=["env-owned", "env-other"]):
            with self.assertRaisesRegex(ValueError, "allocation or boot changed"):
                observer.observe_admission(gate.VM_NAME, SOURCE, PAIR)
        observer = self.observer(Runner())
        with patch.object(observer, "_boot_session", side_effect=["boot-one", "boot-two"]):
            with self.assertRaisesRegex(ValueError, "allocation or boot changed"):
                observer.observe_admission(gate.VM_NAME, SOURCE, PAIR)

    def test_terminal_requires_exact_new_owner_gui_public_job_and_protected_receipt(self):
        class TerminalRunner(Runner):
            def __init__(self):
                super().__init__()
                self.job = "33333333-3333-4333-8333-333333333333"
                self.operation = "22222222-2222-4222-8222-222222222222"
                self.job_match = True
                self.gui_present = True
                self.origin_controller = "controller"
            def __call__(self, argv, **options):
                if "/bin/ps" in argv:
                    self.calls.append(argv)
                    owner = f"999 Tue Sep 29 10:01:00 2026 {LAUNCHER} --headless-controller --state-dir {STATE}"
                    gui = f"1000 Tue Sep 29 10:01:01 2026 {LAUNCHER} --state-dir {STATE}"
                    text = owner + ("\n" + gui if self.gui_present else "") + "\n"
                    return SimpleNamespace(returncode=0, stdout=text, stderr="")
                if "/usr/bin/sudo" in argv:
                    self.calls.append(argv)
                    return SimpleNamespace(returncode=0, stdout=json.dumps({
                        "jobId": self.job, "phase": "SUCCEEDED", "code": "OK",
                        "stageAbsent": True, "backupAbsent": True}), stderr="")
                if "updates" in argv:
                    self.calls.append(argv)
                    return SimpleNamespace(returncode=0, stdout=json.dumps({
                        "ok": True, "code": "OK", "final": True, "controllerId": "new-controller",
                        "data": {"installations": [{"jobId": self.job if self.job_match else "other",
                            "operationId": self.operation, "originControllerId": self.origin_controller,
                            "final": True, "code": "OK",
                            "installed": True, "cleanupCode": "OK"}]}}), stderr="")
                if LAUNCHER in argv:
                    self.calls.append(argv)
                    return SimpleNamespace(returncode=0, stdout=json.dumps({
                        "ok": True, "code": "OK", "final": True, "controllerId": "new-controller",
                        "data": {"runtimeRunning": False}}), stderr="")
                return super().__call__(argv, **options)
        runner = TerminalRunner()
        observer = self.observer(runner)
        query = boundary.NativeTerminalQuery(SOURCE, "install", runner.operation, runner.job,
                                            FIXED["app"], FIXED["guestRoot"], 123, 456,
                                            "boot-session", "env-owned", "controller")
        result = observer.observe_terminal(gate.VM_NAME, query)
        self.assertTrue(result["guiReturned"])
        self.assertEqual(result["newOwnerPid"], 999)
        self.assertEqual(result["protectedPhase"], "SUCCEEDED")
        self.assertFalse(result["fixtureServerStopped"], "a separate server receipt is required")
        runner.job_match = False
        with self.assertRaisesRegex(ValueError, "not terminal"):
            observer.observe_terminal(gate.VM_NAME, query)
        runner.job_match = True; runner.gui_present = False
        with self.assertRaisesRegex(ValueError, "owner or GUI"):
            observer.observe_terminal(gate.VM_NAME, query)
        runner.gui_present = True; runner.origin_controller = "another-controller"
        with self.assertRaisesRegex(ValueError, "not terminal"):
            observer.observe_terminal(gate.VM_NAME, query)
        runner.origin_controller = "controller"
        with patch.object(observer, "_reservation", side_effect=["env-owned", "env-other"]):
            with self.assertRaisesRegex(ValueError, "allocation or boot changed"):
                observer.observe_terminal(gate.VM_NAME, query)


if __name__ == "__main__":
    unittest.main()
