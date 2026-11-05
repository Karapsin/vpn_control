"""Causal renderer/owner regression for the five-field private root identity.

The rejected native program was never submitted: its renderer supplied five
fields but its owner compared two. These tests call the real start_program(),
then execute its complete unchanged output against inert owned files. They do
not rebuild _START_BODY or manufacture the owner's plan. The retained complete
unfixed module uses the same harness and refuses before actor publication.
"""
from contextlib import nullcontext
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart_macos as mac
from agent_tools import readiness_tart_macos_lifecycle as lifecycle


FIXTURES = Path(__file__).parent / "fixtures/tart_macos_lifecycle_root_identity"
BEFORE_SHA256 = "b1bfc8ea5f71d978597825306aa3abb19546d531dc5a200996c1835f82ccae02"
REJECTION_SHA256 = "35dc19b51666f4dd74e4bdef9b285f1f33bea4d167f9e63337eeaeb382fb51a1"
RECOVERY_ID = "a" * 64
HOST_BOOT = "owned-inert-host-boot"
FIELD_INDEX = {"device": 0, "inode": 1, "mode": 2, "uid": 3, "gid": 4}


def retained_beforeimage():
    """Load the authenticated whole file with its real source guard intact."""
    path = FIXTURES / "lifecycle.before.source"
    if hashlib.sha256(path.read_bytes()).hexdigest() != BEFORE_SHA256:
        raise AssertionError("retained lifecycle beforeimage changed")
    name = "agent_tools._tart_root_identity_before"
    if name not in sys.modules:
        loader = importlib.machinery.SourceFileLoader(name, str(path))
        spec = importlib.util.spec_from_loader(name, loader)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        loader.exec_module(module)
    return sys.modules[name]


@unittest.skipUnless(os.name == "posix", "actual private directory FDs and owned PTY required")
class RenderedRootIdentityTests(unittest.TestCase):
    def implementation(self):
        return (retained_beforeimage() if os.environ.get("VPN_CONTROL_TEST_TART_ROOT_IDENTITY_BEFORE") == "1"
                else lifecycle)

    def execute_owner(self, implementation, *, admitted_drift=None, mode=0o700, evidence_name):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)
            vm_name = "vpn-tool-recovery-tart-macos-root-identity"
            vm, share, lifecycle_root = base / vm_name, base / "share", base / "lifecycle"
            for path in (vm, share, lifecycle_root):
                path.mkdir(mode=0o700)
            launches = lifecycle_root / "macos-launches"
            launches.mkdir(mode=0o700)
            operation = implementation.operation_id(RECOVERY_ID)
            run = launches / operation
            run.mkdir(mode=mode)
            run.chmod(mode)
            binary = base / "controlled-tart"
            binary.write_text("#!" + sys.executable + "\n" + (FIXTURES / "inert_tart.py").read_text())
            binary.chmod(0o700)
            config, disk, nvram = (vm / name for name in ("config.json", "disk.img", "nvram.bin"))
            for path in (config, disk, nvram):
                path.write_bytes(b"public inert fixture")
                path.chmod(0o600)
            binding = mac.MacBinding(
                "local-tart-macos-" + "a" * 24, "11111111-1111-4111-8111-111111111111",
                vm_name, str(binary), str(vm), "owned", max(os.geteuid(), 501), "/Users/owned",
                "/usr/bin/python3", 4096, "owned-root-identity")
            memory, storage = base / "memory.json", base / "storage.json"
            custody = types.SimpleNamespace(
                binding=binding, lifecycle_root=lifecycle_root,
                host_binding=jobs.MachineBinding("owned", "machine", HOST_BOOT, str(os.geteuid())),
                _public_share=types.SimpleNamespace(guard=lambda: None, rows={}),
                guard=lambda **kwargs: {"state": "stopped"},
                run_intent={"plan": {
                    "configSha256": hashlib.sha256(config.read_bytes()).hexdigest(),
                    "diskGeneration": list(private._generation(disk.lstat())),
                    "binaryGeneration": list(private._generation(binary.lstat())),
                    "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    "bootstrapShare": str(share), "storageLedger": str(storage), "memoryLedger": str(memory),
                    "reservationKey": "owned-root-identity"}})

            actual_identity = private._directory_identity
            root_identity = list(actual_identity(run.lstat()))
            admitted_identity = root_identity.copy()
            if admitted_drift:
                index = FIELD_INDEX[admitted_drift]
                admitted_identity[index] += 1

            def admitted_snapshot(info):
                # Only the admitted metadata is controlled. The owner sees the
                # real safe root, so mode/UID safety checks cannot hide omission
                # of those fields from the plan-to-current identity comparison.
                identity = actual_identity(info)
                return tuple(admitted_identity) if list(identity) == root_identity else identity

            patch = (mock.patch.object(private, "_directory_identity", side_effect=admitted_snapshot)
                     if admitted_drift else nullcontext())
            with patch:
                program = implementation.start_program(binding, custody, RECOVERY_ID, run,
                                                       deadline=time.monotonic() + 5)
            source = base / "emitted-owner.py"
            source.write_bytes(program.source)
            adapter = FIXTURES / "launch_adapter.py"
            child = subprocess.Popen([sys.executable, "-I", str(adapter), str(source), HOST_BOOT],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout = stderr = b""
            try:
                until = time.monotonic() + 5
                actor_path = run / "actor.json"
                while not actor_path.exists() and child.poll() is None and time.monotonic() < until:
                    time.sleep(.01)
                if actor_path.exists():
                    actor = json.loads(actor_path.read_bytes())

                    def publish(path, value):
                        path.write_text(json.dumps(value))
                        path.chmod(0o600)

                    publish(storage, {"plans": {binding.storage_fixture_id: {
                        "state": "pending", "writerPid": actor["pid"], "directory": str(vm),
                        "disks": [{"path": str(disk), "capacityBytes": disk.stat().st_size}]}}})
                    publish(memory, {"schema_version": 1, "reservations": {
                        "owned-root-identity": {"memory_mib": 4096, "pid": 0}}})
                    publish(run / "authority.json", {"operationId": operation, "actor": actor,
                            "storageFixtureId": binding.storage_fixture_id,
                            "reservationKey": "owned-root-identity", "hostBoot": HOST_BOOT})
                stdout, stderr = child.communicate(timeout=5)
            finally:
                # This is the isolated test interpreter, never a native Tart actor.
                if child.poll() is None:
                    child.terminate()
                    stdout, stderr = child.communicate(timeout=2)

            calls_path = base / "adapter-calls.jsonl"
            calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
            terminal_path = run / "child-terminal.json"
            result = {
                "returncode": child.returncode, "stdout": stdout.decode(), "stderr": stderr.decode(),
                "actorPublished": actor_path.exists(), "childPublished": (run / "child.json").exists(),
                "adapterCalls": calls, "rootIdentity": root_identity, "admittedIdentity": admitted_identity,
                "terminal": json.loads(terminal_path.read_bytes()) if terminal_path.exists() else None,
                "programSha256": program.digest,
                "implementationSha256": hashlib.sha256(Path(implementation.__file__).read_bytes()).hexdigest(),
            }
            evidence = os.environ.get("VPN_CONTROL_TEST_TART_ROOT_IDENTITY_EVIDENCE")
            if evidence:
                directory = Path(evidence) / evidence_name
                directory.mkdir(parents=True, exist_ok=False)
                (directory / "emitted-owner.py").write_bytes(program.source)
                (directory / "stdout.bin").write_bytes(stdout)
                (directory / "stderr.bin").write_bytes(stderr)
                (directory / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
            return result

    def test_real_renderer_round_trip_accepts_unchanged_five_field_identity(self):
        result = self.execute_owner(self.implementation(), evidence_name="unchanged")
        self.assertEqual(result["returncode"], 0, result)
        self.assertTrue(result["actorPublished"], result)
        self.assertTrue(result["childPublished"], result)
        self.assertEqual(len(result["rootIdentity"]), 5)
        self.assertEqual(result["admittedIdentity"], result["rootIdentity"])
        self.assertEqual([call[0] for call in result["adapterCalls"]], ["list", "run"], result)
        self.assertEqual(result["terminal"]["delegateOutcome"], "guest_did_stop", result)

    def test_each_emitted_identity_field_must_match_before_actor_publication(self):
        for field in FIELD_INDEX:
            with self.subTest(field=field):
                result = self.execute_owner(self.implementation(), admitted_drift=field,
                                            evidence_name="changed-" + field)
                self.assertEqual(result["returncode"], 1, result)
                self.assertIn("run_owner_root_changed", result["stderr"], result)
                self.assertFalse(result["actorPublished"], result)
                self.assertFalse(result["childPublished"], result)
                self.assertEqual(result["adapterCalls"], [], result)

    def test_matching_identity_still_requires_exact_private_directory_mode(self):
        # 0750 passes private.Directory's no-group-write rule, but is not the
        # owner's required 0700. Equality alone must not admit it.
        result = self.execute_owner(self.implementation(), mode=0o750, evidence_name="unsafe-mode")
        self.assertEqual(result["returncode"], 1, result)
        self.assertIn("run_owner_root_changed", result["stderr"], result)
        self.assertEqual(result["admittedIdentity"], result["rootIdentity"])
        self.assertEqual(stat.S_IMODE(result["rootIdentity"][2]), 0o750)
        self.assertFalse(result["actorPublished"], result)
        self.assertEqual(result["adapterCalls"], [], result)

    def test_retained_whole_renderer_reproduces_pre_submission_rejection(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        self.assertFalse(provenance["nativeOwnerSubmitted"])
        self.assertFalse(provenance["actualNativeFailure"])
        for name, digest in (("lifecycle.before.source", BEFORE_SHA256),
                             ("static-review-rejected.json", REJECTION_SHA256)):
            raw = (FIXTURES / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            self.assertEqual(provenance["files"][name], {"bytes": len(raw), "sha256": digest})
        result = self.execute_owner(retained_beforeimage(), evidence_name="retained-before")
        self.assertEqual(result["returncode"], 1, result)
        self.assertIn("run_owner_root_changed", result["stderr"], result)
        self.assertEqual(len(result["rootIdentity"]), 5)
        self.assertEqual(result["rootIdentity"], result["admittedIdentity"])
        self.assertFalse(result["actorPublished"], result)
        self.assertEqual(result["adapterCalls"], [], result)


if __name__ == "__main__":
    unittest.main()
