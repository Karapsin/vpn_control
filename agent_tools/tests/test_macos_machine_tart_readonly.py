"""Fixed Tart readback is bounded, identity-bound, and mutation-inert."""
from __future__ import annotations

import json
from types import SimpleNamespace
import unittest

from agent_tools import macos_machine_acceptance as gate
from agent_tools import macos_machine_tart_readonly as subject


SOURCE = "a" * 40


class TartReadOnlyTest(unittest.TestCase):
    def observation(self):
        return {"schemaVersion": 1, "sourceSha": SOURCE, **gate._fixed_paths({"sourceSha": SOURCE}),
                "baseDevice": 1, "baseInode": 2, "baseRootOwned": True,
                "baseSignatureValid": True, "baseJarSha256": "b" * 64,
                "baseDmgSha256": "c" * 64, "targetDmgSha256": "d" * 64}

    def test_guest_read_uses_fixed_tart_argv_and_cannot_admit_native_action(self):
        calls = []
        def runner(argv, **options):
            calls.append((argv, options))
            if argv[:2] == ["tart", "list"]:
                return SimpleNamespace(returncode=0, stdout=json.dumps([
                    {"Name": gate.VM_NAME, "Source": "local", "Running": True, "State": "running"}]), stderr="")
            return SimpleNamespace(returncode=0, stdout=json.dumps(self.observation()), stderr="")
        provider = subject.TartReadOnlyProvider(runner=runner)
        result = provider.observe_admission(gate.VM_NAME, SOURCE)
        self.assertEqual(result["resourceAdmitted"], False)
        self.assertEqual(result["ownerReady"], False)
        self.assertEqual(calls[0][0], ["tart", "list", "--format", "json"])
        self.assertEqual(calls[1][0][:4], ["tart", "exec", gate.VM_NAME, "/usr/bin/python3"])
        self.assertEqual(calls[1][0][-1], SOURCE)
        self.assertEqual(calls[1][1]["timeout"], 120)
        self.assertNotIn("password", repr(calls).lower())
        with self.assertRaisesRegex(ValueError, "cannot submit"):
            provider.submit_public(gate.VM_NAME, object())
        with self.assertRaisesRegex(ValueError, "cannot authorize"):
            provider.authorize_visible_prompt(gate.VM_NAME, "job", "operation")

    def test_wrong_guest_source_or_path_rejects_and_never_returns_identity(self):
        value = self.observation()
        value["app"] = "/Applications/other.app"
        def runner(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                {"Name": gate.VM_NAME, "Source": "local", "Running": True, "State": "running"}]
                if argv[:2] == ["tart", "list"] else value), stderr="")
        provider = subject.TartReadOnlyProvider(runner=runner)
        with self.assertRaisesRegex(ValueError, "identity changed"):
            provider.observe_admission(gate.VM_NAME, SOURCE)
        with self.assertRaisesRegex(ValueError, "source or VM"):
            provider.observe_admission("other-vm", SOURCE)

    def test_stopped_vm_fails_before_tart_exec(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout=json.dumps([
                {"Name": gate.VM_NAME, "Source": "local", "Running": False, "State": "stopped"}]), stderr="")
        provider = subject.TartReadOnlyProvider(runner=runner)
        with self.assertRaisesRegex(ValueError, "not already running"):
            provider.observe_admission(gate.VM_NAME, SOURCE)
        self.assertEqual(calls, [["tart", "list", "--format", "json"]])


if __name__ == "__main__":
    unittest.main()
