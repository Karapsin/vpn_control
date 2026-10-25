"""Explicit lease VM targeting through the complete generated executable caller."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_leases as leases
from agent_tools import readiness_lease_workflow as flow
from agent_tools.tests import test_readiness_lease_workflow as facade_fixtures


class LeaseTargetingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vc-lease-targets-")
        self.base = Path(self.tmp.name).resolve(); self.base.chmod(0o700)
        self.originals = []

    def tearDown(self):
        for root, operation, binding, generation in self.originals:
            end = time.monotonic() + 5
            while time.monotonic() < end:
                if jobs.observe(root, operation, binding, generation=generation)["state"] in {"terminal", "unsubmitted"}:
                    break
                time.sleep(.02)
            else:
                self.fail("original controlled caller did not close")
        self.tmp.cleanup()

    def controlled_call(self, module, *, public, machine="selected-B"):
        case = self.base / uuid.uuid4().hex; case.mkdir(mode=0o700)
        root = case / "jobs"; root.mkdir(mode=0o700)
        state = case / "targets.json"
        boot = str(uuid.uuid4())
        state.write_text(json.dumps({"emulator-9986": {"avd": "selected-A", "boot": boot, "value": "0", "writes": []},
                                     "emulator-9988": {"avd": "selected-B", "boot": str(uuid.uuid4()),
                                                       "value": "2", "writes": []}, "calls": []}))
        state.chmod(0o600)
        executable = case / "fixed-adb"
        source = '''
        import json,pathlib,sys
        path=pathlib.Path(STATE)
        value=json.loads(path.read_text());args=sys.argv[1:]
        assert args[:4]==['-H','127.0.0.1','-P','5040'] and args[4]=='-s'
        serial=args[5];target=value[serial];tail=args[6:];value['calls'].append(args)
        if tail==['emu','avd','name']:print(target['avd']+'\\nOK')
        elif tail==['shell','cat','/proc/sys/kernel/random/boot_id']:print(target['boot'])
        elif tail==['shell','settings','get','global','stay_on_while_plugged_in']:print(target['value'])
        elif tail[:5]==['shell','settings','put','global','stay_on_while_plugged_in'] and len(tail)==6:
            assert tail[5]in ['0','7'];target['value']=tail[5];target['writes'].append(tail[5])
        else:raise SystemExit(9)
        path.write_text(json.dumps(value))
        '''
        import textwrap
        executable.write_text("#!" + sys.executable + "\nSTATE=" + repr(str(state)) + "\n" + textwrap.dedent(source))
        executable.chmod(0o700)
        operation = str(uuid.uuid4())
        binding = jobs.current_binding("selected-transport", machine)
        generation = jobs.root_generation(root)
        self.originals.append((root, operation, binding, generation))
        with patch.object(module, "ADB_PATHS", module.ADB_PATHS | {str(executable)}):
            spec = module.LeaseSpec("android-emulator", .7, adb_path=str(executable), adb_serial="emulator-9986",
                                    adb_port=5040, guest_boot=boot, guest_avd="selected-A")
            rejected = None
            try:
                if public:
                    module.acquire(root, operation, binding, spec, generation=generation)
                else:
                    program = module._program(root, operation, binding, module._config(spec))
                    jobs.submit(root, operation, binding, program, generation=generation)
            except ValueError as error:
                rejected = str(error)
            end = time.monotonic() + 8
            while (root / operation).exists() and time.monotonic() < end:
                status = jobs.observe(root, operation, binding, generation=generation)
                if status["state"] == "terminal":
                    jobs.collect(root, operation, binding, generation=generation)
                    break
                time.sleep(.02)
            else:
                if (root / operation).exists():
                    self.fail("complete generated adb caller did not finish")
            result = module.inspect(root, operation, binding, generation=generation)
        return json.loads(state.read_text()), rejected, result, root / operation

    def test_causal_conflicting_declared_target_cannot_mutate_other_vm(self):
        self.causal_results = []
        fixture = Path(__file__).parent / "fixtures/readiness_lease_target_before.py"
        self.assertEqual("40a7c4b7271487fe60df3e3a2f80942b2270902e7cdc5504dbf26215bbec4873",
                         hashlib.sha256(fixture.read_bytes()).hexdigest())
        name = "agent_tools._lease_target_before"
        spec = importlib.util.spec_from_file_location(name, fixture)
        before = importlib.util.module_from_spec(spec); sys.modules[name] = before
        try:
            spec.loader.exec_module(before)
            for public in (True, False):
                with self.subTest(public=public):
                    red, error, result, _ = self.controlled_call(before, public=public)
                    self.assertIsNone(error)
                    self.assertEqual(["7", "0"], red["emulator-9986"]["writes"],
                                     "unfixed exact caller must demonstrate wrong-A mutation despite declared B")
                    self.assertEqual([], red["emulator-9988"]["writes"])
                    self.assertEqual("expired", result["state"])
                    green, error, result, admitted = self.controlled_call(leases, public=public)
                    self.causal_results.append({"entrypoint": "acquire" if public else "generated_owner",
                        "declaredMachine": "selected-B", "explicitAdbTarget": "selected-A",
                        "beforeActualCalls": red["calls"], "beforeActualWritesA": red["emulator-9986"]["writes"],
                        "beforeActualWritesB": red["emulator-9988"]["writes"],
                        "afterActualCalls": green["calls"], "afterActualWritesA": green["emulator-9986"]["writes"],
                        "afterActualWritesB": green["emulator-9988"]["writes"],
                        "afterPreAdmissionError": error, "afterResult": result, "afterAdmitted": admitted.exists()})
                    self.assertEqual([], green["calls"], "wrong target must be rejected before any adb dispatch")
                    self.assertEqual([], green["emulator-9986"]["writes"])
                    self.assertEqual([], green["emulator-9988"]["writes"])
                    if public:
                        self.assertEqual("lease_target_binding_mismatch", error)
                        self.assertFalse(admitted.exists(), "direct pre-admission refusal must not consume an operation")
                    else:
                        self.assertIsNone(error)
                        self.assertEqual(("failed", "lease_target_binding_mismatch"),
                                         (result["state"], result["reason"]))
        finally:
            sys.modules.pop(name, None)

    def test_matching_declared_avd_uses_only_explicit_serial_without_default_vm(self):
        state, error, result, _ = self.controlled_call(leases, public=True, machine="selected-A")
        self.assertIsNone(error)
        self.assertEqual(("expired", True), (result["state"], result["restored"]))
        self.assertEqual(["7", "0"], state["emulator-9986"]["writes"])
        self.assertEqual([], state["emulator-9988"]["writes"])
        self.assertTrue(state["calls"])
        self.assertTrue(all(row[4:6] == ["-s", "emulator-9986"] for row in state["calls"]))

    def test_facade_rejects_missing_or_extra_target_selectors_before_lookup(self):
        operation = str(uuid.uuid4())
        with patch.object(flow.fixtures, "registered_fixture", side_effect=AssertionError("lookup forbidden")):
            for action in ("acquire", "status", "cancel", "reconcile"):
                inputs = {"operationId": operation, **({"ttlSeconds": 1} if action == "acquire" else {})}
                for invalid in (inputs, {**inputs, "fixtureId": "", "vm": "other"},
                                {**inputs, "fixtureId": "explicit", "adbSerial": "emulator-9988"}):
                    with self.subTest(action=action, inputs=invalid), self.assertRaises(ValueError):
                        flow.workflow(self.base, action, invalid)
        self.assertEqual([], list(self.base.iterdir()))

    def test_other_fixture_with_original_uuid_cannot_cancel_or_reconcile_original_target(self):
        # Reuse the actual detached controlled-owner facade fixture. No fake
        # registration or provider success is introduced by this target test.
        fixture = facade_fixtures.LeaseWorkflowTests("runTest")
        fixture.setUp()
        try:
            operation, setting, root, binding, generation = fixture.original(ttl=3)
            fixture.wait(operation, {"active"})
            original = jobs._record(root / operation / "intent.json")
            with patch.object(flow.fixtures, "registered_fixture", side_effect=AssertionError("wrong target lookup forbidden")):
                for action in ("status", "cancel", "reconcile"):
                    result = flow.workflow(fixture.root, action,
                                           {"fixtureId": "different-explicit-vm", "operationId": operation})
                    self.assertFalse(result["ok"])
                    self.assertFalse((root / operation / "lease-cancel.json").exists())
                    self.assertFalse((root / operation / "lease-restore-admission.json").exists())
                    self.assertEqual("awake", setting.read_text())
                    self.assertEqual(original, jobs._record(root / operation / "intent.json"))
                fixture.call("cancel", operation)
                self.assertTrue(fixture.wait(operation, {"cancelled"})["restored"])
                self.assertEqual("sleep", setting.read_text())
                self.assertEqual(original, jobs._record(root / operation / "intent.json"))
        finally:
            fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
