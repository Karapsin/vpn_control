"""Public facade guards plus actual detached, original local reconciliation."""
from dataclasses import asdict
import json
import hashlib
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_leases as leases
from agent_tools import readiness_lease_workflow as flow
from agent_tools.native_next_action import next_action


class LeaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpn-control-lease-facade-test-")
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.fixture = "controlled-lease-observation"
        self.owned = []

    def tearDown(self):
        for operation, root, binding, generation in self.owned:
            try:
                leases.cancel(root, operation, binding, generation=generation)
            except (OSError, ValueError):
                pass
            end = time.monotonic() + 8
            while time.monotonic() < end:
                if jobs.observe(root, operation, binding, generation=generation)["state"] in {"terminal", "unsubmitted"}:
                    break
                time.sleep(.02)
            else:
                self.fail("original fixture owner did not become terminal")
        self.tmp.cleanup()

    def original(self, ttl=3, *, submit=True, program_transform=None):
        """Private test custody: metadata + real fixed controlled-setting job.

        This does not register a fake guest or claim acquisition qualification.
        It exercises the observation/cancellation side of an original admission.
        """
        state, targets = flow._paths(self.root, self.fixture, create=True)
        operation = str(uuid.uuid4())
        spec = leases.LeaseSpec("android-emulator", ttl, adb_path="/usr/bin/adb",
                                adb_serial="emulator-9988", adb_port=5999,
                                guest_boot=str(uuid.uuid4()), guest_avd="owned-observation-avd")
        key = flow._key(spec, spec.guest_avd)
        root = flow._directory(targets / key, create=True)
        binding = jobs.current_binding("android-lease-" + key, spec.guest_avd)
        generation = jobs.root_generation(root)
        setting = self.root / (operation + ".setting")
        setting.write_text("sleep")
        setting.chmod(0o600)
        program = leases._program(root, operation, binding,
                                  {"backend": "controlled", "ttlSeconds": ttl, "setting": str(setting)})
        if program_transform is not None:
            program=jobs.Program(program.purpose,program_transform(program.source),program.stream_limit)
        value = {"schemaVersion": 1, "fixtureId": self.fixture, "operationId": operation,
                 "provider": "android-emulator", "ttlSeconds": ttl, "binding": asdict(binding),
                 "jobRootKey": key, "jobRootGeneration": list(generation), "leaseSpec": asdict(spec),
                 "readyIdentities": ["owned-target", spec.guest_avd, "owned-connection", spec.guest_boot,
                                     "android-user:0", spec.guest_boot + ":user:0"],
                 "sources": dict(flow._LOADED), "programSha256": program.digest}
        jobs._create(state / (operation + ".program.py"), program.source)
        jobs._publish(state / (operation + ".json"), value)
        if submit:
            jobs.submit(root, operation, binding, program, generation=generation)
        self.owned.append((operation, root, binding, generation))
        return operation, setting, root, binding, generation

    def call(self, action, operation, **extra):
        return flow.workflow(self.root, action, {"fixtureId": self.fixture, "operationId": operation, **extra})

    def wait(self, operation, states):
        end = time.monotonic() + 8
        while time.monotonic() < end:
            result = self.call("status", operation)
            if result["state"] in states and (result["state"] == "active" or result.get("jobState") == "terminal"):
                return result
            time.sleep(.02)
        self.fail("original lease state not reached: " + json.dumps(result))

    def test_local_status_cancel_use_original_without_registry_probe(self):
        operation, setting, _, _, _ = self.original()
        with patch.object(flow.fixtures, "registered_fixture", side_effect=AssertionError("guest probe forbidden")):
            self.assertEqual(self.wait(operation, {"active"})["operationId"], operation)
            self.assertEqual(setting.read_text(), "awake")
            self.call("cancel", operation)
            result = self.wait(operation, {"cancelled"})
        self.assertTrue(result["restored"])
        self.assertEqual(setting.read_text(), "sleep")

    def test_fresh_process_can_cancel_original_and_retain_identity(self):
        operation, setting, root, binding, generation = self.original()
        self.wait(operation, {"active"})
        original_owner = jobs._record(root / operation / "owner.json")
        code = "\n".join([
            "from agent_tools import readiness_lease_workflow as f",
            "import json",
            "print(json.dumps(f.workflow(" + repr(str(self.root)) + ",'cancel'," +
            repr({"fixtureId": self.fixture, "operationId": operation}) + ")))",
        ])
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[2],
                                check=True, capture_output=True, timeout=5)
        self.assertEqual(json.loads(result.stdout)["operationId"], operation)
        self.wait(operation, {"cancelled"})
        self.assertEqual(jobs._record(root / operation / "owner.json"), original_owner)
        self.assertEqual(setting.read_text(), "sleep")

    def test_repeat_acquire_observes_same_source_owner_and_expiry(self):
        operation, _, root, _, _ = self.original(ttl=.8)
        self.wait(operation, {"active"})
        before = jobs._record(root / operation / "intent.json")
        with patch.object(flow.fixtures, "registered_fixture", side_effect=AssertionError("repeat guest probe forbidden")):
            for _ in range(3):
                result = self.call("acquire", operation, ttlSeconds=.8)
                self.assertEqual(result["operationId"], operation)
        self.wait(operation, {"expired"})
        self.assertEqual(jobs._record(root / operation / "intent.json"), before)

    def test_conflicting_repeat_input_never_changes_original(self):
        operation, _, root, _, _ = self.original()
        self.wait(operation, {"active"})
        intent = jobs._record(root / operation / "intent.json")
        result = self.call("acquire", operation, ttlSeconds=4)
        self.assertEqual(result["reason"], "lease_original_inputs_conflict")
        self.assertFalse(result["replayAllowed"])
        self.assertEqual(jobs._record(root / operation / "intent.json"), intent)

    def external_original(self, *, submit=True):
        """Exercise the executor boundary with a real controlled POSIX owner.

        This is protocol coverage, not Windows/Tart native qualification. The
        actual registered executor remains responsible for native ownership.
        """
        operation, setting, root, binding, generation = self.original(submit=submit)
        state, _ = flow._paths(self.root,self.fixture,create=False)
        old=jobs._record(state/(operation+'.json'))
        snapshot={'provider':'raw-qemu-windows','controlledOriginal':operation}
        value={'schemaVersion':2,'fixtureId':self.fixture,'operationId':operation,
               'provider':'raw-qemu-windows','ttlSeconds':3,'executor':snapshot,
               'readyIdentities':old['readyIdentities'],'sources':dict(flow._LOADED)}
        (state/(operation+'.json')).unlink()
        jobs._publish(state/(operation+'.json'),value)
        class Executor:
            provider='raw-qemu-windows'
            def observe(self, original):
                if original!=operation: raise ValueError('original_identity_changed')
                result=leases.inspect(root,original,binding,generation=generation)
                if result['state']=='unsubmitted':
                    result.update(reason='original_admission_absent',nextAction='resolve_blocker')
                result['ok']=result['state']!='unknown'
                return result
            def cancel(self, original):
                leases.cancel(root,original,binding,generation=generation)
                return self.observe(original)
            def submit(self,*args):
                raise AssertionError('replacement forbidden')
        def factory(repository, original):
            if original!=snapshot: raise ValueError('original_snapshot_changed')
            return Executor()
        return operation,setting,root,factory

    def test_saved_executor_reconciles_real_original_without_registry_or_resubmission(self):
        operation,setting,root,factory=self.external_original()
        with patch.object(flow.fixtures,'lease_executor_from_snapshot',side_effect=factory), \
             patch.object(flow.fixtures,'registered_fixture',side_effect=AssertionError('live readiness forbidden')):
            self.wait(operation,{'active'})
            owner=jobs._record(root/operation/'owner.json')
            self.assertEqual('active',self.call('acquire',operation,ttlSeconds=3)['state'])
            self.call('cancel',operation)
            terminal=self.wait(operation,{'cancelled'})
            self.assertEqual('terminal',terminal['jobState'])
            self.assertEqual(owner,jobs._record(root/operation/'owner.json'))
            self.assertEqual('sleep',setting.read_text())

    def test_saved_executor_cancel_before_dispatch_is_durable_and_never_submits(self):
        operation,setting,root,factory=self.external_original(submit=False)
        with patch.object(flow.fixtures,'lease_executor_from_snapshot',side_effect=factory), \
             patch.object(flow.fixtures,'registered_fixture',side_effect=AssertionError('live readiness forbidden')):
            for action in ['cancel','status','acquire']:
                result=self.call(action,operation,**({'ttlSeconds':3} if action=='acquire' else {}))
                self.assertEqual('cancelled',result['state'])
                self.assertEqual('none',result['nextAction'])
        self.assertFalse((root/operation).exists())
        self.assertEqual('sleep',setting.read_text())

    def test_cancel_proven_unsubmitted_never_builds_or_submits_job(self):
        operation, setting, root, _, _ = self.original(submit=False)
        with patch.object(flow.fixtures, "registered_fixture", side_effect=AssertionError("guest probe forbidden")):
            result = self.call("cancel", operation)
            self.assertEqual(result["state"], "cancelled")
            self.assertEqual(self.call("status", operation)["state"], "cancelled")
            self.assertEqual(self.call("acquire", operation, ttlSeconds=3)["state"], "cancelled")
        self.assertFalse((root / operation).exists())
        self.assertEqual(setting.read_text(), "sleep")

    def test_root_generation_change_blocks_without_replacing_original(self):
        operation, _, root, binding, generation = self.original(ttl=.2)
        self.wait(operation, {"expired"})
        # Original owner is terminal before moving its preserved evidence.
        retained = root.with_name(root.name + "-retained")
        root.rename(retained)
        root.mkdir(mode=0o700)
        self.owned = [(operation, retained, binding, jobs.root_generation(retained))]
        result = self.call("status", operation)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["replayAllowed"])
        self.assertEqual(list(root.iterdir()), [])

    def test_unknown_local_observation_creates_no_state_and_probes_nothing(self):
        operation = str(uuid.uuid4())
        before = list(self.root.iterdir())
        with patch.object(flow.fixtures, "registered_fixture", side_effect=AssertionError("guest probe forbidden")):
            for action in ("status", "cancel"):
                result = self.call(action, operation)
                self.assertEqual(result["state"], "unknown")
        self.assertEqual(before, list(self.root.iterdir()))

    def test_first_acquisition_requires_actual_registration(self):
        operation = str(uuid.uuid4())
        result = self.call("acquire", operation, ttlSeconds=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(any(self.root.rglob("child-admission")))

    def test_public_schema_rejects_paths_programs_ownership_and_private_input(self):
        operation = str(uuid.uuid4())
        base = {"fixtureId": self.fixture, "operationId": operation, "ttlSeconds": 1}
        for key in ("path", "root", "program", "binding", "owned", "credential", "adbSerial"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                flow.workflow(self.root, "acquire", {**base, key: "PRIVATE-MARKER"})
        for ttl in (float("nan"), float("inf"), 18001, 0, True, "1"):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                flow.workflow(self.root, "acquire", {**base, "ttlSeconds": ttl})
        with self.assertRaises(ValueError):
            flow.workflow(self.root, "status", base)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_causal_original_detached_owner_ack_gap_only_observes_same_uuid(self):
        # Stop the actual detached owner at a real socket before its first
        # ACK. The exact original source/intent has already been admitted.
        directory=Path(__file__).parent/'fixtures/lease_initial_ack_before'
        path=directory/'readiness_lease_workflow.py'
        provenance=json.loads((directory/'provenance.json').read_text())
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),provenance['fixtureSha256'])
        spec=importlib.util.spec_from_file_location('lease_initial_ack_before',path)
        before=importlib.util.module_from_spec(spec);spec.loader.exec_module(before)
        original_popen=subprocess.Popen
        with socket.socket()as gate:
            gate.bind(('127.0.0.1',0));gate.listen(1);gate.settimeout(8)
            port=gate.getsockname()[1]
            bootstrap=('import os,socket,sys\nwith socket.create_connection(("127.0.0.1",'+str(port)+'),timeout=15)as gate:\n'
                       ' gate.sendall(b"original-ack-gate");assert gate.recv(1)==b"1"\n'
                       'os.execv(sys.executable,[sys.executable]+sys.argv[1:])\n')
            def paused(argv,**kwargs):
                if len(argv)<6 or argv[-2]!='--own':
                    return original_popen(argv,**kwargs)
                self.assertEqual(['-I','-B'],argv[1:3])
                self.assertEqual(['--own'],argv[-2:-1])
                return original_popen([argv[0],'-I','-B','-c',bootstrap,*argv[1:]],**kwargs)
            with patch.object(jobs.subprocess,'Popen',side_effect=paused):
                operation,setting,root,binding,generation=self.original(ttl=3)
            channel,_=gate.accept()
            with channel:
                try:
                    self.assertEqual(b'original-ack-gate',channel.recv(64))
                    state,targets=flow._paths(self.root,self.fixture,create=False)
                    admission=flow._admission(state,targets,self.fixture,operation)
                    red=before._status(admission)
                    self.assertEqual('record_unavailable',red['reason'])
                    self.assertFalse(red['ok'])
                    self.assertEqual('resolve_blocker',next_action('vm_workflow','readiness-lease-acquire',red)['kind'])
                    green=self.call('status',operation)
                    self.assertEqual('unknown',green['state'])
                    self.assertEqual('original_admission_pending',green['reason'])
                    self.assertTrue(green['ok'])
                    continuation=next_action('vm_workflow','readiness-lease-status',green)
                    self.assertEqual('observe_original',continuation['kind'])
                    self.assertEqual(operation,continuation['action']['args']['inputs']['operationId'])
                    original_intent=jobs._record(root/operation/'intent.json')
                    with patch.object(jobs,'submit',side_effect=AssertionError('consumed original launch must not replay')):
                        again=self.call('acquire',operation,ttlSeconds=3)
                    self.assertEqual(green,again)
                    self.assertEqual(original_intent,jobs._record(root/operation/'intent.json'))
                    self.assertEqual('sleep',setting.read_text(),'pending ACK is never GUI readiness')
                finally:
                    channel.sendall(b'1')
            self.wait(operation,{'active'})
            self.call('cancel',operation)
            self.assertTrue(self.wait(operation,{'cancelled'})['restored'])
            self.assertEqual('sleep',setting.read_text())

    def test_pending_ack_corrupt_receipts_fences_source_and_age_fail_closed(self):
        operation,_,root,binding,generation=self.original(submit=False)
        state,targets=flow._paths(self.root,self.fixture,create=False)
        admission=flow._admission(state,targets,self.fixture,operation)
        value=admission[0];job=root/operation;job.mkdir(mode=0o700)
        intent={'schemaVersion':1,'operationId':operation,'binding':asdict(binding),'purpose':'temporary-keep-awake-v1',
                'programSha256':value['programSha256'],'streamLimit':4096,'generation':str(uuid.uuid4())}
        jobs._publish(job/'intent.json',intent)
        jobs._create(job/'program.py',jobs._read(state/(operation+'.program.py'),jobs.MAX_PROGRAM_BYTES))
        jobs._create(job/'owner.py',jobs.owner_source())
        self.assertEqual('original_admission_pending',self.call('status',operation)['reason'])
        for filename in ('owner.json','terminal.json','child-admission','lease-original.json','lease-acquired.json','lease-terminal.json','lease-cancel.json'):
            with self.subTest(filename=filename):
                path=job/filename;jobs._create(path,b'PRIVATE-MALFORMED-MARKER')
                result=self.call('status',operation)
                self.assertFalse(result['ok'])
                self.assertNotIn('PRIVATE-MALFORMED-MARKER',json.dumps(result))
                self.assertEqual('resolve_blocker',next_action('vm_workflow','readiness-lease-status',result)['kind'])
                path.unlink()
        (job/'owner.json').symlink_to(job/'absent-private-owner')
        self.assertFalse(self.call('status',operation)['ok']);(job/'owner.json').unlink()
        saved=(job/'program.py').read_bytes();(job/'program.py').write_bytes(b'changed fixed source')
        self.assertFalse(self.call('status',operation)['ok']);(job/'program.py').write_bytes(saved)
        saved=(job/'owner.py').read_bytes();(job/'owner.py').write_bytes(b'changed owner source')
        self.assertFalse(self.call('status',operation)['ok']);(job/'owner.py').write_bytes(saved)
        old=time.time()-flow.readiness.NORMAL_BUDGET-1;os.utime(job/'intent.json',(old,old))
        result=self.call('status',operation)
        self.assertEqual('lease_original_activation_unresolved',result['reason'])
        self.assertFalse(result['ok'])
        self.assertEqual([],list(job.glob('child-admission')))
        # No process was submitted in this intentionally lost-launch fixture.
        # Its immutable consumed intent stays UNKNOWN, and teardown must not
        # wait for a nonexistent owner or manufacture a terminal receipt.
        self.owned=[]

    def test_live_original_wrapper_before_lease_acquisition_is_starting_never_ready(self):
        with socket.socket()as gate:
            gate.bind(('127.0.0.1',0));gate.listen(1);gate.settimeout(8)
            port=gate.getsockname()[1]
            bootstrap=('\nimport socket\nwith socket.create_connection(("127.0.0.1",'+str(port)+'),timeout=15)as gate:\n'
                       ' gate.sendall(b"original-activation-gate");assert gate.recv(1)==b"1"\n')
            def transform(raw):
                result=raw.replace(b'\nlease_run(',bootstrap.encode()+b'\nlease_run(')
                self.assertNotEqual(raw,result)
                return result
            operation,setting,root,binding,generation=self.original(ttl=3,program_transform=transform)
            channel,_=gate.accept()
            with channel:
                try:
                    self.assertEqual(b'original-activation-gate',channel.recv(64))
                    result=self.call('status',operation)
                    self.assertEqual('starting',result['state'])
                    self.assertEqual('running',result['jobState'])
                    self.assertTrue(result['ok'])
                    self.assertEqual('sleep',setting.read_text())
                    guidance=next_action('vm_workflow','readiness-lease-status',result)
                    self.assertEqual('observe_original',guidance['kind'])
                    self.assertEqual(operation,guidance['action']['args']['inputs']['operationId'])
                finally:channel.sendall(b'1')
            self.wait(operation,{'active'})
            self.call('cancel',operation)
            self.assertTrue(self.wait(operation,{'cancelled'})['restored'])


if __name__ == "__main__":
    unittest.main()
