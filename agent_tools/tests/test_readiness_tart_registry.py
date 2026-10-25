import os
import json
import hashlib
from dataclasses import replace
from uuid import uuid4
from pathlib import Path
import tempfile
import time
import shutil
import subprocess
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools import readiness_fixture_registry as registry
from agent_tools import readiness_tart_registry as custody_module


@unittest.skipUnless(os.name == "posix", "Tart custody uses POSIX owner locks")
class TartCustodyTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(); self.root.chmod(0o700)
        self.lifecycle = self.root / "lifecycle"; self.lifecycle.mkdir(mode=0o700)
        (self.lifecycle / "jobs").mkdir(mode=0o700)
        self.current = {"state": "running", "actor": {"pid": 123, "birth": "actual"}, "jobState": "running", "operationId": "native"}
        self.custody = object.__new__(custody_module.TartCustody)
        self.custody.root = self.root; self.custody.lifecycle_root = self.lifecycle
        self.custody.descriptor = {"provider": "tart-linux"}; self.custody._operator_held = False
        from types import SimpleNamespace
        self.custody.binding = SimpleNamespace(memory_mib=4096)
        self.custody.guard = lambda: dict(self.current)
        self.custody._pins = lambda: None
        self.custody._job_facts = lambda current: set()
        self.guest = {"jobVisibilityComplete": True, "runningJobs": [], "unknownJobs": [],
                      "processVisibilityComplete": True, "protectedProcesses": [], "installerRoles": [],
                      "installerLocks": [], "installerUpdates": [], "systemdJobs": "", "interactiveSessions": ""}
        patch = mock.patch.object(custody_module.visual, "_read_reservations", return_value={"linux": {"memory_mib": 4096, "pid": 123}})
        patch.start(); self.addCleanup(patch.stop)

    def test_only_held_actual_operator_scope_completes_idle_visibility(self):
        visibility, blockers = self.custody.idle_facts(self.guest)
        self.assertNotIn("operators", visibility)
        with self.custody.operator(deadline=time.monotonic()+1):
            visibility, blockers = self.custody.idle_facts(self.guest)
            self.assertEqual(visibility, readiness.IDLE_VISIBILITY)
            self.assertFalse(blockers)
            with self.custody.operator(deadline=time.monotonic()+1):
                self.assertTrue(self.custody._operator_held)
        self.assertFalse(self.custody._operator_held)

    def test_other_owned_fixture_claim_is_preserved_while_own_target_idle_is_proved(self):
        key=custody_module.visual._qualified_reservation_key("tart-linux","9"*64)
        self.custody.reservation_key=key
        reservations={"android":{"memory_mib":2048,"pid":999},key:{"memory_mib":4096,"pid":123}}
        with mock.patch.object(custody_module.visual,"_read_reservations",return_value=reservations), \
                self.custody.operator(deadline=time.monotonic()+1):
            visibility,blockers=self.custody.idle_facts(self.guest)
            self.assertEqual(visibility,readiness.IDLE_VISIBILITY);self.assertFalse(blockers)
        self.assertEqual(reservations["android"],{"memory_mib":2048,"pid":999})

    def test_lost_client_pending_claim_binds_original_tart_actor_once(self):
        from types import SimpleNamespace
        from agent_tools import readiness_tart,durable_remote_job as jobs
        self.custody.binding=SimpleNamespace(memory_mib=4096,fixture_root=self.root/"fixture",storage_fixture_id="owned")
        self.custody.reservation_key="recovery-test:tart-linux:"+"8"*64;key=self.custody.reservation_key
        self.custody.guard=lambda **kwargs:dict(self.current);self.custody._operator_held=True
        jobs._publish(self.lifecycle/"active.json",{"original":"durable-owner"})
        requirements=readiness.Requirements(frozenset({"guest_agent"}))
        ready=readiness.ReadyContext(str(uuid4()),"owned","machine","connection","boot",None,None,requirements)
        observed=readiness.Observation("owned","machine",connection="connection",boot="boot")
        reservations={"android":{"memory_mib":2048,"pid":0},key:{"memory_mib":4096,"pid":0}}
        plan={"directory":str(self.custody.binding.fixture_root),"state":"retained","writerPid":99}
        plans=mock.MagicMock();plans._read.return_value={"plans":{"owned":plan}}
        def bind(pid):
            self.assertEqual(pid,123);reservations[key]["pid"]=pid;plan["writerPid"]=pid
        with mock.patch.object(readiness_tart.TartBackend,"observe",return_value=observed), \
                mock.patch.object(custody_module.visual,"_read_reservations",return_value=reservations), \
                mock.patch.object(custody_module.storage,"StoragePlans",return_value=plans), \
                mock.patch.object(self.custody,"bind_start",side_effect=bind) as binding:
            hook=getattr(self.custody,"reconcile_ready",None)
            if hook:hook(ready,time.monotonic()+5)
            self.assertEqual(reservations[key]["pid"],123)
            if hook:hook(ready,time.monotonic()+5)
            self.assertEqual(binding.call_count,1)
        self.assertEqual(reservations["android"],{"memory_mib":2048,"pid":0})

    def test_missing_or_uncertain_guest_jobs_never_receive_idle_proof(self):
        with self.custody.operator(deadline=time.monotonic()+1):
            for field in ("jobVisibilityComplete", "runningJobs", "unknownJobs"):
                value = dict(self.guest); value.pop(field)
                visibility, _ = self.custody.idle_facts(value)
                self.assertNotIn("unknown_jobs", visibility)
            for field in ("runningJobs", "unknownJobs"):
                value = dict(self.guest); value[field] = [{"pid": 456, "birth": "actual", "role": "sentinel"}]
                _, blockers = self.custody.idle_facts(value)
                self.assertIn("running_jobs" if field == "runningJobs" else "unknown_jobs", blockers)

    def test_guest_packet_registry_closes_original_admission_and_never_trusts_terminal_flags(self):
        from types import SimpleNamespace
        from agent_tools import durable_remote_job as jobs, ssh_program_execution_remote as protocol
        operation = str(uuid4()); boot = str(uuid4())
        self.custody.binding = SimpleNamespace(memory_mib=4096, machine="1"*32,
                                              expected_uid=1000, expected_account="admin")
        self.custody.guard = lambda **kwargs: dict(self.current)
        program = {"language":"python3","source":"print('sentinel')","args":[],"cwd":"/tmp",
                   "targetContext":{"kind":"ssh","uid":1000,"principal":"admin","home":"/home/admin","bootId":boot}}
        packet = {"operationId":operation,"remoteRoot":"/tmp/vpn-control-program-1000-"+operation,
                  "generation":[1,2],"binding":{"target":"job-target","machine":"1"*32,"boot":boot,"account":"1000"},
                  "requestSha256":hashlib.sha256(protocol._canonical(program)).hexdigest(),
                  "ownerSourceSha256":hashlib.sha256(jobs.owner_source()).hexdigest()}
        directory = self.root/".runtime/native-counter";directory.mkdir(parents=True,mode=0o700)
        admission = directory/"original.json"
        value = {"operationId":operation,"provider":"tart-linux","packet":packet,
                 "program":program,"counterPath":"/tmp/owned-counter"}
        admission.write_text(json.dumps(value));admission.chmod(0o600)
        fixture = SimpleNamespace(adapter=SimpleNamespace(backend=SimpleNamespace(custody=self.custody)))
        with mock.patch.object(registry,"registered_fixture",return_value=fixture):
            self.assertEqual(custody_module.admit_guest_program_packet(self.root,"owned",admission),packet)
            original = (self.lifecycle/"guest-programs"/(operation+".json")).read_bytes()
            self.assertEqual(custody_module.admit_guest_program_packet(self.root,"owned",admission),packet)
            self.assertEqual((self.lifecycle/"guest-programs"/(operation+".json")).read_bytes(),original)
        self.assertEqual(self.custody.guest_jobs,[packet])
        value["program"]["source"]="print('changed')"
        admission.write_text(json.dumps(value));admission.chmod(0o600)
        with self.assertRaisesRegex(registry.FixtureRegistryError,"tart_guest_packet_changed"):
            _ = self.custody.guest_jobs

    def test_unrecognized_guest_packet_cannot_be_adopted(self):
        from types import SimpleNamespace
        from agent_tools import durable_remote_job as jobs
        binding = SimpleNamespace(machine="1"*32, expected_uid=1000)
        operation=str(uuid4())
        packet={"remoteRoot":"/tmp/foreign","generation":[1,2],"operationId":operation,
                "binding":{"target":"job","machine":"1"*32,"boot":str(uuid4()),"account":"1000"},
                "requestSha256":"0"*64,"ownerSourceSha256":hashlib.sha256(jobs.owner_source()).hexdigest()}
        with self.assertRaisesRegex(registry.FixtureRegistryError,"tart_guest_packet_invalid"):
            custody_module._guest_packet(packet,binding)

    def test_stopped_source_refresh_preserves_lineage_and_never_runs_guest_or_power(self):
        from agent_tools import durable_remote_job as jobs, readiness_tart
        target="owned-tart";host=jobs.current_binding(target,"test-host")
        directory=self.root/".rag_index/readiness-fixtures";directory.mkdir(parents=True,mode=0o700)
        descriptor={"schemaVersion":1,"fixtureId":"old","provider":"tart-linux","qualifiedRecoveries":["start","reboot"],
          "binding":{"target":target,"machine":"1"*32,"vmName":"vpn-tool-recovery-tart-owned","tartBinary":"/fixed/tart",
                     "fixtureRoot":str(self.root/"vpn-tool-recovery-tart-owned"),"expectedAccount":"admin","expectedUid":1000,"memoryMiB":4096,"storageFixtureId":"owned-plan"},
          "lifecycleRoot":str(self.lifecycle),"hostBinding":host.__dict__,"jobRootGeneration":list(jobs.root_generation(self.lifecycle/"jobs")),
          "guestBaseline":{},"qualification":{},"seedActor":{"pid":123},"sources":{"old":"source"}}
        path=directory/"old.json";path.write_text(json.dumps(descriptor));path.chmod(0o600)
        original=path.read_bytes();plan=mock.MagicMock();plan._read.return_value={"plans":{"owned-plan":{"directory":str(self.root/"vpn-tool-recovery-tart-owned"),"state":"retained","writerPid":123}}}
        stopped={"state":"stopped","jobState":"terminal","actor":{"pid":123,"birth":"original"},"operationId":"same-original"}
        with mock.patch.object(custody_module.TartCustody,"_pins"), \
                mock.patch.object(readiness_tart,"current_instance",return_value=stopped), \
                mock.patch.object(jobs,"_birth",return_value=None), \
                mock.patch.object(custody_module.storage,"StoragePlans",return_value=plan), \
                mock.patch.object(custody_module,"_sources",return_value={"new":"source"}), \
                mock.patch.object(custody_module,"load_registered_fixture",side_effect=lambda root,fixture_id,value,pin:value), \
                mock.patch.object(readiness_tart.TartBackend,"_guest") as guest:
            refreshed=custody_module.refresh_stopped_tart_linux(self.root,"old","new")
            self.assertEqual(refreshed["qualifiedRecoveries"],["start"])
            self.assertEqual(refreshed["lifecycleRoot"],descriptor["lifecycleRoot"])
            self.assertEqual(refreshed["jobRootGeneration"],descriptor["jobRootGeneration"])
            self.assertEqual(refreshed["binding"],descriptor["binding"])
            guest.assert_not_called()
            with mock.patch.object(custody_module.TartCustody,"_job_facts",return_value={"unknown_jobs"}):
                with self.assertRaisesRegex(registry.FixtureRegistryError,"tart_original_owner_unresolved"):
                    custody_module.refresh_stopped_tart_linux(self.root,"old","blocked")
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse((directory/"blocked.json").exists())

    def test_guest_namespace_is_observed_before_create_only_admission(self):
        from types import SimpleNamespace
        from agent_tools import durable_remote_job as jobs,readiness_tart
        self.custody.binding=SimpleNamespace(target="owned",machine="1"*32,expected_uid=1000)
        packet={"schemaVersion":1,"root":"/var/tmp/vc-recovery-jobs","generation":[1,2],"admissionGeneration":[3,4],
                "target":"owned","machine":"1"*32,"actualMachineId":"1"*32,"account":"1000",
                "ownerSourceSha256":hashlib.sha256(jobs.owner_source()).hexdigest()}
        self.assertIsNone(self.custody.load_guest_namespace())
        observed={"visibilityComplete":True,"jobs":[],"idle":True}
        reply=subprocess.CompletedProcess([],0,json.dumps(observed).encode(),b"")
        with mock.patch.object(readiness_tart.TartBackend,"_guest",return_value=(reply,{})) as guest:
            with self.assertRaisesRegex(ValueError,"guest_namespace_packet"):
                self.custody.admit_guest_namespace(
                    {**packet,"root":"/private/var/tmp/vc-recovery-jobs"},deadline=time.monotonic()+5)
            guest.assert_not_called()
            self.assertFalse((self.lifecycle/"guest-jobs.json").exists())
            self.assertEqual(self.custody.admit_guest_namespace(packet,deadline=time.monotonic()+5),packet)
            self.assertEqual(guest.call_count,1)
            source=guest.call_args.kwargs["payload"]
            self.assertIn(b"inventory",source)
            self.assertNotIn(b"'mode': 'enroll'",source)
            self.assertEqual(self.custody.admit_guest_namespace(packet,deadline=time.monotonic()+5),packet)
            self.assertEqual(guest.call_count,1)
            with self.assertRaisesRegex(registry.FixtureRegistryError,"tart_guest_namespace_changed"):
                self.custody.admit_guest_namespace({**packet,"generation":[3,4]},deadline=time.monotonic()+5)
        self.assertEqual(self.custody.load_guest_namespace(),packet)

    def test_reboot_qualification_cannot_adopt_a_later_different_vm_actor(self):
        from types import SimpleNamespace
        from agent_tools import durable_remote_job as jobs,readiness_tart
        rid="6"*64;self.custody.binding=SimpleNamespace()
        self.current["actor"]={"pid":456,"birth":"later"}
        effect={"action":"reboot","recoveryIdentity":rid,"target":"owned","machine":"machine",
                "bootBefore":"old-boot","connectionBefore":"tart:123:original:agent:linux:10:20"}
        jobs._publish(self.lifecycle/("effect-"+rid+".json"),effect)
        fixture=SimpleNamespace(target="owned",machine="machine",adapter=SimpleNamespace(backend=SimpleNamespace(custody=self.custody)))
        current=readiness.Observation("owned","machine",connection="tart:456:later:agent:linux:11:21",boot="new-boot",guest="running",
                                     idle_visibility=readiness.IDLE_VISIBILITY)
        with mock.patch.object(registry,"registered_fixture",return_value=fixture), \
                mock.patch.object(readiness_tart.TartBackend,"observe",return_value=current) as observe, \
                mock.patch.object(custody_module,"_sources",return_value={}):
            with self.assertRaisesRegex(registry.FixtureRegistryError,"tart_qualification_invalid"):
                custody_module.record_direct_reboot_qualification(self.root,"owned",rid)
            self.current["actor"]={"pid":123,"birth":"original"}
            observe.return_value=replace(current,connection="tart:123:original:agent:linux:11:21")
            proof=custody_module.record_direct_reboot_qualification(self.root,"owned",rid)
            self.assertTrue(proof.is_file())

    def test_unrecognized_installer_role_and_interactive_operator_block(self):
        with self.custody.operator(deadline=time.monotonic()+1):
            value = dict(self.guest); value["installerRoles"] = [{"pid": 77, "role": "unrecognized"}]
            visibility, _ = self.custody.idle_facts(value)
            self.assertNotIn("installers", visibility)
            value["installerRoles"] = [{"pid": 77, "role": "blocked"}]
            value["interactiveSessions"] = "a-live-operator"
            _, blockers = self.custody.idle_facts(value)
            self.assertEqual(blockers, frozenset({"installers", "operators"}))

    def test_other_operator_wait_obeys_caller_deadline_and_releases_descriptor(self):
        other = object.__new__(custody_module.TartCustody)
        other.lifecycle_root = self.lifecycle; other._operator_held = False; other._pins = lambda: None
        with self.custody.operator(deadline=time.monotonic()+1):
            with self.assertRaisesRegex(registry.FixtureRegistryError, "tart_readiness_deadline"):
                with other.operator(deadline=time.monotonic()+.05):
                    self.fail("a competing operator cannot acquire")
        with other.operator(deadline=time.monotonic()+1):
            self.assertTrue(other._operator_held)

    def test_exact_homebrew_wrapper_resolves_the_actual_kernel_executable(self):
        prefix = self.root / "cellar/tart/2.32.1"
        launcher = prefix / "bin/tart"
        binary = prefix / "libexec/tart.app/Contents/MacOS/tart"
        launcher.parent.mkdir(parents=True); binary.parent.mkdir(parents=True)
        shutil.copyfile("/bin/sleep", binary); binary.chmod(0o700)
        launcher.write_text('#!/bin/bash\nexec "' + str(binary) + '" "$@"\n'); launcher.chmod(0o700)
        process = subprocess.Popen([str(launcher), "10"])
        try:
            end = time.monotonic()+2
            while time.monotonic()<end:
                actual = subprocess.check_output(["ps", "-p", str(process.pid), "-o", "comm="], text=True).strip()
                if Path(actual) == binary:
                    break
                time.sleep(.01)
            self.assertEqual(custody_module._tart_binary(launcher), binary)
        finally:
            process.terminate(); process.wait(timeout=5)
        launcher.write_text('#!/bin/bash\necho unreviewed\n'); launcher.chmod(0o700)
        with self.assertRaisesRegex(registry.FixtureRegistryError, "tart_launcher_unrecognized"):
            custody_module._tart_binary(launcher)

    def test_complete_registration_keeps_vm_name_distinct_from_baseline_units(self):
        from agent_tools import tart_linux_probe
        name = "vpn-tool-recovery-tart-linux-owned"
        machine = "1" * 32
        home = self.root / "home"
        vm = home / ".tart/vms" / name; vm.mkdir(parents=True)
        config = vm / "config.json"; config.write_text("{}")
        disk = vm / "disk.img"; disk.write_bytes(b"owned")
        evidence = self.root / ".runtime/owned"; evidence.mkdir(parents=True)
        def record(relative, value):
            path = evidence / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value)); path.chmod(0o600); return path
        op = str(uuid4())
        actor = {"fixture": name, "childPid": 123, "childStartTime": "safe-start", "submitted": True}
        sha = hashlib.sha256(config.read_bytes()).hexdigest()
        record("linux-fixture.json", {"fixtureRoot": str(vm), "name": name, "configSha256": sha})
        record("linux-active-run.json", {"operationIdentity": op, "ownerPid": 124, "actor": actor})
        record("linux-persisted-restart-proof.json", {"fixtureRoot": str(vm), "machine": machine,
            "firstBoot": "boot1", "restartBoot": "boot2", "configSha256": sha,
            "configInode": config.stat().st_ino, "diskInode": disk.stat().st_ino})
        for filename, boot in (("linux-first-ready.json", "boot1"), ("linux-restarted-ready.json", "boot2")):
            record(filename, {"observation": {"machine": machine, "account": "admin", "uid": 1000, "boot": boot}})
        record("run-"+op+"/actor.json", actor)
        record("run-"+op+"/intent.json", {"operationIdentity": op, "fixture": name})
        record("reboot-proof.json", {"phase": "reboot-complete"})
        record("poweroff-proof.json", {"phase": "poweroff-complete"})
        record("linux-service-unit-baseline.json", {"schemaVersion": 1, "machine": machine, "boot": "boot2",
            "sourceOciDigest": "sha256:51b493a05e4bc6f21c5c5052cffc1b26b5cea1d76847f5db10b97da90c16e58c",
            "probeSha256": hashlib.sha256(Path(tart_linux_probe.__file__).read_bytes()).hexdigest(),
            "units": {"unattended-upgrades.service": {"fragment": "/usr/lib/systemd/system/unattended-upgrades.service",
                                                       "sha256": "2"*64, "generation": [1]*9}}})
        ledger = self.root / "storage"
        binary = Path("/bin/sleep").resolve()
        def observed(argv):
            return "safe-start" if argv[-1] == "lstart=" else str(binary)
        def identity(pid):
            return {"pid": pid, "birth": "actual-"+str(pid), "uid": os.getuid(), "commandSha256": "3"*64}
        with mock.patch.object(Path, "home", return_value=home), \
                mock.patch.object(custody_module.visual, "STORAGE_PLANS_ROOT", ledger), \
                mock.patch.object(custody_module.storage.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(1024**4, 0, 1024**4)), \
                mock.patch.object(custody_module.registry, "_run", side_effect=observed), \
                mock.patch.object(custody_module.registry, "process_identity", side_effect=identity), \
                mock.patch.object(custody_module.shutil, "which", return_value=str(binary)), \
                mock.patch.object(custody_module, "_sources", return_value={}), \
                mock.patch.object(custody_module, "load_registered_fixture", side_effect=lambda root, fixture_id, descriptor, pin: descriptor):
            custody_module.storage.StoragePlans(ledger).reserve("tart-owned", "linux", "start", vm,
                [{"path": str(disk), "capacityBytes": 1024**2}], writer_pid=123)
            result = custody_module.register_tart_linux(self.root, "tart-qualified", evidence)
        self.assertEqual(result["binding"]["vmName"], name)
        self.assertEqual(result["guestBaseline"]["unattended-upgrades.service"]["sha256"], "2"*64)

    def test_actual_baseline_refresh_gate_rejects_changed_unit_before_read_or_hash(self):
        marker = self.root / "unit-was-read"
        original = {"public.service": {"fragment": "/usr/lib/systemd/system/public.service", "generation": [1]*9, "sha256": "a"*64}}
        source = ("from pathlib import Path\n"
                  "def _unit(name): return {},Path('/usr/lib/systemd/system/public.service'),[2]*9\n"
                  "def baseline_units():\n Path("+repr(str(marker))+").write_text('read');return {}\n").encode()
        command = [__import__("sys").executable, "-c", custody_module._BASELINE_REFRESH_GATE,
                   str(len(source)), hashlib.sha256(source).hexdigest(), json.dumps(original)]
        result = subprocess.run(command, input=source, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_disk_pin_allows_guest_writes_but_rejects_replacement(self):
        disk = self.root / "disk.img"; disk.write_bytes(b"owned")
        before = custody_module._disk_pin(disk)
        with disk.open("r+b") as stream: stream.write(b"other")
        self.assertEqual(custody_module._disk_pin(disk), before)
        disk.unlink(); disk.write_bytes(b"owned")
        self.assertNotEqual(custody_module._disk_pin(disk), before)


if __name__ == "__main__":
    unittest.main()
