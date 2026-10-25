import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import signal
from unittest import mock
from uuid import uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness
from agent_tools import readiness_android as android
from agent_tools import readiness_providers as providers


@unittest.skipUnless(os.name == "posix", "durable existing-instance owner requires POSIX")
class AndroidLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(); self.root.chmod(0o700)
        self.jobroot = self.root / "jobs"; self.jobroot.mkdir(mode=0o700)
        self.binding = jobs.current_binding("owned-fixture", "actual-controlled-host")
        self.generation = jobs.root_generation(self.jobroot)
        self.descriptor = {"binding": {"target": "owned-fixture", "machine": "task-avd",
                "adb": "/usr/bin/adb", "avdName": "task-avd", "serial": "emulator-5660", "serverPort": 5038},
            "hostBinding": self.binding.__dict__, "jobRootGeneration": list(self.generation),
            "storagePlan": "owned-plan", "avdConfig": str(self.root / "task-avd.avd/config.ini"),
            "initialActor": {"pid": os.getpid(), "birth": "not-this-generation"}, "writableDisks": []}

    def backend(self):
        backend = android.AndroidInstanceBackend(self.root, self.descriptor, lambda: "actual-adb-generation", self.root)
        backend.transport = mock.Mock()
        backend.transport.observe.return_value = ("ready", "actual-adb-generation")
        backend.transport.connection.return_value = "actual-adb-generation"
        return backend

    def test_generated_program_retains_one_original_execution_across_new_clients(self):
        sentinel = self.root / "sentinel"
        counter = self.root / "counter"
        sentinel.write_text("#!" + sys.executable + "\nimport pathlib,sys,time\np=pathlib.Path(sys.argv[1])\n"
                            "for i in range(8):\n p.write_text(str(i)); print(i,flush=True); time.sleep(.1)\n")
        sentinel.chmod(0o700)
        operation = str(uuid4())
        program = android.launch_program(self.jobroot, operation, self.binding, [str(sentinel), str(counter)], {"PATH": os.defpath})
        self.assertNotIn(str(Path(android.__file__)), program.source.decode())
        record = {"index": 0, "operationId": operation, "recoveryId": "1" * 64, "programSha256": program.digest}
        jobs._publish(self.root / "launch-000000.json", record)
        jobs.submit(self.jobroot, operation, self.binding, program, generation=self.generation)
        end = time.monotonic() + 10
        while time.monotonic() < end and not counter.exists():
            time.sleep(.02)
        first = int(counter.read_text())
        actor, state, original = self.backend()._current()
        self.assertEqual(state, "live")
        self.assertEqual(original, record)
        # A new interpreter's observation never submits another execution.
        child_source = ("import sys,json;sys.path.insert(0," + repr(str(Path(__file__).resolve().parents[2])) + ");"
                        "from agent_tools import durable_remote_job as j;"
                        "print(json.dumps(j.observe(" + repr(str(self.jobroot)) + "," + repr(operation) + ","
                        "j.MachineBinding.from_dict(" + repr(self.binding.__dict__) + "),generation=" + repr(self.generation) + ")))" )
        fresh = subprocess.run([sys.executable, "-c", child_source], capture_output=True, check=True, timeout=5)
        self.assertIn(json.loads(fresh.stdout)["state"], {"running", "terminal"})
        time.sleep(.2)
        self.assertGreater(int(counter.read_text()), first)
        while time.monotonic() < end:
            result = jobs.observe(self.jobroot, operation, self.binding, generation=self.generation)
            if result["state"] == "terminal":
                break
            time.sleep(.02)
        self.assertEqual(result["state"], "terminal")
        terminal, stdout, stderr = jobs.collect(self.jobroot, operation, self.binding, generation=self.generation)
        self.assertEqual(stdout.decode().splitlines(), [str(i) for i in range(8)])
        self.assertEqual(stderr, b"")
        self.assertEqual(terminal["terminal"]["exitCode"], 0)
        self.assertEqual(self.backend()._current()[1], "stopped")
        self.assertEqual(len(list(self.jobroot.iterdir())), 1)
        self.assertIsNone(jobs._birth(actor["pid"]))

    def test_native_seed_program_digest_survives_json_environment_key_order(self):
        operation=str(uuid4())
        environment={"PATH":os.defpath,"HOME":"/owned-home","ANDROID_ADB_SERVER_PORT":"5042"}
        method=android.launch_program
        if os.environ.get("VPN_CONTROL_ANDROID_ENV_BEFORE"):
            self.assertEqual(os.environ["VPN_CONTROL_ANDROID_ENV_BEFORE"],"1")
            path=Path(__file__).parent/"fixtures"/"android_environment_order_before.py"
            namespace=dict(vars(android));exec(compile(path.read_text(),str(path),"exec"),namespace)
            method=namespace["launch_program"]
        first=method(self.jobroot,operation,self.binding,["/owned-emulator"],environment)
        restored=method(self.jobroot,operation,self.binding,["/owned-emulator"],json.loads(json.dumps(environment,sort_keys=True)))
        self.assertEqual(first.source,restored.source)
        self.assertEqual(first.digest,restored.digest)

    def test_unknown_launch_without_actor_receipt_never_becomes_stopped(self):
        record = {"index": 0, "operationId": str(uuid4()), "recoveryId": "2" * 64, "programSha256": "3" * 64}
        jobs._publish(self.root / "launch-000000.json", record)
        with mock.patch.object(jobs, "observe", return_value={"state": "unknown"}):
            with self.assertRaisesRegex(providers.ProviderError, "android_lifecycle_outcome_unknown"):
                self.backend()._current()

    def test_native_seed_lost_owner_terminal_never_authorizes_another_start(self):
        from agent_tools import readiness_fixture_registry as registry
        native=self.root/".runtime/native-jobs";native.mkdir(mode=0o700,parents=True)
        generation=jobs.root_generation(native);operation=str(uuid4())
        marker=self.root/"native-started"
        sentinel=self.root/"native-seed"
        sentinel.write_text("#!"+sys.executable+"\nimport pathlib,time\npathlib.Path("+repr(str(marker))+").touch()\ntime.sleep(60)\n")
        sentinel.chmod(0o700)
        program=android.launch_program(native,operation,self.binding,[str(sentinel)],{"PATH":os.defpath})
        jobs.submit(native,operation,self.binding,program,generation=generation)
        end=time.monotonic()+10;actor=None;owner=None
        try:
            while time.monotonic()<end:
                if marker.exists() and (native/operation/"emulator.json").exists():
                    actor=jobs._record(native/operation/"emulator.json")["actor"]
                    owner=jobs._record(native/operation/"owner.json")["owner"]
                    break
                time.sleep(.02)
            self.assertIsNotNone(actor);self.assertIsNotNone(owner)
            self.assertEqual(jobs._birth(owner["pid"]),owner["birth"])
            os.kill(owner["pid"],signal.SIGKILL)
            self.assertEqual(jobs._birth(actor["pid"]),actor["birth"])
            os.kill(actor["pid"],signal.SIGTERM)
            while time.monotonic()<end and (jobs._birth(owner["pid"]) is not None or jobs._birth(actor["pid"]) is not None):time.sleep(.02)
            self.assertIsNone(jobs._birth(actor["pid"]))
            self.assertEqual(jobs.observe(native,operation,self.binding,generation=generation)["state"],"unknown")
            self.descriptor.update(initialActor=actor,argv=[str(sentinel)],environment={"PATH":os.defpath},
                initialOwner={"jobRoot":str(native),"operationId":operation,"hostBinding":self.binding.__dict__,
                              "rootGeneration":list(generation),"programSha256":program.digest,
                              "programPin":registry._body(native/operation/"program.py")[1]})
            backend=self.backend()
            before=os.environ.get("VPN_CONTROL_ANDROID_SEED_BEFORE")
            if before:
                self.assertEqual(before,"1")
                path=Path(__file__).parent/"fixtures"/"android_native_seed_before.py"
                namespace=dict(vars(android));exec(compile(path.read_text(),str(path),"exec"),namespace)
                method=lambda:namespace["_current"](backend)
            else:method=backend._current
            with self.assertRaisesRegex(providers.ProviderError,"android_lifecycle_outcome_unknown"):method()
            self.assertEqual(len(list(native.iterdir())),1)
        finally:
            for process in (actor,owner):
                if process and jobs._birth(process["pid"])==process["birth"]:os.kill(process["pid"],signal.SIGKILL)

    def test_reused_original_pid_blocks_replacement(self):
        with self.assertRaisesRegex(providers.ProviderError, "android_owner_unavailable"):
            self.backend()._current()

    def test_unmanaged_guest_job_prevents_full_idle_reboot_proof(self):
        backend = self.backend(); backend._operator_held = True
        backend.descriptor.update(memoryMiB=2048, jobBaseline=["init"])
        observation = readiness.Observation("owned-fixture", "task-avd", connection="actual-adb-generation", boot="boot", guest="running")
        installers = ("Active install sessions:\n\nFinalized install sessions:\n\n"
                      "Historical install sessions:\n\nLegacy install sessions:\n{}\n"
                      "Gentle update with constraints info:\nhasPendingIdleJob=false\n")
        def command(args, deadline):
            if args == ["shell", "ps", "-A", "-o", "NAME"]: return "NAME\ninit\nsleep\nps\n", "actual-adb-generation"
            if args == ["shell", "dumpsys", "package", "installs"]: return installers, "actual-adb-generation"
            if args == ["shell", "pm", "list", "packages", "com.kardinal.vpncontrol"]: return "", "actual-adb-generation"
            self.fail("unexpected fixed probe")
        with mock.patch.object(backend, "_current", return_value=({"pid": 123, "birth": "fixed"}, "live", None)), \
                mock.patch.object(backend, "_launches", return_value=[]), \
                mock.patch.object(android.visual, "_read_reservations", return_value={"android": {"memory_mib": 2048, "pid": 123}}), \
                mock.patch.object(backend.adb, "_command", side_effect=command):
            with self.assertRaisesRegex(providers.ProviderError, "android_idle_work_active"):
                backend._idle(observation, time.monotonic()+10)

    def test_admitted_guest_job_or_missing_visibility_blocks_reboot_before_guest_probe(self):
        from agent_tools import readiness_adb_jobs
        backend=self.backend();backend._operator_held=True
        observation=readiness.Observation("owned-fixture","task-avd",guest="running")
        for evidence in ({"visibility":False,"reservations":[],"runningJobs":[],"unknownJobs":[]},
                         {"visibility":True,"reservations":[],"runningJobs":[],"unknownJobs":[str(uuid4())]}):
            with mock.patch.object(backend,"_current",return_value=({"pid":123,"birth":"fixed"},"live",None)), \
                    mock.patch.object(readiness_adb_jobs,"active_operations",return_value=evidence), \
                    mock.patch.object(backend.adb,"_command") as command:
                with self.assertRaisesRegex(providers.ProviderError,"android_idle_(visibility_incomplete|work_active)"):
                    backend._idle(observation,time.monotonic()+5)
                command.assert_not_called()

    def test_original_absent_durable_admission_is_proved_without_phase_writes(self):
        child = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(.05)"])
        birth = jobs._birth(child.pid); child.wait(timeout=5)
        self.descriptor.update(initialActor={"pid": child.pid, "birth": birth}, argv=["/bin/sleep", "1"], environment={"PATH": os.defpath})
        backend = self.backend()
        rid = "5"*64
        from uuid import uuid5, NAMESPACE_URL
        op = str(uuid5(NAMESPACE_URL, "android-existing-instance:"+rid))
        program = android.launch_program(self.jobroot, op, self.binding, self.descriptor["argv"], self.descriptor["environment"])
        record = {"index": 0, "operationId": op, "recoveryId": rid, "programSha256": program.digest}
        jobs._publish(self.root / "launch-000000.json", record)
        jobs._publish(self.root / ("effect-"+rid+".json"), {"action": "start", "recoveryId": rid, "operationId": op})
        before = {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file()}
        self.assertEqual(backend._current()[1], "stopped")
        observation = backend.observe(readiness.Requirements(frozenset({"guest_agent"})), time.monotonic()+5)
        self.assertEqual(observation.guest, "stopped")
        self.assertIsNone(backend.observe_recovery("start", rid, observation, time.monotonic()+5, 1, "6"*64))
        with backend.operation_scope(deadline=time.monotonic()+5):
            proof = backend.observe_recovery("start", rid, observation, time.monotonic()+5, 1, "6"*64)
        self.assertIs(type(proof), readiness.RecoveryUnsubmitted)
        self.assertTrue(proof.matches({"attempt": 1, "recoveryId": rid, "dispatchDigest": "6"*64}))
        after = {path.name: path.read_bytes() for path in self.root.iterdir() if path.is_file() and path.name != "operator.lock"}
        self.assertEqual(before, after)
        # Consumed job admission with missing owner is UNKNOWN, never absence.
        (self.jobroot / op).mkdir(mode=0o700)
        with backend.operation_scope(deadline=time.monotonic()+5):
            self.assertIsNone(backend.observe_recovery("start", rid, observation, time.monotonic()+5, 1, "6"*64))

    def test_native_invocation_rejects_arbitrary_arguments(self):
        identity = {"sdk": "/safe/sdk", "name": "task-avd", "serial": "emulator-5660", "memoryMiB": 2048}
        for argv in (["/bin/sh", "-c", "anything"], ["/safe/sdk/emulator/emulator", "-wipe-data"]):
            with self.subTest(argv=argv), self.assertRaisesRegex(providers.ProviderError, "android_lifecycle_spec_invalid"):
                android._argv(identity, argv)

    def _complete_registration(self,qualified=False):
        from agent_tools import readiness_fixture_registry as registry
        fixture=self.root/".runtime/native";fixture.mkdir(parents=True,mode=0o700)
        avd=fixture/"avd/task-avd.avd";avd.mkdir(parents=True)
        config=avd/"config.ini";config.write_text("owned=yes\n")
        op=str(uuid4());identity={"sdk":"/safe/sdk","name":"task-avd","serial":"emulator-5660",
                                  "memoryMiB":2048,"avdHome":str(avd.parent)}
        actor={"pid":999999999,"birth":"gone","uid":os.geteuid(),"commandSha256":"0"*64}
        records={"avd-identity.json":identity,"retry-launch-intent.json":{"argv":["/safe/sdk/emulator/emulator"],"identity":identity},
          "existing-start-intent.json":{"operationId":op,"originalRoot":str(avd),"configSha256":hashlib.sha256(config.read_bytes()).hexdigest(),"disks":{}},
          "existing-start-result.json":{"operationId":op,"bootBefore":"old","bootAfter":"new","user":"0","actualAvdPath":[str(avd),"OK"]},
          "existing-start-actor.json":{"process":actor,"operationId":op},
          "direct-reboot-result.json":{"bootBefore":"old","bootAfter":"new","user":"0"},
          "direct-pause-result.json":{"status":"virtual device is stopped\nOK\n"},
          "direct-resume-result.json":{"status":"virtual device is running\nOK\n"},
          "v4-direct-core-wake.json":{"display":"ready","recoveryRecords":1}}
        if qualified:
            target="local-android-"+hashlib.sha256(str(avd).encode()).hexdigest()[:24]
            digest=hashlib.sha256(json.dumps([target,"task-avd"],separators=(",",":")).encode()).hexdigest()
            records["existing-start-intent.json"]["admission"]={"profile":"infrastructure-recovery-tests",
                "reservationKey":android.visual._qualified_reservation_key("android-emulator",digest)}
        for name in ("direct-reboot-idle.json","existing-stop-before-idle.json","existing-stop-final-idle.json"):
            records[name]={"protected_processes":"NAME                       \ninit\ncom.android.systemui\n"}
        for name,value in records.items():
            path=fixture/name;path.write_text(json.dumps(value));path.chmod(0o600)
        plan=mock.MagicMock();plan._read.return_value={"plans":{"owned":{"directory":str(avd),"state":"retained","disks":[]}}}
        with mock.patch.object(android,"_argv",return_value=["/safe/sdk/emulator/emulator"]), \
                mock.patch.object(android.storage,"StoragePlans",return_value=plan), \
                mock.patch.object(registry,"adb_server_identity",return_value=actor), \
                mock.patch.object(android,"_source_pins",return_value={}), \
                mock.patch.object(android,"load_registered_fixture",side_effect=lambda root,fixture_id,descriptor,pin:descriptor):
            descriptor=android.register_existing_instance(self.root,"owned-fixture",fixture)
        self.assertEqual(descriptor["jobBaseline"],["com.android.systemui","init"])
        self.assertEqual(descriptor["environment"]["ANDROID_ADB_SERVER_PORT"],"5038")
        return descriptor

    def test_complete_registration_accepts_actual_aligned_ps_header(self):
        descriptor=self._complete_registration()
        self.assertNotIn("memoryReservation",descriptor)

    def test_qualified_reservation_is_derived_from_native_start_proof(self):
        descriptor=self._complete_registration(qualified=True)
        digest=hashlib.sha256(json.dumps([descriptor["binding"]["target"],descriptor["binding"]["machine"]],separators=(",",":")).encode()).hexdigest()
        self.assertEqual(descriptor["memoryReservation"],android.visual._qualified_reservation_key("android-emulator",digest))

    def test_duplicate_resume_recovery_does_not_submit_again(self):
        backend = self.backend()
        observation = readiness.Observation("owned-fixture", "task-avd", connection="actual-adb-generation",
                                             transport="ready", guest="paused", trusted=True, owned=True, integrity=True)
        with mock.patch.object(backend, "observe", return_value=observation), \
                mock.patch.object(backend, "_current", return_value=({"pid": 123, "birth": "fixed"}, "live", None)), \
                mock.patch.object(backend.adb, "_command") as command:
            backend.recover("resume", "4" * 64, observation, time.monotonic()+10)
            backend.recover("resume", "4" * 64, observation, time.monotonic()+10)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args[0][0], ["emu", "avd", "resume"])

    def test_start_waits_for_original_owner_publication_without_replacement(self):
        backend=self.backend();backend.descriptor.update(memoryMiB=2048,argv=["/bin/sleep","1"],environment={"PATH":os.defpath})
        observation=readiness.Observation("owned-fixture","task-avd",connection="actual-adb-generation",transport="ready",guest="stopped")
        actor={"pid":123,"birth":"fixed"};plan=mock.MagicMock()
        with mock.patch.object(backend,"observe",return_value=observation), \
                mock.patch.object(backend,"_stopped_disk_guard"), \
                mock.patch.object(android.storage,"StoragePlans",return_value=plan), \
                mock.patch.object(android.visual,"_read_reservations",return_value={}), \
                mock.patch.object(android.local_fixture_admission,"memory_plan",return_value={}), \
                mock.patch.object(android.visual,"_admit_visual_start"), \
                mock.patch.object(backend,"_launches",return_value=[]), \
                mock.patch.object(jobs,"submit") as submit, \
                mock.patch.object(backend,"_current",side_effect=[providers.ProviderError("android_lifecycle_outcome_unknown"),(actor,"live",None)]), \
                mock.patch.object(backend,"_bind_actor") as bind:
            backend.recover("start","7"*64,observation,time.monotonic()+5)
        self.assertEqual(submit.call_count,1);bind.assert_called_once_with(actor)
        self.assertEqual(len(list(self.root.glob("launch-*.json"))),1)

    def test_lost_client_pending_claim_binds_same_original_actor_once(self):
        backend=self.backend();backend._operator_held=True;backend.descriptor["memoryMiB"]=2048
        actor={"pid":123,"birth":"original"};record={"operationId":str(uuid4())}
        requirements=readiness.Requirements(frozenset({"guest_agent"}))
        ready=readiness.ReadyContext(str(uuid4()),"owned-fixture","task-avd","actual-adb-generation","boot",None,None,requirements)
        observed=readiness.Observation("owned-fixture","task-avd",connection="actual-adb-generation",boot="boot")
        reservations={"android":{"memory_mib":2048,"pid":0}}
        plan={"directory":str(backend.avd_root),"state":"retained","writerPid":99};plans=mock.MagicMock()
        plans._read.return_value={"plans":{backend.storage_plan:plan}}
        def bind(original):
            self.assertEqual(original,actor)
            reservations["android"]["pid"]=actor["pid"];plan["writerPid"]=actor["pid"]
        with mock.patch.object(backend,"_current",return_value=(actor,"live",record)), \
                mock.patch.object(backend,"observe",return_value=observed), \
                mock.patch.object(android.visual,"_read_reservations",return_value=reservations), \
                mock.patch.object(android.storage,"StoragePlans",return_value=plans), \
                mock.patch.object(backend,"_bind_actor",side_effect=bind) as binding:
            hook=getattr(backend,"reconcile_ready",None)
            if hook:hook(ready,time.monotonic()+5)
            self.assertEqual(reservations["android"]["pid"],actor["pid"])
            if hook:hook(ready,time.monotonic()+5)
            self.assertEqual(binding.call_count,1)


if __name__ == "__main__":
    unittest.main()
