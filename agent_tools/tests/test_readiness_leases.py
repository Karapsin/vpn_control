"""Actual detached owners; controlled settings are private harmless fixtures."""
from concurrent.futures import ThreadPoolExecutor
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_leases as leases


class _LeaseFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpn-control-lease-test-")
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.setting = self.root / "controlled-setting"
        self.setting.write_text("sleep")
        self.setting.chmod(0o600)
        self.binding = jobs.current_binding("owned-lease-test", "controlled-setting")
        self.generation = jobs.root_generation(self.root)
        self.operations = []

    def tearDown(self):
        for operation in self.operations:
            try:
                leases.cancel(self.root, operation, self.binding, generation=self.generation)
            except (OSError, ValueError, AssertionError):
                pass
            # The lease receipt proves settings restoration, while its durable
            # wrapper may still be closing retained streams. Never delete the
            # private root until that same original wrapper is terminal.
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                status = jobs.observe(self.root, operation, self.binding, generation=self.generation)
                if status["state"] in {"terminal", "unsubmitted"}:
                    break
                time.sleep(0.02)
            else:
                self.fail("original durable wrapper did not finish before fixture cleanup")
        self.tmp.cleanup()

    def acquire(self, ttl=0.35):
        operation = str(uuid.uuid4())
        self.operations.append(operation)
        leases._acquire_controlled(self.root, operation, self.binding, self.setting, ttl, generation=self.generation)
        return operation

    def wait(self, operation, states, limit=8):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            result = leases.inspect(self.root, operation, self.binding, generation=self.generation)
            if result["state"] in states:
                return result
            time.sleep(0.02)
        self.fail("lease did not reach expected finite state: " + json.dumps(result))


class LeaseTests(_LeaseFixture):
    def _android_server_race(self, module):
        operation=str(uuid.uuid4());self.operations.append(operation)
        marker=self.root/(operation+'.implicit-daemon')
        log=self.root/(operation+'.argv.json')
        executable=self.root/(operation+'.adb')
        executable.write_text('#!'+sys.executable+'\n'+
            'import json,pathlib,sys\n'+
            'log=pathlib.Path('+repr(str(log))+')\n'+
            'rows=json.loads(log.read_text())if log.exists()else []\nrows.append(sys.argv[1:]);log.write_text(json.dumps(rows))\n'+
            'if sys.argv[-3:]==["emu","avd","name"]:\n print("controlled-setting\\nOK");raise SystemExit(0)\n'+
            'if sys.argv[1:3]!=["-H","127.0.0.1"]:\n'+
            ' pathlib.Path('+repr(str(marker))+').write_text("unowned daemon admitted")\n'+
            'sys.stderr.write("controlled owned server absent")\nraise SystemExit(1)\n')
        executable.chmod(0o700)
        config={'backend':'android','ttlSeconds':.1,'adbPath':str(executable),'adbPort':5040,
                'adbSerial':'emulator-9988','guestAvd':self.binding.machine,'guestBoot':str(uuid.uuid4())}
        jobs.submit(self.root,operation,self.binding,module._program(self.root,operation,self.binding,config),generation=self.generation)
        self.wait(operation,{'failed'})
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if jobs.observe(self.root,operation,self.binding,generation=self.generation)['state']=='terminal':break
            time.sleep(.02)
        else:self.fail('original Android lease caller did not close')
        self.assertTrue(log.exists(),'complete generated caller must execute the controlled adb client')
        rows=json.loads(log.read_text())
        self.assertEqual(2,len(rows),'native adb emu identity succeeds before server-based shell failure')
        self.assertEqual(['emu','avd','name'],rows[0][-3:])
        self.assertEqual(['shell','cat','/proc/sys/kernel/random/boot_id'],rows[1][-3:])
        return marker.exists(),rows[1]

    def test_complete_generated_android_caller_cannot_implicitly_start_adb_daemon(self):
        created,argv=self._android_server_race(leases)
        self.assertFalse(created,'owned server loss must not implicitly create another daemon')
        self.assertEqual(['-H','127.0.0.1','-P','5040'],argv[:4])

    def test_causal_unfixed_generated_android_caller_autostarts_after_server_loss(self):
        name='agent_tools._lease_adb_autostart_before'
        path=Path(__file__).parent/'fixtures/readiness_lease_adb_autostart_before.py'
        spec=importlib.util.spec_from_file_location(name,path);before=importlib.util.module_from_spec(spec)
        sys.modules[name]=before
        try:
            spec.loader.exec_module(before)
            created,_=self._android_server_race(before)
            self.assertTrue(created,'preserved unfixed generated caller must demonstrate daemon admission')
            fixed,_=self._android_server_race(leases)
            self.assertFalse(fixed)
        finally:sys.modules.pop(name,None)

    def test_actual_expiry_restores_original_setting(self):
        operation = self.acquire()
        self.assertEqual(self.wait(operation, {"active"})["operationId"], operation)
        self.assertEqual(self.setting.read_text(), "awake")
        result = self.wait(operation, {"expired"})
        self.assertTrue(result["restored"])
        self.assertEqual(self.setting.read_text(), "sleep")
        self.assertFalse(result["replayAllowed"])

    def test_cancel_is_idempotent_and_does_not_signal_unrelated_process(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            operation = self.acquire(ttl=10)
            self.wait(operation, {"active"})
            for _ in range(3):
                leases.cancel(self.root, operation, self.binding, generation=self.generation)
            result = self.wait(operation, {"cancelled"})
            self.assertTrue(result["restored"])
            self.assertEqual(self.setting.read_text(), "sleep")
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=5)

    def test_same_uuid_concurrent_callers_share_one_lease(self):
        operation = str(uuid.uuid4())
        self.operations.append(operation)
        def call(_):
            return leases._acquire_controlled(self.root, operation, self.binding, self.setting, 0.5,
                                              generation=self.generation)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(call, range(6)))
        self.assertTrue(all(value["operationId"] == operation for value in results))
        self.wait(operation, {"active"})
        acquired = jobs._record(self.root / operation / "lease-acquired.json")
        self.assertEqual(len(list(self.root.glob("*/child-admission"))), 1)
        self.wait(operation, {"expired"})
        self.assertEqual(jobs._record(self.root / operation / "lease-acquired.json"), acquired)
        self.assertEqual(self.setting.read_text(), "sleep")

    def test_distinct_leases_cannot_replace_active_setting_owner(self):
        first = self.acquire(ttl=10)
        self.wait(first, {"active"})
        second = self.acquire(ttl=0.2)
        result = self.wait(second, {"failed"})
        self.assertEqual(result["reason"], "lease_resource_busy")
        self.assertEqual(self.setting.read_text(), "awake")
        leases.cancel(self.root, first, self.binding, generation=self.generation)
        self.wait(first, {"cancelled"})
        third = self.acquire(ttl=0.2)
        self.wait(third, {"expired"})
        self.assertEqual(self.setting.read_text(), "sleep")

    def test_client_death_and_fresh_interpreter_observe_original_and_restore(self):
        operation = str(uuid.uuid4())
        self.operations.append(operation)
        source = "\n".join([
            "from pathlib import Path",
            "from agent_tools import durable_remote_job as j, readiness_leases as l",
            "import time",
            "root = Path(" + repr(str(self.root)) + ")",
            "binding = j.MachineBinding.from_dict(" + repr(jobs.asdict(self.binding)) + ")",
            "l._acquire_controlled(root," + repr(operation) + ",binding,root/'controlled-setting',1.2,generation=" +
            repr(self.generation) + ")",
            "time.sleep(60)",
        ])
        client = subprocess.Popen([sys.executable, "-c", source], cwd=Path(__file__).resolve().parents[2])
        try:
            self.wait(operation, {"active"})
            owner = jobs._record(self.root / operation / "owner.json")
            client.kill()
            client.wait(timeout=5)
            observe = "\n".join([
                "from agent_tools import durable_remote_job as j, readiness_leases as l",
                "import json",
                "print(json.dumps(l.inspect(" + repr(str(self.root)) + "," + repr(operation) +
                ",j.MachineBinding.from_dict(" + repr(jobs.asdict(self.binding)) + "),generation=" +
                repr(self.generation) + ")))",
            ])
            fresh = subprocess.run([sys.executable, "-c", observe], capture_output=True, check=True,
                                   cwd=Path(__file__).resolve().parents[2], timeout=5)
            self.assertEqual(json.loads(fresh.stdout)["state"], "active")
            self.wait(operation, {"expired"})
            self.assertEqual(jobs._record(self.root / operation / "owner.json"), owner)
            self.assertEqual(self.setting.read_text(), "sleep")
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)

    def test_fresh_server_module_can_cancel_original_owner(self):
        operation = self.acquire(ttl=5)
        self.wait(operation, {"active"})
        importlib.reload(leases)
        leases.cancel(self.root, operation, self.binding, generation=self.generation)
        self.assertTrue(self.wait(operation, {"cancelled"})["restored"])

    def test_terminal_lease_keeps_observing_until_retained_streams_close(self):
        operation = str(uuid.uuid4())
        self.operations.append(operation)
        program = leases._program(self.root, operation, self.binding,
                                  {"backend": "controlled", "ttlSeconds": 0.2, "setting": str(self.setting)})
        # Execute the real owner, delaying only its final output after the lease
        # restored its setting. This exercises the actual receipt ordering.
        source = program.source.replace(b"        print(json.dumps({\"state\": state,",
                                        b"        time.sleep(0.5)\n        print(json.dumps({\"state\": state,")
        self.assertNotEqual(source, program.source)
        jobs.submit(self.root, operation, self.binding, jobs.Program(program.purpose, source, 4096),
                    generation=self.generation)
        result = self.wait(operation, {"expired"})
        self.assertEqual(result["jobState"], "running")
        self.assertEqual(result["nextAction"], "observe_original")
        self.assertTrue(result["restored"])

    def test_external_setting_change_is_not_overwritten(self):
        operation = self.acquire(ttl=1)
        self.wait(operation, {"active"})
        # Replace with a private, valid but unrelated setting object. Even if
        # its value happens to match, inode admission must reject writing it.
        replacement = self.root / "replacement"
        replacement.write_text("awake")
        replacement.chmod(0o600)
        replacement.replace(self.setting)
        result = self.wait(operation, {"restore_blocked"})
        self.assertFalse(result["restored"])
        self.assertEqual(self.setting.read_text(), "awake")

    def test_corrupted_cancel_does_not_disclose_private_marker(self):
        operation = self.acquire(ttl=3)
        self.wait(operation, {"active"})
        jobs._publish(self.root / operation / "lease-cancel.json", {"private": "PRIVATE-CREDENTIAL-MARKER"})
        result = self.wait(operation, {"failed"})
        self.assertNotIn("PRIVATE-CREDENTIAL-MARKER", json.dumps(result))
        self.assertTrue(result["restored"])
        self.assertEqual(self.setting.read_text(), "sleep")

    def test_inspection_is_observation_only(self):
        operation = str(uuid.uuid4())
        before = sorted(path.name for path in self.root.iterdir())
        result = leases.inspect(self.root, operation, self.binding, generation=self.generation)
        self.assertEqual(result["state"], "unsubmitted")
        self.assertEqual(before, sorted(path.name for path in self.root.iterdir()))

    def test_unknown_root_generation_never_reacquires_or_cancels(self):
        operation = self.acquire(ttl=0.4)
        self.wait(operation, {"active"})
        invalid = (self.generation[0], self.generation[1] + 1)
        result = leases.inspect(self.root, operation, self.binding, generation=invalid)
        self.assertEqual(result["state"], "unknown")
        with self.assertRaises(jobs.DurableJobError):
            leases.cancel(self.root, operation, self.binding, generation=invalid)
        self.wait(operation, {"expired"})

    def test_finite_schema_no_arbitrary_provider_or_commands(self):
        for ttl in (float("nan"), float("inf"), True, 0, 18_001, "1"):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                leases.LeaseSpec("native-macos", ttl)
        with self.assertRaises(ValueError):
            leases.LeaseSpec("shell", 1)
        with self.assertRaises(ValueError):
            leases.LeaseSpec("android-emulator", 1, adb_path="/bin/sh", adb_serial="owned")
        with self.assertRaises(ValueError):
            leases.LeaseSpec("android-emulator", 1, adb_path="/usr/bin/adb", adb_serial="owned;echo private")
        self.assertFalse(leases.capabilities("raw-qemu-windows")["available"])
        self.assertEqual(leases.capabilities("tart-linux")["reason"], "headless_no_gui_lease")


@unittest.skipUnless(sys.platform == "darwin", "native macOS assertion test")
class NativeMacLeaseTests(_LeaseFixture):
    # One direct real OS scenario; controlled tests above remain portable.
    def test_tart_guest_never_acquires_coordinator_assertion(self):
        operation = str(uuid.uuid4())
        self.operations.append(operation)
        with self.assertRaises(leases.LeaseError):
            leases.acquire(self.root, operation, self.binding,
                           leases.LeaseSpec("tart-macos", .3), generation=self.generation)
        self.assertFalse((self.root / operation).exists())

    def test_native_assertion_expiry_and_cancellation_restore_process_state(self):
        self.binding = leases.native_macos_binding()
        self.assertEqual(self.binding.target, "native-macos-local")
        self.assertTrue(self.binding.machine.startswith("native-macos-"))
        for cancel in (False, True):
            operation = str(uuid.uuid4())
            self.operations.append(operation)
            leases.acquire(self.root, operation, self.binding,
                           leases.LeaseSpec("native-macos", 3 if cancel else 0.6), generation=self.generation)
            self.wait(operation, {"active"})
            acquired = jobs._record(self.root / operation / "lease-acquired.json")
            helper = acquired["helper"]
            output = subprocess.run(["/usr/bin/pmset", "-g", "assertions"], capture_output=True,
                                    check=True, timeout=5).stdout.decode()
            self.assertIn("pid " + str(helper["pid"]) + "(caffeinate)", output)
            self.assertIn("PreventUserIdleDisplaySleep", output)
            self.assertIn("PreventUserIdleSystemSleep", output)
            if cancel:
                leases.cancel(self.root, operation, self.binding, generation=self.generation)
            result = self.wait(operation, {"cancelled" if cancel else "expired"})
            self.assertTrue(result["restored"])
            self.assertNotEqual(jobs._birth(helper["pid"]), helper["birth"])

    def test_native_assertion_rejects_caller_invented_machine_binding(self):
        operation = str(uuid.uuid4())
        with self.assertRaisesRegex(leases.LeaseError, "native_machine_binding_mismatch"):
            leases.acquire(self.root, operation, self.binding,
                           leases.LeaseSpec("native-macos", .3), generation=self.generation)
        self.assertFalse((self.root / operation).exists())


if __name__ == "__main__":
    unittest.main()
