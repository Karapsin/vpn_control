"""Real sockets and detached owners prove repair of an original failed lease."""
import json
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from types import SimpleNamespace
from unittest.mock import patch

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_leases as leases
from agent_tools import readiness_lease_reconciliation as repair
from agent_tools import readiness_lease_workflow as flow
from agent_tools import readiness, readiness_providers as providers


class LeaseReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vpn-control-lease-reconcile-")
        self.base = Path(self.tmp.name).resolve()
        self.base.chmod(0o700)
        self.root = self.base / "jobs"
        self.root.mkdir(mode=0o700)
        self.generation = jobs.root_generation(self.root)
        self.binding = jobs.current_binding("lease-repair-socket", "owned-controlled-avd")
        self.boot = str(uuid.uuid4())
        self.state = self.base / "state.json"
        self.state.write_text(json.dumps({"boot": self.boot, "account": "0", "avd": "owned-controlled-avd", "value": "3", "writes": []}))
        self.fixture = Path(__file__).parent / "fixtures/readiness_lease_adb_socket.py"
        self.client = self.base / "fixed-client"
        self.client.write_text("#!" + sys.executable + "\n" + self.fixture.read_text())
        self.client.chmod(0o700)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.daemon = None
        self.operations = []
        self.start_daemon()

    def tearDown(self):
        for operation in self.operations:
            try:
                leases.cancel(self.root, operation, self.binding, generation=self.generation)
            except (ValueError, OSError):
                pass
            self.wait_job(operation)
            derived = repair.restoration_id(operation)
            if (self.root / derived).exists():
                self.wait_job(derived)
        self.stop_daemon()
        self.tmp.cleanup()

    def start_daemon(self):
        marker = self.base / (str(uuid.uuid4()) + ".ready")
        self.daemon = subprocess.Popen([sys.executable, str(self.fixture), "daemon", str(self.state), str(self.port), str(marker)],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.until(lambda: marker.exists())

    def stop_daemon(self):
        if self.daemon is not None:
            self.daemon.terminate()
            self.daemon.wait(timeout=5)
            self.daemon = None

    def until(self, predicate, timeout=12):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            result = predicate()
            if result:
                return result
            time.sleep(.02)
        self.fail("owned socket/owner did not reach expected state")

    def wait_job(self, operation):
        return self.until(lambda: (s if s["state"] in {"terminal", "unsubmitted"} else None)
                          if (s := jobs.observe(self.root, operation, self.binding, generation=self.generation)) else None)

    def original(self, ttl=1.2):
        operation = str(uuid.uuid4())
        self.operations.append(operation)
        config = {"backend": "android", "ttlSeconds": ttl, "adbPath": str(self.client), "adbSerial": "emulator-5678",
                  "adbPort": self.port, "guestBoot": self.boot, "guestAvd": "owned-controlled-avd"}
        jobs.submit(self.root, operation, self.binding, leases._program(self.root, operation, self.binding, config), generation=self.generation)
        self.until(lambda: leases.inspect(self.root, operation, self.binding, generation=self.generation)["state"] == "active")
        return operation

    def failed_original(self):
        operation = self.original()
        self.stop_daemon()
        self.wait_job(operation)
        status = leases.inspect(self.root, operation, self.binding, generation=self.generation)
        self.assertEqual("restore_blocked", status["state"])
        self.assertFalse(status["restored"])
        self.assertEqual("7", json.loads(self.state.read_text())["value"])
        return operation

    def config(self):
        return {"adbPath": str(self.client), "adbSerial": "emulator-5678", "adbPort": self.port,
                "guestBoot": self.boot, "guestAvd": "owned-controlled-avd", "guestAccount": "0",
                "daemonPin": repair._bridge()["capture_pin"](self.daemon.pid, self.port)}

    def finish_repair(self, operation):
        repair.admit(self.root, operation, self.binding, self.config(), generation=self.generation)
        self.wait_job(repair.restoration_id(operation))
        return repair.observe(self.root, operation, self.binding, generation=self.generation)

    def test_daemon_loss_at_ttl_preserves_failure_then_one_fresh_agent_restores(self):
        operation = self.failed_original()
        failed = (self.root / operation / "lease-terminal.json").read_bytes()
        original = (self.root / operation / "lease-original.json").read_bytes()
        self.assertEqual("unsubmitted", repair.observe(self.root, operation, self.binding, generation=self.generation)["state"])
        self.start_daemon()
        result = self.finish_repair(operation)
        self.assertEqual("terminal", result["state"])
        self.assertTrue(result["restored"])
        self.assertEqual(["7", "3"], json.loads(self.state.read_text())["writes"])
        self.assertEqual(failed, (self.root / operation / "lease-terminal.json").read_bytes())
        self.assertEqual(original, (self.root / operation / "lease-original.json").read_bytes())
        owner = jobs._record(self.root / repair.restoration_id(operation) / "owner.json")
        for _ in range(3):
            self.assertEqual(result, repair.admit(self.root, operation, self.binding, self.config(), generation=self.generation))
        self.assertEqual(owner, jobs._record(self.root / repair.restoration_id(operation) / "owner.json"))
        script = "from agent_tools import readiness_lease_reconciliation as r,durable_remote_job as j;import json;print(json.dumps(r.observe(" + repr(str(self.root)) + "," + repr(operation) + ",j.MachineBinding.from_dict(" + repr(jobs.asdict(self.binding)) + "),generation=" + repr(self.generation) + ")))"
        fresh = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2], capture_output=True, check=True, timeout=8)
        self.assertEqual(result, json.loads(fresh.stdout))

    def test_guest_account_change_and_failed_attempt_cannot_be_replayed(self):
        operation = self.failed_original()
        state = json.loads(self.state.read_text());state["account"] = "10";self.state.write_text(json.dumps(state))
        self.start_daemon()
        self.assertEqual("blocked", self.finish_repair(operation)["state"])
        owner = jobs._record(self.root / repair.restoration_id(operation) / "owner.json")
        state["account"] = "0";self.state.write_text(json.dumps(state))
        self.assertEqual("blocked", repair.admit(self.root, operation, self.binding, self.config(), generation=self.generation)["state"])
        self.assertEqual(owner, jobs._record(self.root / repair.restoration_id(operation) / "owner.json"))
        self.assertEqual(["7"], json.loads(self.state.read_text())["writes"])

    def test_changed_setting_is_never_overwritten(self):
        operation = self.failed_original()
        state = json.loads(self.state.read_text());state["value"] = "5";self.state.write_text(json.dumps(state))
        self.start_daemon()
        self.assertEqual("blocked", self.finish_repair(operation)["state"])
        self.assertEqual("5", json.loads(self.state.read_text())["value"])
        self.assertEqual(["7"], json.loads(self.state.read_text())["writes"])

    def test_active_original_and_stale_daemon_pin_never_admit_restoration(self):
        operation = self.original(ttl=3)
        with self.assertRaisesRegex(ValueError, "lease_restore_original_not_terminal"):
            repair.admit(self.root, operation, self.binding, self.config(), generation=self.generation)
        self.stop_daemon();self.wait_job(operation);self.start_daemon()
        config = self.config()
        self.stop_daemon();self.start_daemon()
        with self.assertRaisesRegex(ValueError, "lease_restore_daemon_"):
            repair.admit(self.root, operation, self.binding, config, generation=self.generation)
        self.assertFalse((self.root / repair.restoration_id(operation)).exists())

    def test_resource_history_allows_new_assertion_only_after_verified_restoration(self):
        operation = self.failed_original()
        self.start_daemon()
        blocked = str(uuid.uuid4());self.operations.append(blocked)
        config = {"backend": "android", "ttlSeconds": .2, "adbPath": str(self.client), "adbSerial": "emulator-5678",
                  "adbPort": self.port, "guestBoot": self.boot, "guestAvd": "owned-controlled-avd"}
        jobs.submit(self.root, blocked, self.binding, leases._program(self.root, blocked, self.binding, config), generation=self.generation)
        self.wait_job(blocked)
        self.assertEqual("lease_previous_restoration_unknown", leases.inspect(self.root, blocked, self.binding, generation=self.generation)["reason"])
        self.assertTrue(self.finish_repair(operation)["restored"])
        next_operation = self.original(ttl=.8)
        self.wait_job(next_operation)
        self.assertEqual("expired", leases.inspect(self.root, next_operation, self.binding, generation=self.generation)["state"])
        self.assertEqual(["7", "3", "7", "3"], json.loads(self.state.read_text())["writes"])

    def test_actual_client_death_and_concurrent_reconcile_keep_original_derived_owner(self):
        operation = self.failed_original();self.start_daemon()
        config = self.config()
        source = "from agent_tools import readiness_lease_reconciliation as r,durable_remote_job as j;import os;r.admit(" + repr(str(self.root)) + "," + repr(operation) + ",j.MachineBinding.from_dict(" + repr(jobs.asdict(self.binding)) + ")," + repr(config) + ",generation=" + repr(self.generation) + ");os._exit(73)"
        client = subprocess.run([sys.executable, "-c", source], cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=10)
        self.assertEqual(73, client.returncode)
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(lambda _: repair.admit(self.root, operation, self.binding, config, generation=self.generation), range(5)))
        self.assertTrue(all(r["restorationOperationId"] == repair.restoration_id(operation) for r in results))
        self.wait_job(repair.restoration_id(operation))
        self.assertTrue(repair.observe(self.root, operation, self.binding, generation=self.generation)["restored"])
        self.assertEqual(["7", "3"], json.loads(self.state.read_text())["writes"])
        self.assertEqual(1, len(list((self.root / repair.restoration_id(operation)).glob("child-admission"))))

    def test_preparation_crash_is_unknown_and_never_reconstructs_submission(self):
        operation = self.failed_original();self.start_daemon()
        jobs._create(self.root / operation / "lease-restore-program.py", b"original preparation interrupted\n")
        result = repair.admit(self.root, operation, self.binding, self.config(), generation=self.generation)
        self.assertEqual("unknown", result["state"])
        self.assertEqual("lease_restore_preparation_unresolved", result["reason"])
        self.assertFalse((self.root / repair.restoration_id(operation)).exists())
        self.assertEqual(["7"], json.loads(self.state.read_text())["writes"])

    def test_changed_boot_or_avd_never_writes_and_original_receipt_remains(self):
        for key, changed in (("boot", str(uuid.uuid4())), ("avd", "different-owned-avd")):
            with self.subTest(key=key):
                # One resource root per immutable history; a failed restoration
                # deliberately prevents admitting another assertion there.
                if self.operations:
                    self.stop_daemon();self.start_daemon()
                    self.root = self.base / ("jobs-" + key);self.root.mkdir(mode=0o700)
                    self.generation = jobs.root_generation(self.root);self.operations = []
                state = json.loads(self.state.read_text());state.update(boot=self.boot, avd="owned-controlled-avd", value="3", writes=[]);self.state.write_text(json.dumps(state))
                operation = self.failed_original()
                failed = (self.root / operation / "lease-terminal.json").read_bytes()
                state = json.loads(self.state.read_text());state[key] = changed;self.state.write_text(json.dumps(state));self.start_daemon()
                self.assertEqual("blocked", self.finish_repair(operation)["state"])
                self.assertEqual(["7"], json.loads(self.state.read_text())["writes"])
                self.assertEqual(failed, (self.root / operation / "lease-terminal.json").read_bytes())

    def test_facade_transport_only_repair_and_local_status_use_real_fixed_callers(self):
        # Test-only registration wraps the complete actual coordinator/backend;
        # no VM/provider-native qualification is inferred from this socket.
        old_root = self.root
        state, targets = flow._paths(self.base, "socket-fixture", create=True)
        spec = leases.LeaseSpec("android-emulator", 1.2, adb_path="/usr/bin/adb", adb_serial="emulator-5678",
                                adb_port=self.port, guest_boot=self.boot, guest_avd="owned-controlled-avd")
        key = flow._key(spec, "owned-controlled-avd")
        self.root = flow._directory(targets / key, create=True)
        self.generation = jobs.root_generation(self.root)
        self.binding = jobs.current_binding("android-lease-" + key, "owned-controlled-avd")
        operation = self.failed_original()
        spec_data = asdict(spec);spec_data["adb_path"] = str(self.client)
        # The internal script executable is deliberately fixture-only. Its
        # kernel PID/executable pin is still checked around every real command.
        with patch.object(leases, "ADB_PATHS", leases.ADB_PATHS | {str(self.client)}):
            spec = leases.LeaseSpec(**spec_data)
            # Actual stable job root is derived from the approved fixture path.
            new_key = flow._key(spec, "owned-controlled-avd")
            # Preserve the actual original root and bind metadata to it by
            # using the internal key adapter only within this test.
            with patch.object(flow, "_key", return_value=key):
                intent = jobs._intent(self.root / operation, operation, self.binding)
                value = {"schemaVersion": 1, "fixtureId": "socket-fixture", "operationId": operation,
                         "provider": "android-emulator", "ttlSeconds": spec.ttl_seconds, "binding": asdict(self.binding),
                         "jobRootKey": key, "jobRootGeneration": list(self.generation), "leaseSpec": asdict(spec),
                         "readyIdentities": ["socket-target", "owned-controlled-avd", "original-dead-connection", self.boot, "android-user:0", self.boot + ":user:0"],
                         "sources": dict(flow._LOADED), "programSha256": intent["programSha256"]}
                jobs._publish(state / (operation + ".json"), value)
                self.start_daemon();pin=self.config()["daemonPin"]
                connection="adb:" + str(pin["pid"]) + ":" + pin["birth"]
                def guard():
                    repair._bridge()["guard_pin"](pin,self.port)
                    return connection
                binding = providers.AndroidBinding("socket-target", "owned-controlled-avd", self.client, "owned-controlled-avd", "emulator-5678", self.port)
                backend = providers.AndroidAdbBackend(binding, guard, wake_qualified=True)
                adapter = providers.ProviderAdapter("android-emulator", "socket-target", "owned-controlled-avd", backend)
                journal = self.base / "readiness";journal.mkdir(mode=0o700)
                fixture = SimpleNamespace(machine="owned-controlled-avd", adapter=adapter,
                    context=lambda: readiness.Context("socket-target", "owned-controlled-avd", adapter, readiness.RecoveryJournal(journal)))
                inputs={"fixtureId":"socket-fixture","operationId":operation}
                # Preserve the exact prior facade with only its package imports
                # made absolute for independent loading. It cannot continue
                # this actual failed owner's public restoration request.
                before_path=Path(__file__).parent/"fixtures/lease_daemon_loss_before/readiness_lease_workflow.py"
                before_spec=importlib.util.spec_from_file_location("lease_daemon_loss_before",before_path)
                before=importlib.util.module_from_spec(before_spec);before_spec.loader.exec_module(before)
                with self.assertRaisesRegex(ValueError,"lease_action_invalid"):
                    before.workflow(self.base,"reconcile",inputs)
                self.assertEqual("7",json.loads(self.state.read_text())["value"])
                with patch.object(flow.fixtures,"registered_fixture",return_value=fixture),patch.object(repair,"capture_adb_pin",return_value=pin):
                    actual=flow.workflow(self.base,"reconcile",inputs)
                self.assertIn(actual["state"],{"restoring","restored"}, actual)
                self.wait_job(repair.restoration_id(operation))
                with patch.object(flow.fixtures,"registered_fixture",side_effect=AssertionError("local status must not probe a guest")):
                    result=flow.workflow(self.base,"status",inputs)
                    again=flow.workflow(self.base,"reconcile",inputs)
                self.assertEqual("restored",result["state"])
                self.assertTrue(result["ok"])
                self.assertEqual(result,again)
        old_root.rmdir()


if __name__ == "__main__":
    unittest.main()
