"""Real generated launch-owner/socket tests; native provider proof stays separate."""
import ast
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import uuid

from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart as tart
from agent_tools import tart_linux_probe as probe


class TartProbeTest(unittest.TestCase):
    def test_collected_original_missing_after_boot_closes_only_exact_absence(self):
        source = Path(probe.__file__)
        if os.environ.get("VPN_TEST_TART_COLLECTED_OWNER_BEFORE"):
            source = Path(__file__).parent / "fixtures/tart_collected_owner_before.py"
        namespace = {"__name__": "owned_collected_probe"}
        exec(compile(source.read_bytes(), str(source), "exec"), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = root / "tmp"; guest.mkdir()
            machine = root / "machine"; machine.write_text("0" * 32)
            boot = root / "boot"; boot.write_text("new-boot")
            operation = str(uuid.uuid4())
            remote = "/tmp/vpn-control-program-" + str(os.getuid()) + "-" + operation
            packet = {"remoteRoot": remote, "generation": [1, 2], "operationId": operation,
                      "binding": {"target": "owned", "machine": "0" * 32, "boot": "old-boot", "account": str(os.getuid())},
                      "requestSha256": "0" * 64, "ownerSourceSha256": hashlib.sha256(jobs.owner_source()).hexdigest()}
            def local_path(*parts):
                value = Path(*parts)
                if value == Path("/tmp"): return guest
                if value == Path("/etc/machine-id"): return machine
                if value == Path("/proc/sys/kernel/random/boot_id"): return boot
                if str(value).startswith("/tmp/vpn-control-program-"): return guest / value.name
                return value
            namespace.update(Path=local_path, __guest_jobs__=[packet], __collected_guest_jobs__=[packet],
                             __owner_source__=jobs.owner_source())
            observe = namespace["_guest_owner_facts"]
            value = observe()
            self.assertTrue(value["complete"], value)
            self.assertEqual(value["collectedAbsences"], [operation])
            for mutation in ("uncollected", "same_boot", "reappeared", "dangling_symlink", "wrong_machine"):
                with self.subTest(mutation=mutation):
                    namespace["__collected_guest_jobs__"] = [] if mutation == "uncollected" else [packet]
                    boot.write_text("old-boot" if mutation == "same_boot" else "new-boot")
                    machine.write_text("1" * 32 if mutation == "wrong_machine" else "0" * 32)
                    path = guest / Path(remote).name
                    if mutation == "reappeared": path.mkdir()
                    if mutation == "dangling_symlink": path.symlink_to(root / "absent")
                    try:
                        self.assertFalse(observe()["complete"])
                    finally:
                        if path.is_symlink(): path.unlink()
                        elif path.is_dir(): path.rmdir()

    def test_cgroup_newline_retains_exact_service_identity(self):
        raw = "0::/system.slice/tart-guest-agent.service\n"
        if os.environ.get("VPN_TEST_TART_CGROUP_BEFORE"):
            source = Path(__file__).parent / "fixtures/tart_cgroup_newline_before.py"
            tree = ast.parse(source.read_text())
            expression = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                              and any(isinstance(name, ast.Name) and name.id == "unit" for name in node.targets))
            actual = eval(compile(ast.Expression(expression), str(source), "eval"), {"cgroup": raw})
        else:
            actual = probe.cgroup_unit(raw)
        self.assertEqual(actual, "tart-guest-agent.service")

    def test_unknown_durable_namespace_without_live_pid_blocks_complete_idle(self):
        namespace = vars(probe).copy()
        if os.environ.get("VPN_TEST_TART_GUEST_OWNERS_BEFORE"):
            source = Path(__file__).parent / "fixtures/tart_guest_owners_before.py"
            namespace = {"__name__": "unfixed_tart_guest_probe"}
            exec(compile(source.read_bytes(), str(source), "exec"), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "proc").mkdir()
            (root / "guest").mkdir()
            (root / "guest" / ("vpn-control-program-" + str(os.getuid()) + "-" + str(uuid.uuid4()))).mkdir(mode=0o700)
            def local_path(*parts):
                value = Path(*parts)
                return root / "proc" if value == Path("/proc") else root / "guest" if value == Path("/tmp") else value
            # Execute the complete actual projection, including real on-disk
            # namespace enumeration. There is deliberately no live job PID.
            function = namespace["_job_facts"]
            saved = function.__globals__["Path"]
            function.__globals__["Path"] = local_path
            try:
                value = function({key: {} for key in namespace["_UNITS"]})
            finally:
                function.__globals__["Path"] = saved
            self.assertFalse(value["jobVisibilityComplete"])
            self.assertTrue(value["unknownJobs"])

    def test_active_packagekit_and_wrong_service_pid_block(self):
        state = "MainPID=91\nActiveState=active\nSubState=running\n"
        self.assertEqual(probe.installer_role(91, b"/usr/libexec/packagekitd\0", state, b"ao 1 /transaction\n"), "blocked")
        self.assertEqual(probe.installer_role(90, b"/usr/libexec/packagekitd\0", state, b"ao 0\n"), "blocked")
        self.assertEqual(probe.installer_role(91, b"/usr/libexec/packagekitd\0", state, b"ao 0\n"), "packagekit_idle")

    def test_fwupd_idle_requires_no_devices_or_history_and_actual_service_pid(self):
        classify = probe.installer_role
        if os.environ.get("VPN_TEST_TART_FWUPD_BEFORE"):
            source = Path(__file__).parent / "fixtures/tart_fwupd_idle_before.py"
            function = next(node for node in ast.parse(source.read_text()).body
                            if isinstance(node, ast.FunctionDef) and node.name == "installer_role")
            namespace = {}
            exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), "exec"), namespace)
            classify = namespace["installer_role"]
        state = "MainPID=994\nActiveState=active\nSubState=running\n"
        idle = ((0, b"u 1\n", b""), (1, b"", b"Call failed: No detected devices\n"),
                (1, b"", b"Call failed: No history\n"))
        self.assertEqual(classify(994, b"/usr/libexec/fwupd/fwupd\0", state, idle), "fwupd_idle_no_devices")
        for changed in (((0, b"u 5\n", b""), *idle[1:]), (idle[0], (0, b"devices", b""), idle[2]),
                        (idle[0], idle[1], (0, b"history", b""))):
            self.assertEqual(classify(994, b"/usr/libexec/fwupd/fwupd\0", state, changed), "blocked")
        self.assertEqual(classify(993, b"/usr/libexec/fwupd/fwupd\0", state, idle), "blocked")


class TartCanonicalJobsTest(unittest.TestCase):
    def backend(self, response, returncode=0):
        namespace = {"schemaVersion": 1, "root": "/var/tmp/vc-recovery-jobs", "generation": [1, 2],
                     "admissionGeneration": [1, 3], "target": "fixture", "machine": "0" * 32,
                     "actualMachineId": "0" * 32, "account": "1000",
                     "ownerSourceSha256": hashlib.sha256(jobs.owner_source()).hexdigest()}
        backend = tart.TartBackend(None, SimpleNamespace(load_guest_namespace=lambda: namespace))
        backend._guest = lambda argv, deadline, payload=None: (SimpleNamespace(
            returncode=returncode, stdout=json.dumps(response).encode()), {})
        return backend

    def facts(self, complete=True):
        return {"jobVisibilityComplete": False, "legacyJobVisibilityComplete": complete,
                "canonicalOwnerPresent": True, "runningJobs": [], "unknownJobs": []}

    def test_terminal_canonical_namespace_cannot_hide_unknown_legacy_owner(self):
        backend = self.backend({"visibilityComplete": True, "jobs": [], "idle": True})
        facts = self.facts(False)
        facts["unknownJobs"] = [{"role": "unadmitted_durable_namespace"}]
        result = backend._canonical_jobs(facts, time.monotonic() + 10)
        self.assertFalse(result["jobVisibilityComplete"])
        self.assertEqual(result["unknownJobs"], [{"role": "unadmitted_durable_namespace"}])

    def test_running_and_unknown_canonical_owners_remain_idle_blockers(self):
        active, uncertain = str(uuid.uuid4()), str(uuid.uuid4())
        backend = self.backend({"visibilityComplete": True, "jobs": [
            {"operationId": active, "state": "running"}, {"operationId": uncertain, "state": "unknown"}], "idle": False})
        result = backend._canonical_jobs(self.facts(), time.monotonic() + 10)
        self.assertTrue(result["jobVisibilityComplete"])
        self.assertEqual(result["runningJobs"], [{"operationId": active, "role": "durable_running"}])
        self.assertEqual(result["unknownJobs"], [{"operationId": uncertain, "role": "durable_unknown"}])

    def test_inconsistent_or_failed_canonical_observer_never_proves_idle(self):
        response = {"visibilityComplete": True, "jobs": [{"operationId": str(uuid.uuid4()), "state": "running"}], "idle": True}
        for backend in (self.backend(response), self.backend({}, returncode=1)):
            with self.subTest(backend=backend):
                result = backend._canonical_jobs(self.facts(), time.monotonic() + 10)
                self.assertFalse(result["jobVisibilityComplete"])
                self.assertEqual(result["unknownJobs"], [{"role": "canonical_owner_unresolved"}])


@unittest.skipUnless(os.name == "posix" and (sys.platform == "darwin" or sys.platform.startswith("linux")),
                     "POSIX durable host owner required")
class TartGeneratedStartTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tart-owner-", dir="/tmp")
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.lifecycle = self.root / "lifecycle"; self.lifecycle.mkdir(mode=0o700)
        self.job_root = self.lifecycle / "jobs"; self.job_root.mkdir(mode=0o700)
        self.vm = self.root / "vpn-tool-recovery-tart-linux-test"; self.vm.mkdir(mode=0o700)
        self.config = self.vm / "config.json"; self.config.write_text('{"os":"linux"}')
        self.disk = self.vm / "disk.img"; self.disk.write_bytes(b"inert-fixture")
        self.config.chmod(0o600); self.disk.chmod(0o600)
        self.release = threading.Event(); self.admitted = threading.Event(); self.starts = 0
        self.socket_path = self.root / "s"
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.socket_path)); self.server.listen(); self.server.settimeout(.1)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True); self.thread.start()
        self.binary = self.root / "tart"
        self.binary.write_text("#!" + sys.executable + "\nimport json,socket,sys\n"
                               "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
                               "s.connect(" + repr(str(self.socket_path)) + ")\n"
                               "s.sendall(json.dumps({'action':sys.argv[1]}).encode()+b'\\n')\n"
                               "with s.makefile('rb') as f:\n"
                               " for line in f: sys.stdout.buffer.write(line);sys.stdout.buffer.flush()\n")
        self.binary.chmod(0o700)
        config_pin = {"generation": list(private._generation(self.config.stat())),
                      "sha256": hashlib.sha256(self.config.read_bytes()).hexdigest()}
        d = self.disk.stat()
        self.custody = SimpleNamespace(lifecycle_root=self.lifecycle, descriptor={"configPin": config_pin,
            "diskPin": {"device": d.st_dev, "inode": d.st_ino, "size": d.st_size, "uid": d.st_uid,
                        "mode": stat.S_IMODE(d.st_mode)}, "binaryPin": list(private._generation(self.binary.stat()))})
        self.binding = tart.TartBinding("socket-fixture", "0" * 32, self.vm.name, self.binary, self.vm)
        self.host = jobs.current_binding("socket-fixture", "test-host")
        self.generation = jobs.root_generation(self.job_root)
        self.operation = str(uuid.uuid4())

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                request = json.loads(connection.makefile("rb").readline())
                if request["action"] == "get":
                    connection.sendall(b'{"State":"stopped","Running":false}\n')
                elif request["action"] == "run":
                    self.starts += 1; self.admitted.set()
                    connection.sendall(b"same-original-start\n")
                    self.release.wait(8)
                    connection.sendall(b"same-original-terminal\n")

    def tearDown(self):
        self.release.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not (self.job_root / self.operation).exists():
                break
            status = jobs.observe(self.job_root, self.operation, self.host, generation=self.generation)
            if status["state"] == "terminal":
                break
            time.sleep(.02)
        self.stop.set(); self.server.close(); self.thread.join(timeout=2); self.temp.cleanup()

    def terminal(self):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            status = jobs.observe(self.job_root, self.operation, self.host, generation=self.generation)
            if status["state"] == "terminal":
                return status
            time.sleep(.02)
        self.fail("original start owner did not close")

    def test_saved_start_program_executes_once_and_retains_original_output(self):
        program = tart.start_program(self.binding, self.custody, self.operation, "a" * 64)
        jobs.submit(self.job_root, self.operation, self.host, program, generation=self.generation)
        self.assertTrue(self.admitted.wait(5), "generated owner did not execute controlled Tart CLI")
        original = jobs.observe(self.job_root, self.operation, self.host, generation=self.generation)
        again = jobs.submit(self.job_root, self.operation, self.host, program, generation=self.generation)
        self.assertEqual(original["owner"], again["owner"])
        self.assertEqual(self.starts, 1)
        actor = json.loads((self.lifecycle / "active.json").read_text())
        self.assertEqual(actor["operationId"], self.operation)
        self.assertEqual(jobs._birth(actor["actor"]["pid"]), actor["actor"]["birth"])
        self.release.set(); self.terminal()
        result, stdout, stderr = jobs.collect(self.job_root, self.operation, self.host, generation=self.generation)
        self.assertEqual(result["terminal"]["exitCode"], 0)
        self.assertEqual(stdout, b"same-original-start\nsame-original-terminal\n")
        self.assertEqual(stderr, b"")

    def test_changed_config_is_rejected_before_cli_or_vm_launch(self):
        program = tart.start_program(self.binding, self.custody, self.operation, "b" * 64)
        self.config.write_text('{"changed":true}')
        jobs.submit(self.job_root, self.operation, self.host, program, generation=self.generation)
        result = self.terminal()
        self.assertNotEqual(result["terminal"]["exitCode"], 0)
        self.assertEqual(self.starts, 0)
        self.assertFalse((self.lifecycle / "active.json").exists())


if __name__ == "__main__":
    unittest.main()
