"""Actual owner/process/socket tests; no SSH/provider acceptance is implied."""
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import warnings

from agent_tools import durable_remote_job as jobs

SOURCE = Path(jobs.__file__).resolve()
ENDPOINT = Path(__file__).parent / "fixtures" / "durable_remote_job" / "socket_endpoint.py"


@unittest.skipUnless(os.name == "posix" and (sys.platform.startswith("linux") or sys.platform == "darwin"),
                     "POSIX process-generation owner only")
class DurableRemoteJobTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.binding = jobs.current_binding("fixture", "owned-fixture")
        self.generation = jobs.root_generation(self.root)
        self.operation = str(uuid.uuid4())
        self.endpoints = []
        self.owners = []

    def tearDown(self):
        for process in self.endpoints:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
        # Test-owned inert actors only; no production VM/runtime is touched.
        for path in self.root.glob("*/owner.json"):
            try:
                owner = json.loads(path.read_text())["owner"]
                if jobs._birth(owner["pid"]) == owner["birth"]:
                    os.kill(owner["pid"], signal.SIGTERM)
            except (OSError, ValueError, KeyError):
                pass
        self.temp.cleanup()

    def program(self, source=b"print('complete')\n", limit=1024):
        return jobs.Program("test-sentinel", source, limit)

    def submit(self, program=None, operation=None):
        return jobs.submit(self.root, operation or self.operation, self.binding,
                           program or self.program(), generation=self.generation)

    def observe(self, operation=None):
        return jobs.observe(self.root, operation or self.operation, self.binding, generation=self.generation)

    def terminal(self, operation=None):
        deadline = time.monotonic() + 8
        result = None
        while time.monotonic() < deadline:
            result = self.observe(operation)
            if result["state"] == "terminal" or result["reason"] == "output_overflow":
                return result
            time.sleep(.02)
        self.fail("owner did not complete: " + str(result))

    def endpoint(self):
        ready = self.root / ("endpoint-" + str(len(self.endpoints)) + ".json")
        process = subprocess.Popen([sys.executable, "-I", "-B", str(ENDPOINT), str(SOURCE), str(self.root), str(ready)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.endpoints.append(process)
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline and process.poll() is None:
            time.sleep(.01)
        self.assertIsNone(process.poll())
        return process, json.loads(ready.read_text())["port"]

    def call(self, port, action, drop=False):
        with socket.create_connection(("127.0.0.1", port), timeout=3) as channel:
            channel.sendall(json.dumps({"action": action, "operationId": self.operation,
                                       "dropReply": drop}).encode() + b"\n")
            channel.shutdown(socket.SHUT_WR)
            if drop:
                return None
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = channel.recv(65536)
                if not chunk:
                    self.fail("endpoint closed before its reply")
                raw += chunk
            return json.loads(raw)

    def test_real_generated_owner_retains_dual_streams_and_nonzero_receipt(self):
        self.submit(self.program(b"import sys;print('sentinel');sys.stderr.write('private\\n');sys.exit(7)"))
        result = self.terminal()
        self.assertEqual(7, result["terminal"]["exitCode"])
        result, stdout, stderr = jobs.collect(self.root, self.operation, self.binding, generation=self.generation)
        self.assertEqual((b"sentinel\n", b"private\n"), (stdout, stderr))
        self.assertNotIn("private", json.dumps(result))
        for path in (self.root / self.operation).iterdir():
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_socket_disconnect_before_submission_is_proven_unsubmitted(self):
        _, port = self.endpoint()
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass
        self.assertEqual("unsubmitted", self.call(port, "observe")["state"])
        self.call(port, "submit")
        self.terminal()
        self.assertEqual(1, (self.root / "counter").read_text().splitlines().count("execution"))

    def test_socket_ack_loss_during_execution_reconnects_to_same_owner_once(self):
        _, port = self.endpoint()
        self.call(port, "submit", drop=True)
        deadline = time.monotonic() + 5
        while not (self.root / self.operation / "owner.json").exists() and time.monotonic() < deadline:
            time.sleep(.01)
        original = self.call(port, "observe")
        self.assertEqual("running", original["state"])
        before = len((self.root / "counter").read_text().splitlines()) if (self.root / "counter").exists() else 0
        time.sleep(.12)
        self.assertGreater(len((self.root / "counter").read_text().splitlines()), before)
        self.assertEqual(original["owner"], self.call(port, "submit")["owner"])
        terminal = self.terminal()
        self.assertEqual(original["owner"], terminal["owner"])
        result = self.call(port, "collect")
        self.assertEqual(list(range(15)), [int(x) for x in base64.b64decode(result["privateStdout"]).splitlines()])
        self.assertEqual(1, (self.root / "counter").read_text().splitlines().count("execution"))

    def test_server_death_restart_and_lost_terminal_ack_do_not_relaunch(self):
        process, port = self.endpoint()
        self.call(port, "submit")
        deadline = time.monotonic() + 3
        while self.observe()["state"] != "running" and time.monotonic() < deadline:
            time.sleep(.01)
        original = self.observe()["owner"]
        process.terminate()
        process.wait(timeout=5)
        self.terminal()
        _, new_port = self.endpoint()
        self.call(new_port, "collect", drop=True)
        result = self.call(new_port, "submit")
        self.assertEqual("terminal", result["state"])
        self.assertEqual(original, result["owner"])
        self.assertEqual(1, (self.root / "counter").read_text().splitlines().count("execution"))

    def test_concurrent_admission_has_one_execution(self):
        count = self.root / "invocations"
        source = ("import pathlib,time\nwith pathlib.Path(" + repr(str(count)) + ").open('a') as out:out.write('once\\n')\ntime.sleep(.1)\n").encode()
        program = self.program(source)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: self.submit(program), range(32)))
        self.terminal()
        self.assertEqual("once\n", count.read_text())
        self.assertTrue(all(result["replayAllowed"] is False for result in results))
        self.assertEqual("terminal", self.submit(program)["state"])

    def test_duplicate_program_or_binding_change_refuses_without_replacement(self):
        self.submit()
        self.terminal()
        original = (self.root / self.operation / "intent.json").read_bytes()
        self.assertEqual("operation_admission_conflict", self.submit(self.program(b"print('changed')"))["reason"])
        other = replace(self.binding, machine="different-machine")
        result = jobs.observe(self.root, self.operation, other, generation=self.generation)
        self.assertEqual("operation_binding_mismatch", result["reason"])
        self.assertEqual(original, (self.root / self.operation / "intent.json").read_bytes())

    def test_consumed_admission_without_owner_stays_unknown_and_never_executes(self):
        (self.root / self.operation).mkdir(mode=0o700)
        result = self.submit()
        self.assertEqual("unknown", result["state"])
        self.assertEqual("operation_admission_conflict", result["reason"])
        self.assertEqual([], list((self.root / self.operation).iterdir()))

    def test_stale_unsubmitted_boot_is_refused_before_admission(self):
        stale = replace(self.binding, boot=str(uuid.uuid4()))
        with self.assertRaisesRegex(jobs.DurableJobError, "boot_changed"):
            jobs.submit(self.root, self.operation, stale, self.program(), generation=self.generation)
        self.assertFalse((self.root / self.operation).exists())

    def test_root_replacement_does_not_claim_proven_unsubmitted(self):
        result = jobs.observe(self.root, self.operation, self.binding,
                              generation=(self.generation[0], self.generation[1] + 1))
        self.assertEqual("root_generation_changed", result["reason"])
        self.assertEqual("unknown", result["state"])

    def test_output_overflow_is_bounded_retained_and_unknown_without_replay(self):
        program = self.program(b"import sys;sys.stdout.write('x'*100000);sys.stderr.write('y'*200000)", limit=73)
        self.submit(program)
        result = self.terminal()
        self.assertEqual(("unknown", "output_overflow"), (result["state"], result["reason"]))
        for name, total in (("stdout", 100000), ("stderr", 200000)):
            self.assertEqual(73, (self.root / self.operation / (name + ".bin")).stat().st_size)
            self.assertEqual(total, result["terminal"][name]["totalBytes"])
        with self.assertRaisesRegex(jobs.DurableJobError, "collection_not_terminal"):
            jobs.collect(self.root, self.operation, self.binding, generation=self.generation)
        self.assertEqual("unknown", self.submit(program)["state"])

    def test_stream_tampering_is_rejected_without_private_error_disclosure(self):
        self.submit()
        self.terminal()
        (self.root / self.operation / "stdout.bin").write_text("secret-test-value")
        with self.assertRaisesRegex(jobs.DurableJobError, "stream_integrity_mismatch") as raised:
            jobs.collect(self.root, self.operation, self.binding, generation=self.generation)
        self.assertNotIn("secret-test-value", str(raised.exception))

    def test_malformed_terminal_and_owner_are_unknown_without_private_values(self):
        self.submit()
        self.terminal()
        terminal = self.root / self.operation / "terminal.json"
        original = terminal.read_bytes()
        terminal.write_text('{"private":"secret-test-value"}')
        result = self.observe()
        self.assertEqual("unknown", result["state"])
        self.assertNotIn("secret-test-value", json.dumps(result))
        terminal.write_bytes(original)
        owner = self.root / self.operation / "owner.json"
        value = json.loads(owner.read_text())
        value["owner"] = {"pid": 1, "private": "secret-test-value"}
        owner.write_text(json.dumps(value))
        result = self.observe()
        self.assertEqual("unknown", result["state"])
        self.assertNotIn("secret-test-value", json.dumps(result))

    def test_original_owner_death_is_unknown_and_consumed_admission_cannot_replay(self):
        # Only terminate this exact inert test-owned owner after process birth
        # verification. Its child naturally exits shortly and no runtime exists.
        counter = self.root / "death-counter"
        source = ("import pathlib,time\nwith pathlib.Path(" + repr(str(counter)) + ").open('a') as out:out.write('once\\n');out.flush()\ntime.sleep(.2)\n").encode()
        program = self.program(source)
        self.submit(program)
        deadline = time.monotonic() + 5
        while not counter.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(counter.exists())
        owner = json.loads((self.root / self.operation / "owner.json").read_text())["owner"]
        self.assertEqual(owner["birth"], jobs._birth(owner["pid"]))
        os.kill(owner["pid"], signal.SIGTERM)
        deadline = time.monotonic() + 5
        while jobs._birth(owner["pid"]) == owner["birth"] and time.monotonic() < deadline:
            time.sleep(.01)
        result = self.submit(program)
        self.assertEqual(("unknown", "original_owner_missing"), (result["state"], result["reason"]))
        time.sleep(.25)
        self.assertEqual("once\n", counter.read_text())

    def test_source_larger_than_argv_limit_uses_private_stdin_snapshot(self):
        source = b"# padding\n" * 7000 + b"print('large-source-complete')\n"
        self.assertGreater(len(source), 60000)
        self.submit(self.program(source))
        self.terminal()
        _, stdout, stderr = jobs.collect(self.root, self.operation, self.binding, generation=self.generation)
        self.assertEqual((b"large-source-complete\n", b""), (stdout, stderr))

    def test_detached_owner_is_reaped_without_resource_warning(self):
        with warnings.catch_warnings(record=True) as received:
            warnings.simplefilter("always", ResourceWarning)
            self.submit(self.program(b"import time;time.sleep(.2)"))
        self.terminal()
        self.assertEqual([], [str(row.message) for row in received if row.category is ResourceWarning])

    def test_invalid_identity_program_and_nonprivate_state_refuse(self):
        for operation in ("../bad", str(uuid.uuid4()).upper(), "password-value"):
            with self.assertRaisesRegex(jobs.DurableJobError, "operation_identity_invalid"):
                jobs.observe(self.root, operation, self.binding, generation=self.generation)
        with self.assertRaisesRegex(jobs.DurableJobError, "program_invalid"):
            self.program(b"x" * (jobs.MAX_PROGRAM_BYTES + 1))
        self.root.chmod(0o755)
        self.assertEqual("private_state_unsafe", self.observe()["reason"])


if __name__ == "__main__":
    unittest.main()
