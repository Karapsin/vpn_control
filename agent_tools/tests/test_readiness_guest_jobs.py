"""Full fixed guest source over real TCP and detached process ownership."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, redirect_stdout
import io
import json
import hashlib
import os
import plistlib
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import types
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness
from agent_tools import readiness_guest_jobs as facade
from agent_tools import readiness_qemu_jobs as protocol


@unittest.skipUnless(os.name == "posix" and os.geteuid() > 0, "ordinary POSIX user required")
class RegisteredGuestJobsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.machine = (Path('/etc/machine-id').read_text().strip() if sys.platform.startswith('linux') else
                        plistlib.loads(subprocess.check_output(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice', '-a'], timeout=3))[0]['IOPlatformUUID'])
        self.root = Path(self.temp.name).resolve()
        # reconcile's actual original-observation discriminant reads this private
        # registration itself; only registered_fixture below is controlled.
        registration = self.root / ".rag_index/readiness-fixtures"; registration.mkdir(mode=0o700, parents=True)
        descriptor = registration / "fixture.json"; descriptor.write_text('{"provider":"controlled-unqualified"}'); descriptor.chmod(0o600)
        self.guest = self.root / "guest-jobs"
        self.patch = patch.object(protocol, "ROOT", str(self.guest)); self.patch.start()
        self.darwin_patch = patch.object(protocol, "DARWIN_ROOT", str(self.guest)); self.darwin_patch.start()
        outer = self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                request = json.loads(self.rfile.readline(262145))
                if request.get("dropBefore"):
                    return
                argv, payload = protocol.stdin_command(request["source"])
                response = subprocess.run([sys.executable, *argv[1:]], input=payload, capture_output=True, timeout=8)
                if request["drop"]:
                    return
                self.wfile.write(json.dumps({"code": response.returncode,
                    "stdout": base64.b64encode(response.stdout).decode(),
                    "stderr": base64.b64encode(response.stderr).decode()}).encode()+b"\n")
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.namespace = None
        self.submissions = 0
        self.drop_submission_ack = False
        self.drop_before_submission = False
        self.observations = []
        self.recoveries = []
        binding = jobs.current_binding("fixture", self.machine)
        self.actual_boot = binding.boot
        self.executor_boot = binding.boot
        class Executor:
            provider = "tart-macos" if sys.platform == "darwin" else "tart-linux"
            target, machine = binding.target, binding.machine
            @property
            def boot(self):
                return outer.executor_boot
            uid, principal, home = os.geteuid(), "fixture", str(outer.root)
            def execute_source(self, source):
                submit = "'mode': 'submit'" in source
                if submit:
                    outer.submissions += 1
                drop = submit and outer.drop_submission_ack
                with socket.create_connection(outer.server.server_address, timeout=3) as channel:
                    before = submit and outer.drop_before_submission
                    if before:
                        outer.drop_before_submission = False
                    channel.sendall(json.dumps({"source": source, "drop": drop, "dropBefore": before}).encode()+b"\n")
                    stream = channel.makefile("rb")
                    raw = stream.readline(262145)
                    if not raw:
                        raise ConnectionResetError("owned fixture lost acknowledgement")
                    row = json.loads(raw)
                return subprocess.CompletedProcess([], row["code"], base64.b64decode(row["stdout"]), base64.b64decode(row["stderr"]))
        class Backend:
            capabilities = frozenset()
            @contextmanager
            def guest_job_executor(self, *, deadline):
                yield Executor()
            def load_guest_namespace(self):
                return outer.namespace
            def admit_guest_namespace(self, packet):
                if outer.namespace is not None and outer.namespace != packet:
                    raise ValueError("changed")
                outer.namespace = packet
        backend = Backend()
        class Adapter:
            capabilities = frozenset()
            backend = None
            def observe(self, requirements, deadline):
                outer.observations.append(requirements)
                return readiness.Observation(binding.target, binding.machine, connection="actual-owned-socket", boot=outer.executor_boot,
                    account=str(os.geteuid()), session="ordinary", transport="ready", guest="running", guest_agent=True,
                    trusted=True, owned=True, integrity=True)
            def recover(self, *args):
                outer.recoveries.append(args)
                raise AssertionError("healthy fixture recovered")
        adapter = Adapter(); adapter.backend = backend
        class Fixture:
            target, machine = binding.target, binding.machine
            adapter = None
            def context(self, *, deadline):
                path = outer.root / "journal"; path.mkdir(mode=0o700, exist_ok=True)
                return readiness.Context(binding.target, binding.machine, adapter, readiness.RecoveryJournal(path), deadline=deadline)
        fixture = Fixture(); fixture.adapter = adapter
        self.resolver = patch.object(facade.registry, "registered_fixture", return_value=fixture); self.resolver.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.resolver.stop(); self.patch.stop(); self.darwin_patch.stop(); self.temp.cleanup()

    def finish(self, operation):
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            result = facade.reconcile(self.root, "fixture", operation)
            if result["state"] == "terminal":
                return result
            time.sleep(.02)
        self.fail("guest sentinel did not finish")

    def test_real_socket_lost_submission_ack_fresh_caller_observes_once_and_local_tools(self):
        operation = str(uuid4()); self.drop_submission_ack = True
        result = facade.start(self.root, "fixture", operation, count=20, interval_seconds=.02)
        self.assertEqual((result["state"], result["operationId"]), ("unknown", operation))
        self.drop_submission_ack = False
        result = self.finish(operation)
        self.assertEqual(result["executions"], 1)
        self.assertEqual(result["counterValues"], 20)
        self.assertEqual(self.submissions, 1)
        self.assertEqual(facade.start(self.root, "fixture", operation, count=20, interval_seconds=.02), result)
        with patch.object(facade.registry, "registered_fixture", side_effect=AssertionError("local action recovered connection")):
            self.assertEqual(facade.status(self.root, "fixture", operation), result)
            self.assertEqual(facade.collect(self.root, "fixture", operation), result)
        self.assertFalse(self.recoveries)
        self.assertTrue(any(row.required == frozenset({"transport"}) and row.permitted_recoveries == frozenset({"reconnect"})
                            for row in self.observations))

    def test_deleted_namespace_after_enrollment_never_adopts_replacement_or_replays(self):
        operation = str(uuid4())
        facade.start(self.root, "fixture", operation, count=2, interval_seconds=.01)
        self.finish(operation)
        old = self.guest.rename(self.root / "old-jobs")
        self.guest.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            facade.start(self.root, "fixture", str(uuid4()), count=2, interval_seconds=.01)
        self.assertEqual(self.submissions, 1)
        self.assertFalse(list(self.guest.iterdir()))

    def test_public_arguments_cannot_supply_source_paths_or_replace_spec(self):
        with self.assertRaises(ValueError):
            facade.start(self.root, "fixture", str(uuid4()), count=True)
        operation = str(uuid4())
        facade.start(self.root, "fixture", operation, count=2, interval_seconds=.01)
        self.finish(operation)
        with self.assertRaises(ValueError):
            facade.start(self.root, "fixture", operation, count=3, interval_seconds=.01)
        self.assertEqual(self.submissions, 1)

    def test_prelaunch_socket_loss_retries_only_positive_original_absence(self):
        operation = str(uuid4()); self.drop_before_submission = True
        result = facade.workflow(self.root, "start", {"fixtureId": "fixture", "operationId": operation,
                                  "count": 12, "intervalSeconds": .02})
        self.assertEqual(result["state"], "unknown")
        self.assertFalse((self.guest / operation).exists())
        result = self.finish(operation)
        self.assertEqual(result["executions"], 1)
        self.assertEqual(self.submissions, 2)
        directory = self.root / ".runtime/readiness-guest-jobs/fixture" / operation
        self.assertEqual(len(list(directory.glob("unsubmitted-proof-*.json"))), 1)

    def test_concurrent_same_original_starts_have_one_remote_admission(self):
        # Establish namespace first so this test isolates operation admission,
        # while the provider's own cooperative operator owns enrollment.
        first = str(uuid4())
        facade.start(self.root, "fixture", first, count=1, interval_seconds=.01)
        self.finish(first)
        operation = str(uuid4())
        def call(_):
            try:
                return facade.start(self.root, "fixture", operation, count=12, interval_seconds=.02)
            except FileExistsError:
                return None  # A racing create-only host intent is a safe loser.
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(call, range(3)))
        result = self.finish(operation)
        self.assertEqual(result["executions"], 1)
        self.assertEqual(self.submissions, 2)  # warmup plus one new dispatch

    def test_workflow_rejects_unknown_inputs_before_fixture_or_transport(self):
        with patch.object(facade.registry, "registered_fixture", side_effect=AssertionError("unexpected lookup")):
            with self.assertRaises(ValueError):
                facade.workflow(self.root, "start", {"source": "untrusted"})

    def test_stale_unsubmitted_whole_before_red_current_same_uuid_amendment_green(self):
        directory = Path(__file__).parent / "fixtures/guest_unsubmitted_boot_before"
        path = directory / "readiness_guest_jobs.py.source"
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), json.loads((directory / "provenance.json").read_bytes())["sha256"]["readiness_guest_jobs.py"])
        before = types.ModuleType("agent_tools.guest_facade_before")
        before.__file__ = str(path); before.__package__ = "agent_tools"
        exec(compile(raw, str(path), "exec"), before.__dict__)
        operation = str(uuid4())
        self.executor_boot = str(uuid4())
        self.drop_before_submission = True
        initial = before.start(self.root, "fixture", operation, count=12, interval_seconds=.02)
        self.assertEqual(initial["state"], "unknown")
        local = self.root / ".runtime/readiness-guest-jobs/fixture" / operation
        original = (local / "intent.json").read_bytes()
        self.executor_boot = self.actual_boot
        with self.assertRaises(ValueError):
            before.reconcile(self.root, "fixture", operation)  # actual old caller RED
        self.assertFalse((self.guest / operation).exists())
        result = self.finish(operation)
        self.assertEqual(result["operationId"], operation)
        self.assertEqual(result["executions"], 1)
        self.assertEqual(result["binding"]["boot"], self.actual_boot)
        self.assertEqual((local / "intent.json").read_bytes(), original)
        self.assertEqual(len(list(local.glob("binding-amendment-*.json"))), 1)
        self.assertEqual(self.submissions, 2)  # one lost-before-admission request, one proven original retry

    def test_submitted_owner_and_admission_index_cannot_be_replaced(self):
        operation = str(uuid4())
        facade.start(self.root, "fixture", operation, count=12, interval_seconds=.02)
        result = self.finish(operation)
        local = self.root / ".runtime/readiness-guest-jobs/fixture" / operation
        original = (local / "intent.json").read_bytes()
        self.executor_boot = str(uuid4())  # renewed outer boot projection cannot replace terminal owner
        self.assertEqual(facade.reconcile(self.root, "fixture", operation), result)
        self.assertEqual((local / "intent.json").read_bytes(), original)
        self.assertFalse(list(local.glob("binding-amendment-*.json")))
        self.assertEqual(self.submissions, 1)

    def test_public_mcp_and_actual_cli_parser_share_original_socket_owner_schema(self):
        from agent_tools import mcp_server
        original = mcp_server._agent_module
        def module(name):
            return facade if name == "readiness_guest_jobs" else original(name)
        operation = str(uuid4())
        with patch.object(mcp_server, "REPO_ROOT", self.root), patch.object(mcp_server, "_agent_module", side_effect=module):
            result = mcp_server.vm_workflow("guest-program-start", {"fixtureId": "fixture", "operationId": operation,
                                              "count": 12, "intervalSeconds": .02})
            self.assertIn(result["state"], {"running", "terminal", "unknown"}, result)
            deadline = time.monotonic()+10
            inputs = self.root / "cli-inputs.json"
            inputs.write_text(json.dumps({"fixtureId": "fixture", "operationId": operation}))
            while time.monotonic() < deadline:
                output = io.StringIO()
                with redirect_stdout(output):
                    code = mcp_server.main(["vm-workflow", "guest-program-reconcile", "--inputs-file", str(inputs)])
                self.assertEqual(code, 0, output.getvalue())
                result = json.loads(output.getvalue())
                if result["state"] == "terminal":
                    break
                time.sleep(.02)
            self.assertEqual(result["state"], "terminal", result)
            public = mcp_server.vm_workflow("guest-program-collect", {"fixtureId": "fixture", "operationId": operation})
            output = io.StringIO()
            with redirect_stdout(output):
                code = mcp_server.main(["vm-workflow", "guest-program-collect", "--inputs-file", str(inputs)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue()), public)
            self.assertEqual(public["executions"], 1)
            self.assertEqual(public["counterValues"], 12)
            self.assertEqual(self.submissions, 1)


if __name__ == "__main__":
    unittest.main()
