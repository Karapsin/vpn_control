"""Real local SSH-boundary children; no network, VM, VPN or installed product."""
import hashlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import unittest
import uuid
from unittest import mock

from agent_tools.tests.test_ssh_automatic_program import PeerFixture


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def target():
    import pwd
    user = pwd.getpwuid(os.getuid())
    if sys.platform.startswith("linux"):
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    else:
        boot = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], text=True).strip().lower()
    return {"kind": "ssh", "uid": os.getuid(), "principal": user.pw_name, "home": user.pw_dir, "bootId": boot}


def original_worker_exited(directory):
    """True once the exact original worker that start() recorded in owner.json is gone."""
    from agent_tools import ssh_channel_keeper_entry as keeper
    try:
        owner = json.loads((directory / "owner.json").read_bytes())
        return keeper.actor(owner["actor"]["pid"]) != owner["actor"]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return True


@unittest.skipUnless(os.name == "posix", "configured POSIX peer")
class ProgramExecutionTests(unittest.TestCase):
    def setUp(self):
        global subject, remote, loader
        from agent_tools import ssh_program_execution as subject
        from agent_tools import ssh_program_execution_remote as remote
        from agent_tools import source_module_loader as loader
        temporary = tempfile.TemporaryDirectory(dir=Path("/tmp").resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.peer = PeerFixture(self.root)
        binary = self.root / "bin"
        binary.mkdir(mode=0o700)
        shutil.copyfile(self.peer.binary, binary / "ssh")
        (binary / "ssh").chmod(0o700)
        self.environment = mock.patch.dict(os.environ, {"PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "TMPDIR": str(self.peer.peer), "TMP": str(self.peer.peer), "TEMP": str(self.peer.peer)})
        self.environment.start(); self.addCleanup(self.environment.stop)
        self.operation = str(uuid.uuid4())

    def request(self, source, args=None, cwd=None):
        return {"operationId": self.operation, "program": {"language": "python3", "source": source,
                "args": args or [], "cwd": str(cwd or self.root), "targetContext": target()}}

    def start(self, request, source_root=SOURCE_ROOT):
        module = loader
        if source_root != SOURCE_ROOT:
            name = "_owned_program_loader_" + uuid.uuid4().hex
            spec = importlib.util.spec_from_file_location(name, source_root / "agent_tools/source_module_loader.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            self.addCleanup(sys.modules.pop, name, None)
            spec.loader.exec_module(module)
        proxy = module.Adapter(source_root / "agent_tools", "ssh_program_execution")
        try:
            return proxy.start(self.root, "explicit-peer", request, source_context=proxy._session,
                               **({"durable": False} if source_root == SOURCE_ROOT else {}))
        finally:
            proxy.close()

    def observe(self):
        return subject.status(self.root, "explicit-peer", {"operationId": self.operation})

    def terminal(self, deadline=15):
        end = time.monotonic() + deadline
        directory = self.root / ".rag_index/ssh-program-execution" / self.operation
        stderr = directory / "worker.stderr.private"
        while time.monotonic() < end:
            result = self.observe()
            if result["state"] == "terminal":
                return result
            if result["state"] == "unknown" and not (directory / "owner-closed.json").exists():
                # A worker's traceback reaches this file in several writes (CPython 3.12
                # writes each File line before reading its source line), and a legacy
                # intent is unknown from the first observation. Report the whole stderr
                # only once that exact recorded worker has exited.
                if stderr.exists() and stderr.stat().st_size and original_worker_exited(directory):
                    self.fail("Original worker failed before terminal: " + stderr.read_text(errors="backslashreplace"))
            time.sleep(.05)
        self.fail("Original program did not reach a verified terminal: " + json.dumps(self.observe())
                  + "\nOriginal worker stderr so far: "
                  + (stderr.read_text(errors="backslashreplace") if stderr.exists() else "<absent>"))

    def raw(self, name):
        return (self.root / ".rag_index/ssh-program-execution" / self.operation / (name + ".private")).read_bytes()

    def test_real_small_child_preserves_main_args_cwd_streams_exit_and_duplicate_identity(self):
        source = ("import __main__,json,os,pickle,sys\n"
                  "class Sample: pass\n"
                  "assert __main__.Sample is Sample\nassert type(pickle.loads(pickle.dumps(Sample()))) is Sample\n"
                  "print(json.dumps({'args':sys.argv,'cwd':os.getcwd()},ensure_ascii=False))\n"
                  "sys.stderr.write('東京 stderr\\n')\nraise SystemExit(7)\n")
        request = self.request(source, ["space argument", "Ω ' quote", "backslash\\"])
        self.start(request)
        result = self.terminal()
        self.assertEqual(7, result["exitCode"])
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), result["sourceSha256"])
        intent = json.loads((self.root / ".rag_index/ssh-program-execution" / self.operation / "intent.json").read_bytes())
        self.assertEqual(source.encode(), intent["request"]["program"]["source"].encode())
        self.assertEqual(["-c", *request["program"]["args"]], json.loads(self.raw("stdout"))["args"])
        self.assertEqual(str(self.root), json.loads(self.raw("stdout"))["cwd"])
        self.assertEqual("東京 stderr\n".encode(), self.raw("stderr"))
        self.assertTrue(all(pin["eof"] for pin in result["streams"].values()))
        self.assertEqual(result, self.start(request))
        self.assertEqual(1, len(self.peer.events()))
        refusal = subject.admit_start(self.root, "explicit-peer", self.request("print('different')"))
        self.assertEqual({"state": "refused", "reason": "program_operation_conflict"}, {key: refusal[key] for key in ("state", "reason")})
        with self.assertRaisesRegex(ValueError, "program_operation_conflict"):
            self.start(self.request("print('different')"))
        self.assertEqual(1, len(self.peer.events()))

    def test_real_long_child_uses_existing_bounded_saved_source_transport(self):
        marker = self.root / "program-marker"
        source = "PADDING=" + repr("Ω'\\\"" * 14000) + "\nfrom pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('once')\nprint('complete')\n"
        self.start(self.request(source))
        result = self.terminal()
        self.assertEqual(0, result["exitCode"])
        self.assertEqual("once", marker.read_text())
        self.assertEqual(b"complete\n", self.raw("stdout"))
        self.assertEqual("saved-file", result["transport"])
        self.assertEqual(len(source.encode()), result["sourceBytes"])
        self.assertGreater(result["originalCommandBounds"]["wholeArgvBytes"], 60000)
        self.assertLessEqual(result["capture"]["submittedCommandBounds"]["wholeArgvBytes"], 60000)
        self.assertGreaterEqual(len(self.peer.events()), 2)
        self.assertTrue(all(event["commandBytes"] <= 60000 and event["maxArgumentBytes"] <= 60000 for event in self.peer.events()))

    def test_pending_status_does_not_replay_and_client_return_keeps_original_child(self):
        ready, release = self.root / "ready", self.root / "release"
        source = ("from pathlib import Path\nimport time\nPath(" + repr(str(ready)) + ").write_text('original')\n"
                  "while not Path(" + repr(str(release)) + ").exists():time.sleep(.02)\nprint('finished')\n")
        request = self.request(source)
        self.start(request)
        end = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < end:
            time.sleep(.02)
        try:
            self.assertTrue(ready.exists())
            self.assertEqual("pending", self.observe()["state"])
            self.assertEqual("pending", self.start(request)["state"])
            self.assertEqual(1, len(self.peer.events()))
        finally:
            release.write_text("finish original")
        self.assertEqual(0, self.terminal()["exitCode"])
        self.assertEqual(1, len(self.peer.events()))

    def original_source_root(self, remote_before=False, owner_fixture=None):
        # Start from the actual transitive snapshot, then replace only complete,
        # byte-preserved unfixed modules. No model of their implementation.
        self.start(self.request("print('snapshot source closure')"))
        self.terminal()
        source_root = self.root / ("before-source-" + str(uuid.uuid4()))
        capsule = self.root / ".rag_index/ssh-program-execution" / self.operation / "capsule"
        shutil.copytree(capsule, source_root)
        fixture = Path(__file__).parent / "fixtures/program_execution_before"
        names = ["ssh_program_execution.py"]
        if remote_before:
            names.append("ssh_program_execution_remote.py")
        for name in names:
            if owner_fixture is not None and name == "ssh_program_execution.py":
                raw = (owner_fixture / (name + ".source")).read_bytes()
                pin = json.loads((owner_fixture / "provenance.json").read_bytes())
            else:
                raw = (fixture / (name + ".source")).read_bytes()
                pin = json.loads((fixture / "provenance.json").read_bytes())["files"][name]
            self.assertEqual(pin["sha256"], hashlib.sha256(raw).hexdigest())
            (source_root / "agent_tools" / name).write_bytes(raw)
        self.operation = str(uuid.uuid4())
        return source_root

    def test_original_route_order_failure_and_fixed_actual_worker(self):
        before_root = self.original_source_root(remote_before=True)
        marker = self.root / "ordered-target-marker"
        request = self.request("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('once')\n")
        self.start(request, before_root)
        directory = self.root / ".rag_index/ssh-program-execution" / self.operation
        end = time.monotonic() + 10
        # The original worker's traceback reaches this file in several writes. Wait for
        # the asserted error text itself, not the first non-empty observation.
        while time.monotonic() < end and b"program_route_changed_before_launch" not in (directory / "worker.stderr.private").read_bytes():
            time.sleep(.02)
        self.assertIn(b"program_route_changed_before_launch", (directory / "worker.stderr.private").read_bytes())
        self.assertFalse(marker.exists())
        self.assertFalse((directory / "execution-intent.json").exists())
        self.operation = str(uuid.uuid4())
        request["operationId"] = self.operation
        self.start(request)
        self.assertEqual(0, self.terminal()["exitCode"])
        self.assertEqual("once", marker.read_text())

    def test_unfixed_worker_path_executes_swapped_source_fixed_preexec_refuses(self):
        before_root = self.original_source_root()
        original_popen = subprocess.Popen
        for source_root, expected_effect in ((before_root, True), (SOURCE_ROOT, False)):
            self.operation = str(uuid.uuid4())
            marker = self.root / ("swapped-" + self.operation)
            children = []
            def swapped(argv, *args, **kwargs):
                worker = self.root / ".rag_index/ssh-program-execution" / self.operation / "worker.py"
                is_worker = argv[0] == sys.executable and "-I" in argv and worker.exists()
                if is_worker:
                    worker.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('untrusted')\n")
                child = original_popen(argv, *args, **kwargs)
                if is_worker:
                    children.append(child)
                return child
            with mock.patch.object(subprocess, "Popen", side_effect=swapped):
                self.start(self.request("print('never reached target')"), source_root)
            for child in children:
                child.wait(timeout=10)
            self.assertEqual(expected_effect, marker.exists())
            directory = self.root / ".rag_index/ssh-program-execution" / self.operation
            self.assertFalse((directory / "execution-intent.json").exists())
            if not expected_effect:
                self.assertIn(b"program_worker_shape", (directory / "worker.stderr.private").read_bytes())

    def test_reaper_start_failure_waits_original_real_child(self):
        ready, release = self.root / "reaper-ready", self.root / "reaper-release"
        child = subprocess.Popen([sys.executable, "-c", "from pathlib import Path;import time;Path(" + repr(str(ready)) + ").touch();time.sleep(.1);Path(" + repr(str(release)) + ").touch()"])
        try:
            with mock.patch.object(subject.threading.Thread, "start", side_effect=RuntimeError("thread refused")):
                with self.assertRaisesRegex(RuntimeError, "thread refused"):
                    subject._reap(child)
            self.assertEqual(0, child.returncode)
            self.assertTrue(ready.exists() and release.exists())
        finally:
            child.wait(timeout=10)

    def test_ssh_exit_255_is_unknown_and_identical_start_never_replays(self):
        self.peer.mode.write_text("reject")
        request = self.request("print('never started')")
        self.start(request)
        directory = self.root / ".rag_index/ssh-program-execution" / self.operation
        end = time.monotonic() + 10
        while time.monotonic() < end and not (directory / "owner-closed.json").exists():
            time.sleep(.02)
        self.assertTrue((directory / "owner-closed.json").exists())
        result = self.observe()
        self.assertEqual("unknown", result["state"])
        self.assertEqual(255, result["exitCode"])
        self.assertTrue(result["capture"]["complete"])
        self.assertEqual(result, self.start(request))
        self.assertEqual(1, len(self.peer.events()))

    def test_private_connection_drift_is_rejected_before_target_launch(self):
        request = self.request("print('never started')")
        original_popen = subprocess.Popen
        children = []
        def drift(argv, *args, **kwargs):
            if argv[0] == sys.executable and "-I" in argv:
                (self.root / "inert-known").write_bytes(b"DIFFERENT_PRIVATE_ROUTE\n")
            child = original_popen(argv, *args, **kwargs)
            if argv[0] == sys.executable and "-I" in argv:
                children.append(child)
            return child
        with mock.patch.object(subprocess, "Popen", side_effect=drift):
            self.start(request)
        for child in children:
            child.wait(timeout=10)
        directory = self.root / ".rag_index/ssh-program-execution" / self.operation
        self.assertFalse((directory / "execution-intent.json").exists())
        self.assertFalse(self.peer.events())
        self.assertEqual("unknown", self.observe()["state"])

    def test_concurrent_same_identity_during_capsule_publish_never_resubmits(self):
        request = self.request("print('one original')")
        entered, release = threading.Event(), threading.Event()
        original_capsule = subject._source_capsule
        outcomes, failures = [], []
        proxy = loader.Adapter(SOURCE_ROOT / "agent_tools", "ssh_program_execution")
        def paused(*args):
            entered.set()
            if not release.wait(10):
                raise RuntimeError("fixture release missing")
            return original_capsule(*args)
        def original():
            try:
                outcomes.append(subject.start(self.root, "explicit-peer", request, source_context=proxy._session, durable=False))
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=original)
        try:
            with mock.patch.object(subject, "_source_capsule", side_effect=paused):
                thread.start()
                self.assertTrue(entered.wait(10))
                result = subject.start(self.root, "explicit-peer", request, source_context=proxy._session)
                self.assertEqual("original_initialization_in_progress", result["reason"])
                self.assertEqual(self.operation, result["operationId"])
                self.assertFalse(self.peer.events())
        finally:
            release.set()
            thread.join(timeout=10)
            proxy.close()
        self.assertFalse(thread.is_alive())
        self.assertFalse(failures)
        self.assertEqual(1, len(outcomes))
        self.assertEqual(0, self.terminal()["exitCode"])
        self.assertEqual(1, len(self.peer.events()))

    def test_direct_source_session_lazy_dependency_before_red_current_green(self):
        fixture = Path(__file__).parent / "fixtures/program_direct_capsule_before"
        before = (fixture / "ssh_program_execution.py.source").read_bytes()
        self.assertEqual(json.loads((fixture / "provenance.json").read_bytes())["sha256"],
                         hashlib.sha256(before).hexdigest())
        before_root = self.root / "before-direct-source"
        proxy = loader.Adapter(SOURCE_ROOT / "agent_tools", "ssh_program_execution")
        try:
            for path, (_, _, _, raw) in proxy._session.held.files.items():
                target_path = before_root / Path(path).relative_to(SOURCE_ROOT)
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_bytes(raw)
        finally:
            proxy.close()
        before_path = before_root / "agent_tools/ssh_program_execution.py"
        before_path.write_bytes(before)
        # Preserve the real supported canonical entrypoint + independent source
        # capability arrangement. Calling through Adapter would conceal the bug
        # by admitting the lazy dependency through that same namespace.
        name = "agent_tools._before_direct_owner_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, before_path)
        old = importlib.util.module_from_spec(spec)
        sys.modules[name] = old
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(old)
        loader_name = "_before_direct_loader_" + uuid.uuid4().hex
        loader_spec = importlib.util.spec_from_file_location(loader_name, before_root / "agent_tools/source_module_loader.py")
        before_loader = importlib.util.module_from_spec(loader_spec)
        sys.modules[loader_name] = before_loader
        self.addCleanup(sys.modules.pop, loader_name, None)
        loader_spec.loader.exec_module(before_loader)
        context = before_loader.Adapter(before_root / "agent_tools", "ssh_program_execution")
        try:
            old.start(self.root, "explicit-peer", self.request("print('original')"),
                      source_context=context._session, durable=False)
        finally:
            context.close()
        with self.assertRaisesRegex(AssertionError, "expected_source_bytes_changed"):
            self.terminal()
        self.assertFalse(self.peer.events())
        self.operation = str(uuid.uuid4())
        context = loader.Adapter(SOURCE_ROOT / "agent_tools", "ssh_program_execution")
        try:
            subject.start(self.root, "explicit-peer", self.request("print('original')"),
                          source_context=context._session, durable=False)
        finally:
            context.close()
        self.assertEqual(0, self.terminal()["exitCode"])
        self.assertEqual(b"original\n", self.raw("stdout"))
        self.assertEqual(1, len(self.peer.events()))

    def test_private_inventory_password_hash_before_red_generation_custody_green(self):
        fixture = Path(__file__).parent / "fixtures/program_config_pin_before"
        raw = (fixture / "ssh_program_execution.py.source").read_bytes()
        self.assertEqual(json.loads((fixture / "provenance.json").read_bytes())["sha256"], hashlib.sha256(raw).hexdigest())
        name = "agent_tools._before_config_pin_" + uuid.uuid4().hex
        # The preserved .source suffix is intentionally not an import suffix.
        old = type(sys)(name); old.__file__ = str(fixture / "ssh_program_execution.py.source"); old.__package__ = "agent_tools"
        sys.modules[name] = old
        self.addCleanup(sys.modules.pop, name, None)
        exec(compile(raw, old.__file__, "exec"), old.__dict__)
        secret = "synthetic-fixture-credential-only"
        config_path = self.peer.config_path
        config = json.loads(config_path.read_bytes())
        config["hosts"]["explicit-peer"]["password"] = secret
        config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
        real_sha = hashlib.sha256
        seen = []
        def inspect_digest(data=b"", *args, **kwargs):
            seen.append(secret.encode() in data)
            return real_sha(data, *args, **kwargs)
        with mock.patch.object(hashlib, "sha256", side_effect=inspect_digest):
            with old._holding() as held:
                old._hold_connection(held, self.root, "explicit-peer")
        self.assertIn(True, seen)
        seen.clear()
        with mock.patch.object(hashlib, "sha256", side_effect=inspect_digest):
            with subject._holding() as held:
                _, pins = subject._hold_connection(held, self.root, "explicit-peer")
                private_pins = held.private_connection_pins
                self.assertNotIn(str(config_path), pins)
                self.assertNotIn("sha256", private_pins[str(config_path)])
                self.assertEqual("private-fd-generation-v2", private_pins[str(config_path)]["kind"])
                self.assertNotIn(secret, json.dumps(pins))
                self.assertNotIn(str(config_path), held.files)
                held.finish(); held.final_identity_pass()
            with subject._holding() as held:
                subject._hold_connection(held, self.root, "explicit-peer", pins, private_expected=private_pins)
                config_path.write_text(config_path.read_text().replace(secret, secret.upper()))
                with self.assertRaises(ValueError):
                    held.finish()
        self.assertNotIn(True, seen)

    def test_identical_start_reconciles_without_current_credentials_or_route(self):
        request = self.request("print('retained result')")
        self.start(request)
        result = self.terminal()
        self.peer.config_path.unlink()
        self.assertEqual({"ok": True}, subject.admit_start(self.root, "explicit-peer", request))
        self.assertEqual(result, self.start(request))
        self.assertEqual(1, len(self.peer.events()))

    def test_real_kernel_e2big_original_unknown_then_one_forced_file_execution(self):
        fixture = Path(__file__).parent / "fixtures/program_e2big_before"
        before_root = self.original_source_root(owner_fixture=fixture)
        # Shared Popen now also fixes this failure. Preserve its original typed
        # refusal boundary alongside the whole unfixed owner for causal RED.
        transport_fixture = Path(__file__).parent / "fixtures/ssh_generic_e2big"
        before_transport = (transport_fixture / "ssh_transport.py.before.source").read_bytes()
        self.assertEqual(json.loads((transport_fixture / "provenance.json").read_bytes())["beforeSha256"],
                         hashlib.sha256(before_transport).hexdigest())
        (before_root / "agent_tools/ssh_transport.py").write_bytes(before_transport)
        # The kernel accounts for environment and argv together. Leave enough
        # room for the fixed local owner and saved loader, but not the legal
        # sub-60000-byte inline source. No exception or command result is faked.
        argmax = os.sysconf("SC_ARG_MAX")
        if not 65536 <= argmax <= 8 * 1024 * 1024:
            self.skipTest("finite native ARG_MAX control unavailable")
        remaining = argmax - 20000 - sum(len(os.fsencode(k)) + len(os.fsencode(v)) + 2 for k, v in os.environ.items())
        padding = {}; index = 0
        while remaining > 128:
            name = "VC_PROGRAM_KERNEL_BUDGET_" + str(index)
            value = "E" * min(60000, remaining - len(name) - 2)
            padding[name] = value; remaining -= len(name) + len(value) + 2; index += 1
        long_literal = "PADDING=" + repr("X" * 32000) + "\n"
        requests = []
        for _ in range(2):
            operation = str(uuid.uuid4())
            marker = self.root / ("kernel-once-" + operation)
            request = self.request(long_literal + "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('once')\nprint('kernel fallback complete')\n")
            request["operationId"] = operation
            requests.append((request, marker))
        initial_events = len(self.peer.events())
        with mock.patch.dict(os.environ, padding):
            probe = subprocess.Popen([sys.executable, "-c", "pass"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = probe.communicate(timeout=10)
            self.assertEqual((0, b"", b""), (probe.returncode, out, err))
            with self.assertRaises(OSError) as refusal:
                subprocess.Popen([sys.executable, "-c", long_literal + "pass"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(errno.E2BIG, refusal.exception.errno)
            request, marker = requests[0]; self.operation = request["operationId"]
            self.start(request, before_root)
            directory = self.root / ".rag_index/ssh-program-execution" / self.operation
            end = time.monotonic() + 15
            while time.monotonic() < end and not (directory / "owner-closed.json").exists():
                time.sleep(.02)
            self.assertTrue((directory / "owner-closed.json").exists())
            original = self.observe()
            self.assertEqual("unknown", original["state"])
            self.assertFalse(marker.exists())
            self.assertEqual(initial_events, len(self.peer.events()))
            request, marker = requests[1]; self.operation = request["operationId"]
            self.start(request)
            result = self.terminal()
        self.assertEqual(0, result["exitCode"])
        self.assertEqual("inline", result["transport"])
        self.assertEqual("saved-file", result["capture"]["effectiveTransport"])
        self.assertLessEqual(result["originalCommandBounds"]["wholeArgvBytes"], 60000)
        self.assertLessEqual(result["capture"]["submittedCommandBounds"]["wholeArgvBytes"], 60000)
        self.assertEqual("once", marker.read_text())
        directory = self.root / ".rag_index/ssh-program-execution" / self.operation
        proof = json.loads((directory / "prelaunch-refusal.json").read_bytes())
        fallback = json.loads((directory / "file-fallback-intent.json").read_bytes())
        self.assertEqual(errno.E2BIG, proof["errno"])
        self.assertIs(proof["childCreated"], False); self.assertIs(proof["programStarted"], False)
        self.assertEqual(hashlib.sha256(subject._json(proof)).hexdigest(), fallback["refusalSha256"])
        self.assertEqual(request["operationId"], fallback["operationId"])
        self.assertEqual(result, self.start(request))
        self.assertEqual(2, len(self.peer.events()) - initial_events)

    def test_fast_original_exit_before_actor_observation_keeps_known_terminal(self):
        before_root = self.original_source_root(owner_fixture=Path(__file__).parent / "fixtures/program_fast_child_before")
        for source_root, expected in ((before_root, "unknown"), (SOURCE_ROOT, "terminal")):
            self.operation = str(uuid.uuid4())
            request = self.request("print('fast complete')\nraise SystemExit(7)\n")
            module = loader
            if source_root != SOURCE_ROOT:
                name = "_fast_program_loader_" + uuid.uuid4().hex
                spec = importlib.util.spec_from_file_location(name, source_root / "agent_tools/source_module_loader.py")
                module = importlib.util.module_from_spec(spec);sys.modules[name] = module
                self.addCleanup(sys.modules.pop, name, None);spec.loader.exec_module(module)
            proxy = module.Adapter(source_root / "agent_tools", "ssh_program_execution")
            try:
                owner = proxy._module
                normalized = owner._request("explicit-peer", request)
                config = owner.transport.load_config(self.root)
                argv = owner.transport.build_ssh_argv(config, "explicit-peer", 15, owner.remote.command(request["program"]))
                owner.transport._automatic_module()
                directory = owner._directory(self.root, self.operation, create=True)
                with owner._holding() as held:
                    _, connection = owner._hold_connection(held, self.root, "explicit-peer")
                    private_connection = getattr(held, "private_connection_pins", None)
                capsule, pins = owner._source_capsule(self.root, directory, proxy._session)
                intent = {"schemaVersion": 2 if private_connection is not None else 1, "operationId": self.operation, "request": normalized,
                          "requestSha256": hashlib.sha256(owner._json(normalized)).hexdigest(),
                          "sourcePins": pins, "connectionPins": connection,
                          "sourceRoot": str(source_root), "capsuleRoot": str(capsule), "transport": "inline",
                          "originalArgvSha256": owner.transport.argv_sha256(argv),
                          "originalCommandBounds": owner._command_bounds(argv), "replayAllowed": False}
                if private_connection is not None:
                    intent["privateConnectionPins"] = private_connection
                owner._save(directory, "intent.json", intent)
                original_popen = subprocess.Popen
                children = []
                def original_finished_before_observation(*args, **kwargs):
                    child = original_popen(*args, **kwargs)
                    if args[0][0] == "ssh":
                        children.append(child)
                        child.wait(timeout=10)
                    return child
                with mock.patch.object(subprocess, "Popen", side_effect=original_finished_before_observation):
                    proxy.worker(self.root, self.operation, source_context=proxy._session)
                self.assertEqual(1, len(children))
                terminal = json.loads((directory / "terminal.json").read_bytes())
                self.assertEqual(expected, terminal["state"])
                self.assertEqual(b"fast complete\n", (directory / "stdout.private").read_bytes())
                self.assertEqual(7, terminal["capture"]["returnCode"])
                self.assertTrue(terminal["capture"]["complete"])
                self.assertEqual({"stdout": True, "stderr": True}, terminal["capture"]["eof"])
                if expected == "terminal":
                    child = json.loads((directory / "child.json").read_bytes())
                    self.assertIsNone(child["actor"])
                    self.assertTrue(child["alreadyExited"])
                    self.assertEqual(7, child["exitCode"])
            finally:
                proxy.close()

    def test_public_admission_reports_fixed_refusal_before_any_journal_or_child(self):
        for mutate, reason in ((lambda value: value["program"].update(language="powershell"), "program_language_unsupported"),
                               (lambda value: value["program"].update(source="not valid python!"), "program_source_syntax"),
                               (lambda value: value["program"].update(args="whole shell string"), "program_arguments")):
            request = self.request("print('never starts')")
            mutate(request)
            refusal = subject.admit_start(self.root, "explicit-peer", request)
            self.assertEqual("refused", refusal["state"])
            self.assertEqual(reason, refusal["reason"])
            self.assertEqual(self.operation, refusal["operationId"])
            self.assertFalse(refusal["replayAllowed"])
        self.assertFalse((self.root / ".rag_index/ssh-program-execution").exists())
        self.assertFalse(self.peer.events())

    def test_structured_source_literals_and_root_cwd_are_not_rewritten(self):
        value = self.request("print('__CWD__ __SOURCE__')", cwd=Path("/"))["program"]
        command = remote.command(value)
        child = subprocess.run([sys.executable, *command[1:]], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(0, child.returncode, child.stderr)
        self.assertEqual(b"__CWD__ __SOURCE__\n", child.stdout)



@unittest.skipUnless(os.name == "posix", "original pipe custody")
class ProgramCaptureTests(unittest.TestCase):
    def setUp(self):
        global subject
        from agent_tools import ssh_program_execution as subject
        temporary = tempfile.TemporaryDirectory(dir=Path("/tmp").resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.capture = subject._Capture(self.root)
        self.addCleanup(self.capture.close_raw)

    def test_actual_child_exit_does_not_imply_descendant_pipe_eof(self):
        release, ready = self.root / "release", self.root / "ready"
        child_source = ("from pathlib import Path\nimport time\nPath(" + repr(str(ready)) + ").touch()\n"
                        "while not Path(" + repr(str(release)) + ").exists():time.sleep(.02)\nprint('descendant end')\n")
        source = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child_source) + "]);print('original end')"
        self.capture.start([sys.executable, "-c", source])
        try:
            end = time.monotonic() + 10
            while time.monotonic() < end and (self.capture.child.poll() is None or not ready.exists()):
                self.capture.step(.02)
            self.assertTrue(ready.exists())
            self.assertEqual(0, self.capture.child.returncode)
            self.assertFalse(self.capture.snapshot()["complete"])
            self.assertFalse(all(self.capture.eof.values()))
        finally:
            release.touch()
            self.capture.finish_naturally()
        self.assertTrue(self.capture.snapshot()["complete"])
        self.assertEqual(b"original end\ndescendant end\n", (self.root / "stdout.private").read_bytes())

    def test_zero_write_after_real_child_does_not_spin_or_lose_other_stream(self):
        self.capture.start([sys.executable, "-c", "import os;os.write(1,b'OUT');os.write(2,b'ERR')"])
        original_write = os.write
        def zero_stdout(descriptor, raw):
            return 0 if descriptor == self.capture.output["stdout"] else original_write(descriptor, raw)
        try:
            with mock.patch.object(os, "write", side_effect=zero_stdout):
                with self.assertRaisesRegex(OSError, "program_raw_short_write"):
                    end = time.monotonic() + 10
                    while time.monotonic() < end:
                        self.capture.step(.02)
                self.capture.finish_unknown()
            self.assertTrue(self.capture.snapshot()["complete"])
            self.assertEqual(b"ERR", (self.root / "stderr.private").read_bytes())
            self.assertEqual({"stdout": 3, "stderr": 3}, self.capture.counts)
            self.assertEqual(0, self.capture.retained["stdout"])
            self.assertEqual(3, self.capture.retained["stderr"])
        finally:
            if not self.capture.closed:
                self.capture.finish_unknown()

    def test_pipe_attachment_failure_keeps_original_child_for_recovery(self):
        with mock.patch.object(self.capture.selector, "register", side_effect=OSError("attachment failed")):
            with self.assertRaisesRegex(OSError, "attachment failed"):
                self.capture.start([sys.executable, "-c", "import os;os.write(1,b'OUT');os.write(2,b'ERR')"])
        self.assertIsNotNone(self.capture.child)
        self.capture.finish_unknown()
        self.assertTrue(self.capture.snapshot()["complete"])
        self.assertEqual(b"OUT", (self.root / "stdout.private").read_bytes())
        self.assertEqual(b"ERR", (self.root / "stderr.private").read_bytes())

@unittest.skipUnless(os.name == "posix", "private retained worker records")
class ProgramWorkerDiagnosticsTests(unittest.TestCase):
    FIXTURES = Path(__file__).parent / "fixtures" / "program_worker_diagnostics"

    def implementation(self, before=False):
        from agent_tools import ssh_program_execution as current
        if not before:
            return current
        path = self.FIXTURES / "ssh_program_execution.py.before.source"
        data = path.read_bytes()
        provenance = json.loads((self.FIXTURES / "provenance.json").read_text())
        self.assertEqual(hashlib.sha256(data).hexdigest(), provenance["sources"][path.name]["sha256"])
        import types
        name = "agent_tools._before_worker_diagnostics_" + uuid.uuid4().hex
        module = types.ModuleType(name); module.__file__ = str(path); module.__package__ = "agent_tools"
        sys.modules[name] = module; self.addCleanup(sys.modules.pop, name, None)
        exec(compile(data, str(path), "exec"), module.__dict__)
        return module

    def run_worker(self, *, before=False, fail_write=False, bad_capture=False, large_message=False,
                   seed_ready=False, terminal_code=None, initial_refusal=False):
        import types
        from agent_tools import ssh_channel_selection as selection
        from agent_tools import ssh_fresh_nested_channel as channel
        owner = self.implementation(before)
        temporary = tempfile.TemporaryDirectory(dir=Path("/tmp").resolve())
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve(); root.chmod(0o700)
        operation = str(uuid.uuid4()); directory = owner._directory(root, operation, create=True)
        source = root / "agent_tools"; source.mkdir(mode=0o700)
        source_file = source / "ssh_program_execution.py"; source_file.write_bytes(Path(owner.__file__).read_bytes()); source_file.chmod(0o600)
        info = source_file.stat()
        generation = [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                      info.st_size, info.st_mtime_ns, info.st_ctime_ns]
        argv = ["ssh", "declared-preautomatic-boundary"]
        intent = {"schemaVersion": 1 if before else 2, "operationId": operation, "sourceRoot": str(root),
                  "sourcePins": {"agent_tools/ssh_program_execution.py": {"sha256": hashlib.sha256(source_file.read_bytes()).hexdigest(), "originalGeneration": generation}},
                  "connectionPins": {}, **({} if before else {"privateConnectionPins": {}}), "requestSha256": "3" * 64,
                  "request": {"host": "explicit-peer", "program": {"language": "python3", "source": "pass\n", "args": [], "cwd": None, "targetContext": {}}},
                  "transport": "saved-file", "originalCommandBounds": owner._command_bounds(argv),
                  "originalArgvSha256": owner.transport.argv_sha256(argv)}
        owner._save(directory, "intent.json", intent)
        context = types.SimpleNamespace(directory=source, guard=mock.Mock())
        calls = []; captures = []; initial_errors = []
        raw = {"stdout": b'{"state":"unknown","failureReason":"master_check"}\n',
               "stderr": b"private socket detail", "returnCode": 3, "complete": True,
               "counts": {"stdout": 56, "stderr": 21}, "eof": {"stdout": True, "stderr": True}}
        ready = {**raw, "stdout": b'{"state":"ready"}\n', "stderr": b"", "returnCode": 0}
        def initial_build(*args, **kwargs):
            if seed_ready:
                owner.transport._retain_private_admission(ready)
                # The provider may reuse its local dictionary after closing
                # custody. The collector must already own an immutable copy.
                ready["stdout"] = b"mutated after callback"
            if initial_refusal:
                try:
                    return refusal()
                except BaseException as error:
                    initial_errors.append(error)
                    raise
            return argv
        class BadCapture:
            def keys(self): raise RuntimeError("private capture retention failed")
        def selected(*args, **kwargs):
            calls.append((args, kwargs))
            callback = kwargs.get("_private_capture")
            if callback is not None: callback(BadCapture() if bad_capture else raw)
            try:
                raise channel.ChannelUnknown({"state": "unknown", "correlationId": "1" * 32, "nativeActionAllowed": False, "replayAllowed": False})
            except channel.ChannelUnknown:
                raise selection.SelectionUnknown("private selected marker" + ("Ω" * 20000 if large_message else "")) from None
        provider = types.SimpleNamespace(SelectionUnknown=selection.SelectionUnknown,
                                         transport=owner.transport, selected_route_options=selected)
        session = types.SimpleNamespace(SessionUnknown=RuntimeError, transport=owner.transport)
        config = types.SimpleNamespace(root=root)
        def refusal(*args, **kwargs):
            return owner.transport._build_selected_arch_argv(config, [types.SimpleNamespace(alias="explicit-peer")],
                                                             ("python3", "-c", "pass"), "ssh", "ssh")
        real_capture = owner._Capture
        class KnownTerminalCapture:
            """Declared child-observer seam; no child/process/socket is started."""
            def __init__(self, directory): self.child = None; self.closed = False
            def start(self, argv): self.child = types.SimpleNamespace(pid=123)
            def snapshot(self):
                return {"complete": True, "overflow": False, "sendError": None,
                        "returnCode": terminal_code, "eof": {"stdout": True, "stderr": True}}
            def finish_naturally(self): self.closed = True
            def stream_records(self, tolerant=False): return {}
            def close_raw(self): pass
        def retain_capture(*args):
            result = real_capture(*args); captures.append(result); return result
        real_save = owner._save
        def save(parent, name, value):
            if fail_write and name == "failure-diagnostic.private.json": raise OSError("private evidence write failed")
            return real_save(parent, name, value)
        with mock.patch.object(owner, "_hold_connection", return_value=(config, {})), \
                mock.patch.object(owner.remote, "command", return_value=("python3", "-c", "pass")), \
                mock.patch.object(owner.transport, "build_ssh_argv", side_effect=initial_build), \
                mock.patch.object(owner.transport, "_selection_module", return_value=provider), \
                mock.patch.object(owner.transport, "_session_module", return_value=session), \
                mock.patch.object(owner.transport, "popen_ssh", side_effect=refusal), \
                mock.patch.object(owner, "_Capture", side_effect=retain_capture if terminal_code is None else KnownTerminalCapture), \
                mock.patch.object(owner, "_child_record", return_value={"pid": 123}), \
                mock.patch.object(owner, "_save", side_effect=save), \
                mock.patch.object(subprocess, "Popen", side_effect=AssertionError("no program start")), \
                mock.patch("socket.socket", side_effect=AssertionError("no network")):
            if initial_refusal:
                with self.assertRaises(owner.transport.SshConfigError) as caught:
                    owner.worker(root, operation, source_context=context)
                self.assertIs(initial_errors[0], caught.exception)
            else:
                owner.worker(root, operation, source_context=context)
        for capture in captures:
            self.assertIsNone(capture.child)
            self.assertEqual(capture.output, {})
            capture.selector.close()
        self.assertEqual(len(calls), 1 if terminal_code is None else 0)
        self.assertIsNone(owner.transport._PRIVATE_ADMISSION_CAPTURE.get())
        if initial_refusal:
            self.assertFalse((directory / "execution-intent.json").exists())
            self.assertFalse((directory / "terminal.json").exists())
            return caught.exception, directory / "failure-diagnostic.private.json", intent, raw, context
        terminal = json.loads((directory / "terminal.json").read_bytes())
        self.assertEqual(terminal["state"], "terminal" if terminal_code == 0 else "unknown")
        if terminal_code is None:
            self.assertEqual(terminal["errorClass"], "SshConfigError")
            self.assertIsNone(terminal["capture"])
        self.assertNotIn("private selected marker", json.dumps(terminal))
        self.assertNotIn("private socket detail", json.dumps(terminal))
        diagnostic = directory / "failure-diagnostic.private.json"
        return terminal, diagnostic, intent, raw, context

    def test_actual_original_worker_loses_details_red_current_private_diagnostic_green(self):
        old, old_path, _, _, _ = self.run_worker(before=True)
        self.assertFalse(old_path.exists())
        self.assertNotIn("failureDiagnosticSha256", old)
        terminal, path, intent, raw, context = self.run_worker()
        report = json.loads(path.read_bytes())
        self.assertEqual(report["phase"], "ssh-submission")
        self.assertTrue(report["complete"]); self.assertFalse(report["overflow"])
        self.assertEqual(report["sourceIdentity"]["originalArgvSha256"], intent["originalArgvSha256"])
        self.assertEqual(report["sourceIdentity"]["workerSource"], intent["sourcePins"]["agent_tools/ssh_program_execution.py"])
        error = report["exception"]
        self.assertEqual(error["errorClass"], "SshConfigError")
        self.assertTrue(any(frame["function"] == "_build_selected_arch_argv" for frame in error["traceback"]))
        self.assertEqual(error["chained"]["message"], "private selected marker")
        self.assertEqual(error["chained"]["chained"]["typedRefusal"]["correlationId"], "1" * 32)
        admission = error["selectedAdmission"]
        self.assertTrue(admission["rawCaptureAvailable"])
        captured = admission["observations"][0]["capture"]["stderr"]
        self.assertEqual(captured["sha256"], hashlib.sha256(raw["stderr"]).hexdigest())
        self.assertTrue(captured["complete"])
        self.assertLessEqual(path.stat().st_size, 16384)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(terminal["failureDiagnosticSha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertGreater(context.guard.call_count, 0)

    def test_diagnostic_write_failure_keeps_primary_unknown_and_original_custody(self):
        terminal, path, _, _, context = self.run_worker(fail_write=True)
        self.assertFalse(path.exists())
        self.assertIs(terminal["failureDiagnosticAvailable"], False)
        self.assertEqual(terminal["errorClass"], "SshConfigError")
        self.assertGreater(context.guard.call_count, 0)

    def test_capture_callback_failure_keeps_same_selected_refusal_without_requery(self):
        _, path, _, _, _ = self.run_worker(bad_capture=True)
        admission = json.loads(path.read_bytes())["exception"]["selectedAdmission"]
        self.assertFalse(admission["rawCaptureAvailable"])
        self.assertEqual(admission["captureFailures"], ["RuntimeError"])

    def test_long_exception_diagnostic_is_bounded_and_truthfully_incomplete(self):
        terminal, path, _, _, _ = self.run_worker(large_message=True)
        report = json.loads(path.read_bytes())
        self.assertLessEqual(path.stat().st_size, 16384)
        self.assertTrue(report["overflow"]); self.assertFalse(report["complete"])
        self.assertTrue(terminal["failureDiagnosticOverflow"])

    def test_prior_ready_and_first_refusal_raw_are_both_retained_without_requery(self):
        _, path, intent, raw, _ = self.run_worker(seed_ready=True)
        report = json.loads(path.read_bytes())
        self.assertEqual(2, len(report["admissionRecords"]))
        records = []
        for ordinal, pin in enumerate(report["admissionRecords"], 1):
            data = (path.parent / pin["name"]).read_bytes()
            self.assertEqual(pin["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(pin["bytes"], len(data)); self.assertLessEqual(len(data), 16384)
            row = json.loads(data)
            self.assertEqual(intent["operationId"], row["operationId"])
            self.assertEqual(ordinal, row["observation"])
            self.assertEqual(report["sourceIdentity"]["sourceManifestSha256"], row["sourceManifestSha256"])
            records.append(row["record"]["capture"])
        import base64
        self.assertEqual(b'{"state":"ready"}\n', base64.b64decode(records[0]["stdout"]["prefixBase64"]))
        self.assertEqual(raw["stdout"], base64.b64decode(records[1]["stdout"]["prefixBase64"]))

    def test_nonexception_unknown_retains_ready_capture_success_discards_it(self):
        terminal, path, _, _, _ = self.run_worker(seed_ready=True, terminal_code=255)
        report = json.loads(path.read_bytes())
        self.assertNotIn("errorClass", terminal)
        self.assertIsNone(report["exception"])
        self.assertEqual("child-terminal-unverified", report["phase"])
        self.assertEqual(1, len(report["admissionRecords"]))
        terminal, path, _, _, _ = self.run_worker(seed_ready=True, terminal_code=0)
        self.assertEqual(0, terminal["exitCode"])
        self.assertFalse(path.exists())
        self.assertEqual([], list(path.parent.glob("selected-admission-*.private.json")))

    def test_nested_collectors_are_immutable_reset_and_failure_isolated(self):
        from agent_tools import ssh_transport as transport
        self.assertIsNone(transport._PRIVATE_ADMISSION_CAPTURE.get())

        raw = {"stdout": b"original", "counts": {"stdout": 8}}
        with transport._private_admission_capture() as outer:
            transport._retain_private_admission(raw)
            raw["counts"]["stdout"] = 999; raw["stdout"] = b"changed"
            with self.assertRaisesRegex(RuntimeError, "primary"):
                with transport._private_admission_capture() as inner:
                    transport._retain_private_admission({"stdout": b"inner"})
                    transport._retain_private_admission(object())
                    raise RuntimeError("primary")
            self.assertIs(outer, transport._PRIVATE_ADMISSION_CAPTURE.get())
            self.assertEqual(1, len(outer["observations"]))
            self.assertEqual(b"original", outer["observations"][0]["capture"]["stdout"])
            self.assertEqual(8, outer["observations"][0]["capture"]["counts"]["stdout"])
            self.assertEqual(b"inner", inner["observations"][0]["capture"]["stdout"])
            self.assertEqual(["ValueError"], inner["captureFailures"])
        self.assertIsNone(transport._PRIVATE_ADMISSION_CAPTURE.get())

    def test_initial_admission_keeps_exception_identity_with_private_evidence_or_writer_failure(self):
        _, old_path, _, _, _ = self.run_worker(before=True, initial_refusal=True)
        self.assertFalse(old_path.exists())
        error, path, _, _, _ = self.run_worker(initial_refusal=True)
        report = json.loads(path.read_bytes())
        self.assertEqual("initial-admission", report["phase"])
        self.assertEqual(str(error), report["exception"]["message"])
        self.assertEqual("private selected marker", report["exception"]["chained"]["message"])
        self.assertEqual(1, len(report["admissionRecords"]))
        _, failed_path, _, _, _ = self.run_worker(initial_refusal=True, fail_write=True)
        self.assertFalse(failed_path.exists())



@unittest.skipUnless(os.name == 'posix', 'owned local source-closing publisher')
class ProgramSourceClosingPublicationTests(unittest.TestCase):
    FIXTURE = Path(__file__).parent / 'fixtures/program_source_closing_publication'
    CAUSAL = []

    def setUp(self):
        from agent_tools import ssh_program_execution
        self.current = ssh_program_execution
        temporary = tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)

    def before(self):
        import types
        path = self.FIXTURE / 'ssh_program_execution.py.before.source'
        raw = path.read_bytes(); pin = json.loads((self.FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(pin['beforeSha256'], hashlib.sha256(raw).hexdigest())
        name = 'agent_tools._source_closing_before_' + uuid.uuid4().hex
        module = types.ModuleType(name); module.__file__ = str(path); module.__package__ = 'agent_tools'
        sys.modules[name] = module; self.addCleanup(sys.modules.pop, name, None)
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        return module

    def intent(self, owner, operation):
        request = {'host':'explicit-peer','operationId':operation,
                   'program':{'language':'python3','source':"print('OWNED GAP ONCE')\n",'args':[],
                              'cwd':'/','targetContext':{'kind':'ssh','uid':1000,'principal':'fixture',
                              'home':'/inert/fixture','bootId':'00000000-0000-0000-0000-000000000000'}}}
        return {'schemaVersion':2 if hasattr(owner, '_private_pin') else 1,'operationId':operation,'request':request,
                **({'privateConnectionPins':{}} if hasattr(owner, '_private_pin') else {}),
                'requestSha256':hashlib.sha256(owner._json(request)).hexdigest(),
                'sourcePins':{},'connectionPins':{},'sourceRoot':str(SOURCE_ROOT),
                'transport':'inline','originalArgvSha256':'a'*64,
                'originalCommandBounds':{'wholeArgvBytes':40,'maxArgumentBytes':20,'limitBytes':60000}}

    def layout(self):
        owner = self.current; operation = str(uuid.uuid4())
        directory = owner._directory(self.root, operation, create=True)
        intent = self.intent(owner, operation); owner._save(directory, 'intent.json', intent)
        stdout = b'UNVALIDATED PRIVATE RAW\x00'; stderr = b''
        streams = {}
        for name, raw in [('stdout',stdout),('stderr',stderr)]:
            owner._bytes(directory, name+'.private', raw)
            streams[name] = {'bytes':len(raw),'receivedBytes':len(raw),
                             'receivedSha256':hashlib.sha256(raw).hexdigest(),
                             'retainedSha256':hashlib.sha256(raw).hexdigest(),'eof':True}
        terminal = owner._public(intent,'terminal',exitCode=0,
                    capture={'complete':True,'eof':{'stdout':True,'stderr':True},'returnCode':0},streams=streams)
        owner._save(directory,'terminal.json',terminal)
        actor = {'pid':424242,'uid':os.getuid(),'sessionId':424242,'birthSha256':'b'*64}
        owner._save(directory,'owner.json',{'operationId':operation,'actor':actor})
        return directory,intent,terminal,actor

    def close_record(self, directory, intent, **changes):
        closed = {'operationId':intent['operationId'],
                  'terminalSha256':hashlib.sha256((directory/'terminal.json').read_bytes()).hexdigest(),
                  'sourceClosing':True, **changes}
        self.current._save(directory,'owner-closed.json',closed)

    def replace(self, path, value=None):
        raw = path.read_bytes() if value is None else self.current._json(value)
        fresh = path.with_name('replacement-'+uuid.uuid4().hex)
        fresh.write_bytes(raw); fresh.chmod(0o600); fresh.replace(path)

    def observe(self, intent):
        return self.current.status(self.root,'explicit-peer',{'operationId':intent['operationId']})

    def publisher(self, owner):
        # The actual source-bound publisher and whole real worker execute.
        # Only the configured credential/argv boundary is an inert local peer.
        from contextlib import contextmanager
        @contextmanager
        def opened():
            operation = str(uuid.uuid4()); directory = owner._directory(self.root,operation,create=True)
            request = self.intent(owner,operation)['request']; request.pop('host')
            gap = directory/'gap-ready'
            body = ("from pathlib import Path\nimport sys,json,hashlib\n"
                    "from unittest import mock\n"
                    "assert sys.stdin.buffer.read(1)==b'B'\n"
                    "source=Path("+repr(str(SOURCE_ROOT))+ ")\nroot=Path("+repr(str(self.root))+")\n"
                    "sys.path.insert(0,str(source))\nfrom agent_tools import source_module_loader as loader\n"
                    "with loader.request_scope(source/'agent_tools'):\n"
                    " owner=loader.adapter(source/'agent_tools','ssh_program_execution')\n"
                    " module=owner._module;context=owner._session\n"
                    " operation="+repr(operation)+"\n request="+repr(request)+"\n"
                    " request={'host':'explicit-peer',**request}\n"
                    " argv=[sys.executable,'-I','-B','-c',request['program']['source']]\n"
                    " pins={str(Path(name).relative_to(source)):{'sha256':item[2],'originalGeneration':list(item[1])} for name,item in context.held.files.items()}\n"
                    " intent={'schemaVersion':2,'privateConnectionPins':{},'operationId':operation,'request':request,'requestSha256':hashlib.sha256(module._json(request)).hexdigest(),'sourcePins':pins,'connectionPins':{},'sourceRoot':str(source),'transport':'inline','originalArgvSha256':module.transport.argv_sha256(argv),'originalCommandBounds':module._command_bounds(argv)}\n"
                    " directory=module._directory(root,operation)\n module._save(directory,'intent.json',intent)\n"
                    " with mock.patch.object(module,'_hold_connection',return_value=(None,{})),mock.patch.object(module.transport,'build_ssh_argv',return_value=argv) as build:\n"
                    "  module.worker(root,operation,source_context=context)\n  assert build.call_count==1\n"
                    " context.guard()\n terminal=json.loads((directory/'terminal.json').read_bytes())\n"
                    " assert terminal['state']=='terminal' and terminal['exitCode']==0,terminal\n"
                    " (directory/'gap-ready').write_text('exact original publisher held')\n"
                    " assert sys.stdin.buffer.read(1)==b'C'\n")
            owner._bytes(directory,'worker.py',body.encode())
            child = subprocess.Popen(owner._worker_command(directory/'worker.py',body.encode(),self.root,operation),
                                     stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                     env={k:v for k,v in os.environ.items()if not k.startswith('DYLD_')})
            try:
                actor = owner.keeper.actor(child.pid)
                owner._save(directory,'owner.json',{'operationId':operation,'actor':actor})
                child.stdin.write(b'B');child.stdin.flush()
                deadline=time.monotonic()+15
                while not gap.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(gap.exists(),'original publisher did not reach terminal gap')
                self.assertIsNone(child.poll());self.assertTrue((directory/'terminal.json').exists())
                self.assertFalse((directory/'owner-closed.json').exists())
                yield directory,operation,child,actor
            finally:
                if child.poll() is None:
                    try:child.stdin.write(b'C');child.stdin.flush()
                    except (BrokenPipeError,OSError):pass
                if not child.stdin.closed:child.stdin.close()
                child.wait(timeout=15)
                stdout=child.stdout.read();stderr=child.stderr.read();child.stdout.close();child.stderr.close()
                self.assertEqual(0,child.returncode,stderr.decode(errors='replace'))
                self.assertEqual(b'',stdout)
        return opened()

    def test_actual_whole_publisher_gap_before_red_current_pending_then_terminal(self):
        for owner,fixed in [(self.before(),False),(self.current,True)]:
            with self.subTest(fixed=fixed):
                with self.publisher(owner) as (directory,operation,child,actor):
                    observed=owner.status(self.root,'explicit-peer',{'operationId':operation})
                    def pending_oracle():
                        self.assertEqual('pending',observed['state'])
                        self.assertEqual('original_source_closing_pending',observed['reason'])
                        for name in ['exitCode','capture','streams']:self.assertNotIn(name,observed)
                    if fixed:pending_oracle()
                    else:
                        with self.assertRaises(AssertionError):pending_oracle()
                        self.assertEqual('original_source_closing_unproved',observed['reason'])
                    owner._save(directory,'observation-00000098.json',observed)
                    original_observation=(directory/'observation-00000098.json').read_bytes()
                final=owner.status(self.root,'explicit-peer',{'operationId':operation})
                self.assertEqual('terminal',final['state']);self.assertEqual(0,final['exitCode'])
                self.assertEqual({'stdout':True,'stderr':True},final['capture']['eof'])
                self.assertEqual(b'OWNED GAP ONCE\n',(directory/'stdout.private').read_bytes())
                self.assertEqual(b'',(directory/'stderr.private').read_bytes())
                self.assertEqual(original_observation,(directory/'observation-00000098.json').read_bytes())
                self.CAUSAL.append({'fixed':fixed,'sourceSha256':hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest(),
                    'gap':observed,'final':final,'originalPublisherPid':child.pid,'originalActor':actor,
                    'sameOriginalPublisherExitCode':child.returncode,'originalObservationUnchanged':True,
                    'closing':json.loads((directory/'owner-closed.json').read_bytes())})

    def test_closing_gap_requires_exact_original_owner_and_actor(self):
        cases=['missing-owner','foreign-operation','owner-extra','actor-none','actor-extra','bool-pid',
               'uid-mismatch','session-mismatch','birth-mismatch']
        for case in cases:
            with self.subTest(case=case):
                directory,intent,terminal,actor=self.layout()
                owner={'operationId':intent['operationId'],'actor':dict(actor)}
                if case=='missing-owner':(directory/'owner.json').unlink()
                else:
                    if case=='foreign-operation':owner['operationId']=str(uuid.uuid4())
                    if case=='owner-extra':owner['other']=True
                    if case=='actor-none':owner['actor']=None
                    if case=='actor-extra':owner['actor']['extra']=True
                    if case=='bool-pid':owner['actor']['pid']=True
                    if case=='uid-mismatch':owner['actor']['uid']+=1
                    if case=='session-mismatch':owner['actor']['sessionId']+=1
                    if case=='birth-mismatch':owner['actor']['birthSha256']='c'*64
                    self.replace(directory/'owner.json',owner)
                with mock.patch.object(self.current.keeper,'actor',return_value=actor):result=self.observe(intent)
                self.assertEqual('unknown',result['state']);self.assertEqual('original_source_closing_unproved',result['reason'])
                self.assertNotIn('capture',result);self.assertNotIn('streams',result)

    def test_self_consistent_foreign_records_cannot_prove_requested_owner(self):
        import types
        path=self.FIXTURE/'ssh_program_execution.private-identity.before.source'
        raw=path.read_bytes();pin=json.loads((self.FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(pin['privateIdentityBeforeSha256'],hashlib.sha256(raw).hexdigest())
        name='agent_tools._closing_identity_before_'+uuid.uuid4().hex
        before=types.ModuleType(name);before.__file__=str(path);before.__package__='agent_tools'
        sys.modules[name]=before;self.addCleanup(sys.modules.pop,name,None)
        exec(compile(raw,str(path),'exec'),before.__dict__)
        for owner,fixed in [(before,False),(self.current,True)]:
            directory,intent,terminal,actor=self.layout();requested=directory.name
            foreign=str(uuid.uuid4());intent['operationId']=intent['request']['operationId']=foreign
            intent['requestSha256']=hashlib.sha256(owner._json(intent['request'])).hexdigest()
            self.replace(directory/'intent.json',intent)
            terminal=owner._public(intent,'terminal',exitCode=0,capture=terminal['capture'],streams=terminal['streams'])
            self.replace(directory/'terminal.json',terminal)
            self.replace(directory/'owner.json',{'operationId':foreign,'actor':actor})
            with mock.patch.object(owner.keeper,'actor',return_value=actor) as lookup:
                observed=owner.status(self.root,'explicit-peer',{'operationId':requested})
            def unknown_oracle():self.assertEqual('unknown',observed['state'])
            if fixed:unknown_oracle();lookup.assert_not_called()
            else:
                with self.assertRaises(AssertionError):unknown_oracle()
                self.assertEqual('pending',observed['state']);self.assertEqual(1,lookup.call_count)
            self.CAUSAL.append({'kind':'requested-operation-binding','fixed':fixed,
                'sourceSha256':hashlib.sha256(Path(owner.__file__).read_bytes()).hexdigest(),
                'requestedOperationId':requested,'foreignOperationId':foreign,'observed':observed,
                'actorLookupCount':lookup.call_count,'noCaptureOrStreamsExposed':not({'capture','streams'}&set(observed))})

    def test_boolean_actor_fields_cannot_equal_integer_identity(self):
        for name in ['pid','uid','sessionId']:
            directory,intent,terminal,actor=self.layout()
            actual={'pid':1,'uid':0,'sessionId':1,'birthSha256':'b'*64}
            saved=dict(actual);saved[name]=bool(saved[name])
            self.replace(directory/'owner.json',{'operationId':intent['operationId'],'actor':saved})
            with mock.patch.object(self.current.keeper,'actor',return_value=actual) as lookup:
                result=self.observe(intent)
            self.assertEqual('unknown',result['state']);lookup.assert_not_called()

    def test_dead_and_unproved_actor_observations_remain_unknown(self):
        for error in [OSError('dead'),ValueError('unproved'),subprocess.TimeoutExpired('owned ps',3)]:
            with self.subTest(error=type(error).__name__):
                directory,intent,terminal,actor=self.layout()
                with mock.patch.object(self.current.keeper,'actor',side_effect=error) as observed:result=self.observe(intent)
                self.assertEqual(1,observed.call_count);self.assertEqual('unknown',result['state'])
                self.assertNotIn('capture',result)

    def test_arrived_closure_uses_existing_validation_after_single_actor_lookup(self):
        for ended in [False,True]:
            directory,intent,terminal,actor=self.layout()
            def observed(_):
                self.close_record(directory,intent)
                if ended:raise ValueError('publisher now ended')
                return actor
            with mock.patch.object(self.current.keeper,'actor',side_effect=observed) as lookup:result=self.observe(intent)
            self.assertEqual(1,lookup.call_count);self.assertEqual(terminal,result)

    def test_arrived_invalid_closure_is_never_accepted(self):
        for changes in [{'terminalSha256':'0'*64},{'sourceClosing':False},{'operationId':str(uuid.uuid4())}]:
            directory,intent,terminal,actor=self.layout()
            def observed(_):self.close_record(directory,intent,**changes);return actor
            with mock.patch.object(self.current.keeper,'actor',side_effect=observed):
                with self.assertRaisesRegex(ValueError,'program_source_closing_binding'):self.observe(intent)

    def test_pending_return_closes_all_held_record_generations(self):
        for name in ['intent.json','terminal.json','owner.json']:
            directory,intent,terminal,actor=self.layout()
            def observed(_):self.replace(directory/name);return actor
            with mock.patch.object(self.current.keeper,'actor',side_effect=observed):
                with self.assertRaises(ValueError):self.observe(intent)

    def test_terminal_public_binding_precedes_actor_lookup(self):
        directory,intent,terminal,actor=self.layout();terminal['sourceSha256']='f'*64
        self.replace(directory/'terminal.json',terminal)
        with mock.patch.object(self.current.keeper,'actor',side_effect=AssertionError('must not observe')):
            with self.assertRaisesRegex(ValueError,'program_terminal_binding'):self.observe(intent)

    def test_after_closure_existing_capture_and_stream_guards_remain_strict(self):
        for mutation in ['partial-eof','exit255','bad-stream-sha','bad-stream-count']:
            directory,intent,terminal,actor=self.layout()
            if mutation=='partial-eof':terminal['capture']['eof']['stderr']=False
            if mutation=='exit255':terminal['exitCode']=terminal['capture']['returnCode']=255
            if mutation=='bad-stream-sha':terminal['streams']['stdout']['retainedSha256']='0'*64
            if mutation=='bad-stream-count':terminal['streams']['stdout']['bytes']+=1
            self.replace(directory/'terminal.json',terminal);self.close_record(directory,intent)
            with mock.patch.object(self.current.keeper,'actor',side_effect=AssertionError('closed needs no liveness')):
                with self.assertRaises(ValueError):self.observe(intent)

    def test_live_closing_is_read_only_and_redacts_unvalidated_terminal_fields(self):
        directory,intent,terminal,actor=self.layout();terminal['capture']={'unvalidated-private':'MARKER'}
        terminal['streams']={'private':'MARKER'};self.replace(directory/'terminal.json',terminal)
        before={p.name:(p.read_bytes(),self.current.closure.generation(p.stat()))for p in directory.iterdir()}
        with mock.patch.object(self.current.keeper,'actor',return_value=actor) as lookup:result=self.observe(intent)
        self.assertEqual(1,lookup.call_count)
        self.assertEqual(self.current._public(intent,'pending',reason='original_source_closing_pending'),result)
        self.assertNotIn('MARKER',json.dumps(result))
        self.assertEqual(before,{p.name:(p.read_bytes(),self.current.closure.generation(p.stat()))for p in directory.iterdir()})

    def test_existing_unknown_terminal_remains_unchanged_without_liveness(self):
        directory,intent,terminal,actor=self.layout()
        unknown=self.current._public(intent,'unknown',reason='original_execution_unverified',capture=None,streams={})
        self.replace(directory/'terminal.json',unknown);before=(directory/'terminal.json').read_bytes()
        with mock.patch.object(self.current.keeper,'actor',side_effect=AssertionError('must not observe unknown')):
            result=self.observe(intent)
        self.assertEqual(unknown,result);self.assertEqual(before,(directory/'terminal.json').read_bytes())

if __name__ == "__main__":
    unittest.main()
