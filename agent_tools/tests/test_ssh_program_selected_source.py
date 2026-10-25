"""Real selected-route source custody across complete saved worker bootstraps.

Only native channel responses are fixtures. Source generation observation,
selection publication/admission, worker bootstrap and pipe children are real.
No network, VM, VPN or historical producer modification is involved.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import types
import unittest
import uuid
from unittest import mock

from agent_tools import source_module_loader as loader


SOURCE_ROOT = Path(__file__).resolve().parents[2]
BEFORE = Path(__file__).parent / "fixtures/program_selected_source"
BEFORE_SHA = "b58ef1a95cb093da721863c1805bdcacfebb11ce13c2882bb7367c4718d9ea49"


class SelectedProgramImportTests(unittest.TestCase):
    def test_fresh_program_test_discovery_without_pwd(self):
        script = '''import importlib.abc,importlib.machinery,importlib.util,sys
sys.modules.pop("pwd",None)
class NoPwd(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=="pwd":raise ModuleNotFoundError("simulated unavailable pwd")
sys.meta_path.insert(0,NoPwd())
name="_selected_source_import"
spec=importlib.util.spec_from_loader(name,importlib.machinery.SourceFileLoader(name,sys.argv[1]))
module=importlib.util.module_from_spec(spec);sys.modules[name]=module
spec.loader.exec_module(module)
for name in ("agent_tools.tests.test_ssh_program_execution","agent_tools.tests.test_ssh_program_selected_source","agent_tools.tests.test_ssh_saved_program_force"):
 importlib.import_module(name)
assert "pwd" not in sys.modules
'''
        result = subprocess.run([sys.executable, "-S", "-c", script, str(Path(__file__).resolve())],
                                cwd=SOURCE_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=10, check=False)
        self.assertEqual(0, result.returncode, result.stderr)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX source custody")
class SelectedProgramSourceTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests import test_ssh_fresh_nested_channel as channel_fixture
        self.fixture = channel_fixture.FreshChannelTests("runTest")
        self.master_output = (str(os.getuid()) + " Mon Jan 1 00:00:00 2024 ssh\n").encode()
        master = {"pid": 12345, "generationSha256": hashlib.sha256(self.master_output.strip()).hexdigest()}
        original_ready = channel_fixture.fixtures.SessionTests.ready
        def ready(session):
            # Publish a genuine fixture receipt whose declared native master
            # tuple can subsequently be observed by freshly imported modules.
            channel_fixture.fixtures.s._master.return_value = master
            return original_ready(session)
        with mock.patch.object(channel_fixture.fixtures.SessionTests, "ready", new=ready):
            self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.real_popen = subprocess.Popen
        self.real_run = subprocess.run
        self.program_children = []
        self.native_calls = 0
        self.on_program_started = None
        self.addCleanup(self._reap_children)
        previous = {name: sys.modules.get(name) for name in ("_program_source_loader", "_program_worker_bootstrap")}
        def restore_modules():
            for name, module in previous.items():
                if module is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = module
        self.addCleanup(restore_modules)
        # Capture the actual currently consumed closure; this is fixture input,
        # rather than a hand-maintained imitation of the selected policy.
        context = loader.SourceSession(SOURCE_ROOT / "agent_tools", "ssh_program_execution")
        try:
            context.load("ssh_channel_selection")
            # Match start()'s authenticated lazy-helper admission before its
            # source capsule is copied; importing the owner alone cannot do it.
            automatic = context.load("ssh_automatic_program")
            context.held.read(str(context.directory / "private_config_custody.py"),
                              automatic._PRIVATE_CONFIG_SHA)
            self.sources = {Path(path).relative_to(SOURCE_ROOT): raw
                            for path, (_, _, _, raw) in context.held.files.items()}
            context.guard()
        finally:
            context.close()
        raw = (BEFORE / "ssh_program_execution.py.source").read_bytes()
        provenance = json.loads((BEFORE / "provenance.json").read_bytes())
        self.assertEqual(BEFORE_SHA, provenance["sha256"])
        self.assertEqual(BEFORE_SHA, hashlib.sha256(raw).hexdigest())
        self.before = raw
        # Native channel facts remain the existing declared seam. The inert
        # target program executes under the actual local fixture principal.
        self.fixture.stdout = json.dumps(self.fixture.ready_fixture()).encode()
        self.fixture.rc = 0
        self.receipt = self.fixture.invoke()["receiptSha256"]

    def _reap_children(self):
        for child in self.program_children:
            child.wait(timeout=10)

    def test_whole_before_missing_private_config_red_current_bootstrap_green(self):
        path = SOURCE_ROOT / 'agent_tools/tests/fixtures/ssh_generated_dependency_closure_before/selected_program.before.source'
        raw = path.read_bytes()
        self.assertEqual('ec44f28b9747abe1415777e8494bc6798a0695ed77218190cd6d0a73f941d718', hashlib.sha256(raw).hexdigest())
        original = types.ModuleType('_selected_dependency_before_' + uuid.uuid4().hex)
        original.__file__ = __file__
        exec(compile(raw, str(path), 'exec'), original.__dict__)
        result = unittest.TestResult()
        name = 'test_same_bytes_original_source_replacement_refuses_before_any_native_or_program_child'
        original.SelectedProgramSourceTests(name).run(result)
        self.assertEqual(1, len(result.errors))
        self.assertFalse(result.failures)
        self.assertIn("No such file or directory: 'private_config_custody.py'", result.errors[0][1])
        current = unittest.TestResult()
        SelectedProgramSourceTests(name).run(current)
        self.assertTrue(current.wasSuccessful(), current.failures + current.errors)

    def _source_tree(self, old):
        root = self.root / ("source-before" if old else "source-fixed")
        root.mkdir(mode=0o700)
        for relative, raw in self.sources.items():
            path = root / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(self.before if old and relative == Path("agent_tools/ssh_program_execution.py") else raw)
            path.chmod(0o600)
        return root

    def _transport(self, argv, **kwargs):
        # Preserve the existing actual native-response harness. The submitted
        # program branch instead runs its unchanged structured Python argv as a
        # real local child, retaining stdout/stderr and inherited-pipe EOF.
        if argv[0] == "/bin/ps" and "12345" in argv and "comm=" in argv:
            self.fail("Native metadata fixture must use its exact run response")
        if Path(argv[0]).name != "ssh":
            return self.real_popen(argv, **kwargs)
        if "-O" in argv and argv[argv.index("-O") + 1] == "check":
            self.fail("Native metadata fixture must use its exact run response")
        command = shlex.split(argv[-1])
        while command and Path(command[0]).name == "ssh":
            command = shlex.split(command[-1])
        if len(command) > 4 and command[4] == self.fixture.calls[0][4]:
            self.native_calls += 1
            return self.fixture.consumer(argv, **kwargs)
        self.assertEqual(["python3", "-I", "-B", "-c"], command[:4])
        child = self.real_popen([sys.executable, *command[1:]], **kwargs)
        self.program_children.append(child)
        if self.on_program_started is not None:
            self.on_program_started()
        return child

    def _native_metadata(self, argv, *args, **kwargs):
        # These two native facts are already synthetic in SessionTests.ready.
        # Keep the actual master/PID parsers and exact generation comparison,
        # without launching unrelated Python interpreters under their 3s OS
        # observation budgets. Channel and target pipe children remain real.
        if argv[0] == "/bin/ps" and "12345" in argv and "comm=" in argv:
            self.assertEqual(3, kwargs.get("timeout"))
            return subprocess.CompletedProcess(argv, 0, self.master_output, b"")
        if Path(argv[0]).name == "ssh" and "-O" in argv and argv[argv.index("-O") + 1] == "check":
            self.assertEqual(3, kwargs.get("timeout"))
            return subprocess.CompletedProcess(argv, 0, b"", b"Master running (pid=12345)\n")
        return self.real_run(argv, *args, **kwargs)

    def _prepared(self, old):
        import pwd
        source_root = self._source_tree(old)
        # The loader is itself an admitted source; load the complete copied
        # loader from this original fixture namespace, exactly like the worker.
        name = "_selected_program_loader_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, source_root / "agent_tools/source_module_loader.py")
        source_loader = importlib.util.module_from_spec(spec)
        sys.modules[name] = source_loader
        self.addCleanup(sys.modules.pop, name, None)
        spec.loader.exec_module(source_loader)
        context = source_loader.SourceSession(source_root / "agent_tools", "ssh_program_execution")
        self.addCleanup(context.close)
        owner = context.module
        selection = context.load("ssh_channel_selection")
        with mock.patch.object(subprocess, "Popen", side_effect=self._transport), mock.patch.object(subprocess, "run", side_effect=self._native_metadata):
            chosen = selection.select_channel(self.root, "archlinux", self.fixture.corr, self.receipt)
            self.assertEqual("selected", chosen["state"], chosen)
            # Real source generations enter authentic immutable selection history.
            pointer = self.root / ".rag_index/ssh-channel-selection/hosts/archlinux/current.json"
            pointer_body = pointer.read_bytes()
            history = pointer.parent / json.loads(pointer_body)["history"]
            selected_sources = json.loads(history.read_bytes())["sources"]
            self.assertEqual(selection._sources(), selected_sources)
            self.assertIsNotNone(selection.selected_route_options(self.root, "archlinux"))
            operation = str(uuid.uuid4())
            user = pwd.getpwuid(os.getuid())
            if sys.platform.startswith("linux"):
                boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            else:
                boot = subprocess.check_output(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], text=True).strip().lower()
            # The descendant keeps both pipes open after its original parent
            # exits. Verified terminal therefore requires actual dual EOF.
            descendant = "import sys,time;time.sleep(.05);sys.stdout.write('descendant stdout\\n');sys.stderr.write('descendant stderr\\n')"
            child_record = self.root / ".rag_index/ssh-program-execution" / operation / "child.json"
            source = ("import subprocess,sys,time\nfrom pathlib import Path\n"
                      "deadline=time.monotonic()+5\n"
                      "while not Path(" + repr(str(child_record)) + ").exists():\n"
                      " if time.monotonic()>deadline:raise RuntimeError('original child anchor not published')\n"
                      " time.sleep(.005)\n"
                      "print('parent stdout',flush=True)\nsubprocess.Popen([sys.executable,'-c'," + repr(descendant) + "])\n")
            request = owner._request("archlinux", {"operationId": operation, "program": {
                "language": "python3", "source": source, "args": [], "cwd": str(self.root),
                "targetContext": {"kind": "ssh", "uid": os.getuid(), "principal": user.pw_name,
                                  "home": user.pw_dir, "bootId": boot}}})
            config = owner.transport.load_config(self.root)
            argv = owner.transport.build_ssh_argv(config, "archlinux", 15, owner.remote.command(request["program"]))
            with owner._holding() as held:
                _, connection_pins = owner._hold_connection(held, self.root, "archlinux")
                directory = owner._directory(self.root, operation, create=True)
                # Reproduce start()'s explicit lazy-helper hold in this second
                # source session too, before generating its genuine capsule.
                automatic = context.load("ssh_automatic_program")
                context.held.read(str(context.directory / "private_config_custody.py"),
                                  automatic._PRIVATE_CONFIG_SHA)
                capsule, source_pins = owner._source_capsule(self.root, directory, context)
                intent = {"schemaVersion": 2 if hasattr(owner, "_private_pin") else 1, "operationId": operation, "request": request,
                          "requestSha256": hashlib.sha256(owner._json(request)).hexdigest(),
                          "sourcePins": source_pins, "connectionPins": connection_pins,
                          "transport": "inline", "originalArgvSha256": owner.transport.argv_sha256(argv),
                          "originalCommandBounds": owner._command_bounds(argv), "replayAllowed": False}
                if hasattr(owner, "_private_pin"):
                    intent["privateConnectionPins"] = held.private_connection_pins
                if old:
                    body = owner._bootstrap(self.root, operation, capsule, source_pins)
                else:
                    intent.update(sourceRoot=str(source_root), capsuleRoot=str(capsule))
                    directories = {path: list(pin[1]) for path, pin in context.held.parents.items()}
                    body = owner._bootstrap(self.root, operation, source_root, source_pins, directories)
                owner._save(directory, "intent.json", intent)
                owner._bytes(directory, "worker.py", body.encode())
                command = owner._worker_command(directory / "worker.py", body.encode(), self.root, operation)
                held.finish()
            context.guard()
        return {"owner": owner, "selection": selection, "context": context, "sourceRoot": source_root,
                "directory": directory, "command": command, "pointer": pointer,
                "pointerBody": pointer_body, "selectedSources": selected_sources, "capsule": capsule}

    def _run(self, prepared):
        with mock.patch.object(subprocess, "Popen", side_effect=self._transport), mock.patch.object(subprocess, "run", side_effect=self._native_metadata):
            # Execute the entire exact producer-rendered saved-file bootstrap.
            # In-process execution exposes only the declared native transport
            # seam to freshly imported modules; worker/source code is untouched.
            exec(compile(prepared["command"][-1], "<saved-program-worker>", "exec"), {"__name__": "__main__"})

    def test_preserved_copied_worker_red_and_original_namespace_green(self):
        before = self._prepared(True)
        native_before = self.native_calls
        with self.assertRaises(ValueError) as refusal:
            self._run(before)
        self.assertEqual("SshConfigError", type(refusal.exception).__name__)
        self.assertIn("Explicitly selected SSH", str(refusal.exception))
        self.assertIn("unavailable", str(refusal.exception))
        self.assertEqual(native_before, self.native_calls)
        self.assertFalse((before["directory"] / "execution-intent.json").exists())
        self.assertEqual([], self.program_children)
        self.assertEqual(before["pointerBody"], before["pointer"].read_bytes())
        copied = loader.SourceSession(before["capsule"] / "agent_tools", "ssh_channel_selection")
        try:
            observed = copied.module._sources()
            self.assertEqual({name: value["sha256"] for name, value in before["selectedSources"].items()},
                             {name: value["sha256"] for name, value in observed.items()})
            self.assertNotEqual(before["selectedSources"], observed)
        finally:
            copied.close()
        fixed = self._prepared(False)
        self._run(fixed)
        terminal = json.loads((fixed["directory"] / "terminal.json").read_bytes())
        self.assertEqual("terminal", terminal["state"], terminal)
        self.assertEqual(0, terminal["exitCode"])
        self.assertEqual(1, len(self.program_children))
        self.assertEqual({"stdout": True, "stderr": True}, terminal["capture"]["eof"])
        self.assertEqual(b"parent stdout\ndescendant stdout\n", (fixed["directory"] / "stdout.private").read_bytes())
        self.assertEqual(b"descendant stderr\n", (fixed["directory"] / "stderr.private").read_bytes())
        self.assertTrue((fixed["directory"] / "owner-closed.json").exists())
        self.assertEqual(fixed["pointerBody"], fixed["pointer"].read_bytes())

    def test_same_bytes_original_source_replacement_refuses_before_any_native_or_program_child(self):
        prepared = self._prepared(False)
        path = prepared["sourceRoot"] / "agent_tools/ssh_channel_selection.py"
        replacement = path.with_suffix(".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, path)
        native_before = self.native_calls
        with self.assertRaisesRegex(ValueError, "program_original_source_generation"):
            self._run(prepared)
        self.assertEqual(native_before, self.native_calls)
        self.assertEqual([], self.program_children)
        self.assertFalse((prepared["directory"] / "execution-intent.json").exists())
        self.assertFalse((prepared["directory"] / "owner-closed.json").exists())
        self.assertEqual(prepared["pointerBody"], prepared["pointer"].read_bytes())

    def test_added_private_config_helper_replacement_refuses_before_native_or_program_child(self):
        # With identical current setup inputs, execute the complete preserved
        # caller: its capsule omitted the lazy helper's original generation.
        before = SOURCE_ROOT / 'agent_tools/tests/fixtures/ssh_generated_dependency_closure_before/selected_program.before.source'
        raw = before.read_bytes()
        self.assertEqual('ec44f28b9747abe1415777e8494bc6798a0695ed77218190cd6d0a73f941d718', hashlib.sha256(raw).hexdigest())
        module = types.ModuleType('_selected_capsule_before_' + uuid.uuid4().hex)
        module.__file__ = __file__
        exec(compile(raw, str(before), 'exec'), module.__dict__)
        original = module.SelectedProgramSourceTests('runTest')
        try:
            SelectedProgramSourceTests.setUp(original)
            # This authentic historical caller emits schema1. Retain its whole
            # contemporaneous owner instead of upgrading old receipts to v2.
            custody_fixture = SOURCE_ROOT / "agent_tools/tests/fixtures/ssh_program_private_custody"
            legacy_owner = (custody_fixture / "ssh_program_execution.py.before.source").read_bytes()
            self.assertEqual(json.loads((custody_fixture / "provenance.json").read_bytes())["beforeSha256"],
                             hashlib.sha256(legacy_owner).hexdigest())
            original.sources[Path("agent_tools/ssh_program_execution.py")] = legacy_owner
            old = original._prepared(False)
            path = old['sourceRoot'] / 'agent_tools/private_config_custody.py'
            replacement = path.with_suffix('.replacement')
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, path)
            original._run(old)
            self.assertEqual(1, len(original.program_children), 'old fixture failed to detect helper replacement')
            self.assertEqual('terminal', json.loads((old['directory'] / 'terminal.json').read_bytes())['state'])
        finally:
            original.doCleanups()
        prepared = self._prepared(False)
        path = prepared["sourceRoot"] / "agent_tools/private_config_custody.py"
        replacement = path.with_suffix(".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, path)
        native_before = self.native_calls
        with self.assertRaisesRegex(ValueError, "program_original_source_generation"):
            self._run(prepared)
        self.assertEqual(native_before, self.native_calls)
        self.assertEqual([], self.program_children)
        self.assertFalse((prepared["directory"] / "execution-intent.json").exists())
        self.assertFalse((prepared["directory"] / "owner-closed.json").exists())
        self.assertEqual(prepared["pointerBody"], prepared["pointer"].read_bytes())

    def test_source_replacement_after_start_drains_original_child_to_dual_eof_and_stays_unknown(self):
        prepared = self._prepared(False)
        path = prepared["sourceRoot"] / "agent_tools/ssh_channel_selection.py"
        def replace_after_start():
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, path)
        self.on_program_started = replace_after_start
        with self.assertRaises(ValueError):
            self._run(prepared)
        self.assertEqual(1, len(self.program_children))
        self.assertEqual(0, self.program_children[0].returncode)
        terminal = json.loads((prepared["directory"] / "terminal.json").read_bytes())
        self.assertEqual("unknown", terminal["state"])
        self.assertEqual("original_execution_unverified", terminal["reason"])
        self.assertEqual({"stdout": True, "stderr": True}, terminal["capture"]["eof"])
        self.assertEqual(b"parent stdout\ndescendant stdout\n", (prepared["directory"] / "stdout.private").read_bytes())
        self.assertEqual(b"descendant stderr\n", (prepared["directory"] / "stderr.private").read_bytes())
        self.assertFalse((prepared["directory"] / "owner-closed.json").exists())
        self.assertEqual(prepared["pointerBody"], prepared["pointer"].read_bytes())


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX selected admission")
class SelectedDiagnosticForwardingTests(unittest.TestCase):
    """Actual admission functions; only existing native status facts are inert.

    Selection bytes, private descriptor snapshots, history/source pin checks and
    metadata validation remain real. No channel preparation or child runs.
    """

    def setUp(self):
        import tempfile
        from agent_tools import ssh_channel_selection as selection
        self.selection = selection
        self.transport = selection.transport
        self.providers = (selection.channel, selection.direct_channel)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.corr = "1" * 32
        self.receipt = "2" * 64
        self.unknown = {"state": "unknown", "correlationId": self.corr,
                        "nativeActionAllowed": False, "replayAllowed": False}
        self.raw = {"stdout": b'{"state":"unknown"}\n', "stderr": b"private status marker\n",
                    "returncode": 3}
        # Any accidentally introduced extra native observation is a hard test
        # failure rather than an actual SSH/process start.
        for name, message in (("Popen", "unexpected child"), ("run", "unexpected native query")):
            patch = mock.patch.object(subprocess, name, side_effect=AssertionError(message))
            patch.start()
            self.addCleanup(patch.stop)

    def _selection_history(self, provider):
        private = self.selection.private
        group = self.root / ".rag_index/ssh-channel-selection/hosts/archlinux"
        group.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (group.parent, group.parent.parent, group.parent.parent.parent):
            parent.chmod(0o700)
        def write(path, value):
            path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
            path.chmod(0o600)
        write(self.root / self.transport.CONFIG_FILENAME, b"inert private inventory\n")
        write(group / self.selection._Lock.name, self.selection._Lock.body)
        direct = provider is self.selection.direct_channel
        metadata = {"correlationId": self.corr, "receiptSha256": self.receipt,
                    "outerOptions": ["-S", "/inert/outer", "-o", "ControlMaster=no",
                                     "-o", "ControlPersist=no", "-o", "ProxyCommand=false"],
                    "innerOptions": ["-S", "/tmp/vpn-channel-" + self.corr + "/m",
                                     "-o", "ControlMaster=no", "-o", "ControlPersist=no",
                                     "-o", "ProxyCommand=false"]}
        if direct:
            metadata.update(transportMode="direct", outerAuthoritySha256="3" * 64,
                            outerOptions=list(provider.OUTER_OPTIONS))
        else:
            metadata["outerReceiptSha256"] = "3" * 64
        with private.Directory(self.root) as directory, private.Snapshot(directory, self.transport.CONFIG_FILENAME) as inventory:
            history = {"version": 2 if direct else 1, "host": "archlinux", "metadata": metadata,
                       "inventory": inventory.pin(), "sources": self.selection._sources()}
        history_name = "selection-" + "4" * 32 + ".json"
        write(group / history_name, history)
        with private.Directory(group) as directory, private.Snapshot(directory, history_name) as snapshot:
            write(group / "current.json", {"version": 1, "history": history_name, "pin": snapshot.pin()})
        return metadata

    def test_provider_default_callback_preserves_three_argument_status_abi(self):
        for provider in self.providers:
            with self.subTest(provider=provider.__name__):
                calls = []
                # Exact historical signature intentionally accepts no kwargs.
                def status(root, host, correlation_id):
                    calls.append((root, host, correlation_id))
                    return dict(self.unknown)
                with mock.patch.object(provider, "status", new=status):
                    with self.assertRaises(self.selection.channel.ChannelUnknown) as caught:
                        provider.route_options(self.root, "archlinux", self.corr, self.receipt)
                self.assertEqual(self.unknown, caught.exception.result)
                self.assertEqual([(self.root, "archlinux", self.corr)], calls)

    def test_provider_explicit_callback_forwards_same_capture_once(self):
        for provider in self.providers:
            with self.subTest(provider=provider.__name__):
                calls, captures = [], []
                callback = captures.append
                def status(root, host, correlation_id, *, _private_capture):
                    calls.append((root, host, correlation_id))
                    self.assertIs(callback, _private_capture)
                    _private_capture(self.raw)
                    return dict(self.unknown)
                with mock.patch.object(provider, "status", new=status):
                    with self.assertRaises(self.selection.channel.ChannelUnknown) as caught:
                        provider.route_options(self.root, "archlinux", self.corr, self.receipt,
                                               _private_capture=callback)
                self.assertEqual(self.unknown, caught.exception.result)
                self.assertEqual([(self.root, "archlinux", self.corr)], calls)
                self.assertEqual(1, len(captures))
                self.assertIs(self.raw, captures[0])

    def test_selection_default_callback_preserves_four_argument_provider_abi(self):
        self.assertIsNone(self.transport._PRIVATE_ADMISSION_CAPTURE.get())
        for provider in self.providers:
            with self.subTest(provider=provider.__name__):
                expected = self._selection_history(provider)
                calls = []
                # Exact historical provider ABI intentionally rejects kwargs.
                def route_options(root, host, correlation_id, receipt_sha256):
                    calls.append((root, host, correlation_id, receipt_sha256))
                    return expected
                with mock.patch.object(provider, "route_options", new=route_options):
                    actual = self.selection.selected_route_options(self.root, "archlinux")
                self.assertEqual(expected, actual)
                self.assertEqual([(self.root, "archlinux", self.corr, self.receipt)], calls)

    def test_selection_explicit_and_active_collector_use_same_observation(self):
        for provider in self.providers:
            for active_collector in (False, True):
                with self.subTest(provider=provider.__name__, active_collector=active_collector):
                    expected = self._selection_history(provider)
                    calls, captures = [], []
                    callback = captures.append
                    def route_options(root, host, correlation_id, receipt_sha256, *, _private_capture):
                        calls.append((root, host, correlation_id, receipt_sha256))
                        self.assertIs(self.transport._retain_private_admission if active_collector else callback,
                                      _private_capture)
                        _private_capture(self.raw)
                        return expected
                    with mock.patch.object(provider, "route_options", new=route_options):
                        if active_collector:
                            with self.transport._private_admission_capture() as records:
                                actual = self.selection.selected_route_options(self.root, "archlinux")
                            self.assertEqual([], records["captureFailures"])
                            self.assertEqual(1, len(records["observations"]))
                            self.assertEqual(self.raw, records["observations"][0]["capture"])
                            self.assertIsNot(self.raw, records["observations"][0]["capture"])
                            self.assertEqual(self.transport._LOADED_SOURCE_SHA,
                                             records["observations"][0]["transportSourceSha256"])
                            self.assertIsNone(self.transport._PRIVATE_ADMISSION_CAPTURE.get())
                        else:
                            actual = self.selection.selected_route_options(self.root, "archlinux",
                                                                            _private_capture=callback)
                            self.assertEqual(1, len(captures))
                            self.assertIs(self.raw, captures[0])
                    self.assertEqual(expected, actual)
                    self.assertEqual([(self.root, "archlinux", self.corr, self.receipt)], calls)


if __name__ == "__main__":
    unittest.main()
