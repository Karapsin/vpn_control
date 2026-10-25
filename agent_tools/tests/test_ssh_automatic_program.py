"""Real local SSH boundary tests for implicit saved-file Python carriers.

The executable below is the only substituted boundary. It executes the exact
emitted remote argv locally, refuses any command over 60000 bytes, and never
opens a network connection or starts a VM.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import ast
import hashlib
import importlib
import importlib.util
import json
import os
import py_compile
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock


TOOLS = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures/ssh_automatic_program"


def before_module(name):
    path = FIXTURE / (name + ".py.before.source")
    manifest = json.loads((FIXTURE / "provenance.json").read_bytes())
    if hashlib.sha256(path.read_bytes()).hexdigest() != manifest["beforeimages"][name + ".py"]["sha256"]:
        raise AssertionError("Preserved pre-staging source changed")
    alias = "agent_tools._automatic_before_" + name + "_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_loader(alias, loader=None, origin=str(path))
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[alias] = module
    try:
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    finally:
        sys.modules.pop(alias, None)
    return module


def preserved_named_module(name, filename, manifest_key):
    path = FIXTURE / filename
    manifest = json.loads((FIXTURE / "provenance.json").read_bytes())
    expected = manifest["beforeimages"][manifest_key]["sha256"]
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise AssertionError("Preserved automatic transport source changed")
    alias = "agent_tools._automatic_before_" + name + "_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_loader(alias, loader=None, origin=str(path))
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[alias] = module
    try:
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    finally:
        sys.modules.pop(alias, None)
    return module


@contextmanager
def preserved_stage_implementation(*, residual=False):
    import agent_tools
    automatic = preserved_named_module("automatic",
        "residual_args.before.source" if residual else "stage_failure.before.source",
        "ssh_automatic_program.py.residual-args" if residual else "ssh_automatic_program.py.stage-failure")
    transport = preserved_named_module("transport", "residual_transport.before.source",
                                      "ssh_transport.py.residual-args")
    # Both builder and submitter use complete physical preserved files. The
    # current builder cannot repair/refuse a historical carrier for this RED.
    with mock.patch.dict(sys.modules, {"agent_tools.ssh_automatic_program": automatic,
                                       "agent_tools.ssh_transport": transport}), \
         mock.patch.object(agent_tools, "ssh_automatic_program", automatic, create=True), \
         mock.patch.object(agent_tools, "ssh_transport", transport, create=True):
        yield automatic


class PeerFixture:
    def __init__(self, root):
        import pwd
        self.root = root
        self.peer = root / "peer"
        self.peer.mkdir(mode=0o700)
        self.log = root / "peer-commands.jsonl"
        self.mode = root / "peer-mode"
        self.binary = root / "local-fixture-ssh"
        self.binary.write_text(
            "#!" + sys.executable + "\n"
            "import hashlib,json,os,shlex,sys\n"
            "from pathlib import Path\n"
            "args=sys.argv[1:];command=args[-1]\n"
            "record={'commandBytes':len(command.encode()),'maxArgumentBytes':max(map(lambda x:len(x.encode()),args)),"
            "'commandSha256':hashlib.sha256(command.encode()).hexdigest(),'endpoint':args[-2]}\n"
            "fd=os.open(" + repr(str(self.log)) + ",os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n"
            "try:os.write(fd,(json.dumps(record,sort_keys=True)+'\\n').encode())\n"
            "finally:os.close(fd)\n"
            "if record['commandBytes']>60000 or record['maxArgumentBytes']>60000:sys.exit(91)\n"
            "mode=Path(" + repr(str(self.mode)) + ")\n"
            "if mode.exists() and mode.read_text()=='reject':sys.exit(255)\n"
            "if mode.exists() and mode.read_text()=='stderr':sys.stdin.buffer.read();sys.stdout.write('PUBLIC_STAGE_OUT');sys.stderr.write('PUBLIC_STAGE_ERR');sys.exit(255)\n"
            "argv=shlex.split(command)\n"
            "if argv[0] in ('python3','/usr/bin/python3'):argv[0]=sys.executable\n"
            "if Path(argv[0]).name in ('ssh','sftp','scp'):raise RuntimeError('network executable refused')\n"
            "os.execvpe(argv[0],argv,os.environ)\n"
        )
        self.binary.chmod(0o700)
        self.config_path = root / ".vm-hosts.local.json"
        key, known = root / "inert-key", root / "inert-known"
        for path in (key, known):
            path.write_bytes(b"PUBLIC_INERT_FIXTURE\n")
            path.chmod(0o600)
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.hosts = {"explicit-peer": {
            "host": "192.0.2.72", "port": 2228, "user": self.user,
            "identityFile": str(key), "knownHostsFile": str(known),
        }}
        self.write_config()

    def write_config(self):
        self.config_path.write_text(json.dumps({"schemaVersion": 1, "hosts": self.hosts}))
        self.config_path.chmod(0o600)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    @contextmanager
    def environment(self):
        with mock.patch.dict(os.environ, {"TMPDIR": str(self.peer), "TMP": str(self.peer), "TEMP": str(self.peer)}):
            yield


def long_command(marker="PUBLIC", exitcode=0):
    # Fixed source and payload are deliberately separate. The wrapper is the
    # existing repository carrier shape, including quotes expanded by SSH hops.
    code = (
        "import hashlib,json,sys\n"
        "PADDING=" + repr("Ω'\"" * 10000) + "\n"
        "payload=sys.stdin.buffer.read()\n"
        "print(json.dumps({'marker':" + repr(marker) + ", 'argv':sys.argv[1:],"
        "'stdinSha256':hashlib.sha256(payload).hexdigest(),'stdinBytes':len(payload)},sort_keys=True))\n"
        "raise SystemExit(" + repr(exitcode) + ")\n"
    )
    return ("python3", "-I", "-B", "-c", "exec(" + repr(code) + ")", "PUBLIC argument with spaces", "Ω ' quote")


@unittest.skipUnless(os.name == "posix", "owned POSIX peer boundary")
class AutomaticProgramTests(unittest.TestCase):
    retained_evidence = None
    legacy_transport = None
    custody_before = False

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        (self.root / ".rag_index").mkdir(mode=0o700)
        self.peer = PeerFixture(self.root)

    def implementation(self, before=False):
        if before:
            transfer, transport = before_module("ssh_transfer"), before_module("ssh_transport")
            transfer.ssh_transport = transport
            return transfer, transport
        from agent_tools import ssh_transfer, ssh_transport
        return ssh_transfer, ssh_transport

    def argv(self, transport, command=None):
        config = transport.load_config(self.root)
        return transport.build_ssh_argv(config, "explicit-peer", 5,
            command=long_command() if command is None else command,
            ssh_binary=str(self.peer.binary), nested_ssh_binary=str(self.peer.binary))

    def exercise_shared_owner(self, before=False):
        transfer, transport = self.implementation(before)
        argv = self.argv(transport)
        payload = b"PUBLIC original stdin\x00\xff" * 7000
        caught = None
        with self.peer.environment():
            try:
                code, output = transfer._bounded_run(argv, payload, 10)
            except Exception as error:
                caught = type(error).__name__ + ": " + str(error)
                code, output = None, b""
        value = {"error": caught, "exitCode": code, "stdout": output.decode("utf-8", "replace"),
                 "events": self.peer.events()}
        if self.retained_evidence is not None:
            target = Path(self.retained_evidence) / ("before" if before else "after")
            shutil.copytree(self.root, target)
            (target / "assertion-input.json").write_text(json.dumps(value, indent=2) + "\n")
        return value, payload

    def assert_shared_owner_works(self, value, payload):
        self.assertIsNone(value["error"], value)
        self.assertEqual(0, value["exitCode"], value)
        result = json.loads(value["stdout"])
        self.assertEqual("PUBLIC", result["marker"])
        self.assertEqual(["PUBLIC argument with spaces", "Ω ' quote"], result["argv"])
        self.assertEqual(len(payload), result["stdinBytes"])
        self.assertEqual(hashlib.sha256(payload).hexdigest(), result["stdinSha256"])
        self.assertGreaterEqual(len(value["events"]), 2, value)
        self.assertTrue(all(event["commandBytes"] <= 60000 and event["maxArgumentBytes"] <= 60000
                            for event in value["events"]), value)

    def test_shared_owner_stages_oversized_program_automatically(self):
        self.assert_shared_owner_works(*self.exercise_shared_owner())

    def automatic(self):
        from agent_tools import ssh_automatic_program
        return ssh_automatic_program

    def execute(self, submitted, payload=b"PUBLIC stdin"):
        return subprocess.run(submitted, input=payload, capture_output=True, timeout=10)

    @contextmanager
    def physical_public_server(self):
        directory = self.root / "agent_tools"
        directory.mkdir(mode=0o700)
        # Keep complete source files. No dispatch fragment or source guard is
        # replaced; only the allowed fixed adapter is an inert local fixture.
        raw = (TOOLS / "mcp_server.py").read_bytes()
        captured = {
            node.args[0].value + ".py"
            for node in ast.walk(ast.parse(raw))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "_captured_core" and node.args
            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        }
        needed = captured | {
            "mcp_server.py", "affected_agent_tests.py", "affected_agent_test_dependencies.json",
            "agent_test_runner.py", "native_review_source_closure.py", "source_module_loader.py",
            "ssh_transfer.py", "ssh_transport.py", "ssh_automatic_program.py", "private_config_custody.py",
            "readiness.py", "private_inventory_lock.py", "tool_action_policy.py", "tool_action_policy.json",
        }
        needed.update({'readiness_vm_dispatch.py','readiness_vm_dispatch.json',
                       'android_observation.py','readiness_transport.py','readiness_ssh_master.py'})
        # The real mandatory VM admission imports its finite transitive Python
        # closure. Include complete source files, not replacement dispatch code.
        pending=list(needed);scripts=set()
        while pending:
            name=pending.pop()
            if not name.endswith('.py'):continue
            for node in ast.walk(ast.parse((TOOLS/name).read_bytes())):
                if not isinstance(node,ast.ImportFrom):continue
                modules=([node.module.split('.')[0]]if node.module else [v.name for v in node.names])if node.level==1 else []
                if node.level==0 and node.module=='agent_tools':modules=[v.name for v in node.names]
                elif node.level==0 and node.module and node.module.startswith('agent_tools.'):
                    modules=[node.module.removeprefix('agent_tools.').split('.')[0]]
                for module in modules:
                    child=module+'.py'
                    if (TOOLS/child).is_file()and child not in needed:needed.add(child);pending.append(child)
                if node.level==0 and node.module and node.module.startswith('scripts.'):
                    scripts.add(node.module.removeprefix('scripts.').replace('.','/')+'.py')
        for name in sorted(needed):
            shutil.copyfile(TOOLS / name, directory / name)
        if scripts:
            (self.root/'scripts').mkdir(mode=0o700)
            for name in scripts:shutil.copyfile(TOOLS.parent/'scripts'/name,self.root/'scripts'/name)
        adapter = directory / "android_proxy_recovery.py"
        adapter.write_text(
            "import json\nfrom pathlib import Path\n"
            "from . import ssh_transfer,ssh_transport\n"
            "class AndroidProxyRecoveryError(ValueError):pass\n"
            "def observe_recovery(root,host,device,identity):\n"
            " root=Path(root)\n"
            " config=ssh_transport.load_config(root)\n"
            " command=" + repr(long_command()) + "\n"
            " argv=ssh_transport.build_ssh_argv(config,host,5,command=command,"
            "ssh_binary=str(root/'local-fixture-ssh'),nested_ssh_binary=str(root/'local-fixture-ssh'))\n"
            " code,output=ssh_transfer._bounded_run(argv,b'PUBLIC_MCP_INPUT',10)\n"
            " if (root/'drift').exists():\n"
            "  path=Path(__file__);path.write_bytes(path.read_bytes()+b'\\n# changed during call\\n')\n"
            " return {'ok':code==0,'state':'observed','nativeActionAllowed':False,"
            "'replayAllowed':False,'localFixtureOnly':True,'observed':json.loads(output)}\n"
        )
        # This deliberately inert adapter has its own explicitly reviewed
        # physical fixture digest; retain the production target-source guards.
        manifest=directory/'readiness_vm_dispatch.json'
        body=json.loads(manifest.read_bytes())
        body['sourcePins']['android_proxy_recovery']=hashlib.sha256(adapter.read_bytes()).hexdigest()
        manifest.write_text(json.dumps(body,sort_keys=True)+'\n')
        readiness_binary=self.root/'readiness-fixture-ssh'
        readiness_binary.write_text('#!'+sys.executable+'\n'+(Path(__file__).parent/'fixtures/readiness_transport/ssh_peer.source').read_text())
        readiness_binary.chmod(0o700)
        package_name = "_physical_automatic_public_" + uuid.uuid4().hex
        package = types.ModuleType(package_name)
        package.__path__ = [str(directory)]
        sys.modules[package_name] = package
        public = None
        self._public_fixture_sources=tuple(sorted({'agent_tools/'+name for name in needed}|{'scripts/'+name for name in scripts}))
        try:
            spec = importlib.util.spec_from_file_location(package_name + ".mcp_server", directory / "mcp_server.py")
            public = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = public
            spec.loader.exec_module(public)
            # Only the SSH executable path is substituted. The genuine
            # coordinator, journal, kernel actor join and real Unix socket peer
            # establish readiness before the generated file transfer caller.
            children=[]
            public._fixture_readiness_children=children
            try:
                with public._SOURCE_MODULE_LOADER.request_scope(directory):
                    loaded=public._agent_module('ssh_transport')._module
                    master=public._agent_module('readiness_ssh_master')._module
                    prefix=loaded.fresh_direct_prefix;spawn=master.session._spawn;builder=loaded._build_ssh_argv
                    def fixture_prefix(config,host):
                        argv,endpoint=prefix(config,host)
                        return [str(readiness_binary),*argv[1:]],endpoint
                    def tracked_spawn(*args,**kwargs):
                        child=spawn(*args,**kwargs);children.append(child);return child
                    def fixture_builder(*args,**kwargs):
                        argv=builder(*args,**kwargs)
                        if argv[0] in ('ssh','/usr/bin/ssh'):argv[0]=str(readiness_binary)
                        return argv
                    with mock.patch.object(loaded,'fresh_direct_prefix',side_effect=fixture_prefix), \
                         mock.patch.object(loaded,'_build_ssh_argv',side_effect=fixture_builder), \
                         mock.patch.object(master.session,'_spawn',side_effect=tracked_spawn), \
                         mock.patch.dict(os.environ,{'VC_READINESS_FIXTURE_MODE':str(self.root/'readiness-mode')}), \
                         mock.patch.object(public, "_native_response", side_effect=lambda tool, action, result, request: result):
                        yield public
            except ValueError:
                # The explicit drift test also invalidates this outer retained
                # source scope after the tool already reports its closed guard.
                if not (self.root/'drift').exists():raise
            finally:
                for child in children:
                    if child.poll()is None:child.terminate()
                    child.wait(timeout=3)
        finally:
            for name in list(sys.modules):
                if (name == package_name or name.startswith(package_name + ".") or
                        public is not None and (name.startswith("_vpn_core_" + str(public._MCP_BOOT_TIME_NS) + "_") or
                        name == "_vpn_native_core_" + str(public._MCP_BOOT_TIME_NS) or
                        name.startswith("_vpn_native_core_" + str(public._MCP_BOOT_TIME_NS) + "."))):
                    sys.modules.pop(name, None)

    def test_previous_public_vm_fixture_lacks_real_readiness_causal_red(self):
        fixture=Path(__file__).parent/'fixtures/readiness_submission'
        raw=(fixture/'test_ssh_automatic_program.py.before-vm-admission.source').read_bytes()
        expected=json.loads((fixture/'provenance.json').read_bytes())['beforeSha256']['test_ssh_automatic_program.py.vm-admission']
        self.assertEqual(expected,hashlib.sha256(raw).hexdigest())
        name='agent_tools.tests._automatic_vm_fixture_before_'+uuid.uuid4().hex
        old=types.ModuleType(name);old.__file__=str(fixture/'test_ssh_automatic_program.py.before-vm-admission.source')
        with mock.patch.dict(sys.modules,{name:old}):exec(compile(raw,old.__file__,'exec'),old.__dict__)
        old.TOOLS=TOOLS
        owner=old.AutomaticProgramTests('runTest');owner.setUp();self.addCleanup(owner.doCleanups)
        with self.assertRaises(AssertionError):owner.test_registered_public_vm_route_reaches_automatic_real_child_path()
        self.assertEqual([],owner.peer.events())

    def test_registered_public_vm_route_reaches_automatic_real_child_path(self):
        with self.physical_public_server() as public, self.peer.environment():
            result = public.vm_workflow("android-proxy-recovery-status", {
                "host": "explicit-peer", "device": "api29", "identity": {}})
            self.assertIs(True, result.get("ok"), result)
            self.assertEqual("observed", result.get("state"), result)
            self.assertIs(True, result.get("localFixtureOnly"), result)
            self.assertEqual(1,len(public._fixture_readiness_children))
            self.assertIsNone(public._fixture_readiness_children[0].poll())
            self.assertEqual("PUBLIC", result["observed"]["marker"])
            self.assertEqual(hashlib.sha256(b"PUBLIC_MCP_INPUT").hexdigest(), result["observed"]["stdinSha256"])
            self.assertEqual(2, len(self.peer.events()))
            self.assertTrue(all(e["commandBytes"] <= 60000 for e in self.peer.events()))
            before = len(self.peer.events())
            refused = public.vm_workflow("android-proxy-recovery-status", {
                "host": "explicit-peer", "device": "api29", "identity": {}, "command": "unallowed"})
            self.assertIs(False, refused.get("ok"), refused)
            self.assertEqual(before, len(self.peer.events()))

    def test_registered_public_route_preserves_source_closing_refusal_after_child(self):
        (self.root / "drift").touch()
        with self.physical_public_server() as public, self.peer.environment():
            result = public.vm_workflow("android-proxy-recovery-status", {
                "host": "explicit-peer", "device": "api29", "identity": {}})
        self.assertEqual(2, len(self.peer.events()))
        self.assertEqual("unknown", result.get("state"), result)
        self.assertEqual("native_source_closure_unavailable", result.get("reason"), result)
        self.assertIs(False, result.get("nativeActionAllowed"), result)
        self.assertIs(False, result.get("replayAllowed"), result)

    def test_closed_source_session_plan_refuses_before_journal_or_peer(self):
        from agent_tools.source_module_loader import Adapter
        with self.physical_public_server():
            directory = self.root / "agent_tools"
            (directory / "inert_plan.py").write_text(
                "from . import ssh_transport\n"
                "def plan(root):\n"
                " config=ssh_transport.load_config(root)\n"
                " return ssh_transport.build_ssh_argv(config,'explicit-peer',5,command=" + repr(long_command()) + ","
                "ssh_binary=str(config.root/'local-fixture-ssh'),nested_ssh_binary=str(config.root/'local-fixture-ssh'))\n"
            )
            adapter = Adapter(directory, "inert_plan")
            try:
                plan = adapter.plan(str(self.root))
                raw_automatic = adapter._session.load("ssh_automatic_program")
            finally:
                adapter.close()
            with self.peer.environment(), self.assertRaisesRegex(ValueError, "closed_adapter_source"):
                with raw_automatic.automatic_submission(plan):
                    self.fail("Closed adapter plan escaped source custody")
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    @contextmanager
    def stale_automatic_cache(self, *, timestamp_pyc):
        import agent_tools
        current = self.automatic()
        actual = Path(current.__file__).read_bytes()
        old = (FIXTURE / "residual_args.before.source").read_bytes()
        source = self.root / ("cached-automatic-pyc.py" if timestamp_pyc else "cached-automatic-module.py")
        if timestamp_pyc:
            # Extra comment bytes only equalize pyc header size. Executable
            # bytes remain the exact preserved unfixed module.
            gap = len(actual) - len(old)
            if gap < 2:
                raise AssertionError("Pyc fixture requires shorter preserved source")
            source.write_bytes(old + b"\n#" + b"X" * (gap - 2))
            stamp = source.stat()
            py_compile.compile(str(source), doraise=True,
                               invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            source.write_bytes(actual)
            os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        else:
            source.write_bytes(actual)
        name = "agent_tools._cached_automatic_" + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        try:
            if timestamp_pyc:
                spec.loader.exec_module(module)
            else:
                exec(compile(old, str(source), "exec"), module.__dict__)
            self.assertEqual(hashlib.sha256(actual).hexdigest(), module._SOURCE_SHA)
            self.assertFalse(hasattr(module, "_EXECUTING_CODE"))
            selected_transport = self.legacy_transport
            overrides = {"agent_tools.ssh_automatic_program": module}
            if selected_transport is not None:
                overrides["agent_tools.ssh_transport"] = selected_transport
            with mock.patch.dict(sys.modules, overrides), \
                 mock.patch.object(agent_tools, "ssh_automatic_program", module), \
                 (mock.patch.object(agent_tools, "ssh_transport", selected_transport)
                  if selected_transport is not None else nullcontext()):
                yield module
        finally:
            sys.modules.pop(name, None)

    def assert_stale_automatic_refuses(self, timestamp_pyc):
        _, transport = self.implementation()
        with self.stale_automatic_cache(timestamp_pyc=timestamp_pyc) as stale, self.peer.environment():
            with self.assertRaises(ValueError):
                argv = self.argv(transport)
                with stale.automatic_submission(argv):
                    self.fail("Old executed module was admitted under current source bytes")
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_cached_old_automatic_module_refuses_under_current_source_digest(self):
        self.assert_stale_automatic_refuses(False)

    def test_timestamp_valid_old_automatic_pyc_refuses_under_current_source_digest(self):
        self.assert_stale_automatic_refuses(True)

    def exercise_cached_before(self, timestamp_pyc):
        import agent_tools
        original_transfer, _ = self.implementation()
        legacy = preserved_named_module("cached_transport", "residual_transport.before.source",
                                        "ssh_transport.py.residual-args")
        with mock.patch.object(self, "legacy_transport", legacy), \
             mock.patch.object(self, "implementation", return_value=(original_transfer, legacy)):
            with self.assertRaises(AssertionError):
                self.assert_stale_automatic_refuses(timestamp_pyc)
        self.assertGreaterEqual(len(self.peer.events()), 1)
        self.assertTrue((self.root / ".rag_index/ssh-automatic-program").is_dir())

    def test_preserved_transport_accepts_cached_old_module_under_current_digest(self):
        self.exercise_cached_before(False)

    def test_preserved_transport_accepts_valid_old_pyc_under_current_digest(self):
        self.exercise_cached_before(True)

    def test_unsupported_coordinator_refuses_before_binding_or_journal(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        with mock.patch.object(automatic, "coordinator_capable", return_value=False):
            with self.assertRaisesRegex(automatic.AutomaticProgramError, "automatic_unsupported_coordinator"):
                self.argv(transport)
            with self.assertRaisesRegex(automatic.AutomaticProgramError, "automatic_unsupported_coordinator"):
                with automatic.automatic_submission(argv):
                    self.fail("Unsupported coordinator submitted")
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_symlink_local_journal_cannot_redirect_saved_source_or_intent(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        unrelated = self.root / "unrelated"
        unrelated.mkdir(mode=0o700)
        sentinel = unrelated / "sentinel"
        sentinel.write_bytes(b"PUBLIC_UNRELATED")
        for parent_link in (True, False):
            with self.subTest(parent_link=parent_link):
                link = self.root / ".rag_index" if parent_link else self.root / ".rag_index/ssh-automatic-program"
                if parent_link:
                    link.rmdir()
                link.symlink_to(unrelated, target_is_directory=True)
                try:
                    argv = self.argv(transport)
                    with self.peer.environment(), self.assertRaises((ValueError, OSError)):
                        with automatic.automatic_submission(argv):
                            self.fail("Symlink journal admitted")
                    self.assertEqual(b"PUBLIC_UNRELATED", sentinel.read_bytes())
                    self.assertEqual([sentinel], list(unrelated.iterdir()))
                    self.assertFalse(self.peer.events())
                finally:
                    link.unlink()
                    if parent_link:
                        link.mkdir(mode=0o700)

    def test_oversized_residual_argument_refuses_before_journal_or_peer(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        command = (*long_command()[:5], "PUBLIC_ARG_" + "X" * 70000)
        with self.peer.environment(), self.assertRaises((automatic.AutomaticProgramError, ValueError)):
            argv = self.argv(transport, command)
            with automatic.automatic_submission(argv):
                self.fail("Oversized residual argument submitted")
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_preserved_residual_argument_beforeimage_uploads_before_refusal(self):
        with preserved_stage_implementation(residual=True), self.assertRaises(AssertionError):
            self.test_oversized_residual_argument_refuses_before_journal_or_peer()
        self.assertEqual(1, len(self.peer.events()))
        directories = list((self.root / ".rag_index/ssh-automatic-program").iterdir())
        self.assertEqual(1, len(directories))
        self.assertTrue((directories[0] / "unknown.json").is_file())
        self.assertTrue((directories[0] / "stage.stdout").is_file())

    def test_small_argv_is_unchanged_without_automatic_state(self):
        _, transport = self.implementation()
        argv = self.argv(transport, ("python3", "-I", "-B", "-c", "print('PUBLIC_SMALL')"))
        self.assertIsInstance(argv, list)
        with self.peer.environment(), self.automatic().automatic_submission(argv) as submitted:
            self.assertIs(submitted, argv)
            result = self.execute(submitted)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(b"PUBLIC_SMALL\n", result.stdout)
        self.assertEqual(1, len(self.peer.events()))
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_oversized_plan_cannot_bypass_submission_or_be_mutated(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        self.assertIsInstance(argv, automatic.PlannedArgv)
        with self.assertRaises(automatic.AutomaticProgramError):
            list(argv)
        with self.assertRaises(automatic.AutomaticProgramError):
            argv[:]
        with self.assertRaises((TypeError, AttributeError, ValueError)):
            argv[-1] = "true"
        with self.assertRaises((TypeError, AttributeError)):
            argv.command = ("true",)
        with self.assertRaises(automatic.AutomaticProgramError):
            subprocess.Popen(argv)
        self.assertFalse(self.peer.events())

    def test_unsupported_oversized_form_and_program_limit_refuse_pre_effect(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        for command in (("sh", "-c", "true #" + "X" * 65000),
                        ("python3", "-c", "X" * (automatic.MAX_PROGRAM_BYTES + 1)),
                        ("python3", "-m", "X" * 65000)):
            with self.subTest(command=command[:2]), self.assertRaises(automatic.AutomaticProgramError):
                self.argv(transport, command)
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_unbound_oversized_list_and_password_route_refuse_pre_effect(self):
        _, transport = self.implementation()
        argv = self.argv(transport)
        with self.assertRaises(ValueError):
            with transport.automatic_submission(list(argv.original_argv)):
                self.fail("Unbound oversized command submitted")
        self.peer.hosts["explicit-peer"]["password"] = "PUBLIC_INERT_PASSWORD"
        self.peer.write_config()
        with self.assertRaises(ValueError):
            self.argv(transport)
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_whole_saved_program_and_original_stdin_arguments_and_exit_survive(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        command = long_command(exitcode=23)
        argv = self.argv(transport, command)
        with self.peer.environment(), automatic.automatic_submission(argv) as submitted:
            local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
            remote = self.peer.peer / ("vpn-control-auto-" + argv.correlation)
            self.assertEqual(command[4].encode(), (local / "program.source").read_bytes())
            self.assertEqual(command[4].encode(), (remote / "program.source").read_bytes())
            self.assertEqual(0o600, (remote / "program.source").stat().st_mode & 0o777)
            self.assertEqual(0o700, remote.stat().st_mode & 0o777)
            self.assertFalse((remote / "execution-intent.json").exists())
            self.assertLessEqual(automatic.command_bytes(submitted), 60000)
            payload = b"PUBLIC original input\x00\xff" * 10000
            result = self.execute(submitted, payload)
            self.assertEqual(23, result.returncode, result.stderr)
            self.assertEqual(b"", result.stderr)
            output = json.loads(result.stdout)
            self.assertEqual(hashlib.sha256(payload).hexdigest(), output["stdinSha256"])
            self.assertEqual(["PUBLIC argument with spaces", "Ω ' quote"], output["argv"])
        self.assertTrue((remote / "execution-intent.json").is_file())
        self.assertTrue((local / "submission-returned.json").is_file())
        self.assertFalse(json.loads((local / "intent.json").read_bytes())["replayAllowed"])

    def test_stage_failure_retains_exact_original_streams_and_observation(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        self.peer.mode.write_text("stderr")
        with self.peer.environment(), self.assertRaises(automatic.AutomaticProgramError):
            with automatic.automatic_submission(argv):
                self.fail("Failed stage submitted original program")
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertEqual(b"PUBLIC_STAGE_OUT", (local / "stage.stdout").read_bytes())
        self.assertEqual(b"PUBLIC_STAGE_ERR", (local / "stage.stderr").read_bytes())
        observation = json.loads((local / "stage.observation.json").read_bytes())
        self.assertEqual(255, observation["returnCode"])
        self.assertTrue(observation["complete"])
        self.assertEqual(len(b"PUBLIC_STAGE_OUT"), observation["counts"]["stdout"])
        self.assertEqual(len(b"PUBLIC_STAGE_ERR"), observation["counts"]["stderr"])
        self.assertTrue((local / "unknown.json").is_file())
        self.assertFalse((local / "execution-intent.json").exists())
        count = len(self.peer.events())
        with self.peer.environment(), self.assertRaises((FileExistsError, automatic.AutomaticProgramError)):
            with automatic.automatic_submission(argv):
                self.fail("Failed stage replayed")
        self.assertEqual(count, len(self.peer.events()))

    def test_preserved_stage_failure_beforeimage_discards_original_streams(self):
        with preserved_stage_implementation():
            with self.assertRaises(FileNotFoundError):
                self.test_stage_failure_retains_exact_original_streams_and_observation()
        self.assertEqual(1, len(self.peer.events()))
        directories = list((self.root / ".rag_index/ssh-automatic-program").iterdir())
        self.assertEqual(1, len(directories))
        self.assertTrue((directories[0] / "unknown.json").is_file())
        self.assertFalse((directories[0] / "stage.stdout").exists())
        self.assertFalse((directories[0] / "stage.stderr").exists())

    def test_program_transfer_writes_and_remote_reads_remain_chunk_bounded(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        sizes = []
        write = os.write
        def tracked(fd, payload):
            sizes.append(len(payload))
            return write(fd, payload)
        with self.peer.environment(), mock.patch.object(automatic.os, "write", side_effect=tracked):
            with automatic.automatic_submission(argv) as submitted:
                result = self.execute(submitted)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertGreater(len(argv.command[4].encode()), automatic.CHUNK_BYTES)
        self.assertTrue(sizes)
        self.assertLessEqual(max(sizes), automatic.CHUNK_BYTES)
        self.assertTrue(all(e["commandBytes"] <= automatic.COMMAND_BYTES for e in self.peer.events()))

    def test_saved_source_tamper_is_refused_before_program_effect(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        with self.peer.environment(), automatic.automatic_submission(argv) as submitted:
            remote = self.peer.peer / ("vpn-control-auto-" + argv.correlation)
            path = remote / "program.source"
            path.write_bytes(path.read_bytes() + b"# PUBLIC changed\n")
            result = self.execute(submitted)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(b"", result.stdout)
        self.assertIn(b"automatic_program_metadata", result.stderr)
        self.assertFalse((remote / "execution-intent.json").exists())

    def test_remote_saved_loader_and_original_automatic_plan_never_replay(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        with self.peer.environment(), automatic.automatic_submission(argv) as submitted:
            first = self.execute(submitted)
            second = self.execute(submitted)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertNotEqual(0, second.returncode)
        self.assertEqual(b"", second.stdout)
        count = len(self.peer.events())
        with self.peer.environment(), self.assertRaises((FileExistsError, automatic.AutomaticProgramError)):
            with automatic.automatic_submission(argv):
                self.fail("A completed automatic plan was replayed")
        self.assertEqual(count, len(self.peer.events()))

    def test_unknown_stage_retains_original_intent_and_cannot_retry(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        self.peer.mode.write_text("reject")
        with self.peer.environment(), self.assertRaises(automatic.AutomaticProgramError):
            with automatic.automatic_submission(argv):
                self.fail("Unknown stage submitted original program")
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "intent.json").is_file())
        self.assertTrue((local / "program.source").is_file())
        self.assertFalse((local / "execution-intent.json").exists())
        self.assertFalse(json.loads((local / "unknown.json").read_bytes())["replayAllowed"])
        count = len(self.peer.events())
        self.peer.mode.unlink()
        with self.peer.environment(), self.assertRaises((FileExistsError, automatic.AutomaticProgramError)):
            with automatic.automatic_submission(argv):
                self.fail("Unknown automatic plan was retried")
        self.assertEqual(count, len(self.peer.events()))

    def test_shared_observer_stages_oversized_program_with_devnull_input(self):
        from agent_tools import android_observation
        _, transport = self.implementation()
        argv = self.argv(transport)
        with self.peer.environment():
            code, output = android_observation._run_probe(argv, 10)
        self.assertEqual(0, code)
        result = json.loads(output)
        self.assertEqual("PUBLIC", result["marker"])
        self.assertEqual(0, result["stdinBytes"])
        self.assertEqual(2, len(self.peer.events()))
        self.assertTrue(all(e["commandBytes"] <= 60000 for e in self.peer.events()))

    def test_synchronous_owner_runner_is_called_once_after_automatic_staging(self):
        _, transport = self.implementation()
        argv = self.argv(transport, long_command(exitcode=23))
        calls = []
        def runner(submitted, **kwargs):
            calls.append({"peerEventsBeforeExecute": len(self.peer.events()), "argv": submitted})
            return subprocess.run(submitted, **kwargs)
        payload = b"PUBLIC synchronous input\x00"
        with self.peer.environment():
            result = transport.run_ssh(argv, runner=runner, input=payload,
                                       capture_output=True, timeout=10)
        self.assertEqual(1, len(calls))
        self.assertEqual(1, calls[0]["peerEventsBeforeExecute"])
        self.assertEqual(23, result.returncode)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), json.loads(result.stdout)["stdinSha256"])
        self.assertEqual(2, len(self.peer.events()))

    def test_receipt_actual_principal_cannot_replace_configured_target_user(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        self.peer.hosts["explicit-peer"]["user"] = "different-user"
        self.peer.write_config()
        argv = self.argv(transport)
        with self.peer.environment(), self.assertRaises(automatic.AutomaticProgramError):
            with automatic.automatic_submission(argv):
                self.fail("Mismatched actual principal submitted program")
        self.assertEqual(1, len(self.peer.events()))
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "unknown.json").is_file())
        self.assertTrue((local / "stage.stdout").is_file())
        self.assertFalse((local / "execution-intent.json").exists())
        remote = self.peer.peer / ("vpn-control-auto-" + argv.correlation)
        self.assertFalse((remote / "execution-intent.json").exists())

    def test_popen_unread_pipes_cannot_finish_as_verified(self):
        _, transport = self.implementation()
        argv = self.argv(transport)
        with self.peer.environment():
            process = transport.popen_ssh(argv, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait(timeout=10)
            with self.assertRaises(ValueError):
                transport.finish_ssh(process)
            process.stdout.close()
            process.stderr.close()
            transport.finish_ssh(process, failed=True)
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "unknown.json").is_file())
        self.assertFalse((local / "submission-returned.json").exists())

    def test_popen_owner_preserves_original_input_exit_and_nonreplay(self):
        _, transport = self.implementation()
        argv = self.argv(transport, long_command(exitcode=23))
        payload = b"PUBLIC pipe input\x00\xff" * 9000
        with self.peer.environment():
            process = transport.popen_ssh(argv, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate(payload, timeout=10)
            local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
            self.assertFalse((local / "submission-returned.json").exists())
            transport.finish_ssh(process)
        self.assertEqual(23, process.returncode)
        self.assertEqual(b"", stderr)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), json.loads(stdout)["stdinSha256"])
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "execution-intent.json").is_file())
        count = len(self.peer.events())
        with self.peer.environment(), self.assertRaises((FileExistsError, ValueError)):
            transport.popen_ssh(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(count, len(self.peer.events()))

    def test_popen_timeout_is_not_retried_or_restaged(self):
        _, transport = self.implementation()
        command = long_command()
        command = (*command[:4], "import time;time.sleep(2);" + command[4], *command[5:])
        argv = self.argv(transport, command)
        with self.peer.environment():
            process = transport.popen_ssh(argv, stdin=subprocess.PIPE,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.communicate(b"PUBLIC", timeout=.15)
                count = len(self.peer.events())
                with self.assertRaises((FileExistsError, ValueError)):
                    transport.popen_ssh(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(count, len(self.peer.events()))
            finally:
                process.kill()
                process.communicate(timeout=5)
                transport.finish_ssh(process, failed=True)
        self.assertEqual(2, len(self.peer.events()))
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "execution-intent.json").is_file())
        self.assertTrue((local / "unknown.json").is_file())
        self.assertFalse((local / "submission-returned.json").exists())

    @contextmanager
    def copied_transport_bundle(self, *, custody_symlink=False, before_custody=False):
        directory = self.root / ("physical-module-bundle-" + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)
        for name in ("ssh_transport.py", "ssh_automatic_program.py", "private_config_custody.py", "native_review_source_closure.py", "readiness.py", "private_inventory_lock.py"):
            shutil.copyfile(TOOLS / name, directory / name)
        if before_custody:
            preserved = FIXTURE / "custody_preexec.before.source"
            manifest = json.loads((FIXTURE / "provenance.json").read_bytes())
            expected = manifest["beforeimages"]["ssh_automatic_program.py.custody-preexec"]["sha256"]
            if hashlib.sha256(preserved.read_bytes()).hexdigest() != expected:
                raise AssertionError("Preserved custody preexec source changed")
            (directory / "ssh_automatic_program.py").write_bytes(preserved.read_bytes())
        if custody_symlink:
            source = directory / "native_review_source_closure.py"
            target = directory / "physical-custody-target.py"
            target.write_bytes(source.read_bytes() + ("\nfrom pathlib import Path\nPath(" +
                repr(str(directory / "custody-executed")) + ").write_text('PUBLIC_UNTRUSTED_CUSTODY')\n").encode())
            source.unlink()
            source.symlink_to(target)
        package_name = "_physical_automatic_bundle_" + uuid.uuid4().hex
        package = types.ModuleType(package_name)
        package.__path__ = [str(directory)]
        sys.modules[package_name] = package
        try:
            transport = importlib.import_module(package_name + ".ssh_transport")
            automatic = importlib.import_module(package_name + ".ssh_automatic_program")
            yield transport, automatic
        finally:
            for name in list(sys.modules):
                if name == package_name or name.startswith(package_name + "."):
                    sys.modules.pop(name, None)

    def test_symlink_custody_source_refuses_before_top_level_source_execution(self):
        with self.copied_transport_bundle(custody_symlink=True, before_custody=self.custody_before) as (transport, automatic):
            marker = Path(automatic.__file__).parent / "custody-executed"
            with self.peer.environment(), self.assertRaises((ValueError, OSError)):
                argv = self.argv(transport)
                with automatic.automatic_submission(argv):
                    self.fail("Symlink custody source admitted")
            self.assertFalse(marker.exists(), "Unadmitted custody source executed before nofollow validation")
        self.assertFalse(self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_preserved_custody_beforeimage_executes_symlink_source_before_refusal(self):
        with mock.patch.object(self, "custody_before", True), self.assertRaises(AssertionError):
            self.test_symlink_custody_source_refuses_before_top_level_source_execution()
        markers = list(self.root.glob("physical-module-bundle-*/custody-executed"))
        self.assertEqual(1, len(markers))
        self.assertEqual("PUBLIC_UNTRUSTED_CUSTODY", markers[0].read_text())
        self.assertFalse(self.peer.events())

    def test_transitive_custody_ignores_stale_module_and_timestamp_valid_pyc(self):
        for timestamp_pyc in (False, True):
            with self.subTest(timestamp_pyc=timestamp_pyc), self.copied_transport_bundle() as (transport, automatic):
                source = Path(automatic.__file__).with_name("native_review_source_closure.py")
                actual = source.read_bytes()
                marker = source.parent / "untrusted-cache-used"
                old = ("from pathlib import Path\n"
                       "class _Held:\n"
                       " def __init__(self):\n"
                       "  Path(" + repr(str(marker)) + ").write_text('PUBLIC_STALE_CUSTODY')\n"
                       "  raise RuntimeError('PUBLIC_STALE_CUSTODY')\n").encode()
                name = transport.__package__ + ".native_review_source_closure"
                if timestamp_pyc:
                    gap = len(actual) - len(old)
                    self.assertGreaterEqual(gap, 2)
                    source.write_bytes(old + b"\n#" + b"X" * (gap - 2))
                    stamp = source.stat()
                    py_compile.compile(str(source), doraise=True,
                        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                    source.write_bytes(actual)
                    os.utime(source, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
                    spec = importlib.util.spec_from_file_location(name, source)
                    stale_code = spec.loader.get_code(name)
                    self.assertNotEqual(compile(actual, str(source), "exec"), stale_code)
                    sys.modules.pop(name, None)
                    package = sys.modules[transport.__package__]
                    if hasattr(package, "native_review_source_closure"):
                        delattr(package, "native_review_source_closure")
                    context = nullcontext()
                else:
                    stale = types.ModuleType(name)
                    stale.__file__ = str(source)
                    exec(compile(old, str(source), "exec"), stale.__dict__)
                    context = mock.patch.dict(sys.modules, {name: stale})
                with context, self.peer.environment():
                    argv = self.argv(transport)
                    with automatic.automatic_submission(argv) as submitted:
                        result = self.execute(submitted)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("PUBLIC", json.loads(result.stdout)["marker"])
                self.assertFalse(marker.exists())
                self.assertEqual(actual, source.read_bytes())

    def test_popen_exited_child_keeps_source_custody_until_collector_finishes(self):
        with self.copied_transport_bundle() as (transport, automatic), self.peer.environment():
            copied_source = Path(automatic.__file__)
            argv = self.argv(transport)
            process = transport.popen_ssh(argv, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.wait(timeout=10)
            local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
            self.assertFalse((local / "submission-returned.json").exists())
            copied_source.write_bytes(copied_source.read_bytes() + b"# exchanged before pipe capture\n")
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual("PUBLIC", json.loads(stdout)["marker"])
            with self.assertRaises(ValueError):
                transport.finish_ssh(process)
        self.assertTrue((local / "unknown.json").is_file())
        self.assertFalse((local / "submission-returned.json").exists())

    def test_held_source_exchange_during_program_marks_closing_unknown(self):
        with self.copied_transport_bundle() as (transport, automatic):
            copied_source = Path(automatic.__file__)
            argv = self.argv(transport)
            with self.peer.environment(), self.assertRaises(ValueError):
                with automatic.automatic_submission(argv) as submitted:
                    result = self.execute(submitted)
                    self.assertEqual(0, result.returncode, result.stderr)
                    copied_source.write_bytes(copied_source.read_bytes() + b"# changed after native result\n")
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "unknown.json").is_file())
        self.assertFalse((local / "submission-returned.json").exists())

    def test_config_change_before_submit_is_detected_without_peer_contact(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        self.peer.hosts["explicit-peer"]["port"] = 2229
        self.peer.write_config()
        with self.peer.environment(), self.assertRaises((automatic.AutomaticProgramError, ValueError)):
            with automatic.automatic_submission(argv):
                self.fail("Changed configuration submitted")
        self.assertFalse(self.peer.events())

    def test_config_change_during_program_marks_closing_unknown(self):
        _, transport = self.implementation()
        automatic = self.automatic()
        argv = self.argv(transport)
        with self.peer.environment(), self.assertRaises((automatic.AutomaticProgramError, ValueError)):
            with automatic.automatic_submission(argv) as submitted:
                result = self.execute(submitted)
                self.assertEqual(0, result.returncode, result.stderr)
                self.peer.hosts["explicit-peer"]["port"] = 2229
                self.peer.write_config()
        local = self.root / ".rag_index/ssh-automatic-program" / argv.correlation
        self.assertTrue((local / "unknown.json").is_file())
        self.assertFalse((local / "submission-returned.json").exists())

    def test_nested_configured_route_stages_and_executes_at_destination(self):
        _, transport = self.implementation()
        outer = self.peer.hosts["explicit-peer"]
        self.peer.hosts = {"relay": outer, "explicit-peer": {
            **outer, "transport": "nested", "gateway": "relay",
            "remoteHostAlias": "explicit-destination", "remoteConfigFile": "/owned/explicit.conf",
        }}
        self.peer.write_config()
        argv = self.argv(transport)
        with self.peer.environment(), self.automatic().automatic_submission(argv) as submitted:
            result = self.execute(submitted)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("PUBLIC", json.loads(result.stdout)["marker"])
        events = self.peer.events()
        self.assertEqual(["192.0.2.72", "explicit-destination"] * 2, [e["endpoint"] for e in events])
        self.assertTrue(all(e["commandBytes"] <= 60000 for e in events))

    def test_preserved_beforeimage_demonstrates_real_bound_failure(self):
        value, payload = self.exercise_shared_owner(before=True)
        with self.assertRaises(AssertionError):
            self.assert_shared_owner_works(value, payload)
        self.assertEqual(91, value["exitCode"], value)
        self.assertEqual(1, len(value["events"]), value)
        self.assertGreater(value["events"][0]["commandBytes"], 60000, value)


if __name__ == "__main__":
    unittest.main()
