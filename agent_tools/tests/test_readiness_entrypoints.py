"""Exercise direct caller admission and per-input checks over real sockets."""
from dataclasses import replace
import importlib.util
import hashlib
from importlib.machinery import SourceFileLoader
import json
import math
import os
from pathlib import Path
import socket
import socketserver
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import UUID, uuid4

from agent_tools import readiness
from agent_tools import readiness_entrypoints as entry
from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_leases as leases
from agent_tools.tests.test_readiness import Provider, SocketAdapter

ROOT = Path(__file__).resolve().parents[2]


def before_source(name):
    directory = Path(__file__).parent/'fixtures/direct_entrypoint_admission'
    path = directory/name
    expected = json.loads((directory/'provenance.json').read_bytes())['beforeimages'][name]
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise AssertionError('preserved causal beforeimage changed')
    return path


def target_before_source(name):
    directory = Path(__file__).parent/'fixtures/direct_explicit_target'
    path = directory/name
    expected = json.loads((directory/'provenance.json').read_bytes())[name]['sha256']
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise AssertionError('preserved explicit-target beforeimage changed')
    return path


def macos_module():
    path = Path(os.environ.get("VPN_CONTROL_MACOS_SOURCE_UNDER_TEST", ROOT / "scripts/capture_visual_macos_tart.py"))
    specification = importlib.util.spec_from_loader("controlled_macos_capture", SourceFileLoader("controlled_macos_capture", str(path)))
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class QmpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'{"QMP":{"version":{}}}\n'); self.wfile.flush()
        while line := self.rfile.readline():
            request = json.loads(line)
            self.server.requests.append(request)
            if request["execute"] == "human-monitor-command":
                self.server.inputs.append(request["arguments"]["command-line"])
                if self.server.change_after_input:
                    self.server.change_after_input()
            self.wfile.write(b'{"return":{}}\n'); self.wfile.flush()


# This complete caller loads the actual production script, substitutes only the
# controlled private fixture factory and runs its real argparse/QMP path. All
# observations, recoveries and GUI input use real Unix sockets.
CALLER = r'''
import importlib.util,json,os,sys
from pathlib import Path
from types import SimpleNamespace
from agent_tools import readiness,readiness_entrypoints as entry
from agent_tools.tests.test_readiness import SocketAdapter
root,source,provider,qmp,journal=sys.argv[1:]
context=readiness.Context("fixture","machine-a",SocketAdapter(provider),readiness.RecoveryJournal(Path(journal)))
fixture=SimpleNamespace(context=lambda:context)
entry.fixtures.registered_fixture=lambda *_:fixture
entry.fixtures.dispatch_binding=lambda *args:{"qmpSocket":qmp}
target='qemu:'+str(Path(qmp).with_name('disk.img'))
entry.fixtures.explicit_target=lambda *args:target
entry._registration_pin=lambda *args:{"generation":[1],"sha256":"fixture-pin"}
from agent_tools.tests.test_readiness_entrypoints import controlled_lease_workflow
entry.gui_leases.workflow.workflow=controlled_lease_workflow(Path(journal))
original_from_environment=entry.from_environment
entry.from_environment=lambda *args,**kwargs:original_from_environment(*args,lease_ttl_seconds=5,**kwargs)
os.environ["VPN_CONTROL_READINESS_FIXTURE_ID"]="controlled-fixture"
spec=importlib.util.spec_from_file_location("controlled_direct_caller",source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.ROOT=Path(root);module.QMP_SOCKET=Path(qmp)
sys.argv=[source,"--send-key","a","--send-key","b","--key-delay","0"]
if '--target' in Path(source).read_text() and os.environ.get('ENTRY_NO_TARGET')!='1':
    sys.argv += ['--target',os.environ.get('ENTRY_TARGET_OVERRIDE',target)]
try:
    code=module.main()
    print(json.dumps({"result":"dispatched","code":code}))
except readiness.ReadinessBlocked as error:
    print(json.dumps({"result":"blocked","reason":error.reason}))
except SystemExit as error:
    print(json.dumps({"result":"blocked","reason":"explicit_target_required","code":error.code}))
'''


SHELL_CLI = r'''
import json,os,sys
from pathlib import Path
from types import SimpleNamespace
from agent_tools import readiness,readiness_entrypoints as entry
from agent_tools.tests.test_readiness import SocketAdapter
root=Path(os.environ["ENTRY_FIXTURE_ROOT"])
context=readiness.Context("fixture","machine-a",SocketAdapter(root/"provider.sock"),readiness.RecoveryJournal(root))
fixture=SimpleNamespace(context=lambda:context)
entry.fixtures.registered_fixture=lambda *_:fixture
entry.fixtures.dispatch_binding=lambda *args:json.loads(os.environ["ENTRY_FIXTURE_BINDING"])
entry.fixtures.explicit_target=lambda *args:'android:'+json.loads(os.environ['ENTRY_FIXTURE_BINDING'])['avd']
entry._registration_pin=lambda *args:{"generation":[1],"sha256":"controlled-fixture-pin"}
from agent_tools.tests.test_readiness_entrypoints import controlled_lease_workflow
entry.gui_leases.workflow.workflow=controlled_lease_workflow(root)
args=sys.argv[1:]
if args[0]=='admit':
    ttl=os.environ.get('ENTRY_CAPTURE_LEASE_TTL','5')
    if not ttl.isascii() or not ttl.isdecimal() or not 1<=int(ttl)<=30:raise SystemExit('controlled lease TTL invalid')
    args += ['--lease-ttl-seconds',ttl]
if args[0]=='admit' and '--target'not in args:args+=['--target','android:'+json.loads(os.environ['ENTRY_FIXTURE_BINDING'])['avd']]
raise SystemExit(entry.main(args,root=root))
'''


def controlled_lease_workflow(root):
    """The fixture executor uses the actual durable owner/settings protocol."""
    root = Path(root).resolve(strict=True)
    state = root / "controlled-lease-jobs"
    state.mkdir(mode=0o700, exist_ok=True)
    setting = root / "controlled-lease-setting"
    try:
        descriptor = os.open(setting, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        pass
    else:
        os.write(descriptor, b"sleep"); os.close(descriptor)
    binding = jobs.current_binding("controlled-gui-lease", "controlled-setting")
    generation = jobs.root_generation(state)
    def call(_root, action, inputs, *, deadline=None):
        if deadline is not None:
            if type(deadline) not in (int, float) or not math.isfinite(deadline):
                raise AssertionError("controlled caller deadline invalid")
            if deadline <= time.monotonic():
                raise TimeoutError("controlled caller deadline expired")
        operation = inputs["operationId"]
        if action == "acquire":
            return leases._acquire_controlled(state, operation, binding, setting, inputs["ttlSeconds"], generation=generation)
        if action == "cancel":
            leases.cancel(state, operation, binding, generation=generation)
        return leases.inspect(state, operation, binding, generation=generation)
    return call


def finish_controlled_leases(root):
    state = Path(root).resolve(strict=True) / "controlled-lease-jobs"
    if not state.exists():
        return
    binding = jobs.current_binding("controlled-gui-lease", "controlled-setting")
    generation = jobs.root_generation(state)
    for directory in state.iterdir():
        if not directory.is_dir():
            continue
        try:
            operation = str(UUID(directory.name))
        except ValueError:
            continue
        leases.cancel(state, operation, binding, generation=generation)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if jobs.observe(state, operation, binding, generation=generation)["state"] in {"terminal", "unsubmitted"}:
                break
            time.sleep(.02)
        else:
            raise AssertionError("original controlled GUI lease owner did not close")


def run_qualified_android_capture(command, *, cwd, env, provider_setup=None, provider_assert=None, **kwargs):
    """Existing shell scenarios use the real guard against a controlled provider.

    The test seam selects only its private fixture factory. The production CLI,
    durable admission, revalidation and actual shell/ADB executable calls run
    unchanged. It does not qualify a native emulator.
    """
    target = env.get("VPN_CONTROL_VISUAL_VM_TARGET")
    if type(target) is not str or not target.startswith("android:") or not target[8:]:
        raise ValueError("controlled Android caller requires an explicit target")
    private_avd = env.get("VPN_CONTROL_VISUAL_ANDROID_AVD_NAME", target[8:])
    with tempfile.TemporaryDirectory(prefix="shell-entry-") as temporary:
        root = Path(temporary).resolve(strict=True)
        server = Provider(root / "provider.sock")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        try:
            if provider_setup is not None:
                provider_setup(server)
            original_python = shutil.which("python3", path=env["PATH"])
            adb = shutil.which("adb", path=env["PATH"])
            assert original_python and adb
            driver = root / "cli.py"; driver.write_text(SHELL_CLI)
            wrapper = root / "python3"
            wrapper.write_text("#!" + sys.executable + "\n" +
                "import os,sys\n" +
                "if sys.argv[1:3]==['-m','agent_tools.readiness_entrypoints']:\n" +
                " os.execv(" + repr(sys.executable) + ", [" + repr(sys.executable) + "," + repr(str(driver)) + ",*sys.argv[3:]])\n" +
                "os.execv(" + repr(original_python) + ",[" + repr(original_python) + ",*sys.argv[1:]])\n")
            wrapper.chmod(0o700)
            environment = dict(env)
            environment.update({"PATH": str(root) + os.pathsep + env["PATH"],
                                "PYTHONPATH": str(ROOT) + os.pathsep + env.get("PYTHONPATH", ""),
                                "ENTRY_FIXTURE_ROOT": str(root),
                                "VPN_CONTROL_READINESS_FIXTURE_ID": "controlled-shell-fixture",
                                "VPN_CONTROL_READINESS_OPERATION_ID": str(uuid4()),
                                "ENTRY_FIXTURE_BINDING": json.dumps({"adb": adb, "serial": "emulator-" + env.get("VPN_CONTROL_VISUAL_ANDROID_PORT", "5600"),
                                    "avd": private_avd, "serverPort": 5037})})
            result = subprocess.run(command, cwd=cwd, env=environment, **kwargs)
            if provider_assert is not None:
                provider_assert(server)
            return result
        finally:
            finish_controlled_leases(root)
            server.shutdown(); server.server_close(); thread.join(2)


@unittest.skipUnless(os.name == "posix", "private journals and native fixture sockets")
class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="entry-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve(strict=True)
        self.provider = Provider(self.root / "provider.sock")
        self.qmp = socketserver.ThreadingUnixStreamServer(str(self.root / "qmp.sock"), QmpHandler)
        self.qmp.daemon_threads = True
        self.qmp.requests = []; self.qmp.inputs = []; self.qmp.change_after_input = None
        self.threads = []
        for server in (self.provider, self.qmp):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
            thread.start(); self.threads.append(thread)
        self.addCleanup(self.close)
        self.context = readiness.Context("fixture", "machine-a", SocketAdapter(self.root / "provider.sock"),
                                         readiness.RecoveryJournal(self.root))
        self.fixture = SimpleNamespace(context=lambda: self.context)
        self.binding = {"qmpSocket": str(self.root / "qmp.sock")}
        self.registered = mock.patch.object(entry.fixtures, "registered_fixture", return_value=self.fixture)
        self.dispatch = mock.patch.object(entry.fixtures, "dispatch_binding", return_value=self.binding)
        self.target_selector = "qemu:" + str(self.root / "disk.img")
        self.target_patch = mock.patch.object(entry.fixtures, "explicit_target", return_value=self.target_selector)
        self.target = self.target_patch.start(); self.addCleanup(self.target_patch.stop)
        self.pin = mock.patch.object(entry, "_registration_pin", return_value={"generation": [1], "sha256": "fixture-pin"})
        self.registered.start(); self.dispatch.start()
        self.pin.start(); self.addCleanup(self.pin.stop)
        self.lease = mock.patch.object(entry.gui_leases.workflow, "workflow", side_effect=controlled_lease_workflow(self.root))
        self.lease.start(); self.addCleanup(self.lease.stop)
        self.addCleanup(finish_controlled_leases, self.root)
        self.addCleanup(self.registered.stop); self.addCleanup(self.dispatch.stop)

    def close(self):
        for server in (self.provider, self.qmp):
            server.shutdown(); server.server_close()
        for thread in self.threads:
            thread.join(2)

    def admit(self, **kwargs):
        kwargs.setdefault("lease_ttl_seconds", 5)
        return entry.admit(self.root, "capture_visual_windows_qemu", "input", fixture_id="fixture-a", **kwargs)

    def caller(self, source=None):
        selected = Path(os.environ.get("VPN_CONTROL_DIRECT_SOURCE_UNDER_TEST", source or ROOT / "scripts/capture_visual_windows_qemu.py"))
        # The caller admits under the script ROOT it is given; a controlled
        # fixture must never leave lease records in the checkout running this test.
        checkout = ROOT / ".rag_index/readiness-gui-leases"
        retained = sorted(os.listdir(checkout)) if checkout.is_dir() else None
        done = subprocess.run([sys.executable, "-c", CALLER, str(self.root), str(selected), str(self.root / "provider.sock"),
                               str(self.root / "qmp.sock"), str(self.root)], cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertEqual(0, done.returncode, done.stderr)
        self.assertEqual(retained, sorted(os.listdir(checkout)) if checkout.is_dir() else None)
        return json.loads(done.stdout.splitlines()[-1])

    def test_healthy_actual_direct_caller_dispatches_once_without_recovery(self):
        result = self.caller()
        self.assertEqual("dispatched", result["result"])
        self.assertEqual(["sendkey a", "sendkey b"], self.qmp.inputs)
        self.assertEqual([], self.provider.effects)

    def test_complete_driver_missing_target_original_red_current_green(self):
        before = target_before_source('capture_visual_windows_qemu.py.before.source')
        previous = self.root/'before-explicit-target.py'; previous.write_bytes(before.read_bytes())
        with mock.patch.dict(os.environ, {'ENTRY_NO_TARGET':'1'}):
            self.assertEqual('dispatched', self.caller(source=previous)['result'])
            self.qmp.inputs.clear();self.qmp.requests.clear()
            result = self.caller()
        self.assertEqual('explicit_target_required', result['reason'])
        self.assertEqual([], self.qmp.inputs);self.assertEqual([], self.qmp.requests)
        self.assertEqual([], self.provider.effects)

    def test_actual_android_shell_missing_target_precedes_any_default_configuration_lookup(self):
        repository=self.root/'missing-selector';scripts=repository/'scripts';scripts.mkdir(parents=True)
        client=repository/'python3';log=repository/'default-configuration.log'
        client.write_text('#!/bin/sh\nprintf called >> "$ENTRY_CONFIG_LOOKUP_LOG"\nexit 99\n');client.chmod(0o700)
        environment=dict(os.environ,PATH=str(repository)+os.pathsep+os.environ['PATH'],ENTRY_CONFIG_LOOKUP_LOG=str(log))
        environment.pop('VPN_CONTROL_VISUAL_VM_TARGET',None)
        path=scripts/'capture_visual_android.sh'
        path.write_bytes(target_before_source('capture_visual_android.sh.before.source').read_bytes())
        before=subprocess.run(['bash',str(path)],env=environment,capture_output=True,text=True,timeout=5)
        self.assertNotEqual(0,before.returncode);self.assertTrue(log.exists())
        log.unlink();path.write_bytes((ROOT/'scripts/capture_visual_android.sh').read_bytes())
        fixed=subprocess.run(['bash',str(path)],env=environment,capture_output=True,text=True,timeout=5)
        self.assertEqual(2,fixed.returncode);self.assertIn('explicit --target',fixed.stderr)
        self.assertFalse(log.exists())

    def test_complete_wrong_target_blocks_before_sleep_recovery_or_qmp(self):
        self.provider.observation = replace(self.provider.observation, display='sleeping')
        with mock.patch.dict(os.environ, {'ENTRY_TARGET_OVERRIDE':'qemu:/controlled/wrong-disk'}):
            result = self.caller()
        self.assertEqual('fixture_entrypoint_target_mismatch', result['reason'])
        self.assertEqual([], self.provider.effects);self.assertEqual([], self.qmp.inputs);self.assertEqual([], self.qmp.requests)

    def test_original_target_is_persisted_and_rechecked_before_each_dispatch(self):
        admitted = self.admit(expected_target=self.target_selector)
        try:
            entry.persist(admitted)
            receipt = json.loads((self.root/'.rag_index/readiness-entrypoints'/(admitted.operation_identity+'.json')).read_text())
            self.assertEqual(self.target_selector,receipt['expectedTarget'])
            self.target.return_value='qemu:/controlled/new-disk'
            called=[]
            with self.assertRaisesRegex(entry.EntrypointBlocked,'fixture_entrypoint_target_mismatch'):
                admitted.dispatch(lambda:called.append(True))
            self.assertEqual([],called);self.assertEqual([],self.provider.effects)
        finally:admitted.close()

    def test_socket_only_qmp_and_pure_observer_target_never_gain_recovery_authority(self):
        self.target.side_effect=ValueError('private endpoint proof unavailable')
        with self.assertRaisesRegex(entry.EntrypointBlocked,'fixture_target_authority_unavailable'):
            self.admit(expected_target=self.target_selector)
        self.target.side_effect=None
        with mock.patch.object(self.fixture,'context',side_effect=AssertionError('observer cannot initialize readiness')), \
             mock.patch.object(entry.readiness,'ensure_ready',side_effect=AssertionError('no recovery')):
            self.assertEqual(self.binding,entry.bound_target(self.root,'capture_visual_windows_qemu',self.target_selector,fixture_id='fixture-a'))
        self.assertEqual([],self.provider.effects)

    def test_actual_direct_caller_restores_sleep_before_input(self):
        self.provider.observation = replace(self.provider.observation, display="sleeping")
        result = self.caller()
        self.assertEqual("dispatched", result["result"])
        self.assertEqual(["wake_display"], [effect[0] for effect in self.provider.effects])
        self.assertEqual(2, len(self.qmp.inputs))

    def test_actual_direct_caller_refuses_wrong_account_without_input(self):
        self.provider.observation = replace(self.provider.observation, ordinary_session="wrong_account")
        original = self.root/'before_windows.py'
        original.write_bytes(before_source('capture_visual_windows_qemu.before.source').read_bytes())
        self.assertEqual('dispatched', self.caller(source=original)['result'])
        self.assertEqual(['sendkey a','sendkey b'], self.qmp.inputs)
        self.qmp.inputs.clear()
        result = self.caller()
        self.assertEqual("blocked", result["result"])
        self.assertEqual("wrong_account", result["reason"])
        self.assertEqual([], self.qmp.inputs)
        self.assertEqual([], self.provider.effects)

    def test_actual_direct_caller_boot_change_after_first_key_does_not_send_second(self):
        self.qmp.change_after_input = lambda: setattr(self.provider, "observation", replace(self.provider.observation, boot="boot-b"))
        result = self.caller()
        self.assertEqual("blocked", result["result"])
        self.assertEqual("prepared_context_stale", result["reason"])
        self.assertEqual(["sendkey a"], self.qmp.inputs)
        self.assertEqual([], self.provider.effects)

    def test_endpoint_mismatch_precedes_observation_and_recovery(self):
        self.provider.observation = replace(self.provider.observation, display="sleeping")
        with self.assertRaisesRegex(entry.EntrypointBlocked, "fixture_entrypoint_mismatch"):
            self.admit(expected_binding={"qmpSocket": "/unrelated/qmp.sock"})
        self.assertEqual(0, self.provider.observe_calls)
        self.assertEqual([], self.provider.effects)

    def test_local_probe_and_intentional_stop_never_resolve_or_probe_fixture(self):
        for surface, action in (("capture_visual_windows_qemu", "probe"), ("visual_platform", "stop")):
            with mock.patch.object(entry.fixtures, "registered_fixture", side_effect=AssertionError("must stay local")):
                admitted = entry.admit(self.root, surface, action)
                admitted.revalidate()
                self.assertEqual({}, dict(admitted.binding))
        self.assertEqual(0, self.provider.observe_calls)
        self.assertEqual([], self.provider.effects)

    def test_unqualified_legacy_profile_does_not_submit_or_recover(self):
        with self.assertRaisesRegex(entry.EntrypointBlocked, "fixture_entrypoint_unqualified"):
            entry.admit(self.root, "capture_visual_windows_qemu", "input")
        self.assertEqual(0, self.provider.observe_calls)

    def test_packet_is_generated_after_recovery_and_stale_packet_is_not_submitted(self):
        self.provider.observation = replace(self.provider.observation, display="sleeping")
        admitted = self.admit()
        packets = []
        def build(binding):
            self.assertEqual("ready", self.provider.observation.display)
            self.provider.observation = replace(self.provider.observation, session="session-b")
            return [binding["qmpSocket"], "payload"]
        with self.assertRaisesRegex(readiness.ReadinessBlocked, "prepared_context_stale"):
            admitted.run(build, packets.append)
        self.assertEqual([], packets)
        self.assertEqual(["wake_display"], [effect[0] for effect in self.provider.effects])

    def test_private_factory_exception_does_not_disclose_private_input(self):
        secret = "PRIVATE-INPUT-DO-NOT-DISCLOSE"
        with mock.patch.object(entry.fixtures, "registered_fixture", side_effect=ValueError(secret)):
            with self.assertRaises(entry.EntrypointBlocked) as error:
                self.admit()
        self.assertNotIn(secret, str(error.exception.as_dict()))

    def test_fresh_process_style_receipt_reopen_preserves_original_session_and_never_recovers(self):
        admitted = self.admit()
        result = entry.persist(admitted)
        self.assertEqual(dict(admitted.binding), result["binding"])
        self.assertEqual(result, entry.check_persisted(self.root, admitted.operation_identity))
        self.provider.observation = replace(self.provider.observation, ordinary_session="locked")
        with self.assertRaises(readiness.ReadinessBlocked):
            entry.check_persisted(self.root, admitted.operation_identity)
        self.assertEqual([], self.provider.effects)
        self.assertEqual("locked", self.provider.observation.ordinary_session)

    def test_receipt_never_overwrites_original_and_rejects_registration_replacement(self):
        admitted = self.admit()
        entry.persist(admitted)
        with self.assertRaises(FileExistsError):
            entry.persist(admitted)
        with mock.patch.object(entry, "_registration_pin", return_value={"generation": [2], "sha256": "fixture-pin"}):
            with self.assertRaisesRegex(entry.EntrypointBlocked, "fixture_entrypoint_changed"):
                entry.check_persisted(self.root, admitted.operation_identity)
        self.assertEqual([], self.provider.effects)

    def test_receipt_source_change_and_symlink_cannot_dispatch(self):
        admitted = self.admit(); entry.persist(admitted)
        with mock.patch.object(entry, "_source_pins", return_value={"changed": True}):
            with self.assertRaisesRegex(entry.EntrypointBlocked, "entrypoint_source_changed"):
                entry.check_persisted(self.root, admitted.operation_identity)
        path = self.root / ".rag_index/readiness-entrypoints" / (admitted.operation_identity + ".json")
        original = path.with_suffix(".original"); path.rename(original); path.symlink_to(original)
        with self.assertRaisesRegex(entry.EntrypointBlocked, "entrypoint_receipt_invalid"):
            entry.check_persisted(self.root, admitted.operation_identity)

    def test_complete_android_shell_refuses_wrong_account_before_adb(self):
        repository = self.root / "mini-repo"
        scripts = repository / "scripts"; scripts.mkdir(parents=True)
        (repository / "visual-tests").mkdir()
        (repository / "visual-tests/scenes.json").write_text('{"scenes":[]}')
        source = Path(os.environ.get("VPN_CONTROL_ANDROID_SOURCE_UNDER_TEST", ROOT / "scripts/capture_visual_android.sh"))
        shutil.copy2(source, scripts / "capture_visual_android.sh")
        shutil.copy2(ROOT / "scripts/select_visual_scenes.py", scripts / "select_visual_scenes.py")
        shutil.copy2(ROOT / "scripts/android_visual_geometry.py", scripts / "android_visual_geometry.py")
        (scripts / "visual_platform.py").write_text(
            "import json,sys\n"
            "if sys.argv[1]=='android-local-config': print(json.dumps({'result':{'avd_name':'controlled-avd','emulator_port':5600}}))\n")
        adb = repository / "adb"
        log = repository / "adb.log"
        adb.write_text("#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$ADB_LOG\"\n"
            "if [ \"$3 $4 $5\" = 'emu avd name' ]; then printf 'controlled-avd\\nOK\\n'; fi\n"
            "if [ \"$3 $4 $5 $6\" = 'shell dumpsys window displays' ]; then cat <<'DUMP'\n"
            "displayId=0\n  mDisplayFrame=Rect(0, 0 - 1080, 2400)\n"
            "  mDisplayCutout=DisplayCutout{insets=Rect(0, 63 - 0, 0)}\n"
            "    InsetsSource id=1 type=statusBars frame=[0,0][1080,63] visible=true flags= sideHint=TOP\nDUMP\nfi\n")
        adb.chmod(0o700)
        environment = {**os.environ, "PATH": str(repository) + os.pathsep + os.environ["PATH"],
                       "ADB_LOG": str(log), "VPN_CONTROL_VISUAL_PROVIDER": "local",
                       "VPN_CONTROL_VISUAL_ANDROID_AVD_NAME": "controlled-avd", "VPN_CONTROL_VISUAL_ANDROID_PORT": "5600",
                       "VPN_CONTROL_VISUAL_VM_TARGET": "android:controlled-avd",
                       "VPN_CONTROL_VISUAL_TARGET_SHA": "a" * 40}
        current = (scripts/'capture_visual_android.sh').read_bytes()
        (scripts/'capture_visual_android.sh').write_bytes(before_source('capture_visual_android.before.source').read_bytes())
        original = run_qualified_android_capture(["bash", str(scripts / "capture_visual_android.sh"), str(repository / "before-output")],
            cwd=repository, env=environment, capture_output=True, text=True, timeout=15,
            provider_setup=lambda provider: setattr(provider, "observation", replace(provider.observation, ordinary_session="wrong_account")))
        self.assertEqual(0, original.returncode, original.stdout+original.stderr)
        self.assertTrue(log.exists())
        self.assertGreater(len(log.read_text().splitlines()), 0)
        log.unlink()
        (scripts/'capture_visual_android.sh').write_bytes(current)
        result = run_qualified_android_capture(["bash", str(scripts / "capture_visual_android.sh"), str(repository / "output")],
            cwd=repository, env=environment, capture_output=True, text=True, timeout=15,
            provider_setup=lambda provider: setattr(provider, "observation", replace(provider.observation, ordinary_session="wrong_account")))
        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("wrong_account", result.stderr)
        self.assertFalse(log.exists(), log.read_text() if log.exists() else "")

    def test_macos_command_description_does_not_contain_private_credential(self):
        secret = "PRIVATE-VNC-CREDENTIAL-DO-NOT-EMIT"
        with mock.patch.dict(os.environ, {"VPN_CONTROL_VISUAL_MACOS_PASSWORD": secret,
                                         "VPN_CONTROL_MACOS_SOURCE_UNDER_TEST": str(before_source('capture_visual_macos_tart.before.source'))}):
            previous = macos_module()
        with mock.patch.object(previous, "vnc_client", return_value="controlled-vnc"):
            self.assertIn(secret, previous.vnc_command("controlled-address", "key", "esc"))
        with mock.patch.dict(os.environ, {"VPN_CONTROL_VISUAL_MACOS_PASSWORD": secret}):
            module = macos_module()
        with mock.patch.object(module, "vnc_client", return_value="controlled-vnc"):
            command = module.vnc_command("controlled-address", "key", "esc")
        self.assertNotIn(secret, repr(command))
        self.assertNotIn("-p", command)

    def test_missing_private_vnc_executor_blocks_before_input(self):
        module = macos_module()
        self.fixture.adapter = SimpleNamespace(backend=SimpleNamespace())
        with mock.patch.object(entry.fixtures, "dispatch_binding", return_value={"vmName": "controlled-vm"}):
            admitted = entry.admit(self.root, "capture_visual_macos_tart", "run", fixture_id="fixture-a", lease_ttl_seconds=5)
            module._ADMISSION = admitted
            with self.assertRaisesRegex(entry.EntrypointBlocked, "qualified_vnc_executor_unavailable"):
                module.run_vnc_checked("ignored-old-address", "key", "esc")
        self.assertEqual([], self.provider.effects)

    def test_terminal_original_reboot_renews_only_after_actual_new_boot_and_closes_old_context(self):
        recovery_id = str(uuid4())
        calls = []
        def reboot(operation, before):
            calls.append((operation, before.boot))
            self.context.adapter.recover("reboot", recovery_id, self.provider.observation, 1)
            return recovery_id
        def receipt(original):
            self.assertEqual(recovery_id, original)
            actual = self.context.adapter.observe(readiness.Requirements(), 1)
            return {"operationId": admitted.operation_identity, "recoveryId": recovery_id,
                    "target": actual.target, "machine": actual.machine, "oldBoot": "boot-a", "newBoot": actual.boot,
                    "state": "terminal", "result": "rebooted"}
        self.fixture.adapter = SimpleNamespace(backend=SimpleNamespace(idle_reboot=reboot, reboot_receipt=receipt))
        with mock.patch.object(entry.fixtures, "dispatch_binding", return_value={"vmName": "controlled-vm"}):
            admitted = entry.admit(self.root, "capture_visual_macos_tart", "run", fixture_id="fixture-a", lease_ttl_seconds=5)
            renewed = admitted.reboot_guest()
            self.assertEqual("boot-b", renewed.ready.boot)
            renewed.revalidate()
            with self.assertRaisesRegex(entry.EntrypointBlocked, "prepared_context_closed"):
                admitted.revalidate()
        self.assertEqual([(admitted.operation_identity, "boot-a")], calls)
        self.assertEqual([("reboot", recovery_id)], self.provider.effects)

    def test_unknown_reboot_receipt_never_renews_or_submits_another_power_action(self):
        recovery_id = str(uuid4())
        calls = []
        def reboot(operation, before):
            calls.append(operation)
            self.context.adapter.recover("reboot", recovery_id, self.provider.observation, 1)
            return recovery_id
        self.fixture.adapter = SimpleNamespace(backend=SimpleNamespace(idle_reboot=reboot, reboot_receipt=lambda _: {"state": "unknown"}))
        with mock.patch.object(entry.fixtures, "dispatch_binding", return_value={"vmName": "controlled-vm"}):
            admitted = entry.admit(self.root, "capture_visual_macos_tart", "run", fixture_id="fixture-a", lease_ttl_seconds=5)
            with self.assertRaisesRegex(entry.EntrypointBlocked, "direct_power_outcome_unknown"):
                admitted.reboot_guest()
            with self.assertRaises(readiness.ReadinessBlocked):
                admitted.reboot_guest()
        self.assertEqual(1, len(calls))
        self.assertEqual([("reboot", recovery_id)], self.provider.effects)

    def test_changed_reboot_receipt_closes_renewed_lease_without_more_power_or_input(self):
        recovery_id = str(uuid4())
        calls = []
        def reboot(operation, before):
            self.context.adapter.recover('reboot', recovery_id, self.provider.observation, 1)
            return recovery_id
        def receipt(original):
            calls.append(original)
            return {'operationId': admitted.operation_identity, 'recoveryId': recovery_id,
                    'target':'fixture','machine':'machine-a','oldBoot':'boot-a',
                    'newBoot':'boot-b' if len(calls)==1 else 'unexpected-boot',
                    'state':'terminal','result':'rebooted'}
        self.fixture.adapter = SimpleNamespace(backend=SimpleNamespace(idle_reboot=reboot,reboot_receipt=receipt))
        with mock.patch.object(entry.fixtures,'dispatch_binding',return_value={'vmName':'controlled-vm'}):
            admitted = entry.admit(self.root,'capture_visual_macos_tart','run',fixture_id='fixture-a',lease_ttl_seconds=5)
            with self.assertRaisesRegex(entry.EntrypointBlocked,'direct_power_outcome_unknown'):
                admitted.reboot_guest()
        self.assertEqual('sleep',(self.root/'controlled-lease-setting').read_text())
        self.assertEqual([('reboot',recovery_id)],self.provider.effects)
        self.assertEqual([],self.qmp.inputs)

    def test_private_executor_error_is_unknown_without_echo_or_input_replay(self):
        secret = "PRIVATE-EXECUTOR-INPUT"
        calls = []
        def execute(commands, operation, ready, timeout):
            calls.append((commands, operation, ready.boot, timeout))
            raise ConnectionResetError(secret)
        self.fixture.adapter = SimpleNamespace(backend=SimpleNamespace(vnc_action=execute))
        with mock.patch.object(entry.fixtures, "dispatch_binding", return_value={"vmName": "controlled-vm"}):
            admitted = entry.admit(self.root, "capture_visual_macos_tart", "run", fixture_id="fixture-a", lease_ttl_seconds=5)
            with self.assertRaises(entry.EntrypointBlocked) as error:
                admitted.vnc_action(("key", "esc"), timeout=30)
            with self.assertRaisesRegex(entry.EntrypointBlocked, "prepared_context_closed"):
                admitted.vnc_action(("key", "esc"), timeout=30)
        self.assertEqual(1, len(calls))
        self.assertEqual("direct_input_outcome_unknown", error.exception.reason)
        self.assertNotIn(secret, str(error.exception.as_dict()))

    def test_installer_adb_guard_refuses_stale_context_before_any_process_launch(self):
        scripts = str(ROOT / "scripts")
        sys.path.insert(0, scripts)
        try:
            specification = importlib.util.spec_from_file_location("controlled_tls_preflight", ROOT / "scripts/android_no_update_tls_preflight.py")
            module = importlib.util.module_from_spec(specification)
            specification.loader.exec_module(module)
        finally:
            sys.path.pop(0)
        executable = self.root / "adb"
        log = self.root / "adb-inputs.log"
        executable.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + str(log) + "\nprintf sentinel\n")
        executable.chmod(0o700)
        admitted = self.admit()
        adb = module.Adb(str(executable), "controlled", dispatch_guard=admitted.revalidate)
        self.assertEqual("sentinel", adb.run("shell", "printf", "sentinel"))
        self.provider.observation = replace(self.provider.observation, session="session-b")
        for invoke in (adb.run, adb.exec_out_bytes):
            with self.assertRaisesRegex(readiness.ReadinessBlocked, "prepared_context_stale"):
                invoke("shell", "printf", "second")
        self.assertEqual(["-H127.0.0.1 -s controlled shell printf sentinel"], log.read_text().splitlines())
        self.assertEqual([], self.provider.effects)


if __name__ == "__main__":
    unittest.main()
