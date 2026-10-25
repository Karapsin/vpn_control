"""Whole staged Android factories and real controlled callers; no VM effects."""
import hashlib
from dataclasses import replace
import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import types
import unittest
from unittest import mock

from agent_tools import android_installer_component_bundle as bundle
from agent_tools import android_installer_component_adapter as adapter
from agent_tools import readiness, readiness_entrypoints as entry
from agent_tools import ssh_transport
from agent_tools.tests import test_android_installer_component_bundle as component_cases
from agent_tools.tests import test_android_installer_component_adapter as adapter_cases
from agent_tools.tests import test_readiness_entrypoints as entry_cases
from agent_tools.tests import test_android_api35_os_session_projection as os_cases
from agent_tools.tests import test_android_install_recovery_mcp_route as route_cases
from scripts import android_installer_lifecycle as lifecycle
from scripts import android_no_update_tls_preflight as tls

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / 'fixtures/android_component_readiness_closure'


def preserved(name, module_name):
    raw = (FIXTURE / (name + '.before.source')).read_bytes()
    metadata = json.loads((FIXTURE / 'provenance.json').read_bytes())
    original = ('scripts/' if name == 'android_installer_lifecycle.py' else 'agent_tools/') + name
    if hashlib.sha256(raw).hexdigest() != metadata['beforeSha256'][original]:
        raise AssertionError('preserved component source changed')
    module = types.ModuleType(module_name)
    module.__package__ = 'agent_tools' if original.startswith('agent_tools/') else 'scripts'
    module.__file__ = str(FIXTURE / (name + '.before.source'))
    exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return module, raw


@unittest.skipUnless(os.name == 'posix', 'private source descriptors and Unix peers')
class ComponentReadinessClosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)

    def stage(self, factory, label, replacements):
        source = self.root / (label + '-source')
        source.mkdir(mode=0o700)
        for relative in factory.FILES:
            target = source / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = replacements.get(relative)
            factory._write(target, (ROOT / relative).read_bytes() if raw is None else raw)
        return factory.prepare(source, self.root / (label + '-stage'),
                               factory.reviewed_tree(source)['treeSha256'])

    def test_complete_before_factory_and_eager_producer_fail_closed_current_namespace_runs(self):
        before, raw = preserved('android_installer_component_bundle.py', 'agent_tools._component_closure_before')
        _, producer = preserved('android_installer_lifecycle.py', 'scripts._lifecycle_import_before')
        receipt = self.stage(before, 'original', {
            'agent_tools/android_installer_component_bundle.py': raw,
            'scripts/android_installer_lifecycle.py': producer})
        original = before.load(receipt)
        with self.assertRaisesRegex(ImportError, 'component_bundle_external_import'):
            before.modules(receipt)
        self.assertEqual(original, before.load(receipt))
        # The eager CLI-only import is a separate causal gate after the two
        # transport dependencies are staged; no registry fallback is allowed.
        eager = self.stage(bundle, 'eager', {'scripts/android_installer_lifecycle.py': producer})
        with self.assertRaisesRegex(ImportError, 'readiness_entrypoints'):
            bundle.modules(eager)
        current = self.stage(bundle, 'current', {})
        program = "CLOSURE_SENTINEL='complete-current-namespace'\ndef coldboot_dispatch():\n raise AssertionError('no native dispatch')\ncoldboot_dispatch()\n"
        prepared = {'program': program, 'snapshots': {},
                    'commandProgramSha256': hashlib.sha256(program.encode()).hexdigest()}
        namespace = {}
        exec(bundle.namespace_source(current, prepared), namespace)
        self.assertEqual('complete-current-namespace', namespace['CLOSURE_SENTINEL'])
        transport = namespace['COMPONENT_MODULES']['transport'].readonly.availability.ssh_transport
        self.assertEqual(str(Path(current['directory']) / 'agent_tools/readiness.py'),
                         transport._readiness.__file__)
        self.assertEqual(str(Path(current['directory']) / 'agent_tools/private_inventory_lock.py'),
                         transport._readiness.private.__file__)
        self.assertNotEqual(readiness, transport._readiness)
        self.assertNotIn('readiness_entrypoints', namespace['COMPONENT_MODULES']['lifecycle'].__dict__)
        # Staged importer policy stays finite; adding a missing dependency never
        # grants third-party or repository fallback imports.
        importer = transport.__dict__['__builtins__']['__import__']
        with self.assertRaisesRegex(ImportError, 'component_bundle_external_import'):
            importer('unstaged_component_external_dependency')
        with self.assertRaisesRegex(ImportError, 'component_bundle_unstaged_import'):
            importer('agent_tools.readiness_entrypoints')
        source = Path(current['directory']) / 'agent_tools/readiness.py'
        source.write_bytes(source.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'component_bundle_file_changed'):
            bundle.modules(current)

    def test_current_complete_factory_executes_fixed_physical_caller_through_real_socket(self):
        case = component_cases.BundleTests()
        case.setUp()
        self.addCleanup(case.tearDown)
        selected, backend, args, _, log, _, _ = case.fixture()
        temporary = tempfile.TemporaryDirectory(prefix='vc-ac-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        path = str(Path(temporary.name) / 'peer')
        requests = []
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                request = json.loads(self.rfile.readline(262145))
                requests.append(request)
                self.wfile.write(b'OK\n')
        server = socketserver.UnixStreamServer(path, Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        thread.start()
        def close():
            server.shutdown(); server.server_close(); thread.join(2)
        self.addCleanup(close)
        prelude = ("import socket as _peer_socket\n_peer=_peer_socket.socket(_peer_socket.AF_UNIX)\n"
                   "_peer.settimeout(3)\n_peer.connect(" + repr(path) + ")\n"
                   "_peer.sendall(__import__('json').dumps(__import__('sys').argv[1:]).encode()+b'\\n')\n"
                   "assert _peer.recv(3)==b'OK\\n'\n_peer.close()\n")
        for executable in (Path(backend['LAUNCH']['adbPath']), Path(backend['EXTERNAL']['selectedJdk']['root']) / 'bin/java'):
            first, body = executable.read_text().split('\n', 1)
            executable.write_text(first + '\n' + prelude + body)
        adb = Path(backend['LAUNCH']['adbPath'])
        backend['LAUNCH']['adbFacts']['generation'] = backend['fp'](adb.stat())
        backend['EXTERNAL']['selectedJdk'] = backend['external_jdk']('jdk17')
        guard = bundle.CurrentGuard(case.receipt, selected, backend, args)
        opening = len(requests)
        self.assertGreater(opening, 0)
        self.assertEqual(guard.expected, guard._physical())
        self.assertGreater(len(requests), opening)
        self.assertFalse(any('updates' in request or 'install' in request for request in requests))
        self.assertTrue(log.is_file())

    def test_complete_old_adapter_pin_refusal_current_exact_producers_and_drift_guards(self):
        before, _ = preserved('android_installer_component_adapter.py', 'agent_tools._adapter_closure_before')
        for name, module, attribute in (('main', lifecycle, 'LIFECYCLE_SHA'),
                                        ('public_cli_environment', tls, 'TLS_SHA')):
            with self.subTest(producer=module.__name__):
                with self.assertRaisesRegex(ValueError, 'installer_adapter_source_changed'):
                    before._module(module, getattr(before, attribute), (name,))
                self.assertTrue(adapter._module(module, getattr(adapter, attribute), (name,)))
                changed = self.root / (module.__name__.split('.')[-1] + '.py')
                changed.write_bytes(Path(module.__file__).read_bytes() + b'\n')
                changed.chmod(0o600)
                with mock.patch.object(module, '__file__', str(changed)), \
                        self.assertRaisesRegex(ValueError, 'installer_adapter_source_changed'):
                    adapter._module(module, getattr(adapter, attribute), (name,))

    def test_complete_old_adapter_install_refuses_current_template_current_caller_runs(self):
        before, _ = preserved('android_installer_component_adapter.py', 'agent_tools._adapter_install_before')
        case = adapter_cases.AdapterTests()
        case.setUp()
        self.addCleanup(case.tearDown)
        with mock.patch.object(adapter_cases, 'adapter', before), \
                self.assertRaisesRegex(ValueError, 'installer_adapter_source_changed'):
            case.test_actual_complete_template_production_namespace_adapter_and_lifecycle()
        self.assertEqual([], case.calls)
        current = adapter_cases.AdapterTests()
        current.setUp()
        self.addCleanup(current.tearDown)
        current.test_actual_complete_template_production_namespace_adapter_and_lifecycle()

    def test_new_main_callee_is_authenticated_before_install_and_each_dispatch(self):
        path = FIXTURE / 'android_installer_component_adapter.before-run-admitted.source'
        raw = path.read_bytes()
        self.assertEqual(json.loads((FIXTURE/'provenance.json').read_bytes())['beforeRunAdmittedSha256'],
                         hashlib.sha256(raw).hexdigest())
        before = types.ModuleType('agent_tools._adapter_before_main_callee_guard')
        before.__package__ = 'agent_tools'; before.__file__ = str(path)
        exec(compile(raw, str(path), 'exec', dont_inherit=True), before.__dict__)
        changed = lambda args: None
        def fixture():
            case = adapter_cases.AdapterTests(); case.setUp()
            self.addCleanup(case.tearDown); case.backend_functions()
            return case
        old = fixture()
        with mock.patch.object(lifecycle, '_run_admitted', changed):
            restore = before.install(lifecycle, tls, old.env, old.args, lambda: None)
            restore()
        self.assertTrue((old.path/'component-transport-admission.json').is_file())
        self.assertEqual([], old.calls)
        current = fixture()
        with mock.patch.object(lifecycle, '_run_admitted', changed), \
                self.assertRaisesRegex(ValueError, 'installer_adapter_hook_changed'):
            adapter.install(lifecycle, tls, current.env, current.args, lambda: None)
        self.assertFalse((current.path/'component-transport-admission.json').exists())
        live = fixture()
        restore = adapter.install(lifecycle, tls, live.env, live.args, lambda: None)
        self.addCleanup(restore)
        with mock.patch.object(lifecycle, '_run_admitted', changed), \
                self.assertRaises(lifecycle.InvocationFailure) as error:
            lifecycle.invoke(live.args.cli, live.args.serial, 'status')
        self.assertIsInstance(error.exception.__cause__, ValueError)
        self.assertEqual('installer_adapter_semantic_guard_changed', str(error.exception.__cause__))
        self.assertEqual([], live.calls)

    def test_actual_main_still_admits_via_real_provider_socket_before_dispatch(self):
        case = entry_cases.EntrypointTests()
        case.setUp()
        self.addCleanup(case.doCleanups)
        adb = self.root / 'adb'
        adb.write_text('#!/bin/sh\nexit 0\n'); adb.chmod(0o700)
        case.binding.clear()
        case.binding.update(adb=str(adb), serial='emulator-5684', avd='owned-fixture', serverPort=5037)
        case.target_selector = 'android:emulator-5684'
        case.target.return_value = case.target_selector
        args = types.SimpleNamespace(device_port='5684', api='29', reconciliation_timeout_seconds=3,
            reconciliation_poll_seconds=.01, output=self.root/'run', adb=str(adb), cli=self.root/'cli.py',
            serial='emulator-5684', avd='owned-fixture')
        before = case.provider.observe_calls
        dispatched = []
        def run(admitted):
            self.assertGreater(case.provider.observe_calls, before)
            admitted.readiness_admission.revalidate()
            dispatched.append(admitted.readiness_admission)
        environment = {'VPN_CONTROL_READINESS_FIXTURE_ID': 'controlled-fixture',
                       'ANDROID_ADB_SERVER_PORT': '5037', 'ADB_SERVER_SOCKET': 'tcp:localhost:5037'}
        # The entrypoint admits under its script ROOT; a controlled fixture must
        # never leave lease records in the checkout running this test.
        checkout = Path(lifecycle.ROOT) / '.rag_index/readiness-gui-leases'
        retained = sorted(os.listdir(checkout)) if checkout.is_dir() else None
        for stale in (False, True):
            with self.subTest(stale=stale):
                def target(admitted):
                    if stale:
                        case.provider.observation = replace(case.provider.observation, session='changed-session')
                    run(admitted)
                with mock.patch.object(lifecycle, 'ROOT', case.root), \
                        mock.patch.object(lifecycle, 'parse_args', return_value=args), \
                        mock.patch.object(lifecycle, 'validate_intent', return_value={'operationId': str(__import__('uuid').uuid4())}) as validate, \
                        mock.patch.object(lifecycle.tls, 'public_cli_environment', return_value={}), \
                        mock.patch.object(lifecycle, '_run_admitted', side_effect=target), \
                        mock.patch.dict(os.environ, environment):
                    if stale:
                        with self.assertRaisesRegex(readiness.ReadinessBlocked, 'prepared_context_stale'):
                            lifecycle.main()
                    else:
                        lifecycle.main()
                validate.assert_called_once_with(args, local_only=True)
                self.assertEqual(1, len(dispatched))
                with self.assertRaisesRegex(entry.EntrypointBlocked, 'prepared_context_closed'):
                    args.readiness_admission.revalidate()
        self.assertEqual([], case.provider.effects)
        self.assertEqual(retained, sorted(os.listdir(checkout)) if checkout.is_dir() else None)

    def test_preserved_old_fixture_seams_fail_at_actual_current_boundaries(self):
        metadata = json.loads((FIXTURE/'provenance.json').read_bytes())['beforeFixtureSha256']
        modules = {}
        for name, digest in metadata.items():
            raw = (FIXTURE/(name+'.before.source')).read_bytes()
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            module = types.ModuleType('agent_tools.tests._before_' + name.removesuffix('.py'))
            # Preserve the original fixture's own source-relative inputs.
            module.__file__ = str(Path(__file__).with_name(name))
            exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
            modules[name] = module
        old_route = modules['test_android_install_recovery_mcp_route.py'].AndroidInstallRecoveryRouteTest()
        with self.assertRaisesRegex(TypeError, 'isinstance'):
            old_route.test_proof_and_release_require_exact_reviewed_inputs()
        old_os = modules['test_android_api35_os_session_projection.py'].OsSessionProjectionTest()
        self.addCleanup(old_os.doCleanups)
        with mock.patch.object(ssh_transport, '_build_readiness_nested_argv',
                               side_effect=AssertionError('unintended readiness route')), \
                self.assertRaisesRegex(AssertionError, 'unintended readiness route'):
            old_os.test_measured_bootstrap_command_red_then_fixed_green()
        current_route = route_cases.AndroidInstallRecoveryRouteTest()
        current_route.test_proof_and_release_require_exact_reviewed_inputs()
        current_os = os_cases.OsSessionProjectionTest()
        self.addCleanup(current_os.doCleanups)
        with mock.patch.object(ssh_transport, '_build_readiness_nested_argv',
                               side_effect=AssertionError('no readiness route in this inert selected-route fixture')):
            current_os.test_measured_bootstrap_command_red_then_fixed_green()


if __name__ == '__main__':
    unittest.main()
