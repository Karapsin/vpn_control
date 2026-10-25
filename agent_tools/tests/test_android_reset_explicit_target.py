"""Execute the complete reset producer against two isolated target routes."""
import ast
import base64
import contextlib
import hashlib
import json
from pathlib import Path
import re
import socket
import tempfile
import threading
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock
from uuid import UUID

from agent_tools import android_vpn_permission_reset as current

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / 'fixtures/explicit_android_reset_target'
OP = '7e865d03-8e17-42fa-81c4-a18f537d4501'
SHA = 'a' * 64
SOURCE = 'b' * 40
ARGS = (OP, 'sha256-' + SHA, OP, OP, SHA, OP, 1)


def before(name):
    raw = (FIXTURE / name).read_bytes()
    pins = json.loads((FIXTURE / 'provenance.json').read_bytes())['sourceSha256']
    if hashlib.sha256(raw).hexdigest() != pins[name]:
        raise AssertionError('original target producer changed')
    return raw


def old_module():
    module = ModuleType('agent_tools._reset_target_before')
    module.__package__ = 'agent_tools'
    module.__file__ = str(FIXTURE / 'android_vpn_permission_reset.before.source')
    exec(compile(before('android_vpn_permission_reset.before.source'), module.__file__, 'exec'), module.__dict__)
    return module


class ExplicitAndroidResetTargetTests(unittest.TestCase):
    def submit(self, module, selectors):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            # Both routes exist. The real producer must choose solely from input.
            hosts = {}
            for host, device, serial, avd in (('archlinux', 'api29', 'serial-A', 'avd-A'),
                                               ('other-host', 'other-device', 'serial-B', 'avd-B')):
                hosts[host] = SimpleNamespace(android_devices={device: {
                    'api': 29, 'adb': '/owned/adb', 'serial': serial, 'expectedAvd': avd}},
                    fixture_transfer_root=Path('/owned/fixture'))
            config = SimpleNamespace(hosts=hosts)
            stage = {'ok': True, 'state': 'published', 'sourceSha': SOURCE, 'receipt': {
                'cliPath': '/owned/fixture/android-cli-stage-' + OP + '/tree/cli',
                'manifestSha256': SHA, 'rpmSha256': SHA, 'launcherSha256': SHA,
                'desktopJarSha256': SHA}}
            backup = {'sha256': SHA, 'rulesValid': True}
            artifact = {'verification': 'verified', 'artifact': {'platform': 'android',
                'artifactKind': 'apk', 'sourceSha': SOURCE, 'sha256': SHA},
                'location': {'localPath': '/owned/test.apk'}}
            opening = {'ok': True, 'state': 'complete', 'result': {'package': {'baseSha256': SHA},
                'backup': backup, 'guard': {'controllerId': OP, 'configurationRevision': 1},
                'device': {'api': 29}}}
            live = {'ok': True, 'result': {'stage': 'backup_present', 'controllerId': OP,
                'configurationRevision': 1, 'backup': backup}}
            calls = []
            endpoint = socket.socket(socket.AF_UNIX)
            endpoint.bind(str(root / 'target.sock')); endpoint.listen(1); endpoint.settimeout(2)
            stack.callback(endpoint.close)

            def peer():
                connection, _ = endpoint.accept()
                with connection:
                    calls.append(json.loads(connection.recv(65536)))
                    connection.sendall(json.dumps({'state': 'submitted', 'correlationId': OP}).encode())

            def transport(argv, timeout):
                worker = base64.urlsafe_b64decode(argv[-1]).decode()
                # The complete emitted worker must use exactly the chosen serial/AVD.
                selected = hosts[argv[0]].android_devices
                profile = next(iter(selected.values()))
                self.assertIn(repr(profile['serial']), worker)
                self.assertIn(repr(profile['expectedAvd']), worker)
                thread = threading.Thread(target=peer); thread.start()
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(root / 'target.sock'))
                    client.sendall(json.dumps({'host': argv[0], 'serial': profile['serial']}).encode())
                    answer = client.recv(65536)
                thread.join(2); self.assertFalse(thread.is_alive())
                return 0, answer

            def patch(owner, name, **kwargs):
                return stack.enter_context(mock.patch.object(owner, name, **kwargs))
            patch(module.ssh_transport, 'load_config', return_value=config)
            patch(module.ssh_transport, 'connection_host', return_value=SimpleNamespace(password=None))
            patch(module.ssh_transport, 'build_ssh_argv', side_effect=lambda config, host, timeout, command: (host, *command))
            patch(module.android_observation, '_profile', side_effect=lambda value: value)
            patch(module.native_artifact_registry, 'verify_artifact', return_value=artifact)
            patch(module.subprocess, 'run', return_value=SimpleNamespace(stdout=SOURCE))
            patch(module.android_package_install, '_inspect_apk', return_value=None)
            patch(module.android_cli_stage, 'status', return_value=stage)
            patch(module.android_admission_readback, 'async_collect', return_value=opening)
            patch(module.android_admission_readback, 'readback_status', return_value=live)
            patch(module, '_public_preflight', return_value=True)
            patch(module.android_public_inspect, 'inspect', return_value={'outcome': 'admitted', 'result': {'runtime': {'running': False}}})
            patch(module.android_observation, '_run_probe', side_effect=transport)
            try:
                result = module.start(root, *ARGS, **selectors)
            except ValueError as error:
                return str(error), calls, list(root.rglob('*.json'))
            intent = json.loads(module._journal(root, OP).read_bytes())
            return result, calls, intent

    def test_whole_before_implicitly_submits_A_current_missing_target_has_no_effect(self):
        result, calls, _ = self.submit(old_module(), {})
        self.assertEqual('submitted', result['state'])
        self.assertEqual([{'host': 'archlinux', 'serial': 'serial-A'}], calls)
        result, calls, files = self.submit(current, {})
        self.assertIn('explicit host and device', result)
        self.assertEqual([], calls)
        self.assertEqual([], files)

    def test_explicit_B_routes_packet_and_original_intent_to_B_only(self):
        result, calls, intent = self.submit(current, {'host': 'other-host', 'device': 'other-device'})
        self.assertEqual('submitted', result['state'])
        self.assertEqual([{'host': 'other-host', 'serial': 'serial-B'}], calls)
        self.assertEqual(('other-host', 'other-device', 'avd-B'),
                         (intent['host'], intent['device'], intent['expectedAvd']))

    def test_unknown_explicit_target_never_falls_back_to_A(self):
        result, calls, files = self.submit(current, {'host': 'missing', 'device': 'api29'})
        self.assertIn('route is unavailable', result)
        self.assertEqual([], calls)
        self.assertEqual([], files)

    def test_transport_route_uses_input_or_original_journal_instead_of_fixed_A(self):
        from agent_tools import readiness_vm_dispatch as routes
        old = json.loads(before('readiness_vm_dispatch.before.json'))
        self.assertEqual('archlinux', old['actions']['android-vpn-permission-reset-start']['host'])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / '.rag_index/android-vpn-permission-reset'
            directory.mkdir(parents=True, mode=0o700)
            (root / '.rag_index').chmod(0o700)
            record = directory / (OP + '.json')
            record.write_text(json.dumps({'host': 'other-host', 'device': 'other-device', 'correlationId': OP}))
            record.chmod(0o600)
            for suffix in ('start', 'status', 'collect'):
                row = routes.ROUTES['android-vpn-permission-reset-' + suffix]
                self.assertEqual('selected_host', row['kind'])
                self.assertNotIn('host', row)
                self.assertEqual('other-host', routes._selected_host(root,
                    {'host': 'other-host', 'correlationId': OP} if suffix == 'start' else {'correlationId': OP}, row, OP))

    def test_actual_mcp_dispatch_requires_and_forwards_target(self):
        inputs = dict(zip(('correlationId', 'artifactId', 'cliStageCorrelationId',
            'openingReadbackCorrelationId', 'expectedBackupSha256', 'expectedOwner', 'expectedRevision'), ARGS))
        calls = []
        module = SimpleNamespace(start=lambda *args, **kwargs: calls.append(kwargs) or {'state': 'submitted'})
        projection = SimpleNamespace(project=lambda action, identity, result: result)
        def dispatch(raw):
            tree = ast.parse(raw)
            # The dispatcher and the shared refusal helper it calls, when the source has one.
            functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name in {'_vm_workflow_dispatch', '_vpn_permission_reset_refusal'}]
            namespace = {'Any': object, 'REPO_ROOT': ROOT, 're': re,
                '_valid_uuid': lambda value: str(UUID(value)) == value,
                '_error': lambda tool, message: {'state': 'blocked'},
                '_agent_module': lambda name: module if name == 'android_vpn_permission_reset' else projection}
            exec(compile(ast.Module(body=functions, type_ignores=[]), '<actual-complete-dispatch>', 'exec'), namespace)
            return namespace['_vm_workflow_dispatch']
        dispatch(before('mcp_server.before.source'))('android-vpn-permission-reset-start', inputs)
        self.assertEqual([{}], calls)  # Actual old dispatch permits implicit A.
        calls.clear()
        fixed = dispatch((ROOT / 'agent_tools/mcp_server.py').read_bytes())
        self.assertEqual('blocked', fixed('android-vpn-permission-reset-start', inputs)['state'])
        self.assertEqual([], calls)
        fixed('android-vpn-permission-reset-start', {**inputs, 'host': 'other-host', 'device': 'other-device'})
        self.assertEqual([{'host': 'other-host', 'device': 'other-device'}], calls)


class ExplicitTartDispatchTargetTests(unittest.TestCase):
    def test_whole_before_ignores_conflicting_explicit_VM_fixed_refuses(self):
        from agent_tools import readiness_vm_dispatch as routes
        tree = ast.parse(before('readiness_vm_dispatch.before.source'))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == '_tart_fixture')
        namespace = dict(routes.__dict__)
        a, b = object(), object()
        namespace['_fixture_candidates'] = lambda root, operation: [('fixture-A', a), ('fixture-B', b)]
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<complete-old-tart-selector>', 'exec'), namespace)
        inputs = {'vmName': 'VM-B', 'environmentContext': {'vmName': 'VM-A'}}
        with mock.patch.object(routes.fixtures, 'dispatch_binding', side_effect=lambda fixture, family: {'vmName': 'VM-A' if fixture is a else 'VM-B'}):
            self.assertEqual(('fixture-A', a), namespace['_tart_fixture'](ROOT, inputs, OP))
            with mock.patch.object(routes, '_fixture_candidates', side_effect=AssertionError('must reject before lookup')):
                with self.assertRaisesRegex(routes.DispatchBlocked, 'vm_readiness_target_mismatch'):
                    routes._tart_fixture(ROOT, inputs, OP, action='macos-machine-server-stop-start')

    def test_explicit_B_and_original_B_both_select_only_B(self):
        from agent_tools import readiness_vm_dispatch as routes, macos_machine_server_stop as stop
        a, b = object(), object()
        with mock.patch.object(routes, '_fixture_candidates', return_value=[('fixture-A', a), ('fixture-B', b)]), \
                mock.patch.object(routes.fixtures, 'dispatch_binding', side_effect=lambda fixture, family: {'vmName': 'VM-A' if fixture is a else 'VM-B'}), \
                mock.patch.object(stop, 'original_vm_name', return_value='VM-B') as original:
            self.assertEqual(('fixture-B', b), routes._tart_fixture(ROOT, {'vmName': 'VM-B'}, OP, action='macos-machine-server-stop-start'))
            original.assert_not_called()
            self.assertEqual(('fixture-B', b), routes._tart_fixture(ROOT, {'correlationId': OP}, OP, action='macos-machine-server-stop-status'))
            original.assert_called_once_with(ROOT, OP)
            with self.assertRaises(routes.DispatchBlocked):
                routes._tart_fixture(ROOT, {'vmName': 'VM-A', 'correlationId': OP}, OP, action='macos-machine-server-stop-status')
