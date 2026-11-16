"""Normal VM admission dispatches complete generated SSH callers to real sockets."""
from dataclasses import replace
import ast
import contextlib
import json
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness
from agent_tools import readiness_vm_dispatch as subject
from agent_tools import ssh_transport as transport
from agent_tools import source_module_loader
from agent_tools.tests import red_gate
from agent_tools.tests import test_readiness_transport as transport_fixture
from agent_tools.tests.test_readiness import Provider, SocketAdapter
from agent_tools.tests.test_readiness_entrypoints import before_source, controlled_lease_workflow, finish_controlled_leases


@unittest.skipUnless(os.name == 'posix', 'owned SSH master and controlled provider sockets')
class VmDispatchTests(unittest.TestCase):
    close_children = transport_fixture.ReadinessTransportTests.close_children

    def setUp(self):
        transport_fixture.ReadinessTransportTests.setUp(self)
        # This checkout need not be published; test_committed_source covers the
        # rule and the tests below cover where resolve() applies it.
        self.committed = []
        hook = mock.patch.object(subject, '_require_committed',
                                 side_effect=lambda repository, paths: self.committed.append((repository, tuple(paths))))
        hook.start(); self.addCleanup(hook.stop)
        self.provider = Provider(self.root/'provider.sock')
        self.thread = threading.Thread(target=self.provider.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start(); self.addCleanup(self.close_provider)
        (self.root/'guest-readiness').mkdir(mode=0o700)
        self.context = readiness.Context('fixture', 'machine-a', SocketAdapter(self.root/'provider.sock'),
                                          readiness.RecoveryJournal(self.root/'guest-readiness'))
        self.fixture = SimpleNamespace(context=lambda **_: self.context)

    def close_provider(self):
        self.provider.shutdown(); self.provider.server_close(); self.thread.join(2)

    def inputs(self):
        return {'host': 'explicit-peer', 'correlationId': str(uuid4())}

    def command(self, host='explicit-peer'):
        config = transport.load_config(self.root)
        return transport.build_ssh_argv(config, host, command=('python3', '-I', '-B', '-c', "print('vm-sentinel')"))

    def run_command(self, host='explicit-peer'):
        result = transport.run_ssh(self.command(host), capture_output=True, timeout=5)
        self.assertEqual((0, b'vm-sentinel\n', b''), (result.returncode, result.stdout, result.stderr))

    def test_remote_observer_restores_only_transport_and_executes_once(self):
        with subject.admitted_dispatch(self.root, 'windows-credential-probe-status', self.inputs()) as plan:
            self.assertEqual('explicit-peer', plan.host)
            self.assertIsNone(plan.fixture)
            self.run_command()
        self.assertEqual(1, len(self.children))
        self.assertEqual([], self.provider.effects)
        self.assertEqual(0, self.provider.observe_calls)

    def test_dead_owned_transport_recovers_once_before_new_packet_generation(self):
        inputs = self.inputs()
        with subject.admitted_dispatch(self.root, 'windows-credential-probe-status', inputs):
            self.run_command()
        old = self.children[0]; old.terminate(); old.wait(3)
        with subject.admitted_dispatch(self.root, 'windows-credential-probe-status', inputs):
            self.run_command()
        self.assertEqual(2, len(self.children))
        self.assertEqual([], self.provider.effects)

    def test_background_guest_requires_agent_without_unlock_or_display_wake(self):
        self.provider.observation = replace(self.provider.observation, ordinary_session='locked', display='sleeping')
        with mock.patch.object(subject, '_guest_fixture', return_value=('fixture', self.fixture)):
            with subject.admitted_dispatch(self.root, 'android-readback-start', self.inputs()):
                self.run_command()
        self.assertEqual([], self.provider.effects)
        self.assertGreater(self.provider.observe_calls, 0)

    def test_guest_boot_change_after_generation_refuses_actual_ssh_process(self):
        with mock.patch.object(subject, '_guest_fixture', return_value=('fixture', self.fixture)):
            with subject.admitted_dispatch(self.root, 'android-readback-start', self.inputs()):
                command = self.command()
                self.provider.observation = replace(self.provider.observation, boot='boot-b')
                with self.assertRaises(readiness.ReadinessBlocked) as caught:
                    transport.run_ssh(command, capture_output=True, timeout=5)
        self.assertEqual('prepared_context_stale', caught.exception.reason)
        self.assertEqual([], self.provider.effects)

    def test_local_and_intentional_phases_have_no_transport_or_guest_effects(self):
        with mock.patch.object(subject.ssh_transport, 'load_config', side_effect=AssertionError('no target lookup')):
            for action in ('artifact-find', 'acceptance-status', 'windows-vm-deploy-stop', 'macos-fixture-guest-stage-start'):
                with subject.admitted_dispatch(self.root, action, {}) as plan:
                    self.assertEqual('observation_only', plan.boundary)
        self.assertEqual([], self.children)
        self.assertEqual(0, self.provider.observe_calls)

    def test_hosted_and_self_admitting_facades_do_not_invent_ssh_targets(self):
        with mock.patch.object(subject.ssh_transport, 'load_config', side_effect=AssertionError('no host default')):
            for action in ('readiness-reboot', 'readiness-ensure', 'readiness-lease-acquire'):
                with subject.admitted_dispatch(self.root, action, {}) as plan:
                    self.assertEqual('facade', plan.boundary)
        self.assertEqual([], self.children)

    def test_real_source_request_preserves_context_manager_and_closes_capability(self):
        directory = Path(subject.__file__).parent
        with source_module_loader.request_scope(directory):
            adapter = source_module_loader.adapter(directory, 'readiness_vm_dispatch')
            before_path = before_source('readiness_vm_dispatch.before-source-owned-context.source')
            tree = ast.parse(before_path.read_bytes())
            original = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'admitted_dispatch')
            namespace = dict(subject.__dict__)
            exec(compile(ast.Module(body=[original], type_ignores=[]), str(before_path), 'exec'), namespace)
            foreign = namespace['admitted_dispatch'](self.root, 'artifact-find', {})
            try:
                # This extracted historical function uses copied live globals;
                # it is not code owned by this request's captured module. The
                # fixed loader must refuse it before any context entry.
                with self.assertRaisesRegex(ValueError, 'foreign_adapter_context'):
                    adapter._session.hold_result(foreign)
            finally:
                foreign.gen.close()
            context = adapter.admitted_dispatch(self.root, 'artifact-find', {})
            with context as plan:
                self.assertEqual('observation_only', plan.boundary)
        with self.assertRaises(ValueError) as caught:
            context.__enter__()
        self.assertEqual('closed_adapter_source', str(caught.exception))

    def test_wrong_fixed_host_rejected_before_any_recovery(self):
        action = next(name for name, row in subject.ROUTES.items() if row['kind'] == 'fixed_host' and not subject.policies.action_policy('vm_workflow', name).requirements - {'transport'})
        with self.assertRaises(subject.DispatchBlocked) as caught:
            subject.resolve(self.root, action, {'host': 'unrelated-target'})
        self.assertEqual('vm_readiness_target_mismatch', caught.exception.reason)
        self.assertEqual([], self.children)

    def test_missing_remote_android_profile_is_precise_blocker_without_probe(self):
        with self.assertRaises(subject.DispatchBlocked) as caught:
            subject.resolve(self.root, 'android-readback-start', {**self.inputs(), 'device': 'unknown-device'})
        self.assertEqual('vm_readiness_device_unconfigured', caught.exception.reason)
        self.assertEqual([], self.children)
        self.assertEqual(0, self.provider.observe_calls)

    def test_every_remote_action_has_reviewed_current_target_source(self):
        audited = subject.audit_sources()
        self.assertTrue(audited['ok'])
        self.assertEqual(len(subject.ROUTES),audited['actions'])

    def refuse(self, module):
        def check(repository, paths):
            if 'agent_tools/' + module + '.py' in paths:
                raise subject.committed_source.SourceNotCommitted(subject.committed_source.UNPUBLISHED, [module])
        return mock.patch.object(subject, '_require_committed', side_effect=check)

    def test_every_shipped_windows_instance_source_is_reviewed_before_dispatch(self):
        # windows_vm_deploy ships _INSTANCE_SOURCES to the lab host. An unpublished
        # edit to any shipped source must refuse before recovery, like every other
        # closure member (windows_vm_image was shipped without being in any Windows
        # deployment closure); the computed closure now includes the registry.
        from agent_tools import windows_vm_deploy
        # windows_visual_fixture ships only for a windowsUacVisual setup, which a dispatch
        # cannot see from its action, so every deployment route reviews it too.
        shipped = sorted({*windows_vm_deploy._INSTANCE_SOURCES, 'windows_visual_fixture'})
        self.assertIn('windows_vm_image', shipped)
        for module in shipped:
            # Only the private deployment lookup is substituted; the closure check follows it.
            with self.refuse(module), mock.patch.object(subject, '_deployment_host', return_value='explicit-peer'), \
                 self.assertRaises(subject.DispatchBlocked) as caught:
                subject.resolve(self.root,'windows-vm-deploy-status',self.inputs())
            self.assertEqual('vm_readiness_target_source_unpublished',caught.exception.reason,module)
        self.assertEqual([],self.children)
        routes = sorted(action for action, row in subject.ROUTES.items() if row['kind'] == 'windows_deployment')
        self.assertIn('windows-vm-deploy-start',routes)
        for action in routes:
            self.assertEqual([],sorted({'agent_tools/'+module+'.py' for module in shipped}-set(subject.ROUTES[action]['closure'])),action)

    def test_missing_action_or_changed_target_source_fails_before_recovery(self):
        routes = dict(subject.ROUTES)
        routes.pop('windows-credential-probe-status')
        with mock.patch.object(subject,'ROUTES',routes), self.assertRaisesRegex(ValueError,'action_unclassified'):
            subject.audit_sources()
        with self.refuse('windows_credential_probe_ssh'), self.assertRaises(subject.DispatchBlocked) as caught:
            with subject.admitted_dispatch(self.root,'windows-credential-probe-status',self.inputs()):
                self.fail('dispatch admitted unpublished source')
        self.assertEqual('vm_readiness_target_source_unpublished',caught.exception.reason)
        self.assertEqual([],self.children)

    def test_every_closure_file_must_be_committed_after_target_selection(self):
        action = 'windows-credential-probe-status'
        expected = (subject._SOURCE.parent.parent, tuple(subject.ROUTES[action]['closure']))
        plan = subject.resolve(self.root, action, self.inputs())
        self.assertEqual(('explicit-peer', [expected]), (plan.host, self.committed))
        # A target refusal comes first and costs no git call.
        self.committed.clear()
        with self.assertRaises(subject.DispatchBlocked) as caught:
            subject.resolve(self.root, action, {**self.inputs(), 'host': 'unconfigured-peer'})
        self.assertEqual(('vm_readiness_host_unconfigured', []), (caught.exception.reason, self.committed))
        # Facade, hosted and provider boundaries reach native targets too: their source is checked as well.
        subject.resolve(self.root, 'readiness-ensure', {})
        self.assertEqual([(subject._SOURCE.parent.parent, tuple(subject.ROUTES['readiness-ensure']['closure']))], self.committed)
        self.committed.clear()
        for reason, blocked in ((subject.committed_source.UNPUBLISHED, 'vm_readiness_target_source_unpublished'),
                                (subject.committed_source.DIRTY, 'vm_readiness_target_source_uncommitted'),
                                (subject.committed_source.HIDDEN, 'vm_readiness_target_source_uncommitted'),
                                (subject.committed_source.UNTRACKED, 'vm_readiness_target_source_uncommitted'),
                                (subject.committed_source.GIT_UNAVAILABLE, 'vm_readiness_target_source_uncommitted')):
            refusal = subject.committed_source.SourceNotCommitted(reason, ['agent_tools/ssh_transport.py'])
            with self.subTest(reason=reason), mock.patch.object(subject, '_require_committed', side_effect=refusal), \
                 self.assertRaises(subject.DispatchBlocked) as caught:
                with subject.admitted_dispatch(self.root, action, self.inputs()):
                    self.fail('dispatch admitted unpublished source')
            self.assertEqual(blocked, caught.exception.reason)
        self.assertEqual([], self.children)
        self.assertEqual(0, self.provider.observe_calls)

    def test_requirement_free_phases_and_boundaries_are_source_checked_RED_unchecked_GREEN(self):
        """Review finding 3: scenario-start (requirements: []) dispatched without the committed-source check."""
        from agent_tools.tests.test_committed_source import before
        phases = sorted(action for action, row in subject.ROUTES.items() if row['kind'] == 'phase')
        self.assertIn('scenario-start', phases)
        self.assertEqual({'intentional_phase'}, {subject.policies.action_policy('vm_workflow', action).classification
                                                 for action in phases})
        boundaries = sorted(action for action, row in subject.ROUTES.items()
                            if row['kind'] in ('facade', 'hosted_boundary', 'provider_boundary'))
        source = before('readiness_vm_dispatch.before.source')
        if red_gate.red_required(self, source):
            tree = ast.parse(source.read_bytes())
            function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'resolve')
            namespace = dict(subject.__dict__)
            exec(compile(ast.Module(body=[function], type_ignores=[]), str(source), 'exec'), namespace)
            for action in phases + boundaries:
                namespace['resolve'](self.root, action, self.inputs())
            # RED: the bf8d2da2 resolve returned before any source check for every one of them.
            self.assertEqual([], self.committed)
        for action in phases + boundaries:
            with self.subTest(action=action):
                self.committed.clear()
                plan = subject.resolve(self.root, action, self.inputs())
                self.assertEqual([(subject._SOURCE.parent.parent, tuple(subject.ROUTES[action]['closure']))], self.committed)
                self.assertEqual('observation_only' if action in phases else subject.ROUTES[action]['kind'], plan.boundary)
                refusal = subject.committed_source.SourceNotCommitted(subject.committed_source.UNTRACKED, ['agent_tools/x.py'])
                with mock.patch.object(subject, '_require_committed', side_effect=refusal), \
                     self.assertRaises(subject.DispatchBlocked) as caught:
                    with subject.admitted_dispatch(self.root, action, self.inputs()):
                        self.fail('dispatch admitted uncommitted source')
                self.assertEqual('vm_readiness_target_source_uncommitted', caught.exception.reason)
        # Local metadata and local observation stay unchecked: they reach no guest.
        self.committed.clear()
        for action in ('artifact-find', 'matrix-status', 'guest-program-status'):
            subject.resolve(self.root, action, {})
        self.assertEqual([], self.committed)
        self.assertEqual([], self.children)

    def test_a_submit_records_its_published_source_and_observation_reads_it(self):
        head = __import__('subprocess').run(['git', 'rev-parse', 'HEAD'], cwd=subject._SOURCE.parent, capture_output=True,
                                            text=True).stdout.strip()
        if len(head) != 40:
            self.skipTest('no git checkout')
        source = {'reference': head, 'basis': subject.committed_source.BASIS_REMOTE, 'head': head}
        inputs = self.inputs()
        with mock.patch.object(subject, '_require_committed', return_value=source), \
             mock.patch.object(subject, '_deployment_host', return_value='explicit-peer'):
            with subject.admitted_dispatch(self.root, 'scenario-start', inputs) as plan:
                self.assertEqual(source, plan.source)
        record = json.loads((self.root / '.rag_index' / 'dispatch-source' / (inputs['correlationId'] + '.json')).read_bytes())
        self.assertEqual({'schemaVersion': 1, 'identity': inputs['correlationId'], 'action': 'scenario-start', 'reference': head,
                          'basis': 'origin-ci', 'head': head}, record)
        # The status of that job, after its candidate branch is gone, checks the recorded submit SHA.
        refusal = subject.committed_source.SourceNotCommitted(subject.committed_source.UNPUBLISHED, ['agent_tools/'])
        with mock.patch.object(subject, '_require_committed', side_effect=refusal), \
             mock.patch.object(subject, '_selected_host', return_value='explicit-peer'):
            with subject.admitted_dispatch(self.root, 'windows-credential-probe-status', inputs) as plan:
                self.assertEqual((head, 'submit-record'), (plan.source['reference'], plan.source['basis']))
                self.run_command()
            # An observation records nothing; another job's status stays refused.
            with self.assertRaises(subject.DispatchBlocked) as caught:
                subject.resolve(self.root, 'windows-credential-probe-status', self.inputs())
        self.assertEqual('vm_readiness_target_source_unpublished', caught.exception.reason)
        self.assertEqual(1, len(list((self.root / '.rag_index' / 'dispatch-source').iterdir())))

    def test_interactive_lease_guards_every_ssh_packet_and_cancels_original(self):
        self.peer.hosts['archlinux'] = dict(self.peer.hosts['explicit-peer'])
        self.peer.write_config()
        executor = controlled_lease_workflow(self.root)
        self.addCleanup(finish_controlled_leases, self.root)
        acquire = subject.gui_leases.acquire
        def short(*args, **kwargs):
            return acquire(*args, ttl_seconds=2, **kwargs)
        with mock.patch.object(subject, '_guest_fixture', return_value=('fixture', self.fixture)), \
             mock.patch.object(subject.gui_leases.workflow, 'workflow', side_effect=executor), \
             mock.patch.object(subject.gui_leases, 'acquire', side_effect=short):
            # Actual fixed target metadata resolves to an isolated trusted
            # endpoint. Only its private fixture matcher is substituted.
            with subject.admitted_dispatch(self.root, 'android-action-acceptance-start', {'correlationId':str(uuid4())}):
                self.run_command('archlinux')
                self.assertEqual('awake', (self.root/'controlled-lease-setting').read_text())
            self.assertEqual('sleep', (self.root/'controlled-lease-setting').read_text())
        self.assertEqual([], self.provider.effects)


class McpPhaseRoutingTests(unittest.TestCase):
    """The MCP vm_workflow route sends requirement-free intentional phases through admitted_dispatch (TEST-005)."""

    def route(self, implementation, server, action):
        admitted, dispatched = [], []

        original = server._agent_module

        @contextlib.contextmanager
        def admission(root, name, inputs):
            admitted.append(name)
            # The route recognises a refusal by the class its request scope loaded, as production raises it.
            raise original('readiness_vm_dispatch').DispatchBlocked('vm_readiness_target_source_unpublished', 'operation')
            yield  # pragma: no cover

        fake = SimpleNamespace(admitted_dispatch=admission)
        with mock.patch.object(server, '_agent_module', side_effect=lambda name: fake if name == 'readiness_vm_dispatch'
                               else original(name)), \
             mock.patch.object(server, '_vm_workflow_dispatch', side_effect=lambda *args: dispatched.append(args) or {'ok': True}):
            result = implementation(action, {'correlationId': str(uuid4())})
        return admitted, dispatched, result

    def test_scenario_start_is_admitted_before_dispatch_RED_direct_GREEN(self):
        from agent_tools import mcp_server as server
        from agent_tools.tests.test_committed_source import before
        source = before('mcp_server_vm_workflow_impl.before.source')
        if red_gate.red_required(self, source):
            namespace = dict(server.__dict__)
            exec(compile(source.read_bytes(), str(source), 'exec'), namespace)
            admitted, dispatched, _ = self.route(lambda action, inputs: namespace['_vm_workflow_impl'](action, inputs),
                                                 _Namespace(namespace), 'scenario-start')
            # RED: bf8d2da2 dispatched scenario-start (requirements: []) with no admission and no source check.
            self.assertEqual(([], 1), (admitted, len(dispatched)))
        phases = sorted(action for action, row in subject.ROUTES.items() if row['kind'] == 'phase'
                        # A request-shape refusal still answers first, before any admission or contact.
                        and not server._vm_invalid_before_recovery(action, {'correlationId': str(uuid4())}))
        self.assertIn('scenario-start', phases)
        for action in phases:
            with self.subTest(action=action):
                admitted, dispatched, result = self.route(server._vm_workflow_impl, server, action)
                self.assertEqual(([action], []), (admitted, dispatched))
                self.assertEqual('vm_readiness_target_source_unpublished', result['reason'])
        # Local metadata still dispatches without admission.
        admitted, dispatched, _ = self.route(server._vm_workflow_impl, server, 'artifact-find')
        self.assertEqual(([], 1), (admitted, len(dispatched)))


class _Namespace:
    """Attribute view of an exec namespace, so mock.patch.object can patch its globals."""

    def __init__(self, namespace):
        object.__setattr__(self, '_namespace', namespace)

    def __getattr__(self, name):
        try:
            return self._namespace[name]
        except KeyError:
            raise AttributeError(name) from None

    def __setattr__(self, name, value):
        self._namespace[name] = value

    def __delattr__(self, name):
        del self._namespace[name]


if __name__ == '__main__':
    unittest.main()
