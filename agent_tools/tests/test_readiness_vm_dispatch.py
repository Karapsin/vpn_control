"""Normal VM admission dispatches complete generated SSH callers to real sockets."""
from dataclasses import replace
import ast
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
from agent_tools.tests import test_readiness_transport as transport_fixture
from agent_tools.tests.test_readiness import Provider, SocketAdapter
from agent_tools.tests.test_readiness_entrypoints import before_source, controlled_lease_workflow, finish_controlled_leases


@unittest.skipUnless(os.name == 'posix', 'owned SSH master and controlled provider sockets')
class VmDispatchTests(unittest.TestCase):
    close_children = transport_fixture.ReadinessTransportTests.close_children

    def setUp(self):
        transport_fixture.ReadinessTransportTests.setUp(self)
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

    def test_missing_action_or_changed_target_source_fails_before_recovery(self):
        routes = dict(subject.ROUTES)
        routes.pop('windows-credential-probe-status')
        with mock.patch.object(subject,'ROUTES',routes), self.assertRaisesRegex(ValueError,'action_unclassified'):
            subject.audit_sources()
        pins = dict(subject._SOURCE_PINS)
        pins['windows_credential_probe_ssh'] = '0'*64
        with mock.patch.object(subject,'_SOURCE_PINS',pins), self.assertRaises(subject.DispatchBlocked) as caught:
            subject.resolve(self.root,'windows-credential-probe-status',self.inputs())
        self.assertEqual('vm_readiness_target_source_unreviewed',caught.exception.reason)
        self.assertEqual([],self.children)

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


if __name__ == '__main__':
    unittest.main()
