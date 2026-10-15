"""Explicit configured channel contexts; real custody, inert remote programmes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import types
import unittest
import uuid
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import ssh_direct_nested_channel as direct
from agent_tools import ssh_fresh_nested_channel as channel
from agent_tools import ssh_channel_selection as selection
from agent_tools import ssh_transport as transport
from agent_tools.tests import test_ssh_fresh_nested_channel as fixtures
from agent_tools.tests import test_ssh_direct_nested_channel as direct_fixtures
from agent_tools.tests.route_adapter import bind_cached_routes


@unittest.skipUnless(direct_fixtures.COORDINATOR_CAPABLE, 'POSIX source custody and inert channel children')
class GenericChannelContextTests(unittest.TestCase):
    host = 'peer-rebuilt'
    other = 'peer-other'

    def fixture(self, *, direct_mode=False):
        if direct_mode:
            owner = direct_fixtures.DirectChannelTests('runTest')
            owner.setUp()
            self.addCleanup(owner.doCleanups)
            fixture = owner.f
        else:
            owner = fixture = fixtures.FreshChannelTests('runTest')
            fixture.setUp()
            self.addCleanup(fixture.doCleanups)
        config = fixture.f.config
        peer = config['hosts'].pop('archlinux')
        config['hosts']['jump-rebuilt'] = config['hosts'].pop('gateway')
        peer['gateway'] = 'jump-rebuilt'
        config['hosts'][self.host] = peer
        config['hosts'][self.other] = {**copy.deepcopy(peer), 'remoteHostAlias': 'other-peer'}
        fixture.f.write_config()
        if not direct_mode:
            for host in (self.host, self.other):
                self.assertEqual('ready', channel.session.prepare(fixture.root, host)['state'])
        remote = copy.deepcopy(owner.result) if direct_mode else fixture.ready_fixture()
        remote['arch'] = {'uid': 2048, 'boot': 'bfcb12fa-d056-4f8c-bcef-929380a44d1d'}
        if direct_mode:
            owner.result = remote
        else:
            fixture.stdout = json.dumps(remote).encode()
            fixture.rc = 0
        bind_cached_routes(self, server, 'ssh_fresh_nested_channel', 'ssh_direct_nested_channel',
                           'ssh_channel_selection', 'ssh_transport')
        patch = mock.patch.object(server, 'REPO_ROOT', fixture.root)
        patch.start()
        self.addCleanup(patch.stop)
        return owner, fixture

    def invoke(self, owner, fixture, *, direct_mode=False, method='prepare', host=None, corr=None):
        provider = direct if direct_mode else channel
        with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
            return getattr(provider, method)(fixture.root, host or self.host, corr or fixture.corr)

    def test_fresh_context_uses_arbitrary_alias_and_observed_peer_then_only_observes(self):
        owner, fixture = self.fixture()
        first = self.invoke(owner, fixture)
        self.assertEqual('ready', first['state'])
        self.assertEqual('ready', self.invoke(owner, fixture, method='status')['state'])
        self.assertEqual('ready', self.invoke(owner, fixture)['state'])
        self.assertEqual(['prepare', 'status', 'status'], [call[6] for call in fixture.calls])

    def test_direct_context_uses_arbitrary_alias_and_observed_peer_then_only_observes(self):
        owner, fixture = self.fixture(direct_mode=True)
        first = self.invoke(owner, fixture, direct_mode=True)
        self.assertEqual('ready', first['state'])
        self.assertEqual('ready', self.invoke(owner, fixture, direct_mode=True, method='status')['state'])
        self.assertEqual('ready', self.invoke(owner, fixture, direct_mode=True)['state'])
        self.assertEqual(['prepare', 'status', 'status'], [call[6] for call in owner.calls])

    def test_cross_host_original_never_observes_or_replays_and_invalid_alias_has_no_effect(self):
        for direct_mode in (False, True):
            with self.subTest(direct=direct_mode):
                owner, fixture = self.fixture(direct_mode=direct_mode)
                ready = self.invoke(owner, fixture, direct_mode=direct_mode)
                self.assertEqual('ready', ready['state'])
                calls = owner.calls
                count = len(calls)
                for host in (self.other, 'missing-peer', '../foreign'):
                    for method in ('prepare', 'status'):
                        value = self.invoke(owner, fixture, direct_mode=direct_mode, method=method, host=host)
                        self.assertEqual('unknown', value['state'])
                        self.assertEqual(count, len(calls))
                # Correlations are provider-bound as well as host-bound.
                other_provider = channel if direct_mode else direct
                with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
                    for method in ('prepare', 'status'):
                        self.assertEqual('unknown', getattr(other_provider, method)(fixture.root, self.host, fixture.corr)['state'])
                self.assertEqual(count, len(calls))
                with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
                    self.assertEqual('unknown', selection.select_channel(fixture.root, self.other, fixture.corr,
                        ready['receiptSha256'], direct=direct_mode)['state'])
                self.assertEqual(count, len(calls))
                self.assertFalse((fixture.root / '.rag_index/ssh-channel-selection/hosts' / self.other).exists())

    def test_malformed_scoped_intent_is_finite_unknown_without_submission(self):
        for direct_mode in (False, True):
            with self.subTest(direct=direct_mode):
                owner, fixture = self.fixture(direct_mode=direct_mode)
                self.assertEqual('ready', self.invoke(owner, fixture, direct_mode=direct_mode)['state'])
                provider = 'ssh-direct-nested-channel' if direct_mode else 'ssh-fresh-nested-channel'
                intent = fixture.root / '.rag_index' / provider / 'hosts' / self.host / (fixture.corr + '.intent.json')
                intent.write_bytes(b'[]')
                count = len(owner.calls)
                for method in ('prepare', 'status'):
                    self.assertEqual('unknown', self.invoke(owner, fixture, direct_mode=direct_mode, method=method)['state'])
                self.assertEqual(count, len(owner.calls))

    def test_public_direct_prepare_status_select_and_transport_use_same_explicit_host(self):
        owner, fixture = self.fixture(direct_mode=True)
        identity = {'correlationId': str(uuid.UUID(fixture.corr))}
        with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
            ready = server._ssh_direct_channel_workflow('connection-direct-channel-prepare', self.host, 30, identity, None, None)
            self.assertTrue(ready['ok'])
            self.assertTrue(server._ssh_direct_channel_workflow('connection-direct-channel-status', self.host, 30, identity, None, None)['ok'])
            selected = server._ssh_direct_channel_workflow('connection-direct-channel-select', self.host, 30,
                {**identity, 'receiptSha256': ready['receiptSha256']}, None, None)
            self.assertTrue(selected['ok'])
            argv = transport.build_ssh_argv(transport.load_config(fixture.root), self.host, command=('true',))
        self.assertIn('/tmp/vpn-channel-' + fixture.corr + '/m', argv[-1])
        self.assertNotIn('/private/inert-master', argv[-1])
        self.assertEqual(1, sum(call[6] == 'prepare' for call in owner.calls))

    def test_public_fresh_prepare_status_ensure_select_same_explicit_host(self):
        owner, fixture = self.fixture()
        identity = {'correlationId': str(uuid.UUID(fixture.corr))}
        with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
            ready = server._ssh_channel_workflow('connection-channel-prepare', self.host, 30, identity, None, None)
            self.assertTrue(ready['ok'])
            self.assertTrue(server._ssh_channel_workflow('connection-channel-status', self.host, 30, identity, None, None)['ok'])
            selected = server._ssh_channel_workflow('connection-channel-ensure', self.host, 30,
                {**identity, 'receiptSha256': ready['receiptSha256']}, None, None)
            self.assertTrue(selected['ok'])
            self.assertTrue(selected['selected'])
            argv = transport.build_ssh_argv(transport.load_config(fixture.root), self.host, command=('true',))
        self.assertIn('/tmp/vpn-channel-' + fixture.corr + '/m', argv[-1])
        self.assertEqual(1, sum(call[6] == 'prepare' for call in fixture.calls))

    def test_scoped_unknown_never_replays_and_different_explicit_host_is_independent(self):
        owner, fixture = self.fixture()
        remote = json.loads(fixture.stdout)
        fixture.stdout = json.dumps({'state': 'unknown', 'correlationId': fixture.corr}).encode()
        fixture.rc = 3
        self.assertEqual('unknown', self.invoke(owner, fixture)['state'])
        self.assertEqual('unknown', self.invoke(owner, fixture)['state'])
        self.assertEqual(['prepare', 'status'], [call[6] for call in fixture.calls])
        count = len(fixture.calls)
        self.assertEqual('unknown', self.invoke(owner, fixture, corr='c' * 32)['state'])
        self.assertEqual(count, len(fixture.calls))
        remote.update(correlationId='c' * 32, controlPath='/tmp/vpn-channel-' + 'c' * 32 + '/m')
        fixture.stdout = json.dumps(remote).encode()
        fixture.rc = 0
        self.assertEqual('ready', self.invoke(owner, fixture, host=self.other, corr='c' * 32)['state'])
        group = fixture.root / '.rag_index/ssh-fresh-nested-channel/hosts'
        self.assertTrue((group / self.host / (fixture.corr + '.intent.json')).exists())
        self.assertTrue((group / self.other / ('c' * 32 + '.intent.json')).exists())

    def test_new_arch_context_preserves_legacy_unknown_without_consuming_or_replaying_it(self):
        fixture = fixtures.FreshChannelTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path = Path(__file__).parent / 'fixtures/ssh_direct_ended_v1/reviewed_optimizer/ssh_fresh_nested_channel.py'
        old = types.ModuleType('agent_tools._original_legacy_channel_context')
        old.__file__ = str(path)
        old.__package__ = 'agent_tools'
        source = path.read_bytes()
        self.assertEqual('a89b78915104aca50a6f5bbd1f7c9e9961248f308c10014572c6c77f702da603', hashlib.sha256(source).hexdigest())
        exec(compile(source, str(path), 'exec'), old.__dict__)
        with mock.patch.object(fixtures, 'channel', old):
            self.assertEqual('unknown', fixture.invoke()['state'])
        legacy = fixture.root / '.rag_index/ssh-fresh-nested-channel'
        before = {p.name: p.read_bytes() for p in legacy.iterdir() if p.is_file()}
        count = len(fixture.calls)
        self.assertEqual('unknown', fixture.invoke()['state'])
        self.assertEqual(count, len(fixture.calls))
        remote = fixture.ready_fixture()
        remote.update(correlationId='c' * 32, controlPath='/tmp/vpn-channel-' + 'c' * 32 + '/m')
        fixture.stdout = json.dumps(remote).encode()
        fixture.rc = 0
        self.assertEqual('ready', fixture.invoke(corr='c' * 32)['state'])
        self.assertEqual(before, {p.name: p.read_bytes() for p in legacy.iterdir() if p.is_file()})
        self.assertTrue((legacy / 'hosts/archlinux' / ('c' * 32 + '.intent.json')).exists())

    def test_per_host_selection_keeps_other_explicit_pointer_unchanged(self):
        owner, fixture = self.fixture(direct_mode=True)
        with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
            ready = direct.prepare(fixture.root, self.host, fixture.corr)
            self.assertEqual('selected', selection.select_channel(fixture.root, self.host, fixture.corr,
                ready['receiptSha256'], direct=True)['state'])
            base = fixture.root / '.rag_index/ssh-channel-selection/hosts'
            original = (base / self.host / 'current.json').read_bytes()
            other_corr = 'c' * 32
            owner.result.update(correlationId=other_corr, controlPath='/tmp/vpn-channel-' + other_corr + '/m')
            other_ready = direct.prepare(fixture.root, self.other, other_corr)
            self.assertEqual('ready', other_ready['state'])
            self.assertEqual('selected', selection.select_channel(fixture.root, self.other, other_corr,
                other_ready['receiptSha256'], direct=True)['state'])
        self.assertEqual(original, (base / self.host / 'current.json').read_bytes())
        original_history = json.loads(original)['history']
        other_history = json.loads((base / self.other / 'current.json').read_bytes())['history']
        self.assertEqual(self.host, json.loads((base / self.host / original_history).read_bytes())['host'])
        self.assertEqual(self.other, json.loads((base / self.other / other_history).read_bytes())['host'])

    def test_bad_scoped_selection_never_falls_back_to_configured_socket(self):
        owner, fixture = self.fixture(direct_mode=True)
        ready = self.invoke(owner, fixture, direct_mode=True)
        self.assertEqual('ready', ready['state'])
        with mock.patch.object(subprocess, 'Popen', side_effect=owner.consumer):
            self.assertEqual('selected', selection.select_channel(fixture.root, self.host, fixture.corr,
                ready['receiptSha256'], direct=True)['state'])
        pointer = fixture.root / '.rag_index/ssh-channel-selection/hosts' / self.host / 'current.json'
        pointer.write_bytes(b'{}')
        count = len(owner.calls)
        with self.assertRaises(transport.SshConfigError):
            transport.build_ssh_argv(transport.load_config(fixture.root), self.host)
        self.assertEqual(count, len(owner.calls))

    def test_direct_or_three_hop_routes_refuse_before_journal_or_submission(self):
        owner, fixture = self.fixture(direct_mode=True)
        peer = copy.deepcopy(fixture.f.config['hosts'][self.host])
        peer['gateway'] = self.host
        fixture.f.config['hosts']['third-peer'] = peer
        fixture.f.write_config()
        for host in ('jump-rebuilt', 'third-peer'):
            self.assertEqual('unknown', self.invoke(owner, fixture, direct_mode=True, host=host)['state'])
        self.assertEqual([], owner.calls)
        self.assertFalse((fixture.root / '.rag_index/ssh-direct-nested-channel').exists())


if __name__ == '__main__':
    unittest.main()
