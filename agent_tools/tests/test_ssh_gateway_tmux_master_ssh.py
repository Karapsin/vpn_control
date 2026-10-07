"""Source/config-bound adapter tests through real inert gateway subprocesses."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import ssh_gateway_tmux_master as owner
from agent_tools import ssh_gateway_tmux_master_ssh as adapter
from agent_tools import ssh_recovery_adoption as adoption
from agent_tools import ssh_connection_recovery as recovery
from agent_tools.tests.test_ssh_gateway_tmux_master import GatewayOwnerTests


@unittest.skipUnless(os.name == 'posix', 'POSIX fixture')
class GatewayImportTests(unittest.TestCase):
    def test_existing_mcp_top_level_import_style(self):
        directory=Path(adapter.__file__).parent
        program="import sys;sys.path.insert(0,"+repr(str(directory))+");import ssh_gateway_tmux_master_ssh;assert callable(ssh_gateway_tmux_master_ssh.operate)"
        result=subprocess.run([os.sys.executable,'-I','-B','-c',program],capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,result.stderr.decode())


@unittest.skipUnless(os.name == 'posix', 'POSIX fixture')
class GatewayAdapterTests(GatewayOwnerTests):
    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory(prefix='vct-controller-', dir='/tmp'); self.addCleanup(temporary.cleanup)
        self.controller = Path(temporary.name).resolve(); self.controller.chmod(0o700)
        key = self.controller / 'key'; key.write_bytes(b'inert-outer-key'); key.chmod(0o600)
        known = self.controller / 'known'; known.write_bytes(b'inert-host-key'); known.chmod(0o600)
        outer = {'host': 'gateway.invalid', 'port': 2228, 'user': 'fixture', 'identityFile': str(key), 'knownHostsFile': str(known)}
        target = {**outer, 'host': '192.0.2.1', 'port': 22, 'transport': 'nested', 'gateway': 'gateway',
                  'remoteHostAlias': 'arch', 'remoteConfigFile': self.request['configFile'],
                  'remoteControlPath': self.request['configuredControlPath'], 'knownHostsFile': str(self.home / '.ssh/known'),
                  'password': 'inert-secret'}
        self.config = self.controller / '.vm-hosts.local.json'
        self.config.write_bytes(owner.canonical({'schemaVersion': 1, 'hosts': {'gateway': outer, 'archlinux': target}})); self.config.chmod(0o600)
        self.source = self.controller / 'gateway-owner.py'; self.source.write_bytes(self.raw); self.source.chmod(0o600)
        file_patch = mock.patch.object(owner, '__file__', str(self.source)); file_patch.start(); self.addCleanup(file_patch.stop)
        self.calls = []; self.original_popen = subprocess.Popen
        self.request_inputs = {'correlationId': self.request['correlationId']}
        def launch(argv, **kw):
            self.calls.append(argv)
            self.assertEqual(argv[2:5], ['-B', '-c', adapter.EXEC])
            ssh = json.loads(argv[-1]); self.assertEqual('/usr/bin/ssh', ssh[0]); self.assertEqual(['-F','/dev/null'], ssh[1:3]);
            self.assertIn('ControlMaster=no',ssh); self.assertIn('ControlPath=none',ssh); self.assertIn('PermitLocalCommand=no',ssh); self.assertEqual('gateway.invalid', ssh[-2])
            self.assertNotIn('inert-secret', ' '.join(ssh)); self.assertNotIn('192.0.2.1', ' '.join(ssh))
            command = shlex.split(ssh[-1]); self.assertEqual(['python3', '-I', '-B', '-c'], command[:4])
            # Execute the exact staged gateway source/packet through the same
            # stdin/private stdout/stderr boundary, without network activity.
            return self.original_popen([os.sys.executable, '-I', '-B', '-c', command[4]], **kw)
        self.launcher = mock.patch.object(adapter.subprocess, 'Popen', side_effect=launch)
        self.launcher.start(); self.addCleanup(self.launcher.stop)

    def prepare_adapter(self):
        result = adapter.operate(self.controller, 'prepare', self.request_inputs)
        self.assertEqual('prepared', result.get('state'), result); self.anchor = result['anchorPin']; return result

    def ready_adapter(self):
        self.prepare_adapter()
        result = adapter.operate(self.controller, 'release', self.request_inputs)
        self.assertEqual('released', result.get('state'), result)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = adapter.operate(self.controller, 'status', self.request_inputs)
            if result.get('state') == 'ready': return result
            time.sleep(.02)
        self.fail(str(result))

    def test_readonly_status_diagnostic_finite_actual_failure_stages(self):
        self.prepare_adapter()
        actual_capture=adapter.LocalAuthority.capture
        def source_failure(authority,path,**kw):
            if Path(path)==Path(adapter.owner.__file__).absolute():raise ValueError('private-sensitive-sentinel')
            return actual_capture(authority,path,**kw)
        scenarios=(('source',mock.patch.object(adapter.LocalAuthority,'capture',source_failure)),
            ('config',mock.patch.object(adapter.connection,'_snapshot',side_effect=ValueError('private-sensitive-sentinel'))),
            ('authority',mock.patch.object(adapter,'original_authority',side_effect=ValueError('private-sensitive-sentinel'))),
            ('localmaster',mock.patch.object(adapter.transport,'build_ssh_argv',side_effect=ValueError('private-sensitive-sentinel'))),
            ('remotequery',mock.patch.object(adapter.subprocess,'Popen',side_effect=OSError('private-sensitive-sentinel'))),
            ('parser',mock.patch.object(adapter,'query',return_value={'state':'invalid-private-sensitive-sentinel'})))
        for phase,seam in scenarios:
            with self.subTest(phase=phase),seam:
                result=adapter.configured_status_diagnostic(self.controller,self.request_inputs)
            self.assertEqual(result,{'state':'unknown','replayAllowed':False,'failurePhase':phase,'nativeActionAllowed':False})
            self.assertNotIn('sentinel',json.dumps(result))
        # Existing API remains exactly compatible, with no diagnostic fields.
        with mock.patch.object(adapter,'original_authority',side_effect=ValueError('private-sensitive-sentinel')):
            self.assertEqual({'state':'unknown','replayAllowed':False},adapter.operate(self.controller,'status',self.request_inputs))

    def test_readonly_status_actual_child_unknown_and_malformed_reply(self):
        self.prepare_adapter()
        real_popen=self.original_popen
        for body,phase in (('{"state":"unknown","replayAllowed":false}','remotequery'),
                           ('private-sensitive-sentinel-invalid-json','parser')):
            def launch(argv,**kw):
                return real_popen([os.sys.executable,'-I','-B','-c',
                    'import sys;sys.stdin.buffer.read();sys.stdout.write('+repr(body)+')'],**kw)
            with self.subTest(phase=phase),mock.patch.object(adapter.subprocess,'Popen',side_effect=launch):
                result=adapter.configured_status_diagnostic(self.controller,self.request_inputs)
            self.assertEqual(result,{'state':'unknown','replayAllowed':False,'failurePhase':phase,'nativeActionAllowed':False})
            self.assertNotIn('sentinel',json.dumps(result))

    def test_actual_prepare_release_ready_fixed_gateway_only(self):
        result = self.ready_adapter()
        self.assertEqual(self.request['masterControlPath'], result['controlPath'])
        self.assertEqual(self.request['correlationId'].replace('-', ''), result['recoveryCorrelationId'])
        self.assertFalse(result['adoptionAllowed']); self.assertEqual('ready', adapter.operate(self.controller, 'status', self.request_inputs)['state'])
        self.assertNotIn('inert-secret', json.dumps(result))

    def test_lost_prepare_reply_consumes_local_fence(self):
        actual = adapter.query
        def lost(*args, **kw):
            actual(*args, **kw); raise subprocess.TimeoutExpired('inert', 30)
        with mock.patch.object(adapter, 'query', side_effect=lost):
            self.assertEqual('unknown', adapter.operate(self.controller, 'prepare', self.request_inputs)['state'])
        before = len(self.calls)
        self.assertEqual('unknown', adapter.operate(self.controller, 'prepare', self.request_inputs)['state'])
        self.assertEqual('unknown', adapter.operate(self.controller, 'status', self.request_inputs)['state'])
        self.assertEqual(before, len(self.calls))

    def test_lost_release_reply_observes_original_owner_without_replay(self):
        self.prepare_adapter(); actual = adapter.query
        def lost(*args, **kw):
            actual(*args, **kw); raise subprocess.TimeoutExpired('inert', 30)
        with mock.patch.object(adapter, 'query', side_effect=lost):
            self.assertEqual('unknown', adapter.operate(self.controller, 'release', self.request_inputs)['state'])
        self.assertEqual('unknown', adapter.operate(self.controller, 'release', self.request_inputs)['state'])
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = adapter.operate(self.controller, 'status', self.request_inputs)
            if result.get('state') == 'ready': break
            time.sleep(.02)
        self.assertEqual('ready', result.get('state'), result)

    def test_same_bytes_config_rewrite_before_release_blocks_remote_effect(self):
        self.prepare_adapter(); self.config.write_bytes(self.config.read_bytes()); count = len(self.calls)
        self.assertEqual('unknown', adapter.operate(self.controller, 'release', self.request_inputs)['state'])
        self.assertEqual(count, len(self.calls))

    def test_source_generation_replacement_before_release_blocks_remote_effect(self):
        self.prepare_adapter(); self.source.write_bytes(self.source.read_bytes()); count = len(self.calls)
        self.assertEqual('unknown', adapter.operate(self.controller, 'release', self.request_inputs)['state'])
        self.assertEqual(count, len(self.calls))

    def adopt_original(self):
        config=adapter.transport.load_config(self.controller); target=config.hosts['archlinux']
        intent_path=recovery._intent_path(self.controller, 'archlinux', target)
        intent_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        value=recovery._intent_value('archlinux', target, self.request_inputs['correlationId'].replace('-',''), 'ready', self.request['masterControlPath'])
        intent_path.write_bytes(owner.canonical(value)); intent_path.chmod(0o600)
        with mock.patch.object(recovery, '_socket_state', side_effect=['absent','ready']):
            result=adoption.adopt(self.controller,'archlinux')
        self.assertEqual('ready',result['state'],result)

    def test_original_ready_observer_survives_exact_separately_proven_adoption(self):
        original=self.ready_adapter(); self.adopt_original()
        result=adapter.operate(self.controller,'status',self.request_inputs)
        self.assertEqual('ready',result['state'],result)
        self.assertEqual(original['readyPin'],result['readyPin'])
        self.assertEqual('unknown',adapter.operate(self.controller,'release',self.request_inputs)['state'])

    def test_config_change_without_exact_adoption_proof_rejects_before_query(self):
        self.ready_adapter(); raw=json.loads(self.config.read_text())
        raw['hosts']['archlinux']['remoteControlPath']=self.request['masterControlPath']
        self.config.write_bytes(owner.canonical(raw)); count=len(self.calls)
        self.assertEqual('unknown',adapter.operate(self.controller,'status',self.request_inputs)['state'])
        self.assertEqual(count,len(self.calls))

    def test_no_command_path_host_or_credential_overrides(self):
        for field in ('command', 'host', 'controlPath', 'credential', 'executable'):
            with self.subTest(field=field):
                result = adapter.operate(self.controller, 'prepare', {**self.request_inputs, field: 'foreign'})
                self.assertEqual('unknown', result['state'])
        self.assertEqual([], self.calls)

    def test_gateway_availability_returns_typed_missing_dependency(self):
        self.tmux.unlink()
        result = adapter.operate(self.controller, 'availability', {})
        self.assertEqual({'available': False, 'reason': 'tmux_unavailable', 'nativeActionAllowed': False}, result)

    def test_prepare_missing_dependency_is_typed_blocked_no_gateway_job(self):
        self.tmux.unlink()
        result = adapter.operate(self.controller, 'prepare', self.request_inputs)
        self.assertEqual('blocked', result.get('state'), result)
        self.assertEqual('tmux_unavailable', result.get('reason'))
        self.assertFalse(owner.paths(self.request)[2].exists())

    def test_forged_ready_reply_without_original_proof_is_rejected(self):
        self.prepare_adapter()
        with mock.patch.object(adapter, 'query', return_value={'state':'ready','correlationId':self.request_inputs['correlationId'],'replayAllowed':False}):
            self.assertEqual('unknown', adapter.operate(self.controller, 'status', self.request_inputs)['state'])


for _name in GatewayOwnerTests.__dict__:
    if _name.startswith('test_') and _name not in GatewayAdapterTests.__dict__:
        setattr(GatewayAdapterTests, _name, None)
del GatewayOwnerTests
