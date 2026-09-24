import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_credential_recovery_ssh as backend


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'), 'POSIX private journal required')
class WindowsCredentialRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        (self.root/'.runtime').mkdir(mode=0o700)
        self.correlation='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        admission=SimpleNamespace(task_name='Fixture_BaseInstall',task_path='\\',expected_task_state='Disabled',
            expected_last_result=1601,expected_task_execute=r'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe',
            expected_task_principal='fixtureuser',expected_task_arguments_sha256='9b22eff9a3ce8fab00c0c3aad52d823aab10284dd79e2a081f252ff1a331f2f7')
        self.probe=SimpleNamespace(environment='windows-fixture',account_name='fixtureuser',
            expected_sid='S-1-5-21-11-22-33-1002',
            qga_socket_path=PurePosixPath('/owned/qga.sock'),qemu_pid=1234,qemu_start_ticks=5678,
            credential_path=Path('/old/credential'),recovery_admission=admission)
        self.target=SimpleNamespace(windows_credential_probe=self.probe,fixture_transfer_root=PurePosixPath('/owned/private'))
        self.config=SimpleNamespace(hosts={'arch':self.target})
        self.config_patch=mock.patch.object(backend.transport,'_config',return_value=self.config)
        self.config_patch.start()

    def tearDown(self):
        self.config_patch.stop(); self.tmp.cleanup()

    def test_lost_submit_is_durable_and_second_start_only_observes(self):
        with mock.patch.object(backend.transport,'_run_ssh',side_effect=[None,json.dumps({'state':'unknown'}).encode()]) as ssh:
            first=backend.start(self.root,'arch',self.correlation)
            self.assertEqual(first['state'],'unknown')
            self.assertRegex(first['handle'],r'^nc-[0-9a-f]{32}$')
            self.assertEqual(backend.start(self.root,'arch',self.correlation)['state'],'unknown')
            self.assertEqual(ssh.call_count,2)
            self.assertIn('REMOTE_START', 'REMOTE_START')
            self.assertIsNotNone(ssh.call_args_list[0].args[3])
            self.assertIsNone(ssh.call_args_list[1].args[3])
        self.assertTrue(backend._journal_path(backend.native_credentials.NativeCredentialStore(self.root),self.correlation).is_file())

    def test_recovery_secret_never_enters_public_result_or_ssh_argv(self):
        with mock.patch.object(backend.transport,'_run_ssh',return_value=b'{"state":"submitted","pid":24}') as ssh:
            result=backend.start(self.root,'arch',self.correlation)
        binding=backend._binding(self.target,self.correlation)
        secret=backend.native_credentials.NativeCredentialStore(self.root).read(result['handle'],binding)
        self.assertNotIn(secret.decode(),json.dumps(result))
        self.assertNotIn(secret.decode(),repr(ssh.call_args.args[2]))
        self.assertIn(secret,backend.base64.b64decode(json.loads(ssh.call_args.args[3][4:])['credential']))

    def test_wrong_host_or_vm_binding_blocks_existing_intent(self):
        with mock.patch.object(backend.transport,'_run_ssh',return_value=None):
            backend.start(self.root,'arch',self.correlation)
        with self.assertRaises(backend.WindowsCredentialRecoveryError):
            backend.status(self.root,'other',self.correlation)
        self.probe.qemu_start_ticks=999
        with self.assertRaises(backend.WindowsCredentialRecoveryError):
            backend.status(self.root,'arch',self.correlation)

    def test_different_correlation_cannot_race_inflight_reset(self):
        with mock.patch.object(backend.transport,'_run_ssh',return_value=None) as ssh:
            backend.start(self.root,'arch',self.correlation)
            with self.assertRaisesRegex(backend.WindowsCredentialRecoveryError,'Another recovery owns'):
                backend.start(self.root,'arch','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')
            self.assertEqual(ssh.call_count,1)

    def test_inventory_edit_during_publication_is_preserved_and_blocks_switch(self):
        path=self.root.resolve()/'.vm-hosts.local.json'
        config={'schemaVersion':1,'hosts':{'arch':{'windowsCredentialProbe':{
            'environment':self.probe.environment,'accountName':self.probe.account_name,
            'expectedSid':self.probe.expected_sid,'qgaSocketPath':str(self.probe.qga_socket_path),
            'qemuPid':self.probe.qemu_pid,'qemuStartTicks':self.probe.qemu_start_ticks,
            'credentialPath':str(self.probe.credential_path)}}}}
        path.write_text(json.dumps(config)); path.chmod(0o600)
        with mock.patch.object(backend.transport,'_run_ssh',return_value=None):
            backend.start(self.root,'arch',self.correlation)
        record=backend._intent(self.root,self.correlation)
        original=backend.os.lstat
        seen=[0]
        def intervene(target):
            if Path(target)==path:
                seen[0]+=1
                if seen[0]==2:
                    x=json.loads(path.read_text()); x['unrelated']='intervening edit'
                    path.write_text(json.dumps(x))
            return original(target)
        with mock.patch.object(backend.os,'lstat',side_effect=intervene):
            with self.assertRaisesRegex(backend.WindowsCredentialRecoveryError,'changed before publication'):
                backend._publish_inventory(self.root,'arch',record)
        result=json.loads(path.read_text())
        self.assertEqual(result['unrelated'],'intervening edit')
        self.assertEqual(result['hosts']['arch']['windowsCredentialProbe']['credentialPath'],str(self.probe.credential_path))

    def test_terminal_reset_success_dispatches_one_fixed_probe_then_publishes(self):
        reset=b'{"state":"terminal","success":true,"category":"none","pid":7}'
        with mock.patch.object(backend.transport,'_run_ssh',side_effect=[b'{"state":"submitted","pid":7}',reset,reset,reset]), \
             mock.patch.object(backend.transport,'start_with_private_secret',return_value={'state':'submitted'} ) as probe_start, \
             mock.patch.object(backend.transport,'status',return_value={'state':'terminal','success':True,'errorCategory':'none'}) as probe_status, \
             mock.patch.object(backend,'_publish_inventory') as publish:
            backend.start(self.root,'arch',self.correlation)
            first=backend.status(self.root,'arch',self.correlation)
            self.assertEqual(first['state'],'verifying')
            self.assertEqual(probe_start.call_count,1)
            # Simulate the fixed probe's durable local intent from its actual helper.
            path=backend.transport._intent_path(self.root,first['probeCorrelationId'])
            path.parent.mkdir(parents=True); path.write_text('{}')
            second=backend.status(self.root,'arch',self.correlation)
            self.assertTrue(second['verified'])
            self.assertEqual(probe_status.call_count,1)
            self.assertEqual(publish.call_count,1)

    def test_script_admission_and_unknown_categories_are_distinct(self):
        source=backend.RESET_SCRIPT.read_text()
        self.assertIn("$attempted = $true",source)
        self.assertIn("Emit $false 'unknown'",source)
        self.assertIn("Emit $false 'admission-rejected'",source)
        for literal in ('fixtureuser','Fixture_BaseInstall'):
            self.assertNotIn(literal,source)
        self.assertIn("result['correlationId']!=corr",backend._REMOTE_STATUS)


class WindowsCredentialRecoveryPortableTests(unittest.TestCase):
    def test_fixed_script_encodes_only_nonsecret_parameters(self):
        probe=SimpleNamespace(account_name='fixtureuser',expected_sid='S-1-5-21-11-22-33-1002')
        admission=SimpleNamespace(task_name='Fixture_BaseInstall',task_path='\\',expected_task_state='Disabled',expected_last_result=1601,
            expected_task_execute=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            expected_task_principal='fixtureuser',expected_task_arguments_sha256='a'*64)
        program,digest=backend._program(probe,admission,'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
        self.assertRegex(digest,r'^[0-9a-f]{64}$')
        source=backend.base64.b64decode(program).decode('utf-16le')
        self.assertIn('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',source)
        self.assertNotIn('V!private-secret',source)

    def test_disabled_state_exact_and_running_or_numeric_rejected(self):
        admission=SimpleNamespace(task_name='Fixture_BaseInstall',task_path='\\',expected_task_state='Disabled',
            expected_last_result=0xffffffff,expected_task_execute='powershell.exe',
            expected_task_principal='fixtureuser',expected_task_arguments_sha256='a'*64)
        self.assertEqual(backend._task(admission)['expected_task_state'],'Disabled')
        self.assertIn('[UInt32]$ExpectedLastResult',backend.RESET_SCRIPT.read_text())
        self.assertIn("[string]$task.State -cne $ExpectedTaskState",backend.RESET_SCRIPT.read_text())
        for state in ('Running','Queued','1'):
            admission.expected_task_state=state
            with self.assertRaises(backend.WindowsCredentialRecoveryError):
                backend._task(admission)

    def test_top_level_mcp_import_path(self):
        env=os.environ.copy()
        env['PYTHONPATH']=str(backend.REPO_ROOT/'agent_tools')
        result=subprocess.run([sys.executable,'-c','import windows_credential_recovery_ssh'],
            env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__=='__main__': unittest.main()
