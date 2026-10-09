"""Actual provider/selector with real local byte consumers, no SSH actors.

Remote kernel/master reply is a declared fixture seam. Native MCP equivalent
retest remains required; these controls prove only local admission behavior.
"""
import ast,json,os,shlex,shutil,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
from agent_tools import ssh_direct_nested_channel as direct

# Windows discovery must not import POSIX fixtures before honoring their skip.
COORDINATOR_CAPABLE=(direct.coordinator_capable() and hasattr(socket,'AF_UNIX')
                     and Path('/dev/fd').is_dir() and shutil.which('ssh') is not None)
if COORDINATOR_CAPABLE:
    from agent_tools import ssh_fresh_nested_channel as channel
    from agent_tools import ssh_channel_selection as selection
    from agent_tools import ssh_transport as transport
    from agent_tools.tests import test_ssh_fresh_nested_channel as fixtures


class PortableDirectChannelBoundaryTests(unittest.TestCase):
    def test_unsupported_prepare_and_status_refuse_before_private_or_posix_imports(self):
        with mock.patch.object(direct,'coordinator_capable',return_value=False),mock.patch.object(direct,'_dependencies',side_effect=AssertionError('POSIX dependencies opened')):
            expected={'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}
            for method in (direct.prepare,direct.status):
                self.assertEqual(expected,method('/unopened-private-root','archlinux','b'*32))
    def test_actual_mcp_unsupported_boundary_refuses_all_explicit_entries(self):
        import uuid
        from agent_tools import mcp_server as server
        identity={'correlationId':str(uuid.UUID('b'*32))}
        with mock.patch.object(direct,'coordinator_capable',return_value=False),mock.patch.object(direct,'_dependencies',side_effect=AssertionError('POSIX dependencies opened')):
            for method in ('prepare','status','select'):
                value=server._ssh_workflow_impl('connection-direct-channel-'+method,'archlinux',identity={**identity,**({'receiptSha256':'c'*64} if method=='select' else {})})
                self.assertFalse(value['ok']);self.assertEqual('unknown',value['state']);self.assertTrue(value['connectionOnly'])
                self.assertFalse(value['nativeActionAllowed']);self.assertFalse(value['replayAllowed'])
    def test_unsupported_guard_and_route_refuse_before_private_construction(self):
        with mock.patch.object(direct,'coordinator_capable',return_value=False):
            with self.assertRaisesRegex(ValueError,'^unsupported_coordinator$'):direct.Guard('/unopened-private-root')
            with self.assertRaisesRegex(ValueError,'^unsupported_coordinator$'):direct.route_options('/unopened-private-root','archlinux','b'*32,'c'*64)


@unittest.skipUnless(COORDINATOR_CAPABLE,'POSIX SSH coordinator with protected FD ancestry, /dev/fd and OpenSSH required')
class DirectChannelTests(unittest.TestCase):
    def setUp(self):
        original=fixtures.fixtures.SessionTests.setUp
        def setup(owner):
            original(owner)
            owner.config['hosts']['archlinux']['windowsCredentialProbe']={'environment':'windows-cp117','qgaSocketPath':'/private/old/qga.sock','qemuPid':123,'qemuStartTicks':456,'accountName':'vpncp117','expectedSid':'S-1-5-21-1-2-3-1002','credentialPath':'/private/credential'}
            owner.write_config()
        self.f=fixtures.FreshChannelTests('runTest')
        with mock.patch.object(fixtures.fixtures.SessionTests,'setUp',setup):self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root=self.f.root;self.corr=self.f.corr;self.calls=[]
        self.real_popen=self.f.real_popen;self.result=self.f.ready_fixture();self.returncode=0
        self.config_path=self.f.f.config_path;self.legacy=self.root/'.rag_index/ssh-connection-session'
        self.legacy_before={str(p.relative_to(self.legacy)):p.read_bytes() for p in self.legacy.rglob('*') if p.is_file()}
    def consumer(self,argv,**kw):
        self.assertEqual(['-F','/dev/null'],argv[1:3]);self.assertEqual('none',argv[argv.index('-S')+1])
        self.assertIn('ControlMaster=no',argv);self.assertNotIn('inert private sentinel',repr(argv))
        remote=shlex.split(argv[-1]);self.assertEqual(['python3','-I','-B','-c'],remote[:4])
        call=ast.parse(remote[4],mode='eval').body;self.assertEqual(channel._REMOTE,ast.literal_eval(call.args[0]))
        self.calls.append(remote)
        code='import sys,json;body=sys.stdin.buffer.read();assert json.loads(body) in ({},{"passphrase":"inert private sentinel"});sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));sys.exit(int(sys.argv[2]))'
        return self.real_popen([sys.executable,'-I','-B','-c',code,json.dumps(self.result).encode().hex(),str(self.returncode)],**kw)
    def invoke(self,method='prepare',corr=None,capture=None):
        with mock.patch.object(subprocess,'Popen',side_effect=self.consumer):
            return getattr(direct,method)(self.root,'archlinux',corr or self.corr,_private_capture=capture)
    def assert_legacy_unchanged(self):
        self.assertEqual(self.legacy_before,{str(p.relative_to(self.legacy)):p.read_bytes() for p in self.legacy.rglob('*') if p.is_file()})
    def drift_metadata(self):
        self.f.f.config['hosts']['archlinux']['windowsCredentialProbe'].update(qgaSocketPath='/private/new/qga.sock',qemuPid=124,qemuStartTicks=457);self.f.f.write_config()
    def test_actual_old_generation_red_explicit_direct_green_preserves_history(self):
        self.drift_metadata();old=channel.prepare(self.root,'archlinux',self.corr)
        self.assertEqual('unknown',old['state']);self.assertEqual('outer_reuse',old['failurePhase'])
        fixed=self.invoke();self.assertEqual('ready',fixed['state']);self.assertEqual(['prepare'],[c[6] for c in self.calls])
        self.assert_legacy_unchanged();self.assertNotIn('inert private sentinel',json.dumps(fixed));self.assertFalse(fixed['nativeActionAllowed'])
    def test_unknown_same_original_observes_no_second_producer(self):
        self.result={'state':'unknown','correlationId':self.corr};self.returncode=3
        self.assertEqual('unknown',self.invoke()['state']);self.assertEqual('unknown',self.invoke()['state'])
        self.assertEqual(['prepare','status'],[c[6] for c in self.calls]);count=len(self.calls)
        self.assertEqual('unknown',self.invoke(corr='c'*32)['state']);self.assertEqual(count,len(self.calls));self.assert_legacy_unchanged()
    def test_selected_route_normal_builder_green_expired_refuses_no_fallback(self):
        self.drift_metadata();ready=self.invoke();self.assertEqual('ready',ready['state'])
        with mock.patch.object(subprocess,'Popen',side_effect=self.consumer):
            self.assertEqual('selected',selection.select_channel(self.root,'archlinux',self.corr,ready['receiptSha256'],direct=True)['state'])
            argv=transport.build_ssh_argv(transport.load_config(self.root),'archlinux',command=('printf','inert value'))
            self.assertEqual('none',argv[argv.index('-S')+1]);self.assertIn('ControlMaster=no',argv)
            inner=shlex.split(argv[-1]);self.assertEqual('/tmp/vpn-channel-'+self.corr+'/m',inner[inner.index('-S')+1]);self.assertIn('ProxyCommand=false',inner)
            self.assertNotIn('/private/inert-master',argv[-1]);self.assertEqual(['printf','inert value'],shlex.split(inner[-1]))
            self.result={'state':'ended','correlationId':self.corr,'prior':self.result,'gatewayBoot':self.result['master']['gatewayBoot']}
            with self.assertRaises(transport.SshConfigError):transport.build_ssh_argv(transport.load_config(self.root),'archlinux')
        self.assertEqual(1,sum(c[6]=='prepare' for c in self.calls));self.assert_legacy_unchanged()
    def test_secret_only_stdin_full_current_config_controls(self):
        capture={};ready=self.invoke(capture=capture.update);self.assertEqual('ready',ready['state']);self.assertTrue(capture['complete'])
        intent=json.loads((self.root/'.rag_index/ssh-direct-nested-channel'/(self.corr+'.intent.json')).read_bytes())
        self.assertNotIn('inert private sentinel',json.dumps(intent));self.assertEqual('direct',intent['transportMode'])
        before=len(self.calls);self.f.f.config['hosts']['archlinux']['password']='changed secret';self.f.f.write_config()
        self.assertEqual('unknown',self.invoke('status')['state']);self.assertEqual(before,len(self.calls))
    def closing_refusal(self,name):
        import shutil
        with tempfile.TemporaryDirectory(dir=self.root) as temp:
            source=Path(temp)/'source';source.mkdir()
            for leaf in direct._SOURCE_NAMES:shutil.copyfile(Path(direct.__file__).with_name(leaf),source/leaf)
            with mock.patch.object(direct,'__file__',str(source/'ssh_direct_nested_channel.py')):
                path=self.f.f.key if name=='key' else self.config_path if name=='config' else Path(direct.__file__)
                before=path.read_bytes();original=self.consumer
                def changed(argv,**kw):
                    child=original(argv,**kw);path.write_bytes(before+b' ');return child
                fd_before=len(os.listdir('/dev/fd'))
                try:
                    with mock.patch.object(subprocess,'Popen',side_effect=changed):value=direct.prepare(self.root,'archlinux',self.corr)
                    self.assertEqual('unknown',value['state']);self.assertEqual('closing',value['failurePhase'])
                finally:path.write_bytes(before)
                self.assertEqual(fd_before,len(os.listdir('/dev/fd')))
    def test_closing_key_mutation_refuses_and_closes_holders(self):self.closing_refusal('key')
    def test_closing_config_mutation_refuses_and_closes_holders(self):self.closing_refusal('config')
    def test_closing_source_mutation_refuses_and_closes_holders(self):self.closing_refusal('source')
    def test_missing_secret_bad_correlation_no_transport(self):
        self.f.f.config['hosts']['archlinux'].pop('password');self.f.f.write_config()
        self.assertEqual('unknown',self.invoke()['state']);self.assertEqual([],self.calls)
        self.assertEqual('unknown',self.invoke(corr='invalid')['state']);self.assertEqual([],self.calls)
    def test_actual_openssh_dead_socket_cause_is_not_authentication(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=str(Path(tmp)/'m');sock=socket.socket(socket.AF_UNIX);sock.bind(path);sock.close()
            result=subprocess.run(['ssh','-F','/dev/null','-S',path,'-O','check','unused'],capture_output=True,timeout=3)
            self.assertNotEqual(0,result.returncode);self.assertIn(b'Connection refused',result.stderr);self.assertNotIn(b'Permission denied',result.stderr)
    def test_original_multiline_builder_red_program_escaping_green(self):
        config=transport.load_config(self.root);gateway=transport._route_hosts(config.hosts,'archlinux')[-1]
        with self.assertRaises(transport.SshConfigError):transport.build_ssh_argv(config,gateway.alias,command=('python3','-c',channel._REMOTE))
        self.assertEqual('ready',self.invoke()['state']);self.assertEqual(channel._REMOTE,ast.literal_eval(ast.parse(self.calls[0][4],mode='eval').body.args[0]))

    def test_positive_ended_then_metadata_change_allows_new_intent_only(self):
        ready=self.invoke();prior=self.result
        self.result={'state':'ended','correlationId':self.corr,'prior':prior,'gatewayBoot':prior['master']['gatewayBoot']}
        self.assertEqual('ended',self.invoke('status')['state'])
        oldpath=self.root/'.rag_index/ssh-direct-nested-channel'/(self.corr+'.intent.json');old=oldpath.read_bytes()
        self.drift_metadata();new='c'*32
        self.result={**prior,'correlationId':new,'controlPath':'/tmp/vpn-channel-'+new+'/m'}
        self.assertEqual('ready',self.invoke(corr=new)['state'])
        self.assertEqual(old,oldpath.read_bytes());self.assertEqual(2,sum(c[6]=='prepare' for c in self.calls))
    def test_selected_source_and_full_caller_password_drift_refused(self):
        from dataclasses import replace
        ready=self.invoke()
        with mock.patch.object(subprocess,'Popen',side_effect=self.consumer):
            self.assertEqual('selected',selection.select_channel(self.root,'archlinux',self.corr,ready['receiptSha256'],direct=True)['state'])
            config=transport.load_config(self.root);config.hosts['archlinux']=replace(config.hosts['archlinux'],password='foreign secret')
            with self.assertRaises(transport.SshConfigError):transport.build_ssh_argv(config,'archlinux')
    def test_mcp_explicit_actions_and_finite_public_boundary(self):
        import uuid
        from agent_tools import mcp_server as server
        identity={'correlationId':str(uuid.UUID(self.corr))}
        retained=[]
        with mock.patch.object(server,'REPO_ROOT',self.root),mock.patch.object(subprocess,'Popen',side_effect=self.consumer),mock.patch.object(server.check_output_retention,'retain_observation_capture',side_effect=lambda *a,**kw:retained.append(kw['capture'])):
            prepared=server._ssh_workflow_impl('connection-direct-channel-prepare','archlinux',identity=identity)
            self.assertTrue(prepared['ok']);self.assertEqual('ready',prepared['state']);self.assertNotIn('inert private sentinel',json.dumps(prepared))
            selected=server._ssh_workflow_impl('connection-direct-channel-select','archlinux',identity={**identity,'receiptSha256':prepared['receiptSha256']})
            self.assertTrue(selected['ok']);self.assertEqual('selected',selected['state'])
            status=server._ssh_workflow_impl('connection-direct-channel-status','archlinux',identity=identity)
            self.assertTrue(status['ok']);self.assertEqual('ready',status['state'])
            for bad in ({**identity,'command':'true'}, {**identity,'correlationId':True}):
                value=server._ssh_workflow_impl('connection-direct-channel-prepare','archlinux',identity=bad)
                self.assertFalse(value['ok']);self.assertFalse(value['nativeActionAllowed']);self.assertFalse(value['replayAllowed'])
        self.assertEqual(1,sum(c[6]=='prepare' for c in self.calls));self.assertEqual(2,len(retained))
