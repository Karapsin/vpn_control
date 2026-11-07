"""Complete emitted preflight, physical files/sockets, native IO seams only.

No KVM, SSH, pacman or Windows native claim. Before/fix use the identical
boundary and assertions, preserving the original package-policy discrepancy.
"""
import builtins,contextlib,hashlib,io,json,os,pwd,grp,socket,stat,subprocess,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_deploy_remote as subject
from agent_tools import windows_vm_deploy as adapter
from agent_tools import arch_package_integrity as integrity
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests import test_native_vm_spec as specs

SYNC_DATABASE_ADVISORY=b"warning: database file for 'openai-chatgpt' does not exist (use '-Sy' to download)\n"


def preserved_sync_database_policy():
    path=Path(__file__).parent/'fixtures/arch_runtime_policy/sync_database.before.source';raw=path.read_bytes()
    provenance=json.loads(path.with_name('sync_database.provenance.json').read_text())
    expected='f35c1da6433caf42baa9a4f77fa6bcd86c6eaa064b94567f06ad2812e003f00d'
    if (hashlib.sha256(raw).hexdigest()!=expected or provenance['sourceSha256']!=expected
            or provenance['sourceBytes']!=len(raw)):raise AssertionError('preserved package-policy source changed')
    namespace={};exec(compile(raw,str(path),'exec'),namespace)
    return namespace['swtpm_runtime_owner_accepted']


@unittest.skipUnless(os.name=='posix','POSIX package/physical metadata boundary')
class WindowsVmPreflightTests(unittest.TestCase):
    def observe(self,producer=subject,*,alteration='uid',layout='a',directory_readable=True,missing_binary=None,repository_warning=False,pacman_advisory=b'',package_policy=None):
        with tempfile.TemporaryDirectory(prefix='vcv-',dir=Path('/tmp').resolve()) as tmp:
            base=Path(tmp).resolve();base.chmod(0o700)
            binaries=base/'bin';binaries.mkdir()
            for name in ('pacman','qemu-system-x86_64','qemu-img','swtpm','virt-fw-vars','xorriso'):
                path=binaries/name;path.write_bytes(b'PUBLIC_OWNED_BINARY_'+name.encode());path.chmod(0o755)
            ca=base/'ca';ca.mkdir(mode=0o750);ca.chmod(0o750)
            policy=base/'policy';policy.write_text('z /var/lib/swtpm-localca 0750 '+pwd.getpwuid(os.geteuid()).pw_name+' '+grp.getgrgid(ca.stat().st_gid).gr_name+'\n');policy.chmod(0o600)
            memory=base/'memory';memory.write_text('MemAvailable: 100000000 kB\n')
            kvm=base/'kvm';kvm.write_bytes(b'PUBLIC')
            spec=specs.request();spec.update(host='archlinux',root=str(base/('vm '+layout)))
            with socket.socket() as probe:probe.bind(('127.0.0.1',0));spec['vncPort']=probe.getsockname()[1]
            for name,value in spec['assets'].items():
                path=base/(layout+'-'+name);path.write_bytes(b'PUBLIC_'+name.encode());path.chmod(0o600)
                value.update(path=str(path),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            spec=FreshWindowsVmSpec.parse(spec)
            fixed={'/usr/lib/tmpfiles.d/swtpm.conf':policy,'/var/lib/swtpm-localca':ca,'/proc/meminfo':memory,'/dev/kvm':kvm}
            def path(value):return fixed.get(os.fspath(value),value) if not isinstance(value,int) else value
            real_open=os.open;real_stat=os.stat;real_builtin=builtins.open;calls=[]
            metadata_flag=getattr(os,'O_PATH',1<<29)
            def native_open(value,flags,*args,**kwargs):
                if str(value)=='/var/lib/swtpm-localca':
                    if not directory_readable and not flags&metadata_flag:raise PermissionError(13,'Declared runtime directory read restriction')
                    flags &= ~metadata_flag
                return real_open(path(value),flags,*args,**kwargs)
            def run(argv,**kw):
                calls.append(argv)
                self.assertEqual(str(binaries/'pacman'),argv[0])
                isolated=argv[1:7]==['--config','/dev/null','--root','/','--dbpath','/var/lib/pacman']
                arguments=argv[7:] if isolated else argv[1:]
                self.assertIn(arguments[0],('-Q','-Qkk','-Ql','-Qoq'))
                # A repository warning needs inherited pacman configuration; the
                # package-policy advisory reaches every query, isolated or not.
                nuisance=(SYNC_DATABASE_ADVISORY if repository_warning and not isolated else b'')+pacman_advisory
                if arguments[0]=='-Qoq':return subprocess.CompletedProcess(argv,0,b'libisoburn\n',nuisance)
                if arguments[0]=='-Q':return subprocess.CompletedProcess(argv,0,(arguments[1]+' 42.7-3\n').encode(),nuisance)
                if arguments[0]=='-Ql':return subprocess.CompletedProcess(argv,0,b'swtpm /usr/lib/tmpfiles.d/swtpm.conf\n',nuisance)
                if arguments[1]=='qemu-img' and alteration=='required-package':
                    return subprocess.CompletedProcess(argv,1,b'qemu-img: 24 total files, 1 altered file\n',nuisance+b'warning: qemu-img: /usr/bin/qemu-img (SHA256 checksum mismatch)\n')
                if arguments[1]=='swtpm' and alteration:
                    stderr=b'warning: swtpm: /var/lib/swtpm-localca (UID mismatch)\n'
                    if alteration=='extra':stderr+=b'warning: swtpm: /usr/bin/swtpm (SHA256 checksum mismatch)\n'
                    return subprocess.CompletedProcess(argv,1,b'swtpm: 259 total files, 1 altered file\n',nuisance+stderr)
                return subprocess.CompletedProcess(argv,0,b'',pacman_advisory)
            stream=io.StringIO()
            with (mock.patch.object(producer,'swtpm_runtime_owner_accepted',package_policy) if package_policy is not None else contextlib.nullcontext()):
                body=producer.program(spec,'preflight')
            with mock.patch.object(os,'O_PATH',metadata_flag,create=True),mock.patch.object(os,'open',side_effect=native_open),mock.patch.object(os,'stat',side_effect=lambda p,*a,**kw:real_stat(path(p),*a,**kw)),mock.patch.object(builtins,'open',side_effect=lambda p,*a,**kw:real_builtin(path(p),*a,**kw)),mock.patch('shutil.which',side_effect=lambda n,**kw:None if n==missing_binary else str(binaries/n)),mock.patch.object(subprocess,'run',side_effect=run),mock.patch('shutil.disk_usage',return_value=types.SimpleNamespace(free=1024**4)),contextlib.redirect_stdout(stream):
                exec(compile(body,'complete saved VM preflight','exec'),{'__name__':'__main__'})
            self.assertFalse(Path(spec.root).exists())
            if missing_binary is None:self.assertTrue(calls)
            return json.loads(stream.getvalue())
    def test_unavailable_sync_repository_cannot_block_local_installed_file_verification(self):
        self.assertEqual('qualified',self.observe(repository_warning=True)['state'])
        self.assertEqual('package_integrity',self.observe(repository_warning=True,alteration='extra')['reason'])
    def test_preserved_repository_configuration_failure_is_causal(self):
        path=Path(__file__).parent/'fixtures/local_package_database_query/windows_vm_deploy_remote.py.before.source'
        raw=path.read_bytes()
        self.assertEqual('f057a59b70cb8e3a79d520bf435fc246725a8ee54a7cb97e5d754b9a328515f2',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._local_package_database_before');old.__package__='agent_tools';old.__file__=str(path)
        exec(compile(raw,str(path),'exec'),old.__dict__)
        # The original failure paired this producer with the strict policy preserved
        # from the same base; the current policy alone tolerates one such advisory.
        self.assertEqual('blocked',self.observe(old,repository_warning=True,package_policy=preserved_sync_database_policy())['state'])
        self.assertEqual('qualified',self.observe(repository_warning=True)['state'])
    def test_runtime_policy_owner_is_accepted_without_chown_or_version_pin(self):
        self.assertEqual('qualified',self.observe()['state'])
        self.assertEqual('qualified',self.observe(layout='another layout')['state'])
    def test_other_package_alterations_are_blocked(self):
        self.assertEqual('package_integrity',self.observe(alteration='extra')['reason'])
    def test_missing_sync_database_advisory_keeps_complete_preflight_qualified(self):
        self.assertEqual('qualified',self.observe(pacman_advisory=SYNC_DATABASE_ADVISORY)['state'])
    def test_preserved_sync_database_guard_blocks_identical_complete_preflight(self):
        self.assertEqual('package_integrity',self.observe(pacman_advisory=SYNC_DATABASE_ADVISORY,package_policy=preserved_sync_database_policy())['reason'])
        self.assertEqual('qualified',self.observe(pacman_advisory=SYNC_DATABASE_ADVISORY)['state'])
    def test_sync_database_advisory_does_not_hide_package_alterations(self):
        for alteration in ('extra','required-package'):
            with self.subTest(alteration=alteration):
                self.assertEqual('package_integrity',self.observe(alteration=alteration,pacman_advisory=SYNC_DATABASE_ADVISORY)['reason'])
    def test_missing_seed_builder_is_rejected_before_vm_creation(self):
        self.assertEqual('binary_unavailable',self.observe(missing_binary='xorriso')['reason'])
    def test_preserved_complete_before_producer_exposes_same_causal_failure(self):
        path=Path(__file__).parent/'fixtures/arch_runtime_policy/before.source';raw=path.read_bytes()
        self.assertEqual('ac313a8f38da94312733d1d0cc84829ae055bd9cbe20f2cb398590f0c5f72885',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._runtime_policy_before');old.__package__='agent_tools';old.__file__=str(path)
        exec(compile(raw,str(path),'exec'),old.__dict__)
        self.assertEqual('blocked',self.observe(old)['state'])
        self.assertEqual('qualified',self.observe()['state'])
    def test_metadata_only_directory_open_does_not_require_reading_tpm_ca(self):
        self.assertEqual('qualified',self.observe(directory_readable=False)['state'])
    def test_preserved_permission_failure_is_causal_on_same_complete_producer(self):
        path=Path(__file__).parent/'fixtures/arch_runtime_policy/permission.before.source';raw=path.read_bytes()
        self.assertEqual('ddfcbb3af63fb6943fdba15dfa0334eda8025a1044142e1fc04615bb4f55c545',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._runtime_permission_before');old.__package__='agent_tools';old.__file__=str(path)
        exec(compile(raw,str(path),'exec'),old.__dict__)
        self.assertEqual('blocked',self.observe(old,directory_readable=False)['state'])
        self.assertEqual('qualified',self.observe(directory_readable=False)['state'])
    def test_saved_gateway_is_whole_and_only_invokes_observed_filename(self):
        receipt={'path':'/tmp/vpn-control-windows-caller-'+'a'*32+'/caller.py','sha256':'ab'*32,'bytes':123,'principal':'current_user'}
        raw=adapter.gateway_program(receipt)
        namespace={};exec(compile(raw,'complete saved VM gateway','exec'),namespace)
        import shlex
        command=shlex.split(namespace['COMMAND'])
        self.assertEqual(receipt['path'],command[-3]);self.assertEqual(receipt['sha256'],command[-2])
        self.assertEqual(receipt['principal'],namespace['PRINCIPAL']);self.assertLess(len(namespace['COMMAND'].encode()),60000)

class VmDeployMcpBoundaryTests(unittest.TestCase):
    def setUp(self):
        from contextlib import nullcontext
        from agent_tools import readiness_vm_dispatch
        # This suite isolates schema/adapter routing. Generated socket callers
        # and native fixtures exercise the actual readiness boundary separately.
        admission = mock.patch.object(readiness_vm_dispatch, 'admitted_dispatch', return_value=nullcontext())
        admission.start(); self.addCleanup(admission.stop)
        from agent_tools.tests.route_adapter import bind_cached_routes
        from agent_tools import mcp_server as _route_server
        bind_cached_routes(self,_route_server,
            'readiness_vm_dispatch',
            'arch_package_integrity',
            'windows_vm_deploy',
            'windows_vm_deploy_remote',
        )

    def test_unsupported_coordinator_refuses_before_any_files_or_transport(self):
        with mock.patch.object(adapter.direct,'coordinator_capable',return_value=False),mock.patch.object(adapter,'Path',side_effect=AssertionError('filesystem must not open')):
            with self.assertRaisesRegex(ValueError,'unsupported_deployment_coordinator'):
                adapter.preflight('unopened',specs.request())

    def test_finite_media_frame_qualification_and_secure_schemas_reject_extra_authority(self):
        from agent_tools import mcp_server
        identity=specs.request()['deploymentId'];operation='e314d08a-80eb-4d98-9abe-0c1b245a3807'
        for action,arguments in (
            ('windows-vm-deploy-media',{'spec':specs.request()}),
            ('windows-vm-deploy-frame',{'deploymentId':identity,'operationId':operation}),
            ('windows-vm-deploy-frame-collect',{'deploymentId':identity,'operationId':operation}),
            ('windows-vm-deploy-qualify',{'deploymentId':identity,'operationId':operation,'credentialFile':'/INERT'}),
            ('windows-vm-deploy-qualify-status',{'deploymentId':identity,'operationId':operation,'credentialFile':'/INERT'}),
            ('windows-vm-deploy-secure',{'deploymentId':identity,'operationId':operation,'credentialFile':'/INERT'}),
            ('windows-vm-deploy-secure-status',{'deploymentId':identity,'operationId':operation,'credentialFile':'/INERT'})):
            with self.subTest(action=action),mock.patch.object(mcp_server,'_agent_module',side_effect=AssertionError('no adapter load allowed')):
                for extra in ({'command':'PUBLIC'},{'ready':True},{'path':'/PREVIOUS_ATTEMPT'}):
                    self.assertFalse(mcp_server._vm_workflow_impl(action,{**arguments,**extra})['ok'])

    def test_extra_commands_or_authority_flags_refuse_before_transport(self):
        from agent_tools import mcp_server
        with mock.patch.object(adapter,'_execute',side_effect=AssertionError('transport must not run')):
            for request in ({'spec':{**specs.request(),'command':'PUBLIC'}},{'spec':specs.request(),'ready':True},{'spec':'PUBLIC'}):
                value=mcp_server._vm_workflow_impl('windows-vm-deploy-preflight',request)
                self.assertFalse(value['ok'])

    def test_stop_and_closed_status_route_only_original_identity_and_reject_extra_authority(self):
        from agent_tools import mcp_server
        identity=specs.request()['deploymentId'];inputs={'deploymentId':identity,'credentialFile':'/INERT_PRIVATE_PATH'}
        result={'state':'stopped-observed','reason':None,'positiveAbsence':True,'productReady':False,
                'qemu':{'pid':123,'startTicks':456},'swtpm':{'pid':124,'startTicks':457},
                'nativeActionAllowed':False,'replayAllowed':False}
        for action,method in (('windows-vm-deploy-stop','stop'),('windows-vm-deploy-status','status')):
            with mock.patch.object(adapter,method,return_value=result) as operation:
                value=mcp_server._vm_workflow_impl(action,inputs)
                self.assertTrue(value['ok']);self.assertTrue(value['positiveAbsence'])
                operation.assert_called_once_with(mcp_server.REPO_ROOT,identity,inputs['credentialFile'])
                operation.reset_mock()
                self.assertFalse(mcp_server._vm_workflow_impl(action,{**inputs,'force':True})['ok'])
                operation.assert_not_called()

class PackagePolicyTests(unittest.TestCase):
    def arguments(self):
        return [1,b'swtpm: 259 total files, 1 altered file\n',b'warning: swtpm: /var/lib/swtpm-localca (UID mismatch)\n','z /var/lib/swtpm-localca 0750 tss root\n',{'mode':stat.S_IFDIR|0o750,'uid':972,'gid':0},972,0]

    def test_missing_sync_database_advisory_preserves_single_uid_policy(self):
        for name in ('openai-chatgpt','another-repo','a'*128):
            args=self.arguments();args[2]=SYNC_DATABASE_ADVISORY.replace(b'openai-chatgpt',name.encode())+args[2]
            with self.subTest(repository=name):self.assertTrue(integrity.swtpm_runtime_owner_accepted(*args))

    def test_preserved_sync_database_guard_rejects_same_valid_helper_observation(self):
        args=self.arguments();args[2]=SYNC_DATABASE_ADVISORY+args[2]
        self.assertFalse(preserved_sync_database_policy()(*args))
        self.assertTrue(integrity.swtpm_runtime_owner_accepted(*args))

    def test_sync_database_advisory_keeps_exact_stderr_and_package_guards(self):
        args=self.arguments();uid_warning=args[2];args[2]=SYNC_DATABASE_ADVISORY+uid_warning
        invalid_stderr=(SYNC_DATABASE_ADVISORY,uid_warning+SYNC_DATABASE_ADVISORY,
            SYNC_DATABASE_ADVISORY*2+uid_warning,SYNC_DATABASE_ADVISORY+uid_warning*2,
            SYNC_DATABASE_ADVISORY+b'unknown warning\n'+uid_warning,
            SYNC_DATABASE_ADVISORY+uid_warning+b'warning: swtpm: /usr/bin/swtpm (SHA256 checksum mismatch)\n',
            SYNC_DATABASE_ADVISORY.replace(b'openai-chatgpt',b'a'*129)+uid_warning,
            SYNC_DATABASE_ADVISORY.replace(b'openai-chatgpt',b'')+uid_warning,
            SYNC_DATABASE_ADVISORY.replace(b'openai-chatgpt',b"repo'name")+uid_warning,
            SYNC_DATABASE_ADVISORY.replace(b'openai-chatgpt',b'repo/name')+uid_warning,
            SYNC_DATABASE_ADVISORY.replace(b'openai-chatgpt',b'repo\x00name')+uid_warning,
            SYNC_DATABASE_ADVISORY.replace(b'\n',b'\r\n')+uid_warning,
            SYNC_DATABASE_ADVISORY.replace(b"'-Sy'",b"'-Syy'")+uid_warning,
            SYNC_DATABASE_ADVISORY+uid_warning+b'\n',SYNC_DATABASE_ADVISORY+uid_warning+b'\x00')
        for value in invalid_stderr:
            changed=list(args);changed[2]=value
            with self.subTest(stderr=value):self.assertFalse(integrity.swtpm_runtime_owner_accepted(*changed))
        for index,value in ((0,0),(0,True),(1,b'swtpm: 259 total files, 2 altered files\n'),
                (1,args[1]+b'ignored\n'),(3,args[3]*2),(3,args[3].replace('0750','0777')),
                (4,{**args[4],'uid':0}),(4,{**args[4],'gid':1}),(4,{**args[4],'mode':stat.S_IFDIR|0o777}),(5,True)):
            changed=list(args);changed[index]=value
            with self.subTest(index=index,value=value):self.assertFalse(integrity.swtpm_runtime_owner_accepted(*changed))

    def test_only_exact_policy_and_metadata_may_explain_the_single_uid_difference(self):
        args=self.arguments()
        self.assertTrue(integrity.swtpm_runtime_owner_accepted(*args))
        for index,value in ((0,0),(1,b'bad'),(2,args[2]+b'other warning'),(3,args[3]*2),(3,args[3].replace('0750','0777')),(4,{**args[4],'uid':0}),(4,{**args[4],'mode':stat.S_IFREG|0o750}),(5,True)):
            changed=list(args);changed[index]=value
            self.assertFalse(integrity.swtpm_runtime_owner_accepted(*changed))

if __name__=='__main__':unittest.main()
