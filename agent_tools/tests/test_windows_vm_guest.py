"""Complete fixed guest operations with physical records and finite QGA seams."""
import base64,builtins,hashlib,inspect,io,json,os,shutil,socket,subprocess,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_guest as guest


@unittest.skipUnless(os.name=='posix','POSIX host receipt fixture')
class GuestQualificationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        listener=socket.socket(socket.AF_UNIX);self.addCleanup(listener.close);listener.bind(str(self.root/'qga.sock'))
        self.operation=str(uuid.uuid4());self.setup={'imageName':'Windows 11 Enterprise Evaluation','locale':'en-US','user':'fixtureUser','administrator':'fixtureAdmin'}
        self.row={'pid':4242};self.records={'qemu-started.json':self.row,'installer-image.json':{'installerSha256':'a'*64,'image':{'name':self.setup['imageName'],'editionId':'EnterpriseEval'}}}
        (self.root/'installer-image.json').write_text(json.dumps(self.records['installer-image.json']))
        self.spec={'assets':{'installer':{'sha256':'a'*64}}};self.calls=[];self.submission_error=False
        self.result={'nonce':self.operation,'fixturePrincipal':'S-1-5-18',
                     'os':{'caption':'Microsoft Windows 11 Enterprise Evaluation','version':'10.0.26200','bootTime':'test','productName':'test','editionId':'EnterpriseEval','displayVersion':'25H2','build':'26200','ubr':1,'locale':'en-US'},
                     'computer':{'name':'fixture','loggedOn':'fixture\\fixtureUser','partOfDomain':False},
                     'user':{'name':'fixtureUser','sid':'S-1-5-21-1-2-3-1001','enabled':True,'isAdministrator':False,'isUsersMember':True,'profileRoot':'C:\\Users\\fixtureUser'},
                     'administrator':{'name':'fixtureAdmin','sid':'S-1-5-21-1-2-3-1000','enabled':True,'isAdministrator':True},
                     'setup':{'systemSetupInProgress':0,'oobeInProgress':0,'imageState':'IMAGE_STATE_COMPLETE','taskState':'Ready','taskResult':0,'ready':{'state':'ready','installerExit':0}},
                     'guestAgent':{'state':'Running','startMode':'Auto','path':'fixture','pid':123}}
        self.terminal={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(self.result).encode()).decode()}
        namespace={'CONTEXT':{'hostBootId':'FIXTURE_BOOT'},'PS_SCRIPT':guest.powershell_source(self.setup,self.operation),
                   'call':self.call,'validate_setup_result':guest.validate_setup_result}
        exec(compile(inspect.getsource(guest.qualify_instance),'actual qualification','exec'),namespace)
        self.subject=namespace['qualify_instance']
    def read(self,name):
        if name not in self.records:raise FileNotFoundError(name)
        return self.records[name]
    def save(self,name,value):
        path=self.root/name
        with path.open('xb')as stream:stream.write(value if type(value)is bytes else json.dumps(value).encode())
        self.records[name]=value
    def call(self,path,command,arguments,**kwargs):
        self.calls.append(command)
        if command=='guest-exec':
            self.assertEqual(str(self.root/'qga.sock'),path)
            if self.submission_error:raise ValueError('instance_fixture_lost_ack')
            self.assertEqual('powershell.exe',arguments['path']);return {'pid':31415}
        self.assertEqual('guest-exec-status',command);self.assertEqual({'pid':31415},arguments);return self.terminal
    def run_subject(self,status_only=False):
        real=builtins.open
        def opened(path,*args,**kwargs):
            return io.StringIO('FIXTURE_BOOT') if str(path)=='/proc/sys/kernel/random/boot_id' else real(path,*args,**kwargs)
        with mock.patch.object(builtins,'open',side_effect=opened):
            return self.subject(self.spec,self.setup,self.operation,status_only,self.root,self.read,self.save,
                                lambda r:self.assertEqual(self.row,r),lambda *_:None,lambda:None,lambda:None,
                                lambda:{'guestAgentReady':True,'ordinarySessionObserved':True})
    def test_full_terminal_collect_preserves_original_and_never_resubmits(self):
        value=self.run_subject();self.assertTrue(value['setupReady']);self.assertFalse(value['productReady'])
        records={n:(self.root/n).read_bytes()for n in (self.root.iterdir())if n.is_file()}
        self.calls.clear();self.assertEqual(value,self.run_subject(True));self.assertEqual([],self.calls)
        for n,raw in records.items():self.assertEqual(raw,(self.root/n).read_bytes())
        with self.assertRaises(FileExistsError):self.run_subject()
        self.assertEqual([],self.calls)
    def test_lost_ack_is_retained_and_status_cannot_replay_it(self):
        self.submission_error=True
        with self.assertRaisesRegex(ValueError,'lost_ack'):self.run_subject()
        self.assertEqual(['guest-exec'],self.calls);self.calls.clear()
        with self.assertRaises(FileNotFoundError):self.run_subject(True)
        with self.assertRaises(FileExistsError):self.run_subject()
        self.assertEqual([],self.calls)
    def test_progress_error_retains_original_terminal_and_is_not_success(self):
        self.terminal['err-data']=base64.b64encode(b'#< CLIXML progress').decode()
        with self.assertRaisesRegex(ValueError,'instance_guest_admission_output'):self.run_subject()
        self.calls.clear()
        with self.assertRaisesRegex(ValueError,'instance_guest_admission_output'):self.run_subject(True)
        self.assertEqual([],self.calls)
    def test_unrecorded_media_and_admin_ordinary_user_cannot_be_ready(self):
        del self.records['installer-image.json'];(self.root/'installer-image.json').unlink();self.assertFalse(self.run_subject()['setupReady'])

    def test_secure_uses_stdin_then_collect_only_finishes_cleanup_without_replay(self):
        namespace={'CONTEXT':{'hostBootId':'FIXTURE_BOOT'},'SECURE_SCRIPT':guest.secure_source(self.setup,self.operation),
                   'SECURE_CHECK_SCRIPT':'FIXED_ADMISSION','qualify_instance':mock.Mock(return_value={'state':'setup-observed','setupReady':True})}
        password='INERT_SECRET_'+'a'*24;executions=[];ejections=[];inserted=True
        terminal={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps({'nonce':self.operation,'principal':'S-1-5-18','passwordVerified':True,'automaticLogonDisabled':True,'setupCachesRemoved':True,'setupTaskDisabled':True}).encode()).decode()}
        def call(path,command,arguments,**kwargs):
            if command=='guest-exec':
                executions.append(command);payload=json.loads(base64.b64decode(arguments['input-data']))
                self.assertEqual(password,payload['password']);self.assertNotIn(password,str(arguments['arg']))
                return {'pid':31415}
            self.assertEqual({'pid':31415},arguments);return terminal
        def qmp(command,arguments=None):
            nonlocal inserted
            if command=='eject':
                self.assertEqual({'device':'seed','force':True},arguments);ejections.append(command);inserted=False;return {}
            return [{'device':'seed',**({'inserted':{'file':str(self.root/'seed.iso')}}if inserted else {})}]
        namespace['call']=call
        exec(compile(inspect.getsource(guest.secure_instance),'actual secure setup','exec'),namespace)
        (self.root/'seed').mkdir(mode=0o700)
        for name in ('seed.iso','seed/Autounattend.xml','seed/initialize.ps1','seed/install-agent.ps1'):
            path=self.root/name;path.write_bytes(b'INERT_SETUP');path.chmod(0o600)
        real=builtins.open
        def opened(path,*args,**kwargs):return io.StringIO('FIXTURE_BOOT')if str(path)=='/proc/sys/kernel/random/boot_id'else real(path,*args,**kwargs)
        def run(status_only):
            with mock.patch.object(builtins,'open',side_effect=opened),mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(json.dumps({'password':password}).encode()))):
                return namespace['secure_instance'](self.spec,self.setup,self.operation,status_only,self.root,self.read,self.save,lambda r:self.assertEqual(self.row,r),lambda *_:None,lambda:None,lambda:None,lambda:{},qmp)
        result=run(False);self.assertTrue(result['setupSecured']);self.assertFalse(result['productReady'])
        self.assertFalse((self.root/'seed').exists());self.assertFalse((self.root/'seed.iso').exists())
        self.assertEqual(result,run(True));self.assertEqual(['guest-exec'],executions);self.assertEqual(['eject'],ejections)
        with self.assertRaises(FileExistsError):run(False)
        self.assertEqual(['guest-exec'],executions);self.assertEqual(['eject'],ejections)


class FixedPowerShellTests(unittest.TestCase):
    def test_validated_binding_and_secret_stdin_are_distinct_from_executable_credentials(self):
        folder=Path(__file__).parent/'fixtures/guest_progress';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        settings={'imageName':'Windows 11 Pro','locale':'en-US','user':'otherUser','administrator':'otherAdmin'}
        identity=str(uuid.uuid4());source=guest.powershell_source(settings,identity)
        self.assertIn("$ExpectedUser='otherUser'",source);self.assertIn(identity,source)
        secure=guest.secure_source(settings,identity)
        self.assertIn('[Console]::In.ReadToEnd()',secure)
        self.assertIn(guest.SECURE_SETUP,secure)
        self.assertNotIn('final-administrator.secret',secure)

    @unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'actual Windows PowerShell5.1 streams')
    def test_actual_progress_before_is_stderr_fixed_is_clean_real_errors_remain_errors(self):
        # Exercise the actual production source constructor through native
        # EncodedCommand, the same path which emitted the retained CLIXML.
        body="$ErrorActionPreference='Stop'\nWrite-Progress -Activity 'Module preparation control' -Status 'Loading' -PercentComplete 50\n[Console]::WriteLine('{\"ok\":true}')\n"
        def run(source):
            encoded=base64.b64encode(source.encode('utf-16le')).decode()
            return subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],capture_output=True,timeout=20)
        before=run(body);after=run(guest.quiet_source(body))
        self.assertEqual(0,before.returncode);self.assertIn(b'CLIXML',before.stderr);self.assertIn(b'progress',before.stderr)
        self.assertEqual(0,after.returncode,after.stderr.decode('utf8','replace'));self.assertEqual(b'',after.stderr)
        self.assertEqual({'ok':True},json.loads(after.stdout.decode('utf-8-sig')))
        failed=run(guest.quiet_source("$ErrorActionPreference='Stop'\nthrow 'ORIGINAL_ERROR_CONTROL'"))
        self.assertNotEqual(0,failed.returncode);self.assertIn(b'ORIGINAL_ERROR_CONTROL',failed.stderr)


if __name__=='__main__':unittest.main()
