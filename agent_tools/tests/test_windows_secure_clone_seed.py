"""Secure cleanup covers the per-clone seed script; anything unknown still refuses.

The whole beforeimage reproduces the clone failure: the seed directory keeps
clone-specialize.ps1, so rmdir raises after the credential effects already ran.
Status then repeats the same refusal, never another credential submission.
"""
import ast,base64,builtins,hashlib,io,json,os,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import windows_vm_guest as guest

FIXTURE=Path(__file__).parent/'fixtures/windows_secure_clone_seed'


def before_source():
    raw=(FIXTURE/'before.source').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']:
        raise AssertionError('secure clone seed beforeimage changed')
    return raw.decode()


def function_source(text):
    node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='secure_instance')
    return ast.get_source_segment(text,node)


CURRENT=Path(guest.__file__).read_text()


@unittest.skipUnless(os.name=='posix','POSIX host receipt fixture')
class SecureCloneSeedTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.operation=str(uuid.uuid4());self.password='INERT_SECRET_'+'a'*24;self.executions=[];self.ejections=[];self.inserted=True;self.records={'qemu-started.json':{'pid':4242}}
        (self.root/'seed').mkdir(mode=0o700)
        import socket
        listener=socket.socket(socket.AF_UNIX);self.addCleanup(listener.close);listener.bind(str(self.root/'qga.sock'))

    def seed(self,*extra):
        for name in ('seed.iso','seed/Autounattend.xml','seed/initialize.ps1','seed/install-agent.ps1',*extra):
            path=self.root/name;path.write_bytes(b'INERT_SETUP');path.chmod(0o600)

    def read(self,name):
        if name not in self.records:raise FileNotFoundError(name)
        return self.records[name]

    def save(self,name,value):
        with (self.root/name).open('xb')as stream:stream.write(value if type(value)is bytes else json.dumps(value).encode())
        self.records[name]=value

    def call(self,path,command,arguments,**kwargs):
        if command=='guest-exec':
            self.executions.append(command);return {'pid':31415}
        self.assertEqual({'pid':31415},arguments)
        body={'nonce':self.operation,'principal':'S-1-5-18','passwordVerified':True,'automaticLogonDisabled':True,'setupCachesRemoved':True,'setupTaskDisabled':True}
        return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(body).encode()).decode()}

    def qmp(self,command,arguments=None):
        if command=='eject':
            self.ejections.append(command);self.inserted=False;return {}
        return [{'device':'seed',**({'inserted':{'file':str(self.root/'seed.iso')}}if self.inserted else {})}]

    def run_secure(self,text,status_only):
        namespace={'CONTEXT':{'hostBootId':'FIXTURE_BOOT'},'SECURE_SCRIPT':'FIXED_SECURE','SECURE_CHECK_SCRIPT':'FIXED_ADMISSION','call':self.call,
                   'qualify_instance':mock.Mock(return_value={'state':'setup-observed','setupReady':True})}
        exec(compile(function_source(text),'actual secure setup','exec'),namespace)
        real=builtins.open
        def opened(path,*args,**kwargs):return io.StringIO('FIXTURE_BOOT')if str(path)=='/proc/sys/kernel/random/boot_id'else real(path,*args,**kwargs)
        stdin=types.SimpleNamespace(buffer=io.BytesIO(json.dumps({'password':self.password}).encode()))
        with mock.patch.object(builtins,'open',side_effect=opened),mock.patch('sys.stdin',stdin):
            return namespace['secure_instance']({},{},self.operation,status_only,self.root,self.read,self.save,lambda row:None,lambda *_:None,lambda:None,lambda:None,lambda:{},self.qmp)

    def test_before_clone_seed_fails_after_the_one_credential_effect(self):
        self.seed('seed/clone-specialize.ps1')
        with self.assertRaises(OSError):self.run_secure(before_source(),False)
        self.assertEqual(['guest-exec'],self.executions);self.assertEqual(['eject'],self.ejections)
        with self.assertRaises(OSError):self.run_secure(before_source(),True)
        self.assertEqual(['guest-exec'],self.executions,'status must never resubmit the credential')

    def test_fixed_clone_seed_finishes_cleanup_once(self):
        self.seed('seed/clone-specialize.ps1')
        result=self.run_secure(CURRENT,False)
        self.assertEqual({'state':'secured-observed','operationId':self.operation,'setupSecured':True,'productReady':False},result)
        self.assertFalse((self.root/'seed').exists());self.assertFalse((self.root/'seed.iso').exists())
        self.assertEqual(result,self.run_secure(CURRENT,True))
        self.assertEqual(['guest-exec'],self.executions);self.assertEqual(['eject'],self.ejections)

    def test_blank_install_seed_is_unchanged(self):
        self.seed()
        self.assertEqual('secured-observed',self.run_secure(CURRENT,False)['state'])
        self.assertFalse((self.root/'seed').exists())

    def test_unknown_seed_file_still_refuses_and_is_kept(self):
        self.seed('seed/clone-specialize.ps1','seed/unexpected.bin')
        with self.assertRaises(OSError):self.run_secure(CURRENT,False)
        self.assertTrue((self.root/'seed/unexpected.bin').exists())

    def test_clone_specialize_identity_is_still_checked(self):
        self.seed('seed/clone-specialize.ps1');(self.root/'seed/clone-specialize.ps1').chmod(0o644)
        with self.assertRaisesRegex(ValueError,'instance_seed_cleanup_identity'):self.run_secure(CURRENT,False)
        self.assertTrue((self.root/'seed/clone-specialize.ps1').exists())


if __name__=='__main__':unittest.main()
