"""Complete emitted census import regression, with declared isolated inert IO boundaries."""
import ast,hashlib,json,os,subprocess,sys,unittest
from pathlib import Path
from agent_tools.tests import descriptor_window
FIXTURES=Path(__file__).with_name('fixtures')/'windows_census_child_imports'
PINS={'inert_consumer.py': {'bytes': 3370, 'sha256': '22b81eeeb2ce8245a97892632b4987fcb230689648afbc13054caa87c936991e'}, 'after.py.txt': {'bytes': 9373, 'sha256': '392f5e9778de50fe9598d01c80a6e2934ed9358ae7c1cc07f7d36ce569c4dbb1'}, 'metadata.public.json': {'bytes': 984, 'sha256': '423d779113f869a204e7c1fa630d579c740953a58a10f4a1c3809d3c4f5943a8'}, 'before.py.txt': {'bytes': 9362, 'sha256': '7fd5c034e02760c760661e07cbb2c5e1b6c9a51a0da2c1ac77918896d272350a'}}

def read_fixture(name):
    pin=PINS[name]
    with (FIXTURES/name).open('rb')as source:raw=source.read(pin['bytes']+1)
    if len(raw)!=pin['bytes'] or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise ValueError('census_import_fixture_pin')
    return raw

# Runs in a fresh child so the existing public consumer's Path hook is isolated.
# These strengthen its declared host boundaries: no live process/disk read occurs.
WORKER=r'''import hashlib,json,os,sys,types
from pathlib import Path
consumer,source=json.loads(sys.stdin.buffer.read(20000))
real_text=Path.read_text;real_vfs=os.statvfs
calls=[]
def owned_text(path,*args,**kwargs):
    value=str(path)
    if value.startswith('/proc/4321/')or value.startswith('/proc/4322/'):
        calls.append('synthetic_h10_absent');raise FileNotFoundError('owned synthetic process')
    if value=='/proc/meminfo':return 'MemAvailable: 12345678 kB\n'
    if value=='/proc/sys/kernel/random/boot_id':return '11111111-2222-3333-4444-555555555555\n'
    raise AssertionError('FOREIGN_HOST_READ')
def owned_vfs(path):
    if str(path)not in ('/tmp','/synthetic/owner-home'):raise AssertionError('FOREIGN_DISK_READ')
    calls.append('synthetic_disk');return types.SimpleNamespace(f_bavail=100000,f_frsize=4096)
Path.read_text=owned_text;os.statvfs=owned_vfs
try:
    namespace={'__name__':'owned_inert_census_consumer'}
    exec(compile(consumer,'exact-public-inert-consumer','exec'),namespace)
    result=namespace['control'](source)
    result['declaredHostBoundaryCalls']=calls
    print(json.dumps(result,sort_keys=True))
finally:
    Path.read_text=real_text;os.statvfs=real_vfs
'''

@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW') and Path('/dev/fd').is_dir(),'requires owned POSIX inert child')
class WindowsCensusChildImportsTests(unittest.TestCase):
    def setUp(self):
        # The whole case is the FD window (earlier serial cases' cyclic owners are finalized first).
        self.descriptors=descriptor_window.begin();self.addCleanup(descriptor_window.restore,self.descriptors);self.addCleanup(self.assert_fd_count)
        before=read_fixture('before.py.txt');after=read_fixture('after.py.txt')
        self.assertEqual(before.replace(b'import os,sys,json,stat,socket,secrets,time,base64,hashlib\n',b'import os,sys,json,stat,socket,secrets,time,base64,hashlib,subprocess\n',1),after)
        # No used function/main-body change is accepted beside that one import.
        a=ast.parse(before);b=ast.parse(after);a.body[0]=b.body[0]
        self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(b,include_attributes=False))
        metadata=json.loads(read_fixture('metadata.public.json'));self.assertIs(metadata['native'],False);self.assertIs(metadata['rawPrivateExport'],False)
    def assert_fd_count(self):descriptor_window.check(self,descriptor_window.end(self.descriptors),'test')
    def control(self,name):
        envelope=json.dumps([read_fixture('inert_consumer.py').decode(),read_fixture(name).decode()]).encode()
        self.assertLessEqual(len(envelope),20000)
        env=dict(os.environ);env.pop('DYLD_INSERT_LIBRARIES',None)
        result=subprocess.run([sys.executable,'-I','-B','-c',WORKER],input=envelope,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,env=env)
        self.assertEqual(0,result.returncode,result.stderr.decode('utf-8','replace'));self.assertFalse(result.stderr)
        self.assertLessEqual(len(result.stdout),16384)
        return json.loads(result.stdout)
    def test_actual_before_stops_at_missing_subprocess_after_two_inert_QGA_calls(self):
        value=self.control('before.py.txt')
        self.assertEqual('RED',value['state']);self.assertEqual('NameError',value['errorClass']);self.assertEqual('subprocess',value['identifier'])
        self.assertEqual(['guest-exec','guest-exec-status'],value['calls'])
        self.assertTrue(value['declaredHostBoundaryCalls']);self.assertNotIn('stdoutJson',value)
    def test_exact_one_import_fix_completes_entire_main_JSON(self):
        value=self.control('after.py.txt');self.assertEqual('PASS',value['state']);self.assertEqual(['guest-exec','guest-exec-status'],value['calls'])
        data=value['stdoutJson'];self.assertEqual({'uid','boot','memAvailableBytes','diskAvailableBytes','guest','h10','qemuOpeningClosingEqual','qemu'},set(data))
        self.assertEqual(1000,data['uid']);self.assertEqual('11111111-2222-3333-4444-555555555555',data['boot']);self.assertEqual(12345678*1024,data['memAvailableBytes']);self.assertEqual(100000*4096,data['diskAvailableBytes'])
        self.assertIs(data['qemuOpeningClosingEqual'],True);self.assertEqual({'inertGuest':True},data['guest']['data']);self.assertEqual(1234,data['guest']['pid']);self.assertEqual(0,data['guest']['exit'])
        self.assertIs(data['h10']['timeoutParent']['present'],False);self.assertIs(data['h10']['server']['present'],False);self.assertIs(data['h10']['ownedPort53895HasAnyListener'],False);self.assertIs(data['h10']['oldDeadlineIsNotAbsence'],True)
        self.assertEqual(4,value['declaredHostBoundaryCalls'].count('synthetic_h10_absent'));self.assertEqual(1,value['declaredHostBoundaryCalls'].count('synthetic_disk'))

if __name__=='__main__':unittest.main()
