"""Deterministic guest OS decisions; native qualification belongs to Tart owner."""
import ctypes as C
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
from agent_tools import tart_macos_probe as probe


class MacProbeTests(unittest.TestCase):
    def row(self,**fields):
        return {'kCGSSessionUserIDKey':501,'kCGSSessionUserNameKey':'toolrecovery','kCGSSessionOnConsoleKey':True,'kSCSecuritySessionID':100,**fields}
    def process(self,pid=1,uid=0,path='/sbin/launchd',birth=(100,50)):
        return {'pid':pid,'uid':uid,'birth':birth,'path':path}
    def test_console_absent_lock_never_implies_unlocked_or_nullcaller_onconsole(self):
        actual=probe.console_facts('toolrecovery',501,[self.row()],None)
        self.assertEqual(True,actual['onConsole']);self.assertIsNone(actual['locked']);self.assertEqual('100',actual['session'])
        for user in (None,'root','loginwindow','_mbsetupuser'):
            self.assertIsNone(probe.console_facts(user,501,[self.row()])['onConsole'])
        self.assertIsNone(probe.console_facts('toolrecovery',501,[],None)['onConsole'])
        self.assertEqual('loginwindow',probe.console_facts('loginwindow',0,[])['name'])
        self.assertEqual(0,probe.console_facts('root',0,[])['uid'])
    def test_explicit_lock_and_authoritative_global_crosscheck(self):
        for locked in (False,True):
            self.assertIs(locked,probe.console_facts('toolrecovery',501,[self.row(CGSSessionScreenIsLocked=locked)])['locked'])
            self.assertIs(locked,probe.console_facts('toolrecovery',501,[self.row()],global_locked=locked)['locked'])
        for malformed in (0,1,'false',None):
            self.assertIsNone(probe.console_facts('toolrecovery',501,[self.row(CGSSessionScreenIsLocked=malformed)])['locked'])
        self.assertIsNone(probe.console_facts('toolrecovery',501,[self.row(CGSSessionScreenIsLocked=True)],global_locked=False)['locked'])
        self.assertIsNone(probe.console_facts('toolrecovery',501,[self.row(),self.row(kSCSecuritySessionID=101)])['onConsole'])
        self.assertIsNone(probe.console_facts('toolrecovery',501,[self.row(kCGSSessionOnConsoleKey=False)])['locked'])
    def test_displays_distinguish_sleep_ready_and_missing_visibility(self):
        self.assertEqual('ready',probe.display_facts([(4,False),(5,True)]))
        self.assertEqual('sleeping',probe.display_facts([(4,True)]))
        for rows in ([],None,[(4,0)],[(4,True),(4,False)],[(0,False)]):self.assertEqual('unknown',probe.display_facts(rows))
    def test_native_same_count_display_replacement_and_sleep_transition_unknown(self):
        native=object.__new__(probe.Native)
        for mutation in ('stable','replacement','sleep','api-error'):
            calls=[0]
            def listing(capacity,array,count):
                calls[0]+=1
                C.cast(count,C.POINTER(C.c_uint32)).contents.value=1
                if mutation=='api-error':return 1
                if array is not None:array[0]=5 if mutation=='replacement'and calls[0]>2 else 4
                return 0
            def sleeping(display):return 1 if mutation=='sleep'and calls[0]>2 else 0
            native.cg=SimpleNamespace(CGGetOnlineDisplayList=listing,CGDisplayIsAsleep=sleeping)
            self.assertEqual('ready'if mutation=='stable'else 'unknown',native.displays())
    def test_complete_root_process_snapshot_still_requires_launchd_job_qualification(self):
        rows=[self.process(),self.process(2,501,'/usr/local/bin/python3'),self.process(3,0,'/usr/sbin/installd'),self.process(4,501,'/Applications/VPN Control.app/Contents/MacOS/VPN Control')]
        facts=probe.process_facts(rows,rows,observer_pid=2,observer_uid=0)
        self.assertTrue(facts['processVisibilityComplete']);self.assertTrue(facts['installerVisibilityComplete'])
        self.assertEqual([3],facts['installerBlockers']);self.assertEqual([4],facts['protectedProcesses'])
        self.assertFalse(facts['jobVisibilityComplete']);self.assertTrue(facts['unknownJobs']);self.assertNotIn('path',json.dumps(facts))
        self.assertEqual({'pid','uid','birth','executableRole'},set(facts['processes'][0]))
    def test_pid_reuse_partial_privilege_and_unseen_processes_failclosed(self):
        rows=[self.process(),self.process(2,501,'/usr/local/bin/python3')]
        for changed in ([self.process(birth=(101,0)),rows[1]],rows[:1],None,rows+[rows[0]],rows+[self.process(5,path='unknown')]):
            self.assertFalse(probe.process_facts(rows,changed,observer_pid=2,observer_uid=0)['processVisibilityComplete'])
        self.assertFalse(probe.process_facts(rows,rows,observer_pid=2,observer_uid=501)['installerVisibilityComplete'])
        self.assertFalse(probe.process_facts([],[],observer_pid=2,observer_uid=0)['processVisibilityComplete'])
    def test_fixed_libproc_native_layout_short_reply_and_overflow(self):
        self.assertEqual(136,C.sizeof(probe._Bsd))
        state={'mode':'ok'}
        def listed(buffer,size):
            if buffer is None:return 2
            buffer[0]=1;buffer[1]=2
            return 258 if state['mode']=='overflow'else 2
        def info(pid,flavor,arg,buffer,size):
            self.assertEqual(3,flavor);self.assertEqual(0,arg)
            value=C.cast(buffer,C.POINTER(probe._Bsd)).contents
            value.pid=pid;value.uid=501;value.start_seconds=100;value.start_microseconds=50
            return size-1 if state['mode']=='short'else size
        def path(pid,buffer,size):buffer.value=b'/usr/bin/fixed';return 14
        native=object.__new__(probe.Native);native.proc=SimpleNamespace(proc_listallpids=listed,proc_pidinfo=info,proc_pidpath=path)
        self.assertEqual(2,len(native.processes()))
        for mode in ('overflow','short'):
            state['mode']=mode
            with self.assertRaises(probe.ProbeUnavailable):native.processes()
    def test_complete_generated_collect_uses_actual_native_identity_not_baseline_claim(self):
        rows=[self.process(),self.process(2,501,'/usr/bin/python3')]
        class NativePeer:
            def machine(self):return '00000000-0000-4000-8000-000000000001'
            def boot(self):return '00000000-0000-4000-8000-000000000002',{'seconds':100,'microseconds':50}
            def console(self):return probe.console_facts('toolrecovery',501,[{'kCGSSessionUserIDKey':501,'kCGSSessionUserNameKey':'toolrecovery','kCGSSessionOnConsoleKey':True,'kSCSecuritySessionID':101,'CGSSessionScreenIsLocked':True}])
            def displays(self):return 'sleeping'
            def processes(self):return rows
        accounts=SimpleNamespace(getpwnam=lambda name:SimpleNamespace(pw_uid=501,pw_name='toolrecovery',pw_dir='/Users/toolrecovery'),
                                 getpwuid=lambda uid:SimpleNamespace(pw_name='root',pw_dir='/var/root'))
        local_os=SimpleNamespace(name='posix',getpid=lambda:2,geteuid=lambda:0)
        with mock.patch.object(probe,'Native',NativePeer),mock.patch.object(probe,'pwd',accounts),mock.patch.object(probe,'os',local_os):
            result=probe.collect('toolrecovery')
        self.assertEqual((0,'root','/var/root'),(result['observerUid'],result['observerAccount'],result['observerHome']))
        self.assertEqual((501,'toolrecovery','/Users/toolrecovery'),(result['uid'],result['account'],result['home']))
        self.assertEqual('00000000-0000-4000-8000-000000000002',result['boot']);self.assertTrue(result['console']['locked']);self.assertEqual('sleeping',result['display']);self.assertFalse(result['jobVisibilityComplete'])
    def test_import_and_source_have_no_coordinator_observation_or_side_effect_entrypoint(self):
        # Full emitted source is independently compilable. Loading it must not
        # initialize native frameworks or require repository helpers.
        source=Path(probe.__file__).read_bytes();namespace={'__name__':'inert_guest_probe'}
        with mock.patch.object(C,'CDLL',side_effect=AssertionError('host framework observation')):exec(compile(source,'inert guest source','exec'),namespace)
        for invalid in (None,'root','../user','tool recovery'):
            accounts=SimpleNamespace(getpwnam=mock.Mock(side_effect=KeyError))
            with mock.patch.object(probe,'pwd',accounts),mock.patch.object(probe,'os',SimpleNamespace(name='posix')),self.assertRaises(probe.ProbeUnavailable):probe.collect(invalid)
        self.assertEqual('01234567-89ab-4def-8123-0123456789ab',probe._uuid('01234567-89AB-4DEF-8123-0123456789AB'))

_WINDOWS_MAC_HELPER = r'''import builtins,ctypes,dataclasses,importlib,importlib.abc,importlib.util,json,os,pathlib,subprocess,sys,traceback,types,unittest
from unittest import mock
data=json.load(sys.stdin);root=pathlib.Path(data['root']);sys.path.insert(0,str(root));original_platform=(os.name,sys.platform)
real_os=os;real_sys=sys
class LocalOs:
 name=data['osName']
 def __getattr__(self,key):
  if self.name=='nt'and key in {'getuid','geteuid','getgid','getegid','getsid','killpg','setsid','O_DIRECTORY','O_NOFOLLOW'}:raise AttributeError(key)
  return getattr(real_os,key)
class LocalSys:
 platform='win32'if data['osName']=='nt'else'darwin'
 def __getattr__(self,key):return getattr(real_sys,key)
local_os=LocalOs();local_sys=LocalSys();original=builtins.__import__
def controlled(name,globals=None,locals=None,fromlist=(),level=0):
 if globals is not None and str(globals.get('__name__','')).startswith('agent_tools'):
  if name=='os':return local_os
  if name=='sys':return local_sys
  if name.split('.',1)[0]in{'pwd','fcntl'}:raise ModuleNotFoundError('controlled unavailable '+name)
 return original(name,globals,locals,fromlist,level)
builtins.__import__=controlled
try:
 if data['mode']in{'source','capture'}:
  module=types.ModuleType('agent_tools._portable_mac_source');module.__file__=data['path'];sys.modules[module.__name__]=module
  namespace=module.__dict__
  with mock.patch.object(ctypes,'CDLL',side_effect=AssertionError('native framework must not open')):
   exec(compile(data['source'],data['path'],'exec'),namespace)
   if data['mode']=='capture':
    with mock.patch.object(namespace['os'],'open',side_effect=AssertionError('unsupported source file opened'))as opened:
     try:namespace['capability_source'](machine='11111111-1111-4111-8111-111111111111',boot='22222222-2222-4222-8222-222222222222',uid=502,principal='ordinary')
     except namespace['ServiceUnavailable']as error:assert str(error)=='macos_service_source_unavailable'
     else:raise AssertionError('unsupported source capture accepted')
     opened.assert_not_called()
   elif data['osName']=='nt':
    assert namespace['pwd']is None
    try:
     namespace['collect']('ordinary')if 'collect'in namespace else namespace['NativeServices'](None,None)
    except (namespace.get('ProbeUnavailable',ValueError),namespace.get('ServiceUnavailable',ValueError)):
     pass
    else:raise AssertionError('unsupported native access accepted')
  print(json.dumps({'state':'imported','finiteUnsupported':True}))
 else:
  name=data['module']
  if data.get('before')is not None:
   class Loader(importlib.abc.Loader):
    def create_module(self,spec):return None
    def exec_module(self,module):
     module.__file__=str(root/(name.replace('.','/')+'.py'))
     exec(compile(data['before'],module.__file__,'exec'),module.__dict__)
   class Finder(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
     return importlib.util.spec_from_loader(fullname,Loader())if fullname==name else None
   sys.meta_path.insert(0,Finder())
  module=importlib.import_module(name);suite=unittest.TestSuite()
  for owner in data['classes']:suite.addTests(unittest.TestLoader().loadTestsFromTestCase(getattr(module,owner)))
  result=unittest.TextTestRunner(verbosity=1).run(suite)
  print(json.dumps({'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),'skipped':[test.id()for test,_ in result.skipped]}))
  if not result.wasSuccessful():raise SystemExit(1)
 assert (real_os.name,real_sys.platform)==original_platform,'global platform changed'
except BaseException as error:
 traceback.print_exc();raise SystemExit(1)
'''


class PortableMacImportTests(unittest.TestCase):
    def before(self,name):
        folder=Path(__file__).parent/'fixtures/macos_windows_import_portability'
        raw=(folder/(name+'.source')).read_bytes()
        pins={'tart_macos_probe.py':'b144862272b3bbb5464bcdb3ed57403d76d4f5418c4388c859195f9afb3c38ab',
              'tart_macos_service_census.py':'46fff3b34994f63c11045da358e9444b4bbec49b8ca003ac1e7f424add40efe8',
              'test_tart_macos_probe.py':'b3c2a845211700a828ef9103416a4ab4e5f8db330a51d3e988ec82d3e35be361',
              'test_tart_macos_service_census.py':'cee7d04d7007e0979039f72f48dbf74a1f5ac86e76a4ff7464836ee0476c2a1d'}
        self.assertEqual(pins[name],hashlib.sha256(raw).hexdigest())
        self.assertEqual(pins,json.loads((folder/'provenance.json').read_bytes())['sourceSha256'])
        return raw.decode()

    def call(self,**data):
        root=Path(__file__).resolve().parents[2]
        return subprocess.run([sys.executable,'-I','-B','-c',_WINDOWS_MAC_HELPER],
            input=json.dumps({'root':str(root),**data}),capture_output=True,text=True,timeout=25)

    def test_whole_mac_helpers_windows_import_red_current_finite_green_posix_import_error_preserved(self):
        root=Path(__file__).resolve().parents[1]
        for name in ('tart_macos_probe.py','tart_macos_service_census.py'):
            with self.subTest(helper=name):
                old=self.call(mode='source',osName='nt',path=str(root/name),source=self.before(name))
                self.assertNotEqual(0,old.returncode);self.assertIn('controlled unavailable pwd',old.stderr)
                current=(root/name).read_text()
                green=self.call(mode='source',osName='nt',path=str(root/name),source=current)
                self.assertEqual(0,green.returncode,green.stderr)
                # A real POSIX/Darwin import failure cannot become a fake healthy
                # module merely because unsupported Windows import is portable.
                genuine=self.call(mode='source',osName='posix',path=str(root/name),source=current)
                self.assertNotEqual(0,genuine.returncode);self.assertIn('controlled unavailable pwd',genuine.stderr)

    def test_whole_pure_unit_mocks_before_red_current_windows_projection_cases_green(self):
        for name,classes in [('test_tart_macos_probe.py',['MacProbeTests']),
                             ('test_tart_macos_service_census.py',['ServiceReviewTests','CapabilityGetterTests'])]:
            module='agent_tools.tests.'+name[:-3]
            with self.subTest(module=module):
                red=self.call(mode='tests',osName='nt',module=module,classes=classes,before=self.before(name))
                self.assertNotEqual(0,red.returncode);self.assertIn('AttributeError',red.stderr)
                green=self.call(mode='tests',osName='nt',module=module,classes=classes,before=None)
                self.assertEqual(0,green.returncode,green.stderr)
                summary=json.loads(green.stdout)
                self.assertGreater(summary['tests'],0);self.assertEqual(0,summary['errors']);self.assertEqual(0,summary['failures'])
                self.assertTrue(all('statfs_layout_matches_installed_apple_primary_header'in test for test in summary['skipped']))

    def test_whole_source_builder_before_missing_flag_red_current_finite_no_open_green(self):
        root=Path(__file__).resolve().parents[1]
        path=Path(__file__).parent/'fixtures/macos_windows_import_portability/tart_macos_service_source_guard.before.source'
        raw=path.read_bytes()
        self.assertEqual('c4e4082317f0b332482ad07b3680af20b49c48d7fe97840b21bef9a11efb9403',hashlib.sha256(raw).hexdigest())
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads(path.with_name('provenance.json').read_bytes())['sourceCaptureBeforeSha256'])
        before=self.call(mode='capture',osName='nt',path=str(root/'tart_macos_service_census.py'),source=raw.decode())
        self.assertNotEqual(0,before.returncode);self.assertIn('AttributeError: O_NOFOLLOW',before.stderr)
        current=self.call(mode='capture',osName='nt',path=str(root/'tart_macos_service_census.py'),source=(root/'tart_macos_service_census.py').read_text())
        self.assertEqual(0,current.returncode,current.stderr)


if __name__=='__main__':unittest.main()
