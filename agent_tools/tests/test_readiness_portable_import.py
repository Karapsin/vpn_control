"""Full import-only caller and actual lazy lock protocol portability controls."""
import builtins,hashlib,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from uuid import uuid4
from agent_tools import readiness
from agent_tools.tests.test_ssh_direct_inventory_diagnostic import _IMPORT_DISCOVERY_SOURCE

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).parent/'fixtures/readiness_portable_import'
_BEFORE_LOADER="""import importlib.abc,importlib.util,sys
class BeforeLoader(importlib.abc.Loader):
 def create_module(self,spec):return None
 def exec_module(self,module):
  module.__file__=sys.argv[3]
  with open(sys.argv[3],'rb')as stream:body=stream.read()
  exec(compile(body,sys.argv[3],'exec'),module.__dict__)
class BeforeFinder(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=='agent_tools.readiness':return importlib.util.spec_from_loader(fullname,BeforeLoader())
sys.meta_path.insert(0,BeforeFinder())
"""

def authenticate():
    record=json.loads((FIXTURE/'provenance.json').read_bytes())
    if record['schemaVersion']!=1 or set(record['sourceSha256'])!={'readiness.before.source','original-failure.log'}:
        raise ValueError('portable_import_fixture_scope')
    for name,digest in record['sourceSha256'].items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()!=digest:raise ValueError('portable_import_fixture_changed')

class PortableReadinessImportTests(unittest.TestCase):
    def test_whole_before_breaks_exact_import_and_discovery_current_skips_without_private_dependencies(self):
        authenticate()
        args=[str(ROOT),str(Path(__file__).with_name('test_ssh_direct_inventory_diagnostic.py'))]
        before=subprocess.run([sys.executable,'-I','-B','-c',_BEFORE_LOADER+_IMPORT_DISCOVERY_SOURCE,*args,str(FIXTURE/'readiness.before.source')],capture_output=True,text=True,timeout=15,check=False)
        self.assertNotEqual(0,before.returncode);self.assertIn('POSIX dependency forbidden',before.stderr)
        self.assertIn('from . import private_inventory_lock as private',before.stderr)
        after=subprocess.run([sys.executable,'-I','-B','-c',_IMPORT_DISCOVERY_SOURCE,*args],capture_output=True,text=True,timeout=15,check=False)
        self.assertEqual(0,after.returncode,after.stderr)
        result=json.loads(after.stdout)
        self.assertEqual([],result['blocked']);self.assertEqual(9,result['skips']);self.assertTrue(result['posixModulesAbsent'])
        self.assertFalse(result['privateDependenciesOpened'])
        self.assertIn(b'POSIX dependency forbidden',(FIXTURE/'original-failure.log').read_bytes())

    def test_unsupported_readiness_blocks_before_journal_observer_or_effect(self):
        journal=mock.Mock();adapter=mock.Mock();operation=str(uuid4())
        context=readiness.Context('fixture','machine',adapter,journal)
        with mock.patch.object(readiness,'os',types.SimpleNamespace(name='nt')),mock.patch.object(readiness,'_private_dependency',side_effect=AssertionError('no private import')):
            with self.assertRaises(readiness.ReadinessBlocked)as caught:
                readiness.ensure_ready(context,readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'})),operation)
        self.assertEqual('unsupported_coordinator',caught.exception.reason);self.assertEqual(operation,caught.exception.operation_identity)
        journal.locked.assert_not_called();adapter.observe.assert_not_called();adapter.recover.assert_not_called()

    @unittest.skipUnless(os.name=='posix','qualified POSIX dependency path required')
    def test_qualified_private_dependency_import_error_is_not_masked(self):
        original=builtins.__import__;failure=ImportError('controlled-qualified-dependency-failure');operation=str(uuid4())
        adapter=types.SimpleNamespace(observe=mock.Mock(),recover=mock.Mock())
        def guarded(name,globals=None,locals=None,fromlist=(),level=0):
            if level==1 and fromlist==('private_inventory_lock',):raise failure
            return original(name,globals,locals,fromlist,level)
        with tempfile.TemporaryDirectory()as tmp:
            context=readiness.Context('fixture','machine',adapter,readiness.RecoveryJournal(Path(tmp)))
            with mock.patch.object(builtins,'__import__',side_effect=guarded):
                with self.assertRaises(ImportError)as caught:readiness.ensure_ready(context,readiness.Requirements(),operation)
        self.assertIs(failure,caught.exception);adapter.observe.assert_not_called();adapter.recover.assert_not_called()

    @unittest.skipUnless(os.name=='posix','actual descriptor-bound journal protocol required')
    def test_lazy_lock_preserves_protocol_and_restart_record_identity(self):
        self.assertEqual('readiness.lock',readiness.RecoveryJournal.Lock.name)
        self.assertEqual(b'tool-readiness-lock-v1\n',readiness.RecoveryJournal.Lock.body)
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp)
            with readiness.RecoveryJournal(path).locked()as journal:
                self.assertTrue(journal.record('continuity',{'version':1,'original':'same'}))
            original=(path/'readiness.lock').stat()
            with readiness.RecoveryJournal(path).locked()as journal:
                self.assertEqual({'version':1,'original':'same'},journal.lookup('continuity'))
                self.assertFalse(journal.record('continuity',{'version':1,'original':'same'}))
            current=(path/'readiness.lock').stat()
            self.assertEqual((original.st_dev,original.st_ino),(current.st_dev,current.st_ino))
            self.assertEqual(readiness.RecoveryJournal.Lock.body,(path/'readiness.lock').read_bytes())

if __name__=='__main__':unittest.main()
