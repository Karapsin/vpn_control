"""Whole loader/transport beforeimages at actual context and isolated CLI boundaries."""
import ast,contextlib,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import source_module_loader as current
from agent_tools.tests import test_ssh_session_transport_routes as routes

TOOLS=Path(__file__).resolve().parents[1]
FIXTURE=Path(__file__).parent/'fixtures/ssh_adapter_context'
OWNED='''from contextlib import contextmanager
from pathlib import Path
@contextmanager
def owner(marker):
 path=Path(marker)
 with path.open('a')as stream:stream.write('enter\\n')
 try:yield {'state':'ready'}
 finally:
  with path.open('a')as stream:stream.write('exit\\n')
def create(marker):return owner(marker)
def foreign(value):return value
'''

def authenticate(name):
    records=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    for path,digest in records.items():
        if hashlib.sha256((FIXTURE/path).read_bytes()).hexdigest()!=digest:raise ValueError('adapter_context_fixture_changed')
    return (FIXTURE/name).read_bytes()

@unittest.skipUnless(os.name=='posix','actual descriptor source custody required')
class SourceContextTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        shutil.copyfile(TOOLS/'native_review_source_closure.py',self.root/'native_review_source_closure.py')
        self.source=self.root/'owned_context.py';self.source.write_text(OWNED)
        self.marker=self.root/'marker'
    def old(self):
        path=self.root/'source_module_loader.py';path.write_bytes(authenticate('source_module_loader.py.before.source'))
        spec=importlib.util.spec_from_file_location('agent_tools._before_context_loader_'+uuid.uuid4().hex,path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    def test_complete_before_loses_context_protocol_current_preserves_exact_owner(self):
        with contextlib.closing(self.old().Adapter(self.root,'owned_context'))as old:
            value=old.create(self.marker);self.assertTrue(callable(value))
            with self.assertRaises(TypeError):
                with value:pass
        self.assertFalse(self.marker.exists())
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as new:
            with new.create(self.marker)as result:self.assertEqual({'state':'ready'},result)
        self.assertEqual('enter\nexit\n',self.marker.read_text())
    def test_stale_before_enter_never_executes_generator(self):
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as owner:
            value=owner.create(self.marker);self.source.write_text(OWNED+'\n# changed\n')
            with self.assertRaises(ValueError):value.__enter__()
        self.assertFalse(self.marker.exists())
    def test_stale_during_context_always_cleans_original_generator(self):
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as owner:
            with self.assertRaises(ValueError):
                with owner.create(self.marker):self.source.write_text(OWNED+'\n# changed\n')
        self.assertEqual('enter\nexit\n',self.marker.read_text())
    def test_foreign_generator_context_is_not_adopted(self):
        entered=[]
        @contextlib.contextmanager
        def foreign():entered.append(True);yield None
        value=foreign()
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as owner:
            with self.assertRaisesRegex(ValueError,'foreign_adapter_context'):owner.foreign(value)
        value.gen.close();self.assertFalse(entered)
    def test_closed_source_session_refuses_prepared_context(self):
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as owner:value=owner.create(self.marker)
        with self.assertRaisesRegex(ValueError,'closed_adapter_source'):value.__enter__()
        self.assertFalse(self.marker.exists())
    def test_closed_source_during_context_still_runs_original_cleanup(self):
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as owner:
            with self.assertRaisesRegex(ValueError,'closed_adapter_source'):
                with owner.create(self.marker):owner.close()
        self.assertEqual('enter\nexit\n',self.marker.read_text())
    def test_forged_generator_with_owned_module_globals_and_foreign_code_refuses(self):
        def foreign(marker):yield marker
        with contextlib.closing(current.Adapter(self.root,'owned_context'))as owner:
            forged=types.FunctionType(foreign.__code__,vars(owner._module),'forged')
            value=contextlib.contextmanager(forged)(self.marker)
            with self.assertRaisesRegex(ValueError,'foreign_adapter_context'):owner.foreign(value)
            value.gen.close()

class TopLevelReadinessImportTests(unittest.TestCase):
    def program(self):
        tree=ast.parse(Path(routes.__file__).read_bytes())
        owner=next(node for node in tree.body if isinstance(node,ast.ClassDef)and node.name=='SessionTransportRoutes')
        method=next(node for node in owner.body if isinstance(node,ast.FunctionDef)and node.name=='test_documented_top_level_cli_import_fails_closed_without_parent_pythonpath')
        return next(ast.literal_eval(node.value)for node in method.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='program'for t in node.targets))
    def test_complete_before_import_fails_current_actual_documented_caller_fails_closed(self):
        authenticate('ssh_transport.py.before.source')
        loader='''import importlib.abc,importlib.util,sys
class Loader(importlib.abc.Loader):
 def create_module(self,spec):return None
 def exec_module(self,module):
  module.__file__=sys.argv[3]
  with open(sys.argv[3],'rb')as stream:raw=stream.read()
  exec(compile(raw,sys.argv[3],'exec'),module.__dict__)
class Finder(importlib.abc.MetaPathFinder):
 def find_spec(self,name,path=None,target=None):
  if name=='ssh_transport':return importlib.util.spec_from_loader(name,Loader())
sys.meta_path.insert(0,Finder())
'''
        with tempfile.TemporaryDirectory()as tmp:
            (Path(tmp)/'.rag_index/ssh-connection-session').mkdir(parents=True)
            args=[str(TOOLS),tmp]
            old=subprocess.run([sys.executable,'-I','-B','-c',loader+self.program(),*args,str(FIXTURE/'ssh_transport.py.before.source')],cwd=tmp,capture_output=True,text=True,timeout=10)
            self.assertNotEqual(0,old.returncode);self.assertIn("No module named 'agent_tools'",old.stderr)
            current_program=self.program()+"\nfrom agent_tools import readiness\nassert t._readiness is readiness\nassert sys.path[0]==sys.argv[1]\nassert sys.path.count(str(Path(sys.argv[1]).parent))==0\n"
            fixed=subprocess.run([sys.executable,'-I','-B','-c',current_program,*args],cwd=tmp,capture_output=True,text=True,timeout=10)
            self.assertEqual(0,fixed.returncode,fixed.stderr);self.assertEqual('guarded',fixed.stdout.strip())
    def test_genuine_package_dependency_import_error_is_not_retried(self):
        raw=(TOOLS/'ssh_transport.py').read_bytes();namespace={'__name__':'agent_tools._dependency_failure','__package__':'agent_tools','__file__':str(TOOLS/'ssh_transport.py')}
        import builtins
        real=builtins.__import__;failure=ImportError('controlled-package-readiness-import');calls=[]
        def importing(name,globals=None,locals=None,fromlist=(),level=0):
            if level==1 and fromlist==('readiness',):calls.append(name);raise failure
            return real(name,globals,locals,fromlist,level)
        namespace['__builtins__']={**vars(builtins),'__import__':importing}
        with self.assertRaises(ImportError)as caught:exec(compile(raw,str(TOOLS/'ssh_transport.py'),'exec'),namespace)
        self.assertIs(failure,caught.exception);self.assertEqual(1,len(calls))

if __name__=='__main__':unittest.main()
