"""Canonical acceptance keeps original byte and inode custody across fresh lookups."""
import ast,hashlib,json,os,sys,types,unittest,uuid
from pathlib import Path
from agent_tools import readiness_windows_host_work as current
from agent_tools.tests import test_readiness_windows_host_work as fixtures

FIXTURE=Path(__file__).parent/'fixtures/windows_host_work_acceptance'

def reviewed_ast():
    """before.source pins CPython 3.13/3.14 ast.dump digests; keep that form on every interpreter."""
    value=types.ModuleType('ast');vars(value).update(vars(ast))
    def dump(node,annotate_fields=True,include_attributes=False):
        if annotate_fields is not True or include_attributes is not False:raise AssertionError('unreviewed ast.dump form')
        return current._syntax(node)
    value.dump=dump;return value

def old_module():
    records=json.loads((FIXTURE/'provenance.json').read_bytes())['sourceSha256']
    if set(records)!={'before.source','actual-failure.txt'}:raise ValueError('acceptance_fixture_scope')
    for name,digest in records.items():
        if hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()!=digest:raise ValueError('acceptance_fixture_changed')
    name='agent_tools._host_work_before_'+uuid.uuid4().hex
    module=types.ModuleType(name);module.__file__=str(FIXTURE/'before.source');module.__package__='agent_tools'
    sys.modules[name]=module
    try:exec(compile((FIXTURE/'before.source').read_bytes(),module.__file__,'exec'),vars(module))
    finally:sys.modules.pop(name,None)
    module.ast=reviewed_ast()
    return module

def digests(old):
    """Interpreter and reviewed digest evidence printed with every failure."""
    sha=lambda text:hashlib.sha256(text.encode()).hexdigest();rows={}
    for phase,name in (('define','define.source'),('start','start.source')):
        for node in ast.parse(fixtures.fixtures()[1][name]).body:
            if isinstance(node,ast.FunctionDef):
                rows[phase+':'+node.name]={'beforeReviewed':old._REVIEWED[phase].get(node.name),'currentReviewed':current._REVIEWED[phase].get(node.name),
                    'beforeDump':sha(old.ast.dump(node,include_attributes=False)),'canonical':sha(current._syntax(node)),
                    'interpreterDump':sha(ast.dump(node,include_attributes=False))}
    return json.dumps({'python':sys.version,'functions':rows},indent=1,sort_keys=True)

class AcceptanceOriginalPinsTests(unittest.TestCase):
    def fixture(self):
        value=fixtures.HostWorkTests('runTest');value.setUp();self.addCleanup(value.doCleanups)
        args=value.arguments();identity={k:args[k]for k in ('spec','setup','host_boot')}
        return value,args,identity
    def mutate(self,fixture,args,mode):
        path=fixture.root/args['define_capture'];body=path.read_bytes()
        if mode=='whitespace':path.write_bytes(body+b'\n')
        else:
            other=path.with_name('same-content-replacement');other.write_bytes(body);other.chmod(0o600)
            original=path.stat();os.replace(other,path)
            self.assertNotEqual(original.st_ino,path.stat().st_ino)
    def call(self,function,*args,**kwargs):
        try:return function(*args,**kwargs)
        except ValueError as error:self.fail(function.__module__+'.'+function.__name__+' refused: '+str(error)+'\n'+self.detail)
    def test_full_before_rebuilds_changed_pins_current_refuses_bytes_and_same_content_inode(self):
        old=old_module();self.detail=digests(old)
        for mode in ('whitespace','same-content-inode'):
            with self.subTest(mode=mode):
                f,args,identity=self.fixture();self.call(old.register_libvirt_lifecycle_proofs,f.root,'fixture',**args)
                self.mutate(f,args,mode)
                self.assertEqual(2,len(self.call(old.accepted_libvirt_lifecycle_proofs,f.root,'fixture',**identity)),
                                 'authentic before no longer reproduces silently rebuilt custody\n'+self.detail)
                f,args,identity=self.fixture();self.call(current.register_libvirt_lifecycle_proofs,f.root,'fixture',**args)
                self.mutate(f,args,mode)
                with self.assertRaisesRegex(ValueError,'original_evidence_changed',msg=self.detail):
                    current.accepted_libvirt_lifecycle_proofs(f.root,'fixture',**identity)
    def test_legacy_unpinned_record_stays_unchanged_and_requires_separate_explicit_admission(self):
        old=old_module();self.detail=digests(old);f,args,identity=self.fixture()
        self.call(old.register_libvirt_lifecycle_proofs,f.root,'fixture',**args)
        path=old._phase_record(f.root,'fixture',args['spec']['deploymentId']);before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'acceptance_unpinned',msg=self.detail):
            current.accepted_libvirt_lifecycle_proofs(f.root,'fixture',**identity)
        self.assertEqual(before,path.read_bytes(),self.detail)
        self.call(current.register_libvirt_lifecycle_proofs,f.root,'fixture',**args)
        self.assertEqual(before,path.read_bytes(),self.detail)
        self.assertEqual(2,len(self.call(current.accepted_libvirt_lifecycle_proofs,f.root,'fixture',**identity)),self.detail)
        self.assertNotEqual(path,current._phase_record(f.root,'fixture',args['spec']['deploymentId']),self.detail)

if __name__=='__main__':unittest.main()
