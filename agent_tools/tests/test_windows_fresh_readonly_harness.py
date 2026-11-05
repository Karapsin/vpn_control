"""Causal controls for the preserved complete fresh-Windows R0 harnesses.

Native process, UID and /proc seams below are explicit inert projections. They
qualify no VM, current transport or full native capacity/storage observation.
"""
import ast,base64,contextlib,hashlib,io,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
FIXTURES=Path(__file__).parent/'fixtures/windows_fresh_readonly_observer'
FILES={'importBefore':'import.before.source','quoteBefore':'quoting.before.source','bootstrapAfter':'native.before.source','nativeBefore':'native.before.source','after':'after.source','schemaBefore':'schema.before.source','coupledBefore':'coupled-bootstrap.before.source','coupledAfter':'coupled-bootstrap.generator.after.source','builderBefore':'held-builder.before.source','builderAfter':'held-builder.after.source','storageBefore':'storage-claim.before.source','storageAfter':'storage-claim.after.source','secureBefore':'secure-custody.before.source','secureAfter':'secure-custody.after.source','wakeBefore':'wake-operators.before.source','wakeAfter':'wake-operators.after.source'}
BEFORE=os.environ.get('VPN_CONTROL_WINDOWS_R0_CONTROL_BEFORE')

def source(name):return (FIXTURES/FILES[name]).read_bytes()
def load_after(*,native_graph=True):
    module=types.ModuleType('owned_readonly_harness_causal_after')
    module.__file__=str(ROOT/'.runtime/tool-recovery/native-followup-20261027/windows/fresh-fixture-plan/controlled/r0.py')
    old_path=list(sys.path)
    try:
        if native_graph:exec(compile(source('after'),module.__file__,'exec'),vars(module))
        else:
            wanted={'executable_generation','verify_executable_source_schemas','verify_allocation_identity'}
            tree=ast.parse(source('after'))
            nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in wanted or isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='EXECUTABLE_GENERATION_FIELDS'for t in n.targets)]
            if {n.name for n in nodes if isinstance(n,ast.FunctionDef)}!=wanted:raise AssertionError('consumed schema definition missing')
            module.ast=ast
            # Source-only metadata seam: read the actual POSIX producer texts
            # without importing its unavailable platform dependency graph.
            raw=(ROOT/'agent_tools/ssh_tmux_resource_admission.py').read_text()
            remote=next(ast.literal_eval(n.value)for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_REMOTE'for t in n.targets))
            raw=(ROOT/'agent_tools/windows_vm_instance.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='_vm_main');getter=ast.get_source_segment(raw,node)
            marker=object();module.windows_vm_resources=types.SimpleNamespace(admission=types.SimpleNamespace(_REMOTE=remote));module.windows_vm_instance=types.SimpleNamespace(_vm_main=marker)
            def getsource(function):
                if function is not marker:raise AssertionError('unowned schema function')
                return getter
            module.inspect=types.SimpleNamespace(getsource=getsource)
            exec(compile(ast.Module(body=nodes,type_ignores=[]),module.__file__,'exec'),vars(module))
    finally:sys.path[:]=old_path
    return module

def original_remote(raw,programs):
    tree=ast.parse(raw)
    node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='remote'for t in n.targets))
    namespace={'base64':base64,'sources':programs,'operation':'controlled-r0-only'}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-whole-harness-remote-render','exec'),namespace)
    return namespace['remote']

class FakePath:
    def __init__(self,value):self.value=str(value)
    def read_text(self):
        if self.value.endswith('/stat'):return '424242 (controlled) '+' '.join(['S']+['0']*18+['17'])
        return '25515f23-b966-4c3a-ae63-d38452375578'

def execute_role(source_bytes,uid,*,child_counter=None):
    real_import=__import__
    surface=types.SimpleNamespace(getuid=lambda:uid,geteuid=lambda:uid,getgid=lambda:uid,getegid=lambda:uid,getgroups=lambda:[uid],getpid=lambda:424242)
    class Child:
        pid=424242;returncode=0
        def communicate(self,raw):
            if child_counter is not None:child_counter.append('completed')
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream):exec(compile(raw,'controlled-native-business-seam','exec'),{})
            return json.dumps({'principal':[1000,1000,1000,1000,[1000]],'value':json.loads(stream.getvalue())}).encode(),b''
    def imports(name,*args,**kwargs):
        if name=='os':return surface
        if name=='pwd':return types.SimpleNamespace(getpwuid=lambda _:types.SimpleNamespace(pw_name='kardinal',pw_dir='/home/kardinal'))
        if name=='pathlib':return types.SimpleNamespace(Path=FakePath)
        if name=='subprocess':return types.SimpleNamespace(Popen=lambda *a,**k:Child(),PIPE=-1)
        return real_import(name,*args,**kwargs)
    namespace={'__name__':'controlled_complete_readonly_owner','__builtins__':dict(vars(__import__('builtins')),__import__=imports)}
    output=io.StringIO()
    with contextlib.redirect_stdout(output):exec(compile(source_bytes,'actual-complete-readonly-owner','exec'),namespace)
    return output.getvalue()



def storage_wrapper_control(raw):
    """Only actual helper bodies plus actual current canonical locked writer.

    UID1000 alone projects to this owned fixture UID. No native authority is
    claimed by that seam; real files, fullFD9 and canonical lock/save execute.
    """
    import stat
    tree=ast.parse(raw)
    module=types.ModuleType('owned_storage_wrapper_current');module.__file__=str(ROOT/'scripts/native_fixture_storage.py');sys.modules[module.__name__]=module
    exec(compile(Path(module.__file__).read_bytes(),module.__file__,'exec',dont_inherit=True),vars(module))
    module.shutil=types.SimpleNamespace(disk_usage=lambda _:types.SimpleNamespace(free=300*1024**3))
    nodes=[__import__('copy').deepcopy(n)for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in ('need','gen','private','fsync_directory','save')or isinstance(n,ast.ClassDef)and n.name=='ExactOldPlans']
    class FixtureUID(ast.NodeTransformer):
        def visit_Constant(self,node):
            return ast.copy_location(ast.Constant(os.getuid()),node)if type(node.value)is int and node.value==1000 else node
    namespace={'os':os,'stat':stat,'pathlib':types.SimpleNamespace(Path=Path),'json':json,'storage':module}
    exec(compile(ast.fix_missing_locations(FixtureUID().visit(ast.Module(body=nodes,type_ignores=[]))),'actual-storage-wrapper-owned-uid-seam','exec'),namespace)
    return tree,module,namespace



def load_control_definitions(raw,names,namespace):
    tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in names]
    if {n.name for n in nodes}!=set(names):raise AssertionError('explicit control definitions missing')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'actual-preserved-native-caller-definitions','exec'),namespace)
    return namespace

def inert_recipient():
    ordinary={'name':'fixtureuser','sid':'S-1-5-21-1-2-3-1001','enabled':True,'isAdministrator':False,'isUsersMember':True,'profileRoot':r'C:\Users\fixtureuser'}
    administrator={'name':'fixtureadmin','sid':'S-1-5-21-1-2-3-1000','enabled':True,'isAdministrator':True}
    computer={'name':'INERT-OWNED','loggedOn':r'INERT-OWNED\fixtureuser','partOfDomain':False}
    osdata={'bootTime':'2026-01-01T00:00:00.0000000Z'}
    return {'recipient':{'ordinaryUser':ordinary,'administrator':administrator,'computer':computer,'os':osdata,'fixturePrincipal':'S-1-5-18'}},{'state':'setup-observed','setupReady':True,'imageMatchesRequest':True,'result':{'user':ordinary,'administrator':administrator,'computer':computer,'os':osdata,'fixturePrincipal':'S-1-5-18'}}

def portable_module(relative,name):
    path=ROOT/relative;module=types.ModuleType(name);module.__file__=str(path)
    exec(compile(path.read_bytes(),str(path),'exec',dont_inherit=True),vars(module))
    return module

class FreshReadonlyHarnessControls(unittest.TestCase):
    def test_whole_harness_is_importable_from_its_owned_deep_entrypoint(self):
        raw=source('importBefore'if BEFORE=='import'else'after')
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary)/'owned-checkout';package=root/'agent_tools';package.mkdir(parents=True)
            (package/'__init__.py').write_text("from pathlib import Path\nPath(__file__).parent.parent.joinpath('imported.marker').write_text('controlled-import')\nraise SystemExit(0)\n")
            entry=root/'.runtime/tool-recovery/native-followup-20261027/windows/fresh-fixture-plan/controlled/r0.py';entry.parent.mkdir(parents=True);entry.write_bytes(raw)
            env=dict(os.environ);env.pop('PYTHONPATH',None);env['PYTHONDONTWRITEBYTECODE']='1'
            result=subprocess.run([sys.executable,'-B',str(entry)],cwd=temporary,env=env,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            self.assertTrue((root/'imported.marker').is_file())

    @unittest.skipUnless(os.name=='posix'and hasattr(os,'getuid'),'Actual child principal bootstrap is POSIX')
    def test_actual_bootstrap_render_compiles_and_delivers_owned_stdin(self):
        raw=source('quoteBefore'if BEFORE=='quoting'else'bootstrapAfter')
        remote=original_remote(raw,{'inert':b'print(1)'})
        compile(remote,'complete-generated-before-or-after-owner','exec')
        node=next(n for n in ast.walk(ast.parse(remote))if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='bootstrap'for t in n.targets))
        bootstrap=ast.literal_eval(node.value)
        result=subprocess.run([sys.executable,'-I','-B','-c',bootstrap],input=b"import json;print(json.dumps({'state':'controlled-observed'}))\n",capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['value'],{'state':'controlled-observed'})

    @unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'Actual POSIX private ledger reader required')
    def test_storage_reader_keeps_original_owner_role(self):
        after=load_after();role=after.source_role('storage')
        if BEFORE=='role':
            remote=original_remote(source('nativeBefore'),{'inert':b'print(1)'})
            condition=next(n.test for n in ast.walk(ast.parse(remote))if isinstance(n,ast.If)and isinstance(n.test,ast.Compare)and isinstance(n.test.left,ast.Name)and n.test.left.id=='label')
            role='root'if eval(compile(ast.Expression(condition),'actual-old-role-route','eval'),{'label':'storage'})else'ordinary'
        uid=0 if role=='root' else 1000
        from scripts import native_fixture_storage
        module=types.ModuleType('controlled_storage_reader');sys.modules[module.__name__]=module
        exec(compile(Path(native_fixture_storage.__file__).read_bytes(),'actual-canonical-private-storage-reader','exec'),vars(module))
        real_os=module.os
        proxy=types.SimpleNamespace(**vars(real_os));proxy.geteuid=lambda:uid
        def info(fd):
            value=real_os.fstat(fd)
            return types.SimpleNamespace(st_mode=value.st_mode,st_uid=1000,st_nlink=value.st_nlink,st_size=value.st_size)
        proxy.fstat=info;module.os=proxy
        with tempfile.TemporaryDirectory()as temporary:
            path=Path(temporary)/'storage-plans.json';path.write_text('{"schemaVersion":1,"plans":{}}');path.chmod(0o600)
            self.assertEqual(module.StoragePlans(temporary)._read(),{'schemaVersion':1,'plans':{}})
        self.assertEqual(after.source_role('storageCoverage'),'root')
        coverage=after.storage_coverage_source({'ledgerPath':'/controlled','generation':[],'parentIdentity':[],'sha256':'0'*64,'rawBase64':'','ledger':{'schemaVersion':1,'plans':{}}})
        syntax=ast.parse(coverage);namespace={}
        declarations=[n for n in syntax.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        exec(compile(ast.Module(body=declarations,type_ignores=[]),'actual-root-full-FD-definitions','exec'),namespace)
        self.assertTrue(callable(namespace['stat']))
        self.assertTrue(callable(namespace['census']))
        self.assertTrue(callable(namespace['_storage_vm_coverage']))

    @unittest.skipUnless(os.name=='posix'and hasattr(os,'O_DIRECTORY'),'Actual fsynced phase receipt required')
    def test_completed_phase_is_retained_before_later_failure(self):
        after=load_after()
        with tempfile.TemporaryDirectory()as temporary:
            out=Path(temporary)
            if BEFORE=='publication':
                completed=[]
                programs={'getterBefore':b"import json;print(json.dumps({'state':'controlled-observed'}))",'capacity':b"raise ValueError('controlled-later-failure')"}
                remote=original_remote(source('nativeBefore'),programs)
                with self.assertRaisesRegex(ValueError,'controlled-later-failure'):
                    execute_role(remote,0,child_counter=completed)
                self.assertEqual(completed,['completed'])
            else:
                def launch(label,wrapper,role):
                    if label=='later':self.assertEqual((out/'first.result.private.json').read_bytes()[-1:],b'\n')
                    return {'returnCode':0,'stdout':execute_role(wrapper,1000).encode(),'stderr':b'','reaped':True,'localPid':424242,'elapsedSeconds':0}
                after.collect_phase(out,'first',b"import json;print(json.dumps({'state':'controlled-observed'}))",'controlled-r0-only',launch)
                with self.assertRaises(AssertionError):after.collect_phase(out,'later',b"raise ValueError('controlled-later-failure')",'controlled-r0-only',launch)
            self.assertTrue((out/'first.result.private.json').is_file(),'earlier complete phase was erased by the later failure')

    def test_actual_native_schema_preserves_every_executable_generation_field(self):
        after=load_after(native_graph=False);facts=json.loads((FIXTURES/'executable-schema-native-facts.json').read_text())
        for pair in facts['pairs']:
            if BEFORE=='schema':
                tree=ast.parse(source('schemaBefore'));main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main')
                loop=next(n for n in ast.walk(main)if isinstance(n,ast.For)and isinstance(n.target,ast.Name)and n.target.id=='field'and isinstance(n.iter,ast.Tuple)and any(isinstance(x,ast.Constant)and x.value=='executableGeneration'for x in n.iter.elts))
                exec(compile(ast.Module(body=[loop],type_ignores=[]),'actual-before-native-join','exec'),{'row':pair['getter'],'matches':[pair['resource']]})
            else:after.verify_allocation_identity(pair['getter'],pair['resource'])
            for index in range(9):
                changed=json.loads(json.dumps(pair['resource']));changed['executableGeneration'][index]+=1
                with self.subTest(index=index),self.assertRaises(ValueError):after.verify_allocation_identity(pair['getter'],changed)
        for bad in ([1]*8,[1]*10,[True]*9,[-1]*9,'unknown'):
            with self.subTest(shape=type(bad).__name__),self.assertRaises(ValueError):after.executable_generation(bad,'resource')
        with self.assertRaises(ValueError):after.executable_generation([1]*9,'unknown-source')
        changed=json.loads(json.dumps(facts['pairs'][0]['resource']))
        changed['executableGeneration'][5],changed['executableGeneration'][8]=changed['executableGeneration'][8],changed['executableGeneration'][5]
        with self.assertRaises(ValueError):after.verify_allocation_identity(facts['pairs'][0]['getter'],changed)
        after.verify_executable_source_schemas()
        resource_module=after.windows_vm_resources.admission
        original=resource_module._REMOTE;tree=ast.parse(original)
        census=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='census')
        value=next(v for n in ast.walk(census)if isinstance(n,ast.Dict)for k,v in zip(n.keys,n.values)if isinstance(k,ast.Constant)and k.value=='executableGeneration')
        value.elts[5],value.elts[8]=value.elts[8],value.elts[5]
        with mock.patch.object(resource_module,'_REMOTE',ast.unparse(tree)),self.assertRaisesRegex(ValueError,'source_schema_changed'):
            after.verify_executable_source_schemas()
        original_getsource=after.inspect.getsource
        def changed_getsource(function):
            text=original_getsource(function)
            if function is after.windows_vm_instance._vm_main:
                tree=ast.parse(text);node=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='generation')
                value=next(n.value for n in ast.walk(node)if isinstance(n,ast.Return));value.elts[5],value.elts[6]=value.elts[6],value.elts[5]
                return ast.unparse(tree)
            return text
        with mock.patch.object(after.inspect,'getsource',side_effect=changed_getsource),self.assertRaisesRegex(ValueError,'source_schema_changed'):
            after.verify_executable_source_schemas()
        raw=after.windows_vm_resources.admission._REMOTE;tree=ast.parse(raw)
        census=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='census')
        actual=next(v for n in ast.walk(census)if isinstance(n,ast.Dict)for k,v in zip(n.keys,n.values)if isinstance(k,ast.Constant)and k.value=='executableGeneration')
        self.assertEqual([n.attr for n in actual.elts],['st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns','st_nlink'])
        raw=after.inspect.getsource(after.windows_vm_instance._vm_main);tree=ast.parse(raw)
        generation=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='generation')
        actual=next(n.value for n in ast.walk(generation)if isinstance(n,ast.Return))
        self.assertEqual([n.attr for n in actual.elts],['st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'])


    def test_current_getter_rebinds_every_protected_child_source_check(self):
        # Whole native-refused outer source contains the actual new getter and
        # old inner digest. Only the provider body execution is a marker seam;
        # stdin read, byte bound, SHA and complete principal checks execute.
        tree=ast.parse(source('coupledBefore'))
        bindings={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in ('GETTER_SOURCE','GETTER_SHA','CHILD_BOOTSTRAP')}
        getter=bindings['GETTER_SOURCE'];bootstrap=bindings['CHILD_BOOTSTRAP']
        self.assertEqual(hashlib.sha256(getter).hexdigest(),bindings['GETTER_SHA'])
        generator=next(n for n in ast.parse(source('coupledAfter')).body if isinstance(n,ast.FunctionDef)and n.name=='rebind_child_bootstrap')
        namespace={'ast':ast,'hashlib':hashlib}
        exec(compile(ast.Module(body=[generator],type_ignores=[]),'actual-complete-child-binding-generator','exec'),namespace)
        rebind=namespace['rebind_child_bootstrap']
        if BEFORE!='coupled':bootstrap=rebind(bootstrap,getter)
        def run(raw,*,principal_changed=False):
            entered=[];output=io.StringIO();actual_import=__import__;actual_exec=exec
            uid=1001 if principal_changed else 1000
            principal=types.SimpleNamespace(getuid=lambda:uid,geteuid=lambda:uid,getgid=lambda:uid,getegid=lambda:uid,getgroups=lambda:[uid])
            stdin=types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(raw)))
            def imports(name,*args,**kwargs):
                if name=='os':return principal
                if name=='sys':return stdin
                return actual_import(name,*args,**kwargs)
            def provider_execution(code,scope):
                self.assertEqual(code.co_filename,'source-held-ordinary-windows-coverage')
                entered.append('provider-body-marker');scope['get_windows_allocation_coverage']=lambda:{'state':'controlled-fixture-only'}
            scope={'__builtins__':dict(vars(__import__('builtins')),__import__=imports,exec=provider_execution)}
            with contextlib.redirect_stdout(output):actual_exec(compile(bootstrap,'actual-protected-child-bootstrap','exec'),scope)
            return entered,json.loads(output.getvalue())
        entered,value=run(getter)
        self.assertEqual(entered,['provider-body-marker']);self.assertEqual(value,{'principal':[1000,1000,1000,1000,[1000]],'coverage':{'state':'controlled-fixture-only'}})
        for malformed in (getter[:-1],getter+b'x',b'x'+getter[1:]):
            with self.subTest(shape=len(malformed)),self.assertRaisesRegex(ValueError,'ordinary_coverage_source_changed'):run(malformed)
        with self.assertRaisesRegex(ValueError,'ordinary_coverage_principal_changed'):run(getter,principal_changed=True)
        # Unknown/missing/duplicate source-check shapes cannot silently produce
        # a partial binding. The old source check remains mandatory.
        original=bindings['CHILD_BOOTSTRAP']
        tree=ast.parse(original);read=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='read');read.func.attr='read1'
        with self.assertRaisesRegex(ValueError,'bridge_child_read_schema'):rebind(ast.unparse(tree),getter)
        with self.assertRaisesRegex(ValueError,'bridge_child_digest_schema'):rebind(original.replace("raw=sys.stdin.buffer.read(114728)","raw=sys.stdin.buffer.read(114728)\nraw=sys.stdin.buffer.read(114728)"),getter)


    @unittest.skipUnless(os.name=='posix'and all(hasattr(os,k)for k in ('getuid','O_NOFOLLOW','O_DIRECTORY')),'Actual retained source descriptors are POSIX')
    def test_held_builder_bytes_ignore_timestamp_valid_foreign_pyc(self):
        import importlib.util,py_compile
        from agent_tools.native_review_source_closure import _Held
        raw=source('builderBefore'if BEFORE=='cache'else'builderAfter')
        node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='module_from_path')
        namespace={'Path':Path,'types':types,'sys':sys,'importlib':__import__('importlib')}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-whole-controller-builder-loader','exec'),namespace)
        with tempfile.TemporaryDirectory()as temporary:
            path=Path(temporary).resolve(strict=True)/'builder.py';foreign=b'EXECUTED="FOREIGN-PYC"\n';legitimate=b'EXECUTED="SOURCE-BYTE"\n'
            self.assertEqual(len(foreign),len(legitimate));path.write_bytes(foreign);path.chmod(0o600);stamp=path.stat().st_mtime_ns
            py_compile.compile(str(path),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            path.write_bytes(legitimate);os.utime(path,ns=(stamp,stamp));digest=hashlib.sha256(legitimate).hexdigest();held=_Held();name='owned_r0_held_builder_control'
            try:
                self.assertEqual(held.read(str(path),digest,max_bytes=1024),legitimate);held.finish();held.final_identity_pass()
                loader=namespace['module_from_path']
                module=loader(path,name)if BEFORE=='cache'else loader(path,name,held,digest)
                held.finish();held.final_identity_pass()
                self.assertEqual(module.EXECUTED,'SOURCE-BYTE','held source must be executed even when a foreign timestamp pyc is valid')
                self.assertEqual(module.__file__,str(path));self.assertIs(sys.modules[name],module)
                with self.assertRaisesRegex(ValueError,'owned_builder_namespace_exists'):loader(path,name,held,digest)
                with self.assertRaises(ValueError):loader(path,name+'changed',held,'0'*64)
                self.assertNotIn(name+'changed',sys.modules)
            finally:held.close();sys.modules.pop(name,None);sys.modules.pop(name+'changed',None)


    @unittest.skipUnless(os.name=='posix'and all(hasattr(os,k)for k in ('getuid','O_NOFOLLOW','O_DIRECTORY')),'Actual POSIX retained FD9 and storage writer lock')
    def test_storage_pinned_raw_generation_joins_canonical_state_inside_lock(self):
        raw=source('storageBefore'if BEFORE=='storage-raw'else'storageAfter')
        tree,storage,namespace=storage_wrapper_control(raw)
        self.addCleanup(sys.modules.pop,storage.__name__,None)
        for drift in ('none','different-raw','same-raw-new-generation'):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary).resolve(strict=True);ledger=root/'ledger';directory=root/'fixture';directory.mkdir(mode=0o700);disk=directory/'inert.raw';disk.write_bytes(b'inert');disk.chmod(0o600)
                original=storage.StoragePlans(str(ledger));original.reserve('old-inert','linux','start',str(directory),[{'path':str(disk),'capacityBytes':4096}],writer_pid=os.getpid());path=ledger/'storage-plans.json'
                raw_a,pin_a=namespace['private'](path,4*1024**2)
                if drift=='different-raw':original.reserve('other-inert','linux','start',str(directory),[{'path':str(disk),'capacityBytes':4096}],writer_pid=os.getpid())
                if drift=='same-raw-new-generation':original._save(original._read())
                before_b=original._read();unchanged=path.read_bytes();namespace.update(ledger_path=path,before=before_b,before_raw=raw_a,before_pin=pin_a)
                def reserve():namespace['ExactOldPlans'](str(ledger)).reserve('new-inert','windows','start',str(directory),[{'path':str(disk),'capacityBytes':4096}],writer_pid=os.getpid())
                if drift=='none':
                    reserve();after=original._read();self.assertEqual({key:value for key,value in after['plans'].items()if key!='new-inert'},before_b['plans']);self.assertIn('new-inert',after['plans'])
                else:
                    with self.assertRaisesRegex(ValueError,'new_storage_locked_raw_generation_changed'):reserve()
                    self.assertEqual(path.read_bytes(),unchanged);self.assertNotIn('new-inert',original._read()['plans'])

    @unittest.skipUnless(os.name=='posix'and all(hasattr(os,k)for k in ('getuid','O_NOFOLLOW','O_DIRECTORY')),'Actual POSIX file/directory fsync boundary')
    def test_storage_once_fence_and_beforeimage_are_durable_before_writer(self):
        import stat
        raw=source('storageBefore'if BEFORE=='storage-durable'else'storageAfter');tree,storage,namespace=storage_wrapper_control(raw);self.addCleanup(sys.modules.pop,storage.__name__,None)
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve(strict=True);events=[];opened={};proxy=types.SimpleNamespace(**vars(os))
            def opening(path,flags,*args,**kwargs):
                fd=os.open(path,flags,*args,**kwargs);opened[fd]=str(path);return fd
            def syncing(fd):
                events.append(('directory'if stat.S_ISDIR(os.fstat(fd).st_mode)else'file',opened.get(fd,'unknown')));os.fsync(fd)
            proxy.open=opening;proxy.fsync=syncing
            namespace.update(os=proxy,base64=base64,hashlib=hashlib,types=types,root=root,OP='owned-durable',FIXTURE='windows-inert',PID=os.getpid(),START=1,ledger_path=root/'inert-ledger',before_pin=[0]*9,before_raw=b'{}',coverage={},EXPECTED_ACTORS={},intent_pin=[0]*9,qpin=[0]*9)
            begin=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='evidence'for t in n.targets));end=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='result'for t in n.targets))
            exec(compile(ast.Module(body=tree.body[begin:end],type_ignores=[]),'actual-source-before-canonical-storage-writer','exec'),namespace)
            evidence=namespace['evidence'];self.assertIn(('directory',str(root)),events);self.assertIn(('directory',str(evidence)),events);self.assertIn(('file',str(evidence/'intent.json')),events);self.assertIn(('file',str(evidence/'before.private.json')),events)
            # All observations above run before the actual next statement,
            # result=host.register(...), which this no-native fixture excludes.
            self.assertGreater(max(i for i,e in enumerate(events)if e==('directory',str(evidence))),max(i for i,e in enumerate(events)if e==('file',str(evidence/'before.private.json'))))


    @unittest.skipUnless(os.name=='posix'and all(hasattr(os,k)for k in ('getuid','O_NOFOLLOW','O_DIRECTORY')),'Actual held reviewed byte/generation custody is POSIX')
    def test_secure_reviewed_artifact_bytes_precede_parse_and_current_hashes(self):
        from agent_tools.native_review_source_closure import _Held,generation
        raw=source('secureBefore'if BEFORE=='secure-proof'else'secureAfter')
        after=load_control_definitions(source('secureAfter'),{'load_reviewed_inputs'},{'json':json})
        old_with=next(n for n in ast.parse(source('secureBefore')).body if isinstance(n,ast.With));old_loop=next(n for n in old_with.body if isinstance(n,ast.For)and isinstance(n.target,ast.Name)and n.target.id=='path'and isinstance(n.iter,ast.Tuple))
        for drift in ('none','review','setup','original-contents','original-generation'):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary).resolve(strict=True);setup=root/'setup.json';original=root/'original.json';review_path=root/'custody-review.json'
                for path,value in ((setup,b'{"inert":"setup"}\n'),(original,b'{"inert":"original"}\n')):path.write_bytes(value);path.chmod(0o600)
                review={'setupProof':{'path':str(setup),'sha256':hashlib.sha256(setup.read_bytes()).hexdigest()},'originalIntentPath':str(original),'originalIntentPin':{'sha256':hashlib.sha256(original.read_bytes()).hexdigest(),'generation':list(generation(original.stat()))}}
                controller=root/'controller.before.source';controller.write_bytes(source('secureBefore'));controller.chmod(0o600)
                review_path.write_text(json.dumps(review));review_path.chmod(0o600);expected=hashlib.sha256(review_path.read_bytes()).hexdigest()
                if drift=='review':review_path.write_bytes(review_path.read_bytes()+b' ')
                if drift=='setup':setup.write_bytes(b'{"inert":"changed"}\n')
                if drift=='original-contents':original.write_bytes(b'{"inert":"changed"}\n')
                if drift=='original-generation':
                    replacement=root/'replacement.json';replacement.write_bytes(original.read_bytes());replacement.chmod(0o600);os.replace(replacement,original)
                parsed=[];json_view=types.SimpleNamespace(loads=lambda value:(parsed.append(True),json.loads(value))[1]);after['json']=json_view
                with contextlib.closing(_Held())as held:
                    def consume():
                        if BEFORE=='secure-proof':
                            namespace={'held':held,'Path':Path,'OUT':root,'__file__':str(controller),'hashlib':hashlib,'review':json.loads(review_path.read_bytes())}
                            exec(compile(ast.Module(body=[old_loop],type_ignores=[]),'actual-legacy-current-hash-reader','exec'),namespace)
                        else:after['load_reviewed_inputs'](held,review_path,expected)
                    if drift=='none':consume();held.finish();held.final_identity_pass()
                    else:
                        with self.assertRaises(ValueError):consume()
                        if drift=='review':self.assertFalse(parsed,'unreviewed bytes reached JSON parser')

    @unittest.skipUnless(os.name=='posix'and all(hasattr(os,k)for k in ('getuid','O_NOFOLLOW','O_DIRECTORY')),'Actual inert SecretFile open boundary is POSIX')
    def test_secure_recipient_and_pending_refuse_before_inert_file_open(self):
        from agent_tools.native_review_source_closure import _Held
        from agent_tools.private_credential_file import SecretFile
        raw=source('secureBefore'if BEFORE=='secure-recipient'else'secureAfter');top=next(n for n in ast.parse(raw).body if isinstance(n,ast.With));end=next(i for i,n in enumerate(top.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='result'for t in n.targets));begin=end if BEFORE=='secure-recipient'else next(i for i,n in enumerate(top.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='recipient_operation'for t in n.targets));code=compile(ast.Module(body=top.body[begin:end+1],type_ignores=[]),'actual-secure-credential-entry-sequence','exec')
        import copy,uuid
        for drift in ('none','adminSID','userSID','name','role','computer','boot','pending'):
            with self.subTest(drift=drift),tempfile.TemporaryDirectory()as temporary,contextlib.closing(_Held())as held:
                root=Path(temporary).resolve(strict=True);path=root/'inert.secret';path.write_text('INERT-NONSECRET-fixture\n');path.chmod(0o600);review,check=inert_recipient();check=copy.deepcopy(check);opened=[]
                if drift=='adminSID':check['result']['administrator']['sid']='S-1-5-21-1-2-3-999'
                if drift=='userSID':check['result']['user']['sid']='S-1-5-21-1-2-3-998'
                if drift=='name':check['result']['administrator']['name']='otheradmin'
                if drift=='role':check['result']['user']['isAdministrator']=True
                if drift=='computer':check['result']['computer']['name']='INERT-OTHER'
                if drift=='boot':check['result']['os']['bootTime']='2000-01-01T00:00:00.0000000Z'
                if drift=='pending':check={'state':'qualification-pending'}
                def secure_effect(*args):
                    with SecretFile(str(path)):opened.append('actual-inert-file-open')
                    return {'state':'inert-boundary-only'}
                review['hostSudoInput']='INERT-host-credential-not-opened'
                namespace={'ROOT':root,'DEPLOYMENT':'00000000-0000-4000-8000-000000000062','OP':'00000000-0000-4000-8000-000000000001','uuid':uuid,'json':json,'review':review,'namespace':{'secure':secure_effect},'deploy':types.SimpleNamespace(qualify=lambda *args:check),'save':lambda *args:None,'held':held}
                load_control_definitions(source('secureAfter'),{'require_reviewed_recipient'},namespace)
                with contextlib.redirect_stdout(io.StringIO()):
                    if drift=='none':exec(code,namespace);self.assertEqual(opened,['actual-inert-file-open'])
                    else:
                        with self.assertRaisesRegex(ValueError,'fresh_secure_reviewed_recipient_changed'):exec(code,namespace)
                        self.assertFalse(opened)

    def test_wake_uses_validated_competing_sessions_in_exact_raw_schema(self):
        from agent_tools import readiness
        from uuid import uuid4
        import copy
        guest=portable_module('agent_tools/readiness_windows_guest.py','owned_portable_wts');display=portable_module('agent_tools/readiness_windows_display.py','owned_portable_display')
        raw=(ROOT/'agent_tools/readiness_windows.py').read_text();cls=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef)and n.name=='WindowsBackend');observe=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=='observe');scope={'guest':guest,'monitor':display,'readiness':readiness,'uuid4':uuid4,'_need':lambda ok,reason:None if ok else (_ for _ in ()).throw(ValueError(reason))};exec(compile(ast.Module(body=[observe],type_ignores=[]),'actual-canonical-backend-observation-projection','exec'),scope)
        machine='00000000-0000-4000-8000-000000000062';sid='S-1-5-21-1-2-3-1001';boot='2026-01-01T00:00:00.0000000Z';session={key:0 for key in 'SessionId State Flags Station User Domain Logon Connect Disconnect LastInput Current InBytes OutBytes InFrames OutFrames InCompressed OutCompressed'.split()};session.update(SessionId=1,State=0,Flags=1,Station='Console',User='fixtureuser',Domain='INERT',Logon=100)
        base={'state':'observed','provider':'raw-qemu-windows','machine':machine,'guest':'running','guestAgent':True,'actor':{'pid':1,'startTicks':1},'hostBoot':'00000000-0000-4000-8000-000000000001','controlConnection':'inert-qmp','sessionFacts':{'machine':machine,'boot':boot,'console':1,'infoLevel':1,'session':session,'tokenSid':sid,'expectedSid':sid,'ordinary':True,'sessions':[{'Id':0,'Name':'Services','State':4},{'Id':1,'Name':'Console','State':0}],'explorers':[{'Id':2,'SessionId':1}]},'displayFacts':{'schemaVersion':1,'machine':machine,'boot':boot,'displayState':0},'idleFacts':None,'hostWork':None}
        driver=source('wakeBefore'if BEFORE=='wake-operators'else'wakeAfter');top=next(n for n in ast.parse(driver).body if isinstance(n,ast.With));body=next(n for n in top.body if isinstance(n,ast.Try)).body;code=compile(ast.Module(body=body,type_ignores=[]),'actual-wake-operator-admission-route','exec');plain_scope=load_control_definitions(driver,{'plain'},{})
        for competing in (False,True):
            with self.subTest(competing=competing):
                facts=copy.deepcopy(base)
                if competing:facts['sessionFacts']['sessions'].append({'Id':77,'Name':'INERT-OTHER','State':0})
                self.assertNotIn('competingSessions',facts['sessionFacts']);decoded=guest.validate_session(facts['sessionFacts'],sid,'fixtureuser',machine);self.assertEqual(decoded['competingSessions'],competing);calls=[]
                backend=types.SimpleNamespace(_managed_original=None,capabilities=frozenset(),provider='raw-qemu-windows',binding={'setup':{'user':'fixtureuser'}},expected_sid=sid,target='inert-owned',machine=machine,lease_root_generation=None)
                def native_io(mode,operation,deadline,**options):
                    if mode=='observe':
                        value=copy.deepcopy(facts);value['displayFacts']['displayState']=1 if calls else 0;return value,types.SimpleNamespace(connection='inert-source-only')
                    if mode=='wake_display':calls.append('motion-boundary');return {'state':'submitted','wakeInputSubmitted':True},None
                    raise AssertionError('unexpected native mode')
                backend._run=native_io;backend.observe=lambda requirements,deadline:scope['observe'](backend,requirements,deadline)
                namespace={'backend':backend,'readiness':readiness,'time':__import__('time'),'save':lambda *args:None,'plain':plain_scope['plain'],'asdict':__import__('dataclasses').asdict,'hashlib':hashlib,'json':json,'OP':'00000000-0000-4000-8000-000000000002','binding':backend.binding,'guard':lambda:None,'OUT':ROOT,'sources':{},'session_module':guest,'expected_sid':sid}
                with contextlib.redirect_stdout(io.StringIO()):
                    if not competing:exec(code,namespace);self.assertEqual(calls,['motion-boundary'])
                    else:
                        with self.assertRaisesRegex(ValueError,'direct_wake_current_recipient_not_ready'):exec(code,namespace)
                        self.assertFalse(calls)

if __name__=='__main__':unittest.main()
