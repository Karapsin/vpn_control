"""Portable controls for the used GUI preparation admission; no native dispatch."""
import ast, contextlib, copy, hashlib, inspect, io, json, os, stat, unittest
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch
from agent_tools import native_owner_gui_lifecycle_ssh as canonical
from agent_tools import native_artifact_registry as registry

# An inert SOURCE override is used only when demonstrating preserved RED/GREEN.
def provider():
    source=os.environ.get('GUI_ADMISSION_CONTROL_SOURCE')
    if not source:return canonical
    import importlib.util
    spec=importlib.util.spec_from_file_location('agent_tools.gui_admission_control',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
G=provider()

class ProbeOS:
    O_RDONLY=0;O_DIRECTORY=1;O_NOFOLLOW=2
    path=__import__('posixpath')
    def __init__(self,problem=None):
        self.problem=problem;self.opened=[];self.closed=[];self.uid=1000
        self.context=SimpleNamespace(st_dev=1,st_ino=10,st_mode=stat.S_IFDIR|0o700,st_uid=1000,st_gid=1000)
        self.root=SimpleNamespace(st_dev=1,st_ino=11,st_mode=stat.S_IFDIR|0o700,st_uid=1000,st_gid=1000)
        if problem=='mode':self.root.st_mode=stat.S_IFDIR|0o755
        if problem=='owner':self.root.st_uid=2000
    def getuid(self):return self.uid
    def open(self,path,flags,dir_fd=None):
        if path=='/owned':fd=10
        elif path=='mcp-native' and dir_fd==10:
            if self.problem=='missing':raise FileNotFoundError(path)
            if self.problem=='symlink':raise OSError('nofollow')
            fd=11
        else:raise AssertionError('unexpected open')
        assert flags==3;self.opened.append(fd);return fd
    def fstat(self,fd):return copy.copy(self.context if fd==10 else self.root)
    def stat(self,path,dir_fd=None,follow_symlinks=None):
        assert follow_symlinks is False
        v=copy.copy(self.context if path=='/owned' else self.root)
        if self.problem=='replaced' and path=='mcp-native':v.st_ino+=1
        if self.problem=='context-replaced' and path=='/owned':v.st_ino+=1
        return v
    def close(self,fd):self.closed.append(fd)

def execute_probe(program,payload,filesystem):
    output=io.StringIO();fake_sys=SimpleNamespace(stdin=SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
    with patch.dict('sys.modules',{'os':filesystem,'sys':fake_sys}),contextlib.redirect_stdout(output):exec(program,{})
    return json.loads(output.getvalue())

class PreparationAdmissionTest(unittest.TestCase):
    def prepared(self):
        return (None,b'{}',None,{'guest':{'host':'owned','ownedRoot':'/owned/scenarios','uid':1000}},
                {G._FILES[0]:b'driver',G._FILES[1]:b'fixture'},None,PurePosixPath('/owned/mcp-native'),object(),None)
    def test_actual_preflight_missing_root_refuses_before_gui_probe(self):
        calls=[];fs=ProbeOS('missing');driver=G.NativeOwnerGuiLifecycleSshDriver(Path.cwd(),lambda p:None,lambda p:None)
        def run(config,host,command,payload,held):
            calls.append(payload)
            if json.loads(payload).get('root'):
                return execute_probe(G._TRANSFER_ROOT_PROBE,json.loads(payload),fs)
            return {'ready':True}
        with patch.object(driver,'_run_closed',side_effect=run),patch.object(G,'_probe_prefix',return_value=''),patch.object(G,'Path',PurePosixPath):
            self.assertFalse(driver._preflight_prepared(self.prepared())['ready'])
        self.assertEqual(len(calls),1);self.assertEqual(fs.closed,fs.opened)
    def test_actual_preflight_safe_root_then_gui_admission(self):
        calls=[];fs=ProbeOS();driver=G.NativeOwnerGuiLifecycleSshDriver(Path.cwd(),lambda p:None,lambda p:None)
        def run(config,host,command,payload,held):
            calls.append(payload)
            return execute_probe(G._TRANSFER_ROOT_PROBE,json.loads(payload),fs) if json.loads(payload).get('root') else {'ready':True}
        with patch.object(driver,'_run_closed',side_effect=run),patch.object(G,'_probe_prefix',return_value=''),patch.object(G,'Path',PurePosixPath):
            self.assertTrue(driver._preflight_prepared(self.prepared())['ready'])
        self.assertEqual(len(calls),2);self.assertCountEqual(fs.closed,fs.opened)
    def test_probe_actual_code_refuses_unsafe_generation_mode_and_owner(self):
        for problem in ('missing','symlink','mode','owner','replaced','context-replaced'):
            with self.subTest(problem=problem):
                fs=ProbeOS(problem);v=execute_probe(G._TRANSFER_ROOT_PROBE,{'root':'/owned/mcp-native','context':'/owned','uid':1000},fs)
                self.assertEqual(v,{'ready':False,'readOnly':True});self.assertCountEqual(fs.closed,fs.opened)
    def test_probe_actual_code_refuses_wrong_binding(self):
        for change in ({'uid':True},{'uid':2000},{'context':'/foreign'},{'root':'/owned/../mcp-native'}):
            fs=ProbeOS();v=execute_probe(G._TRANSFER_ROOT_PROBE,{'root':'/owned/mcp-native','context':'/owned','uid':1000,**change},fs)
            self.assertFalse(v['ready']);self.assertFalse(fs.opened)
    def record(self):
        body=b'unchanged preparation';digest=hashlib.sha256(body).hexdigest();locations=[]
        for correlation in ('original','current'):
            path=str(Path.cwd()/'.rag_index'/'native-owner-gui-preparations'/correlation/'guest.json')
            identity,location=registry._normalize_registration({'platform':'linux','artifactKind':'guest-receipt','sha256':digest,'size':len(body),'sourceSha':'a'*40,'localPath':path,'evidenceClass':'local-verified'},historical=True)
            locations.append(location)
        return body,{'schemaVersion':2,'artifactId':'sha256-'+digest,**identity,'locations':locations}
    @contextlib.contextmanager
    def registry_bytes(self,body,record):
        # Model only filesystem reads; actual registry selection and byte comparison run.
        with patch.object(registry,'_readonly_private_directory'),patch.object(registry,'_read_record_readonly',return_value=record),patch.object(registry,'_stream_local_bytes',return_value=(len(body),hashlib.sha256(body).hexdigest())):yield
    def test_actual_duplicate_registry_and_correlated_held_read(self):
        body,record=self.record();expected=Path(record['locations'][1]['localPath']);reads=[]
        held=SimpleNamespace(read=lambda path,digest,max_bytes:(reads.append(path) or body))
        with self.registry_bytes(body,record):
            with self.assertRaisesRegex(registry.NativeArtifactRegistryError,'no unique default'):registry.verify_artifact_readonly(Path.cwd(),record['artifactId'])
            args=(Path.cwd(),record['artifactId'],1024,held)
            data,_=G._held_registered(*args,expected) if 'expected_path' in inspect.signature(G._held_registered).parameters else G._held_registered(*args)
        self.assertEqual(data,body);self.assertEqual(reads,[str(expected)])
    def test_default_call_retains_original_two_argument_protocol(self):
        body,record=self.record();record['locations']=record['locations'][:1]
        original=registry.verify_artifact_readonly;calls=[]
        def two_args(root,identity):calls.append(identity);return original(root,identity)
        with self.registry_bytes(body,record),patch.object(registry,'verify_artifact_readonly',side_effect=two_args):
            self.assertEqual(G._held_registered(Path.cwd(),record['artifactId'],1024,SimpleNamespace(read=lambda *a,**k:body))[0],body)
        self.assertEqual(calls,[record['artifactId']])
    def test_missing_or_ambiguous_expected_location_refuses_before_held_read(self):
        body,record=self.record();held=SimpleNamespace(read=lambda *a,**k:self.fail('read after missing location'))
        with self.registry_bytes(body,record),self.assertRaisesRegex(G.NativeOwnerGuiLifecycleSshError,'correlated_preparation_location'):
            G._held_registered(Path.cwd(),record['artifactId'],1024,held,Path.cwd()/'wrong.json')
        record['locations'].append(copy.deepcopy(record['locations'][1]))
        with self.registry_bytes(body,record),self.assertRaisesRegex(G.NativeOwnerGuiLifecycleSshError,'correlated_preparation_location'):
            G._held_registered(Path.cwd(),record['artifactId'],1024,held,Path(record['locations'][1]['localPath']))
    def test_only_four_preparation_receipts_bind_known_correlation_paths(self):
        tree=ast.parse(Path(G.__file__).read_text());function=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='_prepare')
        calls=[n for n in ast.walk(function) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_held_registered']
        self.assertEqual(sorted(len(n.args) for n in calls),[4,5])
        explicit=next(n for n in calls if len(n.args)==5)
        self.assertIn('plan.correlation_id',ast.unparse(explicit.args[-1]));self.assertIn('native-owner-gui-preparations',ast.unparse(explicit.args[-1]))

if __name__=='__main__':unittest.main()
