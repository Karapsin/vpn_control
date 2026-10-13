"""Real owned inert children through the actual emitted GUI recipe programs.

Production custody/helper/fixture dispatch and complete launcher source execute.
Only main's product boundary is replaced with an inert role; Linux /proc birth
reads are projected explicitly for portability. No guest, network, Xlib, VPN or private credential is used.
Timeout cleanup may signal only the exact admitted inert control child. All actual children are waited/reaped.
Set LINUX_GUI_CUSTODY_VARIANT=before for the preserved unfixed actual source.
"""
import ast, base64, hashlib, json, os, shutil, subprocess, sys, tempfile, unittest, uuid, zlib
from types import SimpleNamespace
from unittest.mock import patch
from agent_tools.native_review_source_closure import _Held
from pathlib import Path
from agent_tools import native_owner_gui_lifecycle_ssh as adapter
from agent_tools import native_scenario_bundle
ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).parent/'fixtures/linux_gui_source_custody'
VARIANT=os.environ.get('LINUX_GUI_CUSTODY_VARIANT','fixed')
if VARIANT not in ('before','fixed'):raise ValueError('causal variant')
CURRENT=(ROOT/'scripts/integration/linux_owner_lifecycle_scenario.py').read_text()
BEFORE=(FIXTURE/'driver.before.source').read_text()
SOCKS=(ROOT/'scripts/integration/socks_http_fixture.py').read_bytes()
RUNNER=(ROOT/'scripts/native_fixture_run.sh').read_bytes()
NAMES=adapter._FILES+('native-scenario-manifest.json','scenario-input.json','admissions.json')
CID='12345678-1234-4321-8123-123456789abc'
# An actual unchanged fixture-dispatch boundary from the preserved driver.
OLD_FIXTURE_DISPATCH='''def start_fixture_child(input_path,admissions_path,root,out,err):
    return subprocess.Popen([sys.executable,'-I','-B','-c',
        'import pathlib,runpy,sys;p=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(p.parent));sys.argv=sys.argv[1:];runpy.run_path(str(p),run_name="__main__")',str(Path(__file__)),
        '--fixture-worker',str(input_path),str(admissions_path),str(root)],stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True)
'''
_OWNED_CONTROL_SOURCE=r'''
class OwnedControlReapingUnknown(RuntimeError):
    """An owned harmless test child or its capture did not close in time."""

def complete_owned_control(process, timeout, *, communicate=False, reap_timeout=2):
    completion = process.communicate if communicate else process.wait
    try:
        return completion(timeout=timeout)
    except subprocess.TimeoutExpired as original:
        failures = []
        closed = False
        for action in ('terminate', 'kill'):
            try:
                if process.poll() is None:
                    getattr(process, action)()
            except OSError as error:
                failures.append(type(error).__name__ + ':errno=' + str(error.errno))
            try:
                completion(timeout=reap_timeout)
                closed = process.returncode is not None
                if closed:
                    break
            except (OSError, subprocess.TimeoutExpired) as error:
                failures.append(type(error).__name__ + ':errno=' + str(getattr(error, 'errno', None)) + ':timeout=' + str(getattr(error, 'timeout', None)))
        if not closed:
            unknown = OwnedControlReapingUnknown('owned_harmless_control_reaping_unknown')
            unknown.pid = process.pid
            unknown.cleanup_failures = tuple(failures)
            raise unknown from original
        original.owned_control_pid = process.pid
        original.owned_control_reaped = True
        original.cleanup_failures = tuple(failures)
        raise
'''
exec(compile(_OWNED_CONTROL_SOURCE, "owned_harmless_control_cleanup", "exec"), globals())

INERT_MAIN=_OWNED_CONTROL_SOURCE+r'''
def main():
    global display_env
    display_env=dict(os.environ)
    arguments=sys.argv[1:]
    if arguments[0]=='--component-helper':
        Path(arguments[1]).write_text(json.dumps({'pid':os.getpid(),'uid':os.getuid(),'role':'actual-helper','bodySha256':hashlib.sha256(fixed_source()).hexdigest()})+'\n');return 0
    if arguments[0]=='--fixture-worker':
        from socks_http_fixture import FixtureServer
        Path(arguments[3]+'/fixture-child.json').write_text(json.dumps({'pid':os.getpid(),'uid':os.getuid(),'role':'actual-fixture-worker','fixtureClass':FixtureServer.__name__})+'\n');return 0
    input_path=Path(arguments[arguments.index('--input')+1]);admissions_path=Path(arguments[arguments.index('--admissions')+1])
    spec=json.loads(input_path.read_bytes());root=Path(spec['componentRoot']);mode=spec['componentMode']
    if mode in ('helper','helper-clean'):
        if mode=='helper':
            changed=Path(__file__) if not ('_CUSTODY' in globals()) else Path(source_custody().path(FixedGuiSourceCustody.DRIVER))
            replacement="from pathlib import Path;Path("+repr(str(root/'replacement-marker'))+").write_text('executed')\n"
            temporary=changed.with_name(changed.name+'.replacement');temporary.write_text(replacement);temporary.chmod(0o600);os.replace(temporary,changed)
        try:
            result=isolated_helper(['--component-helper',str(root/'helper-child.json')]);code=result.returncode
        except Exception:code=64
        (root/'role-result.json').write_text(json.dumps({'mode':mode,'childExitCode':code,'replayAllowed':False})+'\n');return 0
    if mode=='fixture':
        with private_stream(root/'fixture.stdout.private') as out,private_stream(root/'fixture.stderr.private') as err:
            if '_CUSTODY' in globals():changed=Path(source_custody().path(FixedGuiSourceCustody.SOCKS))
            else:changed=Path(__file__).with_name('socks_http_fixture.py')
            temporary=changed.with_name(changed.name+'.replacement')
            temporary.write_text("from pathlib import Path;Path("+repr(str(root/'replacement-marker'))+").write_text('executed')\nclass FixtureServer:pass\n")
            temporary.chmod(0o600);os.replace(temporary,changed)
            child=None;control_unknown=False
            try:
                child=start_fixture_child(input_path,admissions_path,root,out,err);code=complete_owned_control(child,10)
            except OwnedControlReapingUnknown:code=64;control_unknown=True
            except Exception:code=64
        (root/'role-result.json').write_text(json.dumps({'mode':mode,'childPid':child.pid if child else None,'childExitCode':code,'childReaped':child is not None and child.returncode is not None,'controlClosureState':'UNKNOWN' if control_unknown else 'reaped' if child is not None and child.returncode is not None else 'not-submitted','replayAllowed':False})+'\n');return 0
    from socks_http_fixture import FixtureServer
    (root/'main-child.json').write_text(json.dumps({'pid':os.getpid(),'uid':os.getuid(),'fixtureClass':FixtureServer.__name__})+'\n');return 0
if __name__=='__main__':raise SystemExit(main())
'''

def production_component_source(variant):
    source=BEFORE if variant=='before' else CURRENT
    tree=ast.parse(source);entry=next(n for n in tree.body if isinstance(n,ast.If) and "__name__" in ast.get_source_segment(source,n))
    # Remove only the native product entry call. Every production decision and
    # loader function remains intact; the inert main is the finite OS boundary.
    lines=source.splitlines(keepends=True);source=''.join(lines[:entry.lineno-1]+lines[entry.end_lineno:])
    if variant=='before':source+='\n'+OLD_FIXTURE_DISPATCH
    return (source+'\n'+INERT_MAIN).encode()

def gen(st):return [st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]

def make_stage(root,variant,mode):
    stage=root/'stage';stage.mkdir(mode=0o700)
    bodies={adapter._FILES[0]:production_component_source(variant),adapter._FILES[1]:SOCKS,adapter._FILES[2]:RUNNER}
    manifest={'schemaVersion':1,'scenarioId':adapter.BUNDLE_SCENARIO_ID,'files':[{'path':p,'sha256':hashlib.sha256(bodies[p]).hexdigest(),'sizeBytes':len(bodies[p])} for p in adapter._FILES]}
    bodies['native-scenario-manifest.json']=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
    bodies['scenario-input.json']=json.dumps({'componentRoot':str(root),'componentMode':mode,'sourceIdentity':{'sourceSha':'c'*40}}).encode()
    bodies['admissions.json']=json.dumps({'source':{'packageSourceSha':'a'*40}}).encode()
    inputs=[];parents={}
    for name in NAMES:
        path=stage/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(bodies[name]);path.chmod(0o600)
        inputs.append({'path':name,'body':base64.b64encode(bodies[name]).decode(),'sha256':hashlib.sha256(bodies[name]).hexdigest(),'generation':gen(path.lstat())})
        cursor=path.parent
        while True:
            st=cursor.lstat();parents[str(cursor)]=[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid]
            if cursor==cursor.parent:break
            cursor=cursor.parent
    capsule={'stage':str(stage),'inputs':inputs,'parents':parents,'manifestSha256':hashlib.sha256(bodies['native-scenario-manifest.json']).hexdigest()}
    return stage,bodies,capsule

BOOTSTRAP=r'''import base64,builtins,io,json,os,sys,zlib
job,stage,encoded_capsule,encoded_plan,encoded_launcher,mutate=sys.argv[1:]
_ORIGINAL_CAPSULE=json.loads(zlib.decompress(base64.b64decode(encoded_capsule)));_ORIGINAL_PLAN=json.loads(base64.b64decode(encoded_plan))
# Actual PID/UID, explicit inert Linux birth projection, no /proc access.
intent=dict(_ORIGINAL_PLAN);intent['identity']={'jobId':intent['jobId'],'pid':os.getpid(),'startTicks':17,'receiptPath':job+'/receipt.json'}
with open(job+'/intent.json','w') as out:json.dump(intent,out)
os.chmod(job+'/intent.json',0o600)
open(job+'/release','x').close()
original_open=builtins.open

def projected_open(path,*args,**kwargs):
 if str(path)=='/proc/self/stat':return io.StringIO(str(os.getpid())+' (owned-inert) '+' '.join(['0']*19+['17']))
 return original_open(path,*args,**kwargs)
builtins.open=projected_open
original_os_open=os.open

def output_open(path,*args,**kwargs):
 fd=original_os_open(path,*args,**kwargs)
 if mutate=='1' and str(path)==job+'/failure.stderr':
  target=stage+'/scripts/integration/linux_owner_lifecycle_scenario.py'
  temporary=target+'.replacement'
  with original_open(temporary,'w') as out:out.write('from pathlib import Path;Path('+repr(os.path.dirname(job)+'/replacement-marker')+').write_text("executed")\n')
  os.chmod(temporary,0o600);os.replace(temporary,target)
 return fd
os.open=output_open
sys.argv=[sys.argv[0],job,stage]
exec(compile(base64.b64decode(encoded_launcher),'actual_complete_gui_launcher','exec'))
'''

@unittest.skipUnless(os.name=='posix' and callable(getattr(os,'getuid',None)),'strict Linux source FD custody requires POSIX nofollow and actual UID APIs')
class ActualEmittedSourceCustodyTest(unittest.TestCase):
    def launch(self,mode='main',mutate=False):
        root=Path(tempfile.mkdtemp(prefix='owned-gui-custody-')).resolve();cleanup_state={'permitted':True}
        self.addCleanup(lambda: shutil.rmtree(root) if cleanup_state['permitted'] else None)
        stage,bodies,capsule=make_stage(root,VARIANT,mode);job=root/'job';job.mkdir(mode=0o700)
        plan={'scenarioId':adapter.SCENARIO_ID,'host':'inert-local','environment':'owned-component','bundleHash':capsule['manifestSha256'],
            'artifactIds':{'bundleManifest':'sha256-'+capsule['manifestSha256'],'scenarioInput':'sha256-'+hashlib.sha256(bodies['scenario-input.json']).hexdigest()},'correlationId':CID,'jobId':'gui-lifecycle-'+CID}
        launcher=(FIXTURE/'launcher.before.source').read_text() if VARIANT=='before' else adapter._LAUNCHER
        encode=lambda v:base64.b64encode(v).decode()
        argv=[sys.executable,'-I','-B','-c',BOOTSTRAP,str(job),str(stage),encode(zlib.compress(json.dumps(capsule).encode())),encode(json.dumps(plan).encode()),encode(launcher.encode()),'1' if mutate else '0']
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:stdout,stderr=complete_owned_control(child,20,communicate=True)
        except OwnedControlReapingUnknown as error:
            cleanup_state['permitted']=False
            error.retained_root=str(root)
            (root/'control-unknown.public.json').write_text(json.dumps({'state':'UNKNOWN','pid':child.pid,'replayAllowed':False,'nativeActionAllowed':False})+'\n')
            raise
        role_path=root/'role-result.json'
        if role_path.exists() and json.loads(role_path.read_text()).get('controlClosureState')=='UNKNOWN':
            cleanup_state['permitted']=False
            raise OwnedControlReapingUnknown('embedded_harmless_control_reaping_unknown')
        record={'pid':child.pid,'exitCode':child.returncode,'actualReaped':child.returncode is not None,'stdoutBytes':len(stdout),'stderrBytes':len(stderr),
            'kernelBirthProjection':17,'nativeAcceptance':False,'replayAllowed':False}
        (root/'actual-outer-child.json').write_text(json.dumps(record)+'\n')
        self.assertEqual(child.returncode,0,stderr.decode()[-2000:]);self.assertTrue(record['actualReaped'])
        self.assertEqual(stdout,b'');self.assertEqual(stderr,b'')
        receipt=json.loads((job/'receipt.json').read_text());self.assertEqual(receipt['pid'],child.pid);self.assertEqual(receipt['startTicks'],17)
        evidence_root=os.environ.get('LINUX_GUI_CUSTODY_EVIDENCE_DIR')
        if evidence_root:
            parent=Path(evidence_root).resolve();self.assertTrue(parent.is_dir());self.assertEqual(parent.stat().st_uid,root.stat().st_uid)
            retained=parent/(VARIANT+'-'+mode+'-'+('output-replacement' if mutate else 'original')+'-'+uuid.uuid4().hex)
            (root/'original-capsule.json').write_text(json.dumps(capsule,sort_keys=True)+'\n')
            (root/'scope.public.json').write_text(json.dumps({'scope':'historical-inert-component','actualOuterPid':child.pid,'actualOuterReaped':True,'kernelBirthProjection':17,'nativeActionAllowed':False,'productAcceptance':False,'replayAllowed':False})+'\n')
            shutil.copytree(root,retained)
        return root,job,record
    def test_actual_complete_launcher_rejects_replacement_during_output_setup(self):
        root,job,record=self.launch(mutate=True)
        self.assertFalse((root/'replacement-marker').exists(),'replaced staged source actually executed')
        self.assertFalse((job/'child.pid').exists())
        evidence=json.loads((job/'evidence.json').read_text());self.assertFalse(evidence['originalChildSubmitted']);self.assertEqual(evidence['cleanupState'],'unknown')
    def test_actual_normal_guest_namespace_binds_original_fixture(self):
        root,job,_=self.launch()
        proof=json.loads((root/'main-child.json').read_text());actual_pid=int((job/'child.pid').read_text())
        self.assertEqual(proof['pid'],actual_pid);self.assertEqual(proof['uid'],root.stat().st_uid);self.assertEqual(proof['fixtureClass'],'FixtureServer')
        self.assertEqual((job/'child.exit').read_text().strip(),'0')
    def test_actual_helper_creation_rejects_late_named_replacement(self):
        root,job,_=self.launch('helper')
        self.assertFalse((root/'replacement-marker').exists(),'actual helper executed replacement bytes')
        proof=json.loads((root/'role-result.json').read_text());self.assertNotEqual(proof['childExitCode'],0)
        self.assertFalse((root/'helper-child.json').exists())
        self.assertEqual((job/'child.exit').read_text().strip(),'0')
    def test_actual_helper_child_uses_normal_original_namespace(self):
        root,job,_=self.launch('helper-clean')
        proof=json.loads((root/'helper-child.json').read_text());result=json.loads((root/'role-result.json').read_text())
        self.assertGreater(proof['pid'],0);self.assertEqual(proof['uid'],root.stat().st_uid)
        capsule=json.loads((root/'original-capsule.json').read_text()) if (root/'original-capsule.json').exists() else None
        expected=hashlib.sha256((root/'stage'/adapter._FILES[0]).read_bytes()).hexdigest()
        self.assertEqual(proof['bodySha256'],expected);self.assertEqual(result['childExitCode'],0)
        self.assertEqual((job/'child.exit').read_text().strip(),'0')

    def test_actual_fixture_dispatch_closes_after_output_setup(self):
        root,job,_=self.launch('fixture')
        self.assertFalse((root/'replacement-marker').exists(),'actual fixture imported replaced named source')
        proof=json.loads((root/'role-result.json').read_text());self.assertIsNone(proof['childPid']);self.assertNotEqual(proof['childExitCode'],0)
        self.assertFalse((root/'fixture-child.json').exists());self.assertEqual((job/'child.exit').read_text().strip(),'0')
    def test_missing_original_custody_never_rehashes_named_source(self):
        namespace=adapter._source_namespace(CURRENT.encode(),SOCKS)
        namespace['_CUSTODY'].close();del namespace['_CUSTODY']
        with self.assertRaisesRegex(namespace['ScenarioError'],'original_source_custody_required'):namespace['fixed_source']()

    def test_joined_original_fd_population_closes_on_current_name_drift(self):
        with tempfile.TemporaryDirectory(prefix='owned-gui-fd-close-') as t:
            root=Path(t).resolve();stage,bodies,capsule=make_stage(root,'fixed','main')
            namespace=adapter._source_namespace(bodies[adapter._FILES[0]],bodies[adapter._FILES[1]])
            custody=namespace['FixedGuiSourceCustody'](capsule);fds=list(custody._fds)
            self.assertGreater(len(fds),len(NAMES));target=stage/adapter._FILES[0]
            temporary=target.with_name(target.name+'.changed');temporary.write_bytes(b'print("owned inert replacement")\n');temporary.chmod(0o600);os.replace(temporary,target)
            try:
                with self.assertRaises(namespace['ScenarioError']):custody.finish()
            finally:custody.close();namespace['_CUSTODY'].close()
            for fd in fds:
                with self.assertRaises(OSError):os.fstat(fd)


    def test_actual_transport_dispatch_closes_after_argv_output_setup(self):
        with tempfile.TemporaryDirectory(prefix='owned-gui-transport-') as t:
            root=Path(t).resolve();source=root/'original.py';source.write_bytes(b'# Original explicitly held source\n');source.chmod(0o600)
            held=_Held();held.read(str(source),hashlib.sha256(source.read_bytes()).hexdigest(),max_bytes=source.stat().st_size)
            marker=root/'transport-marker.json';driver=adapter.NativeOwnerGuiLifecycleSshDriver(ROOT,lambda p:None,lambda p:None)
            actual_command=[sys.executable,'-I','-B','-c','import json,os;from pathlib import Path;Path('+repr(str(marker))+').write_text(json.dumps({"pid":os.getpid(),"uid":os.getuid()}));print("{}")']
            def setup(*args,**kwargs):
                (root/'owned-output').write_bytes(b'')
                temporary=root/'replaced.py';temporary.write_bytes(b'# Named replacement after output setup\n');temporary.chmod(0o600);os.replace(temporary,source)
                return actual_command
            try:
                with patch.object(adapter.ssh_transport,'build_ssh_argv',side_effect=setup),patch.object(adapter.ssh_transport,'connection_host',return_value=SimpleNamespace(password=None)):
                    if VARIANT=='before':driver._run(None,'owned-component',('fixed-component',),b'')
                    else:
                        with self.assertRaises(ValueError):driver._run_closed(None,'owned-component',('fixed-component',),b'',held)
                self.assertFalse(marker.exists(),'original transport dispatch ran after its source identity changed')
            finally:held.close()


@unittest.skipUnless(os.name=='posix' and callable(getattr(os,'getuid',None)), 'owned harmless timeout controls require actual POSIX child ownership')
class OwnedHarmlessControlTimeoutTest(unittest.TestCase):
    def exercise(self, kind, refuse_cleanup=False):
        with tempfile.TemporaryDirectory(prefix='owned-gui-timeout-control-') as temporary:
            root=Path(temporary).resolve();ready=root/'ready.public.json';release=root/'release.control'
            original_popen=subprocess.Popen;children=[];timeout_records=[];retained_root=None
            record={'scope':'SOURCE_ONLY-owned-harmless-control','kind':kind,'nativeActionAllowed':False,'productAcceptance':False,'replayAllowed':False}
            class ProcessBoundary:
                def __init__(self, child):self.child=child
                def __getattr__(self, name):return getattr(self.child,name)
                def communicate(self, timeout=None):
                    actual=.1 if timeout==20 or refuse_cleanup else timeout
                    try:return self.child.communicate(timeout=actual)
                    except subprocess.TimeoutExpired as error:
                        timeout_records.append(repr(error));raise
                def wait(self, timeout=None):
                    actual=.1 if timeout==10 or refuse_cleanup else timeout
                    try:return self.child.wait(timeout=actual)
                    except subprocess.TimeoutExpired as error:
                        timeout_records.append(repr(error));raise
                def terminate(self):
                    if refuse_cleanup:raise PermissionError('explicit owned control process-boundary refusal')
                    return self.child.terminate()
                def kill(self):
                    if refuse_cleanup:raise PermissionError('explicit owned control process-boundary refusal')
                    return self.child.kill()
            def process_boundary(argv, **options):
                control=('import json,os,time;from pathlib import Path;ready=Path('+repr(str(ready))+');release=Path('+repr(str(release))+');'
                    'ready.write_text(json.dumps({"pid":os.getpid(),"uid":os.getuid()})+"\\n");print("owned-control-ready",flush=True)\n'
                    'while not release.exists():time.sleep(.01)\n')
                child=original_popen([sys.executable,'-I','-B','-c',control],**options);children.append(child)
                import time
                deadline=time.monotonic()+5
                while not ready.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(ready.exists());self.assertEqual(json.loads(ready.read_text())['pid'],child.pid)
                return ProcessBoundary(child)
            try:
                with patch.object(subprocess,'Popen',side_effect=process_boundary):
                    if kind=='outer':
                        case=ActualEmittedSourceCustodyTest('test_actual_normal_guest_namespace_binds_original_fixture');self.addCleanup(case.doCleanups)
                        try:case.launch()
                        except subprocess.TimeoutExpired as error:record['originalExceptionType']=type(error).__name__
                        except OwnedControlReapingUnknown as error:
                            record['state']='UNKNOWN';retained_root=Path(error.retained_root);record['retainedRootExists']=retained_root.is_dir()
                            case.doCleanups();record['retainedAfterRegisteredCleanup']=retained_root.is_dir()
                        else:self.fail('marker-wait control unexpectedly completed')
                    else:
                        stage,bodies,_=make_stage(root,'before','fixture');source=bodies[adapter._FILES[0]]
                        namespace={'__name__':'owned_inert_fixture_timeout','__file__':str(stage/adapter._FILES[0])}
                        exec(compile(source,'owned_inert_fixture_timeout','exec'),namespace)
                        with patch.object(sys,'argv',['owned-inert-fixture','--input',str(stage/'scenario-input.json'),'--admissions',str(stage/'admissions.json')]):
                            self.assertEqual(namespace['main'](),0)
                        record['roleResult']=json.loads((root/'role-result.json').read_text())
                self.assertEqual(len(children),1);record.update(originalPid=children[0].pid,
                    aliveAfterBody=children[0].poll() is None,reapedByBody=children[0].returncode is not None)
            finally:
                for child in children:
                    release.write_text('release this exact owned harmless child\n')
                    stdout,stderr=child.communicate(timeout=5)
                    self.assertEqual(child.pid,json.loads(ready.read_text())['pid']);record.update(finallyPid=child.pid,finallyReaped=child.returncode is not None,
                        finallyExitCode=child.returncode,stdoutBytes=len(stdout or b''),stderrBytes=len(stderr or b''))
                if retained_root is not None:
                    self.assertTrue(record['finallyReaped']);shutil.rmtree(retained_root)
                evidence_dir=os.environ.get('LINUX_GUI_TIMEOUT_EVIDENCE_DIR')
                if evidence_dir:
                    destination=Path(evidence_dir);self.assertTrue(destination.is_dir())
                    label=os.environ.get('LINUX_GUI_TIMEOUT_VARIANT','fixed')+'-'+kind+('-unknown' if refuse_cleanup else '')
                    (destination/(label+'.public.json')).write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
                    (destination/(label+'.timeout.raw.txt')).write_text('\n'.join(timeout_records)+'\n')
            return record

    def test_outer_timeout_reaps_exact_owned_control(self):
        record=self.exercise('outer');self.assertTrue(record['reapedByBody']);self.assertFalse(record['aliveAfterBody'])
        self.assertEqual(record['originalExceptionType'],'TimeoutExpired');self.assertTrue(record['finallyReaped'])

    def test_embedded_fixture_timeout_reaps_exact_owned_control(self):
        record=self.exercise('fixture');self.assertTrue(record['reapedByBody']);self.assertFalse(record['aliveAfterBody'])
        self.assertTrue(record['roleResult']['childReaped']);self.assertNotEqual(record['roleResult']['childExitCode'],0)
        self.assertTrue(record['finallyReaped'])

    def test_unproved_outer_control_cleanup_retains_unknown_evidence(self):
        record=self.exercise('outer',refuse_cleanup=True);self.assertEqual(record['state'],'UNKNOWN')
        self.assertTrue(record['aliveAfterBody']);self.assertFalse(record['reapedByBody'])
        self.assertTrue(record['retainedRootExists']);self.assertTrue(record['retainedAfterRegisteredCleanup']);self.assertTrue(record['finallyReaped'])

    def test_owned_harmless_control_ignoring_terminate_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory(prefix='owned-gui-kill-control-') as t:
            root=Path(t);ready=root/'ready';release=root/'release'
            code=('import signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);'
                'ready=Path('+repr(str(ready))+');release=Path('+repr(str(release))+');ready.write_text("ready")\n'
                'while not release.exists():time.sleep(.01)\n')
            child=subprocess.Popen([sys.executable,'-I','-B','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            import time
            try:
                deadline=time.monotonic()+5
                while not ready.exists() and child.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                self.assertTrue(ready.exists())
                with self.assertRaises(subprocess.TimeoutExpired) as caught:complete_owned_control(child,.1,communicate=True)
                self.assertTrue(caught.exception.owned_control_reaped);self.assertEqual(caught.exception.owned_control_pid,child.pid)
                self.assertEqual(child.returncode,-9)
            finally:
                release.write_text('release exact owned harmless child\n');child.communicate(timeout=5)


if __name__=='__main__':unittest.main()
