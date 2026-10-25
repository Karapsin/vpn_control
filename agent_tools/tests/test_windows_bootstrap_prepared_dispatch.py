"""Complete old/new harmless dispatcher boundaries; no SSH or VM endpoint."""
from pathlib import Path
from contextlib import chdir,contextmanager
import hashlib,importlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from unittest import mock
from uuid import uuid4
from agent_tools import readiness,ssh_transport as transport
from agent_tools.native_review_source_closure import generation
from agent_tools.tests import test_windows_bootstrap_durable as owner_fixtures

FIXTURE=Path(__file__).with_name('fixtures')/'windows_bootstrap_dispatch'


def load(path):
    name='bootstrap_dispatch_fixture_'+uuid4().hex;raw=path.read_bytes()
    spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path));module=importlib.util.module_from_spec(spec)
    module.__file__=str(path);sys.modules[name]=module;exec(compile(raw,str(path),'exec'),module.__dict__);return module


class StoredDispatcherTests(unittest.TestCase):
    def case(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);direct=root/'.runtime/tool-recovery-windows/direct';direct.mkdir(parents=True)
        own=root/'dispatcher.py';own.write_bytes((FIXTURE/'dispatcher.source').read_bytes());subject=load(own)
        operation=str(uuid4());packet=direct/('bootstrap-linux-packet-'+operation);packet.mkdir(mode=0o700)
        caller=b'print("stored reviewed caller")\n';(packet/'caller.py').write_bytes(caller)
        source=root/'never_import_this_payload.py';source.write_bytes(b'raise AssertionError("payload imports forbidden at dispatch")\n')
        copy=packet/'sources/source.py';copy.parent.mkdir();copy.write_bytes(source.read_bytes())
        manifest={'schemaVersion':1,'group':'bootstrap','operationId':operation,'nativeSubmitted':False,'vmCalls':0,
            'callerSha256':hashlib.sha256(caller).hexdigest(),'callerBytes':len(caller),'sourceFiles':1,
            'sources':[{'path':str(source),'generation':list(generation(source.stat())),
                'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'bytes':source.stat().st_size,'copy':'sources/source.py'}]}
        raw=json.dumps(manifest).encode();(packet/'manifest.json').write_bytes(raw)
        subject.seal(root,packet,hashlib.sha256(raw).hexdigest())
        sha=hashlib.sha256((packet/'dispatch-manifest.json').read_bytes()).hexdigest()
        return root,packet,operation,subject,sha,source

    def invoke(self,case,run):
        root,packet,operation,subject,sha,_=case
        @contextmanager
        def admitted(*args,**kwargs):yield None
        with chdir(root),mock.patch.object(transport,'admitted_transport',admitted),mock.patch.object(transport,'load_config',return_value={}),mock.patch.object(transport,'build_ssh_argv',return_value=['controlled-public']),mock.patch.object(transport,'run_ssh',side_effect=run)as submit:
            try:return subject.dispatch(root,packet,sha)
            finally:self.assertLessEqual(submit.call_count,1)

    def old_capsule(self,case,run):
        root,packet,operation,subject,sha,_=case
        old=root/'old-capsule.py';raw=(FIXTURE/'capsule.before.source').read_bytes();old.write_bytes(raw)
        @contextmanager
        def admitted(*args,**kwargs):yield None
        with chdir(root),mock.patch.object(transport,'admitted_transport',admitted),mock.patch.object(transport,'load_config',return_value={}),mock.patch.object(transport,'build_ssh_argv',return_value=['controlled-public']),mock.patch.object(transport,'run_ssh',side_effect=run)as submit:
            with self.assertRaises(BaseException):
                exec(compile(raw,str(old),'exec'),{'__file__':str(old),'OPERATION':operation,'CALLER':(packet/'caller.py').read_bytes(),
                    'PROCEDURE':'controlled-public','OUTER_SOURCE':b'preserved-old-outer','SOURCE_CUSTODY':[], 'OUTER_GUARD':lambda:None})
            self.assertEqual(submit.call_count,1)
        return root/'.runtime/tool-recovery-windows/direct'/('admitted-'+operation)

    def test_all_whole_sources_authenticated(self):
        expected={'outer.before.source':'fe2baf937bb21f54335f827cc6f48fdb06f8b03448ab75a905b63b9728f2211c',
            'capsule.before.source':'86db23ae32fbe23eaa57c938cfe46aef7fc90de9b2592ad331da288d1685be58',
            'dispatcher.source':'6210bb28ec3d28c9e5d259e922e62cb89c70031522b21d5af767ba7b5e34b431','provenance.json':'e61ffde1fab14a3dc4ca1188ce87ec24754f2b9f50cf304123a4c2171fb4e1c5'}
        self.assertEqual({p.name for p in FIXTURE.iterdir()},set(expected))
        for name,sha in expected.items():self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),sha)

    def test_complete_old_rebuilds_before_packet_new_only_stored_bytes(self):
        case=self.case();root,packet,operation,subject,sha,_=case
        old=FIXTURE/'outer.before.source';attempts=[]
        def refuse_import(name):attempts.append(name);raise RuntimeError('actual old graph reconstruction before stored admission')
        with chdir(root),mock.patch.object(sys,'argv',['outer','bootstrap','--operation',operation,'--packet-sha256',hashlib.sha256((packet/'manifest.json').read_bytes()).hexdigest()]),mock.patch.object(importlib,'import_module',side_effect=refuse_import):
            with self.assertRaisesRegex(RuntimeError,'actual old graph reconstruction'):
                exec(compile(old.read_bytes(),str(old),'exec'),{'__file__':str(old)})
        self.assertTrue(attempts)
        if os.environ.get('VPN_CONTROL_BOOTSTRAP_DISPATCH_BEFORE')=='1':
            self.assertEqual(attempts,[],'old driver reconstructs before stored-packet admission');return
        result=subprocess.CompletedProcess([],0,b'{"state":"passed"}\n',b'')
        with mock.patch.object(importlib,'import_module',side_effect=AssertionError('dispatch reconstructed payload')):
            self.assertEqual(self.invoke(case,lambda *a,**k:result)['state'],'passed')
        admitted=root/'.runtime/tool-recovery-windows/direct'/('admitted-'+operation)
        self.assertEqual((admitted/'caller.py').read_bytes(),(packet/'caller.py').read_bytes())

    def test_exact_submitted_reply_old_lost_new_retained_once_no_replay(self):
        result=subprocess.CompletedProcess([],7,b'public original output\n',b'public original error\n')
        def error():return transport.SubmittedResultReadinessChanged(readiness.ReadinessBlocked('session_changed','controlled'),result)
        old=self.old_capsule(self.case(),error());self.assertFalse((old/'callback.json').exists())
        if os.environ.get('VPN_CONTROL_BOOTSTRAP_DISPATCH_BEFORE')=='1':
            self.assertTrue((old/'callback.json').exists(),'old carrier lost sealed returned output');return
        case=self.case();root,_,op,subject,_,_=case;sealed=error()
        with self.assertRaisesRegex(ValueError,'original_submitted_reply_retained'):self.invoke(case,sealed)
        directory=root/'.runtime/tool-recovery-windows/direct'/('admitted-'+op)
        self.assertEqual((directory/'stdout.public').read_bytes(),result.stdout);self.assertEqual((directory/'stderr.public').read_bytes(),result.stderr)
        callback=json.loads((directory/'callback.json').read_bytes());self.assertEqual(callback['returnCode'],7);self.assertTrue(callback['submittedReadinessChanged'])
        self.assertTrue(json.loads((directory/'closing.failed.json').read_bytes())['callbackRetained']);self.assertFalse((directory/'closing.json').exists())
        with self.assertRaises(ValueError):sealed.take_submitted_result()
        with self.assertRaises(FileExistsError):self.invoke(case,AssertionError('must never submit second time'))

    def test_actual_timeout_partial_old_lost_new_bounded_incomplete(self):
        def timeout(*args,**kwargs):
            return owner_fixtures.run_owned([sys.executable,'-I','-B','-c','import sys,time;print("original partial public",flush=True);sys.stderr.write("partial error\\n");sys.stderr.flush();time.sleep(2)'],capture_output=True,timeout=.15)
        old=self.old_capsule(self.case(),timeout);self.assertFalse((old/'callback.json').exists())
        if os.environ.get('VPN_CONTROL_BOOTSTRAP_DISPATCH_BEFORE')=='1':
            self.assertTrue((old/'callback.json').exists(),'old carrier lost timeout partial output');return
        case=self.case();root,_,op,subject,_,_=case
        with self.assertRaisesRegex(ValueError,'partial_timeout_retained'):self.invoke(case,timeout)
        directory=root/'.runtime/tool-recovery-windows/direct'/('admitted-'+op);callback=json.loads((directory/'callback.json').read_bytes())
        self.assertEqual((directory/'stdout.public').read_bytes(),b'original partial public\n');self.assertEqual((directory/'stderr.public').read_bytes(),b'partial error\n')
        self.assertIsNone(callback['returnCode']);self.assertFalse(callback['stdoutComplete']);self.assertFalse(callback['stderrComplete']);self.assertTrue(callback['timeout'])
        self.assertFalse((directory/'closing.json').exists());self.assertTrue((directory/'closing.failed.json').exists())

    def test_source_change_after_return_keeps_raw_and_failed_closing(self):
        case=self.case();root,_,op,subject,_,source=case;result=subprocess.CompletedProcess([],0,b'{"state":"passed"}\n',b'completed public stderr')
        def changed(*args,**kwargs):source.write_bytes(source.read_bytes()+b'# real generation change\n');return result
        with self.assertRaises(ValueError):self.invoke(case,changed)
        directory=root/'.runtime/tool-recovery-windows/direct'/('admitted-'+op)
        self.assertEqual((directory/'stdout.public').read_bytes(),result.stdout);self.assertEqual((directory/'stderr.public').read_bytes(),result.stderr)
        self.assertFalse(json.loads((directory/'closing.failed.json').read_bytes())['sourceClosed']);self.assertFalse((directory/'closing.json').exists())

    def test_identical_source_inode_replacement_before_submit_refuses(self):
        case=self.case();root,_,op,subject,_,source=case;other=source.with_suffix('.new');other.write_bytes(source.read_bytes());other.replace(source)
        with self.assertRaises(ValueError):self.invoke(case,AssertionError('source replacement must not submit'))
        self.assertFalse((root/'.runtime/tool-recovery-windows/direct'/('admitted-'+op)).exists())

    def test_output_directory_replacement_never_redirects_original_capture(self):
        case=self.case();root,_,op,subject,_,_=case;directory=root/'.runtime/tool-recovery-windows/direct'/('admitted-'+op)
        moved=directory.with_name(directory.name+'-actual-original');result=subprocess.CompletedProcess([],0,b'{"state":"passed"}\n',b'')
        def replaced(*args,**kwargs):directory.rename(moved);directory.mkdir(mode=0o700);return result
        with self.assertRaises(ValueError):self.invoke(case,replaced)
        self.assertEqual((moved/'stdout.public').read_bytes(),result.stdout);self.assertTrue((moved/'closing.failed.json').exists())
        self.assertEqual(list(directory.iterdir()),[]);self.assertFalse((moved/'closing.json').exists())

    def test_timeout_overflow_records_counts_bounded_without_eof(self):
        case=self.case();root,_,op,subject,_,_=case
        error=subprocess.TimeoutExpired('controlled',1,output=b'x'*(subject.OUT_LIMIT+5),stderr=b'y'*(subject.ERR_LIMIT+3))
        with self.assertRaises(ValueError):self.invoke(case,error)
        directory=root/'.runtime/tool-recovery-windows/direct'/('admitted-'+op);callback=json.loads((directory/'callback.json').read_bytes())
        for name,limit,extra in (('stdout',subject.OUT_LIMIT,5),('stderr',subject.ERR_LIMIT,3)):
            self.assertEqual((directory/(name+'.public')).stat().st_size,limit);self.assertEqual(callback[name+'Bytes'],limit+extra)
            self.assertTrue(callback[name+'Truncated']);self.assertFalse(callback[name+'Complete'])


if __name__=='__main__':unittest.main()
