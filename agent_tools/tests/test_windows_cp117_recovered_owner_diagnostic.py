from agent_tools.tests.fixtures.windows_cp117_historical_factory.context import HistoricalFactoryTestCase as HistoryCase, provider as historical_provider
import ast,base64,copy,json,unittest,tempfile,os,sys
from pathlib import Path
from unittest.mock import patch
from agent_tools.tests.fixtures.windows_cp117_historical_factory.context import diagnostic as historical_diagnostic
d=historical_diagnostic()
from agent_tools import windows_cp117_recovered_owner_observe as owner
from agent_tools.tests.test_windows_cp117_recovered_owner_observe import OwnerFactsTests

class DiagnosticTests(HistoryCase):
    def value(self):
        return {'version':1,'correlationId':d.CORRELATION,'outcome':'blocked','stage':'process-generation','category':'OWNER_PROCESS_GENERATION','errorType':'RuntimeException','hresult':-2146233087,'observations':[{'pid':123,'sessionId':1,'osStart':'134356179626700513','cimStart':'134356179626700510','hasExited':False}],'facts':None,'details':'private measured mismatch'}
    def execute_flow(self,stale=False,foreign=False):
        import io,types,signal
        o=owner.guest;recipe=o.recovery.recipe();request={'recipeSha256':o.recovery._digest(recipe)}
        identity={'st_dev':1,'st_ino':2,'st_mode':16832,'st_uid':1000,'st_gid':1000}
        children=[{'role':role,'child':{'pid':pid},'pin':{'role':role},'intentPin':{},'attemptPin':{},'leafIdentity':identity}for role,pid in(('tpm',10),('qemu',11))]
        proof=[{'frame':{'kind':'child','value':c}}for c in children]
        sockets={name:{'kernelInode':str(i),'fingerprint':{'marker':name}}for i,name in enumerate(('swtpm.sock','qga.sock','qmp.sock'),100)}
        sockets['swtpm.sock']=o.TPM_SOCKET
        record={'request':request,'authority':proof,'result':{'state':'running','sockets':sockets}}
        source,sha=d.program(record);tree=ast.parse(source)
        # Execute every generated definition/constant, then the unchanged entire
        # operation. Only OS/transport authority observations are inert fixtures.
        self.assertIsInstance(tree.body[-1],ast.Try)
        ns={}
        with patch('signal.signal'),patch('signal.setitimer',create=True),patch('signal.ITIMER_REAL',0,create=True),patch('signal.SIGALRM',0,create=True):
            exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'complete-generated-definitions','exec'),ns)
        class FakeOS:
            O_RDONLY=0;O_DIRECTORY=0;O_NOFOLLOW=0
            def open(self,*a):return 1
            def fstat(self,*a):return types.SimpleNamespace(**identity)
            def lstat(self,path):
                if path.endswith('.sock'):return sockets[path.split('/')[-1]]['fingerprint']
                if path in recipe['files']:return types.SimpleNamespace(**recipe['files'][path]['fingerprint'])
                return types.SimpleNamespace(**identity)
            def listdir(self,path):return ['0','1','2']
            def stat(self,path):
                paths=(o.recovery.DISK,o.recovery.BACKING,o.recovery.VARS)
                return types.SimpleNamespace(**recipe['files'][paths[int(path.split('/')[-1])]]['fingerprint'])
        queries=[];anchors=[];out=io.StringIO();err=io.StringIO()
        def protected_read(name,pin):
            anchors.append(name)
            if name=='intent.json':return request
            if name=='attempt.json':return {'state':'consumed','requestSha256':o.recovery._digest(request)}
            return next(c['child']for c in children if name==c['role']+'.json')
        def call(path,op,args):
            queries.append((op,args))
            if op=='guest-exec':return {'pid':456}
            raw=('CP117-READ '+('old'if stale else d.NONCE)+' '+sha+' 456\n'+json.dumps(self.value())).encode()
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
        def rows(path):
            name=path.split('/')[-1];inode=sockets[name]['kernelInode']
            if foreign and name=='swtpm.sock':inode='999'
            return [dict(flags='00010000',type='0001',state='01',inode=inode)]
        ack=o.recovery._digest({'diagnosticId':d.CORRELATION,'nonce':d.NONCE,'sourceSha256':sha,'pid':456})
        ns.update(os=FakeOS(),fp=lambda s:s if isinstance(s,dict)else vars(s),read=protected_read,leaf_check=lambda:None,child_guard=lambda c,a:None,unix_rows=rows,fd_socket_inodes=lambda p:{s['kernelInode']for s in sockets.values()},call=call,open=lambda p:io.StringIO(recipe['bootId']),sys=types.SimpleNamespace(stderr=err,stdin=io.StringIO(ack+'\n')),time=types.SimpleNamespace(sleep=lambda n:None),result=lambda v:out.write(json.dumps(v)))
        with patch('select.select',return_value=([ns['sys'].stdin],[],[])),patch('signal.signal'),patch('signal.setitimer',create=True),patch('signal.ITIMER_REAL',0,create=True),patch('signal.SIGALRM',0,create=True):
            exec(compile(ast.Module(body=tree.body[-1:],type_ignores=[]),'complete-generated-operation','exec'),ns)
        return json.loads(out.getvalue()),queries,anchors


    def test_complete_generated_blocked_transport_is_diagnosis_not_admission(self):
        value,calls,anchors=self.execute_flow()
        self.assertEqual(value['facts'],self.value())
        self.assertEqual([op for op,_ in calls],['guest-exec','guest-exec-status'])
        self.assertEqual(calls[1][1],{'pid':456})
        report=d.summary(value['facts']);self.assertFalse(report['ordinaryRequesterAdmission'])
        self.assertNotIn('details',report);self.assertNotIn('observations',report)
        self.assertTrue({'intent.json','attempt.json','tpm.json','qemu.json'}<=set(anchors))
    def test_actual_stale_full_flow_exhausts_same_pid_without_new_dispatch(self):
        value,calls,_=self.execute_flow(stale=True)
        self.assertEqual(value['state'],'unknown');self.assertEqual(len(calls),81)
        self.assertEqual(sum(op=='guest-exec'for op,_ in calls),1)
        self.assertTrue(all(args=={'pid':456}for op,args in calls if op=='guest-exec-status'))
    def test_foreign_original_socket_zero_submit(self):
        value,calls,_=self.execute_flow(foreign=True)
        self.assertEqual(value['state'],'unknown');self.assertEqual(calls,[])
    def test_strict_output_identity_and_type_refusal(self):
        for update in ({'version':True},{'correlationId':'foreign'},{'hresult':False},{'stage':'arbitrary'},{'category':'arbitrary'},{'details':'x'*4097},{'facts':{}},{'observations':[{'pid':True,'sessionId':1,'osStart':'1','cimStart':'1','hasExited':False}]}):
            with self.subTest(update=update):
                with self.assertRaises(ValueError):d.validate(dict(self.value(),**update))
        with self.assertRaises(ValueError):d.validate(dict(self.value(),foreign=1))
    def test_original_success_facts_remain_required_and_never_grant_input(self):
        value=dict(self.value(),outcome='complete',stage='complete',category='none',errorType='none',hresult=0,details='',facts=OwnerFactsTests().facts())
        self.assertTrue(d.summary(d.validate(value))['originalFactsVerified'])
        value['facts']['explorers'][0]['elevated']=True
        self.assertFalse(d.summary(d.validate(value))['originalFactsVerified'])
    def test_original_body_predicates_unchanged_in_diagnostic(self):
        body=d.body()
        for predicate in ("[int]$t[5] -ne $item.SessionId","$again.CreationDate -ne $item.CreationDate"):
            self.assertIn(predicate,body)
        for forbidden in ('Start-Process','Stop-Process','SetValue(', 'LogonUser(', 'SendInput(', 'msiexec.exe /'):
            self.assertNotIn(forbidden,body)
        with patch.object(owner,'_PS',owner._PS+'\nforeign'):
            with self.assertRaises(ValueError):d.body()
    def test_consumed_correlation_never_queries(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);(root/'.runtime/parity-evidence'/('windows-cp117-owner-diagnostic-'+d.CORRELATION)).mkdir(parents=True)
            with patch.object(d.flow,'_stream')as stream:answer=d.observe(root)
            self.assertEqual(answer['stage'],'consumed');stream.assert_not_called()

@unittest.skipIf(os.name=='nt','POSIX repository transport')
class ActualStreamTests(HistoryCase):
    def run_child(self,tail,deadline=False):
        from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
        event={'kind':'submitted','diagnosticId':d.CORRELATION,'nonce':d.NONCE,'sourceSha256':'a'*64,'qemu':{'pid':12},'pid':456}
        script="import sys,json\nprint('CP117-OBSERVE '+"+repr(json.dumps(event))+",file=sys.stderr,flush=True)\nsys.stdin.readline()\n"+tail
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();(root/'.runtime/parity-evidence/test').mkdir(parents=True,mode=0o700)
            capture=AuthorityCapture(root,'test')
            try:
                try:
                    if deadline:
                        import time
                        clock=time.monotonic;start=clock()
                        with patch.object(d.flow.time,'monotonic',side_effect=lambda:start+(clock()-start)*100):
                            answer=d.flow._stream([sys.executable,'-c',script],capture,d.CORRELATION,d.NONCE,'a'*64,{'pid':12},None)
                    else:answer=d.flow._stream([sys.executable,'-c',script],capture,d.CORRELATION,d.NONCE,'a'*64,{'pid':12},None)
                    error=None
                except Exception as caught:answer=None;error=caught
                retained={p.name:p.read_bytes()for p in (root/'.runtime/parity-evidence/test').iterdir()}
                return answer,error,retained
            finally:capture.close()
    def test_actual_bad_output_retained_before_parse_failure(self):
        answer,error,retained=self.run_child("print('malformed original owner output')")
        self.assertIsInstance(error,json.JSONDecodeError)
        self.assertIn(b'malformed original owner output',b''.join(retained.values()))
        self.assertEqual(error.events[0]['event']['pid'],456)
    def test_actual_exit_retains_partial_stderr_and_original_child(self):
        answer,error,retained=self.run_child("print('bounded private cause',file=sys.stderr,flush=True);sys.exit(1)")
        self.assertRegex(str(error),'observer-exit')
        self.assertIn(b'bounded private cause',b''.join(retained.values()))
        self.assertEqual(error.events[0]['event']['pid'],456)

    def test_actual_local_reader_deadline_retains_child_and_partial_output(self):
        answer,error,retained=self.run_child("import time;print('partial owner evidence',flush=True);time.sleep(2)",deadline=True)
        self.assertRegex(str(error),'observer-deadline')
        self.assertIn(b'partial owner evidence',b''.join(retained.values()))
        self.assertEqual(error.events[0]['event']['pid'],456)

class ActualPowerShellBoundaryTests(HistoryCase):
    @unittest.skipUnless(os.name=='nt','actual Windows PowerShell boundary execution')
    def test_actual_whole_body_compiler_failure_original_opaque_new_retained(self):
        import subprocess
        def inert(value):
            # Throw at the actual compiler boundary; the rest of the real body
            # remains assembled but cannot execute native APIs or CIM queries.
            return value.replace(" Add-Type -TypeDefinition @'", " throw 'CP117_INERT_COMPILER_FAILURE'\n Add-Type -TypeDefinition @'",1)
        old=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command','-'],input=inert(owner.body()).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(old.returncode,1);self.assertEqual(json.loads(old.stdout),{'version':1,'code':'OWNER_UNKNOWN'})
        fixed=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command','-'],input=inert(d.body()).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(fixed.returncode,0,fixed.stderr.decode(errors='replace'))
        answer=d.validate(json.loads(fixed.stdout));self.assertEqual(answer['stage'],'compiler')
        self.assertEqual(answer['outcome'],'blocked');self.assertIn('CP117_INERT_COMPILER_FAILURE',answer['details'])
        self.assertIsNone(answer['facts']);self.assertEqual(answer['observations'],[])


@unittest.skipIf(os.name=='nt','POSIX protected local descriptor capture wrapper')
class ActualObserveWrapperTests(HistoryCase):
    def test_actual_wrapper_records_attempt_before_ack_only_boundary(self):
        from agent_tools.tests.test_windows_cp117_recovered_login import ScreenTests
        from contextlib import ExitStack
        r=d.owner.guest.recovery;record=ScreenTests().record();record['authority']=[];record['result']['qemu']={'pid':12}
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();(root/'.runtime/parity-evidence').mkdir(parents=True)
            for name in ('windows-cp117-recovery-'+r.CORRELATION,d.ORIGINAL_LOGIN_LEAF):(root/'.runtime/parity-evidence'/name).mkdir(mode=0o700)
            def local_read(capture,name,pin):
                return json.dumps({'state':'unknown','phase':'login-owner'}if name=='unknown.json'else record).encode()
            def native_boundary(argv,capture,correlation,nonce,sha,qemu,private):
                self.assertIsNone(private);self.assertEqual(correlation,d.CORRELATION);self.assertEqual(qemu,{'pid':12})
                leaf=root/'.runtime/parity-evidence'/('windows-cp117-owner-diagnostic-'+d.CORRELATION)
                for filename in ('attempt.json','remote.py','request.json'):self.assertTrue((leaf/filename).is_file())
                source=(leaf/'remote.py').read_text();self.assertIn('def validate(value):',source);compile(source,'actual-wrapper-carrier','exec')
                return {'state':'observed','facts':DiagnosticTests().value()},[]
            with ExitStack()as stack:
                stack.enter_context(patch.object(r,'_local_read',side_effect=local_read))
                stack.enter_context(patch.object(d.flow,'_execution_source_proof',return_value={'historical':False}))
                stack.enter_context(patch.object(r.authority,'_outer_authority',return_value={'fixed':True}))
                stack.enter_context(patch.object(r.authority,'_verify_outer'))
                stack.enter_context(patch.object(r.authority.closure.base,'_descriptor',return_value=({},None,None)))
                stack.enter_context(patch.object(r.authority.closure.base.ssh_transport,'build_ssh_argv',return_value=['fixed-observer']))
                boundary=stack.enter_context(patch.object(d.flow,'_stream',side_effect=native_boundary))
                answer=d.observe(root)
            self.assertEqual(answer['state'],'diagnosed');self.assertEqual(answer['stage'],'process-generation');self.assertEqual(boundary.call_count,1)
            self.assertFalse(answer['ordinaryRequesterAdmission'])

class ActualPrecisionPredicateTests(HistoryCase):
    def predicate(self,body,os_time,cim_time,exited=False,session=1):
        import re
        expression=re.search(r"if\((.*?)\)\{throw 'OWNER_PROCESS_GENERATION'\}",body).group(1)
        for before,after in (('$item.CreationDate.ToUniversalTime().ToFileTimeUtc()',repr(cim_time)),('$stamp',repr(os_time)),('$p.HasExited',repr(exited)),('$p.SessionId',repr(session)),('$item.SessionId','1')):expression=expression.replace(before,after)
        for before,after in ((' -or ',' or '),(' -ne ',' != '),(' -le ',' <= ')):expression=expression.replace(before,after)
        tree=ast.parse(expression,mode='eval')
        self.assertFalse(any(isinstance(n,(ast.Name,ast.Call,ast.Attribute))for n in ast.walk(tree)))
        return not eval(compile(tree,'actual-integer-cross-api-condition','eval'),{'__builtins__':{}})
    def test_measured_actual_original_predicate_red_and_integer_bucket_green(self):
        os_time=134356192583360055;cim_time=134356192583360050
        self.assertFalse(self.predicate(owner.body(),os_time,cim_time))
        self.assertTrue(self.predicate(d.body(),os_time,cim_time))
        for digit in range(10):self.assertTrue(self.predicate(d.body(),cim_time+digit,cim_time))
        for changed in (cim_time-10,cim_time+10,cim_time+1,0,-10):self.assertFalse(self.predicate(d.body(),os_time,changed))
        self.assertFalse(self.predicate(d.body(),os_time,cim_time,exited=True))
        self.assertFalse(self.predicate(d.body(),os_time,cim_time,session=0))
        self.assertNotIn('/ 10',d.body()) # no floating FILETIME rounding
        self.assertIn('GetProcessTimes(p,out c,out e,out k,out u)||c!=creation',d.body())
        self.assertIn('$p.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $stamp',d.body())
        self.assertIn('$again.CreationDate -ne $item.CreationDate',d.body())
    def test_timestamp_output_boolean_negative_malformed_refuses(self):
        for bad in (True,-1,'-1','1.0','NaN','١','x',''):
            value=DiagnosticTests().value();value['observations'][0]['osStart']=bad
            with self.assertRaises(ValueError):d.validate(value)
    @unittest.skipUnless(os.name=='nt','actual Windows PowerShell integer precision predicate')
    def test_actual_powershell_generated_condition_uses_integer_precision(self):
        import re,subprocess
        body=d.body();condition=re.search(r"if\((.*?)\)\{throw 'OWNER_PROCESS_GENERATION'\}",body).group(1)
        script="$ErrorActionPreference='Stop';$p=[pscustomobject]@{HasExited=$false;SessionId=1};$item=[pscustomobject]@{SessionId=1;CreationDate=[DateTime]::FromFileTimeUtc(134356192583360050)};"
        script+="foreach($n in 0..9){$stamp=[long]134356192583360050+$n;if("+condition+"){throw 'SAME_BUCKET_REFUSED'}};"
        script+="$stamp=[long]134356192583360060;if(-not ("+condition+")){throw 'FOREIGN_BUCKET_ACCEPTED'};'PRECISION_CASES_PASS'"
        completed=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command','-'],input=script.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(completed.returncode,0,completed.stderr.decode(errors='replace'));self.assertEqual(completed.stdout.decode().strip(),'PRECISION_CASES_PASS')

class MissingSignalApiCompositionTests(HistoryCase):
    def test_actual_complete_generated_linux_fixture_without_windows_signal_apis(self):
        import signal
        with patch.dict(signal.__dict__):
            for name in ('setitimer','SIGALRM','ITIMER_REAL'):signal.__dict__.pop(name,None)
            actual=DiagnosticTests()
            answer,calls,_=actual.execute_flow();self.assertEqual(answer['facts'],actual.value());self.assertEqual(len(calls),2)
            answer,calls,_=actual.execute_flow(stale=True);self.assertEqual(answer['state'],'unknown');self.assertEqual(len(calls),81)
            answer,calls,_=actual.execute_flow(foreign=True);self.assertEqual(answer['state'],'unknown');self.assertEqual(calls,[])
            self.assertTrue(all(name not in signal.__dict__ for name in ('setitimer','SIGALRM','ITIMER_REAL')))


class HistoricalSourceBindingTests(unittest.TestCase):
    """Public source-only controls; never invoke a native provider entry."""
    def test_exact_archive_and_one_byte_cleanup_refusal(self):
        import hashlib
        from agent_tools.tests.fixtures import historical_source
        from agent_tools.tests.fixtures.windows_cp117_historical_factory import context
        raw=context.SOURCE.read_bytes()
        self.assertEqual(len(raw),69940)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),context.SHA256)
        lines=raw.splitlines(keepends=True)
        self.assertTrue(lines[145].endswith(b"::Read([uint32[]]$ids)' \n"))
        lines[145]=lines[145][:-2]+b'\n'
        changed=b''.join(lines)
        self.assertEqual(hashlib.sha256(changed).hexdigest(),'3447001b51cb4df248e4566135bba568c5e3e090a9a9744d4ba3eafc4e9a8c12')
        with tempfile.TemporaryDirectory(prefix='cp117-public-source-control-') as tmp:
            path=Path(tmp)/'changed.source';path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError,'historical_source_binding_changed'):
                historical_source.load(path,context.SHA256)
            altered=historical_source.load(path,hashlib.sha256(changed).hexdigest())
            with patch.object(d,'flow',altered):
                with self.assertRaisesRegex(ValueError,'diagnostic-factory-source'):
                    d.program({})

    def test_scoped_historical_references_restore(self):
        from agent_tools import windows_cp117_installed_base_observe as installed
        from agent_tools import windows_cp117_base_source_refresh as refresh
        from agent_tools.tests.fixtures.windows_cp117_historical_factory import context
        modules=(d,installed,refresh);before=tuple(m.flow for m in modules)
        with context.historical_factories() as old:
            self.assertTrue(all(m.flow is old for m in modules))
            self.assertEqual(Path(old.__file__).read_bytes(),context.SOURCE.read_bytes())
        self.assertEqual(tuple(m.flow for m in modules),before)


    def test_actual_bound_source_reader_retains_one_mib_limit(self):
        with tempfile.TemporaryDirectory(prefix='cp117-public-cap-') as tmp:
            path=Path(tmp).resolve()/'oversized.source'
            path.write_bytes(b'x'*(1048576+1))
            with self.assertRaisesRegex(ValueError,'source-record'):
                owner.guest.recovery.authority._read_bound_file(path,retain_bytes=True)
