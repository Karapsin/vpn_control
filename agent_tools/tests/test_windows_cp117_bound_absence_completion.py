"""Causal guards for terminal-only completion of a consumed absence closure."""
import unittest
from unittest import mock
from agent_tools import windows_cp117_bound_absence_completion as c


class TestTerminalOnly(unittest.TestCase):
    def census(self):
        return {'version':1,'correlationId':c.closure._CLOSE,'root':'present-valid','unknownEntry':False,
                'binding':{'state':'present-valid','sha256':'a'*64,'generation':{'bytes':1,'creationTicks':1,'writeTicks':1,'attributes':32,'owner':'S-1-5-18','aclSha256':'b'*64}},
                'terminal':{'state':'absent'}}

    def test_routes_only_original_final_no_initial_binding_source(self):
        with mock.patch.object(c.closure,'_scripts',return_value=('FORBIDDEN-FIRST','EXACT-FINAL',{'binding':{}})):
            self.assertEqual(c._final_only({},[],{}, {'binding':{}}),'EXACT-FINAL')

    def test_rejects_original_intent_drift(self):
        with mock.patch.object(c.closure,'_scripts',return_value=('FIRST','FINAL',{'different':True})):
            with self.assertRaises(ValueError):c._final_only({},[],{}, {'binding':{}})

    def test_valid_binding_and_absent_terminal_required(self):
        self.assertEqual(c._admit_census(self.census()),self.census()['binding'])
        for kind in ('terminal','binding','root','unknownEntry'):
            value=self.census()
            if kind=='terminal':value[kind]={'state':'present-valid'}
            elif kind=='binding':value[kind]['state']='unknown'
            elif kind=='root':value[kind]='absent'
            else:value[kind]=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):c._admit_census(value)

    def test_binding_generation_drift_rejected(self):
        first=self.census();later=self.census();later['binding']['generation']['writeTicks']=2
        with self.assertRaises(ValueError):c._admit_census(later,first['binding'])

    def test_stale_same_schema_census_cannot_override_new_source_nonce(self):
        value=self.census()
        with self.assertRaises(ValueError):c._bound_census(value,{'nonce':'old','sourceSha256':'a'*64},'new','b'*64)

    def test_consumed_attempt_does_not_dispatch_again_after_unknown(self):
        records={};calls=[]
        def create(name,value):
            if name in records:raise FileExistsError(name)
            records[name]=value
        def dispatch():calls.append(True);raise ConnectionError('lost-stream')
        for _ in range(2):
            with self.assertRaises((ConnectionError,FileExistsError)):
                c._consume_attempt(create,{'sourceSha256':'a'*64},dispatch)
        self.assertEqual(calls,[True])
        self.assertEqual(set(records),{'attempt.json'})

    def test_before_dispatch_guard_failure_never_submits(self):
        calls=[]
        with self.assertRaises(ValueError):
            c._consume_attempt(lambda *args:None,{},lambda:calls.append(True),guard=lambda:(_ for _ in ()).throw(ValueError('drift')))
        self.assertEqual(calls,[])

class TestActualWorkflow(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from contextlib import nullcontext
        from agent_tools.tests.test_windows_cp117_static_tasks_retire import snapshot,packet
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();(self.root/'.rag_index').mkdir(mode=0o700)
        (self.root/'.runtime').mkdir(mode=0o755);(self.root/'.runtime/parity-evidence').mkdir(mode=0o755)
        r=c.closure;expected=r.original._expected();rows=[snapshot(e)for e in expected]
        snapshots=[r.original._archive(a,e)for a,e in zip(rows,expected)]
        original_binding={'retirementCorrelationId':r.original._RETIREMENT,'generation':list(r.wire.observer._GENERATION),'originalProductSourceSha':r.original._SOURCE,'historicalRecordSha256':r.original._RECORDS,'taskArgumentSha256':list(r.original._ARGUMENT_HASHES),'taskToolSourceSha256':[e['toolSourceSha256']for e in expected],'snapshots':snapshots}
        old=r.original._plan(original_binding,expected)[1]
        progress=[{'retirementCorrelationId':r.original._RETIREMENT,'index':i,'bindingSha256':old['bindingSha256'],'xmlSha256':a['xmlSha256'],'state':'removed'}for i,a in enumerate(rows)]
        proof={'originalIntent':old,'archivePayloadSha256':packet(rows)['sha256'],'progress':progress}
        binding=r._binding(r.wire.observer._GENERATION,proof);first,final,intent=r._scripts(binding,expected,proof)
        self.context={'sources':{},'outerAuthority':{},'descriptor':r.wire.observer._GENERATION,'closed':{},'expected':expected,'proof':proof,'intent':intent,'final':final}
        self.first=first;self.pin=TestTerminalOnly().census()['binding'];self.census=TestTerminalOnly().census();self.calls=[]
        for obj,name,kw in [(c,'_source_pins',{'return_value':{}}),(c,'_context',{'return_value':self.context}),
              (c,'_guard',{'return_value':None}),(r.original,'_start_admission',{'side_effect':lambda root:nullcontext()}),
              (r.history,'_history_lock',{'side_effect':lambda root:nullcontext()}),(r,'_fresh_read_scope',{'side_effect':lambda *args:nullcontext()})]:
            p=mock.patch.object(obj,name,**kw);p.start();self.addCleanup(p.stop)

    def test_actual_generated_final_and_command_cap(self):
        final=c._catalog(self.context,'final',self.pin)
        self.assertTrue(final.endswith(self.context['final']))
        self.assertNotIn("Write-SecureJsonCreate 'binding.json'",final)
        self.assertIn("Write-SecureJsonCreate 'terminal.json'",final)
        self.assertIn('binding-generation',final)
        self.assertLess(len(c.closure.wire._command(final)),30000)
        census=c._catalog(self.context,'census')
        self.assertLess(len(c.closure.wire._command(census)),30000)
        with self.assertRaises(ValueError):c._catalog(self.context,'binding')

    def test_actual_generated_prefix_hash_is_defined_before_census_executes(self):
        source=c._catalog(self.context,'final',self.pin)
        # The actual generated prefix executes this read before the preserved
        # suffix; its LeafGeneration calls Hash synchronously.
        self.assertIn('Hash ([Text.Encoding]::UTF8.GetBytes',source)
        self.assertLess(source.index('function Hash('),source.index("$current=CensusLeaf 'binding.json'"))

    def test_actual_unknown_final_workflow_never_replays(self):
        def run(root,context,role,capture,pin=None):
            self.calls.append(role)
            if role=='census':return self.census
            if role=='final':
                self.assertTrue((self.root/c._DIR/'attempt.json').exists())
                raise ConnectionError('failed-stream')
            self.fail('unexpected status')
        with mock.patch.object(c,'_run_bound',side_effect=run):
            self.assertEqual(c.start(self.root,{})['state'],'unknown')
            for _ in range(3):self.assertEqual(c.start(self.root,{})['phase'],'attempt-consumed')
        self.assertEqual(self.calls,['census','final'])

    def test_actual_existing_terminal_stops_before_attempt(self):
        value=dict(self.census);value['terminal']={'state':'present-valid'}
        with mock.patch.object(c,'_run_bound',return_value=value):self.assertEqual(c.start(self.root,{})['state'],'blocked')
        self.assertFalse((self.root/c._DIR/'attempt.json').exists())

    def test_actual_success_routes_final_then_fresh_status(self):
        def run(root,context,role,capture,pin=None):
            self.calls.append(role)
            if role=='census':return self.census
            if role=='final':return {'closed':True}
            return {'binding':context['intent'],'terminal':c._terminal(context['intent'])}
        with mock.patch.object(c,'_run_bound',side_effect=run):
            self.assertEqual(c.start(self.root,{})['state'],'closed')
            self.assertEqual(c.start(self.root,{})['phase'],'attempt-consumed')
        self.assertEqual(self.calls,['census','final','status'])

    def test_actual_bound_reader_ignores_nested_outer_master_checks(self):
        import json
        from types import SimpleNamespace
        from agent_tools import ssh_connection_session as connection
        subprocess=c.closure.base.subprocess
        capture=c._new_capture(self.root);self.addCleanup(capture.close)
        expected={'stdin':subprocess.DEVNULL,'stdout':subprocess.PIPE,'stderr':subprocess.PIPE,'timeout':90,'check':False}
        control={**expected,'timeout':5}
        def remote(*args):
            # Actual source reader's builder performs these authority reads
            # inside the scoped native observer. They are not native output.
            subprocess.run(['MASTER-CHECK'],**control)
            subprocess.run(['MASTER-CHECK'],**control)
            result=subprocess.run(['NATIVE'],**expected)
            return result.stdout
        def stream(argv,receive,retain_failure=None):
            request=json.loads((capture.path/'census-request.json').read_bytes())
            sha=c._digest(json.dumps(request,sort_keys=True,separators=(',',':')).encode())
            receipt={'child':{**request,'pid':456,'requestSha256':sha},'pins':{k:{}for k in ('request.json','child.json','seal.json','authority.json')},'hostRoot':str(self.root)}
            receive(('METADATA-ANCHOR '+json.dumps(receipt)).encode())
            return subprocess.CompletedProcess(argv,0,json.dumps({'state':'observed','receipt':self.census}).encode(),b'NATIVE-TRACE')
        target=SimpleNamespace(fixture_transfer_root=self.root)
        current='dbc88042fb791f11f8f2243466841b5a1ec47c472ee65878601a37dc8d586852'
        authority={'receiptSha256':current,'readyPin':{'generation':[1]},'proof':{'master':{'pid':234}}}
        self.context['outerAuthority']=authority
        def verify(root,host,receipt):
            self.assertEqual(receipt,current,'retired receipt must not be used after reviewed recovery')
            return True
        with mock.patch.object(c,'_outer_authority',return_value=authority,create=True),mock.patch.object(connection,'verify_reuse',side_effect=verify),mock.patch.object(c.closure.base,'_descriptor',return_value=(object(),target,self.context['descriptor'])),mock.patch.object(c.closure.base.ssh_transport,'build_ssh_argv',return_value=['NATIVE']),mock.patch.object(subprocess,'run',return_value=subprocess.CompletedProcess(['MASTER-CHECK'],0,b'',b'Master running (pid=14315)\r\n')),mock.patch.object(c.closure.base,'_remote',side_effect=remote),mock.patch.object(c,'_stream',side_effect=stream):
            self.assertEqual(c._run_bound(self.root,self.context,'census',capture),self.census)
        self.assertEqual((capture.path/'census-stderr.private').read_bytes(),b'NATIVE-TRACE')

    def test_local_named_lock_exchange_prevents_attempt(self):
        j=c._Journal(self.root);self.addCleanup(j.close)
        (self.root/c._DIR/'lock').unlink();(self.root/c._DIR/'lock').write_bytes(b'');(self.root/c._DIR/'lock').chmod(0o600)
        with self.assertRaises(ValueError):j.create('attempt.json',{})
        self.assertFalse((self.root/c._DIR/'attempt.json').exists())

    def test_local_attempt_fifo_rejected_without_blocking(self):
        import os
        j=c._Journal(self.root);self.addCleanup(j.close)
        os.mkfifo(self.root/c._DIR/'attempt.json',0o600)
        with self.assertRaises(ValueError):j.read('attempt.json')

class TestRetention(unittest.TestCase):
    def test_actual_host_setup_retains_child_before_lost_status_no_resubmit(self):
        import tempfile,sys,json,io
        from pathlib import Path
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();root.chmod(0o700)
            request={'nonce':'11111111-1111-4111-8111-111111111111','role':'final','generation':['vm','fixed-socket',1,2,'SID'],'sourceSha256':'a'*64}
            calls=[]
            def native(sock,operation,args):
                calls.append(operation)
                if operation=='guest-exec':return {'pid':456}
                raise ConnectionError('lost-poll')
            ns={'sys':sys,'call':native,'metadata_request':request,'metadata_command':'EXACT-FINAL'}
            with mock.patch.object(sys,'argv',['fixed',str(root)]):
                exec(c._ANCHOR+c._METADATA_CALL,ns)
                with redirect_stderr(io.StringIO())as stream:
                    self.assertEqual(ns['call']('fixed-socket','guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command','EXACT-FINAL'],'capture-output':True}),{'pid':456})
                receipt=json.loads(stream.getvalue().split(' ',1)[1]);self.assertEqual(receipt['child']['pid'],456)
                self.assertEqual(set(receipt['pins']),{'request.json','child.json','seal.json','authority.json'})
                with self.assertRaises(ConnectionError):ns['call']('fixed-socket','guest-exec-status',{'pid':456})
                with self.assertRaises(ValueError):ns['call']('fixed-socket','guest-exec',{})
            self.assertEqual(calls,['guest-exec','guest-exec-status'])
            ns['metadata_anchor'].close()

    def test_actual_stream_exit255_keeps_original_frame_authority(self):
        import tempfile,sys,json
        from pathlib import Path
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp).resolve();(root/'.runtime').mkdir(mode=0o755);(root/'.runtime/parity-evidence').mkdir(mode=0o755);leaf='stream-one';(root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700)
            capture=c.AuthorityCapture(root,leaf)
            try:
                request={'nonce':'11111111-1111-4111-8111-111111111111','role':'final','generation':['vm','sock',1,2,'SID'],'sourceSha256':'a'*64}
                sha=c._digest(json.dumps(request,sort_keys=True,separators=(',',':')).encode())
                receipt={'child':{**request,'pid':456,'requestSha256':sha},'pins':{k:{}for k in ('request.json','child.json','seal.json','authority.json')},'hostRoot':str(root)}
                payload='METADATA-ANCHOR '+json.dumps(receipt)+'\n';argv=[sys.executable,'-c','import sys;sys.stderr.write('+repr(payload)+');sys.stderr.flush();sys.exit(255)'];anchors=[]
                value=c._stream(argv,lambda line:c._capture_frame(capture,'final',request,SimpleNamespace(fixture_transfer_root=root),line,anchors))
                self.assertEqual(value.returncode,255);self.assertEqual(anchors,[receipt])
                self.assertTrue((capture.path/'final-authority.json').exists())
            finally:capture.close()

class TestPartialFailure(unittest.TestCase):
    def test_actual_timeout_retains_partial_stream_before_unknown(self):
        import sys,subprocess
        argv=[sys.executable,'-c','import sys,time;sys.stderr.write("PARTIAL-MARKER\\n");sys.stderr.flush();time.sleep(30)']
        # One readable poll, then the unchanged90s deadline expires. No real90s wait.
        with mock.patch.object(c.time,'monotonic',side_effect=[0,0,91]):
            with self.assertRaises(subprocess.TimeoutExpired)as caught:c._stream(argv,lambda line:None)
        self.assertIn(b'PARTIAL-MARKER',caught.exception.stderr or b'')

    def test_bound_fd_reader_rejects_fifo_symlink_and_fullgen_drift(self):
        import tempfile,os
        from pathlib import Path
        with tempfile.TemporaryDirectory()as tmp:
            path=Path(tmp).resolve()/'record';path.write_bytes(b'abc');path.chmod(0o600)
            first=c._read_bound_file(path,private=True);path.write_bytes(b'abc')
            self.assertNotEqual(c._read_bound_file(path,private=True),first)
            alias=path.with_name('alias');alias.symlink_to(path)
            with self.assertRaises(OSError):c._read_bound_file(alias,private=True)
            path.unlink();os.mkfifo(path,0o600)
            with self.assertRaises(ValueError):c._read_bound_file(path,private=True)

class TestArchiveLockCallgraph(unittest.TestCase):
    def setUp(self):
        import tempfile,os,json,hashlib
        from pathlib import Path
        from agent_tools.tests.test_windows_msi_base_prepare import BasePrepareTests
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();base=c.closure.base
        fixture=BasePrepareTests();self.config,self.target,self.descriptor=fixture._unknown_close_root(self.root)
        (self.root/'.rag_index').chmod(0o700)
        campaign=self.root/base.campaign_lease._DIR;campaign.mkdir(mode=0o700)
        (campaign/'.environment.lock').write_bytes(b'');(campaign/'.environment.lock').chmod(0o600)
        (self.root/base._LOCAL/'.environment.lock').write_bytes(b'');(self.root/base._LOCAL/'.environment.lock').chmod(0o600)
        intent=base._private_intent(self.root,base._UNKNOWN_CLOSURE_CORRELATION)
        present=fixture._unknown_census('present','present');self.absent=fixture._unknown_census('absent','absent')
        base._write_private_once(base._unknown_closure_marker(self.root),base._unknown_close_marker_value(intent,self.descriptor,present,present))
        evidence={'afterFirst':self.absent,'afterSecond':self.absent,'closeIntent':base._UNKNOWN_CLOSURE_CORRELATION}
        sha=hashlib.sha256(json.dumps(evidence,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        closed={'version':1,'identity':base._campaign_identity(base._UNKNOWN_CLOSURE_REQUEST,self.descriptor),'sequence':1,'state':'closed','role':None,'correlationId':None,'server':'stopped','credentials':'cleaned','lastOutcome':'unknown-cleaned','lastEvidenceSha256':sha}
        path=campaign/(base._UNKNOWN_CLOSURE_CORRELATION+'.closed.json');path.write_text(json.dumps(closed));path.chmod(0o600)
        self.context={'sources':{},'descriptor':self.descriptor,'closed':{},'expected':[],'proof':{}}

    def test_actual_guard_unknown_archive_fallback_under_real_sh(self):
        import os,fcntl
        base=c.closure.base;actual=fcntl.flock;operations=[]
        def finite(fd,operation):
            operations.append(operation)
            try:return actual(fd,operation|fcntl.LOCK_NB if operation!=fcntl.LOCK_UN else operation)
            except BlockingIOError:
                # Old lease._locked leaks its new FD if flock fails. Close only
                # this inert observed test FD; production repair won't call EX.
                os.close(fd);raise
        with mock.patch.object(c,'_source_pins',return_value={}),mock.patch.object(c,'_verify_outer'),mock.patch.object(c.closure,'_recheck'),mock.patch.object(base,'_descriptor',return_value=(self.config,self.target,self.descriptor)),mock.patch.object(base,'_unknown_cleanup_census',return_value=self.absent),mock.patch.object(fcntl,'flock',side_effect=finite):
            with c.closure.history._history_lock(self.root):
                c._guard(self.root,self.context)
                writer=os.open(self.root/base.campaign_lease._DIR/'.environment.lock',os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):actual(writer,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(writer)
        self.assertFalse(any(op&fcntl.LOCK_EX for op in operations))

    def test_readonly_archive_predicates_still_reject_wrong_evidence(self):
        import json
        base=c.closure.base;path=self.root/base.campaign_lease._DIR/(base._UNKNOWN_CLOSURE_CORRELATION+'.closed.json')
        value=json.loads(path.read_text());value['lastEvidenceSha256']='0'*64;path.write_text(json.dumps(value))
        with mock.patch.object(base,'_unknown_cleanup_census',return_value=self.absent):
            self.assertFalse(c._readonly_unknown_archive(self.root,self.config,self.target,self.descriptor))

    def test_busy_actual_start_admission_fails_finitely(self):
        import os,fcntl,time
        base=c.closure.base;fd=os.open(self.root/base._LOCAL/'.environment.lock',os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);started=time.monotonic()
            with c._bounded_locks(),self.assertRaises(BlockingIOError):
                with c.closure.original._start_admission(self.root):self.fail('busy writer admitted')
            self.assertLess(time.monotonic()-started,1)
        finally:os.close(fd)

class TestCurrentOuterAuthority(unittest.TestCase):
    def test_current_ready_receipt_uses_complete_pin_no_prepare(self):
        import tempfile,json
        from pathlib import Path
        from agent_tools import ssh_connection_session as connection
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            path=root/'ready.json';path.write_text(json.dumps({'master':{'pid':234,'start':'current'},'socketFingerprint':[7,8]}));path.chmod(0o600)
            pin=c._read_bound_file(path,private=True)
            session_pin={'sha256':pin['sha256'],'fingerprint':pin['generation'][:4]+pin['generation'][5:]}
            receipt=connection._sha(connection._json(session_pin))
            with mock.patch.object(connection,'_journal',return_value=root),mock.patch.object(connection,'verify_reuse',return_value=True)as verify,mock.patch.object(connection,'prepare',side_effect=AssertionError('no prepare')):
                authority=c._outer_authority(root)
            verify.assert_called_once_with(root,'archlinux',receipt)
            self.assertEqual(authority['readyPin'],pin)
            self.assertEqual(authority['receiptSha256'],receipt)
            self.assertEqual(authority['proof']['master']['pid'],234)

    def test_ready_same_bytes_rewrite_during_verify_is_rejected(self):
        import tempfile,json
        from pathlib import Path
        from agent_tools import ssh_connection_session as connection
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory).resolve();path=root/'ready.json';path.write_text('{"master":{"pid":234}}');path.chmod(0o600)
            def verify(*args):path.write_bytes(path.read_bytes());return True
            with mock.patch.object(connection,'_journal',return_value=root),mock.patch.object(connection,'verify_reuse',side_effect=verify):
                with self.assertRaisesRegex(ValueError,'outer-generation'):c._outer_authority(root)

    def test_pinned_context_refuses_new_ready_generation(self):
        old={'receiptSha256':'a'*64,'readyPin':{'generation':[1]},'proof':{'master':{'pid':234}}}
        changed={**old,'readyPin':{'generation':[2]}}
        with mock.patch.object(c,'_outer_authority',return_value=changed):
            with self.assertRaisesRegex(ValueError,'outer-generation'):c._verify_outer(None,{'outerAuthority':old})
