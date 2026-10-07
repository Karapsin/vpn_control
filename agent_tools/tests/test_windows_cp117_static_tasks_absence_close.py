"""Inert separate-closure regressions; no SSH, QGA or scheduled-task mutation."""
import base64
import copy
import gzip
import hashlib
import json
import re
import os
from pathlib import Path
import tempfile
import unittest
import io
import sys
import stat
import time
from contextlib import redirect_stdout
from unittest import mock
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from agent_tools import windows_cp117_static_tasks_absence_close as r
from agent_tools.tests.test_windows_cp117_static_tasks_retire import snapshot,packet

@unittest.skipUnless(r.history._supported(),'POSIX campaign locks required')
class StaticAbsenceClosureTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        campaign=self.root/r.base.campaign_lease._DIR;campaign.mkdir(parents=True,mode=0o700);campaign.parent.chmod(0o700)
        (campaign/'.environment.lock').write_bytes(b'');(campaign/'.environment.lock').chmod(0o600)
        directory=self.root/r.base._LOCAL;directory.mkdir(mode=0o700)
        (directory/'.environment.lock').write_bytes(b'');(directory/'.environment.lock').chmod(0o600)
        self.descriptor=r.wire.observer._GENERATION;self.closed={'historical':'closed'};self.expected=r.original._expected()
        self.rows=[snapshot(e) for e in self.expected]
        snapshots=[r.original._archive(a,e) for a,e in zip(self.rows,self.expected)]
        binding={'retirementCorrelationId':r.original._RETIREMENT,'generation':list(self.descriptor),'originalProductSourceSha':r.original._SOURCE,'historicalRecordSha256':r.original._RECORDS,'taskArgumentSha256':list(r.original._ARGUMENT_HASHES),'taskToolSourceSha256':[e['toolSourceSha256'] for e in self.expected],'snapshots':snapshots}
        self.old=r.original._plan(binding,self.expected)[1]
        directory=self.root/r.original._DIR;directory.mkdir(mode=0o700)
        r.wire.guards.secure_write_create(directory/'intent.json',self.old)
        self.progress=[{'retirementCorrelationId':r.original._RETIREMENT,'index':i,'bindingSha256':self.old['bindingSha256'],'xmlSha256':a['xmlSha256'],'state':'removed'} for i,a in enumerate(self.rows)]
        self.observed={'binding':self.old,'terminal':None,'archivesPacket':packet(self.rows),'progress':self.progress,'absent':True,'terminalAbsent':True}
        self.calls=[];self.writes=[];self.bound=None;self.terminal=None;self.lost=None;self.observation=None
        self.patch(r.original,'_admit_local',return_value=(self.descriptor,self.closed,self.expected))
        self.patch(r.original,'_steady',return_value=None)
        self.patch(r.original,'diagnose',return_value=r.original._result('unknown','diagnostic-terminal-absent-verified'))
        self.patch(r.base,'_descriptor',return_value=(object(),object(),self.descriptor))
        self.patch(r.base,'_require_base_route_free',return_value=None)
        self.patch(r,'_parse',side_effect=self.parse)
        self.patch(r.original,'_parse',side_effect=self.parse)
        self.patch(r.original,'_run',side_effect=self.fake_run)
    def patch(self,obj,name,**kwargs):
        patch=mock.patch.object(obj,name,**kwargs);p=patch.start();self.addCleanup(patch.stop);return p
    def parse(self,root,descriptor,closed,source):self.calls.append(('parse',source));return True
    def fake_run(self,root,descriptor,closed,source):
        self.calls.append(('run',source))
        if source==r.original._diagnostic_reader(self.expected):return copy.deepcopy(self.observation or self.observed)
        if source==r._root_absence(self.expected):return {'absent':True}
        intent=r.wire._read(self.root/r._DIR/'intent.json')
        if "Write-SecureJsonCreate 'binding.json'" in source:
            self.writes.append('binding');self.bound=intent
            return None if self.lost=='binding' else {'bound':True}
        if "Write-SecureJsonCreate 'terminal.json'" in source:
            self.writes.append('terminal')
            if self.lost!='before-terminal':self.terminal=self.terminal_value(intent)
            return None if self.lost in {'terminal','before-terminal'} else {'closed':True}
        return {'binding':self.bound,'terminal':self.terminal}
    def terminal_value(self,intent):return {'closureCorrelationId':r._CLOSE,'originalRetirementCorrelationId':r.original._RETIREMENT,'bindingSha256':intent['bindingSha256'],'actionSha256':intent['actionSha256'],'state':'closed','proof':'current-absence','originalOutcome':'unknown'}
    def test_measured_original_missing_terminal_is_preserved_by_distinct_closure(self):
        old=(self.root/r.original._DIR/'intent.json').read_bytes();before=set(self.root.rglob('*'))
        self.assertEqual(r.preflight(self.root,{})['state'],'ready');self.assertEqual(before,set(self.root.rglob('*')))
        self.assertEqual(r.start(self.root,{}),r._result('closed','complete'))
        self.assertEqual(self.writes,['binding','terminal'])
        for action in (r.start,r.preflight,r.diagnose,r.status):self.assertEqual(action(self.root,{})['state'],'closed')
        self.assertEqual(self.writes,['binding','terminal']);self.assertEqual(old,(self.root/r.original._DIR/'intent.json').read_bytes())
        self.assertFalse((self.root/r.original._DIR/'terminal.json').exists())
        self.assertEqual(r.original._plan(self.old['binding'],self.expected)[1],self.old)
    def test_lost_binding_and_terminal_never_replay_or_resume(self):
        for lost in ('binding','before-terminal','terminal'):
            with self.subTest(lost=lost):
                # Reset only an inert local test fixture between independent cases.
                path=self.root/r._DIR/'intent.json'
                if path.exists():path.unlink()
                self.writes=[];self.bound=None;self.terminal=None;self.lost=lost
                self.assertEqual(r.start(self.root,{})['state'],'unknown')
                writes=list(self.writes)
                for action in (r.start,r.status,r.preflight,r.diagnose):
                    self.assertEqual(action(self.root,{})['state'],'closed' if lost=='terminal' else 'unknown')
                self.assertEqual(writes,self.writes)
    def test_original_drift_process_or_task_presence_never_consumes(self):
        for key,changed in (('absent',False),('terminalAbsent',False),('terminal',{}),('progress',[]),('binding',{})):
            value=copy.deepcopy(self.observed);value[key]=changed
            with self.subTest(key=key),mock.patch.object(r.original,'_run',return_value=value):
                self.assertEqual(r.start(self.root,{})['state'],'blocked')
                self.assertFalse((self.root/r._DIR).exists())
        for phase in ('process','installer','generation','diagnostic-leaf-acl'):
            with mock.patch.object(r.original,'_run',return_value={'state':'blocked','phase':phase}):
                self.assertEqual(r.start(self.root,{})['phase'],phase)
                self.assertFalse((self.root/r._DIR).exists())
    def test_original_marker_hash_and_progress_corruption_never_consumes(self):
        for kind in ('archive','progress','intent'):
            value=copy.deepcopy(self.observed)
            if kind=='archive':value['archivesPacket']['sha256']='0'*64
            elif kind=='progress':value['progress'][2]['xmlSha256']='0'*64
            else:value['binding']['actionSha256']='0'*64
            with self.subTest(kind=kind),mock.patch.object(r.original,'_run',return_value=value):
                self.assertEqual(r.start(self.root,{})['state'],'blocked')
                self.assertFalse((self.root/r._DIR).exists())
    def test_generation_race_after_final_proof_stops_before_terminal(self):
        actual=r._recheck
        def check(root,descriptor,closed,expected,proof):
            # This is exactly the last local boundary after fresh post-binding proof.
            if self.writes==['binding']:raise r.Blocked('generation')
            return actual(root,descriptor,closed,expected,proof)
        with mock.patch.object(r,'_recheck',side_effect=check):
            self.assertEqual(r.start(self.root,{}),r._result('unknown','generation'))
        self.assertEqual(self.writes,['binding']);self.assertIsNone(self.terminal)
        self.assertEqual(r.start(self.root,{})['state'],'unknown');self.assertEqual(self.writes,['binding'])
    def test_exact_generated_sources_parser_only_and_no_task_or_product_actions(self):
        descriptor,closed,expected,proof=r._proof(self.root)
        first,final,intent=r._scripts(r._binding(descriptor,proof),expected,proof)
        reader=r._reader(expected,proof)
        for source in (first,final,reader):
            with mock.patch.object(r,'_parser_observe',return_value={'version':1,'code':'OK'}) as run:
                self.assertTrue(ACTUAL_PARSE(self.root,descriptor,closed,source))
                parser=run.call_args.args[-1];packed=parser.split("FromBase64String('",1)[1].split("')",1)[0]
                self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
                self.assertIn('Parser]::ParseInput',parser);self.assertNotIn('Invoke-Expression',parser)
            for action in ('Unregister-ScheduledTask','Disable-ScheduledTask','Start-ScheduledTask','Stop-Process','Stop-Service','Start-Service','msiexec.exe /'):
                self.assertNotIn(action,source)
        for action in ('Initialize-SecureJournal','Write-SecureJsonCreate','CreateNew'):
            self.assertNotIn(action,reader)
        with mock.patch.object(r,'_parse',return_value=False),mock.patch.object(r.original,'_run') as run:
            self.assertEqual(r.start(self.root,{})['phase'],'parser');run.assert_not_called()
    def test_current_proof_is_required_even_after_own_terminal(self):
        r.start(self.root,{})
        value=copy.deepcopy(self.observed);value['absent']=False
        with mock.patch.object(r.original,'_run',return_value=value):self.assertEqual(r.status(self.root,{})['state'],'unknown')
        self.assertEqual(self.writes,['binding','terminal'])
    def test_own_terminal_extra_fields_and_binding_drift_reject(self):
        r.start(self.root,{})
        self.terminal['originalSucceeded']=True
        self.assertEqual(r.status(self.root,{})['phase'],'terminal')
        self.terminal=self.terminal_value(self.bound);self.bound=dict(self.bound,actionSha256='0'*64)
        self.assertEqual(r.status(self.root,{})['phase'],'terminal')
    def test_strict_private_intent_and_fixed_inputs_platform(self):
        for value in ({'task':'foreign'},None,[],{'correlationId':r._CLOSE}):
            with self.assertRaises(ValueError):r.preflight(self.root,value)
        with mock.patch.object(r.history,'_supported',return_value=False):self.assertEqual(r.start(self.root,{})['phase'],'platform')
        r.start(self.root,{})
        path=self.root/r._DIR/'intent.json';path.chmod(0o644)
        self.assertEqual(r.status(self.root,{})['state'],'unknown')
        path.chmod(0o600);data=path.read_bytes();path.unlink();path.symlink_to(self.root/'absent')
        self.assertEqual(r.start(self.root,{})['state'],'unknown');self.assertEqual(self.writes,['binding','terminal'])
    def test_campaign_active_and_base_reservation_exclusion(self):
        active=self.root/r.base.campaign_lease._DIR/'active.json';active.write_text('{}');active.chmod(0o600)
        self.assertEqual(r.start(self.root,{})['phase'],'active-lease');self.assertFalse((self.root/r._DIR).exists());active.unlink()
        with mock.patch.object(r.base,'_require_base_route_free',side_effect=ValueError('reserved')):
            self.assertEqual(r.start(self.root,{})['phase'],'base-route');self.assertFalse((self.root/r._DIR).exists())
    def test_fixed_source_transport_and_leaf_budget_and_last_absence_boundary(self):
        d,c,e,p=r._proof(self.root)
        first,final,intent=r._scripts(r._binding(d,p),e,p)
        for source in (first,final,r._reader(e,p),r._root_absence(e)):
            self.assertLess(len(r.wire._command(source)),30000)
        self.assertLess(len(json.dumps(intent,separators=(',',':')).encode()),16384)
        self.assertEqual(len(r._LEAVES),2)
        self.assertLess(final.index("for($j=0;$j -lt 5;$j++){Absent $expected[$j]};Idle\nWrite-SecureJsonCreate 'terminal.json'"),final.index("Write-SecureJsonCreate 'terminal.json'"))
        self.assertNotIn("Write-SecureJsonCreate 'terminal.json'",first)
        self.assertTrue(';Same $archives[$j] $proof.originalIntent.binding.snapshots[$j]' in first)
        self.assertTrue('-not (Same' not in first)
        for source in (first,final,r._reader(e,p)):
            self.assertIn('FileShare]::None',source)
            self.assertIn('UTF8Encoding]::new($false,$true)',source)
        self.assertTrue('originalOutcome' in first and 'originalOutcome' in final)

    def test_measured_generated_closure_parser_fits_without_double_packing(self):
        d,c,e,p=r._proof(self.root)
        first,final,_=r._scripts(r._binding(d,p),e,p)
        for source in (first,final,r._reader(e,p)):
            packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
            parser=r.history._PARSER.replace('@PACKED@',packed)
            self.assertGreaterEqual(len(r.wire.transport._launcher(parser)),30000)
            command=r._parser_command(source)
            self.assertLess(len(command),30000)
            literal=command[len('&([scriptblock]::Create("'):-len('"))')]
            restored=re.sub(r'`(.)',lambda m:{'n':'\n','r':'\r','t':'\t'}.get(m[1],m[1]),literal)
            self.assertEqual(restored,parser)
            self.assertEqual(gzip.decompress(base64.b64decode(command.split("FromBase64String('",1)[1].split("')",1)[0])),source.encode('utf-16le'))
            self.assertEqual(command.count('scriptblock]::Create'),1)
            self.assertIn('Parser]::ParseInput',command)

    def test_measured_parser_control_characters_reach_existing_ssh_admission(self):
        transport=r.base.ssh_transport
        host=transport.SshHost('archlinux','example.test',22,'fixture',Path('/owned/key'),Path('/owned/known'))
        config=transport.SshConfig(self.root,{'archlinux':host})
        source=r.original._diagnostic_reader(self.expected)
        command=r._parser_command(source)
        remote=r.base.windows_credential_probe_ssh._remote_command(r.original._REMOTE,'owned',command)
        argv=transport.build_ssh_argv(config,'archlinux',60,command=remote)
        self.assertIn('example.test',argv)
        self.assertFalse(any(ord(c)<32 or ord(c)==127 for c in command))

    def test_single_packed_parser_uses_exact_existing_guarded_transport(self):
        d,c,e,p=r._proof(self.root)
        source=r._scripts(r._binding(d,p),e,p)[0]
        config=object();target=SimpleNamespace(fixture_transfer_root=Path('/owned/fixture'))
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,d)),mock.patch.object(r.base,'_remote',return_value=b'{"state":"observed","receipt":{"version":1,"code":"OK"}}') as remote:
            self.assertTrue(ACTUAL_PARSE(self.root,d,c,source))
            args=remote.call_args.args
            self.assertIs(args[0],config)
            self.assertEqual(args[1],r.original._REMOTE)
            self.assertEqual(args[2],('/owned/fixture',*r.wire.observer._remote_arguments(d,c),r._parser_command(source)))
            self.assertEqual(args[3:],(None,90))
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,('foreign',))),mock.patch.object(r.base,'_remote') as remote:
            self.assertFalse(ACTUAL_PARSE(self.root,d,c,source));remote.assert_not_called()
        for payload in (None,b'{}',b'{"state":"observed","receipt":{"version":1,"code":"FAILED"}}',b'{"state":"observed","state":"observed","receipt":{"version":1,"code":"OK"}}',b'x'*16385):
            with self.subTest(payload=repr(payload)[:30]),mock.patch.object(r.base,'_descriptor',return_value=(config,target,d)),mock.patch.object(r.base,'_remote',return_value=payload):
                self.assertFalse(ACTUAL_PARSE(self.root,d,c,source))

    def test_single_packed_parser_retains_command_bound_before_transport(self):
        source='# '+''.join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(1000))
        with mock.patch.object(r.base,'_remote') as remote:
            with self.assertRaisesRegex(ValueError,'Windows command bound'):
                ACTUAL_PARSE(self.root,self.descriptor,self.closed,source)
            remote.assert_not_called()

    def test_recovery_child_is_durable_before_poll_and_socket_timeout_is_distinct(self):
        events=[];calls=[];ticks=iter((1.0,1.1,2.0,22.0))
        def delegate(sock,command,args):
            calls.append(command)
            if command=='guest-exec':return {'pid':123}
            self.assertEqual(events[0],{'kind':'child','pid':123})
            raise TimeoutError()
        self.assertEqual(r._recovery_call(delegate,'socket','guest-exec',{},events.append,lambda:next(ticks)),{'pid':123})
        with self.assertRaises(TimeoutError):r._recovery_call(delegate,'socket','guest-exec-status',{'pid':123},events.append,lambda:next(ticks))
        self.assertEqual(events[-1],{'kind':'poll','pid':123,'outcome':'socket-timeout','elapsedMs':20000})
        self.assertEqual(calls,['guest-exec','guest-exec-status'])

    def test_hardlinked_local_anchor_is_rejected_before_read(self):
        directory=self.root/'anchor';directory.mkdir(mode=0o700)
        path=directory/'child.json';path.write_text('{"pid":456}');path.chmod(0o600)
        os.link(path,directory/'alias.json')
        with self.assertRaises(r.Blocked):r._anchor_read(path)

    def test_actual_callsite_rejects_arbitrary_source_or_changed_identity(self):
        config=object();source=r.base._fixed_recovery_task_status_script()
        with mock.patch.object(r.base,'_descriptor',return_value=(config,object(),self.descriptor)):
            self.assertTrue(r._validate_recovery_source(self.root,config,self.descriptor,source))
            for passed_config,descriptor,script in ((config,self.descriptor,source+';Stop-Service qemu-ga'),(config,('foreign',),source),(object(),self.descriptor,source)):
                with self.assertRaises(r.Blocked):r._validate_recovery_source(self.root,passed_config,descriptor,script)
            with mock.patch.object(r,'recovery_read_diagnostic') as diagnostic:
                with self.assertRaises(r.Blocked):r.retained_recovery_observe(self.root,config,self.descriptor,source+';Stop-Service qemu-ga','52d3eefc-a4b1-466a-a76a-7ff41f59030f')
                diagnostic.assert_not_called()

    def test_static_audit_delegate_remains_bound_after_unrelated_recovery_rebind(self):
        static=mock.Mock(return_value={'binding':'static'});recovery=mock.Mock(return_value={'service':'recovery'})
        current=static;events=[]
        wrapped=r._static_trace_delegate(current,lambda args,kwargs,result:events.append(result))
        current=recovery
        self.assertEqual(wrapped('static-source'),{'binding':'static'})
        static.assert_called_once_with('static-source');recovery.assert_not_called()
        self.assertEqual(events,[{'binding':'static'}])

    def test_static_boundary_trace_preserves_exact_source_predicates_and_child_identity(self):
        source=r.original._diagnostic_reader(self.expected);correlation='dc63ecde-807e-4dfc-93c5-723a7d51f3d0'
        program,binding=r._static_boundary_program(source,self.expected,correlation)
        self.assertTrue(program.endswith(r.original._REMOTE_BODY))
        self.assertEqual(binding['sourceSha256'],hashlib.sha256(source.encode('utf-16le')).hexdigest())
        self.assertEqual(binding['commandSha256'],hashlib.sha256(r.wire._command(source).encode()).hexdigest())
        self.assertLess(len(r.wire._command(source)),30000)
        with self.assertRaises(r.Blocked):r._static_boundary_program(source+';Stop-Service qemu-ga',self.expected,correlation)
        namespace={};exec(r.base._QGA,namespace)
        result={'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"service":"old-recovery"}').decode()}
        delegate=mock.Mock(side_effect=[{'pid':456},result]);namespace['call']=delegate
        trace=program[len(r.base._QGA):-len(r.original._REMOTE_BODY)]
        output=io.StringIO()
        with mock.patch('sys.stderr',output):
            exec(trace,namespace)
            namespace['_trace_delegate']=mock.Mock(side_effect=AssertionError('rebound delegate'))
            self.assertEqual(namespace['call']('sock','guest-exec',{'arg':[r.wire._command(source)]}),{'pid':456})
            self.assertIs(namespace['call']('sock','guest-exec-status',{'pid':456}),result)
        events=[json.loads(line.split(' ',1)[1]) for line in output.getvalue().splitlines()]
        self.assertEqual(events[0]['returnedPid'],456);self.assertEqual(events[1]['queriedPid'],456)
        self.assertEqual(events[0]['requestedCommandSha256'],binding['commandSha256'])
        self.assertEqual(events[1]['outputKeys'],['service'])
        self.assertEqual(events[1]['outputSha256'],hashlib.sha256(b'{"service":"old-recovery"}').hexdigest())

    def test_c32_unknown_retains_original_criteria_and_caught_schema_phase(self):
        from agent_tools import windows_cp117_c32_absence as absence
        source=absence._script(absence._C32);correlation='8b50c059-2b05-4123-a3e8-590ee12c0616'
        program,binding=r._c32_boundary_program(source,correlation)
        raw=b'{"service":"recovery"}'
        item={'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
        namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *args:True
        delegate=mock.Mock(side_effect=[{'pid':456},item]);namespace['call']=delegate
        output=io.StringIO();trace=io.StringIO()
        encoded=base64.b64encode(source.encode('utf-16le')).decode()
        with mock.patch.object(sys,'argv',['program','sock','1','2',encoded]),mock.patch('sys.stderr',trace),redirect_stdout(output),mock.patch.object(time,'sleep'):
            exec(program[len(r.base._QGA):],namespace)
        self.assertEqual(json.loads(output.getvalue()),{'state':'unknown'})
        events=[json.loads(line.split(' ',1)[1]) for line in trace.getvalue().splitlines()]
        self.assertEqual(events[-1]['phase'],'receipt-shape')
        self.assertEqual(events[-1]['exception'],'ValueError')
        self.assertEqual(events[0]['returnedPid'],456);self.assertEqual(events[1]['queriedPid'],456)
        self.assertEqual(events[1]['outputKeys'],['service'])
        self.assertEqual(events[0]['requestedCommandSha256'],binding['commandSha256'])
        with self.assertRaises(r.Blocked):r._c32_boundary_program(source+';Stop-Service qemu-ga',correlation)

    def test_c32_trace_preserves_original_result_for_every_terminal_failure_class(self):
        from agent_tools import windows_cp117_c32_absence as absence
        source=absence._script(absence._C32);correlation='1354aa10-9baf-48a6-b389-c55e511b68ef'
        program,binding=r._c32_boundary_program(source,correlation)
        encoded=base64.b64encode(source.encode('utf-16le')).decode()
        good={k:'absent' for k in ('baseTask','transferTask','guestLeaf','baseMsi','correlationProcess')}
        def execute(remote,item,live=True):
            namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *args:live
            def delegate(sock,command,args):
                return {'pid':456} if command=='guest-exec' else item
            namespace['call']=delegate;out=io.StringIO();trace=io.StringIO()
            with mock.patch.object(sys,'argv',['program','sock','1','2',encoded]),mock.patch('sys.stderr',trace),redirect_stdout(out),mock.patch.object(time,'sleep'):
                exec(remote[len(r.base._QGA):],namespace)
            return json.loads(out.getvalue()),trace.getvalue()
        item={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(good).encode()).decode()}
        cases=[(item,True),(item,False),({'exited':False},True),({**item,'exitcode':1},True),({**item,'out-truncated':True},True),({**item,'out-data':'invalid'},True),({**item,'out-data':base64.b64encode(b'not-json').decode()},True),({**item,'out-data':base64.b64encode(b'{"service":"foreign"}').decode()},True),({**item,'out-data':base64.b64encode(b'x'*1025).decode()},True)]
        for value,live in cases:
            original,unused=execute(absence._REMOTE,value,live)
            observed,trace=execute(program,value,live)
            self.assertEqual(observed,original)
            if original['state']=='unknown':self.assertIn('"phase":',trace)
        self.assertIn('for _ in range(80):',program)
        self.assertIn('time.sleep(.25)',program)

    def test_same_schema_cached_terminal_cannot_prove_new_execution(self):
        from agent_tools import windows_cp117_c32_absence as absence
        source=absence._script(absence._C32)
        receipt={k:'absent' for k in absence._FIELDS}
        cached={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(receipt).encode()).decode()}
        namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *args:True
        # The cached exit belongs to an older execution with the same numeric PID;
        # the newly submitted execution is still running on the next status.
        statuses=iter([cached,{'exited':False}]);queries=[]
        def delegate(sock,command,args):
            if command=='guest-exec':return {'pid':4560}
            queries.append(args['pid']);return next(statuses)
        namespace['call']=delegate;out=io.StringIO()
        encoded=base64.b64encode(source.encode('utf-16le')).decode()
        with mock.patch.object(sys,'argv',['program','sock','1','2',encoded]),redirect_stdout(out),mock.patch.object(time,'sleep'):
            exec(absence._REMOTE[len(r.base._QGA):],namespace)
        self.assertEqual(json.loads(out.getvalue()),{'state':'observed','receipt':receipt})
        self.assertEqual(queries,[4560])
        self.assertEqual(next(statuses),{'exited':False})
        self.assertIsNone(r._fresh_terminal(cached,'7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b',hashlib.sha256(source.encode('utf-16le')).hexdigest(),4560))

    def test_process_gate_rejects_stale_nonce_source_and_child_before_facts(self):
        value={'correlationId':'2355f68a-c958-4e13-8eb2-141dccf004f9','selfPid':4560,'selfSourceSha256':'0'*64,'guard':'process','otherCount':0,'processes':[]}
        with self.assertRaises(r.Blocked):r._process_gate_receipt(value,'7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b','1'*64,4561)

    def test_fresh_c32_generated_reader_discards_cached_exit_queries_same_child(self):
        from agent_tools import windows_cp117_c32_absence as absence
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';source=absence._script(absence._C32)
        sha=hashlib.sha256(source.encode('utf-16le')).hexdigest();receipt={k:'absent' for k in absence._FIELDS}
        payload=json.dumps(receipt).encode();prefix=('VPNCONTROL-READ '+nonce+' '+sha+' 4560\r\n').encode()
        cached={'exited':True,'exitcode':0,'out-data':base64.b64encode(payload).decode()}
        current={**cached,'out-data':base64.b64encode(prefix+payload).decode()}
        program=r._fresh_c32_program(source,nonce)
        self.assertTrue(program.endswith(absence._REMOTE[len(r.base._QGA):]))
        def execute(items):
            namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *args:True
            submitted=[];queried=[];responses=iter(items)
            def delegate(sock,command,args):
                if command=='guest-exec':submitted.append(args);return {'pid':4560}
                queried.append(args['pid']);return next(responses)
            namespace['call']=delegate;output=io.StringIO();events=io.StringIO()
            with mock.patch.object(sys,'argv',['program','sock','1','2',base64.b64encode(source.encode('utf-16le')).decode()]),mock.patch('sys.stderr',events),redirect_stdout(output),mock.patch.object(time,'sleep'):
                exec(program[len(r.base._QGA):],namespace)
            return json.loads(output.getvalue()),submitted,queried,events.getvalue()
        value,submitted,queried,events=execute([cached,{'exited':False},current])
        self.assertEqual(value,{'state':'observed','receipt':receipt});self.assertEqual(queried,[4560]*3)
        self.assertEqual(len(submitted),1)
        bound=base64.b64decode(submitted[0]['arg'][-1]).decode('utf-16le')
        self.assertTrue(bound.endswith(source));self.assertTrue(bound.startswith('[Console]::Out.WriteLine('))
        self.assertIn('execution-binding-pending',events);self.assertIn('execution-bound',events)
        for old in (cached,{**current,'out-data':base64.b64encode(prefix.replace(nonce.encode(),b'0'*36)+payload).decode()}):
            value,submitted,queried,events=execute([old]*80)
            self.assertEqual(value,{'state':'unknown'});self.assertEqual(len(submitted),1);self.assertEqual(queried,[4560]*80)
        for bad in ({**current,'exitcode':1},{**current,'out-truncated':True},{**current,'out-data':base64.b64encode(prefix+b'x'*1025).decode()}):
            value,submitted,queried,events=execute([bad])
            self.assertEqual(value,{'state':'unknown'});self.assertEqual(queried,[4560])

    def test_fresh_binding_header_stripping_preserves_original_envelope(self):
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';sha='a'*64;child=4560
        header=('VPNCONTROL-READ '+nonce+' '+sha+' '+str(child)).encode()
        payload=b'\xef\xbb\xbf{"bad":"encoding"}'
        item={'exited':True,'exitcode':1,'err-data':'ZXJyb3I=','err-truncated':True,'out-truncated':True,'extra':'preserve','out-data':base64.b64encode(header+b'\r\n'+payload).decode()}
        stripped=r._fresh_terminal(item,nonce,sha,child)
        self.assertEqual(stripped,{**item,'out-data':base64.b64encode(payload).decode()})
        for prefix in (header.replace(nonce.encode(),b'0'*36),header.replace(sha.encode(),b'b'*64),header.replace(b'4560',b'4561'),header+b' extra',b'\xef\xbb\xbf'+header,b'foreign\n'+header):
            with self.subTest(prefix=prefix):self.assertIsNone(r._fresh_terminal({**item,'out-data':base64.b64encode(prefix+b'\r\n'+payload).decode()},nonce,sha,child))
        with self.assertRaises(ValueError):r._fresh_terminal({**item,'out-data':'!'},nonce,sha,child)
        with self.assertRaises(ValueError):r._fresh_terminal({**item,'out-data':base64.b64encode(b'x'*50301).decode()},nonce,sha,child)

    def test_fresh_factories_reject_effects_wrong_sources_and_preserve_caps(self):
        from agent_tools import windows_cp117_c32_absence as absence
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b'
        with self.assertRaises(r.Blocked):r._fresh_c32_program(absence._script(absence._C32)+';exit',nonce)
        with self.assertRaises(r.Blocked):r._fresh_recovery_program('Stop-Service qemu-ga',nonce)
        recovery=r._fresh_recovery_program(r.base._fixed_recovery_task_status_script(),nonce)
        self.assertIn('for _ in range(80):',recovery)
        static=r._fresh_static_program(r.wire._command(r.original._diagnostic_reader(self.expected)),self.expected,nonce)
        self.assertTrue(static.endswith(r.original._REMOTE_BODY));self.assertIn('for _ in range(200):',static)
        with self.assertRaises(r.Blocked):r._fresh_static_program(r.wire._command('Stop-Service qemu-ga'),self.expected,nonce)
        with self.assertRaises(ValueError):r._fresh_call(lambda *a:None,'-Command','x'*27900,'a'*64,nonce,lambda v:None,28000)
        submitted=[]
        call=r._fresh_call(lambda *a:submitted.append(a),'-Command','x','a'*64,nonce,lambda v:None,28000)
        with self.assertRaises(ValueError):call('sock','guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command','y'],'capture-output':True})
        self.assertEqual(submitted,[])

    def test_fresh_scope_routes_exact_original_readers_and_restores_delegate(self):
        from agent_tools import windows_cp117_c32_absence as absence
        from agent_tools import windows_cp117_guest_agent_recovery as recovery
        config=object();target=SimpleNamespace(fixture_transfer_root=Path('/fixture'))
        delegated=mock.Mock(return_value=b'original-result')
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,self.descriptor)),mock.patch.object(r.base,'_remote',delegated):
            with r._fresh_read_scope(self.root,'preflight') as scope:
                original_delegate=r.base._remote
                command=r.wire._command(r.original._diagnostic_reader(self.expected))
                args=(str(target.fixture_transfer_root),*r.wire.observer._remote_arguments(self.descriptor,self.closed),command)
                self.assertEqual(r.base._remote(config,r.original._REMOTE,args,None,90),b'original-result')
                actual=delegated.call_args.args
                self.assertNotEqual(actual[1],r.original._REMOTE);self.assertTrue(actual[1].endswith(r.original._REMOTE_BODY))
                self.assertEqual(actual[2:],(args,None,90))
                for module,source,mode,cap in ((absence,absence._script(absence._C32),'-EncodedCommand',30000),(recovery,r.base._fixed_recovery_task_status_script(),'-Command',28000)):
                    encoded=base64.b64encode(source.encode('utf-16le')).decode() if mode=='-EncodedCommand' else recovery._launcher(source)
                    remote=module._REMOTE if module is absence else module._REMOTE_PS
                    args=(str(self.descriptor[1]),str(self.descriptor[2]),str(self.descriptor[3]),encoded)
                    self.assertEqual(r.base._remote(config,remote,args,None,30 if module is absence else 60),b'original-result')
                    self.assertTrue(delegated.call_args.args[1].endswith(remote[len(r.base._QGA):]))
                before=delegated.call_count
                with self.assertRaises(r.Blocked):r.base._remote(config,r.original._REMOTE,('/fixture',*r.wire.observer._remote_arguments(self.descriptor,self.closed),r.wire._command('Stop-Service qemu-ga')),None,90)
                self.assertEqual(delegated.call_count,before)
                with self.assertRaises(r.Blocked):
                    with r._fresh_read_scope(self.root,'preflight'):pass
            self.assertIs(r.base._remote,delegated);self.assertIsNone(r._FRESH_READ_SCOPE.get())

    def test_fresh_recovery_generated_reader_preserves_schema_and_pending_budget(self):
        from agent_tools import windows_cp117_guest_agent_recovery as recovery
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';source=r.base._fixed_recovery_task_status_script()
        sha=hashlib.sha256(source.encode('utf-16le')).hexdigest();payload=b'{"task":"absent"}'
        prefix=('VPNCONTROL-READ '+nonce+' '+sha+' 4560\n').encode()
        cached={'exited':True,'exitcode':0,'out-data':base64.b64encode(payload).decode()}
        fresh={**cached,'out-data':base64.b64encode(prefix+payload).decode()}
        program=r._fresh_recovery_program(source,nonce)
        for items,expected,count in (([cached,fresh],{'state':'observed','receipt':{'task':'absent'}},2),([cached]*80,{'state':'diagnosed','phase':'guest-status'},80)):
            namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *args:True
            queries=[];submits=[];statuses=iter(items)
            def delegate(sock,command,args):
                if command=='guest-exec':submits.append(args);return {'pid':4560}
                queries.append(args['pid']);return next(statuses)
            namespace['call']=delegate;out=io.StringIO();err=io.StringIO()
            with mock.patch.object(sys,'argv',['program','sock','1','2',recovery._launcher(source)]),mock.patch('sys.stderr',err),redirect_stdout(out),mock.patch.object(time,'sleep'):
                exec(program[len(r.base._QGA):],namespace)
            self.assertEqual(json.loads(out.getvalue()),expected);self.assertEqual(queries,[4560]*count);self.assertEqual(len(submits),1)

    def test_actual_c32_observe_keeps_original_30_second_transport_limit(self):
        from agent_tools import windows_cp117_c32_absence as absence
        config=object();target=SimpleNamespace(fixture_transfer_root=Path('/fixture'))
        receipt={k:'absent' for k in absence._FIELDS}
        delegated=mock.Mock(return_value=json.dumps({'state':'observed','receipt':receipt}).encode())
        record={'socketPath':self.descriptor[1],'qemuPid':self.descriptor[2],'startTicks':self.descriptor[3]}
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,self.descriptor)),mock.patch.object(r.base,'_remote',delegated),mock.patch.object(absence,'_admit',return_value=(record,Path('/fixed-route'))):
            with r._fresh_read_scope(self.root,'preflight'):
                observed=absence.observe(self.root,config,target,self.descriptor)
            self.assertEqual(observed,{'state':'observed',**receipt,'replayAllowed':False,'nativeActionAllowed':False,'productAction':False})
            self.assertEqual(delegated.call_count,1)
            self.assertEqual(delegated.call_args.args[-1],30)
            self.assertTrue(delegated.call_args.args[1].endswith(absence._REMOTE[len(r.base._QGA):]))

    def test_actual_retained_c32_parser_through_scope_requires_execution_binding(self):
        from agent_tools import windows_cp117_c32_absence as absence
        from agent_tools.tests.test_windows_cp117_c32_absence import INTENT
        intent={**copy.deepcopy(INTENT),'socketPath':self.descriptor[1],'pid':self.descriptor[2],'startTicks':self.descriptor[3],'expectedSid':self.descriptor[4]}
        config=object();target=SimpleNamespace(fixture_transfer_root=Path('/fixture'))
        delegated=mock.Mock(return_value=b'{"state":"observed","phase":"ast","strict":"passed","diagnostic":"passed"}')
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,self.descriptor)),mock.patch.object(r.base,'_remote',delegated),mock.patch.object(absence,'_admit',return_value=({},Path('/fixed-route'))),mock.patch.object(r.base,'_private_intent',return_value=intent):
            with r._fresh_read_scope(self.root,'preflight'):
                observed=absence.parse_retained(self.root,config,target,self.descriptor)
            self.assertEqual(observed,{'state':'observed','phase':'ast','strict':'passed','diagnostic':'passed'})
            self.assertEqual(delegated.call_count,1);self.assertEqual(delegated.call_args.args[-1],60)
            self.assertNotEqual(delegated.call_args.args[1],absence._RETAINED_PARSE_REMOTE)
            self.assertIn('call=_fresh_call(',delegated.call_args.args[1])

    def test_actual_retained_terminal_and_diagnostic_callgraphs_are_bound(self):
        from agent_tools import windows_cp117_c32_absence as absence
        from agent_tools.tests.test_windows_cp117_c32_absence import INTENT,PAYLOAD
        intent={**copy.deepcopy(INTENT),'socketPath':self.descriptor[1],'pid':self.descriptor[2],'startTicks':self.descriptor[3],'expectedSid':self.descriptor[4]}
        payload={**copy.deepcopy(PAYLOAD),'originalSid':self.descriptor[4]}
        config=object();target=SimpleNamespace(fixture_transfer_root=Path('/fixture'));programs=[]
        def delegate(c,program,args,stdin,timeout):
            programs.append(program);self.assertEqual(timeout,60);self.assertIn('call=_fresh_call(',program)
            if program.endswith(absence._RETAINED_PARSE_REMOTE[len(r.base._QGA):]):return b'{"state":"observed","phase":"ast","strict":"passed","diagnostic":"passed"}'
            if program.endswith(absence._RETAINED_REMOTE[len(r.base._QGA):]):return json.dumps({'state':'observed','receipt':payload}).encode()
            if program.endswith(absence._RETAINED_DIAG_REMOTE[len(r.base._QGA):]):return b'{"state":"observed","guard":"ready","phase":"result"}'
            self.fail('unexpected reader')
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,self.descriptor)),mock.patch.object(r.base,'_remote',side_effect=delegate),mock.patch.object(absence,'_admit',return_value=({},Path('/fixed-route'))),mock.patch.object(r.base,'_private_intent',return_value=intent):
            with r._fresh_read_scope(self.root,'preflight'):
                self.assertEqual(absence.retained_terminal(self.root,config,target,self.descriptor)['state'],'retained-terminal')
                self.assertEqual(absence.diagnose_retained(self.root,config,target,self.descriptor)['guard'],'ready')
        self.assertEqual(len(programs),4)

    def test_generated_retained_readers_discard_old_same_schema_terminal_without_replay(self):
        from agent_tools import windows_cp117_c32_absence as absence
        from agent_tools.tests.test_windows_cp117_c32_absence import INTENT,PAYLOAD
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';intent=copy.deepcopy(INTENT)
        strict=absence._retained_script(intent);diagnostic=absence._retained_script(intent,diagnostic=True)
        parse=absence._retained_parse_script(strict,diagnostic)
        cases=[(absence._RETAINED_PARSE_REMOTE,parse,parse,{'strict':'passed','diagnostic':'passed'}),
               (absence._RETAINED_REMOTE,strict,base64.b64encode(strict.encode('utf-16le')).decode(),{'result':PAYLOAD}),
               (absence._RETAINED_DIAG_REMOTE,diagnostic,base64.b64encode(diagnostic.encode('utf-16le')).decode(),{'guard':'ready','phase':'result'})]
        for remote,source,command,payload in cases:
            with mock.patch.object(r.base,'_private_intent',return_value=intent):program=r._fresh_retained_c32_program(self.root,remote,command,nonce)
            sha=hashlib.sha256(source.encode('utf-16le')).hexdigest();raw=json.dumps(payload).encode()
            header=('VPNCONTROL-READ '+nonce+' '+sha+' 4560\r\n').encode()
            old={'exited':True,'exitcode':0,'out-data':base64.b64encode(raw).decode()}
            fresh={**old,'out-data':base64.b64encode(header+raw).decode()}
            def execute(script,statuses):
                namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *a:True
                items=iter(statuses);queries=[];submits=[]
                def delegate(sock,operation,args):
                    if operation=='guest-exec':submits.append(args);return {'pid':4560}
                    queries.append(args['pid']);return next(items)
                namespace['call']=delegate;out=io.StringIO();err=io.StringIO()
                with mock.patch.object(sys,'argv',['program','sock','1','2',command]),redirect_stdout(out),mock.patch('sys.stderr',err),mock.patch.object(time,'sleep'):
                    exec(script[len(r.base._QGA):],namespace)
                return json.loads(out.getvalue()),queries,submits,err.getvalue()
            original,queries,submits,_=execute(remote,[old])
            self.assertEqual(original['state'],'observed')
            bound,queries,submits,events=execute(program,[old,{'exited':False},fresh])
            self.assertEqual(bound['state'],'observed')
            self.assertEqual(bound,original);self.assertEqual(queries,[4560]*3);self.assertEqual(len(submits),1)
            self.assertIn('execution-binding-pending',events)
            rejected,queries,submits,_=execute(program,[old]*80)
            self.assertEqual(rejected['state'],'unknown');self.assertEqual(queries,[4560]*80);self.assertEqual(len(submits),1)
            with mock.patch.object(r.base,'_private_intent',return_value=intent):
                with self.assertRaises(r.Blocked):r._fresh_retained_c32_program(self.root,remote,command+'x',nonce)

    def test_fresh_call_never_resubmits_or_queries_different_child_or_socket(self):
        delegate=mock.Mock(return_value={'pid':4560});events=[]
        call=r._fresh_call(delegate,'-Command','exit 0','a'*64,'7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b',events.append,28000)
        args={'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command','exit 0'],'capture-output':True}
        call('sock','guest-exec',args)
        for command,arguments,sock in (('guest-exec',args,'sock'),('guest-exec-status',{'pid':4561},'sock'),('guest-exec-status',{'pid':4560},'other')):
            with self.assertRaises(ValueError):call(sock,command,arguments)
        self.assertEqual(delegate.call_count,1)

    def test_generated_poll_events_distinguish_80_live_observations_from_socket_timeout(self):
        from agent_tools import windows_cp117_c32_absence as absence
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';source=absence._script(absence._C32)
        program=r._fresh_c32_program(source,nonce)
        def execute(timeout):
            namespace={};exec(r.base._QGA,namespace);namespace['live']=lambda *args:True
            calls=[]
            def delegate(sock,command,args):
                calls.append((command,args))
                if command=='guest-exec':return {'pid':7100}
                if timeout:raise TimeoutError('must not appear in event')
                return {'exited':False}
            namespace['call']=delegate;output=io.StringIO();events=io.StringIO()
            with mock.patch.object(sys,'argv',['program','sock','1','2',base64.b64encode(source.encode('utf-16le')).decode()]),mock.patch('sys.stderr',events),redirect_stdout(output),mock.patch.object(time,'sleep'):
                exec(program[len(r.base._QGA):],namespace)
            self.assertEqual(json.loads(output.getvalue()),{'state':'unknown'})
            self.assertNotIn('must not appear',events.getvalue())
            return [json.loads(line.split(' ',1)[1]) for line in events.getvalue().splitlines()],calls
        exhausted,calls=execute(False)
        self.assertEqual(len(calls),81);self.assertEqual([e['poll'] for e in exhausted if e['kind']=='poll-observed'],list(range(1,81)))
        self.assertTrue(all(e['exited'] is False for e in exhausted if e['kind']=='poll-observed'))
        self.assertNotIn('poll-exception',[e['kind'] for e in exhausted])
        failed,calls=execute(True)
        self.assertEqual(len(calls),2);self.assertEqual(failed[-1]['kind'],'poll-exception');self.assertEqual(failed[-1]['exception'],'socket-timeout');self.assertEqual(failed[-1]['poll'],1)
        for events in (exhausted,failed):self.assertTrue(all(e['childPid']==7100 for e in events))

    def test_pending_execution_reasons_are_finite_and_keep_raw_payload_private(self):
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';sha='a'*64
        header=('VPNCONTROL-READ '+nonce+' '+sha+' 7100\r\n').encode()
        for raw,reason in ((b'private payload','header-missing'),(header.replace(nonce.encode(),b'0'*36),'nonce-mismatch'),(header.replace(sha.encode(),b'b'*64),'source-mismatch'),(header.replace(b'7100',b'7101'),'child-mismatch'),(b'VPNCONTROL-READ malformed\n','header-malformed')):
            self.assertEqual(r._fresh_reject_reason(raw,nonce,sha,7100),reason)

    def test_fresh_static_effects_are_only_admitted_as_fixed_parser_data(self):
        nonce='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b'
        proof=r._validate_original(self.old,self.observed,self.expected)
        first,final,intent=r._scripts(r._binding(self.descriptor,proof),self.expected,proof)
        for effect in (first,final):
            with self.assertRaises(r.Blocked):r._fresh_static_program(r.wire._command(effect),self.expected,nonce,proof)
            parser=r._parser_command(effect)
            program=r._fresh_static_program(parser,self.expected,nonce,proof)
            self.assertTrue(program.endswith(r.original._REMOTE_BODY))
        config=object();target=SimpleNamespace(fixture_transfer_root=Path('/fixture'));delegate=mock.Mock(return_value=b'effect-result')
        args=('/fixture',*r.wire.observer._remote_arguments(self.descriptor,self.closed),r.wire._command(first))
        with mock.patch.object(r.base,'_descriptor',return_value=(config,target,self.descriptor)),mock.patch.object(r.base,'_remote',delegate):
            with r._fresh_read_scope(self.root,'start') as scope:
                scope['proof']=proof
                with self.assertRaises(r.Blocked):r.base._remote(config,r.original._REMOTE,args,None,90)
                self.assertEqual(delegate.call_count,0)
                directory=self.root/r._DIR;directory.mkdir(mode=0o700)
                r.wire.guards.secure_write_create(directory/'intent.json',intent)
                self.assertEqual(r.base._remote(config,r.original._REMOTE,args,None,90),b'effect-result')
                self.assertEqual(delegate.call_args.args,(config,r.original._REMOTE,args,None,90))

    def test_process_gate_source_keeps_exact_idle_snapshot_and_fixed_readonly_inputs(self):
        correlation='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b'
        source=r._process_gate_source(correlation,self.expected)
        common=r.original._common(self.expected).split('function Snapshot(',1)[0]
        self.assertTrue(source.startswith(common.replace(' $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)',' $all=@(Get-CimInstance Win32_Process -ErrorAction Stop); $script:ObservedAll=$all',1)))
        self.assertIn("if(@($all|Where-Object {$_.ProcessId -ne $PID -and $_.Name -match '^(powershell|pwsh|vpn-control|vpn-control-cli|sing-box)\\.exe$'}).Count -ne 0){throw 'process'}",source)
        launcher=r.wire.transport._launcher(source)
        self.assertLess(len(launcher),28000)
        packed=launcher.split("FromBase64String('")[1].split("')")[0]
        self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
        self.assertIn('selfSourceSha256=(SourceDigest',source)
        self.assertIn('otherCount=$others.Count',source)
        self.assertNotIn('function Snapshot(',source)
        with self.assertRaises(r.Blocked):r._process_gate_source(correlation,self.expected[:-1])

    def test_process_gate_facts_validate_nonce_source_pid_and_each_identity_field(self):
        correlation='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';sha='1'*64
        fact={'pid':4560,'parentPid':123,'creationTicks':638000000000000000,'name':'powershell.exe','commandSha256':'2'*64,'sourceSha256':'3'*64,'osState':'live','osCreationTicks':638000000000000000}
        value={'correlationId':correlation,'selfPid':7000,'selfSourceSha256':sha,'guard':'process','otherCount':1,'processes':[fact]}
        self.assertEqual(r._process_gate_receipt(value,correlation,sha,7000),value)
        for field,bad in (('correlationId','2355f68a-c958-4e13-8eb2-141dccf004f9'),('selfSourceSha256','0'*64),('selfPid',True),('otherCount',True),('processes',[])):
            changed=copy.deepcopy(value);changed[field]=bad
            with self.assertRaises(r.Blocked):r._process_gate_receipt(changed,correlation,sha,7000)
        for field,bad in (('pid',True),('pid',7000),('parentPid',True),('creationTicks',True),('name','foreign.exe'),('commandSha256','x'*64),('sourceSha256','x'*64),('osState','foreign'),('osCreationTicks',True),('osCreationTicks',None)):
            changed=copy.deepcopy(value);changed['processes'][0][field]=bad
            with self.assertRaises(r.Blocked):r._process_gate_receipt(changed,correlation,sha,7000)
        changed=copy.deepcopy(value);changed['processes']*=2;changed['otherCount']=2
        with self.assertRaises(r.Blocked):r._process_gate_receipt(changed,correlation,sha,7000)
        with self.assertRaises(r.Blocked):r._process_gate_receipt({**value,'selfSourceSha256':None},correlation,None,7000)

    def test_process_gate_os_metadata_is_readonly_and_does_not_promote_absent_or_unknown(self):
        correlation='7045a115-ecc2-4a18-9c1f-4c0ea8d8ce3b';sha='1'*64
        source=r._process_gate_source(correlation,self.expected)
        for item in ('GetProcessById([int]$p.ProcessId)','StartTime.ToUniversalTime().Ticks','HasExited','$ownedProcess.Dispose()'):
            self.assertIn(item,source)
        for forbidden in ('WaitForExit','Kill(','Stop-Process','CloseMainWindow','TerminateProcess'):
            self.assertNotIn(forbidden,source.split('function SourceDigest',1)[1])
        fact={'pid':4560,'parentPid':123,'creationTicks':638000000000000000,'name':'powershell.exe','commandSha256':'2'*64,'sourceSha256':'3'*64,'osState':'absent','osCreationTicks':None}
        value={'correlationId':correlation,'selfPid':7000,'selfSourceSha256':sha,'guard':'process','otherCount':1,'processes':[fact]}
        for state in ('absent','unknown','exited'):
            value['processes'][0]['osState']=state
            observed=r._process_gate_receipt(value,correlation,sha,7000)
            self.assertEqual(observed['guard'],'process')
            self.assertEqual(observed['processes'][0]['osState'],state)
        value['processes'][0]['osState']='absent';value['processes'][0]['osCreationTicks']=638000000000000000
        with self.assertRaises(r.Blocked):r._process_gate_receipt(value,correlation,sha,7000)

    def test_actual_retained_observer_preserves_original_receipt_and_failure_predicates(self):
        receipt={'binding':'original-proof','service':{'pid':123}}
        payload=base64.b64encode(json.dumps(receipt).encode()).decode()
        for item,expected in (({'exited':True,'exitcode':0,'out-data':payload},receipt),({'exited':True,'exitcode':1,'out-data':payload},{'_phase':'powershell-terminal'}),({'exited':True,'exitcode':0,'out-truncated':True,'out-data':payload},{'_phase':'powershell-terminal'}),({'exited':True,'exitcode':0,'out-data':base64.b64encode(b'bad json').decode()},{'_phase':'json-shape'})):
            correlation=str(__import__('uuid').uuid4());remote_root=self.root/('remote-'+correlation);remote_root.mkdir(mode=0o700)
            config=object();target=SimpleNamespace(fixture_transfer_root=remote_root)
            def remote(config,program,args,source,timeout):
                namespace={};exec(r.base._QGA,namespace)
                namespace['live']=lambda *args:True
                namespace['call']=lambda sock,command,args:{'pid':123} if command=='guest-exec' else item
                output=io.StringIO()
                with mock.patch.object(sys,'argv',['program',*args]),mock.patch.object(time,'sleep'),redirect_stdout(output):exec(program[len(r.base._QGA):],namespace)
                os.close(namespace['lock'])
                return output.getvalue().encode()
            with mock.patch.object(r.base,'_descriptor',return_value=(config,target,self.descriptor)),mock.patch.object(r.base,'_remote',side_effect=remote):
                observed,diagnostic=r.retained_recovery_observe(self.root,config,self.descriptor,r.base._fixed_recovery_task_status_script(),correlation)
            self.assertEqual(observed,expected);self.assertEqual(diagnostic['childPid'],123)

    def test_local_anchor_receipts_reject_drift_before_remote_status(self):
        for change in ('hardlink','same-bytes','pid','missing','exchange','receipt-generation','seal-generation'):
            with self.subTest(change=change):
                correlation=str(__import__('uuid').uuid4());target=SimpleNamespace(fixture_transfer_root=Path('/owned/fixture'))
                def remote(config,program,args,source,timeout):
                    request=json.loads(args[3]);digest=hashlib.sha256(args[3].encode()).hexdigest()
                    if args[2]=='start':return json.dumps({'state':'retained','anchor':{'requestSha256':digest,'child':{'requestSha256':digest,'kind':'child','pid':456},'fingerprint':[1,2,3,4,1,6,7,8],'rootIdentity':[1,2],'jobIdentity':[3,4]}}).encode()
                    return b'{"state":"diagnosed","childPid":456,"pollCount":1,"lastObservation":{"kind":"poll","pid":456,"outcome":"running","elapsedMs":1},"replayAllowed":false,"productAction":false}'
                with mock.patch.object(r.base,'_descriptor',return_value=(object(),target,self.descriptor)),mock.patch.object(r.base,'_remote',side_effect=remote):
                    self.assertEqual(r.recovery_read_diagnostic(self.root,correlation,'start')['childPid'],456)
                directory=self.root/'.rag_index/windows-recovery-read-diagnostic';anchor=directory/(correlation+'.child.json')
                path=directory/(correlation+'.child.receipt.json') if change=='receipt-generation' else directory/(correlation+'.child.seal.json') if change=='seal-generation' else anchor
                raw=path.read_bytes()
                if change=='hardlink':os.link(path,directory/(correlation+'.alias'))
                elif change=='pid':value=json.loads(raw);value['child']['pid']=999;path.write_text(json.dumps(value))
                elif change=='missing':path.unlink()
                elif change=='exchange':path.unlink();path.write_bytes(raw);path.chmod(0o600)
                else:path.write_bytes(raw)
                with mock.patch.object(r.base,'_descriptor',return_value=(object(),target,self.descriptor)),mock.patch.object(r.base,'_remote') as query:
                    with self.assertRaises((r.Blocked,OSError)):r.recovery_read_diagnostic(self.root,correlation,'status')
                    query.assert_not_called()

    def test_local_anchor_drift_during_remote_status_discards_observation(self):
        correlation='5063c817-dbbb-49c4-8712-abd2d3f48594';target=SimpleNamespace(fixture_transfer_root=Path('/owned/fixture'))
        def remote(config,program,args,source,timeout):
            digest=hashlib.sha256(args[3].encode()).hexdigest()
            if args[2]=='start':return json.dumps({'state':'retained','anchor':{'requestSha256':digest,'child':{'requestSha256':digest,'kind':'child','pid':456},'fingerprint':[1,2,3,4,1,6,7,8],'rootIdentity':[1,2],'jobIdentity':[3,4]}}).encode()
            return b'{"state":"diagnosed","childPid":456,"pollCount":1,"lastObservation":{"kind":"poll","pid":456,"outcome":"running","elapsedMs":1},"replayAllowed":false,"productAction":false}'
        with mock.patch.object(r.base,'_descriptor',return_value=(object(),target,self.descriptor)),mock.patch.object(r.base,'_remote',side_effect=remote):r.recovery_read_diagnostic(self.root,correlation,'start')
        anchor=self.root/'.rag_index/windows-recovery-read-diagnostic'/(correlation+'.child.json')
        def drift(*args):anchor.write_bytes(anchor.read_bytes());return remote(*args)
        with mock.patch.object(r.base,'_descriptor',return_value=(object(),target,self.descriptor)),mock.patch.object(r.base,'_remote',side_effect=drift):
            with self.assertRaises(r.Blocked):r.recovery_read_diagnostic(self.root,correlation,'status')

    def test_retained_remote_exhaustion_then_same_child_completion_without_relaunch(self):
        root=self.root/'remote';root.mkdir(mode=0o700)
        correlation='550ccca4-cd89-412b-9ec9-2ea75b2bac3b';launcher='fixed-read-only-test'
        request={'correlationId':correlation,'generation':list(self.descriptor),'launcherSha256':hashlib.sha256(launcher.encode()).hexdigest()}
        request_text=json.dumps(request,separators=(',',':'),sort_keys=True)
        program=r._recovery_diagnostic_program()[len(r.base._QGA):]
        calls=[]
        def delegate(sock,command,args):
            calls.append((command,args))
            if command=='guest-exec':return {'pid':456}
            child=json.loads((root/('windows-recovery-read-diagnostic-'+correlation)/'child.json').read_text())
            self.assertEqual(child['pid'],456)
            return {'exited':False}
        namespace={'call':delegate,'live':lambda *args:True,'os':os,'stat':stat,'sys':sys,'re':__import__('re'),'hashlib':hashlib,'json':json,'decode':lambda raw:raw.decode()}
        out=io.StringIO()
        with mock.patch.object(sys,'argv',['program',str(root),correlation,'start',request_text,launcher,'{}']),mock.patch.object(time,'sleep'),redirect_stdout(out):exec(program,namespace)
        os.close(namespace['lock']) # Model the completed remote process's FD close.
        anchor=json.loads(out.getvalue())['anchor'];namespace['call']=delegate;out=io.StringIO()
        with mock.patch.object(sys,'argv',['program',str(root),correlation,'poll',request_text,launcher,json.dumps(anchor)]),mock.patch.object(time,'sleep'),redirect_stdout(out):exec(program,namespace)
        os.close(namespace['lock'])
        value=json.loads(out.getvalue());self.assertEqual(value['pollCount'],80);self.assertEqual(value['lastObservation']['outcome'],'running')
        self.assertEqual(sum(command=='guest-exec' for command,_ in calls),1)

        def completed(sock,command,args):
            self.assertEqual(command,'guest-exec-status');self.assertEqual(args,{'pid':456});return {'exited':True,'exitcode':0}
        namespace['call']=completed;out=io.StringIO()
        with mock.patch.object(sys,'argv',['program',str(root),correlation,'status',request_text,launcher,json.dumps(anchor)]),redirect_stdout(out):exec(program,namespace)
        os.close(namespace['lock'])
        value=json.loads(out.getvalue());self.assertEqual(value['pollCount'],81);self.assertEqual(value['lastObservation']['outcome'],'exited')
        self.assertEqual(sum(command=='guest-exec' for command,_ in calls),1)
        namespace['call']=delegate
        with mock.patch.object(sys,'argv',['program',str(root),correlation,'start',request_text,launcher,'{}']):
            with self.assertRaises(FileExistsError):exec(program,namespace)
        self.assertEqual(sum(command=='guest-exec' for command,_ in calls),1)

    def test_rewritten_retained_child_never_queries_replacement_pid(self):
        for change in ('pid','same-bytes','missing'):
            with self.subTest(change=change):
                root=self.root/('child-seal-'+change);root.mkdir(mode=0o700)
                correlation='dc63ecde-807e-4dfc-93c5-723a7d51f3d0';launcher='fixed-read-only-test'
                request={'correlationId':correlation,'generation':list(self.descriptor),'launcherSha256':hashlib.sha256(launcher.encode()).hexdigest()}
                request_text=json.dumps(request,separators=(',',':'),sort_keys=True)
                program=r._recovery_diagnostic_program()[len(r.base._QGA):]
                namespace={'call':lambda sock,command,args:{'pid':456} if command=='guest-exec' else {'exited':False},'live':lambda *args:True,'os':os,'stat':stat,'sys':sys,'re':__import__('re'),'hashlib':hashlib,'json':json,'decode':lambda raw:raw.decode()}
                out=io.StringIO()
                with mock.patch.object(sys,'argv',['program',str(root),correlation,'start',request_text,launcher,'{}']),redirect_stdout(out):exec(program,namespace)
                os.close(namespace['lock']);anchor=json.loads(out.getvalue())['anchor']
                child=root/('windows-recovery-read-diagnostic-'+correlation)/'child.json'
                raw=child.read_bytes();data=json.loads(raw)
                if change=='pid':data['pid']=999;child.write_text(json.dumps(data));child.chmod(0o600)
                elif change=='same-bytes':child.write_bytes(raw);child.chmod(0o600)
                else:child.unlink()
                queried=[]
                namespace['call']=lambda sock,command,args:queried.append(args['pid']) or {'exited':False}
                with mock.patch.object(sys,'argv',['program',str(root),correlation,'status',request_text,launcher,json.dumps(anchor)]),redirect_stdout(io.StringIO()):
                    try:exec(program,namespace)
                    except (ValueError,OSError):pass
                if 'lock' in namespace:os.close(namespace['lock'])
                self.assertEqual(queried,[])

    def test_second_original_receipt_drift_and_current_identity_block(self):
        calls=[0]
        def observe(root,descriptor,closed,source):
            calls[0]+=1;value=copy.deepcopy(self.observed)
            if calls[0]==2:value['archivesPacket']['sha256']='0'*64
            return value
        with mock.patch.object(r.original,'_run',side_effect=observe):
            self.assertEqual(r.start(self.root,{})['state'],'blocked')
        self.assertFalse((self.root/r._DIR).exists())
        wrong=copy.deepcopy(self.old);wrong['binding']['generation'][1]='foreign'
        wrong=r.original._plan(wrong['binding'],self.expected)[1]
        value=copy.deepcopy(self.observed);value['binding']=wrong
        with self.assertRaises(r.Blocked):r._validate_original(wrong,value,self.expected)

    def test_existing_foreign_own_root_and_unsafe_parent_reject_without_consumption(self):
        def observe(root,descriptor,closed,source):
            if source==r._root_absence(self.expected):return {'state':'blocked','phase':'binding'}
            return self.fake_run(root,descriptor,closed,source)
        with mock.patch.object(r.original,'_run',side_effect=observe):
            self.assertEqual(r.start(self.root,{})['phase'],'binding')
            self.assertFalse((self.root/r._DIR).exists())
        (self.root/r.original._DIR).chmod(0o755)
        self.assertEqual(r.start(self.root,{})['phase'],'host-original-intent-value')
        self.assertFalse((self.root/r._DIR).exists())

    def test_verified_observer_then_payload_mismatch_reports_exact_readonly_boundary(self):
        value=copy.deepcopy(self.observed);value['binding']=dict(value['binding'],actionSha256='0'*64)
        with mock.patch.object(r.original,'_run',return_value=value):result=r.preflight(self.root,{})
        self.assertEqual(result['phase'],'original-binding')
        self.assertEqual(result['state'],'blocked')
        self.assertFalse((self.root/r._DIR).exists());self.assertEqual(self.writes,[])

    def test_actual_original_diagnose_callgraph_under_outer_shared_token(self):
        flock=r.history.fcntl.flock
        with mock.patch.object(r.original,'diagnose',side_effect=ACTUAL_DIAGNOSE),mock.patch.object(r.history.fcntl,'flock',wraps=flock) as acquire:
            result=r.preflight(self.root,{})
        self.assertEqual(result,r._result('ready','snapshot'))
        self.assertEqual(acquire.call_count,1)
        self.assertEqual(self.writes,[]);self.assertFalse((self.root/r._DIR).exists())

    def test_actual_missing_terminal_diagnosis_has_four_recovery_reads(self):
        with mock.patch.object(r.original,'_steady',side_effect=ACTUAL_STEADY),mock.patch.object(r.base,'_fixed_c32_task_terminal',return_value=True),mock.patch.object(r.base,'_fixed_recovery_task_terminal',return_value=True) as recovery:
            self.assertEqual(ACTUAL_DIAGNOSE(self.root,{}),r.original._result('unknown','diagnostic-terminal-absent-verified'))
        self.assertEqual(recovery.call_count,4)
        self.assertEqual(recovery.call_args_list,[mock.call(self.root.resolve(),self.descriptor)]*4)

    def test_actual_recovery_predicates_four_reads_and_single_failure_localization(self):
        from agent_tools import windows_cp117_guest_agent_recovery_successor as recovery
        before={'name':'qemu-ga','state':'Running','startName':'LocalSystem','pid':12,'startTicks':41,'path':r'C:\qemu-ga.exe'}
        intent={'recoveryCorrelationId':recovery._RECOVERY,'service':before,'guestGeneration':{'socketPath':self.descriptor[1],'qemuPid':self.descriptor[2],'startTicks':self.descriptor[3]}}
        digest=recovery._digest(intent);action=recovery._action(before,digest)
        observed={'binding':digest,'terminalBinding':digest,'outcome':'restarted','taskSystem':True,'taskState':'Ready','actionSha256':action,'service':{**before,'pid':13,'startTicks':42},'recoveryCorrelationId':recovery._RECOVERY,'childPid':20,'childStartTicks':40}
        directory=self.root/recovery._DIR;directory.mkdir(mode=0o700)
        for name,value in (('intent.json',intent),('terminal.json',{'intentSha256':digest,'outcome':'restarted'}),('action.json',{'intentSha256':digest,'actionSha256':action})):r.wire.guards.secure_write_create(directory/name,value)
        with mock.patch.object(r.original,'_steady',side_effect=ACTUAL_STEADY),mock.patch.object(r.base,'_fixed_c32_task_terminal',return_value=True),mock.patch.object(recovery.original,'_run_ps',return_value=observed) as transport:
            self.assertEqual(ACTUAL_DIAGNOSE(self.root,{}),r.original._result('unknown','diagnostic-terminal-absent-verified'))
            self.assertEqual(transport.call_count,4)
        with mock.patch.object(r.original,'diagnose',side_effect=ACTUAL_DIAGNOSE),mock.patch.object(r.original,'_steady',side_effect=ACTUAL_STEADY),mock.patch.object(r.base,'_fixed_c32_task_terminal',return_value=True),mock.patch.object(recovery.original,'_run_ps',return_value=observed) as transport:
            self.assertEqual(r.preflight(self.root,{}),r._result('ready','snapshot'))
            self.assertEqual(transport.call_count,6)
        order=[]
        def bounded(config,descriptor,script):
            self.assertLess(len(order),5)
            self.assertEqual(descriptor,self.descriptor);self.assertEqual(script,r.base._fixed_recovery_task_status_script())
            order.append(len(order)+1)
            return {'_phase':'guest-status'} if len(order)==4 else observed
        with mock.patch.object(r.original,'_steady',side_effect=ACTUAL_STEADY),mock.patch.object(r.base,'_fixed_c32_task_terminal',return_value=True),mock.patch.object(recovery.original,'_run_ps',side_effect=bounded):
            result=ACTUAL_DIAGNOSE(self.root,{})
            self.assertEqual(result,r.original._result('unknown','history'))
            with self.assertRaises(r.Blocked) as failure:r._history_failure(self.root,self.descriptor,self.closed,self.expected)
            self.assertEqual(failure.exception.phase,'original-history-transient')
        self.assertEqual(order,[1,2,3,4,5]);self.assertEqual(self.writes,[])

    def test_original_observer_finite_phase_and_dispatch_hash_stability(self):
        d,c,e,p=r._proof(self.root);binding=r._binding(d,p)
        scripts=r._scripts(binding,e,p)
        with mock.patch.object(r,'_PHASES',r._PHASES | {'future-readonly-diagnostic'}):self.assertEqual(r._scripts(binding,e,p),scripts)
        for phase in ('diagnostic-stage-terminal','process','transport-status'):
            with self.subTest(phase=phase),mock.patch.object(r.original,'diagnose',return_value=r.original._result('unknown',phase)):
                self.assertEqual(r.preflight(self.root,{})['phase'],'original-observer-'+phase)
        with mock.patch.object(r.original,'diagnose',return_value={'state':'unknown','phase':'private-raw-error'}):
            self.assertEqual(r.preflight(self.root,{})['phase'],'original-observer-shape')
        self.assertFalse((self.root/r._DIR).exists());self.assertEqual(self.writes,[])

    def test_actual_host_exception_is_finite_and_no_intent_or_dispatch(self):
        with mock.patch.object(r.original,'_admit_local',side_effect=ValueError('private-path-and-error')):
            result=r.preflight(self.root,{})
        self.assertEqual(result['phase'],'host-admission-value')
        self.assertEqual(result['state'],'blocked')
        self.assertNotIn('private',json.dumps(result))
        self.assertFalse((self.root/r._DIR).exists());self.assertEqual(self.writes,[])

    def test_host_boundaries_are_redacted_before_and_after_consumption(self):
        for checkpoint,function,error,phase in (
            ('observer','diagnose',TypeError('private raw'),'host-observer-type'),
            ('probe','_run',KeyError('private field'),'host-probe-key'),
            ('plan','_diagnostic_reader',ValueError('private source'),'host-plan-value')):
            with self.subTest(checkpoint=checkpoint),mock.patch.object(r.original,function,side_effect=error):
                result=r.preflight(self.root,{})
                self.assertEqual(result['phase'],phase)
                self.assertNotIn('private',json.dumps(result));self.assertEqual(self.writes,[])
        r.start(self.root,{})
        with mock.patch.object(r.original,'_admit_local',side_effect=OSError('private path')):
            result=r.start(self.root,{})
            self.assertEqual(result['state'],'unknown')
            self.assertEqual(result['phase'],'host-admission-os')
        self.assertEqual(self.writes,['binding','terminal'])

    def test_measured_original_history_failure_localizes_exact_fresh_guard(self):
        with mock.patch.object(r.original,'diagnose',return_value=r.original._result('unknown','history')),mock.patch.object(r.base,'_fixed_c32_task_terminal',return_value=False):
            result=r.preflight(self.root,{})
        self.assertEqual(result['phase'],'original-history-c32')
        self.assertEqual(result['state'],'blocked')
        self.assertFalse((self.root/r._DIR).exists());self.assertEqual(self.writes,[])

    def test_history_localization_never_promotes_transient_or_foreign_proof(self):
        observed=r.original._result('unknown','history')
        for c32,recovery,phase in ((True,False,'original-history-recovery'),(True,True,'original-history-transient')):
            with self.subTest(phase=phase),mock.patch.object(r.original,'diagnose',return_value=observed),mock.patch.object(r.base,'_fixed_c32_task_terminal',return_value=c32),mock.patch.object(r.base,'_fixed_recovery_task_terminal',return_value=recovery):
                self.assertEqual(r.preflight(self.root,{})['phase'],phase)
        count=[0]
        def admit(root):
            count[0]+=1
            if count[0]>1:raise r.original.Blocked('history')
            return self.descriptor,self.closed,self.expected
        with mock.patch.object(r.original,'diagnose',return_value=observed),mock.patch.object(r.original,'_admit_local',side_effect=admit):
            self.assertEqual(r.preflight(self.root,{})['phase'],'original-history-local')
        self.assertFalse((self.root/r._DIR).exists());self.assertEqual(self.writes,[])

    def test_actual_base_route_read_reuses_campaign_shared_lock_without_upgrade(self):
        # Actual closure callgraph: route census -> pre-effect closed receipt.
        # NB on an attempted EX makes the historical self-deadlock deterministic.
        b=r.base;corr=b._PRE_EFFECT_REJECTED_CORRELATION
        intent={'request':b._PRE_EFFECT_REJECTED_REQUEST,'commandSha256':b._PRE_EFFECT_REJECTED_COMMAND_SHA256,
                'environment':'windows-cp117','pid':589342,'startTicks':520739,
                'socketPath':self.descriptor[1],'expectedSid':self.descriptor[4]}
        marker={'correlationId':corr,'commandSha256':b._PRE_EFFECT_REJECTED_COMMAND_SHA256,
                'state':'pre-effect-closed','cleanupReceiptSha256':'a'*64}
        r.wire.guards.secure_write_create(b._pre_effect_marker(self.root),marker)
        r.wire.guards.secure_write_create(b._intent_path(self.root,corr),intent)
        closed={'identity':b._campaign_identity(b._PRE_EFFECT_REJECTED_REQUEST,self.descriptor),
                'lastOutcome':'failed-cleaned','lastEvidenceSha256':'a'*64}
        flock=r.history.fcntl.flock;exclusive=[]
        def bounded(fd,operation):
            if operation & r.history.fcntl.LOCK_EX:
                exclusive.append(fd);operation |= r.history.fcntl.LOCK_NB
            return flock(fd,operation)
        reads=[]
        def protected_read(directory,correlation):
            self.assertEqual(correlation,corr)
            writer=os.open(directory/'.environment.lock',os.O_RDONLY|os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError):
                    flock(writer,r.history.fcntl.LOCK_EX|r.history.fcntl.LOCK_NB)
            finally:os.close(writer)
            reads.append(True)
            return closed
        with mock.patch.object(b,'_private_intent',return_value=intent),mock.patch.object(b.campaign_lease,'_closed',side_effect=protected_read):
            with r.history._history_lock(self.root),mock.patch.object(r.history.fcntl,'flock',side_effect=bounded):
                ACTUAL_ROUTE(self.root)
        self.assertTrue(reads)
        self.assertEqual(exclusive,[])
        self.assertFalse((self.root/r._DIR/'intent.json').exists())

    def test_two_concurrent_start_calls_consume_only_once(self):
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(lambda _:r.start(self.root,{}),range(2)))
        self.assertEqual(self.writes,['binding','terminal']);self.assertIn('closed',[v['state'] for v in results])

ACTUAL_ROUTE=r.base._require_base_route_free
ACTUAL_DIAGNOSE=r.original.diagnose
ACTUAL_PARSE=r._parse
ACTUAL_STEADY=r.original._steady
if __name__=='__main__':unittest.main()
