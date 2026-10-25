"""Complete inert gateway callers retain immutable SSH submission custody."""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import types
import unittest
from unittest import mock

from agent_tools import ssh_gateway_tmux_master_ssh as adapter
from agent_tools import ssh_gateway_tmux_d606_diagnostic as diagnostic
from agent_tools.tests import test_ssh_gateway_tmux_master_ssh as gateway_fixtures
from agent_tools.tests import test_ssh_gateway_tmux_d606_diagnostic as diagnostic_fixtures

FIXTURE = Path(__file__).parent/'fixtures/ssh_gateway_bound_carrier'


def before(name):
    path = FIXTURE/(name+'.before.source'); raw=path.read_bytes()
    record=json.loads((FIXTURE/'provenance.json').read_bytes())['sources'][str(path.relative_to(Path(__file__).parents[2]))]
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source')
    module=types.ModuleType('agent_tools._bound_gateway_before_'+name.removesuffix('.py'))
    module.__package__='agent_tools';module.__file__=str(path)
    with mock.patch.dict(sys.modules,{module.__name__:module}):
        exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


@unittest.skipUnless(os.name=='posix','POSIX private gateway fixture')
class GatewayBoundCarrierTests(unittest.TestCase):
    @contextmanager
    def fixture(self,kind=gateway_fixtures.GatewayAdapterTests):
        case=kind('test_actual_prepare_release_ready_fixed_gateway_only')
        try:
            case.setUp();yield case
        finally:case.doCleanups()

    def compress_fixture_owner(self,case):
        # Exact public standalone source, compressed only for the inline/E2BIG
        # boundary cohort. The actual saved-source cohort uses the full source.
        import zlib,base64
        body=case.new_source.read_bytes()
        encoded=base64.b64encode(zlib.compress(body,9)).decode()
        case.new_source.write_text("import base64,zlib;exec(compile(zlib.decompress(base64.b64decode("+repr(encoded)+")),__file__,'exec'))\n")

    def bridge(self,case,events):
        def launch(argv,**kw):
            self.assertEqual('/usr/bin/ssh',argv[0]);self.assertEqual('gateway.invalid',argv[-2])
            self.assertIn('ControlPath=none',argv);self.assertIn('ControlMaster=no',argv)
            self.assertLessEqual(sum(len(x.encode())+1 for x in argv),60000)
            self.assertNotIn('inert-secret',' '.join(argv))
            command=shlex.split(argv[-1]);self.assertIn(command[0],('python3','/usr/bin/python3'))
            self.assertEqual(['-I','-B','-c'],command[1:4])
            # This boundary replaces only SSH/sshd with its exact emitted Python
            # command. The remote interpreter has no local SSH writer file cap.
            kw.pop('preexec_fn',None)
            try:child=case.original_popen([sys.executable,*command[1:]],**kw)
            except OSError as error:
                events.append(('refused',error.errno));raise
            events.append(('child',child.pid));return child
        return launch

    def test_whole_original_mutation_red_new_prepare_release_ready_green(self):
        old=before('ssh_gateway_tmux_master_ssh.py')
        with self.fixture() as case:
            result=old.operate(case.controller,'prepare',case.request_inputs)
            self.assertEqual('unknown',result['state']);self.assertEqual([],case.calls)
            intent=case.controller/'.rag_index/ssh-gateway-tmux-master'/case.request_inputs['correlationId']/'intent.json'
            self.assertTrue(intent.exists())
            self.assertEqual('unknown',old.operate(case.controller,'prepare',case.request_inputs)['state'])
            self.assertEqual([],case.calls)
        with self.fixture() as case:
            result=case.ready_adapter();self.assertEqual('ready',result['state'])
            self.assertGreaterEqual(len(case.calls),3)
            self.assertTrue(all('ControlPath=none' in x and 'ControlMaster=no' in x for x in case.calls))

    def test_whole_original_diagnostic_mutation_red_archived_public_proof_green(self):
        old=before('ssh_gateway_tmux_d606_diagnostic.py')
        with self.fixture(diagnostic_fixtures.DiagnosticCallerTests) as case:
            case.ready_adapter();case.launcher.stop();events=[]
            with mock.patch.object(old,'__file__',str(case.caller)), \
                 mock.patch.object(old,'ORIGINAL_SOURCE_SHA256',adapter.owner.sha(case.raw)), \
                 mock.patch.object(subprocess,'Popen',side_effect=self.bridge(case,events)):
                self.assertEqual('unknown',old.observe(case.controller)['state'])
            self.assertEqual([],events)
            from agent_tools.tests.ssh_gateway_historical_fixture import load
            qualified=load('diagnostic.carrier-only.before.source')
            with mock.patch.object(qualified,'__file__',str(case.caller)), \
                 mock.patch.object(qualified,'ORIGINAL_SOURCE_SHA256',adapter.owner.sha(case.raw)), \
                 mock.patch.object(subprocess,'Popen',side_effect=self.bridge(case,events)):
                result=qualified.observe(case.controller)
            self.assertEqual('observed',result['state'],result);self.assertEqual(1,len(events))

    def test_bound_original_corruption_at_actual_submission_blocks_child(self):
        with self.fixture() as case:
            self.compress_fixture_owner(case)
            original=adapter.transport.popen_ssh;observed=[]
            def dispatch(argv,**kw):
                observed.append(argv)
                # An adversarial list-subclass bypass must still fail the
                # actual submission guard, before any SSH child exists.
                list.__setitem__(argv,-1,argv[-1]+' ')
                return original(argv,**kw)
            with mock.patch.object(adapter.transport,'popen_ssh',side_effect=dispatch):
                result=adapter.operate(case.controller,'prepare',case.request_inputs)
            self.assertEqual('unknown',result['state']);self.assertEqual([],case.calls)
            self.assertEqual(1,len(observed));self.assertIsInstance(observed[0],adapter.transport.BoundInlineArgv)

    def test_actual_kernel_prelaunch_e2big_uses_same_bound_source_once(self):
        argmax=os.sysconf('SC_ARG_MAX')
        if not 65536<=argmax<=8*1024*1024:self.skipTest('finite native ARG_MAX unavailable')
        remaining=argmax-20000-sum(len(os.fsencode(k))+len(os.fsencode(v))+2 for k,v in os.environ.items())
        padding={};index=0
        while remaining>128:
            name='VC_GATEWAY_KERNEL_BUDGET_'+str(index);value='E'*min(60000,remaining-len(name)-2)
            padding[name]=value;remaining-=len(name)+len(value)+2;index+=1
        with self.fixture() as case:
            self.compress_fixture_owner(case)
            case.launcher.stop();events=[];bound=[];actual=adapter.transport.build_ssh_argv
            def build(*args,**kw):
                argv=actual(*args,**kw)
                if isinstance(argv,adapter.transport.BoundInlineArgv) and not bound:bound.append(argv)
                return argv
            stage=case.controller/'automatic-stage';stage.mkdir(mode=0o700)
            with mock.patch.dict(os.environ,{**padding,'TMPDIR':str(stage)}), \
                 mock.patch('tempfile.tempdir',None), \
                 mock.patch.object(adapter.transport,'build_ssh_argv',side_effect=build), \
                 mock.patch.object(subprocess,'Popen',side_effect=self.bridge(case,events)):
                result=adapter.operate(case.controller,'prepare',case.request_inputs)
            self.assertEqual('prepared',result['state'],result)
            self.assertEqual([('refused',errno.E2BIG)], [x for x in events if x[0]=='refused'])
            self.assertEqual(2,len([x for x in events if x[0]=='child']))
            plan=bound[0].saved_plan;self.assertTrue(plan.fresh_direct)
            journal=case.controller/'.rag_index/ssh-automatic-program'/plan.correlation
            proof=json.loads((journal/'prelaunch-refusal.json').read_bytes())
            self.assertIs(False,proof['childCreated']);self.assertIs(False,proof['programStarted'])
            self.assertEqual(adapter.transport.argv_sha256(bound[0]),proof['originalArgvSha256'])
            self.assertTrue((journal/'submission-returned.json').exists())
            self.assertFalse((journal/'unknown.json').exists())
            original=shlex.split(bound[0][-1])[4].encode()
            self.assertEqual(original,(journal/'program.source').read_bytes())

    def test_authentic_old_release_echo_retained_red_public_projection_green(self):
        old=before('ssh_gateway_tmux_master_ssh.py')
        code="import json,sys;v=json.load(sys.stdin);print(json.dumps({'state':'unknown','replayAllowed':False,'echo':{'partial':v['credential'][:6],'whole':v['credential']}}))"
        def exercise(implementation,historical=False,program=code,budget=None):
            with self.fixture() as case:
                # This scenario targets final inline replies, not saved-source
                # transfer/preflight. Preserve the exact public owner bytes.
                if not historical:self.compress_fixture_owner(case)
                case.launcher.stop()
                def launch(argv,**kw):
                    # Original expects the historical raw list builder and EXEC
                    # wrapper; current preserves its immutable admitted carrier.
                    if historical:self.assertEqual(argv[2:5],['-B','-c',old.EXEC])
                    else:self.assertEqual('/usr/bin/ssh',argv[0])
                    return case.original_popen([sys.executable,'-I','-B','-c',program],**kw)
                with mock.patch.object(subprocess,'Popen',side_effect=launch):
                    with implementation.LocalAuthority(case.controller) as authority:
                        group=authority.group(create=True);job=group/case.request_inputs['correlationId']
                        job.mkdir(mode=0o700);authority.directory(job,True)
                        raw=implementation.packet(authority,case.request_inputs['correlationId'])
                        from contextlib import ExitStack
                        with ExitStack() as stack:
                            if historical:
                                stack.enter_context(mock.patch.object(implementation.transport,'build_ssh_argv',side_effect=implementation.transport._build_ssh_argv))
                            if budget is not None:
                                stack.enter_context(mock.patch.object(implementation.transport,'_remaining_timeout',return_value=budget))
                            try:implementation.query(authority,job,'release',raw)
                            except ValueError:pass
                        capsule=next(job.glob('query-*'))
                        stdout=(capsule/'stdout.private').read_bytes();stderr=(capsule/'stderr.private').read_bytes()
                        receipt=(capsule/'receipt.json').read_bytes()
                        if historical:
                            self.assertIn(b'inert-secret',stdout)
                            self.assertEqual(hashlib.sha256(stdout).hexdigest(),json.loads(receipt)['stdout']['sha256'])
                        else:
                            self.assertEqual(b'',stdout);self.assertEqual(b'',stderr)
                            self.assertNotIn(b'inert',receipt);self.assertNotIn(hashlib.sha256(b'inert-secret').hexdigest().encode(),receipt)
                            self.assertIs(False,json.loads(receipt)['replayAllowed'])
        exercise(old,True)
        cases=(('nested_echo',code,None),
            ('escaped_echo',"import json,sys;v=json.load(sys.stdin);print(json.dumps({'state':'unknown','replayAllowed':False,'echo':json.dumps(v)}))",None),
            ('malformed',"import json,sys;v=json.load(sys.stdin);sys.stdout.write(v['credential'][:6])",None),
            ('stderr',"import json,sys;v=json.load(sys.stdin);print(json.dumps({'state':'unknown','replayAllowed':False}));sys.stderr.write(v['credential'])",None),
            ('overflow',"import json,sys,os;v=json.load(sys.stdin);os.write(1,(v['credential']*7000).encode())",None),
            ('timeout',"import json,sys,time;v=json.load(sys.stdin);sys.stdout.write(v['credential'][:6]);sys.stdout.flush();time.sleep(5)",.05))
        for name,program,budget in cases:
            with self.subTest(case=name):exercise(adapter,program=program,budget=budget)

    def test_actual_two_stream_duplex_remains_bounded_before_input_consumed(self):
        with self.fixture() as case:
            code="import os,sys;os.write(1,b'A'*60000);os.write(2,b'B'*60000);raw=sys.stdin.buffer.read();assert raw==b'P'*100000"
            process=case.original_popen([sys.executable,'-I','-B','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            import time
            outcome,code,out,err=adapter._public_exchange(process,b'P'*100000,time.monotonic()+5)
            self.assertEqual(('completed',0), (outcome,code));self.assertEqual(b'A'*60000,out);self.assertEqual(b'B'*60000,err)
            self.assertTrue(all(getattr(process,n).closed for n in ('stdin','stdout','stderr')))

    def test_actual_local_writer_keeps_kernel_file_limit(self):
        with self.fixture() as case:
            path=case.controller/'bounded-writer'
            with path.open('wb') as stream:
                result=case.original_popen([sys.executable,'-I','-B','-c',
                    'import os;os.write(1,b"X"*70000);os.write(1,b"Y")'],
                    stdout=stream,stderr=subprocess.DEVNULL,preexec_fn=adapter._client_limit)
                result.wait(timeout=5)
            self.assertNotEqual(0,result.returncode);self.assertEqual(adapter.MAX_REPLY,path.stat().st_size)


if __name__=='__main__':unittest.main()
