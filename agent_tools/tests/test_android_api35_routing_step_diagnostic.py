"""Fixed generated diagnostic, harmless process tests only; no native actions."""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import io
import subprocess
import sys
import time
import unittest
from unittest import mock
from agent_tools import android_api35_routing_step_diagnostic as diag
from agent_tools.tests import test_android_api35_coldboot_product_observation as original_tests

ROOT=Path(__file__).resolve().parents[2]


def scope():
    nodes=[n for n in ast.parse(diag.original._GETTER).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))and getattr(n,'name',None)not in {'getter_bounded','current_getter','observed_getter'}]
    nodes += [n for n in ast.parse(diag._MEASUREMENT).body if isinstance(n,ast.FunctionDef)]
    env=dict(os=os,time=time,subprocess=subprocess,pathlib=__import__('pathlib'),re=re,json=json,hashlib=hashlib,__PRIOR_SHA__=diag.PRIOR_SHA,ROUTING_OWNER=diag.OWNER,ROUTING_OUTER_SECONDS=.5,GETTER_RECORDS={},GETTER={'cli':'/fixed/cli','packageSha256':diag.original.APK})
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-routing-measurement>','exec'),env)
    return env


class RoutingTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'diag')

    def argv(self):return ['/fixed/cli','--json','--android','--serial','emulator-5682','--timeout-seconds','30','--controller-id',diag.OWNER,'routing','show']

    def launch(self,code,*,ready=None,startup_delay=0):
        # POSIX setup readiness consumes no measured stdout/stderr bytes.
        modes=(None,'stderr-readable','parent-exited','parent-exited-pipe-open','parent-exited-pipe-open-refusal')
        if ready not in modes:raise AssertionError('unknown owned child readiness mode')
        if ready is not None and os.name!='posix':raise ValueError('routing_fixture_posix_required')
        if type(startup_delay) not in (int,float) or startup_delay not in (0,.2):
            raise AssertionError('unknown controlled fixture startup delay')
        original=subprocess.Popen
        def run(*a,**kw):
            gate=[];readers={};process=None;record={'ready':ready,'captureFailures':[],'cleanup':{}}
            if not hasattr(self,'_routing_fixture_evidence'):self._routing_fixture_evidence=[]
            self._routing_fixture_evidence.append(record)
            def release_gate():
                if gate:
                    fd=gate.pop()
                    try:os.write(fd,b'R')
                    except BrokenPipeError:pass
                    finally:os.close(fd)
            def close_owned():
                # unittest retains this cleanup outcome separately from any
                # primary test/setup assertion. Drain both held readers even
                # if one EOF observation fails, preserving every raw prefix.
                failures=[]
                try:release_gate()
                except Exception as error:failures.append('gate:'+repr(error))
                if process is not None:
                    try:
                        if process.poll() is None:process.kill()
                        record['cleanupReturnCode']=process.wait(timeout=2)
                    except Exception as error:failures.append('child:'+repr(error))
                    for name,stream in (('stdout',process.stdout),('stderr',process.stderr)):
                        try:
                            if not stream.closed:stream.close()
                        except Exception as error:failures.append(name+'-close:'+repr(error))
                for name,fd in list(readers.items()):
                    raw=b'';eof=False;failure=None;deadline=time.monotonic()+2
                    try:
                        while True:
                            remaining=deadline-time.monotonic()
                            if remaining<=0 or not select.select([fd],[],[],remaining)[0]:
                                raise AssertionError('owned '+name+' pipe did not reach EOF after release')
                            part=os.read(fd,min(4096,1048577-len(raw)))
                            if not part:eof=True;break
                            raw+=part
                            if len(raw)>1048576:raise AssertionError('owned '+name+' cleanup output bound')
                    except Exception as error:
                        failure=repr(error);failures.append(name+':'+failure)
                    finally:
                        os.close(fd);readers.pop(name,None)
                        record['cleanup'][name]={'eof':eof,'rawBase64':base64.b64encode(raw).decode(),'failure':failure}
                if failures:raise AssertionError('owned fixture cleanup incomplete: '+json.dumps({'failures':failures,'evidence':record},sort_keys=True))
            self.addCleanup(close_owned)
            body=code;inherited=();ready_read=ready_write=release_read=None
            negative=ready=='parent-exited-pipe-open-refusal'
            try:
                if ready in ('parent-exited-pipe-open','parent-exited-pipe-open-refusal'):
                    parsed=ast.parse(code)
                    if (len(parsed.body)!=2 or not isinstance(parsed.body[0],ast.Import)
                            or not isinstance(parsed.body[1],ast.Expr)):
                        raise AssertionError('owned descendant source changed')
                    call=parsed.body[1].value
                    expected=ast.parse("subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(.12)'])").body[0].value
                    if ast.dump(call)!=ast.dump(expected):raise AssertionError('owned descendant argv changed')
                    release_read,release_write=os.pipe();ready_read,ready_write=os.pipe();gate.append(release_write)
                    inner=call.args[0].elts[-1].value
                    prefix="sys.stderr.buffer.write(b'owned-descendant-prefix\\xff');sys.stderr.flush()\n" if negative else ''
                    gated=("import os,select,sys\n"+prefix
                           +f"os.write({ready_write},b'R')\n"
                           +f"if not select.select([{release_read}],[],[],15)[0]:sys.exit(24)\n"
                           +f"if os.read({release_read},1)!=b'R':sys.exit(25)\n"+inner)
                    call.args[0].elts[-1]=ast.Constant(gated)
                    call.keywords.append(ast.keyword(arg='pass_fds',value=ast.Tuple(elts=[ast.Constant(release_read),ast.Constant(ready_write)],ctx=ast.Load())))
                    if negative:parsed.body.append(ast.Raise(exc=ast.Call(func=ast.Name(id='SystemExit',ctx=ast.Load()),args=[ast.Constant(23)],keywords=[]),cause=None))
                    body=ast.unparse(ast.fix_missing_locations(parsed));inherited=(release_read,ready_write)
                if startup_delay:body='import time;time.sleep('+repr(startup_delay)+')\n'+body
                options=dict(stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                if inherited:options['pass_fds']=inherited
                process=original([sys.executable,'-I','-c',body],**options);record['pid']=process.pid
                # Reader custody starts at creation, including setup refusals.
                readers['stdout']=os.dup(process.stdout.fileno());readers['stderr']=os.dup(process.stderr.fileno())
                if release_read is not None:os.close(release_read);release_read=None
                if ready_write is not None:os.close(ready_write);ready_write=None
                if ready=='stderr-readable':
                    if not select.select([process.stderr],[],[],2)[0] or process.poll() is not None:
                        raise AssertionError('owned stderr fixture not ready')
                elif ready in ('parent-exited','parent-exited-pipe-open','parent-exited-pipe-open-refusal'):
                    if ready_read is not None:
                        if not select.select([ready_read],[],[],2)[0] or os.read(ready_read,1)!=b'R':
                            raise AssertionError('owned descendant holder not ready')
                    if process.wait(timeout=2)!=0:raise AssertionError('owned parent did not exit successfully')
                    if ready=='parent-exited-pipe-open' and select.select([process.stdout],[],[],0)[0]:
                        raise AssertionError('owned descendant pipe was already readable')
                return process
            except BaseException as primary:
                if process is not None:
                    try:
                        if process.poll() is None:process.kill()
                        stdout,stderr=process.communicate(timeout=.05 if negative else 2)
                        record['refusalCapture']={'complete':True,'stdoutBase64':base64.b64encode(stdout).decode(),'stderrBase64':base64.b64encode(stderr).decode(),'returnCode':process.returncode}
                    except subprocess.TimeoutExpired as capture:
                        record['captureFailures'].append({'type':'TimeoutExpired','stdoutBase64':base64.b64encode(capture.output or b'').decode(),'stderrBase64':base64.b64encode(capture.stderr or b'').decode(),'eofClaim':False})
                    except BaseException as capture:
                        record['captureFailures'].append({'type':type(capture).__name__,'repr':repr(capture),'eofClaim':False})
                primary.add_note('owned child startup evidence='+json.dumps(record,sort_keys=True))
                raise
            finally:
                for fd in (release_read,ready_read,ready_write):
                    if fd is not None:os.close(fd)
        return run

    @unittest.skipUnless(os.name=='posix','actual emitted diagnostic reads POSIX pipes and inherits file descriptors')
    def test_actual_old_outer_deadline_loses_finite_inner_timeout_new_retains(self):
        # Scaled startup .08 + inner .08 requires >.10 outer. The public
        # deadline starts after launcher startup, so equal budgets lose it.
        code="import time;time.sleep(.08);time.sleep(.08);print('{\"code\":\"TIMEOUT\"}')"
        env=scope();old=next(n for n in ast.parse(diag.original._GETTER).body if isinstance(n,ast.FunctionDef)and n.name=='getter_bounded')
        exec(compile(ast.Module(body=[old],type_ignores=[]),'<consumed-outer-deadline>','exec'),env)
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)),self.assertRaisesRegex(ValueError,'getter_command_timeout'):env['getter_bounded'](self.argv(),1,{},timeout=.10)
        self.assertEqual('',env['GETTER_RECORDS']['lastBoundedCommand']['stdoutRaw'])
        env=scope();env['ROUTING_OUTER_SECONDS']=.3
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)):
            result=env['getter_bounded'](self.argv(),1,{},timeout=.10)
        self.assertEqual({'code':'TIMEOUT'},json.loads(result['stdoutRaw']))
        self.assertEqual('terminal_collected',env['GETTER_RECORDS']['routingMeasurement']['classification'])
        self.assertTrue(env['GETTER_RECORDS']['routingMeasurement']['stdoutEof'])

    @unittest.skipUnless(os.name=='posix','real pipe readiness and inherited-descriptor fixture require POSIX')
    def test_live_child_and_exact_partial_bytes_retained_before_owned_kill(self):
        env=scope();env['ROUTING_OUTER_SECONDS']=.05
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch("import sys,time;sys.stderr.buffer.write(b'notice\\xff');sys.stderr.flush();time.sleep(3)",ready='stderr-readable')),self.assertRaisesRegex(ValueError,'getter_command_timeout'):
            env['getter_bounded'](self.argv(),1,{})
        record=env['GETTER_RECORDS']['routingPartial'];self.assertEqual(b'notice\xff',base64.b64decode(record['stderrBase64']))
        measurement=env['GETTER_RECORDS']['routingMeasurement'];self.assertEqual('child_live_at_outer_deadline',measurement['classification']);self.assertIsNone(measurement['exitCode']);self.assertFalse(measurement['stdoutEof'])

    @unittest.skipUnless(os.name=='posix','real pipe readiness and inherited-descriptor fixture require POSIX')
    def test_exited_parent_with_descendant_held_pipe_is_distinct(self):
        env=scope();env['ROUTING_OUTER_SECONDS']=.05
        # A harmless short-lived descendant holds stdout; no persistent job.
        code="import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(.12)'])"
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code,ready='parent-exited-pipe-open')),self.assertRaises(ValueError):env['getter_bounded'](self.argv(),1,{})
        self.assertEqual('child_exited_pipe_open',env['GETTER_RECORDS']['routingMeasurement']['classification'])


    @unittest.skipUnless(os.name=='posix','real pipe readiness and inherited-descriptor fixture require POSIX')
    def test_original_short_lived_descendant_still_closes_naturally(self):
        code="import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(.12)'])"
        process=self.launch(code,ready='parent-exited')()
        stdout,stderr=process.communicate(timeout=2)
        self.assertEqual(0,process.returncode);self.assertEqual((b'',b''),(stdout,stderr))


    def test_routing_source_serial_owner_or_timeout_change_before_process(self):
        for index,value in ((0,'/foreign'),(4,'old-serial'),(6,'45'),(8,'foreign')):
            args=self.argv();args[index]=value;env=scope()
            with mock.patch.object(subprocess,'Popen')as launch,self.assertRaises(ValueError):env['getter_bounded'](args,1,{})
            launch.assert_not_called()

    def guarded(self):
        env=scope();calls=[]
        env['getter_stage']=lambda:{'exact':'stage'};env['getter_generation']=lambda _:calls.append('generation')
        env['getter_apk']=lambda:diag.original.APK
        def cli(words,owner):
            calls.append(tuple(words));return {'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':diag.OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[],'routing':{}}}}
        env['getter_cli']=cli;return env,calls

    def test_one_routing_only_closing_guards_diagnostic_no_admission(self):
        env,calls=self.guarded();result=env['observed_getter'](Path('/fixed'))
        self.assertEqual(1,calls.count(('routing','show')));self.assertTrue(result['closingGuardsVerified']);self.assertIs(result['productAdmitted'],False);self.assertIs(result['acceptanceComplete'],False)
        self.assertNotIn('routingAfter',result['records'])

    def test_timeout_keeps_measurement_and_closes_guards_no_replay(self):
        env,calls=self.guarded();original=env['getter_cli']
        def cli(words,owner):
            if words==['routing','show']:
                calls.append(tuple(words));env['GETTER_RECORDS']['routingPartial']={'stdoutBase64':'','stderrBase64':''};raise ValueError('getter_command_timeout')
            return original(words,owner)
        env['getter_cli']=cli;result=env['observed_getter'](Path('/fixed'))
        self.assertTrue(result['closingGuardsVerified']);self.assertIn('routingPartial',result['records']);self.assertEqual(1,calls.count(('routing','show')))

    def test_owner_revision_runtime_operations_apk_stage_closing_drift(self):
        for mutation in ('owner','revision','runtime','operations','apk','stage','generation'):
            env,calls=self.guarded();original=env['getter_cli']
            def cli(words,owner):
                value=original(words,owner)
                if mutation=='owner':value['stdout']['controllerId']='foreign'
                if mutation=='revision':value['stdout']['configurationRevision']=1
                if mutation=='runtime':value['stdout']['data']['runtimeRunning']=True
                if mutation=='operations':value['stdout']['data']['operations']=[{'final':True}]
                return value
            env['getter_cli']=cli
            if mutation=='apk':env['getter_apk']=lambda:'f'*64
            if mutation=='stage':rows=iter([{'a':1},{'a':2}]);env['getter_stage']=lambda:next(rows)
            if mutation=='generation':env['getter_generation']=lambda _:(_ for _ in ()).throw(ValueError('getter_generation_changed'))
            result=env['observed_getter'](Path('/fixed'));self.assertFalse(result['closingGuardsVerified']);self.assertIs(result['productAdmitted'],False)
            if mutation not in ('stage',):self.assertNotIn(('routing','show'),calls)

    def test_current_private_original_composition_and_authority_mutations(self):
        self.assertTrue((ROOT/diag.PRIOR).exists(),'owned synthetic historical fixture is incomplete')
        reservation=original_tests.CompositionTests().reservation();prepared=diag.prepare(ROOT,reservation)
        diag.original.validate_readonly(prepared['program']);self.assertLess(len(diag.ssh_carrier(prepared)),131072)
        self.assertNotIn('def current_getter(',prepared['program']);self.assertIn('ROUTING_OUTER_SECONDS=45',prepared['program'])
        original=diag.availability._snapshot
        for path in (Path(diag.original.__file__).absolute(),ROOT/diag.PRIOR):
            def changed(candidate):
                pin,raw=original(candidate);return pin,raw+b' ' if Path(candidate)==path else raw
            with mock.patch.object(diag.availability,'_snapshot',side_effect=changed),self.assertRaises(ValueError):diag.prepare(ROOT,reservation)


class ReadinessRegressionTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','real pipe readiness and inherited-descriptor fixture require POSIX')
    def test_controlled_startup_same_original_assertions_need_ready_fixture(self):
        path=Path(__file__).parent/'fixtures/android_routing_readiness/launch_and_cases.before.source'
        raw=path.read_bytes();metadata=json.loads(path.with_name('provenance.json').read_text())
        expected='94547a8fffccbce08e0a6ed95f2898abea3c1c6b73620ff5345b9476f9140fad'
        self.assertEqual(expected,hashlib.sha256(raw).hexdigest());self.assertEqual(expected,metadata['fragmentSha256'])
        self.assertEqual(len(raw),metadata['fragmentBytes'])
        namespace=dict(globals());exec(compile(raw,str(path),'exec'),namespace)
        methods=('test_live_child_and_exact_partial_bytes_retained_before_owned_kill','test_exited_parent_with_descendant_held_pipe_is_distinct')
        class BoundaryResult(unittest.TextTestResult):
            def addFailure(result,case,error):
                if not hasattr(result,'boundaryFailures'):result.boundaryFailures=[]
                frames=[];tb=error[2]
                while tb is not None:
                    frames.append((tb.tb_frame.f_code.co_filename,tb.tb_frame.f_code.co_name,tb.tb_lineno));tb=tb.tb_next
                result.boundaryFailures.append({'method':case._testMethodName,'type':error[0],'args':error[1].args,'frames':frames})
                super().addFailure(case,error)
        original_scope=scope
        for fixed in (False,True):
            definitions={} if fixed else {name:namespace[name] for name in methods}
            case_type=type('ControlledRoutingReadyFixture',(RoutingTests,),definitions)
            def launch(case,code,*,ready=None):
                if fixed:return RoutingTests.launch(case,code,ready=ready,startup_delay=.2)
                return namespace['launch'](case,'import time;time.sleep(.2)\n'+code)
            case_type.launch=launch
            for method in methods:
                with self.subTest(fixed=fixed,method=method):
                    captured=[]
                    def measured_scope():
                        value=original_scope();captured.append(value);return value
                    namespace['scope']=measured_scope
                    stream=io.StringIO()
                    with mock.patch.dict(globals(),{'scope':measured_scope}):
                        result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=BoundaryResult).run(case_type(method))
                    # Emit the actual inner before/fix streams to ordinary runner
                    # retention, including original assertions and operands.
                    print('ROUTING_FIXTURE_CAUSAL '+json.dumps({'fixed':fixed,'method':method,'stream':stream.getvalue()},sort_keys=True))
                    self.assertEqual(1,result.testsRun);self.assertEqual([],result.errors);self.assertEqual([],result.skipped)
                    self.assertEqual(1,len(captured));records=captured[0]['GETTER_RECORDS'];measurement=records['routingMeasurement']
                    self.assertEqual(.05,measurement['outerTimeoutSeconds']);self.assertEqual(30,measurement['publicTimeoutSeconds'])
                    if fixed:
                        self.assertTrue(result.wasSuccessful(),stream.getvalue())
                        if method==methods[0]:
                            self.assertEqual(b'notice\xff',base64.b64decode(records['routingPartial']['stderrBase64']))
                            self.assertEqual('child_live_at_outer_deadline',measurement['classification'])
                        else:self.assertEqual('child_exited_pipe_open',measurement['classification'])
                    else:
                        self.assertEqual(1,len(result.failures),stream.getvalue());fact=result.boundaryFailures[0]
                        self.assertIs(AssertionError,fact['type']);self.assertEqual(method,fact['method'])
                        target=b'notice\xff' if method==methods[0] else 'child_exited_pipe_open'
                        function=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name==method)
                        assertion=next(n for n in ast.walk(function) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='assertEqual' and isinstance(n.args[0],ast.Constant) and n.args[0].value==target)
                        self.assertIn((str(path),method,assertion.lineno),fact['frames'])
                        message="b'notice\\xff' != b''" if method==methods[0] else "'child_exited_pipe_open' != 'child_live_at_outer_deadline'\n- child_exited_pipe_open\n+ child_live_at_outer_deadline\n"
                        self.assertEqual((message,),fact['args'])
                        self.assertEqual('',records['routingPartial']['stderrBase64'])
                        self.assertEqual('child_live_at_outer_deadline',measurement['classification']);self.assertIsNone(measurement['exitCode'])


    @unittest.skipUnless(os.name=='posix','real pipe readiness and inherited-descriptor fixture require POSIX')
    def test_failed_ready_setup_keeps_real_raw_reply_and_closes_owned_child(self):
        children=[]
        class OwnedRefusalCase(RoutingTests):
            def runTest(case):
                original=subprocess.Popen
                def remember(*args,**kwargs):
                    process=original(*args,**kwargs);children.append(process);return process
                with mock.patch.object(subprocess,'Popen',side_effect=remember):
                    launch=case.launch("import sys;sys.stderr.buffer.write(b'owned-startup-failure');sys.exit(23)",ready='parent-exited')
                    with case.assertRaisesRegex(AssertionError,'owned parent did not exit successfully') as failure:launch()
                case.assertEqual(1,len(children));case.assertEqual(23,children[0].poll())
                capture=case._routing_fixture_evidence[0]['refusalCapture']
                case.assertTrue(capture['complete']);case.assertEqual(23,capture['returnCode'])
                case.assertEqual(b'owned-startup-failure',base64.b64decode(capture['stderrBase64']))
                case.assertIn('refusalCapture',' '.join(failure.exception.__notes__))
        stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(OwnedRefusalCase())
        self.assertTrue(result.wasSuccessful(),stream.getvalue())
        self.assertTrue(children[0].stdout.closed);self.assertTrue(children[0].stderr.closed)
        self.assertEqual(23,children[0].wait(timeout=2))

    def test_ready_modes_reject_non_posix_before_any_child(self):
        case=RoutingTests('test_original_short_lived_descendant_still_closes_naturally')
        with mock.patch.object(os,'name','nt'),mock.patch.object(subprocess,'Popen') as launch:
            for ready in ('stderr-readable','parent-exited','parent-exited-pipe-open','parent-exited-pipe-open-refusal'):
                with self.assertRaisesRegex(ValueError,'routing_fixture_posix_required'):case.launch('unused',ready=ready)
            launch.assert_not_called()

    @unittest.skipUnless(os.name=='posix','real pipe readiness and inherited-descriptor fixture require POSIX')
    def test_original_assertion_and_real_eof_cleanup_failure_are_both_retained(self):
        observed={};patcher=mock.patch.object(select,'select',return_value=([],[],[]))
        class FailedOwnedCase(RoutingTests):
            def runTest(case):
                case.addCleanup(patcher.stop)
                code="import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(.12)'])"
                process=case.launch(code,ready='parent-exited-pipe-open')()
                # A second owned observation reader closes the original holder
                # after deliberately refusing the helper's EOF cleanup check.
                observed['fd']=os.dup(process.stdout.fileno())
                patcher.start()
                case.fail('controlled original measurement assertion')
        stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(FailedOwnedCase())
        try:
            self.assertEqual([],result.errors);self.assertEqual(2,len(result.failures),stream.getvalue())
            self.assertIn('controlled original measurement assertion',stream.getvalue())
            self.assertIn('owned stdout pipe did not reach EOF after release',stream.getvalue())
            fd=observed['fd'];self.assertTrue(select.select([fd],[],[],2)[0]);self.assertEqual(b'',os.read(fd,4096))
        finally:
            patcher.stop()
            if 'fd' in observed:os.close(observed['fd'])

    @unittest.skipUnless(os.name=='posix','real descendant-held pipes and inherited descriptors require POSIX')
    def test_descendant_held_pipe_refusal_preserves_primary_capture_prefix_and_eof(self):
        observed={}
        class OwnedRefusalCase(RoutingTests):
            def runTest(case):
                code="import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(.12)'])"
                with case.assertRaisesRegex(AssertionError,'owned parent did not exit successfully') as failure:
                    case.launch(code,ready='parent-exited-pipe-open-refusal')()
                evidence=case._routing_fixture_evidence[0];observed['evidence']=evidence
                case.assertEqual(1,len(evidence['captureFailures']));capture=evidence['captureFailures'][0]
                case.assertEqual('TimeoutExpired',capture['type']);case.assertIs(False,capture['eofClaim'])
                case.assertEqual(b'owned-descendant-prefix\xff',base64.b64decode(capture['stderrBase64']))
                case.assertIn('TimeoutExpired',' '.join(failure.exception.__notes__))
        stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(OwnedRefusalCase())
        self.assertTrue(result.wasSuccessful(),stream.getvalue());evidence=observed['evidence']
        self.assertEqual(23,evidence['cleanupReturnCode'])
        self.assertTrue(evidence['cleanup']['stdout']['eof']);self.assertTrue(evidence['cleanup']['stderr']['eof'])


if __name__=='__main__':unittest.main()
