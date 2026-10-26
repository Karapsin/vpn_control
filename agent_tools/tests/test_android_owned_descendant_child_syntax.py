"""Whole-before RED/GREEN for the owned-descendant Linux case's child program and timeout report.

Fast Checks run 40232090301 (ubuntu-24.04, CPython 3.12.15) failed the unfixed
test_actual_separate_session_descendants_reaped_and_flag_restored in 9 ms: its
'python -I -B -c' child exited 1 with 'SyntaxError: unterminated string literal
(detected at line 22)'. The case wrote that program in a non-raw triple-quoted
literal, so the escape child's newline pid terminator reached the child as a real
line break inside a one-line string. The interpreter compiles the whole program
before it runs any of it, so this failure precedes every Linux facility and is the
same on every host. Here the original case of the whole beforeimage and of the fix
hands its exact argv to the real interpreter: once unchanged, and once with only its
fixture argument replaced by an owned probe that reports and exits as soon as the
program runs. The program itself runs only on Linux, where the original case is the
CI confirmation. No subreaper, PIDfd, VM or native host is involved here.

Review of that fix found a second, latent defect: a child that outlived the
case's 8 s timeout failed it as a bare TimeoutExpired. The separate-session
sleepers that cleanup_selftest forks inherit the child's output pipes, so after a
refusal before they are killed the child's error stayed in the exception's captured
output, which unittest does not print, and no host facts were reported. The timeout
control runs the case's exact call under a real shortened timeout, with only its
fixture replaced by an owned probe whose separate-session descendant holds those
pipes until the control releases it.
"""
import hashlib,json,os,re,select,subprocess,sys,tempfile,traceback,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools.tests import test_android_launcher_version_source_snapshot as current

FIXTURES=Path(__file__).parent/'fixtures/android_owned_descendant_child_syntax'
BEFORE=FIXTURES/'test_android_launcher_version_source_snapshot.py.before.source'
PROVENANCE=FIXTURES/'provenance.json'
BEFORE_SHA256='a0de51cba5459cfffda68efbf472761b17d7ea7981f155e320e39e0d134096f3'
ORIGINAL='test_actual_separate_session_descendants_reaped_and_flag_restored'
PROBE_MARKER='OWNED_DESCENDANT_PROGRAM_RUNNING'
PROBE_SOURCE=("import json,os,sys\n"
              "print('"+PROBE_MARKER+"',json.dumps(sys.argv[1:]),flush=True)\n"
              "os._exit(0)\n")
ANSI=re.compile(r'\x1b\[[0-9;]*m')  # FORCE_COLOR still colours tracebacks under -I.
NON_RAW_PROGRAM=b'        code = """\nimport importlib.util,sys,os,pathlib,ctypes,signal,select,time,json\n'
REFUSAL='debugger_descendant_identity_unknown'
SHORT_TIMEOUT=2
# Stands in for a refusal after cleanup_selftest forks: the descendant keeps the
# inherited output pipes open until the control closes the release pipe, and its
# exit closes the alive pipe.
HOLDER_SOURCE=("OWNED_DESCENDANT_SOURCE='''\n"
               "held=os.fork()\n"
               "if held==0:\n"
               " os.setsid();os.read(%(release)d,1);os._exit(0)\n"
               "os.close(%(release)d);os.close(%(alive)d)\n"
               "raise ValueError('"+REFUSAL+"')\n"
               "'''\n")


class _ProgramObserved(Exception):
    """Stops the original case as soon as its child program has run."""


@unittest.skipUnless(os.name=='posix','The original case reports host facts through POSIX resource limits')
class GeneratedChildProgramRegression(unittest.TestCase):
    def provenance(self):
        provenance=json.loads(PROVENANCE.read_bytes());trace=provenance['originalFailureTrace']
        self.assertEqual(provenance['originalFailureTraceSha256'],hashlib.sha256(('\n'.join(trace)+'\n').encode()).hexdigest())
        return provenance,trace

    def before(self,raw_program=False):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__+'.OwnedDescendantLinuxTests.'+ORIGINAL,provenance['originalFailureTestId'])
        if raw_program:
            # Only the syntax fix, so the program runs and the beforeimage's own timeout path is reached.
            self.assertEqual(1,raw.count(NON_RAW_PROGRAM));raw=raw.replace(NON_RAW_PROGRAM,NON_RAW_PROGRAM.replace(b'"""',b'r"""',1))
            unfixed=provenance['timeoutDiagnostics']
            self.assertEqual((unfixed['unfixedSourceSha256'],unfixed['unfixedSourceBytes']),(hashlib.sha256(raw).hexdigest(),len(raw)))
        # Its fixture import and sibling paths resolve beside the current module, as in the original run.
        module=types.ModuleType('_android_launcher_snapshot_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(BEFORE),'exec',dont_inherit=True),module.__dict__)
        return module

    @staticmethod
    def original(implementation):
        # Called directly: the class's Linux-only skip guards facilities that the
        # original failure never reaches, since the child rejects the program first.
        return getattr(implementation.OwnedDescendantLinuxTests(ORIGINAL),ORIGINAL)

    def observe(self,implementation,probe):
        """The case's exact child argv, run by the real interpreter with only the fixture replaced."""
        actual=subprocess.run;calls=[]
        def run(argv,*args,**kwargs):
            calls.append((list(argv),args,dict(kwargs)))
            raise _ProgramObserved(actual([*argv[:5],str(probe),*argv[6:]],*args,**kwargs))
        with mock.patch.object(subprocess,'run',run):
            try:
                self.original(implementation)()
            except _ProgramObserved as observed:
                return calls,observed.args[0]
        self.fail('the original case launched no child program: calls=%r'%(calls,))

    def held_timeout(self,implementation,temporary,label):
        """The case's exact call under a real shortened timeout, with only its fixture replaced by a holder."""
        actual=subprocess.run;calls=[];error=None
        release,release_end=os.pipe();alive_end,alive=os.pipe()
        try:
            probe=Path(temporary).resolve()/('holder_%s.py'%label)
            probe.write_text(HOLDER_SOURCE%{'release':release,'alive':alive})
            def run(argv,*args,**kwargs):
                calls.append((list(argv),args,dict(kwargs)))
                return actual([*argv[:5],str(probe),*argv[6:]],*args,**{**kwargs,'timeout':SHORT_TIMEOUT,'pass_fds':(release,alive)})
            with mock.patch.object(subprocess,'run',run):
                try:
                    self.original(implementation)()
                except Exception as raised:
                    error=raised
        finally:
            for fd in (release,release_end,alive):os.close(fd)
            # Released, the holder exits and so closes the last write end of the alive pipe.
            gone=bool(select.select([alive_end],[],[],5)[0]) and os.read(alive_end,1)==b''
            os.close(alive_end)
        return calls,error,gone

    @staticmethod
    def expired(error):
        """The real run's TimeoutExpired: raised as is, or as the cause or context of the case's failure."""
        while error is not None and not isinstance(error,subprocess.TimeoutExpired):
            error=error.__cause__ or error.__context__
        return error

    def test_unfixed_original_case_fails_with_the_ci_syntax_error(self):
        _,trace=self.provenance();unfixed=self.before()
        try:
            self.original(unfixed)()
        except AssertionError as error:
            failure=error
        else:
            self.fail('the unfixed original case passed on %s with %s'%(sys.platform,sys.version))
        text=ANSI.sub('',str(failure));lines=text.split('\n')
        frames=[frame for frame in traceback.extract_tb(failure.__traceback__) if frame.filename==str(BEFORE)]
        details=lambda:'platform=%s python=%s\nframes=%r\nfailure=%s'%(sys.platform,sys.version,frames,text)
        # The original statement fails with the CI message: returncode 1, no output and
        # the child's complete compile error at program line 22; only host facts differ.
        self.assertEqual(trace[6:13],['AssertionError: '+lines[0],*lines[1:7]],details())
        self.assertEqual((8,'host={'),(len(lines),lines[-1][:6]),details())
        self.assertEqual([(314,ORIGINAL,trace[5].strip())],[(f.lineno,f.name,(f.line or '').strip())for f in frames],details())

    def test_exact_generated_program_unfixed_red_and_fixed_green(self):
        _,trace=self.provenance();unfixed=self.before()
        with tempfile.TemporaryDirectory() as temporary:
            probe=Path(temporary).resolve()/'probe_fixture.py';probe.write_text(PROBE_SOURCE)
            old_calls,old=self.observe(unfixed,probe)
            new_calls,new=self.observe(current,probe)
        show=lambda result:'returncode=%r\nstdout=%s\nstderr=%s'%(result.returncode,result.stdout.decode(errors='replace'),result.stderr.decode(errors='replace'))
        details=lambda:'platform=%s python=%s\nold_calls=%r\nold:\n%s\nnew_calls=%r\nnew:\n%s'%(sys.platform,sys.version,old_calls,show(old),new_calls,show(new))
        # Both cases launch one child with the same interpreter, flags, fixture and bounds.
        for calls in (old_calls,new_calls):
            self.assertEqual(1,len(calls),details());argv,args,kwargs=calls[0]
            self.assertEqual(([sys.executable,'-I','-B','-c'],[current.fixture.__file__],6,(),{'capture_output':True,'timeout':8}),
                             (argv[:4],argv[5:],len(argv),args,kwargs),details())
        before_program,fixed_program=old_calls[0][0][4],new_calls[0][0][4]
        # Unfixed: the real interpreter rejects the program before its first line runs.
        child_error=[trace[8].removeprefix('stderr='),*trace[9:12],'']
        self.assertEqual((1,b''),(old.returncode,old.stdout),details())
        self.assertEqual(child_error,ANSI.sub('',old.stderr.decode()).split('\n'),details())
        with self.assertRaises(SyntaxError) as raised:
            compile(before_program,'<string>','exec',dont_inherit=True)
        error=raised.exception
        self.assertEqual((22,trace[11].split(': ',1)[1],trace[9].strip()),(error.lineno,error.msg,(error.text or '').strip()),details())
        # Fixed: the same exact program compiles completely and runs up to its fixture load.
        self.assertEqual((0,(PROBE_MARKER+' '+json.dumps([str(probe)])+'\n').encode(),b''),(new.returncode,new.stdout,new.stderr),details())
        compile(fixed_program,'<string>','exec',dont_inherit=True)
        # The fix restores only the intended escape; every other program byte is unchanged.
        broken,intended="+'\n')","+'\\n')"
        self.assertEqual((1,0,1),(before_program.count(broken),fixed_program.count(broken),fixed_program.count(intended)),details())
        self.assertEqual(before_program.replace(broken,intended),fixed_program,details())

    def test_descendant_held_pipes_timeout_reports_child_error_and_host_facts(self):
        unfixed=self.before(raw_program=True)
        with tempfile.TemporaryDirectory() as temporary:
            old_calls,old,old_gone=self.held_timeout(unfixed,temporary,'unfixed')
            new_calls,new,new_gone=self.held_timeout(current,temporary,'fixed')
        old_expired,new_expired=self.expired(old),self.expired(new)
        report=lambda error:''.join(traceback.format_exception(type(error),error,error.__traceback__)) if error is not None else ''
        captured=lambda expired:'stdout=%s\nstderr=%s\nhost={'%((expired.stdout or b'').decode(errors='replace'),(expired.stderr or b'').decode(errors='replace'))
        facts=lambda error:[line for line in report(error).split('\n') if line.startswith('host={')]
        details=lambda:('platform=%s python=%s\nold_calls=%r\nold_gone=%r old_stderr=%r\nold_report:\n%s\n'
                        'new_calls=%r\nnew_gone=%r new_stderr=%r\nnew_report:\n%s')%(
            sys.platform,sys.version,old_calls,old_gone,getattr(old_expired,'stderr',None),report(old),
            new_calls,new_gone,getattr(new_expired,'stderr',None),report(new))
        # Both cases make the one call with the same program, interpreter, flags and bounds.
        for calls in (old_calls,new_calls):
            self.assertEqual(1,len(calls),details());argv,args,kwargs=calls[0]
            self.assertEqual(([sys.executable,'-I','-B','-c'],[current.fixture.__file__],6,(),{'capture_output':True,'timeout':8}),
                             (argv[:4],argv[5:],len(argv),args,kwargs),details())
        self.assertEqual(old_calls[0][0][4],new_calls[0][0][4],details())
        # Each real run times out after the child reported its refusal; the released holder exits.
        for expired,gone in ((old_expired,old_gone),(new_expired,new_gone)):
            self.assertIsInstance(expired,subprocess.TimeoutExpired,details())
            self.assertEqual(SHORT_TIMEOUT,expired.timeout,details())
            self.assertIn('ValueError: '+REFUSAL,ANSI.sub('',(expired.stderr or b'').decode(errors='replace')),details())
            self.assertTrue(gone,details())
        # Unfixed: the bare timeout hides what the child wrote and the host facts.
        self.assertIs(old,old_expired,details())
        self.assertEqual((False,False,[]),(REFUSAL in report(old),captured(old_expired) in report(old),facts(old)),details())
        # Fixed: the report carries the child's complete captured output and the host facts.
        self.assertIn(captured(new_expired),report(new),details())
        self.assertEqual(1,len(facts(new)),details())
        self.assertLessEqual({'release','python','uid','gid','groups','subreaper','status','childrenFile'},
                             set(json.loads(facts(new)[0][len('host='):])),details())

    def test_retained_whole_before_and_ci_evidence_custody(self):
        provenance,trace=self.provenance()
        self.assertEqual((False,False),(provenance['nativeFailureClaimed'],provenance['timeoutDiagnostics']['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        self.assertEqual('FAIL: %s (%s)'%(ORIGINAL,provenance['originalFailureTestId']),trace[1])
        for name in ('originalFailureEvent','earlierFailureEvent'):
            event=provenance[name]
            self.assertEqual(('finished','failure',provenance['originalFailureTestId']),(event['event'],event['outcome'],event['publicTestId']),name)
            self.assertEqual(provenance[name+'Sha256'],hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest(),name)


if __name__=='__main__':unittest.main()
