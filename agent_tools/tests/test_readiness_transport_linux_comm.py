"""Whole-before RED/GREEN for the daemonization case under Linux process-name semantics.

Fast Checks run 40187427911 (ubuntu-latest, CPython 3.12) failed the unfixed
test_preserved_implicit_daemonization_cannot_authorize_replacement with
'MasterUnknown not raised'. Its fixture daemon is a forked process of the inert
'ssh' peer script, launched through its '#!' interpreter. Linux names such a
process after the executed script ('ssh' in ps comm), Darwin after the
interpreter, so only on Linux does the production actor rule prove it an SSH
executable and reconcile the original daemon instead of refusing it. Here only
/bin/ps comm answers are given the Linux rule on every host; the production
reconciliation, sockets and fixture processes stay actual. No VM, SSH host or
network is involved.
"""
import hashlib,json,os,subprocess,sys,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools.tests import test_readiness_transport as current

FIXTURES=Path(__file__).parent/'fixtures/readiness_transport_linux_comm'
BEFORE=FIXTURES/'test_readiness_transport.py.before.source'
PROVENANCE=FIXTURES/'provenance.json'
BEFORE_SHA256='7d0795aee26bf2e958eda8c34963d052520df2e3dc4e02846273603a5c6b484f'
ORIGINAL='test_preserved_implicit_daemonization_cannot_authorize_replacement'
TASK_COMM_BYTES=15  # Linux TASK_COMM_LEN less its terminating NUL.


def linux_comm(pid,run):
    """Linux comm: basename of the executed file, the script for a '#!' launch."""
    args=run(['/bin/ps','-p',str(pid),'-o','args='],stdin=subprocess.DEVNULL,capture_output=True,timeout=3).stdout.decode().split()
    executable=run(['/bin/ps','-p',str(pid),'-o','comm='],stdin=subprocess.DEVNULL,capture_output=True,timeout=3).stdout.decode().strip()
    if len(args)>1 and os.path.basename(args[0]).lower().startswith('python') and os.path.isfile(args[1]):
        with open(args[1],'rb') as script:
            if script.read(2)==b'#!':return os.path.basename(args[1])[:TASK_COMM_BYTES]
    return os.path.basename(executable)[:TASK_COMM_BYTES]


def linux_ps(observed):
    """subprocess.run stand-in: only /bin/ps comm answers follow the Linux rule."""
    actual=subprocess.run
    def run(argv,*args,**kwargs):
        result=actual(argv,*args,**kwargs)
        if not(isinstance(argv,list)and argv[:2]==['/bin/ps','-p']and argv[-1]=='comm='and result.returncode==0 and result.stdout.strip()):
            return result
        comm=linux_comm(int(argv[2]),actual)
        # The production format keeps uid and the five lstart words before comm.
        words=result.stdout.decode().split()[:6]if 'lstart='in argv else []
        observed.append((int(argv[2]),tuple(word for word in argv[3:]if word!='-o'),comm))
        return subprocess.CompletedProcess(result.args,0,(' '.join([*words,comm])+'\n').encode(),result.stderr)
    return run


@unittest.skipUnless(os.name=='posix','POSIX owned control socket')
class LinuxCommRegression(unittest.TestCase):
    def before(self):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__+'.ReadinessTransportTests.'+ORIGINAL,provenance['originalFailureTestId'])
        # Its fixture paths resolve beside the current module, as in the original run.
        module=types.ModuleType('_readiness_transport_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(BEFORE),'exec',dont_inherit=True),module.__dict__)
        return module

    @staticmethod
    def run_case(implementation):
        case=implementation.ReadinessTransportTests(ORIGINAL);result=unittest.TestResult();case.run(result);return result

    def test_unfixed_red_and_fixed_green_under_linux_comm(self):
        provenance=json.loads(PROVENANCE.read_bytes());trace=provenance['originalFailureTrace']
        self.assertEqual(provenance['originalFailureTraceSha256'],hashlib.sha256(('\n'.join(trace)+'\n').encode()).hexdigest())
        unfixed=self.before();observed=[]
        with mock.patch.object(subprocess,'run',linux_ps(observed)):
            old=self.run_case(unfixed)
            old_rows=list(observed);observed.clear()
            new=self.run_case(current)
        details=lambda:'\n'.join(text for _,text in old.failures+old.errors+new.failures+new.errors)+'\nobserved=%r/%r'%(old_rows,observed)
        # Unfixed: the original statement fails with the original message once the
        # production actor rule has seen the daemon's Linux name.
        self.assertEqual((1,1,0,0),(old.testsRun,len(old.failures),len(old.errors),len(old.skipped)),details())
        failure=old.failures[0][1].splitlines()
        self.assertIn('  File "%s", %s'%(BEFORE,trace[4].split('", ',1)[1]),failure,details())
        self.assertIn(trace[5],failure,details());self.assertEqual(trace[-1],failure[-1],details())
        self.assertIn(('uid=','lstart=','comm=','ssh'),[(*fields,comm)for _,fields,comm in old_rows],details())
        # Fixed: the same production answer reconciles the original daemon, launches
        # nothing and keeps the original generation selected.
        self.assertEqual((1,0,0,0),(new.testsRun,len(new.failures),len(new.errors),len(new.skipped)),details())
        self.assertIn(('comm=','ssh'),[(*fields,comm)for _,fields,comm in observed],details())
        self.assertIn(('uid=','lstart=','comm=','ssh'),[(*fields,comm)for _,fields,comm in observed],details())

    def test_retained_whole_before_and_ci_evidence_custody(self):
        provenance=json.loads(PROVENANCE.read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        event=provenance['originalFailureEvent']
        self.assertEqual(('finished','failure',provenance['originalFailureTestId']),(event['event'],event['outcome'],event['publicTestId']))
        self.assertEqual(provenance['originalFailureEventSha256'],hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest())


if __name__=='__main__':unittest.main()
