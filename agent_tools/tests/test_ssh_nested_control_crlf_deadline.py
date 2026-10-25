"""Actual local OpenSSH control check outlasting the old 5 s case deadline; owned wrapper, no TCP, VM or SSH host.

In managed pre-push run 5 the real /usr/bin/ssh -F /dev/null -S <owned absent socket> -O check child (milliseconds
when idle) did not close its streams within the case's 5 s observation deadline, so the unfixed case's capture was
unfinished, the beforeimage's _failure() returned 'unavailable' and the case failed with 'AdapterBlocked not raised'.
On this directory-bound host ssh's service lookup waits for opendirectoryd, whose directory reconnect times out
after 10 s. Here only that exact launch is replaced, by an owned wrapper that records itself, sleeps past that stall
and then execs the real /usr/bin/ssh in the same process with the same arguments, streams and environment.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,os,subprocess,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools.tests import test_ssh_nested_control_crlf as current

BEFORE=Path(__file__).parent/'fixtures/ssh_nested_control_crlf_deadline/test_ssh_nested_control_crlf.py.before.source'
PROVENANCE=Path(__file__).parent/'fixtures/ssh_nested_control_crlf_deadline/provenance.json'
BEFORE_SHA256='db7b8b58c4cb35d0a471662cf5bb318a28fce602a0ab3251be815fcf228bbdf0'
ORIGINAL='test_actual_openssh_absent_socket_full_before_red_fixed_green'
OLD_BOUND_SECONDS=5
STALL_SECONDS=10  # Observed opendirectoryd reconnect timeout that held ssh's service lookup.
# Fixed stand-in for that stall: past it and the old bound, far inside the fixed one.
DELAY_SECONDS=STALL_SECONDS+1
CONTROL=(('/usr/bin/ssh','-F','/dev/null','-S'),('-O','check','public-local-no-network'))
WRAPPER=("import os,sys,time\n"
         "with open(sys.argv[1],'a') as record:record.write(str(os.getpid())+'\\n')\n"
         "time.sleep(float(sys.argv[2]));os.execv(sys.argv[3],sys.argv[3:])\n")


def slow_control(record,launched):
    """Popen stand-in: only a case's exact control check goes through the owned delaying wrapper."""
    actual=subprocess.Popen
    def popen(argv,*args,**kwargs):
        if not isinstance(argv,(list,tuple))or len(argv)!=8 or (tuple(argv[:4]),tuple(argv[5:]))!=CONTROL:return actual(argv,*args,**kwargs)
        child=actual([sys.executable,'-I','-c',WRAPPER,str(record),str(DELAY_SECONDS),*argv],*args,**kwargs)
        launched.append((argv[4],child));return child
    return popen


@unittest.skipUnless(os.name=='posix'and Path('/usr/bin/ssh').is_file(),'requires actual local OpenSSH control observer')
class ControlCheckDeadlineTests(unittest.TestCase):
    def before(self):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__+'.ExactNestedControl.'+ORIGINAL,provenance['originalFailureTestId'])
        module=types.ModuleType('_ssh_nested_control_crlf_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(BEFORE),'exec',dont_inherit=True),module.__dict__)
        return module

    @staticmethod
    def run_case(implementation):
        case=implementation.ExactNestedControl(ORIGINAL);result=unittest.TestResult();started=time.monotonic()
        case.run(result);return case,result,time.monotonic()-started

    def test_unfixed_deadline_red_on_slow_control_check_and_fixed_bound_green(self):
        provenance=json.loads(PROVENANCE.read_bytes());trace=provenance['originalFailureTrace']
        self.assertEqual(provenance['originalFailureTraceSha256'],hashlib.sha256(('\n'.join(trace)+'\n').encode()).hexdigest())
        unfixed=self.before();launched=[]
        with tempfile.TemporaryDirectory(prefix='vct-crlf-deadline-') as temporary:
            record=Path(temporary)/'launches'
            try:
                # Both actual cases at once: the unfixed one ends at its 5 s deadline while the fixed one waits.
                with mock.patch.object(subprocess,'Popen',slow_control(record,launched)),ThreadPoolExecutor(2) as pool:
                    (old_case,old,old_elapsed),(case,new,elapsed)=[f.result() for f in [pool.submit(self.run_case,m) for m in (unfixed,current)]]
                recorded=set(record.read_text().split()) if record.exists() else set()
            finally:
                for _,child in launched:  # Owned wrappers, or the real ssh one became; normally reaped by their collector.
                    if child.poll() is None:child.kill()
                    child.wait(timeout=30)
        launches={}
        for path,child in launched:launches.setdefault(path,[]).append((child.returncode,str(child.pid)in recorded))
        # Unfixed: the original statement fails with the original message at its own 5 s deadline, and its one
        # control check was stopped there, before the wrapper could become the real ssh.
        self.assertEqual((1,1,0,0),(old.testsRun,len(old.failures),len(old.errors),len(old.skipped)),''.join(t for _,t in old.failures+old.errors))
        failure=old.failures[0][1].splitlines()
        self.assertIn('  File "%s", %s'%(BEFORE,trace[4].split('", ',1)[1]),failure)
        self.assertIn(trace[5],failure);self.assertEqual(trace[-1],failure[-1])
        self.assertGreaterEqual(old_elapsed,OLD_BOUND_SECONDS)
        self.assertEqual(1,len(launches[str(old_case.anchor.remote_control_path)]))
        self.assertLess(launches[str(old_case.anchor.remote_control_path)][0][0],0)
        # Fixed: both actual observations outwait the delay and judge the real rc 255 CRLF answer exactly.
        self.assertEqual((1,0,0,0),(new.testsRun,len(new.failures),len(new.errors),len(new.skipped)),''.join(t for _,t in new.failures+new.errors))
        self.assertEqual([(255,True),(255,True)],launches[str(case.anchor.remote_control_path)])
        self.assertGreaterEqual(elapsed,2*DELAY_SECONDS)
        self.assertEqual(2,len(launches))


if __name__=='__main__':
    unittest.main()
