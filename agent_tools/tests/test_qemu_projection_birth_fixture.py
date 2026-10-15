"""Held-child fixture birth regression; Darwin is a Linux metadata model only."""
import ast
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest

from agent_tools.tests import test_windows_parallel_vm_prepare as subject

FIXTURE = Path(__file__).with_name('fixtures') / 'qemu_projection_birth'
BEFORE_SHA256 = 'beab62becfbb8b2e9947243ba5d2ec7c848bb91998480e6f1ef21d2c7d7cbad6'
ORIGINAL_TEST_SHA256 = 'f1f0287effa870e832103bc304c430425c461862fd352ddf9d67181c72637005'
_REAL_BIRTH = object()
_USE_BEFORE = False
CHILD_SOURCE = '''import json,os,select,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)
if fd!=9:
 os.dup2(fd,9)
 os.close(fd)
s=os.fstat(9)
row={'pid':os.getpid(),'fd':9,'generation':[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]}
os.write(1,json.dumps(row,sort_keys=True).encode()+b'\\n')
ready,unused,unused=select.select([sys.stdin],[],[],8)
if ready:os.read(0,32)
os.close(9)
'''


def _projection(before):
    raw = (FIXTURE / 'projection.before.fragment').read_bytes()
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    if (hashlib.sha256(raw).hexdigest() != BEFORE_SHA256
            or provenance['fragmentSha256'] != BEFORE_SHA256
            or provenance['originalTestSha256'] != ORIGINAL_TEST_SHA256):
        raise ValueError('projection-before-source')
    if before:
        node = ast.parse(textwrap.dedent(raw.decode())).body[0]
    else:
        tree = ast.parse(Path(subject.__file__).read_bytes())
        owner = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'QemuPreparationTest')
        node = next(n for n in owner.body if isinstance(n, ast.FunctionDef) and n.name == 'native_process_projection')
    if not isinstance(node, ast.FunctionDef) or node.name != 'native_process_projection':
        raise ValueError('projection-function-selection')
    namespace = dict(vars(subject))
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'exact before/current projection fixture', 'exec'), namespace)
    return namespace[node.name]


def _guard_boundary(case, before=False, constructor_birth=_REAL_BIRTH, tamper=False):
    temporary = tempfile.TemporaryDirectory()
    case.addCleanup(temporary.cleanup)
    root = Path(temporary.name).resolve();root.chmod(0o700)
    source = root / 'source.qcow2';source.write_bytes(b'OWNED_PHYSICAL_READ_ONLY_SOURCE');source.chmod(0o600)
    proc = root / 'proc';proc.mkdir()
    code = root / 'held-child.py';code.write_text(CHILD_SOURCE);code.chmod(0o600)
    scope = SimpleNamespace(source=source,source_root=root,proc=proc)
    source_pin = subject.inventory.generation(source.lstat())
    pin = {'generation':source_pin,'parents':[{'path':str(p),'generation':g}
            for p,g in subject.inventory.parent_pins(source,root)]}
    evidence = root / 'evidence';evidence.mkdir(mode=0o700)
    receipts = {}

    class OwnedChildLock:
        def __init__(self, binary, selected_source, selected_evidence):
            case.assertEqual(Path(selected_source),source)
            self.child = subprocess.Popen([sys.executable,'-B',str(code),str(source)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self._quit_sent=False;self._quit_attempts=0;self._closed=False;self.ready=False
            case.addCleanup(self._natural_close)
            try:
                raw=bytearray();deadline=time.monotonic()+5
                while b'\n' not in raw:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise RuntimeError('owned-child-ready-timeout')
                    readable,unused,unused=select.select([self.child.stdout],[],[],remaining)
                    if not readable:raise RuntimeError('owned-child-ready-timeout')
                    chunk=os.read(self.child.stdout.fileno(),4096-len(raw))
                    if not chunk:raise RuntimeError('owned-child-ready-eof')
                    raw.extend(chunk)
                    if len(raw)>=4096:raise RuntimeError('owned-child-ready-bound')
                packet=json.loads(bytes(raw))
                case.assertEqual(packet['pid'],self.child.pid);case.assertEqual(packet['fd'],9)
                case.assertEqual(packet['generation'],source_pin)
                actual=subject.inventory.process_birth(Path('/proc'),self.child.pid)
                if constructor_birth is _REAL_BIRTH:
                    if actual is None:
                        case.assertEqual(sys.platform, 'darwin', 'Only Darwin may use the explicit Linux metadata model')
                        case.assertFalse(Path('/proc/self/stat').exists(), 'Real Linux birth must remain observable')
                        self.birth=987654321
                        mode='explicit-Darwin-Linux-metadata-model'
                    else:
                        case.assertIs(type(actual),int);case.assertGreater(actual,0)
                        self.birth=actual;mode='actual-Linux-owned-child-birth'
                else:
                    self.birth=constructor_birth;mode='explicit-constructor-field-control'
                if self.birth is not None and self.birth!=0:case.assertNotEqual(self.birth,123)
                if actual is not None:
                    case.assertEqual(subject.inventory.generation((Path('/proc')/str(self.child.pid)/'fd'/'9').stat()),source_pin)
                receipts.update(mode=mode,constructorBirth=self.birth,kernelBirthObserved=actual is not None,
                    sourceGeneration=packet['generation'],physicalChildFd=packet['fd'])
                self.ready=True
            except BaseException:
                self._natural_close()
                raise

        def _natural_close(self):
            if self._closed:return
            try:
                if not self._quit_sent:
                    self._quit_sent=True
                    if self.child.poll() is None:
                        self._quit_attempts+=1
                        try:self.child.stdin.write(b'quit\n');self.child.stdin.flush()
                        except BrokenPipeError:pass
                self.child.wait(timeout=10)
                remaining=self.child.stdout.read(4096)
                case.assertEqual(remaining,b'')
                case.assertEqual(self.child.returncode,0)
            finally:
                self.child.stdin.close();self.child.stdout.close()
                self._closed=self.child.poll() is not None
                receipts.update(childWaited=self._closed,childPipesClosed=self.child.stdin.closed and self.child.stdout.closed,
                                quitDispatches=self._quit_attempts)

        def close(self):
            self._natural_close()

    original_init,original_close=OwnedChildLock.__init__,OwnedChildLock.close
    fixture=SimpleNamespace(proc=proc)
    start,close=_projection(before)(fixture,OwnedChildLock)
    reader=os.open(source,os.O_RDONLY|os.O_NOFOLLOW)
    lock=None
    try:
        with start,close:
            try:
                lock=OwnedChildLock(str(Path(sys.executable).resolve()),source,evidence)
                receipts['constructorFieldAfterProjection']=lock.birth
                if tamper:
                    path=proc/str(lock.child.pid)/'stat'
                    text=path.read_text();path.write_text(text.rsplit(' ',1)[0]+' '+str(lock.birth+1))
                receipts['projectedBirth']=subject.inventory.process_birth(proc,lock.child.pid)
                try:
                    result=subject.prepare.close_source(scope,reader,pin,lock,time.monotonic()+5)
                    receipts['guard']='source-closed'
                    case.assertEqual(len(result['holders']),1)
                    case.assertEqual(result['holders'][0]['pid'],lock.child.pid)
                    case.assertEqual(result['holders'][0]['startTicks'],lock.birth)
                except ValueError as error:
                    receipts['guard']=str(error)
                receipts['constructorFieldAfterGuard']=lock.birth
            finally:
                if lock is not None:lock.close()
    finally:
        os.close(reader)
    case.assertIs(OwnedChildLock.__init__,original_init);case.assertIs(OwnedChildLock.close,original_close)
    case.assertEqual(subject.inventory.generation(source.lstat()),source_pin)
    case.assertTrue(receipts['childWaited']);case.assertTrue(receipts['childPipesClosed'])
    case.assertEqual(receipts['quitDispatches'],1)
    if lock is not None:case.assertFalse((proc/str(lock.child.pid)).exists())
    # Public marker contains no path/argv/PID; complete owned observations stay
    # within this actual positive assertion and the source-bound routine.
    print(json.dumps({'qemuProjectionBirthFixture':receipts,'before':before,
                      'nativeVmOrQemuStarted':False},sort_keys=True),flush=True)
    return receipts


def _assert_positive(case,receipts):
    case.assertEqual(receipts['guard'],'source-closed')
    case.assertEqual(receipts['projectedBirth'],receipts['constructorBirth'])
    case.assertEqual(receipts['constructorFieldAfterProjection'],receipts['constructorBirth'])
    case.assertEqual(receipts['constructorFieldAfterGuard'],receipts['constructorBirth'])


@unittest.skipUnless(os.name=='posix','Physical POSIX child/FD/proc fixture required')
class QemuProjectionBirthFixtureTests(unittest.TestCase):
    def test_actual_constructor_birth_survives_projection_and_real_close_source(self):
        _assert_positive(self,_guard_boundary(self,before=_USE_BEFORE))

    def test_preserved_projection_fails_same_actual_guard(self):
        observations=[]
        class Before(unittest.TestCase):
            def runTest(inner):
                value=_guard_boundary(inner,before=True);observations.append(value)
                _assert_positive(inner,value)
        result=unittest.TestResult();unittest.TestSuite([Before()]).run(result)
        self.assertEqual(result.testsRun,1);self.assertEqual(len(result.failures),1)
        self.assertEqual(result.errors,[]);self.assertEqual(result.skipped,[])
        self.assertEqual(len(observations),1)
        self.assertEqual(observations[0]['guard'],'source-lock-birth-changed')
        self.assertEqual(observations[0]['projectedBirth'],123)
        self.assertNotEqual(observations[0]['constructorBirth'],123)

    def test_none_constructor_retains_explicit_projection_fallback(self):
        value=_guard_boundary(self,constructor_birth=None)
        self.assertEqual(value['guard'],'source-closed')
        self.assertIsNone(value['constructorBirth']);self.assertIsNone(value['constructorFieldAfterProjection'])
        self.assertEqual(value['projectedBirth'],123);self.assertEqual(value['constructorFieldAfterGuard'],123)
        self.assertEqual(value['mode'],'explicit-constructor-field-control')

    def test_zero_constructor_is_not_replaced_by_fallback(self):
        value=_guard_boundary(self,constructor_birth=0)
        self.assertEqual(value['guard'],'source-lock-birth')
        self.assertEqual(value['projectedBirth'],0);self.assertEqual(value['constructorFieldAfterGuard'],0)

    def test_changed_positive_projection_still_refuses_real_birth_guard(self):
        value=_guard_boundary(self,tamper=True)
        self.assertEqual(value['guard'],'source-lock-birth-changed')
        self.assertNotEqual(value['projectedBirth'],value['constructorBirth'])
        self.assertEqual(value['constructorFieldAfterGuard'],value['constructorBirth'])


if __name__=='__main__':
    if '--fixture-red' in sys.argv:
        _USE_BEFORE=True;sys.argv.remove('--fixture-red')
        unittest.main(defaultTest='QemuProjectionBirthFixtureTests.test_actual_constructor_birth_survives_projection_and_real_close_source')
    else:unittest.main()
