"""Owned local fixture capture; never a device or historical CI acceptance proof."""
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


GRACE = 15
BEFORE = Path(__file__).with_name('fixtures') / 'android_direct_fixture_lifecycle' / 'before.source'
BEFORE_SHA = '4dbc607a372b2c5189ad555540ab16683319046142ce48bd60b6950a75eddbf5'
_CAUSAL_BEFORE = False


class FixtureUnknown(AssertionError):
    """Original fixture outcome is retained, never accepted or resubmitted."""


def _before_tree():
    raw = BEFORE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BEFORE_SHA:
        raise FixtureUnknown('authentic_before_source_changed')
    return ast.parse(raw, filename=str(BEFORE.resolve()))


def _before_execute(nodes, inputs=None):
    """Execute genuine leading imports and selected old code in its actual file."""
    leading = []
    for node in _before_tree().body:
        if isinstance(node, ast.ClassDef):break
        if not (isinstance(node, (ast.Import, ast.ImportFrom))
                or isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            raise FixtureUnknown('before_import_prefix_changed')
        leading.append(node)
    if set(inputs or {}) - {'command', 'scaled'}:
        raise FixtureUnknown('counterfactual_input_scope_changed')
    scope = {'__name__': 'retained_android_direct_fixture_before',
             '__file__': str(BEFORE.resolve()), **(inputs or {})}
    code = compile(ast.fix_missing_locations(ast.Module(body=leading + nodes, type_ignores=[])),
                   str(BEFORE.resolve()), 'exec', dont_inherit=True)
    exec(code, scope)
    return scope


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(raw)
            output.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _record(path, value):
    _write(path, (json.dumps(value, sort_keys=True) + '\n').encode())


def supervisor_budget(source):
    """Use the actual authenticated supervisor's existing finite lifecycle."""
    tree = ast.parse(source)
    deadlines = [n.value.value for n in ast.walk(tree)
                 if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant)
                 and any(isinstance(t, ast.Name) and t.id == 'DEADLINE' for t in n.targets)]
    waits = [kw.value.value for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
             and n.func.value.id == 'child' and n.func.attr == 'wait'
             for kw in n.keywords if kw.arg == 'timeout' and isinstance(kw.value, ast.Constant)]
    if deadlines != [1800] or waits != [5]:
        raise FixtureUnknown('fixture_supervisor_policy_changed')
    return deadlines[0] + waits[0] + GRACE


def _owned_capture(argv, timeout, directory):
    """Wait/capture one exact local Popen; no process search, group signal or retry."""
    if os.name != 'posix':
        raise FixtureUnknown('posix_fixture_capture_required')
    _record(directory / 'fixture-capture-intent.json', {'argv': argv, 'timeout': timeout,
            'submissionCount': 1, 'replayAllowed': False})
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    actions, errors, partials = [], [], []
    uncertain = complete = False
    out = err = b''
    failure = None

    def note(phase, error):
        errors.append({'phase': phase, 'type': type(error).__name__,
                       'errno': getattr(error, 'errno', None)})

    def partial(error, phase):
        nonlocal out, err
        item = {'phase': phase, 'channels': {}}
        for name, raw in [('stdout', error.output), ('stderr', error.stderr)]:
            entry = {'available': raw is not None}
            if raw is not None:
                if not isinstance(raw, bytes):
                    note(phase, TypeError('binary capture required'))
                    entry['binary'] = False
                else:
                    previous = out if name == 'stdout' else err
                    if not raw.startswith(previous) and not previous.startswith(raw):
                        note(phase, ValueError('partial capture prefix changed'))
                    if len(raw) >= len(previous):
                        if name == 'stdout':out = raw
                        else:err = raw
                    filename = 'fixture-partial-%02d-%s.private' % (len(partials), name)
                    entry.update(name=filename, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                    try:_write(directory / filename, raw)
                    except BaseException as failed:note('partial_' + name, failed)
            item['channels'][name] = entry
        partials.append(item)  # Every actual TimeoutExpired is retained, cumulative or empty.

    try:
        out, err = child.communicate(timeout=timeout)
        complete = True
    except BaseException as error:
        uncertain, failure = True, error
        note('initial_capture', error)
        if isinstance(error, subprocess.TimeoutExpired):partial(error, 'initial_capture')
        try:
            _record(directory / 'fixture-capture-unknown.json', {'pid': child.pid,
                    'reason': type(error).__name__, 'replayAllowed': False})
        except BaseException as failed:note('unknown_publication', failed)
        try:
            if child.poll() is None:
                actions.append('terminate');child.terminate()
            try:
                out, err = child.communicate(timeout=GRACE)
                complete = True
            except subprocess.TimeoutExpired as stopped:
                note('after_terminate', stopped);partial(stopped, 'after_terminate')
                actions.append('kill');child.kill()
                try:
                    out, err = child.communicate(timeout=GRACE)
                    complete = True
                except subprocess.TimeoutExpired as stopped:
                    note('after_kill', stopped);partial(stopped, 'after_kill')
        except BaseException as failed:note('capture_cleanup', failed)
    finally:
        try:
            if child.poll() is None:
                if not actions:actions.append('terminate');child.terminate()
                try:child.wait(timeout=GRACE)
                except subprocess.TimeoutExpired as stopped:
                    note('reap_after_terminate', stopped);partial(stopped, 'reap_after_terminate')
                    if 'kill' not in actions:actions.append('kill');child.kill()
                    try:child.wait(timeout=GRACE)
                    except subprocess.TimeoutExpired as stopped:
                        note('reap_after_kill', stopped);partial(stopped, 'reap_after_kill')
        except BaseException as failed:note('final_reap', failed)
        for name, stream in [('stdout', child.stdout), ('stderr', child.stderr)]:
            try:
                if not stream.closed:stream.close()
            except BaseException as failed:note('close_' + name, failed)
    for name, raw in [('stdout', out), ('stderr', err)]:
        try:_write(directory / ('fixture-capture.' + name + '.private'), raw)
        except BaseException as failed:
            note('write_' + name, failed)
            if failure is None:failure = failed
    closed = all(stream.closed for stream in (child.stdout, child.stderr))
    uncertain = uncertain or bool(errors) or not complete or not closed or child.returncode is None
    _record(directory / 'fixture-capture-terminal.json', {'pid': child.pid,
            'returncode': child.returncode, 'reaped': child.returncode is not None,
            'bothEof': complete, 'pipesClosed': closed, 'uncertain': uncertain,
            'actions': actions, 'errors': errors, 'partials': partials, 'replayAllowed': False})
    if uncertain:
        raise FixtureUnknown('owned_fixture_capture_unknown; original capture retained') from failure
    return subprocess.CompletedProcess(argv, child.returncode, out, err)


# This test-only owner intercepts only the Popen created inside the unchanged
# supervisor. The detached worker's actual handle remains available in finally.
# None of this wrapper is transferred to a product host or used by production.
WRAPPER = r'''
import hashlib,json,os,signal,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]);source_sha=sys.argv[2];worker_sha=sys.argv[3]
def record(name,value):
 raw=(json.dumps(value,sort_keys=True)+'\n').encode()
 fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
 finally:os.close(fd)
fd=os.open(root/'fixture-supervisor.py',os.O_RDONLY|os.O_NOFOLLOW)
try:
 before=os.fstat(fd);source=b''
 while block:=os.read(fd,65536):source+=block
 after=os.fstat(fd);named=(root/'fixture-supervisor.py').lstat()
 key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 if key(before)!=key(after)or key(after)!=key(named)or hashlib.sha256(source).hexdigest()!=source_sha:raise ValueError('fixture_supervisor_source_changed')
finally:os.close(fd)
owned=[];original=subprocess.Popen
def accepted(*args,**kwargs):
 child=original(*args,**kwargs);owned.append(child)
 record('fixture-worker-accepted.json',{'pid':child.pid,'parentPid':os.getpid(),'workerSha256':worker_sha,'replayAllowed':False})
 return child
class StopFixture(BaseException):pass
def stop(*_):raise StopFixture()
signal.signal(signal.SIGTERM,stop)
subprocess.Popen=accepted
try:
 sys.argv=[sys.argv[0],str(root),worker_sha]
 exec(compile(source,str(root/'fixture-supervisor.py'),'exec'),{'__name__':'__main__','__file__':str(root/'fixture-supervisor.py')})
finally:
 subprocess.Popen=original
 rows=[]
 for child in owned:
  actions=[];out=err=b'';error=None;errors=[];partials=[];complete=False
  buffers={'stdout':b'','stderr':b''}
  def note(phase,failed):errors.append({'phase':phase,'type':type(failed).__name__,'errno':getattr(failed,'errno',None)})
  def partial(failed,phase):
   item={'phase':phase,'channels':{}}
   for name,raw in [('stdout',failed.output),('stderr',failed.stderr)]:
    entry={'available':raw is not None}
    if raw is not None:
     if not isinstance(raw,bytes):
      note(phase,TypeError('binary fixture tail required'));entry['binary']=False
     else:
      previous=buffers[name]
      if not raw.startswith(previous)and not previous.startswith(raw):note(phase,ValueError('fixture tail prefix changed'))
      if len(raw)>=len(previous):buffers[name]=raw
      filename='fixture-worker-partial-%02d-%s.private'%(len(partials),name)
      entry.update(name=filename,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
      try:
       fd=os.open(root/filename,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
       try:
        with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
       finally:os.close(fd)
      except BaseException as publish:note('partial_'+name,publish)
    item['channels'][name]=entry
   partials.append(item)
  try:
   if child.poll()is None:
    try:record('fixture-worker-close-intent.json',{'pid':child.pid,'action':'terminate','replayAllowed':False})
    except BaseException as failed:error=type(failed).__name__;note('close_intent',failed)
    actions.append('terminate');child.terminate()
   for stream in (child.stdout,child.stderr):
    if stream is not None and not stream.closed:os.set_blocking(stream.fileno(),True)
   try:out,err=child.communicate(timeout=5);complete=True
   except subprocess.TimeoutExpired as failed:
    note('after_terminate',failed);partial(failed,'after_terminate')
    actions.append('kill');child.kill()
    try:out,err=child.communicate(timeout=5);complete=True
    except subprocess.TimeoutExpired as failed:
     note('after_kill',failed);partial(failed,'after_kill');error=type(failed).__name__
  except BaseException as failed:error=type(failed).__name__;note('worker_capture',failed)
  finally:
   try:
    if child.poll()is None:
     if 'kill'not in actions:actions.append('kill');child.kill()
     try:child.wait(timeout=5)
     except subprocess.TimeoutExpired as failed:note('final_reap',failed);partial(failed,'final_reap');error=type(failed).__name__
   except BaseException as failed:error=type(failed).__name__;note('final_reap',failed)
   for name,stream in [('stdout',child.stdout),('stderr',child.stderr)]:
    try:
     if stream is not None and not stream.closed:stream.close()
    except BaseException as failed:error=type(failed).__name__;note('close_'+name,failed)
  if not complete:out,err=buffers['stdout'],buffers['stderr']
  try:record('fixture-worker-tail.json',{'stdoutHex':out.hex(),'stderrHex':err.hex(),'bothEof':complete,'partials':partials,'errors':errors})
  except BaseException as failed:error=type(failed).__name__;note('tail_publication',failed)
  rows.append({'pid':child.pid,'returncode':child.returncode,'reaped':child.returncode is not None,'pipesClosed':all(s is None or s.closed for s in (child.stdout,child.stderr)),'bothEof':complete,'actions':actions,'error':error,'errors':errors,'partials':partials})
 record('fixture-worker-closure.json',{'children':rows,'replayAllowed':False})
'''


def _preserve(directory, parent):
    """Retain this new fixture's immutable files outside runner TMPDIR cleanup."""
    destination = Path(tempfile.mkdtemp(prefix='android-direct-fixture-failure-', dir=parent))
    destination.chmod(0o700)
    for path in directory.iterdir():
        if path.is_file() and not path.is_symlink():
            shutil.copyfile(path, destination / path.name)
            (destination / path.name).chmod(0o600)
    return destination


@contextmanager
def emitted_capture(directory, source, worker_sha, retention_parent, retain=None):
    """The two full-flow callers retain their bodies and original assertions."""
    directory = Path(directory)
    try:
        budget = supervisor_budget(source)
        _write(directory / 'fixture-supervisor.py', source.encode())
        _write(directory / 'fixture-owner.py', WRAPPER.encode())
        argv = [sys.executable, '-I', '-u', '-B', str(directory / 'fixture-owner.py'),
                str(directory), hashlib.sha256(source.encode()).hexdigest(), worker_sha]
        if sum(len(s.encode()) + 1 for s in argv) > 60000:
            raise FixtureUnknown('fixture_command_bound')
        result = _owned_capture(argv, budget, directory)
        closure = json.loads((directory / 'fixture-worker-closure.json').read_bytes())
        rows = closure['children']
        accepted = json.loads((directory / 'fixture-worker-accepted.json').read_bytes())
        if (len(rows) != 1 or rows[0]['pid'] != accepted['pid']
                or not all(row['reaped'] is True and row['pipesClosed'] is True
                           and row['error'] is None for row in rows)):
            raise FixtureUnknown('fixture_worker_closure_unknown')
        terminal = json.loads((directory / 'terminal.json').read_bytes())
        if (terminal['reason'] is not None or type(terminal['returncode']) is not int
                or set(terminal['eof']) != {'stdout', 'stderr'}
                or not all(value is True for value in terminal['eof'].values())):
            raise FixtureUnknown('original_supervisor_outcome_unknown')
        yield result
    except BaseException as error:
        if retain is not None:
            retain()  # Registered setup cleanup must honor this explicit flag.
        try:
            retained = _preserve(directory, retention_parent)
            error.add_note('Owned fixture evidence retained: ' + str(retained))
        except BaseException as failed:
            error.add_note('Fixture evidence copy failed: ' + type(failed).__name__
                           + '; original root retained: ' + str(directory))
        raise


@unittest.skipUnless(os.name == 'posix', 'Actual saved child/owned descriptor fixture requires POSIX')
class PolicyTests(unittest.TestCase):
    def test_authentic_old_call_scaled_red_current_wait_green(self):
        tree = _before_tree()
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name in {'WholeWorkerTests', 'JoinedDirectFlowTests'}:
                calls.extend(n for n in ast.walk(node) if isinstance(n, ast.Call)
                             and ast.unparse(n.func) == 'subprocess.run'
                             and any(k.arg == 'timeout' and isinstance(k.value, ast.Constant)
                                     and k.value.value == 150 for k in n.keywords))
        self.assertEqual(2, len(calls))
        for old_call in calls:
            with self.subTest(caller=old_call.lineno), tempfile.TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                script = root / 'child.py'
                script.write_text("import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\nwith(p/'launches').open('ab')as f:f.write(b'ONE\\n')\n(p/'ready').write_text('READY')\nwhile not(p/'release').exists():time.sleep(.005)\nprint('ACTUAL_EOF')\n")
                command = [sys.executable, '-I', '-B', str(script), str(root)]
                timeout = next(k for k in old_call.keywords if k.arg == 'timeout')
                old_seconds = timeout.value.value
                scaled = 1.0
                from agent_tools import android_installer_direct_transport as direct
                current_wait = supervisor_budget(direct.supervisor_source()) * scaled / old_seconds
                # Only the saved direct child argv and time scale are projected.
                # Leading imports and the old call execute from authentic BEFORE.
                old_call.args[0] = ast.Name(id='command', ctx=ast.Load())
                timeout.value = ast.Name(id='scaled', ctx=ast.Load())
                projected = ast.Assign(targets=[ast.Name(id='_result', ctx=ast.Store())], value=old_call)

                def scheduled(invoke):
                    for name in ('ready', 'release'):
                        path = root / name
                        if path.exists():path.unlink()
                    def release():
                        deadline = time.monotonic() + current_wait
                        while not(root / 'ready').exists():
                            if time.monotonic() > deadline:return
                            time.sleep(.005)
                        threading.Event().wait(scaled * 1.1)
                        (root / 'release').write_text('GO')
                    gate = threading.Thread(target=release)
                    gate.start()
                    try:
                        return invoke()
                    finally:
                        gate.join(current_wait + 1)
                        self.assertFalse(gate.is_alive())
                        self.assertEqual('READY', (root / 'ready').read_text())
                        self.assertEqual('GO', (root / 'release').read_text())

                children = []
                real = subprocess.Popen
                def accepted(*a, **kw):
                    child = real(*a, **kw);children.append(child);return child
                with mock.patch.object(subprocess, 'Popen', side_effect=accepted):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        scheduled(lambda:_before_execute([projected], {'command': command, 'scaled': scaled}))
                self.assertEqual(1, len(children), 'one original direct child; no replay')
                self.assertIsNotNone(children[0].returncode)
                self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)
                self.assertEqual(b'ONE\n', (root / 'launches').read_bytes())
                if _CAUSAL_BEFORE:
                    self.fail('authentic old caller preempted a live READY child before its input/EOF')
                # Identical program/argv and READY->1.1-scaled release schedule.
                # Only the caller cutoff policy changes; both gates are joined.
                result = scheduled(lambda:_owned_capture(command, current_wait, root))
                self.assertEqual(0, result.returncode)
                self.assertEqual(b'ACTUAL_EOF\n', result.stdout)
                self.assertEqual(b'', result.stderr)
                self.assertEqual(b'ONE\nONE\n', (root / 'launches').read_bytes())


@unittest.skipUnless(os.name == 'posix', 'Actual descriptor/gate supervisor fixture requires POSIX')
class ActualSupervisorTests(unittest.TestCase):
    def source(self):
        from agent_tools.tests.test_android_installer_direct_transport import EmittedSupervisorTests
        return EmittedSupervisorTests.source(self)

    def run_body(self, root, body):
        from agent_tools import android_installer_direct_transport as direct
        program = (direct.WORKER_GATE + body).encode()
        direct.write_once(root, 'worker.py', program)
        return emitted_capture(root, self.source(), direct.sha(program), root.parent)

    def test_actual_supervisor_both_eofs_original_raw_and_owned_reap(self):
        from agent_tools import android_installer_direct_transport as direct
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); root.chmod(0o700)
            with self.run_body(root, "import sys\nprint('RAW-OUT')\nprint('RAW-ERR',file=sys.stderr)\n") as result:
                self.assertEqual(0, result.returncode, result.stderr)
                terminal = json.loads((root / 'terminal.json').read_bytes())
                self.assertEqual({'stdout': True, 'stderr': True}, terminal['eof'])
                closure = json.loads((root / 'fixture-worker-closure.json').read_bytes())['children'][0]
                self.assertTrue(closure['reaped']); self.assertTrue(closure['pipesClosed'])
                self.assertEqual([], closure['actions'])
                saved = direct.saved_terminal(root, terminal['workerSha256'])
                self.assertEqual('terminal', saved['state'])
                self.assertEqual(b'RAW-OUT\n', saved['raw']['stdout'])
                self.assertEqual(b'RAW-ERR\n', saved['raw']['stderr'])

    def test_actual_capture_storage_fault_reaps_original_worker_and_retains_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve(); root = parent / 'fixture'; root.mkdir(mode=0o700)
            original = _write
            def fault(path, raw):
                if path.name == 'fixture-capture.stdout.private':
                    fd = os.open(os.devnull, os.O_WRONLY); os.close(fd)
                    os.write(fd, b'actual-EBADF')
                return original(path, raw)
            with mock.patch.object(sys.modules[__name__], '_write', side_effect=fault):
                with self.assertRaises(FixtureUnknown) as failed:
                    with self.run_body(root, "print('RETAINED-BEFORE-STORAGE-FAULT')\n"):
                        self.fail('storage fault cannot pass')
            self.assertIsInstance(failed.exception.__cause__, OSError)
            closure = json.loads((root / 'fixture-worker-closure.json').read_bytes())['children'][0]
            self.assertTrue(closure['reaped']); self.assertTrue(closure['pipesClosed'])
            self.assertEqual([], closure['actions'])
            retained = list(parent.glob('android-direct-fixture-failure-*'))
            self.assertEqual(1, len(retained))
            self.assertIn(b'RETAINED-BEFORE-STORAGE-FAULT', (retained[0] / 'stdout-00000.private').read_bytes())

    def test_registered_cleanup_honors_retention_flag_old_source_red_current_green(self):
        from agent_tools.tests.test_android_installer_direct_transport import EmittedSupervisorTests
        tree = _before_tree()
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'EmittedSupervisorTests')
        setup = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'setUp')
        scope = _before_execute([setup])
        old = unittest.TestCase()
        scope['setUp'](old)
        old._retain_fixture_root = True
        old.doCleanups()
        with self.assertRaisesRegex(AssertionError, 'retained root'):
            self.assertTrue(old.root.exists(), 'retained root')
        current = EmittedSupervisorTests()
        current.setUp()
        try:
            current._retain_fixture_root = True
            current.doCleanups()
            self.assertTrue(current.root.is_dir(), 'registered callback must honor UNKNOWN retention')
        finally:
            current.tmp.cleanup()  # This control's exact new root, after inspection.

    def test_actual_timeout_retains_both_partial_channels_and_closes_original_child(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            script = root / 'blocked.py'
            script.write_text("import pathlib,signal,sys,time\nsignal.signal(signal.SIGTERM,lambda *_:None)\nprint('PREFIX-OUT',flush=True)\nprint('PREFIX-ERR',file=sys.stderr,flush=True)\npathlib.Path(sys.argv[1]).write_text('READY')\nwhile True:time.sleep(.01)\n")
            argv = [sys.executable, '-I', '-B', str(script), str(root / 'ready')]
            # Scale only this cleanup control's grace; the actual supervisor and
            # its1800s policy are unchanged. Both timeouts occur on real pipes.
            with mock.patch.object(sys.modules[__name__], 'GRACE', .2):
                with self.assertRaisesRegex(FixtureUnknown, 'owned_fixture_capture_unknown'):
                    _owned_capture(argv, 1.0, root)
            self.assertEqual('READY', (root / 'ready').read_text())
            terminal = json.loads((root / 'fixture-capture-terminal.json').read_bytes())
            self.assertTrue(terminal['uncertain']);self.assertTrue(terminal['reaped'])
            self.assertTrue(terminal['bothEof']);self.assertTrue(terminal['pipesClosed'])
            self.assertEqual(['terminate', 'kill'], terminal['actions'])
            self.assertEqual(2, len(terminal['partials']))
            self.assertEqual(b'PREFIX-OUT\n', (root / 'fixture-capture.stdout.private').read_bytes())
            self.assertEqual(b'PREFIX-ERR\n', (root / 'fixture-capture.stderr.private').read_bytes())
            for partial in terminal['partials']:
                for name, expected in [('stdout', b'PREFIX-OUT\n'), ('stderr', b'PREFIX-ERR\n')]:
                    item = partial['channels'][name]
                    self.assertTrue(item['available'])
                    raw = (root / item['name']).read_bytes()
                    self.assertEqual(expected, raw)
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), item['sha256'])
            self.assertFalse(terminal['replayAllowed'])

    def test_actual_supervisor_raw_limit_unknown_preserved_owned_worker_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve(); root = parent / 'fixture'; root.mkdir(mode=0o700)
            body = "import os,signal,sys,time\nsignal.signal(signal.SIGTERM,lambda *_:None)\nfor n in range(32):os.write(1,b'x'*524288)\nprint('TAIL-OUT',flush=True)\nprint('TAIL-ERR',file=sys.stderr,flush=True)\ntime.sleep(30)\n"
            with self.assertRaisesRegex(FixtureUnknown, 'original_supervisor_outcome_unknown'):
                with self.run_body(root, body):self.fail('UNKNOWN cannot pass')
            terminal = json.loads((root / 'terminal.json').read_bytes())
            self.assertEqual('direct_raw_limit', terminal['reason'])
            closure = json.loads((root / 'fixture-worker-closure.json').read_bytes())['children'][0]
            self.assertTrue(closure['reaped']); self.assertTrue(closure['pipesClosed'])
            self.assertEqual(['terminate', 'kill'], closure['actions'])
            self.assertTrue(closure['bothEof'])
            self.assertEqual(1, len(closure['partials']))
            partial = closure['partials'][0]
            self.assertEqual('after_terminate', partial['phase'])
            for name, ending in [('stdout', b'TAIL-OUT\n'), ('stderr', b'TAIL-ERR\n')]:
                item = partial['channels'][name]
                self.assertTrue(item['available'])
                raw = (root / item['name']).read_bytes()
                self.assertTrue(raw.endswith(ending))
                self.assertEqual(hashlib.sha256(raw).hexdigest(), item['sha256'])
            tail = json.loads((root / 'fixture-worker-tail.json').read_bytes())
            self.assertTrue(bytes.fromhex(tail['stdoutHex']).endswith(b'TAIL-OUT\n'))
            self.assertEqual(b'TAIL-ERR\n', bytes.fromhex(tail['stderrHex']))
            self.assertEqual(1, len(list(parent.glob('android-direct-fixture-failure-*'))))


if __name__ == '__main__':
    if sys.argv[1:] == ['--causal-before']:
        _CAUSAL_BEFORE = True
        unittest.main(argv=[sys.argv[0]], defaultTest='PolicyTests.test_authentic_old_call_scaled_red_current_wait_green')
    else:
        unittest.main()
