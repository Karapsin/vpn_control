"""Retained whole callers and real local pipes; never native VM/input data."""
import ast
from contextlib import contextmanager
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from agent_tools import durable_remote_job as jobs
from agent_tools import private_inventory_lock as private
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_unlock as unlock
from agent_tools import source_module_loader as loader
from agent_tools.tests import test_readiness_tart_macos_unlock as unlock_tests

binding, identity = unlock_tests.binding, unlock_tests.identity

FIXTURE = Path(__file__).with_name('fixtures') / 'tart_macos_observer_startup'
FILES = {'controller.constructor.before.source': '4813b97431bb71995fbaca9c49a94289ced255209c60c480e00af51497592c51', 'controller.current.source': '4723098644a375e821cd80a2a988cd4fb736010882bf7870436a9068f3bc942b', 'controller.deadline.before.source': '0f1732c7eabfdc111fb49d67a3a251471f53403a8e342cf2a56470fbbb39c2d7', 'driver.current.source': 'fc0c83c1fbec04affae3f01cac3bd0e09eb3912857725ec91bcde4794fc475ee', 'driver.deadline.before.source': 'cbbc3bd209fb909aeb802833e4d019d5898357d67525b687cd55bc18e1757fc1', 'retention.before.source': '2f585e773704809b9db8e3c104ea86968aefdc057b368c06282b00e578db05ed', 'retention.reviewed.source': '98a9de44f74f5a2e6b051531082ff9be811e274399f0fb9b25dbf687f402de88', 'unlock.before.source': 'ba316162d6191922253ba7d3a03a3bea1599a1612cffe2e0049fcdea4706f135'}


def fixture(name):
    if name not in FILES:
        raise AssertionError('unmapped startup fixture')
    path = FIXTURE / name
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FILES[name]:
        raise AssertionError('startup fixture changed')
    return path, raw


def subject(name):
    path, raw = fixture(name)
    module = ModuleType('agent_tools._startup_' + name.replace('.', '_'))
    module.__package__ = 'agent_tools'
    module.__file__ = str(path)
    if name == 'retention.before.source':
        module.__dict__.update(unlock.__dict__)
        module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


class IntegrityTests(unittest.TestCase):
    def test_exact_finite_whole_before_fixtures(self):
        for name in FILES:
            fixture(name)
        self.assertEqual('ba316162d6191922253ba7d3a03a3bea1599a1612cffe2e0049fcdea4706f135',
                         FILES['unlock.before.source'])


class GuardStopped(RuntimeError):
    pass


@unittest.skipUnless(os.name == 'posix', 'startup evidence uses private POSIX FDs')
class StartupTests(unittest.TestCase):
    def exercise(self, mode, *, before=False, after_ready=False):
        selected = subject('unlock.before.source') if before else unlock
        argv, payload = selected.stream.session_stream_command(binding())
        actual_popen = subprocess.Popen
        children = []
        calls = 0
        observer = None
        journal = None
        error = None

        def launch(args, **kwargs):
            self.assertEqual([binding().tart_binary, 'exec', '-i', binding().vm_name, *argv], args)
            if mode == 'popen':
                raise OSError()
            reply = {'protocol': selected.stream.PROTOCOL, 'state': 'observer_ready', 'observation': identity()}
            if mode == 'malformed':
                reply.pop('observation')
            code = 'import sys,time\nraw=sys.stdin.buffer.read(' + str(len(payload)) + ')\n'
            if mode == 'delay':
                code += 'time.sleep(3.2)\n'
            if mode == 'eof':
                code += "sys.stderr.write('PUBLIC_STARTUP_ERROR\\n');sys.stderr.flush();raise SystemExit(73)\n"
            elif mode == 'overflow':
                code += "sys.stdout.buffer.write(b'x'*32768+b'\\n');sys.stdout.buffer.flush();sys.stdin.buffer.read()\n"
            else:
                code += 'print(' + repr(json.dumps(reply)) + ',flush=True)\n'
                if after_ready:
                    code += "sys.stdin.buffer.readline()\nprint('FUTURE_PRIVATE_SENTINEL',flush=True)\nsys.stdin.buffer.read()\n"
                else:
                    code += 'sys.stdin.buffer.read()\n'
            child = actual_popen([sys.executable, '-I', '-B', '-c', code], **kwargs)
            children.append((child, jobs._birth(child.pid)))
            return child

        def guard():
            nonlocal calls
            calls += 1
            if mode == 'guard' + str(calls):
                raise GuardStopped()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            operation = '22222222-2222-4222-8222-222222222222'
            with private.Directory(root) as directory:
                if not before:
                    journal = unlock._StartupEvidence(directory, operation)
                try:
                    with mock.patch.object(selected.subprocess, 'Popen', launch):
                        kwargs = {'guard': guard}
                        if journal is not None:
                            kwargs['_startup'] = journal
                        observer = selected.SessionObserver(SimpleNamespace(binding=binding()), identity(),
                                                            time.monotonic() + 10, **kwargs)
                        if after_ready:
                            saved = {path.name: path.read_bytes() for path in root.iterdir()}
                            self.assertIsNone(observer._startup)
                            self.assertEqual({}, journal.fds)
                            with self.assertRaises(selected.UnlockBlocked):
                                observer.check()
                            self.assertEqual(saved, {path.name: path.read_bytes() for path in root.iterdir()})
                except BaseException as caught:
                    error = type(caught).__name__
                finally:
                    if observer is not None:
                        observer.close()
                    for child, birth in children:
                        if child.poll() is None:
                            child.stdin.close()
                            child.wait(timeout=3)
                        self.assertIsNotNone(birth)
                        self.assertNotEqual(jobs._birth(child.pid), birth)
                        for pipe in (child.stdin, child.stdout, child.stderr):
                            if not pipe.closed:
                                pipe.close()
                    if journal is not None:
                        journal.close()
            data = {path.name: path.read_bytes() for path in root.iterdir()}
        self.assertEqual(error is None, mode == 'valid')
        if before:
            self.assertFalse(data, 'whole ba316 had no retained actor/phase/startup bytes')
        else:
            records = [json.loads(line) for line in data['startup-' + operation + '.events'].splitlines()]
            self.assertEqual('startup_retained', records[-1]['stage'])
            self.assertEqual('ready' if mode == 'valid' else 'failed', records[-1]['state'])
            if children:
                self.assertTrue(any(row['stage'] == 'host_actor_started' for row in records))
            if mode != 'valid':
                failure = next(row for row in records if row['stage'] == 'startup_failed')
                self.assertTrue(failure['failure']['class'])
                self.assertLessEqual(len(failure['failure']['frames']), 16)
                self.assertNotIn('message', failure['failure'])
            if mode == 'eof':
                self.assertEqual(b'PUBLIC_STARTUP_ERROR\n', data['startup-' + operation + '.stderr'])
            if mode == 'overflow':
                self.assertEqual(16384, len(data['startup-' + operation + '.stdout']))
                self.assertTrue(records[-1]['stdoutOverflow'])
            self.assertNotIn(b'FUTURE_PRIVATE_SENTINEL', b''.join(data.values()))

    def test_whole_native071_before_lost_diagnostics_red_current_green(self):
        for mode in ('valid', 'guard1', 'guard2', 'guard3', 'popen', 'eof', 'malformed', 'delay', 'overflow'):
            with self.subTest(mode=mode):
                self.exercise(mode, before=True)
                self.exercise(mode)

    def test_capture_disarmed_after_ready_future_output_is_never_retained(self):
        self.exercise('valid', after_ready=True)

    def test_all_evidence_faults_always_attempt_process_cleanup_and_both_output_closes(self):
        before = subject('retention.before.source')
        for current in (False, True):
            module = unlock if current else before
            for exited in (False, True):
                for fault in ('actor', 'phase', 'bytes', 'failure', 'drain', 'finish'):
                    with self.subTest(current=current, exited=exited, fault=fault):
                        actual_popen = subprocess.Popen
                        children = []
                        calls = 0
                        argv, payload = module.stream.session_stream_command(binding())

                        def launch(args, **kwargs):
                            self.assertEqual([binding().tart_binary, 'exec', '-i', binding().vm_name, *argv], args)
                            reply = {'protocol': module.stream.PROTOCOL, 'state': 'observer_ready', 'observation': identity()}
                            code = 'import sys\nraw=sys.stdin.buffer.read(' + str(len(payload)) + ')\nprint(' + repr(json.dumps(reply)) + ',flush=True)\n'
                            if not exited:
                                code += 'sys.stdin.buffer.read()\n'
                            child = actual_popen([sys.executable, '-I', '-B', '-c', code], **kwargs)
                            children.append((child, jobs._birth(child.pid)))
                            return child

                        def guard():
                            nonlocal calls
                            calls += 1
                            if fault in ('failure', 'drain') and calls == 3:
                                raise GuardStopped()

                        method = getattr(module._StartupEvidence, fault)

                        def broken(evidence, *args):
                            if fault == 'phase' and args[0] != 'write_fixed_payload':
                                return method(evidence, *args)
                            if fault == 'actor':
                                method(evidence, *args)
                            raise OSError()

                        with tempfile.TemporaryDirectory() as temporary:
                            root = Path(temporary).resolve()
                            root.chmod(0o700)
                            with private.Directory(root) as directory:
                                evidence = module._StartupEvidence(directory, '33333333-3333-4333-8333-333333333333')
                                try:
                                    with mock.patch.object(module._StartupEvidence, fault, broken), mock.patch.object(module.subprocess, 'Popen', launch):
                                        with self.assertRaises((OSError, GuardStopped)):
                                            module.SessionObserver(SimpleNamespace(binding=binding()), identity(),
                                                                   time.monotonic() + 10, guard=guard, _startup=evidence)
                                        closed = all(child.stdin.closed and child.stdout.closed and child.stderr.closed
                                                     for child, _ in children)
                                        if current:
                                            self.assertTrue(closed)
                                            self.assertTrue(all(child.poll() is not None for child, _ in children))
                                        elif fault in ('bytes', 'failure', 'drain', 'finish'):
                                            self.assertFalse(closed, 'retained 2f585 skipped cleanup on evidence failure')
                                finally:
                                    for child, birth in children:
                                        if child.poll() is None:
                                            if not child.stdin.closed:
                                                child.stdin.close()
                                            child.wait(timeout=3)
                                        self.assertIsNotNone(birth)
                                        self.assertNotEqual(jobs._birth(child.pid), birth)
                                        for pipe in (child.stdin, child.stdout, child.stderr):
                                            if not pipe.closed:
                                                pipe.close()
                                    evidence.close()


@unittest.skipUnless(os.name == 'posix', 'controlled input gate uses POSIX private FDs')
class PipelineTests(unittest.TestCase):
    setUp = unlock_tests.CallerTests.setUp
    tearDown = unlock_tests.CallerTests.tearDown
    run_unlock = unlock_tests.CallerTests.run_unlock

    def test_startup_failure_never_opens_vnc_or_ordinary_credential(self):
        def failed_start(*args, **kwargs):
            child = self.popen([sys.executable, '-I', '-B', '-c',
                               'import sys;sys.stdin.buffer.read(7);sys.stderr.write("PUBLIC_STARTUP_ERROR\\n");raise SystemExit(73)'],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            self.children.append(child)
            return child
        with mock.patch.object(unlock.subprocess, 'Popen', failed_start):
            with self.assertRaises(unlock.UnlockBlocked):
                self.run_unlock()
        self.assertEqual({'vnc': 0, 'ordinary': 0}, self.opens)
        self.assertEqual([], self.endpoint.responses)
        self.assertFalse((self.root / ('macos-unlock-' + self.operation + '.json')).exists())
        rows = [json.loads(line) for line in (self.root / ('startup-' + self.operation + '.events')).read_bytes().splitlines()]
        self.assertEqual(('failed', True, True), (rows[-1]['state'], rows[-1]['stdoutEof'], rows[-1]['stderrEof']))

    def test_preinit_failure_always_closes_preopened_startup_fds(self):
        journals = []
        def stopped(*args, **kwargs):
            journals.append(kwargs['_startup'])
            raise GuardStopped()
        with mock.patch.object(unlock, 'SessionObserver', stopped):
            with self.assertRaises(unlock.UnlockBlocked):
                self.run_unlock()
        self.assertEqual(1, len(journals))
        self.assertEqual({}, journals[0].fds)
        self.assertEqual({'vnc': 0, 'ordinary': 0}, self.opens)
        self.assertEqual([], self.endpoint.responses)


class CallerSignatureTests(unittest.TestCase):
    def test_actual_whole_controller_before_keyword_failure_red_exact_current_signature_green(self):
        signature = inspect.signature(registry.MacCustody)
        self.assertNotIn('deadline', signature.parameters)
        for old in (True, False):
            path, raw = fixture('controller.constructor.before.source' if old else 'controller.current.source')
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                runpath = root / 'originalRun.json'
                calls = {'factory': 0, 'submit': 0}
                run = {'operationId': '11111111-1111-4111-8111-111111111111', 'hostBinding': {},
                       'jobRootGeneration': [1, 2], 'programSha256': '0' * 64}
                descriptor = {'provider': 'tart-macos', 'binding': {'vm_name': 'vpn-tool-recovery-tart-macos-7686d4aa'},
                              'originalRun': {'path': str(runpath), 'pin': {}}}
                class Proof:
                    def __init__(self, path, pin, **kwargs):
                        self.path, self.body = Path(path), raw
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def guard(self): pass
                    def value(self): return run
                class Custody:
                    lifecycle_root = root
                    def close(self): pass
                    @contextmanager
                    def operator(self, *, deadline): yield self
                    def guard(self, *, deadline): raise GuardStopped()
                def factory(*args, **kwargs):
                    signature.bind(*args, **kwargs)
                    calls['factory'] += 1
                    return Custody()
                def submit(*args, **kwargs):
                    calls['submit'] += 1
                    raise AssertionError('dispatch forbidden')
                controlled_registry = SimpleNamespace(PublicProof=Proof, MacCustody=factory, _limit=registry._limit)
                controlled_jobs = SimpleNamespace(MachineBinding=SimpleNamespace(from_dict=lambda value: SimpleNamespace()),
                    _uuid=jobs._uuid, _root=lambda *args: None, _intent=lambda *args: {'programSha256': '0' * 64},
                    observe=lambda *args, **kwargs: {'state': 'unsubmitted'}, submit=submit)
                modules = {'readiness_tart_macos_registry': controlled_registry,
                    'readiness_fixture_registry': SimpleNamespace(_json=lambda path: (descriptor, {})),
                    'durable_remote_job': controlled_jobs, 'private_inventory_lock': private}
                class Session:
                    module = controlled_registry
                    def __init__(self, *args): pass
                    def load(self, name): return modules[name]
                    def guard(self): pass
                    def close(self): pass
                argv = [str(path), '--action', 'start', '--phase', 'census', '--target',
                        'tart:vpn-tool-recovery-tart-macos-7686d4aa', '--fixture-id',
                        'tart-macos-independent-parent-recovery-v13', '--operation-id',
                        'fbba7fe9-0dbb-4e04-86cc-3bec5c58c998']
                with mock.patch.object(loader, 'SourceSession', Session), mock.patch.object(sys, 'argv', argv):
                    with self.assertRaises(TypeError if old else GuardStopped):
                        exec(compile(raw, str(path), 'exec'), {'__name__': '__main__', '__file__': str(path)})
                self.assertEqual(0 if old else 1, calls['factory'])
                self.assertEqual(0, calls['submit'])

    def test_selected_real_factory_brackets_refuse_elapsed_absolute_cap(self):
        signature = inspect.signature(registry.MacCustody)
        for kind, budget in (('driver', 120), ('controller', 30)):
            for before in (True, False):
                path, raw = fixture(kind + ('.deadline.before.source' if before else '.current.source'))
                statements = []
                for node in ast.walk(ast.parse(raw)):
                    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'c' for t in node.targets):
                        statements.append(node)
                    if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                            and isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name)
                            and node.value.func.value.id == 'R' and node.value.func.attr == '_limit'):
                        statements.append(node)
                statements.sort(key=lambda node: node.lineno)
                clock = {'now': 1.}
                def factory(*args, **kwargs):
                    signature.bind(*args, **kwargs)
                    clock['now'] += budget + 1
                    return object()
                scope = {'R': SimpleNamespace(MacCustody=factory, _limit=registry._limit), 'PROJECT': None,
                    'FIXTURE': None, 'd': None, 'pin': None, 'ENTRY_DEADLINE': 1 + budget,
                    'args': SimpleNamespace(fixture_id='fixed'), 'descriptor': None, 'admission_deadline': 1 + budget}
                with mock.patch.object(registry.time, 'monotonic', side_effect=lambda: clock['now']):
                    if before:
                        exec(compile(ast.Module(body=statements, type_ignores=[]), str(path), 'exec'), scope)
                    else:
                        with self.assertRaises(registry.MacBlocked):
                            exec(compile(ast.Module(body=statements, type_ignores=[]), str(path), 'exec'), scope)

    def test_exact_controller_target_predicate_rejects_internal_identity_before_effect(self):
        path, raw = fixture('controller.current.source')
        tree = ast.parse(raw)
        call = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name) and node.func.id == 'need'
                    and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == 'controller_explicit_target_mismatch')
        code = compile(ast.Expression(call.args[0]), str(path), 'eval')
        descriptor = {'provider': 'tart-macos', 'binding': {'vm_name': 'selected-explicit-vm'}}
        self.assertFalse(eval(code, {'descriptor': descriptor, 'args': SimpleNamespace(target='local-tart-macos-' + 'a' * 24)}))
        self.assertTrue(eval(code, {'descriptor': descriptor, 'args': SimpleNamespace(target='tart:selected-explicit-vm')}))


if __name__ == '__main__':
    unittest.main(verbosity=2)
