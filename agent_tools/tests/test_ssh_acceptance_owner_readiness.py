"""No-network models over authenticated whole14d AST and ordinary successor."""
import ast
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import ModuleType, SimpleNamespace
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/ssh_acceptance_owner_readiness'
SOURCE = FIXTURE / 'controller14d.before.source'
EXPECTED = '14d50b0ccccaf944d92a9c5784fbb0f6deeb7910289f579b8b1b54ac24d6de3d'


def authenticated(name):
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    expected = {'controller14d.before.source', 'ordinary_controller.before.source',
                'ordinary_controller.fixed.source', 'original61bd.failure.txt',
                'original61bd.failure-provenance.json'}
    if provenance['schemaVersion'] != 1 or set(provenance['files']) != expected:
        raise AssertionError('finite acceptance fixture scope changed')
    for leaf, digest in provenance['files'].items():
        if hashlib.sha256((FIXTURE / leaf).read_bytes()).hexdigest() != digest:
            raise AssertionError('acceptance fixture changed: ' + leaf)
    return (FIXTURE / name).read_bytes()


def load_helper(name, alias):
    module = ModuleType(alias)
    module.__file__ = str(FIXTURE / name)
    sys.modules[alias] = module
    exec(compile(authenticated(name), module.__file__, 'exec'), module.__dict__)
    return module


current = load_helper('ordinary_controller.fixed.source', '_acceptance_owner_fixed')
old_output = load_helper('ordinary_controller.before.source', '_acceptance_owner_output_before')
OP = '3f369d7f-1e56-44b4-b9d0-ed2c716e7ef1'
OWNER = {'pid': 417, 'birth': 'linux:9012'}


class CarriedCompletedResult(Exception):
    def __init__(self, result):
        self.result = result
        self.takes = 0

    def take_submitted_result(self):
        self.takes += 1
        result, self.result = self.result, None
        if result is None:
            raise ValueError('already consumed')
        return result


def status(**changes):
    return {'schemaVersion': 1, 'host': 'gateway', 'operationId': OP, 'state': 'pending',
            'reason': 'original_remote_owner_observed', 'remoteState': 'running',
            'remoteOwner': OWNER, 'remoteOperationId': OP, 'durableProtocol': 1,
            'replayAllowed': False, **changes}


def completed(returncode=0, stdout=None, stderr=b''):
    raw = json.dumps({'operationId': OP, 'owner': OWNER, 'executions': 1, 'lines': 7}).encode()
    return subprocess.CompletedProcess(['PUBLIC_ARGUMENT_MUST_NOT_BE_RETAINED'], returncode,
                                       raw if stdout is None else stdout, stderr)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'private POSIX output FD custody')
class OrdinaryControllerTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(EXPECTED, hashlib.sha256(SOURCE.read_bytes()).hexdigest())
        self.tree = ast.parse(authenticated('controller14d.before.source'))
        self.main = next(node for node in self.tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def old_remote(self, invoke, guard=lambda: None):
        remote = next(node for node in self.main.body if isinstance(node, ast.Try))
        remote = next(node for node in remote.body if isinstance(node, ast.FunctionDef) and node.name == 'remote')
        transport = SimpleNamespace(admitted_transport=lambda *a, **k: nullcontext(),
            build_ssh_argv=lambda *a: ['inert-public-model'], load_config=lambda *a: object(),
            run_ssh=lambda *a, **k: invoke())
        ns = {'t': transport, 'guard': guard, 'root': self.root, 'operation': OP,
              'host': 'gateway', 'deadline': time.monotonic() + 10,
              'time': time, 'json': json, 'subprocess': subprocess}
        exec(compile(ast.Module(body=[remote], type_ignores=[]), str(SOURCE), 'exec'), ns)
        return ns['remote']

    def observe(self, invoke, guard=lambda: None, *, observations=None, error_type=None, helper=current, root=None):
        values = iter(observations or [status()])
        calls = []
        def fresh(action, inputs):
            calls.append((action, inputs))
            return next(values)
        value = helper.observe_ordinary(OP, 'gateway', fresh, invoke, guard, root or self.root,
                    deadline=time.monotonic() + 5, pause=lambda _: None,
                    submitted_result_error_type=error_type)
        self.assertTrue(calls)
        self.assertTrue(all(action == 'program-status' and inputs ==
            {'host': 'gateway', 'identity': {'operationId': OP}} for action, inputs in calls))
        return value

    def test_actual14d_admission_gate_probes_early_current_requires_exact_observed_running(self):
        enclosing = next(node for node in self.main.body if isinstance(node, ast.Try))
        gate = []
        for node in enclosing.body:
            if isinstance(node, (ast.Expr, ast.Assign)) and any(
                    isinstance(part, ast.Constant) and part.value in
                    ('program_remote_admission_missing', 'counter_not_started') for part in ast.walk(node)):
                gate.append(node)
        self.assertEqual(2, len(gate))
        directory = self.root / 'admission'
        directory.mkdir()
        (directory / 'remote-admission.json').write_text('{}')
        old_calls = []
        def probe(_):
            old_calls.append('counter-before-running-status')
            return {'owner': OWNER}
        ns = {'directory': directory, 'deadline': time.monotonic() + 5, 'time': time,
              'until': lambda predicate, *_: predicate(), 'active_after': probe}
        exec(compile(ast.Module(body=gate, type_ignores=[]), str(SOURCE), 'exec'), ns)
        self.assertEqual(['counter-before-running-status'], old_calls)  # actual old ordering RED
        events = []
        observations = [status(reason='original_owner_not_yet_observed', remoteOwner=None),
                        {key: value for key, value in status().items() if key != 'remoteState'},
                        status(remoteOwner=None), status()]
        values = iter(observations)
        def fresh(action, inputs):
            value = next(values)
            events.append(('status', value.get('remoteState'), value.get('remoteOwner')))
            return value
        def public_probe():
            events.append(('counter',))
            return completed()
        current.observe_ordinary(OP, 'gateway', fresh, public_probe, lambda: None, self.root,
                                 deadline=time.monotonic() + 5, pause=lambda _: None)
        self.assertEqual(4, sum(event[0] == 'status' for event in events))
        self.assertEqual(('counter',), events[-1])

    def test_actual14d_nonzero_drops_public_raw_current_retains_before_assertion(self):
        result = completed(23, b'bounded public stdout', b'bounded public stderr')
        with self.assertRaisesRegex(ValueError, 'owned_readonly_observation_failed'):
            self.old_remote(lambda: result)('fixed public probe')
        self.assertEqual([], list(self.root.iterdir()))  # actual whole-old remote has no capture
        with self.assertRaisesRegex(current.QualificationBlocked, 'public_probe_failed'):
            self.observe(lambda: result)
        leaf = self.root / 'counter-000001'
        self.assertEqual(result.stdout, (leaf / 'stdout.bin').read_bytes())
        self.assertEqual(result.stderr, (leaf / 'stderr.bin').read_bytes())
        receipt = json.loads((leaf / 'receipt.json').read_bytes())
        self.assertEqual(23, receipt['returnCode'])
        self.assertTrue(receipt['complete'])
        self.assertNotIn('PUBLIC_ARGUMENT', json.dumps(receipt))

    def test_actual14d_closing_guard_drops_result_current_captures_before_guard_refusal(self):
        result = completed()
        def guards(check_retained):
            count = [0]
            def guard():
                count[0] += 1
                if count[0] == 2:
                    if check_retained:
                        self.assertEqual(result.stdout, (self.root / 'counter-000001/stdout.bin').read_bytes())
                    raise ValueError('closing source refused model')
            return guard
        with self.assertRaisesRegex(ValueError, 'closing source refused model'):
            self.old_remote(lambda: result, guards(False))('fixed public probe')
        self.assertEqual([], list(self.root.iterdir()))
        with self.assertRaisesRegex(current.QualificationBlocked, 'closing_guard_refused'):
            self.observe(lambda: result, guards(True))
        self.assertEqual(0, json.loads((self.root / 'counter-000001/receipt.json').read_bytes())['returnCode'])

    def test_actual14d_completed_result_exception_is_retained_once_without_retry(self):
        result = completed(31, b'public completed body', b'public completed diagnostic')
        old_error = CarriedCompletedResult(result)
        def old_invoke():
            raise old_error
        with self.assertRaises(CarriedCompletedResult):
            self.old_remote(old_invoke)('fixed public probe')
        self.assertEqual([], list(self.root.iterdir()))
        error = CarriedCompletedResult(result)
        calls = []
        def invoke():
            calls.append('one-public-call')
            raise error
        with self.assertRaisesRegex(current.QualificationBlocked, 'completed_public_result_readiness_refused'):
            self.observe(invoke, error_type=CarriedCompletedResult)
        self.assertEqual(['one-public-call'], calls)
        self.assertEqual(1, error.takes)
        self.assertEqual(result.stdout, (self.root / 'counter-000001/stdout.bin').read_bytes())
        self.assertEqual(31, json.loads((self.root / 'counter-000001/receipt.json').read_bytes())['returnCode'])

    def test_terminal_or_wrong_original_status_never_calls_counter_or_creates_replacement(self):
        for value in (status(state='terminal'), status(operationId='e5a31916-90a7-4b1b-945e-acb258a5dc6c'),
                      status(host='other-host')):
            calls = []
            with self.subTest(value=value), self.assertRaises(current.QualificationBlocked):
                self.observe(lambda: calls.append('counter'), observations=[value])
            self.assertEqual([], calls)
        self.assertEqual([], list(self.root.iterdir()))

    def test_completed_overflow_is_bounded_and_retained_before_refusal(self):
        result = completed(stdout=b'x' * (current.STDOUT_LIMIT + 1))
        with self.assertRaisesRegex(current.QualificationBlocked, 'stream_limit'):
            self.observe(lambda: result)
        leaf = self.root / 'counter-000001'
        self.assertEqual(current.STDOUT_LIMIT, (leaf / 'stdout.bin').stat().st_size)
        receipt = json.loads((leaf / 'receipt.json').read_bytes())
        self.assertFalse(receipt['complete'])
        self.assertTrue(receipt['streamCapped'])
        self.assertEqual(current.STDOUT_LIMIT + 1, receipt['countsObserved']['stdout'])

    def test_pending_without_running_evidence_times_out_without_counter(self):
        clock = [0.0]
        calls = []
        with self.assertRaisesRegex(current.QualificationBlocked, 'running_not_observed'):
            current.observe_ordinary(OP, 'gateway', lambda *a: status(remoteState=None, remoteOwner=None),
                lambda: calls.append('counter'), lambda: None, self.root, deadline=.3,
                clock=lambda: clock[0], pause=lambda seconds: clock.__setitem__(0, clock[0] + seconds))
        self.assertEqual([], calls)

    def test_whole_dada_parent_replacement_redirects_red_fixed_held_original_retention_green(self):
        for symlink in (False, True):
            for helper, old in ((old_output, True), (current, False)):
                with self.subTest(symlink=symlink, before=old):
                    scope = self.root / ('scope-%s-%s' % (symlink, old))
                    scope.mkdir(mode=0o700)
                    parent, moved, redirect = scope / 'present', scope / 'moved', scope / 'redirect'
                    parent.mkdir(mode=0o700)
                    output = parent / 'output'
                    output.mkdir(mode=0o700)
                    redirect.mkdir(mode=0o700)
                    (redirect / 'output').mkdir(mode=0o700)
                    result = completed()
                    calls = []
                    def replace_parent():
                        calls.append('one-completed-public-probe')
                        parent.rename(moved)
                        if symlink:
                            parent.symlink_to(redirect, target_is_directory=True)
                        else:
                            parent.mkdir(mode=0o700)
                            (parent / 'output').mkdir(mode=0o700)
                        return result
                    if old:
                        self.observe(replace_parent, helper=helper, root=output)
                        self.assertEqual(result.stdout, (output / 'counter-000001/stdout.bin').read_bytes())
                        self.assertEqual([], list((moved / 'output').iterdir()))
                    else:
                        with self.assertRaisesRegex(current.QualificationBlocked, 'output_named_custody_changed'):
                            self.observe(replace_parent, helper=helper, root=output)
                        self.assertEqual([], list(output.iterdir()))
                        leaf = moved / 'output/counter-000001'
                        self.assertEqual(result.stdout, (leaf / 'stdout.bin').read_bytes())
                        receipt = json.loads((leaf / 'receipt.json').read_bytes())
                        self.assertFalse(receipt['namedCustody'])
                        self.assertEqual(0, receipt['returnCode'])
                    self.assertEqual(['one-completed-public-probe'], calls)

    def test_actual_independent_source_generation_refusal_still_retains_public_result(self):
        output = self.root / 'output'
        output.mkdir(mode=0o700)
        source = self.root / 'public-source.py'
        result = completed()
        def generation():
            info = source.stat()
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns, source.read_bytes())
        def setup_source_guard():
            source.write_bytes(b'# fixed public source before\n')
            initial = generation()
            def guard():
                if generation() != initial:
                    raise ValueError('owned source generation changed')
            return guard
        def completed_then_source_changed():
            source.write_bytes(b'# changed public source after completed observation\n')
            return result
        with self.assertRaisesRegex(ValueError, 'owned source generation changed'):
            self.old_remote(completed_then_source_changed, setup_source_guard())('fixed public probe')
        self.assertFalse((output / 'counter-000001').exists())
        with self.assertRaisesRegex(current.QualificationBlocked, 'closing_guard_refused'):
            self.observe(completed_then_source_changed, setup_source_guard(), root=output)
        self.assertEqual(result.stdout, (output / 'counter-000001/stdout.bin').read_bytes())
        self.assertTrue(json.loads((output / 'counter-000001/receipt.json').read_bytes())['namedCustody'])

    def test_private_leaf_or_retained_file_generation_change_never_adopted(self):
        for change_file in (False, True):
            output = self.root / ('output-' + str(change_file))
            output.mkdir(mode=0o700)
            calls = [0]
            def guard():
                calls[0] += 1
                if change_file and calls[0] == 2:
                    (output / 'counter-000001/stdout.bin').write_bytes(b'changed public output')
            def probe():
                if not change_file:
                    (output / 'counter-000001').chmod(0o701)
                return completed()
            with self.subTest(file=change_file), self.assertRaisesRegex(current.QualificationBlocked, 'output_(custody|file)_changed'):
                self.observe(probe, guard, root=output)
            if not change_file:
                self.assertFalse((output / 'counter-000001/stdout.bin').exists())


class OwnerReadinessPortableTests(unittest.TestCase):
    def test_exact_actual_running_schema_only_and_terminal_collect_only(self):
        value = current.wait_running(OP, 'gateway', lambda *a: status(), deadline=1,
                                     clock=lambda: 0, pause=lambda _: None)
        self.assertEqual(tuple(sorted(OWNER.items())), value.owner)
        for changed in ({'state': 'terminal'}, {'operationId': 'e5a31916-90a7-4b1b-945e-acb258a5dc6c'},
                        {'host': 'other-host'}, {'replayAllowed': True}):
            with self.subTest(changed=changed), self.assertRaises(current.QualificationBlocked):
                current.wait_running(OP, 'gateway', lambda *a: status(**changed), deadline=1,
                                     clock=lambda: 0, pause=lambda _: None)

    def test_no_remote_state_or_invalid_owner_never_means_running(self):
        for changed in ({'remoteState': None}, {'remoteOwner': None}, {'durableProtocol': True},
                        {'remoteOwner': {'pid': True, 'birth': 'linux:9012'}},
                        {'remoteOwner': {'pid': 417, 'birth': 'linux:0'}}):
            clock = [0.0]
            with self.subTest(changed=changed), self.assertRaisesRegex(current.QualificationBlocked, 'running_not_observed'):
                current.wait_running(OP, 'gateway', lambda *a: status(**changed), deadline=.3,
                    clock=lambda: clock[0], pause=lambda seconds: clock.__setitem__(0, clock[0] + seconds))


# Finite complete controller beforeimages exercise all nineteen original wiring
# and deadline controls in addition to the twelve retained owner-readiness cases.
from agent_tools.tests.test_ssh_acceptance_preparation import load_fixture as _load_controller_fixture, SUPPORTED as _CONTROLLER_SUPPORTED
if _CONTROLLER_SUPPORTED:
    _controller_cases = _load_controller_fixture('test_controller.py', '_routine_controller_deadline_tests')
    ControllerWiringTests = _controller_cases.ControllerWiringTests
    DeadlineFenceTests = _controller_cases.DeadlineFenceTests
    AbsoluteAdmissionDeadlineTests = _controller_cases.AbsoluteAdmissionDeadlineTests


if __name__ == '__main__':
    unittest.main()
