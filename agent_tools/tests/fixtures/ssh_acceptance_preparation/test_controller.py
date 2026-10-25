"""Source-only controller wiring; no main, connections, jobs or signal calls."""
import ast
from contextlib import contextmanager, nullcontext
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from agent_tools import readiness, ssh_transport

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


controller = module('_reviewed_ordinary_controller', HERE / 'controller.py')
retention = module('_reviewed_ordinary_retention', HERE / 'ordinary_retention.py')
OLD = ast.parse((HERE / 'controller14d.before.source').read_bytes())
DEADLINE_BEFORE = ast.parse((HERE / 'controller.edc5.before.source').read_bytes())
NEW = ast.parse((HERE / 'controller.py').read_bytes())
OP = controller.NEW_OPERATIONS['direct']
OWNER = {'pid': 417, 'birth': 'linux:9012'}
SHA = 'a' * 64


def running(**updates):
    return {'schemaVersion': 1, 'operationId': OP, 'host': 'gateway', 'state': 'pending',
            'reason': 'original_remote_owner_observed', 'remoteState': 'running',
            'remoteOwner': OWNER, 'remoteOperationId': OP, 'durableProtocol': 1,
            'replayAllowed': False, **updates}


def records(value, pid=501):
    request = {'action': 'program-status', 'host': 'gateway', 'timeout_seconds': 15,
               'identity': {'operationId': OP}}
    return {'client-intent.json': {'request': request, 'serverSha256': SHA,
                'clientPid': pid, 'automaticReplay': False},
            'call-intent-00000000.json': {'request': request, 'operationId': OP,
                'automaticReplay': False, 'relayAttempt': 1},
            'call-result-00000000.json': {'isError': False, 'structuredContent': value,
                'content': [{'type': 'text', 'text': json.dumps(value)}]},
            'client-result.json': {'state': 'rpc_returned', 'host': 'gateway', 'operationId': OP,
                'toolError': False, 'attemptedToolCalls': 1, 'returnedToolCalls': 1, 'relayAttempts': 1,
                'allRelayAttemptsClosed': True, 'programState': value['state']}}


def body(tree):
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    return next(node for node in main.body if isinstance(node, ast.Try)).body


def nested(tree, name):
    return copy.deepcopy(next(node for node in body(tree) if isinstance(node, ast.FunctionDef) and node.name == name))


class ControllerWiringTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual('14d50b0ccccaf944d92a9c5784fbb0f6deeb7910289f579b8b1b54ac24d6de3d',
            hashlib.sha256((HERE / 'controller14d.before.source').read_bytes()).hexdigest())
        self.assertEqual('edc5e5f7bd235c90462cf908be2b6d3afc56d75d85fe4f244509dadd315d7b76',
            hashlib.sha256((HERE / 'controller.edc5.before.source').read_bytes()).hexdigest())
        self.assertEqual(controller.RETENTION_SHA, hashlib.sha256((HERE / 'ordinary_retention.py').read_bytes()).hexdigest())
        self.assertEqual(controller.CRITICAL['agent_tools/ssh_transport.py'], hashlib.sha256(Path(ssh_transport.__file__).read_bytes()).hexdigest())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)

    def remote(self, result_callback, *, old=False, guard=lambda: None, prepare=None):
        node = nested(OLD if old else NEW, 'remote')
        template = ast.parse('def make(t,root,operation,deadline,retention,guard,public_observation_root,host):\n public_observation_serial=0\n return None\n').body[0]
        template.body[-1:] = [node, ast.Return(value=ast.Name(id='remote', ctx=ast.Load()))]
        ast.fix_missing_locations(template)
        fake = SimpleNamespace(admitted_transport=prepare or (lambda *a, **k: nullcontext()),
            load_config=lambda *_: object(), build_ssh_argv=lambda *_: ['fixed-public-model'],
            run_ssh=lambda *a, **k: result_callback(),
            SubmittedResultReadinessChanged=ssh_transport.SubmittedResultReadinessChanged)
        ns = {'time': time, 'subprocess': subprocess, 'json': json,
              'retained_public_observation': controller.retained_public_observation}
        exec(compile(ast.Module(body=[template], type_ignores=[]), '<authentic-full-controller-remote>', 'exec'), ns)
        return ns['make'](fake, self.root, OP, time.monotonic() + 20, retention, guard, self.root, 'gateway')

    def test_all_public_remote_shapes_captured_and_not_misparsed_as_four_key_counter(self):
        values = [{'kind': 'ssh', 'uid': 1000, 'bootId': 'public-boot'},
                  {'owner': OWNER, 'binding': {'machine': 'public-machine'}, 'generation': [1, 2],
                   'programSha256': 'b' * 64, 'lines': 7, 'executions': 1, 'terminal': False,
                   'ownerProcess': {'pid': 417}, 'stdio': {'0': '/dev/null'}},
                  {'operationId': OP, 'state': 'close-returned', 'returnCode': 0},
                  ['execution', '0', '1', '2']]
        queue = iter(values)
        raw = []
        def complete():
            value = next(queue)
            body = json.dumps(value).encode()
            raw.append(body)
            return subprocess.CompletedProcess(['PUBLIC_ARGV_NEVER_RETAIN'], 0, body, b'')
        remote = self.remote(complete)
        for index, expected in enumerate(values, 1):
            self.assertEqual(expected, remote('fixed public observation'))
            leaf = self.root / ('counter-%06d' % index)
            self.assertEqual(raw[-1], (leaf / 'stdout.bin').read_bytes())
            self.assertEqual(b'', (leaf / 'stderr.bin').read_bytes())
            receipt = json.loads((leaf / 'receipt.json').read_bytes())
            self.assertEqual(0, receipt['returnCode'])
            self.assertTrue(receipt['namedCustody'])
            self.assertNotIn('PUBLIC_ARGV', json.dumps(receipt))

    def test_authentic_old_nonzero_discards_current_retains_before_context_and_source_closing(self):
        result = subprocess.CompletedProcess(['public-model'], 23, b'public stdout', b'public stderr')
        with self.assertRaisesRegex(ValueError, 'owned_readonly_observation_failed'):
            self.remote(lambda: result, old=True)('fixed public observation')
        self.assertEqual([], list(self.root.iterdir()))
        events = []
        @contextmanager
        def admission(*args, **kwargs):
            events.append('admitted')
            yield
            self.assertEqual(result.stdout, (self.root / 'counter-000001/stdout.bin').read_bytes())
            events.append('context-closed-after-capture')
        with self.assertRaisesRegex(ValueError, 'owned_readonly_observation_failed'):
            self.remote(lambda: result, prepare=admission)('fixed public observation')
        self.assertEqual(['admitted', 'context-closed-after-capture'], events)
        self.assertEqual(23, json.loads((self.root / 'counter-000001/receipt.json').read_bytes())['returnCode'])

    def test_exact_current_transport_completed_result_taken_once_before_guard_refusal(self):
        result = subprocess.CompletedProcess(['public-model'], 29, b'completed public body', b'completed public diagnostic')
        error = ssh_transport.SubmittedResultReadinessChanged(readiness.ReadinessBlocked('public_test_change', OP), result)
        calls = []
        def completed_but_guard_refused():
            calls.append('one-call')
            raise error
        with self.assertRaisesRegex(ValueError, 'completed_public_observation_readiness_refused'):
            self.remote(completed_but_guard_refused)('fixed public observation')
        self.assertEqual(['one-call'], calls)
        self.assertEqual(result.stdout, (self.root / 'counter-000001/stdout.bin').read_bytes())
        with self.assertRaisesRegex(ValueError, 'already_consumed'):
            error.take_submitted_result()

    def test_transport_context_closing_refusal_cannot_discard_completed_public_result(self):
        result = subprocess.CompletedProcess(['public-model'], 0, b'{"public":true}', b'')
        @contextmanager
        def context_refuses(*args, **kwargs):
            yield
            raise ValueError('modeled_context_closing_refusal')
        with self.assertRaisesRegex(ValueError, 'modeled_context_closing_refusal'):
            self.remote(lambda: result, old=True, prepare=context_refuses)('fixed public observation')
        self.assertEqual([], list(self.root.iterdir()))
        with self.assertRaisesRegex(ValueError, 'modeled_context_closing_refusal'):
            self.remote(lambda: result, prepare=context_refuses)('fixed public observation')
        self.assertEqual(result.stdout, (self.root / 'counter-000001/stdout.bin').read_bytes())
        self.assertEqual(0, json.loads((self.root / 'counter-000001/receipt.json').read_bytes())['returnCode'])

    def test_exact_normal_sdk_records_and_wrong_identity_or_unclosed_terminal_refused(self):
        good = records(running())
        self.assertEqual(running(), controller.exact_normal_sdk_status(good, OP, 'gateway', SHA, 501))
        mutations = [('client-intent.json', 'clientPid', 502), ('client-intent.json', 'serverSha256', 'f' * 64),
                     ('call-intent-00000000.json', 'operationId', 'wrong'),
                     ('client-result.json', 'attemptedToolCalls', True),
                     ('client-result.json', 'allRelayAttemptsClosed', False),
                     ('call-result-00000000.json', 'isError', True)]
        for name, key, value in mutations:
            changed = copy.deepcopy(good)
            changed[name][key] = value
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                controller.exact_normal_sdk_status(changed, OP, 'gateway', SHA, 501)

    def test_full_first_snapshot_gate_uses_new_sdk_status_after_admission_not_admission_as_running(self):
        # Preserve the actual fresh SDK callback body; only its spawn is a local
        # fixed-record model. No child/SDK/server/transport is started here.
        callback = nested(NEW, 'fresh_running_status')
        outer = ast.parse('def make(start_client,operation,host,deadline,holders,guard,server_sha):\n running_deadline=deadline\n status_serial=0\n status_client_dirs=[]\n return None\n').body[0]
        outer.body[-1:] = [callback, ast.Return(value=ast.Name(id='fresh_running_status', ctx=ast.Load()))]
        ast.fix_missing_locations(outer)
        observed = [running(reason='original_owner_not_yet_observed', remoteOwner=None),
                    {key: value for key, value in running().items() if key != 'remoteState'}, running()]
        events, holders = [], []
        self.addCleanup(lambda: [held.close() for held in reversed(holders)])
        def start_client(label, action, filename, *, follow=True, caller_deadline=None):
            self.assertEqual(('program-status', 'identity.json', False), (action, filename, follow))
            events.append('normal-status')
            directory = self.root / label
            directory.mkdir(mode=0o700)
            pid = 501 + len(events)
            for name, value in records(observed[len(events) - 1], pid=pid).items():
                controller.save(directory / name, value)
            return SimpleNamespace(pid=pid, returncode=0, wait=lambda **kw: 0), directory
        ns = {'time': time, 'json': json, 'SourceHold': controller.SourceHold,
              'exact_normal_sdk_status': controller.exact_normal_sdk_status, 'SDK_RPC_SECONDS': controller.SDK_RPC_SECONDS}
        exec(compile(ast.Module(body=[outer], type_ignores=[]), '<full-controller-sdk-callback>', 'exec'), ns)
        fresh = ns['make'](start_client, OP, 'gateway', time.monotonic() + 40, holders,
                          lambda: [held.guard() for held in holders], SHA)
        directory = self.root / 'original-local-admission'
        directory.mkdir()
        (directory / 'remote-admission.json').write_text('{}')
        names = {'running_deadline', 'running_proof', 'running_owner', 'before'}
        gate = []
        for node in body(NEW):
            if (isinstance(node, ast.Assign) and not (isinstance(node.value, ast.Constant) and node.value.value is None)
                    and any(isinstance(t, ast.Name) and t.id in names for t in node.targets)):
                gate.append(node)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call) and node.value.args and any(
                    isinstance(n, ast.Constant) and n.value == 'program_remote_admission_missing' for n in ast.walk(node)):
                gate.append(node)
        self.assertEqual(5, len(gate))
        def active_after(_):
            events.append('counter')
            return {'owner': OWNER}
        namespace = {'time': time, 'directory': directory, 'deadline': time.monotonic() + 40,
                     'operation': OP, 'host': 'gateway', 'retention': retention,
                     'fresh_running_status': fresh, 'until': lambda predicate, *_: predicate(), 'active_after': active_after}
        exec(compile(ast.Module(body=gate, type_ignores=[]), '<full-controller-first-gate>', 'exec'), namespace)
        self.assertEqual(['normal-status', 'normal-status', 'normal-status', 'counter'], events)
        self.assertEqual(OWNER, namespace['running_owner'])

    def test_frozen_owned_fault_and_full_stream_cli_checks_preserved_without_executing_them(self):
        names = {'fingerprint', 'save', 'read', 'until', 'SourceHold', 'Proxy', 'finish_local_scope'}
        old = {node.name: ast.dump(node, include_attributes=False) for node in OLD.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names}
        new = {node.name: ast.dump(node, include_attributes=False) for node in NEW.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names}
        self.assertEqual(old, new)
        literals = lambda tree: {target.id: node.value.value for node in tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) for target in node.targets if isinstance(target, ast.Name)}
        self.assertEqual(literals(OLD)['NESTED_CLOSE'], literals(NEW)['NESTED_CLOSE'])
        source = (HERE / 'controller.py').read_text()
        for marker in ('complete_retained_streams_missing', 'cli_schema_not_equivalent', 'new_job_submission_not_once',
                       'counter_not_continuous_once', 'remote_owner_changed', 'terminal_ack_fault_not_observed'):
            self.assertIn(marker, source)
        self.assertNotIn('61bd241b-5633-46d8-9a7f-0e90d74bf5c0', controller.NEW_OPERATIONS.values())
        self.assertEqual(Path(__file__).resolve().parents[4], controller.CHECKOUT)

    def test_snapshot_refuses_before_running_proof_and_refuses_different_observed_owner(self):
        node = nested(NEW, 'snapshot')
        calls = []
        value = {'owner': {'pid': 999, 'birth': 'linux:9999'}, 'binding': {}, 'lines': 7}
        namespace = {'running_owner': None, 'counter': '/public/counter', 'remote_root': '/public/job',
                     'operation': OP, 'remote': lambda code: calls.append('one-public-call') or value}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<actual-controller-snapshot>', 'exec'), namespace)
        with self.assertRaisesRegex(ValueError, 'before_normal_sdk_running'):
            namespace['snapshot']()
        self.assertEqual([], calls)
        namespace['running_owner'] = OWNER
        with self.assertRaisesRegex(ValueError, 'not_normal_sdk_owner'):
            namespace['snapshot']()
        self.assertEqual(['one-public-call'], calls)

class DeadlineFenceTests(unittest.TestCase):
    """Executes authentic old/current ASTs with fixed local callbacks, never children."""
    def setUp(self):
        self.assertEqual('edc5e5f7bd235c90462cf908be2b6d3afc56d75d85fe4f244509dadd315d7b76',
                         hashlib.sha256((HERE / 'controller.edc5.before.source').read_bytes()).hexdigest())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)

    def callback(self, tree, start, clock, *, deadline=700, running_deadline=130, guard=lambda: None):
        node = nested(tree, 'fresh_running_status')
        factory = ast.parse('def make(start_client,operation,host,deadline,running_deadline,holders,guard,server_sha):\n status_serial=0\n status_client_dirs=[]\n return None\n').body[0]
        factory.body[-1:] = [node, ast.Return(value=ast.Name(id='fresh_running_status', ctx=ast.Load()))]
        ast.fix_missing_locations(factory)
        ns = {'time': clock, 'json': json, 'SourceHold': controller.SourceHold,
              'SDK_RPC_SECONDS': controller.SDK_RPC_SECONDS,
              'exact_normal_sdk_status': controller.exact_normal_sdk_status}
        exec(compile(ast.Module(body=[factory], type_ignores=[]), '<actual-edc5-current-status-deadline>', 'exec'), ns)
        holders = []
        self.addCleanup(lambda: [held.close() for held in reversed(holders)])
        return ns['make'](start, OP, 'gateway', deadline, running_deadline, holders, guard, SHA)

    def test_actual_edc5_status_spent_budget_started_child_current_stops_before_child(self):
        clock = SimpleNamespace(monotonic=lambda: 100)
        for tree, old in ((DEADLINE_BEFORE, True), (NEW, False)):
            calls = []
            def start(*args, **kwargs):
                calls.append((args, kwargs))
                return SimpleNamespace(), self.root
            fn = self.callback(tree, start, clock, deadline=99, running_deadline=99)
            with self.assertRaisesRegex(ValueError, 'fresh_status_.*deadline|fresh_status_rpc_budget_exhausted'):
                fn('program-status', {'host': 'gateway', 'identity': {'operationId': OP}})
            self.assertEqual(1 if old else 0, len(calls))

    def test_status_uses_gate_deadline_for_spawn_and_wait_without_replacement_on_timeout(self):
        for tree, old in ((DEADLINE_BEFORE, True), (NEW, False)):
            calls, waits = [], []
            def start(label, action, filename, **kw):
                calls.append((action, filename, kw))
                def wait(**args):
                    waits.append(args['timeout'])
                    raise subprocess.TimeoutExpired('fixed-public-status', args['timeout'])
                return SimpleNamespace(wait=wait), self.root
            fn = self.callback(tree, start, SimpleNamespace(monotonic=lambda: 100), running_deadline=125)
            with self.assertRaises(subprocess.TimeoutExpired):
                fn('program-status', {'host': 'gateway', 'identity': {'operationId': OP}})
            self.assertEqual([('program-status', 'identity.json', {'follow': False} if old else
                               {'follow': False, 'caller_deadline': 125})], calls)
            self.assertEqual([60] if old else [25], waits)
            self.assertNotIn('program-start', [item[0] for item in calls])

    def test_guard_cost_rechecked_before_status_child_and_wrong_request_zero_calls(self):
        now, calls = [100], []
        fn = self.callback(NEW, lambda *a, **k: calls.append('forbidden-child'),
                           SimpleNamespace(monotonic=lambda: now[0]), running_deadline=120,
                           guard=lambda: now.__setitem__(0, 106))
        with self.assertRaisesRegex(ValueError, 'fresh_status_rpc_budget_exhausted'):
            fn('program-status', {'host': 'gateway', 'identity': {'operationId': OP}})
        with self.assertRaisesRegex(ValueError, 'fresh_status_request_changed'):
            fn('program-start', {'host': 'gateway', 'identity': {'operationId': OP}})
        self.assertEqual([], calls)

    def sdk_start(self, tree, *, scenario, old):
        root = self.root / (scenario + ('-old' if old else '-fixed'))
        root.mkdir(mode=0o700)
        now, calls, streams, guard_calls = [100], [], [], []
        class ChildBoundary(Exception): pass
        def popen(*args, **kwargs):
            calls.append((args, kwargs))
            raise ChildBoundary('fixed-public-Popen-boundary')
        def guard():
            guard_calls.append('source-guard')
            if scenario == 'source-cost':
                now[0] += 6
        real_open = open
        def controlled_open(*args, **kwargs):
            stream = real_open(*args, **kwargs)
            streams.append(stream)
            if scenario == 'preparation-cost':
                now[0] += 2
            return stream
        factory = ast.parse('def make(deadline,root,guard,python,server_sha,host,operation,clients,keeper):\n return None\n').body[0]
        factory.body[-1:] = [nested(tree, 'start_client'), ast.Return(value=ast.Name(id='start_client', ctx=ast.Load()))]
        ast.fix_missing_locations(factory)
        ns = {'time': SimpleNamespace(monotonic=lambda: now[0]), 'os': os, 'open': controlled_open,
              'subprocess': SimpleNamespace(Popen=popen, DEVNULL=subprocess.DEVNULL),
              'SDK_RPC_SECONDS': controller.SDK_RPC_SECONDS, 'save': controller.save}
        exec(compile(ast.Module(body=[factory], type_ignores=[]), '<whole-edc5-current-SDK-start>', 'exec'), ns)
        start = ns['make'](120, root, guard, 'fixed-python', SHA, 'gateway', OP, [], SimpleNamespace())
        try:
            if old or scenario != 'gate-cost':
                start('local-status', 'program-status', 'identity.json', follow=False)
            else:
                start('local-status', 'program-status', 'identity.json', follow=False, caller_deadline=114)
        except (ValueError, ChildBoundary) as error:
            result = error
        else:
            self.fail('controlled Popen boundary or explicit deadline refusal required')
        closed_before_cleanup = all(stream.closed for stream in streams)
        for stream in streams:
            if not stream.closed:
                stream.close()
        return calls, result, closed_before_cleanup, guard_calls

    def test_whole_edc5_guard_cost_and_actual_output_preparation_cost_red_current_no_child_green(self):
        for scenario in ('source-cost', 'preparation-cost'):
            with self.subTest(scenario=scenario):
                old_calls, old_error, _, _ = self.sdk_start(DEADLINE_BEFORE, scenario=scenario, old=True)
                self.assertEqual(1, len(old_calls))
                self.assertEqual('fixed-public-Popen-boundary', str(old_error))
                calls, error, closed, _ = self.sdk_start(NEW, scenario=scenario, old=False)
                self.assertEqual([], calls)
                self.assertRegex(str(error), 'sdk_rpc_budget_exhausted_before_')
                self.assertTrue(closed, 'all own opened log descriptors close on refused child')

    def test_status_subdeadline_shorter_than_global_prevents_sdk_preparation(self):
        calls, error, closed, guards = self.sdk_start(NEW, scenario='gate-cost', old=False)
        self.assertEqual([], calls)
        self.assertEqual('sdk_rpc_budget_exhausted_before_preparation', str(error))
        self.assertTrue(closed)
        self.assertEqual(['source-guard'], guards)
        self.assertEqual([], list((self.root / 'gate-cost-fixed').iterdir()))

    def test_positive_remaining_preserves_one_child_boundary_and_exact_follow_budget(self):
        calls, error, closed, guards = self.sdk_start(NEW, scenario='healthy', old=False)
        self.assertEqual(1, len(calls))
        argv = calls[0][0][0]
        self.assertEqual('20', argv[argv.index('--follow-seconds') + 1])
        self.assertEqual('program-status', argv[argv.index('--action') + 1])
        self.assertIn('--no-follow', argv)
        self.assertTrue(closed)
        self.assertEqual(2, len(guards))

    def test_whole_edc5_cli_guard_spent_budget_red_current_no_child_green(self):
        for spent_initially in (False, True):
            for tree, old in ((DEADLINE_BEFORE, True), (NEW, False)):
                with self.subTest(spent_initially=spent_initially, old=old):
                    calls, now = [], [100]
                    class ChildBoundary(Exception): pass
                    def popen(*args, **kw):
                        calls.append('child')
                        raise ChildBoundary('fixed-public-CLI-boundary')
                    node = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'bounded_cli'))
                    ns = {'os': os, 'time': SimpleNamespace(monotonic=lambda: now[0]), 'SDK_RPC_SECONDS': 15,
                          'subprocess': SimpleNamespace(Popen=popen, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE)}
                    exec(compile(ast.Module(body=[node], type_ignores=[]), '<whole-edc5-current-CLI>', 'exec'), ns)
                    def guard(): now.__setitem__(0, 106)
                    args = (['fixed-public-collect'], self.root, 99 if spent_initially else 120, SimpleNamespace(), OP)
                    with self.assertRaises(ChildBoundary if old else ValueError):
                        ns['bounded_cli'](*args, **({} if old else {'source_guard': guard}))
                    self.assertEqual(['child'] if old else [], calls)

    def test_expected_rpc15_is_actual_pinned_sdk_request_and_cli_default(self):
        checkout = controller.CHECKOUT
        path = checkout / 'agent_tools/ssh_program_mcp_client.py'
        self.assertEqual(controller.CRITICAL['agent_tools/ssh_program_mcp_client.py'], hashlib.sha256(path.read_bytes()).hexdigest())
        tree = ast.parse(path.read_bytes())
        selected = [copy.deepcopy(n) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ACTIONS' for t in n.targets)]
        selected += [copy.deepcopy(n) for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'request']
        import re, uuid
        ns = {'re': re, 'uuid': uuid}
        exec(compile(ast.Module(body=selected, type_ignores=[]), '<actual-pinned-SDK-request>', 'exec'), ns)
        actual = ns['request']('program-status', 'gateway', {'operationId': OP})
        self.assertEqual(records(running())['client-intent.json']['request'], actual)
        self.assertEqual(controller.SDK_RPC_SECONDS, actual['timeout_seconds'])
        cli = ast.parse((checkout / 'agent_tools/mcp_server.py').read_bytes())
        nodes = [n for n in ast.walk(cli) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == 'ssh_parser'
                 and n.func.attr == 'add_argument' and n.args and isinstance(n.args[0], ast.Constant)
                 and n.args[0].value == '--timeout-seconds']
        self.assertEqual(1, len(nodes))
        default = next(k.value for k in nodes[0].keywords if k.arg == 'default')
        self.assertEqual(controller.SDK_RPC_SECONDS, ast.literal_eval(default))
        request = records(running())
        request['client-intent.json']['request']['timeout_seconds'] = 14
        with self.assertRaises(ValueError):
            controller.exact_normal_sdk_status(request, OP, 'gateway', SHA, 501)

    def test_only_one_original_start_site_and_status_never_restarts(self):
        calls = [n for n in ast.walk(NEW) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id == 'start_client' and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant)
                 and n.args[1].value == 'program-start']
        self.assertEqual(1, len(calls))
        for node in ast.walk(nested(NEW, 'fresh_running_status')):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'start_client':
                self.assertEqual('program-status', ast.literal_eval(node.args[1]))


class AbsoluteAdmissionDeadlineTests(unittest.TestCase):
    def test_actual_complete_4674_main_prepares_after_spent_outer_deadline_current_zero_effects(self):
        import builtins, math
        before = (HERE / 'controller.4674.before.source').read_bytes()
        self.assertEqual('46748882bd73fd27b51ccb03e33da057749b7e805c4b20b8b3634310e3a77660', hashlib.sha256(before).hexdigest())
        for tree, old in ((ast.parse(before), True), (NEW, False)):
            effects = []
            class PreparationBoundary(Exception): pass
            def forbid_import(*args, **kwargs):
                effects.append('agent-module-preparation')
                raise PreparationBoundary('controlled-preparation-boundary')
            node = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main'))
            scope = {'HERE': HERE, 'time': SimpleNamespace(monotonic=lambda: 100), 'math': math,
                     'sys': SimpleNamespace(path=SimpleNamespace(insert=lambda *args: effects.append('path-preparation'))),
                     '__builtins__': {**vars(builtins), '__import__': forbid_import}}
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<actual-whole-controller-absolute-budget>', 'exec'), scope)
            args = SimpleNamespace(mode='direct', budget=600, native_go=True)
            with self.assertRaises(PreparationBoundary if old else ValueError):
                scope['main'](args, **({} if old else {'absolute_deadline': 99}))
            self.assertEqual(['path-preparation','agent-module-preparation'] if old else [], effects)

    def test_optional_absolute_deadline_invalid_or_expired_never_reaches_preparation(self):
        import math
        for value in (True, False, '99', float('nan'), float('inf'), -1, 0, 99):
            effects = []
            node = copy.deepcopy(next(n for n in NEW.body if isinstance(n, ast.FunctionDef) and n.name == 'main'))
            scope = {'HERE': HERE, 'time': SimpleNamespace(monotonic=lambda: 100), 'math': math,
                     'sys': SimpleNamespace(path=SimpleNamespace(insert=lambda *args: effects.append('forbidden')))}
            exec(compile(ast.Module(body=[node], type_ignores=[]), '<actual-absolute-deadline-validation>', 'exec'), scope)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'local_owner_absolute_deadline_'):
                scope['main'](SimpleNamespace(mode='direct',budget=600,native_go=True), absolute_deadline=value)
            self.assertEqual([],effects)


if __name__ == '__main__':
    unittest.main()
