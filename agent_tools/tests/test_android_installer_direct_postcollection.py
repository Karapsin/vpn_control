"""Actual direct start/observe functions; every transport dependency is inert.

The owner source is parsed, and only its public decisions/callers are executed.
No native launcher or protected constructor is imported. The fixed transport
returns one fake original child, raw submission and EOF tuple; it never starts
a child. TempFS is used solely for an empty own capsule and is always removed.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
import uuid


OWNER = Path(__file__).resolve().parents[1] / 'android_installer_direct_transport.py'
CORRELATION = '8c661a6c-c8f2-4f69-b7d9-a795ff2e439e'
BOOT = '03315797-fc18-465b-bc43-f4400dcc1497'
FUNCTIONS = {'require', 'canonical', 'equal', 'sha', 'correlation',
             'submission_shape', 'start', 'observe', 'status', '_postcollection_unknown'}
AUDIT = []


class Case:
    def __init__(self, *, publication_error=None, guard_failure=None,
                 transport_reason=None, malformed=False):
        self.tmp = tempfile.TemporaryDirectory(
            dir=os.environ.get('CONTROL_OUTPUT_DIR'), prefix='own-direct-postcollection-')
        self.root = Path(self.tmp.name)
        self.capsule = self.root / 'capsule'
        self.capsule.mkdir(mode=0o700)
        self.child = types.SimpleNamespace(pid=401, returncode=0, poll=lambda: 0)
        self.children = []
        self.publications = []
        self.guard_calls = 0
        self.transport_calls = 0
        self.publication_error = publication_error
        self.source_error = ValueError('direct_source_changed')
        self.guard_failure = guard_failure
        self.primary = publication_error or (
            self.source_error if guard_failure else None)
        self.transport_reason = transport_reason
        self.malformed = malformed
        self.accepted = {
            'state': 'submitted',
            'correlationId': str(uuid.uuid5(uuid.UUID(CORRELATION),
                                          'complete-update-direct-worker')),
            'pid': 701, 'identity': {'pid': 701, 'startTicks': 17, 'bootId': BOOT},
            'workerSha256': hashlib.sha256(b'PUBLIC_WORKER').hexdigest(),
            'replayAllowed': False,
        }
        self.status_calls = 0
        self.transport_raw = None
        self.current_function = None
        self.observed = {'state': 'unknown', 'reason': 'PUBLIC_OBSERVATION',
                         'replayAllowed': False}
        self.effect_attempts = []
        self.source_raw = OWNER.read_bytes()
        tree = ast.parse(self.source_raw)
        selected = [n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
        if ({n.name for n in selected} not in (FUNCTIONS, FUNCTIONS - {'_postcollection_unknown'})
                or len(selected) != len({n.name for n in selected})):
            raise AssertionError('actual_public_owner_functions_changed')
        self.ns = {'hashlib': hashlib, 'json': json, 'uuid': uuid, 'Path': Path,
                   'os': types.SimpleNamespace(path=types.SimpleNamespace(
                       lexists=self.lexists)),
                   'subprocess': types.SimpleNamespace(Popen=self.forbidden),
                   'socket': types.SimpleNamespace(socket=self.forbidden)}
        exec(compile(ast.Module(body=selected, type_ignores=[]),
                     str(OWNER), 'exec', dont_inherit=True), self.ns)
        self.ns.update({
            'prepared_program': self.prepare,
            'intent_host_binding': lambda intent: {'publicFixture': True},
            'bootstrap_source': lambda *args: 'PUBLIC_BOOTSTRAP',
            'fixed_ssh_argv': lambda *args: ('INERT-NO-EXEC',),
            '_source_guard': self.guard,
            'framed_program': lambda source: b'PUBLIC_FRAME',
            '_transport_capture': self.transport,
            'write_once': self.publish,
            'host_observation_source': lambda *args: 'PUBLIC_HOST',
            'observer_source': lambda *args: b'PUBLIC_OBSERVER',
            'original_journal_source': lambda *args: b'PUBLIC_JOURNAL_READER',
            '_observer_frame_reader': lambda *args: 'PUBLIC_READER_FRAME',
            'project_original_capture': lambda *args: {'publicProjection': True},
        })

    def forbidden(self, *args, **kwargs):
        self.effect_attempts.append('forbidden-native-effect')
        raise AssertionError('all_native_process_network_private_effects_forbidden')

    def lexists(self, path):
        if Path(path) == self.capsule / 'start-dispatch.json':
            return self.current_function == 'status'
        if Path(path) == self.capsule / 'actor-original.json':
            return False
        return self.forbidden()

    def prepare(self, root, corr):
        if Path(root) != self.root or corr != CORRELATION:
            raise AssertionError('fixed_fixture_crossed')
        return self.capsule, {'remoteRoot': '/SYNTHETIC_PUBLIC',
                             'sources': {'publicSource': True},
                             'packet': {'publicPacket': True}}, b'PUBLIC_WORKER'

    def guard(self, root, pins):
        self.guard_calls += 1
        if Path(root) != self.root or pins != {'publicSource': True}:
            raise AssertionError('source_guard_fixture_crossed')
        if self.guard_calls == self.guard_failure:
            raise self.source_error

    def transport(self, capsule, argv, frame, role, root, pins, program_sha):
        self.transport_calls += 1
        if self.transport_calls != 1 or Path(capsule) != self.capsule:
            raise AssertionError('original_transport_replay_or_crossing')
        self.children.append(self.child)
        raw = (self.accepted if role == 'start' else self.observed).copy()
        if role.startswith('status-'):
            raw = {'state': 'original-observed', 'supervisor': {'publicSupervisor': True},
                   'actorAccepted': self.accepted, 'actorCustody': {'publicCustody': True},
                   'collector': {'state': 'terminal'},
                   'raw': [{'channel': 'stdout', 'bodyBase64': 'UFVCTElD',
                            'bytes': 6, 'sha256': hashlib.sha256(b'PUBLIC').hexdigest()}],
                   'replayAllowed': False}
        if role == 'start' and self.malformed:
            raw['pid'] = True
        self.transport_raw = json.dumps(raw).encode()
        return self.child, self.transport_raw, b'', {
            'stdout': True, 'stderr': True}, self.transport_reason

    def publish(self, capsule, name, raw):
        if Path(capsule) != self.capsule or name not in ('accepted.json', 'actor-original.json'):
            raise AssertionError('only_fixed_accepted_publication_allowed')
        self.publications.append((name, json.loads(raw)))
        if self.publication_error is not None:
            raise self.publication_error
        return {'sha256': hashlib.sha256(raw).hexdigest(), 'generation': [1] * 9}

    def call(self, function):
        result = error = None
        self.current_function = function
        try:
            if function == 'start':
                result = self.ns['start'](self.root, CORRELATION)
            elif function == 'observe':
                result = self.ns['observe'](self.root, CORRELATION,
                                            self.accepted, {'publicCustody': True})
            elif function == 'status':
                # Native observation is a distinct future route. These controls
                # end before it on refusal; a success control uses one inert stub.
                def observe_without_route(*args, **kwargs):
                    self.status_calls += 1
                    return self.observed.copy()
                self.ns['observe'] = observe_without_route
                result = self.ns['status'](self.root, CORRELATION)
            else:
                raise AssertionError('only_actual_fixed_callers')
        except BaseException as caught:
            error = caught
        AUDIT.append({'function': function,
                      'sourceSha256': hashlib.sha256(self.source_raw).hexdigest(),
                      'transportCalls': self.transport_calls,
                      'nestedStatusObserverCalls': self.status_calls,
                      'guardCalls': self.guard_calls,
                      'childWasExactOriginal': not self.children or self.children == [self.child],
                      'originalChildPid': self.child.pid if self.children else None,
                      'publicationNames': [name for name, _ in self.publications],
                      'result': result,
                      'originalDiagnosticClass': type(self.primary).__name__ if self.primary else None,
                      'escapedErrorClass': type(error).__name__ if error else None,
                      'escapedErrorIsOriginal': error is self.primary if error else None,
                      'forbiddenEffectAttempts': self.effect_attempts[:],
                      'realChildCalls': 0, 'networkCalls': 0, 'privateReads': 0})
        return result, error

    def close(self):
        self.tmp.cleanup()


class PostCollectionFacts(unittest.TestCase):
    def case(self, **kwargs):
        value = Case(**kwargs)
        self.addCleanup(value.close)
        return value

    def assert_unknown(self, case, result, error, reason, original_remote=False):
        self.assertIsNone(error, 'original accepted child must survive publication/closing refusal')
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['localPid'], case.child.pid)
        self.assertIs(result['replayAllowed'], False)
        self.assertIs(result['nativeAcceptance'], False)
        self.assertEqual(result['reason'], reason)
        self.assertEqual(result['exceptionClass'], type(case.primary).__name__)
        self.assertIs(case.children[0], case.child)
        self.assertEqual(case.transport_calls, 1)
        self.assertFalse(case.effect_attempts)
        facts = result['localTransport']
        self.assertEqual(facts, {'returncode': case.child.returncode,
                                'stdoutBytes': len(case.transport_raw),
                                'stdoutSha256': hashlib.sha256(case.transport_raw).hexdigest(),
                                'stderrBytes': 0,
                                'stderrSha256': hashlib.sha256(b'').hexdigest(),
                                'eof': {'stdout': True, 'stderr': True}})
        if original_remote:
            self.assertEqual(result['originalRemotePid'], case.accepted['pid'])

    def test_start_accepted_publication_failure_keeps_child_unknown(self):
        for primary in (OSError('PUBLIC_DENIED_JOURNAL'), ValueError('PUBLIC_DENIED_JOURNAL')):
            with self.subTest(exception=type(primary).__name__):
                case = self.case(publication_error=primary)
                result, error = case.call('start')
                self.assert_unknown(case, result, error,
                                    'direct_accepted_journal_publication_failed', True)
                self.assertEqual([n for n, _ in case.publications], ['accepted.json'])

    def test_accepted_publication_refusal_remains_primary_when_closing_also_refuses(self):
        case = self.case(publication_error=OSError('PUBLIC_FIRST_JOURNAL_REFUSAL'),
                         guard_failure=2)
        result, error = case.call('start')
        self.assert_unknown(case, result, error,
                            'direct_accepted_journal_publication_failed', True)
        self.assertEqual(case.guard_calls, 2, 'closing must still be attempted after journal refusal')
        self.assertEqual(result['secondaryExceptionClass'], 'ValueError')

    def test_start_postcollection_source_failure_keeps_child_unknown(self):
        case = self.case(guard_failure=2)
        result, error = case.call('start')
        self.assert_unknown(case, result, error, 'direct_postcollection_source_unknown', True)
        self.assertEqual(case.guard_calls, 2)
        self.assertEqual([n for n, _ in case.publications], ['accepted.json'])

    def test_observe_postcollection_source_failure_keeps_child_unknown(self):
        case = self.case(guard_failure=2)
        result, error = case.call('observe')
        self.assert_unknown(case, result, error, 'direct_postcollection_source_unknown')
        self.assertEqual(case.guard_calls, 2)
        self.assertFalse(case.publications)

    def test_normal_callers_are_unchanged(self):
        start = self.case()
        result, error = start.call('start')
        self.assertIsNone(error)
        self.assertEqual(result, {'state': 'submitted', 'correlationId': CORRELATION,
                                 'localPid': 401, 'originalRemotePid': 701,
                                 'replayAllowed': False, 'nativeAcceptance': False})
        self.assertEqual(start.publications[0][1]['remote'], start.accepted)
        observe = self.case()
        result, error = observe.call('observe')
        self.assertIsNone(error)
        self.assertEqual(result, observe.observed)

    def test_transport_unknown_keeps_child_without_accepted_publication(self):
        for function in ('start', 'observe'):
            with self.subTest(function=function):
                case = self.case(transport_reason='direct_journal_publication_failed')
                result, error = case.call(function)
                self.assertIsNone(error)
                self.assertEqual(result, {'state': 'unknown', 'correlationId': CORRELATION,
                                         'localPid': 401, 'replayAllowed': False})
                self.assertFalse(case.publications)
                self.assertIs(case.children[0], case.child)
                self.assertEqual(case.transport_calls, 1)

    def test_presubmission_source_failure_does_not_invent_child(self):
        for function in ('start', 'observe'):
            with self.subTest(function=function):
                case = self.case(guard_failure=1)
                result, error = case.call(function)
                self.assertIsNone(result)
                self.assertIs(error, case.source_error)
                self.assertEqual(case.transport_calls, 0)
                self.assertFalse(case.children)
                self.assertFalse(case.publications)

    def test_status_postcollection_source_failure_keeps_original_tuple_unknown(self):
        case = self.case(guard_failure=1)
        result, error = case.call('status')
        self.assert_unknown(case, result, error, 'direct_postcollection_source_unknown')
        self.assertEqual(case.guard_calls, 1)
        self.assertFalse(case.publications)
        self.assertEqual(case.status_calls, 0)

    def test_status_actor_original_publication_failure_keeps_original_tuple_unknown(self):
        for primary in (OSError('PUBLIC_DENIED_ACTOR_JOURNAL'),
                        ValueError('PUBLIC_DENIED_ACTOR_JOURNAL')):
            with self.subTest(exception=type(primary).__name__):
                case = self.case(publication_error=primary)
                result, error = case.call('status')
                self.assert_unknown(case, result, error,
                                    'direct_original_actor_publication_failed')
                self.assertEqual([n for n, _ in case.publications], ['actor-original.json'])
                self.assertEqual(case.guard_calls, 2, 'final source closing must still be attempted')
                self.assertEqual(case.status_calls, 0)

    def test_status_final_source_failure_keeps_original_tuple_unknown(self):
        case = self.case(guard_failure=2)
        result, error = case.call('status')
        self.assert_unknown(case, result, error, 'direct_postcollection_source_unknown')
        self.assertEqual(case.guard_calls, 2)
        self.assertEqual(case.status_calls, 1)
        self.assertEqual([n for n, _ in case.publications], ['actor-original.json'])

    def test_status_actor_refusal_remains_primary_when_closing_also_refuses(self):
        case = self.case(publication_error=OSError('PUBLIC_FIRST_ACTOR_JOURNAL_REFUSAL'),
                         guard_failure=2)
        result, error = case.call('status')
        self.assert_unknown(case, result, error,
                            'direct_original_actor_publication_failed')
        self.assertEqual(result['secondaryExceptionClass'], 'ValueError')
        self.assertEqual(case.guard_calls, 2)
        self.assertEqual(case.status_calls, 0)

    def test_normal_status_is_unchanged(self):
        case = self.case()
        result, error = case.call('status')
        self.assertIsNone(error)
        original = json.loads(case.transport_raw)
        self.assertEqual(result, {'state': 'unknown', 'journal': case.observed,
                                 'collector': original['collector'], 'raw': original['raw'],
                                 'component': {'publicProjection': True},
                                 'nativeAcceptance': False, 'replayAllowed': False})
        self.assertEqual(case.status_calls, 1)
        self.assertEqual([n for n, _ in case.publications], ['actor-original.json'])
        self.assertEqual(case.guard_calls, 2)
        self.assertEqual(case.transport_calls, 1)

    def test_malformed_accepted_actor_stays_refused_without_publication(self):
        case = self.case(malformed=True)
        result, error = case.call('start')
        self.assertIsNone(result)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(error), 'direct_submission_unknown')
        self.assertEqual(case.transport_calls, 1)
        self.assertFalse(case.publications)


if __name__ == '__main__':
    unittest.main()
