"""Causal observer closure over whole sources and owned fixtures; no native authority."""
from pathlib import Path
import ast, base64, contextlib, copy, hashlib, io, json, os, re
import selectors, subprocess, sys, tempfile, time, types, unittest, uuid

ROOT = Path(__file__).resolve().parents[2]
RESOURCES = Path(__file__).resolve().parent / 'fixtures/android_terminal_observer_lifetime'
FIXED = ROOT / 'agent_tools/tests/fixtures/android_terminal_observer_lifetime/controller.fixed.source'
BEFORE = RESOURCES / 'controller-74c.before.source'
REMOTE = RESOURCES / 'remote-terminal-owned.source'
BEFORE_SHA = '74c60b99426fb73cf3ea5ef9ad69f097d723b30a0fca72796e45935b7e7e8552'
FIXED_SHA = 'ab09df502d6f8096cc7af753f8eedc0404d60fe25e144c8c48db92bd18168243'
REMOTE_SHA = 'afd06ca4bdd584587a7e4ab05954be902b35508c18acb42de8e616d065939725'
SEAL = {'configSha256': 'c' * 64, 'sourceManifestSha256': 'd' * 64, 'receiverSha256': 'e' * 64}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def controlled_remote_result():
    raw = REMOTE.read_bytes()
    assert sha(raw) == REMOTE_SHA
    return json.loads(raw)

def pure_namespace():
    raw = FIXED.read_bytes()
    assert sha(raw) == FIXED_SHA
    source = raw.decode()
    names = {'need', 'sha', 'canonical', 'unique', 'decode', 'terminal_unknown_observation', 'local_observation_result'}
    nodes = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == names
    ns = {'json': json, 'hashlib': hashlib, 'uuid': uuid, 're': re, 'SEAL': copy.deepcopy(SEAL)}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'actual-controller-terminal-observation-functions', 'exec'), ns)
    return ns

def controlled_context(ns):
    result = controlled_remote_result()
    ns['SEAL'] = {'configSha256': result['context']['controllerConfigSha256'],
                  'receiverSha256': result['preparation']['receiverSha256']}
    context = types.SimpleNamespace(config={'operationId': result['operationId'],
                  'localOperationId': '662fb6fd-6ec1-4ba6-9513-351992d8eac6',
                  'binding': copy.deepcopy(result['durable']['binding'])},
                  programme={'ownerProgramSha256': 'b' * 64})
    return context, result, copy.deepcopy(result['preparation']), copy.deepcopy(result['context']), result['receiver']['claimed']['payloadSha256']

def owner_control(source_path, out, mode):
    """Whole actual owner_main; only native context/transport are explicit seams."""
    import fcntl
    selected = Path(source_path).resolve()
    assert selected in {BEFORE.resolve(), FIXED.resolve()}, 'observer source outside finite fixture set'
    source = selected.read_bytes()
    assert sha(source) == (BEFORE_SHA if selected == BEFORE.resolve() else FIXED_SHA)
    before = sha(source) == BEFORE_SHA
    namespace = {'__name__': 'owned_whole_terminal_observer_control', '__CONTROLLER_SEAL__': copy.deepcopy(SEAL)}
    exec(compile(source, str(source_path), 'exec', dont_inherit=True), namespace)
    out = Path(out).resolve()
    out.chmod(0o700)
    namespace['OUT'] = out
    (out / 'remote_receiver.py').write_bytes(b'inert-controlled-receiver\n')
    (out / 'start-authority.json').write_bytes(b'controlled-distinct-start-authority\n')
    operation = controlled_remote_result()['operationId']
    original = controlled_remote_result()
    binding = copy.deepcopy(original['durable']['binding'])
    preparation = copy.deepcopy(original['preparation'])
    preparation['controllerConfigSha256'] = SEAL['configSha256']
    preparation['receiverSha256'] = SEAL['receiverSha256']
    lock_rows = []
    for index in range(3):
        path = out / ('owned-lock-' + str(index))
        namespace['save'](out, path.name, b'')
        custody = namespace['Custody']()
        try:
            custody.add(path, private=True, allow_empty=True, write=True)
            lock_rows.append({'path': str(path), 'pin': copy.deepcopy(custody.files[str(path)]['pin'])})
        finally:
            custody.close()
    holder = types.SimpleNamespace(config={'operationId': operation,
        'localOperationId': '662fb6fd-6ec1-4ba6-9513-351992d8eac6',
        'localBinding': {'target': 'owned-local-observation', 'machine': 'owned-machine',
                         'boot': 'owned-boot', 'account': str(os.geteuid())},
        'binding': binding, 'lockFiles': lock_rows, 'remoteRoot': original['preparation']['binding']['target'],
        'coverageBridgeQualified': True, 'originalSourceSha256': 'a' * 64},
        programme={'controllerSha256': 'a' * 64, 'ownerProgramSha256': 'b' * 64},
        sent=False, closed=False, calls=[], remote=None, closeCalls=0)
    holder.inputs = namespace['Custody']()
    holder.durable = types.SimpleNamespace(MachineBinding=types.SimpleNamespace(from_dict=lambda value: value),
                                           _binding_live=lambda value: None)
    holder.review = lambda *args: None
    holder.original = lambda: b'controlled-original-reader-source'
    holder.authority = lambda: {'controlled-reservations': 'still-held'}
    holder.input = lambda label: b'controlled-inert-input-' + label.encode()
    holder.capsule = lambda prefix: {'sha256': ('f' if prefix == 'installer' else 'e') * 64}
    holder.guard = lambda **kwargs: holder.inputs.guard()
    def close():
        holder.closeCalls += 1
        holder.inputs.close()
        holder.closed = True
    holder.close = close
    program, quick = b'controlled-inert-start-programme\n', b'controlled-inert-quick-observer\n'
    admission = canonical({'kind': 'controlled-preflight-outside-tested-decision', 'operationId': operation})
    holder.renderer = types.SimpleNamespace(observation_program=lambda *a, **k: 'controlled-observer',
        start_plan=lambda *a, **k: {'program': program, 'programSha256': sha(program),
                                  'launch': {'intentSha256': 'f' * 64}})
    def transaction(action, payload, prepared=None, **options):
        holder.calls.append(action)
        if action == 'prepare':
            value = {'state': 'prepared-not-submitted', 'preparation': preparation}
            return value, canonical(value), out
        if action == 'submit-once':
            assert holder.calls.count('submit-once') == 1
            holder.sent = True
            value = copy.deepcopy(original)
            value['preparation'] = copy.deepcopy(preparation)
            value['context'] = copy.deepcopy(payload['context'])
            value['receiver']['call'] = copy.deepcopy(payload['context'])
            value['receiver']['claimed'].update(receiverSha256=SEAL['receiverSha256'],
                controllerConfigSha256=SEAL['configSha256'], payloadSha256=sha(canonical(payload)),
                programSha256=sha(program))
            value['durable']['terminal']['programSha256'] = sha(program)
            if mode == 'running':
                value['durable']['state'] = 'running'
                value['durable'].pop('terminal')
            holder.remote = value
            return value, canonical(value), out
        assert action == 'observe', 'controlled owner attempted another native effect'
        return copy.deepcopy(holder.remote), canonical(holder.remote), out
    holder.transaction = transaction
    namespace['Context'] = lambda: holder
    namespace['machine'] = lambda: 'owned-machine'
    namespace['prepare_review'] = lambda c: {'scope': 'controlled-preparation-only'}
    namespace['sample_admission'] = lambda *a: ({}, admission)
    namespace['quick_source'] = lambda *a: quick
    def interval_collection(*args):
        if mode == 'collection-exception':
            raise OSError('owned_interval_collection_exception')
        if mode == 'collection-failure':
            return {'state': 'original-interval-report-collection-unknown', 'complete': False}
        return {'state': 'original-interval-reports-collected', 'complete': True}
    namespace['collect_interval_reports'] = interval_collection
    original_jsave = namespace['jsave']
    def jsave(path, name, value):
        if name == 'local-observation-unknown.json' and mode == 'publication-failure':
            raise OSError('owned_receipt_publication_failure')
        return original_jsave(path, name, value)
    namespace['jsave'] = jsave
    class EndControl(BaseException):
        pass
    wait_started = False
    def controlled_sleep(seconds):
        nonlocal wait_started
        if not wait_started:
            wait_started = True
            print(json.dumps({'stage': 'waiting', 'closed': holder.closed, 'calls': holder.calls}), flush=True)
            sys.stdin.buffer.read(1)
        raise EndControl()
    namespace['time'] = types.SimpleNamespace(sleep=controlled_sleep)
    try:
        namespace['owner_main']()
        state = 'returned'
    except SystemExit as error:
        state = 'observer-error-' + str(error.code)
    except EndControl:
        # Old owner and a genuinely RUNNING remote job still retain the locks
        # while this owned parent asks the control to finish cooperatively.
        return
    if mode == 'running':
        raise AssertionError('running original execution incorrectly closed observer')
    assert holder.closed and holder.closeCalls == 1
    assert holder.calls.count('submit-once') == 1 and 'observe' not in holder.calls
    assert holder.remote['state'] == 'unknown' and original == controlled_remote_result()
    print(json.dumps({'stage': 'done', 'state': state, 'closed': holder.closed,
                      'calls': holder.calls, 'closeCalls': holder.closeCalls,
                      'unknownReceipt': (out / 'local-observation-unknown.json').exists(),
                      'originalOutcomeUnmodified': True, 'beforeSource': before}), flush=True)
    sys.stdin.buffer.read(1)

class TerminalObservationTests(unittest.TestCase):
    def test_correlated_original_terminal_is_accepted_as_unknown_only(self):
        ns = pure_namespace()
        c, result, prepared, context, digest = controlled_context(ns)
        before = canonical(result)
        value = ns['terminal_unknown_observation'](c, result, prepared, context, digest)
        self.assertEqual(value['state'], 'unknown')
        self.assertEqual(value['vmOutcome'], 'unknown')
        self.assertTrue(value['localLocksMayClose'])
        self.assertFalse(value['claimsReleased'])
        self.assertFalse(value['guestAdmitted'])
        self.assertFalse(value['replayAllowed'])
        self.assertEqual(canonical(result), before)
        self.assertEqual(value['originalRemoteResult'], result)

    def test_foreign_partial_running_overflow_and_replay_metadata_refuse(self):
        changes = {
            'foreign-operation': lambda v: v.update(operationId=str(uuid.uuid4())),
            'foreign-root': lambda v: v['preparation'].update(rootGeneration=[1, 2]),
            'foreign-context': lambda v: v['context'].update(programSha256='0' * 64),
            'foreign-claim': lambda v: v['receiver']['claimed'].update(payloadSha256='0' * 64),
            'foreign-receiver': lambda v: v['receiver']['claimed'].update(receiverSha256='0' * 64),
            'foreign-binding': lambda v: v['durable']['binding'].update(boot='foreign'),
            'foreign-owner': lambda v: v['durable']['terminal']['owner'].update(pid=1),
            'foreign-program': lambda v: v['durable']['terminal'].update(programSha256='0' * 64),
            'running': lambda v: v['durable'].update(state='running'),
            'missing-terminal': lambda v: v['durable'].pop('terminal'),
            'open-streams': lambda v: v['durable']['terminal'].update(streamsClosed=False),
            'overflow': lambda v: v['durable']['terminal']['stderr'].update(overflow=True),
            'partial-output': lambda v: v['durable']['terminal']['stderr'].update(totalBytes=65536),
            'bad-digest': lambda v: v['durable']['terminal']['stderr'].update(sha256='bad'),
            'boolean-exit': lambda v: v['durable']['terminal'].update(exitCode=True),
            'replay': lambda v: v.update(replayAllowed=True),
            'outcome-changed': lambda v: v.update(originalOutcomesChanged=True),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                ns = pure_namespace()
                c, result, prepared, context, digest = controlled_context(ns)
                result = copy.deepcopy(result)
                mutate(result)
                with self.assertRaises((ValueError, KeyError)):
                    ns['terminal_unknown_observation'](c, result, prepared, context, digest)

    def test_fresh_local_status_and_collect_preserve_original_unknown(self):
        ns = pure_namespace()
        c, remote, prepared, context, digest = controlled_context(ns)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory).resolve()
            ns['OUT'] = out
            marker = ns['terminal_unknown_observation'](c, remote, prepared, context, digest)
            submitted = {'operationId': c.config['operationId'], 'context': context,
                         'header': {'action': 'submit-once', 'operationId': c.config['operationId'],
                                    'controllerConfigSha256': ns['SEAL']['configSha256'],
                                    'receiverSha256': ns['SEAL']['receiverSha256'],
                                    'rootGeneration': prepared['rootGeneration'],
                                    'programSha256': context['programSha256'], 'payloadSha256': digest}}
            for name, value in [('local-observation-unknown.json', marker), ('prepared.json', prepared),
                                ('remote-submission.once.json', submitted)]:
                (out / name).write_bytes(canonical(value))
            c.snapshot = types.SimpleNamespace(add=lambda p, **k: Path(p).read_bytes(), guard=lambda: None)
            for local in ({'state': 'terminal', 'terminal': {'exitCode': 0}},
                          {'state': 'terminal', 'terminal': {'exitCode': 65}, 'collectionDirectory': 'owned-collection'}):
                value = ns['local_observation_result'](c, local)
                self.assertEqual(value['state'], 'unknown')
                self.assertEqual(value['originalRemoteResult'], remote)
                self.assertEqual(value['localDurable'], local)
                self.assertFalse(value['replayAllowed'])

    def test_missing_unknown_publication_never_projects_vm_success(self):
        ns = pure_namespace()
        c, _, _, _, _ = controlled_context(ns)
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory).resolve()
            ns['OUT'] = out
            (out / 'remote-submission.once.json').write_bytes(b'{}')
            local = {'state': 'terminal', 'terminal': {'exitCode': 65}}
            value = ns['local_observation_result'](c, local)
            self.assertEqual(value['state'], 'unknown')
            self.assertEqual(value['localDurable'], local)
            self.assertFalse(value['claimsReleased'])

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid'), 'Actual POSIX owner/lock control')
class ActualOwnedObserverTests(unittest.TestCase):
    def run_control(self, mode='terminal', source=None):
        import fcntl
        with tempfile.TemporaryDirectory(prefix='vc-terminal-observer-') as directory:
            out = Path(directory).resolve()
            selected = Path(source or os.environ.get('ANDROID_TERMINAL_OBSERVER_SOURCE', str(FIXED))).resolve()
            self.assertIn(selected, {BEFORE.resolve(), FIXED.resolve()})
            child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                '--owner-control', str(selected), str(out), mode], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            try:
                selector = selectors.DefaultSelector()
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=10), 'owned observer did not publish control boundary')
                line = child.stdout.readline()
                self.assertTrue(line, 'owned observer control ended without a boundary record')
                value = json.loads(line)
                states = []
                for index in range(3):
                    fd = os.open(out / ('owned-lock-' + str(index)), os.O_RDWR | os.O_NOFOLLOW)
                    try:
                        try:
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            states.append('held')
                        else:
                            states.append('available')
                            fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)
                evidence = os.environ.get('ANDROID_TERMINAL_OBSERVER_EVIDENCE_DIR')
                if evidence:
                    record = {'schema': 1, 'mode': mode, 'sourceSha256': sha(selected.read_bytes()),
                              'controlBoundary': value, 'independentKernelLockStates': states,
                              'childPid': child.pid, 'nativeVmCalls': 0, 'signalsSent': False}
                    path = Path(evidence) / ('owned-boundary-' + str(uuid.uuid4()) + '.json')
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(canonical(record))
                        stream.flush()
                        os.fsync(stream.fileno())
                if mode == 'running':
                    self.assertEqual(value['stage'], 'waiting')
                    self.assertEqual(states, ['held'] * 3)
                    self.assertFalse(value['closed'])
                else:
                    self.assertEqual(value['stage'], 'done')
                    self.assertEqual(states, ['available'] * 3)
                    self.assertTrue(value['closed'])
                    self.assertEqual(value['calls'].count('submit-once'), 1)
                    self.assertNotIn('observe', value['calls'])
                    self.assertTrue(value['originalOutcomeUnmodified'])
                return value
            finally:
                if child.stdin is not None:
                    child.stdin.close()
                    child.stdin = None
                stdout, stderr = child.communicate(timeout=10)
                self.assertEqual(child.returncode, 0, stderr.decode())

    def test_actual_owner_closes_only_observation_after_original_terminal(self):
        value = self.run_control()
        self.assertTrue(value['unknownReceipt'])

    def test_running_original_keeps_its_qualified_observer(self):
        self.run_control('running', source=FIXED)

    def test_interval_collection_unknown_does_not_extend_observer(self):
        self.assertTrue(self.run_control('collection-failure', source=FIXED)['unknownReceipt'])

    def test_failed_receipt_publication_still_closes_only_observer(self):
        value = self.run_control('publication-failure', source=FIXED)
        self.assertEqual(value['state'], 'observer-error-65')
        self.assertFalse(value['unknownReceipt'])

    def test_interval_collection_exception_still_closes_only_observer(self):
        value = self.run_control('collection-exception', source=FIXED)
        self.assertEqual(value['state'], 'observer-error-65')
        self.assertFalse(value['unknownReceipt'])

@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid'), 'Actual POSIX Context and frozen SourceSession')
class ActualFreshContextTests(unittest.TestCase):
    def run_fresh(self, action):
        from unittest import mock
        sys.path.insert(0, str(ROOT))
        from agent_tools.tests import test_android_interval_report_context as actual
        # Only the controlled fixture's source directory changes. Its genuine
        # Context/Custody/frozen durable constructor runs the exact new bytes.
        with mock.patch.object(actual, 'RESOURCES', FIXED.parent):
            fixture = actual.ActualContextFixture(self)
        c = fixture.context
        fixture.seal['receiverSha256'] = fixture.preparation['receiverSha256']
        remote = controlled_remote_result()
        remote['operationId'] = c.config['operationId']
        remote['preparation'] = copy.deepcopy(fixture.preparation)
        remote['context'].update(operationId=c.config['operationId'], rootGeneration=fixture.preparation['rootGeneration'],
                                 controllerConfigSha256=fixture.seal['configSha256'])
        remote['receiver']['call'] = copy.deepcopy(remote['context'])
        remote['receiver']['claimed'].update(operationId=c.config['operationId'],
            rootGeneration=fixture.preparation['rootGeneration'], receiverSha256=fixture.seal['receiverSha256'],
            controllerConfigSha256=fixture.seal['configSha256'])
        remote['durable']['operationId'] = c.config['operationId']
        remote['durable']['binding'] = copy.deepcopy(c.config['binding'])
        remote['durable']['terminal']['operationId'] = c.config['operationId']
        remote['durable']['terminal']['binding'] = copy.deepcopy(c.config['binding'])
        digest = remote['receiver']['claimed']['payloadSha256']
        marker = fixture.ns['terminal_unknown_observation'](c, remote, fixture.preparation, remote['context'], digest)
        fixture.write(fixture.out / 'local-observation-unknown.json', canonical(marker))
        submitted = {'operationId': c.config['operationId'], 'context': remote['context'],
            'header': {'action': 'submit-once', 'operationId': c.config['operationId'],
                'controllerConfigSha256': fixture.seal['configSha256'],
                'receiverSha256': fixture.seal['receiverSha256'],
                'rootGeneration': fixture.preparation['rootGeneration'],
                'programSha256': remote['context']['programSha256'], 'payloadSha256': digest}}
        fixture.write(fixture.out / 'remote-submission.once.json', canonical(submitted))
        result = fixture.main(action)
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['originalRemoteResult'], remote)
        self.assertEqual(result['localDurable']['state'], 'terminal')
        self.assertFalse(result['claimsReleased'])
        self.assertFalse(result['guestAdmitted'])
        self.assertFalse(result['replayAllowed'])
        self.assertFalse(c.sent)
        self.assertNotIn('prepare', fixture.rpc_events)
        self.assertNotIn('submit-once', fixture.rpc_events)
        if action == 'local-status':
            self.assertEqual(fixture.rpc_events, [])
            self.assertEqual(fixture.tool_events, [])
        else:
            collected = Path(result['localDurable']['collectionDirectory'])
            self.assertEqual((collected / 'stdout.raw').read_bytes(), fixture.stdout)
            self.assertEqual((collected / 'stderr.raw').read_bytes(), fixture.stderr)

    def test_actual_constructor_fresh_status_keeps_original_unknown(self):
        self.run_fresh('local-status')

    def test_actual_constructor_fresh_collection_keeps_original_unknown(self):
        self.run_fresh('local-collect')

if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--owner-control':
        owner_control(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        unittest.main()
