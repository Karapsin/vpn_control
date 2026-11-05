"""Actual emitted readers/owners over owned temporary filesystem fixtures only."""
from contextlib import redirect_stdout
from pathlib import Path
import ast
import base64
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
import uuid
import warnings

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from agent_tools import android_persisted_start as FIXED
from agent_tools import durable_remote_job as durable
from agent_tools.tests import android_interval_fixture_support as FIXTURE
from agent_tools.tests import test_android_persisted_interval_storage as PLUMBING
RESOURCES=FIXTURE.RESOURCES
BEFORE=FIXTURE.before_helper('helper-734.before.source','7341b274393541566e05ca526e2608cdcdc00a132e7a9839a9763e3fbf464b18')
REPORTS = []


class OwnedOwnerStop(BaseException):
    pass


class OwnedFilesystem:
    """Real fixture FD/bytes, virtual root UID and canonical path only.

    Every open is asserted read-only and mapped under one owned /tmp fixture.
    No real /var/tmp, host identity path, privilege, guest, or network is used.
    """
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='vc-ir-', dir=None)
        self.base = Path(self.temporary.name).resolve()
        self.operation = str(uuid.uuid4())
        self.root = '/var/tmp/vc-android-persisted-' + self.operation
        self.fds = {}
        self.opens = 0
        self.drift = None
        self.machine = b'owned-private-report-machine\n'
        self.context = {'schema': 1, 'operationId': self.operation, 'root': self.root,
                        'rootGeneration': [], 'hostBootId': '25515f23-b966-4c3a-ae63-d38452375578',
                        'machineSha256': hashlib.sha256(self.machine).hexdigest(), 'account': '0'}
        for path, raw in [('/etc/machine-id', self.machine),
                          ('/proc/sys/kernel/random/boot_id', (self.context['hostBootId'] + '\n').encode())]:
            actual = self.map(path)
            actual.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            actual.write_bytes(raw)
            actual.chmod(0o600)
        self.map(self.root).mkdir(parents=True, mode=0o700)
        self.directory = self.map(self.root + '/current-intervals')
        self.directory.mkdir(mode=0o700)
        info = self.map(self.root).stat()
        self.context['rootGeneration'] = [info.st_dev, info.st_ino]
        self.records = {}

    def close(self):
        self.temporary.cleanup()

    def map(self, path):
        path = str(path)
        assert path.startswith('/') and '..' not in Path(path).parts
        return self.base / path.lstrip('/')

    def info(self, value, name=None):
        fields = {key: getattr(value, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
        fields.update(st_uid=0, st_gid=0)
        if name is not None and self.drift == Path(str(name)).name:
            fields['st_ctime_ns'] += 1
        return types.SimpleNamespace(**fields)

    def adapter(self):
        fixture = self

        class Adapter:
            def __getattr__(self, name):
                return getattr(os, name)

            @staticmethod
            def getuid(): return 0
            @staticmethod
            def geteuid(): return 0
            @staticmethod
            def getgid(): return 0
            @staticmethod
            def getegid(): return 0

            @staticmethod
            def open(path, flags, *, dir_fd=None):
                assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND | os.O_WRONLY | os.O_RDWR), 'reader attempted a write'
                text = str(path)
                actual = fixture.map(text) if text.startswith('/') else text
                if dir_fd is not None:
                    assert dir_fd in fixture.fds
                fd = os.open(actual, flags, dir_fd=dir_fd)
                fixture.fds[fd] = text
                fixture.opens += 1
                return fd

            @staticmethod
            def close(fd):
                fixture.fds.pop(fd)
                return os.close(fd)

            @staticmethod
            def fstat(fd):
                assert fd in fixture.fds
                return fixture.info(os.fstat(fd))

            @staticmethod
            def stat(path, *, dir_fd=None, follow_symlinks=True):
                text = str(path)
                actual = fixture.map(text) if text.startswith('/') else text
                if dir_fd is not None:
                    assert dir_fd in fixture.fds
                return fixture.info(os.stat(actual, dir_fd=dir_fd, follow_symlinks=follow_symlinks), text)

        return Adapter()

    def report(self, attempt=0, size=None):
        record = uuid.uuid4().hex
        document = {'schema': 1, 'kind': 'android-current1e15-unknown-interval',
                    'operationId': self.operation, 'recordId': record,
                    'guardInvocationId': '1' * 32, 'attempt': attempt,
                    **FIXED._interval_report_namespace()['INTERVAL_REPORT_HEADERS'],
                    'retryable': attempt < 2, 'unknownInterval': True,
                    'outcomesChanged': False, 'nativeAction': False,
                    'hostAttempt': {'ownedOnly': True}, 'payload': ''}
        encode = lambda: json.dumps(document, sort_keys=True, separators=(',', ':')).encode() + b'\n'
        if size is not None:
            document['payload'] = 'x' * (size - len(encode()))
        raw = encode()
        if size is not None: assert len(raw) == size
        path = self.directory / ('interval-' + record + '.json')
        path.write_bytes(raw)
        path.chmod(0o600)
        self.records[record] = (path, raw)
        return record

    def run(self, request, *, context=None, helper=FIXED):
        source = helper.interval_report_program(context or self.context, request)
        tree = ast.parse(source)
        # Only the OS boundary is owned; every emitted guard/parser/read loop,
        # FD generation check, source header check and serializer stays actual.
        for node in tree.body:
            if isinstance(node, ast.Import):
                node.names = [value for value in node.names if value.name != 'os']
        tree.body = [node for node in tree.body if not isinstance(node, ast.Import) or node.names]
        namespace = {'__name__': 'owned_emitted_report_reader', 'os': self.adapter()}
        stream = io.StringIO()
        with redirect_stdout(stream):
            exec(compile(tree, '<actual-emitted-reader-owned-filesystem>', 'exec'), namespace)
        assert not self.fds
        raw = stream.getvalue().encode()
        assert len(raw) < 7 * 1024 ** 2
        return json.loads(raw), raw


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.fs = OwnedFilesystem()
        self.addCleanup(self.fs.close)

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_actual_emitted_discovery_and_contiguous_bounded_slices(self):
        record = self.fs.report(size=4 * 1024 ** 2 + 321)
        catalog, _ = self.fs.run({'action': 'discover'})
        FIXED.validate_interval_report_catalog(catalog, self.fs.context)
        reference = catalog['references'][0]
        parts = []
        for offset in (0, 4 * 1024 ** 2):
            requested = [{'reference': reference, 'offset': offset,
                          'length': min(4 * 1024 ** 2, reference['bytes'] - offset)}]
            value, response = self.fs.run({'action': 'slice', 'slices': requested})
            parsed = FIXED.validate_interval_report_slices(value, self.fs.context, requested)
            self.assertLess(len(response), 7 * 1024 ** 2)
            self.assertLessEqual(value['aggregateBytes'], 4 * 1024 ** 2)
            parts.extend(raw for _, _, raw in parsed)
        self.assertEqual(b''.join(parts), self.fs.records[record][1])


    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_refuses_foreign_name_report_malformed_duplicate_and_oversize(self):
        record = self.fs.report()
        path, raw = self.fs.records[record]
        variants = [('foreign-name', self.fs.directory / 'foreign.json', b'{}'),
                    ('malformed', path, b'{'),
                    ('duplicate', path, b'{"schema":1,"schema":1}'),
                    ('foreign-operation', path, raw.replace(self.fs.operation.encode(), str(uuid.uuid4()).encode())),
                    ('foreign-header', path, raw.replace(b'779c7bce', b'00000000'))]
        for label, target, value in variants:
            with self.subTest(label=label):
                target.write_bytes(value)
                target.chmod(0o600)
                observed, _ = self.fs.run({'action': 'discover'})
                self.assertEqual(observed['state'], 'unknown')
                if target != path:target.unlink()
                path.write_bytes(raw)
                path.chmod(0o600)
        with path.open('r+b') as stream:stream.truncate(8 * 1024 ** 2 + 1)
        observed, _ = self.fs.run({'action': 'discover'})
        self.assertEqual(observed['reason'], 'interval_collection_file_bound_or_principal')

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_refuses_aggregate_root_generation_and_full_pin_drift(self):
        records = [self.fs.report() for _ in range(4)]
        for record in records:
            with self.fs.records[record][0].open('r+b') as stream:stream.truncate(6 * 1024 ** 2 + 1)
        value, _ = self.fs.run({'action': 'discover'})
        self.assertEqual(value['reason'], 'interval_collection_aggregate_bound')
        for record in records[1:]:self.fs.records[record][0].unlink()
        path, original = self.fs.records[records[0]]
        path.write_bytes(original)
        bad = copy.deepcopy(self.fs.context)
        bad['rootGeneration'][1] += 1
        value, _ = self.fs.run({'action': 'discover'}, context=bad)
        self.assertEqual(value['reason'], 'interval_collection_root_changed')
        catalog, _ = self.fs.run({'action': 'discover'})
        reference = catalog['references'][0]
        self.fs.drift = path.name
        value, _ = self.fs.run({'action': 'slice', 'slices': [{'reference': reference, 'offset': 0, 'length': reference['bytes']}]})
        self.assertEqual(value['reason'], 'interval_collection_report_changed')

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_rejects_foreign_reference_and_oversize_slice_before_read(self):
        self.fs.report()
        catalog, _ = self.fs.run({'action': 'discover'})
        reference = catalog['references'][0]
        for mutation in ({'operationId': str(uuid.uuid4())}, {'rootGeneration': [1, 2]},
                         {'path': reference['path'] + '/../foreign'}, {'generation': reference['generation'][:-1] + [0]}):
            value, _ = self.fs.run({'action': 'slice', 'slices': [{'reference': dict(reference, **mutation), 'offset': 0, 'length': 1}]})
            self.assertEqual(value['state'], 'unknown')
        value, _ = self.fs.run({'action': 'slice', 'slices': [{'reference': reference, 'offset': 0, 'length': 4 * 1024 ** 2 + 1}]})
        self.assertEqual(value['state'], 'unknown')


class OwnerCollectionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_complete24mib_uses_at_most_six4mib_data_replies(self):
        fs = OwnedFilesystem()
        self.addCleanup(fs.close)
        for attempt in range(3):fs.report(attempt, 8 * 1024 ** 2)
        path = RESOURCES / 'controller.fixed.source'
        namespace = {'__name__': 'owned_maximum_collection', '__CONTROLLER_SEAL__': {}}
        exec(compile(path.read_bytes(), str(path), 'exec'), namespace)
        temp = tempfile.TemporaryDirectory(prefix='vc-im-', dir=None)
        self.addCleanup(temp.cleanup)
        out = Path(temp.name).resolve();out.chmod(0o700);namespace['OUT'] = out
        source = b'CURRENT_INTERVAL_STORAGE_REQUIRED=True\n'
        capsule = {'source': source, 'sha256': hashlib.sha256(source).hexdigest()}
        c = types.SimpleNamespace(config={'operationId': fs.operation, 'remoteRoot': fs.root,
               'binding': {'boot': fs.context['hostBootId'], 'machine': fs.context['machineSha256'], 'account': '0'}},
               sent=True, renderer=FIXED, capsule=lambda name: capsule, guard=lambda **kwargs: None)
        requests=[]
        def transaction(action, payload, prepared):
            self.assertEqual(action, 'admit')
            program=base64.b64decode(payload['observerBase64'],validate=True)
            tree=ast.parse(program)
            request=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and
                         any(isinstance(x,ast.Name)and x.id=='INTERVAL_REPORT_REQUEST'for x in n.targets))
            requests.append(request)
            value,raw=fs.run(request)
            return value,raw,out
        c.transaction=transaction
        c.bind_interval_collection=lambda:None
        result=namespace['collect_interval_reports'](c,{'operationId':fs.operation,'rootGeneration':fs.context['rootGeneration']},'terminal')
        self.assertEqual(result['state'],'original-interval-reports-collected')
        self.assertEqual(result['aggregateBytes'],24*1024**2)
        self.assertEqual(result['queries'],8)
        self.assertEqual(len([r for r in requests if r['action']=='slice']),6)
        self.assertTrue(all(sum(x['length']for x in r['slices'])<=4*1024**2 for r in requests if r['action']=='slice'))
        REPORTS.append({'kind':'actual-maximum-budget-collection','aggregateBytes':result['aggregateBytes'],
                        'dataReplies':6,'totalReplies':8,'complete':True,'nativeEffectsAttempted':False})

    def run_failed_owner(self, before=False, *, collection_failure=False, runtime_unknown=False):
        helper = BEFORE if before else FIXED
        fs = OwnedFilesystem()
        self.addCleanup(fs.close)
        for attempt in range(3):fs.report(attempt)
        catalog, _ = fs.run({'action': 'discover'})
        references = catalog['references']
        FIXTURE.start = helper
        original, original_sha, launch = FIXTURE.capsule()
        preflight = "def installer_host_preflight():raise ValueError('current_interval_guard_unknown')\n"
        if runtime_unknown:
            preflight = "def installer_host_preflight():return {'state':'admitted','stableBinding':{'owned-inert-installer-precondition':True},'evidence':{'unitOnly':True}}\n"
        capsule_source = ('CURRENT_INTERVAL_STORAGE_REQUIRED=True\nCURRENT_INTERVAL_FAILURES=' + repr(references) + '\n' + preflight).encode()
        capsule = {'source': capsule_source, 'sha256': hashlib.sha256(capsule_source).hexdigest(),
                   'originalSourceSha256': original_sha, 'sourcePins': {'owned-exhausted-host-capsule': original_sha}}
        auth = FIXTURE.authority()
        coverage = None
        capacity_runtime = None
        if runtime_unknown:
            auth, coverage, unused, probe = FIXTURE.allocation_control()
            capacity_runtime = FIXTURE.allocation_runtime(auth, coverage, probe)
        good = FIXTURE.admission(fs.operation, original_sha, auth, launch)
        good['installerGuardSha256'] = capsule['sha256']
        good['installerGuardSourcePins'] = capsule['sourcePins']
        for row in good['observations']:
            row['host']['machineSha256'] = fs.context['machineSha256']
        if capacity_runtime is not None:
            native, capacity = capacity_runtime['native_capacity']()
            evidence = copy.deepcopy(capacity_runtime['LAST_ALLOCATION_EVIDENCE'])
            good['allocationCoverageContract'] = evidence['contract']
            for row in good['observations']:
                row['resources'].update(nativeObservation=native, canonicalPlan=capacity,
                       availableMemoryBytes=native['measurement']['availableMemoryBytes'], allocationCoverage=evidence)
        path = RESOURCES / ('controller-e43.before.source' if before else 'controller.fixed.source')
        source = path.read_bytes()
        if before:self.assertEqual(hashlib.sha256(source).hexdigest(), 'e43f0997cfae188c433e5cea86807e36bc247b971093534fecfe88ef38510c86')
        namespace = {'__name__': 'owned_whole_failed_collection_owner', '__CONTROLLER_SEAL__':
                     {'configSha256': 'a' * 64, 'sourceManifestSha256': 'b' * 64, 'receiverSha256': 'c' * 64}}
        exec(compile(source, str(path), 'exec', dont_inherit=True), namespace)
        temporary = tempfile.TemporaryDirectory(prefix='vc-ic-', dir=None)
        self.addCleanup(temporary.cleanup)
        out = Path(temporary.name).resolve()
        out.chmod(0o700)
        namespace['OUT'] = out
        (out / 'remote_receiver.py').write_bytes(b'owned-inert-receiver\n')
        holder = types.SimpleNamespace(config={'operationId': fs.operation, 'localBinding':
                  {'target': 'owned-local', 'machine': 'owned-machine', 'boot': 'owned-boot', 'account': str(os.geteuid())},
                  'lockFiles': [], 'coverageBridgeQualified': True, 'originalSourceSha256': original_sha,
                  'remoteRoot': fs.root, 'binding': {'target': 'owned-native', 'machine': fs.context['machineSha256'],
                     'boot': fs.context['hostBootId'], 'account': '0'}}, programme={'controllerSha256': 'd' * 64, 'ownerProgramSha256': 'e' * 64},
                  sent=False, locked=False, labels=[], rawReplies=[], planCalls=0, closed=False, renderer=helper)
        holder.inputs = types.SimpleNamespace(acquire=lambda rows: setattr(holder, 'locked', True))
        holder.durable = types.SimpleNamespace(MachineBinding=durable.MachineBinding, _binding_live=lambda binding: None)
        holder.review = lambda name, expected: None
        holder.authority = lambda: auth
        holder.original = lambda: original
        holder.capsule = lambda name: capsule if name == 'installer' else coverage
        inputs = {'coverageBridgeQualification': b'owned fixture', 'durableSource': durable.owner_source(),
                  'coldbootSource': FIXTURE.PRODUCER.read_bytes()}
        holder.input = lambda name: inputs[name]
        def guard(*, preeffect):
            self.assertTrue(holder.locked)
            if runtime_unknown and (out / 'expected-start-authority.json').exists() and not (out / 'start-authority.json').exists():
                (out / 'start-authority.json').write_bytes((out / 'expected-start-authority.json').read_bytes())
        holder.guard = guard
        def close(): holder.closed=True;holder.locked=False
        holder.close = close

        def transaction(label, payload, prepared=None, **options):
            self.assertTrue(holder.locked)
            holder.labels.append(label)
            if label in ('prepare', 'recover-prepare'):
                value={'state':'prepared-not-submitted','preparation':{'operationId':fs.operation,'rootGeneration':fs.context['rootGeneration']}}
                return value,helper._canonical(value),out
            if runtime_unknown and label == 'submit-once':
                holder.sent = True
                return None, b'', out
            if runtime_unknown and label == 'observe':
                raise ValueError('owned_original_observation_lost')
            self.assertEqual(label, 'admit', 'Any submit/observe/GO is forbidden')
            program=base64.b64decode(payload['observerBase64'],validate=True)
            tree=ast.parse(program)
            request=next((ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and
                         any(isinstance(x,ast.Name) and x.id=='INTERVAL_REPORT_REQUEST' for x in n.targets)),None)
            if request is not None:
                if collection_failure:
                    raw=b'{';value=None
                else:value,raw=fs.run(request)
            else:
                value,_=PLUMBING.run_emitted_observer(program)
                if runtime_unknown:
                    self.assertEqual(value['state'], 'admitted')
                    value = copy.deepcopy(good)
                raw=helper._canonical(value)
            directory=out/('capture-'+str(len(holder.labels)));directory.mkdir(mode=0o700)
            (directory/'stdout.raw').write_bytes(raw);holder.rawReplies.append(raw)
            if value is None:raise ValueError('owned_collection_transport_partial')
            return value,raw,directory
        holder.transaction = transaction
        holder.bind_interval_collection = lambda: None
        namespace['Context'] = lambda:holder
        namespace['machine'] = lambda:'owned-machine'
        if runtime_unknown:
            def sleep(unused):
                if holder.sent:
                    raise OwnedOwnerStop()
            namespace['time'] = types.SimpleNamespace(sleep=sleep)
        saved=os.umask(0o077)
        try:
            with self.assertRaises(OwnedOwnerStop if runtime_unknown else SystemExit):namespace['owner_main']()
        finally:os.umask(saved)
        if runtime_unknown:
            self.assertFalse(holder.closed);self.assertTrue(holder.locked)
            self.addCleanup(holder.close)
            self.assertEqual(holder.labels.count('submit-once'), 1)
        else:
            self.assertTrue(holder.closed);self.assertFalse(holder.locked)
            self.assertNotIn('submit-once',holder.labels)
        holder.refusal=json.loads((out/('post-submit-unknown.json' if runtime_unknown else 'local-prefork-refusal.json')).read_bytes())
        collection=out/('interval-reports-runtime-unknown' if runtime_unknown else 'interval-reports-prefork-refusal')
        holder.collected=json.loads((collection/'collected.json').read_bytes())if(collection/'collected.json').exists()else None
        holder.collectionUnknown=json.loads((collection/'unknown.json').read_bytes())if(collection/'unknown.json').exists()else None
        holder.nativeReply=json.loads(holder.rawReplies[0])
        if holder.collected:
            self.assertEqual(len(holder.collected['files']),3)
            for row in holder.collected['files']:
                self.assertEqual(Path(row['localPath']).read_bytes(),fs.records[row['reference']['recordId']][1])
        holder.namespace, holder.output = namespace, out
        return holder

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_whole734_e43_missing_collection_red_fixed_exhausted_path_green(self):
        red=self.run_failed_owner(before=True);green=self.run_failed_owner()
        self.assertNotIn('currentIntervalFailures',red.nativeReply)
        self.assertIsNone(red.collected)
        self.assertEqual(len(green.nativeReply['currentIntervalFailures']),3)
        self.assertEqual(green.nativeReply['reason'],red.nativeReply['reason'])
        self.assertEqual(green.refusal['reason'],red.refusal['reason'])
        self.assertEqual(green.collected['state'],'original-interval-reports-collected')
        self.assertEqual(green.labels.count('prepare'),1)
        self.assertEqual(green.labels.count('admit'),4)
        REPORTS.append({'kind':'whole734-e43-missing-collection-causal','beforeReportsCollected':False,
                        'fixedReportsCollected':3,'fixedBoundedProjectionReferences':3,'guardFailurePreserved':True,
                        'originalRefusalPreserved':True,'submitCalls':0,'nativeEffectsAttempted':False})

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_collection_partial_retains_original_refusal_without_replay(self):
        green=self.run_failed_owner(collection_failure=True)
        self.assertIsNone(green.collected)
        self.assertEqual(green.collectionUnknown['state'],'original-interval-report-collection-unknown')
        self.assertEqual(green.refusal['reason'],'controller_admission_not_retryable')
        self.assertEqual(green.labels,['prepare','admit','admit'])

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_runtime_unknown_retains_original_locks_and_collects_without_effect_replay(self):
        red = self.run_failed_owner(before=True, runtime_unknown=True)
        green = self.run_failed_owner(runtime_unknown=True)
        self.assertIsNone(red.collected)
        self.assertEqual(green.collected['state'], 'original-interval-reports-collected')
        self.assertTrue(green.locked)
        self.assertEqual(green.labels.count('submit-once'), 1)
        self.assertEqual(green.labels.count('observe'), 1)
        self.assertEqual(green.refusal['state'], 'unknown')
        self.assertTrue(green.refusal['locksRetained'])
        REPORTS.append({'kind': 'whole-runtime-unknown-collection-causal', 'beforeCollected': False,
                        'fixedCollected': 3, 'originalUnknownAndLocksRetained': True,
                        'ownedSubmitBoundaryCalls': 1, 'realNativeEffectCalls': 0, 'effectReplayCalls': 0})

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_fresh_client_collects_original_reports_and_keeps_unknown_outcome(self):
        original = self.run_failed_owner(runtime_unknown=True)
        fresh = copy.copy(original)
        fresh.config = dict(original.config, localOperationId=str(uuid.uuid4()), localRootGeneration=[1, 2])
        fresh.closed = False
        fresh.snapshot = original.namespace['Custody']()
        self.addCleanup(fresh.snapshot.close)
        fresh.guard = lambda **kwargs: None
        fresh.close = lambda: setattr(fresh, 'closed', True)
        calls = []
        def collect(root, operation, binding, *, generation):
            calls.append(operation)
            return {'state': 'unknown', 'operationId': operation, 'reason': 'owned-original-outcome-unknown'}, b'owned original stdout', b''
        fresh.durable = types.SimpleNamespace(MachineBinding=durable.MachineBinding, collect=collect)
        namespace = original.namespace
        namespace['Context'] = lambda **kwargs: fresh
        stream = io.StringIO()
        with redirect_stdout(stream):namespace['main'](['local-collect'])
        answer = json.loads(stream.getvalue())
        self.assertEqual(answer['state'], 'unknown')
        self.assertEqual(answer['reason'], 'owned-original-outcome-unknown')
        self.assertEqual(answer['intervalReports']['state'], 'original-interval-reports-collected')
        self.assertEqual(calls, [fresh.config['localOperationId']])
        self.assertTrue(original.locked)
        self.assertEqual(original.labels.count('submit-once'), 1)
        self.assertIn('recover-prepare', original.labels)


if __name__=='__main__':unittest.main()
