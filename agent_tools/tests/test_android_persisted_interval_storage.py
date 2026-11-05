"""Private causal controls; all guest/transport boundaries are owned inert seams.

Real helper emissions, real whole owners, real start_plan validation. Never
execute a native observer, durable owner, SSH command, VM effect, or root write.
"""
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from agent_tools import android_persisted_start as FIXED
from agent_tools import durable_remote_job as durable
from agent_tools.tests import android_interval_fixture_support as FIXTURE
RESOURCES=FIXTURE.RESOURCES
REPORTS = []




BEFORE=FIXTURE.before_helper('helper-53b.before.source','53b0fca6d7eba6344420c3d83c028aa18be60669f0af9305df8dbbd54c77bd82')



def fixture(helper=FIXED):
    FIXTURE.start = helper
    original, original_sha, launch = FIXTURE.capsule()
    operation = str(uuid.uuid4())
    storage = {'schema': 1, 'operationId': operation,
               'root': '/var/tmp/vc-android-persisted-' + operation,
               'rootGeneration': [11, 22], 'hostBootId': launch['observation']['bootId'],
               'machineSha256': 'a' * 64, 'account': '0'}
    capsule_source = ("CURRENT_INTERVAL_STORAGE_REQUIRED=True\nEXPECTED=" + repr(storage) + '\n' + '''
def installer_host_preflight():
    value=globals().get('CURRENT_INTERVAL_STORAGE')
    if value is None:raise ValueError('current_interval_storage_required')
    if value!=EXPECTED:raise ValueError('owned_interval_storage_binding_changed')
    return {'state':'admitted','stableBinding':{'owned-inert-installer-precondition':True},
            'evidence':{'unitOnly':True,'intervalStorage':value}}
''').encode()
    capsule = {'source': capsule_source, 'sha256': hashlib.sha256(capsule_source).hexdigest(),
               'originalSourceSha256': original_sha, 'sourcePins': {'owned-storage-capsule': original_sha}}
    return original, original_sha, launch, operation, storage, capsule


def run_emitted_observer(program):
    """Replace ONLY the actual host-measurement entry, not capsule plumbing.

    The capsule module/exec/assignment and real rendered terminal catch/JSON
    handling execute unchanged. Its owned preflight checks exact storage.
    """
    tree = ast.parse(program)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'observations']
    if len(nodes) != 1:
        raise ValueError('owned_host_boundary_changed')
    nodes[0].body = ast.parse('return installer_host_preflight()').body
    ast.fix_missing_locations(tree)
    output = io.StringIO()
    namespace = {'__name__': 'owned_emitted_interval_observer'}
    previous = sys.modules.get('persisted_start_installer_host_snapshot')
    try:
        with redirect_stdout(output):
            exec(compile(tree, '<real-emitted-observer-owned-host-boundary>', 'exec'), namespace)
    finally:
        if previous is None:
            sys.modules.pop('persisted_start_installer_host_snapshot', None)
        else:
            sys.modules['persisted_start_installer_host_snapshot'] = previous
    return json.loads(output.getvalue()), namespace


def run_start_prefix(program):
    """Execute only inert emitted declarations before the durable owner module."""
    tree = ast.parse(program)
    prefix = []
    found = False
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == '_D'
                                                for target in node.targets):
            found = True
            break
        prefix.append(node)
    if not found:
        raise ValueError('owned_durable_boundary_changed')
    module = ast.Module(body=prefix, type_ignores=[])
    namespace = {'__name__': 'owned_emitted_start_prefix'}
    previous = sys.modules.get('persisted_start_installer_host_snapshot')
    try:
        exec(compile(module, '<real-emitted-start-inert-prefix>', 'exec'), namespace)
        value = namespace['installer_host_preflight']()
    finally:
        if previous is None:
            sys.modules.pop('persisted_start_installer_host_snapshot', None)
        else:
            sys.modules['persisted_start_installer_host_snapshot'] = previous
    return value, namespace


class IntervalStorageTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'requires emitted Linux/POSIX owner code')
    def test_real_emitted_before_missing_storage_red_fixed_green(self):
        original, digest, launch, operation, storage, capsule = fixture()
        auth = FIXTURE.authority()
        before = BEFORE.observation_program(original, digest, operation, auth, installer_guard=capsule)
        red, _ = run_emitted_observer(before)
        self.assertEqual((red['state'], red['reason']), ('blocked', 'current_interval_storage_required'))
        fixed = FIXED.observation_program(original, digest, operation, auth,
                                         installer_guard=capsule, interval_storage=storage)
        green, namespace = run_emitted_observer(fixed)
        self.assertEqual(green['state'], 'admitted')
        self.assertEqual(green['evidence']['intervalStorage'], storage)
        self.assertEqual(namespace['_INSTALLER_HOST'].CURRENT_INTERVAL_STORAGE, storage)
        REPORTS.append({'kind': 'real-emitted-program-causal', 'beforeReason': red['reason'],
                        'fixedState': green['state'], 'beforeProgramSha256': hashlib.sha256(before.encode()).hexdigest(),
                        'fixedProgramSha256': hashlib.sha256(fixed.encode()).hexdigest(), 'nativeEffectsAttempted': False})

    def test_required_storage_refuses_before_returning_program(self):
        original, digest, launch, operation, storage, capsule = fixture()
        with self.assertRaisesRegex(ValueError, '^persisted_start_interval_storage_required$'):
            FIXED.observation_program(original, digest, operation, FIXTURE.authority(), installer_guard=capsule)

    def test_exact_context_rejects_aliases_wrong_ids_types_and_extra_fields(self):
        original, digest, launch, operation, storage, capsule = fixture()
        mutations = {'other-op': {'operationId': str(uuid.uuid4())},
                     'other-root': {'root': '/var/tmp/other'},
                     'path-alias': {'root': storage['root'] + '/.'},
                     'traversal': {'root': storage['root'] + '/../other'},
                     'zero-generation': {'rootGeneration': [11, 0]},
                     'boolean-generation': {'rootGeneration': [11, True]},
                     'extra-generation': {'rootGeneration': [11, 22, 33]},
                     'tuple-generation': {'rootGeneration': (11, 22)},
                     'other-boot': {'hostBootId': str(uuid.uuid4())},
                     'invalid-machine': {'machineSha256': 'INVALID'},
                     'ordinary-account': {'account': '1000'},
                     'boolean-schema': {'schema': True},
                     'unknown-field': {'unexpected': True}}
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                bad = dict(storage, **mutation)
                with self.assertRaisesRegex(ValueError, '^persisted_start_interval_storage_invalid$'):
                    FIXED.observation_program(original, digest, operation, FIXTURE.authority(),
                                              installer_guard=capsule, interval_storage=bad)

    def test_marker_requires_one_boolean_literal(self):
        original, digest, launch, operation, storage, capsule = fixture()
        for marker in ('CURRENT_INTERVAL_STORAGE_REQUIRED=1',
                       'CURRENT_INTERVAL_STORAGE_REQUIRED=bool(1)',
                       'CURRENT_INTERVAL_STORAGE_REQUIRED=True\nCURRENT_INTERVAL_STORAGE_REQUIRED=False',
                       'CURRENT_INTERVAL_STORAGE_REQUIRED: bool=True'):
            cap = dict(capsule)
            cap['source'] = (marker + '\ndef installer_host_preflight():return {}\n').encode()
            cap['sha256'] = hashlib.sha256(cap['source']).hexdigest()
            with self.assertRaisesRegex(ValueError, '^persisted_start_interval_storage_marker_invalid$'):
                FIXED.observation_program(original, digest, operation, FIXTURE.authority(),
                                          installer_guard=cap, interval_storage=storage)

    def test_old_default_observer_is_byte_identical_and_policy_paths_are_real(self):
        original, digest, launch, operation, storage, capsule = fixture()
        cap = FIXTURE.host_guard(digest)
        auth = FIXTURE.authority()
        self.assertEqual(BEFORE.observation_program(original, digest, operation, auth, installer_guard=cap),
                         FIXED.observation_program(original, digest, operation, auth, installer_guard=cap))
        self.assertEqual(BEFORE._capacity_sources(), FIXED._capacity_sources())
        for name, value in FIXED._capacity_sources()[1].items():
            path = ROOT / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), value)
            self.assertEqual(path.read_bytes(), (ROOT / name).read_bytes())
        self.assertEqual(Path(FIXED.__file__), ROOT / 'agent_tools/android_persisted_start.py')

    @unittest.skipUnless(os.name == 'posix', 'requires emitted Linux/POSIX owner code')
    def test_start_plan_forms_storage_automatically_with_truthful_own_sha(self):
        original, digest, launch, operation, storage, capsule = fixture()
        auth = FIXTURE.authority()
        good = FIXTURE.admission(operation, digest, auth, launch)
        good['installerGuardSha256'] = capsule['sha256']
        good['installerGuardSourcePins'] = capsule['sourcePins']
        raw = FIXED._canonical(good)
        plan = FIXED.start_plan(original, digest, operation, auth, raw, hashlib.sha256(raw).hexdigest(),
               job_root=storage['root'], root_generation=storage['rootGeneration'],
               host_binding={'target': 'owned-native', 'machine': storage['machineSha256'],
                             'boot': storage['hostBootId'], 'account': '0'},
               coldboot_source=FIXTURE.PRODUCER.read_bytes(), durable_source=durable.owner_source(), installer_guard=capsule)
        value, namespace = run_start_prefix(plan['program'])
        self.assertEqual(value['evidence']['intervalStorage'], storage)
        self.assertEqual(plan['adapterSourceSha256'], hashlib.sha256(Path(FIXED.__file__).read_bytes()).hexdigest())
        self.assertNotEqual(plan['adapterSourceSha256'], '53b0fca6d7eba6344420c3d83c028aa18be60669f0af9305df8dbbd54c77bd82')
        self.assertEqual(namespace['_INSTALLER_HOST'].CURRENT_INTERVAL_STORAGE, storage)
        REPORTS.append({'kind': 'real-start-prefix-context', 'programmeSha256': plan['programSha256'],
                        'actualPrivateHelperSha256': plan['adapterSourceSha256'], 'nativeEffectsAttempted': False})


class WholeOwnerTests(unittest.TestCase):
    def run_owner(self, *, before=False, prepare_recover=False):
        helper = BEFORE if before else FIXED
        FIXTURE.start = helper
        original, digest, launch, operation, storage, capsule = fixture(helper)
        auth, coverage, _, probe = FIXTURE.allocation_control()
        good = FIXTURE.admission(operation, digest, auth, launch)
        runtime = FIXTURE.allocation_runtime(auth, coverage, probe)
        native, capacity = runtime['native_capacity']()
        evidence = copy.deepcopy(runtime['LAST_ALLOCATION_EVIDENCE'])
        good['allocationCoverageContract'] = evidence['contract']
        good['installerGuardSha256'] = capsule['sha256']
        good['installerGuardSourcePins'] = capsule['sourcePins']
        for row in good['observations']:
            row['resources'].update(nativeObservation=native, canonicalPlan=capacity,
                   availableMemoryBytes=native['measurement']['availableMemoryBytes'], allocationCoverage=evidence)
        path = RESOURCES / ('controller-b2.before.source' if before else 'controller.fixed.source')
        source = path.read_bytes()
        if before:
            self.assertEqual(hashlib.sha256(source).hexdigest(), 'b2cec75b415152f88c629a56aad01a9db601b54183fa0a786a3e6a4e1fa043c6')
        namespace = {'__name__': 'owned_whole_interval_controller', '__CONTROLLER_SEAL__':
                     {'configSha256': 'a' * 64, 'sourceManifestSha256': 'b' * 64, 'receiverSha256': 'c' * 64}}
        exec(compile(source, str(path), 'exec', dont_inherit=True), namespace)
        temporary = tempfile.TemporaryDirectory(prefix='vc-is-', dir=None)
        self.addCleanup(temporary.cleanup)
        out = Path(temporary.name).resolve()
        out.chmod(0o700)
        namespace['OUT'] = out
        (out / 'remote_receiver.py').write_bytes(b'owned-inert-receiver-source\n')
        holder = types.SimpleNamespace(config={'operationId': operation,
                 'localBinding': {'target': 'owned-local', 'machine': 'owned-machine', 'boot': 'owned-boot', 'account': str(os.geteuid())},
                 'lockFiles': [], 'coverageBridgeQualified': True, 'originalSourceSha256': digest,
                 'remoteRoot': storage['root'], 'binding': {'target': 'owned-native', 'machine': 'a' * 64,
                     'boot': launch['observation']['bootId'], 'account': '0'}},
                 programme={'controllerSha256': 'd' * 64, 'ownerProgramSha256': 'e' * 64},
                 sent=False, labels=[], events=[], admitted=0, plans=[], locked=False, acquires=0, closed=False)

        def acquire(rows):
            holder.locked = True
            holder.acquires += 1
        holder.inputs = types.SimpleNamespace(acquire=acquire)
        holder.durable = types.SimpleNamespace(MachineBinding=durable.MachineBinding, _binding_live=lambda value: None)
        holder.review = lambda name, expected: None
        holder.authority = lambda: auth
        holder.original = lambda: original
        holder.capsule = lambda name: capsule if name == 'installer' else coverage
        data = {'coverageBridgeQualification': b'owned qualification', 'durableSource': durable.owner_source(),
                'coldbootSource': FIXTURE.PRODUCER.read_bytes()}
        holder.input = lambda name: data[name]

        def guard(*, preeffect):
            self.assertTrue(holder.locked)
            self.assertTrue(preeffect)
            if (out / 'expected-start-authority.json').exists():
                raise ValueError('owned_distinct_start_authority_not_granted')
        holder.guard = guard

        def close():
            holder.closed = True
            holder.locked = False
        holder.close = close

        def transaction(label, payload, prepared=None, **options):
            holder.labels.append(label)
            holder.events.append(label)
            self.assertTrue(holder.locked)
            if label in ('prepare', 'recover-prepare'):
                if label == 'prepare' and prepare_recover:
                    raise ValueError('owned_lost_prepare_ack')
                value = {'state': 'prepared-not-submitted', 'preparation':
                         {'operationId': operation, 'rootGeneration': storage['rootGeneration']}}
                return value, helper._canonical(value), out
            self.assertEqual(label, 'admit', 'Owned test forbids submit/observe/GO')
            holder.admitted += 1
            raw_source = base64.b64decode(payload['observerBase64'], validate=True)
            self.assertEqual(hashlib.sha256(raw_source).hexdigest(), payload['observerSha256'])
            observed, _ = run_emitted_observer(raw_source)
            if observed['state'] == 'admitted':
                self.assertEqual(observed['evidence']['intervalStorage'], storage)
                value = copy.deepcopy(good)
                for row in value['observations']:
                    row['installerHost'] = copy.deepcopy(observed)
            else:
                value = observed
            raw = helper._canonical(value)
            directory = out / ('owned-capture-' + str(holder.admitted))
            directory.mkdir(mode=0o700)
            (directory / 'stdout.raw').write_bytes(raw)
            return value, raw, directory
        holder.transaction = transaction

        def observer(*args, **kwargs):
            holder.events.append('render-observer')
            return helper.observation_program(*args, **kwargs)

        def plan(*args, **kwargs):
            holder.events.append('real-final-plan-validation')
            result = helper.start_plan(*args, **kwargs)
            holder.plans.append(copy.deepcopy(result))
            return result
        holder.renderer = types.SimpleNamespace(observation_program=observer, start_plan=plan,
                                               _source=helper._source, _launchers=helper._launchers)
        namespace['Context'] = lambda: holder
        namespace['machine'] = lambda: 'owned-machine'
        saved_umask = os.umask(0o077)
        try:
            with self.assertRaises(SystemExit):
                namespace['owner_main']()
        finally:
            os.umask(saved_umask)
        self.assertTrue(holder.closed)
        self.assertFalse(holder.locked)
        self.assertEqual(holder.acquires, 1)
        self.assertEqual(holder.labels.count('prepare'), 1)
        self.assertNotIn('submit-once', holder.labels)
        self.assertFalse((out / 'start-authority.json').exists())
        holder.refusal = json.loads((out / 'local-prefork-refusal.json').read_bytes())
        holder.ready = (out / 'ready-for-review.json').exists()
        return holder

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_whole_authentic_before_red_fixed_green_same_fixture(self):
        red = self.run_owner(before=True)
        green = self.run_owner()
        self.assertFalse(red.ready)
        self.assertEqual(red.plans, [])
        self.assertEqual(red.refusal['reason'], 'controller_admission_not_retryable')
        self.assertEqual(red.events, ['render-observer', 'prepare', 'admit'])
        self.assertTrue(green.ready)
        self.assertEqual(len(green.plans), 1)
        self.assertEqual(green.refusal['reason'], 'owned_distinct_start_authority_not_granted')
        self.assertEqual(green.events, ['prepare', 'render-observer', 'admit', 'real-final-plan-validation'])
        self.assertEqual(green.labels, ['prepare', 'admit'])
        REPORTS.append({'kind': 'whole-authentic-owner-causal', 'beforeEvents': red.events,
                        'beforeReason': red.refusal['reason'], 'fixedEvents': green.events,
                        'fixedStoppedAt': green.refusal['reason'], 'realFinalPlanValidated': True,
                        'submitCalls': 0, 'nativeEffectsAttempted': False})

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_prepare_lost_ack_recovers_original_before_render(self):
        green = self.run_owner(prepare_recover=True)
        self.assertEqual(green.events, ['prepare', 'recover-prepare', 'render-observer', 'admit', 'real-final-plan-validation'])
        self.assertTrue(green.ready)
        self.assertEqual(green.labels, ['prepare', 'recover-prepare', 'admit'])
        self.assertEqual(len(green.plans), 1)


if __name__ == '__main__':unittest.main()
