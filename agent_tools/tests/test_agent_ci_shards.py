"""Actual tiny Git checkouts, unchanged scaled CI phase deadlines and measured capacity.

The synthetic workload proves deterministic partition throughput, not the cause
of the unobserved hosted timeout. Historical timing is never an allocation input;
the measured hosted run only checks the fixed partition's capacity.
"""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import affected_agent_tests as selector
from agent_tools import agent_ci_evidence as public


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name('fixtures') / 'agent_ci_shards'
SCALE = 0.08
HOSTED = 'hosted-capacity.'
# A hosted agent shard's measured share of the preserved selection may use at
# most this fraction of its 50-minute phase bound (30 minutes). In run
# 40187427911 both shards of the 815-module selection needed more than the whole
# bound; the remaining 40% absorbs comparable growth and a re-alignment of the
# heavy android_installer modules, which one inserted module can move together.
PHASE_SHARE = 0.6


def retained(name):
    metadata = json.loads((FIXTURE / 'provenance.json').read_bytes())
    row = next(item for item in metadata['files'] if item['path'] == name)
    raw = (FIXTURE / name).read_bytes()
    if len(raw) != row['sourceBytes'] or hashlib.sha256(raw).hexdigest() != row['sourceSha256']:
        raise ValueError('Preserved CI source changed')
    return raw


def preserved(name):
    """A whole cc2873b5 beforeimage of the hosted timeout, authenticated by its provenance."""
    metadata = json.loads((FIXTURE / 'hosted-capacity.provenance.json').read_bytes())
    row = next(item for item in metadata['files'] if item['path'] == HOSTED + name)
    raw = (FIXTURE / row['path']).read_bytes()
    if len(raw) != row['sourceBytes'] or hashlib.sha256(raw).hexdigest() != row['sourceSha256']:
        raise ValueError('Preserved hosted CI source changed: ' + name)
    return raw


def hosted_timing():
    """The exact global selection and measured seconds of Fast Checks run 40187427911."""
    metadata = json.loads((FIXTURE / 'hosted-capacity.provenance.json').read_bytes())
    value = json.loads((FIXTURE / 'hosted-capacity.timing.json').read_bytes())
    plan = {key: value[key] for key in ('baseline', 'head', 'sourceFingerprint', 'modules', 'runId', 'runAttempt')}
    if (hashlib.sha256(public.canonical(value)).hexdigest() != metadata['timing']['canonicalSha256']
            or hashlib.sha256(public.canonical(plan)).hexdigest() != value['globalDigest']
            or value['globalDigest'] != metadata['ci']['globalDigest']):
        raise ValueError('Preserved hosted timing changed')
    return value


def preserved_partition():
    """The unfixed selector's own shard_selection, from its whole beforeimage."""
    raw = preserved('selector.before.source')
    functions = [node for node in ast.parse(raw).body
                 if isinstance(node, ast.FunctionDef) and node.name == 'shard_selection']
    namespace = {'Selection': selector.Selection, 'SelectionError': selector.SelectionError}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(FIXTURE / 'hosted-capacity.selector.before.source'), 'exec'),
         namespace)
    return namespace['shard_selection']


def shard_minutes(raw, partition):
    """Measured minutes of every actual hosted agent job over the preserved selection.

    Each job is charged the longest measured selection time, then the measured
    seconds of each assigned module; a module that never started before the
    timeouts is charged the mean measured module time.
    """
    timing = hosted_timing()
    measured = timing['measuredSeconds']
    allowance = sum(measured.values()) / len(measured)
    selection = selector.Selection(timing['baseline'], (), tuple(timing['modules']), len(timing['modules']))
    jobs = []
    for job, minutes, argv in workflow_jobs(raw):
        index, count = (int(argv[argv.index(flag) + 1]) for flag in ('--shard-index', '--shard-count'))
        assigned = partition(selection, index, count).modules
        seconds = max(timing['selectionSeconds']) + sum(measured.get(name, allowance) for name in assigned)
        jobs.append({'job': job, 'phaseMinutes': minutes, 'shardIndex': index, 'shardCount': count,
                     'modules': len(assigned), 'unmeasured': sum(name not in measured for name in assigned),
                     'minutes': round(seconds / 60, 2)})
    counts = {job['shardCount'] for job in jobs}
    if len(counts) != 1 or sorted(job['shardIndex'] for job in jobs) != list(range(counts.pop())):
        raise ValueError('Hosted jobs do not cover one complete partition: ' + json.dumps(jobs, sort_keys=True))
    return jobs


def workflow_jobs(raw):
    """Read only the fixed actual agent step, preserving its shell branch argv."""
    jobs = []
    current = None
    lines = raw.decode().splitlines()
    for index, line in enumerate(lines):
        if line.startswith('  ') and not line.startswith('   ') and line.endswith(':'):
            current = line.strip()[:-1]
        if line == '      - name: Test affected agent tools':
            end = next((i for i in range(index + 1, len(lines)) if lines[i].startswith('      - ') or
                        lines[i].startswith('  ') and not lines[i].startswith('   ')), len(lines))
            body = lines[index + 1:end]
            phase = [int(item.split(':', 1)[1]) for item in body if item.startswith('        timeout-minutes: ')]
            commands = [shlex.split(item.strip()) for item in body if item.strip().startswith('python agent_tools/affected_agent_tests.py --run')]
            if phase != [50] or len(commands) != 1:
                raise ValueError('Unknown actual CI phase command')
            jobs.append((current, phase[0], commands[0]))
    return jobs


class ShardTests(unittest.TestCase):
    maxDiff = None

    def temporary(self):
        value = tempfile.TemporaryDirectory()
        self.addCleanup(value.cleanup)
        return Path(value.name).resolve()

    def git(self, root, *args):
        return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()

    def tiny(self, *, before=False, workload=False, phase_seconds=4.0):
        root = self.temporary()
        tools = root / 'agent_tools'
        tests = tools / 'tests'
        tests.mkdir(parents=True)
        for path in (tools / '__init__.py', tests / '__init__.py'):
            path.write_bytes(b'')
        for name in ('affected_agent_test_dependencies.json', 'agent_test_runner.py', 'agent_test_session_observer.py',
                     'agent_ci_evidence.py', 'agent_ci_module_seconds.json'):
            (tools / name).write_bytes((ROOT / 'agent_tools' / name).read_bytes())
        (tools / 'affected_agent_tests.py').write_bytes(retained('selector.before.source') if before else (ROOT / 'agent_tools/affected_agent_tests.py').read_bytes())
        (root / '.gitignore').write_text('.rag_index/\n__pycache__/\n')
        (root / 'Feature.kt').write_text('product')
        (tools / 'leaf.py').write_text('VALUE=1\n')
        if workload:
            # Physical READY/GO admission precedes the actual monotonic phase.
            # Each worker has its own imported phase object in its own checkout.
            (tools / 'phase.py').write_text('''import json,time
from pathlib import Path
START=None
BUDGET=PHASE_SECONDS
def run(name):
 global START
 if START is None:
  base=Path('.rag_index');base.mkdir(exist_ok=True)
  (base/'ready').write_text('READY')
  end=time.monotonic()+10
  while not (base/'go').exists():
   if time.monotonic()>end:raise TimeoutError('scaled readiness deadline')
   time.sleep(.01)
  START=time.monotonic()
 if time.monotonic()-START+.64>BUDGET:raise TimeoutError('scaled unchanged 50-minute phase')
 time.sleep(.64)
 elapsed=time.monotonic()-START
 if elapsed>BUDGET:raise TimeoutError('actual monotonic phase completion exceeded deadline')
 (Path('.rag_index')/('completed-'+name)).write_text(json.dumps({'name':name,'elapsedSeconds':elapsed,'phaseSeconds':BUDGET}))
'''.replace('PHASE_SECONDS', repr(phase_seconds)))
        for index in range(8 if workload else 3):
            name = 'test_ci_%02d' % index
            body = 'import unittest\nfrom agent_tools import leaf\n'
            if workload:
                body += 'from agent_tools import phase\n'
            body += 'class Case(unittest.TestCase):\n def test_value(self):\n'
            body += '  phase.run(%r)\n' % name if workload else '  self.assertEqual(1,leaf.VALUE)\n'
            (tests / (name + '.py')).write_text(body)
        self.git(root, 'init', '-q')
        self.git(root, 'config', 'user.email', 'fixture@example.invalid')
        self.git(root, 'config', 'user.name', 'Fixture')
        self.git(root, 'add', '.')
        self.git(root, 'commit', '-qm', 'source-owned tiny fixture')
        return root, self.git(root, 'rev-parse', 'HEAD')

    def invoke(self, root, base, index, *, extra=()):
        env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_') and key != 'DYLD_INSERT_LIBRARIES'}
        env.update(PYTHONDONTWRITEBYTECODE='1')
        return subprocess.run([sys.executable, '-B', str(root / 'agent_tools/affected_agent_tests.py'), '--baseline', base,
                               '--run', '--shard-index', str(index), '--shard-count', str(selector.CI_SHARD_COUNT), *extra],
                              cwd=root, env=env, capture_output=True, text=True, timeout=30)

    def test_partition_is_exact_and_gate_stays_first_only_in_its_bucket(self):
        gate = 'agent_tools.tests.test_ssh_connection_session_close'
        names = ('agent_tools.tests.test_a', gate, 'agent_tools.tests.test_z') + tuple(
            'agent_tools.tests.test_m%02d' % index for index in range(8))
        original = selector.Selection('a' * 40, (), names, len(names))
        for count in (2, selector.CI_SHARD_COUNT):
            with self.subTest(count=count):
                buckets = [selector.shard_selection(original, index, count) for index in range(count)]
                self.assertEqual(sorted(names), sorted(name for bucket in buckets for name in bucket.modules))
                self.assertEqual(len(names), len({name for bucket in buckets for name in bucket.modules}))
                commands = [command for bucket in buckets for command in bucket.commands('python')]
                self.assertEqual(1, sum(command[3:] == [gate] for command in commands))
                owner = next(bucket for bucket in buckets if gate in bucket.modules)
                self.assertEqual([gate], owner.commands('python')[0][3:])
        for index, count in ((0, 3), (2, 2), (-1, 2), (selector.CI_SHARD_COUNT, selector.CI_SHARD_COUNT), (True, 2), (0, 2.0)):
            with self.subTest(index=index, count=count), self.assertRaises(selector.SelectionError):
                selector.shard_selection(original, index, count)

    def test_managed_halves_stay_alternating_and_hosted_shards_follow_measured_durations(self):
        # Managed failed-first regrouping relies on the sorted alternating halves;
        # the hosted count uses the tracked duration table instead.
        for modules in (tuple(hosted_timing()['modules']), ('agent_tools.tests.test_a',), ()):
            selection = selector.Selection('a' * 40, (), modules, len(modules))
            for half in (0, 1):
                self.assertEqual(tuple(sorted(modules))[half::2], selector.shard_selection(selection, half, 2).modules)
            buckets = public.duration_partition(sorted(modules), selector.CI_SHARD_COUNT)
            for index in range(selector.CI_SHARD_COUNT):
                self.assertEqual(tuple(buckets[index]),
                                 selector.shard_selection(selection, index, selector.CI_SHARD_COUNT).modules)

    def test_default_and_include_commands_keep_the_existing_dispatch(self):
        value = selector.Selection('a' * 40, (), ('agent_tools.tests.test_a',), 1)
        self.assertEqual([['python', '-m', 'unittest', 'agent_tools.tests.test_a']], value.commands('python'))
        root, base = self.tiny()
        for index, extra in ((0, ('--include', 'agent_tools.tests.test_ci_00')), (0, ('--shard-count', '3')),
                             (0, ('--shard-count', '2')), (selector.CI_SHARD_COUNT, ())):
            result = self.invoke(root, base, index, extra=extra)
            self.assertNotEqual(0, result.returncode, (index, extra, result.stdout, result.stderr))
            self.assertFalse((root / '.rag_index').exists())

    def test_opaque_loader_in_other_bucket_never_refuses_selection(self):
        # Precise selection (TEST-004): an unseen dynamic import is left to the
        # recorded footprints and the complete CI suite, never a refusal.
        root, base = self.tiny()
        path = root / 'agent_tools/tests/test_ci_02.py'
        path.write_text(path.read_text() + '\nimport importlib\ndef opaque(name):return importlib.import_module(name)\n')
        for index in range(selector.CI_SHARD_COUNT):
            result = self.invoke(root, base, index, extra=('--ci-evidence-dir', '.rag_index/public-%d' % index))
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn('Unresolved', result.stderr)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'),
                         'POSIX pooled worker evidence')
    def test_every_real_checkout_produces_one_actual_complete_union(self):
        first, base = self.tiny()
        (first / 'agent_tools/leaf.py').write_text('VALUE=1\n# changed\n')
        roots = [first]
        for unused in range(1, selector.CI_SHARD_COUNT):
            roots.append(self.temporary())
            shutil.copytree(first, roots[-1], dirs_exist_ok=True)
        directories = []
        for index, root in enumerate(roots):
            result = self.invoke(root, base, index, extra=('--ci-evidence-dir', '.rag_index/public'))
            self.assertEqual(0, result.returncode, result.stderr)
            directories.append(root / '.rag_index/public')
        result = public.verify(directories, ['success'] * selector.CI_SHARD_COUNT)
        self.assertTrue(result['successful'])
        self.assertEqual(3, result['coveredModules'])

    def test_product_only_empty_shards_create_no_actor_and_never_reuse_evidence(self):
        root, base = self.tiny()
        (root / 'Feature.kt').write_text('product edit only')
        directories = []
        for index in range(selector.CI_SHARD_COUNT):
            relative = '.rag_index/public-%d' % index
            result = self.invoke(root, base, index, extra=('--ci-evidence-dir', relative))
            self.assertEqual(0, result.returncode, result.stderr)
            directory = root / relative
            directories.append(directory)
            summary = json.loads((directory / 'summary.json').read_bytes())
            self.assertEqual('empty-shard', summary['state'])
            self.assertEqual([], summary['commands'])
        self.assertEqual(0, public.verify(directories, ['success'] * selector.CI_SHARD_COUNT)['coveredModules'])
        self.assertFalse((root / '.rag_index/agent-test-runs').exists())
        original = {path.name: path.read_bytes() for path in directories[0].iterdir()}
        result = self.invoke(root, base, 0, extra=('--ci-evidence-dir', '.rag_index/public-0'))
        self.assertEqual(2, result.returncode)
        self.assertEqual(original, {path.name: path.read_bytes() for path in directories[0].iterdir()})
        self.assertFalse((root / '.rag_index/agent-test-runs').exists())

    def test_source_drift_cannot_publish_complete_shard_evidence(self):
        root, base = self.tiny()
        target = root / 'agent_tools/tests/test_ci_00.py'
        target.write_text('import unittest\nfrom pathlib import Path\nclass Case(unittest.TestCase):\n def test_value(self): Path("Feature.kt").write_text("drift")\n')
        result = self.invoke(root, base, 0, extra=('--ci-evidence-dir', '.rag_index/public'))
        self.assertEqual(2, result.returncode, result.stderr)
        summary = json.loads((root / '.rag_index/public/summary.json').read_bytes())
        self.assertIs(False, summary['sourceUnchanged'])
        self.assertIs(False, summary['successful'])
        self.assertEqual('incomplete', summary['state'])

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'),
                         'POSIX pooled worker evidence')
    def test_actual_workflow_completes_exact_global_selection_before_deadline(self):
        before = os.environ.get('AGENT_CI_SHARDS_BEFORE') == '1'
        raw = retained('workflow.before.yml') if before else (ROOT / '.github/workflows/fast-checks.yml').read_bytes()
        jobs = workflow_jobs(raw)
        template, base = self.tiny(before=before, workload=True, phase_seconds=jobs[0][1] * SCALE)
        (template / 'agent_tools/leaf.py').write_text('VALUE=1\n# affected global closure\n')
        actors = []
        records = []
        evidence_root = os.environ.get('AGENT_CI_SHARD_EVIDENCE')
        for ordinal, (job, minutes, argv) in enumerate(jobs):
            self.assertEqual(50, minutes)
            root = self.temporary()
            shutil.copytree(template, root, dirs_exist_ok=True)
            env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_') and key != 'DYLD_INSERT_LIBRARIES'}
            env.update(PYTHONDONTWRITEBYTECODE='1', AGENT_TEST_BASELINE=base, AUDIT_AGENT_TESTS='')
            # Logs live outside each Git checkout's fingerprint.
            logs = self.temporary()
            out = (logs / 'stdout').open('xb'); err = (logs / 'stderr').open('xb')
            command = [sys.executable, '-B', *argv[1:]]
            child = subprocess.Popen(command, cwd=root, env=env, stdout=out, stderr=err)
            out.close(); err.close()
            actors.append((child, root, logs))
            records.append({'job': job, 'command': command, 'phaseMinutes': minutes})
        try:
            readiness = time.monotonic() + 15
            while not all((root / '.rag_index/ready').exists() for child, root, logs in actors):
                if time.monotonic() > readiness or any(child.poll() is not None for child, root, logs in actors):
                    self.fail('Owned actual workflow did not reach READY')
                time.sleep(.01)
            for child, root, logs in actors:
                (root / '.rag_index/go').write_text('GO')
            for child, root, logs in actors:
                child.wait(timeout=15)
            for record, (child, root, logs) in zip(records, actors):
                reports = [path / 'report.json' for path in (root / '.rag_index/agent-test-runs').iterdir() if path.is_dir()]
                report = json.loads(reports[0].read_bytes()) if len(reports) == 1 else None
                closed = (report is not None and bool(report['workers']) and
                          all(worker['reaped'] and worker['sessionAbsent'] and not worker['descendantLeak']
                              and worker['fixtureRootRemoved'] for worker in report['workers']))
                record.update(returncode=child.returncode,
                              reaped=child.poll() is not None, workerClosure=closed, runnerReport=report,
                              completed=sorted(path.name for path in (root / '.rag_index').iterdir() if path.name.startswith('completed-')),
                              monotonicCompletions=[json.loads(path.read_bytes()) for path in (root / '.rag_index').iterdir() if path.name.startswith('completed-')],
                              stdout=(logs / 'stdout').read_text(), stderr=(logs / 'stderr').read_text())
            expected = ['completed-test_ci_%02d' % index for index in range(8)]
            completed = [name for record in records for name in record['completed']]
            complete = all(record['returncode'] == 0 and record['workerClosure'] for record in records) and sorted(completed) == expected
            if evidence_root:
                destination = Path(evidence_root)
                destination.mkdir(parents=True, exist_ok=True)
                with (destination / ('before.json' if before else 'current.json')).open('x') as stream:
                    json.dump({'before': before, 'scaleSecondsPerMinute': SCALE, 'workflowSha256': hashlib.sha256(raw).hexdigest(),
                               'complete': complete, 'actors': records}, stream, indent=2)
            self.assertTrue(complete, json.dumps({'complete': complete, 'actors': records}))
            if not before:
                self.assertTrue(public.verify([root / ('.rag_index/agent-ci-evidence-%d' % index) for index, (child, root, logs) in enumerate(actors)],
                                              ['success'] * len(actors))['successful'])
        finally:
            for child, root, logs in actors:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=20)
                self.assertIsNotNone(child.returncode)


class HostedCapacityTests(unittest.TestCase):
    """The actual hosted jobs and partition against run 40187427911's measured selection.

    Only the Linux CI run itself can confirm the wall time of each new hosted
    shard; this checks the application-controlled shard count and partition.
    """
    maxDiff = None
    workflow_raw = None
    partition = staticmethod(selector.shard_selection)

    def test_every_hosted_shard_fits_its_measured_share_with_growth_margin(self):
        raw = self.workflow_raw if self.workflow_raw is not None else (ROOT / '.github/workflows/fast-checks.yml').read_bytes()
        jobs = shard_minutes(raw, self.partition)
        print('HOSTED_SHARD_CAPACITY ' + json.dumps({'phaseShare': PHASE_SHARE, 'jobs': jobs}, sort_keys=True), flush=True)
        over = [job for job in jobs if job['minutes'] > PHASE_SHARE * job['phaseMinutes']]
        self.assertEqual([], over, 'measured hosted share exceeds %d%% of its phase bound: %s'
                         % (round(PHASE_SHARE * 100), json.dumps(jobs, sort_keys=True)))

    def test_whole_two_shard_workflow_and_selector_exceed_the_measured_capacity(self):
        # RED on the whole cc2873b5 beforeimages: both of their shards exceed even
        # the whole 50-minute phase, as in the hosted run. Each half of the fix
        # is needed: the old workflow still plans two shards, and the old
        # selector refuses the new hosted count.
        workflow, partition = preserved('workflow.before.yml'), preserved_partition()
        records = {}
        for label, raw, chosen in (('before', workflow, partition), ('before-workflow', workflow, selector.shard_selection),
                                   ('before-selector', None, partition), ('current', None, selector.shard_selection)):
            case = type(self)('test_every_hosted_shard_fits_its_measured_share_with_growth_margin')
            case.workflow_raw, case.partition = raw, chosen
            result = unittest.TestResult()
            case.run(result)
            records[label] = {'testsRun': result.testsRun, 'failures': [text for unused, text in result.failures],
                              'errors': [text for unused, text in result.errors]}
        print('HOSTED_SHARD_CAPACITY_CAUSAL ' + json.dumps(records, sort_keys=True), flush=True)
        self.assertEqual(1, len(records['before']['failures']), records)
        self.assertIn('measured hosted share exceeds 60% of its phase bound', records['before']['failures'][0])
        before = shard_minutes(workflow, partition)
        self.assertEqual([0, 1], [job['shardIndex'] for job in before], before)
        self.assertTrue(all(job['minutes'] > job['phaseMinutes'] for job in before), before)
        self.assertEqual(1, len(records['before-workflow']['failures']), records)
        self.assertEqual(1, len(records['before-selector']['errors']), records)
        self.assertIn('CI shards require index 0 or 1 and count 2', records['before-selector']['errors'][0])
        self.assertEqual(([], []), (records['current']['failures'], records['current']['errors']), records)


GATE_PREFIX = 'ci-gate.'
# Hosted agent shards run beside the Fast Checks hygiene and Gradle job, whose
# measured non-agent work is about 15 minutes; no shard may extend that path.
HOSTED_SHARD_TARGET_MINUTES = 16


def gate_before(name):
    """A whole a34e07cb beforeimage of the CI agent stage, authenticated by its provenance."""
    metadata = json.loads((FIXTURE / 'ci-gate.provenance.json').read_bytes())
    row = next(item for item in metadata['files'] if item['path'] == GATE_PREFIX + name)
    raw = (FIXTURE / row['path']).read_bytes()
    if len(raw) != row['sourceBytes'] or hashlib.sha256(raw).hexdigest() != row['sourceSha256']:
        raise ValueError('Preserved CI gate source changed: ' + name)
    return raw


def gate_before_manifest(tools):
    """The schema 1 manifest entries the a34e07cb stage needs, pinned to the copied runner and projector.

    At a34e07cb the tracked manifest declared these two loaders (same scopes) with digests of the
    sources in that tree; that selector cannot read the schema 2 manifest, which has no digests.
    """
    digest = lambda name: hashlib.sha256((tools / name).read_bytes()).hexdigest()
    return {'schemaVersion': 1, 'nonPythonResources': {}, 'loaders': {
        'agent_tools/agent_test_runner.py': {
            'reason': 'Transparent execution of selected, validated test inputs; those test modules are the '
                      'selection graph roots.',
            'scopes': ['agent_tools/agent_test_session_observer.py'],
            'sourceSha256': [digest('agent_test_runner.py')]},
        'agent_tools/agent_ci_evidence.py': {
            'reason': 'Explicit CI-only projector reads only the freshly allocated runner directory and explicit '
                      'public artifact inputs.',
            'scopes': [], 'sourceSha256': [digest('agent_ci_evidence.py')]}}}


def gate_before_partition():
    """The a34e07cb selector's own sorted alternating shard_selection."""
    raw = gate_before('selector.before.source')
    functions = [node for node in ast.parse(raw).body
                 if isinstance(node, ast.FunctionDef) and node.name == 'shard_selection']
    namespace = {'Selection': selector.Selection, 'SelectionError': selector.SelectionError, 'CI_SHARD_COUNT': 6}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(FIXTURE / 'ci-gate.selector.before.source'), 'exec'),
         namespace)
    return namespace['shard_selection']


def full_suite_minutes(raw, partition):
    """Measured minutes of every actual hosted shard over the complete current agent suite."""
    measured, default = public.module_seconds()
    modules = tuple(sorted(path[:-3].replace('/', '.') for path in subprocess.check_output(
        ['git', '-C', str(ROOT), 'ls-files', '-z', 'agent_tools/tests/test_*.py'], text=True).split('\0') if path))
    selection = selector.Selection('a' * 40, (), modules, len(modules))
    jobs = []
    for job, minutes, argv in workflow_jobs(raw):
        index, count = (int(argv[argv.index(flag) + 1]) for flag in ('--shard-index', '--shard-count'))
        assigned = partition(selection, index, count).modules
        jobs.append({'job': job, 'shardIndex': index, 'shardCount': count, 'modules': len(assigned),
                     'minutes': round(sum(measured.get(name, default) for name in assigned) / 60, 2)})
    return jobs


class HostedDurationTests(unittest.TestCase):
    """Duration-assigned hosted shards over the measured complete suite (run 43877068416)."""
    maxDiff = None
    workflow_raw = None
    partition = staticmethod(selector.shard_selection)

    def test_every_hosted_shard_fits_beside_the_fast_checks_job(self):
        raw = self.workflow_raw if self.workflow_raw is not None else (ROOT / '.github/workflows/fast-checks.yml').read_bytes()
        jobs = full_suite_minutes(raw, self.partition)
        print('HOSTED_SHARD_DURATION ' + json.dumps({'targetMinutes': HOSTED_SHARD_TARGET_MINUTES, 'jobs': jobs},
                                                     sort_keys=True), flush=True)
        self.assertEqual(list(range(len(jobs))), sorted(job['shardIndex'] for job in jobs))
        over = [job for job in jobs if job['minutes'] > HOSTED_SHARD_TARGET_MINUTES]
        self.assertEqual([], over, 'hosted shard exceeds %d minutes: %s' % (HOSTED_SHARD_TARGET_MINUTES, json.dumps(jobs)))

    def test_whole_a34e07cb_alternating_shards_exceed_the_target(self):
        # RED on the whole a34e07cb workflow and selector: six sorted alternating
        # shards put up to ~29 measured minutes in one job. GREEN now.
        records = {}
        for label, raw, chosen in (('before', gate_before('workflow.before.yml'), gate_before_partition()),
                                   ('current', None, selector.shard_selection)):
            case = type(self)('test_every_hosted_shard_fits_beside_the_fast_checks_job')
            case.workflow_raw, case.partition = raw, chosen
            result = unittest.TestResult()
            case.run(result)
            records[label] = {'testsRun': result.testsRun, 'failures': [text for unused, text in result.failures],
                              'errors': [text for unused, text in result.errors]}
        print('HOSTED_SHARD_DURATION_CAUSAL ' + json.dumps(records, sort_keys=True), flush=True)
        self.assertEqual((1, 1, []), (records['before']['testsRun'], len(records['before']['failures']),
                                      records['before']['errors']), records)
        self.assertIn('hosted shard exceeds', records['before']['failures'][0])
        self.assertEqual((1, [], []), (records['current']['testsRun'], records['current']['failures'],
                                       records['current']['errors']), records)


class CiGateTests(unittest.TestCase):
    """The actual hosted shard commands: none, or the complete suite on any agent input."""
    maxDiff = None
    temporary = ShardTests.temporary
    git = ShardTests.git

    def template(self, *, before, opaque):
        root = self.temporary()
        tools = root / 'agent_tools'
        (tools / 'tests').mkdir(parents=True)
        for name in ('__init__.py', 'tests/__init__.py'):
            (tools / name).write_bytes(b'')
        for name in ('affected_agent_test_dependencies.json', 'agent_test_runner.py', 'agent_test_session_observer.py',
                     'agent_ci_module_seconds.json'):
            (tools / name).write_bytes((ROOT / 'agent_tools' / name).read_bytes())
        (tools / 'affected_agent_tests.py').write_bytes(
            gate_before('selector.before.source') if before else (ROOT / 'agent_tools/affected_agent_tests.py').read_bytes())
        (tools / 'agent_ci_evidence.py').write_bytes(
            gate_before('evidence.before.source') if before else (ROOT / 'agent_tools/agent_ci_evidence.py').read_bytes())
        if before:
            # The a34e07cb selector reads only its schema 1 manifest, whose reviewed loaders pinned the
            # exact runner and projector sources it ran with. Rebuild that shape for the copied files.
            (tools / 'affected_agent_test_dependencies.json').write_text(json.dumps(gate_before_manifest(tools)))
        (root / '.gitignore').write_text('.rag_index/\n__pycache__/\n')
        (root / 'Feature.kt').write_text('product')
        (tools / 'leaf.py').write_text('VALUE=1\n')
        for index in range(3):
            (tools / 'tests' / ('test_ci_%02d.py' % index)).write_text(
                'import unittest\nfrom agent_tools import leaf\nclass Case(unittest.TestCase):\n'
                ' def test_value(self):\n  self.assertEqual(1, leaf.VALUE)\n')
        # Not a consumer of leaf.py: affected selection omits it, the gate runs it.
        (tools / 'tests/test_unrelated.py').write_text(
            'import unittest\nclass Case(unittest.TestCase):\n def test_value(self):\n  self.assertTrue(True)\n')
        if opaque:
            (tools / 'tests/test_opaque.py').write_text(
                'import importlib\nimport unittest\ndef load(name):\n return importlib.import_module(name)\n'
                'class Case(unittest.TestCase):\n def test_value(self):\n  self.assertTrue(True)\n')
        self.git(root, 'init', '-q')
        self.git(root, 'config', 'user.email', 'fixture@example.invalid')
        self.git(root, 'config', 'user.name', 'Fixture')
        self.git(root, 'add', '.')
        self.git(root, 'commit', '-qm', 'source-owned gate fixture')
        return root, self.git(root, 'rev-parse', 'HEAD')

    def run_jobs(self, raw, *, before, opaque, change):
        template, base = self.template(before=before, opaque=opaque)
        for path, text in change.items():
            (template / path).write_text(text)
        records, directories = [], []
        for job, minutes, argv in workflow_jobs(raw):
            root = self.temporary()
            shutil.copytree(template, root, dirs_exist_ok=True)
            env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_') and key != 'DYLD_INSERT_LIBRARIES'}
            env.update(PYTHONDONTWRITEBYTECODE='1', AGENT_TEST_BASELINE=base, AUDIT_AGENT_TESTS='')
            result = subprocess.run([sys.executable, '-B', *argv[1:]], cwd=root, env=env, capture_output=True,
                                    text=True, timeout=120)
            index = int(argv[argv.index('--shard-index') + 1])
            evidence = root / ('.rag_index/agent-ci-evidence-%d' % index)
            plan = json.loads((evidence / 'plan.json').read_bytes()) if (evidence / 'plan.json').exists() else None
            records.append({'job': job, 'returncode': result.returncode, 'stderr': result.stderr[-2000:],
                            'globalModules': None if plan is None else plan['modules'],
                            'assigned': None if plan is None else plan['assignedModules']})
            directories.append(evidence)
        return records, directories

    def test_actual_workflow_runs_the_complete_suite_without_dependency_analysis(self):
        raw = (ROOT / '.github/workflows/fast-checks.yml').read_bytes()
        records, directories = self.run_jobs(raw, before=False, opaque=True, change={'agent_tools/leaf.py': 'VALUE=1\n# changed\n'})
        everything = ['agent_tools.tests.test_ci_00', 'agent_tools.tests.test_ci_01', 'agent_tools.tests.test_ci_02',
                      'agent_tools.tests.test_opaque', 'agent_tools.tests.test_unrelated']
        self.assertEqual([0] * selector.CI_SHARD_COUNT, [record['returncode'] for record in records], records)
        self.assertEqual([everything] * selector.CI_SHARD_COUNT, [record['globalModules'] for record in records])
        result = public.verify(directories, ['success'] * selector.CI_SHARD_COUNT)
        self.assertEqual(len(everything), result['coveredModules'])

    def test_actual_workflow_product_and_prose_only_run_no_agent_test(self):
        raw = (ROOT / '.github/workflows/fast-checks.yml').read_bytes()
        records, directories = self.run_jobs(raw, before=False, opaque=True,
                                             change={'Feature.kt': 'product edit', 'AGENTS.md': 'prose'})
        self.assertEqual([0] * selector.CI_SHARD_COUNT, [record['returncode'] for record in records], records)
        self.assertEqual([[]] * selector.CI_SHARD_COUNT, [record['globalModules'] for record in records])
        self.assertEqual(0, public.verify(directories, ['success'] * selector.CI_SHARD_COUNT)['coveredModules'])

    def test_gate_without_a_comparison_baseline_runs_the_complete_suite(self):
        root, base = self.template(before=False, opaque=False)
        env = {key: value for key, value in os.environ.items() if not key.startswith('GITHUB_')}
        with mock.patch.dict(os.environ, {**env, 'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(root / 'missing.json')},
                             clear=True):
            value = selector.select_ci_gate(root)
        self.assertEqual(base, value.baseline)
        self.assertEqual(4, len(value.modules))
        audit = selector.select_ci_gate(root, base, audit=True)
        self.assertEqual(value.modules, audit.modules)

    def red_gate_sets(self, root, argv, env):
        """The changed set every hosted shard hands to the runner's RED gate (None: every RED half runs)."""
        seen = []

        def prepare(_root, _command, _fingerprint, changed=None):
            seen.append(None if changed is None else sorted(changed))
            return [sys.executable, '-c', 'pass']

        clean = {key: value for key, value in os.environ.items()
                 if not key.startswith('GITHUB_') and key != 'AGENT_TEST_BASELINE'}
        with mock.patch.object(selector, 'prepare_run', side_effect=prepare), \
                mock.patch.dict(os.environ, {**clean, **env}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()):
            for index in range(selector.CI_SHARD_COUNT):
                self.assertEqual(0, selector.main(['--root', str(root), *argv, '--shard-index', str(index),
                                                   '--shard-count', str(selector.CI_SHARD_COUNT)]))
        self.assertTrue(seen)
        return seen

    def test_hosted_red_gate_gets_the_push_changed_set_and_none_without_a_baseline_or_in_an_audit(self):
        root, base = self.template(before=False, opaque=False)
        (root / 'agent_tools/leaf.py').write_text('VALUE=1\n# changed\n')
        # A push compared with its baseline hands the real changed set, so unchanged RED halves may skip.
        pushed = self.red_gate_sets(root, ['--run', '--ci-gate'], {'AGENT_TEST_BASELINE': base})
        self.assertEqual([['agent_tools/leaf.py']] * len(pushed), pushed)
        # No established baseline: the complete suite runs and so does every RED half (an empty set would skip them all).
        unknown = self.red_gate_sets(root, ['--run', '--ci-gate'],
                                     {'GITHUB_EVENT_NAME': 'push', 'GITHUB_EVENT_PATH': str(root / 'missing.json')})
        self.assertEqual([None] * len(unknown), unknown)
        # The workflow's explicit audit (dispatch passes --baseline) re-proves every RED half.
        audit = self.red_gate_sets(root, ['--baseline', base, '--audit', '--run'], {})
        self.assertEqual([None] * len(audit), audit)

    def test_whole_a34e07cb_stage_selects_only_consumers_or_refuses_current_runs_all(self):
        # RED on the whole a34e07cb workflow, selector and projector: the
        # affected selection omits the unrelated suite and an unreviewed
        # dynamic import refuses every shard. GREEN: the gate runs everything.
        raw = gate_before('workflow.before.yml')
        change = {'agent_tools/leaf.py': 'VALUE=1\n# changed\n'}
        omitted, unused = self.run_jobs(raw, before=True, opaque=False, change=change)
        refused, unused = self.run_jobs(raw, before=True, opaque=True, change=change)
        print('CI_GATE_CAUSAL ' + json.dumps({'beforeOmitted': omitted, 'beforeRefused': refused}, sort_keys=True), flush=True)
        self.assertEqual(6, len(omitted))
        self.assertEqual([0] * 6, [record['returncode'] for record in omitted], omitted)
        self.assertNotIn('agent_tools.tests.test_unrelated', omitted[0]['globalModules'])
        self.assertEqual([2] * 6, [record['returncode'] for record in refused], refused)
        self.assertTrue(all('Unresolved' in record['stderr'] for record in refused), refused)
        current, unused = self.run_jobs((ROOT / '.github/workflows/fast-checks.yml').read_bytes(), before=False, opaque=False,
                                        change=change)
        self.assertIn('agent_tools.tests.test_unrelated', current[0]['globalModules'])
        self.assertEqual([0] * selector.CI_SHARD_COUNT, [record['returncode'] for record in current], current)


if __name__ == '__main__':
    unittest.main()
