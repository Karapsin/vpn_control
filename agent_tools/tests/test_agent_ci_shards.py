"""Actual tiny Git checkouts and unchanged scaled CI phase deadlines.

The synthetic workload proves deterministic partition throughput, not the cause
of the unobserved hosted timeout. Historical timing is never an allocation input.
"""
import hashlib
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

from agent_tools import affected_agent_tests as selector
from agent_tools import agent_ci_evidence as public


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_name('fixtures') / 'agent_ci_shards'
SCALE = 0.08


def retained(name):
    metadata = json.loads((FIXTURE / 'provenance.json').read_bytes())
    row = next(item for item in metadata['files'] if item['path'] == name)
    raw = (FIXTURE / name).read_bytes()
    if len(raw) != row['sourceBytes'] or hashlib.sha256(raw).hexdigest() != row['sourceSha256']:
        raise ValueError('Preserved CI source changed')
    return raw


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
        for name in ('affected_agent_test_dependencies.json', 'agent_test_runner.py', 'agent_test_session_observer.py', 'agent_ci_evidence.py'):
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
                               '--run', '--shard-index', str(index), '--shard-count', '2', *extra],
                              cwd=root, env=env, capture_output=True, text=True, timeout=30)

    def test_partition_is_exact_and_gate_stays_first_only_in_its_bucket(self):
        gate = 'agent_tools.tests.test_ssh_connection_session_close'
        names = ('agent_tools.tests.test_a', gate, 'agent_tools.tests.test_z')
        original = selector.Selection('a' * 40, (), names, len(names))
        buckets = [selector.shard_selection(original, index, 2) for index in (0, 1)]
        self.assertEqual(sorted(names), sorted(name for bucket in buckets for name in bucket.modules))
        self.assertFalse(set(buckets[0].modules) & set(buckets[1].modules))
        commands = [command for bucket in buckets for command in bucket.commands('python')]
        self.assertEqual(1, sum(command[3:] == [gate] for command in commands))
        owner = next(bucket for bucket in buckets if gate in bucket.modules)
        self.assertEqual([gate], owner.commands('python')[0][3:])

    def test_default_and_include_commands_keep_the_existing_dispatch(self):
        value = selector.Selection('a' * 40, (), ('agent_tools.tests.test_a',), 1)
        self.assertEqual([['python', '-m', 'unittest', 'agent_tools.tests.test_a']], value.commands('python'))
        root, base = self.tiny()
        for extra in (('--include', 'agent_tools.tests.test_ci_00'), ('--shard-count', '3')):
            result = self.invoke(root, base, 0, extra=extra)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((root / '.rag_index').exists())

    def test_unknown_loader_in_other_bucket_refuses_before_either_actor(self):
        root, base = self.tiny()
        path = root / 'agent_tools/tests/test_ci_02.py'
        path.write_text(path.read_text() + '\nimport importlib\ndef opaque(name):return importlib.import_module(name)\n')
        for index in (0, 1):
            result = self.invoke(root, base, index, extra=('--ci-evidence-dir', '.rag_index/public-%d' % index))
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertIn('Unresolved', result.stderr)
        self.assertFalse((root / '.rag_index').exists())

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'),
                         'POSIX pooled worker evidence')
    def test_two_real_checkouts_produce_one_actual_complete_union(self):
        first, base = self.tiny()
        (first / 'agent_tools/leaf.py').write_text('VALUE=1\n# changed\n')
        second = self.temporary()
        shutil.copytree(first, second, dirs_exist_ok=True)
        directories = []
        for index, root in enumerate((first, second)):
            result = self.invoke(root, base, index, extra=('--ci-evidence-dir', '.rag_index/public'))
            self.assertEqual(0, result.returncode, result.stderr)
            directories.append(root / '.rag_index/public')
        result = public.verify(directories, ['success', 'success'])
        self.assertTrue(result['successful'])
        self.assertEqual(3, result['coveredModules'])

    def test_product_only_empty_shards_create_no_actor_and_never_reuse_evidence(self):
        root, base = self.tiny()
        (root / 'Feature.kt').write_text('product edit only')
        directories = []
        for index in (0, 1):
            relative = '.rag_index/public-%d' % index
            result = self.invoke(root, base, index, extra=('--ci-evidence-dir', relative))
            self.assertEqual(0, result.returncode, result.stderr)
            directory = root / relative
            directories.append(directory)
            summary = json.loads((directory / 'summary.json').read_bytes())
            self.assertEqual('empty-shard', summary['state'])
            self.assertEqual([], summary['commands'])
        self.assertEqual(0, public.verify(directories, ['success', 'success'])['coveredModules'])
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
                self.assertTrue(public.verify([root / ('.rag_index/agent-ci-evidence-%d' % index) for index, (child, root, logs) in enumerate(actors)], ['success', 'success'])['successful'])
        finally:
            for child, root, logs in actors:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=20)
                self.assertIsNotNone(child.returncode)


if __name__ == '__main__':
    unittest.main()
