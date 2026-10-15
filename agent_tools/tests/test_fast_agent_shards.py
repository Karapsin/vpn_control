"""Validate actual CI jobs and receipt wiring against the retained full tail."""
import ast
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_tools.tests import test_agent_ci_shards as fixture


ROOT = Path(__file__).resolve().parents[2]


def workflow_jobs(raw):
    """Strict stdlib reader for this workflow's jobs/maps/lists/literal blocks.

    This deliberately refuses YAML anchors, folded blocks and unknown nesting;
    CI wiring changes require review rather than an optional parser dependency.
    """
    lines = raw.decode('utf-8').splitlines()
    starts = [index for index, line in enumerate(lines) if line == 'jobs:']
    if len(starts) != 1:
        raise ValueError('Expected one workflow jobs mapping')
    lines = lines[starts[0] + 1:]

    def scalar(value):
        if value.startswith(('&', '*', '!', '>', '{')):
            raise ValueError('Unsupported workflow scalar')
        if value.startswith(('"', "'")):
            parsed = ast.literal_eval(value)
            if not isinstance(parsed, str):
                raise ValueError('Workflow string required')
            return parsed
        if value in ('true', 'false'):
            return value == 'true'
        if re.fullmatch(r'0|[1-9][0-9]*', value):
            return int(value)
        if value.startswith('['):
            if not value.endswith(']'):
                raise ValueError('Invalid workflow sequence')
            items = [item.strip() for item in value[1:-1].split(',')]
            if not items or any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', item) for item in items):
                raise ValueError('Invalid workflow sequence item')
            return items
        return value

    def skip(index):
        while index < len(lines) and not lines[index].strip():
            index += 1
        return index

    def indentation(line):
        if '\t' in line:
            raise ValueError('Workflow tabs are unsupported')
        return len(line) - len(line.lstrip(' '))

    def mapping(index, indent):
        result = {}
        while (index := skip(index)) < len(lines):
            line = lines[index]
            depth = indentation(line)
            if depth < indent:
                break
            if depth != indent:
                raise ValueError('Unexpected workflow indentation')
            key, separator, value = line[indent:].partition(':')
            if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', key) or key in result:
                raise ValueError('Invalid or duplicate workflow key')
            value = value.strip()
            index += 1
            if value == '|':
                body = []
                while index < len(lines):
                    body_line = lines[index]
                    if body_line.strip() and indentation(body_line) < indent + 2:
                        break
                    body.append(body_line[indent + 2:] if body_line.strip() else '')
                    index += 1
                result[key] = '\n'.join(body).rstrip('\n') + '\n'
            elif value:
                result[key] = scalar(value)
            else:
                index = skip(index)
                if index >= len(lines) or indentation(lines[index]) != indent + 2:
                    raise ValueError('Missing workflow nested mapping')
                if lines[index][indent + 2:].startswith('- '):
                    values = []
                    while (index := skip(index)) < len(lines) and indentation(lines[index]) == indent + 2:
                        if not lines[index][indent + 2:].startswith('- '):
                            raise ValueError('Invalid workflow step list')
                        # Inline first map entry and subsequent keys have the
                        # same logical indentation after the sequence marker.
                        lines[index] = ' ' * (indent + 4) + lines[index][indent + 4:]
                        item, index = mapping(index, indent + 4)
                        values.append(item)
                    result[key] = values
                else:
                    result[key], index = mapping(index, indent + 2)
        return result, index

    jobs, end = mapping(skip(0), 2)
    if skip(end) != len(lines):
        raise ValueError('Unconsumed workflow source')
    return jobs


class FastAgentShardWorkflowTests(unittest.TestCase):
    def workflow(self):
        return {'jobs': workflow_jobs((ROOT / '.github/workflows/fast-checks.yml').read_bytes())}

    def named(self, job, name):
        steps = [step for step in job['steps'] if step.get('name') == name]
        self.assertEqual(1, len(steps), name)
        return steps[0]

    def test_both_fresh_hosted_jobs_have_identical_admission_and_unchanged_limits(self):
        jobs = self.workflow()['jobs']
        agent = [jobs['fast-checks'], jobs['agent-tests-shard-1']]
        phases = []
        for index, job in enumerate(agent):
            self.assertEqual('ubuntu-latest', job['runs-on'])
            self.assertEqual(90, job['timeout-minutes'])
            self.assertNotIn('strategy', job)
            steps = job['steps']
            checkout = self.named(job, 'Checkout')
            self.assertEqual({'fetch-depth': 0}, checkout['with'])
            python = self.named(job, 'Set up Python 3.12')
            self.assertEqual('3.12', python['with']['python-version'])
            dependency = self.named(job, 'Install agent tool dependencies')
            qemu = self.named(job, 'Install qemu-img for agent fixtures')
            phase = self.named(job, 'Test affected agent tools')
            phases.append(phase)
            self.assertEqual(50, phase['timeout-minutes'])
            self.assertLess(steps.index(checkout), steps.index(python))
            self.assertLess(steps.index(python), steps.index(dependency))
            self.assertLess(steps.index(dependency), steps.index(phase))
            self.assertLess(steps.index(qemu), steps.index(phase))
            commands = [shlex.split(line.strip()) for line in phase['run'].splitlines()
                        if line.strip().startswith('python agent_tools/affected_agent_tests.py ')]
            self.assertEqual(2, len(commands))
            audit, affected = commands
            self.assertEqual(['python', 'agent_tools/affected_agent_tests.py', '--baseline', '$AGENT_TEST_BASELINE', '--audit', '--run'], audit[:6])
            self.assertEqual(['python', 'agent_tools/affected_agent_tests.py', '--run'], affected[:3])
            tail = ['--shard-index', str(index), '--shard-count', '2', '--ci-evidence-dir', '.rag_index/agent-ci-evidence-%d' % index]
            self.assertEqual(tail, audit[6:])
            self.assertEqual(tail, affected[3:])
            self.assertNotIn('--include', phase['run'])
        self.assertEqual(phases[0]['env'], phases[1]['env'])
        self.assertEqual("${{ github.event_name == 'workflow_dispatch' && (inputs.baseline || github.sha) || '' }}", phases[0]['env']['AGENT_TEST_BASELINE'])
        self.assertEqual("${{ inputs.audit_agent_tests && '1' || '' }}", phases[0]['env']['AUDIT_AGENT_TESTS'])

    def test_entire_original_build_tail_remains_once_in_its_original_job(self):
        original = workflow_jobs(fixture.retained('workflow.before.yml'))['fast-checks']['steps']
        start = next(index for index, step in enumerate(original) if step.get('name') == 'Test affected agent tools')
        tail = original[start + 1:]
        jobs = self.workflow()['jobs']
        current = jobs['fast-checks']['steps']
        self.assertEqual(tail, [step for step in current if any(step.get('name') == old.get('name') for old in tail)])
        for old in tail:
            owners = [name for name, job in jobs.items() for step in job['steps'] if step.get('name') == old.get('name')]
            self.assertEqual(['fast-checks'], owners)

    def test_uploads_only_fixed_public_files_from_this_run_and_attempt(self):
        jobs = self.workflow()['jobs']
        names = []
        for index, key in enumerate(('fast-checks', 'agent-tests-shard-1')):
            step = self.named(jobs[key], 'Retain public agent shard evidence')
            self.assertEqual('always()', step['if'])
            self.assertEqual('actions/upload-artifact@v4', step['uses'])
            self.assertEqual({'name', 'if', 'uses', 'with'}, set(step))
            options = step['with']
            self.assertEqual({'name', 'path', 'if-no-files-found', 'include-hidden-files', 'retention-days'}, set(options))
            name = 'agent-test-shard-${{ github.run_id }}-${{ github.run_attempt }}-%d' % index
            self.assertEqual(name, options['name'])
            names.append(name)
            expected = ['.rag_index/agent-ci-evidence-%d/%s' % (index, name)
                        for name in ('plan.json', 'events.jsonl', 'summary.json')]
            self.assertEqual(expected, options['path'].splitlines())
            self.assertEqual('error', options['if-no-files-found'])
            self.assertIs(True, options['include-hidden-files'])
            self.assertEqual(7, options['retention-days'])
        coverage = jobs['agent-test-coverage']
        self.assertEqual('always()', coverage['if'])
        self.assertEqual({'fast-checks', 'agent-tests-shard-1'}, set(coverage['needs']))
        downloads = [step for step in coverage['steps'] if step.get('uses') == 'actions/download-artifact@v4']
        self.assertEqual(names, [step['with']['name'] for step in downloads])
        self.assertEqual(['.rag_index/agent-ci-evidence-0', '.rag_index/agent-ci-evidence-1'], [step['with']['path'] for step in downloads])

    def test_coverage_verifier_requires_actual_parents_and_current_invocation(self):
        job = self.workflow()['jobs']['agent-test-coverage']
        step = self.named(job, 'Require actual complete disjoint shard coverage')
        self.assertEqual({'FIRST_SHARD_RESULT': '${{ needs.fast-checks.result }}',
                          'SECOND_SHARD_RESULT': '${{ needs.agent-tests-shard-1.result }}'}, step['env'])
        argv = shlex.split(step['run'])
        self.assertEqual(['python', 'agent_tools/agent_ci_evidence.py', '--verify',
                          '.rag_index/agent-ci-evidence-0', '.rag_index/agent-ci-evidence-1',
                          '--parent-results', '$FIRST_SHARD_RESULT', '$SECOND_SHARD_RESULT',
                          '--run-id', '${{ github.run_id }}', '--run-attempt', '${{ github.run_attempt }}',
                          '--head', '${{ github.sha }}'], argv)
        self.assertFalse(any(step.get('continue-on-error') for step in job['steps']))
        self.assertNotIn('continue-on-error', job)

    def test_strict_reader_refuses_duplicate_keys_and_unknown_yaml_features(self):
        for source in (b'jobs:\n  task:\n    name: first\n    name: second\n',
                       b'jobs:\n  task:\n    name: &shared value\n',
                       b'jobs:\n  task:\n    run: >\n      folded\n',
                       b'jobs:\n  task:\n     name: wrong-indent\n'):
            with self.subTest(source=source):
                with self.assertRaises(ValueError):
                    workflow_jobs(source)

    def test_saved_isolated_stdlib_child_runs_the_same_positive_without_yaml(self):
        before = fixture.retained('wiring.before.source')
        current_path = ROOT / 'agent_tools/tests/test_fast_agent_shards.py'
        current = current_path.read_bytes()
        harness = '''import hashlib,sys,unittest
from pathlib import Path
root,source,expected=sys.argv[1:]
sys.path.insert(0,root)
raw=Path(source).read_bytes()
if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('Owned wiring source changed')
namespace={'__name__':'owned_wiring','__file__':source}
exec(compile(raw,source,'exec'),namespace)
case=namespace['FastAgentShardWorkflowTests']('test_both_fresh_hosted_jobs_have_identical_admission_and_unchanged_limits')
result=unittest.TextTestRunner().run(case)
raise SystemExit(0 if result.wasSuccessful() else 1)
'''
        records = []
        with tempfile.TemporaryDirectory() as temporary:
            program = Path(temporary).resolve() / 'stdlib-wiring.py'
            fd = os.open(program, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(harness.encode('utf-8'))
            env = dict(os.environ)
            env.pop('DYLD_INSERT_LIBRARIES', None)
            for label, source, raw in (('before', fixture.FIXTURE / 'wiring.before.source', before),
                                       ('current', current_path, current)):
                args = [sys.executable, '-I', '-S', '-B', str(program), str(ROOT), str(source), hashlib.sha256(raw).hexdigest()]
                result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=20)
                records.append({'source': label, 'args': args, 'sourceSha256': hashlib.sha256(raw).hexdigest(),
                                'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
            print(json.dumps({'event': 'stdlib-wiring-causal', 'children': records}, sort_keys=True))
            self.assertEqual(1, records[0]['returncode'], records)
            self.assertIn("ModuleNotFoundError: No module named 'yaml'", records[0]['stderr'])
            self.assertEqual(0, records[1]['returncode'], records)
            self.assertIn('Ran 1 test', records[1]['stderr'])


if __name__ == '__main__':
    unittest.main()
