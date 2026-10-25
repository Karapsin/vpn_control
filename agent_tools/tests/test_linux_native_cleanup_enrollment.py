"""Keep the real Linux cleanup controls enrolled independently of changed paths."""
import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'agent_tools/tests/fixtures/linux_native_cleanup_enrollment'
WORKFLOW = ROOT / '.github/workflows/linux-desktop.yml'
TEMURIN = ROOT / 'agent_tools/tests/test_temurin_artifact_continuity.py'
TARGET = 'agent_tools.tests.test_temurin_artifact_continuity.CleanupOwnershipTests'
METHODS = frozenset((
    'test_actual_retainer_old_tuple_cleanup_red_and_all_fixed_contexts_close',
    'test_every_partial_retainer_and_cleanup_context_admission_closes_fds',
    'test_owned_root_and_descendant_generation_tamper_still_refuse',
    'test_shared_coordinator_mutation_keeps_owned_155_record_retainer',
))
BEFORE_SHA = 'a5886a0ae519834adc8012d05af5d596b7440e076e62e8ee494bfa5b5ddf909e'
BEFORE_RED = '--before-red' in sys.argv
if BEFORE_RED:
    sys.argv.remove('--before-red')


def _read(path):
    raw = path.read_bytes()
    assert len(raw) <= 1048576, 'workflow/test source bound'
    return raw


def _workflow_text(raw):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    assert '\r' not in text, 'lone CR in workflow source'
    return text


def _job(text, name):
    top = list(re.finditer(r'^([A-Za-z0-9_-]+):[^\n]*$', text, re.M))
    assert len({m.group(1) for m in top}) == len(top), 'duplicate top-level mapping'
    assert {m.group(1) for m in top} == {'name', 'run-name', 'on', 'jobs'}, 'unexpected top-level authority or defaults'
    indexes = [i for i, m in enumerate(top) if m.group(1) == 'jobs']
    assert len(indexes) == 1 and top[indexes[0]].group(0) == 'jobs:', 'unique jobs mapping required'
    i = indexes[0]
    jobs = text[top[i].end():top[i + 1].start() if i + 1 < len(top) else len(text)]
    hits = list(re.finditer(r'^  ([A-Za-z0-9_-]+):\s*$', jobs, re.M))
    assert len({m.group(1) for m in hits}) == len(hits), 'duplicate workflow job'
    indexes = [i for i, m in enumerate(hits) if m.group(1) == name]
    assert len(indexes) == 1, 'ordinary package job must be unique'
    i = indexes[0]
    return jobs[hits[i].end():hits[i + 1].start() if i + 1 < len(hits) else len(jobs)]


def _steps(job):
    starts = list(re.finditer(r'^      - (?:name|uses):.*$', job, re.M))
    rows = []
    for i, match in enumerate(starts):
        block = job[match.start():starts[i + 1].start() if i + 1 < len(starts) else len(job)]
        name = re.match(r'      - name: (.+)', block)
        rows.append((name.group(1) if name else None, block))
    return rows


# TEST-006 adds exactly this continuation under a step name so an earlier
# failed check never hides the step; every other condition is still refused.
CONTINUATION = '        if: ${{ !cancelled() }}\n'


def _without_continuation(step):
    head, newline, rest = step.partition('\n')
    return head + newline + rest[len(CONTINUATION):] if rest.startswith(CONTINUATION) else step


def enrolled_cleanup_ids(workflow_raw, test_raw):
    text = _workflow_text(workflow_raw)
    assert re.search(r'^  push:\n    branches:\n      - dev$', text, re.M), 'dev push coverage required'
    job = _job(text, 'package-linux-desktop')
    header, separator, _ = job.partition('    steps:\n')
    expected_header = ("    name: Build DEB and RPM\n"
                       "    if: github.event_name != 'workflow_dispatch' || inputs.fixture_base_version == ''\n"
                       "    runs-on: ubuntu-latest\n"
                       "    timeout-minutes: 45")
    assert separator and header.strip('\n') == expected_header, 'ordinary dev job header, Linux capability and failure policy must be exact'
    rows = [(name, _without_continuation(block)) for name, block in _steps(job)]
    target = [(i, b) for i, (n, b) in enumerate(rows) if n == 'Verify native JDK launcher before packaging']
    assert len(target) == 1, 'native-JDK step must be unique'
    i, step = target[0]
    assert not re.search(r'^        (?:if|continue-on-error):', step, re.M), 'native cleanup must not be conditional or ignored'
    java = [(j, b) for j, (n, b) in enumerate(rows) if n == 'Set up JDK 17']
    assert len(java) == 1 and java[0][0] < i, 'Temurin setup must precede native cleanup'
    expected_java = ('      - name: Set up JDK 17\n'
                     '        uses: actions/setup-java@v4\n'
                     '        with:\n'
                     '          distribution: temurin\n'
                     '          java-version: "17"')
    assert java[0][1].rstrip() == expected_java, 'real unconditional Temurin17 setup required'
    packaging = [j for j, (n, _) in enumerate(rows) if n == 'Build Linux packages']
    assert len(packaging) == 1 and i < packaging[0], 'cleanup controls must run before packaging'
    prefix = '      - name: Verify native JDK launcher before packaging\n        run: |\n'
    assert step.startswith(prefix), 'missing explicit native cleanup enrollment'
    body = step[len(prefix):].rstrip('\n')
    lines = body.splitlines()
    assert lines and all(line.startswith('          ') and line.strip() for line in lines), 'strict native-JDK step fields and default fail-fast shell required'
    commands = [line.strip() for line in lines]
    expected = [
        ['python3', 'scripts/test_jpackage_launcher.py', '--jdk', '$JAVA_HOME'],
        ['python3', '-m', 'unittest', '-v', TARGET],
    ]
    assert [shlex.split(line, comments=False) for line in commands] == expected, 'preserve launcher and exact verbose cleanup enrollment'
    tree = ast.parse(test_raw, filename=str(TEMURIN))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'CleanupOwnershipTests']
    assert len(classes) == 1, 'actual cleanup class must be unique'
    case = classes[0]
    actual = {node.name for node in case.body if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}
    assert actual == METHODS, 'actual four native cleanup methods changed'
    decorators = [ast.dump(node, include_attributes=False) for node in case.decorator_list]
    guard = ast.parse("unittest.skipUnless(os.name=='posix','POSIX real FD closure required')", mode='eval').body
    assert ast.dump(guard, include_attributes=False) in decorators, 'original POSIX capability guard required'
    return frozenset(TARGET + '.' + method for method in actual)


def preserved_before():
    raw = _read(FIXTURE / 'linux-desktop.before.yml')
    provenance = json.loads(_read(FIXTURE / 'provenance.json'))
    assert hashlib.sha256(raw).hexdigest() == BEFORE_SHA == provenance['workflowSha256'], 'frozen F workflow authority'
    assert provenance['headSha'] == '3a7f6d3414f25c232f2512112ed527c819a7bb21', 'frozen exact F source'
    return raw


class LinuxNativeCleanupEnrollmentTests(unittest.TestCase):
    def test_actual_workflow_enrolls_all_four_native_cleanup_cases(self):
        raw = preserved_before() if BEFORE_RED else _read(WORKFLOW)
        variants = (('frozen-before', raw),) if BEFORE_RED else (
            ('LF', _workflow_text(raw).encode('utf-8')),
            ('CRLF', _workflow_text(raw).replace('\n', '\r\n').encode('utf-8')),
        )
        for label, variant in variants:
            with self.subTest(line_endings=label):
                self.assertEqual(enrolled_cleanup_ids(variant, _read(TEMURIN)), frozenset(TARGET + '.' + m for m in METHODS))

    def test_preserved_F_same_positive_has_one_enrollment_failure(self):
        case = unittest.FunctionTestCase(lambda: enrolled_cleanup_ids(preserved_before(), _read(TEMURIN)))
        result = unittest.TestResult()
        unittest.TestSuite([case]).run(result)
        self.assertEqual((result.testsRun, len(result.failures), len(result.errors), len(result.skipped)), (1, 1, 0, 0))
        self.assertIn('missing explicit native cleanup enrollment', result.failures[0][1])

    def test_conditional_and_ignored_native_steps_refuse(self):
        raw = _workflow_text(_read(WORKFLOW))
        marker = '      - name: Verify native JDK launcher before packaging\n'
        hostile = [raw.replace(marker, marker + extra) for extra in (
            '        if: false\n', '        continue-on-error: true\n',
            '        shell: bash {0}\n', '        run: echo fake\n')]
        hostile.extend((
            raw.replace("inputs.fixture_base_version == ''\n    runs-on:", "inputs.fixture_base_version == '' && false\n    runs-on:"),
            raw.replace('    timeout-minutes: 45\n', '    timeout-minutes: 45\n    continue-on-error: true\n'),
            raw.replace('      - name: Set up JDK 17\n', '      - name: Set up JDK 17\n        if: false\n'),
            raw.replace('jobs:\n', 'defaults:\n  run:\n    shell: bash {0}\njobs:\n'),
            raw.replace('jobs:\n', 'unrelated:\n'),
        ))
        for index, changed in enumerate(hostile):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                enrolled_cleanup_ids(changed.encode(), _read(TEMURIN))

    def test_dispatch_only_job_cannot_supply_ordinary_enrollment(self):
        raw = _workflow_text(_read(WORKFLOW)).encode('utf-8').replace(b'  package-linux-desktop:', b'  dispatch-only-fixture:')
        with self.assertRaisesRegex(AssertionError, 'ordinary package job'):
            enrolled_cleanup_ids(raw, _read(TEMURIN))

    def test_original_launcher_and_exact_unittest_command_are_required(self):
        raw = _workflow_text(_read(WORKFLOW))
        with self.assertRaisesRegex(AssertionError, 'lone CR'):
            enrolled_cleanup_ids(raw.replace('jobs:\n', 'jobs:\r', 1).encode('utf-8'), _read(TEMURIN))
        for old, new in (('python3 scripts/test_jpackage_launcher.py', '# python3 scripts/test_jpackage_launcher.py'), ('python3 -m unittest -v ' + TARGET, 'python3 -m unittest -v ' + TARGET + ' ' + TARGET)):
            with self.subTest(old=old), self.assertRaisesRegex(AssertionError, 'preserve launcher'):
                enrolled_cleanup_ids(raw.replace(old, new).encode(), _read(TEMURIN))

    def test_duplicate_native_step_and_incomplete_case_set_refuse(self):
        raw = _workflow_text(_read(WORKFLOW)).encode('utf-8')
        marker = b'      - name: Verify native JDK launcher before packaging\n'
        with self.assertRaisesRegex(AssertionError, 'native-JDK step must be unique'):
            enrolled_cleanup_ids(raw.replace(marker, marker + marker), _read(TEMURIN))
        changed = _read(TEMURIN).replace(b'def test_shared_coordinator_mutation_keeps_owned_155_record_retainer', b'def helper_without_native_case')
        with self.assertRaisesRegex(AssertionError, 'four native cleanup methods'):
            enrolled_cleanup_ids(raw, changed)


    def test_actual_ordinary_linux_job_runs_all_enrollment_guards(self):
        raw = _workflow_text(_read(WORKFLOW))
        temurin = _read(TEMURIN)
        for variant in (raw.encode('utf-8'), raw.replace('\n', '\r\n').encode('utf-8')):
            enrolled_cleanup_ids(variant, temurin)
            rows = [(name, _without_continuation(block))
                    for name, block in _steps(_job(_workflow_text(variant), 'package-linux-desktop'))]
            guards = [(i, block) for i, (name, block) in enumerate(rows)
                      if name == 'Verify Linux cleanup enrollment guards']
            self.assertEqual(len(guards), 1, 'ordinary Linux cleanup enrollment step must be unique')
            index, block = guards[0]
            self.assertEqual(block.rstrip(),
                             '      - name: Verify Linux cleanup enrollment guards\n'
                             '        run: python3 -m unittest -v agent_tools.tests.test_linux_native_cleanup_enrollment')
            names = [name for name, _ in rows]
            self.assertLess(names.index('Verify native JDK launcher before packaging'), index)
            self.assertLess(index, names.index('Build Linux packages'))

if __name__ == '__main__':
    unittest.main(defaultTest='LinuxNativeCleanupEnrollmentTests.test_actual_workflow_enrolls_all_four_native_cleanup_cases' if BEFORE_RED else None)
