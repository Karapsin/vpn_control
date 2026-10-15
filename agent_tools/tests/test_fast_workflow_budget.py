"""Real scaled deadlines for the complete CI job around its managed tool phase.

The producer is a saved local program and does no CI, SSH or native work. Five
prelude, 42 tool and one tail model-minutes are a synthetic allowed schedule,
not a measurement or promise about the actual Gradle tail. The actual workflow
limits and unchanged managed command limit determine the real deadlines.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
CURRENT = ROOT / '.github/workflows/fast-checks.yml'
FIXTURES = Path(__file__).with_name('fixtures') / 'fast_workflow_budget'
BEFORE = FIXTURES / 'before.yml'
MANAGED_SOURCE = ROOT / 'agent_tools/mcp_server.py'
SCALE_SECONDS_PER_MINUTE = 0.08
MAX_OUTPUT_BYTES = 65536

PRODUCER = r'''import json,sys,time
from pathlib import Path
root=Path(sys.argv[1]);scale=float(sys.argv[2]);phase_limit=float(sys.argv[3]);work=float(sys.argv[4])
def mark(name):
    (root/(name+'.json')).write_text(json.dumps({'event':name,'monotonic':time.monotonic()}))
sys.stdout.buffer.write(b'READY\n');sys.stdout.buffer.flush()
if sys.stdin.readline()!='GO\n':raise SystemExit(11)
mark('prelude_started');time.sleep(5*scale)
mark('tool_started');started=time.monotonic()
while True:
    elapsed=time.monotonic()-started
    if elapsed>=phase_limit*scale:
        mark('phase_timeout');print('PHASE_TIMEOUT',flush=True);raise SystemExit(23)
    if elapsed>=work*scale:break
    time.sleep(min(0.01,(work*scale)-elapsed,(phase_limit*scale)-elapsed))
mark('tool_completed');mark('tail_started');time.sleep(scale)
mark('tail_completed');print('COMPLETE',flush=True)
'''


def _integer(expression):
    if isinstance(expression, ast.Constant) and type(expression.value) is int:
        return expression.value
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Mult):
        return _integer(expression.left) * _integer(expression.right)
    raise ValueError('Managed deadline must remain an explicit integer product')


def managed_minutes():
    tree = ast.parse(MANAGED_SOURCE.read_bytes())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == '_run_check_commands']
    if len(functions) != 1:
        raise ValueError('Managed check owner is unavailable')
    budgets = [_integer(keyword.value) for node in ast.walk(functions[0])
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id == '_run' for keyword in node.keywords
               if keyword.arg == 'timeout']
    if budgets != [50 * 60]:
        raise ValueError('Existing 50-minute managed command bound changed')
    return budgets[0] // 60


def workflow_limits(source):
    source = Path(source)
    if source not in (CURRENT, BEFORE):
        raise ValueError('Unknown workflow source')
    raw = source.read_bytes()
    if source == BEFORE:
        provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
        if (len(raw) != provenance['sourceBytes']
                or hashlib.sha256(raw).hexdigest() != provenance['sourceSha256']):
            raise ValueError('Preserved actual workflow changed')
    lines = raw.decode().splitlines()
    starts = [index for index, line in enumerate(lines) if line == '  fast-checks:']
    if len(starts) != 1:
        raise ValueError('Expected one fixed Fast Checks job')
    body = []
    for line in lines[starts[0] + 1:]:
        if line.strip() and not line.startswith('    '):
            break
        body.append(line)
    job = [int(match[1]) for line in body
           if (match := re.fullmatch(r'    timeout-minutes: ([1-9][0-9]*)', line))]
    step_starts = [index for index, line in enumerate(body)
                   if line == '      - name: Test affected agent tools']
    if len(job) != 1 or not 1 <= job[0] <= 360 or len(step_starts) != 1:
        raise ValueError('Unknown workflow deadline structure')
    step = []
    tail = []
    retention_steps = 0
    for line in body[step_starts[0] + 1:]:
        if line.startswith('      - '):
            break
        step.append(line)
    for tail_index in range(step_starts[0] + 1, len(body)):
        line = body[tail_index]
        if line.startswith('      - name: '):
            name = line.removeprefix('      - name: ')
            if name == 'Retain public agent shard evidence':
                retention_steps += 1
                if retention_steps != 1:
                    raise ValueError('Duplicate public retention step')
                end = next((index for index in range(tail_index + 1, len(body))
                            if body[index].startswith('      - ')), len(body))
                actual = [item for item in body[tail_index:end] if item.strip()]
                expected = '''      - name: Retain public agent shard evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agent-test-shard-${{ github.run_id }}-${{ github.run_attempt }}-0
          path: |
            .rag_index/agent-ci-evidence-0/plan.json
            .rag_index/agent-ci-evidence-0/events.jsonl
            .rag_index/agent-ci-evidence-0/summary.json
          if-no-files-found: error
          include-hidden-files: true
          retention-days: 7'''.splitlines()
                if actual != expected:
                    raise ValueError('Unexpected public retention step')
                continue
            tail.append(name)
    if retention_steps != (1 if source == CURRENT else 0):
        raise ValueError('Required public retention step unavailable')
    limits = [int(match[1]) for line in step
              if (match := re.fullmatch(r'        timeout-minutes: ([1-9][0-9]*)', line))]
    if (len(limits) > 1 or limits and not 1 <= limits[0] <= 360
            or not any('affected_agent_tests.py --run' in line for line in step)):
        raise ValueError('Original affected-selection command unavailable')
    managed = managed_minutes()
    return {'jobMinutes': job[0], 'phaseMinutes': limits[0] if limits else managed,
            'explicitPhaseLimit': bool(limits), 'managedMinutes': managed,
            'tailSteps': tail, 'workflowSha256': hashlib.sha256(raw).hexdigest()}


def run_schedule(policy, *, work_minutes=42):
    """One new owned child: READY precedes its real monotonic job deadline."""
    with tempfile.TemporaryDirectory(prefix='workflow-budget-') as temporary:
        root = Path(temporary).resolve()
        program = root / 'producer.py'
        program.write_bytes(PRODUCER.encode())
        argv = [sys.executable, '-I', '-B', str(program), str(root),
                str(SCALE_SECONDS_PER_MINUTE), str(policy['phaseMinutes']), str(work_minutes)]
        if sum(len(word.encode()) + 1 for word in argv) > 60000:
            raise ValueError('Saved producer command exceeds command bound')
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        events = queue.Queue(maxsize=128)
        overflow = threading.Event()
        streams = {'stdout': bytearray(), 'stderr': bytearray()}

        def drain(stream, name):
            try:
                while chunk := stream.readline(1024):
                    if len(streams[name]) + len(chunk) > MAX_OUTPUT_BYTES:
                        overflow.set()
                        return
                    streams[name].extend(chunk)
                    try:
                        events.put_nowait((name, chunk))
                    except queue.Full:
                        overflow.set()
                        return
            finally:
                try:
                    events.put_nowait((name, None))
                except queue.Full:
                    overflow.set()

        threads = [threading.Thread(target=drain, args=(stream, name), daemon=True)
                   for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr'))]
        for thread in threads:
            thread.start()
        reason = 'readiness_timeout'
        ready = False
        started = None
        deadline = None
        completion_observed = None
        try:
            readiness_deadline = time.monotonic() + 10
            while time.monotonic() < readiness_deadline:
                if overflow.is_set():
                    reason = 'output_bound'
                    break
                try:
                    name, value = events.get(timeout=min(0.05, max(0, readiness_deadline-time.monotonic())))
                except queue.Empty:
                    if process.poll() is not None:
                        reason = 'readiness_exit'
                        break
                    continue
                if name == 'stdout' and value is not None and value.rstrip(b'\r\n') == b'READY':
                    ready = True
                    break
            if ready:
                started = time.monotonic()
                deadline = started + policy['jobMinutes'] * SCALE_SECONDS_PER_MINUTE
                process.stdin.write(b'GO\n')
                process.stdin.flush()
                process.stdin.close()
                while process.poll() is None:
                    remaining = deadline-time.monotonic()
                    if overflow.is_set():
                        reason = 'output_bound'
                        break
                    if remaining <= 0:
                        reason = 'outer_timeout'
                        break
                    try:
                        process.wait(timeout=min(0.05, remaining))
                    except subprocess.TimeoutExpired:
                        pass
                else:
                    completion_observed = time.monotonic()
                    reason = 'complete' if process.returncode == 0 else 'phase_timeout' if process.returncode == 23 else 'child_exit'
                    if reason == 'complete' and completion_observed > deadline:
                        reason = 'late_completion'
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            for thread in threads:
                thread.join(timeout=10)
            readers_closed = not any(thread.is_alive() for thread in threads)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        markers = {path.name: json.loads(path.read_bytes()) for path in root.glob('*.json')}
        completed_at = markers.get('tail_completed.json', {}).get('monotonic')
        if reason == 'complete' and (type(completed_at) not in (int, float) or completed_at > deadline):
            reason = 'late_completion'
        result = {'reason': reason, 'ready': ready, 'pid': process.pid,
                  'returncode': process.returncode, 'reaped': process.poll() is not None,
                  'readersClosed': readers_closed, 'attempts': 1, 'replayAllowed': False,
                  'jobMinutes': policy['jobMinutes'], 'phaseMinutes': policy['phaseMinutes'],
                  'scaleSecondsPerMinute': SCALE_SECONDS_PER_MINUTE,
                  'workModelMinutes': {'prelude': 5, 'tool': work_minutes, 'tail': 1},
                  'jobDeadlineStarted': started, 'jobDeadline': deadline,
                  'completionObserved': completion_observed,
                  'programSha256': hashlib.sha256(program.read_bytes()).hexdigest(),
                  'markers': markers,
                  'stdout': streams['stdout'].decode(errors='replace'),
                  'stderr': streams['stderr'].decode(errors='replace'),
                  'stdoutHex': bytes(streams['stdout']).hex(),
                  'stderrHex': bytes(streams['stderr']).hex()}
        print('WORKFLOW_BUDGET_TRACE ' + json.dumps(result, sort_keys=True), flush=True)
        evidence = os.environ.get('WORKFLOW_BUDGET_EVIDENCE_DIR')
        if evidence:
            folder = Path(evidence) / str(process.pid)
            folder.mkdir(parents=True, exist_ok=False)
            def retain(name, raw):
                with (folder / name).open('xb') as output:
                    output.write(raw)
            retain('producer.py', program.read_bytes())
            retain('stdout.bin', bytes(streams['stdout']))
            retain('stderr.bin', bytes(streams['stderr']))
            for name, marker in markers.items():
                retain(name, (json.dumps(marker)+'\n').encode())
            retain('trace.json', (json.dumps(result, indent=2)+'\n').encode())
        return result


class FastWorkflowBudgetTests(unittest.TestCase):
    workflow_source = CURRENT

    def assert_allowed_schedule_finishes(self, source):
        result = run_schedule(workflow_limits(source))
        self.assertTrue(result['ready'] and result['reaped'] and result['readersClosed'], result)
        self.assertEqual('complete', result['reason'], result)
        self.assertEqual(0, result['returncode'], result)
        self.assertIn('tool_completed.json', result['markers'])
        self.assertIn('tail_completed.json', result['markers'])
        return result

    def test_actual_workflow_allows_managed_phase_and_following_checks(self):
        self.assert_allowed_schedule_finishes(self.workflow_source)

    def test_preserved_actual_job_deadline_cancels_without_tail_or_success(self):
        result = run_schedule(workflow_limits(BEFORE))
        self.assertTrue(result['ready'] and result['reaped'] and result['readersClosed'], result)
        self.assertEqual('outer_timeout', result['reason'], result)
        self.assertNotIn('tool_completed.json', result['markers'])
        self.assertNotIn('tail_completed.json', result['markers'])
        self.assertNotIn('COMPLETE', result['stdout'])
        self.assertEqual(1, result['attempts'])
        self.assertIs(False, result['replayAllowed'])

    def test_larger_outer_job_never_extends_managed_phase_limit(self):
        policy = workflow_limits(CURRENT)
        self.assertTrue(policy['explicitPhaseLimit'])
        self.assertEqual(policy['managedMinutes'], policy['phaseMinutes'])
        result = run_schedule(policy, work_minutes=policy['managedMinutes']+1)
        self.assertEqual('phase_timeout', result['reason'], result)
        self.assertEqual(23, result['returncode'], result)
        self.assertIn('phase_timeout.json', result['markers'])
        self.assertNotIn('tool_completed.json', result['markers'])
        self.assertNotIn('tail_completed.json', result['markers'])
        self.assertTrue(result['reaped'] and result['readersClosed'], result)

    def test_existing_build_and_validation_tail_stays_after_agent_phase(self):
        current = workflow_limits(CURRENT)
        before = workflow_limits(BEFORE)
        self.assertEqual(before['tailSteps'], current['tailSteps'])
        self.assertIn('Run fast unit tests', current['tailSteps'])
        self.assertIn('Verify Android instrumentation signature guard', current['tailSteps'])

    def test_preserved_tail_reader_reproduces_the_same_assertion_then_current_passes(self):
        folder = Path(__file__).with_name('fixtures') / 'agent_ci_shards'
        metadata = json.loads((folder / 'provenance.json').read_bytes())
        row = next(item for item in metadata['files'] if item['path'] == 'budget.before.source')
        raw = (folder / 'budget.before.source').read_bytes()
        self.assertEqual(row['sourceBytes'], len(raw))
        self.assertEqual(row['sourceSha256'], hashlib.sha256(raw).hexdigest())
        functions = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef)
                     and node.name == 'workflow_limits']
        self.assertEqual(1, len(functions))
        namespace = dict(globals())
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(folder / 'budget.before.source'), 'exec'), namespace)
        case = type(self)('test_existing_build_and_validation_tail_stays_after_agent_phase')
        legacy = unittest.TestResult()
        with mock.patch.dict(globals(), {'workflow_limits': namespace['workflow_limits']}):
            case.run(legacy)
        self.assertEqual(1, legacy.testsRun)
        self.assertEqual(1, len(legacy.failures))
        self.assertEqual([], legacy.errors)
        self.assertIn('Retain public agent shard evidence', legacy.failures[0][1])
        current = unittest.TestResult()
        type(self)('test_existing_build_and_validation_tail_stays_after_agent_phase').run(current)
        self.assertEqual(1, current.testsRun)
        self.assertTrue(current.wasSuccessful(), current.failures + current.errors)
        print(json.dumps({'event': 'budget-retention-causal', 'beforeSourceSha256': row['sourceSha256'],
                          'samePositive': 'test_existing_build_and_validation_tail_stays_after_agent_phase',
                          'beforeFailures': len(legacy.failures), 'currentFailures': len(current.failures)}, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
