"""Darwin zombie-only process groups: no runner or original-runner observation crashes on EPERM.

XNU killpg skips zombie members, so for a group that still exists but holds only
unreaped zombies it returns EPERM, not ESRCH. close_session and _stop_workers
caught only ProcessLookupError, and the session observer tests passed the
original runner's refusal straight into their assertions and cleanup. An owned
holder that leaves the group (same session) and never reaps its member keeps
exactly that state until this test releases it, so every observation here is
deterministic. Local owned processes only; no VM, SSH or host tool.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import agent_test_runner as runner
from agent_tools.tests import test_agent_test_session_observer as observer_tests

FIXTURE = Path(__file__).parent / 'fixtures/agent_test_runner_zombie_group'
PROVENANCE = FIXTURE / 'provenance.json'
RUNNER_BEFORE = FIXTURE / 'agent_test_runner.py.before.source'
TESTS_BEFORE = FIXTURE / 'test_agent_test_session_observer.py.before.source'
# The complete original runner that the observer tests execute in process and as a CLI.
ORIGINAL_RUNNER = Path(__file__).parent / 'fixtures/agent_test_session_observer/before.source'
REFUSED = 'Agent unittest runner refused: PermissionError\n'
DARWIN_ONLY = 'XNU killpg reports EPERM for a group of only unreaped zombies; Linux still signals zombie members'

# Holder N: forks member M, which stays in the caller's process group, then leaves that group for
# its own (same session), reports M and never reaps it until the release file exists (30 s backstop).
HOLDER = r'''
import os,sys,time
release,mode=sys.argv[1],sys.argv[2]
member=os.fork()
if member==0:
    os.close(1)
    if mode=='live':time.sleep(30)
    os._exit(0)
os.setpgid(0,0)
os.write(1,b'%d\n'%member);os.close(1)
end=time.monotonic()+30
while time.monotonic()<end and not os.path.exists(release):time.sleep(0.005)
os._exit(0)
'''
# New-session leader L: starts the holder inside its group, reports once the holder has left it,
# then exits ('exit') or waits for stdin EOF ('wait', or 'ignore-term' with SIGTERM ignored).
LEADER = r'''
import signal,subprocess,sys
holder=subprocess.Popen([sys.executable,'-I','-c',sys.argv[1],sys.argv[2],sys.argv[3]],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
member=holder.stdout.readline();holder.stdout.close()
if sys.argv[4]=='ignore-term':signal.signal(signal.SIGTERM,signal.SIG_IGN)
sys.stdout.buffer.write(member);sys.stdout.flush()
if sys.argv[4]!='exit':sys.stdin.buffer.read()
'''
# A selected test whose worker group keeps one held member after the worker exits.
HELD_TEST = ("import subprocess,sys,unittest\nclass C(unittest.TestCase):\n def test_one(self):\n"
             "  holder=subprocess.Popen([sys.executable,'-I','-c',%r,%r,'live'],stdin=subprocess.DEVNULL,"
             "stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)\n"
             "  self.assertTrue(holder.stdout.readline().strip().isdigit());holder.stdout.close()\n")
# Observer-test injection: the first orphan session and the first original CLI worker also hold a member.
ORPHAN_CODE = "import json,subprocess,sys;child=subprocess.Popen("
ORPHAN_PRELUDE = ("import subprocess as _s,sys as _y\n"
                  "_h=_s.Popen([_y.executable,'-I','-c',%r,%r,'live'],stdin=_s.DEVNULL,stdout=_s.PIPE,stderr=_s.DEVNULL)\n"
                  "_h.stdout.readline();_h.stdout.close()\n")
CLI_HELD = ("  holder=subprocess.Popen([sys.executable,'-I','-c',%r,%r,'live'],stdin=subprocess.DEVNULL,"
            "stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)\n  holder.stdout.readline();holder.stdout.close()\n")
CLI_CHILD = (b"  child=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)'],"
             b"stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n")
# Later original CLI observations without the zombie window: on SIGTERM the child leaves the worker
# group before it exits, so that group goes from one live member straight to ESRCH.
LEAVER = ("import os,signal,time\nsignal.signal(signal.SIGTERM,lambda *_:(os.setpgid(0,0),os._exit(0)))\n"
          "os.write(1,b'ready\\n');os.close(1)\ntime.sleep(60)\n")
CLI_LEAVER = ("  child=subprocess.Popen([sys.executable,'-I','-c',%r],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,"
              "stderr=subprocess.DEVNULL);child.stdout.readline();child.stdout.close()\n" % LEAVER).encode()


def vanish(pgid, probe, seconds=10.0):
    """Probe (signal 0) an owned group until the kernel reports it gone; EPERM still means present."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            probe(pgid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            pass
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.002)


def zombie_only(pgid, probe, seconds=10.0):
    """Probe until the kernel reports EPERM: the owned group exists with only unreaped zombies."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            probe(pgid, 0)
        except PermissionError:
            return True
        except ProcessLookupError:
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.002)


def beforeimage(test, path, source):
    provenance = json.loads(PROVENANCE.read_bytes())
    raw, entry = path.read_bytes(), provenance['files'][path.name]
    test.assertEqual((entry['sha256'], entry['bytes'], entry['path'], False),
                     (hashlib.sha256(raw).hexdigest(), len(raw), source, provenance['nativeFailureClaimed']))
    return raw, provenance


@unittest.skipUnless(sys.platform == 'darwin', DARWIN_ONLY)
class RunnerZombieGroupTests(unittest.TestCase):
    def runner_before(self):
        raw, _ = beforeimage(self, RUNNER_BEFORE, 'agent_tools/agent_test_runner.py')
        module = types.ModuleType('_agent_test_runner_zombie_group_before_' + uuid4().hex)
        module.__file__ = str(RUNNER_BEFORE.absolute())
        exec(compile(raw, module.__file__, 'exec', dont_inherit=True), module.__dict__)
        return module

    def held(self, mode, leader='exit'):
        """Owned new-session leader L whose group keeps member M; holder N (own group) never reaps M."""
        workspace = tempfile.TemporaryDirectory(prefix='vct-zombie-group-')
        self.addCleanup(workspace.cleanup)
        release = Path(workspace.name) / 'release'
        process = subprocess.Popen([sys.executable, '-I', '-c', LEADER, HOLDER, str(release), mode, leader],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        self.addCleanup(self.drain, process, release)
        member = process.stdout.readline()
        process.stdout.close()
        self.assertTrue(member.strip().isdigit(), 'holder did not report its member')
        if leader == 'exit':
            process.stdin.close()
            self.assertEqual(0, process.wait(timeout=10))
        return process, release

    def drain(self, process, release):
        release.touch()
        if not process.stdin.closed:
            process.stdin.close()
        process.wait(timeout=10)
        if not vanish(process.pid, os.killpg, 2):
            # Only a failed case leaves a live member in this owned group; stop it.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        self.assertTrue(vanish(process.pid, os.killpg), 'owned held group did not vanish')

    def recorder(self, pgid, release, after):
        """Pass-through killpg for one owned group; releases the holder at the 2nd EPERM probe after `after`."""
        calls, actual = [], os.killpg
        def killpg(target, signum):
            if target != pgid:
                return actual(target, signum)
            try:
                actual(target, signum)
            except OSError as error:
                calls.append((signum, errno.errorcode[error.errno]))
                raise
            else:
                calls.append((signum, 'ok'))
            finally:
                sent = [value for value, _ in calls]
                if after in sent and calls[sent.index(after) + 1:].count((0, 'EPERM')) == 2:
                    release.touch()
        return calls, mock.patch.object(os, 'killpg', killpg)

    def refusal(self, call, *args):
        """The unfixed runner's PermissionError: errno and its own raising frames (assertRaises drops them)."""
        try:
            call(*args)
        except PermissionError as error:
            return error.errno, [(frame.lineno, frame.name) for frame in traceback.extract_tb(error.__traceback__)
                                 if frame.filename == str(RUNNER_BEFORE.absolute())]
        self.fail('the unfixed runner did not refuse')

    def test_zombie_only_group_unfixed_close_session_refuses_current_waits_for_esrch(self):
        before = self.runner_before()
        # (case, member at entry, release at the 2nd EPERM probe after this signal, unfixed raising line)
        for name, mode, after, line in (('member killed by close_session', 'live', signal.SIGTERM, 526),
                                        ('zombie-only at entry', 'zombie', signal.SIGTERM, 514),
                                        ('zombie-only through SIGKILL', 'zombie', signal.SIGKILL, 514)):
            with self.subTest(name):
                process, release = self.held(mode)
                if mode == 'live':
                    os.killpg(process.pid, 0)  # Its member is alive.
                else:
                    self.assertTrue(zombie_only(process.pid, os.killpg), 'kernel did not report EPERM')
                calls, patch = self.recorder(process.pid, release, after)
                with patch:
                    self.assertEqual((errno.EPERM, [(line, 'close_session')]), self.refusal(before.close_session, process))
                self.assertEqual((0, 'EPERM'), calls[-1])
                self.assertEqual(mode == 'zombie', calls == [(0, 'EPERM')])

                process, release = self.held(mode)
                if mode == 'zombie':
                    self.assertTrue(zombie_only(process.pid, os.killpg), 'kernel did not report EPERM')
                calls, patch = self.recorder(process.pid, release, after)
                with patch:
                    terminal = runner.close_session(process)
                # Absent only on the kernel's ESRCH, never on EPERM; the group really is gone.
                with self.assertRaises(ProcessLookupError):
                    os.killpg(process.pid, 0)
                self.assertEqual((True, True), terminal)
                self.assertEqual((0, 'ESRCH'), calls[-1])
                self.assertNotIn('ESRCH', [outcome for _, outcome in calls[:-1]])
                self.assertEqual([(0, 'ok' if mode == 'live' else 'EPERM'), (signal.SIGTERM, 'ok' if mode == 'live' else 'EPERM')], calls[:2])
                self.assertEqual(after == signal.SIGKILL, (signal.SIGKILL, 'EPERM') in calls)
                sent = [value for value, _ in calls]
                self.assertGreaterEqual(calls[sent.index(after) + 1:].count((0, 'EPERM')), 2)
                if after == signal.SIGKILL:  # Zombie-only through the whole SIGTERM bound.
                    self.assertEqual({(0, 'EPERM')}, set(calls[2:sent.index(signal.SIGKILL)]))

    def test_stop_workers_unfixed_refuses_current_reaps_worker_that_exits_before_its_signal(self):
        before = self.runner_before()
        for name, leader, line in (('exits after its poll, before SIGTERM', 'wait', 495),
                                   ('ignores SIGTERM, exits after the grace, before SIGKILL', 'ignore-term', 505)):
            for implementation in (before, runner):
                with self.subTest(name, unfixed=implementation is before):
                    process, release = self.held('zombie', leader)
                    actual_poll, actual_wait, exited = process.poll, process.wait, []
                    def leave():
                        # The worker exits now and stays unreaped: its group holds only zombies.
                        process.stdin.close()
                        self.assertTrue(zombie_only(process.pid, os.killpg), 'kernel did not report EPERM')
                        exited.append(True)
                    def poll():
                        value = actual_poll()
                        if leader == 'wait' and not exited:
                            self.assertIsNone(value)  # Observed live, then it exits before its SIGTERM.
                            leave()
                        return value
                    def wait(timeout=None):
                        if leader == 'ignore-term' and timeout is not None and not exited:
                            try:
                                return actual_wait(0.05)  # It ignores SIGTERM: a real expiry of a shortened grace.
                            except subprocess.TimeoutExpired:
                                leave()
                                raise
                        return actual_wait(timeout)
                    with mock.patch.object(process, 'poll', poll), mock.patch.object(process, 'wait', wait):
                        if implementation is before:
                            self.assertEqual((errno.EPERM, [(line, '_stop_workers')]),
                                             self.refusal(before._stop_workers, [{'process': process}]))
                            self.assertIsNone(process.returncode)  # The refusal never reaps its worker.
                        else:
                            runner._stop_workers([{'process': process}])
                            self.assertEqual(0, process.returncode)
                    self.assertEqual([True], exited)

    def test_runner_cli_unfixed_refuses_current_writes_incomplete_report(self):
        for source, unfixed in ((RUNNER_BEFORE, True), (Path(runner.__file__), False)):
            if unfixed:
                beforeimage(self, RUNNER_BEFORE, 'agent_tools/agent_test_runner.py')
            with self.subTest(unfixed=unfixed), tempfile.TemporaryDirectory(prefix='vct-zombie-cli-') as raw:
                root = Path(raw).resolve()
                root.chmod(0o700)
                release = root / 'release'
                package = root / 'agent_tools/tests'
                package.mkdir(parents=True)
                (package.parent / '__init__.py').write_text('')
                (package / '__init__.py').write_text('')
                (package / 'test_held_member.py').write_text(HELD_TEST % (HOLDER, str(release)))
                plan = root / 'input.json'
                plan.write_text(json.dumps({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64,
                                            'modules': ['agent_tools.tests.test_held_member'], 'maxWorkers': 1}))
                report_dir = root / 'report'
                try:
                    child = subprocess.run([sys.executable, '-B', str(source.absolute()), '--plan-file', str(plan),
                                            '--report-dir', str(report_dir)], cwd=root, stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
                finally:
                    release.touch()
                worker = json.loads((report_dir / 'worker-0000/started.json').read_bytes())['pid']
                self.assertTrue(vanish(worker, os.killpg), 'released worker group did not vanish')
                # Neither removes the worker fixture root: the refusal stops first, the fix keeps it for a present group.
                fixture = json.loads((report_dir / 'worker-0000/fixture-root.json').read_bytes())
                self.assertTrue(runner.cleanup_fixture_root(Path(fixture['path']), fixture['generation']))
                if unfixed:
                    self.assertEqual((2, REFUSED, ''), (child.returncode, child.stderr, child.stdout))
                    self.assertFalse((report_dir / 'report.json').exists())
                    continue
                self.assertEqual(1, child.returncode, child.stderr)
                report = json.loads((report_dir / 'report.json').read_bytes())
                record, = report['workers']
                self.assertEqual(('incomplete', False, None), (report['state'], report['successful'], report['infrastructureError']))
                self.assertEqual((1, 0, 0), (report['counts']['testsRun'], report['counts']['failures'], report['counts']['errors']))
                self.assertEqual(('complete', 0, True), (record['state'], record['returncode'], record['reaped']))
                self.assertEqual((False, True, False), (record['sessionAbsent'], record['descendantLeak'], record['fixtureRootRemoved']))


@unittest.skipUnless(sys.platform == 'darwin', DARWIN_ONLY)
class ObserverOriginalRetryTests(unittest.TestCase):
    """Old and new observer cases with a held member in their first orphan session and first original CLI run."""

    def observer_tests_before(self):
        raw, provenance = beforeimage(self, TESTS_BEFORE, 'agent_tools/tests/test_agent_test_session_observer.py')
        for failure in provenance['originalFailures']:
            self.assertEqual(failure['traceSha256'], hashlib.sha256(('\n'.join(failure['trace']) + '\n').encode()).hexdigest())
        module = types.ModuleType('_session_observer_tests_before_' + uuid4().hex)
        module.__file__ = observer_tests.__file__
        exec(compile(raw, str(TESTS_BEFORE), 'exec', dont_inherit=True), module.__dict__)
        return module

    def run_case(self, module, name):
        temporary = tempfile.TemporaryDirectory(prefix='vct-observer-retry-')
        self.addCleanup(temporary.cleanup)
        workspace = Path(temporary.name)
        release = workspace / 'orphan-release'
        launches, refusals, runs = [], [], []
        actual_popen, actual_run, actual_killpg = subprocess.Popen, subprocess.run, os.killpg

        def popen(argv, *args, **kwargs):
            if not (argv[:3] == [sys.executable, '-I', '-c'] and argv[3].startswith(ORPHAN_CODE) and kwargs.get('start_new_session')):
                return actual_popen(argv, *args, **kwargs)
            held = not launches
            code = (ORPHAN_PRELUDE % (HOLDER, str(release)) if held else '') + argv[3]
            process = actual_popen([*argv[:3], code, *argv[4:]], *args, **kwargs)
            launches.append((process.pid, held))
            return process

        def killpg(pgid, signum):
            try:
                actual_killpg(pgid, signum)
            except PermissionError:
                if (pgid, True) in launches:
                    # A close_session observed the held member: release it before the caller continues.
                    release.touch()
                    refusals.append((pgid, signum, vanish(pgid, actual_killpg)))
                raise
            if signum == signal.SIGTERM and (pgid, False) in launches:
                vanish(pgid, actual_killpg)  # Later orphans: reaped before the caller's next probe.

        def run(argv, *args, **kwargs):
            if argv[2:3] != [str(ORIGINAL_RUNNER.absolute())]:
                return actual_run(argv, *args, **kwargs)
            target = Path(kwargs['cwd']) / 'agent_tools/tests/test_owned_orphan.py'
            original, held = target.read_bytes(), not runs
            self.assertEqual(1, original.count(CLI_CHILD))
            cli_release = workspace / ('cli-release-%d' % len(runs))
            target.write_bytes(original + (CLI_HELD % (HOLDER, str(cli_release))).encode() if held
                               else original.replace(CLI_CHILD, CLI_LEAVER))
            try:
                child = actual_run(argv, *args, **kwargs)
            finally:
                target.write_bytes(original)
                cli_release.touch()
            report = Path(argv[argv.index('--report-dir') + 1])
            worker = json.loads((report / 'worker-0000/started.json').read_bytes())['pid']
            runs.append({'held': held, 'returncode': child.returncode, 'stderr': child.stderr, 'vanished': vanish(worker, actual_killpg),
                         'fixture': json.loads((report / 'worker-0000/fixture-root.json').read_bytes())})
            return child

        proxy = types.SimpleNamespace(**{key: getattr(subprocess, key) for key in dir(subprocess) if not key.startswith('_')})
        proxy.Popen, proxy.run = popen, run
        result = unittest.TestResult()
        with mock.patch.object(module, 'subprocess', proxy), mock.patch.object(os, 'killpg', killpg):
            module.SessionObserverTests(name).run(result)
        release.touch()
        self.assertTrue(all(vanish(pid, os.killpg) for pid, _ in launches), 'orphan session remained')
        for value in runs:  # Hygiene for the unfixed case, which leaves its refused fixture root.
            value['fixtureRetained'] = os.path.lexists(value['fixture']['path'])
            if value['fixtureRetained']:
                self.assertTrue(runner.cleanup_fixture_root(Path(value['fixture']['path']), value['fixture']['generation']))
        return result, launches, refusals, runs

    def text(self, result):
        return ''.join(text for _, text in result.errors + result.failures)

    def test_unfixed_harness_red_on_original_refusal_fixed_harness_retries_or_uses_current_cleanup(self):
        old = self.observer_tests_before()
        original = str(ORIGINAL_RUNNER.absolute())
        refusal = 'PermissionError: [Errno 1] Operation not permitted'
        whole = 'test_actual_whole_before_cleans_orphan_without_identity_current_observes_generations'
        with self.subTest(whole):
            result, launches, refusals, runs = self.run_case(old, whole)
            self.assertEqual((1, 0, 1), (result.testsRun, len(result.failures), len(result.errors)), self.text(result))
            lines = self.text(result).splitlines()
            self.assertIn('  File "%s", line 62, in %s' % (TESTS_BEFORE, whole), lines)
            self.assertIn('    terminal = before.close_session(process)', lines)
            self.assertIn('  File "%s", line 526, in close_session' % original, lines)
            self.assertEqual(refusal, lines[-1])
            self.assertEqual(([True], [(launches[0][0], 0, True)], []), ([held for _, held in launches], refusals, runs))
            result, launches, refusals, runs = self.run_case(observer_tests, whole)
            self.assertEqual((1, 0, 0), (result.testsRun, len(result.failures), len(result.errors)), self.text(result))
            # One fresh orphan after the original's refusal; the later one never sees a zombie window.
            self.assertEqual(([True, False], [(launches[0][0], 0, True)]), ([held for _, held in launches], refusals))
        for cleanup in ('test_foreign_leader_generation_and_missing_member_visibility_never_signal',
                        'test_missing_observer_visibility_has_finite_reason_without_private_exception_value'):
            with self.subTest(cleanup):
                result, launches, refusals, runs = self.run_case(old, cleanup)
                self.assertEqual((1, 0, 1), (result.testsRun, len(result.failures), len(result.errors)), self.text(result))
                lines = self.text(result).splitlines()
                # The original's close_session ran as the orphan cleanup, after the case body passed.
                self.assertIn('  File "%s", line 526, in close_session' % original, lines)
                self.assertNotIn(str(TESTS_BEFORE), self.text(result))
                self.assertEqual(refusal, lines[-1])
                self.assertEqual(([True], [(launches[0][0], 0, True)]), ([held for _, held in launches], refusals))
                result, launches, refusals, runs = self.run_case(observer_tests, cleanup)
                self.assertEqual((1, 0, 0), (result.testsRun, len(result.failures), len(result.errors)), self.text(result))
                # The current runner's cleanup saw the same EPERM, kept the group present and waited for ESRCH.
                self.assertEqual(([True], [(launches[0][0], 0, True)]), ([held for _, held in launches], refusals))
        cli = 'test_complete_original_runner_cannot_attribute_current_retains_orphan_before_after'
        with self.subTest(cli):
            result, launches, refusals, runs = self.run_case(old, cli)
            self.assertEqual((1, 1, 0), (result.testsRun, len(result.failures), len(result.errors)), self.text(result))
            lines = self.text(result).splitlines()
            self.assertIn('  File "%s", line 126, in %s' % (TESTS_BEFORE, cli), lines)
            self.assertIn('AssertionError: 1 != 2 : ' + REFUSED.strip(), lines)
            self.assertEqual([(True, 2, REFUSED, True, True)],
                             [(v['held'], v['returncode'], v['stderr'], v['vanished'], v['fixtureRetained']) for v in runs])
            result, launches, refusals, runs = self.run_case(observer_tests, cli)
            self.assertEqual((1, 0, 0), (result.testsRun, len(result.failures), len(result.errors)), self.text(result))
            # The refused original's fixture root was removed by its generation; one fresh original run passed.
            refused, *later = runs
            self.assertEqual((True, 2, REFUSED, True, False), (refused['held'], refused['returncode'], refused['stderr'],
                                                               refused['vanished'], refused['fixtureRetained']))
            self.assertEqual([(False, 1, True, False)], [(v['held'], v['returncode'], v['vanished'], v['fixtureRetained']) for v in later])


if __name__ == '__main__':
    unittest.main()
