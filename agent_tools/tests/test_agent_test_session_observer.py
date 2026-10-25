"""Actual orphaned owned-session metadata; no production runner integration."""
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import agent_test_session_observer as observer
from agent_tools import agent_test_runner as runner

FIXTURE = Path(__file__).parent / 'fixtures/agent_test_session_observer'
# The original runner refuses when a poll lands while its SIGTERMed orphan is an unreaped zombie:
# Darwin killpg then reports EPERM. Only original-runner observations get fresh orphans, at most three.
ORIGINAL_ATTEMPTS = 3
ORIGINAL_REFUSED = 'Agent unittest runner refused: PermissionError\n'


@unittest.skipUnless(os.name == 'posix' and (sys.platform == 'darwin' or sys.platform.startswith('linux')),
                     'native owned POSIX process generations')
class SessionObserverTests(unittest.TestCase):
    def before(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual({'before.source', 'actual-failure.json'}, set(provenance['files']))
        for name, digest in provenance['files'].items():
            self.assertEqual(digest, hashlib.sha256((FIXTURE / name).read_bytes()).hexdigest())
        path = FIXTURE / 'before.source'
        module = types.ModuleType('agent_tools._session_observer_runner_before')
        module.__file__ = str(path.absolute())
        exec(compile(path.read_bytes(), module.__file__, 'exec'), module.__dict__)
        return module

    def orphan(self):
        code = ("import json,subprocess,sys;"
                "child=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                "print(json.dumps({'pid':child.pid}),flush=True);sys.stdin.buffer.read(1)")
        process = subprocess.Popen([sys.executable, '-I', '-c', code], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        before = self.before()
        # The current runner stops the owned orphan session; it waits out a zombie-only group.
        self.addCleanup(runner.close_session, process)
        self.addCleanup(lambda: process.poll() is None and process.communicate(b'x', timeout=5))
        owner = observer.admit(process)
        selector = selectors.DefaultSelector()
        self.addCleanup(selector.close)
        selector.register(process.stdout, selectors.EVENT_READ)
        self.assertTrue(selector.select(5), 'owned child did not publish its PID')
        child = json.loads(process.stdout.readline())['pid']
        process.communicate(b'x', timeout=5)
        self.assertEqual(0, process.returncode)
        return process, owner, child, before

    def test_actual_whole_before_cleans_orphan_without_identity_current_observes_generations(self):
        for attempt in range(1, ORIGINAL_ATTEMPTS + 1):
            process, owner, child, before = self.orphan()
            observed = observer.snapshot(owner, 'before_cleanup')
            row, = [value for value in observed['members'] if value['pid'] == child]
            self.assertEqual((process.pid, process.pid), (row['sid'], row['pgid']))
            self.assertTrue(row['birth'].startswith('darwin:' if sys.platform == 'darwin' else 'linux:'))
            self.assertEqual(os.geteuid(), row['uid'])
            self.assertEqual('python', row['role'])
            try:
                terminal = before.close_session(process)
                break
            except PermissionError as error:
                if error.errno != errno.EPERM or attempt == ORIGINAL_ATTEMPTS:
                    raise
        self.assertEqual((True, True), terminal)
        # Actual old API has only two booleans; it cannot identify its residual child.
        with self.assertRaises(TypeError):
            terminal['members']
        after = observer.snapshot(owner, 'after_cleanup')
        self.assertEqual([], after['members'])
        self.assertFalse(observed['memberOwnershipEstablished'])
        self.assertFalse(observed['cleanupAuthority'])
        self.assertFalse(observed['sourceAttributionAvailable'])
        serialized = json.dumps(observed)
        self.assertNotIn('time.sleep', serialized)
        self.assertNotIn(sys.executable, serialized)

    def test_foreign_leader_generation_and_missing_member_visibility_never_signal(self):
        process, owner, _, _ = self.orphan()
        changed = dict(owner._original, birth='foreign-generation')
        with mock.patch.object(observer, '_identity', return_value=changed), \
             mock.patch.object(os, 'killpg') as signal:
            with self.assertRaisesRegex(observer.SessionObservationBlocked, 'owner_generation_changed'):
                observer.snapshot(owner, 'before_cleanup')
            signal.assert_not_called()
        with mock.patch.object(observer, '_pids', side_effect=observer.SessionObservationBlocked('session_process_catalogue_incomplete')), \
             mock.patch.object(os, 'killpg') as signal:
            with self.assertRaisesRegex(observer.SessionObservationBlocked, 'catalogue_incomplete'):
                observer.snapshot(owner, 'before_cleanup')
            signal.assert_not_called()
        with self.assertRaises(TypeError):
            owner._original['pid'] = 1
        self.assertIsNotNone(process.returncode)

    def test_unadmitted_popen_and_changed_source_fail_without_observer_signals(self):
        with mock.patch.object(os, 'killpg') as signal:
            with self.assertRaisesRegex(observer.SessionObservationBlocked, 'owner_not_live'):
                observer.admit(object())
            with mock.patch.object(observer, '_SOURCE', observer._SOURCE + b'\n'):
                with self.assertRaisesRegex(observer.SessionObservationBlocked, 'source_changed'):
                    observer.admit(object())
            signal.assert_not_called()

    def test_complete_original_runner_cannot_attribute_current_retains_orphan_before_after(self):
        self.before()  # Authenticate the complete original CLI source before dispatch.
        for source, old in ((FIXTURE / 'before.source', True), (Path(runner.__file__), False)):
            with self.subTest(before=old), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                root.chmod(0o700)
                package = root / 'agent_tools/tests'
                package.mkdir(parents=True)
                (package.parent / '__init__.py').write_text('')
                (package / '__init__.py').write_text('')
                module = 'agent_tools.tests.test_owned_orphan'
                (package / 'test_owned_orphan.py').write_text(
                    "import subprocess,sys,unittest\nclass C(unittest.TestCase):\n"
                    " def test_one(self):\n"
                    "  child=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(60)'],"
                    "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                    "  print('owned-child:'+str(child.pid),flush=True)\n")
                plan = root / 'input.json'
                plan.write_text(json.dumps({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64,
                                            'modules': [module], 'maxWorkers': 1}))
                report_dir = root / 'report'
                for attempt in range(1, ORIGINAL_ATTEMPTS + 1):
                    child = subprocess.run([sys.executable, '-B', str(source.absolute()),
                        '--plan-file', str(plan), '--report-dir', str(report_dir)], cwd=root,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
                    if not old or attempt == ORIGINAL_ATTEMPTS or (child.returncode, child.stderr) != (2, ORIGINAL_REFUSED):
                        break
                    # The refused original keeps its worker fixture root: remove it by its recorded
                    # generation, then observe a fresh orphan in a new report directory.
                    fixture = json.loads((report_dir / 'worker-0000/fixture-root.json').read_bytes())
                    self.assertTrue(runner.cleanup_fixture_root(Path(fixture['path']), fixture['generation']))
                    report_dir = root / ('report-%d' % (attempt + 1))
                self.assertEqual(1, child.returncode, child.stderr)
                report = json.loads((report_dir / 'report.json').read_bytes())
                worker, = report['workers']
                self.assertEqual('incomplete', report['state'])
                self.assertEqual(1, report['counts']['testsRun'])
                self.assertEqual(0, report['counts']['errors'])
                self.assertTrue(worker['descendantLeak'])
                self.assertTrue(worker['sessionAbsent'])
                self.assertTrue(worker['fixtureRootRemoved'])
                if old:
                    with self.assertRaises(KeyError):
                        worker['sessionBeforeCleanup']
                    self.assertFalse((report_dir / 'worker-0000/session-before-cleanup.json').exists())
                else:
                    before = worker['sessionBeforeCleanup']
                    pid = int((report_dir / 'worker-0000/stdout.txt').read_text().strip().split(':')[1])
                    member, = [row for row in before['members'] if row['pid'] == pid]
                    self.assertEqual(worker['pid'], member['sid'])
                    self.assertEqual(worker['pid'], member['pgid'])
                    self.assertEqual('python', member['role'])
                    self.assertTrue(member['birth'])
                    self.assertTrue(worker['sessionObservationComplete'])
                    self.assertEqual([], worker['sessionAfterCleanup']['members'])
                    self.assertEqual(before, json.loads((report_dir / 'worker-0000/session-before-cleanup.json').read_bytes()))
                    self.assertFalse(before['cleanupAuthority'])

    def test_missing_observer_visibility_has_finite_reason_without_private_exception_value(self):
        process, owner, _, _ = self.orphan()
        with mock.patch.object(observer, 'snapshot', side_effect=observer.SessionObservationBlocked('session_member_visibility_incomplete')):
            self.assertEqual({'state': 'incomplete', 'reason': 'session_member_visibility_incomplete',
                              'cleanupAuthority': False}, runner._session_snapshot(owner, 'before_cleanup'))
        with mock.patch.object(observer, 'snapshot', side_effect=RuntimeError('PRIVATE INPUT MUST NOT LEAK')):
            value = runner._session_snapshot(owner, 'before_cleanup')
            self.assertEqual('session_observation_unavailable', value['reason'])
            self.assertNotIn('PRIVATE', json.dumps(value))
        self.assertIsNotNone(process.returncode)


if __name__ == '__main__':
    unittest.main()
