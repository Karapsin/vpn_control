"""Original consumed-snapshot queries never initialize missing metadata."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock

from agent_tools import readiness_resources as resources
from agent_tools.tests import test_readiness_resources as fixtures


class SubmissionQueryTests(unittest.TestCase):
    def setUp(self):
        self.case = fixtures.ResourceTests('test_consumed_snapshot_is_original_full_census_and_local_only')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.admission = self.case.prepare()
        self.admission.mark_submitting()
        self.case.calls.clear()

    def before(self):
        folder = Path(__file__).parent / 'fixtures/resource_submission_query_before'
        raw = (folder / 'readiness_resources.py.source').read_bytes()
        expected = json.loads((folder / 'provenance.json').read_bytes())['sourceSha256']
        self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
        module = types.ModuleType('agent_tools._resource_submission_query_before')
        module.__package__, module.__file__ = 'agent_tools', str(folder / 'readiness_resources.py.source')
        with mock.patch.dict(sys.modules, {module.__name__: module}):
            exec(compile(raw, module.__file__, 'exec'), module.__dict__)
        admission = self.admission
        return module.ResourceAdmission(admission.root, admission.target, admission.machine_uuid,
            admission.operation_id, admission.directory, admission.credential_file, admission.deadline)

    def paths(self):
        return set(path.relative_to(self.case.root) for path in self.case.root.rglob('*'))

    def test_whole_before_recreates_missing_lock_RED_current_refuses_without_mutation_GREEN(self):
        original = self.admission.submission_snapshot()
        before = self.before()
        lock = self.admission.directory / 'readiness.lock'
        lock.unlink()
        paths = self.paths()
        with self.assertRaises(FileNotFoundError):
            self.admission.submission_snapshot()
        self.assertEqual(paths, self.paths())
        self.assertEqual(original, before.submission_snapshot())
        self.assertTrue(lock.exists())
        self.assertEqual(original, self.admission.submission_snapshot())
        self.assertEqual([], self.case.calls)

    def test_expired_or_corrupt_journal_remains_blocked_and_missing_directory_stays_absent(self):
        with self.assertRaisesRegex(TimeoutError, 'resource_deadline'):
            replace(self.admission, deadline=time.monotonic()-1).submission_snapshot()
        lock = self.admission.directory / 'readiness.lock'
        lock.write_bytes(b'UNRECOGNIZED BODY\n')
        paths = self.paths()
        with self.assertRaisesRegex(ValueError, 'lock_integrity'):
            self.admission.submission_snapshot()
        self.assertEqual(paths, self.paths())
        missing = self.case.root / 'absent-journal'
        with self.assertRaises(FileNotFoundError):
            replace(self.admission, directory=missing).submission_snapshot()
        self.assertEqual(paths, self.paths())
        self.assertFalse(missing.exists())
        self.assertEqual([], self.case.calls)


if __name__ == '__main__':
    unittest.main()
