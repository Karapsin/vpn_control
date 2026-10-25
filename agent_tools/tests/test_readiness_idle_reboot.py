"""Exercise finite graceful reboot admission over a real provider socket."""
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import unittest
from uuid import uuid4

from agent_tools import readiness as r
from agent_tools import readiness_workflow
from agent_tools.tests import test_readiness as controlled


class IdleRebootTests(unittest.TestCase):
    setUp = controlled.ReadinessTests.setUp
    close = controlled.ReadinessTests.close
    observe = controlled.ReadinessTests.observe

    def test_healthy_normal_admission_does_not_reboot_but_explicit_reboot_runs_once(self):
        r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual([], self.server.effects)
        ready = r.idle_reboot(self.context, self.operation)
        self.assertEqual('boot-b', ready.boot)
        r.revalidate(self.context, ready)
        self.server.lost_ack = {'reboot'}
        r.idle_reboot(self.context, self.operation)
        self.assertEqual(['reboot'], [action for action, _ in self.server.effects])

    def test_every_idle_category_and_uncertain_job_blocks_power(self):
        for category in r.IDLE_VISIBILITY:
            for changes in ({'idle_visibility': r.IDLE_VISIBILITY - {category}},
                            {'idle_visibility': r.IDLE_VISIBILITY, 'idle_blockers': frozenset({category})}):
                with self.subTest(category=category, changes=changes):
                    self.observe(idle_blockers=frozenset(), **changes) if 'idle_blockers' not in changes else self.observe(**changes)
                    with self.assertRaises(r.ReadinessBlocked) as error:
                        r.idle_reboot(self.context, str(uuid4()))
                    self.assertEqual('positive_idle_proof_missing', error.exception.reason)
        self.assertEqual([], self.server.effects)

    def test_stopped_and_paused_fixtures_are_not_started_to_reboot(self):
        for state in ('stopped', 'paused', 'suspended'):
            self.observe(guest=state)
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.idle_reboot(self.context, str(uuid4()))
            self.assertEqual('recovery_not_permitted', error.exception.reason)
        self.assertEqual([], self.server.effects)

    def test_lost_ack_and_new_caller_share_original_reboot_no_replacement(self):
        self.server.lost_ack = {'reboot'}
        self.server.dont_apply = {'reboot'}
        second = str(uuid4())
        for operation in (self.operation, second):
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.idle_reboot(self.context, operation)
            self.assertEqual('recovery_outcome_unknown', error.exception.reason)
        self.assertEqual(1, len(self.server.effects))
        self.observe(boot='boot-b')
        for operation in (self.operation, second):
            ready = r.idle_reboot(self.context, operation)
            self.assertEqual('boot-b', ready.boot)
        self.assertEqual(1, len(self.server.effects))

    def test_known_unsubmitted_retry_keeps_one_recovery_identity(self):
        self.context.adapter = controlled.ProofSocketAdapter(self.path)
        self.server.unsubmitted = {'reboot': 1}
        ready = r.idle_reboot(self.context, self.operation)
        self.assertEqual('boot-b', ready.boot)
        self.assertEqual([1, 2], [x['attempt'] for x in self.server.attempts])
        self.assertEqual(1, len({x['recoveryId'] for x in self.server.attempts}))
        self.assertEqual(1, len(self.server.effects))

    def test_facade_keeps_fixture_identity_and_does_not_require_unlock(self):
        self.observe(ordinary_session='locked', display='sleeping', credential_available=False)
        fixture = SimpleNamespace(adapter=self.context.adapter, context=lambda: self.context)
        with mock.patch.object(readiness_workflow.fixtures, 'registered_fixture', return_value=fixture):
            result = readiness_workflow.vm_workflow(Path(self.directory.name), 'readiness-reboot',
                {'fixtureId': 'owned-headless', 'operationId': self.operation})
        self.assertTrue(result['ok'])
        self.assertEqual('owned-headless', result['fixtureId'])
        self.assertEqual(self.operation, result['operationId'])
        self.assertEqual(['reboot'], [action for action, _ in self.server.effects])
        self.assertEqual('locked', self.server.observation.ordinary_session)


if __name__ == '__main__':
    unittest.main()
