"""Reconcile original capacity ownership before reporting readiness after ACK loss."""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools.tests import test_readiness as controlled


def original_core():
    folder = Path(__file__).parent / 'fixtures/readiness_ready_bookkeeping_before'
    path = folder / 'readiness.py.source'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != json.loads((folder / 'provenance.json').read_bytes())['sha256']:
        raise AssertionError('beforeimage changed')
    module = types.ModuleType('agent_tools._readiness_bookkeeping_before')
    module.__package__, module.__file__ = 'agent_tools', str(path)
    with mock.patch.dict(sys.modules, {module.__name__: module}):
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class BookkeepingTests(unittest.TestCase):
    setUp = controlled.ReadinessTests.setUp
    close = controlled.ReadinessTests.close
    observe = controlled.ReadinessTests.observe

    def scenario(self, core, *, fail=False, stale=False):
        peer = self.context.adapter
        publications = []

        class Adapter:
            capabilities = peer.capabilities

            def observe(adapter, requirements, deadline):
                return core.Observation(**asdict(peer.observe(requirements, deadline)))

            def recover(adapter, *args):
                raise AssertionError('healthy original VM must not be replaced')

            def reconcile_ready(adapter, ready, *, deadline):
                if fail:
                    raise RuntimeError('private provider message')
                publications.append(ready.identities())
                if stale:
                    self.observe(boot='changed-after-original-actor-publication')

        context = core.Context('fixture', 'machine-a', Adapter(), core.RecoveryJournal(Path(self.directory.name)),
                               clock=self.clock, sleep=self.clock.sleep)
        result = core.ensure_ready(context, core.Requirements(frozenset({'guest_agent'})), self.operation)
        self.assertEqual([result.identities()], publications,
                         'normal admission left original capacity owner UNKNOWN after lost acknowledgement')
        return result

    def test_actual_original_admission_red_and_same_socket_fixed_green(self):
        with self.assertRaisesRegex(AssertionError, 'original capacity owner UNKNOWN'):
            self.scenario(original_core())
        self.scenario(readiness)
        self.assertEqual([], self.server.effects)

    def test_bookkeeping_failure_stays_specific_and_never_replays_vm(self):
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.scenario(readiness, fail=True)
        self.assertEqual('recovery_bookkeeping_unresolved', error.exception.reason)
        self.assertNotIn('private provider', str(error.exception))
        self.assertEqual([], self.server.effects)

    def test_generation_change_during_bookkeeping_refuses_ready_packet(self):
        with self.assertRaises(readiness.ReadinessBlocked) as error:
            self.scenario(readiness, stale=True)
        self.assertEqual('prepared_context_stale', error.exception.reason)
        self.assertEqual([], self.server.effects)


if __name__ == '__main__':
    unittest.main()
