"""Fresh coordinator observes an original prelaunch crash before retrying it."""
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


class RecoveryObserver(controlled.SocketAdapter):
    def __init__(self, path, core):
        super().__init__(path)
        self.core = core
        self.crash = True
        self.original_absent = True
        self.invalid = False
        self.observations = []

    def observe(self, requirements, deadline):
        return self.core.Observation(**asdict(super().observe(requirements, deadline)))

    def recover(self, *args):
        if self.crash:
            self.crash = False
            raise SystemExit("controlled coordinator death before provider admission")
        return super().recover(*args)

    def observe_recovery(self, action, recovery_id, observed, deadline, attempt, digest):
        self.observations.append((action, recovery_id, attempt, digest))
        if not self.original_absent:
            return None
        proof = hashlib.sha256(("retained-private-original-owner-absence:" + digest).encode()).hexdigest()
        return readiness.RecoveryUnsubmitted(recovery_id, attempt, "0" * 64 if self.invalid else digest, proof)


class RecoveryObserverTests(unittest.TestCase):
    setUp = controlled.ReadinessTests.setUp
    close = controlled.ReadinessTests.close
    observe = controlled.ReadinessTests.observe

    def crashed(self):
        self.observe(guest="stopped", boot=None, guest_agent=False)
        adapter = RecoveryObserver(self.path, readiness)
        self.context.adapter = adapter
        with self.assertRaises(SystemExit):
            readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual([], self.server.effects)
        return adapter

    def test_whole_before_coordinator_red_fresh_same_original_green(self):
        adapter = self.crashed()
        folder = Path(__file__).parent / "fixtures/readiness_recovery_observer_before"
        path = folder / "readiness.py.source"
        raw = path.read_bytes()
        self.assertEqual(json.loads((folder / "provenance.json").read_bytes())["sha256"], hashlib.sha256(raw).hexdigest())
        old = types.ModuleType("agent_tools._readiness_recovery_observer_before")
        old.__package__ = "agent_tools"
        old.__file__ = str(path)
        with mock.patch.dict(sys.modules, {old.__name__: old}):
            exec(compile(raw, str(path), "exec"), old.__dict__)
        adapter.core = old
        with self.assertRaises(old.ReadinessBlocked) as failure:
            old.ensure_ready(self.context, old.Requirements(frozenset({"guest_agent"}), old.RECOVERIES), self.operation)
        self.assertEqual("recovery_outcome_unknown", failure.exception.reason)
        self.assertEqual([], adapter.observations)
        self.assertEqual([], self.server.effects)
        clock = controlled.Clock()
        self.context.clock, self.context.sleep = clock, clock.sleep
        adapter.core = readiness
        ready = readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("boot-b", ready.boot)
        self.assertEqual(1, len(adapter.observations))
        self.assertEqual([("start", adapter.observations[0][1])], self.server.effects)
        self.assertEqual(1, adapter.observations[0][2])

    def test_unknown_original_never_replays_after_restart(self):
        adapter = self.crashed()
        adapter.original_absent = False
        with self.assertRaises(readiness.ReadinessBlocked) as failure:
            readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("recovery_outcome_unknown", failure.exception.reason)
        self.assertEqual([], self.server.effects)
        self.assertEqual(1, len(adapter.observations))

    def test_stale_proof_fails_closed_and_never_dispatches(self):
        adapter = self.crashed()
        adapter.invalid = True
        with self.assertRaises(readiness.ReadinessBlocked) as failure:
            readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("recovery_unsubmitted_proof_invalid", failure.exception.reason)
        self.assertEqual([], self.server.effects)


if __name__ == "__main__":
    unittest.main()
