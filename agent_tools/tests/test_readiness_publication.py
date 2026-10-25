"""Retain original connection owners across lost receipts and terminal failure."""
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools.tests import test_readiness as controlled


def before_core():
    folder = Path(__file__).parent / "fixtures/readiness_publication_before"
    path = folder / "readiness.py.source"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != json.loads((folder / "provenance.json").read_bytes())["sha256"]:
        raise AssertionError("beforeimage changed")
    module = types.ModuleType("agent_tools._readiness_publication_before")
    module.__package__, module.__file__ = "agent_tools", str(path)
    with mock.patch.dict(sys.modules, {module.__name__: module}):
        exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


class PublicationAdapter(controlled.SocketAdapter):
    def __init__(self, path, directory):
        super().__init__(path)
        self.directory = directory
        self.core = readiness
        self.reconciled = []

    def observe(self, requirements, deadline):
        observed = super().observe(requirements, deadline)
        if not (self.directory / "ready-receipt").exists():
            observed = replace(observed, transport="unavailable", connection=None)
        return self.core.Observation(**asdict(observed))

    def recover(self, action, recovery_id, observed, deadline):
        if (self.directory / "original-owner").exists():
            raise AssertionError("replacement owner was launched")
        (self.directory / "original-owner").write_text(recovery_id)
        super().recover(action, recovery_id, observed, deadline)
        raise ConnectionError("controlled lost ready publication")

    def reconcile_recovery(self, action, recovery_id, observed, deadline, attempt, digest):
        if (self.directory / "original-owner").read_text() != recovery_id:
            return None
        self.reconciled.append(recovery_id)
        (self.directory / "ready-receipt").write_text(recovery_id)
        return True


class FailedConnectionAdapter(controlled.SocketAdapter):
    def __init__(self, path):
        super().__init__(path)
        self.core = readiness
        self.restored = False
        self.ready = False
        self.attempts = []
        self.ended = set()

    def observe(self, requirements, deadline):
        observed = super().observe(requirements, deadline)
        if not self.ready:
            observed = replace(observed, transport="unavailable", connection=None)
        return self.core.Observation(**asdict(observed))

    def recover(self, action, recovery_id, observed, deadline):
        self.attempts.append(recovery_id)
        if not self.restored:
            self.ended.add(recovery_id)
            return  # Original connection owner positively ended in failure.
        self.ready = True
        super().recover(action, recovery_id, observed, deadline)

    def reconcile_recovery(self, action, recovery_id, observed, deadline, attempt, digest):
        if recovery_id in self.ended:
            proof = hashlib.sha256(("original-terminal-and-closed-socket:" + digest).encode()).hexdigest()
            return readiness.RecoveryEnded(recovery_id, attempt, digest, proof)
        return None


class RecoveryPublicationTests(unittest.TestCase):
    setUp = controlled.ReadinessTests.setUp
    close = controlled.ReadinessTests.close
    observe = controlled.ReadinessTests.observe

    def reset_clock(self):
        clock = controlled.Clock()
        self.context.clock, self.context.sleep = clock, clock.sleep

    def test_original_live_owner_ready_publication_red_green_without_replacement(self):
        old = before_core()
        adapter = PublicationAdapter(self.path, Path(self.directory.name))
        adapter.core = old
        self.context.adapter = adapter
        with self.assertRaises(old.ReadinessBlocked) as failure:
            old.ensure_ready(self.context, old.Requirements(frozenset({"transport"}), old.RECOVERIES), self.operation)
        self.assertEqual("recovery_outcome_unknown", failure.exception.reason)
        self.assertEqual(1, len(self.server.effects))
        self.assertEqual([], adapter.reconciled)
        adapter.core = readiness
        self.reset_clock()
        result = readiness.ensure_ready(self.context, readiness.Requirements(frozenset({"transport"}), readiness.RECOVERIES), self.operation)
        self.assertEqual("connection-b", result.connection)
        self.assertEqual([self.server.effects[0][1]], adapter.reconciled)
        self.assertEqual(1, len(self.server.effects))

    def test_exhausted_dead_connections_allow_same_original_after_network_restoration(self):
        old = before_core()
        adapter = FailedConnectionAdapter(self.path)
        self.context.adapter = adapter
        requirements = readiness.Requirements(frozenset({"transport"}), readiness.RECOVERIES)
        with self.assertRaises(readiness.ReadinessBlocked) as failure:
            readiness.ensure_ready(self.context, requirements, self.operation)
        self.assertEqual("transport_attempts_exhausted", failure.exception.reason)
        self.assertEqual(3, len(set(adapter.attempts)))
        # Demonstrate the old coordinator on the same original failure shape
        # without the new terminal receipts. Old intents remain retained.
        for path in Path(self.directory.name).glob("ended-*.json"):
            path.rename(path.with_suffix(".retained"))
        adapter.restored, adapter.core = True, old
        self.reset_clock()
        with self.assertRaises(old.ReadinessBlocked) as failure:
            old.ensure_ready(self.context, old.Requirements(frozenset({"transport"}), old.RECOVERIES), self.operation)
        self.assertEqual("recovery_outcome_unknown", failure.exception.reason)
        self.assertEqual(3, len(adapter.attempts))
        adapter.core = readiness
        self.reset_clock()
        result = readiness.ensure_ready(self.context, requirements, self.operation)
        self.assertEqual("connection-b", result.connection)
        self.assertEqual(self.operation, result.operation_identity)
        self.assertEqual(4, len(set(adapter.attempts)))
        self.assertEqual(1, len(self.server.effects))

    def test_locked_sleeping_desktop_wakes_before_credential_screen_admission(self):
        old = before_core()
        observed = replace(self.server.observation, ordinary_session="locked", display="sleeping")
        self.assertEqual("login", old._next(old.Observation(**asdict(observed)), self.gui, self.operation))
        self.assertEqual("wake_display", readiness._next(observed, self.gui, self.operation))
        for state, reason in (("wrong_account", "wrong_account"), ("locked", "credential_unavailable")):
            with self.assertRaises(readiness.ReadinessBlocked) as failure:
                readiness._next(replace(observed, ordinary_session=state, credential_available=False), self.gui, self.operation)
            self.assertEqual(reason, failure.exception.reason)

    def test_expired_zero_deadline_never_opens_the_journal_or_provider(self):
        self.context.deadline = 0
        with self.assertRaises(readiness.ReadinessBlocked) as failure:
            readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("readiness_deadline", failure.exception.reason)
        self.assertEqual(0, self.server.observe_calls)
        self.assertEqual([], self.server.effects)


if __name__ == "__main__":
    unittest.main()
