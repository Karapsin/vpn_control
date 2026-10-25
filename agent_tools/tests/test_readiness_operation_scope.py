"""Positive operator ownership must span observation and the actual power call."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import readiness
from agent_tools.tests import test_readiness as controlled


class OperatorAdapter(controlled.SocketAdapter):
    def __init__(self, path, core):
        super().__init__(path)
        self.core = core
        self.held = False
        self.scope_events = []

    @contextmanager
    def operation_scope(self, *, deadline, cancelled):
        if cancelled():
            raise self.core.ReadinessBlocked("readiness_cancelled", str(uuid4()))
        self.held = True
        self.scope_events.append("enter")
        try:
            yield
        finally:
            self.held = False
            self.scope_events.append("close")

    def observe(self, requirements, deadline):
        value = asdict(super().observe(requirements, deadline))
        if not self.held:
            value["idle_visibility"] -= {"operators"}
        return self.core.Observation(**value)

    def recover(self, *args):
        if not self.held:
            raise AssertionError("operator lock released before dispatch")
        return super().recover(*args)


class OperationScopeTests(unittest.TestCase):
    setUp = controlled.ReadinessTests.setUp
    close = controlled.ReadinessTests.close
    observe = controlled.ReadinessTests.observe

    def test_operator_lock_is_held_before_observation_through_power_dispatch(self):
        self.observe(guest="unhealthy")
        folder = Path(__file__).parent / "fixtures/readiness_operator_scope_before"
        path = folder / "readiness.py.source"
        raw = path.read_bytes()
        self.assertEqual(json.loads((folder / "provenance.json").read_bytes())["sha256"], hashlib.sha256(raw).hexdigest())
        old = types.ModuleType("agent_tools._readiness_operator_before")
        old.__package__ = "agent_tools"
        old.__file__ = str(path)
        with mock.patch.dict(sys.modules, {old.__name__: old}):
            exec(compile(raw, str(path), "exec"), old.__dict__)
        adapter = OperatorAdapter(self.path, old)
        self.context.adapter = adapter
        with self.assertRaises(old.ReadinessBlocked) as failure:
            old.ensure_ready(self.context, old.Requirements(frozenset({"guest_agent"}), old.RECOVERIES), self.operation)
        self.assertEqual("positive_idle_proof_missing", failure.exception.reason)
        self.assertEqual([], self.server.effects)
        self.assertEqual([], adapter.scope_events)

        adapter = OperatorAdapter(self.path, readiness)
        self.context.adapter = adapter
        ready = readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("boot-b", ready.boot)
        self.assertEqual(["reboot"], [a for a, _ in self.server.effects])
        self.assertEqual(["enter", "close"], adapter.scope_events)
        self.assertFalse(adapter.held)

    def test_scope_is_released_on_unknown_and_observers_do_not_acquire_it(self):
        adapter = OperatorAdapter(self.path, readiness)
        self.context.adapter = adapter
        adapter.observe(self.gui, self.clock() + 10)
        self.assertEqual([], adapter.scope_events)
        self.observe(ordinary_session="wrong_account")
        with self.assertRaises(readiness.ReadinessBlocked):
            readiness.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual(["enter", "close"], adapter.scope_events)
        self.assertEqual([], self.server.effects)


if __name__ == "__main__":
    unittest.main()
