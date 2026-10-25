"""Original owner publication must survive the qualified provider wrapper."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools import readiness_providers as providers
from agent_tools.tests import test_readiness as controlled
from agent_tools.tests.test_readiness_publication import PublicationAdapter, FailedConnectionAdapter


def before_provider():
    folder = Path(__file__).parent / "fixtures/provider_recovery_delegate_before"
    path = folder / "readiness_providers.py.source"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != json.loads((folder / "provenance.json").read_bytes())["sha256"]:
        raise AssertionError("beforeimage changed")
    module = types.ModuleType("agent_tools._provider_recovery_delegate_before")
    module.__package__, module.__file__ = "agent_tools", str(path)
    with mock.patch.dict(sys.modules, {module.__name__: module}):
        exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


class ProviderRecoveryDelegateTests(unittest.TestCase):
    setUp = controlled.ReadinessTests.setUp
    close = controlled.ReadinessTests.close
    observe = controlled.ReadinessTests.observe

    def wrapper(self, backend, module=providers):
        return module.ProviderAdapter("raw-qemu-windows", "fixture", "machine-a", backend)

    def reset_clock(self):
        clock = controlled.Clock()
        self.context.clock, self.context.sleep = clock, clock.sleep

    def test_same_original_publication_whole_before_red_fixed_green_over_real_socket(self):
        backend = PublicationAdapter(self.path, Path(self.directory.name))
        self.context.adapter = self.wrapper(backend, before_provider())
        requirements = readiness.Requirements(frozenset({"transport"}), frozenset({"reconnect"}))
        with self.assertRaises(readiness.ReadinessBlocked) as failure:
            readiness.ensure_ready(self.context, requirements, self.operation)
        self.assertEqual("recovery_outcome_unknown", failure.exception.reason)
        self.assertEqual(1, len(self.server.effects))
        self.assertEqual([], backend.reconciled)
        original = self.server.effects[0][1]
        self.context.adapter = self.wrapper(backend)
        self.reset_clock()
        ready = readiness.ensure_ready(self.context, requirements, self.operation)
        self.assertEqual(self.operation, ready.operation_identity)
        self.assertEqual("connection-b", ready.connection)
        self.assertEqual([original], backend.reconciled)
        self.assertEqual([("reconnect", original)], self.server.effects)

    def test_failed_connection_owner_can_end_without_replacing_an_application_job(self):
        backend = FailedConnectionAdapter(self.path)
        self.context.adapter = self.wrapper(backend)
        requirements = readiness.Requirements(frozenset({"transport"}), frozenset({"reconnect"}))
        with self.assertRaises(readiness.ReadinessBlocked) as failure:
            readiness.ensure_ready(self.context, requirements, self.operation)
        self.assertEqual("transport_attempts_exhausted", failure.exception.reason)
        self.assertEqual(3, len(set(backend.attempts)))
        self.assertEqual([], self.server.effects)
        backend.restored = True
        self.reset_clock()
        ready = readiness.ensure_ready(self.context, requirements, self.operation)
        self.assertEqual(self.operation, ready.operation_identity)
        self.assertEqual(4, len(set(backend.attempts)))
        self.assertEqual(1, len(self.server.effects))

    def test_wrong_target_unowned_or_unqualified_outcomes_never_reach_backend(self):
        backend = PublicationAdapter(self.path, Path(self.directory.name))
        adapter = self.wrapper(backend)
        observed = self.server.observation
        for change in ({"owned": False}, {"coordinator_host": True}, {"machine": "other"}):
            with self.subTest(change=change), self.assertRaises(providers.ProviderError):
                adapter.reconcile_recovery("reconnect", "a" * 64, replace(observed, **change), 10, 1, "b" * 64)
        with self.assertRaises(providers.ProviderError):
            adapter.reconcile_recovery("reconnect", "a" * 64, observed, 10, True, "b" * 64)
        self.assertEqual([], backend.reconciled)
        self.assertEqual([], self.server.effects)

    def test_only_exact_correlated_connection_terminal_or_boolean_crosses_hook(self):
        backend = controlled.SocketAdapter(self.path)
        adapter = self.wrapper(backend)
        observed = self.server.observation
        self.assertIs(False, adapter.reconcile_recovery("reconnect", "a" * 64, observed, 10, 1, "b" * 64))
        for result in (1, {"ready": True}, readiness.RecoveryUnsubmitted("a" * 64, 1, "b" * 64, "c" * 64),
                       readiness.RecoveryEnded("a" * 64, 2, "b" * 64, "c" * 64)):
            backend.reconcile_recovery = lambda *args: result
            with self.subTest(kind=type(result).__name__), self.assertRaises(providers.ProviderError):
                adapter.reconcile_recovery("reconnect", "a" * 64, observed, 10, 1, "b" * 64)
        result = readiness.RecoveryEnded("a" * 64, 1, "b" * 64, "c" * 64)
        backend.reconcile_recovery = lambda *args: result
        self.assertIs(result, adapter.reconcile_recovery("reconnect", "a" * 64, observed, 10, 1, "b" * 64))
        with self.assertRaises(providers.ProviderError):
            adapter.reconcile_recovery("login", "a" * 64, observed, 10, 1, "b" * 64)
        result.extra = "unreviewed"
        with self.assertRaises(providers.ProviderError):
            adapter.reconcile_recovery("reconnect", "a" * 64, observed, 10, 1, "b" * 64)
        self.assertEqual([], self.server.effects)


if __name__ == "__main__":
    unittest.main()
