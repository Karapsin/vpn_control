"""Actual public dispatcher admission, before any target program generation."""
from contextlib import contextmanager
from types import SimpleNamespace
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import mcp_server, readiness


class ReadinessDispatchTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.operation = str(uuid4())

    @contextmanager
    def admission(self, root, host, operation, *, deadline):
        self.events.append(("admit", host, operation))
        try:
            yield
        finally:
            self.events.append(("close", host, operation))

    def adapters(self, name):
        return {"readiness": readiness,
                "ssh_transport": SimpleNamespace(admitted_transport=self.admission)}[name]

    def caller(self):
        def _ssh_generate(action="inventory", host=None, timeout_seconds=15, identity=None, transfer=None, device=None):
            self.events.append(("generate", action))
            return {"ok": True, "state": "observed"}
        return mcp_server._native_source_request(_ssh_generate)

    def test_remote_original_observation_admits_transport_before_generation(self):
        with mock.patch.object(mcp_server, "_agent_module", side_effect=self.adapters):
            result = self.caller()("job-status", "fixture", identity={"operationId": self.operation})
        self.assertTrue(result["ok"])
        self.assertEqual([("admit", "fixture", self.operation), ("generate", "job-status"),
                          ("close", "fixture", self.operation)], self.events)

    def test_local_history_and_intentional_phase_never_enter_transport_recovery(self):
        for action in ("inventory", "program-status", "program-collect", "forward-status", "tmux-disconnect-probe"):
            with self.subTest(action=action):
                self.events.clear()
                with mock.patch.object(mcp_server, "_agent_module", side_effect=AssertionError("local action recovered")):
                    result = self.caller()(action, "fixture", identity={"operationId": self.operation})
                self.assertTrue(result["ok"])
                self.assertEqual([("generate", action)], self.events)

    def test_transport_blocker_retains_original_operation_and_prevents_generation(self):
        @contextmanager
        def blocked(*args, **kwargs):
            raise readiness.ReadinessBlocked("trust_mismatch", self.operation)
            yield
        with mock.patch.object(mcp_server, "_agent_module", side_effect=lambda name:
                               readiness if name == "readiness" else SimpleNamespace(admitted_transport=blocked)):
            result = self.caller()("probe", "fixture", identity={"operationId": self.operation})
        self.assertEqual("trust_mismatch", result["reason"])
        self.assertEqual(self.operation, result["operationId"])
        self.assertFalse(result["replayAllowed"])
        self.assertEqual([], self.events)

    def test_invalid_target_uses_existing_pure_refusal_without_network(self):
        with mock.patch.object(mcp_server, "_agent_module", side_effect=AssertionError("invalid target recovered")):
            self.caller()("probe", "fixture;foreign")
        self.assertEqual([("generate", "probe")], self.events)

    def test_policy_integrity_failure_is_not_mislabeled_as_unknown_action(self):
        policy = SimpleNamespace(action_policy=mock.Mock(side_effect=ValueError("loaded_policy_changed")))
        with mock.patch.object(mcp_server._SOURCE_MODULE_LOADER, "adapter", return_value=policy):
            result = self.caller()("inventory")
        self.assertEqual("native_source_closure_unavailable", result["reason"])
        self.assertEqual("unknown", result["state"])
        self.assertEqual([], self.events)


if __name__ == "__main__":
    unittest.main()
