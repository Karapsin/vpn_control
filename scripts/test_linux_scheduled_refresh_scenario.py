#!/usr/bin/env python3
"""Fast causal regressions for the installed Linux scheduled-refresh driver."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import uuid


INTEGRATION = pathlib.Path(__file__).parent / "integration"
sys.path.insert(0, str(INTEGRATION))
sys.path.insert(0, str(pathlib.Path(__file__).parent))
SPEC = importlib.util.spec_from_file_location("linux_scheduled_refresh_scenario", INTEGRATION / "linux_scheduled_refresh_scenario.py")
assert SPEC and SPEC.loader
scenario = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scenario)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "getuid"),
                     "installed Linux scenario uses POSIX-owned absolute fixture paths")
class ScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = pathlib.Path(self.temp.name).resolve()
        self.owned = base / "owned"
        self.owned.mkdir()
        self.protected = base / "protected"
        self.protected.mkdir()
        self.receipt = base / "receipt.json"
        self.input = {
            "schema": scenario.SCHEMA, "schemaVersion": 1, "scenarioId": scenario.SCENARIO,
            "correlationId": str(uuid.uuid4()), "ownedWorkspaceRoot": str(self.owned),
            "protectedStateDir": str(self.protected), "protectedControllerId": str(uuid.uuid4()),
            "expectedPackageNevra": "vpn-control-2.1.17-1.x86_64",
            "expectedDesktopJarSha256": "a" * 64, "mode": "refresh-find-best",
            "scheduleHours": 0.084, "maxObservationSeconds": 390,
        }

    def spec(self):
        return scenario.validate_input(self.input, self.receipt)

    def test_rejects_wrong_selector_and_missing_explicit_refresh(self) -> None:
        runner = scenario.ScenarioRunner(self.spec())
        commands = []
        active = {"runtimeRunning": True, "runtimeId": "runtime-a", "activeLocationId": "a",
                  "selectedLocationId": "a"}
        pending = {**active, "selectedLocationId": "b"}

        def fake_cli(tail, **_kwargs):
            commands.append(tail)
            if tail[:2] == ["subscriptions", "add"]:
                return {"data": {"id": "source-id"}}
            if tail == ["locations", "list"]:
                # Native locations are empty until the explicit refresh.
                count = 2 if ["subscriptions", "refresh", "source-id"] in commands else 0
                return {"data": {"locations": [{} for _ in range(count)]}}
            if tail == ["status"]:
                return {"data": pending if ["locations", "select", "2"] in commands else active}
            if tail == ["locations", "benchmark", "1"]:
                return {"data": {"primaryStatus": "manual", "primaryTotalMs": None,
                                 "secondaryStatus": "ok", "secondaryTotalMs": 62.2}}
            return {"data": {}}

        runner.cli = fake_cli
        runner.receipt["source"] = {}
        runner._preflight = lambda _source, _cert: None
        runner._probe = lambda *_args: {"returncode": 0, "matchedFixtureBody": True}
        with mock.patch.object(scenario, "named_mixed_port", return_value=1234):
            runner._configure("https://localhost:1234/subscription", self.owned / "cert.pem")
        self.assertLess(commands.index(["source", "set", "subscription", "source-id"]),
                        commands.index(["subscriptions", "refresh", "source-id"]))
        self.assertLess(commands.index(["subscriptions", "refresh", "source-id"]),
                        commands.index(["locations", "list"]))
        self.assertNotIn(["source", "set", "source-id"], commands)

    def test_find_best_validation_url_and_secondary_measurement(self) -> None:
        runner = scenario.ScenarioRunner(self.spec())
        commands = []
        active = {"runtimeRunning": True, "runtimeId": "runtime-a", "activeLocationId": "a",
                  "selectedLocationId": "a"}
        pending = {**active, "selectedLocationId": "b"}

        def fake_cli(tail, **_kwargs):
            commands.append(tail)
            if tail[:2] == ["subscriptions", "add"]:
                return {"data": {"id": "source-id"}}
            if tail == ["locations", "list"]:
                return {"data": {"locations": [{}, {}]}}
            if tail == ["status"]:
                return {"data": pending if ["locations", "select", "2"] in commands else active}
            if tail == ["locations", "benchmark", "1"]:
                return {"data": {"primaryStatus": "manual", "primaryTotalMs": None,
                                 "secondaryStatus": "ok", "secondaryTotalMs": 62.2}}
            return {"data": {}}

        runner.cli = fake_cli
        runner.receipt["source"] = {}
        runner._preflight = lambda _source, _cert: None
        runner._probe = lambda *_args: {"returncode": 0, "matchedFixtureBody": True}
        with mock.patch.object(scenario, "named_mixed_port", return_value=1234):
            explicit = runner._configure("https://localhost:1234/subscription", self.owned / "cert.pem")
        self.assertLess(commands.index(["settings", "set", "validation.test-url", "https://localhost:1234/subscription"]),
                        commands.index(["locations", "benchmark", "1"]))
        self.assertLess(commands.index(["locations", "benchmark", "1"]), commands.index(["find-best"]))
        self.assertEqual(explicit["benchmark"]["secondaryTotalMs"], 62.2)
        with self.assertRaisesRegex(scenario.ScenarioError, "secondary"):
            scenario.require_measured_benchmark({"data": {"primaryStatus": "ok", "primaryTotalMs": 5,
                                                            "secondaryStatus": "failed", "secondaryTotalMs": None}})

    def test_timed_out_mutation_is_unknown_and_called_once(self) -> None:
        calls = []

        def timeout(argv, **_kwargs):
            calls.append(argv)
            raise subprocess.TimeoutExpired(argv, 3)

        runner = scenario.ScenarioRunner(self.spec(), run=timeout)
        with self.assertRaises(scenario.OutcomeUnknown):
            runner.cli(["subscriptions", "refresh", "id"], mutation=True)
        self.assertEqual(len(calls), 1)
        runner.root.mkdir()
        runner.owner = object()
        runner._protected_status = lambda: True
        runner._cleanup()
        self.assertTrue(runner.root.exists())
        self.assertEqual(runner.receipt["cleanup"]["state"], "preserved-for-recovery")

    def test_reported_accepted_timeout_is_not_replayed(self) -> None:
        calls = []

        def timed_out(argv, **_kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 2, json.dumps({"ok": False, "code": "TIMEOUT",
                                                                       "operationId": "accepted-op", "final": False}), "")

        runner = scenario.ScenarioRunner(self.spec(), run=timed_out)
        with self.assertRaises(scenario.OutcomeUnknown):
            runner.cli(["find-best"], mutation=True)
        self.assertEqual(len(calls), 1)
        self.assertEqual(runner.unknown_operation["operationId"], "accepted-op")

    def test_cleanup_refuses_changed_or_missing_owner_identity(self) -> None:
        runner = scenario.ScenarioRunner(self.spec())
        runner.root.mkdir()
        runner.owner = object()
        runner.owner_id = "owner-a"
        calls = []

        def changed(tail, **_kwargs):
            calls.append(tail)
            return {"controllerId": "owner-b"}

        runner.cli = changed
        runner._protected_status = lambda: True
        runner._cleanup()
        self.assertEqual(calls, [["status"]])
        self.assertTrue(runner.root.exists())
        self.assertEqual(runner.receipt["cleanup"]["state"], "preserved-for-recovery")

    def test_port_migration_requires_new_named_listener_probe(self) -> None:
        state = self.owned / "state"
        state.mkdir()
        (state / "runtime-config.json").write_text(json.dumps({"inbounds": [
            {"type": "mixed", "tag": "management", "listen": "127.0.0.1", "listen_port": 39921},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 38105},
        ]}))
        self.assertEqual(scenario.named_mixed_port(state), 38105)
        result = scenario.traffic_classification(42071, 38105,
                                                 [{"returncode": 0, "matchedFixtureBody": True},
                                                  {"returncode": 7, "matchedFixtureBody": False}],
                                                 {"port": 38105, "returncode": 0, "matchedFixtureBody": True})
        self.assertTrue(result["portMigrated"])
        self.assertFalse(result["oldPortContinuity"])
        self.assertTrue(result["postTransitionTraffic"])

    def test_preflight_rejects_default_validation_url_before_on(self) -> None:
        runner = scenario.ScenarioRunner(self.spec())
        original = scenario.linux_scheduled_refresh
        try:
            scenario.linux_scheduled_refresh = lambda *_args, **_kwargs: {
                "profile": "linux-scheduled-refresh", "checks": {"settings": False}, "ready": False}
            with self.assertRaisesRegex(scenario.ScenarioError, "preflight"):
                runner._preflight("https://localhost:1234/subscription", self.owned / "cert.pem")
        finally:
            scenario.linux_scheduled_refresh = original
        self.assertIs(runner.receipt["preflight"]["checks"]["settings"], False)

    def test_input_rejects_workspace_overlap_or_existing_receipt(self) -> None:
        self.input["protectedStateDir"] = str(self.owned / "protected")
        with self.assertRaisesRegex(scenario.ScenarioError, "overlap"):
            self.spec()
        self.input["protectedStateDir"] = str(self.protected)
        self.receipt.write_text("existing")
        with self.assertRaisesRegex(scenario.ScenarioError, "new"):
            self.spec()

    def test_rejects_non_finite_schedule_numbers(self) -> None:
        for field in ("scheduleHours", "maxObservationSeconds"):
            original = self.input[field]
            for invalid in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(field=field, invalid=invalid):
                    self.input[field] = invalid
                    with self.assertRaisesRegex(scenario.ScenarioError, "schedule"):
                        self.spec()
            self.input[field] = original


if __name__ == "__main__":
    unittest.main()
