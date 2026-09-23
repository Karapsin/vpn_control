import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("android_subscription_refresh_lifecycle.py")
spec = importlib.util.spec_from_file_location("refresh_lifecycle", MODULE_PATH)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def envelope(**values):
    base = {"ok": True, "controllerId": "owner-7", "configurationRevision": 4}
    base.update(values)
    return type("Result", (), {"returncode": 0, "stdout": json.dumps(base), "stderr": ""})()


class SubscriptionRefreshDriverTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temporary.cleanup()

    def args(self):
        server_log = Path(self.temporary.name) / "requests.jsonl"
        if not server_log.exists():
            server_log.write_text("")
        return SimpleNamespace(
            cli=Path("/opt/vpn-control"), serial="emulator-5584", timeout_seconds=180,
            cli_environment={"PATH": "/approved"}, device_port=45390,
            subscription_source="https://localhost:45390/subscription", subscription_name="native-refresh",
            probe_output=Path(self.temporary.name) / "cli-records.json",
            server_log=server_log,
        )

    def test_source_is_exact_local_fixture_endpoint(self):
        self.assertEqual("https://localhost:45390/subscription", driver.require_fixture_source(
            "https://localhost:45390/subscription", 45390))
        for unsafe in ("http://localhost:45390/subscription", "https://example.test/subscription",
                       "https://localhost:45390/other", "https://localhost:45390/subscription?secret=x"):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                driver.require_fixture_source(unsafe, 45390)

    def test_existing_fixture_source_is_rejected_without_upsert_or_cleanup(self):
        args = self.args()
        calls = []
        def run(command, **kwargs):
            calls.append(command)
            if command[-2:] == ["source", "show"]:
                return envelope(data={"mode": "current-locations", "subscriptionId": None})
            if command[-2:] == ["subscriptions", "list"]:
                return envelope(data={"subscriptions": [{"id": "existing"}]})
            if command[-3:] == ["subscriptions", "show", "existing"]:
                return envelope(data={"id": "existing", "source": args.subscription_source})
            if command[-1] == "status":
                return envelope(data={"runtimeRunning": False})
            self.fail("existing subscription must not be mutated")
        with patch.object(driver.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                driver.run_subscription_refresh_action(args, None, {})
        self.assertEqual(3, len(calls))

    def test_admission_revision_change_prevents_add_after_source_inventory(self):
        args = self.args()
        responses = iter([
            envelope(data={"mode": "current-locations", "subscriptionId": None}),
            envelope(data={"subscriptions": []}),
            envelope(configurationRevision=5, data={"runtimeRunning": False}),
        ])
        with patch.object(driver.subprocess, "run", side_effect=lambda *_a, **_k: next(responses)) as run:
            with self.assertRaisesRegex(RuntimeError, "snapshot changed"):
                driver.run_subscription_refresh_action(args, None, {})
        self.assertEqual(3, run.call_count)
        self.assertFalse(any("add" in call.args[0] or "delete" in call.args[0] for call in run.call_args_list))

    def test_certificate_admission_requires_local_regular_non_symlink_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); certificate = root / "ca.pem"; certificate.write_text("fixture")
            self.assertEqual(certificate.resolve(), driver.require_local_fixture_certificate(certificate, "CA certificate"))
            with self.assertRaises(ValueError):
                driver.require_local_fixture_certificate(root / "missing.pem", "CA certificate")
            link = root / "link.pem"; link.symlink_to(certificate)
            with self.assertRaises(ValueError):
                driver.require_local_fixture_certificate(link, "CA certificate")

    def test_main_uses_reverse_only_tls_route_and_api_specific_ca_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ca = root / "ca.pem"; leaf = root / "leaf.pem"; ca.write_text("ca"); leaf.write_text("leaf")
            argv = ["tool", "--adb", str(root / "adb"), "--serial", "serial", "--cli", str(root / "cli.py"),
                    "--certificate", str(ca), "--leaf-certificate", str(leaf), "--fixture-parent", str(root),
                    "--server-log", str(root / "requests.jsonl"), "--probe-output", str(root / "records.json"),
                    "--device-port", "45390", "--host-port", "61000", "--staging", "/data/local/tmp/vpn-control-test",
                    "--receipt", str(root / "receipt.json"), "--expected-avd", "api35", "--expected-api", "35",
                    "--expected-version", "1", "--expected-code", "1", "--base-apk", str(ca), "--base-sha256", "0" * 64,
                    "--subscription-source", "https://localhost:45390/subscription", "--subscription-name", "fixture"]
            with patch.object(sys, "argv", argv), patch.object(driver, "require_interactive_stdin"), \
                 patch.object(driver, "public_cli_environment", return_value={}), \
                 patch.object(driver, "run_fixture_lifecycle") as lifecycle:
                driver.main()
        self.assertEqual("/apex/com.android.conscrypt/cacerts", lifecycle.call_args.kwargs["ca_store_target"])
        self.assertEqual("reverse-only", lifecycle.call_args.kwargs["transport_mode"])

    def test_add_refresh_wait_delete_keeps_exact_owner_and_operation_identities(self):
        responses = iter([
            envelope(data={"mode": "current-locations", "subscriptionId": None}),
            envelope(data={"subscriptions": []}),
            envelope(data={"runtimeRunning": False}),
            envelope(operationId="add-1"),
            envelope(final=True, operationId="add-1", data={"id": "subscription-9"}),
            envelope(data={"cachedLocations": 0}),
            envelope(configurationRevision=5, data={"runtimeRunning": False}),
            envelope(configurationRevision=5, operationId="refresh-2"),
            envelope(configurationRevision=5, final=True, operationId="refresh-2", data={}),
            envelope(configurationRevision=5, data={"cachedLocations": 1}),
            envelope(configurationRevision=5, data={"runtimeRunning": False}),
            envelope(configurationRevision=5, data={}),
            envelope(configurationRevision=6, data={"runtimeRunning": False}),
            envelope(configurationRevision=6, data={}),
            envelope(configurationRevision=6, data={"mode": "current-locations", "subscriptionId": None}),
        ])
        calls = []
        args = self.args()
        def run(command, **kwargs):
            calls.append((command, kwargs))
            if command[-2:] == ["wait", "refresh-2"]:
                args.server_log.write_text(
                    '{"method":"GET","endpoint":"subscription","count":1}\n'
                )
            return next(responses)
        with patch.object(driver.subprocess, "run", side_effect=run):
            result = driver.run_subscription_refresh_action(args, None, {})
        self.assertEqual({"subscriptionId": "subscription-9", "operations": {
            "add": "add-1", "refresh": "refresh-2",
        }, "cachedLocations": {"afterAdd": 0, "afterRefresh": 1},
            "fixtureRequests": {"beforeRefresh": 0, "afterRefresh": 1}}, result)
        mutation_calls = [command for command, _ in calls if "--async" in command]
        self.assertEqual(2, len(mutation_calls))
        self.assertTrue(all(command[0] == str(args.cli) for command in mutation_calls))
        self.assertTrue(all("--controller-id" in command and "owner-7" in command for command in mutation_calls))
        self.assertIn("subscription-9", mutation_calls[1])
        self.assertTrue(any("subscriptions" in command and "delete" in command and "--async" not in command for command, _ in calls))
        self.assertTrue(all(kwargs["env"] == {"PATH": "/approved"} for _, kwargs in calls))
        saved = json.loads(self.args().probe_output.read_text())
        self.assertEqual(len(calls), len(saved))
        if os.name == "posix":
            self.assertEqual(0o600, self.args().probe_output.stat().st_mode & 0o777)

    def test_request_counter_rejects_nonmonotonic_or_non_fixture_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "requests.jsonl"
            log.write_text('{"method":"GET","endpoint":"subscription","count":2}\n'
                           '{"method":"GET","endpoint":"subscription","count":1}\n')
            with self.assertRaisesRegex(RuntimeError, "monotonic"):
                driver.subscription_request_count(log)
            log.write_text('{"method":"POST","endpoint":"subscription","count":1}\n')
            with self.assertRaisesRegex(RuntimeError, "invalid"):
                driver.subscription_request_count(log)

    def test_empty_add_cache_and_request_log_are_admitted_only_until_refresh(self):
        args = self.args()
        self.assertEqual(0, driver.subscription_request_count(args.server_log))
        responses = iter([envelope(data={"cachedLocations": 0}), envelope(data={"cachedLocations": 1})])
        with patch.object(driver.subprocess, "run", side_effect=lambda *_a, **_k: next(responses)):
            self.assertEqual(0, driver.require_cached_locations(args, "subscription-9", minimum=0))
            self.assertEqual(1, driver.require_cached_locations(args, "subscription-9", minimum=1))

    def test_unsafe_owner_rejects_before_any_mutation(self):
        result = envelope(ok=True, controllerId="", data={"runtimeRunning": False})
        with patch.object(driver.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(RuntimeError, "owner identity"):
                driver.run_subscription_refresh_action(self.args(), None, {})
        self.assertEqual(1, run.call_count)

    def test_mismatched_wait_identity_preserves_unknown_add_without_delete_or_replay(self):
        responses = iter([
            envelope(data={"mode": "current-locations", "subscriptionId": None}),
            envelope(data={"subscriptions": []}),
            envelope(data={"runtimeRunning": False}), envelope(operationId="add-1"),
            envelope(final=True, operationId="other-operation", data={"id": "subscription-9"}),
        ])
        with patch.object(driver.subprocess, "run", side_effect=lambda *_args, **_kwargs: next(responses)) as run:
            with self.assertRaisesRegex(RuntimeError, "matching terminal"):
                driver.run_subscription_refresh_action(self.args(), None, {})
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(5, len(commands))
        self.assertFalse(any("delete" in command for command in commands))

    def test_cli_failure_does_not_retry_uncertain_mutation(self):
        responses = iter([envelope(data={"mode": "current-locations", "subscriptionId": None}),
            envelope(data={"subscriptions": []}), envelope(data={"runtimeRunning": False}), type("Result", (), {
            "returncode": 2, "stdout": "", "stderr": "timeout",
        })()])
        with patch.object(driver.subprocess, "run", side_effect=lambda *_args, **_kwargs: next(responses)) as run:
            with self.assertRaisesRegex(RuntimeError, "command failed"):
                driver.run_subscription_refresh_action(self.args(), None, {})
        self.assertEqual(4, run.call_count)

    def test_refresh_wait_unknown_does_not_delete_or_restore(self):
        args = self.args()
        responses = iter([
            envelope(data={"mode": "current-locations", "subscriptionId": None}),
            envelope(data={"subscriptions": []}),
            envelope(data={"runtimeRunning": False}), envelope(operationId="add-1"),
            envelope(final=True, operationId="add-1", data={"id": "subscription-9"}),
            envelope(data={"cachedLocations": 1}), envelope(configurationRevision=5, data={"runtimeRunning": False}),
            envelope(configurationRevision=5, operationId="refresh-2"),
            envelope(configurationRevision=5, final=False, operationId="refresh-2", data={}),
        ])
        with patch.object(driver.subprocess, "run", side_effect=lambda *_a, **_k: next(responses)) as run:
            with self.assertRaisesRegex(RuntimeError, "matching terminal"):
                driver.run_subscription_refresh_action(args, None, {})
        commands = [call.args[0] for call in run.call_args_list]
        self.assertFalse(any("delete" in command or ("source" in command and "set" in command) for command in commands))
        self.assertTrue(args.probe_output.exists())

    def test_guard_rejects_replacement_owner_before_followup_write(self):
        args = self.args()
        responses = iter([
            envelope(data={"mode": "current-locations", "subscriptionId": None}),
            envelope(data={"subscriptions": []}),
            envelope(data={"runtimeRunning": False}), envelope(operationId="add-1"),
            envelope(final=True, operationId="add-1", data={"id": "subscription-9"}),
            envelope(data={"cachedLocations": 1}),
            envelope(controllerId="replacement", configurationRevision=5, data={"runtimeRunning": False}),
        ])
        with patch.object(driver.subprocess, "run", side_effect=lambda *_a, **_k: next(responses)) as run:
            with self.assertRaisesRegex(RuntimeError, "owner changed"):
                driver.run_subscription_refresh_action(args, None, {})
        self.assertFalse(any("refresh" in call.args[0] for call in run.call_args_list))


if __name__ == "__main__":
    unittest.main()
