"""Causal CP117 owner JVM launch admission tests; no native guest action."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_fixture_owner_network as owner


LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
SERVER = "33333333-3333-4333-8333-333333333333"
CORR = "44444444-4444-4444-8444-444444444444"
CONTROLLER = "55555555-5555-4555-8555-555555555555"
SID = "S-1-5-21-1-2-3-1002"
REQUEST = {"host": "archlinux", "leaseId": LEASE, "stageCorrelationId": STAGE,
           "serverCorrelationId": SERVER, "ownerNetworkCorrelationId": CORR,
           "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64,
           "controllerId": CONTROLLER, "ownerPid": 4321,
           "ownerStartedAtUtc": "2026-09-28T10:00:00Z"}
BINDING = {"originalSid": SID, "baseCliSha256": "e" * 64,
           "trustStoreSha256": "f" * 64, "serverPort": 53633,
           "trustStore": owner._ROOT + r"\mcp-update-credentials-" + STAGE + r"\fixture-trust.p12"}
PREFLIGHT = {"schemaVersion": 1, "code": "OWNER_RUNTIME_CHECK", "ownerPid": 4321,
             "ownerStartedAtUtc": REQUEST["ownerStartedAtUtc"], "controllerId": CONTROLLER,
             "cliSha256": BINDING["baseCliSha256"],
             "trustStoreSha256": BINDING["trustStoreSha256"], "activeProcessCount": 0}


class OwnerNetworkTests(unittest.TestCase):
    def test_request_rejects_changed_generation_and_extra_fields(self):
        self.assertEqual(owner._request(REQUEST), REQUEST)
        for change in ({"ownerPid": True}, {"ownerStartedAtUtc": "now"},
                       {"ownerNetworkCorrelationId": STAGE}, {"sourceSha": "0"},
                       {"extra": 1}):
            with self.subTest(change=change), self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                owner._request({**REQUEST, **change})

    def test_runtime_off_preflight_requires_exact_original_owner_and_no_active_process(self):
        owner._validate_preflight(REQUEST, BINDING, PREFLIGHT)
        for change in ({"ownerPid": True}, {"ownerStartedAtUtc": "2026-09-29T10:00:00Z"},
                       {"controllerId": LEASE}, {"trustStoreSha256": "0" * 64},
                       {"activeProcessCount": 1}, {"code": "UNKNOWN"}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                owner._validate_preflight(REQUEST, BINDING, {**PREFLIGHT, **change})
        script = owner._preflight_script(REQUEST, BINDING)
        self.assertIn("GetOwnerSid", script)
        self.assertIn("'^(msiexec|consent|sing-box)", script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("Start-ScheduledTask", script)
        self.assertNotIn(" quit|", script)

    def test_one_shot_task_checks_runtime_before_public_quit_and_scoped_serve(self):
        script = owner._task_script(REQUEST, BINDING)
        runtime = script.index("$status.data.runtimeRunning -ne $false")
        quit_command = script.index(" quit|ConvertFrom-Json")
        exit_check = script.index("QUIT_NOT_EXITED")
        endpoint_clear = script.index("OLD_ENDPOINT_REMAINS")
        scope = script.index("$env:JAVA_TOOL_OPTIONS=")
        serve = script.index("Start-Process -FilePath $cli")
        new_owner = script.index("$newStatus=& $cli")
        self.assertLess(runtime, quit_command)
        self.assertLess(quit_command, exit_check)
        self.assertLess(exit_check, endpoint_clear)
        self.assertLess(endpoint_clear, scope)
        self.assertLess(scope, serve)
        self.assertLess(serve, new_owner)
        self.assertIn("GetOwnerSid", script)
        self.assertNotIn("Stop-Process", script)
        self.assertNotIn("taskkill", script)

    def test_public_start_and_static_receipt_are_hard_blocked(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner, "_binding", return_value=BINDING):
            with self.assertRaisesRegex(owner.WindowsFixtureOwnerNetworkError,
                                        "OWNER_NETWORK_DISPATCH_UNAVAILABLE"):
                owner.start(directory, REQUEST)
            with self.assertRaisesRegex(owner.WindowsFixtureOwnerNetworkError,
                                        "OWNER_JVM_RECEIPT_UNAVAILABLE"):
                owner.verified_owner_jvm_receipt(directory, LEASE)


if __name__ == "__main__":
    unittest.main()
