"""Causal CP117 owner JVM launch admission tests; no native guest action."""
from __future__ import annotations

import tempfile
import unittest
import uuid
import hashlib
import json
import base64
import contextlib
import fcntl
import io
import os
import re
import stat
import types
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
           "trustStore": owner._ROOT + r"\mcp-update-credentials-" + STAGE + r"\fixture-trust.p12",
           "socketPath": "/owned/cp117.sock", "qemuPid": 4322, "startTicks": 98765,
           "liveReceiptSha256": "1" * 64}
PREFLIGHT = {"schemaVersion": 1, "code": "OWNER_RUNTIME_CHECK", "ownerPid": 4321,
             "ownerStartedAtUtc": REQUEST["ownerStartedAtUtc"], "controllerId": CONTROLLER,
             "cliSha256": BINDING["baseCliSha256"],
             "trustStoreSha256": BINDING["trustStoreSha256"], "activeProcessCount": 0}
PROVENANCE = {"state": "terminal", "ownerNetworkCorrelationId": CORR,
              "bootstrapExitCode": 0, "bindingSha256": "2" * 64, "dispatchPid": 7444}


class OwnerNetworkTests(unittest.TestCase):
    def test_remote_prior_job_requires_exact_closed_lease_before_guest_exec(self):
        old_lease = str(uuid.uuid4()); old_corr = str(uuid.uuid4())
        with tempfile.TemporaryDirectory() as directory:
            root = owner.Path(directory); root.chmod(0o700)
            parent = root / "windows-cp117"; parent.mkdir(mode=0o700)
            group = parent / "windows-owner-network"; group.mkdir(mode=0o700)
            old = group / old_corr; old.mkdir(mode=0o700)
            old_binding = {"leaseId": old_lease, "ownerNetworkCorrelationId": old_corr,
                           "socketPath": BINDING["socketPath"], "qemuPid": BINDING["qemuPid"],
                           "startTicks": BINDING["startTicks"], "sourceSha": REQUEST["sourceSha"],
                           "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                           "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                           "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                           "commandSha256": "3" * 64}
            owner._write_private(old / "binding.json", old_binding)
            code = "import fcntl,re\nroot,env" + owner._REMOTE_START.split("import fcntl,re\nroot,env", 1)[1]
            command = b"fixed bootstrap"
            calls = []
            argv = ["remote", str(root), "windows-cp117", LEASE, CORR,
                    BINDING["socketPath"], str(BINDING["qemuPid"]), str(BINDING["startTicks"]),
                    base64.b64encode(command).decode(), hashlib.sha256(command).hexdigest(),
                    REQUEST["sourceSha"], REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseMsiArtifactId"], REQUEST["targetMsiArtifactId"]]
            def invoke():
                output = io.StringIO()
                namespace = {"os": os, "stat": stat, "json": json, "base64": base64,
                             "hashlib": hashlib, "fcntl": fcntl, "re": re,
                             "sys": types.SimpleNamespace(argv=argv),
                             "live": lambda *args: True,
                             "require_campaign_role": lambda *args: None,
                             "call": lambda *args: calls.append(args) or {"pid": 777}}
                with contextlib.redirect_stdout(output):
                    exec(code, namespace)
                return json.loads(output.getvalue())
            self.assertEqual(invoke()["state"], "unknown")
            self.assertEqual(calls, [])
            campaign = parent / "windows-cp117-campaign"; campaign.mkdir(mode=0o700)
            closed = {"state": "closed", "role": None,
                      "identity": {"leaseId": old_lease, "host": "archlinux",
                                   "environment": "windows-cp117", "sourceSha": REQUEST["sourceSha"],
                                   "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                                   "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                                   "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                                   "socketPath": BINDING["socketPath"],
                                   "qemuPid": BINDING["qemuPid"], "startTicks": BINDING["startTicks"]}}
            owner._write_private(campaign / (old_lease + ".closed.json"), closed)
            self.assertEqual(invoke()["state"], "submitted")
            self.assertEqual(len(calls), 1)

    def test_prior_owner_network_history_requires_exact_remote_closed_campaign(self):
        old_request = {**REQUEST, "leaseId": str(uuid.uuid4()),
                       "ownerNetworkCorrelationId": str(uuid.uuid4())}
        with tempfile.TemporaryDirectory() as directory:
            root = owner.Path(directory); group = root / owner._GROUP
            group.mkdir(parents=True, mode=0o700)
            old = group / (old_request["ownerNetworkCorrelationId"] + ".json")
            owner._write_private(old, {"request": old_request, "binding": BINDING,
                                       "commandSha256": "3" * 64})
            with patch.object(owner, "_closed_prior_campaign", return_value=True):
                owner._reserve(root, REQUEST, BINDING, "4" * 64)
            self.assertIsNotNone(owner._read_intent(root, CORR))
        with tempfile.TemporaryDirectory() as directory:
            root = owner.Path(directory); group = root / owner._GROUP
            group.mkdir(parents=True, mode=0o700)
            old = group / (old_request["ownerNetworkCorrelationId"] + ".json")
            owner._write_private(old, {"request": old_request, "binding": BINDING,
                                       "commandSha256": "3" * 64})
            with patch.object(owner, "_closed_prior_campaign", return_value=False):
                with self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                    owner._reserve(root, REQUEST, BINDING, "4" * 64)
            self.assertIsNone(owner._read_intent(root, CORR))

    def test_remote_bootstrap_provenance_must_precede_guest_result_and_role_finish(self):
        command_hash = "3" * 64
        expected = {"leaseId": LEASE, "ownerNetworkCorrelationId": CORR,
                    "socketPath": BINDING["socketPath"], "qemuPid": BINDING["qemuPid"],
                    "startTicks": BINDING["startTicks"], "sourceSha": REQUEST["sourceSha"],
                    "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                    "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                    "commandSha256": command_hash}
        digest = hashlib.sha256(json.dumps(expected, sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest()
        valid = {"state": "terminal", "ownerNetworkCorrelationId": CORR,
                 "bootstrapExitCode": 0, "bindingSha256": digest, "dispatchPid": 7222}
        class Target:
            fixture_transfer_root = "/private/cp117"
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner.base, "_descriptor", return_value=(object(), Target(),
                 ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                  BINDING["startTicks"], SID))), \
             patch.object(owner.base, "_remote") as remote:
            remote.return_value = json.dumps(valid).encode()
            self.assertEqual(owner._remote_provenance(owner.Path(directory), REQUEST,
                                                      BINDING, command_hash), valid)
            for changed in ({"bootstrapExitCode": True}, {"bindingSha256": "0" * 64},
                            {"dispatchPid": 0}, {"state": "running"}):
                remote.return_value = json.dumps({**valid, **changed}).encode()
                with self.subTest(changed=changed), self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                    owner._remote_provenance(owner.Path(directory), REQUEST, BINDING, command_hash)

        local_hash = hashlib.sha256("fixed-command".encode("utf-16le")).hexdigest()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner, "_read_intent", return_value={"request": REQUEST, "binding": BINDING,
                                                                "commandSha256": local_hash}), \
             patch.object(owner, "_binding", return_value=BINDING), \
             patch.object(owner, "_bootstrap_script", return_value="fixed-command"), \
             patch.object(owner, "_remote_provenance", side_effect=owner.WindowsFixtureOwnerNetworkError("unknown")), \
             patch.object(owner, "_observe_native") as observe, \
             patch.object(owner.lease, "finish_role") as finish:
            self.assertEqual(owner.status(directory, {"ownerNetworkCorrelationId": CORR})["state"], "unknown")
            observe.assert_not_called(); finish.assert_not_called()

    def test_owner_intent_write_failure_precedes_lease_claim_and_guest_dispatch(self):
        class Target:
            fixture_transfer_root = "/private/cp117"
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner.base, "_descriptor", return_value=(object(), Target(),
                 ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                  BINDING["startTicks"], SID))), \
             patch.object(owner, "_preflight_native", return_value=PREFLIGHT), \
             patch.object(owner, "_reserve", side_effect=OSError("fsync failed")), \
             patch.object(owner.lease, "claim_role") as claim, \
             patch.object(owner.base, "_remote") as remote:
            with self.assertRaisesRegex(OSError, "fsync failed"):
                owner._submit_candidate(owner.Path(directory), REQUEST, BINDING)
            claim.assert_not_called()
            remote.assert_not_called()

    def test_owner_role_waits_for_task_cleanup_and_reconciles_lost_response(self):
        """A cleanup transport loss cannot finish; a later exact absence can."""
        local_hash = hashlib.sha256("fixed-command".encode("utf-16le")).hexdigest()
        current = {"identity": {"leaseId": LEASE}, "server": "live",
                   "credentials": "ready", "state": "role-active", "role": "owner-network",
                   "correlationId": CORR}
        before = {"ownerTaskCleanupSha256": None, "ownerLaunchReceiptSha256": "3" * 64}
        after = {"ownerTaskCleanupSha256": "9" * 64,
                 "ownerLaunchReceiptSha256": "4" * 64,
                 "ownerPid": 5321, "ownerStartedAtUtc": "2026-09-29T10:00:00Z",
                 "controllerId": str(uuid.uuid4())}
        class Target:
            fixture_transfer_root = "/private/cp117"
        def locked(_root):
            return owner.Path(_root), os.open(os.devnull, os.O_RDONLY)
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner, "_read_intent", return_value={"request": REQUEST, "binding": BINDING,
                                                                 "commandSha256": local_hash}), \
             patch.object(owner, "_binding", return_value=BINDING), \
             patch.object(owner, "_bootstrap_script", return_value="fixed-command"), \
             patch.object(owner, "_remote_provenance", return_value=PROVENANCE), \
             patch.object(owner, "_observe_native", side_effect=[before, before, after]) as observe, \
             patch.object(owner, "_cleanup_native", side_effect=owner.WindowsFixtureOwnerNetworkError("response lost")) as cleanup, \
             patch.object(owner, "_save_terminal") as save, \
             patch.object(owner.lease, "_locked", side_effect=locked), \
             patch.object(owner.lease, "_active", return_value=current), \
             patch.object(owner.lease, "finish_role", return_value={"state": "active"}) as finish, \
             patch.object(owner.base, "_descriptor", return_value=(object(), Target(),
                 ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                  BINDING["startTicks"], SID))):
            self.assertEqual(owner.status(directory, {"ownerNetworkCorrelationId": CORR})["state"], "unknown")
            finish.assert_not_called(); save.assert_not_called()
            cleanup.side_effect = None
            cleanup.return_value = "9" * 64
            self.assertEqual(owner.status(directory, {"ownerNetworkCorrelationId": CORR})["state"], "correlated")
            self.assertEqual(observe.call_count, 3)
            self.assertEqual(cleanup.call_count, 2)
            finish.assert_called_once()
            save.assert_called_once_with(owner.Path(directory).resolve(), after)

    def test_owner_cleanup_is_exact_and_proof_precedes_task_removal(self):
        script = owner._cleanup_script(REQUEST, BINDING)
        self.assertLess(script.index("Set-Acl -LiteralPath $proofPath"),
                        script.index("Unregister-ScheduledTask"))
        for code in ("PATH_ANCESTOR", "PRIVATE_ACL", "TASK_ACTION_CHANGED",
                     "CLEANUP_PROOF_CHANGED", "TASK_CLEANUP_UNKNOWN"):
            self.assertIn(code, script)
        self.assertNotIn("Stop-Process", script)
        self.assertNotIn("taskkill", script)
        action = "-NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(
            owner._task_script(REQUEST, BINDING).encode("utf-16le")).decode("ascii")
        result = {"schemaVersion": 1, "correlationId": CORR,
                  "taskName": "VpnControlMcpOwnerNetwork-" + CORR,
                  "actionSha256": hashlib.sha256(action.encode()).hexdigest(),
                  "taskAbsent": True, "cleanupProofSha256": "9" * 64}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner.base, "_descriptor", return_value=(object(),
                 types.SimpleNamespace(fixture_transfer_root="/private/cp117"),
                 ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                  BINDING["startTicks"], SID))), \
             patch.object(owner.base, "_remote", return_value=json.dumps(
                 {"state": "observed", "result": result}).encode()):
            self.assertEqual(owner._cleanup_native(owner.Path(directory), REQUEST, BINDING), "9" * 64)
            for changed in ({"taskAbsent": False}, {"actionSha256": "0" * 64},
                            {"cleanupProofSha256": "short"}, {"correlationId": LEASE}):
                with self.subTest(changed=changed), \
                     patch.object(owner.base, "_remote", return_value=json.dumps(
                         {"state": "observed", "result": {**result, **changed}}).encode()), \
                     self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                    owner._cleanup_native(owner.Path(directory), REQUEST, BINDING)

    def test_terminal_owner_launch_requires_fresh_bound_generation(self):
        new_controller = str(uuid.uuid4())
        record = {"schemaVersion": 1, "correlationId": CORR,
                  "oldOwnerPid": REQUEST["ownerPid"],
                  "oldOwnerStartedAtUtc": REQUEST["ownerStartedAtUtc"],
                  "oldControllerId": REQUEST["controllerId"],
                  "newOwnerPid": 5321, "newOwnerStartedAtUtc": "2026-09-29T10:00:00Z",
                  "newControllerId": new_controller, "originalSid": SID,
                  "sessionId": 1, "limited": True,
                  "cliSha256": BINDING["baseCliSha256"], "proxyHost": "127.0.0.1",
                  "proxyPort": BINDING["serverPort"],
                  "trustStoreSha256": BINDING["trustStoreSha256"],
                  "runtimeOff": True, "launchSource": "limited-task-process-environment"}
        observed = {"schemaVersion": 1, "correlationId": CORR, "record": record,
                    "taskState": "AbsentCleaned", "taskExitCode": 0,
                    "cleanupProofSha256": "9" * 64,
                    "ownerPid": 5321, "ownerStartedAtUtc": record["newOwnerStartedAtUtc"],
                    "controllerId": new_controller, "originalSid": SID,
                    "sessionId": 1, "activeProcessCount": 0}
        receipt = owner._validate_terminal(REQUEST, BINDING, observed, PROVENANCE)
        self.assertEqual(receipt["ownerJvmPid"], 5321)
        self.assertEqual(receipt["ownerTaskCleanupSha256"], "9" * 64)
        self.assertFalse(receipt["ownerJvmNetworkVerified"])
        for change in ({"taskState": "Ready"}, {"cleanupProofSha256": None},
                       {"taskState": "Running"}, {"taskExitCode": True},
                       {"ownerPid": REQUEST["ownerPid"]}, {"activeProcessCount": 1},
                       {"controllerId": CONTROLLER},
                       {"record": {**record, "proxyPort": 443}},
                       {"record": {**record, "trustStoreSha256": "0" * 64}},
                       {"record": {**record, "runtimeOff": False}},
                       {"record": {**record, "launchSource": "forwarding-cli-env"}}):
            with self.subTest(change=change), self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                owner._validate_terminal(REQUEST, BINDING, {**observed, **change}, PROVENANCE)
        for change in ({"bootstrapExitCode": True}, {"dispatchPid": 0},
                       {"ownerNetworkCorrelationId": LEASE}, {"bindingSha256": "wrong"}):
            with self.subTest(change=change), self.assertRaises(owner.WindowsFixtureOwnerNetworkError):
                owner._validate_terminal(REQUEST, BINDING, observed, {**PROVENANCE, **change})

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
        observer = owner._observation_script(REQUEST, BINDING)
        for evidence in ("TASK_COMMAND", "PATH_ANCESTOR", "ROOT_ACL", "RESULT_ACL",
                         "OLD_OWNER_STILL_LIVE", "NEW_OWNER_CHANGED"):
            self.assertIn(evidence, observer)
        self.assertNotIn("updates transport-probe", observer)

    def test_bootstrap_checks_ancestors_before_atomic_private_root_create(self):
        script = owner._bootstrap_script(REQUEST, BINDING)
        path_guard = script.index("PATH_ANCESTOR")
        acl_guard = script.index("ANCESTOR_ACL")
        create = script.index("$directory.Create($security)")
        register = script.index("Register-ScheduledTask")
        self.assertLess(path_guard, create)
        self.assertLess(acl_guard, create)
        self.assertLess(create, register)
        self.assertNotIn("[IO.Directory]::CreateDirectory($root)", script)
        self.assertNotIn("Set-Acl -LiteralPath $root", script)

    def test_public_start_dispatches_once_and_static_receipt_remains_blocked(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner, "_binding", return_value=BINDING), \
             patch.object(owner.lease, "_locked", side_effect=lambda *_:
                          (owner.Path(directory), os.open(os.devnull, os.O_RDONLY))), \
             patch.object(owner.lease, "_active", return_value={
                 "identity": {"leaseId": LEASE}, "state": "active", "role": None}), \
             patch.object(owner, "_submit_candidate", return_value={
                 "state": "submitted", "ownerNetworkCorrelationId": CORR,
                 "replayAllowed": False}) as submit:
            self.assertEqual(owner.start(directory, REQUEST)["state"], "submitted")
            submit.assert_called_once_with(owner.Path(directory).resolve(), REQUEST, BINDING)
            with self.assertRaisesRegex(owner.WindowsFixtureOwnerNetworkError,
                                        "OWNER_JVM_RECEIPT_UNAVAILABLE"):
                owner.verified_owner_jvm_receipt(directory, LEASE)

    def test_public_start_existing_intent_never_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = owner.Path(directory)
            owner._intent_path(root, CORR).parent.mkdir(parents=True, mode=0o700)
            owner._write_private(owner._intent_path(root, CORR), {
                "request": REQUEST, "binding": BINDING, "commandSha256": "4" * 64})
            with patch.object(owner, "_binding") as binding, \
                 patch.object(owner, "_submit_candidate") as submit:
                outcome = owner.start(directory, REQUEST)
                self.assertEqual(outcome["state"], "unknown")
                self.assertFalse(outcome["replayAllowed"])
                binding.assert_not_called()
                submit.assert_not_called()

    def test_start_rejects_existing_owner_role_before_reserving_intent(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner, "_binding", return_value=BINDING), \
             patch.object(owner.lease, "_locked", side_effect=lambda *_:
                          (owner.Path(directory), os.open(os.devnull, os.O_RDONLY))), \
             patch.object(owner.lease, "_active", return_value={
                 "identity": {"leaseId": LEASE}, "state": "role-active",
                 "role": "owner-network", "correlationId": CORR}), \
             patch.object(owner, "_submit_candidate") as submit:
            with self.assertRaisesRegex(owner.WindowsFixtureOwnerNetworkError,
                                        "idle campaign"):
                owner.start(directory, REQUEST)
            self.assertIsNone(owner._read_intent(owner.Path(directory), CORR))
            submit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
