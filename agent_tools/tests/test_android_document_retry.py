"""Causal guards for the large-document same-request campaign."""

import unittest
from unittest import mock
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from agent_tools import android_document_retry as retry
from agent_tools import mcp_server
from agent_tools import android_installer_dispatch


class AndroidDocumentRetryTest(unittest.TestCase):
    def test_identical_request_bytes_and_identity_are_required(self):
        first = retry._request_bytes("request-id", "owner-id", 1, "large input")
        self.assertEqual(first, retry._request_bytes("request-id", "owner-id", 1, "large input"))
        self.assertNotEqual(first, retry._request_bytes("new-request", "owner-id", 1, "large input"))
        self.assertNotEqual(first, retry._request_bytes("request-id", "owner-id", 1, "changed"))

    def test_remote_request_bytes_match_journaled_hash(self):
        module = ast.parse(retry._REMOTE)
        definition = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "request")
        scope = {"json": json, "request_id": "11111111-1111-4111-8111-111111111111",
                 "owner": "22222222-2222-4222-8222-222222222222", "revision": "1"}
        exec(compile(ast.Module(body=[definition], type_ignores=[]), "<request>", "exec"), scope)
        text = retry._fixture_text()
        self.assertEqual(scope["request"](text), retry._request_bytes(scope["request_id"], scope["owner"], 1, text))

    def test_remote_private_creation_overrides_inherited_umask_022(self):
        module = ast.parse(retry._REMOTE)
        phase = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "phase")
        setup = [node for node in module.body if isinstance(node, ast.Expr) and
                 isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and
                 isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "os" and
                 node.value.func.attr == "umask"]
        with tempfile.TemporaryDirectory() as temp:
            job = Path(temp)
            scope = {"os": os, "job": job, "json": json}
            inherited = os.umask(0o022)
            try:
                exec(compile(ast.Module(body=setup + [phase], type_ignores=[]), "<phase>", "exec"), scope)
                scope["phase"]("first_upload")
                self.assertEqual((job / "phase.json").stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(inherited)

    def test_public_cli_zero_exit_stderr_does_not_reject_bound_json(self):
        module = ast.parse(retry._REMOTE)
        invoke = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "invoke")
        public = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "public")
        class Finished:
            returncode = 0
            stdout = b'{"ok":true,"controllerId":"owner","configurationRevision":1}'
            stderr = b'benign packaged CLI diagnostic\n'
        scope = {"subprocess": mock.Mock(run=mock.Mock(return_value=Finished()), DEVNULL=object()),
                 "json": json, "cli": "/packaged/cli", "serial": "emulator-5554", "environment": {},
                 "fail": lambda reason: (_ for _ in ()).throw(ValueError(reason))}
        exec(compile(ast.Module(body=[invoke, public], type_ignores=[]), "<remote-public>", "exec"), scope)
        self.assertEqual(scope["public"]("status")["controllerId"], "owner")
        with self.assertRaisesRegex(ValueError, "command_failed"):
            scope["invoke"](["adb", "shell", "id"])
        failed = Finished()
        failed.returncode = 1
        scope["subprocess"].run.return_value = failed
        with self.assertRaisesRegex(ValueError, "command_failed"):
            scope["public"]("status")

    def test_terminal_rejects_a_new_request_noop_as_same_request_proof(self):
        intent = retry._test_intent()
        result = retry._test_result(intent)
        self.assertTrue(retry._terminal_valid(intent, result))
        result["retry"]["requestId"] = "different-request"
        self.assertFalse(retry._terminal_valid(intent, result))
        result = retry._test_result(intent)
        result["retry"]["operationId"] = "different-operation"
        self.assertFalse(retry._terminal_valid(intent, result))
        result = retry._test_result(intent)
        result["retry"]["revision"] += 1
        self.assertFalse(retry._terminal_valid(intent, result))

    def test_terminal_requires_restored_private_backup_and_no_runtime(self):
        intent = retry._test_intent()
        for field, value in (("openingRulesRestored", False), ("runtimeOff", False)):
            result = retry._test_result(intent)
            result["restore"][field] = value
            self.assertFalse(retry._terminal_valid(intent, result))
        result = retry._test_result(intent)
        result["opening"]["backupSha256"] = "0" * 64
        self.assertFalse(retry._terminal_valid(intent, result))

    def test_unknown_never_releases_device_lease(self):
        self.assertFalse(retry._collect_release_allowed({"state": "unknown"}))
        self.assertFalse(retry._collect_release_allowed({"state": "running"}))
        self.assertTrue(retry._collect_release_allowed({"state": "complete", "terminalValidated": True}))

    def test_mcp_route_rejects_extra_native_inputs(self):
        request = {"host": "archlinux", "device": "api29", "correlationId": "c", "artifactId": "a",
                   "cliStageCorrelationId": "s", "openingReadbackCorrelationId": "r",
                   "expectedBackupSha256": "b", "expectedOwner": "o", "expectedRevision": 1}
        with mock.patch.object(retry, "start", return_value={"ok": True, "state": "submitted"}) as start:
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-retry-start", {**request, "shell": "id"})["ok"])
            self.assertTrue(mcp_server._vm_workflow_impl("android-document-retry-start", request)["ok"])
            start.assert_called_once()
        with mock.patch.object(retry, "status", return_value={"ok": True, "state": "running"}) as status:
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-retry-status", {"correlationId": "c", "host": "archlinux"})["ok"])
            self.assertTrue(mcp_server._vm_workflow_impl("android-document-retry-status", {"correlationId": "c"})["ok"])
            status.assert_called_once()

    def test_remote_status_rejects_forged_new_request_terminal(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            os.chmod(base, 0o700)
            correlation = "cafecafe-cafe-4afe-8afe-cafecafecafe"
            job = base / ("android-document-retry-job-" + correlation)
            job.mkdir(mode=0o700)
            intent = retry._test_intent() | {"correlationId": correlation, "fixtureRoot": str(base)}
            forged = retry._test_result(intent)
            forged["retry"]["requestId"] = "fresh-cli-request"
            def write(name, value):
                path = job / name
                path.write_text(json.dumps(value))
                os.chmod(path, 0o600)
            write("intent.json", intent)
            write("identity.json", {"pid": 1234, "startTicks": 1})
            write("result.json", {"state": "complete", "result": forged})
            output = subprocess.run([sys.executable, "-I", "-B", "-c", retry._STATUS,
                                     str(base), correlation, json.dumps(intent, sort_keys=True, separators=(",", ":"))],
                                    capture_output=True, check=True, text=True, timeout=5)
            observed = json.loads(output.stdout)
            self.assertEqual(observed["state"], "unknown")
            self.assertEqual(observed["reason"], "terminal_binding_invalid")

    def test_public_cli_uses_canonical_android_environment(self):
        module = ast.parse(retry._REMOTE)
        definition = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "public")
        scope = {"cli": "/cli", "serial": "serial", "environment": {"ANDROID_HOME": "/sdk"},
                 "json": json, "fail": lambda reason: self.fail(reason)}
        observed = []
        def invoke(*args, **kwargs):
            observed.append((args, kwargs))
            return '{"ok":true}'
        scope["invoke"] = invoke
        exec(compile(ast.Module(body=[definition], type_ignores=[]), "<public>", "exec"), scope)
        self.assertEqual(scope["public"]("status"), {"ok": True})
        self.assertEqual(observed[0][1].get("env"), {"ANDROID_HOME": "/sdk"})

    def test_real_shaped_readback_collect_admits_without_wrapper_only_field(self):
        correlation = "11111111-1111-4111-8111-111111111111"
        root = Path("/private/fixture")
        package = "a" * 64
        backup = "b" * 64
        owner = "22222222-2222-4222-8222-222222222222"
        value = {"ok": True, "state": "complete", "result": {
            "package": {"baseSha256": package},
            "guard": {"controllerId": owner, "configurationRevision": 1, "backupSha256": backup},
            "backup": {"sha256": backup, "size": 239,
                       "path": str(root / ("android-readback-" + correlation) / "routing.json")},
            "device": {"uid": "2000", "api": 29, "avd": "avd"}, "reverseInventory": []}}
        intent = {"host": "archlinux", "device": "api29"}
        self.assertTrue(retry._opening_valid(value, intent, "archlinux", "api29", package,
                                             owner, 1, backup, "avd", root, correlation))
        self.assertFalse(retry._opening_valid({**value, "state": "unknown"}, intent, "archlinux", "api29", package,
                                              owner, 1, backup, "avd", root, correlation))

    def test_foreign_shared_lease_blocks_before_remote_submission(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = "11111111-1111-4111-8111-111111111111"
            attempt = "22222222-2222-4222-8222-222222222222"
            android_installer_dispatch._claim_local(root, "archlinux", "api29", existing, "android-endpoint")
            with mock.patch.object(android_installer_dispatch, "remote_shared_lease") as remote:
                with self.assertRaises(FileExistsError):
                    retry._claim_shared(root, "archlinux", "api29", attempt)
                remote.assert_not_called()
            self.assertEqual(android_installer_dispatch._lease_value("android-endpoint", "archlinux", "api29", existing),
                             json.loads(android_installer_dispatch.android_installer_target._private_file(
                                 android_installer_dispatch._shared_directory(root) / "lease-archlinux-api29.json", 1024)))

    def test_recovery_only_targets_unknown_original_retry_job(self):
        unknown = "11111111-1111-4111-8111-111111111111"
        original = {"host": "archlinux", "device": "api29", "expectedOwner": "owner",
                    "expectedRevision": 1, "correlationId": unknown}
        observed = {"state": "unknown", "reason": "document_outcome_unknown",
                    "identity": {"pid": 123, "startTicks": 456}}
        self.assertTrue(retry._recovery_original_valid(original, observed, "archlinux", "api29", "owner", 2, unknown))
        self.assertFalse(retry._recovery_original_valid(original, {**observed, "state": "running"}, "archlinux", "api29", "owner", 2, unknown))
        self.assertFalse(retry._recovery_original_valid(original, observed, "archlinux", "api29", "foreign", 2, unknown))
        remote, preserved, terminal = retry._recovery_sources()
        self.assertIn('"android-document-retry-job-"', remote)
        self.assertIn('"android-document-retry-job-"', preserved)
        self.assertIn('"android-document-retry-job-"', terminal)

    def test_recovery_mcp_route_is_exact_and_read_only_observation(self):
        request = {"host": "archlinux", "device": "api29", "recoveryCorrelationId": "r",
                   "unknownRetryCorrelationId": "u", "openingReadbackCorrelationId": "o",
                   "currentReadbackCorrelationId": "c", "artifactId": "a",
                   "cliStageCorrelationId": "s", "expectedOwner": "e", "expectedRevision": 2}
        with mock.patch.object(retry, "recovery_start", return_value={"ok": True, "state": "submitted"}) as start:
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-retry-recovery-start", {**request, "shell": "id"})["ok"])
            self.assertTrue(mcp_server._vm_workflow_impl("android-document-retry-recovery-start", request)["ok"])
            start.assert_called_once()
        with mock.patch.object(retry, "recovery_status", return_value={"ok": True, "state": "running"}) as status:
            self.assertTrue(mcp_server._vm_workflow_impl("android-document-retry-recovery-status", {"recoveryCorrelationId": "r"})["ok"])
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-retry-recovery-status", {"recoveryCorrelationId": "r", "host": "archlinux"})["ok"])
            status.assert_called_once()

    def test_recovery_requires_exact_current_fixture_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.chmod(root, 0o700)
            unknown = "11111111-1111-4111-8111-111111111111"
            current = "22222222-2222-4222-8222-222222222222"
            fixture_dir = root / ("android-document-retry-job-" + unknown)
            current_dir = root / ("android-readback-" + current)
            fixture_dir.mkdir(mode=0o700)
            current_dir.mkdir(mode=0o700)
            def document(rules):
                return json.dumps({"type": "vpn_control_routing_rules", "version": 7,
                                   "rules": rules}).encode()
            fixture = document({"direct_domain_suffixes": ["fixture.test"]})
            candidate = document({"direct_domain_suffixes": ["foreign.test"]})
            fpath = fixture_dir / "routing-v7-56000.json"
            cpath = current_dir / "routing.json"
            fpath.write_bytes(fixture); cpath.write_bytes(candidate)
            os.chmod(fpath, 0o600); os.chmod(cpath, 0o600)
            def observe(data):
                output = subprocess.run([sys.executable, "-I", "-B", "-c", retry._RECOVERY_CURRENT_PROOF,
                    str(root), unknown, current, hashlib.sha256(fixture).hexdigest(), str(len(fixture)),
                    hashlib.sha256(data).hexdigest(), str(len(data))], capture_output=True, text=True,
                    check=True, timeout=5)
                return json.loads(output.stdout)["ready"]
            self.assertFalse(observe(candidate))
            cpath.write_bytes(fixture)
            self.assertTrue(observe(fixture))
            fixture = document({"ignore_rules": False})
            candidate = document({"ignore_rules": 0})
            fpath.write_bytes(fixture); cpath.write_bytes(candidate)
            self.assertFalse(observe(candidate))

    def test_terminal_requires_durable_identical_distinct_transfer_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); os.chmod(root, 0o700)
            correlation = "11111111-1111-4111-8111-111111111111"
            job = root / ("android-document-retry-job-" + correlation)
            job.mkdir(mode=0o700)
            opening = b"x" * 239
            fixture = b"fixture"
            intent = retry._test_intent() | {"correlationId": correlation, "fixtureRoot": str(root),
                "backupSha256": hashlib.sha256(opening).hexdigest(),
                "fixtureSha256": hashlib.sha256(fixture).hexdigest(), "fixtureSize": len(fixture),
                "requestSha256": "c" * 64}
            result = retry._test_result(intent)
            def write(name, data):
                path = job / name
                path.write_bytes(data)
                os.chmod(path, 0o600)
            write("intent.json", json.dumps(intent).encode())
            write("identity.json", json.dumps({"pid": 1234, "startTicks": 1}).encode())
            write("result.json", json.dumps({"state": "complete", "result": result}).encode())
            write("opening-routing.json", opening)
            write("routing-v7-56000.json", fixture)
            def state():
                output = subprocess.run([sys.executable, "-I", "-B", "-c", retry._STATUS,
                    str(root), correlation, json.dumps(intent, sort_keys=True, separators=(",", ":"))],
                    capture_output=True, check=True, text=True, timeout=5)
                return json.loads(output.stdout)["state"]
            self.assertEqual(state(), "unknown")
            original_hash = "c" * 64
            for name, transfer in (("first", "33333333-3333-4333-8333-333333333333"),
                                   ("retry", "44444444-4444-4444-8444-444444444444")):
                write("transfer-" + name + ".json", json.dumps({"requestId": intent["requestId"],
                    "controllerId": intent["expectedOwner"], "transferId": transfer,
                    "payloadSha256": original_hash}).encode())
            write("transfer-conflict.json", json.dumps({"requestId": intent["requestId"],
                "controllerId": intent["expectedOwner"], "transferId": "55555555-5555-4555-8555-555555555555",
                "payloadSha256": "d" * 64}).encode())
            self.assertEqual(state(), "complete")
            write("transfer-retry.json", json.dumps({"requestId": intent["requestId"],
                "controllerId": intent["expectedOwner"], "transferId": "44444444-4444-4444-8444-444444444444",
                "payloadSha256": "e" * 64}).encode())
            self.assertEqual(state(), "unknown")

    def test_closing_semantic_rejects_boolean_integer_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); os.chmod(root, 0o700)
            first = "11111111-1111-4111-8111-111111111111"
            last = "22222222-2222-4222-8222-222222222222"
            def saved(correlation, rule):
                directory = root / ("android-readback-" + correlation)
                directory.mkdir(mode=0o700)
                raw = json.dumps({"type": "vpn_control_routing_rules", "version": 7,
                                  "rules": {"ignore_rules": rule}}).encode()
                path = directory / "routing.json"
                path.write_bytes(raw); os.chmod(path, 0o600)
                return hashlib.sha256(raw).hexdigest(), len(raw)
            left = saved(first, False)
            right = saved(last, 0)
            output = subprocess.run([sys.executable, "-I", "-B", "-c", retry._closing_semantic_source(),
                str(root), first, last, left[0], str(left[1]), right[0], str(right[1])],
                capture_output=True, check=True, text=True, timeout=5)
            self.assertFalse(json.loads(output.stdout)["same"])

    def test_recovery_release_reconciles_lost_response_but_rejects_foreign_lease(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old = "11111111-1111-4111-8111-111111111111"
            foreign = "22222222-2222-4222-8222-222222222222"
            android_document_retry = retry.android_document_acceptance
            android_document_retry._claim_device(root, "archlinux", "api29", old)
            android_installer_dispatch._claim_local(root, "archlinux", "api29", old, "android-document-retry")
            with mock.patch.object(android_installer_dispatch, "remote_shared_lease", return_value={"state": "released"}):
                self.assertTrue(retry._release_recovery_leases(root, "archlinux", "api29", old))
                self.assertTrue(retry._release_recovery_leases(root, "archlinux", "api29", old))
                android_installer_dispatch._claim_local(root, "archlinux", "api29", foreign, "android-endpoint")
                self.assertFalse(retry._release_recovery_leases(root, "archlinux", "api29", old))


if __name__ == "__main__":
    unittest.main()
