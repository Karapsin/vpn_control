from __future__ import annotations

import json
import base64
import contextlib
import io
import os
import subprocess
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_msi_owner_observe as owner


CORR = "dfd7b629-0a97-4c1c-a37c-2da5671b0533"
CONTROLLER = "d1040a53-ccaf-4f26-9a1b-76d910d4255f"
REQUEST = {"host": "archlinux", "correlationId": CORR, "sourceSha": "a" * 40,
           "controllerId": CONTROLLER, "installedCliSha256": "b" * 64,
           "parentPid": 3640, "parentStartedAtUtc": "2026-09-25T10:18:47.4249100Z",
           "childPid": 5520, "childStartedAtUtc": "2026-09-25T10:18:47.7734480Z"}
INTENT = {"request": REQUEST, "expectedSid": "S-1-5-21-1-2-3-1002"}


class OwnerObserveTests(unittest.TestCase):
    def test_exact_input_and_generations(self):
        self.assertEqual(owner._request(REQUEST), REQUEST)
        with self.assertRaises(owner.WindowsMsiOwnerObserveError):
            owner._request(dict(REQUEST, childPid=3640))
        with self.assertRaises(owner.WindowsMsiOwnerObserveError):
            owner._request(dict(REQUEST, controllerId="wrong"))

    def test_absent_endpoint_blocks_without_owner_start(self):
        payload = {"state": "observed", "correlationId": CORR, "result": {"version": 1,
            "correlationId": CORR, "code": "ENDPOINT_ABSENT", "originalSid": INTENT["expectedSid"],
            "sessionId": 1, "limited": True, "snapshot": None}}
        result = owner._classify(json.dumps(payload).encode(), CORR, INTENT)
        self.assertEqual(result["state"], "blocked")
        self.assertFalse(result["ownerStarted"])
        self.assertFalse(result["replayAllowed"])
        script = owner._task(CORR, REQUEST, INTENT["expectedSid"])
        self.assertIn("if(-not [IO.File]::Exists($endpointPath))", script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("& $cli", script)

    def test_endpoint_private_file_is_admitted_before_credential_read(self):
        script = owner._task(CORR, REQUEST, INTENT["expectedSid"])
        self.assertIn("$file.Length -gt 4096", script)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", script)
        self.assertIn("$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value", script)
        self.assertIn("$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])", script)
        self.assertIn("$rule.IdentityReference.Value -cne", script)
        self.assertIn("$ownerRead", script)
        self.assertIn("$bytes.Length -gt 4096", script)
        self.assertLess(script.index("$acl.GetOwner"), script.index("$bytes=[IO.File]::ReadAllBytes"))
        self.assertLess(script.index("$bytes.Length -gt 4096"), script.index("ConvertFrom-Json -InputObject"))

    def test_ps5_preflight_parses_each_fixed_component_within_qga_bound(self):
        for kind in ("task", "bootstrap", "cleanup"):
            encoded = base64.b64encode(owner._powershell_preflight_script(kind).encode("utf-16le"))
            self.assertLess(len(encoded), 30000)
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(owner.windows_msi_base_prepare, "_descriptor", return_value=(object(), object(),
                ("windows-cp117", "/qga.sock", 589342, 520739, INTENT["expectedSid"]))), \
             patch.object(owner.windows_credential_probe_ssh, "_run_ssh",
                          side_effect=[b'{"state":"passed"}'] * 3) as remote:
            self.assertEqual(owner.powershell_preflight(directory, {"host": "archlinux"}),
                             {"state": "passed", "productAction": False})
            self.assertEqual(remote.call_count, 3)

    def test_controller_and_runtime_snapshot_binding(self):
        snapshot = {"controllerId": CONTROLLER, "runtimeRunning": False,
                    "configuredMode": "vpn", "activeMode": None,
                    "selectedLocationId": "a" * 64, "activeLocationId": None}
        result = {"version": 1, "correlationId": CORR, "code": "OBSERVED",
                  "originalSid": INTENT["expectedSid"], "sessionId": 1, "limited": True, "snapshot": snapshot}
        raw = json.dumps({"state": "observed", "correlationId": CORR, "result": result}).encode()
        self.assertEqual(owner._classify(raw, CORR, INTENT)["runtimeRunning"], False)
        bad = dict(result, snapshot=dict(snapshot, controllerId="00000000-0000-4000-8000-000000000000"))
        self.assertEqual(owner._classify(json.dumps({"state": "observed", "correlationId": CORR, "result": bad}).encode(), CORR, INTENT)["state"], "unknown")
        for bad_result in (dict(result, version=True), dict(result, sessionId=True),
                           dict(result, snapshot=dict(snapshot, selectedLocationId="arbitrary")),
                           dict(result, snapshot=dict(snapshot, activeMode=[]))):
            encoded = json.dumps({"state": "observed", "correlationId": CORR, "result": bad_result}).encode()
            self.assertEqual(owner._classify(encoded, CORR, INTENT)["state"], "unknown")

    def test_unknown_owner_result_has_only_bounded_stage_diagnostic(self):
        remote = json.dumps({"state": "unknown", "correlationId": CORR,
                             "diagnostic": "BOOTSTRAP_EXIT"}).encode()
        self.assertEqual(owner._classify(remote, CORR, INTENT)["diagnostic"], "BOOTSTRAP_EXIT")
        lost = json.dumps({"state": "unknown", "correlationId": CORR,
                           "diagnostic": "BOOTSTRAP_STATUS_TASK_UNKNOWN"}).encode()
        self.assertEqual(owner._classify(lost, CORR, INTENT)["diagnostic"],
                         "BOOTSTRAP_STATUS_TASK_UNKNOWN")
        injected = json.dumps({"state": "unknown", "correlationId": CORR,
                               "diagnostic": "secret owner output"}).encode()
        self.assertNotIn("diagnostic", owner._classify(injected, CORR, INTENT))
        task_result = {"version": 1, "correlationId": CORR, "code": "UNKNOWN",
                       "originalSid": INTENT["expectedSid"], "sessionId": 1,
                       "limited": True, "snapshot": None}
        observed = json.dumps({"state": "observed", "correlationId": CORR,
                               "result": task_result}).encode()
        self.assertEqual(owner._classify(observed, CORR, INTENT)["diagnostic"], "TASK_UNKNOWN")
        staged = dict(task_result, code="UNKNOWN_ENDPOINT_ACL")
        staged_raw = json.dumps({"state": "observed", "correlationId": CORR,
                                 "result": staged}).encode()
        self.assertEqual(owner._classify(staged_raw, CORR, INTENT)["diagnostic"],
                         "TASK_UNKNOWN_ENDPOINT_ACL")
        script = owner._task(CORR, REQUEST, INTENT["expectedSid"])
        self.assertIn("$stage='ENDPOINT_ACL'", script)
        self.assertIn("P ('UNKNOWN_'+$stage) $null", script)
        self.assertNotIn("$_.Exception.Message", script)

    def test_one_local_intent_prevents_submission_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            owner._reserve(root, INTENT)
            self.assertEqual(owner._read_intent(root, CORR), INTENT)
            with self.assertRaises(owner.WindowsMsiOwnerObserveError):
                owner._reserve(root, dict(INTENT, request=dict(REQUEST, correlationId="13416223-825b-4b75-8da5-ce3c51cc331a")))

    def test_new_intent_requires_closed_prior_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = dict(INTENT, commandSha256="c" * 64)
            next_corr = "13416223-825b-4b75-8da5-ce3c51cc331a"
            next_record = dict(previous, request=dict(REQUEST, correlationId=next_corr))
            owner._reserve(root, previous)
            with self.assertRaises(owner.WindowsMsiOwnerObserveError):
                owner._reserve(root, next_record)
            closed = root / owner._GROUP / (CORR + ".closed.json")
            closed.write_text(json.dumps({"correlationId": CORR,
                "commandSha256": previous["commandSha256"], "state": "cleaned"}), encoding="utf-8")
            closed.chmod(0o600)
            cleanup = root / owner._GROUP / (CORR + ".cleanup.json")
            cleanup.write_text(json.dumps({"correlationId": CORR,
                "commandSha256": previous["commandSha256"]}), encoding="utf-8")
            cleanup.chmod(0o600)
            owner._reserve(root, next_record)

    def test_orphan_closed_receipt_does_not_bypass_environment_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            group = root / owner._GROUP
            group.mkdir(parents=True, mode=0o700)
            (group / (CORR + ".closed.json")).write_text("{}", encoding="utf-8")
            with self.assertRaises(owner.WindowsMsiOwnerObserveError):
                owner._reserve(root, dict(INTENT, commandSha256="c" * 64))

    def test_prior_closure_requires_exact_remote_cleanup_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = dict(INTENT, environment="windows-cp117", socketPath="/qga.sock",
                            pid=589342, startTicks=520739, commandSha256="c" * 64)
            owner._reserve(root, previous)
            marker = root / owner._GROUP / (CORR + ".cleanup.json")
            marker.write_text(json.dumps({"correlationId": CORR,
                "commandSha256": previous["commandSha256"]}), encoding="utf-8")
            marker.chmod(0o600)
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            descriptor = ("windows-cp117", "/qga.sock", 589342, 520739, INTENT["expectedSid"])
            with patch.object(owner.windows_msi_base_prepare, "_remote",
                              return_value=b'{"state":"unknown"}'):
                with self.assertRaises(owner.WindowsMsiOwnerObserveError):
                    owner._close_prior(root, object(), Target(), descriptor)
            self.assertFalse(owner._closed_marker(root, CORR).exists())
            with patch.object(owner.windows_msi_base_prepare, "_remote",
                              return_value=json.dumps({"state": "cleaned", "correlationId": CORR}).encode()) as remote:
                owner._close_prior(root, object(), Target(), descriptor)
                self.assertIs(remote.call_args.args[1], owner._REMOTE_CLEANUP_STATUS)
            self.assertEqual(owner._read_private_json(owner._closed_marker(root, CORR)),
                             {"correlationId": CORR, "commandSha256": "c" * 64, "state": "cleaned"})

    def test_remote_group_admits_only_exact_cleaned_prior_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            group = Path(directory) / "windows-msi-owner-observe"
            prior = group / CORR
            prior.mkdir(parents=True, mode=0o700)
            prior.chmod(0o700)
            binding = {"socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                       "sourceSha": REQUEST["sourceSha"], "artifactIds": [], "commandSha256": "c" * 64}
            (prior / "binding.json").write_text(json.dumps(binding), encoding="utf-8")
            task = "VpnControlMcpOwnerObserve-" + CORR
            (prior / "cleanup-intent.json").write_text(json.dumps({"correlationId": CORR,
                "taskName": task}), encoding="utf-8")
            def safe_dir(path):
                info = os.lstat(path)
                return stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and \
                    stat.S_IMODE(info.st_mode) == 0o700
            def admit():
                exec(owner._REMOTE_CLOSED_CHECK.strip(), {"group": str(group), "os": os,
                    "json": json, "safe_dir": safe_dir})
            with self.assertRaises(FileNotFoundError): admit()
            result = prior / "cleanup-result.json"
            result.write_text(json.dumps({"version": 1, "correlationId": CORR,
                "state": "cleaned", "taskName": task}), encoding="utf-8")
            admit()
            result.write_text(json.dumps({"version": 1, "correlationId": CORR,
                "state": "cleaned", "taskName": "another-task"}), encoding="utf-8")
            with self.assertRaises(ValueError): admit()
            self.assertIn(owner._REMOTE_CLOSED_CHECK.strip(), owner._REMOTE_START)

    def test_lost_cleanup_response_never_resubmits_task_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = dict(INTENT, environment="windows-cp117", socketPath="/qga.sock",
                          pid=589342, startTicks=520739, commandSha256="c" * 64)
            owner._reserve(root, intent)
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            observation = {"state": "blocked", "correlationId": CORR,
                           "code": "ENDPOINT_ABSENT", "ownerStarted": False, "replayAllowed": False}
            with patch.object(owner, "status", return_value=observation), \
                 patch.object(owner.windows_msi_base_prepare, "_descriptor", return_value=(object(), Target(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, INTENT["expectedSid"]))), \
                 patch.object(owner.windows_msi_base_prepare, "_remote", side_effect=[None,
                    json.dumps({"state": "cleaned", "correlationId": CORR}).encode()]) as remote:
                first = owner.collect(root, {"correlationId": CORR})
                second = owner.collect(root, {"correlationId": CORR})
                self.assertEqual(first["cleanupState"], "unknown")
                self.assertEqual(second["cleanupState"], "complete")
                self.assertIs(remote.call_args_list[0].args[1], owner._REMOTE_CLEANUP)
                self.assertIs(remote.call_args_list[1].args[1], owner._REMOTE_CLEANUP_STATUS)

    def test_unknown_task_result_can_clean_exact_task_without_replaying_observer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intent = dict(INTENT, environment="windows-cp117", socketPath="/qga.sock",
                          pid=589342, startTicks=520739, commandSha256="c" * 64)
            owner._reserve(root, intent)
            class Target:
                fixture_transfer_root = Path("/private/cp117")
            observation = {"state": "unknown", "correlationId": CORR,
                           "diagnostic": "BOOTSTRAP_STATUS_TASK_UNKNOWN", "replayAllowed": False}
            with patch.object(owner, "status", return_value=observation), \
                 patch.object(owner.windows_msi_base_prepare, "_descriptor", return_value=(object(), Target(),
                    ("windows-cp117", "/qga.sock", 589342, 520739, INTENT["expectedSid"]))), \
                 patch.object(owner.windows_msi_base_prepare, "_remote",
                              return_value=json.dumps({"state": "cleaned", "correlationId": CORR}).encode()) as remote:
                result = owner.collect(root, {"correlationId": CORR})
                self.assertEqual(result["state"], "unknown")
                self.assertEqual(result["cleanupState"], "complete")
                self.assertIs(remote.call_args.args[1], owner._REMOTE_CLEANUP)
                self.assertEqual(remote.call_args.args[2][-2:], (INTENT["expectedSid"], "UNKNOWN"))

    def test_cleanup_admission_binds_terminal_code_and_root_task_path(self):
        script = owner._REMOTE_CLEANUP
        self.assertIn("terminal['code']!=expected_code", script)
        self.assertLess(script.index("terminal['code']!=expected_code"),
                        script.index("marker=os.path.join(stage,'cleanup-intent.json')"))
        self.assertIn("os.fsync(stage_fd)", script)
        self.assertIn("-TaskPath '\\' -TaskName $name", owner._cleanup_task_script(CORR))
        self.assertIn("$task.State -ne 'Ready'", owner._cleanup_task_script(CORR))
        self.assertNotIn("$task.State -eq 'Running'", owner._cleanup_task_script(CORR))
        bootstrap = owner._bootstrap(CORR, REQUEST, INTENT["expectedSid"])
        self.assertIn("Register-ScheduledTask -TaskPath '\\'", bootstrap)

    def test_cleanup_readback_requires_exact_terminal_receipt_and_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "windows-cp117" / "windows-msi-owner-observe" / CORR
            stage.mkdir(parents=True, mode=0o700)
            stage.chmod(0o700)
            source, command = "a" * 40, "c" * 64
            def readback():
                result = subprocess.run(["python3", "-c", owner._REMOTE_CLEANUP_STATUS,
                    directory, "windows-cp117", CORR, source, command],
                    capture_output=True, check=True, text=True, timeout=5)
                return json.loads(result.stdout)
            self.assertEqual(readback()["state"], "unknown")
            (stage / "binding.json").write_text(json.dumps({"sourceSha": source,
                "commandSha256": command}), encoding="utf-8")
            (stage / "cleanup-intent.json").write_text(json.dumps({"correlationId": CORR,
                "taskName": "VpnControlMcpOwnerObserve-" + CORR}), encoding="utf-8")
            self.assertEqual(readback()["state"], "unknown")
            receipt = stage / "cleanup-result.json"
            receipt.write_text(json.dumps({"version": 1, "correlationId": CORR,
                "state": "cleaned", "taskName": "VpnControlMcpOwnerObserve-" + CORR}), encoding="utf-8")
            self.assertEqual(readback()["state"], "cleaned")
            receipt.write_text(json.dumps({"version": 1, "correlationId": CORR,
                "state": "cleaned", "taskName": "other"}), encoding="utf-8")
            self.assertEqual(readback()["state"], "unknown")

    def test_terminal_qga_status_is_journaled_before_later_task_read(self):
        with tempfile.TemporaryDirectory() as directory:
            stage = Path(directory) / "windows-cp117" / "windows-msi-owner-observe" / CORR
            stage.mkdir(parents=True, mode=0o700)
            stage.chmod(0o700)
            binding = {"socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                       "sourceSha": REQUEST["sourceSha"], "artifactIds": [], "commandSha256": "c" * 64}
            (stage / "binding.json").write_text(json.dumps(binding), encoding="utf-8")
            (stage / "dispatch.json").write_text(json.dumps({"pid": 1234}), encoding="utf-8")
            result_path = ("C:\\Users\\vpncp117\\AppData\\Local\\VpnControl\\mcp-owner-observe-"
                           + CORR + "\\result.json")
            files = {}
            bootstrap = json.dumps({"version": 1, "correlationId": CORR,
                                    "taskName": "VpnControlMcpOwnerObserve-" + CORR,
                                    "triggered": True}).encode()
            class FakeSocket:
                status_calls = 0
                next_handle = 1
                handles = {}
                def __init__(self, *args, **kwargs): self.data = bytearray()
                def settimeout(self, value): pass
                def connect(self, value): pass
                def close(self): pass
                def sendall(self, raw):
                    if raw.startswith(b"\xff"):
                        request = json.loads(raw[1:])
                        self.data.extend(b"\xff" + json.dumps({"return": request["arguments"]["id"]}).encode() + b"\n")
                        return
                    request = json.loads(raw)
                    command, args = request["execute"], request["arguments"]
                    if command == "guest-exec-status":
                        FakeSocket.status_calls += 1
                        reply = {"return": {"exited": True, "exitcode": 0,
                                            "out-data": base64.b64encode(bootstrap).decode()}}
                    elif command == "guest-file-open":
                        content = files.get(args["path"])
                        if content is None: reply = {"error": {"class": "GenericError"}}
                        else:
                            handle = FakeSocket.next_handle; FakeSocket.next_handle += 1
                            FakeSocket.handles[handle] = content
                            reply = {"return": handle}
                    elif command == "guest-file-read":
                        content = FakeSocket.handles[args["handle"]]
                        reply = {"return": {"count": len(content),
                                            "buf-b64": base64.b64encode(content).decode(), "eof": True}}
                    else: reply = {"return": {}}
                    self.data.extend(json.dumps(reply).encode() + b"\n")
                def recv(self, size):
                    take = min(size, len(self.data))
                    raw = bytes(self.data[:take]); del self.data[:take]
                    return raw
            argv = ["status", directory, "windows-cp117", CORR, "/qga.sock", "589342", "520739",
                    REQUEST["sourceSha"], "c" * 64]
            code = owner._REMOTE_STATUS.replace("if not live(sock,pid,ticks):raise ValueError()",
                                                "if False:raise ValueError()")
            def readback():
                output = io.StringIO()
                with patch("socket.socket", FakeSocket), patch.object(sys, "argv", argv), \
                     contextlib.redirect_stdout(output):
                    try: exec(code, {"__name__": "__main__"})
                    except SystemExit as exited:
                        if exited.code != 0: raise
                return json.loads(output.getvalue())
            self.assertEqual(readback()["state"], "running")
            self.assertEqual(FakeSocket.status_calls, 1)
            receipt = json.loads((stage / "bootstrap-result.json").read_text())
            self.assertEqual(receipt, {"version": 1, "correlationId": CORR,
                                       "pid": 1234, "state": "accepted", "code": "ACCEPTED"})
            files[result_path] = b"\xef\xbb\xbf" + json.dumps({"version": 1, "correlationId": CORR,
                "code": "UNKNOWN", "originalSid": INTENT["expectedSid"], "sessionId": 1,
                "limited": True, "snapshot": None}).encode()
            second = readback()
            self.assertEqual(second["state"], "observed", second)
            self.assertEqual(FakeSocket.status_calls, 1)

    def test_rejected_terminal_qga_receipt_keeps_exact_stage_without_requery(self):
        for expected, process in (("BOOTSTRAP_EXIT", {"exited": True, "exitcode": 1}),
                                  ("BOOTSTRAP_OUTPUT", {"exited": True, "exitcode": 0,
                                                        "out-data": base64.b64encode(b"not-json").decode()})):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                stage = Path(directory) / "windows-cp117" / "windows-msi-owner-observe" / CORR
                stage.mkdir(parents=True, mode=0o700)
                stage.chmod(0o700)
                binding = {"socketPath": "/qga.sock", "pid": 589342, "startTicks": 520739,
                           "sourceSha": REQUEST["sourceSha"], "artifactIds": [], "commandSha256": "c" * 64}
                (stage / "binding.json").write_text(json.dumps(binding), encoding="utf-8")
                (stage / "dispatch.json").write_text(json.dumps({"pid": 1234}), encoding="utf-8")
                calls = []
                def one_shot_status():
                    calls.append(True)
                    if len(calls) != 1: raise AssertionError("Terminal QGA status was replayed")
                    return process
                code = owner._REMOTE_STATUS.replace("if not live(sock,pid,ticks):raise ValueError()",
                                                    "if False:raise ValueError()")
                code = code.replace("process=call(sock,'guest-exec-status',{'pid':dispatch['pid']})",
                                    "process=one_shot_status()")
                argv = ["status", directory, "windows-cp117", CORR, "/qga.sock", "589342", "520739",
                        REQUEST["sourceSha"], "c" * 64]
                def readback():
                    output = io.StringIO()
                    with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                        exec(code, {"__name__": "__main__", "one_shot_status": one_shot_status})
                    return json.loads(output.getvalue())
                first = readback()
                self.assertEqual(first["diagnostic"], expected)
                receipt = json.loads((stage / "bootstrap-result.json").read_text())
                self.assertEqual(receipt, {"version": 1, "correlationId": CORR,
                                           "pid": 1234, "state": "rejected", "code": expected})
                self.assertEqual(readback()["diagnostic"], expected)
                self.assertEqual(len(calls), 1)


if __name__ == "__main__": unittest.main()
