#!/usr/bin/env python3
"""Fast checks for strict packaged CLI output verification (not native evidence)."""
import json
import io
import os
import ast
import base64
import hashlib
import re
import shutil
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from test_packaged_cli import (envelope, stream_records, verify_stream_records, interrupt_stream,
                               large_routing_fixture, verify_routing_export, implicit_owner_smoke, smoke)


class StaticLaunchFailureTest(unittest.TestCase):
    def test_unexpected_json_exit_preserves_failure_identity_without_payload(self):
        response = dict(schemaVersion=1, controllerId="fixture-owner", requestId="fixture-request",
                        operationId="fixture-operation", code="OUTCOME_UNKNOWN", final=False,
                        configurationRevision=7, message="PRIVATE_MESSAGE",
                        data={"content": "PRIVATE_DOCUMENT"})
        result = subprocess.CompletedProcess([], 2, json.dumps(response), "")
        with self.assertRaises(AssertionError) as failure:
            envelope(result)
        message = str(failure.exception)
        for expected in ("OUTCOME_UNKNOWN", "fixture-owner", "fixture-request", "fixture-operation"):
            self.assertIn(expected, message)
        self.assertNotIn("PRIVATE", message)

    def test_unexpected_exit_diagnostics_are_bounded_for_malformed_output(self):
        result = subprocess.CompletedProcess([], 2, "PRIVATE_DOCUMENT" * 10000, "failure " * 10000)
        with self.assertRaises(AssertionError) as failure:
            envelope(result)
        message = str(failure.exception)
        self.assertIn("CLI exit 2", message)
        self.assertIn("stdout", message)
        self.assertNotIn("PRIVATE_DOCUMENT", message)
        self.assertLess(len(message), 6000)

    def test_serve_failure_preserves_exit_and_bounded_owner_output(self):
        def invoke(arguments, **kwargs):
            if "--help" in arguments:
                return subprocess.CompletedProcess(arguments, 0, "Usage:", "")
            if "--version" in arguments:
                return subprocess.CompletedProcess(arguments, 0, "2.1.4", "")
            code, status = (1, "INVALID_ARGUMENT") if "--typo" in arguments else (
                (2, "UNAVAILABLE") if "status" in arguments else (0, "OK"))
            return subprocess.CompletedProcess(arguments, code, json.dumps({
                "schemaVersion": 1, "code": status, "ok": code == 0}), "")

        def start(arguments, **kwargs):
            kwargs["stderr"].write(b"owner bootstrap failed " + b"x" * 10000)
            kwargs["stderr"].flush()
            return mock.Mock(poll=mock.Mock(return_value=2))

        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "launcher"
            launcher.touch()
            with mock.patch("test_packaged_cli.subprocess.run", side_effect=invoke), \
                    mock.patch("test_packaged_cli.subprocess.Popen", side_effect=start):
                with self.assertRaises(AssertionError) as failure:
                    smoke(launcher, "2.1.4")
        message = str(failure.exception)
        self.assertIn("Serve did not become ready", message)
        self.assertIn("exit=2", message)
        self.assertIn("owner bootstrap failed", message)
        self.assertLess(len(message), 9000)

    def test_windows_failure_collects_admission_evidence_without_replacing_failure(self):
        result = subprocess.CompletedProcess([], 2, "", "UNAVAILABLE\n")
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "launcher"
            launcher.touch()
            with mock.patch("test_packaged_cli.subprocess.run", return_value=result), \
                    mock.patch("test_packaged_cli.sys.platform", "win32"), \
                    mock.patch.dict(os.environ, {"JAVA_HOME": directory}), \
                    mock.patch("windows_install_admission_diagnostic.diagnose", return_value={
                        "schemaVersion": 1, "admission": "rejected", "failure": {"nativeCode": 5}
                    }) as diagnose, mock.patch("test_packaged_cli.sys.stderr", new_callable=io.StringIO) as errors:
                with self.assertRaisesRegex(AssertionError, "Help must exit 0.*exit=2"):
                    smoke(launcher, "2.1.4")
                diagnose.assert_called_once_with(launcher.resolve(), directory)
                self.assertIn('"nativeCode": 5', errors.getvalue())

    def test_diagnostic_failure_keeps_original_launcher_evidence(self):
        result = subprocess.CompletedProcess([], 2, "", "UNAVAILABLE\n")
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "launcher"
            launcher.touch()
            with mock.patch("test_packaged_cli.subprocess.run", return_value=result), \
                    mock.patch("test_packaged_cli.sys.platform", "win32"), \
                    mock.patch.dict(os.environ, {"JAVA_HOME": directory}), \
                    mock.patch("windows_install_admission_diagnostic.diagnose", side_effect=RuntimeError("private detail")), \
                    mock.patch("test_packaged_cli.sys.stderr", new_callable=io.StringIO) as errors:
                with self.assertRaisesRegex(AssertionError, "Help must exit 0.*UNAVAILABLE"):
                    smoke(launcher, "2.1.4")
                self.assertIn("RuntimeError", errors.getvalue())
                self.assertNotIn("private detail", errors.getvalue())

    def test_help_failure_preserves_bounded_launcher_diagnostics(self):
        result = subprocess.CompletedProcess([], 137, "unexpected stdout", "launch failed " + "x" * 10000)
        with tempfile.TemporaryDirectory() as directory:
            launcher = Path(directory) / "launcher"
            launcher.touch()
            with mock.patch("test_packaged_cli.subprocess.run", return_value=result) as run:
                with self.assertRaises(AssertionError) as failure:
                    smoke(launcher, "2.1.3")
        message = str(failure.exception)
        self.assertIn("exit=137", message)
        self.assertIn("unexpected stdout", message)
        self.assertIn("launch failed", message)
        self.assertLess(len(message), 9000)
        self.assertEqual(1, run.call_count)


class ImplicitOwnerTest(unittest.TestCase):
    def test_bootstrap_is_verified_and_only_its_owner_is_quit(self):
        calls = []
        def invoke(workspace, *args):
            calls.append(args)
            data = {"runtimeRunning": False} if args[-1] == "status" else {"validation.batch-size": 9}
            return subprocess.CompletedProcess([], 0, json.dumps({"schemaVersion": 1, "code": "OK",
                "ok": True, "final": True, "controllerId": "owner", "configurationRevision": 1, "data": data}), "")
        with tempfile.TemporaryDirectory() as root:
            implicit_owner_smoke(Path(root), invoke)
        self.assertEqual(("--json", "settings", "set", "validation.batch-size", "9"), calls[0])
        self.assertEqual(("--json", "--controller-id", "owner", "quit"), calls[-1])

    def test_failed_bootstrap_still_attempts_non_starting_cleanup(self):
        calls = []
        def invoke(workspace, *args):
            calls.append(args)
            return subprocess.CompletedProcess([], 2, json.dumps({"schemaVersion": 1,
                "code": "UNAVAILABLE", "ok": False}), "")
        with tempfile.TemporaryDirectory() as root, self.assertRaises(AssertionError):
            implicit_owner_smoke(Path(root), invoke)
        self.assertEqual(("--json", "quit"), calls[-1])


class LargeTransferTest(unittest.TestCase):
    def test_real_fixture_exceeds_ten_mib_and_contains_valid_length_domains(self):
        rules, content = large_routing_fixture()
        self.assertGreater(len(content.encode("utf-8")), 10 * 1024 * 1024)
        self.assertEqual(rules, json.loads(content)["rules"])
        self.assertEqual(56000, len(rules["direct_domain_suffixes"]))
        self.assertTrue(all(len(domain) <= 253 and all(len(label) <= 63 for label in domain.split("."))
                            for domain in rules["direct_domain_suffixes"]))

    def test_export_verifier_checks_content_count_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "東京 output.json"
            rules, content = large_routing_fixture(2)
            path.write_text(content, encoding="utf-8")
            path.chmod(0o600)
            size = path.stat().st_size
            self.assertEqual(32, len(verify_routing_export(path, rules, size)))
            with self.assertRaises(AssertionError):
                verify_routing_export(path, rules, size + 1)
            with self.assertRaises(AssertionError):
                verify_routing_export(path, dict(rules, ignore_rules=True), size)
            if os.name != "nt":
                path.chmod(0o644)
                with self.assertRaises(AssertionError):
                    verify_routing_export(path, rules, size)


class EnvelopeTest(unittest.TestCase):
    def result(self, *, code="OK", ok=True, exit_code=0, stderr="", suffix=""):
        return subprocess.CompletedProcess([], exit_code,
            json.dumps({"schemaVersion": 1, "code": code, "ok": ok}) + suffix, stderr)

    def test_success_and_action_failure_exit_codes(self):
        self.assertEqual("OK", envelope(self.result())["code"])
        failure = self.result(code="NOT_FOUND", ok=False, exit_code=1)
        self.assertEqual("NOT_FOUND", envelope(failure, 1, "NOT_FOUND")["code"])

    def test_rejects_stderr_and_exit_mismatch(self):
        for result in (self.result(stderr="launcher failed"), self.result(exit_code=1),
                       self.result(ok=False), self.result(code="NOT_FOUND")):
            with self.subTest(result=result), self.assertRaises(AssertionError):
                envelope(result)

    def test_rejects_noise_and_multiple_json_documents(self):
        for suffix in ("launcher noise", '\n{"code":"OK"}'):
            with self.subTest(suffix=suffix), self.assertRaises(json.JSONDecodeError):
                envelope(self.result(suffix=suffix))


class StreamTest(unittest.TestCase):
    def row(self, **changes):
        return dict(schemaVersion=1, code="OK", ok=True, final=False, controllerId="owner", **changes)

    def test_ndjson_preserves_unicode_and_waits_for_complete_lines(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stream.out"
            path.write_bytes('{"message":"東京"}\n{"unfinished":'.encode("utf-8"))
            self.assertEqual([{"message": "東京"}], stream_records(path))

    def test_rejects_unbounded_noise_and_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "stream.out"
            for content, maximum, error in ((b"12345", 4, AssertionError),
                                             (b"noise\n", 20, json.JSONDecodeError),
                                             (b'"\xff"\n', 20, UnicodeDecodeError)):
                path.write_bytes(content)
                with self.subTest(content=content), self.assertRaises(error):
                    stream_records(path, maximum)

    def test_requires_live_success_from_same_owner(self):
        row = self.row()
        verify_stream_records([row], "owner")
        for changes in ({"final": True}, {"ok": False}, {"controllerId": "replacement"},
                        {"code": "CONFLICT"}, {"schemaVersion": 2}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                verify_stream_records([dict(row, **changes)], "owner")

    def test_posix_interrupt_checks_exit130_without_terminating_owner(self):
        process = mock.Mock()
        process.poll.return_value = None
        process.wait.return_value = 130
        with mock.patch("test_packaged_cli.os.name", "posix"):
            interrupt_stream(process)
        process.send_signal.assert_called_once()
        process.terminate.assert_not_called()
        process.wait.assert_called_once_with(timeout=10)

    def test_windows_interrupt_uses_isolated_helper_for_exact_child(self):
        process = mock.Mock(pid=321)
        process.poll.return_value = None
        process.wait.return_value = 130
        with mock.patch("test_packaged_cli.os", SimpleNamespace(name="nt")), \
                mock.patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), \
                mock.patch("test_packaged_cli.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
            interrupt_stream(process)
        arguments, options = run.call_args
        self.assertEqual(["--interrupt-test-console", "321"], arguments[0][-2:])
        self.assertEqual(0x08000000, options["creationflags"])
        self.assertEqual(subprocess.DEVNULL, options["stdin"])
        self.assertEqual(10, options["timeout"])
        process.send_signal.assert_not_called()
        process.terminate.assert_not_called()


_PERSISTENT_OBSERVATIONS = []


class _PersistentSourceTest(unittest.TestCase):
    """Execute selected public sources with a real parser and owned inert children."""

    source_stage = "after"
    fixture_root = Path(__file__).resolve().parent / "testdata"

    @classmethod
    def setUpClass(cls):
        names = ("powershell.exe", "powershell") if os.name == "nt" else ("pwsh",)
        cls.runner = next((path for name in names if (path := shutil.which(name))), None)
        if cls.runner is None:
            if os.name == "nt":
                raise AssertionError("Windows PowerShell is required for persistent source checks")
            raise unittest.SkipTest("PowerShell is unavailable on this host")

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def generation(value):
        return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]

    def asset(self, family, name):
        root = self.fixture_root / family
        pins = json.loads((root / "fixture-pins.json").read_bytes())["files"]
        data = (root / name).read_bytes()
        self.assertEqual(pins[name]["sha256"], self.digest(data))
        self.assertEqual(pins[name]["bytes"], len(data))
        return data

    def parse_bound_sources(self, directory, bodies):
        # All files are created in this test's TempFS. Do not use POSIX-only flags.
        self.asset("windows-persistent-ready-parser", "parser.ps1")
        pins = []
        with ExitStack() as holders:
            opened = []
            for name, data in bodies.items():
                path = directory / name
                path.write_bytes(data)
                self.assertFalse(path.is_symlink())
                stream = holders.enter_context(path.open("rb"))
                opened.append((path, stream, self.generation(os.fstat(stream.fileno())), self.digest(data)))
            parsed = subprocess.run([self.runner, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                str(self.fixture_root / "windows-persistent-ready-parser" / "parser.ps1"),
                "-FixtureRoot", str(directory)], capture_output=True, timeout=20)
            self.assertEqual(b"", parsed.stderr)
            result = json.loads(parsed.stdout)
            self.assertIn(parsed.returncode, (0, 1))
            errors = [error["errorId"] for row in result["files"] for error in row["errors"]]
            self.assertEqual(int(bool(errors)), parsed.returncode)
            for path, stream, opening, digest in opened:
                stream.seek(0)
                data = stream.read()
                self.assertEqual(opening, self.generation(os.fstat(stream.fileno())))
                self.assertEqual(opening, self.generation(path.lstat()))
                self.assertEqual(digest, self.digest(data))
                pins.append({"name": path.name, "generation": opening, "sha256": digest,
                             "bytes": len(data)})
        return {"returnCode": parsed.returncode, "pins": pins, "fullClosing": True}, errors, result["PSVersion"]

    def launch_selected(self, family, directory, name):
        self.asset("windows-persistent-ready-parser", "inert-child.py")
        before = ast.parse(self.asset(family, "before/launcher.py.source").decode("utf-8"))
        after = ast.parse(self.asset(family, "after/launcher.py.source").decode("utf-8"))
        boundary = after.body[-1]
        self.assertIsInstance(boundary, ast.Assign)
        self.assertEqual("subprocess.Popen", ast.unparse(boundary.value.func))
        self.assertEqual(ast.dump(before.body[-1], include_attributes=False),
                         ast.dump(boundary, include_attributes=False))
        selected = before if self.source_stage == "before" else after
        guards = compile(ast.fix_missing_locations(ast.Module(body=selected.body[:-1], type_ignores=[])),
                         str(self.fixture_root / family / (self.source_stage + "/launcher.py.source")), "exec")
        popen = compile(ast.fix_missing_locations(ast.Module(body=[boundary], type_ignores=[])),
                        str(self.fixture_root / family / "after/launcher.py.source"), "exec")
        marker = directory / "inert-invocation.json"
        environment = os.environ.copy()
        environment.pop("DYLD_INSERT_LIBRARIES", None)
        namespace = {"OUT": directory, "hashlib": hashlib, "json": json, "base64": base64,
                     "re": re, "subprocess": subprocess, "env": environment,
                     "argv": [sys.executable, str(self.fixture_root / "windows-persistent-ready-parser" /
                     "inert-child.py"), str(marker), name, self.source_stage]}
        refusal = None
        try:
            exec(guards, namespace)
            exec(popen, namespace)
        except AssertionError:
            self.assertNotIn("child", namespace)
            refusal = "AssertionError"
        if "child" in namespace:
            with namespace["child"] as child:
                try:
                    stdout, stderr = child.communicate(b"", timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate()
                    raise
                self.assertEqual(0, child.returncode)
                self.assertEqual(b"", stderr)
                self.assertTrue(json.loads(stdout)["inertChildInvoked"])
            self.assertTrue(marker.exists())
            invoked = json.loads(marker.read_bytes())
            self.assertIs(invoked["invoked"], True)
            self.assertEqual([name, self.source_stage], invoked["argv"])
            self.assertEqual(0, invoked["stdinBytes"])
        self.assertEqual("child" in namespace, marker.exists())
        return {"name": name, "stage": self.source_stage, "invocationCount": int(marker.exists()),
                "blockedBeforePopen": "child" not in namespace, "refusal": refusal}

    def write_inputs(self, directory, bodies, receipt, payload):
        (directory / "parser-bound-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        (directory / "payload.preserve.json").write_text(json.dumps(payload), encoding="utf-8")

    def payload(self, bodies):
        return {"bootstrapBase64": base64.b64encode(bodies["bootstrap.preserve.ps1"]).decode("ascii"),
                "files": [{"sha256": self.digest(bodies["recovery.task.ps1"]),
                           "base64": base64.b64encode(bodies["recovery.task.ps1"]).decode("ascii")}]}


class PersistentReadyParserTest(_PersistentSourceTest):
    def test_actual_parser_and_bound_sources_block_before_child_launch(self):
        family = "windows-persistent-ready-parser"
        cases = [("malformed-original-parser", False), ("fixed-parser-and-bound-sources", True),
                 ("changed-source-after-parse", False), ("same-bytes-new-generation", False),
                 ("false-full-closing", False), ("payload-bootstrap-mismatch", False)]
        with tempfile.TemporaryDirectory(prefix="vpn-parser-routine-") as temp:
            for name, expected in cases:
                with self.subTest(case=name):
                    directory = Path(temp) / name
                    directory.mkdir()
                    bootstrap = self.asset(family, ("before" if name == "malformed-original-parser" else
                                                   "after") + "/bootstrap.preserve.ps1")
                    bodies = {"recovery.task.ps1": b"Write-Output 'inert source only'\n",
                              "bootstrap.preserve.ps1": bootstrap,
                              "bootstrap.preserve.consumer.ps1": b"param([string]$Value)\n$null=$Value\n"}
                    receipt, errors, version = self.parse_bound_sources(directory, bodies)
                    self.assertEqual(name == "malformed-original-parser", bool(errors))
                    if errors:
                        self.assertIn("UnexpectedToken", errors)
                    payload = self.payload(bodies)
                    if name == "changed-source-after-parse":
                        with (directory / "bootstrap.preserve.ps1").open("ab") as stream:
                            stream.write(b"\n# changed after the actual parser\n")
                    elif name == "same-bytes-new-generation":
                        replacement = directory / "bootstrap.replacement"
                        replacement.write_bytes(bootstrap)
                        replacement.replace(directory / "bootstrap.preserve.ps1")
                        old = next(pin["generation"] for pin in receipt["pins"]
                                   if pin["name"] == "bootstrap.preserve.ps1")
                        self.assertNotEqual(old, self.generation((directory / "bootstrap.preserve.ps1").lstat()))
                        self.assertEqual(self.digest(bootstrap), self.digest((directory / "bootstrap.preserve.ps1").read_bytes()))
                    elif name == "false-full-closing":
                        receipt["fullClosing"] = False
                    elif name == "payload-bootstrap-mismatch":
                        payload["bootstrapBase64"] = base64.b64encode(b"# different owned source").decode("ascii")
                    self.write_inputs(directory, bodies, receipt, payload)
                    observed = self.launch_selected(family, directory, name)
                    _PERSISTENT_OBSERVATIONS.append(dict(observed, PSVersion=version, parserErrors=errors))
                    self.assertEqual(int(expected), observed["invocationCount"])
                    self.assertEqual(not expected, observed["blockedBeforePopen"])


class PersistentTaskRootTest(_PersistentSourceTest):
    def test_actual_staging_and_durable_status_write_share_root(self):
        family = "windows-persistent-taskroot"
        old_task = self.asset(family, "before/recovery.task.ps1")
        old_bootstrap = self.asset(family, "before/bootstrap.preserve.ps1")
        old_root = re.search(rb"\$root='([^']+)'", old_task).group(1)
        staged_root = re.search(rb"\$root='([^']+)'", old_bootstrap).group(1)
        self.assertEqual(self.asset(family, "before-corrected-one-root.task.ps1"),
                         old_task.replace(old_root, staged_root, 1))
        self.asset(family, "control-write.ps1")
        for name in ("after/recovery.task.ps1", "after/bootstrap.preserve.ps1"):
            self.asset(family, name)
        for stage, expected in (("before", False), ("corrected", True), (self.source_stage, True)):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(prefix="vpn-root-write-") as temp:
                parsed = subprocess.run([self.runner, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                    str(self.fixture_root / family / "control-write.ps1"), "-Stage", stage,
                    "-WorkRoot", temp], capture_output=True, timeout=20)
                self.assertEqual(b"", parsed.stderr)
                observed = json.loads(parsed.stdout)
                _PERSISTENT_OBSERVATIONS.append(dict(observed, returnCode=parsed.returncode))
                if not expected:
                    self.assertEqual(1, parsed.returncode)
                    self.assertIn("System.IO.DirectoryNotFoundException", observed["errorTypes"])
                    self.assertFalse(observed["statusWriteSucceeded"])
                    self.assertFalse(observed["declaredStatusExists"])
                else:
                    self.assertEqual(0, parsed.returncode)
                    self.assertTrue(observed["pass"])
                    self.assertTrue(observed["statusWriteSucceeded"])
                    self.assertEqual(observed["mappedTaskRoot"], observed["mappedStagedRoot"])

    def test_actual_root_join_blocks_mixed_sources_before_child(self):
        family = "windows-persistent-taskroot"
        cases = [("genuine-old-task-root-mismatch", False), ("genuine-new-coupled-roots", True),
                 ("foreign-params-root", False), ("mixed-bootstrap-root", False), ("foreign-task-root", False)]
        with tempfile.TemporaryDirectory(prefix="vpn-root-join-") as temp:
            for name, expected in cases:
                with self.subTest(case=name):
                    directory = Path(temp) / name
                    directory.mkdir()
                    task = self.asset(family, ("before" if name == "genuine-old-task-root-mismatch" else
                                              "after") + "/recovery.task.ps1")
                    bootstrap = self.asset(family, ("before" if name in ("genuine-old-task-root-mismatch",
                                                                         "mixed-bootstrap-root") else
                                                   "after") + "/bootstrap.preserve.ps1")
                    params = json.loads(self.asset(family, "after/operator-parameters.json"))
                    if name == "genuine-old-task-root-mismatch":
                        params["taskRoot"] = re.search(rb"\$root='([^']+)'", bootstrap).group(1).decode("utf-8")
                    elif name == "foreign-params-root":
                        params["taskRoot"] = params["taskRoot"].replace(
                            "persistent-recovery-owner-a0e4e274-f0a7-4346-a4b1-bee9783beb83",
                            "persistent-recovery-owner-00000000-0000-0000-0000-000000000000")
                    elif name == "foreign-task-root":
                        task = task.replace(b"persistent-recovery-owner-a0e4e274-f0a7-4346-a4b1-bee9783beb83",
                                            b"persistent-recovery-owner-00000000-0000-0000-0000-000000000000", 1)
                    (directory / "operator-parameters.json").write_text(json.dumps(params), encoding="utf-8")
                    bodies = {"recovery.task.ps1": task, "bootstrap.preserve.ps1": bootstrap,
                              "bootstrap.preserve.consumer.ps1": b"param([string]$Value)\n$null=$Value\n"}
                    receipt, errors, version = self.parse_bound_sources(directory, bodies)
                    self.assertEqual([], errors)
                    self.write_inputs(directory, bodies, receipt, self.payload(bodies))
                    observed = self.launch_selected(family, directory, name)
                    _PERSISTENT_OBSERVATIONS.append(dict(observed, PSVersion=version))
                    self.assertEqual(int(expected), observed["invocationCount"])
                    self.assertEqual(not expected, observed["blockedBeforePopen"])


if __name__ == "__main__":
    unittest.main()
