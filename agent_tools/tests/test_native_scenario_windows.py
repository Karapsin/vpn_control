"""The closed Windows table, admit_start and the driver behind the real ScenarioExecutor.

Nothing here reaches a VM. FakeSsh answers the fixed carrier programs, and one test runs
the real durable owner through a fake ssh binary with a harmless job in its place.
"""
import ast
import base64
from contextlib import nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import uuid

from agent_tools import durable_remote_job
from agent_tools import native_scenario_bundle as bundles
from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_ssh as ssh_driver
from agent_tools import native_scenario_windows as windows
# Before any transport patch below: its source guard refuses a patched ssh_transport at import.
from agent_tools import readiness_windows_registration  # noqa: F401
from agent_tools import ssh_program_execution_remote as carrier
from agent_tools import ssh_transport as transport
from agent_tools import windows_scenario_host_job as host_job
from agent_tools.tests.test_native_vm_spec import request as vm_request

ROOT = Path(__file__).resolve().parents[2]
MACHINE = "33333333-4444-4555-8666-777777777777"
SCENARIO = "windows-ordinary-qualification"
HOME = "/home/fixture-owner"
TARGET = {"kind": "ssh", "uid": 1000, "principal": "fixture-owner", "home": HOME, "bootId": "22222222-3333-4444-8555-666666666666"}
OWNER = {"pid": 4242, "birth": "linux:987654"}


def setup_fields():
    return {"imageName": "Windows 11 Pro", "locale": "en-US", "user": "recovery", "administrator": "recoveryadmin"}


def receipt_bytes(operation, *, exit_code=0, evidence=None, **changes):
    value = host_job.build_receipt({"scenarioId": SCENARIO, "operationId": operation, "machine": MACHINE, "bundleHash": "a" * 64},
                                   exit_code=exit_code, stage="receipt", failure=None, evidence=evidence, guest_programs=9,
                                   task={"state": "task-finished", "ownerExitCode": 7, "terminalExitCode": 7, "lastTaskResult": 7,
                                         "events": [{}, {}, {}], "workerEvents": 0, "taskDeleted": True, "parkedFiles": [], "commandLineMatched": True,
                                         "enginePid": 900, "ownerPid": 901, "polls": 2, "rawStreams": []})
    value.update(changes)
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


class FakeSsh:
    """Answers the driver's fixed programs by what they are; nothing else may arrive."""

    def __init__(self, directory):
        self.directory = directory
        self.calls = []
        self.lost = set()
        self.unreached = set()
        self.submits = 0
        self.prepares = 0
        self.job = "absent"
        self.owner = dict(OWNER)
        self.reason = None
        self.exit_code = 0
        self.stdout = None
        self.collect_reply = None
        self.evidence = b""
        self.on_submit = None
        self.pulls = 0

    def _marker(self, operation):
        return json.dumps({"schemaVersion": 1, "operationId": operation, "scenarioExit": self.exit_code, "failure": None}).encode() + b"\n"

    def respond(self, command):
        if command[:4] != ("python3", "-I", "-B", "-c") or not command[4].startswith("exec("):
            raise AssertionError("not a fixed carrier: " + repr(command[:4]))
        program = ast.literal_eval(command[4][5:-1])
        if program == windows._TARGET:
            return "target", TARGET
        if program == windows._COLLECT:
            return "collect", self.collect_reply
        if program == windows._PULL:
            self.pulls += 1
            offset, length = int(command[7]), int(command[8])
            return "pull", {"size": len(self.evidence), "data": base64.b64encode(self.evidence[offset:offset + length]).decode()}
        first = program.split("\n", 1)[0]
        parameters = ast.literal_eval(first.split("=", 1)[1])
        if program.split("\n", 2)[1].startswith("OWNER_SOURCE="):
            self.prepares += 1
            return "prepare", {"remoteRoot": "/tmp/vpn-control-program-1000-" + parameters["operationId"], "generation": [1, 2],
                               "binding": {"target": "program-target", "machine": "machine", "boot": TARGET["bootId"], "account": "1000"},
                               "operationId": parameters["operationId"], "requestSha256": parameters["requestSha256"],
                               "ownerSourceSha256": parameters["ownerSourceSha256"]}
        operation = parameters["operationId"]
        if parameters["mode"] == "submit":
            if "submit" not in self.unreached:
                self.submits += 1
                self.job = "running"
                if self.on_submit is not None:
                    self.on_submit(parameters)
            return "submit", self._status(operation)
        return "observe", self._status(operation)

    def _status(self, operation):
        status = {"schemaVersion": 1, "operationId": operation, "replayAllowed": False}
        if self.job == "absent":
            status.update(state="unsubmitted", reason="admission_absent")
        elif self.job == "running":
            status.update(state="running", reason="original_owner_running", owner=self.owner)
        elif self.job == "lost":
            status.update(state="unknown", reason=self.reason or "original_owner_missing")
        else:
            status.update(state="terminal", reason="correlated_terminal", owner=self.owner, terminal={"exitCode": self.exit_code})
            stdout = self._marker(operation) if self.stdout is None else self.stdout
            return {"schemaVersion": 1, "operationId": operation, "status": status,
                    "stdout": base64.b64encode(stdout).decode(), "stderr": ""}
        return {"schemaVersion": 1, "operationId": operation, "status": status}

    def run(self, argv, **options):
        command = tuple(argv[1:])
        kind, reply = self.respond(command)
        self.calls.append(kind)
        if kind in self.lost:
            self.lost.discard(kind)
            return subprocess.CompletedProcess(argv, 255, b"", b"")
        return subprocess.CompletedProcess(argv, 0, json.dumps(reply).encode(), b"")


@unittest.skipUnless(os.name == "posix", "private scenario journals are POSIX")
class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "repository"
        self.root.mkdir()
        for relative in bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID]:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        info = bundles.prepare_bundle(self.root, windows.BUNDLE_SCENARIO_ID, self.work / "bundle")
        self.bundle = Path(info["directory"])
        self.bundle_hash = info["manifestSha256"]
        spec = vm_request()
        spec.update(deploymentId=MACHINE, host="fixture", root="/owned/vm")
        intent = {"spec": spec, "setup": setup_fields(), "context": {"hostBootId": TARGET["bootId"], "pending": []},
                  "correlationId": str(uuid.uuid4()), "mode": "start", "callerSha256": "c" * 64}
        directory = self.root / ".rag_index/windows-vm-deploy-intents"
        directory.mkdir(parents=True, mode=0o700)
        path = directory / (MACHINE + ".intent.json")
        path.write_text(json.dumps(intent))
        path.chmod(0o600)
        key = self.work / "key"
        key.write_text("key")
        key.chmod(0o600)
        known = self.work / "known"
        known.write_text("known")
        known.chmod(0o600)
        config = self.root / ".vm-hosts.local.json"
        config.write_text(json.dumps({"schemaVersion": 1, "hosts": {"fixture": {"host": "fixture", "port": 22, "user": "tester", "identityFile": str(key), "knownHostsFile": str(known)}}}))
        config.chmod(0o600)
        self.operation = str(uuid.uuid4())
        self.journal = self.root / ".rag_index/native-scenario-executions"

    def request(self, **changes):
        value = {"scenarioId": SCENARIO, "host": "fixture", "environment": MACHINE, "bundleHash": self.bundle_hash,
                 "artifactIds": {"bundleManifest": "sha256-" + self.bundle_hash}, "correlationId": self.operation}
        value.update(changes)
        return value

    def resolver(self, plan=None):
        return self.bundle

    def plan(self):
        return execution.ScenarioPlan.from_mapping(self.request())


class AdmissionTests(Base):
    def assert_refused(self, request, reason=None):
        with self.assertRaises(ValueError) as caught:
            windows.admit_start(self.root, request, self.resolver)
        if reason is not None:
            self.assertEqual(reason, str(caught.exception))
        self.assertFalse(self.journal.exists(), "a refusal leaves no journal")
        self.assertFalse(self.root.joinpath(*windows._LOCAL_STATE).exists())

    def test_the_exact_request_is_admitted(self):
        self.assertEqual("component", windows.admit_start(self.root, self.request(), self.resolver)["evidenceClass"])

    def test_unknown_name_is_refused_before_any_journal(self):
        for name in ("windows-arbitrary-command", "windows-ordinary-qualification.other", "windows-python-install", "linux-scheduled-refresh", None, 7):
            with self.subTest(name=name):
                self.assert_refused(self.request(scenarioId=name), "windows_scenario_not_allowlisted")

    def test_input_fields_stay_exact(self):
        for extra in ({"path": "C:\\x"}, {"argv": ["cmd"]}, {"source": "x"}, {"bytes": "x"}, {"stopAfter": "context"}, {"variant": "x"}):
            with self.subTest(extra=extra):
                self.assert_refused({**self.request(), **extra})
        missing = self.request()
        del missing["bundleHash"]
        self.assert_refused(missing)
        self.assert_refused("not-a-request", "windows_scenario_request_invalid")

    def test_identities_must_be_canonical_and_name_the_recorded_vm(self):
        self.assert_refused(self.request(correlationId="not-a-uuid"), "windows_scenario_correlation_invalid")
        self.assert_refused(self.request(correlationId=self.operation.upper()), "windows_scenario_correlation_invalid")
        self.assert_refused(self.request(environment="disposable"), "windows_scenario_environment_invalid")
        self.assert_refused(self.request(environment=str(uuid.uuid4())), "windows_scenario_environment_unavailable")
        self.assert_refused(self.request(host="another-host"), "windows_scenario_environment_mismatch")

    def test_package_and_unknown_artifacts_are_refused(self):
        manifest = "sha256-" + self.bundle_hash
        for artifacts in ({"bundleManifest": manifest, "targetPackage": "sha256-" + "b" * 64},
                          {"bundleManifest": manifest, "scenarioInput": "sha256-" + "b" * 64},
                          {"targetPackage": "sha256-" + "b" * 64}):
            with self.subTest(artifacts=artifacts):
                self.assert_refused(self.request(artifactIds=artifacts), "windows_scenario_artifacts_invalid")
        self.assert_refused(self.request(artifactIds={"bundleManifest": "sha256-" + "b" * 64}), "windows_scenario_bundle_artifact_invalid")

    def test_foreign_bundle_bytes_are_refused(self):
        (self.bundle / "agent_tools/windows_scenario_qualification_child.ps1").write_bytes(b"exit 0\n")
        self.assert_refused(self.request(), "windows_scenario_bundle_unavailable")

    def test_a_bundle_of_another_scenario_is_refused(self):
        other = bundles.prepare_bundle(ROOT, "desktop-update-entrypoint", self.work / "other")
        artifacts = {"bundleManifest": "sha256-" + other["manifestSha256"]}
        with self.assertRaises(ValueError) as caught:
            windows.admit_start(self.root, self.request(bundleHash=other["manifestSha256"], artifactIds=artifacts), lambda plan: other["directory"])
        self.assertEqual("windows_scenario_bundle_foreign", str(caught.exception))

    def test_a_bundle_that_differs_from_this_checkout_is_refused(self):
        (self.root / "agent_tools/windows_scenario_qualification_child.ps1").write_bytes(b"exit 0\n")
        self.assert_refused(self.request(), "windows_scenario_bundle_differs_from_checkout")

    def test_a_missing_checkout_file_is_refused(self):
        (self.root / "agent_tools/windows_ordinary_task.py").unlink()
        self.assert_refused(self.request(), "windows_scenario_bundle_differs_from_checkout")

    def test_the_route_helpers_delegate_only_windows_names(self):
        with self.assertRaises(ValueError):
            ssh_driver.admit_start(self.root, self.request(scenarioId="windows-arbitrary"), self.resolver)
        self.assertIsNone(ssh_driver.admit_start(self.root, {"scenarioId": "linux-public-update-preflight"}, self.resolver))
        self.assertEqual({"evidenceClass": "component", "productAction": False}, ssh_driver.public_evidence({"state": "submitted"}))
        self.assertEqual({"evidenceClass": "installed-package", "productAction": True}, ssh_driver.public_evidence({"scenarioId": "linux-scheduled-refresh"}))


class TableTests(unittest.TestCase):
    def test_the_closed_names_agree_everywhere(self):
        self.assertEqual(set(windows.RECIPES), set(execution.WINDOWS_SCENARIOS))
        self.assertEqual({"windows-ordinary-qualification"}, set(windows.RECIPES))
        for name, row in windows.RECIPES.items():
            self.assertEqual(frozenset(row["artifactKeys"]), ssh_driver.SCENARIO_ARTIFACT_KEYS[name])
            self.assertIn(name, execution._SCENARIOS)
            self.assertIn(name, execution._COLLECTED_SCENARIOS)
            for relative, _, _ in row["guestFiles"]:
                self.assertIn(relative, bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID])

    def test_the_qualification_doors_are_constants_of_the_row(self):
        row = windows.RECIPES["windows-ordinary-qualification"]
        self.assertEqual(("-Value", "scenario-ok"), row["qualificationArguments"])
        self.assertEqual("qualification", row["bootstrapMode"])
        self.assertIsNone(row["workerAction"])
        self.assertEqual((host_job.POWERSHELL_PATH,), row["readPins"])
        self.assertEqual("agent_tools/windows_scenario_host_job.py", bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID][0])

    def test_start_ticks_come_only_from_the_recorded_birth(self):
        self.assertEqual(987654, windows._start_ticks("linux:987654"))
        self.assertGreater(windows._start_ticks("darwin:12:34"), 0)
        for birth in ("linux:0", "linux:x", "987654", None, 7, "linux:12:13"):
            self.assertIsNone(windows._start_ticks(birth))

    def test_exit_markers_must_name_the_operation(self):
        operation = str(uuid.uuid4())
        good = json.dumps({"operationId": operation, "scenarioExit": 1, "failure": "x"}).encode()
        self.assertEqual(1, windows._exit_marker(b"noise\n" + good + b"\n", operation)["scenarioExit"])
        for raw in (b"", b"Traceback\n", json.dumps({"operationId": "other", "scenarioExit": 1}).encode(),
                    json.dumps({"operationId": operation, "scenarioExit": True}).encode()):
            self.assertIsNone(windows._exit_marker(raw, operation))


class PublicEvidenceTests(unittest.TestCase):
    def test_a_component_row_never_claims_installed_package(self):
        claim = {"scenarioId": SCENARIO, "state": "terminal", "collectionState": "complete",
                 "scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": "a" * 64}}}
        self.assertEqual({"evidenceClass": "component", "productAction": False}, windows.public_evidence(claim))

    def test_setup_keeps_its_class(self):
        with mock.patch.dict(windows.RECIPES, {"windows-setup-row": {"evidenceClass": "setup"}}):
            self.assertEqual({"evidenceClass": "setup", "productAction": False}, windows.public_evidence({"scenarioId": "windows-setup-row", "state": "terminal"}))

    def test_a_product_row_needs_every_real_fact(self):
        digest = "b" * 64
        complete = {"scenarioId": "windows-product-row", "state": "terminal", "collectionState": "complete",
                    "scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": digest}}}
        with mock.patch.dict(windows.RECIPES, {"windows-product-row": {"evidenceClass": "product", "packageSha256": digest}}):
            self.assertEqual({"evidenceClass": "installed-package", "productAction": True}, windows.public_evidence(complete))
            for change in ({"state": "submitted"}, {"state": "unknown"}, {"collectionState": "unknown"},
                           {"scenarioEvidence": {"windows": {"installedPackage": False, "packageSha256": digest}}},
                           {"scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": "c" * 64}}},
                           {"scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": None}}},
                           {"scenarioEvidence": None}):
                with self.subTest(change=change):
                    self.assertEqual({"evidenceClass": "installed-package-unproven", "productAction": True}, windows.public_evidence({**complete, **change}))


class DriverBase(Base):
    def setUp(self):
        super().setUp()
        self.ssh = FakeSsh(self.work)
        for patcher in (mock.patch.object(transport, "admitted_transport", return_value=nullcontext()),
                        mock.patch.object(transport, "build_ssh_argv", side_effect=lambda config, host, timeout, command, ssh_binary: ["fake-ssh", *command]),
                        mock.patch.object(transport, "run_ssh", side_effect=lambda argv, **options: self.ssh.run(argv, **options))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def driver(self, **options):
        return windows.NativeScenarioWindowsDriver(self.root, self.resolver, **options)

    def executor(self, driver=None):
        return execution.ScenarioExecutor(self.journal, driver or self.driver())

    def finished(self, *, exit_code=0, evidence=None, raw=None):
        self.ssh.job = "terminal"
        self.ssh.exit_code = exit_code
        raw = receipt_bytes(self.operation, exit_code=exit_code, evidence=evidence) if raw is None else raw
        self.ssh.collect_reply = {"state": "collected", "receipt": base64.b64encode(raw).decode(),
                                  "jobExit": {"schemaVersion": 1, "operationId": self.operation, "exitCode": exit_code, "fenceAnchored": True}}
        return raw


class SubmitTests(DriverBase):
    def test_submit_order_and_job_identity(self):
        seen = {}

        def at_submit(parameters):
            local = self.root.joinpath(*windows._LOCAL_STATE, self.operation)
            seen.update(journal=json.loads((self.journal / (self.operation + ".json")).read_text())["state"],
                        program=(local / "program.json").exists(), admission=(local / "admission.json").exists())
            seen["mode"] = oct((local / "program.json").stat().st_mode & 0o777)
        self.ssh.on_submit = at_submit
        started = self.executor().start(self.request())
        self.assertEqual(["target", "prepare", "submit"], self.ssh.calls)
        self.assertEqual({"journal": "submitting", "program": True, "admission": True, "mode": "0o600"}, seen)
        self.assertEqual(("submitted", "submitted"), (started["state"], started["reason"]))
        local = self.root.joinpath(*windows._LOCAL_STATE, self.operation)
        for name in ("target", "prepare", "submit"):
            self.assertEqual(b"0", (local / (name + ".returncode")).read_bytes(), "what the host said stays private and local")
            self.assertEqual(0o600, (local / (name + ".stderr.private")).stat().st_mode & 0o777)
        self.assertEqual({"jobId": "windows-" + self.operation, "pid": 4242, "startTicks": 987654,
                          "receiptPath": HOME + "/.cache/vpn-control-windows-scenarios/" + MACHINE + "/" + self.operation + "/scenario-receipt.json"},
                         started["jobIdentity"])

    def test_repeated_start_returns_the_original_and_submits_once(self):
        executor = self.executor()
        executor.start(self.request())
        again = executor.start(self.request())
        self.assertTrue(again["duplicate"])
        self.assertEqual(1, self.ssh.submits)
        self.assertEqual(["target", "prepare", "submit"], self.ssh.calls)

    def test_lost_submit_reply_discovers_the_same_generation_and_never_submits_twice(self):
        self.ssh.lost = {"submit"}
        first = self.executor().start(self.request())
        self.assertEqual(("submitting", "submit_response_unavailable"), (first["state"], first["reason"]))
        self.assertEqual(1, self.ssh.submits)
        resumed = self.executor().resume(self.operation)
        self.assertEqual(("submitted", "original_owner_running"), (resumed["state"], resumed["reason"]))
        self.assertEqual((4242, 987654), (resumed["jobIdentity"]["pid"], resumed["jobIdentity"]["startTicks"]))
        self.assertTrue(self.executor().start(self.request())["duplicate"])
        self.finished()
        terminal = self.executor().status(self.operation)
        self.assertEqual(("terminal", 0, "complete"), (terminal["state"], terminal["exitCode"], terminal["collectionState"]))
        self.assertEqual(1, self.ssh.submits)
        self.assertEqual(1, self.ssh.prepares)

    def test_a_lost_reply_where_the_job_was_never_admitted_stays_unknown_without_a_submit(self):
        self.ssh.lost = {"submit"}
        self.ssh.unreached = {"submit"}
        first = self.executor().start(self.request())
        self.assertEqual("submitting", first["state"])
        self.assertEqual(0, self.ssh.submits)
        for _ in range(2):
            result = self.executor().resume(self.operation)
            self.assertEqual(("unknown", "job_not_discovered"), (result["state"], result["reason"]))
        self.assertEqual(1, self.ssh.calls.count("submit"), "an absent admission is never resubmitted by an observer")

    def test_a_lost_preparation_reply_never_reaches_a_submit(self):
        self.ssh.lost = {"prepare"}
        self.assertEqual("submit_response_unavailable", self.executor().start(self.request())["reason"])
        self.assertEqual(("unknown", "job_not_discovered"), tuple(self.executor().resume(self.operation)[key] for key in ("state", "reason")))
        self.assertNotIn("submit", self.ssh.calls)
        self.assertEqual(0, self.ssh.submits)

    def test_a_second_submit_of_one_correlation_stops_before_any_connection(self):
        self.executor().start(self.request())
        calls = list(self.ssh.calls)
        with self.assertRaisesRegex(ValueError, "windows_scenario_job_already_exists"):
            self.driver().submit(self.plan())
        self.assertEqual(calls, self.ssh.calls)
        self.assertEqual(1, self.ssh.submits)

    def test_a_local_source_edit_after_submit_does_not_change_observation(self):
        self.executor().start(self.request())
        (self.root / "agent_tools/windows_ordinary_task.py").write_text("# edited after the job started\n")
        self.assertEqual("submitted", self.executor().status(self.operation)["state"])

    def test_stop_after_is_constructor_wiring_only(self):
        self.assertNotIn("stopAfter", execution.ScenarioPlan.__dataclass_fields__)
        with self.assertRaisesRegex(ValueError, "windows_scenario_stop_after_invalid"):
            self.driver(stop_after="run").submit(self.plan())
        self.assertEqual(0, self.ssh.submits)
        delegate = ssh_driver.NativeScenarioSshDriver(self.root, self.resolver)._windows(self.plan())
        self.assertIsNone(delegate.stop_after, "the MCP route cannot ask for a partial job")

    def test_direct_stop_after_reaches_the_job_plan(self):
        self.executor(self.driver(stop_after="context")).start(self.request())
        program = json.loads(self.root.joinpath(*windows._LOCAL_STATE, self.operation, "program.json").read_text())
        self.assertIn("'stopAfter': 'context'", program["program"]["source"])


class ObservationTests(DriverBase):
    def setUp(self):
        super().setUp()
        self.executor().start(self.request())

    def status(self):
        return self.executor().status(self.operation)

    def test_running_is_the_original_owner(self):
        result = self.status()
        self.assertEqual(("submitted", "original_owner_running"), (result["state"], result["reason"]))

    def test_exits_0_1_2_with_the_jobs_own_line_are_terminal(self):
        for exit_code, result_word in ((0, "passed"), (1, "failed"), (2, "failed")):
            with self.subTest(exit_code=exit_code):
                self.setUp()
                self.finished(exit_code=exit_code)
                result = self.status()
                self.assertEqual(("terminal", exit_code, "complete", result_word),
                                 (result["state"], result["exitCode"], result["collectionState"], result["scenarioEvidence"]["result"]))

    def test_exit_3_and_any_other_exit_stay_unknown_and_never_terminal(self):
        for exit_code in (3, 4, 64, 70, 137, -9):
            with self.subTest(exit_code=exit_code):
                self.setUp()
                self.ssh.job = "terminal"
                self.ssh.exit_code = exit_code
                result = self.status()
                self.assertEqual("unknown", result["state"])
                self.assertTrue(result["reason"].startswith("job_exit_unknown:"))
                self.assertNotIn("exitCode", result)
                self.assertNotEqual("terminal", json.loads((self.journal / (self.operation + ".json")).read_text())["state"])

    def test_an_exit_1_without_the_jobs_own_line_is_an_uncaught_error_not_a_known_failure(self):
        self.ssh.job = "terminal"
        self.ssh.exit_code = 1
        for stdout in (b"", b"Traceback (most recent call last)\n", json.dumps({"operationId": str(uuid.uuid4()), "scenarioExit": 1}).encode(),
                       json.dumps({"operationId": self.operation, "scenarioExit": 0}).encode()):
            with self.subTest(stdout=stdout):
                self.ssh.stdout = stdout
                result = self.status()
                self.assertEqual("unknown", result["state"])
                self.assertEqual("job_exit_unknown:unverified", result["reason"])

    def test_a_refusal_before_the_job_started_keeps_its_cause(self):
        self.ssh.job = "terminal"
        self.ssh.exit_code = 2
        self.ssh.stdout = json.dumps({"schemaVersion": 1, "operationId": self.operation, "scenarioExit": 2, "failure": "host_setup:instance_host_epoch"}).encode() + b"\n"
        self.ssh.collect_reply = {"state": "unknown"}
        result = self.status()
        self.assertEqual(("unknown", "terminal_collection_unverified", "terminal", 2, "host_setup:instance_host_epoch"),
                         tuple(result[key] for key in ("state", "reason", "executionState", "executionExitCode", "executionFailure")))
        self.assertEqual("host_setup:instance_host_epoch", self.executor().collect(self.operation, include_failure_excerpt=True)["failureExcerpt"])
        self.assertEqual(1, self.ssh.submits)

    def test_a_missing_owner_or_changed_boot_is_unknown(self):
        for reason in ("original_owner_missing", "boot_changed", "root_generation_changed"):
            with self.subTest(reason=reason):
                self.ssh.job = "lost"
                self.ssh.reason = reason
                result = self.status()
                self.assertEqual(("unknown", reason), (result["state"], result["reason"]))

    def test_a_different_generation_is_refused(self):
        self.ssh.owner = {"pid": 4242, "birth": "linux:1"}
        self.finished()
        result = self.status()
        self.assertEqual(("unknown", "job_identity_mismatch"), (result["state"], result["reason"]))

    def test_a_reply_for_another_operation_is_unavailable(self):
        original = self.ssh._status
        self.ssh._status = lambda operation: original(str(uuid.uuid4()))
        result = self.status()
        self.assertEqual(("unknown", "observer_unavailable"), (result["state"], result["reason"]))

    def test_observation_reads_and_never_submits(self):
        for _ in range(3):
            self.status()
        self.assertEqual(1, self.ssh.submits)
        self.assertEqual({"target", "prepare", "submit", "observe"}, set(self.ssh.calls))


class CollectionTests(DriverBase):
    def setUp(self):
        super().setUp()
        self.executor().start(self.request())

    def status(self):
        return self.executor().status(self.operation)

    def test_a_complete_collection_keeps_its_failure_in_the_evidence_only(self):
        self.finished(exit_code=1, raw=receipt_bytes(self.operation, exit_code=1, failure="task_exit_code"))
        result = self.status()
        self.assertEqual(("terminal", "complete", "task_exit_code"), (result["state"], result["collectionState"], result["scenarioEvidence"]["windows"]["failure"]))
        self.assertNotIn("executionFailure", result)

    def test_collection_is_a_closed_projection_of_the_receipt(self):
        raw = receipt_bytes(self.operation, stoppedAfter=None, context={"profileRoot": "C:\\Users\\private-account", "ordinarySessionId": 2}, failure=None)
        self.finished(raw=raw)
        result = self.status()
        self.assertEqual(("terminal", "complete"), (result["state"], result["collectionState"]))
        projected = result["scenarioEvidence"]
        self.assertEqual({"state", "scenarioId", "correlationId", "result", "actualReceiptSha256", "exitCode", "windows"}, set(projected))
        self.assertEqual({"evidenceClass": "component", "installedPackage": False, "taskDeleted": True, "parked": False, "taskExitCode": 7, "taskEvents": 3}, projected["windows"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), projected["actualReceiptSha256"])
        self.assertNotIn("private-account", json.dumps(result))
        record = json.loads((self.journal / (self.operation + ".json")).read_text())
        self.assertIn("private-account", record["collection"]["rawJson"], "the whole receipt stays in the private journal")

    def test_projection_refuses_paths_and_free_text_in_the_windows_part(self):
        value = {"state": "collected", "scenarioId": SCENARIO, "correlationId": self.operation, "result": "passed", "actualReceiptSha256": "a" * 64, "exitCode": 0,
                 "windows": {"evidenceClass": "C:\\Users\\private", "installedPackage": "yes", "packageSha256": "not-a-digest", "taskExitCode": True, "taskEvents": "3",
                             "failure": "C:\\Users\\private\\activation.port", "stoppedAfter": "a b", "extra": "x"}}
        self.assertEqual({}, execution.ScenarioExecutor._project_collection(value)["windows"])

    def test_a_receipt_for_another_operation_or_exit_is_not_collected(self):
        for raw, job_exit in ((receipt_bytes(str(uuid.uuid4())), None), (receipt_bytes(self.operation, exit_code=1), None),
                              (receipt_bytes(self.operation), {"schemaVersion": 1, "operationId": str(uuid.uuid4()), "exitCode": 0})):
            with self.subTest(raw=raw[:40]):
                self.setUp()
                self.finished(raw=raw)
                if job_exit is not None:
                    self.ssh.collect_reply["jobExit"] = job_exit
                result = self.status()
                self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))
                self.assertNotIn("scenarioEvidence", result)

    def test_an_unavailable_collection_stays_unknown_and_recovers_on_a_later_read(self):
        self.finished()
        good = self.ssh.collect_reply
        self.ssh.collect_reply = {"state": "unknown"}
        self.assertEqual("unknown", self.status()["state"])
        self.ssh.collect_reply = good
        self.assertEqual(("terminal", "complete"), tuple(self.status()[key] for key in ("state", "collectionState")))
        self.assertEqual(1, self.ssh.submits)

    def test_evidence_is_pulled_private_and_verified_before_the_collection_completes(self):
        self.ssh.evidence = os.urandom(windows._EVIDENCE_CHUNK + 17)
        evidence = {"name": "evidence-1.zip", "bytes": len(self.ssh.evidence), "sha256": hashlib.sha256(self.ssh.evidence).hexdigest(), "entries": 5}
        self.finished(evidence=evidence)
        result = self.status()
        self.assertEqual("complete", result["collectionState"])
        directory = self.root.joinpath(*windows._EVIDENCE_PARENT, self.operation)
        self.assertEqual(self.ssh.evidence, (directory / "evidence-1.zip").read_bytes())
        self.assertEqual(0o700, directory.stat().st_mode & 0o777)
        self.assertEqual(0o600, (directory / "evidence-1.zip").stat().st_mode & 0o777)
        self.assertEqual(2, self.ssh.pulls)

    def test_changed_evidence_bytes_leave_the_collection_unknown_and_save_nothing(self):
        self.ssh.evidence = b"zip-bytes"
        evidence = {"name": "evidence-1.zip", "bytes": 9, "sha256": "0" * 64, "entries": 1}
        self.finished(evidence=evidence)
        self.assertEqual(("unknown", "terminal_collection_unverified"), tuple(self.status()[key] for key in ("state", "reason")))
        self.assertFalse(self.root.joinpath(*windows._EVIDENCE_PARENT, self.operation, "evidence-1.zip").exists())

    def test_evidence_beyond_what_one_admission_carries_is_never_pulled(self):
        self.ssh.evidence = b"zip-bytes"
        self.finished(evidence={"name": "evidence-1.zip", "bytes": windows._MAX_EVIDENCE + 1, "sha256": "0" * 64, "entries": 1})
        self.assertEqual(("unknown", "terminal_collection_unverified"), tuple(self.status()[key] for key in ("state", "reason")))
        self.assertEqual(0, self.ssh.pulls)
        # Every chunk shares one admission: each pull is a new SSH connection and a new python3.
        self.assertLessEqual(windows._MAX_EVIDENCE // windows._EVIDENCE_CHUNK, windows._OBSERVE_SECONDS // 7)

    def test_evidence_names_are_closed(self):
        self.ssh.evidence = b"zip-bytes"
        for name in ("../secret.zip", "activation.port", "evidence-1.zip/../x", "evidence-.zip"):
            with self.subTest(name=name):
                self.setUp()
                self.ssh.evidence = b"zip-bytes"
                self.finished(evidence={"name": name, "bytes": 9, "sha256": hashlib.sha256(b"zip-bytes").hexdigest(), "entries": 1})
                self.assertEqual("unknown", self.status()["state"])
                self.assertEqual(0, self.ssh.pulls)

    def test_the_largest_receipt_fits_the_collection_bound(self):
        word = "x" * 120
        task = {"state": word, "ownerExitCode": 2 ** 31, "terminalExitCode": 2 ** 31, "lastTaskResult": -2 ** 31, "events": [{}] * 512,
                "workerEvents": 8192, "taskDeleted": True, "parkedFiles": ["task-owner-parked.json"], "commandLineMatched": True, "enginePid": 2 ** 32,
                "ownerPid": 2 ** 32, "polls": 10 ** 6, "statusFailures": 10 ** 6, "rawStreams": [{"name": "stdout", "bytes": 64 * 1024 ** 2, "sha256": "f" * 64}, {"name": "stderr", "bytes": 64 * 1024 ** 2, "sha256": "f" * 64}]}
        context = {"ordinarySid": "S-1-5-21-" + "-".join(["4294967295"] * 4), "ordinarySessionId": 2 ** 32, "profileRoot": "C:\\Users\\" + "u" * 32, "bootFileTimeUtc": "1" * 19,
                   "bootIdentifier": "f" * 36, "hardwareUuid": "F" * 36, "machineGuid": "f" * 36, "ignored": "y" * 4096}
        evidence = {"name": "evidence-999999.zip", "bytes": windows._MAX_EVIDENCE, "sha256": "f" * 64, "entries": 8192}
        plan = {"scenarioId": SCENARIO, "operationId": self.operation, "machine": MACHINE, "bundleHash": "f" * 64, "stopAfter": "publish"}
        receipt = host_job.build_receipt(plan, exit_code=0, stage="publish", failure=word, context=context, task=task, evidence=evidence, guest_programs=4096)
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self.assertLessEqual(len(raw), host_job.RECEIPT_BYTES)
        summary = self.driver()._summary(self.plan(), raw, {"operationId": self.operation, "exitCode": 0})
        payload = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        self.assertLessEqual(len(payload), execution._COLLECTION_LIMIT)
        self.assertLess(len(raw), 6144, "around 5 KB, as the spec sizes it")
        self.assertTrue(execution.ScenarioExecutor._collection_matches(self.plan(), 0, json.loads(payload)))


class DelegateTests(DriverBase):
    def test_the_ssh_driver_never_falls_through_for_a_windows_name(self):
        driver = ssh_driver.NativeScenarioSshDriver(self.root, self.resolver)
        plan = self.plan()
        with mock.patch.object(ssh_driver.NativeScenarioSshDriver, "_admit", side_effect=AssertionError("linux admission")), \
             mock.patch.object(ssh_driver.NativeScenarioSshDriver, "_status", side_effect=AssertionError("linux status")), \
             mock.patch.object(ssh_driver.NativeScenarioSshDriver, "_run", side_effect=AssertionError("linux program")):
            executor = execution.ScenarioExecutor(self.journal, driver)
            started = executor.start(self.request())
            self.assertEqual("windows-" + self.operation, started["jobIdentity"]["jobId"])
            self.assertEqual("submitted", executor.status(self.operation)["state"])
            self.finished()
            self.assertEqual("complete", executor.status(self.operation)["collectionState"])
        self.assertEqual(1, self.ssh.submits)
        self.assertEqual(driver.root, driver._windows(plan).root)

    def test_linux_names_do_not_build_a_windows_driver(self):
        driver = ssh_driver.NativeScenarioSshDriver(self.root, self.resolver)
        linux = execution.ScenarioPlan.from_mapping({**self.request(), "scenarioId": "linux-public-update-preflight"})
        self.assertIsNone(driver._windows(linux))


class RenderTests(DriverBase):
    def rendered(self, **options):
        plan = self.plan()
        bundle, verified = windows.verified_bundle(self.root, plan, self.resolver)
        binding = windows._binding(self.root, plan)
        return windows.render_program(plan, binding, bundle, verified, TARGET, **options)

    def test_the_job_source_is_one_closed_compilable_program(self):
        source, data = self.rendered()
        self.assertEqual(HOME + "/.cache/vpn-control-windows-scenarios/" + MACHINE + "/" + self.operation, data)
        tree = ast.parse(source)
        self.assertIsInstance(tree.body[-1], ast.Raise)
        self.assertLess(len(source.encode()), carrier.MAX_SOURCE_BYTES)
        names = {target.id for node in tree.body if isinstance(node, ast.Assign) for target in node.targets if isinstance(target, ast.Name)}
        self.assertLessEqual({"SPEC", "SETUP", "CONTEXT", "PLAN", "FILES_GZ", "wire", "partial_wire"}, names)
        host_main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_host_main")
        defined = {node.name for node in ast.walk(host_main) if isinstance(node, ast.FunctionDef)}
        self.assertLessEqual({"require", "chain", "closing", "private", "save", "read", "process", "owns", "instance_intent", "vm_guard", "exchange"}, defined)
        self.assertNotIn("launch", defined)
        self.assertNotIn("_CANONICAL_INSTANCE_DEFINITIONS", source)
        self.assertIn("def call(", source)

    def test_the_staged_files_are_the_frozen_bundle_exactly(self):
        source, _ = self.rendered()
        namespace = {}
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") in {"FILES_GZ", "PLAN"}:
                namespace[node.targets[0].id] = ast.literal_eval(node.value)
        payload = json.loads(gzip.decompress(base64.b64decode(namespace["FILES_GZ"])))
        self.assertEqual(set(bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID]), set(payload))
        self.assertEqual(set(payload), set(namespace["PLAN"]["files"]))
        for relative, encoded in payload.items():
            self.assertEqual((self.bundle / relative).read_bytes(), base64.b64decode(encoded))
        plan = namespace["PLAN"]
        self.assertEqual(self.operation, plan["operationId"])
        self.assertEqual(["-Value", "scenario-ok"], plan["row"]["qualificationArguments"])
        self.assertIsNone(plan["stopAfter"])
        self.assertEqual(json.loads(json.dumps(windows.RECIPES[SCENARIO])), plan["row"])

    def test_the_rendered_program_runs_on_a_plain_python3_and_refuses_cleanly_without_a_vm(self):
        source, data = self.rendered()
        host = self.work / "isolated"
        host.mkdir()
        done = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys;exec(compile(sys.stdin.buffer.read(),'job','exec'),{'__name__':'__main__'})"],
                              input=source.encode(), cwd=host, capture_output=True, env={"PATH": os.defpath}, timeout=120)
        self.assertEqual(2, done.returncode, done.stderr.decode("utf-8", "replace"))
        marker = windows._exit_marker(done.stdout, self.operation)
        self.assertEqual(2, marker["scenarioExit"])
        self.assertTrue(marker["failure"].startswith("host_setup:"))
        self.assertEqual([], list(host.iterdir()))
        self.assertFalse(Path(data).exists())

    def test_a_carrier_accepts_the_rendered_program_for_submit_and_observe(self):
        source, _ = self.rendered()
        program = {"language": "python3", "source": source, "args": [], "cwd": HOME, "targetContext": TARGET}
        prepare = carrier.prepare_command(self.operation, program, durable_remote_job.owner_source())
        self.assertEqual("python3", prepare[0])
        packet = {"remoteRoot": "/tmp/vpn-control-program-1000-" + self.operation, "generation": [1, 2], "binding": {}, "operationId": self.operation,
                  "requestSha256": hashlib.sha256(carrier._canonical(program)).hexdigest(), "ownerSourceSha256": "a" * 64}
        observe = carrier.durable_command(self.operation, program, packet, mode="observe", wait_seconds=0)
        submit = carrier.durable_command(self.operation, program, packet, mode="submit", wait_seconds=2)
        self.assertLess(len(observe[4]), 60000)
        self.assertGreater(len(submit[4]), len(observe[4]))


@unittest.skipUnless(os.name == "posix" and shutil.which("python3"), "the fake ssh runs a POSIX python3")
class RealCarrierTests(Base):
    """The real prepare and durable commands, the real detached owner and its real files."""

    JOB = r"""import json,os,pathlib,sys,time
data=pathlib.Path(%(data)r);gate=pathlib.Path(%(gate)r);starts=pathlib.Path(%(starts)r)
with open(starts,'a') as stream:stream.write('started\n')
for _ in range(15000):
 if gate.exists():break
 time.sleep(.02)
data.mkdir(parents=True,mode=0o700)
for name,raw in ((%(receipt_name)r,%(receipt)r),('job-exit.json',%(job_exit)r)):
 descriptor=os.open(data/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 os.write(descriptor,raw);os.close(descriptor)
print(json.dumps({'schemaVersion':1,'operationId':%(operation)r,'scenarioExit':0,'failure':None}))
raise SystemExit(0)
"""

    def setUp(self):
        super().setUp()
        self.fake = self.work / "fake-ssh"
        self.fake.write_text('#!/bin/sh\nfor last; do :; done\nexec /bin/sh -c "$last"\n')
        self.fake.chmod(0o700)
        patcher = mock.patch.object(transport, "admitted_transport", return_value=nullcontext())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gate = self.work / "gate"
        self.addCleanup(self.gate.touch)  # A failed test must not leave its detached job waiting.
        self.starts = self.work / "starts"
        self.data = self.work / "host-home/.cache/vpn-control-windows-scenarios" / MACHINE / self.operation
        self.addCleanup(shutil.rmtree, "/tmp/vpn-control-program-" + str(os.geteuid()) + "-" + self.operation, True)
        self.addCleanup(shutil.rmtree, "/private/tmp/vpn-control-program-" + str(os.geteuid()) + "-" + self.operation, True)

    def job_source(self):
        job_exit = json.dumps({"schemaVersion": 1, "operationId": self.operation, "exitCode": 0, "fenceAnchored": True}).encode()
        return self.JOB % {"data": str(self.data), "gate": str(self.gate), "starts": str(self.starts), "receipt_name": "scenario-receipt.json",
                           "receipt": receipt_bytes(self.operation), "job_exit": job_exit, "operation": self.operation}

    def test_a_lost_submit_reply_finds_the_one_real_job_and_collects_its_receipt(self):
        losses = []
        fake_binary = str(self.fake)

        class LosingDriver(windows.NativeScenarioWindowsDriver):
            def _send(self, config, host, command, **options):
                reply = super()._send(config, host, command, **options)
                if "'mode': 'submit'" in command[4] or "\\'mode\\': \\'submit\\'" in command[4]:
                    losses.append(reply)
                    return None
                return reply
        rendered = mock.patch.object(windows, "render_program", return_value=(self.job_source(), str(self.data)))
        with rendered:
            first = execution.ScenarioExecutor(self.journal, LosingDriver(self.root, self.resolver, ssh_binary=fake_binary)).start(self.request())
        self.assertEqual(("submitting", "submit_response_unavailable"), (first["state"], first["reason"]))
        self.assertEqual(1, len(losses), "the submit command really ran and its reply was dropped")
        driver = windows.NativeScenarioWindowsDriver(self.root, self.resolver, ssh_binary=fake_binary)
        executor = execution.ScenarioExecutor(self.journal, driver)
        deadline = time.monotonic() + 120
        result = executor.resume(self.operation)
        while result["state"] != "submitted":
            self.assertLess(time.monotonic(), deadline, str(result))
            time.sleep(.05)
            result = executor.resume(self.operation)
        self.assertEqual("original_owner_running", result["reason"])
        identity = result["jobIdentity"]
        self.assertEqual("windows-" + self.operation, identity["jobId"])
        self.assertGreater(identity["pid"], 0)
        self.assertGreater(identity["startTicks"], 0)
        self.assertTrue(executor.start(self.request())["duplicate"])
        self.gate.touch()
        while result["state"] != "terminal":
            self.assertLess(time.monotonic(), deadline, str(result))
            time.sleep(.05)
            result = executor.status(self.operation)
        self.assertEqual((0, "complete", "passed"), (result["exitCode"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual(identity, result["jobIdentity"])
        self.assertEqual(["started"], self.starts.read_text().splitlines(), "one job, one start")
        with self.assertRaisesRegex(ValueError, "windows_scenario_job_already_exists"):
            driver.submit(self.plan())


if __name__ == "__main__":
    unittest.main()
