"""matrix_observation over real journals, a real registry and the real matrix ledger.

Rows are written by the real ScenarioExecutor. A fake driver stands for the VM: it answers with
receipts the real host job builds (build_receipt) and collections the real driver projects (_summary),
so every journal is one the MCP route or the direct script could leave. Nothing reaches a host.
"""
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import uuid

from agent_tools import native_acceptance_matrix as matrix
from agent_tools import native_artifact_registry as registry
from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_windows as windows
from agent_tools import windows_scenario_host_job as host_job

MACHINE = "33333333-4444-4555-8666-777777777777"
OTHER_MACHINE = "33333333-4444-4555-8666-888888888888"
HOME = "/home/fixture-owner"
SMK, SSH, CFG = "windows-packaged-cli-smoke", "windows-disconnected-cli-config.ssh-import-routing", "windows-disconnected-cli-config"
REVIEW = "Coordinator reviewed every receipt of this set."
NATIVE = matrix.load_requirements()["windows-native-cli"]["requiredScenarios"]
# A synthetic table that a complete set can satisfy: ten scenarios on the smoke row, five on the SSH row.
TEST_TABLE = {name: ((SMK,) if index < 10 else (SSH,)) for index, name in enumerate(NATIVE)}
# What the driver passes on for an UNKNOWN job: its own unknown exit, the durable job's final unknowns and a transient miss.
UNKNOWN_REASONS = {"unknown": "job_exit_unknown:owner-parked", "owner-missing": "original_owner_missing", "boot-changed": "boot_changed",
                   "output-overflow": "output_overflow", "observer-lost": "observer_unavailable"}
# Known failures once the task finished, as the host job ends them: failure, stage, owner and terminal exit code.
# Only the first is the owner's own exit 1; the others are the harness's, after a task that passed or crashed.
AFTER_TASK = {"failed": ("task_exit_code", "run", 1), "evidence-failed": ("evidence_hash", "evidence", 0),
              "events-failed": ("task_events", "run", 0), "command-line-failed": ("task_command_line", "run", 0),
              "worker-crashed": ("task_exit_code", "run", -1073741819)}
DOC, DOCUMENTS, PRINCIPAL = "windows-document-acceptance", "document-persistence-transfer", "wrong-principal-owner-context-kind"
ENDPOINT = {"exists": True, "sizeBytes": 6, "creationFileTime": "133000000000000000", "lastWriteFileTime": "133000000000000001"}
PROBE_TASK = {"registered": True, "principalSid": host_job.LOCAL_SERVICE, "logonType": 5, "ran": True, "ended": True, "finished": True,
              "lastTaskResult": 0, "deleted": True, "resultRemoved": True, "code": None}
DENIED = {"state": "observed", "actualSid": host_job.LOCAL_SERVICE, "actualSessionId": 0, "accessDenied": True, "credentialOpened": False,
          "credentialBytesRead": 0, "socketOpened": False, "authenticatedCommandSent": False, "win32Error": 5}


def probe_outcome(task=None, probe=DENIED, after=ENDPOINT):
    """What the job reads from one publisher principal-probe reply (principal_outcome): an observed denial unless changed."""
    return host_job.principal_outcome({"endpoint": "C:\\fixture\\workspace\\activation.port", "before": dict(ENDPOINT), "after": dict(after),
                                       "task": {**PROBE_TASK, **(task or {})}, "probe": probe})


# The acceptance row's LOCAL SERVICE probe once its owner passed, by outcome (None: never served); stage_run ends each
# with document_principal_<reason>. Only a probe that proved no denial (here the endpoint opened) judges the product.
PROBE = {"principal-not-denied": probe_outcome(probe={"state": "refused", "code": "DOCUMENT_DIFFERENT_PRINCIPAL_CREDENTIAL_BOUNDARY"}),
         "principal-window-closed": probe_outcome(after={**ENDPOINT, "exists": False}),
         "principal-result-missing": probe_outcome(task={"finished": False, "lastTaskResult": 1}, probe=None),
         "principal-result-left": probe_outcome(task={"resultRemoved": False}),
         "principal-refused": probe_outcome(task={"ran": False, "ended": False, "finished": False, "lastTaskResult": None}),
         "principal-unserved": None}


def principal_failure(principal):
    """The known failure stage_run raises for a probe that was not observed."""
    state = None if principal is None else principal["state"]
    return "document_principal_" + ("unserved" if state is None else state if state != "failed" else principal["reason"])


class FakeDriver:
    """The VM: real receipts and real projections, by the outcome each correlation was given."""

    def __init__(self, case):
        self.case, self.outcomes = case, {}

    @staticmethod
    def identity(plan):
        return execution.JobIdentity("windows-" + plan.correlation_id, 4242, 987654, HOME + "/scenario-receipt.json")

    def submit(self, plan):
        return self.identity(plan)

    def discover(self, plan):
        return self.identity(plan)

    def observe(self, plan, identity):
        kind = self.outcomes[plan.correlation_id]
        if kind == "submitted":
            return execution.DriverObservation(execution.ObservationStatus.RUNNING, "original_owner_running", identity)
        if kind in UNKNOWN_REASONS:
            return execution.DriverObservation(execution.ObservationStatus.UNKNOWN, UNKNOWN_REASONS[kind], identity)
        receipt = {**plan.as_dict(), "jobId": identity.job_id, "pid": identity.pid, "startTicks": identity.start_ticks,
                   "exitCode": self.exit_code(kind)}
        return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "remote_receipt", identity, receipt,
                                           (identity.receipt_path,))

    @staticmethod
    def exit_code(kind):
        return 2 if kind == "refused" else 1 if kind in AFTER_TASK or kind in PROBE or kind == "failed-before-task" else 0

    def collect(self, plan, identity):
        kind = self.outcomes[plan.correlation_id]
        code = self.exit_code(kind)
        if code == 2:
            return None  # A job refused before it started leaves no receipt.
        failure, stage, owner = AFTER_TASK.get(kind, (None, "receipt", 0))
        if kind in PROBE:
            failure, stage = principal_failure(PROBE[kind]), "run"
        finished = {"state": "task-finished", "ownerExitCode": owner, "terminalExitCode": owner,
                    "events": [{}, {}, {}], "taskDeleted": True, "parkedFiles": []}
        package = self.case.packages[plan.artifact_ids.get("targetPackage")] if "targetPackage" in plan.artifact_ids else None
        claimed = kind == "passed" and package is not None
        receipt = host_job.build_receipt(
            {"scenarioId": plan.scenario_id, "operationId": plan.correlation_id, "machine": plan.environment, "bundleHash": plan.bundle_hash,
             "stopAfter": "publish" if kind == "stopped" else None},
            exit_code=code, stage="publish" if kind == "failed-before-task" else stage,
            failure={"failed-before-task": "installed_tree_differs", "overflow": "x" * 9000}.get(kind, failure),
            task=None if kind in ("stopped", "failed-before-task") else finished,
            windows={"installedPackage": claimed, "packageSha256": package if claimed else None})
        document = windows.RECIPES[plan.scenario_id].get("document")
        if document:  # As the job's _finish adds it: the row's variant and what its probe showed (None: never served).
            receipt["document"] = {"variant": document["variant"],
                                   "principal": PROBE.get(kind, probe_outcome() if kind == "passed" else None) if document["principalProbe"] else None}
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return windows.NativeScenarioWindowsDriver(self.case.root, lambda value: self.case.root)._summary(
            plan, raw, {"schemaVersion": 1, "operationId": plan.correlation_id, "exitCode": code})


@unittest.skipUnless(os.name == "posix", "private scenario journals are POSIX")
class MatrixBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "repository"
        self.root.mkdir()
        self.sources = self.work / "packages"
        self.sources.mkdir(mode=0o700)
        self.source, self.other_source = "1" * 40, "4" * 40
        self.packages = {}
        self.target = self.register(b"MSI target " * 2000, "vpn-control-2.2.17.msi", "desktop-package", self.source)
        self.set_id = "artifact-set-" + "2" * 64
        self.prior = str(uuid.uuid4())
        self.bundle_hash = "3" * 64
        self.driver = FakeDriver(self)
        self.executor = execution.ScenarioExecutor(self.root.joinpath(*windows._JOURNALS), self.driver)
        patcher = mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": TEST_TABLE})
        patcher.start()
        self.addCleanup(patcher.stop)

    def register(self, raw, name, kind, source=None):
        directory = Path(tempfile.mkdtemp(dir=self.sources))
        path = directory / name
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        record = {"platform": "windows", "artifactKind": kind, "localPath": str(path), "sha256": digest, "size": len(raw),
                  "evidenceClass": "local-verified", **({"sourceSha": source} if source else {})}
        artifact = registry.register_artifact(self.root, record)["artifactId"]
        self.assertEqual("sha256-" + digest, artifact)
        self.packages[artifact] = digest
        return artifact

    def row(self, scenario, route="direct", kind="passed", *, target=None, source=None, machine=MACHINE):
        correlation = str(uuid.uuid4())
        recipe = windows.RECIPES[scenario]
        artifacts = {"bundleManifest": "sha256-" + self.bundle_hash}
        if "scenarioInput" in recipe["artifactKeys"]:
            value = {"schema": windows.INPUT_SCHEMA, "schemaVersion": 1, "scenarioId": scenario, "correlationId": correlation,
                     "deploymentId": machine, "sourceSha": source or self.source, "productVersion": "2.2.17", "artifactSetId": self.set_id,
                     "priorInstall": self.prior if recipe["priorInstall"] else None}
            artifacts["scenarioInput"] = self.register(json.dumps(value, sort_keys=True).encode(), "input.json", "scenario-input")
        for role in recipe["artifactKeys"]:
            if role in windows.PACKAGE_KINDS:
                artifacts[role] = target or self.target
        self.driver.outcomes[correlation] = kind
        self.executor.start({"scenarioId": scenario, "host": "fixture", "environment": machine, "bundleHash": self.bundle_hash,
                             "artifactIds": artifacts, "correlationId": correlation})
        if kind != "submitted":
            self.executor.status(correlation)
        if route is not None:
            local = self.root.joinpath(*windows._LOCAL_STATE, correlation)
            local.mkdir(mode=0o700, parents=True)
            windows._create_private(local / windows.ROUTE_NAME, json.dumps(
                {"schemaVersion": 1, "correlationId": correlation, "route": route}, sort_keys=True).encode())
        return correlation

    def complete(self):
        return [self.row(SMK, "direct"), self.row(SMK, "mcp"), self.row(SSH, "direct"), self.row(SSH, "mcp")]

    def observe(self, rows, requirement="windows-native-cli", attestation=REVIEW):
        return windows.matrix_observation(self.root, requirement, rows, attestation)

    def assert_refused(self, rows, reason, requirement="windows-native-cli"):
        with self.assertRaises(windows.NativeScenarioWindowsError) as caught:
            self.observe(rows, requirement)
        self.assertEqual(reason, str(caught.exception))


class CompleteSetTests(MatrixBase):
    def test_a_complete_set_yields_the_record_matrix_record_accepts(self):
        rows = self.complete()
        observation = self.observe(rows)
        self.assertEqual({"requirementId", "platform", "originalSourceSHA", "immutableArtifactIDs", "evidencePath", "evidenceHash",
                          "environment", "result", "scenarioResults", "missingEvidence", "nextFixedCommand", "reviewerAttestation",
                          "evidenceScope"}, set(observation))
        self.assertEqual(("passed", "full-native", "windows", self.source, [self.target], [], "none", REVIEW, "windows-qemu-" + MACHINE),
                         tuple(observation[key] for key in ("result", "evidenceScope", "platform", "originalSourceSHA", "immutableArtifactIDs",
                                                            "missingEvidence", "nextFixedCommand", "reviewerAttestation", "environment")))
        self.assertEqual({name: "passed" for name in NATIVE}, observation["scenarioResults"])
        path = self.root / observation["evidencePath"]
        self.assertTrue(observation["evidencePath"].startswith(".rag_index/native-acceptance-evidence/windows-native-cli-"))
        self.assertEqual(observation["evidenceHash"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(path.parent.stat().st_mode))
        document = json.loads(path.read_bytes())
        self.assertEqual(set(rows), {row["correlationId"] for row in document["rows"]})
        journals = {row: json.loads((self.root.joinpath(*windows._JOURNALS) / (row + ".json")).read_text()) for row in rows}
        for entry in document["rows"]:
            summary = json.loads(journals[entry["correlationId"]]["collection"]["rawJson"])
            self.assertEqual(hashlib.sha256(summary["actualReceiptRaw"].encode()).hexdigest(), entry["receiptSha256"], "each receipt is hashed")
            self.assertEqual("passed", entry["classification"])
        self.assertNotIn(REVIEW, path.read_text(), "the attestation is the coordinator's record, not evidence")
        recorded = matrix.matrix_record(self.root, observation)
        self.assertEqual(("passed", self.source), (recorded["result"], recorded["originalSourceSHA"]))
        status = next(row for row in matrix.matrix_status(self.root, self.source)["requirements"]
                      if row["requirementId"] == "windows-native-cli")
        self.assertEqual("passed", status["status"])

    def test_a_passed_requirement_is_recorded_once(self):
        rows = self.complete()
        first = self.observe(rows)
        recorded = matrix.matrix_record(self.root, first)
        self.assert_refused(rows, "windows_matrix_already_recorded")
        self.assert_refused(self.complete(), "windows_matrix_already_recorded")
        matrix.matrix_retract(self.root, {"receiptId": recorded["receiptId"], "reason": "overstated", "reviewer": "coordinator"})
        again = self.observe(rows)
        self.assertEqual((first["evidencePath"], first["evidenceHash"]), (again["evidencePath"], again["evidenceHash"]),
                         "the same rows are the same create-only evidence")

    def test_the_document_requirement_is_recorded_limited_without_android(self):
        documents = {name: (SMK,) for name in windows.MATRIX_SCENARIOS["document-persistence-transfer"]}
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"document-persistence-transfer": documents}):
            observation = self.observe([self.row(SMK, "direct"), self.row(SMK, "mcp")], "document-persistence-transfer")
        self.assertEqual(("passed", "limited", "cross-platform", ["android-48m-heap"], 16),
                         (observation["result"], observation["evidenceScope"], observation["platform"], observation["missingEvidence"],
                          len(observation["scenarioResults"])))
        matrix.matrix_record(self.root, observation)
        status = next(row for row in matrix.matrix_status(self.root, self.source)["requirements"]
                      if row["requirementId"] == "document-persistence-transfer")
        self.assertEqual("open", status["status"], "a limited record never closes the shared row")
        self.assertEqual(16, len(status["limitedPassedScenarios"]))

    def test_rows_on_several_clones_name_them_by_digest(self):
        rows = [self.row(SMK, "direct"), self.row(SMK, "mcp", machine=OTHER_MACHINE), self.row(SSH, "direct"), self.row(SSH, "mcp")]
        environment = self.observe(rows)["environment"]
        self.assertRegex(environment, r"\Awindows-qemu-2-clones-[0-9a-f]{12}\Z")

    def test_setup_rows_in_the_set_are_shown_and_never_counted(self):
        setup = self.row("windows-msi-base-install", "direct")
        observation = self.observe([*self.complete(), setup])
        document = json.loads((self.root / observation["evidencePath"]).read_bytes())
        self.assertEqual("setup", next(row["classification"] for row in document["rows"] if row["correlationId"] == setup))
        table = dict(TEST_TABLE, **{NATIVE[0]: ("windows-msi-base-install",)})
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": table}):
            rows = [*self.complete(), self.row("windows-msi-base-install", "direct"), self.row("windows-msi-base-install", "mcp")]
            self.assert_refused(rows, "windows_matrix_incomplete:1")


class NeverCountsTests(MatrixBase):
    def assert_incomplete(self, replacement, classification="passed"):
        rows = [self.row(SMK, "direct"), replacement, self.row(SSH, "direct"), self.row(SSH, "mcp")]
        review = windows.matrix_review(self.root, "windows-native-cli", rows)
        self.assertEqual(classification, next(row["classification"] for row in review["rows"] if row["correlationId"] == replacement))
        self.assert_refused(rows, "windows_matrix_incomplete:10")
        self.assertFalse(self.root.joinpath(*windows._MATRIX_EVIDENCE).exists(), "nothing is written for an incomplete set")

    def test_a_missing_mcp_twin_never_counts(self):
        self.assert_incomplete(self.row(SMK, "direct"))

    def test_a_row_without_a_recorded_route_never_counts(self):
        self.assert_incomplete(self.row(SMK, None))

    def test_a_stopped_row_never_counts(self):
        self.assert_incomplete(self.row(SMK, "mcp", "stopped"), "stopped")

    def test_an_installed_package_unproven_row_never_counts(self):
        self.assert_incomplete(self.row(SMK, "mcp", "unproven"), "installed-package-unproven")

    def test_a_failure_before_the_task_never_counts(self):
        self.assert_incomplete(self.row(SMK, "mcp", "failed-before-task"), "failed-before-task")

    def test_a_harness_failure_after_the_task_never_counts_or_fails_the_requirement(self):
        # The task ran, then the harness failed: its evidence copy after a passed task, the task journal, the command
        # line read, or a worker that crashed. Only the owner's own exit 1 is the product's failure.
        for kind in ("evidence-failed", "events-failed", "command-line-failed", "worker-crashed"):
            with self.subTest(kind=kind):
                self.assert_incomplete(self.row(SMK, "mcp", kind), "failed-after-task")
                self.assert_refused([self.row(SMK, "direct", kind)], "windows_matrix_incomplete:15")
        self.assertFalse(self.root.joinpath(*windows._MATRIX_EVIDENCE).exists(), "no failed record is made of a harness failure")

    def test_a_refused_row_never_claims(self):
        self.assert_incomplete(self.row(SMK, "mcp", "refused"), "refused")

    def test_a_mixed_source_or_package_is_refused(self):
        mixed = self.row(SMK, "mcp", source=self.other_source)
        self.assert_refused([self.row(SMK, "direct"), mixed, self.row(SSH, "direct"), self.row(SSH, "mcp")], "windows_matrix_mixed_source")
        other = self.register(b"MSI other " * 2000, "vpn-control-2.2.17.msi", "desktop-package", self.source)
        mixed = self.row(SMK, "mcp", target=other)
        self.assert_refused([self.row(SMK, "direct"), mixed, self.row(SSH, "direct"), self.row(SSH, "mcp")], "windows_matrix_mixed_package")

    def test_an_unsettled_row_refuses_the_whole_observation(self):
        running = self.row(SMK, "mcp", "submitted")
        self.assert_refused([*self.complete(), running], "windows_matrix_row_unsettled:" + running)
        lost = self.row(SMK, "mcp", "observer-lost")  # A missed read proves nothing; the next status reads again.
        self.assert_refused([*self.complete(), lost], "windows_matrix_row_unsettled:" + lost)
        absent = str(uuid.uuid4())
        self.assert_refused([*self.complete(), absent], "windows_matrix_journal_unavailable:" + absent)


class FailedAndUnknownTests(MatrixBase):
    def test_a_failed_row_yields_failed_at_once(self):
        failed = self.row(SMK, "direct", "failed")
        observation = self.observe([failed])
        self.assertEqual(("failed", "inspect-evidence", "full-native"),
                         (observation["result"], observation["nextFixedCommand"], observation["evidenceScope"]))
        self.assertEqual({name: "failed" for name in NATIVE[:10]}, observation["scenarioResults"])
        self.assertEqual(sorted(NATIVE[10:]), observation["missingEvidence"])
        document = json.loads((self.root / observation["evidencePath"]).read_bytes())
        self.assertEqual([("failed", "task_exit_code")], [(row["classification"], row["failure"]) for row in document["rows"]])
        matrix.matrix_record(self.root, observation)
        status = next(row for row in matrix.matrix_status(self.root, self.source)["requirements"] if row["requirementId"] == "windows-native-cli")
        self.assertEqual("failed", status["status"])

    def test_a_failure_wins_over_a_passed_twin_and_an_unknown_row(self):
        rows = [self.row(SMK, "direct"), self.row(SMK, "mcp", "failed"), self.row(SSH, "direct", "unknown")]
        observation = self.observe(rows)
        self.assertEqual("failed", observation["result"])
        self.assertEqual({**{name: "failed" for name in NATIVE[:10]}, **{name: "unknown" for name in NATIVE[10:]}}, observation["scenarioResults"])

    def test_an_unknown_row_yields_unknown_at_once(self):
        for kind in ("unknown", "overflow"):
            with self.subTest(kind=kind):
                observation = self.observe([self.row(SSH, "mcp", kind)])
                self.assertEqual(("unknown", {name: "unknown" for name in NATIVE[10:]}),
                                 (observation["result"], observation["scenarioResults"]))
                matrix.matrix_record(self.root, observation)

    def test_a_missing_owner_a_host_boot_or_an_overflowed_stream_is_unknown_at_once(self):
        # The durable job's final UNKNOWNs: no terminal and no owner, a host boot since submit, a terminal that overflowed.
        for kind in ("owner-missing", "boot-changed", "output-overflow"):
            with self.subTest(kind=kind):
                row = self.row(SSH, "mcp", kind)
                observation = self.observe([row])
                self.assertEqual(("unknown", {name: "unknown" for name in NATIVE[10:]}),
                                 (observation["result"], observation["scenarioResults"]))
                document = json.loads((self.root / observation["evidencePath"]).read_bytes())
                self.assertEqual([(row, "unknown")], [(entry["correlationId"], entry["classification"]) for entry in document["rows"]])
                matrix.matrix_record(self.root, observation)

    def test_a_pass_needs_every_failed_or_unknown_run_of_its_package_recorded_first(self):
        rows = self.complete()
        failed, lost = self.row(SMK, "direct", "failed"), self.row(SSH, "mcp", "boot-changed")
        # Runs that say nothing of this package's counted rows never stand in the way: another package, a row this
        # requirement does not count, a harness failure and a run still going.
        other = self.register(b"MSI other " * 2000, "vpn-control-2.2.17.msi", "desktop-package", self.source)
        for scenario, kind, target in ((SMK, "failed", other), (CFG, "failed", None), (SMK, "evidence-failed", None),
                                       (SMK, "submitted", None)):
            self.row(scenario, "direct", kind, target=target)
        self.assert_refused(rows, "windows_matrix_unrecorded_outcome:" + min(failed, lost))
        matrix.matrix_record(self.root, self.observe([failed]))
        self.assert_refused(rows, "windows_matrix_unrecorded_outcome:" + lost)
        matrix.matrix_record(self.root, self.observe([lost]))
        observation = self.observe(rows)
        self.assertEqual("passed", observation["result"])
        matrix.matrix_record(self.root, observation)
        status = next(row for row in matrix.matrix_status(self.root, self.source)["requirements"] if row["requirementId"] == "windows-native-cli")
        self.assertEqual("conflicting", status["status"], "the recorded failure still stands beside the pass")

    def test_with_the_real_table_the_ssh_row_proves_no_scenario_alone(self):
        # The row declares a relayed transfer and a stdin import still to do, so ssh-import-routing stays unmapped.
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": MATRIX_REAL["windows-native-cli"]}):
            self.assert_refused([self.row(SSH, "direct", "failed")], "windows_matrix_incomplete:15")
            # Smoke and CLI config rows prove packaged-public-cli and unicode-space-path only.
            complete = [self.row(name, route) for name in (SMK, CFG, SSH) for route in ("direct", "mcp")]
            self.assert_refused(complete, "windows_matrix_incomplete:13")
            review = windows.matrix_review(self.root, "windows-native-cli", complete)
            self.assertEqual("unmapped", review["scenarios"]["ssh-import-routing"])


class PrincipalVerdictTests(MatrixBase):
    """The acceptance row's LOCAL SERVICE probe judges the product after its owner passed and exited 0."""

    def documents_status(self):
        return next(row for row in matrix.matrix_status(self.root, self.source)["requirements"] if row["requirementId"] == DOCUMENTS)

    def test_a_probe_that_proved_no_denial_fails_its_own_scenario_at_once(self):
        failed = self.row(DOC, "direct", "principal-not-denied")
        review = windows.matrix_review(self.root, DOCUMENTS, [failed])
        self.assertEqual(("failed-principal", "document_principal_not_denied", 1),
                         tuple(review["rows"][0][key] for key in ("classification", "failure", "exitCode")))
        observation = self.observe([failed], DOCUMENTS)
        self.assertEqual(("failed", {PRINCIPAL: "failed"}, "inspect-evidence", "limited"),
                         tuple(observation[key] for key in ("result", "scenarioResults", "nextFixedCommand", "evidenceScope")))
        self.assertEqual(sorted(set(matrix.load_requirements()[DOCUMENTS]["requiredScenarios"]) - {PRINCIPAL}), observation["missingEvidence"])
        matrix.matrix_record(self.root, observation)
        self.assertEqual("failed", self.documents_status()["status"])

    def test_the_row_s_other_scenarios_never_count_that_run(self):
        # The owner passed every case, so the run neither passes nor fails DOC's other scenarios; a passed pair proves them.
        rows = [self.row(DOC, "direct"), self.row(DOC, "mcp"), self.row(DOC, "mcp", "principal-not-denied")]
        scenarios = windows.matrix_review(self.root, DOCUMENTS, rows)["scenarios"]
        alone = sorted(name for name, names in windows.MATRIX_SCENARIOS[DOCUMENTS].items() if names == (DOC,) and name != PRINCIPAL)
        self.assertEqual(6, len(alone))
        self.assertEqual(("failed", {"passed"}), (scenarios[PRINCIPAL], {scenarios[name] for name in alone}))
        self.assertEqual({PRINCIPAL: "failed"}, self.observe(rows, DOCUMENTS)["scenarioResults"])

    def test_it_holds_a_later_pass_of_the_package_until_it_is_recorded(self):
        documents = {name: (DOC,) for name in windows.MATRIX_SCENARIOS[DOCUMENTS]}
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {DOCUMENTS: documents}):
            rows = [self.row(DOC, "direct"), self.row(DOC, "mcp")]
            failed = self.row(DOC, "mcp", "principal-not-denied")  # Never named: the scan of the package's settled runs finds it.
            self.assert_refused(rows, "windows_matrix_unrecorded_outcome:" + failed, DOCUMENTS)
            matrix.matrix_record(self.root, self.observe([failed], DOCUMENTS))
            observation = self.observe(rows, DOCUMENTS)
        self.assertEqual("passed", observation["result"])
        matrix.matrix_record(self.root, observation)
        status = self.documents_status()
        self.assertEqual(("conflicting", [PRINCIPAL]), (status["status"], status["conflictingScenarios"]),
                         "the recorded failure stands beside the pass for its own scenario only")

    def test_it_judges_no_other_requirement(self):
        # Were the row named elsewhere, its probe verdict would neither fail nor hold that requirement.
        table = dict(TEST_TABLE, **{name: (DOC,) for name in NATIVE[:10]})
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": table}):
            self.assert_refused([self.row(DOC, "direct", "principal-not-denied")], "windows_matrix_incomplete:15")
            rows = [self.row(DOC, "direct"), self.row(DOC, "mcp"), self.row(SSH, "direct"), self.row(SSH, "mcp")]
            self.assertEqual("passed", self.observe(rows)["result"])

    def test_the_probe_s_other_ends_are_the_harness_s_and_never_count(self):
        for kind in ("principal-window-closed", "principal-result-missing", "principal-result-left", "principal-refused", "principal-unserved"):
            with self.subTest(kind=kind):
                row = self.row(DOC, "mcp", kind)
                review = windows.matrix_review(self.root, DOCUMENTS, [row])
                self.assertEqual(("failed-after-task", principal_failure(PROBE[kind])),
                                 (review["rows"][0]["classification"], review["rows"][0]["failure"]))
                self.assert_refused([row], "windows_matrix_incomplete:16", DOCUMENTS)
        self.assertFalse(self.root.joinpath(*windows._MATRIX_EVIDENCE).exists(), "no failed record is made of a harness failure")


class InputTests(MatrixBase):
    def test_inputs_are_closed(self):
        rows = self.complete()
        for requirement in ("linux-native-cli", None, "windows-unknown"):
            self.assert_refused(rows, "windows_matrix_requirement_unknown", requirement)
        for value in ([], [rows[0], rows[0]], [rows[0].upper()], "not-a-list", [7]):
            with self.subTest(value=value):
                self.assert_refused(value, "windows_matrix_correlations_invalid")
        for attestation in ("", "   ", "x" * 241, None):
            with self.subTest(attestation=attestation), self.assertRaises(windows.NativeScenarioWindowsError) as caught:
                self.observe(rows, attestation=attestation)
            self.assertEqual("windows_matrix_attestation_invalid", str(caught.exception))

    def test_evidence_is_create_only(self):
        rows = self.complete()
        path = self.root / self.observe(rows)["evidencePath"]
        path.chmod(0o600)
        path.write_bytes(b"{}\n")
        self.assert_refused(rows, "windows_matrix_evidence_differs")

    @contextlib.contextmanager
    def full_disk(self):
        """Every binary write of the observation stores half its bytes, then fails as a full disk does."""
        real = os.fdopen

        class Torn:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.stream.close()

            def write(self, raw):
                self.stream.write(raw[:len(raw) // 2])
                self.stream.flush()
                raise OSError(errno.ENOSPC, "No space left on device")

            def __getattr__(self, name):
                return getattr(self.stream, name)

        def fdopen(descriptor, mode="r", *args, **kwargs):
            stream = real(descriptor, mode, *args, **kwargs)
            return Torn(stream) if mode == "wb" else stream
        with mock.patch.object(os, "fdopen", fdopen):
            yield

    def test_an_interrupted_evidence_write_leaves_nothing_under_its_name(self):
        rows = self.complete()
        with self.full_disk(), self.assertRaises((OSError, windows.NativeScenarioWindowsError)) as caught:
            self.observe(rows)
        directory = self.root.joinpath(*windows._MATRIX_EVIDENCE)
        self.assertEqual([], [path.name for path in directory.iterdir() if path.name.startswith("windows-native-cli-")],
                         "no part of a document is left under its digest name")
        self.assertEqual("windows_matrix_evidence_unavailable", str(caught.exception))
        observation = self.observe(rows)
        self.assertEqual(observation["evidenceHash"], hashlib.sha256((self.root / observation["evidencePath"]).read_bytes()).hexdigest())
        matrix.matrix_record(self.root, observation)

    def test_the_entry_point_refuses_a_ledger_or_evidence_failure_finitely(self):
        rows = self.complete()

        def run():
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = windows.main(["matrix-observation", "--root", str(self.root), "--requirement", "windows-native-cli",
                                     "--reviewer-attestation", REVIEW, *rows])
            return code, stdout.getvalue(), json.loads(stderr.getvalue().splitlines()[-1])
        with self.full_disk():
            self.assertEqual((1, "", {"refused": "windows_matrix_evidence_unavailable"}), run())
        ledger = self.root / matrix.RECEIPTS_RELATIVE
        ledger.mkdir(mode=0o700)
        foreign = ledger / "foreign.json"  # Not a receipt: the ledger refuses to read it, and so does the observation.
        foreign.write_bytes(b"{}\n")
        foreign.chmod(0o600)
        self.assertEqual((1, "", {"refused": "windows_matrix_ledger_unavailable"}), run())

    def test_the_entry_point_prints_the_observation_and_records_nothing(self):
        rows = self.complete()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = windows.main(["matrix-observation", "--root", str(self.root), "--requirement", "windows-native-cli",
                                 "--reviewer-attestation", REVIEW, *rows])
        self.assertEqual(0, code)
        self.assertEqual(self.observe(rows), json.loads(stdout.getvalue()))
        self.assertEqual("passed", json.loads(stderr.getvalue())["scenarios"][NATIVE[0]])
        self.assertFalse((self.root / matrix.RECEIPTS_RELATIVE).exists(), "recording stays matrix-record")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = windows.main(["matrix-observation", "--root", str(self.root), "--requirement", "windows-native-cli",
                                 "--reviewer-attestation", REVIEW, rows[0]])
        self.assertEqual((1, ""), (code, stdout.getvalue()))
        self.assertIn('"refused": "windows_matrix_incomplete:15"', stderr.getvalue())


MATRIX_REAL = {key: dict(value) for key, value in windows.MATRIX_SCENARIOS.items()}


class TableTests(unittest.TestCase):
    def test_the_table_names_every_windows_scenario_and_only_built_rows(self):
        requirements = matrix.load_requirements()
        windows_requirements = {name for name, value in requirements.items() if value["platform"] == "windows"}
        self.assertEqual(windows_requirements | {"document-persistence-transfer"}, set(MATRIX_REAL))
        self.assertEqual(48, sum(len(requirements[name]["requiredScenarios"]) for name in windows_requirements))
        for name, table in MATRIX_REAL.items():
            applicable = [item for item in requirements[name]["requiredScenarios"] if item not in windows.MATRIX_LIMITED.get(name, ())]
            self.assertEqual(sorted(applicable), sorted(table), name)
            for scenario, rows in table.items():
                self.assertTrue(set(rows) <= set(windows.RECIPES), (name, scenario))
                self.assertFalse({row for row in rows if windows.RECIPES[row]["evidenceClass"] != "product"}, "setup rows never prove a scenario")
        self.assertEqual(16, len(MATRIX_REAL["document-persistence-transfer"]))
        self.assertEqual({"android-48m-heap"}, set(requirements["document-persistence-transfer"]["requiredScenarios"])
                         - set(MATRIX_REAL["document-persistence-transfer"]))
        unmapped = sorted(name + ":" + scenario for name, table in MATRIX_REAL.items() for scenario, rows in table.items() if not rows)
        self.assertEqual(sorted(["windows-native-cli:" + item for item in ("scoped-elevation", "gui-attach-detach", "ssh-import-routing")]
                                + ["windows-visual:" + item for item in ("scene-capture", "geometry-contrast", "agent-verdict")]
                                + ["windows-scoped-vpn:" + item for item in ("scoped-uac-tun-traffic", "prepare-commit-recovery", "exact-child-stop",
                                                                             "generated-custom-config", "large-config", "dns-ws-ssh-cache-resources",
                                                                             "pipe-storage-races")]
                                + ["windows-owner-lifecycle:" + item for item in ("close-detach-traffic", "scheduled-without-gui")]
                                + ["document-persistence-transfer:" + item for item in ("cache-digest-bytes", "gui-cli-transfer")]),
                         unmapped)
        # The SSH row declares a relayed transfer and a stdin key import still to do, so it proves no scenario alone.
        self.assertFalse([scenario for table in MATRIX_REAL.values() for scenario, rows in table.items() if SSH in rows])

    def test_no_update_row_can_prove_a_scenario_today(self):
        # The host job never claims installed-package for an update row, so a scenario naming one stays unproven.
        named = {scenario for table in MATRIX_REAL.values() for scenario, rows in table.items()
                 if any(row.startswith("windows-public-update.") for row in rows)}
        self.assertEqual({"msi-installer", "public-update", "operation-progress-cancellation", "traffic-continuity", "msi-uac-grant-denial",
                          "ordinary-elevated-owner", "different-approving-admin", "original-user-worker", "participating-copy-locks",
                          "protected-storage-adversarial", "next-owner-recovery", "reconnect-off-preserved"}, named)
        # The installer lifecycle maps every scenario, but each update variant it names is refused at admission today.
        lifecycle = MATRIX_REAL["windows-installer-lifecycle"]
        self.assertTrue(all(lifecycle.values()))
        self.assertEqual(set(), {row for rows in lifecycle.values() for row in rows
                                 if row.startswith("windows-public-update.") and windows.RECIPES[row]["refusal"] is None})

    def test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds(self):
        named = {row: sorted(name + ":" + scenario for name, table in MATRIX_REAL.items() for scenario, rows in table.items() if row in rows)
                 for row in windows.RECIPES}
        rsp, doc, cfg = "windows-document-responsive", "windows-document-acceptance", "windows-disconnected-cli-config"
        # design.md adapter steps 4, 7 and 8: RSP is responsive-status-cancel, cli-disconnect-long-work and its part of
        # operation-progress-cancellation, whose other rows include an update variant refused at admission today.
        self.assertEqual(["document-persistence-transfer:responsive-status-cancel", "windows-native-cli:operation-progress-cancellation",
                          "windows-owner-lifecycle:cli-disconnect-long-work"], named[rsp])
        self.assertEqual(("windows-disconnected-cli-config", "windows-streaming-client-interrupt", rsp, "windows-proxy-lifecycle.find-best-cancel",
                          "windows-public-update.download-cancelled", "windows-public-update.install-cancelled"),
                         MATRIX_REAL["windows-native-cli"]["operation-progress-cancellation"])
        self.assertIsNotNone(windows.RECIPES["windows-public-update.install-cancelled"]["refusal"])
        # Only the admitted TUN denial counts, and only for its own scenario; the grant rows are refused at admission.
        self.assertEqual({"windows-scoped-tun.restart-deny": ["windows-scoped-vpn:denial-preserves-active-a"]},
                         {row: scenarios for row, scenarios in named.items() if row.startswith("windows-scoped-tun.") and scenarios})
        # gui-owner is only the CLI half of gui-cli-transfer, and cache-bytes is refused before any journal: both stay missing.
        self.assertEqual([], named["windows-document-cold.gui-owner"] + named["windows-document-cold.cache-bytes"])
        documents = MATRIX_REAL["document-persistence-transfer"]
        self.assertEqual(((), ()), (documents["gui-cli-transfer"], documents["cache-digest-bytes"]))
        self.assertEqual({doc, rsp, cfg, "windows-document-cold.cold-reopen", "windows-document-cold.legacy-newline"},
                         {row for rows in documents.values() for row in rows})
        self.assertEqual({"large-import-readback", "retained-result-export", "private-no-overwrite-export", "unicode-surrogate"},
                         {scenario for scenario, rows in documents.items() if cfg in rows}, "design.md step 8: these take DOC and CFG")
        self.assertEqual({"document-persistence-transfer": ("android-48m-heap",)}, windows.MATRIX_LIMITED)
        # The one probe verdict judges the one scenario whose rows are exactly the rows that run the probe.
        probes = {row for row, recipe in windows.RECIPES.items() if (recipe.get("document") or {}).get("principalProbe")}
        self.assertEqual(({DOC}, {DOCUMENTS: PRINCIPAL}), (probes, windows.MATRIX_PRINCIPAL))
        self.assertEqual((DOC,), documents[PRINCIPAL])
        # Every row the table names outside the update family is admitted today; the update rows stay unproven (above).
        self.assertEqual(set(), {row for row, scenarios in named.items() if scenarios and not row.startswith("windows-public-update.")
                                 and (windows.RECIPES[row].get("refusal") is not None or windows.RECIPES[row]["evidenceClass"] != "product")})


if __name__ == "__main__":
    unittest.main()
