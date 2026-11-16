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
from agent_tools.windows_public_updater import update_cases

MACHINE = "33333333-4444-4555-8666-777777777777"
OTHER_MACHINE = "33333333-4444-4555-8666-888888888888"
HOME = "/home/fixture-owner"
SMK, SSH, CFG = "windows-packaged-cli-smoke", "windows-disconnected-cli-config.ssh-import-routing", "windows-disconnected-cli-config"
RLY = "windows-disconnected-cli-config.ssh-relay-transfer"
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
        self.extra = {}  # Receipt fields a row's job wrote beyond these (an install's record, an update's names and claim).

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
        receipt.update(json.loads(json.dumps(self.extra.get(plan.correlation_id, {}))))
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

    def row(self, scenario, route="direct", kind="passed", *, target=None, source=None, machine=MACHINE, extra=None, value=None,
            artifacts=None):
        """One run journaled by the real executor; extra, value and artifacts add receipt fields, input fields and artifact IDs."""
        correlation = str(uuid.uuid4())
        recipe = windows.RECIPES[scenario]
        named = {"bundleManifest": "sha256-" + self.bundle_hash}
        if "scenarioInput" in recipe["artifactKeys"]:
            fields = {"schema": windows.INPUT_SCHEMA, "schemaVersion": 1, "scenarioId": scenario, "correlationId": correlation,
                      "deploymentId": machine, "sourceSha": source or self.source, "productVersion": "2.2.17", "artifactSetId": self.set_id,
                      "priorInstall": self.prior if recipe["priorInstall"] else None, **(value or {})}
            named["scenarioInput"] = self.register(json.dumps(fields, sort_keys=True).encode(), "input.json", "scenario-input")
        for role in recipe["artifactKeys"]:
            if role in windows.PACKAGE_KINDS:
                named[role] = target or self.target
        artifacts = {**named, **(artifacts or {})}
        self.driver.outcomes[correlation] = kind
        if extra is not None:
            self.driver.extra[correlation] = extra
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

    def test_with_the_real_table_ssh_import_routing_needs_both_ssh_rows(self):
        # The SSH row leaves a relayed transfer and a stdin key import to the relay row, which does both: the scenario
        # passes only with each row passed through both routes, and a failure of either row is its own at once.
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": MATRIX_REAL["windows-native-cli"]}):
            # Smoke and CLI config rows prove packaged-public-cli and unicode-space-path only; the SSH row alone, nothing.
            complete = [self.row(name, route) for name in (SMK, CFG, SSH) for route in ("direct", "mcp")]
            self.assert_refused(complete, "windows_matrix_incomplete:13")
            review = windows.matrix_review(self.root, "windows-native-cli", complete)
            self.assertEqual("missing", review["scenarios"]["ssh-import-routing"])
            relay = [self.row(RLY, route) for route in ("direct", "mcp")]
            self.assertEqual("missing", windows.matrix_review(self.root, "windows-native-cli", complete[:4] + relay)["scenarios"]["ssh-import-routing"])
            review = windows.matrix_review(self.root, "windows-native-cli", complete + relay)
            self.assertEqual("passed", review["scenarios"]["ssh-import-routing"])
            self.assert_refused(complete + relay, "windows_matrix_incomplete:12")
            for row in (SSH, RLY):
                with self.subTest(row=row):
                    observation = self.observe([self.row(row, "direct", "failed")])
                    self.assertEqual(("failed", {"ssh-import-routing": "failed"}), (observation["result"], observation["scenarioResults"]))


class ExactChildStopTests(MatrixBase):
    """windows-scoped-vpn with its real table: passed direct and MCP pairs of PRX(sibling-off) and the TUN restart grant.

    sibling-off shows a proxy off spares a live sibling runtime. The grant's off record shows its broker and runtime ended
    after the product's own off, but no unrelated runtime runs beside it, so a broker that stopped every sing-box.exe by
    image would pass it as well: together they never prove the elevated stop is exact."""

    def test_the_grant_and_sibling_off_pairs_never_pass_the_exact_child_stop(self):
        rows = [self.row(name, route) for name in ("windows-proxy-lifecycle.sibling-off", "windows-scoped-tun.restart-grant")
                for route in ("direct", "mcp")]
        review = windows.matrix_review(self.root, "windows-scoped-vpn", rows)
        self.assertEqual(["passed"] * 4, [row["classification"] for row in review["rows"]])
        self.assertEqual("passed", review["scenarios"]["scoped-uac-tun-traffic"], "the grant's own scenario passes with its pair")
        self.assertEqual("unmapped", review["scenarios"]["exact-child-stop"], "no row shows the TUN off spares a sibling")
        self.assert_refused(rows, "windows_matrix_incomplete:9", "windows-scoped-vpn")

    def test_with_the_real_table_the_cache_row_proves_no_scenario_alone(self):
        # RED on 7e6ee369, where this set passed cache-digest-bytes. CLD(cache-bytes) reads the committed cache back warm,
        # closed and cold, but the scenario's Android anchor also fails a read of truncated bytes, while the desktop store
        # writes its default workspace over a workspace.json that does not decode, and no row corrupts one.
        cache = "windows-document-cold.cache-bytes"
        names = sorted({row for rows in MATRIX_REAL[DOCUMENTS].values() for row in rows} | {cache})
        rows = [self.row(name, route) for name in names for route in ("direct", "mcp")]
        scenarios = windows.matrix_review(self.root, DOCUMENTS, rows)["scenarios"]
        self.assertEqual(("unmapped", "unmapped"), (scenarios["cache-digest-bytes"], scenarios["gui-cli-transfer"]))
        self.assertEqual({"passed"}, {state for name, state in scenarios.items() if name not in ("cache-digest-bytes", "gui-cli-transfer")})
        self.assert_refused(rows, "windows_matrix_incomplete:2", DOCUMENTS)


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


UPDATE = "windows-public-update."
BASE_VERSION = "2.2.15"
# The product and package codes the recorded S_B and S_T2 installs registered (c3da662a, c693352b): a real pair's, two of each.
BASE_CODE, BASE_PACKAGE_CODE = "{C9C4D717-A81A-3E7D-A67A-2A350331CFB9}", "{5EE5EE4E-6EE5-41CE-BB9C-E263F4C09442}"
TARGET_CODE, TARGET_PACKAGE_CODE = "{BC56AE4E-BF90-3BF6-9E5A-6599CE80CD3B}", "{BA63AD1C-479F-4ACD-B878-E62F8EA82FDC}"


def ends(variant):
    """The package a passed case of this variant leaves: the target only after a granted install that succeeded."""
    return "target" if variant in update_cases.SUCCESS_VARIANTS else "base"


# A grant's principals as its job's context reads them: the original user, the fixture administrator and the clone's
# second Administrators account (windows_vm_unattend secondAdministrator), which approves the different-admin row.
ORDINARY_SID, FIXTURE_ADMIN_SID, SECOND_ADMIN_SID = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1000", "S-1-5-21-1-2-3-1002"


# The grant rows: each collector has an authorization stage, so its installer job's coordinator and worker are observed
# (TableTests holds RECIPES to this set). A run of one names who approved it.
GRANTS = frozenset({"success-off", "different-admin", "success-reconnect", "success-explicit-off", "participating-copy-lock", "wait-client-loss",
                     "installer-wait-client-loss"})


def grant(variant):
    return variant in GRANTS


def approval_fields(variant, fields):
    """What the fixed job adds to a grant row's receipt (host_job Job._finish): the context's ordinary user, who approved
    as the context read it, and the coordinator and worker the authorization stage's SYSTEM census found."""
    approver = windows.RECIPES[UPDATE + variant].get("approver", "administrator")
    approving = SECOND_ADMIN_SID if approver == "second-administrator" else FIXTURE_ADMIN_SID
    fields["context"] = {"ordinarySid": ORDINARY_SID, "ordinarySessionId": 2, "profileRoot": None, "bootFileTimeUtc": None, "bootIdentifier": None,
                         "hardwareUuid": None, "machineGuid": None}
    fields["update"]["approval"] = {"approver": approver, "approvingAdminSid": approving, "administratorSid": FIXTURE_ADMIN_SID}
    fields["update"]["installer"] = {"coordinator": {"pid": 921, "sid": approving, "elevated": 1, "elevationType": 2, "sessionId": 2},
                                     "worker": {"pid": 922, "sid": ORDINARY_SID, "elevated": 0, "elevationType": 1, "sessionId": 2}}


def installed(digest, version, code, package_code, tree):
    """What an installer row records of the install it left (host_job Job.stage_installed)."""
    return {"packageSha256": digest, "productCode": code, "productVersion": version, "packageCode": package_code,
            "treeSha256": tree, "treeFiles": 209}


class UpdateBase(MatrixBase):
    """One clone: the target's own install recorded its tree, then a reset installed the older base, of another source,
    that every update row starts from. Each update row's input names both installs, as a real one does."""

    def setUp(self):
        super().setUp()
        self.base = self.register(b"MSI base " * 2000, "vpn-control-2.2.15.msi", "desktop-package", "5" * 40)
        self.fixture = self.register(b'{"testOnly": true}\n', "fixture-receipt.json", "desktop-update-fixture-receipt", self.source)
        self.base_facts = installed(self.packages[self.base], BASE_VERSION, BASE_CODE, BASE_PACKAGE_CODE, "a" * 64)
        self.target_facts = installed(self.packages[self.target], "2.2.17", TARGET_CODE, TARGET_PACKAGE_CODE, "b" * 64)
        self.target_install = self.install("windows-msi-base-install", self.target, self.target_facts)
        self.base_install = self.install("windows-msi-base-reset", self.base, self.base_facts)

    def install(self, scenario, package, facts, *, machine=MACHINE, kind="passed"):
        return self.row(scenario, "direct", kind, target=package, machine=machine, extra={"installed": facts})

    def update(self, variant, route="direct", kind="passed", *, role="ends", change=None, value=None, machine=MACHINE):
        """One update run as the fixed job records it: the base it found before its task, the two installs it names and the
        package read installed after the task (role: its variant's own end unless named), claimed when it passed with its
        variant's own. change edits the receipt fields first."""
        role = ends(variant) if role == "ends" else role
        after = {"base": self.base_facts, "target": self.target_facts}.get(role)
        claim = kind == "passed" and role == ends(variant)
        fields = {"installed": dict(self.base_facts),
                  "update": {"variant": variant, "collectors": {}, "baseInstall": self.base_install, "targetInstall": self.target_install,
                             "installedAfter": None if after is None else {"role": role, **after}},
                  "windows": {"installedPackage": claim, "packageSha256": after["packageSha256"] if claim else None}}
        if grant(variant):
            approval_fields(variant, fields)
        if change is not None:
            change(fields)
        return self.row(UPDATE + variant, route, kind, machine=machine, extra=fields, artifacts={"fixtureReceipt": self.fixture},
                        value={"priorInstall": self.base_install, "baseVersion": BASE_VERSION, "targetInstall": self.target_install,
                               **(value or {})})

    def classified(self, correlation):
        return windows.matrix_review(self.root, "windows-installer-lifecycle", [correlation])["rows"][0]

    def bound(self, installed_package, base=None):
        return {"baseInstall": self.base_install, "basePackage": self.base if base is None else base, "targetInstall": self.target_install,
                "installedPackage": installed_package}


class UpdateRowTests(UpdateBase):
    """GAP-UPD: the host job never claimed installed-package for an update row, so no update scenario could pass."""

    def test_a_passed_update_run_counts_with_the_package_read_after_its_task(self):
        for variant in windows.UPDATE_VARIANTS:
            with self.subTest(variant=variant):
                row = self.classified(self.update(variant))
                self.assertEqual("passed", row["classification"])
                self.assertEqual(self.bound(self.base if ends(variant) == "base" else self.target), row.get("update"),
                                 "the record names the base install, its package, the target's install and what was left")

    def test_the_update_scenarios_pass_matrix_status_once_their_rows_are_proven(self):
        """Every installer-lifecycle scenario, and the four native-cli scenarios naming update rows, pass once each named
        row has a proven direct and an MCP run on one package. Natively protected-storage-rejected always parks and the
        fault, copy-lock, reconnect and cancel rows are refused at admission: only the matrix's own rule is proven here."""
        lifecycle = MATRIX_REAL["windows-installer-lifecycle"]
        rows = []
        for name in sorted({name for names in lifecycle.values() for name in names}):
            for route in ("direct", "mcp"):
                if name.startswith(UPDATE):
                    rows.append(self.update(name[len(UPDATE):], route))
                else:  # The reboot pair of reconnect-off-preserved: a postboot names its preboot.
                    rows.append(self.row(name, route, value={"priorPreboot": str(uuid.uuid4())} if name.endswith(".post") else None))
        self.assertEqual({name: "passed" for name in lifecycle}, windows.matrix_review(self.root, "windows-installer-lifecycle", rows)["scenarios"])
        observation = self.observe(rows, "windows-installer-lifecycle")
        self.assertEqual(("passed", {name: "passed" for name in lifecycle}, sorted([self.fixture, self.target]), []),
                         (observation["result"], observation["scenarioResults"], observation["immutableArtifactIDs"],
                          observation["missingEvidence"]), "the base, of another source, is no artifact of the record")
        document = json.loads((self.root / observation["evidencePath"]).read_bytes())
        for entry in document["rows"]:
            with self.subTest(row=entry["scenarioId"]):
                if entry["scenarioId"].startswith(UPDATE):
                    self.assertEqual(self.bound(self.base if ends(entry["scenarioId"][len(UPDATE):]) == "base" else self.target), entry.get("update"))
                else:
                    self.assertNotIn("update", entry)
        matrix.matrix_record(self.root, observation)
        status = next(row for row in matrix.matrix_status(self.root, self.source)["requirements"]
                      if row["requirementId"] == "windows-installer-lifecycle")
        self.assertEqual("passed", status["status"])
        native = ("msi-installer", "public-update", "operation-progress-cancellation", "traffic-continuity")
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": MATRIX_REAL["windows-native-cli"]}):
            named = sorted({name for scenario in native for name in MATRIX_REAL["windows-native-cli"][scenario]})
            rows = [self.update(name[len(UPDATE):], route) if name.startswith(UPDATE) else self.row(name, route)
                    for name in named for route in ("direct", "mcp")]
            scenarios = windows.matrix_review(self.root, "windows-native-cli", rows)["scenarios"]
        self.assertEqual({scenario: "passed" for scenario in native}, {scenario: scenarios[scenario] for scenario in native})

    def test_an_update_run_without_its_bound_proof_never_counts(self):
        """Still refused: what the job wrote before this, and every claim with a part missing, another install's or an
        install no journal of this clone binds."""
        def old_job(fields):  # The receipt of every recorded native update run: the base matched before the task, no claim.
            fields["update"] = {"variant": fields["update"]["variant"], "collectors": {}}
            fields["windows"] = {"installedPackage": False, "packageSha256": None}

        def claim_unread(fields):
            fields["update"].pop("installedAfter")
            fields["windows"] = {"installedPackage": True, "packageSha256": self.base_facts["packageSha256"]}

        def claim(fields):  # The package read after the task, claimed although the variant ends with the other one.
            fields["windows"] = {"installedPackage": True, "packageSha256": fields["update"]["installedAfter"]["packageSha256"]}

        def other_tree(fields):
            fields["update"]["installedAfter"]["treeSha256"] = "c" * 64

        def started_elsewhere(fields):
            fields["installed"] = dict(fields["installed"], treeSha256="c" * 64)

        def other_base_install(fields):
            fields["update"]["baseInstall"] = self.target_install

        def other_digest(fields):
            fields["windows"]["packageSha256"] = "c" * 64

        cases = [("public-ready", "old-job", {"change": old_job}, None),
                 ("uac-denied", "claim-unread", {"change": claim_unread}, None),
                 ("public-ready", "the-other-install", {"role": "target", "change": claim}, self.target),
                 ("success-off", "the-other-install", {"role": "base", "change": claim}, self.base),
                 ("checksum-rejected", "no-install-s-tree", {"change": other_tree}, None),
                 ("download-cancelled", "started-elsewhere", {"change": started_elsewhere}, None),
                 ("public-ready", "another-base-install", {"change": other_base_install}, None),
                 ("uac-denied", "another-digest", {"change": other_digest}, self.base)]
        for variant, name, options, left in cases:
            with self.subTest(variant=variant, case=name):
                row = self.classified(self.update(variant, **options))
                self.assertEqual(("installed-package-unproven", left), (row["classification"], (row.get("update") or {}).get("installedPackage")))
        absent = str(uuid.uuid4())
        other_clone = self.install("windows-msi-base-reset", self.base, self.base_facts, machine=OTHER_MACHINE)
        failed = self.install("windows-msi-base-reset", self.base, self.base_facts, kind="failed")
        product = self.row("windows-packaged-cli-smoke", extra={"installed": self.base_facts})
        mislabeled = self.install("windows-msi-base-reset", self.target, self.base_facts)
        for name, prior in (("absent", absent), ("another-clone", other_clone), ("failed", failed), ("not-an-install", product),
                            ("another-package", mislabeled)):
            with self.subTest(base=name):
                def renamed(fields, prior=prior):
                    fields["update"]["baseInstall"] = prior
                row = self.classified(self.update("public-ready", change=renamed, value={"priorInstall": prior}))
                self.assertEqual(("installed-package-unproven", {"baseInstall": prior, "basePackage": None, "targetInstall": self.target_install,
                                                                 "installedPackage": None}), (row["classification"], row.get("update")))
        older = self.classified(self.update("public-ready", value={"baseVersion": "2.2.14"}))
        self.assertEqual(("installed-package-unproven", None, None),
                         (older["classification"], (older.get("update") or {}).get("basePackage", "unnamed"), (older.get("update") or {}).get("installedPackage")), "a base of another version")
        other = self.register(b"MSI other " * 2000, "vpn-control-2.2.17.msi", "desktop-package", self.source)
        elsewhere = self.install("windows-msi-base-install", other, installed(self.packages[other], "2.2.17", TARGET_CODE, TARGET_PACKAGE_CODE, "b" * 64))
        for variant in ("success-off", "wait-client-loss"):
            with self.subTest(target=variant):
                def target_renamed(fields):
                    fields["update"]["targetInstall"] = elsewhere
                row = self.classified(self.update(variant, change=target_renamed, value={"targetInstall": elsewhere}))
                self.assertEqual(("installed-package-unproven", None), (row["classification"], (row.get("update") or {}).get("installedPackage")))

    def test_a_failed_update_run_names_the_package_it_left(self):
        """A grant whose prompt ended CANCELLED is the case's own known failure: no claim, and the base read back after it
        stands in its record, so the failed record says which package is installed."""
        failed = self.update("success-off", kind="failed", role="base")
        row = self.classified(failed)
        self.assertEqual(("failed", "task_exit_code", self.bound(self.base)), (row["classification"], row["failure"], row.get("update")))
        observation = self.observe([failed], "windows-installer-lifecycle")
        self.assertEqual(("failed", "inspect-evidence"), (observation["result"], observation["nextFixedCommand"]))
        document = json.loads((self.root / observation["evidencePath"]).read_bytes())
        self.assertEqual([self.bound(self.base)], [entry.get("update") for entry in document["rows"]])
        matrix.matrix_record(self.root, observation)


class ApprovalTests(UpdateBase):
    """T6: different-approving-admin and original-user-worker had no row that proved them. different-admin was refused at
    admission, and nothing a passed grant run recorded said who approved it or as whom its installer worker ran. A grant
    row now counts only with its own receipt showing the approving account it should have (the clone's second
    Administrators account for different-admin, the fixture's for the others), the coordinator elevated under it and
    the worker unelevated as the original user."""

    PROVEN = {"approver": "second-administrator", "approvedByAnotherAdministrator": True, "coordinatorIsApprover": True, "workerIsOriginalUser": True}

    def review(self, rows):
        return windows.matrix_review(self.root, "windows-installer-lifecycle", rows)

    def test_the_different_admin_row_proves_its_two_scenarios_with_success_off(self):
        rows = [self.update(variant, route) for variant in ("different-admin", "success-off") for route in ("direct", "mcp")]
        review = self.review(rows)
        self.assertEqual(["passed"] * 4, [row["classification"] for row in review["rows"]])
        self.assertEqual([self.PROVEN] * 2 + [{**self.PROVEN, "approver": "administrator", "approvedByAnotherAdministrator": False}] * 2,
                         [row.get("approval") for row in review["rows"]])
        self.assertEqual(("passed", "passed"), tuple(review["scenarios"].get(name) for name in ("different-approving-admin", "original-user-worker")))
        # Without success-off, original-user-worker misses its other row; without different-admin, both miss it.
        self.assertEqual(("passed", "missing"), tuple(self.review(rows[:2])["scenarios"][name] for name in ("different-approving-admin", "original-user-worker")))
        self.assertEqual(("missing", "missing"), tuple(self.review(rows[2:])["scenarios"][name] for name in ("different-approving-admin", "original-user-worker")))

    def test_the_evidence_names_who_approved_each_grant(self):
        rows = [self.update(variant, route) for variant in ("different-admin", "success-off", "uac-denied") for route in ("direct", "mcp")]
        failed = self.update("different-admin", kind="failed", role="base")
        with self.assertRaises(windows.NativeScenarioWindowsError):
            self.observe(rows, "windows-installer-lifecycle")  # Incomplete: the other scenarios' rows are missing.
        observation = self.observe([*rows, failed], "windows-installer-lifecycle")
        self.assertEqual("failed", observation["result"])
        document = json.loads((self.root / observation["evidencePath"]).read_bytes())
        approvals = {entry["correlationId"]: entry.get("approval", "none") for entry in document["rows"]}
        self.assertEqual([self.PROVEN, self.PROVEN, {**self.PROVEN, "approver": "administrator", "approvedByAnotherAdministrator": False},
                          {**self.PROVEN, "approver": "administrator", "approvedByAnotherAdministrator": False}, "none", "none", self.PROVEN],
                         [approvals[correlation] for correlation in [*rows, failed]], "a deny row has no approval; a failed grant names it")

    def test_a_grant_run_without_its_approval_proven_never_counts(self):
        def old_job(fields):  # What the job wrote before T6: the installer's actors, but no approval.
            fields["update"].pop("approval")

        def approval(**changes):
            def change(fields):
                fields["update"]["approval"].update(changes)
            return change

        def actor(role, **changes):
            def change(fields):
                fields["update"]["installer"][role].update(changes)
            return change

        def ordinary(sid):
            def change(fields):
                fields["context"]["ordinarySid"] = sid
            return change

        def both(*changes):
            def change(fields):
                for item in changes:
                    item(fields)
            return change
        cases = [("different-admin", "old-job", old_job),
                 ("different-admin", "fixture-administrator-approved", approval(approver="administrator", approvingAdminSid=FIXTURE_ADMIN_SID)),
                 ("different-admin", "same-account", approval(approvingAdminSid=FIXTURE_ADMIN_SID)),
                 # Consistent in itself, the fixture administrator approving and elevating: only who approved differs.
                 ("different-admin", "the-fixture-administrator-throughout",
                  both(approval(approvingAdminSid=FIXTURE_ADMIN_SID), actor("coordinator", sid=FIXTURE_ADMIN_SID))),
                 ("different-admin", "unrecorded-fixture-administrator", approval(administratorSid=None)),
                 ("different-admin", "coordinator-another-account", actor("coordinator", sid=FIXTURE_ADMIN_SID)),
                 ("different-admin", "coordinator-not-elevated", actor("coordinator", elevated=0)),
                 ("different-admin", "worker-as-the-approver", actor("worker", sid=SECOND_ADMIN_SID)),
                 ("different-admin", "worker-elevated", actor("worker", elevated=1)),
                 ("different-admin", "ordinary-user-approved", ordinary(SECOND_ADMIN_SID)),
                 ("different-admin", "no-ordinary-user", ordinary(None)),
                 ("success-off", "old-job", old_job),
                 ("success-off", "another-administrator", approval(approvingAdminSid=SECOND_ADMIN_SID)),
                 ("success-off", "another-administrator-throughout",
                  both(approval(approvingAdminSid=SECOND_ADMIN_SID), actor("coordinator", sid=SECOND_ADMIN_SID))),
                 ("success-off", "second-administrator-role", approval(approver="second-administrator")),
                 ("success-off", "worker-as-the-administrator", actor("worker", sid=FIXTURE_ADMIN_SID)),
                 ("wait-client-loss", "coordinator-another-account", actor("coordinator", sid=SECOND_ADMIN_SID))]
        unproven = {}
        for variant, name, change in cases:
            correlation = self.update(variant, change=change)
            unproven.setdefault(variant, []).append(correlation)
            with self.subTest(variant=variant, case=name):
                row = self.classified(correlation)
                self.assertEqual("approval-unproven", row["classification"], "its package is proven, its approval is not")
                self.assertEqual(self.bound(self.target), row.get("update"))
        for variant in ("different-admin", "success-off"):
            twins = [self.update(variant, change=old_job, route="mcp"), *unproven[variant]]
            scenarios = self.review(twins)["scenarios"]
            with self.subTest(variant=variant):
                self.assertEqual("missing", scenarios["original-user-worker"])
                if variant == "different-admin":
                    self.assertEqual("missing", scenarios["different-approving-admin"])


NATIVE_UPDATES = Path(__file__).parent / "fixtures/windows_update_native/st2-update-runs.json"
S_B = "sha256-eec83f388f38ef1bf3448dc90f26b3d4dbfe4e795e886ddddf42c788b2881427"


class RecordedDriver(FakeDriver):
    """The VM as the recorded journals left it: each correlation's own collected receipt, replayed as it was."""

    def __init__(self, case):
        super().__init__(case)
        self.receipts = {}

    def observe(self, plan, identity):
        receipt = {**plan.as_dict(), "jobId": identity.job_id, "pid": identity.pid, "startTicks": identity.start_ticks,
                   "exitCode": self.receipts[plan.correlation_id]["exitCode"]}
        return execution.DriverObservation(execution.ObservationStatus.TERMINAL, "remote_receipt", identity, receipt, (identity.receipt_path,))

    def collect(self, plan, identity):
        value = self.receipts[plan.correlation_id]
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        return windows.NativeScenarioWindowsDriver(self.case.root, lambda _: self.case.root)._summary(
            plan, raw, {"schemaVersion": 1, "operationId": plan.correlation_id, "exitCode": value["exitCode"]})


class RecordedNativeUpdateTests(MatrixBase):
    """The six recorded native S_T2 update runs (public-ready, download-cancelled and checksum-rejected, each direct and
    MCP) and the two installs they name, from fixtures/windows_update_native, replayed through the real executor."""

    def setUp(self):
        super().setUp()
        self.recorded = json.loads(NATIVE_UPDATES.read_bytes())
        self.replayer = RecordedDriver(self)
        self.replay_executor = execution.ScenarioExecutor(self.root.joinpath(*windows._JOURNALS), self.replayer)

    def replay(self, change=None):
        """Every recorded install and run, each receipt changed by change(run, receipt) first; the run correlations."""
        for item in self.recorded["installs"] + self.recorded["runs"]:
            receipt = json.loads(json.dumps(item["receipt"]))
            if change is not None and "input" in item:
                change(item, receipt)
            self.replayer.receipts[item["correlationId"]] = receipt
            if "input" in item:
                raw = item["input"].encode("ascii")
                self.assertEqual(item["artifactIds"]["scenarioInput"], "sha256-" + hashlib.sha256(raw).hexdigest(), "the recorded input, byte for byte")
                self.assertEqual(item["artifactIds"]["scenarioInput"], self.register(raw, "scenario-input.json", "scenario-input"))
            self.replay_executor.start({"scenarioId": item["scenarioId"], "host": "fixture", "environment": item["environment"],
                                        "bundleHash": item["bundleHash"], "artifactIds": item["artifactIds"], "correlationId": item["correlationId"]})
            self.assertEqual("terminal", self.replay_executor.status(item["correlationId"])["state"])
            if "route" in item:
                local = self.root.joinpath(*windows._LOCAL_STATE, item["correlationId"])
                local.mkdir(mode=0o700, parents=True)
                windows._create_private(local / windows.ROUTE_NAME, json.dumps(
                    {"schemaVersion": 1, "correlationId": item["correlationId"], "route": item["route"]}, sort_keys=True).encode())
        return [item["correlationId"] for item in self.recorded["runs"]]

    def names(self):
        value = json.loads(self.recorded["runs"][0]["input"])
        return {"baseInstall": value["priorInstall"], "basePackage": S_B, "targetInstall": value["targetInstall"]}

    def test_the_recorded_runs_stay_unproven_and_their_record_names_the_base_they_started_from(self):
        """Natively they passed and found S_B before the task, but nothing read what the task left and no --version
        ran: each stays installed-package-unproven, and public-update stays missing."""
        runs = self.replay()
        with mock.patch.dict(windows.MATRIX_SCENARIOS, {"windows-native-cli": MATRIX_REAL["windows-native-cli"]}):
            review = windows.matrix_review(self.root, "windows-native-cli", runs)
        self.assertEqual(["installed-package-unproven"] * 6, [row["classification"] for row in review["rows"]])
        self.assertEqual([{**self.names(), "installedPackage": None}] * 6, [row.get("update") for row in review["rows"]])
        self.assertEqual("missing", review["scenarios"]["public-update"])

    def test_the_recorded_runs_count_with_what_the_fixed_job_writes_after_the_task(self):
        """The same receipts with the fixed job's additions: both installs named, the base read back after the task as the
        base reset recorded it, and the claim of that base. Each recorded pair then proves its row."""
        base = next(item for item in self.recorded["installs"] if item["correlationId"] == self.names()["baseInstall"])["receipt"]["installed"]

        def after(item, receipt):
            value = json.loads(item["input"])
            receipt["update"].update(baseInstall=value["priorInstall"], targetInstall=value["targetInstall"], installedAfter={"role": "base", **base})
            receipt["windows"] = {"installedPackage": True, "packageSha256": base["packageSha256"]}
        runs = self.replay(after)
        review = windows.matrix_review(self.root, "windows-native-cli", runs)
        self.assertEqual(["passed"] * 6, [row["classification"] for row in review["rows"]])
        self.assertEqual([{**self.names(), "installedPackage": S_B}] * 6, [row.get("update") for row in review["rows"]])
        for variant in ("public-ready", "download-cancelled", "checksum-rejected"):
            self.assertEqual("passed", windows._matrix_row_state(review["rows"], UPDATE + variant), variant)


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
        self.assertEqual(sorted(["windows-visual:" + item for item in ("scene-capture", "geometry-contrast", "agent-verdict")]
                                + ["windows-scoped-vpn:" + item for item in ("exact-child-stop", "dns-ws-ssh-cache-resources", "pipe-storage-races")]
                                + ["document-persistence-transfer:" + item for item in ("gui-cli-transfer", "cache-digest-bytes")]),
                         unmapped)
        # The SSH row declares a relayed transfer and a stdin key import still to do, which the relay row does: they prove
        # ssh-import-routing together and nothing else, and each is a product row admitted today.
        self.assertEqual((SSH, RLY), MATRIX_REAL["windows-native-cli"]["ssh-import-routing"])
        self.assertEqual({SSH: ["windows-native-cli:ssh-import-routing"], RLY: ["windows-native-cli:ssh-import-routing"]},
                         {row: sorted(name + ":" + scenario for name, table in MATRIX_REAL.items() for scenario, rows in table.items() if row in rows)
                          for row in (SSH, RLY)})
        self.assertEqual([None, None], [windows.RECIPES[row].get("refusal") for row in (SSH, RLY)])

    def test_the_update_rows_prove_their_scenarios_through_what_they_read_back(self):
        # Thirteen scenarios name update rows, scoped-elevation among them beside the TUN grant. Each update row reads
        # back what its task left (its installed stage) and counts only with that package bound to its clone's install
        # journal (UpdateRowTests).
        named = {scenario for table in MATRIX_REAL.values() for scenario, rows in table.items()
                 if any(row.startswith("windows-public-update.") for row in rows)}
        self.assertEqual({"msi-installer", "public-update", "operation-progress-cancellation", "traffic-continuity", "msi-uac-grant-denial",
                          "ordinary-elevated-owner", "different-approving-admin", "original-user-worker", "participating-copy-locks",
                          "protected-storage-adversarial", "next-owner-recovery", "reconnect-off-preserved", "scoped-elevation"}, named)
        self.assertTrue(all("installed" in windows.RECIPES[row]["stages"] for table in MATRIX_REAL.values() for rows in table.values()
                            for row in rows if row.startswith("windows-public-update.")))
        # A grant row observes its installer's coordinator and worker: only those runs name who approved them.
        self.assertEqual(GRANTS, {variant for variant in windows.UPDATE_VARIANTS
                                  if "authorization" in windows.RECIPES[UPDATE + variant]["update"]["collectorStages"]})
        # The installer lifecycle maps every scenario. The deny row and the grant rows whose stages are all tooled are
        # admitted, the others are refused at admission with what they lack.
        lifecycle = MATRIX_REAL["windows-installer-lifecycle"]
        self.assertTrue(all(lifecycle.values()))
        self.assertEqual({"windows-public-update." + variant for variant in ("uac-denied", "success-off", "different-admin", "wait-client-loss", "installer-wait-client-loss",
                                                                              "install-cancelled", "participating-copy-lock", "success-reconnect",
                                                                              "success-explicit-off")},
                         {row for rows in lifecycle.values() for row in rows
                          if row.startswith("windows-public-update.") and windows.RECIPES[row]["refusal"] is None})

    def test_reconnect_off_preserved_is_proven_only_by_owners_that_had_a_location_to_reconnect_to(self):
        """PRODUCT-005: an update keeps the prior on or off intent. A returned owner shows it kept an off only where it had
        a location it could reconnect to: success-off's fresh workspace has none, so no returned owner of it could run,
        whatever intent it restored. Both update rows here are connected owners, one on and one explicitly off."""
        rows = MATRIX_REAL["windows-installer-lifecycle"]["reconnect-off-preserved"]
        updates = [row for row in rows if row.startswith("windows-public-update.")]
        self.assertEqual(2, len(updates))
        self.assertEqual({"off", "reconnect"}, {windows.RECIPES[row]["update"].get("initialIntent") for row in updates})
        self.assertTrue(all(windows.RECIPES[row]["update"].get("connected") is True for row in updates))
        self.assertNotIn("windows-public-update.success-off", rows)
        self.assertEqual(["windows-reboot-reconnect.post", "windows-reboot-reconnect.pre"], sorted(set(rows) - set(updates)))

    def test_the_document_tun_and_responsive_rows_prove_only_what_their_evidence_holds(self):
        named = {row: sorted(name + ":" + scenario for name, table in MATRIX_REAL.items() for scenario, rows in table.items() if row in rows)
                 for row in windows.RECIPES}
        rsp, doc, cfg = "windows-document-responsive", "windows-document-acceptance", "windows-disconnected-cli-config"
        # design.md adapter steps 4, 7 and 8: RSP is responsive-status-cancel, cli-disconnect-long-work and its part of
        # operation-progress-cancellation, whose other rows include the install cancelled while its prompt is up.
        self.assertEqual(["document-persistence-transfer:responsive-status-cancel", "windows-native-cli:operation-progress-cancellation",
                          "windows-owner-lifecycle:cli-disconnect-long-work"], named[rsp])
        self.assertEqual(("windows-disconnected-cli-config", "windows-streaming-client-interrupt", rsp, "windows-proxy-lifecycle.find-best-cancel",
                          "windows-public-update.download-cancelled", "windows-public-update.install-cancelled"),
                         MATRIX_REAL["windows-native-cli"]["operation-progress-cancellation"])
        self.assertIsNone(windows.RECIPES["windows-public-update.install-cancelled"]["refusal"])
        # The admitted TUN rows count for what their evidence holds: the denial for its own scenario; the restart grant for
        # the approved TUN's traffic and its half of scoped elevation beside UPD(success-off). It runs no sibling runtime, so
        # it cannot show its elevated off spares one: exact-child-stop stays missing (ExactChildStopTests). The find-best
        # rows count for Find Best in VPN mode beside the proxy rows: a denial keeps A and pending B, a grant commits its
        # winner with traffic through its TUN. They were refused at admission and named no scenario before.
        # The configuration and fault variants are the TUN halves of the proxy rows' config and failure scenarios (T8).
        self.assertEqual({"windows-scoped-tun.restart-deny": ["windows-scoped-vpn:denial-preserves-active-a"],
                          "windows-scoped-tun.restart-grant": ["windows-native-cli:scoped-elevation", "windows-scoped-vpn:scoped-uac-tun-traffic"],
                          "windows-scoped-tun.find-best-deny": ["windows-native-cli:find-best"],
                          "windows-scoped-tun.find-best-grant": ["windows-native-cli:find-best"],
                          "windows-scoped-tun.generated-grant": ["windows-scoped-vpn:generated-custom-config"],
                          "windows-scoped-tun.custom-grant": ["windows-scoped-vpn:generated-custom-config"],
                          "windows-scoped-tun.large-grant": ["windows-scoped-vpn:large-config"],
                          "windows-scoped-tun.vpn-prepare-failure": ["windows-scoped-vpn:prepare-commit-recovery"],
                          "windows-scoped-tun.vpn-commit-failure": ["windows-scoped-vpn:prepare-commit-recovery"]},
                         {row: scenarios for row, scenarios in named.items() if row.startswith("windows-scoped-tun.") and scenarios})
        self.assertEqual((), MATRIX_REAL["windows-scoped-vpn"]["exact-child-stop"])
        self.assertEqual(("windows-scoped-tun.restart-grant", "windows-public-update.success-off"), MATRIX_REAL["windows-native-cli"]["scoped-elevation"])
        # gui-owner is only the CLI half of gui-cli-transfer, which stays missing. cache-bytes is only the readback half of
        # cache-digest-bytes: a workspace.json that does not decode is replaced by defaults today, and no row corrupts one.
        self.assertEqual(([], []), (named["windows-document-cold.gui-owner"], named["windows-document-cold.cache-bytes"]))
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
        # Every row the table names outside the update family is admitted today; the update rows' refusals are above.
        self.assertEqual(set(), {row for row, scenarios in named.items() if scenarios and not row.startswith("windows-public-update.")
                                 and (windows.RECIPES[row].get("refusal") is not None or windows.RECIPES[row]["evidenceClass"] != "product")})


if __name__ == "__main__":
    unittest.main()
