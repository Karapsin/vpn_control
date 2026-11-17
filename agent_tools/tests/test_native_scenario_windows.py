"""The closed Windows table, admit_start and the driver behind the real ScenarioExecutor.

Nothing here reaches a VM. FakeSsh answers the fixed carrier programs, and one test runs
the real durable owner through a fake ssh binary with a harmless job in its place.
"""
import ast
import base64
from contextlib import contextmanager, nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import durable_remote_job
from agent_tools import native_artifact_registry as registry
from agent_tools import native_artifact_reuse as reuse
from agent_tools import native_scenario_bundle as bundles
from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_ssh as ssh_driver
from agent_tools import native_scenario_windows as windows
# Before any transport patch below: its source guard refuses a patched ssh_transport at import.
from agent_tools import readiness_windows_registration  # noqa: F401
from agent_tools import ssh_program_execution_remote as carrier
from agent_tools import ssh_transport as transport
from agent_tools import windows_ordinary_task as planner
from agent_tools import windows_scenario_host_job as host_job
from agent_tools.tests.test_native_vm_spec import request as vm_request
from agent_tools.windows_public_updater import update_cases

ROOT = Path(__file__).resolve().parents[2]
MACHINE = "33333333-4444-4555-8666-777777777777"
SCENARIO = "windows-ordinary-qualification"
PROXY_ROWS = tuple("windows-proxy-lifecycle." + variant for variant in (
    "gui-pending", "find-best-success", "find-best-verification-failure", "find-best-cancel", "generated", "custom", "large",
    "prepare-failure", "commit-readiness-failure", "sibling-off", "scheduled-refresh", "no-tray-close"))
DOCUMENT_ROWS = ("windows-document-acceptance", *("windows-document-cold." + variant for variant in (
    "cold-reopen", "legacy-newline", "gui-owner", "cache-bytes", "gui-picker")))
# The responsive row runs the same document action with its responsiveWork; cache-bytes with its own cache source.
RESPONSIVE_ROW = "windows-document-responsive"
ADMITTED_DOCUMENT_ROWS = (*DOCUMENT_ROWS, RESPONSIVE_ROW)
TUN_ROWS = tuple("windows-scoped-tun." + variant for variant in ("restart-deny", "restart-grant", "find-best-deny", "find-best-grant",
                                                          "generated-grant", "custom-grant", "large-grant", "vpn-prepare-failure", "vpn-commit-failure", "resources-grant", "ssh-grant", "stage-squat"))
# windows_tun_reserved_cases' rows: its case module (and ssh-grant's relay) beside the stages; stage-squat is approved
# but has no collector, sampler or hold.
TUN_RESERVED = {"resources-grant": {"agent_tools/windows_tun_reserved_cases.py": "reserved"},
                "ssh-grant": {"agent_tools/windows_tun_reserved_cases.py": "reserved", "agent_tools/windows_ssh_relay_fixture.py": "relay"},
                "stage-squat": {"agent_tools/windows_tun_reserved_cases.py": "reserved"}}
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


def submitted_bindings(source):
    """The literal assignments a submitted program binds: the loader's deflated bindings, or a single program's own."""
    import zlib
    assigned = {}
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            try:
                assigned[node.targets[0].id] = ast.literal_eval(node.value)
            except ValueError:
                pass
    if "BINDINGS" in assigned:
        return submitted_bindings(zlib.decompress(base64.b64decode(assigned["BINDINGS"])).decode("utf-8"))
    return assigned


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
        self.staged = {}
        self.stdin = None
        self.job_files = {}
        self.decision = None
        self.decision_reply = None  # The read's whole reply, when it is not a read terminal (a refusal before any input).
        self.decision_reads = []
        self.cache_states = {}  # digest -> a state the target read reports instead of what is staged
        self.waits = []
        self.wait_reply = {"state": "read", "ended": True, "why": "terminal", "observedAt": 1.0}

    def _marker(self, operation):
        return json.dumps({"schemaVersion": 1, "operationId": operation, "scenarioExit": self.exit_code, "failure": None}).encode() + b"\n"

    def respond(self, command):
        if command[:4] != ("python3", "-I", "-B", "-c") or not command[4].startswith("exec("):
            raise AssertionError("not a fixed carrier: " + repr(command[:4]))
        program = ast.literal_eval(command[4][5:-1])
        if program == windows._TARGET:
            return "target", TARGET
        if program == getattr(windows, "_TARGET_STAGED", None):
            copies = [word.partition(":") for word in command[5:]]
            states = {digest: ("present" if digest in self.staged and len(self.staged[digest]) == int(size) else "absent")
                      for digest, _, size in copies}
            states.update({digest: state for digest, state in self.cache_states.items() if digest in states})
            return "target", {**TARGET, "staged": states}
        if program == getattr(windows, "_WAIT_JOB", None):
            self.waits.append(tuple(command[5:]))
            return "wait-job", self.wait_reply
        if program == windows._COLLECT:
            return "collect", self.collect_reply
        if program == windows._STAGE:
            digest, size, mode = command[5], int(command[6]), command[7]
            if mode == "check":
                return "stage-check", {"state": "present" if digest in self.staged else "absent"}
            if digest in self.staged:  # As _STAGE: a copy already there is hashed and named, and nothing is written.
                same = len(self.staged[digest]) == size and hashlib.sha256(self.staged[digest]).hexdigest() == digest
                return "stage-write", {"state": "present" if same else "differs"}
            raw = self.stdin.read()
            if len(raw) == size and hashlib.sha256(raw).hexdigest() == digest:
                self.staged[digest] = raw
            return "stage-write", {"state": "staged" if digest in self.staged else "differs"}
        if program == windows._READ_JOB_FILE:
            value = self.job_files.get(command[6])
            return "read-job-file", {"state": "unavailable"} if value is None else {"state": "read", "value": value}
        if program == windows._READ_DECISION:
            self.decision_reads.append(tuple(command[5:7]))
            if self.decision_reply is not None:
                return "read-decision", self.decision_reply
            return "read-decision", {"state": "unavailable"} if self.decision is None else {"state": "read", "value": self.decision}
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
        self.stdin = options.get("stdin")
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
        for name in ("windows-arbitrary-command", "windows-ordinary-qualification.other", "windows-python-install.other", "linux-scheduled-refresh", None, 7):
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
        self.assertEqual({"windows-ordinary-qualification", "windows-python-install", "windows-msi-base-install", "windows-msi-base-reset",
                          "windows-packaged-cli-smoke", "windows-disconnected-cli-config", "windows-streaming-client-interrupt",
                          "windows-disconnected-cli-config.ssh-import-routing", "windows-disconnected-cli-config.ssh-relay-transfer",
                          "windows-autostart-migration.pre", "windows-autostart-migration.post", "windows-reboot-reconnect.pre", "windows-reboot-reconnect.post",
                          "windows-reboot-explicit-off.pre", "windows-reboot-explicit-off.post", "windows-query-owner-gui-reconnect",
                          *PROXY_ROWS, *TUN_ROWS, *("windows-public-update." + variant for variant in windows.UPDATE_VARIANTS), *DOCUMENT_ROWS,
                          RESPONSIVE_ROW},
                         set(windows.RECIPES))
        for name, row in windows.RECIPES.items():
            self.assertEqual(frozenset(row["artifactKeys"]), ssh_driver.SCENARIO_ARTIFACT_KEYS[name])
            self.assertIn(name, execution._SCENARIOS)
            self.assertIn(name, execution._COLLECTED_SCENARIOS)
            for relative, _, _ in row["guestFiles"]:
                self.assertIn(relative, bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID])

    def test_setup_rows_are_never_evidence_and_product_rows_name_their_package(self):
        classes = {name: row["evidenceClass"] for name, row in windows.RECIPES.items()}
        self.assertEqual({"windows-ordinary-qualification": "component", "windows-python-install": "setup", "windows-msi-base-install": "setup",
                          "windows-msi-base-reset": "setup", "windows-packaged-cli-smoke": "product", "windows-disconnected-cli-config": "product",
                          "windows-streaming-client-interrupt": "product", "windows-disconnected-cli-config.ssh-import-routing": "product",
                          "windows-disconnected-cli-config.ssh-relay-transfer": "product",
                          **{name: "product" for name in ("windows-autostart-migration.pre", "windows-autostart-migration.post", "windows-reboot-reconnect.pre", "windows-reboot-reconnect.post",
                          "windows-reboot-explicit-off.pre", "windows-reboot-explicit-off.post", "windows-query-owner-gui-reconnect")},
                          **{name: "product" for name in PROXY_ROWS + TUN_ROWS},
                          **{"windows-public-update." + variant: "product" for variant in windows.UPDATE_VARIANTS},
                          **{name: "product" for name in (*DOCUMENT_ROWS, RESPONSIVE_ROW)}}, classes)
        for name, row in windows.RECIPES.items():
            with self.subTest(name=name):
                packages = [key for key in row["artifactKeys"] if key in windows.PACKAGE_KINDS]
                # native-install-failed also names the pair's failing MSI and its derivation receipt.
                expected = (["targetPackage", "fixtureReceipt", *(["faultPackage", "faultReceipt"] if name.endswith(".native-install-failed") else [])]
                            if row.get("update") else ["targetPackage"])
                self.assertEqual(row["evidenceClass"] == "product", packages == expected and row["priorInstall"] is True)
                self.assertEqual(row["package"] is not None, row["evidenceClass"] == "setup")
                # An update row reads back what its task left installed, as an installer row reads what it installed.
                self.assertEqual("installed" in row["stages"], row["evidenceClass"] == "setup" or bool(row.get("update")))
                self.assertEqual("declare" in row["stages"], (row.get("reboot") or {}).get("phase") == "pre")

    def test_reboot_rows_pair_each_postboot_with_its_preboot(self):
        rows = {name: row for name, row in windows.RECIPES.items() if row.get("reboot")}
        self.assertEqual({"windows-autostart-migration": "autostart-migration", "windows-reboot-reconnect": "reconnect",
                          "windows-reboot-explicit-off": "explicit-off"},
                         {name[:-4]: row["reboot"]["scenario"] for name, row in rows.items() if name.endswith(".pre")})
        for name, row in rows.items():
            with self.subTest(name=name):
                phase = row["reboot"]["phase"]
                self.assertEqual("windows-postboot-final" if phase == "post" else "windows-preboot-reboot", row["workerAction"])
                self.assertEqual(name[:-5] + ".pre" if phase == "post" else None, row["reboot"]["preboot"])
                if phase == "post":
                    self.assertEqual(rows[row["reboot"]["preboot"]]["reboot"]["scenario"], row["reboot"]["scenario"])
                roles = {role for _, role, _ in row["guestFiles"]} - {"owner", "worker"}
                self.assertEqual(planner.POSTBOOT_ROLES - {"gui", "powerShell", "runtimeAuthority"}, roles)
        self.assertEqual({"phase": "none", "scenario": "query-first", "preboot": None}, rows["windows-query-owner-gui-reconnect"]["reboot"])

    def test_the_worker_doors_are_constants_of_their_rows(self):
        casing = {name: [relative for relative, role, _ in row["guestFiles"] if role == "cases"] for name, row in windows.RECIPES.items()}
        self.assertEqual({"windows-disconnected-cli-config": ["agent_tools/windows_disconnected_cli_cases.py"],
                          "windows-streaming-client-interrupt": ["agent_tools/windows_streaming_cli_cases.py"],
                          "windows-disconnected-cli-config.ssh-import-routing": ["agent_tools/windows_ssh_import_routing_cases.py"],
                          "windows-disconnected-cli-config.ssh-relay-transfer": ["agent_tools/windows_ssh_relay_cases.py"],
                          **{name: ["agent_tools/windows_lifecycle_cases.py"] for name in PROXY_ROWS + TUN_ROWS},
                          **{"windows-public-update." + variant: ["agent_tools/windows_public_updater/update_cases.py"]
                             for variant in windows.UPDATE_VARIANTS},
                          "windows-document-acceptance": ["agent_tools/windows_document_cli_cases.py"],
                          **{name: ["agent_tools/windows_document_cold_cases.py"] for name in DOCUMENT_ROWS[1:]},
                          RESPONSIVE_ROW: ["agent_tools/windows_document_responsive_cli_cases.py"]},
                         {name: files for name, files in casing.items() if files})
        self.assertEqual({"windows-packaged-cli-smoke"}, {name for name, row in windows.RECIPES.items() if row["workerAction"] == "qualification"})
        # The SSH variant keeps the disconnected row's owner action, harness and deadline door; only its case module differs.
        variant, base = windows.RECIPES["windows-disconnected-cli-config.ssh-import-routing"], windows.RECIPES["windows-disconnected-cli-config"]
        self.assertEqual({key: value for key, value in base.items() if key not in ("guestFiles", "deadlineSeconds")},
                         {key: value for key, value in variant.items() if key not in ("guestFiles", "deadlineSeconds")})
        self.assertEqual([item for item in base["guestFiles"] if item[1] != "cases"], [item for item in variant["guestFiles"] if item[1] != "cases"])
        # The SSH relay variant keeps the same action, inputs and harness; it adds the relay, the pinned SOCKS location
        # fixture and the origin's TLS material the job makes, and nothing else.
        relay = windows.RECIPES["windows-disconnected-cli-config.ssh-relay-transfer"]
        self.assertEqual({key: value for key, value in base.items() if key not in ("guestFiles", "deadlineSeconds")},
                         {key: value for key, value in relay.items() if key not in ("guestFiles", "deadlineSeconds", "generated", "sshRelay", "refusal")})
        self.assertEqual((("agent_tools/windows_ssh_relay_cases.py", "cases", "data"), ("agent_tools/windows_ssh_relay_fixture.py", "relay", "data"),
                          ("scripts/integration/socks_http_fixture.py", "socks", "data")) + windows._HARNESS, relay["guestFiles"][2:])
        self.assertEqual((host_job.SSH_RELAY_TLS, {"variant": "relay-transfer"}, None, 7200),
                         (relay["generated"], relay["sshRelay"], relay["refusal"], relay["deadlineSeconds"]))
        leaves = [relative.rsplit("/", 1)[1] for relative, _, _ in relay["guestFiles"]] + [leaf for _, leaf in relay["generated"]]
        self.assertEqual(len(leaves), len(set(leaves)), "every published file has its own leaf in the workspace")
        self.assertEqual({"windows-disconnected-cli-config.ssh-relay-transfer"}, {name for name, row in windows.RECIPES.items() if row.get("sshRelay")})
        self.assertEqual({"windows-ordinary-qualification"}, {name for name, row in windows.RECIPES.items() if "qualificationArguments" in row})

    def test_proxy_rows_are_the_dedicated_drivers_variants_with_the_builders_files(self):
        from agent_tools import windows_ordinary_dedicated_driver as dedicated
        from agent_tools import windows_scenario_proxy as proxy
        self.assertEqual(set(windows.PROXY_VARIANTS), dedicated.PROXY_VARIANTS | dedicated.BRANCH_VARIANTS | dedicated.SCHEDULED_VARIANTS
                         | dedicated.NO_TRAY_VARIANTS)
        self.assertEqual(windows.PROXY_VARIANTS, proxy.VARIANTS)
        self.assertEqual(windows._PROXY_BRANCH_VARIANTS, dedicated.BRANCH_VARIANTS)
        self.assertEqual(windows._PROXY_SCHEDULED_VARIANTS, dedicated.SCHEDULED_VARIANTS)
        self.assertEqual(windows._PROXY_NO_TRAY_VARIANTS, dedicated.NO_TRAY_VARIANTS)
        self.assertFalse({"restart-deny"} & set(windows.PROXY_VARIANTS), "a TUN variant is the scoped-TUN family's own")
        for variant in windows.PROXY_VARIANTS:
            with self.subTest(variant=variant):
                row = windows.RECIPES["windows-proxy-lifecycle." + variant]
                self.assertEqual(("product", "python-worker", "windows-proxy-lifecycle", True, None),
                                 (row["evidenceClass"], row["bootstrapMode"], row["workerAction"], row["priorInstall"], row["package"]))
                self.assertEqual({"variant": variant}, row["proxy"])
                self.assertEqual(tuple((role, proxy.GENERATED[role]) for role in proxy.generated_roles(variant)), row["generated"])
                self.assertEqual(((proxy.RUNTIME_ROLE, proxy.RUNTIME_LEAF),), row["extracted"])
                roles = {role for _, role, _ in row["guestFiles"]}
                self.assertEqual(variant in proxy.TRAFFIC_VARIANTS, "traffic" in roles)
                self.assertEqual(variant in dedicated.BRANCH_VARIANTS, {"branches", "listener"} <= roles)
                self.assertEqual(variant in dedicated.SCHEDULED_VARIANTS, "scheduled" in roles)
                self.assertEqual(variant in dedicated.NO_TRAY_VARIANTS, "noTray" in roles)
                leaves = [relative.rsplit("/", 1)[1] for relative, _, _ in row["guestFiles"]] + [leaf for _, leaf in row["generated"] + row["extracted"]]
                self.assertEqual(len(leaves), len(set(leaves)), "every published file has its own leaf in the workspace")
                named = [role for _, role, _ in row["guestFiles"]] + [role for role, _ in row["generated"] + row["extracted"]]
                self.assertEqual(len(named), len(set(named)), "every published file has its own role")
                self.assertNotIn("qualificationArguments", row)

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


class DocumentTableTests(unittest.TestCase):
    def test_the_document_rows_are_the_document_action_with_one_fixed_case_module_each(self):
        from agent_tools import windows_document_cold_cases as cold
        self.assertEqual(set(cold.VARIANTS), set(windows.DOCUMENT_COLD_VARIANTS))
        for name in DOCUMENT_ROWS:
            with self.subTest(name=name):
                row = windows.RECIPES[name]
                variant = None if name == "windows-document-acceptance" else name.split(".", 1)[1]
                cache, gui_picker = variant == "cache-bytes", variant == "gui-picker"
                self.assertEqual(("product", "python-worker", "document-acceptance", True, None),
                                 (row["evidenceClass"], row["bootstrapMode"], row["workerAction"], row["priorInstall"], row["package"]))
                self.assertEqual({"variant": variant, "principalProbe": variant is None, "rootSubfolders": ("document-temp",)}, row["document"])
                self.assertEqual(["owner", "worker", "cases", "client", "windows", "race", "harness", "diagnostic"]
                                 + (["cacheFixture", "runtime", "socks", "https"] if cache else [])
                                 + (["picker", "pickerDesktop"] if gui_picker else []),
                                 [role for _, role, _ in row["guestFiles"]])
                self.assertEqual((host_job.POWERSHELL_PATH,), row["readPins"])
                self.assertIsNone(row["refusal"])
                generated = dict(row.get("generated", ()))
                self.assertEqual({} if variant is None else {"coldInput": "document-cold-input.json",
                                                            **({"legacyInput": "document-legacy-newline.json"} if variant == "legacy-newline" else {}),
                                                            **({"certificate": "document-cache-localhost.pem",
                                                                "privateKey": "document-cache-localhost.key",
                                                                "trustStore": "document-cache-trust.jks",
                                                                "cacheBody": "document-cache-subscription.txt"} if cache else {}),
                                                            **({"pickerFirst": "document-picker-first.json",
                                                                "pickerSecond": "document-picker-second.json"} if gui_picker else {})},
                                 generated)
                leaves = [relative.rsplit("/", 1)[1] for relative, _, _ in row["guestFiles"]] + [leaf for _, leaf in row.get("generated", ())]
                self.assertEqual(len(leaves), len(set(leaves)), "every guest file of the row has its own name in the workspace")
                self.assertNotIn("qualificationArguments", row)
                self.assertNotIn("uac", row)

    def test_the_responsive_row_is_the_document_action_with_the_sources_its_work_pins_and_its_own_tls_files(self):
        row = windows.RECIPES[RESPONSIVE_ROW]
        self.assertEqual(("product", "python-worker", "document-acceptance", True, None, None),
                         (row["evidenceClass"], row["bootstrapMode"], row["workerAction"], row["priorInstall"], row["package"], row["refusal"]))
        self.assertEqual({"variant": "responsive", "principalProbe": False, "rootSubfolders": ("document-temp",)}, row["document"],
                         "only the acceptance row probes a second principal")
        files = {role: relative for relative, role, _ in row["guestFiles"]}
        self.assertEqual(["owner", "worker", "cases", "client", "windows", "race", "harness", "diagnostic", "responsive", "runtime",
                          "workFixture", "socks", "https"], [role for _, role, _ in row["guestFiles"]])
        # The case module and every responsiveWork source are the files the planner and the owner pin by name and digest.
        self.assertEqual(planner.DOCUMENT_RESPONSIVE_CASE[0], files["cases"].rsplit("/", 1)[1])
        self.assertEqual({key: name for key, (name, _) in planner.DOCUMENT_RESPONSIVE_SOURCES.items()},
                         {key: files[role].rsplit("/", 1)[1] for key, role in (("casesPath", "responsive"), ("runtimeStagesPath", "runtime"),
                                                                              ("fixtureWorkerPath", "workFixture"), ("socksSourcePath", "socks"),
                                                                              ("httpsSourcePath", "https"))})
        self.assertEqual((("certificate", "document-work-localhost.pem"), ("privateKey", "document-work-localhost.key"),
                          ("trustStore", "document-work-trust.jks")), tuple(tuple(item) for item in row["generated"]))
        self.assertEqual({"certificatePath", "privateKeyPath", "trustStorePath"},
                         planner.DOCUMENT_RESPONSIVE_FIELDS - {"schemaVersion", "contexts", "largeRoutingInputPath",
                                                               *planner.DOCUMENT_RESPONSIVE_SOURCES},
                         "the job makes exactly the three files the work names that no bundle file supplies")
        leaves = [relative.rsplit("/", 1)[1] for relative in files.values()] + [leaf for _, leaf in row["generated"]]
        self.assertEqual(len(leaves), len(set(leaves)), "every guest file of the row has its own name in the workspace")
        self.assertEqual((host_job.POWERSHELL_PATH,), row["readPins"])
        self.assertEqual(3600, row["deadlineSeconds"])
        for absent in ("qualificationArguments", "uac", "proxy", "update", "reboot", "extracted"):
            self.assertNotIn(absent, row)


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
        for scenario in ("windows-packaged-cli-smoke", "windows-disconnected-cli-config", "windows-streaming-client-interrupt", *PROXY_ROWS,
                         *ADMITTED_DOCUMENT_ROWS):
            complete = {"scenarioId": scenario, "state": "terminal", "collectionState": "complete",
                        "artifactIds": {"bundleManifest": "sha256-" + "a" * 64, "scenarioInput": "sha256-" + "c" * 64, "targetPackage": "sha256-" + digest},
                        "scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": digest}}}
            self.assertEqual({"evidenceClass": "installed-package", "productAction": True}, windows.public_evidence(complete))
            for change in ({"state": "submitted"}, {"state": "unknown"}, {"collectionState": "unknown"},
                           {"scenarioEvidence": {"windows": {"installedPackage": False, "packageSha256": digest}}},
                           {"scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": "c" * 64}}},
                           {"scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": None}}},
                           {"artifactIds": {"bundleManifest": "sha256-" + "a" * 64}}, {"artifactIds": None},
                           {"scenarioEvidence": None}):
                with self.subTest(scenario=scenario, change=change):
                    self.assertEqual({"evidenceClass": "installed-package-unproven", "productAction": True}, windows.public_evidence({**complete, **change}))

    def test_setup_rows_never_claim_whatever_their_receipt_says(self):
        for scenario in ("windows-python-install", "windows-msi-base-install", "windows-msi-base-reset"):
            claim = {"scenarioId": scenario, "state": "terminal", "collectionState": "complete", "artifactIds": {"basePackage": "sha256-" + "b" * 64},
                     "scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": "b" * 64}}}
            self.assertEqual({"evidenceClass": "setup", "productAction": False}, windows.public_evidence(claim))

    def test_an_update_row_claims_the_package_its_variant_ends_with(self):
        """A granted update that succeeded claims its target; every other update row claims the base it started from,
        which the public result does not name: any digest but the target's, bound by the matrix alone."""
        target, base = "b" * 64, "e" * 64

        def claim(variant, digest, **changes):
            return {"scenarioId": UPDATE + variant, "state": "terminal", "collectionState": "complete",
                    "artifactIds": {"bundleManifest": "sha256-" + "a" * 64, "scenarioInput": "sha256-" + "c" * 64,
                                    "targetPackage": "sha256-" + target, "fixtureReceipt": "sha256-" + "d" * 64},
                    "scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": digest, **changes}}}
        proven, unproven = {"evidenceClass": "installed-package", "productAction": True}, {"evidenceClass": "installed-package-unproven",
                                                                                           "productAction": True}
        for variant in windows.UPDATE_VARIANTS:
            # The case module says which: the target only after a granted install that succeeded.
            own, other = (target, base) if variant in update_cases.SUCCESS_VARIANTS else (base, target)
            with self.subTest(variant=variant):
                self.assertEqual(proven, windows.public_evidence(claim(variant, own)))
                self.assertEqual(unproven, windows.public_evidence(claim(variant, other)), "the package another variant ends with")
                for change in ({"installedPackage": False}, {"stoppedAfter": "publish"}, {"packageSha256": None}, {"packageSha256": "E" * 64}):
                    self.assertEqual(unproven, windows.public_evidence(claim(variant, own, **change)))

    def test_a_job_stopped_before_its_task_never_proves_an_installed_package(self):
        digest = "b" * 64
        for stop in ("context", "publish"):
            claim = {"scenarioId": "windows-packaged-cli-smoke", "state": "terminal", "collectionState": "complete",
                     "artifactIds": {"bundleManifest": "sha256-" + "a" * 64, "scenarioInput": "sha256-" + "c" * 64, "targetPackage": "sha256-" + digest},
                     "scenarioEvidence": {"windows": {"installedPackage": True, "packageSha256": digest, "stoppedAfter": stop}}}
            with self.subTest(stop=stop):
                self.assertEqual({"evidenceClass": "installed-package-unproven", "productAction": True}, windows.public_evidence(claim))


@unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid"), "the staging program runs on the POSIX VM host")
class StageProgramTests(unittest.TestCase):
    """The real staging program, run as SSH runs it on the host: a plain login umask, no durable owner."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        self.parent = self.home / ".cache/vpn-control-windows-scenarios"
        self.raw = os.urandom(70000)
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def stage(self, mode, raw=b""):
        argv = list(windows._py(windows._STAGE, self.digest, str(len(self.raw)), mode))
        argv[0] = sys.executable
        done = subprocess.run(argv, input=raw, capture_output=True, env={"HOME": str(self.home), "PATH": os.defpath},
                              umask=0o022, timeout=120)
        return done.returncode, json.loads(done.stdout) if done.returncode == 0 else None

    def test_a_first_staging_under_a_login_umask_creates_private_directories_and_stages_once(self):
        self.assertEqual((0, {"state": "absent"}), self.stage("check"))
        for directory in (self.parent, self.parent / "artifacts"):
            self.assertEqual(0o700, stat.S_IMODE(directory.stat().st_mode), directory.name)
        self.assertEqual((0, {"state": "staged"}), self.stage("write", self.raw))
        target = self.parent / "artifacts" / self.digest
        self.assertEqual((self.raw, 0o600), (target.read_bytes(), stat.S_IMODE(target.stat().st_mode)))
        self.assertEqual([self.digest], os.listdir(self.parent / "artifacts"), "no partial copy is left")
        self.assertEqual((0, {"state": "present"}), self.stage("check"))

    def test_a_cache_open_to_other_users_still_refuses(self):
        self.parent.mkdir(parents=True)
        self.parent.chmod(0o755)
        self.assertEqual((3, None), self.stage("check"))
        self.assertEqual(0o755, stat.S_IMODE(self.parent.stat().st_mode), "an existing folder is refused, never repaired")


class DriverBase(Base):
    def setUp(self):
        super().setUp()
        self.ssh = FakeSsh(self.work)
        for patcher in (mock.patch.object(transport, "admitted_transport", return_value=nullcontext()),
                        mock.patch.object(transport, "build_ssh_argv", side_effect=lambda config, host, timeout, command, ssh_binary: ["fake-ssh", *command]),
                        mock.patch.object(transport, "run_ssh", side_effect=lambda argv, **options: self.ssh.run(argv, **options))):
            patcher.start()
            self.addCleanup(patcher.stop)
        # This checkout's job body is already in the host's cache, as after any earlier row of the same bundle:
        # call lists below are those of an unchanged bundle. CachedBodyTests start from an empty cache.
        if hasattr(windows, "render_job_body"):
            self.body = windows.render_job_body(*windows.verified_bundle(self.root, self.plan(), self.resolver))
            self.ssh.staged[hashlib.sha256(self.body).hexdigest()] = self.body

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
        # The preparation creates no job, and the submit command never went out: proven unsent, never UNKNOWN.
        expected = ("not_submitted", "not_submitted:windows_scenario_preparation_unavailable")
        self.assertEqual(expected, tuple(self.executor().start(self.request())[key] for key in ("state", "reason")))
        self.assertEqual(expected, tuple(self.executor().resume(self.operation)[key] for key in ("state", "reason")))
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
        self.assertEqual(("mcp", "direct"), (delegate.route, self.driver().route))
        with self.assertRaisesRegex(ValueError, "windows_scenario_route_invalid"):
            self.driver(route="other")

    def test_submit_records_its_route_before_any_connection(self):
        delegate = lambda: ssh_driver.NativeScenarioSshDriver(self.root, self.resolver)
        for route, driver in (("direct", self.driver), ("mcp", delegate)):
            with self.subTest(route=route):
                self.operation = str(uuid.uuid4())
                path = self.root.joinpath(*windows._LOCAL_STATE, self.operation, windows.ROUTE_NAME)
                first = []
                run = self.ssh.run

                def checked(argv, **options):
                    first.append(path.exists())
                    return run(argv, **options)
                with mock.patch.object(self.ssh, "run", side_effect=checked):
                    self.assertEqual("submitted", self.executor(driver()).start(self.request())["state"])
                self.assertTrue(first and first[0], "the route exists before the first connection")
                self.assertEqual({"schemaVersion": 1, "correlationId": self.operation, "route": route}, json.loads(path.read_text()))
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
                self.assertEqual(route, windows._route(self.root, self.operation))

    def test_direct_stop_after_reaches_the_job_plan(self):
        self.executor(self.driver(stop_after="context")).start(self.request())
        program = json.loads(self.root.joinpath(*windows._LOCAL_STATE, self.operation, "program.json").read_text())
        self.assertEqual("context", submitted_bindings(program["program"]["source"])["PLAN"]["stopAfter"])


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


class FamilyDriverBase(DriverBase):
    """Package rows over a real registry and real frozen sets in a throwaway Git checkout."""

    def setUp(self):
        super().setUp()
        (self.root / ".gitignore").write_text(".rag_index/\n.vm-hosts.local.json\n")
        (self.root / "gradle.properties").write_text("vpnControlVersion=2.2.15\n")
        (self.root / "gradlew").write_text("#!/bin/sh\n")
        self.git("init", "-q")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "fixture")
        self.head = self.git("rev-parse", "HEAD").strip()
        self.sources = self.work / "packages"
        self.sources.mkdir(mode=0o700)
        self.msi = self.register(b"MSI base " * 4000, "vpn-control-2.2.15.msi", "desktop-package", source=self.head)
        self.set_id = self.freeze([self.msi])
        installer = b"python installer " * 3000
        self.installer = self.register(installer, "python-3.13.15-amd64.exe", "test-toolchain-installer")
        for name, value in (("PYTHON_INSTALLER_SHA256", hashlib.sha256(installer).hexdigest()), ("PYTHON_INSTALLER_BYTES", len(installer))):
            patcher = mock.patch.object(planner, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.prior = str(uuid.uuid4())

    def git(self, *arguments):
        environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.work), "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                       "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}
        return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "core.hooksPath=/dev/null", *arguments],
                              cwd=self.root, env=environment, check=True, capture_output=True, text=True).stdout

    def register(self, raw, name, kind, *, platform="windows", source=None):
        # One location per artifact: a second local copy of the same bytes leaves no unique default to verify.
        known = getattr(self, "registered", {})
        self.registered = known
        if raw in known:
            return known[raw]
        directory = Path(tempfile.mkdtemp(dir=self.sources))
        path = directory / name
        path.write_bytes(raw)
        record = {"platform": platform, "artifactKind": kind, "localPath": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                  "size": len(raw), "evidenceClass": "local-verified", **({"sourceSha": source} if source else {})}
        registered = registry.register_artifact(self.root, record)
        known[raw] = {"artifactId": registered["artifactId"], "locationId": registered["locations"][0]["locationId"], "path": path}
        return known[raw]

    def freeze(self, packages):
        return reuse.artifact_set_freeze(self.root, {"sourceSha": self.head, "runtimePaths": ["gradlew"],
                                                     "packages": [{key: item[key] for key in ("artifactId", "locationId")} for item in packages],
                                                     "provenance": {"architecture": "amd64", "signer": {"kind": "unsigned"}}})["artifactSetId"]

    def scenario_input(self, scenario, **changes):
        value = {"schema": windows.INPUT_SCHEMA, "schemaVersion": 1, "scenarioId": scenario, "correlationId": self.operation, "deploymentId": MACHINE,
                 "sourceSha": self.head, "productVersion": "2.2.15", "artifactSetId": self.set_id,
                 "priorInstall": self.prior if windows.RECIPES[scenario]["priorInstall"] else None}
        value.update(changes)
        return self.register(json.dumps(value, sort_keys=True).encode(), "input-" + str(uuid.uuid4()) + ".json", "scenario-input")["artifactId"]

    def family_request(self, scenario, *, package=None, value=None):
        row = windows.RECIPES[scenario]
        artifacts = {"bundleManifest": "sha256-" + self.bundle_hash}
        if "scenarioInput" in row["artifactKeys"]:
            artifacts["scenarioInput"] = value or self.scenario_input(scenario)
        for role in row["artifactKeys"]:
            if role in windows.PACKAGE_KINDS:
                artifacts[role] = package or (self.installer if role == "pythonInstaller" else self.msi)["artifactId"]
        return self.request(scenarioId=scenario, artifactIds=artifacts)

    def assert_refused(self, request, reason):
        with self.assertRaises(ValueError) as caught:
            windows.admit_start(self.root, request, self.resolver)
        self.assertEqual(reason, str(caught.exception))
        self.assertFalse(self.journal.exists(), "a refusal leaves no journal")
        self.assertFalse(self.root.joinpath(*windows._LOCAL_STATE).exists())


class PackageAdmissionTests(FamilyDriverBase):
    def test_the_ssh_relay_row_is_admitted_with_the_artifacts_of_the_ssh_import_row(self):
        # The same scenario input and target package as the ssh-import-routing row, under the relay row's own name.
        relay, ssh = "windows-disconnected-cli-config.ssh-relay-transfer", "windows-disconnected-cli-config.ssh-import-routing"
        request = self.family_request(ssh, value=self.scenario_input(ssh, scenarioId=relay))
        request["scenarioId"] = relay
        admitted = windows.admit_start(self.root, request, self.resolver)  # Before f31ab987's table knew the name: not allowlisted.
        self.assertEqual(windows.RECIPES[relay], admitted)
        self.assertFalse(self.journal.exists())

    def test_every_new_row_admits_before_any_journal(self):
        for scenario in ("windows-python-install", "windows-msi-base-install", "windows-msi-base-reset", "windows-packaged-cli-smoke",
                         "windows-disconnected-cli-config", "windows-streaming-client-interrupt", "windows-disconnected-cli-config.ssh-import-routing",
                         "windows-disconnected-cli-config.ssh-relay-transfer",
                         *PROXY_ROWS, "windows-scoped-tun.restart-deny", *ADMITTED_DOCUMENT_ROWS):
            with self.subTest(scenario=scenario):
                self.assertEqual(windows.RECIPES[scenario], windows.admit_start(self.root, self.family_request(scenario), self.resolver))
                self.assertFalse(self.journal.exists())

    def test_a_package_failing_any_admission_rule_is_refused_before_any_journal(self):
        other = "f" * 40
        changed = self.register(b"MSI changed " * 4000, "changed.msi", "desktop-package", source=self.head)
        self.freeze([changed])
        changed["path"].write_bytes(b"MSI CHANGED " * 4000)
        cases = {
            "linux-platform": (self.register(b"MSI linux " * 4000, "linux.msi", "desktop-package", platform="linux", source=self.head)["artifactId"],
                               "windows_scenario_package_kind"),
            "other-kind": (self.register(b"MSI receipt " * 4000, "receipt.msi", "fixture-receipt", source=self.head)["artifactId"],
                           "windows_scenario_package_kind"),
            "not-an-msi": (self.register(b"EXE bytes " * 4000, "vpn-control-2.2.15.exe", "desktop-package", source=self.head)["artifactId"],
                           "windows_scenario_package_kind"),
            "other-source": (self.register(b"MSI older " * 4000, "older.msi", "desktop-package", source=other)["artifactId"],
                             "windows_scenario_package_source"),
            "no-source": (self.register(b"MSI unbound " * 4000, "unbound.msi", "desktop-package")["artifactId"], "windows_scenario_package_source"),
            "not-frozen": (self.register(b"MSI loose " * 4000, "loose.msi", "desktop-package", source=self.head)["artifactId"],
                           "windows_scenario_package_not_frozen"),
            "changed-bytes": (changed["artifactId"], "windows_scenario_package_unavailable"),
            "unregistered": ("sha256-" + "e" * 64, "windows_scenario_package_unavailable"),
        }
        for scenario in ("windows-msi-base-install", "windows-msi-base-reset", "windows-packaged-cli-smoke", "windows-proxy-lifecycle.gui-pending"):
            for name, (artifact, reason) in cases.items():
                with self.subTest(scenario=scenario, case=name):
                    self.assert_refused(self.family_request(scenario, package=artifact), reason)
        loose_set = self.freeze([self.register(b"MSI other set " * 4000, "set.msi", "desktop-package", source=self.head)])
        self.assert_refused(self.family_request("windows-packaged-cli-smoke", value=self.scenario_input("windows-packaged-cli-smoke", artifactSetId=loose_set)),
                            "windows_scenario_package_not_frozen")
        self.assert_refused(self.family_request("windows-packaged-cli-smoke", value=self.scenario_input(
            "windows-packaged-cli-smoke", artifactSetId="artifact-set-" + "0" * 64)), "windows_scenario_package_not_frozen")
        wrong = self.register(b"not the python installer", "python-3.13.15-amd64.exe", "test-toolchain-installer")["artifactId"]
        self.assert_refused(self.family_request("windows-python-install", package=wrong), "windows_scenario_python_installer")
        self.assert_refused(self.family_request("windows-python-install", package=self.msi["artifactId"]), "windows_scenario_package_kind")

    def test_an_input_naming_another_version_than_its_frozen_set_is_refused_before_any_journal(self):
        # The set was frozen with gradle.properties' 2.2.15; a well-formed input naming any other version is mislabelled.
        for scenario in ("windows-msi-base-install", "windows-msi-base-reset", "windows-packaged-cli-smoke",
                         "windows-disconnected-cli-config", "windows-streaming-client-interrupt", "windows-proxy-lifecycle.sibling-off"):
            for version in ("2.2.16", "2.2.14", "3.0.0"):
                with self.subTest(scenario=scenario, version=version):
                    self.assert_refused(self.family_request(scenario, value=self.scenario_input(scenario, productVersion=version)),
                                        "windows_scenario_package_version")
        self.assertEqual("2.2.15", reuse.artifact_set_verify_readonly(self.root, self.set_id).get("productVersion"))

    def test_a_document_row_needs_its_prior_install(self):
        for scenario in ADMITTED_DOCUMENT_ROWS:
            for name, change in (("no-prior", {"priorInstall": None}), ("own-prior", {"priorInstall": self.operation}),
                                 ("bad-prior", {"priorInstall": "prior"}), ("other-row", {"scenarioId": "windows-packaged-cli-smoke"}),
                                 ("variant-field", {"variant": "cold-reopen"})):
                with self.subTest(scenario=scenario, case=name):
                    self.assert_refused(self.family_request(scenario, value=self.scenario_input(scenario, **change)), "windows_scenario_input_invalid")
            with self.subTest(scenario=scenario, case="package"):
                self.assert_refused(self.family_request(scenario, package=self.installer["artifactId"]), "windows_scenario_package_kind")

    def test_the_scenario_input_must_name_this_operation_and_nothing_else(self):
        scenario = "windows-disconnected-cli-config"
        cases = {"other-operation": {"correlationId": str(uuid.uuid4())}, "other-scenario": {"scenarioId": "windows-packaged-cli-smoke"},
                 "other-vm": {"deploymentId": str(uuid.uuid4())}, "other-schema": {"schema": "vpn-control.linux-scheduled-refresh.input"},
                 "short-source": {"sourceSha": self.head[:12]}, "version": {"productVersion": "2.2"}, "set": {"artifactSetId": "set"},
                 "no-prior": {"priorInstall": None}, "own-prior": {"priorInstall": self.operation}, "bad-prior": {"priorInstall": "prior"},
                 "extra": {"path": "C:\\x"}, "argv": {"argv": ["cmd.exe"]}}
        for name, change in cases.items():
            with self.subTest(case=name):
                self.assert_refused(self.family_request(scenario, value=self.scenario_input(scenario, **change)), "windows_scenario_input_invalid")
        # A proxy row runs on an installed package: no prior install, its own operation or a malformed one refuse before any journal.
        for scenario in PROXY_ROWS:
            for name in ("no-prior", "own-prior", "bad-prior", "other-scenario"):
                with self.subTest(scenario=scenario, case=name):
                    change = cases[name] if name != "other-scenario" else {"scenarioId": "windows-proxy-lifecycle.generated"
                                                                           if scenario.endswith(".gui-pending") else "windows-proxy-lifecycle.gui-pending"}
                    self.assert_refused(self.family_request(scenario, value=self.scenario_input(scenario, **change)), "windows_scenario_input_invalid")
        self.assert_refused(self.family_request("windows-msi-base-install", value=self.scenario_input("windows-msi-base-install", priorInstall=self.prior)),
                            "windows_scenario_input_invalid")
        kind = self.register(json.dumps({"schema": windows.INPUT_SCHEMA}).encode(), "input.json", "native-scenario-input")["artifactId"]
        self.assert_refused(self.family_request(scenario, value=kind), "windows_scenario_input_invalid")
        self.assert_refused(self.family_request(scenario, value="sha256-" + "d" * 64), "windows_scenario_input_unavailable")

    def test_only_a_postboot_input_names_its_preboot(self):
        preboot = str(uuid.uuid4())
        post = "windows-reboot-reconnect.post"
        self.assertEqual("product", windows.admit_start(self.root, self.family_request(post, value=self.scenario_input(post, priorPreboot=preboot)),
                                                        self.resolver)["evidenceClass"])
        for name, change in (("absent", None), ("null", None.__class__), ("own", self.operation), ("install", self.prior), ("word", "preboot")):
            with self.subTest(case=name):
                value = {} if change is None else {"priorPreboot": None if change is None.__class__ else change}
                self.assert_refused(self.family_request(post, value=self.scenario_input(post, **value)), "windows_scenario_input_invalid")
        for scenario in ("windows-reboot-reconnect.pre", "windows-query-owner-gui-reconnect", "windows-packaged-cli-smoke"):
            with self.subTest(scenario=scenario):
                self.assertIsNotNone(windows.admit_start(self.root, self.family_request(scenario), self.resolver))
                self.assert_refused(self.family_request(scenario, value=self.scenario_input(scenario, priorPreboot=preboot)),
                                    "windows_scenario_input_invalid")

    def test_a_postboot_job_names_its_preboot_and_nothing_else_does(self):
        bundle, verified = windows.verified_bundle(self.root, self.plan_for("windows-reboot-reconnect.post"), self.resolver)
        preboot = str(uuid.uuid4())
        for scenario, value, prior in (("windows-reboot-reconnect.post", {"priorPreboot": preboot}, {"install": self.prior, "preboot": preboot}),
                                       ("windows-reboot-reconnect.pre", {}, {"install": self.prior})):
            with self.subTest(scenario=scenario):
                plan = self.plan_for(scenario)
                source, _ = windows.render_program(plan, windows._binding(self.root, plan), bundle, verified, TARGET,
                                                   value={**self.input_value(scenario), **value}, packages={})
                job_plan = ast.literal_eval(re.search(r"^PLAN=(.*)$", source, re.M)[1])
                self.assertEqual(prior, job_plan["prior"])
                self.assertEqual(windows.RECIPES[scenario]["reboot"], job_plan["row"]["reboot"])

    def plan_for(self, scenario):
        return native_scenario_execution_plan(self, scenario)

    def input_value(self, scenario):
        return {"schema": windows.INPUT_SCHEMA, "schemaVersion": 1, "scenarioId": scenario, "correlationId": self.operation,
                "deploymentId": MACHINE, "sourceSha": self.head, "productVersion": "2.2.15", "artifactSetId": self.set_id,
                "priorInstall": self.prior}


def native_scenario_execution_plan(case, scenario):
    request = case.family_request(scenario, value=case.scenario_input(scenario, **(
        {"priorPreboot": str(uuid.uuid4())} if scenario.endswith(".post") else {})))
    return execution.ScenarioPlan.from_mapping(request)


class PackageSubmitTests(FamilyDriverBase):
    def program_plan(self):
        program = json.loads(self.root.joinpath(*windows._LOCAL_STATE, self.operation, "program.json").read_text())
        return submitted_bindings(program["program"]["source"])["PLAN"]

    def test_the_package_is_staged_once_before_the_job_and_the_job_names_only_digests(self):
        started = self.executor().start(self.family_request("windows-msi-base-install"))
        self.assertEqual("submitted", started["state"])
        self.assertEqual(["target", "stage-write", "prepare", "submit"], self.ssh.calls, "the target read finds the package absent")
        digest = self.msi["artifactId"].removeprefix("sha256-")
        self.assertEqual(self.msi["path"].read_bytes(), self.ssh.staged[digest])
        plan = self.program_plan()
        self.assertEqual({"basePackage": {"sha256": digest, "bytes": len(self.ssh.staged[digest])}}, plan["packages"])
        self.assertEqual({"sourceSha": self.head, "productVersion": "2.2.15"}, plan["product"])
        self.assertEqual({}, plan["prior"])
        self.assertEqual(HOME + "/.cache/vpn-control-windows-scenarios/artifacts", plan["artifactDirectory"])
        self.assertNotIn(str(self.sources), json.dumps(plan), "no local path crosses to the host")
        self.operation = str(uuid.uuid4())
        self.ssh.calls.clear()
        self.executor().start(self.family_request("windows-msi-base-install"))
        self.assertEqual(["target", "prepare", "submit"], self.ssh.calls, "a staged copy is never sent again")

    def test_product_rows_send_no_package_and_name_their_prior_install(self):
        for scenario in ("windows-packaged-cli-smoke", "windows-proxy-lifecycle.commit-readiness-failure", "windows-disconnected-cli-config.ssh-import-routing",
                         "windows-disconnected-cli-config.ssh-relay-transfer", *ADMITTED_DOCUMENT_ROWS):
            with self.subTest(scenario=scenario):
                self.operation = str(uuid.uuid4())
                self.ssh.calls.clear()
                self.executor().start(self.family_request(scenario))
                self.assertEqual(["target", "prepare", "submit"], self.ssh.calls)
                plan = self.program_plan()
                self.assertEqual({"install": self.prior}, plan["prior"])
                self.assertEqual(["targetPackage"], list(plan["packages"]))
                self.assertTrue(plan["row"]["priorInstall"])
                self.assertEqual(scenario, plan["scenarioId"])
                self.assertEqual(json.loads(json.dumps(windows.RECIPES[scenario])), plan["row"], "the job gets the closed row, nothing else")

    def test_every_call_keeps_its_whole_budget_inside_the_one_submit_admission(self):
        # A slow but in-budget staging must not clip the prepare or submit after it into an unknown outcome.
        admissions, budgets = [], []
        run = self.ssh.run
        # The monotonic clock sets the admission deadline; the wall clock only stamps the (non-evidence) timing lines.
        clock = types.SimpleNamespace(monotonic=lambda: 5000.0, time=lambda: 1_800_000_000.0)

        @contextmanager
        def admitted(root, host, operation, *, deadline=None, requirements=None):
            admissions.append(deadline - clock.monotonic())
            yield
            admissions.append(None)

        def timed(argv, **options):
            budgets.append((len(admissions), options["timeout"]))
            return run(argv, **options)
        self.ssh.run = timed
        with mock.patch.object(transport, "admitted_transport", admitted), mock.patch.object(windows, "time", clock):
            for scenario, calls in (("windows-msi-base-install", 4), (SCENARIO, 3)):
                with self.subTest(scenario=scenario):
                    admissions.clear()
                    budgets.clear()
                    self.operation = str(uuid.uuid4())
                    request = self.family_request(scenario) if scenario != SCENARIO else self.request()
                    self.assertEqual("submitted", self.executor().start(request)["state"])
                    self.assertEqual(2, len(admissions), "one admission carries every call of the submit")
                    self.assertEqual([1] * calls, [inside for inside, _ in budgets])
                    self.assertLessEqual(sum(seconds for _, seconds in budgets), admissions[0])

    def test_a_job_stopped_after_publish_is_collected_without_an_installed_package_claim(self):
        self.executor().start(self.family_request("windows-packaged-cli-smoke"))
        digest = self.msi["artifactId"].removeprefix("sha256-")
        plan = {"scenarioId": "windows-packaged-cli-smoke", "operationId": self.operation, "machine": MACHINE, "bundleHash": self.bundle_hash,
                "stopAfter": "publish"}
        # What a stopped job's receipt claimed before its claim needed a checked task.
        receipt = host_job.build_receipt(plan, exit_code=0, stage="publish", failure=None, guest_programs=12,
                                         windows={"installedPackage": True, "packageSha256": digest})
        self.finished(raw=(json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode())
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "publish"),
                         (result["state"], result["collectionState"], result["scenarioEvidence"]["windows"]["stoppedAfter"]))
        self.assertEqual({"evidenceClass": "installed-package-unproven", "productAction": True}, windows.public_evidence(result))
        self.assertEqual({"evidenceClass": "installed-package-unproven", "productAction": True}, ssh_driver.public_evidence(result))

    def test_a_lost_stage_reply_never_reaches_a_submit(self):
        self.ssh.lost = {"stage-write"}
        first = self.executor().start(self.family_request("windows-msi-base-reset"))
        self.assertEqual(("not_submitted", "not_submitted:windows_scenario_stage_unavailable"), (first["state"], first["reason"]))
        self.assertNotIn("prepare", self.ssh.calls)
        self.assertEqual(0, self.ssh.submits)
        self.assertEqual("not_submitted", self.executor().resume(self.operation)["state"])

    def test_the_mcp_route_admits_through_the_ssh_adapter_before_any_journal(self):
        self.assertIsNone(ssh_driver.admit_start(self.root, self.family_request("windows-streaming-client-interrupt"), self.resolver))
        with self.assertRaises(ValueError):
            ssh_driver.admit_start(self.root, self.family_request("windows-streaming-client-interrupt", package=self.installer["artifactId"]), self.resolver)
        self.assertFalse(self.journal.exists())


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
        # The submitted program is this harmless job; the real body is still staged, into a throwaway home's cache.
        rendered = mock.patch.object(windows, "render_loader", return_value=(self.job_source(), str(self.data)))
        home = mock.patch.dict(os.environ, {"HOME": str(self.work / "host-home")})
        with rendered, home:
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


class ScopedTunTableTests(unittest.TestCase):
    """windows-scoped-tun.<variant>: the TUN stages' own variants on the proxy-lifecycle action, each prompt answered
    only by windows-uac-decision, and only a row whose evidence proves its requirement admitted."""

    def test_the_rows_are_the_stages_variants_on_the_proxy_action(self):
        from agent_tools import windows_scenario_proxy as proxy
        from agent_tools import windows_tun_stages as stages
        self.assertEqual(set(windows.TUN_VARIANTS), set(stages.VARIANTS))
        self.assertEqual(windows.TUN_VARIANTS, proxy.TUN_VARIANTS)
        for variant in windows.TUN_VARIANTS:
            row = windows.RECIPES["windows-scoped-tun." + variant]
            with self.subTest(variant=variant):
                self.assertEqual(("product", "python-worker", "windows-proxy-lifecycle", True, None),
                                 (row["evidenceClass"], row["bootstrapMode"], row["workerAction"], row["priorInstall"], row["package"]))
                grant, sampled = variant in proxy.TUN_GRANT_VARIANTS, variant in proxy.TUN_SAMPLED_VARIANTS
                # A grant's one SYSTEM collector stage, tun, is also its final one: the driver's hold waits on it.
                self.assertEqual(({"variant": variant}, {"variant": variant, **({"collectorStages": ("tun",), "finalStage": "tun"} if grant else {})}),
                                 (row["proxy"], row["tun"]))
                self.assertEqual(tuple((role, proxy.GENERATED[role]) for role in proxy.generated_roles(variant)), row["generated"])
                files = {relative: role for relative, role, _ in row["guestFiles"]}
                proxy_files = {relative: role for relative, role, _ in windows._PROXY_FILES}
                collector = {relative: role for relative, role, _ in (*windows._TUN_COLLECTOR, *windows._COLLECTOR_FILES)}
                self.assertEqual({**proxy_files, "agent_tools/windows_tun_stages.py": "tun", **TUN_RESERVED.get(variant, {}),
                                  **({"agent_tools/windows_tun_direct_sampler.py": "sampler"} if sampled else {}), **(collector if grant else {}),
                                  **({"agent_tools/windows_runtime_branch_cases.py": "branches"} if variant in proxy.TUN_PENDING else {}),
                                  "agent_tools/windows_ordinary_task_owner.ps1": "owner", "agent_tools/windows_ordinary_process_owner.py": "worker"}, files)
                self.assertNotIn("traffic", files.values(), "a TUN row samples only through its TUN, never through the SOCKS worker")
                leaves = [relative.rsplit("/", 1)[1] for relative in files] + [leaf for _, leaf in row["generated"] + row["extracted"]]
                self.assertEqual(len(leaves), len(set(leaves)))

    def test_every_tun_row_is_admitted_with_its_decision_row(self):
        # Until the grant's collector route existed every grant was refused windows_scenario_tun_grant_unproven; until
        # the decision waited out a late prompt and the stages read Find Best's own rules, both Find Best rows were
        # refused windows_scenario_tun_find_best_unproven.
        from agent_tools import windows_uac_decision as uac
        refusals = {variant: windows.RECIPES["windows-scoped-tun." + variant]["refusal"] for variant in windows.TUN_VARIANTS}
        self.assertEqual({variant: None for variant in ("restart-deny", "restart-grant", "find-best-deny", "find-best-grant", "generated-grant",
                                                         "custom-grant", "large-grant", "vpn-prepare-failure", "vpn-commit-failure",
                                                         "resources-grant", "ssh-grant", "stage-squat")}, refusals)
        # vpn-prepare-failure is refused by the product before any prompt: it has no decision row.
        self.assertEqual({"windows-scoped-tun." + variant for variant in windows.TUN_VARIANTS if variant != "vpn-prepare-failure"},
                         {name for name in uac.ROWS if name.startswith("windows-scoped-tun.")})

    def test_the_grant_collector_modules_are_the_contract_roles(self):
        from agent_tools.windows_system_collector import collector_contract as contract
        row = windows.RECIPES["windows-scoped-tun.restart-grant"]
        files = {role: relative for relative, role, _ in row["guestFiles"]}
        for role, name in host_job.TUN_COLLECTOR_MODULES.items():
            digest = hashlib.sha256((ROOT / files[name]).read_bytes()).hexdigest()
            expected = {**contract.FIXED, "collector": contract.COLLECTORS["tun"]}.get(role)
            if expected is not None:
                self.assertEqual(expected, digest, role)
        self.assertEqual("agent_tools/windows_tun_native_observer.py", files["collector"])
        for relative, _, _ in row["guestFiles"]:
            self.assertTrue(host_job._BUNDLE_PATH.fullmatch(relative), relative)

    def test_each_prompt_is_the_decision_tables_and_a_denial_joins_its_terminal(self):
        from agent_tools import windows_ordinary_dedicated_driver as dedicated
        from agent_tools import windows_uac_decision as uac
        for variant in windows.TUN_VARIANTS:
            name = "windows-scoped-tun." + variant
            row = windows.RECIPES[name]
            with self.subTest(variant=variant):
                self.assertEqual(name in uac.ROWS, "uac" in row, "a prompt reaches a guest only where the decision table answers it")
                if "uac" in row:
                    table = uac.ROWS[name]
                    self.assertEqual(("vpn-broker", table["decision"], table["event"]), (row["uac"]["prompt"], row["uac"]["decision"], row["uac"]["event"]))
                    self.assertEqual("deny" if variant.endswith("-deny") else "approve", row["uac"]["decision"])
                    self.assertEqual(variant.endswith("-deny"), row["denyJoin"])
                    # A grant joins its approval too, as do the commit fault and stage-squat, approved with no collector.
                    self.assertEqual(not variant.endswith("-deny"), row.get("approveJoin") is True, "a grant and the commit fault join their approval too")
                else:
                    # Only a row with no prompt at all, or one refused at admission, has no decision.
                    self.assertTrue(variant == "vpn-prepare-failure" or row["refusal"] is not None, variant)
                # Only the admitted rows reach the dedicated driver, which takes the grant whose collector stage exists.
                self.assertEqual(row["refusal"] is None, variant in dedicated.TUN_VARIANTS)
                self.assertEqual(row["refusal"] is None and variant.endswith("-grant"), variant in dedicated.TUN_GRANT_VARIANTS)
                self.assertEqual(row["refusal"] is None and "samplerInput" in dict(row["generated"]), variant in dedicated.TUN_SAMPLED_VARIANTS)

    def test_the_tun_files_and_the_collector_pin_are_in_the_bundle(self):
        from agent_tools.windows_system_collector import collector_contract as contract
        for relative in ("agent_tools/windows_tun_stages.py", "agent_tools/windows_tun_direct_sampler.py",
                         "agent_tools/windows_tun_native_observer.py", "agent_tools/windows_system_collector/collector_contract.py"):
            self.assertIn(relative, bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID])
        self.assertEqual(contract.COLLECTORS["tun"], hashlib.sha256((ROOT / "agent_tools/windows_tun_native_observer.py").read_bytes()).hexdigest(),
                         "collectorSourceSha256 names the TUN observer the pinned contract admits")


UPDATE = "windows-public-update."


class TunGrantDecisionTests(FamilyDriverBase):
    """The grant asks for its approval as a denial asks for its own, and a pass names the reviewed approval."""
    GRANT = "windows-scoped-tun.restart-grant"

    def setUp(self):
        super().setUp()
        write_vpn_broker_profile(self.root)
        self.executor().start(self.family_request(self.GRANT))
        self.decision = str(uuid.uuid5(uuid.UUID(self.operation), "windows-uac-decision"))

    def job_receipt(self, exit_code=0, known_end=None):
        plan = {"scenarioId": self.GRANT, "operationId": self.operation, "machine": MACHINE, "bundleHash": self.bundle_hash}
        value = host_job.build_receipt(plan, exit_code=exit_code, stage="receipt", failure=None, guest_programs=40)
        # As the job's _finish adds it for a grant: its collectors, and the known end its owner's journal names.
        value["tun"] = {"variant": "restart-grant", "collectors": {}, "knownEnd": known_end}
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

    def terminal(self, **changes):
        return {"state": "input-ack-only", "operationId": self.decision, "attempt": 1, "decision": "approve", "prompt": "vpn-broker",
                "promptClosed": True, "approvalSucceeded": False, "productOutcomeProved": False, "replayAllowed": False, **changes}

    def test_the_prompt_asks_for_its_approval_until_the_decision_is_known(self):
        self.ssh.job_files["status.json"] = {"pendingKinds": [], "uacEvents": ["scoped-tun-awaiting-current-input"], "uacDecision": None}
        self.assertEqual("uac-pending:vpn-broker:approve", self.executor().status(self.operation)["reason"])
        self.ssh.job_files["status.json"]["uacDecision"] = {"state": "input-ack-only", "decision": "approve", "prompt": "vpn-broker", "promptClosed": True}
        self.assertEqual("original_owner_running", self.executor().status(self.operation)["reason"])

    def test_a_passed_grant_completes_only_with_its_approval_terminal(self):
        self.finished(raw=self.job_receipt())
        for decision in (None, self.terminal(promptClosed=False), self.terminal(decision="deny"), self.terminal(prompt="install-helper"),
                         self.terminal(state="input-outcome-unknown"), self.terminal(approvalSucceeded=True), self.terminal(extra="x")):
            with self.subTest(decision=decision):
                self.ssh.decision = decision
                result = self.executor().status(self.operation)
                self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))
                self.assertNotIn("scenarioEvidence", result)
        self.ssh.decision = self.terminal()
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "passed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual("approve-acknowledged-prompt-closed", result["scenarioEvidence"]["windows"]["uacDecision"])
        self.assertEqual(("/owned/vm", self.decision), self.ssh.decision_reads[-1])

    def test_a_failed_grant_needs_no_join(self):
        self.finished(exit_code=1, raw=self.job_receipt(exit_code=1))
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "failed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual([], self.ssh.decision_reads)

    def test_a_grant_that_failed_by_another_known_end_needs_no_join(self):
        # The product's own RUNTIME_FAILED, say, before any prompt: no decision could have caused it.
        self.finished(exit_code=1, raw=self.job_receipt(exit_code=1, known_end="RUNTIME_FAILED"))
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "failed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual([], self.ssh.decision_reads)

    def test_a_grant_cancelled_by_its_prompt_fails_the_product_only_after_its_typed_approval(self):
        """The product's CANCELLED of the grant's request, which the driver closes as a known end and exits 1 with. A prompt
        the decision never typed into (a final refusal, a black display, a late prompt) expires into that same CANCELLED,
        so the run is the product's failure only once the decision's own terminal shows the approval typed and the prompt
        closed. Until then it stays unsettled, as a deny row's pass does, and no matrix scan counts it."""
        self.finished(exit_code=1, raw=self.job_receipt(exit_code=1, known_end="cancelled"))
        for decision in (None, self.terminal(promptClosed=False), self.terminal(decision="deny"), self.terminal(state="input-outcome-unknown"),
                         self.terminal(prompt="install-helper")):
            with self.subTest(decision=decision):
                self.ssh.decision = decision
                result = self.executor().status(self.operation)
                self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))
                self.assertNotIn("scenarioEvidence", result)
        self.ssh.decision = self.terminal()
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "failed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual("approve-acknowledged-prompt-closed", result["scenarioEvidence"]["windows"]["uacDecision"])
        self.assertEqual(("/owned/vm", self.decision), self.ssh.decision_reads[-1])

    def test_a_grant_cancelled_after_its_decision_refused_before_any_input_is_collected_with_that_refusal(self):
        """Native c7b6562a (S_D4): the approval refused instance_uac_frame_unrecognized, nothing was typed, the prompt
        expired into the grant's CANCELLED and the job exited 1. Collect found no input terminal to join, so the row stayed
        terminal and uncollected for good. A decision whose every attempt ended refused with no input is a known end of
        the decision: the run is collected failed, naming that refusal, and the matrix never counts it as the product's."""
        self.finished(exit_code=1, raw=self.job_receipt(exit_code=1, known_end="cancelled"))
        refused = {"state": "refused", "attempts": 1, "reason": "instance_uac_frame_unrecognized"}
        for reply in ({**refused, "attempts": 0}, {**refused, "attempts": True}, {**refused, "reason": "uac_frame"},
                      {**refused, "reason": "instance_uac_prompt_burned"}, {**refused, "reason": "instance_uac_original_input_unknown"},
                      {**refused, "extra": 1}, {"state": "refused"}, {"state": "unavailable"}):
            with self.subTest(reply=reply):
                self.ssh.decision_reply = reply
                result = self.executor().status(self.operation)
                self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))
                self.assertNotIn("scenarioEvidence", result)
        self.ssh.decision_reply = refused
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "failed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual("approve-refused:instance_uac_frame_unrecognized", result["scenarioEvidence"]["windows"]["uacDecision"])
        self.assertEqual(("/owned/vm", self.decision), self.ssh.decision_reads[-1])
        self.assertEqual(result, self.executor().status(self.operation), "collected once; a repeat reads the journal")

    def test_a_refused_decision_never_completes_a_pass(self):
        # Nothing this decision typed approved the broker, so a pass is not the reviewed approval's: it stays unsettled.
        self.finished(raw=self.job_receipt())
        self.ssh.decision_reply = {"state": "refused", "attempts": 1, "reason": "instance_uac_frame_unrecognized"}
        result = self.executor().status(self.operation)
        self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))


class UpdateTableTests(unittest.TestCase):
    def test_the_variants_are_the_ones_the_case_module_accepts(self):
        from agent_tools.windows_public_updater import update_cases
        self.assertEqual(set(update_cases.VARIANTS) - {"transport-loss"}, set(windows.UPDATE_VARIANTS))
        self.assertIn("transport-loss", update_cases.VARIANTS, "the case module refuses it itself")

    def test_each_row_ends_with_the_package_its_case_leaves_and_reads_it_back(self):
        """A passed case leaves the target only after a granted install that succeeded (SUCCESS_VARIANTS); every other
        variant leaves the base it started from. The job reads which in its installed stage and claims only that one."""
        ends = {variant: windows.RECIPES[UPDATE + variant]["update"].get("ends") for variant in windows.UPDATE_VARIANTS}
        self.assertEqual({variant for variant in windows.UPDATE_VARIANTS if variant in update_cases.SUCCESS_VARIANTS},
                         {variant for variant, end in ends.items() if end == "target"})
        self.assertEqual({"base", "target"}, set(ends.values()))
        for variant in windows.UPDATE_VARIANTS:
            with self.subTest(variant=variant):
                stages = windows.RECIPES[UPDATE + variant]["stages"]
                self.assertEqual(("run", "installed", "evidence"), stages[stages.index("run"):stages.index("run") + 3])

    def test_only_rows_with_a_producer_for_their_evidence_are_admitted(self):
        """Each refused row names exactly what it still lacks; every stage of an admitted row is tooled."""
        refusals = {variant: windows.RECIPES[UPDATE + variant]["refusal"] for variant in windows.UPDATE_VARIANTS}
        self.assertEqual({**dict.fromkeys(("public-ready", "download-cancelled", "checksum-rejected", "uac-denied", "success-off",
                                           "different-admin", "wait-client-loss", "installer-wait-client-loss", "install-cancelled",
                                           "participating-copy-lock", "success-reconnect", "success-explicit-off",
                                           # T5: the fixture workflow derives the failing MSI; the case plants and settles the
                                           # counterfeit root.
                                           "native-install-failed", "protected-storage-rejected"))}, refusals)

    def test_the_rows_agree_with_the_dedicated_driver_and_the_decision_table(self):
        from agent_tools import windows_ordinary_dedicated_driver as dedicated
        from agent_tools import windows_uac_decision as uac
        for variant in windows.UPDATE_VARIANTS:
            row = windows.RECIPES[UPDATE + variant]
            with self.subTest(variant=variant):
                self.assertEqual(variant in dedicated.NO_SYSTEM, "uac" not in row, "a row with no SYSTEM collector raises no prompt")
                if "uac" in row:
                    table = uac.ROWS[UPDATE + variant]
                    self.assertEqual((table["prompt"], table["decision"], table["event"]), (row["uac"]["prompt"], row["uac"]["decision"], row["uac"]["event"]))
                stages, final = row["update"]["collectorStages"], row["update"]["finalStage"]
                finals = dedicated.FINAL_TERMINAL | dedicated.FINAL_RETURNED
                self.assertTrue(final is None or variant in finals)
                if row["refusal"] is None:
                    self.assertEqual(final is not None, variant in finals)
                roles = {role for _, role, _ in row["guestFiles"]}
                self.assertEqual(bool(stages), {"caller_hold", "hold_protocol", "collector_contract", "system_worker"} <= roles)
                self.assertTrue({"driver", "cases", "receipts", "server", "collector", "lifecycle"} <= roles)
                for relative, _, _ in row["guestFiles"]:
                    self.assertTrue(host_job._BUNDLE_PATH.fullmatch(relative), relative)
        self.assertEqual((("before-install", "terminal-actors"), "terminal-actors"),
                         tuple(windows.RECIPES[UPDATE + "uac-denied"]["update"][key] for key in ("collectorStages", "finalStage")))
        for variant in ("success-off", "different-admin", "success-reconnect", "success-explicit-off", "wait-client-loss", "installer-wait-client-loss"):
            self.assertEqual((("before-install", "authorization", "terminal-actors", "returned-cleanup"), "returned-cleanup"),
                             tuple(windows.RECIPES[UPDATE + variant]["update"][key] for key in ("collectorStages", "finalStage")))
            self.assertEqual("approve", windows.RECIPES[UPDATE + variant]["uac"]["decision"])
        # A cancel sent while the prompt is up: its prompt is approved, and its last stage is the watched actors' exit.
        self.assertEqual((("before-install", "terminal-actors"), "terminal-actors", "approve"),
                         (*(windows.RECIPES[UPDATE + "install-cancelled"]["update"][key] for key in ("collectorStages", "finalStage")),
                          windows.RECIPES[UPDATE + "install-cancelled"]["uac"]["decision"]))
        # A running participating copy: fault-ready names its actor before the install is asked for.
        self.assertEqual((("before-install", "fault-ready", "authorization", "terminal-actors", "returned-cleanup"), "returned-cleanup"),
                         tuple(windows.RECIPES[UPDATE + "participating-copy-lock"]["update"][key] for key in ("collectorStages", "finalStage")))
        # Only different-admin is approved by another account than the fixture administrator, as the decision table says.
        self.assertEqual({UPDATE + "different-admin": "second-administrator"},
                         {UPDATE + variant: windows.RECIPES[UPDATE + variant]["approver"] for variant in windows.UPDATE_VARIANTS
                          if "approver" in windows.RECIPES[UPDATE + variant]})
        self.assertEqual(uac.APPROVERS, {name: row["approver"] for name, row in windows.RECIPES.items() if "approver" in row})

    def test_only_the_connected_rows_carry_their_upstream_and_only_the_cancelled_install_watches(self):
        """success-reconnect and its explicit-off twin alone carry the in-guest SOCKS upstream and the traffic sampler and
        have the job write their loopback profile and the sampler input; only success-reconnect's returned owner is to
        reconnect. install-cancelled alone asks before-install for the watch."""
        connection = {"scripts/integration/socks_http_fixture.py": "upstreamFixture", "agent_tools/windows_lifecycle_traffic_worker.py": "trafficWorker"}
        for variant in windows.UPDATE_VARIANTS:
            row = windows.RECIPES[UPDATE + variant]
            files = {relative: role for relative, role, _ in row["guestFiles"]}
            with self.subTest(variant=variant):
                connected = variant in ("success-reconnect", "success-explicit-off")
                self.assertEqual((connected, variant == "install-cancelled"), (row["update"]["connected"], row["update"]["cancelWatch"]))
                self.assertEqual("reconnect" if variant == "success-reconnect" else "off", row["update"]["initialIntent"])
                self.assertEqual(connection if connected else {}, {relative: role for relative, role in files.items() if relative in connection})
                generated = dict(row.get("generated", ()))
                self.assertEqual(connected, {"connectionProfile", "trafficInput"} <= set(generated))
                if connected:
                    self.assertEqual({"connectionProfile": "update-connection-profile.txt", "trafficInput": "update-traffic-input.json"}, generated)
                leaves = [relative.rsplit("/", 1)[1] for relative in files] + [leaf for _, leaf in row.get("generated", ()) + row.get("extracted", ())]
                self.assertEqual(len(leaves), len(set(leaves)), "every guest leaf is one file")
                for relative in files:
                    self.assertTrue(host_job._BUNDLE_PATH.fullmatch(relative), relative)
                    self.assertIn(relative, bundles._SCENARIOS[windows.BUNDLE_SCENARIO_ID], "the bundle carries every row file")

    def test_the_collector_modules_are_the_contract_roles(self):
        from agent_tools.windows_system_collector import collector_contract as contract
        row = windows.RECIPES[UPDATE + "uac-denied"]
        files = {role: relative for relative, role, _ in row["guestFiles"]}
        for role, name in host_job.COLLECTOR_MODULES.items():
            digest = hashlib.sha256((ROOT / files[name]).read_bytes()).hexdigest()
            expected = {**contract.FIXED, "collector": contract.COLLECTORS["update"]}.get(role)
            if expected is not None:
                self.assertEqual(expected, digest, role)
        self.assertEqual(set(host_job.UPDATE_MODULE_ROLES), {role for role in files if role in host_job.UPDATE_MODULE_ROLES})


def write_vpn_broker_profile(root, **changes):
    """A reviewed vpn-broker profile as windows_uac_decision.reviewed_uac_profile writes it: private, create-only."""
    profile = {"schemaVersion": 1, "deploymentId": MACHINE, "prompt": "vpn-broker", "width": 1280, "height": 800,
               "crops": [{"rect": [0, 0, 100, 10], "sha256": "a" * 64}], "field": {"rect": [10, 300, 210, 320], "maxDarkPixels": 0},
               "reviewedFrameSha256": "b" * 64, **changes}
    directory = Path(root) / ".runtime/windows-uac-profiles" / MACHINE
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    path = directory / "vpn-broker.json"
    path.write_text(json.dumps(profile))
    path.chmod(0o600)
    return path


class ScopedTunAdmissionTests(FamilyDriverBase):
    def test_every_refused_row_is_refused_before_any_journal(self):
        write_vpn_broker_profile(self.root)
        name = "windows-scoped-tun.find-best-grant"
        with mock.patch.dict(windows.RECIPES, {name: dict(windows.RECIPES[name], refusal="windows_scenario_tun_find_best_unproven")}):
            self.assert_refused(self.family_request(name), "windows_scenario_tun_find_best_unproven")
        self.assertFalse(self.journal.exists())

    def test_the_find_best_rows_are_admitted_as_the_restart_rows_are(self):
        """The grant needs the deployment's reviewed vpn-broker profile, the denial none (its run is a review's prompt)."""
        grant, deny = "windows-scoped-tun.find-best-grant", "windows-scoped-tun.find-best-deny"
        self.assert_refused(self.family_request(grant), "windows_scenario_uac_profile_unreviewed")
        self.assertEqual(windows.RECIPES[deny], windows.admit_start(self.root, self.family_request(deny), self.resolver))
        write_vpn_broker_profile(self.root)
        self.assertEqual(windows.RECIPES[grant], windows.admit_start(self.root, self.family_request(grant), self.resolver))
        self.assertFalse(self.journal.exists())

    def test_the_grant_is_admitted_only_with_the_deployments_reviewed_broker_profile(self):
        """windows-uac-decision answers the grant's prompt only with this deployment's reviewed vpn-broker profile: without
        one the prompt would expire into the grant's CANCELLED, a failed run, so the row fails closed before any journal.
        At 1d9d239b every grant was refused windows_scenario_tun_grant_unproven."""
        grant = "windows-scoped-tun.restart-grant"
        self.assert_refused(self.family_request(grant), "windows_scenario_uac_profile_unreviewed")
        for name, change in (("another-deployment", {"deploymentId": str(uuid.uuid4())}), ("another-prompt", {"prompt": "install-helper"}),
                             ("caret-crop", {"crops": [{"rect": [10, 300, 210, 320], "sha256": "a" * 64}]})):
            with self.subTest(profile=name):
                path = write_vpn_broker_profile(self.root, **change)
                self.assert_refused(self.family_request(grant), "windows_scenario_uac_profile_unreviewed")
                path.unlink()
        path = write_vpn_broker_profile(self.root)
        path.chmod(0o644)
        self.assert_refused(self.family_request(grant), "windows_scenario_uac_profile_unreviewed")
        path.chmod(0o600)
        self.assertEqual(windows.RECIPES[grant], windows.admit_start(self.root, self.family_request(grant), self.resolver))
        self.assertFalse(self.journal.exists())
        # A denial's run is the prompt a review captures the profile from: it needs none.
        path.unlink()
        self.assertEqual(windows.RECIPES["windows-scoped-tun.restart-deny"],
                         windows.admit_start(self.root, self.family_request("windows-scoped-tun.restart-deny"), self.resolver))

    def test_a_deny_variant_without_a_decision_join_is_refused_whatever_its_refusal(self):
        # A deny row with no decision join: an expired prompt's CANCELLED would pass as its denial.
        name = "windows-scoped-tun.find-best-deny"
        self.assertEqual(("deny", True), ((windows.RECIPES[name].get("uac") or {}).get("decision"), windows.RECIPES[name].get("denyJoin")))
        bare = {key: value for key, value in windows.RECIPES[name].items() if key not in ("uac", "denyJoin")}
        for row in (dict(bare, refusal=None),
                    dict(windows.RECIPES[name], refusal=None, uac={"prompt": "vpn-broker", "decision": "deny", "event": "x"}, denyJoin=False)):
            with self.subTest(row=sorted(row)), mock.patch.dict(windows.RECIPES, {name: row}):
                self.assert_refused(self.family_request(name), "windows_scenario_deny_needs_decision_join")

    def test_the_denial_job_reads_its_administrator_and_nothing_names_its_inputs(self):
        scenario = "windows-scoped-tun.restart-deny"
        self.assertEqual(windows.RECIPES[scenario], windows.admit_start(self.root, self.family_request(scenario), self.resolver))
        plan = native_scenario_execution_plan(self, scenario)
        bundle, verified = windows.verified_bundle(self.root, plan, self.resolver)
        source, _ = windows.render_program(plan, windows._binding(self.root, plan), bundle, verified, TARGET,
                                           value=self.input_value(scenario), packages={})
        job_plan = ast.literal_eval(re.search(r"^PLAN=(.*)$", source, re.M)[1])
        self.assertEqual(windows._binding(self.root, plan)["setup"]["administrator"], job_plan["administrator"])
        self.assertEqual({"install": self.prior}, job_plan["prior"])
        self.assertEqual({"variant": "restart-deny"}, job_plan["row"]["tun"])
        # The typed input carries no TUN field: the stage inputs are the job's own.
        for name in ("uacDecisionId", "expectedApprovingAdminSid", "collectorSourceSha256", "variant"):
            with self.subTest(field=name):
                self.assert_refused(self.family_request(scenario, value=self.scenario_input(scenario, **{name: "x"})), "windows_scenario_input_invalid")

    def input_value(self, scenario):
        return {"schema": windows.INPUT_SCHEMA, "schemaVersion": 1, "scenarioId": scenario, "correlationId": self.operation,
                "deploymentId": MACHINE, "sourceSha": self.head, "productVersion": "2.2.15", "artifactSetId": self.set_id,
                "priorInstall": self.prior}


class UpdateBase(FamilyDriverBase):
    """A fixture pair's target and receipt, frozen together; the base was installed earlier by a family row."""

    def setUp(self):
        super().setUp()
        self.target_install = str(uuid.uuid4())
        self.receipt = self.register(json.dumps(self.fixture_receipt()).encode(), "fixture-receipt.json", "desktop-update-fixture-receipt", source=self.head)
        self.update_set = self.freeze([self.msi, self.receipt])

    def fixture_receipt(self, **changes):
        msi = self.msi["path"].read_bytes()

        def asset(version, sha):
            name = "vpn-control-" + version + ".msi"
            return {"platform": "windows", "architecture": "x86_64", "packageType": "msi", "displayVersion": version, "fileName": name,
                    "downloadUrl": windows._FIXTURE_URL + name, "sha256": sha, "sizeBytes": len(msi)}
        target = asset("2.2.15", hashlib.sha256(msi).hexdigest())
        value = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False, "sourceFingerprint": "f" * 64, "nativeOs": "Windows-11",
                 "architecture": "x86_64",
                 "builds": [{"label": "base", "version": "2.2.14", "sourceFingerprint": "f" * 64, "codeFingerprint": "c" * 64, "assets": [asset("2.2.14", "e" * 64)]},
                            {"label": "target", "version": "2.2.15", "sourceFingerprint": "f" * 64, "codeFingerprint": "c" * 64, "assets": [target]}],
                 "manifest": {"schemaVersion": 1, "buildNumber": host_job.version_build("2.2.15"), "releaseTag": "disposable-desktop-fixture",
                              "releaseNotesUrl": "https://github.com/Karapsin/vpn_control/releases/tag/disposable-desktop-fixture", "assets": [target]}}
        value.update(changes)
        return value

    def update_input(self, variant, **changes):
        value = {"artifactSetId": self.update_set, "baseVersion": "2.2.14", "targetInstall": self.target_install, **changes}
        return self.scenario_input(UPDATE + variant, **value)

    def update_request(self, variant, *, receipt=None, value=None, target=None):
        artifacts = {"bundleManifest": "sha256-" + self.bundle_hash, "scenarioInput": value or self.update_input(variant),
                     "targetPackage": target or self.msi["artifactId"], "fixtureReceipt": receipt or self.receipt["artifactId"]}
        return self.request(scenarioId=UPDATE + variant, artifactIds=artifacts)


class UpdateAdmissionTests(UpdateBase):
    def test_the_admitted_rows_pass_admission_before_any_journal(self):
        for variant in ("public-ready", "download-cancelled", "checksum-rejected"):
            with self.subTest(variant=variant):
                self.assertEqual(windows.RECIPES[UPDATE + variant], windows.admit_start(self.root, self.update_request(variant), self.resolver))
                self.assertFalse(self.journal.exists())

    def test_every_other_row_is_refused_before_any_journal_with_what_it_lacks(self):
        for variant in windows.UPDATE_VARIANTS:
            reason = windows.RECIPES[UPDATE + variant]["refusal"]
            if reason is not None:
                with self.subTest(variant=variant):
                    self.assert_refused(self.update_request(variant), reason)

    def test_the_input_names_an_older_base_and_the_earlier_install_of_its_target(self):
        variant = "public-ready"
        for change, reason in (({"baseVersion": "2.2.13"}, "windows_scenario_update_base_baseline"),
                               ({"baseVersion": "2.2.15"}, "windows_scenario_update_not_newer"),
                               ({"baseVersion": "2.3.0"}, "windows_scenario_update_not_newer"),
                               ({"baseVersion": "2.2"}, "windows_scenario_input_invalid"),
                               ({"targetInstall": self.operation}, "windows_scenario_input_invalid"),
                               ({"targetInstall": self.prior}, "windows_scenario_input_invalid"),
                               ({"targetInstall": "install"}, "windows_scenario_input_invalid")):
            with self.subTest(change=change):
                self.assert_refused(self.update_request(variant, value=self.update_input(variant, **change)), reason)
        plain = self.scenario_input(UPDATE + variant, artifactSetId=self.update_set)
        self.assert_refused(self.update_request(variant, value=plain), "windows_scenario_input_invalid")

    def test_the_receipt_must_describe_the_admitted_target_package(self):
        variant = "public-ready"
        good = self.fixture_receipt()
        target = good["manifest"]["assets"][0]
        cases = {"other-digest": {"sha256": "0" * 64}, "other-size": {"sizeBytes": 1}, "other-version": {"displayVersion": "2.2.16"},
                 "path-name": {"fileName": "..\\vpn-control.msi"}, "other-url": {"downloadUrl": "https://example.invalid/x.msi"}}
        for name, change in cases.items():
            with self.subTest(case=name):
                asset = dict(target, **change)
                builds = [good["builds"][0], dict(good["builds"][1], assets=[asset])]
                receipt = self.register(json.dumps(self.fixture_receipt(builds=builds, manifest=dict(good["manifest"], assets=[asset]))).encode(),
                                        "fixture-receipt.json", "desktop-update-fixture-receipt", source=self.head)
                fixture_set = self.freeze([self.msi, receipt])
                self.assert_refused(self.update_request(variant, receipt=receipt["artifactId"], value=self.update_input(variant, artifactSetId=fixture_set)),
                                    "windows_scenario_fixture_receipt")
        for name, receipt_value in (("two-sources", self.fixture_receipt(builds=[dict(good["builds"][0], sourceFingerprint="d" * 64), good["builds"][1]])),
                                    ("two-codes", self.fixture_receipt(builds=[dict(good["builds"][0], codeFingerprint="d" * 64), good["builds"][1]])),
                                    ("base-not-older", self.fixture_receipt(builds=[dict(good["builds"][0], version="2.2.15"), good["builds"][1]])),
                                    ("production-trust", self.fixture_receipt(productionTrustChanged=True))):
            with self.subTest(case=name):
                receipt = self.register(json.dumps(receipt_value).encode(), "fixture-receipt.json", "desktop-update-fixture-receipt", source=self.head)
                fixture_set = self.freeze([self.msi, receipt])
                self.assert_refused(self.update_request(variant, receipt=receipt["artifactId"], value=self.update_input(variant, artifactSetId=fixture_set)),
                                    "windows_scenario_fixture_receipt")
        loose = self.register(json.dumps(self.fixture_receipt(nativeOs="Windows-loose")).encode(), "fixture-receipt.json", "desktop-update-fixture-receipt",
                              source=self.head)
        self.assert_refused(self.update_request(variant, receipt=loose["artifactId"]), "windows_scenario_package_not_frozen")
        foreign = self.register(json.dumps(self.fixture_receipt(nativeOs="Windows-foreign")).encode(), "fixture-receipt.json",
                                "desktop-update-fixture-receipt", source="f" * 40)
        self.assert_refused(self.update_request(variant, receipt=foreign["artifactId"]), "windows_scenario_package_source")
        kind = self.register(json.dumps(self.fixture_receipt(nativeOs="Windows-kind")).encode(), "fixture-receipt.json", "fixture-receipt", source=self.head)
        self.assert_refused(self.update_request(variant, receipt=kind["artifactId"]), "windows_scenario_package_kind")

    def test_the_deny_row_and_the_tooled_grant_rows_are_admitted_before_any_journal(self):
        """The chain now takes its request in the O:SYD:PAI form the publisher's files read back, terminal-actors reads the
        owner-only disposition through the backup privilege alone, and the job discovers a grant's coordinator, worker
        and returned owner for its stages. At 70ed16cc the deny row was refused windows_scenario_update_collector_unproven
        and the grant rows windows_scenario_update_grant_unproven."""
        for variant in ("uac-denied", "success-off", "wait-client-loss", "installer-wait-client-loss"):
            with self.subTest(variant=variant):
                self.assertEqual(windows.RECIPES[UPDATE + variant], windows.admit_start(self.root, self.update_request(variant), self.resolver))
                self.assertFalse(self.journal.exists())

    def test_the_cancel_watch_copy_lock_and_connected_rows_are_admitted_before_any_journal(self):
        """install-cancelled has its SYSTEM cancel watch, participating-copy-lock its fault inputs and fault-ready actor, and
        the connected rows their loopback profile, upstream and sampler. At 9a8db1e5 the first three were refused before
        any journal (windows_scenario_update_cancel_actors_unobserved, _copy_lock_fixture_unavailable,
        _reconnect_fixture_unavailable) and success-explicit-off was no scenario."""
        for variant in ("install-cancelled", "participating-copy-lock", "success-reconnect", "success-explicit-off"):
            with self.subTest(variant=variant):
                self.assertEqual(windows.RECIPES[UPDATE + variant], windows.admit_start(self.root, self.update_request(variant), self.resolver))
                self.assertFalse(self.journal.exists())

    def test_a_deny_row_needs_collect_to_join_its_decision(self):
        row = dict(windows.RECIPES[UPDATE + "uac-denied"], denyJoin=False, refusal=None)
        with mock.patch.dict(windows.RECIPES, {UPDATE + "uac-denied": row}):
            self.assert_refused(self.update_request("uac-denied"), "windows_scenario_deny_needs_decision_join")


class SecondAdministratorAdmissionTests(UpdateBase):
    """T6: different-admin was refused at admission (windows_scenario_update_second_administrator_unavailable): the fixture
    had one administrator account. A clone whose setup names a second Administrators account now admits it, and its job
    plan names that account beside the fixture administrator; any other clone refuses it before any journal."""

    def second_administrator(self, name="recoveryapprover"):
        path = self.root / ".rag_index/windows-vm-deploy-intents" / (MACHINE + ".intent.json")
        intent = json.loads(path.read_text())
        intent["setup"]["secondAdministrator"] = name
        path.write_text(json.dumps(intent))

    def admitted(self, variant):
        try:
            return windows.admit_start(self.root, self.update_request(variant), self.resolver)
        except ValueError as error:
            self.fail("refused: " + str(error))

    def test_a_clone_with_a_second_administrator_admits_the_different_admin_row(self):
        self.second_administrator()
        self.assertEqual(windows.RECIPES[UPDATE + "different-admin"], self.admitted("different-admin"))
        self.assertFalse(self.journal.exists())
        for variant in ("success-off", "uac-denied", "public-ready"):
            with self.subTest(variant=variant):
                self.assertEqual(windows.RECIPES[UPDATE + variant], self.admitted(variant), "the clone's other rows stay admitted")

    def test_a_clone_without_one_refuses_it_before_any_journal(self):
        self.assert_refused(self.update_request("different-admin"), "windows_scenario_update_second_administrator_absent")

    def test_its_job_grants_with_the_second_administrator_and_names_the_fixture_one(self):
        self.second_administrator()
        self.admitted("different-admin")
        plans = {}
        for variant in ("different-admin", "success-off"):
            plan = execution.ScenarioPlan.from_mapping(self.update_request(variant))
            bundle, verified = windows.verified_bundle(self.root, plan, self.resolver)
            value = windows.scenario_input(self.root, plan, windows.RECIPES[UPDATE + variant])
            source, _ = windows.render_program(plan, windows._binding(self.root, plan), bundle, verified, TARGET, value=value, packages={})
            plans[variant] = ast.literal_eval(re.search(r"^PLAN=(.*)$", source, re.M)[1])
        self.assertEqual(("recoveryadmin", "recoveryapprover", "second-administrator"),
                         tuple(plans["different-admin"].get(key) for key in ("administrator", "approvingAdministrator"))
                         + (plans["different-admin"]["row"].get("approver"),))
        self.assertEqual(("recoveryadmin", None, None), tuple(plans["success-off"].get(key) for key in ("administrator", "approvingAdministrator"))
                         + (plans["success-off"]["row"].get("approver"),), "the fixture administrator approves every other grant")


class UpdateSubmitTests(UpdateBase):
    def program_plan(self):
        program = json.loads(self.root.joinpath(*windows._LOCAL_STATE, self.operation, "program.json").read_text())
        return submitted_bindings(program["program"]["source"])["PLAN"]

    def test_target_and_receipt_are_staged_and_the_job_names_its_base_and_target_install(self):
        self.assertEqual("submitted", self.executor().start(self.update_request("public-ready"))["state"])
        self.assertEqual(["target", "stage-write", "stage-write", "prepare", "submit"], self.ssh.calls)
        plan = self.program_plan()
        self.assertEqual({"targetPackage", "fixtureReceipt"}, set(plan["packages"]))
        for role, artifact in (("targetPackage", self.msi), ("fixtureReceipt", self.receipt)):
            self.assertEqual(artifact["path"].read_bytes(), self.ssh.staged[plan["packages"][role]["sha256"]])
        self.assertEqual({"sourceSha": self.head, "productVersion": "2.2.15", "baseVersion": "2.2.14"}, plan["product"])
        self.assertEqual({"install": self.prior, "targetInstall": self.target_install}, plan["prior"])
        self.assertEqual("recoveryadmin", plan["administrator"])
        self.assertNotIn(str(self.sources), json.dumps(plan))


class UpdateObservationTests(UpdateBase):
    def setUp(self):
        super().setUp()
        self.executor().start(self.update_request("uac-denied"))
        self.status_file = HOME + "/.cache/vpn-control-windows-scenarios/" + MACHINE + "/" + self.operation

    def status(self, value):
        self.ssh.job_files["status.json"] = value
        return self.executor().status(self.operation)["reason"]

    def test_the_prompt_stays_pending_from_every_event_until_its_decision_is_known(self):
        token = "uac-pending:install-helper:deny"
        self.assertEqual("original_owner_running", self.status({"pendingKinds": [], "uacEvents": []}))
        # Sixteen child events after the prompt's: the recent window no longer names it, the sticky list does.
        window = ["child-started", "child-intent"] * 8
        self.assertEqual(token, self.status({"pendingKinds": window, "uacEvents": ["update-uac-action-pending"], "uacDecision": None}))
        self.assertEqual("original_owner_running", self.status({"pendingKinds": ["update-uac-action-pending"], "uacEvents": []}),
                         "only the sticky list counts")
        decided = {"state": "input-ack-only", "decision": "deny", "prompt": "install-helper", "promptClosed": True}
        self.assertEqual("original_owner_running", self.status({"pendingKinds": window, "uacEvents": ["update-uac-action-pending"], "uacDecision": decided}))
        self.assertEqual(1, self.ssh.submits)


class UpdateCollectionTests(UpdateBase):
    def setUp(self):
        super().setUp()
        self.executor().start(self.update_request("uac-denied"))
        self.decision = str(uuid.uuid5(uuid.UUID(self.operation), "windows-uac-decision"))

    def job_receipt(self, exit_code=0):
        plan = {"scenarioId": UPDATE + "uac-denied", "operationId": self.operation, "machine": MACHINE, "bundleHash": self.bundle_hash}
        value = host_job.build_receipt(plan, exit_code=exit_code, stage="receipt", failure=None, guest_programs=40)
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()

    def terminal(self, **changes):
        return {"state": "input-ack-only", "operationId": self.decision, "attempt": 1, "decision": "deny", "prompt": "install-helper",
                "promptClosed": True, "approvalSucceeded": False, "productOutcomeProved": False, "replayAllowed": False, **changes}

    def test_a_passed_deny_row_completes_only_with_its_decision_terminal(self):
        self.finished(raw=self.job_receipt())
        for decision in (None, self.terminal(promptClosed=False), self.terminal(decision="approve"), self.terminal(state="input-outcome-unknown"),
                         self.terminal(operationId=str(uuid.uuid4())), self.terminal(extra="x")):
            with self.subTest(decision=decision):
                self.ssh.decision = decision
                result = self.executor().status(self.operation)
                self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))
                self.assertNotIn("scenarioEvidence", result)
        self.ssh.decision = self.terminal()
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "passed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual("deny-acknowledged-prompt-closed", result["scenarioEvidence"]["windows"]["uacDecision"])
        self.assertEqual(("/owned/vm", self.decision), self.ssh.decision_reads[-1], "the VM root the decision was written under")
        self.assertEqual({"evidenceClass": "installed-package-unproven", "productAction": True}, windows.public_evidence(result))

    def test_a_deny_whose_decision_refused_stays_unsettled(self):
        # An expired prompt is the same denial as Esc: a deny row's pass with no typed Esc proves nothing, refused or not.
        self.finished(raw=self.job_receipt())
        self.ssh.decision_reply = {"state": "refused", "attempts": 1, "reason": "instance_uac_frame_unrecognized"}
        result = self.executor().status(self.operation)
        self.assertEqual(("unknown", "terminal_collection_unverified"), (result["state"], result["reason"]))

    def test_a_failed_deny_row_needs_no_join(self):
        self.finished(exit_code=1, raw=self.job_receipt(exit_code=1))
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete", "failed"), (result["state"], result["collectionState"], result["scenarioEvidence"]["result"]))
        self.assertEqual([], self.ssh.decision_reads)


def run_plain(source, cwd):
    """A submitted program as the durable owner runs it: plain python3, isolated, no VM anywhere."""
    return subprocess.run([sys.executable, "-I", "-B", "-c", "import sys;exec(compile(sys.stdin.buffer.read(),'job','exec'),{'__name__':'__main__'})"],
                          input=source.encode(), cwd=cwd, capture_output=True, env={"PATH": os.defpath}, timeout=120)


class CachedBodyTests(DriverBase):
    """S6: the job body every row of one bundle runs waits in the host's artifact cache; only a small loader travels.

    Natively the 1.2 MB program went through the saved-program route on every row (median 47 s for its submit: bind,
    stage, custody, run) and stage-check was its own contact. RED on a34e07cb: the driver has no cached body.
    """

    def setUp(self):
        super().setUp()
        self.ssh.staged.clear()  # An empty host cache: the first row of a bundle.

    def test_an_unchanged_body_is_staged_once_per_host_and_every_submit_fits_one_inline_child(self):
        self.assertEqual("submitted", self.executor().start(self.request())["state"])
        self.assertEqual(["target", "stage-write", "prepare", "submit"], self.ssh.calls, "one read finds the body absent, one write stages it")
        local = self.root.joinpath(*windows._LOCAL_STATE, self.operation)
        body = (local / "job-body.py").read_bytes()
        self.assertEqual(body, self.ssh.staged[hashlib.sha256(body).hexdigest()], "the host holds the exact local bytes")
        self.assertEqual(0o600, (local / "job-body.py").stat().st_mode & 0o777)
        program = json.loads((local / "program.json").read_text())["program"]
        self.assertNotIn("FILES_GZ", program["source"], "the bundle is in the cached body, not in the program")
        self.assertEqual({"SPEC", "SETUP", "CONTEXT", "PLAN"}, set(submitted_bindings(program["source"])))
        packet = json.loads((local / "admission.json").read_text())
        submit = carrier.durable_command(self.operation, program, packet, mode="submit", wait_seconds=2)
        self.assertLess(sum(len(part.encode()) + 1 for part in submit), 60000 // 2,
                        "under ssh_transport's inline bound with room for a nested route's quoting")
        for _ in range(2):
            self.operation = str(uuid.uuid4())
            self.ssh.calls.clear()
            self.assertEqual("submitted", self.executor().start(self.request())["state"])
            self.assertEqual(["target", "prepare", "submit"], self.ssh.calls, "an unchanged body is never sent again")
        self.assertEqual(1, len(self.ssh.staged))

    def test_a_cached_copy_that_differs_refuses_before_any_preparation(self):
        digest = hashlib.sha256(self.body).hexdigest()
        for state in ("differs", "unsafe", None):
            with self.subTest(state=state):
                self.operation = str(uuid.uuid4())
                self.ssh.calls.clear()
                self.ssh.cache_states = {digest: state}
                started = self.executor().start(self.request())
                self.assertEqual(("not_submitted", "not_submitted:windows_scenario_stage_unavailable"), (started["state"], started["reason"]))
                self.assertEqual(["target"], self.ssh.calls)
                self.assertEqual(0, self.ssh.submits)

    def test_the_loader_over_the_cached_body_runs_what_the_single_program_runs(self):
        home = self.work / "host-home"
        cache = home / ".cache/vpn-control-windows-scenarios/artifacts"
        cache.mkdir(parents=True, mode=0o700)
        target = dict(TARGET, home=str(home))
        plan = self.plan()
        bundle, verified = windows.verified_bundle(self.root, plan, self.resolver)
        binding = windows._binding(self.root, plan)
        single, data = windows.render_program(plan, binding, bundle, verified, target)
        body = windows.render_job_body(bundle, verified)
        loader, loader_data = windows.render_loader(plan, binding, verified, target, body)
        self.assertEqual(data, loader_data)
        self.assertEqual(set(windows._BINDING_NAMES), set(submitted_bindings(loader)))
        for name in windows._BINDING_NAMES:
            self.assertEqual(submitted_bindings(single)[name], submitted_bindings(loader)[name])
        assigned = {target.id for node in ast.parse(body.decode()).body if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        self.assertFalse(assigned & set(windows._BINDING_NAMES), "the body never rebinds what the loader bound first")
        self.assertEqual(single, body.decode().replace("\nFILES_GZ=", "\n" + "".join(
            name + "=" + repr(submitted_bindings(single)[name]) + "\n" for name in windows._BINDING_NAMES) + "FILES_GZ=", 1)
            + "raise SystemExit(_host_main())\n", "the single program is the body with the bindings and the last line in place")
        path = cache / hashlib.sha256(body).hexdigest()
        path.write_bytes(body)
        path.chmod(0o600)
        isolated = self.work / "isolated"
        isolated.mkdir()
        ran = {name: run_plain(source, isolated) for name, source in (("single", single), ("loader", loader))}
        for name, done in ran.items():
            self.assertEqual(2, done.returncode, name + ": " + done.stderr.decode("utf-8", "replace"))
        self.assertEqual(ran["single"].stdout, ran["loader"].stdout, "the same refusal, from the same code, without a VM")
        self.assertTrue(windows._exit_marker(ran["loader"].stdout, self.operation)["failure"].startswith("host_setup:"))
        self.assertEqual([], list(isolated.iterdir()))
        self.assertFalse(Path(data).exists())
        for change, failure in ((lambda: path.write_bytes(body[:-1] + b"#"), "host_setup:job_body_changed"),
                                (lambda: path.chmod(0o644), "host_setup:job_body_unsafe"),
                                (lambda: path.unlink(), "host_setup:job_body_unavailable")):
            with self.subTest(failure=failure):
                path.unlink(missing_ok=True)
                path.write_bytes(body)
                path.chmod(0o600)
                change()
                done = run_plain(loader, isolated)
                self.assertEqual(2, done.returncode, done.stderr.decode("utf-8", "replace"))
                self.assertEqual({"schemaVersion": 1, "operationId": self.operation, "scenarioExit": 2, "failure": failure},
                                 windows._exit_marker(done.stdout, self.operation), "refused before a byte of the body ran")


class HostSubmitRaceTests(DriverBase):
    """Windows VM operator B, 2026-11-17 (bf9266d7, NE2 different-admin).

    The target read found the job body 7c0869fe absent from the host's artifact cache; before this submit's write,
    another operator's submit staged the same content-addressed body, so _STAGE answered present. _stage accepted only
    staged and raised, and the executor recorded a submit that never left the host as the ambiguous
    submit_response_unavailable, then job_not_discovered UNKNOWN with no identity. Beforeimages:
    fixtures/windows_host_submit (fd17037c).
    """

    def before(self, name):
        fixture = Path(__file__).parent / "fixtures" / "windows_host_submit"
        source = fixture / name
        self.assertEqual(json.loads((fixture / "provenance.json").read_bytes())["files"][name]["sha256"],
                         hashlib.sha256(source.read_bytes()).hexdigest())
        return source

    @contextmanager
    def unfixed(self):
        """The driver's _stage and submit and the executor's start exactly as they were at fd17037c."""
        functions = {}
        for name, module in (("stage.before.source", windows), ("submit.before.source", windows),
                             ("executor_start.before.source", execution)):
            namespace = dict(module.__dict__)
            exec(compile(self.before(name).read_bytes(), name, "exec"), namespace)
            functions[name] = namespace
        with mock.patch.object(windows.NativeScenarioWindowsDriver, "_stage", functions["stage.before.source"]["_stage"]), \
                mock.patch.object(windows.NativeScenarioWindowsDriver, "submit", functions["submit.before.source"]["submit"]), \
                mock.patch.object(execution.ScenarioExecutor, "start", functions["executor_start.before.source"]["start"]):
            yield

    def race(self):
        """The target read reports the body absent; another operator's copy of the same bytes is staged before the write."""
        digest = hashlib.sha256(self.body).hexdigest()
        self.ssh.staged[digest] = self.body
        self.ssh.cache_states = {digest: "absent"}
        return digest

    def test_a_body_another_submit_staged_after_the_read_is_used_RED_refused_GREEN(self):
        from agent_tools.tests import red_gate
        digest = self.race()
        if red_gate.red_required(self, *(self.before(name) for name in ("stage.before.source", "submit.before.source",
                                                                        "executor_start.before.source"))):
            with self.unfixed():
                first = self.executor().start(self.request())
                # RED: the present answer refused the submit, recorded as an ambiguous one that resume can never settle.
                self.assertEqual(("submitting", "submit_response_unavailable"), (first["state"], first["reason"]))
                self.assertEqual(["target", "stage-write"], self.ssh.calls)
                self.assertEqual(("unknown", "job_not_discovered"),
                                 tuple(self.executor().resume(self.operation)[key] for key in ("state", "reason")))
            self.operation = str(uuid.uuid4())
            self.ssh.calls.clear()
        started = self.executor().start(self.request())
        self.assertEqual(("submitted", "submitted"), (started["state"], started["reason"]))
        self.assertEqual(["target", "stage-write", "prepare", "submit"], self.ssh.calls, "the present copy is the copy; nothing is resent")
        self.assertEqual(1, self.ssh.submits)
        self.assertEqual({digest: self.body}, self.ssh.staged, "the cached body is the other operator's, unchanged")

    def test_a_different_copy_found_at_the_write_still_refuses_and_is_not_submitted(self):
        digest = self.race()
        self.ssh.staged[digest] = self.body[:-1] + b"#"  # Same name, other bytes: _STAGE hashes it and says differs.
        started = self.executor().start(self.request())
        self.assertEqual(("not_submitted", "not_submitted:windows_scenario_stage_unavailable"), (started["state"], started["reason"]))
        self.assertEqual(["target", "stage-write"], self.ssh.calls)
        self.assertEqual(0, self.ssh.submits)

    def test_the_real_stage_program_answers_present_for_a_copy_staged_after_the_read(self):
        """The fake above answers as _STAGE itself does: run it with a throwaway home, as the host runs it over SSH."""
        home = self.work / "stage-home"
        home.mkdir(mode=0o700)
        body = b"job body " * 1000
        digest = hashlib.sha256(body).hexdigest()

        def write(raw):
            done = subprocess.run([sys.executable, "-I", "-B", "-c", windows._STAGE, digest, str(len(body)), "write"], input=raw,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "HOME": str(home)}, check=True)
            return json.loads(done.stdout)["state"]
        self.assertEqual("staged", write(body), "the first operator's write")
        self.assertEqual("present", write(body), "the second operator's write, whose read found the body absent")
        cached = home / ".cache/vpn-control-windows-scenarios/artifacts" / digest
        self.assertEqual(body, cached.read_bytes())
        cached.chmod(0o600)
        cached.write_bytes(body[:-1] + b"#")
        self.assertEqual("differs", write(body), "a copy that is not this digest's bytes is never taken")

    def test_a_submit_that_fails_before_the_submit_command_is_not_submitted_RED_unknown_GREEN(self):
        from agent_tools.tests import red_gate
        cases = {"target": ("windows_scenario_target_unavailable", ["target"]),
                 "stage-write": ("windows_scenario_stage_unavailable", ["target", "stage-write"]),
                 "prepare": ("windows_scenario_preparation_unavailable", ["target", "stage-write", "prepare"])}
        self.ssh.staged.clear()  # The body is staged by this submit, so a lost write reply is one of the cases.
        if red_gate.red_required(self, *(self.before(name) for name in ("stage.before.source", "submit.before.source",
                                                                        "executor_start.before.source"))):
            with self.unfixed():
                for lost in cases:
                    with self.subTest(before=lost):
                        self.operation = str(uuid.uuid4())
                        self.ssh.calls.clear()
                        self.ssh.staged.clear()
                        self.ssh.lost = {lost}
                        first = self.executor().start(self.request())
                        # RED: nothing that could start the job was sent, yet the record is the ambiguous one, then UNKNOWN.
                        self.assertEqual(("submitting", "submit_response_unavailable"), (first["state"], first["reason"]))
                        self.assertEqual("unknown", self.executor().resume(self.operation)["state"])
        for lost, (reason, calls) in cases.items():
            with self.subTest(lost=lost):
                self.operation = str(uuid.uuid4())
                self.ssh.calls.clear()
                self.ssh.staged.clear()
                self.ssh.lost = {lost}
                first = self.executor().start(self.request())
                self.assertEqual(("not_submitted", "not_submitted:" + reason), (first["state"], first["reason"]))
                self.assertNotIn("jobIdentity", first)
                self.assertEqual(calls, self.ssh.calls)
                for observe in (self.executor().status, self.executor().resume, self.executor().collect):
                    self.assertEqual(("not_submitted", "not_submitted:" + reason),
                                     tuple(observe(self.operation)[key] for key in ("state", "reason")))
                again = self.executor().start(self.request())
                self.assertEqual((True, "not_submitted"), (again["duplicate"], again["state"]))
                self.assertEqual(calls, self.ssh.calls, "a proven-unsent start is never observed, discovered or submitted again")
        self.assertEqual(0, self.ssh.submits)

    def test_a_submit_whose_command_went_out_stays_ambiguous(self):
        self.ssh.lost = {"submit"}
        first = self.executor().start(self.request())
        self.assertEqual(("submitting", "submit_response_unavailable"), (first["state"], first["reason"]))
        self.assertEqual(1, self.ssh.submits)
        self.assertEqual(("submitted", "original_owner_running"),
                         tuple(self.executor().resume(self.operation)[key] for key in ("state", "reason")))
        self.assertEqual(1, self.ssh.submits, "found by correlation, never submitted again")


class CleanStartWiringTests(FamilyDriverBase):
    """S6: only the direct script's wiring asks a product row to prove its own start (host_job Job._since_install).
    RED on a34e07cb: the driver has no clean_start wiring."""

    def plan_of(self, driver, scenario):
        self.operation = str(uuid.uuid4())
        self.assertEqual("submitted", self.executor(driver).start(self.family_request(scenario))["state"])
        program = json.loads(self.root.joinpath(*windows._LOCAL_STATE, self.operation, "program.json").read_text())
        return submitted_bindings(program["program"]["source"])["PLAN"]

    def test_a_product_row_after_no_reset_asks_for_its_proof_and_nothing_else_does(self):
        self.assertIs(True, self.plan_of(self.driver(clean_start=True), "windows-packaged-cli-smoke")["cleanStart"])
        self.assertNotIn("cleanStart", self.plan_of(self.driver(), "windows-packaged-cli-smoke"), "the default plan is unchanged")
        self.assertNotIn("cleanStart", self.plan_of(self.driver(clean_start=True), "windows-msi-base-reset"), "a setup row is the reset")
        binding = {"spec": {}, "setup": {"user": "recovery", "administrator": "recoveryadmin"}, "context": {}}
        value = {"sourceSha": self.head, "productVersion": "2.2.15", "priorInstall": self.prior, "priorPreboot": str(uuid.uuid4())}
        post = execution.ScenarioPlan.from_mapping(self.request(scenarioId="windows-reboot-reconnect.post"))
        bindings, _ = windows._job_bindings(post, binding, {"files": []}, TARGET, stop_after=None, value=value, packages={}, clean_start=True)
        self.assertNotIn("cleanStart", bindings, "a postboot keeps its own chain rules")
        delegate = ssh_driver.NativeScenarioSshDriver(self.root, self.resolver)._windows(self.plan())
        self.assertIs(False, delegate.clean_start, "the MCP route never asks")
        with self.assertRaisesRegex(ValueError, "windows_scenario_clean_start_invalid"):
            self.driver(clean_start="yes")


class CountedAdmissions:
    """admitted_transport as a counter: each entry is one readiness admission."""

    def __init__(self):
        self.entered = 0
        self.open = 0

    @contextmanager
    def __call__(self, root, host, operation, *, deadline=None, requirements=None):
        self.entered += 1
        self.open += 1
        try:
            yield
        finally:
            self.open -= 1


class RowAdmissionTests(DriverBase):
    """S6: one readiness admission per row; each call still revalidates at its dispatch (ssh_transport, unchanged).

    Natively every target, prepare, submit, status, wait and collect call entered its own admission. RED on a34e07cb:
    the driver has no row admission.
    """

    def setUp(self):
        super().setUp()
        self.admissions = CountedAdmissions()
        patcher = mock.patch.object(transport, "admitted_transport", self.admissions)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_row(self, driver):
        executor = self.executor(driver)
        executor.start(self.request())
        for _ in range(3):
            executor.status(self.operation)
        self.finished()
        return executor.status(self.operation)

    def test_one_admission_carries_every_call_of_a_row(self):
        driver = self.driver()
        with driver.row_admission(self.plan()):
            result = self.run_row(driver)
            self.assertEqual(1, self.admissions.open, "held for the whole row")
        self.assertEqual(("terminal", "complete"), (result["state"], result["collectionState"]))
        self.assertEqual((1, 0), (self.admissions.entered, self.admissions.open))
        self.assertEqual(["target", "prepare", "submit", "observe", "observe", "observe", "observe", "collect"], self.ssh.calls)

    def test_without_a_row_admission_each_call_admits_as_before(self):
        self.run_row(self.driver())
        self.assertEqual(6, self.admissions.entered, "submit, three status rounds, the terminal round and its collect")

    def test_a_call_that_got_no_reply_makes_the_next_admit_afresh(self):
        driver = self.driver()
        executor = self.executor(driver)
        with driver.row_admission(self.plan()):
            executor.start(self.request())
            self.ssh.lost = {"observe"}
            result = executor.status(self.operation)
            self.assertEqual(("unknown", "observer_unavailable"), (result["state"], result["reason"]))
            self.assertEqual(1, self.admissions.entered)
            self.assertEqual("submitted", executor.status(self.operation)["state"])
            self.assertEqual(2, self.admissions.entered, "the stale admission was replaced before the next contact")
            self.assertEqual(1, self.admissions.open)
        self.assertEqual(1, self.ssh.submits)

    def test_a_refused_admission_sends_nothing_and_the_next_call_tries_again(self):
        driver = self.driver()
        executor = self.executor(driver)
        refusals = []
        counted = self.admissions

        @contextmanager
        def flaky(root, host, operation, *, deadline=None, requirements=None):
            if refusals:
                raise refusals.pop()
            with counted(root, host, operation, deadline=deadline):
                yield
        with mock.patch.object(transport, "admitted_transport", flaky), driver.row_admission(self.plan()):
            executor.start(self.request())
            self.ssh.lost = {"observe"}
            executor.status(self.operation)
            calls = list(self.ssh.calls)
            refusals.append(ValueError("readiness_deadline"))
            result = executor.status(self.operation)
            self.assertEqual(("unknown", "observer_unavailable"), (result["state"], result["reason"]))
            self.assertEqual(calls, self.ssh.calls, "no admission, no contact")
            self.assertEqual("submitted", executor.status(self.operation)["state"])
        self.assertEqual((2, 1), (counted.entered, self.ssh.submits))

    def test_admissions_are_one_row_at_a_time(self):
        driver = self.driver()
        with driver.row_admission(self.plan()), self.assertRaisesRegex(ValueError, "windows_scenario_row_admission_nested"):
            with driver.row_admission(self.plan()):
                pass


class JobWaitSsh(FakeSsh):
    """Runs the driver's real job wait over a local stand-in for the durable owner's job directory."""

    def __init__(self, directory, job):
        super().__init__(directory)
        self.job_directory = job

    def respond(self, command):
        if command[:4] == ("python3", "-I", "-B", "-c") and ast.literal_eval(command[4][5:-1]) == getattr(windows, "_WAIT_JOB", None):
            self.waits.append(tuple(command[5:]))
            done = subprocess.run([sys.executable, "-I", "-B", "-c", windows._WAIT_JOB, str(self.job_directory), *command[6:]],
                                  capture_output=True, timeout=200)
            return "wait-job", json.loads(done.stdout)
        return super().respond(command)


class JobWaitTests(DriverBase):
    """S6: a client waits on the host for the job's end instead of sleeping and asking status a round late.

    Natively each status round took 39-61 s, so the end was seen up to a round late and every round was a contact.
    RED on a34e07cb: the driver has no job wait.
    """

    def setUp(self):
        super().setUp()
        self.job = self.work / "durable-job"
        self.job.mkdir(mode=0o700)
        body = self.body
        self.ssh = JobWaitSsh(self.work, self.job)
        self.ssh.staged[hashlib.sha256(body).hexdigest()] = body
        self.assertEqual("submitted", self.executor().start(self.request())["state"])

    def owner(self, pid, birth):
        (self.job / "owner.json").write_text(json.dumps({"operationId": self.operation, "owner": {"pid": pid, "birth": birth}}))

    def test_the_end_comes_back_when_the_owner_records_its_terminal(self):
        self.owner(os.getpid(), "darwin:0:0")
        landed = threading.Timer(1.0, (self.job / "terminal.json").write_text, ("{}",))
        landed.start()
        self.addCleanup(landed.cancel)
        began = time.monotonic()
        found = self.driver().wait_job(self.plan(), 100)
        took = time.monotonic() - began
        self.assertEqual((True, "terminal"), (found["ended"], found["why"]))
        self.assertGreaterEqual(took, 1.0)
        self.assertLess(took, 30.0, "it returns when the terminal lands, well before its bound")
        packet = json.loads(self.root.joinpath(*windows._LOCAL_STATE, self.operation, "admission.json").read_text())
        self.assertEqual([(packet["remoteRoot"] + "/" + self.operation, "100")], self.ssh.waits, "the original's own job directory")
        self.assertEqual(1, self.ssh.submits)

    def test_an_owner_gone_without_a_terminal_ends_the_wait(self):
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()
        self.owner(gone.pid, "darwin:0:0")
        found = self.driver().wait_job(self.plan(), 100)
        self.assertEqual((True, "owner-gone"), (found["ended"], found["why"]))
        result = self.executor().status(self.operation)
        self.assertEqual("submitted", result["state"], "the wait decides nothing: status reads the original")

    def test_a_running_owner_holds_the_wait_to_its_bound_and_a_failed_read_proves_nothing(self):
        self.owner(os.getpid(), "darwin:0:0")
        began = time.monotonic()
        found = self.driver().wait_job(self.plan(), 1)
        self.assertEqual((False, None), (found["ended"], found["why"]))
        self.assertGreaterEqual(time.monotonic() - began, 1.0)
        for seconds in (-1, windows._JOB_WAIT_SECONDS + 1, 1.5, True, "5"):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(ValueError, "windows_scenario_job_wait_invalid"):
                self.driver().wait_job(self.plan(), seconds)
        self.ssh.lost.add("wait-job")
        self.assertIsNone(self.driver().wait_job(self.plan(), 0))
        with self.assertRaisesRegex(ValueError, "windows_scenario_job_unknown"):
            self.driver().wait_job(execution.ScenarioPlan.from_mapping(self.request(correlationId=str(uuid.uuid4()))), 1)
        self.assertEqual(1, self.ssh.submits)


class DriverTimingTests(DriverBase):
    """Every driver call and admission is timed beside the job's program record, and the job's own stage times are kept
    from its collect; neither is evidence. RED on a34e07cb: nothing records how long a call took."""

    def test_a_row_measures_itself(self):
        self.executor().start(self.request())
        self.executor().status(self.operation)
        self.finished()
        self.ssh.collect_reply["timing"] = {"schemaVersion": 1, "stages": [{"name": "anchor", "at": 0.0, "seconds": 1.5}], "programs": [],
                                            "seconds": 300.25}
        result = self.executor().status(self.operation)
        self.assertEqual(("terminal", "complete"), (result["state"], result["collectionState"]))
        local = self.root.joinpath(*windows._LOCAL_STATE, self.operation)
        lines = [json.loads(line) for line in (local / "timing.jsonl").read_text().splitlines()]
        self.assertEqual(["admission", "target", "prepare", "submit", "admission", "observe", "admission", "observe", "admission", "collect"],
                         [line["phase"] for line in lines])
        for line in lines:
            self.assertEqual(1, line["schemaVersion"])
            self.assertIsInstance(line["seconds"], float)
            self.assertIsInstance(line["startedAt"], float)
        self.assertEqual(0o600, (local / "timing.jsonl").stat().st_mode & 0o777)
        kept = json.loads((local / "host-timing.json").read_text())
        self.assertEqual(300.25, kept["seconds"])
        record = json.loads((self.journal / (self.operation + ".json")).read_text())
        self.assertNotIn("300.25", record["collection"]["rawJson"], "timing is no part of the collected evidence")

    def test_a_timing_line_that_cannot_be_written_changes_nothing(self):
        local = self.root.joinpath(*windows._LOCAL_STATE, self.operation)
        original = os.open

        def refusing(path, *arguments, **options):
            if str(path).endswith("timing.jsonl"):
                raise PermissionError("read-only")
            return original(path, *arguments, **options)
        with mock.patch.object(windows.os, "open", refusing):
            self.assertEqual("submitted", self.executor().start(self.request())["state"])
        self.assertFalse((local / "timing.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
