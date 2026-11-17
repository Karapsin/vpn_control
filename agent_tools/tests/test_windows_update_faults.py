"""T5: the two Windows update fault rows, windows-public-update.native-install-failed and .protected-storage-rejected.

native-install-failed had no producer: the product's MSIs carry no LaunchCondition table, so nothing could make one
fail. The Windows fixture workflow now derives the pair's failing MSI (scripts/windows_native_failure_msi.py); these
tests admit the row with that MSI and its derivation receipt and run its job, which serves the failing MSI in the
target's place. protected-storage-rejected had no counterfeit root and parked unconditionally, in its case and again in
the dedicated driver, so every run was unknown and protected-storage-adversarial could never pass. The case now plants
the counterfeit as the ordinary user, the job serves its SYSTEM stages once no helper process is left, and a correct
product answer settles the run passed or failed with proof, while anything unproven still parks.

Peers: the host job's fake guest (test_windows_scenario_host_job), the admission's real registry and frozen sets in a
throwaway checkout (test_native_scenario_windows), the dedicated driver's dispatch peer (test_windows_ordinary_task),
and for the case module a public CLI, an owner and a file system of its own below. Nothing here runs on Windows.
"""
from __future__ import annotations

import ast
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import subprocess
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_windows as windows
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_scenario_host_job as job
from agent_tools.tests.test_native_scenario_windows import UpdateBase as AdmissionBase
from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer, DedicatedParked
from agent_tools.tests.test_windows_scenario_host_job import (
    ADMIN_SID, BASE, HELPER_BYTES, HELPER_PATH, INSTALLED_ROOT, JOB_ID, PRODUCT_OPERATION, PROFILE, PROTECTED_RECEIPT,
    RETURNED_PID, SESSION, SID, UpdateFamilyBase, UpdateQga, VERSION, WORKER_BIRTH, WORKER_PID, WORKER_READY, out_data, process_row,
)
from agent_tools.windows_public_updater import update_cases


UPDATE = "windows-public-update."
FAILING = UPDATE + "native-install-failed"
COUNTERFEIT = UPDATE + "protected-storage-rejected"
WORKER_RESULT = PROFILE + "\\AppData\\Local\\vpn-control-install-inputs\\" + JOB_ID + "\\worker-result.json"
# The documented failing MSI, written out here rather than read from the code under test: one LaunchCondition "0" in a
# new table, its action at InstallExecuteSequence 100, and a new package code (scripts/windows_native_failure_msi.py).
FAULT_KIND = "windows-native-install-failed-msi"
FAULT_DELTA = {"launchCondition": ["0", "VPN_CONTROL_NATIVE_ACCEPTANCE_DELIBERATE_FAILURE"], "executeSequence": ["LaunchConditions", None, 100],
               "table": {"name": "LaunchCondition", "columns": [["Condition", "s255"], ["Description", "l255"]]}}
RELEASE_URL = "https://github.com/Karapsin/vpn_control/releases/download/disposable-desktop-fixture/"
UPGRADE_CODE = "{7A5E0A8E-2A7A-4BAF-9F2A-5FB2C3529AF2}"
PARENT_CODE, FAULT_CODE = "{44444444-5555-4666-8777-888888888888}", "{55555555-6666-4777-8888-999999999999}"
FAULT_RECEIPT_LEAF = "native-install-failure.json"
# The counterfeit as the job binds it: the product's machine root, owned by the ordinary user with full control, and a
# canary naming the operation.
COUNTERFEIT_ROOT = "C:\\ProgramData\\vpn-control-install-jobs"
ROOT_SDDL = "O:{sid}G:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{sid})"
CANARY_SDDL = "O:{sid}G:{sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})"


def canary(operation):
    return (json.dumps({"schemaVersion": 1, "kind": "vpn-control-counterfeit-protected-storage-canary", "operationId": operation,
                        "testOnly": True}, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def counterfeit_binding(operation, sid=SID):
    raw = canary(operation)
    return {"kind": "protected-storage-rejected", "path": COUNTERFEIT_ROOT,
            "canary": {"path": COUNTERFEIT_ROOT + "\\counterfeit-canary.json", "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)},
            "canaryText": raw.decode("ascii"), "rootSddl": ROOT_SDDL.format(sid=sid), "canarySddl": CANARY_SDDL.format(sid=sid)}


def asset(target_asset, name, raw):
    return {"platform": "windows", "architecture": "x86_64", "packageType": "msi", "displayVersion": target_asset["displayVersion"],
            "fileName": name, "downloadUrl": RELEASE_URL + name, "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)}


def fault_receipt(target_asset, fault_raw, *, fingerprint="f" * 64, **changes):
    """The fixture workflow's receipt of a failing MSI derived from target_asset (windows_native_failure_msi.build_receipt)."""
    output = asset(target_asset, target_asset["fileName"][:-len(".msi")] + "-native-install-failed.msi", fault_raw)
    value = {"schemaVersion": 1, "kind": FAULT_KIND, "testOnly": True, "productionTrustChanged": False, "sourceFingerprint": fingerprint,
             "recipeSha256": "b" * 64,
             "parent": {"asset": target_asset, "productCode": "{33333333-4444-4555-8666-777777777777}", "upgradeCode": UPGRADE_CODE,
                        "productVersion": target_asset["displayVersion"], "packageCode": PARENT_CODE},
             "output": {"asset": output, "packageCode": FAULT_CODE},
             "delta": {**copy.deepcopy(FAULT_DELTA), "packageCode": {"before": PARENT_CODE, "after": FAULT_CODE}},
             "expectedInstallerResult": 1603, "beforeSnapshotSha256": "1" * 64, "afterSnapshotSha256": "2" * 64,
             "nativeInstallationExecuted": False, "nativeAcceptance": None}
    value.update(changes)
    return value


class AgreementTests(unittest.TestCase):
    def test_the_builder_the_admission_the_job_and_these_tests_name_one_failing_msi_and_one_counterfeit(self):
        from scripts import windows_native_failure_msi as recipe
        self.assertEqual((FAULT_KIND, FAULT_DELTA, "-native-install-failed.msi", 1603, RELEASE_URL, UPGRADE_CODE, FAULT_RECEIPT_LEAF),
                         (recipe.KIND, recipe.DELTA, recipe.FAULT_SUFFIX, recipe.EXPECTED_INSTALLER_RESULT, recipe.RELEASE_URL, recipe.UPGRADE_CODE,
                          recipe.RECEIPT_NAME))
        self.assertEqual((FAULT_KIND, FAULT_DELTA, "-native-install-failed.msi", 1603, RELEASE_URL, UPGRADE_CODE),
                         (windows.FAULT_KIND, windows.FAULT_DELTA, windows.FAULT_SUFFIX, windows.FAULT_INSTALLER_RESULT, windows._FIXTURE_URL,
                          job.UPGRADE_CODE))
        self.assertEqual(FAULT_RECEIPT_LEAF, job.FAULT_RECEIPT_LEAF)
        self.assertEqual((COUNTERFEIT_ROOT, ROOT_SDDL, CANARY_SDDL, canary("x")), (job.INSTALL_JOBS, job.COUNTERFEIT_ROOT_SDDL,
                                                                                job.COUNTERFEIT_CANARY_SDDL, job.counterfeit_canary("x")))
        self.assertEqual((ROOT_SDDL, CANARY_SDDL, "counterfeit-canary.json"),
                         (update_cases.COUNTERFEIT_ROOT_SDDL, update_cases.COUNTERFEIT_CANARY_SDDL, update_cases.COUNTERFEIT_CANARY))


class FailingMsiAdmissionTests(AdmissionBase):
    """native-install-failed was refused windows_scenario_update_fault_unavailable: no failing MSI existed to serve."""

    def setUp(self):
        super().setUp()
        self.target_asset = self.fixture_receipt()["manifest"]["assets"][0]
        self.fault_raw = b"MSI failing " * 5000
        self.fault = self.register(self.fault_raw, "vpn-control-2.2.15-native-install-failed.msi", "desktop-update-fault-package", source=self.head)
        self.fault_receipt = self.register(json.dumps(fault_receipt(self.target_asset, self.fault_raw)).encode(), "native-install-failure.json",
                                           "desktop-update-fault-receipt", source=self.head)
        self.fault_set = self.freeze([self.msi, self.receipt, self.fault, self.fault_receipt])

    def failing_request(self, *, fault=None, receipt=None, frozen=None):
        artifacts = {"bundleManifest": "sha256-" + self.bundle_hash,
                     "scenarioInput": self.update_input("native-install-failed", artifactSetId=frozen or self.fault_set),
                     "targetPackage": self.msi["artifactId"], "fixtureReceipt": self.receipt["artifactId"],
                     "faultPackage": (fault or self.fault)["artifactId"], "faultReceipt": (receipt or self.fault_receipt)["artifactId"]}
        return self.request(scenarioId=FAILING, artifactIds=artifacts)

    def admitted(self, scenario, request):
        try:
            return windows.admit_start(self.root, request, self.resolver)
        except ValueError as error:
            self.fail(scenario + " refused before any journal: " + str(error))

    def test_the_failing_msi_row_is_admitted_with_the_package_its_pair_derived(self):
        self.assertEqual(windows.RECIPES[FAILING], self.admitted(FAILING, self.failing_request()))
        self.assertFalse(self.journal.exists())
        self.assertEqual(("fixtureReceipt", "faultPackage", "faultReceipt"), windows.staged_roles(windows.RECIPES[FAILING]),
                         "the failing MSI is served in the target's place; the target's bytes stay on the host")

    def test_the_counterfeit_root_row_is_admitted(self):
        self.assertEqual(windows.RECIPES[COUNTERFEIT], self.admitted(COUNTERFEIT, self.update_request("protected-storage-rejected")))

    def test_a_failing_msi_that_is_not_this_pairs_declared_one_is_refused(self):
        other = dict(self.target_asset, sha256="0" * 64)
        # A failure scheduled at 900 would come after RemoveExistingProducts (798): the base would be gone when it fails.
        later = {**FAULT_DELTA, "executeSequence": ["LaunchConditions", None, 900], "packageCode": {"before": PARENT_CODE, "after": FAULT_CODE}}
        cases = {"another-parent": (fault_receipt(other, self.fault_raw), "windows_scenario_fault_receipt_parent"),
                 "another-package": (fault_receipt(self.target_asset, b"another failing MSI"), "windows_scenario_fault_receipt_output"),
                 "a-later-failure": (fault_receipt(self.target_asset, self.fault_raw, delta=later), "windows_scenario_fault_receipt_delta"),
                 "another-source": (fault_receipt(self.target_asset, self.fault_raw, fingerprint="d" * 64), "windows_scenario_fault_receipt"),
                 "installed-claim": (fault_receipt(self.target_asset, self.fault_raw, nativeInstallationExecuted=True), "windows_scenario_fault_receipt")}
        for name, (value, reason) in cases.items():
            with self.subTest(case=name):
                receipt = self.register(json.dumps(value).encode(), "native-install-failure.json", "desktop-update-fault-receipt", source=self.head)
                frozen = self.freeze([self.msi, self.receipt, self.fault, receipt])
                self.assert_refused(self.failing_request(receipt=receipt, frozen=frozen), reason)
        loose = self.register(b"MSI loose " * 3000, "vpn-control-2.2.15-native-install-failed.msi", "desktop-update-fault-package", source=self.head)
        self.assert_refused(self.failing_request(fault=loose), "windows_scenario_package_not_frozen")


class FailingMsiQga(UpdateQga):
    """The grant guest of native-install-failed: its SYSTEM stages, a protected terminal FAILED with RUNTIME_FAILED, the
    worker's own MSI result 1603, and the next owner the case starts from the base."""


class FailingMsiJobTests(UpdateFamilyBase):
    def setUp(self):
        super().setUp()
        self.qga = FailingMsiQga()
        self.rt.qga = self.qga
        target = self.packages["targetPackage"]
        name = "vpn-control-" + VERSION + ".msi"
        self.target_asset = {"platform": "windows", "architecture": "x86_64", "packageType": "msi", "displayVersion": VERSION, "fileName": name,
                             "downloadUrl": RELEASE_URL + name, "sha256": target["sha256"], "sizeBytes": target["bytes"]}
        self.pair = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False, "sourceFingerprint": "f" * 64, "architecture": "x86_64",
                     "builds": [{"label": "base", "version": BASE, "assets": [dict(self.target_asset, displayVersion=BASE, sha256="e" * 64)]},
                                {"label": "target", "version": VERSION, "assets": [self.target_asset]}],
                     "manifest": {"schemaVersion": 1, "buildNumber": job.version_build(VERSION), "assets": [self.target_asset]}}
        self.fault_raw = b"MSI failing " * 5000
        self.fault_value = fault_receipt(self.target_asset, self.fault_raw)
        for role, raw in (("fixtureReceipt", json.dumps(self.pair).encode()), ("faultPackage", self.fault_raw),
                          ("faultReceipt", json.dumps(self.fault_value).encode())):
            digest = hashlib.sha256(raw).hexdigest()
            (self.artifacts / digest).write_bytes(raw)
            (self.artifacts / digest).chmod(0o600)
            self.packages[role] = {"sha256": digest, "bytes": len(raw)}

    def failing_guest(self, target):
        self.grant_guest(target)
        self.qga.needs = ["before-install", "fault-ready", "authorization", "terminal-actors", "returned-cleanup"]
        self.qga.product_files[PROTECTED_RECEIPT] = ('{"version":1,"jobId":"' + JOB_ID + '","sequence":6,"phase":"Failed","code":"RUNTIME_FAILED"}').encode()
        self.qga.product_files[WORKER_RESULT] = ('{"version":1,"jobId":"' + JOB_ID + '","exitCode":1603}').encode()
        # The next owner the case starts once the install failed runs the base's CLI, which the installer never replaced.
        files = json.loads((self.machine_data / self.base / job.INVENTORY_NAME).read_bytes())["files"]
        self.qga.returned = {"actors": {"owner": {"pid": RETURNED_PID, "creationFileTime": 134368653065000040, "image": INSTALLED_ROOT + "\\vpn-control-cli.exe",
                                                  "sha256": files["vpn-control-cli.exe"]["sha256"], "sid": SID, "sessionId": SESSION}},
                             "jobId": JOB_ID, "operationId": PRODUCT_OPERATION}
        self.qga.update_effect = None  # The failing MSI changed nothing: the base stays.

    def failing_plan(self, base, target):
        packages = {key: self.packages[key] for key in ("targetPackage", "fixtureReceipt", "faultPackage", "faultReceipt")}
        return self.update_plan("native-install-failed", base, target, packages=packages)

    def harness_inputs(self, plan):
        raw = self.qga.files[job.WORKSPACE_PREFIX + plan["operationId"] + "\\update-harness.py"]
        return ast.literal_eval(ast.parse(raw.decode("utf-8")).body[1].value)

    def test_the_failing_msi_is_served_in_the_targets_place_and_its_grant_stages_are_tooled(self):
        self.base, target = self.prepared()
        self.failing_guest(target)
        plan = self.failing_plan(self.base, target)
        self.addCleanup(self.forget_modules, plan["operationId"])
        code = job.run_job(self.rt, plan, self.files)
        receipt = self.receipt(plan)
        self.assertEqual((0, None, "passed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual(["before-install", "fault-ready", "authorization", "terminal-actors", "returned-cleanup"],
                         [request["collectorRequest"]["stage"] for request in self.qga.collectors])
        inputs = self.harness_inputs(plan)
        content = job.WORKSPACE_PREFIX + plan["operationId"] + "\\mcp-update-fixture-" + job.fixture_id(plan["operationId"]) + "\\content"
        served = json.loads(self.qga.files[content + "\\fixture-receipt.json"])
        failing = self.fault_value["output"]["asset"]
        self.assertEqual([failing], served["manifest"]["assets"], "the server's manifest names the failing MSI")
        self.assertEqual([failing], served["builds"][1]["assets"])
        self.assertEqual({key: value for key, value in self.pair.items() if key not in ("builds", "manifest")},
                         {key: value for key, value in served.items() if key not in ("builds", "manifest")}, "nothing else of the pair changes")
        self.assertEqual(self.fault_raw, self.qga.files[content + "\\packages\\target\\" + failing["fileName"]])
        self.assertNotIn(content + "\\packages\\target\\" + self.target_asset["fileName"], self.qga.files, "the target itself is never served")
        derivation = self.qga.files[content + "\\" + FAULT_RECEIPT_LEAF]
        binding = {"kind": "native-install-failed", "admittedFailingMsiMetadata": {"path": content + "\\" + FAULT_RECEIPT_LEAF,
                                                                                    "sha256": hashlib.sha256(derivation).hexdigest(), "sizeBytes": len(derivation)}}
        self.assertEqual(binding, inputs["faultInputs"])
        stages = {request["collectorRequest"]["stage"]: request["collectorRequest"] for request in self.qga.collectors}
        self.assertEqual(binding, stages["fault-ready"]["faultBinding"], "the owner and SYSTEM read one binding")
        self.assertEqual({}, stages["terminal-actors"]["faultBinding"])
        self.assertEqual({"protectedReceipt", "workerResult"}, set(stages["terminal-actors"]["fileInputs"]))
        self.assertEqual(WORKER_RESULT, stages["terminal-actors"]["fileInputs"]["workerResult"]["path"], "the worker's own MSI result")
        self.assertEqual({"pid": RETURNED_PID, "image": INSTALLED_ROOT + "\\vpn-control-cli.exe"},
                         {key: stages["returned-cleanup"]["actors"]["owner"][key] for key in ("pid", "image")},
                         "the next owner runs the base's own CLI")
        self.assertEqual({"installedPackage": True, "packageSha256": self.packages["basePackage"]["sha256"]}, receipt["windows"],
                         "the base stays installed and is what the row claims")
        self.assertEqual("base", receipt["update"]["installedAfter"]["role"])
        self.assertEqual({"servedPackageSha256": failing["sha256"], "servedFileName": failing["fileName"],
                          "faultReceiptSha256": hashlib.sha256(derivation).hexdigest(), "packageCode": self.fault_value["output"]["packageCode"]},
                         receipt["update"]["fault"])

    def stage(self, role, value):
        raw = json.dumps(value).encode()
        digest = hashlib.sha256(raw).hexdigest()
        if not (self.artifacts / digest).exists():
            (self.artifacts / digest).write_bytes(raw)
            (self.artifacts / digest).chmod(0o600)
        self.packages[role] = {"sha256": digest, "bytes": len(raw)}

    def test_a_failing_msi_receipt_that_names_another_target_or_package_stops_before_any_task(self):
        self.base, target = self.prepared()
        # A pair whose target is not this row's targetPackage, with a failing MSI derived from that other target: the
        # receipts agree with each other, and only the join to the row's own target refuses them.
        other = dict(self.target_asset, sha256="0" * 64)
        other_pair = dict(self.pair, builds=[self.pair["builds"][0], dict(self.pair["builds"][1], assets=[other])],
                          manifest=dict(self.pair["manifest"], assets=[other]))
        for name, pair, value in (("another-parent", self.pair, fault_receipt(other, self.fault_raw)),
                                  ("another-package", self.pair, fault_receipt(self.target_asset, b"another failing MSI")),
                                  ("another-pair-target", other_pair, fault_receipt(other, self.fault_raw))):
            with self.subTest(case=name):
                self.failing_guest(target)
                self.stage("fixtureReceipt", pair)
                self.stage("faultReceipt", value)
                plan = self.failing_plan(self.base, target)
                self.addCleanup(self.forget_modules, plan["operationId"])
                code = job.run_job(self.rt, plan, self.files)
                receipt = self.receipt(plan)
                self.assertEqual((1, "fixture_receipt_identity", "publish"), (code, receipt["failure"], receipt["stage"]))
                self.assertNotIn("system-run", self.qga.kinds())
                self.forget(plan)


class CounterfeitQga(UpdateQga):
    """protected-storage-rejected's guest. The product root is absent before the task; the case plants its counterfeit;
    the helper image's census shows what is still running when terminal-actors is asked for, one list per census; and
    the root lists as SYSTEM finds it at each read, one listing per read in order."""

    def __init__(self):
        super().__init__()
        self.needs = ["before-install", "fault-ready", "terminal-actors"]
        self.helper_censuses = [[]]
        self.root_listings = [None, (["counterfeit-canary.json"], []), None]
        self.root_listed = []
        self.need_values = {"terminal-actors": {"jobId": None, "productOperationId": PRODUCT_OPERATION}}
        self.install_stdout = None  # The install child's stdout SYSTEM reads at terminal-actors, when not the owner's own.

    def _guest_file_open(self, arguments):
        if arguments["path"].endswith("\\scenario-status.json") and arguments["mode"] == "rb":
            served = [kind for kind, _ in self.programs if kind == "collector"]
            needs = self.needs[:len(served) + 1]
            self.files[arguments["path"]] = json.dumps({"schemaVersion": 1, "poll": len(self.calls), "pendingKinds": [], "parkedFiles": list(self.parked_files),
                                                        "uacEvents": ["update-uac-action-pending"] if served else [],
                                                        "nativeNeeds": [{"name": "event", "ordinal": i, "stage": stage,
                                                                         **self.need_values.get(stage, {"jobId": None, "productOperationId": None})}
                                                                        for i, stage in enumerate(needs)]}).encode()
            return super(UpdateQga, self)._guest_file_open(arguments)
        return super()._guest_file_open(arguments)

    def _publisher(self, m, pid):
        if m["action"] == "list-tree" and m["treeRoot"] == job.INSTALL_JOBS:
            found = self.root_listings.pop(0) if self.root_listings else None
            self.root_listed.append(found)
            self.trees[job.INSTALL_JOBS] = found
            if found is None:
                self.trees.pop(job.INSTALL_JOBS)
        if m["action"] == "collector-observe" and m.get("census") is not None and m["census"]["image"] == HELPER_PATH:
            # The publisher matches the process snapshot's own leaf name, so a process it could not open (no image read)
            # is listed too: this census is set whole rather than filtered by each row's image.
            rows = self.helper_censuses.pop(0) if len(self.helper_censuses) > 1 else self.helper_censuses[0]
            self.processes = []
            terminal = super()._publisher(m, pid)
            reply = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(terminal["out-data"]))))
            reply["observation"]["census"] = json.loads(json.dumps(rows))
            files = reply["observation"].get("files") or {}
            if self.install_stdout is not None and "child-0005.stdout.raw" in files:
                files["child-0005.stdout.raw"] = base64.b64encode(self.install_stdout.encode()).decode()
            return {**terminal, "out-data": out_data(reply)}
        return super()._publisher(m, pid)


def helper_rows():
    """A coordinator that refused the root has gone; its original-user worker still polls until its own deadline."""
    owner = ["913", "134368653065000006"]
    return [process_row(WORKER_PID, 921, WORKER_BIRTH, HELPER_PATH, [HELPER_PATH, "install-user", JOB_ID, *owner], SID, 0, image_bytes=HELPER_BYTES)]


def unopened_rows():
    """A process of the helper image's name that the SYSTEM census listed but could not open: only its ids, as the
    publisher's Describe reports one. It may be the worker itself, so it is not yet gone."""
    return [{"pid": WORKER_PID, "parentPid": 921, "openError": 5, "creationFileTime": None, "alive": None, "image": None, "argv": None,
             "token": None, "imageSha256": None, "imageSizeBytes": None, "parent": None}]


class CounterfeitJobTests(UpdateFamilyBase):
    def setUp(self):
        super().setUp()
        self.qga = CounterfeitQga()
        self.rt.qga = self.qga

    def counterfeit(self, *, task_exit=None):
        base, target = self.prepared()
        self.to_base()
        self.qga.update_effect = None
        self.qga.task_exit = task_exit  # The update task's own exit; the installs before it passed.
        plan = self.update_plan("protected-storage-rejected", base, target)
        self.addCleanup(self.forget_modules, plan["operationId"])
        code = job.run_job(self.rt, plan, self.files)
        return plan, code, self.receipt(plan)

    def test_terminal_actors_waits_for_every_helper_process_then_serves_the_counterfeit_as_system_saw_it(self):
        self.qga.helper_censuses = [helper_rows(), helper_rows(), []]
        plan, code, receipt = self.counterfeit()
        self.assertEqual((0, None, "passed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual(["before-install", "fault-ready", "terminal-actors"], [request["collectorRequest"]["stage"] for request in self.qga.collectors])
        self.assertTrue(all(request["closeHold"] is None for request in self.qga.collectors), "no close hold: the row may end a known failure")
        binding = counterfeit_binding(plan["operationId"])
        stages = {request["collectorRequest"]["stage"]: request["collectorRequest"] for request in self.qga.collectors}
        self.assertEqual(binding, stages["fault-ready"]["faultBinding"])
        self.assertEqual(binding, stages["terminal-actors"]["faultBinding"])
        self.assertEqual(({}, {}, None, PRODUCT_OPERATION), (stages["terminal-actors"]["actors"], stages["terminal-actors"]["fileInputs"],
                                                               stages["terminal-actors"]["jobId"], stages["terminal-actors"]["productOperationId"]))
        raw = self.qga.files[job.WORKSPACE_PREFIX + plan["operationId"] + "\\update-harness.py"]
        self.assertEqual(binding, ast.literal_eval(ast.parse(raw.decode()).body[1].value)["faultInputs"])
        canary_only = {"present": True, "files": ["counterfeit-canary.json"], "directories": []}
        absent = {"present": False, "files": [], "directories": []}
        self.assertEqual({"rootBefore": absent, "helperPolls": 3, "helperProcessesSeen": 1, "rootAtTerminal": canary_only, "rootAfter": absent},
                         receipt["update"]["fault"])
        self.assertEqual({"installedPackage": True, "packageSha256": self.packages["basePackage"]["sha256"]}, receipt["windows"])
        self.assertEqual([None, (["counterfeit-canary.json"], []), None], self.qga.root_listed, "listed before, at terminal-actors and after the task")

    def test_a_clone_whose_product_made_its_own_root_stops_before_any_task(self):
        self.qga.root_listings = [(["gate-0123", "88888888-9999-4aaa-8bbb-cccccccccccc/status.json"], ["88888888-9999-4aaa-8bbb-cccccccccccc"])]
        plan, code, receipt = self.counterfeit()
        self.assertEqual((1, "protected_root_present", "publish"), (code, receipt["failure"], receipt["stage"]))
        self.assertNotIn("system-run", self.qga.kinds(), "no task, so the run never counts")

    def test_a_helper_process_that_never_leaves_keeps_the_outcome_unknown(self):
        self.qga.helper_censuses = [helper_rows()]
        plan, code, receipt = self.counterfeit()
        self.assertEqual((job.EXIT_UNKNOWN, "counterfeit_installer_actors_live:1"), (code, receipt["failure"]))
        self.assertEqual(["before-install", "fault-ready"], [request["collectorRequest"]["stage"] for request in self.qga.collectors],
                         "terminal-actors is never served while an installer actor lives")
        self.assertFalse(self.fence(plan, ".terminal.json").exists(), "the fence stays open")

    def test_a_helper_process_the_census_could_not_open_is_waited_for(self):
        """Only a census that lists no process of the helper image at all ends the wait."""
        self.qga.helper_censuses = [unopened_rows(), []]
        plan, code, receipt = self.counterfeit()
        self.assertEqual((0, None), (code, receipt["failure"]))
        self.assertEqual((2, 1), (receipt["update"]["fault"]["helperPolls"], receipt["update"]["fault"]["helperProcessesSeen"]))

    def test_a_helper_process_the_census_never_opens_keeps_the_outcome_unknown(self):
        self.qga.helper_censuses = [unopened_rows()]
        plan, code, receipt = self.counterfeit()
        self.assertEqual((job.EXIT_UNKNOWN, "counterfeit_installer_actors_live:1"), (code, receipt["failure"]))
        self.assertEqual(["before-install", "fault-ready"], [request["collectorRequest"]["stage"] for request in self.qga.collectors])
        self.assertFalse(self.fence(plan, ".terminal.json").exists(), "the fence stays open")

    def test_a_helper_process_listed_again_at_terminal_actors_leaves_the_outcome_open(self):
        """terminal-actors takes the census once more: any process of the helper image there, opened or not, means the
        product may still act, so no collector is served and the owner keeps waiting."""
        self.qga.helper_censuses = [[], unopened_rows()]
        plan, code, receipt = self.counterfeit()
        self.assertEqual((job.EXIT_UNKNOWN, "collector_stage_failed:terminal-actors:collector_counterfeit_terminal"), (code, receipt["failure"]))
        self.assertEqual(["before-install", "fault-ready"], [request["collectorRequest"]["stage"] for request in self.qga.collectors])
        self.assertFalse(self.fence(plan, ".terminal.json").exists(), "the fence stays open")

    def test_a_known_failure_keeps_what_system_listed_after_the_task(self):
        """The case settled a definite wrong answer (exit 1): the base is read back and the root listed beside the failure."""
        plan, code, receipt = self.counterfeit(task_exit=1)
        self.assertEqual((1, "task_exit_code"), (code, receipt["failure"]))
        self.assertEqual({"present": False, "files": [], "directories": []}, receipt["update"]["fault"]["rootAfter"])
        self.assertEqual("base", receipt["update"]["installedAfter"]["role"])
        self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])

    def test_the_products_process_admission_refusal_is_served_at_terminal_actors(self):
        """5c54358f: the install child answered the CLI's local UNAVAILABLE, with no controller or operation, because the
        product's process admission refused the root before any owner contact. terminal-actors took any reply without
        a controller for unobserved, so the owner would have waited on it for good; it is served, and the case's known
        failure (exit 1) is read with the base and the root's removal."""
        self.qga.install_stdout = NATIVE_ADMISSION_REFUSAL
        self.qga.need_values = {"terminal-actors": {"jobId": None, "productOperationId": None}}
        plan, code, receipt = self.counterfeit(task_exit=1)
        self.assertEqual((1, "task_exit_code"), (code, receipt["failure"]))
        self.assertEqual(["before-install", "fault-ready", "terminal-actors"], [request["collectorRequest"]["stage"] for request in self.qga.collectors])
        self.assertEqual({"present": False, "files": [], "directories": []}, receipt["update"]["fault"]["rootAfter"])
        self.assertEqual("base", receipt["update"]["installedAfter"]["role"])

    def test_a_reply_without_a_controller_that_is_not_the_admission_refusal_stays_unobserved(self):
        for name, change in (("maybe-delivered", {"code": "OUTCOME_UNKNOWN", "message": "OUTCOME_UNKNOWN", "final": False}),
                             ("owner-metadata-claimed", {"warnings": []}),
                             ("operation-named", {"operationId": PRODUCT_OPERATION})):
            with self.subTest(case=name):
                self.setUp()  # A fresh journal: an UNKNOWN run leaves its fence open for the next.
                body = json.loads(NATIVE_ADMISSION_REFUSAL)
                body.update(change)
                self.qga.install_stdout = json.dumps(body)
                self.qga.need_values = {"terminal-actors": {"jobId": None, "productOperationId": body["operationId"]}}
                plan, code, receipt = self.counterfeit(task_exit=1)
                self.assertEqual((job.EXIT_UNKNOWN, "collector_stage_failed:terminal-actors:collector_counterfeit_terminal"), (code, receipt["failure"]))

    def test_a_root_still_there_or_changed_after_a_passed_task_is_this_rows_failure(self):
        for name, listings, failure in (("left", [None, (["counterfeit-canary.json"], []), (["counterfeit-canary.json"], [])], "counterfeit_root_left"),
                                        ("changed", [None, (["counterfeit-canary.json", "gate-0123"], []), None], "counterfeit_root_changed")):
            with self.subTest(case=name):
                self.qga = CounterfeitQga()
                self.rt.qga = self.qga
                self.qga.root_listings = listings
                plan, code, receipt = self.counterfeit()
                self.assertEqual((1, failure, "installed"), (code, receipt["failure"], receipt["stage"]))
                self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])


# The installed CLI's own stdout in 5c54358f (NE3, tools 3a081133, fixture set S_Q from f4a66b93), byte for byte: the
# install child's answer while the counterfeit root stood. Main.kt runs DesktopWindowsProcessAdmission before any CLI
# parsing or owner contact; DesktopWindowsInstallAdmission pins ProgramData\vpn-control-install-jobs as the product's
# final root, WindowsInstallTrust refuses its user owner ("Untrusted installer owner"), and Main prints the local
# desktopCliJsonFailure(UNAVAILABLE), exit 2.
NATIVE_ADMISSION_REFUSAL = ('{"schemaVersion":1,"controllerId":null,"requestId":"e19f74b3-7124-497c-a957-b7410603e31c","ok":false,'
                            '"code":"UNAVAILABLE","message":"UNAVAILABLE","messageKey":null,"messageArgs":[],"final":true,'
                            '"operationId":null,"configurationRevision":0,"restartRequired":false,"data":{},'
                            '"warnings":["OWNER_METADATA_UNAVAILABLE"]}\n')


def admission_refusal():
    """What any new CLI process prints while the product refuses the root at process admission: a fresh request id."""
    body = json.loads(NATIVE_ADMISSION_REFUSAL)
    body["requestId"] = str(uuid.uuid4())
    return subprocess.CompletedProcess([], 2, json.dumps(body, separators=(",", ":")) + "\n", "")


class CounterfeitCli:
    """The public CLI one update case reaches, answered by its arguments, and the install's own reply.

    refusing() models the product's process admission (Main.kt, DesktopWindowsProcessAdmission): while it is true every
    new CLI process answers the local UNAVAILABLE before it parses its command or reaches any owner. calls keeps each
    invocation's own arguments beside whether it was refused so.
    """

    def __init__(self, controller):
        self.controller, self.commands, self.install, self.calls = controller, [], None, []
        self.refusing = lambda: False

    def envelope(self, code="OK", *, exit_code=0, final=True, **data):
        body = {"schemaVersion": 1, "ok": exit_code == 0, "code": code, "final": final, "controllerId": self.controller,
                "configurationRevision": 4, "requestId": "aaaaaaaa-0000-4000-8000-000000000001", "data": data}
        return subprocess.CompletedProcess([], exit_code, json.dumps(body), "")

    def answer(self, arguments):
        refused = self.refusing()
        self.calls.append((list(arguments), refused))
        if refused:
            return admission_refusal()
        words = [word for word in arguments if word not in {"--json", "--async"}]
        guarded = "--if-revision" in words
        while words and words[0] in {"--controller-id", "--if-revision"}:
            words = words[2:]
        self.commands.append(words)
        if words == ["status"] and guarded:
            # An admitted CLI refuses a revision guard on a read itself (DesktopCli: UNSUPPORTED), before any owner.
            body = json.loads(NATIVE_ADMISSION_REFUSAL)
            body.update(code="UNSUPPORTED", message="UNSUPPORTED")
            return subprocess.CompletedProcess([], 1, json.dumps(body), "")
        if words == ["operations", "list"]:
            return self.envelope(operations=[{"controllerId": self.controller, "id": "bbbbbbbb-0000-4000-8000-000000000002",
                                              "operation": "updates.download", "phase": "succeeded", "final": True, "code": "OK"}])
        if words == ["status"]:
            return self.envelope(runtimeRunning=False, activeMode=None, selectedLocationId=None, activeLocationId=None)
        if words[:2] == ["updates", "status"]:
            return self.envelope(available=True, compatible=True, availableVersion="2.2.16", totalBytes=3, phase="ready", downloadedBytes=3)
        if words == ["updates", "download"]:
            body = json.loads(self.envelope("ACCEPTED", final=False).stdout)
            body["operationId"] = "bbbbbbbb-0000-4000-8000-000000000002"
            return subprocess.CompletedProcess([], 0, json.dumps(body), "")
        if words[:2] in (["updates", "transport-probe"], ["updates", "check"], ["operations", "wait"]) or words == ["quit"]:
            return self.envelope()
        raise AssertionError("unexpected public command: " + repr(words))


class CounterfeitChild:
    def __init__(self, owner, label, argv, completed=None):
        self.owner, self.label, self.argv, self.completed_value = owner, label, tuple(argv), completed
        self.pid, self.birth, self.ordinal, self.terminal = 4100 + len(owner.children), "134368653065000001", len(owner.children), None
        self.process = types.SimpleNamespace(poll=lambda: None if self.terminal is None else 0, _handle=1)

    def wait(self):
        self.terminal = {"exitCode": 0, "eof": {"stdout": True, "stderr": True}}
        return self.terminal

    def completed(self):
        self.wait()
        return self.completed_value


class Parked(BaseException):
    pass


class CounterfeitOwner:
    """The original ordinary owner as the case reaches it: children, events, parking and the public CLI."""

    def __init__(self, root):
        self.root, self.operation = root, "2c731e91-c158-4e8a-b779-54076ce85229"
        self.children, self.events, self.parked, self.environment, self.modules = [], [], None, {}, {}
        self.pins = [types.SimpleNamespace(path=Path("C:/owner"))]
        self.request = {"workspace": str(root / "workspace"), "cliPath": "C:\\app\\vpn-control-cli.exe", "casesPath": "C:\\s\\cases.py",
                        "harnessPath": "C:\\s\\h.py", "productVersion": "2.2.15",
                        "context": {"ordinarySid": SID, "ordinarySessionId": SESSION, "bootIdentifier": "boot"}}
        self.by_path = {key.casefold(): types.SimpleNamespace(record={"sha256": "c" * 64}) for key in
                        ("C:\\s\\receipts.py", "C:\\s\\server.py", "C:\\s\\env.py", "C:\\s\\jdk.py", "C:\\s\\prepare.py", "C:\\s\\observer.py",
                         "C:\\s\\lifecycle.py", "C:\\s\\collector.py", self.request["cliPath"])}
        self.native = types.SimpleNamespace(read_blocks=lambda handle: [b"abc"])
        self.cli = CounterfeitCli("controller-1")

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append((kind, value))

    def park(self, reason, error=None):
        # The real owner never returns from park: its first reason is the one recorded.
        if self.parked is None:
            self.parked = (reason, error)
        raise Parked(reason)

    def module(self, path, name):
        return self.modules[path]

    def invoke(self, workspace, *arguments, timeout=30):
        return self.cli.answer(list(arguments))

    def child(self, label, argv, **options):
        child = CounterfeitChild(self, label, argv, self.cli.install if label == "one-public-update-install" else None)
        self.children.append(child)
        return child


class Volume:
    """The guest's file system as the counterfeit and SYSTEM see it: one entry per path, with its identity and security."""

    def __init__(self):
        self.entries, self.next_index, self.calls = {}, 900, []

    def add(self, path, directory, sddl, raw=b""):
        self.next_index += 1
        # Read back as GetSecurityInfo reports a protected DACL set at creation: owner and auto-inherited DACL.
        self.entries[path] = {"directory": directory, "raw": raw, "identity": {"volumeSerial": 7, "fileIndex": self.next_index,
                                                                                "attributes": 16 if directory else 32},
                              "security": {"ownerSid": SID, "sddl": "O:" + SID + "D:PAI" + sddl.split("D:P", 1)[1]}}

    def opening(self, path):
        entry = self.entries[path]
        return {"path": path, "nativeIdentity": dict(entry["identity"]), "security": dict(entry["security"])}

    def children(self, path):
        return sorted(name[len(path) + 1:] for name in self.entries if name.startswith(path + "\\") and "\\" not in name[len(path) + 1:])


class CounterfeitNativePeer:
    """update_cases.CounterfeitNative over the Volume: the same create-only, list and identity-checked delete calls."""

    def __init__(self, volume, *, present=False, remove_error=None):
        self.volume, self.present, self.remove_error = volume, present, remove_error

    def create_directory(self, path, sddl):
        self.volume.calls.append(("create-directory", path, sddl))
        update_cases.require(path not in self.volume.entries and not self.present, "counterfeit-root-present")
        self.volume.add(path, True, sddl)

    def create_file(self, path, sddl, raw):
        self.volume.calls.append(("create-file", path, sddl))
        update_cases.require(path not in self.volume.entries, "counterfeit-canary-exists")
        self.volume.add(path, False, sddl, raw)

    def names(self, path):
        return self.volume.children(path)

    def remove(self, path, directory, identity):
        self.volume.calls.append(("remove", path, directory))
        if self.remove_error is not None:
            raise self.remove_error
        entry = self.volume.entries[path]
        update_cases.require(entry["directory"] is directory and {key: entry["identity"][key] for key in ("volumeSerial", "fileIndex")}
                             == {key: identity[key] for key in ("volumeSerial", "fileIndex")}, "counterfeit-identity-changed")
        update_cases.require(not directory or not self.volume.children(path), "counterfeit-root-not-empty")
        del self.volume.entries[path]

    def absent(self, path):
        return path not in self.volume.entries


class CounterfeitCaseTests(unittest.TestCase):
    """The case's own half of protected-storage-rejected, run through update_cases.run_update over declared peers.

    It used to park in every outcome ("protected-storage-refused-requires-exact-native-reconciliation"), so a correct
    product refusal was as unknown as anything else. Each outcome below ends passed, failed or parked for its own reason.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.owner = CounterfeitOwner(Path(temporary.name))
        self.volume = Volume()
        self.native = CounterfeitNativePeer(self.volume)
        self.system_writes = None  # What the product does to the root between fault-ready and terminal-actors.
        self.fixture = types.SimpleNamespace(ready={"sourceFingerprint": "f" * 64}, closed=False, owner_jvm_environment=dict,
                                             manifest={"assets": [{"displayVersion": "2.2.16", "sizeBytes": 3, "sha256": hashlib.sha256(b"abc").hexdigest(),
                                                                   "fileName": "t.msi"}]})
        self.fixture.close_known = lambda **options: setattr(self.fixture, "closed", options == {"all_update_operations_terminal": True})
        self.registration = []
        lease = types.SimpleNamespace(files=[types.SimpleNamespace(digest=lambda: self.registration.append("base-file"))], retired=False, admitted=False)
        receipts = types.SimpleNamespace(within=lambda *_: True, InstalledApplicationLease=lambda *_: lease,
                                         installed_registration=lambda *_: self.registration.append("base-registration") or {},
                                         preserve=lambda *_: None, canonical_uuid=lambda value: value, machine_security=lambda *_: None,
                                         canonical_path=lambda value: PureWindowsPath(value), FileObservation=self.observation())
        self.owner.modules = {"C:\\s\\receipts.py": receipts, "C:\\s\\server.py": types.SimpleNamespace(UpdateFixture=lambda *_: self.fixture),
                              "C:\\s\\env.py": types.SimpleNamespace(), "C:\\s\\jdk.py": types.SimpleNamespace(),
                              "C:\\s\\prepare.py": types.SimpleNamespace(require_install_ready=lambda *_: None,
                                                                         desktop_install_arguments=lambda *_, **__: ["--json", "updates", "install"]),
                              "C:\\s\\observer.py": types.SimpleNamespace(), "C:\\s\\lifecycle.py": types.SimpleNamespace()}
        self.binding = counterfeit_binding(self.owner.operation)
        inputs = {"schemaVersion": 1, "variant": "protected-storage-rejected", "sourceSha": "a" * 40, "sourceFingerprint": "f" * 64,
                  "modules": {"receipts": "C:\\s\\receipts.py", "server": "C:\\s\\server.py", "fixture_environment": "C:\\s\\env.py",
                              "macos_packaging_jdk_preflight": "C:\\s\\jdk.py", "prepare_desktop_update_fixture": "C:\\s\\prepare.py",
                              "broker_observer": "C:\\s\\observer.py", "lifecycle": "C:\\s\\lifecycle.py", "collector": "C:\\s\\collector.py"},
                  "fixture": {"fixtureId": "x", "content": "c", "state": "s", "certificate": "e", "privateKey": "k", "trustStore": "t", "certificateSha256": "h"},
                  "baseVersion": "2.2.15", "targetVersion": "2.2.16", "installedRoot": "C:\\app", "guiPath": "C:\\app\\vpn-control.exe",
                  "baseInventory": {"a": {"sizeBytes": 1, "sha256": "a" * 64}}, "targetInventory": {"a": {"sizeBytes": 1, "sha256": "b" * 64}},
                  "baseRegistration": {}, "targetRegistration": {}, "programData": job.PROGRAM_DATA,
                  "evidenceRoot": job.PROGRAM_DATA + "\\update-evidence-" + self.owner.operation, "collectorSourceSha256": "c" * 64,
                  "ordinarySid": SID, "ordinarySessionId": SESSION, "approvingAdminSid": ADMIN_SID, "initialIntent": "off", "trafficInputs": None,
                  "faultInputs": self.binding, "returnGuiRequired": False, "connectionFixturePath": None, "upstreamFixture": None}
        self.harness = {"UPDATE_INPUTS": inputs}
        self.reply("OUTCOME_UNKNOWN", 2)
        # The product admits no new process while the user-owned root stands (5c54358f): every CLI call the case makes
        # then answers the local UNAVAILABLE. The install child's own reply is set per test.
        self.owner.cli.refusing = lambda: COUNTERFEIT_ROOT in self.volume.entries

    def reply(self, code, exit_code, **changes):
        body = {"schemaVersion": 1, "ok": exit_code == 0, "code": code, "final": True, "controllerId": "controller-1",
                "operationId": "cccccccc-0000-4000-8000-000000000003", "requestId": "dddddddd-0000-4000-8000-000000000004", "data": {}, **changes}
        self.owner.cli.install = subprocess.CompletedProcess([], exit_code, json.dumps(body), "")

    def observation(self):
        test = self

        class Observation:
            """receipts.FileObservation over the Volume, and over the SYSTEM collector's evidence files of this operation."""

            def __init__(self, owner, path, directory=False):
                self.owner, self.path, self.handle = owner, str(path), 1
                stage = re.fullmatch(r".*\\update-evidence-[0-9a-f-]+\\([a-z-]+)\.json", self.path)
                self.stage = stage[1] if stage else None
                if self.path in test.volume.entries:
                    self.opening = test.volume.opening(self.path)
                elif self.stage or self.path.endswith("update-evidence-" + owner.operation):
                    self.opening = {"security": "machine"}
                else:
                    self.opening = {"security": "s"}  # The downloaded package, read through owner.native.read_blocks.

            def read(self, limit):
                if self.path in test.volume.entries:
                    return test.volume.entries[self.path]["raw"]
                return test.evidence(self.stage)

            def describe(self):
                return self.opening

            def _canonical(self):
                pass

            def close(self):
                pass
        return Observation

    def evidence(self, stage):
        """What the SYSTEM collector publishes for one stage: the counterfeit as SYSTEM opens it at that moment."""
        need = [value for kind, value in self.owner.events if kind == "update-native-observation-needed" and value["stage"] == stage][-1]
        if stage == "terminal-actors" and self.system_writes is not None:
            self.system_writes(self.volume)
        root, canary = self.binding["path"], self.binding["canary"]["path"]
        if stage == "before-install":
            observations = {"ordinaryOwner": {"token": {"sid": SID, "elevated": 0}, "pid": 4100, "creationFileTime": 134368653065000001,
                                              "image": "C:\\app\\vpn-control-cli.exe", "sha256": "c" * 64}}
        else:
            fault = {"kind": "protected-storage-rejected", "binding": self.binding, "root": self.volume.opening(root),
                     "canary": {"nativeFile": self.volume.opening(canary), "sha256": hashlib.sha256(self.volume.entries[canary]["raw"]).hexdigest()}}
            observations = {"fault-ready": fault, "terminal-actors": {"protectedStorageRefusal": fault}}[stage]
        return json.dumps({"schemaVersion": 1, "ordinaryTaskOperationId": self.owner.operation, "stage": stage, "sourceSha": "a" * 40,
                           "collectorSourceSha256": "c" * 64, "bootIdentifier": "boot", "jobId": need["jobId"],
                           "productOperationId": need["productOperationId"], "observations": observations}).encode()

    def run_case(self):
        # create=True: the unfixed module has no counterfeit at all, and its run is what the RED records.
        with mock.patch.object(update_cases, "CounterfeitNative", lambda: self.native, create=True), mock.patch.object(update_cases.time, "sleep"):
            try:
                return update_cases.run_update(self.owner, self.harness)
            except Parked:
                return "parked:" + self.owner.parked[0]

    def kinds(self):
        return [kind for kind, _ in self.owner.events]

    def test_a_refused_counterfeit_root_settles_passed_with_proof_and_leaves_nothing(self):
        self.assertEqual(0, self.run_case())
        self.assertIsNone(self.owner.parked)
        kinds = self.kinds()
        self.assertLess(kinds.index("update-counterfeit-root-planted"), kinds.index("update-uac-action-pending"),
                        "the counterfeit exists before the product is asked to install")
        stages = [value["stage"] for kind, value in self.owner.events if kind == "update-native-observation-needed"]
        self.assertEqual(["before-install", "fault-ready", "terminal-actors"], stages)
        self.assertLess(kinds.index("update-counterfeit-root-planted"), [i for i, (k, v) in enumerate(self.owner.events)
                                                                         if k == "update-native-observation-needed" and v["stage"] == "fault-ready"][0])
        self.assertEqual([("create-directory", job.INSTALL_JOBS, self.binding["rootSddl"]),
                          ("create-file", self.binding["canary"]["path"], self.binding["canarySddl"]),
                          ("remove", self.binding["canary"]["path"], False), ("remove", job.INSTALL_JOBS, True)], self.volume.calls)
        self.assertEqual({}, self.volume.entries, "the clone keeps nothing of the counterfeit")
        self.assertTrue(self.fixture.closed)
        self.assertEqual([["quit"]], [command for command in self.owner.cli.commands if command == ["quit"]])
        self.assertTrue(all(child.terminal is not None for child in self.owner.children))
        self.assertEqual(["base-registration", "base-registration", "base-file"], self.registration,
                         "matched before the case and again after the answer: the base is still installed, byte for byte")
        self.assertEqual({"variant": "protected-storage-rejected", "result": 0, "code": "OUTCOME_UNKNOWN", "answeredBy": "owner",
                          "operationId": "cccccccc-0000-4000-8000-000000000003", "systemUnchanged": True, "rootRemoved": True},
                         self.owner.update_counterfeit_settled)
        need = [value for kind, value in self.owner.events if kind == "update-native-observation-needed" and value["stage"] == "terminal-actors"][0]
        self.assertEqual((None, "cccccccc-0000-4000-8000-000000000003"), (need["jobId"], need["productOperationId"]))
        self.assertEqual([], [arguments for arguments, refused in self.owner.cli.calls if refused],
                         "no CLI call while the counterfeit stands: the product admits no new process then")

    def test_the_products_process_admission_refusal_ends_known_with_the_counterfeit_removed(self):
        """5c54358f: the install CLI never reached the owner. Every new product process pins the product's machine root
        at admission and refuses a user-owned one, so the install answered the local UNAVAILABLE (no controller, no
        operation, OWNER_METADATA_UNAVAILABLE) right after the case asked for the prompt, and no prompt ever came. The
        case required the original controller and parked with the counterfeit kept and both collectors read.

        Provable without replay: SYSTEM sees no helper process and the root and canary unchanged; the same admission path
        refuses a probe that, admitted, could reach no owner; only then is the counterfeit removed, after which the
        original owner answers unchanged and its ledger holds no install. UNAVAILABLE is not a refusal the row accepts,
        so the row ends a known failure.
        """
        self.owner.cli.install = subprocess.CompletedProcess([], 2, NATIVE_ADMISSION_REFUSAL, "")
        self.assertEqual(1, self.run_case())
        self.assertIsNone(self.owner.parked)
        self.assertEqual({}, self.volume.entries, "the clone keeps nothing of the counterfeit")
        self.assertEqual({"variant": "protected-storage-rejected", "result": 1, "code": "UNAVAILABLE", "answeredBy": "process-admission",
                          "operationId": None, "systemUnchanged": True, "rootRemoved": True}, self.owner.update_counterfeit_settled)
        stages = [value["stage"] for kind, value in self.owner.events if kind == "update-native-observation-needed"]
        self.assertEqual(["before-install", "fault-ready", "terminal-actors"], stages)
        refused = [arguments for arguments, refused in self.owner.cli.calls if refused]
        self.assertEqual([["--json", "--controller-id", "controller-1", "--if-revision", "4", "status"]], refused,
                         "while the counterfeit stands, only the probe that no admitted CLI could send to an owner")
        kinds = self.kinds()
        self.assertLess(kinds.index("update-counterfeit-admission-refusal-reproduced"), kinds.index("update-counterfeit-root-removed"))
        self.assertLess(kinds.index("update-counterfeit-root-removed"), kinds.index("update-counterfeit-settled"))
        self.assertIn(["operations", "list"], self.owner.cli.commands, "the original owner's ledger, read after the removal")
        self.assertTrue(self.fixture.closed)
        self.assertEqual([["quit"]], [command for command in self.owner.cli.commands if command == ["quit"]])
        self.assertEqual(["base-registration", "base-registration", "base-file"], self.registration)

    def test_a_local_answer_it_cannot_tie_to_admission_parks_with_the_counterfeit_kept(self):
        """Only the admission refusal is provably undelivered. A local answer that may follow delivery, an admission
        that now lets the probe through, or a ledger that names an install leaves the outcome open."""
        maybe_delivered = json.loads(NATIVE_ADMISSION_REFUSAL)
        maybe_delivered.update(code="OUTCOME_UNKNOWN", message="OUTCOME_UNKNOWN", final=False)
        for name, change, reason, kept in (
                ("maybe-delivered", lambda: setattr(self.owner.cli, "install", subprocess.CompletedProcess([], 2, json.dumps(maybe_delivered), "")),
                 "counterfeit-local-reply-open", True),
                ("probe-admitted", lambda: setattr(self.owner.cli, "refusing", lambda: False), "counterfeit-local-refusal-unexplained", True),
                ("install-in-ledger", lambda: self.owner.cli.__dict__.update(answer=self.ledger_with_install(self.owner.cli.answer)),
                 "counterfeit-install-in-ledger-after-local-refusal", False)):
            with self.subTest(case=name):
                self.setUp()
                self.owner.cli.install = subprocess.CompletedProcess([], 2, NATIVE_ADMISSION_REFUSAL, "")
                change()
                result = self.run_case()
                self.assertTrue(str(result).startswith("parked:"), result)
                self.assertIn(reason, str(self.owner.parked[0]) + str(self.owner.parked[1]))
                self.assertFalse(hasattr(self.owner, "update_counterfeit_settled"))
                self.assertEqual(kept, job.INSTALL_JOBS in self.volume.entries)
                if kept:
                    self.assertNotIn("remove", [call[0] for call in self.volume.calls])

    def ledger_with_install(self, answer):
        def wrapped(arguments):
            reply = answer(arguments)
            if arguments[-2:] == ["operations", "list"]:
                body = json.loads(reply.stdout)
                body["data"]["operations"].append({"controllerId": "controller-1", "id": "eeeeeeee-0000-4000-8000-000000000009",
                                                   "operation": "updates.install", "phase": "running", "final": False, "code": None})
                reply = subprocess.CompletedProcess([], 0, json.dumps(body), "")
            return reply
        return wrapped

    def test_each_refusal_passes_and_any_other_definite_answer_is_a_known_failure(self):
        for code, exit_code, expected in (("RUNTIME_FAILED", 1, 0), ("PERMISSION_DENIED", 1, 0), ("CANCELLED", 130, 1),
                                          ("INVALID_ARGUMENT", 1, 1), ("BUSY", 1, 1)):
            with self.subTest(code=code):
                self.setUp()
                self.reply(code, exit_code)
                self.assertEqual(expected, self.run_case())
                self.assertEqual({}, self.volume.entries)
                self.assertEqual((expected, code, True), tuple(self.owner.update_counterfeit_settled[key] for key in ("result", "code", "rootRemoved")))

    def test_an_accepted_install_parks_with_the_counterfeit_kept(self):
        for code in ("OK", "ACCEPTED"):
            with self.subTest(code=code):
                self.setUp()
                self.reply(code, 0, final=code == "OK", data={"handoffReady": True, "jobId": "eeeeeeee-0000-4000-8000-000000000005"})
                self.assertEqual("parked:counterfeit-root-install-accepted-open", self.run_case())
                self.assertEqual({job.INSTALL_JOBS, self.binding["canary"]["path"]}, set(self.volume.entries))
                self.assertNotIn("terminal-actors", [value["stage"] for kind, value in self.owner.events if kind == "update-native-observation-needed"])

    def test_a_root_or_canary_that_changed_parks_and_is_never_removed(self):
        def product_wrote(volume):
            volume.add(job.INSTALL_JOBS + "\\" + JOB_ID, True, "O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)")

        def canary_rewritten(volume):
            volume.entries[self.binding["canary"]["path"]]["raw"] = b"rewritten"
            volume.entries[self.binding["canary"]["path"]]["identity"]["fileIndex"] += 1000
        for name, change, reason in (("product-job-in-root", product_wrote, "counterfeit-root-changed"),
                                     ("canary-rewritten", canary_rewritten, "counterfeit-root-system-changed")):
            with self.subTest(case=name):
                self.setUp()
                self.system_writes = change
                result = self.run_case()
                self.assertTrue(str(result).startswith("parked:"), result)
                self.assertIn(reason, str(self.owner.parked[1]) + str(self.owner.parked[0]))
                self.assertNotIn("remove", [call[0] for call in self.volume.calls], "nothing it did not make alone is ever removed")
                self.assertIn(job.INSTALL_JOBS, self.volume.entries)
                self.assertFalse(hasattr(self.owner, "update_counterfeit_settled"))

    def test_a_root_that_already_exists_is_never_taken_for_the_counterfeit(self):
        self.native.present = True
        self.assertEqual("parked:update-scenario-failed-with-retained-owned-resources", self.run_case())
        self.assertEqual("counterfeit-root-present", str(self.owner.parked[1]))
        self.assertNotIn("update-uac-action-pending", self.kinds(), "no install is asked for")
        self.assertEqual([("create-directory", job.INSTALL_JOBS, self.binding["rootSddl"])], self.volume.calls)

    def test_a_counterfeit_that_could_not_be_removed_parks_with_it_kept(self):
        # The removal now comes before any CLI call after the answer (the product admits no process while the root
        # stands), so the serve and fixture are still open when it fails; the counterfeit names the park.
        self.native.remove_error = OSError(32, "sharing violation")
        self.assertEqual("parked:update-counterfeit-root-retained", self.run_case())
        self.assertFalse(self.fixture.closed, "nothing after the removal ran")
        self.assertIn(job.INSTALL_JOBS, self.volume.entries)
        self.assertFalse(hasattr(self.owner, "update_counterfeit_settled"))

    def test_the_binding_must_be_the_jobs_fixed_form(self):
        for field, value in (("rootSddl", "O:" + SID + "D:P(A;OICI;FA;;;WD)"), ("path", "C:\\ProgramData\\elsewhere"),
                             ("canaryText", "another canary\n")):
            with self.subTest(field=field):
                self.setUp()
                self.harness["UPDATE_INPUTS"]["faultInputs"] = dict(self.binding, **{field: value})
                with self.assertRaisesRegex(AssertionError, "^counterfeit-root-binding$"):
                    self.run_case()
                self.assertIsNone(self.owner.parked, "refused with its inputs, before any effect")
                self.assertEqual(([], []), (self.volume.calls, self.owner.children), "nothing is created from a binding the job did not make")


class CounterfeitDriverTests(unittest.TestCase):
    """The dedicated driver parked protected-storage-rejected whatever its case returned."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.owner = DedicatedDispatchPeer(Path(temporary.name))
        patcher = mock.patch.object(dedicated_driver, "__file__", str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_ordinary_dedicated_driver.py"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_driver(self):
        try:
            return dedicated_driver.run(self.owner, "windows-public-update")
        except DedicatedParked:
            return "parked:" + self.owner.parked["reason"]

    def settled(self, result, **changes):
        return {"variant": "protected-storage-rejected", "result": result, "code": "OUTCOME_UNKNOWN" if result == 0 else "CANCELLED",
                "operationId": "x", "systemUnchanged": True, "rootRemoved": True, **changes}

    def test_a_settled_counterfeit_ends_with_its_own_result(self):
        for result in (0, 1):
            with self.subTest(result=result):
                self.setUp()
                self.owner.update("protected-storage-rejected", hold=False)
                self.owner.result = result
                self.owner.update_counterfeit_settled = self.settled(result)
                self.assertEqual(result, self.run_driver())
                self.assertNotIn("arm", self.owner.calls, "no close hold")
                self.assertIn("dedicated-update-counterfeit-settled", [call[0] for call in self.owner.calls if isinstance(call, tuple)])

    def test_without_its_own_proof_the_row_still_parks(self):
        for name, result, proof in (("no-proof", 0, None), ("other-result", 1, self.settled(0)), ("root-kept", 0, self.settled(0, rootRemoved=False)),
                                    ("system-unproven", 0, self.settled(0, systemUnchanged=None)),
                                    ("grant-proof-only", 1, None), ("other-variant", 0, self.settled(0, variant="uac-denied"))):
            with self.subTest(case=name):
                self.setUp()
                self.owner.update("protected-storage-rejected", hold=False)
                self.owner.result = result
                if proof is not None:
                    self.owner.update_counterfeit_settled = proof
                if name == "grant-proof-only":
                    self.owner.update_cancelled_grant = {"variant": "protected-storage-rejected", "operationId": "x"}
                self.assertEqual("parked:dedicated-counterfeit-settlement-unproven", self.run_driver())


if __name__ == "__main__":
    unittest.main()
