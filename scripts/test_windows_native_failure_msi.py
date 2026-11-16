#!/usr/bin/env python3
"""The deliberately failing MSI the Windows fixture workflow derives (windows_native_failure_msi.py).

The product schedule here is the InstallExecuteSequence read offline from two CI MSIs
(agent_tools/tests/fixtures/windows_public_update_defects/real-msi-schedule.json). msi.dll itself runs only on the
Windows fixture builder: FakeMsi stands for its database API, applying the three fixed statements as the engine
applies them, so the derivation's own read-back check is what these tests exercise.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

import windows_native_failure_msi as recipe


ROOT = Path(__file__).resolve().parent.parent
SCHEDULE = ROOT / "agent_tools/tests/fixtures/windows_public_update_defects/real-msi-schedule.json"


def product_snapshot():
    """The product MSI as the builder reads it: the real execute sequence, its identity, and its user streams."""
    value = json.loads(SCHEDULE.read_text(encoding="utf-8"))
    value["streams"] = {"\x05SummaryInformation": {"sizeBytes": 412, "sha256": "1" * 64},
                        "cab1.cab": {"sizeBytes": 61234567, "sha256": "2" * 64},
                        "Binary.JpLauncher": {"sizeBytes": 9000, "sha256": "3" * 64}}
    value["tables"]["Media"] = {"columns": [["DiskId", "i2"], ["LastSequence", "I4"], ["Cabinet", "S255"]], "rows": [["1", "209", "#cab1.cab"]]}
    return value


class FakeMsi:
    """msi.dll's database API as a peer: one snapshot per file name. apply runs the recipe's three statements as the
    engine runs them (CREATE TABLE adds the declared columns, INSERT adds one row with omitted nullable columns NULL and
    integers read back as text), persists the package code and rewrites the summary property set. ``extra`` stands
    for an engine that also changes something else, and the database bytes change as a real commit's would."""

    def __init__(self, base, extra=None):
        self.base, self.extra, self.files, self.calls = base, extra, {}, []

    def inspect(self, path):
        self.calls.append(("inspect", Path(path).name))
        return copy.deepcopy(self.files.get(Path(path).name, self.base))

    def apply(self, path, code):
        self.calls.append(("apply", Path(path).name, code))
        snapshot = copy.deepcopy(self.base)
        for sql in (recipe.CREATE_TABLE, recipe.INSERT_CONDITION, recipe.INSERT_ACTION):
            self.execute(snapshot, sql)
        snapshot["summary"]["9"] = {"type": 30, "value": code}
        snapshot["streams"]["\x05SummaryInformation"] = {"sizeBytes": 412, "sha256": hashlib.sha256(code.encode()).hexdigest()}
        if self.extra is not None:
            self.extra(snapshot)
        self.files[Path(path).name] = snapshot
        with open(path, "ab") as stream:
            stream.write(b"\0committed " + code.encode())

    @staticmethod
    def execute(snapshot, sql):
        create = re.fullmatch(r"CREATE TABLE `(\w+)` \((.*) PRIMARY KEY `(\w+)`\)", sql)
        if create is not None:
            if create[1] in snapshot["tables"]:
                raise ValueError("table exists")
            columns = []
            for part in create[2].split(", "):
                found = re.fullmatch(r"`(\w+)` CHAR\((\d+)\)( NOT NULL)?( LOCALIZABLE)?", part.strip())
                kind = ("l" if found[4] else "s") if found[3] else ("L" if found[4] else "S")
                columns.append([found[1], kind + found[2]])
            snapshot["tables"][create[1]] = {"columns": columns, "rows": []}
            return
        insert = re.fullmatch(r"INSERT INTO `(\w+)` \((.*)\) VALUES \((.*)\)", sql)
        table = snapshot["tables"][insert[1]]
        names = [name.strip().strip("`") for name in insert[2].split(",")]
        values = [value.strip() for value in insert[3].split(",")]
        row = [None] * len(table["columns"])
        for name, value in zip(names, values):
            row[[column[0] for column in table["columns"]].index(name)] = value[1:-1] if value.startswith("'") else str(int(value))
        table["rows"].append(row)
        table["rows"].sort(key=recipe.encoded)


def pair(directory, target_bytes):
    """A fixture directory as `prepare_desktop_update_fixture.py build` leaves it, with its target MSI."""
    name = "vpn-control-2.2.16.msi"
    target = {"platform": "windows", "architecture": "x86_64", "packageType": "msi", "displayVersion": "2.2.16", "fileName": name,
              "downloadUrl": recipe.RELEASE_URL + name, "sha256": hashlib.sha256(target_bytes).hexdigest(), "sizeBytes": len(target_bytes)}
    base = dict(target, displayVersion="2.2.15", fileName="vpn-control-2.2.15.msi", downloadUrl=recipe.RELEASE_URL + "vpn-control-2.2.15.msi",
                sha256="e" * 64)
    receipt = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False, "sourceFingerprint": "f" * 64, "nativeOs": "Windows-2025",
               "architecture": "x86_64",
               "builds": [{"label": "base", "version": "2.2.15", "assets": [base]}, {"label": "target", "version": "2.2.16", "assets": [target]}],
               "manifest": {"schemaVersion": 1, "buildNumber": 16520, "assets": [target]}}
    (directory / "packages" / "target").mkdir(parents=True)
    (directory / "packages" / "target" / name).write_bytes(target_bytes)
    (directory / "fixture-receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return receipt, target


class ScheduleTest(unittest.TestCase):
    def test_the_product_schedule_takes_the_declared_failure_before_every_change(self):
        before = product_snapshot()
        facts = recipe.validate_schedule(before)
        self.assertEqual(("vpn-control", recipe.UPGRADE_CODE, "2.2.16"), (facts["productName"], facts["upgradeCode"], facts["productVersion"]))
        code = recipe.package_code("f" * 64, "a" * 64, "b" * 64)
        after = recipe.expected_after(before, code)
        self.assertEqual({"columns": [["Condition", "s255"], ["Description", "l255"]], "rows": [["0", "VPN_CONTROL_NATIVE_ACCEPTANCE_DELIBERATE_FAILURE"]]},
                         after["tables"]["LaunchCondition"])
        sequence = {row[0]: int(row[2]) for row in after["tables"]["InstallExecuteSequence"]["rows"]}
        self.assertEqual(100, sequence["LaunchConditions"])
        self.assertLess(sequence["AppSearch"], sequence["LaunchConditions"])
        # RemoveExistingProducts runs at 798, outside the install transaction: the failure comes before it, so the base stays.
        self.assertLess(sequence["LaunchConditions"], sequence["RemoveExistingProducts"])
        self.assertLess(sequence["LaunchConditions"], sequence["InstallInitialize"])
        self.assertTrue(all(number > 100 for name, number in sequence.items() if name not in recipe.READ_ONLY_ACTIONS))
        self.assertEqual(code, after["summary"]["9"]["value"])
        changed = {name for name in set(before["tables"]) | set(after["tables"]) if before["tables"].get(name) != after["tables"].get(name)}
        self.assertEqual({"LaunchCondition", "InstallExecuteSequence"}, changed)
        self.assertEqual(before["streams"], after["streams"])

    def test_a_schedule_with_a_launch_condition_or_an_earlier_change_is_refused(self):
        def sequence(snapshot, action, number):
            rows = [row for row in snapshot["tables"]["InstallExecuteSequence"]["rows"] if row[0] != action]
            snapshot["tables"]["InstallExecuteSequence"]["rows"] = [*rows, [action, None, str(number)]]

        def table(snapshot):
            snapshot["tables"]["LaunchCondition"] = {"columns": [["Condition", "s255"], ["Description", "l255"]], "rows": []}
        cases = {"own-launch-condition-table": (table, "msi-launch-condition-table-present"),
                 "own-launch-conditions-action": (lambda s: sequence(s, "LaunchConditions", 400), "msi-launch-conditions-action-present"),
                 "early-removal": (lambda s: sequence(s, "RemoveExistingProducts", 90), "msi-execute-sequence-modifying-before-failure"),
                 "early-custom-action": (lambda s: sequence(s, "JpEarlyAction", 60), "msi-execute-sequence-modifying-before-failure"),
                 "slot-taken": (lambda s: sequence(s, "CostInitialize", 100), "msi-execute-sequence-slot-taken"),
                 "late-search": (lambda s: sequence(s, "AppSearch", 150), "msi-execute-sequence-search-order"),
                 "no-install": (lambda s: s["tables"]["InstallExecuteSequence"]["rows"].remove(["InstallInitialize", None, "1500"]),
                                "msi-execute-sequence-actions"),
                 "other-product": (lambda s: s["tables"]["Property"]["rows"].__setitem__(3, ["UpgradeCode", "{11111111-2222-4333-8444-555555555555}"]),
                                   "msi-product-upgrade-code")}
        for name, (change, reason) in cases.items():
            with self.subTest(case=name):
                snapshot = product_snapshot()
                change(snapshot)
                with self.assertRaisesRegex(recipe.Refused, "^" + reason + "$"):
                    recipe.validate_schedule(snapshot)

    def test_the_package_code_is_derived_from_its_inputs_and_is_never_the_parents(self):
        code = recipe.package_code("f" * 64, "a" * 64, "b" * 64)
        self.assertRegex(code, r"\A\{[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}\}\Z")
        self.assertEqual(code, recipe.package_code("f" * 64, "a" * 64, "b" * 64))
        self.assertNotEqual(code, recipe.package_code("f" * 64, "c" * 64, "b" * 64))
        before = product_snapshot()
        with self.assertRaisesRegex(recipe.Refused, "msi-derived-package-code"):
            recipe.expected_after(before, recipe.product(before)["packageCode"])


class DeriveTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.target_bytes = b"MSI target " * 4096
        self.receipt, self.target = pair(self.directory, self.target_bytes)

    def test_derive_writes_one_failing_msi_and_its_receipt(self):
        native = FakeMsi(product_snapshot())
        receipt = recipe.derive(self.directory, native)
        fault = self.directory / "packages" / "fault" / "vpn-control-2.2.16-native-install-failed.msi"
        raw = fault.read_bytes()
        code = recipe.package_code("f" * 64, self.target["sha256"], recipe.recipe_sha256())
        self.assertEqual([("inspect", self.target["fileName"]), ("apply", fault.name, code), ("inspect", fault.name)], native.calls)
        self.assertEqual({"platform": "windows", "architecture": "x86_64", "packageType": "msi", "displayVersion": "2.2.16", "fileName": fault.name,
                          "downloadUrl": recipe.RELEASE_URL + fault.name, "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)},
                         receipt["output"]["asset"])
        self.assertNotEqual(self.target["sha256"], receipt["output"]["asset"]["sha256"])
        self.assertEqual(self.target, receipt["parent"]["asset"])
        self.assertEqual({"launchCondition": ["0", "VPN_CONTROL_NATIVE_ACCEPTANCE_DELIBERATE_FAILURE"], "executeSequence": ["LaunchConditions", None, 100],
                          "table": {"name": "LaunchCondition", "columns": [["Condition", "s255"], ["Description", "l255"]]},
                          "packageCode": {"before": "{44444444-5555-4666-8777-888888888888}", "after": code}}, receipt["delta"])
        self.assertEqual((recipe.KIND, True, False, False, None, 1603, "f" * 64),
                         (receipt["kind"], receipt["testOnly"], receipt["productionTrustChanged"], receipt["nativeInstallationExecuted"],
                          receipt["nativeAcceptance"], receipt["expectedInstallerResult"], receipt["sourceFingerprint"]))
        written = json.loads((self.directory / recipe.RECEIPT_NAME).read_bytes())
        self.assertEqual(receipt, written)
        for name, key in ((recipe.BEFORE_NAME, "beforeSnapshotSha256"), (recipe.AFTER_NAME, "afterSnapshotSha256")):
            self.assertEqual(hashlib.sha256((self.directory / name).read_bytes()).hexdigest(), receipt[key])
        self.assertFalse(fault.stat().st_mode & 0o222, "the served package is read-only, as the pair's are")
        self.assertEqual(self.target_bytes, (self.directory / "packages" / "target" / self.target["fileName"]).read_bytes())
        self.assertEqual(["vpn-control-2.2.16-native-install-failed.msi"], os.listdir(self.directory / "packages" / "fault"))

    def test_derive_runs_once(self):
        recipe.derive(self.directory, FakeMsi(product_snapshot()))
        with self.assertRaisesRegex(recipe.Refused, "derivation-outputs-exist"):
            recipe.derive(self.directory, FakeMsi(product_snapshot()))

    def test_any_change_beyond_the_declared_one_is_refused_and_left_for_diagnosis(self):
        def summary(snapshot):
            snapshot["summary"]["13"] = {"type": 64, "value": "133700000000000000"}

        def cabinet(snapshot):
            snapshot["streams"]["cab1.cab"] = {"sizeBytes": 1, "sha256": "4" * 64}

        def media(snapshot):
            snapshot["tables"]["Media"]["rows"][0][1] = "210"
        for name, extra in (("summary", summary), ("cabinet", cabinet), ("table", media)):
            with self.subTest(change=name):
                directory = self.directory / name
                directory.mkdir()
                pair(directory, self.target_bytes)
                with self.assertRaisesRegex(recipe.Refused, "unexpected-native-msi-delta"):
                    recipe.derive(directory, FakeMsi(product_snapshot(), extra))
                self.assertFalse((directory / recipe.RECEIPT_NAME).exists(), "no receipt for a package that is not the declared one")
                self.assertTrue((directory / recipe.AFTER_NAME).exists(), "what the engine left is kept for diagnosis")

    def test_only_the_property_set_stream_may_follow_the_package_code(self):
        def property_set(snapshot):
            snapshot["streams"]["\x05SummaryInformation"] = {"sizeBytes": 413, "sha256": "5" * 64}
        receipt = recipe.derive(self.directory, FakeMsi(product_snapshot(), property_set))
        self.assertEqual(recipe.KIND, receipt["kind"])

    def test_a_target_that_is_not_the_pairs_is_refused_before_any_output(self):
        (self.directory / "packages" / "target" / self.target["fileName"]).write_bytes(b"another MSI")
        with self.assertRaisesRegex(recipe.Refused, "target-msi-bytes"):
            recipe.derive(self.directory, FakeMsi(product_snapshot()))
        self.assertFalse((self.directory / "packages" / "fault").exists())

    def test_the_command_needs_its_confirmation(self):
        with self.assertRaisesRegex(recipe.Refused, "explicit-owned-build-confirmation"):
            recipe.main(["derive", "--directory", str(self.directory)])
        self.assertFalse((self.directory / "packages" / "fault").exists())

    @unittest.skipIf(os.name == "nt", "msi.dll exists here")
    def test_the_database_api_is_reached_only_on_windows(self):
        with self.assertRaisesRegex(recipe.Refused, "native-windows-amd64"):
            recipe.SystemMsi()


if __name__ == "__main__":
    unittest.main()
