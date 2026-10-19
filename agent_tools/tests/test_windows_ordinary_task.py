from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import xml.etree.ElementTree as ET

from agent_tools import windows_ordinary_task as task


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures/windows_ordinary_task"
FIXTURE_NAMES = ("original-launch.before.source", "original-task.xml",
                 "original-current-task.json", "native-policy-receipt.json", "provenance.json",
                 "extra-action.before.source")
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell.exe") or shutil.which("powershell")


def original_inputs():
    before = (FIXTURES / "original-launch.before.source").read_text(encoding="utf-8")
    xml = (FIXTURES / "original-task.xml").read_bytes().decode("utf-8")
    native = json.loads((FIXTURES / "native-policy-receipt.json").read_bytes())["nativePrincipal"]
    return before, xml, native


def pin(path, *, directory=False, size=1, digest="0" * 64):
    # Synthetic pure-planner inputs only. No native admission/capability is minted.
    identity = {"volumeSerial": 1, "fileIndex": 2, "attributes": 16 if directory else 128}
    if not directory:
        identity.update(sizeBytes=size, links=1, creationFileTime="134368653065000000",
                        lastWriteFileTime="134368653065000000")
    result = {"path": str(path), "nativeIdentity": identity,
              "security": {"ownerSid": "S-1-5-18", "sddl": "O:SYD:P(A;;FA;;;SY)"}}
    if not directory:
        result["sha256"] = digest
    return result


def synthetic_request():
    operation = "2c731e91-c158-4e8a-b779-54076ce85229"
    profile = PureWindowsPath(r"C:\Users\winparityUser")
    local = profile / "AppData" / "Local"
    root = local / ("VpnControlOrdinary-" + operation)
    source = PureWindowsPath(r"C:\ProgramData") / ("VpnControlOrdinarySource-" + operation)
    python = local / "Programs" / "Python313"
    context = {"deploymentId": "d493a373-1d2c-4ab0-bfd4-e93575019dce",
        "ordinarySid": "S-1-5-21-4099058025-2437077614-260217637-1001", "ordinarySessionId": 2,
        "profileRoot": str(profile), "localAppData": str(local),
        "machineGuid": "7b109066-c50e-4138-8969-f83555499b60",
        "bootIdentifier": "11111111-2222-4333-8444-555555555555",
        "bootFileTimeUtc": "134368653065000000"}
    inventory = task.source_inventory()
    ps = inventory["agent_tools/windows_ordinary_task_owner.ps1"]
    py = inventory["agent_tools/windows_ordinary_process_owner.py"]
    source_pin = pin(source / "windows_ordinary_task_owner.ps1", size=ps["sizeBytes"], digest=ps["sha256"])
    worker_pin = pin(source / "windows_ordinary_process_owner.py", size=py["sizeBytes"], digest=py["sha256"])
    files = [source_pin, worker_pin, pin(task.PS),
             *(pin(python / PureWindowsPath(name)) for name in sorted(task.PYTHON_REQUIRED_FILES)),
             pin(source / "qualification space 東京.ps1"),
             pin(r"C:\Windows\System32\msiexec.exe"),
             pin(source / "baseline.msi", size=131228020,
                 digest="8167212cb412c0e0d1c3ad1d60f12fdbc5477043725fd35484bdf6b46db25fb6")]
    directories = sorted({root, *(parent for item in files for parent in PureWindowsPath(item["path"]).parents)}, key=str)
    common = task.common_request(context, operation, str(root), files,
        [pin(directory, directory=True) for directory in directories],
        [{"role": "python-runtime", "root": str(python), "files": sorted(task.PYTHON_REQUIRED_FILES)}],
        python_runtime={"root": str(python), "interpreterPath": str(python / "python.exe"),
                        "version": "3.13.15", "architecture": "amd64"})
    return common, source_pin, worker_pin


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.before, self.xml, self.native = original_inputs()
        self.expected = task.policy_fields(self.xml)

    def test_authentic_xml_bytes_and_native_red_green_receipt(self):
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        for record in provenance["sources"]:
            body = (FIXTURES / record["fixture"]).read_bytes()
            self.assertEqual(record["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(record["sizeBytes"], len(body))
        self.assertIn('encoding="UTF-16"', self.xml)
        self.assertNotIn("<RunLevel>", self.xml)
        result = task.validate_task_policy(self.xml, self.native, self.expected)
        self.assertEqual("omitted-native-limited", result["xmlRunLevel"])
        self.assertIs(False, result["nativeActionAllowed"])

    def test_explicit_least_privilege_is_also_valid(self):
        xml = self.xml.replace("</LogonType>", "</LogonType><RunLevel>LeastPrivilege</RunLevel>")
        self.assertEqual("LeastPrivilege", task.validate_task_policy(xml, self.native,
                                                                   self.expected)["xmlRunLevel"])

    def test_original_native_phase_ambiguity_controls(self):
        xml_changes = {
            "elevated": self.xml.replace("</LogonType>", "</LogonType><RunLevel>HighestAvailable</RunLevel>"),
            "empty": self.xml.replace("</LogonType>", "</LogonType><RunLevel/>"),
            "duplicate": self.xml.replace("</LogonType>", "</LogonType><RunLevel>LeastPrivilege</RunLevel><RunLevel>LeastPrivilege</RunLevel>"),
            "user": self.xml.replace(self.expected["UserId"], "S-1-5-18"),
            "kill": self.xml.replace("PT0S", "PT1M"),
            "trigger": self.xml.replace("<Triggers />", "<Triggers><BootTrigger/></Triggers>")}
        for name, xml in xml_changes.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                task.validate_task_policy(xml, self.native, self.expected)
        for name, field, value in (("com-high", "comRunLevel", 1),
                ("cmdlet-high", "cmdletRunLevel", "Highest"), ("com-null", "comRunLevel", None),
                ("com-string", "comRunLevel", "0"), ("com-bool", "comRunLevel", False),
                ("wrong-logon", "comLogonType", 2), ("wrong-native-user", "comSid", "S-1-5-18")):
            native = {**self.native, field: value}
            with self.subTest(name=name), self.assertRaises(ValueError):
                task.validate_task_policy(self.xml, native, self.expected)

    def test_duplicate_principal_and_xml_declarations_refuse(self):
        for xml in (self.xml.replace("</Principals>", "<Principal/></Principals>"),
                    '<!DOCTYPE Task [<!ENTITY x "value">]>' + self.xml,
                    self.xml * 100):
            with self.assertRaises((ValueError, ET.ParseError)):
                task.validate_task_policy(xml, self.native, self.expected)

    def test_authentic_extra_action_before_red_and_current_green(self):
        xml = self.xml.replace("</Actions>", "<ComHandler><ClassId>{11111111-2222-4333-8444-555555555555}</ClassId></ComHandler></Actions>")
        path = FIXTURES / "extra-action.before.source"
        module = types.ModuleType("_ordinary_extra_action_before")
        module.__file__ = str(path)
        sys.modules[module.__name__] = module
        try:
            exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
            def causal_case(validator):
                with self.assertRaisesRegex(ValueError, "ambiguous"):
                    validator(xml, self.native, self.expected)
            red = unittest.TestResult()
            unittest.FunctionTestCase(lambda: causal_case(module.validate_task_policy)).run(red)
            self.assertEqual(1, len(red.failures), red.errors)
            self.assertEqual([], red.errors)
            green = unittest.TestResult()
            unittest.FunctionTestCase(lambda: causal_case(task.validate_task_policy)).run(green)
            self.assertTrue(green.wasSuccessful(), green.failures + green.errors)
        finally:
            sys.modules.pop(module.__name__, None)

    @unittest.skipUnless(POWERSHELL, "PowerShell unavailable; native original RED receipt retained; fresh PS causal run remains required")
    def test_actual_original_powershell_statement_red_and_current_validator_green(self):
        # Only the exact authentic failing if-statement is executed, with the
        # original exported XML. No task/source/install part of its launcher runs.
        with tempfile.TemporaryDirectory(prefix="ordinary-policy-") as directory:
            results = {}
            for mode in ("before", "after"):
                path = Path(directory) / (mode + ".ps1")
                path.write_text(task.policy_regression_program(self.before, self.xml, self.native, mode),
                                encoding="utf-8-sig")
                results[mode] = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(path)],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            self.assertNotEqual(0, results["before"].returncode)
            self.assertIn(b"TOKEN_TASK_XML", results["before"].stderr)
            self.assertNotIn(b"UNEXPECTED_OLD_ACCEPTANCE", results["before"].stderr)
            self.assertEqual(0, results["after"].returncode, results["after"].stderr)
            self.assertEqual(b"", results["after"].stderr)
            body = json.loads(results["after"].stdout)
            self.assertEqual(14, len(body["controls"]))
            self.assertEqual("GREEN", body["fixedValidator"])


class PlannerTests(unittest.TestCase):
    def test_unknown_top_level_and_pin_shapes_refuse(self):
        common, _, _ = synthetic_request()
        for change in (lambda value: value.update(typo="ignored"),
                       lambda value: value.update(schemaVersion=True),
                       lambda value: value.update(filePins="not-a-list"),
                       lambda value: value["treePins"][0].update(role="unbound")):
            bad = copy.deepcopy(common)
            change(bad)
            with self.assertRaises(ValueError):
                task.validate_closure(bad)

    def test_current_exact_canonical_owners_are_consumed(self):
        common, source_pin, _ = synthetic_request()
        request = task.bootstrap_request(common, "qualification",
            qualificationSourcePath=next(item["path"] for item in common["filePins"]
                                         if item["path"].endswith("qualification space 東京.ps1")),
            qualificationArguments=['space "quote" Ж trailing\\', "", "東京"])
        raw = task.data(request)
        request_pin = pin(PureWindowsPath(request["operationRoot"]) / "request.json",
                          size=len(raw), digest=hashlib.sha256(raw).hexdigest())
        plan = task.render_task(request, source_pin, request_pin)
        self.assertFalse(plan["nativeActionAllowed"])
        self.assertLessEqual(plan["commandUtf16Units"], 32767)
        self.assertLessEqual(plan["commandJsonBytes"], 60000)
        self.assertIn("<RunLevel>LeastPrivilege</RunLevel>", plan["xmlUtf8"])
        self.assertIn("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>", plan["xmlUtf8"])
        self.assertEqual(task.source_inventory(), plan["canonicalSourceFiles"])
        self.assertIn("Assert-OrdinaryTaskPolicy", plan["policyValidatorPowerShell"])
        task.validate_task_policy(plan["xmlUtf8"], original_inputs()[2], plan["policyExpected"])

    def test_altered_or_private_duplicate_ps_source_cannot_be_consumed(self):
        common, source_pin, _ = synthetic_request()
        request = task.bootstrap_request(common, "qualification",
            qualificationSourcePath=next(item["path"] for item in common["filePins"]
                                         if item["path"].endswith("qualification space 東京.ps1")),
            qualificationArguments=[])
        raw = task.data(request)
        request_pin = pin(PureWindowsPath(request["operationRoot"]) / "request.json",
                          size=len(raw), digest=hashlib.sha256(raw).hexdigest())
        bad = copy.deepcopy(source_pin)
        bad["sha256"] = "1" * 64
        request["filePins"][request["filePins"].index(source_pin)] = bad
        raw = task.data(request)
        request_pin.update(sha256=hashlib.sha256(raw).hexdigest())
        request_pin["nativeIdentity"]["sizeBytes"] = len(raw)
        with self.assertRaisesRegex(ValueError, "canonical-original-powershell"):
            task.render_task(request, bad, request_pin)

    def test_complete_runtime_role_is_required(self):
        common, _, _ = synthetic_request()
        task.validate_python_runtime(common)
        for change in (lambda value: value.pop("pythonRuntime"),
                       lambda value: value["treePins"].clear(),
                       lambda value: value["treePins"][0]["files"].remove("DLLs/_ctypes.pyd"),
                       lambda value: value["pythonRuntime"].update(interpreterPath=r"C:\other\python.exe")):
            bad = copy.deepcopy(common)
            change(bad)
            with self.assertRaises(ValueError):
                task.validate_python_runtime(bad)

    def test_filetimes_are_exact_decimal_strings(self):
        common, source_pin, _ = synthetic_request()
        self.assertEqual("134368653065000000", common["context"]["bootFileTimeUtc"])
        for value in (134368653065000000, 134368653065000000.0, True, "1.34368653065e17"):
            bad = copy.deepcopy(common["context"])
            bad["bootFileTimeUtc"] = value
            with self.assertRaises(ValueError):
                task.validate_context(bad)
        bad = copy.deepcopy(source_pin)
        bad["nativeIdentity"]["creationFileTime"] = 134368653065000000
        with self.assertRaises(ValueError):
            task.validate_pin(bad)

    def test_paths_and_missing_ancestor_fail_before_planning(self):
        for value in (r"C:relative", r"\\host\share\file", r"C:\a\..\b", r"C:\a\NUL.txt",
                      'C:\\a\\bad".txt', "C:\\a\\trailing."):
            with self.subTest(path=value), self.assertRaises(ValueError):
                task.path(value)
        common, _, _ = synthetic_request()
        common["directoryPins"] = [item for item in common["directoryPins"] if item["path"] != "C:\\"]
        with self.assertRaisesRegex(ValueError, "ancestor"):
            task.validate_closure(common)

    def test_msiexec_and_exact_installer_flags_are_data_only(self):
        common, _, _ = synthetic_request()
        msi = next(item["path"] for item in common["filePins"] if item["path"].endswith("baseline.msi"))
        request = task.worker_request(common, "msi-install", msiPath=msi,
            installerLogPath=str(PureWindowsPath(common["operationRoot"]) / "msi.log"))
        self.assertEqual("msi-install", request["action"])
        flags = task.python_installer_arguments(str(PureWindowsPath(common["context"]["localAppData"]) / "Python3.13.15"),
            str(PureWindowsPath(common["operationRoot"]) / "python.log"),
            common["context"]["localAppData"], common["operationRoot"])
        self.assertEqual(list(task.PYTHON_FLAGS), flags[:6])
        self.assertEqual("/log", flags[6])
        self.assertTrue(flags[-1].startswith("TargetDir="))
        self.assertNotIn("InstallAllUsers=1", flags)


if __name__ == "__main__":
    unittest.main()
