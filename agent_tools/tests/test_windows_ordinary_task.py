from __future__ import annotations

import copy
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest import mock
import xml.etree.ElementTree as ET

from agent_tools import windows_ordinary_task as task
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools import windows_disconnected_cli_cases as disconnected_cases
from agent_tools import windows_document_cli_cases as document_cases
from agent_tools import windows_streaming_cli_cases as streaming_cases
from agent_tools import affected_agent_tests as selector


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
        if str(path) in {task.PS, r"C:\Windows\System32\msiexec.exe"}:
            trustee = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            result["security"] = {"ownerSid": trustee,
                "sddl": "O:" + trustee + "D:P(A;;FA;;;" + trustee + ")(A;;FRFX;;;BU)"}
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


def finite_cli_inputs():
    """Synthetic request data only; no ordinary/native capability is minted."""
    common, _, _ = synthetic_request()
    root = PureWindowsPath(common["operationRoot"])
    source = PureWindowsPath(next(item["path"] for item in common["filePins"]
        if item["path"].endswith("windows_ordinary_process_owner.py"))).parent
    cli = PureWindowsPath(common["context"]["localAppData"]) / "Programs/VpnControl/vpn-control-cli.exe"
    fields = dict(cliPath=str(cli), workspace=str(root / "東京 workspace"),
        productVersion="2.2.14", casesPath=str(source / "held-cases.py"),
        harnessPath=str(source / "test_packaged_cli.py"))
    common["filePins"].extend(pin(fields[name]) for name in ("cliPath", "casesPath", "harnessPath"))
    directories = {PureWindowsPath(item["path"]) for item in common["directoryPins"]}
    for item in common["filePins"]:
        directories.update(PureWindowsPath(item["path"]).parents)
    common["directoryPins"] = [pin(path, directory=True) for path in sorted(directories, key=str)]
    return common, fields


class FiniteActionTests(unittest.TestCase):
    def test_exact_finite_actions_and_baseline_exclusion(self):
        for action in ("disconnected-cli-config", "streaming-client-interrupt"):
            with self.subTest(action=action):
                common, fields = finite_cli_inputs()
                result = task.worker_request(common, action, **fields)
                self.assertEqual(action, result["action"])
                self.assertEqual(set(common) | set(fields) | {"action"}, set(result))
                fields["productVersion"] = "2.2.13"
                with self.assertRaisesRegex(ValueError, "expanded-cases-forbidden-on-baseline"):
                    task.worker_request(common, action, **fields)
                self.assertEqual("baseline-source-mode", task.worker_request(
                    common, "baseline-source-mode", **fields)["action"])

    def test_action_inputs_do_not_admit_commands_unpinned_sources_or_foreign_workspace(self):
        common, fields = finite_cli_inputs()
        with self.assertRaisesRegex(ValueError, "worker-action"):
            task.worker_request(common, "arbitrary-command", **fields)
        for changed in ({**fields, "command": ["unbound"]},
                        {**fields, "casesPath": r"C:\unadmitted.py"},
                        {**fields, "workspace": r"C:\Users\other\workspace"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                task.worker_request(common, "disconnected-cli-config", **changed)


def peer_response():
    return subprocess.CompletedProcess([], 0, json.dumps(dict(schemaVersion=1,
        controllerId="inert-owner", requestId="inert-request", operationId=None,
        configurationRevision=0, restartRequired=False, code="OK", ok=True,
        final=True, data=dict(runtimeRunning=False))), "")


class DispatchPeer:
    """Only records callbacks; never opens native handles or starts processes."""
    def __init__(self, root, action, fail=False):
        self.root, self.trace = Path(root), []
        self.serve_exit_code = 0
        self.request = dict(action=action, cliPath="held-cli.exe", casesPath="held-cases.py",
            harnessPath="held-harness.py", workspace=str(self.root / "workspace"),
            productVersion="2.2.14")
        cases = types.SimpleNamespace()
        def run(*args):
            self.trace.append(("finite-run", args))
            if fail:
                raise RuntimeError("inert-case-unknown")
        def baseline(*args):
            self.trace.append(("baseline",))
            return {"fixedBehaviorPassed": False}
        cases.run, cases.baseline_cases = run, baseline
        cases.fixed_full_cases = lambda *args: self.trace.append(("fixed-source",))
        cases.assert_fixed_behavior = lambda result: self.trace.append(("baseline-after-close",))
        harness = types.ModuleType("inert-held-harness")
        self.harness_dictionary = harness.__dict__
        self.module = lambda path, name: cases if path == "held-cases.py" else harness
        self.guard = lambda: self.trace.append(("source-guard",))
        peer = self
        class Child:
            # This is a declared response peer, not proof of a Windows actor/EOF.
            def __init__(self, label, argv):
                self.label, self.argv = label, argv
                self.code = None
                self.process = types.SimpleNamespace(poll=lambda: self.code)
            def completed(self):
                self.code = 0
                return subprocess.CompletedProcess(self.argv, 0,
                    "Usage:" if self.label == "help" else "2.2.14", "")
            def wait(self):
                peer.trace.append(("same-serve-wait", self))
                self.code = peer.serve_exit_code
                return {"exitCode": self.code}
        self.child = lambda label, argv: Child(label, argv)
    def event(self, kind, value):
        self.trace.append((kind, value))
    def invoke(self, workspace, *argv, **kwargs):
        self.trace.append(("invoke", str(workspace), argv))
        return peer_response()


class FiniteDispatchTests(unittest.TestCase):
    def test_known_nonzero_original_serve_terminal_is_not_reported_success(self):
        with tempfile.TemporaryDirectory() as root:
            owner = DispatchPeer(root, "fixed-source-mode")
            owner.serve_exit_code = 37
            with mock.patch.object(process_owner, "absolute", Path):
                with self.assertRaisesRegex(process_owner.Refused, "original-serve-exit-not-zero"):
                    process_owner.Owner.run(owner)
            self.assertEqual(1, sum(row[0] == "same-serve-wait" for row in owner.trace))
            self.assertEqual(1, sum(row[0] == "invoke" and "quit" in row[2] for row in owner.trace))

    def test_authentic_original_owner_fails_same_nonzero_terminal_oracle(self):
        path = FIXTURES / "serve-exit.before.source"
        raw = path.read_bytes()
        expected = "ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18"
        self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
        provenance = json.loads((FIXTURES / "serve-exit.provenance.json").read_bytes())
        self.assertEqual(expected, provenance["sha256"])
        self.assertEqual(len(raw), provenance["sizeBytes"])
        name = "_ordinary_original_serve_exit_owner"
        before = types.ModuleType(name)
        before.__file__, before.__package__ = str(path), ""
        sys.modules[name] = before
        self.addCleanup(sys.modules.pop, name, None)
        exec(compile(raw, str(path), "exec"), before.__dict__)
        method = "test_known_nonzero_original_serve_terminal_is_not_reported_success"
        red = unittest.TestResult()
        with mock.patch.dict(globals(), {"process_owner": before}):
            FiniteDispatchTests(method).run(red)
        self.assertEqual(1, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        self.assertIn("Refused not raised", red.failures[0][1])
        green = unittest.TestResult()
        FiniteDispatchTests(method).run(green)
        self.assertTrue(green.wasSuccessful(), green.failures + green.errors)

    def test_actual_dispatch_calls_held_cases_then_original_safe_finalizer(self):
        for action in ("disconnected-cli-config", "streaming-client-interrupt", "baseline-source-mode",
                       "fixed-source-mode"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as root:
                owner = DispatchPeer(root, action)
                # TempFS path peer only: Windows path/schema validation is tested above.
                with mock.patch.object(process_owner, "absolute", Path):
                    self.assertEqual(0, process_owner.Owner.run(owner))
                kinds = [row[0] for row in owner.trace]
                if action == "baseline-source-mode":
                    self.assertNotIn("finite-run", kinds)
                    self.assertLess(kinds.index("baseline"), kinds.index("same-serve-wait"))
                    self.assertLess(kinds.index("same-serve-wait"), kinds.index("baseline-after-close"))
                elif action == "fixed-source-mode":
                    self.assertNotIn("finite-run", kinds)
                    self.assertLess(kinds.index("fixed-source"), kinds.index("same-serve-wait"))
                else:
                    args = next(row[1] for row in owner.trace if row[0] == "finite-run")
                    self.assertIs(owner, args[0])
                    self.assertEqual(Path(owner.request["workspace"]), args[1])
                    self.assertEqual("inert-owner", args[2])
                    self.assertIs(owner.harness_dictionary, args[3])
                    self.assertLess(kinds.index("finite-run"), kinds.index("same-serve-wait"))
                commands = [row[2] for row in owner.trace if row[0] == "invoke"]
                self.assertEqual(("--json", "--controller-id", "inert-owner", "quit"), commands[-1])

    def test_case_unknown_never_replays_or_runs_finalizer(self):
        with tempfile.TemporaryDirectory() as root:
            owner = DispatchPeer(root, "disconnected-cli-config", fail=True)
            with mock.patch.object(process_owner, "absolute", Path):
                with self.assertRaisesRegex(RuntimeError, "inert-case-unknown"):
                    process_owner.Owner.run(owner)
            self.assertEqual(1, sum(row[0] == "finite-run" for row in owner.trace))
            self.assertFalse(any(row[0] == "same-serve-wait" for row in owner.trace))
            self.assertFalse(any(row[0] == "invoke" and "quit" in row[2] for row in owner.trace))

    def test_actual_invoke_binds_workspace_once_and_uses_same_retained_child(self):
        captured = []
        child = types.SimpleNamespace(completed=lambda: "same-inert-child-result")
        owner = types.SimpleNamespace(request={"cliPath": "held-cli.exe"},
            child=lambda label, argv: captured.append((label, argv)) or child)
        self.assertEqual("same-inert-child-result", process_owner.Owner.invoke(owner,
            Path("owned workspace"), "--json", "status", timeout=1))
        self.assertEqual([("public-cli", ["held-cli.exe", "--state-dir", "owned workspace",
                                          "--json", "status"])], captured)


class ConsoleConstructorTests(unittest.TestCase):
    """Actual Child/Owner.child with explicit Popen/thread/birth peers, no Win32."""
    def peers(self, *, fail_after_handle=False):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="ordinary-console-unit-")))
        owner = types.SimpleNamespace(root=root, children=[], environment={}, events=[], flags=[],
                                      by_path={"held.exe": object()}, birth_calls=[], parks=[])
        owner.guard = lambda: owner.events.append(("source-guard",))
        owner.event = lambda kind, value: owner.events.append((kind, value))
        owner.native = types.SimpleNamespace(birth=lambda handle:
            owner.birth_calls.append(handle) or "inert-birth")
        class Parked(RuntimeError):
            pass
        def park(reason, error):
            owner.parks.append((reason, error))
            raise Parked(reason)
        owner.park, owner.Parked = park, Parked
        primary = RuntimeError("inert-constructor-after-handle")
        class Popen:
            def __init__(self, argv, **kwargs):
                # Inert integers are never supplied to a Win32 API.
                self.pid, self._handle = 101, 707
                self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
                self_outer.assertIs(owner.children[-1].process, self)
                self_outer.assertEqual("child-intent", owner.events[-1][0])
                owner.flags.append(kwargs["creationflags"])
                self_outer.assertIs(kwargs["stdin"], subprocess.DEVNULL)
                if fail_after_handle:
                    raise primary
            def poll(self):
                return None
        class Thread:
            def __init__(self, **kwargs):
                pass
            def start(self):
                pass  # No pump/EOF is fabricated or qualified by these peers.
            def join(self):
                pass
        self_outer = self
        self.enterContext(mock.patch.object(process_owner.subprocess, "Popen", Popen))
        self.enterContext(mock.patch.object(process_owner.subprocess, "CREATE_NEW_CONSOLE", 0x10, create=True))
        self.enterContext(mock.patch.object(process_owner.subprocess, "CREATE_NO_WINDOW", 0x8000000, create=True))
        self.enterContext(mock.patch.object(process_owner.threading, "Thread", Thread))
        def close_inert_objects():
            for child in owner.children:
                for stream in child.streams.values():
                    stream.close()
                if child.process is not None:
                    child.process.stdout.close()
                    child.process.stderr.close()
        self.addCleanup(close_inert_objects)
        return owner, primary

    def test_actual_default_and_opt_in_flags_keep_original_constructor_custody(self):
        owner, _ = self.peers()
        default = process_owner.Child(owner, "inert-default", ["held.exe"])
        with mock.patch.object(process_owner, "absolute", Path):
            console = process_owner.Owner.child(owner, "inert-console", ["held.exe"], new_console=True)
        self.assertEqual([0x8000000, 0x10], owner.flags)
        self.assertFalse(default.new_console)
        self.assertTrue(console.new_console)
        self.assertEqual([707, 707], owner.birth_calls)
        self.assertIs(owner.children[0], default)
        self.assertIs(owner.children[1], console)
        for child in (default, console):
            self.assertEqual({"stdout": False, "stderr": False}, child.eof)
            self.assertIsNone(child.terminal)
        modes = [row[1]["consoleCreation"] for row in owner.events if row[0] == "child-started"]
        self.assertEqual(["none", "new"], modes)

    def test_non_boolean_console_mode_refuses_before_intent_or_popen(self):
        owner, _ = self.peers()
        for mode in (None, 0, 1, "true"):
            with self.subTest(mode=mode), self.assertRaisesRegex(process_owner.Refused,
                                                               "explicit-child-console-mode"):
                process_owner.Child(owner, "invalid", ["held.exe"], new_console=mode)
        self.assertEqual([], owner.children)
        self.assertEqual([], owner.events)
        self.assertEqual([], owner.flags)

    def test_constructor_exception_keeps_same_inert_handle_and_primary_error(self):
        owner, primary = self.peers(fail_after_handle=True)
        with self.assertRaisesRegex(owner.Parked, "post-start-admission-unknown"):
            process_owner.Child(owner, "inert-after-handle", ["held.exe"], new_console=True)
        self.assertEqual(1, len(owner.children))
        child = owner.children[0]
        self.assertEqual(707, child.process._handle)
        self.assertEqual([("post-start-admission-unknown", primary)], owner.parks)
        self.assertFalse(any(row[0] == "child-no-process" for row in owner.events))
        self.assertTrue(all(not stream.closed for stream in child.streams.values()))
        self.assertEqual({"stdout": False, "stderr": False}, child.eof)
        self.assertEqual([], owner.birth_calls)


class BoundedCaseFileTests(unittest.TestCase):
    BEFORE_SHA256 = "d00ab003ea79b961efa25ff22a69cdea981203b259cb13ba4dbd1b8e87bbb6ef"
    def reader(self, module, root):
        owner = types.SimpleNamespace(event=lambda kind, value: None)
        return module.Cases(owner, Path(root) / "workspace", "inert-owner", {}, root)

    def sparse_oracle(self, module):
        with tempfile.TemporaryDirectory(prefix="ordinary-read-bound-") as root:
            path = Path(root) / "oversized.json"
            with path.open("xb") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)
            with mock.patch.object(Path, "open", side_effect=AssertionError("must-not-open")):
                with self.assertRaisesRegex(AssertionError, "output-file-read-bound"):
                    self.reader(module, root).output(path)

    def test_output_refuses_oversized_real_file_before_open(self):
        self.sparse_oracle(disconnected_cases)

    def finite_read_oracle(self, module):
        with tempfile.TemporaryDirectory(prefix="ordinary-finite-read-") as root:
            path = Path(root) / "small.json"
            content = b'{"exact":"UTF-8 file"}\n'
            path.write_bytes(content)
            original_open = Path.open
            requested = []
            class Reader:
                def __init__(self, stream):
                    self.stream = stream
                def __enter__(self):
                    self.stream.__enter__()
                    return self
                def __exit__(self, *args):
                    return self.stream.__exit__(*args)
                def fileno(self):
                    return self.stream.fileno()
                def read(self, bound=-1):
                    requested.append(bound)
                    return self.stream.read(bound)
            def open_peer(item, *args, **kwargs):
                return Reader(original_open(item, *args, **kwargs))
            with mock.patch.object(Path, "open", open_peer):
                result = self.reader(module, root).output(path)
            self.assertEqual(content, result["content"])
            self.assertEqual(hashlib.sha256(content).hexdigest(), result["sha256"])
            self.assertEqual(1, len(requested))
            self.assertGreater(requested[0], 0, "read must have a positive finite bound")
            self.assertLessEqual(requested[0], 64 * 1024 * 1024 + 1)

    def test_small_real_file_is_read_with_finite_bound_and_exact_digest(self):
        self.finite_read_oracle(disconnected_cases)

    def test_whole_authentic_unbounded_reader_fails_both_current_positive_oracles(self):
        path = FIXTURES / "disconnected-file-read.before.source"
        raw = path.read_bytes()
        self.assertEqual(self.BEFORE_SHA256, hashlib.sha256(raw).hexdigest())
        provenance = json.loads((FIXTURES / "disconnected-file-read.provenance.json").read_bytes())
        self.assertEqual(self.BEFORE_SHA256, provenance["sha256"])
        self.assertEqual(len(raw), provenance["sizeBytes"])
        name = "_ordinary_authentic_unbounded_cases"
        before = types.ModuleType(name)
        before.__file__ = str(path)
        sys.modules[name] = before
        self.addCleanup(sys.modules.pop, name, None)
        exec(compile(raw, str(path), "exec"), before.__dict__)
        red = unittest.TestResult()
        for oracle in (self.sparse_oracle, self.finite_read_oracle):
            unittest.FunctionTestCase(lambda oracle=oracle: oracle(before)).run(red)
        self.assertEqual(2, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        self.assertIn("must-not-open", red.failures[0][1])
        self.assertIn("read must have a positive finite bound", red.failures[1][1])
        green = unittest.TestResult()
        for oracle in (self.sparse_oracle, self.finite_read_oracle):
            unittest.FunctionTestCase(lambda oracle=oracle: oracle(disconnected_cases)).run(green)
        self.assertTrue(green.wasSuccessful(), green.failures + green.errors)


class FiniteEnrollmentTests(unittest.TestCase):
    def test_reviewed_test_source_has_only_finite_resources_and_changed_source_refuses(self):
        source_path = "agent_tools/tests/test_windows_ordinary_task.py"
        source = Path(__file__).read_text(encoding="utf-8")
        record = selector.REVIEWED_DYNAMIC_DEPENDENCIES[source_path]
        # A literal repository canary in this self-analyzed source would itself
        # be a dependency. This generated inventory label is inert test data.
        unrelated = task.__package__ + "/" + hashlib.sha256(b"unused dependency canary").hexdigest() + ".py"
        inventory = set(record["scopes"]) | {source_path, unrelated}
        edges = selector.dependencies(source_path, source, inventory)
        required = {"agent_tools/windows_disconnected_cli_cases.py",
            "agent_tools/windows_ordinary_process_owner.py",
            "agent_tools/tests/fixtures/windows_ordinary_task/disconnected-file-read.before.source",
            "agent_tools/tests/fixtures/windows_ordinary_task/disconnected-file-read.provenance.json"}
        self.assertLessEqual(required, edges)
        self.assertNotIn(unrelated, edges)
        with self.assertRaises(selector.SelectionError):
            selector.dependencies(source_path, source + "\n# unreviewed loader change\n", inventory)

    def test_new_resource_changes_select_this_existing_routine_suite(self):
        source_path = "agent_tools/tests/test_windows_ordinary_task.py"
        record = selector.REVIEWED_DYNAMIC_DEPENDENCIES[source_path]
        sources = dict.fromkeys(record["scopes"])
        sources[source_path] = Path(__file__).read_text(encoding="utf-8")
        for changed in ("agent_tools/windows_disconnected_cli_cases.py",
                "agent_tools/tests/fixtures/windows_ordinary_task/disconnected-file-read.before.source",
                "agent_tools/tests/fixtures/windows_ordinary_task/disconnected-file-read.provenance.json"):
            with self.subTest(changed=changed):
                selected = selector.select_from_sources(sources, {changed})
                self.assertEqual(("agent_tools.tests.test_windows_ordinary_task",), selected.modules)


def document_cli_inputs():
    common, fields = finite_cli_inputs()
    root = PureWindowsPath(common["operationRoot"])
    source = PureWindowsPath(fields["casesPath"]).parent
    document = dict(schemaVersion=1, clientPath=str(source / "windows_document_client.py"),
        windowsPath=str(source / "windows_document_native.py"),
        racePath=str(source / "windows_document_export_race.py"),
        largeRoutingInputPath=str(source / "large-document.json"),
        spoolTempParent=str(root / "dedicated-temp"),
        contexts=[str(uuid.UUID(int=value + 1)) for value in range(52)],
        endpointPinBeforeObservation=None)
    for key in ("clientPath", "windowsPath", "racePath", "largeRoutingInputPath"):
        size = 11 * 1024 * 1024 if key == "largeRoutingInputPath" else 1
        common["filePins"].append(pin(document[key], size=size))
    directories = {PureWindowsPath(item["path"]) for item in common["directoryPins"]}
    directories.add(PureWindowsPath(document["spoolTempParent"]))
    for item in common["filePins"]:
        directories.update(PureWindowsPath(item["path"]).parents)
    common["directoryPins"] = [pin(path, directory=True) for path in sorted(directories, key=str)]
    fields["documentAcceptance"] = document
    return common, fields


class DocumentActionTests(unittest.TestCase):
    def test_document_helper_sources_have_exact_hash_bound_dependency_scope(self):
        path = "agent_tools/windows_document_cli_cases.py"
        source = Path(document_cases.__file__).read_text(encoding="utf-8")
        record = selector.REVIEWED_DYNAMIC_DEPENDENCIES[path]
        inventory = set(record["scopes"]) | {path}
        self.assertEqual(set(record["scopes"]), selector.dependencies(path, source, inventory))
        self.assertEqual({"agent_tools/windows_document_client.py",
                          "agent_tools/windows_document_native.py",
                          "agent_tools/windows_document_export_race.py"}, set(record["scopes"]))
        with self.assertRaises(selector.SelectionError):
            selector.dependencies(path, source + "\n# unreviewed helper loader change\n", inventory)

    def test_closed_document_action_inputs_are_pinned_and_baseline_excluded(self):
        common, fields = document_cli_inputs()
        request = task.worker_request(common, "document-acceptance", **fields)
        self.assertIs(fields["documentAcceptance"], request["documentAcceptance"])
        self.assertIsNone(request["documentAcceptance"]["endpointPinBeforeObservation"])
        self.assertEqual(52, len(request["documentAcceptance"]["contexts"]))
        task.validate_closure(request)
        for action in ("disconnected-cli-config", "streaming-client-interrupt"):
            with self.assertRaisesRegex(ValueError, "cli-worker-input-schema"):
                task.worker_request(common, action, **fields)
        fields["productVersion"] = "2.2.13"
        with self.assertRaisesRegex(ValueError, "expanded-cases-forbidden-on-baseline"):
            task.worker_request(common, "document-acceptance", **fields)

    def test_document_booleans_context_aliases_missing_pins_and_temp_scope_refuse(self):
        changes = ({"schemaVersion": True}, {"success": True},
            {"endpointPinBeforeObservation": {"observed": True}},
            {"clientPath": r"C:\unadmitted.py"},
            {"largeRoutingInputPath": r"C:\unadmitted.json"},
            {"spoolTempParent": r"C:\unadmitted-temp"},
            {"contexts": ["not-a-uuid"] * 52}, {"contexts": [None] * 52},
            {"contexts": [str(uuid.UUID(int=1))] * 52})
        for change in changes:
            with self.subTest(change=change):
                common, fields = document_cli_inputs()
                fields["documentAcceptance"].update(change)
                with self.assertRaises(ValueError):
                    task.worker_request(common, "document-acceptance", **fields)
        for kind in ("aliased-module", "workspace-as-temp", "small-input", "oversized-input"):
            common, fields = document_cli_inputs()
            document = fields["documentAcceptance"]
            if kind == "aliased-module": document["windowsPath"] = document["clientPath"]
            elif kind == "workspace-as-temp": document["spoolTempParent"] = fields["workspace"]
            else:
                item = next(item for item in common["filePins"]
                            if item["path"] == document["largeRoutingInputPath"])
                item["nativeIdentity"]["sizeBytes"] = 10 if kind == "small-input" else 64 * 1024 * 1024 + 1
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                task.worker_request(common, "document-acceptance", **fields)


class DocumentLaunchTests(unittest.TestCase):
    def peer(self, root, *, bad_pin=False, run_unknown=False):
        owner = DispatchPeer(root, "document-acceptance")
        workspace = Path(owner.request["workspace"])
        temp = Path(root) / "dedicated-temp"
        temp.mkdir()
        owner.request["documentAcceptance"] = dict(schemaVersion=1, clientPath="held-client.py",
            windowsPath="held-native.py", racePath="held-race.py", largeRoutingInputPath="held-large.json",
            spoolTempParent=str(temp), contexts=[str(uuid.UUID(int=value + 1)) for value in range(52)],
            endpointPinBeforeObservation=None)
        native_pin = types.SimpleNamespace(directory=True, path=temp,
            current=lambda: owner.trace.append(("temp-pin-current",)),
            record={"nativeIdentity": {"unitPeer": True}})
        owner.pins = [] if bad_pin else [native_pin]
        owner.children, owner.environment = [], {"UNCHANGED_UNIT_VALUE": "kept"}
        harness = types.ModuleType("inert-document-harness")
        owner.harness_dictionary = harness.__dict__
        cases = types.ModuleType("held-document-cases-peer")
        cases.configure_launch = document_cases.configure_launch
        def run(*args):
            owner.trace.append(("document-run", args))
            self.assertIs(owner.document_temp_pin, native_pin)
            self.assertEqual(owner.children[-1].ordinal, owner.document_launch_marker["expectedServeOrdinal"])
            if run_unknown:
                raise RuntimeError("document-run-unknown")
        cases.run = run
        def module(path, name):
            owner.trace.append(("module-load", path, name))
            return cases if path == "held-cases.py" else harness
        owner.module = module
        original_child = owner.child
        def child(label, argv):
            owner.trace.append(("child-submission-peer", label))
            value = original_child(label, argv)
            value.ordinal = len(owner.children)
            value.argv = tuple(argv)
            owner.children.append(value)
            if label == "serve":
                self.assertEqual(owner.environment["TEMP"], str(temp))
                self.assertEqual(owner.environment["TMP"], str(temp))
                self.assertFalse(workspace.exists())
                workspace.mkdir()  # Explicit unit workspace peer, never a native JVM.
            return value
        owner.child = child
        return owner, cases

    def test_same_held_module_configures_actual_temp_before_exact_original_serve(self):
        with tempfile.TemporaryDirectory() as root:
            owner, cases = self.peer(root)
            with mock.patch.object(process_owner, "absolute", Path):
                self.assertEqual(0, process_owner.Owner.run(owner))
            loads = [row for row in owner.trace if row[0] == "module-load" and row[1] == "held-cases.py"]
            self.assertEqual(1, len(loads))
            kinds = [row[0] for row in owner.trace]
            self.assertLess(kinds.index("module-load"), kinds.index("child-submission-peer"))
            configured = kinds.index("document-temp-configured-before-serve")
            self.assertEqual(("child-submission-peer", "serve"), owner.trace[configured + 1])
            self.assertEqual(["help", "version", "serve"],
                             [row[1] for row in owner.trace if row[0] == "child-submission-peer"])
            args = next(row[1] for row in owner.trace if row[0] == "document-run")
            self.assertIs(owner, args[0])
            self.assertEqual(Path(owner.request["workspace"]), args[1])
            self.assertEqual("inert-owner", args[2])
            self.assertIs(owner.harness_dictionary, args[3])
            self.assertEqual("kept", owner.environment["UNCHANGED_UNIT_VALUE"])
            self.assertIn("same-serve-wait", kinds)

    def test_missing_original_temp_pin_refuses_before_serve_or_owner_request(self):
        with tempfile.TemporaryDirectory() as root:
            owner, _ = self.peer(root, bad_pin=True)
            with mock.patch.object(process_owner, "absolute", Path):
                with self.assertRaisesRegex(RuntimeError, "prelaunch-temp-directory-pin"):
                    process_owner.Owner.run(owner)
            self.assertEqual(["help", "version"],
                             [row[1] for row in owner.trace if row[0] == "child-submission-peer"])
            self.assertFalse(any(row[0] in ("invoke", "same-serve-wait", "document-run") for row in owner.trace))
            self.assertNotIn("TEMP", owner.environment)

    def test_document_run_unknown_retains_same_serve_without_finalizer_or_replay(self):
        with tempfile.TemporaryDirectory() as root:
            owner, _ = self.peer(root, run_unknown=True)
            with mock.patch.object(process_owner, "absolute", Path):
                with self.assertRaisesRegex(RuntimeError, "document-run-unknown"):
                    process_owner.Owner.run(owner)
            self.assertEqual(1, sum(row[0] == "document-run" for row in owner.trace))
            self.assertEqual(1, sum(row[0] == "module-load" and row[1] == "held-cases.py" for row in owner.trace))
            self.assertFalse(any(row[0] == "same-serve-wait" for row in owner.trace))
            self.assertFalse(any(row[0] == "invoke" and "quit" in row[2] for row in owner.trace))


class StreamingConsoleHelperTests(unittest.TestCase):
    """Explicit logical kernel peers only; no Windows ABI/console qualification."""
    def kernel_peer(self, *, birth=123, session=7, live=True, extra=False,
                    closing_change=False, submit=True):
        state = dict(signals=0, closes=0, members=0)
        class Call:
            def __init__(self, function): self.function = function
            def __call__(self, *args): return self.function(*args)
        kernel = types.SimpleNamespace()
        def opened(access, inherit, pid):
            self.assertEqual((0x101000, False, 101), (access, inherit, pid))
            return 707  # Inert integer: never passed to a real Win32 function.
        def closed(handle):
            self.assertEqual(707, handle)
            state["closes"] += 1
            return 1
        def times(handle, creation, *_):
            self.assertEqual(707, handle)
            creation._obj.dwLowDateTime, creation._obj.dwHighDateTime = birth, 0
            return 1
        def session_id(pid, result):
            self.assertIn(pid, (101, 505, 303, 404))
            result._obj.value = session
            return 1
        def members(values, bound):
            state["members"] += 1
            result = [101, 505]
            if extra or closing_change and state["members"] == 2: result.append(909)
            for index, value in enumerate(result): values[index] = value
            return len(result)
        def signal(event, group):
            self.assertEqual((0, 0), (event, group))
            state["signals"] += 1
            return int(submit)
        methods = dict(OpenProcess=opened, CloseHandle=closed, GetProcessTimes=times,
            WaitForSingleObject=lambda *_: 0x102 if live else 0,
            ProcessIdToSessionId=session_id, FreeConsole=lambda: 1,
            AttachConsole=lambda pid: int(pid == 101), GetConsoleProcessList=members,
            SetConsoleCtrlHandler=lambda *args: int(args == (None, True)),
            GenerateConsoleCtrlEvent=signal)
        for name, method in methods.items(): setattr(kernel, name, Call(method))
        return kernel, state

    def helper(self, kernel, root):
        with mock.patch.object(streaming_cases.ctypes, "WinDLL", return_value=kernel, create=True), \
             mock.patch.object(streaming_cases, "os", types.SimpleNamespace(
                 name="nt", getpid=lambda: 505, fsync=os.fsync)), \
             mock.patch.object(streaming_cases.time, "sleep", return_value=None), \
             mock.patch.object(Path, "cwd", return_value=root):
            return streaming_cases.interrupt_owned_console(101, "123", 7, 303, 404,
                root / "child-0001.ctrl-c.intent.json")

    def test_exact_birth_session_live_and_two_member_console_required_before_signal(self):
        controls = (("positive", {}), ("birth", {"birth": 124}),
            ("session", {"session": 8}), ("terminal", {"live": False}),
            ("foreign-member", {"extra": True}), ("closing-change", {"closing_change": True}))
        for label, options in controls:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kernel, state = self.kernel_peer(**options)
                if label == "positive":
                    receipt = self.helper(kernel, root)
                    self.assertEqual("signal-submitted", receipt["state"])
                    self.assertEqual([101, 505], receipt["consolePids"])
                    self.assertEqual(1, receipt["signalAttempts"])
                else:
                    with self.assertRaises(AssertionError): self.helper(kernel, root)
                self.assertEqual(1 if label == "positive" else 0, state["signals"])
                self.assertEqual(1, state["closes"])

    def test_uncertain_signal_keeps_create_only_intent_and_blocks_second_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kernel, state = self.kernel_peer(submit=False)
            with self.assertRaisesRegex(AssertionError, "owned-console-ctrl-c-submit"):
                self.helper(kernel, root)
            intent = root / "child-0001.ctrl-c.intent.json"
            original = intent.read_bytes()
            self.assertEqual(1, json.loads(original)["signalAttempts"])
            with self.assertRaises(FileExistsError): self.helper(kernel, root)
            self.assertEqual(original, intent.read_bytes())
            self.assertEqual(1, state["signals"])
            self.assertEqual(2, state["closes"])


# Insert before the existing unittest.main() block in the ordinary routine suite.
# These are local error/lifetime controls, not native acceptance or admission.
import base64 as _document_base64
import io as _document_io
import struct as _document_struct
from unittest import mock as _document_mock

from agent_tools import windows_document_client as document_client
from agent_tools import windows_document_native as document_native


class _DocumentControlStream:
    """Explicit in-memory peer; no socket or native API is used."""
    def __init__(self, data, error=None):
        self.source = _document_io.BytesIO(data)
        self.error = error
        self.sent = []

    def recv(self, count):
        data = self.source.read(count)
        if not data and self.error is not None:
            raise self.error
        return data

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, value):
        pass

    def close(self):
        pass


def _document_control_client(stream, guard=lambda: None, event=lambda *_: None):
    token = _document_base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
    descriptor = {"port": 47891, "controllerId": "bca8cef3-3c17-49a6-95ce-86e6d42e19a8",
                  "token": token, "documentTransfers": True}
    return document_client.Client(descriptor, guard, event, connector=lambda _: stream)


class DocumentRetentionControls(unittest.TestCase):
    def test_document_negative_requires_known_close_and_successful_closing_observers(self):
        for failure in ("guard", "event", "close"):
            with self.subTest(failure=failure):
                stream = _DocumentControlStream(document_client.wire("AUTHENTICATED"))
                calls = []

                def guard():
                    calls.append(1)
                    if failure == "guard" and len(calls) == 2:
                        raise RuntimeError("secondary-guard")

                def event(*_):
                    if failure == "event":
                        raise RuntimeError("secondary-event")

                if failure == "close":
                    def close():
                        raise RuntimeError("secondary-close")
                    stream.close = close
                owned = _document_control_client(stream, guard, event)
                observed = None
                try:
                    owned.negative("invalid")
                except BaseException as error:
                    observed = error
                self.assertIsInstance(observed, document_client.ClosedFrame)
                self.assertTrue(getattr(observed, "document_secondary_errors", []))
                self.assertEqual(len(owned.original_sockets), 1 if failure == "close" else 0)

    def test_document_authentication_eof_cannot_count_protocol_refusal(self):
        with self.assertRaises(document_client.Refused):
            _document_control_client(_DocumentControlStream(b"")).negative("invalid")

    def test_document_announced_payload_eof_is_partial_not_clean_negative(self):
        stream = _DocumentControlStream(document_client.wire("AUTHENTICATED")
                                        + _document_struct.pack(">I", 12))
        with self.assertRaises(document_client.Refused):
            _document_control_client(stream).negative("invalid")

    def test_document_timeout_retains_header_and_available_payload(self):
        fragment = _document_struct.pack(">I", 12) + b'"ab'
        primary = TimeoutError("owned-local-timeout")
        journal = []
        with self.assertRaises(TimeoutError) as caught:
            document_client.receive(_DocumentControlStream(fragment, primary), journal)
        self.assertIs(caught.exception, primary)
        self.assertEqual(getattr(caught.exception, "document_frame_fragment", None), fragment)
        self.assertEqual(journal[-1]["partialBytes"], len(fragment))

    def test_document_closing_guard_cannot_replace_primary_receive_timeout(self):
        count = []

        def guard():
            count.append(1)
            if len(count) == 2:
                raise RuntimeError("secondary-closing-guard")

        primary = TimeoutError("owned-local-timeout")
        stream = _DocumentControlStream(document_client.wire("AUTHENTICATED"), primary)
        observed = None
        try:
            _document_control_client(stream, guard).exchange("invalid")
        except BaseException as error:
            observed = error
        self.assertIs(observed, primary)
        secondary = getattr(observed, "document_secondary_errors", [])
        self.assertTrue(secondary, "Primary timeout must retain secondary guard error")
        self.assertEqual(type(secondary[0]), RuntimeError)

    def test_document_closing_event_cannot_replace_primary_receive_timeout(self):
        def event(*_):
            raise RuntimeError("secondary-event")

        primary = TimeoutError("owned-local-timeout")
        stream = _DocumentControlStream(document_client.wire("AUTHENTICATED"), primary)
        observed = None
        try:
            _document_control_client(stream, event=event).exchange("invalid")
        except BaseException as error:
            observed = error
        self.assertIs(observed, primary)
        secondary = getattr(observed, "document_secondary_errors", [])
        self.assertTrue(secondary, "Primary timeout must retain secondary event error")
        self.assertEqual(type(secondary[0]), RuntimeError)

    def test_document_native_open_error_is_captured_before_any_inspection(self):
        calls = []

        def inspect(*_):
            raise AssertionError("No inspection before immediate error capture")

        native = types.SimpleNamespace(
            k=types.SimpleNamespace(CreateFileW=lambda *_: calls.append("open")
                                    or document_native.ctypes.c_void_p(-1).value),
            identity=inspect, security=inspect)
        with _document_mock.patch.object(document_native, "lexical", Path), \
                _document_mock.patch.object(document_native.ctypes, "get_last_error",
                    lambda: calls.append("last-error") or 32, create=True):
            with self.assertRaises(document_native.NativeOpenError) as caught:
                document_native.Held(native, "/inert-local", write=True, share=7)
        self.assertEqual(caught.exception.winerror, 32)
        self.assertEqual(calls, ["open", "last-error"])
        self.assertEqual(len(native.document_retained_handles), 1)
        self.assertEqual(native.document_retained_handles[0].open_error, 32)

    def test_document_exact_constructor_object_retained_before_inspection_failure(self):
        primary = RuntimeError("local-inspection-fault")

        def inspect(*_):
            raise primary

        native = types.SimpleNamespace(k=types.SimpleNamespace(CreateFileW=lambda *_: 917),
                                       identity=inspect)
        with _document_mock.patch.object(document_native, "lexical", Path):
            with self.assertRaisesRegex(RuntimeError, "local-inspection-fault") as caught:
                document_native.Held(native, "/local-inert-fixture")
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(native.document_retained_handles), 1)
        original = native.document_retained_handles[0]
        self.assertEqual(original.handle, 917)
        self.assertIsNone(original.initial)
        self.assertFalse(original.closed)


class DocumentCausalRetentionTests(unittest.TestCase):
    """Actual private draft omissions; never product/native failure claims."""
    def before(self, filename, expected):
        path = FIXTURES / filename
        raw = path.read_bytes()
        self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
        provenance = json.loads((FIXTURES / "document-client-retention.provenance.json").read_bytes())
        record = next(item for item in provenance["sources"] if item["fixture"] == filename)
        self.assertEqual(expected, record["sha256"])
        self.assertEqual(len(raw), record["sizeBytes"])
        name = "_ordinary_document_before_" + expected[:12]
        module = types.ModuleType(name)
        module.__file__, module.__package__ = str(path), ""
        sys.modules[name] = module
        self.addCleanup(sys.modules.pop, name, None)
        exec(compile(raw, str(path), "exec"), module.__dict__)
        return module

    def run_controls(self, module, names):
        result = unittest.TestResult()
        with mock.patch.dict(globals(), {"document_client": module}):
            unittest.TestSuite(DocumentRetentionControls(name) for name in names).run(result)
        return result

    def test_authentic_v1_fails_five_current_frame_and_primary_error_controls(self):
        before = self.before("document-client-v1.before.source",
            "3b34a9402881175fd1466519922be02e69d680141dd95c8fd134a61225d9537c")
        names = ("test_document_authentication_eof_cannot_count_protocol_refusal",
            "test_document_announced_payload_eof_is_partial_not_clean_negative",
            "test_document_timeout_retains_header_and_available_payload",
            "test_document_closing_guard_cannot_replace_primary_receive_timeout",
            "test_document_closing_event_cannot_replace_primary_receive_timeout")
        red = self.run_controls(before, names)
        self.assertEqual(5, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        green = self.run_controls(document_client, names)
        self.assertTrue(green.wasSuccessful(), green.failures + green.errors)

    def test_authentic_v2_fails_three_secondary_observer_subcases(self):
        before = self.before("document-client-v2.before.source",
            "9d3e56d15da321a7e20bcfc4d2aa3a863efb1244066f96d6676b83f834c3ff16")
        names = ("test_document_negative_requires_known_close_and_successful_closing_observers",)
        red = self.run_controls(before, names)
        self.assertEqual(3, len(red.failures), red.errors)
        self.assertEqual([], red.errors)
        self.assertTrue(all("ClosedFrame" in failure and "is not an instance" in failure
                            for _, failure in red.failures))
        green = self.run_controls(document_client, names)
        self.assertTrue(green.wasSuccessful(), green.failures + green.errors)



from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools.windows_system_collector import hold_protocol as dedicated_protocol


class DedicatedParked(BaseException):
    pass


class DedicatedPinPeer:
    def __init__(self, path, raw):
        self.path, self.raw, self.directory = PureWindowsPath(path), raw, False
        self.record = pin(path, size=len(raw), digest=hashlib.sha256(raw).hexdigest())

    def digest(self, return_bytes=False, maximum=8 * 1024 * 1024):
        if return_bytes:
            assert len(self.raw) <= maximum
            return self.raw
        return self.record["sha256"]


class DedicatedDispatchPeer:
    """Declared pure source/module/terminal peers; no native actor or socket."""
    SOURCE_ROOT = PureWindowsPath(r"C:\Reviewed\agent_tools")

    def __init__(self, root):
        self.root, self.operation = root, "2c731e91-c158-4e8a-b779-54076ce85229"
        self.calls, self.by_path, self.children = [], {}, []
        self.request = {"workspace": str(root / "workspace"), "productVersion": "2.2.14"}
        self.result, self.case_error, self.release_error = 0, None, None
        self.modules = {}
        self.inputs = None

    def source(self, name, canonical):
        path = str(self.SOURCE_ROOT / name)
        self.by_path[path.casefold()] = DedicatedPinPeer(path, (ROOT / canonical).read_bytes())
        return path

    def guard(self):
        self.calls.append("guard")

    def park(self, reason, error=None):
        self.parked = {"reason": reason, "error": error,
                       "originalHold": getattr(self, "caller_collection_hold", None)}
        raise DedicatedParked(reason)

    def event(self, kind, value):
        self.calls.append((kind, value))

    def module(self, path, name):
        self.calls.append(("module", name))
        if path == self.request.get("harnessPath"):
            result = types.ModuleType(name)
            exec(compile(self.by_path[path.casefold()].raw, path, "exec"), result.__dict__)
            return result
        if path.endswith("hold_protocol.py"):
            return dedicated_protocol
        if path.endswith("caller_hold.py"):
            outer = self
            class Hold:
                def __init__(self, owner, inputs):
                    outer.calls.append("arm")
                    self.state = "armed"
                    owner.caller_collection_hold = self
                def driver_completed(self, value):
                    outer.calls.append(("driver-completed", value))
                    if type(value) is not int or value != 0:
                        outer.park("peer-nonzero-driver")
                    self.state = "driver-terminal"
                def wait_for_release(self):
                    outer.calls.append("wait-release")
                    if outer.release_error is not None:
                        outer.park("peer-release-unknown", outer.release_error)
                    self.state = "released"
            return types.SimpleNamespace(CallerCollectionHold=Hold)
        return self.modules[path]

    def update(self, variant="success-off", hold=True):
        targets = {"receipts": "windows_public_updater/update_receipts.py", "server": "windows_public_updater/update_fixture_server.py",
            "lifecycle": "windows_lifecycle_cases.py", "collector": "windows_public_updater/native_collector.py"}
        production = {"fixture_environment": "scripts/fixture_environment.py",
            "macos_packaging_jdk_preflight": "scripts/macos_packaging_jdk_preflight.py",
            "prepare_desktop_update_fixture": "scripts/prepare_desktop_update_fixture.py",
            "broker_observer": "scripts/windows_broker_fixture_observer.py"}
        paths = {role: self.source(name, "agent_tools/" + name) for role, name in targets.items()}
        paths.update({role: self.source(Path(name).name, name) for role, name in production.items()})
        self.inputs = {"schemaVersion": 1, "variant": variant, "sourceSha": "a" * 40,
                       "installedRoot": r"C:\InstalledApp", "modules": paths}
        self.request["casesPath"] = self.source("windows_public_updater/update_cases.py", "agent_tools/windows_public_updater/update_cases.py")
        for name in ("caller_hold.py", "hold_protocol.py"):
            self.source("windows_system_collector/" + name, "agent_tools/windows_system_collector/" + name)
        hold_inputs = None if not hold else {"schemaVersion": 1,
            "collectorOperationId": "f2217b3c-82c1-4862-bab8-09b8498e7929",
            "collectorRoot": r"C:\ProgramData\VpnControlOrdinaryTask-2c731e91-c158-4e8a-b779-54076ce85229\system-collector-f2217b3c-82c1-4862-bab8-09b8498e7929",
            "scope": "update", "stage": "terminal-actors" if variant in dedicated_driver.FINAL_TERMINAL else "returned-cleanup",
            "sourceSha": self.inputs["sourceSha"], "systemContractSourceSha256": dedicated_driver.CONTRACT_SHA,
            "systemWorkerSourceSha256": dedicated_driver.SYSTEM_WORKER_SHA,
            "collectorSourceSha256": dedicated_driver.UPDATE_MODULES["collector"], "receiptsPath": paths["receipts"]}
        def validate(owner, inputs):
            self.calls.append("validate-update")
            if inputs["variant"] == "transport-loss":
                raise ValueError("outer-transport-loss-semantic-producer-not-yet-prepared")
        def run(owner, harness):
            self.calls.append("cases")
            if self.case_error is not None:
                raise self.case_error
            return self.result
        self.modules[self.request["casesPath"]] = types.SimpleNamespace(validate_inputs=validate, run_update=run)
        self.harness({"UPDATE_INPUTS": self.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": hold_inputs})
        return hold_inputs

    def harness(self, values):
        self.request["harnessPath"] = str(self.SOURCE_ROOT / "admitted-harness.py")
        raw = "\n".join(name + " = " + repr(value) for name, value in values.items()).encode()
        self.by_path[self.request["harnessPath"].casefold()] = DedicatedPinPeer(self.request["harnessPath"], raw)

    def lifecycle(self, variant="gui-pending", *, crashed_code=0xE0421001):
        runtime_path = self.source("windows_lifecycle_runtime_stages.py", "agent_tools/windows_lifecycle_runtime_stages.py")
        observer_path = self.source("windows_broker_fixture_observer.py", "scripts/windows_broker_fixture_observer.py")
        self.request["casesPath"] = self.source("windows_lifecycle_cases.py", "agent_tools/windows_lifecycle_cases.py")
        runtime_inputs = {"schemaVersion": 1, "operationId": self.operation,
            "fixtureWorkerPath": self.source("windows_lifecycle_runtime_fixture_worker.py", "agent_tools/windows_lifecycle_runtime_fixture_worker.py"),
            "socksSourcePath": self.source("socks_http_fixture.py", "scripts/integration/socks_http_fixture.py"),
            "httpsSourcePath": self.source("https_subscription_relay_fixture.py", "scripts/integration/https_subscription_relay_fixture.py"),
            "runtimeImagePath": str(self.root / "workspace/runtime/tools/sing-box.exe"),
            "runtimeSha256": "b" * 64, "installedAdmissionArtifactId": "peer-package-admission"}
        def child(label, code=0, crashed=False):
            value = types.SimpleNamespace(label=label, _lifecycle_crash_attempted=crashed)
            value.wait = lambda: self.calls.append(("wait", label, code)) or {"exitCode": code, "eof": {"stdout": True, "stderr": True}}
            return value
        serve = child("serve")
        actors = {"owner": {"peer": "original-owner"}, "runtime": {"peer": "original-runtime"}}
        current = {"owner": {"peer": "current-owner"}, "runtime": {"peer": "current-runtime"}}
        state = {"workspace": self.root / "workspace", "identity": "peer-controller", "serve": serve,
            "actors": actors, "ready": {"advertisedSocksPort": 12345}, "runtimeArtifact": {"peer": "runtime-artifact"}}
        def start(*_):
            self.calls.append("start-runtime"); self.children.append(serve); return state
        def gui(*args):
            self.calls.append(("gui-derived", args[-1]))
            self.children += [child("lifecycle-gui", crashed_code, True), child("lifecycle-gui")]
        def off(*args):
            self.calls.append(("off-actors", args[-2:]))
        self.modules[runtime_path] = types.SimpleNamespace(validate_inputs=lambda *_: self.calls.append("validate-runtime"),
            start_runtime=start, find_best=lambda *args: self.calls.append(("find-best", args[-1])),
            capture_proxy_actors=lambda *_: self.calls.append("recapture-actors") or current,
            stop_fixture=lambda *_: self.calls.append("stop-fixture"))
        self.modules[observer_path] = types.SimpleNamespace(WindowsNative=lambda: "declared-native-peer")
        self.modules[self.request["casesPath"]] = types.SimpleNamespace(CRASH_EXIT=0xE0421001,
            gui_continuity=gui, pending_selection=lambda *_: self.calls.append("pending-selection"),
            off_proxy_and_disconnected_serve=off, read=lambda *args: self.calls.append(("public", args[-1])))
        gui_inputs = None
        if variant == "gui-pending":
            gui_inputs = {"schemaVersion": 1, "guiPath": str(self.SOURCE_ROOT / "VPN.exe"),
                "trafficWorkerPath": self.source("windows_lifecycle_traffic_worker.py", "agent_tools/windows_lifecycle_traffic_worker.py"),
                "trafficInputPath": str(self.SOURCE_ROOT / "traffic-input.json"),
                "installedAdmissionArtifactId": "peer-package-admission", "fixtureAdmissionArtifactId": "peer-fixture",
                "sourceArtifactId": "peer-source", "frontendCrashScenario": "exact-owned-original-gui-handle",
                "trayAdmissionArtifactId": "peer-tray"}
            for path in (gui_inputs["guiPath"], gui_inputs["trafficInputPath"]):
                self.by_path[path.casefold()] = DedicatedPinPeer(path, b"explicit inert input")
        self.inputs = {"schemaVersion": 1, "variant": variant, "sourceSha": "a" * 40,
            "modules": {"runtime": runtime_path, "observer": observer_path}, "runtime": runtime_inputs, "gui": gui_inputs}
        self.harness({"LIFECYCLE_INPUTS": self.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
        return state, current


class DedicatedDriverControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.owner = DedicatedDispatchPeer(Path(self.temp.name))
        patcher = mock.patch.object(dedicated_driver, "__file__", str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_ordinary_dedicated_driver.py"))
        patcher.start(); self.addCleanup(patcher.stop)

    def test_armed_update_holds_original_owner_until_release_after_known_driver(self):
        self.owner.update()
        self.assertEqual(0, dedicated_driver.run(self.owner, "windows-public-update"))
        calls = self.owner.calls
        self.assertLess(calls.index("arm"), calls.index("cases"))
        self.assertLess(calls.index("cases"), calls.index(("driver-completed", 0)))
        self.assertLess(calls.index(("driver-completed", 0)), calls.index("wait-release"))
        self.assertEqual("released", self.owner.caller_collection_hold.state)

    def test_final_stage_is_bound_per_update_variant_before_case_effect(self):
        for variant in sorted(dedicated_driver.FINAL_TERMINAL | dedicated_driver.FINAL_RETURNED):
            with self.subTest(variant=variant):
                owner = DedicatedDispatchPeer(Path(self.temp.name)); inputs = owner.update(variant)
                inputs["stage"] = "returned-cleanup" if variant in dedicated_driver.FINAL_TERMINAL else "terminal-actors"
                owner.harness({"UPDATE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": inputs})
                with self.assertRaisesRegex(ValueError, "exact-final-update-collector"):
                    dedicated_driver.run(owner, "windows-public-update")
                self.assertNotIn("arm", owner.calls); self.assertNotIn("cases", owner.calls)

    def test_no_install_variants_have_no_collector_or_hold(self):
        for variant in sorted(dedicated_driver.NO_SYSTEM):
            with self.subTest(variant=variant):
                owner = DedicatedDispatchPeer(Path(self.temp.name)); owner.update(variant, hold=False)
                self.assertEqual(0, dedicated_driver.run(owner, "windows-public-update"))
                self.assertNotIn("arm", owner.calls); self.assertNotIn("wait-release", owner.calls)

    def test_armed_case_failure_and_release_unknown_park_without_unwinding_hold(self):
        for role in ("case_error", "release_error"):
            with self.subTest(role=role):
                owner = DedicatedDispatchPeer(Path(self.temp.name)); owner.update()
                error = RuntimeError("explicit local " + role); setattr(owner, role, error)
                with self.assertRaises(DedicatedParked):
                    dedicated_driver.run(owner, "windows-public-update")
                self.assertIs(error, owner.parked["error"])
                self.assertIs(owner.caller_collection_hold, owner.parked["originalHold"])
                self.assertNotEqual("released", owner.caller_collection_hold.state)

    def test_nonzero_or_boolean_result_cannot_publish_ready_or_release(self):
        for result in (1, None, True):
            with self.subTest(result=result):
                owner = DedicatedDispatchPeer(Path(self.temp.name)); owner.update(); owner.result = result
                with self.assertRaises(DedicatedParked):
                    dedicated_driver.run(owner, "windows-public-update")
                self.assertNotIn("wait-release", owner.calls)

    def test_protected_unknown_cannot_be_accepted_as_normal_return(self):
        self.owner.update("protected-storage-rejected", hold=False)
        with self.assertRaisesRegex(DedicatedParked, "cannot-return-known-success"):
            dedicated_driver.run(self.owner, "windows-public-update")
        self.assertNotIn("arm", self.owner.calls)

    def test_transport_gap_refuses_before_scenario_or_hold(self):
        self.owner.update("transport-loss", hold=False)
        with self.assertRaisesRegex(ValueError, "semantic-producer-not-yet-prepared"):
            dedicated_driver.run(self.owner, "windows-public-update")
        self.assertNotIn("cases", self.owner.calls); self.assertNotIn("arm", self.owner.calls)

    def test_executable_harness_or_changed_reviewed_source_refuses_before_module_execution(self):
        self.owner.update()
        path = self.owner.request["harnessPath"]
        self.owner.by_path[path.casefold()] = DedicatedPinPeer(path, b"import os\n")
        with self.assertRaisesRegex(ValueError, "literal-harness-only"):
            dedicated_driver.run(self.owner, "windows-public-update")
        self.assertNotIn(("module", "_owned_dedicated_literal_harness"), self.owner.calls)
        self.owner.update()
        path = self.owner.inputs["modules"]["server"]
        self.owner.by_path[path.casefold()] = DedicatedPinPeer(path, b"unreviewed source")
        with self.assertRaisesRegex(ValueError, "reviewed-source-pin"):
            dedicated_driver.run(self.owner, "windows-public-update")
        self.assertNotIn("cases", self.owner.calls); self.assertNotIn("arm", self.owner.calls)

    def test_driver_hold_sources_cannot_be_part_of_retiring_app_role(self):
        self.owner.update()
        self.owner.inputs["installedRoot"] = str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_system_collector")
        self.owner.harness({"UPDATE_INPUTS": self.owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
        with self.assertRaisesRegex(ValueError, "outside-retiring-app-role"):
            dedicated_driver.run(self.owner, "windows-public-update")
        self.assertNotIn("arm", self.owner.calls); self.assertNotIn("cases", self.owner.calls)

    def test_gui_actors_are_observed_state_and_intentional_crash_is_preserved(self):
        state, _ = self.owner.lifecycle()
        observed_error = None
        try:
            result = dedicated_driver.run_lifecycle(self.owner, self.owner.modules[self.owner.request["casesPath"]],
                self.owner.module(self.owner.request["harnessPath"], "peer-literal"))
        except Exception as error:
            observed_error = error
        self.assertIsNone(observed_error, repr(observed_error))
        self.assertEqual(0, result)
        gui = next(call[1] for call in self.owner.calls if isinstance(call, tuple) and call[0] == "gui-derived")
        self.assertIs(gui["ownerActor"], state["actors"]["owner"])
        self.assertIs(gui["runtimeActor"], state["actors"]["runtime"])
        self.assertEqual(state["identity"], gui["controllerId"])
        self.assertIn(("wait", "lifecycle-gui", 0xE0421001), self.owner.calls)
        self.assertIn(("wait", "lifecycle-gui", 0), self.owner.calls)
        self.assertLess(self.owner.calls.index("stop-fixture"), self.owner.calls.index(("public", "quit")))

    def test_find_best_recaptures_actual_current_actors_before_explicit_off(self):
        for variant in sorted(dedicated_driver.PROXY_VARIANTS - {"gui-pending"}):
            with self.subTest(variant=variant):
                owner = DedicatedDispatchPeer(Path(self.temp.name)); _, current = owner.lifecycle(variant)
                self.assertEqual(0, dedicated_driver.run(owner, "windows-proxy-lifecycle"))
                self.assertIn(("off-actors", (current["owner"], current["runtime"])), owner.calls)
                self.assertLess(owner.calls.index("recapture-actors"), next(i for i, call in enumerate(owner.calls)
                    if isinstance(call, tuple) and call[0] == "off-actors"))

    def test_tun_scheduled_autostart_and_unreviewed_variants_refuse(self):
        for variant in ("restart-grant", "scheduled", "no-tray", "autostart", "external-hook"):
            with self.subTest(variant=variant):
                owner = DedicatedDispatchPeer(Path(self.temp.name)); owner.lifecycle("find-best-success")
                owner.inputs["variant"] = variant
                with self.assertRaisesRegex(ValueError, "finite-proxy-variants-only"):
                    dedicated_driver.run_lifecycle(owner, owner.modules[owner.request["casesPath"]],
                        types.SimpleNamespace(LIFECYCLE_INPUTS=owner.inputs, SYSTEM_COLLECTOR_CLOSE_HOLD=None))
                self.assertNotIn("start-runtime", owner.calls)

    def test_incomplete_original_eof_cannot_close_lifecycle(self):
        self.owner.lifecycle("find-best-success")
        runtime = self.owner.modules[self.owner.inputs["modules"]["runtime"]]
        original = runtime.start_runtime
        def start(*args):
            state = original(*args)
            state["serve"].wait = lambda: {"exitCode": 0, "eof": {"stdout": True, "stderr": False}}
            return state
        runtime.start_runtime = start
        with self.assertRaisesRegex(ValueError, "terminal-and-eof"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")


class DedicatedPlannerAndOwnerControls(unittest.TestCase):
    def request(self, action="windows-public-update"):
        common, _, worker = synthetic_request(); source = PureWindowsPath(worker["path"]).parent
        case_name, case_sha = task.DEDICATED_CASES[action]
        driver_path = ROOT / "agent_tools/windows_ordinary_dedicated_driver.py"
        extra = [pin(source / "VPN.exe"), pin(source / case_name, digest=case_sha),
            pin(source / "admitted-harness.py"), pin(source / "windows_ordinary_dedicated_driver.py",
                size=driver_path.stat().st_size, digest=hashlib.sha256(driver_path.read_bytes()).hexdigest())]
        common["filePins"] += extra
        directories = {PureWindowsPath(item["path"]) for item in common["directoryPins"]}
        directories.update(parent for item in common["filePins"] for parent in PureWindowsPath(item["path"]).parents)
        common["directoryPins"] = [pin(directory, directory=True) for directory in sorted(directories, key=str)]
        args = {"cliPath": extra[0]["path"], "workspace": str(PureWindowsPath(common["operationRoot"]) / "workspace"),
            "productVersion": "2.2.14", "casesPath": extra[1]["path"], "harnessPath": extra[2]["path"]}
        return common, args

    def test_only_closed_dedicated_actions_and_reviewed_source_pins_are_admitted(self):
        for action in task.DEDICATED_CASES:
            with self.subTest(action=action):
                common, args = self.request(action)
                self.assertEqual(action, task.worker_request(common, action, **args)["action"])
                with self.assertRaises(ValueError):
                    task.worker_request(common, action, **dict(args, callback="run"))
                with self.assertRaisesRegex(ValueError, "baseline"):
                    task.worker_request(common, action, **dict(args, productVersion="2.2.13"))
                target = next(p for p in common["filePins"] if p["path"] == args["casesPath"])
                target["sha256"] = "f" * 64
                with self.assertRaisesRegex(ValueError, "fixed-reviewed-source-roles"):
                    task.worker_request(common, action, **args)

    def test_owner_dedicated_route_never_starts_generic_serve(self):
        calls = []; driver_path = str(Path(process_owner.__file__).with_name("windows_ordinary_dedicated_driver.py"))
        for action in task.DEDICATED_CASES:
            owner = types.SimpleNamespace(request={"action": action}, by_path={driver_path.casefold():
                types.SimpleNamespace(record={"sha256": task.DEDICATED_DRIVER_SHA})},
                module=lambda path, name: types.SimpleNamespace(run=lambda original, selected:
                    calls.append((original, selected)) or 0),
                child=lambda *_: self.fail("dedicated route must not create generic child"))
            with mock.patch.object(process_owner, "absolute", Path):
                self.assertEqual(0, process_owner.Owner.run(owner))
            self.assertIs(owner, calls[-1][0]); self.assertEqual(action, calls[-1][1])

    def test_finish_cannot_release_pins_before_original_collection_hold_released(self):
        for state in ("armed", "driver-terminal", "waiting-release", "unknown"):
            with self.subTest(state=state):
                closed = []
                owner = types.SimpleNamespace(caller_collection_hold=types.SimpleNamespace(state=state),
                    children=[], pins=[types.SimpleNamespace(directory=True, close=lambda: closed.append(True))],
                    park=lambda reason, error=None: (_ for _ in ()).throw(DedicatedParked(reason)),
                    guard=lambda: self.fail("finish guard reached before hold release"))
                with self.assertRaisesRegex(DedicatedParked, "hold-not-released"):
                    process_owner.Owner.finish(owner, 0)
                self.assertEqual([], closed)


class DedicatedCleanupCausalControls(unittest.TestCase):
    def test_authentic_initial_dispatcher_rejects_intentional_crash_current_accepts(self):
        path = FIXTURES / "dedicated-driver-cleanup.before.source"; raw = path.read_bytes()
        self.assertEqual("9fde8ce7db24dbc4d7c437400c43af6794f3f0a10c9f1422e62c08ce3d9353c0", hashlib.sha256(raw).hexdigest())
        provenance = json.loads((FIXTURES / "dedicated-driver-cleanup.provenance.json").read_bytes())
        self.assertEqual(provenance["sha256"], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType("_whole_initial_dedicated_dispatcher")
        before.__file__ = str(path)
        exec(compile(raw, str(path), "exec"), before.__dict__)
        name = "test_gui_actors_are_observed_state_and_intentional_crash_is_preserved"
        with mock.patch.dict(globals(), {"dedicated_driver": before}):
            result = unittest.TestResult(); DedicatedDriverControls(name).run(result)
        self.assertEqual(1, len(result.failures), result.errors); self.assertEqual([], result.errors)
        self.assertIn("dedicated-original-lifecycle-terminal-and-eof", result.failures[0][1])
        green = unittest.TestResult(); DedicatedDriverControls(name).run(green)
        self.assertTrue(green.wasSuccessful(), green.failures + green.errors)


class RuntimeBranchDispatchControls(unittest.TestCase):
    """Finite source/sequence peers only; real branch bodies have their own suite."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        patcher = mock.patch.object(dedicated_driver, "__file__", str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_ordinary_dedicated_driver.py"))
        patcher.start(); self.addCleanup(patcher.stop)

    def owner(self, variant):
        owner = DedicatedDispatchPeer(Path(self.temp.name))
        state, current = owner.lifecycle("find-best-success")
        owner.raw_limit = 8 * 1024 * 1024
        owner.inputs["variant"] = variant
        owner.inputs["runtime"]["ordinaryContextArtifactId"] = "peer-native-context-admission"
        path = owner.source("windows_runtime_branch_cases.py", "agent_tools/windows_runtime_branch_cases.py")
        owner.inputs["modules"]["branches"] = path
        branch = {"schemaVersion": 1, "fixtureRuntimeToolPath": str(owner.SOURCE_ROOT / "sing-box.exe"),
            "runtimeSha256": "b" * 64,
            "listenerScriptPath": owner.source("windows_runtime_tcp_listeners.ps1", "agent_tools/windows_runtime_tcp_listeners.ps1"),
            "powerShellPath": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "trafficWorkerPath": owner.source("windows_lifecycle_traffic_worker.py", "agent_tools/windows_lifecycle_traffic_worker.py"),
            "trafficInputPath": str(owner.SOURCE_ROOT / "traffic-input.json"),
            "installedAdmissionArtifactId": "peer-package-admission",
            "ordinaryContextArtifactId": "peer-native-context-admission"}
        for name in ("fixtureRuntimeToolPath", "powerShellPath", "trafficInputPath"):
            value = branch[name]; owner.by_path[value.casefold()] = DedicatedPinPeer(value, b"declared inert data/program peer")
        # A declared admitted executable record, never a real/native positive.
        owner.by_path[branch["fixtureRuntimeToolPath"].casefold()].record["sha256"] = "b" * 64
        owner.inputs["branch"] = branch
        runtime = owner.modules[owner.inputs["modules"]["runtime"]]
        start = runtime.start_runtime
        serve_wait = state["serve"].wait
        state["serve"].terminal = None
        def finish_serve():
            value = serve_wait(); state["serve"].terminal = value; return value
        state["serve"].wait = finish_serve
        fixture = types.SimpleNamespace(label="owned-runtime-fixture", terminal=None)
        def fresh(*args):
            result = start(*args); owner.children.append(fixture); return result
        runtime.start_runtime = fresh
        def stop(*args):
            owner.calls.append("stop-fixture")
            fixture.terminal = {"exitCode": 0, "eof": {"stdout": True, "stderr": True}}
        runtime.stop_fixture = stop
        owner.branch_error = owner.files_error = None
        def config(*args):
            owner.calls.append(("branch-config", args[-1], args[1] is state))
            if owner.branch_error is not None: raise owner.branch_error
            state["actors"] = current
        def failure(*args):
            owner.calls.append(("branch-failure", args[-1], args[1] is state))
            if owner.branch_error is not None: raise owner.branch_error
            state["actors"] = current
        def sibling_start(*args):
            owner.calls.append("sibling-start")
            child = types.SimpleNamespace(label="owned-sibling-proxy-runtime", terminal=None)
            value = {"child": child}; owner.runtime_case_sibling = value
            owner.children.append(child); return value
        def sibling_off(*args):
            self.assertIs(args[-1], owner.runtime_case_sibling)
            self.assertIsNone(args[-1]["child"].terminal)
            owner.calls.append("sibling-off-survivor")
        def sibling_close(*args):
            self.assertIs(args[-1], owner.runtime_case_sibling)
            owner.calls.append("sibling-close-original")
            args[-1]["child"].terminal = {"exitCode": 0xE0421002, "eof": {"stdout": True, "stderr": True}}
        def close_files(*args):
            self.assertIs(args[1], state); owner.calls.append("files-close-after-off")
            if owner.files_error is not None: raise owner.files_error
        owner.modules[path] = types.SimpleNamespace(config_case=config, failure_case=failure,
            start_sibling=sibling_start, off_with_sibling_survivor=sibling_off,
            close_sibling=sibling_close, close_fixture_files_after_off=close_files)
        owner.harness({"LIFECYCLE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
        return owner, state, current

    def run_owner(self, owner):
        return dedicated_driver.run(owner, "windows-proxy-lifecycle")

    def test_six_named_variants_use_original_state_and_known_cleanup(self):
        for variant in ("generated", "custom", "large", "prepare-failure", "commit-readiness-failure", "sibling-off"):
            with self.subTest(variant=variant):
                owner, state, current = self.owner(variant)
                self.assertEqual(0, self.run_owner(owner))
                self.assertEqual(1, owner.calls.count("start-runtime"))
                self.assertLess(owner.calls.index("files-close-after-off"), owner.calls.index("stop-fixture"))
                self.assertLess(owner.calls.index("stop-fixture"), owner.calls.index(("public", "quit")))
                self.assertIs(owner.children[0], state["serve"])
                self.assertTrue(all(child.terminal["eof"] == {"stdout": True, "stderr": True} for child in owner.children))
                if variant == "sibling-off":
                    self.assertLess(owner.calls.index("sibling-off-survivor"), owner.calls.index("sibling-close-original"))
                    self.assertLess(owner.calls.index("sibling-close-original"), owner.calls.index("files-close-after-off"))
                    self.assertFalse(any(isinstance(row, tuple) and row[0] == "off-actors" for row in owner.calls))
                    self.assertEqual(0xE0421002, owner.runtime_case_sibling["child"].terminal["exitCode"])
                else:
                    expected = "branch-config" if variant in {"generated", "custom", "large"} else "branch-failure"
                    self.assertIn((expected, variant, True), owner.calls)
                    self.assertLess(next(i for i, row in enumerate(owner.calls) if isinstance(row, tuple) and row[0] == expected), owner.calls.index("recapture-actors"))
                    off = ("off-actors", (current["owner"], current["runtime"]))
                    self.assertIn(off, owner.calls)
                    self.assertLess(owner.calls.index(off), owner.calls.index("files-close-after-off"))

    def test_strict_nine_fields_bool_versions_and_old_four_schema_before_start(self):
        for change in ("extra", "missing", "bool-version", "null-input", "old-four-extra"):
            with self.subTest(change=change):
                owner, _, _ = self.owner("generated")
                if change == "extra": owner.inputs["branch"]["callback"] = "not allowed"
                elif change == "missing": owner.inputs["branch"].pop("listenerScriptPath")
                elif change == "bool-version": owner.inputs["branch"]["schemaVersion"] = True
                elif change == "null-input": owner.inputs["branch"]["ordinaryContextArtifactId"] = None
                else: owner.inputs["variant"] = "find-best-success"
                owner.harness({"LIFECYCLE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
                with self.assertRaises(ValueError): self.run_owner(owner)
                self.assertNotIn("start-runtime", owner.calls)

    def test_exact_branch_and_listener_and_traffic_sources_before_start(self):
        for role in ("branches", "listenerScriptPath", "trafficWorkerPath"):
            with self.subTest(role=role):
                owner, _, _ = self.owner("generated")
                path = owner.inputs["modules"][role] if role == "branches" else owner.inputs["branch"][role]
                owner.by_path[path.casefold()].record["sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "reviewed-source-pin"): self.run_owner(owner)
                self.assertNotIn("start-runtime", owner.calls)

    def test_admission_tool_and_program_capture_joins_before_start(self):
        for change in ("package", "context", "tool-sha", "powershell", "capture"):
            with self.subTest(change=change):
                owner, _, _ = self.owner("custom")
                if change == "package": owner.inputs["branch"]["installedAdmissionArtifactId"] = "foreign"
                elif change == "context": owner.inputs["branch"]["ordinaryContextArtifactId"] = "foreign"
                elif change == "tool-sha": owner.inputs["branch"]["runtimeSha256"] = "c" * 64
                elif change == "powershell": owner.inputs["branch"]["powerShellPath"] = r"C:\Other\powershell.exe"
                else: owner.raw_limit -= 1
                owner.harness({"LIFECYCLE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": None})
                with self.assertRaises(ValueError): self.run_owner(owner)
                self.assertNotIn("start-runtime", owner.calls)

    def test_original_case_error_keeps_same_children_without_replay_or_cleanup(self):
        owner, state, _ = self.owner("large")
        original = RuntimeError("declared branch observation unknown"); owner.branch_error = original
        with self.assertRaises(RuntimeError) as caught: self.run_owner(owner)
        self.assertIs(original, caught.exception)
        self.assertIs(owner.children[0], state["serve"])
        self.assertEqual(1, sum(isinstance(row, tuple) and row[0] == "branch-config" for row in owner.calls))
        self.assertTrue(all(child.terminal is None for child in owner.children))
        self.assertNotIn("stop-fixture", owner.calls); self.assertNotIn(("public", "quit"), owner.calls)

    def test_fixture_close_error_is_primary_and_blocks_quit(self):
        owner, state, _ = self.owner("prepare-failure")
        original = RuntimeError("declared closing observer unknown"); owner.files_error = original
        with self.assertRaises(RuntimeError) as caught: self.run_owner(owner)
        self.assertIs(original, caught.exception)
        self.assertIs(owner.children[0], state["serve"])
        self.assertNotIn("stop-fixture", owner.calls); self.assertNotIn(("public", "quit"), owner.calls)

    def test_missing_original_child_eof_cannot_publish_known_closed(self):
        owner, _, _ = self.owner("sibling-off")
        runtime = owner.modules[owner.inputs["modules"]["runtime"]]
        stop = runtime.stop_fixture
        def incomplete(*args):
            stop(*args); owner.children[1].terminal["eof"]["stderr"] = False
        runtime.stop_fixture = incomplete
        with self.assertRaisesRegex(ValueError, "all-original-child-eof"): self.run_owner(owner)
        self.assertFalse(any(isinstance(row, tuple) and row[0] == "dedicated-proxy-lifecycle-known-closed" for row in owner.calls))


# Protected OS-file role controls; portable declared Win32 peers, not native admission.
import ast as _os_role_ast
import inspect as _os_role_inspect

_OS_ROLE_TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
_OS_ROLE_PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
_OS_ROLE_MSI = 'C:\\Windows\\System32\\msiexec.exe'
_OS_ROLE_ASSET = 'C:\\ProgramData\\VpnControlArtifact-87079087-ae56-43c9-b504-842d2f300e12\\vpn-control-2.2.13.msi'
_OS_ROLE_ACTUAL_SDDL = 'O:' + _OS_ROLE_TI + 'D:P(A;;FA;;;' + _OS_ROLE_TI + ')(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)'
_OS_ROLE_PROTECTED = {'ownerSid': _OS_ROLE_TI, 'sddl': _OS_ROLE_ACTUAL_SDDL}
_OS_ROLE_DATA = b'Portable declared OS bytes; not a native positive.\x00\xff'

def _os_role_record(path=_OS_ROLE_PS, *, links=2, security=None, directory=False):
    identity = {'volumeSerial': 213740663, 'fileIndex': 4222124650664500, 'attributes': 16 if directory else 32}
    if not directory:
        identity.update(sizeBytes=len(_OS_ROLE_DATA), links=links, creationFileTime='133700000000000001', lastWriteFileTime='133700000000000002')
    value = {'path': path, 'nativeIdentity': identity, 'security': copy.deepcopy(_OS_ROLE_PROTECTED if security is None else security)}
    if not directory:
        value['sha256'] = hashlib.sha256(_OS_ROLE_DATA).hexdigest()
    return value

def _os_role_number(value):
    return value.value if hasattr(value, 'value') else value

class _OsRoleKernelPeer:
    """Declared handle, namespace, Info, byte-stream and LocalFree API peer."""

    def __init__(self, module, states):
        self.module = module
        self.files = {path: copy.deepcopy(state) for path, state in states.items()}
        self.handles, self.positions, self.closed, self.calls = ({}, {}, [], [])
        self.next_handle = 100
        self.read_hook = None
        self.read_count = 0
        self.buffers = []

    def CreateFileW(self, path, access, share, security, disposition, flags, template):
        self.calls.append(('CreateFileW', path, access, share, disposition, flags))
        if path not in self.files:
            return ctypes.c_void_p(-1).value
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = self.files[path]
        self.positions[handle] = 0
        return handle

    def GetFileInformationByHandle(self, handle, output):
        handle = _os_role_number(handle)
        self.calls.append(('GetFileInformationByHandle', handle))
        state = self.handles[handle]
        if state.get('infoFailure'):
            return 0
        identity = state['nativeIdentity']
        info = ctypes.cast(output, ctypes.POINTER(self.module.Info)).contents
        info.attributes = identity['attributes']
        info.volume = identity['volumeSerial']
        info.index_high, info.index_low = (identity['fileIndex'] >> 32, identity['fileIndex'] & 4294967295)
        info.size_high, info.size_low = (identity.get('sizeBytes', 0) >> 32, identity.get('sizeBytes', 0) & 4294967295)
        info.links = identity.get('links', 0)
        for name, key in (('creation', 'creationFileTime'), ('write', 'lastWriteFileTime')):
            value = int(identity.get(key, '0'))
            item = getattr(info, name)
            item.dwHighDateTime, item.dwLowDateTime = (value >> 32, value & 4294967295)
        return 1

    def SetFilePointerEx(self, handle, position, output, method):
        self.positions[_os_role_number(handle)] = _os_role_number(position)
        return 1

    def ReadFile(self, handle, buffer, maximum, count, overlapped):
        handle = _os_role_number(handle)
        start = self.positions[handle]
        data = self.handles[handle]['data'][start:start + maximum]
        ctypes.memmove(buffer, data, len(data))
        ctypes.cast(count, ctypes.POINTER(self.module.W.DWORD))[0] = len(data)
        self.positions[handle] += len(data)
        self.read_count += 1
        self.calls.append(('ReadFile', handle, len(data)))
        if self.read_hook is not None:
            hook, self.read_hook = (self.read_hook, None)
            hook(self.handles[handle])
        return 1

    def CloseHandle(self, handle):
        handle = _os_role_number(handle)
        self.closed.append(handle)
        self.calls.append(('CloseHandle', handle))
        return 1

    def LocalFree(self, pointer):
        self.calls.append(('LocalFree', _os_role_number(pointer)))
        return None

    def string(self, text, output):
        buffer = ctypes.create_unicode_buffer(text)
        self.buffers.append(buffer)
        ctypes.cast(output, ctypes.POINTER(self.module.W.LPWSTR))[0] = ctypes.cast(buffer, self.module.W.LPWSTR)

class _OsRoleSecurityPeer:
    """Declared owner+DACL query/conversion peer; Native.security stays real."""

    def __init__(self, kernel):
        self.k = kernel
        self.owners, self.descriptors = ({}, {})

    def GetSecurityInfo(self, handle, kind, flags, owner_out, group, dacl, sacl, descriptor_out):
        handle = _os_role_number(handle)
        assert kind == 1 and flags == 5
        state = self.k.handles[handle]
        if state.get('securityFailure'):
            return 5
        process_owner, descriptor = (handle + 10000, handle + 20000)
        self.owners[process_owner] = state['security']['ownerSid']
        self.descriptors[descriptor] = state['security']['sddl']
        ctypes.cast(owner_out, ctypes.POINTER(self.k.module.W.LPVOID))[0] = process_owner
        ctypes.cast(descriptor_out, ctypes.POINTER(self.k.module.W.LPVOID))[0] = descriptor
        self.k.calls.append(('GetSecurityInfo', handle, flags))
        return 0

    def ConvertSidToStringSidW(self, sid, output):
        self.k.string(self.owners[_os_role_number(sid)], output)
        return 1

    def ConvertSecurityDescriptorToStringSecurityDescriptorW(self, descriptor, revision, flags, output, length):
        assert revision == 1 and flags == 5
        text = self.descriptors[_os_role_number(descriptor)]
        self.k.string(text, output)
        ctypes.cast(length, ctypes.POINTER(self.k.module.W.DWORD))[0] = len(text)
        return 1

def _os_role_native_for(item, data=_OS_ROLE_DATA, module=process_owner):
    state = copy.deepcopy(item)
    state['data'] = data
    kernel = _OsRoleKernelPeer(module, {item['path']: state})
    native = module.Native.__new__(module.Native)
    native.k, native.a = (kernel, _OsRoleSecurityPeer(kernel))
    return (native, kernel)

def _os_role_observed_handle(native, kernel, path):
    return kernel.CreateFileW(path, 2147614720, 1, None, 3, 35651584, None)

class ProtectedOsPinRegressionTests(unittest.TestCase):

    def test_fixed_os_native_role_links_two(self):
        for path in (_OS_ROLE_PS, _OS_ROLE_MSI):
            with self.subTest(path=path):
                item = _os_role_record(path)
                native, kernel = _os_role_native_for(item)
                pin = process_owner.Pin(native, item)
                self.assertEqual(pin.digest(), item['sha256'])
                pin.current()
                self.assertGreater(kernel.read_count, 0)
                self.assertTrue(any((row[0] == 'GetSecurityInfo' for row in kernel.calls)))
                pin.close()
                self.assertEqual(set(kernel.handles), set(kernel.closed))

    def test_fixed_os_planner_role_links_two(self):
        for path in (_OS_ROLE_PS, _OS_ROLE_MSI):
            with self.subTest(path=path):
                self.assertEqual(str(task.validate_pin(_os_role_record(path))), path)

    def test_original_generic_native_identity_stays_single_link(self):
        for path in (_OS_ROLE_PS, _OS_ROLE_MSI, _OS_ROLE_ASSET):
            item = _os_role_record(path)
            native, kernel = _os_role_native_for(item)
            handle = _os_role_observed_handle(native, kernel, path)
            with self.assertRaisesRegex(process_owner.Refused, '^native-file-hardlink$'):
                native.identity(handle)

    def test_only_fixed_case_sensitive_paths_get_exception(self):
        aliases = (_OS_ROLE_PS.lower(), _OS_ROLE_MSI.upper(), _OS_ROLE_PS.replace('System32', 'SysWOW64'), _OS_ROLE_PS + '.backup', 'C:\\Elsewhere\\powershell.exe', _OS_ROLE_ASSET)
        for path in aliases:
            with self.subTest(path=path):
                item = _os_role_record(path)
                with self.assertRaisesRegex(ValueError, '^single-link-file-digest$'):
                    task.validate_pin(item)
                native, kernel = _os_role_native_for(item)
                handle = _os_role_observed_handle(native, kernel, path)
                with self.assertRaisesRegex(process_owner.Refused, '^protected-os-path$'):
                    native.protected_os_identity(handle, path)
                with self.assertRaisesRegex(process_owner.Refused, '^native-file-hardlink$'):
                    process_owner.Pin(native, item)

    def test_positive_count_preserves_actual_value_not_normalized(self):
        for links in (1, 2, 3, 17):
            item = _os_role_record(links=links)
            native, kernel = _os_role_native_for(item)
            handle = _os_role_observed_handle(native, kernel, _OS_ROLE_PS)
            self.assertEqual(native.protected_os_identity(handle, _OS_ROLE_PS), item['nativeIdentity'])
            task.validate_pin(item)
        item = _os_role_record(links=0)
        native, kernel = _os_role_native_for(item)
        handle = _os_role_observed_handle(native, kernel, _OS_ROLE_PS)
        with self.assertRaisesRegex(process_owner.Refused, '^protected-os-positive-links$'):
            native.protected_os_identity(handle, _OS_ROLE_PS)
        with self.assertRaisesRegex(ValueError, '^single-link-file-digest$'):
            task.validate_pin(item)

    def test_equivalent_protected_writer_policies_not_fixture_text(self):
        equivalents = ('O:' + _OS_ROLE_TI + 'D:PAI(A;;FA;;;' + _OS_ROLE_TI + ')(A;;FRFX;;;BU)', 'O:' + _OS_ROLE_TI + 'D:PAR(A;;GA;;;S-1-5-18)(A;;0x1200a9;;;S-1-5-21-1-2-3-1001)', 'O:' + _OS_ROLE_TI + 'D:P(D;;FA;;;BU)(A;;GA;;;BA)(A;ID;GRGX;;;WD)', 'O:' + _OS_ROLE_TI + 'D:P(A;;0x0;;;S-1-15-2-1234567890)')
        for sddl in equivalents:
            with self.subTest(sddl=sddl):
                security = {'ownerSid': _OS_ROLE_TI, 'sddl': sddl}
                self.assertTrue(process_owner._protected_os_security(security))
                self.assertTrue(task._protected_os_security(security))
                item = _os_role_record(security=security)
                task.validate_pin(item)
                native, _ = _os_role_native_for(item)
                pin = process_owner.Pin(native, item)
                pin.close()

    def test_invalid_writer_policies_refused_before_digest(self):
        prefix = 'O:' + _OS_ROLE_TI + 'D:'
        policies = (_OS_ROLE_PROTECTED | {'ownerSid': 'S-1-5-18'}, {'ownerSid': _OS_ROLE_TI, 'sddl': 'O:S-1-5-18D:P(A;;FA;;;SY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + '(A;;FA;;;SY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'NO_ACCESS_CONTROL'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;FW;;;BU)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;ID;GA;;;S-1-5-21-1-2-3-1001)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;0x01000000;;;AC)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(XA;;FA;;;SY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(OA;;FA;;;SY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;FA;guid;;SY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;SA;FR;;;BU)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;ZZ;;;BU)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;0x100000000;;;SY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;FR;;;S-1-5-' + '9' * 5000 + ')'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;FR;;;XY)'}, {'ownerSid': _OS_ROLE_TI, 'sddl': prefix + 'P(A;;FR;;;S-1-5-01)'})
        for security in policies:
            with self.subTest(sddl=security['sddl'][:110], owner=security['ownerSid']):
                self.assertFalse(process_owner._protected_os_security(security))
                self.assertFalse(task._protected_os_security(security))
                item = _os_role_record(security=security)
                with self.assertRaisesRegex(ValueError, '^protected-os-writer-policy$'):
                    task.validate_pin(item)
                native, kernel = _os_role_native_for(item)
                with self.assertRaisesRegex(process_owner.Refused, '^protected-os-writer-policy$'):
                    process_owner.Pin(native, item)
                self.assertEqual(kernel.read_count, 0)

    def test_reparse_directory_and_api_failure_refused(self):
        for field, value, error in (('attributes', 1056, 'native-file-type-or-reparse'), ('attributes', 16, 'native-file-type-or-reparse')):
            item = _os_role_record()
            item['nativeIdentity'][field] = value
            native, kernel = _os_role_native_for(item)
            handle = _os_role_observed_handle(native, kernel, _OS_ROLE_PS)
            with self.assertRaisesRegex(process_owner.Refused, '^' + error + '$'):
                native.protected_os_identity(handle, _OS_ROLE_PS)
            with self.assertRaisesRegex(ValueError, '^native-reparse-or-type$'):
                task.validate_pin(item)
        item = _os_role_record()
        native, kernel = _os_role_native_for(item)
        handle = _os_role_observed_handle(native, kernel, _OS_ROLE_PS)
        kernel.handles[handle]['infoFailure'] = True
        with self.assertRaisesRegex(process_owner.Refused, '^native-file-information$'):
            native.protected_os_identity(handle, _OS_ROLE_PS)
        kernel.handles[handle].pop('infoFailure')
        kernel.handles[handle]['securityFailure'] = True
        with self.assertRaisesRegex(process_owner.Refused, '^native-security-information$'):
            native.protected_os_identity(handle, _OS_ROLE_PS)

    def test_held_identity_all_seven_fields_are_exact(self):
        for key in _os_role_record()['nativeIdentity']:
            with self.subTest(key=key):
                item = _os_role_record()
                native, kernel = _os_role_native_for(item)
                pin = process_owner.Pin(native, item)
                value = kernel.handles[pin.handle]['nativeIdentity'][key]
                kernel.handles[pin.handle]['nativeIdentity'][key] = str(int(value) + 1) if isinstance(value, str) else value + 1
                with self.assertRaisesRegex(process_owner.Refused, '^pin-native-identity-changed$'):
                    pin.current()
                pin.close()

    def test_named_replacement_detected_and_temporary_handle_closed(self):
        item = _os_role_record()
        native, kernel = _os_role_native_for(item)
        pin = process_owner.Pin(native, item)
        replacement = copy.deepcopy(kernel.files[_OS_ROLE_PS])
        replacement['nativeIdentity']['fileIndex'] += 1
        kernel.files[_OS_ROLE_PS] = replacement
        before = kernel.next_handle
        with self.assertRaisesRegex(process_owner.Refused, '^pin-namespace-changed$'):
            pin.current()
        self.assertIn(before, kernel.closed)
        pin.close()

    def test_exact_security_equality_held_and_named(self):
        for changed_target in ('held', 'named'):
            with self.subTest(changed_target=changed_target):
                item = _os_role_record()
                native, kernel = _os_role_native_for(item)
                pin = process_owner.Pin(native, item)
                changed = copy.deepcopy(kernel.files[_OS_ROLE_PS])
                changed['security']['sddl'] += '(A;;FR;;;S-1-5-21-1-2-3-1001)'
                self.assertTrue(process_owner._protected_os_security(changed['security']))
                if changed_target == 'held':
                    kernel.handles[pin.handle] = changed
                    error = '^pin-security-changed$'
                else:
                    kernel.files[_OS_ROLE_PS] = changed
                    error = '^pin-namespace-changed$'
                with self.assertRaisesRegex(process_owner.Refused, error):
                    pin.current()
                pin.close()

    def test_digest_bytes_and_after_read_identity_remain_required(self):
        item = _os_role_record()
        native, kernel = _os_role_native_for(item)
        pin = process_owner.Pin(native, item)
        kernel.handles[pin.handle]['data'] = b'x' * len(_OS_ROLE_DATA)
        with self.assertRaisesRegex(process_owner.Refused, '^pin-digest-changed$'):
            pin.digest()
        kernel.handles[pin.handle]['data'] = _OS_ROLE_DATA
        kernel.read_hook = lambda state: state['nativeIdentity'].__setitem__('links', 3)
        with self.assertRaisesRegex(process_owner.Refused, '^pin-native-identity-changed$'):
            pin.digest()
        pin.close()

    def test_generic_files_and_directories_unchanged(self):
        for directory in (False, True):
            item = _os_role_record(_OS_ROLE_ASSET, links=1, directory=directory)
            task.validate_pin(item, directory)
            native, _ = _os_role_native_for(item)
            pin = process_owner.Pin(native, item, directory)
            pin.current()
            pin.close()
        for sha in ('', '0' * 63, 'F' * 64, None):
            item = _os_role_record()
            item['sha256'] = sha
            with self.assertRaisesRegex(ValueError, '^single-link-file-digest$'):
                task.validate_pin(item)

    def test_authentic_unfixed_policy_and_identical_role_helpers(self):
        for name, fixture, expected in (
            ("owner", "protected-os-owner.before.source", "ee28050bd0e33166956cc4f4ac68ca10cc89c30c01ae93468379895fee268a18"),
            ("planner", "protected-os-planner.before.source", "52d75b323d0a6cb867277e5d75f9c218860d2b7bc826f51ad81a2b89f177853c"),
        ):
            source = (FIXTURES / fixture).read_bytes()
            self.assertEqual(hashlib.sha256(source).hexdigest(), expected)
            module = types.ModuleType("_os_role_before_" + name)
            exec(compile(source, str(FIXTURES / fixture), "exec"), module.__dict__)
            for path in (_OS_ROLE_PS, _OS_ROLE_MSI):
                item = _os_role_record(path)
                if name == "owner":
                    native, kernel = _os_role_native_for(item, module=module)
                    with self.assertRaisesRegex(module.Refused, "^native-file-hardlink$"):
                        module.Pin(native, item)
                    self.assertTrue(any(row[0] == "GetFileInformationByHandle" for row in kernel.calls))
                else:
                    with self.assertRaisesRegex(ValueError, "^single-link-file-digest$"):
                        module.validate_pin(item)
        self.assertEqual(
            _os_role_ast.dump(_os_role_ast.parse(_os_role_inspect.getsource(process_owner._protected_os_security))),
            _os_role_ast.dump(_os_role_ast.parse(_os_role_inspect.getsource(task._protected_os_security))))


# Exact live PS owner method controls with declared Win32/security/typed ACL peers.
# Appends to test_windows_ordinary_task.py; no native or guest operation is performed.
class ProtectedOsPowerShellRegressionTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, "PowerShell is unavailable for the exact C# method controls")
    def test_live_owner_protected_os_role_and_authentic_before(self):
        fixture_hashes = {
            "protected-os-ps-owner.before.source": "d6317f066f4a679e37f0a6aa5c30c229a2c6115ae2968aed568bec91d07362b2",
            "protected-os-api-peers.cs.source": "49cd0db3cd9c045bb7e08adb8990275705a1611b94e7ff6cf7183e341254ef95",
            "protected-os-38-controls.ps1.source": "cffcf76aa26c622a7e1b141ac9af0b89985204b27c1fb1ae3fd5eaa26958af05",
        }
        fixtures = {}
        for name, expected in fixture_hashes.items():
            raw = (FIXTURES / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), expected, name)
            fixtures[name] = raw.decode("utf-8-sig")
        current_path = ROOT / "agent_tools/windows_ordinary_task_owner.ps1"
        current = current_path.read_bytes().decode("utf-8-sig")
        before = fixtures["protected-os-ps-owner.before.source"]

        def exact_line(source, marker):
            values = [line for line in source.splitlines(keepends=True) if marker in line]
            self.assertEqual(len(values), 1, marker)
            return values[0]

        replacements = {
            "@@BEFORE_FI@@": exact_line(before, "struct FI {"),
            "@@CANDIDATE_FI@@": exact_line(current, "struct FI {"),
            "@@BEFORE_IDENTITY@@": exact_line(before, " public static Dictionary<string,object> Identity("),
            "@@CANDIDATE_METHODS@@": "".join(exact_line(current, marker) for marker in (
                " const string OsOwner=", " static bool OsPath(", " static void ProtectedOsSecurity(",
                " public static Dictionary<string,object> Identity(",
                " public static Dictionary<string,object> PinIdentity(",
                " static Dictionary<string,object> PinInfo(")),
        }
        self.assertEqual(replacements["@@BEFORE_FI@@"], replacements["@@CANDIDATE_FI@@"])
        boundary = fixtures["protected-os-api-peers.cs.source"]
        for marker, value in replacements.items():
            self.assertEqual(boundary.count(marker), 1, marker)
            boundary = boundary.replace(marker, value)
        self.assertNotIn("@@", boundary)
        opening = "Add-Type -TypeDefinition @'\n"
        start = current.index(opening) + len(opening)
        whole_csharp = current[start:current.index("\n'@ -ReferencedAssemblies", start)]
        start = current.index("function Assert-NativeIdentity(")
        assertion = current[start:current.index("function Assert-Pin(", start)]
        with tempfile.TemporaryDirectory(prefix="protected-os-role-") as directory:
            directory = Path(directory)
            (directory / "decision-boundary.cs").write_bytes(boundary.encode())
            (directory / "current.complete.cs").write_bytes(whole_csharp.encode())
            (directory / "Assert-NativeIdentity.fragment.ps1").write_bytes(assertion.encode())
            (directory / "decision-controls.ps1").write_bytes(fixtures["protected-os-38-controls.ps1.source"].encode())
            launcher = directory / "routine.ps1"
            launcher.write_text(
                "$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n"
                "# Compile the complete current production C# with default runtime references.\n"
                "# Its native methods remain uncalled; the decisions use declared boundary peers.\n"
                "Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'current.complete.cs')))\n"
                ". (Join-Path $PSScriptRoot 'decision-controls.ps1')\n")
            environment = {key: value for key, value in os.environ.items() if not key.startswith("DYLD_")}
            environment.update(POWERSHELL_UPDATECHECK="Off", POWERSHELL_TELEMETRY_OPTOUT="1")
            result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(launcher)],
                                    env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
            self.assertEqual(result.stderr, b"")
            value = json.loads(result.stdout.decode("utf-8-sig"))
        self.assertEqual(value["state"], "portable-exact-body-controls-passed")
        self.assertEqual(value["count"], 38)
        self.assertEqual(len(value["results"]), 38)
        self.assertTrue(all(row["pass"] is True for row in value["results"]))
        self.assertFalse(value["nativeQualified"])
        names = {row["name"] for row in value["results"]}
        self.assertIn("causal-before-real-Identity-links2-RED", names)
        self.assertIn("causal-fixed-real-PinIdentity-powershell-links2-GREEN", names)
        self.assertIn("causal-fixed-real-PinIdentity-msiexec-links2-GREEN", names)
        self.assertIn("fixed-generic-Identity-links2-refuses", names)
        self.assertIn("generic-one-link-still-accepted", names)


if __name__ == "__main__":
    unittest.main()
