#!/usr/bin/env python3
"""Fast deterministic regression for Windows MSI fixture stage ACL receipts."""

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_fixture_stage_acl import (  # noqa: E402
    ADMINISTRATORS_SID,
    FULL_CONTROL,
    READ_AND_EXECUTE,
    SYSTEM_SID,
    StageAclValidationError,
    stage_acl_powershell,
    validate_stage_acl_receipt,
)


SID = "S-1-5-21-2404255130-2183793310-3766671872-1002"
STAGE = r"C:\ProgramData\VpnControlCp140\stage-ba35-35982037383"
OTHER_STAGE = r"C:\ProgramData\VpnControlCp140\other-stage"


def _qga_receipt(output: dict) -> dict:
    return {"verify": {
        "exitcode": 0,
        "exited": True,
        "out-truncated": False,
        "err-truncated": False,
        "out-data": base64.b64encode(json.dumps(output).encode()).decode(),
    }}


def _green_output(stage: str = STAGE) -> dict:
    return {
        "stage": stage,
        "protected": True,
        "acl": [
            {"sid": SYSTEM_SID, "rights": FULL_CONTROL, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
            {"sid": ADMINISTRATORS_SID, "rights": FULL_CONTROL, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
            {"sid": SID, "rights": READ_AND_EXECUTE, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
        ],
    }


class WindowsFixtureStageAclTest(unittest.TestCase):
    def test_cp138_actual_receipt_is_rejected_before_repair(self):
        # CP138's retained output: successful PowerShell with SYSTEM/Admin only;
        # it did not attest protected inheritance or the intended user SID.
        old_actual = _qga_receipt({"stage": STAGE, "files": [{"name": "base.msi"}], "acl": [
            {"id": "NT AUTHORITY\\SYSTEM", "rights": "FullControl", "type": "Allow", "inherited": False},
            {"id": "BUILTIN\\Administrators", "rights": "FullControl", "type": "Allow", "inherited": False},
        ]})
        with self.assertRaisesRegex(StageAclValidationError, "protected inheritance"):
            validate_stage_acl_receipt(old_actual, SID, STAGE)

    def test_complete_typed_acl_receipt_passes_and_any_extra_right_is_rejected(self):
        green = _green_output()
        validate_stage_acl_receipt(_qga_receipt(green), SID, STAGE)
        green["acl"].append({"sid": "S-1-1-0", "rights": READ_AND_EXECUTE, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0})
        with self.assertRaisesRegex(StageAclValidationError, "principals or rights"):
            validate_stage_acl_receipt(_qga_receipt(green), SID, STAGE)

    def test_generated_powershell_uses_typed_sids_terminating_errors_and_self_verification(self):
        command = stage_acl_powershell(STAGE, SID)
        self.assertIn("$ErrorActionPreference = 'Stop'", command)
        self.assertIn("[Security.Principal.SecurityIdentifier]::new", command)
        self.assertNotIn("FileSystemAccessRule($id", command)
        self.assertIn("AreAccessRulesProtected", command)
        self.assertIn("fixture stage ACL principal or rights differ", command)
        self.assertIn("Set-Acl -LiteralPath $stage -AclObject $acl -ErrorAction Stop", command)
        self.assertIn("stage = $stage", command)
        with self.assertRaisesRegex(ValueError, "stage directory"):
            stage_acl_powershell("C:\\", SID)

    def test_command_line_rejects_cp138_receipt_and_prints_reviewable_powershell(self):
        old_actual = _qga_receipt({"stage": STAGE, "acl": []})
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "cp138-receipt.json"
            receipt.write_text(json.dumps(old_actual), encoding="utf-8")
            rejected = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("windows_fixture_stage_acl.py")),
                 "--receipt", str(receipt), "--stage-directory", STAGE, "--recipient-sid", SID],
                text=True, capture_output=True, check=False,
            )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("protected inheritance", rejected.stderr)
        generated = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("windows_fixture_stage_acl.py")),
             "--stage-directory", STAGE, "--recipient-sid", SID],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr)
        self.assertIn("SecurityIdentifier", generated.stdout)

    def test_direct_verified_json_is_a_documented_local_validation_input(self):
        validate_stage_acl_receipt(_green_output(), SID, STAGE)

    def test_qga_receipt_requires_captured_output(self):
        receipt = {"verify": {
            "exitcode": 0,
            "exited": True,
            "out-truncated": False,
            "err-truncated": False,
            **_green_output(),
        }}
        with self.assertRaisesRegex(StageAclValidationError, "missing output"):
            validate_stage_acl_receipt(receipt, SID, STAGE)

    def test_receipt_rejects_acl_for_a_different_stage_directory(self):
        with self.assertRaisesRegex(StageAclValidationError, "requested stage directory"):
            validate_stage_acl_receipt(_qga_receipt(_green_output(OTHER_STAGE)), SID, STAGE)

    def test_qga_receipt_requires_terminal_complete_capture(self):
        green = _green_output()
        for patch in ({"exited": False}, {"out-truncated": True}, {"err-truncated": True}):
            with self.subTest(patch=patch):
                receipt = _qga_receipt(green)
                receipt["verify"].update(patch)
                with self.assertRaises(StageAclValidationError):
                    validate_stage_acl_receipt(receipt, SID, STAGE)

    def test_generator_rejects_windows_alias_components_and_checks_reparse_points(self):
        for unsafe in (
            r"C:\ProgramData\VpnControlCp138\..\stage",
            r"C:\ProgramData\VpnControlCp138\stage. ",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    stage_acl_powershell(unsafe, SID)
        command = stage_acl_powershell(STAGE, SID)
        self.assertIn("FileAttributes]::ReparsePoint", command)
        self.assertIn("fixture stage path contains a reparse point", command)
        self.assertIn("$seen", command)
        self.assertIn("fixture stage ACL is missing a required principal", command)
        self.assertIn("fixture stage ACL repeats a principal", command)
        quoted_component = stage_acl_powershell(r"C:\ProgramData\VpnControl'Cp138\stage", SID)
        self.assertIn("FromBase64String", quoted_component)
        self.assertNotIn("VpnControl'Cp138", quoted_component)



class WindowsPublisherAccessOnlyPersistenceTest(unittest.TestCase):
    """The actual CP117 Limited publisher failed Set-Acl with SeSecurityPrivilege.

    Old native evidence: decoded projection 2fe49299..., acl-stderr.private
    records PrivilegeNotHeldException at the exact setter. The routine native
    case below runs actual old/new generated scripts on isolated own files;
    a non-Limited CI account cannot attest the ordinary-user failure case.
    """
    @staticmethod
    def publisher_script(source, path):
        import ast
        module = ast.parse(source)
        function = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == "windows_acl_receipt")
        assignment = next(n for n in function.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "script" for t in n.targets))
        expression = ast.Expression(assignment.value)
        return eval(compile(expression, "actual-publisher-script-producer", "eval"), {"encoded_path": base64.b64encode(str(path).encode("utf-16le")).decode(), "action": "private"})

    def test_actual_publisher_script_producer_access_only_delta(self):
        source = Path(__file__).with_name("prepare_desktop_update_fixture.py").read_text()
        current = self.publisher_script(source, r"C:\PUBLIC\ready.json")
        self.assertIn("AccessControlSections]::Access", current)
        self.assertNotIn("Set-Acl -LiteralPath $path -AclObject $acl", current)
        self.assertIn("$acl = Get-Acl -LiteralPath $path -ErrorAction Stop", current)

    @unittest.skipUnless(__import__("os").name == "nt", "actual Windows Limited DACL persistence")
    def test_actual_old_setter_refuses_new_access_only_preserves_owner_group(self):
        import gzip
        old_source = gzip.decompress(base64.b64decode(OLD_PUBLISHER_SOURCE_GZIP)).decode()
        new_source = Path(__file__).with_name("prepare_desktop_update_fixture.py").read_text()
        probe = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"], capture_output=True, text=True, timeout=10)
        self.assertEqual(probe.returncode, 0, probe.stderr)
        if probe.stdout.strip() != "False":
            self.skipTest("actual ordinary Limited account required; administrator cannot prove SeSecurityPrivilege refusal")
        import ast, ctypes, os, platform, re, types, uuid
        def functions(source, captured):
            module = ast.parse(source)
            selected = [next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name)
                        for name in ("require", "fsync_probe_directory", "windows_acl_receipt", "require_windows_private_acl", "write_private_ready_json")]
            def capture(*args, **kwargs):
                result = subprocess.run(*args, **kwargs)
                captured.append(result)
                return result
            namespace = {"os": os, "platform": platform, "ctypes": ctypes, "re": re,
                         "uuid": uuid, "subprocess": types.SimpleNamespace(run=capture),
                         "base64": base64, "json": json, "Path": Path}
            exec(compile(ast.Module(body=selected, type_ignores=[]), "actual-native-publisher-functions", "exec"), namespace)
            return namespace
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old_calls, new_calls = [], []
            old, new = functions(old_source, old_calls), functions(new_source, new_calls)
            with self.assertRaisesRegex(ValueError, "Windows fixture ACL verification failed"):
                old["write_private_ready_json"](root / "old-ready.json", {"diagnosticOnly": True})
            self.assertIn("SeSecurityPrivilege", old_calls[-1].stderr)
            path = root / "ready.json"
            new["write_private_ready_json"](path, {"diagnosticOnly": True})
            self.assertEqual(json.loads(path.read_text()), {"diagnosticOnly": True})
            receipt = new["windows_acl_receipt"](path, private=True, establish=False)
            self.assertTrue(receipt["protected"])
            self.assertEqual({row["sid"] for row in receipt["acl"]}, {SYSTEM_SID, ADMINISTRATORS_SID, receipt["currentSid"]})
            # The actual new setter checks native owner/group before/after each
            # Access-only persistence; no SACL read or modification is requested.
            self.assertTrue(all(call.returncode == 0 for call in new_calls))

OLD_PUBLISHER_SOURCE_GZIP = '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'



class WindowsFixtureCopiedPackageReadOnlyTests(unittest.TestCase):
    def test_actual_copy_and_resource_producer_rejects_writable_preserved_bytes(self):
        import shutil
        import prepare_desktop_update_fixture as fixture
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "source" / "vpn-control-2.2.2.msi"
            original.parent.mkdir()
            original.write_bytes(b"PUBLIC_INERT_PACKAGE")
            original.chmod(0o400)
            target_root = root / "mcp-update-fixture-6d0bf26d-1708-4869-b9f3-c890d5719440" / "content"
            target = target_root / "packages" / "target" / original.name
            target.parent.mkdir(parents=True)
            shutil.copyfile(original, target)
            asset = fixture.package_asset(original, "windows", "x86_64", "2.2.2")
            manifest = {"assets": [asset], "buildNumber": fixture.version_build("2.2.2")}
            source = "a" * 64
            code = "b" * 64
            receipt = {"testOnly": True, "productionTrustChanged": False,
                       "sourceFingerprint": source, "manifest": manifest,
                       "builds": [{"sourceFingerprint": source, "codeFingerprint": code},
                                  {"sourceFingerprint": source, "codeFingerprint": code,
                                   "assets": [asset], "version": "2.2.2"}]}
            body = json.dumps(receipt).encode()
            self.assertEqual(fixture.package_asset(target, "windows", "x86_64", "2.2.2"), asset)
            with self.assertRaisesRegex(ValueError, "Fixture package must remain read-only"):
                fixture.load_resources(target_root, receipt_bytes=body)
            # Only this owned inert fixture changes; production/guest state is untouched.
            target.chmod(0o400)
            try:
                observed, resources = fixture.load_resources(target_root, receipt_bytes=body)
                self.assertEqual(observed, manifest)
                self.assertEqual(resources, {target.name: target})
                self.assertEqual(fixture.package_asset(target, "windows", "x86_64", "2.2.2"), asset)
            finally:
                original.chmod(0o600)
                target.chmod(0o600)

if __name__ == "__main__":
    unittest.main()
