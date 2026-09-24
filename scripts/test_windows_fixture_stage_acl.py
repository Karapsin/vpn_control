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


if __name__ == "__main__":
    unittest.main()
