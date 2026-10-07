"""Causal regressions for fixed CP117 stage deletion guards."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_tools import windows_cp117_retirement_guards as guards


CORR = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
SID = "S-1-5-21-1-2-3-1001"


def intent():
    return {"request": {"correlationId": CORR}, "bundleSha256": "a" * 64,
            "bundleSize": 7, "fileHashes": {"packages/target/update.msi": "b" * 64}}


def acl(path):
    return {"stage": path, "protected": True, "acl": [
        {"sid": "S-1-5-18", "rights": 0x1F01FF, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
        {"sid": "S-1-5-32-544", "rights": 0x1F01FF, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
        {"sid": SID, "rights": 0x1200A9, "type": "Allow", "inherited": False, "inheritance": 3, "propagation": 0},
    ]}


class RetirementGuardTests(unittest.TestCase):
    def test_red_owner_only_admission_rejects_non_creator_owner_even_with_exact_acl(self):
        root = guards.stage_root(CORR)
        receipt = {"owner": SID, "rootAcl": acl(root), "contentAcl": acl(root + r"\content"),
                   "files": ["packages/target/update.msi"]}
        with self.assertRaisesRegex(guards.RetirementGuardError, "trusted creator"):
            guards.validate_deletion_census(receipt, intent(), CORR, SID)

    def test_green_creator_owner_and_exact_acl_admit_saved_manifest(self):
        root = guards.stage_root(CORR)
        receipt = {"owner": "S-1-5-18", "rootAcl": acl(root), "contentAcl": acl(root + r"\content"),
                   "files": ["packages/target/update.msi"]}
        guards.validate_deletion_census(receipt, intent(), CORR, SID)

    def test_green_administrators_creator_owner_admits_exact_acl_and_manifest(self):
        # Native Windows evidence shows a SYSTEM actor can create a directory
        # whose token default owner is Administrators.  Actor SID is not owner.
        root = guards.stage_root(CORR)
        receipt = {"owner": "S-1-5-32-544", "rootAcl": acl(root), "contentAcl": acl(root + r"\content"),
                   "files": ["packages/target/update.msi"]}
        guards.validate_deletion_census(receipt, intent(), CORR, SID)

    def test_census_script_rechecks_exact_tree_hash_manifest_and_reparses(self):
        script = guards.deletion_census_powershell(intent(), CORR, SID)
        self.assertIn("ReparsePoint", script)
        self.assertIn("bundle.zip", script)
        self.assertIn("result.json", script)
        self.assertIn("server-state", script)
        self.assertIn("probe-events", script)
        self.assertIn("STATE_TREE", script)
        self.assertIn("PROBE_EVENTS", script)
        self.assertIn("AssertAcl", script)
        self.assertIn("1179817", script)  # 0x1200A9 ReadAndExecute
        self.assertIn("S-1-5-32-544", script)
        self.assertIn("DIRECTORY_TREE", script)
        self.assertIn("packages", script)
        self.assertIn("FILE_HASH", script)
        self.assertIn("S-1-5-18", script)

    def test_private_journal_never_follows_links_or_replaces_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal" / "intent.json"
            guards.secure_write_create(path, {"stage": CORR})
            self.assertEqual({"stage": CORR}, guards.secure_read(path))
            with self.assertRaises(FileExistsError):
                guards.secure_write_create(path, {"stage": CORR})

    def test_remaining_result_only_census_uses_exclusive_read_and_exact_root_tree(self):
        script = guards.remaining_result_census_powershell(intent(), CORR, SID)
        self.assertIn("FileShare]::None", script)
        self.assertIn("result.json", script)
        self.assertIn("TREE", script)
        self.assertIn("ReparsePoint", script)

    def test_remaining_result_lock_diagnostic_is_restart_manager_read_only_and_redacted(self):
        script = guards.remaining_result_lock_diagnostic_powershell(CORR)
        self.assertIn("RmStartSession", script)
        self.assertIn("RmRegisterResources", script)
        self.assertIn("RmGetList", script)
        self.assertIn("RmEndSession", script)
        self.assertNotIn("RmShutdown", script)
        self.assertNotIn("RmRestart", script)
        self.assertIn("low-hresult-32", script)
        self.assertIn("low-hresult-33", script)
        self.assertIn("qemuGaExactLocalSystem", script)
        self.assertIn("FileShare]::None", script)
        self.assertIn("$lockPid", script)
        self.assertNotIn("$pid=", script)
        self.assertIn("Win32_Process", script)
        self.assertIn("Win32_Service", script)
        self.assertIn("[Math]::Min", script)
        self.assertIn("$lockException", script)
        self.assertNotIn("$error=", script.lower())
        self.assertIn("$processes.Count -eq 1", script)
        self.assertIn("NT AUTHORITY\\SYSTEM", script)


if __name__ == "__main__":
    unittest.main()
