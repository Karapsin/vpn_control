from __future__ import annotations

import unittest

from agent_tools import windows_cp117_protected_journal as journal


ROOT = r"C:\ProgramData\VpnControl\cp117-recovery"
LEAVES = ("binding.json", "terminal.json")


def acl(inherited: bool):
    return {"protected": not inherited, "acl": [
        {"sid": journal.SYSTEM_SID, "rights": 2032127, "type": "Allow", "inherited": inherited, "inheritance": 0 if inherited else 3, "propagation": 0},
        {"sid": journal.ADMINISTRATORS_SID, "rights": 2032127, "type": "Allow", "inherited": inherited, "inheritance": 0 if inherited else 3, "propagation": 0},
    ]}


class ProtectedJournalTests(unittest.TestCase):
    def test_generator_uses_exclusive_same_handle_read_and_create_new_writer(self):
        source = journal.powershell(ROOT, LEAVES)
        self.assertIn("FileShare]::None", source)
        self.assertIn("FileMode]::CreateNew", source)
        self.assertIn("Flush($true)", source)
        self.assertIn("ANCESTOR_REPARSE", source)
        self.assertIn("ROOT_ACL_COUNT", source)
        self.assertIn("LEAF_ACL", source)
        self.assertIn("Get-ChildItem -LiteralPath $path", source)
        self.assertIn("LEAF_OWNER", source)
        self.assertIn("PARENT_ABSENT", source)
        self.assertNotIn("Remove-Item", source)
        self.assertNotIn("Move-Item", source)

    def test_red_acl_creator_uses_typed_sids_and_typed_enums(self):
        source = journal.powershell(ROOT, LEAVES)
        self.assertIn("[Security.Principal.SecurityIdentifier]::new($sid)", source)
        self.assertIn("[Security.AccessControl.FileSystemRights]::FullControl", source)
        self.assertIn("[Security.AccessControl.InheritanceFlags]::ContainerInherit", source)
        self.assertIn("[Security.AccessControl.PropagationFlags]::None", source)
        self.assertIn("[Security.AccessControl.AccessControlType]::Allow", source)

    def test_acl_constructor_is_read_only_and_reusable_for_native_diagnosis(self):
        source = journal.acl_construction_powershell()
        self.assertIn("[Security.Principal.SecurityIdentifier]::new($sid)", source)
        self.assertNotIn("CreateDirectory", source)
        self.assertNotIn("Set-Acl", source)

    def test_portable_census_requires_exact_creator_acl_and_allowed_leaves(self):
        receipt = {"owner": journal.SYSTEM_SID, "rootAcl": acl(False),
                   "leaves": [{"name": "binding.json", "bytes": 50, "owner": journal.SYSTEM_SID, "acl": acl(True)}]}
        journal.validate_census(receipt, LEAVES)
        with self.assertRaises(journal.ProtectedJournalError):
            journal.validate_census({**receipt, "owner": "S-1-5-21-foreign"}, LEAVES)
        bad = {**receipt, "leaves": [{"name": "other.json", "bytes": 50, "owner": journal.SYSTEM_SID, "acl": acl(True)}]}
        with self.assertRaises(journal.ProtectedJournalError):
            journal.validate_census(bad, LEAVES)

    def test_rejects_unsafe_root_or_leaf_names_before_script_generation(self):
        with self.assertRaises(journal.ProtectedJournalError):
            journal.powershell(r"C:\Users\vpncp117\x", LEAVES)
        with self.assertRaises(journal.ProtectedJournalError):
            journal.powershell(ROOT, ("../terminal.json",))

    def test_red_direct_cp117_root_is_admitted_without_shared_vpncontrol_parent(self):
        root = r"C:\ProgramData\VpnControlCp117-guest-agent-8dbecc32-6ad2-4e0b-a068-84a550fa850d"
        source = journal.powershell(root, LEAVES)
        self.assertIn(root, source)

    def test_green_direct_cp117_root_rejects_wrong_prefix_and_noncanonical_uuid(self):
        with self.assertRaises(journal.ProtectedJournalError):
            journal.powershell(r"C:\ProgramData\VpnControlCp117-other-8dbecc32-6ad2-4e0b-a068-84a550fa850d", LEAVES)
        with self.assertRaises(journal.ProtectedJournalError):
            journal.powershell(r"C:\ProgramData\VpnControlCp117-retirement-8DBECC32-6AD2-4E0B-A068-84A550FA850D", LEAVES)


if __name__ == "__main__":
    unittest.main()
