"""Causal guards for the fixed CP117 guest-agent recovery reservation."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_cp117_guest_agent_recovery as recovery


TREE = {"state": "remaining-result-only"}
LOCK = {"cause": "low-hresult-32", "lockingProcess": "qemu-ga", "count": 1, "qemuGaExactLocalSystem": True}
SERVICE = {"name": "qemu-ga", "state": "Running", "startName": "LocalSystem", "pid": 5,
           "startTicks": 9, "path": r"C:\Program Files\qemu-ga.exe"}


class GuestAgentRecoveryTests(unittest.TestCase):
    def test_reserved_journal_diagnostic_reads_existing_attempt_without_replay(self):
        script = recovery._journal_diagnostic_script(True)
        for leaf in ('binding.json','child.json','terminal.json'):
            self.assertIn(leaf, script)
        self.assertIn('missing-child', script)
        self.assertNotIn('Start-ScheduledTask', script)
        self.assertNotIn('Initialize-SecureJournal', script.split('\ntry{',1)[1])
        self.assertNotIn("throw 'REPLAY'", script)

    def test_task_checks_service_account_and_elevation_before_mutation(self):
        script=recovery._restart_task_body(SERVICE,'0'*64)
        prefix=script.split('Stop-Service',1)[0]
        self.assertIn("$task.Principal.LogonType.ToString() -cne 'ServiceAccount'",prefix)
        self.assertIn("$task.Principal.RunLevel.ToString() -cne 'Highest'",prefix)

    def test_protected_journal_validator_is_read_only_and_exact(self):
        script = recovery.protected_journal_validator_powershell()
        self.assertIn("SetAccessRuleProtection($true,$false)", script)
        self.assertIn("S-1-5-18", script)
        self.assertIn("S-1-5-32-544", script)
        self.assertIn("ReparsePoint", script)
        self.assertIn("2032127", script)
    def test_native_status_rejects_terminal_for_different_task_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            intent={"recoveryCorrelationId":recovery._RECOVERY,"service":SERVICE}
            recovery.guards.secure_write_create(root/recovery._DIR/"intent.json",intent)
            observed={"binding":recovery._digest(intent),"terminalBinding":recovery._digest(intent),
                "outcome":"restarted","taskSystem":True,"actionSha256":"0"*64}
            with patch.object(recovery.base,"_descriptor",return_value=(object(),object(),(None,"/qga",1,2,"SID"))), \
                 patch.object(recovery,"_run_ps",return_value=observed):
                result=recovery.status(root,{})
            self.assertEqual("unknown",result["state"])
            self.assertFalse((root/recovery._DIR/"terminal.json").exists())

    def test_native_status_requires_fresh_restarted_service_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            intent={"recoveryCorrelationId":recovery._RECOVERY,"service":SERVICE}
            recovery.guards.secure_write_create(root/recovery._DIR/"intent.json",intent)
            action=recovery._action_sha(SERVICE,recovery._digest(intent))
            recovery.guards.secure_write_create(root/recovery._DIR/"action.json",{"intentSha256":recovery._digest(intent),"actionSha256":action})
            observed={"binding":recovery._digest(intent),"terminalBinding":recovery._digest(intent),
                "outcome":"restarted","taskSystem":True,"actionSha256":action}
            with patch.object(recovery.base,"_descriptor",return_value=(object(),object(),(None,"/qga",1,2,"SID"))), \
                 patch.object(recovery,"_run_ps",return_value=observed):
                self.assertEqual("unknown",recovery.status(root,{})["state"])
            self.assertFalse((root/recovery._DIR/"terminal.json").exists())

    def test_compressed_submission_fits_windows_command_bound(self):
        intent={"recoveryCorrelationId":recovery._RECOVERY,"service":SERVICE}
        script=recovery._restart_task_script(SERVICE,recovery._digest(intent))
        self.assertLessEqual(len(recovery._encode_ps(script)),30000)

    def test_complete_fresh_terminal_is_accepted_and_each_identity_change_rejected(self):
        generation={"socketPath":"/qga","qemuPid":1,"startTicks":2}
        after={**SERVICE,"pid":6,"startTicks":10}
        for change in ({}, {"actionSha256":"0"*64}, {"taskSystem":False}, {"taskState":"Running"},
                       {"service":SERVICE}, {"service":{**after,"path":"different"}},
                       {"service":{**after,"startName":"user"}}, {"childPid":False}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);intent={"recoveryCorrelationId":recovery._RECOVERY,"service":SERVICE,"guestGeneration":generation}
                digest=recovery._digest(intent);action=recovery._action_sha(SERVICE,digest)
                recovery.guards.secure_write_create(root/recovery._DIR/"intent.json",intent)
                recovery.guards.secure_write_create(root/recovery._DIR/"action.json",{"intentSha256":digest,"actionSha256":action})
                observed={"binding":digest,"terminalBinding":digest,"outcome":"restarted","taskSystem":True,
                          "taskState":"Ready","actionSha256":action,"service":after,
                          "recoveryCorrelationId":recovery._RECOVERY,"childPid":20,"childStartTicks":99,**change}
                with patch.object(recovery.base,"_descriptor",return_value=(object(),object(),(None,"/qga",1,2,"SID"))), \
                     patch.object(recovery,"_run_ps",return_value=observed):
                    self.assertEqual("unknown" if change else "terminal",recovery.status(root,{})["state"])
                self.assertEqual(not bool(change),(root/recovery._DIR/"terminal.json").exists())

    def test_one_shot_reservation_never_replays_lost_submit(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(recovery, "_ready", return_value=True):
            root = Path(temporary)
            self.assertEqual("unknown", recovery.start(root, TREE, LOCK, LOCK, SERVICE, lambda _: {})["state"])
            self.assertEqual("unknown", recovery.start(root, TREE, LOCK, LOCK, SERVICE, lambda _: self.fail("replay"))["state"])

    def test_changed_service_identity_blocks_terminal_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(recovery, "_ready", return_value=True):
            changed = {**SERVICE, "startTicks": 10}
            # The durable binding records the observed identity; a terminal for
            # a replacement process cannot be accepted.
            recovery.start(Path(temporary), TREE, LOCK, LOCK, SERVICE, lambda _: {"state": "submitted"})
            with self.assertRaises(recovery.WindowsCp117GuestAgentRecoveryError):
                recovery.record_terminal(Path(temporary), "wrong", changed, "restarted")

    def test_terminal_is_durable_and_distinguishes_submitted_from_terminal(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(recovery, "_ready", return_value=True):
            root = Path(temporary)
            recovery.start(root, TREE, LOCK, LOCK, SERVICE, lambda _: {"state": "submitted"})
            intent = recovery.guards.secure_read(root / recovery._DIR / "intent.json")
            recovery.record_terminal(root, recovery._digest(intent), SERVICE, "restarted")
            self.assertEqual("terminal", recovery.status(root)["state"])


if __name__ == "__main__":
    unittest.main()
