"""Fixed adoption route must not turn arbitrary helper data into authority."""
import unittest
from unittest import mock
from agent_tools import mcp_server as server, ssh_recovery_adoption as helper


class AdoptionRouteTests(unittest.TestCase):
    def test_exact_dispatch(self):
        receipt = {"state": "ready", "nextAction": "configured-probe", "replayAllowed": False}
        with mock.patch.object(helper, "adopt", return_value=receipt) as call:
            result = server._ssh_workflow_impl("connection-adopt", "archlinux", 30)
        call.assert_called_once_with(server.REPO_ROOT, "archlinux", 30)
        self.assertTrue(result["ok"])
        self.assertIs(result["replayAllowed"], False)

    def test_invalid_input_never_dispatches(self):
        for fields in ({"host": None}, {"host": []}, {"timeout_seconds": True},
                       {"timeout_seconds": 61}, {"identity": {}}, {"transfer": {}}, {"device": "api35"}):
            arguments = {"host": "archlinux", "timeout_seconds": 30, **fields}
            with self.subTest(fields=fields), mock.patch.object(helper, "adopt") as call:
                self.assertFalse(server._ssh_workflow_impl("connection-adopt", **arguments)["ok"])
                call.assert_not_called()

    def test_untrusted_receipt_cannot_publish_ready(self):
        receipts = [None, {"state": "ready"},
                    {"state": "ready", "nextAction": "configured-probe", "replayAllowed": 0},
                    {"state": "ready", "nextAction": "retry", "replayAllowed": False},
                    {"state": "ready", "nextAction": "configured-probe", "replayAllowed": False, "raw": "secret"}]
        for receipt in receipts:
            with self.subTest(receipt=receipt), mock.patch.object(helper, "adopt", return_value=receipt):
                result = server._ssh_workflow_impl("connection-adopt", "archlinux", 30)
                self.assertEqual("unknown", result["state"])
                self.assertNotIn("raw", result)

    def test_helper_exception_is_finite_unknown(self):
        with mock.patch.object(helper, "adopt", side_effect=ValueError("private detail")):
            result = server._ssh_workflow_impl("connection-adopt", "archlinux", 30)
        self.assertEqual("unknown", result["state"])
        self.assertNotIn("private detail", str(result))

    def test_cli_exposes_same_fixed_route(self):
        with mock.patch.object(server, "ssh_workflow", return_value={"ok": True}) as call:
            self.assertEqual(0, server.main(["ssh-workflow", "connection-adopt", "--host", "archlinux", "--timeout-seconds", "30"]))
        self.assertEqual("connection-adopt", call.call_args.args[0])

    def test_guidance_uses_fixed_followup_not_helper_action(self):
        from agent_tools.native_next_action import next_action
        cases = (("connection-recover", "recovery_master_ready", "connection-adopt"),
                 ("connection-adopt", "ready", "probe"))
        for action, state, followup in cases:
            receipt = {"ok": True, "state": state, "host": "archlinux", "replayAllowed": False,
                       "nextAction": {"action": "arbitrary"}}
            guidance = next_action("ssh_workflow", action, receipt)
            self.assertEqual(followup, guidance["action"]["action"])
            self.assertIs(guidance["replayAllowed"], False)
            for changes in ({"host": []}, {"ok": False}, {"state": "unknown"}):
                rejected = next_action("ssh_workflow", action, {**receipt, **changes})
                self.assertNotIn("action", rejected)


if __name__ == "__main__":
    unittest.main()
