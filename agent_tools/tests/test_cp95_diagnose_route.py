"""Bounded CP95 original-attempt diagnostic MCP boundary."""
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import windows_cp117_cp95_task_retire as helper

class CP95DiagnoseRouteTests(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        p.start(); self.addCleanup(p.stop)
    def receipt(self, **changes):
        return {"state": "diagnosed", "phase": "archive",
                "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86",
                "replayAllowed": False, "nativeActionAllowed": False,
                "productAction": False, **changes}
    def test_exact_fixed_dispatch(self):
        with mock.patch.object(helper, "workflow", return_value=self.receipt()) as call:
            r = server._vm_workflow_impl("windows-cp117-cp95-task-retire-diagnose", {})
        self.assertTrue(r["ok"])
        call.assert_called_once_with(server.REPO_ROOT, "diagnose", {})
    def test_bounded_remote_file_phase_is_observation_only(self):
        with mock.patch.object(helper, "workflow", return_value=self.receipt(phase="remote-file-access")):
            r = server._vm_workflow_impl("windows-cp117-cp95-task-retire-diagnose", {})
        self.assertTrue(r["ok"])
        self.assertFalse(r["nativeActionAllowed"])
    def test_foreign_inputs_never_dispatch(self):
        for payload in ({"correlationId": "foreign"}, {"command": "retry"}, [], None):
            with mock.patch.object(helper, "workflow") as call:
                r = server._vm_workflow_impl("windows-cp117-cp95-task-retire-diagnose", payload)
            self.assertFalse(r["ok"]); call.assert_not_called()
    def test_untrusted_receipts_fail_closed(self):
        cases = [self.receipt(phase=[]), self.receipt(phase="retry"),
                 self.receipt(retirementCorrelationId="foreign"),
                 self.receipt(replayAllowed=True), self.receipt(productAction=0),
                 self.receipt(extra="raw"), self.receipt(state="complete"), None]
        for value in cases:
            with self.subTest(value=value), mock.patch.object(helper, "workflow", return_value=value):
                r = server._vm_workflow_impl("windows-cp117-cp95-task-retire-diagnose", {})
            self.assertFalse(r["ok"])
            self.assertEqual("unknown", r["state"])
            self.assertFalse(r["nativeActionAllowed"])

    def test_finish_exact_fixed_binding_and_no_replay_flags(self):
        receipt = self.receipt(state="retired",phase="complete")
        with mock.patch.object(helper,"workflow",return_value=receipt) as call:
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish",{})
        self.assertTrue(r["ok"]);self.assertFalse(r["replayAllowed"])
        call.assert_called_once_with(server.REPO_ROOT,"finish",{})
        for value in (self.receipt(state=[]),self.receipt(state="retired",phase="intent"), self.receipt(state="retired",phase="complete",retirementCorrelationId="foreign")):
            with mock.patch.object(helper,"workflow",return_value=value):
                r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish",{})
            self.assertFalse(r["ok"]);self.assertEqual("unknown",r["state"])
        with mock.patch.object(helper,"workflow") as call:
            self.assertFalse(server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish",{"command":"retry"})["ok"])
        call.assert_not_called()

    def test_finish_diagnose_cannot_invoke_finish_writer(self):
        with mock.patch.object(helper,"finish_diagnose",return_value=self.receipt(phase="binding")) as observer, mock.patch.object(helper,"workflow") as writer:
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish-diagnose",{})
        self.assertTrue(r["ok"]); self.assertFalse(r["nativeActionAllowed"])
        observer.assert_called_once_with(server.REPO_ROOT,{})
        writer.assert_not_called()
        with mock.patch.object(helper,"finish_diagnose",return_value=self.receipt(phase="remote-file-access")):
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish-diagnose",{})
        self.assertFalse(r["ok"]); self.assertEqual("unknown",r["state"])

    def test_finish_diagnose_bounded_task_positions(self):
        for phase in ("task-query", "task-present-1", "task-present-5"):
            with mock.patch.object(helper,"finish_diagnose",return_value=self.receipt(phase=phase)):
                r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish-diagnose",{})
            self.assertTrue(r["ok"]);self.assertFalse(r["nativeActionAllowed"])
        with mock.patch.object(helper,"finish_diagnose",return_value=self.receipt(phase="task-present-6")):
            self.assertFalse(server._vm_workflow_impl("windows-cp117-cp95-task-retire-finish-diagnose",{})["ok"])

    def test_tail_start_cannot_replay_parent_workflow(self):
        with mock.patch.object(helper,"tail_start",return_value=helper._tail_result("retired","complete")) as child, mock.patch.object(helper,"workflow") as parent:
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-start",{})
        self.assertTrue(r["ok"]);child.assert_called_once_with(server.REPO_ROOT,{})
        parent.assert_not_called()
        with mock.patch.object(helper,"tail_start") as child:
            self.assertFalse(server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-start",{"command":"retry"})["ok"])
        child.assert_not_called()

    def test_tail_status_actual_helper_shape_and_wrong_child_binding(self):
        receipt=helper._tail_result("retired","complete")
        with mock.patch.object(helper,"tail_status",return_value=receipt) as child, mock.patch.object(helper,"workflow") as parent:
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-status",{})
        self.assertTrue(r["ok"]);self.assertEqual(helper._TAIL,r["tailCorrelationId"])
        child.assert_called_once_with(server.REPO_ROOT,{});parent.assert_not_called()
        with mock.patch.object(helper,"tail_status",return_value={**receipt,"tailCorrelationId":"foreign"}):
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-status",{})
        self.assertFalse(r["ok"]);self.assertEqual(helper._TAIL,r["tailCorrelationId"])

    def test_tail_diagnose_actual_helper_shape_no_parent_replay(self):
        receipt=helper._tail_result("diagnosed","child-intent-absent")
        with mock.patch.object(helper,"tail_diagnose",return_value=receipt) as child, mock.patch.object(helper,"workflow") as parent:
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-diagnose",{})
        self.assertTrue(r["ok"]);self.assertFalse(r["nativeActionAllowed"]);self.assertEqual(helper._TAIL,r["tailCorrelationId"])
        child.assert_called_once_with(server.REPO_ROOT,{});parent.assert_not_called()
        for changes in ({"tailCorrelationId":"foreign"},{"phase":"task-present-5"}):
            with mock.patch.object(helper,"tail_diagnose",return_value={**receipt,**changes}):
                self.assertFalse(server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-diagnose",{})["ok"])

    def test_old_tail_closure_exact_no_parent_replay(self):
        receipt=helper._tail_result("closed","tail-closure-complete")
        with mock.patch.object(helper,"tail_close_pre_effect",return_value=receipt) as close, mock.patch.object(helper,"workflow") as parent:
            r=server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-close-pre-effect",{})
        self.assertTrue(r["ok"]);close.assert_called_once_with(server.REPO_ROOT,{});parent.assert_not_called()
        self.assertFalse(r["nativeActionAllowed"])
        for bad in ({**receipt,"tailCorrelationId":"foreign"},{**receipt,"phase":"tail-closure-proof"}):
            with mock.patch.object(helper,"tail_close_pre_effect",return_value=bad):
                self.assertFalse(server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-close-pre-effect",{})["ok"])
        with mock.patch.object(helper,"tail_start",return_value=receipt):
            self.assertFalse(server._vm_workflow_impl("windows-cp117-cp95-task-retire-tail-start",{})["ok"])

    def test_successor_actual_shape_dispatch_and_exclusive_binding(self):
        for suffix, method in (("start","successor_start"),("status","successor_status")):
            action="windows-cp117-cp95-task-retire-successor-"+suffix
            receipt=helper._successor_result("retired","complete")
            with mock.patch.object(helper,method,return_value=receipt) as child, mock.patch.object(helper,"workflow") as parent, mock.patch.object(helper,"tail_start") as old:
                r=server._vm_workflow_impl(action,{})
            self.assertTrue(r["ok"]);self.assertEqual(helper._SUCCESSOR,r["tailCorrelationId"])
            child.assert_called_once_with(server.REPO_ROOT,{});parent.assert_not_called();old.assert_not_called()
            for value in ({**receipt,"tailCorrelationId":helper._TAIL},{**receipt,"raw":"private"},{**receipt,"state":"closed"},{**receipt,"productAction":True},{**receipt,"phase":[]}):
                with mock.patch.object(helper,method,return_value=value):
                    r=server._vm_workflow_impl(action,{})
                self.assertFalse(r["ok"]);self.assertEqual("unknown",r["state"])
                self.assertEqual(helper._SUCCESSOR,r["tailCorrelationId"])
                self.assertNotIn("raw",r)
            for value in (None,[],{"command":"retry"}):
                with mock.patch.object(helper,method) as child:
                    self.assertFalse(server._vm_workflow_impl(action,value)["ok"])
                child.assert_not_called()

    def test_successor_diagnosis_cannot_dispatch_or_admit(self):
        action="windows-cp117-cp95-task-retire-successor-admission-diagnose"
        receipt=helper._successor_result("diagnosed","closure-keyerror")
        with mock.patch.object(helper,"successor_admission_diagnose",return_value=receipt) as observer, mock.patch.object(helper,"successor_start") as writer:
            r=server._vm_workflow_impl(action,{})
        self.assertTrue(r["ok"]);self.assertFalse(r["nativeActionAllowed"])
        observer.assert_called_once_with(server.REPO_ROOT,{});writer.assert_not_called()
        for changes in ({"phase":[]},{"phase":"raw-secret"},{"state":"retired"},{"tailCorrelationId":helper._TAIL},{"stderr":"secret"},{"replayAllowed":True}):
            with mock.patch.object(helper,"successor_admission_diagnose",return_value={**receipt,**changes}):
                r=server._vm_workflow_impl(action,{})
            self.assertFalse(r["ok"]);self.assertEqual("unknown",r["state"]);self.assertNotIn("stderr",r)
        with mock.patch.object(helper,"successor_admission_diagnose") as observer:
            self.assertFalse(server._vm_workflow_impl(action,{"command":"retry"})["ok"])
        observer.assert_not_called()
