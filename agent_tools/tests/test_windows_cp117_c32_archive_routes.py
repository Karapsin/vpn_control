"""Fixed historical archive routes keep private evidence out of MCP output."""
import unittest
import sys
from unittest import mock
from agent_tools import mcp_server as server

class ArchiveRouteTests(unittest.TestCase):
    def test_source_closure_and_e848_retire_fixed_routes(self):
        flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        cases = [("windows-cp117-source-pre-effect-status", "windows_cp117_source_pre_effect_close", {"state": "observed", "phase": "verified-absence", "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", **flags}),
                 ("windows-cp117-source-pre-effect-close", "windows_cp117_source_pre_effect_close", {"state": "closed", "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", "closureReceiptSha256": "a" * 64, **flags})]
        cases += [("windows-cp117-e848-http-task-retire-" + action, "windows_cp117_e848_http_task_retire", {"state": "retired", "phase": "complete", "retirementCorrelationId": "477365c8-3c78-4d5c-83c9-2f6de2bd5997", **flags}) for action in ("preflight", "start", "status")]
        for action, name, good in cases:
            self.assertEqual("agent_tools." + name, server._agent_module(name).__name__)
            for extra, expected in (({}, True), ({"privatePath": "secret"}, False), ({"nativeActionAllowed": True}, False)):
                module = mock.Mock(); module.workflow.return_value = {**good, **extra}
                module._GUEST_CENSUS_PHASES = {"guest-qga-status-rpc"}
                module._PHASES = {"complete"}; module._DIAGNOSTIC_PHASES = set()
                with mock.patch.object(server, "_agent_module", return_value=module):
                    result = server._vm_workflow_impl(action, {})
                self.assertEqual(expected, result["ok"]); self.assertNotIn("privatePath", result)
            with mock.patch.object(server, "_agent_module") as loader:
                self.assertFalse(server._vm_workflow_impl(action, {"path": "foreign"})["ok"])
            loader.assert_not_called()

    def test_cp95_retirement_fixed_routes_and_real_inventory(self):
        self.assertEqual("agent_tools.windows_cp117_cp95_task_retire", server._agent_module("windows_cp117_cp95_task_retire").__name__)
        good = {"state": "retired", "phase": "complete", "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        for action in ("preflight", "start", "status"):
            for extra, expected in (({}, True), ({"path": "private"}, False), ({"nativeActionAllowed": True}, False), ({"retirementCorrelationId": "foreign"}, False), ({"phase": "dispatch"}, False)):
                module = mock.Mock(); module.workflow.return_value = {**good, **extra}
                module._PHASES = {"complete", "proof", "dispatch"}; module._DIAGNOSTIC_PHASES = set()
                with mock.patch.object(server, "_agent_module", return_value=module):
                    result = server._vm_workflow_impl("windows-cp117-cp95-task-retire-" + action, {})
                self.assertEqual(expected, result["ok"])
                self.assertNotIn("path", result)
            with mock.patch.object(server, "_agent_module") as loader:
                result = server._vm_workflow_impl("windows-cp117-cp95-task-retire-" + action, {"task": "foreign"})
            loader.assert_not_called(); self.assertFalse(result["ok"])

    def test_retained_task_adapters_load_through_real_fixed_inventory(self):
        for name in ("windows_cp117_cp95_retained_tasks", "windows_cp117_e848_http_task"):
            self.assertEqual("agent_tools."+name,server._agent_module(name).__name__)

    def test_cp95_retained_tasks_route_requires_all_fixed_terminal_profiles(self):
        flags={"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
        profiles=[{"profile":name,"state":"terminal","result":"succeeded","correlatedProcess":"absent"} for name in
                  ("acquire-194eb94d","acquire-26ced2bf","acquire-7b721c91","acquire-f4930053","python-f4930053")]
        good={"state":"ready","profiles":profiles,"activeInstallerCount":0,"opaquePowerShellCount":0,**flags}
        for change,expected in (({},True),({"privatePath":"secret"},False),({"activeInstallerCount":1},False),({"profiles":profiles[:-1]},False)):
            module=mock.Mock();module.status.return_value={**good,**change}
            with mock.patch.object(server,"_agent_module",return_value=module):
                result=server._vm_workflow_impl("windows-cp117-cp95-retained-tasks",{})
            self.assertEqual(expected,result["ok"])
            self.assertNotIn("privatePath",result)

    def test_e848_retained_http_task_route_is_fixed_and_nonmutating(self):
        flags={"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
        module=mock.Mock();module.observe.return_value={"state":"ready","phase":"verified","proof":"terminal-success",**flags}
        with mock.patch.object(server,"_agent_module",return_value=module):
            result=server._vm_workflow_impl("windows-cp117-e848-http-task",{})
        self.assertTrue(result["ok"])
        for extra in ({"privatePath":"secret"},{"proof":"unverified"},{"nativeActionAllowed":True}):
            module.observe.return_value={"state":"ready","phase":"verified","proof":"terminal-success",**flags,**extra}
            with mock.patch.object(server,"_agent_module",return_value=module):
                result=server._vm_workflow_impl("windows-cp117-e848-http-task",{})
            self.assertFalse(result["ok"])
            self.assertNotIn("privatePath",result)
        with mock.patch.object(server,"_agent_module") as loader:
            result=server._vm_workflow_impl("windows-cp117-e848-http-task",{"correlationId":"arbitrary"})
        loader.assert_not_called()
        self.assertFalse(result["ok"])

    def test_historical_archive_route_requires_complete_finite_proof(self):
        flags={"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
        for state,phases,extra,expected in (
            ("ready",{"transfer-recovery":"archived","unknown-closure":"archived"},{},True),
            ("ready",{"transfer-recovery":"archived","unknown-closure":"unknown"},{},False),
            ("ready",{"transfer-recovery":"archived","unknown-closure":"archived"},{"path":"private"},False)):
            module=mock.Mock();module.observe.return_value={"state":state,"phases":phases,**flags,**extra}
            with mock.patch.object(server,"_agent_module",return_value=module):
                result=server._vm_workflow_impl("windows-cp117-historical-base-archives",{})
            self.assertEqual(expected,result["ok"])
            self.assertNotIn("path",result)

    def test_historical_archive_output_phase_remains_visible_without_authority(self):
        module=mock.Mock();module.observe.return_value={"state":"blocked","phases":{"transfer-recovery":"remote-output-stderr-progress","unknown-closure":"remote-parser"},"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
        with mock.patch.object(server,"_agent_module",return_value=module):
            result=server._vm_workflow_impl("windows-cp117-historical-base-archives",{})
        self.assertEqual(module.observe.return_value["phases"],result["phases"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_host_archive_routes_preserve_uncertainty_and_private_fields(self):
        for action in ("start", "status"):
            for state in ("archived", "blocked", "not-started", "unknown"):
                module = mock.Mock()
                getattr(module, action).return_value = {"state": state, "replayAllowed": False,
                    "nativeActionAllowed": False, "productAction": False}
                with mock.patch.object(server, "_agent_module", return_value=module):
                    result = server._vm_workflow_impl("windows-cp117-c32-host-archive-" + action, {})
                self.assertEqual(state == "archived", result["ok"])
                self.assertFalse(result["replayAllowed"])
            with mock.patch.object(server, "_agent_module") as loader:
                result = server._vm_workflow_impl("windows-cp117-c32-host-archive-" + action, {"path": "arbitrary"})
            self.assertFalse(result["ok"])
            loader.assert_not_called()

    def test_inert_archive_self_test_projects_only_exact_cases(self):
        flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False, "componentOnly": True}
        for cases, extra, expected in (({"exclusive-rename": "passed", "destination-race": "passed"}, {}, True),
                                      ({"exclusive-rename": "passed", "destination-race": "failed"}, {}, False),
                                      ({"exclusive-rename": "passed", "destination-race": "passed"}, {"path": "private"}, False)):
            module = mock.Mock()
            module.self_test.return_value = {"state": "passed", "cases": cases, **flags, **extra}
            with mock.patch.object(server, "_agent_module", return_value=module):
                result = server._vm_workflow_impl("windows-cp117-c32-host-archive-self-test", {})
            self.assertEqual(expected, result["ok"])
            self.assertNotIn("path", result)

    def test_task_diagnostics_remain_finite_and_visible(self):
        for guard in ("TASK_COUNT", "TASK_STATE", "TASK_ACTION_COUNT", "TASK_EXEC", "TASK_TRIGGER_COUNT", "TASK_TRIGGER_NULL"):
            module = mock.Mock()
            module.preflight.return_value = {"state": "blocked", "phase": "absence",
                "retainedGuard": guard, "retainedPhase": "task",
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            with mock.patch.object(server, "_agent_module", return_value=module):
                result = server._vm_workflow_impl("windows-cp117-c32-archive-preflight",
                    {"leaseId": "67eeeedb-a618-42d5-8e31-821650d16302"})
            self.assertEqual("blocked", result["state"])
            self.assertEqual(guard, result["retainedGuard"])
            self.assertFalse(result["nativeActionAllowed"])

    def test_diagnostic_is_read_only_and_rejects_private_output(self):
        for extra in ({}, {"privatePath": "secret"}):
            module = mock.Mock()
            module.diagnose.return_value = {"state": "observed", "phase": "local-ready",
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False, **extra}
            with mock.patch.object(server, "_agent_module", return_value=module):
                result = server._vm_workflow_impl("windows-cp117-c32-archive-diagnose",
                    {"leaseId": "67eeeedb-a618-42d5-8e31-821650d16302"})
            self.assertEqual(not bool(extra), result["ok"])
            self.assertNotIn("privatePath", result)
            self.assertFalse(result["replayAllowed"])

    def test_inputs_rejected_before_module(self):
        with mock.patch.object(server, "_agent_module") as loader:
            result = server._vm_workflow_impl("windows-cp117-c32-archive-diagnose", {"command": "anything"})
        self.assertFalse(result["ok"])
        loader.assert_not_called()

    def test_result_encoding_diagnostics_are_visible(self):
        for guard in ("RESULT_UTF8_BOM", "RESULT_UTF16_LE", "RESULT_UTF16_BE"):
            module = mock.Mock()
            module.preflight.return_value = {"state": "blocked", "phase": "absence",
                "retainedGuard": guard, "retainedPhase": "result",
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            with mock.patch.object(server, "_agent_module", return_value=module):
                result = server._vm_workflow_impl("windows-cp117-c32-archive-preflight",
                    {"leaseId": "67eeeedb-a618-42d5-8e31-821650d16302"})
            self.assertEqual(guard, result["retainedGuard"])
            self.assertEqual("blocked", result["state"])

class StrictRetirementIntegrationTests(unittest.TestCase):
    flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}

    def test_c32_retained_task_retire_routes_are_fixed_and_redact_private_fields(self):
        module_name = "windows_cp117_c32_retained_task_retire"
        self.assertEqual("agent_tools." + module_name, server._agent_module(module_name).__name__)
        retirement = "d8917ee1-667f-4ee6-9af7-b8d33f3e6fb9"
        task = "VpnControlMcpBase-c32cb108-4d48-407e-9153-40774559ba50"
        for action, good in (
            ("preflight", {"state": "ready", "retirementCorrelationId": retirement, "task": task, **self.flags}),
            ("start", {"state": "terminal", "retirementCorrelationId": retirement, "task": task, **self.flags}),
            ("status", {"state": "terminal", "retirementCorrelationId": retirement, "task": task, **self.flags}),
        ):
            for extra, expected in (({}, True), ({"privatePath": "secret"}, False),
                                    ({"retirementCorrelationId": "foreign"}, False),
                                    ({"nativeActionAllowed": True}, False)):
                module = mock.Mock(); module.workflow.return_value = {**good, **extra}
                with mock.patch.object(server, "_agent_module", return_value=module):
                    result = server._vm_workflow_impl("windows-cp117-c32-retained-task-retire-" + action, {})
                self.assertEqual(expected, result["ok"])
                self.assertNotIn("privatePath", result)
            with mock.patch.object(server, "_agent_module") as loader:
                result = server._vm_workflow_impl("windows-cp117-c32-retained-task-retire-" + action,
                                                  {"correlationId": "foreign"})
            loader.assert_not_called()
            self.assertFalse(result["ok"])

    def test_source67_diagnostic_requires_exact_finite_guest_phase(self):
        flags = self.flags
        correlation = "67eeeedb-a618-42d5-8e31-821650d16302"
        good = {"state": "observed", "phase": "guest-census", "guestCensusPhase": "observed",
                "correlationId": correlation, **flags}
        for extra, expected in (({}, True), ({"guestCensusPhase": "private-data"}, False),
                                ({"privatePayload": "secret"}, False), ({"nativeActionAllowed": True}, False)):
            module = mock.Mock(); module.workflow.return_value = {**good, **extra}
            module._GUEST_CENSUS_PHASES = {"guest-qga-status-rpc"}
            with mock.patch.object(server, "_agent_module", return_value=module):
                result = server._vm_workflow_impl("windows-cp117-source-pre-effect-diagnose", {})
            self.assertEqual(expected, result["ok"])
            self.assertNotIn("privatePayload", result)
        with mock.patch.object(server, "_agent_module") as loader:
            result = server._vm_workflow_impl("windows-cp117-source-pre-effect-diagnose", {"path": "foreign"})
        loader.assert_not_called()
        self.assertFalse(result["ok"])

    def test_retirement_phase_and_cp95_snapshot_diagnostics_are_strict(self):
        flags = self.flags
        good = {"state": "blocked", "phase": "snapshot-output-guest-output-size",
                "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86",
                "snapshotDiagnostic": {"phase": "guest-output-size", "rawBytes": 100001, "wireBytes": 150000}, **flags}
        for extra, expected in (({}, True),
                                ({"snapshotDiagnostic": {"phase": "guest-output-size", "rawBytes": -1}}, False),
                                ({"snapshotDiagnostic": {"phase": "guest-output-size", "rawBytes": 150001}}, False),
                                ({"snapshotDiagnostic": {"phase": "private", "rawBytes": 0}}, False),
                                ({"snapshotDiagnostic": {"phase": "guest-output-size", "secret": "x"}}, False)):
            module = mock.Mock(); module.workflow.return_value = {**good, **extra}
            module._PHASES = {"snapshot-output-guest-output-size"}; module._DIAGNOSTIC_PHASES = {"guest-output-size"}
            with mock.patch.object(server, "_agent_module", return_value=module):
                result = server._vm_workflow_impl("windows-cp117-cp95-task-retire-preflight", {})
            if expected:
                self.assertEqual("snapshot-output-guest-output-size", result["phase"])
            else:
                self.assertEqual("proof", result["phase"])
            self.assertFalse(result["ok"])
            self.assertNotIn("secret", result)

    def test_cli_exposes_fixed_new_routes_without_dispatching_native_work(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            inputs = Path(directory) / "inputs.json"; inputs.write_text("{}")
            for action in ("windows-cp117-source-pre-effect-diagnose",
                           "windows-cp117-c32-retained-task-retire-preflight",
                           "windows-cp117-c32-retained-task-retire-start",
                           "windows-cp117-c32-retained-task-retire-status"):
                with self.subTest(action=action), mock.patch.object(server, "vm_workflow", return_value={"ok": False}) as dispatch:
                    self.assertEqual(1, server.main(["vm-workflow", action, "--inputs-file", str(inputs)]))
                dispatch.assert_called_once_with(action, {})

class StrictRouteMalformedPhaseTests(unittest.TestCase):
    def test_unhashable_phase_values_fall_back_without_validation_errors(self):
        flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        cases = (
            ("windows-cp117-c32-retained-task-retire-status",
             {"state": "unknown", "phase": [], **flags},
             {"state": "unknown", **flags}),
            ("windows-cp117-c32-retained-task-retire-preflight",
             {"state": "blocked", "phase": {}, **flags},
             {"state": "unknown", **flags}),
            ("windows-cp117-source-pre-effect-diagnose",
             {"state": "unknown", "phase": "guest-census", "guestCensusPhase": {},
              "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", **flags},
             {"state": "unknown", "phase": "local-intent",
              "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", **flags}),
            ("windows-cp117-source-pre-effect-diagnose",
             {"state": "unknown", "phase": [],
              "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", **flags},
             {"state": "unknown", "phase": "local-intent",
              "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", **flags}),
            ("windows-cp117-cp95-task-retire-preflight",
             {"state": "blocked", "phase": "snapshot-output-guest-output-size",
              "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86",
              "snapshotDiagnostic": {"phase": []}, **flags},
             {"state": "unknown", "phase": "proof",
              "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86", **flags}),
        )
        for action, malformed, fallback in cases:
            with self.subTest(action=action):
                module = mock.Mock(); module.workflow.return_value = malformed
                module._GUEST_CENSUS_PHASES = {"guest-qga-status-rpc"}
                module._PHASES = {"snapshot-output-guest-output-size"}
                module._DIAGNOSTIC_PHASES = {"guest-output-size"}
                with mock.patch.object(server, "_agent_module", return_value=module):
                    result = server._vm_workflow_impl(action, {})
                self.assertEqual({"tool": "vm_workflow", **fallback, "ok": False,
                                  "evidenceClass": "native-history"}, result)
