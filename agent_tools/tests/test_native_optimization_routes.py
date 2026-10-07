import unittest
from unittest.mock import patch

from agent_tools import mcp_server


class NativeOptimizationRoutesTest(unittest.TestCase):
    def test_windows_optical_current_screen_routes_are_fixed_and_one_shot(self):
        from agent_tools import windows_vm_optical_boot, windows_vm_optical_current_screen
        observation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "observationCorrelationId": observation,
                   "timeoutSeconds": 90}
        for action, method, state, accepted in (
                ("windows-vm-optical-current-screen-preflight", "preflight", "ready", True),
                ("windows-vm-optical-current-screen-start", "start", "unknown", False),
                ("windows-vm-optical-current-screen-status", "status", "observed", True),
                ("windows-vm-optical-current-screen-collect", "collect", "collected", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_current_screen, method, return_value={
                     "state": state, "observationCorrelationId": observation,
                     "nativeActionAllowed": False, "replayAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                observation_correlation_id=observation, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["replayAllowed"])
        with patch.object(windows_vm_optical_current_screen, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "observationCorrelationId": windows_vm_optical_boot.SECOND_CORRELATION},
                        {**request, "observationCorrelationId": windows_vm_optical_current_screen.ATTEMPT_CORRELATION},
                        {**request, "observationCorrelationId": windows_vm_optical_current_screen.CLOSURE_CORRELATION},
                        {**request, "imagePath": "/tmp/untrusted.png"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-current-screen-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
            uncertain = mcp_server.vm_workflow("windows-vm-optical-current-screen-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual(observation, uncertain["observationCorrelationId"])
        self.assertEqual("windows-vm-optical-current-screen-status", uncertain["nextAction"]["action"]["action"])
        self.assertEqual(observation, uncertain["nextAction"]["action"]["inputs"]["observationCorrelationId"])

    def test_windows_optical_attempt3_frame_collect_is_fixed_and_no_replay(self):
        from agent_tools import windows_vm_optical_post_collect
        correlation = "e80d5b29-d44f-4b22-a821-5612304564b5"
        closure = "7cbc014c-3890-422a-891a-a114d7cb779e"
        request = {"host": "archlinux", "correlationId": correlation,
                   "closureCorrelationId": closure, "timeoutSeconds": 90}
        for state, accepted in (("collected", True), ("unknown", False)):
            with self.subTest(state=state), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_post_collect, "collect", return_value={
                     "state": state, "correlationId": correlation,
                     "imagePath": "/private/ignored/post.png" if accepted else None,
                     "pngSha256": "a" * 64 if accepted else None,
                     "nativeActionAllowed": False, "replayAllowed": False}) as collect:
                result = mcp_server._vm_workflow_impl("windows-vm-optical-attempt3-frame-collect", request)
            collect.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                correlation_id=correlation, closure_correlation_id=closure, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["replayAllowed"])
        with patch.object(windows_vm_optical_post_collect, "collect", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "timeoutSeconds": 301},
                        {**request, "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
                        {**request, "closureCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
                        {**request, "imagePath": "/tmp/untrusted.png"}):
                self.assertFalse(mcp_server._vm_workflow_impl(
                    "windows-vm-optical-attempt3-frame-collect", bad)["ok"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_optical_post_collect, "collect", side_effect=ValueError("uncertain owner")):
            result = mcp_server._vm_workflow_impl("windows-vm-optical-attempt3-frame-collect", request)
        self.assertEqual("unknown", result["state"])
        self.assertFalse(result["replayAllowed"])

    def test_arch_qemu_holder_census_is_read_only_and_fails_closed(self):
        from agent_tools import arch_qemu_holder_census
        request = {"host": "archlinux", "timeoutSeconds": 20}
        for complete, expected_state in ((True, "observed"), (False, "unknown")):
            with self.subTest(complete=complete), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(arch_qemu_holder_census, "observe", return_value={
                     "state": expected_state, "inventoryComplete": complete,
                     "nativeActionAllowed": False, "processes": []}) as observe:
                result = mcp_server._vm_workflow_impl("arch-qemu-holder-census", request)
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
            self.assertEqual(complete, result["ok"])
            self.assertEqual(expected_state, result["state"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["productAction"])
        with patch.object(arch_qemu_holder_census, "observe", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "fedora2328"}, {**request, "timeoutSeconds": True},
                        {**request, "timeoutSeconds": 31}, {**request, "park": True}):
                self.assertFalse(mcp_server._vm_workflow_impl("arch-qemu-holder-census", bad)["ok"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(arch_qemu_holder_census, "observe", side_effect=ValueError("transport unknown")):
            uncertain = mcp_server._vm_workflow_impl("arch-qemu-holder-census", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["nativeActionAllowed"])

    def test_windows_optical_attempt2_close_routes_are_exact_and_one_shot(self):
        from agent_tools import windows_vm_optical_boot, windows_vm_optical_boot_attempt2
        closure = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "closureCorrelationId": closure, "timeoutSeconds": 90}
        for action, method, state, accepted in (
                ("windows-vm-optical-attempt2-close-preflight", "close_preflight", "ready", True),
                ("windows-vm-optical-attempt2-close-start", "close_start", "unknown", False),
                ("windows-vm-optical-attempt2-close-status", "close_status", "pre-effect-closed", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_boot_attempt2, method, return_value={
                     "state": state, "closureCorrelationId": closure,
                     "replayAllowed": False, "nativeActionAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                closure_correlation_id=closure, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(windows_vm_optical_boot_attempt2, "close_start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "closureCorrelationId": windows_vm_optical_boot.FIRST_CORRELATION},
                        {**request, "closureCorrelationId": windows_vm_optical_boot.FIRST_CLOSURE},
                        {**request, "closureCorrelationId": windows_vm_optical_boot.SECOND_CORRELATION},
                        {**request, "resetCount": 2}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-attempt2-close-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after close intent")):
            uncertain = mcp_server.vm_workflow("windows-vm-optical-attempt2-close-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual("windows-vm-optical-attempt2-close-status", uncertain["nextAction"]["action"]["action"])
        self.assertEqual(closure, uncertain["nextAction"]["action"]["inputs"]["closureCorrelationId"])

    def test_windows_optical_attempt3_routes_bind_second_closure_and_never_replay(self):
        from agent_tools import windows_vm_optical_boot, windows_vm_optical_boot_attempt3
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        closure = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        request = {"host": "archlinux", "correlationId": correlation,
                   "closureCorrelationId": closure, "timeoutSeconds": 90}
        for action, method, state, accepted in (
                ("windows-vm-optical-attempt3-preflight", "preflight", "ready", True),
                ("windows-vm-optical-attempt3-start", "start", "unknown", False),
                ("windows-vm-optical-attempt3-status", "status", "post-screen-observed", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_boot_attempt3, method, return_value={
                     "state": state, "correlationId": correlation,
                     "closureCorrelationId": closure, "replayAllowed": False,
                     "nativeActionAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                correlation_id=correlation, closure_correlation_id=closure, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(windows_vm_optical_boot_attempt3, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "correlationId": windows_vm_optical_boot.SECOND_CORRELATION},
                        {**request, "closureCorrelationId": windows_vm_optical_boot.FIRST_CLOSURE},
                        {**request, "closureCorrelationId": correlation},
                        {**request, "spaceKey": True}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-attempt3-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
            uncertain = mcp_server.vm_workflow("windows-vm-optical-attempt3-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual("windows-vm-optical-attempt3-status", uncertain["nextAction"]["action"]["action"])
        self.assertEqual(closure, uncertain["nextAction"]["action"]["inputs"]["closureCorrelationId"])

    def test_windows_optical_attempt2_phase_probe_is_exact_and_read_only(self):
        from agent_tools import windows_vm_optical_boot_attempt2
        request = {"host": "archlinux",
                   "correlationId": "98b4f1e0-968c-455b-a85b-d87490f5b256",
                   "closureCorrelationId": "b76bfd72-2d7b-459a-91da-a063e35c8007",
                   "timeoutSeconds": 90}
        for state, admitted in (("ready", True), ("unknown", False)):
            with self.subTest(state=state), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_boot_attempt2, "phase_probe", return_value={
                     "state": "phase-probed", "correlationId": request["correlationId"],
                     "closureCorrelationId": request["closureCorrelationId"],
                     "probe": {"state": state, "phase": "complete" if admitted else "admission"},
                     "replayAllowed": False, "nativeActionAllowed": False}) as probe:
                result = mcp_server._vm_workflow_impl("windows-vm-optical-attempt2-phase-probe", request)
            probe.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                correlation_id=request["correlationId"],
                closure_correlation_id=request["closureCorrelationId"], timeout_seconds=90)
            self.assertEqual(admitted, result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["replayAllowed"])
        with patch.object(windows_vm_optical_boot_attempt2, "phase_probe", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
                        {**request, "closureCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"},
                        {**request, "timeoutSeconds": True},
                        {**request, "key": "spc"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-attempt2-phase-probe", bad)["ok"])

    def test_windows_optical_attempt2_routes_bind_exact_closure_and_never_replay(self):
        from agent_tools import windows_vm_optical_boot, windows_vm_optical_boot_attempt2
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        closure = "b76bfd72-2d7b-459a-91da-a063e35c8007"
        request = {"host": "archlinux", "correlationId": correlation,
                   "closureCorrelationId": closure, "timeoutSeconds": 90}
        for action, method, state, accepted in (
                ("windows-vm-optical-attempt2-preflight", "preflight", "ready", True),
                ("windows-vm-optical-attempt2-start", "start", "unknown", False),
                ("windows-vm-optical-attempt2-status", "status", "post-screen-observed", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_boot_attempt2, method, return_value={
                     "state": state, "correlationId": correlation,
                     "closureCorrelationId": closure, "replayAllowed": False,
                     "nativeActionAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                correlation_id=correlation, closure_correlation_id=closure, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(windows_vm_optical_boot_attempt2, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "correlationId": windows_vm_optical_boot.FIRST_CORRELATION},
                        {**request, "correlationId": closure},
                        {**request, "closureCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"},
                        {**request, "resetCount": 2}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-attempt2-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
            uncertain = mcp_server.vm_workflow("windows-vm-optical-attempt2-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual("windows-vm-optical-attempt2-status", uncertain["nextAction"]["action"]["action"])
        self.assertEqual(closure, uncertain["nextAction"]["action"]["inputs"]["closureCorrelationId"])

    def test_windows_optical_close_routes_bind_first_attempt_and_never_replay(self):
        from agent_tools import windows_vm_optical_boot
        closure = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "closureCorrelationId": closure, "timeoutSeconds": 90}
        for action, method, state, accepted in (
                ("windows-vm-optical-close-preflight", "close_preflight", "ready", True),
                ("windows-vm-optical-close-start", "close_start", "unknown", False),
                ("windows-vm-optical-close-status", "close_status", "pre-effect-closed", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_boot, method, return_value={
                     "state": state, "closureCorrelationId": closure,
                     "originalCorrelationId": windows_vm_optical_boot.FIRST_CORRELATION,
                     "replayAllowed": False, "nativeActionAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                closure_correlation_id=closure, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(windows_vm_optical_boot, "close_start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "closureCorrelationId": windows_vm_optical_boot.FIRST_CORRELATION},
                        {**request, "closureCorrelationId": windows_vm_optical_boot.VM_CORRELATION},
                        {**request, "correlationId": "foreign"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-close-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after close intent")):
            uncertain = mcp_server.vm_workflow("windows-vm-optical-close-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertEqual(closure, uncertain["closureCorrelationId"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual("windows-vm-optical-close-status", uncertain["nextAction"]["action"]["action"])
        self.assertEqual(closure, uncertain["nextAction"]["action"]["inputs"]["closureCorrelationId"])

    def test_android_installer_dispatch_routes_bind_fixed_campaign_and_ui_phases(self):
        from agent_tools import android_installer_dispatch
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api29", "correlationId": correlation,
                   "sourceSha": "a" * 40, "baseArtifactId": "sha256-" + "b" * 64,
                   "targetArtifactId": "sha256-" + "c" * 64,
                   "backupCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "inspectCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                   "expectedOwner": "controller-1", "expectedRevision": 4,
                   "expectedBackupSha256": "d" * 64, "expectedTerminal": "installed",
                   "cliStageCorrelationId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                   "caArtifactId": "sha256-" + "e" * 64,
                   "leafArtifactId": "sha256-" + "f" * 64,
                   "keyArtifactId": "sha256-" + "a" * 64}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(android_installer_dispatch, "start", return_value={
                 "ok": True, "state": "submitted", "correlationId": correlation,
                 "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-installer-dispatch-start", request)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["replayAllowed"])
        start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", correlation,
            request["sourceSha"], request["baseArtifactId"], request["targetArtifactId"],
            request["backupCorrelationId"], request["inspectCorrelationId"],
            request["expectedOwner"], request["expectedRevision"],
            request["expectedBackupSha256"], "installed", request["cliStageCorrelationId"],
            request["caArtifactId"], request["leafArtifactId"], request["keyArtifactId"])
        with patch.object(android_installer_dispatch, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "shell": "id"}, {**request, "expectedRevision": True},
                        {**request, "expectedTerminal": ["installed"]},
                        {**request, "caArtifactId": "a" * 64},
                        {**request, "correlationId": correlation.upper()}):
                self.assertFalse(mcp_server._vm_workflow_impl("android-installer-dispatch-start", bad)["ok"])
        observed = {"correlationId": correlation}
        cases = (
            ("android-installer-dispatch-status", "status", observed, (correlation,)),
            ("android-installer-dispatch-collect", "collect", observed, (correlation,)),
            ("android-installer-callback-handoff-ready", "callback", observed, (correlation, "handoff-ready")),
            ("android-installer-callback-continue", "callback", observed, (correlation, "continue")),
            ("android-installer-callback-status-handoff-ready", "callback_status", observed, (correlation, "handoff-ready")),
            ("android-installer-callback-status-continue", "callback_status", observed, (correlation, "continue")),
            ("android-installer-abort-prelaunch", "abort_prelaunch",
             {**observed, "closingReadbackCorrelationId": request["backupCorrelationId"]},
             (correlation, request["backupCorrelationId"])),
            ("android-installer-reconcile", "reconcile",
             {**observed, "closingReadbackCorrelationId": request["backupCorrelationId"],
              "expectedClosingOwner": "controller-2", "expectedClosingRevision": 5},
             (correlation, request["backupCorrelationId"], "controller-2", 5)))
        for action, method, inputs, args in cases:
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(android_installer_dispatch, method, return_value={
                     "ok": False, "state": "unknown", "correlationId": correlation,
                     "replayAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, inputs)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, *args)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(mcp_server._vm_workflow_impl(action, {**inputs, "shell": "id"})["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
            uncertain = mcp_server.vm_workflow("android-installer-callback-continue", observed)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual("android-installer-callback-status-continue",
                         uncertain["nextAction"]["action"]["action"])

    def test_windows_optical_boot_routes_require_new_fixed_identity_and_no_replay(self):
        from agent_tools import windows_vm_optical_boot
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "correlationId": correlation, "timeoutSeconds": 90}
        for action, method, state, accepted in (
                ("windows-vm-optical-boot-preflight", "preflight", "ready", True),
                ("windows-vm-optical-boot-start", "start", "unknown", False),
                ("windows-vm-optical-boot-status", "status", "post-screen-observed", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_optical_boot, method, return_value={
                     "state": state, "correlationId": correlation,
                     "nativeActionAllowed": False, "replayAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                             correlation_id=correlation, timeout_seconds=90)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["replayAllowed"])
        with patch.object(windows_vm_optical_boot, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "timeoutSeconds": True},
                        {**request, "correlationId": windows_vm_optical_boot.VM_CORRELATION},
                        {**request, "correlationId": correlation.upper()},
                        {**request, "key": "spc"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-optical-boot-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
            uncertain = mcp_server.vm_workflow("windows-vm-optical-boot-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual(correlation, uncertain["correlationId"])
        self.assertEqual("windows-vm-optical-boot-status", uncertain["nextAction"]["action"]["action"])

    def test_android_endpoint_routes_bind_exact_inputs_and_never_replay_unknown(self):
        from agent_tools import android_endpoint_admission
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api29", "correlationId": correlation,
                   "campaignId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "sourceSha": "c" * 40, "targetArtifactId": "sha256-" + "d" * 64,
                   "caArtifactId": "sha256-" + "e" * 64,
                   "backupCorrelationId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                   "expectedOwner": "owner-1", "expectedRevision": 7,
                   "expectedBackupSha256": "a" * 64}
        for action, method, payload, state, accepted in (
                ("android-endpoint-admission-start", "start", request, "unknown", False),
                ("android-endpoint-admission-status", "status", {"correlationId": correlation}, "ready", True),
                ("android-endpoint-admission-cleanup", "cleanup", {"correlationId": correlation}, "cleaned", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(android_endpoint_admission, method, return_value={
                     "ok": accepted, "state": state, "correlationId": correlation,
                     "replayAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, payload)
            if method == "start":
                dispatch.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29",
                    correlation, request["campaignId"], request["sourceSha"],
                    request["targetArtifactId"], request["caArtifactId"],
                    request["backupCorrelationId"], request["expectedOwner"],
                    request["expectedRevision"], request["expectedBackupSha256"])
            else:
                dispatch.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["productMutationAllowed"])
            self.assertFalse(result["installerTargetAdmitted"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["replayAllowed"])
        with patch.object(android_endpoint_admission, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({key: value for key, value in request.items() if key != "caArtifactId"},
                        {**request, "targetArtifactId": "a" * 64},
                        {**request, "expectedRevision": True},
                        {**request, "sourceSha": "z" * 40},
                        {**request, "correlationId": "aaaaaaaa-aaaa-0aaa-8aaa-aaaaaaaaaaaa"},
                        {**request, "extra": "unsafe"}):
                self.assertFalse(mcp_server._vm_workflow_impl("android-endpoint-admission-start", bad)["ok"])
        with patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
            uncertain = mcp_server.vm_workflow("android-endpoint-admission-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertEqual("android-endpoint-admission-status", uncertain["nextAction"]["action"]["action"])

    def test_acceptance_status_is_read_only_and_does_not_promote_supplied_owner(self):
        from agent_tools import native_acceptance_overview
        source = "a" * 40
        rows = [{"platform": platform, "requirementId": platform + "-native", "status": "open",
                 "missingScenarios": ["installer"]} for platform in ("android", "linux", "windows", "macos")]
        matrix = {"currentSourceSHA": source, "gate": "open", "requirements": rows}
        artifacts = {"matches": [{"platform": "linux", "sourceSha": source, "artifactKind": "package",
                                  "artifactId": "sha256-" + "b" * 64}], "records": {}}
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"sourceSha": source,
                   "correlations": [{"platform": "linux", "correlationId": correlation,
                                     "statusAction": "linux-rpm-workspace-recovery-status"}],
                   "ownerProbes": [{"platform": "linux", "action": "linux-owner-public-quit-status",
                                    "inputs": {"correlationId": correlation}}]}
        result = native_acceptance_overview.acceptance_status(matrix, request, artifacts,
            correlation_observer=lambda item, sha, index: {
                "state": "verified", "correlationId": correlation, "sourceSha": "b" * 40,
                "operationState": "running"},
            owner_observer=lambda item: {
                "state": "stopped", "evidenceScope": "owner", "source": "caller-receipt"})
        self.assertFalse(result["nativeActionAllowed"])
        linux = next(p for p in result["platforms"] if p["platform"] == "linux")
        self.assertEqual("unknown", linux["ownerEvidence"])
        self.assertEqual("unknown", linux["correlationEvidence"])
        self.assertIsNone(linux["activeCorrelationId"])
        self.assertEqual(1, linux["unmetGates"][0]["missingCount"])
        self.assertEqual("registered-unverified", linux["artifactEvidence"])
        with self.assertRaisesRegex(ValueError, "current exact"):
            native_acceptance_overview.acceptance_status(matrix, {**request, "sourceSha": "b" * 40},
                artifacts, correlation_observer=lambda *args: self.fail("stale source was observed"))
        with self.assertRaisesRegex(ValueError, "only sourceSha"):
            native_acceptance_overview.acceptance_status(matrix,
                {**request, "ownerObservations": [{"platform": "linux", "state": "stopped"}]}, artifacts)

    def test_acceptance_status_promotes_only_exact_live_status_and_owner_probe(self):
        from agent_tools import native_acceptance_overview
        source = "a" * 40
        rows = [{"platform": platform, "requirementId": platform + "-native", "status": "open",
                 "missingScenarios": []} for platform in ("android", "linux", "windows", "macos")]
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        result = native_acceptance_overview.acceptance_status(
            {"currentSourceSHA": source, "gate": "open", "requirements": rows},
            {"sourceSha": source,
             "correlations": [{"platform": "android", "correlationId": correlation,
                               "statusAction": "android-consent-acceptance-status"}],
             "ownerProbes": [{"platform": "android", "action": "android-observe",
                              "inputs": {"host": "archlinux", "device": "api29", "timeoutSeconds": 5}}]},
            {"matches": [], "records": {}},
            correlation_observer=lambda item, sha, index: {
                "state": "verified", "correlationId": correlation,
                "sourceSha": source, "operationState": "running",
                "ownerIdentity": "owned", "deviceAlias": "api29"},
            owner_observer=lambda item: {"state": "running", "evidenceScope": "owner",
                                         "source": "live-tool", "controllerId": "owned",
                                         "deviceAlias": "api29"})
        android = result["platforms"][0]
        self.assertEqual(correlation, android["activeCorrelationId"])
        self.assertEqual("verified-current-source-status", android["correlationEvidence"])
        self.assertEqual("live-observer", android["ownerEvidence"])
        self.assertEqual("running", android["ownerOrGuest"]["state"])
        foreign = native_acceptance_overview.acceptance_status(
            {"currentSourceSHA": source, "gate": "open", "requirements": rows},
            {"sourceSha": source,
             "correlations": [{"platform": "android", "correlationId": correlation,
                               "statusAction": "android-consent-acceptance-status"}],
             "ownerProbes": [{"platform": "android", "action": "android-observe",
                              "inputs": {"host": "archlinux", "device": "api29", "timeoutSeconds": 5}}]},
            {"matches": [], "records": {}},
            correlation_observer=lambda item, sha, index: {
                "state": "verified", "correlationId": correlation,
                "sourceSha": source, "operationState": "running",
                "ownerIdentity": "old", "deviceAlias": "api29"},
            owner_observer=lambda item: {"state": "running", "evidenceScope": "owner",
                                         "source": "live-tool", "controllerId": "replacement",
                                         "deviceAlias": "api29"})
        self.assertIsNone(foreign["platforms"][0]["activeCorrelationId"])
        self.assertEqual("unknown", foreign["platforms"][0]["ownerEvidence"])
        with self.assertRaisesRegex(ValueError, "fixed and bounded"):
            native_acceptance_overview.acceptance_status(
                {"currentSourceSHA": source, "gate": "open", "requirements": rows},
                {"ownerProbes": [{"platform": "android", "action": "android-observe",
                                  "inputs": {"host": "archlinux", "device": "api29",
                                             "timeoutSeconds": 5, "shell": "id"}}]},
                {"matches": [], "records": {}},
                owner_observer=lambda item: self.fail("unsafe probe dispatched"))

    def test_multiple_source_bound_correlations_remain_separately_observed(self):
        from agent_tools import native_acceptance_overview
        source = "a" * 40
        first = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        second = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        rows = [{"platform": platform, "requirementId": platform + "-native", "status": "open",
                 "missingScenarios": []} for platform in ("android", "linux", "windows", "macos")]
        known = {"android": [{"correlationId": corr, "sourceSha": source,
                 "statusAction": "android-consent-acceptance-status",
                 "evidence": "source-bound-local-intent"} for corr in (first, second)]}
        result = native_acceptance_overview.acceptance_status(
            {"currentSourceSHA": source, "gate": "open", "requirements": rows}, {},
            {"matches": [], "records": {}}, known_correlations=known,
            correlation_observer=lambda item, sha, index: {"state": "verified",
                "correlationId": item["correlationId"], "sourceSha": source,
                "operationState": "complete" if item["correlationId"] == first else "running"})
        android = result["platforms"][0]
        self.assertEqual(2, len(android["correlationObservations"]))
        self.assertEqual([first, second], android["observedCorrelationIds"])
        self.assertEqual(second, android["activeCorrelationId"])
        self.assertEqual("verified-current-source-status", android["correlationEvidence"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_acceptance_artifact_index_read_does_not_create_or_clean_state(self):
        import os
        if os.name == "nt":
            self.skipTest("POSIX private registry ownership is required")
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from agent_tools import native_acceptance_overview, native_artifact_registry
        source = "a" * 40
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self.assertEqual({"matches": [], "records": {}}, native_acceptance_overview.read_artifact_index(
                root, source, native_artifact_registry))
            self.assertFalse((root / ".rag_index").exists())
            index = root / ".rag_index" / "native-artifacts"
            index.mkdir(parents=True)
            os.chmod(index.parent, 0o700)
            os.chmod(index, 0o700)
            (index / ".tmp-incomplete").write_text("partial")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                native_acceptance_overview.read_artifact_index(root, source, native_artifact_registry)
            self.assertTrue((index / ".tmp-incomplete").exists())
            (index / ".tmp-incomplete").unlink()
            legacy = index / ("sha256-" + "b" * 64 + ".json")
            legacy.write_text('{"schemaVersion":1}')
            os.chmod(legacy, 0o600)
            before = legacy.read_bytes()
            with self.assertRaisesRegex(ValueError, "migration"):
                native_acceptance_overview.read_artifact_index(root, source, native_artifact_registry)
            self.assertEqual(before, legacy.read_bytes())

    def test_acceptance_verifies_current_local_artifact_bytes_without_matrix_promotion(self):
        import hashlib
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from agent_tools import native_acceptance_overview, native_artifact_registry
        source = "a" * 40
        with TemporaryDirectory() as raw:
            path = Path(raw) / "package.rpm"
            path.write_bytes(b"exact rpm")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            identifier = "sha256-" + digest
            record = {"platform": "linux", "artifactKind": "package", "artifactId": identifier,
                      "sourceSha": source, "sha256": digest, "size": path.stat().st_size,
                      "locations": [{"evidenceClass": "local-verified", "localPath": str(path)}]}
            index = {"matches": [{"platform": "linux", "sourceSha": source,
                                  "artifactKind": "package", "artifactId": identifier}],
                     "records": {identifier: record}}
            states = native_acceptance_overview.verify_local_artifact_bytes(index, native_artifact_registry)
            self.assertEqual("verified-local-bytes", states[identifier])
            path.write_bytes(b"changed rpm")
            states = native_acceptance_overview.verify_local_artifact_bytes(index, native_artifact_registry)
            self.assertEqual("local-bytes-mismatch", states[identifier])
        rows = [{"platform": platform, "requirementId": platform + "-native", "status": "open",
                 "missingScenarios": []} for platform in ("android", "linux", "windows", "macos")]
        result = native_acceptance_overview.acceptance_status(
            {"currentSourceSHA": source, "gate": "open", "requirements": rows}, {}, index,
            artifact_verification={identifier: "verified-local-bytes"})
        linux = result["platforms"][1]
        self.assertEqual("verified-local-bytes", linux["artifactHashes"][0]["evidence"])
        self.assertEqual("open", result["matrixGate"])

    def test_source_bound_local_intents_are_discovered_without_promoting_status(self):
        import os
        if os.name == "nt":
            self.skipTest("POSIX private intent ownership is required")
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from agent_tools import native_acceptance_overview
        source = "a" * 40
        artifact_id = "sha256-" + "b" * 64
        android_corr = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        cleanup_corr = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        public_corr = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
        class Android:
            @staticmethod
            def _load(root, corr):
                return {"correlationId": corr, "artifactId": artifact_id, "device": "api35",
                        "backupSha256": "d" * 64, "openingReadbackCorrelationId": public_corr,
                        "cliStageCorrelationId": public_corr, "packageSha256": "b" * 64}
        class Cleanup:
            @staticmethod
            def _cleanup_journal(root, corr):
                return root / ".rag_index" / "linux-rpm-workspace-cleanup" / (corr + ".json")
            @staticmethod
            def _read_cleanup_journal(path):
                return {"cleanupCorrelationId": cleanup_corr, "correlationId": public_corr}
        class Server:
            @staticmethod
            def _journal(root, corr):
                return {"correlationId": corr, "sourceSha": source}
        with TemporaryDirectory() as raw:
            root = Path(raw)
            for name, correlation in (("android-document-jobs", android_corr),
                                      ("linux-rpm-workspace-cleanup", cleanup_corr)):
                directory = root / ".rag_index" / name
                directory.mkdir(parents=True)
                os.chmod(directory, 0o700)
                path = directory / (correlation + ".json")
                path.write_text("{}")
                os.chmod(path, 0o600)
            found = native_acceptance_overview.discover_source_correlations(
                root, source, {"records": {artifact_id: {"platform": "android",
                    "sourceSha": source, "sha256": "b" * 64}}}, Android, Cleanup, Server)
            self.assertEqual(android_corr, found["android"][0]["correlationId"])
            self.assertEqual(cleanup_corr, found["linux"][0]["correlationId"])
            self.assertEqual("source-bound-local-intent", found["android"][0]["evidence"])
            self.assertEqual("source-bound-local-intent", found["linux"][0]["evidence"])
            self.assertEqual([], found["macos"])
            self.assertEqual([], found["windows"])
            self.assertEqual("{}", (root / ".rag_index" / "android-document-jobs" /
                                    (android_corr + ".json")).read_text())
            self.assertEqual([], native_acceptance_overview.discover_source_correlations(
                root, "e" * 40, {"records": {}}, Android, Cleanup, Server)["android"])

    def test_macos_summary_is_source_bound_pointer_not_live_owner(self):
        import os
        if os.name == "nt":
            self.skipTest("POSIX local evidence ownership is required")
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from agent_tools import native_acceptance_overview
        source = "a" * 40
        base, target = "sha256-" + "b" * 64, "sha256-" + "c" * 64
        with TemporaryDirectory() as raw:
            root = Path(raw)
            path = (root / ".runtime" / "parity-evidence" / "continuation-macos" /
                    ("fixture-" + source[:7]) / "native-machine-denial" /
                    "reviewed-denial-summary.json")
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"sourceSha": source, "baseArtifactId": base,
                "targetArtifactId": target, "finalPublicCode": "CANCELLED", "installed": False,
                "installOperationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}))
            index = {"records": {base: {"platform": "macos", "sourceSha": source},
                                 target: {"platform": "macos", "sourceSha": source}}}
            found = native_acceptance_overview.read_macos_denial_summary(root, source, index)
            self.assertEqual("local-summary-not-matrix-reviewed", found[0]["evidence"])
            self.assertEqual("cancelled", found[0]["outcome"])
            self.assertEqual("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", found[0]["correlationId"])
            self.assertFalse(found[0]["liveOwnerVerified"])
            path.write_text(json.dumps({"sourceSha": "d" * 40, "baseArtifactId": base,
                "targetArtifactId": target, "finalPublicCode": "CANCELLED", "installed": False,
                "installOperationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}))
            self.assertEqual([], native_acceptance_overview.read_macos_denial_summary(root, source, index))

    def test_readonly_matrix_does_not_use_registry_mutation_path(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from agent_tools import native_acceptance_matrix, native_acceptance_overview, native_artifact_registry
        source = "a" * 40
        with TemporaryDirectory() as raw:
            root = Path(raw)
            with patch.object(native_artifact_registry, "_prepare_registry",
                              side_effect=AssertionError("registry mutation path used")), \
                 patch.object(native_acceptance_matrix, "matrix_status",
                              side_effect=AssertionError("canonical matrix writer path used")):
                report = native_acceptance_overview.matrix_status_readonly(
                    root, source, native_acceptance_matrix, native_artifact_registry,
                    {"matches": [], "records": {}})
            self.assertEqual("open", report["gate"])
            self.assertFalse((root / ".rag_index").exists())

    def test_acceptance_route_requires_live_correlated_status_and_current_artifact_source(self):
        from agent_tools import native_acceptance_overview, android_consent_acceptance, android_document_acceptance
        source = "a" * 40
        artifact_id = "sha256-" + "b" * 64
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        rows = [{"platform": platform, "requirementId": platform + "-native", "status": "open",
                 "missingScenarios": []} for platform in ("android", "linux", "windows", "macos")]
        request = {"sourceSha": source, "correlations": [{"platform": "android",
                   "correlationId": correlation, "statusAction": "android-consent-acceptance-status"}]}
        index = {"matches": [], "records": {artifact_id: {"sourceSha": source}}}
        with patch.object(mcp_server.subprocess, "check_output", return_value=source), \
             patch.object(native_acceptance_overview, "read_artifact_index", return_value=index), \
             patch.object(native_acceptance_overview, "verify_local_artifact_bytes", return_value={}), \
             patch.object(native_acceptance_overview, "discover_source_correlations", return_value={
                 "android": [], "linux": [], "windows": [], "macos": []}), \
             patch.object(native_acceptance_overview, "matrix_status_readonly", return_value={
                 "currentSourceSHA": source, "gate": "open", "requirements": rows}), \
             patch.object(android_consent_acceptance, "status", return_value={
                 "state": "running", "correlationId": correlation}), \
             patch.object(android_document_acceptance, "_load", return_value={
                 "device": "api29", "artifactId": artifact_id, "cliStageCorrelationId": correlation,
                 "expectedOwner": "owned"}):
            current = mcp_server._vm_workflow_impl("acceptance-status", request)
            self.assertEqual(correlation, current["platforms"][0]["activeCorrelationId"])
            index["records"][artifact_id]["sourceSha"] = "c" * 40
            stale = mcp_server._vm_workflow_impl("acceptance-status", request)
            self.assertIsNone(stale["platforms"][0]["activeCorrelationId"])
            self.assertEqual("unknown", stale["platforms"][0]["correlationEvidence"])
        self.assertFalse(stale["nativeActionAllowed"])

    def test_checkout_status_marks_dirty_source_and_fails_closed(self):
        from pathlib import Path
        from subprocess import CompletedProcess
        from agent_tools import native_acceptance_overview
        root = Path("/tmp/read-only-checkout")
        with patch.object(native_acceptance_overview.subprocess, "run", return_value=
                          CompletedProcess([], 0, b"", b"")) as run:
            self.assertEqual({"checkoutExact": True, "worktreeDirty": False},
                             native_acceptance_overview.checkout_state(root))
        self.assertIn("--no-optional-locks", run.call_args.args[0])
        self.assertEqual("0", run.call_args.kwargs["env"]["GIT_OPTIONAL_LOCKS"])
        with patch.object(native_acceptance_overview.subprocess, "run", return_value=
                          CompletedProcess([], 0, b" M app/src/main.kt\n?? new.kt\n", b"")):
            self.assertEqual({"checkoutExact": False, "worktreeDirty": True},
                             native_acceptance_overview.checkout_state(root))
        with patch.object(native_acceptance_overview.subprocess, "run", return_value=
                          CompletedProcess([], 1, b"", b"")):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                native_acceptance_overview.checkout_state(root)

    def test_acceptance_route_never_claims_exact_dirty_checkout(self):
        from agent_tools import native_acceptance_overview
        source = "a" * 40
        rows = [{"platform": platform, "requirementId": platform + "-native", "status": "open",
                 "missingScenarios": []} for platform in ("android", "linux", "windows", "macos")]
        with patch.object(mcp_server.subprocess, "check_output", return_value=source), \
             patch.object(native_acceptance_overview, "read_artifact_index",
                          return_value={"matches": [], "records": {}}), \
             patch.object(native_acceptance_overview, "discover_source_correlations", return_value={
                 "android": [], "linux": [], "windows": [], "macos": []}), \
             patch.object(native_acceptance_overview, "matrix_status_readonly", return_value={
                 "currentSourceSHA": source, "gate": "open", "requirements": rows}):
            for dirty in (False, True):
                with patch.object(native_acceptance_overview, "checkout_state", return_value={
                        "worktreeDirty": dirty, "checkoutExact": not dirty}):
                    result = mcp_server._vm_workflow_impl("acceptance-status", {"sourceSha": source})
                self.assertEqual(not dirty, result["checkoutExact"])
                self.assertEqual(dirty, result["worktreeDirty"])
                self.assertFalse(result["nativeActionAllowed"])

    def test_unknown_acceptance_does_not_write_failure_evidence(self):
        from agent_tools import native_failure_evidence
        result = {"tool": "vm_workflow", "ok": False, "state": "unknown",
                  "nativeActionAllowed": False, "productAction": False,
                  "checkoutExact": False, "worktreeDirty": None}
        with patch.object(native_failure_evidence, "record_failure",
                          side_effect=AssertionError("read-only route wrote evidence")):
            observed = mcp_server._native_response("vm_workflow", "acceptance-status", result, {})
        self.assertFalse(observed["checkoutExact"])
        self.assertNotIn("failureEvidence", observed)

    def test_acceptance_guidance_names_unmet_review_gate_without_authorizing_action(self):
        result = {"tool": "vm_workflow", "ok": True, "state": "observed", "matrixGate": "open",
                  "checkoutExact": False, "worktreeDirty": True,
                  "platforms": [{"platform": "android", "artifactHashes": [{"sha256": "sha256-" + "a" * 64,
                      "evidence": "verified-local-bytes"}], "observedCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                      "unmetGates": [{"requirementId": "android-api29-native-cli", "status": "open"}]}],
                  "nativeActionAllowed": False, "productAction": False}
        observed = mcp_server._native_response("vm_workflow", "acceptance-status", result, {})
        self.assertEqual("review-current-source-native-evidence", observed["nextAction"]["kind"])
        self.assertEqual("android-api29-native-cli", observed["admissionGap"]["requirementId"])
        self.assertFalse(observed["nextAction"]["replayAllowed"])
        self.assertFalse(observed["admissionGap"]["nativeActionAllowed"])

    def test_windows_baseline_inventory_route_is_read_only_and_never_admits_clone(self):
        from agent_tools import windows_vm_baseline_inventory
        request = {"host": "archlinux", "timeoutSeconds": 20}
        sample = {"inventoryComplete": True, "nativeActionAllowed": False,
                  "candidates": [{"path": "/home/kardinal/win11/base.qcow2",
                                  "sourceState": "unknown", "noQemuObserved": True}]}
        # Other tests may import the MCP server before a concurrent worker
        # finishes editing this domain module; bypass only that hot-reload
        # guard here so the test measures route dispatch and input bounds.
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_baseline_inventory, "observe", return_value=sample) as observe:
            result = mcp_server._vm_workflow_impl("windows-vm-baseline-inventory", request)
        observe.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", timeout_seconds=20)
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["productAction"])
        self.assertEqual("unknown", result["candidates"][0]["sourceState"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_baseline_inventory, "observe",
                          side_effect=AssertionError("unsafe request dispatched")):
            for bad in ({"host": "fedora2328", "timeoutSeconds": 20},
                        {"host": "archlinux", "timeoutSeconds": 31},
                        {"host": "archlinux", "timeoutSeconds": 20, "clone": True}):
                self.assertFalse(mcp_server._vm_workflow_impl(
                    "windows-vm-baseline-inventory", bad)["ok"])

    def test_windows_driver_fetch_route_exact_identity_and_status_read_only(self):
        from agent_tools import windows_vm_driver_fetch
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 120}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_driver_fetch, "start", return_value={
                 "state": "unknown", "correlationId": request["correlationId"],
                 "replayAllowed": False, "nativeActionAllowed": False}) as start:
            started = mcp_server._vm_workflow_impl("windows-vm-driver-fetch-start", request)
        self.assertFalse(started["ok"])
        self.assertFalse(started["replayAllowed"])
        start.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                      correlation_id=request["correlationId"], timeout_seconds=120)
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_driver_fetch, "status", return_value={
                 "state": "verified", "correlationId": request["correlationId"],
                 "replayAllowed": False, "nativeActionAllowed": False}) as status:
            observed = mcp_server._vm_workflow_impl("windows-vm-driver-fetch-status", request)
        self.assertTrue(observed["ok"])
        self.assertFalse(observed["nativeActionAllowed"])
        status.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                       correlation_id=request["correlationId"], timeout_seconds=120)
        with patch.object(windows_vm_driver_fetch, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "fedora2328"}, {**request, "timeoutSeconds": 29},
                        {**request, "correlationId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
                        {**request, "url": "https://foreign.example"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-driver-fetch-start", bad)["ok"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_driver_fetch, "start", side_effect=ValueError("private intent exists")):
            uncertain = mcp_server._vm_workflow_impl("windows-vm-driver-fetch-start", request)
        self.assertEqual("unknown", uncertain["state"])
        self.assertEqual(request["correlationId"], uncertain["correlationId"])
        self.assertFalse(uncertain["replayAllowed"])
        self.assertNotIn("private intent exists", str(uncertain))
        for state in ("unknown", "partial", "linked-partial", "mismatch"):
            detail = mcp_server._native_response("vm_workflow", "windows-vm-driver-fetch-status",
                {"ok": False, "state": state, "correlationId": request["correlationId"],
                 "replayAllowed": False, "nativeActionAllowed": False}, request)
            self.assertEqual("unknown", detail["failureSignature"]["basis"]["classification"])
            self.assertEqual("windows-vm-driver-fetch-status",
                             detail["admissionGap"]["readOnlyAction"]["action"])
            self.assertFalse(detail["replayAllowed"])

    def test_driver_fetch_unexpected_boundary_exception_keeps_correlation_and_status_only(self):
        import subprocess
        from agent_tools import windows_vm_driver_fetch
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 300}
        for error in (RuntimeError("unexpected private transport detail"),
                      subprocess.TimeoutExpired(["ssh"], 300)):
            with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_driver_fetch, "start", side_effect=error):
                result = mcp_server.vm_workflow("windows-vm-driver-fetch-start", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            self.assertEqual(request["correlationId"], result["correlationId"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertNotIn("unexpected private transport detail", str(result))
            self.assertEqual("windows-vm-driver-fetch-status", result["nextAction"]["action"]["action"])

    def test_driver_fetch_partial_start_is_uncertain_with_exact_status_followup(self):
        from agent_tools import native_failure_evidence
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        captured = []
        def record(root, context, receipt):
            captured.append(receipt)
            return {"state": "recorded"}
        with patch.object(native_failure_evidence, "record_failure", side_effect=record):
            result = mcp_server._native_response("vm_workflow", "windows-vm-driver-fetch-start",
                {"ok": False, "state": "linked-partial", "correlationId": correlation,
                 "replayAllowed": False, "nativeActionAllowed": False},
                {"host": "archlinux", "correlationId": correlation, "timeoutSeconds": 300})
        self.assertEqual("nativeUNKNOWN", captured[0]["classification"])
        self.assertEqual("observe-existing-driver-fetch", result["nextAction"]["kind"])
        self.assertEqual(correlation, result["nextAction"]["action"]["inputs"]["correlationId"])
        self.assertFalse(result["nextAction"]["replayAllowed"])

    def test_failure_receipt_enrichment_tolerates_missing_optional_signature(self):
        from agent_tools import native_failure_evidence, native_response_diagnostics
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with patch.object(native_response_diagnostics, "describe", return_value={}), \
             patch.object(native_failure_evidence, "record_failure", return_value={
                 "evidenceId": "native-failure-" + "a" * 64}):
            result = mcp_server._native_response("vm_workflow", "windows-vm-driver-fetch-start",
                {"ok": False, "state": "partial", "correlationId": correlation,
                 "replayAllowed": False, "nativeActionAllowed": False},
                {"host": "archlinux", "correlationId": correlation, "timeoutSeconds": 300})
        self.assertEqual("partial", result["state"])
        self.assertFalse(result["replayAllowed"])
        self.assertEqual("native-failure-" + "a" * 64, result["failureEvidence"]["evidenceId"])

    def test_windows_inventory_incomplete_is_unknown_diagnostic_not_native_failure(self):
        result = mcp_server._native_response("vm_workflow", "windows-vm-baseline-inventory",
            {"ok": False, "state": "unknown", "inventoryComplete": False,
             "reason": "incomplete_or_conflicting_inventory", "nativeActionAllowed": False,
             "productAction": False}, {"host": "archlinux", "timeoutSeconds": 20})
        self.assertEqual("unknown", result["failureSignature"]["basis"]["classification"])
        self.assertEqual("complete all-process file-holder census and QEMU generation recheck",
                         result["admissionGap"]["missingFact"])

    def test_environment_status_unknown_probe_gap_does_not_record_native_failure(self):
        from agent_tools import native_failure_evidence
        with patch.object(native_failure_evidence, "record_failure",
                          side_effect=AssertionError("read-only status wrote failure receipt")):
            result = mcp_server._native_response("vm_workflow", "environment-status",
                {"ok": False, "state": "UNKNOWN", "requestedProbesReady": True,
                 "components": {"host": {"state": "available"}}},
                {"hostAlias": "archlinux", "observeHost": True})
        self.assertEqual("UNKNOWN", result["state"])
        self.assertNotIn("failureEvidence", result)
        self.assertNotIn("failureSignature", result)
        self.assertEqual("required environment receipts outside the requested live probes",
                         result["admissionGap"]["missingFact"])

    def test_windows_media_fingerprint_route_reports_bytes_without_publisher_claim(self):
        from agent_tools import windows_vm_baseline_inventory
        request = {"host": "archlinux", "timeoutSeconds": 180}
        sample = {"mediaFingerprintComplete": True, "nativeActionAllowed": False,
                  "media": {"windows": {"sha256": "a" * 64, "sizeBytes": 100}}}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_baseline_inventory, "media_fingerprint",
                          return_value=sample) as fingerprint:
            observed = mcp_server._vm_workflow_impl("windows-vm-media-fingerprint", request)
        fingerprint.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", timeout_seconds=180)
        self.assertEqual("observed", observed["state"])
        self.assertTrue(observed["ok"])
        self.assertFalse(observed["nativeActionAllowed"])
        self.assertNotIn("publisherVerified", observed)
        with patch.object(windows_vm_baseline_inventory, "media_fingerprint",
                          side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "fedora2328"}, {**request, "timeoutSeconds": 29},
                        {**request, "path": "/foreign.iso"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-media-fingerprint", bad)["ok"])

    def test_windows_disk_probe_routes_preserve_exact_one_shot_identity(self):
        from agent_tools import windows_vm_fresh_setup
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 60}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_fresh_setup, "probe_start", return_value={
                 "state": "partial", "correlationId": request["correlationId"],
                 "replayAllowed": False, "nativeActionAllowed": False}) as start:
            partial = mcp_server._vm_workflow_impl("windows-vm-disk-probe-start", request)
        self.assertFalse(partial["ok"])
        self.assertFalse(partial["replayAllowed"])
        start.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                      correlation_id=request["correlationId"], timeout_seconds=60)
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_fresh_setup, "probe_status", return_value={
                 "state": "verified", "correlationId": request["correlationId"],
                 "replayAllowed": False, "nativeActionAllowed": False}) as status:
            verified = mcp_server._vm_workflow_impl("windows-vm-disk-probe-status", request)
        self.assertTrue(verified["ok"])
        self.assertFalse(verified["nativeActionAllowed"])
        status.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                       correlation_id=request["correlationId"], timeout_seconds=60)
        with patch.object(windows_vm_fresh_setup, "probe_start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "fedora2328"}, {**request, "timeoutSeconds": 29},
                        {**request, "correlationId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
                        {**request, "sizeMiB": 96 * 1024}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-disk-probe-start", bad)["ok"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_fresh_setup, "probe_start", side_effect=ValueError("remote private detail")):
            unknown = mcp_server._vm_workflow_impl("windows-vm-disk-probe-start", request)
        self.assertEqual("unknown", unknown["state"])
        self.assertEqual(request["correlationId"], unknown["correlationId"])
        self.assertNotIn("remote private detail", str(unknown))
        detail = mcp_server._native_response("vm_workflow", "windows-vm-disk-probe-status",
            {"ok": False, "state": "partial", "correlationId": request["correlationId"],
             "replayAllowed": False, "nativeActionAllowed": False}, request)
        self.assertEqual("unknown", detail["failureSignature"]["basis"]["classification"])
        self.assertEqual("windows-vm-disk-probe-status",
                         detail["admissionGap"]["readOnlyAction"]["action"])

    def test_windows_fresh_preflight_is_bounded_read_only_and_no_start(self):
        from agent_tools import windows_vm_fresh_setup
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 180}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_fresh_setup, "preflight", return_value={
                 "state": "ready", "correlationId": request["correlationId"],
                 "nativeActionAllowed": False}) as preflight, \
             patch.object(windows_vm_fresh_setup, "start", side_effect=AssertionError("VM started")):
            ready = mcp_server._vm_workflow_impl("windows-vm-fresh-preflight", request)
        preflight.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                          correlation_id=request["correlationId"], timeout_seconds=180)
        self.assertTrue(ready["ok"])
        self.assertFalse(ready["nativeActionAllowed"])
        self.assertFalse(ready["productAction"])
        with patch.object(windows_vm_fresh_setup, "preflight", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "fedora2328"}, {**request, "timeoutSeconds": 301},
                        {**request, "reservationRequest": {}},
                        {**request, "correlationId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-fresh-preflight", bad)["ok"])

    def test_windows_fresh_start_status_require_exact_reservation(self):
        from agent_tools import windows_vm_fresh_setup
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        common = {"host": "archlinux", "correlationId": correlation, "timeoutSeconds": 180}
        reservation = {"hostAlias": "archlinux", "environment": "windows-vm-baseline-20260929",
                       "operator": "windows-baseline", "requestedMemoryBytes": 6442450944,
                       "allocationState": "pending", "reservationIdentity": {},
                       "measurement": {}, "headroomBytes": 8589934592}
        request = {**common, "reservationRequest": reservation}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_fresh_setup, "start", return_value={
                 "state": "running-unrecorded-observed", "correlationId": correlation,
                 "replayAllowed": False, "nativeActionAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("windows-vm-fresh-start", request)
        start.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                      correlation_id=correlation, reservation_request=reservation,
                                      timeout_seconds=180)
        self.assertEqual("running-unrecorded-observed", result["state"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["replayAllowed"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_vm_fresh_setup, "status", return_value={
                "state": "running-observed", "correlationId": correlation,
                "nativeActionAllowed": False}) as status:
            observed = mcp_server._vm_workflow_impl("windows-vm-fresh-status", common)
        status.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                       correlation_id=correlation, timeout_seconds=180)
        self.assertTrue(observed["ok"])
        with patch.object(windows_vm_fresh_setup, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "fedora2328"},
                        {**request, "reservationRequest": {**reservation, "operator": "other"}},
                        {**request, "reservationRequest": {**reservation, "extra": True}},
                        {**request, "timeoutSeconds": True},
                        {**request, "correlationId": correlation.upper()}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-fresh-start", bad)["ok"])

    def test_windows_fresh_screen_routes_return_only_bounded_observation(self):
        from agent_tools import windows_vm_fresh_setup
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "timeoutSeconds": 60}
        for action, method in (("windows-vm-fresh-screen-start", "screen_start"),
                               ("windows-vm-fresh-screen-status", "screen_status")):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_vm_fresh_setup, method, return_value={
                     "state": "observed", "correlationId": request["correlationId"],
                     "framePath": "/private/frame.ppm", "frameSha256": "a" * 64,
                     "width": 800, "height": 600, "nativeActionAllowed": False}) as dispatch:
                observed = mcp_server._vm_workflow_impl(action, request)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, host="archlinux",
                                             correlation_id=request["correlationId"], timeout_seconds=60)
            self.assertTrue(observed["ok"])
            self.assertFalse(observed["nativeActionAllowed"])
            self.assertNotIn("frameBytes", observed)
        with patch.object(windows_vm_fresh_setup, "screen_start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "reservationRequest": {}},
                        {**request, "timeoutSeconds": 301}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-vm-fresh-screen-start", bad)["ok"])

    def test_mac_server_stop_routes_keep_live_and_historical_evidence_distinct(self):
        from agent_tools import macos_machine_server_stop
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"schemaVersion": 1, "sourceSha": "a" * 40, "correlationId": correlation,
                   "scenario": "install", "jobId": "job", "operationId": correlation,
                   "bootSessionUuid": correlation, "reservationId": correlation,
                   "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                   "serverInstanceId": correlation, "serverPid": 1234,
                   "serverProcessStartIdentity": "darwin:123:456",
                   "readySha256": "c" * 64}
        actions = (("macos-machine-server-stop-start", "start", request, "unknown", False),
                   ("macos-machine-server-stop-status", "status", {"correlationId": correlation}, "complete", True),
                   ("macos-machine-server-stop-collect", "collect", {"correlationId": correlation},
                    "historical-receipt", False))
        for action, method, inputs, state, accepted in actions:
            response = {"state": state, "correlationId": correlation, "replayAllowed": False}
            if state == "historical-receipt":
                response["currentState"] = "unverified"
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(macos_machine_server_stop, method, return_value=response) as dispatch:
                result = mcp_server._vm_workflow_impl(action, inputs)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT,
                                             inputs if method == "start" else correlation)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["productAction"])
            self.assertFalse(result["nativeActionAllowed"])
        with patch.object(macos_machine_server_stop, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "extra": True}, {**request, "schemaVersion": True},
                        {**request, "serverPid": 0}, {**request, "sourceSha": "z" * 40}):
                self.assertFalse(mcp_server._vm_workflow_impl("macos-machine-server-stop-start", bad)["ok"])

    def test_linux_guest_park_routes_load_fixed_evidence_and_never_replay(self):
        from agent_tools import linux_guest_park
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"correlationId": correlation,
                   "preparationCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "guestRole": "ubuntu-update", "sourceSha": "c" * 40}
        for action, method, inputs, state, accepted in (
                ("linux-guest-park-preflight", "preflight", request, "ready", True),
                ("linux-guest-park-start", "start", request, "unknown", False),
                ("linux-guest-park-status", "status", {"correlationId": correlation}, "parked", True)):
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(linux_guest_park, "FixedRemoteDriver") as driver, \
                 patch.object(linux_guest_park, "Adapter") as adapter:
                getattr(adapter.return_value, method).return_value = {
                    "state": state, "correlationId": correlation, "replayAllowed": False}
                result = mcp_server._vm_workflow_impl(action, inputs)
                getattr(adapter.return_value, method).assert_called_once_with(
                    request if method != "status" else correlation)
                driver.assert_called_once_with(mcp_server.REPO_ROOT)
            self.assertEqual(accepted, result["ok"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["productAction"])
        with patch.object(linux_guest_park, "Adapter", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "guestRole": "other"}, {**request, "sourceSha": "z" * 40},
                        {**request, "preparationCorrelationId": correlation},
                        {**request, "guestManifest": {}}):
                self.assertFalse(mcp_server._vm_workflow_impl("linux-guest-park-start", bad)["ok"])

    def test_one_shot_fixture_boundary_preserves_correlation_without_replay(self):
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        cases = (
            ("linux-guest-park-start", {"correlationId": correlation}, "linux-guest-park-status"),
            ("macos-machine-server-stop-start", {"correlationId": correlation}, "macos-machine-server-stop-status"))
        for action, request, status_action in cases:
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_vm_workflow_impl", side_effect=RuntimeError("after intent")):
                result = mcp_server.vm_workflow(action, request)
            self.assertEqual("unknown", result["state"])
            self.assertEqual(correlation, result["correlationId"])
            self.assertFalse(result["replayAllowed"])
            self.assertFalse(result["nativeActionAllowed"])
            self.assertEqual(status_action, result["nextAction"]["action"]["action"])

    def test_linux_package_fixture_build_routes_preserve_one_shot_identity(self):
        from agent_tools import linux_package_fixture_build
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"sourceSha": "b" * 40, "baseVersion": "2.2.0",
                   "targetVersion": "2.2.1", "correlationId": correlation}
        actions = (("linux-package-fixture-build-preflight", "preflight", request,
                    {"state": "ready", "nativeActionAllowed": False}),
                   ("linux-package-fixture-build-start", "start", request,
                    {"state": "submitted", "correlationId": correlation, "replayAllowed": False}),
                   ("linux-package-fixture-build-status", "status", {"correlationId": correlation},
                    {"state": "running", "correlationId": correlation, "replayAllowed": False}),
                   ("linux-package-fixture-build-collect", "collect", {"correlationId": correlation},
                    {"state": "ready", "correlationId": correlation, "artifacts": [],
                     "timingReferences": {"sourceSha": request["sourceSha"], "phases": []},
                     "replayAllowed": False}))
        for action, method, inputs, response in actions:
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(linux_package_fixture_build, method, return_value=response) as dispatch:
                result = mcp_server._vm_workflow_impl(action, inputs)
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, inputs)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            if action.endswith("-collect"):
                self.assertEqual(request["sourceSha"], result["timingReferences"]["sourceSha"])
        with patch.object(linux_package_fixture_build, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "correlationId": correlation.upper()},
                        {**request, "sourceSha": "z" * 40},
                        {**request, "targetVersion": None}):
                self.assertFalse(mcp_server._vm_workflow_impl("linux-package-fixture-build-start", bad)["ok"])
        with patch.object(linux_package_fixture_build, "start", return_value={
                "state": "unknown", "correlationId": correlation, "replayAllowed": False}):
            unknown = mcp_server._vm_workflow_impl("linux-package-fixture-build-start", request)
        self.assertFalse(unknown["ok"])
        self.assertFalse(unknown["replayAllowed"])
        with patch.object(linux_package_fixture_build, "start", side_effect=RuntimeError("private transport")):
            bounded = mcp_server.vm_workflow("linux-package-fixture-build-start", request)
        self.assertEqual("unknown", bounded["state"])
        self.assertFalse(bounded["replayAllowed"])
        self.assertEqual("linux-package-fixture-build-status", bounded["nextAction"]["action"]["action"])

    def test_linux_package_build_pre_effect_routes_bind_exact_proof(self):
        from agent_tools import linux_package_fixture_build
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        digest = "b" * 64
        with patch.object(linux_package_fixture_build, "pre_effect_status", return_value={
                "state": "ready", "correlationId": correlation, "closureDigest": digest,
                "replayAllowed": False}) as observe:
            ready = mcp_server._vm_workflow_impl("linux-package-fixture-build-pre-effect-status",
                                                 {"correlationId": correlation})
        observe.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": correlation})
        self.assertTrue(ready["ok"])
        self.assertFalse(ready["nativeActionAllowed"])
        with patch.object(linux_package_fixture_build, "pre_effect_close", return_value={
                "state": "closed", "correlationId": correlation, "replayAllowed": False}) as close:
            closed = mcp_server._vm_workflow_impl("linux-package-fixture-build-pre-effect-close",
                {"correlationId": correlation, "closureDigest": digest})
        close.assert_called_once_with(mcp_server.REPO_ROOT,
            {"correlationId": correlation, "closureDigest": digest})
        self.assertTrue(closed["ok"])
        self.assertFalse(closed["productAction"])
        with patch.object(linux_package_fixture_build, "pre_effect_close",
                          side_effect=AssertionError("unsafe close")):
            for bad in ({"correlationId": correlation},
                        {"correlationId": correlation, "closureDigest": digest, "host": "other"},
                        {"correlationId": correlation, "closureDigest": "invalid"}):
                self.assertFalse(mcp_server._vm_workflow_impl(
                    "linux-package-fixture-build-pre-effect-close", bad)["ok"])

    def test_linux_package_build_terminal_ready_routes_bind_exact_proof(self):
        from agent_tools import linux_package_fixture_build
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        digest = "b" * 64
        with patch.object(linux_package_fixture_build, "terminal_ready_status", return_value={
                "state": "ready", "correlationId": correlation, "closureDigest": digest,
                "replayAllowed": False}) as observe:
            ready = mcp_server._vm_workflow_impl("linux-package-fixture-build-terminal-ready-status",
                                                 {"correlationId": correlation})
        observe.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": correlation})
        self.assertTrue(ready["ok"])
        self.assertFalse(ready["nativeActionAllowed"])
        with patch.object(linux_package_fixture_build, "terminal_ready_close", return_value={
                "state": "closed", "correlationId": correlation, "closureDigest": digest,
                "replayAllowed": False}) as close:
            closed = mcp_server._vm_workflow_impl("linux-package-fixture-build-terminal-ready-close",
                {"correlationId": correlation, "closureDigest": digest})
        close.assert_called_once_with(mcp_server.REPO_ROOT,
            {"correlationId": correlation, "closureDigest": digest})
        self.assertTrue(closed["ok"])
        self.assertFalse(closed["productAction"])
        with patch.object(linux_package_fixture_build, "terminal_ready_close",
                          side_effect=AssertionError("unsafe close")):
            for bad in ({"correlationId": correlation},
                        {"correlationId": correlation, "closureDigest": digest, "host": "other"},
                        {"correlationId": correlation, "closureDigest": "invalid"}):
                self.assertFalse(mcp_server._vm_workflow_impl(
                    "linux-package-fixture-build-terminal-ready-close", bad)["ok"])
        with patch.object(linux_package_fixture_build, "terminal_ready_status", return_value={
                "state": "unknown", "correlationId": correlation, "replayAllowed": False}):
            self.assertFalse(mcp_server._vm_workflow_impl(
                "linux-package-fixture-build-terminal-ready-status",
                {"correlationId": correlation})["ok"])
        with patch.object(linux_package_fixture_build, "terminal_ready_close", return_value={
                "state": "closed", "correlationId": correlation, "closureDigest": "c" * 64,
                "replayAllowed": False}):
            self.assertFalse(mcp_server._vm_workflow_impl(
                "linux-package-fixture-build-terminal-ready-close",
                {"correlationId": correlation, "closureDigest": digest})["ok"])

    def test_windows_owner_quit_routes_require_exact_request(self):
        from agent_tools import windows_msi_owner_observe
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "correlationId": correlation, "sourceSha": "a" * 40,
                   "controllerId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "installedCliSha256": "b" * 64, "parentPid": 3640,
                   "parentStartedAtUtc": "2026-09-25T10:18:47.4249100Z", "childPid": 5520,
                   "childStartedAtUtc": "2026-09-25T10:18:47.7734480Z",
                   "statusCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc"}
        routes = (("windows-msi-owner-quit-preflight", "quit_powershell_preflight", {"host": "archlinux"}),
                  ("windows-msi-owner-quit-start", "quit_start", request),
                  ("windows-msi-owner-quit-status", "quit_status", {"correlationId": correlation}),
                  ("windows-msi-owner-quit-collect", "quit_collect", {"correlationId": correlation}))
        for action, method, inputs in routes:
            with self.subTest(action=action), \
                 patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
                 patch.object(windows_msi_owner_observe, method, return_value={
                     "state": "passed" if action.endswith("preflight") else "running",
                     "correlationId": correlation, "replayAllowed": False}) as dispatch:
                result = mcp_server._vm_workflow_impl(action, inputs)
                self.assertTrue(result["ok"])
                dispatch.assert_called_once_with(mcp_server.REPO_ROOT, inputs)
        with patch.object(windows_msi_owner_observe, "quit_start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "host": "other"}, {**request, "extra": True},
                        {**request, "statusCorrelationId": "not-a-uuid"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-owner-quit-start", bad)["ok"])
        for state, expected in (("quit-complete", True), ("quit-partial", False), ("unknown", False)):
            with self.subTest(state=state), \
                 patch.object(windows_msi_owner_observe, "quit_status", return_value={
                     "state": state, "correlationId": correlation,
                     "replayAllowed": False}) as status:
                observed = mcp_server._vm_workflow_impl("windows-msi-owner-quit-status",
                    {"correlationId": correlation})
            status.assert_called_once()
            self.assertEqual(expected, observed["ok"])
            self.assertFalse(observed["replayAllowed"])
            if expected:
                from agent_tools import native_failure_evidence
                with patch.object(native_failure_evidence, "record_failure",
                                  side_effect=AssertionError("successful quit recorded failure")):
                    enriched = mcp_server._native_response("vm_workflow",
                        "windows-msi-owner-quit-status", observed, {"correlationId": correlation})
                self.assertNotIn("failureSignature", enriched)
                self.assertNotIn("failureEvidence", enriched)

    def test_windows_base_pre_effect_status_is_read_only_exact_host(self):
        from agent_tools import windows_msi_base_prepare
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_msi_base_prepare, "pre_effect_status", return_value={
                 "state": "absent", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}) as observe:
            result = mcp_server._vm_workflow_impl("windows-msi-base-pre-effect-status",
                                                  {"host": "archlinux"})
        observe.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["nativeActionAllowed"])
        with patch.object(windows_msi_base_prepare, "pre_effect_status", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({"host": "other"}, {"host": "archlinux", "correlationId": "other"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-base-pre-effect-status", bad)["ok"])

    def test_windows_base_pre_effect_close_requires_fixed_host_and_terminal_receipt(self):
        from agent_tools import windows_msi_base_prepare
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(windows_msi_base_prepare, "close_pre_effect", return_value={
                 "state": "pre-effect-closed", "replayAllowed": False,
                 "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}) as close:
            result = mcp_server._vm_workflow_impl("windows-msi-base-pre-effect-close",
                                                  {"host": "archlinux"})
        close.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        self.assertTrue(result["ok"])
        self.assertFalse(result["replayAllowed"])
        with patch.object(windows_msi_base_prepare, "close_pre_effect", return_value={
                "state": "unknown", "replayAllowed": False}):
            uncertain = mcp_server._vm_workflow_impl("windows-msi-base-pre-effect-close",
                                                       {"host": "archlinux"})
        self.assertFalse(uncertain["ok"])
        self.assertFalse(uncertain["replayAllowed"])
        with patch.object(windows_msi_base_prepare, "close_pre_effect", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({"host": "other"}, {"host": "archlinux", "correlationId": "other"}):
                self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-base-pre-effect-close", bad)["ok"])

    def test_android_host_fixture_routes_preserve_no_device_admission(self):
        from agent_tools import android_native_fixture_lifecycle
        campaign = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api29", "campaignId": campaign,
                   "planPath": "/private/fixture-plan.json", "certificatePath": "/private/cert.pem",
                   "privateKeyPath": "/private/key.pem"}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(android_native_fixture_lifecycle, "start", return_value={
                 "ok": True, "state": "running", "campaignId": campaign,
                 "deviceMutationAllowed": False, "installerTargetAdmitted": False}) as start:
            result = mcp_server._vm_workflow_impl("android-native-fixture-start", request)
        start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", campaign,
                                      "/private/fixture-plan.json", "/private/cert.pem", "/private/key.pem")
        self.assertFalse(result["deviceMutationAllowed"])
        self.assertFalse(result["installerTargetAdmitted"])
        for action, name in (("android-native-fixture-status", "status"),
                             ("android-native-fixture-stop", "stop"),
                             ("android-native-fixture-collect", "collect")):
            with self.subTest(action=action), \
                 patch.object(android_native_fixture_lifecycle, name, return_value={
                     "ok": False, "state": "unknown", "campaignId": campaign,
                     "replayAllowed": False}) as method:
                observed = mcp_server._vm_workflow_impl(action, {"campaignId": campaign})
                method.assert_called_once_with(mcp_server.REPO_ROOT, campaign)
                self.assertFalse(observed["installerTargetAdmitted"])
                self.assertFalse(observed["deviceMutationAllowed"])
        with patch.object(android_native_fixture_lifecycle, "start", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "planPath": "relative.json"},
                        {**request, "device": "API29"}, {**request, "secretBytes": "data"}):
                self.assertFalse(mcp_server._vm_workflow_impl("android-native-fixture-start", bad)["ok"])

    def test_linux_deb_arch_preparation_and_acceptance_routes_are_exact_one_shot(self):
        from agent_tools import (linux_deb_arch_guest_prepare as preparation,
                                 linux_deb_arch_acceptance as acceptance,
                                 linux_deb_arch_guest_prepare_remote as remote,
                                 linux_deb_arch_host_supervisor as supervisor,
                                 linux_deb_arch_transport as transport)
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        artifacts = {key: "sha256-" + "a" * 64 for key in
                     ("fixtureReceipt", "basePackage", "targetPackage", "bundleManifest")}
        request = {"profile": "package-update", "distribution": "arch", "correlationId": correlation,
                   "sourceSha": "b" * 40, "artifactIds": artifacts}
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(preparation, "preflight", return_value={"inputsVerified": True,
                                                                     "nativeActionAllowed": False}) as preflight:
            checked = mcp_server._vm_workflow_impl("linux-deb-arch-guest-prepare-preflight", request)
        self.assertTrue(checked["ok"])
        self.assertFalse(checked["nativeActionAllowed"])
        preflight.assert_called_once()
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(remote, "FixedRemoteDriver") as driver, \
             patch.object(preparation, "Adapter") as adapter:
            adapter.return_value.start.return_value = {"state": "unknown", "correlationId": correlation,
                                                        "replayAllowed": False}
            unknown = mcp_server._vm_workflow_impl("linux-deb-arch-guest-prepare-start", request)
            adapter.return_value.start.assert_called_once_with(request)
            driver.assert_called_once_with(mcp_server.REPO_ROOT)
        self.assertFalse(unknown["ok"])
        self.assertFalse(unknown["replayAllowed"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(supervisor, "FixedHostSupervisor") as driver, \
             patch.object(transport, "FixedLiveObserver") as observer, \
             patch.object(acceptance, "Adapter") as adapter:
            adapter.return_value.status.return_value = {"state": "terminal", "result": "rollback-restored",
                                                         "correlationId": correlation, "replayAllowed": False}
            terminal = mcp_server._vm_workflow_impl("linux-deb-arch-acceptance-status",
                                                     {"correlationId": correlation})
            adapter.return_value.status.assert_called_once_with(correlation)
            driver.assert_called_once_with(mcp_server.REPO_ROOT)
            observer.assert_called_once_with(mcp_server.REPO_ROOT)
        self.assertTrue(terminal["ok"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(supervisor, "FixedHostSupervisor"), \
             patch.object(transport, "FixedLiveObserver"), \
             patch.object(acceptance, "Adapter") as adapter:
            adapter.return_value.preflight.return_value = {"ready": False,
                                                             "nativeActionAllowed": False}
            blocked = mcp_server._vm_workflow_impl("linux-deb-arch-acceptance-preflight", request)
            adapter.return_value.preflight.assert_called_once_with(request)
        self.assertFalse(blocked["ok"])
        self.assertFalse(blocked["nativeActionAllowed"])
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 2**63 - 1), \
             patch.object(supervisor, "FixedHostSupervisor"), \
             patch.object(transport, "FixedLiveObserver"), \
             patch.object(acceptance, "Adapter") as adapter:
            adapter.return_value.start.return_value = {"state": "unknown", "correlationId": correlation,
                                                        "replayAllowed": False}
            unknown = mcp_server._vm_workflow_impl("linux-deb-arch-acceptance-start", request)
            adapter.return_value.start.assert_called_once_with(request)
        self.assertFalse(unknown["ok"])
        self.assertFalse(unknown["replayAllowed"])
        with patch.object(preparation, "Adapter", side_effect=AssertionError("unsafe dispatch")):
            for bad in ({**request, "artifactIds": {}}, {**request, "extra": True}):
                self.assertFalse(mcp_server._vm_workflow_impl("linux-deb-arch-guest-prepare-start", bad)["ok"])

    def test_artifact_cache_requires_verified_same_source(self):
        from agent_tools import native_artifact_reuse
        source = "a" * 40
        base = {"decision": "same-source", "verification": "verified",
                "currentSourceSha": source, "originalSourceSha": source,
                "reasons": [], "nativeAdmissionReady": False}
        with patch.object(mcp_server.subprocess, "check_output", return_value=source), \
             patch.object(native_artifact_reuse, "artifact_reuse_check", return_value=base):
            result = mcp_server._vm_workflow_impl("artifact-cache-check",
                {"sourceSha": source, "artifactSetId": "set"})
        self.assertTrue(result["cacheEligible"])
        self.assertFalse(result["nativeActionAllowed"])
        for changed in ({"verification": "mismatch"}, {"decision": "verified-equivalent-product-inputs"},
                        {"currentSourceSha": "b" * 40}, {"reasons": ["dirty product"]}):
            with patch.object(mcp_server.subprocess, "check_output", return_value=source), \
                 patch.object(native_artifact_reuse, "artifact_reuse_check", return_value={**base, **changed}):
                self.assertFalse(mcp_server._vm_workflow_impl("artifact-cache-check",
                    {"sourceSha": source, "artifactSetId": "set"})["cacheEligible"])
        self.assertFalse(mcp_server._vm_workflow_impl("artifact-cache-check",
            {"sourceSha": source, "artifactSetId": "set", "command": "build"})["ok"])

    def test_vm_preflight_batch_parallel_and_fail_closed(self):
        import threading
        from agent_tools import native_acceptance_overview
        barrier = threading.Barrier(2)
        def observe(action, inputs):
            barrier.wait(timeout=2)
            if action == "environment-status":
                return {"ok": True, "state": "READY", "source": "live-tool",
                        "ready": True, "productAction": False}
            return {"ok": True, "inventoryComplete": True,
                    "nativeActionAllowed": False, "productAction": False}
        reads = {"reads": [
            {"id": "ubuntu", "action": "environment-status", "inputs": {"hostAlias": "archlinux"}},
            {"id": "arch", "action": "linux-vm-readonly-inventory",
             "inputs": {"host": "archlinux", "timeoutSeconds": 5}},
        ]}
        result = native_acceptance_overview.batch_preflight(reads, observe)
        self.assertTrue(result["observationsComplete"])
        self.assertFalse(result["nativeActionAllowed"])
        unknown = native_acceptance_overview.batch_preflight(reads,
            lambda action, inputs: {"ok": False, "state": "unknown"})
        self.assertFalse(unknown["observationsComplete"])
        self.assertEqual("unknown", unknown["state"])
        with self.assertRaisesRegex(ValueError, "read-only"):
            native_acceptance_overview.batch_preflight({"reads": [
                {"id": "unsafe", "action": "environment-reserve", "inputs": {}}]}, observe)
        with self.assertRaisesRegex(ValueError, "repeated"):
            native_acceptance_overview.batch_preflight({"reads": [reads["reads"][0], reads["reads"][0]]}, observe)

    def test_android_consent_preflight_exact_route(self):
        from agent_tools import android_consent_acceptance
        request = {"host": "archlinux", "device": "api29",
                   "cliStageCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(android_consent_acceptance, "preflight", return_value={
            "ok": False, "state": "unknown", "code": "stage_unknown", "productAction": False}) as preflight:
            result = mcp_server._vm_workflow_impl("android-consent-acceptance-preflight", request)
        self.assertFalse(result["ok"])
        self.assertFalse(result["productAction"])
        preflight.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", request["cliStageCorrelationId"])
        self.assertFalse(mcp_server._vm_workflow_impl("android-consent-acceptance-preflight",
            {**request, "command": "start"})["ok"])

    def test_linux_workspace_cleanup_route_requires_exact_terminal_proof(self):
        from agent_tools import linux_rpm_workspace_recovery
        request = {"correlationId": "944447ff-7ee3-42df-8ca8-f02dac670459",
                   "cleanupCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_rpm_workspace_recovery, "cleanup_start", return_value={
            "state": "unknown", "correlationId": request["cleanupCorrelationId"],
            "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("linux-rpm-workspace-cleanup-start", request)
        self.assertFalse(result["ok"])
        self.assertTrue(result["productAction"])
        start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_workspace_recovery, "cleanup_status", return_value={
            "state": "terminal", "result": "passed", "workspaceRemoved": True,
            "replayAllowed": False}) as status:
            result = mcp_server._vm_workflow_impl("linux-rpm-workspace-cleanup-status",
                {"cleanupCorrelationId": request["cleanupCorrelationId"]})
        self.assertTrue(result["ok"])
        status.assert_called_once()
        self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-workspace-cleanup-start",
            {**request, "shell": "rm"})["ok"])
        self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-workspace-cleanup-status",
            {"cleanupCorrelationId": "not-a-uuid"})["ok"])

    def test_build_timing_report_is_source_bound_and_marks_missing_phases(self):
        import hashlib
        import json
        import os
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from agent_tools import native_build_timing
        source = "a" * 40
        run = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with TemporaryDirectory() as raw:
            root = Path(raw)
            directory = root / ".rag_index" / "build-timings"
            directory.mkdir(parents=True)
            os.chmod(directory.parent, 0o700)
            os.chmod(directory, 0o700)
            record = {"schemaVersion": 1, "sourceSha": source, "pipelineId": "linux-rpm",
                      "runId": run, "hostAlias": "archlinux", "phase": "gradle",
                      "startedMonotonicNs": 100, "finishedMonotonicNs": 10_000_100}
            path = directory / "gradle.json"
            raw_bytes = json.dumps(record).encode()
            path.write_bytes(raw_bytes)
            os.chmod(path, 0o600)
            request = {"sourceSha": source, "pipelineId": "linux-rpm", "runId": run,
                       "receipts": [{"path": ".rag_index/build-timings/gradle.json",
                                     "sha256": hashlib.sha256(raw_bytes).hexdigest()}]}
            result = native_build_timing.report(root, source, request)
            self.assertEqual("gradle", result["largestMeasuredPhase"])
            self.assertFalse(result["allPhasesMeasured"])
            self.assertEqual(4, sum(p["state"] == "unmeasured" for p in result["phases"]))
            self.assertFalse(result["nativeActionAllowed"])
            with self.assertRaisesRegex(ValueError, "source"):
                native_build_timing.report(root, "b" * 40, request)
            with self.assertRaisesRegex(ValueError, "bytes"):
                native_build_timing.report(root, source, {**request,
                    "receipts": [{**request["receipts"][0], "sha256": "0" * 64}]})
            path.unlink()
            self.assertFalse(path.exists())
            empty = native_build_timing.report(root, source, {**request, "receipts": []})
            self.assertEqual("unmeasured", empty["state"])

    def test_build_timing_route_does_not_promote_unmeasured_to_complete(self):
        from agent_tools import native_build_timing
        source = "a" * 40
        request = {"sourceSha": source, "pipelineId": "linux-rpm",
                   "runId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "receipts": []}
        with patch.object(mcp_server.subprocess, "check_output", return_value=source), \
             patch.object(native_build_timing, "report", return_value={
                 "state": "unmeasured", "allPhasesMeasured": False,
                 "nativeActionAllowed": False, "productAction": False}):
            result = mcp_server._vm_workflow_impl("build-timing-report", request)
        self.assertTrue(result["ok"])
        self.assertFalse(result["allPhasesMeasured"])

    def test_mcp_boundary_adds_valid_correlation_and_disallows_unknown_replay(self):
        from agent_tools import native_failure_evidence, native_next_action
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with patch.object(native_next_action, "next_action", return_value={}), \
             patch.object(native_failure_evidence, "record_failure", return_value={"state": "recorded"}):
            unknown = mcp_server._native_response("vm_workflow", "fixture-status",
                {"ok": False, "state": "unknown"}, {"correlationId": correlation})
            self.assertEqual(correlation, unknown["correlationId"])
            self.assertFalse(unknown["replayAllowed"])
            unsafe = mcp_server._native_response("vm_workflow", "fixture-status",
                {"ok": False, "state": "unknown", "replayAllowed": True},
                {"correlationId": correlation})
            self.assertFalse(unsafe["replayAllowed"])
            typed = mcp_server._native_response("vm_workflow", "fixture-status",
                {"ok": False, "state": "unknown", "failurePhase": "owner_probe",
                 "failureType": "process_identity_changed"}, {"correlationId": correlation})
            self.assertEqual({"phase": "owner_probe", "failureType": "process_identity_changed"},
                             typed["uncertainty"])
            untyped = mcp_server._native_response("vm_workflow", "fixture-status",
                {"ok": False, "state": "unknown", "failurePhase": "owner_probe",
                 "failureType": "unexpected; command"}, {"correlationId": correlation})
            self.assertNotIn("uncertainty", untyped)
            malformed = mcp_server._native_response("vm_workflow", "fixture-status",
                {"ok": True, "state": "ready"}, {"correlationId": "untrusted"})
            self.assertNotIn("correlationId", malformed)

    def test_failure_signature_groups_cause_without_erasing_correlation_or_receipt(self):
        from agent_tools import native_failure_evidence, native_next_action
        first = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        second = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        with patch.object(native_next_action, "next_action", return_value={}), \
             patch.object(native_failure_evidence, "record_failure", side_effect=[
                 {"evidenceId": "native-failure-one"}, {"evidenceId": "native-failure-two"}]):
            a = mcp_server._native_response("vm_workflow", "linux-rpm-workspace-cleanup-start",
                {"ok": False, "state": "unknown", "reason": "workspace-reference-unknown"},
                {"correlationId": first})
            b = mcp_server._native_response("vm_workflow", "linux-rpm-workspace-cleanup-start",
                {"ok": False, "state": "unknown", "reason": "workspace-reference-unknown"},
                {"correlationId": second})
        self.assertNotEqual(a["correlationId"], b["correlationId"])
        self.assertNotEqual(a["failureEvidence"], b["failureEvidence"])
        self.assertEqual(a["failureSignature"]["fingerprint"], b["failureSignature"]["fingerprint"])
        self.assertIn("test_cleanup_requires_absent_scanner", a["failureSignature"]["causalRegression"])
        self.assertFalse(a["admissionGap"]["nativeActionAllowed"])
        self.assertEqual({"tool": "vm_workflow", "action": "linux-rpm-workspace-cleanup-status",
                          "inputs": {"cleanupCorrelationId": first}},
                         a["admissionGap"]["readOnlyAction"])
        self.assertEqual({"tool": "vm_workflow", "action": "linux-rpm-workspace-cleanup-status",
                          "inputs": {"cleanupCorrelationId": second}},
                         b["admissionGap"]["readOnlyAction"])

    def test_admission_gap_uses_only_adapter_correlation_for_safe_status(self):
        from agent_tools import native_response_diagnostics
        cleanup = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        described = native_response_diagnostics.describe("vm_workflow",
            "linux-rpm-workspace-cleanup-start",
            {"state": "unknown", "reason": "existing-intent", "correlationId": cleanup})
        self.assertEqual({"tool": "vm_workflow", "action": "linux-rpm-workspace-cleanup-status",
                          "inputs": {"cleanupCorrelationId": cleanup}},
                         described["admissionGap"]["readOnlyAction"])
        foreign = native_response_diagnostics.describe("vm_workflow",
            "linux-rpm-workspace-cleanup-start",
            {"state": "unknown", "reason": "existing-intent", "correlationId": "bad"})
        self.assertIsNone(foreign["admissionGap"]["readOnlyAction"])
        self.assertEqual("terminal status of the existing cleanup intent",
                         foreign["admissionGap"]["missingFact"])

    def test_loaded_native_adapter_changed_after_mcp_boot_requires_fresh_process(self):
        with patch.object(mcp_server, "_MCP_BOOT_TIME_NS", 0, create=True):
            with self.assertRaisesRegex(ValueError, "MCP adapter source changed"):
                mcp_server._agent_module("android_package_install")

    def test_preflight_routes_current_readiness_without_promoting_failure(self):
        from agent_tools import native_fixture_preflight
        request = {"scenarioId": "linux-public-update-preflight"}
        with patch.object(native_fixture_preflight, "check", return_value={"ready": False}) as check:
            result = mcp_server._vm_workflow_impl("fixture-preflight", request)
        self.assertFalse(result["ok"])
        check.assert_called_once_with(mcp_server.REPO_ROOT, request, mcp_server._native_fixed_dispatch)

    def test_artifact_mismatch_and_rebuild_are_not_success(self):
        from agent_tools import native_artifact_reuse
        with patch.object(native_artifact_reuse, "artifact_set_verify", return_value={"verification": "mismatch"}):
            self.assertFalse(mcp_server._vm_workflow_impl("artifact-set-verify", {"artifactSetId": "id"})["ok"])
        with patch.object(native_artifact_reuse, "artifact_reuse_check", return_value={"decision": "rebuild-required"}):
            self.assertFalse(mcp_server._vm_workflow_impl("artifact-reuse-check", {"artifactSetId": "id"})["ok"])

    def test_rpm_proc_observation_keeps_unreadable_processes_unknown(self):
        from agent_tools import native_rpm_public_install_ssh
        request = {"host": "fedora2328", "environment": "fedora2328"}
        with patch.object(native_rpm_public_install_ssh, "observe_proc", return_value={"ok": True, "procState": "unknown", "uninspectable": [{"pid": 123}]}) as observe:
            result = mcp_server._vm_workflow_impl("rpm-proc-observe", request)
        self.assertFalse(result["ok"])
        self.assertEqual("unknown", result["procState"])
        self.assertEqual("unknown", result["state"])
        observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(native_rpm_public_install_ssh, "observe_proc", return_value={"procState": "clear", "uninspectable": []}):
            self.assertTrue(mcp_server._vm_workflow_impl("rpm-proc-observe", request)["ok"])

    def test_privileged_rpm_proc_observer_only_promotes_clear_state(self):
        from agent_tools import native_rpm_public_install_ssh
        request = {"host": "fedora2328", "environment": "fedora2328"}
        with patch.object(native_rpm_public_install_ssh, "observe_proc_privileged", return_value={"ok": True, "procState": "unknown"}) as observe:
            result = mcp_server._vm_workflow_impl("rpm-proc-observe-privileged", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(native_rpm_public_install_ssh, "observe_proc_privileged", return_value={"procState": "clear"}):
            self.assertTrue(mcp_server._vm_workflow_impl("rpm-proc-observe-privileged", request)["ok"])

    def test_linux_fixture_route_distinguishes_dispatch_uncertainty_from_verified_artifact(self):
        from agent_tools import linux_update_fixture_workflow
        request = {"sourceSha": "a" * 40, "baseVersion": "2.1.19", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_update_fixture_workflow, "dispatch", return_value={"state": "unknown", "replayAllowed": False}) as dispatch:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-dispatch", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_update_fixture_workflow, "status", return_value={"state": "complete", "artifactId": 81}) as status:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-status", {"correlationId": request["correlationId"]})
            self.assertTrue(result["ok"])
            self.assertEqual("fixture-build", result["evidenceClass"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        with patch.object(linux_update_fixture_workflow, "status", side_effect=ValueError("Invalid inputs")):
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-fixture-status", {"correlationId": request["correlationId"], "shell": "id"})["ok"])

    def test_linux_https_server_route_preserves_unknown_and_requires_fresh_ready(self):
        from agent_tools import linux_rpm_fixture_server_lifecycle
        request = {"sourceSha": "a" * 40, "scenarioId": "linux-rpm-public-install-recovery",
                   "host": "fedora2328", "environment": "fedora2328", "bundleHash": "b" * 64,
                   "artifactIds": {}, "credentialHandle": "opaque",
                   "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        observe = {"correlationId": request["correlationId"]}
        with patch.object(linux_rpm_fixture_server_lifecycle, "start", return_value={"state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-server-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_fixture_server_lifecycle, "status", return_value={"state": "ready", "correlationId": request["correlationId"]}) as status:
            self.assertTrue(mcp_server._vm_workflow_impl("linux-rpm-fixture-server-status", observe)["ok"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, observe)
        with patch.object(linux_rpm_fixture_server_lifecycle, "collect", return_value={"state": "unknown", "replayAllowed": False}):
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-fixture-server-collect", observe)["ok"])
        with patch.object(linux_rpm_fixture_server_lifecycle, "status", side_effect=ValueError("invalid observation")):
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-fixture-server-status", {**observe, "shell": "id"})["ok"])

    def test_linux_https_server_stop_route_requires_exact_terminal_pidfd_proof(self):
        from agent_tools import linux_rpm_fixture_server_lifecycle
        observe = {"correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_rpm_fixture_server_lifecycle, "stop", return_value={
            "state": "unknown", "replayAllowed": False}) as stop:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-server-stop", observe)
            self.assertFalse(result["ok"])
            stop.assert_called_once_with(mcp_server.REPO_ROOT, observe)
        with patch.object(linux_rpm_fixture_server_lifecycle, "stop", return_value={
            "state": "terminal", "result": "stopped", "pidfdExitObserved": True,
            "replayAllowed": False}) as stop:
            result = mcp_server._vm_workflow_impl("linux-rpm-fixture-server-stop", observe)
            self.assertTrue(result["ok"])
            stop.assert_called_once_with(mcp_server.REPO_ROOT, observe)
        self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-fixture-server-stop", {**observe, "shell": "id"})["ok"])

    def test_linux_vm_inventory_route_is_fixed_and_read_only(self):
        from agent_tools import linux_vm_readonly_inventory
        with patch.object(linux_vm_readonly_inventory, "observe", return_value={
                "inventoryComplete": True, "nativeActionAllowed": False, "guests": {}}) as observe:
            result = mcp_server._vm_workflow_impl("linux-vm-readonly-inventory",
                                                  {"host": "archlinux", "timeoutSeconds": 20})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", timeout_seconds=20)
            self.assertFalse(mcp_server._vm_workflow_impl("linux-vm-readonly-inventory",
                {"host": "archlinux", "timeoutSeconds": 20, "shell": "id"})["ok"])

    def test_linux_rpm_workspace_recovery_status_is_exact_read_only(self):
        from agent_tools import linux_rpm_workspace_recovery
        inputs = {"correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_rpm_workspace_recovery, "status", return_value={
                "state": "observed", "scannerState": "referenced",
                "referencePid": 123, "referenceStartTicks": 456}) as status:
            result = mcp_server._vm_workflow_impl("linux-rpm-workspace-recovery-status", inputs)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, inputs)
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-workspace-recovery-status",
                {**inputs, "shell": "id"})["ok"])
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-workspace-recovery-status",
                {"correlationId": "not-a-uuid"})["ok"])
        with patch.object(linux_rpm_workspace_recovery, "status", return_value={
                "state": "unknown", "scannerReason": "scanner-unavailable"}):
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-workspace-recovery-status", inputs)["ok"])

    def test_windows_fixture_route_requires_correlated_artifact_collection(self):
        from agent_tools import windows_update_fixture_workflow
        request = {"sourceSha": "a" * 40, "baseVersion": "2.1.19",
                   "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(windows_update_fixture_workflow, "dispatch", return_value={"state": "unknown", "replayAllowed": False}) as dispatch:
            result = mcp_server._vm_workflow_impl("windows-msi-fixture-dispatch", request)
            self.assertFalse(result["ok"])
            dispatch.assert_called_once_with(mcp_server.REPO_ROOT, request)
        status_request = {"correlationId": request["correlationId"]}
        with patch.object(windows_update_fixture_workflow, "status", return_value={"state": "complete", "replayAllowed": False}) as status:
            self.assertTrue(mcp_server._vm_workflow_impl("windows-msi-fixture-status", status_request)["ok"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, status_request)
        with patch.object(windows_update_fixture_workflow, "collect", return_value={"state": "unknown", "replayAllowed": False}) as collect:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-fixture-collect", status_request)["ok"])
            collect.assert_called_once_with(mcp_server.REPO_ROOT, status_request)
        with patch.object(windows_update_fixture_workflow, "collect", return_value={"state": "collected", "replayAllowed": False}):
            self.assertTrue(mcp_server._vm_workflow_impl("windows-msi-fixture-collect", status_request)["ok"])
        with patch.object(windows_update_fixture_workflow, "failed_log", return_value={"state": "failed-log", "replayAllowed": False}) as failed_log:
            self.assertTrue(mcp_server._vm_workflow_impl("windows-msi-fixture-failed-log", status_request)["ok"])
            failed_log.assert_called_once_with(mcp_server.REPO_ROOT, status_request)

    def test_windows_server_python_preflight_is_read_only_and_exact(self):
        from agent_tools import windows_update_fixture_server
        request = {"host": "archlinux", "leaseId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "stageCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "serverCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                   "sourceSha": "d" * 40, "fixtureReceiptArtifactId": "sha256-" + "e" * 64,
                   "baseMsiArtifactId": "sha256-" + "f" * 64,
                   "targetMsiArtifactId": "sha256-" + "1" * 64}
        with patch.object(windows_update_fixture_server, "python_preflight",
                          return_value={"state": "observed", "serverReady": False}) as preflight:
            result = mcp_server._vm_workflow_impl("windows-fixture-python-preflight", request)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, request)
            self.assertFalse(mcp_server._vm_workflow_impl("windows-fixture-python-preflight", {**request, "command": "id"})["ok"])
            preflight.assert_called_once()

    def test_linux_public_owner_quit_route_keeps_uncertain_exit_unverified(self):
        from agent_tools import linux_owner_public_quit
        request = {"host": "fedora2328", "environment": "fedora2328", "pid": 18367,
                   "startTicks": 2078693, "controllerId": "1780cc81-65a6-4284-a424-2178b94e2690",
                   "approval": "explicit-user-approved-disposable-owner-quit",
                   "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_owner_public_quit, "start", return_value={"state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("linux-owner-public-quit-start", request)
            self.assertFalse(result["ok"])
            self.assertTrue(result["productAction"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        observation = {"correlationId": request["correlationId"]}
        with patch.object(linux_owner_public_quit, "status", return_value={"state": "terminal", "result": "passed", "ownerGenerationGone": True}) as status:
            self.assertTrue(mcp_server._vm_workflow_impl("linux-owner-public-quit-status", observation)["ok"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, observation)
        with patch.object(linux_owner_public_quit, "collect", return_value={"state": "failed", "replayAllowed": False}) as collect:
            self.assertFalse(mcp_server._vm_workflow_impl("linux-owner-public-quit-collect", observation)["ok"])
            collect.assert_called_once_with(mcp_server.REPO_ROOT, observation)

    def test_linux_protected_job_inventory_is_read_only_diagnostic(self):
        from agent_tools import linux_rpm_protected_job_observe
        request = {"host": "fedora2328", "environment": "fedora2328"}
        with patch.object(linux_rpm_protected_job_observe, "observe", return_value={"state": "observed", "jobs": []}) as observe:
            result = mcp_server._vm_workflow_impl("linux-rpm-protected-job-observe", request)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_protected_job_observe, "observe", return_value={"state": "unknown"}):
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-protected-job-observe", request)["ok"])

    def test_linux_base_prepare_route_preserves_no_replay_and_terminal_failure(self):
        from agent_tools import linux_rpm_base_prepare
        preflight = {"host": "fedora2328", "environment": "fedora2328",
                     "expectedCurrentNevra": "vpn-control-2.1.17-1.x86_64"}
        with patch.object(linux_rpm_base_prepare, "preflight", return_value={"state": "ready"}) as observe:
            result = mcp_server._vm_workflow_impl("linux-rpm-base-prepare-preflight", preflight)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, preflight)
        request = {"host": "fedora2328", "environment": "fedora2328", "baseArtifactId": "sha256-" + "a" * 64,
                   "sourceSha": "b" * 40, "sourceFingerprint": "c" * 64,
                   "expectedCurrentNevra": "vpn-control-2.1.17-1.x86_64",
                   "expectedBaseNevra": "vpn-control-2.1.19-1.x86_64",
                   "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
        with patch.object(linux_rpm_base_prepare, "start", return_value={"state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("linux-rpm-base-prepare-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_base_prepare, "status", return_value={"state": "terminal", "result": "failed"}) as status:
            result = mcp_server._vm_workflow_impl("linux-rpm-base-prepare-status", {"correlationId": request["correlationId"]})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        with patch.object(linux_rpm_base_prepare, "status", side_effect=ValueError("Invalid fields")) as status:
            self.assertFalse(mcp_server._vm_workflow_impl("linux-rpm-base-prepare-status", {"correlationId": request["correlationId"], "command": "rpm"})["ok"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"], "command": "rpm"})

    def test_linux_owner_observation_is_read_only_and_requires_observed_state(self):
        from agent_tools import linux_rpm_base_prepare
        request = {"host": "fedora2328", "environment": "fedora2328", "pid": 18367, "startTicks": 2078693}
        with patch.object(linux_rpm_base_prepare, "observe_owner", return_value={"state": "unknown"}) as observe:
            result = mcp_server._vm_workflow_impl("linux-rpm-owner-observe", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(linux_rpm_base_prepare, "observe_owner", return_value={"state": "observed", "runtimeRunning": False}):
            self.assertTrue(mcp_server._vm_workflow_impl("linux-rpm-owner-observe", request)["ok"])

    def test_android_admission_readback_requires_exact_inputs_and_actual_admission(self):
        from agent_tools import android_admission_readback
        request = {"host": "archlinux", "device": "api35", "correlationId": "ad399bdd-25cb-4f71-857e-34ad18ae0399"}
        with patch.object(android_admission_readback, "readback", return_value={"ok": True, "outcome": "unknown"}) as readback:
            unknown = mcp_server._vm_workflow_impl("android-admission-readback", request)
            self.assertFalse(unknown["ok"])
            self.assertEqual("unknown", unknown["state"])
            readback.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", request["correlationId"],
                expected_base_sha256=None, timeout_seconds=45)
        with patch.object(android_admission_readback, "readback") as readback:
            self.assertFalse(mcp_server._vm_workflow_impl("android-admission-readback", {**request, "shell": "id"})["ok"])
            readback.assert_not_called()
        with patch.object(android_admission_readback, "readback", return_value={"outcome": "admitted"}):
            self.assertTrue(mcp_server._vm_workflow_impl("android-admission-readback", request)["ok"])

    def test_android_admission_status_observes_exact_correlation_without_replay(self):
        from agent_tools import android_admission_readback
        request = {"host": "archlinux", "device": "api35", "correlationId": "a4a2f73c-6c99-4028-a846-a4c63f21f6d6"}
        with patch.object(android_admission_readback, "readback_status", return_value={"ok": False, "outcome": "unknown"}) as observe:
            result = mcp_server._vm_workflow_impl("android-admission-status", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request["host"], request["device"], request["correlationId"], timeout_seconds=45)
        with patch.object(android_admission_readback, "readback_status") as observe:
            self.assertFalse(mcp_server._vm_workflow_impl("android-admission-status", {**request, "newRequest": True})["ok"])
            observe.assert_not_called()

    def test_android_admission_preflight_preserves_completed_stages_on_timeout(self):
        from agent_tools import android_admission_readback
        request = {"host": "archlinux", "device": "api35", "correlationId": "a4a2f73c-6c99-4028-a846-a4c63f21f6d6"}
        stage = {"stage": "uid", "ok": True}
        with patch.object(android_admission_readback, "preflight", return_value={"ok": True, "outcome": "unknown", "completedStages": [stage]}) as preflight:
            result = mcp_server._vm_workflow_impl("android-admission-preflight", request)
            self.assertFalse(result["ok"])
            self.assertEqual("unknown", result["state"])
            self.assertEqual([stage], result["completedStages"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", request["correlationId"], timeout_seconds=60)
        with patch.object(android_admission_readback, "preflight") as preflight:
            self.assertFalse(mcp_server._vm_workflow_impl("android-admission-preflight", {**request, "command": "shell"})["ok"])
            preflight.assert_not_called()

    def test_android_async_readback_routes_exact_nonreplaying_correlation(self):
        from agent_tools import android_admission_readback
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api35", "correlationId": correlation,
                   "expectedBaseSha256": "a" * 64}
        with patch.object(android_admission_readback, "async_start", return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-readback-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", correlation, "a" * 64)
        with patch.object(android_admission_readback, "async_start") as start:
            self.assertFalse(mcp_server._vm_workflow_impl("android-readback-start", {**request, "shell": "id"})["ok"])
            start.assert_not_called()
        with patch.object(android_admission_readback, "async_status", return_value={"ok": False, "state": "running", "replayAllowed": False}) as status:
            result = mcp_server._vm_workflow_impl("android-readback-status", {"correlationId": correlation})
            self.assertTrue(result["ok"])
            self.assertEqual("running", result["state"])
            self.assertFalse(result["admissionReady"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
        with patch.object(android_admission_readback, "async_collect", return_value={"ok": True, "state": "complete", "replayAllowed": False}) as collect:
            result = mcp_server._vm_workflow_impl("android-readback-collect", {"correlationId": correlation})
            self.assertTrue(result["ok"])
            self.assertTrue(result["admissionReady"])
            self.assertFalse(result["productAction"])
            collect.assert_called_once_with(mcp_server.REPO_ROOT, correlation)

    def test_android_package_install_route_never_promotes_unknown_or_collect_to_mutation_admission(self):
        from agent_tools import android_package_install
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api35", "correlationId": correlation,
                   "artifactId": "sha256-" + "b" * 64, "stageIdentity": {"correlationId": "stage"},
                   "backupCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                   "expectedBackupSha256": "d" * 64, "expectedOldBaseSha256": "e" * 64,
                   "expectedOwner": "owner", "expectedRevision": 2}
        with patch.object(android_package_install, "start", return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-package-install-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once()
        with patch.object(android_package_install, "start") as start:
            self.assertFalse(mcp_server._vm_workflow_impl("android-package-install-start", {**request, "shell": "id"})["ok"])
            start.assert_not_called()
        with patch.object(android_package_install, "collect", return_value={"ok": True, "state": "complete", "admissionReady": False}) as collect:
            result = mcp_server._vm_workflow_impl("android-package-install-collect", {"correlationId": correlation})
            self.assertTrue(result["ok"])
            self.assertFalse(result["admissionReady"])
            self.assertFalse(result["productAction"])
            collect.assert_called_once_with(mcp_server.REPO_ROOT, correlation)

    def test_android_package_install_running_status_is_not_terminal_failure_evidence(self):
        from agent_tools import android_package_install, native_failure_evidence
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"correlationId": correlation}
        for action, method in (("android-package-install-status", "status"),
                               ("android-package-install-collect", "collect")):
            with self.subTest(action=action), \
                    patch.object(android_package_install, method,
                                 return_value={"state": "running", "correlationId": correlation,
                                               "replayAllowed": False}), \
                    patch.object(native_failure_evidence, "record_failure") as record:
                result = mcp_server.vm_workflow(action, request)
                self.assertTrue(result["ok"])
                self.assertEqual("running", result["state"])
                self.assertNotIn("failureEvidence", result)
                record.assert_not_called()

    def test_android_install_lease_reconcile_requires_exact_readback_and_never_replays(self):
        from agent_tools import android_package_install
        request = {"installCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "currentReadbackCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "expectedCurrentOwner": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                   "expectedCurrentRevision": 0}
        with patch.object(android_package_install, "reconcile_terminal_lease",
                          return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as reconcile:
            result = mcp_server._vm_workflow_impl("android-package-install-reconcile", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            reconcile.assert_called_once_with(mcp_server.REPO_ROOT, request["installCorrelationId"],
                                              request["currentReadbackCorrelationId"],
                                              request["expectedCurrentOwner"], 0)
            self.assertFalse(mcp_server._vm_workflow_impl("android-package-install-reconcile", {**request, "shell": "rm"})["ok"])
            reconcile.assert_called_once()
        with patch.object(android_package_install, "reconcile_terminal_lease",
                          return_value={"ok": True, "state": "complete", "leaseReleased": True, "replayAllowed": False}):
            self.assertTrue(mcp_server._vm_workflow_impl("android-package-install-reconcile", request)["ok"])

    def test_android_document_route_requires_fixed_start_and_observation_fields(self):
        from agent_tools import android_document_acceptance
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api29", "correlationId": correlation,
                   "artifactId": "sha256-" + "b" * 64,
                   "cliStageCorrelationId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                   "expectedOwner": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "expectedRevision": 0}
        with patch.object(android_document_acceptance, "start", autospec=True,
                          return_value={"ok": True, "state": "submitted", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-document-acceptance-start", request)
            self.assertTrue(result["ok"])
            self.assertTrue(result["productAction"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", correlation,
                                          request["artifactId"], request["cliStageCorrelationId"],
                                          request["expectedOwner"], 0)
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-acceptance-start", {**request, "shell": "id"})["ok"])
            start.assert_called_once()
        for action, method in (("android-document-acceptance-status", "status"),
                               ("android-document-acceptance-collect", "collect")):
            with self.subTest(action=action), patch.object(android_document_acceptance, method,
                    return_value={"ok": True, "state": "running", "replayAllowed": False}) as observed:
                result = mcp_server._vm_workflow_impl(action, {"correlationId": correlation})
                self.assertTrue(result["ok"])
                self.assertFalse(result["productAction"])
                observed.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
                self.assertFalse(mcp_server._vm_workflow_impl(action, {"correlationId": correlation, "device": "api29"})["ok"])

    def test_android_action_route_requires_exact_same_request_fixture_fields(self):
        from agent_tools import android_action_acceptance
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api29", "correlationId": correlation,
                   "artifactId": "sha256-" + "b" * 64,
                   "backupCorrelationId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                   "expectedBackupSha256": "e" * 64,
                   "expectedOwner": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "expectedRevision": 0}
        with patch.object(android_action_acceptance, "start", return_value={
                "state": "submitted", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-action-acceptance-start", request)
            self.assertTrue(result["ok"])
            self.assertTrue(result["productAction"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", correlation,
                request["artifactId"], request["backupCorrelationId"], request["expectedBackupSha256"],
                request["expectedOwner"], 0)
            self.assertFalse(mcp_server._vm_workflow_impl("android-action-acceptance-start", {**request, "shell": "id"})["ok"])
        for action, method in (("android-action-acceptance-status", "status"),
                               ("android-action-acceptance-collect", "collect")):
            with self.subTest(action=action), patch.object(android_action_acceptance, method,
                    return_value={"state": "running", "replayAllowed": False}) as observed:
                result = mcp_server._vm_workflow_impl(action, {"correlationId": correlation})
                self.assertTrue(result["ok"])
                self.assertFalse(result["productAction"])
                observed.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
                self.assertFalse(mcp_server._vm_workflow_impl(action, {"correlationId": correlation, "shell": "id"})["ok"])

    def test_android_consent_denial_route_has_only_fixed_denial_inputs(self):
        from agent_tools import android_consent_acceptance
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "device": "api35", "correlationId": correlation,
                   "artifactId": "sha256-" + "b" * 64,
                   "cliStageCorrelationId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                   "openingReadbackCorrelationId": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                   "expectedBackupSha256": "f" * 64,
                   "expectedOwner": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "expectedRevision": 0}
        with patch.object(android_consent_acceptance, "start", return_value={
                "state": "submitted", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-consent-acceptance-start", request)
            self.assertTrue(result["ok"])
            self.assertTrue(result["productAction"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api35", correlation,
                request["artifactId"], request["cliStageCorrelationId"],
                request["openingReadbackCorrelationId"], request["expectedBackupSha256"],
                request["expectedOwner"], 0)
            self.assertFalse(mcp_server._vm_workflow_impl("android-consent-acceptance-start",
                {**request, "grant": True})["ok"])
            start.assert_called_once()
        for action, method in (("android-consent-acceptance-status", "status"),
                               ("android-consent-acceptance-collect", "collect")):
            with self.subTest(action=action), patch.object(android_consent_acceptance, method,
                    return_value={"state": "running", "replayAllowed": False}) as observed:
                result = mcp_server._vm_workflow_impl(action, {"correlationId": correlation})
                self.assertTrue(result["ok"])
                self.assertFalse(result["productAction"])
                observed.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
                self.assertFalse(mcp_server._vm_workflow_impl(action,
                    {"correlationId": correlation, "grant": True})["ok"])

    def test_android_document_recovery_routes_exact_unknown_and_fresh_closing_readback(self):
        from agent_tools import android_document_recovery
        request = {"host": "archlinux", "device": "api29",
                   "recoveryCorrelationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "unknownDocumentCorrelationId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                   "openingReadbackCorrelationId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                   "currentReadbackCorrelationId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                   "artifactId": "sha256-" + "e" * 64,
                   "cliStageCorrelationId": "ffffffff-ffff-4fff-8fff-ffffffffffff",
                   "expectedOwner": "11111111-1111-4111-8111-111111111111",
                   "expectedRevision": 1}
        recovery = request["recoveryCorrelationId"]
        with patch.object(android_document_recovery, "start",
                          return_value={"state": "unknown", "ok": False, "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-document-recovery-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, *request.values())
            self.assertFalse(mcp_server._vm_workflow_impl("android-document-recovery-start", {**request, "shell": "id"})["ok"])
            start.assert_called_once()
        for action, method in (("android-document-recovery-status", "status"),
                               ("android-document-recovery-collect", "collect")):
            with self.subTest(action=action), patch.object(android_document_recovery, method,
                    return_value={"state": "unknown", "ok": False, "replayAllowed": False}) as observed:
                self.assertFalse(mcp_server._vm_workflow_impl(action, {"recoveryCorrelationId": recovery})["ok"])
                observed.assert_called_once_with(mcp_server.REPO_ROOT, recovery)
                self.assertFalse(mcp_server._vm_workflow_impl(action, {"recoveryCorrelationId": recovery, "shell": "id"})["ok"])
        closing = {"recoveryCorrelationId": recovery,
                   "closingReadbackCorrelationId": "22222222-2222-4222-8222-222222222222",
                   "expectedOwner": request["expectedOwner"], "expectedRevision": 2}
        with patch.object(android_document_recovery, "finalize",
                          return_value={"ok": True, "state": "complete", "leaseReleased": True, "replayAllowed": False}) as finalize:
            result = mcp_server._vm_workflow_impl("android-document-recovery-finalize", closing)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            finalize.assert_called_once_with(mcp_server.REPO_ROOT, recovery,
                                              closing["closingReadbackCorrelationId"],
                                              closing["expectedOwner"], 2)

    def test_android_cli_stage_route_has_exact_nonreplayable_fields(self):
        from agent_tools import android_cli_stage
        correlation = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        request = {"host": "archlinux", "correlationId": correlation, "artifactId": "sha256-" + "b" * 64}
        with patch.object(android_cli_stage, "start", autospec=True,
                          return_value={"ok": True, "state": "published", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("android-cli-stage-start", request)
            self.assertTrue(result["ok"])
            self.assertTrue(result["productAction"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", correlation, request["artifactId"])
            self.assertFalse(mcp_server._vm_workflow_impl("android-cli-stage-start", {**request, "command": "id"})["ok"])
            start.assert_called_once()
        for action, method in (("android-cli-stage-status", "status"), ("android-cli-stage-collect", "collect")):
            with self.subTest(action=action), patch.object(android_cli_stage, method, autospec=True,
                    return_value={"ok": False, "state": "unknown", "replayAllowed": False}) as observed:
                result = mcp_server._vm_workflow_impl(action, {"correlationId": correlation})
                self.assertFalse(result["ok"])
                self.assertFalse(result["productAction"])
                observed.assert_called_once_with(mcp_server.REPO_ROOT, correlation)
                self.assertFalse(mcp_server._vm_workflow_impl(action, {"correlationId": correlation, "host": "archlinux"})["ok"])

    def test_macos_guest_stage_requires_two_verified_same_source_dmgs(self):
        from agent_tools import macos_fixture_guest_stage, native_artifact_registry
        source = "a" * 40
        request = {"correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sourceSha": source,
                   "guestRoot": "/Users/admin/macos-parityaaaaaaa", "baseSha256": "b" * 64,
                   "baseSizeBytes": 123, "targetSha256": "c" * 64, "targetSizeBytes": 456}
        def verified(_root, artifact_id):
            size = 123 if artifact_id.endswith("b" * 64) else 456
            return {"verification": "verified", "artifact": {"platform": "macos", "artifactKind": "desktop-package",
                    "sourceSha": source, "sourceFingerprint": "d" * 64, "size": size}}
        with patch.object(native_artifact_registry, "verify_artifact", side_effect=verified) as verify, \
             patch.object(macos_fixture_guest_stage, "start", return_value={"ok": True, "state": "complete"}) as start:
            result = mcp_server._vm_workflow_impl("macos-fixture-guest-stage-start", request)
            self.assertTrue(result["ok"])
            self.assertTrue(result["productAction"])
            self.assertEqual(2, verify.call_count)
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
            self.assertFalse(mcp_server._vm_workflow_impl("macos-fixture-guest-stage-start", {**request, "command": "id"})["ok"])
            start.assert_called_once()
        with patch.object(native_artifact_registry, "verify_artifact", return_value={"verification": "missing"}), \
             patch.object(macos_fixture_guest_stage, "start") as start:
            self.assertFalse(mcp_server._vm_workflow_impl("macos-fixture-guest-stage-start", request)["ok"])
            start.assert_not_called()
        with patch.object(native_artifact_registry, "verify_artifact", side_effect=verified), \
             patch.object(macos_fixture_guest_stage, "start", return_value={"ok": False, "state": "unknown", "replayAllowed": False}):
            result = mcp_server._vm_workflow_impl("macos-fixture-guest-stage-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])

    def test_android_public_inspect_routes_only_bounded_readonly_request(self):
        from agent_tools import android_public_inspect
        request = {"host": "archlinux", "device": "api29", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "expectedBaseSha256": "b" * 64, "expectedOwner": "owner", "expectedRevision": 0}
        with patch.object(android_public_inspect, "inspect", return_value={"ok": True, "outcome": "admitted", "nativeMutationAllowed": False}) as inspect:
            result = mcp_server._vm_workflow_impl("android-public-inspect", request)
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertFalse(result["nativeMutationAllowed"])
            inspect.assert_called_once_with(mcp_server.REPO_ROOT, "archlinux", "api29", request["correlationId"],
                "b" * 64, "owner", 0, timeout_seconds=60)
        with patch.object(android_public_inspect, "inspect", return_value={"ok": False, "outcome": "unknown", "nativeMutationAllowed": False}):
            self.assertFalse(mcp_server._vm_workflow_impl("android-public-inspect", request)["ok"])
        with patch.object(android_public_inspect, "inspect") as inspect:
            self.assertFalse(mcp_server._vm_workflow_impl("android-public-inspect", {**request, "command": "on"})["ok"])
            inspect.assert_not_called()

    def test_windows_msi_preinstall_status_only_accepts_exact_readonly_job(self):
        from agent_tools import windows_msi_public_scenario
        request = {"host": "archlinux", "jobId": "9107428f-9c80-4284-9f4e-926350105a59"}
        with patch.object(windows_msi_public_scenario, "preinstall_status", return_value={"state": "unknown"}) as observe:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-preinstall-status", request)["ok"])
            observe.assert_called_once_with(mcp_server.REPO_ROOT, request["host"], request["jobId"], timeout_seconds=15)
        with patch.object(windows_msi_public_scenario, "preinstall_status") as observe:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-preinstall-status", {**request, "command": "guest-exec"})["ok"])
            observe.assert_not_called()
        with patch.object(windows_msi_public_scenario, "preinstall_status", return_value={"state": "observed"}):
            self.assertTrue(mcp_server._vm_workflow_impl("windows-msi-preinstall-status", request)["ok"])

    def test_windows_powershell_preflight_is_fixed_and_cannot_promote_failure(self):
        from agent_tools import windows_msi_public_scenario
        with patch.object(windows_msi_public_scenario, "powershell_preflight", return_value={"state": "failed"}) as preflight:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-powershell-preflight", {"host": "archlinux"})["ok"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        with patch.object(windows_msi_public_scenario, "powershell_preflight") as preflight:
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-powershell-preflight", {"host": "archlinux", "command": "install"})["ok"])
            preflight.assert_not_called()
        with patch.object(windows_msi_public_scenario, "powershell_preflight", return_value={"state": "passed", "checks": ["gzip", "utf8"]}):
            result = mcp_server._vm_workflow_impl("windows-msi-powershell-preflight", {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])

    def test_windows_msi_public_route_keeps_uncertain_submission_and_terminal_observation_distinct(self):
        from agent_tools import windows_msi_public_scenario
        start_request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                         "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                         "baseMsiArtifactId": "sha256-" + "c" * 64, "targetMsiArtifactId": "sha256-" + "d" * 64}
        with patch.object(windows_msi_public_scenario, "start", return_value={"state": "unknown", "replayAllowed": False}) as submit:
            result = mcp_server._vm_workflow_impl("windows-msi-public-start", start_request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            submit.assert_called_once_with(mcp_server.REPO_ROOT, start_request)
        with patch.object(windows_msi_public_scenario, "status", return_value={"state": "observed", "phase": "protected-terminal", "installedVerified": False}):
            result = mcp_server._vm_workflow_impl("windows-msi-public-status", {"host": "archlinux", "correlationId": start_request["correlationId"]})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertFalse(result["installedVerified"])
        with patch.object(windows_msi_public_scenario, "collect", return_value={"state": "observed", "collected": True, "installedVerified": False}):
            self.assertFalse(mcp_server._vm_workflow_impl("windows-msi-public-collect", {"host": "archlinux", "correlationId": start_request["correlationId"]})["installedVerified"])

    def test_windows_base_route_requires_inert_preflight_and_never_replays_unknown(self):
        from agent_tools import windows_msi_base_prepare
        request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                   "sourceSha": "a" * 40, "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
                   "baseMsiArtifactId": "sha256-" + "c" * 64,
                   "targetMsiArtifactId": "sha256-" + "d" * 64, "expectedCurrentVersion": "2.1.17"}
        with patch.object(windows_msi_base_prepare, "powershell_preflight", return_value={"state": "passed"}) as preflight:
            result = mcp_server._vm_workflow_impl("windows-msi-base-preflight", {"host": "archlinux"})
            self.assertTrue(result["ok"])
            self.assertFalse(result["productAction"])
            preflight.assert_called_once_with(mcp_server.REPO_ROOT, {"host": "archlinux"})
        readiness_request = {"host": "archlinux", "expectedCurrentVersion": "2.1.17"}
        with patch.object(windows_msi_base_prepare, "readiness", return_value={"state": "blocked", "ready": False}) as readiness:
            result = mcp_server._vm_workflow_impl("windows-msi-base-readiness", readiness_request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            readiness.assert_called_once_with(mcp_server.REPO_ROOT, readiness_request)
        with patch.object(windows_msi_base_prepare, "readiness", return_value={"state": "ready", "ready": True}):
            self.assertTrue(mcp_server._vm_workflow_impl("windows-msi-base-readiness", readiness_request)["ok"])
        with patch.object(windows_msi_base_prepare, "start", return_value={"state": "unknown", "replayAllowed": False}) as start:
            result = mcp_server._vm_workflow_impl("windows-msi-base-start", request)
            self.assertFalse(result["ok"])
            self.assertFalse(result["replayAllowed"])
            start.assert_called_once_with(mcp_server.REPO_ROOT, request)
        with patch.object(windows_msi_base_prepare, "status", return_value={"state": "terminal", "result": "FAILED"}) as status:
            result = mcp_server._vm_workflow_impl("windows-msi-base-status", {"correlationId": request["correlationId"]})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        with patch.object(windows_msi_base_prepare, "reconcile", return_value={
                "state": "unknown", "failurePhase": "bootstrap",
                "failureType": "task_trigger_outcome_ambiguous",
                "code": "task_trigger_outcome_ambiguous", "replayAllowed": False}) as reconcile:
            result = mcp_server._vm_workflow_impl("windows-msi-base-reconcile", {"correlationId": request["correlationId"]})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertEqual(result["evidenceClass"], "causal-reconciliation")
            self.assertFalse(result["replayAllowed"])
            reconcile.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        with patch.object(windows_msi_base_prepare, "diagnose", return_value={
                "state": "unknown", "correlationId": request["correlationId"], "binding": "exact",
                "checkpoint": "qga-protocol", "replayAllowed": False,
                "nativeActionAllowed": False}) as diagnose:
            result = mcp_server._vm_workflow_impl("windows-msi-base-diagnostic", {
                "correlationId": request["correlationId"]})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertEqual(result["evidenceClass"], "causal-diagnostic")
            self.assertFalse(result["nativeActionAllowed"])
            self.assertFalse(result["replayAllowed"])
            diagnose.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": request["correlationId"]})
        exact_unknown = "2ace6a48-ba60-4705-9200-4ff857f2aba6"
        with patch.object(windows_msi_base_prepare, "close_unknown", return_value={
                "state": "unknown", "correlationId": exact_unknown, "replayAllowed": False}) as close:
            result = mcp_server._vm_workflow_impl("windows-msi-base-unknown-close", {"correlationId": exact_unknown})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertEqual(result["evidenceClass"], "causal-cleanup")
            close.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": exact_unknown})
        with patch.object(windows_msi_base_prepare, "close_unknown", return_value={
                "state": "closed", "correlationId": exact_unknown, "outcome": "unknown-cleaned",
                "replayAllowed": False}):
            result = mcp_server._vm_workflow_impl("windows-msi-base-unknown-close", {"correlationId": exact_unknown})
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidenceClass"], "causal-cleanup")
        self.assertFalse(result["productAction"])
        with patch.object(windows_msi_base_prepare, "close_unknown_status", return_value={
                "state": "unknown", "correlationId": exact_unknown, "phase": "diagnostic",
                "reason": "qga-protocol", "replayAllowed": False}) as status:
            result = mcp_server._vm_workflow_impl("windows-msi-base-unknown-close-status", {"correlationId": exact_unknown})
            self.assertFalse(result["ok"])
            self.assertFalse(result["productAction"])
            self.assertEqual(result["evidenceClass"], "causal-status")
            status.assert_called_once_with(mcp_server.REPO_ROOT, {"correlationId": exact_unknown})
        with patch.object(windows_msi_base_prepare, "close_unknown_status", return_value={
                "state": "closed", "correlationId": exact_unknown, "outcome": "unknown-cleaned",
                "replayAllowed": False}):
            result = mcp_server._vm_workflow_impl("windows-msi-base-unknown-close-status",
                                                  {"correlationId": exact_unknown})
        self.assertTrue(result["ok"])
        self.assertEqual(result["evidenceClass"], "causal-status")
        self.assertFalse(result["productAction"])
        self.assertEqual(result["outcome"], "unknown-cleaned")
        with patch.object(windows_msi_base_prepare, "close_unknown_status", return_value={
                "state": "closed", "correlationId": exact_unknown, "replayAllowed": False}):
            result = mcp_server._vm_workflow_impl("windows-msi-base-unknown-close-status",
                                                  {"correlationId": exact_unknown})
        self.assertFalse(result["ok"])

    def test_windows_owner_observe_routes_are_read_only_and_do_not_promote_unknown(self):
        from agent_tools import windows_msi_owner_observe
        cases = (
            ("preflight", "powershell_preflight", {"state": "passed"}, True),
            ("start", "start", {"state": "submitted", "replayAllowed": False}, True),
            ("status", "status", {"state": "observed", "controllerId": "owned"}, True),
            ("collect", "collect", {"state": "unknown", "cleanupReplayAllowed": False}, False),
        )
        for suffix, method_name, response, expected_ok in cases:
            request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
            with self.subTest(suffix=suffix), patch.object(windows_msi_owner_observe, method_name, return_value=response) as method:
                result = mcp_server._vm_workflow_impl("windows-msi-owner-observe-" + suffix, request)
            self.assertEqual(result["ok"], expected_ok)
            self.assertFalse(result["productAction"])
            method.assert_called_once_with(mcp_server.REPO_ROOT, request)

    def test_windows_target_preparation_routes_keep_install_separate(self):
        from agent_tools import windows_msi_target_prepare
        cases = (
            ("preflight", "powershell_preflight", {"state": "passed"}, True, False),
            ("readiness", "readiness", {"state": "ready"}, True, False),
            ("start", "start", {"state": "submitted", "replayAllowed": False}, True, True),
            ("status", "status", {"state": "unknown", "replayAllowed": False}, False, False),
        )
        for suffix, method_name, response, expected_ok, product_action in cases:
            request = {"host": "archlinux", "correlationId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
            with self.subTest(suffix=suffix), patch.object(windows_msi_target_prepare, method_name, return_value=response) as method:
                result = mcp_server._vm_workflow_impl("windows-msi-target-" + suffix, request)
            self.assertEqual(result["ok"], expected_ok)
            self.assertEqual(result["productAction"], product_action)
            method.assert_called_once_with(mcp_server.REPO_ROOT, request)

    def test_batch_observation_does_not_accept_replacement_plan(self):
        from agent_tools import native_scenario_batch
        with patch.object(native_scenario_batch.NativeScenarioBatch, "status") as status:
            result = mcp_server._vm_workflow_impl("batch-status", {"batchId": "owned", "recipe": "replacement"})
        self.assertFalse(result["ok"])
        status.assert_not_called()

    def test_batch_failure_and_unknown_are_not_successful_completion(self):
        from agent_tools import native_scenario_batch
        for state in ("failed", "blocked", "unknown"):
            with self.subTest(state=state), patch.object(native_scenario_batch.NativeScenarioBatch, "status", return_value={"state": state}):
                self.assertFalse(mcp_server._vm_workflow_impl("batch-status", {"batchId": "owned"})["ok"])

    def test_fixed_dispatch_rejects_arbitrary_and_recursive_execution(self):
        for surface, action in (("shell", "exec"), ("vm", "baseline-restore"),
                                ("vm", "batch-start"), ("ssh", "apk-publish")):
            with self.subTest(surface=surface, action=action), self.assertRaises(ValueError):
                mcp_server._native_fixed_dispatch(surface, action, {})

    def test_fixed_dispatch_forwards_only_existing_adapter(self):
        with patch.object(mcp_server, "_ssh_workflow_impl", return_value={"available": True}) as probe:
            result = mcp_server._native_fixed_dispatch("ssh", "probe", {"host": "owned", "timeout_seconds": 15})
        self.assertTrue(result["available"])
        probe.assert_called_once_with(action="probe", host="owned", timeout_seconds=15)

    def test_matrix_status_is_read_only_and_does_not_assert_gate_success(self):
        from agent_tools import native_acceptance_matrix
        with patch.object(mcp_server.subprocess, "check_output", return_value="a" * 40), patch.object(native_acceptance_matrix, "matrix_status", return_value={"gate": "open"}) as status:
            result = mcp_server._vm_workflow_impl("matrix-status", {"sourceSha": "a" * 40})
        self.assertTrue(result["ok"])
        self.assertEqual("open", result["gate"])
        status.assert_called_once_with(mcp_server.REPO_ROOT, "a" * 40)

    def test_matrix_retract_routes_exact_reviewed_correction(self):
        from agent_tools import native_acceptance_matrix
        correction = {"receiptId": "native-acceptance-" + "a" * 32,
                      "reason": "Scenario was not observed", "reviewer": "maintainer"}
        with patch.object(native_acceptance_matrix, "matrix_retract", return_value={"receiptId": correction["receiptId"]}) as retract:
            result = mcp_server._vm_workflow_impl("matrix-retract", correction)
            self.assertTrue(result["ok"])
            retract.assert_called_once_with(mcp_server.REPO_ROOT, correction)
        with patch.object(native_acceptance_matrix, "matrix_retract", side_effect=native_acceptance_matrix.NativeAcceptanceMatrixError("bad correction")):
            result = mcp_server._vm_workflow_impl("matrix-retract", {**correction, "extra": "unsafe"})
            self.assertFalse(result["ok"])

    def test_matrix_cannot_present_old_sha_as_current_acceptance(self):
        from agent_tools import native_acceptance_matrix
        with patch.object(mcp_server.subprocess, "check_output", return_value="b" * 40), patch.object(native_acceptance_matrix, "matrix_status") as status:
            result = mcp_server._vm_workflow_impl("matrix-status", {"sourceSha": "a" * 40})
        self.assertFalse(result["ok"])
        status.assert_not_called()

    def test_reuse_success_is_explicitly_bytes_only_until_native_admission(self):
        from agent_tools import native_artifact_reuse
        with patch.object(native_artifact_reuse, "artifact_reuse_check", return_value={"decision": "verified-equivalent-product-inputs", "nativeAdmissionReady": False}):
            result = mcp_server._vm_workflow_impl("artifact-reuse-check", {"artifactSetId": "id"})
        self.assertTrue(result["ok"])
        self.assertEqual("artifact-byte-reuse", result["evidenceScope"])
        self.assertFalse(result["nativeAdmissionReady"])

    def test_baselines_use_configured_backend_only(self):
        from agent_tools import native_vm_baseline_config
        request = {"provider": "tart", "sourceId": "owned"}
        with patch.object(native_vm_baseline_config, "handle", return_value={"state": "ready"}) as handle:
            mcp_server._vm_workflow_impl("baseline-preflight", request)
        handle.assert_called_once_with(mcp_server.REPO_ROOT, "baseline-preflight", request)


if __name__ == "__main__":
    unittest.main()
