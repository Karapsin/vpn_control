from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import tool_action_policy as policy
from agent_tools import native_workflow_policy, windows_vm_setup_policy

ROOT = Path(__file__).resolve().parents[2]


class ActionCatalogTests(unittest.TestCase):
    def test_complete_current_source_audits_without_importing_dispatcher(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("audit may not run tools")):
            report = policy.audit_action_catalog(ROOT)
        self.assertTrue(report["ok"])
        self.assertGreater(report["actionCount"], 590)

    def test_explicit_visual_target_selector_cli_is_local_metadata(self):
        classified=policy.action_policy('visual_target','run')
        self.assertEqual('local_metadata',classified.classification)
        self.assertFalse(classified.requirements)
        self.assertFalse(classified.permitted_recoveries)
        self.assertEqual('scripts/visual_target.py',policy.DIRECT_SCRIPTS['visual_target'])
        with self.assertRaises(policy.ActionPolicyError):policy.action_policy('visual_target','start')

    def test_lookup_has_no_default_and_is_deeply_immutable(self):
        item = policy.action_policy("ssh_workflow", "inventory")
        with self.assertRaises(FrozenInstanceError):
            item.classification = "background_submission"
        with self.assertRaises(TypeError):
            policy.CATALOG["ssh_workflow", "new"] = item
        self.assertIsInstance(item.requirements, frozenset)
        self.assertIsInstance(item.permitted_recoveries, frozenset)
        for surface, action in (("ssh_workflow", "inventory-new"), ("new_surface", "inventory"), ("vm_workflow", None)):
            with self.assertRaisesRegex(policy.ActionPolicyError, "unclassified_tool_action"):
                policy.action_policy(surface, action)

    def _isolated_sources(self, path):
        (path / "agent_tools").mkdir()
        shutil.copyfile(ROOT / "agent_tools/mcp_server.py", path / "agent_tools/mcp_server.py")
        (path / "scripts").mkdir()
        for relative in policy.DIRECT_SCRIPTS.values():
            shutil.copyfile(ROOT / relative, path / relative)

    def test_new_mcp_only_action_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/mcp_server.py"
            source = target.read_text()
            source = source.replace('    """Dispatch finite native workflows with explicit source and ownership gates."""',
                                    '    """Dispatch finite native workflows with explicit source and ownership gates."""\n'
                                    '    if action == "new-unclassified-mcp-action":\n        return {}', 1)
            self.assertNotEqual(source, target.read_text())
            target.write_text(source)
            with self.assertRaisesRegex(policy.ActionPolicyError, "new-unclassified-mcp-action"):
                policy.audit_action_catalog(root)

    def test_new_cli_only_action_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/mcp_server.py"
            target.write_text(target.read_text() + '\nvm_parser._actions[-1].choices = (*vm_parser._actions[-1].choices, "new-cli-action")\n')
            with self.assertRaisesRegex(policy.ActionPolicyError, "new-cli-action"):
                policy.audit_action_catalog(root)

    def test_new_direct_action_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "scripts/visual_platform.py"
            target.write_text(target.read_text().replace('    subparsers.add_parser("android-local-config")',
                                                       '    subparsers.add_parser("new-direct-action")\n    subparsers.add_parser("android-local-config")', 1))
            with self.assertRaisesRegex(policy.ActionPolicyError, "new-direct-action"):
                policy.audit_action_catalog(root)

    def test_removed_action_requires_removing_stale_policy(self):
        extra = dict(policy.CATALOG)
        extra["vm_workflow", "removed-action"] = replace(policy.action_policy("vm_workflow", "matrix-status"), action="removed-action")
        with self.assertRaisesRegex(policy.ActionPolicyError, "removed-action"):
            policy.audit_action_catalog(ROOT, extra)

    def test_local_metadata_history_and_collection_perform_zero_recovery(self):
        examples = {
            "ssh_workflow": ("inventory", "windows-caller-file-receipt", "connection-nested-orphan-archive-status", "forward-status"),
            "vm_workflow": ("source-review-close", "baseline-source-inventory", "matrix-status", "credential-status", "macos-fixture-stage-collect", "macos-machine-server-stop-collect", "macos-installer-recovery-status", "android-fixture-tls-mint"),
            "visual_review": ("status", "record"),
        }
        for surface, actions in examples.items():
            for action in actions:
                with self.subTest(surface=surface, action=action):
                    item = policy.action_policy(surface, action)
                    self.assertEqual(item.requirements, frozenset())
                    self.assertEqual(item.permitted_recoveries, frozenset())

    def test_program_submission_and_reconciliation_preserve_local_observers(self):
        start = policy.action_policy("ssh_workflow", "program-start")
        self.assertEqual(start.requirements, {"transport"})
        self.assertEqual(start.permitted_recoveries, {"reconnect"})
        self.assertEqual(start.observation_route, "ssh_workflow:program-reconcile")
        for action in ("program-status", "program-collect"):
            item = policy.action_policy("ssh_workflow", action)
            self.assertEqual(item.classification, "local_observation")
            self.assertFalse(item.requirements)
            self.assertFalse(item.permitted_recoveries)
        reconcile = policy.action_policy("ssh_workflow", "program-reconcile")
        self.assertEqual(reconcile.requirements, {"transport"})
        self.assertEqual(reconcile.permitted_recoveries, {"reconnect"})

    def test_readiness_status_is_observation_only_and_ensure_has_bounded_authority(self):
        ssh_status = policy.action_policy("ssh_workflow", "readiness-status")
        self.assertEqual(ssh_status.requirements, {"transport"})
        self.assertFalse(ssh_status.permitted_recoveries)
        ssh_ensure = policy.action_policy("ssh_workflow", "readiness-ensure")
        self.assertEqual(ssh_ensure.requirements, {"transport"})
        self.assertEqual(ssh_ensure.permitted_recoveries, {"reconnect"})
        vm_status = policy.action_policy("vm_workflow", "readiness-status")
        self.assertEqual(vm_status.requirements, policy.REQUIREMENTS)
        self.assertFalse(vm_status.permitted_recoveries)
        vm_ensure = policy.action_policy("vm_workflow", "readiness-ensure")
        self.assertEqual(vm_ensure.requirements, policy.REQUIREMENTS)
        self.assertEqual(vm_ensure.permitted_recoveries, policy.RECOVERIES)
        providers = policy.action_policy("vm_workflow", "readiness-providers")
        self.assertEqual(providers.classification, "local_metadata")
        self.assertFalse(providers.requirements)
        self.assertFalse(providers.permitted_recoveries)

    def test_direct_client_has_finite_actions_and_preserves_local_observations(self):
        actions = policy.exposed_actions(ROOT)["ssh_program_mcp_client"]
        self.assertEqual(actions, {"run", "program-start", "program-status", "program-collect", "program-reconcile",
                                   "guest-program-start", "guest-program-status", "guest-program-collect", "guest-program-reconcile",
                                   "android-program-start", "android-program-status", "android-program-collect", "android-program-reconcile"})
        for action in ("run", "program-status", "program-collect", "guest-program-status", "guest-program-collect",
                       "android-program-status", "android-program-collect"):
            item = policy.action_policy("ssh_program_mcp_client", action)
            self.assertFalse(item.requirements)
            self.assertFalse(item.permitted_recoveries)
        for action in ("program-start", "program-reconcile", "guest-program-reconcile", "android-program-reconcile"):
            item = policy.action_policy("ssh_program_mcp_client", action)
            self.assertEqual(item.requirements, {"transport"})
            self.assertEqual(item.permitted_recoveries, {"reconnect"})
        for action, recoveries in (("guest-program-start", {"reconnect", "start", "resume", "reboot"}),
                                   ("android-program-start", {"reconnect", "start", "resume"})):
            item = policy.action_policy("ssh_program_mcp_client", action)
            self.assertEqual(item.requirements, {"guest_agent"})
            self.assertEqual(item.permitted_recoveries, recoveries)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/ssh_program_mcp_client.py"
            before = target.read_text()
            changed = before.replace('ACTIONS = ("program-start",', 'ACTIONS = ("new-direct-client-action", "program-start",', 1)
            self.assertNotEqual(changed, before)
            target.write_text(changed)
            with self.assertRaisesRegex(policy.ActionPolicyError, "new-direct-client-action"):
                policy.audit_action_catalog(root)

    def test_lease_policies_keep_old_status_and_cancel_entirely_local(self):
        acquisition = policy.action_policy("vm_workflow", "readiness-lease-acquire")
        self.assertEqual(acquisition.requirements, policy.REQUIREMENTS)
        self.assertEqual(acquisition.permitted_recoveries, {"wake_display"})
        self.assertEqual(acquisition.observation_route, "vm_workflow:readiness-lease-status")
        for action in ("readiness-lease-status", "readiness-lease-cancel"):
            item = policy.action_policy("vm_workflow", action)
            self.assertFalse(item.requirements)
            self.assertFalse(item.permitted_recoveries)
            self.assertEqual(item.classification, "local_observation")
        reconciliation = policy.action_policy("vm_workflow", "readiness-lease-reconcile")
        self.assertEqual(reconciliation.requirements,{"transport"})
        self.assertEqual(reconciliation.permitted_recoveries,{"reconnect"})
        self.assertEqual(reconciliation.observation_route,"vm_workflow:readiness-lease-status")

    def test_new_unbounded_prefix_suffix_and_adapter_routes_fail_audit(self):
        additions = (
            '    if action.startswith("future-family-"):\n        return _agent_module("future_adapter").dispatch(action)\n',
            '    if action.endswith("-future-suffix"):\n        return _agent_module("future_adapter").dispatch(action)\n',
            '    return _agent_module(action).dispatch(inputs)\n',
            '    predicate = action.startswith\n    if predicate("future-family-"):\n        return {}\n',
            '    module_name = action\n    return _agent_module(module_name).dispatch(inputs)\n',
        )
        marker = '    """Dispatch finite native workflows with explicit source and ownership gates."""'
        for addition in additions:
            with self.subTest(addition=addition), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._isolated_sources(root)
                target = root / "agent_tools/mcp_server.py"
                target.write_text(target.read_text().replace(marker, marker + "\n" + addition, 1))
                with self.assertRaisesRegex(policy.ActionPolicyError, "unbounded_dynamic_action_route"):
                    policy.audit_action_catalog(root)

    def test_finite_prefix_dictionary_keys_enter_inventory_and_guard_cannot_weaken(self):
        marker = '    """Dispatch finite native workflows with explicit source and ownership gates."""'
        addition = '''
    if action.startswith("future-family-"):
        routes = {"future-family-specific": ("future_adapter", "status")}
        route = routes.get(action)
        if route is None:
            return {"state": "refused"}
        return _agent_module(route[0]).dispatch(route[1])
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/mcp_server.py"
            target.write_text(target.read_text().replace(marker, marker + "\n" + addition, 1))
            with self.assertRaisesRegex(policy.ActionPolicyError, "future-family-specific"):
                policy.audit_action_catalog(root)
        # Weakening the finite join's missing-route guard reopens the prefix.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/mcp_server.py"
            weakened = addition.replace('        if route is None:\n            return {"state": "refused"}',
                                        '        if route is None:\n            pass', 1)
            self.assertNotEqual(addition, weakened)
            target.write_text(target.read_text().replace(marker, marker + "\n" + weakened, 1))
            with self.assertRaisesRegex(policy.ActionPolicyError, "unbounded_dynamic_action_route"):
                policy.audit_action_catalog(root)
        # The actual fixture lifecycle route admits exact table members only.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/mcp_server.py"
            original = target.read_text()
            gate = '        if action in {"windows-fixture-stage-start", '
            self.assertEqual(1, original.count(gate))
            target.write_text(original.replace(gate, '        if action.startswith("windows-fixture-") or action in {"windows-fixture-stage-start", ', 1))
            with self.assertRaisesRegex(policy.ActionPolicyError, "unbounded_dynamic_action_route:_vm_workflow_dispatch"):
                policy.audit_action_catalog(root)

    def test_registered_public_routes_never_inherit_internal_caller_bounds(self):
        addition = '''
def future_registered(action):
    if action == "matrix-status":
        return {}
    if action.startswith("unbounded-public-family-"):
        return _agent_module("future_adapter").dispatch(action)
def internal_finite_caller(action):
    if action in {"matrix-status"}:
        return future_registered(action)
MCP_SERVER.tool()(future_registered)
'''
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._isolated_sources(root)
            target = root / "agent_tools/mcp_server.py"
            target.write_text(target.read_text() + addition)
            # Even reviewing its one explicit metadata action cannot grant the
            # public function a bound established only by an internal caller.
            catalog = dict(policy.CATALOG)
            catalog["future_registered", "matrix-status"] = replace(
                policy.action_policy("vm_workflow", "matrix-status"), surface="future_registered")
            with self.assertRaisesRegex(policy.ActionPolicyError, "unbounded_dynamic_action_route:future_registered"):
                policy.audit_action_catalog(root, catalog)

    def test_actual_native_request_wrapper_refuses_dynamic_route_before_adapter_import(self):
        import importlib.util
        from agent_tools import mcp_server
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            marker = root / "adapter-imported"
            adapter_source = root / "future_adapter.py"
            adapter_source.write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('imported')\n")
            def native_adapter_import(_):
                spec = importlib.util.spec_from_file_location("_policy_future_adapter", adapter_source)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module
            def _vm_future_dynamic(action, inputs):
                if action.startswith("future-family-"):
                    mcp_server._agent_module("future_adapter")
                return {"ok": True, "state": "observed"}
            call = mcp_server._native_source_request(_vm_future_dynamic)
            with mock.patch.object(mcp_server, "_agent_module", side_effect=native_adapter_import) as imports:
                result = call("future-family-unclassified", {})
                self.assertEqual(result, {"tool": "vm_workflow", "ok": False, "state": "refused",
                                          "reason": "unclassified_tool_action", "replayAllowed": False})
                imports.assert_not_called()
                self.assertFalse(marker.exists())
                self.assertEqual(call("matrix-status", {}), {"ok": True, "state": "observed"})
                imports.assert_not_called()
                self.assertFalse(marker.exists())
            # Execute the complete authentic pre-policy wrapper with the same
            # real loader. Its missing classifier admits the import effect.
            import hashlib
            before_root = ROOT / "agent_tools/tests/fixtures/action_policy_wrapper_before"
            before_path = before_root / "native_source_request.before.source"
            before = before_path.read_bytes()
            provenance = json.loads((before_root / "provenance.json").read_bytes())
            self.assertEqual(provenance["extractedSourceSha256"], "fa8eb8003b53fa0da5ec13129e10f850cd35e045082d630c414b5faed462a723")
            self.assertEqual(hashlib.sha256(before).hexdigest(), provenance["extractedSourceSha256"])
            self.assertEqual(len(before), provenance["extractedSourceBytes"])
            namespace = {"functools": mcp_server.functools, "Path": Path,
                         "_SOURCE_MODULE_LOADER": mcp_server._SOURCE_MODULE_LOADER, "__file__": mcp_server.__file__}
            exec(compile(before, str(before_path), "exec"), namespace)
            before_call = namespace["_native_source_request"](_vm_future_dynamic)
            with mock.patch.object(mcp_server, "_agent_module", side_effect=native_adapter_import):
                self.assertTrue(before_call("future-family-unclassified", {})["ok"])
            self.assertEqual(marker.read_text(), "imported")

    def test_remote_original_observers_may_only_reconnect(self):
        for key, item in policy.CATALOG.items():
            if item.classification == "remote_observation":
                with self.subTest(key=key):
                    self.assertEqual(item.requirements, {"transport"})
                    self.assertLessEqual(item.permitted_recoveries, {"reconnect"})
        for action in ("android-document-acceptance-status", "linux-package-fixture-build-status", "windows-vm-deploy-status"):
            self.assertEqual(policy.action_policy("vm_workflow", action).permitted_recoveries, {"reconnect"})

    def test_background_and_intentional_phases_do_not_unlock_desktop(self):
        for item in policy.CATALOG.values():
            if item.classification in {"background_submission", "original_operation", "existing_lifecycle"}:
                self.assertNotIn("login", item.permitted_recoveries)
                self.assertNotIn("wake_display", item.permitted_recoveries)
                self.assertNotIn("ordinary_session", item.requirements)
            if item.classification == "intentional_phase":
                self.assertFalse(item.permitted_recoveries)
        self.assertEqual(policy.action_policy("ssh_workflow", "tmux-disconnect-probe").expected_test_state, "disconnected")
        self.assertEqual(policy.action_policy("visual_platform", "stop").expected_test_state, "stopped")

    def test_all_existing_historical_refusals_remain_recovery_free(self):
        for action in policy.exposed_actions(ROOT)["vm_workflow"]:
            if native_workflow_policy.refusal(action) is not None or windows_vm_setup_policy.refusal(action, {}) is not None:
                item = policy.action_policy("vm_workflow", action)
                self.assertEqual(item.classification, "retired", action)
                self.assertFalse(item.requirements, action)
                self.assertFalse(item.permitted_recoveries, action)
        self.assertEqual(policy.action_policy("ssh_workflow", "forward-open").classification, "retired")

    def test_original_observation_routes_name_existing_actions_or_explicit_legacy_limit(self):
        for item in policy.CATALOG.values():
            surface, action = item.observation_route.split(":", 1)
            if surface != "none":
                self.assertIn((surface, action), policy.CATALOG)
            else:
                self.assertEqual(action, "legacy-foreground-outcome-unknown")

    def test_cli_audit_reports_finite_schema(self):
        result = subprocess.run([sys.executable, str(ROOT / "agent_tools/tool_action_policy.py"), "--root", str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_manifest_rejects_duplicate_and_observer_power_authority(self):
        document = json.loads(policy.MANIFEST_PATH.read_text())
        group = next(group for group in document["groups"] if group["classification"] == "remote_observation")
        group["permittedRecoveries"].append("reboot")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "policy.json"
            target.write_text(json.dumps(document))
            with self.assertRaisesRegex(policy.ActionPolicyError, "remote_observation_may_not_wake_guest"):
                policy.load_catalog(target)
            target.write_text('{"schemaVersion":1,"schemaVersion":1,"groups":[]}')
            with self.assertRaisesRegex(policy.ActionPolicyError, "duplicate_policy_key"):
                policy.load_catalog(target)

    def test_new_registered_singleton_and_action_family_require_review(self):
        for addition, missing in (
            ('\ndef new_metadata(): return {}\nMCP_SERVER.tool()(new_metadata)\n', "new_metadata:call"),
            ('\ndef new_action_family(action):\n if action in {"new-action"}: return {}\nMCP_SERVER.tool()(new_action_family)\n', "new_action_family:new-action"),
        ):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self._isolated_sources(root)
                target = root / "agent_tools/mcp_server.py"
                target.write_text(target.read_text() + addition)
                with self.assertRaisesRegex(policy.ActionPolicyError, missing):
                    policy.audit_action_catalog(root)

    def test_all_registered_singleton_tools_have_explicit_policies(self):
        for surface in ("prepare_start", "docs", "change_impact", "workflow_status", "version_bump", "run_checks"):
            self.assertIn((surface, "call"), policy.CATALOG)
        for surface, actions in (("git_workflow", ("commit", "checkpoint", "push", "checks")),
                                 ("release_workflow", ("status", "merge-dev", "publish"))):
            for action in actions:
                self.assertFalse(policy.action_policy(surface, action).permitted_recoveries)

    @unittest.skipUnless(sys.platform != "win32", "POSIX nofollow/current-UID qualification")
    def test_policy_data_rejects_symlink_and_multiple_links(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "policy.json"
            target.write_bytes(policy.MANIFEST_PATH.read_bytes())
            alias = root / "alias.json"
            alias.symlink_to(target)
            with self.assertRaisesRegex(policy.ActionPolicyError, "policy_source_custody_failed"):
                policy.load_catalog(alias)
            alias.unlink()
            os.link(target, alias)
            with self.assertRaisesRegex(policy.ActionPolicyError, "policy_source_custody_failed"):
                policy.load_catalog(target)

    def test_imported_catalog_refuses_source_or_json_change_before_lookup_and_audit(self):
        for filename in ("tool_action_policy.json", "tool_action_policy.py"):
            for operation in ("lookup", "audit"):
                with self.subTest(filename=filename, operation=operation), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    package = root / "agent_tools"
                    package.mkdir()
                    (package / "__init__.py").write_text("")
                    for name in ("tool_action_policy.py", "tool_action_policy.json", "source_module_loader.py",
                                 "native_review_source_closure.py", "windows_source_custody.py"):
                        shutil.copyfile(ROOT / "agent_tools" / name, package / name)
                    script = (
                        "from agent_tools import tool_action_policy as p\n"
                        "from pathlib import Path\n"
                        f"target=Path('agent_tools/{filename}')\n"
                        "target.write_bytes(target.read_bytes()+b'\\n')\n"
                        "try:\n"
                        + (" p.action_policy('ssh_workflow','inventory')\n" if operation == "lookup" else " p.audit_action_catalog(Path.cwd())\n")
                        + "except p.ActionPolicyError as error:\n print(str(error))\n raise SystemExit(0)\n"
                        "raise SystemExit(9)\n"
                    )
                    result = subprocess.run([sys.executable, "-B", "-c", script], cwd=root, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "loaded_policy_changed")

    def test_captured_source_adapter_loads_catalog(self):
        from agent_tools import source_module_loader
        with source_module_loader.request_scope(ROOT / "agent_tools"):
            adapter = source_module_loader.adapter(ROOT / "agent_tools", "tool_action_policy")
            item = adapter.action_policy("ssh_workflow", "inventory")
            self.assertEqual(item.classification, "local_metadata")
            self.assertFalse(item.permitted_recoveries)

    def test_malformed_catalog_errors_are_finite(self):
        for value in ([], {"schemaVersion": 1, "groups": None}, {"schemaVersion": 1, "groups": [None]}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                target = Path(directory).resolve() / "policy.json"
                target.write_text(json.dumps(value))
                with self.assertRaises(policy.ActionPolicyError) as raised:
                    policy.load_catalog(target)
                self.assertIn(str(raised.exception), {"unsupported_policy_schema", "invalid_policy_document"})

    def test_dispatch_inventory_excludes_substring_tests(self):
        import ast
        tree = ast.parse('def dispatch(action):\n if "-start" in action: pass\n if action == "actual": pass\n')
        self.assertEqual(policy._dispatch_actions(tree, {"dispatch"}), {"actual"})


if __name__ == "__main__":
    unittest.main()
