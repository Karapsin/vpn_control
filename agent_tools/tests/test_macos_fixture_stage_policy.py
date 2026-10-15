"""Execute the real public/batch policy callbacks with inert native effects."""
import ast
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest import mock

from agent_tools import mcp_server as server, native_workflow_policy as policy


class MacosFixtureStagePolicyTests(unittest.TestCase):
    def callbacks(self, effect, source=None):
        source = source or Path(os.environ.get("VPN_MACOS_STAGE_POLICY_SOURCE", server.__file__))
        tree = ast.parse(source.read_bytes())
        names = {"vm_workflow", "_native_fixed_dispatch"}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(names, {node.name for node in nodes})
        namespace = dict(vars(server))
        namespace.update(native_workflow_policy=policy, _vm_workflow_impl=effect,
                         _native_response=lambda _tool, _action, value, _inputs: value)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
        return namespace["vm_workflow"], namespace["_native_fixed_dispatch"]

    def test_new_correlation_cannot_submit_to_the_implicit_historical_guest(self):
        effect = mock.Mock(return_value={"state": "submitted"})
        public, batch = self.callbacks(effect)
        action = "macos-fixture-guest-stage-start"
        result = public(action, {"correlationId": "fresh-request"})
        self.assertEqual("blocked", result["state"])
        self.assertEqual("historical_macos_fixture_stage_retired", result["reason"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["replayAllowed"])
        self.assertEqual(result, batch("vm", action, {"correlationId": "fresh-request"}))
        effect.assert_not_called()

    def test_preserved_before_callback_reaches_the_inert_submission(self):
        folder = Path(__file__).parent / "fixtures" / "macos_stage_policy"
        source = folder / "before.source"
        provenance = json.loads((folder / "provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(provenance["fragmentSha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        effect = mock.Mock(return_value={"state": "submitted"})
        public, _batch = self.callbacks(effect, source)
        identity = {"correlationId": "fresh-request"}
        result = public("macos-fixture-guest-stage-start", identity)
        self.assertEqual("submitted", result["state"])
        effect.assert_called_once_with("macos-fixture-guest-stage-start", identity)

    def test_original_status_and_collection_keep_the_original_inputs(self):
        effect = mock.Mock(return_value={"state": "unknown", "replayAllowed": False})
        public, _batch = self.callbacks(effect)
        for action in ("macos-fixture-guest-stage-status", "macos-fixture-guest-stage-collect"):
            identity = {"correlationId": "unresolved-original"}
            effect.reset_mock()
            self.assertIsNone(policy.refusal(action))
            result = public(action, identity)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            effect.assert_called_once_with(action, identity)


if __name__ == "__main__":
    unittest.main()
