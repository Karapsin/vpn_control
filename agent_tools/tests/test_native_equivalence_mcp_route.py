"""The public route must retain provenance without granting current CI success."""
import contextlib
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import native_acceptance_matrix as matrix
from agent_tools.tests import test_native_acceptance_equivalence as fixture_module


class EquivalenceMcpRouteTest(unittest.TestCase):
    request = {"receiptId": "native-acceptance-" + "a" * 32,
               "artifactSetId": "artifact-set-" + "b" * 64,
               "targetSourceSHA": "c" * 40, "reviewerAttestation": "reviewed"}

    def setUp(self):
        patch = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        patch.start(); self.addCleanup(patch.stop)

    def output(self):
        return {"linkId": "native-equivalence-" + "d" * 32,
                "receiptId": self.request["receiptId"], "originalSourceSHA": "e" * 40,
                "targetSourceSHA": self.request["targetSourceSHA"],
                "requiredCurrentChecks": ["exact-sha-ci", "changed-tool-tests"]}

    def test_registered_route_preserves_provenance_and_open_checks(self):
        with mock.patch.object(matrix, "matrix_equivalence_record", return_value=self.output()) as record:
            result = server._vm_workflow_impl("matrix-equivalence-record", dict(self.request))
        self.assertTrue(result["ok"])
        record.assert_called_once_with(server.REPO_ROOT, self.request)
        self.assertEqual(self.output(), {k: result[k] for k in self.output()})
        self.assertFalse(result["nativeActionPerformed"])
        self.assertFalse(result["currentChecksCompleted"])

    def test_invalid_requests_never_create_a_link(self):
        for edit in ({"privatePath": "/private/secret"}, {"targetSourceSHA": True},
                     {"reviewerAttestation": ""}, {"receiptId": "bad"}, {"artifactSetId": "../bad"},
                     {"artifactSetId": "abc"}, {"artifactSetId": "artifact-set-" + "b" * 32}):
            with self.subTest(edit=edit), mock.patch.object(matrix, "matrix_equivalence_record") as record:
                result = server._vm_workflow_impl("matrix-equivalence-record", {**self.request, **edit})
                self.assertFalse(result["ok"]); record.assert_not_called()

    def test_invalid_or_private_response_is_unknown_without_replay(self):
        for field, value in (("privateKey", "secret-marker"), ("originalSourceSHA", True),
                             ("targetSourceSHA", "f" * 40), ("receiptId", "native-acceptance-" + "f" * 32),
                             ("requiredCurrentChecks", ["exact-sha-ci", "exact-sha-ci"]),
                             ("requiredCurrentChecks", ["changed-tool-tests"]),
                             ("requiredCurrentChecks", ["exact-sha-ci", "passed"])):
            output = copy.deepcopy(self.output()); output[field] = value
            with self.subTest(field=field, value=value), mock.patch.object(matrix, "matrix_equivalence_record", return_value=output):
                result = server._vm_workflow_impl("matrix-equivalence-record", self.request)
                self.assertFalse(result["ok"]); self.assertEqual("unknown", result["state"])
                self.assertFalse(result["replayAllowed"]); self.assertNotIn("secret-marker", str(result))

    def test_core_failure_never_leaks_error_or_authorizes_retry(self):
        with mock.patch.object(matrix, "matrix_equivalence_record", side_effect=ValueError("secret-marker")):
            result = server._vm_workflow_impl("matrix-equivalence-record", self.request)
        self.assertFalse(result["ok"]); self.assertFalse(result["replayAllowed"])
        self.assertNotIn("secret-marker", str(result))

    def test_cli_inputs_file_dispatches_exact_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"; path.write_text(json.dumps(self.request))
            with mock.patch.object(server, "vm_workflow", return_value={"ok": True}) as dispatch, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, server.main(["vm-workflow", "matrix-equivalence-record", "--inputs-file", str(path)]))
            dispatch.assert_called_once_with("matrix-equivalence-record", self.request)

    @unittest.skipIf(os.name == "nt", "private acceptance evidence requires POSIX ownership")
    def test_actual_committed_docs_link_through_public_route(self):
        fixture = fixture_module.NativeAcceptanceEquivalenceTest()
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        (fixture.root / "docs/guide.md").write_text("after\n"); fixture.commit()
        request = {"receiptId": fixture.record["receiptId"], "artifactSetId": fixture.frozen["artifactSetId"],
                   "targetSourceSHA": fixture.head(), "reviewerAttestation": "reviewed docs-only change"}
        request_path = Path(fixture.temp.name) / "request.json"
        request_path.write_text(json.dumps(request)); request_path.chmod(0o600)
        # Exercise fresh import, public action registration, inputs-file parsing,
        # and JSON serialization, rather than mocking the CLI dispatcher.
        program = ("import sys; from pathlib import Path; from agent_tools import mcp_server as s; "
                   "s.REPO_ROOT=Path(sys.argv[1]); "
                   "raise SystemExit(s.main(['vm-workflow','matrix-equivalence-record',"
                   "'--inputs-file',sys.argv[2]]))")
        completed = subprocess.run([sys.executable, "-c", program, str(fixture.root), str(request_path)],
                                   cwd=server.REPO_ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(0, completed.returncode, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["ok"]); self.assertFalse(result["currentChecksCompleted"])
        with mock.patch.object(server, "REPO_ROOT", fixture.root):
            duplicate = server._vm_workflow_impl("matrix-equivalence-record", request)
            status = server._vm_workflow_impl("matrix-status", {})
        self.assertFalse(duplicate["ok"]); self.assertFalse(duplicate["replayAllowed"])
        self.assertTrue(status["ok"])
        row = fixture.row(fixture.head())
        self.assertEqual("passed", row["status"])
        self.assertEqual(fixture.original, row["originalSourceSHA"])
        self.assertEqual(["exact-sha-ci"], row["requiredCurrentChecks"])
        self.assertEqual(result["linkId"], row["equivalenceLinkId"])
