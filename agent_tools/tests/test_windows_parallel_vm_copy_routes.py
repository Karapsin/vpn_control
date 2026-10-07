"""Actual fixed copy producer DTOs through MCP ingress; no SSH/VM/credentials."""
import ast
import copy
import inspect
import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import mcp_server as server
from agent_tools import windows_parallel_vm_prepare_transport as transport

CORRELATION = "cd719164-5170-4c7d-8900-f49ee7ab9322"
FOREIGN = "94f1a3c7-f53f-41b2-bafc-2ac9a08e8438"
FLAGS = {"nativeGuestStarted": False, "launchAdmitted": False, "productAcceptance": False}


def producer(function, match, namespace):
    """Evaluate exact public return/result dictionary AST with inert facts only."""
    tree = ast.parse(inspect.getsource(function))
    rows = [node for node in ast.walk(tree) if isinstance(node, ast.Dict) and match(ast.unparse(node))]
    if len(rows) != 1:
        raise AssertionError((function.__name__, len(rows)))
    return eval(compile(ast.Expression(rows[0]), "actual fixed producer DTO", "eval"), namespace)


def pin(size, uid=0, gid=0, mode=0o100600):
    return {"generation": [1, 2, mode, uid, gid, 1, size, 1, 1], "sha256": "a" * 64}


def response(method, state):
    # Entire DTO shapes come from actual producer code, not proposed schemas.
    identity = producer(transport.submit, lambda s: "'supervisorSha256'" in s,
        {"correlation": CORRELATION, "child": SimpleNamespace(pid=321), "ticks": 100,
         "intent": {"programSha256": "a" * 64}, "digest": lambda _: "b" * 64, "supervisor": "inert"})
    env = {"started": identity, "correlation": CORRELATION, "child": None, "ticks": None}
    if state in ("submitted", "running"):
        function = transport.submit if state == "submitted" else transport.query
        value = producer(function, lambda s: "'state': '" + state + "'" in s, env)
    elif state == "unknown":
        value = producer(transport.submit, lambda s: "'reason': 'submission-unknown'" in s, env)
    else:
        result = producer(transport.core.prepare_core, lambda s: "'ordinaryQemuReadAccessConfigured'" in s,
            {"correlation_id": CORRELATION, "template": transport.core.TEMPLATE_ROOT / "template.qcow2",
             "digest": "c" * 64, "sealed": pin(39 * 1024**3, gid=1000, mode=0o100440)["generation"],
             "overlays": [{"path": str(Path(p) / "disk.qcow2"),
                           "generation": pin(198144, 1000, 1000)["generation"],
                           "guestGeneration": [1, 2, 0o40700, 1000, 1000]}
                          for p in transport.inventory.DESTINATIONS]})
        child = producer(transport.supervise, lambda s: "'workerPin'" in s and "'pid'" in s and "'startTicks'" in s,
            {"correlation": CORRELATION, "child": SimpleNamespace(pid=322), "ticks": 101,
             "program_sha": "a" * 64, "worker_pin": pin(34936)})
        outcome = producer(transport.collect_copy, lambda s: "'outputBytes'" in s,
            {"code": 0, "eof": True, "total": 1021, "retained": 1021, "LIMIT": transport.LIMIT})
        outcome.update(child); outcome["rawPin"] = pin(1021)
        value = producer(transport.query, lambda s: "'copyIdentity'" in s,
            {"value": result, "started": identity, "child": child, "terminal": outcome})
    return producer(transport._dispatch, lambda s: "**value" in s,
        {"value": value, "leaf": "windows-parallel-vm-copy-" + method + "-" + "d" * 32,
         "handle": SimpleNamespace(child=SimpleNamespace(pid=123))})


class WindowsParallelCopyRoutes(unittest.TestCase):
    def setUp(self):
        boot = mock.patch.object(server, "_MCP_BOOT_TIME_NS", 2**63 - 1)
        boot.start(); self.addCleanup(boot.stop)
        self.request = {"host": "archlinux", "correlationId": CORRELATION, "timeoutSeconds": 60}

    def invoke(self, method, request=None, public=False):
        inputs = copy.deepcopy(self.request if request is None else request)
        if method == "start" and request is None:
            inputs["sourceEvidenceLeaf"] = "windows-parallel-vm-source-read-" + "e" * 32
        function = server.vm_workflow if public else server._vm_workflow_impl
        return function("windows-parallel-vm-copy-" + method, inputs)

    def test_actual_submitted_running_prepared_shapes_preserved(self):
        for method, state in (("start", "submitted"), ("status", "running"), ("status", "prepared")):
            original = response(method, state)
            with self.subTest(state=state), mock.patch.object(transport, method, return_value=original) as call:
                value = self.invoke(method)
            self.assertTrue(value["ok"])
            self.assertEqual(value["state"], state)
            self.assertEqual(value["identity"], original["identity"])
            self.assertEqual(value.get("result"), original.get("result"))
            args = {"host": "archlinux", "correlation_id": CORRELATION, "timeout_seconds": 60}
            if method == "start":
                args["source_evidence_leaf"] = "windows-parallel-vm-source-read-" + "e" * 32
            call.assert_called_once_with(server.REPO_ROOT, **args)
            for key in FLAGS:
                self.assertIs(value[key], False)
            self.assertIs(value["replayAllowed"], False)
            self.assertIs(value["productAction"], False)

    def test_actual_unknown_shapes_no_private_reason_or_replay(self):
        cases = [response("start", "unknown")]
        common = {**FLAGS, "state": "unknown", "evidenceLeaf": "windows-parallel-vm-copy-status-" + "d" * 32,
                  "originalTransportPid": 123}
        cases += [{**common, "reason": "private untrusted exception", "replayAllowed": False},
                  {**common, "reason": "copy-bootstrap-or-status"},
                  {**common, "reason": "original-observer-unknown", "originalSupervisorAlive": True,
                   "identity": response("status", "running")["identity"]}]
        terminal = response("status", "prepared")
        terminal["state"] = "unknown"
        terminal["result"] = {**FLAGS, "state": "unknown", "reason": "private exception"}
        cases.append(terminal)
        for item in cases:
            method = "start" if "-start-" in item["evidenceLeaf"] else "status"
            with self.subTest(item=item), mock.patch.object(transport, method, return_value=item):
                value = self.invoke(method)
            self.assertFalse(value["ok"])
            self.assertEqual(value["state"], "unknown")
            self.assertNotIn("private", json.dumps(value))
            self.assertIs(value["replayAllowed"], False)

    def test_invalid_fields_hosts_types_and_paths_refuse_before_dispatch(self):
        for method in ("start", "status"):
            base = dict(self.request)
            if method == "start":base["sourceEvidenceLeaf"] = "windows-parallel-vm-source-read-" + "e" * 32
            cases = [{**base, key: val} for key, val in (
                ("host", "other"), ("host", True), ("command", "id"), ("password", "private"),
                ("path", "/tmp/disk"), ("correlationId", FOREIGN.upper()), ("correlationId", 1))]
            cases += [{**base, "timeoutSeconds": val} for val in (True, 5.0, "60", 4, 61)]
            cases += [{k: v for k, v in base.items() if k != "host"}]
            if method == "start":cases += [{**base, "sourceEvidenceLeaf": value} for value in ("../escape", "/tmp/path", True)]
            with mock.patch.object(transport, method) as call:
                for request in cases:
                    with self.subTest(request=request):self.assertFalse(self.invoke(method, request)["ok"])
            call.assert_not_called()

    def test_malformed_envelopes_and_capability_promotion_refuse(self):
        for method, state in (("start", "submitted"), ("status", "prepared")):
            original = response(method, state)
            cases = [{**original, key: value} for key, value in (
                ("nativeGuestStarted", True), ("launchAdmitted", 1), ("productAcceptance", True),
                ("productAction", True), ("foreignCapability", "private"), ("replayAllowed", True),
                ("originalTransportPid", True), ("state", "accepted"), ("evidenceLeaf", "foreign"))]
            cases += [None, [], {k: v for k, v in original.items() if k != "identity"}]
            for item in cases:
                with self.subTest(item=item), mock.patch.object(transport, method, return_value=item):
                    value = self.invoke(method)
                self.assertFalse(value["ok"]);self.assertEqual(value["state"], "unknown")
                self.assertNotIn("foreignCapability", value)

    def test_identity_foreign_correlation_bool_and_extra_refuse(self):
        original = response("status", "prepared")
        cases = []
        for key, value in (("correlationId", FOREIGN), ("pid", True), ("startTicks", 0),
                           ("schemaVersion", True), ("supervisorSha256", "bad"), ("private", "secret")):
            row = copy.deepcopy(original);row["identity"][key] = value;cases.append(row)
        for row in cases:
            with self.subTest(row=row), mock.patch.object(transport, "status", return_value=row):
                self.assertFalse(self.invoke("status")["ok"])

    def test_terminal_nested_types_binding_and_eof_refuse(self):
        original = response("status", "prepared")
        mutations = [lambda r:r["terminal"].update(stdoutEof=False),
                     lambda r:r["terminal"].update(exitCode=True),
                     lambda r:r["terminal"].update(retainedBytes=1020),
                     lambda r:r["terminal"].update(private="secret"),
                     lambda r:r["terminal"]["workerPin"]["generation"].__setitem__(5, True),
                     lambda r:r["copyIdentity"].update(correlationId=FOREIGN),
                     lambda r:r["terminal"]["rawPin"].update(sha256="bad")]
        for mutate in mutations:
            row = copy.deepcopy(original);mutate(row)
            with self.subTest(mutate=mutate), mock.patch.object(transport, "status", return_value=row):
                self.assertFalse(self.invoke("status")["ok"])

    def test_prepared_artifact_geometry_paths_and_foreign_grants_refuse(self):
        original = response("status", "prepared")
        mutations = [lambda r:r["result"].update(correlationId=FOREIGN),
                     lambda r:r["result"].update(template="/tmp/foreign"),
                     lambda r:r["result"].update(ordinaryQemuReadAccessConfigured=1),
                     lambda r:r["result"].update(foreignGrant=True),
                     lambda r:r["result"]["templateGeneration"].__setitem__(5, True),
                     lambda r:r["result"]["overlays"][0].update(path="/tmp/foreign"),
                     lambda r:r["result"]["overlays"][0]["guestGeneration"].__setitem__(3, 0)]
        for mutate in mutations:
            row = copy.deepcopy(original);mutate(row)
            with self.subTest(mutate=mutate), mock.patch.object(transport, "status", return_value=row):
                self.assertFalse(self.invoke("status")["ok"])

    def test_helper_exception_and_existing_once_intent_are_not_replayed(self):
        for method in ("start", "status"):
            with mock.patch.object(transport, method, side_effect=ValueError("copy-already-submitted private")) as call:
                value = self.invoke(method, public=True)
            call.assert_called_once()
            self.assertFalse(value["ok"]);self.assertEqual(value["state"], "unknown")
            self.assertNotIn("private", json.dumps(value))
            self.assertEqual(value["nextAction"]["action"]["action"], "windows-parallel-vm-copy-status")

    def test_actual_start_existing_once_intent_refuses_before_secret_or_process(self):
        from agent_tools import windows_cp117_bound_absence_completion as authority
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / ".runtime").mkdir()
            (root / ".runtime/windows-parallel-vm-copy-intent.json").write_text('{}')
            with mock.patch.object(server, "REPO_ROOT", root), \
                 mock.patch.object(transport.core, "build_plan", return_value={}), \
                 mock.patch.object(authority, "_outer_authority", return_value={}), \
                 mock.patch.object(transport.inventory, "config_metadata", return_value={}), \
                 mock.patch.object(authority, "_read_bound_file", return_value={}), \
                 mock.patch.object(transport.subprocess, "Popen") as child:
                result = self.invoke("start")
            child.assert_not_called()
            self.assertEqual(result["state"], "unknown")
            self.assertIs(result["replayAllowed"], False)

    def test_public_enrichment_never_promotes_or_requests_start(self):
        for state in ("running", "prepared", "unknown"):
            with mock.patch.object(transport, "status", return_value=response("status", state)):
                value = self.invoke("status", public=True)
            self.assertIs(value["replayAllowed"], False)
            self.assertIs(value["launchAdmitted"], False)
            self.assertNotIn("windows-parallel-vm-copy-start", json.dumps(value["nextAction"]))

    def test_cli_uses_same_fixed_dispatch_and_adapter_catalogue(self):
        with tempfile.TemporaryDirectory() as temp:
            request = Path(temp) / "inputs.json"
            request.write_text(json.dumps(self.request))
            with mock.patch.object(transport, "status", return_value=response("status", "prepared")) as call:
                with mock.patch.object(server, "_json_print", side_effect=lambda value: value):
                    value = server.main(["vm-workflow", "windows-parallel-vm-copy-status", "--inputs-file", str(request)])
        self.assertTrue(value["ok"]);call.assert_called_once()
        self.assertIs(server._agent_module("windows_parallel_vm_prepare_transport"), transport)
