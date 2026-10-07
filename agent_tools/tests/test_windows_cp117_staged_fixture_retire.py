"""Causal guard for CP117's source-invalid staged-fixture retirement."""
from __future__ import annotations
import tempfile
import unittest
import base64
import json
import re
import sys
import contextlib
import io
from pathlib import Path
from unittest import mock
from agent_tools import windows_cp117_staged_fixture_retire as retire


class StagedFixtureRetireTests(unittest.TestCase):
    def test_lock_diagnostic_projects_only_bounded_owner_evidence(self):
        receipt = {"cause":"low-hresult-32", "lockingProcess":"qemu-ga", "count":1, "qemuGaExactLocalSystem":True}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), (None,"/qga",1,2,"SID"))), \
             mock.patch.object(retire.base, "_remote", side_effect=lambda *args: json.dumps({"state":"observed", "receipt":receipt})):
            self.assertEqual("observed", retire.diagnose_locks(temporary, {})["state"])
            receipt["count"] = 2
            self.assertEqual("lock-shape", retire.diagnose_locks(temporary, {})["phase"])

    def test_lock_diagnostic_preserves_transport_failure_phase(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), (None,"/qga",1,2,"SID"))), \
             mock.patch.object(retire.base, "_remote", return_value='{"state":"diagnosed","phase":"powershell-nonzero"}'):
            self.assertEqual("powershell-nonzero", retire.diagnose_locks(temporary, {})["phase"])

    def test_tree_diagnostic_rejects_unexpected_private_fields(self):
        receipt = {**{key:"absent" for key in ("root","bundle","content","result","serverState","probeEvents","resultReadOnly")},
            **{key:0 for key in ("unexpectedRootCount","contentFileCount","probeEntryCount","otherPowerShellCount")},
            "resultAccess":"absent","privatePath":"secret"}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base,"_descriptor",return_value=(object(),object(),(None,"/qga",1,2,"SID"))), \
             mock.patch.object(retire.base,"_remote",return_value=json.dumps({"state":"observed","receipt":receipt})):
            result=retire.diagnose_tree(temporary,{})
        self.assertNotIn("privatePath",result)
        self.assertEqual("diagnosed",result["state"])

    def test_partial_retirement_recovery_does_not_require_deleted_full_stage(self):
        intent={"request":{"targetMsiArtifactId":"sha256-"+"1"*64}}
        ready={"state":"ready","ready":True,"installedVersion":"2.1.19","productCount":1,"activeCount":0,"activeProcesses":[]}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base,"readiness",return_value=ready), \
             mock.patch.object(retire.stage,"status",return_value={"state":"unknown"}), \
             mock.patch.object(retire.phase.http_stage,"listener_status",return_value={"state":"stopped"}), \
             mock.patch.object(retire,"_admitted",return_value=(intent,{},("windows-cp117","/qga",1,2,"SID"))), \
             mock.patch.object(retire.base,"_descriptor",return_value=(object(),object(),("windows-cp117","/qga",1,2,"SID"))), \
             mock.patch.object(retire.lease,"_remote_confirm",return_value=True), \
             mock.patch.object(retire.base,"_campaign_remote",return_value=object()):
            self.assertFalse(retire._fresh(Path(temporary),intent,()))
            self.assertTrue(retire._recovery_fresh(Path(temporary),intent,("windows-cp117","/qga",1,2,"SID")))

    def test_exact_parser_transport_does_not_double_encode_large_guard_script(self):
        encoded = base64.b64encode(("#" + "x" * 7700).encode("utf-16le")).decode()
        submitted = []
        def call(sock, command, values):
            if command == "guest-exec":
                submitted.append(values)
                self.assertLess(sum(len(x) for x in values["arg"]), 30000)
                return {"pid": 3}
            return {"exited": True, "exitcode": 0,
                    "out-data": base64.b64encode(b'{"syntax":"valid","runtime":"available"}').decode()}
        namespace = {"live": lambda *args: True, "call": call,
                     "decode": lambda value: value.decode()}
        with mock.patch.object(sys, "argv", ["parser", "/qga", "1", "2", encoded]), contextlib.redirect_stdout(io.StringIO()) as output:
            exec(retire._REMOTE_PARSER[len(retire.base._QGA):], namespace)
        self.assertEqual("observed", json.loads(output.getvalue())["state"])
        self.assertEqual(1, len(submitted))

    def test_terminal_stage_guard_uses_idle_campaign_without_requiring_completed_stage_role(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire, "_script", return_value="guard"), \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), ("windows-cp117","/qga",1,2,"SID"))), \
             mock.patch.object(retire.phase.http_stage, "_qga_action", side_effect=AssertionError("completed stage role cannot be reclaimed")), \
             mock.patch.object(retire.base, "_remote", return_value='{"state":"staged"}'):
            self.assertEqual("ready", retire._guest_preflight(Path(temporary))["state"])

    def test_runtime_census_pattern_detects_actual_windows_executable_names(self):
        # PowerShell and Python agree on this regular-expression escape. A
        # double slash matches a literal slash instead of the filename dot.
        for source in retire._SCRIPT_TEMPLATES.values():
            pattern = re.search(r"\$_.Name -match '([^']+)'", source).group(1)
            for name in ("vpn-control.exe", "vpn-control-cli.exe", "msiexec.exe", "consent.exe", "sing-box.exe"):
                self.assertIsNotNone(re.fullmatch(pattern, name), name)
            self.assertIsNone(re.fullmatch(pattern, "unrelated.exe"))

    def test_parser_observes_exact_three_generated_scripts_without_invoking_them(self):
        scripts = {kind: "source-for-" + kind for kind in ("diagnostic", "preflight", "retire")}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), (None,"/qga",1,2,"SID"))), \
             mock.patch.object(retire, "_script", side_effect=lambda root, kind: scripts[kind]), \
             mock.patch.object(retire.base, "_remote", return_value=json.dumps({"state":"observed", "receipt":{"syntax":"valid","runtime":"available"}})) as remote:
            result = retire.diagnose_parser(Path(temporary), {})
        self.assertEqual(set(scripts), set(result["scripts"]))
        self.assertEqual(list(scripts.values()), [base64.b64decode(c.args[2][3]).decode("utf-16le") for c in remote.call_args_list])
        self.assertTrue(all(c.args[1] == retire._REMOTE_PARSER for c in remote.call_args_list))

    def test_generated_diagnostic_has_no_unmatched_closing_block(self):
        # The native diagnostic failed before any observer could run because it
        # had a trailing catch for an already closed try block. Ignore quoted
        # path/argument text and reduce that exact generated grammar defect.
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), (None,"/qga",1,2,"S-1-5-21-1-2-3-4"))), \
             mock.patch.object(retire.server, "_read_intent", return_value={"request":{}, "pythonPath":"C:\\Python\\python.exe"}), \
             mock.patch.object(retire.server, "_request", return_value={}), \
             mock.patch.object(retire.server, "_launch_arguments", return_value="-m fixture"), \
             mock.patch.object(retire.base, "_remote", return_value='{}') as remote:
            retire.diagnose(Path(temporary), {})
        source = base64.b64decode(remote.call_args.args[2][3]).decode("utf-16le")
        unquoted = re.sub(r"'([^']|'')*'|\"([^\"]|`\")*\"", "", source)
        depth = 0
        for char in unquoted:
            depth += (char == "{") - (char == "}")
            self.assertGreaterEqual(depth, 0, "generated observer closes a block that was never opened")
        self.assertEqual(0, depth)

    def test_red_stale_native_evidence_never_reserves_the_one_shot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
                 mock.patch.object(retire, "_fresh", return_value=False), \
                 mock.patch.object(retire, "_guest_preflight", return_value={"state":"ready"}):
                self.assertEqual("blocked", retire.start(root, {})["state"])
            self.assertFalse((root / retire._DIR / "intent.json").exists())

    def test_green_exact_fresh_evidence_reserves_once_and_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
                 mock.patch.object(retire, "_fresh", return_value=True), \
                 mock.patch.object(retire, "_guest_preflight", return_value={"state":"ready"}), \
                 mock.patch.object(retire, "_guest_retire", return_value=True), \
                 mock.patch.object(retire, "_remove_host", return_value=True), \
                 mock.patch.object(retire, "_close", return_value=True):
                self.assertEqual("retired", retire.start(root, {})["state"])
                self.assertEqual("unknown", retire.start(root, {})["state"])
            self.assertEqual("unknown", retire.status(root, {})["state"])

    def test_red_guest_failure_never_removes_host_payload_or_closes_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
                 mock.patch.object(retire, "_fresh", return_value=True), \
                 mock.patch.object(retire, "_guest_preflight", return_value={"state":"ready"}), \
                 mock.patch.object(retire, "_guest_retire", return_value=False), \
                 mock.patch.object(retire, "_remove_host") as host, \
                 mock.patch.object(retire, "_close") as close:
                self.assertEqual("unknown", retire.start(root, {})["state"])
            host.assert_not_called(); close.assert_not_called()

    def test_host_reply_loss_retains_completed_guest_step_and_never_repeats_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
                 mock.patch.object(retire, "_fresh", return_value=True), \
                 mock.patch.object(retire, "_guest_preflight", return_value={"state":"ready"}), \
                 mock.patch.object(retire, "_guest_retire", return_value=True) as guest, \
                 mock.patch.object(retire, "_remove_host", return_value=False) as host, \
                 mock.patch.object(retire, "_close") as close:
                self.assertEqual("host-submitted", retire.start(root, {})["phase"])
                self.assertEqual("host-submitted", retire.status(root, {})["phase"])
                self.assertEqual("unknown", retire.start(root, {})["state"])
            guest.assert_called_once(); host.assert_called_once(); close.assert_not_called()
            self.assertEqual(retire._step("guest-removed"), retire._read(root / retire._DIR / "guest-removed.json"))

    def test_guest_dry_run_blocks_before_retirement_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(retire, "_admitted", return_value=({}, {}, ())), \
                 mock.patch.object(retire, "_fresh", return_value=True), \
                 mock.patch.object(retire, "_guest_preflight", return_value={"state":"blocked"}):
                self.assertEqual("blocked", retire.preflight(root, {})["state"])
                self.assertEqual("blocked", retire.start(root, {})["state"])
            self.assertFalse((root / retire._DIR / "intent.json").exists())

    def test_diagnostic_projects_finite_guest_guard_that_blocked_preflight(self):
        receipt = {"stage":"present","owner":"original-user","reparse":"absent","serverTask":"absent",
                   "serverProcess":"absent","listener":"present","credentials":"absent","runtime":"absent"}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), (None,"/qga",1,2,"S-1-5-21-1-2-3-4"))), \
             mock.patch.object(retire.server, "_read_intent", return_value={"request":{}, "pythonPath":"C:\\Python\\python.exe"}), \
             mock.patch.object(retire.server, "_request", return_value={}), \
             mock.patch.object(retire.server, "_private_tls_descriptor", side_effect=AssertionError("must not read cleaned credentials")), \
             mock.patch.object(retire.server, "_launch_arguments", return_value="-m fixture"), \
             mock.patch.object(retire.base, "_remote", return_value='{"state":"observed","receipt":'+__import__('json').dumps(receipt)+'}'):
            result = retire.diagnose(Path(temporary), {})
        self.assertEqual("observed", result["state"]); self.assertEqual("present", result["listener"])

    def test_diagnostic_preserves_bounded_powershell_nonzero_phase(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), (None,"/qga",1,2,"S-1-5-21-1-2-3-4"))), \
             mock.patch.object(retire.server, "_read_intent", return_value={"request":{}, "pythonPath":"C:\\Python\\python.exe"}), \
             mock.patch.object(retire.server, "_request", return_value={}), \
             mock.patch.object(retire.server, "_launch_arguments", return_value="-m fixture"), \
             mock.patch.object(retire.base, "_remote", return_value='{"state":"diagnosed","phase":"powershell-nonzero"}'):
            result = retire.diagnose(Path(temporary), {})
        self.assertEqual({"state":"diagnosed", "phase":"powershell-nonzero"}, {"state":result["state"], "phase":result["phase"]})

    def test_status_reconciles_only_the_reserved_close_after_a_lost_reply(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); directory = root / retire._DIR
            retire.guards.secure_write_create(directory / "intent.json", {})
            retire.guards.secure_write_create(directory / "receipt.json", {"leaseId":retire._LEASE, "removed":True,"stageCorrelationId":retire._STAGE})
            with mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), ())), \
                 mock.patch.object(retire.base, "_campaign_remote", return_value=object()), \
                 mock.patch.object(retire.lease, "reconcile", return_value={"state":"closed"}) as reconcile:
                self.assertEqual("retired", retire.status(root, {})["state"])
            reconcile.assert_called_once()

    def test_authoritative_stage_readback_accepts_served_listener_without_consumed_guest_process(self):
        intent = {"request": {"targetMsiArtifactId": "sha256-" + "a" * 64}}
        idle = {"state":"ready", "ready":True, "installedVersion":"2.1.19", "productCount":1,
                "activeCount":0, "activeProcesses":[]}
        staged = {"state":"staged-not-server-ready", "sourceSha":retire._SOURCE,
                  "targetMsiSha256":"a" * 64, "serverReady":False}
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base, "readiness", return_value=idle), \
             mock.patch.object(retire.stage, "status", return_value=staged), \
             mock.patch.object(retire.phase.http_stage, "listener_status", return_value={"state":"served"}):
            self.assertTrue(retire._fresh(Path(temporary), intent, ()))

    def test_unrelated_loopback_is_permitted_but_matching_fixture_listener_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(retire.base, "_descriptor", return_value=(None, None, (None, None, None, None, "S-1-5-21-1-2-3-4"))), \
             mock.patch.object(retire.server, "_read_intent", return_value={"request": {}, "pythonPath": r"C:\\Python\\python.exe"}), \
             mock.patch.object(retire.server, "_request", return_value={}), \
             mock.patch.object(retire.server, "_private_tls_descriptor", side_effect=AssertionError("must not read cleaned credentials")), \
             mock.patch.object(retire.server, "_launch_arguments", return_value="-m fixture --fixed"), \
             mock.patch.object(retire.stage, "_read_intent", return_value={"request":{"correlationId":retire._STAGE}, "bundleSha256":"a"*64, "bundleSize":1, "fileHashes":{"server/test.py":"b"*64}}), \
             mock.patch.object(retire, "_run_guard", return_value=True) as qga:
            self.assertTrue(retire._guest_retire(Path(temporary)))
        script = qga.call_args.args[1]
        self.assertIn(retire.stage._GUEST + r"\mcp-update-fixture-" + retire._STAGE, script)
        self.assertIn(retire.credentials._fixed_paths(retire._STAGE)["directory"], script)
        self.assertIn("ReparsePoint", script)
        self.assertIn("OwningProcess", script)
        self.assertNotIn("LocalAddress -eq '127.0.0.1'", script)
        self.assertIn("$fixture.Count -ne 0 -or $listeners.Count -ne 0", script)

    def test_tls_mapping_not_qga_tuple_builds_server_arguments(self):
        request = {"stageCorrelationId": retire._STAGE}
        paths = {"directory": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + retire._STAGE,
                 "certificate": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + retire._STAGE + r"\server-cert.pem",
                 "privateKey": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + retire._STAGE + r"\server-key.pem",
                 "trustStore": r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + retire._STAGE + r"\fixture-trust.p12"}
        with self.assertRaises(TypeError):
            retire.server._launch_arguments(request, ("windows-cp117", "/qga", 1, 2, "S-1"))
        self.assertIn("prepare_desktop_update_fixture.py", retire.server._launch_arguments(request, {"paths": paths}))

    def test_cleaned_credential_state_never_requires_live_tls_descriptor(self):
        request = {"stageCorrelationId": retire._STAGE}
        with mock.patch.object(retire.server, "_private_tls_descriptor", side_effect=AssertionError("cleaned credentials")):
            arguments = retire.server._launch_arguments(request, {"paths": retire.credentials._fixed_paths(retire._STAGE)})
        self.assertIn("mcp-update-credentials-" + retire._STAGE, arguments)


if __name__ == "__main__": unittest.main()
