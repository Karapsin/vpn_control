import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import windows_msi_transfer_endpoint as endpoint
from agent_tools import mcp_server


class WindowsMsiTransferEndpointTest(unittest.TestCase):
    correlation = endpoint._CORRELATION

    def _admission(self):
        return {"state": "ready", "correlationId": self.correlation, "qga": "healthy", "network": "slirp",
                "endpointEligibility": "eligible", "hostBindAddress": "127.0.0.1",
                "guestHostAddress": "10.0.2.2", "replayAllowed": False, "nativeActionAllowed": False}

    def _descriptor(self):
        class Target:
            fixture_transfer_root = Path("/private/cp117")
        return object(), Target(), ("windows-cp117", "/qga.sock", 4321, 98765, "S-1-5-21-1-2-3-1002")

    def _intent(self, root):
        journal = root / endpoint.base._LOCAL
        journal.mkdir(mode=0o700, parents=True)
        value = {"request": endpoint.base._TRANSFER_RECOVERY_REQUEST,
                 "commandSha256": endpoint.base._TRANSFER_RECOVERY_COMMAND_SHA256,
                 "leaseId": self.correlation, "environment": "windows-cp117", "socketPath": "/qga.sock",
                 "pid": 4321, "startTicks": 98765, "expectedSid": "S-1-5-21-1-2-3-1002"}
        path = journal / (self.correlation + ".json")
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def _run(self, replies):
        def remote(_config, program, args, source, timeout):
            if program is endpoint._REMOTE_START:
                self.assertEqual(timeout, 10)
                self.assertIsNotNone(source)
                payload = json.loads(source.read_text())
                self.assertEqual(set(payload), {"path", "token"})
                self.assertNotIn(payload["path"], args)
                self.assertNotIn(payload["token"], args)
                self.assertEqual(len(args), 6)
            elif program is endpoint._REMOTE_PROBE:
                self.assertEqual(timeout, 20)
                self.assertIsNone(source)
            elif program is endpoint._REMOTE_STOP:
                self.assertEqual(timeout, 10)
                self.assertIsNone(source)
            else:
                self.fail("unexpected remote program")
            value = replies.pop(0)
            if callable(value):
                value = value(args)
            return value
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(endpoint.base, "transfer_network_admission", return_value=self._admission()), \
             patch.object(endpoint.base, "_descriptor", return_value=self._descriptor()), \
             patch.object(endpoint.base, "_remote", side_effect=remote):
            self._intent(Path(directory))
            result = endpoint.endpoint_probe(Path(directory), {"correlationId": self.correlation})
        self.assertFalse(replies, "endpoint did not reconcile its listener")
        return result

    def test_success_requires_exact_nonce_projection_and_proven_stop(self):
        def observed(args):
            return json.dumps({"state": "observed", "bodySha256": args[-1]}).encode()
        result = self._run([b'{"port":43123,"state":"ready"}', observed, b'{"state":"stopped"}'])
        self.assertEqual(result["state"], "reachable")
        self.assertTrue(result["reachable"])
        self.assertEqual(result["cleanup"], "stopped")

    def test_refusal_is_bounded_blocked_only_after_stop(self):
        result = self._run([b'{"port":43123,"state":"ready"}', b'{"state":"blocked"}', b'{"state":"stopped"}'])
        self.assertEqual(result["state"], "blocked")
        self.assertFalse(result["reachable"])

    def test_spoofed_guest_projection_stays_unknown(self):
        result = self._run([b'{"port":43123,"state":"ready"}',
                            b'{"bodySha256":"' + b"0" * 64 + b'","state":"observed"}',
                            b'{"state":"stopped"}'])
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["cleanup"], "stopped")

    def test_timeout_stays_unknown_and_stops_listener(self):
        result = self._run([b'{"port":43123,"state":"ready"}', None, b'{"state":"stopped"}'])
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["cleanup"], "stopped")

    def test_lost_start_response_still_stops_possible_listener(self):
        result = self._run([None, b'{"state":"stopped"}'])
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["cleanup"], "stopped")

    def test_delayed_ready_response_still_stops_worker_recorded_before_ready(self):
        result = self._run([b'{"state":"unknown"}', b'{"state":"stopped"}'])
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["cleanup"], "stopped")

    def test_generation_change_after_admission_makes_zero_remote_calls(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(endpoint.base, "transfer_network_admission", return_value=self._admission()), \
             patch.object(endpoint.base, "_descriptor", return_value=self._descriptor()), \
             patch.object(endpoint.base, "_remote", side_effect=AssertionError("endpoint must not open")):
            root = Path(directory); self._intent(root)
            intent_path = root / endpoint.base._LOCAL / (self.correlation + ".json")
            changed = json.loads(intent_path.read_text()); changed["startTicks"] = 98766
            intent_path.write_text(json.dumps(changed)); intent_path.chmod(0o600)
            result = endpoint.endpoint_probe(root, {"correlationId": self.correlation})
        self.assertEqual(result["state"], "unknown")

    def test_unknown_cleanup_overrides_success(self):
        def observed(args):
            return json.dumps({"state": "observed", "bodySha256": args[-1]}).encode()
        result = self._run([b'{"port":43123,"state":"ready"}', observed, None])
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["cleanup"], "unknown")

    def test_admission_or_input_failure_never_opens_listener(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(endpoint.base, "transfer_network_admission", return_value={"state": "unknown"}), \
             patch.object(endpoint.base, "_remote", side_effect=AssertionError("listener opened")):
            self.assertEqual(endpoint.endpoint_probe(Path(directory), {"correlationId": self.correlation})["state"], "unknown")
        with self.assertRaises(endpoint.WindowsMsiTransferEndpointError):
            endpoint.endpoint_probe(Path.cwd(), {"correlationId": "not-the-reviewed-correlation"})

    def test_remote_programs_reject_truncation_and_recheck_topology(self):
        self.assertIn("user_network(pid)", endpoint._REMOTE_PROBE)
        self.assertIn("UseProxy=$false", endpoint._REMOTE_PROBE)
        self.assertIn("'out-truncated' in item", endpoint._REMOTE_PROBE)
        self.assertIn("'err-truncated' in item", endpoint._REMOTE_PROBE)
        self.assertIn("('127.0.0.1',0)", endpoint._REMOTE_START)
        self.assertIn("worker.json", endpoint._REMOTE_START)
        self.assertIn("worker.json", endpoint._REMOTE_STOP)
        self.assertIn("child=subprocess.Popen((sys.executable,'-c',worker,stage)", endpoint._REMOTE_START)
        self.assertIn("child.stdin.write(worker_payload)", endpoint._REMOTE_START)
        self.assertIn("stop(child.pid,worker_tick,port)", endpoint._REMOTE_START)
        self.assertIn("probe.bind(('127.0.0.1',worker['port']))", endpoint._REMOTE_STOP)
        self.assertNotIn("msiexec", endpoint._REMOTE_START + endpoint._REMOTE_PROBE + endpoint._REMOTE_STOP)

    def test_mcp_route_preserves_non_product_endpoint_result(self):
        request = {"correlationId": self.correlation}
        with patch.object(endpoint, "endpoint_probe", return_value={
                "state": "reachable", "correlationId": self.correlation, "reachable": True,
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}) as probe:
            result = mcp_server._vm_workflow_impl("windows-msi-base-transfer-endpoint-probe", request)
        probe.assert_called_once_with(mcp_server.REPO_ROOT, request)
        self.assertTrue(result["ok"])
        self.assertFalse(result["productAction"])
        self.assertEqual(result["evidenceClass"], "native-preflight")

    def test_mcp_status_and_reconcile_routes_keep_cleanup_separate(self):
        request = {"correlationId": self.correlation}
        with patch.object(endpoint, "endpoint_probe_status", return_value={"state": "observed"}) as status:
            observed = mcp_server._vm_workflow_impl("windows-msi-base-transfer-endpoint-status", request)
        status.assert_called_once_with(mcp_server.REPO_ROOT, request)
        self.assertTrue(observed["ok"]); self.assertFalse(observed["productAction"])
        self.assertEqual(observed["evidenceClass"], "causal-status")
        with patch.object(endpoint, "endpoint_probe_reconcile", return_value={"state": "stopped"}) as reconcile:
            stopped = mcp_server._vm_workflow_impl("windows-msi-base-transfer-endpoint-reconcile", request)
        reconcile.assert_called_once_with(mcp_server.REPO_ROOT, request)
        self.assertTrue(stopped["ok"]); self.assertFalse(stopped["productAction"])
        self.assertEqual(stopped["evidenceClass"], "causal-cleanup")

    def test_status_projects_only_bounded_owned_identity(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(endpoint, "_bound_endpoint", return_value=(Path(directory), object(), self._descriptor()[1], self._descriptor()[2])), \
             patch.object(endpoint.base, "_remote", return_value=b'{"listener":"owned","port":"bound","receipt":"unknown","startup":"ready","state":"observed","worker":"running"}') as remote:
            result = endpoint.endpoint_probe_status(Path(directory), {"correlationId": self.correlation})
        self.assertEqual(result["listener"], "owned")
        self.assertTrue(result["nativeActionAllowed"])
        self.assertIs(remote.call_args.args[1], endpoint._REMOTE_STATUS)
        self.assertIsNone(remote.call_args.args[3])

    def test_status_rejects_unattributed_or_spoofed_worker_record(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(endpoint, "_bound_endpoint", return_value=(Path(directory), object(), self._descriptor()[1], self._descriptor()[2])), \
             patch.object(endpoint.base, "_remote", return_value=b'{"listener":"unattributed","port":"bound","receipt":"unknown","startup":"ready","state":"observed","worker":"stopped"}'):
            result = endpoint.endpoint_probe_status(Path(directory), {"correlationId": self.correlation})
        self.assertEqual(result["listener"], "unattributed")
        self.assertFalse(result["nativeActionAllowed"])
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(endpoint, "_bound_endpoint", return_value=(Path(directory), object(), self._descriptor()[1], self._descriptor()[2])), \
             patch.object(endpoint.base, "_remote", return_value=b'{"listener":"owned","port":"bound","receipt":"unknown","startup":"ready","state":"observed","worker":"stopped"}'):
            self.assertEqual(endpoint.endpoint_probe_status(Path(directory), {"correlationId": self.correlation})["state"], "unknown")

    def test_reconcile_never_kills_unattributed_listener(self):
        status = {"state": "observed", "correlationId": self.correlation, "worker": "running",
                  "listener": "unattributed", "port": "bound", "replayAllowed": False,
                  "nativeActionAllowed": False, "productAction": False}
        with patch.object(endpoint, "endpoint_probe_status", return_value=status), \
             patch.object(endpoint.base, "_remote", side_effect=AssertionError("must not stop foreign listener")):
            result = endpoint.endpoint_probe_reconcile(Path.cwd(), {"correlationId": self.correlation})
        self.assertEqual(result["outcome"], "not-owned")
        self.assertEqual(result["state"], "unknown")

    def test_reconcile_lost_stop_response_uses_fresh_status_without_replay(self):
        running = {"state": "observed", "correlationId": self.correlation, "worker": "running",
                   "listener": "owned", "port": "bound", "replayAllowed": False,
                   "startup": "ready", "receipt": "unknown", "nativeActionAllowed": True, "productAction": False}
        stopped = {"state": "observed", "worker": "stopped", "listener": "absent", "port": "free", "startup": "ready", "receipt": "not-seen"}
        class Target: fixture_transfer_root = Path("/private/cp117")
        with patch.object(endpoint, "endpoint_probe_status", return_value=running), \
             patch.object(endpoint, "_bound_endpoint", return_value=(Path.cwd(), object(), Target(), self._descriptor()[2])), \
             patch.object(endpoint, "_status", return_value=stopped) as status, \
             patch.object(endpoint.base, "_remote", return_value=None) as remote:
            result = endpoint.endpoint_probe_reconcile(Path.cwd(), {"correlationId": self.correlation})
        self.assertEqual(result["state"], "stopped")
        self.assertEqual(result["outcome"], "reconciled")
        self.assertEqual(remote.call_count, 1)
        self.assertIs(remote.call_args.args[1], endpoint._REMOTE_STOP)
        status.assert_called_once()


if __name__ == "__main__":
    unittest.main()
