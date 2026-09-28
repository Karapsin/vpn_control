import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import linux_owner_public_quit as quit_owner


CORRELATION = "12345678-1234-1234-1234-123456789abc"
CONTROLLER = "1780cc81-65a6-4284-a424-2178b94e2690"


class FakeDriver:
    def __init__(self, responses, on_call=None):
        self.responses = list(responses)
        self.on_call = on_call
        self.calls = []

    def _remote(self, config, host, program, args, **kwargs):
        self.calls.append((host, program, args, kwargs))
        if self.on_call:
            self.on_call(program)
        return self.responses.pop(0)


class LinuxOwnerPublicQuitTest(unittest.TestCase):
    def request(self):
        return {"host": "fedora2328", "environment": "fedora2328", "pid": 18367,
                "startTicks": 2078693, "controllerId": CONTROLLER,
                "approval": quit_owner.APPROVAL, "correlationId": CORRELATION}

    def guest(self, driver):
        config = mock.Mock(hosts={"fedora2328": mock.Mock(user="vpnfixture")})
        return mock.patch.object(quit_owner.ssh_transport, "load_config", return_value=config), \
            mock.patch.object(quit_owner, "_driver", return_value=driver)

    def test_rejects_wrong_guest_identity_or_unapproved_request_before_access(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for changed in ({"host": "other"}, {"pid": True}, {"pid": 18368},
                            {"startTicks": 0}, {"startTicks": 2078694},
                            {"approval": "not-approved"}, {"controllerId": "replacement"},
                            {"controllerId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                            {"command": "kill -9 18367"}):
                request = dict(self.request(), **changed)
                with self.subTest(changed=changed), self.assertRaises(quit_owner.LinuxOwnerPublicQuitError):
                    quit_owner.start(root, request)
            self.assertFalse((root / ".rag_index").exists())

    def test_runtime_or_owner_drift_blocks_before_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for preflight in ({"state": "blocked", "reason": "active-runtime"},
                              {"state": "unknown", "reason": "owner-generation-changed"},
                              {"state": "ready", "pid": 18367, "startTicks": 2078693,
                               "controllerId": "replacement"}):
                driver = FakeDriver([preflight])
                config, owner = self.guest(driver)
                with config, owner:
                    result = quit_owner.start(root, self.request())
                self.assertIn(result["state"], {"blocked", "unknown"})
                self.assertFalse(result["replayAllowed"])
                self.assertEqual(1, len(driver.calls))
                self.assertFalse((root / ".rag_index" / "linux-owner-public-quit").exists())

    def test_intent_precedes_effect_and_response_loss_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / ".rag_index" / "linux-owner-public-quit" / (CORRELATION + ".json")
            def observe(program):
                if program == quit_owner._SUBMIT:
                    self.assertEqual(self.request(), json.loads(path.read_text()))
            driver = FakeDriver([
                {"state": "ready", "pid": 18367, "startTicks": 2078693, "controllerId": CONTROLLER},
                None], observe)
            config, owner = self.guest(driver)
            with config, owner:
                result = quit_owner.start(root, self.request())
                again = quit_owner.start(root, self.request())
            self.assertEqual("unknown", result["state"])
            self.assertEqual("unknown", again["state"])
            self.assertEqual("existing-intent", again["reason"])
            self.assertFalse(again["replayAllowed"])
            self.assertEqual(2, len(driver.calls))
            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    def test_status_and_collect_require_exact_terminal_receipt_without_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            preflight = {"state": "ready", "pid": 18367, "startTicks": 2078693,
                         "controllerId": CONTROLLER}
            terminal = {"state": "terminal", "result": "passed", "correlationId": CORRELATION,
                        "pid": 18367, "startTicks": 2078693, "controllerId": CONTROLLER,
                        "exitCode": 0, "ownerGenerationGone": True}
            driver = FakeDriver([preflight, {"state": "submitted", "correlationId": CORRELATION},
                                 terminal, dict(terminal, controllerId="replacement")])
            config, owner = self.guest(driver)
            with config, owner:
                self.assertEqual("submitted", quit_owner.start(root, self.request())["state"])
                observed = quit_owner.status(root, {"correlationId": CORRELATION})
                self.assertEqual("terminal", observed["state"])
                self.assertTrue(observed["ownerGenerationGone"])
                invalid = quit_owner.collect(root, {"correlationId": CORRELATION})
            self.assertEqual("unknown", invalid["state"])
            self.assertEqual(4, len(driver.calls))
            self.assertTrue(all(call[1] != quit_owner._SUBMIT for call in driver.calls[2:]))

    def test_status_rejects_unsafe_journal_and_never_creates_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = quit_owner.status(root, {"correlationId": CORRELATION})
            self.assertEqual("unknown", missing["state"])
            self.assertFalse((root / ".rag_index").exists())
            driver = FakeDriver([{"state": "ready", "pid": 18367, "startTicks": 2078693,
                                  "controllerId": CONTROLLER}, None])
            config, owner = self.guest(driver)
            with config, owner:
                quit_owner.start(root, self.request())
            path = root / ".rag_index" / "linux-owner-public-quit" / (CORRELATION + ".json")
            path.chmod(0o644)
            with self.assertRaisesRegex(quit_owner.LinuxOwnerPublicQuitError, "unsafe"):
                quit_owner.status(root, {"correlationId": CORRELATION})

    def test_guest_programs_compile_and_use_only_public_quit_for_effect(self):
        for name in ("_PREFLIGHT", "_SUBMIT", "_STATUS"):
            with self.subTest(name=name):
                compile(getattr(quit_owner, name), name, "exec")
        self.assertIn("'--controller-id',intent['controllerId'],'quit'", quit_owner._SUBMIT)
        self.assertNotIn("os.kill", quit_owner._SUBMIT)
        self.assertNotIn("systemctl", quit_owner._SUBMIT)
        self.assertNotIn("rpm -", quit_owner._SUBMIT)

    def test_unreadable_proc_identity_cannot_prove_owner_exit(self):
        namespace = {}
        exec(quit_owner._COMMON, namespace)
        with mock.patch("builtins.open", side_effect=PermissionError("unreadable")):
            self.assertIsNone(namespace["same_owner"](self.request()))

    def test_zombie_with_same_generation_is_not_reported_gone(self):
        namespace = {}
        exec(quit_owner._COMMON, namespace)
        namespace["generation"] = lambda pid: ("Z", 2078693)
        self.assertTrue(namespace["same_owner"](self.request()))

    def test_guest_rejects_a_different_owner_before_public_commands(self):
        namespace = {}
        exec(quit_owner._COMMON, namespace)
        altered = dict(self.request(), pid=18368)
        with mock.patch("subprocess.run") as public_command:
            workspace, reason = namespace["public_status"](altered)
        self.assertIsNone(workspace)
        self.assertEqual("approval-owner-mismatch", reason)
        public_command.assert_not_called()

    def test_guest_rechecks_runtime_after_durable_intent_before_public_quit(self):
        with tempfile.TemporaryDirectory() as temporary:
            namespace = {}
            exec(quit_owner._COMMON, namespace)
            namespace["directory"] = lambda create: temporary
            namespace["public_status"] = mock.Mock(side_effect=[
                ("/home/vpnfixture/state", None), (None, "active-runtime")])
            observations = []
            namespace["output"] = lambda *args, **kwargs: observations.append((args, kwargs))
            with mock.patch.object(sys, "argv", ["guest", json.dumps(self.request())]), \
                 mock.patch("subprocess.run") as public_command:
                with self.assertRaises(SystemExit):
                    exec(quit_owner._SUBMIT[len(quit_owner._COMMON):], namespace)
            public_command.assert_not_called()
            self.assertEqual("blocked", observations[-1][0][0])
            job = Path(temporary) / CORRELATION
            self.assertTrue((job / "intent.json").is_file())


if __name__ == "__main__":
    unittest.main()
