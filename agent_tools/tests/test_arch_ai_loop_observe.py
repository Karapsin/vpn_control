"""Causal regressions for the fixed, redacting Arch ai_loop observer."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader
    spec.loader.exec_module(module)
    return module


transport = load("ssh_transport")
observation = load("arch_ai_loop_observe")


class ArchAiLoopObservationTest(unittest.TestCase):
    class _FakeStdout:
        def close(self):
            self.closed = True

        def fileno(self):
            return 7

    class _FakeProcess:
        def __init__(self):
            self.stdout = ArchAiLoopObservationTest._FakeStdout()
            self.killed = False
            self.waited = False

        def poll(self):
            return None

        def kill(self):
            self.killed = True

        def wait(self):
            self.waited = True

    def ssh_config(self, root):
        host = transport.SshHost("archlinux", "arch.example", 22, "tester", Path("/tmp/key"), Path("/tmp/known"))
        return transport.SshConfig(root=Path(root), hosts={"archlinux": host})

    def payload(self, **changes):
        value = {
            "schemaVersion": 1,
            "installation": {"package": "installed", "executable": "present", "version": "1.2.3"},
            "activity": {"userService": "inactive", "systemService": "inactive", "process": "not_running"},
            "safeProjection": {"state": "available", "provider": "openai", "model": "gpt-5.6-terra", "budget": {"maxInputTokens": 1000, "maxOutputTokens": 500, "maxIterations": 1, "maxConcurrency": 1, "timeoutSeconds": 900}, "metrics": {"window": "last_7d", "completedRuns": 2, "failedRuns": 0, "inputTokens": 100, "outputTokens": 200}},
        }
        value.update(changes)
        return json.dumps(value).encode()

    def test_fixed_arch_route_and_probe_command_have_no_caller_paths_or_commands(self):
        with mock.patch.object(observation.ssh_transport, "load_config", side_effect=self.ssh_config), mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh", "fixed"]) as build, mock.patch.object(observation, "_run_probe", return_value=(0, self.payload())):
            result = observation.observe("/workspace", timeout_seconds=12)
        self.assertTrue(result["available"])
        config, host, timeout = build.call_args.args[:3]
        self.assertEqual("archlinux", host)
        self.assertEqual(12, timeout)
        command = build.call_args.kwargs["command"]
        self.assertEqual(("/usr/bin/python3", "-c"), command[:2])
        self.assertEqual(3, len(command))
        self.assertNotIn("/workspace", command[2])
        self.assertIn(observation.SAFE_PROJECTION_PATH, command[2])

    def test_redacting_remote_probe_never_reads_normal_config_or_emits_secret_terms(self):
        source = observation._remote_probe()
        self.assertIn("observer-v1.json", source)
        self.assertNotIn(".config/ai_loop/config", source)
        self.assertIn("SECRET", source)
        self.assertIn("AI_LOOP_OFFLINE", source)
        self.assertNotIn("prompt", source.lower())
        self.assertNotIn("authorization", source.lower())

    def test_fixed_probe_never_executes_ai_loop_including_for_its_version(self):
        source = observation._remote_probe()
        self.assertNotIn('executable, "--version"', source)
        self.assertNotIn('"ai_loop", "--version"', source)
        self.assertNotIn('"ai-loop", "--version"', source)
        self.assertIn('"/usr/bin/pacman", "-Q", name', source)

    def test_unknown_projection_schema_is_rejected_without_leaking_fields(self):
        unsafe = {"state": "available", "provider": "openai", "model": "gpt-5.6-terra", "budget": {}, "metrics": {}, "apiKey": "secret"}
        payload = json.loads(self.payload())
        payload["safeProjection"] = unsafe
        with mock.patch.object(observation.ssh_transport, "load_config", side_effect=self.ssh_config), mock.patch.object(observation, "_run_probe", return_value=(0, json.dumps(payload).encode())):
            result = observation.observe("/workspace")
        self.assertEqual((False, "unknown", "malformed_observation"), (result["available"], result["outcome"], result["reason"]))
        self.assertNotIn("secret", json.dumps(result))

    def test_secret_like_model_or_version_in_remote_output_is_rejected_without_leakage(self):
        payload = json.loads(self.payload())
        payload["installation"]["version"] = "1.2.3-sk-private"
        payload["safeProjection"]["model"] = "sk-private"
        with mock.patch.object(observation.ssh_transport, "load_config", side_effect=self.ssh_config), mock.patch.object(observation, "_run_probe", return_value=(0, json.dumps(payload).encode())):
            result = observation.observe("/workspace")
        self.assertEqual((False, "unknown", "malformed_observation"), (result["available"], result["outcome"], result["reason"]))
        self.assertNotIn("private", json.dumps(result))

    def test_malformed_output_and_transport_failure_remain_unknown(self):
        with mock.patch.object(observation.ssh_transport, "load_config", side_effect=self.ssh_config), mock.patch.object(observation, "_run_probe", return_value=(0, b"not json")):
            malformed = observation.observe("/workspace")
        with mock.patch.object(observation.ssh_transport, "load_config", side_effect=self.ssh_config), mock.patch.object(observation, "_run_probe", return_value=(1, self.payload())):
            failed = observation.observe("/workspace")
        self.assertEqual("malformed_observation", malformed["reason"])
        self.assertEqual("transport_failed", failed["reason"])

    def test_duplicate_json_keys_are_rejected_before_any_field_is_returned(self):
        duplicated = self.payload().decode().replace('"schemaVersion": 1,', '"schemaVersion": 1, "schemaVersion": 1,', 1).encode()
        with mock.patch.object(observation.ssh_transport, "load_config", side_effect=self.ssh_config), mock.patch.object(observation, "_run_probe", return_value=(0, duplicated)):
            result = observation.observe("/workspace")
        self.assertEqual((False, "unknown", "malformed_observation"), (result["available"], result["outcome"], result["reason"]))
        self.assertIsNone(result["installation"])
        self.assertIn("object_pairs_hook=reject_duplicate_keys", observation._remote_probe())

    def test_timeout_and_oversized_probe_output_kill_and_close_the_local_child(self):
        timed_out = self._FakeProcess()
        with mock.patch.object(observation.subprocess, "Popen", return_value=timed_out), mock.patch.object(observation.time, "monotonic", side_effect=(0, 99)):
            with self.assertRaises(TimeoutError):
                observation._run_probe(["ssh"], 1)
        self.assertTrue(timed_out.killed)
        self.assertTrue(timed_out.waited)
        self.assertTrue(timed_out.stdout.closed)

        oversized = self._FakeProcess()
        with mock.patch.object(observation, "MAX_OUTPUT_BYTES", 1), mock.patch.object(observation.subprocess, "Popen", return_value=oversized), mock.patch.object(observation.select, "select", return_value=([oversized.stdout], [], [])), mock.patch.object(observation.os, "read", return_value=b"xx"):
            with self.assertRaisesRegex(RuntimeError, "oversized_output"):
                observation._run_probe(["ssh"], 1)
        self.assertTrue(oversized.killed)
        self.assertTrue(oversized.waited)
        self.assertTrue(oversized.stdout.closed)

    def test_invalid_timeout_rejects_before_private_inventory_access(self):
        with mock.patch.object(observation.ssh_transport, "load_config") as config:
            with self.assertRaisesRegex(observation.ArchAiLoopObservationError, "timeout"):
                observation.observe("/workspace", timeout_seconds=0)
        config.assert_not_called()

    def test_password_authenticated_route_is_rejected_before_remote_probe(self):
        host = transport.SshHost("archlinux", "arch.example", 22, "tester", Path("/tmp/key"), Path("/tmp/known"), password="private")
        config = transport.SshConfig(root=Path("/workspace"), hosts={"archlinux": host})
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=config), mock.patch.object(observation, "_run_probe") as remote:
            with self.assertRaisesRegex(observation.ArchAiLoopObservationError, "key or agent"):
                observation.observe("/workspace")
        remote.assert_not_called()


if __name__ == "__main__":
    unittest.main()
