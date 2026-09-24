"""Pure adapter tests for compact live native environment observation."""
from __future__ import annotations

from pathlib import Path
import json
import subprocess
import sys
import unittest
from unittest import mock

from agent_tools import native_environment_observation as observation


class NativeEnvironmentObservationTest(unittest.TestCase):
    def request(self, **changes):
        result = {"hostAlias": "fixture", "timeoutSeconds": 12}
        result.update(changes)
        return result

    def android_available_result(self):
        """Produce a real public observer result from its bounded envelope."""
        proxy = {name: {"state": "null", "value": "null"} for name in observation.android_observation._PROXY_FIELDS}
        payload = {"baseline": {"uid": "2000", "sdk": "35", "kernelAvd": "api35", "bootAvd": "api35", "proxy": proxy},
                   "admitted": True,
                   "status": {"ok": True, "code": "OK", "final": True, "controllerId": "owner", "operationId": None},
                   "operations": {"ok": True, "code": "OK", "final": True, "controllerId": "owner", "operationId": None, "operationCount": 0}}
        return observation.android_observation._result(0, json.dumps(payload).encode())

    def test_compact_live_components_use_configured_profile_and_safe_evidence(self):
        host = mock.Mock(android_devices={"pixel": {"adb": "/tools/adb", "cli": "/tools/cli", "serial": "emulator-5554", "expectedAvd": "api35", "api": 35}})
        config = mock.Mock(hosts={"fixture": host})
        probe = mock.Mock(ok=True, status=observation.ssh_transport.ProbeStatus.OK)
        job = mock.Mock(status=mock.Mock(value="running"), reason="live_pid")
        with mock.patch.object(observation.ssh_transport, "probe", return_value=probe) as ssh, \
             mock.patch.object(observation.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(observation.android_observation, "observe", return_value=self.android_available_result()) as android, \
             mock.patch.object(observation.ssh_jobs, "observe", return_value=job) as jobs, \
             mock.patch.object(observation.native_artifact_registry, "verify_artifact", return_value={"verification": "verified"}) as artifact:
            result = observation.observe_environment(".", self.request(device="pixel", jobIdentity={"jobId": "job", "pid": 1, "startTicks": 2}, artifactId="sha256-" + "a" * 64))
        self.assertFalse(result["ready"]); self.assertTrue(result["requestedProbesReady"]); self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual("live-tool", result["source"]); self.assertEqual("available", result["components"]["android"]["status"])
        self.assertEqual("running", result["components"]["job"]["status"]); self.assertEqual("verified", result["components"]["artifact"]["status"])
        self.assertLessEqual(sum(value.call_args.kwargs["timeout_seconds"] + 1 for value in (ssh, android, jobs)), 12)
        artifact.assert_called_once()

    def test_failed_required_probe_is_unknown_and_never_ready(self):
        probe = mock.Mock(ok=False, status=observation.ssh_transport.ProbeStatus.TIMEOUT)
        with mock.patch.object(observation.ssh_transport, "probe", return_value=probe):
            result = observation.observe_environment(".", self.request())
        self.assertEqual(("UNKNOWN", False), (result["state"], result["ready"]))
        self.assertEqual("unknown", result["components"]["ssh"]["status"])
        self.assertNotIn("output", str(result))

    def test_missing_configured_device_is_unknown_without_starting_a_probe(self):
        config = mock.Mock(hosts={"fixture": mock.Mock(android_devices={})})
        with mock.patch.object(observation.ssh_transport, "probe", return_value=mock.Mock(ok=True, status=observation.ssh_transport.ProbeStatus.OK)), \
             mock.patch.object(observation.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(observation.android_observation, "observe") as android:
            result = observation.observe_environment(".", self.request(device="pixel"))
        self.assertEqual("unknown", result["components"]["android"]["status"])
        android.assert_not_called()

    def test_caller_vm_memory_facts_remain_supplied_not_observed(self):
        with mock.patch.object(observation.ssh_transport, "probe", return_value=mock.Mock(ok=True, status=observation.ssh_transport.ProbeStatus.OK)):
            result = observation.observe_environment(".", self.request(observations=[{"kind": "vm"}, {"kind": "memory"}]))
        self.assertFalse(result["ready"], "unverified caller kind labels must not establish environment readiness")
        supplied = result["components"]["supplied"]
        self.assertEqual(("supplied", False, "not-live"), (supplied["status"], supplied["observed"], supplied["freshness"]))

    def test_ssh_only_is_requested_probe_ready_not_overall_environment_ready(self):
        with mock.patch.object(observation.ssh_transport, "probe", return_value=mock.Mock(ok=True, status=observation.ssh_transport.ProbeStatus.OK)):
            result = observation.observe_environment(".", self.request())
        self.assertEqual(("requested-probes-ready", False, "UNKNOWN"),
                         (result["observationStatus"], result["ready"], result["state"]))

    def test_windows_is_explicitly_unsupported_without_adapter_calls(self):
        with mock.patch.object(observation.os, "name", "nt"), mock.patch.object(observation.ssh_transport, "probe") as probe:
            result = observation.observe_environment(Path("."), self.request())
        self.assertEqual("unsupported_platform", result["components"]["ssh"]["reason"])
        probe.assert_not_called()

    def test_unsafe_fields_are_rejected_before_adapters(self):
        with mock.patch.object(observation.ssh_transport, "probe") as probe:
            with self.assertRaisesRegex(observation.NativeEnvironmentObservationError, "unsupported"):
                observation.observe_environment(".", self.request(command="bad"))
        probe.assert_not_called()

    def test_standalone_import_uses_the_same_fallback_imports(self):
        source = Path(observation.__file__).parent
        result = subprocess.run([sys.executable, "-c", "import native_environment_observation"],
                                cwd=source.parent, env={"PYTHONPATH": str(source)},
                                capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
