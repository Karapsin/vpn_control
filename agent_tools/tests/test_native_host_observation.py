from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

from agent_tools import native_host_observation as observation


class NativeHostObservationTest(unittest.TestCase):
    def payload(self, *, memory=8 * 1024 ** 3):
        return {"state": "observed", "physicalMemoryBytes": 32 * 1024 ** 3, "swapUsedBytes": 0,
                "samples": [{"observedAtUnixMs": 100, "availableMemoryBytes": 20 * 1024 ** 3, "psi": "normal", "psiSomeAvg10": 0.2, "psiFullAvg10": 0.0, "vmstat": {"pswpin": 1, "pswpout": 2, "oomKill": 0}},
                            {"observedAtUnixMs": 101, "availableMemoryBytes": 19 * 1024 ** 3, "psi": "normal", "psiSomeAvg10": 0.2, "psiFullAvg10": 0.0, "vmstat": {"pswpin": 1, "pswpout": 2, "oomKill": 0}}],
                "vms": [{"pid": 42, "startTicks": 99, "qemuExecutable": "qemu-system-x86_64", "configuredMemoryBytes": memory}], "inventoryComplete": True}

    def config(self):
        host = mock.Mock(transport="direct", gateway=None, password=None)
        return mock.Mock(hosts={"fixture": host})

    def test_complete_measurement_has_vm_workflow_shape_and_exact_identity(self):
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
             mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(observation, "_run", return_value=json.dumps(self.payload()).encode()):
            result = observation.observe_host(".", "fixture", 8, {"pid": 42, "startTicks": 99})
        self.assertEqual("OBSERVED", result["state"])
        self.assertEqual(8 * 1024 ** 3, result["measurement"]["runningConfiguredMemoryBytes"])
        self.assertEqual("matched", result["vmIdentity"]["state"])
        self.assertNotIn("cmdline", str(result))

    def test_unparsed_live_qemu_memory_never_becomes_zero_or_a_measurement(self):
        payload = self.payload(memory=None)
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
             mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(observation, "_run", return_value=json.dumps(payload).encode()):
            result = observation.observe_host(".", "fixture", 8)
        self.assertEqual(("UNKNOWN", "unknown_qemu_memory", None), (result["state"], result["reason"], result["measurement"]))
        self.assertEqual(19 * 1024 ** 3, result["memory"]["availableMemoryBytes"])

    def test_incomplete_inventory_or_known_qemu_read_failure_cannot_admit(self):
        for payload in ({**self.payload(), "inventoryComplete": False},
                        {**self.payload(), "vms": [{"pid": 42, "startTicks": 99, "qemuExecutable": None, "configuredMemoryBytes": None}]}):
            with self.subTest(payload=payload), \
                 mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
                 mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
                 mock.patch.object(observation, "_run", return_value=json.dumps(payload).encode()):
                result = observation.observe_host(".", "fixture", 8)
            self.assertEqual(("UNKNOWN", "unknown", None),
                             (result["state"], result["measurementAvailability"], result["measurement"]))

    def test_missing_required_vmstat_counter_cannot_be_fabricated_as_zero(self):
        payload = self.payload()
        del payload["samples"][1]["vmstat"]["oomKill"]
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
             mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(observation, "_run", return_value=json.dumps(payload).encode()):
            result = observation.observe_host(".", "fixture", 8)
        self.assertEqual(("UNKNOWN", "malformed_probe_output", None),
                         (result["state"], result["reason"], result["measurement"]))

    def test_remote_non_linux_and_transport_failures_are_categorical_unknown(self):
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
             mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(observation, "_run", return_value=b'{"state":"unsupported_linux"}'):
            result = observation.observe_host(".", "fixture", 8)
        self.assertEqual("unsupported_linux", result["reason"])

    def test_fixed_remote_program_reads_proc_and_never_accepts_caller_command(self):
        self.assertIn('/proc/meminfo', observation._REMOTE_PROGRAM)
        self.assertIn('/proc/vmstat', observation._REMOTE_PROGRAM)
        self.assertIn('qemu-system-', observation._REMOTE_PROGRAM)
        self.assertIn('inventory_complete=False', observation._REMOTE_PROGRAM)
        self.assertNotIn('shell=True', observation._REMOTE_PROGRAM)
        with self.assertRaisesRegex(observation.NativeHostObservationError, "only pid"):
            observation.observe_host(".", "fixture", 8, {"pid": 1, "startTicks": 2, "command": "x"})

    def test_memory_parser_does_not_mistake_machine_for_compact_m(self):
        namespace: dict[str, object] = {"__name__": "not_main"}
        exec(observation._REMOTE_PROGRAM.split('if not sys.platform', 1)[0], namespace)
        self.assertEqual(6144 * 1024 ** 2, namespace["parse_memory"]([b"qemu-system-x86_64", b"-m", b"6144", b"-machine", b"q35"]))

    @unittest.skipUnless(sys.platform.startswith("linux"), "remote /proc fixture is Linux-only")
    def test_fixed_remote_program_collects_a_real_linux_proc_fixture(self):
        completed = subprocess.run([sys.executable, "-c", observation._REMOTE_ARGUMENT], capture_output=True,
                                   text=True, check=False, timeout=5)
        self.assertEqual(0, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertEqual("observed", payload["state"])
        self.assertEqual(2, len(payload["samples"]))

    def test_malformed_or_failed_output_is_unknown_not_zero(self):
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
             mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(observation, "_run", side_effect=RuntimeError("timeout")):
            result = observation.observe_host(Path("."), "fixture", 8)
        self.assertEqual(("UNKNOWN", "observer_failed", None), (result["state"], result["reason"], result["measurement"]))


if __name__ == "__main__":
    unittest.main()
