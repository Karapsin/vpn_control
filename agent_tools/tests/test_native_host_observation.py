from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_memory_parser_accepts_android_emulator_memory_mebibytes(self):
        namespace: dict[str, object] = {"__name__": "not_main"}
        exec(observation._REMOTE_PROGRAM.split('if not sys.platform', 1)[0], namespace)
        self.assertEqual(2048 * 1024 ** 2,
                         namespace["parse_memory"]([b"qemu-system-x86_64-headless", b"-memory", b"2048"]))

    def test_memory_parser_rejects_ambiguous_or_invalid_android_memory(self):
        namespace: dict[str, object] = {"__name__": "not_main"}
        exec(observation._REMOTE_PROGRAM.split('if not sys.platform', 1)[0], namespace)
        parse_memory = namespace["parse_memory"]
        for argv in ([b"qemu-system-x86_64-headless", b"-memory", b"2048", b"-memory", b"4096"],
                     [b"qemu-system-x86_64", b"-m", b"2048", b"-m", b"4096"],
                     [b"qemu-system-x86_64-headless", b"-m", b"2048", b"-memory", b"2048"],
                     [b"qemu-system-x86_64-headless", b"-memory", b"2048M"],
                     [b"qemu-system-x86_64-headless", b"-memory"],
                     [b"qemu-system-x86_64-headless", b"-memory=2048"]):
            with self.subTest(argv=argv):
                self.assertIsNone(parse_memory(argv))

    @unittest.skipUnless(sys.platform.startswith("linux"), "remote /proc fixture is Linux-only")
    def test_fixed_remote_program_collects_a_real_linux_proc_fixture(self):
        completed = subprocess.run([sys.executable, "-c", observation._REMOTE_ARGUMENT], capture_output=True,
                                   text=True, check=False, timeout=5)
        self.assertEqual(0, completed.returncode)
        payload = json.loads(completed.stdout)
        self.assertEqual("observed", payload["state"])
        self.assertEqual(2, len(payload["samples"]))

    def _inert_remote_census(self, processes, *, change_ticks=False, change_exe_ticks=False, change_kernel_ticks=False, change_kernel_flags=False,
                             change_zombie_ticks=False, change_zombie_state=False):
        """Run the emitted observer against only owned files, never host /proc or SSH."""
        def stat_text(pid, ticks, flags=0, state="S"):
            fields = [state] + ["0"] * 18 + [str(ticks), "0"]
            fields[6] = str(flags)
            return str(pid) + " (fixture) " + " ".join(fields) + "\n"
        with tempfile.TemporaryDirectory(prefix="vpn-host-census-") as directory:
            proc = Path(directory) / "proc"
            (proc / "pressure").mkdir(parents=True)
            (proc / "meminfo").write_text("MemTotal: 33554432 kB\nMemAvailable: 20971520 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n", encoding="ascii")
            (proc / "vmstat").write_text("pswpin 0\npswpout 0\noom_kill 0\n", encoding="ascii")
            (proc / "pressure/memory").write_text("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n", encoding="ascii")
            for row in processes:
                child = proc / str(row["pid"])
                child.mkdir()
                (child / "stat").write_text(stat_text(row["pid"], row["ticks"], row.get("flags", 0), row.get("state", "S")), encoding="ascii")
                (child / "comm").write_text(row["comm"] + "\n", encoding="ascii")
                (child / "cmdline").write_bytes(row["cmdline"])
                if row.get("missing_exe"):
                    pass  # An actual missing owned link makes readlink raise ENOENT.
                elif row.get("uninspectable"):
                    (child / "exe").write_text("not a proc executable link", encoding="ascii")
                else:
                    (child / "exe").symlink_to("/inert/" + row["exe"])
            # Project only the fixed proc root and platform gate. The observer's
            # identity, allocation, framing and generation verdicts remain actual.
            source = observation._REMOTE_PROGRAM.replace("/proc", proc.as_posix())
            prefix = "import sys\nsys.platform='linux'\n"
            if change_ticks:
                first = processes[0]
                changed = stat_text(first["pid"], first["ticks"] + 1)
                target = str(proc / str(first["pid"]) / "cmdline")
                stat_path = str(proc / str(first["pid"]) / "stat")
                # Real owned stat bytes change at the cmdline-read boundary.
                prefix += "import builtins\n_fixture_open=builtins.open\n"
                prefix += "class _FixtureCmdline:\n def __init__(self,f): self.f=f\n def __enter__(self): self.f.__enter__();return self\n def __exit__(self,*a): return self.f.__exit__(*a)\n def read(self,*a):\n  data=self.f.read(*a)\n  with _fixture_open(" + repr(stat_path) + ", 'w', encoding='ascii') as out: out.write(" + repr(changed) + ")\n  return data\n"
                prefix += "def _fixture_boundary(path,*a,**k):\n f=_fixture_open(path,*a,**k)\n return _FixtureCmdline(f) if str(path)==" + repr(target) + " else f\nbuiltins.open=_fixture_boundary\n"
            if change_exe_ticks or change_kernel_ticks or change_kernel_flags or change_zombie_ticks or change_zombie_state:
                first = processes[0]
                changed = stat_text(first["pid"], first["ticks"] if change_kernel_flags else first["ticks"] + 1,
                                    0 if change_kernel_flags else first.get("flags", 0), first.get("state", "S"))
                if change_zombie_state:
                    changed = stat_text(first["pid"], first["ticks"], first.get("flags", 0), "S")
                stat_path = str(proc / str(first["pid"]) / "stat")
                prefix += "import builtins,os\n_fixture_open=builtins.open\n"
                if change_exe_ticks:
                    exe_path = str(proc / str(first["pid"]) / "exe")
                    prefix += "_fixture_readlink=os.readlink\ndef _fixture_exe(path,*a,**k):\n if str(path)==" + repr(exe_path) + ":\n  with _fixture_open(" + repr(stat_path) + ", 'w', encoding='ascii') as out: out.write(" + repr(changed) + ")\n return _fixture_readlink(path,*a,**k)\nos.readlink=_fixture_exe\n"
                if change_kernel_ticks or change_kernel_flags or change_zombie_ticks or change_zombie_state:
                    # Change actual owned bytes after the opening proof read:
                    # a stale marker cannot authorize the later process.
                    proof_read = 3 if change_zombie_ticks or change_zombie_state else 2
                    prefix += "_fixture_stat_reads=0\nclass _FixtureStat:\n def __init__(self,f): self.f=f\n def read(self,*a):\n  global _fixture_stat_reads\n  data=self.f.read(*a);_fixture_stat_reads+=1\n  if _fixture_stat_reads==" + str(proof_read) + ":\n   with _fixture_open(" + repr(stat_path) + ", 'w', encoding='ascii') as out: out.write(" + repr(changed) + ")\n  return data\n def __del__(self): self.f.close()\n"
                    prefix += "def _fixture_stat_boundary(path,*a,**k):\n f=_fixture_open(path,*a,**k)\n return _FixtureStat(f) if str(path)==" + repr(stat_path) + " else f\nbuiltins.open=_fixture_stat_boundary\n"
            completed = subprocess.run([sys.executable, "-c", prefix + source], capture_output=True,
                                       text=True, check=False, timeout=5)
            self.assertEqual(0, completed.returncode, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual("observed", payload["state"])
            return payload

    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_counts_qemu_executable_after_comm_rename(self):
        rows = [{"pid": 3726886, "ticks": 21863571, "comm": "7", "exe": "qemu-system-x86_64", "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b""))},
                {"pid": 3847348, "ticks": 22216504, "comm": "7", "exe": "qemu-system-x86_64", "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b""))}]
        payload = self._inert_remote_census(rows)
        self.assertEqual([(row["pid"], row["ticks"]) for row in rows],
                         [(row["pid"], row["startTicks"]) for row in payload["vms"]])
        result = observation._measurement(payload, 100, {"pid": rows[0]["pid"], "startTicks": rows[0]["ticks"]}, 5)
        self.assertEqual("OBSERVED", result["state"])
        self.assertEqual(8 * 1024 ** 3, result["measurement"]["runningConfiguredMemoryBytes"])
        self.assertEqual("matched", result["vmIdentity"]["state"])

    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_keeps_unknown_for_uninspectable_live_executable(self):
        row = {"pid": 42, "ticks": 99, "comm": "7", "exe": "qemu-system-x86_64", "uninspectable": True,
               "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b""))}
        payload = self._inert_remote_census([row])
        self.assertFalse(payload["inventoryComplete"])
        result = observation._measurement(payload, 100, None, 5)
        self.assertEqual(("UNKNOWN", None), (result["state"], result["measurement"]))

    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_preserves_bounds_generation_and_positive_non_qemu_exclusion(self):
        cases = [("ordinary-exe", {"pid": 42, "ticks": 99, "comm": "7", "exe": "python3", "cmdline": b"python3\0-c\0qemu-system-x86_64\0"}, False, "OBSERVED"),
                 ("oversized-cmdline", {"pid": 42, "ticks": 99, "comm": "qemu-system-x86_64", "exe": "qemu-system-x86_64", "cmdline": b"x" * 16385}, False, "UNKNOWN"),
                 ("ambiguous-memory", {"pid": 42, "ticks": 99, "comm": "qemu-system-x86_64", "exe": "qemu-system-x86_64", "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b"-m", b"2048", b""))}, False, "UNKNOWN"),
                 ("generation-change", {"pid": 42, "ticks": 99, "comm": "qemu-system-x86_64", "exe": "qemu-system-x86_64", "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b""))}, True, "UNKNOWN")]
        for label, row, changed, expected in cases:
            with self.subTest(case=label):
                payload = self._inert_remote_census([row], change_ticks=changed)
                result = observation._measurement(payload, 100, {"pid": 42, "startTicks": 99}, 5)
                self.assertEqual(expected, result["state"])
                if expected == "OBSERVED":
                    self.assertEqual([], payload["vms"])
                    self.assertEqual(0, result["measurement"]["runningConfiguredMemoryBytes"])
                else:
                    self.assertIsNone(result["measurement"])
                if changed:
                    self.assertEqual([], payload["vms"])
                    self.assertEqual("unknown", result["vmIdentity"]["state"])

    def test_malformed_or_failed_output_is_unknown_not_zero(self):
        with mock.patch.object(observation.ssh_transport, "load_config", return_value=self.config()), \
             mock.patch.object(observation.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(observation, "_run", side_effect=RuntimeError("timeout")):
            result = observation.observe_host(Path("."), "fixture", 8)
        self.assertEqual(("UNKNOWN", "observer_failed", None), (result["state"], result["reason"], result["measurement"]))


    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_ignores_same_generation_kernel_threads(self):
        kernel = {"pid": 2, "ticks": 14, "comm": "kthreadd", "flags": 0x00200000,
                  "missing_exe": True, "exe": "", "cmdline": b""}
        qemu = {"pid": 3726886, "ticks": 21863571, "comm": "7", "exe": "qemu-system-x86_64",
                "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b""))}
        payload = self._inert_remote_census([kernel, qemu])
        self.assertTrue(payload["inventoryComplete"])
        self.assertEqual([qemu["pid"]], [row["pid"] for row in payload["vms"]])
        result = observation._measurement(payload, 100, {"pid": qemu["pid"], "startTicks": qemu["ticks"]}, 5)
        self.assertEqual("OBSERVED", result["state"])
        self.assertEqual(4 * 1024 ** 3, result["measurement"]["runningConfiguredMemoryBytes"])
        self.assertEqual("matched", result["vmIdentity"]["state"])

    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_keeps_unknown_when_kernel_marker_is_unbound_or_absent(self):
        cases = [("uninspectable-user", 4194560, "S", False, False, False),
                 ("malformed-flags", "invalid", "S", False, False, False),
                 ("negative-flags", -1, "S", False, False, False),
                 ("other-terminal-state-retains-uncertainty", 0, "X", False, False, False),
                 ("reused-before-flags", 0x00200000, "S", True, False, False),
                 ("reused-after-flags", 0x00200000, "S", False, True, False),
                 ("kernel-marker-cleared-same-generation", 0x00200000, "S", False, False, True)]
        for label, flags, state, change_exe, change_kernel, clear_marker in cases:
            with self.subTest(case=label):
                row = {"pid": 42, "ticks": 99, "comm": "kthreadd", "flags": flags, "state": state,
                       "missing_exe": True, "exe": "", "cmdline": b""}
                payload = self._inert_remote_census([row], change_exe_ticks=change_exe, change_kernel_ticks=change_kernel, change_kernel_flags=clear_marker)
                self.assertFalse(payload["inventoryComplete"])
                result = observation._measurement(payload, 100, None, 5)
                self.assertEqual(("UNKNOWN", None), (result["state"], result["measurement"]))


    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_ignores_same_generation_terminal_zombies(self):
        zombie = {"pid": 42, "ticks": 99, "comm": "7", "state": "Z", "flags": 0,
                  "missing_exe": True, "exe": "", "cmdline": b""}
        kernel = {"pid": 2, "ticks": 14, "comm": "kthreadd", "flags": 0x00200000,
                  "missing_exe": True, "exe": "", "cmdline": b""}
        qemu = {"pid": 3726886, "ticks": 21863571, "comm": "7", "exe": "qemu-system-x86_64",
                "cmdline": b"\0".join((b"qemu-system-x86_64", b"-m", b"4096", b""))}
        payload = self._inert_remote_census([zombie, kernel, qemu])
        self.assertTrue(payload["inventoryComplete"])
        self.assertEqual([qemu["pid"]], [row["pid"] for row in payload["vms"]])
        result = observation._measurement(payload, 100, {"pid": qemu["pid"], "startTicks": qemu["ticks"]}, 5)
        self.assertEqual("OBSERVED", result["state"])
        self.assertEqual(4 * 1024 ** 3, result["measurement"]["runningConfiguredMemoryBytes"])
        self.assertEqual("matched", result["vmIdentity"]["state"])

    @unittest.skipUnless(os.name == "posix", "owned proc executable symlink controls require POSIX")
    def test_emitted_census_keeps_unknown_when_zombie_marker_or_generation_changes(self):
        for label, change_ticks, change_state in [("zombie-pid-reuse", True, False), ("zombie-becomes-live", False, True)]:
            with self.subTest(case=label):
                row = {"pid": 42, "ticks": 99, "comm": "7", "state": "Z", "flags": 0,
                       "missing_exe": True, "exe": "", "cmdline": b""}
                payload = self._inert_remote_census([row], change_zombie_ticks=change_ticks, change_zombie_state=change_state)
                self.assertFalse(payload["inventoryComplete"])
                result = observation._measurement(payload, 100, None, 5)
                self.assertEqual(("UNKNOWN", None), (result["state"], result["measurement"]))


if __name__ == "__main__":
    unittest.main()
