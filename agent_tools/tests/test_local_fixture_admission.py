import subprocess
import time
import unittest
from unittest import mock

from agent_tools import local_fixture_admission as admission


class LocalAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.now = [0.0]
        self.epoch = time.time_ns() - 10_000_000_000
        self.pageouts = [12, 12]; self.swap = ["120M", "120M"]; self.sample = 0
        patches = [mock.patch.object(admission.platform, "system", return_value="Darwin"),
                   mock.patch.object(admission.visual, "_read_reservations", return_value={}),
                   mock.patch.object(admission.visual, "_tart_running_allocations", return_value=[]),
                   mock.patch.object(admission.visual, "_resource_policy", return_value=({"build_headroom_mib": 8192}, "controlled"))]
        for patch in patches:
            patch.start(); self.addCleanup(patch.stop)

    def run_probe(self, argv, **options):
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        replies = {("vm_stat",): f"Pageouts: {self.pageouts[self.sample]}.\n",
                   ("memory_pressure", "-Q"): "System-wide memory free percentage: 70%\n",
                   ("sysctl", "-n", "kern.memorystatus_vm_pressure_level"): "1\n",
                   ("sysctl", "-n", "vm.swapusage"): f"total = 2048M used = {self.swap[self.sample]} free = 1000M\n",
                   ("sysctl", "-n", "hw.memsize"): str(32 * 1024**3)}
        return subprocess.CompletedProcess(argv, 0, replies[tuple(argv)].encode())

    def measure(self):
        def sleep(seconds):
            self.now[0] += seconds; self.sample = 1
        return admission.memory_plan(4096, 10, runner=self.run_probe, clock=lambda: self.now[0], sleep=sleep,
                                      epoch_ns=lambda: self.epoch + int(self.now[0] * 1_000_000_000))

    def test_actual_two_sample_shape_retains_historical_swap_without_pageouts(self):
        value = self.measure()
        self.assertEqual(len(value["samples"]), 2)
        self.assertEqual(value["measurement"]["swapUsedBytes"], 120 * 1024**2)
        self.assertGreater(value["samples"][1]["observedAtUnixMs"], value["samples"][0]["observedAtUnixMs"])

    def test_paging_or_swap_growth_blocks_before_any_reservation(self):
        self.pageouts = [12, 13]
        with self.assertRaisesRegex(admission.vm_workflow.VmWorkflowError, "pageout"):
            self.measure()
        self.now[0] = 0; self.sample = 0; self.pageouts = [12, 12]; self.swap = ["120M", "121M"]
        with self.assertRaisesRegex(admission.vm_workflow.VmWorkflowError, "swap growth"):
            self.measure()

    def test_short_caller_deadline_does_not_expand_for_sample_wait(self):
        with self.assertRaisesRegex(admission.LocalAdmissionError, "deadline"):
            admission.memory_plan(4096, 1, runner=self.run_probe, clock=lambda: 0)


if __name__ == "__main__":
    unittest.main()
