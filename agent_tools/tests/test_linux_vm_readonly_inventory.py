"""Causal admission tests for the fixed, read-only Ubuntu/Arch VM inventory."""
from __future__ import annotations

import json
import unittest
from io import StringIO
from unittest import mock

from agent_tools import linux_vm_readonly_inventory as inventory


class LinuxVmReadonlyInventoryTest(unittest.TestCase):
    def payload(self, **changes):
        guests = {
            name: {"state": "stopped", "treeSafe": True, "diskSafe": True,
                   "diskHeldBy": [], "portListeners": 0, "qmpPresent": False,
                   "matchingQemu": [], "guestProbe": "not-running", "guestFacts": None,
                   "socketInventoryComplete": True, "generationStable": True,
                   "portOwnerPids": [], "qmpOwnerPids": []}
            for name in ("ubuntu2307", "arch2317")
        }
        result = {"schemaVersion": 1, "host": "archlinux", "diskAvailableBytes": 30 << 30,
                  "processInventoryComplete": True, "portsComplete": True,
                  "guests": guests, "observedAtUnixMs": 123}
        result.update(changes)
        return result

    def test_clean_stopped_guests_are_observed_without_admitting_a_start(self):
        result = inventory.classify(self.payload())
        self.assertTrue(result["inventoryComplete"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual("stopped", result["guests"]["ubuntu2307"]["state"])

    def test_missing_or_ambiguous_identity_never_becomes_stopped(self):
        for defect in ({"processInventoryComplete": False}, {"portsComplete": False},
                       {"diskAvailableBytes": 1 << 30}):
            with self.subTest(defect=defect):
                result = inventory.classify(self.payload(**defect))
                self.assertFalse(result["inventoryComplete"])
                self.assertFalse(result["nativeActionAllowed"])
        for change in ({"treeSafe": False}, {"diskSafe": False}, {"diskHeldBy": [3]},
                       {"portListeners": 1}, {"qmpPresent": True},
                       {"matchingQemu": [{"pid": 3, "startTicks": 4}]}):
            guests = self.payload()["guests"]
            guests["ubuntu2307"].update(change)
            with self.subTest(change=change):
                self.assertFalse(inventory.classify(self.payload(guests=guests))["inventoryComplete"])

    def test_active_guest_requires_exact_generation_and_guest_job_observation(self):
        guests = self.payload()["guests"]
        guests["arch2317"].update({"state": "running", "matchingQemu": [{"pid": 9, "startTicks": 10}],
                                   "diskHeldBy": [9], "portListeners": 1, "qmpPresent": True,
                                   "portClaimPids": [9], "qmpClaimPids": [9], "qmpSafe": True,
                                   "portOwnerPids": [9], "qmpOwnerPids": [9],
                                   "guestProbe": "unknown"})
        self.assertFalse(inventory.classify(self.payload(guests=guests))["inventoryComplete"])
        guests["arch2317"]["guestProbe"] = "observed-off-no-active-jobs"
        guests["arch2317"]["guestFacts"] = {"complete": True, "appProcesses": 0,
                                                "runtimeProcesses": 0, "jobCount": 2, "activeJobs": 0}
        self.assertTrue(inventory.classify(self.payload(guests=guests))["inventoryComplete"])
        guests["arch2317"]["matchingQemu"] = [{"pid": 9, "startTicks": 11}]
        guests["arch2317"]["guestProbe"] = "observed-off-no-active-jobs"
        guests["arch2317"]["diskHeldBy"] = [8]
        self.assertFalse(inventory.classify(self.payload(guests=guests))["inventoryComplete"])
        guests["arch2317"]["matchingQemu"] = [9]
        self.assertFalse(inventory.classify(self.payload(guests=guests))["inventoryComplete"])
        guests["arch2317"]["matchingQemu"] = [{"pid": 9, "startTicks": 10}]
        guests["arch2317"]["diskHeldBy"] = [9]
        guests["arch2317"]["portClaimPids"] = [8]
        self.assertFalse(inventory.classify(self.payload(guests=guests))["inventoryComplete"])

    def test_running_socket_claims_do_not_substitute_for_actual_fd_ownership(self):
        guests = self.payload()["guests"]
        guests["arch2317"].update({"state": "running", "matchingQemu": [{"pid": 9, "startTicks": 10}],
                                   "diskHeldBy": [9], "portListeners": 1, "qmpPresent": True,
                                   "portClaimPids": [9], "qmpClaimPids": [9], "qmpSafe": True,
                                   "portOwnerPids": [9], "qmpOwnerPids": [9],
                                   "guestProbe": "observed-off-no-active-jobs",
                                   "guestFacts": {"complete": True, "appProcesses": 0,
                                                  "runtimeProcesses": 0, "jobCount": 0, "activeJobs": 0}})
        self.assertTrue(inventory.classify(self.payload(guests=guests))["inventoryComplete"])
        for change in ({"portOwnerPids": []}, {"qmpOwnerPids": []},
                       {"socketInventoryComplete": False}, {"generationStable": False}):
            with self.subTest(change=change):
                candidate = self.payload()["guests"]
                candidate["arch2317"].update(guests["arch2317"] | change)
                self.assertFalse(inventory.classify(self.payload(guests=candidate))["inventoryComplete"])

    def test_unreadable_still_live_guest_pid_makes_guest_census_incomplete(self):
        output = StringIO()
        original_open = open
        def fake_open(path, *args, **kwargs):
            if str(path) == "/proc/123/stat":
                raise PermissionError("unreadable")
            return original_open(path, *args, **kwargs)
        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(inventory.os, "listdir", return_value=["123"]), \
             mock.patch.object(inventory.os.path, "exists", return_value=True), \
             mock.patch.object(inventory.os, "getpid", return_value=1), \
             mock.patch.object(inventory.os, "getppid", return_value=2), \
             mock.patch("builtins.print", side_effect=lambda value: output.write(value)):
            exec(inventory._GUEST_PROGRAM, {})
        self.assertFalse(json.loads(output.getvalue())["complete"])

    def test_first_qemu_generation_is_rechecked_after_second_guest_probe(self):
        guests = self.payload()["guests"]
        guests["ubuntu2307"]["matchingQemu"] = [{"pid": 9, "startTicks": 10}]
        guests["arch2317"]["matchingQemu"] = [{"pid": 11, "startTicks": 12}]
        # Both would have passed a per-guest check before the second probe.
        observed_after_second_probe = {9: 99, 11: 12}
        inventory._final_generation_stability(guests, observed_after_second_probe.get)
        self.assertFalse(guests["ubuntu2307"]["generationStable"])
        self.assertTrue(guests["arch2317"]["generationStable"])
        self.assertIn("_final_generation_stability(guests,ticks)", inventory._REMOTE_PROGRAM)

    def test_observer_uses_only_fixed_host_and_bounded_transport(self):
        with mock.patch.object(inventory, "_run_fixed", return_value=json.dumps(self.payload()).encode()) as run, \
             mock.patch.object(inventory, "_reservations", return_value={"pendingCount": 0, "runningCount": 0,
                                                                         "reservedMemoryBytes": 0}):
            result = inventory.observe(".", "archlinux", 12)
        self.assertTrue(result["inventoryComplete"])
        self.assertEqual(0, result["reservations"]["pendingCount"])
        run.assert_called_once_with(".", "archlinux", 12)
        with self.assertRaises(ValueError):
            inventory.observe(".", "other", 12)


if __name__ == "__main__":
    unittest.main()
