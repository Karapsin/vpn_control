"""Causal guards for Windows baseline discovery around a live CP117 disk."""
from __future__ import annotations

import unittest
from unittest import mock
import json
from types import SimpleNamespace

from agent_tools import windows_vm_baseline_inventory as inventory


def envelope(*, candidates=None, processes=True, census=True):
    return {"schemaVersion": 1, "host": "archlinux", "observedAtUnixMs": 1,
            "pathsComplete": True, "processesComplete": processes,
            "holderCensusComplete": census, "candidates": candidates or []}


def candidate(*, qemu_holders=None, all_holders=None, image=True, no_qemu=None,
              source_state="unknown"):
    qemu_holders = qemu_holders or []
    all_holders = all_holders or []
    return {"path": "/home/kardinal/windows-native/disk.qcow2", "sizeBytes": 100,
            "image": {"format": "qcow2", "backingFile": None, "virtualSizeBytes": 1024}
                     if image else None,
            "holders": qemu_holders, "argvUsers": [], "allProcessHolders": all_holders,
            "noQemuObserved": not qemu_holders if no_qemu is None else no_qemu,
            "sourceState": source_state}


class WindowsVmBaselineInventoryTest(unittest.TestCase):
    def test_remote_observer_compiles(self) -> None:
        compile(inventory._REMOTE, "<windows-baseline-inventory>", "exec")
        compile(inventory._MEDIA_HASH_REMOTE, "<windows-media-hash>", "exec")

    def test_live_disk_is_reported_as_held_and_never_admitted(self) -> None:
        holder = {"pid": 7, "startTicks": 42}
        result = inventory.classify(envelope(candidates=[candidate(
            qemu_holders=[holder], all_holders=[holder])]))
        self.assertTrue(result["inventoryComplete"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["candidates"][0]["noQemuObserved"])
        self.assertEqual("unknown", result["candidates"][0]["sourceState"])

    def test_incomplete_process_census_fails_closed(self) -> None:
        result = inventory.classify(envelope(processes=False))
        self.assertFalse(result["inventoryComplete"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_false_no_qemu_claim_fails_closed(self) -> None:
        holder = {"pid": 7, "startTicks": 42}
        result = inventory.classify(envelope(candidates=[candidate(
            qemu_holders=[holder], all_holders=[holder], no_qemu=True)]))
        self.assertFalse(result["inventoryComplete"])

    def test_locked_image_remains_visible_with_unknown_inventory(self) -> None:
        holder = {"pid": 7, "startTicks": 42}
        result = inventory.classify(envelope(candidates=[candidate(
            qemu_holders=[holder], all_holders=[holder], image=False)]))
        self.assertFalse(result["inventoryComplete"])
        self.assertEqual(1, len(result["candidates"]))

    def test_non_qemu_holder_cannot_be_mislabelled_stopped(self) -> None:
        holder = {"pid": 8, "startTicks": 55}
        result = inventory.classify(envelope(candidates=[candidate(all_holders=[holder])]))
        self.assertTrue(result["inventoryComplete"])
        self.assertTrue(result["candidates"][0]["noQemuObserved"])
        self.assertEqual("unknown", result["candidates"][0]["sourceState"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_clean_fd_census_can_report_stopped_observed_only(self) -> None:
        result = inventory.classify(envelope(candidates=[candidate(source_state="stopped-observed")]))
        self.assertTrue(result["inventoryComplete"])
        self.assertEqual("stopped-observed", result["candidates"][0]["sourceState"])
        self.assertFalse(result["nativeActionAllowed"])

    def test_incomplete_fd_census_cannot_claim_stopped(self) -> None:
        result = inventory.classify(envelope(candidates=[candidate(
            source_state="stopped-observed")], census=False))
        self.assertFalse(result["inventoryComplete"])

    def test_media_fingerprint_rejects_unstable_source(self) -> None:
        payload = {"schemaVersion": 1, "host": "archlinux", "observedAtUnixMs": 1,
                   "media": {key: {"path": path, "sizeBytes": 10, "sha256": "a" * 64,
                                   "stable": key != "windows-x64"}
                             for key, path in inventory._MEDIA_PATHS.items()}}
        fake_config = SimpleNamespace(hosts={"archlinux": object()})
        fake_transport = SimpleNamespace(password=None)
        run = SimpleNamespace(returncode=0, stdout=json.dumps(payload).encode())
        with (mock.patch.object(inventory.ssh_transport, "load_config", return_value=fake_config),
              mock.patch.object(inventory.ssh_transport, "connection_host", return_value=fake_transport),
              mock.patch.object(inventory.ssh_transport, "build_ssh_argv", return_value=("ssh",)),
              mock.patch.object(inventory.subprocess, "run", return_value=run)):
            with self.assertRaisesRegex(ValueError, "unstable"):
                inventory.media_fingerprint(".", "archlinux")


if __name__ == "__main__":
    unittest.main()
