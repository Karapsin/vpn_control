from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent_tools import vm_workflow


def fixture_input(path: Path) -> dict[str, object]:
    contents = path.read_bytes()
    return {"path": str(path), "size": len(contents), "sha256": hashlib.sha256(contents).hexdigest()}


class VmWorkflowTest(unittest.TestCase):
    def test_empty_missing_and_hash_mismatched_inputs_are_rejected_before_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "runner.py"
            empty.write_bytes(b"")
            for value in (
                {"path": str(root / "missing.py"), "size": 1, "sha256": "a" * 64},
                {"path": str(empty), "size": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                {"path": str(empty), "size": 1, "sha256": "b" * 64},
            ):
                with self.subTest(value=value), self.assertRaises(vm_workflow.VmWorkflowError):
                    vm_workflow.inspect_input(value)

    def test_hash_matched_unknown_preflight_is_rejected_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary) / "runner.py"
            runner.write_text("raise RuntimeError('must not run')\n", encoding="utf-8")
            with self.assertRaisesRegex(vm_workflow.VmWorkflowError, "not an approved"):
                vm_workflow.inspect_input(fixture_input(runner), preflight="arbitrary-import")

    def test_tampered_staged_sibling_is_rejected_before_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "stage"
            stage.mkdir()
            for name in ("prepare_desktop_update_fixture.py", "fixture_environment.py",
                         "macos_packaging_jdk_preflight.py"):
                shutil.copy2(vm_workflow.SCRIPTS_ROOT / name, stage / name)
            # The stage must not turn an approved preflight name into an
            # arbitrary import. It is rejected before the subprocess import.
            (stage / "fixture_environment.py").write_text("raise NameError('staged sibling missing')\n", encoding="utf-8")
            with self.assertRaisesRegex(vm_workflow.VmWorkflowError, "differs from checked-in fixture_environment"):
                vm_workflow.inspect_input(
                    fixture_input(stage / "prepare_desktop_update_fixture.py"),
                    preflight="desktop-update-entrypoint",
                )

    def test_known_staged_preflight_isolated_import_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stage = Path(temporary) / "stage"
            stage.mkdir()
            for name in ("prepare_desktop_update_fixture.py", "fixture_environment.py",
                         "macos_packaging_jdk_preflight.py"):
                shutil.copy2(vm_workflow.SCRIPTS_ROOT / name, stage / name)
            # A staged directory can contain unreviewed shadow modules; the
            # preflight copies only the verified inventory into its import root.
            (stage / "ssl.py").write_text("raise NameError('shadow must not import')\n", encoding="utf-8")
            result = vm_workflow.inspect_input(
                fixture_input(stage / "prepare_desktop_update_fixture.py"),
                preflight="desktop-update-entrypoint",
            )
            self.assertEqual("ready", result["state"])
            self.assertEqual("desktop-update-entrypoint", result["preflight"])

    def test_admission_rejects_pressure_swap_and_insufficient_configured_memory_headroom(self) -> None:
        base = {"physicalMemoryBytes": 24, "runningConfiguredMemoryBytes": 4,
                "pressure": "normal", "swapUsedBytes": 0}
        invalid = (
            {**base, "pressure": "warning"},
            {**base, "pressure": True},
            {**base, "swapUsedBytes": 1},
            {**base, "physicalMemoryBytes": 12},
        )
        for measurement in invalid:
            with self.subTest(measurement=measurement), self.assertRaises(vm_workflow.VmWorkflowError):
                vm_workflow.admit_plan(measurement, requested_memory_bytes=8, headroom_bytes=4,
                                       reservations=({"id": "other-vm", "memoryBytes": 4},))

    def test_admission_reports_only_a_nonpersistent_caller_supplied_plan(self) -> None:
        result = vm_workflow.admit_plan(
            {"physicalMemoryBytes": 24, "runningConfiguredMemoryBytes": 4,
             "pressure": 1, "swapUsedBytes": 0},
            requested_memory_bytes=8,
            headroom_bytes=4,
            reservations=({"id": "reserved-fixture", "memoryBytes": 4},),
        )
        self.assertEqual("planned", result["state"])
        self.assertEqual("caller-supplied", result["measurementSource"])
        self.assertFalse(result["reservation"]["persisted"])
        self.assertFalse(result["nativeActionAllowed"])
        self.assertEqual(20, result["requiredMemoryBytes"])

    def test_mcp_cli_loads_vm_workflow_from_a_foreign_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = root / "runner.py"
            runner.write_text("# verified only\n", encoding="utf-8")
            inputs = root / "inputs.json"
            inputs.write_text(json.dumps({"input": fixture_input(runner)}), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(vm_workflow.REPO_ROOT / "agent_tools" / "mcp_server.py"),
                 "vm-workflow", "inspect-input", "--inputs", str(inputs)],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
