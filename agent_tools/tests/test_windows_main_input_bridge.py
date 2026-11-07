"""Routine current input controls and thirteen authentic historical cause pairs.

All guest, review, Win32 and QMP actors are explicitly inert fixture peers.
Availability skips describe host capabilities; they never establish native input.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

FIXTURES = Path(__file__).parent / "fixtures/windows_main_input_bridge"
_path = FIXTURES / "boundary.py"
_spec = importlib.util.spec_from_file_location("_windows_main_input_routine_boundary", _path)
_boundary = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _boundary
_spec.loader.exec_module(_boundary)
_current = _boundary.load_current_controls()
_posix = _boundary.posix_capable()
_powershell = _boundary.powershell()


@unittest.skipUnless(_posix, "POSIX file-descriptor fixture APIs unavailable; native Windows input is separate")
class WindowsMainInputBridgePosixTest(_current.BridgeControls):
    """Unchanged current methods, original real-file setup and declared peers."""


# These actual existing methods need PowerShell and temporary files, not the
# inherited POSIX DurableIntent setup. No method body or predicate is replaced.
for _name in _boundary.POWERSHELL_METHODS:
    setattr(WindowsMainInputBridgePosixTest, _name, None)


@unittest.skipUnless(_powershell is not None, "PowerShell runtime unavailable; native Windows scenario remains open")
class WindowsMainInputBridgePowerShellTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="windows-main-input-powershell-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.expected, self.row, self.render_input = _current.specimen()

    selection_segment = _current.BridgeControls.selection_segment

    def test_actual_native_types_compile_without_pinvoke(self):
        script = self.directory / "compile-native-types-only.ps1"
        script.write_text("$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"
            + _current.s.NATIVE + "\n'@\n[Console]::WriteLine('COMPILED_NO_PINVOKE')\n")
        result = subprocess.run([_powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
            capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout.decode()+result.stderr.decode())
        self.assertIn(b"COMPILED_NO_PINVOKE", result.stdout)


for _name in _boundary.POWERSHELL_METHODS:
    setattr(WindowsMainInputBridgePowerShellTest, _name, getattr(_current.BridgeControls, _name))


@unittest.skipUnless(_posix, "Authentic causal helpers require their original POSIX file fixture setup")
class WindowsMainInputBridgeHistoricalCausalTest(unittest.TestCase):
    def pair(self, name):
        case = next(item for item in _boundary.CASES if item[0] == name)
        if case[7] and _powershell is None:
            self.skipTest("Original PowerShell causal oracle runtime unavailable")
        runs = _boundary.run_pair(name)
        self.assertEqual([run["returnCode"] for run in runs], [1, 0])

    def test_causal_source_helper_import(self): self.pair("source-helper-import")
    def test_causal_canonical_envelope_budget(self): self.pair("canonical-envelope-budget")
    def test_causal_partial_qmp_custody(self): self.pair("partial-qmp-custody")
    def test_causal_parent_capture_scope(self): self.pair("parent-capture-scope")
    def test_causal_powershell_finite_guard(self): self.pair("powershell-finite-guard")
    def test_causal_private_qmp_unknown_lock(self): self.pair("private-qmp-unknown-lock")
    def test_causal_frame_conversion_custody(self): self.pair("frame-conversion-custody")
    def test_causal_fixed_lifetime_root(self): self.pair("fixed-lifetime-root")
    def test_causal_system_consent_sid(self): self.pair("system-consent-sid")
    def test_causal_selected_account_validator(self): self.pair("selected-account-validator")
    def test_causal_selected_account_powershell(self): self.pair("selected-account-powershell")
    def test_causal_native_guid_whole_bridge(self): self.pair("native-guid-whole-bridge")
    def test_causal_native_guid_powershell_emitter(self): self.pair("native-guid-powershell-emitter")


class WindowsMainInputBridgeCatalogTest(unittest.TestCase):
    def test_complete_current_control_inventory_and_registered_globals(self):
        names = unittest.TestLoader().getTestCaseNames(_current.BridgeControls)
        self.assertEqual(len(names), 40)
        self.assertEqual(len(_boundary.CASES), 13)
        self.assertEqual(len(set(_boundary.POWERSHELL_METHODS)), 7)
        for name in names:
            function = getattr(_current.BridgeControls, name)
            self.assertIs(function.__globals__, _current.__dict__)
            self.assertIs(sys.modules[function.__module__], _current)
        for module in (_current.b, _current.s, _current.backend_module, _current.pending_module):
            self.assertIs(sys.modules[module.__name__], module)

    def test_authentic_sources_and_declared_current_roles(self):
        pins = _boundary.provenance()
        self.assertEqual(set(pins["production"]), set(_boundary.SOURCE_ROLES.values()))
        self.assertTrue(all(pin["completeOriginalBytes"] for pin in pins["fixtures"].values()))
        self.assertTrue(all(pin["sourceBytesUnchanged"] for pin in pins["production"].values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
