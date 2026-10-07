"""Discover the unchanged-harness Linux negative protocol regression."""
import importlib.util
from pathlib import Path

_SOURCE = Path(__file__).resolve().parents[2] / "scripts/test_linux_public_install_negative.py"
_SPEC = importlib.util.spec_from_file_location("linux_public_install_negative_regression", _SOURCE)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
LinuxPublicInstallNegativeTests = _MODULE.LinuxPublicInstallNegativeTests
LinuxNegativeImportIsolationTests = _MODULE.LinuxNegativeImportIsolationTests
