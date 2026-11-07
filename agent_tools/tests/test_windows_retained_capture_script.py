"""The frozen UAC routing qualification keeps the capture script it was frozen with."""
import ast
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RETAINED = Path(__file__).resolve().parent / "fixtures/windows_native_packet_recipe/routing/inputs/capture_visual_windows_qemu.pre-admission.source"


def typed(raw):
    return [node.args[1].value for node in ast.walk(ast.parse(raw))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_type_command"
            and len(node.args) == 2 and isinstance(node.args[1], ast.Constant)]


class RetainedCaptureScriptTest(unittest.TestCase):
    def test_retained_capture_script_types_the_same_command_as_the_current_one(self):
        # capture_uac's body moved behind readiness admission after the qualification
        # was frozen. The typed command is all that qualification reads from the script.
        retained = RETAINED.read_bytes()
        self.assertEqual("75c909247fc08ca5fdd7b1b29ea9c82773a4d527c69f0bd450f82c6200b90854", hashlib.sha256(retained).hexdigest())
        current = (ROOT / "scripts/capture_visual_windows_qemu.py").read_bytes()
        self.assertEqual(["powershell start powershell -verb runas"], typed(retained))
        self.assertEqual(typed(retained), typed(current))


if __name__ == "__main__":
    unittest.main()
