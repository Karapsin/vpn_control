import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from windows_native_fixture import private_task_root


class WindowsNativeFixtureTest(unittest.TestCase):
    def test_accepts_each_owned_task_prefix_and_derives_exact_private_root(self):
        local = r"C:\Users\visualagent\AppData\Local"
        suffix = "1b1515e2-2fb1-4483-a280-0b2264d058dc"
        for prefix in ("VpnInstallerEntry32-", "VpnInstallerClose32-", "VpnInstallerPreflight32-"):
            task = prefix + suffix
            self.assertEqual(local + "\\" + task, private_task_root(task, local))

    def test_rejects_mismatched_or_nonprivate_task_root_inputs(self):
        local = r"C:\Users\visualagent\AppData\Local"
        with self.assertRaises(ValueError):
            private_task_root("VpnInstallerBogus32-1b1515e2-2fb1-4483-a280-0b2264d058dc", local)
        with self.assertRaises(ValueError):
            private_task_root("VpnInstallerClose32-not-a-uuid", local)
        with self.assertRaises(ValueError):
            private_task_root("VpnInstallerClose32-1b1515e2-2fb1-4483-a280-0b2264d058dc", r"C:\Windows\Temp")


if __name__ == "__main__":
    unittest.main()
