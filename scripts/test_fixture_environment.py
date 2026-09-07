import os
import unittest
from pathlib import Path
from unittest import mock
from fixture_environment import require_jdk17, validate_qemu_argv

class FixtureEnvironmentTest(unittest.TestCase):
    def test_java26_is_rejected_and_jdk17_is_accepted(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr='openjdk version "26.0.2.1"\n'))
        with self.assertRaisesRegex(ValueError, "JDK 17"):
            require_jdk17(runner=runner)
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr='openjdk version "17.0.20"\n'))
        self.assertIn("17.0.20", require_jdk17(runner=runner))
    def test_java_home_controls_effective_gradle_jvm(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0, stdout="", stderr='openjdk version "26.0.2"\n'))
        with self.assertRaisesRegex(ValueError, "JDK 17"):
            require_jdk17(runner=runner, environment={"JAVA_HOME": "/jdk26"})
        executable = "java.exe" if os.name == "nt" else "java"
        self.assertEqual([str(Path("/jdk26") / "bin" / executable), "-version"], runner.call_args.args[0])

    def test_qemu_serial_requires_file_colon(self):
        with self.assertRaisesRegex(ValueError, "file:"):
            validate_qemu_argv(["qemu", "-serial", "file=x"])
        validate_qemu_argv(["qemu", "-serial", "file:x"])
if __name__ == "__main__": unittest.main()
