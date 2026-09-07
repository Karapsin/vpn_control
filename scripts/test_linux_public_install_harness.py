import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from prepare_linux_public_install_image import prepare
from test_linux_public_install import launch_fixture_owner, run, timed_update_command, verify_recovered_install


class LinuxPublicInstallHarnessTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX controlling-session lifecycle")
    def test_fixture_owner_has_independent_session_before_terminal_driver_exits(self):
        with tempfile.TemporaryDirectory(prefix="vpn-fixture-session-") as temporary:
            root = Path(temporary)
            launcher = root / "inert-launcher"
            launcher.write_text("#!" + sys.executable + "\nimport json, os\n"
                                "print(json.dumps({'pid': os.getpid(), 'session': os.getsid(0)}))\n")
            launcher.chmod(0o700)
            output = root / "owner.log"
            with output.open("wb") as log:
                process = launch_fixture_owner(launcher, root / "unused-state", log, dict(os.environ))
                self.assertEqual(0, process.wait(timeout=10))
            child = json.loads(output.read_text())
            self.assertEqual(child["pid"], child["session"], "PTY driver exit must not SIGHUP the fixture owner")
            self.assertNotEqual(os.getsid(0), child["session"])

    def test_same_source_recovery_requires_exact_protected_job_operation_and_origin(self):
        accepted = {"controllerId": "before", "requestId": "request", "operationId": "operation", "data": {"jobId": "job"}}
        receipt = {"phase": "SUCCEEDED", "code": "OK", "jobId": "job"}
        recovered = {"ok": True, "code": "OK", "final": True, "controllerId": "after", "operationId": "operation",
                     "data": {"jobId": "job", "originControllerId": "before", "originRequestId": "request"}}
        verify_recovered_install(accepted, receipt, recovered)
        for change in ({"ok": False}, {"final": False}, {"code": "ACCEPTED"}, {"controllerId": "before"},
                       {"operationId": "another"}, {"data": {**recovered["data"], "jobId": "another"}},
                       {"data": {**recovered["data"], "originControllerId": "another"}},
                       {"data": {**recovered["data"], "originRequestId": "another"}}):
            with self.assertRaises(RuntimeError):
                verify_recovered_install(accepted, receipt, {**recovered, **change})
        with self.assertRaises(RuntimeError):
            verify_recovered_install(accepted, {**receipt, "phase": "INSTALLING"}, recovered)

    def test_original_user_relaunch_preserves_headless_or_gui_return_intent(self):
        repository = Path(__file__).resolve().parent.parent
        watcher = (repository / "desktopApp/src/main/resources/linux-install-user.sh").read_text()
        definitions = watcher[:watcher.index("\njob_id=")]
        # Execute the actual successful-receipt return dispatch with an inert
        # launcher. Receipt admission and package managers are never executed.
        dispatch = watcher.split('if [ "$(od -An -tu1 "$machine_root/gate-linux"', 1)[1]
        dispatch = dispatch.split("then\n", 1)[1].split("\n        fi", 1)[0]
        with tempfile.TemporaryDirectory(prefix="vpn-install-return-") as temporary:
            root = Path(temporary)
            launcher = root / "fixture launcher"
            launcher.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$VPN_FIXTURE_OUTPUT"\n')
            launcher.chmod(0o700)
            for frontend, expected in (("0", ["serve"]), ("123", [])):
                output = root / ("return-" + frontend)
                script = definitions + '\nlauncher=$1; state_directory=$2; frontend_pid=$3\n' + dispatch
                result = subprocess.run(["/bin/sh", "-c", script, "fixture", str(launcher),
                                         str(root / "state 東京"), frontend], capture_output=True,
                                        text=True, timeout=10, env={**os.environ, "VPN_FIXTURE_OUTPUT": str(output)})
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(["--state-dir", str(root / "state 東京"), *expected], output.read_text().splitlines())

    def test_timed_update_commands_use_actual_shared_parser_global_option(self):
        repository = Path(__file__).resolve().parent.parent
        parser = (repository / "shared/core/src/commonMain/kotlin/com/kardinal/vpncontrol/control/ControlCliParser.kt").read_text()
        declaration = re.search(r"private val globalValues = setOf\(([^\n]+)\)", parser)
        self.assertIsNotNone(declaration, "Review harness grammar when shared parser declaration changes")
        global_values = set(re.findall(r'"([^"]+)"', declaration.group(1)))
        for action, seconds in (("download", 600), ("install", 240)):
            command = timed_update_command(action, seconds)
            self.assertIn(command[0], global_values, "Harness timeout option is not accepted by the production parser")
            self.assertEqual((str(seconds), "updates", action), command[1:])
            self.assertIn('globals["' + command[0] + '"]?.toLongOrNull()', parser)

    def image(self, root):
        source = root / "source"
        (source / "bin").mkdir(parents=True)
        (source / "lib/runtime").mkdir(parents=True)
        (source / "lib/app").mkdir()
        (source / "bin/vpn-control").write_bytes(b"\x7fELFfixture-not-executed")
        main = source / "lib/app/main.jar"
        with zipfile.ZipFile(main, "w") as jar:
            for name in ("com/kardinal/vpncontrol/desktop/MainKt.class", "linux-install-worker.sh",
                         "linux-install-arch.sh", "com/kardinal/vpncontrol/desktop/DesktopLinuxInstallClient.class",
                         "com/kardinal/vpncontrol/desktop/DesktopInstallCorrelationJournal.class"):
                jar.writestr(name, b"frozen fixture bytes")
            jar.writestr("vpn-control-version.properties", b"buildNumber=99\ndisplayVersion=1.0.5\n")
        return source, main

    def test_clone_changes_only_metadata_and_preserves_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, main = self.image(root)
            original = main.read_bytes()
            result = prepare(source, root / "output")
            self.assertEqual(original, main.read_bytes())
            self.assertFalse(result["receipt"]["productionTrustChanged"])
            clone = Path(result["image"])
            self.assertTrue(json.loads((clone / "TEST-ONLY-INSTALL-FIXTURE.json").read_text())["testOnly"])
            with zipfile.ZipFile(main) as before, zipfile.ZipFile(clone / "lib/app/main.jar") as after:
                self.assertEqual(before.namelist(), after.namelist())
                for name in before.namelist():
                    self.assertEqual(b"buildNumber=1\ndisplayVersion=1.0.0\n" if name == "vpn-control-version.properties"
                                     else before.read(name), after.read(name))

    def test_refuses_external_symlink_without_creating_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, _ = self.image(root)
            outside = root / "outside"
            outside.write_text("keep")
            try:
                (source / "lib/runtime/external").symlink_to(outside)
            except OSError:
                self.skipTest("Symlink creation unavailable")
            with self.assertRaises(AssertionError):
                prepare(source, root / "output")
            self.assertFalse((root / "output").exists())
            self.assertEqual("keep", outside.read_text())

    def test_no_install_without_explicit_disposable_vm_confirmation(self):
        with self.assertRaisesRegex(RuntimeError, "Explicit owned-disposable-VM"):
            run(Path("/never-executed"), "1.0.1", False)


if __name__ == "__main__":
    unittest.main()
