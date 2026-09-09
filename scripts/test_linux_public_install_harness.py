import json
import io
import errno
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

from prepare_desktop_update_fixture import MAIN_CLASS, VERSION_RESOURCE, image_identity, version_build
from prepare_linux_public_install_image import prepare
from test_linux_public_install import (launch_fixture_owner, require_package_managed_launcher, run,
                                       observe_terminal_process, timed_update_command, verify_recovered_install)


class LinuxPublicInstallHarnessTest(unittest.TestCase):
    def test_arch_recovery_rejects_alternate_install_path_before_fixture_or_process_access(self):
        linux = types.SimpleNamespace(uname=lambda: types.SimpleNamespace(sysname="Linux"), getuid=lambda: 1000)
        with mock.patch("test_linux_public_install.os", linux), \
             mock.patch("builtins.open", return_value=io.BytesIO()), \
             mock.patch("test_linux_public_install.verify_arch_bundle_base",
                        side_effect=AssertionError("Unsupported installation reached fixture verification")) as verify:
            with self.assertRaisesRegex(RuntimeError, "Arch public installation requires /opt/vpn-control/bin/vpn-control"):
                run(Path("/opt/vpn-control-parity/bin/vpn-control"), "2.1.7", True,
                    same_source_recovery=True, arch_source_fixture=Path("unused-source-fixture"))
        verify.assert_not_called()

    def test_arch_recovery_canonical_path_still_requires_full_fixture_verification(self):
        linux = types.SimpleNamespace(uname=lambda: types.SimpleNamespace(sysname="Linux"), getuid=lambda: 1000)
        with mock.patch("test_linux_public_install.os", linux), \
             mock.patch("builtins.open", return_value=io.BytesIO()), \
             mock.patch("test_linux_public_install.verify_arch_bundle_base",
                        side_effect=RuntimeError("Full source verification reached")) as verify:
            with self.assertRaisesRegex(RuntimeError, "Full source verification reached"):
                run(Path("/opt/vpn-control/bin/vpn-control"), "2.1.7", True,
                    same_source_recovery=True, arch_source_fixture=Path("unused-source-fixture"))
        verify.assert_called_once()

    def test_terminal_observer_drains_final_output_then_records_known_exit_after_pty_eio(self):
        class Process:
            polls = 0
            def poll(self):
                self.polls += 1
                return 7

        process = Process()
        output = bytearray()
        with mock.patch("test_linux_public_install.select.select", side_effect=[([19], [], []), ([19], [], []), ([], [], [])]), \
             mock.patch("test_linux_public_install.os.read", side_effect=[b"final receipt\n", OSError(errno.EIO, "PTY closed")]):
            result = observe_terminal_process(process, 19, output.extend)
        self.assertEqual(b"final receipt\n", bytes(output))
        self.assertEqual({"exit": 7, "observationLost": True, "timedOut": False}, result)
        self.assertEqual(1, process.polls, "Observer must not replay the action after EIO")

    def test_terminal_observer_returns_unknown_for_still_live_timeout_without_waiting(self):
        class LiveProcess:
            def poll(self): return None

        with mock.patch("test_linux_public_install.select.select", return_value=([], [], [])):
            result = observe_terminal_process(LiveProcess(), 19, lambda data: self.fail(data), timeout_seconds=0)
        self.assertEqual({"exit": None, "observationLost": False, "timedOut": True}, result)

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

    def test_fixture_owner_does_not_propagate_dyld_injection_to_the_child(self):
        environment = {"PATH": "/fixture/bin", "DYLD_INSERT_LIBRARIES": "/fixture/injected.dylib"}
        with mock.patch("test_linux_public_install.subprocess.Popen") as start:
            launch_fixture_owner(Path("/fixture/launcher"), Path("/fixture/state"), object(), environment)
        child_environment = start.call_args.kwargs["env"]
        self.assertNotIn("DYLD_INSERT_LIBRARIES", child_environment)
        self.assertEqual("/fixture/bin", child_environment["PATH"])
        self.assertEqual("/fixture/injected.dylib", environment["DYLD_INSERT_LIBRARIES"],
                         "The caller environment must remain unchanged")

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

    def test_same_source_recovery_rejects_an_unmanaged_copied_launcher_before_install(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "opt/vpn-control"
            app = image / "lib/app"
            app.mkdir(parents=True)
            launcher = image / "bin/vpn-control"
            launcher.parent.mkdir()
            # The old harness reached Popen (and this inert ELF fails exec) before
            # it checked package ownership. The fixed harness must reject first.
            launcher.write_bytes(b"\x7fELFfixture-not-executed")
            launcher.chmod(0o755)
            main = app / "desktopApp-fixture.jar"
            with zipfile.ZipFile(main, "w") as jar:
                jar.writestr(MAIN_CLASS, b"fixture-main")
                jar.writestr(VERSION_RESOURCE, "displayVersion=1.0.5\nbuildNumber=" + str(version_build("1.0.5")) + "\n")
            (app / "vpn-control.cfg").write_text("[Application]\napp.classpath=$APPDIR/" + main.name +
                                                   "\napp.mainclass=" + MAIN_CLASS.removesuffix(".class").replace("/", ".") + "\n")
            identity = image_identity(image, "1.0.5")
            (image / "TEST-ONLY-INSTALL-FIXTURE.json").write_text(json.dumps({
                "testOnly": True, "productionTrustChanged": False, "sameSourceBuild": True,
                "sourceFingerprint": "0" * 64, "version": "1.0.5", **identity,
            }))
            original_stat = Path.stat

            def root_owned(path, *args, **kwargs):
                info = original_stat(path, *args, **kwargs)
                # Model a private root-owned fixture mount. The temporary host
                # directory is deliberately not part of that fixture ancestry.
                return os.stat_result((info.st_mode & ~0o022, info.st_ino, info.st_dev, info.st_nlink, 0, info.st_gid,
                                       info.st_size, info.st_atime, info.st_mtime, info.st_ctime))

            public_ancestor = launcher.resolve().parents[3]

            def public_temp_ancestor(path, *args, **kwargs):
                info = root_owned(path, *args, **kwargs)
                # Do not resolve here: Python 3.12's resolve implementation
                # consults Path.stat, which is the mocked method calling us.
                if path == public_ancestor:
                    return os.stat_result((info.st_mode | 0o022, info.st_ino, info.st_dev, info.st_nlink,
                                           info.st_uid, info.st_gid, info.st_size, info.st_atime,
                                           info.st_mtime, info.st_ctime))
                return info

            original_resolve = Path.resolve

            def resolve_via_stat(path, *args, **kwargs):
                path.stat()
                return original_resolve(path, *args, **kwargs)

            original_open = open

            def open_tty(path, *args, **kwargs):
                return io.BytesIO() if path == "/dev/tty" else original_open(path, *args, **kwargs)

            # Windows lacks uname/getuid. Start with a child os namespace that
            # has neither attribute, then create only the deterministic Linux
            # fixture APIs that this test needs.
            with mock.patch("test_linux_public_install.os", types.SimpleNamespace()):
                common = dict(return_value=type("Unix", (), {"sysname": "Linux"})(), create=True)
                with mock.patch("test_linux_public_install.os.uname", **common), \
                     mock.patch("test_linux_public_install.os.getuid", return_value=1000, create=True), \
                     mock.patch("builtins.open", open_tty):
                    # Reproduce Python 3.12's resolve-to-stat interaction. The
                    # legacy callback recursed here; the fixed comparison must
                    # reach the real public-ancestor rejection.
                    with mock.patch("test_linux_public_install.Path.stat", public_temp_ancestor), \
                         mock.patch("test_linux_public_install.Path.resolve", resolve_via_stat):
                        with self.assertRaisesRegex(RuntimeError, "ancestry"):
                            run(launcher, "1.0.5", True, same_source_recovery=True)
                    with mock.patch("test_linux_public_install.subprocess.run") as command, \
                         mock.patch("test_linux_public_install.Path.stat", root_owned):
                        command.side_effect = [
                            subprocess.CompletedProcess(["dpkg-query"], 1, "", "not owned"),
                            FileNotFoundError(), FileNotFoundError(),
                        ]
                        with self.assertRaisesRegex(RuntimeError, "owned by vpn-control package metadata"):
                            run(launcher, "1.0.5", True, same_source_recovery=True)
            self.assertEqual(["dpkg-query", "--search", str(launcher.resolve())], command.call_args_list[0].args[0])

    def test_same_source_recovery_accepts_debian_owned_launcher(self):
        launcher = Path("/opt/vpn-control/bin/vpn-control")
        with mock.patch("test_linux_public_install.subprocess.run") as command:
            command.return_value = subprocess.CompletedProcess(["dpkg-query"], 0,
                                                               "vpn-control: " + str(launcher) + "\n", "")
            require_package_managed_launcher(launcher)

    def test_same_source_recovery_uses_the_native_owner_query_after_another_manager_misses(self):
        launcher = Path("/opt/vpn-control/bin/vpn-control")
        with mock.patch("test_linux_public_install.subprocess.run") as command:
            command.side_effect = [
                subprocess.CompletedProcess(["dpkg-query"], 1, "", "not owned"),
                subprocess.CompletedProcess(["rpm"], 0, "vpn-control\n", ""),
            ]
            require_package_managed_launcher(launcher)
        self.assertEqual(["rpm", "--query", "--file", "--queryformat", "%{NAME}\\n", str(launcher)],
                         command.call_args_list[1].args[0])

    @unittest.skipUnless(os.name == "posix", "POSIX shell return-dispatch execution")
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
