import json
import io
import errno
import os
import re
import select
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
                                       observe_terminal_process, terminal_password_prompt_seen, terminal_install_handoff,
                                       terminal_authorized_identity_choice,
                                       terminal_password_input_ready,
                                       write_password_to_original_master,
                                       launch_with_controlling_tty,
                                       invoke_retained_install,
                                       require_human_terminal,
                                       timed_update_command, verify_recovered_install)


class LinuxPublicInstallHarnessTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux controlling terminal semantics")
    def test_controlling_tty_launch_assigns_dev_tty_while_bare_popen_does_not(self):
        import pty
        probe = [sys.executable, "-c", "import os; os.open('/dev/tty', os.O_RDONLY); print('TTY_OK')"]
        master, slave = pty.openpty()
        attached = None
        try:
            bare = subprocess.run(probe, stdin=slave, stdout=slave, stderr=slave,
                                  start_new_session=True, timeout=5)
            self.assertNotEqual(0, bare.returncode)
            while select.select([master], [], [], 0)[0]:
                os.read(master, 4096)
            attached = launch_with_controlling_tty(probe, slave)
            ready, _, _ = select.select([master], [], [], 1)
            self.assertTrue(ready)
            output = os.read(master, 4096)
            self.assertEqual(0, attached.wait(timeout=5))
            self.assertIn(b"TTY_OK", output)
        finally:
            if attached is not None and attached.poll() is None:
                attached.kill()
                attached.wait(timeout=5)
            os.close(slave)
            os.close(master)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux procfs PTY semantics")
    def test_reopening_proc_master_creates_distinct_pty_but_retained_fd_delivers(self):
        import fcntl
        import pty
        import struct
        import tty
        master, slave = pty.openpty()
        try:
            tty.setraw(slave)
            pty_number = lambda fd: struct.unpack("I", fcntl.ioctl(fd, 0x80045430, struct.pack("I", 0)))[0]
            original = pty_number(master)
            reopened = os.open(f"/proc/self/fd/{master}", os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                self.assertNotEqual(original, pty_number(reopened))
                os.write(reopened, b"wrong\n")
                self.assertFalse(select.select([slave], [], [], 0.05)[0])
                write_password_to_original_master(master, b"synthetic-fixture-response")
                self.assertTrue(select.select([slave], [], [], 0.2)[0])
                self.assertEqual(b"synthetic-fixture-response\n", os.read(slave, 128))
            finally:
                os.close(reopened)
        finally:
            os.close(slave)
            os.close(master)

    @unittest.skipUnless(os.name == "posix", "requires a private POSIX PTY")
    def test_password_response_waits_for_terminal_input_flush_and_echo_disable(self):
        import pty
        import termios
        master, slave = pty.openpty()
        try:
            prompt = b"Password: "
            os.write(slave, prompt)
            observed = os.read(master, len(prompt))
            self.assertTrue(terminal_password_prompt_seen(observed))
            # Polkit prints/flushes its prompt before changing terminal attributes
            # with TCSAFLUSH. A response sent at this point can be discarded.
            self.assertFalse(terminal_password_input_ready(observed, master))
            attributes = termios.tcgetattr(slave)
            # ECHOE/ECHOK are inert while ECHO is disabled and commonly remain
            # set by terminal programs. They must not block an otherwise safe
            # post-flush response.
            attributes[3] |= termios.ECHOE | termios.ECHOK
            attributes[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(slave, termios.TCSAFLUSH, attributes)
            self.assertTrue(terminal_password_input_ready(observed, master))
            attributes[3] |= termios.ECHONL
            termios.tcsetattr(slave, termios.TCSAFLUSH, attributes)
            self.assertFalse(terminal_password_input_ready(observed, master))
            attributes[3] &= ~termios.ECHONL
            termios.tcsetattr(slave, termios.TCSAFLUSH, attributes)
            self.assertTrue(terminal_password_input_ready(observed, master))
            self.assertFalse(terminal_password_input_ready(b"trustStorePassword=diagnostic", master))
            os.write(master, b"synthetic-fixture-response\n")
            self.assertEqual(b"synthetic-fixture-response\n", os.read(slave, 128))
        finally:
            os.close(slave)
            os.close(master)
        self.assertFalse(terminal_password_input_ready(prompt, master))

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux retained PTY semantics")
    def test_retained_driver_repairs_the_ssh_tty_devnull_input_chain_once_after_delayed_echo_off(self):
        # Causal RED: ssh -tt may create /dev/tty while its upstream stdin is
        # /dev/null.  The old file-redirected Popen path then had no writable
        # retained master, so polkit could prompt but never receive input.
        with tempfile.TemporaryDirectory(prefix="vpn-retained-pty-") as temporary:
            root = Path(temporary)
            launcher = root / "fixture-launcher"
            launcher.write_text("#!" + sys.executable + "\n"
                                "import json, os, termios, time\n"
                                "os.write(1, b'Multiple identities can be used for authentication:\\n 1.  vpnfixture\\nChoose identity to authenticate as (1-1): ')\n"
                                "assert os.read(0, 8) == b'1\\n'\n"
                                "time.sleep(.12)\n"
                                "a=termios.tcgetattr(0); a[3] &= ~(termios.ECHO | termios.ECHONL); termios.tcsetattr(0, termios.TCSAFLUSH, a)\n"
                                "os.write(1, b'Password: ')\n"
                                "assert os.read(0, 64) == b'synthetic-private-password\\n'\n"
                                "os.write(1, b'\\n')\n"
                                "os.write(1, json.dumps({'schemaVersion': 1, 'code': 'ACCEPTED', 'final': False, 'data': {}}).encode() + b'\\n')\n")
            launcher.chmod(0o700)
            auth = types.SimpleNamespace(
                status=lambda **kwargs: {"correlation": kwargs["correlation"], "purpose": kwargs["purpose"],
                                          "account": "vpnfixture"},
                # The production helper returns text.  The retained PTY boundary
                # must encode it only immediately before its single write.
                read_credential_after_prompt=mock.Mock(return_value="synthetic-private-password"))
            writes = []
            original_write = write_password_to_original_master
            with mock.patch.dict(sys.modules, {"linux_fixture_auth": auth}), \
                 mock.patch("test_linux_public_install.write_password_to_original_master",
                            side_effect=lambda master, password: (writes.append(password), original_write(master, password))[1]):
                exit_code, envelope = invoke_retained_install(
                    launcher, root / "workspace", dict(os.environ), ("--timeout-seconds", "240", "updates", "install"),
                    root / "credential", "correlation-156", "linux-public-install-polkit-auth", "vpnfixture", root,
                    seconds=.05)
            self.assertEqual(0, exit_code)
            self.assertEqual("ACCEPTED", envelope["code"])
            self.assertEqual([b"synthetic-private-password"], writes,
                             "Delayed prompt/echo-off must admit exactly one credential write")
            auth.read_credential_after_prompt.assert_called_once()
            safe = json.loads((root / "retained-terminal-observation.json").read_text())
            self.assertTrue(safe["identitySelected"] and safe["credentialWritten"])
            self.assertTrue(safe["deadlineElapsed"],
                            "A deadline records UNKNOWN evidence but retains the driver to terminal completion")
            self.assertNotIn("synthetic-private-password", (root / "retained-terminal-observation.json").read_text())

    def test_retained_auth_skips_the_callers_human_tty_requirement(self):
        opener = mock.Mock()
        require_human_terminal(True, opener)
        opener.assert_not_called()
        opened = mock.MagicMock()
        opener.return_value = opened
        require_human_terminal(False, opener)
        opener.assert_called_once_with("/dev/tty", "rb")
        opened.__enter__.assert_called_once_with()

    def test_retained_auth_preparation_forwards_only_an_explicit_password_preservation_opt_in(self):
        auth = types.SimpleNamespace(
            FIXTURE_ACCOUNT="vpnfixture",
            OWNED_GUEST_CONFIRMATION="I_CONFIRM_VPNFIXTURE_DISPOSABLE_GUEST",
            PURPOSE="linux-public-install-polkit-auth",
            prepare=mock.Mock(return_value={"account": "vpnfixture", "correlation": "correlation-157",
                                            "purpose": "linux-public-install-polkit-auth"}),
            status=mock.Mock(return_value={"account": "vpnfixture", "correlation": "correlation-157",
                                           "purpose": "linux-public-install-polkit-auth"}),
        )
        from test_linux_public_install import prepare_retained_fixture_auth
        with tempfile.TemporaryDirectory(prefix="vpn-retained-opt-in-") as temporary, \
             mock.patch.dict(sys.modules, {"linux_fixture_auth": auth}):
            credential, correlation, account, purpose = prepare_retained_fixture_auth(
                Path(temporary), "correlation-157", preserve_existing_password=True)
        self.assertEqual(Path(temporary) / "private-fixture-auth", credential)
        self.assertEqual(("correlation-157", "vpnfixture", "linux-public-install-polkit-auth"),
                         (correlation, account, purpose))
        self.assertIs(auth.prepare.call_args.kwargs["preserve_existing_password"], True)
        self.assertEqual(auth.prepare.call_args.kwargs["guest_confirmation"], auth.OWNED_GUEST_CONFIRMATION)

    def test_retained_driver_rejects_wrong_credential_purpose_before_launch_or_write(self):
        auth = types.SimpleNamespace(status=mock.Mock(side_effect=RuntimeError("purpose rejected")),
                                     read_credential_after_prompt=mock.Mock())
        with tempfile.TemporaryDirectory(prefix="vpn-retained-purpose-") as temporary:
            root = Path(temporary)
            with mock.patch.dict(sys.modules, {"linux_fixture_auth": auth}), \
                 mock.patch("test_linux_public_install.launch_with_controlling_tty") as launch:
                with self.assertRaisesRegex(RuntimeError, "purpose rejected"):
                    invoke_retained_install(Path("/not-started"), root / "workspace", {},
                                            ("--timeout-seconds", "240", "updates", "install"),
                                            root / "credential", "correlation-156", "wrong-purpose", "vpnfixture", root)
            launch.assert_not_called()
            auth.read_credential_after_prompt.assert_not_called()

    def test_complete_handoff_survives_terminal_close_race(self):
        job = "b32f0d40-f03f-4af7-8219-808753e05ee8"
        operation = "e0a17c7e-b47c-486e-944c-274e3343e883"
        observed = {"childExit": 0, "observationLost": True, "observationErrno": 5,
                    "envelope": {"code": "ACCEPTED", "final": False,
                                 "operationId": operation,
                                 "data": {"jobId": job, "handoffReady": True}}}
        self.assertEqual((job, operation), terminal_install_handoff(observed))
        with self.assertRaisesRegex(RuntimeError, "not proven"):
            terminal_install_handoff({**observed, "childExit": None})
        with self.assertRaisesRegex(RuntimeError, "not proven"):
            terminal_install_handoff({**observed, "envelope": None})

    def test_terminal_password_admission_rejects_diagnostics_and_waits_for_fragmented_ansi_prompt(self):
        # This is the checkpoint79 causal vector: the old ignored driver used
        # `b"password" in data.lower()`, which admitted a JVM trust-store
        # diagnostic before polkit had displayed a prompt.
        received = b"Picked up JAVA_TOOL_OPTIONS: -Djavax.net.ssl.trustStorePassword=fixture\n"
        self.assertFalse(terminal_password_prompt_seen(received))
        self.assertFalse(terminal_password_prompt_seen(received + b"Password: diagnostic text\n"))
        self.assertFalse(terminal_password_prompt_seen(received + b"\x1b[1;31mPass"))
        self.assertTrue(terminal_password_prompt_seen(received + b"\x1b[1;31mPassword: "))

    def test_terminal_identity_selector_chooses_only_the_exact_authorized_fixture_account(self):
        # CP139 stopped at this selector, before polkit displayed Password. The
        # old driver only recognized Password and therefore timed out without
        # sending a selector choice. This response is not a credential.
        selector = (b"\x1b[1;31m==== AUTHENTICATING FOR org.freedesktop.policykit.exec ====\r\n"
                    b"\x1b[0mMultiple identities can be used for authentication:\r\n"
                    b" 1.  vpnfixture\r\n 2.  vpnpolkit137\r\n"
                    b"Choose identity to authenticate as (1-2): ")
        # Causal RED replay: this was the complete decision in the retained
        # driver. It could answer only after Password, so it sent no input at
        # the selector and the native request became OUTCOME_UNKNOWN.
        password_only_would_answer = terminal_password_prompt_seen(selector)
        self.assertFalse(terminal_password_prompt_seen(selector))
        self.assertFalse(password_only_would_answer)
        # GREEN: select only the explicitly authorized fixture account; the
        # actual password remains subject to its separate echo-disable gate.
        self.assertEqual(b"2", terminal_authorized_identity_choice(selector, "vpnpolkit137"))
        self.assertEqual(b"1", terminal_authorized_identity_choice(selector, "vpnfixture"))
        self.assertIsNone(terminal_authorized_identity_choice(selector, "unrelated"))
        self.assertIsNone(terminal_authorized_identity_choice(selector + b"Password: ", "vpnpolkit137"))
        self.assertIsNone(terminal_authorized_identity_choice(
            selector.replace(b" 2.  vpnpolkit137", b" 3.  vpnpolkit137"), "vpnpolkit137"))
        self.assertIsNone(terminal_authorized_identity_choice(
            selector.replace(b"vpnpolkit137", b"vpnpolkit137\r\n 3.  vpnpolkit137"), "vpnpolkit137"))

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

    def test_rpm_recovery_uses_its_typed_fixture_verifier_before_owner_startup(self):
        linux = types.SimpleNamespace(uname=lambda: types.SimpleNamespace(sysname="Linux"), getuid=lambda: 1000)
        with mock.patch("test_linux_public_install.os", linux), \
             mock.patch("builtins.open", return_value=io.BytesIO()), \
             mock.patch("test_linux_public_install.verify_arch_bundle_base",
                        side_effect=AssertionError("Arch verifier must not run")) as arch, \
             mock.patch("test_linux_public_install.verify_rpm_bundle_base",
                        side_effect=RuntimeError("RPM verification reached")) as rpm:
            with self.assertRaisesRegex(RuntimeError, "RPM verification reached"):
                run(Path("/opt/vpn-control/bin/vpn-control"), "2.1.17", True,
                    same_source_recovery=True, rpm_source_fixture=Path("rpm-pair"))
        rpm.assert_called_once_with(Path("/opt/vpn-control/bin/vpn-control"), Path("rpm-pair"))
        arch.assert_not_called()

    def test_source_fixture_kinds_are_mutually_exclusive_before_any_verifier(self):
        linux = types.SimpleNamespace(uname=lambda: types.SimpleNamespace(sysname="Linux"), getuid=lambda: 1000)
        with mock.patch("test_linux_public_install.os", linux), \
             mock.patch("builtins.open", return_value=io.BytesIO()), \
             mock.patch("test_linux_public_install.verify_arch_bundle_base") as arch, \
             mock.patch("test_linux_public_install.verify_rpm_bundle_base") as rpm:
            with self.assertRaisesRegex(RuntimeError, "mutually exclusive"):
                run(Path("/opt/vpn-control/bin/vpn-control"), "2.1.17", True,
                    same_source_recovery=True, arch_source_fixture=Path("arch-pair"),
                    rpm_source_fixture=Path("rpm-pair"))
        arch.assert_not_called(); rpm.assert_not_called()

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

    def test_same_source_recovery_rejects_stale_marker_version_before_owner_or_update_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "opt/vpn-control"
            app = image / "lib/app"
            app.mkdir(parents=True)
            launcher = image / "bin/vpn-control"
            launcher.parent.mkdir()
            launcher.write_bytes(b"\x7fELFfixture-not-executed")
            launcher.chmod(0o755)
            installed_version = "2.1.11"
            main = app / "desktopApp-fixture.jar"
            with zipfile.ZipFile(main, "w") as jar:
                jar.writestr(MAIN_CLASS, b"fixture-main")
                jar.writestr(VERSION_RESOURCE, "displayVersion=" + installed_version + "\nbuildNumber=" +
                             str(version_build(installed_version)) + "\n")
            (app / "vpn-control.cfg").write_text("[Application]\napp.classpath=$APPDIR/" + main.name +
                                                   "\napp.mainclass=" + MAIN_CLASS.removesuffix(".class").replace("/", ".") + "\n")
            installed_identity = image_identity(image, installed_version)
            marker = image / "TEST-ONLY-INSTALL-FIXTURE.json"

            def write_marker(version):
                marker.write_text(json.dumps({
                    "testOnly": True, "productionTrustChanged": False, "sameSourceBuild": True,
                    "sourceFingerprint": "0" * 64, "version": version, **installed_identity,
                }))

            original_stat = Path.stat

            def root_owned(path, *args, **kwargs):
                info = original_stat(path, *args, **kwargs)
                return os.stat_result((info.st_mode & ~0o022, info.st_ino, info.st_dev, info.st_nlink, 0, info.st_gid,
                                       info.st_size, info.st_atime, info.st_mtime, info.st_ctime))

            original_open = open

            def open_tty(path, *args, **kwargs):
                return io.BytesIO() if path == "/dev/tty" else original_open(path, *args, **kwargs)

            with mock.patch("test_linux_public_install.os", types.SimpleNamespace()):
                common = dict(return_value=type("Unix", (), {"sysname": "Linux"})(), create=True)
                with mock.patch("test_linux_public_install.os.uname", **common), \
                     mock.patch("test_linux_public_install.os.getuid", return_value=1000, create=True), \
                     mock.patch("builtins.open", open_tty), \
                     mock.patch("test_linux_public_install.Path.stat", root_owned), \
                     mock.patch("test_linux_public_install.subprocess.Popen") as owner, \
                     mock.patch("test_linux_public_install.subprocess.run") as command:
                    # This models the retained 2.3.1 marker in a 2.1.11 packaged
                    # image. Admission must reject it before owner/process work.
                    write_marker("2.3.1")
                    with self.assertRaisesRegex(ValueError, "Packaged version resource disagrees with build"):
                        run(launcher, "2.1.12", True, same_source_recovery=True)
                    owner.assert_not_called()
                    command.assert_not_called()

                    # A repaired marker gets past identity validation and reaches
                    # the established package-ownership admission gate.
                    write_marker(installed_version)
                    command.side_effect = [
                        subprocess.CompletedProcess(["dpkg-query"], 1, "", "not owned"),
                        FileNotFoundError(), FileNotFoundError(),
                    ]
                    with self.assertRaisesRegex(RuntimeError, "owned by vpn-control package metadata"):
                        run(launcher, "2.1.12", True, same_source_recovery=True)
                    owner.assert_not_called()
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
