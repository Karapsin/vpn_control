from dataclasses import replace
from pathlib import Path
import subprocess
import os
import tempfile
import time
import unittest

from agent_tools import readiness as r
from agent_tools import readiness_providers as p


BOOT = "4e162a8b-e701-416b-8900-ec7ebf738d59"


class AdbEndpoint:
    """Finite ADB replies; production adapter assembles and dispatches every argv."""
    def __init__(self):
        self.calls = []
        self.name = "owned-task-avd"
        self.boot = BOOT
        self.user = "0"
        self.wake = "Awake"
        self.showing = "false"
        self.policy_user = "0"
        self.monitor_user = None
        self.overflow = False
        self.failed = False

    def __call__(self, argv, **options):
        self.calls.append(argv)
        assert argv[:7] == ["/fixed/adb", "-H", "127.0.0.1", "-P", "5038", "-s", "emulator-5660"]
        self.assert_options(options)
        args = tuple(argv[7:])
        if len(args) == 2 and args[0] == "shell" and args[1].startswith("set -o pipefail"):
            return subprocess.CompletedProcess(argv, 1 if self.failed else 0,
                                               ("  mWakefulness=" + self.wake + "\n").encode())
        replies = {
            ("emu", "avd", "name"): self.name + "\r\nOK\r\n",
            ("shell", "cat", "/proc/sys/kernel/random/boot_id"): self.boot + "\n",
            ("shell", "getprop", "sys.boot_completed"): "1\n",
            ("shell", "am", "get-current-user"): self.user + "\n",
            ("shell", "dumpsys", "power"): "  mWakefulness=" + self.wake + "\n",
            ("shell", "dumpsys", "window", "policy"): "    KeyguardServiceDelegate\n      showing=" + self.showing + "\n      currentUser=" + self.policy_user + "\n" +
                ("      systemIsReady=true\n      bootCompleted=true\n      KeyguardStateMonitor\n        mCurrentUserId="+self.monitor_user+"\n" if self.monitor_user is not None else ""),
        }
        if args == ("shell", "input", "keyevent", "224"):
            self.wake = "Awake"
            raw = b""
        else:
            raw = replies[args].encode()
        if self.overflow:
            raw = b"x" * 262145
        return subprocess.CompletedProcess(argv, 1 if self.failed else 0, raw)

    @staticmethod
    def assert_options(options):
        assert options["stdin"] == subprocess.DEVNULL
        assert options["stderr"] == subprocess.DEVNULL
        assert 0 < options["timeout"] <= 10
        assert options["check"] is False


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.binding = p.AndroidBinding("local-android", "owned-task-avd", Path("/fixed/adb"),
                                        "owned-task-avd", "emulator-5660", 5038)
        self.endpoint = AdbEndpoint()
        self.connection = "adb-server-pid-generation-1"
        self.adapter = p.android_adapter(self.binding, lambda: self.connection,
                                         wake_qualified=True, runner=self.endpoint)
        self.policy = r.Requirements(frozenset({"interactive_desktop"}), frozenset({"wake_display"}))

    def observe(self):
        return self.adapter.observe(self.policy, time.monotonic() + 20)

    def test_all_six_provider_lanes_are_inspectable_without_effects(self):
        self.assertEqual(set(p.PROVIDERS), {"android-emulator", "raw-qemu-windows", "raw-qemu-linux",
                                            "libvirt-windows", "tart-macos", "tart-linux"})
        for lane in p.PROVIDERS:
            adapter = p.ProviderAdapter(lane, "target", "machine")
            self.assertEqual(adapter.capabilities, frozenset())
            self.assertEqual(adapter.inspect()["blocker"], "provider_backend_unavailable")
            with self.assertRaisesRegex(r.AdapterBlocked, "provider_unavailable"):
                adapter.observe(r.Requirements(), time.monotonic() + 1)

    def test_tart_linux_cannot_admit_an_unsupported_resume_backend(self):
        class UnsupportedBackend:
            capabilities = frozenset({"resume"})
        with self.assertRaisesRegex(p.ProviderError, "provider_capability_invalid"):
            p.ProviderAdapter("tart-linux", "target", "machine", UnsupportedBackend())

    def test_healthy_android_observation_has_actual_boot_user_session_and_no_input(self):
        value = self.observe()
        self.assertEqual((value.boot, value.account, value.session), (BOOT, "android-user:0", BOOT + ":user:0"))
        self.assertEqual((value.guest, value.ordinary_session, value.display), ("running", "ready", "ready"))
        self.assertTrue(value.trusted and value.integrity and value.owned)
        self.assertFalse(any("input" in argv for argv in self.endpoint.calls))
        self.assertFalse(value.idle_visibility)  # ADB reachability cannot prove safe reboot.

    def test_boot_completed_before_actual_keyguard_user_waits_for_session_start(self):
        self.endpoint.policy_user = "-10000"
        self.endpoint.showing = "true"
        value = self.observe()
        self.assertEqual(value.guest, "booting")
        self.assertEqual(value.ordinary_session, "unknown")
        self.assertFalse(value.credential_available)

    def test_actual_keyguard_monitor_admits_user_despite_delegate_sentinel(self):
        self.endpoint.policy_user="-10000";self.endpoint.monitor_user="0"
        value=self.observe()
        self.assertEqual((value.guest,value.ordinary_session,value.account),("running","ready","android-user:0"))
        self.endpoint.monitor_user="1"
        with self.assertRaisesRegex(r.AdapterBlocked,"session_unrecognized"):
            self.observe()

    def test_background_work_never_inspects_or_unlocks_desktop(self):
        value = self.adapter.observe(r.Requirements(frozenset({"guest_agent"})), time.monotonic() + 20)
        self.assertEqual(value.ordinary_session, "unknown")
        self.assertFalse(any("dumpsys" in argv for argv in self.endpoint.calls))

    def test_dozing_sleep_locked_and_wrong_account_remain_distinct(self):
        self.endpoint.wake = "Dozing"
        self.assertEqual(self.observe().display, "sleeping")
        self.endpoint.showing = "true"
        value = self.observe()
        self.assertEqual(value.ordinary_session, "locked")
        self.assertFalse(value.credential_available)
        self.endpoint.user = "10"
        self.endpoint.policy_user = "10"
        self.assertEqual(self.observe().ordinary_session, "wrong_account")

    def test_unknown_power_or_keyguard_reply_does_not_become_ready(self):
        self.endpoint.wake = "malformed"
        self.endpoint.showing = "unrecognized"
        value = self.observe()
        self.assertEqual(value.display, "unrecognized")
        self.assertEqual(value.ordinary_session, "unknown")

    def test_wake_reobserves_identity_and_dispatches_exact_one_input(self):
        self.endpoint.wake = "Dozing"
        value = self.observe()
        self.adapter.recover("wake_display", "a" * 64, value, time.monotonic() + 20)
        self.assertEqual(sum("input" in argv for argv in self.endpoint.calls), 1)
        self.assertEqual(self.observe().display, "ready")

    def test_boot_or_connection_change_blocks_stale_gui_packet(self):
        self.endpoint.wake = "Dozing"
        value = self.observe()
        self.endpoint.boot = "5e162a8b-e701-416b-8900-ec7ebf738d59"
        with self.assertRaisesRegex(p.ProviderError, "android_input_identity_changed"):
            self.adapter.recover("wake_display", "a" * 64, value, time.monotonic() + 20)
        self.assertFalse(any("input" in argv for argv in self.endpoint.calls))

    def test_recover_attempt_falls_back_without_weakening_existing_admission(self):
        self.endpoint.wake = "Dozing"
        observed = self.observe()
        self.adapter.recover_attempt("wake_display", "a" * 64, observed, time.monotonic()+10, 1, "b" * 64)
        self.assertEqual(sum("input" in call for call in self.endpoint.calls), 1)
        with self.assertRaisesRegex(p.ProviderError, "provider_recovery_not_owned"):
            self.adapter.recover_attempt("wake_display", "a" * 64, replace(observed, owned=False), time.monotonic()+10, 1, "b" * 64)

    def test_only_exact_correlated_unsubmitted_proof_crosses_provider_hook(self):
        observed = self.observe()
        error = r.RecoveryUnsubmitted("a" * 64, 2, "b" * 64, "c" * 64)
        def hook(*args):
            raise error
        self.adapter.backend.recover_attempt = hook
        with self.assertRaises(r.RecoveryUnsubmitted) as raised:
            self.adapter.recover_attempt("wake_display", "a" * 64, observed, time.monotonic()+10, 2, "b" * 64)
        self.assertIs(raised.exception, error)
        with self.assertRaisesRegex(p.ProviderError, "provider_unsubmitted_proof_invalid"):
            self.adapter.recover_attempt("wake_display", "a" * 64, observed, time.monotonic()+10, 1, "b" * 64)
        error.extra = "unreviewed"
        with self.assertRaisesRegex(p.ProviderError, "provider_unsubmitted_proof_invalid"):
            self.adapter.recover_attempt("wake_display", "a" * 64, observed, time.monotonic()+10, 2, "b" * 64)

    def test_locked_or_unowned_state_never_sends_gui_input(self):
        self.endpoint.wake = "Dozing"
        self.endpoint.showing = "true"
        value = self.observe()
        with self.assertRaisesRegex(p.ProviderError, "android_input_state_changed"):
            self.adapter.recover("wake_display", "a" * 64, value, time.monotonic() + 20)
        with self.assertRaisesRegex(p.ProviderError, "provider_recovery_not_owned"):
            self.adapter.recover("wake_display", "a" * 64, replace(value, owned=False), time.monotonic() + 20)
        self.assertFalse(any("input" in argv for argv in self.endpoint.calls))

    def test_foreign_machine_and_overflow_fail_with_finite_reasons(self):
        self.endpoint.name = "foreign-avd"
        with self.assertRaisesRegex(r.AdapterBlocked, "^machine_identity_mismatch$"):
            self.observe()
        self.endpoint.overflow = True
        with self.assertRaisesRegex(r.AdapterBlocked, "^provider_unavailable$"):
            self.observe()

    def test_failed_adb_does_not_grant_vm_boot_authority(self):
        self.endpoint.failed = True
        with self.assertRaisesRegex(r.AdapterBlocked, "^guest_agent_unavailable$"):
            self.observe()
        self.assertNotIn("start", self.adapter.capabilities)
        self.assertNotIn("reboot", self.adapter.capabilities)

    def test_inactive_system_packageinstaller_does_not_block_idle(self):
        installers = ("Active install sessions:\n  \nFinalized install sessions:\n  \n"
                      "Historical install sessions:\n  \nLegacy install sessions:\n  {}\n"
                      "Gentle update with constraints info:\n  hasPendingIdleJob=false\n")
        visibility, blockers = p.android_guest_idle_facts("NAME\ninit\ncom.google.android.packageinstaller\n", installers)
        self.assertEqual(visibility, frozenset({"protected_processes", "installers"}))
        self.assertFalse(blockers)

    def test_active_installer_and_actual_runtime_block_idle(self):
        installers = ("Active install sessions:\n  Session123\nFinalized install sessions:\n"
                      "Historical install sessions:\nLegacy install sessions:\n{}\n"
                      "Gentle update with constraints info:\nhasPendingIdleJob=false\n")
        _, blockers = p.android_guest_idle_facts("NAME\nsing-box\n", installers)
        self.assertEqual(blockers, frozenset({"protected_processes", "installers"}))

    @unittest.skipUnless(os.name == "posix", "Android fixed-shell projection requires a POSIX shell")
    def test_large_power_history_is_projected_by_actual_generated_guest_shell(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            dumpsys = directory / "dumpsys"
            dumpsys.write_text("#!/bin/sh\nprintf '  mWakefulness=Awake\\n'\nhead -c 300000 /dev/zero | tr '\\000' x\nprintf '\\n'\n")
            dumpsys.chmod(0o700)
            endpoint = self.endpoint
            def run(argv, **options):
                args = argv[7:]
                environment = {**os.environ, "PATH": str(directory) + os.pathsep + os.environ.get("PATH", "")}
                if args == ["shell", "dumpsys", "power"]:
                    return subprocess.run([str(dumpsys), "power"], env=environment, **options)
                if len(args) == 2 and args[0] == "shell":
                    # Bash supplies the same pipefail grammar as Android mksh;
                    # the real device separately qualifies Android's shell.
                    # Force external printf to exercise Android's argv limit.
                    source = 'printf() { /usr/bin/printf "$@"; }; ' + args[1]
                    return subprocess.run(["/bin/bash", "-c", source], env=environment, **options)
                return endpoint(argv, **options)
            adapter = p.android_adapter(self.binding, lambda: self.connection, runner=run)
            observed = adapter.observe(self.policy, time.monotonic() + 20)
            self.assertEqual(observed.display, "ready")


if __name__ == "__main__":
    unittest.main()
