import subprocess
import unittest

from android_fixture_transport import (
    adb_device_socks_greeting,
    cleanup_fixture_transport,
    establish_fixture_transport,
    establish_socks_fixture_transport,
    fixture_proxy,
    parse_reverse_inventory,
    verify_device_socks_greeting,
    verify_socks_validation_url,
)


class FakeSocksRunner:
    def __init__(self):
        self.command = None

    def __call__(self, command, **_kwargs):
        self.command = command
        return type("Result", (), {"returncode": 0, "stdout": b"\x05\x00"})()


class FakeAdb:
    def __init__(self):
        self.reverse_mappings = {41000: 41001}
        self.proxy = "null"
        self.uid = "uid=0"
        self.calls = []
        self.fail_proxy = False
        self.fail_remove_once = False
        self.socks_reply = b"\x05\x00"

    def reverse(self, device_port, host_port):
        self.calls.append(("reverse", device_port, host_port))
        self.reverse_mappings[device_port] = host_port

    def reverse_inventory(self):
        self.calls.append(("reverse_inventory",))
        return dict(self.reverse_mappings)

    def global_proxy(self):
        self.calls.append(("global_proxy",))
        return self.proxy

    def reverse_mapping(self, device_port):
        self.calls.append(("reverse_mapping", device_port))
        return self.reverse_mappings.get(device_port)

    def remove_reverse(self, device_port):
        self.calls.append(("remove_reverse", device_port))
        if self.fail_remove_once:
            self.fail_remove_once = False
            raise OSError("fixture removal interrupted")
        del self.reverse_mappings[device_port]

    def set_global_proxy(self, value):
        self.calls.append(("proxy", value))
        if self.fail_proxy:
            raise OSError("proxy restoration interrupted")
        self.proxy = value

    def unroot(self):
        self.calls.append(("unroot",))
        self.uid = "uid=2000"
        self.reverse_mappings.clear()

    def wait_for_device(self):
        self.calls.append(("wait",))

    def shell_id(self):
        self.calls.append(("id",))
        return self.uid

    def socks_greeting(self, device_port):
        self.calls.append(("socks_greeting", device_port))
        return self.socks_reply


class AndroidFixtureTransportTest(unittest.TestCase):
    validation_user_agent = "VPN Control fixture test/1"

    def test_socks_validation_requires_accepted_https_status_over_proxy_dns(self):
        captured = {}
        def runner(command, **_kwargs):
            captured["command"] = command
            return type("Result", (), {"returncode": 0, "stdout": "301"})()
        self.assertEqual("301", verify_socks_validation_url(
            "https://validation.example.test/trace?opaque=fixture", 59023, user_agent=self.validation_user_agent, command_runner=runner,
        ))
        command = captured["command"]
        self.assertIn("socks5h://127.0.0.1:59023", command)
        self.assertIn("https://validation.example.test/trace?opaque=fixture", command)
        self.assertIn(self.validation_user_agent, command)
        self.assertIn("--noproxy", command)
        self.assertEqual("", command[command.index("--noproxy") + 1])
        self.assertNotIn("--insecure", command)

    def test_socks_validation_rejects_non_success_status_without_exposing_url(self):
        def runner(_command, **_kwargs):
            return type("Result", (), {"returncode": 0, "stdout": "451"})()
        with self.assertRaisesRegex(RuntimeError, "status") as raised:
            verify_socks_validation_url("https://validation.example.test/", 59023, user_agent=self.validation_user_agent, command_runner=runner)
        self.assertNotIn("validation.example", str(raised.exception))

    def test_socks_validation_rejects_timeout_and_malformed_status(self):
        def timeout(_command, **_kwargs):
            raise subprocess.TimeoutExpired("curl", 10)
        with self.assertRaisesRegex(TimeoutError, "timed out"):
            verify_socks_validation_url("https://validation.example.test/", 59023, user_agent=self.validation_user_agent, command_runner=timeout)
        def malformed(_command, **_kwargs):
            return type("Result", (), {"returncode": 0, "stdout": "200\nextra"})()
        with self.assertRaisesRegex(RuntimeError, "invalid status"):
            verify_socks_validation_url("https://validation.example.test/", 59023, user_agent=self.validation_user_agent, command_runner=malformed)
    def test_adb_socks_greeting_keeps_device_input_open_until_reply_can_arrive(self):
        runner = FakeSocksRunner()
        reply = adb_device_socks_greeting(["adb", "-s", "emulator-5584"], 45384,
                                          command_runner=runner)
        self.assertEqual(b"\x05\x00", reply)
        self.assertIn("toybox printf '\\005\\001\\000'; toybox sleep 1", runner.command[-1])
        self.assertIn("toybox nc -w 2 -W 2 127.0.0.1 45384", runner.command[-1])

    def test_adb_socks_greeting_maps_bounded_command_timeout(self):
        def timeout(*_args, **_kwargs):
            raise subprocess.TimeoutExpired("adb", 6)
        with self.assertRaisesRegex(TimeoutError, "timed out"):
            adb_device_socks_greeting(["adb"], 45384, command_runner=timeout)
    def test_reverse_inventory_accepts_blank_and_captured_serial_prefixed_record(self):
        self.assertEqual({}, parse_reverse_inventory("\n \t\n"))
        self.assertEqual({45384: 61408}, parse_reverse_inventory("tcp:45384 tcp:61408\n"))
        self.assertEqual(
            {45385: 61409},
            parse_reverse_inventory("host-20 tcp:45385 tcp:61409\n\n"),
        )

    def test_reverse_inventory_rejects_malformed_or_foreign_records(self):
        malformed = (
            "tcp:45385\n",
            "host-20 tcp:45385 tcp:61409 extra\n",
            "localabstract:fixture tcp:45385\n",
            "host-20 localabstract:fixture tcp:61409\n",
            "tcp:0 tcp:61409\n",
            "tcp:45385 tcp:not-a-port\n",
        )
        for raw in malformed:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_reverse_inventory(raw)

    def test_reverse_inventory_rejects_duplicate_device_route(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            parse_reverse_inventory("tcp:45385 tcp:61409\nhost-20 tcp:45385 tcp:61410\n")

    def test_restart_preserves_proxy_but_recreates_fixture_reverse_after_public_identity(self):
        adb = FakeAdb()
        adb.reverse_mappings.clear()
        establish_fixture_transport(adb, 45384, 56706)
        self.assertEqual(fixture_proxy(45384), adb.proxy)
        self.assertEqual(56706, adb.reverse_mappings[45384])
        self.assertEqual([("id",), ("reverse_inventory",), ("unroot",), ("wait",), ("id",),
                          ("reverse_mapping", 45384), ("reverse", 45384, 56706),
                          ("proxy", "127.0.0.1:45384")], adb.calls)

    def test_socks_establish_does_not_certify_reverse_list_only_when_device_socks_greeting_is_eof(self):
        adb = FakeAdb()
        adb.reverse_mappings.clear()
        adb.socks_reply = b""
        with self.assertRaisesRegex(RuntimeError, "closed before replying"):
            establish_socks_fixture_transport(adb, 45384, 56706)
        self.assertEqual("null", adb.proxy)
        self.assertEqual(56706, adb.reverse_mappings[45384])

    def test_socks_establish_checks_device_greeting_after_reverse(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        establish_socks_fixture_transport(adb, 45384, 56706)
        self.assertLess(
            adb.calls.index(("reverse", 45384, 56706)),
            adb.calls.index(("socks_greeting", 45384)),
        )

    def test_socks_establish_never_sets_an_http_proxy(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        establish_socks_fixture_transport(adb, 45384, 56706)
        self.assertEqual("null", adb.proxy)
        self.assertNotIn(("proxy", "127.0.0.1:45384"), adb.calls)

    def test_device_socks_greeting_rejects_timeout_partial_and_rejected_reply(self):
        cases = (
            (TimeoutError("late"), "timed out"),
            (EOFError("closed"), "closed before replying"),
            (b"\x05", "partial"),
            (b"\x05\xff", "rejected"),
            ("\x05\x00", "invalid bytes"),
        )
        for reply, reason in cases:
            with self.subTest(reply=type(reply).__name__):
                adb = FakeAdb()
                if isinstance(reply, BaseException):
                    def greeting(_port, error=reply):
                        raise error
                    adb.socks_greeting = greeting
                else:
                    adb.socks_reply = reply
                with self.assertRaisesRegex(RuntimeError, reason):
                    verify_device_socks_greeting(adb, 45384)

    def test_device_socks_greeting_accepts_exact_no_auth_reply(self):
        adb = FakeAdb()
        verify_device_socks_greeting(adb, 45384)
        self.assertEqual([("socks_greeting", 45384)], adb.calls)

    def test_nonpublic_adbd_never_receives_route_or_proxy(self):
        adb = FakeAdb()
        adb.reverse_mappings.clear()
        adb.unroot = lambda: adb.calls.append(("unroot",))
        with self.assertRaisesRegex(RuntimeError, "public adbd"):
            establish_fixture_transport(adb, 45384, 56706)
        self.assertNotIn(45384, adb.reverse_mappings)
        self.assertEqual("null", adb.proxy)

    def test_cleanup_restores_proxy_and_keeps_unrelated_reverse_mapping(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        establish_fixture_transport(adb, 45384, 56706)
        adb.reverse_mappings[41000] = 41001
        cleanup_fixture_transport(adb, 45384, 56706, "null")
        self.assertNotIn(45384, adb.reverse_mappings)
        self.assertEqual({41000: 41001}, adb.reverse_mappings)
        self.assertEqual("null", adb.proxy)

    def test_cleanup_refuses_changed_or_missing_fixture_mapping_without_proxy_mutation(self):
        for mapping in (None, 9999):
            with self.subTest(mapping=mapping):
                adb = FakeAdb()
                adb.uid = "uid=2000"
                if mapping is not None:
                    adb.reverse_mappings[45384] = mapping
                before = dict(adb.reverse_mappings)
                with self.assertRaisesRegex(RuntimeError, "ownership changed"):
                    cleanup_fixture_transport(adb, 45384, 56706, "null")
                self.assertEqual(before, adb.reverse_mappings)
                self.assertEqual("null", adb.proxy)

    def test_cleanup_rejects_nonpublic_identity_and_invalid_values(self):
        adb = FakeAdb()
        with self.assertRaisesRegex(RuntimeError, "public adbd"):
            cleanup_fixture_transport(adb, 45384, 56706, "null")
        self.assertEqual({41000: 41001}, adb.reverse_mappings)
        for device_port, host_port in ((True, 56706), (45384, 0)):
            with self.subTest(device_port=device_port, host_port=host_port), self.assertRaises(ValueError):
                establish_fixture_transport(adb, device_port, host_port)
        with self.assertRaises(ValueError):
            cleanup_fixture_transport(adb, 45384, 56706, None)

    def test_rooted_restart_refuses_unrelated_reverse_mapping_before_unroot(self):
        adb = FakeAdb()
        with self.assertRaisesRegex(RuntimeError, "restart would clear"):
            establish_fixture_transport(adb, 45384, 56706)
        self.assertNotIn(("unroot",), adb.calls)
        self.assertEqual({41000: 41001}, adb.reverse_mappings)

    def test_public_adbd_preserves_unrelated_mapping_without_restart(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        establish_fixture_transport(adb, 45384, 56706)
        self.assertNotIn(("unroot",), adb.calls)
        self.assertEqual(41001, adb.reverse_mappings[41000])
        self.assertEqual(56706, adb.reverse_mappings[45384])

    def test_existing_fixture_target_route_is_never_replaced(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        adb.reverse_mappings[45384] = 9999
        with self.assertRaisesRegex(RuntimeError, "target route already exists"):
            establish_fixture_transport(adb, 45384, 56706)
        self.assertEqual(9999, adb.reverse_mappings[45384])
        self.assertEqual("null", adb.proxy)

    def test_cleanup_refuses_proxy_changed_by_another_owner(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        adb.reverse_mappings[45384] = 56706
        adb.proxy = "127.0.0.1:49999"
        with self.assertRaisesRegex(RuntimeError, "proxy ownership changed"):
            cleanup_fixture_transport(adb, 45384, 56706, "null")
        self.assertEqual(56706, adb.reverse_mappings[45384])
        self.assertEqual("127.0.0.1:49999", adb.proxy)

    def test_cleanup_restores_proxy_before_removing_route_and_can_retry_remove(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        adb.reverse_mappings[45384] = 56706
        adb.proxy = fixture_proxy(45384)
        adb.fail_remove_once = True
        with self.assertRaisesRegex(OSError, "removal interrupted"):
            cleanup_fixture_transport(adb, 45384, 56706, "null")
        self.assertEqual("null", adb.proxy)
        self.assertEqual(56706, adb.reverse_mappings[45384])
        cleanup_fixture_transport(adb, 45384, 56706, "null")
        self.assertNotIn(45384, adb.reverse_mappings)

    def test_cleanup_proxy_restore_failure_keeps_route_available(self):
        adb = FakeAdb()
        adb.uid = "uid=2000"
        adb.reverse_mappings[45384] = 56706
        adb.proxy = fixture_proxy(45384)
        adb.fail_proxy = True
        with self.assertRaisesRegex(OSError, "proxy restoration interrupted"):
            cleanup_fixture_transport(adb, 45384, 56706, "null")
        self.assertEqual(56706, adb.reverse_mappings[45384])
        self.assertEqual(fixture_proxy(45384), adb.proxy)


if __name__ == "__main__":
    unittest.main()
