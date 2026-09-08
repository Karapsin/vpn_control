import unittest

from android_fixture_transport import (
    cleanup_fixture_transport,
    establish_fixture_transport,
    fixture_proxy,
    parse_reverse_inventory,
)


class FakeAdb:
    def __init__(self):
        self.reverse_mappings = {41000: 41001}
        self.proxy = "null"
        self.uid = "uid=0"
        self.calls = []
        self.fail_proxy = False
        self.fail_remove_once = False

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


class AndroidFixtureTransportTest(unittest.TestCase):
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
