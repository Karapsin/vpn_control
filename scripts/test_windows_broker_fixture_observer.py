#!/usr/bin/env python3
"""Causal broker-observer regressions; native cases use only inert processes."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import windows_broker_fixture_observer as observer


class Pin:
    def __init__(self, pid, creation, digest, elevated=0):
        self.record = {"pid": pid, "creationFileTime": creation, "image": f"C:\\fixture\\{pid}.exe",
                       "sha256": digest, "token": {"sid": "S-1-5-21-1001", "elevated": elevated}}
        self.calls = []
        self.wait_result = 258
        self.image_error = None
        self.close_error = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.calls.append("close")
        self.closed = True
        if self.close_error:
            raise self.close_error

    def times(self):
        self.calls.append("times")
        return {"creationFileTime": self.record["creationFileTime"], "exitFileTime": 0}

    def wait(self):
        self.calls.append("wait")
        return self.wait_result

    def describe(self):
        self.calls.append("image")
        if self.image_error:
            raise self.image_error
        return copy.deepcopy(self.record)

    def modules(self):
        return [{"base": 123, "path": "C:\\Windows\\System32\\kernel32.dll"}]


class NativeFixture:
    def __init__(self):
        self.pins = {10: Pin(10, 100, "1" * 64), 20: Pin(20, 200, "2" * 64, 1),
                     30: Pin(30, 300, "3" * 64, 1), 40: Pin(40, 400, "4" * 64, 1)}

    def open_process(self, pid, _access):
        value = self.pins[pid]
        if isinstance(value, Exception):
            raise value
        return value

    def processes(self):
        # The extra helper child was conhost.exe in the captured Windows failure.
        return [{"pid": 30, "parentPid": 20, "name": "sing-box.exe"},
                {"pid": 40, "parentPid": 20, "name": "conhost.exe"}]

    def file_identity(self, path):
        for pin in self.pins.values():
            if isinstance(pin, Pin) and pin.record["image"] == path:
                return {"sha256": pin.record["sha256"], "sizeBytes": 1}
        return {"sha256": "5" * 64, "sizeBytes": 2}

    def threads(self, _pid):
        return [{"tid": 100, "suspendCount": 1}]

    def request(self):
        def identity(pid):
            result = copy.deepcopy(self.pins[pid].record)
            result["sid"] = result.pop("token")["sid"]
            return result
        return {"operation": "ready", "owner": identity(10), "helper": identity(20), "runtime": identity(30)}


class WindowsBrokerFixtureObserverTest(unittest.TestCase):
    def test_ready_consumer_preserves_auxiliary_child_and_selects_exact_runtime(self):
        native = NativeFixture()
        result = observer.observe_ready(native.request(), native)
        self.assertEqual(30, result["runtime"]["pid"])
        self.assertEqual([40], [item["pid"] for item in result["auxiliaryChildren"]])
        self.assertTrue(all(pin.closed for pin in native.pins.values()))

    def test_runtime_name_is_not_identity_authority(self):
        native = NativeFixture()
        native.processes = lambda: [{"pid": 30, "parentPid": 20, "name": "different-name.exe"},
                                   {"pid": 40, "parentPid": 20, "name": "sing-box.exe"}]
        self.assertEqual(30, observer.observe_ready(native.request(), native)["runtime"]["pid"])

    def test_wrong_generation_or_digest_fails_and_closes_all_pins(self):
        for key, value in [("creationFileTime", 301), ("sha256", "0" * 64)]:
            with self.subTest(key=key):
                native = NativeFixture()
                request = native.request()
                request["runtime"][key] = value
                with self.assertRaises(ValueError):
                    observer.observe_ready(request, native)
                self.assertTrue(all(pin.closed for pin in native.pins.values()))

    def test_missing_or_duplicate_runtime_rejected(self):
        child = {"pid": 30, "creationFileTime": 300, "sha256": "3" * 64}
        for children in [[], [child, child]]:
            with self.assertRaises(ValueError):
                observer.select_runtime(children, child)

    def test_foreign_helper_token_is_rejected(self):
        native = NativeFixture()
        request = native.request()
        native.pins[20].record["token"]["sid"] = "S-1-5-18"
        with self.assertRaises(ValueError):
            observer.observe_ready(request, native)
        self.assertTrue(native.pins[10].closed and native.pins[20].closed)

    def test_close_failure_does_not_return_ready(self):
        native = NativeFixture()
        native.pins[30].close_error = OSError("Close failed")
        with self.assertRaises(OSError):
            observer.observe_ready(native.request(), native)
        self.assertTrue(all(pin.closed for pin in native.pins.values()))

    def test_exited_same_handle_is_checked_before_unavailable_image(self):
        native = NativeFixture()
        process = native.pins[30]
        process.wait_result = 0
        process.image_error = OSError(31, "Image unavailable after exit")
        result = observer.observe_exit([{"pid": 30, "creationFileTime": 300}], native)
        self.assertTrue(result[0]["originalAbsent"])
        self.assertEqual(["times", "wait", "close"], process.calls)

    def test_reused_pid_does_not_query_or_change_the_new_process(self):
        native = NativeFixture()
        process = native.pins[30]
        process.image_error = OSError(31, "New generation image is not ours")
        result = observer.observe_exit([{"pid": 30, "creationFileTime": 299}], native)
        self.assertTrue(result[0]["originalAbsent"])
        self.assertEqual(["times", "close"], process.calls)

    def test_live_same_generation_image_failure_remains_unknown(self):
        native = NativeFixture()
        native.pins[30].image_error = OSError(31, "No image information")
        result = observer.observe_exit([{"pid": 30, "creationFileTime": 300}], native)
        self.assertIsNone(result[0]["originalAbsent"])

    def test_wait_failure_remains_unknown_without_querying_image(self):
        native = NativeFixture()
        process = native.pins[30]
        process.wait_result = 0xffffffff
        result = observer.observe_exit([{"pid": 30, "creationFileTime": 300}], native)
        self.assertIsNone(result[0]["originalAbsent"])
        self.assertNotIn("image", process.calls)

    def test_open_failure_is_distinct_from_an_absent_process(self):
        native = NativeFixture()
        for failure, expected in [(PermissionError("Access denied"), None),
                                  (observer.ProcessAbsent("Native OpenProcess error87"), True)]:
            native.pins[30] = failure
            self.assertIs(expected, observer.observe_exit([{"pid": 30, "creationFileTime": 300}], native)[0]["originalAbsent"])

    def test_exit_close_failure_keeps_outcome_unknown(self):
        native = NativeFixture()
        native.pins[30].wait_result = 0
        native.pins[30].close_error = OSError("Close failed")
        self.assertIsNone(observer.observe_exit([{"pid": 30, "creationFileTime": 300}], native)[0]["originalAbsent"])

    def test_live_matching_identity_is_reported_live(self):
        result = observer.observe_exit([{"pid": 30, "creationFileTime": 300}], NativeFixture())
        self.assertFalse(result[0]["originalAbsent"])
        self.assertEqual(300, result[0]["actual"]["creationFileTime"])

    def test_request_rejects_missing_generation_and_mutating_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "request.json"
            for request in [{"operation": "terminate", "processes": [{"pid": 30, "creationFileTime": 300}]},
                            {"operation": "exit", "processes": [{"pid": 30, "creationFileTime": 0}]},
                            {"operation": "exit", "processes": []}]:
                path.write_text(json.dumps(request), encoding="utf-8")
                with self.assertRaises(ValueError):
                    observer.read_request(path)

    @unittest.skipUnless(sys.platform == "win32", "Native Windows process handles")
    def test_native_self_image_token_and_module_queries(self):
        native = observer.WindowsNative()
        with native.open_process(os.getpid(), 0x101410) as process:
            details = process.describe()
            self.assertGreater(details["creationFileTime"], 0)
            self.assertTrue(observer.same_path(details["image"], sys.executable))
            self.assertTrue(details["token"]["sid"].startswith("S-1-"))
            self.assertEqual(258, process.wait())
            self.assertTrue(process.modules())

    @unittest.skipUnless(sys.platform == "win32", "Native Windows process handles")
    def test_native_exited_child_uses_the_retained_signaled_handle(self):
        child = subprocess.Popen([sys.executable, "-c", "import sys;print('READY',flush=True);sys.stdin.buffer.read(1)"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(b"READY\r\n", child.stdout.readline())
            native = observer.WindowsNative()
            with native.open_process(child.pid, 0x101000) as process:
                creation = process.times()["creationFileTime"]
                child.communicate(input=b"x", timeout=5)
                self.assertEqual(0, child.returncode)
                def must_not_query_image():
                    self.fail("Image query ran despite the native retained exit signal")
                result = observer.classify_retained_process(creation, process.times, process.wait, must_not_query_image)
                self.assertTrue(result["originalAbsent"])
                self.assertEqual("same-handle-signaled", result["reason"])
        finally:
            if child.poll() is None:
                child.communicate(input=b"x", timeout=5)


if __name__ == "__main__":
    unittest.main()
