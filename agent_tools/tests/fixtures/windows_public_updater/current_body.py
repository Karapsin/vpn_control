"""Portable behavior controls for private Windows updater preparation.

No Windows, native process, socket, TLS trust, package install or external network
is used. The declared native peer supplies identity observations only. These
checks do not establish real UAC/NTFS/MSI or current installed-package acceptance.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = _canonical_root / 'agent_tools/windows_public_updater'


def module(name):
    return _load_source(ROOT / (name + '.py'))


r = module("update_receipts")
s = module("update_fixture_server")
c = module("update_cases")
n = module("native_collector")
JOB = "b45bc58a-ed79-41c0-b0d0-1f6d9c890892"
OP = "7d705688-613b-4e4c-a43e-74ae5b77063a"
SID = "S-1-5-21-1-2-3-1001"
ADMIN = "S-1-5-21-1-2-3-1000"
SHA = "a" * 64


def raw(seq=0, phase="Preparing", code="OK", job=JOB):
    return ('{"version":1,"jobId":"' + job + '","sequence":' + str(seq)
            + ',"phase":"' + phase + '","code":"' + code + '"}').encode()


def accepted():
    return {"schemaVersion": 1, "ok": True, "code": "ACCEPTED", "final": False,
        "controllerId": "original", "requestId": "request-1", "operationId": OP,
        "data": {"handoffReady": True, "jobId": JOB}}


class ReceiptTests(unittest.TestCase):
    def test_actual_native_wire_spelling_and_skipped_phases(self):
        tracker = r.ReceiptTracker(JOB)
        self.assertEqual("PREPARING", tracker.accept(raw())["phase"])
        self.assertEqual("WAITING_FOR_EXIT", tracker.accept(raw(2, "WaitingForExit"))["phase"])
        self.assertEqual("SUCCEEDED", tracker.accept(raw(4, "Succeeded"))["phase"])
        self.assertEqual("SUCCEEDED", tracker.accept(raw(4, "Succeeded"))["phase"])

    def test_same_sequence_change_and_regression_refused(self):
        tracker = r.ReceiptTracker(JOB)
        tracker.accept(raw(2, "WaitingForExit"))
        for value in (raw(2, "Installing"), raw(3, "Authorized"), raw(1, "Preparing")):
            with self.subTest(value=value), self.assertRaises(r.Refused):
                tracker.accept(value)

    def test_terminal_change_refused(self):
        tracker = r.ReceiptTracker(JOB)
        tracker.accept(raw(4, "Succeeded"))
        with self.assertRaises(r.Refused):
            tracker.accept(raw(5, "Failed", "RUNTIME_FAILED"))

    def test_extra_duplicate_malformed_or_foreign_records_refused(self):
        values = [raw() + b"\n", raw().replace(b'"version":1', b'"version":1,"version":1'),
            raw(code="CANCELLED"), raw(phase="Fake"), raw(job=OP), raw(seq=2**63)]
        for value in values:
            with self.subTest(value=value), self.assertRaises(r.Refused):
                r.receipt(value, JOB)

    def test_cancelled_and_failed_are_distinct_authoritative_terminals(self):
        self.assertEqual("CANCELLED", r.receipt(raw(1, "Cancelled", "CANCELLED"), JOB)["phase"])
        self.assertEqual("BUSY", r.receipt(raw(2, "Failed", "BUSY"), JOB)["code"])
        with self.assertRaises(r.Refused):
            r.receipt(raw(1, "Cancelled", "OK"), JOB)

    def test_handoff_requires_exit_streams_ready_and_original_identity(self):
        value = accepted()
        good = subprocess.CompletedProcess([], 0, json.dumps(value), "")
        self.assertEqual(value, r.handoff(good, "original"))
        for result in (subprocess.CompletedProcess([], 2, good.stdout, ""),
                       subprocess.CompletedProcess([], 0, good.stdout, "warning"),
                       subprocess.CompletedProcess([], 0, json.dumps({**value, "data": {"jobId": JOB}}), "")):
            with self.subTest(result=result), self.assertRaises(r.Refused):
                r.handoff(result, "original")
        with self.assertRaises(r.Refused):
            r.handoff(good, "different")

    def test_recovery_requires_exact_origin_and_new_owner(self):
        value = {"schemaVersion": 1, "ok": True, "code": "OK", "final": True,
            "controllerId": "new", "operationId": OP,
            "data": {"jobId": JOB, "originControllerId": "original", "originRequestId": "request-1"}}
        terminal = r.receipt(raw(4, "Succeeded"), JOB)
        self.assertEqual(OP, r.verify_recovery(accepted(), terminal, value)["operationId"])
        for changed in ({**value, "controllerId": "original"}, {**value, "operationId": JOB},
                        {**value, "data": {**value["data"], "originRequestId": "other"}}):
            with self.assertRaises(r.Refused):
                r.verify_recovery(accepted(), terminal, changed)


class MachinePolicyTests(unittest.TestCase):
    def security(self, extra="", owner="S-1-5-32-544"):
        return {"ownerSid": owner, "sddl": "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)" + extra}

    def test_machine_status_readers_allowed(self):
        self.assertTrue(r.machine_security(self.security(), False))
        self.assertTrue(r.machine_security({"ownerSid": "S-1-5-32-544", "sddl":
            "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"}, True))

    def test_ordinary_write_delete_dacl_and_owner_changes_refused(self):
        for rights in ("GW", "GA", "FA", "WD", "WO", "SD", "0x2", "0x100"):
            with self.subTest(rights=rights), self.assertRaises(r.Refused):
                r.machine_security(self.security("(A;;" + rights + ";;;" + SID + ")"), False)
        with self.assertRaises(r.Refused):
            r.machine_security(self.security(owner=SID), False)

    def test_unprotected_dacl_object_aces_and_extra_sections_refused(self):
        for text in ("O:BAD:(A;;FA;;;BA)", "O:BAD:P(OA;;GR;;;BU)",
                     "O:BAD:P(A;;GR;;;BU)S:(AU;SA;FA;;;BU)"):
            with self.subTest(text=text), self.assertRaises(r.Refused):
                r.machine_security({"ownerSid": "S-1-5-32-544", "sddl": text}, False)


class Pin:
    def __init__(self, native, record, directory=False):
        self.record, self.path, self.directory = record, PureWindowsPath(record["path"]), directory
        self.native, self.handle, self.fail_native_close = native, id(self), False
        self.current_count = self.digest_count = self.close_count = 0
        self.fail_close = False
    def current(self):
        self.current_count += 1
    def digest(self):
        self.digest_count += 1
    def close(self):
        self.close_count += 1
        if self.fail_close:
            raise OSError("declared close peer failure")
        self.native.k.CloseHandle(self.handle)


class Parked(Exception):
    pass


class Owned:
    def __init__(self, root):
        self.root, self.events = Path(root), []
        owner = self
        class ClosePeer:
            def __call__(self, handle):
                value = getattr(handle, "value", handle)
                selected = next(p for p in owner.pins if p.handle == value)
                selected.close_count += 1
                return not selected.fail_native_close and not selected.fail_close
        self.native = types.SimpleNamespace(k=types.SimpleNamespace(CloseHandle=ClosePeer()))
        self.app_root = r"C:\Users\fixture\AppData\Local\VPN Control"
        self.base = {"vpn-control-cli.exe": {"sizeBytes": 3, "sha256": SHA},
                     "app/main.jar": {"sizeBytes": 4, "sha256": "b" * 64}}
        records = [{"path": str(PureWindowsPath(self.app_root) / PureWindowsPath(name)),
                    "nativeIdentity": {"sizeBytes": item["sizeBytes"]}, "sha256": item["sha256"], "security": {}}
                   for name, item in self.base.items()]
        source = {"path": r"C:\Fixture\worker.py", "nativeIdentity": {"sizeBytes": 20}, "sha256": "c" * 64, "security": {}}
        directory = {"path": self.app_root, "nativeIdentity": {}, "security": {}}
        python = {"path": r"C:\Fixture\Python\python.exe", "nativeIdentity": {"sizeBytes": 30}, "sha256": "d" * 64, "security": {}}
        self.pins = [Pin(self.native, x) for x in [source, python, *records]] + [Pin(self.native, directory, True)]
        self.by_path = {str(p.path).casefold(): p for p in self.pins if not p.directory}
        self.source, self.python = self.pins[:2]
        self.request = {"treePins": [{"root": self.app_root, "role": "installed-application", "files": sorted(self.base)},
            {"root": r"C:\Fixture\Python", "role": "python-runtime", "files": ["python.exe"]}],
            "filePins": [source, python, *records], "directoryPins": [directory]}
    def guard(self):
        for p in self.pins:
            p.current()
    def event(self, kind, value):
        self.events.append((kind, value))
    def park(self, reason, error=None):
        self.parked = (reason, error)
        raise Parked(reason)


class AppLeaseTests(unittest.TestCase):
    def test_native_false_close_never_retires_guard_custody(self):
        with tempfile.TemporaryDirectory() as temp:
            owner = Owned(temp)
            lease = r.InstalledApplicationLease(owner, owner.app_root, owner.base, owner.base)
            lease.files[-1].fail_native_close = True
            original_request, pins = owner.request, list(owner.pins)
            with self.assertRaises(Parked):
                lease.retire_after_committed_handoff(accepted(), "original")
            self.assertIs(owner.request, original_request)
            self.assertEqual(pins, owner.pins)
            self.assertFalse(lease.retired)

    def test_source_or_python_role_overlap_refuses_before_any_close(self):
        with tempfile.TemporaryDirectory() as temp:
            owner = Owned(temp)
            owner.update_retained_source_paths = [owner.app_root + r"\app\main.jar"]
            with self.assertRaises(r.Refused):
                r.InstalledApplicationLease(owner, owner.app_root, owner.base, owner.base)
            self.assertTrue(all(p.close_count == 0 for p in owner.pins))
    def test_actual_scoped_transition_retires_app_only_after_known_handoff(self):
        with tempfile.TemporaryDirectory() as temp:
            owner = Owned(temp)
            lease = r.InstalledApplicationLease(owner, owner.app_root, owner.base, owner.base)
            original_request = owner.request
            lease.retire_after_committed_handoff(accepted(), "original")
            self.assertTrue(lease.retired)
            self.assertIs(owner.update_retired_original_request, original_request)
            self.assertEqual([owner.source, owner.python], owner.pins)
            self.assertEqual(0, owner.source.close_count)
            self.assertEqual(0, owner.python.close_count)
            self.assertEqual(1, len(owner.request["treePins"]))
            self.assertEqual("python-runtime", owner.request["treePins"][0]["role"])
            self.assertTrue((Path(temp) / "update-retired-app-before.json").exists())
            with self.assertRaises(r.Refused):
                lease.retire_after_committed_handoff(accepted(), "original")

    def test_unknown_or_wrong_controller_never_retires(self):
        for value in ({**accepted(), "code": "OUTCOME_UNKNOWN"},
                      {**accepted(), "data": {"handoffReady": False, "jobId": JOB}},
                      {**accepted(), "controllerId": "other"}):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temp:
                owner = Owned(temp)
                lease = r.InstalledApplicationLease(owner, owner.app_root, owner.base, owner.base)
                with self.assertRaises(r.Refused):
                    lease.retire_after_committed_handoff(value, "original")
                self.assertFalse(lease.retired)
                self.assertTrue(all(p.close_count == 0 for p in owner.pins))

    def test_full_inventory_and_one_role_required(self):
        with tempfile.TemporaryDirectory() as temp:
            owner = Owned(temp)
            owner.base["unlisted.dll"] = {"sizeBytes": 5, "sha256": SHA}
            with self.assertRaises(r.Refused):
                r.InstalledApplicationLease(owner, owner.app_root, owner.base, owner.base)

    def test_close_failure_parks_without_editing_original_guard_set(self):
        with tempfile.TemporaryDirectory() as temp:
            owner = Owned(temp)
            lease = r.InstalledApplicationLease(owner, owner.app_root, owner.base, owner.base)
            lease.files[-1].fail_close = True
            original_request, pins = owner.request, list(owner.pins)
            with self.assertRaises(Parked):
                lease.retire_after_committed_handoff(accepted(), "original")
            self.assertIs(owner.request, original_request)
            self.assertEqual(pins, owner.pins)
            self.assertFalse(lease.retired)
            self.assertEqual("update-app-lease-retirement-unknown", owner.parked[0])


class AssetResponseTests(unittest.TestCase):
    def test_unexpected_fixture_error_prevents_known_closure(self):
        fixture = object.__new__(s.UpdateFixture)
        fixture.closed, fixture.errors, fixture.records = False, [{"stage": "tls-handshake"}], []
        fixture.fatal, fixture.mode, fixture.resources = None, "exact", {"target.msi": object()}
        fixture.ready = {"serverInstanceId": JOB}
        fixture.owner = types.SimpleNamespace(park=lambda *args: (_ for _ in ()).throw(Parked()), event=lambda *args: None)
        fixture.server = types.SimpleNamespace(shutdown=lambda: None, server_close=lambda: None)
        fixture.thread = types.SimpleNamespace(join=lambda: None)
        with self.assertRaises(Parked):
            fixture.close_known(all_update_operations_terminal=True)
        self.assertFalse(fixture.closed)

    def test_partial_native_send_preserves_actual_unsent_tail_and_count(self):
        class Peer:
            def __init__(self): self.sent = bytearray()
            def send(self, value):
                if self.sent:
                    raise BrokenPipeError(32, "declared native socket peer closed")
                self.sent.extend(value[:3])
                return 3
        peer = Peer()
        fixture = types.SimpleNamespace(pending_sends={})
        tracked = s.TrackedResponse(peer, fixture, 1)
        with self.assertRaises(BrokenPipeError): tracked.sendall(b"abcdef")
        self.assertEqual(b"abc", bytes(peer.sent))
        self.assertEqual(3, tracked.acknowledged_bytes)
        pending = fixture.pending_sends[1]
        self.assertEqual(b"def", pending["block"][pending["offset"]:])
    def response(self, content, mode):
        class Peer:
            def __init__(self): self.output = bytearray()
            def sendall(self, value): self.output.extend(value)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.msi"
            path.write_bytes(content)
            peer = Peer()
            asset = {"sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            with patch.object(s.time, "sleep") as slept:
                count = s.write_asset(peer, path, asset, mode)
            self.assertEqual(len(content), count)
            self.assertEqual(content, path.read_bytes())
            head, body = bytes(peer.output).split(b"\r\n\r\n", 1)
            self.assertIn(f"Content-Length: {len(content)}".encode(), head)
            return body, slept.call_count

    def test_exact_and_paced_stream_same_immutable_bytes(self):
        body = b"MZ" + bytes(range(256)) * 700
        self.assertEqual((body, 0), self.response(body, "exact"))
        actual, calls = self.response(body, "paced")
        self.assertEqual(body, actual)
        self.assertEqual(3, calls)

    def test_checksum_fault_changes_exactly_one_transferred_byte_only(self):
        body = b"MZ" + bytes(range(256)) * 10
        actual, calls = self.response(body, "checksum-corrupt")
        self.assertEqual(len(body), len(actual))
        self.assertEqual(1, sum(x != y for x, y in zip(body, actual)))
        self.assertNotEqual(hashlib.sha256(body).digest(), hashlib.sha256(actual).digest())
        self.assertEqual(0, calls)

    def test_changed_frozen_source_is_refused_before_response(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fixture.msi"
            path.write_bytes(b"MZchanged")
            sent = []
            peer = types.SimpleNamespace(sendall=sent.append)
            with self.assertRaises(ValueError):
                s.write_asset(peer, path, {"sizeBytes": 9, "sha256": SHA}, "exact")
            self.assertEqual([], sent)


class PublicAndInventoryTests(unittest.TestCase):
    def test_ready_handoff_recovers_same_accepted_operation_without_reissue(self):
        original = {**accepted(), "data": {"handoffReady": False}}
        current = {**accepted(), "requestId": "readiness-read-request"}
        result = r.join_ready_handoff(original, current)
        self.assertEqual(original["requestId"], result["requestId"])
        self.assertEqual(OP, result["operationId"])
        with self.assertRaises(r.Refused): r.join_ready_handoff(original, {**current, "operationId": JOB})

    def test_actual_tcp_listener_table_selects_only_exact_loopback_port_owner(self):
        import socket, struct
        def row(port, pid, address=0x0100007f):
            return struct.pack("<6I", 2, address, socket.htons(port), 0, 0, pid)
        table = struct.pack("<I", 2) + row(50001, 740) + row(50002, 750)
        self.assertEqual(740, r.select_listener(table, 50001))
        for wrong in (struct.pack("<I", 2) + row(50001, 740) + row(50001, 750),
                      struct.pack("<I", 1) + row(50001, 740, address=0), table[:-1]):
            with self.assertRaises(r.Refused): r.select_listener(wrong, 50001)

    def test_failure_with_owned_fixture_never_unwinds_source_custody(self):
        owner = types.SimpleNamespace(update_fixture=types.SimpleNamespace(closed=False),
            park=lambda *args: (_ for _ in ()).throw(Parked()))
        with patch.object(c, "_run_update", side_effect=ValueError("declared stage failure")):
            with self.assertRaises(Parked): c.run_update(owner, {})
    def test_exit_and_result_code_must_agree(self):
        data = {"schemaVersion": 1, "code": "CANCELLED", "ok": False, "final": True}
        self.assertEqual(data, c.json_result(subprocess.CompletedProcess([], 130, json.dumps(data), ""), codes=("CANCELLED",)))
        with self.assertRaises(AssertionError):
            c.json_result(subprocess.CompletedProcess([], 0, json.dumps(data), ""), codes=("CANCELLED",))

    def test_complete_inventory_rejects_traversal_case_aliases_and_bad_digest(self):
        item = {"sizeBytes": 1, "sha256": SHA}
        self.assertEqual({"main.exe": item}, c.inventory({"main.exe": item}))
        for value in ({"../main.exe": item}, {"main.exe": item, "MAIN.exe": item},
                      {"C:/main.exe": item}, {"main.exe": {**item, "sha256": "missing"}}):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                c.inventory(value)

    def test_public_invocation_uses_explicit_original_controller_and_revision(self):
        seen = []
        def invoke(workspace, *args):
            seen.append((workspace, args))
            return subprocess.CompletedProcess([], 0, json.dumps({"schemaVersion": 1, "code": "ACCEPTED", "ok": True,
                "final": False, "controllerId": "original"}), "")
        owner = types.SimpleNamespace(invoke=invoke)
        c.public(owner, "workspace", "original", "updates", "download", revision=7,
                 asynchronous=True, codes=("ACCEPTED",), final=False)
        self.assertEqual(("--json", "--controller-id", "original", "--if-revision", "7", "--async", "updates", "download"), seen[0][1])

    def test_snapshot_preparation_continuity_requires_actual_runtime_identity(self):
        before = {"controllerId": "original", "configurationRevision": 3,
                  "data": {"runtimeRunning": True, "activeLocationId": "A", "activeMode": "proxy-only"}}
        c.invariant_status(before, json.loads(json.dumps(before)))
        changed = json.loads(json.dumps(before))
        changed["data"]["activeLocationId"] = "B"
        with self.assertRaises(AssertionError): c.invariant_status(before, changed)

    def test_missing_actual_bindings_cannot_start_any_child(self):
        owner = types.SimpleNamespace(child=lambda *a: self.fail("must not start child"))
        with self.assertRaises((AssertionError, KeyError, TypeError)):
            c.run_update(owner, {"UPDATE_INPUTS": {"schemaVersion": 1, "variant": "success-off"}})


class NativeCollectorTests(unittest.TestCase):
    """Actual collector decisions with a declared read-only Windows API peer."""
    def setUp(self):
        self.pid = 740
        self.created = 134000000000000001
        self.helper = {"pid": self.pid, "creationFileTime": self.created,
            "image": r"C:\Installed\app\helper.exe", "sha256": SHA, "sid": SID, "sessionId": 2}
        self.coordinator = {**self.helper, "pid": 750, "creationFileTime": self.created + 1, "sid": ADMIN}
        self.request = {"schemaVersion": 1, "stage": "authorization", "ordinaryTaskOperationId": OP,
            "sourceSha": "b" * 40, "collectorSourceSha256": SHA,
            "context": {"bootIdentifier": JOB, "ordinarySid": SID, "ordinarySessionId": 2, "approvingAdminSid": ADMIN, "localAppData": r"C:\Users\fixture\AppData\Local", "workspace": r"C:\Fixture\state"},
            "jobId": JOB, "productOperationId": OP, "actors": {"coordinator": self.coordinator, "worker": self.helper},
            "fileInputs": {}, "faultBinding": {}, "programData": r"C:\ProgramData",
            "evidenceRoot": r"C:\ProgramData\update-evidence-" + OP,
            "ordinaryWorkerPid": 100, "ordinaryWorkerBirth": self.created, "expectedHelperSha256": SHA}
        native = types.SimpleNamespace(boot_identifier=lambda: JOB, token=lambda: {"sid": "S-1-5-18", "elevation": 1})
        self.owner = types.SimpleNamespace(native=native, guard=lambda: None,
            by_path={str(Path(n.__file__)).casefold(): types.SimpleNamespace(record={"sha256": SHA})})
        self.open_calls = []
        testcase = self
        class NativePeer:
            def open_process(self, pid, access):
                testcase.open_calls.append((pid, access))
                expected = next(v for v in testcase.request["actors"].values() if v["pid"] == pid)
                class Process:
                    def __enter__(self): return self
                    def __exit__(self, *_): pass
                    def wait(self): return 258
                    def describe(self):
                        return {"creationFileTime": expected["creationFileTime"], "image": expected["image"],
                            "sha256": expected["sha256"], "sizeBytes": 7,
                            "token": {"sid": expected["sid"], "sessionId": expected["sessionId"],
                                      "elevated": int(expected["sid"] == ADMIN)}}
                return Process()
        self.observer = types.SimpleNamespace(WindowsNative=NativePeer, require_identity=lambda actual, expected:
            testcase.assertTrue(actual["creationFileTime"] == expected["creationFileTime"]
                                and actual["image"] == expected["image"] and actual["sha256"] == expected["sha256"]
                                and actual["token"]["sid"] == expected["sid"]))
        self.ready = {"version": 2, "jobId": JOB, "pid": self.pid, "creationFileTime": self.created,
                      "principalSid": SID, "helperSha256": SHA}

    def run_authorization(self, ready=None):
        wire = json.dumps(self.ready if ready is None else ready).encode()
        self.request["fileInputs"]["workerReady"] = {"path": str(PureWindowsPath(r"C:\Users\fixture\AppData\Local\vpn-control-install-inputs") / JOB / "worker-ready.json"),
            "sizeBytes": len(wire), "sha256": hashlib.sha256(wire).hexdigest()}
        class FilePeer:
            def __init__(self, *_): self.opening = {"path": str(PureWindowsPath(r"C:\Users\fixture\AppData\Local\vpn-control-install-inputs") / JOB / "worker-ready.json")}
            def read(self, maximum): return wire
            def close(self): pass
        with patch.object(r, "FileObservation", FilePeer):
            return n.collect(self.request, self.owner, r, self.observer)

    def test_different_approving_admin_does_not_replace_original_worker(self):
        result = self.run_authorization()["observations"]
        self.assertEqual(ADMIN, result["coordinator"]["token"]["sid"])
        self.assertEqual(SID, result["originalUserWorker"]["token"]["sid"])
        self.assertEqual("msi.dll:MsiInstallProductW", result["nativeInstallerApi"])
        self.assertEqual(2, len(self.open_calls))

    def test_worker_ready_generation_must_join_actual_worker(self):
        with self.assertRaises(ValueError):
            self.run_authorization({**self.ready, "creationFileTime": self.created + 10})

    def test_worker_ready_sid_and_helper_bytes_cannot_substitute(self):
        for change in ({"principalSid": ADMIN}, {"helperSha256": "f" * 64}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_authorization({**self.ready, **change})

    def test_ordinary_collector_cannot_publish_machine_authority(self):
        self.owner.native.token = lambda: {"sid": SID, "elevation": 0}
        with self.assertRaises(ValueError): self.run_authorization()
        self.assertEqual([], self.open_calls)

    def test_source_or_boot_drift_refuses_before_actor_open(self):
        self.owner.by_path[str(Path(n.__file__)).casefold()].record["sha256"] = "e" * 64
        with self.assertRaises(ValueError): self.run_authorization()
        self.assertEqual([], self.open_calls)
        self.owner.by_path[str(Path(n.__file__)).casefold()].record["sha256"] = SHA
        self.owner.native.boot_identifier = lambda: OP
        with self.assertRaises(ValueError): self.run_authorization()
        self.assertEqual([], self.open_calls)

    def test_unknown_phase_rejects_before_native_observation(self):
        self.request["stage"] = "invented-operation"
        with self.assertRaises(ValueError): self.run_authorization()
        self.assertEqual([], self.open_calls)


if __name__ == "__main__":
    unittest.main()
