"""Causal checks for the fixed one-shot Mac fixture-server stop."""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import macos_machine_server_stop as stop
from agent_tools import macos_machine_acceptance as acceptance


SOURCE = "a" * 40
CORRELATION = "11111111-1111-4111-8111-111111111111"
INSTANCE = "22222222-2222-4222-8222-222222222222"
JOB = "33333333-3333-4333-8333-333333333333"
OPERATION = "44444444-4444-4444-8444-444444444444"
BOOT = "55555555-5555-4555-8555-555555555555"
REQUEST = {"schemaVersion": 1, "vmName": acceptance.VM_NAME, "sourceSha": SOURCE, "correlationId": CORRELATION,
           "scenario": "install", "jobId": JOB, "operationId": OPERATION,
           "bootSessionUuid": BOOT, "reservationId": "env-1234",
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "serverInstanceId": INSTANCE, "serverPid": 1234,
           "serverProcessStartIdentity": "darwin:123456:123",
           "readySha256": "c" * 64}


def campaign(root: Path, *, source=SOURCE, operation=OPERATION, vm_name=acceptance.VM_NAME):
    directory = acceptance._private_group(root)
    acceptance._save(directory / (CORRELATION + ".json"), {
        "request": {"sourceSha": source, "correlationId": CORRELATION,
                    "scenario": "install", "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"]},
        "admission": {"vmName": vm_name, "bootSessionUuid": BOOT, "reservationId": "env-1234"},
        "operationId": operation, "jobId": JOB, "state": "unknown"})


class Boundary:
    def __init__(self):
        self.calls = 0
        self.fail = False
        self.receipt = None

    def request_stop(self, request):
        self.calls += 1
        if self.fail:
            raise OSError("lost response")
        return None

    def observe_stop(self, request):
        return self.receipt


class MacServerStopTest(unittest.TestCase):
    @staticmethod
    def snapshot(root):
        return {str(path.relative_to(root)): (path.lstat().st_mode, path.lstat().st_ino,
                 path.read_bytes() if path.is_file() and not path.is_symlink() else None)
                for path in root.rglob("*")}

    def test_original_vm_getter_is_pure_for_explicit_and_legacy_journals(self):
        for legacy in (False, True):
            with self.subTest(legacy=legacy), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); campaign(root)
                request = {key: value for key, value in REQUEST.items() if not legacy or key != "vmName"}
                path = stop._directory(root) / (CORRELATION + ".json")
                stop._save(path, {"schemaVersion": 1, "request": request, "state": "unknown", "receipt": None})
                original = self.snapshot(root)
                with patch.object(stop, "TartBoundary", side_effect=AssertionError("provider forbidden")), \
                     patch.object(stop.acceptance, "_private_group", side_effect=AssertionError("creation forbidden")):
                    self.assertEqual(acceptance.VM_NAME, stop.original_vm_name(root, CORRELATION))
                self.assertEqual(original, self.snapshot(root))

    def test_original_vm_getter_missing_history_does_not_create_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError): stop.original_vm_name(root, CORRELATION)
            self.assertEqual([], list(root.iterdir()))
            (root / ".rag_index").mkdir(mode=0o700)
            original = self.snapshot(root)
            with self.assertRaises(ValueError): stop.original_vm_name(root, CORRELATION)
            self.assertEqual(original, self.snapshot(root))

    def test_original_vm_getter_refuses_changed_target_unsafe_journal_and_absent_legacy_binding(self):
        for mode in ("target", "missing-target", "correlation", "symlink", "hardlink", "schema"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); campaign(root)
                request = dict(REQUEST)
                if mode == "missing-target":
                    request.pop("vmName")
                    campaign_path = acceptance._private_group(root) / (CORRELATION + ".json")
                    prior = acceptance._read(campaign_path); prior["admission"].pop("vmName")
                    acceptance._save(campaign_path, prior)
                elif mode == "target": request["vmName"] = "other-selected-vm"
                elif mode == "correlation": request["correlationId"] = "66666666-6666-4666-8666-666666666666"
                path = stop._directory(root) / (CORRELATION + ".json")
                value = {"schemaVersion": True if mode == "schema" else 1,
                         "request": request, "state": "unknown", "receipt": None}
                stop._save(path, value)
                if mode in {"symlink", "hardlink"}:
                    retained = root / "retained-original.json"; path.rename(retained)
                    if mode == "symlink": path.symlink_to(retained)
                    else: os.link(retained, path)
                original = self.snapshot(root)
                with patch.object(stop, "TartBoundary", side_effect=AssertionError("provider forbidden")), \
                     self.assertRaises((ValueError, OSError)):
                    stop.original_vm_name(root, CORRELATION)
                self.assertEqual(original, self.snapshot(root))

    def executable(self, directory):
        script = directory / "controlled-tart.py"
        log = directory / "actual-calls.json"
        code = """import json,pathlib,sys
log=pathlib.Path(LOG)
calls=json.loads(log.read_text())if log.exists()else []
args=sys.argv[1:]
if args==['list','--format','json']:
 calls.append({'kind':'list'})
 print(json.dumps([{'Name':VM,'Source':'local','Running':True,'State':'running'}]))
elif len(args)==6 and args[0]=='exec' and args[2:4]==['/usr/bin/python3','-c']:
 request=json.loads(args[-1])
 assert 'os.kill(pid,signal.SIGTERM)'in args[4]
 calls.append({'kind':'stop','actualVm':args[1],'wire':request})
 print(json.dumps({'stopRequestCount':1}))
else:raise SystemExit(8)
log.write_text(json.dumps(calls))
"""
        script.write_text("LOG=" + repr(str(log)) + "\nVM=" + repr(acceptance.VM_NAME) + "\n" + code)
        def runner(argv, **kwargs):
            self.assertEqual("tart", argv[0])
            return subprocess.run([sys.executable, str(script), *argv[1:]], **kwargs)
        return runner, lambda: json.loads(log.read_text()) if log.exists() else []

    def test_causal_actual_tart_caller_refuses_implicit_or_wrong_target(self):
        path = Path(__file__).parent / "fixtures/macos_server_stop_target_before.py"
        self.assertEqual("3f9bd524f4c716cf5891f94c0fee1c1184ebda22cedf5466bfab2bebb0a6af62",
                         hashlib.sha256(path.read_bytes()).hexdigest())
        name = "agent_tools._mac_server_stop_target_before"
        spec = importlib.util.spec_from_file_location(name, path)
        before = importlib.util.module_from_spec(spec); sys.modules[name] = before
        self.causal_results = []
        try:
            spec.loader.exec_module(before)
            legacy = {key: value for key, value in REQUEST.items() if key != "vmName"}
            for route in ("start-without-selector", "direct-without-selector", "direct-wrong-selector"):
                for module, expected in ((before, "red"), (stop, "green")):
                    with self.subTest(route=route, expected=expected), tempfile.TemporaryDirectory() as directory:
                        root = Path(directory); campaign(root)
                        runner, calls = self.executable(root)
                        boundary = module.TartBoundary(runner=runner)
                        error = None
                        try:
                            if route == "start-without-selector": module.start(root, legacy, boundary)
                            elif route == "direct-without-selector": boundary.request_stop(legacy)
                            else: boundary.request_stop({**REQUEST, "vmName": "other-selected-vm"})
                        except ValueError as failure:
                            error = str(failure)
                        actual = calls()
                        self.causal_results.append({"route": route, "expected": expected,
                                                    "actualCalls": actual, "error": error})
                        if expected == "red":
                            self.assertIsNone(error)
                            self.assertEqual([acceptance.VM_NAME], [row["actualVm"] for row in actual if row["kind"] == "stop"])
                        else:
                            self.assertIsNotNone(error)
                            self.assertEqual([], actual, "refusal must precede any native provider call")
        finally:
            sys.modules.pop(name, None)

    def test_explicit_matching_vm_is_persisted_and_only_it_is_dispatched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); campaign(root)
            runner, calls = self.executable(root)
            result = stop.start(root, REQUEST, stop.TartBoundary(runner=runner))
            self.assertEqual(REQUEST["vmName"], result["vmName"])
            effects = [row for row in calls() if row["kind"] == "stop"]
            self.assertEqual([REQUEST["vmName"]], [row["actualVm"] for row in effects])
            self.assertNotIn("vmName", effects[0]["wire"], "strict existing guest stop protocol is unchanged")
            retained = stop._read(root / ".rag_index/macos-machine-server-stop" / (CORRELATION + ".json"))
            self.assertEqual(REQUEST["vmName"], retained["request"]["vmName"])

    def test_campaign_target_conflict_and_unqualified_vm_never_dispatch(self):
        for selected, original in ((acceptance.VM_NAME, "other-selected-vm"),
                                   ("other-selected-vm", acceptance.VM_NAME),
                                   ("other-selected-vm", "other-selected-vm")):
            with self.subTest(selected=selected, original=original), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); campaign(root, vm_name=original)
                runner, calls = self.executable(root)
                with self.assertRaises(ValueError):
                    stop.start(root, {**REQUEST, "vmName": selected}, stop.TartBoundary(runner=runner))
                self.assertEqual([], calls())
                self.assertFalse((root / ".rag_index/macos-machine-server-stop" / (CORRELATION + ".json")).exists())

    def test_legacy_status_uses_persisted_campaign_target_without_new_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); campaign(root)
            old_request = {key: value for key, value in REQUEST.items() if key != "vmName"}
            path = stop._directory(root) / (CORRELATION + ".json")
            stop._save(path, {"schemaVersion": 1, "request": old_request, "state": "unknown", "receipt": None})
            original = path.read_bytes()
            class HistoricalBoundary(Boundary):
                def observe_stop(self, request):
                    self.observed = request; return None
            boundary = HistoricalBoundary()
            self.assertEqual(acceptance.VM_NAME, stop.status(root, CORRELATION, boundary)["vmName"])
            self.assertEqual(acceptance.VM_NAME, boundary.observed["vmName"])
            self.assertEqual(0, boundary.calls)
            self.assertEqual(original, path.read_bytes())
            self.assertEqual("unknown", stop.collect(root, CORRELATION)["state"])
            self.assertEqual("unknown", stop.start(root, REQUEST, boundary)["state"])
            self.assertEqual(0, boundary.calls, "new explicit repeat cannot resignal a legacy original")
            self.assertEqual(original, path.read_bytes())

    def test_legacy_missing_persisted_vm_cannot_infer_current_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); campaign(root)
            campaign_path = acceptance._private_group(root) / (CORRELATION + ".json")
            original = acceptance._read(campaign_path); del original["admission"]["vmName"]
            acceptance._save(campaign_path, original)
            legacy = {key: value for key, value in REQUEST.items() if key != "vmName"}
            path = stop._directory(root) / (CORRELATION + ".json")
            stop._save(path, {"schemaVersion": 1, "request": legacy, "state": "unknown", "receipt": None})
            runner, calls = self.executable(root)
            with self.assertRaises(ValueError): stop.status(root, CORRELATION, stop.TartBoundary(runner=runner))
            self.assertEqual([], calls())
            self.assertEqual("unknown", stop.collect(root, CORRELATION)["state"])

    def test_unknown_stop_is_durable_and_never_resignaled(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            boundary.fail = True
            first = stop.start(Path(directory), REQUEST, boundary)
            self.assertEqual("unknown", first["state"])
            self.assertFalse(first["replayAllowed"])
            self.assertEqual(1, boundary.calls)
            self.assertEqual(first, stop.start(Path(directory), REQUEST, boundary))
            self.assertEqual(1, boundary.calls)
            self.assertEqual("unknown", stop.status(Path(directory), CORRELATION, boundary)["state"])

    def test_correlation_cannot_be_rebound_to_a_different_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            stop.start(Path(directory), REQUEST, boundary)
            with self.assertRaises(ValueError):
                stop.start(Path(directory), {**REQUEST, "serverPid": 1235}, boundary)
            self.assertEqual(1, boundary.calls)

    def test_new_correlation_cannot_signal_while_prior_stop_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            stop.start(Path(directory), REQUEST, boundary)
            with self.assertRaises(ValueError):
                stop.start(Path(directory), {**REQUEST,
                    "correlationId": "66666666-6666-4666-8666-666666666666"}, boundary)
            self.assertEqual(1, boundary.calls)

    def test_status_only_promotes_a_new_observation_and_does_not_resignal(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            stop.start(Path(directory), REQUEST, boundary)
            self.assertEqual("unknown", stop.status(Path(directory), CORRELATION, boundary)["state"])
            self.assertEqual(1, boundary.calls)
            boundary.receipt = {"serverExitCode": 0, "stopReceiptFinal": True}
            final = stop.status(Path(directory), CORRELATION, boundary)
            self.assertEqual("complete", final["state"])
            self.assertEqual(boundary.receipt, stop.collect(Path(directory), CORRELATION)["receipt"])
            self.assertEqual("historical-receipt", stop.collect(Path(directory), CORRELATION)["state"])
            boundary.receipt = None  # Fresh kernel proof has become unavailable.
            self.assertEqual("unknown", stop.status(Path(directory), CORRELATION, boundary)["state"])
            self.assertEqual("historical-receipt", stop.collect(Path(directory), CORRELATION)["state"])
            self.assertEqual("unverified", stop.collect(Path(directory), CORRELATION)["currentState"])
            self.assertEqual(1, boundary.calls)

    def test_same_prefix_source_or_different_operation_cannot_signal(self):
        for altered in ({"sourceSha": "a" * 7 + "f" * 33},
                        {"operationId": "77777777-7777-4777-8777-777777777777"}):
            with self.subTest(altered=altered), tempfile.TemporaryDirectory() as directory:
                campaign(Path(directory))
                boundary = Boundary()
                with self.assertRaisesRegex(ValueError, "campaign"):
                    stop.start(Path(directory), {**REQUEST, **altered}, boundary)
                self.assertEqual(0, boundary.calls)
                self.assertFalse((Path(directory) / ".rag_index/macos-machine-server-stop" /
                                  (CORRELATION + ".json")).exists())


if __name__ == "__main__":
    unittest.main()
