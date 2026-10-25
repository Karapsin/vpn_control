"""Explicit macOS fixture admission and real saved-program execution, without Tart.

Local filesystem tests use only inert bytes in a new directory owned by this test.
They do not execute a package, access an existing fixture, or start a VM.
"""
from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from uuid import uuid4

if os.environ.get("VPN_MACOS_FIXTURE_STAGE_SOURCE"):
    _source = Path(os.environ["VPN_MACOS_FIXTURE_STAGE_SOURCE"])
    _loader = importlib.machinery.SourceFileLoader("agent_tools._isolated_macos_fixture_stage", str(_source))
    _spec = importlib.util.spec_from_loader(_loader.name, _loader)
    stage = importlib.util.module_from_spec(_spec)
    _loader.exec_module(stage)
else:
    from agent_tools import macos_fixture_stage as stage


SOURCE = "41ec8c4364af6904dcec07ee2631d2d821910c64"
CORRELATION = "6ec74c1c-ced7-4ff2-b0f5-15eadf7751e9"
BOOT = "caf375f0-a9ca-45cf-ac14-035abbc16da7"
BASE_DATA = b"inert base package bytes"
TARGET_DATA = b"inert target package bytes"


def request():
    value = {
        "schemaVersion": 1,
        "correlationId": CORRELATION,
        "sourceSha": SOURCE,
        "fixtureReceiptArtifactId": "sha256-" + "e" * 64,
        "environmentContext": {
            "provider": "tart", "vmName": "owned-macos-fresh-17",
            "guestUser": "fixture_user", "guestUid": 517,
            "guestHome": "/Users/fixture_user", "guestBootSessionUuid": BOOT,
        },
        "guestRoot": "/Users/fixture_user/fresh-stage-17",
        "baseVersion": "2.2.5", "targetVersion": "2.2.6",
        "baseSha256": hashlib.sha256(BASE_DATA).hexdigest(), "baseSizeBytes": len(BASE_DATA),
        "targetSha256": hashlib.sha256(TARGET_DATA).hexdigest(), "targetSizeBytes": len(TARGET_DATA),
    }
    # The first preserved generic beforeimage predates registered receipt input.
    # This explicit RED-only schema seam supplies that source's authentic input;
    # its validation, source custody, transport and guest bytes remain untouched.
    if os.environ.get("VPN_MACOS_FIXTURE_STAGE_TEST_INPUT_SCHEMA") == "initial-no-receipt":
        del value["fixtureReceiptArtifactId"]
    return value


def observed(inputs=None, mode=0o444):
    inputs = inputs or request()
    return {key: copy.deepcopy(inputs[key]) for key in
            ("schemaVersion", "correlationId", "sourceSha", "environmentContext", "guestRoot")} | {
        "files": {label: {"sha256": inputs[label + "Sha256"],
                          "sizeBytes": inputs[label + "SizeBytes"], "mode": mode}
                  for label in ("base", "target")}}


def complete_runner(inputs, calls):
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, json.dumps(observed(inputs)).encode(), b"")
    return run


class ExplicitContextAdmissionTests(unittest.TestCase):
    def refused_without_effect(self, inputs):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = mock.Mock(side_effect=AssertionError("invalid request reached transport"))
            with self.assertRaises((ValueError, TypeError)):
                stage.start(root, inputs, runner=runner)
            runner.assert_not_called()
            self.assertEqual([], list(root.iterdir()), "invalid admission created a journal")

    def test_missing_and_extra_fields_refuse_before_transport_or_journal(self):
        for invalid in (None, [], "request", True):
            with self.subTest(invalid_request=invalid):
                self.refused_without_effect(invalid)
        for key in request():
            with self.subTest(missing=key):
                value = request()
                del value[key]
                self.refused_without_effect(value)
        self.refused_without_effect(request() | {"oldCorrelationId": CORRELATION})
        for key in request()["environmentContext"]:
            with self.subTest(missing_context=key):
                value = request()
                del value["environmentContext"][key]
                self.refused_without_effect(value)
        value = request()
        value["environmentContext"]["historicalVmName"] = "old"
        self.refused_without_effect(value)
        for invalid in (None, [], "context", True):
            self.refused_without_effect(request() | {"environmentContext": invalid})

    def test_invalid_identity_context_refuses_before_effects(self):
        cases = {
            "provider": (None, "ssh", "Tart"),
            "vmName": (None, "", "../guest", "guest;id", "guest\nname", "--unsafe"),
            "guestUser": (None, "", "../admin", "admin;id", "admin\n"),
            "guestUid": (None, True, 0, -1, "517"),
            "guestHome": (None, "", "relative", "/", "/Users/a/../b", "/Users//a", "/Users/a/"),
            "guestBootSessionUuid": (None, "", "not-a-uuid", BOOT.upper()),
        }
        for key, values in cases.items():
            for invalid in values:
                with self.subTest(key=key, invalid=invalid):
                    value = request()
                    value["environmentContext"][key] = invalid
                    self.refused_without_effect(value)

    def test_root_requires_clean_descendant_of_explicit_home(self):
        for invalid in (None, "relative", "/Users/fixture_user", "/Users/fixture_user/",
                        "/Users/fixture_user-other/package", "/Users/admin/macos-parity41ec8c4",
                        "/Users/fixture_user/../other", "/Users/fixture_user//pair",
                        "/Users/fixture_user/./pair", "/Users/fixture_user/pair/"):
            with self.subTest(invalid=invalid):
                self.refused_without_effect(request() | {"guestRoot": invalid})

    def test_schema_sha_sizes_and_versions_are_strict(self):
        cases = [("schemaVersion", value) for value in (None, 0, 2, True, "1")]
        cases += [("sourceSha", value) for value in (None, SOURCE.upper(), SOURCE[:7], SOURCE + "\n")]
        cases += [("fixtureReceiptArtifactId", value) for value in
                  (None, "", "e" * 64, "sha256-" + "A" * 64, "sha256-" + "e" * 63,
                   "sha256-" + "e" * 64 + "\n")]
        for label in ("base", "target"):
            cases += [(label + "Sha256", value) for value in (None, "x" * 64, "a" * 63, "A" * 64)]
            cases += [(label + "SizeBytes", value) for value in (None, True, 0, -1, "4")]
            cases += [(label + "Version", value) for value in
                      (None, "0.2.5", "20.2.5", "2.20.5", "2.2.20", "02.2.5", "2.2.5\n")]
        cases += [("targetVersion", "2.2.5"), ("targetVersion", "2.2.4")]
        for key, invalid in cases:
            with self.subTest(key=key, invalid=invalid):
                self.refused_without_effect(request() | {key: invalid})

    def test_request_that_would_exceed_command_bound_refuses_before_journal(self):
        value = request()
        value["guestRoot"] = value["environmentContext"]["guestHome"] + "/" + "a" * 60_000
        self.refused_without_effect(value)

    def test_version_order_uses_base20_numeric_components(self):
        for base, target in (("2.1.19", "2.2.0"), ("2.19.19", "3.0.0"), ("2.2.9", "2.2.10")):
            with self.subTest(base=base, target=target):
                value = stage._request(request() | {"baseVersion": base, "targetVersion": target})
                self.assertEqual((base, target), (value["baseVersion"], value["targetVersion"]))

    def test_validated_context_is_independent_of_caller_mutation(self):
        value = request()
        admitted = stage._request(value)
        value["environmentContext"]["vmName"] = "changed-after-admission"
        self.assertEqual("owned-macos-fresh-17", admitted["environmentContext"]["vmName"])


class ExplicitContextCommandTests(unittest.TestCase):
    def test_new_guest_versions_and_root_are_carried_without_historical_defaults(self):
        for vm, user, uid, home, root, boot in (
            ("owned-macos-fresh-17", "fixture_user", 517, "/Users/fixture_user", "stage-17", BOOT),
            ("fresh-mac-82", "owner82", 682, "/Volumes/Users/owner82", "pair-current", str(uuid4())),
        ):
            with self.subTest(vm=vm):
                value = request()
                value["environmentContext"].update(vmName=vm, guestUser=user, guestUid=uid,
                                                   guestHome=home, guestBootSessionUuid=boot)
                value["guestRoot"] = home + "/" + root
                argv = stage._command(value, "mutate")
                self.assertEqual(["tart", "exec", "-i", vm, "/usr/bin/python3", "-I", "-B", "-c"], argv[:8])
                self.assertEqual(value, json.loads(argv[9]))
                self.assertEqual("mutate", argv[10])
                programme = stage._GUEST_CODE.encode()
                self.assertEqual(hashlib.sha256(programme).hexdigest(), argv[11])
                self.assertEqual(str(len(programme)), argv[12])
                self.assertLess(sum(len(part.encode()) + 1 for part in argv), 60_000)
                self.assertLessEqual(len(programme), 8 * 1024 * 1024)
                self.assertNotIn("vpn-control-boot-control53", argv)
                self.assertNotIn("/Users/admin/macos-parity", json.dumps(value))


@unittest.skipUnless(os.name == "posix", "bounded Tart transport uses POSIX pipe readiness")
class BoundedTransportTests(unittest.TestCase):
    def test_production_transport_default_bounds_output_and_retains_metadata(self):
        runner = stage.start.__kwdefaults__["runner"]
        amount = stage.MAX_OUTPUT_BYTES * 3
        code = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*int(sys.argv[1]))"
        result = runner([sys.executable, "-I", "-B", "-c", code, str(amount)], input=b"programme",
                        capture_output=True, check=False, timeout=5)
        self.assertLessEqual(len(result.stdout), stage.MAX_OUTPUT_BYTES)
        self.assertTrue(result._capture["overflow"])
        self.assertGreater(result._capture["counts"]["stdout"], stage.MAX_OUTPUT_BYTES)
        self.assertEqual(hashlib.sha256(b"x" * result._capture["counts"]["stdout"]).hexdigest(),
                         result._capture["streamSha256"]["stdout"])
        self.assertTrue(all(result._capture["eof"].values()))
        with self.assertRaises(ChildProcessError):
            os.waitpid(result._capture["pid"], os.WNOHANG)

    def test_duplex_transfer_has_exact_counts_hashes_and_eof(self):
        payload = b"saved programme bytes\n" * 12_000
        code = ("import hashlib,sys;data=sys.stdin.buffer.read();"
                "sys.stdout.write(str(len(data))+':'+hashlib.sha256(data).hexdigest());"
                "sys.stderr.buffer.write(b'retained stderr evidence')")
        result = stage._bounded_runner([sys.executable, "-I", "-B", "-c", code], input=payload,
                                       capture_output=True, timeout=5, check=False)
        expected = (str(len(payload)) + ":" + hashlib.sha256(payload).hexdigest()).encode()
        self.assertEqual((0, expected, b"retained stderr evidence"),
                         (result.returncode, result.stdout, result.stderr))
        capture = result._capture
        self.assertTrue(capture["complete"])
        self.assertFalse(capture["timeout"])
        self.assertFalse(capture["overflow"])
        self.assertEqual(len(payload), capture["sentBytes"])
        self.assertEqual(len(payload), capture["inputBytes"])
        self.assertIsNone(capture["inputError"])
        for label, body in (("stdout", result.stdout), ("stderr", result.stderr)):
            self.assertEqual(len(body), capture["counts"][label])
            self.assertEqual(hashlib.sha256(body).hexdigest(), capture["streamSha256"][label])
            self.assertTrue(capture["eof"][label])
        with self.assertRaises(ChildProcessError):
            os.waitpid(capture["pid"], os.WNOHANG)

    def test_stderr_overflow_retains_only_bound_and_reaps_owned_child(self):
        code = "import sys;sys.stdin.buffer.read();sys.stderr.buffer.write(b'e'*200000)"
        result = stage._bounded_runner([sys.executable, "-I", "-B", "-c", code], input=b"p",
                                       capture_output=True, timeout=5, check=False)
        self.assertEqual(stage.MAX_OUTPUT_BYTES, len(result.stderr))
        self.assertTrue(result._capture["overflow"])
        self.assertGreater(result._capture["counts"]["stderr"], len(result.stderr))
        self.assertFalse(result._capture["timeout"])
        with self.assertRaises(ChildProcessError):
            os.waitpid(result._capture["pid"], os.WNOHANG)

    def test_timeout_reaps_only_its_owned_transport_and_keeps_raw_output(self):
        sibling = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time;time.sleep(60)"])
        try:
            code = "import os,sys,time;sys.stdin.buffer.read();print(os.getpid(),flush=True);time.sleep(60)"
            result = stage._bounded_runner([sys.executable, "-I", "-B", "-c", code], input=b"p",
                                           capture_output=True, timeout=0.2, check=False)
            self.assertTrue(result._capture["timeout"])
            self.assertFalse(result._capture["overflow"])
            self.assertEqual(result._capture["pid"], int(result.stdout))
            self.assertIsNotNone(result.returncode)
            self.assertIsNone(sibling.poll(), "a different owned test child was signalled")
            with self.assertRaises(ChildProcessError):
                os.waitpid(result._capture["pid"], os.WNOHANG)
        finally:
            sibling.terminate()
            sibling.wait(timeout=5)

    def test_closed_stdin_records_incomplete_transfer(self):
        result = stage._bounded_runner([sys.executable, "-I", "-B", "-c", "pass"],
                                       input=b"p" * 1024**2, capture_output=True, timeout=5, check=False)
        self.assertFalse(result._capture["complete"])
        self.assertLess(result._capture["sentBytes"], result._capture["inputBytes"])
        self.assertIn(result._capture["inputError"], ("BrokenPipeError", "OSError"))

    def test_transport_bounds_refuse_before_popen(self):
        good = dict(argv=[sys.executable, "-c", "pass"], input=b"p", capture_output=True, timeout=5, check=False)
        changes = [dict(argv=["x" * 60_001]), dict(input=b""), dict(input=b"p" * (8 * 1024**2 + 1)),
                   dict(timeout=0), dict(timeout=True), dict(capture_output=False), dict(check=True)]
        with mock.patch.object(stage.subprocess, "Popen", side_effect=AssertionError("invalid transport launched")) as popen:
            for change in changes:
                with self.subTest(change={key: len(value) if isinstance(value, bytes) else value
                                          for key, value in change.items()}), self.assertRaises(ValueError):
                    stage._bounded_runner(**(good | change))
            popen.assert_not_called()


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "private durable journal requires POSIX nofollow custody")
class ExplicitContextLifecycleTests(unittest.TestCase):

    def test_complete_start_and_collection_do_not_submit_again(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            value = request()
            runner = complete_runner(value, calls)
            first = stage.start(temporary, value, runner=runner)
            self.assertEqual(["tart", "exec", "-i", value["environmentContext"]["vmName"]], calls[0][0][:4])
            self.assertEqual(stage._GUEST_CODE.encode(), calls[0][1]["input"])
            self.assertFalse(calls[0][1].get("shell", False))
            self.assertEqual(first, stage.start(temporary, value, runner=runner))
            self.assertEqual(first, stage.status(temporary, {"correlationId": CORRELATION}, runner=runner))
            self.assertEqual(first, stage.collect(temporary, {"correlationId": CORRELATION}))
            self.assertEqual(1, len(calls))

    def test_lost_mutation_is_durable_never_replayed_and_status_only_inspects(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            value = request()
            def runner(argv, **kwargs):
                calls.append((argv, kwargs))
                if len(calls) == 1:
                    # The durable original request must precede uncertain submission.
                    journals = [path for path in Path(temporary).rglob("intent.json")
                                if path.parent.name == CORRELATION]
                    self.assertEqual(1, len(journals))
                    record = json.loads(journals[0].read_text())
                    self.assertEqual(value, record["request"])
                    self.assertEqual({"request", "programmeSha256", "adapterSourceSha256"}, set(record))
                    self.assertFalse(journals[0].with_name("complete.json").exists())
                    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                return subprocess.CompletedProcess(argv, 0, json.dumps(observed(value)).encode(), b"")
            first = stage.start(temporary, value, runner=runner)
            self.assertEqual("unknown", first["state"])
            self.assertFalse(first["replayAllowed"])
            self.assertEqual(first, stage.start(temporary, value, runner=runner))
            self.assertEqual(first, stage.collect(temporary, {"correlationId": CORRELATION}))
            self.assertEqual(1, len(calls))
            final = stage.status(temporary, {"correlationId": CORRELATION}, runner=runner)
            self.assertEqual("complete", final["state"])
            self.assertEqual(["mutate", "inspect"], [argv[10] for argv, _options in calls])
            self.assertEqual(value, json.loads(calls[1][0][9]))

    def test_correlation_cannot_relabel_any_original_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = request()
            runner = mock.Mock(side_effect=subprocess.TimeoutExpired("original", 1))
            self.assertEqual("unknown", stage.start(temporary, value, runner=runner)["state"])
            changes = [dict(targetVersion="2.2.7"), dict(sourceSha="a" * 40),
                       dict(guestRoot=value["guestRoot"] + "-new")]
            for key, replacement in (("vmName", "another-vm"), ("guestUser", "other_user"),
                                     ("guestUid", 518), ("guestBootSessionUuid", str(uuid4()))):
                context = dict(value["environmentContext"], **{key: replacement})
                changes.append(dict(environmentContext=context))
            for change in changes:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    stage.start(temporary, value | change, runner=runner)
            self.assertEqual(1, runner.call_count)
            self.assertEqual("unknown", stage.collect(temporary, {"correlationId": CORRELATION})["state"])

    def test_wrong_or_incomplete_observation_stays_unknown(self):
        alterations = [lambda value: value.update(sourceSha="a" * 40),
                       lambda value: value.update(correlationId=str(uuid4())),
                       lambda value: value.update(guestRoot="/Users/fixture_user/other"),
                       lambda value: value["environmentContext"].update(guestUid=518),
                       lambda value: value["files"]["target"].update(sha256="0" * 64),
                       lambda value: value["files"]["base"].update(mode=0o644),
                       lambda value: value["files"].pop("target"),
                       lambda value: value.update(extra=True)]
        for alter in alterations:
            with self.subTest(alter=alter), tempfile.TemporaryDirectory() as temporary:
                result = observed()
                alter(result)
                runner = mock.Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(result).encode(), b""))
                self.assertEqual("unknown", stage.start(temporary, request(), runner=runner)["state"])

    def test_readers_require_only_original_correlation_and_unknown_never_submits(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = mock.Mock(side_effect=AssertionError("unknown status reached transport"))
            for method in (stage.status, stage.collect):
                with self.subTest(method=method.__name__):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        if method is stage.status:
                            method(temporary, {"correlationId": CORRELATION}, runner=runner)
                        else:
                            method(temporary, {"correlationId": CORRELATION})
                    with self.assertRaises(ValueError):
                        method(temporary, {"correlationId": CORRELATION, "environmentContext": request()["environmentContext"]})
            runner.assert_not_called()

    def test_coherent_other_correlation_journal_cannot_be_adopted_by_readers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = request()
            other = request() | {"correlationId": str(uuid4())}
            stage.start(root, original, runner=complete_runner(original, []))
            stage.start(root, other, runner=complete_runner(other, []))
            folder = root / ".rag_index/macos-fixture-stage"
            for name in ("intent.json", "program.source", "adapter.source", "complete.json"):
                (folder / original["correlationId"] / name).write_bytes(
                    (folder / other["correlationId"] / name).read_bytes())
            runner = mock.Mock(side_effect=AssertionError("copied journal reached guest"))
            for method in (stage.status, stage.collect):
                with self.subTest(method=method.__name__), self.assertRaises(ValueError):
                    if method is stage.status:
                        method(root, {"correlationId": original["correlationId"]}, runner=runner)
                    else:
                        method(root, {"correlationId": original["correlationId"]})
            runner.assert_not_called()

    def test_valid_json_before_transport_timeout_remains_unknown_and_cannot_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = request()
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                code = ("import sys,time;sys.stdin.buffer.read();"
                        "sys.stdout.write(sys.argv[1]);sys.stdout.flush();time.sleep(60)")
                return stage._bounded_runner([sys.executable, "-I", "-B", "-c", code,
                                              json.dumps(observed(value))], input=kwargs["input"],
                                             capture_output=True, check=False, timeout=0.2)
            first = stage.start(temporary, value, runner=runner)
            self.assertEqual("unknown", first["state"])
            self.assertEqual(first, stage.start(temporary, value, runner=runner))
            self.assertEqual(1, len(calls))
            journal = Path(temporary) / ".rag_index/macos-fixture-stage" / CORRELATION
            capture_path, = journal.glob("mutate-*.json")
            capture = json.loads(capture_path.read_text())["transportCapture"]
            self.assertTrue(capture["timeout"])
            self.assertTrue(all(capture["eof"].values()))
            self.assertFalse((journal / "complete.json").exists())


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "registered artifact custody requires POSIX nofollow admission")
class RegisteredFixtureAdmissionTests(unittest.TestCase):
    FINGERPRINT = "f" * 64
    CODE = "c" * 64

    def registered_pair(self, root, *, change_receipt=None, record_changes=None,
                        base_name=None):
        from agent_tools import native_artifact_registry as registry
        inputs = request()
        paths = {}
        builds = []
        for label, data in (("base", BASE_DATA), ("target", TARGET_DATA)):
            name = "vpn-control-" + inputs[label + "Version"] + ".dmg"
            path = root / (base_name if label == "base" and base_name else name)
            path.write_bytes(data)
            path.chmod(0o600)
            paths[label] = path
            asset = {"fileName": name, "platform": "macos", "architecture": "arm64",
                     "displayVersion": inputs[label + "Version"], "sha256": inputs[label + "Sha256"],
                     "sizeBytes": inputs[label + "SizeBytes"]}
            builds.append({"label": label, "version": inputs[label + "Version"],
                           "sourceFingerprint": self.FINGERPRINT, "codeFingerprint": self.CODE,
                           "assets": [asset]})
            record = {"platform": "macos", "artifactKind": "desktop-package", "localPath": str(path),
                      "sha256": inputs[label + "Sha256"], "size": len(data),
                      "evidenceClass": "local-verified", "sourceSha": inputs["sourceSha"],
                      "sourceFingerprint": self.FINGERPRINT}
            record.update((record_changes or {}).get(label, {}))
            registry.register_artifact(root, record)
        receipt = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False,
                   "nativeOs": "macOS-test-fixture", "architecture": "arm64",
                   "sourceFingerprint": self.FINGERPRINT, "builds": builds,
                   "manifest": {"assets": copy.deepcopy(builds[1]["assets"])}}
        if change_receipt:
            change_receipt(receipt)
        path = root / "fixture-receipt.json"
        path.write_text(json.dumps(receipt))
        path.chmod(0o600)
        paths["receipt"] = path
        raw = path.read_bytes()
        record = {"platform": "macos", "artifactKind": "fixture-receipt", "localPath": str(path),
                  "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                  "evidenceClass": "local-verified", "sourceSha": inputs["sourceSha"],
                  "sourceFingerprint": self.FINGERPRINT}
        record.update((record_changes or {}).get("receipt", {}))
        inputs["fixtureReceiptArtifactId"] = registry.register_artifact(root, record)["artifactId"]
        return inputs, paths

    def test_real_registry_receipt_and_two_current_packages_admit_without_housekeeping(self):
        from agent_tools import native_artifact_registry as registry
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs, _paths = self.registered_pair(root)
            directory = root / ".rag_index/native-artifacts"
            before = {path.name: path.read_bytes() for path in directory.iterdir()}
            calls = []
            with mock.patch.object(registry, "_prepare_registry", side_effect=AssertionError("registry writer used")):
                first = stage.registered_start(root, inputs, runner=complete_runner(inputs, calls))
                second = stage.registered_start(root, inputs, runner=complete_runner(inputs, calls))
            self.assertEqual("complete", first["state"])
            self.assertEqual(first, second)
            self.assertEqual(1, len(calls))
            self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})

    def test_receipt_semantics_refuse_before_any_submission(self):
        changes = [lambda value: value.update(testOnly=False),
                   lambda value: value.update(productionTrustChanged=True),
                   lambda value: value.update(sourceFingerprint="0" * 64),
                   lambda value: value.update(nativeOs="Linux"),
                   lambda value: value.update(architecture="unverified"),
                   lambda value: value["builds"][1].update(version="2.2.7"),
                   lambda value: value["builds"][1].update(codeFingerprint="0" * 64),
                   lambda value: value["builds"][0]["assets"][0].update(sha256="0" * 64),
                   lambda value: value["builds"][0]["assets"][0].update(sizeBytes=1),
                   lambda value: value["builds"][0]["assets"][0].update(displayVersion="2.2.4"),
                   lambda value: value["builds"][0]["assets"].append(copy.deepcopy(value["builds"][0]["assets"][0])),
                   lambda value: value["manifest"].update(assets=[])]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                inputs, _paths = self.registered_pair(root, change_receipt=change)
                runner = mock.Mock(side_effect=AssertionError("untrusted receipt reached transport"))
                with self.assertRaises(ValueError):
                    stage.registered_start(root, inputs, runner=runner)
                runner.assert_not_called()
                self.assertFalse((root / ".rag_index/macos-fixture-stage").exists())

    def test_registry_identity_platform_source_kind_and_fingerprint_refuse(self):
        changes = [(label, field, wrong) for label in ("base", "target", "receipt")
                   for field, wrong in (("platform", "linux"), ("sourceSha", "0" * 40),
                                        ("artifactKind", "unqualified-package"),
                                        ("sourceFingerprint", "0" * 64))]
        for label, field, wrong in changes:
            with self.subTest(label=label, field=field), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                inputs, _paths = self.registered_pair(root, record_changes={label: {field: wrong}})
                runner = mock.Mock(side_effect=AssertionError("untrusted record reached transport"))
                with self.assertRaises(ValueError):
                    stage.registered_start(root, inputs, runner=runner)
                runner.assert_not_called()

    def test_package_basename_cannot_disagree_with_receipt_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs, _paths = self.registered_pair(root, base_name="vpn-control-2.2.4.dmg")
            runner = mock.Mock(side_effect=AssertionError("wrong package filename reached transport"))
            with self.assertRaises(ValueError):
                stage.registered_start(root, inputs, runner=runner)
            runner.assert_not_called()

    def test_changed_registered_receipt_or_package_bytes_refuse_before_submission(self):
        for label in ("base", "target", "receipt"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                inputs, paths = self.registered_pair(root)
                paths[label].write_bytes(b"changed registered bytes")
                runner = mock.Mock(side_effect=AssertionError("stale registry bytes reached transport"))
                with self.assertRaises(ValueError):
                    stage.registered_start(root, inputs, runner=runner)
                runner.assert_not_called()

    def test_registered_package_change_during_submission_cannot_report_success_or_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs, paths = self.registered_pair(root)
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                paths["target"].write_bytes(b"changed during acknowledged native call")
                return subprocess.CompletedProcess(argv, 0, json.dumps(observed(inputs)).encode(), b"")
            with self.assertRaises(ValueError):
                stage.registered_start(root, inputs, runner=runner)
            result = stage.collect(root, {"correlationId": inputs["correlationId"]})
            self.assertEqual("unknown", result["state"], "artifact closing failure persisted false completion")
            self.assertFalse((root / ".rag_index/macos-fixture-stage" / inputs["correlationId"] / "complete.json").exists())
            with self.assertRaises(ValueError):
                stage.registered_start(root, inputs, runner=runner)
            self.assertEqual(1, len(calls))

    def test_package_change_after_complete_write_retains_negative_closing_evidence_and_never_replays(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs, paths = self.registered_pair(root)
            original_write = stage._write
            calls = []
            def interposed_write(directory, name, raw):
                original_write(directory, name, raw)
                if name == "complete.json":
                    paths["target"].write_bytes(b"changed after complete evidence write")
            with mock.patch.object(stage, "_write", side_effect=interposed_write):
                with self.assertRaises(ValueError):
                    stage.registered_start(root, inputs, runner=complete_runner(inputs, calls))
            journal = root / ".rag_index/macos-fixture-stage" / inputs["correlationId"]
            self.assertTrue((journal / "complete.json").exists(), "original completion evidence was discarded")
            self.assertEqual("unknown", stage.collect(root, {"correlationId": inputs["correlationId"]})["state"])
            never = mock.Mock(side_effect=AssertionError("closing failure replayed the guest operation"))
            self.assertEqual("unknown", stage.status(root, {"correlationId": inputs["correlationId"]}, runner=never)["state"])
            self.assertEqual("unknown", stage.start(root, inputs, runner=never)["state"])
            with self.assertRaises(ValueError):
                stage.registered_start(root, inputs, runner=never)
            never.assert_not_called()
            self.assertEqual(1, len(calls))


class PublicFixtureStageRoutesTests(unittest.TestCase):
    def setUp(self):
        from agent_tools import mcp_server
        from agent_tools.tests.route_adapter import bind_routes
        self.server = mcp_server
        bind_routes(self, self.server, stage)
        enrichment = mock.patch.object(self.server, "_native_response",
                                       side_effect=lambda _tool, _action, value, _inputs: value)
        enrichment.start()
        self.addCleanup(enrichment.stop)

    def test_public_routes_preserve_inputs_and_batch_allowlist_stays_finite(self):
        for suffix, method in (("start", "registered_start"), ("status", "status"), ("collect", "collect")):
            inputs = request() if suffix == "start" else {"correlationId": CORRELATION}
            result = {"ok": True, "state": "complete", "correlationId": CORRELATION,
                      "nativeActionAllowed": False, "replayAllowed": False}
            action = "macos-fixture-stage-" + suffix
            with self.subTest(action=action), mock.patch.object(stage, method, return_value=result) as effect:
                value = self.server.vm_workflow(action, inputs)
                effect.assert_called_once_with(self.server.REPO_ROOT, inputs)
                self.assertTrue(value["ok"])
                self.assertFalse(value["productAction"])
                self.assertFalse(value["nativeActionAllowed"])
                self.assertFalse(value["replayAllowed"])
                effect.reset_mock()
                with self.assertRaisesRegex(ValueError, "not allowlisted"):
                    self.server._native_fixed_dispatch("vm", action, inputs)
                effect.assert_not_called()

    def test_unsupported_program_shell_and_completion_overrides_refuse_before_registry_or_transport(self):
        from agent_tools import native_artifact_registry as registry
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(self.server, "REPO_ROOT", Path(temporary)), \
             mock.patch.object(registry, "verify_artifact_readonly", side_effect=AssertionError("invalid request read registry")) as verify, \
             mock.patch.object(stage.subprocess, "Popen", side_effect=AssertionError("invalid request launched transport")) as popen:
            for key in ("shell", "command", "program", "runner", "_completion_guard"):
                with self.subTest(key=key):
                    inputs = request() | {key: "unapproved override"}
                    value = self.server.vm_workflow("macos-fixture-stage-start", inputs)
                    self.assertFalse(value["ok"])
                    self.assertEqual("unknown", value["state"])
                    self.assertFalse(value["nativeActionAllowed"])
                    self.assertFalse(value["replayAllowed"])
            verify.assert_not_called()
            popen.assert_not_called()
            self.assertEqual([], list(Path(temporary).iterdir()))

    def test_real_cli_lists_and_dispatches_all_three_actions_from_saved_input_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inputs.json"
            for suffix, method in (("start", "registered_start"), ("status", "status"), ("collect", "collect")):
                inputs = request() if suffix == "start" else {"correlationId": CORRELATION}
                path.write_text(json.dumps(inputs))
                result = {"ok": True, "state": "complete", "correlationId": CORRELATION,
                          "nativeActionAllowed": False, "replayAllowed": False}
                output = io.StringIO()
                with self.subTest(suffix=suffix), mock.patch.object(stage, method, return_value=result) as effect, \
                     contextlib.redirect_stdout(output):
                    status = self.server.main(["vm-workflow", "macos-fixture-stage-" + suffix,
                                               "--inputs-file", str(path)])
                self.assertEqual(0, status)
                self.assertTrue(json.loads(output.getvalue())["ok"])
                effect.assert_called_once_with(self.server.REPO_ROOT, inputs)


class RecordedBeforeimageTests(unittest.TestCase):
    def test_all_recorded_causal_source_beforeimages_match_their_provenance(self):
        for name in ("macos_explicit_stage_context", "macos_fixture_stage_initial",
                     "macos_stage_journal_identity", "macos_stage_artifact_closing"):
            with self.subTest(name=name):
                folder = Path(__file__).parent / "fixtures" / name
                provenance = json.loads((folder / "provenance.json").read_text())
                self.assertEqual(provenance["fragmentSha256"],
                                 hashlib.sha256((folder / "before.source").read_bytes()).hexdigest())


@unittest.skipUnless(os.name == "posix", "preserved Tart adapter imports POSIX-only locking")
class PreservedImplicitGuestTests(unittest.TestCase):
    def test_original_command_exposes_historical_vm_dependency_without_running_it(self):
        folder = Path(__file__).parent / "fixtures/macos_explicit_stage_context"
        source = folder / "before.source"
        provenance = json.loads((folder / "provenance.json").read_text())
        self.assertEqual(provenance["fragmentSha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        loader = importlib.machinery.SourceFileLoader("preserved_macos_implicit_stage", str(source))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        before = importlib.util.module_from_spec(spec)
        loader.exec_module(before)
        legacy = request()
        del legacy["schemaVersion"]
        legacy.pop("fixtureReceiptArtifactId", None)
        del legacy["environmentContext"]
        legacy["guestRoot"] = "/Users/admin/macos-parity" + SOURCE[:7]
        command = before._command(legacy, "mutate")
        self.assertEqual("vpn-control-boot-control53", command[2])
        self.assertNotEqual(request()["environmentContext"]["vmName"], command[2])


@unittest.skipUnless(sys.platform == "darwin", "actual macOS account and boot-session binding")
class LocalMacosGuestProgramTests(unittest.TestCase):
    def setUp(self):
        import pwd
        self.account = pwd.getpwuid(os.getuid())
        self.home = Path(self.account.pw_dir).resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix=".mcp-fixture-stage-test-", dir=self.home)
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Path(self.temporary.name).resolve()
        self.inputs = request()
        self.inputs["correlationId"] = str(uuid4())
        boot = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"],
                              capture_output=True, text=True, check=True).stdout.strip().lower()
        self.inputs["environmentContext"].update(guestUser=self.account.pw_name, guestUid=os.getuid(),
                                                 guestHome=str(self.home), guestBootSessionUuid=boot)
        self.inputs["guestRoot"] = str(self.fixture)
        self.paths = {}
        for label, data in (("base", BASE_DATA), ("target", TARGET_DATA)):
            directory = self.fixture / "pair/packages" / label
            directory.mkdir(parents=True, mode=0o700)
            path = directory / ("vpn-control-" + self.inputs[label + "Version"] + ".dmg")
            path.write_bytes(data)
            path.chmod(0o644)
            self.paths[label] = path

    def run_guest(self, inputs=None, mode="mutate"):
        inputs = inputs or self.inputs
        command = stage._command(inputs, mode)
        # The only transport seam replaces Tart/current Python. The fixed
        # bootstrap, stdin bytes, hash, length, intent and file execution remain.
        # 60 s: on a directory-bound host the absent-account directory lookup alone took 10.03 s.
        return subprocess.run([sys.executable, *command[5:]], input=stage._GUEST_CODE.encode(),
                              capture_output=True, timeout=60, check=False)

    def assert_pair_writable(self):
        for path in self.paths.values():
            self.assertEqual(0o644, stat.S_IMODE(path.stat().st_mode))

    def test_actual_whole_pair_verification_precedes_mode_changes(self):
        invalid = copy.deepcopy(self.inputs)
        invalid["targetSha256"] = "0" * 64
        rejected = self.run_guest(invalid)
        self.assertNotEqual(0, rejected.returncode)
        self.assert_pair_writable()

    def test_actual_saved_program_repairs_both_files_and_inspects_original_only(self):
        accepted = self.run_guest()
        self.assertEqual(0, accepted.returncode, accepted.stderr)
        self.assertEqual(observed(self.inputs), json.loads(accepted.stdout))
        programme = self.fixture / ".mcp-fixture-stage" / self.inputs["correlationId"] / "program.py"
        self.assertEqual(stage._GUEST_CODE.encode(), programme.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(programme.stat().st_mode))
        for path in self.paths.values():
            self.assertEqual(0o444, stat.S_IMODE(path.stat().st_mode))
        self.assertEqual(0, self.run_guest(mode="inspect").returncode)
        self.assertNotEqual(0, self.run_guest(mode="mutate").returncode)

    def test_wrong_actual_account_uid_home_and_boot_refuse_before_fixture_mutation(self):
        for key, invalid in (("guestUser", "other_fixture_user"), ("guestUid", os.getuid() + 1),
                             ("guestHome", str(self.home) + "-other"), ("guestBootSessionUuid", BOOT)):
            with self.subTest(key=key):
                value = copy.deepcopy(self.inputs)
                value["environmentContext"][key] = invalid
                if key == "guestHome":
                    # Remain structurally admissible so the real bootstrap, not
                    # host descendant validation, rejects the current identity.
                    value["guestRoot"] = invalid + "/" + self.fixture.name
                result = self.run_guest(value)
                self.assertNotEqual(0, result.returncode)
                self.assert_pair_writable()

    def test_unsafe_target_mode_refuses_before_base_changes(self):
        self.paths["target"].chmod(0o666)
        self.assertNotEqual(0, self.run_guest().returncode)
        self.assertEqual(0o644, stat.S_IMODE(self.paths["base"].stat().st_mode))

    def test_target_symlink_refuses_before_base_changes(self):
        backing = self.paths["target"].with_suffix(".inert")
        self.paths["target"].rename(backing)
        self.paths["target"].symlink_to(backing.name)
        self.assertNotEqual(0, self.run_guest().returncode)
        self.assertEqual(0o644, stat.S_IMODE(self.paths["base"].stat().st_mode))
        self.assertEqual(0o644, stat.S_IMODE(backing.stat().st_mode))

    def test_inspection_never_repairs_writable_files(self):
        result = self.run_guest(mode="inspect")
        self.assertNotEqual(0, result.returncode)
        self.assert_pair_writable()

    def test_missing_or_changed_transferred_program_refuses_before_staging(self):
        command = stage._command(self.inputs, "mutate")
        for payload in (b"", stage._GUEST_CODE.encode() + b"\n"):
            with self.subTest(bytes=len(payload)):
                result = subprocess.run([sys.executable, *command[5:]], input=payload,
                                        capture_output=True, timeout=10, check=False)
                self.assertNotEqual(0, result.returncode)
                self.assert_pair_writable()
                group = self.fixture / ".mcp-fixture-stage" / self.inputs["correlationId"]
                self.assertFalse((group / "program.py").exists())
                self.assertFalse((group / "effect-intent.json").exists())
                self.assertFalse((self.fixture / ".mcp-fixture-stage-owner.json").exists())

    def test_symlinked_fixture_root_refuses_before_original_files_are_touched(self):
        alias = self.fixture / "root-alias"
        alias.symlink_to(self.fixture, target_is_directory=True)
        value = self.inputs | {"guestRoot": str(alias)}
        self.assertNotEqual(0, self.run_guest(value).returncode)
        self.assert_pair_writable()

    def test_saved_program_tamper_refuses_inspection(self):
        self.assertEqual(0, self.run_guest().returncode)
        programme = self.fixture / ".mcp-fixture-stage" / self.inputs["correlationId"] / "program.py"
        self.assertTrue(programme.is_file())
        programme.chmod(0o600)
        programme.write_text("raise AssertionError('tampered programme executed')\n")
        programme.chmod(0o600)
        rejected = self.run_guest(mode="inspect")
        self.assertNotEqual(0, rejected.returncode)
        self.assertNotIn(b"tampered programme executed", rejected.stdout)
        self.assertNotIn(b"tampered programme executed", rejected.stderr)

    def test_lost_actual_mutation_response_recovers_only_through_inspection(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv[10])
            completed = subprocess.run([sys.executable, *argv[5:]], **kwargs)
            self.assertEqual(0, completed.returncode, completed.stderr)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return completed
        host_state = self.fixture / "host-state"
        host_state.mkdir()
        original = stage.start(host_state, self.inputs, runner=runner)
        self.assertEqual("unknown", original["state"])
        self.assertEqual(original, stage.start(host_state, self.inputs, runner=runner))
        self.assertEqual(["mutate"], calls)
        final = stage.status(host_state, {"correlationId": self.inputs["correlationId"]}, runner=runner)
        self.assertEqual("complete", final["state"])
        self.assertEqual(["mutate", "inspect"], calls)


if __name__ == "__main__":
    unittest.main()
