"""Causal guards for the fixed, endpoint-bound Android runtime acceptance."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import android_runtime_acceptance as subject

RUNTIME = "1f3d981d-7d2a-4d15-8cdf-34b884b0e091"
ENDPOINT = "2f3d981d-7d2a-4d15-8cdf-34b884b0e091"
STAGE = "3f3d981d-7d2a-4d15-8cdf-34b884b0e091"
CAMPAIGN = "4f3d981d-7d2a-4d15-8cdf-34b884b0e091"
PACKAGE = "a" * 64
SOURCE = "b" * 40


class AndroidRuntimeAcceptanceTest(unittest.TestCase):
    def _intent(self, root: Path) -> dict[str, object]:
        return {
            "schema": 1, "kind": "android-runtime-acceptance", "correlationId": RUNTIME,
            "parentCorrelationId": ENDPOINT, "campaignId": CAMPAIGN, "sourceSha": SOURCE,
            "packageSha256": PACKAGE, "expectedOwner": "owner-a", "expectedRevision": 7,
            "host": "archlinux", "device": "api29", "api": 29, "expectedAvd": "owned-api29",
            "remoteRoot": "/private/fixture", "cliStageCorrelationId": STAGE,
            "parentLeaseSha256": "c" * 64,
            "cliPath": "/private/fixture/android-cli-stage-" + STAGE + "/tree/vpn-control",
            "location": subject._FIXED_LOCATION, "testUrl": subject._FIXED_URL,
            "cliManifestSha256": "d" * 64, "cliRpmSha256": "e" * 64, "cliLauncherSha256": "c" * 64, "cliDesktopJarSha256": "f" * 64,
            "fixtureEventCounts": {"socksConnected": 0, "socksRejected": 0, "health": 0, "traffic": 0, "subscription": 0},
        }

    def _endpoint(self, device="api29") -> dict[str, object]:
        api = {"api29": 29, "api35": 35}[device]
        return {"host": "archlinux", "device": device, "correlationId": ENDPOINT,
                "remoteRoot": "/private/fixture", "sourceSha": SOURCE, "targetArtifactId": "target-apk", "remote": {
            "api": api, "avd": "owned-" + device, "serial": "emulator-1", "adb": "/bin/adb", "cli": "/bin/vpn-control",
            "host": "archlinux", "packageSha256": PACKAGE,
            "owner": "owner-a", "revision": 7, "campaignId": CAMPAIGN, "httpsHostPort": 41001, "socksHostPort": 41002,
        }}

    def _config(self, device="api29"):
        api = {"api29": 29, "api35": 35}[device]
        profile = {"adb": "/bin/adb", "cli": "/bin/vpn-control", "serial": "emulator-1",
                   "expectedAvd": "owned-" + device, "api": api}
        return SimpleNamespace(hosts={"archlinux": SimpleNamespace(android_devices={device: profile},
                                                               fixture_transfer_root=Path("/private/fixture"))})

    def test_activity_record_is_create_only_and_binds_parent_before_worker(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            activity = {"schema": 1, "kind": "android-runtime-acceptance", "state": "running",
                        "parentCorrelationId": ENDPOINT, "runtimeCorrelationId": RUNTIME,
                        "campaignId": CAMPAIGN, "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": "c" * 64,
                        "endpoint": {"state": "ready", "correlationId": ENDPOINT,
                                     "sourcePackageSha256": PACKAGE, "owner": "owner-a"},
                        "fixture": {"campaignId": CAMPAIGN, "deviceUid": "2000", "api": 29, "avd": "owned-api29"}}
            output = io.StringIO()
            with mock.patch("sys.argv", ["remote", str(root), json.dumps(activity)]), contextlib.redirect_stdout(output):
                exec(subject._ACTIVITY_CREATE, {"__name__": "remote_test"})
            self.assertEqual({"state": "created", "reason": None, "correlationId": RUNTIME}, json.loads(output.getvalue()))
            path = root / ("android-runtime-acceptance-" + RUNTIME + ".json")
            self.assertEqual(activity, json.loads(path.read_text()))
            # RED prior to create-only behavior: a second attempt could overwrite the binding.
            output = io.StringIO()
            with mock.patch("sys.argv", ["remote", str(root), json.dumps({**activity, "campaignId": "other"})]), contextlib.redirect_stdout(output):
                exec(subject._ACTIVITY_CREATE, {"__name__": "remote_test"})
            self.assertEqual("unknown", json.loads(output.getvalue())["state"])
            self.assertEqual(activity, json.loads(path.read_text()))

    def _seed_parent_lease(self, root, device="api29", value=None):
        with subject.android_endpoint_admission._shared_device_lease(root, "archlinux", device) as path:
            subject.android_native_fixture_lifecycle.android_native_fixture.write_private_plan(path, value or {
                "owner": "android-endpoint", "correlationId": ENDPOINT, "host": "archlinux", "device": device})

    def _start_case(self, device="api29", endpoint=None, lease_value=None):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            self._seed_parent_lease(root, device, lease_value)
            calls: list[tuple[str, ...]] = []
            commands = []
            def ssh_argv(*_args, **kwargs):
                commands.append(kwargs["command"])
                return ("ssh", str(len(calls)))
            def probe(argv, _timeout):
                calls.append(tuple(argv))
                if len(calls) == 1:
                    return 0, json.dumps({"state": "created", "correlationId": RUNTIME}).encode()
                self.assertTrue(subject._path(root, RUNTIME).exists(), "local intent must precede submit")
                return 0, json.dumps({"state": "submitted", "correlationId": RUNTIME, "identity": {"pid": 19}}).encode()
            with mock.patch.object(subject.android_endpoint_admission, "_status_intent", return_value=endpoint or self._endpoint(device)), \
                    mock.patch.object(subject.android_endpoint_admission, "status", return_value={"state": "ready"}), \
                    mock.patch.object(subject.android_native_fixture_lifecycle, "status", return_value={"state": "running", "eventCounts": {"socksConnected": 0, "socksRejected": 0, "health": 0, "traffic": 0, "subscription": 0}}), \
                    mock.patch.object(subject.android_cli_stage, "status", return_value={"ok": True, "state": "published", "sourceSha": SOURCE, "receipt": {"cliPath": self._intent(root)["cliPath"], "launcherSha256": "c" * 64, "manifestSha256": "d" * 64, "rpmSha256": "e" * 64, "desktopJarSha256": "f" * 64}}), \
                    mock.patch.object(subject.ssh_transport, "load_config", return_value=self._config(device)), \
                    mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(subject.android_observation, "_profile", return_value=self._config(device).hosts["archlinux"].android_devices[device]), \
                    mock.patch.object(subject.ssh_transport, "build_ssh_argv", side_effect=ssh_argv), \
                    mock.patch.object(subject.android_observation, "_run_probe", side_effect=probe):
                result = subject.start(root, RUNTIME, ENDPOINT, STAGE)
            self.assertEqual("submitted", result["state"])
            self.assertFalse(result["replayAllowed"])
            self.assertEqual(2, len(calls))
            intent = subject._load(root, RUNTIME)
            self.assertEqual(ENDPOINT, intent["parentCorrelationId"])
            self.assertEqual(subject._FIXED_LOCATION, intent["location"])
            self.assertEqual(subject._FIXED_URL, intent["testUrl"])
            self.assertEqual(device, intent["device"])
            activity = json.loads(commands[0][-1])
            self.assertEqual({"campaignId": CAMPAIGN, "deviceUid": "2000", "api": {"api29": 29, "api35": 35}[device], "avd": "owned-" + device}, activity["fixture"])
            self.assertEqual({"api29": 29, "api35": 35}[device], intent["api"])
            with self.assertRaises(FileExistsError):
                subject._save(root, self._intent(root))

    def test_start_journals_then_creates_parent_guard_before_one_submit(self):
        self._start_case()

    def test_api35_start_uses_exact_configured_endpoint_profile(self):
        self._start_case("api35")

    def test_api35_start_rejects_crossed_endpoint_profile_before_activity(self):
        for key, value in (("api", 29), ("avd", "owned-api29"), ("serial", "emulator-other"), ("host", "foreign")):
            endpoint = self._endpoint("api35")
            endpoint["remote"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self._start_case("api35", endpoint)

    def test_api35_crossed_local_lease_never_creates_runtime_intent_or_activity(self):
        crossed = {"owner": "android-endpoint", "correlationId": ENDPOINT, "host": "archlinux", "device": "api29"}
        with self.assertRaises(ValueError):
            self._start_case("api35", lease_value=crossed)

    def test_status_rejects_crossed_profile_or_source_before_transport(self):
        for field, value in (("device", "api35"), ("sourceSha", "0" * 40), ("host", "foreign")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve(); intent = self._intent(root); subject._save(root, intent)
                endpoint = self._endpoint(); endpoint[field] = value
                with mock.patch.object(subject.android_endpoint_admission, "_status_intent", return_value=endpoint), mock.patch.object(subject.android_observation, "_run_probe") as probe:
                    self.assertEqual("parent_endpoint_changed", subject.status(root, RUNTIME)["reason"])
                    probe.assert_not_called()

    def test_distinct_child_correlation_cannot_submit_over_parent_activity(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); self._seed_parent_lease(root); other = "5f3d981d-7d2a-4d15-8cdf-34b884b0e091"
            def probe(_argv, _timeout): return 0, json.dumps({"state": "created", "correlationId": RUNTIME}).encode()
            common = [
                mock.patch.object(subject.android_endpoint_admission, "_status_intent", return_value=self._endpoint()),
                mock.patch.object(subject.android_endpoint_admission, "status", return_value={"state": "ready"}),
                mock.patch.object(subject.android_native_fixture_lifecycle, "status", return_value={"state": "running", "eventCounts": {"socksConnected": 0, "socksRejected": 0, "health": 0, "traffic": 0, "subscription": 0}}),
                mock.patch.object(subject.android_cli_stage, "status", return_value={"ok": True, "state": "published", "sourceSha": SOURCE, "receipt": {"cliPath": self._intent(root)["cliPath"], "launcherSha256": "c" * 64, "manifestSha256": "d" * 64, "rpmSha256": "e" * 64, "desktopJarSha256": "f" * 64}}),
                mock.patch.object(subject.ssh_transport, "load_config", return_value=self._config()),
                mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)),
                mock.patch.object(subject.android_observation, "_profile", return_value=self._config().hosts["archlinux"].android_devices["api29"]),
                mock.patch.object(subject.ssh_transport, "build_ssh_argv", return_value=("ssh", "fixed")),
                mock.patch.object(subject.android_observation, "_run_probe", side_effect=probe),
            ]
            with contextlib.ExitStack() as stack:
                for patcher in common: stack.enter_context(patcher)
                subject.start(root, RUNTIME, ENDPOINT, STAGE)
                with self.assertRaises(FileExistsError): subject.start(root, other, ENDPOINT, STAGE)
                self.assertEqual(2, subject.android_observation._run_probe.call_count)

    def test_uncertain_activity_create_never_submits_or_replays(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); self._seed_parent_lease(root)
            with mock.patch.object(subject.android_endpoint_admission, "_status_intent", return_value=self._endpoint()), \
                    mock.patch.object(subject.android_endpoint_admission, "status", return_value={"state": "ready"}), \
                    mock.patch.object(subject.android_native_fixture_lifecycle, "status", return_value={"state": "running", "eventCounts": {"socksConnected": 0, "socksRejected": 0, "health": 0, "traffic": 0, "subscription": 0}}), \
                    mock.patch.object(subject.android_cli_stage, "status", return_value={"ok": True, "state": "published", "sourceSha": SOURCE, "receipt": {"cliPath": self._intent(root)["cliPath"], "launcherSha256": "c" * 64, "manifestSha256": "d" * 64, "rpmSha256": "e" * 64, "desktopJarSha256": "f" * 64}}), \
                    mock.patch.object(subject.ssh_transport, "load_config", return_value=self._config()), \
                    mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(subject.android_observation, "_profile", return_value=self._config().hosts["archlinux"].android_devices["api29"]), \
                    mock.patch.object(subject.ssh_transport, "build_ssh_argv", return_value=("ssh", "fixed")), \
                    mock.patch.object(subject.android_observation, "_run_probe", return_value=(1, b"")) as probe:
                result = subject.start(root, RUNTIME, ENDPOINT, STAGE)
            self.assertEqual("unknown", result["state"])
            self.assertEqual("activity_create_unknown", result["reason"])
            self.assertEqual(1, probe.call_count)
            self.assertIsNotNone(subject._load(root, RUNTIME))

    def test_worker_uses_only_fixed_public_commands_and_restores_empty_baseline(self):
        # This catches a regression that would turn the acceptance adapter into a generic command runner.
        self.assertIn("https://localhost:18080/traffic", subject._REMOTE)
        self.assertIn("socks://127.0.0.1:18081#NativeFixture", subject._REMOTE)
        for command in ("'locations','add'", "'source','set','current-locations'", "'on'", "'find-best'", "'stats'", "'off'", "'locations','delete'"):
            self.assertIn(command, subject._REMOTE)
        self.assertIn("Every mutation takes its owner/revision from a fresh public STATUS", subject._REMOTE)
        self.assertIn("original_url=settings.get('validation.test-url')", subject._REMOTE)
        self.assertIn("closing_source!=source", subject._REMOTE)
        self.assertIn("closing_settings!=settings", subject._REMOTE)
        self.assertIn("closing_locations.get('locations')!=[]", subject._REMOTE)
        self.assertIn("android-runtime-acceptance-'+correlation+'.terminal.json", subject._REMOTE)
        self.assertNotIn("shell=True", subject._REMOTE)

    def test_status_requires_exact_worker_terminal_and_parent_terminal_record(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); remote = root / "remote"; remote.mkdir(mode=0o700)
            intent = self._intent(root); intent["remoteRoot"] = str(remote)
            subject._save(root, intent)
            activity = {"schema": 1, "kind": "android-runtime-acceptance", "state": "running",
                        "parentCorrelationId": ENDPOINT, "runtimeCorrelationId": RUNTIME, "campaignId": CAMPAIGN,
                        "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": "c" * 64,
                        "endpoint": {"state": "ready", "correlationId": ENDPOINT, "sourcePackageSha256": PACKAGE, "owner": "owner-a"},
                        "fixture": {"campaignId": CAMPAIGN, "deviceUid": "2000", "api": 29, "avd": "owned-api29"}}
            activity_path = remote / ("android-runtime-acceptance-" + RUNTIME + ".json")
            activity_path.write_text(json.dumps(activity)); activity_path.chmod(0o600)
            job = remote / ("android-runtime-job-" + RUNTIME); job.mkdir(mode=0o700)
            for name, value in (("intent.json", intent), ("identity.json", {"pid": os.getpid(), "startTicks": 1})):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            result = {"state": "complete", "sourcePackageSha256": PACKAGE, "parentCorrelationId": ENDPOINT,
                      "campaignId": CAMPAIGN, "opening": {"owner": "owner-a", "revision": 7},
                      "selectedProxy": True, "outboundEvidence": True, "statsObserved": True, "closingOwner": "owner-a", "closingRevision": 12, "admittedMode": "proxy-only",
                      "restoration": {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
                                      "selectedNull": True, "activeNull": True, "runtimeOff": True}}
            receipt = job / "result.json"; receipt.write_text(json.dumps({"state": "complete", "result": result})); receipt.chmod(0o600)
            terminal = {"schema": 1, "kind": "android-runtime-acceptance", "state": "stopped",
                        "parentCorrelationId": ENDPOINT, "runtimeCorrelationId": RUNTIME, "campaignId": CAMPAIGN,
                        "sourcePackageSha256": PACKAGE, "expectedOwner": "owner-a", "parentLeaseSha256": "c" * 64, "closingOwner": "owner-a", "closingRevision": 12, "admittedMode": "proxy-only", "restoration": result["restoration"], "terminal": True}
            path = remote / ("android-runtime-acceptance-" + RUNTIME + ".terminal.json"); path.write_text(json.dumps(terminal)); path.chmod(0o600)
            output = io.StringIO()
            with mock.patch("sys.argv", ["status", str(remote), RUNTIME, json.dumps(intent)]), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): exec(subject._STATUS, {"__name__": "remote_test"})
            observed = json.loads(output.getvalue())
            self.assertEqual("complete", observed["state"])
            activity["fixture"]["api"] = 35
            activity_path.write_text(json.dumps(activity)); activity_path.chmod(0o600)
            output = io.StringIO()
            with mock.patch("sys.argv", ["status", str(remote), RUNTIME, json.dumps(intent)]), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): exec(subject._STATUS, {"__name__": "remote_test"})
            self.assertEqual("activity_binding_invalid", json.loads(output.getvalue())["reason"])
            activity["fixture"]["api"] = 29
            activity_path.write_text(json.dumps(activity)); activity_path.chmod(0o600)
            # The remote completion cannot be substituted from a different local
            # child claim: parent cleanup consumes this exact raw-lease digest.
            terminal["parentLeaseSha256"] = "0" * 64
            path.write_text(json.dumps(terminal)); path.chmod(0o600)
            output = io.StringIO()
            with mock.patch("sys.argv", ["status", str(remote), RUNTIME, json.dumps(intent)]), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): exec(subject._STATUS, {"__name__": "remote_test"})
            self.assertEqual("unknown", json.loads(output.getvalue())["state"])
            terminal["parentLeaseSha256"] = intent["parentLeaseSha256"]
            path.write_text(json.dumps(terminal)); path.chmod(0o600)
            # A terminal worker result without the parent-cleanup release proof must stay unknown.
            path.unlink(); output = io.StringIO()
            with mock.patch("sys.argv", ["status", str(remote), RUNTIME, json.dumps(intent)]), contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit): exec(subject._STATUS, {"__name__": "remote_test"})
            self.assertEqual("unknown", json.loads(output.getvalue())["state"])

    def test_collect_requires_new_fixture_socks_and_traffic_events(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); intent = self._intent(root)
            intent["fixtureEventCounts"] = {"socksConnected": 2, "socksRejected": 0, "health": 0, "traffic": 3, "subscription": 0}
            subject._save(root, intent)
            complete = {"ok": True, "state": "complete", "correlationId": RUNTIME, "receipt": {"result": {
                "state": "complete", "selectedProxy": True, "outboundEvidence": True, "statsObserved": True,
                "restoration": {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
                                "selectedNull": True, "activeNull": True, "runtimeOff": True}}}}
            stale = {"state": "running", "eventCounts": intent["fixtureEventCounts"]}
            with mock.patch.object(subject, "status", return_value=complete), \
                    mock.patch.object(subject.android_endpoint_admission, "status", return_value={"state": "ready"}), \
                    mock.patch.object(subject.android_native_fixture_lifecycle, "status", return_value=stale):
                result = subject.collect(root, RUNTIME)
            self.assertEqual("unknown", result["state"])
            self.assertEqual("fixture_outbound_not_proved", result["reason"])

    def test_status_rejects_tampered_local_intent_before_parent_route(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); bad = self._intent(root); bad.pop("parentCorrelationId")
            subject._save(root, bad)
            with mock.patch.object(subject.android_endpoint_admission, "status") as parent:
                result = subject.status(root, RUNTIME)
            self.assertEqual("unknown", result["state"])
            self.assertEqual("local_intent_invalid", result["reason"])
            parent.assert_not_called()

    def test_status_missing_intent_is_read_only(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            result = subject.status(root, RUNTIME)
            self.assertEqual("unknown", result["state"])
            self.assertFalse((root / ".rag_index").exists())

    def test_collect_never_promotes_incomplete_restoration(self):
        partial = {"ok": True, "state": "complete", "correlationId": RUNTIME,
                   "receipt": {"result": {"state": "complete", "selectedProxy": True, "outboundEvidence": True,
                                              "statsObserved": True, "restoration": {"runtimeOff": True}}}}
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(subject, "status", return_value=partial):
            result = subject.collect(Path(raw), RUNTIME)
        self.assertEqual("unknown", result["state"])
        self.assertEqual("terminal_binding_invalid", result["reason"])


class RuntimeTerminalTypesTest(unittest.TestCase):
    RESTORATION = {"settings": True, "source": True, "routing": True, "locationsEmpty": True,
                   "selectedNull": True, "activeNull": True, "runtimeOff": True}

    def observe(self, mutation=None):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            intent = AndroidRuntimeAcceptanceTest()._intent(root)
            subject._save(root, intent)
            restoration = dict(self.RESTORATION)
            if mutation is not None: mutation(restoration)
            terminal = {"state": "complete", "receipt": {"result": {
                "state": "complete", "selectedProxy": True, "outboundEvidence": True,
                "statsObserved": True, "restoration": restoration}}}
            campaign = {"state": "running", "eventCounts": {
                **intent["fixtureEventCounts"], "socksConnected": 1, "traffic": 1}}
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            # Only the external worker and fixture observations are synthetic;
            # collect and its private intent reader execute unchanged.
            with mock.patch.object(subject, "status", return_value=terminal) as status, mock.patch.object(
                    subject.android_native_fixture_lifecycle, "status", return_value=campaign) as fixture:
                actual = subject.collect(root, RUNTIME)
            status.assert_called_once_with(root, RUNTIME)
            self.assertEqual(before, {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()})
            return actual, fixture.call_count

    def test_genuine_complete_restoration_requires_fixture_observation(self):
        actual, count = self.observe()
        self.assertEqual("complete", actual["state"])
        self.assertIs(actual["result"]["restoredEmptyBaseline"], True)
        self.assertEqual(1, count)

    def test_each_numeric_restoration_boolean_stays_unknown_before_fixture(self):
        for key in self.RESTORATION:
            with self.subTest(key=key):
                actual, count = self.observe(lambda value: value.update({key: 1}))
                self.assertEqual("unknown", actual["state"])
                self.assertEqual("terminal_binding_invalid", actual["reason"])
                self.assertEqual(0, count)

    def test_missing_extra_and_false_restoration_stay_unknown(self):
        for mutation in (lambda value: value.pop("settings"), lambda value: value.update(extra=True),
                         lambda value: value.update(settings=False)):
            with self.subTest(mutation=mutation):
                actual, count = self.observe(mutation)
                self.assertEqual("unknown", actual["state"])
                self.assertEqual(0, count)


if __name__ == "__main__":
    unittest.main()

# Executable remote guards: the script must stop before the first public write.
class AndroidRuntimeRemoteGuardTest(unittest.TestCase):
    def test_opening_revision_drift_rejects_before_mutation(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); root.chmod(0o700)
            corr = RUNTIME; job = root / ("android-runtime-job-" + corr); job.mkdir(mode=0o700)
            cli = root / "vpn-control"; cli.write_text("fixture"); cli.chmod(0o700)
            adb = root / "adb"; adb.write_text("fixture"); adb.chmod(0o700)
            launcher = __import__("hashlib").sha256(cli.read_bytes()).hexdigest()
            (root / "android-native-device-api29.lease").write_text(json.dumps({
                "owner": "android-endpoint", "correlationId": ENDPOINT, "host": "archlinux", "device": "api29"}))
            (root / "android-native-device-api29.lease").chmod(0o600)
            calls: list[list[str]] = []
            def completed(argv, **_kwargs):
                calls.append(list(argv))
                if argv[0] == "python3":
                    # The worker verifies the entire published CLI tree before any
                    # public mutation.  Keep this transport response shaped like
                    # android_cli_stage._STATUS rather than bypassing that call.
                    out = json.dumps({"state": "published", "correlationId": STAGE,
                                     "receipt": {"cliPath": str(cli), "manifestSha256": "d" * 64,
                                     "rpmSha256": "e" * 64, "launcherSha256": launcher,
                                     "desktopJarSha256": "f" * 64}}).encode()
                elif argv[0] == str(adb):
                    if argv[3:6] == ["shell", "-T", "id"]: out = b"2000\n"
                    elif argv[3:6] == ["shell", "-T", "getprop"]: out = b"29\n" if argv[-1] == "ro.build.version.sdk" else b"owned-api29\n"
                    elif argv[3:6] == ["shell", "-T", "pm"]: out = b"package:/data/app/x/base.apk\n"
                    elif argv[3:6] == ["shell", "-T", "sha256sum"]: out = (PACKAGE + " /data/app/x/base.apk\n").encode()
                    elif argv[3:5] == ["reverse", "--list"]: out = b"emu tcp:18080 tcp:41001\nemu tcp:18081 tcp:41002\n"
                    else: raise AssertionError(argv)
                else:
                    self.assertEqual(str(cli), argv[0])
                    # The stale opening revision must stop before a command carries --controller-id.
                    self.assertNotIn("--controller-id", argv)
                    out = json.dumps({"ok": True, "final": True, "code": "OK", "controllerId": "owner-a",
                                     "configurationRevision": 8, "data": {"runtimeRunning": False,
                                     "runtimeObservation": "stopped"}}).encode()
                return SimpleNamespace(returncode=0, stdout=out, stderr=b"")
            output = io.StringIO()
            args = [str(adb), str(cli), "emu", "owned-api29", "api29", "29", str(root), corr, "owner-a", "7", PACKAGE,
                    ENDPOINT, CAMPAIGN, "c"*64, STAGE, "d"*64, "e"*64, launcher, "f"*64, "41001", "41002"]
            with mock.patch("sys.argv", ["remote", *args]), mock.patch("subprocess.run", side_effect=completed), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(subject._REMOTE, {"__name__": "remote_test", "public_cli_environment": lambda *_: {}})
            observed = json.loads(output.getvalue())
            self.assertEqual("unknown", observed["state"])
            self.assertEqual("opening_revision_changed", observed["reason"])

    def test_remote_success_and_guard_vectors(self):
        """Run the emitted worker through its public sequence, then perturb fixed guards."""
        def run_case(*, bad: str | None = None, device="api29", mode="proxy-only"):
            api = {"api29": "29", "api35": "35"}[device]
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw); root.chmod(0o700); job = root / ("android-runtime-job-" + RUNTIME); job.mkdir(mode=0o700)
                cli = root / "vpn-control"; cli.write_text("fixture"); cli.chmod(0o700)
                adb = root / "adb"; adb.write_text("fixture"); adb.chmod(0o700)
                launcher = __import__("hashlib").sha256(cli.read_bytes()).hexdigest()
                (root / ("android-native-device-" + device + ".lease")).write_text(json.dumps({"owner":"android-endpoint","correlationId":ENDPOINT,"host":"archlinux","device": "api29" if bad == "crossed-lease" else device}))
                (root / ("android-native-device-" + device + ".lease")).chmod(0o600)
                revision = 7; running = False; active = None; mutations = 0; routing_reads = 0
                settings = {"validation.test-url":"https://old.example/"}; source = {"mode":"current-locations","subscriptionId":None}
                def routing_snapshot():
                    # Product `routing show` carries generated export metadata;
                    # an unchanged ruleset must still restore successfully.
                    nonlocal routing_reads
                    routing_reads += 1
                    prefix = "." + "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + ".example.test"
                    domains = [f"d{i:05d}{prefix}" for i in range(56_000)] if bad == "large" else []
                    if bad == "oversize": domains = ["x" * 16_777_216]
                    if bad == "rules" and routing_reads >= 2: domains = ["changed.example"]
                    rules = {"ignore_rules": False, "block_quic_udp_443": False,
                             "proxy_packages": [], "direct_domain_suffixes": domains}
                    return {"routing": {"type": "vpn_control_routing_rules", "version": 7,
                                         "exported_at": f"2026-10-02T00:00:{routing_reads:02d}Z",
                                         "rules": rules}}
                def response(data): return {"ok":True,"final":True,"code":"OK","controllerId":"owner-a","configurationRevision":revision,"data":data}
                def status_data(): return {"runtimeRunning":running,"runtimeObservation":"running" if running else "stopped","configuredMode":mode,"selectedLocationId":None if not active else "selected","activeLocationId":active,"activeMode":mode if running else None,"runtimeId":"runtime-a" if running else None}
                def fake(argv, **_kw):
                    nonlocal revision, running, active, mutations
                    if argv[0] == "python3":
                        out=json.dumps({"state":"published","correlationId":STAGE,"receipt":{"cliPath":str(cli),"manifestSha256":"d"*64,"rpmSha256":"e"*64,"launcherSha256":launcher,"desktopJarSha256":"0"*64 if bad == "jar" else "f"*64}}).encode()
                    elif argv[0] == str(adb):
                        if argv[3:6] == ["shell","-T","id"]: out=b"2000\n"
                        elif argv[3:6] == ["shell","-T","getprop"]: out=(api+"\n").encode() if argv[-1]=="ro.build.version.sdk" else ("owned-"+device+"\n").encode()
                        elif argv[3:6] == ["shell","-T","pm"]: out=b"package:/data/app/x/base.apk\n"
                        elif argv[3:6] == ["shell","-T","sha256sum"]: out=(("0"*64 if bad == "package" and mutations else PACKAGE)+" /data/app/x/base.apk\n").encode()
                        elif argv[3:5] == ["reverse","--list"]: out=b"emu tcp:18080 tcp:41001\nemu tcp:18081 tcp:41002\n" if bad!="routes" else b"emu tcp:18080 tcp:41001\n"
                        else: raise AssertionError(argv)
                    else:
                        words = argv[argv.index("--timeout-seconds") + 2:]
                        if words[:2] == ["diagnostics","export"]: out=(b"[runtime]\nmode=VPN\nvpn_permission_granted=false\nis_vpn_running=false\n" if bad == "mode" else (b"[runtime]\nmode=VPN\nvpn_permission_granted=true\nis_vpn_running=false\n" if mode == "vpn" else b"[runtime]\nmode=PROXY_ONLY\nvpn_permission_granted=false\nis_vpn_running=false\n"))
                        else:
                            mutation = "--controller-id" in words
                            if mutation:
                                words = words[words.index("--if-revision") + 2:]
                            op = tuple(words)
                            if op == ("status",):
                                if bad == "lease" and mutations == 1: (root / "android-native-device-api29.lease").write_text("{}")
                                if bad == "launcher" and mutations == 1: cli.write_text("changed")
                                if bad == "revision" and mutations == 1: revision += 1
                                data=status_data()
                            elif op == ("source","show"): data=source
                            elif op == ("settings","show"): data=settings
                            elif op == ("locations","list"): data={"locations":[]}
                            elif op == ("routing","show"): data=routing_snapshot()
                            elif op == ("stats",): data={"running":running,"runtimeId":("other" if bad == "stats" else "runtime-a") if running else None,"activeMode":mode if running else None}
                            else:
                                mutations += 1
                                if op == ("on",): running=True; active="active-a"
                                elif op == ("off",): running=False; active=None
                                if op not in (("source","set","current-locations"),): revision += 1
                                data=status_data()
                            out=json.dumps(response(data)).encode()
                    return SimpleNamespace(returncode=0,stdout=out,stderr=b"")
                args=[str(adb),str(cli),"emu","owned-"+device,device,api,str(root),RUNTIME,"owner-a","7",PACKAGE,ENDPOINT,CAMPAIGN,"c"*64,STAGE,"d"*64,"e"*64,launcher,"f"*64,"41001","41002"]
                output=io.StringIO()
                with mock.patch("sys.argv",["remote",*args]),mock.patch("subprocess.run",side_effect=fake),contextlib.redirect_stdout(output):
                    try:
                        exec(subject._REMOTE,{"__name__":"remote_test"})
                    except SystemExit:
                        pass
                return json.loads(output.getvalue())
        self.assertEqual("complete", run_case()["state"])
        self.assertEqual("complete", run_case(device="api35")["state"])
        self.assertEqual("vpn-authorized", run_case(device="api35", mode="vpn", bad="large")["admittedMode"])
        self.assertEqual("parent_lease_changed", run_case(device="api35", bad="crossed-lease")["reason"])
        # The full product rules document can exceed the generic 1 MiB public
        # result bound.  Routing reads retain a 16 MiB bounded transport.
        self.assertEqual("complete", run_case(bad="large")["state"])
        self.assertEqual("restoration_failed", run_case(bad="rules")["reason"])
        self.assertEqual("command_failed", run_case(bad="oversize")["reason"])
        self.assertEqual("endpoint_routes_changed", run_case(bad="routes")["reason"])
        self.assertEqual("fresh_revision_changed", run_case(bad="revision")["reason"])
        self.assertEqual("package_changed", run_case(bad="package")["reason"])
        self.assertEqual("parent_lease_changed", run_case(bad="lease")["reason"])
        self.assertEqual("cli_stage_changed", run_case(bad="launcher")["reason"])
        # A stable launcher alone is insufficient: the published desktop JAR is
        # covered by the canonical stage manifest verifier on every write.
        self.assertEqual("cli_stage_changed", run_case(bad="jar")["reason"])
        self.assertEqual("runtime_mode_unadmitted", run_case(bad="mode")["reason"])
        self.assertEqual("stats_invalid", run_case(bad="stats")["reason"])
