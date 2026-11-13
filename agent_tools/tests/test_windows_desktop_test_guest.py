"""The in-guest desktop test runner, run whole on this host through its POSIX seam with a fake JVM.

Nothing here starts Gradle or a JVM: the fake process stands where the source's own wrapper would run,
checks the exact argv and environment the runner gives it, and writes JUnit XML as Gradle does.
"""
import ctypes
import hashlib
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
import zipfile

from agent_tools import windows_desktop_test_guest as guest

OPERATION = "0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e"
COMMIT = "a" * 40
URL = "https://services.gradle.org/distributions/gradle-8.10.2-bin.zip"
# Stands where java.exe would: the runner's argv after the executable, its working directory and environment.
FAKE_JVM = r'''
import json, os, sys, time
argv = sys.argv[1:]
mode = os.environ.get("VCDT_FAKE_MODE", "pass")
record = {"argv": argv, "cwd": os.getcwd(), "env": {key: os.environ.get(key) for key in
          ("JAVA_HOME", "GRADLE_USER_HOME", "TEMP", "TMP", "ANDROID_HOME", "ANDROID_SDK_ROOT", "VPN_CONTROL_DESKTOP_TEST_REPOSITORY",
           "VPN_CONTROL_DESKTOP_TEST_HOME", "GRADLE_OPTS", "JAVA_TOOL_OPTIONS")},
          "testHomeIsFolder": os.path.isdir(os.environ.get("VPN_CONTROL_DESKTOP_TEST_HOME", "")),
          # What the desktop tests that build native probes would start, and whether it is there.
          "dotnet": {"program": os.environ.get("VPN_CONTROL_TEST_DOTNET"), "root": os.environ.get("VPN_CONTROL_TEST_DOTNET_ROOT"),
                     "programExists": os.path.lexists(os.environ.get("VPN_CONTROL_TEST_DOTNET") or "dotnet.exe")}}
with open(os.environ["VCDT_FAKE_RECORD"], "w") as stream:
    json.dump(record, stream)
results = os.path.join("desktopApp", "build", "test-results", "test")
os.makedirs(results)
failure = '<failure message="boom" type="java.lang.AssertionError">trace</failure>' if mode == "fail" else ""
for name, cases in (("Alpha", ('<testcase name="a" classname="com.example.Alpha" time="0.1"/>'
                               '<testcase name="b" classname="com.example.Alpha" time="0.1"><skipped/></testcase>')),
                    ("Beta", '<testcase name="c" classname="com.example.Beta" time="0.2">' + failure + '</testcase>')):
    with open(os.path.join(results, "TEST-com.example." + name + ".xml"), "w") as stream:
        failures = 1 if (mode == "fail" and name == "Beta") else 0
        skipped = 1 if name == "Alpha" else 0
        tests = 2 if name == "Alpha" else 1
        stream.write('<?xml version="1.0" encoding="UTF-8"?><testsuite name="com.example.' + name + '" tests="' + str(tests)
                     + '" skipped="' + str(skipped) + '" failures="' + str(failures) + '" errors="0" time="0.2">' + cases + '</testsuite>')
os.makedirs(os.path.join(results, "binary"))
with open(os.path.join(results, "binary", "results.bin"), "wb") as stream:
    stream.write(b"\0binary")
if mode == "state":
    with open(os.path.join(os.environ["VCDT_FAKE_PROFILE"], ".vpn-control-desktop", "workspace.json"), "a") as stream:
        stream.write("changed")
if mode == "residue":  # What a JVM that ignored user.home would leave beside the work folder.
    os.makedirs(os.path.join(os.environ["VCDT_FAKE_PROFILE"], ".skiko"))
os.makedirs(os.path.join(os.environ["VPN_CONTROL_DESKTOP_TEST_HOME"], ".skiko"))
print("> Task :desktopApp:test")
if mode == "fail":
    print("There were failing tests. See the report at: file:///x")
    print("BUILD FAILED in 1s")
    sys.exit(1)
if mode == "hang":
    time.sleep(600)
print("BUILD SUCCESSFUL in 1s")
'''


def zip_bytes(entries, *, directories=()):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in directories:
            archive.writestr(zipfile.ZipInfo(name), b"")
        for name, body in entries.items():
            archive.writestr(name, body)
    return buffer.getvalue()


class FakePlatform(guest.PosixPlatform):
    """POSIX seam with the java executable replaced by the fake JVM above."""

    def __init__(self, work, free=200 * 1024 ** 3):
        self.work, self.free, self.launched = work, free, []

    def free_bytes(self, path):
        return self.free

    def launch(self, argv, environment, cwd, output):
        self.launched.append(list(argv))
        script = self.work / "fake_jvm.py"
        script.write_text(FAKE_JVM)
        return super().launch([sys.executable, str(script), *argv[1:]], environment, cwd, output)


class FakeGroup:
    def __init__(self, *, members=(), terminated=True, waits=None):
        self._members, self.terminated, self.waits, self.closed = list(members), terminated, waits, False
        self.terminate_calls = 0

    def wait(self, timeout):
        if self.waits is None:
            raise subprocess.TimeoutExpired("java", timeout)
        return self.waits

    def members(self):
        return self._members

    def describe(self, pid):
        return "java.exe"

    def terminate(self):
        self.terminate_calls += 1
        return self.terminated

    def close(self):
        self.closed = True


def windows_request(**changes):
    profile = "C:\\Users\\fixtureuser"
    workspace = "C:\\ProgramData\\VpnControlOrdinaryTask-" + OPERATION
    value = {"schema": guest.REQUEST_SCHEMA, "schemaVersion": 1, "operationId": OPERATION, "sourceCommit": COMMIT,
             "profileRoot": profile, "operationRoot": profile + "\\AppData\\Local\\VpnControlOrdinary-" + OPERATION,
             "workspace": workspace, "workRoot": profile + "\\vcdt-" + OPERATION[:8],
             "archives": {role: {"path": workspace + "\\" + leaf, "sha256": "b" * 64, "bytes": 10}
                          for role, leaf in guest.ARCHIVE_LEAVES.items()},
             "jdk": {"root": "jdk-17.0.21+9", "javaVersion": "17.0.21"},
             "gradle": {"version": "8.10.2", "root": "gradle-8.10.2", "distributionUrl": URL, "wrapperHash": "a04bxjujx95o3nb99gddekhwo"},
             "gradleDeadlineSeconds": 10800, "minimumFreeBytes": 10 * 1024 ** 3}
    value.update(changes)
    return value


class StructureTests(unittest.TestCase):
    @unittest.skipUnless(ctypes.sizeof(ctypes.c_void_p) == 8, "x64 layouts")
    def test_job_and_toolhelp_structures_have_the_x64_sdk_sizes(self):
        types = guest.windows_types()
        self.assertEqual(guest.WINDOWS_SIZES, {name: ctypes.sizeof(types[name]) for name in guest.WINDOWS_SIZES})
        self.assertEqual(64, ctypes.sizeof(types["BasicLimit"]))

    def test_toolhelp_names_are_utf16_up_to_the_first_nul(self):
        units = [ord(c) for c in "vpn-control.exe"] + [0, ord("x")]
        self.assertEqual("vpn-control.exe", guest.wide_name(units))

    def test_the_build_starts_suspended_without_a_console_at_normal_priority_and_no_higher(self):
        # CREATE_SUSPENDED, NORMAL_PRIORITY_CLASS and CREATE_NO_WINDOW; never HIGH, REALTIME or a breakaway.
        self.assertEqual(0x00000004 | 0x00000020 | 0x08000000, guest.GRADLE_CREATION_FLAGS)
        self.assertEqual(0, guest.GRADLE_CREATION_FLAGS & (0x80 | 0x100 | 0x01000000))


class RequestTests(unittest.TestCase):
    def test_the_windows_request_is_closed_and_derived_from_its_operation(self):
        self.assertEqual(windows_request(), guest.validate_request(windows_request()))
        base = windows_request()
        wrong = {
            "request-fields": {**base, "extra": 1},
            "request-operation": {**base, "operationId": OPERATION.upper()},
            "request-commit": {**base, "sourceCommit": "A" * 40},
            "request-work-root": {**base, "workRoot": base["profileRoot"] + "\\elsewhere"},
            "request-operation-root": {**base, "operationRoot": base["profileRoot"] + "\\AppData\\Local\\Other"},
            "request-workspace": {**base, "workspace": "C:\\ProgramData\\Other"},
            "request-archive-source": {**base, "archives": {**base["archives"], "source": {**base["archives"]["source"], "path": "C:\\x.zip"}}},
            "request-gradle": {**base, "gradle": {**base["gradle"], "distributionUrl": URL.replace("8.10.2", "8.10.1")}},
            "request-deadline": {**base, "gradleDeadlineSeconds": 60},
            "request-free-space": {**base, "minimumFreeBytes": 1},
            "request-jdk": {**base, "jdk": {"root": "..\\jdk", "javaVersion": "17.0.21"}},
        }
        for code, value in wrong.items():
            with self.subTest(code=code), self.assertRaises(guest.StageFailure) as caught:
                guest.validate_request(value)
            self.assertEqual(code, caught.exception.code)

    def test_a_request_is_read_only_with_its_exact_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "request.json"
            raw = json.dumps(windows_request()).encode()
            path.write_bytes(raw)
            self.assertEqual(windows_request(), guest.read_request(str(path), hashlib.sha256(raw).hexdigest()))
            for digest, code in (("0" * 64, "request-digest"), ("x", "request-digest-argument")):
                with self.subTest(code=code), self.assertRaises(guest.StageFailure) as caught:
                    guest.read_request(str(path), digest)
                self.assertEqual(code, caught.exception.code)


class ZipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)

    def archive(self, entries, name="a.zip", **options):
        path = self.work / name
        path.write_bytes(zip_bytes(entries, **options))
        return str(path)

    def test_names_windows_could_alias_or_escape_with_are_refused_before_anything_is_written(self):
        for name, code in (("../x", "zip-entry-component"), ("/abs", "zip-entry-absolute"), ("C:x", "zip-entry-absolute"),
                           ("a\\b", "zip-entry-absolute"), ("CON", "zip-entry-component"), ("dir/aux.txt", "zip-entry-component"),
                           ("name.", "zip-entry-component"), ("name ", "zip-entry-component"), ("a/./b", "zip-entry-component"),
                           ("a\x01", "zip-entry-name"), ("q?", "zip-entry-component")):
            with self.subTest(name=name), self.assertRaises(guest.StageFailure) as caught:
                guest.extract_zip(self.archive({name: b"x", "ok": b"y"}), str(self.work / "out"), guest.SOURCE_LIMITS)
            self.assertEqual(code, caught.exception.code)
            self.assertFalse((self.work / "out").exists())

    def test_case_aliases_links_and_bounds_refuse(self):
        with self.assertRaises(guest.StageFailure) as caught:
            guest.inspect_zip(self.archive({"Read.me": b"1", "READ.ME": b"2"}), guest.SOURCE_LIMITS)
        self.assertEqual("zip-entry-alias", caught.exception.code)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system, info.external_attr = 3, (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
        (self.work / "link.zip").write_bytes(buffer.getvalue())
        with self.assertRaises(guest.StageFailure) as caught:
            guest.inspect_zip(str(self.work / "link.zip"), guest.SOURCE_LIMITS)
        self.assertEqual("zip-entry-link", caught.exception.code)
        with self.assertRaises(guest.StageFailure) as caught:
            guest.inspect_zip(self.archive({"big": b"x" * 100}), {"entries": 10, "bytes": 50, "file": 1000})
        self.assertEqual("zip-total-bound", caught.exception.code)

    def test_a_root_is_exact_and_extraction_is_create_only(self):
        with self.assertRaises(guest.StageFailure) as caught:
            guest.inspect_zip(self.archive({"other/bin/java": b"x"}), guest.TOOL_LIMITS, root="jdk-17.0.21+9")
        self.assertEqual("zip-root", caught.exception.code)
        path = self.archive({"jdk-17.0.21+9/bin/java": b"java"}, directories=("jdk-17.0.21+9/",))
        facts = guest.extract_zip(path, str(self.work / "j"), guest.TOOL_LIMITS, root="jdk-17.0.21+9")
        self.assertEqual({"entries": 2, "files": 1, "bytes": 4}, facts)
        self.assertEqual(b"java", (self.work / "j/jdk-17.0.21+9/bin/java").read_bytes())
        with self.assertRaises(FileExistsError):
            guest.extract_zip(path, str(self.work / "j"), guest.TOOL_LIMITS)

    def test_wrapper_properties_unescape_as_java_reads_them(self):
        path = self.work / "gradle-wrapper.properties"
        path.write_text("#c\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.10.2-bin.zip\nnetworkTimeout=10000\n")
        self.assertEqual(URL, guest.wrapper_properties(str(path))["distributionUrl"])


@unittest.skipUnless(os.name == "posix", "the POSIX seam")
class RunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.profile = self.work / "profile"
        self.workspace = self.work / "workspace"
        self.root = self.profile / "AppData/Local" / ("VpnControlOrdinary-" + OPERATION)
        for directory in (self.root, self.workspace):
            directory.mkdir(parents=True)
        self.record = self.work / "fake-jvm.json"
        properties = "distributionUrl=" + URL.replace(":", "\\:") + "\n"
        self.payloads = {
            "source": zip_bytes({"gradle/wrapper/gradle-wrapper.properties": properties.encode(), "gradle/wrapper/gradle-wrapper.jar": b"PK",
                                 "desktopApp/build.gradle.kts": b"plugins {}\n", "settings.gradle.kts": b"\n"}),
            "jdk": zip_bytes({"jdk-17.0.21+9/bin/java": b"java", "jdk-17.0.21+9/release": b'JAVA_VERSION="17.0.21"\nIMPLEMENTOR="Eclipse Adoptium"\n'}),
            "gradle": zip_bytes({"gradle-8.10.2/lib/gradle-launcher.jar": b"PK", "gradle-8.10.2/bin/gradle": b"#!"}),
            "dependencies": zip_bytes({"org/example/lib/1.0/lib-1.0.jar": b"PK", "org/example/lib/1.0/lib-1.0.pom": b"<project/>"}),
        }
        for role, raw in self.payloads.items():
            (self.workspace / guest.ARCHIVE_LEAVES[role]).write_bytes(raw)
        environment = {"VCDT_FAKE_RECORD": str(self.record), "VCDT_FAKE_PROFILE": str(self.profile), "GRADLE_OPTS": "-Dleak=1",
                       "JAVA_TOOL_OPTIONS": "-Dleak=1"}
        patcher = mock.patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, **changes):
        value = {"schema": guest.REQUEST_SCHEMA, "schemaVersion": 1, "operationId": OPERATION, "sourceCommit": COMMIT,
                 "profileRoot": str(self.profile), "operationRoot": str(self.root), "workspace": str(self.workspace),
                 "workRoot": str(self.profile / ("vcdt-" + OPERATION[:8])),
                 "archives": {role: {"path": str(self.workspace / guest.ARCHIVE_LEAVES[role]), "sha256": hashlib.sha256(raw).hexdigest(),
                                     "bytes": len(raw)} for role, raw in self.payloads.items()},
                 "jdk": {"root": "jdk-17.0.21+9", "javaVersion": "17.0.21"},
                 "gradle": {"version": "8.10.2", "root": "gradle-8.10.2", "distributionUrl": URL, "wrapperHash": "a04bxjujx95o3nb99gddekhwo"},
                 "gradleDeadlineSeconds": 600, "minimumFreeBytes": 10 * 1024 ** 3}
        value.update(changes)
        return guest.validate_request(value, windows=False)

    def run_main(self, mode="pass", request=None, platform=None):
        request = request or self.request()
        path = self.root / guest.REQUEST_LEAF
        path.write_bytes(json.dumps(request).encode())
        with mock.patch.dict(os.environ, {"VCDT_FAKE_MODE": mode}), mock.patch("builtins.print") as printed:
            code = guest.main(["--request", str(path), "--request-sha256", hashlib.sha256(path.read_bytes()).hexdigest()],
                              platform=platform or FakePlatform(self.work))
        line = json.loads(printed.call_args.args[0])
        self.assertEqual(("completed" if code == 0 else "failed", OPERATION), (line["state"], line["operationId"]))
        summary_path = self.root / guest.SUMMARY_LEAF
        return code, json.loads(summary_path.read_text()) if summary_path.exists() else None

    def results(self):
        with zipfile.ZipFile(self.root / guest.RESULTS_LEAF) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def test_a_passing_run_keeps_every_xml_result_and_the_console_and_removes_its_work_folder(self):
        platform = FakePlatform(self.work)
        code, summary = self.run_main(platform=platform)
        self.assertEqual(0, code)
        self.assertEqual(("completed", None, None), (summary["outcome"], summary["failedStage"], summary["failure"]))
        self.assertEqual([*guest.STAGES, "cleanup"], [row["name"] for row in summary["stages"]])
        self.assertTrue(all(row["outcome"] == "passed" for row in summary["stages"]))
        files = self.results()
        self.assertEqual({"test-results/TEST-com.example.Alpha.xml", "test-results/TEST-com.example.Beta.xml", "gradle-console.log"}, set(files))
        self.assertIn(b"BUILD SUCCESSFUL", files["gradle-console.log"])
        self.assertEqual((0, False, []), (summary["gradle"]["exitCode"], summary["gradle"]["deadline"], summary["gradle"]["leftoverProcesses"]))
        self.assertEqual({"created": True, "deleted": True, "error": None}, summary["workRoot"])
        self.assertFalse((self.profile / ("vcdt-" + OPERATION[:8])).exists())
        self.assertEqual({"JAVA_VERSION": "17.0.21", "IMPLEMENTOR": "Eclipse Adoptium"}, summary["jdkRelease"])
        self.assertEqual(hashlib.sha256((self.root / guest.RESULTS_LEAF).read_bytes()).hexdigest(), summary["results"]["sha256"])
        progress = json.loads((self.root / guest.PROGRESS_LEAF).read_text())
        self.assertEqual(("finished", "completed"), (progress["stage"], progress["outcome"]))

    def test_the_gradle_command_is_gradlew_bat_offline_with_the_pinned_wrapper_and_a_clean_environment(self):
        self.run_main()
        record = json.loads(self.record.read_text())
        work = self.profile / ("vcdt-" + OPERATION[:8])
        self.assertEqual([*guest.WRAPPER_JVM_OPTIONS, "-jar", str(work / "s/gradle/wrapper/gradle-wrapper.jar"), "--init-script",
                          str(work / guest.INIT_LEAF), "--offline", "--no-daemon", "--console=plain",
                          "-Pkotlin.compiler.execution.strategy=in-process", "-Porg.gradle.java.installations.auto-download=false",
                          ":desktopApp:test"], record["argv"])
        self.assertEqual(str(work / "s"), record["cwd"])
        self.assertEqual({"JAVA_HOME": str(work / "j/jdk-17.0.21+9"), "GRADLE_USER_HOME": str(work / "g"), "TEMP": str(work / "t"),
                          "TMP": str(work / "t"), "ANDROID_HOME": str(work / "no-android-sdk"), "ANDROID_SDK_ROOT": str(work / "no-android-sdk"),
                          "VPN_CONTROL_DESKTOP_TEST_REPOSITORY": str(work / "m"), "VPN_CONTROL_DESKTOP_TEST_HOME": str(work / "h"),
                          "GRADLE_OPTS": None, "JAVA_TOOL_OPTIONS": None}, record["env"])
        self.assertTrue(record["testHomeIsFolder"])
        self.assertIn("task.systemProperty('user.home', testHome)", guest.OFFLINE_INIT_SCRIPT)
        self.assertIn("System.getenv('" + guest.HOME_VARIABLE + "')", guest.OFFLINE_INIT_SCRIPT)

    def test_the_build_gets_a_dotnet_that_does_not_exist_and_no_inherited_dotnet_root(self):
        # A fixture user whose environment names an SDK of the fixture's own: CI's pinned SDK is not provisioned here.
        dotnet = self.work / "fixture-sdk"
        dotnet.mkdir()
        (dotnet / "dotnet.exe").write_bytes(b"MZ")
        with mock.patch.dict(os.environ, {"VPN_CONTROL_TEST_DOTNET": str(dotnet / "dotnet.exe"), "VPN_CONTROL_TEST_DOTNET_ROOT": str(dotnet)}):
            code, _ = self.run_main()
        self.assertEqual(0, code)
        work = self.profile / ("vcdt-" + OPERATION[:8])
        self.assertEqual({"program": str(work / "no-dotnet" / "dotnet.exe"), "root": None, "programExists": False},
                         json.loads(self.record.read_text())["dotnet"])

    def test_the_test_jvms_home_goes_with_the_work_folder_and_anything_left_beside_it_is_named(self):
        code, summary = self.run_main()
        self.assertEqual((0, {"added": [], "removed": []}), (code, summary["profileEntries"]))
        self.setUp()
        code, summary = self.run_main("residue")
        self.assertEqual((0, {"added": [".skiko"], "removed": []}), (code, summary["profileEntries"]))
        self.assertFalse((self.profile / ("vcdt-" + OPERATION[:8])).exists())

    def test_the_seeded_wrapper_distribution_is_where_the_wrapper_looks_and_marked_installed(self):
        platform = FakePlatform(self.work)
        runner = guest.Runner(self.request(), platform)
        for name in guest.STAGES[:guest.STAGES.index("init-script") + 1]:
            runner.stage(name, getattr(runner, "_" + name.replace("-", "_")))
        dists = self.profile / ("vcdt-" + OPERATION[:8]) / "g/wrapper/dists/gradle-8.10.2-bin/a04bxjujx95o3nb99gddekhwo"
        self.assertTrue((dists / "gradle-8.10.2/lib/gradle-launcher.jar").is_file())
        self.assertEqual(b"", (dists / "gradle-8.10.2-bin.zip.ok").read_bytes())
        self.assertIn("settingsEvaluated", (self.profile / ("vcdt-" + OPERATION[:8]) / guest.INIT_LEAF).read_text())
        runner.stage("cleanup", runner._cleanup)

    def test_failing_tests_are_a_result_and_the_runner_still_completes(self):
        code, summary = self.run_main("fail")
        self.assertEqual(0, code)
        self.assertEqual(("completed", 1), (summary["outcome"], summary["gradle"]["exitCode"]))
        self.assertIn(b"There were failing tests", self.results()["gradle-console.log"])

    def test_a_product_state_change_during_the_run_is_reported(self):
        state = self.profile / ".vpn-control-desktop"
        state.mkdir(parents=True)
        (state / "workspace.json").write_text("{}")
        code, summary = self.run_main("state")
        self.assertEqual(0, code)
        self.assertFalse(summary["productState"][".vpn-control-desktop"]["unchanged"])
        self.assertEqual(["workspace.json"], summary["productState"][".vpn-control-desktop"]["changedNames"])
        self.assertTrue(summary["productState"]["AppData/Local/vpn-control"]["unchanged"])

    def test_a_work_folder_it_did_not_create_is_refused_and_never_removed(self):
        existing = self.profile / ("vcdt-" + OPERATION[:8])
        existing.mkdir()
        (existing / "keep").write_text("not ours")
        code, summary = self.run_main()
        self.assertEqual(1, code)
        self.assertEqual(("preflight", "work-root-exists"), (summary["failedStage"], summary["failure"]))
        self.assertEqual(b"not ours", (existing / "keep").read_bytes())
        self.assertEqual({"created": False, "deleted": False, "error": "work-root-not-owned"}, summary["workRoot"])
        self.assertFalse((self.root / guest.RESULTS_LEAF).exists())

    def test_a_changed_archive_stops_before_any_extraction(self):
        (self.workspace / guest.ARCHIVE_LEAVES["dependencies"]).write_bytes(b"tampered")
        code, summary = self.run_main()
        self.assertEqual(("verify-archives", "archive-digest-dependencies"), (summary["failedStage"], summary["failure"]))
        self.assertEqual(1, code)
        self.assertFalse(summary["workRoot"]["created"])

    def test_a_source_naming_another_gradle_fails_its_stage_and_cleanup_removes_what_it_extracted(self):
        properties = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.9-bin.zip\n"
        self.payloads["source"] = zip_bytes({"gradle/wrapper/gradle-wrapper.properties": properties.encode(),
                                             "gradle/wrapper/gradle-wrapper.jar": b"PK", "desktopApp/build.gradle.kts": b""})
        (self.workspace / guest.ARCHIVE_LEAVES["source"]).write_bytes(self.payloads["source"])
        code, summary = self.run_main()
        self.assertEqual(("source-wrapper", "wrapper-distribution-mismatch"), (summary["failedStage"], summary["failure"]))
        self.assertEqual({"created": True, "deleted": True, "error": None}, summary["workRoot"])
        self.assertFalse((self.profile / ("vcdt-" + OPERATION[:8])).exists())
        self.assertEqual(1, code)

    def test_a_wrapper_checksum_must_be_the_pinned_distributions_as_the_coordinator_requires(self):
        for checksum, expected in (("0" * 64, (1, "wrapper-distribution-checksum-mismatch")), (None, (0, None))):
            with self.subTest(checksum=checksum):
                self.setUp()
                value = hashlib.sha256(self.payloads["gradle"]).hexdigest() if checksum is None else checksum
                properties = "distributionUrl=" + URL.replace(":", "\\:") + "\ndistributionSha256Sum=" + value + "\n"
                self.payloads["source"] = zip_bytes({"gradle/wrapper/gradle-wrapper.properties": properties.encode(),
                                                     "gradle/wrapper/gradle-wrapper.jar": b"PK", "desktopApp/build.gradle.kts": b""})
                (self.workspace / guest.ARCHIVE_LEAVES["source"]).write_bytes(self.payloads["source"])
                code, summary = self.run_main()
                self.assertEqual(expected, (code, summary["failure"]))

    def test_too_little_free_space_refuses_at_preflight(self):
        code, summary = self.run_main(platform=FakePlatform(self.work, free=1024))
        self.assertEqual(("preflight", "free-space-insufficient"), (summary["failedStage"], summary["failure"]))
        self.assertEqual(1024, summary["freeBytesBefore"])

    def test_a_tampered_request_writes_nothing(self):
        path = self.root / guest.REQUEST_LEAF
        path.write_bytes(json.dumps(self.request()).encode())
        with mock.patch("builtins.print"):
            code = guest.main(["--request", str(path), "--request-sha256", "0" * 64], platform=FakePlatform(self.work))
        self.assertEqual(2, code)
        self.assertFalse((self.root / guest.SUMMARY_LEAF).exists())

    def run_with_group(self, group, clock_step=0):
        platform = FakePlatform(self.work)
        platform.launch = lambda argv, environment, cwd, output: group
        ticks = iter(range(0, 10 ** 9, clock_step or 1))
        runner = guest.Runner(self.request(), platform, clock=(lambda: next(ticks)) if clock_step else __import__("time").monotonic,
                              sleep=lambda seconds: None)
        return runner.run()

    def test_a_build_past_its_deadline_is_ended_with_its_job_and_reported(self):
        group = FakeGroup(waits=None, terminated=True)
        summary = self.run_with_group(group, clock_step=120)
        self.assertEqual(("completed", True, None, True), (summary["outcome"], summary["gradle"]["deadline"], summary["gradle"]["exitCode"],
                                                         summary["gradle"]["leftoversTerminated"]))
        self.assertEqual((1, True), (group.terminate_calls, group.closed))

    def test_processes_the_build_left_running_are_named_then_ended(self):
        group = FakeGroup(waits=0, members=[4242], terminated=True)
        summary = self.run_with_group(group)
        self.assertEqual((["java.exe"], True, "completed"), (summary["gradle"]["leftoverProcesses"], summary["gradle"]["leftoversTerminated"],
                                                             summary["outcome"]))

    def test_processes_that_survive_their_job_fail_the_gradle_stage(self):
        summary = self.run_with_group(FakeGroup(waits=0, members=[4242], terminated=False))
        self.assertEqual(("failed", "gradle", "gradle-processes-survived"), (summary["outcome"], summary["failedStage"], summary["failure"]))

    def test_a_platform_error_is_named_by_its_step_and_number_only(self):
        group_error = guest.PlatformError("job-assign", 5)
        platform = FakePlatform(self.work)

        def refuse(*_):
            raise group_error
        platform.launch = refuse
        summary = guest.Runner(self.request(), platform).run()
        self.assertEqual(("gradle", "gradle-start:job-assign:5"), (summary["failedStage"], summary["failure"]))
        self.assertEqual("gradle-start:PermissionError:13", guest.native_code("gradle-start", PermissionError(13, "Access is denied")))


if __name__ == "__main__":
    unittest.main()
