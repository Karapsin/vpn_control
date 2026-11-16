"""The desktop test coordinator: closed inputs, source and toolchain custody, the driver behind the real
ScenarioExecutor, the results summary and the MCP twin.

Nothing here reaches a VM, a host or the network. git runs on a temporary repository, FakeSsh answers the
fixed carrier programs, a fake opener serves the downloads and a fake Gradle fills the export cache.
"""
import ast
import base64
from contextlib import nullcontext
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
import uuid
import zipfile

from agent_tools import durable_remote_job
from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_windows as windows
# Before any transport patch below: its source guard refuses a patched ssh_transport at import.
from agent_tools import readiness_windows_registration  # noqa: F401
from agent_tools import ssh_program_execution_remote as carrier
from agent_tools import ssh_transport as transport
from agent_tools import windows_desktop_test as desktop
from agent_tools import windows_desktop_test_guest as guest
from agent_tools import windows_desktop_test_host_job as desktop_job
from agent_tools import windows_scenario_host_job as host_job
from agent_tools.tests.test_native_scenario_windows import TARGET, FakeSsh, setup_fields
from agent_tools.tests.test_native_vm_spec import request as vm_request

ROOT = Path(__file__).resolve().parents[2]
MACHINE = "33333333-4444-4555-8666-777777777777"
OTHER = "44444444-5555-4666-8777-888888888888"
WRAPPER = ("distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n"
           "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.10.2-bin.zip\n"
           "networkTimeout=10000\nzipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n")
# The SDK pin of this checkout, which a source must carry: CI reads the lock, its tests copy the global.json.
DOTNET_LOCK = "desktopApp/native/windows/toolchain.lock.json"
DOTNET_GLOBAL_JSON = "desktopApp/native/windows/global.json"
SOURCE = {"settings.gradle.kts": 'rootProject.name = "fixture"\ninclude(":desktopApp")\n',
          "build.gradle.kts": "plugins {}\n",
          "gradle.properties": "vpnControlVersion=2.2.15\norg.gradle.jvmargs=-Xmx2g\n",
          "gradle/libs.versions.toml": '[versions]\nkotlin = "2.0.21"\n',
          "gradle/wrapper/gradle-wrapper.properties": WRAPPER,
          "desktopApp/build.gradle.kts": "plugins {}\n",
          "desktopApp/src/main/kotlin/Main.kt": "fun main() {}\n",
          DOTNET_LOCK: (ROOT / DOTNET_LOCK).read_text(encoding="utf-8"),
          DOTNET_GLOBAL_JSON: (ROOT / DOTNET_GLOBAL_JSON).read_text(encoding="utf-8"),
          "README.md": "readme\n"}
GIT_ENVIRONMENT = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "fixture",
                   "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "fixture",
                   "GIT_COMMITTER_EMAIL": "fixture@example.invalid", "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
                   "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
XML_ALPHA = ('<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="com.example.AlphaTest" tests="2" skipped="1" failures="0" '
             'errors="0" timestamp="2026-11-13T10:00:00" hostname="fixture" time="1.25">\n<properties/>\n'
             '<testcase name="works" classname="com.example.AlphaTest" time="1.0"/>\n'
             '<testcase name="later" classname="com.example.AlphaTest" time="0.0">\n<skipped/>\n</testcase>\n'
             '<system-out><![CDATA[]]></system-out>\n<system-err><![CDATA[]]></system-err>\n</testsuite>\n')
XML_BETA = ('<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="com.example.BetaTest" tests="1" skipped="0" failures="1" '
            'errors="0" time="0.5">\n<testcase name="breaks" classname="com.example.BetaTest" time="0.5">\n'
            '<failure message="expected" type="java.lang.AssertionError">trace</failure>\n</testcase>\n</testsuite>\n')
# Gradle 8.10.2's own console, captured from the pinned distribution offline against a file repository that lacks a
# test runtime jar, then a whole module (.runtime/review-1113/offline-wording of the build clone); only the
# repository location lines are shortened to a guest path.
_TASKS = ("> Task :desktopApp:compileJava NO-SOURCE\n> Task :desktopApp:processResources NO-SOURCE\n> Task :desktopApp:classes UP-TO-DATE\n"
          "> Task :desktopApp:compileTestJava\n> Task :desktopApp:processTestResources NO-SOURCE\n> Task :desktopApp:testClasses\n"
          "> Task :desktopApp:test FAILED\n\nFAILURE: Build failed with an exception.\n\n* What went wrong:\n"
          "Execution failed for task ':desktopApp:test'.\n> Could not resolve all files for configuration ':desktopApp:testRuntimeClasspath'.\n")
_TRY = ("\n* Try:\n> Run with --stacktrace option to get the stack trace.\n> Run with --info or --debug option to get more log output.\n"
        "> Run with --scan to get full insights.\n> Get more help at https://help.gradle.org.\n\n")
MISSING_JAR_CONSOLE = (_TASKS + "   > Could not find lib-1.0.jar (org.example:lib:1.0).\n     Searched in the following locations:\n"
                       "         file:/C:/Users/fixture/vcdt-0f1e2d3c/m/org/example/lib/1.0/lib-1.0.jar\n" + _TRY
                       + "BUILD FAILED in 25s\n2 actionable tasks: 2 executed\n")
MISSING_MODULE_CONSOLE = (_TASKS + "   > Could not find org.example:missing:1.0.\n     Searched in the following locations:\n"
                          "       - file:/C:/Users/fixture/vcdt-0f1e2d3c/m/org/example/missing/1.0/missing-1.0.pom\n"
                          "     Required by:\n         project :desktopApp\n" + _TRY + "BUILD FAILED in 22s\n2 actionable tasks: 1 executed, 1 up-to-date\n")


def dotnet_xml(operation, program=None, error="CreateProcess error=2, The system cannot find the file specified"):
    """Gradle's XML for a desktop test that could not start dotnet: <failure> with message=Throwable.toString()."""
    program = program or "C:\\Users\\fixture\\vcdt-" + operation[:8] + "\\no-dotnet\\dotnet.exe"
    message = ('java.io.IOException: Cannot run program "' + program + '" (in directory "C:\\Users\\fixture\\vcdt-' + operation[:8]
               + '\\t\\vpn-output-native-1"): ' + error)
    quoted = message.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")
    case = ('<testcase name="{name}" classname="com.kardinal.vpncontrol.desktop.DesktopWindowsOutputNativeTest" time="0.01">\n'
            '<failure message="' + quoted + '" type="java.io.IOException">' + quoted + '\n\tat java.base/java.lang.ProcessBuilder.start'
            '(ProcessBuilder.java:1143)</failure>\n</testcase>\n')
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="com.kardinal.vpncontrol.desktop.DesktopWindowsOutputNativeTest" '
            'tests="2" skipped="0" failures="2" errors="0" time="0.02">\n' + case.format(name="first") + case.format(name="second")
            + '</testsuite>\n')


# What `dotnet build` of a desktop test's AOT probe prints when the offline seed lacks its ILLink pack: SDK 10.0.403's own
# wording, captured offline with the guest's NuGet configuration (.runtime/followup2/experiments/adapter-empty/build.log
# of the build clone), the probe folder shortened to a guest path.
SEED_MISSING_BUILD = ("  Determining projects to restore...\n"
                      "C:\\Users\\fixture\\vcdt-0f1e2d3c\\t\\vpn-install-coordinator-adapter-1\\CoordinatorAdapterProbe.csproj : error NU1101: "
                      "Unable to find package Microsoft.NET.ILLink.Tasks. No packages exist with this id in source(s): vpnControlDesktopTestOffline\n"
                      "  Failed to restore C:\\Users\\fixture\\vcdt-0f1e2d3c\\t\\vpn-install-coordinator-adapter-1\\CoordinatorAdapterProbe.csproj"
                      " (in 769 ms).\n\nBuild FAILED.\n")


def build_failure_xml(output, name="completedInputCleanupAndRetentionKeepKnownOutcomeAndExactCustody"):
    """Gradle's XML for a desktop .NET test whose probe build failed: the assertion carries the build's output."""
    message = ("Coordinator adapter build failed; evidence: C:\\Users\\fixture\\vcdt-0f1e2d3c\\t\\vpn-install-coordinator-adapter-1\n"
               + output + "\n expected:<0> but was:<1>")
    quoted = message.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace("\n", "&#10;")
    return ('<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="com.kardinal.vpncontrol.desktop.DesktopWindowsCoordinatorAdapterTest" '
            'tests="1" skipped="0" failures="1" errors="0" time="9.5">\n<testcase name="' + name + '" '
            'classname="com.kardinal.vpncontrol.desktop.DesktopWindowsCoordinatorAdapterTest" time="9.5">\n<failure message="' + quoted
            + '" type="java.lang.AssertionError">java.lang.AssertionError: ' + message.replace("&", "&amp;").replace("<", "&lt;")
            + '\n\tat org.junit.Assert.fail(Assert.java:89)</failure>\n</testcase>\n</testsuite>\n')


ARTIFACTS = (("org.jetbrains.compose.desktop", "desktop-jvm-windows-x64", "1.7.0", "desktop-jvm-windows-x64-1.7.0.jar", b"compose windows"),
             ("org.jetbrains.skiko", "skiko-awt-runtime-windows-x64", "0.8.18", "skiko-awt-runtime-windows-x64-0.8.18.jar", b"skiko windows"),
             ("org.example", "lib", "1.0", "lib-1.0.pom", b"<project/>"))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def zip_bytes(members):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    return buffer.getvalue()


# The SDK zip's layout as the runner checks it: its muxer, the pinned SDK and the runtime it ships.
FAKE_SDK = {"dotnet.exe": b"MZ", "sdk/10.0.403/dotnet.dll": b"MZ", "shared/Microsoft.NETCore.App/10.0.14/System.Private.CoreLib.dll": b"MZ"}


def patch_dotnet_pins(case):
    """Small stand-ins for CI's SDK and the seed's packages, each pin patched to its size and digests; the returned
    payloads are what a download of each url serves. A tree without these pins gets nothing patched."""
    payloads = {}
    sdk = getattr(desktop, "DOTNET", None)
    for number, pin in enumerate(([sdk] if sdk is not None else []) + list(getattr(desktop, "NUGET_PACKAGES", ()))):
        raw = zip_bytes(FAKE_SDK) if pin is sdk else b"PK nupkg %d" % number
        patcher = mock.patch.dict(pin, {"sha256": sha(raw), "sha512": hashlib.sha512(raw).hexdigest(), "bytes": len(raw)})
        patcher.start()
        case.addCleanup(patcher.stop)
        payloads[pin["url"]] = raw
    return payloads


def git(root, *arguments):
    done = subprocess.run(["git", "-C", str(root), *arguments], env={**os.environ, **GIT_ENVIRONMENT}, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=60)
    return done.stdout.decode().strip()


def commit(root, files):
    """One commit of the given files; None removes a path."""
    for relative, text in files.items():
        if text is None:
            git(root, "rm", "-q", "--", relative)
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if type(text) is bytes else text.encode())
        git(root, "add", "--", relative)
    git(root, "commit", "-q", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


def fake_gradle(argv, *, cwd, env, stdin, stdout, stderr, timeout, check):
    """Stands where the commit's wrapper runs on the coordinator: it fills Gradle's own download cache."""
    files = Path(env["GRADLE_USER_HOME"]) / "caches/modules-2/files-2.1"
    for group, module, version, leaf, body in ARTIFACTS:
        directory = files / group / module / version / hashlib.sha1(body).hexdigest()
        directory.mkdir(parents=True)
        (directory / leaf).write_bytes(body)
    stdout.write(b"BUILD SUCCESSFUL in 1m\n")
    fake_gradle.calls.append({"argv": list(argv), "cwd": cwd, "env": dict(env)})
    return subprocess.CompletedProcess(argv, 0)


class DesktopSsh(FakeSsh):
    """The scenario tests' fake host, with each kept job file served by its own name."""

    def __init__(self, directory):
        super().__init__(directory)
        self.kept = {}
        self.pull_hook = None  # (name, offset): runs as one chunk is read, so two readers can be interleaved.

    def respond(self, command):
        if command[:4] == ("python3", "-I", "-B", "-c") and command[4].startswith("exec(") and ast.literal_eval(command[4][5:-1]) == windows._PULL:
            self.pulls += 1
            raw = self.kept[command[6]]
            offset, length = int(command[7]), int(command[8])
            if self.pull_hook is not None:
                self.pull_hook(command[6], offset)
            return "pull", {"size": len(raw), "data": base64.b64encode(raw[offset:offset + length]).decode()}
        return super().respond(command)


class InputTests(unittest.TestCase):
    START = {"deploymentId": MACHINE, "operationId": "e314d08a-80eb-4d98-9abe-0c1b245a3807", "sourceCommit": "a" * 40}

    def test_start_takes_exactly_three_closed_fields(self):
        self.assertEqual((MACHINE, self.START["operationId"], "a" * 40), desktop.start_inputs(self.START))
        for bad, reason in (({**self.START, "sourceCommit": "A" * 40}, "desktop_test_source_commit_invalid"),
                            ({**self.START, "sourceCommit": "g" * 40}, "desktop_test_source_commit_invalid"),
                            ({**self.START, "sourceCommit": "a" * 39}, "desktop_test_source_commit_invalid"),
                            ({**self.START, "sourceCommit": "a" * 40 + "\n"}, "desktop_test_source_commit_invalid"),
                            ({**self.START, "sourceCommit": "HEAD"}, "desktop_test_source_commit_invalid"),
                            ({**self.START, "sourceCommit": 7}, "desktop_test_source_commit_invalid"),
                            ({**self.START, "deploymentId": self.START["operationId"].upper()}, "desktop_test_deployment_invalid"),
                            ({**self.START, "operationId": "x"}, "desktop_test_operation_invalid"),
                            ({**self.START, "command": "gradlew"}, "desktop_test_inputs_invalid"),
                            ({key: value for key, value in self.START.items() if key != "sourceCommit"}, "desktop_test_inputs_invalid"),
                            ([], "desktop_test_inputs_invalid")):
            with self.subTest(bad=bad), self.assertRaises(desktop.DesktopTestError) as caught:
                desktop.start_inputs(bad)
            self.assertEqual(reason, caught.exception.reason)

    def test_status_takes_exactly_the_two_identities(self):
        status = {key: self.START[key] for key in ("deploymentId", "operationId")}
        self.assertEqual((MACHINE, self.START["operationId"]), desktop.status_inputs(status))
        for bad in (self.START, {**status, "path": "/x"}, {"operationId": status["operationId"]}):
            with self.subTest(bad=bad), self.assertRaisesRegex(desktop.DesktopTestError, "desktop_test_inputs_invalid"):
                desktop.status_inputs(bad)

    def test_the_journal_scenario_is_the_one_this_tool_names(self):
        self.assertEqual(execution.DESKTOP_TEST_SCENARIO, desktop.SCENARIO_ID)
        self.assertEqual(desktop_job.DESKTOP_SCENARIO, desktop.SCENARIO_ID)
        self.assertNotIn(desktop.SCENARIO_ID, execution.WINDOWS_SCENARIOS, "scenario-start has no row for it")
        self.assertNotIn(desktop.SCENARIO_ID, windows.RECIPES)

    def test_the_whole_task_ends_before_its_owners_pending_events_reach_the_collectors_bound(self):
        owner = (ROOT / "agent_tools/windows_ordinary_task_owner.ps1").read_text()
        template = (ROOT / "agent_tools/windows_scenario_system_run.ps1.template").read_text()
        cadence = int(re.search(r"Write-OwnedEvent 'pending' .*?\$next=\[DateTime\]::UtcNow\.AddSeconds\((\d+)\)", owner)[1])
        bound = int(re.search(r"N \(\$ordinal -lt (\d+)\) 'RUN_EVENT_BOUND'", template)[1])
        self.assertEqual((30, 512), (cadence, bound))
        # Every other task event (intent, submitted, child records, terminal) fits in the last 32.
        self.assertLess(desktop.ROW["deadlineSeconds"] // cadence + 32, bound)
        self.assertGreaterEqual(desktop.ROW["deadlineSeconds"] - desktop.GRADLE_DEADLINE_SECONDS, 3600)

    def test_the_pins_are_the_ci_toolchain(self):
        self.assertEqual(("17.0.21+9", "17.0.21", "jdk-17.0.21+9"), (desktop.JDK["version"], desktop.JDK["javaVersion"], desktop.JDK["root"]))
        self.assertEqual("https://services.gradle.org/distributions/gradle-8.10.2-bin.zip", desktop.GRADLE["url"])
        properties = guest.wrapper_properties(str(ROOT / "gradle/wrapper/gradle-wrapper.properties"))
        self.assertEqual(desktop.GRADLE["url"], properties["distributionUrl"], "this checkout's wrapper names the pinned distribution")
        for pin in (desktop.JDK, desktop.GRADLE):
            self.assertRegex(pin["sha256"], "^[0-9a-f]{64}$")
            self.assertTrue(pin["url"].startswith("https://"))
        # The wrapper's distribution directory: base 36 of the MD5 of the distribution URL.
        number = int.from_bytes(hashlib.md5(desktop.GRADLE["url"].encode()).digest(), "big")
        digits = ""
        while number:
            number, digit = divmod(number, 36)
            digits = "0123456789abcdefghijklmnopqrstuvwxyz"[digit] + digits
        self.assertEqual(desktop.GRADLE["wrapperHash"], digits)

    def test_the_dotnet_pin_is_this_checkouts_toolchain_lock_and_global_json(self):
        lock = json.loads((ROOT / DOTNET_LOCK).read_text())
        sdk = json.loads((ROOT / DOTNET_GLOBAL_JSON).read_text())["sdk"]
        self.assertEqual((lock["sdkVersion"], lock["runtimeFrameworkVersion"], lock["sdkArchive"]["url"], lock["sdkArchive"]["sha512"]),
                         (desktop.DOTNET["version"], desktop.DOTNET["runtimeVersion"], desktop.DOTNET["url"], desktop.DOTNET["sha512"]))
        self.assertEqual((desktop.DOTNET["version"], "disable"), (sdk["version"], sdk["rollForward"]))
        self.assertEqual({"sdkVersion": desktop.DOTNET["version"], "url": desktop.DOTNET["url"], "sha512": desktop.DOTNET["sha512"]},
                         desktop.DOTNET_SOURCE_PIN, "a source must pin exactly the SDK this tool ships")
        self.assertTrue(desktop.DOTNET["url"].startswith("https://builds.dotnet.microsoft.com/"))
        self.assertEqual(desktop.DOTNET["fileName"], desktop.DOTNET["url"].rsplit("/", 1)[1])
        self.assertRegex(desktop.DOTNET["sha256"], "^[0-9a-f]{64}$")
        self.assertEqual({"jdk": desktop.JDK["version"], "gradle": desktop.GRADLE["version"], "dotnet": "10.0.403"}, desktop.TOOLCHAIN)
        # The seed: the SDK's ILLink pack for net10.0 (its version is the runtime's), from nuget.org's flat container.
        self.assertEqual([("Microsoft.NET.ILLink.Tasks", desktop.DOTNET["runtimeVersion"])],
                         [(pin["id"], pin["version"]) for pin in desktop.NUGET_PACKAGES])
        for pin in desktop.NUGET_PACKAGES:
            with self.subTest(pin=pin["id"]):
                self.assertEqual(pin["id"].lower() + "." + pin["version"] + ".nupkg", pin["file"])
                self.assertEqual("https://api.nuget.org/v3-flatcontainer/" + pin["id"].lower() + "/" + pin["version"] + "/" + pin["file"], pin["url"])
                self.assertRegex(pin["sha512"], "^[0-9a-f]{128}$")
                self.assertRegex(pin["sha256"], "^[0-9a-f]{64}$")
                self.assertLessEqual(pin["bytes"], guest.SEED_LIMITS["file"])
        self.assertEqual(11 * 1024 ** 3, desktop.MINIMUM_FREE_BYTES, "Gradle's margin as before, plus the extracted SDK")


@unittest.skipUnless(os.name == "posix" and shutil.which("git"), "private storage is POSIX and a source is a git commit")
class RepositoryBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "repository"
        self.root.mkdir()
        git(self.root, "-c", "init.defaultBranch=main", "init", "-q")
        self.commit = commit(self.root, {**SOURCE, "gradle/wrapper/gradle-wrapper.jar": b"PK\x05\x06" + bytes(18)})

    def refused(self, reason, function, *arguments, **options):
        with self.assertRaises(desktop.DesktopTestError) as caught:
            function(*arguments, **options)
        self.assertEqual(reason, caught.exception.reason)


class SourceTests(RepositoryBase):
    def test_a_commit_must_exist_here_and_be_a_commit(self):
        self.assertEqual(self.commit, desktop.source_facts(self.root, self.commit)["sourceCommit"])
        tree = git(self.root, "rev-parse", "HEAD^{tree}")
        blob = git(self.root, "rev-parse", "HEAD:README.md")
        for value in ("1" * 40, tree, blob):
            with self.subTest(value=value):
                self.refused("desktop_test_source_commit_unknown", desktop.source_facts, self.root, value)
        for value in ("G" * 40, self.commit[:39], self.commit.upper(), "HEAD", "-" + self.commit[1:]):
            with self.subTest(value=value):
                self.refused("desktop_test_source_commit_invalid", desktop.source_facts, self.root, value)

    def test_the_source_must_name_the_pinned_gradle_and_hold_the_desktop_project(self):
        other = commit(self.root, {"gradle/wrapper/gradle-wrapper.properties": WRAPPER.replace("8.10.2", "8.9")})
        self.refused("desktop_test_gradle_distribution_unpinned", desktop.source_facts, self.root, other)
        checksum = commit(self.root, {"gradle/wrapper/gradle-wrapper.properties": WRAPPER + "distributionSha256Sum=" + "0" * 64 + "\n"})
        self.refused("desktop_test_gradle_distribution_unpinned", desktop.source_facts, self.root, checksum)
        pinned = commit(self.root, {"gradle/wrapper/gradle-wrapper.properties": WRAPPER + "distributionSha256Sum=" + desktop.GRADLE["sha256"] + "\n"})
        self.assertEqual(pinned, desktop.source_facts(self.root, pinned)["sourceCommit"])
        without = commit(self.root, {"desktopApp/build.gradle.kts": None})
        self.refused("desktop_test_source_not_desktop", desktop.source_facts, self.root, without)
        unwrapped = commit(self.root, {"desktopApp/build.gradle.kts": "plugins {}\n", "gradle/wrapper/gradle-wrapper.properties": None})
        self.refused("desktop_test_source_not_desktop", desktop.source_facts, self.root, unwrapped)

    def test_a_commit_whose_dotnet_sdk_pin_is_not_the_tools_is_refused_before_anything_else(self):
        lock = json.loads(SOURCE[DOTNET_LOCK])
        for name, change in (
                ("another SDK", {DOTNET_LOCK: json.dumps({**lock, "sdkVersion": "10.0.404"})}),
                ("another archive digest", {DOTNET_LOCK: json.dumps({**lock, "sdkArchive": {**lock["sdkArchive"], "sha512": "0" * 128}})}),
                ("another archive url", {DOTNET_LOCK: json.dumps({**lock, "sdkArchive": {**lock["sdkArchive"], "url": "https://example.invalid/sdk.zip"}})}),
                ("another global.json", {DOTNET_GLOBAL_JSON: '{"sdk": {"version": "10.0.404", "rollForward": "disable"}}'}),
                ("no global.json", {DOTNET_GLOBAL_JSON: None}), ("no lock", {DOTNET_LOCK: None}),
                ("a lock that is not JSON", {DOTNET_LOCK: "sdkVersion=10.0.403\n"})):
            with self.subTest(name=name):
                changed = commit(self.root, change)
                self.refused("desktop_test_dotnet_sdk_unpinned", desktop.source_facts, self.root, changed)
                self.refused("desktop_test_dotnet_sdk_unpinned", desktop.prepare, self.root, {"sourceCommit": changed},
                             opener=lambda *_, **__: self.fail("nothing is downloaded for a refused commit"))
                commit(self.root, {path: SOURCE[path] for path in (DOTNET_LOCK, DOTNET_GLOBAL_JSON)})
        self.assertEqual(self.commit, desktop.source_facts(self.root, self.commit)["sourceCommit"])

    def test_the_dependency_digest_follows_the_build_definition_only(self):
        first = desktop.dependency_digest(self.root, self.commit)
        unrelated = commit(self.root, {"gradle.properties": SOURCE["gradle.properties"].replace("2.2.15", "2.2.16"),
                                       "README.md": "changed\n", "desktopApp/src/main/kotlin/Main.kt": "fun main() { }\n",
                                       "gradle/wrapper/gradle-wrapper.jar": b"PK\x05\x06" + bytes(17) + b"\x01"})
        self.assertEqual(first, desktop.dependency_digest(self.root, unrelated))
        for change in ({"desktopApp/build.gradle.kts": "plugins { id(\"x\") }\n"}, {"gradle/libs.versions.toml": "[versions]\n"},
                       {"gradle.properties": "vpnControlVersion=2.2.16\nkotlin.code.style=official\n"},
                       {"shared/core/build.gradle.kts": "plugins {}\n"}):
            with self.subTest(change=sorted(change)):
                self.assertNotEqual(first, desktop.dependency_digest(self.root, commit(self.root, change)))

    def test_the_source_archive_is_the_commit_made_once_and_checked_on_every_use(self):
        record = desktop.source_archive(self.root, self.commit)
        path = record["path"]
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        made = subprocess.run(["git", "-C", str(self.root), "archive", "--format=zip", self.commit], stdout=subprocess.PIPE, check=True).stdout
        self.assertEqual(sha(made), record["sha256"], "exactly git archive of the commit")
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(sorted([*SOURCE, "gradle/wrapper/gradle-wrapper.jar"]), sorted(name for name in archive.namelist() if not name.endswith("/")))
        self.assertEqual(record["sha256"], desktop.source_archive(self.root, self.commit)["sha256"])
        path.chmod(0o600)
        path.write_bytes(b"PK changed")
        self.refused("desktop_test_source_archive_changed", desktop.source_archive, self.root, self.commit)

    def test_a_commit_windows_cannot_hold_is_refused_before_it_is_kept(self):
        unsafe = commit(self.root, {"desktopApp/aux.txt": "x\n"})
        self.refused("desktop_test_source_archive_refused:zip-entry-component", desktop.source_archive, self.root, unsafe)
        self.assertEqual([], [path.name for path in (self.root / ".runtime/windows-desktop-test/sources").iterdir()])

    def test_a_record_lost_before_it_was_written_makes_the_same_archive_again(self):
        first = desktop.source_archive(self.root, self.commit)
        (first["path"].parent / (self.commit + ".json")).unlink()
        self.assertEqual(first["sha256"], desktop.source_archive(self.root, self.commit)["sha256"], "git archive is deterministic")


class ToolchainTests(RepositoryBase):
    def pin(self, raw, **changes):
        return {"url": "https://downloads.example.invalid/tool.zip", "sha256": sha(raw), "bytes": len(raw), **changes}

    def opener(self, raw, calls=None):
        def open_url(request, timeout):
            if calls is not None:
                calls.append(request.full_url)
            self.assertNotIn("vpn", json.dumps(request.header_items()).lower(), "no project name leaves this host")
            return io.BytesIO(raw)
        return open_url

    def test_a_download_is_used_only_after_its_pinned_size_and_digest_match(self):
        raw = b"distribution" * 1000
        target = self.work / "tool.zip"
        desktop.download(self.pin(raw), target, opener=self.opener(raw))
        self.assertEqual(raw, target.read_bytes())
        for pin, served in ((self.pin(raw, sha256="0" * 64), raw), (self.pin(raw), raw + b"x"), (self.pin(raw), raw[:-1])):
            with self.subTest(served=len(served)):
                target = self.work / ("tool-" + uuid.uuid4().hex)
                self.refused("desktop_test_toolchain_digest", desktop.download, pin, target, opener=self.opener(served))
                self.assertFalse(target.exists())
        self.assertEqual([], [path.name for path in self.work.iterdir() if path.name.endswith(".partial")])

    def test_a_publisher_sha512_is_checked_with_the_size_and_sha256(self):
        raw = b"sdk" * 1000
        pin = self.pin(raw, sha512=hashlib.sha512(raw).hexdigest())
        target = self.work / "sdk.zip"
        desktop.download(pin, target, opener=self.opener(raw))
        self.assertEqual(raw, target.read_bytes())
        # Bytes that match the recorded sha256 and size but not the publisher's own SHA-512 are never kept.
        wrong = self.pin(raw, sha512="0" * 128)
        self.refused("desktop_test_toolchain_digest", desktop.download, wrong, self.work / "other.zip", opener=self.opener(raw))
        self.assertFalse((self.work / "other.zip").exists())

    def test_a_start_never_downloads_and_a_changed_toolchain_is_refused(self):
        raw = b"jdk" * 100
        pin = self.pin(raw)
        self.refused("desktop_test_toolchain_unprepared", desktop.ensure_toolchain, self.root, pin)
        calls = []
        path = desktop.ensure_toolchain(self.root, pin, opener=self.opener(raw, calls))
        self.assertEqual((1, 0o600), (len(calls), path.stat().st_mode & 0o777))
        self.assertEqual(path, desktop.ensure_toolchain(self.root, pin))
        path.write_bytes(b"other")
        self.refused("desktop_test_toolchain_changed", desktop.ensure_toolchain, self.root, pin)

    def cache(self, rows):
        files = self.work / ("files-" + uuid.uuid4().hex)
        for group, module, version, leaf, body, *digest in rows:
            directory = files / group / module / version / (digest[0] if digest else hashlib.sha1(body).hexdigest())
            directory.mkdir(parents=True, exist_ok=True)
            (directory / leaf).write_bytes(body)
        return files

    def test_gradles_cache_becomes_a_maven_layout_with_only_windows_natives(self):
        body = next(b"x%d" % number for number in range(1000) if hashlib.sha1(b"x%d" % number).hexdigest().startswith("0"))
        short = hashlib.sha1(body).hexdigest().lstrip("0")
        rows = desktop.files_to_repository(self.cache([*ARTIFACTS, ("org.example", "zero", "1.0", "zero-1.0.jar", body, short)]),
                                           self.work / "repository")
        self.assertEqual(["org/example/lib/1.0/lib-1.0.pom", "org/example/zero/1.0/zero-1.0.jar",
                          "org/jetbrains/compose/desktop/desktop-jvm-windows-x64/1.7.0/desktop-jvm-windows-x64-1.7.0.jar",
                          "org/jetbrains/skiko/skiko-awt-runtime-windows-x64/0.8.18/skiko-awt-runtime-windows-x64-0.8.18.jar"],
                         [row["path"] for row in rows])
        self.assertEqual(b"<project/>", (self.work / "repository/org/example/lib/1.0/lib-1.0.pom").read_bytes())
        for extra, reason in ((("org.jetbrains.skiko", "skiko-awt-runtime-macos-arm64", "0.8.18", "s.jar", b"mac"), "dependency_export_foreign_natives"),
                              (("org.example", "bad", "1.0", "bad.jar", b"bytes", "1" * 40), "dependency_export_cache_digest"),
                              (("org.example", "lib", "1.0", "LIB-1.0.POM", b"other"), "dependency_export_conflict")):
            with self.subTest(reason=reason):
                self.refused(reason, desktop.files_to_repository, self.cache([*ARTIFACTS, extra]), self.work / ("r-" + uuid.uuid4().hex))
        self.refused("dependency_export_windows_natives_missing", desktop.files_to_repository, self.cache(ARTIFACTS[1:]),
                     self.work / "r-missing")

    def test_the_repository_archive_is_deterministic(self):
        rows = desktop.files_to_repository(self.cache(ARTIFACTS), self.work / "repository")
        first, second = self.work / "one.zip", self.work / "two.zip"
        desktop.deterministic_zip(self.work / "repository", rows, first)
        desktop.deterministic_zip(self.work / "repository", rows, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            self.assertEqual([row["path"] for row in rows], archive.namelist())
            self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist()))
        self.assertEqual(guest.inspect_zip(str(first), guest.TOOL_LIMITS)["files"], len(rows))


class SeedTests(RepositoryBase):
    def setUp(self):
        super().setUp()
        self.payloads = patch_dotnet_pins(self)
        self.calls = []

    def opener(self, request, timeout):
        self.calls.append(request.full_url)
        return io.BytesIO(self.payloads[request.full_url])

    def test_the_seed_is_exactly_the_pinned_packages_stored_flat_and_made_the_same_every_time(self):
        seed = desktop.nuget_seed(self.root, opener=self.opener)
        self.assertEqual(sorted(pin["url"] for pin in desktop.NUGET_PACKAGES), sorted(self.calls))
        with zipfile.ZipFile(seed["path"]) as archive:
            infos = archive.infolist()
            self.assertEqual(sorted(pin["file"] for pin in desktop.NUGET_PACKAGES), [info.filename for info in infos])
            self.assertTrue(all(info.compress_type == zipfile.ZIP_STORED and info.date_time == (1980, 1, 1, 0, 0, 0) for info in infos))
            for pin in desktop.NUGET_PACKAGES:
                self.assertEqual(pin["sha512"], hashlib.sha512(archive.read(pin["file"])).hexdigest())
        self.assertEqual(len(desktop.NUGET_PACKAGES), guest.inspect_zip(str(seed["path"]), guest.SEED_LIMITS)["files"])
        self.assertEqual((0o600, guest.NUGET_SOURCE), (seed["path"].stat().st_mode & 0o777, seed["source"]))
        self.assertEqual(seed["sha256"], desktop.nuget_seed(self.root)["sha256"], "kept and re-verified, never downloaded again")
        self.assertEqual(len(desktop.NUGET_PACKAGES), len(self.calls))
        # Made again from the same packages (its record lost), the seed is byte for byte the same.
        first = seed["path"].read_bytes()
        (seed["path"].parent / (seed["seedIdentity"] + ".json")).unlink()
        self.assertEqual(first, desktop.nuget_seed(self.root)["path"].read_bytes())

    def test_a_changed_package_or_seed_is_refused_and_only_prepare_downloads(self):
        self.refused("desktop_test_toolchain_unprepared", desktop.nuget_seed, self.root)
        seed = desktop.nuget_seed(self.root, opener=self.opener)
        seed["path"].write_bytes(b"PK changed")
        self.refused("desktop_test_nuget_seed_changed", desktop.nuget_seed, self.root)
        for path in seed["path"].parent.iterdir():
            path.unlink()
        pin = desktop.NUGET_PACKAGES[0]
        desktop.toolchain_path(self.root, pin).write_bytes(b"other")
        self.refused("desktop_test_toolchain_changed", desktop.nuget_seed, self.root)
        # A package whose bytes are not the ones nuget.org publishes is never kept.
        desktop.toolchain_path(self.root, pin).unlink()
        self.payloads[pin["url"]] = self.payloads[pin["url"]][:-1] + b"!"
        self.refused("desktop_test_toolchain_digest", desktop.nuget_seed, self.root, opener=self.opener)
        self.assertEqual([], list(seed["path"].parent.iterdir()))


class PrepareTests(RepositoryBase):
    def setUp(self):
        super().setUp()
        self.payloads = {}
        for name, pin, root in (("JDK", desktop.JDK, "jdk-17.0.21+9"), ("GRADLE", desktop.GRADLE, "gradle-8.10.2")):
            raw = zip_bytes({root + "/lib/x.jar": name.encode() * 50, root + "/bin/run": b"#!"})
            patcher = mock.patch.dict(pin, {"sha256": sha(raw), "bytes": len(raw)})
            patcher.start()
            self.addCleanup(patcher.stop)
            self.payloads[pin["url"]] = raw
        self.payloads.update(patch_dotnet_pins(self))
        self.downloads = []
        fake_gradle.calls = []

    def opener(self, request, timeout):
        self.downloads.append(request.full_url)
        return io.BytesIO(self.payloads[request.full_url])

    def test_prepare_downloads_once_archives_the_commit_and_exports_its_windows_dependencies(self):
        java = self.work / "coordinator-jdk"
        result = desktop.prepare(self.root, {"sourceCommit": self.commit}, opener=self.opener, run=fake_gradle, java_home=str(java))
        self.assertEqual(("prepared", True, False), (result["state"], result["dependenciesExported"], result["nativeActionAllowed"]))
        self.assertEqual(sorted(self.payloads), sorted(self.downloads))
        call = fake_gradle.calls[0]
        self.assertEqual(str(java / "bin/java"), call["argv"][0])
        self.assertEqual([*guest.WRAPPER_JVM_OPTIONS, "-jar"], call["argv"][1:5])
        self.assertEqual(["--no-daemon", "--console=plain", "--init-script"], call["argv"][6:9])
        self.assertEqual([*guest.GRADLE_PROPERTIES, desktop.EXPORT_TASK], call["argv"][10:])
        self.assertNotIn("--offline", call["argv"])
        self.assertEqual(str(java), call["env"]["JAVA_HOME"])
        self.assertFalse(Path(call["env"]["ANDROID_HOME"]).exists())
        self.assertNotEqual(str(Path.home() / ".gradle"), call["env"]["GRADLE_USER_HOME"])
        cache = desktop.dependency_cache(self.root, result["dependencyDigest"])
        with zipfile.ZipFile(cache["path"]) as archive:
            self.assertIn("org/jetbrains/compose/desktop/desktop-jvm-windows-x64/1.7.0/desktop-jvm-windows-x64-1.7.0.jar", archive.namelist())
        self.assertEqual([], list((self.root / ".runtime/windows-desktop-test/work").iterdir()), "the export work folder is removed")
        again = desktop.prepare(self.root, {"sourceCommit": self.commit}, opener=self.opener, run=fake_gradle, java_home=str(java))
        self.assertEqual((False, len(self.payloads), 1), (again["dependenciesExported"], len(self.downloads), len(fake_gradle.calls)))
        self.assertEqual(result["archives"], again["archives"])

    def test_prepare_keeps_cis_sdk_and_the_nuget_seed_as_the_fifth_and_sixth_archives(self):
        result = desktop.prepare(self.root, {"sourceCommit": self.commit}, opener=self.opener, run=fake_gradle, java_home=str(self.work))
        self.assertEqual(["dependencies", "dotnet", "gradle", "jdk", "nuget", "source"], sorted(result["archives"]))
        self.assertEqual({"sha256": desktop.DOTNET["sha256"], "sha512": desktop.DOTNET["sha512"], "bytes": desktop.DOTNET["bytes"],
                          "version": "10.0.403", "entries": len(FAKE_SDK), "uncompressedBytes": sum(map(len, FAKE_SDK.values()))},
                         result["archives"]["dotnet"])
        self.assertEqual([{key: pin[key] for key in ("id", "version", "sha512", "bytes")} for pin in desktop.NUGET_PACKAGES],
                         result["archives"]["nuget"]["packages"])
        self.assertEqual(self.payloads[desktop.DOTNET["url"]], desktop.toolchain_path(self.root, desktop.DOTNET).read_bytes())
        seed = desktop.nuget_seed(self.root)
        self.assertEqual((seed["sha256"], seed["bytes"]), (result["archives"]["nuget"]["sha256"], result["archives"]["nuget"]["bytes"]))
        facts = desktop.source_facts(self.root, self.commit)
        archives = desktop.prepared_archives(self.root, facts)
        self.assertEqual(list(desktop.ARCHIVE_ROLES), list(archives))
        self.assertEqual((str(desktop.toolchain_path(self.root, desktop.DOTNET)), str(seed["path"])),
                         (archives["dotnet"]["localPath"], archives["nuget"]["localPath"]))

    def test_prepare_takes_only_the_commit(self):
        self.refused("desktop_test_inputs_invalid", desktop.prepare, self.root, {"sourceCommit": self.commit, "javaHome": "/x"})
        self.refused("desktop_test_source_commit_unknown", desktop.prepare, self.root, {"sourceCommit": "1" * 40}, opener=self.opener)
        self.assertEqual([], self.downloads)

    def test_an_archive_the_runner_would_refuse_stops_the_export_before_gradle(self):
        raw = zip_bytes({"other-root/lib/x.jar": b"x"})
        with mock.patch.dict(desktop.GRADLE, {"sha256": sha(raw), "bytes": len(raw)}):
            self.payloads[desktop.GRADLE["url"]] = raw
            self.refused("dependency_export_refused:zip-root", desktop.prepare, self.root, {"sourceCommit": self.commit},
                         opener=self.opener, run=fake_gradle, java_home=str(self.work))
        self.assertEqual([], fake_gradle.calls)
        self.assertEqual([], list((self.root / ".runtime/windows-desktop-test").glob("work/*")))

    def test_an_sdk_zip_the_runner_could_not_use_is_refused_by_prepare(self):
        for name, members, reason in (("without the runtime", {key: value for key, value in FAKE_SDK.items() if "shared/" not in key},
                                       "desktop_test_dotnet_archive_refused:dotnet-layout"),
                                      ("with a name Windows aliases", {**FAKE_SDK, "packs/aux.txt": b"x"},
                                       "desktop_test_dotnet_archive_refused:zip-entry-component")):
            with self.subTest(name=name):
                raw = zip_bytes(members)
                with mock.patch.dict(desktop.DOTNET, {"sha256": sha(raw), "sha512": hashlib.sha512(raw).hexdigest(), "bytes": len(raw)}):
                    self.payloads[desktop.DOTNET["url"]] = raw
                    self.refused(reason, desktop.prepare, self.root, {"sourceCommit": self.commit}, opener=self.opener, run=fake_gradle,
                                 java_home=str(self.work))
        self.assertEqual([], fake_gradle.calls, "refused before any export")

    def test_a_failed_export_keeps_no_repository(self):
        def failing(argv, **options):
            options["stdout"].write(b"Could not resolve all files\n")
            return subprocess.CompletedProcess(argv, 1)
        self.refused("dependency_export_gradle_failed", desktop.prepare, self.root, {"sourceCommit": self.commit}, opener=self.opener,
                     run=failing, java_home=str(self.work))
        store = self.root / ".runtime/windows-desktop-test"
        self.assertEqual([], list(store.glob("dependencies/*")) + list(store.glob("work/*")))
        digest = desktop.dependency_digest(self.root, self.commit)
        self.refused("desktop_test_dependencies_unprepared", desktop.dependency_cache, self.root, digest)
        kept = list(store.glob("export-failures/" + digest + "-*.log"))
        self.assertEqual(1, len(kept), "the failed export's console log is kept for reading")
        self.assertEqual((b"Could not resolve all files\n", 0o600), (kept[0].read_bytes(), kept[0].stat().st_mode & 0o777))


def pinned_gradle():
    """The pinned distribution where the commit's own wrapper keeps it, and a JDK: the coordinator's export needs both."""
    home = (Path.home() / ".gradle/wrapper/dists" / ("gradle-" + desktop.GRADLE["version"] + "-bin") / desktop.GRADLE["wrapperHash"]
            / desktop.GRADLE["root"])
    candidates = [os.environ.get("JAVA_HOME")]
    try:
        from agent_tools import local_build_environment
        candidates.append(local_build_environment.apply(ROOT, {}).get("JAVA_HOME"))
    except (OSError, ValueError):
        pass
    java = next((value for value in candidates if value and os.access(os.path.join(value, "bin", "java"), os.X_OK)), None)
    launcher = home / "bin" / "gradle"
    return (launcher, java) if os.name == "posix" and launcher.is_file() and java else (None, None)


class ExportSelectionTests(unittest.TestCase):
    """The export's init script under the pinned Gradle itself (offline, a fresh user home, the java plugin only) and
    this checkout's gradle.properties: the regression the fake Gradle of PrepareTests cannot be."""

    def test_the_export_task_is_selected_under_the_builds_configure_on_demand_and_nothing_else_is_configured(self):
        launcher, java = pinned_gradle()
        if launcher is None:
            self.skipTest("needs the pinned Gradle in the wrapper's own dists folder and a JDK (the coordinator has both)")
        properties = (ROOT / "gradle.properties").read_text(encoding="utf-8")
        self.assertRegex(properties, r"(?m)^org\.gradle\.configureondemand=true$", "the setting this regression stands for")
        with tempfile.TemporaryDirectory(prefix="vcdt-export-") as directory:
            work = Path(directory)
            project = work / "project"
            for relative, text in (("settings.gradle", "rootProject.name = 'fixture'\ninclude ':desktopApp'\ninclude ':app'\n"),
                                   ("gradle.properties", properties), ("desktopApp/build.gradle", "plugins { id 'java' }\n"),
                                   # The Android app cannot configure without an SDK: the export must never configure it.
                                   ("app/build.gradle", "throw new GradleException('vcdt fixture: :app was configured')\n")):
                (project / relative).parent.mkdir(parents=True, exist_ok=True)
                (project / relative).write_text(text, encoding="utf-8")
            init = work / "export-dependencies.gradle"
            init.write_text(desktop.EXPORT_INIT_SCRIPT, encoding="ascii")
            environment = {key: value for key, value in os.environ.items() if key.upper() not in guest.REMOVED_ENVIRONMENT}
            environment["JAVA_HOME"] = java
            done = subprocess.run([str(launcher), "--offline", "--no-daemon", "--console=plain", "--gradle-user-home", str(work / "home"),
                                   "--init-script", str(init), *guest.GRADLE_PROPERTIES, desktop.EXPORT_TASK], cwd=project, env=environment,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900, check=False)
        output = done.stdout.decode("utf-8", "replace")
        self.assertEqual(0, done.returncode, output[-4000:])
        self.assertIn("> Task " + desktop.EXPORT_TASK + "\n", output)


# The seed package the real-NuGet regression restores: nuget.org's own SHA-512, as windows_desktop_test pins it.
ILLINK = {"file": "microsoft.net.illink.tasks.10.0.14.nupkg",
          "sha256": "e2a71b32b5c135dc2b0c87ea8fba6c9e677332e00bf959fbcdced239b825b75c",
          "sha512": "6203bf1a4c7b11b6ffd0522342835176a9f67b522ecc265a893dcaccf90821b4ef435ed04467d83460420f091c30eb71d893b35a7d0ac2a9ee87a49d6d27d9ab"}


def offline_sdk():
    """The real-NuGet regression's inputs: an SDK of the pinned version for this host, named by VPN_CONTROL_TEST_DOTNET
    (as the desktop tests name theirs), and the pinned ILLink package where prepare keeps it, checked by its SHA-512."""
    program = os.environ.get("VPN_CONTROL_TEST_DOTNET")
    package = ROOT.joinpath(".runtime", "windows-desktop-test", "toolchain", ILLINK["sha256"])
    if os.name != "posix" or not program or not os.access(program, os.X_OK) or not package.is_file():
        return None, None
    if hashlib.sha512(package.read_bytes()).hexdigest() != ILLINK["sha512"]:
        return None, None
    return program, package


class OfflineRestoreTests(unittest.TestCase):
    """The guest build's .NET environment under a real SDK of the pinned version: an EnableAotAnalyzer probe whose own
    NuGet.Config adds a remote source (as two desktop tests' do) restores from the seed folder alone, fails rather than
    downloads without it, and nothing reaches that remote source, here a loopback recorder. It skips without the SDK
    and the prepared package; the build clone's evidence ran it with the verified osx-arm64 SDK 10.0.403."""

    def recorder(self):
        import http.server
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *arguments):
                pass
        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d/v3/index.json" % server.server_address[1], requests

    def test_a_probe_restores_only_from_the_seed_folder_and_nothing_reaches_its_own_remote_source(self):
        program, package = offline_sdk()
        if program is None:
            self.skipTest("needs VPN_CONTROL_TEST_DOTNET (an SDK 10.0.403 for this host) and the pinned ILLink package from prepare")
        remote, requests = self.recorder()
        with tempfile.TemporaryDirectory(prefix="vcdt-nuget-") as directory:
            work, home, probe = Path(directory) / "w", Path(directory) / "home", Path(directory) / "probe"
            for path in (work / "n" / "feed", work / "t", work / "dh", home, probe):
                path.mkdir(parents=True)
            runner = guest.Runner({"operationId": "0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e", "workRoot": str(work), "sourceCommit": "a" * 40,
                                   "operationRoot": str(Path(directory) / "operation")}, guest.PosixPlatform())
            runner.jdk_home, runner.dotnet_home = str(Path(directory) / "jdk"), str(Path(program).parent)
            if hasattr(guest, "nuget_config"):
                (work / "n" / "NuGet.Config").write_text(guest.nuget_config(str(work / "n" / "feed"), str(work / "n" / "packages")))
            environment = runner.environment()
            # This host's own home stays untouched: NuGet's once-per-user marker lands in the temporary home.
            environment.update(HOME=str(home), XDG_DATA_HOME=str(home / ".local" / "share"), TMPDIR=str(work / "t"))
            # What DesktopWindowsCoordinatorAdapterTest gives its dotnet, the "1" the SDK does not read as true included.
            environment.update(DOTNET_CLI_HOME=str(probe / "dotnet-home"), DOTNET_SKIP_FIRST_TIME_EXPERIENCE="1", DOTNET_CLI_TELEMETRY_OPTOUT="1",
                               DOTNET_MULTILEVEL_LOOKUP="0", DOTNET_NOLOGO="1", DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE="1",
                               MSBUILDDISABLENODEREUSE="1")
            shutil.copyfile(ROOT / DOTNET_GLOBAL_JSON, probe / "global.json")
            (probe / "NuGet.Config").write_text('<configuration><packageSources><clear /><add key="nuget.org" value="' + remote
                                                + '" protocolVersion="3" allowInsecureConnections="true" /></packageSources></configuration>')
            (probe / "Probe.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><OutputType>Exe</OutputType>'
                '<UseAppHost>false</UseAppHost><Nullable>disable</Nullable><ImplicitUsings>disable</ImplicitUsings>'
                '<TreatWarningsAsErrors>true</TreatWarningsAsErrors><EnableAotAnalyzer>true</EnableAotAnalyzer></PropertyGroup></Project>')
            (probe / "Program.cs").write_text("internal static class P { public static void Main() { System.Console.WriteLine(1); } }\n")

            def dotnet(*arguments):
                done = subprocess.run([program, *arguments], cwd=probe, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, timeout=600, check=False)
                return done.returncode, done.stdout.decode("utf-8", "replace")
            code, output = dotnet("--version")
            if code != 0 or output.strip().splitlines()[-1:] != [json.loads((ROOT / DOTNET_GLOBAL_JSON).read_text())["sdk"]["version"]]:
                self.skipTest("VPN_CONTROL_TEST_DOTNET is not the pinned SDK version")
            build = ("build", "Probe.csproj", "--configuration", "Release", "--disable-build-servers", "-p:UseSharedCompilation=false")
            code, output = dotnet(*build)
            self.assertNotEqual(0, code, output[-3000:])
            self.assertIn("error NU1101: Unable to find package Microsoft.NET.ILLink.Tasks. No packages exist with this id in source(s): "
                          "vpnControlDesktopTestOffline\n", output, "an empty seed fails the restore; nothing is downloaded")
            shutil.copyfile(package, work / "n" / "feed" / ILLINK["file"])
            shutil.rmtree(probe / "obj", ignore_errors=True)
            code, output = dotnet(*build)
            self.assertEqual(0, code, output[-3000:])
            assets = json.loads((probe / "obj" / "project.assets.json").read_text())
            self.assertEqual((["Microsoft.NET.ILLink.Tasks/10.0.14"], [str(work / "n" / "feed")], [str(work / "n" / "NuGet.Config")]),
                             (sorted(assets["libraries"]), sorted(assets["project"]["restore"]["sources"]),
                              assets["project"]["restore"]["configFilePaths"]))
            self.assertTrue((work / "n" / "packages" / "microsoft.net.illink.tasks" / "10.0.14" / ".nupkg.metadata").is_file())
            sentinels = sorted(path.name for path in (probe / "dotnet-home" / ".dotnet").iterdir())
        self.assertEqual([], requests, "nothing reached the probe's own remote source, the SDK's workload check included")
        self.assertEqual(["10.0.403.dotnetFirstUseSentinel"], sentinels, "no development certificate and no tools PATH entry")


@unittest.skipUnless(os.name == "posix" and shutil.which("git"), "private journals are POSIX and a source is a git commit")
class DriverBase(RepositoryBase):
    def setUp(self):
        super().setUp()
        for relative in desktop.BUNDLE_FILES:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.intent(MACHINE)
        key, known = self.work / "key", self.work / "known"
        for path in (key, known):
            path.write_text(path.name)
            path.chmod(0o600)
        config = self.root / ".vm-hosts.local.json"
        config.write_text(json.dumps({"schemaVersion": 1, "hosts": {"fixture": {"host": "fixture", "port": 22, "user": "tester",
                                                                                "identityFile": str(key), "knownHostsFile": str(known)}}}))
        config.chmod(0o600)
        for name, pin in (("JDK", desktop.JDK), ("GRADLE", desktop.GRADLE)):
            raw = (name + " distribution ").encode() * 64
            patcher = mock.patch.dict(pin, {"sha256": sha(raw), "bytes": len(raw)})
            patcher.start()
            self.addCleanup(patcher.stop)
            target = desktop.toolchain_path(self.root, pin)
            target.write_bytes(raw)
            target.chmod(0o600)
        for url, raw in patch_dotnet_pins(self).items():  # As prepare keeps them; the seed is made from these at start.
            target = desktop.toolchain_path(self.root, next(pin for pin in (desktop.DOTNET, *desktop.NUGET_PACKAGES) if pin["url"] == url))
            target.write_bytes(raw)
            target.chmod(0o600)
        self.dependencies(self.commit)
        self.ssh = DesktopSsh(self.work)
        for patcher in (mock.patch.object(transport, "admitted_transport", return_value=nullcontext()),
                        mock.patch.object(transport, "build_ssh_argv", side_effect=lambda config, host, timeout, command, ssh_binary: ["fake-ssh", *command]),
                        mock.patch.object(transport, "run_ssh", side_effect=lambda argv, **options: self.ssh.run(argv, **options))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.operation = str(uuid.uuid4())

    def intent(self, machine, *, setup=None, context=None):
        spec = vm_request()
        spec.update(deploymentId=machine, host="fixture", root="/owned/vm")
        value = {"spec": spec, "setup": {**setup_fields(), **(setup or {})},
                 "context": {"hostBootId": TARGET["bootId"], "pending": [], **(context or {})},
                 "correlationId": str(uuid.uuid4()), "mode": "start", "callerSha256": "c" * 64}
        directory = self.root / ".rag_index/windows-vm-deploy-intents"
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        path = directory / (machine + ".intent.json")
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def dependencies(self, source_commit):
        digest = desktop.dependency_digest(self.root, source_commit)
        directory = self.root / ".runtime/windows-desktop-test/dependencies" / digest
        directory.mkdir(parents=True, mode=0o700)
        raw = zip_bytes({"org/example/lib/1.0/lib-1.0.jar": b"PK repository"})
        (directory / "repository.zip").write_bytes(raw)
        manifest = {"schema": desktop.DEPENDENCY_SCHEMA, "schemaVersion": 1, "dependencyDigest": digest, "zipSha256": sha(raw),
                    "zipBytes": len(raw), "entries": 1}
        (directory / "manifest.json").write_text(json.dumps(manifest))
        for path in directory.iterdir():
            path.chmod(0o600)

    def inputs(self, **changes):
        return {"deploymentId": MACHINE, "operationId": self.operation, "sourceCommit": self.commit, **changes}

    def status(self, **changes):
        return desktop.status(self.root, {"deploymentId": MACHINE, "operationId": self.operation, **changes})

    def operation_directory(self):
        return self.root / ".runtime/windows-desktop-test/operations" / self.operation

    def finished(self, *, exit_code=0, stage="receipt", failure=None, gradle_exit=0, xml=(XML_ALPHA,), console=b"BUILD SUCCESSFUL in 9m\n",
                 runner_outcome="completed"):
        results = zip_bytes({**{"test-results/TEST-%d.xml" % number: text.encode() for number, text in enumerate(xml)},
                             guest.CONSOLE_LEAF: console})
        runner = {"schema": guest.SUMMARY_SCHEMA, "schemaVersion": 1, "operationId": self.operation, "sourceCommit": self.commit,
                  "outcome": runner_outcome, "failedStage": None, "failure": None,
                  "stages": [{"name": name, "outcome": "passed", "seconds": 1.0, "code": None} for name in (*guest.STAGES, "cleanup")],
                  "gradle": {"exitCode": gradle_exit, "seconds": 540.0, "deadline": False, "leftoverProcesses": [], "consoleBytes": len(console)},
                  "results": {"name": guest.RESULTS_LEAF, "bytes": len(results), "sha256": sha(results), "xmlFiles": len(xml)},
                  "jdkRelease": {"JAVA_VERSION": "17.0.21", "IMPLEMENTOR": "Eclipse Adoptium"}, "archives": {}, "freeBytesBefore": 30 * 1024 ** 3,
                  "dotnet": {"sdkVersion": "10.0.403", "runtimeVersion": "10.0.14", "reported": "10.0.403", "exitCode": 0},
                  "nuget": {"source": "vpnControlDesktopTestOffline", "packages": ["microsoft.net.illink.tasks.10.0.14.nupkg"]},
                  "freeBytesAfter": 31 * 1024 ** 3, "productProcessesBefore": [], "productProcessesAfter": [],
                  "productState": {".vpn-control-desktop": {"present": False, "unchanged": True}},
                  "userToolState": {"AppData/Local/NuGet": {"presentBefore": False, "presentAfter": True, "unchanged": False,
                                                            "changedNames": ["Migrations/1"]},
                                    "AppData/Roaming/NuGet": {"presentBefore": False, "presentAfter": False, "unchanged": True}},
                  "profileEntries": {"added": [".skiko"], "removed": []}, "seconds": 600.0,
                  "workRoot": {"created": True, "deleted": True, "error": None}}
        summary_raw = json.dumps(runner, sort_keys=True).encode()
        evidence = b"PK" + b"evidence" * 100
        record = json.loads((self.operation_directory() / "request.json").read_text())
        block = {"sourceCommit": self.commit, "archives": {role: row["sha256"] for role, row in record["archives"].items()},
                 "runnerOutcome": runner_outcome, "runnerFailedStage": None, "runnerFailure": None, "gradleExitCode": gradle_exit,
                 "gradleDeadline": False, "gradleSeconds": 540.0, "summary": {"bytes": len(summary_raw), "sha256": sha(summary_raw)},
                 "results": {"bytes": len(results), "sha256": sha(results), "xmlFiles": len(xml)}, "workRootDeleted": True,
                 "disk": {"freeBytes": 40 * 1024 ** 3, "neededBytes": 11 * 1024 ** 3},
                 "cleanup": {"state": "complete", "archives": ["deleted"] * len(desktop.ARCHIVE_ROLES), "freeBytes": 41 * 1024 ** 3}}
        receipt = host_job.build_receipt({"scenarioId": desktop.SCENARIO_ID, "operationId": self.operation, "machine": MACHINE,
                                          "bundleHash": record["plan"]["bundleHash"]}, exit_code=exit_code, stage=stage, failure=failure,
                                         evidence={"name": "evidence-1.zip", "bytes": len(evidence), "sha256": sha(evidence), "entries": 3},
                                         guest_programs=14, task={"state": "task-finished", "ownerExitCode": 0, "terminalExitCode": 0,
                                                                  "events": [{}, {}, {}], "taskDeleted": True, "parkedFiles": []})
        receipt["desktopTest"] = block
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self.ssh.job, self.ssh.exit_code = "terminal", exit_code
        self.ssh.collect_reply = {"state": "collected", "receipt": base64.b64encode(raw).decode(),
                                  "jobExit": {"schemaVersion": 1, "operationId": self.operation, "exitCode": exit_code, "fenceAnchored": True}}
        self.ssh.kept = {"evidence-1.zip": evidence, guest.SUMMARY_LEAF: summary_raw, guest.RESULTS_LEAF: results}
        return raw


class StartTests(DriverBase):
    def test_start_stages_then_submits_one_job_and_records_its_inputs(self):
        started = desktop.start(self.root, self.inputs())
        self.assertEqual(("submitted", "submitted", False, False), (started["state"], started["reason"], started["replayAllowed"], started["productAction"]))
        roles = len(desktop.ARCHIVE_ROLES)
        self.assertEqual(["stage-check", "stage-write"] * roles + ["target", *["stage-check"] * roles, "prepare", "submit"], self.ssh.calls)
        self.assertEqual(1, self.ssh.submits)
        record = json.loads((self.operation_directory() / "request.json").read_text())
        self.assertEqual((MACHINE, self.commit, "direct"), (record["deploymentId"], record["sourceCommit"], record["route"]))
        self.assertEqual(desktop.TOOLCHAIN, record["toolchain"])
        self.assertEqual(sha((self.root / ".runtime/windows-desktop-test/sources" / (self.commit + ".zip")).read_bytes()),
                         record["archives"]["source"]["sha256"])
        self.assertEqual(record["archives"]["source"]["sha256"], started["sourceArchiveSha256"])
        program = json.loads((self.root / ".rag_index/windows-desktop-test" / self.operation / "program.json").read_text())
        self.assertIn("class DesktopTestJob(Job)", program["program"]["source"])
        self.assertEqual(sorted(row["sha256"] for row in record["archives"].values()), sorted(self.ssh.staged))

    def test_cis_sdk_and_the_nuget_seed_are_staged_and_given_to_the_job_with_their_pins(self):
        started = desktop.start(self.root, self.inputs())
        self.assertEqual({role: "staged" for role in ("source", "jdk", "gradle", "dependencies", "dotnet", "nuget")}, started["staged"])
        self.assertEqual("10.0.403", started["toolchain"]["dotnet"])
        record = json.loads((self.operation_directory() / "request.json").read_text())
        seed = desktop.nuget_seed(self.root)
        self.assertEqual(({"sha256": desktop.DOTNET["sha256"], "bytes": desktop.DOTNET["bytes"]}, {"sha256": seed["sha256"], "bytes": seed["bytes"]}),
                         (record["archives"]["dotnet"], record["archives"]["nuget"]))
        self.assertEqual({"sdkVersion": "10.0.403", "runtimeVersion": "10.0.14"}, record["desktopTest"]["dotnet"])
        self.assertEqual([{"file": pin["file"], "sha512": pin["sha512"], "bytes": pin["bytes"]} for pin in desktop.NUGET_PACKAGES],
                         record["desktopTest"]["nuget"]["packages"])
        self.assertEqual({"dotnetArchive": "sha256-" + desktop.DOTNET["sha256"], "nugetArchive": "sha256-" + seed["sha256"]},
                         {key: value for key, value in record["plan"]["artifactIds"].items() if key in ("dotnetArchive", "nugetArchive")})
        self.assertEqual(desktop.MINIMUM_FREE_BYTES, record["desktopTest"]["minimumFreeBytes"])
        program = json.loads((self.root / ".rag_index/windows-desktop-test" / self.operation / "program.json").read_text())
        tree = ast.parse(program["program"]["source"])
        plan = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "PLAN"))
        self.assertEqual((record["desktopTest"], {role: record["archives"][role] for role in desktop.ARCHIVE_ROLES}),
                         (plan["desktopTest"], plan["packages"]))

    def test_a_second_start_of_one_operation_is_refused_and_submits_nothing(self):
        desktop.start(self.root, self.inputs())
        calls = list(self.ssh.calls)
        for inputs in (self.inputs(), self.inputs(sourceCommit=commit(self.root, {"README.md": "again\n"}))):
            with self.subTest(inputs=inputs):
                self.refused("desktop_test_operation_exists", desktop.start, self.root, inputs)
        self.assertEqual((calls, 1), (self.ssh.calls, self.ssh.submits))

    def test_a_staged_archive_is_never_sent_again(self):
        desktop.start(self.root, self.inputs())
        self.operation = str(uuid.uuid4())
        self.ssh.calls.clear()
        self.assertEqual("submitted", desktop.start(self.root, self.inputs())["state"])
        self.assertNotIn("stage-write", self.ssh.calls)

    def test_refusals_before_any_contact_journal_or_record(self):
        cases = (("desktop_test_source_commit_unknown", self.inputs(sourceCommit="1" * 40)),
                 ("desktop_test_source_commit_invalid", self.inputs(sourceCommit=self.commit.upper())),
                 ("desktop_test_deployment_unknown", self.inputs(deploymentId=OTHER)))
        for reason, inputs in cases:
            with self.subTest(reason=reason):
                self.refused(reason, desktop.start, self.root, inputs)
        for reason, setup, context in (("desktop_test_deployment_foreign", {"purpose": "windowsUacVisual"}, None),
                                       ("desktop_test_deployment_foreign", None, {"network": "restricted"})):
            with self.subTest(setup=setup, context=context):
                self.intent(OTHER, setup=setup, context=context)
                self.refused(reason, desktop.start, self.root, self.inputs(deploymentId=OTHER))
        self.assertEqual([], self.ssh.calls)
        self.assertFalse(self.operation_directory().exists())
        self.assertFalse((self.root / ".rag_index/windows-desktop-test-executions" / (self.operation + ".json")).exists())

    def test_an_unprepared_commit_is_refused_before_contact(self):
        changed = commit(self.root, {"desktopApp/build.gradle.kts": "plugins { id(\"other\") }\n"})
        self.refused("desktop_test_dependencies_unprepared", desktop.start, self.root, self.inputs(sourceCommit=changed))
        self.assertEqual([], self.ssh.calls)

    def test_a_staging_failure_leaves_nothing_so_the_operation_may_start(self):
        self.ssh.lost = {"stage-write"}
        self.refused("desktop_test_stage_unavailable", desktop.start, self.root, self.inputs())
        self.assertFalse((self.operation_directory() / "request.json").exists())
        self.assertEqual("submitted", desktop.start(self.root, self.inputs())["state"])
        self.assertEqual(1, self.ssh.submits)

    def test_a_lost_submit_reply_is_recovered_by_status_and_never_resubmitted(self):
        self.ssh.lost = {"submit"}
        started = desktop.start(self.root, self.inputs())
        self.assertEqual(("submitting", "submit_response_unavailable", "windows-desktop-test-status"),
                         (started["state"], started["reason"], started["nextAction"]))
        self.assertEqual("submitted", self.status()["state"])
        self.refused("desktop_test_operation_exists", desktop.start, self.root, self.inputs())
        self.assertEqual(1, self.ssh.submits)


class StatusTests(DriverBase):
    def setUp(self):
        super().setUp()
        desktop.start(self.root, self.inputs())

    def test_status_of_an_unknown_operation_or_another_deployment_is_refused_without_contact(self):
        calls = list(self.ssh.calls)
        self.refused("desktop_test_operation_unknown", desktop.status, self.root, {"deploymentId": MACHINE, "operationId": str(uuid.uuid4())})
        self.refused("desktop_test_operation_deployment_mismatch", desktop.status, self.root, {"deploymentId": OTHER, "operationId": self.operation})
        self.refused("desktop_test_inputs_invalid", desktop.status, self.root, self.inputs())
        self.assertEqual(calls, self.ssh.calls)

    def test_a_running_job_names_the_runners_last_stage(self):
        self.assertEqual(("submitted", "original_owner_running"), (self.status()["state"], self.status()["reason"]))
        self.ssh.job_files["desktop-progress.json"] = {"stage": "gradle", "elapsedSeconds": 754, "poll": 13}
        self.assertEqual("desktop_test_running:gradle:754s", self.status()["reason"])
        for bad in ({"stage": "Gradle"}, {"stage": "a" * 40}, ["gradle"]):
            with self.subTest(bad=bad):
                self.ssh.job_files["desktop-progress.json"] = bad
                self.assertEqual("original_owner_running", self.status()["reason"])
        self.assertEqual(1, self.ssh.submits)

    def test_a_terminal_job_is_copied_back_and_summarized(self):
        self.finished(xml=(XML_ALPHA,))
        view = self.status()
        self.assertEqual(("terminal", "completed", None, "passed"), (view["state"], view["toolOutcome"], view["failedStage"], view["testOutcome"]))
        self.assertEqual({"classes": 1, "tests": 2, "failures": 0, "errors": 0, "skipped": 1, "timeSeconds": 1.25}, view["tests"])
        self.assertEqual(("17.0.21+9", "8.10.2", 1), (view["jdk"], view["gradle"], view["skippedTests"]))
        directory = self.operation_directory()
        for name in ("receipt.json", "summary.json", "evidence-1.zip", guest.SUMMARY_LEAF, guest.RESULTS_LEAF):
            self.assertEqual(0o600, (directory / name).stat().st_mode & 0o777, name)
        self.assertEqual(XML_ALPHA.encode(), (directory / "results/test-results/TEST-0.xml").read_bytes())
        summary = json.loads((directory / "summary.json").read_text())
        self.assertEqual((self.commit, view["sourceArchiveSha256"], {"JAVA_VERSION": "17.0.21", "IMPLEMENTOR": "Eclipse Adoptium"}),
                         (summary["sourceCommit"], summary["archives"]["source"]["sha256"], summary["toolchain"]["jdkRelease"]))
        self.assertEqual([{"class": "com.example.AlphaTest", "name": "later"}], summary["skippedTests"])
        self.assertEqual({"workRootDeleted": True, "archivesCleanup": "complete", "disk": {"freeBytes": 40 * 1024 ** 3, "neededBytes": 11 * 1024 ** 3},
                          "profileEntriesAdded": [".skiko"], "userToolStateChanged": ["AppData/Local/NuGet"]}, summary["hygiene"])
        self.assertEqual(".runtime/windows-desktop-test/operations/" + self.operation + "/summary.json", view["summary"])
        pulls = self.ssh.pulls
        self.assertEqual(view, self.status(), "a terminal operation is read, never run again")
        self.assertEqual((pulls, 1), (self.ssh.pulls, self.ssh.submits))

    def test_failing_tests_are_a_completed_tool_with_a_failed_test_outcome(self):
        self.finished(gradle_exit=1, xml=(XML_ALPHA, XML_BETA), console=b"There were failing tests.\nBUILD FAILED in 9m\n")
        view = self.status()
        self.assertEqual(("completed", "failed", 1), (view["toolOutcome"], view["testOutcome"], view["tests"]["failures"]))
        self.assertEqual([{"class": "com.example.BetaTest", "name": "breaks", "kind": "failure", "type": "java.lang.AssertionError"}],
                         view["failedTests"])

    def test_a_tool_stage_failure_names_its_stage(self):
        self.finished(exit_code=1, stage="cleanup", failure="desktop_cleanup_incomplete")
        view = self.status()
        self.assertEqual(("failed", "cleanup", "desktop_cleanup_incomplete", "passed"),
                         (view["toolOutcome"], view["failedStage"], view["failure"], view["testOutcome"]))

    def test_results_this_tool_cannot_read_are_its_own_failure(self):
        self.finished(xml=('<!DOCTYPE x [<!ENTITY a "b">]><testsuite name="x" tests="1"/>',))
        view = self.status()
        self.assertEqual(("terminal", "failed", "results-read", "desktop_test_results_xml_declaration"),
                         (view["state"], view["toolOutcome"], view["failedStage"], view["failure"]))
        self.assertEqual(view, self.status(), "the summary is written once")
        self.assertEqual([], list(self.operation_directory().glob("results.*.partial")))

    def test_an_unknown_job_exit_is_read_but_stays_unknown(self):
        self.finished(exit_code=3, stage="cleanup", failure="guest_exec_status_lost:desktop-cleanup")
        view = self.status()
        self.assertEqual(("unknown", "unknown", "cleanup"), (view["state"], view["toolOutcome"], view["failedStage"]))
        self.assertTrue(view["reason"].startswith("job_exit_unknown:"))
        self.assertEqual("passed", view["testOutcome"], "its results were still copied back")
        self.assertEqual(1, self.ssh.submits)

    def test_a_dependency_the_offline_repository_lacks_is_the_tools_failure_though_gradle_names_the_test_task(self):
        for console in (MISSING_JAR_CONSOLE, MISSING_MODULE_CONSOLE):
            with self.subTest(console=console.splitlines()[-1]):
                self.setUp()
                self.finished(gradle_exit=1, xml=(), console=console.encode())
                view = self.status()
                self.assertEqual(("terminal", "failed", "gradle-dependencies", "not-run"),
                                 (view["state"], view["toolOutcome"], view["failedStage"], view["testOutcome"]))

    def test_a_test_that_could_not_start_dotnet_is_a_failure_like_any_other(self):
        # What the guest's missing dotnet.exe used to produce: the guest now has CI's SDK, and no failure is excluded.
        console = b"There were failing tests. See the report at: file:///C:/x/index.html\nBUILD FAILED in 9m\n"
        self.finished(gradle_exit=1, xml=(XML_ALPHA, dotnet_xml(self.operation)), console=console)
        view = self.status()
        self.assertEqual(("completed", None, "failed", 2, 0), (view["toolOutcome"], view["failedStage"], view["testOutcome"],
                                                               len(view["failedTests"]), view["toolCausedTests"]))
        summary = json.loads((self.operation_directory() / "summary.json").read_text())
        self.assertNotIn("excludedTests", view)
        self.assertNotIn("excludedTests", summary)
        self.assertEqual(2, summary["tests"]["failures"], "the totals stay Gradle's own")
        self.assertEqual(("10.0.403", "10.0.403"), (view["dotnet"], summary["toolchain"]["dotnetReported"]))

    def test_a_package_the_offline_seed_lacks_is_the_tools_failure_not_the_sources(self):
        console = b"There were failing tests. See the report at: file:///C:/x/index.html\nBUILD FAILED in 9m\n"
        self.finished(gradle_exit=1, xml=(XML_ALPHA, XML_BETA, build_failure_xml(SEED_MISSING_BUILD)), console=console)
        view = self.status()
        self.assertEqual(("terminal", "failed", "dotnet-packages", "failed", 1),
                         (view["state"], view["toolOutcome"], view["failedStage"], view["testOutcome"], view["toolCausedTests"]))
        summary = json.loads((self.operation_directory() / "summary.json").read_text())
        self.assertEqual([("com.example.BetaTest", None), ("com.kardinal.vpncontrol.desktop.DesktopWindowsCoordinatorAdapterTest", "dotnet-packages")],
                         [(row["class"], row.get("toolCause")) for row in summary["failedTests"]], "the source's own failure stays its own")
        self.assertEqual((2, ["AppData/Local/NuGet"]), (summary["tests"]["failures"], summary["hygiene"]["userToolStateChanged"]))

    def test_restore_words_that_do_not_name_the_seed_stay_the_sources_failure(self):
        console = b"There were failing tests. See the report at: file:///C:/x/index.html\nBUILD FAILED in 9m\n"
        for output in (SEED_MISSING_BUILD.replace("vpnControlDesktopTestOffline", "nuget.org"),
                       "  warning: package source vpnControlDesktopTestOffline is local\nerror CS1002: ; expected\n"):
            with self.subTest(output=output[:60]):
                self.setUp()
                self.finished(gradle_exit=1, xml=(XML_ALPHA, build_failure_xml(output)), console=console)
                view = self.status()
                self.assertEqual(("completed", "failed", 1, 0), (view["toolOutcome"], view["testOutcome"], len(view["failedTests"]),
                                                                 view.get("toolCausedTests", 0)))

    def test_any_other_failure_to_start_a_program_still_fails_the_source(self):
        console = b"There were failing tests. See the report at: file:///C:/x/index.html\nBUILD FAILED in 9m\n"
        for xml in (dotnet_xml(self.operation, program="dotnet.exe"), dotnet_xml("99999999-0000-4000-8000-000000000000"),
                    dotnet_xml(self.operation, error="CreateProcess error=5, Access is denied")):
            with self.subTest(xml=xml[:60]):
                self.setUp()
                self.finished(gradle_exit=1, xml=(XML_ALPHA, xml), console=console)
                view = self.status()
                self.assertEqual(("completed", "failed", 2, 0), (view["toolOutcome"], view["testOutcome"], len(view["failedTests"]),
                                                                 view.get("excludedTests", 0)))

    def test_an_unknown_exit_whose_copy_back_was_cut_is_copied_back_by_a_later_status(self):
        self.finished(exit_code=3, stage="cleanup", failure="guest_exec_status_lost:desktop-cleanup")
        self.ssh.lost = {"pull"}
        first = self.status()
        self.assertEqual(("unknown", "incomplete"), (first["state"], first.get("copyBack")))
        self.assertNotIn("toolOutcome", first, "nothing is summarized before every kept file is here")
        self.assertEqual([], [path.name for path in self.operation_directory().glob("summary*.json")])
        second = self.status()
        self.assertEqual(("unknown", "unknown", "passed", 2), (second["state"], second["toolOutcome"], second["testOutcome"],
                                                               second["tests"]["tests"]))
        self.assertEqual(".runtime/windows-desktop-test/operations/" + self.operation + "/summary-unknown.json", second["summary"])
        self.assertNotIn("copyBack", second)
        pulls = self.ssh.pulls
        self.assertEqual(second, self.status(), "copied back once, then only read")
        self.assertEqual((pulls, 1), (self.ssh.pulls, self.ssh.submits))

    def test_one_copy_back_at_a_time_so_two_status_reads_never_write_one_file(self):
        # Two status reads of one UNKNOWN exit: the second starts while the first is between two chunks of the results,
        # whose stored console makes them three chunks long.
        console = b"> Task :desktopApp:test\n" + b"." * (2 * desktop._PULL_CHUNK + 4096) + b"\nBUILD SUCCESSFUL in 9m\n"
        self.finished(exit_code=3, stage="cleanup", failure="guest_exec_status_lost:desktop-cleanup", console=console)
        results = self.ssh.kept[guest.RESULTS_LEAF]
        self.assertEqual(3, -(-len(results) // desktop._PULL_CHUNK))
        first, second_at_chunk, first_wrote = threading.current_thread(), threading.Event(), threading.Event()
        views, threads = [], []

        def second_read():
            try:
                views.append(self.status())
            except Exception as error:  # Two summaries created at once: the second create-only write fails.
                views.append({"state": "raised", "copyBack": type(error).__name__})
            finally:
                second_at_chunk.set()

        def hook(name, offset):
            if name != guest.RESULTS_LEAF:
                return
            if threading.current_thread() is first and offset == desktop._PULL_CHUNK and not threads:
                threads.append(threading.Thread(target=second_read, daemon=True))
                threads[0].start()
                second_at_chunk.wait(60)  # The second read reaches the results, or ends.
            elif threading.current_thread() is not first and offset == 2 * desktop._PULL_CHUNK:
                second_at_chunk.set()  # It appended the second chunk the first read is about to append as well.
                first_wrote.wait(60)
            elif threading.current_thread() is first and offset == 2 * desktop._PULL_CHUNK:
                first_wrote.set()
        self.ssh.pull_hook = hook
        view = self.status()
        threads[0].join(60)
        self.assertEqual(1, len(views), "the second read returned")
        self.assertEqual(("unknown", "busy"), (views[0]["state"], views[0].get("copyBack")), "the second read wrote nothing")
        self.assertEqual(("unknown", "passed"), (view["toolOutcome"], view["testOutcome"]))
        directory = self.operation_directory()
        self.assertEqual(sha(results), sha((directory / guest.RESULTS_LEAF).read_bytes()))
        self.assertEqual([], [path.name for path in directory.glob("*.partial")])

    def test_a_changed_results_file_is_never_kept(self):
        self.finished()
        self.ssh.kept[guest.RESULTS_LEAF] = self.ssh.kept[guest.RESULTS_LEAF][:-1] + b"!"
        view = self.status()
        self.assertEqual(("unknown", "terminal_collection_unverified"), (view["state"], view["reason"]))
        self.assertFalse((self.operation_directory() / guest.RESULTS_LEAF).exists())
        self.assertNotIn("toolOutcome", view)

    def test_the_largest_desktop_receipt_fits_the_receipt_and_collection_bounds(self):
        word = "x" * 120
        task = {"state": word, "ownerExitCode": 2 ** 31, "terminalExitCode": 2 ** 31, "lastTaskResult": -2 ** 31, "events": [{}] * 512,
                "workerEvents": 8192, "taskDeleted": True, "parkedFiles": ["task-owner-parked.json"], "commandLineMatched": True,
                "enginePid": 2 ** 32, "ownerPid": 2 ** 32, "polls": 10 ** 6, "statusFailures": 10 ** 6,
                "rawStreams": [{"name": name, "bytes": 64 * 1024 ** 2, "sha256": "f" * 64} for name in ("stdout", "stderr")]}
        context = {"ordinarySid": "S-1-5-21-" + "-".join(["4294967295"] * 4), "ordinarySessionId": 2 ** 32, "profileRoot": "C:\\Users\\" + "u" * 32,
                   "bootFileTimeUtc": "1" * 19, "bootIdentifier": "f" * 36, "hardwareUuid": "F" * 36, "machineGuid": "f" * 36}
        plan = {"scenarioId": desktop.SCENARIO_ID, "operationId": self.operation, "machine": MACHINE, "bundleHash": "f" * 64}
        receipt = host_job.build_receipt(plan, exit_code=1, stage="results", failure=word, context=context, task=task, guest_programs=4096,
                                         evidence={"name": "evidence-999999.zip", "bytes": 32 * 1024 ** 2, "sha256": "f" * 64, "entries": 8192})
        receipt["desktopTest"] = {
            "sourceCommit": "f" * 40, "archives": {role: "f" * 64 for role in desktop.ARCHIVE_ROLES}, "runnerOutcome": "failed",
            "runnerFailedStage": "extract-dependencies", "runnerFailure": word, "gradleExitCode": -2 ** 31, "gradleDeadline": True,
            "gradleSeconds": 10800.123456789, "summary": {"bytes": 1024 ** 2, "sha256": "f" * 64},
            "results": {"bytes": guest.RESULTS_ZIP_LIMIT, "sha256": "f" * 64, "xmlFiles": guest.RESULT_ENTRY_LIMIT}, "workRootDeleted": False,
            "disk": {"freeBytes": 2 ** 63 - 1, "neededBytes": 2 ** 40},
            "cleanup": {"state": "incomplete", "archives": ["not-the-published-file"] * len(desktop.ARCHIVE_ROLES), "freeBytes": 2 ** 63 - 1}}
        raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self.assertLessEqual(len(raw), host_job.RECEIPT_BYTES)
        driver = desktop.DesktopTestDriver(self.root)
        plan = execution.ScenarioPlan.from_mapping(json.loads((self.operation_directory() / "request.json").read_text())["plan"])
        summary = driver._summary(plan, raw, {"operationId": self.operation, "exitCode": 1})
        payload = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        self.assertLessEqual(len(payload), execution._COLLECTION_LIMIT)
        self.assertTrue(execution.ScenarioExecutor._collection_matches(plan, 1, json.loads(payload)))


class RenderTests(DriverBase):
    def rendered(self):
        desktop.start(self.root, self.inputs())
        program = json.loads((self.root / ".rag_index/windows-desktop-test" / self.operation / "program.json").read_text())
        return program["program"]["source"], program["dataDirectory"]

    def test_the_job_is_the_scenario_job_with_this_job_over_it(self):
        source, data = self.rendered()
        self.assertLess(len(source.encode()), carrier.MAX_SOURCE_BYTES)
        tree = ast.parse(source)
        self.assertIsInstance(tree.body[-1], ast.Raise)
        functions = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
        classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
        self.assertEqual(2, functions.count("run_job"))
        self.assertLess(classes.index("Job"), classes.index("DesktopTestJob"))
        last = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "run_job"][-1]
        self.assertIn("DesktopTestJob", ast.unparse(last))
        last_job = max(index for index, node in enumerate(tree.body) if isinstance(node, ast.FunctionDef) and node.name == "run_job")
        main = next(index for index, node in enumerate(tree.body) if isinstance(node, ast.FunctionDef) and node.name == "_host_main")
        self.assertLess(main, last_job, "the base main finds this job's run_job when it runs")
        plan = next(node.value for node in tree.body if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "PLAN")
        value = ast.literal_eval(plan)
        self.assertEqual((desktop.SCENARIO_ID, desktop.ROW["workerAction"], self.commit), (value["scenarioId"], value["row"]["workerAction"],
                                                                                            value["desktopTest"]["sourceCommit"]))
        self.assertEqual(sorted(desktop.BUNDLE_FILES), sorted(value["files"]))
        self.assertTrue(data.endswith("/.cache/vpn-control-windows-scenarios/" + MACHINE + "/" + self.operation))

    def test_the_rendered_program_runs_on_a_plain_python3_and_refuses_cleanly_without_a_vm(self):
        source, data = self.rendered()
        host = self.work / "isolated"
        host.mkdir()
        done = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys;exec(compile(sys.stdin.buffer.read(),'job','exec'),{'__name__':'__main__'})"],
                              input=source.encode(), cwd=host, capture_output=True, env={"PATH": os.defpath}, timeout=120)
        self.assertEqual(2, done.returncode, done.stderr.decode("utf-8", "replace"))
        marker = windows._exit_marker(done.stdout, self.operation)
        self.assertTrue(marker["failure"].startswith("host_setup:"))
        self.assertEqual(b"", done.stderr)
        self.assertEqual([], list(host.iterdir()))

    def test_a_carrier_accepts_the_rendered_program(self):
        source, _ = self.rendered()
        program = {"language": "python3", "source": source, "args": [], "cwd": TARGET["home"], "targetContext": TARGET}
        self.assertEqual("python3", carrier.prepare_command(self.operation, program, durable_remote_job.owner_source())[0])


class ResultTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)

    def test_every_suite_class_skip_and_failure_is_counted(self):
        (self.work / "nested").mkdir()
        (self.work / "TEST-com.example.AlphaTest.xml").write_text(XML_ALPHA)
        (self.work / "nested/TEST-com.example.BetaTest.xml").write_text(XML_BETA)
        (self.work / "notes.txt").write_text("ignored")
        value = desktop.parse_results(self.work)
        self.assertEqual({"classes": 2, "tests": 3, "failures": 1, "errors": 0, "skipped": 1, "timeSeconds": 1.75}, value["totals"])
        self.assertEqual(["com.example.AlphaTest", "com.example.BetaTest"], [row["name"] for row in value["classes"]])
        self.assertEqual("nested/TEST-com.example.BetaTest.xml", value["classes"][1]["file"])
        self.assertEqual([{"class": "com.example.AlphaTest", "name": "later"}], value["skippedTests"])

    def test_a_document_type_quoted_in_test_output_is_only_text(self):
        (self.work / "TEST-com.example.HtmlTest.xml").write_text(XML_ALPHA.replace(
            "<system-out><![CDATA[]]>", '<system-out><![CDATA[<!DOCTYPE html><!ENTITY a "b"><html/>]]>'))
        self.assertEqual(2, desktop.parse_results(self.work)["totals"]["tests"])

    def test_entities_and_broken_xml_are_refused(self):
        for text, reason in (('<!DOCTYPE x [<!ENTITY a "b">]><testsuite name="x"/>', "desktop_test_results_xml_declaration"),
                             ("<testsuite", "desktop_test_results_xml_invalid"),
                             ('<testsuite name="x" tests="many"/>', "desktop_test_results_xml_invalid")):
            with self.subTest(reason=reason):
                path = self.work / ("TEST-" + uuid.uuid4().hex + ".xml")
                path.write_text(text)
                with self.assertRaises(desktop.DesktopTestError) as caught:
                    desktop.parse_results(self.work)
                self.assertEqual(reason, caught.exception.reason)
                path.unlink()

    def test_the_console_says_what_kind_of_build_failure_it_was(self):
        self.assertEqual({"build": "successful", "failingTask": None, "offlineResolutionFailure": False, "failingTests": False},
                         desktop.classify_console("> Task :desktopApp:test\nBUILD SUCCESSFUL in 9m\n"))
        failed = desktop.classify_console("There were failing tests. See the report.\n* What went wrong:\nExecution failed for task ':desktopApp:test'.\nBUILD FAILED\n")
        self.assertEqual(("failed", ":desktopApp:test", True), (failed["build"], failed["failingTask"], failed["failingTests"]))
        offline = desktop.classify_console("Could not resolve all files for configuration ':desktopApp:testRuntimeClasspath'.\n"
                                           "   > No cached version of org.example:lib:1.0 available for offline mode.\nBUILD FAILED\n")
        self.assertTrue(offline["offlineResolutionFailure"])
        # The pinned Gradle names the test task for a missing jar and a missing module alike.
        for console in (MISSING_JAR_CONSOLE, MISSING_MODULE_CONSOLE):
            with self.subTest(console=console.splitlines()[-1]):
                self.assertEqual({"build": "failed", "failingTask": ":desktopApp:test", "offlineResolutionFailure": True, "failingTests": False},
                                 desktop.classify_console(console))

    def test_only_a_restore_error_naming_the_seed_marks_a_failure_as_the_tools(self):
        nu1102 = ("C:\\p\\Probe.csproj : error NU1102: Unable to find package Microsoft.NET.ILLink.Tasks with version (>= 10.0.15)\n"
                  "  - Found 1 version(s) in vpnControlDesktopTestOffline [ Nearest version: 10.0.14 ]\n")
        for number, (output, cause) in enumerate(((SEED_MISSING_BUILD, "dotnet-packages"), (nu1102, "dotnet-packages"),
                                                  (SEED_MISSING_BUILD.replace("vpnControlDesktopTestOffline", "nuget.org"), None),
                                                  ("vpnControlDesktopTestOffline\nerror NU1201: incompatible project\n", None),
                                                  ("error CS0246: The type or namespace name could not be found\n", None))):
            with self.subTest(output=output[-60:]):
                (self.work / ("TEST-%d.xml" % number)).write_text(build_failure_xml(output, name="case%d" % number))
                row = next(row for row in desktop.parse_results(self.work)["failedTests"] if row["name"] == "case%d" % number)
                self.assertEqual(cause, row.get("toolCause"))

    def test_the_tool_outcome_and_the_test_outcome_are_apart(self):
        passed = {"totals": {"failures": 0, "errors": 0}}
        failing = {"totals": {"failures": 2, "errors": 0}}
        seed = {"totals": {"failures": 2, "errors": 0}, "failedTests": [{"kind": "failure"}, {"kind": "failure", "toolCause": "dotnet-packages"}]}
        rows = (
            # A probe asked the offline seed for a package it does not hold: the tool's failure; the tests' own outcome stays.
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"failingTests": True}, seed, ("failed", "dotnet-packages", "failed")),
            # A job that failed on its own keeps its stage.
            ({"exitCode": 1, "stage": "cleanup", "failure": "desktop_cleanup_incomplete"}, {"exitCode": 1}, {"failingTests": True}, seed,
             ("failed", "cleanup", "failed")),
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 0}, {}, passed, ("completed", None, "passed")),
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"failingTests": True}, failing, ("completed", None, "failed")),
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"failingTask": ":desktopApp:compileTestKotlin"}, None, ("completed", None, "build-failed")),
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"offlineResolutionFailure": True}, None, ("failed", "gradle-dependencies", "not-run")),
            # Gradle names the test task when it cannot resolve that task's runtime classpath: no test ran.
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"offlineResolutionFailure": True, "failingTask": ":desktopApp:test"}, None,
             ("failed", "gradle-dependencies", "not-run")),
            # Failing tests win over any resolution words a failing test printed.
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"offlineResolutionFailure": True, "failingTask": ":desktopApp:test",
                                                                    "failingTests": True}, failing, ("completed", None, "failed")),
            # A test JVM that ended without "There were failing tests": the source's failure.
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 1}, {"failingTask": ":desktopApp:test"}, None, ("completed", None, "failed")),
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": None, "deadline": True}, {}, None, ("completed", None, "timed-out")),
            ({"exitCode": 0, "stage": "receipt"}, {"exitCode": 0}, {}, None, ("completed", None, "inconsistent")),
            ({"exitCode": 1, "stage": "results", "failure": "desktop_runner:extract-jdk:jdk-version"}, None, None, None,
             ("failed", "runner:extract-jdk", "not-run")),
            ({"exitCode": 1, "stage": "cleanup", "failure": "desktop_cleanup_incomplete"}, {"exitCode": 0}, {}, passed, ("failed", "cleanup", "passed")),
            ({"exitCode": 2, "stage": "anchor", "failure": "prior_fence_open"}, None, None, None, ("refused", "anchor", "not-run")),
            ({"exitCode": 3, "stage": "run", "failure": "task_child_outcome_unknown"}, None, None, None, ("unknown", "run", "not-run")))
        for receipt, gradle, console, results, expected in rows:
            with self.subTest(receipt=receipt, gradle=gradle):
                value = desktop.outcome(receipt, None if gradle is None else {"gradle": gradle}, console, results)
                self.assertEqual(expected, (value["toolOutcome"], value["failedStage"], value["testOutcome"]))
                self.assertEqual(None if expected[0] == "completed" else receipt.get("failure"), value["failure"])


class RouteTests(unittest.TestCase):
    START = {"deploymentId": MACHINE, "operationId": "e314d08a-80eb-4d98-9abe-0c1b245a3807", "sourceCommit": "a" * 40}
    STATUS = {"deploymentId": MACHINE, "operationId": "e314d08a-80eb-4d98-9abe-0c1b245a3807"}

    def setUp(self):
        from agent_tools import mcp_server
        from agent_tools.tests.route_adapter import bind_cached_routes
        self.server = mcp_server
        bind_cached_routes(self, mcp_server, "windows_desktop_test")

    def test_closed_inputs_refuse_before_the_adapter(self):
        cases = [("windows-desktop-test-start", bad) for bad in (
            {**self.START, "sourceCommit": "A" * 40}, {**self.START, "sourceCommit": "a" * 39}, {**self.START, "sourceCommit": "HEAD"},
            {**self.START, "deploymentId": "fixture"}, {**self.START, "operationId": self.START["operationId"].upper()},
            {**self.START, "command": "gradlew"},
            {**self.START, "javaHome": "C:\\jdk"}, self.STATUS, {**self.START, "sourceCommit": 1}, {})]
        cases += [("windows-desktop-test-status", bad) for bad in (self.START, {**self.STATUS, "path": "/x"}, {"operationId": MACHINE})]
        for action, bad in cases:
            with self.subTest(action=action, bad=bad), mock.patch.object(desktop, "start", side_effect=AssertionError("refused first")), \
                    mock.patch.object(desktop, "status", side_effect=AssertionError("refused first")), \
                    mock.patch.object(self.server, "_agent_module", side_effect=AssertionError("no adapter or admission load")):
                result = self.server.vm_workflow(action, bad)
                self.assertFalse(result["ok"])

    def test_the_route_passes_exactly_the_inputs_with_the_mcp_route(self):
        answer = {"state": "submitted", "reason": "submitted", "operationId": self.START["operationId"], "replayAllowed": False, "productAction": False}
        with mock.patch.object(desktop, "start", return_value=answer) as called:
            result = self.server.vm_workflow("windows-desktop-test-start", dict(self.START))
        called.assert_called_once_with(self.server.REPO_ROOT, self.START, route="mcp")
        self.assertEqual((True, False, "in-guest-desktop-test"), (result["ok"], result["nativeActionAllowed"], result["evidenceClass"]))
        for view, ok in (({"state": "submitted", "reason": "desktop_test_running:gradle:60s"}, True),
                         ({"state": "terminal", "toolOutcome": "completed", "testOutcome": "failed"}, True),
                         ({"state": "terminal", "toolOutcome": "failed", "failedStage": "cleanup"}, False),
                         ({"state": "unknown", "toolOutcome": "unknown"}, False)):
            with self.subTest(view=view), mock.patch.object(desktop, "status", return_value=view) as called:
                self.assertEqual(ok, self.server.vm_workflow("windows-desktop-test-status", dict(self.STATUS))["ok"])
                called.assert_called_once_with(self.server.REPO_ROOT, self.STATUS)

    def test_a_refusal_keeps_its_word_and_any_other_failure_is_finite(self):
        with mock.patch.object(desktop, "start", side_effect=desktop.DesktopTestError("desktop_test_operation_exists")):
            result = self.server.vm_workflow("windows-desktop-test-start", dict(self.START))
        self.assertEqual((False, "refused", "desktop_test_operation_exists", False), (result["ok"], result["state"], result["reason"], result["replayAllowed"]))
        secret = "C:\\Users\\private-account\\secret"
        with mock.patch.object(desktop, "status", side_effect=OSError(secret)):
            result = self.server.vm_workflow("windows-desktop-test-status", dict(self.STATUS))
        self.assertEqual(("unknown", "desktop_test_unavailable"), (result["state"], result["reason"]))
        self.assertNotIn("private-account", json.dumps(result))

    def test_the_catalog_rows(self):
        from agent_tools import readiness_vm_dispatch as dispatch, tool_action_policy as policy
        for action, classification in (("windows-desktop-test-start", "original_operation"), ("windows-desktop-test-status", "remote_observation")):
            with self.subTest(action=action):
                row = policy.action_policy("vm_workflow", action)
                self.assertEqual((frozenset({"transport"}), frozenset({"reconnect"}), classification),
                                 (row.requirements, row.permitted_recoveries, row.classification))
                route = dispatch.ROUTES[action]
                self.assertEqual(("windows_deployment", ("windows_desktop_test",)), (route["kind"], tuple(route["modules"])))
                for module in ("windows_desktop_test", "windows_desktop_test_host_job", "windows_desktop_test_guest", "windows_scenario_host_job",
                               "windows_ordinary_task", "windows_ordinary_process_owner", "windows_artifact_transfer", "readiness_windows_guest",
                               "native_scenario_windows", "native_scenario_execution", "readiness_windows_registration", "readiness_windows_remote",
                               "windows_vm_deploy_remote", "durable_remote_job", "ssh_program_execution_remote"):
                    self.assertIn("agent_tools/" + module + ".py", route["closure"])
        self.assertTrue(dispatch.audit_sources()["ok"])

    @unittest.skipUnless(os.name == "posix", "private intents are POSIX")
    def test_the_dispatch_resolves_only_the_original_intents_host(self):
        from agent_tools import readiness_vm_dispatch as dispatch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaises(dispatch.DispatchBlocked) as caught:
                dispatch.resolve(root, "windows-desktop-test-start", dict(self.START))
            self.assertEqual("vm_readiness_original_metadata_unavailable", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
