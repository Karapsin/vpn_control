"""Causal pairs for three defects the public-update family met before reaching a guest.

Each pair runs one oracle on the preserved unfixed bytes and on the current module: the
unfixed bytes must fail it, the current module must pass it. The CLI stand-in models only
the two product rules these defects broke, as the desktop sources state them:
DesktopAppService.kt:410 answers READ_ONLY_SOURCE to locations add unless the workspace
reads current locations (a fresh one reads subscriptions, Models.kt:285), and
DesktopCli.kt:173-175 answers UNSUPPORTED to --if-revision on any command outside
DesktopControlSupport.revisionGuardOperations, which does not list on. Nothing here runs
Windows, a CLI or a guest.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from agent_tools.tests import product_link_schemes
from agent_tools.windows_public_updater import update_receipts

ROOT = Path(__file__).resolve().parents[2]
# The guest runs Windows PowerShell 5.1, so its parser and engine go first where they exist.
POWERSHELL = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh")
FIXTURES = ROOT / "agent_tools/tests/fixtures/windows_public_update_defects"
PROVENANCE = json.loads((FIXTURES / "provenance.json").read_bytes())
SID = "S-1-5-21-1-2-3-1000"
ADMIN = "S-1-5-21-1-2-3-500"
LOCAL = "C:\\Users\\recovery\\AppData\\Local"
INSTALLED = LOCAL + "\\vpn-control"
CLI = INSTALLED + "\\vpn-control-cli.exe"
OPERATION = "33333333-4444-4555-8666-777777777777"
WORKSPACE = "C:\\ProgramData\\VpnControlOrdinaryTask-" + OPERATION
PROFILE = WORKSPACE + "\\update-profile.txt"
UPSTREAM = WORKSPACE + "\\socks_http_fixture.py"
SAMPLER = WORKSPACE + "\\windows_lifecycle_traffic_worker.py"
SAMPLER_INPUT = WORKSPACE + "\\update-traffic-input.json"
PYTHON = "C:\\Users\\recovery\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
# DesktopControlSupport.revisionGuardOperations, as agent_docs/cli.md lists them: routing set is one.
GUARDED = {("settings", "set"), ("settings", "apply"), ("source", "set"), ("locations", "add"), ("locations", "select"),
           ("locations", "update"), ("locations", "delete"), ("routing", "set"), ("quit",), ("updates", "install")}


def fixture(name):
    raw = (FIXTURES / name).read_bytes()
    row = PROVENANCE["files"][name]
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (row["bytes"], row["sha256"]):
        raise ValueError("fixture-bytes-changed:" + name)
    return raw


def module_from(raw, name, path):
    value = types.ModuleType(name)
    value.__file__ = str(path)
    exec(compile(raw, str(path), "exec", dont_inherit=True), value.__dict__)
    return value


def run_pair(case, oracle, before, current, message):
    """The unfixed bytes fail the oracle with the expected words; the current module passes it."""
    observations = {}
    for phase, module in (("before", before), ("current", current)):
        result = unittest.TestResult()
        oracle(module).run(result)
        observations[phase] = (result.testsRun, [text for _, text in result.failures], [text for _, text in result.errors])
    runs, failures, errors = observations["before"]
    case.assertEqual((1, 1, []), (runs, len(failures), errors), "the unfixed bytes must fail the oracle, not error")
    case.assertIn(message, failures[0])
    case.assertEqual((1, [], []), observations["current"], "the current module must pass the same oracle")


# The planner's tree roles.
def _directory(path):
    return {"path": path, "nativeIdentity": {"volumeSerial": 7, "fileIndex": int(hashlib.sha256(path.encode()).hexdigest()[:6], 16), "attributes": 16},
            "security": {"ownerSid": "S-1-5-18", "sddl": "O:SYD:P(A;;FA;;;SY)"}}


def _file(path, raw):
    return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(),
            "nativeIdentity": {"volumeSerial": 7, "fileIndex": int(hashlib.sha256(path.encode()).hexdigest()[:6], 16), "attributes": 32, "sizeBytes": len(raw),
                               "links": 1, "creationFileTime": "1", "lastWriteFileTime": "1"},
            "security": {"ownerSid": SID, "sddl": "O:SYD:P(A;;FA;;;SY)"}}


def tree_request(planner, role):
    root = LOCAL + "\\VpnControlOrdinary-" + OPERATION
    context = {"deploymentId": OPERATION, "ordinarySid": SID, "ordinarySessionId": 2, "profileRoot": "C:\\Users\\recovery",
               "localAppData": LOCAL, "machineGuid": "44444444-5555-4666-8777-888888888888",
               "bootIdentifier": "55555555-6666-4777-8888-999999999999", "bootFileTimeUtc": "134368653065000000"}
    directories = [_directory(path) for path in ("C:\\", "C:\\Users", "C:\\Users\\recovery", "C:\\Users\\recovery\\AppData", LOCAL, root, INSTALLED)]
    files = [_file(INSTALLED + "\\" + name, name.encode()) for name in ("vpn-control.exe", "vpn-control-cli.exe")]
    tree = {"role": role, "root": INSTALLED, "files": ["vpn-control-cli.exe", "vpn-control.exe"]}
    return planner.common_request(context, OPERATION, root, files, directories, [tree])


def tree_role_oracle(planner):
    """update_receipts.InstalledApplicationLease reads exactly one installed-application tree."""
    class Oracle(unittest.TestCase):
        def runTest(self):
            try:
                request = tree_request(planner, "installed-application")
            except ValueError as error:
                self.fail("planner refused the updater's tree role: " + str(error))
            self.assertEqual(["installed-application"], [tree["role"] for tree in request["treePins"]])
    return Oracle()


# The update case module's reconnect branch.
class Stop(Exception):
    """The traffic step: past every public call these defects broke."""


class Cli:
    def __init__(self, source):
        self.source, self.revision, self.running, self.calls, self.last = source, 4, False, [], None

    def envelope(self, code, controller, data=None):
        exit_code = 0 if code in {"OK", "ACCEPTED"} else 130 if code == "CANCELLED" else 2 if code == "UNAVAILABLE" else 1
        body = {"schemaVersion": 1, "ok": exit_code == 0, "code": code, "final": True, "controllerId": controller,
                "configurationRevision": self.revision, "data": data or {}}
        self.last = (self.calls[-1][0][:2], code)
        return subprocess.CompletedProcess([CLI], exit_code, json.dumps(body), "")

    def __call__(self, workspace, *arguments):
        words = list(arguments)
        assert words.pop(0) == "--json"
        controller = revision = None
        while words and words[0].startswith("--"):
            flag = words.pop(0)
            if flag == "--controller-id":
                controller = words.pop(0)
            elif flag == "--if-revision":
                revision = words.pop(0)
        self.calls.append((tuple(words), revision))
        if revision is not None and tuple(words[:2]) not in GUARDED and tuple(words[:1]) not in GUARDED:
            return self.envelope("UNSUPPORTED", None)
        identity = "controller-1"
        if words == ["status"]:
            return self.envelope("OK", identity, {"runtimeRunning": self.running})
        if words[:2] == ["source", "set"]:
            self.source = words[2]
        elif words[:2] == ["locations", "add"] and self.source != "current-locations":
            return self.envelope("READ_ONLY_SOURCE", identity)
        elif words == ["on"]:
            self.running = True
        self.revision += 1
        return self.envelope("OK", identity, {"id": "location-1"} if words[:2] == ["locations", "add"] else None)


class Pin:
    def __init__(self, path, raw=b""):
        self.path, self.raw, self.directory = PureWindowsPath(path), raw, False
        self.record = {"path": path, "sha256": hashlib.sha256(raw).hexdigest()}

    def digest(self, return_bytes=False, maximum=None):
        return self.raw if return_bytes else self.record["sha256"]


class Child:
    def __init__(self, label):
        self.label, self.ordinal, self.pid, self.birth = label, 0, 4100, "134368653065000001"
        self.process = types.SimpleNamespace(poll=lambda: None)


class Fixture:
    def __init__(self, owner, prepared, inputs, mode):
        owner.update_fixture = self
        self.closed = False
        self.ready = {"sourceFingerprint": "f" * 64}
        self.manifest = {"assets": [{"displayVersion": "2.2.16", "sizeBytes": 10}]}

    def owner_jvm_environment(self):
        return {}


def stop_at_traffic(*_arguments):
    raise Stop()


class Owner:
    MODULES = {"receipts": "update_receipts.py", "server": "update_fixture_server.py", "fixture_environment": "fixture_environment.py",
               "macos_packaging_jdk_preflight": "macos_packaging_jdk_preflight.py", "prepare_desktop_update_fixture": "prepare_desktop_update_fixture.py",
               "broker_observer": "windows_broker_fixture_observer.py", "lifecycle": "windows_lifecycle_cases.py", "collector": "native_collector.py"}

    def __init__(self, root, cli, cases=None):
        self.root, self.cli, self.environment, self.events, self.native = root, cli, {}, [], None
        self.request = {"workspace": str(root / "workspace"), "cliPath": CLI, "productVersion": "2.2.15",
                        "casesPath": WORKSPACE + "\\update_cases.py", "harnessPath": WORKSPACE + "\\update-harness.py",
                        "context": {"ordinarySid": SID, "ordinarySessionId": 2}, "pythonRuntime": {"interpreterPath": PYTHON}}
        self.paths = {key: WORKSPACE + "\\" + name for key, name in self.MODULES.items()}
        # Each module gets what its own host job wrote: before the connected row was tooled, a socks5:// profile and no
        # upstream; since, the socks:// profile of the case's own upstream, which it starts on that port.
        self.connected = hasattr(cases, "UPSTREAM_FIELDS")
        pins = [Pin(path, path.encode()) for path in (*self.paths.values(), UPSTREAM, SAMPLER, SAMPLER_INPUT)]
        pins.append(Pin(PROFILE, b"socks://127.0.0.1:41082#Update%20fixture\n" if self.connected
                        else b"socks5://127.0.0.1:1080#Update%20fixture\n"))
        self.by_path = {str(pin.path).casefold(): pin for pin in pins}
        self.pins = [Pin(WORKSPACE + "\\worker-request.json")]
        receipts = types.SimpleNamespace(within=lambda path, root: True, installed_registration=lambda expected, native: dict(expected),
                                         InstalledApplicationLease=lambda *arguments: types.SimpleNamespace(files=[]),
                                         preserve=lambda *arguments: None, canonical_uuid=lambda value: value)
        self.loaded = {self.paths["receipts"]: receipts, self.paths["server"]: types.SimpleNamespace(UpdateFixture=Fixture),
                       self.paths["lifecycle"]: types.SimpleNamespace(prepare_update_traffic=stop_at_traffic)}

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append(kind)

    def module(self, path, name):
        return self.loaded.get(path, types.SimpleNamespace())

    def child(self, label, argv):
        if label == "update-upstream":  # The upstream listens on its port and says so in its ready file.
            Path(argv[argv.index("--ready-file") + 1]).write_text(argv[argv.index("--port") + 1], encoding="utf-8")
        return Child(label)

    def invoke(self, workspace, *arguments):
        return self.cli(workspace, *arguments)

    def inputs(self):
        if self.connected:
            return {**self._inputs(), "upstreamFixture": {"schemaVersion": 1, "sourcePath": UPSTREAM, "port": 41082,
                                                          "token": "vpn-control-update-upstream"},
                    "trafficInputs": {"schemaVersion": 1, "trafficWorkerPath": SAMPLER, "trafficInputPath": SAMPLER_INPUT,
                                      "fixtureAdmissionArtifactId": "update-upstream-" + "5" * 64, "sourceArtifactId": "sha256-" + "6" * 64}}
        return self._inputs()

    def _inputs(self):
        inventory = {"vpn-control-cli.exe": {"sizeBytes": 3, "sha256": "a" * 64}}
        registration = {"productCode": "{33333333-4444-4555-8666-777777777777}", "principalSid": SID, "installContext": 2,
                        "displayVersion": "2.2.15", "installLocation": INSTALLED, "packageCode": "{44444444-5555-4666-8777-888888888888}"}
        fixture_root = WORKSPACE + "\\mcp-update-fixture-" + OPERATION
        return {"schemaVersion": 1, "variant": "success-reconnect", "sourceSha": "a" * 40, "sourceFingerprint": "f" * 64,
                "modules": dict(self.paths), "fixture": {"fixtureId": OPERATION, "content": fixture_root + "\\content",
                                                         "state": fixture_root + "\\server-state", "certificate": WORKSPACE + "\\c.pem",
                                                         "privateKey": WORKSPACE + "\\k.pem", "trustStore": WORKSPACE + "\\t.p12",
                                                         "certificateSha256": "c" * 64},
                "baseVersion": "2.2.15", "targetVersion": "2.2.16", "installedRoot": INSTALLED, "guiPath": INSTALLED + "\\vpn-control.exe",
                "baseInventory": inventory, "targetInventory": inventory, "baseRegistration": registration,
                "targetRegistration": dict(registration, displayVersion="2.2.16"), "programData": "C:\\ProgramData",
                "evidenceRoot": "C:\\ProgramData\\update-evidence-" + OPERATION,
                "collectorSourceSha256": self.by_path[self.paths["collector"].casefold()].record["sha256"],
                "ordinarySid": SID, "ordinarySessionId": 2, "approvingAdminSid": ADMIN, "initialIntent": "reconnect",
                "trafficInputs": {}, "faultInputs": {}, "returnGuiRequired": False, "connectionFixturePath": PROFILE}


def reconnect_oracle(cases, source):
    """success-reconnect connects a loopback location through public guarded writes, then turns the runtime on."""
    class Oracle(unittest.TestCase):
        def runTest(self):
            with tempfile.TemporaryDirectory() as directory:
                cli = Cli(source)
                owner = Owner(Path(directory), cli, cases)
                try:
                    with self.assertRaises(Stop):
                        cases._run_update(owner, {"UPDATE_INPUTS": owner.inputs()})
                except AssertionError as error:
                    self.fail(str(error) + " after " + " ".join(cli.last[0]) + " answered " + cli.last[1])
                self.assertTrue(cli.running)
                self.assertIn((("on",), None), cli.calls)
    return Oracle()


class DefectPairs(unittest.TestCase):
    def test_the_updater_tree_role_is_one_the_planner_admits(self):
        from agent_tools import windows_ordinary_task as current
        before = module_from(fixture("windows-ordinary-task.before.source"), "_before_windows_ordinary_task",
                             ROOT / "agent_tools/windows_ordinary_task.py")
        run_pair(self, tree_role_oracle, before, current, "tree-role-schema")
        self.assertEqual(["installed-app"], [tree["role"] for tree in tree_request(current, "installed-app")["treePins"]],
                         "the read-only CLI rows keep their role")

    def test_a_fresh_workspace_takes_current_locations_before_its_first_location(self):
        from agent_tools.windows_public_updater import update_cases as current
        before = module_from(fixture("update-cases.before.source"), "_before_update_cases",
                             ROOT / "agent_tools/windows_public_updater/update_cases.py")
        run_pair(self, lambda module: reconnect_oracle(module, "subscription"), before, current,
                 "public-envelope-result after locations add answered READ_ONLY_SOURCE")

    def test_on_carries_no_revision_guard(self):
        from agent_tools.windows_public_updater import update_cases as current
        before = module_from(fixture("update-cases.before.source"), "_before_update_cases_guard",
                             ROOT / "agent_tools/windows_public_updater/update_cases.py")
        # The workspace already reads current locations, so only the guard on on can fail.
        run_pair(self, lambda module: reconnect_oracle(module, "current-locations"), before, current,
                 "public-envelope-result after on answered UNSUPPORTED")


# The update variants admitted together: install-cancelled, success-reconnect, its explicit-off twin success-explicit-off
# and participating-copy-lock, run through update_cases._run_update over a declared world. The public CLI answers as the desktop sources state: guarded
# writes (DesktopControlSupport.revisionGuardOperations), only the link prefixes ProxyLinkParser.kt dispatches
# (product_link_schemes), a returned owner that restores its remembered intent itself (DESKTOP-004), possibly after it first
# answers, and the coordinator's own terminals (VpnInstallHelperRoles.RunCoordinator). The SYSTEM collector's records are
# files the world publishes per stage; a stage it was not told to publish stops the case at once (Unserved).
JOB = "44444444-5555-4666-8777-999999999999"
INSTALL = "55555555-6666-4777-8888-aaaaaaaaaaaa"
REQUEST = "66666666-7777-4888-8999-bbbbbbbbbbbb"
DOWNLOAD = "77777777-8888-4999-8aaa-cccccccccccc"
BOOT = "88888888-9999-4aaa-8bbb-dddddddddddd"
GUI = INSTALLED + "\\vpn-control.exe"
ASSET = b"msi-bytes"
HELPER_RELATIVE = "app/native/windows-amd64/vpn-control-install-helper.exe"
HELPER_SHA = "7" * 64
CLI_SHA = "c" * 64
COPY_LEAF = "copy-lock-workspace"
COORDINATOR = {"pid": 921, "creationFileTime": 134368653065000020}
WORKER = {"pid": 922, "creationFileTime": 134368653065000021}


class Unserved(BaseException):
    """A native record the world was not told to publish: the case would wait on it for ever."""


class WorldParked(BaseException):
    pass


class WorldChild:
    def __init__(self, world, label, argv):
        self.world, self.label, self.argv, self.ordinal = world, label, tuple(argv), len(world.owner.children)
        self.pid, self.birth = 5000 + self.ordinal, str(134368653065000100 + self.ordinal)
        self.terminal, self.terminated = None, False
        self.process = types.SimpleNamespace(poll=lambda: None if self.terminal is None else self.terminal["exitCode"],
                                             terminate=self.terminate, _handle=self.ordinal + 1)

    def terminate(self):
        self.terminated = True
        self.terminal = {"exitCode": 1, "eof": {"stdout": True, "stderr": True}}

    def observe(self):
        return self.terminal

    def wait(self):
        if self.terminal is None:
            self.terminal = {"exitCode": 0, "eof": {"stdout": True, "stderr": True}}
            self.world.ended(self)
        return self.terminal

    def completed(self):
        result = self.world.completed(self)
        self.wait()
        return result


class WorldProduct:
    """The public CLI of the base owner, then of the owner the update returns (or the case's own recovery serve)."""

    def __init__(self, world, *, returned_off_polls=0, cancel_code="CANCELLED"):
        self.world, self.controller, self.revision = world, "controller-1", 4
        self.source, self.locations, self.selected, self.mode = "subscription", {}, None, "vpn"
        self.running, self.intent, self.runtime, self.returned = False, False, 0, False
        self.returned_off_polls, self.cancel_code = returned_off_polls, cancel_code
        self.installations, self.calls = [], []

    def envelope(self, code="OK", *, final=True, controller=None, operation=None, data=None):
        exit_code = 0 if code in {"OK", "ACCEPTED"} else 130 if code == "CANCELLED" else 2 if code in {
            "UNAVAILABLE", "TIMEOUT", "OUTCOME_UNKNOWN"} else 1
        body = {"schemaVersion": 1, "ok": exit_code == 0, "code": code, "final": final, "controllerId": controller or self.controller,
                "configurationRevision": self.revision, "requestId": REQUEST, "data": data or {}}
        if operation is not None:
            body["operationId"] = operation
        return subprocess.CompletedProcess([CLI], exit_code, json.dumps(body), "")

    def status(self):
        running = self.running
        if self.returned and running and self.returned_off_polls > 0:
            self.returned_off_polls -= 1  # The returned owner answers before its resumed runtime runs.
            running = False
        return {"runtimeRunning": running, "selectedLocationId": self.selected, "activeLocationId": self.selected if running else None,
                "activeMode": self.mode if running else None, "configuredMode": self.mode, "pendingRestart": False,
                "runtimeId": "runtime-%d" % self.runtime if running else None, "runtimeStartedAt": 1000 * self.runtime if running else None}

    def answer(self, workspace, arguments):
        words, guard, timeout = list(arguments), None, None
        assert words.pop(0) == "--json"
        while words and words[0].startswith("--"):
            flag = words.pop(0)
            if flag == "--controller-id":
                words.pop(0)
            elif flag == "--if-revision":
                guard = words.pop(0)
            elif flag == "--timeout-seconds":
                timeout = int(words.pop(0))
            elif flag != "--async":
                raise AssertionError("unexpected flag " + flag)
        self.calls.append((tuple(words), guard, timeout))
        if str(workspace).endswith(COPY_LEAF):  # The participating copy: its own disconnected owner.
            return self.envelope(controller="copy-controller", data={"runtimeRunning": False} if words == ["status"] else {})
        if guard is not None and tuple(words[:2]) not in GUARDED and tuple(words[:1]) not in GUARDED:
            return self.envelope("UNSUPPORTED")
        if words == ["status"]:
            return self.envelope(data=self.status())
        if words[:3] == ["locations", "add", "--input"]:
            link = self.world.owner.by_path[words[3].casefold()].raw.decode("utf-8")
            if not product_link_schemes.dispatched(link):
                return self.envelope("INVALID_ARGUMENT")
            if self.source != "current-locations":
                return self.envelope("READ_ONLY_SOURCE")
            self.locations["location-1"], self.revision = link, self.revision + 1
            return self.envelope(data={"id": "location-1"})
        if words in (["settings", "set", "mode", "proxy-only"], ["source", "set", "current-locations"], ["locations", "select", "location-1"],
                     ["routing", "set", "ignore-rules", "true"]):
            self.mode = "proxy-only" if words[0] == "settings" else self.mode
            self.source = "current-locations" if words[0] == "source" else self.source
            self.selected = "location-1" if words[0] == "locations" else self.selected
            self.revision += 1
            return self.envelope()
        if words == ["on"]:
            self.running, self.intent, self.runtime = True, True, self.runtime + 1
            return self.envelope()
        if words == ["off"]:
            self.running, self.intent = False, False
            return self.envelope()
        if words == ["quit"] or words[:2] in (["updates", "transport-probe"], ["updates", "check"]):
            return self.envelope()
        if words == ["updates", "status"]:
            return self.envelope(data={"available": True, "compatible": True, "availableVersion": "2.2.16", "totalBytes": len(ASSET),
                                       "phase": "ready", "downloadedBytes": len(ASSET), "installations": self.installations})
        if words == ["updates", "download"]:
            return self.envelope("ACCEPTED", final=False, operation=DOWNLOAD)
        if words == ["operations", "wait", DOWNLOAD]:
            return self.envelope(operation=DOWNLOAD)
        if words == ["operations", "cancel", INSTALL]:
            return self.envelope(final=None)
        if words == ["operations", "wait", INSTALL]:
            if self.cancel_code == "CANCELLED":
                self.installations = [{"originControllerId": "controller-1", "operationId": INSTALL, "final": True, "installed": False, "jobId": JOB}]
                return self.envelope("CANCELLED", operation=INSTALL)
            return self.envelope(self.cancel_code, final=False, operation=INSTALL)
        if words == ["operations", "status", INSTALL]:
            terminal = self.world.terminal
            return self.envelope(terminal["code"], operation=INSTALL, data={"jobId": JOB, "originControllerId": "controller-1",
                                                                            "originRequestId": REQUEST})
        raise AssertionError("unexpected public command: " + repr(words))


class WorldObservation:
    """receipts.FileObservation over the world: published native records, the protected diagnostic, the downloaded MSI."""

    def __init__(self, owner, path, directory=False, replaceable=False):
        self.world, self.path, self.handle = owner.world, str(path), 1
        self.opening = {"path": self.path, "nativeIdentity": {"sizeBytes": 0}, "security": {"ownerSid": "S-1-5-18", "sddl": "O:SYD:P"}}
        self.raw = None if directory else self.world.read(self.path)

    def read(self, maximum):
        return self.raw

    def describe(self):
        return self.opening

    def _canonical(self):
        pass

    def close(self):
        pass


class WorldLease:
    def __init__(self, owner, root, base, target):
        self.files = [types.SimpleNamespace(digest=lambda: None)]
        self.retired = self.admitted = False
        self.phase = None
        owner.update_application_lease = self

    def retire_after_committed_handoff(self, accepted, identity):
        self.retired = True

    def admit_observed_target(self, terminal, *, expected_phase="SUCCEEDED"):
        self.admitted, self.phase = True, expected_phase


class WorldCollector:
    def __init__(self, owner, program_data, job):
        self.world = owner.world

    def observe(self):
        return {"version": 1, "jobId": JOB, "sequence": 3, "phase": "WAITING_FOR_EXIT", "code": "OK"}

    def terminal(self):
        return self.world.terminal

    def close_terminal(self):
        pass


class WorldOwner:
    MODULES = {"receipts": "update_receipts.py", "server": "update_fixture_server.py", "fixture_environment": "fixture_environment.py",
               "macos_packaging_jdk_preflight": "macos_packaging_jdk_preflight.py", "prepare_desktop_update_fixture": "prepare_desktop_update_fixture.py",
               "broker_observer": "windows_broker_fixture_observer.py", "lifecycle": "windows_lifecycle_cases.py", "collector": "native_collector.py"}

    def __init__(self, world, root):
        self.world, self.root, self.operation = world, root, OPERATION
        self.children, self.events, self.environment, self.parked = [], [], {}, None
        self.request = {"workspace": str(root / "workspace"), "cliPath": CLI, "productVersion": "2.2.15",
                        "casesPath": WORKSPACE + "\\windows_public_updater\\update_cases.py", "harnessPath": WORKSPACE + "\\update-harness.py",
                        "context": {"ordinarySid": SID, "ordinarySessionId": 2, "bootIdentifier": BOOT}, "pythonRuntime": {"interpreterPath": PYTHON}}
        self.paths = {key: WORKSPACE + "\\" + name for key, name in self.MODULES.items()}
        pins = [Pin(path, path.encode()) for path in (*self.paths.values(), UPSTREAM, SAMPLER, SAMPLER_INPUT, GUI)]
        pins += [Pin(PROFILE, b"socks://127.0.0.1:41082#Update%20fixture\n"), types.SimpleNamespace(path=PureWindowsPath(CLI), directory=False,
                 record={"path": CLI, "sha256": CLI_SHA}, raw=b"cli", digest=lambda *_: CLI_SHA)]
        self.by_path = {str(pin.path).casefold(): pin for pin in pins}
        self.pins = [Pin(WORKSPACE + "\\worker-request.json")]
        self.native = types.SimpleNamespace(read_blocks=lambda handle: [ASSET])

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append((kind, value))

    def park(self, reason, error=None):
        self.parked = (reason, error)
        raise WorldParked(reason + ": " + str(error))

    def module(self, path, name):
        return self.world.modules[path]

    def child(self, label, argv):
        child = WorldChild(self.world, label, argv)
        self.children.append(child)
        self.world.started(child)
        return child

    def invoke(self, workspace, *arguments, timeout=30, stdin=None):
        return self.world.product.answer(workspace, arguments)


class World:
    """One update case's guest. evidence names the observations each SYSTEM stage publishes."""

    def __init__(self, root, cases, variant, *, terminal=None, diagnostic=None, **product):
        self.root, self.cases, self.variant = root, cases, variant
        self.owner = WorldOwner(self, root)
        self.product = WorldProduct(self, **product)
        self.terminal = terminal or {"version": 1, "jobId": JOB, "sequence": 6, "phase": "SUCCEEDED", "code": "OK"}
        self.diagnostic = diagnostic
        self.traffic, self.closed = [], False
        receipts = types.SimpleNamespace(
            canonical_uuid=update_receipts.canonical_uuid, canonical_path=update_receipts.canonical_path, within=update_receipts.within,
            encoded=update_receipts.encoded, handoff=update_receipts.handoff, verify_recovery=update_receipts.verify_recovery,
            preserve=lambda owner, name, value: {"name": name, "sizeBytes": 1, "sha256": "0" * 64},
            FileObservation=WorldObservation, machine_security=lambda security, directory: None, InstalledApplicationLease=WorldLease,
            installed_registration=lambda expected, native: dict(expected), ProtectedReceiptCollector=WorldCollector,
            endpoint_actor=lambda owner, workspace, name, controller, observer: {"actor": {
                "pid": 7001, "creationFileTime": 134368653065000040, "image": GUI, "sha256": "e" * 64, "sid": SID, "sessionId": 2}})
        fixture = types.SimpleNamespace(ready={"sourceFingerprint": "f" * 64}, owner_jvm_environment=dict, closed=False,
                                        manifest={"assets": [{"displayVersion": "2.2.16", "sizeBytes": len(ASSET),
                                                              "sha256": hashlib.sha256(ASSET).hexdigest(), "fileName": "vpn-control-2.2.16.msi"}]})

        def close_known(*, all_update_operations_terminal, cancelled_download=False):
            fixture.closed = self.closed = True
        fixture.close_known = close_known

        def traffic(label):
            def probe(owner, workspace, identity, inputs):
                live = [child for child in owner.children if child.label == "update-upstream" and child.terminal is None]
                if not (self.product.running and live and identity == self.product.controller):
                    raise AssertionError("update-traffic-" + label + ": no runtime or no upstream behind the location")
                self.traffic.append((label, identity))
                return {"child": label, "identity": identity}
            return probe
        paths = self.owner.paths
        self.modules = {
            paths["receipts"]: receipts, paths["server"]: types.SimpleNamespace(UpdateFixture=lambda *_: fixture),
            paths["fixture_environment"]: types.SimpleNamespace(), paths["macos_packaging_jdk_preflight"]: types.SimpleNamespace(),
            paths["prepare_desktop_update_fixture"]: types.SimpleNamespace(
                require_install_ready=lambda *_: None,
                desktop_install_arguments=lambda ready, version, *, asynchronous=False: [
                    "--json", "--controller-id", "controller-1", "--if-revision", "4", *(["--async"] if asynchronous else []), "updates", "install"]),
            paths["broker_observer"]: types.SimpleNamespace(),
            paths["lifecycle"]: types.SimpleNamespace(prepare_update_traffic=traffic("before"), verify_update_traffic=traffic("after"),
                                                      cleanup_update_traffic=lambda owner, *observations: self.traffic.append(("cleanup", observations)))}
        self.evidence = {"before-install": self.before_install, "authorization": self.authorization, "terminal-actors": self.terminal_actors,
                         "returned-cleanup": self.returned_cleanup, "fault-ready": self.fault_ready, "cancel-actors": self.cancel_actors}

    # The SYSTEM collector's records.
    def child_labelled(self, label):
        return next(child for child in self.owner.children if child.label == label)

    def before_install(self):
        serve = self.child_labelled("update-public-serve")
        return {"ordinaryOwner": {"token": {"sid": SID, "elevated": 0, "sessionId": 2}, "pid": serve.pid, "creationFileTime": int(serve.birth),
                                  "image": CLI, "sha256": CLI_SHA}}

    def fault_ready(self):
        copy = self.child_labelled("participating-installed-copy")
        inputs = self.harness["UPDATE_INPUTS"]
        return {"kind": "participating-copy-lock", "binding": inputs["faultInputs"],
                "participatingCopy": {"pid": copy.pid, "creationFileTime": int(copy.birth), "image": CLI, "sha256": CLI_SHA,
                                      "token": {"sid": SID, "elevated": 0, "sessionId": 2}}}

    def actors(self):
        return {"coordinator": {**COORDINATOR, "image": INSTALLED + "\\" + HELPER_RELATIVE.replace("/", "\\"), "sha256": HELPER_SHA, "sid": ADMIN,
                                "sessionId": 2},
                "worker": {**WORKER, "image": INSTALLED + "\\" + HELPER_RELATIVE.replace("/", "\\"), "sha256": HELPER_SHA, "sid": SID, "sessionId": 2}}

    def authorization(self):
        return {"coordinator": {"token": {"sid": ADMIN, "elevated": 1}}, "originalUserWorker": {"token": {"sid": SID, "elevated": 0, "sessionId": 2}},
                "actorExpectations": self.actors()}

    def terminal_actors(self):
        return {"protectedReceipt": self.terminal, "actorExpectations": self.actors(),
                "actorExitObservations": [{"originalAbsent": True}, {"originalAbsent": True}]}

    def cancel_actors(self):
        def row(role, identity, sid, elevated):
            return {"role": role, **identity, "jobId": JOB, "sha256": HELPER_SHA, "sid": sid, "elevated": elevated, "sessionId": 2,
                    "originalAbsent": True}
        return {"armedBeforeActors": True, "complete": True, "timedOut": False, "jobId": JOB, "others": [],
                "actors": [row("coordinator", COORDINATOR, ADMIN, 1), row("worker", WORKER, SID, 0)]}

    def returned_cleanup(self):
        expected = [value for kind, value in self.owner.events if kind == "update-returned-cleanup-expected-actors"]
        return {"actorExpectations": expected[-1]["actors"], "ownerOriginalAbsent": True, "guiOriginalAbsent": False}

    def read(self, path):
        if path.startswith("C:\\ProgramData\\update-evidence-" + OPERATION + "\\"):
            stage = path.rsplit("\\", 1)[-1][:-len(".json")]
            observations = self.evidence.get(stage)
            if observations is None:
                raise Unserved(stage)
            job, operation = {"before-install": (None, None), "fault-ready": (None, None), "cancel-actors": (JOB, None)}.get(stage, (JOB, INSTALL))
            inputs = self.harness["UPDATE_INPUTS"]
            return json.dumps({"schemaVersion": 1, "ordinaryTaskOperationId": OPERATION, "stage": stage, "sourceSha": inputs["sourceSha"],
                               "collectorSourceSha256": inputs["collectorSourceSha256"], "bootIdentifier": BOOT, "jobId": job,
                               "productOperationId": operation, "observations": observations()}).encode()
        if path == "C:\\ProgramData\\vpn-control-install-jobs\\" + JOB + "\\preinstall-diagnostic.json" and self.diagnostic is not None:
            return self.diagnostic
        if path.endswith("\\updates\\vpn-control-2.2.16.msi"):
            return ASSET
        raise OSError(2, "absent: " + path)

    # The product's own effects.
    def started(self, child):
        if child.label == "update-upstream":  # The upstream listens on its fixed port and writes its ready file.
            Path(child.argv[child.argv.index("--ready-file") + 1]).write_text(child.argv[child.argv.index("--port") + 1], encoding="utf-8")
        if child.label == "negative-installer-next-owner":
            self.product.controller = "controller-2"  # The case's own recovery owner of the same workspace.

    def completed(self, child):
        if child.label == "one-public-update-install":
            ready = self.variant != "install-cancelled"
            if ready:
                self.product.running = False  # The handoff stops the runtime before its commit.
            return self.product.envelope("ACCEPTED", final=False, operation=INSTALL, data={"jobId": JOB, "handoffReady": ready})
        if child.label == "updated-installed-public-version":
            return subprocess.CompletedProcess([CLI], 0, ("2.2.16" if self.terminal["phase"] == "SUCCEEDED" else "2.2.15") + "\n", "")
        return subprocess.CompletedProcess([CLI], 0, "", "")

    def ended(self, child):
        if child.label == "update-public-serve" and self.terminal["phase"] == "SUCCEEDED" and self.product.controller == "controller-1" \
                and self.variant != "install-cancelled" and any(kind == "update-uac-action-pending" for kind, _ in self.owner.events):
            # The worker relaunches the owner after the install, which restores the remembered intent itself.
            product = self.product
            product.returned, product.controller = True, "controller-2"
            product.running = product.intent
            product.runtime += 1 if product.intent else 0

    # The harness the job writes, as each module reads it.
    def inputs(self):
        new = hasattr(self.cases, "UPSTREAM_FIELDS")
        inventory = {"vpn-control-cli.exe": {"sizeBytes": 3, "sha256": CLI_SHA}, "vpn-control.exe": {"sizeBytes": 3, "sha256": "e" * 64},
                     HELPER_RELATIVE: {"sizeBytes": 9, "sha256": HELPER_SHA}}
        registration = {"productCode": "{33333333-4444-4555-8666-777777777777}", "principalSid": SID, "installContext": 2,
                        "displayVersion": "2.2.15", "installLocation": INSTALLED, "packageCode": "{44444444-5555-4666-8777-888888888888}"}
        fixture_root = WORKSPACE + "\\mcp-update-fixture-" + OPERATION
        value = {"schemaVersion": 1, "variant": self.variant, "sourceSha": "a" * 40, "sourceFingerprint": "f" * 64, "modules": dict(self.owner.paths),
                 "fixture": {"fixtureId": OPERATION, "content": fixture_root + "\\content", "state": fixture_root + "\\server-state",
                             "certificate": WORKSPACE + "\\c.pem", "privateKey": WORKSPACE + "\\k.pem", "trustStore": WORKSPACE + "\\t.p12",
                             "certificateSha256": "c" * 64},
                 "baseVersion": "2.2.15", "targetVersion": "2.2.16", "installedRoot": INSTALLED, "guiPath": GUI, "baseInventory": inventory,
                 "targetInventory": {name: dict(item, sha256="d" * 64) for name, item in inventory.items()}, "baseRegistration": registration,
                 "targetRegistration": dict(registration, displayVersion="2.2.16"), "programData": "C:\\ProgramData",
                 "evidenceRoot": "C:\\ProgramData\\update-evidence-" + OPERATION,
                 "collectorSourceSha256": self.owner.by_path[self.owner.paths["collector"].casefold()].record["sha256"],
                 "ordinarySid": SID, "ordinarySessionId": 2, "approvingAdminSid": ADMIN, "initialIntent": "off", "trafficInputs": None,
                 "faultInputs": {}, "returnGuiRequired": False, "connectionFixturePath": None, **({"upstreamFixture": None} if new else {})}
        if self.variant in ("success-reconnect", "success-explicit-off"):
            value.update(initialIntent="reconnect" if self.variant == "success-reconnect" else "off", connectionFixturePath=PROFILE,
                         trafficInputs={"schemaVersion": 1, "trafficWorkerPath": SAMPLER, "trafficInputPath": SAMPLER_INPUT,
                                        "fixtureAdmissionArtifactId": "update-upstream-" + "5" * 64, "sourceArtifactId": "sha256-" + "6" * 64})
            if new:
                value["upstreamFixture"] = {"schemaVersion": 1, "sourcePath": UPSTREAM, "port": 41082, "token": "vpn-control-update-upstream"}
        if self.variant == "participating-copy-lock":
            value["faultInputs"] = {"kind": "participating-copy-lock", "installedCliPath": CLI, "blockingWorkspace": str(self.root / COPY_LEAF)}
        return value

    def run(self):
        self.harness = {"UPDATE_INPUTS": self.inputs()}
        with mock.patch.object(self.cases.time, "sleep"):
            return self.cases.run_update(self.owner, self.harness)


def world_oracle(variant, check, prepare=None, **world):
    """One variant through a module: check(test, world, result) passes only on what the product's documented outcome needs."""
    def oracle(cases):
        class Oracle(unittest.TestCase):
            def runTest(self):
                with tempfile.TemporaryDirectory() as directory:
                    scene = World(Path(directory), cases, variant, **world)
                    if prepare is not None:
                        prepare(scene)
                    try:
                        result = scene.run()
                    except WorldParked as parked:
                        result = parked
                    check(self, scene, result)
        return Oracle()
    return oracle


CANCELLED = {"version": 1, "jobId": JOB, "sequence": 4, "phase": "CANCELLED", "code": "CANCELLED"}
COPY_LOCKED = {"version": 1, "jobId": JOB, "sequence": 5, "phase": "FAILED", "code": "RUNTIME_FAILED"}
INVENTORY = b'{"version":1,"stage":"INVENTORY","kind":"OTHER"}'


def passed(test, scene, result):
    test.assertEqual(0, result, "the case ended %r" % (result,))
    test.assertIsNone(scene.owner.parked)
    test.assertTrue(scene.closed, "the fixture closed known")
    test.assertTrue(all(child.terminal is not None for child in scene.owner.children), "no child left for the owner to park on")


def without_coordinator(scene):
    """The watch saw the job's worker alone: nothing proves an elevated coordinator ran or is gone."""
    observed = scene.cancel_actors
    scene.evidence["cancel-actors"] = lambda: {**observed(), "actors": [row for row in observed()["actors"] if row["role"] == "worker"]}


def refused_without_coordinator(test, scene, result):
    test.assertIsInstance(result, WorldParked, "a cancelled install passed with no elevated coordinator observed")
    test.assertIn("cancel-watch-complete-job-actors", str(result))


class UpdateVariantPairs(unittest.TestCase):
    """Defects these variants met before reaching a guest, each a pair over the case module as committed at 9a8db1e5."""

    def before(self):
        return module_from(fixture("update-cases.variants-before.source"), "_before_update_cases_variants",
                           ROOT / "agent_tools/windows_public_updater/update_cases.py")

    def test_the_connected_case_adds_its_location_from_a_link_the_product_parser_takes(self):
        """The case demanded socks5://127.0.0.1:<port>, which ProxyLinkParser does not dispatch: the owner answers
        INVALID_ARGUMENT at locations add, as the proxy rows met natively. The job now writes the socks:// link of the
        case's own upstream port, and the case takes only that."""
        from agent_tools.windows_public_updater import update_cases as current
        self.assertFalse(product_link_schemes.dispatched("socks5://127.0.0.1:41082#Update%20fixture\n"))
        self.assertTrue(product_link_schemes.dispatched("socks://127.0.0.1:41082#Update%20fixture\n"))
        run_pair(self, world_oracle("success-reconnect", passed), self.before(), current, "owned-no-egress-socks-connection-profile")

    def test_a_participating_copy_ends_with_the_coordinators_documented_failure(self):
        """The coordinator never stops a participating copy: its inventory stage never admits the copy, so it publishes
        FAILED RUNTIME_FAILED at its exit deadline beside the protected INVENTORY diagnostic (RunCoordinator,
        PublishPreinstallDiagnostic). The case demanded code BUSY, which no Windows coordinator publishes."""
        from agent_tools.windows_public_updater import update_cases as current
        run_pair(self, world_oracle("participating-copy-lock", passed, terminal=COPY_LOCKED, diagnostic=INVENTORY), self.before(), current,
                 "participating-copy-gate-native-busy")

    def test_a_cancelled_install_passes_only_with_its_watched_coordinator_and_worker(self):
        """The case accepted a CANCELLED terminal with no proof that the job's elevated coordinator and original-user worker
        ran and are gone: no stage could see them between the approval and the product's CANCELLED."""
        from agent_tools.windows_public_updater import update_cases as current
        run_pair(self, world_oracle("install-cancelled", refused_without_coordinator, without_coordinator, terminal=CANCELLED),
                 self.before(), current, "a cancelled install passed with no elevated coordinator observed")


def update_cases_module():
    from agent_tools.windows_public_updater import update_cases
    return update_cases


class UpdateVariantWorldTests(unittest.TestCase):
    """The current case module through the same world: what each variant now proves, and where it stops."""

    def run_world(self, variant, *, clock=False, prepare=None, **world):
        from agent_tools.windows_public_updater import update_cases
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        scene = World(Path(directory.name), update_cases, variant, **world)
        if prepare is not None:
            prepare(scene)
        ticks = iter(range(0, 10 ** 6))
        with mock.patch.object(update_cases.time, "monotonic", lambda: float(next(ticks))) if clock else contextlib.nullcontext():
            try:
                return scene, scene.run()
            except WorldParked as parked:
                return scene, parked

    def test_a_reconnected_update_restores_the_runtime_itself_after_the_owner_first_answers(self):
        """Traffic before through the base's runtime, the handoff stops it, the returned owner of the target answers
        disconnected three times and then runs its own restored runtime: the case reads it, bounded, records the outage
        and the traffic after, then stops its own upstream last."""
        scene, result = self.run_world("success-reconnect", returned_off_polls=3)
        passed(self, scene, result)
        self.assertEqual([("before", "controller-1"), ("after", "controller-2")], scene.traffic[:2])
        restored = [value for kind, value in scene.owner.events if kind == "update-reconnect-restored"]
        self.assertEqual(1, len(restored))
        self.assertEqual(({"runtimeId": "runtime-1", "runtimeStartedAt": 1000}, {"runtimeId": "runtime-2", "runtimeStartedAt": 2000}),
                         (restored[0]["runtimeBefore"], restored[0]["runtimeAfter"]))
        self.assertLessEqual(restored[0]["secondsAfterHandoff"], 900)
        calls = [words for words, _, _ in scene.product.calls]
        upstream = next(child for child in scene.owner.children if child.label == "update-upstream")
        self.assertEqual(("-I", "-B", UPSTREAM, "--port", "41082", "--token", "vpn-control-update-upstream"), upstream.argv[1:8])
        self.assertTrue(upstream.terminated, "the case's own upstream is stopped once the returned owner quit")
        self.assertLess(calls.index(("routing", "set", "ignore-rules", "true")), calls.index(("on",)))
        self.assertEqual(1, calls.count(("on",)), "the returned owner reconnects by itself: the case never asks it to")
        self.assertEqual(["update-upstream-stop-intent", "update-upstream-stopped"],
                         [kind for kind, _ in scene.owner.events if kind.startswith("update-upstream-st")])

    def test_an_explicit_off_survives_the_update_beside_a_location_it_could_reconnect_to(self):
        """success-explicit-off: the same connected owner, with traffic through its location, is turned off by the public
        explicit off before the update. Its returned owner is read for as long as success-reconnect gives a reconnect, and
        stays off with that location still selected in the same mode; nothing asks it to connect or to stay off."""
        scene, result = self.run_world("success-explicit-off", clock=True)
        passed(self, scene, result)
        calls = [words for words, _, _ in scene.product.calls]
        self.assertEqual((1, 1), (calls.count(("on",)), calls.count(("off",))), "the case's own on, then its explicit off, and nothing after")
        self.assertLess(calls.index(("off",)), calls.index(("updates", "download")), "off before the update is asked for")
        self.assertEqual([("before", "controller-1")], [item for item in scene.traffic if item[0] != "cleanup"])
        self.assertEqual(1, len([item for item in scene.traffic if item[0] == "cleanup"]), "the sampler of before closes once")
        before = [value["status"]["data"] for kind, value in scene.owner.events if kind == "update-explicit-off-before-update"]
        self.assertEqual([(False, "location-1", "proxy-only")], [(data["runtimeRunning"], data["selectedLocationId"], data["configuredMode"]) for data in before])
        kept = [value for kind, value in scene.owner.events if kind == "update-explicit-off-kept"]
        self.assertEqual(1, len(kept))
        self.assertGreaterEqual(kept[0]["watchedSeconds"], update_cases_module().RECONNECT_SECONDS)
        self.assertGreater(kept[0]["reads"], 1, "read over the whole bound, not once")
        self.assertEqual(("controller-2", False, "location-1"), (kept[0]["status"]["controllerId"], kept[0]["status"]["data"]["runtimeRunning"],
                                                                 kept[0]["status"]["data"]["selectedLocationId"]))
        upstream = next(child for child in scene.owner.children if child.label == "update-upstream")
        self.assertTrue(upstream.terminated, "its upstream stays up to the returned cleanup, so a reconnect would have had one")

    def test_only_the_connected_explicit_off_catches_a_returned_owner_that_lost_its_off(self):
        """A product that restored on whatever the remembered intent: success-off still passes, since its fresh workspace has
        no location to run, while success-explicit-off fails on the first read that runs, or a late one."""
        def restores_on(after_reads):
            def prepare(scene):
                status, reads = scene.product.status, []

                def lost(product=scene.product):
                    if product.returned:
                        reads.append(1)
                        if len(reads) > after_reads and product.selected is not None:
                            product.running = True  # A runtime needs a selected location; a fresh workspace has none.
                    return status()
                scene.product.status = lost
            return prepare
        scene, result = self.run_world("success-off", clock=True, prepare=restores_on(0))
        passed(self, scene, result)
        for after_reads in (0, 40):
            with self.subTest(after_reads=after_reads):
                scene, result = self.run_world("success-explicit-off", clock=True, prepare=restores_on(after_reads))
                self.assertIsInstance(result, WorldParked)
                self.assertIn("returned-owner-explicit-off-kept", str(result))

    def test_a_returned_owner_that_stays_off_fails_within_its_bound(self):
        scene, result = self.run_world("success-reconnect", clock=True, returned_off_polls=10 ** 6)
        self.assertIsInstance(result, WorldParked)
        self.assertIn("returned-owner-reconnect-unbounded", str(result))

    def test_a_location_without_its_upstream_carries_no_traffic(self):
        """The location names the upstream's fixed port: the case starts it before the runtime connects."""
        def without_upstream(scene):
            scene.started = lambda child: None  # The upstream never writes its ready file.
        scene, result = self.run_world("success-reconnect", clock=True, prepare=without_upstream)
        self.assertIsInstance(result, WorldParked)
        self.assertIn("update-upstream-readiness-unknown-no-replay", str(result))

    def test_a_cancelled_install_names_its_watched_actors_and_waits_bounded(self):
        scene, result = self.run_world("install-cancelled", terminal=CANCELLED)
        passed(self, scene, result)
        waits = [timeout for words, _, timeout in scene.product.calls if words == ("operations", "wait", INSTALL)]
        self.assertEqual([420], waits, "one bounded wait for the cancelled operation")
        observed = [value for kind, value in scene.owner.events if kind == "update-install-cancel-actors-observed"]
        self.assertEqual([(COORDINATOR["pid"], WORKER["pid"])], [(value["coordinator"]["pid"], value["worker"]["pid"]) for value in observed])

    def test_a_cancellation_the_product_never_ends_parks_with_its_reply_kept(self):
        scene, result = self.run_world("install-cancelled", terminal=CANCELLED, cancel_code="TIMEOUT")
        self.assertIsInstance(result, WorldParked)
        self.assertIn("public-envelope-result", str(result))
        self.assertFalse(scene.closed, "an operation the product may still run keeps the fixture for the park")

    def test_the_watch_record_must_bind_the_job_its_tokens_and_both_exits(self):
        def changed(**fields):
            def prepare(scene):
                observed = scene.cancel_actors
                scene.evidence["cancel-actors"] = lambda: {**observed(), **fields}
            return prepare

        def actor(role, **fields):
            def prepare(scene):
                observed = scene.cancel_actors
                scene.evidence["cancel-actors"] = lambda: {**observed(), "actors": [
                    {**row, **fields} if row["role"] == role else row for row in observed()["actors"]]}
            return prepare
        cases = (("cancel-watch-complete-job-actors", changed(armedBeforeActors=False)),
                 ("cancel-watch-complete-job-actors", changed(timedOut=True)),
                 ("cancel-watch-complete-job-actors", changed(complete=False)),
                 ("cancel-watch-coordinator-identity", actor("coordinator", elevated=0)),
                 ("cancel-watch-coordinator-identity", actor("coordinator", sid=SID)),
                 ("cancel-watch-coordinator-identity", actor("coordinator", originalAbsent=False)),
                 ("cancel-watch-worker-identity", actor("worker", sha256="0" * 64)),
                 ("cancel-watch-worker-generation", actor("worker", creationFileTime=COORDINATOR["creationFileTime"] - 1)),
                 ("cancel-watch-no-elevated-helper-left", changed(others=[{"pid": 930, "elevated": 1, "originalAbsent": False}])))
        for reason, prepare in cases:
            with self.subTest(reason=reason):
                scene, result = self.run_world("install-cancelled", prepare=prepare, terminal=CANCELLED)
                self.assertIsInstance(result, WorldParked)
                self.assertIn(reason, str(result))

    def test_the_copy_lock_terminal_needs_its_diagnostic_and_the_copy_still_running(self):
        for diagnostic in (None, b'{"version":1,"stage":"READINESS","kind":"OTHER"}'):
            with self.subTest(diagnostic=diagnostic):
                scene, result = self.run_world("participating-copy-lock", terminal=COPY_LOCKED, diagnostic=diagnostic)
                self.assertIsInstance(result, WorldParked)
        scene, result = self.run_world("participating-copy-lock", terminal=COPY_LOCKED, diagnostic=INVENTORY)
        passed(self, scene, result)
        copy = next(child for child in scene.owner.children if child.label == "participating-installed-copy")
        self.assertEqual((str(scene.root / COPY_LEAF), "serve"), copy.argv[2:])
        self.assertEqual(2, [words for words, _, _ in scene.product.calls].count(("quit",)), "the copy and the case's recovery owner")

    def test_the_fault_ready_record_must_name_the_copy_the_case_started(self):
        def other(scene):
            observed = scene.fault_ready
            scene.evidence["fault-ready"] = lambda: {**observed(), "participatingCopy": {**observed()["participatingCopy"], "pid": 1}}
        scene, result = self.run_world("participating-copy-lock", prepare=other, terminal=COPY_LOCKED, diagnostic=INVENTORY)
        self.assertIsInstance(result, WorldParked)
        self.assertIn("native-participating-copy-actor", str(result))


def status_oracle(template):
    """A row's prompt event stays named in the status until its decision is known, however many events follow it."""
    class Oracle(unittest.TestCase):
        def runTest(self):
            body = template[template.index("function N("):template.index("function Write-Status(")]
            with tempfile.TemporaryDirectory(prefix="scenario-window-") as directory:
                root = Path(directory) / "operation"
                root.mkdir()
                kinds = ["update-uac-action-pending"] + ["child-intent", "child-started", "child-terminal"] * 7
                for ordinal, kind in enumerate(kinds):
                    (root / ("event-%06d-%s.json" % (ordinal, kind))).write_text(json.dumps({"ordinal": ordinal, "kind": kind}))
                script = Path(directory) / "status.ps1"
                script.write_text("$ErrorActionPreference='Stop';$m=[pscustomobject]@{operationId='" + OPERATION + "';uacKinds=@('update-uac-action-pending');"
                                  "nativeNeeds=$false}\n" + body + "[Console]::Out.Write(((Read-Status '" + str(root).replace("'", "''")
                                  + "' 1)|ConvertTo-Json -Depth 4 -Compress))\n", encoding="ascii")
                done = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                      stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
                self.assertEqual(0, done.returncode, done.stderr.decode("utf-8", "replace"))
                status = json.loads(done.stdout)
                named = list(status.get("uacEvents") or []) + list(status.get("pendingKinds") or [])
                self.assertIn("update-uac-action-pending", named, "the prompt fell out of the status before any client saw it")
    return Oracle()


class StatusWindowPair(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, "PowerShell unavailable; hosted Windows and Linux runners have one")
    def test_a_prompt_event_outlives_the_sixteen_event_window(self):
        before = fixture("system-run.before.ps1").decode("ascii")
        current = (ROOT / "agent_tools/windows_scenario_system_run.ps1.template").read_text(encoding="ascii")
        run_pair(self, status_oracle, before, current, "the prompt fell out of the status")


class FailingMsiProof(unittest.TestCase):
    """The failing-MSI derivation needs a LaunchCondition table and action; the product's MSIs carry neither."""

    def test_the_real_execute_sequence_is_refused_before_any_derivation(self):
        from agent_tools.windows_failing_msi import failing_msi_fixture as recipe
        snapshot = json.loads(fixture("real-msi-schedule.json"))
        self.assertNotIn("LaunchCondition", PROVENANCE["realMsiTables"])
        self.assertNotIn("LaunchConditions", [row[0] for row in snapshot["tables"]["InstallExecuteSequence"]["rows"]])
        self.assertEqual("vpn-control", recipe.product(snapshot)["productName"])
        with self.assertRaisesRegex(recipe.Refused, "existing-unfaulted-launchcondition-table"):
            recipe.validate_schedule(snapshot)
        # An empty table alone would not do either: no LaunchConditions action precedes the modifying actions.
        snapshot["tables"]["LaunchCondition"] = {"columns": [["Condition", "s255"], ["Description", "l255"]], "rows": []}
        with self.assertRaisesRegex(recipe.Refused, "unconditional-positive-launchconditions"):
            recipe.validate_schedule(snapshot)


if __name__ == "__main__":
    unittest.main()
