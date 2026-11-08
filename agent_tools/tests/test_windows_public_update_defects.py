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

import hashlib
import json
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import tempfile
import types
import unittest

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
GUARDED = {("settings", "set"), ("settings", "apply"), ("source", "set"), ("locations", "add"), ("locations", "select"),
           ("locations", "update"), ("locations", "delete"), ("quit",), ("updates", "install")}


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

    def __init__(self, root, cli):
        self.root, self.cli, self.environment, self.events, self.native = root, cli, {}, [], None
        self.request = {"workspace": str(root / "workspace"), "cliPath": CLI, "productVersion": "2.2.15",
                        "casesPath": WORKSPACE + "\\update_cases.py", "harnessPath": WORKSPACE + "\\update-harness.py",
                        "context": {"ordinarySid": SID, "ordinarySessionId": 2}}
        self.paths = {key: WORKSPACE + "\\" + name for key, name in self.MODULES.items()}
        pins = [Pin(path, path.encode()) for path in self.paths.values()]
        pins.append(Pin(PROFILE, b"socks5://127.0.0.1:1080#Update%20fixture\n"))
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
        return Child(label)

    def invoke(self, workspace, *arguments):
        return self.cli(workspace, *arguments)

    def inputs(self):
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
                owner = Owner(Path(directory), cli)
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
