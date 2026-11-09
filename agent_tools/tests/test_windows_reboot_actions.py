"""The whole preboot and postboot action bodies over one declared product world, offline.

The real action, autostart and source-role modules run; the product CLI, Task Scheduler,
native census, listener query, traffic sampler and upstream are declared peers. The CLI
takes a location link only when ProxyLinkParser, read from its Kotlin source, dispatches
it. Nothing here proves a Windows behaviour: it keeps a typo in an action body off a guest.
"""
import base64
from pathlib import Path, PureWindowsPath
import hashlib
import json
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_autostart_reboot as autostart
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools import windows_postboot_action as postboot
from agent_tools import windows_postboot_source_roles as source_roles
from agent_tools import windows_preboot_action as preboot
from agent_tools.tests import product_link_schemes as product_links

SID = "S-1-5-21-1-2-3-1000"
GUI = r"C:\Users\recovery\AppData\Local\vpn-control\vpn-control.exe"
CLI = r"C:\Users\recovery\AppData\Local\vpn-control\vpn-control-cli.exe"
# The package has no loose runtime: its digest is the installed record beside the GUI, the image is extracted per workspace.
AUTHORITY = r"C:\Users\recovery\AppData\Local\vpn-control\app\native\windows-amd64\native-helpers.json"
RUNTIME = hashlib.sha256(b"bundled sing-box.exe").hexdigest()
BOOT = "134368653065000000"
CONTEXT = {"deploymentId": "33333333-4444-4555-8666-777777777777", "ordinarySid": SID, "ordinarySessionId": 2,
           "machineGuid": "a1b2c3d4-0000-4000-8000-000000000001", "bootIdentifier": "11111111-2222-4333-8444-555555555555", "bootFileTimeUtc": BOOT}


class Parked(BaseException):
    pass


class Pin:
    def __init__(self, path, raw=b"declared", directory=False):
        self.path, self.raw, self.directory = Path(path), raw, directory
        self.record = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "nativeIdentity": {"sizeBytes": len(raw)}}

    def current(self):
        pass

    def digest(self, return_bytes=False, maximum=None):
        return self.raw if return_bytes else self.record["sha256"]


class Child:
    def __init__(self, owner, label, argv, ordinal):
        self.owner, self.label, self.argv, self.ordinal = owner, label, tuple(argv), ordinal
        self.pid, self.birth, self.terminal, self.code = 3000 + ordinal, str(int(BOOT) + 10 + ordinal), None, None
        self.process = types.SimpleNamespace(poll=lambda: self.code, terminate=self.terminate, _handle=self.pid)
        self.out = self.err = ""

    def end(self, code, out="", err=""):
        self.code, self.out, self.err = code, out, err
        self.terminal = {"exitCode": code, "eof": {"stdout": True, "stderr": True}, "pid": self.pid}

    def terminate(self):
        self.owner.world.trace.append(("terminate", self.label))
        self.end(1)

    def observe(self):
        return self.terminal

    def wait(self):
        if self.terminal is None:
            self.owner.world.waited(self)
        return self.terminal

    def completed(self):
        self.wait()
        return types.SimpleNamespace(returncode=self.code, stdout=self.out, stderr=self.err)


class World:
    """The product as its public CLI, its autostart task and its processes look from the owner."""

    def __init__(self, owner, scenario):
        self.owner, self.scenario, self.trace = owner, scenario, []
        self.task, self.processes, self.intent, self.running, self.controller = "absent", {}, False, False, None
        self.controller_jvm = None
        self.fixture_refused = False  # The first native gate: a standard user may not register the legacy task.
        self.locations, self.revision, self.settings = [], 0, {"autostart": False}
        self.next_pid, self.visible, self.last_run = 500, True, None

    def envelope(self, data=None, code="OK"):
        self.revision += 0
        return json.dumps({"schemaVersion": 1, "code": code, "ok": code == "OK", "final": True, "controllerId": self.controller,
                           "requestId": "request-" + str(len(self.trace)), "configurationRevision": self.revision, "restartRequired": False,
                           "operationId": None, "data": data or {}})

    def status(self):
        active = self.locations[0]["id"] if self.running else None
        return {"runtimeRunning": self.running, "activeMode": "proxy-only" if self.running else None, "activeLocationId": active,
                "runtimeId": "runtime" if self.running else None, "runtimeStartedAt": "now" if self.running else None}

    def spawn(self, image, argv, parent):
        self.next_pid += 1
        self.processes[self.next_pid] = {"pid": self.next_pid, "parentPid": parent, "image": image, "argv": argv, "sessionId": 2,
                                         "creationFileTime": int(self.owner.request["context"]["bootFileTimeUtc"]) + 1000 + self.next_pid}
        return self.next_pid

    def start_product(self, parent):
        workspace = self.owner.request["workspace"]
        self.last_run = int(self.owner.request["context"]["bootFileTimeUtc"]) + 500
        launcher = self.spawn(GUI, [GUI, "--autostart", "--state-dir", workspace], parent)
        gui = self.spawn(GUI, [GUI, "--autostart", "--state-dir", workspace], launcher)
        controller_launcher = self.spawn(GUI, [GUI, "--headless-controller", "--state-dir", workspace], gui)
        controller = self.spawn(GUI, [GUI, "--headless-controller", "--state-dir", workspace], controller_launcher)
        self.controller, self.running, self.controller_jvm = "controller-" + str(controller), self.intent, controller
        if self.running:
            self.spawn(str(PureWindowsPath(workspace) / "runtime" / "tools" / "sing-box.exe"), ["sing-box.exe", "run"], controller)
        (Path(workspace) / "activation.port").write_text("{}")
        self.owner.native.ports[controller] = 41000

    def start_transient(self, cli):
        """DesktopCli with no owner starts a headless controller for any operation but status, quit, gui hide."""
        workspace = self.owner.request["workspace"]
        argv = [GUI, "--headless-controller", "--state-dir", workspace]
        launcher = self.spawn(GUI, argv, cli.pid)
        self.controller_jvm = self.spawn(GUI, argv, launcher)
        self.controller, self.running = "transient-" + str(self.controller_jvm), False  # A transient owner never resumes.
        (Path(workspace) / "activation.port").write_text("{}")

    def start_gui(self, child):
        """The GUI joins the workspace's owner and restores the remembered intent once."""
        launcher = self.spawn(GUI, list(child.argv), 41)
        self.spawn(GUI, list(child.argv), launcher)
        if self.intent and self.controller is not None and not self.running:
            self.running = True
            self.spawn(str(PureWindowsPath(self.owner.request["workspace"]) / "runtime" / "tools" / "sing-box.exe"), ["sing-box.exe", "run"],
                       self.controller_jvm)

    def snapshot(self, child):
        task = {"state": "absent"}
        if self.task != "absent":
            level = "<RunLevel>HighestAvailable</RunLevel>" if self.task == "highest" else ""
            xml = ('<Task xmlns="' + autostart.NS + '"><Principals><Principal id="Author"><UserId>' + SID + '</UserId><LogonType>InteractiveToken'
                   '</LogonType>' + level + '</Principal></Principals><Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
                   '<Actions Context="Author"><Exec><Command>' + GUI + '</Command><Arguments>--autostart --state-dir "' + self.owner.request["workspace"]
                   + '"</Arguments></Exec></Actions></Task>')
            task = {"state": "present", "path": autostart.TASK, "xml": xml, "sddl": "D:P(A;;FA;;;SY)", "enabled": True, "lastRunFileTimeUtc": str(self.last_run or BOOT),
                    "lastTaskResult": 0, "schedulerState": 3, "runningInstances": []}
        context = self.owner.request["context"]
        return {"schemaVersion": 2, "collector": "exact-autostart-read-only-v2", "sid": SID, "sessionId": 2, "pid": child.pid,
                "creationFileTime": child.birth, "elevated": 0, "inJob": False, "bootIdentifier": context["bootIdentifier"],
                "machineGuid": context["machineGuid"], "task": task, "run": {"state": "absent", "keyState": "present"}}

    def respond(self, child):
        argv = list(child.argv)
        self.trace.append((child.label, tuple(argv[3:] if argv[0] == CLI else argv[-2:])))
        if argv[0] == GUI and argv[1:] == ["--state-dir", self.owner.request["workspace"]]:
            self.start_gui(child)
            return None
        if argv[0] == CLI:
            tail = argv[3:]
            if tail in (["--help"], ["--version"]):
                return child.end(0, "Usage: vpn-control" if tail == ["--help"] else self.owner.request["productVersion"])
            if tail[0] == "serve":
                self.controller = "serve-" + str(child.pid)
                (Path(argv[2]) / "activation.port").parent.mkdir(exist_ok=True)
                (Path(argv[2]) / "activation.port").write_text("{}")
                return None
            tail = tail[1:]
            named = tail[0] == "--controller-id"
            if named:
                tail = tail[2:]
            if tail[0] == "--if-revision":
                tail = tail[2:]
                self.revision += 1
            if self.controller is None and not named and tail not in (["status"], ["quit"], ["gui", "hide"]):
                self.start_transient(child)
            if self.controller is None:
                return child.end(2, self.envelope(code="UNAVAILABLE"))
            body = {}
            if tail == ["status"]:
                body = self.status()
            elif tail[:2] == ["locations", "list"]:
                body = {"locations": list(self.locations)}
            elif tail[:3] == ["locations", "add", "--input"]:
                # LocationConfigs.parseLocationInput: a link ProxyLinkParser does not dispatch is INVALID_ARGUMENT.
                link = Path(tail[3]).read_text(encoding="utf-8").strip()
                if not product_links.dispatched(link):
                    return child.end(1, self.envelope(code="INVALID_ARGUMENT"))
                self.locations.append({"id": "location-" + self.controller, "name": link.rsplit("#", 1)[1].replace("%20", " ")})
            elif tail[:2] == ["settings", "set"] and tail[2] == "autostart":
                self.task = "limited" if tail[3] == "true" else "absent"
            elif tail == ["on"]:
                self.intent = self.running = True
            elif tail == ["off"]:
                self.intent = self.running = False
                for pid in [pid for pid, row in self.processes.items() if row["image"].endswith("sing-box.exe")]:
                    del self.processes[pid]
            elif tail[:1] == ["gui"]:
                self.visible = tail[1] == "show"
            elif tail == ["quit"]:
                answer = self.envelope(body)  # The owner answers, then exits.
                self.quit()
                return child.end(0, answer)
            return child.end(0, self.envelope(body))
        script = argv[6] if len(argv) > 6 else ""
        if script.endswith("snapshotScript.data"):
            return child.end(0, json.dumps(self.snapshot(child)))
        if script.endswith("migrationScript.data"):
            if self.fixture_refused:
                return child.end(1, "", "Access is denied.")
            self.task = "highest"
            return child.end(0, json.dumps({"schemaVersion": 1, "taskPath": autostart.TASK, "runLevel": "HighestAvailable"}))
        if script.endswith("startScript.data"):
            self.start_product(40)
            return child.end(0, json.dumps({"schemaVersion": 1, "taskPath": autostart.TASK, "instanceGuid": "{instance}"}))
        if script.endswith("startupCollector.data"):
            rows = [dict(row) for row in self.processes.values()]
            return child.end(0, json.dumps({"schemaVersion": 1, "collector": "prequery-native-startup-census", "pid": child.pid,
                                            "creationFileTime": child.birth, "sessionId": 2, "rows": rows}))
        if script.endswith("listenerScript.data"):
            pid = int(argv[argv.index("-TargetPid") + 1])
            return child.end(0, json.dumps({"schemaVersion": 1, "pid": pid, "creationFileTime": argv[argv.index("-CreationFileTime") + 1],
                                            "listeners": [{"address": "127.0.0.1", "port": 41000, "pid": pid}]}))
        if argv[-2] == "--mixed-port":
            rows = [json.dumps({"kind": "sample", "ordinal": n, "succeeded": True, "mixedPort": 41000}) for n in range(4)]
            return child.end(0, "\n".join(rows + [json.dumps({"kind": "terminal", "allSamplesSucceeded": True, "sampleCount": 4})]) + "\n")
        if "--ready-file" in argv:
            Path(argv[argv.index("--ready-file") + 1]).write_text(str(source_roles.UPSTREAM_PORT) + "\n")
            return None
        raise AssertionError(("unexpected child", argv))

    def quit(self):
        self.running = False
        self.controller = None
        for path in Path(self.owner.request["workspace"]).glob("activation.port"):
            path.unlink()
        for child in self.owner.children:
            if child.terminal is None and (child.label == "serve" or child.argv[0] == GUI):
                child.end(0)
        self.processes.clear()

    def waited(self, child):
        raise AssertionError(("a live child was waited on", child.label))


class Native:
    def __init__(self, world):
        self.world, self.ports = world, {}
        self.k = types.SimpleNamespace(CreateFileW=lambda *a: 7, CloseHandle=lambda handle: True)
        self.boot_identifier = lambda: world.owner.request["context"]["bootIdentifier"]

    def open_process(self, pid, access):
        world = self.world

        class Process:
            def describe(self):
                row = world.processes.get(pid)
                if row is None:
                    raise AssertionError("absent process")
                image = b"bundled sing-box.exe" if row["image"].endswith("sing-box.exe") else b"declared"
                return {"image": row["image"], "creationFileTime": row["creationFileTime"], "sha256": hashlib.sha256(image).hexdigest(),
                        "token": {"sid": SID, "sessionId": 2, "elevated": 0}}

            def wait(self):
                return 258 if pid in world.processes else 0

            def times(self):
                return {"creationFileTime": self.describe()["creationFileTime"]} if pid in world.processes else {"creationFileTime": exits[pid]}

            def __exit__(self, *_):
                pass
        exits = {}
        if pid in world.processes:
            exits[pid] = world.processes[pid]["creationFileTime"]
        return Process()


class Owner:
    def __init__(self, root, scenario, phase):
        self.root = Path(root)
        self.operation = str(uuid.uuid4())
        self.children, self.events, self.pins, self.reboot_effect = [], [], [], None
        workspace = str(self.root / "workspace")
        self.request = {"action": "windows-preboot-reboot", "cliPath": CLI, "workspace": workspace, "productVersion": "2.2.16",
                        "pythonRuntime": {"interpreterPath": r"C:\Users\recovery\AppData\Local\Programs\Python\Python313\python.exe"},
                        "context": {"deploymentId": "33333333-4444-4555-8666-777777777777", "ordinarySid": SID, "ordinarySessionId": 2,
                                    "machineGuid": "a1b2c3d4-0000-4000-8000-000000000001", "bootIdentifier": "11111111-2222-4333-8444-555555555555",
                                    "bootFileTimeUtc": BOOT}}
        roles = {role: str(self.root / (role + ".data")) for role in source_roles.ROLES}
        roles.update(powerShell=source_roles.POWERSHELL, gui=GUI, sourceRoles=str(Path(source_roles.__file__)), runtimeAuthority=AUTHORITY)
        self.by_path = {str(Path(path)).casefold(): Pin(path) for path in roles.values()}
        self.by_path[AUTHORITY.casefold()] = Pin(AUTHORITY, json.dumps({"schemaVersion": 1, "policySha256": "e" * 64, "artifacts": [],
            "runtimeAuthority": {"runtimeSha256": RUNTIME, "runtimeSizeBytes": 41943040, "authoritySourceSha256": "f" * 64}}).encode())
        traffic = str(self.root / "traffic-input.json")
        body = {"schemaVersion": 1, "mixedPort": None, "expectedBodyHex": source_roles.UPSTREAM_TOKEN.encode().hex(), "sampleCount": 4,
                "intervalSeconds": 0.1, "ioTimeoutSeconds": 2}
        self.by_path[traffic.casefold()] = Pin(traffic, json.dumps(body).encode())
        auto = {"schemaVersion": 1, "workspace": workspace, "snapshotScriptPath": roles["snapshotScript"], "powerShellPath": roles["powerShell"],
                "migrationScriptPath": roles["migrationScript"], "startScriptPath": roles["startScript"], "guiPath": GUI}
        self.config = {"schemaVersion": 1, "phase": phase, "scenario": scenario, "sourceRoles": roles, "autostartInputs": auto, "trafficInputPath": traffic}
        self.world = World(self, scenario)
        self.native = Native(self.world)
        self.native.identity = lambda handle, directory=False: {"sizeBytes": 2}
        self.native.security = lambda handle: {"ownerSid": SID, "sddl": "D:P"}
        # One declared private file answers both reads: the product endpoint and workspace.json.
        self.native.read_blocks = lambda handle: iter([json.dumps({"schemaVersion": 1, "controllerId": self.world.controller, "port": 41000,
                                                                   "resume_connection_on_launch": False}).encode()])

    def guard(self):
        pass

    def event(self, kind, value):
        json.dumps(value)
        self.events.append((kind, value))

    def park(self, reason, error=None):
        raise Parked(reason)

    def child(self, label, argv):
        child = Child(self, label, argv, len(self.children))
        self.children.append(child)
        self.world.respond(child)
        return child

    def invoke(self, workspace, *arguments, timeout=30):
        return self.child("public-cli", [CLI, "--state-dir", str(workspace), *arguments]).completed()

    def module(self, path, name):
        role = next(role for role, value in self.config["sourceRoles"].items() if value == path)
        return self.modules[role]


def fakes(owner):
    def publish(who, path, raw):
        Path(path).write_bytes(raw)
        return path

    def listeners(who, query, actor):
        return json.loads(who.child("owned-runtime-listeners", [query["powerShellPath"], "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                          "-File", query["listenerScriptPath"], "-TargetPid", str(actor["pid"]), "-CreationFileTime",
                          str(actor["creationFileTime"])]).completed().stdout)["listeners"]
    return {"autostart": autostart, "runtimeStages": types.SimpleNamespace(publish=publish),
            "lifecycle": types.SimpleNamespace(product_traffic_port=lambda config, port: 41000,
                                               GuiWindows=lambda: types.SimpleNamespace(windows=lambda pid: [
                                                   {"hwnd": 1, "pid": pid, "visible": owner.world.visible, "width": 800, "height": 600}])),
            "runtime": types.SimpleNamespace(listeners=listeners, probe_stream=lambda raw, port: raw.splitlines()),
            "observer": types.SimpleNamespace(WindowsNative=lambda: owner.native)}


class Clock:
    """Waits advance this clock, never the test's real time."""
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class WorldCase(unittest.TestCase):
    def setUp(self):
        clock = Clock()
        for module in (preboot, postboot):
            patcher = mock.patch.object(module, "time", clock)
            patcher.start()
            self.addCleanup(patcher.stop)
        # The guest's paths are Windows paths; this world's are the test's own temporary directory.
        for patcher in (mock.patch.object(source_roles, "windows_path", lambda value: str(value).casefold()),
                        mock.patch.object(autostart, "path_value", lambda value: value)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def owner(self, scenario):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        owner = Owner(directory.name, scenario, "preboot-reboot")
        owner.modules = fakes(owner)
        return owner

    def after_reboot(self, scenario):
        """A passed preboot, then readiness-reboot and the sign-in: the logon trigger runs the same task once."""
        before = self.owner(scenario)
        self.assertEqual(0, preboot.run_preboot(before, before.config, source_roles, postboot))
        checkpoint = next(value for kind, value in before.events if kind == "reboot-checkpoint")
        owner = Owner(before.root, scenario, "postboot-final")
        owner.modules, owner.world = fakes(owner), before.world
        owner.world.owner, owner.native.world = owner, owner.world
        owner.request["context"] = dict(before.request["context"], bootFileTimeUtc=str(int(BOOT) + 600000000))
        owner.world.processes.clear()
        owner.world.controller = None
        owner.world.start_product(40)
        record = {"schemaVersion": 1, "operationId": before.operation, "ordinal": 30, "kind": "reboot-checkpoint", "value": checkpoint}
        path = str(before.root / "event-000030-reboot-checkpoint.json")
        owner.by_path[path.casefold()] = Pin(path, json.dumps(record).encode())
        owner.config["checkpointPath"] = path
        owner.pins.append(Pin(owner.request["workspace"], directory=True))
        return owner

    def main(self, owner, action):
        """The real owner main and Owner.run dispatch over the real action bodies; the entry table names these pins."""
        owner.request.update(action=action, postbootAcceptance=owner.config)
        owner.modules.update(sourceRoles=source_roles, postbootAction=postboot, prebootAction=preboot)
        finished = []
        owner.finish = lambda code, error=None: finished.append(code)
        real_run = process_owner.Owner.run
        owner.run = lambda: real_run(owner)
        roles = owner.config["sourceRoles"]
        table = {role: {"sha256": owner.by_path[str(Path(roles[role])).casefold()].record["sha256"],
                        "sizeBytes": owner.by_path[str(Path(roles[role])).casefold()].record["nativeIdentity"]["sizeBytes"]}
                 for role in ("sourceRoles", "postbootAction", "prebootAction", "startupCollector")}
        raw = b"{}"
        record = {"path": "declared-request", "sha256": hashlib.sha256(raw).hexdigest()}
        request_pin = types.SimpleNamespace(digest=lambda retain=False, maximum=None: raw)
        argv = ["owner", "--request", record["path"], "--request-sha256", record["sha256"],
                "--request-pin-base64", base64.b64encode(json.dumps(record).encode()).decode()]
        with mock.patch.object(process_owner, "absolute", Path), mock.patch.object(process_owner, "Native", lambda: None), \
                mock.patch.object(process_owner, "Pin", lambda native, pin: request_pin), \
                mock.patch.object(process_owner, "Owner", lambda request, pin: owner), \
                mock.patch.object(process_owner, "_POSTBOOT_ENTRY_SOURCES", table), mock.patch.object(sys, "argv", argv):
            try:
                result = process_owner.main()
            except Parked as parked:
                result = parked
        self.assertEqual("entered-original-action", owner.postboot_dispatch["stage"])
        return result, finished


class PrebootActionTests(WorldCase):
    def test_each_reboot_preboot_leaves_the_autostarted_app_declared_and_no_child_of_its_own(self):
        for scenario, running in (("reconnect", True), ("explicit-off", False), ("autostart-migration", False)):
            with self.subTest(scenario=scenario):
                owner = self.owner(scenario)
                self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
                self.assertTrue(all(child.terminal is not None for child in owner.children), "the owner can finish")
                checkpoint = [value for kind, value in owner.events if kind == "reboot-checkpoint"]
                self.assertEqual(1, len(checkpoint))
                rows = checkpoint[0]["declaredProduct"]
                self.assertEqual(["guiLauncher", "gui", "controllerLauncher", "controller", *(["runtime"] if running else [])],
                                 [row["role"] for row in rows])
                self.assertEqual(40, rows[0]["parentPid"], "the root was started by the task scheduler")
                self.assertEqual([RUNTIME] if running else [], [row["sha256"] for row in rows if row["role"] == "runtime"],
                                 "the runtime is declared by the installed record's digest")
                self.assertEqual("Owned Reboot" if running else None, checkpoint[0]["activeLocationName"])
                labels = [child.label for child in owner.children]
                self.assertLess(labels.index("autostart-highest-fixture"), labels.index("product-autostart-start"))
                self.assertEqual(["terminate"], [kind for kind, _ in owner.world.trace if kind == "terminate"], "one owned upstream stop")
                self.assertEqual(running, owner.world.running)
                order = [" ".join(tail) for label, tail in owner.world.trace if label == "public-cli"]
                first = lambda text: next(number for number, line in enumerate(order) if text in line)
                self.assertLess(first("source set current-locations"), first("locations add"), "the source is set before the first location")

    def test_a_profile_the_product_parser_refuses_is_a_known_refusal_that_retires_the_serve(self):
        # Native 6a0a73b8 met this in the proxy rows: the owner answers a socks5:// location INVALID_ARGUMENT.
        owner = self.owner("reconnect")
        publish = owner.modules["runtimeStages"].publish
        owner.modules["runtimeStages"] = types.SimpleNamespace(
            publish=lambda who, path, raw: publish(who, path, raw.replace(b"socks://", b"socks5://")))
        with self.assertRaisesRegex(ValueError, "^postboot-public-known-terminal$"):
            preboot.run_preboot(owner, owner.config, source_roles, postboot)
        self.assertEqual([], owner.world.locations)
        self.assertEqual([], [child.label for child in owner.children if child.terminal is None], "its own serve answered the quit")
        self.assertEqual(1, [kind for kind, _ in owner.events].count("preboot-refusal-quit-intent"))

    def test_the_query_row_starts_a_transient_owner_by_a_config_query_and_never_reboots_or_declares(self):
        # status with no owner never starts one (DesktopCli noStartupOperations). The body polled status, so it parked.
        owner = self.owner("query-first")
        self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
        self.assertTrue(all(child.terminal is not None for child in owner.children), "the owner can finish")
        result = next(value for kind, value in owner.events if kind == "query-owner-gui-reconnect-observed")
        self.assertEqual((False, True), (result["queryConnected"], result["queryControllerId"].startswith("transient-")))
        calls = [" ".join(tail) for label, tail in owner.world.trace if label == "public-cli"]
        quit_at = calls.index("--json --controller-id serve-" + str(next(c.pid for c in owner.children if c.label == "serve")) + " quit")
        self.assertEqual(["--json status", "--json locations list"], calls[quit_at + 1:quit_at + 3], "a config query starts the owner")
        traffic = next(value for kind, value in owner.events if kind == "postboot-query-first-traffic-observed")
        self.assertEqual(RUNTIME, traffic["runtimeActor"]["sha256"], "the runtime digest is the installed record's")
        self.assertFalse([kind for kind, _ in owner.events if kind == "reboot-checkpoint"])
        self.assertNotIn("product-autostart-start", [child.label for child in owner.children])
        self.assertEqual(("absent", {}, False), (owner.world.task, owner.world.processes, owner.world.intent))

    def test_a_known_refusal_retires_the_upstream_and_its_own_serve_and_raises(self):
        owner = self.owner("reconnect")
        owner.modules["autostart"] = types.SimpleNamespace(**{name: getattr(autostart, name) for name in dir(autostart) if not name.startswith("__")})
        owner.modules["autostart"].migration = lambda *arguments: {"after": {"qualifiedOwnership": "highest"}}
        with self.assertRaisesRegex(ValueError, "ordinary-actual-autostart-migration-required"):
            preboot.run_preboot(owner, owner.config, source_roles, postboot)
        self.assertEqual([("terminate", "owned-upstream-preboot")], [entry for entry in owner.world.trace if entry[0] == "terminate"])
        # Its own serve answered the journaled quit, so no child of the owner is live and main can finish.
        self.assertEqual([], [child.label for child in owner.children if child.terminal is None])
        self.assertEqual(1, [kind for kind, _ in owner.events].count("preboot-refusal-quit-intent"))
        self.assertIsNone(owner.reboot_effect)

    def test_a_refused_legacy_fixture_finishes_the_owner_with_exit_1(self):
        # The first native gate: the serve is live when the standard user cannot register the HighestAvailable task.
        owner = self.owner("autostart-migration")
        owner.world.fixture_refused = True
        result, finished = self.main(owner, "windows-preboot-reboot")
        self.assertEqual((1, [1]), (result, finished), "a known refusal finishes; it never parks")
        self.assertEqual([], [child.label for child in owner.children if child.terminal is None])
        self.assertEqual(("absent", None), (owner.world.task, owner.world.controller), "nothing is left registered or running")
        self.assertNotIn("product-autostart-start", [child.label for child in owner.children])

    def test_a_known_refusal_after_the_query_gui_started_finishes_with_exit_1(self):
        owner = self.owner("query-first")
        listeners = owner.modules["runtime"].listeners
        owner.modules["runtime"].listeners = lambda who, query, actor: [] if actor["image"].endswith("sing-box.exe") else listeners(who, query, actor)
        result, finished = self.main(owner, "windows-preboot-reboot")
        self.assertEqual((1, [1]), (result, finished), "the transient controller's quit ends the GUI child")
        self.assertEqual([], [child.label for child in owner.children if child.terminal is None])
        self.assertIn("query-first-gui", [child.label for child in owner.children])
        self.assertEqual((None, {}), (owner.world.controller, owner.world.processes))

    def test_a_returned_preboot_finishes_its_owner_through_main(self):
        owner = self.owner("explicit-off")
        result, finished = self.main(owner, "windows-preboot-reboot")
        self.assertEqual((0, [0]), (result, finished))
        self.assertTrue(owner.world.processes, "the app runs on from its own autostart task")


class PostbootActionTests(WorldCase):
    def test_each_postboot_finds_the_logon_start_reconnects_or_stays_off_and_closes_autostart(self):
        for scenario, running in (("reconnect", True), ("explicit-off", False), ("autostart-migration", False)):
            with self.subTest(scenario=scenario):
                owner = self.after_reboot(scenario)
                self.assertEqual(0, postboot.run_postboot(owner, owner.config, source_roles))
                labels = [child.label for child in owner.children]
                self.assertEqual("postboot-startup-native-census", labels[0], "the census precedes every public query")
                self.assertEqual("absent", owner.world.task, "autostart is closed off")
                self.assertFalse(owner.world.processes, "the app was retired by its own quit")
                self.assertEqual(running, "owned-upstream-postboot" in labels)
                join = next(value for kind, value in owner.events if kind == "whole-postboot-startup-observed")["join"]
                self.assertEqual(scenario, join["scenario"])

    def test_a_postboot_at_the_same_boot_time_is_refused_before_any_query(self):
        before = self.owner("explicit-off")
        preboot.run_preboot(before, before.config, source_roles, postboot)
        checkpoint = next(value for kind, value in before.events if kind == "reboot-checkpoint")
        owner = Owner(before.root, "explicit-off", "postboot-final")
        owner.modules, owner.world = fakes(owner), before.world
        record = {"schemaVersion": 1, "operationId": before.operation, "ordinal": 30, "kind": "reboot-checkpoint", "value": checkpoint}
        path = str(before.root / "event-000030-reboot-checkpoint.json")
        owner.by_path[path.casefold()] = Pin(path, json.dumps(record).encode())
        owner.config["checkpointPath"] = path
        owner.pins.append(Pin(owner.request["workspace"], directory=True))
        with self.assertRaisesRegex(ValueError, "same-original-reboot-checkpoint-new-native-owner"):
            postboot.run_postboot(owner, owner.config, source_roles)
        self.assertEqual([], owner.children)

    def test_a_known_refusal_in_the_traffic_window_stops_the_upstream_and_finishes_with_exit_1(self):
        owner = self.after_reboot("reconnect")
        listeners = owner.modules["runtime"].listeners
        # The runtime never listens on the product's port: a known refusal while the owned upstream runs.
        owner.modules["runtime"].listeners = lambda who, query, actor: [] if actor["image"].endswith("sing-box.exe") else listeners(who, query, actor)
        result, finished = self.main(owner, "windows-postboot-final")
        self.assertEqual((1, [1]), (result, finished), "a known refusal finishes; it never parks")
        self.assertEqual([], [child.label for child in owner.children if child.terminal is None])
        self.assertEqual([("terminate", "owned-upstream-postboot")], [entry for entry in owner.world.trace if entry[0] == "terminate"][-1:])


class DeclarationTests(unittest.TestCase):
    def test_product_rows_need_the_whole_tree(self):
        actor = {"pid": 1, "parentPid": 2, "creationFileTime": 3, "image": GUI, "sha256": "a" * 64, "sid": SID, "sessionId": 2}
        rows = autostart.product_rows({role: dict(actor, pid=number) for number, role in enumerate(("guiLauncher", "gui", "controllerLauncher", "controller"), 10)})
        self.assertEqual(4, len(rows))
        with self.assertRaisesRegex(AssertionError, "declared-product-tree-shape"):
            autostart.product_rows({"gui": actor})

    def test_an_omitted_run_level_is_the_limited_default(self):
        owner = types.SimpleNamespace(request={"workspace": r"C:\w", "context": CONTEXT})
        world = World(owner, "reconnect")
        world.task = "limited"
        snapshot = world.snapshot(types.SimpleNamespace(pid=1, birth="1"))
        self.assertNotIn("RunLevel", snapshot["task"]["xml"])
        self.assertEqual("limited", autostart.ownership(snapshot, GUI, r"C:\w", SID))
        world.task = "highest"
        self.assertEqual("highest", autostart.ownership(world.snapshot(types.SimpleNamespace(pid=1, birth="1")), GUI, r"C:\w", SID))

    def test_a_new_boot_is_a_later_boot_time_never_another_boot_identifier(self):
        owner = types.SimpleNamespace(request={"workspace": r"C:\w", "context": CONTEXT})
        world = World(owner, "explicit-off")
        world.task = "limited"
        snapshot = world.snapshot(types.SimpleNamespace(pid=1, birth="1"))
        snapshot["machineGuid"] = "a1b2c3d4-0000-4000-8000-000000000001"
        snapshot["qualifiedOwnership"] = "limited"
        checkpoint = {"kind": "owned-reboot-checkpoint", "machineGuid": snapshot["machineGuid"], "deploymentId": "d", "oldBootFileTimeUtc": BOOT,
                      "oldBootIdentifier": snapshot["bootIdentifier"], "ordinarySid": SID, "workspace": r"C:\w", "task": snapshot["task"],
                      "oldControllerId": "old", "scenario": "explicit-off", "operationId": "op", "guiPath": GUI, "activeLocationName": None, "activeMode": None}
        context = {"machineGuid": snapshot["machineGuid"], "deploymentId": "d", "bootIdentifier": snapshot["bootIdentifier"], "ordinarySid": SID,
                   "ordinarySessionId": 2, "bootFileTimeUtc": str(int(BOOT) + 1)}
        gui = {"sid": SID, "sessionId": 2, "elevated": 0, "creationFileTime": int(BOOT) + 2, "image": GUI}
        status = {"code": "OK", "final": True, "controllerId": "new", "data": {"runtimeRunning": False}}
        joined = autostart.qualify_new_boot(checkpoint, snapshot, {"context": context, "workspace": r"C:\w"}, status, gui, None)
        self.assertEqual(str(int(BOOT) + 1), joined["newBootFileTimeUtc"])
        with self.assertRaisesRegex(AssertionError, "new-native-boot-context-changed-or-pending"):
            autostart.qualify_new_boot(checkpoint, snapshot, {"context": dict(context, bootFileTimeUtc=BOOT), "workspace": r"C:\w"}, status, gui, None)


if __name__ == "__main__":
    unittest.main()
