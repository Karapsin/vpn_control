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
import os
import re
import shutil
import subprocess
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
from agent_tools import windows_scenario_host_job as job
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


# The serve and children 17 to 26 of native operation f56f4a4c (windows-query-owner-gui-reconnect, installed 2.2.17
# built from f31ab987), byte for byte from its evidence: its query owner is its own JVM, the runtime's direct parent.
NATIVE_QUERY_FIRST = Path(__file__).parent / "fixtures/windows_query_owner_native/f56f4a4c-query-first.json"


class Retained(BaseException):
    """The first native step past the recorded census: the oracle retains the runtime it found."""


class RecordedChild:
    def __init__(self, owner, recorded):
        self.owner, self.recorded, self.terminal = owner, recorded, None
        self.ordinal, self.label, self.argv = recorded["child"], recorded["label"], tuple(recorded["argv"])
        self.pid, self.birth = recorded["pid"], recorded["birthFileTimeUtc"]
        self.process = types.SimpleNamespace(poll=lambda: None if self.terminal is None else self.terminal["exitCode"])

    def wait(self):
        self.terminal = {"exitCode": self.recorded["exitCode"], "eof": self.recorded["eof"], "pid": self.pid}
        return self.terminal

    def completed(self):
        self.wait()
        return types.SimpleNamespace(returncode=self.recorded["exitCode"], stdout=self.recorded["stdout"], stderr=self.recorded["stderr"])


class RecordedOwner:
    """Answers each child the case starts with the recorded one of the same argv, in the recorded order."""

    def __init__(self, record):
        self.recorded = {child["child"]: child for child in record["children"]}
        self.order = sorted(number for number in self.recorded if number != 3)
        self.children, self.events, self.reboot_effect = [], [], None
        first = self.recorded[self.order[0]]["argv"]
        self.request = {"cliPath": first[0], "workspace": first[2], "context": {"ordinarySid": SID, "ordinarySessionId": record["ordinarySessionId"]}}

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append((kind, value))

    def park(self, reason, error=None):
        raise Parked(reason)

    def started(self, argv):
        if len(self.children) == len(self.order):
            raise AssertionError(("a child past the recorded evidence", argv))
        recorded = self.recorded[self.order[len(self.children)]]
        if list(argv) != recorded["argv"]:
            raise AssertionError(("not the recorded child", recorded["child"], argv))
        child = RecordedChild(self, recorded)
        self.children.append(child)
        return child

    def invoke(self, workspace, *arguments, timeout=30):
        return self.started([self.request["cliPath"], "--state-dir", str(workspace), *arguments]).completed()

    def child(self, label, argv):
        child = self.started(argv)
        if child.label != label:
            raise AssertionError(("not the recorded label", child.label, label))
        return child


def recorded_roles():
    """The four product generations of the f56f4a4c census (child 26), checked for the facts the trees below keep."""
    record = json.loads(NATIVE_QUERY_FIRST.read_text(encoding="utf-8"))
    census = next(child for child in record["children"] if child["label"] == "query-first-census")
    query = next(child for child in record["children"] if child["argv"][-2:] == ["locations", "list"])
    gui = census["argv"][census["argv"].index("-GuiPath") + 1]
    rows = json.loads(census["stdout"])["rows"]
    pids = {row["pid"] for row in rows}

    def one(found, fact):
        if len(found) != 1:
            raise AssertionError(("the recorded census changed", fact, found))
        return found[0]
    controller = one([row for row in rows if row["argv"][1:2] == ["--headless-controller"]], "one controller")
    launcher = one([row for row in rows if row["image"] == gui and row is not controller and row["parentPid"] not in pids], "one GUI launcher")
    jvm = one([row for row in rows if row["image"] == gui and row["parentPid"] == launcher["pid"]], "one GUI relaunch")
    runtime = one([row for row in rows if row["image"].endswith("sing-box.exe")], "one runtime")
    facts = {"the GUI relaunched once with its own argv": jvm["argv"] == launcher["argv"] and jvm["creationFileTime"] > launcher["creationFileTime"],
             "the controller has no same-image child": not [row for row in rows if row["image"] == gui and row["parentPid"] == controller["pid"]],
             "the runtime is the controller's child": runtime["parentPid"] == controller["pid"] and runtime["creationFileTime"] > controller["creationFileTime"],
             "the controller's parent is no process of the census": controller["parentPid"] not in pids}
    if not all(facts.values()):
        raise AssertionError(("the recorded census changed", facts))
    return {"guiLauncher": launcher, "gui": jvm, "controller": controller, "runtime": runtime, "queryLaunch": int(query["birthFileTimeUtc"])}


def recorded_product_tree(workspace, scheduler, running, relaunch=False, gui_relaunch=True):
    """The autostart product tree, as census rows, built from the recorded census of f56f4a4c.

    Kept from the record: the four pids, the GUI launcher's one relaunch with its own argv (3576 to 1068) and both
    births, a controller (3676) with no same-image child, and the runtime (2528) as that controller's child at its
    recorded birth. Substituted: this test's GUI and workspace paths, the argv the autostart task runs and the
    scheduler's pid as the launcher's parent. Inferred, not recorded: the GUI JVM as the controller's parent, born
    after that JVM by the 1.144 s the query CLI's start took to its controller's birth. In f56f4a4c the controller
    was the query CLI's, whose parent had ended; the GUI starts its own through the same startForCliCommand, but no
    GUI-started controller has been recorded, nor a GUI the autostart task started. relaunch models a same-image
    JVM child under the controller; gui_relaunch=False a GUI launcher that runs its own JVM (no 1068), whose
    controller is then its child.
    """
    recorded = recorded_roles()
    autostart_argv = [GUI, "--autostart", "--state-dir", workspace]
    headless_argv = [GUI, "--headless-controller", "--state-dir", workspace]

    def row(pid, parent, image, argv, born):
        return {"pid": pid, "parentPid": parent, "image": image, "argv": argv, "sessionId": 2, "creationFileTime": born}
    launcher = row(recorded["guiLauncher"]["pid"], scheduler, GUI, autostart_argv, recorded["guiLauncher"]["creationFileTime"])
    gui = row(recorded["gui"]["pid"], launcher["pid"], GUI, autostart_argv, recorded["gui"]["creationFileTime"]) if gui_relaunch else launcher
    controller = row(recorded["controller"]["pid"], gui["pid"], GUI, headless_argv,
                     gui["creationFileTime"] + recorded["controller"]["creationFileTime"] - recorded["queryLaunch"])
    tree = {"guiLauncher": launcher, "gui": gui, "controller": controller} if gui_relaunch else {"gui": gui, "controller": controller}
    if relaunch:
        tree["controllerLauncher"] = controller
        tree["controller"] = row(controller["pid"] + 1, controller["pid"], GUI, headless_argv,
                                 controller["creationFileTime"] + recorded["gui"]["creationFileTime"] - recorded["guiLauncher"]["creationFileTime"])
    if running:
        tree["runtime"] = row(recorded["runtime"]["pid"], tree["controller"]["pid"], str(PureWindowsPath(workspace) / "runtime" / "tools" / "sing-box.exe"),
                              ["sing-box.exe", "run"], recorded["runtime"]["creationFileTime"])
    return tree


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
        self.controller_jvm, self.relaunch_transient, self.censuses = None, False, []
        # relaunch_controller models a GUI-started controller that relaunched anyway, relaunch_gui=False an autostart GUI
        # that did not; controller_linger is how long, in the world clock's seconds, the controller still runs after
        # the GUI that acknowledged the quit has ended.
        self.relaunch_controller, self.relaunch_gui = False, True
        self.controller_linger, self.controller_pids, self.exiting = 0.0, set(), {}
        self.clock = None
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

    def spawn(self, image, argv, parent, pid=None, born=None):
        self.next_pid += 1
        pid = self.next_pid if pid is None else pid
        born = int(self.owner.request["context"]["bootFileTimeUtc"]) + 1000 + self.next_pid if born is None else born
        self.processes[pid] = {"pid": pid, "parentPid": parent, "image": image, "argv": argv, "sessionId": 2, "creationFileTime": born}
        return pid

    def settle(self):
        """A lingering controller ends once the world's clock passes its time."""
        now = self.clock.monotonic() if self.clock is not None else 0
        for pid, at in list(self.exiting.items()):
            if now >= at:
                self.processes.pop(pid, None)
                del self.exiting[pid]

    def start_product(self, parent):
        """The product's own start through its autostart task: the recorded tree of f56f4a4c (recorded_product_tree)."""
        workspace = self.owner.request["workspace"]
        self.last_run = int(self.owner.request["context"]["bootFileTimeUtc"]) + 500
        tree = recorded_product_tree(workspace, parent, self.intent, relaunch=self.relaunch_controller, gui_relaunch=self.relaunch_gui)
        for row in tree.values():
            self.processes[row["pid"]] = dict(row)
        controller = tree["controller"]["pid"]
        self.controller_pids = {controller, tree.get("controllerLauncher", tree["controller"])["pid"]}
        # Each boot reuses the recorded pids; a controller ID is fresh per owner, as the product's random UUID is.
        self.controller, self.running, self.controller_jvm = "controller-" + str(uuid.uuid4()), self.intent, controller
        (Path(workspace) / "activation.port").write_text("{}")
        self.owner.native.ports[controller] = 41000

    def start_transient(self, cli):
        """DesktopCli with no owner starts a headless controller for any operation but status, quit, gui hide.

        The native census of f56f4a4c recorded the controller with no same-image child, a parent PID that is no
        longer a process, and the runtime as its direct child. This models why: the CLI launcher relaunches into
        its JVM, which starts the controller with PATH already holding <image>\\app, so jpackage does not relaunch
        the controller, and that JVM ends with the query. relaunch_transient models a controller launcher that
        relaunched anyway."""
        workspace = self.owner.request["workspace"]
        argv = [GUI, "--headless-controller", "--state-dir", workspace]
        cli_jvm = self.spawn(CLI, list(cli.argv), cli.pid)
        launcher = self.spawn(GUI, argv, cli_jvm)
        self.controller_jvm = self.spawn(GUI, argv, launcher) if self.relaunch_transient else launcher
        self.controller_pids = {launcher, self.controller_jvm}
        del self.processes[cli_jvm]
        self.controller, self.running = "transient-" + str(self.controller_jvm), False  # A transient owner never resumes.
        (Path(workspace) / "activation.port").write_text("{}")

    def start_gui(self, child):
        """The GUI joins the workspace's owner and restores the remembered intent once.

        Its launcher is the owner's own child (3576 under the owner in f56f4a4c) and relaunches once."""
        launcher = self.spawn(GUI, list(child.argv), 41, pid=child.pid)
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
            # Native 5594b6f5: the ordinary token may not register a HighestAvailable task. Only the SYSTEM run plants it.
            raise AssertionError("the ordinary owner never runs the legacy planter")
        if script.endswith("startScript.data"):
            self.start_product(40)
            return child.end(0, json.dumps({"schemaVersion": 1, "taskPath": autostart.TASK, "instanceGuid": "{instance}"}))
        if script.endswith("startupCollector.data"):
            self.settle()
            rows = [dict(row) for row in self.processes.values()]
            self.censuses.append((child.label, rows))
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
        # The owner releases its own exit once the GUI acknowledged the quit (DesktopOwnerExitGate.releaseQuit), so the
        # GUI ends first and the controller may still run for controller_linger seconds of the world's clock.
        lingering = {pid for pid in self.controller_pids if pid in self.processes} if self.controller_linger else set()
        for pid in [pid for pid in self.processes if pid not in lingering]:
            del self.processes[pid]
        now = self.clock.monotonic() if self.clock is not None else 0
        self.exiting.update({pid: now + self.controller_linger for pid in lingering})

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
                world.settle()
                row = world.processes.get(pid)
                if row is None:
                    raise AssertionError("absent process")
                image = b"bundled sing-box.exe" if row["image"].endswith("sing-box.exe") else b"declared"
                return {"image": row["image"], "creationFileTime": row["creationFileTime"], "sha256": hashlib.sha256(image).hexdigest(),
                        "token": {"sid": SID, "sessionId": 2, "elevated": 0}}

            def wait(self):
                world.settle()
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
        if phase == "preboot-reboot" and scenario in autostart.SCENARIOS:
            # The SYSTEM run planted the legacy task for this ordinary user before the owner started.
            self.world.task = "highest"
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
        clock = self.clock = Clock()
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
        owner.world.clock = self.clock
        return owner

    def after_reboot(self, scenario, **shape):
        """A passed preboot, then readiness-reboot and the sign-in: the logon trigger runs the same task once.

        shape sets the world's product shape (relaunch_gui, relaunch_controller) for both boots."""
        before = self.owner(scenario)
        for key, value in shape.items():
            setattr(before.world, key, value)
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
                # The recorded shape: the GUI-started controller is its own JVM, so no controllerLauncher row.
                self.assertEqual(["guiLauncher", "gui", "controller", *(["runtime"] if running else [])],
                                 [row["role"] for row in rows])
                self.assertEqual(40, rows[0]["parentPid"], "the root was started by the task scheduler")
                self.assertEqual([RUNTIME] if running else [], [row["sha256"] for row in rows if row["role"] == "runtime"],
                                 "the runtime is declared by the installed record's digest")
                self.assertEqual("Owned Reboot" if running else None, checkpoint[0]["activeLocationName"])
                labels = [child.label for child in owner.children]
                self.assertNotIn("autostart-highest-fixture", labels, "the owner never plants; the SYSTEM run did")
                self.assertLess(labels.index("autostart-read-only"), labels.index("product-autostart-start"))
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

    def test_a_missing_legacy_fixture_finishes_the_owner_with_exit_1_before_any_autostart_change(self):
        # Native 5594b6f5: the toggle off ran, then the planting failed, so the receipt said changed and held the clone.
        # The legacy task is now the SYSTEM run's, before this owner; without it the owner refuses before any public toggle.
        for scenario in sorted(autostart.SCENARIOS):
            with self.subTest(scenario=scenario):
                owner = self.owner(scenario)
                owner.world.task = "absent"
                result, finished = self.main(owner, "windows-preboot-reboot")
                self.assertEqual((1, [1]), (result, finished), "a known refusal finishes; it never parks")
                self.assertEqual([], [child.label for child in owner.children if child.terminal is None])
                self.assertEqual(("absent", None), (owner.world.task, owner.world.controller), "nothing is left registered or running")
                self.assertNotIn("product-autostart-start", [child.label for child in owner.children])
                calls = [" ".join(tail) for label, tail in owner.world.trace if label == "public-cli"]
                self.assertEqual([], [call for call in calls if "autostart" in call], "no public autostart toggle ran")
                self.assertEqual([], [kind for kind, _ in owner.events if kind in job.AUTOSTART_INTENTS],
                                 "the journal holds no autostart intent, so the receipt says untouched and holds no clone")

    def test_the_planted_legacy_task_is_observed_before_any_public_autostart_toggle(self):
        for scenario in sorted(autostart.SCENARIOS):
            with self.subTest(scenario=scenario):
                owner = self.owner(scenario)
                self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
                kinds = [kind for kind, _ in owner.events]
                observed = kinds.index("autostart-legacy-fixture-observed")
                self.assertLess(observed, kinds.index("autostart-public-toggle-intent"))
                self.assertEqual("highest", owner.events[observed][1]["before"]["qualifiedOwnership"])
                toggles = [value["enabled"] for kind, value in owner.events if kind == "autostart-public-toggle-intent"]
                self.assertEqual([True], toggles, "the one public toggle is the migration itself")
                self.assertEqual("limited", owner.world.task)

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


class QueryControllerCensusTests(WorldCase):
    """The query-started controller of windows-query-owner-gui-reconnect, as the native census of f56f4a4c shows it.

    On f31ab987 the case wanted a launcher with one JVM child of the same image under it, and raised
    one-query-controller-jvm: the recorded controller has none, and sing-box is its direct child. The
    product's launch path explains it: the query CLI's JVM starts the controller with PATH already
    holding <image>\\app, so jpackage does not relaunch it.
    """

    def query_census(self, owner):
        return next(rows for label, rows in owner.world.censuses if label == "query-first-census")

    def test_the_recorded_native_census_reaches_the_runtime_of_a_controller_that_is_its_own_jvm(self):
        record = json.loads(NATIVE_QUERY_FIRST.read_text(encoding="utf-8"))
        # The module that ran is f31ab987's windows_postboot_action.py; each stream is the recorded one, byte for byte.
        self.assertEqual(("f56f4a4c-3846-46b2-96d2-87a94db0982a", {"exitCode": 1, "errorClass": "ValueError"},
                          "8eb8d4d694dd5b4b62fa86410ddb5e5810542be7a9753d1ac3a55b6ffa9f8771"),
                         (record["operation"], record["ownerTerminal"], record["ranPostbootAction"]["sha256"]))
        for child in record["children"]:
            self.assertEqual(child["sha256"], {name: hashlib.sha256(child[name].encode()).hexdigest() for name in ("stdout", "stderr")})
        owner = RecordedOwner(record)
        census = next(child for child in record["children"] if child["label"] == "query-first-census")
        argv = census["argv"]
        gui = argv[argv.index("-GuiPath") + 1]
        lease = types.SimpleNamespace(paths={"powerShell": argv[0], "startupCollector": argv[6], "gui": gui}, runtime_sha256=lambda: RUNTIME)
        serve = RecordedChild(owner, owner.recorded[3])
        identity = json.loads(owner.recorded[18]["stdout"])["controllerId"]
        state = {"workspace": Path(owner.request["workspace"]), "identity": identity, "serve": serve, "live": (serve, identity)}
        retained = []

        def actor(who, native, expected, role):
            retained.append((dict(expected), role))
            raise Retained()
        with mock.patch.object(postboot, "Actor", actor):
            try:
                postboot.query_then_gui(owner, lease, source_roles, None, None, None, types.SimpleNamespace(WindowsNative=lambda: None), state)
            except ValueError as refusal:
                self.fail("the case refused the recorded native census: " + str(refusal))
            except Retained:
                pass
        self.assertEqual(list(range(17, 27)), [child.ordinal for child in owner.children], "every recorded child, in order, and no other")
        rows = json.loads(census["stdout"])["rows"]
        controller = next(row for row in rows if row["argv"][1:2] == ["--headless-controller"])
        self.assertEqual([], [row for row in rows if row["parentPid"] == controller["pid"] and row["image"] == gui], "no relaunched JVM")
        self.assertNotIn(controller["parentPid"], [row["pid"] for row in rows], "its parent PID is no process of the census")
        runtime = next(row for row in rows if row["image"].endswith("sing-box.exe"))
        self.assertEqual(controller["pid"], runtime["parentPid"])
        workspace = owner.request["workspace"]
        self.assertEqual([({"pid": runtime["pid"], "creationFileTime": runtime["creationFileTime"],
                            "image": str(PureWindowsPath(workspace) / "runtime" / "tools" / "sing-box.exe"), "sha256": RUNTIME,
                            "sid": SID, "sessionId": 2}, "runtime")], retained)
        self.assertIsNone(owner.reboot_effect)

    def test_the_query_row_closes_known_where_the_controller_is_its_own_jvm(self):
        owner = self.owner("query-first")
        self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
        rows = self.query_census(owner)
        controllers = [row for row in rows if row["argv"][1:2] == ["--headless-controller"]]
        self.assertEqual(1, len(controllers), "the native shape: one controller row and no relaunched JVM")
        self.assertNotIn(controllers[0]["parentPid"], [row["pid"] for row in rows])
        traffic = next(value for kind, value in owner.events if kind == "postboot-query-first-traffic-observed")
        runtime = next(row for row in rows if row["pid"] == traffic["runtimeActor"]["pid"])
        self.assertEqual(controllers[0]["pid"], runtime["parentPid"], "the runtime the controller started itself")
        self.assertTrue(all(child.terminal is not None for child in owner.children), "the owner can finish")

    def test_a_controller_launcher_that_relaunched_is_still_followed_to_its_jvm(self):
        owner = self.owner("query-first")
        owner.world.relaunch_transient = True
        self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
        rows = self.query_census(owner)
        traffic = next(value for kind, value in owner.events if kind == "postboot-query-first-traffic-observed")
        runtime = next(row for row in rows if row["pid"] == traffic["runtimeActor"]["pid"])
        jvm = next(row for row in rows if row["pid"] == runtime["parentPid"])
        launcher = next(row for row in rows if row["pid"] == jvm["parentPid"])
        self.assertEqual((GUI, GUI, launcher["argv"]), (jvm["image"], launcher["image"], jvm["argv"]))

    def test_a_second_relaunch_or_a_runtime_born_before_its_claimed_parent_is_never_taken(self):
        def second_relaunch(world):
            launcher = world.processes[world.controller_jvm]["parentPid"]
            world.spawn(GUI, list(world.processes[launcher]["argv"]), launcher)

        def stale_runtime(world):
            controller = world.processes[world.controller_jvm]
            runtime = next(row for row in world.processes.values() if row["image"].endswith("sing-box.exe"))
            runtime["creationFileTime"] = controller["creationFileTime"] - 1  # Its real parent had the same PID earlier.
        for change, relaunch, code in ((second_relaunch, True, "one-query-controller-jvm"), (stale_runtime, False, "one-reconnected-runtime")):
            with self.subTest(code=code):
                owner = self.owner("query-first")
                owner.world.relaunch_transient = relaunch
                start_gui = owner.world.start_gui

                def changed_start(child, world=owner.world, start_gui=start_gui, change=change):
                    start_gui(child)
                    change(world)
                owner.world.start_gui = changed_start
                with self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    preboot.run_preboot(owner, owner.config, source_roles, postboot)
                self.assertEqual([], [child.label for child in owner.children if child.terminal is None], "a known refusal retires the GUI")
                self.assertNotIn("postboot-query-first-traffic-observed", [kind for kind, _ in owner.events])

    def test_the_closing_census_follows_a_controller_that_ends_after_the_gui(self):
        # The owner releases its exit only once the GUI acknowledged the quit, and polls for it at most every second
        # (DesktopOwnerExitGate.releaseQuit, HeadlessLifecycle.awaitExit): the GUI child ends while the controller runs.
        owner = self.owner("query-first")
        owner.world.controller_linger = 1.5
        self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
        kinds = [kind for kind, _ in owner.events]
        self.assertIn("query-first-controller-exit-observed", kinds)
        self.assertNotIn("query-first-product-exit-timeout", kinds)
        closing = next(rows for label, rows in owner.world.censuses if label == "query-first-closing-census")
        self.assertEqual([], closing, "the closing census ran once every product generation had ended")
        self.assertEqual({}, owner.world.exiting, "the controller had still been running after the GUI child ended")

    def test_a_product_generation_past_the_bound_is_a_known_failure_never_a_park(self):
        owner = self.owner("query-first")
        owner.world.controller_linger = 3600.0  # Still running at the bound.
        result, finished = self.main(owner, "windows-preboot-reboot")
        self.assertEqual((1, [1]), (result, finished), "a known failure finishes; it never parks")
        timeouts = [value for kind, value in owner.events if kind == "query-first-product-exit-timeout"]
        self.assertEqual(["controller"], [value["role"] for value in timeouts], "the generation still running is named")
        self.assertEqual(owner.world.controller_jvm, timeouts[0]["actor"]["pid"])
        self.assertNotIn("query-first-closing-census", [child.label for child in owner.children], "no census after a refusal")
        self.assertEqual([], [child.label for child in owner.children if child.terminal is None])


class TreeHelpers:
    """A product tree checked outside the world, and the host job's own check of its declaration."""
    WORKSPACE = r"C:\Users\recovery\AppData\Local\VpnControlOrdinary-00000000-0000-4000-8000-000000000000\workspace"

    def tree_owner(self):
        context = dict(CONTEXT, bootFileTimeUtc=BOOT)
        owner = types.SimpleNamespace(request={"workspace": self.WORKSPACE, "context": context})
        lease = types.SimpleNamespace(paths={"gui": GUI}, pins={"gui": Pin(GUI)}, runtime_sha256=lambda: RUNTIME)
        return owner, lease

    def declare(self, declared, scenario):
        """The host job's own check of a preboot checkpoint, before any SYSTEM file declares it."""
        op = "00000000-0000-4000-8000-000000000000"
        checkpoint = {"operationId": op, "scenario": scenario, "deploymentId": CONTEXT["deploymentId"], "ordinarySid": SID,
                      "oldSessionId": 2, "oldBootFileTimeUtc": BOOT, "workspace": self.WORKSPACE, "declaredProduct": declared}
        events = [("event-000000-owner-started.json", {"kind": "owner-started", "operationId": op, "value": {"pid": 4408}}),
                  ("event-000001-child-started.json", {"kind": "child-started", "operationId": op, "value": {"pid": 7684}}),
                  ("event-000002-reboot-checkpoint.json", {"kind": "reboot-checkpoint", "operationId": op, "value": checkpoint})]
        paths = {"productWorkspace": self.WORKSPACE, "gui": GUI}
        return job.product_declaration(op, CONTEXT["deploymentId"], dict(CONTEXT, bootFileTimeUtc=BOOT), paths,
                                       {"gui": Pin(GUI).record["sha256"], "runtime": RUNTIME}, events, scenario)

    def declared_rows(self, tree):
        return [{"role": role, "pid": row["pid"], "parentPid": row["parentPid"], "creationFileTime": str(row["creationFileTime"]),
                 "image": row["image"], "sha256": RUNTIME if role == "runtime" else Pin(GUI).record["sha256"], "sid": SID, "sessionId": 2}
                for role, row in sorted(tree.items(), key=lambda item: job.DECLARED_ROLES.index(item[0]))]


class RebootTreeTests(TreeHelpers, WorldCase):
    """The reboot rows' autostart tree over the recorded census shape of f56f4a4c (recorded_product_tree).

    On 529cc610 product_tree wanted a controller launcher with one JVM child, so a controller that is its own JVM
    was refused as one-controller-jvm-child, which the preboot retries and then parks on after 120 s, and the host
    job refused any declaration without a controllerLauncher row. The GUI-started controller's own shape at a
    reboot is inferred from that census, not recorded.
    """

    def test_a_preboot_over_the_recorded_shape_declares_its_own_jvm_controller_and_never_parks(self):
        recorded = recorded_roles()
        for scenario, running in (("reconnect", True), ("explicit-off", False), ("autostart-migration", False)):
            with self.subTest(scenario=scenario):
                owner = self.owner(scenario)
                try:
                    self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
                except Parked as parked:
                    self.fail("the preboot parked over the recorded shape: " + str(parked))
                rows = next(value for kind, value in owner.events if kind == "reboot-checkpoint")["declaredProduct"]
                roles = {row["role"]: row for row in rows}
                self.assertEqual([recorded["guiLauncher"]["pid"], recorded["gui"]["pid"], recorded["controller"]["pid"],
                                  *([recorded["runtime"]["pid"]] if running else [])], [row["pid"] for row in rows])
                self.assertNotIn("controllerLauncher", roles)
                self.assertEqual(roles["gui"]["pid"], roles["controller"]["parentPid"])
                if running:
                    self.assertEqual(roles["controller"]["pid"], roles["runtime"]["parentPid"])

    def test_a_postboot_over_the_recorded_shape_retires_its_own_jvm_controller(self):
        for scenario, running in (("reconnect", True), ("explicit-off", False)):
            with self.subTest(scenario=scenario):
                try:
                    owner = self.after_reboot(scenario)
                    self.assertEqual(0, postboot.run_postboot(owner, owner.config, source_roles))
                except Parked as parked:
                    self.fail("parked over the recorded shape: " + str(parked))
                kinds = [kind for kind, _ in owner.events]
                self.assertEqual(["postboot-startup-gui-exit-observed", "postboot-startup-guiLauncher-exit-observed",
                                  "postboot-startup-controller-exit-observed"], [kind for kind in kinds if kind.endswith("-exit-observed")
                                                                                    and kind.startswith("postboot-startup-") and "runtime" not in kind])
                self.assertFalse(owner.world.processes)

    def test_the_recorded_tree_is_declared_and_the_host_job_allows_it(self):
        for running, scenario in ((True, "reconnect"), (False, "explicit-off")):
            with self.subTest(scenario=scenario):
                owner, lease = self.tree_owner()
                tree = recorded_product_tree(self.WORKSPACE, 40, running)
                actors = postboot.product_tree(owner, lease, list(tree.values()), running)
                self.assertEqual({role: row["pid"] for role, row in tree.items()}, {role: actor["pid"] for role, actor in actors.items()})
                declared = autostart.product_rows(actors)
                declaration, _ = self.declare(declared, scenario)
                self.assertEqual([row["pid"] for row in declared], [row["pid"] for row in declaration["processes"]])

    def test_the_host_job_allows_a_declared_controller_that_is_its_own_jvm(self):
        for running, scenario in ((True, "reconnect"), (False, "explicit-off")):
            with self.subTest(scenario=scenario):
                declared = self.declared_rows(recorded_product_tree(self.WORKSPACE, 40, running))
                declaration, _ = self.declare(declared, scenario)
                self.assertEqual(3 + running, len(declaration["processes"]))

    def test_a_relaunched_controller_is_still_taken_with_its_launcher_row(self):
        owner, lease = self.tree_owner()
        tree = recorded_product_tree(self.WORKSPACE, 40, True, relaunch=True)
        actors = postboot.product_tree(owner, lease, list(tree.values()), True)
        declared = autostart.product_rows(actors)
        self.assertEqual(list(job.DECLARED_ROLES), [row["role"] for row in declared])
        self.declare(declared, "reconnect")

    def test_a_second_relaunch_or_a_child_born_before_its_claimed_parent_is_never_taken(self):
        def second_relaunch(tree):
            extra = dict(tree["controller"], pid=tree["controller"]["pid"] + 1, creationFileTime=tree["controller"]["creationFileTime"] + 2)
            return {**tree, "extra": extra, "controller": dict(tree["controller"], parentPid=tree["controllerLauncher"]["pid"])}

        def stale_runtime(tree):
            return {**tree, "runtime": dict(tree["runtime"], creationFileTime=tree["controller"]["creationFileTime"] - 1)}

        def recorded_controller_birth(tree):
            # 3676 at its recorded birth predates the GUI JVM it would be the child of: no GUI started that controller.
            return {**tree, "controller": dict(tree["controller"], creationFileTime=recorded_roles()["controller"]["creationFileTime"])}
        cases = ((second_relaunch, True, "one-controller-jvm-child"), (stale_runtime, False, "reconnect-or-off-native-runtime-census"),
                 (recorded_controller_birth, False, "one-gui-started-controller-launcher"))
        for change, relaunch, code in cases:
            with self.subTest(code=code):
                owner, lease = self.tree_owner()
                rows = list(change(recorded_product_tree(self.WORKSPACE, 40, True, relaunch=relaunch)).values())
                with self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    postboot.product_tree(owner, lease, rows, True)

    def test_the_host_job_refuses_a_declared_tree_out_of_shape(self):
        def without(role):
            return lambda rows: [row for row in rows if row["role"] != role]

        def parent(role, value):
            return lambda rows: [dict(row, parentPid=value(rows)) if row["role"] == role else row for row in rows]
        pid = lambda role: lambda rows: next(row["pid"] for row in rows if row["role"] == role)
        cases = {"no-runtime-on-reconnect": (without("runtime"), "declaration_tree"),
                 "no-controller": (without("controller"), "declaration_tree"),
                 "out-of-order": (lambda rows: [rows[1], rows[0], *rows[2:]], "declaration_tree"),
                 "controller-not-under-the-gui": (parent("controller", pid("guiLauncher")), "declaration_parentage"),
                 "controller-born-before-the-gui": (lambda rows: [dict(row, creationFileTime=str(recorded_roles()["controller"]["creationFileTime"]))
                                                                  if row["role"] == "controller" else row for row in rows], "declaration_parentage")}
        for name, (change, code) in cases.items():
            with self.subTest(case=name):
                declared = change(self.declared_rows(recorded_product_tree(self.WORKSPACE, 40, True)))
                with self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    self.declare(declared, "reconnect")


class AutostartGuiShapeTests(TreeHelpers, WorldCase):
    """The GUI the autostart task starts, which relaunches when its PATH lacks <image>\\app or else runs its own JVM.

    Recorded in f56f4a4c: an owner-started GUI that relaunched (3576 to 1068). The GUI the task starts has not
    been recorded. On 5b5bca8e product_tree took a GUI launcher's one same-image child as its JVM, so a GUI that
    ran its own JVM had its controller taken as that JVM and was refused (one-gui-started-controller-launcher, which
    the preboot retries and then parks on), and the host job refused any declaration without a guiLauncher row.
    """

    def test_a_preboot_over_a_gui_that_is_its_own_jvm_declares_it_as_the_root_and_never_parks(self):
        recorded = recorded_roles()
        for scenario, running in (("reconnect", True), ("explicit-off", False), ("autostart-migration", False)):
            with self.subTest(scenario=scenario):
                owner = self.owner(scenario)
                owner.world.relaunch_gui = False
                try:
                    self.assertEqual(0, preboot.run_preboot(owner, owner.config, source_roles, postboot))
                except Parked as parked:
                    self.fail("the preboot parked over a GUI that is its own JVM: " + str(parked))
                rows = next(value for kind, value in owner.events if kind == "reboot-checkpoint")["declaredProduct"]
                self.assertEqual(["gui", "controller", *(["runtime"] if running else [])], [row["role"] for row in rows])
                roles = {row["role"]: row for row in rows}
                self.assertEqual((recorded["guiLauncher"]["pid"], 40), (roles["gui"]["pid"], roles["gui"]["parentPid"]), "the GUI is the root")
                self.assertEqual(roles["gui"]["pid"], roles["controller"]["parentPid"])

    def test_a_postboot_over_a_gui_that_is_its_own_jvm_retires_it(self):
        for scenario in ("reconnect", "explicit-off"):
            with self.subTest(scenario=scenario):
                try:
                    owner = self.after_reboot(scenario, relaunch_gui=False)
                    self.assertEqual(0, postboot.run_postboot(owner, owner.config, source_roles))
                except Parked as parked:
                    self.fail("parked over a GUI that is its own JVM: " + str(parked))
                exits = [kind for kind, _ in owner.events if kind.startswith("postboot-startup-") and kind.endswith("-exit-observed")
                         and "runtime" not in kind]
                self.assertEqual(["postboot-startup-gui-exit-observed", "postboot-startup-controller-exit-observed"], exits)
                self.assertFalse(owner.world.processes)

    def test_every_gui_and_controller_shape_is_declared_with_its_row_count(self):
        # gui and controller always, a launcher row for each that relaunched, runtime for reconnect:
        # reconnect 3 to 5 rows, explicit-off (and autostart-migration) 2 to 4.
        for gui_relaunch in (True, False):
            for relaunch in (False, True):
                for running, scenario in ((True, "reconnect"), (False, "explicit-off")):
                    with self.subTest(gui_relaunch=gui_relaunch, controller_relaunch=relaunch, scenario=scenario):
                        owner, lease = self.tree_owner()
                        tree = recorded_product_tree(self.WORKSPACE, 40, running, relaunch=relaunch, gui_relaunch=gui_relaunch)
                        actors = postboot.product_tree(owner, lease, list(tree.values()), running)
                        self.assertEqual({role: row["pid"] for role, row in tree.items()}, {role: actor["pid"] for role, actor in actors.items()})
                        declared = autostart.product_rows(actors)
                        declaration, _ = self.declare(declared, scenario)
                        self.assertEqual(2 + gui_relaunch + relaunch + running, len(declaration["processes"]))

    def test_a_second_gui_relaunch_or_a_gui_child_born_before_its_parent_is_never_taken(self):
        def second_gui_relaunch(tree):
            return {**tree, "extra": dict(tree["gui"], pid=tree["gui"]["pid"] + 1, creationFileTime=tree["gui"]["creationFileTime"] + 1)}

        def stale_gui_relaunch(tree):
            # Its claimed parent, the GUI launcher, was born after it: never its relaunch, so the launcher is its own JVM
            # and the controller under the stale row is no child of it.
            return {**tree, "gui": dict(tree["gui"], creationFileTime=tree["guiLauncher"]["creationFileTime"] - 1)}

        def controller_born_before_its_gui(tree):
            return {**tree, "controller": dict(tree["controller"], creationFileTime=tree["gui"]["creationFileTime"] - 1)}
        cases = ((second_gui_relaunch, True, "one-gui-jvm-child"), (stale_gui_relaunch, True, "one-gui-started-controller-launcher"),
                 (controller_born_before_its_gui, False, "one-gui-started-controller-launcher"))
        for change, gui_relaunch, code in cases:
            with self.subTest(case=change.__name__):
                owner, lease = self.tree_owner()
                rows = list(change(recorded_product_tree(self.WORKSPACE, 40, True, gui_relaunch=gui_relaunch)).values())
                with self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    postboot.product_tree(owner, lease, rows, True)

    def test_the_host_job_refuses_a_gui_root_out_of_shape(self):
        own = lambda: self.declared_rows(recorded_product_tree(self.WORKSPACE, 40, True, gui_relaunch=False))
        relaunched = lambda: self.declared_rows(recorded_product_tree(self.WORKSPACE, 40, True))
        runtime_pid = lambda rows: next(row["pid"] for row in rows if row["role"] == "runtime")
        cases = {"no-gui": (own, lambda rows: [row for row in rows if row["role"] != "gui"], "declaration_tree"),
                 "root-under-a-declared-process": (own, lambda rows: [dict(row, parentPid=runtime_pid(rows)) if row["role"] == "gui" else row
                                                                       for row in rows], "declaration_parentage"),
                 "gui-not-under-its-launcher": (relaunched, lambda rows: [dict(row, parentPid=40) if row["role"] == "gui" else row
                                                                         for row in rows], "declaration_parentage")}
        for name, (rows, change, code) in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(ValueError, "^" + code + "$"):
                    self.declare(change(rows()), "reconnect")


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


ROOT = Path(__file__).resolve().parents[2]
ABSENT = Path(__file__).parent / "fixtures/windows_autostart_absent_task"
AUTOSTART_SCRIPTS = ("agent_tools/windows_autostart_snapshot.ps1", "agent_tools/windows_autostart_create_highest_fixture.ps1",
                     "agent_tools/windows_autostart_task_start.ps1")
# The two scripts that must tell an absent task from a failed lookup; the start script needs the task and fails without it.
ABSENCE_SCRIPTS = AUTOSTART_SCRIPTS[:2]
POWERSHELL = os.environ.get("VPN_CONTROL_TEST_PWSH") or shutil.which("pwsh") or shutil.which("powershell")
# Task Scheduler's lookup, faked: each mode throws what a host has been seen, or may be expected, to throw.
LOOKUP_FAKE = r'''
using System;using System.IO;using System.Runtime.InteropServices;
public sealed class AbsentFakeFolder {public string Mode,Message;public int Calls;
 public object GetTask(string name){Calls++;if(name!="VPN Control")throw new ArgumentException(name);
  if(Mode=="recorded")throw new FileNotFoundException(Message);
  if(Mode=="com-not-found")throw new COMException("fake scheduler",-2147024894);
  if(Mode=="com-denied")throw new COMException("fake scheduler",-2147024891);
  if(Mode=="unauthorized")throw Marshal.GetExceptionForHR(-2147024891);
  if(Mode=="other")throw new InvalidOperationException("fake scheduler");
  return "present-task";}}
'''


def powershell_function(text, name):
    """One top-level function of a script, from its header to its own closing brace at column 0."""
    lines = text.split("\n")
    starts = [index for index, line in enumerate(lines) if re.match("function " + re.escape(name) + r"\(", line)]
    if len(starts) != 1:
        raise ValueError("function_not_one:" + name)
    end = lines.index("}", starts[0])
    return "\n".join(lines[starts[0]:end + 1]) + "\n"


class StartupTaskAbsenceTests(unittest.TestCase):
    """Every reboot .pre on 2.2.19 failed before its reboot: the snapshot's absent-task catch named COMException, but
    native Windows PowerShell raised the missing task as FileNotFoundException, so a machine without the task (every
    fresh install) exited 1 instead of reporting the task absent. Only HRESULT 0x80070002 proves absence."""

    def setUp(self):
        self.record = json.loads((ABSENT / "native-snapshot-children.json").read_text())

    def native_stderr(self, operation):
        run = self.record["runs"][operation]
        raw = base64.b64decode(run["stderrBase64"])
        self.assertEqual(run["stderrSha256"], hashlib.sha256(raw).hexdigest())
        return raw.decode("utf-8")

    def test_the_recorded_native_children_are_the_snapshot_lookup_raising_file_not_found(self):
        before = (ABSENT / self.record["beforeSource"]["path"]).read_bytes()
        self.assertEqual(self.record["beforeSource"]["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(3, len(self.record["runs"]))
        for operation, run in self.record["runs"].items():
            stderr = self.native_stderr(operation)
            self.assertEqual(("autostart-read-only", 1), (run["label"], run["exitCode"]))
            self.assertIn("(Exception from HRESULT: 0x80070002)", stderr)
            self.assertIn("windows_autostart_snapshot.ps1:39 char:3", stderr)
            self.assertIn("FullyQualifiedErrorId : System.IO.FileNotFoundException", stderr)
            self.assertEqual("  $task = $folder.GetTask('VPN Control')", before.decode().split("\n")[38])

    def test_no_autostart_script_catches_a_task_lookup_by_exception_type(self):
        for relative in AUTOSTART_SCRIPTS:
            with self.subTest(script=relative):
                text = (ROOT / relative).read_text()
                self.assertEqual([], re.findall(r"catch\s*\[[^\]]*\]", text), "a typed catch misses the type the native host raises")
                lookups = [line.strip() for line in text.split("\n") if ".GetTask(" in line]
                if relative in ABSENCE_SCRIPTS:
                    self.assertEqual(["try { return $folder.GetTask('VPN Control') } catch { if (-not (Test-TaskAbsent $_)) { throw } }"],
                                     lookups, "the one lookup that may prove absence")
                    self.assertEqual(1, len(re.findall(r"\bcatch\b", text)), "no other catch can turn a failure into absence")
                else:
                    self.assertEqual(0, len(re.findall(r"\bcatch\b", text)), "the start script needs the task; its absence fails")

    def test_both_absence_scripts_hold_one_predicate_matching_only_the_not_found_hresult(self):
        texts = [(ROOT / relative).read_text() for relative in ABSENCE_SCRIPTS]
        for name in ("Test-TaskAbsent", "Get-StartupTask"):
            self.assertEqual(*(powershell_function(text, name) for text in texts))
        predicate = powershell_function(texts[0], "Test-TaskAbsent")
        self.assertEqual(["-2147024894"], re.findall(r"-?\b\d{6,}\b", predicate))
        self.assertIn("$x = $x.InnerException", predicate)
        # The publisher's own Is-TaskAbsent is the same chain walk over the same single HRESULT.
        publisher = (ROOT / "agent_tools/windows_scenario_publisher.ps1.template").read_text()
        walk = " while ($null -ne $x) { if ($x.HResult -eq -2147024894) { return $true }; $x = $x.InnerException }"
        self.assertIn(walk, predicate.split("\n"))
        self.assertIn(walk.replace(" ", ""), publisher.replace(" ", ""))

    def test_the_owner_role_pins_name_the_current_reboot_sources(self):
        from agent_tools import native_scenario_windows as scenario
        from agent_tools import windows_ordinary_task as task
        for relative, role, _ in scenario._REBOOT_FILES:
            if role in task.POSTBOOT_ROLE_HASHES:
                with self.subTest(role=role):
                    self.assertEqual(task.POSTBOOT_ROLE_HASHES[role], hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(),
                                     "the native owner refuses a role whose bytes are not its pin")

    def run_powershell(self, functions, body):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "absent.ps1"
            fake = "Add-Type -TypeDefinition @'\n" + LOOKUP_FAKE + "\n'@\n"
            script.write_text("$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n" + fake + functions + body,
                              encoding="utf-8")
            result = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                    capture_output=True, text=True, timeout=120,
                                    env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT="1"))
        self.assertEqual((0, ""), (result.returncode, result.stderr), result.stdout)
        return json.loads(result.stdout)

    def message(self):
        stderr = self.native_stderr("7d71a92f-4d7a-4e01-a360-d4bac9771457")
        return stderr.split("\r\n")[0]

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_only_a_not_found_lookup_is_absence_under_powershell(self):
        modes = ("recorded", "com-not-found", "com-denied", "unauthorized", "other", "present")
        body = r'''
$out = [ordered]@{}
foreach ($mode in @(MODES)) {
 $folder = [AbsentFakeFolder]::new(); $folder.Mode = $mode; $folder.Message = MESSAGE
 try { $task = Get-StartupTask $folder; $out[$mode] = $(if ($null -eq $task) { 'absent' } else { [string]$task }) }
 catch { $out[$mode] = 'threw' }
 if ($folder.Calls -ne 1) { throw 'ONE_LOOKUP' }
}
# The recorded native shape: an ErrorRecord whose own exception is the bare FileNotFoundException.
$native = [IO.FileNotFoundException]::new(MESSAGE)
$out['nativeHResult'] = $native.HResult
$out['nativeRecord'] = Test-TaskAbsent ([Management.Automation.ErrorRecord]::new($native, 'System.IO.FileNotFoundException', 'OperationStopped', $null))
$out['deniedRecord'] = Test-TaskAbsent ([Management.Automation.ErrorRecord]::new([UnauthorizedAccessException]::new('denied'), 'denied', 'OperationStopped', $null))
[Console]::Out.Write(($out | ConvertTo-Json -Compress))
'''.replace("MODES", ",".join("'" + mode + "'" for mode in modes)).replace("MESSAGE", "'" + self.message().replace("'", "''") + "'")
        for relative in ABSENCE_SCRIPTS:
            with self.subTest(script=relative):
                text = (ROOT / relative).read_text()
                functions = powershell_function(text, "Test-TaskAbsent") + powershell_function(text, "Get-StartupTask")
                self.assertEqual({"recorded": "absent", "com-not-found": "absent", "com-denied": "threw", "unauthorized": "threw",
                                  "other": "threw", "present": "present-task", "nativeHResult": -2147024894,
                                  "nativeRecord": True, "deniedRecord": False}, self.run_powershell(functions, body))

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_every_autostart_script_parses_under_powershell(self):
        paths = ",".join("'" + str(ROOT / relative).replace("'", "''") + "'" for relative in AUTOSTART_SCRIPTS)
        body = ("$out = [ordered]@{}\nforeach ($path in @(" + paths + ")) {\n $tokens = $null; $errors = $null\n"
                " $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)\n"
                " $out[[IO.Path]::GetFileName($path)] = @($errors | ForEach-Object { [string]$_.Message })\n}\n"
                "[Console]::Out.Write(($out | ConvertTo-Json -Compress))\n")
        self.assertEqual({PureWindowsPath(relative).name: [] for relative in AUTOSTART_SCRIPTS}, self.run_powershell("", body))

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_the_unfixed_snapshot_lookup_lets_the_recorded_exception_escape(self):
        # The control: the same recorded exception through the unfixed source's own lookup block escapes it.
        lines = (ABSENT / self.record["beforeSource"]["path"]).read_text().split("\n")
        start, end = lines.index(" $taskData = @{ state = 'absent' }"), lines.index("  if ($_.Exception.HResult -ne -2147024894) { throw }")
        block = "\n".join(lines[start:end + 2]) + "\n"
        body = ("$out = [ordered]@{}\nforeach ($mode in @('recorded')) {\n"
                " $folder = [AbsentFakeFolder]::new(); $folder.Mode = $mode; $folder.Message = MESSAGE\n"
                " try {\n" + block + " $out[$mode] = $taskData.state } catch { $out[$mode] = 'threw' }\n}\n"
                "[Console]::Out.Write(($out | ConvertTo-Json -Compress))\n").replace("MESSAGE", "'" + self.message().replace("'", "''") + "'")
        self.assertEqual({"recorded": "threw"}, self.run_powershell("", body))


RUN_KEY = Path(__file__).parent / "fixtures/windows_autostart_run_key_sacl"
# System.Security.AccessControl.AccessControlSections, not the Win32 SECURITY_INFORMATION bits a COM call takes.
SECTIONS = {"None": 0, "Audit": 1, "Access": 2, "Owner": 4, "Group": 8, "All": 15}
SECTION_CAST = re.compile(r"\[(?:System\.)?Security\.AccessControl\.AccessControlSections\]\s*('[^']*'|\d+)")


def sections_value(literal):
    """The flags a cast literal names: a number, or PowerShell's comma-separated enum names."""
    if literal.isdigit():
        return int(literal)
    value = 0
    for name in literal.strip("'").split(","):
        value |= SECTIONS[name.strip()]
    return value


class RunKeySecurityTests(unittest.TestCase):
    """Past the absent-task lookup, every reboot .pre on NF failed reading the HKCU Run key's security: .NET's
    AccessControlSections 7 is Audit|Access|Owner, and reading the SACL needs SeSecurityPrivilege, which the
    ordinary token lacks. The key is the user's own; owner, group and DACL need only READ_CONTROL, which KEY_READ holds."""

    def setUp(self):
        self.record = json.loads((RUN_KEY / "native-snapshot-children.json").read_text())

    def test_the_recorded_native_children_are_the_run_key_sacl_read_refused(self):
        before = (RUN_KEY / self.record["beforeSource"]["path"]).read_bytes()
        self.assertEqual(self.record["beforeSource"]["sha256"], hashlib.sha256(before).hexdigest())
        line = before.decode().split("\n")[72]
        self.assertIn("$key.GetAccessControl([Security.AccessControl.AccessControlSections]7)", line)
        self.assertEqual(3, len(self.record["runs"]))
        for operation, run in self.record["runs"].items():
            raw = base64.b64decode(run["stderrBase64"])
            self.assertEqual(run["stderrSha256"], hashlib.sha256(raw).hexdigest())
            stderr = raw.decode("utf-8")
            self.assertEqual(("autostart-read-only", 1), (run["label"], run["exitCode"]))
            self.assertIn('Exception calling "GetAccessControl" with "1" argument(s): "Attempted to perform an unauthorized operation."', stderr)
            self.assertIn("windows_autostart_snapshot.ps1:73 char:3", stderr)
            self.assertIn("FullyQualifiedErrorId : UnauthorizedAccessException", stderr)

    def test_no_autostart_script_reads_a_sacl_and_the_run_key_reads_owner_group_and_dacl(self):
        found = []
        for relative in AUTOSTART_SCRIPTS:
            text = (ROOT / relative).read_text()
            for literal in SECTION_CAST.findall(text):
                with self.subTest(script=relative, sections=literal):
                    self.assertFalse(sections_value(literal) & SECTIONS["Audit"], "a SACL needs SeSecurityPrivilege")
                    self.assertEqual(SECTIONS["Access"] | SECTIONS["Owner"] | SECTIONS["Group"], sections_value(literal))
                found.append(literal)
            # No security read takes a number or a variable cast elsewhere: every one names its sections.
            self.assertEqual(len(re.findall(r"\.GetAccessControl\(", text)), len(re.findall(r"\.GetAccessControl\(\$sections\)", text)))
        self.assertEqual(["'Access, Owner, Group'"], found)
        # The task's COM call takes SECURITY_INFORMATION, where 7 is OWNER|GROUP|DACL and the SACL is 8.
        snapshot = (ROOT / "agent_tools/windows_autostart_snapshot.ps1").read_text()
        self.assertEqual(["7"], re.findall(r"\.GetSecurityDescriptor\((\d+)\)", snapshot))

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_powershell_reads_each_cast_as_the_sections_named(self):
        literals = sorted({literal for relative in AUTOSTART_SCRIPTS for literal in SECTION_CAST.findall((ROOT / relative).read_text())}
                          | set(SECTION_CAST.findall((RUN_KEY / self.record["beforeSource"]["path"]).read_text())))
        body = ("$out = [ordered]@{}\n" + "".join(
            "$v = [Security.AccessControl.AccessControlSections]" + literal + "; $out['k" + str(index) + "'] = @([int]$v, [string]$v)\n"
            for index, literal in enumerate(literals)) + "[Console]::Out.Write(($out | ConvertTo-Json -Compress))\n")
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "sections.ps1"
            script.write_text("$ErrorActionPreference = 'Stop'\nSet-StrictMode -Version Latest\n" + body, encoding="utf-8")
            result = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                    capture_output=True, text=True, timeout=120, env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT="1"))
        self.assertEqual((0, ""), (result.returncode, result.stderr), result.stdout)
        reply = json.loads(result.stdout)
        observed = {literal: reply["k" + str(index)] for index, literal in enumerate(literals)}
        self.assertEqual(["7", "Audit, Access, Owner"], [str(value) for value in observed["7"]], "the unfixed cast asked for the SACL")
        for literal, (number, names) in observed.items():
            self.assertEqual(sections_value(literal), number, "the Python table is .NET's")
        for relative in AUTOSTART_SCRIPTS:
            for literal in SECTION_CAST.findall((ROOT / relative).read_text()):
                self.assertNotIn("Audit", observed[literal][1].split(", "), relative + ": .NET reads this cast as asking for the SACL")
        self.assertEqual([14, "Access, Owner, Group"], observed["'Access, Owner, Group'"])



PLANTER = "agent_tools/windows_autostart_create_highest_fixture.ps1"
RUN_TEMPLATE = "agent_tools/windows_scenario_system_run.ps1.template"
LEGACY_DESCRIPTION = "VPN Control owned acceptance legacy run-level fixture"
LEGACY_RESULT = '{"schemaVersion":1,"taskPath":"\\\\VPN Control","runLevel":"HighestAvailable"}'
PRINCIPAL = "S-1-5-21-3038404602-721382561-1826266252-1004"
# Task Scheduler and the token, faked: each folder call is recorded with what it was given.
LEGACY_FAKES = r"""
using System;using System.Collections.Generic;using System.Runtime.InteropServices;
public sealed class LegacyFakeRegistration {public string Description;}
public sealed class LegacyFakePrincipal {public string Id,UserId;public int LogonType,RunLevel;}
public sealed class LegacyFakeSettings {public bool Enabled,DisallowStartIfOnBatteries=true,StopIfGoingOnBatteries=true;public string ExecutionTimeLimit;}
public sealed class LegacyFakeTrigger {public int Type;public bool Enabled;public string UserId;}
public sealed class LegacyFakeTriggers {public List<LegacyFakeTrigger> Items=new List<LegacyFakeTrigger>();
 public LegacyFakeTrigger Create(int type){var t=new LegacyFakeTrigger{Type=type};Items.Add(t);return t;}}
public sealed class LegacyFakeAction {public int Type;public string Path,Arguments;}
public sealed class LegacyFakeActions {public string Context;public List<LegacyFakeAction> Items=new List<LegacyFakeAction>();
 public LegacyFakeAction Create(int type){var a=new LegacyFakeAction{Type=type};Items.Add(a);return a;}}
public sealed class LegacyFakeDefinition {public LegacyFakeRegistration RegistrationInfo=new LegacyFakeRegistration();
 public LegacyFakePrincipal Principal=new LegacyFakePrincipal();public LegacyFakeSettings Settings=new LegacyFakeSettings();
 public LegacyFakeTriggers Triggers=new LegacyFakeTriggers();public LegacyFakeActions Actions=new LegacyFakeActions();}
public sealed class LegacyFakeTask {public string Path;public LegacyFakeDefinition Definition;}
public sealed class LegacyFakeFolder {public string Mode="";public List<string> Calls=new List<string>();
 public Dictionary<string,LegacyFakeTask> Tasks=new Dictionary<string,LegacyFakeTask>();
 public LegacyFakeTask GetTask(string name){Calls.Add("get");if(Mode=="denied")throw new COMException("fake",-2147024891);
  LegacyFakeTask t;if(Tasks.TryGetValue(name,out t))return t;throw new COMException("fake",-2147024894);}
 public LegacyFakeTask RegisterTaskDefinition(string name,LegacyFakeDefinition d,int flags,string user,object password,int logon,object sddl){
  Calls.Add("register:"+name+":"+flags+":"+user+":"+(password==null)+":"+logon+":"+(sddl==null));
  if(Mode=="register-denied")throw new UnauthorizedAccessException("Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))");
  if(Tasks.ContainsKey(name))throw new COMException("fake",-2147024713);
  var t=new LegacyFakeTask{Path="\\"+name,Definition=d};Tasks[name]=t;return t;}
 public void DeleteTask(string name,int flags){Calls.Add("delete:"+name);if(!Tasks.Remove(name))throw new COMException("fake",-2147024894);}
 public void Plant(string description,int runLevel){var d=new LegacyFakeDefinition();d.RegistrationInfo.Description=description;
  d.Principal.RunLevel=runLevel;Tasks["VPN Control"]=new LegacyFakeTask{Path="\\VPN Control",Definition=d};}}
public sealed class LegacyFakeService {public LegacyFakeFolder Folder=new LegacyFakeFolder();public void Connect(){}
 public LegacyFakeFolder GetFolder(string path){return Folder;}public LegacyFakeDefinition NewTask(int flags){return new LegacyFakeDefinition();}}
public sealed class LegacyFakeSid {public string Value;}
public sealed class LegacyFakeIdentity {public static string Sid;public LegacyFakeSid User=new LegacyFakeSid{Value=Sid};
 public static LegacyFakeIdentity GetCurrent(){return new LegacyFakeIdentity();}public void Dispose(){}}
"""
LEGACY_DRIVER = r"""
function New-Object([string]$TypeName,[object[]]$ArgumentList,[string]$ComObject){
 if($ComObject -ceq 'Schedule.Service'){return $script:service}
 if($ComObject){throw 'LEGACY_FAKE_COM'}
 return ,(Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName -ArgumentList $ArgumentList)
}
function N($value,$code){if(-not $value){throw $code}}
function Fresh([string]$sid,[string]$mode){[LegacyFakeIdentity]::Sid=$sid;$script:service=[LegacyFakeService]::new();$script:service.Folder.Mode=$mode;return $script:service.Folder}
function Planted($folder){
 $t=$null;if($folder.Tasks.ContainsKey('VPN Control')){$t=$folder.Tasks['VPN Control']}
 if($null -eq $t){return $null}
 $d=$t.Definition
 return [ordered]@{description=$d.RegistrationInfo.Description;principal=@($d.Principal.Id,$d.Principal.UserId,$d.Principal.LogonType,$d.Principal.RunLevel);
  settings=@($d.Settings.Enabled,$d.Settings.DisallowStartIfOnBatteries,$d.Settings.StopIfGoingOnBatteries,$d.Settings.ExecutionTimeLimit);
  triggers=@($d.Triggers.Items|ForEach-Object {'{0}|{1}|{2}' -f $_.Type,$_.Enabled,$_.UserId});context=$d.Actions.Context;
  actions=@($d.Actions.Items|ForEach-Object {'{0}|{1}|{2}' -f $_.Type,$_.Path,$_.Arguments})}
}
"""


def indented_block(text, first):
    """The block that opens on the line `first` and closes on the next line that is its own indent and a brace."""
    lines = text.split("\n")
    start = lines.index(first)
    indent = first[:len(first) - len(first.lstrip(" "))]
    end = lines.index(indent + "}", start + 1)
    return "\n".join(lines[start:end + 1]) + "\n"


class LegacyAutostartPlantTests(unittest.TestCase):
    """Native 5594b6f5: the ordinary owner's RegisterTaskDefinition of the HighestAvailable task was E_ACCESSDENIED, after its
    public autostart toggle had already run, so the receipt said changed and the reboot chain held the clone. The
    pre-migration product (6f87f740) elevated itself at launch (DesktopWindowsElevation) and ran schtasks /RL HIGHEST
    elevated. The SYSTEM run now plants that task, for the ordinary user, before the owner and any public toggle."""

    def setUp(self):
        self.planter = (ROOT / PLANTER).read_text()
        self.template = (ROOT / RUN_TEMPLATE).read_text(encoding="ascii")

    def faked_planter(self):
        call = "[Security.Principal.WindowsIdentity]::GetCurrent()"
        self.assertEqual(1, self.planter.count(call))
        return self.planter.replace(call, "[LegacyFakeIdentity]::GetCurrent()")

    def run_powershell(self, body):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "legacy.ps1"
            planter = Path(directory) / "planter.ps1"
            planter.write_text(self.faked_planter(), encoding="utf-8")
            script.write_text("$ErrorActionPreference = 'Stop'\nAdd-Type -TypeDefinition @'\n" + LEGACY_FAKES + "\n'@\n" + LEGACY_DRIVER
                              + "$planterText = [IO.File]::ReadAllText('" + str(planter).replace("'", "''") + "')\n" + body
                              + "[Console]::Out.Write(($out | ConvertTo-Json -Depth 8 -Compress))\n", encoding="utf-8")
            result = subprocess.run([POWERSHELL, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)],
                                    capture_output=True, text=True, timeout=180, env=dict(os.environ, POWERSHELL_TELEMETRY_OPTOUT="1"))
        self.assertEqual((0, ""), (result.returncode, result.stderr), result.stdout)
        return json.loads(result.stdout)

    def test_the_legacy_task_arose_from_the_elevated_pre_migration_product(self):
        # The recorded native child: the ordinary token's registration refused.
        evidence = json.loads((Path(__file__).parent / "fixtures/windows_autostart_legacy_plant/native-planter-child.json").read_text())
        raw = base64.b64decode(evidence["stderrBase64"])
        self.assertEqual(evidence["stderrSha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))", raw.decode("utf-8"))
        self.assertEqual(("autostart-highest-fixture", 1), (evidence["label"], evidence["exitCode"]))
        # The planter now refuses any token but SYSTEM, and the owner never runs it.
        self.assertIn("if ($identity.User.Value -cne 'S-1-5-18') { throw 'FIXTURE_SYSTEM_PLANTER' }", self.planter)
        self.assertNotIn("migrationScriptPath", (ROOT / "agent_tools/windows_autostart_reboot.py").read_text().split("def collect", 1)[1]
                         .split("def toggle", 1)[1])

    def test_the_system_run_plants_before_the_owner_and_cleans_only_its_own_task(self):
        lines = self.template.split("\n")
        at = lambda text: next(number for number, line in enumerate(lines) if text in line)
        plant = at("if($null -ne $m.legacyAutostart){")
        self.assertLess(at("$script:P.legacy=$true"), at("[scriptblock]::Create($planter)"), "marked before the planter runs")
        self.assertLess(plant, at("$registered=$folder.RegisterTaskDefinition($name"), "planted before the owner's task")
        self.assertLess(plant, at("$script:P.launchConsumed=$true"), "planted before the owner can run")
        self.assertEqual(2, self.template.count("'" + LEGACY_DESCRIPTION + "'"), "both cleanups know the planter's own description")
        self.assertIn("$task.RegistrationInfo.Description = '" + LEGACY_DESCRIPTION + "'", self.planter)
        self.assertEqual(1, self.template.count("'" + LEGACY_RESULT + "'"))
        self.assertEqual(1, self.planter.count(" '" + LEGACY_RESULT + "'\n"), "the planter answers on the pipeline")
        self.assertNotIn("[Console]::", self.planter, "the SYSTEM run replies on the console; the planter never writes to it")

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_the_planter_registers_the_legacy_task_for_the_ordinary_user_only_as_system(self):
        body = r"""
$out = [ordered]@{}
foreach ($case in @('system','ordinary','existing','system-principal','register-denied')) {
 $sid = $(if ($case -ceq 'ordinary') { 'PRINCIPAL' } else { 'S-1-5-18' })
 $folder = Fresh $sid $(if ($case -ceq 'register-denied') { 'register-denied' } else { '' })
 if ($case -ceq 'existing') { $folder.Plant('another task', 0) }
 $principal = $(if ($case -ceq 'system-principal') { 'S-1-5-18' } else { 'PRINCIPAL' })
 $answer = $null; $threw = $null
 try { $answer = @(& ([scriptblock]::Create($planterText)) -GuiPath 'C:\Program Files\VPN Control\vpn-control.exe' -Workspace 'C:\w' -PrincipalSid $principal) }
 catch { $threw = [string]$_.Exception.Message }
 $out[$case] = [ordered]@{answer=$answer; threw=$threw; calls=@($folder.Calls|Where-Object {$_ -cne 'get'}); task=(Planted $folder)}
}
""".replace("PRINCIPAL", PRINCIPAL)
        out = self.run_powershell(body)
        system = out["system"]
        self.assertEqual(([LEGACY_RESULT], None), (system["answer"], system["threw"]))
        self.assertEqual(["register:VPN Control:2:" + PRINCIPAL + ":True:3:True"], system["calls"],
                         "TASK_CREATE, the ordinary user, no password, an interactive token, the scheduler's own SDDL")
        self.assertEqual({"description": LEGACY_DESCRIPTION, "principal": ["Author", PRINCIPAL, 3, 1],
                          "settings": [True, False, False, "PT0S"], "triggers": ["9|True|" + PRINCIPAL], "context": "Author",
                          "actions": [r'0|C:\Program Files\VPN Control\vpn-control.exe|--autostart --state-dir "C:\w"']},
                         system["task"])
        self.assertEqual(("FIXTURE_SYSTEM_PLANTER", []), (out["ordinary"]["threw"], out["ordinary"]["calls"]))
        self.assertEqual(("EXISTING_STARTUP_TASK_REFUSED", []), (out["existing"]["threw"], out["existing"]["calls"]))
        self.assertEqual("another task", out["existing"]["task"]["description"])
        self.assertEqual(("FIXTURE_ORDINARY_PRINCIPAL", []), (out["system-principal"]["threw"], out["system-principal"]["calls"]))
        self.assertIn("E_ACCESSDENIED", out["register-denied"]["threw"])
        self.assertIsNone(out["register-denied"]["task"])

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_the_system_run_plants_marks_and_refuses_as_the_template_says(self):
        plant = indented_block(self.template, " if($null -ne $m.legacyAutostart){")
        absent = indented_block(self.template, "function Is-TaskAbsent($record){")
        body = absent + r"""
function Open-Pin($record,$directory){return $record}
function Read-PinBytes($p,$limit){return ,[Text.UTF8Encoding]::new($false).GetBytes($planterText)}
function Guard-Full {}
$out = [ordered]@{}
foreach ($case in @('absent','existing','refused','other-principal')) {
 $folder = Fresh $(if ($case -ceq 'refused') { 'PRINCIPAL' } else { 'S-1-5-18' }) ''
 if ($case -ceq 'existing') { $folder.Plant('another task', 0) }
 $script:P = [ordered]@{legacy=$false; legacyPlanted=$false}
 $m = [pscustomobject]@{mode='python-worker'; context=[pscustomobject]@{ordinarySid='PRINCIPAL'};
  legacyAutostart=[pscustomobject]@{planterPin=@{}; guiPath='C:\gui.exe'; workspace='C:\w'; principalSid=$(if ($case -ceq 'other-principal') { 'S-1-5-21-9-9-9-1000' } else { 'PRINCIPAL' })}}
 $threw = $null
 try {
PLANT } catch { $threw = [string]$_.Exception.Message }
 $out[$case] = [ordered]@{threw=$threw; legacy=$script:P.legacy; planted=$script:P.legacyPlanted; task=$(if ($null -eq (Planted $folder)) { $null } else { (Planted $folder).description })}
}
""".replace("PLANT", plant).replace("PRINCIPAL", PRINCIPAL)
        out = self.run_powershell(body)
        self.assertEqual({"threw": None, "legacy": True, "planted": True, "task": LEGACY_DESCRIPTION}, out["absent"])
        self.assertEqual({"threw": "RUN_LEGACY_AUTOSTART_EXISTS", "legacy": False, "planted": False, "task": "another task"}, out["existing"],
                         "a task already there is never this run's: nothing marks it for removal")
        self.assertEqual({"threw": "FIXTURE_SYSTEM_PLANTER", "legacy": True, "planted": False, "task": None}, out["refused"])
        self.assertEqual({"threw": "RUN_LEGACY_AUTOSTART_INPUT", "legacy": False, "planted": False, "task": None}, out["other-principal"])

    @unittest.skipUnless(POWERSHELL, "a PowerShell interpreter is required")
    def test_the_system_run_removes_only_its_own_unmigrated_task(self):
        absent = indented_block(self.template, "function Is-TaskAbsent($record){")
        refusal = indented_block(self.template, " if(-not $unknown -and $script:P.legacy){")
        closing = indented_block(self.template, "  if($script:P.legacyPlanted){")
        body = absent + r"""
$out = [ordered]@{}
foreach ($case in @('own-highest','own-migrated','foreign','absent','denied')) {
 foreach ($path in @('refusal','closing')) {
  $folder = Fresh 'S-1-5-18' $(if ($case -ceq 'denied') { 'denied' } else { '' })
  if ($case -ceq 'own-highest') { $folder.Plant('DESCRIPTION', 1) }
  if ($case -ceq 'own-migrated') { $folder.Plant('DESCRIPTION', 0) }
  if ($case -ceq 'foreign') { $folder.Plant('another task', 1) }
  $script:P = [ordered]@{folder=$folder; legacy=$true; legacyPlanted=$true}
  $unknown = $false; $threw = $null
  try {
   if ($path -ceq 'refusal') {
REFUSAL   } else {
CLOSING   }
  } catch { $threw = [string]$_.Exception.Message }
  $out[$case + ':' + $path] = [ordered]@{unknown=$unknown; threw=$threw; left=$folder.Tasks.ContainsKey('VPN Control'); planted=$script:P.legacyPlanted}
 }
}
""".replace("REFUSAL", refusal).replace("CLOSING", closing).replace("DESCRIPTION", LEGACY_DESCRIPTION)
        out = self.run_powershell(body)
        self.assertEqual({"unknown": False, "threw": None, "left": False, "planted": False}, out["own-highest:refusal"])
        self.assertEqual({"unknown": False, "threw": None, "left": False, "planted": True}, out["own-highest:closing"],
                         "an owner that ended before the migration leaves the clone as it found it")
        self.assertTrue(out["own-migrated:closing"]["left"], "a task the product migrated is the row's")
        for path in ("refusal", "closing"):
            self.assertTrue(out["foreign:" + path]["left"], "another task is never this run's to remove")
            self.assertEqual((False, None, False), (out["absent:" + path]["unknown"], out["absent:" + path]["threw"], out["absent:" + path]["left"]))
        self.assertTrue(out["denied:refusal"]["unknown"], "a failed lookup is no proof of absence")
        self.assertEqual("RUN_LEGACY_AUTOSTART_CLOSING_OBSERVATION", out["denied:closing"]["threw"])


if __name__ == "__main__":
    unittest.main()
