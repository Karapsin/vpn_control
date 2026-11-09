"""The windows-proxy-lifecycle family's case bodies and generated files, offline.

A small Windows world stands in for the guest: a process table where a jpackage launcher
starts itself again and waits for that JVM, a product CLI with the source rule of
DesktopAppService.saveControlLocation and the link rule of ProxyLinkParser (read from its
Kotlin source), real files under a temporary root and a fake clock.
The world models what the repository's own native records show (a relaunched launcher
pair of one image; a fresh workspace that reads a subscription; INVALID_ARGUMENT for a
socks5:// location); nothing here proves a Windows behaviour.
"""
import base64
import hashlib
import json
import ntpath
import os
from pathlib import Path
import random
import re
import shutil
import ssl
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_lifecycle_cases as lifecycle_cases
from agent_tools import windows_lifecycle_runtime_stages as runtime_stages
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_runtime_branch_cases as branch_cases
from agent_tools import windows_scenario_proxy as proxy
from agent_tools.tests import product_link_schemes as product_links
from scripts import windows_broker_fixture_observer as observer_module

ROOT = Path(__file__).resolve().parents[2]
SID = "S-1-5-21-1-2-3-1000"
SESSION = 2
CLI = "C:\\Users\\recovery\\AppData\\Local\\vpn-control\\vpn-control-cli.exe"
GUI = "C:\\Users\\recovery\\AppData\\Local\\vpn-control\\vpn-control.exe"
PYTHON = "C:\\Users\\recovery\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
TOOL = "C:\\ProgramData\\VpnControlOrdinaryTask-op\\sing-box.exe"
LAUNCHER_SHA, GUI_SHA, RUNTIME_SHA = "1" * 64, "2" * 64, "3" * 64
PRODUCT_VERSION = "2.2.14"
INVALID = -1
# The reviewed sources these tests hold at their pinned digests, read once from this checkout.
SOURCE_PATHS = ("agent_tools/windows_lifecycle_runtime_stages.py", "scripts/windows_broker_fixture_observer.py",
                "agent_tools/windows_lifecycle_runtime_fixture_worker.py", "scripts/integration/socks_http_fixture.py",
                "scripts/integration/https_subscription_relay_fixture.py", "agent_tools/windows_lifecycle_traffic_worker.py",
                "agent_tools/windows_runtime_branch_cases.py", "agent_tools/windows_runtime_tcp_listeners.ps1",
                "agent_tools/windows_tun_stages.py")
SOURCES = {}


def source_bytes():
    if not SOURCES:
        for relative in SOURCE_PATHS:
            SOURCES[relative] = (ROOT / relative).read_bytes()
    return SOURCES


class Parked(BaseException):
    """What Owner.park does to the guest: nothing after it runs."""


class Process:
    def __init__(self, world, pid, parent, image, sha256, *, waits_for_child=False):
        self.world, self.pid, self.parent, self.image, self.sha256 = world, pid, parent, image, sha256
        world.clock += 1
        self.created = 133000000000000000 + world.clock
        self.exit_code = None
        self.waits_for_child = waits_for_child

    @property
    def name(self):
        return ntpath.basename(self.image)

    def end(self, code):
        """A launcher that waits for its JVM ends with that JVM's code."""
        if self.exit_code is not None:
            return
        self.exit_code = code
        for other in self.world.processes:
            if other.exit_code is None and other.waits_for_child and self.parent == other.pid and other.created <= self.created:
                other.end(code)


class Held:
    """A process handle: it names one process object even after its pid is reused."""

    def __init__(self, world, process, access):
        self.world, self.process, self.access = world, process, access
        world.next_handle += 4
        self.handle = world.next_handle
        world.handles[self.handle] = self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.world.handles.pop(self.handle, None)
        self.handle = None

    def describe(self):
        process = self.process
        return {"image": process.image, "creationFileTime": process.created, "exitFileTime": 0, "kernelTime100ns": 0,
                "userTime100ns": 0, "token": {"sid": SID, "elevationType": 1, "elevated": 0, "sessionId": SESSION},
                "sha256": process.sha256, "sizeBytes": 1}

    def wait(self):
        return 258 if self.process.exit_code is None else 0

    def times(self):
        return {"creationFileTime": self.process.created, "exitFileTime": 0, "kernelTime100ns": 0, "userTime100ns": 0}


class World:
    """The guest's process table, windows and a jpackage launcher that relaunches itself."""

    def __init__(self, *, relaunch=True):
        self.relaunch = relaunch
        self.clock = 0
        self.next_pid, self.next_handle = 1000, 4000
        self.processes = []
        self.handles = {}
        self.windows = {}
        self.terminated = []
        self.k = types.SimpleNamespace()

    def spawn(self, parent, image, sha256, *, launcher=False):
        """One process; a launcher of the product relaunches itself and its JVM does the work."""
        self.next_pid += 4
        first = Process(self, self.next_pid, parent, image, sha256, waits_for_child=launcher and self.relaunch)
        self.processes.append(first)
        if not (launcher and self.relaunch):
            return first, first
        self.next_pid += 4
        jvm = Process(self, self.next_pid, first.pid, image, sha256)
        self.processes.append(jvm)
        return first, jvm

    def live(self, pid):
        found = [process for process in self.processes if process.pid == pid and process.exit_code is None]
        return found[0] if found else None

    # The observer's WindowsNative, as the cases call it.
    def processes_table(self):
        return [{"pid": process.pid, "parentPid": process.parent, "name": process.name}
                for process in self.processes if process.exit_code is None]

    def native(self):
        world = self

        class Native:
            k = world.k

            @staticmethod
            def processes():
                return world.processes_table()

            @staticmethod
            def open_process(pid, access):
                process = world.live(pid)
                if process is None:
                    raise observer_module.ProcessAbsent("OpenProcess reports no process for this PID")
                return Held(world, process, access)

            @staticmethod
            def api(library, name, result, arguments):
                if name != "TerminateProcess":
                    raise AssertionError("closed native call")
                return world.terminate
        return Native()

    def terminate(self, handle, code):
        held = self.handles.get(handle)
        if held is None or not held.access & 1:
            return False
        self.terminated.append(held.process.pid)
        held.process.end(code)
        return True

    def gui_windows(self):
        world = self

        class Windows:
            @staticmethod
            def windows(pid):
                return [dict(row) for row in world.windows.get(pid, [])]

            @staticmethod
            def close(hwnd, expected_pid):
                rows = [row for row in world.windows.get(expected_pid, []) if row["hwnd"] == hwnd]
                if len(rows) != 1:
                    raise AssertionError("exact-window-process-before-close")
                rows[0]["visible"] = False  # Close to tray: hidden, not detached.
        return Windows()


class Clock:
    """The cases' own waits run on this clock, so a 30 s bound costs nothing."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, 0.05)


class Child:
    """An Owner child: the original handle is a handle to the first process it started."""

    def __init__(self, owner, label, argv, process=None, *, completed=None):
        self.owner, self.label, self.argv = owner, label, tuple(argv)
        self.ordinal = len(owner.children)
        owner.children.append(self)
        self.terminal, self.completed_value = None, completed
        self.os_process = process
        if process is not None:
            self.pid, self.birth = process.pid, str(process.created)
            held = Held(owner.world, process, 0x1F0FFF)
            self.process = types.SimpleNamespace(pid=process.pid, _handle=held.handle, poll=lambda: process.exit_code)
        else:
            self.pid, self.birth = None, None
            self.process = types.SimpleNamespace(pid=None, _handle=None, poll=lambda: 0)
            self.terminal = {"child": self.ordinal, "exitCode": completed.returncode, "eof": {"stdout": True, "stderr": True}}

    def wait(self):
        if self.terminal is None:
            if self.os_process.exit_code is None:
                raise AssertionError("the world never ends " + self.label + " by itself")
            self.terminal = {"child": self.ordinal, "pid": self.pid, "exitCode": self.os_process.exit_code,
                             "eof": {"stdout": True, "stderr": True}}
        return self.terminal

    def completed(self):
        return self.completed_value


class Traffic(Child):
    """The finite sampler: two samples are written before the cases read it, the rest when it ends."""

    def __init__(self, owner, label, argv):
        first, _ = owner.world.spawn(None, PYTHON, "4" * 64)
        super().__init__(owner, label, argv, first)
        self.port, self.started = int(argv[-1]), owner.clock.now
        owner.clock.now += 0.1
        self.write(owner.clock.now)
        (owner.root / f"child-{self.ordinal:04d}.stderr.raw").write_bytes(b"")

    def write(self, until, terminal=False):
        count = int(round((until - self.started) / 0.05))
        rows = [{"kind": "sample", "ordinal": index, "startedAt": self.started + 0.05 * index, "finishedAt": self.started + 0.05 * (index + 1),
                 "mixedPort": self.port, "gapBeforeSeconds": 0.0, "succeeded": True} for index in range(count)]
        if terminal:
            rows.append({"kind": "terminal", "sampleCount": count, "allSamplesSucceeded": True})
        (self.owner.root / f"child-{self.ordinal:04d}.stdout.raw").write_bytes("".join(json.dumps(row) + "\n" for row in rows).encode())

    def wait(self):
        if self.terminal is None:
            self.write(self.owner.clock.now + 1, terminal=True)
            self.os_process.end(0)
        return super().wait()


class Fixture(Child):
    """The owned fixture worker: it ends 0 on its own exact stop record, as windows_lifecycle_runtime_fixture_worker does."""

    def __init__(self, owner, label, argv, process, config):
        super().__init__(owner, label, argv, process)
        self.config = config

    def wait(self):
        control = Path(self.config["controlFile"])
        stop = {"schemaVersion": 1, "operationId": self.config["operationId"], "action": "stop-owned-fixture"}
        if self.terminal is None and self.os_process.exit_code is None and control.exists() and json.loads(control.read_bytes()) == stop:
            self.os_process.end(0)
        return super().wait()


class Product:
    """The packaged CLI and its owner: envelopes, the source rule, and runtime processes."""

    def __init__(self, world, owner):
        self.world, self.owner = world, owner
        self.identity = "controller-" + uuid.uuid4().hex[:8]
        self.revision = 1
        self.source = "subscription"  # DesktopStateStore: a fresh workspace reads a subscription.
        self.locations, self.selected = [], None
        self.running, self.runtime = False, None
        self.jvm = None
        self.calls = []
        # A command a test makes the owner refuse with a code, or answer with a reply that is not JSON.
        self.refusals, self.garbled = {}, set()
        # A second serve while this owner runs: DesktopExistingService.adopt, exit 0, its line on stderr
        # as every headless-controller line (DesktopHeadlessController.handleArgs, writeDesktopCliLine(System.err)).
        self.adoption = (0, "", "VPN Control is already running.\n")

    def envelope(self, code="OK", **data):
        return {"schemaVersion": 1, "controllerId": self.identity, "requestId": str(uuid.uuid4()), "code": code,
                "final": True, "ok": code == "OK", "configurationRevision": self.revision, "restartRequired": False,
                "data": data}

    def status(self):
        return self.envelope(runtimeRunning=self.running, activeMode="proxy-only" if self.running else None,
                             runtimeId="runtime-1" if self.running else None, runtimeStartedAt=1 if self.running else None,
                             activeLocationId=self.selected if self.running else None, selectedLocationId=self.selected)

    def run(self, words):
        self.calls.append(tuple(words))
        words = list(words)
        if words[:1] != ["--json"]:
            raise AssertionError("JSON calls only")
        words = words[1:]
        if words[:1] == ["--controller-id"]:
            if words[1] != self.identity:
                return 2, self.envelope("CONFLICT")
            words = words[2:]
        if words[:1] == ["--if-revision"]:
            if int(words[1]) != self.revision:
                return 1, self.envelope("CONFLICT")
            words = words[2:]
        if tuple(words[:2]) in self.garbled:
            return 0, "VPN Control: a reply that is not JSON\n"
        if tuple(words[:2]) in self.refusals:
            return 1, self.envelope(self.refusals[tuple(words[:2])])
        if words == ["status"]:
            return 0, self.status()
        if words == ["locations", "list"]:
            listed = self.locations if self.source == "current-locations" else []
            return 0, self.envelope(locations=[{"id": name, "name": name} for name in listed])
        if words == ["source", "set", "current-locations"]:
            self.source, self.revision = "current-locations", self.revision + 1
            return 0, self.envelope()
        if words[:3] == ["locations", "add", "--input"]:
            # DesktopAppService.saveControlLocation: only the current-locations source takes a location.
            if self.source != "current-locations":
                return 1, self.envelope("READ_ONLY_SOURCE")
            link = Path(words[3]).read_text(encoding="utf-8").strip()
            # LocationConfigs.parseLocationInput: a link ProxyLinkParser does not dispatch is INVALID_ARGUMENT.
            if not product_links.dispatched(link):
                return 1, self.envelope("INVALID_ARGUMENT")
            self.locations.append(link.rsplit("#", 1)[1].replace("%20", " "))
            self.revision += 1
            return 0, self.envelope()
        if words[:2] == ["locations", "select"]:
            if words[2] not in self.locations:
                return 1, self.envelope("NOT_FOUND")
            self.selected, self.revision = words[2], self.revision + 1
            return 0, self.envelope()
        if words[:2] in (["routing", "set"], ["settings", "set"]):
            self.revision += 1
            return 0, self.envelope()
        if words == ["on"]:
            if not self.running:
                image = str(Path(self.owner.request["workspace"]) / "runtime" / "tools" / "sing-box.exe")
                self.runtime, _ = self.world.spawn(self.jvm.pid, image, RUNTIME_SHA)
                self.running = True
            return 0, self.envelope()
        if words[:1] == ["gui"] and words[1:] in (["show"], ["hide"]):
            # The owner asks its attached frontends; their windows are the JVMs' windows.
            for process in self.world.processes:
                if process.image == GUI and process.exit_code is None:
                    for row in self.world.windows.get(process.pid, []):
                        row["visible"] = words[1] == "show"
            return 0, self.envelope()
        if words == ["off"]:
            if self.running:
                self.runtime.end(0)
                self.running = False
            # An explicit off is remembered: the next start of this workspace does not reconnect.
            workspace = Path(self.owner.request["workspace"])
            workspace.mkdir(exist_ok=True)
            (workspace / "workspace.json").write_text(json.dumps({"resume_connection_on_launch": False}), encoding="utf-8")
            return 0, self.envelope()
        if words == ["quit"]:
            self.jvm.end(0)
            return 0, self.envelope()
        raise AssertionError("closed product command " + repr(words))


class FileNative:
    """The owner's own file custody calls over real files: identity, security and bytes."""

    def __init__(self, owner):
        self.owner = owner
        self.paths = {}
        self.next = 100
        self.k = types.SimpleNamespace(CreateFileW=self.open, CloseHandle=lambda handle: self.paths.pop(handle, None) is not None)

    def open(self, path, *_):
        if not os.path.lexists(path):
            return INVALID
        self.next += 4
        self.paths[self.next] = Path(path)
        return self.next

    def identity(self, handle, directory=False):
        info = self.paths[handle].stat()
        value = {"volumeSerial": 1, "fileIndex": info.st_ino, "attributes": 16 if directory else 32}
        if not directory:
            value.update(sizeBytes=info.st_size, links=1, creationFileTime="1", lastWriteFileTime="1")
        return value

    def security(self, handle):
        return {"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}

    def read_blocks(self, handle):
        yield self.paths[handle].read_bytes()

    def birth(self, handle):
        held = self.owner.world.handles[handle]
        return str(held.process.created)


class Owner:
    """The ordinary Owner's surface the cases use, over the world and a temporary root."""

    def __init__(self, root, world):
        self.root, self.world = root, world
        self.operation = str(uuid.uuid4())
        self.request = {"context": {"ordinarySid": SID, "ordinarySessionId": SESSION}, "workspace": str(root / "workspace"),
                        "cliPath": CLI, "pythonRuntime": {"interpreterPath": PYTHON}, "operationId": self.operation,
                        "productVersion": PRODUCT_VERSION}
        self.children, self.events, self.environment, self.by_path = [], [], {}, {}
        self.native = FileNative(self)
        self.product = Product(world, self)
        self.ready_changes = {}  # What a test makes the fixture's ready record say otherwise.

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append((kind, json.loads(json.dumps(value, default=str))))

    def park(self, reason, error=None):
        self.parked = reason
        raise Parked(reason)

    def module(self, path, name):
        return observer(self.world)

    def child(self, label, argv, **_):
        if argv[0] == CLI and argv[-1] == "serve" and self.product.jvm is not None and self.product.jvm.exit_code is None:
            # The workspace lock is held: this serve adopts the running owner and ends at once.
            code, stdout, stderr = self.product.adoption
            return Child(self, label, argv, completed=subprocess.CompletedProcess(argv, code, stdout, stderr))
        if argv[0] == CLI and argv[-1] == "serve":
            first, jvm = self.world.spawn(None, CLI, LAUNCHER_SHA, launcher=True)
            self.product.jvm = jvm
            return Child(self, label, argv, first)
        if argv[0] == GUI:
            first, jvm = self.world.spawn(None, GUI, GUI_SHA, launcher=True)
            self.world.windows[jvm.pid] = [{"hwnd": jvm.pid * 16, "pid": jvm.pid, "visible": True, "width": 900, "height": 640}]
            return Child(self, label, argv, first)
        if argv[0] == CLI and argv[3:] in (["--help"], ["--version"]):
            # The installed launcher's static probe answers and ends before any owner state exists.
            output = "Usage: vpn-control-cli [OPTIONS] COMMAND\n" if argv[3] == "--help" else "VPN Control " + PRODUCT_VERSION + "\n"
            return Child(self, label, argv, completed=subprocess.CompletedProcess(argv, 0, output, ""))
        if argv[0] == CLI:
            code, body = self.product.run(argv[3:])
            stdout = body if type(body) is str else json.dumps(body)
            return Child(self, label, argv, completed=subprocess.CompletedProcess(argv, code, stdout, ""))
        if argv[0] == PYTHON and label == "lifecycle-traffic":
            return Traffic(self, label, argv)
        if argv[0] == PYTHON and label == "owned-runtime-fixture":
            config = json.loads(Path(argv[-1]).read_bytes())
            ready = {"operationId": config["operationId"], "httpsHost": "localhost", "httpsPort": 24443, "advertisedSocksHost": "127.0.0.1",
                     "advertisedSocksPort": 23456, "trafficUrl": "https://localhost:24443/traffic", **self.ready_changes}
            Path(config["readyFile"]).write_bytes((json.dumps(ready) + "\n").encode())
            first, _ = self.world.spawn(None, PYTHON, "4" * 64)
            return Fixture(self, label, argv, first, config)
        if argv[0] == TOOL:
            first, _ = self.world.spawn(None, TOOL, RUNTIME_SHA)
            return Child(self, label, argv, first)
        raise AssertionError("closed child " + label)

    def invoke(self, workspace, *arguments, timeout=30):
        return self.child("public-cli", [CLI, "--state-dir", str(workspace), *arguments]).completed()

    def pin(self, path, sha256):
        self.by_path[str(Path(path)).casefold()] = types.SimpleNamespace(record={"sha256": sha256}, directory=False)


class NtOs:
    """The stage's own os module as the guest has it, for its Windows-only publication rule."""
    name = "nt"

    def __getattr__(self, name):
        return getattr(os, name)


def observer(world):
    return types.SimpleNamespace(WindowsNative=world.native, require_identity=observer_module.require_identity,
                                 observe_exit=observer_module.observe_exit, ProcessAbsent=observer_module.ProcessAbsent)


class WorldBase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.world = World()
        self.owner = Owner(self.root, self.world)
        self.owner.clock = Clock()

    def serve(self):
        """A serve the owner started and the product's runtime A under it."""
        serve = self.owner.child("serve", [CLI, "--state-dir", self.owner.request["workspace"], "serve"])
        self.owner.product.selected = "Owned A"
        self.owner.product.run(["--json", "on"])
        return serve


class LauncherPairTests(WorldBase):
    """The serve and GUI launchers relaunch themselves; their JVM owns the runtime and the windows."""

    def test_the_runtime_is_found_under_the_jvm_the_serve_launcher_relaunched(self):
        serve = self.serve()
        actors = runtime_stages.capture_proxy_actors(self.owner, serve, self.world.native(),
                                                     self.owner.request["workspace"] + "\\runtime\\tools\\sing-box.exe", RUNTIME_SHA)
        self.assertEqual(serve.pid, actors["owner"]["pid"])
        self.assertEqual(self.owner.product.jvm.pid, actors["jvm"]["pid"])
        self.assertEqual(self.owner.product.runtime.pid, actors["runtime"]["pid"])
        self.assertEqual([], actors["auxiliary"])

    def test_a_launcher_that_is_its_own_jvm_still_owns_its_runtime(self):
        self.world.relaunch = False
        serve = self.serve()
        actors = runtime_stages.capture_proxy_actors(self.owner, serve, self.world.native(),
                                                     self.owner.request["workspace"] + "\\runtime\\tools\\sing-box.exe", RUNTIME_SHA)
        self.assertEqual((serve.pid, serve.pid), (actors["owner"]["pid"], actors["jvm"]["pid"]))
        self.assertEqual(self.owner.product.runtime.pid, actors["runtime"]["pid"])

    def test_a_second_relaunch_or_a_stale_parent_pointer_is_never_taken(self):
        serve = self.serve()
        image = self.owner.request["workspace"] + "\\runtime\\tools\\sing-box.exe"
        stale = Process(self.world, self.owner.product.jvm.pid + 1, self.owner.product.jvm.pid, image, RUNTIME_SHA)
        stale.created = self.owner.product.jvm.created - 5  # Born before the JVM: its parent pointer names an older process.
        self.world.processes.append(stale)
        actors = runtime_stages.capture_proxy_actors(self.owner, serve, self.world.native(), image, RUNTIME_SHA)
        self.assertEqual(self.owner.product.runtime.pid, actors["runtime"]["pid"])
        self.world.spawn(serve.pid, CLI, LAUNCHER_SHA)
        with self.assertRaisesRegex(AssertionError, "one-relaunched-owner-jvm"):
            runtime_stages.capture_proxy_actors(self.owner, serve, self.world.native(), image, RUNTIME_SHA)

    def sibling(self):
        serve = self.serve()
        tool_process, _ = self.world.spawn(None, TOOL, RUNTIME_SHA)
        sibling_child = Child(self.owner, "owned-sibling-proxy-runtime", (TOOL, "run", "-c", str(self.root / "owned-sibling-config.json")), tool_process)
        state = {"serve": serve, "workspace": Path(self.owner.request["workspace"]), "identity": self.owner.product.identity,
                 "inputs": {"runtimeImagePath": self.owner.request["workspace"] + "\\runtime\\tools\\sing-box.exe", "runtimeSha256": RUNTIME_SHA}}
        inputs = {"fixtureRuntimeToolPath": TOOL, "runtimeSha256": RUNTIME_SHA}
        sibling = {"child": sibling_child, "socket": None, "stopAttempted": False, "port": 34567}
        self.owner.runtime_case_sibling = sibling
        runtime = types.SimpleNamespace(capture_proxy_actors=runtime_stages.capture_proxy_actors,
                                        result=lambda owner, workspace, identity, *words: json.loads(owner.invoke(
                                            workspace, "--json", "--controller-id", identity, *words).stdout))
        return state, inputs, sibling, runtime

    def test_the_census_names_the_owner_jvm_beside_the_launcher_and_the_two_runtimes(self):
        state, inputs, sibling, runtime = self.sibling()
        probes = []
        with mock.patch.object(branch_cases, "inputs_guard", lambda *args: None), \
                mock.patch.object(branch_cases, "probe", lambda owner, state, inputs, port, label, actor: probes.append(label)):
            result = branch_cases.off_with_sibling_survivor(self.owner, state, inputs, runtime, None, observer(self.world), sibling)
        roles = set(result["opening"]["expectedRoles"])
        self.assertEqual({"owner", "ownerJvm", "productRuntime", "siblingRuntime"}, roles)
        self.assertEqual({"owner", "ownerJvm", "siblingRuntime"}, set(result["closing"]["expectedRoles"]))
        self.assertEqual(["sibling-after-product-off"], probes)
        self.assertFalse(self.owner.product.running)
        self.assertIsNotNone(self.owner.product.runtime.exit_code)

    def continuity_inputs(self):
        """gui_continuity's inputs around a running runtime A, as the dedicated driver derives them."""
        serve = self.serve()
        workspace = Path(self.owner.request["workspace"])
        workspace.mkdir()
        config = workspace / "runtime-config.json"
        config.write_text(json.dumps({"inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 41000}]}))
        image = str(workspace / "runtime" / "tools" / "sing-box.exe")
        actors = runtime_stages.capture_proxy_actors(self.owner, serve, self.world.native(), image, RUNTIME_SHA)
        paths = {"guiPath": GUI, "observerPath": "C:\\W\\observer.py", "trafficWorkerPath": "C:\\W\\traffic.py", "trafficInputPath": "C:\\W\\traffic.json"}
        for path in paths.values():
            self.owner.pin(path, GUI_SHA if path == GUI else "8" * 64)
        self.owner.pin(CLI, LAUNCHER_SHA)
        return {"schemaVersion": 1, "stateDir": str(workspace), "controllerId": self.owner.product.identity, **paths,
                "runtimeConfigPath": str(config), "ownerActor": actors["owner"], "runtimeActor": actors["runtime"],
                "installedAdmissionArtifactId": "installed", "fixtureAdmissionArtifactId": "fixture", "sourceArtifactId": "source",
                "frontendCrashScenario": "exact-owned-original-gui-handle", "fixtureSocksPort": 23456, "trayAdmissionArtifactId": "tray-unproven",
                "runtimeArtifact": {"installedAdmissionArtifactId": "installed", "runtimeImagePath": image, "runtimeSha256": RUNTIME_SHA}}

    def test_gui_continuity_follows_the_jvm_each_relaunched_gui_runs_in(self):
        inputs = self.continuity_inputs()
        with mock.patch.object(lifecycle_cases, "time", self.owner.clock), mock.patch.object(lifecycle_cases, "GuiWindows", self.world.gui_windows):
            result = lifecycle_cases.gui_continuity(self.owner, Path(inputs["stateDir"]), inputs["controllerId"], inputs)
        launchers = [child for child in self.owner.children if child.label == "lifecycle-gui"]
        jvms = [process for process in self.world.processes if process.image == GUI and process.parent in {child.pid for child in launchers}]
        self.assertEqual(2, len(launchers), "attach, then reopen after the crash")
        self.assertIs(launchers[1], result["guiChild"])
        self.assertEqual([lifecycle_cases.CRASH_EXIT, None], [process.exit_code for process in jvms], "the crashed GUI's JVM ended; the reopened one runs")
        self.assertEqual(lifecycle_cases.CRASH_EXIT, launchers[0].wait()["exitCode"])
        self.assertEqual(8, len(result["measuredTraffic"]["coverage"]))
        closes = [value for kind, value in self.owner.events if kind == "lifecycle-wm-close-intent"]
        self.assertEqual([jvms[0].pid], [value["windowPid"] for value in closes], "WM_CLOSE went to the window of the JVM")

    def test_the_relaunched_jvm_is_found_only_when_asked_for(self):
        self.serve()
        self.owner.pin(GUI, GUI_SHA)
        native, windows = self.world.native(), self.world.gui_windows()
        child = self.owner.child("lifecycle-gui", [GUI, "--state-dir", self.owner.request["workspace"]])
        jvm = self.world.live(child.pid + 4)
        self.assertEqual(child.pid, jvm.parent)
        main = lifecycle_cases.await_window(self.owner, child, native, windows, True, relaunching=True)
        self.assertEqual(jvm.pid, main["pid"])
        self.assertEqual([], lifecycle_cases.window_state(self.owner, child, native, windows), "a launcher taken as its own JVM has no windows here")
        lifecycle_cases.close_window(self.owner, child, main["hwnd"], native, windows, relaunching=True)
        self.assertFalse(self.world.windows[jvm.pid][0]["visible"], "WM_CLOSE reached the JVM's window")
        self.world.spawn(child.pid, GUI, GUI_SHA)
        with self.assertRaisesRegex(AssertionError, "one-relaunched-frontend-jvm"):
            lifecycle_cases.window_state(self.owner, child, native, windows, relaunching=True)

    def test_a_frontend_crash_ends_the_jvm_that_runs_the_gui(self):
        # A launcher without a job object leaves its JVM running when only the launcher ends.
        self.serve()
        self.owner.pin(GUI, GUI_SHA)
        child = self.owner.child("lifecycle-gui", [GUI, "--state-dir", self.owner.request["workspace"]])
        jvm = self.world.live(child.pid + 4)
        terminal = lifecycle_cases.crash_frontend(self.owner, child, self.world.native(), relaunching=True)
        self.assertEqual(lifecycle_cases.CRASH_EXIT, terminal["exitCode"])
        self.assertEqual([jvm.pid], self.world.terminated, "the JVM that runs the GUI ends, through the handle that identified it")
        self.assertEqual(lifecycle_cases.CRASH_EXIT, jvm.exit_code)
        self.assertEqual([], [held for held in self.world.handles.values() if held.process is jvm], "no handle to the JVM stays open")


class SourceOrderTests(WorldBase):
    def inputs(self):
        workspace = self.owner.request["workspace"]
        sources = {"fixtureWorkerPath": "C:\\W\\fixture.py", "socksSourcePath": "C:\\W\\socks.py", "httpsSourcePath": "C:\\W\\https.py",
                   "certificatePath": "C:\\W\\cert.pem", "privateKeyPath": "C:\\W\\key.pem", "trustStorePath": "C:\\W\\trust.jks"}
        for path in sources.values():
            self.owner.pin(path, "5" * 64)
        return {"schemaVersion": 1, "workspace": workspace, "fixtureRoot": str(self.root / "fixture"), "operationId": self.owner.operation,
                **sources, "runtimeImagePath": str(Path(workspace) / "runtime" / "tools" / "sing-box.exe"), "runtimeSha256": RUNTIME_SHA,
                "installedAdmissionArtifactId": "installed", "materialAdmissionArtifactId": "material", "ordinaryContextArtifactId": "context",
                "fixtureBody": "owned", "maxFixtureSeconds": 1800}

    def test_a_fresh_workspace_takes_locations_only_after_its_source_is_current_locations(self):
        inputs = self.inputs()
        with mock.patch.object(runtime_stages, "os", NtOs()), mock.patch.object(runtime_stages, "time", Clock()):
            state = runtime_stages.start_runtime(self.owner, inputs, observer(self.world))
        words = [call for call in self.owner.product.calls if "add" in call or "current-locations" in call]
        self.assertEqual("current-locations", words[0][-1], "the source is set before the first location is added")
        self.assertEqual(["Owned A", "Owned B"], self.owner.product.locations)
        self.assertTrue(state["openingStatus"]["data"]["runtimeRunning"])
        self.assertEqual(self.owner.product.runtime.pid, state["actors"]["runtime"]["pid"])
        self.assertEqual(self.owner.product.jvm.pid, state["actors"]["jvm"]["pid"])
        self.assertNotIn("JAVA_TOOL_OPTIONS", self.owner.environment, "the trust options reached only the serve child")

    def test_each_owned_location_is_a_socks_link_the_product_parser_takes(self):
        # Native 6a0a73b8: the owner answered INVALID_ARGUMENT to the socks5:// profile of Owned A, inside start_runtime.
        with mock.patch.object(runtime_stages, "os", NtOs()), mock.patch.object(runtime_stages, "time", Clock()):
            runtime_stages.start_runtime(self.owner, self.inputs(), observer(self.world))
        adds = [call for call in self.owner.product.calls if "add" in call]
        self.assertEqual(2, len(adds), "each owned location is added once")
        for call in adds:
            link = Path(call[-1]).read_text(encoding="utf-8")
            self.assertTrue(product_links.dispatched(link), link)
            self.assertTrue(link.lower().startswith("socks://127.0.0.1:23456#"), "a SOCKS location for the fixture's SOCKS5 port")
        self.assertEqual(["Owned A", "Owned B"], self.owner.product.locations)


class LinkRuleTests(WorldBase):
    """The fake product takes a location link only when the product's own parser dispatches its scheme."""

    def add(self, text):
        path = self.root / ("profile-" + uuid.uuid4().hex + ".txt")
        path.write_text(text, encoding="utf-8")
        self.owner.product.source = "current-locations"
        return self.owner.product.run(["--json", "--if-revision", str(self.owner.product.revision), "locations", "add", "--input", str(path)])

    def test_the_fake_product_refuses_a_scheme_its_parser_does_not_dispatch(self):
        schemes = product_links.schemes()
        self.assertIn("socks://", schemes)
        self.assertNotIn("socks5://", schemes)
        revision = self.owner.product.revision
        code, body = self.add("socks5://127.0.0.1:23456#Owned%20A\n")
        # The reply of operation 6a0a73b8: exit 1, a final INVALID_ARGUMENT, the revision unchanged.
        self.assertEqual((1, "INVALID_ARGUMENT", False, True, revision),
                         (code, body["code"], body["ok"], body["final"], body["configurationRevision"]))
        self.assertEqual([], self.owner.product.locations)
        for link in ("socks://127.0.0.1:23456#Owned%20A\n", "  SOCKS://127.0.0.1:23456#Owned%20B"):
            with self.subTest(link=link):
                code, body = self.add(link)
                self.assertEqual((0, "OK"), (code, body["code"]))
        self.assertEqual(["Owned A", "Owned B"], self.owner.product.locations)


class DisconnectedServeTests(WorldBase):
    """off_proxy_and_disconnected_serve over the world: explicit off, then a second serve on the same workspace."""
    LINE = "VPN Control is already running.\n"

    def off_and_second_serve(self):
        serve = self.serve()
        workspace = Path(self.owner.request["workspace"])
        actors = runtime_stages.capture_proxy_actors(self.owner, serve, self.world.native(),
                                                     str(workspace / "runtime" / "tools" / "sing-box.exe"), RUNTIME_SHA)
        return lifecycle_cases.off_proxy_and_disconnected_serve(self.owner, workspace, self.owner.product.identity,
                                                               observer(self.world), actors["owner"], actors["runtime"])

    def second(self):
        found = [child for child in self.owner.children if child.label == "lifecycle-second-serve"]
        self.assertEqual(1, len(found), "one second serve")
        value = found[0].completed()
        return value.returncode, value.stdout, value.stderr

    def test_the_existing_owners_line_on_stderr_is_the_known_result(self):
        # Native b3d71dca: child 40 printed nothing on stdout and this one line on stderr, then exited 0.
        result = self.off_and_second_serve()
        self.assertEqual((0, "", self.LINE), self.second())
        self.assertFalse(result["closing"]["data"]["runtimeRunning"])
        self.assertIsNone(self.owner.product.jvm.exit_code, "the second serve left the original owner running")
        self.assertIn("explicit-off-disconnected-serve-observed", [kind for kind, _ in self.owner.events])

    def test_stdout_output_a_second_line_or_a_nonzero_exit_still_refuses(self):
        for name, reply in (("line-on-stdout", (0, self.LINE, "")), ("stdout-beside-the-line", (0, "{}\n", self.LINE)),
                            ("second-stderr-line", (0, "", "Picked up JAVA_TOOL_OPTIONS: -Dx=y\n" + self.LINE)),
                            ("existing-owner-refused", (2, "", "OUTCOME_UNKNOWN\n")), ("nonzero-exit", (2, "", self.LINE))):
            with self.subTest(name=name):
                self.setUp()
                self.owner.product.adoption = reply
                with self.assertRaisesRegex(AssertionError, "^second-serve-existing-owner-result$"):
                    self.off_and_second_serve()
                self.assertEqual(reply, self.second())


class DriverOwner:
    """The dedicated driver's Owner: pinned reviewed sources, stub stage modules and one product."""
    SOURCE = "C:\\ProgramData\\VpnControlOrdinaryTask-op\\"

    def __init__(self, root, variant):
        self.root, self.operation = root, str(uuid.uuid4())
        self.children, self.calls, self.by_path, self.modules = [], [], {}, {}
        self.request = {"workspace": str(root / "workspace"), "cliPath": CLI, "productVersion": PRODUCT_VERSION}
        # What the installed launcher prints for the driver's own --help and --version.
        self.probe_output = {"--help": "Usage: vpn-control-cli [OPTIONS] COMMAND\n", "--version": "VPN Control " + PRODUCT_VERSION + "\n"}
        self.raw_limit = 16 * 1024 * 1024
        self.variant = variant
        self.running = True
        self.failure = None
        paths = {"runtime": "agent_tools/windows_lifecycle_runtime_stages.py", "observer": "scripts/windows_broker_fixture_observer.py",
                 "branches": "agent_tools/windows_runtime_branch_cases.py"}
        self.inputs = {"schemaVersion": 1, "variant": variant, "sourceSha": "a" * 40, "gui": None,
                       "modules": {role: self.source(name) for role, name in paths.items() if role != "branches" or variant in dedicated_driver.BRANCH_VARIANTS},
                       "runtime": {"schemaVersion": 1, "operationId": self.operation, "installedAdmissionArtifactId": "installed",
                                   "ordinaryContextArtifactId": "context",
                                   "fixtureWorkerPath": self.source("agent_tools/windows_lifecycle_runtime_fixture_worker.py"),
                                   "socksSourcePath": self.source("scripts/integration/socks_http_fixture.py"),
                                   "httpsSourcePath": self.source("scripts/integration/https_subscription_relay_fixture.py"),
                                   "runtimeImagePath": str(root / "workspace" / "runtime" / "tools" / "sing-box.exe"), "runtimeSha256": RUNTIME_SHA}}
        if variant in dedicated_driver.BRANCH_VARIANTS:
            tool = self.SOURCE + "sing-box.exe"
            self.by_path[tool.casefold()] = types.SimpleNamespace(record={"sha256": RUNTIME_SHA}, directory=False)
            traffic_input = self.SOURCE + "proxy-traffic.json"
            self.by_path[traffic_input.casefold()] = types.SimpleNamespace(record={"sha256": "6" * 64}, directory=False)
            self.by_path[proxy.POWERSHELL.casefold()] = types.SimpleNamespace(record={"sha256": "7" * 64}, directory=False)
            self.inputs["branch"] = {"schemaVersion": 1, "fixtureRuntimeToolPath": tool, "runtimeSha256": RUNTIME_SHA,
                                     "listenerScriptPath": self.source("agent_tools/windows_runtime_tcp_listeners.ps1"),
                                     "powerShellPath": proxy.POWERSHELL, "trafficWorkerPath": self.source("agent_tools/windows_lifecycle_traffic_worker.py"),
                                     "trafficInputPath": traffic_input, "installedAdmissionArtifactId": "installed", "ordinaryContextArtifactId": "context"}
        self.harness = types.SimpleNamespace(LIFECYCLE_INPUTS=self.inputs, SYSTEM_COLLECTOR_CLOSE_HOLD=None)

    def source(self, relative):
        raw = source_bytes()[relative]
        path = self.SOURCE + relative.rsplit("/", 1)[1]
        record = {"sha256": hashlib.sha256(raw).hexdigest(), "nativeIdentity": {"sizeBytes": len(raw)}}
        self.by_path[path.casefold()] = types.SimpleNamespace(record=record, directory=False, digest=lambda as_bytes=False, maximum=0: raw)
        return path

    def guard(self):
        pass

    def event(self, kind, value):
        self.calls.append((kind, value))

    def park(self, reason, error=None):
        self.parked = reason
        raise Parked(reason)

    def module(self, path, name):
        self.calls.append(("module", name))
        return self.modules[name]

    def child(self, label, argv=None, *, terminal=None):
        child = types.SimpleNamespace(label=label, terminal=terminal, exit_code=0)
        child.process = types.SimpleNamespace(poll=lambda: child.exit_code if getattr(child, "ended", False) else None)
        if argv is not None:  # The launcher's own --help or --version: it ends at once with its output.
            self.calls.append(("child", label, tuple(argv)))
            output = self.probe_output[argv[-1]]
            child.ended, child.terminal = True, {"exitCode": 0, "eof": {"stdout": True, "stderr": True}}
            child.completed = lambda: subprocess.CompletedProcess(argv, 0, output, "")

        def wait():
            if child.terminal is None:
                if label == "lifecycle-traffic":
                    child.terminal = {"exitCode": 0, "eof": {"stdout": True, "stderr": True}}
                elif not getattr(child, "ended", False):
                    raise AssertionError("never ends by itself: " + label)
                else:
                    child.terminal = {"exitCode": child.exit_code, "eof": {"stdout": True, "stderr": True}}
            self.calls.append(("wait", label))
            return child.terminal
        child.wait = wait
        self.children.append(child)
        return child


def driver_world(test, variant, *, fail_at, error=None):
    """Stub stages whose one step fails with a finished, known outcome; the closing steps are real calls on the peer."""
    owner = DriverOwner(test.root, variant)
    error = error or AssertionError("original-operation-unexpected-terminal")
    state = {}

    def failing(step):
        if step == fail_at:
            raise error

    def fail(step):
        owner.calls.append(step)
        failing(step)

    def start(*args):
        owner.calls.append("start-runtime")
        state.update(workspace=test.root / "workspace", identity="controller-1", serve=owner.child("serve"),
                     fixture=owner.child("owned-runtime-fixture"), actors={"owner": {"pid": 1}, "runtime": {"pid": 2}},
                     ready={"advertisedSocksPort": 23456}, runtimeArtifact={})
        return state

    def stop_fixture(owner_, state_):
        # As the stage does: one stop record, then the fixture's own terminal; anything but exit 0 is the stage's failure.
        owner.calls.append("stop-fixture")
        fixture = state_["fixture"]
        if not getattr(fixture, "ended", False):
            fixture.ended, fixture.exit_code = True, 1 if fail_at == "stop-fixture" else 0
        if fixture.wait()["exitCode"] != 0:
            raise AssertionError("original-owned-fixture-terminal")

    def read(owner_, workspace, identity, word):
        owner.calls.append(("public", word))
        if word == "off":
            owner.running = False
        if word == "quit":
            failing("quit")
            state["serve"].ended = True
            for child in owner.children:
                if child.label == "lifecycle-gui":
                    child.ended = True
        return {"data": {"runtimeRunning": owner.running}}

    def off_and_serve(*args):
        fail("off-and-disconnected-serve")
        owner.running = False

    owner.modules["_owned_dedicated_runtime_stages"] = types.SimpleNamespace(
        validate_inputs=lambda *args: owner.calls.append("validate-runtime"), start_runtime=start,
        find_best=lambda *args: fail("find-best"), capture_proxy_actors=lambda *args: fail("capture") or state["actors"],
        stop_fixture=stop_fixture)
    owner.modules["_owned_dedicated_proxy_observer"] = types.SimpleNamespace(WindowsNative=lambda: "native")
    owner.modules["_owned_dedicated_runtime_branches"] = types.SimpleNamespace(
        config_case=lambda *args: fail("branch-config"), failure_case=lambda *args: fail("branch-failure"),
        close_fixture_files_after_off=lambda *args: owner.calls.append("files-close-after-off"))
    cases = types.SimpleNamespace(CRASH_EXIT=0xE0421001, read=read, off_proxy_and_disconnected_serve=off_and_serve)
    return owner, cases, state


class KnownFailureTests(unittest.TestCase):
    """A finished, known wrong outcome closes the row and ends 1; anything else still parks."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_driver(self, owner, cases):
        return dedicated_driver.run_lifecycle(owner, cases, owner.harness)

    def test_a_finished_wrong_find_best_outcome_closes_what_the_row_started_and_ends_one(self):
        owner, cases, state = driver_world(self, "find-best-success", fail_at="find-best")
        self.assertEqual(1, self.run_driver(owner, cases))
        steps = [call for call in owner.calls if not (isinstance(call, tuple) and call[0] == "module")]
        closing = steps[steps.index("find-best") + 1:]
        kinds = [call[0] if isinstance(call, tuple) else call for call in closing]
        # The stop's own wait for the fixture, then the closing's read of that same terminal.
        self.assertEqual(["dedicated-proxy-lifecycle-known-failure-closing", "public", "public", "public", "stop-fixture", "wait", "wait",
                          "public", "wait", "dedicated-proxy-lifecycle-known-failure"], kinds)
        self.assertEqual([("public", "status"), ("public", "off"), ("public", "status"), ("public", "quit")],
                         [call for call in closing if isinstance(call, tuple) and call[0] == "public"])
        self.assertEqual(1, steps.count("find-best"), "the failed oracle never runs again")
        self.assertTrue(all(child.terminal is not None for child in owner.children))
        self.assertEqual("original-operation-unexpected-terminal", closing[-1][1]["reason"])
        self.assertEqual(0, closing[-1][1]["fixtureExitCode"])

    def test_every_variant_but_tun_closes_a_known_failure(self):
        for variant, step in (("find-best-cancel", "find-best"), ("generated", "branch-config"), ("prepare-failure", "branch-failure"),
                              ("find-best-verification-failure", "off-and-disconnected-serve"), ("custom", "stop-fixture")):
            with self.subTest(variant=variant):
                owner, cases, _ = driver_world(self, variant, fail_at=step)
                self.assertEqual(1, self.run_driver(owner, cases))
                self.assertIn(("public", "quit"), owner.calls)
                self.assertTrue(all(child.terminal is not None for child in owner.children))

    def test_an_unknown_error_keeps_every_child_and_closes_nothing(self):
        owner, cases, state = driver_world(self, "find-best-success", fail_at="find-best", error=RuntimeError("observation unknown"))
        with self.assertRaisesRegex(RuntimeError, "observation unknown"):
            self.run_driver(owner, cases)
        self.assertNotIn(("public", "quit"), owner.calls)
        # Only the launcher's --help and --version, which ended before the runtime started, have a terminal.
        self.assertEqual([state["serve"], state["fixture"]], [child for child in owner.children if child.terminal is None])

    def test_a_child_whose_outcome_is_open_parks(self):
        owner, cases, _ = driver_world(self, "find-best-success", fail_at="find-best")
        owner.modules["_owned_dedicated_runtime_stages"].find_best = lambda *args: (owner.child("public-cli"), (_ for _ in ()).throw(AssertionError("x")))
        with self.assertRaisesRegex(Parked, "dedicated-known-failure-child-outcome-open"):
            self.run_driver(owner, cases)
        self.assertNotIn(("public", "off"), owner.calls)

    def test_a_running_sampler_is_waited_for_and_kept_as_evidence(self):
        owner, cases, _ = driver_world(self, "find-best-success", fail_at="find-best")
        stages = owner.modules["_owned_dedicated_runtime_stages"]
        stages.find_best = lambda *args: (owner.child("lifecycle-traffic"), (_ for _ in ()).throw(AssertionError("x")))
        self.assertEqual(1, self.run_driver(owner, cases))
        self.assertLess(owner.calls.index(("wait", "lifecycle-traffic")), owner.calls.index(("public", "off")))

    def test_a_closing_step_that_fails_is_not_retried(self):
        owner, cases, _ = driver_world(self, "find-best-success", fail_at="find-best")
        read = cases.read

        def refusing(owner_, workspace, identity, word):
            if word == "off":
                raise AssertionError("public-cli-owner-envelope")
            return read(owner_, workspace, identity, word)
        cases.read = refusing
        with self.assertRaisesRegex(AssertionError, "public-cli-owner-envelope"):
            self.run_driver(owner, cases)
        self.assertNotIn(("public", "quit"), owner.calls)
        self.assertEqual(1, owner.calls.count("find-best"))

    def test_a_tun_row_keeps_its_own_known_ends(self):
        owner, cases, _ = driver_world(self, "find-best-success", fail_at="tun-finish")
        owner.inputs["variant"] = "restart-deny"
        owner.inputs["tun"] = {"schemaVersion": 1, "variant": "restart-deny"}
        owner.inputs["modules"]["tun"] = owner.source("agent_tools/windows_tun_stages.py")
        owner.modules["_owned_dedicated_tun_stages"] = types.SimpleNamespace(
            begin=lambda *args: "lease", finish=lambda *args: (_ for _ in ()).throw(AssertionError("tun-finish")))
        with self.assertRaisesRegex(AssertionError, "tun-finish"):
            self.run_driver(owner, cases)
        self.assertNotIn(("public", "off"), owner.calls)

    @staticmethod
    def lease(owner):
        """One of the fixture's own data leases, which its stop closes."""
        lease = types.SimpleNamespace(handle=8)
        lease.close = lambda: owner.calls.append("fixture-lease-closed") or setattr(lease, "handle", None)
        owner.fixture_data_leases = [lease]
        return lease

    def test_a_fixture_that_ended_by_itself_still_closes_a_known_failure(self):
        # Its 1,800 s lease ran out, or it crashed, and the oracle saw that: a known failure, never a parked owner.
        owner, cases, state = driver_world(self, "find-best-cancel", fail_at=None)
        lease = self.lease(owner)

        def ended(*args):
            state["fixture"].ended, state["fixture"].exit_code = True, 1
            raise AssertionError("original-fixture-ended-before-https-work")
        owner.modules["_owned_dedicated_runtime_stages"].find_best = ended
        self.assertEqual(1, self.run_driver(owner, cases))
        self.assertNotIn("stop-fixture", owner.calls, "no stop record goes to a fixture that already ended")
        self.assertEqual(["fixture-lease-closed", ("public", "quit")], [call for call in owner.calls if call in ("fixture-lease-closed", ("public", "quit"))])
        self.assertIsNone(lease.handle)
        events = [call[1] for call in owner.calls if isinstance(call, tuple) and call[0] == "dedicated-proxy-lifecycle-known-failure"]
        self.assertEqual([(1, "original-fixture-ended-before-https-work")], [(value["fixtureExitCode"], value["reason"]) for value in events])

    def test_a_fixture_lease_that_ends_as_the_closing_stops_it_is_still_known(self):
        owner, cases, state = driver_world(self, "generated", fail_at="branch-config")
        self.lease(owner)
        stages = owner.modules["_owned_dedicated_runtime_stages"]
        stop = stages.stop_fixture

        def lease_ran_out(owner_, state_):  # The stop record went out as the lease ended: the fixture's own exit 1.
            state_["fixture"].ended, state_["fixture"].exit_code = True, 1
            stop(owner_, state_)
        stages.stop_fixture = lease_ran_out
        self.assertEqual(1, self.run_driver(owner, cases))
        self.assertEqual(1, owner.calls.count("stop-fixture"), "one stop record")
        self.assertLess(owner.calls.index("fixture-lease-closed"), owner.calls.index(("public", "quit")))

    def test_a_stop_that_fails_before_the_fixture_ends_is_not_excused(self):
        owner, cases, state = driver_world(self, "find-best-success", fail_at="find-best")
        stages = owner.modules["_owned_dedicated_runtime_stages"]

        def publish_refused(owner_, state_):
            owner.calls.append("stop-fixture")
            raise AssertionError("owned-create-only-data-publication")
        stages.stop_fixture = publish_refused
        with self.assertRaisesRegex(AssertionError, "owned-create-only-data-publication"):
            self.run_driver(owner, cases)
        self.assertNotIn(("public", "quit"), owner.calls)
        self.assertIsNone(state["fixture"].terminal)

    def test_an_off_or_a_quit_that_had_no_effect_is_issued_once_more_by_the_closing(self):
        # Both earlier outcomes were known, so neither is an unknown step replayed; a second failure would park.
        owner, cases, _ = driver_world(self, "find-best-success", fail_at=None)

        def off_without_effect(*args):
            cases.read(owner, None, None, "off")
            owner.running = True
            raise AssertionError("explicit-off-runtime-state")
        cases.off_proxy_and_disconnected_serve = off_without_effect
        self.assertEqual(1, self.run_driver(owner, cases))
        self.assertEqual(2, owner.calls.count(("public", "off")))
        owner, cases, _ = driver_world(self, "find-best-success", fail_at=None)
        read, refused = cases.read, []

        def refusing_once(owner_, workspace, identity, word):
            if word == "quit" and not refused:
                refused.append(word)
                owner.calls.append(("public", word))
                raise AssertionError("public-cli-owner-envelope")
            return read(owner_, workspace, identity, word)
        cases.read = refusing_once
        self.assertEqual(1, self.run_driver(owner, cases))
        self.assertEqual(2, owner.calls.count(("public", "quit")))


class StartOwner(Owner):
    """The dedicated driver's owner over the world: reviewed sources held at their digests, the real stage module."""
    SOURCE = DriverOwner.SOURCE
    source = DriverOwner.source

    def __init__(self, root, world):
        super().__init__(root, world)
        self.raw_limit = 16 * 1024 * 1024
        self.loaded = []

    def module(self, path, name):
        self.loaded.append(name)
        return {"_owned_dedicated_runtime_stages": runtime_stages, "_owned_dedicated_proxy_observer": observer(self.world)}[name]


class StartFailureTests(WorldBase):
    """A reviewed oracle that fails inside start_runtime, through the real driver, stage and closing over the world."""

    def setUp(self):
        super().setUp()
        self.owner = StartOwner(self.root, self.world)
        for patcher in (mock.patch.object(runtime_stages, "os", NtOs()), mock.patch.object(runtime_stages, "time", Clock())):
            patcher.start()
            self.addCleanup(patcher.stop)

    def harness(self, variant="find-best-success"):
        owner = self.owner
        workspace = owner.request["workspace"]
        material = {"certificatePath": "C:\\W\\cert.pem", "privateKeyPath": "C:\\W\\key.pem", "trustStorePath": "C:\\W\\trust.jks"}
        for path in material.values():
            owner.pin(path, "5" * 64)
        runtime = {"schemaVersion": 1, "workspace": workspace, "fixtureRoot": str(self.root / "fixture"), "operationId": owner.operation,
                   "fixtureWorkerPath": owner.source("agent_tools/windows_lifecycle_runtime_fixture_worker.py"),
                   "socksSourcePath": owner.source("scripts/integration/socks_http_fixture.py"),
                   "httpsSourcePath": owner.source("scripts/integration/https_subscription_relay_fixture.py"), **material,
                   "runtimeImagePath": str(Path(workspace) / "runtime" / "tools" / "sing-box.exe"), "runtimeSha256": RUNTIME_SHA,
                   "installedAdmissionArtifactId": "installed", "materialAdmissionArtifactId": "material",
                   "ordinaryContextArtifactId": "context", "fixtureBody": "owned", "maxFixtureSeconds": 1800}
        inputs = {"schemaVersion": 1, "variant": variant, "sourceSha": "a" * 40, "gui": None, "runtime": runtime,
                  "modules": {"runtime": owner.source("agent_tools/windows_lifecycle_runtime_stages.py"),
                              "observer": owner.source("scripts/windows_broker_fixture_observer.py")}}
        if variant in dedicated_driver.TUN_VARIANTS:
            inputs["modules"]["tun"] = owner.source("agent_tools/windows_tun_stages.py")
            inputs["tun"] = {"schemaVersion": 1, "variant": variant}
        return types.SimpleNamespace(LIFECYCLE_INPUTS=inputs, SYSTEM_COLLECTOR_CLOSE_HOLD=None)

    def run_driver(self, variant="find-best-success", harness=None):
        return dedicated_driver.run_lifecycle(self.owner, lifecycle_cases, harness or self.harness(variant))

    def commands(self):
        """The commands the product received, without their JSON, controller and revision flags; an add without its path."""
        found = []
        for call in self.owner.product.calls:
            words = list(call[1:])
            if words[:1] == ["--controller-id"]:
                words = words[2:]
            if words[:1] == ["--if-revision"]:
                words = words[2:]
            found.append(tuple(words[:2]) if words[:2] == ["locations", "add"] else tuple(words))
        return found

    def known(self):
        return [value for kind, value in self.owner.events if kind == "dedicated-proxy-lifecycle-known-failure"]

    def assert_closed(self):
        self.assertTrue(all(child.terminal is not None for child in self.owner.children), "every child the row started has ended")
        self.assertEqual(0, self.owner.product.jvm.exit_code, "the serve's owner quit")
        self.assertTrue((self.root / "fixture" / "stop.json").exists(), "the fixture ended on its own stop record")
        self.assertEqual(1, self.commands().count(("quit",)))

    def test_a_refused_owned_location_closes_the_fixture_and_serve_and_ends_one(self):
        # Native 6a0a73b8: `locations add` answered INVALID_ARGUMENT inside start_runtime, and the AssertionError
        # left the fixture and serve running, so the owner parked over an outcome that was known.
        self.owner.product.refusals[("locations", "add")] = "INVALID_ARGUMENT"
        self.assertEqual(1, self.run_driver())
        commands = self.commands()
        self.assertEqual(1, commands.count(("locations", "add")), "the refused add is never sent again")
        # The closing's status, then the fixture stop's own status, then quit; no off for a runtime that never ran.
        self.assertEqual([("status",), ("status",), ("quit",)], commands[commands.index(("locations", "add")) + 1:])
        self.assert_closed()
        self.assertEqual([("runtime-public-cli-exit-stderr", 0)], [(value["reason"], value["fixtureExitCode"]) for value in self.known()])

    def test_a_start_that_fails_with_its_runtime_on_turns_it_off_before_the_closing_quits(self):
        harness = self.harness()
        harness.LIFECYCLE_INPUTS["runtime"]["runtimeSha256"] = "9" * 64  # The runtime the owner started is not the admitted one.
        self.assertEqual(1, self.run_driver(harness=harness))
        commands = self.commands()
        self.assertEqual([("status",), ("status",), ("off",), ("status",), ("status",), ("quit",)], commands[commands.index(("on",)) + 1:])
        self.assertFalse(self.owner.product.running)
        self.assertEqual(0, self.owner.product.runtime.exit_code)
        self.assert_closed()
        self.assertEqual(["one-exact-owned-proxy-runtime"], [value["reason"] for value in self.known()])

    def test_a_tun_row_whose_start_fails_closes_the_same_way_before_any_tun_stage(self):
        # Nothing of TUN has begun at start: no pending B and no restart, so no prompt or broker is left to its stages.
        self.owner.product.refusals[("locations", "add")] = "INVALID_ARGUMENT"
        self.assertEqual(1, self.run_driver("restart-deny"))
        self.assertNotIn("_owned_dedicated_tun_stages", self.owner.loaded)
        self.assertEqual(["restart-deny"], [value["variant"] for value in self.known()])
        self.assert_closed()

    def test_a_start_that_fails_before_its_serve_exists_still_escapes_and_closes_nothing(self):
        self.owner.ready_changes["operationId"] = str(uuid.uuid4())  # A ready record of another operation.
        with self.assertRaisesRegex(AssertionError, "^actual-runtime-fixture-endpoints$"):
            self.run_driver()
        self.assertNotIn("serve", [child.label for child in self.owner.children])
        self.assertEqual([], self.owner.product.calls)
        self.assertIsNone(getattr(self.owner, "runtime_start_state", None))
        self.assertEqual(["owned-runtime-fixture"], [child.label for child in self.owner.children if child.terminal is None])

    def test_a_serve_whose_controller_was_never_admitted_still_escapes_and_closes_nothing(self):
        self.owner.product.running = True  # A fresh workspace that reports a running runtime is no owner this row started.
        with self.assertRaisesRegex(AssertionError, "^fresh-runtime-owner-readiness$"):
            self.run_driver()
        self.assertEqual([("status",)], self.commands())
        self.assertIsNone(getattr(self.owner, "runtime_start_state", None))
        self.assertEqual(["owned-runtime-fixture", "serve"], [child.label for child in self.owner.children if child.terminal is None])

    def test_an_unknown_error_after_the_serve_answered_still_escapes_and_closes_nothing(self):
        self.owner.product.garbled.add(("locations", "list"))
        with self.assertRaises(json.JSONDecodeError):
            self.run_driver()
        self.assertFalse({("off",), ("quit",)} & set(self.commands()))
        self.assertFalse((self.root / "fixture" / "stop.json").exists())
        self.assertEqual(["owned-runtime-fixture", "serve"], [child.label for child in self.owner.children if child.terminal is None])


class InstalledVersionTests(unittest.TestCase):
    """installed-package needs --version under the ordinary token: the driver asks the installed launcher first."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_a_row_asks_the_installed_launcher_for_its_version_before_its_runtime_starts(self):
        for variant in ("find-best-success", "custom"):
            with self.subTest(variant=variant):
                owner, cases, _ = driver_world(self, variant, fail_at=None)
                self.assertEqual(0, dedicated_driver.run_lifecycle(owner, cases, owner.harness))
                probes = [call for call in owner.calls if isinstance(call, tuple) and call[0] == "child"]
                workspace = owner.request["workspace"]
                self.assertEqual([("child", "help", (CLI, "--state-dir", workspace, "--help")),
                                  ("child", "version", (CLI, "--state-dir", workspace, "--version"))], probes)
                self.assertLess(owner.calls.index(probes[-1]), owner.calls.index("start-runtime"))

    def test_a_launcher_that_reports_another_version_ends_the_row_before_its_runtime(self):
        owner, cases, _ = driver_world(self, "find-best-success", fail_at=None)
        owner.probe_output["--version"] = "VPN Control 2.2.13\n"
        with self.assertRaisesRegex(ValueError, "^dedicated-static-public-launcher-probe$"):
            dedicated_driver.run_lifecycle(owner, cases, owner.harness)
        self.assertNotIn("start-runtime", owner.calls)

    def test_a_probe_that_left_owner_state_ends_the_row_before_its_runtime(self):
        owner, cases, _ = driver_world(self, "generated", fail_at=None)
        Path(owner.request["workspace"]).mkdir()
        with self.assertRaisesRegex(ValueError, "^dedicated-static-launch-created-owner-state$"):
            dedicated_driver.run_lifecycle(owner, cases, owner.harness)
        self.assertNotIn("start-runtime", owner.calls)


class HarnessTests(unittest.TestCase):
    """The generated literal harness is exactly what the dedicated driver admits, for every variant."""

    OPERATION = "11111111-2222-4333-8444-555555555555"

    def paths(self, variant):
        workspace = "C:\\ProgramData\\VpnControlOrdinaryTask-" + self.OPERATION
        root = "C:\\Users\\recovery\\AppData\\Local\\VpnControlOrdinary-" + self.OPERATION
        paths = {"productWorkspace": root + "\\workspace", "operationRoot": root, "installed": "C:\\Users\\recovery\\AppData\\Local\\vpn-control"}
        for role, leaf in (("runtime", "windows_lifecycle_runtime_stages.py"), ("observer", "windows_broker_fixture_observer.py"),
                           ("fixture", "windows_lifecycle_runtime_fixture_worker.py"), ("socks", "socks_http_fixture.py"),
                           ("https", "https_subscription_relay_fixture.py"), ("traffic", "windows_lifecycle_traffic_worker.py"),
                           ("branches", "windows_runtime_branch_cases.py"), ("listener", "windows_runtime_tcp_listeners.ps1"),
                           (proxy.RUNTIME_ROLE, proxy.RUNTIME_LEAF), *proxy.GENERATED.items()):
            paths["file:" + role] = workspace + "\\" + leaf
        return paths

    def admitted(self, variant):
        """The driver's own literal and input checks over a peer holding each named file at its reviewed digest."""
        paths = self.paths(variant)
        raw = proxy.harness(variant, operation=self.OPERATION, paths=paths, runtime_sha256=RUNTIME_SHA, source_sha="b" * 40,
                            admissions={"installed": "sha256-" + "c" * 64, "material": "proxy-material-x", "context": "windows-context-x",
                                        "fixture": "proxy-fixture-x", "source": "sha256-" + "d" * 64})
        sources = {"file:runtime": "agent_tools/windows_lifecycle_runtime_stages.py", "file:observer": "scripts/windows_broker_fixture_observer.py",
                   "file:fixture": "agent_tools/windows_lifecycle_runtime_fixture_worker.py", "file:socks": "scripts/integration/socks_http_fixture.py",
                   "file:https": "scripts/integration/https_subscription_relay_fixture.py", "file:traffic": "agent_tools/windows_lifecycle_traffic_worker.py",
                   "file:branches": "agent_tools/windows_runtime_branch_cases.py", "file:listener": "agent_tools/windows_runtime_tcp_listeners.ps1"}
        by_path = {}
        for key, relative in sources.items():
            body = source_bytes()[relative]
            by_path[paths[key].casefold()] = types.SimpleNamespace(directory=False, digest=lambda as_bytes=False, maximum=0, body=body: body,
                                                                   record={"sha256": hashlib.sha256(body).hexdigest(), "nativeIdentity": {"sizeBytes": len(body)}})
        for key in ("file:" + proxy.RUNTIME_ROLE, "file:trafficInput", "file:certificate", "file:privateKey", "file:trustStore"):
            by_path[paths[key].casefold()] = types.SimpleNamespace(directory=False, record={"sha256": RUNTIME_SHA})
        for path in (proxy.POWERSHELL, paths["installed"] + "\\vpn-control.exe"):
            by_path[path.casefold()] = types.SimpleNamespace(directory=False, record={"sha256": "e" * 64})
        harness_path = paths["file:harness"]
        by_path[harness_path.casefold()] = types.SimpleNamespace(directory=False, digest=lambda as_bytes=False, maximum=0: raw,
                                                                 record={"sha256": hashlib.sha256(raw).hexdigest(), "nativeIdentity": {"sizeBytes": len(raw)}})
        loaded = types.ModuleType("_proxy_harness_" + variant.replace("-", "_"))
        exec(compile(raw, harness_path, "exec"), loaded.__dict__)
        owner = types.SimpleNamespace(by_path=by_path, request={"harnessPath": harness_path}, operation=self.OPERATION,
                                      raw_limit=16 * 1024 * 1024, module=lambda path, name: loaded)
        harness = dedicated_driver.literal_harness(owner, "windows-proxy-lifecycle")
        return raw, dedicated_driver.lifecycle_inputs(owner, harness.LIFECYCLE_INPUTS), paths

    def test_every_variant_the_driver_accepts_has_an_admitted_harness(self):
        self.assertEqual(set(proxy.VARIANTS), set(dedicated_driver.PROXY_VARIANTS | dedicated_driver.BRANCH_VARIANTS))
        for variant in proxy.VARIANTS:
            with self.subTest(variant=variant):
                raw, inputs, paths = self.admitted(variant)
                raw.decode("ascii")
                self.assertEqual(variant, inputs["variant"])
                self.assertEqual(paths["productWorkspace"] + "\\runtime\\tools\\sing-box.exe", inputs["runtime"]["runtimeImagePath"])
                self.assertEqual(variant == "gui-pending", inputs["gui"] is not None)
                self.assertEqual(variant in dedicated_driver.BRANCH_VARIANTS, "branch" in inputs)
                self.assertEqual(1800, inputs["runtime"]["maxFixtureSeconds"])

    def test_a_mutated_harness_is_refused_by_the_driver(self):
        raw, _, paths = self.admitted("generated")
        for name, change in (("statement", raw + b"import os\n"), ("constant", raw + b"EXTRA = 1\n"),
                             ("callable", raw.replace(b"SYSTEM_COLLECTOR_CLOSE_HOLD = None", b"SYSTEM_COLLECTOR_CLOSE_HOLD = print"))):
            with self.subTest(name=name), mock.patch.object(proxy, "harness", lambda *args, **kwargs: change):
                with self.assertRaises(ValueError):
                    self.admitted("generated")

    def test_the_sampler_input_is_what_the_traffic_worker_reads(self):
        from agent_tools import windows_lifecycle_traffic_worker as worker
        for variant in sorted(proxy.TRAFFIC_VARIANTS):
            with self.subTest(variant=variant):
                value = json.loads(proxy.traffic_input(variant, self.OPERATION))
                worker.validate(value)
                self.assertEqual(proxy.fixture_body(self.OPERATION).encode().hex(), value["expectedBodyHex"])
        self.assertEqual(("harness", "certificate", "privateKey", "trustStore"), proxy.generated_roles("find-best-cancel"))
        with self.assertRaisesRegex(ValueError, "proxy_variant"):
            proxy.generated_roles("scheduled-refresh")


class MaterialTests(unittest.TestCase):
    """The TLS material: one localhost certificate, its key and a JKS trust store holding it."""

    @classmethod
    def setUpClass(cls):
        # One 2,048-bit key per class: generating it is the slow part. The handshake checks validity on the real clock.
        cls.tls = proxy.material(random.Random(7).getrandbits, time.time())

    def write(self, directory):
        paths = {}
        for role, leaf in (("certificate", "cert.pem"), ("privateKey", "key.pem"), ("trustStore", "trust.jks")):
            paths[role] = Path(directory) / leaf
            paths[role].write_bytes(self.tls[role])
        return paths

    def test_a_tls_handshake_in_memory_verifies_localhost_against_it(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write(directory)
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.minimum_version = ssl.TLSVersion.TLSv1_2
            server.load_cert_chain(paths["certificate"], paths["privateKey"])
            client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client.load_verify_locations(paths["certificate"])
            pipes = [ssl.MemoryBIO() for _ in range(4)]
            near = client.wrap_bio(pipes[0], pipes[1], server_hostname="localhost")
            far = server.wrap_bio(pipes[2], pipes[3], server_side=True)
            done = set()
            for _ in range(20):
                for name, side, outgoing, incoming in (("client", near, pipes[1], pipes[2]), ("server", far, pipes[3], pipes[0])):
                    if name not in done:
                        try:
                            side.do_handshake()
                            done.add(name)
                        except ssl.SSLWantReadError:
                            pass
                    incoming.write(outgoing.read())
                if done == {"client", "server"}:
                    break
            self.assertEqual({"client", "server"}, done)
            self.assertEqual((("DNS", "localhost"),), near.getpeercert()["subjectAltName"])

    def test_the_material_is_lf_only_pem_and_the_store_has_one_trusted_entry(self):
        for role in ("certificate", "privateKey"):
            self.assertNotIn(b"\r", self.tls[role])
            self.assertRegex(self.tls[role].decode("ascii"), r"\A-----BEGIN [A-Z ]+-----\n(?:[A-Za-z0-9+/=]{1,64}\n)+-----END [A-Z ]+-----\n\Z")
        store = self.tls["trustStore"]
        self.assertEqual(bytes.fromhex("feedfeed0000000200000001" "00000002"), store[:16])
        key = b"".join(bytes((0, ord(character))) for character in "changeit") + b"Mighty Aphrodite"
        self.assertEqual(hashlib.sha1(key + store[:-20], usedforsecurity=False).digest(), store[-20:])
        der = base64.b64decode(b"".join(self.tls["certificate"].splitlines()[1:-1]))
        self.assertIn(der, store, "the trusted entry is the fixture's own certificate")

    @unittest.skipUnless(shutil.which("java"), "a JDK checks the store as the product's JVM reads it; hosted runners have one")
    def test_a_jdk_trust_manager_trusts_it_for_localhost(self):
        program = r"""
import java.io.*; import java.security.*; import java.security.cert.*; import javax.net.ssl.*;
public class Check { public static void main(String[] a) throws Exception {
  KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
  try (InputStream in = new FileInputStream(a[0])) { store.load(in, "changeit".toCharArray()); }
  TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(store);
  X509TrustManager manager = (X509TrustManager) factory.getTrustManagers()[0];
  X509Certificate certificate; try (InputStream in = new FileInputStream(a[1])) { certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in); }
  manager.checkServerTrusted(new X509Certificate[]{certificate}, "ECDHE_RSA");
  sun.security.util.HostnameChecker.getInstance(sun.security.util.HostnameChecker.TYPE_TLS).match("localhost", certificate);
  System.out.println("trusted " + store.getType());
}}
"""
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("JAVA_TOOL", "_JAVA", "JDK_JAVA"))}
        # A single source file runs from JDK 11; an older default java, or a stub without a runtime, cannot check it.
        version = subprocess.run(["java", "--version"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, env=environment)
        major = re.match(r"\S+ (\d+)", version.stdout)
        if version.returncode or major is None or int(major[1]) < 11:
            self.skipTest("no JDK 11 or later on PATH")
        with tempfile.TemporaryDirectory() as directory:
            paths = self.write(directory)
            source = Path(directory) / "Check.java"
            source.write_text(program, encoding="ascii")
            result = subprocess.run(["java", "--add-exports", "java.base/sun.security.util=ALL-UNNAMED", str(source), str(paths["trustStore"]),
                                     str(paths["certificate"])], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300, env=environment)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("trusted", result.stdout)


if __name__ == "__main__":
    unittest.main()
