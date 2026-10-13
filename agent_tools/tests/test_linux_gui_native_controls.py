"""Portable controls executing retained, actually used Linux GUI harness source.

OS seams below observe commands/events; they never start a process, load Xlib,
touch /proc, send a signal, contact a guest, or read runtime/private artifacts.
Native WM dispatch/callback, real traffic, and MCP equivalence remain native gates.
Set LINUX_GUI_CAUSAL_VARIANT=before for the preserved causal RED implementation.
"""
import ast
import contextlib
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch


FIXTURES = Path(__file__).parent / "fixtures" / "linux_gui_native_controls"
SOURCE = json.loads((FIXTURES / "source_fragments.json").read_text())
VARIANT = os.environ.get("LINUX_GUI_CAUSAL_VARIANT", "fixed")
if VARIANT not in ("before", "fixed"):
    raise RuntimeError("invalid causal variant")


DRIVER = Path(__file__).resolve().parents[2] / "scripts" / "integration" / "linux_owner_lifecycle_scenario.py"
DRIVER_TREE = ast.parse(DRIVER.read_text())
DRIVER_FUNCTIONS = {node.name: ast.get_source_segment(DRIVER.read_text(), node)
                    for node in DRIVER_TREE.body if isinstance(node, ast.FunctionDef)}


def execute(name, namespace):
    adopted = {"start_gui.fixed": "start_gui", "window_state.before": "window_state",
               "visible_main": "visible_main", "visible_window": "visible_window",
               "hidden_frontend": "hidden_frontend", "matched_status": "matched_status",
               "checkpoint": "checkpoint", "wm_close.fixed": "request_owned_wm_close"}
    if VARIANT == "fixed" and name in adopted:
        body = DRIVER_FUNCTIONS[adopted[name]]
        namespace.setdefault("os", SimpleNamespace(getuid=lambda: 1000))
        # Source tests supply UID observation rather than reading actual /proc.
        namespace.setdefault("Path", Path)
        if name == "visible_main":
            namespace["Path"] = OwnedProcPath
        exec(compile(body, "adopted-driver:" + name, "exec"), namespace)
        return
    if VARIANT == "fixed" and name == "caller.fixed":
        exec(compile(DRIVER_FUNCTIONS["wm_close_show_cycle"], "adopted-driver:wm_close_show_cycle", "exec"), namespace)
        namespace["wm_close"] = lambda xid: namespace["request_owned_wm_close"](xid, namespace["gui"].pid, namespace["gui_birth"], namespace["display_env"])
        namespace["window"] = namespace["wm_close_show_cycle"](namespace["window"])
        return
    if VARIANT == "fixed" and name == "lease.fixed":
        namespace["require"] = lambda value, label: value or (_ for _ in ()).throw(RuntimeError(label))
        exec(compile(DRIVER_FUNCTIONS["wait_crash_lease"], "adopted-driver:wait_crash_lease", "exec"), namespace)
        namespace["wait_crash_lease"]([701,702])
        return
    exec(compile(SOURCE[name], "retained-source:" + name, "exec"), namespace)


class Clock:
    def __init__(self, frames):
        self.now = 0.0
        self.frames = frames

    def monotonic(self):
        return self.now

    def sleep(self, duration):
        self.now += duration
        self.frames.extend(range(max(1, int(duration / .08))))


class GuiSurface:
    """Deterministic X observation seam, permitting legal XID disposal/recreation."""
    def __init__(self):
        self.pid = 701
        self.tick = 901
        self.gui = SimpleNamespace(pid=self.pid, poll=lambda: None)
        self.visible = [101]
        self.next_xid = 201
        self.commands = []
        self.spawns = []
        self.records = []
        self.controller = "owned-controller"
        self.runtime = "owned-runtime"
        self.running = True

    def run(self, argv, **kwargs):
        self.commands.append(tuple(argv))
        if argv[0].endswith("xdotool") and argv[1] == "search":
            output = "\n".join(str(x) for x in self.visible).encode()
            return SimpleNamespace(returncode=0, stdout=output, stderr=b"")
        if argv[0].endswith("xwininfo"):
            if int(argv[-1]) not in self.visible:
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"retired XID")
            return SimpleNamespace(returncode=0,
                                   stdout=b"Width: 800\nHeight: 600\nMap State: IsViewable\n",
                                   stderr=b"")
        if argv[0].endswith("xprop"):
            return SimpleNamespace(returncode=0, stdout=("_NET_WM_PID = " + str(self.pid)).encode(), stderr=b"")
        if argv[0].endswith("xdotool") and argv[1] == "windowclose":
            self.visible = []
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        raise AssertionError("unexpected OS command")

    def popen(self, argv, **kwargs):
        self.spawns.append((tuple(argv), kwargs))
        return self.gui

    def invoke(self, *argv):
        if argv == ("gui", "hide"):
            self.visible = []
            return {}
        if argv == ("gui", "show"):
            self.visible = [self.next_xid]
            self.next_xid += 1
            return {}
        if argv == ("status",):
            return {"controllerId": self.controller,
                    "data": {"runtimeId": self.runtime, "runtimeRunning": self.running,
                             "configuredMode": "proxy-only", "activeMode": "proxy-only"}}
        raise AssertionError("unexpected public command")

    def namespace(self):
        frames = []
        clock = Clock(frames)
        namespace = {
            "subprocess": SimpleNamespace(run=self.run, Popen=self.popen, DEVNULL=-3),
            "re": re, "time": clock, "Path": Path,
            "R": Path("/owned-source-seam"), "W": Path("/owned-state-seam"),
            "private_stream": lambda path: contextlib.nullcontext(None),
            "durable": lambda path, record: self.records.append(record),
            "birth": lambda pid: self.tick,
            "gui": self.gui, "gui_birth": self.tick, "gui_counter": 0,
            "display_env": {"DISPLAY": ":202", "XAUTHORITY": "/owned-source-seam/auth"},
            "owner_env": {"DISPLAY": ":202"}, "cid": "owned-controller",
            "runtime_id": "owned-runtime", "owner": SimpleNamespace(poll=lambda: None),
            "frames": frames, "flow_errors": [], "slices": [],
            "stream": SimpleNamespace(is_alive=lambda: True), "invoke": self.invoke,
            "close_window": lambda window: self.visible.clear(),
            "request_owned_wm_close": lambda *args: self.visible.clear(),
        }
        for name in ("window_state.before", "visible_main", "visible_window", "hidden_frontend", "matched_status", "checkpoint"):
            execute(name, namespace)
        return namespace


class DisplayBindingRegression(unittest.TestCase):
    def test_actual_start_gui_records_bound_display_after_spawn(self):
        surface = GuiSurface()
        namespace = surface.namespace()
        execute("start_gui." + VARIANT, namespace)
        self.assertEqual(namespace["start_gui"](), 101)
        self.assertEqual(len(surface.spawns), 1)
        self.assertEqual(surface.records[0]["privateDisplay"], ":202")
        self.assertEqual(surface.records[0]["pid"], surface.pid)
        self.assertEqual(surface.records[0]["startTicks"], surface.tick)


class WorkerPinRegression(unittest.TestCase):
    def test_actual_builder_hashes_original_worker_before_stage_rewrite(self):
        original = SOURCE["worker.original.source"]
        class OriginalInput:
            def __truediv__(self, value):
                return self
            def read_text(self):
                return original
        namespace = {"N": OriginalInput(), "Path": Path, "ast": ast, "hashlib": hashlib,
                     "uuid": SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="owned-causal-stage"))}
        if VARIANT == "fixed":
            execute("worker_pin.fixed", namespace)
            exec(compile(DRIVER_FUNCTIONS["pin_worker_source"], "adopted-driver:pin_worker_source", "exec"), namespace)
        else:
            execute("worker_pin.before", namespace)
        node = next(n for n in ast.walk(ast.parse(original))
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "write_text" and n.args
                    and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)
                    and "owned_socks_fixture" in n.args[0].value)
        worker = node.args[0].value.encode()
        if VARIANT == "fixed":
            bound, namespace["worker_sha"] = namespace["pin_worker_source"](worker, lambda body: body.replace(b"gui-resumption", b"gui-existing-continuation"))
            self.assertNotEqual(bound, worker)
        self.assertEqual(len(worker), 4728)
        self.assertEqual(namespace["worker_sha"], hashlib.sha256(worker).hexdigest())
        self.assertEqual(namespace["worker_sha"], "e1f62f06e47a052a07bae68169517dcdc5295b1449b1ee286afb9d3c060709be")
        self.assertNotEqual(namespace["s"], original)


class WindowCallerRegression(unittest.TestCase):
    def test_actual_caller_accepts_retired_xid_then_fresh_show(self):
        surface = GuiSurface()
        namespace = surface.namespace()
        namespace["window"] = 101
        execute("window_state.before", namespace)
        execute("caller." + VARIANT, namespace)
        self.assertEqual(namespace["gui"].pid, 701)
        self.assertEqual(namespace["gui_birth"], 901)
        self.assertEqual(surface.visible, [201])
        self.assertEqual(len(namespace["slices"]), 2)
        self.assertTrue(all(s["sameController"] and s["sameRuntime"] and s["frames"] >= 10
                            for s in namespace["slices"]))

    def test_actual_hide_show_accepts_disposal_and_recreation(self):
        surface = GuiSurface()
        namespace = surface.namespace()
        surface.invoke("gui", "hide")
        namespace["hidden_frontend"]()
        surface.invoke("gui", "show")
        self.assertEqual(namespace["visible_window"](), 201)

    def test_actual_visibility_rejects_frontend_pid_generation_change(self):
        surface = GuiSurface()
        namespace = surface.namespace()
        surface.tick += 1
        with self.assertRaises(AssertionError):
            namespace["visible_main"]()
        self.assertEqual(surface.commands, [])

    def test_actual_checkpoint_rejects_owner_runtime_and_traffic_changes(self):
        for failure in ("controller", "runtime", "running", "traffic", "owner"):
            with self.subTest(failure=failure):
                surface = GuiSurface()
                namespace = surface.namespace()
                if failure == "controller":
                    surface.controller = "replacement"
                elif failure == "runtime":
                    surface.runtime = "replacement"
                elif failure == "running":
                    surface.running = False
                elif failure == "traffic":
                    namespace["flow_errors"].append("traffic-error")
                else:
                    namespace["owner"] = SimpleNamespace(poll=lambda: 0)
                with self.assertRaises(AssertionError):
                    namespace["checkpoint"]("owned-causal-check", 0)


class AbsentProcessPath:
    def __init__(self, *args):
        pass
    def exists(self):
        return False


class CrashLeaseRegression(unittest.TestCase):
    def test_actual_used_prefix_waits_for_lease_before_new_gui(self):
        surface = GuiSurface()
        namespace = surface.namespace()
        attached = []
        clock = namespace["time"]
        # A process/clock boundary only: admission assertion is independent of the seam.
        namespace.update({"Path": AbsentProcessPath,
                          "gui": SimpleNamespace(pid=701, poll=lambda: None, kill=lambda: None,
                                                 wait=lambda timeout: "ABSENT"),
                          "own_tray_stop": lambda *args: None, "start": 0,
                          "start_gui": lambda: attached.append(clock.monotonic()) or 201})
        execute("lease." + VARIANT, namespace)
        if VARIANT == "fixed":
            execute("lease.fixed.attach", namespace)
        self.assertEqual(len(attached), 1)
        self.assertGreaterEqual(attached[0], 15.0)
        self.assertGreaterEqual(len(namespace["frames"]), 10)
        self.assertEqual(surface.runtime, "owned-runtime")


class OwnedProcPath:
    def __init__(self, path, tick=901):
        self.path = str(path)
        self.tick = tick
    def __truediv__(self, leaf):
        return type(self)(self.path + "/" + str(leaf), self.tick)
    def exists(self):
        return True
    def stat(self):
        return SimpleNamespace(st_uid=1000)
    def read_text(self):
        return "701 (owned-source-seam) " + " ".join(["0"] * 19 + [str(self.tick)])


class XFunction:
    def __init__(self, function):
        self.function = function
    def __call__(self, *args):
        return self.function(*args)


class XProtocolObservation:
    """ABI/protocol observations only; no simulated native callback success."""
    def __init__(self, pid=701):
        self.events = []
        self.pid = pid
        self.allocations = []
        self.atoms = {b"CARDINAL": 11, b"_NET_WM_PID": 12,
                      b"WM_DELETE_WINDOW": 13, b"_NET_CLOSE_WINDOW": 14}
        functions = {
            "XOpenDisplay": lambda display: 1,
            "XDefaultRootWindow": lambda display: 55,
            "XInternAtom": lambda display, name, only: self.atoms.get(name, 0),
            "XGrabServer": lambda *args: 0, "XUngrabServer": lambda *args: 0,
            "XGetWindowProperty": self.property, "XGetWMProtocols": self.protocols,
            "XFree": lambda *args: 0, "XSendEvent": self.send,
            "XSync": lambda *args: 0, "XCloseDisplay": lambda *args: 0,
            "XSetErrorHandler": lambda *args: 0,
        }
        for name, function in functions.items():
            setattr(self, name, XFunction(function))

    def property(self, display, window, atom, start, length, delete, required,
                 actual, fmt, count, remaining, result):
        actual._obj.value = 11
        fmt._obj.value = 32
        count._obj.value = 1
        remaining._obj.value = 0
        value = (ctypes.c_ulong * 1)(self.pid)
        self.allocations.append(value)
        ctypes.cast(result, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)))[0] = ctypes.cast(value, ctypes.POINTER(ctypes.c_ubyte))
        return 0

    def protocols(self, display, window, result, size):
        value = (ctypes.c_ulong * 1)(13)
        self.allocations.append(value)
        ctypes.cast(result, ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)))[0] = ctypes.cast(value, ctypes.POINTER(ctypes.c_ulong))
        size._obj.value = 1
        return 1

    def send(self, display, destination, propagate, mask, event):
        message = event._obj.message
        self.events.append({"destination": destination, "mask": mask, "propagate": propagate,
                            "type": message.type, "window": message.window,
                            "messageType": message.message_type, "format": message.format,
                            "data": list(message.data.longs)})
        return 1


class WmRequestRegression(unittest.TestCase):
    def invoke_fixed(self, observation, window=101, display=":202"):
        namespace = {}
        execute("wm_close.fixed", namespace)
        # The retained helper explicitly admits Linux LP64. Supply that ABI at
        # the ctypes boundary on other hosts; this does not admit another OS.
        with patch("ctypes.c_long", ctypes.c_int64), \
                patch("ctypes.c_ulong", ctypes.c_uint64), \
                patch("os.getuid", return_value=1000, create=True), \
                patch("ctypes.CDLL", return_value=observation), \
                patch("ctypes.util.find_library", return_value="libX11.so.6"), \
                patch("pathlib.Path", OwnedProcPath):
            namespace["request_owned_wm_close"](window, 701, 901,
                                                 {"DISPLAY": display, "XAUTHORITY": "/owned-source-seam/auth"}, ":202")

    def test_actual_close_emits_validated_wm_request(self):
        observation = XProtocolObservation()
        if VARIANT == "before":
            surface = GuiSurface()
            namespace = surface.namespace()
            execute("wm_close.before", namespace)
            namespace["close_window"](101)
        else:
            self.invoke_fixed(observation)
        self.assertEqual(observation.events, [{"destination": 55, "mask": (1 << 19) | (1 << 20),
                                              "propagate": False, "type": 33, "window": 101,
                                              "messageType": 14, "format": 32,
                                              "data": [0, 2, 0, 0, 0]}])

    def test_actual_wm_request_rejects_changed_window_pid(self):
        observation = XProtocolObservation(pid=702)
        with self.assertRaisesRegex(RuntimeError, "owned_window_pid_changed"):
            self.invoke_fixed(observation)
        self.assertEqual(observation.events, [])

    def test_actual_wm_request_rejects_unadmitted_display(self):
        observation = XProtocolObservation()
        with self.assertRaisesRegex(RuntimeError, "owned_window_process_changed"):
            self.invoke_fixed(observation, display=":203")
        self.assertEqual(observation.events, [])

    def test_actual_wm_request_rejects_missing_delete_protocol(self):
        observation = XProtocolObservation()
        observation.atoms[b"WM_DELETE_WINDOW"] = 0
        with self.assertRaisesRegex(RuntimeError, "owned_window_graceful_close_unsupported"):
            self.invoke_fixed(observation)
        self.assertEqual(observation.events, [])


if __name__ == "__main__":
    unittest.main()
